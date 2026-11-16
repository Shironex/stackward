package fleet

import (
	"encoding/json"
	"fmt"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/Shironex/stackward/internal/catalog"
	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/profile"
	"github.com/Shironex/stackward/internal/report"
	"github.com/Shironex/stackward/internal/sandbox"
)

// Limits on what is kept from one host's report, so a hostile or broken
// host cannot fill this machine's memory or the fleet report.
const (
	maxResults      = 5000      // results kept per host
	maxText         = 2048      // bytes of one subject or message
	maxShortText    = 256       // bytes of a host, collector or sandbox field
	maxEvidenceItem = 8 << 10   // bytes of one result's evidence as JSON
	maxEvidenceHost = 256 << 10 // bytes of evidence kept per host
)

// Shapes of the host fields that have one. A value that does not fit is
// replaced, with a note, before anything renders it.
var (
	hashPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{16}$`)
	hostnamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$`)
	versionPattern  = regexp.MustCompile(`^(dev|v?[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.+-]{1,64})?)$`)
)

var knownLevels = map[checks.Level]bool{
	checks.Pass: true, checks.Warn: true, checks.Fail: true,
	checks.Unknown: true, checks.Skip: true, checks.Info: true,
}

var knownSandbox = map[sandbox.State]bool{
	sandbox.Landlock: true, sandbox.Unavailable: true, sandbox.Disabled: true, sandbox.Failed: true,
}

var knownCollector = map[facts.Status]bool{
	facts.StatusOK: true, facts.StatusPartial: true, facts.StatusFailed: true,
	facts.StatusTimeout: true, facts.StatusSkipped: true,
}

// validateReport rebuilds a host's report from what this machine knows.
// A result is kept only when its check id is in the local catalog and its
// level is a known one; its title, severity, group and fix come from the
// local catalog, never from the host, because the renderers print those as
// trusted text (links, the fix hint). Free text the host does supply
// (subject, message, evidence) is cleaned, capped and escaped by the
// renderers. The summary and coverage counts are recomputed from the kept
// results. It returns the notes to show beside the host.
func validateReport(r *report.Report, cat *catalog.Catalog) []string {
	cleanReport(r)
	notes := validateShapes(r)
	h := &r.Host
	h.HostnameHash, h.Hostname, h.OS = truncate(h.HostnameHash, maxShortText), truncate(h.Hostname, maxShortText), truncate(h.OS, maxShortText)
	h.OSID, h.Version, h.Kernel = truncate(h.OSID, maxShortText), truncate(h.Version, maxShortText), truncate(h.Kernel, maxShortText)
	r.Tool.Version, r.GeneratedAt = truncate(r.Tool.Version, maxShortText), truncate(r.GeneratedAt, maxShortText)
	if _, set, err := profile.Parse(string(r.Profile.Name)); err != nil || !set {
		if r.Profile.Name != profile.Mixed {
			r.Profile.Name = profile.Unknown
		}
	}
	if r.Profile.Source != "flag" {
		r.Profile.Source = "inferred"
	}
	sb := &r.Coverage.Sandbox
	sb.Reason = truncate(sb.Reason, maxShortText)
	if !knownSandbox[sb.State] {
		sb.State, sb.Reason = sandbox.Failed, "the host reported an unrecognised sandbox state"
	}
	for i := range r.Coverage.Collectors {
		c := &r.Coverage.Collectors[i]
		c.Name, c.Reason, c.Error = truncate(c.Name, maxShortText), truncate(c.Reason, maxShortText), truncate(c.Error, maxShortText)
		if !knownCollector[c.Status] {
			c.Status = facts.StatusFailed
		}
	}
	kept := make([]report.Item, 0, min(len(r.Results), maxResults))
	dropped, truncated, overflow, evDropped, evBudget := 0, 0, 0, 0, maxEvidenceHost
	// Waivers are never taken from a host: a fleet run reads no waivers
	// file, and a host's own .stackward.yml (or a forged waiver) must not
	// mark its findings accepted or bring its reason text into the report.
	waived := len(r.Waivers) > 0
	r.Waivers = nil
	for _, it := range r.Results {
		waived = waived || it.Waiver != nil
		it.Waiver = nil
		e, ok := cat.Lookup(it.ID)
		if !ok || !knownLevels[it.Level] {
			dropped++
			continue
		}
		if len(kept) == maxResults {
			overflow++
			continue
		}
		it.ID, it.Group, it.Title, it.Severity = e.ID, catalog.GroupOf(e.ID), e.Title, e.Severity
		it.Fix = report.Fix{Hint: e.Fix, Docs: e.Docs}
		if s, m := truncate(it.Subject, maxText), truncate(it.Message, maxText); s != it.Subject || m != it.Message {
			it.Subject, it.Message = s, m
			truncated++
		}
		if it.Evidence != nil {
			b, err := json.Marshal(it.Evidence)
			if err != nil || len(b) > maxEvidenceItem || len(b) > evBudget {
				it.Evidence = nil
				evDropped++
			} else {
				evBudget -= len(b)
			}
		}
		kept = append(kept, it)
	}
	r.Results = kept
	r.Recount()
	// The check count can be no lower than the checks that left a result
	// and no higher than the catalog.
	ids := map[string]bool{}
	for _, it := range kept {
		ids[it.ID] = true
	}
	r.Coverage.Checks = max(min(r.Coverage.Checks, len(cat.Entries())), len(ids))
	if waived {
		notes = append(notes, "waivers from the host ignored: every finding is shown at its level")
	}
	if dropped > 0 {
		notes = append(notes, fmt.Sprintf("unknown results dropped: %d (check id not in this stackward's catalog, or an unknown level)", dropped))
	}
	if overflow > 0 {
		notes = append(notes, fmt.Sprintf("results dropped over the limit of %d: %d", maxResults, overflow))
	}
	if truncated > 0 {
		notes = append(notes, fmt.Sprintf("long subjects or messages cut to %d bytes: %d results", maxText, truncated))
	}
	if evDropped > 0 {
		notes = append(notes, fmt.Sprintf("evidence dropped over the size limit: %d results", evDropped))
	}
	return notes
}

// validateShapes replaces host fields that do not have their expected
// shape: the hostname hash, the hostname (--show-hostname), the tool
// version and the collection time.
func validateShapes(r *report.Report) []string {
	var notes []string
	h := &r.Host
	if h.HostnameHash != "" && !hashPattern.MatchString(h.HostnameHash) {
		h.HostnameHash = ""
		notes = append(notes, "invalid hostname hash from the host dropped")
	}
	if h.Hostname != "" && !hostnamePattern.MatchString(h.Hostname) {
		h.Hostname = "invalid"
		notes = append(notes, "invalid hostname from the host replaced")
	}
	if !versionPattern.MatchString(r.Tool.Version) {
		r.Tool.Version = "invalid"
		notes = append(notes, "invalid tool version from the host replaced")
	}
	if r.GeneratedAt != "" {
		if _, err := time.Parse(time.RFC3339, r.GeneratedAt); err != nil {
			r.GeneratedAt = ""
			notes = append(notes, "invalid collection time from the host dropped")
		}
	}
	return notes
}

// truncate cuts s to at most n bytes on a rune boundary.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}
