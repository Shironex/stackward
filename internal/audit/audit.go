// Package audit is the one pipeline from facts to a report, shared by the
// CLI, the golden tests and (later) the TUI, so they can never disagree.
package audit

import (
	"io"

	"github.com/Shironex/stackward/internal/catalog"
	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/profile"
	"github.com/Shironex/stackward/internal/redact"
	"github.com/Shironex/stackward/internal/report"
	"github.com/Shironex/stackward/internal/sandbox"
)

// Options carries what the report needs beyond the facts.
type Options struct {
	Version string
	Sandbox sandbox.Status
	// Profile, when ProfileSet, overrides inference (--profile).
	Profile      profile.Name
	ProfileSet   bool
	ShowHostname bool
}

// Evaluate runs every registered check over f and builds the report.
func Evaluate(f *facts.Facts, o Options) (*report.Report, error) {
	cat, err := catalog.Default()
	if err != nil {
		return nil, err
	}
	prof, src := o.Profile, "flag"
	if !o.ProfileSet {
		prof, src = profile.Infer(f), "inferred"
	}
	all := checks.All()
	results := checks.EvaluateChecks(all, checks.Input{Facts: f, Profile: prof})
	return report.Build(f, results, cat, report.Meta{
		Version: o.Version, Sandbox: o.Sandbox, Profile: prof, ProfileSource: src,
		ShowHostname: o.ShowHostname, ChecksRun: len(all),
	}), nil
}

// DumpFacts writes f as redacted JSON for bug reports and fixtures. The
// hostname is replaced by its hash unless showHostname is set.
func DumpFacts(w io.Writer, f *facts.Facts, showHostname bool) error {
	cp := *f
	if cp.Host != nil && !showHostname && cp.Host.Hostname != "" {
		h := *cp.Host
		h.Hostname = report.HashHostname(h.Hostname)
		cp.Host = &h
	}
	b, err := redact.JSON(&cp)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}
