// Package audit is the one pipeline from facts to a report, shared by the
// CLI, the golden tests and (later) the TUI, so they can never disagree.
package audit

import (
	"fmt"
	"io"
	"net/netip"
	"regexp"

	"github.com/Shironex/stackward/internal/catalog"
	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/profile"
	"github.com/Shironex/stackward/internal/redact"
	"github.com/Shironex/stackward/internal/report"
	"github.com/Shironex/stackward/internal/sandbox"
	"github.com/Shironex/stackward/internal/waiver"
)

// Options carries what the report needs beyond the facts.
type Options struct {
	Version string
	Sandbox sandbox.Status
	// Profile, when ProfileSet, overrides inference (--profile).
	Profile      profile.Name
	ProfileSet   bool
	ShowHostname bool
	// Waivers are the entries of the waivers file (--waivers), if any.
	Waivers []waiver.Waiver
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
		ShowHostname: o.ShowHostname, ChecksRun: len(all), Waivers: o.Waivers,
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
	if cp.ProviderFirewall != nil {
		cp.ProviderFirewall = maskProviderAddresses(cp.ProviderFirewall)
	}
	b, err := redact.JSON(&cp)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// maskProviderAddresses returns a copy of pf for a facts dump, which is
// posted in bug reports: every matched address loses its last octet
// ("192.0.2.x"), every IPv4 address in a reason (request URLs carry them)
// too, and every rule network keeps its prefix length but loses its host
// bits past the first three octets (IPv4) or the first 64 bits (IPv6), so
// the checks still see how wide each source is. The live report keeps the
// full values.
func maskProviderAddresses(pf *facts.ProviderFirewall) *facts.ProviderFirewall {
	cp := *pf
	cp.Reason = maskIPv4Text(pf.Reason)
	cp.Targets = make([]facts.ProviderTarget, len(pf.Targets))
	for i, t := range pf.Targets {
		t.Address = maskIPv4(t.Address)
		t.Reason = maskIPv4Text(t.Reason)
		t.Rules = make([]facts.ProviderRule, len(pf.Targets[i].Rules))
		for j, r := range pf.Targets[i].Rules {
			r.Sources = maskNetworks(r.Sources)
			r.Destinations = maskNetworks(r.Destinations)
			t.Rules[j] = r
		}
		cp.Targets[i] = t
	}
	return &cp
}

var ipv4Text = regexp.MustCompile(`\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b`)

// maskIPv4Text masks the last octet of every IPv4 address in s.
func maskIPv4Text(s string) string { return ipv4Text.ReplaceAllString(s, "$1.$2.$3.x") }

func maskIPv4(s string) string {
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() {
		return s
	}
	b := a.As4()
	return fmt.Sprintf("%d.%d.%d.x", b[0], b[1], b[2])
}

// unparsedNetwork replaces, in a dump, a rule network that does not parse:
// it may hold an address. It does not parse either, so a replay judges it
// the same way (a permit from it reaches anywhere, a deny from it blocks
// nothing).
const unparsedNetwork = "unparsed"

// maskNetworks zeroes the host bits of each network past the first 24
// (IPv4) or 64 (IPv6) bits, keeping its prefix length; a network that does
// not parse becomes unparsedNetwork.
func maskNetworks(ns []string) []string {
	if ns == nil {
		return nil
	}
	out := make([]string, len(ns))
	for i, n := range ns {
		p, err := netip.ParsePrefix(n)
		if err != nil {
			out[i] = unparsedNetwork
			continue
		}
		if a := p.Addr(); a.Is4In6() && p.Bits() >= 96 {
			// An IPv4-mapped prefix is masked as the IPv4 prefix it is.
			p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
		}
		keep := 24
		if p.Addr().Is6() {
			keep = 64
		}
		if p.Bits() < keep {
			keep = p.Bits()
		}
		masked, err := p.Addr().Prefix(keep)
		if err != nil {
			out[i] = unparsedNetwork
			continue
		}
		out[i] = netip.PrefixFrom(masked.Addr(), p.Bits()).String()
	}
	return out
}
