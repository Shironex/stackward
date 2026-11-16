package fleet

import (
	"strings"
	"unicode"

	"github.com/Shironex/stackward/internal/catalog"
	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/profile"
	"github.com/Shironex/stackward/internal/report"
	"github.com/Shironex/stackward/internal/sandbox"
)

// cleanText replaces control characters and bidirectional overrides with
// a space. Everything that comes back from a host passes through it before
// it reaches a terminal or a Markdown file: a compromised host must not be
// able to send escape sequences to the operator's terminal or forge lines
// in the fleet report.
func cleanText(s string) string {
	if strings.IndexFunc(s, unsafeRune) < 0 {
		return s
	}
	return strings.Map(func(r rune) rune {
		if unsafeRune(r) {
			return ' '
		}
		return r
	}, s)
}

func unsafeRune(r rune) bool {
	return unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) || r == unicode.ReplacementChar
}

// cleanReport runs cleanText over every string a host's report carries.
func cleanReport(r *report.Report) {
	r.Schema = cleanText(r.Schema)
	r.Tool.Name, r.Tool.Version = cleanText(r.Tool.Name), cleanText(r.Tool.Version)
	r.GeneratedAt = cleanText(r.GeneratedAt)
	h := &r.Host
	h.HostnameHash, h.Hostname, h.OS = cleanText(h.HostnameHash), cleanText(h.Hostname), cleanText(h.OS)
	h.OSID, h.Version, h.Kernel = cleanText(h.OSID), cleanText(h.Version), cleanText(h.Kernel)
	r.Profile.Name, r.Profile.Source = profile.Name(cleanText(string(r.Profile.Name))), cleanText(r.Profile.Source)
	sb := &r.Coverage.Sandbox
	sb.State, sb.Reason = sandbox.State(cleanText(string(sb.State))), cleanText(sb.Reason)
	for i := range r.Coverage.Collectors {
		c := &r.Coverage.Collectors[i]
		c.Name, c.Reason, c.Error = cleanText(c.Name), cleanText(c.Reason), cleanText(c.Error)
		c.Status = facts.Status(cleanText(string(c.Status)))
	}
	for i := range r.Results {
		it := &r.Results[i]
		it.ID, it.Group, it.Title = cleanText(it.ID), cleanText(it.Group), cleanText(it.Title)
		it.Subject, it.Message = cleanText(it.Subject), cleanText(it.Message)
		it.Level, it.Severity = checks.Level(cleanText(string(it.Level))), catalog.Severity(cleanText(string(it.Severity)))
		it.Fix.Hint, it.Fix.Docs = cleanText(it.Fix.Hint), cleanText(it.Fix.Docs)
		if it.Evidence != nil {
			it.Evidence = cleanValue(it.Evidence).(map[string]any)
		}
	}
	r.Probe = nil // an audit report never carries one
}

// cleanValue walks decoded JSON and cleans every string, keys included.
func cleanValue(v any) any {
	switch t := v.(type) {
	case string:
		return cleanText(t)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[cleanText(k)] = cleanValue(x)
		}
		return out
	case []any:
		for i, x := range t {
			t[i] = cleanValue(x)
		}
		return t
	}
	return v
}
