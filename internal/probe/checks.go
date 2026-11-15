package probe

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Shironex/stackward/internal/catalog"
	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/profile"
	"github.com/Shironex/stackward/internal/report"
	"github.com/Shironex/stackward/internal/sandbox"
)

// The PRB checks live in their own registry, not in checks.Register: they
// judge probe facts, which an audit never has, so listing them in every
// audit report would only add unknown rows (and change every golden
// fixture). They reuse checks.Result, levels and EvaluateChecks, so the
// report, its renderers and the JSON schema are shared with audit.

// Input is what a PRB check may look at.
type Input struct {
	Facts   *Facts
	Profile profile.Name
}

// Check is one PRB check.
type Check struct {
	ID  string
	Run func(Input) []checks.Result
}

// Checks returns every PRB check in id order.
func Checks() []Check {
	return []Check{
		{ID: "PRB-001", Run: checkSSH},
		{ID: "PRB-002", Run: checkRawWeb},
		{ID: "PRB-003", Run: func(in Input) []checks.Result { return closedPorts(in, in.Facts.PortList.Docker) }},
		{ID: "PRB-004", Run: func(in Input) []checks.Result { return closedPorts(in, in.Facts.PortList.Panels) }},
		{ID: "PRB-005", Run: func(in Input) []checks.Result { return closedPorts(in, in.Facts.PortList.Databases) }},
		{ID: "PRB-006", Run: checkHostname},
	}
}

// certWarnWindow is how close to expiry a certificate draws a warning.
const certWarnWindow = 14 * 24 * time.Hour

// serviceNames label well known ports in messages.
var serviceNames = map[int]string{
	22: "SSH", 80: "HTTP", 443: "HTTPS", 2375: "Docker API", 2376: "Docker API over TLS",
	3000: "Dokploy or Grafana", 3100: "Loki", 6001: "Coolify realtime", 6002: "Coolify terminal",
	8000: "Coolify", 8080: "Traefik dashboard or admin UI", 8081: "admin UI", 9000: "Portainer",
	9090: "Prometheus", 3306: "MySQL or MariaDB", 5432: "PostgreSQL", 6379: "Redis",
	9200: "Elasticsearch", 27017: "MongoDB",
}

func service(port int) string {
	if n, ok := serviceNames[port]; ok {
		return fmt.Sprintf("%d (%s)", port, n)
	}
	return fmt.Sprint(port)
}

// portView sorts the addresses of one port by state.
type portView struct {
	port                                   int
	open, closed, filtered, unreach, other []string
	reasons                                []string
}

func view(f *Facts, port int) portView {
	v := portView{port: port, open: []string{}, closed: []string{}, filtered: []string{}, unreach: []string{}, other: []string{}}
	for _, p := range f.Ports {
		if p.Port != port {
			continue
		}
		switch p.State {
		case Open:
			v.open = append(v.open, p.Address)
		case Closed:
			v.closed = append(v.closed, p.Address)
		case Filtered:
			v.filtered = append(v.filtered, p.Address)
		case Unreachable:
			v.unreach = append(v.unreach, p.Address)
			v.reasons = append(v.reasons, p.Address+" ("+orWord(p.Error, "no route")+")")
		default:
			v.other = append(v.other, p.Address)
			v.reasons = append(v.reasons, p.Address+" ("+orWord(p.Error, "connect failed")+")")
		}
	}
	return v
}

func orWord(s, w string) string {
	if s == "" {
		return w
	}
	return s
}

func (v portView) evidence() map[string]any {
	return map[string]any{
		"port": v.port, "open": v.open, "closed": v.closed, "filtered": v.filtered,
		"unreachable": append(append([]string{}, v.unreach...), v.other...),
	}
}

// judge is the shared shape of every port check: open goes to onOpen;
// nothing open but some address not reachable is unknown (never a pass);
// closed or filtered everywhere passes.
func judge(v portView, onOpen func(portView) (checks.Level, string)) checks.Result {
	r := checks.Result{Subject: fmt.Sprintf("port:tcp/%d", v.port), Evidence: v.evidence()}
	switch {
	case len(v.open) > 0:
		r.Level, r.Message = onOpen(v)
	case len(v.unreach)+len(v.other) > 0:
		r.Level = checks.Unknown
		r.Message = fmt.Sprintf("port %s could not be checked on %s", service(v.port), strings.Join(v.reasons, ", "))
		if done := append(append([]string{}, v.closed...), v.filtered...); len(done) > 0 {
			r.Message += "; closed or filtered on " + addrList(done)
		}
	case len(v.closed)+len(v.filtered) == 0:
		r.Level, r.Message = checks.Unknown, fmt.Sprintf("port %s was not probed", service(v.port))
	default:
		r.Level = checks.Pass
		r.Message = fmt.Sprintf("port %s is closed or filtered on %s", service(v.port), addrList(append(append([]string{}, v.closed...), v.filtered...)))
	}
	return r
}

func addrList(a []string) string {
	sort.Strings(a)
	return strings.Join(a, ", ")
}

// notProbed is the result when there was nothing to probe.
func notProbed(f *Facts) []checks.Result {
	msg := "not probed: the target resolved to no address"
	if f.ResolveError != "" {
		msg = "not probed: the target did not resolve: " + f.ResolveError
	}
	return []checks.Result{{Level: checks.Unknown, Message: msg, Evidence: map[string]any{"target": f.Target}}}
}

func closedPorts(in Input, ports []int) []checks.Result {
	if len(in.Facts.Addresses) == 0 {
		return notProbed(in.Facts)
	}
	var out []checks.Result
	for _, p := range ports {
		out = append(out, judge(view(in.Facts, p), func(v portView) (checks.Level, string) {
			return checks.Fail, fmt.Sprintf("port %s answers from outside on %s", service(v.port), addrList(v.open))
		}))
	}
	if len(out) == 0 {
		return checks.One(checks.Unknown, "no ports of this check were in the probe list", nil)
	}
	return out
}

// private reports whether the profile says nothing should be public.
func private(p profile.Name) bool { return p == profile.Tunnel || p == profile.TailnetOnly }

const unknownProfileNote = "profile unknown, judged as if nothing should be public; pass --profile to judge against your ingress"

func sshPorts(f *Facts) []int {
	ports := append([]int{}, f.PortList.SSH...)
	isSSH := map[int]bool{}
	for _, p := range ports {
		isSSH[p] = true
	}
	for _, p := range f.Ports {
		if !isSSH[p.Port] && strings.HasPrefix(p.Banner, "SSH-") {
			isSSH[p.Port] = true
			ports = append(ports, p.Port)
		}
	}
	sort.Ints(ports)
	return ports
}

func banner(f *Facts, port int) string {
	for _, p := range f.Ports {
		if p.Port == port && p.Banner != "" {
			return p.Banner
		}
	}
	return ""
}

func checkSSH(in Input) []checks.Result {
	f := in.Facts
	if len(f.Addresses) == 0 {
		return notProbed(f)
	}
	var out []checks.Result
	for _, port := range sshPorts(f) {
		b := banner(f, port)
		r := judge(view(f, port), func(v portView) (checks.Level, string) {
			msg := fmt.Sprintf("SSH answers from outside on port %d at %s", v.port, addrList(v.open))
			if b != "" {
				msg += " (" + b + ")"
			}
			switch {
			case private(in.Profile):
				return checks.Warn, msg + ", although ingress is " + string(in.Profile)
			case in.Profile == profile.Unknown:
				return checks.Warn, msg + "; " + unknownProfileNote
			}
			return checks.Info, msg + "; on " + string(in.Profile) + " this is a choice, keep it key only"
		})
		r.Evidence["banner"] = b
		out = append(out, r)
	}
	if len(out) == 0 {
		return checks.One(checks.Unknown, "no SSH port was in the probe list", nil)
	}
	return out
}

func checkRawWeb(in Input) []checks.Result {
	f := in.Facts
	if len(f.Addresses) == 0 {
		return notProbed(f)
	}
	ports := append(append([]int{}, f.PortList.HTTP...), f.PortList.HTTPS...)
	sort.Ints(ports)
	var out []checks.Result
	for _, port := range ports {
		var responses []map[string]any
		var codes []string
		for _, h := range f.RawHTTP {
			if h.Port != port {
				continue
			}
			responses = append(responses, map[string]any{
				"address": h.Address, "scheme": h.Scheme, "status": h.Status, "location": h.Location, "error": h.Error,
			})
			if h.Status != 0 {
				codes = append(codes, fmt.Sprintf("%s %d", h.Scheme, h.Status))
			}
		}
		r := judge(view(f, port), func(v portView) (checks.Level, string) {
			msg := fmt.Sprintf("port %d answers on the raw IP %s", v.port, addrList(v.open))
			if len(codes) > 0 {
				msg += " (" + strings.Join(dedupe(codes), ", ") + ")"
			}
			switch {
			case private(in.Profile):
				return checks.Fail, msg + ": ingress is " + string(in.Profile) + ", so this is an origin bypass (see CF-005)"
			case in.Profile == profile.Unknown:
				return checks.Warn, msg + "; if a tunnel is the only ingress this is an origin bypass; " + unknownProfileNote
			}
			return checks.Info, msg + "; expected on " + string(in.Profile)
		})
		if responses == nil {
			responses = []map[string]any{}
		}
		r.Evidence["responses"] = responses
		out = append(out, r)
	}
	if len(out) == 0 {
		return checks.One(checks.Unknown, "no web port was in the probe list", nil)
	}
	return out
}

func dedupe(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range s {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

func checkHostname(in Input) []checks.Result {
	f := in.Facts
	h := f.HTTPS
	if h == nil {
		if f.Hostname == "" {
			return checks.One(checks.Skip, "no --hostname given; pass --hostname app.example.com to check it over HTTPS", nil)
		}
		return checks.One(checks.Unknown, "the --hostname check did not run", map[string]any{"hostname": f.Hostname})
	}
	hops := make([]string, 0, len(h.Hops))
	for _, hp := range h.Hops {
		s := fmt.Sprintf("%d %s", hp.Status, hp.URL)
		if hp.Location != "" {
			s += " -> " + hp.Location
		}
		hops = append(hops, s)
	}
	var anomalies []string
	if h.TLSError != "" {
		anomalies = append(anomalies, "TLS failed: "+h.TLSError)
	}
	if h.Loop {
		anomalies = append(anomalies, "redirect loop (often an app redirecting to HTTPS behind a tunnel that already terminates TLS)")
	}
	if h.TooManyRedirects {
		anomalies = append(anomalies, fmt.Sprintf("more than %d redirects", maxRedirects))
	}
	if h.Downgrade {
		anomalies = append(anomalies, "redirects from HTTPS to plain HTTP")
	}
	certExpiry := ""
	if h.CertNotAfter != nil {
		certExpiry = h.CertNotAfter.UTC().Format(time.RFC3339)
		switch left := h.CertNotAfter.Sub(f.CollectedAt); {
		case left <= 0:
			anomalies = append(anomalies, "certificate expired on "+certExpiry)
		case left < certWarnWindow:
			anomalies = append(anomalies, fmt.Sprintf("certificate expires in %d days", int(left.Hours()/24)))
		}
	}
	if h.FinalStatus >= 500 {
		anomalies = append(anomalies, fmt.Sprintf("answers with %d", h.FinalStatus))
	}
	ev := map[string]any{
		"hostname": h.Hostname, "hops": hops, "final_status": h.FinalStatus, "anomalies": nonNil(anomalies),
		"tls_error": h.TLSError, "cert_not_after": certExpiry, "off_host": h.OffHost,
	}
	switch {
	case len(anomalies) > 0:
		return checks.One(checks.Warn, fmt.Sprintf("https://%s/: %s", h.Hostname, strings.Join(anomalies, "; ")), ev)
	case len(h.Hops) == 0:
		return checks.One(checks.Unknown, fmt.Sprintf("could not reach https://%s/: %s", h.Hostname, orWord(h.Error, "no response")), ev)
	}
	msg := fmt.Sprintf("https://%s/ answers with %d", h.Hostname, h.FinalStatus)
	if n := len(h.Hops) - 1; n > 0 {
		msg += fmt.Sprintf(" after %d redirects", n)
	}
	if h.OffHost != "" {
		msg += "; redirects to " + h.OffHost + " (not followed)"
	}
	return checks.One(checks.Pass, msg, ev)
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// EvalOptions carries what the report needs beyond the probe facts.
type EvalOptions struct {
	Version string
	Sandbox sandbox.Status
	// Profile, when ProfileSet, is the --profile. Probe has no host facts
	// to infer from, so auto means profile.Unknown.
	Profile    profile.Name
	ProfileSet bool
}

// Evaluate runs the PRB checks over pf and builds a report.v1 document.
func Evaluate(pf *Facts, o EvalOptions) (*report.Report, error) {
	cat, err := catalog.Default()
	if err != nil {
		return nil, err
	}
	prof, src := o.Profile, "flag"
	if !o.ProfileSet {
		prof, src = profile.Unknown, "inferred"
	}
	in := Input{Facts: pf, Profile: prof}
	list := Checks()
	wrapped := make([]checks.Check, 0, len(list))
	for _, c := range list {
		wrapped = append(wrapped, checks.Check{ID: c.ID, Run: func(checks.Input) []checks.Result { return c.Run(in) }})
	}
	results := checks.EvaluateChecks(wrapped, checks.Input{Facts: &facts.Facts{}, Profile: prof})
	host := &facts.Facts{CollectedAt: pf.CollectedAt, Collectors: pf.Steps}
	return report.Build(host, results, cat, report.Meta{
		Version: o.Version, Sandbox: o.Sandbox, Profile: prof, ProfileSource: src,
		ChecksRun: len(wrapped), Probe: summary(pf, o.ProfileSet),
	}), nil
}

// summary is the report's probe section.
func summary(pf *Facts, profileSet bool) *report.Probe {
	p := &report.Probe{
		Target: pf.Target, Hostname: pf.Hostname,
		Addresses: []report.ProbeAddress{}, Families: []report.ProbeFamily{}, Ports: []report.ProbePort{},
	}
	for _, a := range pf.Addresses {
		p.Addresses = append(p.Addresses, report.ProbeAddress{Address: a.Address, Family: a.Family})
	}
	for _, fm := range pf.Families {
		p.Families = append(p.Families, report.ProbeFamily{Family: fm.Family, Status: fm.Status, Detail: fm.Detail})
	}
	for _, pt := range pf.Ports {
		p.Ports = append(p.Ports, report.ProbePort{Address: pt.Address, Family: pt.Family, Port: pt.Port, State: pt.State, Banner: pt.Banner})
	}
	if !profileSet {
		p.Notes = append(p.Notes, "profile unknown: probe has no host facts, so open SSH and web ports are judged as if nothing should be public; pass --profile tunnel, public-web, tailnet-only or paas-panel")
	}
	for _, h := range pf.RawHTTP {
		if h.TLSVerifySkipped {
			p.Notes = append(p.Notes, "the raw IP HTTPS check skips certificate verification (an IP has no certificate name); the --hostname check verifies normally")
			break
		}
	}
	if pf.Truncated {
		p.Notes = append(p.Notes, fmt.Sprintf("the name resolved to more than %d addresses per family; only the first %d were probed", maxPerFamily, maxPerFamily))
	}
	if _, isIP := parseIP(pf.Target); !isIP && pf.Target != "" {
		p.Notes = append(p.Notes, "the target is a name: if it points at a CDN or tunnel edge, probe the origin IP instead and pass the name with --hostname")
	}
	return p
}
