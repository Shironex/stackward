package probe

import (
	"strings"
	"testing"
	"time"

	"github.com/Shironex/stackward/internal/catalog"
	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/profile"
)

const v4, v6 = "192.0.2.10", "2001:db8::10"

// fakeFacts builds probe facts for one v4 and one v6 address where every
// port of the default list is closed unless states says otherwise.
func fakeFacts(states map[int][2]string) *Facts {
	f := &Facts{
		Schema: SchemaVersion, CollectedAt: fixedNow(), Target: v4, PortList: DefaultPorts(),
		Addresses: []Address{{v4, IPv4}, {v6, IPv6}},
		Families:  []Family{{Family: IPv4, Status: FamilyProbed}, {Family: IPv6, Status: FamilyProbed}},
	}
	for _, p := range f.PortList.All() {
		s, ok := states[p]
		if !ok {
			s = [2]string{Closed, Closed}
		}
		f.Ports = append(f.Ports, Port{Address: v4, Family: IPv4, Port: p, State: s[0]}, Port{Address: v6, Family: IPv6, Port: p, State: s[1]})
	}
	return f
}

func runCheck(t *testing.T, id string, f *Facts, p profile.Name) []checks.Result {
	t.Helper()
	for _, c := range Checks() {
		if c.ID == id {
			return c.Run(Input{Facts: f, Profile: p})
		}
	}
	t.Fatalf("no check %s", id)
	return nil
}

func bySubject(rs []checks.Result) map[string]checks.Result {
	m := map[string]checks.Result{}
	for _, r := range rs {
		m[r.Subject] = r
	}
	return m
}

func TestChecksMatchCatalog(t *testing.T) {
	cat, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, c := range Checks() {
		ids[c.ID] = true
		if e, ok := cat.Lookup(c.ID); !ok || e.Group != "PRB" {
			t.Errorf("%s has no PRB catalog entry", c.ID)
		}
	}
	for _, e := range cat.Entries() {
		if e.Group == "PRB" && !ids[e.ID] {
			t.Errorf("catalog entry %s has no probe check", e.ID)
		}
	}
	for _, c := range checks.All() {
		if catalog.GroupOf(c.ID) == "PRB" {
			t.Errorf("%s is in the audit registry; PRB checks belong to probe only", c.ID)
		}
	}
}

func TestEmptyFactsNeverPass(t *testing.T) {
	for _, c := range Checks() {
		for _, p := range []profile.Name{profile.Unknown, profile.Tunnel, profile.PublicWeb} {
			for _, r := range c.Run(Input{Facts: &Facts{}, Profile: p}) {
				if r.Level == checks.Pass {
					t.Errorf("%s passed on empty facts: %s", c.ID, r.Message)
				}
			}
		}
	}
}

func TestSSHByProfile(t *testing.T) {
	f := fakeFacts(map[int][2]string{22: {Open, Closed}})
	f.Ports[0].Banner = "SSH-2.0-OpenSSH_9.6"
	cases := map[profile.Name]checks.Level{
		profile.Tunnel: checks.Warn, profile.TailnetOnly: checks.Warn, profile.Unknown: checks.Warn,
		profile.PublicWeb: checks.Info, profile.PaaSPanel: checks.Info,
	}
	for p, want := range cases {
		r := runCheck(t, "PRB-001", f, p)
		if len(r) != 1 || r[0].Level != want || r[0].Subject != "port:tcp/22" {
			t.Fatalf("%s: %+v", p, r)
		}
		if !strings.Contains(r[0].Message, "SSH-2.0-OpenSSH_9.6") || r[0].Evidence["banner"] != "SSH-2.0-OpenSSH_9.6" {
			t.Errorf("%s: banner missing: %+v", p, r[0])
		}
		if p == profile.Unknown && !strings.Contains(r[0].Message, "profile unknown") {
			t.Errorf("unknown profile must say it judged conservatively: %s", r[0].Message)
		}
	}
	if r := runCheck(t, "PRB-001", fakeFacts(nil), profile.Tunnel); r[0].Level != checks.Pass {
		t.Errorf("closed everywhere: %+v", r)
	}
}

func TestSSHOnExtraPort(t *testing.T) {
	f := fakeFacts(nil)
	f.PortList.Extra = []int{2222, 8443}
	f.Ports = append(f.Ports,
		Port{Address: v4, Family: IPv4, Port: 2222, State: Open, Banner: "SSH-2.0-dropbear"},
		Port{Address: v4, Family: IPv4, Port: 8443, State: Open})
	m := bySubject(runCheck(t, "PRB-001", f, profile.Tunnel))
	if m["port:tcp/2222"].Level != checks.Warn || m["port:tcp/22"].Level != checks.Pass {
		t.Errorf("%+v", m)
	}
	if _, ok := m["port:tcp/8443"]; ok {
		t.Error("a non SSH extra port is not an SSH result")
	}
}

func TestUnreachableIsUnknownNeverPass(t *testing.T) {
	f := fakeFacts(map[int][2]string{6379: {Closed, Unreachable}, 5432: {Filtered, Error}})
	m := bySubject(runCheck(t, "PRB-005", f, profile.Tunnel))
	if m["port:tcp/6379"].Level != checks.Unknown || m["port:tcp/5432"].Level != checks.Unknown {
		t.Errorf("%+v", m)
	}
	if m["port:tcp/3306"].Level != checks.Pass {
		t.Errorf("closed on both families: %+v", m["port:tcp/3306"])
	}
	// Open wins over unreachable: what answers is a finding.
	f = fakeFacts(map[int][2]string{6379: {Open, Unreachable}})
	if r := bySubject(runCheck(t, "PRB-005", f, profile.Tunnel))["port:tcp/6379"]; r.Level != checks.Fail || !strings.Contains(r.Message, "Redis") {
		t.Errorf("%+v", r)
	}
}

func TestExposureChecksFailOnOpen(t *testing.T) {
	f := fakeFacts(map[int][2]string{2375: {Closed, Open}, 8000: {Open, Open}, 27017: {Filtered, Open}})
	for id, subject := range map[string]string{"PRB-003": "port:tcp/2375", "PRB-004": "port:tcp/8000", "PRB-005": "port:tcp/27017"} {
		for _, p := range []profile.Name{profile.Unknown, profile.PublicWeb} {
			r := bySubject(runCheck(t, id, f, p))[subject]
			if r.Level != checks.Fail {
				t.Errorf("%s %s on %s: %+v", id, subject, p, r)
			}
			if open, _ := r.Evidence["open"].([]string); len(open) == 0 {
				t.Errorf("%s: evidence lists no open address: %+v", id, r.Evidence)
			}
		}
	}
	if n := len(runCheck(t, "PRB-004", f, profile.Unknown)); n != len(DefaultPorts().Panels) {
		t.Errorf("PRB-004 gave %d results, want one per panel port", n)
	}
}

func TestRawWebByProfile(t *testing.T) {
	f := fakeFacts(map[int][2]string{443: {Open, Closed}})
	f.RawHTTP = []RawHTTP{{Address: v4, Family: IPv4, Port: 443, Scheme: "https", Status: 404, TLSVerifySkipped: true}}
	cases := map[profile.Name]checks.Level{
		profile.Tunnel: checks.Fail, profile.TailnetOnly: checks.Fail, profile.Unknown: checks.Warn,
		profile.PublicWeb: checks.Info, profile.PaaSPanel: checks.Info,
	}
	for p, want := range cases {
		m := bySubject(runCheck(t, "PRB-002", f, p))
		r := m["port:tcp/443"]
		if r.Level != want || !strings.Contains(r.Message, "https 404") {
			t.Errorf("%s: %+v", p, r)
		}
		if m["port:tcp/80"].Level != checks.Pass {
			t.Errorf("%s: closed 80: %+v", p, m["port:tcp/80"])
		}
	}
	if r := bySubject(runCheck(t, "PRB-002", f, profile.Tunnel))["port:tcp/443"]; !strings.Contains(r.Message, "CF-005") {
		t.Errorf("tunnel fail must point at CF-005: %s", r.Message)
	}
}

func TestNotResolved(t *testing.T) {
	f := &Facts{Target: "missing.example.com", ResolveError: "no such host"}
	for _, c := range Checks() {
		if c.ID == "PRB-006" {
			continue
		}
		r := c.Run(Input{Facts: f, Profile: profile.Tunnel})
		if len(r) != 1 || r[0].Level != checks.Unknown || !strings.Contains(r[0].Message, "did not resolve") {
			t.Errorf("%s: %+v", c.ID, r)
		}
	}
}

func TestHostnameCheck(t *testing.T) {
	soon := fixedNow().Add(5 * 24 * time.Hour)
	later := fixedNow().Add(60 * 24 * time.Hour)
	past := fixedNow().Add(-time.Hour)
	ok := []Hop{{URL: "https://app.example.com/", Status: 302, Location: "/login"}, {URL: "https://app.example.com/login", Status: 200}}
	cases := []struct {
		name string
		h    *HTTPSFact
		host string
		want checks.Level
		text string
	}{
		{"skipped", nil, "", checks.Skip, "no --hostname"},
		{"did not run", nil, "app.example.com", checks.Unknown, "did not run"},
		{"ok", &HTTPSFact{Hostname: "app.example.com", Hops: ok, FinalStatus: 200, CertNotAfter: &later}, "app.example.com", checks.Pass, "after 1 redirects"},
		{"loop", &HTTPSFact{Hostname: "app.example.com", Hops: ok[:1], FinalStatus: 302, Loop: true, CertNotAfter: &later}, "app.example.com", checks.Warn, "redirect loop"},
		{"too many", &HTTPSFact{Hostname: "app.example.com", Hops: ok[:1], FinalStatus: 302, TooManyRedirects: true}, "app.example.com", checks.Warn, "more than 10"},
		{"downgrade", &HTTPSFact{Hostname: "app.example.com", Hops: ok, FinalStatus: 200, Downgrade: true}, "app.example.com", checks.Warn, "plain HTTP"},
		{"tls", &HTTPSFact{Hostname: "app.example.com", Hops: []Hop{}, TLSError: "certificate signed by unknown authority"}, "app.example.com", checks.Warn, "TLS failed"},
		{"expiring", &HTTPSFact{Hostname: "app.example.com", Hops: ok, FinalStatus: 200, CertNotAfter: &soon}, "app.example.com", checks.Warn, "expires in 5 days"},
		{"expired", &HTTPSFact{Hostname: "app.example.com", Hops: ok, FinalStatus: 200, CertNotAfter: &past}, "app.example.com", checks.Warn, "expired"},
		{"5xx", &HTTPSFact{Hostname: "app.example.com", Hops: ok[1:], FinalStatus: 502}, "app.example.com", checks.Warn, "answers with 502"},
		{"no answer", &HTTPSFact{Hostname: "app.example.com", Hops: []Hop{}, Error: "i/o timeout"}, "app.example.com", checks.Unknown, "i/o timeout"},
		{"off host", &HTTPSFact{Hostname: "app.example.com", Hops: ok[:1], FinalStatus: 302, OffHost: "https://id.example.com"}, "app.example.com", checks.Pass, "not followed"},
	}
	for _, tc := range cases {
		f := fakeFacts(nil)
		f.Hostname, f.HTTPS = tc.host, tc.h
		r := runCheck(t, "PRB-006", f, profile.Unknown)
		if len(r) != 1 || r[0].Level != tc.want || !strings.Contains(r[0].Message, tc.text) {
			t.Errorf("%s: %+v", tc.name, r)
		}
	}
}

func TestEvaluateBuildsProbeReport(t *testing.T) {
	f := fakeFacts(map[int][2]string{22: {Open, Closed}})
	rep, err := Evaluate(f, EvalOptions{Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Probe == nil || rep.Probe.Target != v4 || len(rep.Probe.Ports) != len(f.Ports) {
		t.Fatalf("probe section: %+v", rep.Probe)
	}
	if rep.Profile.Name != profile.Unknown || rep.Profile.Source != "inferred" || !strings.Contains(strings.Join(rep.Probe.Notes, "\n"), "profile unknown") {
		t.Errorf("auto profile must be unknown and explained: %+v %v", rep.Profile, rep.Probe.Notes)
	}
	for _, it := range rep.Results {
		if it.Group != "PRB" || it.Title == "" {
			t.Errorf("result %+v", it)
		}
	}
	if rep.Coverage.Checks != len(Checks()) {
		t.Errorf("coverage checks = %d", rep.Coverage.Checks)
	}
	rep, _ = Evaluate(f, EvalOptions{Version: "test", Profile: profile.PublicWeb, ProfileSet: true})
	if rep.Profile.Source != "flag" || strings.Contains(strings.Join(rep.Probe.Notes, "\n"), "profile unknown") {
		t.Errorf("flag profile: %+v %v", rep.Profile, rep.Probe.Notes)
	}
}
