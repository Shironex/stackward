package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/redact"
)

// The test token is assembled at run time so the source holds no literal a
// secret scanner would take for a credential. It is not a real token.
var testToken = strings.Repeat("Tk", 16) + "-test-only"

// answer is one recorded response.
type answer struct {
	status int
	file   string // under testdata/
	body   string
	header map[string]string
}

// recorder is an httptest server that replays recorded answers and keeps
// every request it saw.
type recorder struct {
	t       *testing.T
	srv     *httptest.Server
	answers map[string]answer // keyed by path with query
	mu      sync.Mutex
	seen    []*http.Request
}

func newRecorder(t *testing.T, answers map[string]answer) *recorder {
	t.Helper()
	r := &recorder{t: t, answers: answers}
	r.srv = httptest.NewServer(http.HandlerFunc(r.serve))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *recorder) serve(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	r.seen = append(r.seen, req.Clone(context.Background()))
	r.mu.Unlock()
	key := req.URL.EscapedPath()
	if req.URL.RawQuery != "" {
		key += "?" + req.URL.RawQuery
	}
	a, ok := r.answers[key]
	if !ok {
		http.Error(w, `{"error":{"code":"not_found"}}`, http.StatusNotFound)
		return
	}
	for k, v := range a.header {
		w.Header().Set(k, v)
	}
	body := []byte(a.body)
	if a.file != "" {
		b, err := os.ReadFile(filepath.Join("testdata", a.file))
		if err != nil {
			r.t.Errorf("fixture: %v", err)
		}
		body = b
	}
	if a.status != 0 {
		w.WriteHeader(a.status)
	}
	_, _ = w.Write(body)
}

// RoundTrip sends the request to the test server, keeping its path and
// query. The client checked the real API host before this point.
func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	u, _ := url.Parse(r.srv.URL)
	out := req.Clone(req.Context())
	out.URL.Scheme, out.URL.Host, out.Host = u.Scheme, u.Host, u.Host
	return http.DefaultTransport.RoundTrip(out)
}

// assertClean checks every request was a GET and the token never reached
// a URL.
func (r *recorder) assertClean(token string) {
	r.t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.seen) == 0 {
		r.t.Error("no request reached the recorder")
	}
	for _, q := range r.seen {
		if q.Method != http.MethodGet {
			r.t.Errorf("%s %s: only GET is allowed", q.Method, q.URL)
		}
		if token != "" && strings.Contains(q.URL.String(), token) {
			r.t.Errorf("token in URL %s", q.URL)
		}
	}
}

func hetznerAnswers() map[string]answer {
	return map[string]answer{
		"/v1/primary_ips?ip=192.0.2.10":       {file: "hetzner/primary_ips_192.0.2.10.json"},
		"/v1/primary_ips?ip=192.0.2.11":       {file: "hetzner/primary_ips_192.0.2.11.json"},
		"/v1/primary_ips?ip=192.0.2.12":       {file: "hetzner/primary_ips_192.0.2.12.json"},
		"/v1/primary_ips?ip=198.51.100.20":    {file: "hetzner/primary_ips_empty.json"},
		"/v1/primary_ips?ip=203.0.113.99":     {file: "hetzner/primary_ips_empty.json"},
		"/v1/floating_ips?page=1&per_page=50": {file: "hetzner/floating_ips_page1.json"},
		"/v1/floating_ips?page=2&per_page=50": {file: "hetzner/floating_ips_page2.json"},
		"/v1/servers/42":                      {file: "hetzner/server_42.json"},
		"/v1/servers/43":                      {file: "hetzner/server_43.json"},
		"/v1/servers/44":                      {file: "hetzner/server_44.json"},
		"/v1/servers/45":                      {file: "hetzner/server_45.json"},
		"/v1/firewalls/7":                     {file: "hetzner/firewall_7.json"},
		"/v1/firewalls/8":                     {file: "hetzner/firewall_8.json"},
		"/v1/firewalls/9":                     {file: "hetzner/firewall_9.json"},
	}
}

func envOf(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func fetchWith(t *testing.T, rec *recorder, addrs ...string) *facts.ProviderFirewall {
	t.Helper()
	return Fetch(context.Background(), Options{
		Provider: Hetzner, Addresses: addrs, Env: envOf(map[string]string{EnvHetznerToken: testToken}),
		Timeout: 5 * time.Second, Transport: rec,
	})
}

func TestHetznerOneFirewall(t *testing.T) {
	rec := newRecorder(t, hetznerAnswers())
	pf := fetchWith(t, rec, "192.0.2.10")
	rec.assertClean(testToken)
	if pf.Status != facts.ProviderOK || !pf.Stateful || !pf.IPv6Filtered || len(pf.Targets) != 1 {
		t.Fatalf("pf = %+v", pf)
	}
	tg := pf.Targets[0]
	if tg.Status != facts.ProviderOK || !tg.Attached || !tg.Enabled || tg.Pending || tg.State != "applied" ||
		tg.Firewalls != 1 || tg.DefaultInbound != "deny" || tg.Ordered || !tg.RulesComplete || len(tg.Rules) != 4 {
		t.Fatalf("target = %+v", tg)
	}
	ssh := tg.Rules[0]
	if ssh.Direction != "in" || ssh.Action != "permit" || ssh.Protocol != "tcp" ||
		len(ssh.DstPorts) != 1 || ssh.DstPorts[0] != (facts.PortRange{From: 22, To: 22}) || ssh.Sources[0] != "203.0.113.7/32" {
		t.Errorf("ssh rule = %+v", ssh)
	}
	if icmp := tg.Rules[2]; icmp.Protocol != "icmp" || icmp.DstPorts != nil {
		t.Errorf("icmp rule = %+v", icmp)
	}
	if out := tg.Rules[3]; out.Direction != "out" || out.DstPorts != nil || len(out.Destinations) != 2 || out.Sources != nil {
		t.Errorf("out rule = %+v", out)
	}
	if rec.seen[0].Header.Get("Authorization") != "Bearer "+testToken {
		t.Error("no bearer token sent")
	}
	// Nothing provider specific beyond the rules is kept: no names, labels,
	// descriptions or ids.
	b, _ := json.Marshal(pf)
	for _, leak := range []string{"web-example", "panel ssh", "role", "4711", testToken} {
		if strings.Contains(string(b), leak) {
			t.Errorf("facts hold %q: %s", leak, b)
		}
	}
}

func TestHetznerSeveralFirewallsCombine(t *testing.T) {
	rec := newRecorder(t, hetznerAnswers())
	pf := fetchWith(t, rec, "192.0.2.11")
	tg := pf.Targets[0]
	if tg.Firewalls != 2 || len(tg.Rules) != 7 {
		t.Fatalf("target = %+v", tg)
	}
	for i, r := range tg.Rules {
		if r.Order != i {
			t.Errorf("rule %d has order %d", i, r.Order)
		}
	}
	// "1-65535" is every port.
	if udp := tg.Rules[4]; udp.Protocol != "udp" || udp.DstPorts != nil {
		t.Errorf("udp rule = %+v", udp)
	}
	if r := tg.Rules[6]; r.DstPorts[0] != (facts.PortRange{From: 27015, To: 27030}) {
		t.Errorf("range rule = %+v", r)
	}
}

func TestHetznerPendingFirewall(t *testing.T) {
	rec := newRecorder(t, hetznerAnswers())
	tg := fetchWith(t, rec, "192.0.2.12").Targets[0]
	if !tg.Attached || tg.Enabled || !tg.Pending || tg.State != "pending" || !tg.Rules[0].Pending {
		t.Errorf("target = %+v", tg)
	}
}

func TestHetznerFloatingIPPagedAndNoFirewall(t *testing.T) {
	rec := newRecorder(t, hetznerAnswers())
	tg := fetchWith(t, rec, "198.51.100.20").Targets[0]
	if tg.Status != facts.ProviderOK || tg.Attached || tg.Enabled || tg.Firewalls != 0 || len(tg.Rules) != 0 {
		t.Errorf("target = %+v", tg)
	}
}

func TestHetznerNoMatchIsAResult(t *testing.T) {
	rec := newRecorder(t, hetznerAnswers())
	pf := fetchWith(t, rec, "203.0.113.99", "192.0.2.10")
	if pf.Status != facts.ProviderOK || len(pf.Targets) != 2 {
		t.Fatalf("pf = %+v", pf)
	}
	if pf.Targets[0].Status != facts.ProviderNoMatch || pf.Targets[1].Status != facts.ProviderOK {
		t.Errorf("targets = %+v", pf.Targets)
	}
}

func TestHetznerFailures(t *testing.T) {
	big := `{"primary_ips":[` + strings.Repeat(`{"ip":"192.0.2.250"},`, 60000) + `{"ip":"192.0.2.251"}]}`
	cases := []struct {
		name   string
		answer answer
		status facts.ProviderStatus
		reason string
	}{
		{"unauthorized", answer{status: 401, body: `{"error":{"code":"unauthorized"}}`}, facts.ProviderDenied, "401"},
		{"forbidden", answer{status: 403, body: `{"error":{"code":"forbidden"}}`}, facts.ProviderDenied, "403"},
		{"rate limited", answer{status: 429, body: `{"error":{"code":"rate_limit_exceeded"}}`, header: map[string]string{"RateLimit-Remaining": "0"}}, facts.ProviderError, "rate limited"},
		{"redirect", answer{status: 302, header: map[string]string{"Location": "https://attacker.example.com/v1/primary_ips"}}, facts.ProviderError, "redirect"},
		{"over size cap", answer{body: big}, facts.ProviderError, "larger than"},
		{"malformed", answer{body: `{"primary_ips": "nope"}`}, facts.ProviderError, "decoding"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := newRecorder(t, map[string]answer{"/v1/primary_ips?ip=192.0.2.10": c.answer})
			pf := fetchWith(t, rec, "192.0.2.10")
			rec.assertClean(testToken)
			st, reason := pf.Status, pf.Reason
			if len(pf.Targets) == 1 {
				st, reason = pf.Targets[0].Status, pf.Targets[0].Reason
			}
			if st != c.status || !strings.Contains(reason, c.reason) {
				t.Errorf("status %s reason %q, want %s with %q (pf %+v)", st, reason, c.status, c.reason, pf)
			}
			if strings.Contains(reason, testToken) {
				t.Error("token in reason")
			}
		})
	}
}

func TestHetznerPartialRuleRead(t *testing.T) {
	a := hetznerAnswers()
	delete(a, "/v1/firewalls/8")
	rec := newRecorder(t, a)
	tg := fetchWith(t, rec, "192.0.2.11").Targets[0]
	if tg.Status != facts.ProviderOK || tg.RulesComplete || len(tg.Rules) != 4 {
		t.Errorf("target = %+v", tg)
	}
}

func TestHetznerRefusesUnparsableNetworks(t *testing.T) {
	a := hetznerAnswers()
	a["/v1/firewalls/7"] = answer{body: `{"firewall":{"rules":[
		{"direction":"in","protocol":"tcp","port":"22","source_ips":["0.0.0.0"]},
		{"direction":"in","protocol":"tcp","port":"443","source_ips":["0.0.0.0/0"]}]}}`}
	rec := newRecorder(t, a)
	tg := fetchWith(t, rec, "192.0.2.10").Targets[0]
	if tg.RulesComplete || len(tg.Rules) != 1 {
		t.Errorf("target = %+v", tg)
	}
}

func TestUnreachable(t *testing.T) {
	rec := newRecorder(t, nil)
	rec.srv.Close()
	pf := fetchWith(t, rec, "192.0.2.10")
	if pf.Status != facts.ProviderUnreachable {
		t.Errorf("pf = %+v", pf)
	}
}

func TestGetterRefusesOtherHostsAndMethods(t *testing.T) {
	rec := newRecorder(t, map[string]answer{"/x": {body: "{}"}})
	g := newGetter(rec, time.Second)
	for _, u := range []string{
		"http://api.hetzner.cloud/v1/x", "https://example.com/x", "https://api.hetzner.cloud:8443/x",
		"https://user:pw@api.hetzner.cloud/x", "https://api.hetzner.cloud.example.com/x",
	} {
		if _, err := g.get(context.Background(), u, nil); err == nil {
			t.Errorf("%s was allowed", u)
		}
	}
	if len(rec.seen) != 0 {
		t.Errorf("refused URLs reached the network: %d requests", len(rec.seen))
	}
}

func TestCredentials(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "token")
	if err := os.WriteFile(good, []byte(testToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loose := filepath.Join(dir, "loose")
	if err := os.WriteFile(loose, []byte(testToken), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	twoWords := filepath.Join(dir, "two")
	if err := os.WriteFile(twoWords, []byte("a b c d e f g h"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		env  map[string]string
		ok   bool
		want string
	}{
		{"env", map[string]string{EnvHetznerToken: testToken}, true, ""},
		{"file", map[string]string{EnvHetznerTokenFile: good}, true, ""},
		{"none", map[string]string{}, false, "no credentials"},
		{"both", map[string]string{EnvHetznerToken: testToken, EnvHetznerTokenFile: good}, false, "both"},
		{"group readable", map[string]string{EnvHetznerTokenFile: loose}, false, "chmod 600"},
		{"symlink", map[string]string{EnvHetznerTokenFile: link}, false, "symlink"},
		{"directory", map[string]string{EnvHetznerTokenFile: dir}, false, "not a regular file"},
		{"missing", map[string]string{EnvHetznerTokenFile: filepath.Join(dir, "nope")}, false, "no such file"},
		{"white space", map[string]string{EnvHetznerTokenFile: twoWords}, false, "white space"},
		// The vendor's own variable is never picked up.
		{"vendor name", map[string]string{"HCLOUD_TOKEN": testToken}, false, "no credentials"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tok, err := hetznerToken(envOf(c.env))
			if c.ok {
				if err != nil || tok != testToken {
					t.Errorf("token %q err %v", tok, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err %v, want %q", err, c.want)
			}
		})
	}
	// A loaded token is masked by the redaction pass.
	if got := redact.String("x " + testToken); strings.Contains(got, testToken) {
		t.Errorf("token not registered for redaction: %q", got)
	}
}

func TestFetchWithoutCredentials(t *testing.T) {
	pf := Fetch(context.Background(), Options{Provider: Hetzner, Addresses: []string{"192.0.2.10"}, Env: envOf(nil)})
	if pf.Status != facts.ProviderNoCredentials || !strings.Contains(pf.Reason, EnvHetznerToken) {
		t.Errorf("pf = %+v", pf)
	}
	pf = Fetch(context.Background(), Options{Provider: Auto, Env: envOf(nil)})
	if pf.Status != facts.ProviderNoCredentials {
		t.Errorf("auto pf = %+v", pf)
	}
	rec := newRecorder(t, hetznerAnswers())
	pf = Fetch(context.Background(), Options{Provider: Auto, Addresses: []string{"192.0.2.10"},
		Env: envOf(map[string]string{EnvHetznerToken: testToken}), Transport: rec})
	if pf.Provider != Hetzner || pf.Status != facts.ProviderOK {
		t.Errorf("auto with a Hetzner token: %+v", pf)
	}
	pf = Fetch(context.Background(), Options{Provider: Hetzner, Env: envOf(map[string]string{EnvHetznerToken: testToken}), Transport: rec})
	if pf.Status != facts.ProviderNoMatch || !strings.Contains(pf.Reason, "--provider-ip") {
		t.Errorf("no addresses: %+v", pf)
	}
}

func TestParsePortSpec(t *testing.T) {
	for in, want := range map[string]string{"22": "22", "80-85": "80-85", "any": "", "1-65535": "", "443": "443"} {
		got, err := parsePortSpec(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		s := ""
		if len(got) == 1 {
			s = got[0].String()
		}
		if s != want {
			t.Errorf("%q = %q, want %q", in, s, want)
		}
	}
	for _, bad := range []string{"0", "70000", "85-80", "x", "1-"} {
		if _, err := parsePortSpec(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
