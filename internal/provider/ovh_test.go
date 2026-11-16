package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/redact"
)

// Test credentials, assembled at run time; none of them is real.
var (
	testAppKey    = strings.Repeat("ak", 8)
	testAppSecret = strings.Repeat("Sx", 16)
	testConsumer  = strings.Repeat("ck", 16)
)

const ovhServerTime = 1789560000

func ovhAnswers() map[string]answer {
	b := "/1.0/ip/192.0.2.10%2F32/firewall"
	a := map[string]answer{
		"/1.0/auth/time":                      {body: "1789560000"},
		"/1.0/ip?ip=192.0.2.10":               {file: "ovh/ip_192.0.2.10.json"},
		"/1.0/ip?ip=198.51.100.20":            {file: "ovh/ip_198.51.100.20.json"},
		"/1.0/ip?ip=192.0.2.12":               {file: "ovh/ip_192.0.2.12.json"},
		"/1.0/ip?ip=203.0.113.30":             {file: "ovh/ip_empty.json"},
		b:                                     {file: "ovh/firewall_192.0.2.10.json"},
		b + "/192.0.2.10":                     {file: "ovh/firewall_ip_192.0.2.10.json"},
		b + "/192.0.2.10/rule":                {file: "ovh/rules_192.0.2.10.json"},
		"/1.0/ip/198.51.100.16%2F28/firewall": {file: "ovh/firewall_none.json"},
		"/1.0/ip/192.0.2.12%2F32/firewall":    {file: "ovh/firewall_192.0.2.12.json"},
		"/1.0/ip/192.0.2.12%2F32/firewall/192.0.2.12":         {file: "ovh/firewall_ip_192.0.2.12.json"},
		"/1.0/ip/192.0.2.12%2F32/firewall/192.0.2.12/rule":    {file: "ovh/rules_192.0.2.12.json"},
		"/1.0/ip/192.0.2.12%2F32/firewall/192.0.2.12/rule/0":  {file: "ovh/rule_192.0.2.12_0.json"},
		"/1.0/ip/192.0.2.12%2F32/firewall/192.0.2.12/rule/19": {file: "ovh/rule_192.0.2.12_19.json"},
	}
	for _, seq := range []string{"0", "1", "2", "3", "4", "5", "6", "7", "19"} {
		a[b+"/192.0.2.10/rule/"+seq] = answer{file: "ovh/rule_192.0.2.10_" + seq + ".json"}
	}
	return a
}

func ovhEnv() map[string]string {
	return map[string]string{EnvOVHAppKey: testAppKey, EnvOVHAppSecret: testAppSecret, EnvOVHConsumer: testConsumer}
}

// localClock runs 30 s behind the server, so the signature must use the
// server time.
func localClock() time.Time { return time.Unix(ovhServerTime-30, 0) }

func fetchOVHWith(t *testing.T, rec *recorder, addrs ...string) *facts.ProviderFirewall {
	t.Helper()
	return Fetch(context.Background(), Options{Provider: OVH, Addresses: addrs, Env: envOf(ovhEnv()),
		Timeout: 5 * time.Second, Transport: rec, Now: localClock})
}

// assertSigned checks every authenticated request carries a valid OVH
// signature over the URL the client sent, and no secret in the URL.
func assertSigned(t *testing.T, rec *recorder) {
	t.Helper()
	rec.mu.Lock()
	defer rec.mu.Unlock()
	for _, q := range rec.seen {
		if q.URL.Path == "/1.0/auth/time" {
			if q.Header.Get("X-Ovh-Signature") != "" || q.Header.Get("X-Ovh-Application") != "" {
				t.Error("the time request carries credentials")
			}
			continue
		}
		full := "https://eu.api.ovh.com" + q.URL.EscapedPath()
		if q.URL.RawQuery != "" {
			full += "?" + q.URL.RawQuery
		}
		ts := q.Header.Get("X-Ovh-Timestamp")
		if ts != "1789560000" {
			t.Errorf("timestamp %q, want the server time", ts)
		}
		if want := ovhSignature(testAppSecret, testConsumer, "GET", full, "", ts); q.Header.Get("X-Ovh-Signature") != want {
			t.Errorf("%s: bad signature", full)
		}
		if q.Header.Get("X-Ovh-Application") != testAppKey || q.Header.Get("X-Ovh-Consumer") != testConsumer {
			t.Errorf("%s: missing key headers", full)
		}
		for _, secret := range []string{testAppSecret, testConsumer, testAppKey} {
			if strings.Contains(q.URL.String(), secret) {
				t.Errorf("credential in URL %s", q.URL)
			}
		}
	}
}

func TestOVHSignatureKnownValue(t *testing.T) {
	// From the shell: printf '%s' 'S+C+GET+https://eu.api.ovh.com/1.0/auth/time++1' | shasum -a 1
	got := ovhSignature("S", "C", "GET", "https://eu.api.ovh.com/1.0/auth/time", "", "1")
	if want := "$1$67462aa809d3a35b282358d621b5d30c68268388"; got != want {
		t.Errorf("signature %q, want %q", got, want)
	}
}

func TestOVHWorkingRuleSet(t *testing.T) {
	rec := newRecorder(t, ovhAnswers())
	pf := fetchOVHWith(t, rec, "192.0.2.10")
	rec.assertClean("")
	assertSigned(t, rec)
	if pf.Status != facts.ProviderOK || pf.Stateful || pf.IPv6Filtered || len(pf.Targets) != 1 {
		t.Fatalf("pf = %+v", pf)
	}
	tg := pf.Targets[0]
	if !tg.Attached || !tg.Enabled || tg.Pending || tg.State != "ok" || tg.DefaultInbound != "allow" || !tg.Ordered ||
		!tg.RulesComplete || len(tg.Rules) != 9 {
		t.Fatalf("target = %+v", tg)
	}
	est, ssh, quic, deny := tg.Rules[0], tg.Rules[1], tg.Rules[2], tg.Rules[8]
	if est.TCPOption != "established" || est.Sources != nil || est.Direction != "in" {
		t.Errorf("established rule = %+v", est)
	}
	if ssh.Sources[0] != "203.0.113.7/32" || ssh.DstPorts[0] != (facts.PortRange{From: 22, To: 22}) {
		t.Errorf("ssh rule = %+v", ssh)
	}
	if quic.SrcPorts[0] != (facts.PortRange{From: 7844, To: 7844}) || quic.DstPorts != nil {
		t.Errorf("quic rule = %+v", quic)
	}
	if deny.Order != 19 || deny.Action != "deny" || deny.Protocol != "ipv4" {
		t.Errorf("deny rule = %+v", deny)
	}
	b, _ := json.Marshal(pf)
	for _, leak := range []string{"creationDate", "2026-01-10", testAppSecret, testConsumer} {
		if strings.Contains(string(b), leak) {
			t.Errorf("facts hold %q", leak)
		}
	}
}

func TestOVHNoFirewallObjectAndNoMatch(t *testing.T) {
	rec := newRecorder(t, ovhAnswers())
	pf := fetchOVHWith(t, rec, "198.51.100.20", "203.0.113.30")
	if len(pf.Targets) != 2 {
		t.Fatalf("pf = %+v", pf)
	}
	if tg := pf.Targets[0]; tg.Status != facts.ProviderOK || tg.Attached || tg.Enabled || len(tg.Rules) != 0 {
		t.Errorf("no firewall object: %+v", tg)
	}
	if tg := pf.Targets[1]; tg.Status != facts.ProviderNoMatch {
		t.Errorf("no match: %+v", tg)
	}
}

func TestOVHDisabledWithPendingRule(t *testing.T) {
	rec := newRecorder(t, ovhAnswers())
	tg := fetchOVHWith(t, rec, "192.0.2.12").Targets[0]
	if !tg.Attached || tg.Enabled || !tg.Pending || len(tg.Rules) != 2 {
		t.Fatalf("target = %+v", tg)
	}
	if r := tg.Rules[0]; !r.Pending || r.DstPorts[0] != (facts.PortRange{From: 8000, To: 8100}) {
		t.Errorf("pending rule = %+v", r)
	}
}

func TestOVHFailures(t *testing.T) {
	cases := []struct {
		name   string
		edit   func(map[string]answer)
		status facts.ProviderStatus
		reason string
	}{
		{"denied", func(a map[string]answer) {
			a["/1.0/ip?ip=192.0.2.10"] = answer{status: http.StatusForbidden, body: `{"message":"This call has not been granted"}`}
		}, facts.ProviderDenied, "403"},
		{"time unreadable", func(a map[string]answer) { a["/1.0/auth/time"] = answer{body: "soon"} }, facts.ProviderError, "auth/time"},
		{"rule missing", func(a map[string]answer) { delete(a, "/1.0/ip/192.0.2.10%2F32/firewall/192.0.2.10/rule/4") }, facts.ProviderOK, ""},
		{"rule unparsable", func(a map[string]answer) {
			a["/1.0/ip/192.0.2.10%2F32/firewall/192.0.2.10/rule/4"] = answer{body: `{"sequence":4,"action":"permit","protocol":"udp","sourcePort":"neq 53","state":"ok"}`}
		}, facts.ProviderOK, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := ovhAnswers()
			c.edit(a)
			rec := newRecorder(t, a)
			pf := fetchOVHWith(t, rec, "192.0.2.10")
			if c.status != facts.ProviderOK {
				st, reason := pf.Status, pf.Reason
				if len(pf.Targets) == 1 {
					st, reason = pf.Targets[0].Status, pf.Targets[0].Reason
				}
				if st != c.status || !strings.Contains(reason, c.reason) {
					t.Errorf("status %s reason %q", st, reason)
				}
				return
			}
			if tg := pf.Targets[0]; tg.RulesComplete || len(tg.Rules) != 8 {
				t.Errorf("partial read: %+v", tg)
			}
		})
	}
}

func TestOVHCredentials(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := write("good", "# stackward OVH\n"+EnvOVHAppKey+"="+testAppKey+"\n"+EnvOVHAppSecret+"="+testAppSecret+"\n"+
		EnvOVHConsumer+"="+testConsumer+"\n"+EnvOVHEndpoint+"=ovh-ca\n", 0o600)
	stray := write("stray", "AWS_SECRET="+testAppSecret+"\n", 0o600)
	cases := []struct {
		name string
		env  map[string]string
		ok   bool
		want string
	}{
		{"env", ovhEnv(), true, "ovh-eu"},
		{"file", map[string]string{EnvOVHCredsFile: good}, true, "ovh-ca"},
		{"none", map[string]string{}, false, "no credentials"},
		{"both", map[string]string{EnvOVHCredsFile: good, EnvOVHAppKey: testAppKey}, false, "both"},
		{"missing secret", map[string]string{EnvOVHAppKey: testAppKey, EnvOVHConsumer: testConsumer}, false, EnvOVHAppSecret},
		{"bad endpoint", func() map[string]string { e := ovhEnv(); e[EnvOVHEndpoint] = "ovh-mars"; return e }(), false, "ovh-eu, ovh-ca or ovh-us"},
		{"stray line", map[string]string{EnvOVHCredsFile: stray}, false, "line 1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ovhCredentials(envOf(c.env))
			if c.ok {
				if err != nil || got.endpoint != c.want || got.appSecret != testAppSecret {
					t.Errorf("creds %+v err %v", got.endpoint, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err %v, want %q", err, c.want)
			}
			if err != nil && strings.Contains(err.Error(), testAppSecret) {
				t.Error("secret echoed in an error")
			}
		})
	}
	if got := redact.String("x " + testAppSecret + " " + testConsumer); strings.Contains(got, testAppSecret) || strings.Contains(got, testConsumer) {
		t.Errorf("OVH secrets not registered for redaction: %q", got)
	}
}

func TestAutoPicksByCredentials(t *testing.T) {
	both := ovhEnv()
	both[EnvHetznerToken] = testToken
	if pf := Fetch(context.Background(), Options{Provider: Auto, Env: envOf(both)}); pf.Status != facts.ProviderNoCredentials || !strings.Contains(pf.Reason, "name the provider") {
		t.Errorf("both: %+v", pf)
	}
	rec := newRecorder(t, ovhAnswers())
	pf := Fetch(context.Background(), Options{Provider: Auto, Addresses: []string{"192.0.2.10"}, Env: envOf(ovhEnv()), Transport: rec, Now: localClock})
	if pf.Provider != OVH || pf.Status != facts.ProviderOK {
		t.Errorf("auto with OVH credentials: %+v", pf)
	}
}

func TestParseOVHPorts(t *testing.T) {
	str := func(s string) *string { return &s }
	for in, want := range map[string]string{"53": "53", "eq 53": "53", "1000-2000": "1000-2000", "range 1000 2000": "1000-2000",
		"gt 1023": "1024-65535", "lt 1024": "1-1023", "": ""} {
		got, err := parseOVHPorts(str(in))
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
	for _, bad := range []string{"neq 53", "gt 65535", "lt 1", "eq", "1 2 3 4"} {
		if _, err := parseOVHPorts(str(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if got, err := parseOVHPorts(nil); err != nil || got != nil {
		t.Errorf("nil: %v %v", got, err)
	}
}
