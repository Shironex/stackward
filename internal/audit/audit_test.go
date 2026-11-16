package audit

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/facts"
)

func TestDumpFactsMasksProviderAddresses(t *testing.T) {
	f := &facts.Facts{Schema: facts.SchemaVersion, ProviderFirewall: &facts.ProviderFirewall{
		Provider: "ovh", Status: facts.ProviderOK,
		Reason: "GET https://eu.api.ovh.com/1.0/ip?ip=192.0.2.10 failed",
		Targets: []facts.ProviderTarget{{
			Address: "192.0.2.10", Status: facts.ProviderError,
			Reason: "decoding /ip/192.0.2.10%2F32/firewall/192.0.2.10: bad",
			Rules:  []facts.ProviderRule{{Sources: []string{"203.0.113.7/32", "2001:db8:1:2:3::9/128", "0.0.0.0/0", "198.51.100.77 junk"}}},
		}},
	}}
	var b bytes.Buffer
	if err := DumpFacts(&b, f, false); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, leak := range []string{"192.0.2.10", "203.0.113.7", "2001:db8:1:2:3::9", "198.51.100.77"} {
		if strings.Contains(out, leak) {
			t.Errorf("dump holds %s:\n%s", leak, out)
		}
	}
	for _, want := range []string{`"192.0.2.x"`, "ip=192.0.2.x", "203.0.113.0/32", "2001:db8:1:2::/128", "0.0.0.0/0", `"unparsed"`} {
		if !strings.Contains(out, want) {
			t.Errorf("dump lacks %s:\n%s", want, out)
		}
	}
	// The facts in memory are untouched.
	if f.ProviderFirewall.Targets[0].Address != "192.0.2.10" || f.ProviderFirewall.Targets[0].Rules[0].Sources[0] != "203.0.113.7/32" {
		t.Error("DumpFacts changed the live facts")
	}
}
