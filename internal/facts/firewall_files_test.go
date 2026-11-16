package facts

import (
	"context"
	"strings"
	"testing"
)

// The firewall collector keeps the text of the UFW files a plan step
// edits, and leaves out a file that is too long to keep.
func TestFirewallCollectorKeepsUFWFiles(t *testing.T) {
	conf := "# /etc/ufw/ufw.conf\nENABLED=no\nLOGLEVEL=low\n"
	sys := newFakeSystem(map[string]string{
		UFWConfPath:       conf,
		UFWDefaultPath:    "IPV6=yes\nDEFAULT_INPUT_POLICY=\"DROP\"\n",
		UFWUserRulesPath:  userRulesCapture,
		UFWAfterRulesPath: strings.Repeat("#\n", MaxUFWFileBytes/2+1),
	})
	var out Facts
	if err := (firewallCollector{}).Collect(context.Background(), sys, &out); err != nil {
		t.Fatal(err)
	}
	files := out.Firewall.UFW.Files
	if files[UFWConfPath] != conf || files[UFWUserRulesPath] != userRulesCapture {
		t.Errorf("files %v", files)
	}
	if _, ok := files[UFWAfterRulesPath]; ok {
		t.Error("an after.rules over the cap was kept")
	}
	if _, ok := files[UFWUser6RulesPath]; ok {
		t.Error("a missing user6.rules was kept")
	}
}

func TestFirewallCollectorNoUFWFiles(t *testing.T) {
	var out Facts
	if err := (firewallCollector{}).Collect(context.Background(), newFakeSystem(nil), &out); err != nil {
		t.Fatal(err)
	}
	if out.Firewall.UFW.Files != nil {
		t.Errorf("files %v without UFW", out.Firewall.UFW.Files)
	}
}
