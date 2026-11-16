package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/provider"
	"github.com/Shironex/stackward/internal/report"
)

func TestProviderFlags(t *testing.T) {
	cases := []struct {
		args []string
		want string
	}{
		{[]string{"audit", "--no-sandbox", "--provider", "aws"}, "--provider must be one of"},
		{[]string{"audit", "--no-sandbox", "--provider-ip", "192.0.2.10"}, "--provider-ip needs --provider"},
		{[]string{"audit", "--no-sandbox", "--provider", "hetzner", "--provider-ip", "2001:db8::1"}, "must be an IPv4 address"},
		{[]string{"audit", "--no-sandbox", "--provider", "hetzner", "--facts", fixture("pfw-hetzner-ok")}, "cannot be combined with --facts"},
		{[]string{"plan", "--no-sandbox", "--provider", "hetzner", "--facts", fixture("pfw-hetzner-ok")}, "cannot be combined with --facts"},
		// There is no flag for a token.
		{[]string{"audit", "--no-sandbox", "--provider", "hetzner", "--token", "x"}, "flag provided but not defined"},
	}
	for _, c := range cases {
		code, _, errs := run(c.args...)
		if code != report.ExitError || !strings.Contains(errs, c.want) {
			t.Errorf("%v: exit %d, stderr %q, want %q", c.args, code, errs, c.want)
		}
	}
}

func TestAuditHelpNamesReadToken(t *testing.T) {
	_, _, errs := run("audit", "-h")
	for _, want := range []string{"--provider", provider.EnvHetznerToken, "never from a flag", "with permission Read"} {
		if !strings.Contains(errs, want) {
			t.Errorf("audit help lacks %q", want)
		}
	}
}

func TestFetchProviderNotRequestedSendsNothing(t *testing.T) {
	if pf := fetchProvider(context.Background(), providerFlags{}, nil); pf != nil {
		t.Errorf("no --provider gave %+v", pf)
	}
}

func TestFetchProviderWithoutCredentials(t *testing.T) {
	t.Setenv(provider.EnvHetznerToken, "")
	t.Setenv(provider.EnvHetznerTokenFile, "")
	pf := fetchProvider(context.Background(), providerFlags{name: "hetzner", ip: "192.0.2.10"}, nil)
	if pf == nil || pf.Status != facts.ProviderNoCredentials {
		t.Errorf("pf = %+v", pf)
	}
}

func TestDumpFactsMasksProviderAddress(t *testing.T) {
	code, out, errs := run("audit", "--no-sandbox", "--facts", fixture("pfw-hetzner-ok"), "--dump-facts")
	if code != report.ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	f, err := facts.Load(strings.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	if got := f.ProviderFirewall.Targets[0].Address; got != "203.0.113.x" {
		t.Errorf("provider address in dump = %q", got)
	}
	if len(f.ProviderFirewall.Targets[0].Rules) != 4 {
		t.Errorf("rules lost in dump: %+v", f.ProviderFirewall.Targets[0])
	}
}
