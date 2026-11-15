package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/apply"
	"github.com/Shironex/stackward/internal/apply/applytest"
	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/plan"
	"github.com/Shironex/stackward/internal/plan/txntest"
	"github.com/Shironex/stackward/internal/report"
)

// The lockout guard and the never touched list through the command line.
// This file sorts after plan_test.go on purpose: it registers the
// test-only access steps, which the plan tests before it do not expect.

// guardFactsFile writes the plan fixture's facts with the guard's facts
// laid over (then changed by edit) to a temporary file.
func guardFactsFile(t *testing.T, edit func(f *facts.Facts)) string {
	t.Helper()
	fh, err := os.Open(fixture("plan-host-settings-fix"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fh.Close() }()
	f, err := facts.Load(fh)
	if err != nil {
		t.Fatal(err)
	}
	applytest.GuardFacts(f)
	if edit != nil {
		edit(f)
	}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "facts.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestPlanRefusesALockoutStepWithItsReason(t *testing.T) {
	txntest.Register()
	noKey := guardFactsFile(t, func(f *facts.Facts) { f.SSH.Users = nil })
	code, out, errs := run("plan", "--no-sandbox", "--facts", noKey, "--json")
	if code != report.ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	p := decodePlan(t, []byte(out))
	var refused *plan.Skipped
	for i, s := range p.Skipped {
		if s.ID == txntest.KeysOnlyID {
			refused = &p.Skipped[i]
		}
	}
	want := "lockout guard: txn-test-keys-only sets password authentication (passwordauthentication no), and no second way in exists: " +
		"it needs a non-root sudo user with an authorized key (alice: no usable authorized key (it would log in with a password only))"
	if refused == nil || refused.Kind != plan.SkipRefused || refused.Reason != want {
		t.Fatalf("skipped %+v\nwant reason %q", refused, want)
	}
	for _, s := range p.Steps {
		if s.ID == txntest.KeysOnlyID {
			t.Error("the refused step is in the plan")
		}
	}
	// The summary a person reads shows the step as refused, with the
	// reason, and the step that narrows nothing is planned.
	code, out, _ = run("plan", "--no-sandbox", "--facts", noKey)
	if code != report.ExitOK || !strings.Contains(out, txntest.KeysOnlyID) || !strings.Contains(out, "alice: no usable authorized key") {
		t.Errorf("exit %d:\n%s", code, out)
	}
	if !strings.Contains(out, txntest.GoodID) {
		t.Errorf("txn-test-sshd narrows nothing and must be planned:\n%s", out)
	}

	// With the key, the step is planned.
	code, out, errs = run("plan", "--no-sandbox", "--facts", guardFactsFile(t, nil), "--json")
	if code != report.ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	found := false
	for _, s := range decodePlan(t, []byte(out)).Steps {
		found = found || s.ID == txntest.KeysOnlyID
	}
	if !found {
		t.Error("txn-test-keys-only is not planned although alice has a key")
	}
}

// Apply proves the second way in again from the live host: the key that
// the plan saw is gone, so the step is refused and nothing changes.
func TestApplyRefusesWhenTheLiveHostLostTheSecondWayIn(t *testing.T) {
	x := newTxnTest(t)
	x.env.liveFacts = func(context.Context) *facts.Facts {
		f := applytest.GuardFacts(&facts.Facts{})
		f.SSH.Users = nil
		return f
	}
	code, out, errs := x.apply("--step", txntest.KeysOnlyID, "--yes", x.plan)
	if code != report.ExitError || !strings.Contains(errs, "lockout guard: txn-test-keys-only") ||
		!strings.Contains(errs, "alice: no usable authorized key") || !strings.Contains(errs, "nothing was changed") {
		t.Fatalf("exit %d: %s\n%s", code, out, errs)
	}
	if x.exists(txntest.KeysOnlyPath) || x.exists(apply.TxnStatePath) || x.sys.Active("stackward-rollback-"+txnRunID+".timer") {
		t.Error("a refused step changed the host")
	}

	// The live host has the key: the transaction opens and says which
	// way in it proved.
	x.env.liveFacts = func(context.Context) *facts.Facts { return applytest.GuardFacts(&facts.Facts{}) }
	code, out, errs = x.apply("--step", txntest.KeysOnlyID, "--yes", x.plan)
	if code != report.ExitOK {
		t.Fatalf("exit %d: %s\n%s", code, out, errs)
	}
	for _, want := range []string{
		"lockout guard: proving a second way in", "txn-test-keys-only sets password authentication",
		"second way in: alice (sudo, authorized key) logs in with a key from 192.0.2.10 over SSH on port 22",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if !x.exists(txntest.KeysOnlyPath) {
		t.Error("the drop-in was not written")
	}
}

// A transaction that closes public SSH must be confirmed over the tailnet.
func TestClosingPublicSSHIsConfirmedOverTheTailnet(t *testing.T) {
	x := newTxnTest(t)
	code, out, errs := x.apply("--step", txntest.ClosePublicID, "--confirm-within", "1m", "--yes", x.plan)
	if code != report.ExitOK {
		t.Fatalf("exit %d: %s\n%s", code, out, errs)
	}
	if !strings.Contains(out, "second way in: alice (sudo, authorized key) logs in with a key from the tailnet over the tailnet") ||
		!strings.Contains(out, "that session must come over the way that stays: from 100.64.0.0/10, fd7a:115c:a1e0::/48") {
		t.Errorf("output:\n%s", out)
	}
	// secondSession is a new session, but over public SSH.
	code, _, errs = x.confirm(secondSession, txnRunID)
	if code != report.ExitError || !strings.Contains(errs, "closed public SSH") {
		t.Fatalf("a confirm over public SSH: exit %d: %s", code, errs)
	}
	overTailnet := apply.Session{SSHConnection: "100.101.102.103 50544 100.64.0.5 22", AuditSession: "11", SSHD: "1100:9000"}
	if code, out, errs = x.confirm(overTailnet, txnRunID); code != report.ExitOK {
		t.Fatalf("a confirm over the tailnet: exit %d: %s\n%s", code, out, errs)
	}
	if st := x.state(t); st.Status != apply.TxnConfirmed {
		t.Errorf("state %+v", st)
	}
}

// The tailnet is down on the live host: closing public SSH is refused.
func TestClosingPublicSSHWithoutATailnetIsRefused(t *testing.T) {
	x := newTxnTest(t)
	x.env.liveFacts = func(context.Context) *facts.Facts {
		f := applytest.GuardFacts(&facts.Facts{})
		f.Tailscale.BackendState = "NeedsLogin"
		return f
	}
	code, _, errs := x.apply("--step", txntest.ClosePublicID, "--yes", x.plan)
	if code != report.ExitError || !strings.Contains(errs, "public SSH must not close without a proven second way in") ||
		!strings.Contains(errs, "the Tailscale backend is NeedsLogin, not Running") {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if x.exists(txntest.ClosePublicPath) {
		t.Error("a refused step changed the host")
	}
}

// A plan edited after the fact to reach the never touched list is refused
// at apply time, even though plan never wrote such a step.
func TestApplyRefusesATamperedNeverTouchedStep(t *testing.T) {
	a := newApplyTest(t)
	rewritePlan(t, a, func(m map[string]any) {
		for _, s := range m["steps"].([]any) {
			step := s.(map[string]any)
			if step["id"] == "journald-cap" {
				step["touches"] = []any{"tailscale:logout"}
			}
		}
	})
	code, _, errs := a.apply("--step", "journald-cap", "--yes", a.plan)
	if code != report.ExitError || !strings.Contains(errs, "never touched: journald-cap reaches tailscale:logout") || !strings.Contains(errs, "nothing was changed") {
		t.Fatalf("exit %d: %s", code, errs)
	}
	assertUntouched(t, a)
}
