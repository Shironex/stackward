package apply_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Shironex/stackward/internal/apply"
	"github.com/Shironex/stackward/internal/apply/applytest"
	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/plan"
	"github.com/Shironex/stackward/internal/plan/txntest"
)

func liveFacts() *facts.Facts { return applytest.GuardFacts(&facts.Facts{}) }

// Apply proves the second way in again from the live host: the plan's
// facts may be stale, so a key removed since the plan refuses the step.
func TestGuardAccessFromTheLiveHost(t *testing.T) {
	p := applytest.TxnPlan(t)
	pwOff := applytest.Step(t, p, txntest.KeysOnlyID)
	good := applytest.Step(t, p, txntest.GoodID)
	if !apply.NeedsProof([]plan.Step{pwOff}) || apply.NeedsProof([]plan.Step{good}) {
		t.Fatal("password-off needs a proof, LoginGraceTime does not")
	}
	sess := apply.Session{SSHConnection: "192.0.2.10 50022 198.51.100.5 22", LoginUID: "1000"}
	proofs, err := apply.GuardAccess([]plan.Step{pwOff}, liveFacts(), sess)
	if err != nil || len(proofs) != 1 || !strings.Contains(proofs[0].Ways[0], "alice (sudo, authorized key) logs in with a key from 192.0.2.10") {
		t.Fatalf("proofs %+v, err %v", proofs, err)
	}
	if got := apply.ConfirmFrom(proofs); got != nil {
		t.Errorf("public SSH stays open, the confirm may come from anywhere: %v", got)
	}

	stale := liveFacts()
	stale.SSH.Users = nil
	_, err = apply.GuardAccess([]plan.Step{pwOff}, stale, sess)
	if err == nil || !strings.Contains(err.Error(), "lockout guard: txn-test-keys-only sets password authentication") ||
		!strings.Contains(err.Error(), "alice: no usable authorized key") {
		t.Errorf("err %v", err)
	}

	closePub := applytest.Step(t, p, txntest.ClosePublicID)
	proofs, err = apply.GuardAccess([]plan.Step{closePub}, liveFacts(), sess)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(apply.ConfirmFrom(proofs), " "); got != "100.64.0.0/10 fd7a:115c:a1e0::/48" {
		t.Errorf("confirm from %q", got)
	}
	down := liveFacts()
	down.Tailscale.BackendState = "NeedsLogin"
	if _, err = apply.GuardAccess([]plan.Step{closePub}, down, sess); err == nil || !strings.Contains(err.Error(), "NeedsLogin, not Running") {
		t.Errorf("err %v", err)
	}
}

func TestSessionClientAddr(t *testing.T) {
	for conn, want := range map[string]string{
		"192.0.2.10 50022 198.51.100.5 22":   "192.0.2.10",
		"2001:db8::7 50022 2001:db8::1 22":   "2001:db8::7",
		"::ffff:192.0.2.10 1 198.51.100.5 2": "192.0.2.10",
		"":                                   "invalid IP",
		"not-an-address 1 2 3":               "invalid IP",
	} {
		if got := (apply.Session{SSHConnection: conn}).ClientAddr().String(); got != want {
			t.Errorf("%q: %s, want %s", conn, got, want)
		}
	}
}

// A transaction that closed public SSH is confirmed only from a new
// session over the way the guard proved; --console stays the way out.
func TestConfirmMustComeOverTheProvenWay(t *testing.T) {
	g := newTxnRig(t)
	ctx := context.Background()
	steps := mustSelect(t, g.p, []string{txntest.ClosePublicID}, false)
	prepared, err := apply.Prepare(g.h, steps)
	if err != nil {
		t.Fatal(err)
	}
	base, err := apply.Preflight(ctx, g.h)
	if err != nil {
		t.Fatal(err)
	}
	o := options(g.h, txnID)
	o.Now = g.clock
	from := []string{plan.TailnetV4.String(), plan.TailnetV6.String()}
	_, st, err := apply.RunTransaction(ctx, prepared, apply.TxnOptions{
		Options: o, ConfirmWithin: time.Minute, Session: applying, Exe: applytest.Exe, Baseline: base, ConfirmFrom: from,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(g.state(t).ConfirmFrom, " ") != strings.Join(from, " ") {
		t.Fatalf("state %+v", g.state(t))
	}
	validateAgainst(t, "schema/transaction.v1.json", filepath.Join(g.root, apply.TxnStatePath))
	public := apply.Session{SSHConnection: "198.51.100.20 50544 198.51.100.5 22", AuditSession: "9", SSHD: "900:7000"}
	_, err = apply.ConfirmTxn(ctx, g.h, st, false, public, g.now)
	if err == nil || !strings.Contains(err.Error(), "closed public SSH") || !strings.Contains(err.Error(), "comes from 198.51.100.20") {
		t.Fatalf("a confirm over public SSH: %v", err)
	}
	if g.state(t).Status != apply.TxnOpen {
		t.Fatal("a refused confirm changed the state")
	}
	tailnet := apply.Session{SSHConnection: "100.101.102.103 50544 100.64.0.5 22", AuditSession: "9", SSHD: "900:7000"}
	why, err := apply.ConfirmTxn(ctx, g.h, st, false, tailnet, g.now)
	if err != nil || !strings.Contains(why, "comes from 100.101.102.103, over the way the lockout guard proved") {
		t.Fatalf("why %q, err %v", why, err)
	}
}
