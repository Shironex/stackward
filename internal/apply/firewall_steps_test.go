package apply_test

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Shironex/stackward/internal/apply"
	"github.com/Shironex/stackward/internal/apply/applytest"
	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/plan"
)

// The firewall steps (ufw-policy, ufw-docker) against a t.TempDir() root
// with the fake runner: run as a transaction, applied again, rolled back
// to the exact files and UFW state, refused when tampered with, and
// guarded against the applying session.

// fwTransaction applies the step id of the plan fixture name as a
// transaction and returns what the rollback needs.
func fwTransaction(t *testing.T, root, name, id string) (apply.Host, *applytest.Runner, []plan.Step, *apply.Journal, *apply.Txn, apply.Options) {
	t.Helper()
	h, r, _ := applytest.NewTxnHost(t, root)
	p := applytest.FixturePlan(t, name)
	applytest.Seed(t, root, p)
	steps := mustSelect(t, p, []string{id}, false)
	if !(apply.Selection{Steps: steps}).AccessCritical() {
		t.Fatalf("%s must run as a transaction", id)
	}
	ctx := context.Background()
	prepared, err := apply.Prepare(h, steps)
	if err != nil {
		t.Fatal(err)
	}
	base, err := apply.Preflight(ctx, h)
	if err != nil {
		t.Fatal(err)
	}
	o := options(h, txnID)
	o.Now = func() time.Time { return fixedNow }
	j, st, err := apply.RunTransaction(ctx, prepared, apply.TxnOptions{
		Options: o, ConfirmWithin: time.Minute, Session: applying, Exe: applytest.Exe, Baseline: base,
	})
	if err != nil || st.Status != apply.TxnOpen {
		t.Fatalf("transaction: %v %+v", err, st)
	}
	return h, r, steps, j, st, o
}

// appliedTwiceIsNothing checks a second run of steps changes nothing.
func appliedTwiceIsNothing(t *testing.T, h apply.Host, r *applytest.Runner, steps []plan.Step) {
	t.Helper()
	r.Reset()
	prepared, err := apply.Prepare(h, steps)
	if err != nil {
		t.Fatal(err)
	}
	if n := apply.ToRun(prepared); n != 0 || len(r.Calls()) != 0 {
		t.Errorf("second run would apply %d steps, ran %v", n, r.Calls())
	}
}

func TestUFWPolicyTransactionAndRollbackRestoreTheExactState(t *testing.T) {
	root := t.TempDir()
	h, r, steps, j, st, o := fwTransaction(t, root, "plan-firewall-ufw-policy", plan.UFWPolicyID)
	s := steps[0]
	for _, e := range s.Edits {
		if got, _ := applytest.Read(t, root, e.Path); got != e.New {
			t.Errorf("%s not written", e.Path)
		}
	}
	// The rules files are test loaded before UFW turns on, and UFW turns
	// on once, after every file is in place.
	enable := callIndex(r, "ufw --force enable")
	if enable < 0 || callIndex(r, "iptables-restore --test --noflush") < 0 || callIndex(r, "ip6tables-restore --test --noflush") < 0 ||
		callIndex(r, "iptables-restore --test") > enable || callIndex(r, "ip6tables-restore --test") > enable {
		t.Errorf("validate then enable: %v", r.Calls())
	}
	appliedTwiceIsNothing(t, h, r, steps)

	// The rollback puts every file back byte for byte and turns UFW off.
	r.Reset()
	if err := apply.RollBack(context.Background(), h, j, st, apply.CauseTimer, apply.UndoOptions{Host: h, Now: o.Now}); err != nil {
		t.Fatal(err)
	}
	for _, e := range s.Edits {
		if got, _ := applytest.Read(t, root, e.Path); got != e.Old {
			t.Errorf("%s not restored exactly", e.Path)
		}
	}
	if conf, _ := applytest.Read(t, root, facts.UFWConfPath); !strings.Contains(conf, "ENABLED=no") {
		t.Error("ufw.conf does not say disabled again")
	}
	if callIndex(r, "ufw disable") < 0 || callIndex(r, "ufw --force enable") >= 0 || callIndex(r, "ufw reset") >= 0 {
		t.Errorf("rollback commands %v", r.Calls())
	}
}

func TestUFWDockerTransactionAndUndoRestoreTheExactState(t *testing.T) {
	root := t.TempDir()
	h, r, steps, j, st, o := fwTransaction(t, root, "plan-firewall-ufw-docker", plan.UFWDockerID)
	s := steps[0]
	after, _ := applytest.Read(t, root, facts.UFWAfterRulesPath)
	if !strings.Contains(after, "# BEGIN UFW AND DOCKER") || after != s.Edits[1].New {
		t.Error("after.rules does not hold the ufw-docker block")
	}
	reload := callIndex(r, "ufw reload")
	if reload < 0 || callIndex(r, "iptables-restore --test --noflush") > reload {
		t.Errorf("validate then reload: %v", r.Calls())
	}
	for _, c := range r.Calls() {
		if c[0] == "curl" || c[0] == "wget" || (c[0] == "ufw" && slices.Contains(c, "enable")) {
			t.Errorf("unexpected command %v", c)
		}
	}
	appliedTwiceIsNothing(t, h, r, steps)

	r.Reset()
	if err := apply.RollBack(context.Background(), h, j, st, apply.CauseTimer, apply.UndoOptions{Host: h, Now: o.Now}); err != nil {
		t.Fatal(err)
	}
	for _, e := range s.Edits {
		if got, _ := applytest.Read(t, root, e.Path); got != e.Old {
			t.Errorf("%s not restored exactly", e.Path)
		}
	}
	// DOCKER-USER goes back to Docker's RETURN before UFW reloads the
	// old rules, and the logging chain goes last, once nothing jumps to it.
	var got []string
	for _, c := range r.Calls() {
		if c[0] == "iptables" || c[0] == "ufw" {
			got = append(got, strings.Join(c, " "))
		}
	}
	want := []string{
		"iptables -F DOCKER-USER", "iptables -A DOCKER-USER -j RETURN", "ufw reload",
		"iptables -F ufw-docker-logging-deny", "iptables -X ufw-docker-logging-deny",
	}
	if !slices.Equal(got, want) {
		t.Errorf("undo commands %v, want %v", got, want)
	}
}

func TestFirewallStepsTamperedAreRefused(t *testing.T) {
	pol := applytest.FixturePlan(t, "plan-firewall-ufw-policy")
	dk := applytest.FixturePlan(t, "plan-firewall-ufw-docker")
	rehash := func(e *plan.FileEdit) { e.NewSHA256 = plan.SHA256([]byte(e.New)) }
	for name, tc := range map[string]struct {
		p      *plan.Plan
		id     string
		tamper func(s *plan.Step)
		want   string
	}{
		"policy opens everything": {pol, plan.UFWPolicyID, func(s *plan.Step) {
			e := &s.Edits[0]
			e.New = strings.Replace(e.New, "-A ufw-user-input -p tcp --dport 22 -j ACCEPT", "-A ufw-user-input -j ACCEPT", 1)
			rehash(e)
		}, "not one the step adds"},
		"policy skips the test load": {pol, plan.UFWPolicyID, func(s *plan.Step) { s.Edits[0].Validate = []string{"true"} }, "validate"},
		"policy undo resets": {pol, plan.UFWPolicyID, func(s *plan.Step) {
			s.Undo.Commands[0].Args = []string{"ufw", "--force", "reset"}
		}, "not one the step runs"},
		"docker downloads": {dk, plan.UFWDockerID, func(s *plan.Step) {
			s.Commands = append([]plan.Command{{Args: []string{"wget", "-O", "/usr/local/bin/ufw-docker", "https://example.com/ufw-docker"}}}, s.Commands...)
		}, "commands"},
		"docker block loosened": {dk, plan.UFWDockerID, func(s *plan.Step) {
			e := &s.Edits[len(s.Edits)-1]
			e.New = strings.Replace(e.New, "-A DOCKER-USER -j ufw-docker-logging-deny -m conntrack --ctstate NEW -d 172.16.0.0/12\n", "", 1)
			rehash(e)
		}, "not what the step writes"},
		"docker touches ip_forward": {dk, plan.UFWDockerID, func(s *plan.Step) {
			s.Edits[len(s.Edits)-1].Path = "/etc/ufw/sysctl.conf"
		}, "edits /etc/ufw/sysctl.conf"},
	} {
		t.Run(name, func(t *testing.T) {
			s := clone(applytest.Step(t, tc.p, tc.id))
			tc.tamper(&s)
			h, r := applytest.NewHost(t.TempDir())
			_, err := apply.Prepare(h, []plan.Step{s})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v, want %q", err, tc.want)
			}
			if len(r.Calls()) != 0 {
				t.Errorf("commands ran: %v", r.Calls())
			}
		})
	}
}

// liveUFW is what the firewall collector reads on the live host before
// ufw-policy: UFW installed and off, sshd on port, with rules.
func liveUFW(port string, rules ...facts.UFWRule) *facts.Facts {
	return &facts.Facts{
		SSH:       &facts.SSH{Installed: true, Effective: map[string][]string{"port": {port}}},
		Listeners: &facts.Listeners{},
		Firewall: &facts.Firewall{UFW: &facts.UFW{Installed: true, Source: "live", Status: "inactive", IPv6: "yes",
			DefaultIncoming: "deny", RulesKnown: true, Rules: rules}},
	}
}

// Before the transaction, apply proves from the live host that SSH stays
// reachable for the session that applies: the port comes from sshd, and
// the session's source must be let in by the step's rules or the live
// ones.
func TestUFWPolicyGuardChecksTheApplyingSession(t *testing.T) {
	p := applytest.FixturePlan(t, "plan-firewall-ufw-policy")
	steps := mustSelect(t, p, []string{plan.UFWPolicyID}, false)
	if !apply.NeedsProof(steps) {
		t.Fatal("ufw-policy must go through the lockout guard")
	}
	// The plan adds SSH from anywhere on 22 and 2222: every session passes.
	proofs, err := apply.GuardAccess(steps, liveUFW("22"), applying)
	if err != nil || len(apply.ConfirmFrom(proofs)) != 0 {
		t.Errorf("ssh from anywhere: %+v %v", proofs, err)
	}
	// sshd moved to a port the plan does not open since the plan was made.
	if _, err := apply.GuardAccess(steps, liveUFW("2200"), applying); err == nil || !strings.Contains(err.Error(), "tcp/2200") {
		t.Errorf("a port the rules miss: %v", err)
	}
	// The live host denies the session's network before the plan's allow.
	deny := facts.UFWRule{Action: "deny", Direction: "in", Port: "22", Proto: "tcp", From: "192.0.2.0/24"}
	if _, err := apply.GuardAccess(steps, liveUFW("22", deny), applying); err == nil || !strings.Contains(err.Error(), "192.0.2.10") {
		t.Errorf("a deny for the session: %v", err)
	}
	// No sshd facts: the guard does not assume 22.
	noSSH := liveUFW("22")
	noSSH.SSH = nil
	if _, err := apply.GuardAccess(steps, noSSH, applying); err == nil || !strings.Contains(err.Error(), "does not assume 22") {
		t.Errorf("no sshd facts: %v", err)
	}
	// A step whose rules no longer let SSH in is refused before anything
	// runs, though each rule it adds is one the step may add.
	cut := clone(steps[0])
	for i := range cut.Edits[:2] {
		e := &cut.Edits[i]
		e.New = strings.NewReplacer(
			"### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in\n-A ufw-user-input -p tcp --dport 22 -j ACCEPT\n\n", "",
			"### tuple ### allow tcp 22 ::/0 any ::/0 in\n-A ufw6-user-input -p tcp --dport 22 -j ACCEPT\n\n", "",
		).Replace(e.New)
		e.NewSHA256 = plan.SHA256([]byte(e.New))
	}
	if _, err := apply.GuardAccess([]plan.Step{cut}, liveUFW("22"), applying); err == nil || !strings.Contains(err.Error(), "tcp/22") {
		t.Errorf("a step without the ssh rule: %v", err)
	}
	// UFW was turned on by hand since the plan: plan again.
	on := liveUFW("22")
	on.Firewall.UFW.Status = "active"
	if _, err := apply.GuardAccess(steps, on, console); err == nil {
		t.Error("an active UFW must refuse a plan that turns it on")
	}
}
