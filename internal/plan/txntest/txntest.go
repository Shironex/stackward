// Package txntest holds access-critical steps that exist only to test the
// rollback transaction and the lockout guard: no real step of this release
// is access-critical. Nothing registers them by default. Tests call
// Register, and so does the scenario binary (cmd/stackward built with the
// stackward_scenario tag); the released binary never imports this
// package, and a test in cmd/stackward proves it.
//
// Every step writes an sshd drop-in:
//
//   - txn-test-sshd sets LoginGraceTime 60 (sshd's default is 120) and
//     reloads ssh.service, so the transaction can apply it, validate it
//     with sshd -t and sshd -T, and roll it back. It narrows no way in, so
//     the lockout guard has nothing to prove;
//   - txn-test-sshd-bad writes a value sshd refuses, so the validation
//     fails and the transaction must roll back at once;
//   - txn-test-keys-only sets PasswordAuthentication no and reloads
//     ssh.service: the lockout guard must prove a key login first;
//   - txn-test-close-public writes a drop-in with a comment only and says
//     it closes public SSH (Access.ClosesPublicSSH), standing for the
//     firewall step of #29: the guard must prove the tailnet path or an
//     allowed source, and the confirm must come over it.
package txntest

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"sync"

	"github.com/Shironex/stackward/internal/plan"
)

// Step ids and the files they create.
const (
	GoodID          = "txn-test-sshd"
	BadID           = "txn-test-sshd-bad"
	KeysOnlyID      = "txn-test-keys-only"
	ClosePublicID   = "txn-test-close-public"
	GoodPath        = "/etc/ssh/sshd_config.d/01-stackward-txn-test.conf"
	BadPath         = "/etc/ssh/sshd_config.d/01-stackward-txn-test-bad.conf"
	KeysOnlyPath    = "/etc/ssh/sshd_config.d/01-stackward-txn-test-keys-only.conf"
	ClosePublicPath = "/etc/ssh/sshd_config.d/01-stackward-txn-test-close.conf"
	// Fixes is the check id the test steps claim. It is not in the
	// catalog: these steps fix nothing.
	Fixes = "TXN-TEST"
)

// IDs lists every test step, for the test that keeps them out of the
// released binary.
var IDs = []string{GoodID, BadID, KeysOnlyID, ClosePublicID}

// What the steps write.
const (
	header             = "# Written by the stackward transaction test (test builds only).\n"
	GoodContent        = header + "LoginGraceTime 60\n"
	BadContent         = header + "LoginGraceTime not-a-duration\n"
	KeysOnlyContent    = header + "PasswordAuthentication no\n"
	ClosePublicContent = header + "# Stands for a firewall change that closes public SSH; sets nothing.\n"
)

var reload = []string{"systemctl", "try-reload-or-restart", "ssh.service"}

// spec is one test step.
type spec struct {
	id, title, path, content string
	// reload runs the ssh reload after the edit, and again after undo.
	reload bool
	sshd   map[string]string
	access *plan.Access
}

var once sync.Once

// Register adds every test step to the plan registry, once.
func Register() {
	once.Do(func() {
		for _, s := range []spec{
			{id: GoodID, title: "Test only: set LoginGraceTime 60 in an sshd drop-in", path: GoodPath, content: GoodContent, reload: true,
				sshd: map[string]string{"logingracetime": "60"}},
			{id: BadID, title: "Test only: write an sshd drop-in that sshd -t refuses", path: BadPath, content: BadContent},
			{id: KeysOnlyID, title: "Test only: turn SSH password authentication off", path: KeysOnlyPath, content: KeysOnlyContent, reload: true,
				sshd: map[string]string{"passwordauthentication": "no"}},
			{id: ClosePublicID, title: "Test only: stand for a firewall change that closes public SSH", path: ClosePublicPath, content: ClosePublicContent,
				access: &plan.Access{ClosesPublicSSH: true}},
		} {
			plan.Register(generator(s))
		}
	})
}

func generator(sp spec) plan.Generator {
	var commands, undo [][]string
	undo = append(undo, []string{"rm", "-f", sp.path})
	if sp.reload {
		commands = append(commands, reload)
		undo = append(undo, reload)
	}
	g := plan.Generator{
		ID: sp.id, Title: sp.title, Fixes: []string{Fixes}, Risk: plan.AccessCritical,
		CommandsOnChange: sp.reload,
		Plan:             func(in plan.Input) plan.Outcome { return planStep(in, sp, commands, undo) },
		Authorize: func(s plan.Step) error {
			if len(s.Edits) != 1 || s.Edits[0].Path != sp.path || s.Edits[0].Action != plan.Create || s.Edits[0].Mode != "0644" || s.Edits[0].New != sp.content {
				return fmt.Errorf("the step only ever creates %s with fixed content", sp.path)
			}
			if !sameArgs(s.Commands, commands) || !sameArgs(s.Undo.Commands, undo) {
				return errors.New("commands are not the ones the step runs")
			}
			return nil
		},
		Check: func(r plan.Reader, s plan.Step) (bool, string, error) {
			b, err := r.ReadFile(sp.path)
			if errors.Is(err, fs.ErrNotExist) {
				return false, "", nil
			}
			if err != nil {
				return false, "", err
			}
			if sum(string(b)) == s.Edits[0].NewSHA256 {
				return true, sp.path + " already holds the test setting", nil
			}
			return false, "", nil
		},
		// Every test step declares its effect on access: the effective
		// sshd settings it means to leave (none for the bad one) and,
		// for close-public, the way in it closes.
		SSHD: func(plan.Step) map[string]string { return sp.sshd },
	}
	if sp.access != nil {
		a := *sp.access
		g.Access = func(plan.Step) plan.Access { return a }
	}
	return g
}

func planStep(in plan.Input, sp spec, commands, undo [][]string) plan.Outcome {
	if in.Facts == nil {
		return plan.Skip(plan.SkipUnknown, "no facts to plan from")
	}
	s := &plan.Step{
		Touches: []string{"file:" + sp.path},
		Edits: []plan.FileEdit{{
			Path: sp.path, Action: plan.Create, Mode: "0644", New: sp.content, NewSHA256: sum(sp.content),
			Diff: plan.Diff("/dev/null", "b"+sp.path, "", sp.content),
		}},
		Undo: plan.Undo{Description: "remove " + sp.path},
	}
	for _, c := range commands {
		s.Commands = append(s.Commands, plan.Command{Args: c, Why: "load the new sshd settings"})
	}
	if sp.reload {
		s.Restarts = []string{"ssh"}
		s.Touches = append(s.Touches, "service:ssh")
	}
	for _, c := range undo {
		s.Undo.Commands = append(s.Undo.Commands, plan.Command{Args: c, Why: "undo"})
	}
	return plan.Outcome{Step: s}
}

func sameArgs(got []plan.Command, want [][]string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range want {
		if !slices.Equal(got[i].Args, want[i]) {
			return false
		}
	}
	return true
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
