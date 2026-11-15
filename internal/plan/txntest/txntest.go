// Package txntest holds access-critical steps that exist only to test the
// rollback transaction: no real step of this release is access-critical.
// Nothing registers them by default. Tests call Register, and so does the
// scenario binary (cmd/stackward built with the stackward_scenario tag);
// the released binary never imports this package, and a test in
// cmd/stackward proves it.
//
// Both steps write an sshd drop-in with a harmless setting:
//
//   - txn-test-sshd sets LoginGraceTime 60 (sshd's default is 120) and
//     reloads ssh.service, so the transaction can apply it, validate it
//     with sshd -t and sshd -T, and roll it back;
//   - txn-test-sshd-bad writes a value sshd refuses, so the validation
//     fails and the transaction must roll back at once.
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
	GoodID   = "txn-test-sshd"
	BadID    = "txn-test-sshd-bad"
	GoodPath = "/etc/ssh/sshd_config.d/01-stackward-txn-test.conf"
	BadPath  = "/etc/ssh/sshd_config.d/01-stackward-txn-test-bad.conf"
	// Fixes is the check id the test steps claim. It is not in the
	// catalog: these steps fix nothing.
	Fixes = "TXN-TEST"
)

// GoodContent and BadContent are what the steps write.
const (
	GoodContent = "# Written by the stackward transaction test (test builds only).\nLoginGraceTime 60\n"
	BadContent  = "# Written by the stackward transaction test (test builds only).\nLoginGraceTime not-a-duration\n"
)

var reload = []string{"systemctl", "try-reload-or-restart", "ssh.service"}

var once sync.Once

// Register adds both test steps to the plan registry, once.
func Register() {
	once.Do(func() {
		plan.Register(generator(GoodID, "Test only: set LoginGraceTime 60 in an sshd drop-in", GoodPath, GoodContent, true))
		plan.Register(generator(BadID, "Test only: write an sshd drop-in that sshd -t refuses", BadPath, BadContent, false))
	})
}

func generator(id, title, path, content string, good bool) plan.Generator {
	var commands, undo [][]string
	undo = append(undo, []string{"rm", "-f", path})
	if good {
		commands = append(commands, reload)
		undo = append(undo, reload)
	}
	return plan.Generator{
		ID: id, Title: title, Fixes: []string{Fixes}, Risk: plan.AccessCritical,
		CommandsOnChange: good,
		Plan: func(in plan.Input) plan.Outcome {
			if in.Facts == nil {
				return plan.Skip(plan.SkipUnknown, "no facts to plan from")
			}
			s := &plan.Step{
				Touches: []string{"file:" + path},
				Edits: []plan.FileEdit{{
					Path: path, Action: plan.Create, Mode: "0644", New: content, NewSHA256: sum(content),
					Diff: plan.Diff("/dev/null", "b"+path, "", content),
				}},
				Undo: plan.Undo{Description: "remove " + path},
			}
			for _, c := range commands {
				s.Commands = append(s.Commands, plan.Command{Args: c, Why: "load the new sshd settings"})
			}
			if good {
				s.Restarts = []string{"ssh"}
				s.Touches = append(s.Touches, "service:ssh")
			}
			for _, c := range undo {
				s.Undo.Commands = append(s.Undo.Commands, plan.Command{Args: c, Why: "undo"})
			}
			return plan.Outcome{Step: s}
		},
		Authorize: func(s plan.Step) error {
			if len(s.Edits) != 1 || s.Edits[0].Path != path || s.Edits[0].Action != plan.Create || s.Edits[0].Mode != "0644" || s.Edits[0].New != content {
				return fmt.Errorf("the step only ever creates %s with fixed content", path)
			}
			if !sameArgs(s.Commands, commands) || !sameArgs(s.Undo.Commands, undo) {
				return errors.New("commands are not the ones the step runs")
			}
			return nil
		},
		Check: func(r plan.Reader, s plan.Step) (bool, string, error) {
			b, err := r.ReadFile(path)
			if errors.Is(err, fs.ErrNotExist) {
				return false, "", nil
			}
			if err != nil {
				return false, "", err
			}
			if sum(string(b)) == s.Edits[0].NewSHA256 {
				return true, path + " already holds the test setting", nil
			}
			return false, "", nil
		},
		SSHD: func(plan.Step) map[string]string {
			if good {
				return map[string]string{"logingracetime": "60"}
			}
			return nil
		},
	}
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
