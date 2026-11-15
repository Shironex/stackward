// Package applytest holds the fakes apply and cli tests share: a command
// runner that records what it is asked to run and never starts a program,
// and helpers that lay out a host under a temporary root. Nothing here
// touches the machine outside the root a test gives it.
package applytest

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/Shironex/stackward/internal/apply"
	"github.com/Shironex/stackward/internal/plan"
	"github.com/Shironex/stackward/internal/report"
)

// Hostname is the host name the fixtures are given.
const Hostname = "test-host.example.com"

// Runner is a fake apply.Runner. It records every command and returns
// Exit[args[0]] (0 when unset). `sysctl -p FILE` also writes the values of
// FILE under Root/proc/sys, as the real command would, so a second run
// sees them applied.
type Runner struct {
	Root string
	Exit map[string]int

	mu    sync.Mutex
	calls [][]string
}

// Run implements apply.Runner.
func (r *Runner) Run(_ context.Context, args []string) apply.CmdResult {
	r.mu.Lock()
	r.calls = append(r.calls, append([]string{}, args...))
	r.mu.Unlock()
	code := r.Exit[args[0]]
	if code != 0 {
		return apply.CmdResult{ExitCode: code, Output: []byte(args[0] + ": refused by the test")}
	}
	if len(args) == 3 && args[0] == "sysctl" && args[1] == "-p" {
		b, err := os.ReadFile(filepath.Join(r.Root, args[2]))
		if err != nil {
			return apply.CmdResult{ExitCode: 1, Output: []byte(err.Error())}
		}
		for _, line := range strings.Split(string(b), "\n") {
			if k, v, ok := strings.Cut(line, " = "); ok && !strings.HasPrefix(line, "#") {
				p := filepath.Join(r.Root, "proc", "sys", filepath.FromSlash(strings.ReplaceAll(k, ".", "/")))
				if err := os.WriteFile(p, []byte(v+"\n"), 0o600); err != nil { //nolint:gosec // G703: the fake writes under the test's own root
					return apply.CmdResult{ExitCode: 1, Output: []byte(err.Error())}
				}
			}
		}
	}
	return apply.CmdResult{}
}

// Calls returns every command run so far.
func (r *Runner) Calls() [][]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([][]string{}, r.calls...)
}

// Reset forgets the recorded commands.
func (r *Runner) Reset() {
	r.mu.Lock()
	r.calls = nil
	r.mu.Unlock()
}

// RepoPath returns a path in the repository from its root.
func RepoPath(rel string) string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", filepath.FromSlash(rel))
}

// FixturePlan loads test/fixtures/<name>/plan.json and makes it a plan for
// Hostname.
func FixturePlan(t testing.TB, name string) *plan.Plan {
	t.Helper()
	b, err := os.ReadFile(RepoPath("test/fixtures/" + name + "/plan.json"))
	if err != nil {
		t.Fatal(err)
	}
	var p plan.Plan
	if err := json.Unmarshal(b, &p); err != nil {
		t.Fatal(err)
	}
	p.Host.HostnameHash = report.HashHostname(Hostname)
	return &p
}

// Step returns the step id of p.
func Step(t testing.TB, p *plan.Plan, id string) plan.Step {
	t.Helper()
	for _, s := range p.Steps {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("plan has no step %s", id)
	return plan.Step{}
}

// Write puts a file under root, creating its directory.
func Write(t testing.TB, root, p, content string, mode os.FileMode) {
	t.Helper()
	rp := filepath.Join(root, filepath.FromSlash(p))
	if err := os.MkdirAll(filepath.Dir(rp), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rp, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(rp, mode); err != nil {
		t.Fatal(err)
	}
}

// Read returns the content of a file under root, or "" with false.
func Read(t testing.TB, root, p string) (string, bool) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(p)))
	if err != nil {
		return "", false
	}
	return string(b), true
}

// Seed lays out the host a plan was made on: every replaced file holds the
// old side of its edit, and every sysctl the plan restores in its undo has
// that value as its running value (what the audit saw).
func Seed(t testing.TB, root string, p *plan.Plan) {
	t.Helper()
	for _, s := range p.Steps {
		for _, e := range s.Edits {
			if e.Action == plan.Replace {
				Write(t, root, e.Path, e.Old, 0o644)
			}
		}
		for _, c := range s.Undo.Commands {
			if len(c.Args) == 3 && c.Args[0] == "sysctl" && c.Args[1] == "-w" {
				k, v, _ := strings.Cut(c.Args[2], "=")
				Write(t, root, "/proc/sys/"+strings.ReplaceAll(k, ".", "/"), v+"\n", 0o644)
			}
		}
	}
}

// NewHost returns a host under root with a fake runner.
func NewHost(root string) (apply.Host, *Runner) {
	r := &Runner{Root: root, Exit: map[string]int{}}
	return apply.NewHost(root, r), r
}
