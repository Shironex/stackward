package applytest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/Shironex/stackward/internal/apply"
	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/plan"
	"github.com/Shironex/stackward/internal/plan/txntest"
	"github.com/Shironex/stackward/internal/report"
)

// Exe is where the transaction tests put the fake stackward binary.
const Exe = "/usr/local/bin/stackward"

// System fakes what the transaction talks to, without starting anything:
// systemd-run and systemctl for the rollback timer (units only live in
// this struct), sshd -t and sshd -T computed from the drop-ins under Root,
// and ss listing Listening. Other commands fall through to the Runner.
type System struct {
	Root string
	// Listening are the TCP ports ss reports as listened on.
	Listening []string
	// FailArm makes arming the timer fail; FailProve makes the test run
	// of the binary copy as a service fail; FailEnable makes systemctl
	// enable of the boot unit fail.
	FailArm, FailProve, FailEnable bool
	// Reloads counts systemctl daemon-reload.
	Reloads int

	mu     sync.Mutex
	active map[string]bool
	armed  map[string][]string
}

// NewTxnHost returns a host under root whose runner answers through a
// System, with sshd listening on 22 and a fake binary at Exe.
func NewTxnHost(t testing.TB, root string) (apply.Host, *Runner, *System) {
	t.Helper()
	sys := &System{Root: root, Listening: []string{"22"}, active: map[string]bool{}, armed: map[string][]string{}}
	r := &Runner{Root: root, Exit: map[string]int{}, Respond: sys.Respond}
	Write(t, root, Exe, "#!/bin/false\nfake stackward\n", 0o755)
	return apply.NewHost(root, r), r, sys
}

// Active reports whether unit is active.
func (s *System) Active(unit string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active[unit]
}

// Fire elapses the timer of unit as systemd would at the deadline: the
// timer goes away (RemainAfterElapse=no) and the command it runs is
// returned, for the test to run.
func (s *System) Fire(unit string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	cmd := s.armed[unit]
	delete(s.active, unit+".timer")
	return cmd
}

func ok(out string) (apply.CmdResult, bool) {
	return apply.CmdResult{Output: []byte(out)}, true
}

func exit(code int, out string) (apply.CmdResult, bool) {
	return apply.CmdResult{ExitCode: code, Output: []byte(out)}, true
}

// Respond answers the commands it fakes.
func (s *System) Respond(args []string) (apply.CmdResult, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case len(args) == 2 && args[0] == "systemd-run" && args[1] == "--version":
		return ok("systemd 255 (fake)\n")
	case args[0] == "systemd-run":
		if !slicesContainsPrefix(args, "--on-active=") {
			// systemd-run --wait BINARY version: does the copy start?
			if s.FailProve {
				return exit(203, "Job failed: exec of the binary refused by the test\n")
			}
			return ok("")
		}
		if s.FailArm {
			return exit(1, "Failed to start transient timer unit: refused by the test\n")
		}
		unit := ""
		for i, a := range args[1:] {
			if u, found := strings.CutPrefix(a, "--unit="); found {
				unit = u
			}
			if !strings.HasPrefix(a, "--") {
				s.armed[unit] = append([]string{}, args[1+i:]...)
				break
			}
		}
		s.active[unit+".timer"] = true
		return ok("")
	case len(args) == 3 && args[0] == "systemctl" && args[1] == "enable":
		return s.enable(args[2])
	case len(args) == 2 && args[0] == "systemctl" && args[1] == "daemon-reload":
		s.Reloads++
		return ok("")
	case len(args) >= 2 && args[0] == "systemctl" && args[1] == "stop":
		for _, u := range args[2:] {
			delete(s.active, u)
		}
		return ok("")
	case len(args) == 3 && args[0] == "systemctl" && args[1] == "is-active":
		if s.active[args[2]] {
			return ok("active\n")
		}
		return exit(3, "inactive\n")
	case len(args) == 2 && args[0] == "sshd" && args[1] == "-t":
		if _, bad := s.sshd(); bad != "" {
			return exit(255, bad+"\n")
		}
		return ok("")
	case len(args) == 2 && args[0] == "sshd" && args[1] == "-T":
		eff, bad := s.sshd()
		if bad != "" {
			return exit(255, bad+"\n")
		}
		return ok(eff)
	case len(args) == 2 && args[0] == "ss" && args[1] == "-Htln":
		var b strings.Builder
		for _, p := range s.Listening {
			b.WriteString("LISTEN 0      4096         0.0.0.0:" + p + "        0.0.0.0:*\n")
			b.WriteString("LISTEN 0      4096            [::]:" + p + "           [::]:*\n")
		}
		return ok(b.String())
	}
	return apply.CmdResult{}, false
}

// enable does what systemctl enable does with the boot unit: the link in
// the wants directory of its WantedBy target, under Root.
func (s *System) enable(unit string) (apply.CmdResult, bool) {
	if s.FailEnable {
		return exit(1, "Failed to enable unit: refused by the test\n")
	}
	unitFile := filepath.Join(s.Root, "etc", "systemd", "system", unit)
	if _, err := os.Stat(unitFile); err != nil {
		return exit(1, "Failed to enable unit: Unit file "+unit+" does not exist.\n")
	}
	wants := filepath.Join(s.Root, "etc", "systemd", "system", apply.BootTarget+".wants")
	if err := os.MkdirAll(wants, 0o750); err != nil {
		return exit(1, err.Error())
	}
	if err := os.Symlink("/etc/systemd/system/"+unit, filepath.Join(wants, unit)); err != nil {
		return exit(1, err.Error())
	}
	return ok("Created symlink.\n")
}

var digits = regexp.MustCompile(`^[0-9]+$`)

// sshd computes what sshd -T prints from the drop-ins under Root (the
// first value of a key wins, as in sshd), or why sshd -t would refuse.
func (s *System) sshd() (effective, bad string) {
	eff := map[string]string{"port": "22", "logingracetime": "120", "permitrootlogin": "without-password"}
	set := map[string]bool{}
	files, _ := filepath.Glob(filepath.Join(s.Root, "etc", "ssh", "sshd_config.d", "*.conf"))
	sort.Strings(files)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			k, v, found := strings.Cut(strings.TrimSpace(line), " ")
			if !found || strings.HasPrefix(k, "#") {
				continue
			}
			k = strings.ToLower(k)
			if k == "logingracetime" && !digits.MatchString(v) {
				return "", filepath.Base(f) + ": invalid time value \"" + v + "\""
			}
			if !set[k] {
				set[k], eff[k] = true, v
			}
		}
	}
	keys := make([]string, 0, len(eff))
	for k := range eff {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + " " + eff[k] + "\n")
	}
	return b.String(), ""
}

// TxnPlan returns the fixture plan with every transaction test step
// added, for Hostname. It registers the test steps.
func TxnPlan(t testing.TB) *plan.Plan {
	t.Helper()
	txntest.Register()
	p := FixturePlan(t, "plan-host-settings-fix")
	rep := &report.Report{Schema: p.Source.Report.Schema, GeneratedAt: p.GeneratedAt, Host: p.Host}
	in := plan.Input{Facts: &facts.Facts{}}
	for _, id := range txntest.IDs {
		g, _ := plan.Lookup(id)
		built := plan.BuildWith([]plan.Generator{g}, in, rep, plan.Options{Version: "test", SourceKind: plan.FromFacts})
		p.Steps = append(p.Steps, built.Steps...)
	}
	return p
}

// WritePlan writes p to a file in a new temporary directory.
func WritePlan(t testing.TB, p *plan.Plan) string {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(t.TempDir(), "plan.json")
	if err := os.WriteFile(f, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

func slicesContainsPrefix(args []string, prefix string) bool {
	for _, a := range args {
		if strings.HasPrefix(a, prefix) {
			return true
		}
	}
	return false
}
