//go:build linux

package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// planChildEnv makes the test binary act as a sandboxed `stackward plan`.
// Landlock cannot be undone, so the run happens in a separate process.
const planChildEnv = "STACKWARD_PLAN_CHILD"

func TestMain(m *testing.M) {
	if dir := os.Getenv(planChildEnv); dir != "" {
		os.Exit(planChild(dir))
	}
	if dir := os.Getenv(textfileChildEnv); dir != "" {
		os.Exit(textfileChild(dir))
	}
	os.Exit(m.Run())
}

// planChild runs plan with the sandbox on and then proves the process can
// no longer create a file. Exit 0 means it held, 3 that Landlock is not
// usable here.
func planChild(dir string) int {
	code := Run([]string{"plan", "--facts", fixture("plan-host-settings-fix"), "--out", filepath.Join(dir, "plan.json")}, io.Discard, os.Stderr)
	if code != 0 {
		println("plan exit", code)
		return 1
	}
	b, err := os.ReadFile(filepath.Join(dir, "plan.json"))
	if err != nil {
		println("read plan:", err.Error())
		return 1
	}
	if !strings.Contains(string(b), `"state": "landlock"`) {
		println("sandbox not applied:", string(b[:min(len(b), 2000)]))
		return 3
	}
	if err := os.WriteFile(filepath.Join(dir, "after.txt"), []byte("x"), 0o600); !errors.Is(err, os.ErrPermission) {
		println("a file could be created after plan:", fmt.Sprint(err))
		return 1
	}
	return 0
}

func TestPlanUnderLandlock(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cmd := exec.Command(exe, "-test.run=^$")
	cmd.Env = append(os.Environ(), planChildEnv+"="+dir)
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		t.Logf("child output:\n%s", out)
	case errors.As(err, &exitErr) && exitErr.ExitCode() == 3:
		t.Skipf("Landlock not usable here:\n%s", out)
	default:
		t.Fatalf("sandboxed plan failed: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "after.txt")); err == nil {
		t.Error("file created under the sandbox")
	}
}
