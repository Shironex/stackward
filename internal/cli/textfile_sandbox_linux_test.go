//go:build linux

package cli

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// textfileChildEnv makes the test binary act as a sandboxed audit that
// writes a report and a textfile, as the scheduled unit runs it.
const textfileChildEnv = "STACKWARD_TEXTFILE_CHILD"

// textfileChild runs the audit with the sandbox on. Exit 0 means both files
// were written through descriptors opened before the sandbox, 3 that
// Landlock is not usable here.
func textfileChild(dir string) int {
	code := Run([]string{"audit", "--facts", fixture("ubuntu-2404-clean"), "--format", "json", "--fail-on", "never",
		"--out", filepath.Join(dir, "report.json.tmp"), "--textfile", filepath.Join(dir, "stackward.prom.tmp")}, io.Discard, os.Stderr)
	if code != 0 {
		println("audit exit", code)
		return 1
	}
	rep, err := os.ReadFile(filepath.Join(dir, "report.json.tmp"))
	if err != nil {
		println("read report:", err.Error())
		return 1
	}
	if !strings.Contains(string(rep), `"state": "landlock"`) {
		return 3
	}
	prom, err := os.ReadFile(filepath.Join(dir, "stackward.prom.tmp"))
	if err != nil || !strings.Contains(string(prom), "stackward_sandbox_confined 1\n") {
		println("textfile under the sandbox:", string(prom), err)
		return 1
	}
	return 0
}

func TestTextfileUnderLandlock(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^$")
	cmd.Env = append(os.Environ(), textfileChildEnv+"="+t.TempDir())
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr) && exitErr.ExitCode() == 3:
		t.Skipf("Landlock not usable here:\n%s", out)
	default:
		t.Fatalf("sandboxed audit with --textfile failed: %v\n%s", err, out)
	}
}
