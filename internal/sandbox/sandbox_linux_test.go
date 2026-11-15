//go:build linux

package sandbox

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// childEnv makes the test binary act as the sandboxed child. Landlock cannot
// be undone, so the real assertions run in a separate process.
const childEnv = "STACKWARD_SANDBOX_CHILD"

func TestMain(m *testing.M) {
	if dir := os.Getenv(childEnv); dir != "" {
		os.Exit(child(dir))
	}
	os.Exit(m.Run())
}

// child applies the sandbox and probes what is still allowed. Exit 0 means
// every expectation held, 3 means Landlock was not available here.
func child(dir string) int {
	pre, err := os.OpenFile(filepath.Join(dir, "report.json"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		println("open before sandbox:", err.Error())
		return 1
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		println("listen:", err.Error())
		return 1
	}
	defer func() { _ = ln.Close() }()

	st := Apply(Options{})
	println("status:", string(st.State), st.ABI, st.Network, st.Reason)
	if st.State != Landlock {
		return 3
	}
	fails := 0
	expect := func(what string, ok bool) {
		if !ok {
			println("FAIL:", what)
			fails++
		}
	}
	_, err = os.ReadFile("/proc/self/status")
	expect("reading still works", err == nil)
	_, err = pre.WriteString("{}")
	expect("a descriptor opened before Apply still writes", err == nil)
	err = os.WriteFile(filepath.Join(dir, "new.txt"), []byte("x"), 0o600)
	expect("creating a file is denied", errors.Is(err, os.ErrPermission))
	err = os.Mkdir(filepath.Join(dir, "sub"), 0o700)
	expect("making a directory is denied", errors.Is(err, os.ErrPermission))
	err = os.Remove(pre.Name())
	expect("removing a file is denied", errors.Is(err, os.ErrPermission))
	devnull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	expect("/dev/null stays writable", err == nil)
	if devnull != nil {
		_ = devnull.Close()
	}
	childFile := filepath.Join(dir, "from-shell.txt")
	err = exec.Command("/bin/sh", "-c", "echo marker > "+childFile).Run()
	_, statErr := os.Stat(childFile)
	expect("child processes inherit the sandbox", err != nil && errors.Is(statErr, os.ErrNotExist))
	if st.Network {
		c, err := net.Dial("tcp", ln.Addr().String())
		if c != nil {
			_ = c.Close()
		}
		expect("TCP connect is denied", err != nil)
	}
	if fails > 0 {
		return 1
	}
	return 0
}

func TestApplyConfinesProcess(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cmd := exec.Command(exe, "-test.run=^$")
	cmd.Env = append(os.Environ(), childEnv+"="+dir)
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		t.Logf("child output:\n%s", out)
	case errors.As(err, &exitErr) && exitErr.ExitCode() == 3:
		t.Skipf("Landlock not usable here:\n%s", out)
	default:
		t.Fatalf("child failed: %v\n%s", err, out)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "report.json")); string(b) != "{}" {
		t.Errorf("pre-opened report not written: %q", b)
	}
	if _, err := os.Stat(filepath.Join(dir, "new.txt")); err == nil {
		t.Error("file created under the sandbox")
	}
}

func TestDisabled(t *testing.T) {
	st := Apply(Options{Disabled: true})
	if st.State != Disabled || !strings.Contains(st.Reason, "--no-sandbox") {
		t.Fatalf("%+v", st)
	}
}
