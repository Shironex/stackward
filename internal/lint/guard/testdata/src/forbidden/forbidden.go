package forbidden

import (
	"net"
	"net/http"
	"os"
	"os/exec"
	"syscall"
)

func writes() {
	_ = os.WriteFile("a", nil, 0o600) // want `os.WriteFile writes to the filesystem`
	_ = os.Remove("a")                // want `os.Remove writes to the filesystem`
	_ = os.MkdirAll("a", 0o750)       // want `os.MkdirAll writes to the filesystem`
	_ = os.Rename("a", "b")           // want `os.Rename writes to the filesystem`
	_ = syscall.Unlink("a")           // want `syscall.Unlink writes to the filesystem`
	f, _ := os.Create("a")            // want `os.Create writes to the filesystem`
	_ = f
}

func removeAsValue() {
	rm := os.RemoveAll // want `os.RemoveAll writes to the filesystem`
	_ = rm
}

func runs() {
	_ = exec.Command("ls")                // want `os/exec.Command starts a program`
	_ = syscall.Exec("a", nil, nil)       // want `syscall.Exec starts a program`
	_, _ = os.StartProcess("a", nil, nil) // want `os.StartProcess starts a program`
}

func dials() {
	_, _ = net.Dial("tcp", "192.0.2.1:80") // want `net.Dial uses the network`
	var d net.Dialer
	_, _ = d.DialContext(nil, "tcp", "x") // want `\(\*net.Dialer\).DialContext uses the network`
	_, _ = http.Get("http://example.com") // want `net/http.Get uses the network`
	c := &http.Client{}
	_, _ = c.Do(nil) // want `\(\*net/http.Client\).Do uses the network`
}

func syscalls() {
	_, _, _ = syscall.Syscall(1, 0, 0, 0) // want `syscall.Syscall makes a raw system call`
}

// Reading is fine.
func reads() {
	_, _ = os.ReadFile("a")
	_, _ = os.Open("a")
	_, _ = os.Stat("a")
	_, _ = exec.LookPath("ls")
	_, _, _ = net.ParseCIDR("192.0.2.0/24")
}
