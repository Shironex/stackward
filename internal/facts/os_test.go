package facts

import (
	"context"
	"reflect"
	"testing"
	"time"
)

const ubuntuRelease = `PRETTY_NAME="Ubuntu 24.04.1 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
# a comment
HOME_URL="https://www.ubuntu.com/"
`

func TestParseOSRelease(t *testing.T) {
	kv := ParseOSRelease([]byte(ubuntuRelease + "QUOTED='single'\nESCAPED=\"a \\\"b\\\"\"\nbroken line\n"))
	want := map[string]string{
		"PRETTY_NAME": "Ubuntu 24.04.1 LTS", "NAME": "Ubuntu", "VERSION_ID": "24.04",
		"VERSION_CODENAME": "noble", "ID": "ubuntu", "ID_LIKE": "debian",
		"HOME_URL": "https://www.ubuntu.com/", "QUOTED": "single", "ESCAPED": `a "b"`,
	}
	if !reflect.DeepEqual(kv, want) {
		t.Fatalf("got %v\nwant %v", kv, want)
	}
}

func TestOSCollector(t *testing.T) {
	sys := newFakeSystem(map[string]string{
		"/etc/os-release":                ubuntuRelease,
		"/proc/sys/kernel/osrelease":     "6.8.0-45-generic\n",
		"/boot/vmlinuz-6.8.0-45-generic": "",
		"/boot/vmlinuz-6.8.0-49-generic": "",
		"/boot/config-6.8.0-49-generic":  "",
		"/var/run/reboot-required":       "*** System restart required ***\n",
		"/var/run/reboot-required.pkgs":  "linux-base\nlibc6\nlinux-base\n",
	})
	sys.files["var/run/reboot-required"].ModTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	out := &Facts{}
	if err := (osCollector{}).Collect(context.Background(), sys, out); err != nil {
		t.Fatal(err)
	}
	if out.OS.ID != "ubuntu" || out.OS.VersionID != "24.04" || out.OS.Family() != "debian" {
		t.Errorf("os = %+v", out.OS)
	}
	if out.Kernel.Release != "6.8.0-45-generic" {
		t.Errorf("kernel release = %q", out.Kernel.Release)
	}
	if want := []string{"6.8.0-45-generic", "6.8.0-49-generic"}; !reflect.DeepEqual(out.Kernel.Installed, want) {
		t.Errorf("installed = %v, want %v", out.Kernel.Installed, want)
	}
	if !out.Reboot.Required || !out.Reboot.Since.Equal(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("reboot = %+v", out.Reboot)
	}
	if want := []string{"libc6", "linux-base"}; !reflect.DeepEqual(out.Reboot.Packages, want) {
		t.Errorf("packages = %v, want %v", out.Reboot.Packages, want)
	}
}

func TestOSCollectorPartial(t *testing.T) {
	// No os-release (a minimal container): the kernel still lands and the
	// error says what was missing, so the run is marked partial.
	sys := newFakeSystem(map[string]string{"/proc/sys/kernel/osrelease": "6.1.0-27-amd64\n"})
	f := Run(context.Background(), sys, []Collector{osCollector{}}, RunOptions{})
	st, _ := f.CollectorStatus("os")
	if st.Status != StatusPartial || f.OS != nil || f.Kernel == nil {
		t.Fatalf("status=%+v os=%v kernel=%v", st, f.OS, f.Kernel)
	}
	if f.Reboot == nil || f.Reboot.Required {
		t.Errorf("absent marker should read as not required: %+v", f.Reboot)
	}
	if f.Kernel.Installed != nil {
		t.Errorf("no /boot should leave Installed nil, got %v", f.Kernel.Installed)
	}
}

func TestOSReleaseFallback(t *testing.T) {
	sys := newFakeSystem(map[string]string{"/usr/lib/os-release": "ID=debian\nVERSION_ID=\"12\"\n"})
	o, err := readOSRelease(sys)
	if err != nil || o.ID != "debian" || o.VersionID != "12" {
		t.Fatalf("o=%+v err=%v", o, err)
	}
}

func TestHostSystemRoot(t *testing.T) {
	dir := t.TempDir()
	h := &HostSystem{Root: dir}
	if got := h.path("/etc/../etc/os-release"); got != dir+"/etc/os-release" {
		t.Errorf("path = %q", got)
	}
	if got := h.path("../../outside"); got != dir+"/outside" {
		t.Errorf("relative escape not contained: %q", got)
	}
	if _, err := h.LookPath("/bin/sh"); err == nil {
		t.Error("LookPath must refuse paths")
	}
}
