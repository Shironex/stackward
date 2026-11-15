package facts

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

// fakeProc builds a /proc like tree: per pid a comm file and an fd
// directory of symlinks whose targets are what the kernel shows
// ("socket:[123]", "/dev/null", "pipe:[9]").
func fakeProc(t *testing.T, procs map[string]struct {
	comm string
	fds  []string
}) string {
	t.Helper()
	root := t.TempDir()
	for pid, p := range procs {
		dir := filepath.Join(root, pid)
		if err := os.MkdirAll(filepath.Join(dir, "fd"), 0o755); err != nil {
			t.Fatal(err)
		}
		if p.comm != "" {
			if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(p.comm+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		for i, target := range p.fds {
			if err := os.Symlink(target, filepath.Join(dir, "fd", string(rune('0'+i)))); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Not a process: must be ignored.
	if err := os.MkdirAll(filepath.Join(root, "net"), 0o755); err != nil {
		t.Fatal(err)
	}
	return root
}

type procSpec = struct {
	comm string
	fds  []string
}

func TestSnapshotSocketOwners(t *testing.T) {
	root := fakeProc(t, map[string]procSpec{
		"1":    {"systemd", []string{"socket:[100]", "/dev/null", "socket:[200]"}},
		"812":  {"sshd", []string{"socket:[100]", "pipe:[5]"}},
		"900":  {"tailscaled", []string{"socket:[300]", "socket:[300]", "anon_inode:[eventfd]"}},
		"950":  {"", []string{"socket:[400]"}}, // exited between listing and reading comm
		"1000": {"cloudflared", []string{"socket:[0]", "socket:[x]", "socket:[500"}},
	})
	o := SnapshotSocketOwners(root, DefaultSnapshotLimits)
	if o == nil {
		t.Fatal("nil snapshot")
	}
	if o.Processes != 5 || o.FDsRead != 4 || o.Truncated {
		t.Errorf("counts: processes %d fds read %d truncated %v", o.Processes, o.FDsRead, o.Truncated)
	}
	want := map[uint64][]string{100: {"sshd", "systemd"}, 200: {"systemd"}, 300: {"tailscaled"}}
	for ino, names := range want {
		if got := o.Names(ino); !reflect.DeepEqual(got, names) {
			t.Errorf("Names(%d) = %v, want %v", ino, got, names)
		}
	}
	if o.Sockets() != 3 {
		t.Errorf("Sockets() = %d, want 3", o.Sockets())
	}
	if o.Names(400) != nil || o.Names(0) != nil {
		t.Error("unexpected owner for a socket without a readable comm, or inode 0")
	}
}

func TestSnapshotSocketOwnersLimits(t *testing.T) {
	procs := map[string]procSpec{}
	for _, pid := range []string{"10", "11", "12", "13"} {
		procs[pid] = procSpec{"p" + pid, []string{"socket:[1" + pid + "]", "socket:[2" + pid + "]"}}
	}
	root := fakeProc(t, procs)

	o := SnapshotSocketOwners(root, SnapshotLimits{MaxProcs: 2, MaxFDs: 100, Timeout: time.Minute})
	if !o.Truncated || o.Processes != 2 {
		t.Errorf("process cap: truncated %v processes %d", o.Truncated, o.Processes)
	}
	o = SnapshotSocketOwners(root, SnapshotLimits{MaxProcs: 100, MaxFDs: 3, Timeout: time.Minute})
	if !o.Truncated || o.Sockets() != 3 {
		t.Errorf("fd cap: truncated %v sockets %d", o.Truncated, o.Sockets())
	}
	o = SnapshotSocketOwners(root, SnapshotLimits{MaxProcs: 100, MaxFDs: 100, Timeout: -time.Second})
	if !o.Truncated || o.Sockets() != 0 {
		t.Errorf("time limit: truncated %v sockets %d", o.Truncated, o.Sockets())
	}
}

func TestSnapshotSocketOwnersNoProc(t *testing.T) {
	if o := SnapshotSocketOwners(filepath.Join(t.TempDir(), "missing"), DefaultSnapshotLimits); o != nil {
		t.Errorf("want nil without /proc, got %+v", o)
	}
	var none *SocketOwners
	if none.Names(1) != nil || none.Sockets() != 0 {
		t.Error("nil snapshot must name nothing")
	}
}

func TestParseSocketLink(t *testing.T) {
	cases := map[string]uint64{"socket:[12345]": 12345, "socket:[0]": 0, "pipe:[1]": 0, "socket:[]": 0, "socket:[12": 0, "/dev/null": 0}
	for in, want := range cases {
		got, ok := parseSocketLink(in)
		if got != want || ok != (want != 0) {
			t.Errorf("parseSocketLink(%q) = %d %v, want %d", in, got, ok, want)
		}
	}
}

func TestWithSocketOwners(t *testing.T) {
	sys := newFakeSystem(nil)
	if WithSocketOwners(sys, nil) != System(sys) {
		t.Error("a nil snapshot must leave the System unchanged")
	}
	o := &SocketOwners{}
	if socketOwnersOf(WithSocketOwners(sys, o)) != o || socketOwnersOf(sys) != nil {
		t.Error("snapshot not carried")
	}
}
