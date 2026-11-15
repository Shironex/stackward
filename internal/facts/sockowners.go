package facts

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// SocketOwners is a read only snapshot of which processes hold which
// sockets, taken before the Landlock sandbox is applied.
//
// Why before: naming the process behind a socket means reading the links
// in /proc/<pid>/fd of every process, and the kernel checks ptrace read
// access for that. Landlock scopes ptrace to processes inside the sandbox,
// so once it is on neither stackward nor the ss it starts can name any
// owner. The snapshot reads the same links a moment earlier, keeps only
// socket inode numbers and process short names (/proc/<pid>/comm, what ss
// prints), and the listeners collector joins them to the sockets ss lists.
//
// It opens nothing for writing and starts no command.
type SocketOwners struct {
	byInode map[uint64][]string
	// Processes is how many process directories were looked at; FDsRead
	// how many of them had a readable fd directory.
	Processes int
	FDsRead   int
	// Truncated is true when a limit stopped the walk early, so a socket
	// without an owner in the snapshot proves nothing.
	Truncated bool
}

// SnapshotLimits bound the walk: at most MaxProcs processes and MaxFDs file
// descriptors in all, and no longer than Timeout.
type SnapshotLimits struct {
	MaxProcs int
	MaxFDs   int
	Timeout  time.Duration
}

// DefaultSnapshotLimits are generous for a server and still finish in well
// under a second on one.
var DefaultSnapshotLimits = SnapshotLimits{MaxProcs: 16384, MaxFDs: 1 << 20, Timeout: 3 * time.Second}

// errSnapshotLimit stops the walk when a limit is reached.
var errSnapshotLimit = errors.New("snapshot limit reached")

// SnapshotSocketOwners walks procRoot ("/proc" on a live host) and records
// the owner of every socket it can see. Processes that exit or deny access
// are skipped. It returns nil when procRoot cannot be listed at all (not
// Linux, or /proc not mounted).
func SnapshotSocketOwners(procRoot string, lim SnapshotLimits) *SocketOwners {
	pids, err := readNames(procRoot, -1)
	if err != nil {
		return nil
	}
	o := &SocketOwners{byInode: map[uint64][]string{}}
	deadline := time.Now().Add(lim.Timeout)
	fds := 0
	for _, pid := range pids {
		if !isPIDName(pid) {
			continue
		}
		if o.Processes >= lim.MaxProcs || time.Now().After(deadline) {
			o.Truncated = true
			break
		}
		o.Processes++
		comm, err := os.ReadFile(filepath.Join(procRoot, pid, "comm"))
		if err != nil {
			continue
		}
		name := strings.TrimSpace(string(comm))
		if name == "" {
			continue
		}
		dir := filepath.Join(procRoot, pid, "fd")
		names, err := readNames(dir, lim.MaxFDs-fds)
		if errors.Is(err, errSnapshotLimit) {
			o.Truncated = true
		} else if err != nil {
			continue
		}
		o.FDsRead++
		for _, fd := range names {
			fds++
			target, err := os.Readlink(filepath.Join(dir, fd))
			if err != nil {
				continue
			}
			if ino, ok := parseSocketLink(target); ok {
				o.add(ino, name)
			}
		}
		if o.Truncated {
			break
		}
	}
	for ino, ns := range o.byInode {
		sort.Strings(ns)
		o.byInode[ino] = ns
	}
	return o
}

// readNames lists a directory without stat calls. With limit >= 0 it reads
// at most limit names and returns errSnapshotLimit with what it read when
// there were more.
func readNames(dir string, limit int) ([]string, error) {
	f, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if limit < 0 {
		return f.Readdirnames(-1)
	}
	var out []string
	for {
		batch, err := f.Readdirnames(256)
		for _, n := range batch {
			if len(out) >= limit {
				return out, errSnapshotLimit
			}
			out = append(out, n)
		}
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return out, err
		}
	}
}

func (o *SocketOwners) add(ino uint64, name string) {
	for _, n := range o.byInode[ino] {
		if n == name {
			return
		}
	}
	o.byInode[ino] = append(o.byInode[ino], name)
}

// Names returns the sorted process names holding the socket with this
// inode, or nil when the snapshot saw none.
func (o *SocketOwners) Names(ino uint64) []string {
	if o == nil || ino == 0 {
		return nil
	}
	ns := o.byInode[ino]
	if len(ns) == 0 {
		return nil
	}
	return append([]string(nil), ns...)
}

// Sockets is how many distinct sockets the snapshot named an owner for.
func (o *SocketOwners) Sockets() int {
	if o == nil {
		return 0
	}
	return len(o.byInode)
}

// parseSocketLink reads the target of a /proc/<pid>/fd link to a socket:
// "socket:[12345]".
func parseSocketLink(s string) (uint64, bool) {
	rest, ok := strings.CutPrefix(s, "socket:[")
	if !ok || !strings.HasSuffix(rest, "]") {
		return 0, false
	}
	ino, err := strconv.ParseUint(strings.TrimSuffix(rest, "]"), 10, 64)
	if err != nil || ino == 0 {
		return 0, false
	}
	return ino, true
}

// SocketOwnerSource is implemented by a System that carries a socket
// ownership snapshot taken before the sandbox (see WithSocketOwners). The
// listeners collector asks for it; a System without one, such as a test
// fake, simply has no snapshot.
type SocketOwnerSource interface {
	SocketOwners() *SocketOwners
}

// WithSocketOwners returns sys with the snapshot attached. A nil snapshot
// returns sys unchanged.
func WithSocketOwners(sys System, o *SocketOwners) System {
	if o == nil {
		return sys
	}
	return ownersSystem{System: sys, owners: o}
}

type ownersSystem struct {
	System
	owners *SocketOwners
}

func (s ownersSystem) SocketOwners() *SocketOwners { return s.owners }

// socketOwnersOf returns the snapshot sys carries, or nil.
func socketOwnersOf(sys System) *SocketOwners {
	if src, ok := sys.(SocketOwnerSource); ok {
		return src.SocketOwners()
	}
	return nil
}
