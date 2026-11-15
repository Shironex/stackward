package facts

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Size caps. A collector that needs more is reading the wrong thing.
const (
	MaxReadBytes   = 16 << 20 // per ReadFile
	MaxOutputBytes = 4 << 20  // per stream of a command
)

// ErrTooLarge is returned when a file or command output passes its cap.
var ErrTooLarge = errors.New("output larger than the read cap")

// System is the only way collectors touch the host. It has no method that
// writes, which keeps the read only promise reviewable in one place, and it
// lets tests feed collectors a fake host (see fake_test.go).
type System interface {
	// ReadFile reads a whole file, up to MaxReadBytes. Never call it on a
	// secret bearing file: use Meta for those.
	ReadFile(path string) ([]byte, error)
	// ReadDir lists a directory, sorted by name.
	ReadDir(path string) ([]fs.DirEntry, error)
	// Meta returns metadata for path without following a final symlink.
	Meta(path string) (FileMeta, error)
	// Run executes a read only command and captures its output. It does
	// not go through a shell. Only run commands that inspect state; the
	// command list is reviewed with every collector.
	Run(ctx context.Context, name string, args ...string) (CmdResult, error)
	// LookPath reports where a command lives, or an error if it is absent.
	LookPath(name string) (string, error)
	// Identity returns who the audit runs as.
	Identity() Host
}

// FileMeta is metadata about one path. It never carries file contents.
type FileMeta struct {
	Path    string      `json:"path"`
	Mode    fs.FileMode `json:"mode"`
	UID     int         `json:"uid"`
	GID     int         `json:"gid"`
	Size    int64       `json:"size"`
	ModTime int64       `json:"mtime"` // unix seconds
	// IsSymlink is true when the path itself is a symlink (not followed).
	IsSymlink bool `json:"is_symlink,omitempty"`
}

// CmdResult is the captured result of Run. A non zero exit is not an error
// by itself: many inspection commands use exit codes to report state.
type CmdResult struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// HostSystem is the real System. Root lets tests and offline audits point
// file reads at a directory tree instead of "/"; commands are not affected.
type HostSystem struct {
	Root string
}

// NewHostSystem returns a System reading the live host.
func NewHostSystem() *HostSystem { return &HostSystem{Root: "/"} }

func (h *HostSystem) path(p string) string {
	if h.Root == "" || h.Root == "/" {
		return p
	}
	return filepath.Join(h.Root, filepath.Clean("/"+p))
}

// ReadFile implements System.
func (h *HostSystem) ReadFile(p string) ([]byte, error) {
	f, err := os.Open(h.path(p))
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, MaxReadBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxReadBytes {
		return nil, fmt.Errorf("%s: %w", p, ErrTooLarge)
	}
	return b, nil
}

// ReadDir implements System.
func (h *HostSystem) ReadDir(p string) ([]fs.DirEntry, error) {
	return os.ReadDir(h.path(p))
}

// Meta implements System.
func (h *HostSystem) Meta(p string) (FileMeta, error) {
	fi, err := os.Lstat(h.path(p))
	if err != nil {
		return FileMeta{}, err
	}
	m := FileMeta{
		Path:      p,
		Mode:      fi.Mode(),
		Size:      fi.Size(),
		ModTime:   fi.ModTime().Unix(),
		IsSymlink: fi.Mode()&fs.ModeSymlink != 0,
		UID:       -1,
		GID:       -1,
	}
	fillOwner(&m, fi)
	return m, nil
}

// commandPath is the fixed PATH for every command, so a user's PATH cannot
// swap in another binary when the audit runs under sudo.
const commandPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// Run implements System. Commands get a fixed PATH, the C locale (stable
// output to parse) and no stdin.
func (h *HostSystem) Run(ctx context.Context, name string, args ...string) (CmdResult, error) {
	bin, err := h.LookPath(name)
	if err != nil {
		return CmdResult{}, err
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = []string{"PATH=" + commandPath, "LC_ALL=C", "LANG=C"}
	var stdout, stderr cappedBuffer
	stdout.max, stderr.max = MaxOutputBytes, MaxOutputBytes
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()
	res := CmdResult{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), ExitCode: -1}
	if cmd.ProcessState != nil {
		res.ExitCode = cmd.ProcessState.ExitCode()
	}
	if stdout.over || stderr.over {
		return res, fmt.Errorf("%s: %w", name, ErrTooLarge)
	}
	var exitErr *exec.ExitError
	if runErr != nil && !errors.As(runErr, &exitErr) {
		return res, fmt.Errorf("%s: %w", name, runErr)
	}
	if ctx.Err() != nil {
		return res, fmt.Errorf("%s: %w", name, ctx.Err())
	}
	return res, nil
}

// LookPath implements System, searching only the fixed command PATH.
func (h *HostSystem) LookPath(name string) (string, error) {
	if strings.ContainsRune(name, '/') {
		return "", fmt.Errorf("command %q: give a bare name, not a path", name)
	}
	for _, dir := range filepath.SplitList(commandPath) {
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", fmt.Errorf("command %q: %w", name, exec.ErrNotFound)
}

// Identity implements System.
func (h *HostSystem) Identity() Host {
	name, _ := os.Hostname()
	euid := os.Geteuid()
	return Host{Hostname: name, UID: os.Getuid(), EUID: euid, Root: euid == 0}
}

// cappedBuffer keeps at most max bytes and remembers that it overflowed.
type cappedBuffer struct {
	bytes.Buffer
	max  int
	over bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	room := c.max - c.Len()
	if room <= 0 {
		c.over = c.over || len(p) > 0
		return len(p), nil
	}
	if len(p) > room {
		c.over = true
		c.Buffer.Write(p[:room])
		return len(p), nil
	}
	return c.Buffer.Write(p)
}
