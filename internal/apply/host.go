package apply

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Host is the one seam through which apply and undo touch a system: every
// file read, write, copy and removal, and every command. Paths are host
// paths ("/etc/docker/daemon.json"). NewHost("/") is the real machine;
// tests use NewHost(t.TempDir()) with a fake Runner, so nothing a test
// does lands outside its temporary directory.
type Host interface {
	// ReadFile reads a regular file; a missing file matches fs.ErrNotExist.
	ReadFile(p string) ([]byte, error)
	// Stat describes p without following a final symlink.
	Stat(p string) (FileState, error)
	// WriteAtomic replaces (or creates) p with data: a temporary file in
	// the same directory, mode and owner set, fsync, check(staged path),
	// rename, fsync of the directory. A check error removes the temporary
	// file and leaves p untouched.
	WriteAtomic(p string, data []byte, st FileState, check func(staged string) error) error
	// CopyNew copies src to dst, which must not exist yet (O_EXCL, never a
	// symlink), keeping the mode and owner of src.
	CopyNew(src, dst string) error
	// MkdirAll creates p and its missing parents with mode.
	MkdirAll(p string, mode fs.FileMode) error
	// Remove deletes the file p, or the empty directory p.
	Remove(p string) error
	// ReadDir lists the names in directory p, sorted; a missing directory
	// is an empty list.
	ReadDir(p string) ([]string, error)
	// Lock takes the exclusive lock file p without waiting and writes
	// holder into it. When another process holds it, the error is a
	// *HeldError naming that holder. The lock is released by the returned
	// function or when the process ends, so a file left by a dead process
	// is not a lock. See lock.go.
	Lock(p, holder string) (release func() error, err error)
	// Run starts args[0] from the fixed PATH, without a shell.
	Run(ctx context.Context, args []string) CmdResult
}

// FileState is what apply needs to know about a file before it writes.
type FileState struct {
	Exists  bool
	Regular bool
	Symlink bool
	Mode    fs.FileMode // permission bits
	// UID and GID are the owner; -1 leaves the owner to the writing
	// process (root on a real run).
	UID, GID int
}

// CmdResult is a finished command.
type CmdResult struct {
	ExitCode int
	Output   []byte // stdout and stderr, capped
	Duration time.Duration
	Err      error // the command could not start or timed out
}

// Runner runs commands for a Host.
type Runner interface {
	Run(ctx context.Context, args []string) CmdResult
}

// NewHost returns a Host whose paths live under root, running commands
// with r (nil means ExecRunner).
func NewHost(root string, r Runner) Host {
	if r == nil {
		r = ExecRunner{}
	}
	return &dirHost{root: root, run: r}
}

type dirHost struct {
	root string
	run  Runner
}

// real maps a host path to the path on this machine. Only absolute, clean
// paths are accepted, so nothing escapes the root.
func (h *dirHost) real(p string) (string, error) {
	if !path.IsAbs(p) || path.Clean(p) != p || strings.ContainsRune(p, 0) {
		return "", fmt.Errorf("refusing path %q: not an absolute clean path", p)
	}
	return filepath.Join(h.root, filepath.FromSlash(p)), nil
}

func (h *dirHost) ReadFile(p string) ([]byte, error) {
	rp, err := h.real(p)
	if err != nil {
		return nil, err
	}
	st, err := h.Stat(p)
	if err != nil {
		return nil, err
	}
	if !st.Exists {
		return nil, fmt.Errorf("%s: %w", p, fs.ErrNotExist)
	}
	if st.Symlink {
		return nil, fmt.Errorf("%s is a symlink; stackward does not read or write through links", p)
	}
	if !st.Regular {
		return nil, fmt.Errorf("%s is not a regular file", p)
	}
	f, err := os.OpenFile(rp, os.O_RDONLY|noFollow, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(f)
}

func (h *dirHost) Stat(p string) (FileState, error) {
	rp, err := h.real(p)
	if err != nil {
		return FileState{}, err
	}
	fi, err := os.Lstat(rp)
	if errors.Is(err, fs.ErrNotExist) {
		return FileState{UID: -1, GID: -1}, nil
	}
	if err != nil {
		return FileState{}, err
	}
	st := FileState{
		Exists:  true,
		Regular: fi.Mode().IsRegular(),
		Symlink: fi.Mode()&fs.ModeSymlink != 0,
		Mode:    fi.Mode().Perm(),
		UID:     -1, GID: -1,
	}
	st.UID, st.GID = owner(fi)
	return st, nil
}

func (h *dirHost) WriteAtomic(p string, data []byte, st FileState, check func(staged string) error) error {
	rp, err := h.real(p)
	if err != nil {
		return err
	}
	dir := filepath.Dir(rp)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(rp)+".stackward-*")
	if err != nil {
		return err
	}
	staged := tmp.Name()
	done := false
	defer func() {
		if !done {
			_ = tmp.Close()
			_ = os.Remove(staged)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Chmod(st.Mode.Perm()); err != nil {
		return err
	}
	if st.UID >= 0 && st.GID >= 0 {
		if err := tmp.Chown(st.UID, st.GID); err != nil {
			return err
		}
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if check != nil {
		if err := check(staged); err != nil {
			return err
		}
	}
	if err := os.Rename(staged, rp); err != nil {
		return err
	}
	done = true
	return syncDir(dir)
}

func (h *dirHost) CopyNew(src, dst string) error {
	rs, err := h.real(src)
	if err != nil {
		return err
	}
	rd, err := h.real(dst)
	if err != nil {
		return err
	}
	in, err := os.OpenFile(rs, os.O_RDONLY|noFollow, 0)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	fi, err := in.Stat()
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}
	out, err := os.OpenFile(rd, os.O_WRONLY|os.O_CREATE|os.O_EXCL|noFollow, 0o600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		if !ok {
			_ = out.Close()
			_ = os.Remove(rd)
		}
	}()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	if err := out.Chmod(fi.Mode().Perm()); err != nil {
		return err
	}
	if uid, gid := owner(fi); uid >= 0 && gid >= 0 {
		if err := out.Chown(uid, gid); err != nil {
			return err
		}
	}
	if err := out.Sync(); err != nil {
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	ok = true
	return syncDir(filepath.Dir(rd))
}

func (h *dirHost) MkdirAll(p string, mode fs.FileMode) error {
	rp, err := h.real(p)
	if err != nil {
		return err
	}
	return os.MkdirAll(rp, mode)
}

func (h *dirHost) Remove(p string) error {
	rp, err := h.real(p)
	if err != nil {
		return err
	}
	if err := os.Remove(rp); err != nil {
		return err
	}
	return syncDir(filepath.Dir(rp))
}

func (h *dirHost) ReadDir(p string) ([]string, error) {
	rp, err := h.real(p)
	if err != nil {
		return nil, err
	}
	ents, err := os.ReadDir(rp)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	names := make([]string, len(ents))
	for i, e := range ents {
		names[i] = e.Name()
	}
	return names, nil
}

func (h *dirHost) Run(ctx context.Context, args []string) CmdResult {
	return h.run.Run(ctx, args)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	if err := d.Sync(); err != nil && !errors.Is(err, syscall.EINVAL) {
		return err
	}
	return nil
}

// commandPath is the fixed PATH for every command apply runs, the same as
// the audit's (facts.HostSystem), so a user's PATH cannot swap in another
// binary under sudo.
const commandPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// maxOutput caps what a command may print into the journal.
const maxOutput = 64 << 10

// ExecRunner runs real programs: a bare name looked up in the fixed PATH,
// the C locale, no stdin, no shell.
type ExecRunner struct{}

// Run implements Runner.
func (ExecRunner) Run(ctx context.Context, args []string) CmdResult {
	start := time.Now()
	res := CmdResult{ExitCode: -1}
	if len(args) == 0 {
		res.Err = errors.New("empty command")
		return res
	}
	bin, err := lookPath(args[0])
	if err != nil {
		res.Err = err
		return res
	}
	c := exec.CommandContext(ctx, bin, args[1:]...)
	c.Env = []string{"PATH=" + commandPath, "LC_ALL=C", "LANG=C"}
	var out capped
	c.Stdout, c.Stderr = &out, &out
	runErr := c.Run()
	res.Duration = time.Since(start)
	res.Output = out.Bytes()
	if c.ProcessState != nil {
		res.ExitCode = c.ProcessState.ExitCode()
	}
	var exitErr *exec.ExitError
	if runErr != nil && !errors.As(runErr, &exitErr) {
		res.Err = runErr
	}
	if ctx.Err() != nil {
		res.Err = ctx.Err()
	}
	return res
}

func lookPath(name string) (string, error) {
	if name == "" || strings.ContainsRune(name, '/') {
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

type capped struct{ bytes.Buffer }

func (c *capped) Write(p []byte) (int, error) {
	if room := maxOutput - c.Len(); room > 0 {
		c.Buffer.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}
