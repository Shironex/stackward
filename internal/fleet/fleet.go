package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Shironex/stackward/internal/redact"
	"github.com/Shironex/stackward/internal/report"
)

// Limits of one run.
const (
	// DefaultParallel is how many hosts are audited at once by default.
	DefaultParallel = 4
	// MaxParallel caps --ssh-parallel.
	MaxParallel = 32
	// DefaultHostTimeout bounds everything done for one host.
	DefaultHostTimeout = 10 * time.Minute
	// maxReport caps the JSON read from one host.
	maxReport = 32 << 20
	// maxStderr caps the standard error kept from one host.
	maxStderr = 64 << 10
	// cleanupTimeout bounds the extra connection that removes a leftover
	// directory after a failed run.
	cleanupTimeout = 30 * time.Second
)

// Options configures a fleet run.
type Options struct {
	// Binaries are the Linux builds to copy, at most one per architecture.
	Binaries []Binary
	// Sudo runs the remote audit with sudo -n (no password prompt; the
	// host's sudoers must allow it).
	Sudo bool
	// Parallel is how many hosts run at once (1 to MaxParallel).
	Parallel int
	// HostTimeout bounds each host, DefaultHostTimeout when zero.
	HostTimeout time.Duration
	// Remote are the audit flags passed on.
	Remote RemoteArgs
	// Version names the release asset in an architecture mismatch.
	Version string
}

// Run audits every host, at most o.Parallel at a time, and returns one
// result per host in the order given. A failing host is reported in its
// result and never stops the others.
func Run(ctx context.Context, hosts []string, o Options) ([]report.FleetHost, error) {
	args, err := o.Remote.args()
	if err != nil {
		return nil, err
	}
	if len(o.Binaries) == 0 {
		return nil, errors.New("no binary to copy")
	}
	n := o.Parallel
	if n < 1 {
		n = 1
	}
	if n > MaxParallel {
		n = MaxParallel
	}
	if o.HostTimeout <= 0 {
		o.HostTimeout = DefaultHostTimeout
	}
	script := remoteCommand(remoteScript(o.Sudo, args))
	out := make([]report.FleetHost, len(hosts))
	sem := make(chan struct{}, n)
	var wg sync.WaitGroup
	for i, h := range hosts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i] = auditHost(ctx, h, script, o)
		}()
	}
	wg.Wait()
	return out, nil
}

// auditHost does everything for one host: architecture, upload and run,
// report, cleanup on failure.
func auditHost(ctx context.Context, host, script string, o Options) report.FleetHost {
	res := report.FleetHost{Host: host, Status: report.FleetError}
	if ctx.Err() != nil {
		res.Error = "not started: the run was interrupted"
		return res
	}
	hctx, cancel := context.WithTimeout(ctx, o.HostTimeout)
	defer cancel()

	arch, err := remoteArch(hctx, host)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.Arch = string(arch)
	bin, err := pickBinary(o.Binaries, arch, o.Version)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	f, err := os.Open(bin.Path)
	if err != nil {
		res.Error = "cannot read the binary to copy: " + err.Error()
		return res
	}
	defer func() { _ = f.Close() }()

	stdout := &capped{max: maxReport, strict: true}
	stderr := &capped{max: maxStderr}
	code, runErr := runSSH(hctx, host, script, f, stdout, stderr)
	if code != 0 || runErr != nil {
		res.Error = runFailure(code, runErr, stderr.Bytes(), stdout.over)
		res.Cleanup = cleanupAfterFailure(ctx, host, stderr.Bytes())
		return res
	}
	rep, err := parseReport(stdout.Bytes())
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.Status, res.Report = report.FleetAudited, rep
	return res
}

// remoteArch asks the host for `uname -m`. It is also the connection test:
// an ssh failure shows here, before anything is copied.
func remoteArch(ctx context.Context, host string) (Arch, error) {
	stdout := &capped{max: 256, strict: true}
	stderr := &capped{max: maxStderr}
	code, err := runSSH(ctx, host, archCommand, nil, stdout, stderr)
	switch {
	case err != nil:
		return "", fmt.Errorf("ssh: %w", err)
	case code == 255:
		return "", fmt.Errorf("ssh failed (exit 255): %s", tail(stderr.Bytes()))
	case code != 0:
		return "", fmt.Errorf("uname -m failed (exit %d): %s", code, tail(stderr.Bytes()))
	}
	return RemoteArch(string(stdout.Bytes()))
}

// runFailure explains why the remote run did not give a report.
func runFailure(code int, err error, stderr []byte, overflow bool) string {
	msg := tail([]byte(stripMarker(stderr)))
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timed out (--ssh-timeout)"
	case errors.Is(err, context.Canceled):
		return "interrupted"
	case overflow:
		return fmt.Sprintf("the report was larger than %d MiB", maxReport>>20)
	case err != nil:
		return "ssh: " + err.Error()
	case code == 255:
		return "ssh failed (exit 255): " + msg
	case code == exitSetup:
		return "could not create the private temporary directory or copy the binary: " + msg
	case code == exitInterrupted:
		return "the remote run was interrupted (connection lost or signal)"
	case code == 126 || code == 127:
		return fmt.Sprintf("could not start the copied binary (exit %d; is the temporary directory on a noexec mount?): %s", code, msg)
	case strings.Contains(msg, "sudo:"):
		return "sudo -n refused (--ssh-sudo needs passwordless sudo for this user): " + msg
	}
	return fmt.Sprintf("the remote audit failed (exit %d): %s", code, msg)
}

// cleanupAfterFailure removes the directory the script announced, in case
// its trap could not run (the connection broke, the run was killed). It is
// best effort with its own short timeout, even after an interrupt; when
// the directory was never announced nothing was created. It returns a note
// for the report when the removal could not be confirmed.
func cleanupAfterFailure(ctx context.Context, host string, stderr []byte) string {
	dir, ok := tmpDirFrom(stderr)
	if !ok {
		if bytes.Contains(stderr, []byte(tmpMarker)) {
			return "a temporary directory was announced in an unexpected form and was not removed; check the host's temporary directory"
		}
		return ""
	}
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
	defer cancel()
	errb := &capped{max: maxStderr}
	code, err := runSSH(cctx, host, cleanupCommand(dir), nil, &capped{max: 4096}, errb)
	if err != nil || code != 0 {
		return fmt.Sprintf("could not confirm that %s was removed (%s); remove it by hand", dir, firstNonEmpty(errString(err), tail(errb.Bytes())))
	}
	return ""
}

// parseReport decodes and cleans the report a host sent.
func parseReport(b []byte) (*report.Report, error) {
	var r report.Report
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("the host did not send a report.v1 JSON document: %w", err)
	}
	if r.Schema != report.SchemaID {
		return nil, fmt.Errorf("the host sent schema %q, want %q", cleanText(r.Schema), report.SchemaID)
	}
	if r.Probe != nil {
		return nil, errors.New("the host sent a probe report, not an audit")
	}
	cleanReport(&r)
	return &r, nil
}

// tail returns the last line of stderr worth showing, cleaned and
// redacted.
func tail(b []byte) string {
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	s := strings.TrimSpace(lines[len(lines)-1])
	if len(s) > 300 {
		s = s[len(s)-300:]
	}
	s = redact.String(cleanText(s))
	if s == "" {
		return "no error output"
	}
	return s
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// capped is a writer that keeps at most max bytes. When strict, writing
// past the cap fails, which stops ssh; otherwise the rest is dropped.
type capped struct {
	buf    bytes.Buffer
	max    int
	strict bool
	over   bool
}

func (c *capped) Write(p []byte) (int, error) {
	room := c.max - c.buf.Len()
	if len(p) <= room {
		return c.buf.Write(p)
	}
	c.over = true
	if room > 0 {
		c.buf.Write(p[:room])
	}
	if c.strict {
		return room, errors.New("output cap reached")
	}
	return len(p), nil
}

func (c *capped) Bytes() []byte { return c.buf.Bytes() }
