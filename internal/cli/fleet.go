package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Shironex/stackward/internal/fleet"
	"github.com/Shironex/stackward/internal/report"
	"github.com/Shironex/stackward/internal/version"
)

// sshFlags are the flags of stackward audit --ssh.
type sshFlags struct {
	on       bool
	hosts    string
	binaries stringList
	sudo     bool
	parallel int
	timeout  time.Duration
}

// stringList is a repeatable string flag.
type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// sshHelp is appended to the usage of audit.
const sshHelp = `
Audit other hosts over ssh (--ssh):
  stackward audit --ssh [flags] [--] HOST...
  stackward audit --ssh-hosts FILE [flags]
  Uses your own ssh client and ssh config (keys, agent, jump hosts, known
  hosts); stackward never sees a key or a password, and ssh runs in batch
  mode, so set up key or agent login first. For each host it reads the
  architecture, streams a matching stackward binary into a new private
  temporary directory (mode 700), runs the same read only audit there with
  --json, reads the report and removes the directory, even on failure. That
  upload is the only write on the host. Pass --ssh-sudo for full coverage
  (sudo -n: needs passwordless sudo). One failing host never stops the
  others; exit code 2 when any host could not be audited. Host names are
  kept only in the report you ask for.
`

func addSSHFlags(fs *flag.FlagSet, s *sshFlags) {
	fs.BoolVar(&s.on, "ssh", false, "audit the hosts named after the flags over ssh instead of this host (see below)")
	fs.StringVar(&s.hosts, "ssh-hosts", "", "with --ssh: read hosts from this file, one per line, # comments (implies --ssh)")
	fs.Var(&s.binaries, "ssh-binary", "with --ssh: the linux stackward build to copy (default this binary); repeat for amd64 and arm64")
	fs.BoolVar(&s.sudo, "ssh-sudo", false, "with --ssh: run the remote audit with sudo -n (full coverage; passwordless sudo only)")
	fs.IntVar(&s.parallel, "ssh-parallel", fleet.DefaultParallel, fmt.Sprintf("with --ssh: hosts audited at once (1 to %d)", fleet.MaxParallel))
	fs.DurationVar(&s.timeout, "ssh-timeout", fleet.DefaultHostTimeout, "with --ssh: time limit for each host")
}

// enabled reports whether this is a fleet run.
func (s sshFlags) enabled() bool { return s.on || s.hosts != "" }

// check validates the ssh flags against the rest of the audit flags.
func (s sshFlags) check(af auditFlags, hosts []string) error {
	if !s.enabled() {
		if len(s.binaries) > 0 || s.sudo {
			return fmt.Errorf("--ssh-binary and --ssh-sudo need --ssh")
		}
		return nil
	}
	switch {
	case af.factsFile != "" || af.dumpFacts:
		return fmt.Errorf("--ssh audits live hosts; it cannot be combined with --facts or --dump-facts")
	case af.prov.name != "":
		return fmt.Errorf("--ssh cannot be combined with --provider: no credential is sent to a host")
	case af.textfile != "":
		return fmt.Errorf("--ssh cannot be combined with --textfile yet: the metric describes one host, and a fleet metric needs its own labels and design")
	case af.waivers != "":
		return fmt.Errorf("--ssh cannot be combined with --waivers yet: a local waivers file would have to apply to every host's report, which needs its own design")
	case af.noSandbox:
		return fmt.Errorf("--ssh always runs the remote audit in its sandbox; --no-sandbox is refused")
	case s.parallel < 1 || s.parallel > fleet.MaxParallel:
		return fmt.Errorf("--ssh-parallel must be 1 to %d, not %d", fleet.MaxParallel, s.parallel)
	case s.timeout <= 0:
		return fmt.Errorf("--ssh-timeout must be positive")
	case len(hosts) == 0 && s.hosts == "":
		return fmt.Errorf("--ssh needs at least one host after the flags, or --ssh-hosts FILE")
	}
	return nil
}

// fleetLoadBinaries is the seam tests use to copy a stand in for the
// binary.
var fleetLoadBinaries = fleet.LoadBinaries

// fleetNow is the clock of the fleet report, a seam for tests.
var fleetNow = time.Now

// runFleetAudit is stackward audit --ssh. It runs no collector and applies
// no sandbox here: this machine only starts ssh, which needs the network
// and writes its own files (known hosts, control sockets). Each remote audit
// applies its own sandbox.
func runFleetAudit(af auditFlags, failOn report.FailOn, stdout, stderr io.Writer) int {
	fail := func(err error) int {
		fmt.Fprintf(stderr, "stackward audit: %v\n", err)
		return report.ExitError
	}
	var fromFile []string
	if af.ssh.hosts != "" {
		fh, err := os.Open(af.ssh.hosts)
		if err != nil {
			return fail(fmt.Errorf("--ssh-hosts: %w", err))
		}
		fromFile, err = fleet.ReadHosts(fh)
		_ = fh.Close()
		if err != nil {
			return fail(fmt.Errorf("--ssh-hosts %s: %w", af.ssh.hosts, err))
		}
	}
	hosts, err := fleet.Hosts(af.args, fromFile)
	if err != nil {
		return fail(err)
	}
	bins, err := fleetLoadBinaries(af.ssh.binaries, version.String())
	if err != nil {
		return fail(err)
	}
	w := stdout
	var outFile *os.File
	if af.out != "" {
		if outFile, err = createOutput(af.out); err != nil {
			return fail(err)
		}
		defer func() { _ = outFile.Close() }()
		w = outFile
	}
	textOpts := textOptions(stdout, outFile != nil, af.plain)
	textOpts.Passing, textOpts.Info, textOpts.Group = af.all, af.info, af.group

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	started := fleetNow().UTC().Format(time.RFC3339)
	results, err := fleet.Run(ctx, hosts, fleet.Options{
		Binaries: bins, Sudo: af.ssh.sudo, Parallel: af.ssh.parallel, HostTimeout: af.ssh.timeout,
		Remote:  fleet.RemoteArgs{Profile: af.profile, Timeout: af.timeout, ShowHostname: af.showHostname},
		Version: version.String(),
	})
	if err != nil {
		return fail(err)
	}
	fl := report.NewFleet(version.String(), started, results)
	switch af.format {
	case "json":
		err = report.WriteFleetJSON(w, fl)
	case "md":
		err = report.WriteFleetMarkdown(w, fl, report.MarkdownOptions{Passing: af.all})
	default:
		err = report.WriteFleetText(w, fl, textOpts)
	}
	if err != nil {
		return fail(fmt.Errorf("writing report: %w", err))
	}
	for _, h := range fl.Hosts {
		if h.Error != "" {
			fmt.Fprintf(stderr, "stackward audit: %s: %s\n", h.Host, h.Error)
		}
	}
	return fl.ExitCode(failOn)
}
