package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Shironex/stackward/internal/probe"
	"github.com/Shironex/stackward/internal/profile"
	"github.com/Shironex/stackward/internal/report"
	"github.com/Shironex/stackward/internal/sandbox"
	"github.com/Shironex/stackward/internal/version"
)

// Seams for the consent prompt, so tests can answer it.
var (
	probeStdin    io.Reader = os.Stdin
	probeStdinTTY           = func() bool {
		fi, err := os.Stdin.Stat()
		return err == nil && fi.Mode()&os.ModeCharDevice != 0
	}
)

// probeLocalAddrs is the seam for this machine's addresses, so tests can
// pretend to be any host.
var probeLocalAddrs probe.LocalAddrs = probe.InterfaceAddrs

type probeFlags struct {
	hostname  string
	ports     string
	format    string
	jsonOut   bool
	out       string
	failOn    string
	profile   string
	timeout   time.Duration
	iOwnThis  bool
	noSandbox bool
	all       bool
	plain     bool
}

// newProbeFlagSet declares the probe flags into pf.
func newProbeFlagSet(pf *probeFlags, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&pf.hostname, "hostname", "", "also check this app hostname over HTTPS (redirect loops, TLS)")
	fs.StringVar(&pf.ports, "ports", "", "extra TCP ports to try, comma separated (for example a moved SSH port)")
	fs.StringVar(&pf.format, "format", "text", "output format: text or json")
	fs.BoolVar(&pf.jsonOut, "json", false, "shorthand for --format json")
	fs.StringVar(&pf.out, "out", "", "write the report to this file (the only file stackward writes)")
	fs.StringVar(&pf.failOn, "fail-on", "fail", "exit 1 when a result is at or above: fail, warn or never")
	fs.StringVar(&pf.profile, "profile", "auto", "ingress profile of the target: auto, tunnel, public-web, tailnet-only or paas-panel")
	fs.DurationVar(&pf.timeout, "timeout", probe.DefaultTimeout, "time limit for each TCP connect and banner read")
	fs.BoolVar(&pf.iOwnThis, "i-own-this", false, "confirm you own the host or may test it (required when not on a terminal)")
	fs.BoolVar(&pf.noSandbox, "no-sandbox", false, "do not apply the Landlock self sandbox (debugging only)")
	fs.BoolVar(&pf.all, "all", false, "text output: list passing and skipped results too")
	fs.BoolVar(&pf.plain, "plain", false, "text output: no colors, Unicode or box lines, as when piped (NO_COLOR drops only colors)")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "Usage: stackward probe <host-or-ip> [flags]\n\n")
		fmt.Fprintf(stderr, "Run from another machine: plain TCP connects to a short fixed port list over\nIPv4 and IPv6, an SSH banner read, an HTTP check of the raw IP and an\noptional HTTPS check of --hostname. One host only; ranges are refused.\n\nFlags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(stderr, "\nExit codes: 0 no finding at or above --fail-on, 1 findings, 2 error.\n")
	}
	return fs
}

func runProbe(args []string, stdout, stderr io.Writer) int {
	var pf probeFlags
	fs := newProbeFlagSet(&pf, stderr)
	// Flags may come before or after the host.
	var positional []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return report.ExitOK
			}
			return report.ExitError
		}
		if fs.NArg() == 0 {
			break
		}
		positional = append(positional, fs.Arg(0))
		rest = fs.Args()[1:]
	}
	fail := func(format string, a ...any) int {
		fmt.Fprintf(stderr, "stackward probe: "+format+"\n", a...)
		return report.ExitError
	}
	if len(positional) != 1 {
		return fail("give exactly one host name or IP address (got %d); run \"stackward probe -h\"", len(positional))
	}
	target, err := probe.ParseTarget(positional[0])
	if err != nil {
		return fail("%v", err)
	}
	hostname, err := probe.ParseHostname(pf.hostname)
	if err != nil {
		return fail("%v", err)
	}
	extra, err := probe.ParsePorts(pf.ports)
	if err != nil {
		return fail("%v", err)
	}
	if pf.jsonOut {
		pf.format = "json"
	}
	if pf.format != "text" && pf.format != "json" {
		return fail("--format must be text or json, not %q", pf.format)
	}
	failOn := report.FailOn(pf.failOn)
	if failOn != report.FailOnFail && failOn != report.FailOnWarn && failOn != report.FailOnNever {
		return fail("--fail-on must be fail, warn or never, not %q", pf.failOn)
	}
	prof, profSet, err := profile.Parse(pf.profile)
	if err != nil {
		return fail("%v", err)
	}
	if pf.timeout <= 0 || pf.timeout > time.Minute {
		return fail("--timeout must be between 1ms and 1m")
	}

	if err := probe.Confirm(target, pf.iOwnThis, probeStdinTTY(), probeStdin, stderr); err != nil {
		return fail("%v", err)
	}

	w := stdout
	var outFile *os.File
	if pf.out != "" {
		outFile, err = createOutput(pf.out)
		if err != nil {
			return fail("%v", err)
		}
		defer func() { _ = outFile.Close() }()
		w = outFile
	}
	textOpts := textOptions(stdout, outFile != nil, pf.plain)
	textOpts.Passing = pf.all
	// Probe needs outbound TCP, so only file writes are taken away.
	sb := sandbox.Apply(sandbox.Options{Disabled: pf.noSandbox, AllowNetwork: true})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	facts := probe.Run(ctx, probe.Options{
		Target: target, Hostname: hostname, Extra: extra, Timeout: pf.timeout,
		UserAgent:  "stackward-probe/" + version.String(),
		LocalAddrs: probeLocalAddrs,
		OnSelfTarget: func(addrs []string) {
			fmt.Fprintf(stderr, "stackward probe: warning: %s is this machine (%s). %s\n", target, strings.Join(addrs, ", "), probe.SelfNote)
		},
	})
	rep, err := probe.Evaluate(facts, probe.EvalOptions{
		Version: version.String(), Sandbox: sb, Profile: prof, ProfileSet: profSet,
	})
	if err != nil {
		return fail("%v", err)
	}
	if pf.format == "json" {
		err = report.WriteJSON(w, rep)
	} else {
		err = report.WriteText(w, rep, textOpts)
	}
	if err != nil {
		return fail("writing report: %v", err)
	}
	return rep.ExitCode(failOn)
}
