package cli

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/Shironex/stackward/internal/diff"
	"github.com/Shironex/stackward/internal/report"
	"github.com/Shironex/stackward/internal/sandbox"
	"github.com/Shironex/stackward/internal/version"
)

const diffUsage = `Usage: stackward diff [flags] OLD.json NEW.json

Compare two saved reports of one host (stackward audit --json --out FILE)
and print the drift (a new listener, authorized key, sudoer or root
container) and the findings that were added, removed or changed, a change
of waiver state included. It only reads the two files: no host access, no
network, under the same sandbox as audit.

Flags:
`

const (
	failOnDriftHelp = "exit 1 on: any (a new fail or warn finding, drift, or a drift check that lost coverage), fail (a new fail finding, drift or lost coverage), drift (drift or lost coverage only) or never"
	forceHostHelp   = "compare reports even when their hostname hashes differ or one has none"
)

const diffExitCodes = "\nExit codes: 0 nothing at or above --fail-on-drift, 1 drift, lost coverage or new findings at it, 2 error.\n"

type diffFlags struct {
	format      string
	jsonOut     bool
	mdOut       bool
	out         string
	failOnDrift string
	forceHost   bool
	noSandbox   bool
	// files are the two report files, fod the parsed --fail-on-drift.
	files []string
	fod   diff.FailOn
}

// parseDiffArgs parses the flags and the two file names; flags may come
// before, between or after the files. done is true when the run ends here.
func parseDiffArgs(args []string, stderr io.Writer) (df diffFlags, code int, done bool) {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&df.format, "format", "text", "output format: text, json or md")
	fs.BoolVar(&df.jsonOut, "json", false, "shorthand for --format json (schema/diff.v1.json)")
	fs.BoolVar(&df.mdOut, "md", false, "shorthand for --format md")
	fs.StringVar(&df.out, "out", "", "write the diff to this file (the only file stackward diff writes)")
	fs.StringVar(&df.failOnDrift, "fail-on-drift", string(diff.FailOnAny), failOnDriftHelp)
	fs.BoolVar(&df.forceHost, "force-host", false, forceHostHelp)
	fs.BoolVar(&df.noSandbox, "no-sandbox", false, "do not apply the Landlock self sandbox (debugging only)")
	fs.Usage = func() {
		fmt.Fprint(stderr, diffUsage)
		fs.PrintDefaults()
		fmt.Fprint(stderr, diffExitCodes)
	}
	stop := func(c int) (diffFlags, int, bool) { return df, c, true }
	for {
		if err := fs.Parse(args); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return stop(report.ExitOK)
			}
			return stop(report.ExitError)
		}
		if fs.NArg() == 0 {
			break
		}
		df.files = append(df.files, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if len(df.files) != 2 {
		fmt.Fprintf(stderr, "stackward diff: give two report files, the baseline and the new one (got %d)\n", len(df.files))
		return stop(report.ExitError)
	}
	var err error
	if df.format, err = outputFormat(df.format, df.jsonOut, df.mdOut); err == nil {
		df.fod, err = diff.ParseFailOn(df.failOnDrift)
	}
	if err != nil {
		fmt.Fprintf(stderr, "stackward diff: %v\n", err)
		return stop(report.ExitError)
	}
	return df, 0, false
}

// outputFormat resolves --format and its --json and --md shorthands.
func outputFormat(format string, jsonOut, mdOut bool) (string, error) {
	if jsonOut {
		format = "json"
	}
	if mdOut {
		format = "md"
	}
	if format != "text" && format != "json" && format != "md" {
		return "", fmt.Errorf("--format must be text, json or md, not %q", format)
	}
	return format, nil
}

func runDiff(args []string, stdout, stderr io.Writer) int {
	df, code, done := parseDiffArgs(args, stderr)
	if done {
		return code
	}
	fail := func(err error) int {
		fmt.Fprintf(stderr, "stackward diff: %v\n", err)
		return report.ExitError
	}
	// Both reports and the output file are opened before the sandbox,
	// which forbids opening anything for writing afterwards.
	var inputs [2]*os.File
	for i, path := range df.files {
		fh, err := openInput(path)
		if err != nil {
			return fail(fmt.Errorf("%s: %w", path, err))
		}
		defer func() { _ = fh.Close() }()
		inputs[i] = fh
	}
	w := stdout
	if df.out != "" {
		outFile, err := createOutput(df.out, inputs[:]...)
		if err != nil {
			return fail(err)
		}
		defer func() { _ = outFile.Close() }()
		w = outFile
	}

	// Only reading is left; the status matters to a report, not a diff.
	_ = sandbox.Apply(sandbox.Options{Disabled: df.noSandbox})

	var reps [2]*report.Report
	for i, fh := range inputs {
		rep, err := diff.LoadReport(fh)
		if err != nil {
			return fail(fmt.Errorf("%s: %w", df.files[i], err))
		}
		reps[i] = rep
	}
	d, err := diff.Compare(reps[0], reps[1], diff.Options{Version: version.String(), ForceHost: df.forceHost})
	if err != nil {
		return fail(err)
	}
	if err := writeDiff(w, d, df.format); err != nil {
		return fail(fmt.Errorf("writing the diff: %w", err))
	}
	return d.ExitCode(df.fod)
}

func writeDiff(w io.Writer, d *diff.Diff, format string) error {
	switch format {
	case "json":
		return diff.WriteJSON(w, d)
	case "md":
		return diff.WriteMarkdown(w, d)
	}
	return diff.WriteText(w, d)
}

// baselineFlags are the audit flags of --baseline.
type baselineFlags struct {
	file        string
	failOnDrift string
	forceHost   bool
	// fh is the baseline file, opened before the sandbox.
	fh *os.File
}

func addBaselineFlags(fs *flag.FlagSet, b *baselineFlags) {
	fs.StringVar(&b.file, "baseline", "", "compare this audit with a saved report of the same host and print the diff instead of the report (see stackward diff)")
	fs.StringVar(&b.failOnDrift, "fail-on-drift", string(diff.FailOnAny), "with --baseline, "+failOnDriftHelp)
	fs.BoolVar(&b.forceHost, "force-host", false, "with --baseline, "+forceHostHelp)
}

// check refuses baseline flags without --baseline and --baseline with
// flags it does not go with. set holds the flags given.
func (b baselineFlags) check(set map[string]bool) error {
	if b.file == "" {
		for _, n := range []string{"fail-on-drift", "force-host"} {
			if set[n] {
				return fmt.Errorf("--%s goes with --baseline", n)
			}
		}
		return nil
	}
	if set["dump-facts"] {
		return errors.New("--baseline does not go with --dump-facts")
	}
	_, err := diff.ParseFailOn(b.failOnDrift)
	return err
}

// open opens the --baseline file, before the sandbox.
func (b *baselineFlags) open() error {
	if b.file == "" {
		return nil
	}
	fh, err := openInput(b.file)
	if err != nil {
		return fmt.Errorf("--baseline %s: %w", b.file, err)
	}
	b.fh = fh
	return nil
}

// opened is the opened --baseline file as a list, for --out to stay
// clear of.
func (b baselineFlags) opened() []*os.File {
	if b.fh == nil {
		return nil
	}
	return []*os.File{b.fh}
}

func (b *baselineFlags) close() {
	if b.fh != nil {
		_ = b.fh.Close()
	}
}

// baselineDiff diffs a fresh report against the --baseline file and
// writes the diff. The fresh report goes through the same loader as a
// saved one (JSON, schema check, cleaning, redaction), so both sides are
// compared and rendered alike. The exit code is the diff's under
// --fail-on-drift; an explicit --fail-on also counts.
func baselineDiff(w io.Writer, rep *report.Report, af auditFlags, failOn report.FailOn) (int, error) {
	old, err := diff.LoadReport(af.base.fh)
	if err != nil {
		return report.ExitError, fmt.Errorf("--baseline %s: %w", af.base.file, err)
	}
	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, rep); err != nil {
		return report.ExitError, err
	}
	cur, err := diff.LoadReport(&buf)
	if err != nil {
		return report.ExitError, fmt.Errorf("this audit's report: %w", err)
	}
	d, err := diff.Compare(old, cur, diff.Options{Version: version.String(), ForceHost: af.base.forceHost})
	if err != nil {
		return report.ExitError, err
	}
	if err := writeDiff(w, d, af.format); err != nil {
		return report.ExitError, fmt.Errorf("writing the diff: %w", err)
	}
	fod, _ := diff.ParseFailOn(af.base.failOnDrift) // checked with the flags
	code := d.ExitCode(fod)
	if af.failOnSet && rep.ExitCode(failOn) != report.ExitOK {
		code = report.ExitFindings
	}
	return code, nil
}

// visited returns the names of the flags given on the command line.
func visited(fs *flag.FlagSet) map[string]bool {
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })
	return set
}

// checkRegular returns fh when it is a regular file and closes it
// otherwise.
func checkRegular(fh *os.File) (*os.File, error) {
	fi, err := fh.Stat()
	if err == nil && !fi.Mode().IsRegular() {
		err = errors.New("not a regular file")
	}
	if err != nil {
		_ = fh.Close()
		return nil, err
	}
	return fh, nil
}

// notAnInput refuses an output file that is one of the files the run
// reads: writing the diff over a report would destroy it before it is read.
// It compares the opened descriptors (fstat), never the paths again, so a
// path swapped after the input was opened changes nothing.
func notAnInput(out os.FileInfo, inputs []*os.File) error {
	for _, in := range inputs {
		fi, err := in.Stat()
		if err != nil {
			return fmt.Errorf("%s: %w", in.Name(), err)
		}
		if os.SameFile(out, fi) {
			return fmt.Errorf("%s is also an input; write the output to another file", in.Name())
		}
	}
	return nil
}
