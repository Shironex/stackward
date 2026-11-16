package report

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/sandbox"
)

// The metric names of the Prometheus textfile. They are a public interface:
// dashboards and alerts depend on them, so a name or a label is never renamed
// or given a new meaning. docs/schedule.md documents each one.
const (
	MetricResults        = "stackward_results"
	MetricLastRun        = "stackward_last_run_timestamp_seconds"
	MetricCoverageRatio  = "stackward_coverage_ratio"
	MetricRunAsRoot      = "stackward_run_as_root"
	MetricSandboxConfine = "stackward_sandbox_confined"
	MetricCollectors     = "stackward_collectors"
	MetricInfo           = "stackward_info"
)

// textfileLevels and textfileStatuses are written in this order, every one
// of them on every run, so each series exists even when its count is zero
// (an alert on a missing series would otherwise never fire).
var (
	textfileLevels   = []string{"fail", "warn", "unknown", "info", "pass", "skip"}
	textfileStatuses = []facts.Status{facts.StatusOK, facts.StatusPartial, facts.StatusFailed, facts.StatusTimeout, facts.StatusSkipped}
)

// WriteTextfile writes the summary of a report in the Prometheus text
// exposition format, for the node_exporter textfile collector. It carries
// counts and states only: no hostname, no subject, no message, so nothing
// that redaction would have to mask. The same report gives the same bytes.
func WriteTextfile(w io.Writer, r *Report) error {
	var b strings.Builder
	levels := map[string]int{
		"fail": r.Summary.Fail, "warn": r.Summary.Warn, "unknown": r.Summary.Unknown,
		"info": r.Summary.Info, "pass": r.Summary.Pass, "skip": r.Summary.Skip,
	}
	header(&b, MetricResults, "Results of the last stackward audit, by level (a check gives one result per subject).")
	for _, l := range textfileLevels {
		fmt.Fprintf(&b, "%s{level=\"%s\"} %d\n", MetricResults, l, levels[l])
	}

	header(&b, MetricLastRun, "Unix time at which the last stackward audit collected its facts.")
	fmt.Fprintf(&b, "%s %d\n", MetricLastRun, generatedUnix(r.GeneratedAt))

	header(&b, MetricCoverageRatio, "Share of the last audit's results that could be judged: checked over checked plus unknown. Skipped results do not count.")
	fmt.Fprintf(&b, "%s %s\n", MetricCoverageRatio, strconv.FormatFloat(coverageRatio(r.Coverage), 'g', 4, 64))

	header(&b, MetricRunAsRoot, "1 when the last audit ran as root (full coverage), else 0.")
	fmt.Fprintf(&b, "%s %d\n", MetricRunAsRoot, boolValue(r.Coverage.Root))

	header(&b, MetricSandboxConfine, "1 when the Landlock sandbox confined the last audit, else 0.")
	fmt.Fprintf(&b, "%s %d\n", MetricSandboxConfine, boolValue(r.Coverage.Sandbox.State == sandbox.Landlock))

	statuses := map[facts.Status]int{}
	for _, c := range r.Coverage.Collectors {
		statuses[c.Status]++
	}
	header(&b, MetricCollectors, "Collectors of the last audit, by how they ended.")
	for _, s := range textfileStatuses {
		fmt.Fprintf(&b, "%s{status=\"%s\"} %d\n", MetricCollectors, s, statuses[s])
	}

	header(&b, MetricInfo, "The stackward version and ingress profile of the last audit; the value is always 1.")
	fmt.Fprintf(&b, "%s{version=\"%s\",profile=\"%s\"} 1\n", MetricInfo, labelValue(r.Tool.Version), labelValue(string(r.Profile.Name)))

	_, err := io.WriteString(w, b.String())
	return err
}

func header(b *strings.Builder, name, help string) {
	fmt.Fprintf(b, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
}

// generatedUnix turns the report's RFC 3339 time into Unix seconds, or 0
// when it cannot be read (an alert on a stale run then fires, as it should).
func generatedUnix(s string) int64 {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return 0
	}
	return t.Unix()
}

func coverageRatio(c Coverage) float64 {
	judged := c.Checked + c.Unknown
	if judged == 0 {
		return 0
	}
	return float64(c.Checked) / float64(judged)
}

func boolValue(v bool) int {
	if v {
		return 1
	}
	return 0
}

// labelValue escapes a label value as the exposition format asks:
// backslash, double quote and line feed.
func labelValue(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}
