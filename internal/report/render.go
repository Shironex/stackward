package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/Shironex/stackward/internal/sandbox"
)

// toAny normalizes evidence to plain JSON values (maps, slices, strings,
// json.Number, bools) so redaction can walk every string in it.
func toAny(v map[string]any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return map[string]any{"error": "evidence could not be encoded: " + err.Error()}
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var out any
	if err := dec.Decode(&out); err != nil {
		return map[string]any{"error": "evidence could not be decoded: " + err.Error()}
	}
	return out
}

// WriteJSON writes the report as indented JSON. Struct field order is kept
// and evidence keys are sorted, so the same input gives the same bytes.
func WriteJSON(w io.Writer, r *Report) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// CoverageLine says how many checks ran and how their results split. A
// check gives one result per subject (a container, a port, a file), so
// results outnumber checks; the counts after the colon are results.
func CoverageLine(c Coverage) string {
	return fmt.Sprintf("%d checks, %d results: %d checked, %d unknown, %d skipped",
		c.Checks, c.Results, c.Checked, c.Unknown, c.Skipped)
}

// NotRootNote is the one line that says a run without root left results
// unknown, so no result has to repeat the advice. It is empty for a root run
// and for a run where nothing is unknown.
func NotRootNote(r *Report) string {
	if r.Coverage.Root || r.Summary.Unknown == 0 {
		return ""
	}
	return fmt.Sprintf("not root: %s could not be inspected; run with sudo for full coverage",
		plural(r.Summary.Unknown, "result", "results"))
}

func sandboxLine(s sandbox.Status) string {
	switch {
	case s.State == sandbox.Landlock && s.Network:
		return fmt.Sprintf("landlock (abi %d, no writes, no tcp)", s.ABI)
	case s.State == sandbox.Landlock:
		return fmt.Sprintf("landlock (abi %d, no writes)", s.ABI)
	case s.Reason != "":
		return fmt.Sprintf("%s (%s)", s.State, s.Reason)
	}
	return orDash(string(s.State))
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func joinNonEmpty(a, b string) string {
	if a == "" {
		return b
	}
	return a + "; " + b
}
