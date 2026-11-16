package diff

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"

	"github.com/Shironex/stackward/internal/redact"
	"github.com/Shironex/stackward/internal/report"
	"github.com/Shironex/stackward/internal/schemacheck"
	"github.com/Shironex/stackward/schema"
)

// MaxReportBytes caps a report file. Real reports are a few hundred KiB;
// the cap keeps a hostile file from filling memory.
const MaxReportBytes = 32 << 20

// maxErrors is how many schema violations an error names.
const maxErrors = 3

// LoadReport reads one report file for a diff. The file is untrusted: it is
// read up to MaxReportBytes, must be a single report.v1 JSON document that
// validates against schema/report.v1.json, and every string in it (keys
// included) is cleaned of control and invisible format characters and
// passed through secret redaction before any renderer sees it.
func LoadReport(r io.Reader) (*report.Report, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxReportBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxReportBytes {
		return nil, fmt.Errorf("report is larger than %d MiB", MaxReportBytes>>20)
	}
	var doc any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("not a JSON document: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("more than one JSON value in the file")
	}
	if err := checkSchemaID(doc); err != nil {
		return nil, err
	}
	if errs := schemacheck.Validate(schema.Report, b); len(errs) > 0 {
		return nil, schemaError(errs)
	}
	clean, err := json.Marshal(redact.Value(cleanValue(doc)))
	if err != nil {
		return nil, err
	}
	var rep report.Report
	if err := json.Unmarshal(clean, &rep); err != nil {
		return nil, fmt.Errorf("not a report.v1 JSON document: %w", err)
	}
	if rep.Probe != nil {
		return nil, errors.New("this is a probe report; stackward diff compares audit reports")
	}
	return &rep, nil
}

// checkSchemaID names the common mistakes before the schema check would
// list every field: a facts file, a plan, a diff, a newer report.
func checkSchemaID(doc any) error {
	m, ok := doc.(map[string]any)
	if !ok {
		return errors.New("not a stackward report (not a JSON object)")
	}
	id, _ := m["schema"].(string)
	switch {
	case id == report.SchemaID:
		return nil
	case id == "":
		return errors.New("not a stackward report (no schema field)")
	case strings.HasPrefix(id, "stackward.facts."):
		return errors.New("this is a facts file; run stackward audit --facts FILE --json to make a report from it")
	}
	return fmt.Errorf("unsupported report schema %q (want %s)", cleanString(id), report.SchemaID)
}

// schemaError sums up schema violations. The paths come from the schema
// walk and the values from the file, so they are cleaned like the file.
func schemaError(errs []error) error {
	var parts []string
	for i, e := range errs {
		if i == maxErrors {
			parts = append(parts, fmt.Sprintf("and %d more", len(errs)-maxErrors))
			break
		}
		parts = append(parts, redact.String(cleanString(e.Error())))
	}
	return fmt.Errorf("does not match schema/report.v1.json: %s", strings.Join(parts, "; "))
}

// cleanValue returns a copy of a decoded JSON value with cleanString
// applied to every string and every object key.
func cleanValue(v any) any {
	switch t := v.(type) {
	case string:
		return cleanString(t)
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = cleanValue(e)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[cleanString(k)] = cleanValue(e)
		}
		return out
	}
	return v
}

// cleanString replaces control characters, invisible format characters
// (Unicode Cf, such as bidi overrides) and line or paragraph separators
// with U+FFFD, so a value from a report file cannot move the terminal
// cursor, recolor it or read differently from what it is.
func cleanString(s string) string {
	return strings.Map(func(c rune) rune {
		if unicode.IsControl(c) || unicode.In(c, unicode.Cf, unicode.Zl, unicode.Zp) {
			return unicode.ReplacementChar
		}
		return c
	}, s)
}
