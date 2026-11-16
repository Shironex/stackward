// Package waiver reads the waivers file (.stackward.yml): findings an
// operator accepted on purpose, each with a reason and an expiry date.
//
// A waiver never hides a finding and never changes its evidence. The report
// shows a waived finding as accepted, with its reason and expiry, and an
// expired waiver lets the finding return to its real level.
//
// The file is untrusted input read by a tool that often runs as root, so it
// is parsed by a small strict reader for the one shape it may have, a subset
// of YAML: block mappings and one block sequence, plain or quoted scalars and
// comments. Anchors, aliases, tags, flow collections, block scalars,
// multi-document streams, unknown keys and duplicate keys are all refused
// with the line they are on, and the file and each line are size capped. No
// YAML library is linked, so no YAML feature this file does not need can be
// reached through it.
package waiver

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// DefaultFile is the waivers file audit reads from the working directory
// when --waivers is not given.
const DefaultFile = ".stackward.yml"

// Limits for the untrusted file.
const (
	MaxFileBytes  = 64 << 10 // the whole file
	MaxWaivers    = 500
	maxLineBytes  = 1024
	maxSubjectLen = 256 // runes
	maxReasonLen  = 500 // runes
)

// DateLayout is the form of an expiry date.
const DateLayout = "2006-01-02"

// Levels a waiver can accept up to (the optional level key).
const (
	LevelWarn = "warn" // the default: a warning only
	LevelFail = "fail" // a warning or a fail
)

// longLivedYears is how far past the audit an expiry may lie before the
// report lists the waiver for review. Not a cap: the waiver still applies.
const longLivedYears = 1

// Waiver is one accepted finding: a check id and the exact subject of its
// result, the worst level it accepts, why it is accepted, and the last day
// the acceptance holds.
type Waiver struct {
	Check   string
	Subject string
	// Level is the worst result level the waiver accepts: LevelWarn (the
	// default) or LevelFail. A waiver for a warning never accepts a fail
	// that appears later on the same subject.
	Level  string
	Reason string
	// Expires is the last day (UTC) the waiver applies, as YYYY-MM-DD.
	Expires string
	// Line is where the waiver starts in the file, for messages.
	Line int
}

// ExpiredAt reports whether the waiver no longer applies at t: the UTC date
// of t is after Expires. A zero t (no collection time) counts as expired,
// so a report that cannot date itself shows every finding as it is.
func (w Waiver) ExpiredAt(t time.Time) bool {
	return t.IsZero() || t.UTC().Format(DateLayout) > w.Expires
}

// Covers reports whether the waiver accepts a result of level l ("warn"
// or "fail"); any other level is never accepted.
func (w Waiver) Covers(l string) bool {
	return l == LevelWarn || (l == LevelFail && w.Level == LevelFail)
}

// LongLivedAt reports whether the expiry lies more than a year after t.
func (w Waiver) LongLivedAt(t time.Time) bool {
	return !t.IsZero() && w.Expires > t.UTC().AddDate(longLivedYears, 0, 0).Format(DateLayout)
}

// Load reads and parses a waivers file of at most MaxFileBytes.
func Load(r io.Reader) ([]Waiver, error) {
	b, err := io.ReadAll(io.LimitReader(r, MaxFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > MaxFileBytes {
		return nil, fmt.Errorf("waivers file is larger than %d KiB", MaxFileBytes>>10)
	}
	return Parse(b)
}

var checkID = regexp.MustCompile(`^[A-Z]{2,4}-[0-9]{3}$`)

// requiredKeys are the keys every waiver needs; level is optional.
var requiredKeys = []string{"check", "subject", "reason", "expires"}

// waiverKeys are all keys a waiver may have.
var waiverKeys = append([]string{"level"}, requiredKeys...)

// Parse parses the waivers file. The shape is:
//
//	version: 1
//	waivers:
//	  - check: NET-004
//	    subject: port:tcp/443
//	    reason: public web server by design
//	    expires: 2027-01-31
//	    level: warn # optional: warn (default) or fail
//
// Every waiver needs check, subject, reason and expires; two waivers for
// the same check and subject are refused. Errors name the line and the
// key, never the value, so a value cannot be echoed to a terminal or log.
func Parse(b []byte) ([]Waiver, error) {
	lines, err := splitLines(b)
	if err != nil {
		return nil, err
	}
	p := &parser{lines: lines}
	if err := p.parse(); err != nil {
		return nil, err
	}
	return p.out, nil
}

// line is one meaningful line of the file: its number, its indent and the
// text after the indent, comments not yet stripped.
type line struct {
	n      int
	indent int
	text   string
}

// splitLines checks the bytes (UTF-8, no control characters, line length)
// and returns the lines that are not blank or comment only.
func splitLines(b []byte) ([]line, error) {
	b = []byte(strings.TrimPrefix(string(b), "\uFEFF"))
	if !utf8.Valid(b) {
		return nil, errors.New("waivers file is not valid UTF-8")
	}
	var out []line
	for i, raw := range strings.Split(string(b), "\n") {
		n := i + 1
		raw = strings.TrimSuffix(raw, "\r")
		if len(raw) > maxLineBytes {
			return nil, fmt.Errorf("line %d: longer than %d bytes", n, maxLineBytes)
		}
		for _, c := range raw {
			if c == '\t' {
				return nil, fmt.Errorf("line %d: tab character; indent with spaces", n)
			}
			if unicode.IsControl(c) {
				return nil, fmt.Errorf("line %d: control character %U", n, c)
			}
			// Format characters (bidi overrides, zero width joiners) and
			// line or paragraph separators can make text read differently
			// from what it is.
			if unicode.In(c, unicode.Cf, unicode.Zl, unicode.Zp) {
				return nil, fmt.Errorf("line %d: invisible format or separator character %U", n, c)
			}
		}
		text := strings.TrimLeft(raw, " ")
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		out = append(out, line{n: n, indent: len(raw) - len(text), text: strings.TrimRight(text, " ")})
	}
	return out, nil
}

type parser struct {
	lines   []line
	i       int
	out     []Waiver
	version bool
	list    bool
}

func (p *parser) parse() error {
	if len(p.lines) > 0 && p.lines[0].indent == 0 && p.lines[0].text == "---" {
		p.i++
	}
	for p.i < len(p.lines) {
		l := p.lines[p.i]
		if l.indent != 0 {
			return fmt.Errorf("line %d: unexpected indent", l.n)
		}
		if err := p.topKey(l); err != nil {
			return err
		}
	}
	switch {
	case !p.version:
		return errors.New("missing \"version: 1\"")
	case !p.list:
		return errors.New("missing \"waivers:\"")
	}
	return nil
}

// topKey handles one top level line: version or waivers.
func (p *parser) topKey(l line) error {
	key, rest, err := splitKey(l)
	if err != nil {
		return err
	}
	p.i++
	switch key {
	case "version":
		if p.version {
			return fmt.Errorf("line %d: duplicate key %q", l.n, key)
		}
		p.version = true
		v, err := scalar(l.n, rest)
		if err != nil {
			return err
		}
		if v != "1" {
			return fmt.Errorf("line %d: unsupported version (want 1)", l.n)
		}
		return nil
	case "waivers":
		if p.list {
			return fmt.Errorf("line %d: duplicate key %q", l.n, key)
		}
		p.list = true
		switch strings.TrimSpace(stripComment(rest)) {
		case "":
			return p.items()
		case "[]":
			return nil
		}
		return fmt.Errorf("line %d: waivers must be a list of entries starting with \"- \"", l.n)
	}
	return fmt.Errorf("unknown key on line %d (want version or waivers)", l.n)
}

// items reads the block sequence under "waivers:".
func (p *parser) items() error {
	itemIndent := -1
	seen := map[[2]string]int{}
	for p.i < len(p.lines) {
		l := p.lines[p.i]
		isItem := l.text == "-" || strings.HasPrefix(l.text, "- ")
		if l.indent == 0 && !isItem {
			return nil // the next top level key
		}
		if !isItem {
			return fmt.Errorf("line %d: expected a list entry starting with \"- \"", l.n)
		}
		if itemIndent < 0 {
			itemIndent = l.indent
		}
		if l.indent != itemIndent {
			return fmt.Errorf("line %d: list entries must line up (indent %d, not %d)", l.n, itemIndent, l.indent)
		}
		if len(p.out) == MaxWaivers {
			return fmt.Errorf("line %d: more than %d waivers", l.n, MaxWaivers)
		}
		w, err := p.item()
		if err != nil {
			return err
		}
		k := [2]string{w.Check, w.Subject}
		if prev, dup := seen[k]; dup {
			return fmt.Errorf("line %d: a second waiver for the same check and subject as line %d", w.Line, prev)
		}
		seen[k] = w.Line
		p.out = append(p.out, w)
	}
	return nil
}

// item reads one waiver: the "- key: value" line and the key lines under
// it, which must start in the same column as its first key.
func (p *parser) item() (Waiver, error) {
	first := p.lines[p.i]
	after := strings.TrimPrefix(first.text, "-")
	body := strings.TrimLeft(after, " ")
	if body == "" {
		return Waiver{}, fmt.Errorf("line %d: put the first key on the line of its \"- \"", first.n)
	}
	col := first.indent + 1 + (len(after) - len(body))
	fields := map[string]string{}
	cur := line{n: first.n, indent: col, text: body}
	for {
		if err := field(cur, fields); err != nil {
			return Waiver{}, err
		}
		p.i++
		if p.i >= len(p.lines) || p.lines[p.i].indent != col || strings.HasPrefix(p.lines[p.i].text, "- ") {
			break
		}
		cur = p.lines[p.i]
	}
	if p.i < len(p.lines) {
		if l := p.lines[p.i]; l.indent > first.indent && l.indent != col {
			return Waiver{}, fmt.Errorf("line %d: keys of a waiver must line up under its first key", l.n)
		}
	}
	return build(first.n, fields)
}

// field parses one "key: value" of a waiver into fields.
func field(l line, fields map[string]string) error {
	key, rest, err := splitKey(l)
	if err != nil {
		return err
	}
	if !slices.Contains(waiverKeys, key) {
		return fmt.Errorf("unknown key on line %d (a waiver has check, subject, reason, expires and level)", l.n)
	}
	if _, dup := fields[key]; dup {
		return fmt.Errorf("line %d: duplicate key %q", l.n, key)
	}
	v, err := scalar(l.n, rest)
	if err != nil {
		return err
	}
	fields[key] = v
	return nil
}

// build checks the fields of one waiver.
func build(n int, f map[string]string) (Waiver, error) {
	for _, k := range requiredKeys {
		if _, ok := f[k]; !ok {
			return Waiver{}, fmt.Errorf("line %d: waiver has no %q; every waiver needs check, subject, reason and expires", n, k)
		}
	}
	w := Waiver{Check: f["check"], Subject: f["subject"], Level: LevelWarn, Reason: strings.TrimSpace(f["reason"]), Expires: f["expires"], Line: n}
	if l, ok := f["level"]; ok {
		w.Level = l
	}
	switch {
	case !checkID.MatchString(w.Check):
		return w, fmt.Errorf("line %d: check is not a check id like NET-004", n)
	case w.Level != LevelWarn && w.Level != LevelFail:
		return w, fmt.Errorf("line %d: level must be warn or fail", n)
	case w.Subject == "" || strings.TrimSpace(w.Subject) != w.Subject:
		return w, fmt.Errorf("line %d: subject must be the exact subject of a result, such as host or port:tcp/443", n)
	case utf8.RuneCountInString(w.Subject) > maxSubjectLen:
		return w, fmt.Errorf("line %d: subject is longer than %d characters", n, maxSubjectLen)
	case w.Reason == "":
		return w, fmt.Errorf("line %d: reason is empty; say why the finding is accepted", n)
	case utf8.RuneCountInString(w.Reason) > maxReasonLen:
		return w, fmt.Errorf("line %d: reason is longer than %d characters", n, maxReasonLen)
	}
	if _, err := time.Parse(DateLayout, w.Expires); err != nil {
		return w, fmt.Errorf("line %d: expires is not a date like 2027-01-31", n)
	}
	return w, nil
}

var keyPattern = regexp.MustCompile(`^[a-z]+$`)

// splitKey splits "key: rest" (or "key:" alone).
func splitKey(l line) (key, rest string, err error) {
	key, rest, ok := strings.Cut(l.text, ":")
	if !ok || !keyPattern.MatchString(key) {
		return "", "", fmt.Errorf("line %d: expected \"key: value\"", l.n)
	}
	if rest != "" && rest[0] != ' ' {
		return "", "", fmt.Errorf("line %d: put a space after the colon", l.n)
	}
	return key, rest, nil
}

// stripComment removes a " #" comment from a plain value.
func stripComment(s string) string {
	if i := strings.Index(s, " #"); i >= 0 {
		return s[:i]
	}
	return s
}

// plainStart are characters YAML gives a meaning at the start of a plain
// scalar (anchors, aliases, tags, flow collections, block scalars,
// directives, reserved); a value starting with one must be quoted.
const plainStart = "&*!|>%@`{}[],?#"

// scalar parses the value after "key:": a plain, single quoted or double
// quoted scalar on one line, with an optional trailing comment.
func scalar(n int, rest string) (string, error) {
	s := strings.TrimLeft(rest, " ")
	if s == "" {
		return "", fmt.Errorf("line %d: value is missing", n)
	}
	switch s[0] {
	case '"':
		return quoted(n, s, '"')
	case '\'':
		return quoted(n, s, '\'')
	}
	v := strings.TrimRight(stripComment(s), " ")
	switch {
	case strings.ContainsRune(plainStart, rune(v[0])):
		return "", fmt.Errorf("line %d: a value starting with %q must be quoted; anchors, aliases, tags and flow or block collections are not allowed", n, v[0])
	case v == "-" || strings.HasPrefix(v, "- "):
		return "", fmt.Errorf("line %d: a nested list is not allowed here", n)
	case strings.Contains(v, ": ") || strings.HasSuffix(v, ":"):
		return "", fmt.Errorf("line %d: a nested mapping is not allowed here; quote a value that contains \": \"", n)
	}
	return v, nil
}

// quoted parses a quoted scalar. In double quotes only \" and \\ are
// escapes; in single quotes ” is a quote. Only a comment may follow.
func quoted(n int, s string, q byte) (string, error) {
	var b strings.Builder
	i := 1
	for ; i < len(s); i++ {
		c := s[i]
		switch {
		case q == '"' && c == '\\':
			if i+1 >= len(s) || (s[i+1] != '"' && s[i+1] != '\\') {
				return "", fmt.Errorf("line %d: only \\\" and \\\\ escapes are allowed in double quotes", n)
			}
			i++
			b.WriteByte(s[i])
			continue
		case q == '\'' && c == '\'' && i+1 < len(s) && s[i+1] == '\'':
			i++
			b.WriteByte('\'')
			continue
		case c == q:
			tail := strings.TrimLeft(s[i+1:], " ")
			if tail != "" && (!strings.HasPrefix(tail, "#") || len(tail) == len(s[i+1:])) {
				return "", fmt.Errorf("line %d: unexpected text after the closing quote", n)
			}
			return b.String(), nil
		}
		b.WriteByte(c)
	}
	return "", fmt.Errorf("line %d: unterminated quoted value (multi-line values are not allowed)", n)
}
