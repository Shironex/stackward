package waiver

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

const good = `# accepted findings
version: 1
waivers:
  - check: NET-004
    subject: port:tcp/443
    reason: public web server by design # trailing comment
    expires: 2027-01-31
  -   check: "USR-002"
      subject: 'user:deploy'
      reason: "known sudoer: \"deploy\" runs the CI"
      expires: 2026-12-01
`

func TestParseGood(t *testing.T) {
	ws, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	want := []Waiver{
		{Check: "NET-004", Subject: "port:tcp/443", Reason: "public web server by design", Expires: "2027-01-31", Line: 4},
		{Check: "USR-002", Subject: "user:deploy", Reason: `known sudoer: "deploy" runs the CI`, Expires: "2026-12-01", Line: 8},
	}
	if len(ws) != len(want) {
		t.Fatalf("got %d waivers, want %d: %+v", len(ws), len(want), ws)
	}
	for i := range want {
		if ws[i] != want[i] {
			t.Errorf("waiver %d = %+v, want %+v", i, ws[i], want[i])
		}
	}
}

func TestParseShapes(t *testing.T) {
	for name, src := range map[string]string{
		"empty list":       "version: 1\nwaivers: []\n",
		"empty block":      "waivers:\nversion: 1\n",
		"document marker":  "---\nversion: 1\nwaivers: []\n",
		"zero indent list": "version: 1\nwaivers:\n- check: NET-004\n  subject: host\n  reason: ok\n  expires: 2027-01-01\n",
		"crlf and bom":     "\uFEFFversion: 1\r\nwaivers: []\r\n",
		"single quote esc": "version: 1\nwaivers:\n  - check: NET-004\n    subject: host\n    reason: 'it''s fine'\n    expires: 2027-01-01\n",
		"list then key":    "waivers:\n  - check: NET-004\n    subject: host\n    reason: ok\n    expires: 2027-01-01\nversion: 1\n",
	} {
		if _, err := Parse([]byte(src)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestParseRefuses(t *testing.T) {
	entry := func(lines ...string) string {
		return "version: 1\nwaivers:\n  - " + strings.Join(lines, "\n    ") + "\n"
	}
	full := []string{"check: NET-004", "subject: host", "reason: ok", "expires: 2027-01-01"}
	with := func(i int, s string) string {
		l := append([]string{}, full...)
		l[i] = s
		return entry(l...)
	}
	cases := map[string]struct{ src, want string }{
		"no version":        {"waivers: []\n", "missing \"version: 1\""},
		"no waivers":        {"version: 1\n", "missing \"waivers:\""},
		"bad version":       {"version: 2\nwaivers: []\n", "unsupported version"},
		"unknown top key":   {"version: 1\nwaivers: []\nextra: x\n", "unknown key \"extra\""},
		"duplicate top key": {"version: 1\nversion: 1\nwaivers: []\n", "duplicate key"},
		"missing reason":    {entry(full[0], full[1], full[3]), "no \"reason\""},
		"missing expires":   {entry(full[0], full[1], full[2]), "no \"expires\""},
		"missing subject":   {entry(full[0], full[2], full[3]), "no \"subject\""},
		"missing check":     {entry(full[1], full[2], full[3]), "no \"check\""},
		"unknown key":       {entry(append(full, "owner: me")...), "unknown key \"owner\""},
		"duplicate key":     {entry(append(full, "reason: again")...), "duplicate key \"reason\""},
		"bad check id":      {with(0, "check: net-4"), "not a check id"},
		"empty reason":      {with(2, "reason: \"  \""), "reason is empty"},
		"bad date":          {with(3, "expires: 2027-13-01"), "not a date"},
		"datetime":          {with(3, "expires: 2027-01-01T00:00:00Z"), "not a date"},
		"anchor":            {with(2, "reason: &a ok"), "must be quoted"},
		"alias":             {with(2, "reason: *a"), "must be quoted"},
		"tag":               {with(2, "reason: !!str ok"), "must be quoted"},
		"flow map":          {with(2, "reason: {a: b}"), "must be quoted"},
		"flow seq":          {with(2, "reason: [a]"), "must be quoted"},
		"block scalar":      {with(2, "reason: |"), "must be quoted"},
		"merge key":         {entry(append(full, "<<: *base")...), "expected \"key: value\""},
		"nested map":        {with(2, "reason: a: b"), "nested mapping"},
		"bad escape":        {with(2, `reason: "a\nb"`), "escapes"},
		"unterminated":      {with(2, `reason: "abc`), "unterminated"},
		"text after quote":  {with(2, `reason: "a" b`), "after the closing quote"},
		"tab":               {"version: 1\nwaivers:\n\t- check: NET-004\n", "tab character"},
		"control char":      {"version: 1\x07\nwaivers: []\n", "control character"},
		"bad utf8":          {"version: 1\nwaivers: []\n# \xff\n", "UTF-8"},
		"misaligned key":    {"version: 1\nwaivers:\n  - check: NET-004\n      subject: host\n", "line up"},
		"misaligned item":   {"version: 1\nwaivers:\n  - check: NET-004\n    subject: host\n    reason: ok\n    expires: 2027-01-01\n    - check: NET-005\n", "line 7"},
		"inline list":       {"version: 1\nwaivers: x\n", "must be a list"},
		"dash alone":        {"version: 1\nwaivers:\n  -\n    check: NET-004\n", "first key"},
		"second document":   {"version: 1\nwaivers: []\n---\n", "expected \"key: value\""},
		"indented top":      {" version: 1\nwaivers: []\n", "unexpected indent"},
		"duplicate waiver": {"version: 1\nwaivers:\n" +
			"  - check: NET-004\n    subject: host\n    reason: a\n    expires: 2027-01-01\n" +
			"  - check: NET-004\n    subject: host\n    reason: b\n    expires: 2027-01-01\n", "second waiver for NET-004 on host (the first is on line 3)"},
		"long line": {"version: 1\nwaivers: []\n# " + strings.Repeat("x", maxLineBytes) + "\n", "longer than"},
		"no space":  {"version:1\nwaivers: []\n", "space after"},
	}
	for name, c := range cases {
		_, err := Parse([]byte(c.src))
		if err == nil {
			t.Errorf("%s: parsed, want an error with %q", name, c.want)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q, want it to contain %q", name, err, c.want)
		}
	}
}

func TestLoadCaps(t *testing.T) {
	big := "version: 1\nwaivers: []\n" + strings.Repeat("# padding padding padding\n", MaxFileBytes/20)
	if _, err := Load(strings.NewReader(big)); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("oversized file: err = %v", err)
	}
	var b strings.Builder
	b.WriteString("version: 1\nwaivers:\n")
	for i := 0; i <= MaxWaivers; i++ {
		b.WriteString("- check: NET-004\n  subject: s" + strings.Repeat("x", i%7) + strconv.Itoa(i) + "\n  reason: r\n  expires: 2027-01-01\n")
	}
	if b.Len() <= MaxFileBytes {
		if _, err := Load(strings.NewReader(b.String())); err == nil || !strings.Contains(err.Error(), "more than") {
			t.Errorf("too many waivers: err = %v", err)
		}
	}
}

func TestExpiredAt(t *testing.T) {
	w := Waiver{Expires: "2027-01-31"}
	day := func(s string) time.Time {
		tm, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return tm
	}
	for at, want := range map[string]bool{
		"2027-01-30T12:00:00Z":      false,
		"2027-01-31T23:59:59Z":      false, // the last day still holds
		"2027-02-01T00:00:00Z":      true,
		"2027-02-01T00:30:00+01:00": false, // still Jan 31 in UTC
	} {
		if got := w.ExpiredAt(day(at)); got != want {
			t.Errorf("ExpiredAt(%s) = %v, want %v", at, got, want)
		}
	}
	if !w.ExpiredAt(time.Time{}) {
		t.Error("a zero time must count as expired")
	}
}
