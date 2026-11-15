package probe

import (
	"bytes"
	"strings"
	"testing"
)

func TestConfirm(t *testing.T) {
	cases := []struct {
		name        string
		owned, tty  bool
		input       string
		ok          bool
		wantPrinted string
	}{
		{"flag", true, false, "", true, LegalNotice},
		{"flag on a tty does not ask", true, true, "", true, LegalNotice},
		{"no tty, no flag", false, false, "y\n", false, LegalNotice},
		{"tty yes", false, true, "y\n", true, "[y/N]"},
		{"tty YES", false, true, " YES \n", true, "[y/N]"},
		{"tty no", false, true, "n\n", false, "[y/N]"},
		{"tty empty", false, true, "\n", false, "[y/N]"},
		{"tty eof", false, true, "", false, "[y/N]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			err := Confirm("192.0.2.10", tc.owned, tc.tty, strings.NewReader(tc.input), &out)
			if (err == nil) != tc.ok {
				t.Fatalf("err = %v, want ok=%v", err, tc.ok)
			}
			if !strings.Contains(out.String(), "may be illegal") || !strings.Contains(out.String(), tc.wantPrinted) {
				t.Errorf("printed %q", out.String())
			}
			if tc.owned && strings.Contains(out.String(), "[y/N]") {
				t.Error("asked although --i-own-this was given")
			}
			if tc.name == "tty eof" && (err == nil || !strings.Contains(err.Error(), "--i-own-this")) {
				t.Errorf("an empty stdin must point at --i-own-this: %v", err)
			}
			if !tc.owned && !tc.tty && (err == nil || !strings.Contains(err.Error(), "--i-own-this")) {
				t.Errorf("non interactive refusal must name --i-own-this: %v", err)
			}
		})
	}
}
