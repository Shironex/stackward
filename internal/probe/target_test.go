package probe

import (
	"strings"
	"testing"
)

func TestParseTargetAccepts(t *testing.T) {
	cases := map[string]string{
		"192.0.2.10":         "192.0.2.10",
		"198.51.100.7\n":     "198.51.100.7",
		"2001:db8::10":       "2001:db8::10",
		"[2001:db8::10]":     "2001:db8::10",
		"::ffff:203.0.113.5": "203.0.113.5",
		"App.Example.com.":   "app.example.com",
		"example.com":        "example.com",
	}
	for in, want := range cases {
		got, err := ParseTarget(in)
		if err != nil || got != want {
			t.Errorf("ParseTarget(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestParseTargetRefusesRangesAndLists(t *testing.T) {
	cases := map[string]string{
		"192.0.2.0/24":              "range",
		"2001:db8::/32":             "range",
		"198.51.100.1-20":           "range",
		"198.51.100.1-198.51.100.9": "range",
		"192.0.2.1,192.0.2.2":       "list",
		"*.example.com":             "list",
		"https://example.com/":      "URL",
		"example.com:22":            "--ports",
		"":                          "give one host",
		"0.0.0.0":                   "not a single host",
		"ff02::1":                   "not a single host",
		"fe80::1%eth0":              "zone",
		"-bad-.example.com":         "not a valid host name",
	}
	for in, want := range cases {
		_, err := ParseTarget(in)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ParseTarget(%q) err = %v, want it to mention %q", in, err, want)
		}
	}
}

func TestParseHostname(t *testing.T) {
	for in, want := range map[string]string{
		"":                     "",
		"App.Example.com":      "app.example.com",
		"app.example.com:8443": "app.example.com:8443",
		"127.0.0.1:8443":       "127.0.0.1:8443",
	} {
		got, err := ParseHostname(in)
		if err != nil || got != want {
			t.Errorf("ParseHostname(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"https://app.example.com", "app.example.com/login", "app.example.com:0", "bad_host!"} {
		if _, err := ParseHostname(in); err == nil {
			t.Errorf("ParseHostname(%q) accepted", in)
		}
	}
}

func TestParsePorts(t *testing.T) {
	got, err := ParsePorts(" 2222, 22,2222 ")
	if err != nil || len(got) != 2 || got[0] != 22 || got[1] != 2222 {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, in := range []string{"1-1024", "0", "65536", "ssh"} {
		if _, err := ParsePorts(in); err == nil {
			t.Errorf("ParsePorts(%q) accepted", in)
		}
	}
	if _, err := ParsePorts("1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17"); err == nil {
		t.Error("more than 16 extra ports accepted")
	}
}
