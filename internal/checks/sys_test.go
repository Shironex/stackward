package checks

import (
	"testing"
	"time"

	"github.com/Shironex/stackward/internal/facts"
)

var now = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

func ubuntu(v string) *facts.OS {
	return &facts.OS{ID: "ubuntu", IDLike: []string{"debian"}, VersionID: v}
}

func level(t *testing.T, rs []Result) Level {
	t.Helper()
	if len(rs) != 1 {
		t.Fatalf("want one result, got %v", rs)
	}
	return rs[0].Level
}

func TestSYS001(t *testing.T) {
	cases := []struct {
		os   *facts.OS
		want Level
	}{
		{nil, Unknown},
		{ubuntu("24.04"), Pass},
		{&facts.OS{ID: "debian", VersionID: "12"}, Pass},
		{ubuntu("20.04"), Warn},
		{&facts.OS{ID: "debian"}, Warn}, // testing or sid
		{&facts.OS{ID: "linuxmint", IDLike: []string{"ubuntu"}, VersionID: "22"}, Warn},
		{&facts.OS{ID: "rocky", IDLike: []string{"rhel", "centos", "fedora"}, VersionID: "9.4"}, Skip},
	}
	for _, tc := range cases {
		got := level(t, checkTestedDistro(Input{Facts: &facts.Facts{OS: tc.os}}))
		if got != tc.want {
			t.Errorf("%+v: got %s, want %s", tc.os, got, tc.want)
		}
	}
}

func TestSYS002(t *testing.T) {
	cases := []struct {
		name   string
		os     *facts.OS
		reboot *facts.Reboot
		want   Level
	}{
		{"not inspected", ubuntu("24.04"), nil, Unknown},
		{"other family", &facts.OS{ID: "rocky"}, &facts.Reboot{}, Unknown},
		{"os unknown", nil, &facts.Reboot{}, Unknown},
		{"none pending", ubuntu("24.04"), &facts.Reboot{}, Pass},
		{"recent", ubuntu("24.04"), &facts.Reboot{Required: true, Since: now.Add(-48 * time.Hour)}, Warn},
		{"overdue", ubuntu("24.04"), &facts.Reboot{Required: true, Since: now.Add(-15 * 24 * time.Hour)}, Fail},
		{"age unknown", ubuntu("24.04"), &facts.Reboot{Required: true}, Warn},
	}
	for _, tc := range cases {
		f := &facts.Facts{CollectedAt: now, OS: tc.os, Reboot: tc.reboot}
		if got := level(t, checkRebootPending(Input{Facts: f})); got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.name, got, tc.want)
		}
	}
}

func TestSYS003(t *testing.T) {
	cases := []struct {
		name string
		k    *facts.Kernel
		want Level
	}{
		{"not inspected", nil, Unknown},
		{"no /boot", &facts.Kernel{Release: "6.8.0-45-generic"}, Unknown},
		{"newest", &facts.Kernel{Release: "6.8.0-49-generic", Installed: []string{"6.8.0-45-generic", "6.8.0-49-generic"}}, Pass},
		{"older", &facts.Kernel{Release: "6.8.0-9-generic", Installed: []string{"6.8.0-10-generic", "6.8.0-9-generic"}}, Warn},
		{"custom newer", &facts.Kernel{Release: "6.12.1-custom", Installed: []string{"6.8.0-45-generic"}}, Pass},
	}
	for _, tc := range cases {
		if got := level(t, checkRunningKernel(Input{Facts: &facts.Facts{Kernel: tc.k}})); got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.name, got, tc.want)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"6.8.0-45-generic", "6.8.0-49-generic", -1},
		{"6.8.0-100-generic", "6.8.0-99-generic", 1},
		{"6.1.0-27-amd64", "6.1.0-27-amd64", 0},
		{"6.10.0", "6.9.0", 1},
		{"6.8", "6.8.0", -1},
	}
	for _, tc := range cases {
		if got := compareVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("compare(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}
