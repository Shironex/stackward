package checks

import "testing"

func TestDaysAgo(t *testing.T) {
	for days, want := range map[int]string{0: "since today", 1: "for 1 day", 2: "for 2 days", 20: "for 20 days"} {
		if got := daysAgo(days); got != want {
			t.Errorf("daysAgo(%d) = %q, want %q", days, got, want)
		}
	}
}
