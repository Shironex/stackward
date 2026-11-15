package profile

import "testing"

func TestParse(t *testing.T) {
	for _, s := range []string{"", "auto"} {
		if n, set, err := Parse(s); n != Unknown || set || err != nil {
			t.Errorf("Parse(%q) = %v %v %v", s, n, set, err)
		}
	}
	for _, n := range All {
		if got, set, err := Parse(string(n)); got != n || !set || err != nil {
			t.Errorf("Parse(%q) = %v %v %v", n, got, set, err)
		}
	}
	if _, _, err := Parse("moat"); err == nil {
		t.Error("unknown profile accepted")
	}
}
