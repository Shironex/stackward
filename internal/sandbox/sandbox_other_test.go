//go:build !linux

package sandbox

import "testing"

func TestUnavailableOffLinux(t *testing.T) {
	if st := Apply(Options{}); st.State != Unavailable || st.Reason == "" {
		t.Fatalf("%+v", st)
	}
	if st := Apply(Options{Disabled: true}); st.State != Disabled {
		t.Fatalf("%+v", st)
	}
}
