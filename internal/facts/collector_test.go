package facts

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// stub is a configurable collector for runner tests.
type stub struct {
	name  string
	root  bool
	fn    func(ctx context.Context, out *Facts) error
	calls int
}

func (s *stub) Name() string    { return s.name }
func (s *stub) NeedsRoot() bool { return s.root }
func (s *stub) Collect(ctx context.Context, _ System, out *Facts) error {
	s.calls++
	return s.fn(ctx, out)
}

func fixedNow() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 600, time.UTC) }

func TestRunIsolatesFailures(t *testing.T) {
	sys := newFakeSystem(nil)
	block := make(chan struct{})
	defer close(block)

	cs := []Collector{
		&stub{name: "good", fn: func(_ context.Context, out *Facts) error {
			out.Kernel = &Kernel{Release: "6.8.0-1-generic"}
			return nil
		}},
		&stub{name: "partial", fn: func(_ context.Context, out *Facts) error {
			out.OS = &OS{ID: "debian"}
			return errors.New("half way")
		}},
		&stub{name: "broken", fn: func(context.Context, *Facts) error { return errors.New("boom") }},
		&stub{name: "panics", fn: func(context.Context, *Facts) error { panic("bad index") }},
		&stub{name: "hangs", fn: func(context.Context, *Facts) error { <-block; return nil }},
		&stub{name: "rootonly", root: true, fn: func(context.Context, *Facts) error {
			t.Error("root only collector ran without root")
			return nil
		}},
	}
	f := Run(context.Background(), sys, cs, RunOptions{Timeout: 50 * time.Millisecond, Now: fixedNow})

	if f.Schema != SchemaVersion {
		t.Errorf("schema = %q", f.Schema)
	}
	if !f.CollectedAt.Equal(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)) {
		t.Errorf("collected_at = %v, want truncated to seconds", f.CollectedAt)
	}
	if f.Host == nil || f.Host.Root {
		t.Errorf("host = %+v", f.Host)
	}
	if f.Kernel == nil || f.OS == nil {
		t.Fatalf("good and partial data must merge: kernel=%v os=%v", f.Kernel, f.OS)
	}

	want := map[string]Status{
		"broken": StatusFailed, "good": StatusOK, "hangs": StatusTimeout,
		"panics": StatusFailed, "partial": StatusPartial, "rootonly": StatusSkipped,
	}
	if len(f.Collectors) != len(want) {
		t.Fatalf("got %d statuses, want %d", len(f.Collectors), len(want))
	}
	for i, st := range f.Collectors {
		if i > 0 && f.Collectors[i-1].Name > st.Name {
			t.Errorf("statuses not in name order: %v", f.Collectors)
		}
		if st.Status != want[st.Name] {
			t.Errorf("%s: status %s, want %s (error %q)", st.Name, st.Status, want[st.Name], st.Error)
		}
	}
	if st, _ := f.CollectorStatus("panics"); !strings.Contains(st.Error, "bad index") {
		t.Errorf("panic text lost: %q", st.Error)
	}
	if st, _ := f.CollectorStatus("rootonly"); !strings.Contains(st.Reason, "sudo") {
		t.Errorf("skip reason should say how to get coverage: %q", st.Reason)
	}
}

func TestRunRunsRootCollectorsAsRoot(t *testing.T) {
	sys := newFakeSystem(nil)
	sys.host.EUID, sys.host.Root = 0, true
	s := &stub{name: "rootonly", root: true, fn: func(_ context.Context, out *Facts) error {
		out.Kernel = &Kernel{Release: "x"}
		return nil
	}}
	f := Run(context.Background(), sys, []Collector{s}, RunOptions{})
	if s.calls != 1 || f.Kernel == nil {
		t.Fatalf("root collector did not run as root: calls=%d", s.calls)
	}
}

func TestRunRejectsDoubleOwnership(t *testing.T) {
	sys := newFakeSystem(nil)
	set := func(_ context.Context, out *Facts) error { out.OS = &OS{ID: "debian"}; return nil }
	f := Run(context.Background(), sys, []Collector{&stub{name: "a", fn: set}, &stub{name: "b", fn: set}}, RunOptions{})
	st, _ := f.CollectorStatus("b")
	if st.Status != StatusFailed || !strings.Contains(st.Error, `already set by collector "a"`) {
		t.Fatalf("second owner of OS should fail, got %+v", st)
	}
}

func TestRegisterRejectsBadNames(t *testing.T) {
	for _, name := range []string{"", "OS", "os_x", "-x"} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("Register(%q) did not panic", name)
				}
			}()
			Register(&stub{name: name})
		}()
	}
	defer func() {
		if recover() == nil {
			t.Error("duplicate registration did not panic")
		}
	}()
	Register(&stub{name: "os"})
}
