package facts

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Collector gathers one slice of Facts.
//
// Collect writes into out, which is a fresh, empty Facts value private to
// this call, and only into the fields this collector owns (each domain field
// of Facts has exactly one owner). It may return data and an error together:
// whatever it wrote is kept and the run is marked partial. It must honour
// ctx (pass it to System.Run) and must never write to the host.
type Collector interface {
	// Name is a stable lower case id ("os", "ssh", "docker").
	Name() string
	// NeedsRoot makes the runner skip the collector when not root. A
	// collector that degrades without root returns false and checks
	// System.Identity itself, recording what it could not see.
	NeedsRoot() bool
	Collect(ctx context.Context, sys System, out *Facts) error
}

var (
	registryMu sync.Mutex
	registry   = map[string]Collector{}
	nameRE     = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
)

// Register adds a collector. Call it from an init function in the file that
// defines the collector. It panics on a bad or duplicate name, which a test
// run catches immediately.
func Register(c Collector) {
	registryMu.Lock()
	defer registryMu.Unlock()
	name := c.Name()
	if !nameRE.MatchString(name) {
		panic(fmt.Sprintf("facts: invalid collector name %q", name))
	}
	if _, dup := registry[name]; dup {
		panic(fmt.Sprintf("facts: collector %q registered twice", name))
	}
	registry[name] = c
}

// Collectors returns every registered collector in name order.
func Collectors() []Collector {
	registryMu.Lock()
	defer registryMu.Unlock()
	out := make([]Collector, 0, len(registry))
	for _, c := range registry {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// RunOptions tunes Run.
type RunOptions struct {
	// Timeout bounds each collector. Zero means DefaultTimeout.
	Timeout time.Duration
	// Now overrides the clock (tests). Zero means time.Now.
	Now func() time.Time
}

// DefaultTimeout bounds one collector when RunOptions.Timeout is zero.
const DefaultTimeout = 15 * time.Second

// grace is how long Run waits after a timeout for a collector that honours
// ctx to hand back what it gathered so far.
const grace = 250 * time.Millisecond

// Run executes collectors concurrently and merges their output. One failing,
// panicking or hanging collector never stops the others; its status says
// what happened and its domain stays nil, so checks report unknown.
func Run(ctx context.Context, sys System, collectors []Collector, opts RunOptions) *Facts {
	now := time.Now
	if opts.Now != nil {
		now = opts.Now
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	host := sys.Identity()
	f := &Facts{
		Schema:      SchemaVersion,
		CollectedAt: now().UTC().Truncate(time.Second),
		Host:        &host,
	}

	type outcome struct {
		status CollectorStatus
		data   *Facts
	}
	outcomes := make([]outcome, len(collectors))
	var wg sync.WaitGroup
	for i, c := range collectors {
		if c.NeedsRoot() && !host.Root {
			outcomes[i] = outcome{status: CollectorStatus{
				Name: c.Name(), Status: StatusSkipped,
				Reason: "needs root; run with sudo for full coverage",
			}}
			continue
		}
		wg.Add(1)
		go func(i int, c Collector) {
			defer wg.Done()
			st, data := runOne(ctx, sys, c, timeout)
			outcomes[i] = outcome{status: st, data: data}
		}(i, c)
	}
	wg.Wait()

	owner := map[string]string{}
	for _, o := range outcomes {
		st := o.status
		if o.data != nil {
			if err := merge(f, o.data, st.Name, owner); err != nil {
				st.Status = StatusFailed
				st.Error = joinText(st.Error, err.Error())
			}
		}
		f.Collectors = append(f.Collectors, st)
	}
	sort.Slice(f.Collectors, func(i, j int) bool { return f.Collectors[i].Name < f.Collectors[j].Name })
	return f
}

func runOne(parent context.Context, sys System, c Collector, timeout time.Duration) (CollectorStatus, *Facts) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	st := CollectorStatus{Name: c.Name()}
	type done struct {
		data *Facts
		err  error
	}
	ch := make(chan done, 1)
	go func() {
		out := &Facts{}
		var err error
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("collector panicked: %v", r)
				out = nil
			}
			ch <- done{out, err}
		}()
		err = c.Collect(ctx, sys, out)
	}()

	var d done
	select {
	case d = <-ch:
	case <-ctx.Done():
		select {
		case d = <-ch:
		case <-time.After(grace):
			// The goroutine may still write to its private Facts; we
			// never read that value, so dropping it is safe.
			st.Status = StatusTimeout
			st.Error = fmt.Sprintf("did not finish within %s", timeout)
			return st, nil
		}
	}

	hasData := d.data != nil && hasDomainData(d.data)
	switch {
	case d.err == nil:
		// With no data this means the collector ran fine and had
		// nothing to record; it should prefer recording "not
		// installed" explicitly in its domain over leaving it nil.
		st.Status = StatusOK
	case hasData:
		st.Status = StatusPartial
		st.Error = oneLine(d.err.Error())
	default:
		st.Status = StatusFailed
		st.Error = oneLine(d.err.Error())
		if errors.Is(d.err, context.DeadlineExceeded) {
			st.Status = StatusTimeout
		}
		return st, nil
	}
	return st, d.data
}

// mergeSkip lists Facts fields the runner owns.
var mergeSkip = map[string]bool{"Schema": true, "CollectedAt": true, "Host": true, "Collectors": true}

// hasDomainData reports whether a collector set any domain field.
func hasDomainData(f *Facts) bool {
	v := reflect.ValueOf(f).Elem()
	t := v.Type()
	for i := range t.NumField() {
		if mergeSkip[t.Field(i).Name] {
			continue
		}
		if !v.Field(i).IsZero() {
			return true
		}
	}
	return false
}

// merge copies every domain field src set into dst. Two collectors setting
// the same field is a programming error, reported instead of silently won.
func merge(dst, src *Facts, name string, owner map[string]string) error {
	dv, sv := reflect.ValueOf(dst).Elem(), reflect.ValueOf(src).Elem()
	t := dv.Type()
	var errs []error
	for i := range t.NumField() {
		field := t.Field(i).Name
		if mergeSkip[field] || sv.Field(i).IsZero() {
			continue
		}
		if prev, taken := owner[field]; taken {
			errs = append(errs, fmt.Errorf("field %s already set by collector %q", field, prev))
			continue
		}
		owner[field] = name
		dv.Field(i).Set(sv.Field(i))
	}
	return errors.Join(errs...)
}

// oneLine flattens multi line errors (errors.Join uses newlines) so every
// status prints on one line.
func oneLine(s string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(s, "\n", " ; ")), " ")
}

func joinText(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return a + "; " + b
}
