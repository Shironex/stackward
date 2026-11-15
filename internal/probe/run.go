package probe

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Shironex/stackward/internal/facts"
)

// Defaults for Options.
const (
	DefaultTimeout     = 3 * time.Second
	DefaultConcurrency = 16
	// maxPerFamily bounds how many addresses of one family are probed when
	// a name resolves to many (round robin DNS).
	maxPerFamily = 4
	// bannerMax caps the bytes read for a banner; only the first line is
	// kept, reduced to printable ASCII.
	bannerMax     = 256
	bannerLineMax = 200
)

// Resolver looks up the addresses of a name. *net.Resolver implements it.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Options configures one probe run.
type Options struct {
	// Target comes from ParseTarget, Hostname from ParseHostname.
	Target   string
	Hostname string
	// Ports replaces the whole port list (tests). Zero means DefaultPorts
	// plus Extra.
	Ports *PortList
	// Extra are the --ports.
	Extra []int
	// Timeout bounds each TCP connect and banner read; an HTTP request gets
	// three times as long. Zero means DefaultTimeout.
	Timeout time.Duration
	// Concurrency bounds parallel connects. Zero means DefaultConcurrency.
	Concurrency int
	// UserAgent is sent with every HTTP request.
	UserAgent string
	// Resolver defaults to net.DefaultResolver.
	Resolver Resolver
	// RootCAs replaces the system roots for the --hostname check (tests).
	RootCAs *x509.CertPool
	// Now defaults to time.Now.
	Now func() time.Time
	// LocalAddrs lists this machine's own addresses and defaults to
	// InterfaceAddrs.
	LocalAddrs LocalAddrs
	// OnSelfTarget, when set, is called with the matching addresses after
	// the target resolved and before anything is probed, when the target is
	// this machine.
	OnSelfTarget func(addrs []string)
}

func (o *Options) defaults() {
	if o.Timeout <= 0 {
		o.Timeout = DefaultTimeout
	}
	if o.Concurrency <= 0 {
		o.Concurrency = DefaultConcurrency
	}
	if o.Resolver == nil {
		o.Resolver = net.DefaultResolver
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.LocalAddrs == nil {
		o.LocalAddrs = InterfaceAddrs
	}
	if o.UserAgent == "" {
		o.UserAgent = "stackward-probe"
	}
}

// Run probes the target and returns what it saw. It never returns nil;
// failures are recorded in Facts (Steps, ResolveError, per port states).
func Run(ctx context.Context, o Options) *Facts {
	o.defaults()
	pl := DefaultPorts()
	if o.Ports != nil {
		pl = *o.Ports
	}
	if len(o.Extra) > 0 {
		pl.Extra = append([]int{}, o.Extra...)
	}
	f := &Facts{
		Schema:      SchemaVersion,
		CollectedAt: o.Now().UTC().Truncate(time.Second),
		Target:      o.Target,
		Hostname:    o.Hostname,
		PortList:    pl,
		Addresses:   []Address{},
		Ports:       []Port{},
		RawHTTP:     []RawHTTP{},
	}

	f.Steps = append(f.Steps, resolve(ctx, o, f))
	if self := selfAddresses(f.Addresses, o.LocalAddrs); len(self) > 0 {
		f.SelfTarget, f.SelfAddresses = true, self
		if o.OnSelfTarget != nil {
			o.OnSelfTarget(self)
		}
	}
	f.Steps = append(f.Steps, probeTCP(ctx, o, f))
	f.Steps = append(f.Steps, probeRawHTTP(ctx, o, f))
	f.Steps = append(f.Steps, probeHostname(ctx, o, f))
	return f
}

func familyOf(a netip.Addr) string {
	if a.Is4() || a.Is4In6() {
		return IPv4
	}
	return IPv6
}

// familyName is the display name of a family: IPv4 or IPv6.
func familyName(fam string) string {
	if fam == IPv4 {
		return "IPv4"
	}
	return "IPv6"
}

func resolve(ctx context.Context, o Options, f *Facts) facts.CollectorStatus {
	st := facts.CollectorStatus{Name: "resolve", Status: facts.StatusOK}
	var addrs []netip.Addr
	literal := false
	if a, err := netip.ParseAddr(o.Target); err == nil {
		addrs, literal = []netip.Addr{a.Unmap()}, true
	} else {
		rctx, cancel := context.WithTimeout(ctx, 3*o.Timeout)
		defer cancel()
		got, err := o.Resolver.LookupNetIP(rctx, "ip", o.Target)
		if err != nil {
			f.ResolveError = err.Error()
			st.Status, st.Error = facts.StatusFailed, err.Error()
		}
		addrs = got
	}

	byFamily := map[string][]string{}
	seen := map[string]bool{}
	for _, a := range addrs {
		a = a.Unmap()
		s := a.String()
		if seen[s] || !a.IsValid() {
			continue
		}
		seen[s] = true
		fam := familyOf(a)
		if len(byFamily[fam]) >= maxPerFamily {
			f.Truncated = true
			continue
		}
		byFamily[fam] = append(byFamily[fam], s)
	}
	for _, fam := range []string{IPv4, IPv6} {
		list := byFamily[fam]
		sort.Strings(list)
		for _, a := range list {
			f.Addresses = append(f.Addresses, Address{Address: a, Family: fam})
		}
		if len(list) > 0 {
			f.Families = append(f.Families, Family{Family: fam, Status: FamilyProbed})
			continue
		}
		detail := "no AAAA record"
		if fam == IPv4 {
			detail = "no A record"
		}
		switch {
		case literal:
			detail = "the target is an " + familyName(familyOf(addrs[0])) + " address"
		case f.ResolveError != "":
			detail = "the name did not resolve"
		}
		f.Families = append(f.Families, Family{Family: fam, Status: FamilyNoAddress, Detail: detail})
	}
	if st.Status == facts.StatusOK && len(f.Addresses) == 0 {
		st.Status, st.Error = facts.StatusFailed, "the name resolved to no address"
		f.ResolveError = st.Error
	}
	return st
}

type job struct {
	addr Address
	port int
}

func probeTCP(ctx context.Context, o Options, f *Facts) facts.CollectorStatus {
	st := facts.CollectorStatus{Name: "tcp", Status: facts.StatusOK}
	if len(f.Addresses) == 0 {
		st.Status, st.Reason = facts.StatusSkipped, "no address to probe"
		return st
	}
	banner := f.PortList.bannerPorts()
	var jobs []job
	for _, a := range f.Addresses {
		for _, p := range f.PortList.All() {
			jobs = append(jobs, job{a, p})
		}
	}
	results := make([]Port, len(jobs))
	sem := make(chan struct{}, o.Concurrency)
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = connect(ctx, o.Timeout, j, banner[j.port])
		}()
	}
	wg.Wait()

	markRejects(results)
	f.Ports = results
	sort.SliceStable(f.Ports, func(i, j int) bool {
		a, b := f.Ports[i], f.Ports[j]
		if a.Family != b.Family {
			return a.Family < b.Family
		}
		if a.Address != b.Address {
			return a.Address < b.Address
		}
		return a.Port < b.Port
	})
	markUnreachableFamilies(f)

	var errs []string
	for _, p := range f.Ports {
		if p.State == Error {
			errs = append(errs, fmt.Sprintf("%s port %d: %s", p.Address, p.Port, p.Error))
		}
	}
	if len(errs) > 0 {
		st.Status, st.Error = facts.StatusPartial, strings.Join(firstN(errs, 3), "; ")
	}
	return st
}

func firstN(s []string, n int) []string {
	if len(s) > n {
		return append(s[:n:n], fmt.Sprintf("and %d more", len(s)-n))
	}
	return s
}

// connect makes one plain TCP connect and, for banner ports, reads the
// first line the service sends.
func connect(ctx context.Context, timeout time.Duration, j job, readBanner bool) Port {
	p := Port{Address: j.addr.Address, Family: j.addr.Family, Port: j.port}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(j.addr.Address, strconv.Itoa(j.port)))
	if err != nil {
		p.State, p.Error = classify(err)
		return p
	}
	defer func() { _ = conn.Close() }()
	p.State = Open
	if readBanner {
		p.Banner = grabBanner(conn, timeout)
	}
	return p
}

func classify(err error) (state, detail string) {
	var ne net.Error
	switch {
	case isRefused(err):
		return Closed, ""
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return Filtered, ""
	case isNoRoute(err):
		return Unreachable, shortErr(err)
	}
	return Error, shortErr(err)
}

// shortErr drops the "dial tcp a:p:" prefix the address already says.
func shortErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i >= 0 {
		return s[i+2:]
	}
	return s
}

// grabBanner reads at most bannerMax bytes until the first newline and
// returns that line as printable ASCII. Services that wait for the client
// to speak first (HTTP) give an empty banner after the timeout.
func grabBanner(conn net.Conn, timeout time.Duration) string {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 0, bannerMax)
	tmp := make([]byte, bannerMax)
	for len(buf) < bannerMax {
		n, err := conn.Read(tmp[:bannerMax-len(buf)])
		buf = append(buf, tmp[:n]...)
		if strings.IndexByte(string(buf), '\n') >= 0 || err != nil {
			break
		}
	}
	return cleanBanner(buf)
}

func cleanBanner(b []byte) string {
	line := string(b)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	var out strings.Builder
	for _, r := range line {
		if r >= 0x20 && r <= 0x7e {
			out.WriteRune(r)
		}
		if out.Len() >= bannerLineMax {
			break
		}
	}
	return strings.TrimSpace(out.String())
}

// markRejects turns "unreachable" into "filtered" on an address that
// answered on other ports: the host is reachable, so a host unreachable
// error there is a firewall reject rule (firewalld rejects with
// icmp-host-prohibited), not a missing route on this machine.
func markRejects(ps []Port) {
	answered := map[string]bool{}
	for _, p := range ps {
		if p.State == Open || p.State == Closed {
			answered[p.Address] = true
		}
	}
	for i, p := range ps {
		if p.State == Unreachable && answered[p.Address] {
			ps[i].State = Filtered
			ps[i].Error = "rejected: " + p.Error
		}
	}
}

// markUnreachableFamilies flags a family when every connect to it failed
// for lack of a route: then this machine cannot judge it at all.
func markUnreachableFamilies(f *Facts) {
	for i, fam := range f.Families {
		if fam.Status != FamilyProbed {
			continue
		}
		total, unreachable := 0, 0
		for _, p := range f.Ports {
			if p.Family == fam.Family {
				total++
				if p.State == Unreachable {
					unreachable++
				}
			}
		}
		if total > 0 && unreachable == total {
			f.Families[i].Status = FamilyUnreachable
			f.Families[i].Detail = "this machine has no route to " + fam.Family + "; run probe from a machine with " + fam.Family + " connectivity"
		}
	}
}
