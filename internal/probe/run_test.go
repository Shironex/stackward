package probe

import (
	"context"
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Every test here talks to listeners on 127.0.0.1 and ::1 only.

// listen opens a TCP listener; network address "" picks loopback v4.
func listen(t *testing.T, addr string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("cannot listen on %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

func portOf(t *testing.T, ln net.Listener) int {
	t.Helper()
	_, p, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	n, _ := strconv.Atoi(p)
	return n
}

// serveBanner writes line to every connection, like sshd does.
func serveBanner(ln net.Listener, line string) {
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte(line))
			_ = c.Close()
		}
	}()
}

// closedPort returns a port nothing listens on (listen, note, close).
func closedPort(t *testing.T, host string) int {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		t.Skipf("cannot listen on %s: %v", host, err)
	}
	p := portOf(t, ln)
	_ = ln.Close()
	return p
}

type fakeResolver map[string][]netip.Addr

func (r fakeResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	if a, ok := r[host]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func fixedNow() time.Time { return time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC) }

func TestRunLoopbackIPv4(t *testing.T) {
	ssh := listen(t, "127.0.0.1:0")
	serveBanner(ssh, "SSH-2.0-OpenSSH_9.6 test\r\nsecond line\r\n")
	quiet := listen(t, "127.0.0.1:0") // open, sends nothing
	go func() {
		for {
			c, err := quiet.Accept()
			if err != nil {
				return
			}
			go func() { time.Sleep(time.Second); _ = c.Close() }()
		}
	}()
	web := httptest.NewServer(http.RedirectHandler("https://app.example.com/", http.StatusMovedPermanently))
	defer web.Close()
	webTLS := httptest.NewTLSServer(http.NotFoundHandler())
	defer webTLS.Close()
	closed := closedPort(t, "127.0.0.1")

	pl := PortList{
		SSH:    []int{portOf(t, ssh)},
		HTTP:   []int{mustPort(t, web.URL)},
		HTTPS:  []int{mustPort(t, webTLS.URL)},
		Docker: []int{closed},
		Extra:  []int{portOf(t, quiet)},
	}
	f := Run(context.Background(), Options{Target: "127.0.0.1", Ports: &pl, Timeout: 300 * time.Millisecond, Now: fixedNow})

	if len(f.Addresses) != 1 || f.Addresses[0].Family != IPv4 {
		t.Fatalf("addresses = %+v", f.Addresses)
	}
	if f.Families[1].Family != IPv6 || f.Families[1].Status != FamilyNoAddress || !strings.Contains(f.Families[1].Detail, "IPv4 address") {
		t.Errorf("families = %+v", f.Families)
	}
	states := map[int]Port{}
	for _, p := range f.Ports {
		states[p.Port] = p
	}
	if p := states[pl.SSH[0]]; p.State != Open || p.Banner != "SSH-2.0-OpenSSH_9.6 test" {
		t.Errorf("ssh port = %+v", p)
	}
	if p := states[closed]; p.State != Closed {
		t.Errorf("closed port = %+v", p)
	}
	if p := states[pl.Extra[0]]; p.State != Open || p.Banner != "" {
		t.Errorf("quiet extra port = %+v", p)
	}
	if len(f.RawHTTP) != 2 {
		t.Fatalf("raw http = %+v", f.RawHTTP)
	}
	for _, h := range f.RawHTTP {
		switch h.Scheme {
		case "http":
			if h.Status != http.StatusMovedPermanently || h.Location != "https://app.example.com/" || h.TLSVerifySkipped {
				t.Errorf("http = %+v (redirect must be recorded, not followed)", h)
			}
		case "https":
			if h.Status != http.StatusNotFound || !h.TLSVerifySkipped {
				t.Errorf("https = %+v", h)
			}
		}
	}
	if f.HTTPS != nil || f.Steps[3].Status != "skipped" {
		t.Errorf("hostname check ran without --hostname: %+v %+v", f.HTTPS, f.Steps[3])
	}
	if !f.CollectedAt.Equal(fixedNow()) {
		t.Errorf("collected_at = %v", f.CollectedAt)
	}
}

func mustPort(t *testing.T, rawURL string) int {
	t.Helper()
	i := strings.LastIndex(rawURL, ":")
	n, err := strconv.Atoi(strings.TrimSuffix(rawURL[i+1:], "/"))
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// TestRunBothFamilies resolves a name to 127.0.0.1 and ::1 and checks that
// each family is probed and reported on its own.
func TestRunBothFamilies(t *testing.T) {
	v6 := listen(t, "[::1]:0")
	port := portOf(t, v6)
	v4, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Skipf("port %d not free on 127.0.0.1: %v", port, err)
	}
	t.Cleanup(func() { _ = v4.Close() })
	serveBanner(v4, "SSH-2.0-four\n")
	serveBanner(v6, "SSH-2.0-six\n")
	closed := closedPort(t, "::1")

	res := fakeResolver{"probe.example.com": {
		netip.MustParseAddr("::1"), netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("127.0.0.1"),
	}}
	pl := PortList{SSH: []int{port}, Databases: []int{closed}}
	f := Run(context.Background(), Options{Target: "probe.example.com", Ports: &pl, Resolver: res, Timeout: 300 * time.Millisecond})

	if len(f.Addresses) != 2 || f.Addresses[0] != (Address{"127.0.0.1", IPv4}) || f.Addresses[1] != (Address{"::1", IPv6}) {
		t.Fatalf("addresses = %+v (want v4 then v6, deduplicated)", f.Addresses)
	}
	for _, fam := range f.Families {
		if fam.Status != FamilyProbed {
			t.Errorf("family %+v", fam)
		}
	}
	got := map[string]string{}
	for _, p := range f.Ports {
		if p.Port == port {
			got[p.Family] = p.State + " " + p.Banner
		}
	}
	if got[IPv4] != "open SSH-2.0-four" || got[IPv6] != "open SSH-2.0-six" {
		t.Errorf("per family = %v", got)
	}
}

func TestRunResolveFailure(t *testing.T) {
	f := Run(context.Background(), Options{Target: "missing.example.com", Resolver: fakeResolver{}, Timeout: 100 * time.Millisecond})
	if f.ResolveError == "" || len(f.Addresses) != 0 || f.Steps[0].Status != "failed" || f.Steps[1].Status != "skipped" {
		t.Fatalf("%+v", f)
	}
	for _, fam := range f.Families {
		if fam.Status != FamilyNoAddress || fam.Detail != "the name did not resolve" {
			t.Errorf("family %+v", fam)
		}
	}
}

func TestRunTruncatesManyAddresses(t *testing.T) {
	var addrs []netip.Addr
	for i := 1; i <= 6; i++ {
		addrs = append(addrs, netip.AddrFrom4([4]byte{127, 0, 0, byte(i)}))
	}
	pl := PortList{}
	f := Run(context.Background(), Options{Target: "many.example.com", Ports: &pl, Resolver: fakeResolver{"many.example.com": addrs}})
	if len(f.Addresses) != maxPerFamily || !f.Truncated {
		t.Fatalf("addresses %d truncated %v", len(f.Addresses), f.Truncated)
	}
}

func TestMarkRejectsAndUnreachableFamilies(t *testing.T) {
	f := &Facts{
		Families: []Family{{Family: IPv4, Status: FamilyProbed}, {Family: IPv6, Status: FamilyProbed}},
		Ports: []Port{
			{Address: "192.0.2.10", Family: IPv4, Port: 22, State: Closed},
			{Address: "192.0.2.10", Family: IPv4, Port: 5432, State: Unreachable, Error: "no route to host"},
			{Address: "2001:db8::10", Family: IPv6, Port: 22, State: Unreachable, Error: "network is unreachable"},
			{Address: "2001:db8::10", Family: IPv6, Port: 5432, State: Unreachable, Error: "network is unreachable"},
		},
	}
	markRejects(f.Ports)
	markUnreachableFamilies(f)
	if p := f.Ports[1]; p.State != Filtered || !strings.HasPrefix(p.Error, "rejected") {
		t.Errorf("reject on an answering host must count as filtered: %+v", p)
	}
	if f.Families[0].Status != FamilyProbed || f.Families[1].Status != FamilyUnreachable {
		t.Errorf("families = %+v", f.Families)
	}
}

func TestBanner(t *testing.T) {
	if got := cleanBanner([]byte("SSH-2.0-x\x1b[31m\x00 \r\nmore")); got != "SSH-2.0-x[31m" {
		t.Errorf("clean = %q", got)
	}
	long := strings.Repeat("A", 1000)
	if got := cleanBanner([]byte(long)); len(got) != bannerLineMax {
		t.Errorf("cap = %d", len(got))
	}
	a, b := net.Pipe()
	go func() { _, _ = b.Write([]byte(strings.Repeat("B", 2*bannerMax))); _ = b.Close() }()
	if got := grabBanner(a, time.Second); len(got) != bannerLineMax {
		t.Errorf("grab without newline reads at most %d bytes, kept %d", bannerMax, len(got))
	}
}

func TestRawURL(t *testing.T) {
	for _, c := range []struct {
		scheme, addr string
		port         int
		want         string
	}{
		{"http", "192.0.2.10", 80, "http://192.0.2.10/"},
		{"https", "2001:db8::10", 443, "https://[2001:db8::10]/"},
		{"https", "2001:db8::10", 8443, "https://[2001:db8::10]:8443/"},
	} {
		if got := rawURL(c.scheme, c.addr, c.port); got != c.want {
			t.Errorf("rawURL = %q, want %q", got, c.want)
		}
	}
}

// hostnameServer starts a TLS server on 127.0.0.1 and returns its
// host:port and a pool that trusts it.
func hostnameServer(t *testing.T, h http.Handler) (string, *x509.CertPool) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return strings.TrimPrefix(srv.URL, "https://"), pool
}

func runHostname(t *testing.T, host string, pool *x509.CertPool) *HTTPSFact {
	t.Helper()
	f := &Facts{}
	o := Options{Hostname: host, RootCAs: pool, Timeout: time.Second}
	o.defaults()
	probeHostname(context.Background(), o, f)
	if f.HTTPS == nil {
		t.Fatal("no https fact")
	}
	return f.HTTPS
}

func TestHostnameRedirectLoop(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle("/", http.RedirectHandler("/a", http.StatusFound))
	mux.Handle("/a", http.RedirectHandler("/", http.StatusFound))
	host, pool := hostnameServer(t, mux)
	h := runHostname(t, host, pool)
	if !h.Loop || len(h.Hops) != 2 || h.TLSError != "" || h.CertNotAfter == nil {
		t.Fatalf("%+v", h)
	}
}

func TestHostnameSelfRedirect(t *testing.T) {
	// The tunnel case: the app answers its own HTTPS URL with a redirect to
	// the same HTTPS URL, forever.
	var self string
	host, pool := hostnameServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, self, http.StatusMovedPermanently)
	}))
	self = "https://" + host + "/"
	if h := runHostname(t, host, pool); !h.Loop || len(h.Hops) != 1 {
		t.Fatalf("%+v", h)
	}
}

func TestHostnameOKAndOffHost(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle("/", http.RedirectHandler("/login", http.StatusFound))
	mux.Handle("/login", http.RedirectHandler("https://id.example.com/authorize", http.StatusFound))
	host, pool := hostnameServer(t, mux)
	h := runHostname(t, host, pool)
	if h.Loop || h.OffHost != "https://id.example.com" || len(h.Hops) != 2 || h.FinalStatus != http.StatusFound {
		t.Fatalf("%+v", h)
	}
}

func TestHostnameTooManyRedirects(t *testing.T) {
	n := 0
	host, pool := hostnameServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n++
		http.Redirect(w, r, "/"+strconv.Itoa(n), http.StatusFound)
	}))
	if h := runHostname(t, host, pool); !h.TooManyRedirects || len(h.Hops) != maxRedirects {
		t.Fatalf("%+v", h)
	}
}

func TestHostnameUntrustedCertificate(t *testing.T) {
	host, _ := hostnameServer(t, http.NotFoundHandler())
	h := runHostname(t, host, x509.NewCertPool())
	if h.TLSError == "" || len(h.Hops) != 0 || h.Error != "" {
		t.Fatalf("%+v", h)
	}
}
