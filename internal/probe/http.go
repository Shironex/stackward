package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Shironex/stackward/internal/facts"
)

// maxRedirects bounds the --hostname redirect chain.
const maxRedirects = 10

// transport is an HTTP transport that goes straight to the target: no proxy
// from the environment (a proxy would answer instead of the host), no keep
// alive, bounded header size.
func transport(timeout time.Duration, tc *tls.Config) *http.Transport {
	d := &net.Dialer{Timeout: timeout}
	return &http.Transport{
		Proxy:                  nil,
		DialContext:            d.DialContext,
		TLSClientConfig:        tc,
		TLSHandshakeTimeout:    timeout,
		ResponseHeaderTimeout:  timeout,
		DisableKeepAlives:      true,
		MaxResponseHeaderBytes: 64 << 10,
	}
}

func noRedirects(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// answer is what probe keeps of one response.
type answer struct {
	status   int
	location string
	// notAfter is the leaf certificate expiry, when TLS was used.
	notAfter *time.Time
}

// get sends one GET without following redirects and closes the body unread.
func get(ctx context.Context, c *http.Client, rawURL, ua string) (answer, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, http.NoBody)
	if err != nil {
		return answer{}, err
	}
	req.Header.Set("User-Agent", ua)
	resp, err := c.Do(req)
	if err != nil {
		return answer{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	a := answer{status: resp.StatusCode, location: capString(resp.Header.Get("Location"), 300)}
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		na := resp.TLS.PeerCertificates[0].NotAfter.UTC()
		a.notAfter = &na
	}
	return a, nil
}

// probeRawHTTP asks every open web port for / by IP, with the Host header
// set to the IP (what a scanner that found the origin would send).
func probeRawHTTP(ctx context.Context, o Options, f *Facts) facts.CollectorStatus {
	st := facts.CollectorStatus{Name: "http-raw", Status: facts.StatusOK}
	scheme := map[int]string{}
	for _, p := range f.PortList.HTTP {
		scheme[p] = "http"
	}
	for _, p := range f.PortList.HTTPS {
		scheme[p] = "https"
	}
	// TLS verification is skipped here only: an IP address has no
	// certificate name to verify, and the question is whether the origin
	// answers at all, not whether its certificate is right.
	tc := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12} //nolint:gosec // G402: raw IP reachability check, reported as skipped verification
	client := &http.Client{Transport: transport(o.Timeout, tc), CheckRedirect: noRedirects, Timeout: 3 * o.Timeout}
	defer client.CloseIdleConnections()

	var errs []string
	for _, p := range f.Ports {
		sch, web := scheme[p.Port]
		if !web || p.State != Open {
			continue
		}
		r := RawHTTP{Address: p.Address, Family: p.Family, Port: p.Port, Scheme: sch, TLSVerifySkipped: sch == "https"}
		ans, err := get(ctx, client, rawURL(sch, p.Address, p.Port), o.UserAgent)
		if err != nil {
			r.Error = shortErr(err)
			errs = append(errs, fmt.Sprintf("%s %s port %d: %s", sch, p.Address, p.Port, r.Error))
		} else {
			r.Status, r.Location = ans.status, ans.location
		}
		f.RawHTTP = append(f.RawHTTP, r)
	}
	switch {
	case len(f.RawHTTP) == 0:
		st.Status, st.Reason = facts.StatusSkipped, "no web port answered"
	case len(errs) == len(f.RawHTTP):
		st.Status, st.Error = facts.StatusFailed, strings.Join(firstN(errs, 3), "; ")
	case len(errs) > 0:
		st.Status, st.Error = facts.StatusPartial, strings.Join(firstN(errs, 3), "; ")
	}
	return st
}

// rawURL builds scheme://ip[:port]/, leaving out the default port so the
// Host header is the bare IP.
func rawURL(scheme, addr string, port int) string {
	host := addr
	if strings.Contains(addr, ":") {
		host = "[" + addr + "]"
	}
	if (scheme == "http" && port != 80) || (scheme == "https" && port != 443) {
		host = net.JoinHostPort(addr, strconv.Itoa(port))
	}
	return scheme + "://" + host + "/"
}

func capString(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// probeHostname requests https://<hostname>/ with certificate verification
// on, following redirects on the same host only, and records every hop.
func probeHostname(ctx context.Context, o Options, f *Facts) facts.CollectorStatus {
	st := facts.CollectorStatus{Name: "https-hostname", Status: facts.StatusOK}
	if o.Hostname == "" {
		st.Status, st.Reason = facts.StatusSkipped, "no --hostname given"
		return st
	}
	h := &HTTPSFact{Hostname: o.Hostname, Hops: []Hop{}}
	f.HTTPS = h
	tc := &tls.Config{RootCAs: o.RootCAs, MinVersion: tls.VersionTLS12}
	client := &http.Client{Transport: transport(o.Timeout, tc), CheckRedirect: noRedirects, Timeout: 3 * o.Timeout}
	defer client.CloseIdleConnections()

	cur, err := url.Parse("https://" + o.Hostname + "/")
	if err != nil {
		h.Error = err.Error()
		st.Status, st.Error = facts.StatusFailed, h.Error
		return st
	}
	host := cur.Hostname()
	seen := map[string]bool{}
	for {
		if seen[cur.String()] {
			h.Loop = true
			break
		}
		if len(h.Hops) >= maxRedirects {
			h.TooManyRedirects = true
			break
		}
		seen[cur.String()] = true
		ans, err := get(ctx, client, cur.String(), o.UserAgent)
		if err != nil {
			if isTLSError(err) {
				h.TLSError = shortErr(err)
			} else {
				h.Error = shortErr(err)
			}
			break
		}
		if h.CertNotAfter == nil {
			h.CertNotAfter = ans.notAfter
		}
		hop := Hop{URL: cur.String(), Status: ans.status, Location: ans.location}
		h.Hops = append(h.Hops, hop)
		h.FinalStatus = ans.status
		if ans.status < 300 || ans.status > 399 || hop.Location == "" {
			break
		}
		next, err := cur.Parse(hop.Location)
		if err != nil || (next.Scheme != "http" && next.Scheme != "https") {
			break
		}
		if !strings.EqualFold(next.Hostname(), host) {
			h.OffHost = next.Scheme + "://" + next.Host
			break
		}
		if cur.Scheme == "https" && next.Scheme == "http" {
			h.Downgrade = true
		}
		next.Fragment = ""
		cur = next
	}
	if len(h.Hops) == 0 {
		st.Status = facts.StatusFailed
		st.Error = h.Error
		if h.TLSError != "" {
			st.Error = h.TLSError
		}
	}
	return st
}

// isTLSError reports whether err is a certificate or handshake failure.
func isTLSError(err error) bool {
	var (
		cve  *tls.CertificateVerificationError
		ua   x509.UnknownAuthorityError
		he   x509.HostnameError
		ci   x509.CertificateInvalidError
		rhe  tls.RecordHeaderError
		alrt tls.AlertError
	)
	return errors.As(err, &cve) || errors.As(err, &ua) || errors.As(err, &he) || errors.As(err, &ci) ||
		errors.As(err, &rhe) || errors.As(err, &alrt) || strings.Contains(err.Error(), "tls: ")
}
