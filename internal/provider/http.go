package provider

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// maxBody caps every response body. The largest answer the module reads is
// a firewall with 50 rules, a few tens of kilobytes.
const maxBody = 1 << 20

// apiHosts is every host the client may talk to. A URL with any other host
// is refused before a connection is made, and redirects are never followed.
var apiHosts = map[string]bool{
	"api.hetzner.cloud":   true,
	"eu.api.ovh.com":      true,
	"ca.api.ovh.com":      true,
	"api.us.ovhcloud.com": true,
}

// getter sends GET requests and nothing else. It is the only code of the
// feature that uses the network.
type getter struct {
	client *http.Client
}

func newGetter(rt http.RoundTripper, timeout time.Duration) *getter {
	if rt == nil {
		d := &net.Dialer{Timeout: timeout}
		rt = &http.Transport{
			// No proxy from the environment: the request carries a
			// credential, and only the provider should see it.
			Proxy:                  nil,
			DialContext:            d.DialContext,
			TLSHandshakeTimeout:    timeout,
			ResponseHeaderTimeout:  timeout,
			DisableKeepAlives:      true,
			MaxResponseHeaderBytes: 64 << 10,
		}
	}
	return &getter{client: &http.Client{
		Transport: rt,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errRedirect
		},
	}}
}

var errRedirect = errors.New("the provider API answered with a redirect, which stackward never follows")

// apiError is an answer with a status other than 200.
type apiError struct{ code int }

func (e *apiError) Error() string { return fmt.Sprintf("the provider API answered %d", e.code) }

// get sends one GET to rawURL with the given headers and returns the body.
// The URL must be https on one of apiHosts.
func (g *getter) get(ctx context.Context, rawURL string, header http.Header) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "https" || !apiHosts[u.Hostname()] || u.Port() != "" || u.User != nil {
		return nil, fmt.Errorf("refusing a request to %s://%s: not a provider API host", u.Scheme, u.Host)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), http.NoBody)
	if err != nil {
		return nil, err
	}
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "stackward")
	resp, err := g.client.Do(req)
	if err != nil {
		if errors.Is(err, errRedirect) {
			return nil, errRedirect
		}
		return nil, &unreachableError{err: err}
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, &unreachableError{err: err}
	}
	if len(body) > maxBody {
		return nil, fmt.Errorf("the provider API answer is larger than %d bytes", maxBody)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &apiError{code: resp.StatusCode}
	}
	return body, nil
}

// unreachableError is a failure to reach the API at all.
type unreachableError struct{ err error }

func (e *unreachableError) Error() string {
	return "the provider API could not be reached: " + e.err.Error()
}

func (e *unreachableError) Unwrap() error { return e.err }
