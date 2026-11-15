// Package dockerapi is a minimal, read only client for the Docker Engine API
// over its Unix socket, plus the parsers that turn its answers into small
// typed values.
//
// Access to the Docker socket is root on the host, so a write must be
// impossible by construction, not by convention: the client refuses every
// method but GET before a connection is opened, and the transport refuses
// it again. Paths are built by stackward, never taken from container data;
// redirects are never followed; no proxy is used; every answer is capped in
// size and time. Parsers strip Config.Env, Config.Cmd, Config.Entrypoint,
// Config.Healthcheck and the process Args before anything is decoded.
//
// This package must not import internal/facts (the facts package imports
// it); it returns its own types.
package dockerapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// Method is the only HTTP method this package ever sends.
const Method = http.MethodGet

// Defaults for Options.
const (
	DefaultTimeout  = 10 * time.Second
	DefaultMaxBytes = 8 << 20
	maxHeaderBytes  = 64 << 10
)

// Errors returned by the client. Wrapped errors keep these for errors.Is.
var (
	// ErrMethodNotAllowed is returned for any method but GET, before any
	// connection is made.
	ErrMethodNotAllowed = errors.New("dockerapi: only GET is sent to the Docker API")
	// ErrBadPath is returned for a path that is not a plain absolute API path.
	ErrBadPath = errors.New("dockerapi: not a plain absolute API path")
	// ErrTooLarge is returned when an answer passes Options.MaxBytes.
	ErrTooLarge = errors.New("dockerapi: answer larger than the size cap")
)

// StatusError is a non 2xx answer. The daemon's message is not kept: it can
// quote request data.
type StatusError struct {
	Code int
	Path string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("docker API answered %d for %s", e.Code, e.Path)
}

// Options tunes a Client.
type Options struct {
	// Timeout bounds one request, connection included. Zero means
	// DefaultTimeout.
	Timeout time.Duration
	// MaxBytes caps one answer. Zero means DefaultMaxBytes.
	MaxBytes int64
}

// Client talks to one Docker daemon over a Unix socket, GET only.
type Client struct {
	hc       *http.Client
	tr       *http.Transport
	maxBytes int64
}

// NewUnix returns a client for the daemon listening on socketPath. It does
// not connect until the first request.
func NewUnix(socketPath string, o Options) *Client {
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	maxBytes := o.MaxBytes
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", socketPath)
	}
	tr := &http.Transport{
		// No proxy: the environment must never route Docker traffic.
		Proxy:                  nil,
		DialContext:            dial,
		ForceAttemptHTTP2:      false,
		DisableCompression:     true,
		MaxIdleConns:           1,
		IdleConnTimeout:        timeout,
		ResponseHeaderTimeout:  timeout,
		MaxResponseHeaderBytes: maxHeaderBytes,
	}
	return &Client{
		tr: tr,
		hc: &http.Client{
			Transport: getOnly{next: tr},
			Timeout:   timeout,
			// Never follow a redirect: the answer is reported as a status.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		maxBytes: maxBytes,
	}
}

// Close drops idle connections.
func (c *Client) Close() { c.tr.CloseIdleConnections() }

// Get sends GET path and returns the body of a 2xx answer.
func (c *Client) Get(ctx context.Context, path string) ([]byte, error) {
	return c.Do(ctx, Method, path)
}

// Do sends method path. Any method but GET is refused with
// ErrMethodNotAllowed before anything is opened; it exists so the refusal
// can be tested and reviewed in one place.
func (c *Client) Do(ctx context.Context, method, path string) ([]byte, error) {
	if method != Method {
		return nil, fmt.Errorf("%w (asked for %q)", ErrMethodNotAllowed, method)
	}
	if err := CheckPath(path); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, Method, "http://docker"+path, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrBadPath, path)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	where := strings.SplitN(path, "?", 2)[0]
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		return nil, &StatusError{Code: resp.StatusCode, Path: where}
	}
	if resp.ContentLength > c.maxBytes {
		return nil, fmt.Errorf("%s: %w", where, ErrTooLarge)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > c.maxBytes {
		return nil, fmt.Errorf("%s: %w", where, ErrTooLarge)
	}
	return b, nil
}

// getOnly is the second lock: the transport itself refuses every method
// but GET, so no future caller can send a write by building its own request.
type getOnly struct{ next http.RoundTripper }

func (g getOnly) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != Method {
		if req.Body != nil {
			_ = req.Body.Close()
		}
		return nil, fmt.Errorf("%w (asked for %q)", ErrMethodNotAllowed, req.Method)
	}
	return g.next.RoundTrip(req)
}

// CheckPath accepts a path stackward built: one leading slash, no scheme or
// host, no dot segments, no spaces or control characters.
func CheckPath(path string) error {
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		return fmt.Errorf("%w: %q must start with a single slash", ErrBadPath, path)
	}
	for _, r := range path {
		if r <= 0x20 || r == 0x7f {
			return fmt.Errorf("%w: %q holds a space or control character", ErrBadPath, path)
		}
	}
	p := strings.SplitN(path, "?", 2)[0]
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return fmt.Errorf("%w: %q holds a dot segment", ErrBadPath, path)
		}
	}
	return nil
}
