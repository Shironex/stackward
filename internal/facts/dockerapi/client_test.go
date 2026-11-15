package dockerapi

import (
	"context"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeDaemon serves canned answers on a Unix socket and records every
// request it receives.
type fakeDaemon struct {
	socket string
	srv    *http.Server
	mu     sync.Mutex
	seen   []string // "METHOD /path?query"
}

func startDaemon(t *testing.T, h http.HandlerFunc) *fakeDaemon {
	t.Helper()
	// Unix socket paths are short (104 bytes on macOS); t.TempDir is long.
	dir, err := os.MkdirTemp("", "swd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	d := &fakeDaemon{socket: filepath.Join(dir, "d.sock")}
	ln, err := net.Listen("unix", d.socket)
	if err != nil {
		t.Fatal(err)
	}
	d.srv = &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		d.seen = append(d.seen, r.Method+" "+r.URL.RequestURI())
		d.mu.Unlock()
		h(w, r)
	})}
	go func() { _ = d.srv.Serve(ln) }()
	t.Cleanup(func() { _ = d.srv.Close() })
	return d
}

func (d *fakeDaemon) requests() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.seen...)
}

func okJSON(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}
}

func TestGetReadsJSON(t *testing.T) {
	d := startDaemon(t, okJSON(`{"Version":"27.5.1"}`))
	c := NewUnix(d.socket, Options{})
	defer c.Close()
	b, err := c.Get(context.Background(), PathVersion)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"Version":"27.5.1"}` {
		t.Fatalf("body %q", b)
	}
	if got := d.requests(); len(got) != 1 || got[0] != "GET /version" {
		t.Fatalf("requests %v", got)
	}
}

func TestRefusesEveryMethodButGet(t *testing.T) {
	d := startDaemon(t, okJSON(`[]`))
	c := NewUnix(d.socket, Options{})
	defer c.Close()
	for _, m := range []string{"POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "get", ""} {
		_, err := c.Do(context.Background(), m, PathContainers)
		if !errors.Is(err, ErrMethodNotAllowed) {
			t.Errorf("%q: err %v, want ErrMethodNotAllowed", m, err)
		}
	}
	if got := d.requests(); len(got) != 0 {
		t.Fatalf("daemon saw requests: %v", got)
	}
}

// TestTransportRefusesWrites builds requests around Do, straight on the
// client's transport: the second lock must hold on its own.
func TestTransportRefusesWrites(t *testing.T) {
	d := startDaemon(t, okJSON(`{}`))
	c := NewUnix(d.socket, Options{})
	defer c.Close()
	for _, m := range []string{http.MethodPost, http.MethodDelete, http.MethodPut} {
		req, err := http.NewRequest(m, "http://docker/containers/x/kill", strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := c.hc.Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if !errors.Is(err, ErrMethodNotAllowed) {
			t.Errorf("%s: err %v, want ErrMethodNotAllowed", m, err)
		}
	}
	if got := d.requests(); len(got) != 0 {
		t.Fatalf("daemon saw requests: %v", got)
	}
}

func TestRefusesBadPaths(t *testing.T) {
	d := startDaemon(t, okJSON(`{}`))
	c := NewUnix(d.socket, Options{})
	defer c.Close()
	for _, p := range []string{"containers/json", "//evil.example.com/x", "/a/../b", "/a/./b", "/a b", "/a\nb", "http://x/", ""} {
		if _, err := c.Get(context.Background(), p); !errors.Is(err, ErrBadPath) {
			t.Errorf("%q: err %v, want ErrBadPath", p, err)
		}
	}
	if got := d.requests(); len(got) != 0 {
		t.Fatalf("daemon saw requests: %v", got)
	}
}

func TestStatusErrorDropsDaemonMessage(t *testing.T) {
	d := startDaemon(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"secret detail"}`))
	})
	c := NewUnix(d.socket, Options{})
	defer c.Close()
	_, err := c.Get(context.Background(), "/info?x=1")
	var se *StatusError
	if !errors.As(err, &se) || se.Code != 403 || se.Path != "/info" {
		t.Fatalf("err %v", err)
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatalf("daemon message leaked: %v", err)
	}
}

func TestRedirectIsNotFollowed(t *testing.T) {
	d := startDaemon(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/elsewhere", http.StatusFound)
	})
	c := NewUnix(d.socket, Options{})
	defer c.Close()
	_, err := c.Get(context.Background(), PathInfo)
	var se *StatusError
	if !errors.As(err, &se) || se.Code != http.StatusFound {
		t.Fatalf("err %v", err)
	}
	if got := d.requests(); len(got) != 1 {
		t.Fatalf("redirect followed: %v", got)
	}
}

func TestSizeCap(t *testing.T) {
	big := `"` + strings.Repeat("x", 2048) + `"`
	// With a length header and without (chunked).
	for _, chunked := range []bool{false, true} {
		d := startDaemon(t, func(w http.ResponseWriter, _ *http.Request) {
			if chunked {
				w.Header().Set("Transfer-Encoding", "chunked")
				w.(http.Flusher).Flush()
			}
			_, _ = w.Write([]byte(big))
		})
		c := NewUnix(d.socket, Options{MaxBytes: 1024})
		if _, err := c.Get(context.Background(), PathInfo); !errors.Is(err, ErrTooLarge) {
			t.Errorf("chunked=%v: err %v, want ErrTooLarge", chunked, err)
		}
		c.Close()
	}
}

func TestTimeout(t *testing.T) {
	release := make(chan struct{})
	d := startDaemon(t, func(http.ResponseWriter, *http.Request) { <-release })
	defer close(release)
	c := NewUnix(d.socket, Options{Timeout: 100 * time.Millisecond})
	defer c.Close()
	start := time.Now()
	if _, err := c.Get(context.Background(), PathInfo); err == nil {
		t.Fatal("no error from a daemon that never answers")
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("timeout not honoured")
	}
}

func TestMissingSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "swd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	c := NewUnix(filepath.Join(dir, "none.sock"), Options{})
	defer c.Close()
	_, err = c.Get(context.Background(), PathVersion)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err %v, want not exist", err)
	}
}

func TestIgnoresProxyEnvironment(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://192.0.2.1:3128")
	t.Setenv("http_proxy", "http://192.0.2.1:3128")
	d := startDaemon(t, okJSON(`{}`))
	c := NewUnix(d.socket, Options{})
	defer c.Close()
	if _, err := c.Get(context.Background(), PathInfo); err != nil {
		t.Fatalf("proxy env changed routing: %v", err)
	}
}
