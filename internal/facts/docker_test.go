package facts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"testing/fstest"
	"time"

	"github.com/Shironex/stackward/internal/facts/dockerapi"
)

// fakeDockerAPI serves recorded Engine API answers from
// dockerapi/testdata, keyed by path, and records every path asked for.
type fakeDockerAPI struct {
	answers map[string][]byte
	err     error // returned for every path when set
	paths   []string
}

func (f *fakeDockerAPI) Get(_ context.Context, p string) ([]byte, error) {
	f.paths = append(f.paths, p)
	if f.err != nil {
		return nil, f.err
	}
	if b, ok := f.answers[p]; ok {
		return b, nil
	}
	return nil, &dockerapi.StatusError{Code: 404, Path: p}
}

func (f *fakeDockerAPI) Close() {}

func recordedAPI(t *testing.T) *fakeDockerAPI {
	t.Helper()
	dir := filepath.Join("dockerapi", "testdata")
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	api := &fakeDockerAPI{answers: map[string][]byte{
		dockerapi.PathVersion:    read("version.json"),
		dockerapi.PathInfo:       read("info.json"),
		dockerapi.PathContainers: read("containers.json"),
		dockerapi.PathNetworks:   read("networks.json"),
	}}
	files, _ := filepath.Glob(filepath.Join(dir, "inspect-*.json"))
	for _, f := range files {
		id := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(f), "inspect-"), ".json")
		p, err := dockerapi.InspectPath(id)
		if err != nil {
			t.Fatal(err)
		}
		api.answers[p] = read(filepath.Base(f))
	}
	return api
}

func dockerSys(files map[string]string) *fakeSystem {
	sys := newFakeSystem(files)
	sys.files["var/run/docker.sock"] = &fstest.MapFile{Mode: fs.ModeSocket | 0o660, ModTime: time.Unix(0, 0)}
	return sys
}

func collectDocker(t *testing.T, sys System, api dockerAPI) (*Docker, error) {
	t.Helper()
	c := dockerCollector{open: func(string) dockerAPI { return api }}
	out := &Facts{}
	err := c.Collect(context.Background(), sys, out)
	if out.Docker == nil {
		t.Fatalf("Docker left nil (err %v)", err)
	}
	return out.Docker, err
}

func TestDockerCollectorRecorded(t *testing.T) {
	sys := dockerSys(map[string]string{
		"/etc/group":                                         "root:x:0:\ndocker:x:998:alice\n",
		"/etc/docker/daemon.json":                            `{"log-driver":"json-file","log-opts":{"max-size":"10m","max-file":"3"}}`,
		"/lib/systemd/system/docker.service":                 "[Service]\nExecStart=/usr/bin/dockerd -H fd:// \\\n  --containerd=/run/containerd/containerd.sock\n",
		"/etc/systemd/system/docker.service.d/override.conf": "[Service]\nExecStart=\nExecStart=/usr/bin/dockerd -H fd:// -H tcp://0.0.0.0:2375\n",
		"/proc/net/tcp":                                      "  sl  local_address rem_address   st\n   0: 00000000:0947 00000000:0000 0A 0\n   1: 0100007F:0035 00000000:0000 0A 0\n",
		"/proc/net/tcp6":                                     "  sl  local_address rem_address   st\n",
	})
	api := recordedAPI(t)
	d, err := collectDocker(t, sys, api)
	if err != nil {
		t.Fatalf("err %v", err)
	}
	for _, p := range api.paths {
		if strings.Contains(p, "not-hex") {
			t.Errorf("asked for a path built from a bad id: %s", p)
		}
	}
	if !d.Installed || d.API != "ok" || d.Version.Version != "27.5.1" || d.Info.LoggingDriver != "json-file" {
		t.Fatalf("docker %+v", d)
	}
	if d.Socket == nil || d.Socket.Perm != "0660" || d.Socket.WorldWritable || d.Socket.Group != "root" {
		t.Fatalf("socket %+v", d.Socket)
	}
	if !d.Daemon.ConfigFound || d.Daemon.LogMaxSize != "10m" || len(d.Daemon.UnitFiles) != 2 {
		t.Fatalf("daemon %+v", d.Daemon)
	}
	// The drop-in reset ExecStart: only its hosts count.
	if len(d.Daemon.Hosts) != 2 || d.Daemon.Hosts[1].Addr != "tcp://0.0.0.0:2375" {
		t.Fatalf("hosts %+v", d.Daemon.Hosts)
	}
	if !d.TCPRead || len(d.TCP) != 1 || d.TCP[0] != (DockerTCPListener{Port: 2375, Bind: "any"}) {
		t.Fatalf("tcp %+v", d.TCP)
	}
	if len(d.Containers) != 5 || len(d.Networks) != 4 {
		t.Fatalf("containers %d networks %d", len(d.Containers), len(d.Networks))
	}
	byName := map[string]DockerContainer{}
	for _, c := range d.Containers {
		byName[c.Name] = c
	}
	web := byName["shop-web-1"]
	if web.Project != "shop" || web.Service != "web" || !web.ProxyRouted || web.User != "" {
		t.Fatalf("web %+v", web)
	}
	if web.Flags != nil {
		t.Errorf("flags kept for a container without the socket: %v", web.Flags)
	}
	if strings.Join(web.Networks, ",") != "edge,shop_default" {
		t.Errorf("web networks %v", web.Networks)
	}
	if _, ok := web.Labels["traefik.http.routers.shop.rule"]; ok {
		t.Error("router rule label kept")
	}
	proxy := byName["coolify-proxy"]
	if !MountsDockerSocket(proxy.Mounts) || len(proxy.Ports) != 3 || proxy.Ports[0].HostPort != 80 {
		t.Fatalf("proxy %+v", proxy)
	}
	if _, ok := proxy.Labels["traefik.http.middlewares.auth.basicauth.users"]; ok {
		t.Error("basic auth label kept")
	}
	sp := byName["socket-proxy"]
	if sp.Flags["POST"] != "1" || sp.Flags["EXEC"] != "0" || len(sp.Flags) != 3 {
		t.Fatalf("socket proxy flags %v", sp.Flags)
	}
	if tun := byName["tunnel"]; tun.NetworkMode != "host" || tun.User != "nonroot" {
		t.Fatalf("tunnel %+v", tun)
	}

	// Nothing secret reaches the facts.
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{"not-a-real", "server.js", "proxyuser", "shop.example.com", "basicauth"} {
		if strings.Contains(string(b), m) {
			t.Errorf("%q reached the facts", m)
		}
	}
}

func TestDockerCollectorSocketDenied(t *testing.T) {
	sys := dockerSys(nil)
	denied := &fakeDockerAPI{err: fmt.Errorf("dial unix /var/run/docker.sock: %w", &os.SyscallError{Syscall: "connect", Err: syscall.EACCES})}
	d, err := collectDocker(t, sys, denied)
	if err != nil {
		t.Fatalf("a denied socket is a finding, not an error: %v", err)
	}
	if d.API != "denied" || !strings.Contains(d.APIReason, "docker group") || d.Containers != nil {
		t.Fatalf("docker %+v", d)
	}
}

func TestDockerCollectorNotInstalled(t *testing.T) {
	api := &fakeDockerAPI{}
	d, err := collectDocker(t, newFakeSystem(nil), api)
	if err != nil || d.Installed || d.API != "absent" || len(api.paths) != 0 {
		t.Fatalf("docker %+v err %v paths %v", d, err, api.paths)
	}
}

func TestDockerCollectorNoSocket(t *testing.T) {
	sys := newFakeSystem(map[string]string{"/etc/docker/daemon.json": "{}"})
	api := &fakeDockerAPI{}
	d, err := collectDocker(t, sys, api)
	if err != nil || !d.Installed || d.API != "absent" || len(api.paths) != 0 {
		t.Fatalf("docker %+v err %v", d, err)
	}
}

func TestDockerCollectorBrokenDaemonJSON(t *testing.T) {
	sys := dockerSys(map[string]string{"/etc/docker/daemon.json": "{not json"})
	d, _ := collectDocker(t, sys, recordedAPI(t))
	if d.Daemon.ConfigFound || !strings.Contains(d.Daemon.ConfigError, "invalid JSON") {
		t.Fatalf("daemon %+v", d.Daemon)
	}
}

func TestDockerCollectorInspectError(t *testing.T) {
	api := recordedAPI(t)
	p, _ := dockerapi.InspectPath(strings.Repeat("b", 64))
	api.answers[p] = []byte("{broken")
	d, err := collectDocker(t, dockerSys(nil), api)
	if err == nil || len(d.Containers) != 4 {
		t.Fatalf("want partial data and an error, got %d containers, err %v", len(d.Containers), err)
	}
}

func TestClassifyAPIError(t *testing.T) {
	cases := map[string]error{
		"denied": &dockerapi.StatusError{Code: 403, Path: "/version"},
		"absent": fmt.Errorf("dial: %w", syscall.ECONNREFUSED),
		"error":  errors.New("boom"),
	}
	for want, err := range cases {
		if got, _ := classifyAPIError("/var/run/docker.sock", err); got != want {
			t.Errorf("%v: got %s, want %s", err, got, want)
		}
	}
}

func TestIsDockerSocketPath(t *testing.T) {
	for p, want := range map[string]bool{
		"/var/run/docker.sock": true, "/run/docker.sock": true, "/var/run": true, "/var/run/": true,
		"/run": true, "/var": true, "/": true, "//var//run": true,
		"/var/lib": false, "/var/run/docker": false, "/srv": false, "": false,
	} {
		if got := IsDockerSocketPath(p); got != want {
			t.Errorf("%q: got %v", p, got)
		}
	}
	ro := []DockerMount{ParseVolumeSpec("/var/run/docker.sock:/var/run/docker.sock:ro")}
	if !ro[0].ReadOnly || !MountsDockerSocket(ro) {
		t.Fatalf("read only socket mount must count: %+v", ro)
	}
	if MountsDockerSocket([]DockerMount{{Type: "volume", Source: "/var/run"}}) {
		t.Fatal("a volume is not a bind")
	}
}

func TestParseVolumeSpec(t *testing.T) {
	cases := map[string]DockerMount{
		"/data":             {Type: "volume", Target: "/data"},
		"pg:/var/lib/pg":    {Type: "volume", Source: "pg", Target: "/var/lib/pg"},
		"./app:/app:ro,z":   {Type: "bind", Source: "./app", Target: "/app", ReadOnly: true},
		"${HOME}/x:/x":      {Type: "other", Source: "${HOME}/x", Target: "/x"},
		"/etc:/host-etc:rw": {Type: "bind", Source: "/etc", Target: "/host-etc"},
	}
	for spec, want := range cases {
		if got := ParseVolumeSpec(spec); got != want {
			t.Errorf("%q: got %+v, want %+v", spec, got, want)
		}
	}
}

func TestProcNetBind(t *testing.T) {
	for hex, want := range map[string]string{
		"00000000": "any", "0100007F": "loopback", "0200A8C0": "specific",
		"00000000000000000000000000000000": "any", "00000000000000000000000001000000": "loopback",
		"0000000000000000FFFF00000100007F": "loopback",
	} {
		if got := procNetBind(hex); got != want {
			t.Errorf("%s: got %s, want %s", hex, got, want)
		}
	}
}
