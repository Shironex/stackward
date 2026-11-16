package facts

import (
	"testing"

	"github.com/Shironex/stackward/internal/facts/dockerapi"
)

func TestSocketMask(t *testing.T) {
	root := DockerMount{Type: "bind", Source: "/", Target: "/rootfs", ReadOnly: true}
	tmpfs := func(target string) DockerMount { return DockerMount{Type: "tmpfs", Target: target} }
	cases := []struct {
		name   string
		bind   DockerMount
		others []DockerMount
		masked string // the cover's target, "" when the socket stays reachable
	}{
		{"root without mask", root, nil, ""},
		{"root, tmpfs on run", root, []DockerMount{tmpfs("/rootfs/run")}, "/rootfs/run"},
		{"root, tmpfs on run with slash", root, []DockerMount{tmpfs("/rootfs/run/")}, "/rootfs/run/"},
		{"root, tmpfs on the socket", root, []DockerMount{tmpfs("/rootfs/run/docker.sock")}, "/rootfs/run/docker.sock"},
		{"root, volume on run", root, []DockerMount{{Type: "volume", Source: "runvol", Target: "/rootfs/run"}}, "/rootfs/run"},
		{"root, plain bind on run", root, []DockerMount{{Type: "bind", Source: "/srv/empty", Target: "/rootfs/run"}}, "/rootfs/run"},
		{"root, socket folder bind on run", root, []DockerMount{{Type: "bind", Source: "/run", Target: "/rootfs/run"}}, ""},
		{"root, other type on run", root, []DockerMount{{Type: "other", Target: "/rootfs/run"}}, ""},
		{"root, tmpfs on a sibling", root, []DockerMount{tmpfs("/rootfs/root"), tmpfs("/rootfs/runner")}, ""},
		{"root, tmpfs only on var/run", root, []DockerMount{tmpfs("/rootfs/var/run")}, ""},
		{"root, tmpfs on run then bind under it", root, []DockerMount{tmpfs("/rootfs/run"), {Type: "bind", Source: "/run/docker.sock", Target: "/rootfs/run/docker.sock"}}, ""},
		{"root, tmpfs on run and something at the same depth", root, []DockerMount{tmpfs("/rootfs/run"), {Type: "other", Target: "/rootfs/run"}}, ""},
		{"root, tmpfs above the bind", root, []DockerMount{tmpfs("/")}, ""},
		{"root, relative cover", root, []DockerMount{tmpfs("rootfs/run")}, ""},
		{"relative bind target", DockerMount{Type: "bind", Source: "/", Target: "rootfs"}, []DockerMount{tmpfs("rootfs/run")}, ""},
		{"run folder, tmpfs on the socket", DockerMount{Type: "bind", Source: "/run", Target: "/host-run"}, []DockerMount{tmpfs("/host-run/docker.sock")}, "/host-run/docker.sock"},
		{"var/run folder resolves to run", DockerMount{Type: "bind", Source: "/var/run/", Target: "/h"}, []DockerMount{tmpfs("/h/docker.sock")}, "/h/docker.sock"},
		{"var folder, tmpfs on its run", DockerMount{Type: "bind", Source: "/var", Target: "/hv"}, []DockerMount{tmpfs("/hv/run")}, "/hv/run"},
		{"var folder, tmpfs elsewhere", DockerMount{Type: "bind", Source: "/var", Target: "/hv"}, []DockerMount{tmpfs("/hv/lib")}, ""},
		{"direct socket bind", DockerMount{Type: "bind", Source: "/var/run/docker.sock", Target: "/var/run/docker.sock"}, []DockerMount{tmpfs("/var/run/docker.sock"), tmpfs("/var/run")}, ""},
		{"direct run socket bind", DockerMount{Type: "bind", Source: "/run/docker.sock", Target: "/s/docker.sock"}, []DockerMount{tmpfs("/s/docker.sock")}, ""},
		{"not a bind", DockerMount{Type: "volume", Source: "/", Target: "/rootfs"}, []DockerMount{tmpfs("/rootfs/run")}, ""},
	}
	for _, tc := range cases {
		ms := append([]DockerMount{tc.bind}, tc.others...)
		cover, ok := SocketMask(ms, tc.bind)
		if got := map[bool]string{true: cover.Target}[ok]; got != tc.masked {
			t.Errorf("%s: masked by %q, want %q", tc.name, got, tc.masked)
		}
	}
}

func TestMountsDockerSocketHonoursMasks(t *testing.T) {
	root := DockerMount{Type: "bind", Source: "/", Target: "/rootfs", ReadOnly: true}
	if !MountsDockerSocket([]DockerMount{root}) {
		t.Fatal("an unmasked bind of / exposes the socket")
	}
	masked := []DockerMount{root, {Type: "tmpfs", Target: "/rootfs/run"}}
	if MountsDockerSocket(masked) {
		t.Fatal("a tmpfs on /rootfs/run hides the socket")
	}
	masked = append(masked, DockerMount{Type: "bind", Source: "/var/run/docker.sock", Target: "/var/run/docker.sock"})
	if !MountsDockerSocket(masked) {
		t.Fatal("a direct socket bind exposes it whatever else is mounted")
	}
}

func TestMountsOfReadsHostConfigTmpfs(t *testing.T) {
	raw := `{"Id":"` + "abcdef0123456789" + `","Name":"/alloy",
	 "HostConfig":{"Binds":["/:/rootfs:ro,rslave"],"Tmpfs":{"/rootfs/run":"","/rootfs/etc/ssh":"ro,size=1m"}},
	 "Mounts":[{"Type":"bind","Source":"/","Destination":"/rootfs","RW":false},
	           {"Type":"tmpfs","Source":"","Destination":"/rootfs/home","RW":true}]}`
	in, _, err := dockerapi.ParseInspect([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	got := mountsOf(in)
	want := []DockerMount{
		{Type: "bind", Source: "/", Target: "/rootfs", ReadOnly: true},
		{Type: "tmpfs", Target: "/rootfs/home"},
		{Type: "tmpfs", Target: "/rootfs/etc/ssh", ReadOnly: true},
		{Type: "tmpfs", Target: "/rootfs/run"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("mount %d: got %+v, want %+v", i, got[i], want[i])
		}
	}
	if MountsDockerSocket(got) {
		t.Error("the tmpfs on /rootfs/run hides the socket")
	}
}
