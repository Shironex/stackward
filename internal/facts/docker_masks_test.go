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
		{"root, volume on run", root, []DockerMount{{Type: "volume", Source: "runvol", Target: "/rootfs/run"}}, "/rootfs/run"},
		{"root, plain bind on run", root, []DockerMount{{Type: "bind", Source: "/srv/empty", Target: "/rootfs/run"}}, "/rootfs/run"},
		{"root, socket folder bind on run", root, []DockerMount{{Type: "bind", Source: "/run", Target: "/rootfs/run"}}, ""},
		{"root, other type on run", root, []DockerMount{{Type: "other", Target: "/rootfs/run"}}, ""},
		{"root, tmpfs on a sibling", root, []DockerMount{tmpfs("/rootfs/root"), tmpfs("/rootfs/runner")}, ""},
		{"root, tmpfs only on var/run", root, []DockerMount{tmpfs("/rootfs/var/run")}, ""},
		{"root, tmpfs on run then socket bind under it", root, []DockerMount{tmpfs("/rootfs/run"), {Type: "bind", Source: "/run/docker.sock", Target: "/rootfs/run/docker.sock"}}, ""},
		{"root, tmpfs on run and something at the same depth", root, []DockerMount{tmpfs("/rootfs/run"), {Type: "other", Target: "/rootfs/run"}}, ""},
		{"root, tmpfs above the bind", root, []DockerMount{tmpfs("/")}, ""},
		{"root, relative cover", root, []DockerMount{tmpfs("rootfs/run")}, ""},
		{"relative bind target", DockerMount{Type: "bind", Source: "/", Target: "rootfs"}, []DockerMount{tmpfs("rootfs/run")}, ""},
		// Covering only the socket file leaves containerd.sock and the rest of /run in view.
		{"root, file bind over the socket", root, []DockerMount{{Type: "bind", Source: "/dev/null", Target: "/rootfs/run/docker.sock"}}, ""},
		{"root, tmpfs below run", root, []DockerMount{tmpfs("/rootfs/run/docker")}, ""},
		{"run folder, file bind over the socket", DockerMount{Type: "bind", Source: "/run", Target: "/hr", ReadOnly: true}, []DockerMount{{Type: "bind", Source: "/dev/null", Target: "/hr/docker.sock"}}, ""},
		{"var/run folder, file bind over the socket", DockerMount{Type: "bind", Source: "/var/run/", Target: "/h"}, []DockerMount{{Type: "bind", Source: "/dev/null", Target: "/h/docker.sock"}}, ""},
		{"run folder, volume over it all", DockerMount{Type: "bind", Source: "/run", Target: "/hr"}, []DockerMount{{Type: "volume", Source: "v", Target: "/hr/x"}}, ""},
		// Unclean destinations are not proven.
		{"root, cover with dot dot", root, []DockerMount{tmpfs("/rootfs/x/../run")}, ""},
		{"root, cover with dot", root, []DockerMount{tmpfs("/rootfs/./run")}, ""},
		{"root, cover with trailing slash", root, []DockerMount{tmpfs("/rootfs/run/")}, "/rootfs/run/"},
		{"root at a trailing slash, cover", DockerMount{Type: "bind", Source: "/", Target: "/rootfs/"}, []DockerMount{tmpfs("/rootfs/run")}, "/rootfs/run"},
		{"root, cover with two trailing slashes", root, []DockerMount{tmpfs("/rootfs/run//")}, ""},
		{"root, cover with doubled slash", root, []DockerMount{tmpfs("/rootfs//run")}, ""},
		{"root, clean cover beside an unclean mount", root, []DockerMount{tmpfs("/rootfs/run"), tmpfs("/rootfs/a/../run")}, ""},
		{"bind target with dot dot", DockerMount{Type: "bind", Source: "/", Target: "/x/../rootfs"}, []DockerMount{tmpfs("/rootfs/run")}, ""},
		// Covering bind sources must be proven host folders.
		{"root, relative bind source", root, []DockerMount{{Type: "bind", Source: "./empty", Target: "/rootfs/run"}}, ""},
		{"root, unclean bind source", root, []DockerMount{{Type: "bind", Source: "/srv/../run", Target: "/rootfs/run"}}, ""},
		{"root, proc bind source", root, []DockerMount{{Type: "bind", Source: "/proc/1/root/run", Target: "/rootfs/run"}}, ""},
		// A cover bind from part of /run shows sockets of its own.
		{"root, containerd folder on run", root, []DockerMount{{Type: "bind", Source: "/run/containerd", Target: "/rootfs/run"}}, ""},
		{"root, rootless user run on run", root, []DockerMount{{Type: "bind", Source: "/run/user/1000", Target: "/rootfs/run"}}, ""},
		{"root, var/run subfolder on run", root, []DockerMount{{Type: "bind", Source: "/var/run/docker", Target: "/rootfs/run"}}, ""},
		{"root, run subfolder bound back under the cover", root, []DockerMount{tmpfs("/rootfs/run"), {Type: "bind", Source: "/run/containerd", Target: "/rootfs/run/containerd"}}, ""},
		{"root, unrelated bind under the cover", root, []DockerMount{tmpfs("/rootfs/run"), {Type: "bind", Source: "/srv/cfg", Target: "/rootfs/run/cfg"}}, "/rootfs/run"},
		{"root, proc itself", root, []DockerMount{{Type: "bind", Source: "/proc", Target: "/rootfs/run"}}, ""},
		{"var folder, tmpfs on its run", DockerMount{Type: "bind", Source: "/var", Target: "/hv"}, []DockerMount{tmpfs("/hv/run")}, "/hv/run"},
		{"var folder, tmpfs elsewhere", DockerMount{Type: "bind", Source: "/var", Target: "/hv"}, []DockerMount{tmpfs("/hv/lib")}, ""},
		{"direct socket bind", DockerMount{Type: "bind", Source: "/var/run/docker.sock", Target: "/var/run/docker.sock"}, []DockerMount{tmpfs("/var/run")}, ""},
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
	for name, ms := range map[string][]DockerMount{
		"root with a file bind over the socket": {root, {Type: "bind", Source: "/dev/null", Target: "/rootfs/run/docker.sock"}},
		"run with a file bind over the socket":  {{Type: "bind", Source: "/run", Target: "/hr", ReadOnly: true}, {Type: "bind", Source: "/dev/null", Target: "/hr/docker.sock"}},
		"root with an unclean cover":            {root, {Type: "tmpfs", Target: "/rootfs/x/../run"}},
	} {
		if !MountsDockerSocket(ms) {
			t.Errorf("%s: the socket folder stays in view", name)
		}
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
