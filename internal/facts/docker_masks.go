package facts

import (
	"path"
	"strings"
)

// Docker mounts a container's mounts in order of destination depth, so a
// mount whose destination lies inside a bind's destination is mounted on
// top of that bind and hides what the bind shows there. A tmpfs mount on
// /rootfs/run over a bind of / at /rootfs means /rootfs/run/docker.sock is
// an empty tmpfs, not the host's socket.

// SocketMask returns the mount that hides the Docker socket inside the
// container when bind b holds the socket's folder, and false when the
// socket stays reachable through b or b does not hold it. Only a proven
// cover counts: a direct bind of the socket file is never masked, and an
// unknown mount type, a relative destination or a cover that itself holds
// the socket keeps it reachable.
//
// The host's /var/run is a symlink to /run, so the socket lives at
// /run/docker.sock: through a bind of / it shows at <target>/run/docker.sock,
// and the <target>/var/run symlink resolves inside the container, not on the
// host. A bind of /var holds only that symlink (or, on a host where /var/run
// is still a folder, the socket), so it is masked only by a cover of
// <target>/run.
func SocketMask(ms []DockerMount, b DockerMount) (DockerMount, bool) {
	if b.Type != "bind" {
		return DockerMount{}, false
	}
	var rel string
	switch path.Clean(b.Source) {
	case "/":
		rel = "run/docker.sock"
	case "/run", "/var/run":
		rel = "docker.sock"
	case "/var":
		rel = "run"
	default: // the socket file itself, or not a folder that holds it
		return DockerMount{}, false
	}
	return MaskOf(ms, b, rel, IsDockerSocketPath)
}

// MaskOf returns the mount that hides rel (a path relative to bind b's
// source) inside the container, and false when b still shows it. The
// cover is the deepest mount whose destination lies strictly inside b's
// destination and contains b's destination joined with rel. It hides rel
// only when it is a tmpfs, a volume, or a bind whose source exposed does
// not flag; when several mounts share that destination, every one must
// qualify.
func MaskOf(ms []DockerMount, b DockerMount, rel string, exposed func(source string) bool) (DockerMount, bool) {
	if !path.IsAbs(b.Target) {
		return DockerMount{}, false
	}
	root := path.Clean(b.Target)
	want := path.Join(root, rel)
	var covers []DockerMount
	depth := -1
	for _, m := range ms {
		if !path.IsAbs(m.Target) {
			continue
		}
		t := path.Clean(m.Target)
		if !strictlyInside(t, root) || !within(want, t) {
			continue
		}
		switch d := strings.Count(t, "/"); {
		case d > depth:
			covers, depth = []DockerMount{m}, d
		case d == depth:
			covers = append(covers, m)
		}
	}
	if len(covers) == 0 {
		return DockerMount{}, false
	}
	for _, m := range covers {
		if !hides(m, exposed) {
			return DockerMount{}, false
		}
	}
	return covers[0], true
}

// hides reports whether a covering mount shows something other than the
// host path it covers.
func hides(m DockerMount, exposed func(string) bool) bool {
	switch m.Type {
	case "tmpfs", "volume":
		return true
	case "bind":
		return m.Source != "" && !exposed(m.Source)
	}
	return false
}

// within reports whether p is dir or lies under it (both clean).
func within(p, dir string) bool {
	return p == dir || strings.HasPrefix(p, strings.TrimSuffix(dir, "/")+"/")
}

// strictlyInside reports whether p lies under dir and is not dir.
func strictlyInside(p, dir string) bool {
	return p != dir && within(p, dir)
}
