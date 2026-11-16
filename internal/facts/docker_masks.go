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
// cover counts, and only over the whole socket folder: a bind of /run or
// /var/run (or of the socket file itself) is never masked, since covering
// docker.sock alone leaves containerd.sock and the rest of /run in view.
//
// The host's /var/run is a symlink to /run, so the socket lives in /run:
// through a bind of / it shows under <target>/run, and the <target>/var/run
// symlink resolves inside the container, not on the host. A bind of /var
// holds only that symlink (or, on a host where /var/run is still a folder,
// the socket folder itself). Either way the cover must sit exactly on
// <target>/run, the folder, never deeper.
func SocketMask(ms []DockerMount, b DockerMount) (DockerMount, bool) {
	if b.Type != "bind" {
		return DockerMount{}, false
	}
	switch path.Clean(b.Source) {
	case "/", "/var":
		return MaskOf(ms, b, "run", IsDockerSocketPath)
	}
	return DockerMount{}, false
}

// MaskOf returns the mount that hides rel (a clean path relative to bind
// b's source) inside the container, and false when b still shows it. The
// cover is the deepest mount whose destination lies strictly inside b's
// destination and contains b's destination joined with rel. It hides rel
// only when it is a tmpfs, a volume, or a bind whose source is a proven
// host folder that exposed does not flag; when several mounts share that
// destination, every one must qualify. Any destination among the mounts
// that is relative or not already clean (a "." or ".." element, a doubled
// or trailing slash) leaves the layout unproven, and nothing is masked.
func MaskOf(ms []DockerMount, b DockerMount, rel string, exposed func(source string) bool) (DockerMount, bool) {
	for _, m := range ms {
		if !isCleanAbs(m.Target) {
			return DockerMount{}, false
		}
	}
	if !isCleanAbs(b.Target) {
		return DockerMount{}, false
	}
	root := b.Target
	want := path.Join(root, rel)
	var covers []DockerMount
	depth := -1
	for _, m := range ms {
		t := m.Target
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

// isCleanAbs reports whether p is an absolute path already in clean form.
func isCleanAbs(p string) bool { return path.IsAbs(p) && path.Clean(p) == p }

// hides reports whether a covering mount shows something other than the
// host path it covers.
func hides(m DockerMount, exposed func(string) bool) bool {
	switch m.Type {
	case "tmpfs", "volume":
		return true
	case "bind":
		// A relative or unclean source, or one under /proc (whose links
		// lead anywhere), is not a proven folder.
		return isCleanAbs(m.Source) && !within(m.Source, "/proc") && !exposed(m.Source)
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
