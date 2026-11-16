package facts

import (
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/Shironex/stackward/internal/facts/dockerapi"
)

// containerFacts turns a stripped inspect answer into DockerContainer.
func containerFacts(in dockerapi.Inspect, flags map[string]string) DockerContainer {
	name := strings.TrimLeft(in.Name, "/")
	if name == "" && len(in.ID) >= 12 {
		name = in.ID[:12]
	}
	c := DockerContainer{
		Name:        name,
		Image:       in.Config.Image,
		Running:     in.State.Running,
		User:        in.Config.User,
		Privileged:  in.HostConfig.Privileged,
		CapAdd:      in.HostConfig.CapAdd,
		NetworkMode: in.HostConfig.NetworkMode,
		PidMode:     in.HostConfig.PidMode,
		IpcMode:     in.HostConfig.IpcMode,
		UsernsMode:  in.HostConfig.UsernsMode,
		SecurityOpt: in.HostConfig.SecurityOpt,
	}
	if len(in.ID) >= 12 {
		c.ID = in.ID[:12]
	}
	labels := in.Config.Labels
	for k, v := range labels {
		if keptLabels[k] {
			if c.Labels == nil {
				c.Labels = map[string]string{}
			}
			c.Labels[k] = v
		}
	}
	c.ProxyRouted = proxyRouted(labels)
	c.Project, c.Service = projectOf(labels, name)
	c.Mounts = mountsOf(in)
	for n := range in.NetworkSettings.Networks {
		c.Networks = append(c.Networks, n)
	}
	sort.Strings(c.Networks)
	c.Ports = portsOf(in.NetworkSettings.Ports)
	if MountsDockerSocket(c.Mounts) {
		c.Flags = flags
	}
	return c
}

// projectOf groups a container: the Coolify project, then the compose
// project, then the swarm stack. Plain containers have no project.
func projectOf(labels map[string]string, name string) (project, service string) {
	for _, k := range []string{"coolify.projectName", "com.docker.compose.project", "com.docker.stack.namespace"} {
		if v := strings.TrimSpace(labels[k]); v != "" {
			project = v
			break
		}
	}
	for _, k := range []string{"com.docker.compose.service", "coolify.serviceName", "com.docker.swarm.service.name"} {
		if v := strings.TrimSpace(labels[k]); v != "" {
			service = v
			break
		}
	}
	if project != "" && service == "" {
		service = name
	}
	return project, service
}

// proxyRouted reports Traefik http router rules or Caddy site labels.
func proxyRouted(labels map[string]string) bool {
	if strings.EqualFold(strings.TrimSpace(labels["traefik.enable"]), "false") {
		return false
	}
	for k := range labels {
		if strings.HasPrefix(k, "traefik.http.routers.") && strings.HasSuffix(k, ".rule") {
			return true
		}
		if k == "caddy" || strings.HasPrefix(k, "caddy_") && isDigits(strings.TrimPrefix(k, "caddy_")) {
			return true
		}
	}
	return false
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func mountsOf(in dockerapi.Inspect) []DockerMount {
	var out []DockerMount
	seen := map[string]bool{}
	add := func(m DockerMount) {
		key := m.Type + "|" + m.Source + "|" + m.Target
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, m)
	}
	for _, m := range in.Mounts {
		t := m.Type
		if t != "bind" && t != "volume" && t != "tmpfs" {
			t = "other"
		}
		src := m.Source
		if t == "volume" && m.Name != "" {
			src = m.Name // the folder under /var/lib/docker says less than the name
		}
		add(DockerMount{Type: t, Source: src, Target: m.Destination, ReadOnly: !m.RW})
	}
	for _, b := range in.HostConfig.Binds {
		add(ParseVolumeSpec(b))
	}
	targets := make([]string, 0, len(in.HostConfig.Tmpfs))
	for t := range in.HostConfig.Tmpfs {
		targets = append(targets, t)
	}
	sort.Strings(targets)
	for _, t := range targets {
		add(DockerMount{Type: "tmpfs", Target: t, ReadOnly: hasOption(in.HostConfig.Tmpfs[t], "ro")})
	}
	return out
}

// hasOption reports whether a comma separated mount option list holds opt.
func hasOption(opts, opt string) bool {
	for _, o := range strings.Split(opts, ",") {
		if strings.TrimSpace(o) == opt {
			return true
		}
	}
	return false
}

// ParseVolumeSpec reads the short mount form SRC:DST[:mode] (compose
// volumes and docker run -v). One part is an anonymous volume; a source
// that starts like a path is a bind; mode "ro" in the comma list makes it
// read only.
func ParseVolumeSpec(spec string) DockerMount {
	parts := strings.Split(strings.TrimSpace(spec), ":")
	if len(parts) == 1 {
		return DockerMount{Type: "volume", Target: parts[0]}
	}
	src, dst, mode := parts[0], parts[1], ""
	if len(parts) > 2 {
		mode = parts[2]
	}
	m := DockerMount{Source: src, Target: dst}
	switch {
	case strings.HasPrefix(src, "/") || strings.HasPrefix(src, ".") || strings.HasPrefix(src, "~"):
		m.Type = "bind"
	case strings.Contains(src, "$"):
		m.Type = "other"
	default:
		m.Type = "volume"
	}
	m.ReadOnly = hasOption(mode, "ro")
	return m
}

// dockerSocketPaths are host paths whose mount hands a container the Docker
// daemon: the socket itself or a directory that holds it.
var dockerSocketPaths = map[string]bool{
	"/var/run/docker.sock": true,
	"/run/docker.sock":     true,
	"/var/run":             true,
	"/run":                 true,
	"/var":                 true,
	"/":                    true,
}

// IsDockerSocketPath reports whether a host path is the Docker socket or a
// directory that contains it.
func IsDockerSocketPath(p string) bool {
	if p == "" {
		return false
	}
	return dockerSocketPaths[path.Clean(p)]
}

// MountsDockerSocket reports whether any bind mount exposes the Docker
// socket. Read only mounts count too: the socket accepts writes through a
// read only bind. A bind of a folder that holds the socket does not count
// when another mount provably hides the socket inside the container (see
// SocketMask).
func MountsDockerSocket(ms []DockerMount) bool {
	for _, m := range ms {
		if m.Type != "bind" || !IsDockerSocketPath(m.Source) {
			continue
		}
		if _, masked := SocketMask(ms, m); !masked {
			return true
		}
	}
	return false
}

func portsOf(ports map[string][]dockerapi.PortBinding) []DockerPort {
	var out []DockerPort
	for key, binds := range ports {
		num, proto, _ := strings.Cut(key, "/")
		cp, err := strconv.Atoi(num)
		if err != nil {
			continue
		}
		if proto == "" {
			proto = "tcp"
		}
		for _, b := range binds {
			hp, err := strconv.Atoi(b.HostPort)
			if err != nil {
				continue
			}
			out = append(out, DockerPort{ContainerPort: cp, Proto: proto, HostIP: b.HostIP, HostPort: hp})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.HostPort != b.HostPort {
			return a.HostPort < b.HostPort
		}
		if a.Proto != b.Proto {
			return a.Proto < b.Proto
		}
		return a.HostIP < b.HostIP
	})
	return out
}
