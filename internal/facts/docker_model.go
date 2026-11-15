package facts

import (
	"net/netip"
	"strings"
)

// Docker is what the Docker Engine API answers over the Unix socket (GET
// only, with Config.Env, Cmd, Entrypoint, Healthcheck and Args stripped
// before parsing), plus the daemon's configuration files and its socket
// metadata (DKR group).
type Docker struct {
	// Installed is false when there is no socket, no dockerd binary and no
	// /etc/docker; the DKR checks then skip.
	Installed bool `json:"installed"`
	// SocketPath is the socket stackward used or looked for first.
	SocketPath string `json:"socket_path,omitempty"`
	// Socket is the socket's metadata; nil when it does not exist.
	Socket *DockerSocket `json:"socket,omitempty"`
	// API is how reading the Engine API went: "ok", "denied" (no
	// permission on the socket), "absent" (no socket) or "error".
	API string `json:"api"`
	// APIReason explains a non ok API in words a user can act on.
	APIReason string `json:"api_reason,omitempty"`

	Version *DockerVersion `json:"version,omitempty"`
	Info    *DockerInfo    `json:"info,omitempty"`
	// Daemon is what daemon.json and the systemd unit configure.
	Daemon *DockerDaemon `json:"daemon,omitempty"`
	// TCP and TCPRead are kept so facts files written by older builds
	// still load. The collector no longer fills them: DKR-002 reads the
	// Docker ports from the shared listener facts, and falls back to these
	// only when a saved facts file has no listeners.
	TCP     []DockerTCPListener `json:"tcp,omitempty"`
	TCPRead bool                `json:"tcp_read"`

	Containers []DockerContainer `json:"containers,omitempty"`
	// ContainersTruncated is true when more than dockerapi.MaxContainers
	// containers exist and the rest were not inspected.
	ContainersTruncated bool            `json:"containers_truncated,omitempty"`
	Networks            []DockerNetwork `json:"networks,omitempty"`
}

// DockerSocket is the metadata of the Docker socket. Contents are never read.
type DockerSocket struct {
	// Perm is the permission bits in octal ("0660").
	Perm          string `json:"perm"`
	UID           int    `json:"uid"`
	GID           int    `json:"gid"`
	Group         string `json:"group,omitempty"`
	WorldWritable bool   `json:"world_writable"`
}

// DockerVersion is the part of GET /version stackward keeps.
type DockerVersion struct {
	Version    string `json:"version"`
	APIVersion string `json:"api_version,omitempty"`
	Os         string `json:"os,omitempty"`
	Arch       string `json:"arch,omitempty"`
}

// DockerInfo is the part of GET /info stackward keeps.
type DockerInfo struct {
	LoggingDriver   string   `json:"logging_driver,omitempty"`
	CgroupVersion   string   `json:"cgroup_version,omitempty"`
	SecurityOptions []string `json:"security_options,omitempty"`
}

// DockerDaemon is the daemon configuration from /etc/docker/daemon.json and
// the effective ExecStart of the docker systemd unit.
type DockerDaemon struct {
	// ConfigFound is true when daemon.json exists and was read.
	ConfigFound bool `json:"config_found"`
	// ConfigError is set when daemon.json exists but could not be read or
	// parsed; settings below may then be incomplete.
	ConfigError string `json:"config_error,omitempty"`
	// Hosts lists every -H / "hosts" address, with where it came from.
	Hosts []DockerHost `json:"hosts,omitempty"`
	// TLSVerify is true when tlsverify is on in daemon.json or the unit.
	TLSVerify bool `json:"tlsverify,omitempty"`
	// LogDriver, LogMaxSize and LogMaxFile come from daemon.json.
	LogDriver  string `json:"log_driver,omitempty"`
	LogMaxSize string `json:"log_max_size,omitempty"`
	LogMaxFile string `json:"log_max_file,omitempty"`
	// IPTables is false when Docker is told not to manage the firewall;
	// nil means the default (true).
	IPTables *bool `json:"iptables,omitempty"`
	// NoNewPrivileges is the daemon wide default for new containers.
	NoNewPrivileges bool `json:"no_new_privileges,omitempty"`
	// UnitFiles lists the systemd unit and drop-in files read.
	UnitFiles []string `json:"unit_files,omitempty"`
	// Content is daemon.json as read, so `stackward plan` can merge a
	// change into it without dropping keys. Nil when the file is absent,
	// unreadable, larger than MaxDaemonJSONBytes, or the facts were saved
	// by an older build; an empty file is an empty string. It passes
	// through the same redaction as every other dumped value.
	Content *string `json:"content,omitempty"`
}

// MaxDaemonJSONBytes caps the daemon.json content kept in the facts.
const MaxDaemonJSONBytes = 64 << 10

// DockerHost is one address the daemon listens on.
type DockerHost struct {
	Addr string `json:"addr"`
	// Source is "daemon.json" or the unit file path.
	Source string `json:"source"`
}

// DockerTCPListener is a socket listening on a Docker port (older facts
// files only; see Docker.TCP).
type DockerTCPListener struct {
	Port int `json:"port"`
	// Bind is "loopback", "any" or "specific".
	Bind string `json:"bind"`
}

// DockerContainer is one container, from its inspect answer.
type DockerContainer struct {
	ID      string `json:"id"` // short (12 hex digits)
	Name    string `json:"name"`
	Project string `json:"project,omitempty"`
	Service string `json:"service,omitempty"`
	Image   string `json:"image"`
	Running bool   `json:"running"`
	// User is Config.User: "" means root.
	User        string   `json:"user"`
	Privileged  bool     `json:"privileged,omitempty"`
	CapAdd      []string `json:"cap_add,omitempty"`
	NetworkMode string   `json:"network_mode,omitempty"`
	PidMode     string   `json:"pid_mode,omitempty"`
	IpcMode     string   `json:"ipc_mode,omitempty"`
	UsernsMode  string   `json:"userns_mode,omitempty"`
	SecurityOpt []string `json:"security_opt,omitempty"`
	// Mounts joins inspect Mounts and HostConfig.Binds, deduplicated.
	Mounts []DockerMount `json:"mounts,omitempty"`
	// Networks are the networks the container is attached to, sorted.
	Networks []string `json:"networks,omitempty"`
	// Ports lists every published host binding.
	Ports []DockerPort `json:"ports,omitempty"`
	// ProxyRouted is true when Traefik router or Caddy site labels route
	// traffic to this container. Router rules themselves are not kept.
	ProxyRouted bool `json:"proxy_routed,omitempty"`
	// Labels keeps only grouping labels (compose, swarm, Coolify).
	Labels map[string]string `json:"labels,omitempty"`
	// Flags holds socket proxy permission flags (names and boolean values
	// only) read from the environment of a container that mounts the
	// Docker socket. Nothing else of the environment is ever kept.
	Flags map[string]string `json:"flags,omitempty"`
}

// DockerMount is one mount of a container.
type DockerMount struct {
	// Type is "bind", "volume", "tmpfs" or "other".
	Type string `json:"type"`
	// Source is the host path of a bind, or the volume name.
	Source   string `json:"source,omitempty"`
	Target   string `json:"target,omitempty"`
	ReadOnly bool   `json:"read_only,omitempty"`
}

// DockerPort is one published binding of a container port.
type DockerPort struct {
	ContainerPort int    `json:"container_port"`
	Proto         string `json:"proto"`
	HostIP        string `json:"host_ip"`
	HostPort      int    `json:"host_port"`
}

// Publishing lists the containers that publish proto/port on a host
// address matching addr, the bind address of a listening socket. An
// empty, 0.0.0.0 or :: host address matches any wildcard bind, of either
// family, since Docker binds both for it. Nothing matches when the Docker
// API was not read.
func (d *Docker) Publishing(proto, addr string, port int) []DockerContainer {
	if d == nil || d.API != "ok" {
		return nil
	}
	var out []DockerContainer
	for _, c := range d.Containers {
		for _, p := range c.Ports {
			pp := p.Proto
			if pp == "" {
				pp = "tcp"
			}
			if p.HostPort == port && pp == proto && sameHostAddr(p.HostIP, addr) {
				out = append(out, c)
				break
			}
		}
	}
	return out
}

// sameHostAddr reports whether a published host address and a socket's
// bind address name the same binding.
func sameHostAddr(published, bind string) bool {
	wild := func(a string) bool { return a == "" || a == "0.0.0.0" || a == "::" || a == "*" }
	published = strings.Trim(strings.TrimSpace(published), "[]")
	bind = strings.Trim(strings.TrimSpace(bind), "[]")
	if wild(published) || wild(bind) {
		return wild(published) && wild(bind)
	}
	a, errA := netip.ParseAddr(published)
	b, errB := netip.ParseAddr(bind)
	if errA != nil || errB != nil {
		return published == bind
	}
	return a.Unmap() == b.Unmap()
}

// DockerNetwork is one network from GET /networks.
type DockerNetwork struct {
	Name     string `json:"name"`
	Driver   string `json:"driver,omitempty"`
	Scope    string `json:"scope,omitempty"`
	Internal bool   `json:"internal,omitempty"`
}
