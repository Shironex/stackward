package facts

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/Shironex/stackward/internal/facts/dockerapi"
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
	// TCP lists sockets listening on the Docker ports 2375 and 2376, from
	// /proc/net/tcp and tcp6. Nil with TCPRead false means not read.
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
}

// DockerHost is one address the daemon listens on.
type DockerHost struct {
	Addr string `json:"addr"`
	// Source is "daemon.json" or the unit file path.
	Source string `json:"source"`
}

// DockerTCPListener is a socket listening on a Docker port.
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

// DockerNetwork is one network from GET /networks.
type DockerNetwork struct {
	Name     string `json:"name"`
	Driver   string `json:"driver,omitempty"`
	Scope    string `json:"scope,omitempty"`
	Internal bool   `json:"internal,omitempty"`
}

// Paths the docker collector reads. Socket candidates are tried in order;
// the rootless socket is /run/user/<uid>/docker.sock.
var (
	dockerSockets      = []string{"/var/run/docker.sock", "/run/docker.sock"}
	dockerDaemonJSON   = "/etc/docker/daemon.json"
	dockerUnitFiles    = []string{"/etc/systemd/system/docker.service", "/run/systemd/system/docker.service", "/usr/lib/systemd/system/docker.service", "/lib/systemd/system/docker.service"}
	dockerDropInDirs   = []string{"/etc/systemd/system/docker.service.d", "/run/systemd/system/docker.service.d", "/usr/lib/systemd/system/docker.service.d"}
	dockerProcNetFiles = []string{"/proc/net/tcp", "/proc/net/tcp6"}
	dockerTCPPorts     = map[int]bool{2375: true, 2376: true}
)

// keptLabels are the container labels stackward keeps: the ones that group
// containers into projects. Everything else (router rules, basic auth
// hashes, arbitrary metadata) is dropped at collection.
var keptLabels = map[string]bool{
	"com.docker.compose.project":    true,
	"com.docker.compose.service":    true,
	"com.docker.stack.namespace":    true,
	"com.docker.swarm.service.name": true,
	"coolify.managed":               true,
	"coolify.projectName":           true,
	"coolify.environmentName":       true,
	"coolify.resourceName":          true,
	"coolify.serviceName":           true,
	"coolify.name":                  true,
	"coolify.type":                  true,
	"coolify.proxy":                 true,
	"traefik.enable":                true,
}

// dockerAPI is what the collector needs from the Engine API client.
type dockerAPI interface {
	Get(ctx context.Context, path string) ([]byte, error)
	Close()
}

type dockerCollector struct {
	// open returns a client for a socket path. Tests swap it for a fake
	// that serves recorded answers.
	open func(socket string) dockerAPI
}

func init() {
	Register(dockerCollector{open: func(socket string) dockerAPI {
		return dockerapi.NewUnix(socket, dockerapi.Options{})
	}})
}

func (dockerCollector) Name() string    { return "docker" }
func (dockerCollector) NeedsRoot() bool { return false }

// Collect reads socket metadata, daemon config files and /proc/net/tcp
// through sys, then the Engine API (GET only) through the socket. Without
// access to the socket, API is "denied" and checks report unknown.
func (c dockerCollector) Collect(ctx context.Context, sys System, out *Facts) error {
	d := &Docker{}
	var errs []error

	candidates := append([]string(nil), dockerSockets...)
	if id := sys.Identity(); id.EUID > 0 {
		candidates = append(candidates, fmt.Sprintf("/run/user/%d/docker.sock", id.EUID))
	}
	d.SocketPath = candidates[0]
	for _, p := range candidates {
		m, err := sys.Meta(p)
		if err != nil {
			continue
		}
		d.SocketPath = p
		d.Socket = socketMeta(sys, m)
		break
	}

	d.Daemon = readDaemonConfig(sys)
	d.TCP, d.TCPRead = readDockerTCP(sys)

	_, lookErr := sys.LookPath("dockerd")
	_, etcErr := sys.ReadDir("/etc/docker")
	d.Installed = d.Socket != nil || lookErr == nil || etcErr == nil || d.Daemon.ConfigFound || len(d.Daemon.UnitFiles) > 0

	switch {
	case !d.Installed:
		d.API = "absent"
		d.APIReason = "Docker is not installed (no socket, no dockerd, no /etc/docker)"
	case d.Socket == nil:
		d.API = "absent"
		d.APIReason = fmt.Sprintf("no Docker socket at %s (is the daemon running?)", strings.Join(candidates, " or "))
	default:
		if err := c.readAPI(ctx, d); err != nil {
			errs = append(errs, err)
		}
	}
	out.Docker = d
	return errors.Join(errs...)
}

func socketMeta(sys System, m FileMeta) *DockerSocket {
	s := &DockerSocket{
		Perm:          fmt.Sprintf("%04o", m.Mode.Perm()),
		UID:           m.UID,
		GID:           m.GID,
		WorldWritable: m.Mode.Perm()&0o002 != 0,
	}
	if b, err := sys.ReadFile("/etc/group"); err == nil && m.GID >= 0 {
		s.Group = groupName(b, m.GID)
	}
	return s
}

func groupName(etcGroup []byte, gid int) string {
	sc := bufio.NewScanner(bytes.NewReader(etcGroup))
	for sc.Scan() {
		f := strings.Split(sc.Text(), ":")
		if len(f) >= 3 && f[2] == strconv.Itoa(gid) {
			return f[0]
		}
	}
	return ""
}

// readAPI fills Version, Info, Containers and Networks. A refused socket
// sets API "denied" and returns no error: that is a finding, not a fault.
func (c dockerCollector) readAPI(ctx context.Context, d *Docker) error {
	api := c.open(d.SocketPath)
	defer api.Close()

	b, err := api.Get(ctx, dockerapi.PathVersion)
	if err != nil {
		d.API, d.APIReason = classifyAPIError(d.SocketPath, err)
		if d.API == "error" {
			return fmt.Errorf("docker %s: %w", dockerapi.PathVersion, err)
		}
		return nil
	}
	d.API = "ok"
	var errs []error
	if v, err := dockerapi.ParseVersion(b); err == nil {
		d.Version = &DockerVersion{Version: v.Version, APIVersion: v.APIVersion, Os: v.Os, Arch: v.Arch}
	} else {
		errs = append(errs, err)
	}

	if b, err := api.Get(ctx, dockerapi.PathInfo); err != nil {
		errs = append(errs, fmt.Errorf("docker %s: %w", dockerapi.PathInfo, err))
	} else if i, err := dockerapi.ParseInfo(b); err != nil {
		errs = append(errs, err)
	} else {
		d.Info = &DockerInfo{LoggingDriver: i.LoggingDriver, CgroupVersion: i.CgroupVersion, SecurityOptions: i.SecurityOptions}
	}

	if b, err := api.Get(ctx, dockerapi.PathNetworks); err != nil {
		errs = append(errs, fmt.Errorf("docker %s: %w", dockerapi.PathNetworks, err))
	} else if ns, err := dockerapi.ParseNetworks(b); err != nil {
		errs = append(errs, err)
	} else {
		for _, n := range ns {
			d.Networks = append(d.Networks, DockerNetwork{Name: n.Name, Driver: n.Driver, Scope: n.Scope, Internal: n.Internal})
		}
	}

	b, err = api.Get(ctx, dockerapi.PathContainers)
	if err != nil {
		errs = append(errs, fmt.Errorf("docker containers: %w", err))
		d.API, d.APIReason = "error", "could not list containers: "+err.Error()
		return errors.Join(errs...)
	}
	ids, cut, err := dockerapi.ParseContainerIDs(b)
	if err != nil {
		errs = append(errs, err)
		d.API, d.APIReason = "error", "could not parse the container list"
		return errors.Join(errs...)
	}
	d.ContainersTruncated = cut
	d.Containers = []DockerContainer{}
	for _, id := range ids {
		if ctx.Err() != nil {
			errs = append(errs, ctx.Err())
			break
		}
		p, err := dockerapi.InspectPath(id)
		if err != nil {
			continue
		}
		raw, err := api.Get(ctx, p)
		var se *dockerapi.StatusError
		if errors.As(err, &se) && se.Code == 404 {
			continue // gone between the list and the inspect
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("docker inspect %s: %w", id[:12], err))
			continue
		}
		in, flags, err := dockerapi.ParseInspect(raw)
		if err != nil {
			errs = append(errs, fmt.Errorf("docker inspect %s: %w", id[:12], err))
			continue
		}
		d.Containers = append(d.Containers, containerFacts(in, flags))
	}
	sort.Slice(d.Containers, func(i, j int) bool { return d.Containers[i].Name < d.Containers[j].Name })
	return errors.Join(errs...)
}

func classifyAPIError(socket string, err error) (api, reason string) {
	switch {
	case errors.Is(err, fs.ErrPermission):
		return "denied", fmt.Sprintf("cannot open %s: permission denied (run with sudo, or as a member of the docker group)", socket)
	case errors.Is(err, fs.ErrNotExist):
		return "absent", fmt.Sprintf("no Docker socket at %s", socket)
	case errors.Is(err, syscall.ECONNREFUSED):
		return "absent", fmt.Sprintf("%s refused the connection (is the daemon running?)", socket)
	}
	var se *dockerapi.StatusError
	if errors.As(err, &se) && (se.Code == 401 || se.Code == 403) {
		return "denied", fmt.Sprintf("the Docker API at %s refused GET %s (%d)", socket, se.Path, se.Code)
	}
	return "error", fmt.Sprintf("could not read the Docker API at %s: %v", socket, err)
}

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
	return out
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
	for _, o := range strings.Split(mode, ",") {
		if o == "ro" {
			m.ReadOnly = true
		}
	}
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
// read only bind.
func MountsDockerSocket(ms []DockerMount) bool {
	for _, m := range ms {
		if m.Type == "bind" && IsDockerSocketPath(m.Source) {
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

// daemonJSON is the part of daemon.json stackward reads.
type daemonJSON struct {
	Hosts           []string          `json:"hosts"`
	TLSVerify       *bool             `json:"tlsverify"`
	LogDriver       string            `json:"log-driver"`
	LogOpts         map[string]string `json:"log-opts"`
	IPTables        *bool             `json:"iptables"`
	NoNewPrivileges *bool             `json:"no-new-privileges"`
}

func readDaemonConfig(sys System) *DockerDaemon {
	dd := &DockerDaemon{}
	b, err := sys.ReadFile(dockerDaemonJSON)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		dd.ConfigError = fmt.Sprintf("%s: %v", dockerDaemonJSON, err)
	default:
		var cfg daemonJSON
		if len(bytes.TrimSpace(b)) == 0 {
			dd.ConfigFound = true
			break
		}
		if err := json.Unmarshal(b, &cfg); err != nil {
			dd.ConfigError = fmt.Sprintf("%s: invalid JSON: %v", dockerDaemonJSON, err)
			break
		}
		dd.ConfigFound = true
		for _, h := range cfg.Hosts {
			dd.Hosts = append(dd.Hosts, DockerHost{Addr: h, Source: "daemon.json"})
		}
		dd.TLSVerify = cfg.TLSVerify != nil && *cfg.TLSVerify
		dd.LogDriver = cfg.LogDriver
		dd.LogMaxSize = cfg.LogOpts["max-size"]
		dd.LogMaxFile = cfg.LogOpts["max-file"]
		dd.IPTables = cfg.IPTables
		dd.NoNewPrivileges = cfg.NoNewPrivileges != nil && *cfg.NoNewPrivileges
	}
	readUnitFlags(sys, dd)
	return dd
}

// readUnitFlags applies the effective ExecStart of docker.service: the
// unit file systemd would load, then drop-ins by name; an empty ExecStart=
// resets the list, so the last one after a reset wins.
func readUnitFlags(sys System, dd *DockerDaemon) {
	var files []string
	for _, p := range dockerUnitFiles {
		if _, err := sys.ReadFile(p); err == nil {
			files = append(files, p)
			break
		}
	}
	dropIns := map[string]string{} // base name -> path, first dir wins
	for _, dir := range dockerDropInDirs {
		entries, err := sys.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".conf") {
				continue
			}
			if _, taken := dropIns[e.Name()]; !taken {
				dropIns[e.Name()] = path.Join(dir, e.Name())
			}
		}
	}
	names := make([]string, 0, len(dropIns))
	for n := range dropIns {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		files = append(files, dropIns[n])
	}

	var exec, execFrom string
	for _, f := range files {
		b, err := sys.ReadFile(f)
		if err != nil {
			continue
		}
		dd.UnitFiles = append(dd.UnitFiles, f)
		for _, line := range unitLines(b) {
			k, v, ok := strings.Cut(line, "=")
			if !ok || strings.TrimSpace(k) != "ExecStart" {
				continue
			}
			exec, execFrom = strings.TrimSpace(v), f
		}
	}
	if exec == "" {
		return
	}
	args := strings.Fields(exec)
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-H" || a == "--host":
			if i+1 < len(args) {
				dd.Hosts = append(dd.Hosts, DockerHost{Addr: args[i+1], Source: execFrom})
				i++
			}
		case strings.HasPrefix(a, "-H="), strings.HasPrefix(a, "--host="):
			_, v, _ := strings.Cut(a, "=")
			dd.Hosts = append(dd.Hosts, DockerHost{Addr: v, Source: execFrom})
		case strings.HasPrefix(a, "-H") && len(a) > 2:
			dd.Hosts = append(dd.Hosts, DockerHost{Addr: a[2:], Source: execFrom})
		case a == "--tlsverify" || a == "--tlsverify=true":
			dd.TLSVerify = true
		case a == "--iptables=false":
			f := false
			dd.IPTables = &f
		case a == "--no-new-privileges" || a == "--no-new-privileges=true":
			dd.NoNewPrivileges = true
		}
	}
}

// unitLines joins backslash continued lines and drops comments.
func unitLines(b []byte) []string {
	var out []string
	var cur strings.Builder
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if cur.Len() == 0 && (strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";")) {
			continue
		}
		if strings.HasSuffix(line, "\\") {
			cur.WriteString(strings.TrimSuffix(line, "\\"))
			cur.WriteString(" ")
			continue
		}
		cur.WriteString(line)
		out = append(out, cur.String())
		cur.Reset()
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// readDockerTCP lists LISTEN sockets on the Docker ports. ok is false when
// neither file could be read.
func readDockerTCP(sys System) (ls []DockerTCPListener, ok bool) {
	seen := map[DockerTCPListener]bool{}
	for _, f := range dockerProcNetFiles {
		b, err := sys.ReadFile(f)
		if err != nil {
			continue
		}
		ok = true
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 4 || fields[3] != "0A" { // 0A is LISTEN
				continue
			}
			addr, portHex, found := strings.Cut(fields[1], ":")
			if !found {
				continue
			}
			port, err := strconv.ParseUint(portHex, 16, 16)
			if err != nil || !dockerTCPPorts[int(port)] {
				continue
			}
			l := DockerTCPListener{Port: int(port), Bind: procNetBind(addr)}
			if !seen[l] {
				seen[l] = true
				ls = append(ls, l)
			}
		}
	}
	sort.Slice(ls, func(i, j int) bool {
		if ls[i].Port != ls[j].Port {
			return ls[i].Port < ls[j].Port
		}
		return ls[i].Bind < ls[j].Bind
	})
	return ls, ok
}

// procNetBind classifies a hex address from /proc/net/tcp*: the kernel
// prints each 32 bit word in host (little endian) order.
func procNetBind(hex string) string {
	switch {
	case strings.Trim(hex, "0") == "":
		return "any"
	case len(hex) == 8 && strings.HasSuffix(hex, "7F"):
		return "loopback"
	case len(hex) == 32 && hex == "00000000000000000000000001000000":
		return "loopback"
	case len(hex) == 32 && strings.HasPrefix(hex, "0000000000000000FFFF0000") && strings.HasSuffix(hex, "7F"):
		return "loopback"
	}
	return "specific"
}
