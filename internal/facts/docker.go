package facts

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/Shironex/stackward/internal/facts/dockerapi"
)

// Paths the docker collector reads. Socket candidates are tried in order;
// the rootless socket is /run/user/<uid>/docker.sock.
var (
	dockerSockets    = []string{"/var/run/docker.sock", "/run/docker.sock"}
	dockerDaemonJSON = "/etc/docker/daemon.json"
	dockerUnitFiles  = []string{"/etc/systemd/system/docker.service", "/run/systemd/system/docker.service", "/usr/lib/systemd/system/docker.service", "/lib/systemd/system/docker.service"}
	dockerDropInDirs = []string{"/etc/systemd/system/docker.service.d", "/run/systemd/system/docker.service.d", "/usr/lib/systemd/system/docker.service.d"}
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

// Collect reads socket metadata and daemon config files through sys, then the Engine API (GET only) through the socket. Without
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
