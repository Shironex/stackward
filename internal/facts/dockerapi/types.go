package dockerapi

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Paths the collector reads. All of them are GET only.
const (
	PathVersion    = "/version"
	PathInfo       = "/info"
	PathContainers = "/containers/json?all=1"
	PathNetworks   = "/networks"
)

// MaxContainers caps how many containers are inspected; the list is cut,
// never the run.
const MaxContainers = 500

// containerIDRE is a container id as the list gives it. Anything else is
// never put in a path.
var containerIDRE = regexp.MustCompile(`^[0-9a-f]{12,64}$`)

// InspectPath returns the inspect path for a container id, or an error when
// the id is not a plain hex id.
func InspectPath(id string) (string, error) {
	if !containerIDRE.MatchString(id) {
		return "", fmt.Errorf("%w: container id %q", ErrBadPath, id)
	}
	return "/containers/" + id + "/json", nil
}

// Version is the part of GET /version stackward keeps.
type Version struct {
	Version       string `json:"Version"`
	APIVersion    string `json:"ApiVersion"`
	MinAPIVersion string `json:"MinAPIVersion"`
	Os            string `json:"Os"`
	Arch          string `json:"Arch"`
}

// Info is the part of GET /info stackward keeps. Proxy settings (which can
// hold credentials) are stripped before decoding.
type Info struct {
	ServerVersion   string   `json:"ServerVersion"`
	LoggingDriver   string   `json:"LoggingDriver"`
	CgroupVersion   string   `json:"CgroupVersion"`
	SecurityOptions []string `json:"SecurityOptions"`
	Containers      int      `json:"Containers"`
}

// Network is one entry of GET /networks.
type Network struct {
	ID       string `json:"Id"`
	Name     string `json:"Name"`
	Driver   string `json:"Driver"`
	Scope    string `json:"Scope"`
	Internal bool   `json:"Internal"`
}

// Inspect is the part of GET /containers/{id}/json stackward keeps, after
// Strip removed the fields that can hold secrets.
type Inspect struct {
	ID    string `json:"Id"`
	Name  string `json:"Name"`
	State struct {
		Status  string `json:"Status"`
		Running bool   `json:"Running"`
	} `json:"State"`
	Config struct {
		User   string            `json:"User"`
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
	} `json:"Config"`
	HostConfig struct {
		Binds          []string `json:"Binds"`
		Privileged     bool     `json:"Privileged"`
		CapAdd         []string `json:"CapAdd"`
		NetworkMode    string   `json:"NetworkMode"`
		PidMode        string   `json:"PidMode"`
		IpcMode        string   `json:"IpcMode"`
		UsernsMode     string   `json:"UsernsMode"`
		SecurityOpt    []string `json:"SecurityOpt"`
		ReadonlyRootfs bool     `json:"ReadonlyRootfs"`
	} `json:"HostConfig"`
	Mounts []struct {
		Type        string `json:"Type"`
		Name        string `json:"Name"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
		RW          bool   `json:"RW"`
	} `json:"Mounts"`
	NetworkSettings struct {
		Networks map[string]json.RawMessage `json:"Networks"`
		Ports    map[string][]PortBinding   `json:"Ports"`
	} `json:"NetworkSettings"`
}

// PortBinding is one host binding of a container port.
type PortBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

// ParseVersion decodes GET /version.
func ParseVersion(b []byte) (Version, error) {
	var v Version
	if err := json.Unmarshal(b, &v); err != nil {
		return Version{}, fmt.Errorf("parse /version: %w", err)
	}
	return v, nil
}

// infoStrip lists /info fields that can hold credentials (a proxy URL with
// a user and password) or that stackward has no use for.
var infoStrip = []string{"HttpProxy", "HttpsProxy", "NoProxy", "RegistryConfig", "Labels"}

// ParseInfo decodes GET /info, dropping proxy settings first.
func ParseInfo(b []byte) (Info, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return Info{}, fmt.Errorf("parse /info: %w", err)
	}
	for _, k := range infoStrip {
		delete(m, k)
	}
	clean, err := json.Marshal(m)
	if err != nil {
		return Info{}, err
	}
	var i Info
	if err := json.Unmarshal(clean, &i); err != nil {
		return Info{}, fmt.Errorf("parse /info: %w", err)
	}
	return i, nil
}

// ParseContainerIDs decodes GET /containers/json and returns the ids of up
// to MaxContainers containers, plus whether the list was cut. Each entry's
// Command (the full command line) is dropped before decoding; entries whose
// id is not plain hex are skipped.
func ParseContainerIDs(b []byte) (ids []string, truncated bool, err error) {
	var list []map[string]json.RawMessage
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, false, fmt.Errorf("parse /containers/json: %w", err)
	}
	for _, entry := range list {
		delete(entry, "Command")
		var id string
		if err := json.Unmarshal(entry["Id"], &id); err != nil || !containerIDRE.MatchString(id) {
			continue
		}
		if len(ids) >= MaxContainers {
			return ids, true, nil
		}
		ids = append(ids, id)
	}
	return ids, false, nil
}

// ParseNetworks decodes GET /networks, sorted by name.
func ParseNetworks(b []byte) ([]Network, error) {
	var ns []Network
	if err := json.Unmarshal(b, &ns); err != nil {
		return nil, fmt.Errorf("parse /networks: %w", err)
	}
	sort.Slice(ns, func(i, j int) bool { return ns[i].Name < ns[j].Name })
	return ns, nil
}

// configStrip lists Config fields removed before decoding: the environment,
// the command, the entrypoint and the health check command can all hold
// passwords and tokens.
var configStrip = []string{"Env", "Cmd", "Entrypoint", "Healthcheck"}

// topStrip lists top level inspect fields removed before decoding: Args is
// the process argument list (tokens on a command line), Path its binary.
var topStrip = []string{"Args", "Path"}

// FlagKeys are the environment variable names stackward reads, by name
// only, from containers that mount the Docker socket: the permission flags
// of the common socket proxies. Only boolean shaped values are kept; any
// other value is dropped.
var FlagKeys = map[string]bool{
	"AUTH": true, "BUILD": true, "COMMIT": true, "CONFIGS": true, "CONTAINERS": true,
	"DISTRIBUTION": true, "EVENTS": true, "EXEC": true, "GRPC": true, "IMAGES": true,
	"INFO": true, "NETWORKS": true, "NODES": true, "PING": true, "PLUGINS": true,
	"POST": true, "SECRETS": true, "SERVICES": true, "SESSION": true, "SWARM": true,
	"SYSTEM": true, "TASKS": true, "VERSION": true, "VOLUMES": true, "DELETE": true,
	"ALLOW_START": true, "ALLOW_STOP": true, "ALLOW_RESTARTS": true,
}

var boolValues = map[string]bool{"0": true, "1": true, "true": true, "false": true, "yes": true, "no": true}

// Strip removes every field that can hold a secret from a raw inspect
// answer and returns the cleaned JSON, plus the socket proxy permission
// flags found in Config.Env (names from FlagKeys, boolean values only).
// Nothing else of the environment survives this function.
func Strip(raw []byte) (clean []byte, flags map[string]string, err error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, nil, fmt.Errorf("parse inspect: %w", err)
	}
	for _, k := range topStrip {
		delete(top, k)
	}
	if cfgRaw, ok := top["Config"]; ok && string(cfgRaw) != "null" {
		var cfg map[string]json.RawMessage
		if err := json.Unmarshal(cfgRaw, &cfg); err != nil {
			return nil, nil, fmt.Errorf("parse inspect Config: %w", err)
		}
		flags = envFlags(cfg["Env"])
		for _, k := range configStrip {
			delete(cfg, k)
		}
		if top["Config"], err = json.Marshal(cfg); err != nil {
			return nil, nil, err
		}
	}
	clean, err = json.Marshal(top)
	return clean, flags, err
}

// envFlags keeps only allowlisted names with boolean shaped values.
func envFlags(raw json.RawMessage) map[string]string {
	var env []string
	if len(raw) == 0 || json.Unmarshal(raw, &env) != nil {
		return nil
	}
	var out map[string]string
	for _, kv := range env {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || !FlagKeys[k] {
			continue
		}
		v = strings.ToLower(strings.TrimSpace(v))
		if !boolValues[v] {
			continue
		}
		if out == nil {
			out = map[string]string{}
		}
		out[k] = v
	}
	return out
}

// ParseInspect strips a raw inspect answer (see Strip) and decodes it.
func ParseInspect(raw []byte) (Inspect, map[string]string, error) {
	clean, flags, err := Strip(raw)
	if err != nil {
		return Inspect{}, nil, err
	}
	var in Inspect
	if err := json.Unmarshal(clean, &in); err != nil {
		return Inspect{}, nil, fmt.Errorf("parse inspect: %w", err)
	}
	return in, flags, nil
}
