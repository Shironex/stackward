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
	"time"
)

// OS is the distribution, from os-release.
type OS struct {
	ID              string   `json:"id"`                // "ubuntu", "debian"
	IDLike          []string `json:"id_like,omitempty"` // "debian"
	VersionID       string   `json:"version_id,omitempty"`
	VersionCodename string   `json:"version_codename,omitempty"`
	PrettyName      string   `json:"pretty_name,omitempty"`
}

// Family returns "debian" for Debian and its derivatives, else the ID.
func (o *OS) Family() string {
	if o == nil {
		return ""
	}
	if o.ID == "debian" {
		return "debian"
	}
	for _, like := range o.IDLike {
		if like == "debian" || like == "ubuntu" {
			return "debian"
		}
	}
	return o.ID
}

// Kernel is the running kernel and the kernels installed on disk.
type Kernel struct {
	// Release is the running kernel, from /proc/sys/kernel/osrelease.
	Release string `json:"release"`
	// Installed lists kernel versions found as /boot/vmlinuz-<version>,
	// sorted. Nil means the list could not be read (common in containers).
	Installed []string `json:"installed,omitempty"`
}

// Reboot is the Debian family "reboot required" marker.
type Reboot struct {
	// Required is true when /var/run/reboot-required exists.
	Required bool `json:"required"`
	// Since is the marker's modification time, when Required.
	Since time.Time `json:"since,omitzero"`
	// Packages lists /var/run/reboot-required.pkgs entries.
	Packages []string `json:"packages,omitempty"`
}

// Paths the os collector reads.
const (
	osReleasePath      = "/etc/os-release"
	osReleaseFallback  = "/usr/lib/os-release"
	kernelReleasePath  = "/proc/sys/kernel/osrelease"
	bootDir            = "/boot"
	rebootRequiredPath = "/var/run/reboot-required"
	rebootPkgsPath     = "/var/run/reboot-required.pkgs"
)

type osCollector struct{}

func init() { Register(osCollector{}) }

func (osCollector) Name() string    { return "os" }
func (osCollector) NeedsRoot() bool { return false }

func (osCollector) Collect(_ context.Context, sys System, out *Facts) error {
	var errs []error

	if o, err := readOSRelease(sys); err != nil {
		errs = append(errs, err)
	} else {
		out.OS = o
	}

	if b, err := sys.ReadFile(kernelReleasePath); err != nil {
		errs = append(errs, fmt.Errorf("running kernel: %w", err))
	} else {
		k := &Kernel{Release: strings.TrimSpace(string(b))}
		if entries, err := sys.ReadDir(bootDir); err == nil {
			k.Installed = installedKernels(entries)
		}
		out.Kernel = k
	}

	if r, err := readReboot(sys); err != nil {
		errs = append(errs, err)
	} else {
		out.Reboot = r
	}
	return errors.Join(errs...)
}

func readOSRelease(sys System) (*OS, error) {
	b, err := sys.ReadFile(osReleasePath)
	if errors.Is(err, fs.ErrNotExist) {
		b, err = sys.ReadFile(osReleaseFallback)
	}
	if err != nil {
		return nil, fmt.Errorf("os-release: %w", err)
	}
	kv := ParseOSRelease(b)
	if kv["ID"] == "" {
		return nil, errors.New("os-release: no ID field")
	}
	return &OS{
		ID:              kv["ID"],
		IDLike:          strings.Fields(kv["ID_LIKE"]),
		VersionID:       kv["VERSION_ID"],
		VersionCodename: kv["VERSION_CODENAME"],
		PrettyName:      kv["PRETTY_NAME"],
	}, nil
}

// ParseOSRelease parses the os-release(5) format: KEY=value lines, values
// optionally in single or double quotes with backslash escapes.
func ParseOSRelease(b []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok || key == "" {
			continue
		}
		if len(val) >= 2 && (val[0] == '"' || val[0] == '\'') && val[len(val)-1] == val[0] {
			if val[0] == '"' {
				if uq, err := strconv.Unquote(val); err == nil {
					val = uq
				} else {
					val = val[1 : len(val)-1]
				}
			} else {
				val = val[1 : len(val)-1]
			}
		}
		out[key] = val
	}
	return out
}

func installedKernels(entries []fs.DirEntry) []string {
	var out []string
	for _, e := range entries {
		if v, ok := strings.CutPrefix(e.Name(), "vmlinuz-"); ok && v != "" {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

func readReboot(sys System) (*Reboot, error) {
	m, err := sys.Meta(rebootRequiredPath)
	if errors.Is(err, fs.ErrNotExist) {
		return &Reboot{Required: false}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reboot marker: %w", err)
	}
	r := &Reboot{Required: true, Since: time.Unix(m.ModTime, 0).UTC()}
	if b, err := sys.ReadFile(rebootPkgsPath); err == nil {
		seen := map[string]bool{}
		for _, p := range strings.Fields(string(b)) {
			if !seen[p] {
				seen[p] = true
				r.Packages = append(r.Packages, p)
			}
		}
		sort.Strings(r.Packages)
	}
	return r, nil
}
