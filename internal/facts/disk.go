package facts

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Disk is filesystem usage of /, /var and the Docker root (SYS-005).
type Disk struct {
	// Mounts has one entry per watched path, resolved to the filesystem that
	// holds it. Paths on the same filesystem repeat that filesystem.
	Mounts []DiskMount `json:"mounts"`
}

// DiskMount is the usage of the filesystem holding Path.
type DiskMount struct {
	Path   string `json:"path"`
	Mount  string `json:"mount"`
	Device string `json:"device,omitempty"`
	// TotalKB and UsedKB are in kibibytes, as `df -P -k` prints them.
	TotalKB     int64 `json:"total_kb"`
	UsedKB      int64 `json:"used_kb"`
	UsedPercent int   `json:"used_percent"`
}

// Paths whose filesystem is watched. The Docker root is only included when
// it exists; a moved data-root is not followed (the Docker collector owns
// the daemon settings).
const dockerRoot = "/var/lib/docker"

type diskCollector struct{}

func init() { Register(diskCollector{}) }

func (diskCollector) Name() string    { return "disk" }
func (diskCollector) NeedsRoot() bool { return false }

func (diskCollector) Collect(ctx context.Context, sys System, out *Facts) error {
	// System has no statfs, so use `df -P -k` (read only): one call lists
	// every mount and the paths are matched to the longest mount prefix.
	res, err := sys.Run(ctx, "df", "-P", "-k")
	if err != nil {
		return fmt.Errorf("df: %w", err)
	}
	if res.ExitCode != 0 && len(res.Stdout) == 0 {
		return fmt.Errorf("df: %w", cmdErr(nil, res))
	}
	fsList := ParseDF(res.Stdout)
	if len(fsList) == 0 {
		return fmt.Errorf("df: no filesystems in the output")
	}
	paths := []string{"/", "/var"}
	if _, err := sys.Meta(dockerRoot); err == nil {
		paths = append(paths, dockerRoot)
	}
	d := &Disk{Mounts: []DiskMount{}}
	for _, p := range paths {
		if m, ok := mountFor(fsList, p); ok {
			m.Path = p
			d.Mounts = append(d.Mounts, m)
		}
	}
	out.Disk = d
	if len(d.Mounts) == 0 {
		return fmt.Errorf("df: no mount holds /")
	}
	return nil
}

// ParseDF parses `df -P -k` output: Filesystem 1024-blocks Used Available
// Capacity Mounted-on.
func ParseDF(b []byte) []DiskMount {
	var out []DiskMount
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Scan() // header
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 6 {
			continue
		}
		total, e1 := strconv.ParseInt(f[1], 10, 64)
		used, e2 := strconv.ParseInt(f[2], 10, 64)
		pct, e3 := strconv.Atoi(strings.TrimSuffix(f[4], "%"))
		if e1 != nil || e2 != nil || e3 != nil {
			continue
		}
		out = append(out, DiskMount{
			Device: f[0], Mount: strings.Join(f[5:], " "),
			TotalKB: total, UsedKB: used, UsedPercent: pct,
		})
	}
	return out
}

// mountFor returns the entry with the longest mount point that is a prefix
// of path (on a path component boundary).
func mountFor(list []DiskMount, p string) (DiskMount, bool) {
	cands := make([]DiskMount, 0, len(list))
	for _, m := range list {
		if m.Mount == "/" || p == m.Mount || strings.HasPrefix(p, m.Mount+"/") {
			cands = append(cands, m)
		}
	}
	if len(cands) == 0 {
		return DiskMount{}, false
	}
	sort.SliceStable(cands, func(i, j int) bool { return len(cands[i].Mount) > len(cands[j].Mount) })
	return cands[0], true
}
