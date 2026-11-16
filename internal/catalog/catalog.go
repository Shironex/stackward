// Package catalog is the embedded description of every check: title,
// severity, why it matters, how to verify by hand, how to fix it and what a
// fix can break. Reports, explain and the docs generator all read it.
//
// Entries live in data/<group>.json, one file per group, so slices adding
// checks to different groups never edit the same file.
package catalog

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Severity is how bad a failing check is, independent of its level.
type Severity string

// Severities, most severe first.
const (
	Critical Severity = "critical"
	High     Severity = "high"
	Moderate Severity = "moderate"
	Low      Severity = "low"
	Info     Severity = "info"
)

var severities = map[Severity]bool{Critical: true, High: true, Moderate: true, Low: true, Info: true}

// Group is a check group, such as SYS or DKR.
type Group struct {
	ID   string
	Name string
}

// Groups is every group in report order. A data file for a group not listed
// here fails to load. The order follows the design brief's catalogue.
var Groups = []Group{
	{"SYS", "System"},
	{"SSH", "SSH"},
	{"USR", "Users and privilege"},
	{"NET", "Firewall and exposure"},
	{"PFW", "Provider firewall"},
	{"DKR", "Docker"},
	{"TS", "Tailscale"},
	{"CF", "Cloudflare Tunnel"},
	{"CS", "CrowdSec and fail2ban"},
	{"UPD", "Updates"},
	{"KRN", "Kernel settings"},
	{"LOG", "Logs and monitoring"},
	{"SEC", "Secrets on disk"},
	{"PAAS", "Coolify and Dokploy"},
	{"BAK", "Backups"},
	{"PRB", "Outside view"},
}

// Entry describes one check.
type Entry struct {
	ID       string   `json:"id"`
	Group    string   `json:"-"` // from the file
	Title    string   `json:"title"`
	Severity Severity `json:"severity"`
	// Rationale says why the check matters.
	Rationale string `json:"rationale"`
	// Verify says how to confirm the finding by hand (optional).
	Verify string `json:"verify,omitempty"`
	// Fix is the short fix hint printed in reports.
	Fix string `json:"fix"`
	// Breaks says what applying the fix can break (optional).
	Breaks string `json:"breaks,omitempty"`
	// Docs is a URL with more detail (optional).
	Docs string `json:"docs,omitempty"`
	// NeedsRoot marks checks whose full result needs root.
	NeedsRoot bool `json:"needs_root,omitempty"`
}

type groupFile struct {
	Group  string  `json:"group"`
	Checks []Entry `json:"checks"`
}

// Catalog is the loaded set of entries.
type Catalog struct {
	byID  map[string]Entry
	order []string
}

//go:embed data/*.json
var dataFS embed.FS

// IDPattern is the shape of every check id: an upper case group, a dash and
// three digits. Ids are stable forever; a retired id is never reused.
var IDPattern = regexp.MustCompile(`^([A-Z]{2,4})-([0-9]{3})$`)

// Load parses and validates the embedded catalog.
func Load() (*Catalog, error) {
	names, err := dataFS.ReadDir("data")
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{}
	for _, n := range names {
		b, err := dataFS.ReadFile(path.Join("data", n.Name()))
		if err != nil {
			return nil, err
		}
		files[n.Name()] = b
	}
	return parse(files)
}

var (
	defaultOnce sync.Once
	defaultCat  *Catalog
	defaultErr  error
)

// Default returns the embedded catalog, loaded once. A broken catalog is a
// build defect caught by the package tests, so callers may treat the error
// as fatal.
func Default() (*Catalog, error) {
	defaultOnce.Do(func() { defaultCat, defaultErr = Load() })
	return defaultCat, defaultErr
}

func parse(files map[string][]byte) (*Catalog, error) {
	known := map[string]bool{}
	for _, g := range Groups {
		known[g.ID] = true
	}
	c := &Catalog{byID: map[string]Entry{}}
	var errs []error
	fail := func(format string, a ...any) { errs = append(errs, fmt.Errorf(format, a...)) }

	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		var gf groupFile
		dec := json.NewDecoder(bytes.NewReader(files[name]))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&gf); err != nil {
			fail("%s: %v", name, err)
			continue
		}
		if _, err := dec.Token(); err != io.EOF {
			fail("%s: trailing data after the JSON object", name)
		}
		if !known[gf.Group] {
			fail("%s: unknown group %q (add it to catalog.Groups first)", name, gf.Group)
			continue
		}
		if want := strings.ToLower(gf.Group) + ".json"; name != want {
			fail("%s: group %s must live in %s", name, gf.Group, want)
		}
		for _, e := range gf.Checks {
			e.Group = gf.Group
			m := IDPattern.FindStringSubmatch(e.ID)
			switch {
			case m == nil:
				fail("%s: bad id %q", name, e.ID)
				continue
			case m[1] != gf.Group:
				fail("%s: id %s is not in group %s", name, e.ID, gf.Group)
			case !severities[e.Severity]:
				fail("%s: %s: bad severity %q", name, e.ID, e.Severity)
			case strings.TrimSpace(e.Title) == "", strings.TrimSpace(e.Rationale) == "", strings.TrimSpace(e.Fix) == "":
				fail("%s: %s: title, rationale and fix are required", name, e.ID)
			}
			if _, dup := c.byID[e.ID]; dup {
				fail("%s: duplicate id %s", name, e.ID)
				continue
			}
			c.byID[e.ID] = e
		}
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	c.order = make([]string, 0, len(c.byID))
	for id := range c.byID {
		c.order = append(c.order, id)
	}
	sort.Slice(c.order, func(i, j int) bool { return Less(c.order[i], c.order[j]) })
	return c, nil
}

// Lookup returns the entry for id.
func (c *Catalog) Lookup(id string) (Entry, bool) {
	e, ok := c.byID[id]
	return e, ok
}

// Entries returns every entry in report order.
func (c *Catalog) Entries() []Entry {
	out := make([]Entry, 0, len(c.order))
	for _, id := range c.order {
		out = append(out, c.byID[id])
	}
	return out
}

// GroupOf returns the group id of a check id ("DKR-001" gives "DKR").
func GroupOf(id string) string {
	g, _, _ := strings.Cut(id, "-")
	return g
}

// GroupName returns the display name of a group id.
func GroupName(id string) string {
	for _, g := range Groups {
		if g.ID == id {
			return g.Name
		}
	}
	return id
}

// GroupRank is the position of a group in report order; unknown groups sort
// last.
func GroupRank(id string) int {
	for i, g := range Groups {
		if g.ID == id {
			return i
		}
	}
	return len(Groups)
}

// Less orders check ids by group rank, then by id.
func Less(a, b string) bool {
	ra, rb := GroupRank(GroupOf(a)), GroupRank(GroupOf(b))
	if ra != rb {
		return ra < rb
	}
	return a < b
}
