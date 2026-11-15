// Package sshd parses OpenSSH server configuration files and public keys the
// way sshd itself reads them. It is a leaf package: it does not import facts,
// and it reads only through the small FS interface, so the facts collector
// passes its read only System and tests pass an in memory tree.
//
// The semantics that matter for an audit, all taken from sshd_config(5) and
// servconf.c:
//
//   - For most keywords the first value wins. A later line, in the same file
//     or in a later file, is ignored. This is why a cloud-init drop-in that
//     sorts before a hardening drop-in silently wins.
//   - Include takes one or more glob patterns, relative to /etc/ssh unless
//     absolute. Matches are read in lexical (byte) order, a pattern with no
//     match is ignored, and includes nest up to 16 levels.
//   - Match starts a conditional block that runs to the next Match or the end
//     of the file. A Match block inside an included file ends with that file;
//     an Include inside a Match block belongs to that block.
//   - Port, ListenAddress, HostKey, AllowUsers and a few others accumulate
//     instead of taking the first value.
package sshd

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// FS is what the parser needs from the host. facts.System satisfies it.
type FS interface {
	ReadFile(path string) ([]byte, error)
	ReadDir(path string) ([]fs.DirEntry, error)
}

// Dir is the directory relative Include patterns are resolved against.
const Dir = "/etc/ssh"

// MaxDepth is sshd's include nesting limit (SERVCONF_MAX_DEPTH).
const MaxDepth = 16

// Directive is one keyword line, in the order sshd reads it.
type Directive struct {
	// Keyword is lower case, with deprecated aliases mapped to the current
	// name (ChallengeResponseAuthentication becomes
	// kbdinteractiveauthentication), as sshd -T prints it.
	Keyword string `json:"keyword"`
	// Value is the arguments joined by one space, quotes removed.
	Value string `json:"value"`
	File  string `json:"file"`
	Line  int    `json:"line"`
	// Match is the 1 based index into Config.Matches of the block this line
	// belongs to, or 0 for the global section.
	Match int `json:"match,omitempty"`
}

// Match is one Match block.
type Match struct {
	// Criteria is everything after the Match keyword, for example
	// "User deploy" or "Address 192.0.2.0/24".
	Criteria string `json:"criteria"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	// Incomplete is true when a file included inside the block could not
	// be read, so the block may set more than Directives shows.
	Incomplete bool `json:"incomplete,omitempty"`
}

// All reports whether the block applies to every connection ("Match all").
func (m Match) All() bool { return strings.EqualFold(strings.TrimSpace(m.Criteria), "all") }

// File is one configuration file the parser tried to read, in read order.
type File struct {
	Path     string `json:"path"`
	Readable bool   `json:"readable"`
	// Error says why the file could not be read (for example permission
	// denied when not root).
	Error string `json:"error,omitempty"`
	// Match is the block the file was included from (0 for global).
	Match int `json:"match,omitempty"`
}

// Config is the parsed configuration.
type Config struct {
	Files      []File      `json:"files"`
	Directives []Directive `json:"directives,omitempty"`
	Matches    []Match     `json:"matches,omitempty"`
	// Problems are parse problems sshd would also complain about (include
	// depth exceeded, a line with a keyword and no value).
	Problems []string `json:"problems,omitempty"`

	// Effective is the global effective configuration computed from the
	// files, keyed by lower case keyword, in the shape sshd -T prints:
	// one element for first value wins keywords, one element per value
	// for accumulating ones. A keyword whose value could not be settled
	// (an unreadable file comes first and could set it) is absent.
	Effective map[string][]string `json:"-"`
	// Complete is true when every file of the global section was read, so
	// accumulating keywords and built in defaults are trustworthy.
	Complete bool `json:"-"`
	// Defaulted lists keywords whose Effective value is sshd's built in
	// default because no file sets them (only when Complete).
	Defaulted []string `json:"-"`
}

// Unreadable returns the paths of files that could not be read.
func (c *Config) Unreadable() []string {
	var out []string
	for _, f := range c.Files {
		if !f.Readable {
			out = append(out, f.Path)
		}
	}
	return out
}

// aliases maps deprecated keywords to the name sshd -T prints.
var aliases = map[string]string{
	"challengeresponseauthentication": "kbdinteractiveauthentication",
	"skeyauthentication":              "kbdinteractiveauthentication",
	"pubkeyacceptedkeytypes":          "pubkeyacceptedalgorithms",
	"hostbasedacceptedkeytypes":       "hostbasedacceptedalgorithms",
	"dsaauthentication":               "pubkeyauthentication",
}

// Canonical returns the lower case keyword with aliases resolved.
func Canonical(keyword string) string {
	k := strings.ToLower(keyword)
	if a, ok := aliases[k]; ok {
		return a
	}
	return k
}

// accumulating keywords collect every value instead of taking the first.
var accumulating = map[string]bool{
	"port": true, "listenaddress": true, "hostkey": true, "hostcertificate": true,
	"allowusers": true, "denyusers": true, "allowgroups": true, "denygroups": true,
	"acceptenv": true, "subsystem": true,
}

// splitValues are accumulating keywords whose arguments are separate values
// (sshd -T prints one line per user or group).
var splitValues = map[string]bool{
	"allowusers": true, "denyusers": true, "allowgroups": true, "denygroups": true, "acceptenv": true,
}

// Accumulates reports whether keyword collects every value (Port,
// ListenAddress, AllowUsers, ...) instead of taking the first one.
func Accumulates(keyword string) bool { return accumulating[Canonical(keyword)] }

// defaults are sshd's built in values for the keywords stackward judges, as
// in OpenSSH 8.9 to 9.x (Ubuntu 22.04 to 26.04, Debian 12 and 13). Algorithm
// lists are left out on purpose: they change between releases and builds.
var defaults = map[string]string{
	"passwordauthentication":       "yes",
	"kbdinteractiveauthentication": "yes",
	"permitrootlogin":              "prohibit-password",
	"permitemptypasswords":         "no",
	"pubkeyauthentication":         "yes",
	"maxauthtries":                 "6",
	"x11forwarding":                "no",
	"allowagentforwarding":         "yes",
	"allowtcpforwarding":           "yes",
	"usepam":                       "no",
	"addressfamily":                "any",
	"authenticationmethods":        "any",
	"authorizedkeysfile":           ".ssh/authorized_keys .ssh/authorized_keys2",
	"strictmodes":                  "yes",
	"logingracetime":               "120",
}

// DefaultHostKeys are the host keys sshd loads when no HostKey is set.
var DefaultHostKeys = []string{
	"/etc/ssh/ssh_host_rsa_key",
	"/etc/ssh/ssh_host_ecdsa_key",
	"/etc/ssh/ssh_host_ed25519_key",
}

// event is one step of the read order: a directive or an unreadable file.
type event struct {
	dir        *Directive
	unreadable bool
	match      int
}

type parser struct {
	fsys   FS
	cfg    *Config
	events []event
}

// Parse reads mainPath and everything it includes. It never fails: what
// could not be read is recorded in Files and leaves Complete false.
func Parse(fsys FS, mainPath string) *Config {
	p := &parser{fsys: fsys, cfg: &Config{}}
	p.readFile(mainPath, 0, 0)
	p.cfg.computeEffective(p.events)
	return p.cfg
}

func (p *parser) unreadable(file string, match int, err error) {
	p.cfg.Files = append(p.cfg.Files, File{Path: file, Error: ErrText(err), Match: match})
	p.events = append(p.events, event{unreadable: true, match: match})
	if match > 0 {
		p.cfg.Matches[match-1].Incomplete = true
	}
}

func (p *parser) readFile(file string, match, depth int) {
	b, err := p.fsys.ReadFile(file)
	if err != nil {
		p.unreadable(file, match, err)
		return
	}
	p.cfg.Files = append(p.cfg.Files, File{Path: file, Readable: true, Match: match})
	p.parse(file, string(b), match, depth)
}

func (p *parser) parse(file, body string, match, depth int) {
	// A Match block opened in this file ends with it; the caller's context
	// is restored by simply returning (servconf.c restores *activep).
	ctx := match
	for i, raw := range strings.Split(body, "\n") {
		lineNo := i + 1
		kw, args, ok := splitLine(raw)
		if !ok {
			continue
		}
		keyword := Canonical(kw)
		switch keyword {
		case "match":
			p.cfg.Matches = append(p.cfg.Matches, Match{Criteria: strings.Join(args, " "), File: file, Line: lineNo})
			ctx = len(p.cfg.Matches)
			continue
		case "include":
			if len(args) == 0 {
				p.problem(file, lineNo, "Include without a file")
				continue
			}
			if depth+1 > MaxDepth {
				p.problem(file, lineNo, fmt.Sprintf("Include nested deeper than %d levels", MaxDepth))
				continue
			}
			for _, pat := range args {
				p.include(pat, ctx, depth+1)
			}
			continue
		}
		if len(args) == 0 {
			p.problem(file, lineNo, fmt.Sprintf("%s has no value", kw))
			continue
		}
		d := &Directive{Keyword: keyword, Value: strings.Join(args, " "), File: file, Line: lineNo, Match: ctx}
		p.cfg.Directives = append(p.cfg.Directives, *d)
		p.events = append(p.events, event{dir: d, match: ctx})
	}
}

func (p *parser) problem(file string, line int, msg string) {
	p.cfg.Problems = append(p.cfg.Problems, fmt.Sprintf("%s line %d: %s", file, line, msg))
}

func (p *parser) include(pattern string, match, depth int) {
	if !path.IsAbs(pattern) {
		pattern = path.Join(Dir, pattern)
	}
	files, err := Glob(p.fsys, pattern)
	if err != nil {
		// The directory could not be listed, so whatever it holds is
		// unknown; record the pattern itself as unreadable.
		p.unreadable(pattern, match, err)
		return
	}
	for _, f := range files {
		p.readFile(f, match, depth)
	}
}

// computeEffective applies first value wins and accumulation to the global
// section, in read order.
func (c *Config) computeEffective(events []event) {
	eff := map[string][]string{}
	seen := map[string]bool{}
	multi := map[string][]string{}
	blocked := false // an unreadable global file came before this point
	mainRead := len(c.Files) > 0 && c.Files[0].Readable
	for _, e := range events {
		if e.match != 0 {
			continue
		}
		if e.unreadable {
			blocked = true
			continue
		}
		d := e.dir
		if accumulating[d.Keyword] {
			if splitValues[d.Keyword] {
				multi[d.Keyword] = append(multi[d.Keyword], strings.Fields(d.Value)...)
			} else {
				multi[d.Keyword] = append(multi[d.Keyword], d.Value)
			}
			continue
		}
		if seen[d.Keyword] {
			continue
		}
		seen[d.Keyword] = true
		if !blocked {
			eff[d.Keyword] = []string{d.Value}
		}
	}
	c.Complete = mainRead && !blocked
	if c.Complete {
		for k, v := range multi {
			if k != "listenaddress" {
				eff[k] = v
			}
		}
		for k, v := range defaults {
			if !seen[k] {
				eff[k] = []string{v}
				c.Defaulted = append(c.Defaulted, k)
			}
		}
		sort.Strings(c.Defaulted)
		if len(eff["port"]) == 0 {
			eff["port"] = []string{"22"}
			c.Defaulted = append(c.Defaulted, "port")
			sort.Strings(c.Defaulted)
		}
		eff["listenaddress"] = listenAddresses(multi["listenaddress"], eff["port"], first(eff["addressfamily"]))
	}
	c.Effective = eff
}

func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

// listenAddresses expands ListenAddress and Port into the host:port form sshd
// -T prints ("0.0.0.0:22", "[::]:22").
func listenAddresses(addrs, ports []string, family string) []string {
	if len(addrs) == 0 {
		switch strings.ToLower(family) {
		case "inet":
			addrs = []string{"0.0.0.0"}
		case "inet6":
			addrs = []string{"::"}
		default:
			addrs = []string{"::", "0.0.0.0"}
		}
	}
	var out []string
	for _, a := range addrs {
		a = strings.Fields(a + " ")[0] // drop an "rdomain name" suffix
		host, port, hasPort := SplitHostPort(a)
		if hasPort {
			out = append(out, JoinHostPort(host, port))
			continue
		}
		for _, p := range ports {
			out = append(out, JoinHostPort(host, p))
		}
	}
	return out
}

// SplitHostPort splits "host", "host:port", "[v6]:port", "[v6]" or a bare
// IPv6 address. hasPort is false when no port is given.
func SplitHostPort(s string) (host, port string, hasPort bool) {
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return s, "", false
		}
		host = s[1:end]
		rest := s[end+1:]
		if p, ok := strings.CutPrefix(rest, ":"); ok && p != "" {
			return host, p, true
		}
		return host, "", false
	}
	if strings.Count(s, ":") == 1 {
		h, p, _ := strings.Cut(s, ":")
		return h, p, p != ""
	}
	return s, "", false // a name, an IPv4 address or a bare IPv6 address
}

// JoinHostPort is the inverse of SplitHostPort, bracketing IPv6 hosts.
func JoinHostPort(host, port string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}

// splitLine splits one configuration line into a keyword and its arguments,
// as sshd 8.7 and later do: leading whitespace is ignored, a line or an
// argument starting with # ends the line, the keyword may be followed by
// whitespace or one "=", and arguments may be quoted with " or '.
func splitLine(line string) (keyword string, args []string, ok bool) {
	s := strings.TrimLeft(strings.TrimRight(line, "\r\n"), " \t")
	if s == "" || s[0] == '#' {
		return "", nil, false
	}
	end := strings.IndexAny(s, " \t=")
	if end < 0 {
		return s, nil, true
	}
	keyword, rest := s[:end], strings.TrimLeft(s[end:], " \t")
	if strings.HasPrefix(rest, "=") {
		rest = strings.TrimLeft(rest[1:], " \t")
	}
	return keyword, splitArgs(rest), true
}

// splitArgs splits on unquoted whitespace, honouring " and ' quotes and
// backslash escapes, and stops at an unquoted # that starts an argument.
func splitArgs(s string) []string {
	var out []string
	var cur strings.Builder
	inArg := false
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			switch {
			case c == '\\' && i+1 < len(s) && (s[i+1] == quote || s[i+1] == '\\'):
				i++
				cur.WriteByte(s[i])
			case c == quote:
				quote = 0
			default:
				cur.WriteByte(c)
			}
		case c == ' ' || c == '\t':
			if inArg {
				out = append(out, cur.String())
				cur.Reset()
				inArg = false
			}
		case c == '#' && !inArg:
			return out
		case c == '"' || c == '\'':
			quote = c
			inArg = true
		case c == '\\' && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
			inArg = true
		default:
			cur.WriteByte(c)
			inArg = true
		}
	}
	if inArg {
		out = append(out, cur.String())
	}
	return out
}

// Glob expands an absolute pattern the way glob(3) does for sshd: each path
// element may hold *, ? or [...]; a wildcard never matches a leading dot;
// results are sorted in byte order. A pattern without wildcards is returned
// only if the file exists, or if it may exist but cannot be checked. The
// error is set only when a directory that must be listed cannot be read for
// a reason other than not existing.
func Glob(fsys FS, pattern string) ([]string, error) {
	pattern = path.Clean(pattern)
	if !hasMeta(pattern) {
		if _, err := fsys.ReadFile(pattern); errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return []string{pattern}, nil
	}
	parts := strings.Split(strings.TrimPrefix(pattern, "/"), "/")
	cands := []string{"/"}
	for i, part := range parts {
		last := i == len(parts)-1
		var next []string
		for _, dir := range cands {
			if !hasMeta(part) {
				next = append(next, path.Join(dir, part))
				continue
			}
			entries, err := fsys.ReadDir(dir)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) || isNotDir(err) {
					continue
				}
				return nil, err
			}
			for _, e := range entries {
				name := e.Name()
				if strings.HasPrefix(name, ".") && !strings.HasPrefix(part, ".") {
					continue
				}
				if ok, _ := path.Match(part, name); !ok {
					continue
				}
				if !last && !e.IsDir() && e.Type()&fs.ModeSymlink == 0 {
					continue
				}
				next = append(next, path.Join(dir, name))
			}
		}
		cands = next
	}
	sort.Strings(cands)
	return cands, nil
}

func hasMeta(s string) bool { return strings.ContainsAny(s, "*?[") }

func isNotDir(err error) bool {
	return err != nil && strings.Contains(err.Error(), "not a directory")
}

// ErrText shortens an fs error to its cause ("permission denied").
func ErrText(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

// ParseEffective parses sshd -T output: one "keyword value" pair per line,
// accumulating keywords repeated.
func ParseEffective(out []byte) map[string][]string {
	eff := map[string][]string{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		kw, val, _ := strings.Cut(line, " ")
		eff[Canonical(kw)] = append(eff[Canonical(kw)], strings.TrimSpace(val))
	}
	return eff
}
