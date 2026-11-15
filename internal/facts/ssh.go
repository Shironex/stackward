package facts

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strconv"
	"strings"

	"github.com/Shironex/stackward/internal/facts/sshd"
)

// SSH is the OpenSSH server: its effective configuration, the files it was
// read from, socket activation, listeners on the SSH ports, host keys and
// users' authorized_keys metadata (SSH group).
type SSH struct {
	// Installed is false when neither sshd nor /etc/ssh/sshd_config exists;
	// every other field is then empty.
	Installed bool `json:"installed"`
	// Source says where Effective came from: "sshd -T" (root, the
	// authoritative answer) or "files" (the configuration parsed by
	// stackward, used without root or when sshd -T fails).
	Source string `json:"source,omitempty"`
	// SshdTError says why sshd -T was not used, when Source is "files".
	SshdTError string `json:"sshd_t_error,omitempty"`
	// Effective is the global effective configuration, keyed by lower case
	// keyword in the shape sshd -T prints (accumulating keywords such as
	// port and listenaddress hold one element per value). With Source
	// "files", a keyword an unreadable file could have set first is absent.
	Effective map[string][]string `json:"effective,omitempty"`
	// Complete is true when Effective covers every keyword: sshd -T, or
	// every global configuration file was read.
	Complete bool `json:"complete"`
	// Defaulted lists keywords whose value is sshd's built in default
	// (Source "files" only).
	Defaulted []string `json:"defaulted,omitempty"`

	// Config is the parsed files: read order, every directive with its file
	// and line, and the Match blocks. Kept with either Source, because the
	// drop-in order and Match checks need it.
	Config *sshd.Config `json:"config,omitempty"`

	// Socket is the systemd socket unit (ssh.socket on Debian and Ubuntu).
	// Nil when systemctl could not be asked (SocketError says why).
	Socket      *SSHSocket `json:"socket,omitempty"`
	SocketError string     `json:"socket_error,omitempty"`

	// Listening holds the local addresses of TCP listeners (ss -Htln) on
	// the configured or socket ports, as ss prints them ("*:22",
	// "0.0.0.0:22", "[::]:22"). Valid only when ListeningInspected.
	Listening          []string `json:"listening,omitempty"`
	ListeningInspected bool     `json:"listening_inspected"`
	ListeningError     string   `json:"listening_error,omitempty"`

	// PAM2FA lists second factor PAM modules found in /etc/pam.d/sshd
	// (pam_google_authenticator, pam_oath, ...). Valid only when
	// PAMInspected.
	PAM2FA       []string `json:"pam_2fa,omitempty"`
	PAMInspected bool     `json:"pam_inspected"`

	// HostKeys are the host key files (configured or found in /etc/ssh).
	// Only metadata of private keys is read, never their contents.
	HostKeys []SSHHostKey `json:"host_keys,omitempty"`

	// Users are accounts that can log in and have a ~/.ssh directory or an
	// authorized keys file, or whose home could not be inspected.
	Users []SSHUser `json:"users,omitempty"`
	// UsersError says why /etc/passwd could not be read.
	UsersError string `json:"users_error,omitempty"`
}

// SSHSocket is the state of the sshd socket unit.
type SSHSocket struct {
	Unit          string `json:"unit"`
	LoadState     string `json:"load_state"`                // "loaded", "not-found"
	ActiveState   string `json:"active_state,omitempty"`    // "active", "inactive"
	SubState      string `json:"sub_state,omitempty"`       // "listening"
	UnitFileState string `json:"unit_file_state,omitempty"` // "enabled", "disabled"
	// Listen are the stream addresses the unit listens on ("[::]:22").
	Listen []string `json:"listen,omitempty"`
}

// Active reports whether socket activation is in use.
func (s *SSHSocket) Active() bool {
	return s != nil && s.LoadState == "loaded" && s.ActiveState == "active"
}

// SSHHostKey is one host key: metadata of the private file and the type and
// size from its public half.
type SSHHostKey struct {
	Path string `json:"path"`
	// Configured is true when sshd is configured to load it.
	Configured bool `json:"configured"`
	// Meta is the private key file's metadata; nil when it does not exist
	// or could not be inspected (MetaError).
	Meta      *FileMeta `json:"meta,omitempty"`
	MetaError string    `json:"meta_error,omitempty"`
	// Type and Bits come from the .pub file; empty when it is missing.
	Type string `json:"type,omitempty"`
	Bits int    `json:"bits,omitempty"`
}

// SSHUser is one account's SSH files, metadata only plus key types.
type SSHUser struct {
	Name  string `json:"name"`
	UID   int    `json:"uid"`
	Home  string `json:"home"`
	Shell string `json:"shell,omitempty"`
	// HomeMeta and SSHDir are nil when absent; Error says what could not
	// be inspected (for example permission denied without root).
	HomeMeta *FileMeta    `json:"home_meta,omitempty"`
	SSHDir   *FileMeta    `json:"ssh_dir,omitempty"`
	Error    string       `json:"error,omitempty"`
	KeyFiles []SSHKeyFile `json:"key_files,omitempty"`
}

// SSHKeyFile is one authorized keys file of a user.
type SSHKeyFile struct {
	Path  string    `json:"path"`
	Meta  *FileMeta `json:"meta,omitempty"`
	Error string    `json:"error,omitempty"`
	// Keys holds type and size per key; comments and key material are
	// never kept.
	Keys    []sshd.PubKey `json:"keys,omitempty"`
	Invalid int           `json:"invalid,omitempty"`
}

// Setting returns the global effective value of keyword and whether it is
// known. An accumulating keyword (allowusers, port, ...) that is not set is
// known to be empty when the configuration is Complete.
func (s *SSH) Setting(keyword string) ([]string, bool) {
	if s == nil {
		return nil, false
	}
	kw := sshd.Canonical(keyword)
	if v, ok := s.Effective[kw]; ok {
		return v, true
	}
	if s.Complete && sshd.Accumulates(kw) {
		return nil, true
	}
	return nil, false
}

// Value returns the first effective value of a single valued keyword in
// lower case, and whether it is known.
func (s *SSH) Value(keyword string) (string, bool) {
	v, ok := s.Setting(keyword)
	if !ok || len(v) == 0 {
		return "", false
	}
	return strings.ToLower(v[0]), true
}

// Paths and commands the ssh collector uses.
const (
	sshdConfigPath = "/etc/ssh/sshd_config"
	sshdPAMPath    = "/etc/pam.d/sshd"
)

// pam2FAModules are PAM modules that add a second factor to sshd.
var pam2FAModules = []string{
	"pam_google_authenticator", "pam_oath", "pam_duo", "login_duo", "pam_u2f",
	"pam_yubico", "pam_radius_auth", "pam_totp", "pam_privacyidea",
}

type sshCollector struct{}

func init() { Register(sshCollector{}) }

func (sshCollector) Name() string { return "ssh" }

// NeedsRoot is false: without root the collector parses the configuration
// files it can read and records what it could not see.
func (sshCollector) NeedsRoot() bool { return false }

func (sshCollector) Collect(ctx context.Context, sys System, out *Facts) error {
	s := &SSH{}
	out.SSH = s
	_, lookErr := sys.LookPath("sshd")
	_, metaErr := sys.Meta(sshdConfigPath)
	if lookErr != nil && errors.Is(metaErr, fs.ErrNotExist) {
		return nil
	}
	s.Installed = true

	var errs []error
	s.Config = sshd.Parse(sys, sshdConfigPath)
	root := sys.Identity().Root
	switch {
	case !root:
		s.SshdTError = "not root"
	case lookErr != nil:
		s.SshdTError = "sshd not found"
	default:
		res, err := sys.Run(ctx, "sshd", "-T")
		eff := sshd.ParseEffective(res.Stdout)
		switch {
		case err != nil:
			s.SshdTError = err.Error()
		case res.ExitCode != 0 || len(eff) == 0:
			s.SshdTError = sshFirstLine(res.Stderr, fmt.Sprintf("exit code %d", res.ExitCode))
		default:
			s.Source, s.Effective, s.Complete = "sshd -T", eff, true
		}
	}
	if s.Source == "" {
		s.Source = "files"
		s.Effective, s.Complete, s.Defaulted = s.Config.Effective, s.Config.Complete, s.Config.Defaulted
		if len(s.Config.Files) == 0 || !s.Config.Files[0].Readable {
			errs = append(errs, fmt.Errorf("%s not readable and sshd -T unavailable (%s)", sshdConfigPath, s.SshdTError))
		}
	}

	s.collectSocket(ctx, sys)
	s.collectListeners(ctx, sys)
	s.collectPAM(sys)
	s.collectHostKeys(sys)
	s.collectUsers(sys)
	return errors.Join(errs...)
}

func sshFirstLine(b []byte, fallback string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(string(b)), "\n")
	line = strings.TrimSpace(line)
	if line == "" {
		return fallback
	}
	if len(line) > 200 {
		line = line[:200]
	}
	return line
}

func (s *SSH) collectSocket(ctx context.Context, sys System) {
	if _, err := sys.LookPath("systemctl"); err != nil {
		s.SocketError = "systemctl not found"
		return
	}
	var last *SSHSocket
	for _, unit := range []string{"ssh.socket", "sshd.socket"} {
		res, err := sys.Run(ctx, "systemctl", "show", unit,
			"--property=LoadState,ActiveState,SubState,UnitFileState,Listen")
		if err != nil || res.ExitCode != 0 {
			s.SocketError = sshFirstLine(res.Stderr, fmt.Sprintf("systemctl show %s failed", unit))
			if err != nil {
				s.SocketError = err.Error()
			}
			return
		}
		sock := parseSystemctlShow(unit, res.Stdout)
		if sock.LoadState != "not-found" {
			s.Socket = sock
			return
		}
		last = sock
	}
	s.Socket = last // no socket unit at all: recorded explicitly
	if s.Socket != nil {
		s.Socket.Unit = "ssh.socket"
	}
}

func parseSystemctlShow(unit string, out []byte) *SSHSocket {
	sock := &SSHSocket{Unit: unit}
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "LoadState":
			sock.LoadState = v
		case "ActiveState":
			sock.ActiveState = v
		case "SubState":
			sock.SubState = v
		case "UnitFileState":
			sock.UnitFileState = v
		case "Listen":
			// "[::]:22 (Stream)"; datagram and other kinds are not sshd.
			addr, kind, _ := strings.Cut(v, " ")
			if addr != "" && (kind == "" || kind == "(Stream)") {
				sock.Listen = append(sock.Listen, addr)
			}
		}
	}
	return sock
}

// sshPorts returns every port sshd is configured or socket activated on.
func (s *SSH) sshPorts() map[string]bool {
	ports := map[string]bool{}
	for _, p := range s.Effective["port"] {
		ports[p] = true
	}
	addrs := append([]string{}, s.Effective["listenaddress"]...)
	if s.Socket != nil {
		addrs = append(addrs, s.Socket.Listen...)
	}
	for _, a := range addrs {
		if _, p, ok := sshd.SplitHostPort(a); ok {
			ports[p] = true
		} else if _, err := strconv.Atoi(a); err == nil {
			ports[a] = true // ListenStream=22
		}
	}
	return ports
}

func (s *SSH) collectListeners(ctx context.Context, sys System) {
	res, err := sys.Run(ctx, "ss", "-Htln")
	if err != nil || res.ExitCode != 0 {
		s.ListeningError = sshFirstLine(res.Stderr, "ss -Htln failed")
		if err != nil {
			s.ListeningError = err.Error()
		}
		return
	}
	s.ListeningInspected = true
	ports := s.sshPorts()
	for _, addr := range ParseSSListen(res.Stdout) {
		if _, p, ok := sshd.SplitHostPort(addr); ok && ports[p] {
			s.Listening = append(s.Listening, addr)
		}
	}
}

// ParseSSListen returns the local address column of ss -tln output, with
// any %interface suffix removed ("127.0.0.53%lo:53" becomes
// "127.0.0.53:53").
func ParseSSListen(out []byte) []string {
	var addrs []string
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || f[0] == "State" {
			continue
		}
		addr := f[3]
		if i := strings.LastIndex(addr, ":"); i > 0 {
			host, port := addr[:i], addr[i+1:]
			if j := strings.Index(host, "%"); j >= 0 {
				host = host[:j]
				if strings.HasPrefix(host, "[") && !strings.HasSuffix(host, "]") {
					host += "]"
				}
			}
			addr = host + ":" + port
		}
		addrs = append(addrs, addr)
	}
	return addrs
}

func (s *SSH) collectPAM(sys System) {
	b, err := sys.ReadFile(sshdPAMPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			s.PAMInspected = true
		}
		return
	}
	s.PAMInspected = true
	s.PAM2FA = ParsePAM2FA(b)
}

// ParsePAM2FA returns the second factor modules on active auth lines of a
// PAM service file.
func ParsePAM2FA(b []byte) []string {
	var found []string
	seen := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 || strings.HasPrefix(f[0], "#") {
			continue
		}
		typ := strings.TrimPrefix(f[0], "-")
		if typ != "auth" {
			continue
		}
		// The module follows the control field, which may be [a=b c=d].
		rest := f[2:]
		if strings.HasPrefix(f[1], "[") && !strings.HasSuffix(f[1], "]") {
			for i, t := range rest {
				if strings.HasSuffix(t, "]") {
					rest = rest[i+1:]
					break
				}
			}
		}
		if len(rest) == 0 {
			continue
		}
		mod := strings.TrimSuffix(path.Base(rest[0]), ".so")
		for _, m := range pam2FAModules {
			if mod == m && !seen[m] {
				seen[m] = true
				found = append(found, m)
			}
		}
	}
	return found
}

func (s *SSH) collectHostKeys(sys System) {
	configured := s.Effective["hostkey"]
	if len(configured) == 0 && s.Complete && s.Source == "files" {
		configured = sshd.DefaultHostKeys
	}
	seen := map[string]int{}
	add := func(p string, conf bool) {
		if i, ok := seen[p]; ok {
			s.HostKeys[i].Configured = s.HostKeys[i].Configured || conf
			return
		}
		seen[p] = len(s.HostKeys)
		s.HostKeys = append(s.HostKeys, SSHHostKey{Path: p, Configured: conf})
	}
	for _, p := range configured {
		add(p, true)
	}
	if entries, err := sys.ReadDir(sshd.Dir); err == nil {
		for _, e := range entries {
			n := e.Name()
			if strings.HasPrefix(n, "ssh_host_") && strings.HasSuffix(n, "_key") {
				add(path.Join(sshd.Dir, n), false)
			}
		}
	}
	kept := s.HostKeys[:0]
	for _, k := range s.HostKeys {
		m, err := sys.Meta(k.Path) // metadata only: never read a private key
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue // sshd skips a configured key that is missing
		case err != nil:
			k.MetaError = sshd.ErrText(err)
		default:
			k.Meta = &m
		}
		if b, err := sys.ReadFile(k.Path + ".pub"); err == nil {
			if kl := sshd.ParseKeys(b); len(kl.Keys) > 0 {
				k.Type, k.Bits = kl.Keys[0].Type, kl.Keys[0].Bits
			}
		}
		kept = append(kept, k)
	}
	s.HostKeys = kept
}

// loginCapable picks the accounts worth inspecting: root, regular users
// (uid 1000 and up, except nobody) and anything with a real login shell.
func loginCapable(a Account) bool {
	return a.UID == 0 || (a.UID >= 1000 && a.UID != 65534) || a.LoginShell
}

// authorizedKeysPaths expands AuthorizedKeysFile tokens for one user.
func authorizedKeysPaths(spec string, e Account) []string {
	var out []string
	for _, f := range strings.Fields(spec) {
		if strings.EqualFold(f, "none") {
			continue
		}
		r := strings.NewReplacer("%%", "%", "%h", e.Home, "%u", e.Name, "%U", strconv.Itoa(e.UID))
		p := r.Replace(f)
		if !path.IsAbs(p) {
			p = path.Join(e.Home, p)
		}
		out = append(out, path.Clean(p))
	}
	return out
}

func (s *SSH) collectUsers(sys System) {
	b, err := sys.ReadFile(passwdPath)
	if err != nil {
		s.UsersError = sshd.ErrText(err)
		return
	}
	spec := ".ssh/authorized_keys .ssh/authorized_keys2"
	if v, ok := s.Setting("authorizedkeysfile"); ok && len(v) > 0 {
		spec = strings.Join(v, " ")
	}
	for _, e := range ParsePasswd(b) {
		if !loginCapable(e) || e.Home == "" || e.Home == "/nonexistent" {
			continue
		}
		if u, keep := inspectUser(sys, e, spec); keep {
			s.Users = append(s.Users, u)
		}
	}
}

func inspectUser(sys System, e Account, spec string) (SSHUser, bool) {
	u := SSHUser{Name: e.Name, UID: e.UID, Home: e.Home, Shell: e.Shell}
	hm, err := sys.Meta(e.Home)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return u, false
	case err != nil:
		u.Error = fmt.Sprintf("%s: %s", e.Home, sshd.ErrText(err))
		return u, true
	}
	u.HomeMeta = &hm
	keep := false
	dir := path.Join(e.Home, ".ssh")
	dm, err := sys.Meta(dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		u.Error = fmt.Sprintf("%s: %s", dir, sshd.ErrText(err))
		return u, true
	default:
		u.SSHDir, keep = &dm, true
	}
	for _, p := range authorizedKeysPaths(spec, e) {
		kf := SSHKeyFile{Path: p}
		m, err := sys.Meta(p)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil:
			kf.Error = sshd.ErrText(err)
		default:
			kf.Meta = &m
			// Public keys only: the type and size are kept, the key
			// material and comments are dropped by ParseKeys.
			if b, err := sys.ReadFile(p); err != nil {
				kf.Error = sshd.ErrText(err)
			} else {
				kl := sshd.ParseKeys(b)
				kf.Keys, kf.Invalid = kl.Keys, kl.Invalid
			}
		}
		u.KeyFiles = append(u.KeyFiles, kf)
		keep = true
	}
	return u, keep
}
