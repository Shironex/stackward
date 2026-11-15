package facts

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// Listeners is every listening socket with its bind address and owning
// process names, plus the host's interface addresses (NET-002, NET-004 and
// profile inference).
type Listeners struct {
	// Source is how the sockets were read: "ss" or "proc" (/proc/net
	// parsing when ss is missing; no process names then).
	Source string `json:"source"`
	// ProcessesVisible is true when process names of every user could be
	// seen (ss run as root). Without root only the caller's own processes
	// are named, so an empty Processes list proves nothing.
	ProcessesVisible bool       `json:"processes_visible"`
	Sockets          []Listener `json:"sockets"`
	// Addresses are the interface addresses. Nil means they could not be
	// read; AddressesSource says how they were read ("ip" or "proc", the
	// latter IPv6 only).
	Addresses       []InterfaceAddr `json:"addresses,omitempty"`
	AddressesSource string          `json:"addresses_source,omitempty"`
}

// Listener is one listening TCP socket or bound UDP socket.
type Listener struct {
	Proto string `json:"proto"` // "tcp" or "udp"
	// Address is the bind address without brackets: "0.0.0.0", "::",
	// "127.0.0.1", "2001:db8::1".
	Address string `json:"address"`
	// Interface is the device the socket is bound to ("lo" in
	// 127.0.0.53%lo), when any.
	Interface string `json:"interface,omitempty"`
	Port      int    `json:"port"`
	// Processes are process names only, never command lines.
	Processes []string `json:"processes,omitempty"`
}

// InterfaceAddr is one address configured on an interface.
type InterfaceAddr struct {
	Interface string `json:"interface"`
	Address   string `json:"address"`
	Prefix    int    `json:"prefix"`
	// Scope is "global", "link", "host" or "site".
	Scope string `json:"scope,omitempty"`
}

// BindClass is how reachable a bind address is.
type BindClass string

// Bind classes, from least to most exposed.
const (
	BindLoopback BindClass = "loopback"
	BindTailnet  BindClass = "tailnet" // 100.64.0.0/10 or Tailscale's fd7a:115c:a1e0::/48
	BindPrivate  BindClass = "private" // RFC 1918, ULA, link local
	BindPublic   BindClass = "public"  // a specific public address
	BindWildcard BindClass = "wildcard"
	BindInvalid  BindClass = "unparsed"
)

var (
	tailnetV4 = netip.MustParsePrefix("100.64.0.0/10")
	tailnetV6 = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

// ClassifyAddress classifies a bind address.
func ClassifyAddress(addr string) BindClass {
	if addr == "*" || addr == "" {
		return BindWildcard
	}
	a, err := netip.ParseAddr(addr)
	if err != nil {
		return BindInvalid
	}
	a = a.Unmap()
	switch {
	case a.IsUnspecified():
		return BindWildcard
	case a.IsLoopback():
		return BindLoopback
	case tailnetV4.Contains(a) || tailnetV6.Contains(a):
		return BindTailnet
	case a.IsPrivate() || a.IsLinkLocalUnicast():
		return BindPrivate
	}
	return BindPublic
}

// Class classifies the listener's bind address.
func (l Listener) Class() BindClass { return ClassifyAddress(l.Address) }

// Exposed reports whether the bind address can be reached from outside the
// host's private networks: a wildcard or a specific public address.
func (c BindClass) Exposed() bool { return c == BindWildcard || c == BindPublic }

// HasProcess reports whether any of the listener's process names is name.
func (l Listener) HasProcess(name string) bool {
	for _, p := range l.Processes {
		if p == name {
			return true
		}
	}
	return false
}

// HasGlobalIPv6 reports whether a global unicast IPv6 address (not ULA,
// link local or Tailscale's range) is configured.
// The second result is false when addresses were not read.
func (l *Listeners) HasGlobalIPv6() (has, known bool) {
	if l == nil || l.Addresses == nil {
		return false, false
	}
	for _, a := range l.Addresses {
		ip, err := netip.ParseAddr(a.Address)
		if err != nil || !ip.Is6() || ip.Is4In6() {
			continue
		}
		if ip.IsGlobalUnicast() && !ip.IsPrivate() && !tailnetV6.Contains(ip) {
			return true, true
		}
	}
	return false, true
}

type listenersCollector struct{}

func init() { Register(listenersCollector{}) }

func (listenersCollector) Name() string    { return "listeners" }
func (listenersCollector) NeedsRoot() bool { return false }

// Collect runs (read only):
//
//	ss -Htulnp           listening TCP and bound UDP sockets with process names
//	ip -j addr show      interface addresses
//
// and falls back to /proc/net/{tcp,tcp6,udp,udp6} and /proc/net/if_inet6.
func (listenersCollector) Collect(ctx context.Context, sys System, out *Facts) error {
	var errs []error
	l := &Listeners{}
	res, err := sys.Run(ctx, "ss", "-Htulnp")
	switch {
	case err == nil && res.ExitCode == 0:
		socks, perr := ParseSS(res.Stdout)
		if perr != nil {
			errs = append(errs, perr)
		}
		l.Source, l.Sockets = "ss", socks
		l.ProcessesVisible = sys.Identity().Root
	default:
		if err == nil {
			err = fmt.Errorf("ss exited %d: %s", res.ExitCode, firstLine(res.Stderr))
		}
		socks, perr := readProcNet(sys)
		if perr != nil {
			errs = append(errs, err, perr)
			if socks == nil {
				return errors.Join(errs...)
			}
		}
		l.Source, l.Sockets = "proc", socks
	}

	if r, aerr := sys.Run(ctx, "ip", "-j", "addr", "show"); aerr == nil && r.ExitCode == 0 {
		addrs, perr := ParseIPAddrJSON(r.Stdout)
		if perr != nil {
			errs = append(errs, perr)
		} else {
			l.Addresses, l.AddressesSource = addrs, "ip"
		}
	}
	if l.Addresses == nil {
		if b, rerr := sys.ReadFile("/proc/net/if_inet6"); rerr == nil {
			l.Addresses, l.AddressesSource = ParseIfInet6(b), "proc"
		}
	}
	if l.Sockets == nil {
		l.Sockets = []Listener{}
	}
	sortListeners(l.Sockets)
	out.Listeners = l
	return errors.Join(errs...)
}

func sortListeners(ls []Listener) {
	sort.Slice(ls, func(i, j int) bool {
		a, b := ls[i], ls[j]
		if a.Proto != b.Proto {
			return a.Proto < b.Proto
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		if a.Address != b.Address {
			return a.Address < b.Address
		}
		return a.Interface < b.Interface
	})
}

func firstLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

// ParseSS parses `ss -Htulnp` output (no header). Lines it cannot read are
// skipped and reported in the error; the rest is kept.
func ParseSS(b []byte) ([]Listener, error) {
	var out []Listener
	var bad int
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		// Netid State Recv-Q Send-Q Local Peer [Process]
		if len(f) < 6 {
			bad++
			continue
		}
		proto := f[0]
		if proto != "tcp" && proto != "udp" {
			continue
		}
		addr, iface, port, ok := splitHostPort(f[4])
		if !ok {
			bad++
			continue
		}
		l := Listener{Proto: proto, Address: addr, Interface: iface, Port: port}
		if len(f) > 6 {
			l.Processes = parseSSUsers(strings.Join(f[6:], " "))
		}
		out = append(out, l)
	}
	var err error
	if bad > 0 {
		err = fmt.Errorf("ss: %d unreadable lines skipped", bad)
	}
	if out == nil {
		out = []Listener{}
	}
	return out, err
}

// splitHostPort reads "0.0.0.0:22", "[::]:22", "*:22", "127.0.0.53%lo:53"
// and "[fe80::1%eth0]:546".
func splitHostPort(s string) (addr, iface string, port int, ok bool) {
	i := strings.LastIndexByte(s, ':')
	if i <= 0 {
		return "", "", 0, false
	}
	host, ps := s[:i], s[i+1:]
	p, err := strconv.Atoi(ps)
	if err != nil || p < 0 || p > 65535 {
		return "", "", 0, false
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	if j := strings.IndexByte(host, '%'); j >= 0 {
		host, iface = host[:j], host[j+1:]
	}
	if host != "*" {
		a, err := netip.ParseAddr(host)
		if err != nil {
			return "", "", 0, false
		}
		host = a.String()
	}
	return host, iface, p, true
}

// parseSSUsers extracts process names from users:(("sshd",pid=1,fd=3),...).
// Only the quoted names are kept, deduplicated and sorted.
func parseSSUsers(s string) []string {
	seen := map[string]bool{}
	for {
		i := strings.Index(s, `("`)
		if i < 0 {
			break
		}
		s = s[i+2:]
		j := strings.IndexByte(s, '"')
		if j < 0 {
			break
		}
		if name := s[:j]; name != "" {
			seen[name] = true
		}
		s = s[j+1:]
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// readProcNet parses the /proc/net socket tables.
func readProcNet(sys System) ([]Listener, error) {
	var out []Listener
	var errs []error
	read := 0
	for _, t := range []struct{ file, proto string }{
		{"/proc/net/tcp", "tcp"}, {"/proc/net/tcp6", "tcp"},
		{"/proc/net/udp", "udp"}, {"/proc/net/udp6", "udp"},
	} {
		b, err := sys.ReadFile(t.file)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		read++
		ls, err := ParseProcNet(b, t.proto)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", t.file, err))
		}
		out = append(out, ls...)
	}
	if read == 0 {
		return nil, errors.Join(errs...)
	}
	if out == nil {
		out = []Listener{}
	}
	// A missing tcp6 table only means IPv6 is off; do not report it.
	return out, nil
}

// procListen and procUnconn are the TCP LISTEN and UDP unconnected states.
const (
	procListen = "0A"
	procUnconn = "07"
)

// ParseProcNet parses /proc/net/tcp, tcp6, udp or udp6 and keeps listening
// TCP sockets and UDP sockets with no remote peer.
func ParseProcNet(b []byte, proto string) ([]Listener, error) {
	var out []Listener
	var bad int
	sc := bufio.NewScanner(bytes.NewReader(b))
	first := true
	for sc.Scan() {
		if first {
			first = false
			continue // header
		}
		f := strings.Fields(sc.Text())
		if len(f) < 4 {
			continue
		}
		local, remote, state := f[1], f[2], f[3]
		switch {
		case proto == "tcp" && state != procListen:
			continue
		case proto == "udp" && (state != procUnconn || !zeroRemote(remote)):
			continue
		}
		addr, port, ok := decodeProcAddr(local)
		if !ok {
			bad++
			continue
		}
		out = append(out, Listener{Proto: proto, Address: addr, Port: port})
	}
	var err error
	if bad > 0 {
		err = fmt.Errorf("%d unreadable lines skipped", bad)
	}
	return out, err
}

func zeroRemote(s string) bool {
	return strings.Trim(strings.ReplaceAll(s, ":", ""), "0") == ""
}

// decodeProcAddr decodes "0100007F:0016" (and the 32 digit IPv6 form). The
// kernel prints each 32 bit word in host byte order (little endian on the
// architectures stackward ships for).
func decodeProcAddr(s string) (string, int, bool) {
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return "", 0, false
	}
	raw, err := hex.DecodeString(s[:i])
	if err != nil || (len(raw) != 4 && len(raw) != 16) {
		return "", 0, false
	}
	p, err := strconv.ParseUint(s[i+1:], 16, 16)
	if err != nil {
		return "", 0, false
	}
	for w := 0; w < len(raw); w += 4 {
		raw[w], raw[w+1], raw[w+2], raw[w+3] = raw[w+3], raw[w+2], raw[w+1], raw[w]
	}
	a, ok := netip.AddrFromSlice(raw)
	if !ok {
		return "", 0, false
	}
	return a.Unmap().String(), int(p), true
}

// ParseIPAddrJSON parses `ip -j addr show`.
func ParseIPAddrJSON(b []byte) ([]InterfaceAddr, error) {
	var ifs []struct {
		Ifname   string `json:"ifname"`
		AddrInfo []struct {
			Local     string `json:"local"`
			Prefixlen int    `json:"prefixlen"`
			Scope     string `json:"scope"`
		} `json:"addr_info"`
	}
	if err := json.Unmarshal(b, &ifs); err != nil {
		return nil, fmt.Errorf("ip -j addr: %w", err)
	}
	out := []InterfaceAddr{}
	for _, i := range ifs {
		for _, a := range i.AddrInfo {
			if a.Local == "" {
				continue
			}
			out = append(out, InterfaceAddr{Interface: i.Ifname, Address: a.Local, Prefix: a.Prefixlen, Scope: a.Scope})
		}
	}
	return out, nil
}

// ParseIfInet6 parses /proc/net/if_inet6 (IPv6 addresses only).
func ParseIfInet6(b []byte) []InterfaceAddr {
	out := []InterfaceAddr{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 6 || len(f[0]) != 32 {
			continue
		}
		raw, err := hex.DecodeString(f[0])
		if err != nil {
			continue
		}
		a, ok := netip.AddrFromSlice(raw)
		if !ok {
			continue
		}
		prefix, _ := strconv.ParseInt(f[2], 16, 32)
		out = append(out, InterfaceAddr{Interface: f[5], Address: a.String(), Prefix: int(prefix), Scope: inet6Scope(f[3])})
	}
	return out
}

func inet6Scope(s string) string {
	switch strings.ToLower(s) {
	case "00":
		return "global"
	case "10":
		return "host"
	case "20":
		return "link"
	case "40":
		return "site"
	}
	return s
}
