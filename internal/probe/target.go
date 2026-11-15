package probe

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// maxHostLen is the longest DNS name (RFC 1035).
const maxHostLen = 253

// ParseTarget validates the one host probe may look at: a DNS name or a
// single IPv4 or IPv6 address. Ranges, CIDR blocks, lists, URLs and ports
// are refused, so probe can never be turned into a scanner.
func ParseTarget(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("give one host name or IP address to probe")
	}
	switch {
	case strings.Contains(s, "/"):
		if _, err := netip.ParsePrefix(s); err == nil {
			return "", fmt.Errorf("%q is a network range: probe takes one host, never a range", s)
		}
		return "", fmt.Errorf("%q is not a host: give a name or an IP address, not a URL or path", s)
	case strings.ContainsAny(s, ",* \t"):
		return "", fmt.Errorf("%q is not a single host: probe takes one host, never a list or pattern", s)
	}
	// A bracketed IPv6 address, as people paste it from URLs.
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		s = s[1 : len(s)-1]
	}
	if a, err := netip.ParseAddr(s); err == nil {
		if a.Zone() != "" {
			return "", fmt.Errorf("%q has an interface zone: probe a routable address from another machine", s)
		}
		if a.IsUnspecified() || a.IsMulticast() {
			return "", fmt.Errorf("%q is not a single host address", s)
		}
		return a.Unmap().String(), nil
	}
	if looksLikeRange(s) {
		return "", fmt.Errorf("%q looks like an address range: probe takes one host, never a range", s)
	}
	if strings.Contains(s, ":") {
		return "", fmt.Errorf("%q is not a host: give the port with --ports, not host:port", s)
	}
	if err := validHostname(s); err != nil {
		return "", err
	}
	return strings.ToLower(strings.TrimSuffix(s, ".")), nil
}

// looksLikeRange catches "192.0.2.1-20" and "192.0.2.1-192.0.2.9".
func looksLikeRange(s string) bool {
	if !strings.Contains(s, "-") {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && r != '.' && r != '-' && r != ':' && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	first, _, _ := strings.Cut(s, "-")
	_, err := netip.ParseAddr(first)
	return err == nil
}

func validHostname(s string) error {
	name := strings.TrimSuffix(s, ".")
	if name == "" || len(name) > maxHostLen {
		return fmt.Errorf("%q is not a valid host name", s)
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("%q is not a valid host name", s)
		}
		for _, r := range label {
			if !hostRune(r) {
				return fmt.Errorf("%q is not a valid host name", s)
			}
		}
	}
	return nil
}

func hostRune(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_'
}

// ParseHostname validates --hostname: a DNS name with an optional port
// (app.example.com or app.example.com:8443). A scheme or path is refused.
func ParseHostname(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	if strings.Contains(s, "://") || strings.Contains(s, "/") {
		return "", fmt.Errorf("--hostname %q: give the host name only, without scheme or path", s)
	}
	host, port := s, ""
	if h, p, err := net.SplitHostPort(s); err == nil {
		host, port = h, p
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("--hostname %q: bad port", s)
		}
	}
	if _, err := netip.ParseAddr(host); err != nil {
		if err := validHostname(host); err != nil {
			return "", fmt.Errorf("--hostname: %w", err)
		}
		host = strings.ToLower(strings.TrimSuffix(host, "."))
	}
	if port != "" {
		return net.JoinHostPort(host, port), nil
	}
	return host, nil
}

// maxExtraPorts bounds --ports so probe stays a short fixed list.
const maxExtraPorts = 16

// ParsePorts parses --ports: a comma separated list of TCP ports. Ranges
// are refused on purpose.
func ParsePorts(s string) ([]int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	seen := map[int]bool{}
	var out []int
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if strings.Contains(f, "-") {
			return nil, fmt.Errorf("--ports %q: list single ports, ranges are not supported", f)
		}
		n, err := strconv.Atoi(f)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("--ports: %q is not a TCP port", f)
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	if len(out) > maxExtraPorts {
		return nil, fmt.Errorf("--ports: at most %d extra ports", maxExtraPorts)
	}
	sort.Ints(out)
	return out, nil
}

func parseIP(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(s)
	return a, err == nil
}
