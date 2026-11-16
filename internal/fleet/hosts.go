// Package fleet runs the read only audit on other machines over the user's
// own ssh client (stackward audit --ssh): it checks each host's
// architecture, streams a matching stackward binary into a private
// temporary directory there, runs the same audit, reads the report.v1 JSON
// from its standard output and removes the directory again. It never
// embeds an SSH library and never sees a key or a password: ssh and the
// user's ssh config do all of that.
package fleet

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// MaxHosts caps one run, so a wrong file cannot start thousands of
// connections.
const MaxHosts = 256

// hostPattern is what a host may look like: an optional user@ prefix and a
// name, an alias from the ssh config, an IPv4 address or a bare IPv6
// address. No shell or ssh token characters (space, quote, ';', '%', '$',
// '/'), and the first character is never '-', so a host can never be read
// as an ssh option or expand in a ProxyCommand.
var hostPattern = regexp.MustCompile(`^([A-Za-z0-9_][A-Za-z0-9._-]{0,63}@)?[A-Za-z0-9][A-Za-z0-9._:-]{0,252}$`)

// ValidateHost refuses anything that is not a plain host name for ssh.
func ValidateHost(h string) error {
	switch {
	case h == "":
		return errors.New("empty host name")
	case strings.HasPrefix(h, "-"):
		return fmt.Errorf("host %q starts with '-': refused, ssh would read it as an option (put flags before the hosts)", h)
	case !hostPattern.MatchString(h):
		return fmt.Errorf("host %q refused: use a name from your ssh config, user@name or an address (letters, digits, '.', '-', '_', ':')", h)
	}
	return nil
}

// ReadHosts reads a hosts file: one host per line, blank lines and lines
// starting with '#' are skipped, and so is anything after a '#'.
func ReadHosts(r io.Reader) ([]string, error) {
	var hosts []string
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if err := ValidateHost(line); err != nil {
			return nil, fmt.Errorf("line %d: %w", n, err)
		}
		hosts = append(hosts, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return hosts, nil
}

// Hosts validates and joins the hosts from the command line and a hosts
// file, keeping the first of any duplicate, in order.
func Hosts(groups ...[]string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, g := range groups {
		for _, h := range g {
			if err := ValidateHost(h); err != nil {
				return nil, err
			}
			if seen[h] {
				continue
			}
			seen[h] = true
			out = append(out, h)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no host given: name hosts after the flags or pass --ssh-hosts FILE")
	}
	if len(out) > MaxHosts {
		return nil, fmt.Errorf("%d hosts given, at most %d per run", len(out), MaxHosts)
	}
	return out, nil
}
