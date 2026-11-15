package probe

import (
	"net"
	"net/netip"
	"sort"
)

// LocalAddrs lists the addresses of this machine's network interfaces. It is
// a seam so tests can pretend to be any machine.
type LocalAddrs func() ([]netip.Addr, error)

// InterfaceAddrs is the LocalAddrs that asks the operating system.
func InterfaceAddrs() ([]netip.Addr, error) {
	list, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, a := range list {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		if addr, ok := netip.AddrFromSlice(ip); ok {
			out = append(out, addr.Unmap().WithZone(""))
		}
	}
	return out, nil
}

// selfAddresses returns the resolved addresses that are loopback or belong to
// a local interface, sorted. An error from the interface lookup only means
// the loopback test is all that can be applied.
func selfAddresses(resolved []Address, local LocalAddrs) []string {
	mine := map[netip.Addr]bool{}
	if local != nil {
		if addrs, err := local(); err == nil {
			for _, a := range addrs {
				mine[a.Unmap().WithZone("")] = true
			}
		}
	}
	var out []string
	for _, r := range resolved {
		a, err := netip.ParseAddr(r.Address)
		if err != nil {
			continue
		}
		a = a.Unmap().WithZone("")
		if a.IsLoopback() || mine[a] {
			out = append(out, a.String())
		}
	}
	sort.Strings(out)
	return out
}

// SelfNote is the sentence reports carry when the target is this machine.
const SelfNote = "this target is the machine probe runs on (loopback or a local interface address), so the results are not an outside view: services bound to loopback answer here but may not be reachable from the internet; run probe from another machine"
