package facts

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
)

// ProviderFirewall is what a cloud provider's network firewall API said
// about this host (the PFW checks and NET-009). It is filled by the
// internal/provider client, not by a collector: the provider is asked over
// its API, opt in (--provider), before the sandbox. Nil means the module was
// not requested.
//
// No token, account or project id, firewall id, name, description or label
// is ever stored here: facts files are attached to bug reports.
type ProviderFirewall struct {
	// Provider is "hetzner" or "ovh".
	Provider string `json:"provider"`
	// Status is the outcome for the provider as a whole. Per address
	// outcomes are in Targets.
	Status ProviderStatus `json:"status"`
	// Reason explains a status other than ok in words a user can act on.
	Reason string `json:"reason,omitempty"`
	// Stateful is true when the provider tracks connections, so replies to
	// traffic the host started need no inbound rule (Hetzner). Set by the
	// client from what the provider can do, so checks do not test names.
	Stateful bool `json:"stateful"`
	// IPv6Filtered is true when the provider firewall can filter IPv6
	// traffic (Hetzner yes, OVH no).
	IPv6Filtered bool `json:"ipv6_filtered"`
	// Targets has one entry per public address that was asked about.
	Targets []ProviderTarget `json:"targets,omitempty"`
}

// ProviderStatus is the outcome of asking the provider.
type ProviderStatus string

// Provider outcomes. Only ProviderOK carries data a check may judge.
const (
	ProviderOK            ProviderStatus = "ok"
	ProviderNoCredentials ProviderStatus = "no_credentials"
	ProviderDenied        ProviderStatus = "denied"   // 401 or 403
	ProviderNoMatch       ProviderStatus = "no_match" // no resource has this address
	ProviderUnreachable   ProviderStatus = "unreachable"
	ProviderError         ProviderStatus = "error"
)

// ProviderTarget is the provider firewall in front of one public address.
type ProviderTarget struct {
	// Address is the public address that was matched.
	Address string         `json:"address"`
	Status  ProviderStatus `json:"status"`
	Reason  string         `json:"reason,omitempty"`
	// Attached is true when a firewall object exists for the address
	// (Hetzner: at least one firewall on the server; OVH: the address is on
	// the firewall, enabled or not).
	Attached bool `json:"attached"`
	// Enabled is true when the firewall filters traffic now: Hetzner at
	// least one attached firewall is applied, OVH the firewall is enabled
	// and not waiting for a change.
	Enabled bool `json:"enabled"`
	// State is the provider's own word for the firewall state (Hetzner
	// "applied" or "pending", OVH "ok", "enableFirewallPending",
	// "disableFirewallPending").
	State string `json:"state,omitempty"`
	// Pending is true when a firewall or a rule change is not in force yet.
	Pending bool `json:"pending,omitempty"`
	// Firewalls counts the firewalls attached to the address.
	Firewalls int `json:"firewalls"`
	// DefaultInbound is what happens to inbound traffic no rule matches
	// while the firewall is enabled: "deny" (Hetzner) or "allow" (OVH).
	DefaultInbound string `json:"default_inbound,omitempty"`
	// Ordered is true when rules are evaluated in Order and the first
	// match wins (OVH). Hetzner rules only permit, so order does not
	// matter there.
	Ordered bool `json:"ordered"`
	// RulesComplete is false when some rule could not be read; checks that
	// need every rule then answer unknown.
	RulesComplete bool           `json:"rules_complete"`
	Rules         []ProviderRule `json:"rules,omitempty"`
}

// ProviderRule is one normalised firewall rule.
type ProviderRule struct {
	// Order is the OVH sequence (0 to 19), or the rule's position across
	// the attached Hetzner firewalls.
	Order int `json:"order"`
	// Direction is "in" or "out".
	Direction string `json:"direction"`
	// Action is "permit" or "deny".
	Action string `json:"action"`
	// Protocol is "tcp", "udp", "icmp", "esp", "gre", "ah" or "ipv4" (every
	// IPv4 packet, OVH only).
	Protocol string `json:"protocol"`
	// Sources are the source networks of an inbound rule in CIDR form.
	// Empty means any source.
	Sources []string `json:"sources,omitempty"`
	// Destinations are the destination networks of an outbound rule.
	// Empty means any destination.
	Destinations []string `json:"destinations,omitempty"`
	// DstPorts and SrcPorts are port ranges. Empty means any port.
	DstPorts []PortRange `json:"dst_ports,omitempty"`
	SrcPorts []PortRange `json:"src_ports,omitempty"`
	// TCPOption is "established" or "syn" when the rule only matches TCP
	// packets with those flags (OVH).
	TCPOption string `json:"tcp_option,omitempty"`
	// Fragments is true when the rule only matches fragments (OVH).
	Fragments bool `json:"fragments,omitempty"`
	// Pending is true when the rule is being created or removed, or its
	// firewall is not applied yet: it is not in force.
	Pending bool `json:"pending,omitempty"`
}

// PortRange is an inclusive port range; From equals To for one port.
type PortRange struct {
	From int `json:"from"`
	To   int `json:"to"`
}

// String formats the range as "22" or "1000-2000".
func (p PortRange) String() string {
	if p.From == p.To {
		return fmt.Sprintf("%d", p.From)
	}
	return fmt.Sprintf("%d-%d", p.From, p.To)
}

// PublicIPv4Candidates reads the interface addresses (ip -j addr show, the
// same read only command the listeners collector runs) and returns the
// public IPv4 addresses, sorted: global scope, not private, loopback, link
// local or the shared range Tailscale uses (100.64.0.0/10). The CLI calls it
// before the sandbox, to know which addresses to ask the provider about.
func PublicIPv4Candidates(ctx context.Context, sys System) ([]string, error) {
	res, err := sys.Run(ctx, "ip", "-j", "addr", "show")
	if err != nil {
		return nil, err
	}
	if res.ExitCode != 0 {
		return nil, fmt.Errorf("ip exited %d: %s", res.ExitCode, firstLine(res.Stderr))
	}
	addrs, err := ParseIPAddrJSON(res.Stdout)
	if err != nil {
		return nil, err
	}
	return PublicIPv4(addrs), nil
}

// PublicIPv4 filters interface addresses down to public IPv4 addresses,
// sorted and without duplicates.
func PublicIPv4(addrs []InterfaceAddr) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range addrs {
		ip, err := netip.ParseAddr(a.Address)
		if err != nil || !ip.Is4() || seen[ip.String()] {
			continue
		}
		if a.Scope != "" && a.Scope != "global" {
			continue
		}
		if ClassifyAddress(ip.String()) != BindPublic || !ip.IsGlobalUnicast() {
			continue
		}
		seen[ip.String()] = true
		out = append(out, ip.String())
	}
	sort.Strings(out)
	return out
}
