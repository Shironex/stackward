package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/Shironex/stackward/internal/facts"
)

const hetznerBase = "https://api.hetzner.cloud/v1"

// maxFloatingPages bounds the floating IP listing (50 per page).
const maxFloatingPages = 20

type hetznerClient struct {
	g   *getter
	hdr http.Header
}

// Hetzner Cloud API answers, only the fields stackward reads. Names,
// labels and descriptions are never decoded.
type hzPrimaryIPs struct {
	PrimaryIPs []struct {
		IP           string `json:"ip"`
		AssigneeType string `json:"assignee_type"`
		AssigneeID   *int64 `json:"assignee_id"`
	} `json:"primary_ips"`
}

type hzFloatingIPs struct {
	FloatingIPs []struct {
		IP     string `json:"ip"`
		Server *int64 `json:"server"`
	} `json:"floating_ips"`
	Meta struct {
		Pagination *struct {
			NextPage *int `json:"next_page"`
		} `json:"pagination"`
	} `json:"meta"`
}

type hzServer struct {
	Server struct {
		PublicNet struct {
			Firewalls []struct {
				ID     int64  `json:"id"`
				Status string `json:"status"`
			} `json:"firewalls"`
		} `json:"public_net"`
	} `json:"server"`
}

type hzFirewall struct {
	Firewall struct {
		Rules []hzRule `json:"rules"`
	} `json:"firewall"`
}

type hzRule struct {
	Direction      string   `json:"direction"`
	Protocol       string   `json:"protocol"`
	Port           *string  `json:"port"`
	SourceIPs      []string `json:"source_ips"`
	DestinationIPs []string `json:"destination_ips"`
}

func fetchHetzner(ctx context.Context, g *getter, token string, addrs []string) *facts.ProviderFirewall {
	pf := &facts.ProviderFirewall{Provider: Hetzner, Status: facts.ProviderOK, Stateful: true, IPv6Filtered: true}
	if len(addrs) == 0 {
		return noAddresses(pf)
	}
	c := &hetznerClient{g: g, hdr: http.Header{"Authorization": {"Bearer " + token}}}
	for _, a := range addrs {
		t, err := c.target(ctx, a)
		if err != nil {
			st, reason, fatal := classify(err)
			if fatal {
				pf.Status, pf.Reason, pf.Targets = st, reason, nil
				return pf
			}
			t = facts.ProviderTarget{Address: a, Status: st, Reason: reason}
		}
		pf.Targets = append(pf.Targets, t)
	}
	return pf
}

func (c *hetznerClient) getJSON(ctx context.Context, path string, v any) error {
	b, err := c.g.get(ctx, hetznerBase+path, c.hdr)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("decoding %s: %w", strings.SplitN(path, "?", 2)[0], err)
	}
	return nil
}

// target matches addr to a server and reads its firewalls.
func (c *hetznerClient) target(ctx context.Context, addr string) (facts.ProviderTarget, error) {
	t := facts.ProviderTarget{Address: addr}
	id, found, err := c.serverFor(ctx, addr)
	if err != nil {
		return t, err
	}
	if !found {
		t.Status = facts.ProviderNoMatch
		t.Reason = "no server of this project has this address as its primary or a floating IP"
		return t, nil
	}
	var srv hzServer
	if err := c.getJSON(ctx, "/servers/"+strconv.FormatInt(id, 10), &srv); err != nil {
		return t, err
	}
	t.Status, t.DefaultInbound, t.RulesComplete = facts.ProviderOK, "deny", true
	fws := srv.Server.PublicNet.Firewalls
	t.Firewalls, t.Attached = len(fws), len(fws) > 0
	order := 0
	for _, fw := range fws {
		applied := fw.Status == "applied"
		if applied {
			t.Enabled = true
		} else {
			t.Pending = true
		}
		var body hzFirewall
		if err := c.getJSON(ctx, "/firewalls/"+strconv.FormatInt(fw.ID, 10), &body); err != nil {
			if _, _, fatal := classify(err); fatal {
				return t, err
			}
			t.RulesComplete = false
			continue
		}
		for _, r := range body.Firewall.Rules {
			nr, err := normaliseHetzner(r, order, !applied)
			if err != nil {
				t.RulesComplete = false
				continue
			}
			t.Rules = append(t.Rules, nr)
			order++
		}
	}
	t.State = hetznerState(t)
	return t, nil
}

func hetznerState(t facts.ProviderTarget) string {
	switch {
	case !t.Attached:
		return ""
	case t.Pending:
		return "pending"
	}
	return "applied"
}

// serverFor finds the server that holds addr: as its primary IP, or, when
// no primary IP has it, as a floating IP assigned to it.
func (c *hetznerClient) serverFor(ctx context.Context, addr string) (int64, bool, error) {
	var p hzPrimaryIPs
	if err := c.getJSON(ctx, "/primary_ips?ip="+url.QueryEscape(addr), &p); err != nil {
		return 0, false, err
	}
	for _, ip := range p.PrimaryIPs {
		if ip.IP == addr {
			if ip.AssigneeType == "server" && ip.AssigneeID != nil {
				return *ip.AssigneeID, true, nil
			}
			return 0, false, nil
		}
	}
	// The floating IP list has no ip filter, so it is paged through and
	// matched exactly.
	for page := 1; page <= maxFloatingPages; page++ {
		var f hzFloatingIPs
		if err := c.getJSON(ctx, fmt.Sprintf("/floating_ips?page=%d&per_page=50", page), &f); err != nil {
			return 0, false, err
		}
		for _, ip := range f.FloatingIPs {
			if ip.IP == addr && ip.Server != nil {
				return *ip.Server, true, nil
			}
		}
		if f.Meta.Pagination == nil || f.Meta.Pagination.NextPage == nil {
			break
		}
	}
	return 0, false, nil
}

// normaliseHetzner turns a Hetzner rule into a facts rule. Hetzner rules
// only permit.
func normaliseHetzner(r hzRule, order int, pending bool) (facts.ProviderRule, error) {
	nr := facts.ProviderRule{Order: order, Direction: r.Direction, Action: "permit", Protocol: r.Protocol, Pending: pending}
	switch r.Direction {
	case "in":
		nr.Sources = r.SourceIPs
	case "out":
		nr.Destinations = r.DestinationIPs
	default:
		return nr, fmt.Errorf("unknown direction %q", r.Direction)
	}
	if r.Port != nil {
		pr, err := parsePortSpec(*r.Port)
		if err != nil {
			return nr, err
		}
		nr.DstPorts = pr
	}
	return nr, nil
}

// parsePortSpec reads "80", "80-85" or "any" (nil: every port).
func parsePortSpec(s string) ([]facts.PortRange, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "any" {
		return nil, nil
	}
	lo, hi, isRange := strings.Cut(s, "-")
	from, err := parsePort(lo)
	if err != nil {
		return nil, err
	}
	to := from
	if isRange {
		if to, err = parsePort(hi); err != nil {
			return nil, err
		}
	}
	if to < from {
		return nil, fmt.Errorf("port range %q runs backwards", s)
	}
	if from == 1 && to == 65535 {
		return nil, nil
	}
	return []facts.PortRange{{From: from, To: to}}, nil
}

func parsePort(s string) (int, error) {
	p, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || p < 1 || p > 65535 {
		return 0, fmt.Errorf("bad port %q", s)
	}
	return p, nil
}
