package provider

import (
	"context"
	"crypto/sha1" //nolint:gosec // G505: OVH's request signature is SHA-1 by the vendor's scheme, not a choice
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Shironex/stackward/internal/facts"
)

// ovhEndpoints maps STACKWARD_OVH_ENDPOINT to the regional API base.
var ovhEndpoints = map[string]string{
	"ovh-eu": "https://eu.api.ovh.com/1.0",
	"ovh-ca": "https://ca.api.ovh.com/1.0",
	"ovh-us": "https://api.us.ovhcloud.com/1.0",
}

// maxOVHRules is the most rules an address can have (sequence 0 to 19).
const maxOVHRules = 20

type ovhCreds struct {
	appKey, appSecret, consumerKey, endpoint string
}

type ovhClient struct {
	g     *getter
	base  string
	creds ovhCreds
	// delta is the server time minus the local time, from /auth/time.
	delta time.Duration
	now   func() time.Time
}

// ovhFirewallIP is GET /ip/{block}/firewall/{ip}.
type ovhFirewallIP struct {
	Enabled bool   `json:"enabled"`
	State   string `json:"state"`
}

// ovhRule is GET /ip/{block}/firewall/{ip}/rule/{sequence}, only the
// fields stackward reads.
type ovhRule struct {
	Sequence        int     `json:"sequence"`
	Action          string  `json:"action"`
	Protocol        string  `json:"protocol"`
	Source          *string `json:"source"`
	SourcePort      *string `json:"sourcePort"`
	DestinationPort *string `json:"destinationPort"`
	TCPOption       *string `json:"tcpOption"`
	Fragments       *bool   `json:"fragments"`
	State           string  `json:"state"`
}

func fetchOVH(ctx context.Context, g *getter, creds ovhCreds, addrs []string, now func() time.Time) *facts.ProviderFirewall {
	pf := &facts.ProviderFirewall{Provider: OVH, Status: facts.ProviderOK, Stateful: false, IPv6Filtered: false}
	if len(addrs) == 0 {
		return noAddresses(pf)
	}
	c := &ovhClient{g: g, base: ovhEndpoints[creds.endpoint], creds: creds, now: now}
	if err := c.syncTime(ctx); err != nil {
		st, reason, _ := classify(err)
		pf.Status, pf.Reason = st, reason
		return pf
	}
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

// syncTime reads the server time (unauthenticated), which the signature
// needs.
func (c *ovhClient) syncTime(ctx context.Context) error {
	b, err := c.g.get(ctx, c.base+"/auth/time", nil)
	if err != nil {
		return err
	}
	secs, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		// The answer is not echoed: it is the provider's text, and the
		// reason ends up in reports.
		return fmt.Errorf("decoding /auth/time: not a number (%d bytes)", len(b))
	}
	c.delta = time.Unix(secs, 0).Sub(c.now())
	return nil
}

// ovhSignature is OVH's request signature: "$1$" and the SHA-1 hex digest
// of secret, consumer key, method, full URL, body and timestamp joined by
// "+".
func ovhSignature(secret, consumer, method, fullURL, body, ts string) string {
	h := sha1.New() //nolint:gosec // G401: the vendor's signature scheme
	h.Write([]byte(strings.Join([]string{secret, consumer, method, fullURL, body, ts}, "+")))
	return "$1$" + hex.EncodeToString(h.Sum(nil))
}

func (c *ovhClient) getJSON(ctx context.Context, path string, v any) error {
	full := c.base + path
	ts := strconv.FormatInt(c.now().Add(c.delta).Unix(), 10)
	hdr := http.Header{
		"X-Ovh-Application": {c.creds.appKey},
		"X-Ovh-Consumer":    {c.creds.consumerKey},
		"X-Ovh-Timestamp":   {ts},
		"X-Ovh-Signature":   {ovhSignature(c.creds.appSecret, c.creds.consumerKey, http.MethodGet, full, "", ts)},
	}
	b, err := c.g.get(ctx, full, hdr)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return fmt.Errorf("decoding %s: %w", strings.SplitN(path, "?", 2)[0], err)
	}
	return nil
}

// target finds the block that holds addr, then its firewall and rules.
func (c *ovhClient) target(ctx context.Context, addr string) (facts.ProviderTarget, error) {
	t := facts.ProviderTarget{Address: addr}
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return t, fmt.Errorf("not an address: %q", addr)
	}
	var blocks []string
	if err := c.getJSON(ctx, "/ip?ip="+url.QueryEscape(addr), &blocks); err != nil {
		return t, err
	}
	// The ip filter is "contains or equals": keep the narrowest block that
	// really contains the address.
	block, found := narrowestContaining(blocks, ip)
	if !found {
		t.Status = facts.ProviderNoMatch
		t.Reason = "no IP block of this account holds this address"
		return t, nil
	}
	t.Status, t.DefaultInbound, t.Ordered, t.RulesComplete = facts.ProviderOK, "allow", true, true
	fwPath := "/ip/" + url.PathEscape(block) + "/firewall"
	var onFirewall []string
	if err := c.getJSON(ctx, fwPath, &onFirewall); err != nil {
		return t, err
	}
	if !contains(onFirewall, addr) {
		return t, nil // no firewall object: nothing filters this address
	}
	var fw ovhFirewallIP
	ipPath := fwPath + "/" + url.PathEscape(addr)
	if err := c.getJSON(ctx, ipPath, &fw); err != nil {
		return t, err
	}
	t.Attached, t.Firewalls, t.State = true, 1, fw.State
	t.Pending = fw.State != "ok"
	// A pending disable still filters until it is applied; a pending enable
	// does not filter yet.
	t.Enabled = fw.Enabled && fw.State != "enableFirewallPending"
	if err := c.rules(ctx, ipPath, &t); err != nil {
		return t, err
	}
	return t, nil
}

// rules reads every rule of the address, one request per sequence.
func (c *ovhClient) rules(ctx context.Context, ipPath string, t *facts.ProviderTarget) error {
	var seqs []int
	if err := c.getJSON(ctx, ipPath+"/rule", &seqs); err != nil {
		return err
	}
	if len(seqs) > maxOVHRules {
		seqs, t.RulesComplete = seqs[:maxOVHRules], false
	}
	for _, seq := range seqs {
		var r ovhRule
		if err := c.getJSON(ctx, ipPath+"/rule/"+strconv.Itoa(seq), &r); err != nil {
			if _, _, fatal := classify(err); fatal {
				return err
			}
			t.RulesComplete = false
			continue
		}
		nr, err := normaliseOVH(r)
		if err != nil {
			t.RulesComplete = false
			continue
		}
		if nr.Pending {
			t.Pending = true
		}
		t.Rules = append(t.Rules, nr)
	}
	return nil
}

func narrowestContaining(blocks []string, ip netip.Addr) (string, bool) {
	best, bits := "", -1
	for _, b := range blocks {
		p, err := netip.ParsePrefix(b)
		if err != nil {
			a, aerr := netip.ParseAddr(b)
			if aerr != nil {
				continue
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if p.Contains(ip) && p.Bits() > bits {
			best, bits = b, p.Bits()
		}
	}
	return best, bits >= 0
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// normaliseOVH turns an OVH rule into a facts rule. The Edge Network
// Firewall filters inbound traffic only.
func normaliseOVH(r ovhRule) (facts.ProviderRule, error) {
	nr := facts.ProviderRule{Order: r.Sequence, Direction: "in", Action: r.Action, Protocol: r.Protocol, Pending: r.State != "ok"}
	if r.Action != "permit" && r.Action != "deny" {
		return nr, fmt.Errorf("unknown action %q", r.Action)
	}
	if r.Source != nil {
		src, err := ovhSource(*r.Source)
		if err != nil {
			return nr, err
		}
		nr.Sources = src
	}
	var err error
	if nr.SrcPorts, err = parseOVHPorts(r.SourcePort); err != nil {
		return nr, err
	}
	if nr.DstPorts, err = parseOVHPorts(r.DestinationPort); err != nil {
		return nr, err
	}
	if r.TCPOption != nil {
		switch opt := strings.ToLower(strings.TrimSpace(*r.TCPOption)); {
		case opt == "":
		case strings.Contains(opt, "established"):
			nr.TCPOption = "established"
		case strings.Contains(opt, "syn"):
			nr.TCPOption = "syn"
		default:
			return nr, fmt.Errorf("unknown tcp option %q", opt)
		}
	}
	nr.Fragments = r.Fragments != nil && *r.Fragments
	return nr, nil
}

// ovhSource normalises a rule source: "any" (or empty, or 0.0.0.0/0) is any
// source, an IPv4 prefix stays as it is, a bare IPv4 address becomes a /32
// (a bare 0.0.0.0 too: it names one host, not every one). The Edge Network
// Firewall filters IPv4 only, so an IPv6 or IPv4-mapped source is refused,
// like anything else that does not parse: the read counts as partial
// instead of the checks guessing what the source covers.
func ovhSource(s string) ([]string, error) {
	s = strings.TrimSpace(s)
	switch s {
	case "", "any", "0.0.0.0/0":
		return nil, nil
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		if !p.Addr().Is4() {
			return nil, fmt.Errorf("source %q is not IPv4", s)
		}
		return []string{p.String()}, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return nil, fmt.Errorf("source %q is neither an address nor a prefix", s)
	}
	if !a.Is4() {
		return nil, fmt.Errorf("source %q is not IPv4", s)
	}
	return []string{netip.PrefixFrom(a, 32).String()}, nil
}

// parseOVHPorts reads the port strings OVH prints: "53", "eq 53",
// "1000-2000", "range 1000 2000", "gt 1023", "lt 1024". Nil or empty means
// any port. Anything else is an error, so the rule read counts as partial
// rather than being guessed.
func parseOVHPorts(p *string) ([]facts.PortRange, error) {
	if p == nil {
		return nil, nil
	}
	s := strings.ToLower(strings.TrimSpace(*p))
	if s == "" {
		return nil, nil
	}
	f := strings.Fields(strings.NewReplacer("-", " ", ":", " ").Replace(s))
	switch {
	case len(f) == 2 && f[0] == "eq":
		return parsePortSpec(f[1])
	case len(f) == 3 && f[0] == "range":
		return parsePortSpec(f[1] + "-" + f[2])
	case len(f) == 2 && f[0] == "gt":
		n, err := parsePort(f[1])
		if err != nil || n == 65535 {
			return nil, fmt.Errorf("bad port %q", s)
		}
		return parsePortSpec(strconv.Itoa(n+1) + "-65535")
	case len(f) == 2 && f[0] == "lt":
		n, err := parsePort(f[1])
		if err != nil || n == 1 {
			return nil, fmt.Errorf("bad port %q", s)
		}
		return parsePortSpec("1-" + strconv.Itoa(n-1))
	case len(f) == 1:
		return parsePortSpec(f[0])
	case len(f) == 2:
		return parsePortSpec(f[0] + "-" + f[1])
	}
	return nil, fmt.Errorf("unrecognised port %q", s)
}
