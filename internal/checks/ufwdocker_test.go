package checks

import (
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/profile"
)

// ufwDockerNFTRules is ufwDockerRules as nft lists them on iptables-nft.
var ufwDockerNFTRules = []string{
	"jump ufw-user-forward",
	"ct state established,related return",
	"ct state invalid drop",
	"iifname docker0 oifname docker0 accept",
	"ip saddr 10.0.0.0/8 return",
	"ip saddr 172.16.0.0/12 return",
	"ip saddr 192.168.0.0/16 return",
	"ip daddr 10.0.0.0/8 ct state new jump ufw-docker-logging-deny",
	"ip daddr 172.16.0.0/12 ct state new jump ufw-docker-logging-deny",
	"ip daddr 192.168.0.0/16 ct state new jump ufw-docker-logging-deny",
	"return",
}

var route443 = facts.UFWRule{Action: "allow", Direction: "fwd", Port: "443", Proto: "tcp"}

// ufwDockerHost publishes 443 (web) and 8000 (panel) on all interfaces
// behind a standard ufw-docker chain, with the given route rules. nft
// lists the chain in nft syntax instead of iptables -S.
func ufwDockerHost(nft bool, routes ...facts.UFWRule) *facts.Facts {
	f := exposureHost("filtered", ufwDockerRules,
		app("web", publish("0.0.0.0", 443, 443)), app("panel", publish("0.0.0.0", 8000, 8000)))
	f.Firewall.UFWDocker = &facts.UFWDocker{InFiles: "present", Loaded: "yes"}
	f.Firewall.UFW.Rules = append(f.Firewall.UFW.Rules, routes...)
	if nft {
		f.Firewall.Iptables = &facts.Iptables{Installed: true, Backend: "nf_tables"}
		f.Firewall.NFT = &facts.NFTables{Installed: true, Listed: true, DockerUser: true, DockerUserRules: ufwDockerNFTRules,
			Tables: []facts.NFTTable{{Family: "ip", Name: "filter"}}}
	}
	f.Listeners.Sockets = []facts.Listener{
		netSock("tcp", "0.0.0.0", 443, "docker-proxy"), netSock("tcp", "0.0.0.0", 8000, "docker-proxy"),
	}
	return f
}

func TestUFWDockerRouteRules(t *testing.T) {
	for _, nft := range []bool{false, true} {
		form := map[bool]string{false: "iptables", true: "nft"}[nft]
		f := ufwDockerHost(nft, route443)
		got := map[string]Level{}
		for _, r := range checkExposure(Input{Facts: f}) {
			got[r.Subject] = r.Level
		}
		if got["port:tcp/443"] != Info || got["port:tcp/8000"] != Pass {
			t.Errorf("%s: NET-004 = %v, want 443 info, 8000 pass", form, got)
		}
		got = levels(checkPublishedPorts(Input{Facts: f, Profile: profile.Unknown}))
		if got["container:web"] != Warn || got["container:panel"] != Pass {
			t.Errorf("%s: DKR-001 = %v, want web warn (route rule), panel pass", form, got)
		}
		got = levels(checkPublishedPorts(Input{Facts: f, Profile: profile.PublicWeb}))
		if got["container:web"] != Pass {
			t.Errorf("%s: DKR-001 on public-web = %v, want web pass", form, got)
		}
		f.Cloudflared = cfTunnel(2)
		if r := netOne(t, "CF-003", f, ""); r.Level != Fail || !strings.Contains(r.Message, "tcp/443") || strings.Contains(r.Message, "not analysed") {
			t.Errorf("%s: CF-003 = %s (%s), want fail on tcp/443", form, r.Level, r.Message)
		}
		if got := paasDockerFilter(f, "tcp", 8000); got != paasFilterApplied {
			t.Errorf("%s: panel port filter = %s, want filtered", form, got)
		}
		if got := paasDockerFilter(f, "tcp", 443); got != paasFilterNone {
			t.Errorf("%s: 443 filter = %s, want none", form, got)
		}
		if got := profile.Infer(f); got == profile.Unknown || got == profile.TailnetOnly {
			t.Errorf("%s: profile = %s, want a public web profile", form, got)
		}
	}
}

func TestUFWDockerDenyAll(t *testing.T) {
	for _, nft := range []bool{false, true} {
		form := map[bool]string{false: "iptables", true: "nft"}[nft]
		f := ufwDockerHost(nft)
		for _, r := range checkExposure(Input{Facts: f}) {
			if r.Level != Pass {
				t.Errorf("%s: NET-004 %s = %s (%s), want pass", form, r.Subject, r.Level, r.Message)
			}
		}
		for subj, l := range levels(checkPublishedPorts(Input{Facts: f, Profile: profile.Tunnel})) {
			if l != Pass {
				t.Errorf("%s: DKR-001 %s = %s, want pass", form, subj, l)
			}
		}
		f.Cloudflared = cfTunnel(2)
		if r := netOne(t, "CF-003", f, ""); r.Level != Pass {
			t.Errorf("%s: CF-003 = %s (%s), want pass", form, r.Level, r.Message)
		}
		if got := profile.Infer(f); got != profile.Tunnel {
			t.Errorf("%s: profile = %s, want tunnel (443 is not reachable)", form, got)
		}
	}
}

// TestUFWDockerUnrecognisedChain: an extra rule ufw-docker does not
// install keeps the published ports unknown, never pass.
func TestUFWDockerUnrecognisedChain(t *testing.T) {
	f := ufwDockerHost(false)
	f.Firewall.Iptables.DockerUserRules = append([]string{"-A DOCKER-USER -m set --match-set allow src -j RETURN"}, ufwDockerRules...)
	for _, r := range checkPublishedPorts(Input{Facts: f, Profile: profile.Unknown}) {
		if r.Level != Unknown || !strings.Contains(r.Message, "does not analyse") {
			t.Errorf("DKR-001 %s = %s (%s), want unknown", r.Subject, r.Level, r.Message)
		}
	}
	for _, r := range checkExposure(Input{Facts: f}) {
		if r.Level == Pass {
			t.Errorf("NET-004 %s passed on an unrecognised chain", r.Subject)
		}
	}
	// Without the Docker API the container port is unknown.
	g := ufwDockerHost(false)
	g.Docker.API = "denied"
	for _, r := range checkExposure(Input{Facts: g}) {
		if r.Level == Pass {
			t.Errorf("NET-004 %s passed without the Docker API", r.Subject)
		}
	}
}
