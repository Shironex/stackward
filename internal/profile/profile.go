// Package profile names the intended ingress of a host. The profile changes
// what checks expect (80/443 open is fine on public-web, a bypass on
// tunnel); it never hides a finding.
package profile

import (
	"fmt"
	"path"
	"strings"

	"github.com/Shironex/stackward/internal/facts"
)

// Name is one ingress profile.
type Name string

// Known profiles. Unknown means "not inferred": checks that depend on the
// profile must then return unknown or judge without it, never pass.
const (
	Unknown     Name = "unknown"
	Tunnel      Name = "tunnel"       // nothing public; ingress through a tunnel
	PublicWeb   Name = "public-web"   // 80/443 public by design
	TailnetOnly Name = "tailnet-only" // reachable over the tailnet only
	PaaSPanel   Name = "paas-panel"   // hosts a PaaS control panel
	// Mixed is inferred only: a tunnel is present and the web ports are
	// public as well (often an origin bypass). It is not a --profile value.
	Mixed Name = "mixed"
)

// All lists the profiles a user may pass to --profile, in display order.
var All = []Name{Tunnel, PublicWeb, TailnetOnly, PaaSPanel}

// Parse validates a --profile value. "auto" and "" mean infer.
func Parse(s string) (Name, bool, error) {
	if s == "" || s == "auto" {
		return Unknown, false, nil
	}
	for _, n := range All {
		if string(n) == s {
			return n, true, nil
		}
	}
	return Unknown, false, fmt.Errorf("unknown profile %q (want auto, tunnel, public-web, tailnet-only or paas-panel)", s)
}

// TailnetReporter is implemented by the Tailscale facts (Facts.Tailscale)
// once that collector lands. Running is true when the node is logged in and
// Running; known is false when the state could not be read. Until a facts
// type implements it, every tailnet dependent answer stays unknown.
type TailnetReporter interface {
	TailnetRunning() (running, known bool)
}

// TunnelReporter is implemented by the Cloudflare Tunnel facts
// (Facts.Cloudflared) once that collector lands. Present is true when a
// connector is running; known is false when it could not be inspected.
type TunnelReporter interface {
	TunnelPresent() (present, known bool)
}

// Tailnet reports what the Tailscale facts say about the tailnet, when they
// exist and implement TailnetReporter.
func Tailnet(f *facts.Facts) (running, known bool) {
	if f == nil || f.Tailscale == nil {
		return false, false
	}
	return tailnetOf(f.Tailscale)
}

func tailnetOf(v any) (running, known bool) {
	if r, ok := v.(TailnetReporter); ok {
		return r.TailnetRunning()
	}
	return false, false
}

// TunnelState reports what the Cloudflare Tunnel facts say, when they exist
// and implement TunnelReporter. A running cloudflared container in the
// Docker facts is a tunnel too, even when the process scan could not see
// other users' processes.
func TunnelState(f *facts.Facts) (present, known bool) {
	if f == nil {
		return false, false
	}
	if TunnelContainers(f) > 0 {
		return true, true
	}
	if f.Cloudflared == nil {
		return false, false
	}
	return tunnelOf(f.Cloudflared)
}

// TunnelContainers counts running containers of the cloudflared image in
// the Docker facts; zero when the Docker API was not read.
func TunnelContainers(f *facts.Facts) int {
	if f == nil || f.Docker == nil || f.Docker.API != "ok" {
		return 0
	}
	n := 0
	for _, c := range f.Docker.Containers {
		if c.Running && IsTunnelImage(c.Image) {
			n++
		}
	}
	return n
}

// IsTunnelImage reports whether an image reference is cloudflared
// (cloudflare/cloudflared, with any registry, tag or digest).
func IsTunnelImage(ref string) bool {
	ref, _, _ = strings.Cut(strings.ToLower(strings.TrimSpace(ref)), "@")
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		ref = ref[:i]
	}
	return path.Base(ref) == "cloudflared"
}

func tunnelOf(v any) (present, known bool) {
	if r, ok := v.(TunnelReporter); ok {
		return r.TunnelPresent()
	}
	return false, false
}

// Seams for tests: the facts types of other slices cannot implement the
// reporter interfaces from a test file.
var (
	tailnetState = Tailnet
	tunnelState  = TunnelState
)

// webPorts are the ports whose public exposure makes a host public-web.
var webPorts = map[int]bool{80: true, 443: true}

// Signals are the observations Infer combines, exported so the report can
// explain an inference and tests can pin it.
type Signals struct {
	// PublicWeb: TCP 80 or 443 listens on a wildcard or public address and
	// the host firewall does not visibly block it.
	PublicWeb bool
	// Tunnel: a Cloudflare Tunnel connector is running (tunnel facts, or a
	// cloudflared process holding a socket).
	Tunnel bool
	// Tailnet: Tailscale is running (tailnet facts, a tailscaled socket, or
	// an address in 100.64.0.0/10 on tailscale0).
	Tailnet bool
	// Panel: the host runs a PaaS control panel (Coolify or Dokploy in the
	// panel role on disk, or the panel's container).
	Panel bool
}

// Detect reads the signals from facts. ok is false when the listeners were
// not inspected, since every signal leans on them.
func Detect(f *facts.Facts) (s Signals, ok bool) {
	if f == nil || f.Listeners == nil {
		return s, false
	}
	l := f.Listeners
	for _, sock := range l.Sockets {
		if sock.Proto == "tcp" && webPorts[sock.Port] && sock.Class().Exposed() && !blockedByFirewall(f.Firewall, sock) {
			s.PublicWeb = true
		}
		if sock.HasProcess("cloudflared") {
			s.Tunnel = true
		}
		if sock.HasProcess("tailscaled") {
			s.Tailnet = true
		}
	}
	for _, a := range l.Addresses {
		if a.Interface == "tailscale0" && facts.ClassifyAddress(a.Address) == facts.BindTailnet {
			s.Tailnet = true
		}
	}
	if present, known := tunnelState(f); known {
		s.Tunnel = present
	}
	if running, known := tailnetState(f); known {
		s.Tailnet = running
	}
	s.Panel = PanelHost(f)
	return s, true
}

// PanelHost reports whether the facts show a PaaS control panel on this
// host: a platform in the panel role in the PaaS facts, or a running panel
// container (coollabsio/coolify, dokploy/dokploy) in the Docker facts.
func PanelHost(f *facts.Facts) bool {
	if f == nil {
		return false
	}
	if f.PaaS != nil {
		for _, p := range f.PaaS.Platforms {
			if p.Role == facts.RolePanel {
				return true
			}
		}
	}
	if f.Docker == nil || f.Docker.API != "ok" {
		return false
	}
	for _, c := range f.Docker.Containers {
		repo, _, _ := strings.Cut(strings.ToLower(c.Image), "@")
		if i := strings.LastIndex(repo, ":"); i > strings.LastIndex(repo, "/") {
			repo = repo[:i]
		}
		if c.Running && (strings.HasSuffix(repo, "coollabsio/coolify") || strings.HasSuffix(repo, "dokploy/dokploy")) {
			return true
		}
	}
	return false
}

// blockedByFirewall reports whether an active UFW with a deny default and
// no rule allowing the port from anywhere keeps the socket closed. Docker
// published ports (docker-proxy) skip UFW's input rules, so they never
// count as blocked here.
func blockedByFirewall(fw *facts.Firewall, l facts.Listener) bool {
	if fw == nil || fw.UFW == nil || l.HasProcess("docker-proxy") {
		return false
	}
	u := fw.UFW
	if !u.Live() || u.Status != "active" || !u.RulesKnown {
		return false
	}
	if u.DefaultIncoming != "deny" && u.DefaultIncoming != "reject" {
		return false
	}
	for _, r := range u.Rules {
		if r.Direction == "in" && r.Allows() && r.FromAnywhere() && r.MatchesPort(l.Proto, l.Port) {
			return false
		}
	}
	return true
}

// Infer guesses the profile from facts.
//
//	panel and public web ports   -> paas-panel (a tunnel may run as well)
//	tunnel and public web ports  -> mixed
//	public web ports             -> public-web
//	tunnel                       -> tunnel
//	tailnet, nothing else        -> tailnet-only
//	no signal or no listeners    -> unknown
func Infer(f *facts.Facts) Name {
	s, ok := Detect(f)
	if !ok {
		return Unknown
	}
	switch {
	case s.Panel && s.PublicWeb:
		// The panel's proxy owns 80 and 443 by design (certificates,
		// every app it deploys); a tunnel beside it is an extra way in,
		// not proof that the public ports are a bypass. PAAS-002 still
		// points out the tunnel.
		return PaaSPanel
	case s.Tunnel && s.PublicWeb:
		return Mixed
	case s.PublicWeb:
		return PublicWeb
	case s.Tunnel:
		return Tunnel
	case s.Tailnet:
		return TailnetOnly
	}
	return Unknown
}
