package plan

import (
	"fmt"
	"slices"
	"strings"

	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/profile"
)

// ufw-docker: filter published container ports with UFW (DKR-001).
// Docker publishes ports through DNAT and accepts them in its FORWARD
// rules, so UFW's input rules never see them. The well known ufw-docker
// rule set (https://github.com/chaifeng/ufw-docker, its README's block
// for /etc/ufw/after.rules) sends new connections to containers through
// DOCKER-USER: UFW's route rules (ufw-user-forward) accept them, and
// everything else from outside the private ranges is dropped.
//
// stackward writes that block itself, as an edit of after.rules checked
// with iptables-restore --test; it never downloads the ufw-docker script
// or a package. In the same step it adds the route rules that keep open
// what must stay open: everything on tailscale0 when Tailscale is
// installed, and the container ports the ingress profile says are public
// (the web ports on public-web and paas-panel hosts) or that serve a PaaS
// panel the profile does not move behind a tunnel or the tailnet. Every
// other published port closes to the internet, and the step lists which.
//
// It needs UFW on with a deny default (the ufw-policy step), Docker's
// iptables backend (its nftables backend has no DOCKER-USER chain, so the
// block would filter nothing; stackward refuses it there) and a
// DOCKER-USER chain with nothing but Docker's own RETURN, which the undo
// puts back. It is opt in and access-critical: published ports change
// for every client, so it runs in the rollback transaction.

// UFWDockerID is the id of the ufw-docker step.
const UFWDockerID = "ufw-docker"

func init() {
	Register(Generator{
		ID:    UFWDockerID,
		Title: "Filter published container ports with UFW (ufw-docker rules)",
		Fixes: []string{"DKR-001", "PAAS-002", "PAAS-003"},
		Risk:  AccessCritical,
		Order: orderUFWDocker,
		OptIn: true,
		Plan:  planUFWDocker,

		Authorize: authorizeUFWDocker,
		Check:     checkEditsHold,
		Access:    accessUFWDocker,
	})
}

// ufwDockerBlock is the block the ufw-docker README tells you to append
// to /etc/ufw/after.rules, unchanged.
const ufwDockerBlock = `# BEGIN UFW AND DOCKER
*filter
:ufw-user-forward - [0:0]
:ufw-docker-logging-deny - [0:0]
:DOCKER-USER - [0:0]
-A DOCKER-USER -j ufw-user-forward

-A DOCKER-USER -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
-A DOCKER-USER -m conntrack --ctstate INVALID -j DROP
-A DOCKER-USER -i docker0 -o docker0 -j ACCEPT

-A DOCKER-USER -j RETURN -s 10.0.0.0/8
-A DOCKER-USER -j RETURN -s 172.16.0.0/12
-A DOCKER-USER -j RETURN -s 192.168.0.0/16

-A DOCKER-USER -j ufw-docker-logging-deny -m conntrack --ctstate NEW -d 10.0.0.0/8
-A DOCKER-USER -j ufw-docker-logging-deny -m conntrack --ctstate NEW -d 172.16.0.0/12
-A DOCKER-USER -j ufw-docker-logging-deny -m conntrack --ctstate NEW -d 192.168.0.0/16

-A DOCKER-USER -j RETURN

-A ufw-docker-logging-deny -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix "[UFW DOCKER BLOCK] "
-A ufw-docker-logging-deny -j DROP

COMMIT
# END UFW AND DOCKER
`

const (
	ufwDockerMarker  = "# BEGIN UFW AND DOCKER"
	ufwDockerLogDeny = "ufw-docker-logging-deny"
	dockerUserReturn = "-A DOCKER-USER -j RETURN"
)

var (
	iptFlushDockerUser  = []string{"iptables", "-F", "DOCKER-USER"}
	iptReturnDockerUser = []string{"iptables", "-A", "DOCKER-USER", "-j", "RETURN"}
	iptFlushLogDeny     = []string{"iptables", "-F", ufwDockerLogDeny}
	iptDeleteLogDeny    = []string{"iptables", "-X", ufwDockerLogDeny}
)

// withUFWDockerBlock appends the block to after.rules, after a blank
// line, as the README does.
func withUFWDockerBlock(old string) (string, error) {
	if strings.Contains(old, ufwDockerMarker) {
		return "", fmt.Errorf("it already holds a %q block", ufwDockerMarker)
	}
	if !strings.HasSuffix(old, "\n") {
		return "", fmt.Errorf("it does not end with a newline")
	}
	return old + "\n" + ufwDockerBlock, nil
}

// ufwDockerCommands are the commands and undo commands. The undo empties
// DOCKER-USER first (so nothing refers to ufw-docker's chains), puts
// Docker's RETURN back when the chain had it, reloads UFW from the
// restored files and deletes ufw-docker's logging chain: the chain is
// left as the audit saw it.
func ufwDockerCommands(hadReturn bool) (cmds, undo [][]string) {
	undo = [][]string{iptFlushDockerUser}
	if hadReturn {
		undo = append(undo, iptReturnDockerUser)
	}
	undo = append(undo, ufwReload, iptFlushLogDeny, iptDeleteLogDeny)
	return [][]string{ufwReload}, undo
}

// dockerPlan collects what the step adds, keeps and closes.
type dockerPlan struct {
	adds           []ufwAdd
	kept, closed   []string
	panelKept      bool
	closesPanel    bool
	closesWebProxy bool
}

func planUFWDocker(in Input) Outcome {
	if in.Facts == nil {
		return Skip(SkipUnknown, "there are no facts (a plan from a report alone): the step needs the UFW files and the containers the audit reads")
	}
	if out, need := checkGate(in, []string{"DKR-001"}); !need {
		return out
	}
	f := in.Facts
	if f == nil || f.Firewall == nil || f.Docker == nil || f.Listeners == nil || f.Tailscale == nil {
		return Skip(SkipUnknown, "the firewall, docker, listeners or tailscale facts are missing (planning from a report alone, or a collector did not run)")
	}
	hadReturn, out, ok := ufwDockerReady(f)
	if !ok {
		return out
	}
	ports, ok := checks.PublishedPorts(f, in.Profile)
	if !ok {
		return Skip(SkipUnknown, "the Docker API was not read, so which ports containers publish is unknown")
	}
	dp, out, ok := decidePorts(f.Firewall.UFW, ports, in.Profile)
	if !ok {
		return out
	}
	if len(dp.closed) == 0 {
		return Skip(SkipManual, "every published port stays public as the %s profile expects, so ufw-docker would close nothing now", in.Profile)
	}
	if f.Tailscale.Installed && !hasRouteOn(f.Firewall.UFW.Rules, tailnetIface) {
		dp.adds = append(dp.adds, ufwAdd{route: true, proto: "any", iface: tailnetIface})
	}
	return dp.step(in, f.Firewall.UFW, hadReturn)
}

// ufwDockerReady checks what the block needs: UFW on with a deny default,
// Docker's iptables backend, no ufw-docker yet, and a DOCKER-USER chain
// holding only Docker's RETURN (or nothing).
func ufwDockerReady(f *facts.Facts) (hadReturn bool, out Outcome, ok bool) {
	fw := f.Firewall
	switch fw.DockerBackend {
	case "nftables":
		return false, Skip(SkipManual, "Docker uses its nftables firewall backend, which has no DOCKER-USER chain: the ufw-docker rules would filter nothing there, so stackward refuses them. Publish the ports on 127.0.0.1 or the tailnet address, or filter them in an nftables forward chain"), false
	case "iptables":
	case "none":
		return false, Skip(SkipManual, "Docker has programmed no firewall rules yet (is it running?); plan again when it has"), false
	default:
		return false, Skip(SkipUnknown, "Docker's firewall backend is unknown (run the audit with sudo)"), false
	}
	if d := f.Docker.Daemon; d != nil && d.IPTables != nil && !*d.IPTables {
		return false, Skip(SkipManual, "Docker runs with iptables off, so its published ports are plain host sockets that UFW's input rules already filter"), false
	}
	st, out, ok := liveUFW(f)
	if !ok {
		return false, out, false
	}
	if !st.active || (st.u.DefaultIncoming != "deny" && st.u.DefaultIncoming != "reject") {
		return false, Skip(SkipManual, "UFW must be on with a deny default first: apply %s, then plan again", UFWPolicyID), false
	}
	if d := fw.UFWDocker; d == nil || d.InFiles != "absent" || d.Loaded == "yes" {
		return false, Skip(SkipManual, "ufw-docker is already in after.rules or loaded, or that could not be read (NET-007 says which)"), false
	}
	ipt := fw.Iptables
	if ipt == nil || !ipt.Listed || fw.DockerUser == "" {
		return false, Skip(SkipUnknown, "the DOCKER-USER chain needs root to read"), false
	}
	if fw.DockerUser != "default" || ipt.HasChain(ufwDockerLogDeny) || len(ipt.DockerUserRules) > 1 ||
		(len(ipt.DockerUserRules) == 1 && ipt.DockerUserRules[0] != dockerUserReturn) {
		return false, Skip(SkipManual, "DOCKER-USER holds rules stackward did not write (or is missing); the ufw-docker rules would replace them, so filter by hand"), false
	}
	return len(ipt.DockerUserRules) == 1, Outcome{}, true
}

// decidePorts sorts the published ports into those that stay public (a
// route rule keeps them open) and those that close, by the profile.
func decidePorts(u *facts.UFW, ports []checks.PublishedPort, prof profile.Name) (*dockerPlan, Outcome, bool) {
	dp := &dockerPlan{}
	for _, p := range ports {
		label := p.Label + " (" + p.Container + ")"
		if p.Filter == "input" {
			return nil, Skip(SkipManual, "%s is filtered by the host input rules (Docker's iptables are off)", label), false
		}
		keep := false
		switch prof {
		case profile.Tunnel, profile.TailnetOnly:
		case profile.PublicWeb, profile.PaaSPanel:
			keep = p.Public || p.Panel
		default:
			if checks.WebPort(p.HostPort) || p.Panel {
				return nil, Skip(SkipManual, "%s is a web or panel port and the ingress profile is %s, so whether it must stay public is unknown; plan again with --profile public-web, paas-panel, tunnel or tailnet-only", label, profileWord(prof)), false
			}
		}
		existing := hasRouteFor(u.Rules, p.Proto, p.ContainerPort)
		switch {
		case existing:
			dp.kept = append(dp.kept, label+" from anywhere (an existing route rule)")
		case keep:
			r := ufwAdd{route: true, proto: p.Proto, port: p.ContainerPort}
			if !slices.Contains(dp.adds, r) {
				dp.adds = append(dp.adds, r)
			}
			dp.kept = append(dp.kept, label+" from anywhere ("+r.words()+")")
			dp.panelKept = dp.panelKept || p.Panel
		default:
			dp.closed = append(dp.closed, label)
			dp.closesPanel = dp.closesPanel || p.Panel
			dp.closesWebProxy = dp.closesWebProxy || checks.WebPort(p.HostPort)
		}
	}
	return dp, Outcome{}, true
}

// step builds the edits, commands and notes.
func (dp *dockerPlan) step(in Input, u *facts.UFW, hadReturn bool) Outcome {
	var edits []FileEdit
	if len(dp.adds) > 0 {
		old, out, ok := ufwFile(u, facts.UFWUserRulesPath)
		if !ok {
			return out
		}
		nw, err := addRules(old, dp.adds, false)
		if err != nil {
			return Skip(SkipManual, "%s: %v; stackward only edits the files ufw writes", facts.UFWUserRulesPath, err)
		}
		e := newEdit(facts.UFWUserRulesPath, Replace, "", old, nw)
		e.Validate = slices.Clone(ufwTest4)
		edits = append(edits, e)
	}
	old, out, ok := ufwFile(u, facts.UFWAfterRulesPath)
	if !ok {
		return out
	}
	nw, err := withUFWDockerBlock(old)
	if err != nil {
		return Skip(SkipManual, "%s: %v", facts.UFWAfterRulesPath, err)
	}
	e := newEdit(facts.UFWAfterRulesPath, Replace, "", old, nw)
	e.Validate = slices.Clone(ufwTest4)
	edits = append(edits, e)

	s := Step{
		Fixes:   dp.fixes(in),
		Touches: []string{"firewall:ufw", "firewall:DOCKER-USER"},
		Edits:   edits,
		Undo:    Undo{Description: "Restore after.rules and the UFW rules from the backup, empty DOCKER-USER back to what Docker put there, reload UFW and delete ufw-docker's logging chain: published ports are reachable as before."},
	}
	for _, e := range edits {
		s.Touches = append(s.Touches, "file:"+e.Path)
	}
	cmds, undo := ufwDockerCommands(hadReturn)
	for _, c := range cmds {
		s.Commands = append(s.Commands, cmd("load after.rules with the ufw-docker block and the route rules", c...))
	}
	for _, c := range undo {
		s.Undo.Commands = append(s.Undo.Commands, cmd(ufwDockerUndoWhy(c), c...))
	}
	s.Notes = dp.notes(in, u)
	return Outcome{Step: &s}
}

// fixes narrows the step's checks to what it closes: DKR-001 always,
// PAAS-002 when it closes the proxy's web ports, PAAS-003 when it closes
// the panel ports.
func (dp *dockerPlan) fixes(in Input) []string {
	out := []string{"DKR-001"}
	if dp.closesWebProxy {
		out = append(out, failing(in, []string{"PAAS-002"})...)
	}
	if dp.closesPanel && !dp.panelKept {
		out = append(out, failing(in, []string{"PAAS-003"})...)
	}
	return out
}

func (dp *dockerPlan) notes(in Input, u *facts.UFW) []string {
	notes := []string{
		"Published container ports become filtered: new connections from outside the private ranges to any container are dropped unless a UFW route rule (ufw route allow) allows the container port. Containers you publish later are closed too until you add a route rule.",
		"Closes to the internet: " + strings.Join(dp.closed, ", ") + ".",
	}
	reach := []string{}
	if len(dp.kept) > 0 {
		reach = append(reach, strings.Join(dp.kept, ", "))
	}
	if in.Facts.Tailscale.Installed {
		reach = append(reach, "every published port from the tailnet (route allow on tailscale0)")
	}
	reach = append(reach,
		"every published port from the private ranges 10.0.0.0/8, 172.16.0.0/12 and 192.168.0.0/16 (the ufw-docker rules let them through, so a provider's private network keeps access)",
		"ports published on 127.0.0.1 and connections made on this host")
	notes = append(notes, "Stays reachable: "+strings.Join(reach, "; ")+".")
	if dp.panelKept {
		notes = append(notes, fmt.Sprintf("The PaaS panel ports stay public because the %s profile does not move the panel behind a tunnel or the tailnet; PAAS-003 still warns. Plan with --profile tunnel or tailnet-only to close them.", in.Profile))
	}
	notes = append(notes,
		"Route rules match the container port (after Docker's DNAT), so a rule for 443 opens 443 of every container that publishes it.",
		"The rules are the published ufw-docker block for /etc/ufw/after.rules, written by stackward and test loaded with iptables-restore --test before UFW reloads; no script or package is downloaded. They cover IPv4 only; after6.rules is not changed.",
		"ip_forward and Docker's firewall settings are left alone. Docker keeps DOCKER-USER across restarts, and UFW loads the block at boot before Docker starts.",
	)
	if u.IPv6 == "yes" {
		notes = append(notes, "Containers published over IPv6 through Docker's userland proxy pass UFW's IPv6 input rules instead, which ufw-policy already set to deny.")
	}
	return notes
}

func ufwDockerUndoWhy(c []string) string {
	switch {
	case slices.Equal(c, iptFlushDockerUser):
		return "empty DOCKER-USER, which the ufw-docker block filled"
	case slices.Equal(c, iptReturnDockerUser):
		return "put back Docker's own RETURN rule"
	case slices.Equal(c, iptFlushLogDeny):
		return "empty ufw-docker's logging chain"
	case slices.Equal(c, iptDeleteLogDeny):
		return "delete ufw-docker's logging chain"
	}
	return "load UFW's restored files"
}

// hasRouteOn reports whether a route rule lets everything in on iface.
func hasRouteOn(rules []facts.UFWRule, iface string) bool {
	for _, r := range rules {
		if r.Direction == "fwd" && r.Allows() && r.Interface == iface && r.From == "" && r.Port == "" && r.App == "" && (r.Proto == "any" || r.Proto == "") {
			return true
		}
	}
	return false
}

// hasRouteFor reports whether a route rule lets proto/port in from
// anywhere on any interface.
func hasRouteFor(rules []facts.UFWRule, proto string, port int) bool {
	for _, r := range rules {
		if r.Direction == "fwd" && r.Allows() && r.FromAnywhere() && r.To == "" && r.MatchesPort(proto, port) {
			return true
		}
	}
	return false
}

// authorizeUFWDocker re-derives the edits: after.rules gains exactly the
// ufw-docker block, user.rules (when edited) only route rules of the
// allowed shapes, both test loaded; the commands and undo are fixed, the
// undo putting Docker's RETURN back or not.
func authorizeUFWDocker(s Step) error {
	n := len(s.Edits)
	if n < 1 || n > 2 {
		return fmt.Errorf("edits %d files, the step edits after.rules and maybe user.rules", n)
	}
	if n == 2 {
		e := s.Edits[0]
		if e.Path != facts.UFWUserRulesPath || e.Action != Replace {
			return fmt.Errorf("edits %s (%s) first, the step only adds route rules to %s", e.Path, e.Action, facts.UFWUserRulesPath)
		}
		if err := authorizeAdds(e, false, true); err != nil {
			return err
		}
	}
	e := s.Edits[n-1]
	if e.Path != facts.UFWAfterRulesPath || e.Action != Replace {
		return fmt.Errorf("edits %s (%s), the step appends the ufw-docker block to %s", e.Path, e.Action, facts.UFWAfterRulesPath)
	}
	want, err := withUFWDockerBlock(e.Old)
	if err != nil {
		return fmt.Errorf("%s: %w", e.Path, err)
	}
	if err := wantContent(e, want); err != nil {
		return err
	}
	if err := wantValidate(e, ufwTest4); err != nil {
		return err
	}
	if err := wantRestarts(s); err != nil {
		return err
	}
	hadReturn := len(s.Undo.Commands) > 1 && slices.Equal(s.Undo.Commands[1].Args, iptReturnDockerUser)
	cmds, undo := ufwDockerCommands(hadReturn)
	if err := wantCommands("commands", s.Commands, cmds...); err != nil {
		return err
	}
	return wantCommands("undo", s.Undo.Commands, undo...)
}

// accessUFWDocker: UFW stays on with its input rules as they are; the
// step only adds route rules and the forward filter. The guard still
// proves from the live rules that SSH stays reachable after the reload.
func accessUFWDocker(s Step) Access {
	fc := FirewallChange{What: "reloads UFW with the ufw-docker rules"}
	if len(s.Edits) == 2 {
		if adds, err := addedRules(s.Edits[0], false, true); err == nil {
			for _, r := range adds {
				fc.Adds = append(fc.Adds, r.fact())
			}
		}
	}
	return Access{Firewall: &fc}
}
