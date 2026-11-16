package plan

import (
	"fmt"
	"slices"
	"strings"

	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/profile"
)

// ufw-policy: turn UFW on with a default deny incoming policy (NET-001),
// with the allow rules that keep the host reachable in place before the
// policy loads:
//
//   - sshd's ports (from the sshd facts) from anywhere, unless a rule
//     already lets them in; when the existing rules let SSH in only from
//     some sources, they are kept as they are and the lockout guard proves
//     the applying session comes from one of them;
//   - everything on tailscale0 when Tailscale is installed;
//   - the web ports a host service listens on, when the ingress profile
//     says they are public (public-web, paas-panel).
//
// Every other public host service closes to the internet, and the step
// lists them. Published container ports are not affected: Docker forwards
// them past UFW's input rules, which is what the ufw-docker step is for.
//
// The step writes UFW's own files (the rules in user.rules and
// user6.rules, DEFAULT_INPUT_POLICY in /etc/default/ufw, ENABLED in
// /etc/ufw/ufw.conf) and then runs `ufw --force enable` (UFW was off) or
// `ufw reload` (it was on with an allow default), so all of it loads at
// once and undo restores the files and the on or off state exactly. It
// is access-critical: it runs in the rollback transaction and the lockout
// guard proves SSH stays reachable for the applying session. UFW's
// forward policy, ip_forward, Docker's firewall settings and
// /etc/ufw/sysctl.conf are left alone.

// UFWPolicyID is the id of the ufw-policy step.
const UFWPolicyID = "ufw-policy"

// Order of the firewall steps: after the account and sshd steps, the
// policy before ufw-docker (which needs UFW on), both before the jail.
const (
	orderUFWPolicy = orderLockDefault + 4
	orderUFWDocker = orderLockDefault + 6
)

func init() {
	Register(Generator{
		ID:    UFWPolicyID,
		Title: "Turn UFW on with a default deny incoming policy",
		Fixes: []string{"NET-001"},
		Risk:  AccessCritical,
		Order: orderUFWPolicy,
		Plan:  planUFWPolicy,

		Authorize: authorizeUFWPolicy,
		Check:     checkEditsHold,
		Access:    accessUFWPolicy,
	})
}

var (
	ufwEnable  = []string{"ufw", "--force", "enable"}
	ufwDisable = []string{"ufw", "disable"}
	ufwReload  = []string{"ufw", "reload"}
	// The staged user rules are test loaded, never committed.
	ufwTest4 = []string{"iptables-restore", "--test", "--noflush"}
	ufwTest6 = []string{"ip6tables-restore", "--test", "--noflush"}
)

const (
	ufwInputPolicyKey = "DEFAULT_INPUT_POLICY"
	ufwInputDrop      = `"DROP"`
	ufwEnabledKey     = "ENABLED"
)

// ufwState is what the audit saw of UFW, checked for a step to build on.
type ufwState struct {
	u      *facts.UFW
	active bool
	ipv6   bool
}

// liveUFW returns UFW's live state, or why there is none to plan from.
func liveUFW(f *facts.Facts) (ufwState, Outcome, bool) {
	fw := f.Firewall
	u := fw.UFW
	switch {
	case u == nil || !u.Installed:
		return ufwState{}, Skip(SkipManual, "UFW is not installed; install it (apt-get install ufw) and plan again: stackward does not install a firewall on its own"), false
	case fw.Firewalld != nil && fw.Firewalld.State == "running":
		return ufwState{}, Skip(SkipManual, "firewalld is running; stackward does not stack UFW on another firewall"), false
	case !u.Live():
		return ufwState{}, Skip(SkipUnknown, "the live UFW state needs root to read (run the audit with sudo)"), false
	case !u.RulesKnown:
		return ufwState{}, Skip(SkipUnknown, "the UFW rules could not be read"), false
	}
	return ufwState{u: u, active: u.Status == "active", ipv6: u.IPv6 == "yes"}, Outcome{}, true
}

// ufwFile returns the audited text of a UFW file, or why it is missing.
func ufwFile(u *facts.UFW, path string) (string, Outcome, bool) {
	s, ok := u.Files[path]
	if !ok {
		return "", Skip(SkipUnknown, "%s was not read by the audit (missing, unreadable or over %d bytes)", path, facts.MaxUFWFileBytes), false
	}
	return s, Outcome{}, true
}

// policyPlan collects what the step adds and what it says.
type policyPlan struct {
	adds4, adds6 []ufwAdd
	notes        []string
}

func (pp *policyPlan) add(r ufwAdd, ipv6 bool) {
	pp.adds4 = append(pp.adds4, r)
	if ipv6 {
		r.v6 = true
		pp.adds6 = append(pp.adds6, r)
	}
}

func planUFWPolicy(in Input) Outcome {
	if in.Facts == nil {
		return Skip(SkipUnknown, "there are no facts (a plan from a report alone): the step needs the UFW files the audit reads")
	}
	if out, need := checkGate(in, []string{"NET-001"}); !need {
		return out
	}
	f := in.Facts
	if f == nil || f.Firewall == nil || f.Listeners == nil || f.Tailscale == nil {
		return Skip(SkipUnknown, "the firewall, listeners or tailscale facts are missing (planning from a report alone, or a collector did not run)")
	}
	st, out, ok := liveUFW(f)
	if !ok {
		return out
	}
	u := st.u
	if st.active && u.DefaultIncoming != "allow" {
		return Skip(SkipManual, "UFW is active and its default incoming policy is %s; NET-001 fails for another reason", orNoState(u.DefaultIncoming))
	}
	if !st.active && u.Enabled != "no" {
		return Skip(SkipManual, "ufw.conf says ENABLED=%s but UFW's rules are not loaded; find out why (journalctl -u ufw) before stackward changes the firewall", orNoState(u.Enabled))
	}
	ports := sshdPortsKnown(f)
	if len(ports) == 0 {
		return Skip(SkipUnknown, "the port sshd listens on is unknown (no sshd facts and no sshd listener), and stackward does not assume 22")
	}
	pp := &policyPlan{}
	if out, ok := pp.sshRules(f, u, ports, st.ipv6); !ok {
		return out
	}
	if f.Tailscale.Installed && !hasAllowOn(u.Rules, tailnetIface) {
		pp.add(ufwAdd{proto: "any", iface: tailnetIface}, st.ipv6)
	}
	if out, ok := pp.hostServices(f, u, in.Profile, ports, st.ipv6); !ok {
		return out
	}
	return pp.step(u, st)
}

// sshRules adds an allow rule from anywhere for every sshd port no rule
// lets in yet. A port that existing rules let in only from some sources
// keeps those rules (the lockout guard proves the session is among
// them); a deny for it from anywhere leaves the step to a person.
func (pp *policyPlan) sshRules(f *facts.Facts, u *facts.UFW, ports []int, ipv6 bool) (Outcome, bool) {
	panel := len(checks.PanelPorts(f)) > 0
	for _, port := range ports {
		for _, r := range u.Rules {
			if r.Direction == "in" && !r.Allows() && r.FromAnywhere() && r.MatchesPort("tcp", port) {
				return Skip(SkipManual, "UFW rule %q denies SSH on tcp/%d; remove it before stackward turns UFW on", ufwRuleWords(r), port), false
			}
		}
		anywhere4, some := allowsPort(u.Rules, port, false)
		anywhere6, _ := allowsPort(u.Rules, port, true)
		switch {
		case anywhere4 && (anywhere6 || !ipv6):
		case anywhere4:
			pp.adds6 = append(pp.adds6, ufwAdd{proto: "tcp", port: port, v6: true})
		case some && panel:
			return Skip(SkipManual, "UFW's rules let SSH on tcp/%d in only from some sources, and a PaaS panel on this host reaches sshd from its container; allow the Docker networks to reach tcp/%d first", port, port), false
		case some:
			pp.notes = append(pp.notes, fmt.Sprintf("SSH on tcp/%d stays open only from the sources UFW's rules already allow; the step adds no rule from anywhere for it. Public SSH closes when UFW turns on, so apply and confirm from one of those sources (the lockout guard checks).", port))
		default:
			pp.add(ufwAdd{proto: "tcp", port: port}, ipv6)
		}
	}
	return Outcome{}, true
}

// hostServices keeps the web ports the profile says are public and lists
// every other public host service that the default deny closes.
func (pp *policyPlan) hostServices(f *facts.Facts, u *facts.UFW, prof profile.Name, ssh []int, ipv6 bool) (Outcome, bool) {
	var kept, closed []string
	for _, hp := range checks.ExposedHostPorts(f) {
		label := fmt.Sprintf("%s/%d", hp.Proto, hp.Port)
		if len(hp.Processes) > 0 {
			label += " (" + strings.Join(hp.Processes, ", ") + ")"
		}
		switch {
		case hp.Proto == "tcp" && slices.Contains(ssh, hp.Port):
			continue
		case hp.Proto == "tcp" && checks.WebPort(hp.Port):
			switch prof {
			case profile.PublicWeb, profile.PaaSPanel:
				kept = append(kept, label)
				if a4, _ := allowsPort(u.Rules, hp.Port, false); !a4 {
					pp.add(ufwAdd{proto: "tcp", port: hp.Port}, ipv6)
				}
				continue
			case profile.Tunnel, profile.TailnetOnly:
			default:
				return Skip(SkipManual, "a host service listens publicly on %s and the ingress profile is %s, so whether it must stay public is unknown; plan again with --profile public-web, tunnel or tailnet-only", label, profileWord(prof)), false
			}
		}
		if a4, _ := allowsProtoPort(u.Rules, hp.Proto, hp.Port, false); a4 {
			kept = append(kept, label+" (an existing rule)")
			continue
		}
		closed = append(closed, label)
	}
	if len(kept) > 0 {
		pp.notes = append(pp.notes, fmt.Sprintf("Stays open from anywhere: %s, as the %s profile says.", strings.Join(kept, ", "), prof))
	}
	if len(closed) > 0 {
		pp.notes = append(pp.notes, "Closes to the internet (the default deny drops new connections to them): "+strings.Join(closed, ", ")+". Allow one with `ufw allow` before applying if it must stay public.")
	} else {
		pp.notes = append(pp.notes, "No other host service listens on a public address, so the default deny closes nothing that is reachable now.")
	}
	return Outcome{}, true
}

// step builds the edits, commands and notes.
func (pp *policyPlan) step(u *facts.UFW, st ufwState) Outcome {
	if out, ok := templateLogLevel(u); !ok {
		return out
	}
	var edits []FileEdit
	edit := func(path string, mk func(string) (string, error)) (Outcome, bool) {
		old, out, ok := ufwFile(u, path)
		if !ok {
			return out, false
		}
		nw, err := mk(old)
		if err != nil {
			return Skip(SkipManual, "%s: %v; stackward only edits the files ufw writes", path, err), false
		}
		if nw != old {
			edits = append(edits, newEdit(path, Replace, "", old, nw))
		}
		return Outcome{}, true
	}
	for _, x := range []struct {
		path string
		adds []ufwAdd
		test []string
	}{{facts.UFWUserRulesPath, pp.adds4, ufwTest4}, {facts.UFWUser6RulesPath, pp.adds6, ufwTest6}} {
		if len(x.adds) == 0 {
			continue
		}
		if out, ok := edit(x.path, func(s string) (string, error) { return addRules(s, x.adds, x.path == facts.UFWUser6RulesPath) }); !ok {
			return out
		}
		edits[len(edits)-1].Validate = append([]string{}, x.test...)
	}
	if out, ok := edit(facts.UFWDefaultPath, func(s string) (string, error) {
		if v := shellVar(s, ufwInputPolicyKey); v == "DROP" || v == "REJECT" {
			return s, nil
		}
		return setShellVar(s, ufwInputPolicyKey, ufwInputDrop)
	}); !ok {
		return out
	}
	cmds, undo := ufwPolicyCommands(!st.active)
	if !st.active {
		if out, ok := edit(facts.UFWConfPath, func(s string) (string, error) { return setShellVar(s, ufwEnabledKey, "yes") }); !ok {
			return out
		}
	}
	s := Step{Touches: []string{"firewall:ufw"}, Edits: edits}
	for _, e := range edits {
		s.Touches = append(s.Touches, "file:"+e.Path)
	}
	for _, c := range cmds {
		s.Commands = append(s.Commands, cmd(ufwWhy(c), c...))
	}
	for _, c := range undo {
		s.Undo.Commands = append(s.Undo.Commands, cmd(ufwWhy(c), c...))
	}
	s.Undo.Description = "Restore the UFW files the step changed from the backup and reload UFW: the rules and the default policy are back as they were."
	if !st.active {
		s.Undo.Description = "Restore the UFW files the step changed from the backup and turn UFW off again (ufw disable), as it was before."
	}
	s.Notes = pp.stepNotes(st)
	return Outcome{Step: &s}
}

func (pp *policyPlan) stepNotes(st ufwState) []string {
	var added []string
	for _, r := range append(slices.Clone(pp.adds4), pp.adds6...) {
		added = append(added, r.words())
	}
	head := "Turns UFW on with default deny incoming."
	if st.active {
		head = "Sets UFW's default incoming policy to deny and reloads it."
	}
	if len(added) > 0 {
		head += " The allow rules (" + strings.Join(added, "; ") + ") are written to UFW's rules files before the policy loads, and load with it in one step."
	}
	notes := append([]string{head}, pp.notes...)
	if !st.ipv6 {
		notes = append(notes, "UFW has IPV6 other than yes, so this step does not filter IPv6 (NET-002).")
	}
	return append(notes,
		"Published container ports are not affected: Docker forwards them past UFW's input rules (DKR-001). The ufw-docker step filters them.",
		"Containers that connect to a service on the host itself (host.docker.internal, the bridge gateway) go through UFW's input rules too, and close unless a rule allows them.",
		"Connections that are already open, this SSH session among them, stay up: UFW accepts established traffic.",
		"UFW's forward policy, ip_forward, Docker's firewall settings and /etc/ufw/sysctl.conf are left as they are.",
	)
}

// templateLogLevel: a step writes ufw's template in the format ufw writes
// at log level low (ufwtemplate.go), so on a template the log level must be
// low or ufw would rewrite the file with other logging rules.
func templateLogLevel(u *facts.UFW) (Outcome, bool) {
	tmpl := isUFWTemplate(u.Files[facts.UFWUserRulesPath], false) || isUFWTemplate(u.Files[facts.UFWUser6RulesPath], true)
	if !tmpl {
		return Outcome{}, true
	}
	conf, out, ok := ufwFile(u, facts.UFWConfPath)
	if !ok {
		return out, false
	}
	if lvl := shellVar(conf, "LOGLEVEL"); lvl != "low" {
		return Skip(SkipManual, "UFW's rules files are still its template and its log level is %q, not low: stackward writes them as ufw does at log level low; set `ufw logging low` (or add one rule with ufw) and plan again", lvl), false
	}
	return Outcome{}, true
}

// profileWord names a profile, "unknown" when none was given.
func profileWord(p profile.Name) string {
	if p == "" {
		return string(profile.Unknown)
	}
	return string(p)
}

// ufwPolicyCommands are the commands and undo commands of the two
// shapes: UFW off (turn it on, and off again) or on with an allow
// default (reload, and reload again).
func ufwPolicyCommands(turnOn bool) (cmds, undo [][]string) {
	if turnOn {
		return [][]string{ufwEnable}, [][]string{ufwDisable}
	}
	return [][]string{ufwReload}, [][]string{ufwReload}
}

func ufwWhy(c []string) string {
	switch {
	case slices.Equal(c, ufwEnable):
		return "turn UFW on: load the rules and the default deny together"
	case slices.Equal(c, ufwDisable):
		return "turn UFW off again, as it was"
	}
	return "load UFW's rules files again"
}

// allowsPort reports whether an input rule of the family (v6 or not)
// lets tcp/port in from anywhere, and whether any allow rule names the
// port at all.
func allowsPort(rules []facts.UFWRule, port int, v6 bool) (anywhere, some bool) {
	return allowsProtoPort(rules, "tcp", port, v6)
}

// allowsProtoPort is allowsPort for proto.
func allowsProtoPort(rules []facts.UFWRule, proto string, port int, v6 bool) (anywhere, some bool) {
	for _, r := range rules {
		if r.Direction != "in" || r.V6 != v6 || !r.Allows() || !r.MatchesPort(proto, port) {
			continue
		}
		some = true
		if r.FromAnywhere() && r.To == "" {
			anywhere = true
		}
	}
	return anywhere, some
}

// hasAllowOn reports whether an input rule lets everything in on iface.
func hasAllowOn(rules []facts.UFWRule, iface string) bool {
	for _, r := range rules {
		if r.Direction == "in" && r.Allows() && r.Interface == iface && r.From == "" && r.Port == "" && r.App == "" && (r.Proto == "any" || r.Proto == "") {
			return true
		}
	}
	return false
}

// authorizeUFWPolicy re-derives every edit from its old side: the user
// rules only gain input rules of the allowed shapes (IPv4 in user.rules,
// IPv6 in user6.rules, each test loaded), /etc/default/ufw only gets
// DEFAULT_INPUT_POLICY="DROP", ufw.conf only ENABLED=yes, and the
// commands follow from whether ufw.conf is edited.
func authorizeUFWPolicy(s Step) error {
	if len(s.Edits) == 0 {
		return fmt.Errorf("edits nothing, the step always edits UFW's files")
	}
	seen := map[string]bool{}
	turnOn := false
	for _, e := range s.Edits {
		if seen[e.Path] {
			return fmt.Errorf("edits %s twice", e.Path)
		}
		seen[e.Path] = true
		if e.Action != Replace {
			return fmt.Errorf("%s: action %q, the step only replaces UFW's files", e.Path, e.Action)
		}
		var err error
		switch e.Path {
		case facts.UFWUserRulesPath, facts.UFWUser6RulesPath:
			err = authorizeAdds(e, e.Path == facts.UFWUser6RulesPath, false)
		case facts.UFWDefaultPath:
			err = wantSetVar(e, ufwInputPolicyKey, ufwInputDrop)
		case facts.UFWConfPath:
			turnOn = true
			err = wantSetVar(e, ufwEnabledKey, "yes")
		default:
			err = fmt.Errorf("edits %s, the step only edits UFW's rules, defaults and ufw.conf", e.Path)
		}
		if err != nil {
			return err
		}
	}
	if err := wantRestarts(s); err != nil {
		return err
	}
	cmds, undo := ufwPolicyCommands(turnOn)
	if err := wantCommands("commands", s.Commands, cmds...); err != nil {
		return err
	}
	return wantCommands("undo", s.Undo.Commands, undo...)
}

// authorizeAdds checks an edit of a user rules file: only added rules of
// the allowed shapes, and the test load of the staged file.
func authorizeAdds(e FileEdit, v6, route bool) error {
	if _, err := addedRules(e, v6, route); err != nil {
		return err
	}
	test := ufwTest4
	if v6 {
		test = ufwTest6
	}
	return wantValidate(e, test)
}

// wantSetVar refuses an edit that is not the old file with KEY=value set.
func wantSetVar(e FileEdit, key, value string) error {
	want, err := setShellVar(e.Old, key, value)
	if err != nil {
		return fmt.Errorf("%s: %w", e.Path, err)
	}
	if err := wantContent(e, want); err != nil {
		return err
	}
	return wantValidate(e, nil)
}

// checkEditsHold: applied when every edited file holds its planned
// content. The commands only load what the files say, so they run
// whenever the step is not applied.
func checkEditsHold(r Reader, s Step) (bool, string, error) {
	for _, e := range s.Edits {
		ok, err := FileHolds(r, e.Path, e.NewSHA256)
		if err != nil || !ok {
			return false, "", err
		}
	}
	return true, "UFW's files already hold the planned content", nil
}

// accessUFWPolicy: after the step UFW is active with a default deny and
// the added input rules; the guard proves SSH stays reachable.
func accessUFWPolicy(s Step) Access {
	fc := FirewallChange{What: "sets UFW's default incoming policy to deny"}
	for _, e := range s.Edits {
		switch e.Path {
		case facts.UFWConfPath:
			fc.TurnsOn, fc.What = true, "turns UFW on with default deny incoming"
		case facts.UFWUserRulesPath, facts.UFWUser6RulesPath:
			adds, err := addedRules(e, e.Path == facts.UFWUser6RulesPath, false)
			if err != nil {
				continue // Authorize refuses it; the guard then sees no rule
			}
			for _, r := range adds {
				fc.Adds = append(fc.Adds, r.fact())
			}
		}
	}
	return Access{Firewall: &fc}
}
