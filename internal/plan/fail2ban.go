package plan

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/facts"
)

// fail2ban-sshd: a fail2ban jail.d drop-in that turns on the sshd jail
// on the ports sshd listens on (CS-010, and SSH-011 when that warns only
// for the missing brute force guard). It plans only when SSH is public
// and neither a fail2ban sshd jail nor CrowdSec protects it, which is
// exactly when CS-010 fails. jail.conf and jail.local are never edited.
//
// A ban can lock the owner out, so the step is access-critical: it runs
// inside the rollback transaction, and the jail never bans loopback, the
// ignoreip entries the sshd jail already has, the tailnet when Tailscale
// is installed (CS-011), and the address of the SSH session the plan was
// made from. The lockout guard refuses to apply it from a session whose
// address the jail would not ignore. When fail2ban is missing, the
// install is a command in the step, named in the plan, and the step is
// opt in.

const f2bDropin = "/etc/fail2ban/jail.d/90-stackward-sshd.local"

// orderFail2banSSHD puts the jail after the account and sshd steps: it
// bans clients, so the ways in are settled before it starts.
const orderFail2banSSHD = orderLockDefault + 10

func init() {
	Register(Generator{
		ID:    "fail2ban-sshd",
		Title: "Ban SSH brute force with a fail2ban sshd jail",
		Fixes: []string{"CS-010", "SSH-011"},
		Risk:  AccessCritical,
		Order: orderFail2banSSHD,
		OptIn: true,
		Plan:  planFail2banSSHD,

		Authorize: authorizeFail2banSSHD,
		Check:     checkFail2banSSHD,
		Access:    accessFail2banSSHD,
	})
}

// The fixed head of the ignore list: loopback, which fail2ban's own
// default ignores too.
var f2bLoopback = []string{"127.0.0.1/8", "::1"}

var (
	f2bTest     = []string{"fail2ban-client", "-t"}
	f2bReload   = []string{"systemctl", "reload", "fail2ban"}
	f2bRestart  = []string{"systemctl", "restart", "fail2ban"}
	f2bRemove   = []string{"rm", "-f", f2bDropin}
	f2bInstall  = aptGet("install", "-y", "fail2ban")
	f2bPurge    = aptGet("purge", "-y", "fail2ban")
	f2bHeadText = "# Written by stackward: plan step fail2ban-sshd, fixes CS-010.\n" +
		"# Bans SSH brute force on the sshd ports. Never bans loopback, the\n" +
		"# tailnet when Tailscale is in use, or the address the plan was made\n" +
		"# from. Remove this file and reload fail2ban to undo.\n"
)

// jail is what the drop-in says: the ports, the ignore entries, and
// whether it reads the systemd journal (only when the step installs
// fail2ban, whose recommended python3-systemd comes with it; an existing
// fail2ban keeps the backend it already uses).
type jail struct {
	ports   []int
	ignore  []string
	journal bool
}

const f2bJournalLine = "backend = systemd\n"

// render is the whole drop-in.
func (j jail) render() string {
	ps := make([]string, len(j.ports))
	for i, p := range j.ports {
		ps[i] = strconv.Itoa(p)
	}
	backend := ""
	if j.journal {
		backend = f2bJournalLine
	}
	return f2bHeadText + "[sshd]\n" +
		"enabled = true\n" + backend +
		"port = " + strings.Join(ps, ",") + "\n" +
		"ignoreip = " + strings.Join(j.ignore, " ") + "\n"
}

// f2bCommands are the commands and undo commands of the two shapes: a
// running fail2ban gets the jail with a reload, a missing one is
// installed first and purged by the undo.
func f2bCommands(install bool) (cmds, undo [][]string) {
	if install {
		return [][]string{f2bInstall, f2bTest, f2bRestart}, [][]string{f2bRemove, f2bPurge}
	}
	return [][]string{f2bTest, f2bReload}, [][]string{f2bRemove, f2bReload}
}

func planFail2banSSHD(in Input) Outcome {
	if out, need := checkGate(in, []string{"CS-010"}); !need {
		return out
	}
	if l, _ := in.Level("CS-010"); l != checks.Fail {
		return Skip(SkipManual, "the fail2ban sshd jail exists but bans on another port than sshd's; fix the jail's port by hand")
	}
	f := in.Facts
	if f == nil || f.Fail2ban == nil || f.Listeners == nil || f.Tailscale == nil {
		return Skip(SkipUnknown, "the fail2ban, listeners or tailscale facts are missing (planning from a report alone, or a collector did not run)")
	}
	f2b := f.Fail2ban
	install := !f2b.Installed
	existing, out, ok := f2bExisting(f2b)
	if !ok {
		return out
	}
	ignore, srcNote := f2bIgnoreList(existing, f.Tailscale.Installed, in.Source)
	if len(ignore) == 0 {
		return Skip(SkipManual, "the sshd jail's ignoreip holds an entry that is not an address or network; add the jail by hand")
	}
	ports := sshdPorts(f)
	e := newEdit(f2bDropin, Create, "0644", "", jail{ports: ports, ignore: ignore, journal: install}.render())
	cmds, undo := f2bCommands(install)
	s := Step{
		Fixes:    append([]string{"CS-010"}, failing(in, []string{"SSH-011"})...),
		Restarts: []string{"fail2ban"},
		Touches:  []string{"file:" + f2bDropin, "service:fail2ban"},
		Edits:    []FileEdit{e},
		Undo: Undo{
			Description: "Remove the jail drop-in and reload fail2ban: the sshd jail stops and its bans are lifted.",
		},
		Notes: []string{srcNote,
			"fail2ban-client -t checks the whole fail2ban configuration with the new file before fail2ban loads it; a failure stops the step and the transaction rolls back.",
		},
	}
	if install {
		s.Notes = append(s.Notes, "The jail reads sshd's log from the systemd journal (backend = systemd), so it works on hosts without /var/log/auth.log; apt installs the python3-systemd module fail2ban recommends for it.")
	} else {
		s.Notes = append(s.Notes, "The jail keeps the log backend fail2ban already uses for sshd. If fail2ban cannot read the sshd log with it, loading the jail fails and the transaction rolls back.")
	}
	if install {
		s.Undo.Description = "Remove the jail drop-in and purge fail2ban, which the step installed: its jails stop and every ban is lifted. Packages apt installed with it stay."
		s.Notes = append([]string{"Installs the fail2ban package (and what it depends on) from the configured apt sources with apt-get install. Nothing else is upgraded on purpose, but apt may upgrade a dependency it needs. If the package lists are old, run apt update first, or the install fails and the transaction rolls back."}, s.Notes...)
	}
	for _, c := range cmds {
		s.Commands = append(s.Commands, cmd(f2bWhy(c), c...))
	}
	for _, c := range undo {
		s.Undo.Commands = append(s.Undo.Commands, cmd(f2bUndoWhy(c), c...))
	}
	return Outcome{Step: &s}
}

// f2bExisting returns the ignoreip entries the sshd jail already has, so
// the drop-in keeps them. A running fail2ban must have a readable config.
func f2bExisting(f2b *facts.Fail2ban) ([]string, Outcome, bool) {
	if !f2b.Installed {
		return nil, Outcome{}, true
	}
	running, known := f2b.Running()
	switch {
	case !known:
		return nil, Skip(SkipUnknown, "fail2ban is installed but whether it runs could not be read (run the audit with sudo)"), false
	case !running:
		return nil, Skip(SkipManual, "fail2ban is installed but not running; start it (or remove it) first, then plan again"), false
	case !f2b.ConfigRead:
		return nil, Skip(SkipUnknown, "the fail2ban jail configuration could not be read, so the sshd jail's own ignoreip is unknown"), false
	}
	j, _ := f2b.Jail("sshd")
	return j.IgnoreIP, Outcome{}, true
}

// f2bIgnoreList builds the ignoreip entries: loopback, the sshd jail's
// own entries, the tailnet when Tailscale is installed, then the source
// of the planning session unless one of them already covers it. It
// returns nil when an existing entry is not an address or network. The
// note says whether the source is in, or why not.
func f2bIgnoreList(existing []string, tailscale bool, src netip.Addr) ([]string, string) {
	out := slices.Clone(f2bLoopback)
	add := func(e string) {
		if !slices.Contains(out, e) {
			out = append(out, e)
		}
	}
	for _, e := range existing {
		if _, ok := parseNet(e); !ok {
			return nil, ""
		}
		add(e)
	}
	if tailscale {
		add(TailnetV4.String())
		add(TailnetV6.String())
	}
	if !src.IsValid() {
		return out, "No SSH client address was known when this plan was made (a saved facts file, or not over SSH), so only loopback, the jail's own entries and the tailnet are ignored. apply refuses to run the step from an SSH session whose address the jail would not ignore: plan again from the session you will apply and confirm from."
	}
	src = src.Unmap()
	if !sourceIn(src, out) {
		add(src.String())
	}
	return out, "The jail never bans " + src.String() + ", the address this plan was made from, so a failed test login from there (the confirm included) cannot ban you. apply refuses to run it from another address the jail does not ignore."
}

// sshdPorts mirrors CS-010: the TCP ports sshd listens on, plus the
// configured ones, or 22.
func sshdPorts(f *facts.Facts) []int {
	seen := map[int]bool{}
	for _, s := range f.Listeners.Sockets {
		if s.Proto == "tcp" && s.HasProcess("sshd") {
			seen[s.Port] = true
		}
	}
	if f.SSH != nil {
		for _, p := range f.SSH.Effective["port"] {
			if n, err := strconv.Atoi(p); err == nil && n > 0 && n < 65536 {
				seen[n] = true
			}
		}
	}
	if len(seen) == 0 {
		seen[22] = true
	}
	out := make([]int, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}

func f2bWhy(c []string) string {
	switch {
	case slices.Equal(c, f2bInstall):
		return "install fail2ban (named here so nothing is installed silently)"
	case slices.Equal(c, f2bTest):
		return "check the whole fail2ban configuration with the new jail"
	case slices.Equal(c, f2bRestart):
		return "start fail2ban with the new jail"
	}
	return "load the new jail"
}

func f2bUndoWhy(c []string) string {
	switch {
	case slices.Equal(c, f2bRemove):
		return "remove the jail drop-in"
	case slices.Equal(c, f2bPurge):
		return "remove fail2ban, which the step installed"
	}
	return "stop the jail and lift its bans"
}

// parseJail reads back a drop-in this step wrote, refusing anything
// render would not produce.
func parseJail(content string) (jail, error) {
	var j jail
	body, ok := strings.CutPrefix(content, f2bHeadText+"[sshd]\nenabled = true\n")
	if !ok {
		return j, errors.New("the jail is not what the step writes")
	}
	body, j.journal = strings.CutPrefix(body, f2bJournalLine)
	body, ok = strings.CutPrefix(body, "port = ")
	if !ok {
		return j, errors.New("the jail is not what the step writes")
	}
	portLine, rest, _ := strings.Cut(body, "\n")
	ignoreLine, ok := strings.CutPrefix(rest, "ignoreip = ")
	if !ok {
		return j, errors.New("the jail is not what the step writes")
	}
	ignoreLine, ok = strings.CutSuffix(ignoreLine, "\n")
	if !ok || strings.Contains(ignoreLine, "\n") {
		return j, errors.New("the jail is not what the step writes")
	}
	for _, p := range strings.Split(portLine, ",") {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 || (len(j.ports) > 0 && n <= j.ports[len(j.ports)-1]) {
			return j, fmt.Errorf("port %q is not one the step writes", p)
		}
		j.ports = append(j.ports, n)
	}
	j.ignore = strings.Split(ignoreLine, " ")
	if len(j.ignore) < len(f2bLoopback) || !slices.Equal(j.ignore[:len(f2bLoopback)], f2bLoopback) {
		return j, errors.New("the ignore list does not start with loopback")
	}
	for i, e := range j.ignore {
		if _, ok := parseNet(e); !ok || slices.Contains(j.ignore[:i], e) {
			return j, fmt.Errorf("ignoreip entry %q is not one the step writes", e)
		}
	}
	return j, nil
}

func authorizeFail2banSSHD(s Step) error {
	e, err := wantOneEdit(s, f2bDropin, Create)
	if err != nil {
		return err
	}
	j, err := parseJail(e.New)
	if err != nil {
		return fmt.Errorf("%s: %w", e.Path, err)
	}
	if err := wantContent(e, j.render()); err != nil {
		return err
	}
	if err := wantValidate(e, nil); err != nil {
		return err
	}
	if err := wantRestarts(s, "fail2ban"); err != nil {
		return err
	}
	// The install shape is the only one that reads the journal.
	cmds, undo := f2bCommands(j.journal)
	if err := wantCommands("commands", s.Commands, cmds...); err != nil {
		return err
	}
	return wantCommands("undo", s.Undo.Commands, undo...)
}

// checkFail2banSSHD: applied when the drop-in holds exactly the planned
// content and, for the install shape, dpkg lists fail2ban as installed.
// The commands run whenever it is not applied: a check and a reload are
// safe to repeat.
func checkFail2banSSHD(r Reader, s Step) (bool, string, error) {
	ok, err := FileHolds(r, f2bDropin, s.Edits[0].NewSHA256)
	if err != nil || !ok {
		return false, "", err
	}
	if len(s.Commands) > 0 && slices.Equal(s.Commands[0].Args, f2bInstall) {
		installed, err := dpkgInstalled(r, "fail2ban")
		if err != nil || !installed {
			return false, "", err
		}
	}
	return true, f2bDropin + " already holds the planned content", nil
}

// accessFail2banSSHD: the jail closes no way in, but it bans, so the
// lockout guard checks that the session applying it is never banned.
func accessFail2banSSHD(s Step) Access {
	a := Access{Bans: true}
	if len(s.Edits) == 1 {
		if j, err := parseJail(s.Edits[0].New); err == nil {
			a.IgnoredSources = j.ignore
		}
	}
	return a
}
