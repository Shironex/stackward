package plan

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/Shironex/stackward/internal/facts"
)

// paas-env-perms: a workaround for SEC-001 and SEC-002. Coolify and
// Dokploy write their app .env files again on every deploy, often
// readable by group and others, so a one off chmod is undone by the next
// deploy. This opt in step installs a oneshot service and a timer that
// runs it every minute and at boot. The service runs find over the exact
// folders the platform keeps its .env files in (the folders SEC-001
// scans, the .env names it judges) and removes group and other permission
// bits with chmod. It never opens a file, so it never reads, copies or
// logs a value, and it never changes an owner.
//
// Who must still read the files after the change:
//
//   - Coolify's installer runs chown -R 9999:root and chmod -R 700 on
//     /data/coolify (https://coolify.io/docs/get-started/installation,
//     Manual Installation), and its container runs as www-data with uid
//     9999 (USER_ID=9999 in docker/production/Dockerfile of the Coolify
//     repository). docker-compose.prod.yml mounts /data/coolify/source/.env
//     read only into that container and passes it to compose as an
//     env_file. So the main .env is changed only while uid 9999 owns it,
//     and only its group write and other bits are removed (g-w,o-rwx), as
//     SEC-002 asks: the owner keeps reading it.
//   - Coolify runs deploys on the server over SSH as root, and Dokploy's
//     service runs as root with /etc/dokploy bind mounted (the docker
//     service create of its manual installation has no --user); compose,
//     run as root, reads the app .env files. The owner keeps rw, and root
//     reads any mode, so app files go to owner only (go-rwx), and only
//     files owned by a user the platform writes as (root, and uid 9999
//     under Coolify) are touched; any other owner is left alone and the
//     plan names it.
//
// The timer is wired with a timers.target drop-in instead of systemctl
// enable, so all three units are regular files that apply writes and undo
// removes byte for byte; there is no symlink to forget.

const (
	paasEnvID      = "paas-env-perms"
	paasEnvUnit    = "stackward-paas-env-perms"
	paasEnvService = "/etc/systemd/system/" + paasEnvUnit + ".service"
	paasEnvTimer   = "/etc/systemd/system/" + paasEnvUnit + ".timer"
	paasEnvDropin  = "/etc/systemd/system/timers.target.d/90-" + paasEnvUnit + ".conf"
	// coolifyUID is the uid Coolify's container runs as and its installer
	// gives /data/coolify to.
	coolifyUID = 9999
	// envDepth is how deep under a folder find looks, the same depth the
	// secrets collector walks (a root's entries are depth 1).
	envDepth = 4
	// envWalkCap bounds the walk of Check, like the collector's.
	envWalkCap = 50000
	// fileModeKind is the touches kind of a step that changes only
	// permission bits.
	fileModeKind = "file-mode:"
)

var paasEnvFixes = []string{"SEC-001", "SEC-002"}

func init() {
	Register(Generator{
		ID:    paasEnvID,
		Title: "Keep platform .env files closed to group and others with a systemd timer (workaround)",
		Fixes: paasEnvFixes,
		// Networking, not safe: an app container that bind mounts its
		// .env and reads it as another user than the owner fails at its
		// next start, which can interrupt that app's traffic.
		Risk:  Networking,
		OptIn: true,
		Plan:  planPaaSEnv,

		Authorize: authorizePaaSEnv,
		Pin:       pinPaaSEnv,
		Check:     checkPaaSEnv,
	})
}

// envRule is one place the timer closes: a folder of app .env files, or
// the platform's main .env itself.
type envRule struct {
	root     string
	platform string
	// main is true for a single file (root is the file).
	main   bool
	check  string
	owners []int
	// mask holds the bits that make a file loose; chmod removes them.
	mask  fs.FileMode
	chmod string
}

// envRules are every place the step can cover, in the order the unit
// lists them.
var envRules = []envRule{
	{root: facts.CoolifyApplications, platform: facts.PlatformCoolify, check: "SEC-001", owners: []int{0, coolifyUID}, mask: 0o077, chmod: "go-rwx"},
	{root: facts.CoolifyServices, platform: facts.PlatformCoolify, check: "SEC-001", owners: []int{0, coolifyUID}, mask: 0o077, chmod: "go-rwx"},
	{root: facts.CoolifyMainEnv, platform: facts.PlatformCoolify, main: true, check: "SEC-002", owners: []int{coolifyUID}, mask: 0o027, chmod: "g-w,o-rwx"},
	{root: facts.DokployApplications, platform: facts.PlatformDokploy, check: "SEC-001", owners: []int{0}, mask: 0o077, chmod: "go-rwx"},
	{root: facts.DokployCompose, platform: facts.PlatformDokploy, check: "SEC-001", owners: []int{0}, mask: 0o077, chmod: "go-rwx"},
}

// dataRoot is the platform's data folder, which must exist for the rule.
func (r envRule) dataRoot() string {
	if r.platform == facts.PlatformCoolify {
		return facts.CoolifyRoot
	}
	return facts.DokployRoot
}

// covers reports whether the timer changes the file at p with owner uid
// (by place, name and owner, whatever its mode).
func (r envRule) covers(p string, uid int) bool {
	if !slices.Contains(r.owners, uid) {
		return false
	}
	if r.main {
		return p == r.root
	}
	rel, ok := strings.CutPrefix(p, r.root+"/")
	return ok && rel != "" && strings.Count(rel, "/") < envDepth && facts.IsEnvFileName(path.Base(p))
}

// loose reports whether the timer would change a file with mode perm.
func (r envRule) loose(perm fs.FileMode) bool { return perm&r.mask != 0 }

// execStart renders the find command of the rule as one ExecStart line.
// systemd splits it into arguments itself (no shell): "(", "!" and the
// wildcards reach find as written, and "+" ends -exec without a ";".
func (r envRule) execStart() string {
	args := []string{"/usr/bin/find", r.root}
	if r.main {
		args = append(args, "-maxdepth", "0", "-type", "f")
	} else {
		args = append(args, "-xdev", "-ignore_readdir_race", "-maxdepth", strconv.Itoa(envDepth), "-type", "f",
			"(", "-name", ".env", "-o", "-name", ".env.*", ")")
		for _, t := range facts.EnvTemplateNames {
			args = append(args, "!", "-name", ".env."+t)
		}
	}
	var own []string
	for i, uid := range r.owners {
		if i > 0 {
			own = append(own, "-o")
		}
		own = append(own, "-uid", strconv.Itoa(uid))
	}
	if len(r.owners) > 1 {
		own = append(append([]string{"("}, own...), ")")
	}
	args = append(args, own...)
	args = append(args, "-perm", fmt.Sprintf("/%03o", uint32(r.mask)), "-exec", "chmod", r.chmod, "{}", "+")
	return "ExecStart=" + strings.Join(args, " ")
}

var (
	paasEnvReload       = []string{"systemctl", "daemon-reload"}
	paasEnvRunNow       = []string{"systemctl", "start", paasEnvUnit + ".service"}
	paasEnvStartTimer   = []string{"systemctl", "start", paasEnvUnit + ".timer"}
	paasEnvStopTimer    = []string{"systemctl", "stop", paasEnvUnit + ".timer"}
	paasEnvRemove       = []string{"rm", "-f", paasEnvService, paasEnvTimer, paasEnvDropin}
	paasEnvServiceTouch = []string{"service:" + paasEnvUnit + ".service", "service:" + paasEnvUnit + ".timer"}
)

func planPaaSEnv(in Input) Outcome {
	if out, ok := checkGate(in, paasEnvFixes); !ok {
		return out
	}
	f := in.Facts
	if f == nil || f.Secrets == nil || f.PaaS == nil {
		return Skip(SkipUnknown, "the secrets or platform facts are missing (planning from a report alone, or a collector did not run)")
	}
	rules := coveredRules(f)
	if len(rules) == 0 {
		return Skip(SkipManual, "no Coolify or Dokploy installation with its .env folders was detected; the timer only covers a platform's own files, so close these by hand")
	}
	fixes, left := paasEnvFixesFor(in, f, rules)
	if len(fixes) == 0 {
		return Skip(SkipManual, "every open .env file belongs to an owner the platform does not write as (%s); stackward leaves those alone, so check who reads them and close them by hand", strings.Join(left, ", "))
	}
	s := paasEnvStep(rules)
	s.Fixes = fixes
	s.Notes = paasEnvNotes(rules, left)
	return Outcome{Step: &s}
}

// coveredRules are the rules of every detected platform whose folder (or
// main file) the audit saw.
func coveredRules(f *facts.Facts) []envRule {
	detected := map[string]bool{}
	for _, p := range f.PaaS.Platforms {
		detected[p.Name] = true
	}
	var out []envRule
	for _, r := range envRules {
		if !detected[r.platform] {
			continue
		}
		scan := f.Secrets.PaaSEnvFiles
		if r.main {
			scan = f.Secrets.PaaSMainEnv
			if !slices.ContainsFunc(scan.Files, func(sf facts.SecretFile) bool { return sf.Path == r.root }) {
				continue
			}
		} else if !slices.Contains(scan.Roots, r.root) || slices.Contains(scan.Denied, r.root) {
			continue
		}
		out = append(out, r)
	}
	return out
}

// paasEnvFixesFor returns the failing checks the rules fix (a check with
// at least one open file the timer covers) and the open files it leaves
// alone, as "path (uid N)".
func paasEnvFixesFor(in Input, f *facts.Facts, rules []envRule) (fixes, left []string) {
	failingNow := failing(in, paasEnvFixes)
	fixed := map[string]bool{}
	judge := func(scan facts.SecretScan, check string, mask fs.FileMode) {
		for _, sf := range scan.Files {
			if fs.FileMode(sf.Mode)&mask == 0 {
				continue
			}
			ok := false
			for _, r := range rules {
				if r.check == check && r.covers(sf.Path, sf.UID) {
					ok = true
				}
			}
			if ok {
				fixed[check] = true
			} else {
				left = append(left, fmt.Sprintf("%s (uid %d)", sf.Path, sf.UID))
			}
		}
	}
	// The masks SEC-001 and SEC-002 judge: read by group or others, and
	// read by others or written by group (internal/checks/sec.go).
	judge(f.Secrets.PaaSEnvFiles, "SEC-001", 0o044)
	judge(f.Secrets.PaaSMainEnv, "SEC-002", 0o027)
	for _, id := range failingNow {
		if fixed[id] {
			fixes = append(fixes, id)
		}
	}
	return fixes, left
}

// paasEnvStep is the step for rules: everything but the fixes and notes,
// and exactly what Authorize renders again from the touches.
func paasEnvStep(rules []envRule) Step {
	touches := make([]string, 0, len(rules)+len(paasEnvServiceTouch))
	for _, r := range rules {
		touches = append(touches, fileModeKind+r.root)
	}
	touches = append(touches, paasEnvServiceTouch...)
	return Step{
		Touches: touches,
		Edits: []FileEdit{
			newEdit(paasEnvService, Create, "0644", "", paasEnvServiceContent(rules)),
			newEdit(paasEnvTimer, Create, "0644", "", paasEnvTimerContent),
			newEdit(paasEnvDropin, Create, "0644", "", paasEnvDropinContent),
		},
		Commands: []Command{
			cmd("load the new units", paasEnvReload...),
			cmd("close the open .env files once now (chmod only; a failure stops the run here)", paasEnvRunNow...),
			cmd("start the timer that repeats it every minute; the timers.target drop-in starts it at boot", paasEnvStartTimer...),
		},
		Undo: Undo{
			Description: "Stop the timer, remove the service, the timer and the timers.target drop-in, and reload systemd. Files the timer already closed keep their modes; undo never opens them again.",
			Commands: []Command{
				cmd("stop the timer", paasEnvStopTimer...),
				cmd("remove the three unit files", paasEnvRemove...),
				cmd("forget the removed units", paasEnvReload...),
			},
		},
	}
}

const paasEnvHeader = "# Written by stackward: plan step " + paasEnvID + ". A workaround, not a fix:\n" +
	"# Coolify and Dokploy write their .env files again on every deploy, often\n" +
	"# readable by group and others. stackward undo --run RUN_ID removes all three\n" +
	"# units (" + paasEnvUnit + ".service, .timer and the timers.target.d\n" +
	"# drop-in); by hand: systemctl stop " + paasEnvUnit + ".timer, remove the\n" +
	"# three files, systemctl daemon-reload.\n"

// paasEnvServiceContent is the oneshot service for rules. It only runs
// find and chmod, without network, with the whole file system read only
// except the platform paths it covers, so even a swapped symlink cannot
// make it change a mode outside them.
func paasEnvServiceContent(rules []envRule) string {
	var b strings.Builder
	b.WriteString(paasEnvHeader)
	b.WriteString("# This service only removes group and other permission bits (chmod) of\n" +
		"# those files. It never opens them, so it never reads, copies or logs a\n" +
		"# value, and it never changes an owner.\n")
	b.WriteString("[Unit]\nDescription=stackward: close platform .env files to group and others (chmod only)\n" +
		"Documentation=https://github.com/Shironex/stackward/blob/main/docs/plan.md\n\n[Service]\nType=oneshot\n")
	var rw []string
	for _, r := range rules {
		b.WriteString(r.execStart() + "\n")
		rw = append(rw, "-"+r.root)
	}
	b.WriteString("NoNewPrivileges=yes\nPrivateNetwork=yes\nPrivateTmp=yes\nProtectHome=yes\nProtectSystem=strict\n")
	b.WriteString("ReadWritePaths=" + strings.Join(rw, " ") + "\n")
	b.WriteString("CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_FOWNER\n")
	return b.String()
}

const paasEnvTimerContent = paasEnvHeader +
	"[Unit]\nDescription=stackward: close platform .env files every minute\n" +
	"Documentation=https://github.com/Shironex/stackward/blob/main/docs/plan.md\n\n" +
	"[Timer]\nOnActiveSec=30s\nOnUnitActiveSec=1min\nAccuracySec=5s\n"

const paasEnvDropinContent = paasEnvHeader +
	"# Starts " + paasEnvUnit + ".timer at boot.\n" +
	"[Unit]\nWants=" + paasEnvUnit + ".timer\n"

func paasEnvNotes(rules []envRule, left []string) []string {
	platforms := map[string]bool{}
	hasMain := false
	for _, r := range rules {
		platforms[r.platform] = true
		hasMain = hasMain || r.main
	}
	notes := []string{
		"A workaround, not a fix: the platform writes its .env files again on every deploy. This installs " + paasEnvUnit + ".service and .timer, which every minute and at boot remove the group and other permission bits of those files with chmod. It never reads, copies or logs their contents and never changes their owner. After a deploy a file can stay open for up to a minute.",
		"Off by default: apply runs it only when you name it (--step " + paasEnvID + "). Remove it with one command, stackward undo --run RUN_ID, which stops the timer and removes the three unit files.",
	}
	if platforms[facts.PlatformCoolify] {
		notes = append(notes, "Coolify: app and service .env files owned by root or by uid 9999 (the user Coolify's container runs as and its installer gives /data/coolify to) become owner only (chmod go-rwx); the owner keeps reading and writing them, and root reads any mode.")
	}
	if hasMain {
		notes = append(notes, "Coolify mounts /data/coolify/source/.env into its container, which reads it as uid 9999: the timer changes it only while uid 9999 owns it, and keeps the owner's and group's read bits (chmod g-w,o-rwx).")
	}
	if platforms[facts.PlatformDokploy] {
		notes = append(notes, "Dokploy: app and compose .env files owned by root (Dokploy's service runs as root) become owner only (chmod go-rwx).")
	}
	notes = append(notes, "An app container that bind mounts its .env and reads it as another user than the file's owner loses access at its next start; apps that get their variables through compose (env_file, what both platforms generate) are not affected. Check your apps after the next deploy.")
	if len(left) > 0 {
		notes = append(notes, "Left alone, because the platform does not write files as their owner: "+strings.Join(left, ", ")+". They stay reported; close them by hand once you know who reads them.")
	}
	return notes
}

// rulesFromTouches re-derives the rules from a step's touches: file-mode
// targets of known rules, in rule order, then exactly the unit touches.
func rulesFromTouches(touches []string) ([]envRule, error) {
	var rules []envRule
	next := 0
	i := 0
	for ; i < len(touches) && strings.HasPrefix(touches[i], fileModeKind); i++ {
		root := strings.TrimPrefix(touches[i], fileModeKind)
		k := slices.IndexFunc(envRules, func(r envRule) bool { return r.root == root })
		if k < next {
			return nil, fmt.Errorf("touches %s, which is not a place the step covers (or is out of order)", touches[i])
		}
		rules = append(rules, envRules[k])
		next = k + 1
	}
	if len(rules) == 0 {
		return nil, errors.New("touches no platform .env folder")
	}
	if !slices.Equal(touches[i:], paasEnvServiceTouch) {
		return nil, fmt.Errorf("touches %v after the .env folders, the step touches only %v", touches[i:], paasEnvServiceTouch)
	}
	return rules, nil
}

func authorizePaaSEnv(s Step) error {
	rules, err := rulesFromTouches(s.Touches)
	if err != nil {
		return err
	}
	for _, id := range s.Fixes {
		if !slices.ContainsFunc(rules, func(r envRule) bool { return r.check == id }) {
			return fmt.Errorf("claims to fix %s, but covers none of its files", id)
		}
	}
	want := paasEnvStep(rules)
	if len(s.Edits) != len(want.Edits) {
		return fmt.Errorf("edits %d files, the step creates exactly %d", len(s.Edits), len(want.Edits))
	}
	for i, w := range want.Edits {
		e := s.Edits[i]
		if e.Path != w.Path || e.Action != Create || e.Mode != "0644" {
			return fmt.Errorf("edit %d: %s %s %s, the step creates %s 0644", i, e.Action, e.Path, e.Mode, w.Path)
		}
		if err := wantContent(e, w.New); err != nil {
			return err
		}
		if err := wantValidate(e, nil); err != nil {
			return err
		}
	}
	if err := wantRestarts(s); err != nil {
		return err
	}
	if err := wantCommands("commands", s.Commands, paasEnvReload, paasEnvRunNow, paasEnvStartTimer); err != nil {
		return err
	}
	return wantCommands("undo", s.Undo.Commands, paasEnvStopTimer, paasEnvRemove, paasEnvReload)
}

// pinPaaSEnv refuses the step when a platform it covers is not installed
// on the host now: no data root, or a covered folder or file is gone.
func pinPaaSEnv(r Reader, s Step) error {
	tr, ok := r.(TreeReader)
	if !ok {
		return nil
	}
	rules, err := rulesFromTouches(s.Touches)
	if err != nil {
		return err
	}
	for _, rule := range rules {
		root, err := tr.PathInfo(rule.dataRoot())
		if err != nil {
			return err
		}
		if !root.Dir {
			return fmt.Errorf("%s is not installed here now (no %s folder); the timer only covers a platform's own files, plan again", rule.platform, rule.dataRoot())
		}
		at, err := tr.PathInfo(rule.root)
		if err != nil {
			return err
		}
		if (rule.main && !at.Regular) || (!rule.main && !at.Dir) {
			return fmt.Errorf("%s is gone or is not what the plan saw; plan again", rule.root)
		}
	}
	return nil
}

// checkPaaSEnv: applied when the three units hold the planned content
// and, on a host that shows file modes, no file the timer covers is open.
// An open file (a deploy since the last run) makes the step not applied,
// so a second apply runs the service again and closes it at once.
func checkPaaSEnv(r Reader, s Step) (bool, string, error) {
	for _, e := range s.Edits {
		ok, err := FileHolds(r, e.Path, e.NewSHA256)
		if err != nil || !ok {
			return false, "", err
		}
	}
	tr, ok := r.(TreeReader)
	if !ok {
		return true, "the timer's units already hold the planned content", nil
	}
	rules, err := rulesFromTouches(s.Touches)
	if err != nil {
		return false, "", err
	}
	for _, rule := range rules {
		open, err := openEnvFile(tr, rule)
		if err != nil || open {
			return false, "", err
		}
	}
	return true, "the timer's units hold the planned content and no .env file it covers is open to group or others", nil
}

// openEnvFile reports whether rule covers a file that is loose now.
func openEnvFile(tr TreeReader, rule envRule) (bool, error) {
	if rule.main {
		pi, err := tr.PathInfo(rule.root)
		return err == nil && pi.Regular && rule.covers(rule.root, pi.UID) && rule.loose(pi.Perm), err
	}
	visited := 0
	var walk func(dir string, depth int) (bool, error)
	walk = func(dir string, depth int) (bool, error) {
		names, err := tr.ReadDir(dir)
		if err != nil {
			return false, err
		}
		for _, n := range names {
			if visited++; visited > envWalkCap {
				return false, fmt.Errorf("%s holds more than %d entries; stopped looking", rule.root, envWalkCap)
			}
			p := dir + "/" + n
			pi, err := tr.PathInfo(p)
			if err != nil {
				return false, err
			}
			if pi.Regular && rule.covers(p, pi.UID) && rule.loose(pi.Perm) {
				return true, nil
			}
			if pi.Dir && depth < envDepth {
				if open, err := walk(p, depth+1); err != nil || open {
					return open, err
				}
			}
		}
		return false, nil
	}
	return walk(rule.root, 1)
}
