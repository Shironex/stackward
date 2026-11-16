package plan

import (
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/Shironex/stackward/internal/facts"
)

// The never touched list: things no step may change, whatever it fixes.
// Each one either takes the host off the network, cuts the second way in
// that the lockout guard relies on, breaks Docker or the platform, or can
// only be repaired from the provider console. A step is judged by its
// targets (Touched): the kind:name targets it declares, every file it
// edits, and every program its commands run with their arguments. Build
// refuses such a step at plan time (skipped, kind refused) and Authorize
// refuses it again at apply time and undo time, so a hand edited plan
// cannot slip past by dropping a target from touches.
//
// A step that needs one narrow thing an entry covers gets an exception of
// its own (NeverTouchedExceptions): one step id, exact targets, never a
// pattern. docs/safety.md lists the same entries and exceptions for
// readers; a test keeps the two in step.

// NeverTouchedItem is one entry of the never touched list.
type NeverTouchedItem struct {
	ID string
	// What names the thing in words.
	What string
	// Why says what goes wrong when it is changed.
	Why string
	// Targets are patterns over kind:name targets; "*" matches any run of
	// characters, "/" included. File paths are cleaned before matching.
	Targets []string
}

// NeverTouched is the list, in the order docs/safety.md shows it.
var NeverTouched = []NeverTouchedItem{
	{
		ID: "network-config", What: "the provider's network configuration (cloud-init, netplan, ifupdown, systemd-networkd)",
		Why: "a wrong address, route or renderer takes the host off the network at the next apply or boot, and only the provider console can bring it back",
		Targets: []string{
			"file:/etc/netplan", "file:/etc/netplan/*", "file:/etc/network/interfaces", "file:/etc/network/interfaces.d/*",
			"file:/etc/cloud/cloud.cfg.d/*network*", "file:/etc/systemd/network/*", "cmd:netplan",
			"service:systemd-networkd", "service:networking",
		},
	},
	{
		ID: "tailscale", What: "Tailscale's state and the settings the tailnet ACLs see (login, node key, tags, advertised routes, Tailscale SSH)",
		Why: "the tailnet is the second way in that the lockout guard proves before public SSH closes; a logout, a new node key or a changed tag can cut it silently while everyone believes SSH is private",
		Targets: []string{
			"file:/var/lib/tailscale", "file:/var/lib/tailscale/*", "file:/etc/default/tailscaled",
			"service:tailscaled", "cmd:tailscale", "tailscale:*",
		},
	},
	{
		ID: "cloudflared", What: "cloudflared's configuration and tunnel credentials",
		Why: "the tunnel is the public ingress of a tunnel host; a changed config or credential takes every site offline, and the credentials are secrets stackward never reads",
		Targets: []string{
			"file:/etc/cloudflared", "file:/etc/cloudflared/*", "file:/usr/local/etc/cloudflared/*",
			"file:/root/.cloudflared/*", "file:/home/*/.cloudflared/*", "service:cloudflared", "cmd:cloudflared",
		},
	},
	{
		ID: "paas-data", What: "the data directories of Coolify and Dokploy, their SSH keys included",
		Why: "the platform owns these files and rewrites them on every deploy; its SSH keys are how it reaches this and every other managed server, so a change breaks deploys or locks the platform out",
		Targets: []string{
			"file:/data/coolify", "file:/data/coolify/*", "file:/etc/dokploy", "file:/etc/dokploy/*", "paas:*",
			"file-mode:/data/coolify", "file-mode:/data/coolify/*", "file-mode:/etc/dokploy", "file-mode:/etc/dokploy/*",
		},
	},
	{
		ID: "docker-data", What: "Docker's data root (/var/lib/docker, /var/lib/containerd)",
		Why: "it holds every image, container and volume; Docker alone may change it, and a moved or edited data root loses data",
		Targets: []string{
			"file:/var/lib/docker", "file:/var/lib/docker/*", "file:/var/lib/containerd", "file:/var/lib/containerd/*",
			"docker-daemon:data-root",
		},
	},
	{
		ID: "docker-firewall", What: "Docker daemon firewall settings (iptables, ip6tables, ip-forward, ip-masq, firewall-backend)",
		Why: "Docker programs the NAT and forwarding rules its containers need; turning them off breaks container networking and the DOCKER-USER chain that ufw-docker relies on",
		Targets: []string{
			"docker-daemon:iptables", "docker-daemon:ip6tables", "docker-daemon:ip-forward", "docker-daemon:ip-forward-no-drop",
			"docker-daemon:ip-masq", "docker-daemon:firewall-backend",
		},
	},
	{
		ID: "ip-forward", What: "kernel forwarding (net.ipv4.ip_forward and the forwarding settings of every interface)",
		Why: "Docker and Tailscale subnet routing need it; generic hardening profiles turn it off and silently break both",
		Targets: []string{
			"sysctl:net.ipv4.ip_forward", "sysctl:net.ipv4.conf.*.forwarding", "sysctl:net.ipv6.conf.*.forwarding",
			"cmd:sysctl:*ip_forward*", "cmd:sysctl:*.forwarding*",
		},
	},
	{
		ID: "provider-firewall", What: "the provider's network firewall",
		Why:     "it sits outside the host, stackward cannot see it, and it is the layer that still holds when the host firewall is wrong",
		Targets: []string{"provider-firewall:*"},
	},
	{
		ID: "boot", What: "/boot and the bootloader (GRUB configuration, kernel command line, initramfs, EFI entries)",
		Why: "a broken bootloader or kernel command line leaves a host that does not boot, which only rescue mode can repair",
		Targets: []string{
			"file:/boot", "file:/boot/*", "file:/etc/default/grub", "file:/etc/default/grub.d/*", "file:/etc/grub.d/*",
			"file:/etc/kernel/*", "cmd:grub-install", "cmd:update-grub", "cmd:grub-mkconfig", "cmd:update-initramfs",
			"cmd:efibootmgr",
		},
	},
	{
		ID: "root-password", What: "the root account's password, and the account files edited by hand",
		Why: "root's password is the provider console login of last resort; locking or changing it can make the console useless when SSH is gone, and an edited /etc/shadow or /etc/passwd can lock every account",
		Targets: []string{
			"file:/etc/shadow", "file:/etc/gshadow", "file:/etc/passwd", "file:/etc/group", "password:root",
			"cmd:passwd:root", "cmd:usermod:root", "cmd:chage:root", "cmd:chpasswd",
		},
	},
	{
		ID: "root-keys", What: "root's authorized_keys (removing keys from it, or any edit)",
		Why:     "the platform (Coolify, Dokploy) and recovery tooling often log in as root with a key; removing it cuts them off, and root login is turned off in sshd instead",
		Targets: []string{"file:/root/.ssh", "file:/root/.ssh/*", "authorized-keys:root"},
	},
	{
		ID: "pam", What: "PAM (/etc/pam.d, /etc/pam.conf, /etc/security)",
		Why:     "one wrong PAM line refuses every login, console included, or lets anyone in; it is not part of any step",
		Targets: []string{"file:/etc/pam.d", "file:/etc/pam.d/*", "file:/etc/pam.conf", "file:/etc/security/*", "cmd:pam-auth-update"},
	},
	{
		ID: "admin-sudo", What: "sudo rights of existing accounts (/etc/sudoers itself, revoking anyone's sudo, deleting accounts)",
		Why: "removing the current admin's sudo leaves nobody who can undo the change; stackward only adds sudoers drop-ins and locks accounts, it never takes sudo away or deletes an account",
		Targets: []string{
			"file:/etc/sudoers", "sudo-revoke:*", "user-delete:*", "cmd:userdel", "cmd:deluser", "cmd:delgroup",
			"cmd:gpasswd:-d", "cmd:gpasswd:--delete",
		},
	},
}

// NeverTouchedException lets exactly one step reach exactly the targets
// it names of one entry. An exception is never a pattern: each target is
// matched whole, so it cannot grow into a wider hole in the list.
type NeverTouchedException struct {
	// Step is the one step id the exception is for.
	Step string
	// Entry is the never touched entry it carves out of.
	Entry string
	// What says what the step may do there, in words.
	What string
	// Targets are the exact targets the step may reach.
	Targets []string
}

// NeverTouchedExceptions are the exceptions, in the order docs/safety.md
// shows them.
var NeverTouchedExceptions = []NeverTouchedException{
	{
		Step: "paas-env-perms", Entry: "paas-data",
		What: "remove the group and other permission bits of the platform's .env files (chmod only), from a timer, because the platform rewrites them loose on every deploy; never their content, never their owner",
		Targets: []string{
			"file-mode:" + facts.CoolifyApplications, "file-mode:" + facts.CoolifyServices, "file-mode:" + facts.CoolifyMainEnv,
			"file-mode:" + facts.DokployApplications, "file-mode:" + facts.DokployCompose,
		},
	},
	{
		Step: AdminUserID, Entry: "root-keys",
		What:    "read root's authorized_keys as the source of the new admin account's keys (--admin-keys-from root, on a root only image): install copies it to the new account's home; root's own file is never changed",
		Targets: []string{"file:" + rootKeysFile},
	},
}

// excepted reports whether an exception lets step id reach target t of
// entry.
func excepted(id, entry, t string) bool {
	for _, x := range NeverTouchedExceptions {
		if x.Step == id && x.Entry == entry && slices.Contains(x.Targets, t) {
			return true
		}
	}
	return false
}

// Touched returns every target step s reaches, in the kind:name form the
// list matches: its declared touches; file:PATH for every edit; for every
// command, cmd:PROG and cmd:PROG:ARG for each argument (PROG is the base
// name of the program) and file:PATH for each absolute path argument. An
// undo only reverses what its own step did (a created user is deleted
// again), so undo commands count only for the files they name.
func Touched(s Step) []string {
	seen := map[string]bool{}
	var out []string
	add := func(t string) {
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	for _, t := range s.Touches {
		add(normTarget(t))
	}
	for _, e := range s.Edits {
		add(normTarget("file:" + e.Path))
	}
	for _, c := range s.Commands {
		if len(c.Args) == 0 {
			continue
		}
		prog := path.Base(c.Args[0])
		add("cmd:" + prog)
		for _, a := range c.Args[1:] {
			add("cmd:" + prog + ":" + a)
		}
		for _, a := range c.Args {
			if path.IsAbs(a) {
				add(normTarget("file:" + a))
			}
		}
	}
	for _, c := range s.Undo.Commands {
		for _, a := range c.Args {
			if path.IsAbs(a) {
				add(normTarget("file:" + a))
			}
		}
	}
	return out
}

// normTarget cleans the path of a file target, so /etc/../boot/x is
// judged as /boot/x.
func normTarget(t string) string {
	if p, ok := strings.CutPrefix(t, "file:"); ok && p != "" {
		return "file:" + path.Clean(p)
	}
	return t
}

// NeverTouchedVeto is the plan time policy: it refuses a step that reaches
// anything on the never touched list, naming the target and the reason.
func NeverTouchedVeto(s Step) string {
	if err := checkNeverTouched(s); err != nil {
		return err.Error()
	}
	return ""
}

// checkNeverTouched returns an error naming the first never touched item
// step s reaches.
func checkNeverTouched(s Step) error {
	for _, t := range Touched(s) {
		for _, it := range NeverTouched {
			for _, p := range it.Targets {
				if targetMatch(p, t) && !excepted(s.ID, it.ID, t) {
					return fmt.Errorf("never touched: %s reaches %s (%s), which no step may change: %s", s.ID, t, it.What, it.Why)
				}
			}
		}
	}
	return nil
}

// targetMatch matches target t against pattern p. A program pattern
// (cmd:PROG) also covers that program with any argument (cmd:PROG:ARG).
func targetMatch(p, t string) bool {
	if wildMatch(p, t) {
		return true
	}
	return strings.HasPrefix(p, "cmd:") && strings.Count(p, ":") == 1 && wildMatch(p+":*", t)
}

// wildMatch reports whether s matches pattern, where "*" matches any run
// of characters and "?" any one character. Nothing else is special.
func wildMatch(pattern, s string) bool {
	p, i := 0, 0
	star, mark := -1, 0
	for i < len(s) {
		switch {
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == s[i]):
			p++
			i++
		case p < len(pattern) && pattern[p] == '*':
			star, mark = p, i
			p++
		case star >= 0:
			p = star + 1
			mark++
			i = mark
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}
