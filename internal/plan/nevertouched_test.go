package plan

import (
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/facts"
)

func TestNeverTouchedTargets(t *testing.T) {
	refused := map[string]string{
		"file:/etc/netplan/50-cloud-init.yaml":                     "network-config",
		"file:/etc/cloud/cloud.cfg.d/99-disable-network-config":    "network-config",
		"file:/etc/network/interfaces":                             "network-config",
		"file:/var/lib/tailscale/tailscaled.state":                 "tailscale",
		"cmd:tailscale:up":                                         "tailscale",
		"service:tailscaled":                                       "tailscale",
		"file:/etc/cloudflared/config.yml":                         "cloudflared",
		"file:/home/deploy/.cloudflared/cert.pem":                  "cloudflared",
		"file:/data/coolify/ssh/keys/id.root@host.docker.internal": "paas-data",
		"file:/etc/dokploy/traefik/traefik.yml":                    "paas-data",
		"file:/var/lib/docker/volumes/x/_data":                     "docker-data",
		"docker-daemon:data-root":                                  "docker-data",
		"docker-daemon:iptables":                                   "docker-firewall",
		"sysctl:net.ipv4.ip_forward":                               "ip-forward",
		"sysctl:net.ipv6.conf.all.forwarding":                      "ip-forward",
		"cmd:sysctl:net.ipv4.ip_forward=0":                         "ip-forward",
		"provider-firewall:inbound":                                "provider-firewall",
		"file:/boot/grub/grub.cfg":                                 "boot",
		"file:/etc/default/grub":                                   "boot",
		"cmd:update-grub":                                          "boot",
		"cmd:passwd:root":                                          "root-password",
		"file:/etc/shadow":                                         "root-password",
		"file:/root/.ssh/authorized_keys":                          "root-keys",
		"file:/etc/pam.d/sshd":                                     "pam",
		"file:/etc/security/access.conf":                           "pam",
		"file:/etc/sudoers":                                        "admin-sudo",
		"cmd:gpasswd:-d":                                           "admin-sudo",
		"sudo-revoke:alice":                                        "admin-sudo",
	}
	for target, want := range refused {
		got := ""
		for _, it := range NeverTouched {
			for _, p := range it.Targets {
				if got == "" && targetMatch(p, target) {
					got = it.ID
				}
			}
		}
		if got != want {
			t.Errorf("%s: matched %q, want %q", target, got, want)
		}
	}
	// What the steps of this release and the next ones touch stays free.
	for _, target := range []string{
		"file:/etc/sysctl.d/90-stackward-hardening.conf", "sysctl:net.ipv4.conf.all.rp_filter", "service:systemd-journald",
		"file:/etc/systemd/journald.conf.d/90-stackward.conf", "file:/etc/docker/daemon.json", "docker-daemon:log-opts",
		"docker-daemon:log-driver", "service:docker", "file:/etc/ssh/sshd_config.d/01-stackward.conf", "service:ssh",
		"file:/etc/sudoers.d/90-stackward-admin", "cmd:useradd:admin", "cmd:usermod:ubuntu", "cmd:passwd:ubuntu",
		"cmd:ufw:allow", "file:/etc/ufw/after.rules", "file:/home/admin/.ssh/authorized_keys", "cmd:systemctl:restart",
	} {
		s := Step{ID: "x", Touches: []string{target}}
		if err := checkNeverTouched(s); err != nil {
			t.Errorf("%s refused: %v", target, err)
		}
	}
}

func TestTouchedDerivesTargets(t *testing.T) {
	s := Step{
		ID:      "x",
		Touches: []string{"service:ssh"},
		Edits:   []FileEdit{{Path: "/etc/ssh/../../boot/grub/grub.cfg"}},
		Commands: []Command{
			{Args: []string{"/usr/sbin/sysctl", "-w", "net.ipv4.ip_forward=0"}},
			{Args: []string{"install", "-m", "0600", "/etc/netplan/x.yaml"}},
		},
		Undo: Undo{Commands: []Command{{Args: []string{"userdel", "admin"}}, {Args: []string{"rm", "-f", "/etc/pam.d/sshd"}}}},
	}
	got := strings.Join(Touched(s), " ")
	for _, want := range []string{
		"service:ssh", "file:/boot/grub/grub.cfg", "cmd:sysctl", "cmd:sysctl:net.ipv4.ip_forward=0",
		"cmd:install:/etc/netplan/x.yaml", "file:/etc/netplan/x.yaml", "file:/etc/pam.d/sshd",
	} {
		if !strings.Contains(" "+got+" ", " "+want+" ") {
			t.Errorf("touched %q lacks %q", got, want)
		}
	}
	// An undo that deletes the user its step created is not judged as a
	// command; only the files it names count.
	if strings.Contains(got, "cmd:userdel") {
		t.Errorf("undo commands judged as commands: %q", got)
	}
	err := checkNeverTouched(s)
	if err == nil || !strings.Contains(err.Error(), "never touched: x reaches file:/boot/grub/grub.cfg") {
		t.Errorf("err %v", err)
	}
}

// Plan time: Build refuses a step that reaches the list, as skipped with
// kind refused and the reason, whatever Options.Vetoes says.
func TestBuildRefusesNeverTouchedSteps(t *testing.T) {
	g := Generator{
		ID: "test-netplan", Title: "Test: edit netplan", Fixes: []string{"NET-001"}, Risk: Safe,
		Plan: func(Input) Outcome {
			return Outcome{Step: &Step{Edits: []FileEdit{newEdit("/etc/netplan/50-cloud-init.yaml", Replace, "", "a\n", "b\n")}}}
		},
	}
	in := Input{Facts: &facts.Facts{}, Results: []checks.Result{{ID: "NET-001", Level: checks.Fail}}}
	p := BuildWith([]Generator{g}, in, testReport(), Options{Version: "test"})
	if len(p.Steps) != 0 || len(p.Skipped) != 1 {
		t.Fatalf("steps %v skipped %v", p.Steps, p.Skipped)
	}
	sk := p.Skipped[0]
	if sk.Kind != SkipRefused || !strings.Contains(sk.Reason, "never touched: test-netplan reaches file:/etc/netplan/50-cloud-init.yaml") || !strings.Contains(sk.Reason, "provider console") {
		t.Errorf("skipped %+v", sk)
	}
}
