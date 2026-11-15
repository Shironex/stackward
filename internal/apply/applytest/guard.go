package applytest

import (
	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/facts/sshd"
)

// GuardFacts fills f with the facts the lockout guard reads, for a host
// where alice (uid 1000, sudo through %sudo, an ed25519 key) can log in,
// Tailscale runs with key expiry off, and UFW lets 22 in from anywhere
// and on tailscale0. Tests take pieces away to see the guard refuse.
func GuardFacts(f *facts.Facts) *facts.Facts {
	f.SSH = &facts.SSH{
		Installed: true, Source: "sshd -T", Complete: true,
		Effective: map[string][]string{
			"pubkeyauthentication": {"yes"}, "authenticationmethods": {"any"}, "usepam": {"yes"},
			"passwordauthentication": {"yes"}, "authorizedkeysfile": {".ssh/authorized_keys"},
			"port": {"22"}, "listenaddress": {"0.0.0.0:22"},
		},
		Config: &sshd.Config{},
		Users: []facts.SSHUser{{Name: "alice", UID: 1000, Home: "/home/alice", KeyFiles: []facts.SSHKeyFile{{
			Path: "/home/alice/.ssh/authorized_keys", Keys: []sshd.PubKey{{Type: "ssh-ed25519", Bits: 256}},
		}}}},
	}
	f.Users = &facts.Users{
		Accounts: []facts.Account{
			{Name: "root", UID: 0, Home: "/root", Shell: "/bin/bash", LoginShell: true},
			{Name: "alice", UID: 1000, GID: 1000, Home: "/home/alice", Shell: "/bin/bash", LoginShell: true},
		},
		Groups:  []facts.Group{{Name: "sudo", GID: 27, Members: []string{"alice"}}},
		Sudoers: []facts.Sudoers{{Path: "/etc/sudoers", Readable: true, Principals: []string{"%sudo"}}},
	}
	f.Tailscale = &facts.Tailscale{Installed: true, StatusRead: true, BackendState: "Running"}
	f.Firewall = &facts.Firewall{UFW: &facts.UFW{Installed: true, Status: "active", DefaultIncoming: "deny", RulesKnown: true, Rules: []facts.UFWRule{
		{Action: "allow", Direction: "in", Port: "22", Proto: "tcp"},
		{Action: "allow", Direction: "in", Port: "22", Proto: "tcp", Interface: "tailscale0"},
	}}}
	return f
}
