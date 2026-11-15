package checks

import (
	"testing"
	"time"

	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/profile"
)

func csAt(d time.Duration) *time.Time {
	t := tsNow.Add(-d)
	return &t
}

func csBouncer(name, kind string, age time.Duration) facts.CrowdSecBouncer {
	return facts.CrowdSecBouncer{Name: name, Kind: kind, LastPull: csAt(age)}
}

// csBase is an installed, running CrowdSec whose bouncers were listed.
func csBase(bs ...facts.CrowdSecBouncer) *facts.CrowdSec {
	return &facts.CrowdSec{Installed: true, Cscli: true, ProcessesRead: true, ProcessesVisible: true, EngineProcesses: 1,
		BouncersRead: true, Bouncers: bs, HubRead: true, AcquisitionRead: true, ParserFilesRead: true}
}

func csFacts(c *facts.CrowdSec, mut ...func(*facts.Facts)) *facts.Facts {
	f := &facts.Facts{CollectedAt: tsNow, CrowdSec: c}
	for _, m := range mut {
		m(f)
	}
	return f
}

func withTunnel(f *facts.Facts)   { f.Cloudflared = cfTunnel(2) }
func withNoTunnel(f *facts.Facts) { f.Cloudflared = cfAbsent }

var csAbsent = &facts.CrowdSec{ProcessesRead: true, ProcessesVisible: true}

func TestCS001(t *testing.T) {
	stopped := csBase()
	stopped.EngineProcesses = 0
	stopped.Unit = &facts.ServiceUnit{Name: "crowdsec.service", LoadState: "loaded", ActiveState: "failed"}
	hidden := &facts.CrowdSec{Installed: true, ProcessesRead: true}
	netCases(t, "CS-001", []netCase{
		{"no facts", &facts.Facts{}, "", Unknown},
		{"absent", csFacts(csAbsent), "", Skip},
		{"running", csFacts(csBase()), "", Pass},
		{"stopped", csFacts(stopped), "", Fail},
		{"hidden", csFacts(hidden), "", Unknown},
	})
}

func TestCS002(t *testing.T) {
	unread := csBase()
	unread.BouncersRead = false
	revoked := csBase(facts.CrowdSecBouncer{Name: "old", Kind: "proxy", Revoked: true, LastPull: csAt(time.Second)})
	netCases(t, "CS-002", []netCase{
		{"no facts", &facts.Facts{}, "", Unknown},
		{"absent", csFacts(csAbsent), "", Skip},
		{"none", csFacts(csBase()), "", Fail},
		{"only revoked", csFacts(revoked), "", Fail},
		{"fresh", csFacts(csBase(csBouncer("traefik", "proxy", 10*time.Second))), "", Pass},
		{"stale", csFacts(csBase(csBouncer("traefik", "proxy", 10*time.Minute))), "", Warn},
		{"never pulled", csFacts(csBase(facts.CrowdSecBouncer{Name: "fw", Kind: "firewall"})), "", Warn},
		{"unread", csFacts(unread), "", Unknown},
	})
}

func TestCS003(t *testing.T) {
	fw := csBouncer("fw", "firewall", time.Second)
	proxy := csBouncer("traefik", "proxy", time.Second)
	edge := csBouncer("cf", "cloudflare", time.Second)
	unread := csBase()
	unread.BouncersRead = false
	netCases(t, "CS-003", []netCase{
		{"no facts", &facts.Facts{}, "", Unknown},
		{"absent", csFacts(csAbsent, withTunnel), "", Skip},
		{"no tunnel", csFacts(csBase(fw), withNoTunnel), "", Skip},
		{"tunnel unknown", csFacts(csBase(fw)), "", Unknown},
		{"tunnel, firewall only", csFacts(csBase(fw), withTunnel), "", Fail},
		{"tunnel profile, firewall only", csFacts(csBase(fw)), profile.Tunnel, Fail},
		{"tunnel, proxy", csFacts(csBase(fw, proxy), withTunnel), "", Pass},
		{"tunnel, cloudflare", csFacts(csBase(edge), withTunnel), "", Pass},
		{"tunnel, none", csFacts(csBase(), withTunnel), "", Fail},
		{"tunnel, unclassified", csFacts(csBase(csBouncer("x", "other", time.Second)), withTunnel), "", Unknown},
		{"tunnel, unread", csFacts(unread, withTunnel), "", Unknown},
	})
}

func TestCS004(t *testing.T) {
	wl := facts.CrowdSecParserFile{Path: "/etc/crowdsec/parsers/s02-enrich/whitelists.yaml", WhitelistIPs: []string{"127.0.0.1", "::1"},
		WhitelistCIDRs: []string{"192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"}}
	publicWL := facts.CrowdSecParserFile{Path: "/etc/crowdsec/parsers/s02-enrich/mine.yaml", WhitelistIPs: []string{"198.51.100.7"}}
	ranged := facts.CrowdSecParserFile{Path: "/etc/crowdsec/parsers/s02-enrich/real-ip.yaml", RealIPHeader: "cf-connecting-ip"}
	keyed := facts.CrowdSecParserFile{Path: "/etc/crowdsec/parsers/s02-enrich/real-ip.yaml", RealIPHeader: "cf-connecting-ip", RealIPKeyedTo: []string{"172.18.0.1"}}
	with := func(files ...facts.CrowdSecParserFile) *facts.CrowdSec {
		c := csBase()
		c.ParserFiles = files
		return c
	}
	unread := csBase()
	unread.ParserFilesRead = false
	netCases(t, "CS-004", []netCase{
		{"no facts", &facts.Facts{}, "", Unknown},
		{"absent", csFacts(csAbsent, withTunnel), "", Skip},
		{"no tunnel", csFacts(with(wl), withNoTunnel), "", Skip},
		{"tunnel unknown", csFacts(with(wl)), "", Unknown},
		{"whitelist, no real ip", csFacts(with(wl), withTunnel), "", Fail},
		{"no whitelist, no real ip", csFacts(with(publicWL), withTunnel), "", Warn},
		{"keyed real ip", csFacts(with(wl, keyed), withTunnel), "", Warn},
		{"ranged real ip", csFacts(with(wl, ranged), withTunnel), "", Pass},
		{"unread", csFacts(unread, withTunnel), "", Unknown},
	})
}

func TestCS005(t *testing.T) {
	traefik := csBase()
	traefik.Acquisition = []facts.CrowdSecSource{{File: "/etc/crowdsec/acquis.d/traefik.yaml", Source: "docker", Type: "traefik"}}
	syslogOnly := csBase()
	syslogOnly.Acquisition = []facts.CrowdSecSource{{File: "/etc/crowdsec/acquis.yaml", Source: "file", Type: "syslog"}}
	unread := csBase()
	unread.AcquisitionRead = false
	web := func(f *facts.Facts) {
		f.Cloudflared = cfAbsent
		f.Listeners = &facts.Listeners{Sockets: []facts.Listener{netSock("tcp", "0.0.0.0", 443, "docker-proxy")}}
	}
	quiet := func(f *facts.Facts) {
		f.Cloudflared = cfAbsent
		f.Listeners = &facts.Listeners{Sockets: []facts.Listener{netSock("tcp", "0.0.0.0", 22, "sshd")}}
	}
	netCases(t, "CS-005", []netCase{
		{"no facts", &facts.Facts{}, "", Unknown},
		{"absent", csFacts(csAbsent), "", Skip},
		{"no proxy", csFacts(syslogOnly, quiet), "", Skip},
		{"listeners missing", csFacts(syslogOnly, withNoTunnel), "", Unknown},
		{"proxy acquired", csFacts(traefik, web), "", Pass},
		{"proxy not acquired", csFacts(syslogOnly, web), "", Warn},
		{"tunnel, not acquired", csFacts(syslogOnly, withTunnel), "", Warn},
		{"unread", csFacts(unread, withTunnel), "", Unknown},
	})
}

func TestCS006(t *testing.T) {
	listen := func(v string) *facts.CrowdSec { c := csBase(); c.LAPIListen = v; return c }
	viaSockets := func(addr string) func(*facts.Facts) {
		return func(f *facts.Facts) {
			f.Listeners = &facts.Listeners{Sockets: []facts.Listener{netSock("tcp", addr, 8080, "crowdsec")}}
		}
	}
	netCases(t, "CS-006", []netCase{
		{"no facts", &facts.Facts{}, "", Unknown},
		{"absent", csFacts(csAbsent), "", Skip},
		{"loopback", csFacts(listen("127.0.0.1:8080")), "", Pass},
		{"docker bridge", csFacts(listen("172.17.0.1:8080")), "", Pass},
		{"wildcard", csFacts(listen("0.0.0.0:8080")), "", Warn},
		{"empty host", csFacts(listen(":8080")), "", Warn},
		{"from sockets, wildcard", csFacts(csBase(), viaSockets("::")), "", Warn},
		{"from sockets, loopback", csFacts(csBase(), viaSockets("127.0.0.1")), "", Pass},
		{"unknown", csFacts(csBase()), "", Unknown},
	})
}

func TestCS007(t *testing.T) {
	fwBouncer := csBase(csBouncer("fw", "firewall", time.Second))
	ipt := func(dockerUser ...string) func(*facts.Facts) {
		return func(f *facts.Facts) {
			f.Cloudflared = cfAbsent
			f.Firewall = &facts.Firewall{DockerBackend: "iptables", DockerUser: "default",
				Iptables: &facts.Iptables{Installed: true, Listed: true, Chains: []string{"CROWDSEC_CHAIN", "DOCKER", "DOCKER-USER", "INPUT"}, DockerUserRules: dockerUser}}
		}
	}
	nftForward := func(f *facts.Facts) {
		f.Cloudflared = cfAbsent
		f.Firewall = &facts.Firewall{DockerBackend: "nftables", NFT: &facts.NFTables{Installed: true, Listed: true,
			Tables: []facts.NFTTable{{Family: "ip", Name: "crowdsec"}},
			Chains: []facts.NFTChain{{Family: "ip", Table: "crowdsec", Name: "crowdsec-chain-input", Hook: "input"}, {Family: "ip", Table: "crowdsec", Name: "crowdsec-chain-forward", Hook: "forward"}}}}
	}
	noDocker := func(f *facts.Facts) { f.Cloudflared = cfAbsent; f.Firewall = &facts.Firewall{DockerBackend: "none"} }
	unreadFW := func(f *facts.Facts) { f.Cloudflared = cfAbsent; f.Firewall = &facts.Firewall{} }
	netCases(t, "CS-007", []netCase{
		{"no facts", &facts.Facts{}, "", Unknown},
		{"absent", csFacts(csAbsent, ipt()), "", Skip},
		{"firewall missing", csFacts(fwBouncer), "", Unknown},
		{"behind tunnel", csFacts(fwBouncer, ipt(), withTunnel), "", Skip},
		{"no docker", csFacts(fwBouncer, noDocker), "", Skip},
		{"firewall unread", csFacts(fwBouncer, unreadFW), "", Unknown},
		{"no firewall bouncer", csFacts(csBase(csBouncer("traefik", "proxy", time.Second)), func(f *facts.Facts) {
			ipt()(f)
			f.Firewall.Iptables.Chains = []string{"DOCKER", "DOCKER-USER", "INPUT"}
		}), "", Skip},
		{"docker-user hooked", csFacts(fwBouncer, ipt("-A DOCKER-USER -j CROWDSEC_CHAIN", "-A DOCKER-USER -j RETURN")), "", Pass},
		{"docker-user not hooked", csFacts(fwBouncer, ipt("-A DOCKER-USER -j RETURN")), "", Warn},
		{"nftables forward hook", csFacts(fwBouncer, nftForward), "", Pass},
	})
}

func TestCS008(t *testing.T) {
	unread := csBase()
	unread.BouncersRead = false
	netCases(t, "CS-008", []netCase{
		{"no facts", &facts.Facts{}, "", Unknown},
		{"absent", csFacts(csAbsent), "", Skip},
		{"no proxy bouncer", csFacts(csBase(csBouncer("fw", "firewall", 2*time.Minute))), "", Skip},
		{"slow", csFacts(csBase(csBouncer("traefik", "proxy", 2*time.Minute))), "", Warn},
		{"recent", csFacts(csBase(csBouncer("traefik", "proxy", 5*time.Second))), "", Unknown},
		{"stale is CS-002", csFacts(csBase(csBouncer("traefik", "proxy", time.Hour))), "", Unknown},
		{"unread", csFacts(unread), "", Unknown},
	})
}

func TestCS010(t *testing.T) {
	publicSSH := func(f *facts.Facts) {
		f.Listeners = &facts.Listeners{Sockets: []facts.Listener{netSock("tcp", "0.0.0.0", 2222, "sshd")}}
		f.Firewall = netUFW("deny", facts.UFWRule{Action: "allow", Direction: "in", Port: "2222", Proto: "tcp"})
	}
	privateSSH := func(f *facts.Facts) {
		f.Listeners = &facts.Listeners{Sockets: []facts.Listener{netSock("tcp", "0.0.0.0", 22, "sshd")}}
		f.Firewall = netUFW("deny", netSSHTailnet)
	}
	jail := func(port string) *facts.Fail2ban {
		return &facts.Fail2ban{Installed: true, StatusRead: true, ActiveJails: []string{"sshd"}, ConfigRead: true,
			Jails: []facts.Fail2banJail{{Name: "sshd", Enabled: true, Port: port}}}
	}
	f2bOff := &facts.Fail2ban{}
	csSSH := csBase()
	csSSH.Collections = []string{"crowdsecurity/sshd"}
	with := func(c *facts.CrowdSec, f2b *facts.Fail2ban, mut func(*facts.Facts)) *facts.Facts {
		f := &facts.Facts{CrowdSec: c, Fail2ban: f2b}
		mut(f)
		return f
	}
	netCases(t, "CS-010", []netCase{
		{"no facts", &facts.Facts{}, "", Unknown},
		{"ssh private", with(nil, nil, privateSSH), "", Pass},
		{"public, crowdsec sshd", with(csSSH, nil, publicSSH), "", Pass},
		{"public, jail on the real port", with(csAbsent, jail("ssh,2222"), publicSSH), "", Pass},
		{"public, jail on 22 only", with(csAbsent, jail("ssh"), publicSSH), "", Warn},
		{"public, jail port unresolvable", with(csAbsent, jail("sshd-custom"), publicSSH), "", Unknown},
		{"public, nothing", with(csAbsent, f2bOff, publicSSH), "", Fail},
		{"public, fail2ban facts missing", with(csAbsent, nil, publicSSH), "", Unknown},
		{"public, crowdsec hub unread", with(&facts.CrowdSec{Installed: true}, f2bOff, publicSSH), "", Unknown},
	})
}

func TestCS011(t *testing.T) {
	jails := func(ignore ...string) *facts.Fail2ban {
		return &facts.Fail2ban{Installed: true, ConfigRead: true, Jails: []facts.Fail2banJail{
			{Name: "sshd", Enabled: true, Port: "ssh", IgnoreIP: ignore},
		}}
	}
	ts := tsRunning()
	netCases(t, "CS-011", []netCase{
		{"no facts", &facts.Facts{}, "", Unknown},
		{"no fail2ban", &facts.Facts{Fail2ban: &facts.Fail2ban{}, Tailscale: ts}, "", Skip},
		{"tailscale missing", &facts.Facts{Fail2ban: jails()}, "", Unknown},
		{"no tailscale", &facts.Facts{Fail2ban: jails(), Tailscale: &facts.Tailscale{}}, "", Skip},
		{"range ignored", &facts.Facts{Fail2ban: jails("127.0.0.1/8", "100.64.0.0/10"), Tailscale: ts}, "", Pass},
		{"wider range ignored", &facts.Facts{Fail2ban: jails("100.0.0.0/8"), Tailscale: ts}, "", Pass},
		{"single peer only", &facts.Facts{Fail2ban: jails("100.101.102.103"), Tailscale: ts}, "", Warn},
		{"not ignored", &facts.Facts{Fail2ban: jails("127.0.0.1/8"), Tailscale: ts}, "", Warn},
		{"no enabled jail", &facts.Facts{Fail2ban: &facts.Fail2ban{Installed: true, ConfigRead: true}, Tailscale: ts}, "", Skip},
		{"config unread", &facts.Facts{Fail2ban: &facts.Fail2ban{Installed: true}, Tailscale: ts}, "", Unknown},
	})
}
