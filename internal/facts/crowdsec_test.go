package facts

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// fakeBouncerKey is assembled at run time so secret scanners do not flag
// the source.
var fakeBouncerKey = strings.Repeat("k3y", 11)

const csUnitKey = "systemctl show crowdsec.service --property=" + unitProperties

const csWhitelists = `name: crowdsecurity/whitelists
description: "Whitelist events from private ipv4 addresses"
whitelist:
  reason: "private ipv4/ipv6 ip/ranges"
  ip:
    - "127.0.0.1"
    - "::1"
  cidr:
    - "192.168.0.0/16"
    - "10.0.0.0/8"
    - "172.16.0.0/12"
`

const csRealIPKeyed = `onsuccess: next_stage
filter: "evt.Meta.service == 'http' && evt.Meta.source_ip == '172.18.0.1'"
name: example/cf-real-ip
statics:
  - meta: source_ip
    expression: evt.Unmarshaled.traefik["request_Cf-Connecting-Ip"]
`

func TestCrowdSecCollector(t *testing.T) {
	sys := newFakeSystem(map[string]string{
		"/proc/1/comm":                                     "systemd\n",
		"/proc/50/comm":                                    "crowdsec\n",
		"/proc/50/cgroup":                                  "0::/system.slice/crowdsec.service\n",
		"/etc/crowdsec/acquis.yaml":                        "filenames:\n  - /var/log/auth.log\nlabels:\n  type: syslog\n",
		"/etc/crowdsec/acquis.d/traefik.yaml":              "source: docker\ncontainer_name:\n  - traefik\nlabels:\n  type: traefik\n",
		"/etc/crowdsec/parsers/s02-enrich/whitelists.yaml": csWhitelists,
		"/etc/crowdsec/parsers/s02-enrich/cf-real-ip.yaml": csRealIPKeyed,
		"/etc/crowdsec/parsers/s01-parse/sshd-logs.yaml":   "name: crowdsecurity/sshd-logs\nfilter: evt.Parsed.program == 'sshd'\n",
		"/etc/crowdsec/local_api_credentials.yaml":         "password: " + fakeBouncerKey,
	})
	sys.host.Root = true
	sys.cmds[csUnitKey] = unitShow("loaded", "active", "enabled")
	sys.cmds["cscli version"] = CmdResult{Stderr: []byte("version: v1.6.4-debian-pragmatic\nCodename: alphaga\n")}
	sys.cmds["cscli bouncers list -o json"] = CmdResult{Stdout: []byte(`[
  {"name":"traefik-bouncer","ip_address":"172.18.0.5","api_key":"` + fakeBouncerKey + `","revoked":false,"type":"crowdsec-bouncer-traefik-plugin","version":"1.4.1","last_pull":"2026-03-01T11:59:50Z","auth_type":"api-key"},
  {"name":"fw","revoked":false,"type":"crowdsec-firewall-bouncer","version":"v0.0.31","last_pull":null},
  {"name":"old","revoked":true,"type":"","last_pull":"0001-01-01T00:00:00Z"}
]`)}
	sys.cmds["cscli collections list -o json"] = CmdResult{Stdout: []byte(`{"collections":[{"name":"crowdsecurity/linux","status":"enabled"},{"name":"crowdsecurity/sshd","status":"enabled,update-available"},{"name":"crowdsecurity/nginx","status":"disabled"}]}`)}
	sys.cmds["cscli parsers list -o json"] = CmdResult{Stdout: []byte(`{"parsers":[{"name":"crowdsecurity/whitelists","status":"enabled"}]}`)}
	sys.cmds["cscli config show --key Config.API.Server.ListenURI"] = CmdResult{Stdout: []byte("0.0.0.0:8080\n")}

	out := &Facts{}
	if err := (crowdsecCollector{}).Collect(context.Background(), sys, out); err != nil {
		t.Fatal(err)
	}
	c := out.CrowdSec
	if !c.Installed || c.EngineProcesses != 1 || c.Version != "v1.6.4-debian-pragmatic" || c.LAPIListen != "0.0.0.0:8080" {
		t.Fatalf("engine: %+v", c)
	}
	if !c.BouncersRead || len(c.Bouncers) != 3 {
		t.Fatalf("bouncers: %+v", c.Bouncers)
	}
	kinds := map[string]string{}
	for _, b := range c.Bouncers {
		kinds[b.Name] = b.Kind
	}
	if kinds["traefik-bouncer"] != "proxy" || kinds["fw"] != "firewall" || kinds["old"] != "other" {
		t.Errorf("kinds: %v", kinds)
	}
	for _, b := range c.Bouncers {
		if b.Name == "fw" && b.LastPull != nil || b.Name == "old" && b.LastPull != nil || b.Name == "traefik-bouncer" && b.LastPull == nil {
			t.Errorf("last pull of %s: %v", b.Name, b.LastPull)
		}
	}
	if !c.HubRead || !c.HasItem("sshd") || c.HasItem("nginx") {
		t.Errorf("hub: %v %v", c.Collections, c.Parsers)
	}
	if !c.AcquisitionRead || len(c.Acquisition) != 2 || c.Acquisition[1].Type != "traefik" || c.Acquisition[1].Source != "docker" || c.Acquisition[0].Source != "file" {
		t.Errorf("acquisition: %+v", c.Acquisition)
	}
	if !c.ParserFilesRead || len(c.ParserFiles) != 2 {
		t.Fatalf("parser files: %+v", c.ParserFiles)
	}
	var wl, rip *CrowdSecParserFile
	for i := range c.ParserFiles {
		switch {
		case len(c.ParserFiles[i].WhitelistCIDRs) > 0:
			wl = &c.ParserFiles[i]
		case c.ParserFiles[i].RealIPHeader != "":
			rip = &c.ParserFiles[i]
		}
	}
	if wl == nil || len(wl.WhitelistCIDRs) != 3 || len(wl.WhitelistIPs) != 2 {
		t.Errorf("whitelist: %+v", wl)
	}
	if rip == nil || rip.RealIPHeader != "cf-connecting-ip" || len(rip.RealIPKeyedTo) != 1 || rip.RealIPKeyedTo[0] != "172.18.0.1" {
		t.Errorf("real ip: %+v", rip)
	}

	b, _ := json.Marshal(out)
	if strings.Contains(string(b), fakeBouncerKey) {
		t.Errorf("bouncer key leaked: %s", b)
	}
}

func TestCrowdSecNonRootAndAbsent(t *testing.T) {
	sys := newFakeSystem(map[string]string{"/proc/1/comm": "systemd\n", "/etc/crowdsec/acquis.yaml": "filenames: [/var/log/auth.log]\n"})
	sys.cmds["cscli bouncers list -o json"] = CmdResult{Stderr: []byte("permission denied"), ExitCode: 1}
	out := &Facts{}
	if err := (crowdsecCollector{}).Collect(context.Background(), sys, out); err != nil {
		t.Fatalf("non root denial is not an error: %v", err)
	}
	c := out.CrowdSec
	if !c.Installed || c.BouncersRead || !c.AcquisitionRead {
		t.Errorf("non root: %+v", c)
	}
	if r, k := c.EngineRunning(); r || !k {
		t.Errorf("engine: %v %v", r, k)
	}

	out = &Facts{}
	if err := (crowdsecCollector{}).Collect(context.Background(), newFakeSystem(map[string]string{"/proc/1/comm": "systemd\n"}), out); err != nil {
		t.Fatal(err)
	}
	if out.CrowdSec.Installed {
		t.Error("absent")
	}
}

func TestParseCrowdSecParser(t *testing.T) {
	ranged := `name: example/real-ip
filter: "IpInRange(evt.Meta.source_ip, '172.16.0.0/12')"
statics:
  - meta: source_ip
    expression: evt.Unmarshaled.traefik["request_Cf-Connecting-Ip"]
`
	pf, ok := ParseCrowdSecParser([]byte(ranged))
	if !ok || pf.RealIPHeader != "cf-connecting-ip" || len(pf.RealIPKeyedTo) != 0 {
		t.Errorf("ranged: %+v", pf)
	}
	if _, ok := ParseCrowdSecParser([]byte("name: x/y\nfilter: evt.Line.Labels.type == 'syslog'\n")); ok {
		t.Error("an ordinary parser is of no interest")
	}
	if bs, err := ParseCrowdSecBouncers([]byte("null")); err != nil || len(bs) != 0 {
		t.Errorf("null: %v %v", bs, err)
	}
	for typ, want := range map[string]string{"cs-cloudflare-bouncer": "cloudflare", "crowdsec-nginx-bouncer": "proxy", "crowdsec-custom-bouncer": "other"} {
		if got := BouncerKind(typ, ""); got != want {
			t.Errorf("%s: %s", typ, got)
		}
	}
}
