package facts

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// fakeTunnelToken is assembled at run time so secret scanners do not flag
// the source; it only has the shape of a tunnel token.
var fakeTunnelToken = "eyJ" + strings.Repeat("QUJD", 12)

const cfUnitKey = "systemctl show cloudflared.service --property=" + unitProperties

const cfConfig = `# cloudflared config
tunnel: 6ff42ae2-765d-4adf-8112-31c55c1551ef
credentials-file: /etc/cloudflared/6ff42ae2-765d-4adf-8112-31c55c1551ef.json
ingress:
  - hostname: app.example.com
    service: http://localhost:80
    originRequest:
      noTLSVerify: true
  - hostname: "*.example.com"
    service: https://127.0.0.1:443 # the proxy
  - service: http_status:404
`

func TestCloudflaredCollector(t *testing.T) {
	cmdline := func(args ...string) string { return strings.Join(args, "\x00") + "\x00" }
	sys := newFakeSystem(map[string]string{
		"/proc/1/comm":           "systemd\n",
		"/proc/10/comm":          "cloudflared\n",
		"/proc/10/cgroup":        "0::/system.slice/docker-0123abcd.scope\n",
		"/proc/10/cmdline":       cmdline("cloudflared", "--no-autoupdate", "tunnel", "run", "--token", fakeTunnelToken),
		"/proc/11/comm":          "cloudflared\n",
		"/proc/11/cgroup":        "0::/system.slice/cloudflared.service\n",
		"/proc/11/cmdline":       cmdline("/usr/bin/cloudflared", "--config", "/opt/tunnel/config.yml", "tunnel", "run"),
		"/opt/tunnel/config.yml": cfConfig,
		"/etc/cloudflared/6ff42ae2-765d-4adf-8112-31c55c1551ef.json": `{"AccountTag":"x","TunnelSecret":"must-never-be-read"}`,
	})
	sys.cmds[cfUnitKey] = unitShow("loaded", "active", "enabled")
	sys.cmds["systemctl show cloudflared.service --property=ExecStart"] = CmdResult{Stdout: []byte(
		"ExecStart={ path=/usr/bin/cloudflared ; argv[]=/usr/bin/cloudflared --no-autoupdate tunnel run --token " + fakeTunnelToken + " ; ignore_errors=no ; start_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }\n")}

	out := &Facts{}
	if err := (cloudflaredCollector{}).Collect(context.Background(), sys, out); err != nil {
		t.Fatal(err)
	}
	c := out.Cloudflared
	if !c.Installed || !c.ProcessesRead || !c.ProcessesVisible || len(c.Connectors) != 2 {
		t.Fatalf("connectors: %+v", c)
	}
	if k := c.Connectors[0]; !k.Container || !k.ArgsRead || k.Mode != "token" || !k.TokenInArgs {
		t.Errorf("container connector: %+v", k)
	}
	if k := c.Connectors[1]; k.Container || k.Mode != "named" || k.ConfigPath != "/opt/tunnel/config.yml" {
		t.Errorf("host connector: %+v", k)
	}
	if !c.UnitTokenInArgs {
		t.Error("unit token not seen")
	}
	if len(c.Configs) != 1 {
		t.Fatalf("configs: %+v", c.Configs)
	}
	cfg := c.Configs[0]
	if !cfg.Tunnel || len(cfg.Ingress) != 3 || cfg.Ingress[0].Service != "http://localhost:80" || !cfg.Ingress[1].Hostname || cfg.Ingress[2].Hostname || cfg.CredentialsMode != "0644" {
		t.Errorf("config: %+v", cfg)
	}
	if p, k := c.TunnelPresent(); !p || !k {
		t.Error("tunnel should be present")
	}
	if in, k := c.TokenInArgs(); !in || !k {
		t.Error("token in args should be seen")
	}

	b, _ := json.Marshal(out)
	for _, leak := range []string{fakeTunnelToken, "must-never-be-read", "app.example.com"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("facts leak %q: %s", leak, b)
		}
	}
}

func TestCloudflaredAbsentAndHidden(t *testing.T) {
	// Every process visible, no cloudflared anywhere: a known "no".
	sys := newFakeSystem(map[string]string{"/proc/1/comm": "systemd\n", "/proc/2/comm": "sshd\n"})
	out := &Facts{}
	if err := (cloudflaredCollector{}).Collect(context.Background(), sys, out); err != nil {
		t.Fatal(err)
	}
	if out.Cloudflared.Installed {
		t.Error("nothing installed")
	}
	if p, k := out.Cloudflared.TunnelPresent(); p || !k {
		t.Error("want a known absent")
	}

	// hidepid: /proc/1 hidden, nothing seen: unknown.
	sys = newFakeSystem(map[string]string{"/proc/2000/comm": "bash\n"})
	out = &Facts{}
	_ = (cloudflaredCollector{}).Collect(context.Background(), sys, out)
	if _, k := out.Cloudflared.TunnelPresent(); k {
		t.Error("hidden processes must leave the tunnel unknown")
	}
}

func TestParseCloudflaredArgs(t *testing.T) {
	cases := []struct {
		argv   []string
		mode   string
		config string
	}{
		{[]string{"cloudflared", "tunnel", "--no-autoupdate", "run", "--token=" + fakeTunnelToken}, "token", ""},
		{[]string{"cloudflared", "tunnel", "run", fakeTunnelToken}, "token", ""},
		{[]string{"cloudflared", "tunnel", "--url", "http://localhost:8080"}, "quick", ""},
		{[]string{"cloudflared", "tunnel", "--config=/etc/cloudflared/a.yml", "run", "--url", "http://localhost:80"}, "named", "/etc/cloudflared/a.yml"},
		{[]string{"cloudflared", "--no-autoupdate", "tunnel", "run"}, "named", ""},
	}
	for _, c := range cases {
		a := parseCloudflaredArgs(c.argv)
		if a.mode() != c.mode || a.config != c.config {
			t.Errorf("%v: mode %s config %q", c.argv[1:3], a.mode(), a.config)
		}
	}
}

func TestParseYAMLDocs(t *testing.T) {
	src := `---
source: docker
container_name:
 - traefik
labels:
  type: traefik
---
filenames: [/var/log/auth.log, '/var/log/syslog']
labels:
  type: syslog
---
name: example/realip
filter: |
  evt.Meta.service == 'http' # a comment-looking text
  && evt.Meta.source_ip == '172.18.0.1'
statics:
- meta: source_ip
  expression: evt.Unmarshaled.traefik["request_Cf-Connecting-Ip"]
`
	docs := parseYAMLDocs([]byte(src))
	if len(docs) != 3 {
		t.Fatalf("docs = %d: %#v", len(docs), docs)
	}
	d0 := yamlMap(docs[0])
	if yamlStr(d0["source"]) != "docker" || yamlStrings(d0["container_name"])[0] != "traefik" || yamlStr(yamlMap(d0["labels"])["type"]) != "traefik" {
		t.Errorf("doc 0: %#v", d0)
	}
	if got := yamlStrings(yamlMap(docs[1])["filenames"]); len(got) != 2 || got[1] != "/var/log/syslog" {
		t.Errorf("flow list: %#v", got)
	}
	d2 := yamlMap(docs[2])
	if f := yamlStr(d2["filter"]); !strings.Contains(f, "172.18.0.1") || !strings.Contains(f, "comment-looking") {
		t.Errorf("block scalar: %q", f)
	}
	st := yamlSlice(d2["statics"])
	if len(st) != 1 || yamlStr(yamlMap(st[0])["meta"]) != "source_ip" {
		t.Errorf("statics: %#v", st)
	}
	// Garbage never panics.
	_ = parseYAMLDocs([]byte("- : :\n  - - x\n\"unterminated: \n  |\n"))
}
