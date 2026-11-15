package facts

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

// ssCapture is `ss -Htulnp` as root on an Ubuntu 24.04 Docker host, with
// addresses moved to documentation ranges.
const ssCapture = `udp   UNCONN 0      0          127.0.0.54:53         0.0.0.0:*    users:(("systemd-resolve",pid=612,fd=16))
udp   UNCONN 0      0       127.0.0.53%lo:53         0.0.0.0:*    users:(("systemd-resolve",pid=612,fd=14))
udp   UNCONN 0      0     203.0.113.10%eth0:68       0.0.0.0:*    users:(("systemd-network",pid=590,fd=22))
udp   UNCONN 0      0             0.0.0.0:41641      0.0.0.0:*    users:(("tailscaled",pid=801,fd=9))
udp   UNCONN 0      0                [::]:41641         [::]:*    users:(("tailscaled",pid=801,fd=10))
tcp   LISTEN 0      4096       127.0.0.1:8080        0.0.0.0:*    users:(("docker-proxy",pid=2210,fd=7))
tcp   LISTEN 0      4096          0.0.0.0:22         0.0.0.0:*    users:(("sshd",pid=1001,fd=3),("systemd",pid=1,fd=144))
tcp   LISTEN 0      4096          0.0.0.0:443        0.0.0.0:*    users:(("docker-proxy",pid=2301,fd=7))
tcp   LISTEN 0      4096   100.101.102.103:43125     0.0.0.0:*    users:(("tailscaled",pid=801,fd=21))
tcp   LISTEN 0      4096                [::]:22            [::]:*    users:(("sshd",pid=1001,fd=4),("systemd",pid=1,fd=145))
tcp   LISTEN 0      4096                [::]:443           [::]:*    users:(("docker-proxy",pid=2308,fd=7))
tcp   LISTEN 0      4096   [fd7a:115c:a1e0::1]:43125      [::]:*    users:(("tailscaled",pid=801,fd=22))
tcp   LISTEN 0      511                    *:9100             *:*    users:(("node_exporter",pid=700,fd=3))
tcp   LISTEN 0      128    [2001:db8::10]:8443          [::]:*
garbage line
`

func TestParseSS(t *testing.T) {
	ls, err := ParseSS([]byte(ssCapture))
	if err == nil || !strings.Contains(err.Error(), "1 unreadable") {
		t.Errorf("want one unreadable line reported, got %v", err)
	}
	if len(ls) != 14 {
		t.Fatalf("got %d listeners, want 14: %+v", len(ls), ls)
	}
	want := map[int]Listener{
		1:  {Proto: "udp", Address: "127.0.0.53", Interface: "lo", Port: 53, Processes: []string{"systemd-resolve"}},
		2:  {Proto: "udp", Address: "203.0.113.10", Interface: "eth0", Port: 68, Processes: []string{"systemd-network"}},
		6:  {Proto: "tcp", Address: "0.0.0.0", Port: 22, Processes: []string{"sshd", "systemd"}},
		9:  {Proto: "tcp", Address: "::", Port: 22, Processes: []string{"sshd", "systemd"}},
		11: {Proto: "tcp", Address: "fd7a:115c:a1e0::1", Port: 43125, Processes: []string{"tailscaled"}},
		12: {Proto: "tcp", Address: "*", Port: 9100, Processes: []string{"node_exporter"}},
		13: {Proto: "tcp", Address: "2001:db8::10", Port: 8443},
	}
	for i, w := range want {
		if !reflect.DeepEqual(ls[i], w) {
			t.Errorf("listener %d = %+v, want %+v", i, ls[i], w)
		}
	}
}

func TestClassifyAddress(t *testing.T) {
	cases := map[string]BindClass{
		"0.0.0.0": BindWildcard, "::": BindWildcard, "*": BindWildcard,
		"127.0.0.1": BindLoopback, "127.0.0.53": BindLoopback, "::1": BindLoopback,
		"100.101.102.103": BindTailnet, "fd7a:115c:a1e0::1": BindTailnet,
		"10.0.0.5": BindPrivate, "172.17.0.1": BindPrivate, "192.168.1.2": BindPrivate,
		"fd00::1": BindPrivate, "fe80::1": BindPrivate, "169.254.1.1": BindPrivate,
		"203.0.113.10": BindPublic, "2001:db8::10": BindPublic, "::ffff:198.51.100.1": BindPublic,
		"nonsense": BindInvalid,
	}
	for addr, want := range cases {
		if got := ClassifyAddress(addr); got != want {
			t.Errorf("ClassifyAddress(%q) = %s, want %s", addr, got, want)
		}
	}
}

const procTCP = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 31021 1 0000000000000000 100 0 0 10 0
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 22011 1 0000000000000000 100 0 0 10 0
   2: 0A7100CB:0016 0B7100CB:D431 01 00000000:00000000 02:00093E1F 00000000     0        0 50112 4 0000000000000000 20 4 29 10 -1
`

const procTCP6 = `  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 22013 1 0000000000000000 100 0 0 10 0
   1: B80D0120000000000000000010000000:20FB 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 22014 1 0000000000000000 100 0 0 10 0
`

const procUDP = `   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
  512: 3500007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000   991        0 20120 2 0000000000000000 0
  700: 0A7100CB:0044 00000000:0000 07 00000000:00000000 00:00000000 00000000   998        0 20188 2 0000000000000000 0
`

func TestParseProcNet(t *testing.T) {
	tcp, err := ParseProcNet([]byte(procTCP), "tcp")
	if err != nil {
		t.Fatal(err)
	}
	want := []Listener{{Proto: "tcp", Address: "127.0.0.1", Port: 8080}, {Proto: "tcp", Address: "0.0.0.0", Port: 22}}
	if !reflect.DeepEqual(tcp, want) {
		t.Errorf("tcp = %+v, want %+v", tcp, want)
	}
	tcp6, err := ParseProcNet([]byte(procTCP6), "tcp")
	if err != nil {
		t.Fatal(err)
	}
	want6 := []Listener{{Proto: "tcp", Address: "::", Port: 22}, {Proto: "tcp", Address: "2001:db8::10", Port: 8443}}
	if !reflect.DeepEqual(tcp6, want6) {
		t.Errorf("tcp6 = %+v, want %+v", tcp6, want6)
	}
	udp, err := ParseProcNet([]byte(procUDP), "udp")
	if err != nil {
		t.Fatal(err)
	}
	wantU := []Listener{{Proto: "udp", Address: "127.0.0.53", Port: 53}, {Proto: "udp", Address: "203.0.113.10", Port: 68}}
	if !reflect.DeepEqual(udp, wantU) {
		t.Errorf("udp = %+v, want %+v", udp, wantU)
	}
}

const ipAddrJSON = `[{"ifindex":1,"ifname":"lo","flags":["LOOPBACK","UP","LOWER_UP"],"mtu":65536,"operstate":"UNKNOWN","addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8,"scope":"host","label":"lo"},{"family":"inet6","local":"::1","prefixlen":128,"scope":"host"}]},
{"ifindex":2,"ifname":"eth0","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":1500,"operstate":"UP","addr_info":[{"family":"inet","local":"203.0.113.10","prefixlen":24,"scope":"global","dynamic":true,"label":"eth0"},{"family":"inet6","local":"2001:db8:100::10","prefixlen":64,"scope":"global"},{"family":"inet6","local":"fe80::1","prefixlen":64,"scope":"link"}]},
{"ifindex":3,"ifname":"tailscale0","flags":["POINTOPOINT","MULTICAST","NOARP","UP","LOWER_UP"],"mtu":1280,"operstate":"UNKNOWN","addr_info":[{"family":"inet","local":"100.101.102.103","prefixlen":32,"scope":"global","label":"tailscale0"}]},
{"ifindex":4,"ifname":"docker0","flags":["NO-CARRIER","BROADCAST","MULTICAST","UP"],"mtu":1500,"operstate":"DOWN","addr_info":[]}]`

func TestParseIPAddrJSON(t *testing.T) {
	addrs, err := ParseIPAddrJSON([]byte(ipAddrJSON))
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 6 {
		t.Fatalf("got %d addresses: %+v", len(addrs), addrs)
	}
	if addrs[3] != (InterfaceAddr{Interface: "eth0", Address: "2001:db8:100::10", Prefix: 64, Scope: "global"}) {
		t.Errorf("addrs[3] = %+v", addrs[3])
	}
	l := &Listeners{Addresses: addrs}
	if has, known := l.HasGlobalIPv6(); !has || !known {
		t.Errorf("HasGlobalIPv6 = %v %v", has, known)
	}
	if _, err := ParseIPAddrJSON([]byte("not json")); err == nil {
		t.Error("bad JSON accepted")
	}
}

func TestParseIfInet6(t *testing.T) {
	in := "00000000000000000000000000000001 01 80 10 80       lo\n" +
		"fe800000000000000000000000000001 02 40 20 80     eth0\n"
	addrs := ParseIfInet6([]byte(in))
	want := []InterfaceAddr{
		{Interface: "lo", Address: "::1", Prefix: 128, Scope: "host"},
		{Interface: "eth0", Address: "fe80::1", Prefix: 64, Scope: "link"},
	}
	if !reflect.DeepEqual(addrs, want) {
		t.Errorf("got %+v", addrs)
	}
	l := &Listeners{Addresses: addrs}
	if has, known := l.HasGlobalIPv6(); has || !known {
		t.Errorf("HasGlobalIPv6 = %v %v, want false true", has, known)
	}
	if _, known := (&Listeners{}).HasGlobalIPv6(); known {
		t.Error("nil addresses reported as known")
	}
}

func TestListenersCollectorSS(t *testing.T) {
	sys := newFakeSystem(nil)
	sys.host.Root = true
	sys.cmds["ss -Htulnp"] = CmdResult{Stdout: []byte(strings.Replace(ssCapture, "garbage line\n", "", 1))}
	sys.cmds["ip -j addr show"] = CmdResult{Stdout: []byte(ipAddrJSON)}
	var out Facts
	if err := (listenersCollector{}).Collect(context.Background(), sys, &out); err != nil {
		t.Fatal(err)
	}
	l := out.Listeners
	if l.Source != "ss" || !l.ProcessesVisible || len(l.Sockets) != 14 || l.AddressesSource != "ip" {
		t.Fatalf("unexpected listeners: %+v", l)
	}
	// Sorted: tcp before udp, then by port.
	if l.Sockets[0].Proto != "tcp" || l.Sockets[0].Port != 22 {
		t.Errorf("not sorted: first is %+v", l.Sockets[0])
	}
}

// TestListenersCollectorSandboxHidesProcesses: under the Landlock sandbox
// ss runs as root but cannot read /proc/<pid>/fd of processes outside the
// sandbox, so it prints every socket without an owner (seen on an Ubuntu
// 24.04 runner). That must not claim process names were visible.
func TestListenersCollectorSandboxHidesProcesses(t *testing.T) {
	sys := newFakeSystem(nil)
	sys.host.Root = true
	sys.cmds["ss -Htulnp"] = CmdResult{Stdout: []byte(
		"tcp   LISTEN 0      4096          0.0.0.0:22         0.0.0.0:*\n" +
			"tcp   LISTEN 0      4096          0.0.0.0:8080       0.0.0.0:*\n")}
	var out Facts
	if err := (listenersCollector{}).Collect(context.Background(), sys, &out); err != nil {
		t.Fatal(err)
	}
	if l := out.Listeners; l.ProcessesVisible || len(l.Sockets) != 2 {
		t.Fatalf("root without any process name must not be visible: %+v", l)
	}
}

func TestPublishedByContainer(t *testing.T) {
	d := &Docker{API: "ok", Containers: []DockerContainer{{Name: "web", Ports: []DockerPort{{HostIP: "0.0.0.0", HostPort: 8080, ContainerPort: 80}}}}}
	cases := []struct {
		name string
		l    Listener
		d    *Docker
		want bool
	}{
		{"docker-proxy holds it", Listener{Proto: "tcp", Port: 9000, Processes: []string{"docker-proxy"}}, nil, true},
		{"no owner, a container publishes it", Listener{Proto: "tcp", Port: 8080}, d, true},
		{"no owner, other protocol", Listener{Proto: "udp", Port: 8080}, d, false},
		{"no owner, other port", Listener{Proto: "tcp", Port: 8081}, d, false},
		{"another process owns it", Listener{Proto: "tcp", Port: 8080, Processes: []string{"nginx"}}, d, false},
		{"no owner, Docker API not read", Listener{Proto: "tcp", Port: 8080}, &Docker{API: "denied"}, false},
		{"no owner, no Docker facts", Listener{Proto: "tcp", Port: 8080}, nil, false},
	}
	for _, c := range cases {
		if got := c.l.PublishedByContainer(c.d); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestListenersCollectorProcFallback(t *testing.T) {
	sys := newFakeSystem(map[string]string{
		"/proc/net/tcp":      procTCP,
		"/proc/net/udp":      procUDP,
		"/proc/net/if_inet6": "fe800000000000000000000000000001 02 40 20 80     eth0\n",
	})
	var out Facts
	err := (listenersCollector{}).Collect(context.Background(), sys, &out)
	if err != nil {
		t.Fatalf("missing tcp6 must not be an error: %v", err)
	}
	l := out.Listeners
	if l.Source != "proc" || l.ProcessesVisible || len(l.Sockets) != 4 || l.AddressesSource != "proc" {
		t.Fatalf("unexpected listeners: %+v", l)
	}
}

func TestListenersCollectorNothing(t *testing.T) {
	var out Facts
	if err := (listenersCollector{}).Collect(context.Background(), newFakeSystem(nil), &out); err == nil {
		t.Fatal("want an error when neither ss nor /proc/net can be read")
	}
	if out.Listeners != nil {
		t.Error("listeners set although nothing was read")
	}
}

// ssScoped holds the shapes a real Ubuntu 24.04 host with Docker, Tailscale
// and cloudflared prints on top of ssCapture: scoped IPv6 in both bracket
// orders, a scoped wildcard, mapped IPv4, several processes and no process.
const ssScoped = `udp   UNCONN 0      0     [fe80::a00:27ff:fe4a:1]%eth0:546      [::]:*    users:(("systemd-network",pid=590,fd=23))
udp   UNCONN 0      0               [::1]%lo:323        [::]:*
udp   UNCONN 0      0        100.100.100.100%tailscale0:53   0.0.0.0:*    users:(("tailscaled",pid=801,fd=17))
udp   UNCONN 0      0                  *%docker0:5353      *:*    users:(("avahi-daemon",pid=700,fd=12))
tcp   LISTEN 0      4096   [::ffff:192.0.2.7]:2019     *:*    users:(("cloudflared",pid=910,fd=3),("cloudflared",pid=910,fd=4))
tcp   LISTEN 0      4096     [fe80::1%eth0]:9000        [::]:*
`

func TestParseSSScopedAndMappedShapes(t *testing.T) {
	ls, err := ParseSS([]byte(ssScoped))
	if err != nil {
		t.Fatalf("real shapes must not be reported as unreadable: %v", err)
	}
	want := []Listener{
		{Proto: "udp", Address: "fe80::a00:27ff:fe4a:1", Interface: "eth0", Port: 546, Processes: []string{"systemd-network"}},
		{Proto: "udp", Address: "::1", Interface: "lo", Port: 323},
		{Proto: "udp", Address: "100.100.100.100", Interface: "tailscale0", Port: 53, Processes: []string{"tailscaled"}},
		{Proto: "udp", Address: "*", Interface: "docker0", Port: 5353, Processes: []string{"avahi-daemon"}},
		{Proto: "tcp", Address: "192.0.2.7", Port: 2019, Processes: []string{"cloudflared"}},
		{Proto: "tcp", Address: "fe80::1", Interface: "eth0", Port: 9000},
	}
	if !reflect.DeepEqual(ls, want) {
		t.Errorf("got  %+v\nwant %+v", ls, want)
	}
}

func TestSplitHostPort(t *testing.T) {
	good := []struct {
		in, addr, iface string
		port            int
	}{
		{"0.0.0.0:22", "0.0.0.0", "", 22},
		{"[::]:22", "::", "", 22},
		{"*:22", "*", "", 22},
		{"127.0.0.53%lo:53", "127.0.0.53", "lo", 53},
		{"[fe80::1]%eth0:546", "fe80::1", "eth0", 546},
		{"[fe80::1%eth0]:546", "fe80::1", "eth0", 546},
		{"*%eth0:546", "*", "eth0", 546},
		{"[::ffff:192.0.2.1]:80", "192.0.2.1", "", 80},
		{"[2001:db8::1]%ens3:0", "2001:db8::1", "ens3", 0},
	}
	for _, c := range good {
		addr, iface, port, ok := splitHostPort(c.in)
		if !ok || addr != c.addr || iface != c.iface || port != c.port {
			t.Errorf("splitHostPort(%q) = %q %q %d %v", c.in, addr, iface, port, ok)
		}
	}
	for _, in := range []string{"", "22", ":22", "0.0.0.0:", "0.0.0.0:http", "0.0.0.0:70000", "[::1:22", "[::1]x:22", "[::1]%:22", "[fe80::1%a]%b:22", "host.example:22", "*:*"} {
		if _, _, _, ok := splitHostPort(in); ok {
			t.Errorf("splitHostPort(%q) should be rejected", in)
		}
	}
}

func TestParseSSOnlyMalformedLinesArePartial(t *testing.T) {
	_, err := ParseSS([]byte("tcp LISTEN 0 4096 0.0.0.0:22 0.0.0.0:*\ntcp LISTEN 0 4096 not-an-address 0.0.0.0:*\nshort line\n"))
	if err == nil || !strings.Contains(err.Error(), "2 unreadable") {
		t.Errorf("want two unreadable lines, got %v", err)
	}
}
