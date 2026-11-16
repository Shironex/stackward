package facts

import (
	"context"
	"reflect"
	"testing"
)

func TestPublicIPv4Candidates(t *testing.T) {
	sys := newFakeSystem(nil)
	sys.cmds["ip -j addr show"] = CmdResult{Stdout: []byte(`[
 {"ifname":"lo","addr_info":[{"family":"inet","local":"127.0.0.1","prefixlen":8,"scope":"host"}]},
 {"ifname":"eth0","addr_info":[
   {"family":"inet","local":"203.0.113.10","prefixlen":24,"scope":"global"},
   {"family":"inet","local":"198.51.100.20","prefixlen":32,"scope":"global"},
   {"family":"inet6","local":"2001:db8::10","prefixlen":64,"scope":"global"}]},
 {"ifname":"eth1","addr_info":[{"family":"inet","local":"10.0.0.2","prefixlen":24,"scope":"global"}]},
 {"ifname":"tailscale0","addr_info":[{"family":"inet","local":"100.101.102.103","prefixlen":32,"scope":"global"}]},
 {"ifname":"docker0","addr_info":[{"family":"inet","local":"172.17.0.1","prefixlen":16,"scope":"global"}]},
 {"ifname":"eth2","addr_info":[{"family":"inet","local":"169.254.1.1","prefixlen":16,"scope":"link"}]}
]`)}
	got, err := PublicIPv4Candidates(context.Background(), sys)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"198.51.100.20", "203.0.113.10"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}

	sys.cmds["ip -j addr show"] = CmdResult{ExitCode: 1, Stderr: []byte("ip: not found")}
	if _, err := PublicIPv4Candidates(context.Background(), sys); err == nil {
		t.Error("a failing ip gave no error")
	}
}

func TestPortRangeString(t *testing.T) {
	if s := (PortRange{From: 22, To: 22}).String(); s != "22" {
		t.Errorf("%q", s)
	}
	if s := (PortRange{From: 1000, To: 2000}).String(); s != "1000-2000" {
		t.Errorf("%q", s)
	}
}
