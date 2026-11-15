package probe

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func fakeLocal(addrs ...string) LocalAddrs {
	return func() ([]netip.Addr, error) {
		var out []netip.Addr
		for _, a := range addrs {
			out = append(out, netip.MustParseAddr(a))
		}
		return out, nil
	}
}

func TestSelfAddresses(t *testing.T) {
	local := fakeLocal("198.51.100.7", "2001:db8::7")
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"ipv4 loopback", []string{"127.0.0.1"}, []string{"127.0.0.1"}},
		{"other 127 address", []string{"127.8.9.10"}, []string{"127.8.9.10"}},
		{"ipv6 loopback", []string{"::1"}, []string{"::1"}},
		{"local interface v4", []string{"198.51.100.7"}, []string{"198.51.100.7"}},
		{"local interface v6", []string{"2001:db8::7"}, []string{"2001:db8::7"}},
		{"outside v4", []string{"192.0.2.10"}, nil},
		{"outside v4 neighbour", []string{"198.51.100.8"}, nil},
		{"outside v6", []string{"2001:db8::8"}, nil},
		{"one of many is local", []string{"203.0.113.5", "198.51.100.7"}, []string{"198.51.100.7"}},
	}
	for _, c := range cases {
		var addrs []Address
		for _, a := range c.in {
			addrs = append(addrs, Address{Address: a})
		}
		if got := selfAddresses(addrs, local); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestSelfAddressesInterfaceLookupFails(t *testing.T) {
	failing := LocalAddrs(func() ([]netip.Addr, error) { return nil, errors.New("no interfaces") })
	got := selfAddresses([]Address{{Address: "127.0.0.1"}, {Address: "192.0.2.1"}}, failing)
	if !reflect.DeepEqual(got, []string{"127.0.0.1"}) {
		t.Errorf("loopback must still match: %v", got)
	}
}

func TestRunMarksSelfTarget(t *testing.T) {
	pl := PortList{}
	res := fakeResolver{"self.example.com": {netip.MustParseAddr("127.0.0.1")}}
	var warned []string
	f := Run(context.Background(), Options{
		Target: "self.example.com", Ports: &pl, Resolver: res, Timeout: 100 * time.Millisecond,
		LocalAddrs:   fakeLocal(),
		OnSelfTarget: func(a []string) { warned = a },
	})
	if !f.SelfTarget || !reflect.DeepEqual(f.SelfAddresses, []string{"127.0.0.1"}) || !reflect.DeepEqual(warned, []string{"127.0.0.1"}) {
		t.Fatalf("self target not recorded: %+v warned %v", f, warned)
	}
	rep, err := Evaluate(f, EvalOptions{Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Probe == nil || !rep.Probe.SelfTarget {
		t.Fatalf("report lacks self_target: %+v", rep.Probe)
	}
	found := false
	for _, n := range rep.Probe.Notes {
		found = found || n == SelfNote
	}
	if !found {
		t.Errorf("report lacks the note: %v", rep.Probe.Notes)
	}
}

func TestRunOutsideTargetIsNotSelf(t *testing.T) {
	pl := PortList{}
	res := fakeResolver{"far.example.com": {netip.MustParseAddr("192.0.2.1")}}
	called := false
	f := Run(context.Background(), Options{
		Target: "far.example.com", Ports: &pl, Resolver: res, Timeout: 100 * time.Millisecond,
		LocalAddrs:   fakeLocal("198.51.100.7"),
		OnSelfTarget: func([]string) { called = true },
	})
	if f.SelfTarget || len(f.SelfAddresses) != 0 || called {
		t.Fatalf("outside target flagged as self: %+v", f)
	}
}
