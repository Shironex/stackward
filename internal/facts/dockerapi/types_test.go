package dockerapi

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// secretMarkers are the fake secret values planted in testdata. None may
// survive Strip or the parsers.
var secretMarkers = []string{"not-a-real-password", "not-a-real-token", "not-a-bool-value", "server.js", "proxyuser"}

func TestStripRemovesSecrets(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "inspect-*.json"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no inspect testdata: %v", err)
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		clean, flags, err := Strip(raw)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for _, m := range secretMarkers {
			if strings.Contains(string(clean), m) {
				t.Errorf("%s: %q survived Strip", f, m)
			}
		}
		for _, field := range []string{`"Env"`, `"Cmd"`, `"Entrypoint"`, `"Healthcheck"`, `"Args"`, `"Path"`} {
			if strings.Contains(string(clean), field) {
				t.Errorf("%s: field %s survived Strip", f, field)
			}
		}
		for k, v := range flags {
			if !FlagKeys[k] || !boolValues[v] {
				t.Errorf("%s: kept flag %s=%s", f, k, v)
			}
		}
	}
}

func TestEnvFlags(t *testing.T) {
	_, flags, err := ParseInspect(readTestdata(t, "inspect-dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd.json"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"CONTAINERS": "1", "POST": "1", "EXEC": "0"}
	if len(flags) != len(want) {
		t.Fatalf("flags %v, want %v", flags, want)
	}
	for k, v := range want {
		if flags[k] != v {
			t.Errorf("%s=%q, want %q", k, flags[k], v)
		}
	}
}

func TestParseInspect(t *testing.T) {
	in, _, err := ParseInspect(readTestdata(t, "inspect-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json"))
	if err != nil {
		t.Fatal(err)
	}
	if in.Name != "/coolify-proxy" || in.Config.Image != "traefik:v3.1" || !in.State.Running {
		t.Fatalf("decoded %+v", in)
	}
	if len(in.HostConfig.Binds) != 2 || len(in.Mounts) != 2 || in.Mounts[0].RW {
		t.Fatalf("mounts %+v binds %v", in.Mounts, in.HostConfig.Binds)
	}
	if len(in.NetworkSettings.Ports["80/tcp"]) != 2 || in.NetworkSettings.Ports["8080/tcp"] != nil {
		t.Fatalf("ports %+v", in.NetworkSettings.Ports)
	}
	if _, _, err := ParseInspect([]byte(`[1]`)); err == nil {
		t.Fatal("no error for a non object")
	}
	if in, _, err := ParseInspect([]byte(`{"Id":"x","Config":null}`)); err != nil || in.ID != "x" {
		t.Fatalf("null Config: %+v %v", in, err)
	}
}

func TestParseContainerIDs(t *testing.T) {
	ids, cut, err := ParseContainerIDs(readTestdata(t, "containers.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 5 || cut {
		t.Fatalf("ids %v cut %v (the non hex id must be skipped)", ids, cut)
	}
	var many strings.Builder
	many.WriteString("[")
	for i := range MaxContainers + 3 {
		if i > 0 {
			many.WriteString(",")
		}
		many.WriteString(`{"Id":"` + strings.Repeat("f", 63) + string(rune('0'+i%10)) + `"}`)
	}
	many.WriteString("]")
	ids, cut, err = ParseContainerIDs([]byte(many.String()))
	if err != nil || len(ids) != MaxContainers || !cut {
		t.Fatalf("len %d cut %v err %v", len(ids), cut, err)
	}
}

func TestParseInfoDropsProxy(t *testing.T) {
	i, err := ParseInfo(readTestdata(t, "info.json"))
	if err != nil {
		t.Fatal(err)
	}
	if i.LoggingDriver != "json-file" || i.ServerVersion != "27.5.1" || len(i.SecurityOptions) != 3 {
		t.Fatalf("info %+v", i)
	}
}

func TestParseVersionAndNetworks(t *testing.T) {
	v, err := ParseVersion(readTestdata(t, "version.json"))
	if err != nil || v.Version != "27.5.1" || v.APIVersion != "1.47" {
		t.Fatalf("version %+v %v", v, err)
	}
	ns, err := ParseNetworks(readTestdata(t, "networks.json"))
	if err != nil || len(ns) != 4 || ns[0].Name != "bridge" || ns[1].Name != "edge" {
		t.Fatalf("networks %+v %v", ns, err)
	}
}

func TestInspectPath(t *testing.T) {
	if p, err := InspectPath(strings.Repeat("a", 64)); err != nil || p != "/containers/"+strings.Repeat("a", 64)+"/json" {
		t.Fatalf("%q %v", p, err)
	}
	for _, id := range []string{"../../x", "abc", "ABCDEF0123456", strings.Repeat("a", 12) + "/kill"} {
		if _, err := InspectPath(id); !errors.Is(err, ErrBadPath) {
			t.Errorf("%q accepted", id)
		}
	}
}
