package plan

import (
	"slices"
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/profile"
)

const dockerFixture = "plan-firewall-ufw-docker"

func TestUFWDockerKeepsWhatTheProfileNeeds(t *testing.T) {
	out := planUFWDocker(fwInput(t, dockerFixture, profile.PaaSPanel, nil))
	if out.Step == nil {
		t.Fatalf("no step: %+v", out)
	}
	s := out.Step
	if len(s.Edits) != 2 || s.Edits[0].Path != facts.UFWUserRulesPath || s.Edits[1].Path != facts.UFWAfterRulesPath {
		t.Fatalf("edits %+v", s.Edits)
	}
	adds, err := addedRules(s.Edits[0], false, true)
	if err != nil {
		t.Fatal(err)
	}
	var words []string
	for _, r := range adds {
		words = append(words, r.words())
	}
	want := []string{"route allow 8080/tcp from anywhere", "route allow 80/tcp from anywhere", "route allow 443/tcp from anywhere", "route allow on tailscale0"}
	if !slices.Equal(words, want) {
		t.Errorf("route rules %v, want %v", words, want)
	}
	notes := strings.Join(s.Notes, "\n")
	for _, w := range []string{"Closes to the internet: 0.0.0.0:5432->5432/tcp (shared-db)", "become filtered", "from the tailnet", "no script or package is downloaded", "PAAS-003 still warns"} {
		if !strings.Contains(notes, w) {
			t.Errorf("notes lack %q:\n%s", w, notes)
		}
	}
	if !slices.Equal(s.Fixes, []string{"DKR-001"}) {
		t.Errorf("fixes %v", s.Fixes)
	}
	// Docker's RETURN was there, so the undo puts it back.
	if got := s.Undo.Commands[1].Args; !slices.Equal(got, iptReturnDockerUser) {
		t.Errorf("undo %v", s.Undo.Commands)
	}
	if err := authorizeUFWDocker(*s); err != nil {
		t.Errorf("its own step is refused: %v", err)
	}
}

func TestUFWDockerOnATunnelHostClosesTheProxyAndThePanel(t *testing.T) {
	out := planUFWDocker(fwInput(t, dockerFixture, profile.Tunnel, nil))
	if out.Step == nil {
		t.Fatalf("no step: %+v", out)
	}
	s := out.Step
	adds, _ := addedRules(s.Edits[0], false, true)
	if len(adds) != 1 || adds[0].iface != tailnetIface {
		t.Errorf("only the tailnet route rule may stay: %+v", adds)
	}
	for _, id := range []string{"DKR-001", "PAAS-002", "PAAS-003"} {
		if !slices.Contains(s.Fixes, id) {
			t.Errorf("fixes %v lack %s", s.Fixes, id)
		}
	}
	// Without Tailscale there is no route rule at all: only after.rules.
	out = planUFWDocker(fwInput(t, dockerFixture, profile.Tunnel, func(f *facts.Facts) { f.Tailscale = &facts.Tailscale{} }))
	if out.Step == nil || len(out.Step.Edits) != 1 || out.Step.Edits[0].Path != facts.UFWAfterRulesPath {
		t.Fatalf("no tailnet: %+v", out)
	}
	if err := authorizeUFWDocker(*out.Step); err != nil {
		t.Errorf("refused: %v", err)
	}
}

func TestUFWDockerSkips(t *testing.T) {
	for name, tc := range map[string]struct {
		prof profile.Name
		edit func(f *facts.Facts)
		kind string
		want string
	}{
		"nftables backend": {profile.PaaSPanel, func(f *facts.Facts) {
			f.Firewall.DockerBackend = "nftables"
		}, SkipManual, "nftables firewall backend"},
		"ufw off": {profile.PaaSPanel, func(f *facts.Facts) { f.Firewall.UFW.Status = "inactive" }, SkipManual, "apply ufw-policy"},
		"custom DOCKER-USER": {profile.PaaSPanel, func(f *facts.Facts) {
			f.Firewall.Iptables.DockerUserRules = []string{"-A DOCKER-USER -s 198.51.100.0/24 -j RETURN", "-A DOCKER-USER -j RETURN"}
			f.Firewall.DockerUser = "filtered"
		}, SkipManual, "did not write"},
		"already there":   {profile.PaaSPanel, func(f *facts.Facts) { f.Firewall.UFWDocker.InFiles = "present" }, SkipManual, "already"},
		"no docker api":   {profile.PaaSPanel, func(f *facts.Facts) { f.Docker.API = "denied" }, SkipUnknown, ""},
		"unknown profile": {profile.Unknown, nil, SkipManual, "--profile"},
		"iptables off": {profile.PaaSPanel, func(f *facts.Facts) {
			off := false
			f.Docker.Daemon.IPTables = &off
		}, SkipPassing, ""}, // the host input rules filter them: DKR-001 passes
		"nothing closes": {profile.PaaSPanel, func(f *facts.Facts) {
			f.Docker.Containers = f.Docker.Containers[:len(f.Docker.Containers)-1]
			f.Listeners.Sockets = f.Listeners.Sockets[:len(f.Listeners.Sockets)-1]
		}, SkipManual, "close nothing"},
	} {
		t.Run(name, func(t *testing.T) {
			out := planUFWDocker(fwInput(t, dockerFixture, tc.prof, tc.edit))
			if out.Step != nil || out.Kind != tc.kind || !strings.Contains(out.Reason, tc.want) {
				t.Errorf("got %+v, want %s with %q", out, tc.kind, tc.want)
			}
		})
	}
}

func TestUFWDockerAuthorizeRefusesTampering(t *testing.T) {
	base := *planUFWDocker(fwInput(t, dockerFixture, profile.PaaSPanel, nil)).Step
	rehash := func(e *FileEdit) { e.NewSHA256 = sha(e.New) }
	for name, tc := range map[string]struct {
		tamper func(s *Step)
		want   string
	}{
		"block loosened": {func(s *Step) {
			s.Edits[1].New = strings.Replace(s.Edits[1].New, "-A ufw-docker-logging-deny -j DROP", "-A ufw-docker-logging-deny -j RETURN", 1)
			rehash(&s.Edits[1])
		}, "not what the step writes"},
		"input rule": {func(s *Step) {
			s.Edits[0].New = strings.Replace(s.Edits[0].New, "### tuple ### route:allow tcp 8080 0.0.0.0/0 any 0.0.0.0/0 in\n-A ufw-user-forward -p tcp --dport 8080 -j ACCEPT",
				"### tuple ### allow tcp 8080 0.0.0.0/0 any 0.0.0.0/0 in\n-A ufw-user-input -p tcp --dport 8080 -j ACCEPT", 1)
			rehash(&s.Edits[0])
		}, "not one the step adds"},
		"only after.rules first": {func(s *Step) { s.Edits[0], s.Edits[1] = s.Edits[1], s.Edits[0] }, "first"},
		"no validate":            {func(s *Step) { s.Edits[1].Validate = nil }, "validate"},
		"download": {func(s *Step) {
			s.Commands = append(s.Commands, Command{Args: []string{"curl", "-fsSL", "https://example.com/ufw-docker"}})
		}, "commands"},
		"undo flushes forward": {func(s *Step) { s.Undo.Commands[0].Args = []string{"iptables", "-F", "FORWARD"} }, "not one the step runs"},
		"undo keeps chain":     {func(s *Step) { s.Undo.Commands = s.Undo.Commands[:3] }, "undo"},
	} {
		t.Run(name, func(t *testing.T) {
			s := base
			s.Edits = slices.Clone(base.Edits)
			s.Commands = slices.Clone(base.Commands)
			s.Undo.Commands = slices.Clone(base.Undo.Commands)
			tc.tamper(&s)
			if err := authorizeUFWDocker(s); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err %v, want %q", err, tc.want)
			}
		})
	}
}

// The block is the one the facts recognise as ufw-docker's DOCKER-USER
// chain once loaded, so the audit judges published ports through it.
func TestUFWDockerBlockIsTheRecognisedChain(t *testing.T) {
	var rules []string
	for _, l := range strings.Split(ufwDockerBlock, "\n") {
		if strings.HasPrefix(l, "-A DOCKER-USER ") {
			rules = append(rules, l)
		}
	}
	fw := &facts.Firewall{Iptables: &facts.Iptables{Listed: true, DockerUserRules: rules}}
	c, why := fw.UFWDockerChain()
	if c == nil {
		t.Fatalf("not recognised: %s", why)
	}
	if denied, _ := c.Denies("tcp", 5432); !denied {
		t.Error("the block does not drop new connections to containers")
	}
}
