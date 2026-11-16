package apply_test

import (
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/apply"
)

func TestDetectCI(t *testing.T) {
	noEnv := func(string) string { return "" }
	envOf := func(kv map[string]string) func(string) string { return func(k string) string { return kv[k] } }
	// stackward <- sudo <- bash (the job's step shell) <- runner <- init
	tree := func(t *testing.T, shellEnv string) string {
		proc := t.TempDir()
		writeProc(t, proc, 500, 400, "stackward", map[string]string{})
		writeProc(t, proc, 400, 300, "sudo", map[string]string{"environ": "PATH=/usr/bin\x00"})
		writeProc(t, proc, 300, 200, "bash", map[string]string{"environ": shellEnv})
		writeProc(t, proc, 200, 1, "Runner.Worker", map[string]string{"environ": "HOME=/home/runner\x00"})
		return proc
	}
	for name, tc := range map[string]struct {
		shellEnv string
		own      map[string]string
		want     apply.CIEnv
	}{
		"not CI":                 {"HOME=/home/u\x00CI=false\x00", nil, apply.CIEnv{}},
		"CI=0 is not CI":         {"CI=0\x00", nil, apply.CIEnv{}},
		"sudo dropped it":        {"GITHUB_ACTIONS=true\x00CI=true\x00", nil, apply.CIEnv{Var: "CI", Where: "pid 300 (bash)"}},
		"own environment":        {"", map[string]string{"GITLAB_CI": "true"}, apply.CIEnv{Var: "GITLAB_CI", Where: "this process"}},
		"allowed in the shell":   {"GITHUB_ACTIONS=true\x00STACKWARD_CI_APPLY=throwaway-vm\x00", nil, apply.CIEnv{Var: "GITHUB_ACTIONS", Where: "pid 300 (bash)", Allowed: true}},
		"allowed with sudo -E":   {"GITHUB_ACTIONS=true\x00", map[string]string{"STACKWARD_CI_APPLY": "throwaway-vm"}, apply.CIEnv{Var: "GITHUB_ACTIONS", Where: "pid 300 (bash)", Allowed: true}},
		"another value is not":   {"JENKINS_URL=http://ci.example.com\x00STACKWARD_CI_APPLY=1\x00", nil, apply.CIEnv{Var: "JENKINS_URL", Where: "pid 300 (bash)"}},
		"no environ at all here": {"", nil, apply.CIEnv{}},
	} {
		get := noEnv
		if tc.own != nil {
			get = envOf(tc.own)
		}
		got := apply.DetectCI(tree(t, tc.shellEnv), 500, get)
		if got != tc.want {
			t.Errorf("%s: %+v, want %+v", name, got, tc.want)
		}
	}
	// No /proc at all (another OS, or a root that cannot read it): only
	// the own environment counts.
	if got := apply.DetectCI(t.TempDir(), 500, envOf(map[string]string{"CI": "true"})); got.Var != "CI" {
		t.Errorf("no proc: %+v", got)
	}
}

func TestCheckCI(t *testing.T) {
	if err := apply.CheckCI(apply.CIEnv{}); err != nil {
		t.Errorf("not CI: %v", err)
	}
	if err := apply.CheckCI(apply.CIEnv{Var: "CI", Where: "this process", Allowed: true}); err != nil {
		t.Errorf("allowed: %v", err)
	}
	err := apply.CheckCI(apply.CIEnv{Var: "GITHUB_ACTIONS", Where: "pid 300 (bash)"})
	if err == nil || !strings.Contains(err.Error(), "GITHUB_ACTIONS is set in pid 300 (bash)") || !strings.Contains(err.Error(), "STACKWARD_CI_APPLY=throwaway-vm") {
		t.Errorf("refusal: %v", err)
	}
}
