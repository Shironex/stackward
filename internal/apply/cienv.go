package apply

import (
	"fmt"
	"path/filepath"
	"strconv"
)

// CI gate. Apply changes SSH, the firewall and accounts, so it must never
// run on a CI machine by accident: a workflow that runs `sudo stackward
// apply` on a shared or self-hosted runner could lock that runner out or
// leave it changed for the next job. Apply refuses when it finds a CI
// environment, unless the job says it runs on a throwaway VM of its own
// with CIApplyEnv set to CIApplyValue. Only the scenario jobs (one GitHub
// hosted runner VM per job) and the VM matrix set it (docs/testing.md).
//
// sudo drops the caller's environment, so the variables are looked up in
// the process's own environment and in the environment of every ancestor,
// up to init: the job's shell still holds them when sudo has dropped them
// from ours.

// CIApplyEnv is the variable that lets apply run in CI, and CIApplyValue
// the one value that does.
const (
	CIApplyEnv   = "STACKWARD_CI_APPLY"
	CIApplyValue = "throwaway-vm"
)

// ciVars are the variables CI systems set on every job. Each one counts
// when it is set to anything but "", "false" or "0" (CI=false is a common
// way to say "not CI").
var ciVars = []string{
	"CI", "GITHUB_ACTIONS", "GITLAB_CI", "CIRCLECI", "TRAVIS", "BUILDKITE",
	"JENKINS_URL", "TF_BUILD", "TEAMCITY_VERSION", "BITBUCKET_BUILD_NUMBER",
	"DRONE", "CODEBUILD_BUILD_ID", "SEMAPHORE",
}

// CIEnv is what DetectCI found.
type CIEnv struct {
	// Var is the first CI variable found ("" when none) and Where the
	// process that holds it ("this process" or "pid N (comm)").
	Var, Where string
	// Allowed is true when CIApplyEnv=CIApplyValue was found.
	Allowed bool
}

// DetectCI looks for a CI environment in getenv (the process's own
// environment) and in the environment of every ancestor of pid under
// procRoot ("/proc" on a real host). It only reads; an environment it
// cannot read (another user's process without root) is skipped.
func DetectCI(procRoot string, pid int, getenv func(string) string) CIEnv {
	var c CIEnv
	look := func(get func(string) string, where string) {
		if get(CIApplyEnv) == CIApplyValue {
			c.Allowed = true
		}
		if c.Var != "" {
			return
		}
		for _, v := range ciVars {
			if val := get(v); val != "" && val != "false" && val != "0" {
				c.Var, c.Where = v, where
				return
			}
		}
	}
	look(getenv, "this process")
	p := pid
	for n := 0; n < maxAncestors; n++ {
		comm, ppid, _, ok := readStat(procRoot, p)
		if !ok || ppid <= 0 {
			break
		}
		if n > 0 {
			env := readEnviron(filepath.Join(procRoot, strconv.Itoa(p), "environ"))
			look(func(k string) string { return env[k] }, "pid "+strconv.Itoa(p)+" ("+comm+")")
		}
		if ppid == 1 {
			break
		}
		p = ppid
	}
	return c
}

// CheckCI refuses apply in a CI environment that did not set CIApplyEnv.
func CheckCI(c CIEnv) error {
	if c.Var == "" || c.Allowed {
		return nil
	}
	return fmt.Errorf("this looks like a CI job (%s is set in %s), and apply changes SSH, the firewall and accounts on the machine it runs on; "+
		"it runs in CI only on a throwaway VM the job owns, which the job says with %s=%s (see docs/testing.md)", c.Var, c.Where, CIApplyEnv, CIApplyValue)
}
