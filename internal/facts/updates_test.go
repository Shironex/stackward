package facts

import (
	"slices"
	"testing"
)

// TestAptSimulateWritesNothing pins the options that keep `apt-get -s
// upgrade` from writing: without them apt takes the dpkg lock, rewrites
// pkgcache.bin after dpkg changed, and replaces /var/log/apt/eipp.log.xz
// with its planner dump on every run (seen on an Ubuntu 24.04 runner under
// strace, with and without the sandbox).
func TestAptSimulateWritesNothing(t *testing.T) {
	for _, opt := range []string{"Debug::NoLocking=true", "Dir::Cache::pkgcache=", "Dir::Log::Planner="} {
		i := slices.Index(aptSimulateArgs, opt)
		if i < 1 || aptSimulateArgs[i-1] != "-o" {
			t.Errorf("aptSimulateArgs %q lacks -o %s", aptSimulateArgs, opt)
		}
	}
	if aptSimulateArgs[0] != "-s" || aptSimulateArgs[len(aptSimulateArgs)-1] != "upgrade" {
		t.Errorf("aptSimulateArgs %q is not a simulated upgrade", aptSimulateArgs)
	}
}
