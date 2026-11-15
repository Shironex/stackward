// Package version reports the build version. Release builds set Version
// with -ldflags "-X github.com/Shironex/stackward/internal/version.Version=v0.1.0".
package version

import "runtime/debug"

// Version is set at link time by release builds.
var Version = ""

// String returns the link time version, else the module version recorded
// by `go install`, else "dev".
func String() string {
	if Version != "" {
		return Version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}

// Commit returns the VCS revision recorded by the Go toolchain, if any.
func Commit() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	rev, dirty := "", false
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	if rev != "" && dirty {
		rev += "-dirty"
	}
	return rev
}
