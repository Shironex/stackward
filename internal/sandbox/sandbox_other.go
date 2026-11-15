//go:build !linux

package sandbox

func apply(Options) Status {
	return Status{State: Unavailable, Reason: "Landlock is Linux only"}
}
