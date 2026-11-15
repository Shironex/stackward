//go:build !linux

package sandbox

func apply() Status {
	return Status{State: Unavailable, Reason: "Landlock is Linux only"}
}
