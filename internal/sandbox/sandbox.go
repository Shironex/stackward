// Package sandbox confines stackward itself so that the read only promise
// does not rest on code review alone. On Linux with Landlock (5.13+) Apply
// takes away every filesystem write right from the process and its children
// (and TCP bind and connect on kernels with Landlock ABI 4+). Elsewhere it
// does nothing and says so; the report prints the state either way.
//
// Open every output file before calling Apply: a descriptor opened earlier
// keeps working, a new file cannot be created afterwards.
package sandbox

// State is the sandbox outcome printed in the report coverage block.
type State string

// States.
const (
	// Landlock means the process is confined.
	Landlock State = "landlock"
	// Unavailable means the platform or kernel has no usable Landlock.
	Unavailable State = "unavailable"
	// Disabled means the user turned the sandbox off (--no-sandbox).
	Disabled State = "disabled"
	// Failed means Landlock exists but applying it failed. The audit still
	// runs (the code is read only by construction) and the report says so.
	Failed State = "failed"
)

// Status describes what Apply did.
type Status struct {
	State State `json:"state"`
	// ABI is the Landlock ABI version, when known.
	ABI int `json:"abi,omitempty"`
	// Network is true when TCP bind and connect are denied as well.
	Network bool `json:"network,omitempty"`
	// Reason explains Unavailable, Disabled and Failed.
	Reason string `json:"reason,omitempty"`
}

// Options tunes Apply.
type Options struct {
	// Disabled skips the sandbox (reported as Disabled).
	Disabled bool
}

// Apply confines the current process where possible. It never fails the
// caller: the returned Status carries the outcome.
func Apply(opts Options) Status {
	if opts.Disabled {
		return Status{State: Disabled, Reason: "turned off with --no-sandbox"}
	}
	return apply()
}
