// Package facts holds what stackward knows about the host: the Facts model,
// the collectors that fill it, and the runner that executes them.
//
// Collectors only read. They never write to the system, never send anything
// but GET to Docker, never run commands that change state and never read the
// contents of secret files (metadata only). Checks never touch the system at
// all: they are pure functions over a Facts value, which is why a Facts value
// saved as JSON (see --dump-facts) is enough to reproduce a report.
package facts

import "time"

// SchemaVersion identifies the JSON shape of Facts. Bump it only for a
// breaking change; adding an optional field is not breaking.
const SchemaVersion = "stackward.facts.v1"

// Facts is everything the collectors gathered in one run.
//
// Every domain field is a pointer owned by exactly one collector. A nil
// pointer means "not inspected" (the collector did not run, needed root, or
// failed before it learned anything); checks must turn that into an unknown
// result, never a pass. The domain types live in one file each (ssh.go,
// docker.go, ...) so that slices working in parallel never edit this file.
type Facts struct {
	Schema string `json:"schema"`
	// CollectedAt is when the run started (UTC). Checks use it as "now", so
	// replaying saved facts gives the same answer later.
	CollectedAt time.Time `json:"collected_at"`

	// Host is filled by the runner itself, before any collector runs.
	Host *Host `json:"host,omitempty"`

	// Filled by the os collector (os.go).
	OS     *OS     `json:"os,omitempty"`
	Kernel *Kernel `json:"kernel,omitempty"`
	Reboot *Reboot `json:"reboot,omitempty"`

	// Reserved for later collectors; each type is declared in its own file.
	SSH         *SSH         `json:"ssh,omitempty"`
	Firewall    *Firewall    `json:"firewall,omitempty"`
	Listeners   *Listeners   `json:"listeners,omitempty"`
	Docker      *Docker      `json:"docker,omitempty"`
	Users       *Users       `json:"users,omitempty"`
	Updates     *Updates     `json:"updates,omitempty"`
	Sysctl      *Sysctl      `json:"sysctl,omitempty"`
	Journal     *Journal     `json:"journal,omitempty"`
	Clock       *Clock       `json:"clock,omitempty"`
	Disk        *Disk        `json:"disk,omitempty"`
	Tailscale   *Tailscale   `json:"tailscale,omitempty"`
	Cloudflared *Cloudflared `json:"cloudflared,omitempty"`
	CrowdSec    *CrowdSec    `json:"crowdsec,omitempty"`
	Fail2ban    *Fail2ban    `json:"fail2ban,omitempty"`
	PaaS        *PaaS        `json:"paas,omitempty"`
	Secrets     *Secrets     `json:"secrets,omitempty"`

	// ProviderFirewall is filled by the opt in provider client
	// (internal/provider, --provider) before the sandbox, not by a
	// collector; nil means it was not requested. See provider.go.
	ProviderFirewall *ProviderFirewall `json:"provider_firewall,omitempty"`

	// Collectors records how every collector ended, in name order.
	Collectors []CollectorStatus `json:"collectors"`
}

// Host is the identity of the process that ran the audit.
type Host struct {
	// Hostname is the raw host name. Output hashes it unless the user passes
	// --show-hostname; never put it in a fixture.
	Hostname string `json:"hostname,omitempty"`
	UID      int    `json:"uid"`
	EUID     int    `json:"euid"`
	// Root is true when the effective uid is 0.
	Root bool `json:"root"`
}

// Status is how one collector ended.
type Status string

// Collector outcomes. Only StatusOK and StatusPartial merge data into Facts.
const (
	StatusOK      Status = "ok"
	StatusPartial Status = "partial" // returned data and an error
	StatusFailed  Status = "failed"  // returned an error and no data
	StatusTimeout Status = "timeout" // did not finish within the timeout
	StatusSkipped Status = "skipped" // not run (for example: needs root)
)

// CollectorStatus is one entry of Facts.Collectors.
type CollectorStatus struct {
	Name   string `json:"name"`
	Status Status `json:"status"`
	// Reason explains a skip in words a user can act on.
	Reason string `json:"reason,omitempty"`
	// Error is the collector error text. It is redacted before output.
	Error string `json:"error,omitempty"`
}

// CollectorStatus returns the status entry for the named collector.
func (f *Facts) CollectorStatus(name string) (CollectorStatus, bool) {
	if f == nil {
		return CollectorStatus{}, false
	}
	for _, c := range f.Collectors {
		if c.Name == name {
			return c, true
		}
	}
	return CollectorStatus{}, false
}

// IsRoot reports whether the audit ran as root. Unknown counts as not root.
func (f *Facts) IsRoot() bool {
	return f != nil && f.Host != nil && f.Host.Root
}
