package facts

import (
	"context"
	"fmt"
	"strings"
)

// Clock is time synchronization state (SYS-004).
type Clock struct {
	// NTPSynchronized is timedatectl's NTPSynchronized: the system clock is
	// currently synchronized.
	NTPSynchronized bool `json:"ntp_synchronized"`
	// NTPEnabled is the NTP property: a time sync service is switched on.
	NTPEnabled bool `json:"ntp_enabled"`
	// CanNTP is whether a time sync service is available at all.
	CanNTP   bool   `json:"can_ntp"`
	Timezone string `json:"timezone,omitempty"`
}

type clockCollector struct{}

func init() { Register(clockCollector{}) }

func (clockCollector) Name() string    { return "clock" }
func (clockCollector) NeedsRoot() bool { return false }

func (clockCollector) Collect(ctx context.Context, sys System, out *Facts) error {
	// `timedatectl show` prints properties and changes nothing.
	res, err := sys.Run(ctx, "timedatectl", "show")
	if err != nil {
		return fmt.Errorf("timedatectl: %w", err)
	}
	if res.ExitCode != 0 {
		return fmt.Errorf("timedatectl show: %w", cmdErr(nil, res))
	}
	kv := ParseKeyValues(res.Stdout)
	sync, ok := kv["NTPSynchronized"]
	if !ok {
		return fmt.Errorf("timedatectl show: no NTPSynchronized property")
	}
	out.Clock = &Clock{
		NTPSynchronized: yes(sync),
		NTPEnabled:      yes(kv["NTP"]),
		CanNTP:          yes(kv["CanNTP"]),
		Timezone:        kv["Timezone"],
	}
	return nil
}

func yes(s string) bool { return strings.EqualFold(strings.TrimSpace(s), "yes") }

// ParseKeyValues parses "Key=value" lines (systemd `show` output).
func ParseKeyValues(b []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && k != "" {
			out[k] = v
		}
	}
	return out
}
