package cli

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/provider"
)

// providerFlags are the opt in provider firewall flags of audit and plan.
type providerFlags struct {
	name string
	ip   string
}

// providerHelp is appended to the usage of audit and plan.
const providerHelp = `
Provider firewall (opt in, read only):
  --provider hetzner|ovh|auto reads the cloud provider's firewall over its
  API before the sandbox, with GET requests to the provider's API host only.
  Credentials come from the environment or a file, never from a flag:
    Hetzner: STACKWARD_HETZNER_TOKEN or STACKWARD_HETZNER_TOKEN_FILE
    OVH:     STACKWARD_OVH_APPLICATION_KEY, STACKWARD_OVH_APPLICATION_SECRET,
             STACKWARD_OVH_CONSUMER_KEY, STACKWARD_OVH_ENDPOINT (default
             ovh-eu), or STACKWARD_OVH_CREDENTIALS_FILE with KEY=VALUE lines
  Use a Hetzner API token with permission Read: the audit cannot tell a
  Read token from a Read & Write one. Limit the OVH consumer key to
  GET /ip/*. A credential file must be a regular file owned by you with
  mode 600. Nothing is stored.
`

func addProviderFlags(fs *flag.FlagSet, p *providerFlags) {
	fs.StringVar(&p.name, "provider", "", "read the provider firewall over its API: "+strings.Join(provider.Names, ", ")+" (opt in; see below)")
	fs.StringVar(&p.ip, "provider-ip", "", "the public IPv4 address to match at the provider, when the host does not show it on an interface")
}

// check validates the provider flags against the rest of the run.
func (p providerFlags) check(offline bool) error {
	if p.name == "" {
		if p.ip != "" {
			return fmt.Errorf("--provider-ip needs --provider")
		}
		return nil
	}
	known := false
	for _, n := range provider.Names {
		known = known || n == p.name
	}
	if !known {
		return fmt.Errorf("--provider must be one of %s, not %q", strings.Join(provider.Names, ", "), p.name)
	}
	if offline {
		return fmt.Errorf("--provider reads the live provider API; it cannot be combined with --facts or --report")
	}
	if p.ip != "" {
		a, err := netip.ParseAddr(p.ip)
		if err != nil || !a.Is4() {
			return fmt.Errorf("--provider-ip must be an IPv4 address, not %q", p.ip)
		}
	}
	return nil
}

// fetchProvider asks the provider before the sandbox, which denies TCP
// connect. It returns nil when --provider was not given: no request is
// sent and the PFW checks say the module was not requested.
func fetchProvider(ctx context.Context, p providerFlags, sys facts.System) *facts.ProviderFirewall {
	if p.name == "" {
		return nil
	}
	addrs := []string{p.ip}
	if p.ip == "" {
		var err error
		addrs, err = facts.PublicIPv4Candidates(ctx, sys)
		if err != nil {
			return &facts.ProviderFirewall{Provider: p.name, Status: facts.ProviderError,
				Reason: "the interface addresses could not be read (" + err.Error() + "); pass --provider-ip"}
		}
	}
	return provider.Fetch(ctx, provider.Options{Provider: p.name, Addresses: addrs, Env: os.Getenv})
}
