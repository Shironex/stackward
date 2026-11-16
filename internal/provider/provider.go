// Package provider reads a cloud provider's network firewall over the
// provider's API, read only, into facts.ProviderFirewall for the PFW checks.
//
// It is opt in (stackward audit --provider) and the only code of the audit
// that dials out to the internet. Its reach is small on purpose: one helper
// that can only build GET requests, a fixed list of API hosts, no redirects,
// no proxy, a size cap and one timeout. Credentials come from the environment
// or a file per run, never from argv, and are never stored: they are not in
// facts, reports or logs, and the redaction pass masks them as literal
// values on top of that.
//
// The CLI calls Fetch before the Landlock sandbox, which denies TCP connect
// and cannot be loosened later (see docs/threat-model.md).
package provider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/Shironex/stackward/internal/facts"
)

// DefaultTimeout bounds the whole fetch, every request included.
const DefaultTimeout = 10 * time.Second

// Names accepted by --provider.
const (
	Hetzner = "hetzner"
	OVH     = "ovh"
	Auto    = "auto"
)

// Names lists the --provider values this build supports.
var Names = []string{Hetzner, OVH, Auto}

// Options says what to ask and how.
type Options struct {
	// Provider is a value of Names.
	Provider string
	// Addresses are the public IPv4 addresses to match (interface
	// addresses or --provider-ip).
	Addresses []string
	// Env reads an environment variable (os.Getenv in the CLI).
	Env func(string) string
	// Timeout bounds the whole fetch; zero means DefaultTimeout.
	Timeout time.Duration
	// Now is the clock for OVH request timestamps; nil means time.Now.
	Now func() time.Time
	// Transport replaces the HTTP transport. Tests use it to answer from
	// recorded responses; the URL host is still checked against the fixed
	// host list first.
	Transport http.RoundTripper
}

// Fetch asks the provider about every address and returns what it said. It
// never returns nil and never fails the audit: every problem becomes a
// status and a reason, which the PFW checks turn into unknown.
func Fetch(ctx context.Context, o Options) *facts.ProviderFirewall {
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	name, err := choose(o)
	if err != nil {
		return &facts.ProviderFirewall{Provider: name, Status: facts.ProviderNoCredentials, Reason: err.Error()}
	}
	g := newGetter(o.Transport, timeout)
	switch name {
	case Hetzner:
		tok, err := hetznerToken(o.Env)
		if err != nil {
			return credFailure(Hetzner, err, EnvHetznerToken+" or "+EnvHetznerTokenFile)
		}
		return fetchHetzner(ctx, g, tok, o.Addresses)
	case OVH:
		creds, err := ovhCredentials(o.Env)
		if err != nil {
			return credFailure(OVH, err, EnvOVHAppKey+", "+EnvOVHAppSecret+" and "+EnvOVHConsumer+" (or "+EnvOVHCredsFile+")")
		}
		now := o.Now
		if now == nil {
			now = time.Now
		}
		return fetchOVH(ctx, g, creds, o.Addresses, now)
	}
	return &facts.ProviderFirewall{Provider: name, Status: facts.ProviderError, Reason: "unsupported provider " + name}
}

// choose resolves auto by which credentials are set. It is not a network
// probe.
func choose(o Options) (string, error) {
	if o.Provider != Auto {
		return o.Provider, nil
	}
	hetzner := o.Env(EnvHetznerToken) != "" || o.Env(EnvHetznerTokenFile) != ""
	ovh := o.Env(EnvOVHCredsFile) != ""
	for _, k := range ovhVars {
		ovh = ovh || (k != EnvOVHEndpoint && o.Env(k) != "")
	}
	switch {
	case hetzner && ovh:
		return "none", fmt.Errorf("--provider auto found Hetzner and OVH credentials; name the provider")
	case hetzner:
		return Hetzner, nil
	case ovh:
		return OVH, nil
	}
	return "none", fmt.Errorf("--provider auto found no credentials: set %s or %s for Hetzner, or the %s variables for OVH",
		EnvHetznerToken, EnvHetznerTokenFile, "STACKWARD_OVH_*")
}

func credFailure(name string, err error, vars string) *facts.ProviderFirewall {
	if errors.Is(err, errNoCredentials) {
		return &facts.ProviderFirewall{Provider: name, Status: facts.ProviderNoCredentials,
			Reason: "set " + vars + " to a read only API credential"}
	}
	return &facts.ProviderFirewall{Provider: name, Status: facts.ProviderNoCredentials, Reason: err.Error()}
}

// classify turns a request error into a provider status and a reason, and
// says whether asking about further addresses is pointless.
func classify(err error) (facts.ProviderStatus, string, bool) {
	var ae *apiError
	var ue *unreachableError
	switch {
	case errors.As(err, &ae) && (ae.code == http.StatusUnauthorized || ae.code == http.StatusForbidden):
		return facts.ProviderDenied, fmt.Sprintf("the API refused the credentials (%d); check the token is valid and has read access", ae.code), true
	case errors.As(err, &ae) && ae.code == http.StatusTooManyRequests:
		return facts.ProviderError, "rate limited by the provider API (429); try again later", true
	case errors.As(err, &ue), errors.Is(err, context.DeadlineExceeded):
		return facts.ProviderUnreachable, err.Error(), true
	}
	return facts.ProviderError, err.Error(), false
}

// noAddresses is the result when there is no public address to ask about.
func noAddresses(pf *facts.ProviderFirewall) *facts.ProviderFirewall {
	pf.Status = facts.ProviderNoMatch
	pf.Reason = "the host has no public IPv4 address on an interface; pass --provider-ip with the address the provider gave it"
	return pf
}
