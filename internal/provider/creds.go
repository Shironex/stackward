package provider

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strings"

	"github.com/Shironex/stackward/internal/redact"
)

// Environment variables. They are stackward's own names, not the vendors'
// (HCLOUD_TOKEN), so a token set for another tool is never picked up by
// accident. There is no command line flag for a credential: argv shows in
// ps and in shell history.
const (
	EnvHetznerToken     = "STACKWARD_HETZNER_TOKEN"      //nolint:gosec // G101: a variable name, not a credential
	EnvHetznerTokenFile = "STACKWARD_HETZNER_TOKEN_FILE" //nolint:gosec // G101: a variable name, not a credential

	EnvOVHAppKey    = "STACKWARD_OVH_APPLICATION_KEY"
	EnvOVHAppSecret = "STACKWARD_OVH_APPLICATION_SECRET" //nolint:gosec // G101: a variable name, not a credential
	EnvOVHConsumer  = "STACKWARD_OVH_CONSUMER_KEY"
	EnvOVHEndpoint  = "STACKWARD_OVH_ENDPOINT"
	EnvOVHCredsFile = "STACKWARD_OVH_CREDENTIALS_FILE" //nolint:gosec // G101: a variable name, not a credential
)

// ovhVars are the OVH credential variables, also the keys of the
// credentials file.
var ovhVars = []string{EnvOVHAppKey, EnvOVHAppSecret, EnvOVHConsumer, EnvOVHEndpoint}

// maxCredFile caps the read of a credential file.
const maxCredFile = 4096

// errNoCredentials means no credential variable is set for a provider.
var errNoCredentials = errors.New("no credentials")

// hetznerToken returns the Hetzner token from the environment or the token
// file, and registers it with the redaction pass.
func hetznerToken(env func(string) string) (string, error) {
	tok := strings.TrimSpace(env(EnvHetznerToken))
	path := strings.TrimSpace(env(EnvHetznerTokenFile))
	switch {
	case tok != "" && path != "":
		return "", fmt.Errorf("both %s and %s are set; keep one", EnvHetznerToken, EnvHetznerTokenFile)
	case tok == "" && path == "":
		return "", errNoCredentials
	case path != "":
		b, err := readCredFile(path)
		if err != nil {
			return "", err
		}
		tok = strings.TrimSpace(string(b))
	}
	if tok == "" {
		return "", fmt.Errorf("the Hetzner token is empty")
	}
	if strings.ContainsAny(tok, " \t\r\n") {
		return "", fmt.Errorf("the Hetzner token contains white space; the file must hold the token alone")
	}
	redact.AddLiteral(tok)
	return tok, nil
}

// readCredFile reads a credential file once, capped, after checking it is a
// regular file (not a symlink), owned by the user running the audit and not
// readable or writable by group or others.
func readCredFile(path string) ([]byte, error) {
	fh, err := openNoFollow(path)
	if err != nil {
		return nil, fmt.Errorf("credential file %s: %w", path, err)
	}
	defer func() { _ = fh.Close() }()
	fi, err := fh.Stat()
	if err != nil {
		return nil, fmt.Errorf("credential file %s: %w", path, err)
	}
	if err := credFileOK(fi); err != nil {
		return nil, fmt.Errorf("credential file %s: %w", path, err)
	}
	b, err := io.ReadAll(io.LimitReader(fh, maxCredFile+1))
	if err != nil {
		return nil, fmt.Errorf("credential file %s: %w", path, err)
	}
	if len(b) > maxCredFile {
		return nil, fmt.Errorf("credential file %s is larger than %d bytes", path, maxCredFile)
	}
	return b, nil
}

// credFileOK checks the type, mode and owner of an opened credential file.
func credFileOK(fi fs.FileInfo) error {
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("not a regular file")
	}
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("mode %04o lets other users read it; run chmod 600 on it", perm)
	}
	if uid, ok := fileOwner(fi); ok && uid != os.Geteuid() {
		return fmt.Errorf("owned by uid %d, not by the user running the audit (uid %d); chown it", uid, os.Geteuid())
	}
	return nil
}

// ovhCredentials returns the OVH credentials from the environment or the
// credentials file (KEY=VALUE lines with the same names), and registers the
// secret parts with the redaction pass.
func ovhCredentials(env func(string) string) (ovhCreds, error) {
	vals := map[string]string{}
	anyEnv := false
	for _, k := range ovhVars {
		if v := strings.TrimSpace(env(k)); v != "" {
			vals[k], anyEnv = v, true
		}
	}
	path := strings.TrimSpace(env(EnvOVHCredsFile))
	switch {
	case path != "" && anyEnv:
		return ovhCreds{}, fmt.Errorf("both %s and the OVH variables are set; keep one", EnvOVHCredsFile)
	case path == "" && !anyEnv:
		return ovhCreds{}, errNoCredentials
	case path != "":
		b, err := readCredFile(path)
		if err != nil {
			return ovhCreds{}, err
		}
		if vals, err = parseCredLines(string(b)); err != nil {
			return ovhCreds{}, fmt.Errorf("credential file %s: %w", path, err)
		}
	}
	c := ovhCreds{appKey: vals[EnvOVHAppKey], appSecret: vals[EnvOVHAppSecret], consumerKey: vals[EnvOVHConsumer], endpoint: vals[EnvOVHEndpoint]}
	if c.endpoint == "" {
		c.endpoint = "ovh-eu"
	}
	if _, ok := ovhEndpoints[c.endpoint]; !ok {
		return ovhCreds{}, fmt.Errorf("%s must be ovh-eu, ovh-ca or ovh-us, not %q", EnvOVHEndpoint, c.endpoint)
	}
	var missing []string
	for k, v := range map[string]string{EnvOVHAppKey: c.appKey, EnvOVHAppSecret: c.appSecret, EnvOVHConsumer: c.consumerKey} {
		if v == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return ovhCreds{}, fmt.Errorf("the OVH credentials lack %s", strings.Join(missing, ", "))
	}
	for _, v := range []string{c.appKey, c.appSecret, c.consumerKey} {
		redact.AddLiteral(v)
	}
	return c, nil
}

// parseCredLines reads KEY=VALUE lines; blank lines and # comments are
// skipped, and only the OVH variable names are accepted.
func parseCredLines(s string) (map[string]string, error) {
	vals := map[string]string{}
	known := map[string]bool{}
	for _, k := range ovhVars {
		known[k] = true
	}
	for i, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		k = strings.TrimSpace(k)
		if !ok || !known[k] {
			// The line is never echoed: it may hold a secret.
			return nil, fmt.Errorf("line %d is not one of %s=VALUE", i+1, strings.Join(ovhVars, ", "))
		}
		vals[k] = strings.Trim(strings.TrimSpace(v), `"'`)
	}
	return vals, nil
}
