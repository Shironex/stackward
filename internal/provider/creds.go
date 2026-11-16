package provider

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
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
)

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
