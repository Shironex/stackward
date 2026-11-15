// Package redact masks secret shaped values in anything stackward prints or
// dumps. Collectors are written to never pick up secrets in the first place
// (Docker env is stripped, secret files are only stat'ed); this package is
// the safety net on every output path, not the plan.
package redact

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Mask replaces every redacted value.
const Mask = "[REDACTED]"

type rule struct {
	re   *regexp.Regexp
	repl string // regexp replacement; Mask is spliced in as needed
}

// secretWord matches names that usually hold a secret. It is a pattern of
// key names, not a credential.
const secretWord = `(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|credentials?|auth[_-]?key|session[_-]?key)` //nolint:gosec // G101: a name pattern, not a secret

var rules = []rule{
	// PEM private key blocks, whole.
	{regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----`), Mask},
	// Passwords in URLs: scheme://user:secret@host keeps the user.
	{regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+):[^/\s@]+@`), "${1}:" + Mask + "@"},
	// Authorization headers.
	{regexp.MustCompile(`(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}`), "${1} " + Mask},
	// Well known token formats.
	{regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), Mask},                      // AWS access key id
	{regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{30,}\b`), Mask},                     // GitHub token
	{regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}\b`), Mask},                   // GitHub fine grained token
	{regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{16,}\b`), Mask},                       // GitLab token
	{regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}\b`), Mask},                  // Slack token
	{regexp.MustCompile(`\btskey-[A-Za-z0-9-]{10,}\b`), Mask},                        // Tailscale key
	{regexp.MustCompile(`\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b`), Mask},           // Stripe key
	{regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`), Mask},                          // Google API key
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}(?:\.[A-Za-z0-9_-]+){0,2}=*`), Mask}, // JWT, Cloudflare tunnel token (base64 JSON)
	{regexp.MustCompile(`\bdckr_pat_[A-Za-z0-9_-]{20,}\b`), Mask},                    // Docker Hub token
	{regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`), Mask},                            // npm token
	{regexp.MustCompile(`\bhvs\.[A-Za-z0-9_-]{20,}\b`), Mask},                        // Vault token
	{regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b`), Mask},     // SendGrid key
	{regexp.MustCompile(`\b[0-9a-f]{32}-us[0-9]{1,2}\b`), Mask},                      // Mailchimp key
}

// keyed match a secret looking name followed by its value: command line
// flags (--token X, --password=X) and assignments (NAME=value, "name":
// "value"). Each has three groups: name, separator, value.
var keyed = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(\s--?` + secretWord + `[A-Za-z0-9_-]*)(=|\s+)("[^"]*"|'[^']*'|\S+)`),
	regexp.MustCompile(`(?i)\b([A-Za-z0-9_.-]*` + secretWord + `[A-Za-z0-9_.-]*)(["']?\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s,;&"']+)`),
}

// String returns s with secret shaped values masked.
func String(s string) string {
	if s == "" {
		return s
	}
	for _, r := range rules {
		s = r.re.ReplaceAllString(s, r.repl)
	}
	// A leading space lets the flag pattern match at the very start too.
	s = " " + s
	for _, re := range keyed {
		s = re.ReplaceAllStringFunc(s, func(m string) string {
			sub := re.FindStringSubmatch(m)
			val := sub[3]
			if benign(strings.Trim(val, `"'`)) {
				return m
			}
			if q := val[0]; (q == '"' || q == '\'') && len(val) >= 2 {
				return sub[1] + sub[2] + string(q) + Mask + string(q)
			}
			return sub[1] + sub[2] + Mask
		})
	}
	return s[1:]
}

// benignValues are values a secret named key commonly holds that are not
// secrets: sshd and config switches, and empties. "all" is sudoers'
// NOPASSWD: ALL, which the account steps write.
var benignValues = map[string]bool{
	"": true, "yes": true, "no": true, "true": true, "false": true, "on": true, "off": true, "all": true,
	"none": true, "null": true, "nil": true, "0": true, "1": true, "any": true, "unset": true,
	"prohibit-password": true, "without-password": true, "forced-commands-only": true,
	Mask: true,
}

func benign(v string) bool {
	lv := strings.ToLower(v)
	// Paths name where a secret lives, which is useful evidence and not
	// the secret itself.
	return benignValues[lv] || strings.HasPrefix(v, "/")
}

var secretKey = regexp.MustCompile(`(?i)` + secretWord)

// nonSecretKey matches secret looking names that hold settings, not
// secrets: "PasswordAuthentication", "token_file", "password_age_days".
var nonSecretKey = regexp.MustCompile(`(?i)(authentication|_?(file|path|dir|age|days|expiry|expires|set|present|count|len|length)$)`)

// IsSecretKey reports whether a map key or variable name looks like it holds
// a secret.
func IsSecretKey(k string) bool {
	return secretKey.MatchString(k) && !nonSecretKey.MatchString(k)
}

// Value returns a deep copy of a decoded JSON value (maps, slices, strings,
// numbers, bools, nil) with secrets masked. String values under a secret
// looking key are masked whole unless benign.
func Value(v any) any {
	switch t := v.(type) {
	case string:
		return String(t)
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = Value(e)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			if s, ok := e.(string); ok && IsSecretKey(k) && !benign(s) {
				out[k] = Mask
				continue
			}
			out[k] = Value(e)
		}
		return out
	default:
		return v
	}
}

// JSON marshals v, masks secrets in the result and returns indented JSON.
// Use it for every JSON that leaves the process.
func JSON(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var decoded any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&decoded); err != nil {
		return nil, err
	}
	out, err := json.MarshalIndent(Value(decoded), "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}
