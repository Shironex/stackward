package redact

import (
	"encoding/json"
	"strings"
	"testing"
)

// Planted secrets are assembled at run time from harmless parts, so the
// source never contains a literal that a secret scanner (or a reader)
// would take for a real credential. None of these values is real.
func rep(s string, n int) string { return strings.Repeat(s, n) }

var planted = map[string]string{
	"aws":       "AK" + "IA" + rep("EXAMPLE", 2) + "AB",
	"github":    "gh" + "p_" + rep("a1B2", 9),
	"gh_pat":    "github" + "_pat_" + rep("x9Y8", 6),
	"slack":     "xo" + "xb-" + rep("1234", 4),
	"tailscale": "tsk" + "ey-" + rep("abcd", 5),
	"stripe":    "sk" + "_live_" + rep("Zz09", 5),
	"jwt":       "ey" + "J" + rep("hbGciOi", 3) + ".ey" + "J" + rep("zdWIiOi", 3) + "." + rep("c2lnbmF0", 3),
	"tunnel":    "ey" + "J" + rep("hIjoiZXhhbXBsZSJ9", 4),
	"google":    "AI" + "za" + rep("Sy0", 11) + "ab",
	"docker":    "dck" + "r_pat_" + rep("Qw3r", 6),
}

func pem() string {
	return "-----BEGIN " + "OPENSSH PRIVATE KEY-----\n" + rep("bm90LWEta2V5", 6) + "\n-----END " + "OPENSSH PRIVATE KEY-----"
}

func TestStringMasksPlantedSecrets(t *testing.T) {
	for name, secret := range planted {
		in := "value before " + secret + " value after"
		out := String(in)
		if strings.Contains(out, secret) {
			t.Errorf("%s: secret survived: %q", name, out)
		}
		if !strings.Contains(out, Mask) || !strings.HasPrefix(out, "value before ") || !strings.HasSuffix(out, " value after") {
			t.Errorf("%s: context damaged: %q", name, out)
		}
	}
}

func TestStringMasksContextualSecrets(t *testing.T) {
	pw := "hunter" + "2-not-real"
	cases := []struct{ in, gone, keep string }{
		{"postgres://app:" + pw + "@db.example.com:5432/app", pw, "postgres://app:"},
		{"cloudflared tunnel run --token " + pw, pw, "--token "},
		{"--token=" + pw + " --loglevel info", pw, "--loglevel info"},
		{"DB_PASSWORD=" + pw, pw, "DB_PASSWORD="},
		{`"api_key": "` + pw + `"`, pw, `"api_key": "`},
		{"Authorization: Bearer " + pw + "abcdef", pw, "Bearer "},
		{"key file:\n" + pem() + "\nend", "bm90LWEta2V5", "end"},
		{"MYSQL_ROOT_PASSWORD: '" + pw + "'", pw, "MYSQL_ROOT_PASSWORD"},
	}
	for _, tc := range cases {
		out := String(tc.in)
		if strings.Contains(out, tc.gone) || !strings.Contains(out, tc.keep) || !strings.Contains(out, Mask) {
			t.Errorf("String(%q) = %q", tc.in, out)
		}
	}
}

func TestStringKeepsHarmlessText(t *testing.T) {
	for _, s := range []string{
		"passwordauthentication yes",
		"PasswordAuthentication=no",
		"permitrootlogin prohibit-password",
		"token_file=/etc/stackward/token",
		"--password-file /run/secrets/db",
		"reboot pending for 20 days",
		"running kernel 6.8.0-45-generic is older than installed 6.8.0-49-generic",
		"port:tcp/5432 published on 0.0.0.0",
		"container:app/web runs as root",
		"sha256:0123456789abcdef",
	} {
		if got := String(s); got != s {
			t.Errorf("String(%q) = %q, want unchanged", s, got)
		}
	}
}

func TestValueWalksJSON(t *testing.T) {
	pw := "s3cr3t" + "-not-real"
	in := map[string]any{
		"password":               pw,
		"PasswordAuthentication": "yes",
		"token_file":             "/etc/x/token",
		"nested": []any{
			map[string]any{"client_secret": pw, "count": json.Number("3")},
			"cmd --token " + pw,
		},
		"enabled": true,
	}
	b, err := JSON(in)
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	if strings.Contains(out, pw) {
		t.Fatalf("secret survived:\n%s", out)
	}
	for _, keep := range []string{`"PasswordAuthentication": "yes"`, `"token_file": "/etc/x/token"`, `"count": 3`, `"enabled": true`} {
		if !strings.Contains(out, keep) {
			t.Errorf("lost %s in\n%s", keep, out)
		}
	}
}

func TestIsSecretKey(t *testing.T) {
	yes := []string{"password", "DB_PASSWORD", "api_key", "apiKey", "TUNNEL_TOKEN", "client_secret", "credentials"}
	no := []string{"PasswordAuthentication", "token_file", "hostname", "port", "user", "password_age_days"}
	for _, k := range yes {
		if !IsSecretKey(k) {
			t.Errorf("IsSecretKey(%q) = false", k)
		}
	}
	for _, k := range no {
		if IsSecretKey(k) {
			t.Errorf("IsSecretKey(%q) = true", k)
		}
	}
}
