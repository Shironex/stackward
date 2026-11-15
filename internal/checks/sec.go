package checks

import (
	"fmt"
	"path"
	"strings"

	"github.com/Shironex/stackward/internal/facts"
)

// SEC checks judge file metadata the secrets collector gathered
// (facts/secrets.go). Contents are never read, so every verdict rests on
// mode, owner and name only.

func init() {
	Register(Check{ID: "SEC-001", Run: checkPaaSEnvFiles})
	Register(Check{ID: "SEC-002", Run: checkPaaSMainEnv})
	Register(Check{ID: "SEC-003", Run: checkPaaSSSHKeys})
	Register(Check{ID: "SEC-004", Run: checkProxyDynamicStrays})
	Register(Check{ID: "SEC-005", Run: checkPrivateKeys})
	Register(Check{ID: "SEC-006", Run: checkDockerConfig})
	Register(Check{ID: "SEC-007", Run: checkPaaSWorldWritable})
}

// secScan is how one SEC check reads its scan.
type secScan struct {
	// pick selects the scan from Secrets.
	pick func(*facts.Secrets) facts.SecretScan
	// none is the skip message when there was nothing to search.
	none string
	// judge returns a non pass verdict for a file, or ok false for a pass.
	judge func(facts.SecretFile) (Level, string, bool)
	// passed is the summary message for files that passed, given their
	// count (0 when nothing matched).
	passed func(n int) string
}

// run turns a scan into results: one per bad file, one per path that
// could not be inspected, and one summary pass for the rest.
func (s secScan) run(f *facts.Facts) []Result {
	if f.Secrets == nil {
		return []Result{NotInspected(f, "secrets")}
	}
	scan := s.pick(f.Secrets)
	if len(scan.Roots) == 0 {
		return One(Skip, s.none, nil)
	}
	var out []Result
	good := 0
	for _, file := range scan.Files {
		level, msg, bad := s.judge(file)
		if !bad {
			good++
			continue
		}
		out = append(out, Result{Subject: "file:" + file.Path, Level: level, Message: msg, Evidence: secFileEvidence(file)})
	}
	sudo := ""
	if !f.IsRoot() {
		sudo = "; run with sudo for full coverage"
	}
	for _, d := range scan.Denied {
		out = append(out, Result{Subject: "file:" + d, Level: Unknown,
			Message:  "could not inspect: permission denied" + sudo,
			Evidence: map[string]any{"path": d}})
	}
	if scan.Truncated {
		out = append(out, Result{Level: Unknown, Message: "search stopped at its entry cap; some files were not inspected",
			Evidence: map[string]any{"roots": scan.Roots, "passed": good}})
	}
	if good > 0 || len(out) == 0 {
		out = append(out, Result{Level: Pass, Message: s.passed(good), Evidence: map[string]any{"roots": scan.Roots, "passed": good}})
	}
	return out
}

func secFileEvidence(file facts.SecretFile) map[string]any {
	return map[string]any{"path": file.Path, "kind": file.Kind, "mode": file.Mode.String(),
		"uid": file.UID, "gid": file.GID, "platform": file.Platform}
}

func secPlural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}

func checkPaaSEnvFiles(in Input) []Result {
	return secScan{
		pick: func(s *facts.Secrets) facts.SecretScan { return s.PaaSEnvFiles },
		none: "no Coolify or Dokploy app folders found",
		judge: func(file facts.SecretFile) (Level, string, bool) {
			if file.Mode.GroupOrOtherReadable() {
				return Fail, fmt.Sprintf("app .env is readable by group or others (mode %s)", file.Mode), true
			}
			return "", "", false
		},
		passed: func(n int) string {
			if n == 0 {
				return "no app .env files found"
			}
			return secPlural(n, "app .env file is", "app .env files are") + " readable by the owner only"
		},
	}.run(in.Facts)
}

func checkPaaSMainEnv(in Input) []Result {
	return secScan{
		pick: func(s *facts.Secrets) facts.SecretScan { return s.PaaSMainEnv },
		none: "no platform main .env on this host (Coolify panel not found)",
		judge: func(file facts.SecretFile) (Level, string, bool) {
			switch {
			case file.Mode.OtherReadable():
				return Fail, fmt.Sprintf("platform main .env is world readable (mode %s)", file.Mode), true
			case file.Mode&0o023 != 0:
				return Warn, fmt.Sprintf("platform main .env is writable by group or has other bits set (mode %s)", file.Mode), true
			}
			return "", "", false
		},
		passed: func(n int) string {
			if n == 0 {
				return "platform main .env not found"
			}
			return "platform main .env is not world readable"
		},
	}.run(in.Facts)
}

func checkPaaSSSHKeys(in Input) []Result {
	return secScan{
		pick: func(s *facts.Secrets) facts.SecretScan { return s.PaaSSSHKeys },
		none: "no platform SSH key folder on this host",
		judge: func(file facts.SecretFile) (Level, string, bool) {
			if file.Kind == "dir" {
				if file.Mode&0o077 != 0 {
					return Fail, fmt.Sprintf("SSH key folder is open to group or others (mode %s, want 0700)", file.Mode), true
				}
				return "", "", false
			}
			if !facts.IsPaaSKeyName(path.Base(file.Path)) {
				return "", "", false // a lock file or public half in an older facts file
			}
			if file.Mode.GroupOrOtherReadable() {
				return Fail, fmt.Sprintf("platform SSH key is readable by group or others (mode %s)", file.Mode), true
			}
			return "", "", false
		},
		passed: func(n int) string {
			return secPlural(n, "SSH key path is", "SSH key paths are") + " closed to other users"
		},
	}.run(in.Facts)
}

// strayTokens mark backup and editor copies in a file name.
var (
	secStraySuffixes = []string{"~", ".bak", ".backup", ".old", ".orig", ".save", ".swp", ".swo", ".tmp", ".rej",
		".dpkg-old", ".dpkg-dist", ".ucf-old"}
	secStrayInfixes = []string{".bak", "backup", ".old", "-old", "_old", ".orig", "copy"}
)

// secIsStrayName reports whether a file name looks like a backup or editor
// leftover.
func secIsStrayName(name string) bool {
	lower := strings.ToLower(name)
	if strings.HasPrefix(lower, "#") && strings.HasSuffix(lower, "#") {
		return true
	}
	if strings.HasPrefix(lower, ".") && (strings.HasSuffix(lower, ".swp") || strings.HasSuffix(lower, ".swo")) {
		return true
	}
	for _, s := range secStraySuffixes {
		if strings.HasSuffix(lower, s) {
			return true
		}
	}
	stem := strings.TrimSuffix(lower, path.Ext(lower))
	for _, s := range secStrayInfixes {
		if strings.Contains(stem, s) {
			return true
		}
	}
	return false
}

// secLoadedByTraefik reports whether Traefik's file provider loads the file:
// it reads .yml, .yaml and .toml files in the directory.
func secLoadedByTraefik(name string) bool {
	switch strings.ToLower(path.Ext(name)) {
	case ".yml", ".yaml", ".toml":
		return true
	}
	return false
}

func checkProxyDynamicStrays(in Input) []Result {
	rs := secScan{
		pick: func(s *facts.Secrets) facts.SecretScan { return s.ProxyDynamic },
		none: "no platform proxy dynamic config folder on this host",
		judge: func(file facts.SecretFile) (Level, string, bool) {
			name := path.Base(file.Path)
			if !secIsStrayName(name) {
				return "", "", false
			}
			if secLoadedByTraefik(name) {
				return Warn, "backup copy in the proxy dynamic folder is loaded as live config", true
			}
			return Warn, "backup or editor file in the proxy dynamic folder", true
		},
		passed: func(n int) string {
			if n == 0 {
				return "proxy dynamic config folder is empty"
			}
			return secPlural(n, "file in the proxy dynamic folder is", "files in the proxy dynamic folder are") + " not a backup or editor copy"
		},
	}.run(in.Facts)
	for i := range rs {
		if rs[i].Level == Warn {
			rs[i].Evidence["loaded"] = secLoadedByTraefik(path.Base(rs[i].Evidence["path"].(string)))
		}
	}
	return rs
}

func checkPrivateKeys(in Input) []Result {
	return secScan{
		pick: func(s *facts.Secrets) facts.SecretScan { return s.PrivateKeys },
		none: "no home folders found",
		judge: func(file facts.SecretFile) (Level, string, bool) {
			if !file.Mode.GroupOrOtherReadable() {
				return "", "", false
			}
			if file.Kind == "pem" {
				return Warn, fmt.Sprintf(".pem file is readable by group or others (mode %s); if it holds a private key, chmod 600", file.Mode), true
			}
			return Fail, fmt.Sprintf("private key is readable by group or others (mode %s)", file.Mode), true
		},
		passed: func(n int) string {
			if n == 0 {
				return "no private key files found under the homes"
			}
			return secPlural(n, "private key file is", "private key files are") + " readable by the owner only"
		},
	}.run(in.Facts)
}

func checkDockerConfig(in Input) []Result {
	return secScan{
		pick: func(s *facts.Secrets) facts.SecretScan { return s.DockerConfigs },
		none: "no home folders found",
		judge: func(file facts.SecretFile) (Level, string, bool) {
			if file.Mode.GroupOrOtherReadable() {
				return Warn, fmt.Sprintf("Docker client config (may hold registry credentials) is readable by group or others (mode %s)", file.Mode), true
			}
			return "", "", false
		},
		passed: func(n int) string {
			if n == 0 {
				return "no Docker client config found"
			}
			return secPlural(n, "Docker client config is", "Docker client configs are") + " readable by the owner only"
		},
	}.run(in.Facts)
}

func checkPaaSWorldWritable(in Input) []Result {
	return secScan{
		pick: func(s *facts.Secrets) facts.SecretScan { return s.WorldWritable },
		none: "no Coolify or Dokploy data root found",
		judge: func(file facts.SecretFile) (Level, string, bool) {
			return Fail, fmt.Sprintf("world writable folder under the platform data root (mode %s)", file.Mode), true
		},
		passed: func(int) string { return "no world writable folders under the platform data root" },
	}.run(in.Facts)
}
