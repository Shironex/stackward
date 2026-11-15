package checks

import (
	"fmt"
	"strings"
	"time"

	"github.com/Shironex/stackward/internal/facts"
)

// BAK checks only record backup evidence in v0.1 (paasLevels info and unknown):
// the absence of a local backup proves nothing about off site copies.

func init() {
	Register(Check{ID: "BAK-001", Run: checkPlatformBackups})
	Register(Check{ID: "BAK-002", Run: checkBackupTools})
}

func checkPlatformBackups(in Input) []Result {
	f := in.Facts
	if f.PaaS == nil {
		return []Result{NotInspected(f, "paas")}
	}
	if len(f.PaaS.Platforms) == 0 {
		return One(Skip, "no Coolify or Dokploy installation found", nil)
	}
	var out []Result
	for _, pl := range f.PaaS.Platforms {
		r := Result{Subject: "file:" + pl.DataRoot, Level: Info, Evidence: map[string]any{"platform": pl.Name, "dir": "", "files": 0, "newest": "", "days": -1}}
		b := pl.Backups
		switch {
		case pl.Name == facts.PlatformDokploy:
			r.Message = "Dokploy sends backups to S3 destinations set in the panel; there is no local evidence to read"
		case b == nil:
			r.Message = "no local evidence of platform database backups"
		case !b.Readable:
			r.Evidence["dir"] = b.Dir
			r.Level, r.Message = Unknown, "could not list the platform backup folder: permission denied"
			if !f.IsRoot() {
				r.Message += "; run with sudo for full coverage"
			}
		case b.Files == 0:
			r.Evidence["dir"] = b.Dir
			r.Message = "platform backup folder is empty: no local evidence of platform database backups"
		default:
			r.Evidence["dir"], r.Evidence["files"] = b.Dir, b.Files
			r.Message = fmt.Sprintf("%s in the platform backup folder", secPlural(b.Files, "file", "files"))
			if !b.Newest.IsZero() {
				r.Evidence["newest"] = b.Newest.UTC().Format(time.RFC3339)
				if !f.CollectedAt.IsZero() {
					days := int(f.CollectedAt.Sub(b.Newest).Hours() / 24)
					r.Evidence["days"] = days
					r.Message += fmt.Sprintf(", newest %d days old", days)
				}
			}
			r.Message += "; keep a copy off the server"
		}
		out = append(out, r)
	}
	return out
}

func checkBackupTools(in Input) []Result {
	s := in.Facts.Secrets
	if s == nil {
		return []Result{NotInspected(in.Facts, "secrets")}
	}
	var configs []string
	for _, c := range s.BackupConfigs.Files {
		configs = append(configs, c.Kind+":"+c.Path)
	}
	ev := map[string]any{"tools": paasNonNil(s.BackupTools), "configs": paasNonNil(configs), "denied": paasNonNil(s.BackupConfigs.Denied)}
	if len(s.BackupTools) == 0 && len(configs) == 0 {
		msg := "no restic, borg, borgmatic, kopia or rclone found"
		if len(s.BackupConfigs.Denied) > 0 {
			msg += " (some config paths could not be inspected)"
		}
		return One(Info, msg, ev)
	}
	var parts []string
	if len(s.BackupTools) > 0 {
		parts = append(parts, "tools: "+strings.Join(s.BackupTools, ", "))
	}
	if len(configs) > 0 {
		parts = append(parts, secPlural(len(configs), "config", "configs"))
	}
	return One(Info, "backup tooling found ("+strings.Join(parts, "; ")+"); run a restore test", ev)
}
