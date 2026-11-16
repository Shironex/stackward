package checks

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Shironex/stackward/internal/facts"
)

func checkHostKeys(in Input) []Result {
	s, res := sshFacts(in)
	if s == nil {
		return res
	}
	if len(s.HostKeys) == 0 {
		return One(Unknown, "no host key files found in /etc/ssh", nil)
	}
	var out []Result
	for _, k := range s.HostKeys {
		ev := map[string]any{"type": k.Type, "bits": k.Bits, "configured": k.Configured, "mode": "", "uid": -1}
		level, issues := Pass, []string{}
		raise := func(l Level, msg string) {
			issues = append(issues, msg)
			if l == Fail || (l == Warn && level != Fail) || (l == Unknown && level == Pass) {
				level = l
			}
		}
		if k.Meta == nil {
			raise(Unknown, "could not inspect the private key file: "+k.MetaError)
		} else {
			perm := k.Meta.Mode.Perm()
			ev["mode"], ev["uid"] = fmt.Sprintf("%04o", perm), k.Meta.UID
			switch {
			case perm&0o004 != 0:
				raise(Fail, "private key readable by every user")
			case perm&0o022 != 0:
				raise(Fail, "private key writable by group or others")
			case perm&0o040 != 0:
				raise(Warn, "private key readable by its group")
			}
			if k.Meta.UID > 0 {
				raise(Fail, fmt.Sprintf("private key owned by uid %d, not root", k.Meta.UID))
			}
		}
		typ := k.Type
		if typ == "" {
			typ = keyTypeFromName(k.Path)
		}
		switch {
		case typ == "ssh-dss":
			raise(Warn, "DSA host key (deprecated and disabled in current OpenSSH)")
		case typ == "ssh-rsa" && k.Bits == 0:
			raise(Unknown, "RSA key size unknown (no readable .pub file)")
		case typ == "ssh-rsa" && k.Bits < minHostRSABits:
			raise(Warn, fmt.Sprintf("RSA host key of %d bits (under %d)", k.Bits, minHostRSABits))
		}
		msg := fmt.Sprintf("%s host key is fine", orQ(typ, typ != ""))
		if len(issues) > 0 {
			msg = strings.Join(issues, "; ")
		}
		out = append(out, Result{Subject: "file:" + k.Path, Level: level, Message: msg, Evidence: ev})
	}
	return out
}

func keyTypeFromName(p string) string {
	switch {
	case strings.Contains(p, "_dsa_"):
		return "ssh-dss"
	case strings.Contains(p, "_rsa_"):
		return "ssh-rsa"
	case strings.Contains(p, "_ecdsa_"):
		return "ecdsa"
	case strings.Contains(p, "_ed25519_"):
		return "ssh-ed25519"
	}
	return ""
}

func writableByOthers(m *facts.FileMeta) bool { return m != nil && m.Mode.Perm()&0o022 != 0 }

func modeText(m *facts.FileMeta) string {
	if m == nil {
		return ""
	}
	return fmt.Sprintf("%04o", m.Mode.Perm())
}

func badOwner(m *facts.FileMeta, uid int) bool {
	return m != nil && m.UID >= 0 && m.UID != uid && m.UID != 0
}

func checkSSHFileModes(in Input) []Result {
	s, res := sshFacts(in)
	if s == nil {
		return res
	}
	if s.UsersError != "" {
		return One(Unknown, "could not read /etc/passwd: "+s.UsersError, nil)
	}
	var out []Result
	for _, u := range s.Users {
		ev := map[string]any{"home_mode": modeText(u.HomeMeta), "ssh_dir_mode": modeText(u.SSHDir), "key_files": map[string]string{}}
		subj := "user:" + u.Name
		if u.Error != "" {
			out = append(out, Result{Subject: subj, Level: Unknown, Message: "could not inspect " + u.Error, Evidence: ev})
			continue
		}
		var fails, warns, unknowns []string
		if writableByOthers(u.HomeMeta) {
			fails = append(fails, fmt.Sprintf("home %s is writable by group or others", u.Home))
		}
		if badOwner(u.HomeMeta, u.UID) {
			fails = append(fails, fmt.Sprintf("home %s is owned by uid %d", u.Home, u.HomeMeta.UID))
		}
		if u.SSHDir != nil {
			switch {
			case writableByOthers(u.SSHDir):
				fails = append(fails, "~/.ssh is writable by group or others")
			case u.SSHDir.Mode.Perm() != 0o700:
				warns = append(warns, fmt.Sprintf("~/.ssh is %s, not 0700", modeText(u.SSHDir)))
			}
			if badOwner(u.SSHDir, u.UID) {
				fails = append(fails, fmt.Sprintf("~/.ssh is owned by uid %d", u.SSHDir.UID))
			}
		}
		kfModes := map[string]string{}
		for _, kf := range u.KeyFiles {
			if kf.Meta == nil {
				unknowns = append(unknowns, fmt.Sprintf("%s: %s", kf.Path, kf.Error))
				continue
			}
			kfModes[kf.Path] = modeText(kf.Meta)
			if writableByOthers(kf.Meta) {
				fails = append(fails, kf.Path+" is writable by group or others")
			}
			if badOwner(kf.Meta, u.UID) {
				fails = append(fails, fmt.Sprintf("%s is owned by uid %d", kf.Path, kf.Meta.UID))
			}
		}
		ev["key_files"] = kfModes
		switch {
		case len(fails) > 0:
			out = append(out, Result{Subject: subj, Level: Fail, Message: strings.Join(append(fails, warns...), "; "), Evidence: ev})
		case len(warns) > 0:
			out = append(out, Result{Subject: subj, Level: Warn, Message: strings.Join(warns, "; "), Evidence: ev})
		case len(unknowns) > 0:
			out = append(out, Result{Subject: subj, Level: Unknown, Message: "could not inspect " + strings.Join(unknowns, "; "), Evidence: ev})
		default:
			out = append(out, Result{Subject: subj, Level: Pass, Message: "home, ~/.ssh and authorized keys are private", Evidence: ev})
		}
	}
	if len(out) == 0 {
		return One(Skip, "no account has a ~/.ssh directory or authorized keys file", nil)
	}
	return out
}

func checkAuthorizedKeyTypes(in Input) []Result {
	s, res := sshFacts(in)
	if s == nil {
		return res
	}
	if s.UsersError != "" {
		return One(Unknown, "could not read /etc/passwd: "+s.UsersError, nil)
	}
	rootLogin, rootKnown := s.Value("permitrootlogin")
	var out []Result
	for _, u := range s.Users {
		subj := "user:" + u.Name
		if u.Error != "" {
			out = append(out, Result{Subject: subj, Level: Unknown, Message: "could not inspect " + u.Error,
				Evidence: map[string]any{"keys": 0, "weak": []string{}}})
			continue
		}
		n, weak, unread := 0, []string{}, []string{}
		var fps []string
		for _, kf := range u.KeyFiles {
			if kf.Error != "" {
				unread = append(unread, kf.Path+": "+kf.Error)
			}
			for _, k := range kf.Keys {
				n++
				if k.Fingerprint != "" {
					fps = append(fps, k.Fingerprint)
				}
				switch {
				case k.Type == "ssh-dss":
					weak = append(weak, "ssh-dss")
				case k.Type == "ssh-rsa" && k.Bits < minUserRSABits:
					weak = append(weak, fmt.Sprintf("ssh-rsa %d bits", k.Bits))
				}
			}
		}
		ev := map[string]any{"keys": n, "weak": weak}
		if len(fps) > 0 {
			// Fingerprints, never key material: stackward diff compares
			// them to report a new authorized key.
			sort.Strings(fps)
			ev["fingerprints"] = fps
		}
		var warns []string
		if len(weak) > 0 {
			warns = append(warns, fmt.Sprintf("%s: %s", count(len(weak), "weak key"), strings.Join(weak, ", ")))
		}
		if u.UID == 0 && n > 0 && rootKnown && rootLogin == "no" {
			warns = append(warns, fmt.Sprintf("root has %s while root login is off (stale)", count(n, "authorized key")))
		}
		switch {
		case len(warns) > 0:
			out = append(out, Result{Subject: subj, Level: Warn, Message: strings.Join(warns, "; "), Evidence: ev})
		case len(unread) > 0:
			out = append(out, Result{Subject: subj, Level: Unknown, Message: "could not read " + strings.Join(unread, "; "), Evidence: ev})
		case n > 0:
			out = append(out, Result{Subject: subj, Level: Pass, Message: fmt.Sprintf("%s, none weak", count(n, "authorized key")), Evidence: ev})
		}
	}
	if len(out) == 0 {
		return One(Skip, "no account has authorized keys", nil)
	}
	return out
}

// weakAlgorithms is a short built in list of algorithms ssh-audit and the
// distribution hardening guides remove. Entries ending in "*" are prefixes.
var weakAlgorithms = map[string][]string{
	"kexalgorithms": {
		"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1",
		"gss-gex-sha1-*", "gss-group1-sha1-*", "gss-group14-sha1-*",
	},
	"ciphers": {
		"3des-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc", "blowfish-cbc", "cast128-cbc",
		"arcfour", "arcfour128", "arcfour256", "rijndael-cbc@lysator.liu.se",
	},
	"macs": {
		"hmac-md5*", "hmac-sha1", "hmac-sha1-96", "hmac-sha1-etm@openssh.com", "hmac-sha1-96-etm@openssh.com",
		"umac-64@openssh.com", "umac-64-etm@openssh.com", "hmac-ripemd160*",
	},
}

func isWeak(kind, alg string) bool {
	for _, w := range weakAlgorithms[kind] {
		if p, ok := strings.CutSuffix(w, "*"); ok && strings.HasPrefix(alg, p) || alg == w {
			return true
		}
	}
	return false
}

func checkWeakAlgorithms(in Input) []Result {
	s, res := sshFacts(in)
	if s == nil {
		return res
	}
	weak := map[string][]string{}
	var unknown []string
	for _, kind := range []string{"kexalgorithms", "ciphers", "macs"} {
		weak[kind] = []string{}
		v, ok := s.Value(kind)
		if !ok {
			unknown = append(unknown, kind)
			continue
		}
		list := v
		partial := false
		switch {
		case strings.HasPrefix(v, "+"):
			// Appended to a built in default stackward does not know.
			list, partial = v[1:], true
		case strings.HasPrefix(v, "-") || strings.HasPrefix(v, "^"):
			unknown = append(unknown, kind)
			continue
		}
		for _, alg := range strings.Split(list, ",") {
			if isWeak(kind, alg) {
				weak[kind] = append(weak[kind], alg)
			}
		}
		if partial && len(weak[kind]) == 0 {
			unknown = append(unknown, kind)
		}
	}
	n := len(weak["kexalgorithms"]) + len(weak["ciphers"]) + len(weak["macs"])
	ev := map[string]any{"weak": weak, "unknown": nonNil(unknown), "source": s.Source}
	switch {
	case n > 0:
		var parts []string
		for _, kind := range []string{"kexalgorithms", "ciphers", "macs"} {
			if len(weak[kind]) > 0 {
				parts = append(parts, kind+": "+strings.Join(weak[kind], ","))
			}
		}
		return One(Warn, "weak algorithms enabled: "+strings.Join(parts, "; "), ev)
	case len(unknown) > 0:
		return One(Unknown, fmt.Sprintf("algorithm lists unknown (%s): %s", strings.Join(unknown, ", "), algWhy(s)), ev)
	}
	return One(Pass, "no weak key exchange, cipher or MAC algorithms enabled", ev)
}

func algWhy(s *facts.SSH) string {
	if s.Source == "files" && s.Complete {
		return "the built in defaults depend on the OpenSSH build and sshd -T was unavailable (" + s.SshdTError + ")"
	}
	return why(s)
}
