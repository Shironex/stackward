package checks

import (
	"fmt"
	"path"
	"strings"

	"github.com/Shironex/stackward/internal/facts"
)

// DKR-003: the socket must not be world writable.
func checkSocketMode(in Input) []Result {
	d, early := dockerFacts(in, false)
	if early != nil {
		return early
	}
	s := d.Socket
	if s == nil {
		return One(Unknown, "no Docker socket found at "+d.SocketPath, map[string]any{"path": d.SocketPath})
	}
	ev := map[string]any{"path": d.SocketPath, "perm": s.Perm, "uid": s.UID, "gid": s.GID, "group": s.Group}
	if s.WorldWritable {
		return One(Fail, fmt.Sprintf("%s is world writable (%s): every local user is root", d.SocketPath, s.Perm), ev)
	}
	if d.API != "ok" {
		return apiUnknown(d)
	}
	return One(Pass, fmt.Sprintf("%s is not world writable (%s)", d.SocketPath, s.Perm), ev)
}

// DKR-010: no container gets the Docker socket or a folder holding it.
func checkSocketMounted(in Input) []Result {
	return eachContainer(in, posture(in, func(_ *facts.Docker, c facts.DockerContainer) Result {
		var socket, what []string
		readOnly := false
		for _, m := range c.Mounts {
			if m.Type == "bind" && facts.IsDockerSocketPath(m.Source) {
				socket = append(socket, mountText(m))
				what = append(what, socketMountText(m))
				readOnly = readOnly || m.ReadOnly
			}
		}
		roNote := ""
		if readOnly {
			roNote = "; a read only mount does not stop connecting to a socket"
		}
		role := roleOf(c)
		ev := map[string]any{"container": c.Name, "image": c.Image, "role": role, "socket_mounts": socket, "running": c.Running}
		if len(socket) == 0 {
			return Result{Level: Pass, Message: c.Name + " does not mount the Docker socket", Evidence: ev}
		}
		switch role {
		case roleProxy, rolePaaS, roleSocketProxy:
			return Result{Level: Warn, Message: fmt.Sprintf("%s mounts %s; expected for a %s, but it is root on the host if compromised%s%s",
				c.Name, strings.Join(what, ", "), role, roNote, stateWord(c)), Evidence: ev}
		}
		return Result{Level: Fail, Message: fmt.Sprintf("%s mounts %s: the container controls the host%s%s",
			c.Name, strings.Join(what, ", "), roNote, stateWord(c)), Evidence: ev}
	}))
}

// risky socket proxy flags: POST enables every write, EXEC runs commands.
var socketProxyWriteFlags = []string{"POST", "EXEC"}

func truthy(v string) bool { return v == "1" || v == "true" || v == "yes" }

// DKR-011: a socket proxy must not allow writes.
func checkSocketProxyFlags(in Input) []Result {
	d, early := dockerFacts(in, true)
	if early != nil {
		return early
	}
	var proxies []facts.DockerContainer
	for _, c := range d.Containers {
		if roleOf(c) == roleSocketProxy {
			proxies = append(proxies, c)
		}
	}
	if len(proxies) == 0 {
		return One(Skip, "no Docker socket proxy container found", map[string]any{"socket_proxies": 0})
	}
	isProxy := func(c facts.DockerContainer) bool { return roleOf(c) == roleSocketProxy }
	return eachContainerWhere(in, isProxy, func(_ *facts.Docker, c facts.DockerContainer) Result {
		enabled, writes := socketProxyGrants(c)
		ev := map[string]any{"container": c.Name, "image": c.Image, "enabled": nonNil(enabled), "flags_read": len(c.Flags) > 0}
		if len(writes) > 0 {
			return Result{Level: Warn, Message: fmt.Sprintf("socket proxy %s allows %s", c.Name, strings.Join(writes, " and ")), Evidence: ev}
		}
		if len(c.Flags) == 0 && strings.Contains(c.Image, "wollomatic") {
			return Result{Level: Unknown, Message: "socket proxy " + c.Name + " is configured on its command line, which stackward does not read", Evidence: ev}
		}
		return Result{Level: Pass, Message: "socket proxy " + c.Name + " allows neither POST nor EXEC", Evidence: ev}
	})
}

// sensitiveHostPaths are host paths whose bind mount hands a container the
// host's identity, credentials or kernel interfaces.
var sensitiveHostPaths = map[string]bool{"/": true, "/etc": true, "/root": true, "/home": true, "/proc": true, "/sys": true}

// DKR-012: no bind mount of /, /etc, /root, /home, /proc or /sys.
func checkHostBinds(in Input) []Result {
	return eachContainer(in, posture(in, func(_ *facts.Docker, c facts.DockerContainer) Result {
		var rw, ro []string
		for _, m := range c.Mounts {
			if m.Type != "bind" || m.Source == "" || !sensitiveHostPaths[path.Clean(m.Source)] {
				continue
			}
			if m.ReadOnly {
				ro = append(ro, mountText(m))
			} else {
				rw = append(rw, mountText(m))
			}
		}
		ev := map[string]any{"container": c.Name, "writable": nonNil(rw), "read_only": nonNil(ro)}
		switch {
		case len(rw) > 0:
			return Result{Level: Fail, Message: fmt.Sprintf("%s mounts host %s writable%s", c.Name, strings.Join(rw, ", "), stateWord(c)), Evidence: ev}
		case len(ro) > 0:
			return Result{Level: Warn, Message: fmt.Sprintf("%s mounts host %s read only%s", c.Name, strings.Join(ro, ", "), stateWord(c)), Evidence: ev}
		}
		return Result{Level: Pass, Message: c.Name + " mounts no sensitive host path", Evidence: ev}
	}))
}

// DKR-020: containers should not run as root.
func checkContainerRoot(in Input) []Result {
	return eachContainer(in, posture(in, func(_ *facts.Docker, c facts.DockerContainer) Result {
		root := isRootUser(c.User)
		pub := isPublic(c)
		drops := ""
		if root && c.User == "" {
			drops = dropsTo(c.Image)
		}
		ev := map[string]any{"container": c.Name, "user": c.User, "root": root, "privileged": c.Privileged, "public": pub, "entrypoint_drops_to": drops}
		if !root {
			return Result{Level: Pass, Message: fmt.Sprintf("%s runs as %q", c.Name, c.User), Evidence: ev}
		}
		who := "root"
		if c.User != "" {
			who = fmt.Sprintf("root (%q)", c.User)
		}
		switch {
		case c.Privileged:
			return Result{Level: Fail, Message: fmt.Sprintf("%s runs as %s and privileged%s", c.Name, who, stateWord(c)), Evidence: ev}
		case pub:
			return Result{Level: Fail, Message: fmt.Sprintf("%s runs as %s and is reachable from outside%s", c.Name, who, stateWord(c)), Evidence: ev}
		case drops != "":
			return Result{Level: Info, Message: fmt.Sprintf("%s starts as root, and the %s image entrypoint drops to the %s user; set user: to make it explicit%s",
				c.Name, imageBase(c.Image), drops, stateWord(c)), Evidence: ev}
		}
		return Result{Level: Warn, Message: fmt.Sprintf("%s runs as %s%s", c.Name, who, stateWord(c)), Evidence: ev}
	}))
}

// DKR-021: no privileged containers.
func checkPrivileged(in Input) []Result {
	return eachContainer(in, posture(in, func(_ *facts.Docker, c facts.DockerContainer) Result {
		ev := map[string]any{"container": c.Name, "privileged": c.Privileged}
		if c.Privileged {
			return Result{Level: Fail, Message: c.Name + " is privileged: it has every capability and every device" + stateWord(c), Evidence: ev}
		}
		return Result{Level: Pass, Message: c.Name + " is not privileged", Evidence: ev}
	}))
}

var (
	dangerousCaps = map[string]bool{"SYS_ADMIN": true, "SYS_PTRACE": true, "SYS_MODULE": true, "ALL": true}
	riskyCaps     = map[string]bool{"NET_ADMIN": true, "NET_RAW": true}
)

// DKR-022: no dangerous added capabilities.
func checkCapAdd(in Input) []Result {
	return eachContainer(in, posture(in, func(_ *facts.Docker, c facts.DockerContainer) Result {
		dangerous, risky := []string{}, []string{}
		for _, raw := range c.CapAdd {
			capName := strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(raw)), "CAP_")
			switch {
			case dangerousCaps[capName]:
				dangerous = append(dangerous, capName)
			case riskyCaps[capName]:
				risky = append(risky, capName)
			}
		}
		ev := map[string]any{"container": c.Name, "cap_add": nonNil(c.CapAdd), "dangerous": dangerous, "risky": risky}
		switch {
		case len(dangerous) > 0:
			return Result{Level: Fail, Message: fmt.Sprintf("%s adds %s%s", c.Name, strings.Join(dangerous, ", "), stateWord(c)), Evidence: ev}
		case len(risky) > 0:
			return Result{Level: Warn, Message: fmt.Sprintf("%s adds %s%s", c.Name, strings.Join(risky, ", "), stateWord(c)), Evidence: ev}
		}
		return Result{Level: Pass, Message: c.Name + " adds no dangerous capability", Evidence: ev}
	}))
}

// DKR-023: no host network, PID or IPC namespace.
func checkHostNamespaces(in Input) []Result {
	return eachContainer(in, posture(in, func(_ *facts.Docker, c facts.DockerContainer) Result {
		root := isRootUser(c.User)
		ev := map[string]any{"container": c.Name, "network_mode": c.NetworkMode, "pid_mode": c.PidMode, "ipc_mode": c.IpcMode, "root": root}
		level := Pass
		var why []string
		if c.PidMode == "host" {
			level = worse(level, Fail)
			why = append(why, "host PID namespace")
		}
		if c.NetworkMode == "host" {
			if root {
				level = worse(level, Fail)
				why = append(why, "host network as root")
			} else {
				level = worse(level, Warn)
				why = append(why, "host network")
			}
		}
		if c.IpcMode == "host" {
			level = worse(level, Warn)
			why = append(why, "host IPC namespace")
		}
		if level == Pass {
			return Result{Level: Pass, Message: c.Name + " uses its own network, PID and IPC namespaces", Evidence: ev}
		}
		return Result{Level: level, Message: fmt.Sprintf("%s uses the %s%s", c.Name, strings.Join(why, ", "), stateWord(c)), Evidence: ev}
	}))
}

// DKR-024: no unconfined seccomp or AppArmor; no-new-privileges on public
// containers.
func checkSecurityOpt(in Input) []Result {
	return eachContainer(in, posture(in, func(d *facts.Docker, c facts.DockerContainer) Result {
		var unconfined []string
		nnp := d.Daemon != nil && d.Daemon.NoNewPrivileges
		for _, o := range c.SecurityOpt {
			norm := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(o), ":", "="))
			switch norm {
			case "seccomp=unconfined", "apparmor=unconfined":
				unconfined = append(unconfined, o)
			case "no-new-privileges", "no-new-privileges=true":
				nnp = true
			case "no-new-privileges=false":
				nnp = false
			}
		}
		pub := isPublic(c)
		ev := map[string]any{"container": c.Name, "security_opt": nonNil(c.SecurityOpt), "unconfined": nonNil(unconfined), "no_new_privileges": nnp, "public": pub}
		var why []string
		if len(unconfined) > 0 {
			why = append(why, "runs "+strings.Join(unconfined, ", "))
		}
		if pub && !nnp {
			why = append(why, "is reachable from outside without no-new-privileges")
		}
		if len(why) > 0 {
			return Result{Level: Warn, Message: fmt.Sprintf("%s %s%s", c.Name, strings.Join(why, " and "), stateWord(c)), Evidence: ev}
		}
		return Result{Level: Pass, Message: c.Name + " keeps the default seccomp and AppArmor confinement", Evidence: ev}
	}))
}
