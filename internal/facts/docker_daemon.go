package facts

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// daemonJSON is the part of daemon.json stackward reads.
type daemonJSON struct {
	Hosts           []string          `json:"hosts"`
	TLSVerify       *bool             `json:"tlsverify"`
	LogDriver       string            `json:"log-driver"`
	LogOpts         map[string]string `json:"log-opts"`
	IPTables        *bool             `json:"iptables"`
	NoNewPrivileges *bool             `json:"no-new-privileges"`
}

func readDaemonConfig(sys System) *DockerDaemon {
	dd := &DockerDaemon{}
	b, err := sys.ReadFile(dockerDaemonJSON)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		dd.ConfigError = fmt.Sprintf("%s: %v", dockerDaemonJSON, err)
	default:
		if len(b) <= MaxDaemonJSONBytes {
			content := string(b)
			dd.Content = &content
		}
		var cfg daemonJSON
		if len(bytes.TrimSpace(b)) == 0 {
			dd.ConfigFound = true
			break
		}
		if err := json.Unmarshal(b, &cfg); err != nil {
			dd.ConfigError = fmt.Sprintf("%s: invalid JSON: %v", dockerDaemonJSON, err)
			break
		}
		dd.ConfigFound = true
		for _, h := range cfg.Hosts {
			dd.Hosts = append(dd.Hosts, DockerHost{Addr: h, Source: "daemon.json"})
		}
		dd.TLSVerify = cfg.TLSVerify != nil && *cfg.TLSVerify
		dd.LogDriver = cfg.LogDriver
		dd.LogMaxSize = cfg.LogOpts["max-size"]
		dd.LogMaxFile = cfg.LogOpts["max-file"]
		dd.IPTables = cfg.IPTables
		dd.NoNewPrivileges = cfg.NoNewPrivileges != nil && *cfg.NoNewPrivileges
	}
	readUnitFlags(sys, dd)
	return dd
}

// readUnitFlags applies the effective ExecStart of docker.service: the
// unit file systemd would load, then drop-ins by name; an empty ExecStart=
// resets the list, so the last one after a reset wins.
func readUnitFlags(sys System, dd *DockerDaemon) {
	var exec, execFrom string
	for _, f := range dockerUnitPaths(sys) {
		b, err := sys.ReadFile(f)
		if err != nil {
			continue
		}
		dd.UnitFiles = append(dd.UnitFiles, f)
		for _, line := range unitLines(b) {
			k, v, ok := strings.Cut(line, "=")
			if !ok || strings.TrimSpace(k) != "ExecStart" {
				continue
			}
			exec, execFrom = strings.TrimSpace(v), f
		}
	}
	if exec == "" {
		return
	}
	applyExecFlags(dd, strings.Fields(exec), execFrom)
}

// dockerUnitPaths lists the files that make up docker.service in the order
// systemd reads them: the unit file, then drop-ins by name.
func dockerUnitPaths(sys System) []string {
	var files []string
	for _, p := range dockerUnitFiles {
		if _, err := sys.ReadFile(p); err == nil {
			files = append(files, p)
			break
		}
	}
	dropIns := map[string]string{} // base name -> path, first dir wins
	for _, dir := range dockerDropInDirs {
		entries, err := sys.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".conf") {
				continue
			}
			if _, taken := dropIns[e.Name()]; !taken {
				dropIns[e.Name()] = path.Join(dir, e.Name())
			}
		}
	}
	names := make([]string, 0, len(dropIns))
	for n := range dropIns {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		files = append(files, dropIns[n])
	}
	return files
}

// applyExecFlags reads the dockerd flags of the effective ExecStart (from
// names the file that set it).
func applyExecFlags(dd *DockerDaemon, args []string, from string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-H" || a == "--host":
			if i+1 < len(args) {
				dd.Hosts = append(dd.Hosts, DockerHost{Addr: args[i+1], Source: from})
				i++
			}
		case strings.HasPrefix(a, "-H="), strings.HasPrefix(a, "--host="):
			_, v, _ := strings.Cut(a, "=")
			dd.Hosts = append(dd.Hosts, DockerHost{Addr: v, Source: from})
		case strings.HasPrefix(a, "-H") && len(a) > 2:
			dd.Hosts = append(dd.Hosts, DockerHost{Addr: a[2:], Source: from})
		case a == "--tlsverify" || a == "--tlsverify=true":
			dd.TLSVerify = true
		case a == "--iptables=false":
			f := false
			dd.IPTables = &f
		case a == "--no-new-privileges" || a == "--no-new-privileges=true":
			dd.NoNewPrivileges = true
		}
	}
}

// unitLines joins backslash continued lines and drops comments.
func unitLines(b []byte) []string {
	var out []string
	var cur strings.Builder
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if cur.Len() == 0 && (strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";")) {
			continue
		}
		if strings.HasSuffix(line, "\\") {
			cur.WriteString(strings.TrimSuffix(line, "\\"))
			cur.WriteString(" ")
			continue
		}
		cur.WriteString(line)
		out = append(out, cur.String())
		cur.Reset()
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}
