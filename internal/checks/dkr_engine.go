package checks

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Shironex/stackward/internal/facts"
)

// DKR-031: json-file logs need a max-size or they grow without limit.
func checkLogRotation(in Input) []Result {
	d, early := dockerFacts(in, true)
	if early != nil {
		return early
	}
	dd := d.Daemon
	if dd == nil {
		return One(Unknown, "the daemon config was not read", map[string]any{"config_found": false})
	}
	driver := dd.LogDriver
	if driver == "" && d.Info != nil {
		driver = d.Info.LoggingDriver
	}
	if driver == "" {
		driver = "json-file"
	}
	ev := map[string]any{"driver": driver, "max_size": dd.LogMaxSize, "max_file": dd.LogMaxFile, "config_found": dd.ConfigFound}
	if dd.ConfigError != "" {
		return One(Unknown, "could not read daemon.json: "+dd.ConfigError, ev)
	}
	if driver == "json-file" && dd.LogMaxSize == "" {
		return One(Warn, "json-file container logs have no max-size and grow until the disk is full", ev)
	}
	if driver == "json-file" {
		return One(Pass, "json-file container logs rotate at "+dd.LogMaxSize, ev)
	}
	return One(Pass, "container logs use the "+driver+" driver", ev)
}

// DKR-032: infrastructure containers should run a pinned image.
func checkInfraTags(in Input) []Result {
	d, early := dockerFacts(in, true)
	if early != nil {
		return early
	}
	isInfra := func(c facts.DockerContainer) bool {
		switch roleOf(c) {
		case roleProxy, roleTunnel, roleCrowdSec:
			return true
		}
		return false
	}
	found := false
	for _, c := range d.Containers {
		found = found || isInfra(c)
	}
	if !found {
		return One(Skip, "no proxy, tunnel or CrowdSec container found", map[string]any{"infra_containers": 0})
	}
	return eachContainerWhere(in, isInfra, func(_ *facts.Docker, c facts.DockerContainer) Result {
		_, tag, digest := imageRef(c.Image)
		ev := map[string]any{"container": c.Name, "image": c.Image, "role": roleOf(c), "tag": tag, "digest": digest != ""}
		switch {
		case digest != "":
			return Result{Level: Pass, Message: c.Name + " runs an image pinned by digest", Evidence: ev}
		case tag == "" || tag == "latest":
			return Result{Level: Warn, Message: fmt.Sprintf("%s runs %s, which floats (latest)", c.Name, c.Image), Evidence: ev}
		}
		return Result{Level: Pass, Message: fmt.Sprintf("%s runs a pinned tag (%s)", c.Name, tag), Evidence: ev}
	})
}

// DKR-033: Docker should manage the firewall rules for its networks.
func checkIPTables(in Input) []Result {
	d, early := dockerFacts(in, true)
	if early != nil {
		return early
	}
	dd := d.Daemon
	if dd == nil {
		return One(Unknown, "the daemon config was not read", map[string]any{"iptables": nil, "config_found": false})
	}
	ev := map[string]any{"iptables": dd.IPTables == nil || *dd.IPTables, "config_found": dd.ConfigFound}
	if dd.IPTables != nil && !*dd.IPTables {
		return One(Warn, "Docker does not manage the firewall (iptables: false): published ports may be wide open or silently broken", ev)
	}
	if dd.ConfigError != "" {
		return One(Unknown, "could not read daemon.json: "+dd.ConfigError, ev)
	}
	return One(Pass, "Docker manages the firewall rules for its networks", ev)
}

// engineSupport is when each Docker Engine release line leaves upstream
// support (endoflife.date "docker-engine", as of 2026-11-15). A line not
// listed and newer than every listed one is assumed supported; anything
// older than 20.10 is out of support.
var engineSupport = map[string]string{
	"29": "", // supported
	"28": "2026-05-13", "27": "2025-05-03", "26.1": "2025-02-17", "26.0": "2024-06-08",
	"25.0": "2026-12-04", "24.0": "2024-06-08", "23.0": "2025-05-19", "20.10": "2023-12-10",
}

const engineSupportAsOf = "2026-11-15"

// engineCycle maps a version to its release line: the major from 27 on,
// major.minor before.
func engineCycle(v string) (cycle string, major, minor int, ok bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return "", 0, 0, false
	}
	var err error
	if major, err = strconv.Atoi(parts[0]); err != nil {
		return "", 0, 0, false
	}
	if minor, err = strconv.Atoi(strings.TrimLeftFunc(parts[1], func(r rune) bool { return r < '0' || r > '9' })); err != nil {
		minor = 0
	}
	if major >= 27 {
		return strconv.Itoa(major), major, minor, true
	}
	return fmt.Sprintf("%d.%d", major, minor), major, minor, true
}

// DKR-034: the Docker Engine release line is still supported upstream.
func checkEngineSupport(in Input) []Result {
	d, early := dockerFacts(in, true)
	if early != nil {
		return early
	}
	if d.Version == nil || d.Version.Version == "" {
		return One(Unknown, "the Docker API did not report a version", map[string]any{"version": ""})
	}
	v := d.Version.Version
	cycle, major, _, ok := engineCycle(v)
	ev := map[string]any{"version": v, "cycle": cycle, "eol": "", "table_as_of": engineSupportAsOf}
	if !ok {
		return One(Unknown, "cannot read Docker Engine version "+v, ev)
	}
	eol, known := engineSupport[cycle]
	switch {
	case !known && major > 29:
		return One(Pass, "Docker Engine "+v+" is newer than stackward's support table", ev)
	case !known:
		return One(Warn, "Docker Engine "+v+" is out of upstream support", ev)
	case eol == "":
		return One(Pass, "Docker Engine "+cycle+" is supported upstream", ev)
	}
	ev["eol"] = eol
	end, err := time.Parse("2006-01-02", eol)
	if err != nil || in.Facts.CollectedAt.IsZero() {
		return One(Unknown, "cannot compare the support date", ev)
	}
	if !in.Facts.CollectedAt.Before(end) {
		return One(Warn, fmt.Sprintf("Docker Engine %s left upstream support on %s", cycle, eol), ev)
	}
	return One(Pass, fmt.Sprintf("Docker Engine %s is supported upstream until %s", cycle, eol), ev)
}
