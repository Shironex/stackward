package plan

import (
	"encoding/json"
	"fmt"
	"strings"
)

// docker-log-rotation: json-file log rotation in /etc/docker/daemon.json
// (DKR-031). Docker reads no drop-ins, so the step merges two keys into the
// existing file and keeps every other key and its formatting. It needs a
// Docker restart, so it is a networking step and opt in.

const (
	daemonJSON    = "/etc/docker/daemon.json"
	logMaxSize    = "10m"
	logMaxFile    = "3"
	jsonFileLogDr = "json-file"
)

func init() {
	Register(Generator{
		ID:    "docker-log-rotation",
		Title: "Rotate json-file container logs (max-size " + logMaxSize + ", max-file " + logMaxFile + ") in daemon.json",
		Fixes: []string{"DKR-031"},
		Risk:  Networking,
		OptIn: true,
		Plan:  planDockerLogRotation,

		Authorize:        authorizeDockerLogRotation,
		Check:            checkDockerLogRotation,
		CommandsOnChange: true,
	})
}

var (
	dockerRestart  = []string{"systemctl", "restart", "docker"}
	dockerRemove   = []string{"rm", "-f", daemonJSON}
	dockerValidate = []string{"dockerd", "--validate", "--config-file"}
)

func planDockerLogRotation(in Input) Outcome {
	if out, need := checkGate(in, []string{"DKR-031"}); !need {
		return out
	}
	if in.Facts == nil || in.Facts.Docker == nil || in.Facts.Docker.Daemon == nil {
		return Skip(SkipUnknown, "the Docker daemon facts are missing (planning from a report alone, or the docker collector did not run)")
	}
	dd := in.Facts.Docker.Daemon
	if dd.ConfigError != "" {
		return Skip(SkipManual, "%s cannot be merged safely: %s; fix the file by hand first", daemonJSON, dd.ConfigError)
	}
	if dd.LogDriver != "" && dd.LogDriver != jsonFileLogDr {
		return Skip(SkipPassing, "container logs use the %s driver, not json-file", dd.LogDriver)
	}

	action, old := Create, ""
	if dd.ConfigFound {
		if dd.Content == nil {
			return Skip(SkipUnknown, "the facts do not hold the content of %s (saved by an older stackward, or the file is larger than 64 KiB); audit again with this version", daemonJSON)
		}
		action, old = Replace, *dd.Content
	}
	nw, touched, err := mergeLogRotation(old)
	if err != nil {
		return Skip(SkipManual, "%s cannot be merged safely: %v; fix the file by hand first", daemonJSON, err)
	}
	if nw == old {
		return Skip(SkipPassing, "%s already sets json-file rotation", daemonJSON)
	}

	touches := []string{"file:" + daemonJSON}
	for _, k := range touched {
		touches = append(touches, "docker-daemon:"+k)
	}
	touches = append(touches, "service:docker")
	undo := Undo{
		Description: "Put the previous daemon.json back (its content is the old side of this step's diff; apply also keeps a copy under /var/backups/stackward/<run-id>/) and restart Docker.",
		Commands:    []Command{cmd("load the previous configuration", dockerRestart...)},
	}
	if action == Create {
		undo = Undo{
			Description: "Remove daemon.json, which did not exist before, and restart Docker.",
			Commands: []Command{
				cmd("remove the file this step created", dockerRemove...),
				cmd("load the default configuration", dockerRestart...),
			},
		}
	}
	edit := newEdit(daemonJSON, action, "0644", old, nw)
	// Docker 23 and later can check a configuration file without starting.
	edit.Validate = append([]string{}, dockerValidate...)
	return Outcome{Step: &Step{
		Restarts: []string{"docker"},
		Touches:  touches,
		Edits:    []FileEdit{edit},
		Commands: []Command{
			cmd("load the new log settings", dockerRestart...),
		},
		Undo: undo,
		Notes: []string{
			"Restarting Docker stops and starts every container unless live-restore is on; containers without a restart policy stay stopped.",
			"The limits apply to containers created after the restart; recreate running containers (for example docker compose up -d --force-recreate) to rotate their logs.",
		},
	}}
}

// mergeLogRotation sets log-driver json-file (when unset) and the max-size
// and max-file log options (when unset) in a daemon.json document, keeping
// every other key, the key order and the formatting of untouched values.
// It returns the new document and the top level keys it changed.
func mergeLogRotation(old string) (string, []string, error) {
	obj, err := parseObject([]byte(old))
	if err != nil {
		return "", nil, err
	}
	var touched []string
	if _, ok := obj.get("log-driver"); !ok {
		obj.set("log-driver", json.RawMessage(`"`+jsonFileLogDr+`"`))
		touched = append(touched, "log-driver")
	}
	opts := &jsonObject{values: map[string]json.RawMessage{}, changed: map[string]bool{}}
	if raw, ok := obj.get("log-opts"); ok {
		if opts, err = parseObject(raw); err != nil {
			return "", nil, err
		}
	}
	optsChanged := false
	for _, kv := range [][2]string{{"max-size", logMaxSize}, {"max-file", logMaxFile}} {
		if v, ok := opts.get(kv[0]); !ok || string(v) == `""` {
			opts.set(kv[0], json.RawMessage(`"`+kv[1]+`"`))
			optsChanged = true
		}
	}
	if optsChanged {
		enc, err := opts.encode("  ")
		if err != nil {
			return "", nil, err
		}
		obj.set("log-opts", json.RawMessage(strings.TrimSpace(string(enc))))
		touched = append(touched, "log-opts")
	}
	if len(touched) == 0 {
		return old, nil, nil
	}
	out, err := obj.encode(detectIndent(old))
	if err != nil {
		return "", nil, err
	}
	return string(out), touched, nil
}

// authorizeDockerLogRotation merges the plan's old side again and refuses
// any new content the merge would not produce. The old side itself is
// pinned by old_sha256 and, at apply time, by the file on the host.
func authorizeDockerLogRotation(s Step) error {
	e, err := wantOneEdit(s, daemonJSON, Create, Replace)
	if err != nil {
		return err
	}
	nw, _, err := mergeLogRotation(e.Old)
	if err != nil {
		return fmt.Errorf("%s: the old content cannot be merged: %w", daemonJSON, err)
	}
	if nw == e.Old {
		return fmt.Errorf("%s already sets json-file rotation; the step changes nothing", daemonJSON)
	}
	if err := wantContent(e, nw); err != nil {
		return err
	}
	if err := wantValidate(e, dockerValidate); err != nil {
		return err
	}
	if err := wantRestarts(s, "docker"); err != nil {
		return err
	}
	if err := wantCommands("commands", s.Commands, dockerRestart); err != nil {
		return err
	}
	if e.Action == Create {
		return wantCommands("undo", s.Undo.Commands, dockerRemove, dockerRestart)
	}
	return wantCommands("undo", s.Undo.Commands, dockerRestart)
}

// checkDockerLogRotation: applied when daemon.json holds the planned
// content. Docker is only restarted by a run that changed the file.
func checkDockerLogRotation(r Reader, s Step) (bool, string, error) {
	ok, err := FileHolds(r, daemonJSON, s.Edits[0].NewSHA256)
	if err != nil || !ok {
		return false, "", err
	}
	return true, daemonJSON + " already holds the planned content", nil
}
