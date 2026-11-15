package apply_test

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Shironex/stackward/internal/apply"
	"github.com/Shironex/stackward/internal/apply/applytest"
	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/plan"
	"github.com/Shironex/stackward/internal/redact"
	"github.com/Shironex/stackward/internal/schemacheck"
)

var update = flag.Bool("update", false, "rewrite the golden journal")

func undoOpts(h apply.Host) apply.UndoOptions {
	return apply.UndoOptions{Host: h, Now: func() time.Time { return fixedNow.Add(time.Hour) }}
}

func TestUndoRestoresEveryFileAndRunsTheUndoCommands(t *testing.T) {
	root := t.TempDir()
	p := applytest.FixturePlan(t, "plan-host-settings-fix")
	applytest.Seed(t, root, p)
	if err := os.Chmod(filepath.Join(root, daemonPath), 0o640); err != nil {
		t.Fatal(err)
	}
	h, r := applytest.NewHost(root)
	steps := mustSelect(t, p, []string{"journald-cap", "docker-log-rotation"}, false)
	j, err := run(t, h, steps, "20260301T120000Z-111111")
	if err != nil {
		t.Fatal(err)
	}
	old := applytest.Step(t, p, "docker-log-rotation").Edits[0].Old

	r.Reset()
	loaded, err := apply.LoadJournal(h, j.RunID)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := apply.Undo(context.Background(), loaded, undoOpts(h))
	if err != nil || !changed {
		t.Fatalf("undo: %v %v", changed, err)
	}
	if got, _ := applytest.Read(t, root, daemonPath); got != old {
		t.Errorf("daemon.json not restored: %q", got)
	}
	if m := mode(t, root, daemonPath); m != 0o640 {
		t.Errorf("restored mode %o", m)
	}
	if _, ok := applytest.Read(t, root, journaldPath); ok {
		t.Error("the created drop-in is still there")
	}
	if got, _ := applytest.Read(t, root, daemonPath+".orig"); got != old {
		t.Error("undo touched .orig")
	}
	// Newest first: Docker, then journald; no rm (files are handled natively).
	want := [][]string{{"systemctl", "restart", "docker"}, {"systemctl", "restart", "systemd-journald"}}
	if !slices.EqualFunc(r.Calls(), want, slices.Equal) {
		t.Errorf("undo commands %v, want %v", r.Calls(), want)
	}
	saved, _ := apply.LoadJournal(h, j.RunID)
	if saved.Status != apply.RunUndone || saved.UndoneAt == "" {
		t.Errorf("journal after undo: %s %s", saved.Status, saved.UndoneAt)
	}
	if _, err := apply.Undo(context.Background(), saved, undoOpts(h)); err == nil || !strings.Contains(err.Error(), "already undone") {
		t.Errorf("second undo: %v", err)
	}
}

func TestUndoRefusesAFileChangedAfterTheRun(t *testing.T) {
	root := t.TempDir()
	p := applytest.FixturePlan(t, "plan-host-settings-fix")
	applytest.Seed(t, root, p)
	h, r := applytest.NewHost(root)
	j, err := run(t, h, mustSelect(t, p, []string{"journald-cap", "docker-log-rotation"}, false), "20260301T120000Z-222222")
	if err != nil {
		t.Fatal(err)
	}
	applytest.Write(t, root, daemonPath, "{\"someone\": \"else\"}\n", 0o644)
	r.Reset()
	changed, err := apply.Undo(context.Background(), j, undoOpts(h))
	if err == nil || changed || !strings.Contains(err.Error(), "changed after run") {
		t.Fatalf("undo: %v %v", changed, err)
	}
	if _, ok := applytest.Read(t, root, journaldPath); !ok {
		t.Error("a refused undo still removed a file")
	}
	if len(r.Calls()) != 0 {
		t.Errorf("a refused undo ran %v", r.Calls())
	}
}

func TestUndoRefusesATamperedJournal(t *testing.T) {
	root := t.TempDir()
	p := applytest.FixturePlan(t, "plan-host-settings-fix")
	applytest.Seed(t, root, p)
	h, r := applytest.NewHost(root)
	j, err := run(t, h, mustSelect(t, p, []string{"journald-cap"}, false), "20260301T120000Z-333333")
	if err != nil {
		t.Fatal(err)
	}
	j.Steps[0].Step.Undo.Commands[1].Args = []string{"systemctl", "stop", "ssh"}
	r.Reset()
	if _, err := apply.Undo(context.Background(), j, undoOpts(h)); err == nil || !strings.Contains(err.Error(), "refusing") {
		t.Fatalf("undo: %v", err)
	}
	if len(r.Calls()) != 0 {
		t.Errorf("ran %v", r.Calls())
	}
	if !apply.ValidRunID(j.RunID) || apply.ValidRunID("../../etc") {
		t.Error("run id check")
	}
	if _, err := apply.LoadJournal(h, "../../etc/passwd"); err == nil {
		t.Error("a path as run id was accepted")
	}
}

// The journal of a fixed run, byte for byte, and valid against
// schema/journal.v1.json. Regenerate with go test ./internal/apply/ -update.
func TestGoldenJournal(t *testing.T) {
	root := t.TempDir()
	p := applytest.FixturePlan(t, "plan-host-settings-fix")
	applytest.Seed(t, root, p)
	h, _ := applytest.NewHost(root)
	steps := mustSelect(t, p, []string{"journald-cap", "sysctl-hardening", "docker-log-rotation"}, false)
	// sysctl-hardening is already in place: the journal says so.
	s := applytest.Step(t, p, "sysctl-hardening")
	applytest.Write(t, root, sysctlPath, s.Edits[0].New, 0o644)
	for _, k := range []string{"net/ipv4/conf/all/rp_filter", "net/ipv4/conf/all/accept_redirects", "kernel/kptr_restrict"} {
		v := map[string]string{"net/ipv4/conf/all/rp_filter": "2", "net/ipv4/conf/all/accept_redirects": "0", "kernel/kptr_restrict": "1"}[k]
		applytest.Write(t, root, "/proc/sys/"+k, v+"\n", 0o644)
	}
	if _, err := run(t, h, steps, "20260301T120000Z-abcdef"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(root, apply.JournalPath("20260301T120000Z-abcdef")))
	if err != nil {
		t.Fatal(err)
	}
	b = normalizeJournal(t, b)
	schema, err := os.ReadFile(applytest.RepoPath("schema/journal.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range schemacheck.Validate(schema, b) {
		t.Errorf("journal does not match the schema: %v", e)
	}
	golden := filepath.Join("testdata", "journal.golden.json")
	if *update {
		if err := os.MkdirAll("testdata", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("%v (run with -update)", err)
	}
	if !bytes.Equal(b, want) {
		t.Errorf("journal differs from %s (run with -update and review):\n%s", golden, b)
	}
}

// normalizeJournal replaces what differs between machines: the owner of
// a replaced file (the test user) and the random name of the staged file.
func normalizeJournal(t *testing.T, b []byte) []byte {
	t.Helper()
	var j apply.Journal
	if err := json.Unmarshal(b, &j); err != nil {
		t.Fatal(err)
	}
	for i := range j.Steps {
		for k := range j.Steps[i].Files {
			if f := &j.Steps[i].Files[k]; f.UID >= 0 {
				f.UID, f.GID = 0, 0
			}
		}
		for k := range j.Steps[i].Commands {
			if c := &j.Steps[i].Commands[k]; c.Kind == apply.KindValidate {
				c.Args[len(c.Args)-1] = "/etc/docker/.daemon.json.stackward-STAGED"
			}
		}
	}
	out, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}

// A plan written by stackward never reaches apply with secret shaped
// content (redacted edits are refused). A hand made one can; the journal
// still masks it.
func TestJournalRedactsSecretShapedValues(t *testing.T) {
	// Assembled at run time so secret scanners do not flag the source.
	secret := "https://mirror-user:" + strings.Repeat("x", 6) + "-not-real@mirror.example.com"
	old := "{\n  \"registry-mirrors\": [\"" + secret + "\"]\n}\n"
	g, _ := plan.Lookup("docker-log-rotation")
	in := plan.Input{
		Facts:   &facts.Facts{Docker: &facts.Docker{Daemon: &facts.DockerDaemon{ConfigFound: true, Content: &old}}},
		Results: []checks.Result{{ID: "DKR-031", Subject: "host", Level: checks.Warn}},
	}
	out := g.Plan(in)
	if out.Step == nil {
		t.Fatalf("no step: %s", out.Reason)
	}
	s := *out.Step
	s.ID, s.Risk, s.OptIn, s.Fixes = g.ID, g.Risk, g.OptIn, g.Fixes

	root := t.TempDir()
	applytest.Write(t, root, daemonPath, old, 0o644)
	h, _ := applytest.NewHost(root)
	j, err := run(t, h, []plan.Step{s}, "20260301T120000Z-444444")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(root, apply.JournalPath(j.RunID)))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b, []byte("xxxxxx-not-real")) {
		t.Errorf("the journal holds the secret:\n%s", b)
	}
	if !bytes.Contains(b, []byte(redact.Mask)) {
		t.Error("the journal shows no mask")
	}
	// The file on the host keeps the real value.
	if got, _ := applytest.Read(t, root, daemonPath); !strings.Contains(got, secret) {
		t.Errorf("daemon.json lost the mirror: %q", got)
	}
}
