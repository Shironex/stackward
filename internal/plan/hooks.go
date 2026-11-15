package plan

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
)

// This file holds what `stackward apply` needs from a generator besides
// Plan: Authorize, which refuses any step the generator would not have
// produced, and Check, which says whether a step is already in place.

// Reader is the read access a Check needs. Paths are host paths
// ("/etc/..."); apply passes its host seam, which may sit under a test
// root. A missing file returns an error matching fs.ErrNotExist.
type Reader interface {
	ReadFile(path string) ([]byte, error)
}

// Authorize runs the generator's Authorize on s, after the checks every
// step shares. Apply calls it on every selected step before it changes
// anything, and undo on every step of a run journal, so a hand edited
// plan or journal can name no other path, content or command than the
// generator's own code would.
func Authorize(s Step) error {
	g, ok := Lookup(s.ID)
	if !ok {
		return fmt.Errorf("step %s is not a known step", s.ID)
	}
	if s.Risk != g.Risk || s.OptIn != g.OptIn {
		return fmt.Errorf("step %s: risk %q (opt in %v) differs from the step's own %q (opt in %v)", s.ID, s.Risk, s.OptIn, g.Risk, g.OptIn)
	}
	if len(s.Fixes) == 0 || !subset(s.Fixes, g.Fixes) {
		return fmt.Errorf("step %s: fixes %v are not among %v", s.ID, s.Fixes, g.Fixes)
	}
	for _, e := range s.Edits {
		if e.Redacted {
			return fmt.Errorf("step %s: the content of %s was redacted in the plan (a secret shaped value was masked), so it cannot be applied from the plan; edit the file by hand", s.ID, e.Path)
		}
		if err := e.validate(); err != nil {
			return fmt.Errorf("step %s: %w", s.ID, err)
		}
	}
	if g.Authorize == nil {
		return fmt.Errorf("step %s cannot be applied: it has no authorization rules", s.ID)
	}
	if err := g.Authorize(s); err != nil {
		return fmt.Errorf("step %s: %w", s.ID, err)
	}
	return nil
}

// Check runs the generator's Check on s.
func Check(r Reader, s Step) (applied bool, why string, err error) {
	g, ok := Lookup(s.ID)
	if !ok || g.Check == nil {
		return false, "", fmt.Errorf("step %s has no check", s.ID)
	}
	if len(s.Edits) == 0 {
		return false, "", fmt.Errorf("step %s edits no file; authorize it first", s.ID)
	}
	return g.Check(r, s)
}

// Pin runs the generator's Pin on s: it ties values the plan only states
// (such as what an undo restores) to the host as it is now. Apply calls it
// after Authorize, for a step that still has to run; a plan that disagrees
// with the host must be made again.
func Pin(r Reader, s Step) error {
	g, ok := Lookup(s.ID)
	if !ok || g.Pin == nil {
		return nil
	}
	return g.Pin(r, s)
}

// SSHDExpect returns the effective sshd settings step s means to leave in
// place (see Generator.SSHD), or nil.
func SSHDExpect(s Step) map[string]string {
	g, ok := Lookup(s.ID)
	if !ok || g.SSHD == nil {
		return nil
	}
	return g.SSHD(s)
}

// RunsCommandsOnChange reports whether step id runs its commands only when
// one of its edits changed a file in this run.
func RunsCommandsOnChange(id string) bool {
	g, ok := Lookup(id)
	return ok && g.CommandsOnChange
}

// SHA256 returns the hex SHA-256 of b, the form old_sha256 and new_sha256
// use.
func SHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// FileHolds reports whether path exists and hashes to sum.
func FileHolds(r Reader, path, sum string) (bool, error) {
	b, err := r.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return SHA256(b) == sum, nil
}

// --- shared authorization helpers

// wantOneEdit returns the step's only edit, refusing any other path,
// action or mode.
func wantOneEdit(s Step, path string, actions ...string) (FileEdit, error) {
	if len(s.Edits) != 1 {
		return FileEdit{}, fmt.Errorf("edits %d files, the step only ever edits %s", len(s.Edits), path)
	}
	e := s.Edits[0]
	if e.Path != path {
		return FileEdit{}, fmt.Errorf("edits %s, the step only ever edits %s", e.Path, path)
	}
	if !slices.Contains(actions, e.Action) {
		return FileEdit{}, fmt.Errorf("%s: action %q is not one the step uses", e.Path, e.Action)
	}
	if e.Action == Create && e.Mode != "0644" {
		return FileEdit{}, fmt.Errorf("%s: mode %q, the step creates it 0644", e.Path, e.Mode)
	}
	return e, nil
}

// wantContent refuses an edit whose new content differs from what the
// generator writes.
func wantContent(e FileEdit, want string) error {
	if e.New != want {
		return fmt.Errorf("%s: the new content is not what the step writes; plan again", e.Path)
	}
	return nil
}

// wantValidate refuses an edit whose validate command differs from want
// (nil for none).
func wantValidate(e FileEdit, want []string) error {
	if !slices.Equal(e.Validate, want) {
		return fmt.Errorf("%s: validate command %q is not the step's %q", e.Path, strings.Join(e.Validate, " "), strings.Join(want, " "))
	}
	return nil
}

// wantCommands refuses a command list whose argument vectors differ from
// want, in order. The why text is free.
func wantCommands(what string, got []Command, want ...[]string) error {
	if len(got) != len(want) {
		return fmt.Errorf("%s: %d commands, the step runs %d", what, len(got), len(want))
	}
	for i, w := range want {
		if !slices.Equal(got[i].Args, w) {
			return fmt.Errorf("%s: command %q is not one the step runs (want %q)", what, strings.Join(got[i].Args, " "), strings.Join(w, " "))
		}
	}
	return nil
}

// wantRestarts refuses a step that names other restarts than the
// generator, so what apply prints before it runs is the truth.
func wantRestarts(s Step, want ...string) error {
	if !slices.Equal(s.Restarts, want) && (len(s.Restarts) != 0 || len(want) != 0) {
		return fmt.Errorf("restarts %v, the step restarts %v", s.Restarts, want)
	}
	return nil
}
