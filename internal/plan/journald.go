package plan

// journald-cap: a journald drop-in that caps the persistent journal
// (LOG-001). The main journald.conf is never edited.

const (
	journaldDropin = "/etc/systemd/journald.conf.d/90-stackward-journal-cap.conf"
	journalCap     = "1G"
)

func init() {
	Register(Generator{
		ID:    "journald-cap",
		Title: "Cap the persistent journal at " + journalCap + " with a journald drop-in",
		Fixes: []string{"LOG-001"},
		Risk:  Safe,
		Plan:  planJournaldCap,

		Authorize:        authorizeJournaldCap,
		Check:            checkJournaldCap,
		CommandsOnChange: true,
	})
}

// journaldContent is the whole drop-in. It does not depend on the host,
// so Authorize can compare a plan against it byte for byte.
const journaldContent = "# Written by stackward: plan step journald-cap, fixes LOG-001.\n" +
	"# Caps the persistent journal. Remove this file and restart\n" +
	"# systemd-journald to undo.\n" +
	"[Journal]\n" +
	"SystemMaxUse=" + journalCap + "\n"

var (
	journaldRestart = []string{"systemctl", "restart", "systemd-journald"}
	journaldRemove  = []string{"rm", "-f", journaldDropin}
)

func planJournaldCap(in Input) Outcome {
	if out, need := checkGate(in, []string{"LOG-001"}); !need {
		return out
	}
	if in.Facts == nil || in.Facts.Journal == nil {
		return Skip(SkipUnknown, "the journald facts are missing (planning from a report alone, or the journal collector did not run)")
	}
	j := in.Facts.Journal
	if j.SystemMaxUse != "" {
		return Skip(SkipPassing, "SystemMaxUse is already set to %s", j.SystemMaxUse)
	}
	if !j.Persistent {
		return Skip(SkipManual, "the journal is volatile, so SystemMaxUse does not apply; make it persistent first (LOG-005)")
	}
	return Outcome{Step: &Step{
		Restarts: []string{"systemd-journald"},
		Touches:  []string{"file:" + journaldDropin, "service:systemd-journald"},
		Edits:    []FileEdit{newEdit(journaldDropin, Create, "0644", "", journaldContent)},
		Commands: []Command{
			cmd("load the new limit; journald vacuums older files down to it", journaldRestart...),
		},
		Undo: Undo{
			Description: "Remove the drop-in and restart systemd-journald; the journal may then grow to the default limit again. Journal files already vacuumed are gone.",
			Commands: []Command{
				cmd("remove the drop-in", journaldRemove...),
				cmd("load the default limit", journaldRestart...),
			},
		},
		Notes: []string{
			"Restarting systemd-journald drops no running service; journal files older than the " + journalCap + " limit are deleted.",
		},
	}}
}

func authorizeJournaldCap(s Step) error {
	e, err := wantOneEdit(s, journaldDropin, Create)
	if err != nil {
		return err
	}
	if err := wantContent(e, journaldContent); err != nil {
		return err
	}
	if err := wantValidate(e, nil); err != nil {
		return err
	}
	if err := wantRestarts(s, "systemd-journald"); err != nil {
		return err
	}
	if err := wantCommands("commands", s.Commands, journaldRestart); err != nil {
		return err
	}
	return wantCommands("undo", s.Undo.Commands, journaldRemove, journaldRestart)
}

// checkJournaldCap: applied when the drop-in holds exactly the planned
// content. The restart follows the write in the same run.
func checkJournaldCap(r Reader, s Step) (bool, string, error) {
	ok, err := FileHolds(r, journaldDropin, s.Edits[0].NewSHA256)
	if err != nil || !ok {
		return false, "", err
	}
	return true, journaldDropin + " already holds the planned content", nil
}
