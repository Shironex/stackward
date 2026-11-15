package plan

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"sort"

	"github.com/Shironex/stackward/internal/checks"
	"github.com/Shironex/stackward/internal/facts"
)

// Risk is how much can go wrong when a step runs.
type Risk string

// Risk classes. Apply treats each differently: safe steps run as they are,
// networking steps can interrupt traffic (a Docker restart) and say so,
// access-critical steps (SSH, firewall, users) run only inside the
// rollback transaction.
const (
	Safe           Risk = "safe"
	Networking     Risk = "networking"
	AccessCritical Risk = "access-critical"
)

// rank orders steps in a plan: the least risky first.
func (r Risk) rank() int {
	switch r {
	case Safe:
		return 0
	case Networking:
		return 1
	}
	return 2
}

// Step is one change a plan proposes. It is plain data: everything a reader,
// `--emit-script` or a later `stackward apply` needs is in it, and it
// carries no code. The code that made it is the Generator registered under
// the same ID.
type Step struct {
	// ID is stable across runs and releases (for example "journald-cap"),
	// so a reader can select steps by name and apply can find the
	// generator that owns the step.
	ID    string `json:"id"`
	Title string `json:"title"`
	// Fixes lists the check ids this step makes pass.
	Fixes []string `json:"fixes"`
	Risk  Risk     `json:"risk"`
	// OptIn steps are only applied when selected by id, never by default.
	OptIn bool `json:"opt_in"`
	// Restarts names the services the step restarts, in order.
	Restarts []string `json:"restarts"`
	// Touches is everything the step changes, as kind:name targets
	// (file:/etc/..., sysctl:net.ipv4..., service:docker,
	// docker-daemon:log-opts). A policy such as the never touched list
	// vetoes steps by these targets.
	Touches []string `json:"touches"`
	// Edits are the file changes, applied in order before Commands.
	Edits []FileEdit `json:"edits"`
	// Commands run after the edits, in order, without a shell.
	Commands []Command `json:"commands"`
	Undo     Undo      `json:"undo"`
	// Notes are caveats the reader must know before running the step.
	Notes []string `json:"notes"`
}

// File edit actions.
const (
	Create  = "create"  // the file must not exist yet
	Replace = "replace" // the file must still hold exactly Old
)

// FileEdit is one file change with the content stackward saw and the
// content it would write. Old is a precondition, not a hint: whoever applies
// the edit (apply, or the emitted script) first checks that the file still
// hashes to OldSHA256 (or is absent for Create) and refuses otherwise, so a
// file that changed since the audit is never overwritten blindly.
type FileEdit struct {
	Path   string `json:"path"`
	Action string `json:"action"`
	// Mode is the permission of a created file ("0644"); a replaced file
	// keeps its own.
	Mode string `json:"mode,omitempty"`
	Old  string `json:"old"`
	New  string `json:"new"`
	// OldSHA256 and NewSHA256 are the SHA-256 of Old and New before
	// redaction ("" for the old side of Create).
	OldSHA256 string `json:"old_sha256,omitempty"`
	NewSHA256 string `json:"new_sha256"`
	// Diff is a unified diff from Old to New.
	Diff string `json:"diff"`
	// Validate, when set, is a command that checks the staged new content
	// before it replaces the file, with the staged file's path appended as
	// the last argument. A failure leaves the file untouched.
	Validate []string `json:"validate,omitempty"`
	// Redacted is true when redaction masked something in Old, New or
	// Diff. The plan then cannot be applied from its own text; the hashes
	// still say what was reviewed.
	Redacted bool `json:"redacted,omitempty"`
}

// Command is one program the step runs, as an argument vector (no shell).
type Command struct {
	Args []string `json:"args"`
	Why  string   `json:"why"`
}

// Undo says how to reverse the step by hand.
type Undo struct {
	Description string    `json:"description"`
	Commands    []Command `json:"commands"`
}

// Input is what generators plan from: the facts (nil when planning from a
// saved report alone) and the check results.
type Input struct {
	Facts   *facts.Facts
	Results []checks.Result
	// Accounts are the owner's choices for the account steps (the plan
	// flags --admin-user, --admin-keys-from and --paas-user). The facts
	// cannot hold them: which account to create is the owner's call.
	Accounts AccountChoices
	// Source is the client address of the SSH session that plans; not
	// valid when unknown (not over SSH, or a saved facts file). A step
	// that bans clients (fail2ban-sshd) never bans it.
	Source netip.Addr
}

// Level returns the worst level among the results of check id (fail, warn,
// unknown, then the rest), and false when the check has no result.
func (in Input) Level(id string) (checks.Level, bool) {
	order := map[checks.Level]int{checks.Fail: 5, checks.Warn: 4, checks.Unknown: 3, checks.Info: 2, checks.Pass: 1, checks.Skip: 0}
	var worst checks.Level
	found := false
	for _, r := range in.Results {
		if r.ID != id {
			continue
		}
		if !found || order[r.Level] > order[worst] {
			worst = r.Level
		}
		found = true
	}
	return worst, found
}

// Skip kinds: why a generator planned no step.
const (
	SkipPassing = "passing" // the checks it fixes already pass or do not apply
	SkipUnknown = "unknown" // the facts or results it needs are missing
	SkipManual  = "manual"  // a step would not fix it; a person has to look
	SkipRefused = "refused" // a policy vetoed the step (never touched list)
)

// Skipped is a generator that planned no step, and why.
type Skipped struct {
	ID     string   `json:"id"`
	Title  string   `json:"title"`
	Fixes  []string `json:"fixes"`
	Kind   string   `json:"kind"`
	Reason string   `json:"reason"`
}

// Outcome is what a generator returns: a step, or a skip reason.
type Outcome struct {
	Step *Step
	Kind string
	// Reason explains a skip in words a reader can act on.
	Reason string
}

// Skip returns an outcome without a step.
func Skip(kind, format string, a ...any) Outcome {
	return Outcome{Kind: kind, Reason: fmt.Sprintf(format, a...)}
}

// Generator plans one step. Plan must be a pure function of its Input: no
// host access, no clock, no network. It fills the step's Edits, Commands,
// Undo, Notes, Restarts and Touches; Build fills ID, Title, Fixes, Risk and
// OptIn from the generator itself, so a plan can never disagree with the
// registry about them.
//
// `stackward apply` looks the generator up by Step.ID and uses Authorize
// and Check; a shared executor (internal/apply) does the edits and runs
// the commands, so a step needs no apply code of its own.
type Generator struct {
	ID    string
	Title string
	Fixes []string
	Risk  Risk
	OptIn bool
	// Order sorts steps of one risk class before their id, for steps
	// that must run after another (create an account, prove it, then
	// lock the default one). Zero for most steps.
	Order int
	Plan  func(in Input) Outcome
	// Authorize refuses a step this generator would not produce: an edit
	// of a path it does not own, content it would not write, a command or
	// undo command it would not run. It re-derives what it can (content
	// from the old side, the drop-in from its keys) instead of trusting
	// the plan file, so a hand edited plan cannot reach anything else.
	Authorize func(s Step) error
	// Pin, when set, refuses a step whose plan states a value that the
	// host contradicts, for example an undo value that is not what the
	// host holds now. Authorize only sees the plan; Pin reads the host.
	Pin func(r Reader, s Step) error
	// Check reads the host and reports whether the step's change is
	// already in place, so a second apply does nothing. It must only read.
	Check func(r Reader, s Step) (applied bool, why string, err error)
	// CommandsOnChange runs the commands only when an edit changed a file
	// in this run (a restart that only loads a new file). Otherwise they
	// run whenever the step is not already applied.
	CommandsOnChange bool
	// SSHD, for an access-critical step, returns the effective sshd
	// settings the step means to leave in place, as `sshd -T` prints them
	// (lowercase key, value): the transaction refuses to keep the change
	// unless `sshd -T` shows every one. It reads the step, never the host.
	SSHD func(s Step) map[string]string
	// Access, for an access-critical step, says which ways in the step
	// closes or narrows besides its sshd settings: public SSH, accounts,
	// keys. The lockout guard (ProveAccess) proves from it and from SSHD
	// that a second way in survives the step. An access-critical step
	// with neither hook is assumed to narrow everything, so it always
	// needs that proof. It reads the step, never the host.
	Access func(s Step) Access
}

// Veto lets a policy refuse a planned step before it reaches the plan
// (NeverTouchedVeto, LockoutVeto). A non empty reason refuses the step.
type Veto func(s Step) (reason string)

var stepID = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

var registry = map[string]Generator{}

// Register adds a generator. It panics on a malformed or duplicate id, so a
// mistake fails every test at start up.
func Register(g Generator) {
	if !stepID.MatchString(g.ID) {
		panic("plan: bad step id " + g.ID)
	}
	if _, dup := registry[g.ID]; dup {
		panic("plan: duplicate step id " + g.ID)
	}
	if g.Plan == nil || len(g.Fixes) == 0 || g.Title == "" {
		panic("plan: step " + g.ID + " needs a title, the checks it fixes and a Plan function")
	}
	if g.Authorize == nil || g.Check == nil {
		panic("plan: step " + g.ID + " needs Authorize and Check, so apply can run it safely")
	}
	switch g.Risk {
	case Safe, Networking, AccessCritical:
	default:
		panic("plan: step " + g.ID + " has no risk class")
	}
	registry[g.ID] = g
}

// Generators returns every registered generator in plan order: risk class
// (safe first), then Order, then id.
func Generators() []Generator {
	out := make([]Generator, 0, len(registry))
	for _, g := range registry {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Risk.rank() != out[j].Risk.rank() {
			return out[i].Risk.rank() < out[j].Risk.rank()
		}
		if out[i].Order != out[j].Order {
			return out[i].Order < out[j].Order
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Lookup returns the generator registered under id.
func Lookup(id string) (Generator, bool) {
	g, ok := registry[id]
	return g, ok
}

// checkGate decides from the results alone whether the checks a generator
// fixes need a step. It returns ok when at least one is warn or fail, and
// otherwise the skip outcome: passing when every one passes, is skipped or
// is info, unknown when any is unknown or missing.
func checkGate(in Input, ids []string) (Outcome, bool) {
	var unknown []string
	for _, id := range ids {
		l, found := in.Level(id)
		switch {
		case !found:
			unknown = append(unknown, id+" has no result")
		case l == checks.Fail || l == checks.Warn:
			return Outcome{}, true
		case l == checks.Unknown:
			unknown = append(unknown, id+" is unknown")
		}
	}
	if len(unknown) > 0 {
		return Skip(SkipUnknown, "%s; nothing to plan until the audit can inspect it", joinAnd(unknown)), false
	}
	if len(ids) == 1 {
		return Skip(SkipPassing, "%s already passes or does not apply", ids[0]), false
	}
	return Skip(SkipPassing, "%s already pass or do not apply", joinAnd(ids)), false
}

// newEdit builds a file edit with its hashes and diff.
func newEdit(path, action, mode, old, nw string) FileEdit {
	e := FileEdit{Path: path, Action: action, Old: old, New: nw, NewSHA256: sha(nw)}
	if action == Create {
		e.Mode = mode
		e.Diff = Diff("/dev/null", "b"+path, "", nw)
	} else {
		e.OldSHA256 = sha(old)
		e.Diff = Diff("a"+path, "b"+path, old, nw)
	}
	return e
}

func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func cmd(why string, args ...string) Command {
	return Command{Args: append([]string{}, args...), Why: why}
}

func joinAnd(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	}
	out := ""
	for i, s := range items {
		switch {
		case i == 0:
			out = s
		case i == len(items)-1:
			out += " and " + s
		default:
			out += ", " + s
		}
	}
	return out
}
