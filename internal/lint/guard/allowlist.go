package guard

// Category is one kind of side effect the guard polices.
type Category string

// The side effect categories.
const (
	// FSWrite is anything that creates, changes or removes a file, a
	// directory, a link or file metadata.
	FSWrite Category = "fswrite"
	// Exec is starting another program.
	Exec Category = "exec"
	// Net is dialing, listening or sending a request over the network.
	Net Category = "net"
	// RawSyscall is a raw system call (the Landlock setup).
	RawSyscall Category = "rawsyscall"
)

// Entry allows some categories in one package, or in single files of it.
type Entry struct {
	// Pkg is the package path relative to the module, for example
	// "internal/apply". It matches that package only, not its children.
	Pkg string
	// Files limits the entry to these file base names. Empty means the
	// whole package.
	Files []string
	// Allow lists the categories the entry permits.
	Allow []Category
	// Why says what the code is for. Every entry needs one.
	Why string
}

// DefaultAllowlist is the one place that says which code may write to the
// system, start programs or use the network. Everything else is a finding.
// Test files (_test.go) are never checked. To add an entry, explain it in
// the pull request: each one widens what a read only audit tool may do.
var DefaultAllowlist = []Entry{
	{
		Pkg:   "internal/apply",
		Allow: []Category{FSWrite, Exec},
		Why:   "the apply Host: the only code that changes the audited system, behind plan.Authorize, with backups, the journal and the run lock",
	},
	{
		Pkg:   "internal/apply/applytest",
		Allow: []Category{FSWrite},
		Why:   "fake Host for tests: writes under a temporary root",
	},
	{
		Pkg:   "internal/facts",
		Files: []string{"system.go"},
		Allow: []Category{Exec},
		Why:   "facts.System.Run: how collectors start read only commands, without a shell, with a fixed PATH",
	},
	{
		Pkg:   "internal/facts/dockerapi",
		Files: []string{"client.go"},
		Allow: []Category{Net},
		Why:   "dials the local Docker Unix socket; the client only sends GET requests",
	},
	{
		Pkg:   "internal/probe",
		Allow: []Category{Net},
		Why:   "stackward probe connects to the one host the user named and consented to",
	},
	{
		Pkg:   "internal/provider",
		Files: []string{"http.go"},
		Allow: []Category{Net},
		Why:   "opt in provider firewall audit (--provider): GET requests only, to a fixed list of provider API hosts (Hetzner, OVH), no redirects, no proxy, capped answers, before the sandbox",
	},
	{
		Pkg:   "internal/sandbox",
		Allow: []Category{RawSyscall},
		Why:   "applies the Landlock sandbox with raw system calls",
	},
	{
		Pkg:   "internal/cli",
		Files: []string{"outfile_unix.go", "outfile_other.go"},
		Allow: []Category{FSWrite},
		Why:   "opens the files the user asked for with --out (the report, created 0600) and --textfile (the Prometheus metric, 0644), symlinks refused",
	},
	{
		Pkg:   "internal/docgen",
		Allow: []Category{FSWrite},
		Why:   "build time tool code: writes the generated docs/checks pages",
	},
}
