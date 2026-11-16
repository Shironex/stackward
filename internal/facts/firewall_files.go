package facts

// The UFW files a firewall plan step edits. A step replaces a file only
// when it holds exactly what the audit saw, so the audit keeps their text.

// UFW file paths.
const (
	UFWDefaultPath    = ufwDefaultPath
	UFWConfPath       = ufwConfPath
	UFWUserRulesPath  = ufwUserRules
	UFWUser6RulesPath = ufwUser6Rules
	UFWAfterRulesPath = ufwAfterRules
)

// MaxUFWFileBytes caps each file kept in UFW.Files. Stock files are a few
// kilobytes; a longer one is left out, and a step that needs it is then
// skipped as unknown.
const MaxUFWFileBytes = 256 << 10

// UFWFilePaths are the files kept in UFW.Files.
var UFWFilePaths = []string{UFWDefaultPath, UFWConfPath, UFWUserRulesPath, UFWUser6RulesPath, UFWAfterRulesPath}

// readUFWFiles reads the files of UFWFilePaths that are readable and
// small enough; nil when none is.
func readUFWFiles(sys System) map[string]string {
	var out map[string]string
	for _, p := range UFWFilePaths {
		b, err := sys.ReadFile(p)
		if err != nil || len(b) > MaxUFWFileBytes {
			continue
		}
		if out == nil {
			out = map[string]string{}
		}
		out[p] = string(b)
	}
	return out
}
