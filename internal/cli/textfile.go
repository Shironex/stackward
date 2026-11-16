package cli

import (
	"fmt"
	"strings"
)

// textfileSuffix is what a --textfile name must end in. node_exporter reads
// only *.prom, so it never sees the file while stackward writes it; the
// caller renames it over the .prom file once the run succeeded, and a failed
// run leaves the previous metric in place. stackward cannot do that rename
// itself: the Landlock sandbox takes the right to create, rename and remove
// files away before the audit runs, and stays that strict.
const textfileSuffix = ".prom.tmp"

// checkTextfileName accepts an empty name (no metric) or one ending in
// textfileSuffix with a base name in front of it.
func checkTextfileName(name string) error {
	if name == "" {
		return nil
	}
	base := name[strings.LastIndexAny(name, `/\`)+1:]
	if !strings.HasSuffix(base, textfileSuffix) || base == textfileSuffix {
		return fmt.Errorf("--textfile must name a temporary file ending in %s, such as DIR/stackward%s, not %q: "+
			"rename it to DIR/stackward.prom after a successful run (as the unit of stackward schedule does), "+
			"so a failed run keeps the previous metric", textfileSuffix, textfileSuffix, name)
	}
	return nil
}
