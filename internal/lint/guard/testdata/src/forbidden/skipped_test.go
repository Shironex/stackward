package forbidden

import "os"

// Test files are never checked.
func inTest() { _ = os.WriteFile("a", nil, 0o600) }
