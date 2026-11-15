//go:build !unix

package apply

import "io/fs"

// apply only runs on Linux; these keep the package building elsewhere.
const noFollow = 0

func owner(fs.FileInfo) (uid, gid int) { return -1, -1 }
