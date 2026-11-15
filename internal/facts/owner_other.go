//go:build !unix

package facts

import "io/fs"

// fillOwner leaves UID and GID at -1 where the platform has no owners.
func fillOwner(*FileMeta, fs.FileInfo) {}
