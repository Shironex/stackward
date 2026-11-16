package plan

import "io/fs"

// TreeReader is read access to metadata, beyond Reader, for a Check or Pin
// that judges file modes rather than content (paas-env-perms). The apply
// host implements it; a Reader without it makes such a check judge the
// content it can read only. Paths are host paths, as for Reader.
type TreeReader interface {
	// ReadDir lists the names in directory path, sorted; a missing
	// directory is an empty list.
	ReadDir(path string) ([]string, error)
	// PathInfo describes path without following a final symlink. A
	// missing path is no error: Exists is false.
	PathInfo(path string) (PathInfo, error)
}

// PathInfo is the metadata a TreeReader reports. It never holds content.
type PathInfo struct {
	Exists  bool
	Regular bool
	Dir     bool
	Symlink bool
	// Perm is the permission bits.
	Perm fs.FileMode
	// UID is the owner, -1 when unknown.
	UID int
}
