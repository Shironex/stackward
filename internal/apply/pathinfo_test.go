package apply_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Shironex/stackward/internal/apply"
	"github.com/Shironex/stackward/internal/apply/applytest"
	"github.com/Shironex/stackward/internal/plan"
)

func TestHostPathInfoReadsMetadataOnly(t *testing.T) {
	root := t.TempDir()
	applytest.Write(t, root, "/data/x/.env", "SECRET=1\n", 0o640)
	if err := os.Symlink("/etc/shadow", filepath.Join(root, "data/x/link")); err != nil {
		t.Fatal(err)
	}
	tr, ok := apply.NewHost(root, nil).(plan.TreeReader)
	if !ok {
		t.Fatal("the host is not a plan.TreeReader")
	}
	f, err := tr.PathInfo("/data/x/.env")
	if err != nil || !f.Exists || !f.Regular || f.Dir || f.Perm != 0o640 || f.UID != os.Getuid() {
		t.Errorf("file: %+v %v", f, err)
	}
	d, err := tr.PathInfo("/data/x")
	if err != nil || !d.Dir || d.Regular {
		t.Errorf("dir: %+v %v", d, err)
	}
	l, err := tr.PathInfo("/data/x/link")
	if err != nil || !l.Symlink || l.Regular {
		t.Errorf("link is followed: %+v %v", l, err)
	}
	if m, err := tr.PathInfo("/data/missing"); err != nil || m.Exists {
		t.Errorf("missing: %+v %v", m, err)
	}
	if _, err := tr.PathInfo("/data/../etc"); err == nil {
		t.Error("an unclean path is accepted")
	}
	if names, err := tr.ReadDir("/data/x"); err != nil || len(names) != 2 {
		t.Errorf("readdir %v %v", names, err)
	}
}
