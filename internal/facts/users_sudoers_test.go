package facts

import (
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/sudoersdrop"
)

// Only stackward's own drop-ins keep their text, and only when small.
func TestSudoersContentKeptForOwnDropinsOnly(t *testing.T) {
	own := sudoersdrop.Render(sudoersdrop.AdminUserID, "ops")
	sys := newFakeSystem(map[string]string{
		"/etc/passwd":                        "root:x:0:0:root:/root:/bin/bash\n",
		"/etc/sudoers":                       "root ALL=(ALL:ALL) ALL\n",
		"/etc/sudoers.d/90-stackward-ops":    own,
		"/etc/sudoers.d/90-stackward-big":    "# " + strings.Repeat("x", ownDropinMax) + "\n",
		"/etc/sudoers.d/90-cloud-init-users": "ubuntu ALL=(ALL) NOPASSWD:ALL\n",
	})
	f, err := collectOne(t, usersCollector{}, sys)
	if err != nil && f.Users == nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, s := range f.Users.Sudoers {
		got[s.Path] = s.Content
	}
	if got["/etc/sudoers.d/90-stackward-ops"] != own {
		t.Errorf("own drop-in content = %q", got["/etc/sudoers.d/90-stackward-ops"])
	}
	for _, p := range []string{"/etc/sudoers.d/90-stackward-big", "/etc/sudoers.d/90-cloud-init-users", "/etc/sudoers"} {
		if got[p] != "" {
			t.Errorf("%s kept content", p)
		}
	}
}
