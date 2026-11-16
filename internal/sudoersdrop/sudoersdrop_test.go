package sudoersdrop

import "testing"

func TestPathAndName(t *testing.T) {
	if got := Path("ops"); got != "/etc/sudoers.d/90-stackward-ops" {
		t.Errorf("Path = %s", got)
	}
	if n, ok := NameOf(Path("ops")); !ok || n != "ops" {
		t.Errorf("NameOf = %q %v", n, ok)
	}
	for _, p := range []string{"/etc/sudoers.d/90-stackward-", "/etc/sudoers.d/90-cloud-init-users", "/etc/sudoers"} {
		if _, ok := NameOf(p); ok {
			t.Errorf("NameOf(%s) accepted", p)
		}
	}
}

func TestWriter(t *testing.T) {
	for _, id := range []string{AdminUserID, PaaSUserID} {
		if got, ok := Writer("ops", Render(id, "ops")); !ok || got != id {
			t.Errorf("Writer(%s) = %q %v", id, got, ok)
		}
	}
	if _, ok := Writer("ops", Render(AdminUserID, "other")); ok {
		t.Error("another name accepted")
	}
	if _, ok := Writer("ops", Render(AdminUserID, "ops")+"x ALL=(ALL) NOPASSWD: ALL\n"); ok {
		t.Error("extra line accepted")
	}
}
