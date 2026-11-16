package facts

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// TestAptSimulateWritesNothing pins the options that keep `apt-get -s
// upgrade` from writing: without them apt takes the dpkg lock, rewrites
// pkgcache.bin after dpkg changed, and replaces /var/log/apt/eipp.log.xz
// with its planner dump on every run (seen on an Ubuntu 24.04 runner under
// strace, with and without the sandbox).
func TestAptSimulateWritesNothing(t *testing.T) {
	for _, opt := range []string{"Debug::NoLocking=true", "Dir::Cache::pkgcache=", "Dir::Log::Planner="} {
		i := slices.Index(aptSimulateArgs, opt)
		if i < 1 || aptSimulateArgs[i-1] != "-o" {
			t.Errorf("aptSimulateArgs %q lacks -o %s", aptSimulateArgs, opt)
		}
	}
	if aptSimulateArgs[0] != "-s" || aptSimulateArgs[len(aptSimulateArgs)-1] != "upgrade" {
		t.Errorf("aptSimulateArgs %q is not a simulated upgrade", aptSimulateArgs)
	}
}

// A fresh cloud image ships /var/lib/apt/lists with only auxfiles (and a
// lock): no index, so apt-get install finds no package.
func TestAptListsEmptyOnAFreshImage(t *testing.T) {
	sys := newFakeSystem(map[string]string{
		"/var/lib/apt/lists/auxfiles/.keep": "",
		"/var/lib/apt/lists/lock":           "",
	})
	l := readAptLists(sys)
	if !l.Read || l.Indexes != 0 || !l.Newest.IsZero() {
		t.Fatalf("fresh image: %+v", l)
	}
	u := &Updates{Apt: true, Lists: l}
	need, why := u.ListsRefresh(time.Unix(1_800_000_000, 0), 72*time.Hour)
	if !need || !strings.Contains(why, "empty") {
		t.Errorf("empty lists: %v %q", need, why)
	}
}

func TestAptListsAge(t *testing.T) {
	sys := newFakeSystem(map[string]string{
		"/var/lib/apt/lists/deb.debian.org_debian_dists_bookworm_InRelease":                      "",
		"/var/lib/apt/lists/deb.debian.org_debian_dists_bookworm_main_binary-amd64_Packages.lz4": "",
		"/var/lib/apt/lists/deb.debian.org_debian_dists_bookworm_main_i18n_Translation-en":       "",
		"/var/lib/apt/lists/partial/.keep":                                                       "",
	})
	updated := time.Unix(1_800_000_000, 0).UTC()
	for _, f := range sys.files {
		f.ModTime = updated
	}
	l := readAptLists(sys)
	if !l.Read || l.Indexes != 1 || !l.Newest.Equal(updated) {
		t.Fatalf("lists: %+v", l)
	}
	u := &Updates{Apt: true, Lists: l}
	if need, why := u.ListsRefresh(updated.Add(24*time.Hour), 72*time.Hour); need {
		t.Errorf("a day old: %q", why)
	}
	need, why := u.ListsRefresh(updated.Add(10*24*time.Hour), 72*time.Hour)
	if !need || !strings.Contains(why, "10 days ago") {
		t.Errorf("ten days old: %v %q", need, why)
	}
	// The update-success stamp is a newer sign of an update.
	u.ListsUpdated = updated.Add(9 * 24 * time.Hour)
	if need, why := u.ListsRefresh(updated.Add(10*24*time.Hour), 72*time.Hour); need {
		t.Errorf("updated a day ago by the stamp: %q", why)
	}
	// Lists that were not read, or no apt at all, ask for nothing.
	for _, u := range []*Updates{nil, {Apt: true}, {Apt: true, Lists: &AptLists{Error: "permission denied"}}, {Lists: &AptLists{Read: true}}} {
		if need, _ := u.ListsRefresh(updated, 72*time.Hour); need {
			t.Errorf("%+v asks for a refresh", u)
		}
	}
}
