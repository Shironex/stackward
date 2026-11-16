package plan

import (
	"testing"

	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/sudoersdrop"
)

// What the account steps write is what USR-004 recognises as stackward's own.
func TestAccountDropinsAreRecognised(t *testing.T) {
	admin := planAdminUser(Input{Facts: cloudFacts(), Accounts: adminChoices()})
	pf := cloudFacts()
	pf.PaaS.Platforms = []facts.Platform{{Name: facts.PlatformCoolify, Role: facts.RolePanel, DataRoot: "/data/coolify"}}
	paas := planPaaSUser(Input{Facts: pf, Accounts: AccountChoices{PaaS: "coolify"}})
	for id, out := range map[string]Outcome{AdminUserID: admin, PaaSUserID: paas} {
		if out.Step == nil {
			t.Fatalf("%s: no step: %+v", id, out)
		}
		e := out.Step.Edits[0]
		name, ok := sudoersdrop.NameOf(e.Path)
		if !ok {
			t.Fatalf("%s: path %s", id, e.Path)
		}
		if got, ok := sudoersdrop.Writer(name, e.New); !ok || got != id {
			t.Errorf("%s: Writer = %q %v", id, got, ok)
		}
		if e.Mode != sudoersdrop.Mode {
			t.Errorf("%s: mode %s", id, e.Mode)
		}
	}
}
