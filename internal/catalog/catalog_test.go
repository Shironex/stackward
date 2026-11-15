package catalog

import (
	"strings"
	"testing"
)

func TestEmbeddedCatalogLoads(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	entries := c.Entries()
	if len(entries) == 0 {
		t.Fatal("catalog is empty")
	}
	for i := 1; i < len(entries); i++ {
		if !Less(entries[i-1].ID, entries[i].ID) {
			t.Errorf("entries out of order: %s before %s", entries[i-1].ID, entries[i].ID)
		}
	}
	e, ok := c.Lookup("SYS-001")
	if !ok || e.Group != "SYS" || e.Title == "" {
		t.Errorf("SYS-001 = %+v, %v", e, ok)
	}
}

func TestParseRejectsBadData(t *testing.T) {
	good := `{"id":"SYS-001","title":"t","severity":"low","rationale":"r","fix":"f"}`
	cases := map[string]struct {
		files map[string]string
		want  string
	}{
		"unknown field":  {map[string]string{"sys.json": `{"group":"SYS","checks":[{"id":"SYS-001","title":"t","severity":"low","rationale":"r","fix":"f","extra":1}]}`}, "unknown field"},
		"unknown group":  {map[string]string{"zzz.json": `{"group":"ZZZ","checks":[]}`}, "unknown group"},
		"wrong file":     {map[string]string{"other.json": `{"group":"SYS","checks":[` + good + `]}`}, "must live in sys.json"},
		"bad id":         {map[string]string{"sys.json": `{"group":"SYS","checks":[{"id":"SYS-1","title":"t","severity":"low","rationale":"r","fix":"f"}]}`}, "bad id"},
		"group mismatch": {map[string]string{"sys.json": `{"group":"SYS","checks":[{"id":"SSH-001","title":"t","severity":"low","rationale":"r","fix":"f"}]}`}, "not in group"},
		"bad severity":   {map[string]string{"sys.json": `{"group":"SYS","checks":[{"id":"SYS-001","title":"t","severity":"huge","rationale":"r","fix":"f"}]}`}, "bad severity"},
		"missing fix":    {map[string]string{"sys.json": `{"group":"SYS","checks":[{"id":"SYS-001","title":"t","severity":"low","rationale":"r"}]}`}, "required"},
		"duplicate":      {map[string]string{"sys.json": `{"group":"SYS","checks":[` + good + `,` + good + `]}`}, "duplicate"},
		"trailing":       {map[string]string{"sys.json": `{"group":"SYS","checks":[]} {}`}, "trailing"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			files := map[string][]byte{}
			for k, v := range tc.files {
				files[k] = []byte(v)
			}
			_, err := parse(files)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.want)
			}
		})
	}
}

func TestOrdering(t *testing.T) {
	if !Less("SYS-002", "SSH-001") {
		t.Error("SYS sorts before SSH by group rank, not alphabet")
	}
	if !Less("DKR-001", "DKR-010") || Less("DKR-010", "DKR-001") {
		t.Error("ids within a group sort by number")
	}
	if GroupRank("NOPE") != len(Groups) {
		t.Error("unknown groups sort last")
	}
	if GroupName("DKR") != "Docker" || GroupOf("PAAS-004") != "PAAS" {
		t.Error("group helpers")
	}
}
