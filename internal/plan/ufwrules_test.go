package plan

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// On ufw's template, the step writes the file ufw itself writes when it
// first saves its rules, so `ufw enable` leaves it as it is. The hashes are
// what ufw 0.36.1 (Ubuntu 22.04) and 0.36.2 (Ubuntu 24.04) wrote on the CI
// runners after `ufw reset`, `ufw allow 22/tcp` style rules and
// `ufw enable`.
func TestAddRulesToUFWsTemplateWritesUFWsOwnFormat(t *testing.T) {
	for _, tc := range []struct {
		v6   bool
		add  ufwAdd
		want string
	}{
		{false, ufwAdd{proto: "tcp", port: 22}, "6398538b7da3"},
		{true, ufwAdd{proto: "tcp", port: 22, v6: true}, "0e8688803c21"},
	} {
		got, err := addRules(ufwTemplate(tc.v6), []ufwAdd{tc.add}, tc.v6)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(got))
		if h := hex.EncodeToString(sum[:])[:12]; h != tc.want {
			t.Errorf("v6=%v: sha256 %s, ufw writes %s:\n%s", tc.v6, h, tc.want, got)
		}
		read, err := addedRules(FileEdit{Path: "/etc/ufw/user.rules", Old: ufwTemplate(tc.v6), New: got}, tc.v6, false)
		if err != nil || len(read) != 1 || read[0] != tc.add {
			t.Errorf("v6=%v: read back %+v %v", tc.v6, read, err)
		}
	}
	// The template of the other family, or an edited template, is not
	// taken for it.
	if isUFWTemplate(ufwTemplate(true), false) || isUFWTemplate(ufwTemplate(false)+"\n", false) {
		t.Error("only the exact template counts")
	}
	if _, err := addRules(strings.Replace(ufwTemplate(false), "COMMIT", "-A ufw-user-input -j ACCEPT\nCOMMIT", 1), []ufwAdd{{proto: "tcp", port: 22}}, false); err == nil {
		t.Error("an edited template was accepted")
	}
}

func TestRulesEndRefusesFilesUFWDoesNotWrite(t *testing.T) {
	full := ufwEmptyRules(false)
	for name, bad := range map[string]string{
		"no RULES line":     strings.Replace(full, ufwRulesBegin+"\n", "", 1),
		"two RULES lines":   strings.Replace(full, ufwRulesBegin+"\n", ufwRulesBegin+"\n"+ufwRulesBegin+"\n", 1),
		"no END RULES":      strings.Replace(full, ufwRulesEnd+"\n", "", 1),
		"two END RULES":     strings.Replace(full, ufwRulesEnd+"\n", ufwRulesEnd+"\n\n"+ufwRulesEnd+"\n", 1),
		"no final newline":  strings.TrimSuffix(full, "\n"),
		"END without blank": strings.Replace(full, ufwRulesBegin+"\n\n", ufwRulesBegin+"\n", 1),
	} {
		if _, err := rulesEnd(bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := rulesEnd(full); err != nil {
		t.Errorf("ufw's own empty file: %v", err)
	}
}
