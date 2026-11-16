package checks

import (
	"strings"
	"testing"

	"github.com/Shironex/stackward/internal/facts"
	"github.com/Shironex/stackward/internal/sudoersdrop"
)

func ownDropin(step, name string) facts.Sudoers {
	return facts.Sudoers{
		Path: sudoersdrop.Path(name), Perm: sudoersdrop.Perm, Readable: true,
		Content:    sudoersdrop.Render(step, name),
		NoPasswd:   []facts.SudoRule{{Who: name, Line: 4}},
		Principals: []string{name},
	}
}

func TestUSR004OwnDropin(t *testing.T) {
	mod := func(f func(*facts.Sudoers)) facts.Sudoers {
		s := ownDropin(sudoersdrop.AdminUserID, "ops")
		f(&s)
		return s
	}
	cases := []struct {
		name string
		in   []facts.Sudoers
		want []Level
	}{
		{"admin-user drop-in", []facts.Sudoers{ownDropin(sudoersdrop.AdminUserID, "ops")}, []Level{Info}},
		{"paas-user drop-in", []facts.Sudoers{ownDropin(sudoersdrop.PaaSUserID, "coolify")}, []Level{Info}},
		{"extra line", []facts.Sudoers{mod(func(s *facts.Sudoers) { s.Content += "evil ALL=(ALL) NOPASSWD: ALL\n" })}, []Level{Warn}},
		{"no trailing newline", []facts.Sudoers{mod(func(s *facts.Sudoers) { s.Content = strings.TrimSuffix(s.Content, "\n") })}, []Level{Warn}},
		{"content of another name", []facts.Sudoers{mod(func(s *facts.Sudoers) { s.Content = sudoersdrop.Render(sudoersdrop.AdminUserID, "mallory") })}, []Level{Warn}},
		{"content not kept", []facts.Sudoers{mod(func(s *facts.Sudoers) { s.Content = "" })}, []Level{Warn}},
		{"other path", []facts.Sudoers{mod(func(s *facts.Sudoers) { s.Path = "/etc/sudoers.d/90-other-ops" })}, []Level{Warn}},
		{"wrong uid", []facts.Sudoers{mod(func(s *facts.Sudoers) { s.UID = 1000 })}, []Level{Warn}},
		{"wrong gid", []facts.Sudoers{mod(func(s *facts.Sudoers) { s.GID = 1000 })}, []Level{Warn}},
		{"loose mode", []facts.Sudoers{mod(func(s *facts.Sudoers) { s.Perm = 0o444 })}, []Level{Warn}},
		{"writable", []facts.Sudoers{mod(func(s *facts.Sudoers) { s.Perm = 0o664; s.NonRootWritable = true })}, []Level{Fail}},
		{
			"own drop-in beside a foreign NOPASSWD",
			[]facts.Sudoers{
				ownDropin(sudoersdrop.AdminUserID, "ops"),
				{Path: "/etc/sudoers.d/90-cloud-init-users", Readable: true, NoPasswd: []facts.SudoRule{{Who: "ubuntu", Line: 2}}},
			},
			[]Level{Info, Warn},
		},
		{
			"NOPASSWD in /etc/sudoers itself",
			[]facts.Sudoers{
				{Path: "/etc/sudoers", Perm: 0o440, Readable: true, NoPasswd: []facts.SudoRule{{Who: "ops", Line: 9}}},
				ownDropin(sudoersdrop.AdminUserID, "ops"),
			},
			[]Level{Warn, Info},
		},
	}
	for _, tc := range cases {
		rs := checkSudoers(Input{Facts: &facts.Facts{Users: &facts.Users{Sudoers: tc.in}}})
		var got []Level
		for _, r := range rs {
			got = append(got, r.Level)
		}
		if len(got) != len(tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
				break
			}
		}
	}
}

func TestUSR004OwnDropinMessage(t *testing.T) {
	rs := checkSudoers(Input{Facts: &facts.Facts{Users: &facts.Users{Sudoers: []facts.Sudoers{ownDropin(sudoersdrop.AdminUserID, "ops")}}}})
	const want = "written by stackward admin-user for ops; passwordless sudo because the account has no password"
	if len(rs) != 1 || rs[0].Message != want {
		t.Errorf("got %+v", rs)
	}
}
