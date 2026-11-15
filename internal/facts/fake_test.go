package facts

import (
	"context"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"testing/fstest"
	"time"
)

// fakeSystem is a System over an in memory tree, for collector tests.
// Every collector test in this package can use it:
//
//	sys := newFakeSystem(map[string]string{"/etc/os-release": "ID=debian\n"})
//	sys.cmds["sshd -T"] = CmdResult{Stdout: []byte("port 22\n")}
type fakeSystem struct {
	files fstest.MapFS
	cmds  map[string]CmdResult // key: name and args joined by spaces
	host  Host
}

func newFakeSystem(files map[string]string) *fakeSystem {
	m := fstest.MapFS{}
	for p, body := range files {
		m[strings.TrimPrefix(p, "/")] = &fstest.MapFile{Data: []byte(body), Mode: 0o644, ModTime: time.Unix(0, 0)}
	}
	return &fakeSystem{files: m, cmds: map[string]CmdResult{}, host: Host{Hostname: "host.example.com", UID: 1000, EUID: 1000}}
}

func (s *fakeSystem) rel(p string) string { return strings.TrimPrefix(path.Clean(p), "/") }

func (s *fakeSystem) ReadFile(p string) ([]byte, error) { return fs.ReadFile(s.files, s.rel(p)) }

func (s *fakeSystem) ReadDir(p string) ([]fs.DirEntry, error) {
	entries, err := fs.ReadDir(s.files, s.rel(p))
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, err
}

func (s *fakeSystem) Meta(p string) (FileMeta, error) {
	fi, err := fs.Stat(s.files, s.rel(p))
	if err != nil {
		return FileMeta{}, err
	}
	return FileMeta{Path: p, Mode: fi.Mode(), Size: fi.Size(), ModTime: fi.ModTime().Unix()}, nil
}

func (s *fakeSystem) Run(_ context.Context, name string, args ...string) (CmdResult, error) {
	key := strings.Join(append([]string{name}, args...), " ")
	if r, ok := s.cmds[key]; ok {
		return r, nil
	}
	return CmdResult{}, fmt.Errorf("command %q: not found", name)
}

func (s *fakeSystem) LookPath(name string) (string, error) {
	for k := range s.cmds {
		if k == name || strings.HasPrefix(k, name+" ") {
			return "/usr/bin/" + name, nil
		}
	}
	return "", fmt.Errorf("command %q: not found", name)
}

func (s *fakeSystem) Identity() Host { return s.host }
