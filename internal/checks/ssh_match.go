package checks

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Shironex/stackward/internal/facts/sshd"
)

// securityRank orders values of keywords whose insecure value can shadow a
// later secure one (higher is safer). ok is false for other keywords.
func securityRank(keyword, value string) (int, bool) {
	v := strings.ToLower(value)
	switch keyword {
	case "passwordauthentication", "kbdinteractiveauthentication", "permitemptypasswords",
		"x11forwarding", "allowagentforwarding":
		if v == "no" {
			return 1, true
		}
		return 0, true
	case "permitrootlogin":
		return rootLoginRank(v), true
	case "maxauthtries":
		n, err := strconv.Atoi(v)
		if err != nil {
			return 0, false
		}
		return -n, true
	}
	return 0, false
}

// shadowed is one insecure first value that hides a later safer one.
type shadowed struct {
	Keyword      string `json:"keyword"`
	Value        string `json:"value"`
	Line         int    `json:"line"`
	IgnoredFile  string `json:"ignored_file"`
	IgnoredLine  int    `json:"ignored_line"`
	IgnoredValue string `json:"ignored_value"`
}

func checkDropInOrder(in Input) []Result {
	s, res := sshFacts(in)
	if s == nil {
		return res
	}
	c := s.Config
	if c == nil || len(c.Files) == 0 || !c.Files[0].Readable {
		return One(Unknown, "configuration files could not be read: "+why(s), map[string]any{"unreadable": unreadable(s)})
	}
	winner := map[string]sshd.Directive{}
	reported := map[string]bool{}
	byFile := map[string][]shadowed{}
	for _, d := range c.Directives {
		if d.Match != 0 {
			continue
		}
		rank, ok := securityRank(d.Keyword, d.Value)
		if !ok {
			continue
		}
		w, seen := winner[d.Keyword]
		if !seen {
			winner[d.Keyword] = d
			continue
		}
		wrank, _ := securityRank(w.Keyword, w.Value)
		if rank > wrank && !reported[d.Keyword] {
			reported[d.Keyword] = true
			byFile[w.File] = append(byFile[w.File], shadowed{Keyword: d.Keyword, Value: w.Value, Line: w.Line,
				IgnoredFile: d.File, IgnoredLine: d.Line, IgnoredValue: d.Value})
		}
	}
	if len(byFile) > 0 {
		files := make([]string, 0, len(byFile))
		for f := range byFile {
			files = append(files, f)
		}
		sort.Strings(files)
		var out []Result
		for _, f := range files {
			var parts []string
			for _, sh := range byFile[f] {
				parts = append(parts, fmt.Sprintf("%s %s (line %d) wins over %s in %s line %d",
					sh.Keyword, sh.Value, sh.Line, sh.IgnoredValue, sh.IgnoredFile, sh.IgnoredLine))
			}
			out = append(out, Result{Subject: "file:" + f, Level: Warn,
				Message:  "first value wins: " + strings.Join(parts, "; "),
				Evidence: map[string]any{"settings": byFile[f]}})
		}
		return out
	}
	if u := unreadable(s); len(u) > 0 {
		return One(Unknown, "could not check the drop-in order: "+why(s), map[string]any{"unreadable": u})
	}
	return One(Pass, fmt.Sprintf("no insecure value shadows a later setting in %d files", len(c.Files)),
		map[string]any{"files": len(c.Files)})
}

func checkMatchCoverage(in Input) []Result {
	s, res := sshFacts(in)
	if s == nil {
		return res
	}
	matches := 0
	if s.Config != nil {
		matches = len(s.Config.Matches)
	}
	ev := map[string]any{"source": s.Source, "match_blocks": matches, "unreadable": unreadable(s)}
	switch {
	case s.Source == "sshd -T":
		return One(Skip, "effective configuration read with sshd -T", ev)
	case !s.Complete:
		return One(Unknown, "configuration only partly read: "+why(s), ev)
	case matches > 0:
		return One(Unknown, fmt.Sprintf("%s and no sshd -T: per connection settings are not confirmed (%s)", count(matches, "Match block"), why(s)), ev)
	}
	return One(Pass, "every configuration file read and no Match blocks", ev)
}
