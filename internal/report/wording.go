package report

import (
	"regexp"
	"strings"

	"github.com/Shironex/stackward/internal/checks"
)

// Headline is what a line about a result says: the result message, which
// states what was found ("A container mounts the Docker socket"). The check
// title states the good state and would read as the opposite of a fail, so
// it is only the fallback for a result without a message; renderers show the
// title as the rule the result was measured against.
//
// Container names Coolify generated ("alloy-a2arfozauvzagw6if1eisq30") are
// shown as their service ("alloy"); the message and the JSON keep the full
// name.
func Headline(it Item) string {
	if it.Message != "" {
		return ShortenGeneratedNames(it.Message)
	}
	return it.Title
}

// nameToken is a candidate container name inside a sentence.
var nameToken = regexp.MustCompile(`[a-z0-9][a-z0-9_.-]*`)

// generatedID reports whether s is the 24 character lowercase alphanumeric
// id Coolify appends to a service name. It must mix letters and digits so a
// long plain word is never taken for one.
func generatedID(s string) bool {
	if len(s) != 24 {
		return false
	}
	letters, digits := 0, 0
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z':
			letters++
		case c >= '0' && c <= '9':
			digits++
		default:
			return false
		}
	}
	return letters > 0 && digits > 0
}

// shortenName turns "<service>-<24 chars>[-suffix]" into "<service>[-suffix]"
// and returns any other name unchanged. A lone trailing run of 10 or more
// digits (a deploy timestamp) is dropped with the id.
func shortenName(name string) string {
	segs := strings.Split(name, "-")
	for i := 1; i < len(segs); i++ {
		if segs[i-1] == "" || !generatedID(segs[i]) {
			continue
		}
		out := append([]string{}, segs[:i]...)
		rest := segs[i+1:]
		stamp := len(rest) == 1 && len(rest[0]) >= 10 && isDigits(rest[0])
		if !stamp {
			out = append(out, rest...)
		}
		return strings.Join(out, "-")
	}
	return name
}

func isDigits(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

// ShortenGeneratedNames replaces every Coolify style generated container
// name in text with its service name; text without one is returned as is.
func ShortenGeneratedNames(text string) string {
	return nameToken.ReplaceAllStringFunc(text, func(tok string) string {
		core := strings.TrimRight(tok, ".-_")
		return shortenName(core) + tok[len(core):]
	})
}

// ExpectedLowered reports whether the level of a result was lowered because
// a platform manages the thing (a warn on a platform component).
func ExpectedLowered(it Item) bool {
	mgr, _ := it.Evidence["managed_by"].(string)
	return mgr != "" && it.Level == checks.Warn
}

// NamesSubject reports whether the message opens with the subject, so a line
// can drop the subject and give the sentence the room.
func NamesSubject(msg, subj string) bool {
	if subj == "" {
		return false
	}
	first, _, _ := strings.Cut(msg, " ")
	return strings.TrimRight(first, ",:;") == subj
}

// ShortSubject drops the kind prefix of a subject ("container:app/web"
// gives "app/web") and hides the default "host".
func ShortSubject(s string) string {
	if s == "" || s == "host" {
		return ""
	}
	if _, rest, ok := strings.Cut(s, ":"); ok && rest != "" {
		return rest
	}
	return s
}
