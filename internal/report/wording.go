package report

import "strings"

// Headline is what a line about a result says: the result message, which
// states what was found ("A container mounts the Docker socket"). The check
// title states the good state and would read as the opposite of a fail, so
// it is only the fallback for a result without a message; renderers show the
// title as the rule the result was measured against.
func Headline(it Item) string {
	if it.Message != "" {
		return it.Message
	}
	return it.Title
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
