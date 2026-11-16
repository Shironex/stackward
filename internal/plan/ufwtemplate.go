package plan

import "strings"

// A fresh install of ufw, and `ufw reset`, put a short template in
// user.rules and user6.rules: the user chains, a RULES line and the rate
// limit rules, with no END RULES line. The first time ufw writes its rules
// (any `ufw allow`, and `ufw enable` on the template) it replaces the
// template with its full format: every chain, the RULES section, the
// logging rules of its log level and the rate limit section. A step that
// edited the template would see ufw rewrite its file right away, so a
// second apply and the undo would find a file they did not write. So a
// step writes the template's place in ufw's full format itself, byte for
// byte as ufw does at its default log level (low); ufw's rewrite then
// changes nothing.

// ufwPrefix is the chain prefix of a user rules file.
func ufwPrefix(v6 bool) string {
	if v6 {
		return "ufw6"
	}
	return "ufw"
}

// ufwTemplate is the user rules template ufw ships. The IPv6 one has no
// rate limit chains.
func ufwTemplate(v6 bool) string {
	p := ufwPrefix(v6)
	var b strings.Builder
	b.WriteString("*filter\n")
	for _, c := range []string{"user-input", "user-output", "user-forward"} {
		b.WriteString(":" + p + "-" + c + " - [0:0]\n")
	}
	if v6 {
		b.WriteString(ufwRulesBegin + "\nCOMMIT\n")
		return b.String()
	}
	b.WriteString(":" + p + "-user-limit - [0:0]\n:" + p + "-user-limit-accept - [0:0]\n")
	b.WriteString(ufwRulesBegin + "\n")
	b.WriteString(`-A ` + p + `-user-limit -m limit --limit 3/minute -j LOG --log-prefix "[UFW LIMIT BLOCK] "` + "\n")
	b.WriteString("-A " + p + "-user-limit -j REJECT\n")
	b.WriteString("-A " + p + "-user-limit-accept -j ACCEPT\n")
	b.WriteString("COMMIT\n")
	return b.String()
}

// ufwEmptyRules is the user rules file ufw writes with no rules at log
// level low.
func ufwEmptyRules(v6 bool) string {
	p := ufwPrefix(v6)
	var b strings.Builder
	b.WriteString("*filter\n")
	for _, c := range []string{"user-input", "user-output", "user-forward", "before-logging-input", "before-logging-output",
		"before-logging-forward", "user-logging-input", "user-logging-output", "user-logging-forward",
		"after-logging-input", "after-logging-output", "after-logging-forward", "logging-deny",
		"logging-allow", "user-limit", "user-limit-accept"} {
		b.WriteString(":" + p + "-" + c + " - [0:0]\n")
	}
	b.WriteString(ufwRulesBegin + "\n\n" + ufwRulesEnd + "\n\n### LOGGING ###\n")
	const limit = ` -m limit --limit 3/min --limit-burst 10`
	b.WriteString("-A " + p + `-after-logging-input -j LOG --log-prefix "[UFW BLOCK] "` + limit + "\n")
	b.WriteString("-A " + p + `-after-logging-forward -j LOG --log-prefix "[UFW BLOCK] "` + limit + "\n")
	b.WriteString("-I " + p + `-logging-deny -m conntrack --ctstate INVALID -j RETURN` + limit + "\n")
	b.WriteString("-A " + p + `-logging-deny -j LOG --log-prefix "[UFW BLOCK] "` + limit + "\n")
	b.WriteString("-A " + p + `-logging-allow -j LOG --log-prefix "[UFW ALLOW] "` + limit + "\n")
	b.WriteString("### END LOGGING ###\n\n### RATE LIMITING ###\n")
	b.WriteString("-A " + p + `-user-limit -m limit --limit 3/minute -j LOG --log-prefix "[UFW LIMIT BLOCK] "` + "\n")
	b.WriteString("-A " + p + "-user-limit -j REJECT\n")
	b.WriteString("-A " + p + "-user-limit-accept -j ACCEPT\n")
	b.WriteString("### END RATE LIMITING ###\nCOMMIT\n")
	return b.String()
}

// isUFWTemplate reports whether content is ufw's user rules template.
func isUFWTemplate(content string, v6 bool) bool { return content == ufwTemplate(v6) }

// fromTemplate returns the file ufw writes in place of its template, and
// any other content as it is.
func fromTemplate(content string, v6 bool) string {
	if isUFWTemplate(content, v6) {
		return ufwEmptyRules(v6)
	}
	return content
}
