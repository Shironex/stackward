package report

import (
	"strings"

	"github.com/charmbracelet/x/ansi"

	"github.com/Shironex/stackward/internal/checks"
)

// DefaultTextWidth is the wrap width when the caller knows none (output to a
// pipe or a file without COLUMNS).
const DefaultTextWidth = 100

// minTextWidth keeps a very narrow terminal from wrapping one word a line.
const minTextWidth = 40

// SGR codes the text report uses.
const (
	sgrBold = "1"
	sgrDim  = "2"
)

var levelSGR = map[checks.Level]string{
	checks.Fail: "31", checks.Warn: "33", checks.Unknown: "35",
	checks.Info: "36", checks.Pass: "32", checks.Skip: "90",
}

// Marks in front of a result: Unicode on a terminal, ASCII in plain output.
var (
	fancyMarks = map[checks.Level]string{
		checks.Fail: "✗", checks.Warn: "!", checks.Unknown: "?",
		checks.Info: "i", checks.Pass: "✓", checks.Skip: "-",
	}
	plainMarks = map[checks.Level]string{
		checks.Fail: "x", checks.Warn: "!", checks.Unknown: "?",
		checks.Info: "i", checks.Pass: "+", checks.Skip: "-",
	}
)

// boxChars are the corners and edges of the summary box, the section rule,
// the ellipsis of a shortened line and the separator of the meta line.
type boxChars struct{ tl, tr, bl, br, h, v, rule, ellipsis, sep string }

var (
	fancyBox = boxChars{"╭", "╮", "╰", "╯", "─", "│", "─", "…", " · "}
	plainBox = boxChars{"+", "+", "+", "+", "-", "|", "-", "...", ", "}
)

// style renders the pieces of the text report for one output: ANSI colors
// only when Color is set, Unicode marks and box lines only when Fancy is.
type style struct {
	color bool
	marks map[checks.Level]string
	box   boxChars
}

func newStyle(o TextOptions) style {
	s := style{color: o.Color, marks: plainMarks, box: plainBox}
	if o.Fancy {
		s.marks, s.box = fancyMarks, fancyBox
	}
	return s
}

// sgr wraps text in one SGR sequence when colors are on.
func (s style) sgr(code, text string) string {
	if !s.color || code == "" || text == "" {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

func (s style) dim(text string) string  { return s.sgr(sgrDim, text) }
func (s style) bold(text string) string { return s.sgr(sgrBold, text) }

func (s style) level(l checks.Level, text string) string { return s.sgr(levelSGR[l], text) }

// levelBold is the level color in bold, for marks and section labels.
func (s style) levelBold(l checks.Level, text string) string {
	return s.sgr(sgrBold+";"+levelSGR[l], text)
}

func (s style) mark(l checks.Level) string { return s.levelBold(l, s.marks[l]) }

// width is the display width of plain text.
func width(s string) int { return ansi.StringWidth(s) }

// wrapWords breaks plain text into lines of at most w cells, at spaces. A
// word longer than a whole line (a URL, a long path) is the only thing ever
// cut, and only when it would not fit on a line of its own either.
// Paragraph breaks are kept.
func wrapWords(text string, w int) []string {
	w = max(w, 1)
	var out []string
	for _, para := range strings.Split(strings.TrimRight(text, "\n"), "\n") {
		line := ""
		for _, word := range strings.Fields(para) {
			for width(word) > w {
				if line != "" {
					out, line = append(out, line), ""
				}
				head := ansi.Truncate(word, w, "")
				out = append(out, head)
				word = word[len(head):]
			}
			switch {
			case line == "":
				line = word
			case width(line)+1+width(word) <= w:
				line += " " + word
			default:
				out, line = append(out, line), word
			}
		}
		out = append(out, line)
	}
	return out
}

// truncateWords shortens plain text to at most w cells, cutting at the last
// space that leaves room for the ellipsis.
func truncateWords(text string, w int, ellipsis string) string {
	if width(text) <= w {
		return text
	}
	room := w - width(ellipsis)
	if room <= 0 {
		return ansi.Truncate(ellipsis, max(w, 0), "")
	}
	cut := ansi.Truncate(text, room, "")
	if i := strings.LastIndexByte(cut, ' '); i > room/2 {
		cut = cut[:i]
	}
	return strings.TrimRight(cut, " ,;:") + ellipsis
}
