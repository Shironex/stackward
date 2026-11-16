package tui

import (
	"image/color"

	"charm.land/lipgloss/v2"

	"github.com/Shironex/stackward/internal/checks"
)

// The brand palette (assets/brand/README.md). Dark terminals get the colors
// meant for ink surfaces, light terminals their darker aliases, so every
// pairing keeps the contrast the brand sheet measured.
var (
	ink        = lipgloss.Color("#102B2B")
	paper      = lipgloss.Color("#F3F6F1")
	mint       = lipgloss.Color("#72D6BC")
	muted      = lipgloss.Color("#B7CAC4")
	dimDark    = lipgloss.Color("#497B70")
	teal       = lipgloss.Color("#246B5B")
	quietLight = lipgloss.Color("#49675D")
	dimLight   = lipgloss.Color("#739184")
	warnDark   = lipgloss.Color("#F3C879")
	failDark   = lipgloss.Color("#FF9C90")
	warnLight  = lipgloss.Color("#875400")
	failLight  = lipgloss.Color("#AD3C30")
)

// styles is every style the view uses, built for one background.
type styles struct {
	fg, accent, secondary, dim color.Color

	brand    lipgloss.Style
	text     lipgloss.Style
	bold     lipgloss.Style
	quiet    lipgloss.Style
	faint    lipgloss.Style
	accentS  lipgloss.Style
	section  lipgloss.Style
	rule     lipgloss.Style
	selected lipgloss.Style // cursor row while the list has focus
	marker   lipgloss.Style
	key      lipgloss.Style
	warnText lipgloss.Style
	level    map[checks.Level]lipgloss.Style
}

// newStyles builds the styles for a dark or light terminal background.
// Colors never carry meaning alone: every level is also a word.
func newStyles(dark bool) styles {
	ld := lipgloss.LightDark(dark)
	s := styles{
		fg:        ld(ink, paper),
		accent:    ld(teal, mint),
		secondary: ld(quietLight, muted),
		dim:       ld(dimLight, dimDark),
	}
	warn, fail := ld(warnLight, warnDark), ld(failLight, failDark)
	base := lipgloss.NewStyle()
	s.text = base.Foreground(s.fg)
	s.bold = s.text.Bold(true)
	s.quiet = base.Foreground(s.secondary)
	s.faint = base.Foreground(s.dim)
	s.accentS = base.Foreground(s.accent)
	s.brand = s.accentS.Bold(true)
	s.section = s.accentS.Bold(true)
	s.rule = s.faint
	s.selected = base.Reverse(true).Bold(true)
	s.marker = s.accentS.Bold(true)
	s.key = s.accentS.Bold(true)
	s.warnText = base.Foreground(warn)
	s.level = map[checks.Level]lipgloss.Style{
		checks.Fail:    base.Foreground(fail).Bold(true),
		checks.Warn:    base.Foreground(warn).Bold(true),
		checks.Unknown: base.Foreground(s.secondary).Bold(true),
		checks.Info:    base.Foreground(s.secondary),
		accepted:       base.Foreground(s.secondary).Italic(true),
		checks.Pass:    base.Foreground(s.accent),
		checks.Skip:    base.Foreground(s.dim),
	}
	return s
}

// levelStyle returns the style of a level, plain text for an unknown one.
func (s styles) levelStyle(l checks.Level) lipgloss.Style {
	if st, ok := s.level[l]; ok {
		return st
	}
	return s.text
}
