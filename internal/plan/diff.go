package plan

import (
	"fmt"
	"strings"
)

// diffContext is the number of unchanged lines around each hunk.
const diffContext = 3

// maxDiffLines bounds the line table; beyond it the diff replaces the
// whole file in one hunk, which is still a correct unified diff.
const maxDiffLines = 4000

// Diff returns a unified diff from old to new with the given file labels,
// or "" when they are equal. Old and new are split on "\n"; a missing final
// newline is marked the way diff(1) marks it.
func Diff(oldName, newName, old, nw string) string {
	if old == nw {
		return ""
	}
	a, b := splitLines(old), splitLines(nw)
	ops := lineOps(a, b)
	var out strings.Builder
	fmt.Fprintf(&out, "--- %s\n+++ %s\n", oldName, newName)
	for _, h := range hunks(ops) {
		writeHunk(&out, h, a, b)
	}
	return out.String()
}

// line is one line and whether it ended with a newline.
type line struct {
	text string
	eol  bool
}

func splitLines(s string) []line {
	if s == "" {
		return nil
	}
	parts := strings.SplitAfter(s, "\n")
	out := make([]line, 0, len(parts))
	for _, p := range parts {
		if p == "" {
			continue
		}
		out = append(out, line{text: strings.TrimSuffix(p, "\n"), eol: strings.HasSuffix(p, "\n")})
	}
	return out
}

// op is one diff operation: ' ' keep, '-' delete a[i], '+' insert b[j].
type op struct {
	kind byte
	i, j int
}

// lineOps returns the edit script from a longest common subsequence table.
// Plan files are small configuration files, so O(n*m) is fine; larger
// inputs fall back to delete all, insert all.
func lineOps(a, b []line) []op {
	n, m := len(a), len(b)
	var ops []op
	if n > maxDiffLines || m > maxDiffLines {
		for i := range a {
			ops = append(ops, op{'-', i, 0})
		}
		for j := range b {
			ops = append(ops, op{'+', n, j})
		}
		return ops
	}
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	i, j := 0, 0
	for i < n || j < m {
		switch {
		case i < n && j < m && a[i] == b[j]:
			ops = append(ops, op{' ', i, j})
			i++
			j++
		case i < n && (j == m || lcs[i+1][j] >= lcs[i][j+1]):
			ops = append(ops, op{'-', i, j})
			i++
		default:
			ops = append(ops, op{'+', i, j})
			j++
		}
	}
	return ops
}

// hunks groups ops into ranges with diffContext lines of context.
func hunks(ops []op) [][]op {
	var out [][]op
	start, end := -1, -1
	for k, o := range ops {
		if o.kind == ' ' {
			continue
		}
		lo, hi := max(k-diffContext, 0), min(k+diffContext, len(ops)-1)
		if start >= 0 && lo <= end+1 {
			end = hi
			continue
		}
		if start >= 0 {
			out = append(out, ops[start:end+1])
		}
		start, end = lo, hi
	}
	if start >= 0 {
		out = append(out, ops[start:end+1])
	}
	return out
}

func writeHunk(out *strings.Builder, h []op, a, b []line) {
	oldStart, newStart := h[0].i, h[0].j
	oldLen, newLen := 0, 0
	for _, o := range h {
		if o.kind != '+' {
			oldLen++
		}
		if o.kind != '-' {
			newLen++
		}
	}
	fmt.Fprintf(out, "@@ -%s +%s @@\n", hunkRange(oldStart, oldLen), hunkRange(newStart, newLen))
	for _, o := range h {
		var l line
		switch o.kind {
		case '-':
			l = a[o.i]
		case '+':
			l = b[o.j]
		default:
			l = a[o.i]
		}
		out.WriteByte(o.kind)
		out.WriteString(l.text)
		out.WriteByte('\n')
		if !l.eol {
			out.WriteString("\\ No newline at end of file\n")
		}
	}
}

// hunkRange formats a hunk range: start is 0 based, the output 1 based; an
// empty range names the line before it, as diff(1) does.
func hunkRange(start, n int) string {
	switch n {
	case 0:
		return fmt.Sprintf("%d,0", start)
	case 1:
		return fmt.Sprintf("%d", start+1)
	}
	return fmt.Sprintf("%d,%d", start+1, n)
}
