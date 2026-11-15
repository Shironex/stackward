package guard

import (
	"go/scanner"
	"go/token"
	"os"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// MaxTestFileLines is the limit for one _test.go file, counted in lines of
// code (blank lines and comment only lines do not count). Production files
// have a stricter limit, enforced by revive's file-length-limit.
const MaxTestFileLines = 1000

// TestLength reports test files longer than MaxTestFileLines code lines.
var TestLength = &analysis.Analyzer{
	Name: "stackwardtestlen",
	Doc:  "report _test.go files with more than 1000 lines of code",
	Run:  runTestLen,
}

func runTestLen(pass *analysis.Pass) (any, error) {
	for _, f := range pass.Files {
		name := pass.Fset.Position(f.Pos()).Filename
		if !strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			return nil, err
		}
		if n := codeLines(src); n > MaxTestFileLines {
			pass.Reportf(f.Package, "test file has %d lines of code, over the limit of %d; split it by topic", n, MaxTestFileLines)
		}
	}
	return nil, nil
}

// codeLines counts the lines that hold at least one token other than a
// comment. A raw string literal counts every line it spans.
func codeLines(src []byte) int {
	fset := token.NewFileSet()
	file := fset.AddFile("", fset.Base(), len(src))
	var s scanner.Scanner
	s.Init(file, src, nil, 0)
	lines := map[int]bool{}
	for {
		pos, tok, lit := s.Scan()
		if tok == token.EOF {
			break
		}
		start := fset.Position(pos).Line
		end := start
		if tok == token.STRING {
			end += strings.Count(lit, "\n")
		}
		for l := start; l <= end; l++ {
			lines[l] = true
		}
	}
	return len(lines)
}
