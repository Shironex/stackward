// Package guard holds the stackward-guard analyzers. They enforce the
// safety model of docs/safety.md in code: a read only audit tool must not
// write files, start programs or open network connections outside a short
// allowlist (allowlist.go), and test files stay below a length limit.
package guard

import (
	"go/ast"
	"go/constant"
	"go/types"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/tools/go/analysis"
)

// New returns the side effect analyzer for an allowlist.
func New(allow []Entry) *analysis.Analyzer {
	return &analysis.Analyzer{
		Name: "stackwardguard",
		Doc: "report filesystem writes, program starts and network use outside the allowlist\n\n" +
			"Allowed places are listed in internal/lint/guard/allowlist.go. Test files are skipped.",
		Run: func(pass *analysis.Pass) (any, error) { return run(pass, allow) },
	}
}

// Analyzer is the side effect analyzer with the real allowlist.
var Analyzer = New(DefaultAllowlist)

func run(pass *analysis.Pass, allow []Entry) (any, error) {
	for _, f := range pass.Files {
		name := pass.Fset.Position(f.Pos()).Filename
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		allowed := allowedFor(pass.Pkg.Path(), filepath.Base(name), allow)
		check(pass, f, allowed)
	}
	return nil, nil
}

// allowedFor returns the categories permitted in one file.
func allowedFor(pkgPath, file string, allow []Entry) map[Category]bool {
	out := map[Category]bool{}
	for _, e := range allow {
		if pkgPath != e.Pkg && !strings.HasSuffix(pkgPath, "/"+e.Pkg) {
			continue
		}
		if len(e.Files) > 0 && !contains(e.Files, file) {
			continue
		}
		for _, c := range e.Allow {
			out[c] = true
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func check(pass *analysis.Pass, f *ast.File, allowed map[Category]bool) {
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if fn := calledFunc(pass, x); fn != nil && fn.FullName() == "os.OpenFile" {
				if !allowed[FSWrite] && opensForWrite(pass, x) {
					pass.Reportf(x.Pos(), "os.OpenFile opens a file for writing (or with flags the guard cannot read); %s", hint(pass, FSWrite))
				}
			}
		case *ast.Ident:
			fn, ok := pass.TypesInfo.Uses[x].(*types.Func)
			if !ok {
				return true
			}
			if cat, bad := forbidden[fn.FullName()]; bad && !allowed[cat] {
				pass.Reportf(x.Pos(), "%s %s; %s", fn.FullName(), describe[cat], hint(pass, cat))
			}
		}
		return true
	})
}

func hint(pass *analysis.Pass, c Category) string {
	return "package " + pass.Pkg.Path() + " is not allowed to (" + string(c) + ") in internal/lint/guard/allowlist.go"
}

// calledFunc resolves the function a call expression calls, if static.
func calledFunc(pass *analysis.Pass, call *ast.CallExpr) *types.Func {
	var id *ast.Ident
	switch f := call.Fun.(type) {
	case *ast.Ident:
		id = f
	case *ast.SelectorExpr:
		id = f.Sel
	default:
		return nil
	}
	fn, _ := pass.TypesInfo.Uses[id].(*types.Func)
	return fn
}

// writeFlags are the os.OpenFile flags that can change a file.
const writeFlags = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREATE | os.O_TRUNC

// opensForWrite reports whether an os.OpenFile call may write. A flag
// argument that is not a constant counts as writing: the guard cannot tell.
func opensForWrite(pass *analysis.Pass, call *ast.CallExpr) bool {
	if len(call.Args) < 2 {
		return true
	}
	tv, ok := pass.TypesInfo.Types[call.Args[1]]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.Int {
		return true
	}
	v, exact := constant.Int64Val(tv.Value)
	return !exact || v&int64(writeFlags) != 0
}
