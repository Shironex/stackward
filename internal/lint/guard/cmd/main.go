// Command guard runs the stackward-guard analyzers:
//
//	go run ./internal/lint/guard/cmd ./...
package main

import (
	"golang.org/x/tools/go/analysis/multichecker"

	"github.com/Shironex/stackward/internal/lint/guard"
)

func main() {
	multichecker.Main(guard.Analyzer, guard.TestLength)
}
