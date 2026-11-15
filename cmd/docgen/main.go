// Command docgen writes docs/checks from the embedded check catalog.
//
//	go run ./cmd/docgen            regenerate docs/checks
//	go run ./cmd/docgen -check     exit 1 if the committed pages are stale
//	go run ./cmd/docgen -out DIR   write somewhere else
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Shironex/stackward/internal/catalog"
	"github.com/Shironex/stackward/internal/docgen"
)

func main() {
	out := flag.String("out", "docs/checks", "directory for the generated pages")
	check := flag.Bool("check", false, "only compare, do not write")
	flag.Parse()

	cat, err := catalog.Default()
	if err != nil {
		fmt.Fprintln(os.Stderr, "docgen:", err)
		os.Exit(2)
	}
	if *check {
		problems, err := docgen.Check(cat, *out)
		if err != nil {
			fmt.Fprintln(os.Stderr, "docgen:", err)
			os.Exit(2)
		}
		for _, p := range problems {
			fmt.Fprintln(os.Stderr, p)
		}
		if len(problems) > 0 {
			fmt.Fprintln(os.Stderr, "docgen: pages are stale; run: go run ./cmd/docgen")
			os.Exit(1)
		}
		return
	}
	if err := docgen.Write(cat, *out); err != nil {
		fmt.Fprintln(os.Stderr, "docgen:", err)
		os.Exit(2)
	}
}
