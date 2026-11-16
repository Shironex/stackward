// Package schema embeds the JSON contracts that stackward checks at run
// time: stackward diff validates both report files against report.v1
// before it trusts a field of them.
package schema

import _ "embed" // for go:embed

// Report is schema/report.v1.json.
//
//go:embed report.v1.json
var Report []byte

// Diff is schema/diff.v1.json.
//
//go:embed diff.v1.json
var Diff []byte
