//go:build stackward_scenario

package main

import "github.com/Shironex/stackward/internal/plan/txntest"

// The scenario binary (go build -tags stackward_scenario) carries the
// test-only access-critical steps, so the transaction scenario can apply
// one on a disposable runner VM. Released builds have no tag and do not
// contain them (main_test.go).
func init() { txntest.Register() }
