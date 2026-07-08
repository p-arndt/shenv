package harden

import "testing"

// TestProcessNoPanic is a smoke test: hardening is best-effort and must never
// fail the program, so on whatever platform the test runs, Process must simply
// return without panicking. Calling it twice checks it is also idempotent.
func TestProcessNoPanic(t *testing.T) {
	Process()
	Process()
}
