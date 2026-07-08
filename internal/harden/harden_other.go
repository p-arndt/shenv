//go:build !unix && !windows

package harden

// Process is a no-op on platforms without a supported core/crash-dump
// suppression mechanism (e.g. plan9, wasm). Hardening is best-effort, so its
// absence here is not an error — the rest of shenv works unchanged.
func Process() {}
