//go:build unix && !linux

package harden

// extraHardening is a no-op on the non-Linux unixes: PR_SET_DUMPABLE is
// Linux-specific, and the RLIMIT_CORE=0 that Process already set covers core
// dumps everywhere else.
func extraHardening() {}
