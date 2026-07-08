//go:build linux

package harden

import "golang.org/x/sys/unix"

// extraHardening marks the process non-dumpable on Linux.
func extraHardening() {
	// PR_SET_DUMPABLE=0 both blocks core dumps and stops other same-user
	// processes from ptrace-attaching to us after this point. Honest caveats: it
	// does NOT detach a debugger that launched us, and root (or CAP_SYS_PTRACE)
	// can still attach regardless. As a side effect the kernel reassigns
	// /proc/<pid>/environ and /proc/<pid>/mem to root ownership, so they become
	// root-only rather than readable by the process's own user.
	_ = unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}
