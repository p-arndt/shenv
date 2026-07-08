//go:build unix

package harden

import "golang.org/x/sys/unix"

// Process disables core dumps and applies any platform-specific extra hardening.
func Process() {
	// Both the soft and hard RLIMIT_CORE to zero: the soft limit stops the
	// kernel writing a core file if we crash (which would contain the decrypted
	// key and .env plaintext), and pinning the hard limit to zero stops this
	// process — or a child — from raising it again.
	_ = unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
	extraHardening()
}
