// Package harden applies best-effort, process-wide mitigations that shrink the
// window in which shenv's in-memory secrets — the decrypted private key and
// .env plaintext — could leak. It closes two casual paths: a crash writing a
// core/crash dump that contains those secrets to disk, and another process
// running as the same user peeking into this one's memory after startup.
//
// The threat model is deliberately narrow. These are hygiene measures against
// accidental disk spillage and casual same-user inspection; they are NOT
// anti-debugging or DRM, and they cannot stop malware running as you — once the
// key is unlocked it lives in this process's memory, and code running with your
// privileges (or root) can still read it. For that threat the answer is a
// hardware-backed key, as the README notes. Everything here is applied
// best-effort: every step ignores its errors, so hardening never fails the
// program or changes its behavior.
package harden
