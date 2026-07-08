package crypto

import "runtime"

// Zero overwrites b with zeros. Best-effort hygiene: Go's GC may already have
// copied the data, and copies that were converted to string cannot be wiped —
// this shrinks the exposure window, it does not guarantee erasure.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}
