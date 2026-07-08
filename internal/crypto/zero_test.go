package crypto

import (
	"bytes"
	"testing"
)

// TestZero verifies Zero overwrites every byte of the buffer.
func TestZero(t *testing.T) {
	b := []byte("AGE-SECRET-KEY-1EXAMPLE")
	Zero(b)
	if !bytes.Equal(b, make([]byte, len(b))) {
		t.Fatalf("Zero left non-zero bytes: %v", b)
	}
}

// TestZeroEmpty verifies Zero is a safe no-op on an empty and a nil slice.
func TestZeroEmpty(t *testing.T) {
	Zero(nil)
	Zero([]byte{})
}
