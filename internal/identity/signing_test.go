package identity

import (
	"os"
	"strings"
	"testing"

	"shenv/internal/crypto"
)

// TestVerifyKeyPlaintext: an unencrypted key derives the verify key directly,
// no passphrase func needed.
func TestVerifyKeyPlaintext(t *testing.T) {
	tempHome(t)
	id, err := Create("")
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifyKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	key, err := crypto.DeriveSigningKey(id)
	if err != nil {
		t.Fatal(err)
	}
	if got != crypto.VerifyKeyString(key) {
		t.Fatalf("verify key mismatch: got %q", got)
	}
}

// TestVerifyKeyEncryptedUsesComment: an encrypted key must yield the verify key
// WITHOUT invoking the passphrase func — it lives in the plaintext comment.
func TestVerifyKeyEncryptedUsesComment(t *testing.T) {
	tempHome(t)
	if _, err := Create("hunter2"); err != nil {
		t.Fatal(err)
	}
	got, err := VerifyKey(func() (string, error) {
		t.Fatal("VerifyKey must not need the passphrase when the comment exists")
		return "", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if got == "" {
		t.Fatal("expected a verify key")
	}
}

// TestVerifyKeySelfHeals: key files written before signing existed have no
// signing-key comment. VerifyKey must unlock once, derive it, and write the
// comment back so the next call is silent again.
func TestVerifyKeySelfHeals(t *testing.T) {
	tempHome(t)
	const pass = "hunter2"
	id, err := Create(pass)
	if err != nil {
		t.Fatal(err)
	}

	// Simulate the old file format by stripping the signing-key comment.
	path, err := Path()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var kept []string
	for line := range strings.SplitSeq(string(data), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), signKeyComment) {
			kept = append(kept, line)
		}
	}
	if err := os.WriteFile(path, []byte(strings.Join(kept, "\n")), 0o600); err != nil {
		t.Fatal(err)
	}

	asked := 0
	got, err := VerifyKey(func() (string, error) { asked++; return pass, nil })
	if err != nil {
		t.Fatal(err)
	}
	if asked == 0 {
		t.Fatal("expected the passphrase to be needed once for the old format")
	}
	key, err := crypto.DeriveSigningKey(id)
	if err != nil {
		t.Fatal(err)
	}
	if got != crypto.VerifyKeyString(key) {
		t.Fatalf("derived verify key mismatch: got %q", got)
	}

	// Healed: the comment is back, and the key still unlocks with the passphrase.
	again, err := VerifyKey(func() (string, error) {
		t.Fatal("second call must read the healed comment, not unlock")
		return "", nil
	})
	if err != nil || again != got {
		t.Fatalf("healed file must return the same key silently: %q, %v", again, err)
	}
	if unlocked, err := Load(func() (string, error) { return pass, nil }); err != nil {
		t.Fatalf("healed key file must still unlock: %v", err)
	} else if unlocked.Recipient().String() != id.Recipient().String() {
		t.Fatal("healed key file must hold the same identity")
	}
}
