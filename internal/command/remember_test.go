package command

import (
	"testing"

	"shenv/internal/identity"
	"shenv/internal/keystore"
)

func TestRememberCachesVerifiedPassphrase(t *testing.T) {
	setup(t)
	if _, err := identity.Create("hunter2"); err != nil {
		t.Fatal(err)
	}
	pub, _ := identity.PublicKey()

	feed(t, "hunter2\n")
	if err := Remember(nil); err != nil {
		t.Fatalf("remember: %v", err)
	}
	if got, ok := keystore.Get(pub); !ok || got != "hunter2" {
		t.Fatalf("passphrase not cached: got=%q ok=%v", got, ok)
	}
}

func TestRememberRejectsPlaintextKey(t *testing.T) {
	setup(t)
	if _, err := identity.Create(""); err != nil {
		t.Fatal(err)
	}
	if err := Remember(nil); err == nil {
		t.Fatal("a plaintext key has no passphrase to remember")
	}
}

// TestRememberDoesNotCacheWrongPassphrase: a passphrase that fails to unlock the
// key must never be stored.
func TestRememberDoesNotCacheWrongPassphrase(t *testing.T) {
	setup(t)
	if _, err := identity.Create("hunter2"); err != nil {
		t.Fatal(err)
	}
	pub, _ := identity.PublicKey()

	feed(t, "wrong\n")
	if err := Remember(nil); err == nil {
		t.Fatal("a wrong passphrase should fail Remember")
	}
	if _, ok := keystore.Get(pub); ok {
		t.Fatal("a wrong passphrase must not be cached")
	}
}

func TestForget(t *testing.T) {
	setup(t)
	pub := mustInit(t)
	if err := keystore.Set(pub, "hunter2"); err != nil {
		t.Fatal(err)
	}
	if err := Forget(nil); err != nil {
		t.Fatalf("forget: %v", err)
	}
	if _, ok := keystore.Get(pub); ok {
		t.Fatal("passphrase should be gone after forget")
	}
}

func TestForgetNoIdentity(t *testing.T) {
	setup(t)
	if err := Forget(nil); err == nil {
		t.Fatal("forget without an identity should error")
	}
}

// TestUnlockerPrefersCache: when the keychain has the passphrase, unlocker returns
// it without prompting.
func TestUnlockerPrefersCache(t *testing.T) {
	setup(t)
	const pub = "age1self"
	if err := keystore.Set(pub, "cached-pass"); err != nil {
		t.Fatal(err)
	}
	feed(t, "") // must not read from stdin
	got, err := unlocker(pub)()
	if err != nil {
		t.Fatal(err)
	}
	if got != "cached-pass" {
		t.Fatalf("got %q, want the cached passphrase", got)
	}
}

// TestUnlockerFallsBackToPrompt: a cache miss prompts the user.
func TestUnlockerFallsBackToPrompt(t *testing.T) {
	setup(t)
	feed(t, "typed-pass\n")
	got, err := unlocker("age1uncached")()
	if err != nil {
		t.Fatal(err)
	}
	if got != "typed-pass" {
		t.Fatalf("got %q, want the typed passphrase", got)
	}
}

func TestOfferToRemember(t *testing.T) {
	setup(t)
	const pub = "age1self"

	feed(t, "n\n")
	offerToRemember(pub, "hunter2")
	if _, ok := keystore.Get(pub); ok {
		t.Fatal("declining should not cache the passphrase")
	}

	feed(t, "y\n")
	offerToRemember(pub, "hunter2")
	if got, ok := keystore.Get(pub); !ok || got != "hunter2" {
		t.Fatalf("accepting should cache the passphrase, got=%q ok=%v", got, ok)
	}
}
