package command

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"filippo.io/age"

	"shenv/internal/backend"
	"shenv/internal/identity"
)

// scriptedBackend is a backend whose reads can fail independently of its writes —
// the situation behind the fail-open guard: a store that denies `get` but happily
// accepts `put`.
type scriptedBackend struct {
	blob   []byte
	getErr error
	puts   int
}

func (b *scriptedBackend) Get() ([]byte, error) {
	if b.getErr != nil {
		return nil, b.getErr
	}
	if b.blob == nil {
		return nil, backend.ErrNotFound
	}
	return append([]byte(nil), b.blob...), nil
}

func (b *scriptedBackend) Put(data []byte) error {
	b.puts++
	b.blob = append([]byte(nil), data...)
	return nil
}

func (b *scriptedBackend) String() string { return "scripted backend" }

// sealInto runs the shared sealing path against the given store with the test's
// identity, the way Seal and Edit do.
func sealInto(t *testing.T, store backend.Backend, pub string, plaintext []byte) (bool, error) {
	t.Helper()
	return sealEnv(plaintext, "test", pub,
		func() (*age.X25519Identity, error) { return identity.Load(unlocker(pub)) },
		func() (backend.Backend, error) { return store, nil })
}

// TestSealAbortsWhenBlobCannotBeRead: a read failure is not an absent blob. A
// store that denies reads but accepts writes would otherwise pass the lockout
// guard unchallenged and overwrite a blob nobody compared.
func TestSealAbortsWhenBlobCannotBeRead(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"access denied", errors.New("access denied")},
		{"transient failure", errors.New("service unavailable, try again")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setup(t)
			pub := mustInit(t)
			store := &scriptedBackend{getErr: tc.err}

			feed(t, "") // no prompt may be reachable: this is a hard failure
			sealed, err := sealInto(t, store, pub, []byte("X=1\n"))
			if err == nil {
				t.Fatal("sealing over an unreadable blob must fail")
			}
			if sealed {
				t.Fatal("sealing must not report success")
			}
			if store.puts != 0 {
				t.Fatalf("nothing may be written, got %d put(s)", store.puts)
			}
		})
	}
}

// TestSealProceedsOnGenuineNotFound: the first seal must still work — only a
// genuine "nothing stored yet" grants that permission.
func TestSealProceedsOnGenuineNotFound(t *testing.T) {
	setup(t)
	pub := mustInit(t)
	store := &scriptedBackend{}

	feed(t, "")
	sealed, err := sealInto(t, store, pub, []byte("X=1\n"))
	if err != nil {
		t.Fatalf("first seal: %v", err)
	}
	if !sealed || store.puts != 1 {
		t.Fatalf("first seal should store the blob (sealed=%v puts=%d)", sealed, store.puts)
	}
}

// TestSealRefusesOversizeCiphertext: the manifest and ASCII armor grow a payload
// that already sits near the cap, so the finished blob has to be checked before
// it replaces a readable one.
func TestSealRefusesOversizeCiphertext(t *testing.T) {
	setup(t)
	pub := mustInit(t)
	store := &scriptedBackend{}

	feed(t, "")
	if _, err := sealInto(t, store, pub, []byte("X=1\n")); err != nil {
		t.Fatalf("first seal: %v", err)
	}
	previous := append([]byte(nil), store.blob...)

	feed(t, "")
	big := bytes.Repeat([]byte("A"), backend.MaxBlobSize)
	sealed, err := sealInto(t, store, pub, big)
	if err == nil {
		t.Fatal("a blob past the read cap must be refused")
	}
	if sealed {
		t.Fatal("sealing must not report success")
	}
	if store.puts != 1 || !bytes.Equal(store.blob, previous) {
		t.Fatal("the previous blob must survive untouched")
	}
}

// TestSealRefusesOversizePlaintext: the input is bounded before it is read into
// memory and encrypted, so no blob is produced at all.
func TestSealRefusesOversizePlaintext(t *testing.T) {
	setup(t)
	mustInit(t)
	if err := os.WriteFile(defaultEnvFile, make([]byte, backend.MaxBlobSize+1), 0o600); err != nil {
		t.Fatal(err)
	}

	feed(t, "")
	err := Seal(nil)
	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("expected a size-limit error, got %v", err)
	}
	if _, err := os.Stat(backend.DefaultBlobPath); err == nil {
		t.Fatal("a refused seal must not write a blob")
	}
}
