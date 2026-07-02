package recipients

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestManifestRoundTrip(t *testing.T) {
	members := []Member{
		{Name: "alice", Key: "age1alice", SignKey: "signalice"},
		{Name: "bob", Key: "age1bob", SignKey: "signbob"},
	}
	plaintext := []byte("API_KEY=abc\n# a real comment\nDB=x\n")

	payload := EmbedManifest(plaintext, members)
	got, rest := ExtractManifest(payload)

	if len(got) != 2 || got[0] != members[0] || got[1] != members[1] {
		t.Fatalf("members round trip mismatch: %+v", got)
	}
	if !bytes.Equal(rest, plaintext) {
		t.Fatalf("plaintext round trip mismatch: %q", rest)
	}
}

func TestExtractManifestLegacyPayload(t *testing.T) {
	plaintext := []byte("API_KEY=abc\n")
	members, rest := ExtractManifest(plaintext)
	if members != nil {
		t.Fatalf("legacy payload should have no members, got %+v", members)
	}
	if !bytes.Equal(rest, plaintext) {
		t.Fatalf("legacy payload must pass through untouched, got %q", rest)
	}
}

func TestExtractManifestMalformedLineStops(t *testing.T) {
	payload := []byte("#shenv:member alice age1alice\n#shenv:member broken\nX=1\n")
	members, rest := ExtractManifest(payload)
	if len(members) != 1 || members[0].Name != "alice" {
		t.Fatalf("expected only the valid line, got %+v", members)
	}
	if string(rest) != "#shenv:member broken\nX=1\n" {
		t.Fatalf("malformed line must stay in the content, got %q", rest)
	}
}

func TestEmbedManifestEmptyMembers(t *testing.T) {
	plaintext := []byte("X=1\n")
	if got := EmbedManifest(plaintext, nil); !bytes.Equal(got, plaintext) {
		t.Fatalf("no members must leave the payload untouched, got %q", got)
	}
}

// TestSealPayloadRoundTrip: seal, split the signature back off, verify it, and
// recover members and plaintext untouched.
func TestSealPayloadRoundTrip(t *testing.T) {
	verifyKey, signKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	members := []Member{{Name: "alice", Key: "age1alice", SignKey: "signalice"}}
	plaintext := []byte("API_KEY=abc\n")

	payload := SealPayload(plaintext, members, "alice", signKey)

	signer, sig, body, ok := ExtractSignature(payload)
	if !ok || signer != "alice" {
		t.Fatalf("expected a signature by alice, got ok=%v signer=%q", ok, signer)
	}
	if !VerifySignature(body, sig, verifyKey) {
		t.Fatal("a freshly sealed payload must verify")
	}
	got, rest := ExtractManifest(body)
	if len(got) != 1 || got[0] != members[0] {
		t.Fatalf("members mismatch: %+v", got)
	}
	if !bytes.Equal(rest, plaintext) {
		t.Fatalf("plaintext mismatch: %q", rest)
	}
}

// TestVerifySignatureRejectsTamper: flipping a single byte of the signed body —
// whether in the manifest or the env content — must fail verification.
func TestVerifySignatureRejectsTamper(t *testing.T) {
	verifyKey, signKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := SealPayload([]byte("API_KEY=abc\n"), []Member{{Name: "a", Key: "k", SignKey: "s"}}, "a", signKey)
	_, sig, body, _ := ExtractSignature(payload)

	tampered := bytes.Replace(body, []byte("abc"), []byte("abd"), 1)
	if VerifySignature(tampered, sig, verifyKey) {
		t.Fatal("a tampered env value must not verify")
	}
	tampered = bytes.Replace(body, []byte("#shenv:member a k s"), []byte("#shenv:member a k x"), 1)
	if VerifySignature(tampered, sig, verifyKey) {
		t.Fatal("a tampered manifest must not verify")
	}

	// A signature from a different key must not verify either.
	otherVerify, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if VerifySignature(body, sig, otherVerify) {
		t.Fatal("a foreign verify key must not accept the signature")
	}
}

// TestExtractSignatureUnsignedPayload: payloads without a signer line (older
// shenv) pass through unchanged with ok=false.
func TestExtractSignatureUnsignedPayload(t *testing.T) {
	payload := []byte("#shenv:member a k s\nX=1\n")
	signer, sig, body, ok := ExtractSignature(payload)
	if ok || signer != "" || sig != nil {
		t.Fatalf("unsigned payload must report ok=false, got signer=%q", signer)
	}
	if !bytes.Equal(body, payload) {
		t.Fatalf("unsigned payload must pass through untouched, got %q", body)
	}
}
