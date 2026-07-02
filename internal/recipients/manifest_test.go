package recipients

import (
	"bytes"
	"testing"
)

func TestManifestRoundTrip(t *testing.T) {
	members := []Member{
		{Name: "alice", Key: "age1alice"},
		{Name: "bob", Key: "age1bob"},
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
