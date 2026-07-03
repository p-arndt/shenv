package update

// Each test here encodes a forgery the release signature must defeat: unsigned
// releases, re-signed checksums from a non-release key, tampered content under
// a genuine signature, replaying an old signed release under a new version, and
// builds with no verify key embedded (which must fail closed).

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	sign := withTestReleaseKey(t)
	name := "shenv_1.0.0_checksums.txt"
	content := []byte("abc123  shenv_1.0.0_linux_amd64.tar.gz\n")
	sig := sign(name, content)

	if err := VerifyChecksumsSignature(name, content, []byte(sig)); err != nil {
		t.Fatalf("genuine signature rejected: %v", err)
	}
	// Trailing whitespace (the .sig file ends with a newline) must be tolerated.
	if err := VerifyChecksumsSignature(name, content, []byte(sig+"\n")); err != nil {
		t.Fatalf("signature with trailing newline rejected: %v", err)
	}
}

// A checksums file altered after signing — the "compromised account regenerates
// the assets" attack — must fail even though the signature itself is genuine.
func TestVerifyRejectsTamperedContent(t *testing.T) {
	sign := withTestReleaseKey(t)
	name := "shenv_1.0.0_checksums.txt"
	sig := sign(name, []byte("original content"))

	if err := VerifyChecksumsSignature(name, []byte("attacker content"), []byte(sig)); err == nil {
		t.Fatal("tampered checksums content must not verify")
	}
}

// A signature from any key other than the release key — an attacker signing
// their own checksums — must fail.
func TestVerifyRejectsWrongKey(t *testing.T) {
	withTestReleaseKey(t) // embed key A
	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	name := "shenv_1.0.0_checksums.txt"
	content := []byte("checksums")
	forged := SignChecksums(otherPriv, name, content) // sign with key B

	if err := VerifyChecksumsSignature(name, content, []byte(forged)); err == nil {
		t.Fatal("signature from a non-release key must not verify")
	}
}

// The signed message includes the checksums file's name (which carries the
// version), so a genuinely-signed old release replayed under a newer version's
// asset name must fail.
func TestVerifyRejectsVersionReplay(t *testing.T) {
	sign := withTestReleaseKey(t)
	content := []byte("abc123  shenv_0.3.1_linux_amd64.tar.gz\n")
	oldSig := sign("shenv_0.3.1_checksums.txt", content)

	if err := VerifyChecksumsSignature("shenv_9.9.9_checksums.txt", content, []byte(oldSig)); err == nil {
		t.Fatal("old release's signature must not vouch for a newer version's name")
	}
}

// A build whose embedded verify key is the unset placeholder (or garbage) must
// fail closed — never "no key, skip verification".
func TestVerifyFailsClosedWithoutKey(t *testing.T) {
	orig := releaseVerifyKeys
	t.Cleanup(func() { releaseVerifyKeys = orig })
	for _, key := range []string{"RELEASE-KEY-NOT-SET", "", "not!!base64", base64.RawStdEncoding.EncodeToString([]byte("short"))} {
		releaseVerifyKeys = []string{key}
		if err := VerifyChecksumsSignature("n", []byte("c"), []byte("sig")); err == nil {
			t.Errorf("verify key %q must fail closed", key)
		}
	}
	// A list with no usable key at all (empty, or only garbage entries) must
	// also fail closed rather than "no key, so skip verification".
	for _, keys := range [][]string{{}, {"", "not!!base64"}} {
		releaseVerifyKeys = keys
		if err := VerifyChecksumsSignature("n", []byte("c"), []byte("sig")); err == nil {
			t.Errorf("verify keys %q must fail closed", keys)
		}
	}
}

// Key rotation: while both the retiring key and its successor are embedded, a
// release signed by EITHER must verify. That overlap window is exactly what
// lets a new key roll out before the old one is dropped without stranding
// binaries that trust only one of the two. A signature from an untrusted third
// key must still be rejected.
func TestVerifyAcceptsAnyTrustedKey(t *testing.T) {
	oldPub, oldPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newPub, newPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	orig := releaseVerifyKeys
	t.Cleanup(func() { releaseVerifyKeys = orig })
	releaseVerifyKeys = []string{
		base64.RawStdEncoding.EncodeToString(oldPub),
		base64.RawStdEncoding.EncodeToString(newPub),
	}

	name := "shenv_1.0.0_checksums.txt"
	content := []byte("abc123  shenv_1.0.0_linux_amd64.tar.gz\n")

	for label, priv := range map[string]ed25519.PrivateKey{"retiring key": oldPriv, "successor key": newPriv} {
		sig := SignChecksums(priv, name, content)
		if err := VerifyChecksumsSignature(name, content, []byte(sig)); err != nil {
			t.Errorf("signature from the %s should verify during the rotation overlap: %v", label, err)
		}
	}

	_, strangerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	forged := SignChecksums(strangerPriv, name, content)
	if err := VerifyChecksumsSignature(name, content, []byte(forged)); err == nil {
		t.Error("a signature from an untrusted key must be rejected even while two keys are trusted")
	}
}

func TestVerifyRejectsMalformedSignature(t *testing.T) {
	withTestReleaseKey(t)
	for _, sig := range []string{"", "not base64 !!!", base64.RawStdEncoding.EncodeToString([]byte("too short"))} {
		if err := VerifyChecksumsSignature("n", []byte("c"), []byte(sig)); err == nil {
			t.Errorf("malformed signature %q must not verify", sig)
		}
	}
}

// A release with no .sig asset at all — what an attacker who can't sign would
// publish — must be refused before anything is downloaded.
func TestSelfUpdateRefusesUnsignedRelease(t *testing.T) {
	withTestReleaseKey(t)
	version := "9.9.9"
	mux := http.NewServeMux()
	var base string
	mux.HandleFunc("/repos/p-arndt/shenv/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		// Archive and checksums present, signature absent.
		json.NewEncoder(w).Encode(Release{Tag: "v" + version, Assets: []Asset{
			{Name: ArchiveName(version, "linux", "amd64"), URL: base + "/dl/a"},
			{Name: ArchiveName(version, "windows", "amd64"), URL: base + "/dl/a"},
			{Name: ArchiveName(version, "darwin", "amd64"), URL: base + "/dl/a"},
			{Name: ArchiveName(version, "linux", "arm64"), URL: base + "/dl/a"},
			{Name: ArchiveName(version, "windows", "arm64"), URL: base + "/dl/a"},
			{Name: ArchiveName(version, "darwin", "arm64"), URL: base + "/dl/a"},
			{Name: ChecksumsName(version), URL: base + "/dl/s"},
		}})
	})
	downloaded := false
	mux.HandleFunc("/dl/", func(w http.ResponseWriter, r *http.Request) { downloaded = true })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	base = srv.URL
	c := &Client{HTTP: srv.Client(), APIBase: srv.URL, Owner: "p-arndt", Repo: "shenv"}

	_, err := c.SelfUpdate(t.Context(), "0.3.1", false)
	if err == nil || !strings.Contains(err.Error(), "not signed") {
		t.Fatalf("unsigned release must be refused, got err=%v", err)
	}
	if downloaded {
		t.Error("no asset bytes should be fetched from an unsigned release")
	}
}

func TestSigName(t *testing.T) {
	if got, want := SigName("0.3.2"), "shenv_0.3.2_checksums.txt.sig"; got != want {
		t.Errorf("SigName = %q, want %q", got, want)
	}
}
