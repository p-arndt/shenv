package update

// Regression tests for the security hardening: each test encodes an attack that
// the update path must refuse — hostile release metadata, plaintext downloads,
// and oversized payloads that would otherwise install truncated.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestValidVersion(t *testing.T) {
	good := []string{"0.3.1", "0.3.2-pre.4", "1.0.0-beta.1+build.5", "10.20.30"}
	for _, v := range good {
		if !validVersion(v) {
			t.Errorf("validVersion(%q) = false, want true", v)
		}
	}
	bad := []string{
		"",                         // empty
		"dev",                      // not a release
		"v1.2.3",                   // callers must strip the "v" first
		"1.2.3\x1b[2J",             // ANSI escape smuggled into a tag
		"1.2.3\n4.5.6",             // newline injection
		"1.2.3 ",                   // whitespace
		"../1.2.3",                 // path-ish
		strings.Repeat("1", 65),    // over length bound
		"\x1b]0;pwned\x07" + "1.0", // must start with a digit
	}
	for _, v := range bad {
		if validVersion(v) {
			t.Errorf("validVersion(%q) = true, want false", v)
		}
	}
}

// A tag carrying terminal escapes must be rejected at ingress — it would
// otherwise flow into terminal output, the on-disk cache, and asset names.
func TestLatestReleaseRejectsHostileTag(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/p-arndt/shenv/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(Release{Tag: "v9.9.9\x1b[2J\x1b[8m"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := &Client{HTTP: srv.Client(), APIBase: srv.URL, Owner: "p-arndt", Repo: "shenv"}

	if _, err := c.LatestRelease(context.Background()); err == nil {
		t.Fatal("a tag with terminal escapes must be refused")
	}
}

func TestAllowedURL(t *testing.T) {
	ok := []string{
		"https://api.github.com/x",
		"https://objects.githubusercontent.com/y",
		"http://127.0.0.1:8080/test", // loopback http for tests
		"http://localhost:9/test",
		"http://[::1]:9/test",
	}
	for _, u := range ok {
		if err := allowedURL(u); err != nil {
			t.Errorf("allowedURL(%q) = %v, want nil", u, err)
		}
	}
	bad := []string{
		"http://example.com/shenv.tar.gz", // plaintext to the internet
		"http://192.168.1.1/x",            // plaintext, non-loopback
		"ftp://example.com/x",
		"file:///etc/passwd",
		"://not a url",
	}
	for _, u := range bad {
		if err := allowedURL(u); err == nil {
			t.Errorf("allowedURL(%q) = nil, want error", u)
		}
	}
}

// An asset URL pointing at plain http (what a tampered release or API response
// would use to enable an on-path swap) must abort before any bytes are trusted.
func TestSelfUpdateRejectsPlainHTTPAsset(t *testing.T) {
	version := "9.9.9"
	archiveName := ArchiveName(version, "linux", "amd64") // name only has to exist
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/p-arndt/shenv/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(Release{Tag: "v" + version, Assets: []Asset{
			{Name: archiveName, URL: "http://evil.example.com/swap.tar.gz"},
			{Name: ChecksumsName(version), URL: "http://evil.example.com/sums.txt"},
		}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := &Client{HTTP: srv.Client(), APIBase: srv.URL, Owner: "p-arndt", Repo: "shenv"}

	got, err := c.download(context.Background(), "http://evil.example.com/swap.tar.gz", "release archive")
	if err == nil || got != nil {
		t.Fatal("plain-http asset download must be refused")
	}
}

// The redirect policy installed by NewClient must refuse an https→http downgrade
// mid-chain, not just validate the first URL.
func TestNewClientRedirectPolicyBlocksDowngrade(t *testing.T) {
	c := NewClient(&http.Client{Timeout: time.Second})
	req, _ := http.NewRequest(http.MethodGet, "http://example.com/step2", nil)
	via := []*http.Request{{}}
	if err := c.HTTP.CheckRedirect(req, via); err == nil {
		t.Fatal("redirect hop to plain http must be refused")
	}
	reqOK, _ := http.NewRequest(http.MethodGet, "https://example.com/step2", nil)
	if err := c.HTTP.CheckRedirect(reqOK, via); err != nil {
		t.Fatalf("https redirect hop should be allowed: %v", err)
	}
}

// NewClient(nil) must not hand back the global http.DefaultClient: it has no
// timeout, and installing our redirect policy on it would mutate shared state.
func TestNewClientNilIsNotDefaultClient(t *testing.T) {
	c := NewClient(nil)
	if c.HTTP == http.DefaultClient {
		t.Fatal("NewClient(nil) must not use http.DefaultClient")
	}
	if c.HTTP.Timeout == 0 {
		t.Error("NewClient(nil) client should have a timeout")
	}
	if http.DefaultClient.CheckRedirect != nil {
		t.Error("http.DefaultClient was mutated")
	}
}

// A checksums line whose hash field isn't clean 64-char hex must never be
// treated as this archive's entry — a hostile hash could carry terminal escapes
// into the mismatch error, and a malformed line vouches for nothing.
func TestVerifyChecksumIgnoresMalformedHash(t *testing.T) {
	name := "shenv_9.9.9_linux_amd64.tar.gz"
	hostile := "\x1b[31mEVIL\x1b[0m  " + name + "\n"
	err := verifyChecksum([]byte("archive"), name, []byte(hostile))
	if err == nil {
		t.Fatal("malformed checksum line must not verify")
	}
	if strings.Contains(err.Error(), "\x1b") {
		t.Fatalf("error message leaks untrusted bytes: %q", err.Error())
	}
}

// Payloads past the cap must be an error, never a silent truncation — a
// truncated binary passed checksum verification (which covers the compressed
// archive, not what it inflates to) and would be installed as corrupt garbage.
func TestOversizedPayloadsRefused(t *testing.T) {
	orig := maxAsset
	t.Cleanup(func() { maxAsset = orig })
	maxAsset = 16

	big := bytes.Repeat([]byte("A"), 64)

	// Extraction: binary inflates past the cap.
	if _, err := extractBinary(makeTarGz(t, "shenv", big), "shenv", false); err == nil {
		t.Error("tar.gz binary past the cap must refuse, not truncate")
	}
	if _, err := extractBinary(makeZip(t, "shenv.exe", big), "shenv.exe", true); err == nil {
		t.Error("zip binary past the cap must refuse, not truncate")
	}

	// Download: response body past the cap.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(big)
	}))
	defer srv.Close()
	c := &Client{HTTP: srv.Client(), APIBase: srv.URL, Owner: "p-arndt", Repo: "shenv"}
	if _, err := c.download(context.Background(), srv.URL+"/big", "release archive"); err == nil {
		t.Error("download past the cap must refuse, not truncate")
	}
}

// A tampered ~/.shenv/update-check.json must not turn the passive notice into a
// terminal-escape injection vector.
func TestNoticeCacheRejectsHostileVersion(t *testing.T) {
	seedState(t, state{LastCheck: time.Now(), Latest: "9.9.9\x1b[2J\x1b]0;pwned\x07"})
	var buf bytes.Buffer
	NotifyIfAvailable(&buf, "0.3.1")
	if buf.Len() != 0 {
		t.Errorf("hostile cached version must be dropped, got %q", buf.String())
	}
}
