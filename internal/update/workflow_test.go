package update

import (
	"os"
	"strings"
	"testing"
)

// The updater downloads assets by name, so it has to agree with the workflow
// that uploads them. The shared go-release workflow owns the naming in archive
// style (<binary>_<version>_<os>_<arch>.tar.gz, .zip on windows,
// <binary>_<version>_checksums.txt), and release-sign writes the signature next
// to the checksums file as <file>.sig. Here we pin the caller inputs that
// select those names, and the names the updater derives from them.
func TestReleaseWorkflowMatchesAssetNames(t *testing.T) {
	b, err := os.ReadFile("../../.github/workflows/release.yml")
	if err != nil {
		t.Fatalf("read release.yml: %v", err)
	}
	wf := string(b)
	for _, want := range []struct{ needle, why string }{
		{"uses: p-arndt/.github/.github/workflows/go-release.yml@v1", "the shared workflow defines the asset names"},
		{"binary: shenv", "asset names are prefixed with the binary name"},
		{"main: ./cmd/shenv", "the shipped binary is the CLI, not the repo root"},
		{"sign: true", "shenv update refuses unsigned releases"},
		{`release-sign" sign "$CHECKSUMS"`, "the signature is written as <checksums>.sig"},
		{`release-sign" selfcheck "$CHECKSUMS"`, "a key mismatch must fail the release"},
		{"signing-key: ${{ secrets.RELEASE_SIGNING_KEY }}", "the key reaches sign-command as $RELEASE_SIGNING_KEY"},
	} {
		if !strings.Contains(wf, want.needle) {
			t.Errorf("release.yml does not contain %q (%s)", want.needle, want.why)
		}
	}
	if strings.Contains(wf, "artifact-style: raw") {
		t.Error("release.yml sets artifact-style: raw; the updater expects archives")
	}

	for got, want := range map[string]string{
		ArchiveName("1.2.3", "linux", "amd64"):   "shenv_1.2.3_linux_amd64.tar.gz",
		ArchiveName("1.2.3", "windows", "arm64"): "shenv_1.2.3_windows_arm64.zip",
		ChecksumsName("1.2.3"):                   "shenv_1.2.3_checksums.txt",
		SigName("1.2.3"):                         "shenv_1.2.3_checksums.txt.sig",
	} {
		if got != want {
			t.Errorf("asset name %q, want %q", got, want)
		}
	}
}
