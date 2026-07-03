package update

// Release signing closes the gap that TLS + checksums leave open: the checksums
// file travels over the same channel as the archive, so anyone who can edit
// release assets (a compromised GitHub account or token, a hostile CDN) can
// regenerate both and verification still "passes". The checksums file is
// therefore signed at release time with the project's Ed25519 release key.
// The public half is embedded below; the private half exists only in the
// RELEASE_SIGNING_KEY GitHub Actions secret (and the maintainer's offline
// backup) — it is never stored in the repo or the release itself, so forging a
// release requires more than control of the GitHub account's contents.
//
// The signed message is domain-separated and includes the checksums file's
// *name*, which carries the version: a signature for shenv_0.3.1_checksums.txt
// can never vouch for a release claiming to be 0.4.0, so replaying an old,
// genuinely-signed release under a newer tag fails too.
//
// Same primitives and encodings as internal/crypto's member signing (Ed25519,
// base64 RawStdEncoding, domain-separation string) — one signing idiom repo-wide.

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
)

// releaseVerifyKey is the Ed25519 public key (base64, RawStdEncoding — the same
// encoding as keys in recipients.shenv) that release signatures are checked
// against. A var only so tests can substitute their own keypair.
var releaseVerifyKey = "sQrabBts6F9SlNhvnwFw5HRHS8xHHM92frEJKpctvd4"

// releaseSigDomain domain-separates release signatures from env.shenv member
// signatures and anything else that might ever be signed with Ed25519 here.
const releaseSigDomain = "shenv release checksums v1"

// releaseSigMessage builds the exact bytes that are signed: domain, then the
// checksums file's name (binding the version), then its content.
func releaseSigMessage(name string, content []byte) []byte {
	return append([]byte(releaseSigDomain+"\n"+name+"\n"), content...)
}

// SigName is the signature asset's file name for a version.
func SigName(version string) string {
	return ChecksumsName(version) + ".sig"
}

// SignChecksums signs a checksums file for release, returning the base64
// signature text. Used only by the release tooling (cmd/release-sign) — the
// updater never signs anything.
func SignChecksums(priv ed25519.PrivateKey, name string, content []byte) string {
	return base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, releaseSigMessage(name, content)))
}

// VerifyChecksumsSignature checks sigText (as produced by SignChecksums,
// surrounding whitespace tolerated) over the named checksums content against
// the embedded release key. Anything short of a valid signature is fatal to the
// update — an unsigned or re-signed checksums file vouches for nothing.
func VerifyChecksumsSignature(name string, content, sigText []byte) error {
	return VerifyWithKey(releaseVerifyKey, name, content, sigText)
}

// VerifyWithKey is VerifyChecksumsSignature against an explicit base64 public
// key — used by `release-sign verify` for spot-checking a downloaded release.
func VerifyWithKey(verifyKey, name string, content, sigText []byte) error {
	pub, err := base64.RawStdEncoding.DecodeString(verifyKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("this build has no valid release verify key embedded — it cannot authenticate releases")
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(sigText)))
	if err != nil || len(raw) != ed25519.SignatureSize {
		return fmt.Errorf("release signature is malformed")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), releaseSigMessage(name, content), raw) {
		return fmt.Errorf("release signature verification FAILED — the checksums file was not signed by this project's release key, so the download cannot be trusted")
	}
	return nil
}
