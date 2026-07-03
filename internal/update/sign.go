package update

// Release signing closes the gap that TLS + checksums leave open: the checksums
// file travels over the same channel as the archive, so anyone who can edit
// release assets (a compromised GitHub account or token, a hostile CDN) can
// regenerate both and verification still "passes". The checksums file is
// therefore signed at release time with the project's Ed25519 release key.
// The public half (or halves, mid-rotation) is embedded below; the private
// half exists only in the RELEASE_SIGNING_KEY GitHub Actions secret (and the
// maintainer's offline backup) — it is never stored in the repo or the release
// itself, so forging a release requires more than control of the GitHub
// account's contents. Generating and rotating that key is documented in
// docs/release-signing.md.
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

// releaseVerifyKeys are the Ed25519 public keys (base64, RawStdEncoding — the
// same encoding as keys in recipients.shenv) that release signatures are
// checked against. A signature is trusted if it verifies under ANY key in this
// list; an empty or all-garbage list fails closed.
//
// The list — rather than a single key — is what makes key rotation possible
// without bricking already-shipped updaters. A binary only trusts the keys it
// was compiled with, and the updater accepts a release only if its signature
// matches one of them, so a one-shot swap of the sole key would make every
// older binary reject every new release and permanently break its
// `shenv update`. To rotate safely you instead ADD the successor key here, ship
// releases signed by it while both keys are trusted, and only remove the
// retired key once enough users have upgraded. See docs/release-signing.md for
// the full procedure. A var (not const) only so tests can substitute keys.
var releaseVerifyKeys = []string{
	"sQrabBts6F9SlNhvnwFw5HRHS8xHHM92frEJKpctvd4",
}

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
// the embedded release keys, accepting it if any of them signed it. Anything
// short of a valid signature is fatal to the update — an unsigned or re-signed
// checksums file vouches for nothing.
func VerifyChecksumsSignature(name string, content, sigText []byte) error {
	return verifyAgainstKeys(releaseVerifyKeys, name, content, sigText)
}

// VerifyWithKey is VerifyChecksumsSignature against a single explicit base64
// public key — used by `release-sign verify` for spot-checking a downloaded
// release against a key supplied out of band.
func VerifyWithKey(verifyKey, name string, content, sigText []byte) error {
	return verifyAgainstKeys([]string{verifyKey}, name, content, sigText)
}

// verifyAgainstKeys accepts sigText when it is a well-formed Ed25519 signature
// over the release message that verifies under at least one of keys. It keeps
// the three failure modes distinct so the error says what to fix: a malformed
// signature, no usable key embedded at all (fail closed — never "no key, so
// skip"), and a good signature that simply matches none of the trusted keys.
func verifyAgainstKeys(keys []string, name string, content, sigText []byte) error {
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(string(sigText)))
	if err != nil || len(raw) != ed25519.SignatureSize {
		return fmt.Errorf("release signature is malformed")
	}
	msg := releaseSigMessage(name, content)
	haveUsableKey := false
	for _, k := range keys {
		pub, err := base64.RawStdEncoding.DecodeString(k)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			continue // skip the unset placeholder or a malformed entry
		}
		haveUsableKey = true
		if ed25519.Verify(ed25519.PublicKey(pub), msg, raw) {
			return nil
		}
	}
	if !haveUsableKey {
		return fmt.Errorf("this build has no valid release verify key embedded — it cannot authenticate releases")
	}
	return fmt.Errorf("release signature verification FAILED — the checksums file was not signed by any of this project's release keys, so the download cannot be trusted")
}
