// Command release-sign manages the release signing key that authenticates
// shenv's published checksums files (see internal/update/sign.go for the trust
// model). It is release tooling only — never shipped to users.
//
//	release-sign gen <keyfile>    Generate the release keypair. The private key
//	                              (a base64 Ed25519 seed) is written to keyfile
//	                              with mode 0600 and never printed; the public
//	                              key — the half embedded in internal/update —
//	                              goes to stdout. Put the keyfile's content in
//	                              the RELEASE_SIGNING_KEY GitHub Actions secret,
//	                              back it up somewhere offline, and never commit it.
//	release-sign sign <file>      Sign file with the key from the
//	                              RELEASE_SIGNING_KEY environment variable,
//	                              writing <file>.sig. Used by the release workflow.
//	release-sign verify <file> <verify-key>
//	                              Check <file>.sig against a public key — a local
//	                              sanity check for a downloaded release.
//	release-sign selfcheck <file> Check <file>.sig against the public key embedded
//	                              in internal/update — the same check shipped
//	                              updaters run. The release workflow runs this
//	                              after signing so a key mismatch fails the
//	                              release instead of stranding updaters.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"

	"shenv/internal/update"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: release-sign gen <keyfile> | sign <file> | verify <file> <verify-key> | selfcheck <file>")
	}
	switch args[0] {
	case "gen":
		if len(args) != 2 {
			return fmt.Errorf("usage: release-sign gen <keyfile>")
		}
		return gen(args[1])
	case "sign":
		if len(args) != 2 {
			return fmt.Errorf("usage: release-sign sign <file> (key in $RELEASE_SIGNING_KEY)")
		}
		return sign(args[1])
	case "verify":
		if len(args) != 3 {
			return fmt.Errorf("usage: release-sign verify <file> <verify-key>")
		}
		return verify(args[1], args[2])
	case "selfcheck":
		if len(args) != 2 {
			return fmt.Errorf("usage: release-sign selfcheck <file>")
		}
		return selfcheck(args[1])
	default:
		return fmt.Errorf("unknown mode %q (want gen, sign, verify, or selfcheck)", args[0])
	}
}

// gen creates the keypair. Refusing to overwrite an existing keyfile guards the
// one copy of a key whose loss would strand every shipped binary's updater.
func gen(keyfile string) error {
	if _, err := os.Lstat(keyfile); err == nil {
		return fmt.Errorf("%s already exists — refusing to overwrite a release key (rotating it strands binaries that embed the old public key)", keyfile)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	seed := base64.RawStdEncoding.EncodeToString(priv.Seed())
	if err := os.WriteFile(keyfile, []byte(seed+"\n"), 0o600); err != nil {
		return err
	}
	fmt.Printf("public key (add to releaseVerifyKeys in internal/update/sign.go):\n  %s\n\n", base64.RawStdEncoding.EncodeToString(pub))
	fmt.Printf("private key written to %s — NOT printed.\n", keyfile)
	fmt.Println("Next:")
	fmt.Println("  1. gh secret set RELEASE_SIGNING_KEY < " + keyfile)
	fmt.Println("  2. back the file up somewhere offline (password manager), then delete it here")
	fmt.Println("  3. never commit it — losing it means shipped updaters can't verify future releases")
	fmt.Println("  Rotating an existing key? Keep the old entry in releaseVerifyKeys")
	fmt.Println("  until users have upgraded — see docs/release-signing.md.")
	return nil
}

// sign reads the base64 seed from RELEASE_SIGNING_KEY and writes <file>.sig.
func sign(file string) error {
	seedB64 := os.Getenv("RELEASE_SIGNING_KEY")
	if seedB64 == "" {
		return fmt.Errorf("RELEASE_SIGNING_KEY is not set")
	}
	seed, err := base64.RawStdEncoding.DecodeString(seedB64)
	if err != nil || len(seed) != ed25519.SeedSize {
		return fmt.Errorf("RELEASE_SIGNING_KEY is not a valid base64 Ed25519 seed")
	}
	content, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	// The signed message includes the file's base name (it carries the release
	// version) — see releaseSigMessage. The updater verifies under that name.
	sig := update.SignChecksums(ed25519.NewKeyFromSeed(seed), filepath.Base(file), content)
	if err := os.WriteFile(file+".sig", []byte(sig+"\n"), 0o644); err != nil {
		return err
	}
	fmt.Printf("signed %s -> %s.sig\n", file, file)
	return nil
}

// verify checks <file>.sig against a public key, for spot-checking a release.
func verify(file, verifyKey string) error {
	content, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(file + ".sig")
	if err != nil {
		return err
	}
	if err := update.VerifyWithKey(verifyKey, filepath.Base(file), content, sig); err != nil {
		return err
	}
	fmt.Println("signature OK")
	return nil
}

// selfcheck verifies <file>.sig against the public key embedded in
// internal/update — exactly the check every shipped updater will run. The
// release workflow runs this right after signing: if RELEASE_SIGNING_KEY has
// drifted from the embedded key (say, a regenerated secret), the release must
// fail here rather than publish assets that would strand every updater.
func selfcheck(file string) error {
	content, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	sig, err := os.ReadFile(file + ".sig")
	if err != nil {
		return err
	}
	if err := update.VerifyChecksumsSignature(filepath.Base(file), content, sig); err != nil {
		return fmt.Errorf("%w\n(the signing key does not match the public key embedded in internal/update/sign.go — publishing this release would strand every shipped updater)", err)
	}
	fmt.Println("signature verifies against the embedded release key")
	return nil
}
