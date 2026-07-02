package recipients

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
)

// The manifest embeds the recipient list inside the encrypted payload itself, so
// the next push — from any machine — can see who the current blob was encrypted
// for and refuse to silently lock someone out. Unlike recipients.shenv (which
// can drift, be forgotten in a commit, or lose a merge), the manifest travels
// with the blob through every backend and is encrypted+authenticated, so it
// can't be tampered with in transit.
//
// The payload is also signed by the pusher (sign-then-encrypt): the first line
// names the signer and carries an Ed25519 signature over everything after it —
// manifest and env content alike. The recipient keys in recipients.shenv are
// public, so without this anyone could encrypt a replacement blob "for the
// team"; the signature proves a current member produced it.
//
// Format: a "#shenv:signer <name> <sig>" line, then one
// "#shenv:member <name> <key> <sign-key>" line per member, then the env
// content. All lines are valid dotenv comments, so even an unstripped payload
// parses fine; pull/run strip them anyway so the local .env stays clean.

// manifestPrefix marks an embedded member line inside the encrypted payload.
const manifestPrefix = "#shenv:member "

// signerPrefix marks the signature line at the top of the payload.
const signerPrefix = "#shenv:signer "

// signContext domain-separates payload signatures from any other use of the
// same Ed25519 key.
const signContext = "shenv payload v1\n"

// EmbedManifest prepends the member list to the plaintext before encryption.
func EmbedManifest(plaintext []byte, members []Member) []byte {
	var b strings.Builder
	for _, m := range members {
		fmt.Fprintf(&b, "%s%s %s %s\n", manifestPrefix, m.Name, m.Key, m.SignKey)
	}
	return append([]byte(b.String()), plaintext...)
}

// ExtractManifest splits a decrypted payload into the embedded member list and
// the actual plaintext. Member lines from blobs written before signing existed
// have no sign key; they parse with an empty SignKey. Blobs from even older
// shenv versions have no manifest at all and come back with a nil member list
// and the payload untouched.
func ExtractManifest(payload []byte) ([]Member, []byte) {
	var members []Member
	rest := string(payload)
	for {
		line, tail, found := strings.Cut(rest, "\n")
		if !strings.HasPrefix(line, manifestPrefix) || !found {
			break
		}
		fields := strings.Fields(strings.TrimPrefix(line, manifestPrefix))
		if len(fields) != 2 && len(fields) != 3 {
			break // malformed line — treat it and everything after as content
		}
		m := Member{Name: fields[0], Key: fields[1]}
		if len(fields) == 3 {
			m.SignKey = fields[2]
		}
		members = append(members, m)
		rest = tail
	}
	return members, []byte(rest)
}

// SealPayload assembles what push encrypts: the signer line, the member
// manifest, then the env content. The signature covers everything after the
// signer line, so neither the member list nor the secrets can be altered
// without the signer's private key.
func SealPayload(plaintext []byte, members []Member, signer string, key ed25519.PrivateKey) []byte {
	body := EmbedManifest(plaintext, members)
	sig := ed25519.Sign(key, signedBytes(body))
	header := fmt.Sprintf("%s%s %s\n", signerPrefix, signer, base64.RawStdEncoding.EncodeToString(sig))
	return append([]byte(header), body...)
}

// ExtractSignature splits the signer line off a decrypted payload, returning
// the claimed signer, the signature, and the signed body (manifest + env). ok
// is false when the payload carries no signature (blob from an older shenv);
// the payload then passes through as the body.
func ExtractSignature(payload []byte) (signer string, sig []byte, body []byte, ok bool) {
	line, rest, found := strings.Cut(string(payload), "\n")
	if !found || !strings.HasPrefix(line, signerPrefix) {
		return "", nil, payload, false
	}
	fields := strings.Fields(strings.TrimPrefix(line, signerPrefix))
	if len(fields) != 2 {
		return "", nil, payload, false
	}
	raw, err := base64.RawStdEncoding.DecodeString(fields[1])
	if err != nil {
		return "", nil, payload, false
	}
	return fields[0], raw, []byte(rest), true
}

// VerifySignature reports whether sig over body was produced by verifyKey.
func VerifySignature(body, sig []byte, verifyKey ed25519.PublicKey) bool {
	return ed25519.Verify(verifyKey, signedBytes(body), sig)
}

// signedBytes is the exact byte string signatures are computed over.
func signedBytes(body []byte) []byte {
	return append([]byte(signContext), body...)
}
