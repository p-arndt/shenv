package recipients

import (
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
// Format: one "#shenv:member <name> <key>" line per member, prepended to the
// plaintext. The lines are valid dotenv comments, so even an unstripped payload
// parses fine; pull/run strip them anyway so the local .env stays clean.

// manifestPrefix marks an embedded member line inside the encrypted payload.
const manifestPrefix = "#shenv:member "

// EmbedManifest prepends the member list to the plaintext before encryption.
func EmbedManifest(plaintext []byte, members []Member) []byte {
	var b strings.Builder
	for _, m := range members {
		fmt.Fprintf(&b, "%s%s %s\n", manifestPrefix, m.Name, m.Key)
	}
	return append([]byte(b.String()), plaintext...)
}

// ExtractManifest splits a decrypted payload into the embedded member list and
// the actual plaintext. Blobs from older shenv versions have no manifest lines;
// they come back with a nil member list and the payload untouched.
func ExtractManifest(payload []byte) ([]Member, []byte) {
	var members []Member
	rest := string(payload)
	for {
		line, tail, found := strings.Cut(rest, "\n")
		if !strings.HasPrefix(line, manifestPrefix) || !found {
			break
		}
		fields := strings.Fields(strings.TrimPrefix(line, manifestPrefix))
		if len(fields) != 2 {
			break // malformed line — treat it and everything after as content
		}
		members = append(members, Member{Name: fields[0], Key: fields[1]})
		rest = tail
	}
	return members, []byte(rest)
}
