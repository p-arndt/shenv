// Package crypto wraps age encryption/decryption. It is purely bytes-in/bytes-out
// and knows nothing about where blobs are stored — that is the backend's job.
package crypto

import (
	"bytes"
	"fmt"
	"io"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// EncryptBytes returns an ASCII-armored, encrypted blob that any of the given
// recipients can later decrypt. Armor keeps stored blobs text-friendly.
func EncryptBytes(plaintext []byte, recipients []age.Recipient) ([]byte, error) {
	var buf bytes.Buffer
	armorWriter := armor.NewWriter(&buf)
	w, err := age.Encrypt(armorWriter, recipients...)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil { // flushes the age stream
		return nil, err
	}
	if err := armorWriter.Close(); err != nil { // flushes the armor footer
		return nil, err
	}
	return buf.Bytes(), nil
}

// maxPlaintextSize caps how much decrypted output we buffer. A hostile blob could
// otherwise decompress/stream far beyond its stored size and exhaust memory. .env
// files are tiny; 16 MiB is comfortably above any legitimate secrets file.
const maxPlaintextSize = 16 << 20

// DecryptBytes unwraps an armored blob with the given identity. It returns a clear
// error if this identity isn't among the recipients.
func DecryptBytes(blob []byte, id age.Identity) ([]byte, error) {
	armorReader := armor.NewReader(bytes.NewReader(blob))
	r, err := age.Decrypt(armorReader, id)
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt (are you a member of this repo?): %w", err)
	}
	return readCapped(r, "decrypted content")
}

// readCapped copies r into memory, refusing to buffer more than maxPlaintextSize.
func readCapped(r io.Reader, what string) ([]byte, error) {
	var out bytes.Buffer
	n, err := io.Copy(&out, io.LimitReader(r, maxPlaintextSize+1))
	if err != nil {
		return nil, err
	}
	if n > maxPlaintextSize {
		return nil, fmt.Errorf("%s exceeds the %d-byte limit", what, maxPlaintextSize)
	}
	return out.Bytes(), nil
}

// EncryptWithPassphrase returns an armored blob of data encrypted with a scrypt
// passphrase — used to protect the private key itself at rest.
func EncryptWithPassphrase(data []byte, passphrase string) ([]byte, error) {
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	armorWriter := armor.NewWriter(&buf)
	w, err := age.Encrypt(armorWriter, recipient)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	if err := armorWriter.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// DecryptWithPassphrase decrypts an armored scrypt blob produced by EncryptWithPassphrase.
func DecryptWithPassphrase(blob []byte, passphrase string) ([]byte, error) {
	id, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, err
	}

	armorReader := armor.NewReader(bytes.NewReader(blob))
	r, err := age.Decrypt(armorReader, id)
	if err != nil {
		return nil, fmt.Errorf("wrong passphrase or corrupt key: %w", err)
	}
	return readCapped(r, "decrypted key")
}
