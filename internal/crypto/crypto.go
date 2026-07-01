// Package crypto wraps age encryption/decryption of files. It is deliberately
// storage-agnostic: it only turns plaintext into an armored blob and back, and
// knows nothing about where that blob is stored.
package crypto

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// EncryptFile reads a plaintext file and writes an ASCII-armored, encrypted blob
// that any of the given recipients can later decrypt. Armor keeps git diffs text-friendly.
func EncryptFile(plaintextPath, outPath string, recipients []age.Recipient) error {
	plaintext, err := os.ReadFile(plaintextPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", plaintextPath, err)
	}

	out, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer out.Close()

	armorWriter := armor.NewWriter(out)
	w, err := age.Encrypt(armorWriter, recipients...)
	if err != nil {
		return err
	}
	if _, err := w.Write(plaintext); err != nil {
		return err
	}
	if err := w.Close(); err != nil { // flushes the age stream
		return err
	}
	return armorWriter.Close() // flushes the armor footer
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

	var out bytes.Buffer
	if _, err := io.Copy(&out, r); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// DecryptFile reads an armored, encrypted blob and returns the plaintext, using the
// given identity to unwrap it. Returns a clear error if this identity isn't a recipient.
func DecryptFile(encPath string, id age.Identity) ([]byte, error) {
	f, err := os.Open(encPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%s not found — has anyone run `shenv push` yet?", encPath)
		}
		return nil, err
	}
	defer f.Close()

	armorReader := armor.NewReader(f)
	r, err := age.Decrypt(armorReader, id)
	if err != nil {
		return nil, fmt.Errorf("cannot decrypt %s (are you a member of this repo?): %w", encPath, err)
	}

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
