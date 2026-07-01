package command

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// stdin is a shared buffered reader so successive line reads (e.g. a passphrase
// followed by its confirmation, when piped) don't drop buffered input.
var stdin = bufio.NewReader(os.Stdin)

// readSecret reads one secret line. On a real terminal it disables echo; when
// input is piped (tests, scripts) it falls back to a plain line read.
func readSecret(promptText string) (string, error) {
	fmt.Print(promptText)
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		b, err := term.ReadPassword(fd)
		fmt.Println()
		if err != nil {
			return "", err
		}
		return string(b), nil
	}
	line, err := stdin.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// readNewPassphrase prompts for a passphrase at init time. An empty answer means
// "no passphrase" (the key stays plaintext, protected only by file permissions).
func readNewPassphrase() (string, error) {
	pass, err := readSecret("Set a passphrase to encrypt your key (leave empty for none): ")
	if err != nil {
		return "", err
	}
	if pass == "" {
		return "", nil
	}
	again, err := readSecret("Confirm passphrase: ")
	if err != nil {
		return "", err
	}
	if pass != again {
		return "", fmt.Errorf("passphrases do not match")
	}
	return pass, nil
}

// askPassphrase prompts to unlock an existing encrypted key.
func askPassphrase() (string, error) {
	return readSecret("Enter passphrase for your key: ")
}
