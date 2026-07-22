package command

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"shenv/internal/buildinfo"
	"shenv/internal/style"
	"shenv/internal/update"
)

// updateTimeout bounds the whole check-download-verify-install cycle. Generous
// compared to the passive notice, since the user explicitly asked to update.
const updateTimeout = 60 * time.Second

// Update self-updates the running binary to the latest published release,
// verifying the download's checksum before swapping it in. With --check it only
// reports whether a newer version exists and does nothing else.
func Update(args []string) error {
	checkOnly := false
	for _, a := range args {
		switch a {
		case "--check", "-n":
			checkOnly = true
		default:
			return fmt.Errorf("usage: shenv update [--check]")
		}
	}

	current := buildinfo.Version
	client := update.NewClient(&http.Client{Timeout: updateTimeout})
	ctx, cancel := context.WithTimeout(context.Background(), updateTimeout)
	defer cancel()

	if !checkOnly {
		fmt.Printf("Current version: %s. Checking for updates…\n", current)
	}
	res, err := client.SelfUpdate(ctx, current, checkOnly)
	if err != nil {
		return err
	}

	if !update.IsNewer(res.Latest, res.Current) {
		fmt.Println(style.Good(fmt.Sprintf("You're on the latest version (%s).", res.Current)))
		return nil
	}
	if checkOnly {
		fmt.Printf("%s %s (you have %s). Run `shenv update` to upgrade.\n", style.Warn("A newer version is available:"), style.Bold(res.Latest), res.Current)
		return nil
	}
	fmt.Println(style.Good(fmt.Sprintf("Updated shenv %s → %s.", res.Current, res.Latest)))
	return nil
}
