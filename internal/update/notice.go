package update

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// checkInterval is how often the passive notice refreshes its cached "latest
// version" — at most once per this window, so normal commands never repeatedly
// hit the network.
const checkInterval = 24 * time.Hour

// noticeTimeout bounds the background refresh so a slow or unreachable GitHub
// can't delay the user's command by more than this.
const noticeTimeout = 1500 * time.Millisecond

// state is the cached result of the last update check, stored as JSON in
// ~/.shenv/update-check.json.
type state struct {
	LastCheck time.Time `json:"last_check"`
	Latest    string    `json:"latest"` // latest version seen, without a leading "v"
}

// statePath returns the cache file location, alongside the key in ~/.shenv.
func statePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".shenv", "update-check.json"), nil
}

func loadState() state {
	var st state
	path, err := statePath()
	if err != nil {
		return st
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return st
	}
	_ = json.Unmarshal(data, &st) // a corrupt cache just triggers a fresh check
	// The cached version is printed to the terminal on every command, so it gets
	// the same ingress validation as the release tag it came from — a tampered
	// cache file must not become a terminal-escape injection vector.
	if !validVersion(st.Latest) {
		st.Latest = ""
	}
	return st
}

func saveState(st state) {
	path, err := statePath()
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	data, err := json.Marshal(st)
	if err != nil {
		return
	}
	_ = os.WriteFile(path, data, 0o600)
}

// NotifyIfAvailable prints a one-line "newer version available" hint to w when
// the cached latest version is newer than current, then refreshes the cache in
// the background if it's stale. It never blocks longer than noticeTimeout and
// never touches stdout, so machine-readable output stays clean.
//
// The notice always reflects the *previously* cached check: the refresh here
// updates the cache for the next run. That keeps the hot path free of a
// blocking network call while still converging within a day.
//
// Set SHENV_NO_UPDATE_CHECK to any non-empty value to disable it entirely.
func NotifyIfAvailable(w io.Writer, current string) {
	if os.Getenv("SHENV_NO_UPDATE_CHECK") != "" || isDevVersion(current) {
		return
	}
	st := loadState()

	if st.Latest != "" && IsNewer(st.Latest, current) {
		fmt.Fprintf(w, "\nA newer shenv is available: %s (you have %s). Run `shenv update` to upgrade.\n", st.Latest, current)
	}

	if time.Since(st.LastCheck) < checkInterval {
		return
	}
	refresh(NewClient(&http.Client{Timeout: noticeTimeout}), st)
}

// refresh claims the check window immediately (so a hanging network doesn't make
// every run retry), then fetches the latest version bounded by noticeTimeout and
// records it for the next run.
func refresh(c *Client, st state) {
	st.LastCheck = time.Now()
	saveState(st) // claim the window up front, even if the fetch below times out

	ctx, cancel := context.WithTimeout(context.Background(), noticeTimeout)
	defer cancel()

	done := make(chan string, 1)
	go func() {
		rel, err := c.LatestRelease(ctx)
		if err != nil {
			close(done)
			return
		}
		done <- strings.TrimPrefix(rel.Tag, "v")
	}()

	select {
	case v, ok := <-done:
		if ok && v != "" {
			st.Latest = v
			saveState(st)
		}
	case <-ctx.Done():
		// Timed out; leave the claimed window in place and try again next day.
	}
}
