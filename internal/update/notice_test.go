package update

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// seedState writes a cache file into a temp HOME and points the process at it.
func seedState(t *testing.T, st state) {
	t.Helper()
	home := t.TempDir()
	// os.UserHomeDir consults HOME on unix and USERPROFILE on Windows; set both.
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	dir := filepath.Join(home, ".shenv")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(st)
	if err := os.WriteFile(filepath.Join(dir, "update-check.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestNotifyPrintsWhenNewerCached(t *testing.T) {
	// Fresh check so no network refresh is attempted.
	seedState(t, state{LastCheck: time.Now(), Latest: "0.4.0"})
	t.Setenv("SHENV_NO_UPDATE_CHECK", "")

	var buf bytes.Buffer
	NotifyIfAvailable(&buf, "0.3.1")
	if !strings.Contains(buf.String(), "0.4.0") {
		t.Errorf("expected a hint mentioning 0.4.0, got %q", buf.String())
	}
}

func TestNotifySilentWhenCurrent(t *testing.T) {
	seedState(t, state{LastCheck: time.Now(), Latest: "0.3.1"})
	var buf bytes.Buffer
	NotifyIfAvailable(&buf, "0.3.1")
	if buf.Len() != 0 {
		t.Errorf("expected no output when on latest, got %q", buf.String())
	}
}

func TestNotifyRespectsOptOut(t *testing.T) {
	seedState(t, state{LastCheck: time.Now(), Latest: "0.4.0"})
	t.Setenv("SHENV_NO_UPDATE_CHECK", "1")
	var buf bytes.Buffer
	NotifyIfAvailable(&buf, "0.3.1")
	if buf.Len() != 0 {
		t.Errorf("opt-out should silence the notice, got %q", buf.String())
	}
}

func TestNotifySilentForDevBuild(t *testing.T) {
	seedState(t, state{LastCheck: time.Now(), Latest: "0.4.0"})
	var buf bytes.Buffer
	NotifyIfAvailable(&buf, "dev")
	if buf.Len() != 0 {
		t.Errorf("dev builds should never see the notice, got %q", buf.String())
	}
}
