package command

import (
	"os"
	"strings"
	"testing"

	"filippo.io/age"

	"shenv/internal/crypto"
	"shenv/internal/recipients"
)

// These tests cover the two read-side trust anchors: the project id a blob's
// signature is bound to, and the pinned member list it is verified against.

func setProject(t *testing.T, id string) {
	t.Helper()
	content := ""
	if id != "" {
		content = "project = " + id + "\n"
	}
	if err := os.WriteFile("config.shenv", []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func sealEnvFile(t *testing.T, content string) {
	t.Helper()
	writeEnv(t, content)
	feed(t, "y\ny\n")
	if err := Seal(nil); err != nil {
		t.Fatalf("seal: %v", err)
	}
}

func openErr(t *testing.T) error {
	t.Helper()
	os.Remove(defaultEnvFile)
	feed(t, "")
	return Open(nil)
}

// TestOpenRejectsBlobFromAnotherProject is the substitution the binding exists
// for: same member, same keys, trusted in both repos — only the project differs.
func TestOpenRejectsBlobFromAnotherProject(t *testing.T) {
	setup(t)
	mustInit(t)
	setProject(t, "project-a")
	sealEnvFile(t, "TOKEN=from-a\n")
	if err := openErr(t); err != nil {
		t.Fatalf("open inside the sealing project: %v", err)
	}

	setProject(t, "project-b")
	if err := openErr(t); err == nil {
		t.Fatal("a blob sealed for project-a must not open in project-b")
	}
	if _, err := os.Stat(defaultEnvFile); err == nil {
		t.Fatal("a rejected blob must not produce a .env")
	}
}

// TestOpenRejectsUnboundBlobOnceProjectIsSet: a legacy signature names no
// project, which is exactly what a blob from elsewhere looks like.
func TestOpenRejectsUnboundBlobOnceProjectIsSet(t *testing.T) {
	setup(t)
	mustInit(t)
	sealEnvFile(t, "TOKEN=legacy\n")
	if err := openErr(t); err != nil {
		t.Fatalf("unbound blob without a project must keep working: %v", err)
	}

	setProject(t, "project-a")
	err := openErr(t)
	if err == nil || !strings.Contains(err.Error(), "not bound to project") {
		t.Fatalf("want a not-bound error, got %v", err)
	}
}

// TestOpenRejectsBoundBlobWithoutProject: stripping the `project` line from the
// config must not downgrade verification to the unbound form.
func TestOpenRejectsBoundBlobWithoutProject(t *testing.T) {
	setup(t)
	mustInit(t)
	setProject(t, "project-a")
	sealEnvFile(t, "TOKEN=bound\n")

	setProject(t, "")
	if err := openErr(t); err == nil {
		t.Fatal("a bound blob must not verify once the project line is gone")
	}
}

// TestSealMigratesUnboundBlob: the lockout guard still reads the legacy blob's
// manifest, so setting a project and sealing is all a migration takes.
func TestSealMigratesUnboundBlob(t *testing.T) {
	setup(t)
	mustInit(t)
	sealEnvFile(t, "TOKEN=legacy\n")
	setProject(t, "project-a")

	writeEnv(t, "TOKEN=migrated\n")
	feed(t, "") // no prompt may be needed: an unverifiable old blob would ask
	if err := Seal(nil); err != nil {
		t.Fatalf("seal over a legacy blob: %v", err)
	}
	if err := openErr(t); err != nil {
		t.Fatalf("open after migration: %v", err)
	}
	got, _ := os.ReadFile(defaultEnvFile)
	if string(got) != "TOKEN=migrated\n" {
		t.Fatalf("opened %q after migration", got)
	}
}

// addStranger registers a second member behind the pin's back, the way a pulled
// commit would.
func addStranger(t *testing.T) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	signKey, err := crypto.DeriveSigningKey(id)
	if err != nil {
		t.Fatal(err)
	}
	if err := recipients.Add("stranger", id.Recipient().String(), crypto.VerifyKeyString(signKey)); err != nil {
		t.Fatal(err)
	}
}

// TestOpenAsksBeforeTrustingChangedRecipients: the signing keys open verifies
// against come from a file anyone with repo access can edit.
func TestOpenAsksBeforeTrustingChangedRecipients(t *testing.T) {
	setup(t)
	mustInit(t)
	sealEnvFile(t, "TOKEN=x\n")
	addStranger(t)

	if err := openErr(t); err == nil {
		t.Fatal("an unconfirmed member change must block open")
	}
	os.Remove(defaultEnvFile)
	feed(t, "n\n")
	if err := Open(nil); err == nil {
		t.Fatal("a declined member change must block open")
	}

	os.Remove(defaultEnvFile)
	feed(t, "y\n")
	if err := Open(nil); err != nil {
		t.Fatalf("open after confirming: %v", err)
	}
	// Confirmed once — the new list is the pin now.
	if err := openErr(t); err != nil {
		t.Fatalf("open must not ask twice: %v", err)
	}
}

// TestOpenTrustsRecipientsOnFirstUse: a fresh clone has nothing to compare
// against, and CI machines are always fresh.
func TestOpenTrustsRecipientsOnFirstUse(t *testing.T) {
	setup(t)
	mustInit(t)
	sealEnvFile(t, "TOKEN=x\n")
	path, err := pushedRecipientsPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	if err := openErr(t); err != nil {
		t.Fatalf("first use must not prompt: %v", err)
	}
	addStranger(t)
	if err := openErr(t); err == nil {
		t.Fatal("first use must pin the list, so the next change is caught")
	}
}

// TestRecipientChangeEnvOverride: non-interactive runs need a way to accept a
// change, and it must be explicit.
func TestRecipientChangeEnvOverride(t *testing.T) {
	setup(t)
	mustInit(t)
	sealEnvFile(t, "TOKEN=x\n")
	addStranger(t)

	t.Setenv("SHENV_TRUST_RECIPIENTS", "1")
	if err := openErr(t); err != nil {
		t.Fatalf("override must accept the change: %v", err)
	}
}
