package command

import (
	"slices"
	"testing"
)

func TestCommandAfterSeparator(t *testing.T) {
	got, err := commandAfterSeparator([]string{"--", "npm", "start"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{"npm", "start"}) {
		t.Errorf("got %v", got)
	}

	if _, err := commandAfterSeparator([]string{"npm", "start"}); err == nil {
		t.Error("expected error when `--` is missing")
	}
	if _, err := commandAfterSeparator([]string{"--"}); err == nil {
		t.Error("expected error when nothing follows `--`")
	}
}

func TestMergeEnvSecretsWin(t *testing.T) {
	base := []string{"PATH=/bin", "TOKEN=old"}
	got := mergeEnv(base, map[string]string{"TOKEN": "new", "EXTRA": "1"})

	if slices.Contains(got, "TOKEN=old") {
		t.Error("inherited TOKEN should have been overridden")
	}
	if !slices.Contains(got, "TOKEN=new") {
		t.Error("secret TOKEN=new missing")
	}
	if !slices.Contains(got, "PATH=/bin") {
		t.Error("inherited PATH should be preserved")
	}
	if !slices.Contains(got, "EXTRA=1") {
		t.Error("new secret EXTRA missing")
	}
}
