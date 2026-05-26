package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseSyncTargetsExpandsDirectoryRecursively(t *testing.T) {
	baseDir := t.TempDir()
	mustWriteFile(t, filepath.Join(baseDir, "lists", "devs_whitelist", "alpha.txt"), "alpha")
	mustWriteFile(t, filepath.Join(baseDir, "lists", "devs_whitelist", "nested", "beta.txt"), "beta")

	targets := parseSyncTargets(baseDir, []string{"lists/devs_whitelist"})
	if len(targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(targets))
	}

	expected := map[string]string{
		"lists/devs_whitelist/alpha.txt":       "lists/devs_whitelist/alpha.txt",
		"lists/devs_whitelist/nested/beta.txt": "lists/devs_whitelist/nested/beta.txt",
	}

	for _, target := range targets {
		if target.Writable {
			t.Fatalf("expected directory expansion to keep writable=false")
		}

		if destination, ok := expected[target.Source]; !ok || destination != target.Destination {
			t.Fatalf("unexpected target: %+v", target)
		}
	}
}

func TestParseSyncTargetsExpandsGlobIntoDestinationRoot(t *testing.T) {
	baseDir := t.TempDir()
	mustWriteFile(t, filepath.Join(baseDir, "lists", "devs_whitelist", "alpha.txt"), "alpha")
	mustWriteFile(t, filepath.Join(baseDir, "lists", "devs_whitelist", "skip.log"), "skip")

	targets := parseSyncTargets(baseDir, []string{"[RW] lists/devs_whitelist/*.txt -> synced/devs_whitelist"})
	if len(targets) != 1 {
		t.Fatalf("expected 1 target, got %d", len(targets))
	}

	target := targets[0]
	if !target.Writable {
		t.Fatalf("expected glob expansion to keep writable=true")
	}

	if target.Source != "lists/devs_whitelist/alpha.txt" {
		t.Fatalf("unexpected source path: %s", target.Source)
	}

	if target.Destination != "synced/devs_whitelist/alpha.txt" {
		t.Fatalf("unexpected destination path: %s", target.Destination)
	}
}

func TestResolveSyncDestinationMatchesRemoteGlobWithoutLocalFile(t *testing.T) {
	rule := SyncTarget{
		Source:      "lists/devs_whitelist/*.txt",
		Destination: "lists/devs_whitelist",
	}

	destination, ok := resolveSyncDestination(rule, "lists/devs_whitelist/alpha.txt")
	if !ok {
		t.Fatalf("expected glob rule to match remote file")
	}

	if destination != "lists/devs_whitelist/alpha.txt" {
		t.Fatalf("unexpected destination path: %s", destination)
	}
}

func TestResolveSyncDestinationMatchesRemoteDirectoryWithoutLocalFile(t *testing.T) {
	rule := SyncTarget{
		Source:      "lists/devs_whitelist",
		Destination: "lists/devs_whitelist",
	}

	destination, ok := resolveSyncDestination(rule, "lists/devs_whitelist/nested/beta.txt")
	if !ok {
		t.Fatalf("expected directory rule to match remote file")
	}

	if destination != "lists/devs_whitelist/nested/beta.txt" {
		t.Fatalf("unexpected destination path: %s", destination)
	}
}

func mustWriteFile(t *testing.T, path, content string) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}

	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write failed: %v", err)
	}
}
