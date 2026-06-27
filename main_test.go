package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseSyncEntryMirrorOption(t *testing.T) {
	target, ok := parseSyncEntry("[MIRROR] lists/server -> synced/server")
	if !ok {
		t.Fatalf("expected entry to parse")
	}

	if target.Writable {
		t.Fatalf("expected writable=false for mirror-only entry")
	}

	if !target.Mirror {
		t.Fatalf("expected mirror=true")
	}

	if target.Source != "lists/server" || target.Destination != "synced/server" {
		t.Fatalf("unexpected target mapping: %+v", target)
	}
}

func TestSyncReadOnlyFilesMirrorDeletesMissingRemoteFiles(t *testing.T) {
	baseDir := t.TempDir()

	mustWriteFile(t, filepath.Join(baseDir, "synced", "dir", "keep.txt"), "old-keep")
	mustWriteFile(t, filepath.Join(baseDir, "synced", "dir", "delete.txt"), "delete")

	cfg := &Config{BaseDir: baseDir}
	rules := []SyncTarget{{
		Source:      "server/dir",
		Destination: "synced/dir",
		Mirror:      true,
	}}

	remoteFiles := []FileState{{
		Path:    "server/dir/keep.txt",
		Content: "new-keep",
		Hash:    "hash-keep",
	}}

	lastLocal := make(map[string]string)
	lastRemote := make(map[string]string)

	syncReadOnlyFiles(cfg, rules, remoteFiles, lastLocal, lastRemote)

	keepPath := filepath.Join(baseDir, "synced", "dir", "keep.txt")
	deletedPath := filepath.Join(baseDir, "synced", "dir", "delete.txt")

	data, err := os.ReadFile(keepPath)
	if err != nil {
		t.Fatalf("expected keep file to exist: %v", err)
	}

	if string(data) != "new-keep" {
		t.Fatalf("expected keep file content to be updated, got %q", string(data))
	}

	if _, err := os.Stat(deletedPath); !os.IsNotExist(err) {
		t.Fatalf("expected deleted file to be removed, stat err=%v", err)
	}
}

func TestSyncReadOnlyFilesMirrorDeletesSingleFileWhenRemoteMissing(t *testing.T) {
	baseDir := t.TempDir()
	localPath := filepath.Join(baseDir, "synced", "single.txt")
	mustWriteFile(t, localPath, "stale")

	cfg := &Config{BaseDir: baseDir}
	rules := []SyncTarget{{
		Source:      "server/single.txt",
		Destination: "synced/single.txt",
		Mirror:      true,
	}}

	syncReadOnlyFiles(cfg, rules, nil, map[string]string{}, map[string]string{})

	if _, err := os.Stat(localPath); !os.IsNotExist(err) {
		t.Fatalf("expected mirrored single file to be removed, stat err=%v", err)
	}
}

func TestIsWriteAllowedForWritableDirectoryRule(t *testing.T) {
	entries := []string{"[RW] server/dir -> client/dir"}

	if !isWriteAllowed(entries, "server/dir/new.txt") {
		t.Fatalf("expected write to be allowed for file under writable directory rule")
	}
}

func TestIsWriteAllowedRejectsNonWritableRule(t *testing.T) {
	entries := []string{"server/dir -> client/dir"}

	if isWriteAllowed(entries, "server/dir/new.txt") {
		t.Fatalf("expected write to be rejected for non-writable rule")
	}
}

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
