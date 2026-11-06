package main

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReadAllHandlesDuplicateAndTemporaryNames(t *testing.T) {
	baseDir := t.TempDir()
	names := []string{"original.txt", "original (copy).txt", ".original.txt.tmp"}
	for _, name := range names {
		mustWriteFile(t, filepath.Join(baseDir, "lists", name), name)
	}

	files, err := readAllFiles(baseDir, []string{"lists", "already-renamed.tmp"})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != len(names) {
		t.Fatalf("expected %d files, got %d", len(names), len(files))
	}
	for _, name := range names {
		file, ok := findRemoteFile(files, "lists/"+name)
		if !ok || file.Content != name {
			t.Fatalf("missing or incorrect duplicate/temp file %q", name)
		}
	}
}

func TestBuildFileStateRejectsNonRegularFile(t *testing.T) {
	_, err := buildFileState(t.TempDir(), "directory")
	if !errors.Is(err, errNotRegularFile) {
		t.Fatalf("expected non-regular file error, got %v", err)
	}
}

func TestClientRequestsTimeoutWithoutResponse(t *testing.T) {
	requests := map[string]func(*Config) error{
		"READ_ALL": func(cfg *Config) error {
			_, err := sendReadAllOnce(cfg)
			return err
		},
		"WRITE": func(cfg *Config) error {
			return sendWriteOnce(cfg, FileState{Path: "file.txt", Content: "test"})
		},
	}
	for name, request := range requests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()

			done := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					done <- err
					return
				}
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(40 * time.Second))
				var req Request
				if err := json.NewDecoder(conn).Decode(&req); err != nil {
					done <- err
					return
				}
				_, err = io.Copy(io.Discard, conn)
				done <- err
			}()

			start := time.Now()
			err = request(&Config{ServerAddr: listener.Addr().String()})
			var netErr net.Error
			if !errors.As(err, &netErr) || !netErr.Timeout() {
				t.Errorf("expected response timeout, got %v", err)
			}
			if elapsed := time.Since(start); elapsed < 29*time.Second || elapsed > 38*time.Second {
				t.Errorf("expected a 30s request deadline, elapsed %s", elapsed)
			}
			if err := <-done; err != nil {
				t.Errorf("test server: %v", err)
			}
		})
	}
}

func TestLoadConfigDefaultsInvalidPollInterval(t *testing.T) {
	testCases := []struct {
		name     string
		interval string
	}{
		{name: "unset"},
		{name: "zero", interval: "0s"},
		{name: "negative", interval: "-1s"},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			configPath := filepath.Join(t.TempDir(), ".env")
			contents := "APP_MODE=client\n"
			if testCase.interval != "" {
				contents += "POLL_INTERVAL=" + testCase.interval + "\n"
			}

			if err := os.WriteFile(configPath, []byte(contents), 0644); err != nil {
				t.Fatalf("write config: %v", err)
			}

			config, err := loadConfig(configPath)
			if err != nil {
				t.Fatalf("load config: %v", err)
			}

			if config.PollInterval != 10*time.Second {
				t.Fatalf("expected default poll interval of 10s, got %s", config.PollInterval)
			}
		})
	}
}

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

func TestMarkWriteDenied(t *testing.T) {
	state := make(map[string]bool)

	if !markWriteDenied(errors.New("WRITE rejected by server for path \"cache/pumpfun_global_traded_devs.json\": writes are disabled for path \"cache/pumpfun_global_traded_devs.json\""), "cache/pumpfun_global_traded_devs.json", state) {
		t.Fatalf("expected write-denied error to be detected")
	}

	if !state["cache/pumpfun_global_traded_devs.json"] {
		t.Fatalf("expected mapping path to be marked as denied")
	}

	if markWriteDenied(errors.New("dial tcp: i/o timeout"), "cache/other.json", state) {
		t.Fatalf("expected non-authorization error to remain unsuppressed")
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
