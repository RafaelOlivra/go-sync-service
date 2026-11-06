package main

import (
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestReadAllSkipsNamedPipe(t *testing.T) {
	baseDir := t.TempDir()
	mustWriteFile(t, filepath.Join(baseDir, "lists", "original (copy).txt"), "copy")
	pipe := filepath.Join(baseDir, "lists", ".copy.tmp")
	if err := syscall.Mkfifo(pipe, 0600); err != nil {
		t.Fatal(err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		files, err := readAllFiles(baseDir, []string{"lists"})
		if err != nil {
			t.Error(err)
			return
		}
		if len(files) != 1 || files[0].Path != "lists/original (copy).txt" {
			t.Errorf("expected only the regular file, got %+v", files)
		}
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		// Unblock a regressed reader before cleaning up the test directory.
		f, err := os.OpenFile(pipe, os.O_RDWR|syscall.O_NONBLOCK, 0)
		if err != nil {
			t.Fatalf("unblock pipe: %v", err)
		}
		_ = f.Close()
		<-done
		t.Fatal("reading a named pipe blocked the sync snapshot")
	}
}

func TestReadAllReportsReadFailure(t *testing.T) {
	baseDir := t.TempDir()
	mustWriteFile(t, filepath.Join(baseDir, "good.txt"), "good")
	if err := os.Symlink("loop", filepath.Join(baseDir, "loop")); err != nil {
		t.Fatal(err)
	}

	files, err := readAllFiles(baseDir, []string{"good.txt", "loop"})
	if !errors.Is(err, syscall.ELOOP) || files != nil {
		t.Fatalf("expected failed snapshot, got files=%+v err=%v", files, err)
	}

	server, client := net.Pipe()
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	done := make(chan struct{})
	go func() {
		defer close(done)
		handleConnection(server, &Config{
			BaseDir: baseDir, SyncFiles: []string{"good.txt", "loop"}, APIKey: "test",
		})
	}()
	if err := json.NewEncoder(client).Encode(Request{Type: "READ_ALL", Key: "test"}); err != nil {
		t.Fatal(err)
	}
	var response Response
	if err := json.NewDecoder(client).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Status != "error" || response.Error == "" || len(response.Files) != 0 {
		t.Fatalf("expected explicit failure without partial snapshot, got %+v", response)
	}
	<-done
}
