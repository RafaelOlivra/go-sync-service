package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
)

type rotatingLogWriter struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	file     *os.File
	size     int64
}

func setupLogging(cfg *Config) (func(), error) {
	writer, err := newRotatingLogWriter(cfg.LogFile, int64(cfg.LogMaxSizeMB)*1024*1024)
	if err != nil {
		return nil, err
	}

	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.LUTC)
	log.SetOutput(writer)
	log.Printf("logging to %s (max %d MB)", cfg.LogFile, cfg.LogMaxSizeMB)

	return func() {
		_ = writer.Close()
	}, nil
}

func newRotatingLogWriter(path string, maxBytes int64) (*rotatingLogWriter, error) {
	if maxBytes <= 0 {
		maxBytes = 10 * 1024 * 1024
	}

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, err
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, err
	}

	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}

	writer := &rotatingLogWriter{
		path:     path,
		maxBytes: maxBytes,
		file:     file,
		size:     info.Size(),
	}

	if writer.size >= writer.maxBytes {
		if err := writer.rotateLocked(); err != nil {
			_ = file.Close()
			return nil, err
		}
	}

	return writer, nil
}

func (w *rotatingLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return 0, io.ErrClosedPipe
	}

	if w.size+int64(len(p)) > w.maxBytes && w.size > 0 {
		if err := w.rotateLocked(); err != nil {
			return 0, err
		}
	}

	n, err := w.file.Write(p)
	w.size += int64(n)
	return n, err
}

func (w *rotatingLogWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return nil
	}

	err := w.file.Close()
	w.file = nil
	return err
}

func (w *rotatingLogWriter) rotateLocked() error {
	if w.file != nil {
		if err := w.file.Close(); err != nil {
			return err
		}
	}

	backupPath := w.path + ".1"
	_ = os.Remove(backupPath)
	if err := os.Rename(w.path, backupPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	file, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}

	w.file = file
	w.size = 0
	return nil
}

func (w *rotatingLogWriter) String() string {
	return fmt.Sprintf("rotatingLogWriter(%s)", w.path)
}
