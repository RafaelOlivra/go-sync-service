package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Config struct {
	AppMode      string
	ServerAddr   string
	APIKey       string
	BaseDir      string
	SyncFiles    []string
	PollInterval time.Duration
	LogFile      string
	LogMaxSizeMB int

	UseTLS bool
	Cert   string
	Key    string
}

type SyncTarget struct {
	Source      string
	Destination string
	Writable    bool
	Mirror      bool
}

type FileState struct {
	Path      string `json:"path"`
	Content   string `json:"content"`
	Timestamp int64  `json:"timestamp"`
	Hash      string `json:"hash"`
}

type Request struct {
	Type string    `json:"type"`
	Key  string    `json:"key"`
	File FileState `json:"file"`
}

type Response struct {
	Status string      `json:"status"`
	Error  string      `json:"error,omitempty"`
	Files  []FileState `json:"files,omitempty"`
}

var (
	fileLocks = make(map[string]*sync.Mutex)
	lockMu    sync.Mutex

	fileVersions = make(map[string]int64)
	versionMu    sync.Mutex

	connectionSlots = make(chan struct{}, 256)
)

func main() {

	// If --env is provided, load config from that file instead of .env
	envFile := ".env"
	for i, arg := range os.Args {
		if arg == "--env" && i+1 < len(os.Args) {
			envFile = os.Args[i+1]
			break
		}
	}

	cfg, err := loadConfig(envFile)
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	cleanup, err := setupLogging(cfg)
	if err != nil {
		log.Fatalf("log setup error: %v", err)
	}
	defer cleanup()

	switch strings.ToLower(cfg.AppMode) {
	case "server":
		startServer(cfg)
	case "client":
		startClient(cfg)
	default:
		log.Fatalf("invalid APP_MODE")
	}
}

func loadConfig(path string) (*Config, error) {
	env, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	cfg := &Config{}

	lines := strings.Split(string(env), "\n")

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		line = strings.TrimSpace(line)

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "APP_MODE":
			cfg.AppMode = value

		case "SERVER_ADDRESS":
			cfg.ServerAddr = value

		case "API_KEY":
			cfg.APIKey = value

		case "SYNC_BASE_DIR":
			cfg.BaseDir = value

		case "SYNC_FILES":
			if strings.HasPrefix(value, "\"") {
				block := strings.TrimPrefix(value, "\"")
				for {
					if strings.HasSuffix(block, "\"") {
						block = strings.TrimSuffix(block, "\"")
						break
					}

					if i+1 >= len(lines) {
						break
					}

					i++
					nextLine := strings.TrimSpace(lines[i])
					if nextLine == "\"" || nextLine == "\"\"" {
						break
					}

					if block != "" {
						block += "\n"
					}
					block += nextLine
				}

				value = block
			}

			for _, item := range strings.FieldsFunc(value, func(r rune) bool {
				return r == ',' || r == '\n' || r == '\r'
			}) {
				item = strings.TrimSpace(item)
				item = strings.Trim(item, "\"")
				if item != "" {
					cfg.SyncFiles = append(cfg.SyncFiles, item)
				}
			}

		case "POLL_INTERVAL":
			d, err := time.ParseDuration(value)
			if err != nil {
				return nil, err
			}
			cfg.PollInterval = d

		case "LOG_FILE":
			cfg.LogFile = value

		case "LOG_MAX_SIZE_MB":
			maxSize, err := strconv.Atoi(value)
			if err != nil {
				return nil, err
			}
			cfg.LogMaxSizeMB = maxSize

		case "USE_TLS":
			cfg.UseTLS = strings.ToLower(value) == "true"

		case "TLS_CERT":
			cfg.Cert = value

		case "TLS_KEY":
			cfg.Key = value
		}
	}

	if cfg.LogFile == "" {
		cfg.LogFile = "log.txt"
	}

	if cfg.LogMaxSizeMB <= 0 {
		cfg.LogMaxSizeMB = 10
	}

	return cfg, nil
}

func startServer(cfg *Config) {
	var listener net.Listener
	var err error

	if cfg.UseTLS {
		cert, err := tls.LoadX509KeyPair(cfg.Cert, cfg.Key)
		if err != nil {
			log.Fatalf("tls cert error: %v", err)
		}

		tlsCfg := &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

		listener, err = tls.Listen("tcp", cfg.ServerAddr, tlsCfg)
	} else {
		listener, err = net.Listen("tcp", cfg.ServerAddr)
	}

	if err != nil {
		log.Fatalf("listen error: %v", err)
	}

	log.Printf("server listening on %s", cfg.ServerAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}

		select {
		case connectionSlots <- struct{}{}:
			go func() {
				defer func() { <-connectionSlots }()
				handleConnection(conn, cfg)
			}()
		default:
			log.Printf("connection limit reached, dropping connection from %s", conn.RemoteAddr())
			_ = conn.Close()
		}
	}
}

func handleConnection(conn net.Conn, cfg *Config) {
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	var req Request

	limitedReader := io.LimitReader(conn, 100*1024*1024)
	bufReader := bufio.NewReader(limitedReader)

	firstByte, err := bufReader.Peek(1)
	if err != nil {
		if shouldLogDecodeError(err) {
			log.Printf("json decode error from %s: %v", conn.RemoteAddr(), err)
		}
		return
	}

	if len(firstByte) == 1 && firstByte[0] != '{' {
		// Ignore non-JSON protocol probes (for example HTTP health checks) quietly.
		return
	}

	dec := json.NewDecoder(bufReader)
	if err := dec.Decode(&req); err != nil {
		if shouldLogDecodeError(err) {
			log.Printf("json decode error from %s: %v", conn.RemoteAddr(), err)
		}
		return
	}

	_ = conn.SetReadDeadline(time.Time{})

	if !authenticate(req.Key, cfg.APIKey) {
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		sendResponse(conn, Response{
			Status: "error",
			Error:  "authentication failed",
		})

		log.Printf("authentication failed from %s for type=%q path=%q", conn.RemoteAddr(), req.Type, req.File.Path)
		return
	}

	switch req.Type {

	case "WRITE":
		if !isWriteAllowed(cfg.SyncFiles, req.File.Path) {
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			sendResponse(conn, Response{
				Status: "error",
				Error:  fmt.Sprintf("writes are disabled for path %q", req.File.Path),
			})
			log.Printf("reject write from %s: path=%q is not writable by current SYNC_FILES rules", conn.RemoteAddr(), req.File.Path)
			return
		}

		err := handleWrite(cfg.BaseDir, req.File)

		if err != nil {
			_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			sendResponse(conn, Response{
				Status: "error",
				Error:  err.Error(),
			})
			return
		}

		log.Printf("[Client] --> [Server] updated file: %s from %s", req.File.Path, conn.RemoteAddr())

		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		sendResponse(conn, Response{
			Status: "ok",
		})

	case "READ_ALL":
		files := readAllFiles(cfg.BaseDir, cfg.SyncFiles)

		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		sendResponse(conn, Response{
			Status: "ok",
			Files:  files,
		})

	default:
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		sendResponse(conn, Response{
			Status: "error",
			Error:  "invalid request",
		})
		log.Printf("reject request from %s: unknown type=%q", conn.RemoteAddr(), req.Type)
	}
}

func shouldLogDecodeError(err error) bool {
	if err == nil || errors.Is(err, io.EOF) {
		return false
	}

	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "first record does not look like a tls handshake") {
		return false
	}

	if strings.Contains(lower, "invalid character") && strings.Contains(lower, "looking for beginning of value") {
		return false
	}

	if strings.Contains(lower, "connection reset by peer") || strings.Contains(lower, "broken pipe") {
		return false
	}

	return true
}

func handleWrite(baseDir string, file FileState) error {
	resolvedPath, err := safeJoin(baseDir, file.Path)
	if err != nil {
		return err
	}

	lock := getFileLock(resolvedPath)

	lock.Lock()
	defer lock.Unlock()

	versionMu.Lock()
	currentVersion := fileVersions[resolvedPath]

	if file.Timestamp < currentVersion {
		versionMu.Unlock()
		return errors.New("incoming file is older than current version")
	}

	fileVersions[resolvedPath] = file.Timestamp
	versionMu.Unlock()

	err = os.MkdirAll(filepath.Dir(resolvedPath), 0755)
	if err != nil {
		return err
	}

	err = os.WriteFile(resolvedPath, []byte(file.Content), 0644)
	if err != nil {
		return err
	}

	return nil
}

func getFileLock(path string) *sync.Mutex {
	lockMu.Lock()
	defer lockMu.Unlock()

	if l, ok := fileLocks[path]; ok {
		return l
	}

	fileLocks[path] = &sync.Mutex{}
	return fileLocks[path]
}

func startClient(cfg *Config) {
	log.Printf("client started")

	mappings := parseSyncTargets(cfg.BaseDir, cfg.SyncFiles)
	rules := parseSyncRules(cfg.SyncFiles)
	lastLocalHashes := make(map[string]string)
	lastRemoteHashes := make(map[string]string)
	writeDeniedPaths := make(map[string]bool)

	for {
		files, err := sendReadAll(cfg)
		if err != nil {
			log.Printf("sync error: %v", err)
			time.Sleep(cfg.PollInterval)
			continue
		}

		for _, mapping := range mappings {
			if !mapping.Writable {
				continue
			}

			if writeDeniedPaths[mapping.Source] {
				continue
			}

			resolvedDest, err := safeJoin(cfg.BaseDir, mapping.Destination)
			if err != nil {
				log.Printf("invalid destination path: %v", err)
				continue
			}

			localFile, localErr := buildFileState(resolvedDest, mapping.Destination)
			remoteFile, ok := findRemoteFile(files, mapping.Source)
			if localErr != nil && !ok {
				continue
			}

			if localErr != nil {
				if ok {
					if err := writeLocalFile(resolvedDest, remoteFile.Content); err != nil {
						log.Printf("file write error: %v", err)
						continue
					}

					lastRemoteHashes[mapping.Source] = remoteFile.Hash
					lastLocalHashes[resolvedDest] = remoteFile.Hash
					log.Printf("[Server] --> [Client] %s -> %s", mapping.Source, mapping.Destination)
				}
				continue
			}

			if !ok {
				if err := sendWrite(cfg, FileState{
					Path:      mapping.Source,
					Content:   localFile.Content,
					Timestamp: localFile.Timestamp,
					Hash:      localFile.Hash,
				}); err != nil {
					if markWriteDenied(err, mapping.Source, writeDeniedPaths) {
						continue
					}
					log.Printf("sync error: %v", err)
					continue
				}

				lastLocalHashes[resolvedDest] = localFile.Hash
				lastRemoteHashes[mapping.Source] = localFile.Hash
				log.Printf("synced: %s -> %s", mapping.Destination, mapping.Source)
				continue
			}

			lastLocalHash := lastLocalHashes[resolvedDest]
			lastRemoteHash := lastRemoteHashes[mapping.Source]
			localChanged := localFile.Hash != lastLocalHash
			remoteChanged := remoteFile.Hash != lastRemoteHash

			switch {
			case localFile.Hash == remoteFile.Hash:
				lastLocalHashes[resolvedDest] = localFile.Hash
				lastRemoteHashes[mapping.Source] = remoteFile.Hash
				continue

			case localChanged && !remoteChanged:
				if err := sendWrite(cfg, FileState{
					Path:      mapping.Source,
					Content:   localFile.Content,
					Timestamp: localFile.Timestamp,
					Hash:      localFile.Hash,
				}); err != nil {
					if markWriteDenied(err, mapping.Source, writeDeniedPaths) {
						continue
					}
					log.Printf("sync error: %v", err)
					continue
				}

				lastLocalHashes[resolvedDest] = localFile.Hash
				lastRemoteHashes[mapping.Source] = localFile.Hash
				log.Printf("[Client] --> [Server] %s -> %s", mapping.Destination, mapping.Source)

			case remoteChanged && !localChanged:
				if err := writeLocalFile(resolvedDest, remoteFile.Content); err != nil {
					log.Printf("file write error: %v", err)
					continue
				}

				lastLocalHashes[resolvedDest] = remoteFile.Hash
				lastRemoteHashes[mapping.Source] = remoteFile.Hash
				log.Printf("[Server] --> [Client] %s -> %s", mapping.Source, mapping.Destination)

			default:
				if localFile.Timestamp >= remoteFile.Timestamp {
					if err := sendWrite(cfg, FileState{
						Path:      mapping.Source,
						Content:   localFile.Content,
						Timestamp: localFile.Timestamp,
						Hash:      localFile.Hash,
					}); err != nil {
						if markWriteDenied(err, mapping.Source, writeDeniedPaths) {
							continue
						}
						log.Printf("sync error: %v", err)
						continue
					}

					lastLocalHashes[resolvedDest] = localFile.Hash
					lastRemoteHashes[mapping.Source] = localFile.Hash
					log.Printf("[Client] --> [Server] %s -> %s", mapping.Destination, mapping.Source)
				} else {
					if err := writeLocalFile(resolvedDest, remoteFile.Content); err != nil {
						log.Printf("file write error: %v", err)
						continue
					}

					lastLocalHashes[resolvedDest] = remoteFile.Hash
					lastRemoteHashes[mapping.Source] = remoteFile.Hash
					log.Printf("[Server] --> [Client] %s -> %s", mapping.Source, mapping.Destination)
				}
			}
		}

		syncReadOnlyFiles(cfg, rules, files, lastLocalHashes, lastRemoteHashes)

		time.Sleep(cfg.PollInterval)
	}
}

func markWriteDenied(err error, sourcePath string, writeDeniedPaths map[string]bool) bool {
	if err == nil {
		return false
	}

	lower := strings.ToLower(err.Error())
	if !strings.Contains(lower, "writes are disabled") {
		return false
	}

	if writeDeniedPaths[sourcePath] {
		return true
	}

	writeDeniedPaths[sourcePath] = true
	log.Printf("server denied writes for %s; switching this mapping to read-only", sourcePath)
	return true
}

func syncReadOnlyFiles(cfg *Config, rules []SyncTarget, files []FileState, lastLocalHashes, lastRemoteHashes map[string]string) {
	for _, rule := range rules {
		if rule.Writable {
			continue
		}

		expectedDestinations := make(map[string]struct{})

		for _, remoteFile := range files {
			resolvedDest, ok := resolveSyncDestination(rule, remoteFile.Path)
			if !ok {
				continue
			}

			expectedDestinations[resolvedDest] = struct{}{}

			resolvedLocal, err := safeJoin(cfg.BaseDir, resolvedDest)
			if err != nil {
				log.Printf("invalid destination path: %v", err)
				continue
			}

			localFile, localErr := buildFileState(resolvedLocal, resolvedDest)
			if localErr == nil && localFile.Hash == remoteFile.Hash {
				lastLocalHashes[resolvedLocal] = localFile.Hash
				lastRemoteHashes[remoteFile.Path] = remoteFile.Hash
				continue
			}

			if err := writeLocalFile(resolvedLocal, remoteFile.Content); err != nil {
				log.Printf("file write error: %v", err)
				continue
			}

			lastLocalHashes[resolvedLocal] = remoteFile.Hash
			lastRemoteHashes[remoteFile.Path] = remoteFile.Hash
			log.Printf("[Server] --> [Client] %s -> %s", remoteFile.Path, resolvedDest)
		}

		if rule.Mirror {
			applyMirrorDeletions(cfg.BaseDir, rule, expectedDestinations, lastLocalHashes)
		}
	}
}

func applyMirrorDeletions(baseDir string, rule SyncTarget, expectedDestinations map[string]struct{}, lastLocalHashes map[string]string) {
	destinationRoot := normalizeSyncPath(rule.Destination)
	if destinationRoot == "" {
		destinationRoot = defaultDestinationRoot(rule.Source)
	}

	rootAbs, err := safeJoin(baseDir, destinationRoot)
	if err != nil {
		log.Printf("mirror delete skipped for %s: %v", destinationRoot, err)
		return
	}

	pruneAsDirectory := hasGlobMeta(rule.Source) || expectsNestedDestinations(destinationRoot, expectedDestinations)
	if !pruneAsDirectory {
		if info, statErr := os.Stat(rootAbs); statErr == nil && info.IsDir() {
			pruneAsDirectory = true
		}
	}

	if !pruneAsDirectory {
		if _, ok := expectedDestinations[destinationRoot]; ok {
			return
		}

		info, statErr := os.Stat(rootAbs)
		if statErr != nil || info.IsDir() {
			return
		}

		if err := os.Remove(rootAbs); err != nil && !os.IsNotExist(err) {
			log.Printf("mirror delete failed for %s: %v", destinationRoot, err)
			return
		}

		delete(lastLocalHashes, rootAbs)
		log.Printf("[Server] -x- [Client] removed: %s", destinationRoot)
		return
	}

	if info, statErr := os.Stat(rootAbs); statErr != nil || !info.IsDir() {
		return
	}

	var directories []string
	_ = filepath.Walk(rootAbs, func(currentPath string, info os.FileInfo, walkErr error) error {
		if walkErr != nil || info == nil {
			return nil
		}

		if info.IsDir() {
			directories = append(directories, currentPath)
			return nil
		}

		rel, err := filepath.Rel(rootAbs, currentPath)
		if err != nil {
			return nil
		}

		localSyncPath := normalizeSyncPath(filepath.Join(destinationRoot, rel))
		if _, ok := expectedDestinations[localSyncPath]; ok {
			return nil
		}

		if err := os.Remove(currentPath); err != nil && !os.IsNotExist(err) {
			log.Printf("mirror delete failed for %s: %v", localSyncPath, err)
			return nil
		}

		delete(lastLocalHashes, currentPath)
		log.Printf("[Server] -x- [Client] removed: %s", localSyncPath)
		return nil
	})

	for i := len(directories) - 1; i >= 0; i-- {
		dir := directories[i]
		if dir == rootAbs {
			continue
		}
		_ = os.Remove(dir)
	}
}

func expectsNestedDestinations(destinationRoot string, expectedDestinations map[string]struct{}) bool {
	prefix := destinationRoot + "/"
	for destination := range expectedDestinations {
		if strings.HasPrefix(destination, prefix) {
			return true
		}
	}

	return false
}

func sendReadAll(cfg *Config) ([]FileState, error) {
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		files, err := sendReadAllOnce(cfg)
		if err == nil {
			return files, nil
		}

		lastErr = err
		if !isRetryableNetworkError(err) || attempt == 3 {
			break
		}

		time.Sleep(time.Duration(attempt) * 250 * time.Millisecond)
	}

	return nil, lastErr
}

func sendReadAllOnce(cfg *Config) ([]FileState, error) {
	var conn net.Conn
	var err error

	conn, err = dialServer(cfg)

	if err != nil {
		return nil, err
	}

	defer conn.Close()

	req := Request{
		Type: "READ_ALL",
		Key:  cfg.APIKey,
	}

	enc := json.NewEncoder(conn)
	if err := enc.Encode(req); err != nil {
		return nil, err
	}

	dec := json.NewDecoder(conn)
	var resp Response
	if err := dec.Decode(&resp); err != nil {
		return nil, err
	}

	if resp.Status != "ok" {
		return nil, fmt.Errorf("READ_ALL rejected by server: %s", resp.Error)
	}

	return resp.Files, nil
}

func sendWrite(cfg *Config, file FileState) error {
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		err := sendWriteOnce(cfg, file)
		if err == nil {
			return nil
		}

		lastErr = err
		if !isRetryableNetworkError(err) || attempt == 3 {
			break
		}

		time.Sleep(time.Duration(attempt) * 250 * time.Millisecond)
	}

	return lastErr
}

func sendWriteOnce(cfg *Config, file FileState) error {
	var conn net.Conn
	var err error

	conn, err = dialServer(cfg)

	if err != nil {
		return err
	}

	defer conn.Close()

	req := Request{
		Type: "WRITE",
		Key:  cfg.APIKey,
		File: file,
	}

	enc := json.NewEncoder(conn)
	if err := enc.Encode(req); err != nil {
		return err
	}

	dec := json.NewDecoder(conn)
	var resp Response
	if err := dec.Decode(&resp); err != nil {
		return err
	}

	if resp.Status != "ok" {
		return fmt.Errorf("WRITE rejected by server for path %q: %s", file.Path, resp.Error)
	}

	return nil
}

func dialServer(cfg *Config) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}

	if cfg.UseTLS {
		tlsCfg := &tls.Config{
			InsecureSkipVerify: true,
		}

		return tls.DialWithDialer(dialer, "tcp", cfg.ServerAddr, tlsCfg)
	}

	return dialer.Dial("tcp", cfg.ServerAddr)
}

func isRetryableNetworkError(err error) bool {
	if err == nil {
		return false
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return true
		}
	}

	if errors.Is(err, io.EOF) {
		return true
	}

	lower := strings.ToLower(err.Error())
	if strings.Contains(lower, "connection reset") ||
		strings.Contains(lower, "broken pipe") ||
		strings.Contains(lower, "unexpected eof") ||
		strings.Contains(lower, "timeout") ||
		strings.Contains(lower, "refused") {
		return true
	}

	return false
}

func buildFileState(sourcePath, destinationPath string) (FileState, error) {
	data, err := os.ReadFile(sourcePath)
	if err != nil {
		return FileState{}, err
	}

	info, err := os.Stat(sourcePath)
	if err != nil {
		return FileState{}, err
	}

	hash := sha256.Sum256(data)

	return FileState{
		Path:      destinationPath,
		Content:   string(data),
		Timestamp: info.ModTime().Unix(),
		Hash:      hex.EncodeToString(hash[:]),
	}, nil
}

func writeLocalFile(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	return os.WriteFile(path, []byte(content), 0644)
}

func authenticate(incoming, expected string) bool {
	return subtle.ConstantTimeCompare(
		[]byte(incoming),
		[]byte(expected),
	) == 1
}

func sendResponse(conn net.Conn, resp Response) {
	enc := json.NewEncoder(conn)
	enc.Encode(resp)
}

func readAllFiles(baseDir string, paths []string) []FileState {
	var files []FileState

	targets := parseSyncTargets(baseDir, paths)

	for _, target := range targets {
		resolvedPath, err := safeJoin(baseDir, target.Source)
		if err != nil {
			continue
		}

		f, err := buildFileState(resolvedPath, target.Source)
		if err != nil {
			continue
		}

		files = append(files, f)
	}

	return files
}

func parseSyncTargets(baseDir string, entries []string) []SyncTarget {
	targets := make([]SyncTarget, 0, len(entries))

	for _, target := range parseSyncRules(entries) {
		targets = append(targets, expandSyncTarget(baseDir, target)...)
	}

	return targets
}

func parseSyncRules(entries []string) []SyncTarget {
	targets := make([]SyncTarget, 0, len(entries))

	for _, entry := range entries {
		target, ok := parseSyncEntry(entry)
		if !ok {
			continue
		}
		targets = append(targets, target)
	}

	return targets
}

func parseSyncEntry(entry string) (SyncTarget, bool) {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return SyncTarget{}, false
	}

	writable := false
	mirror := false
	for strings.HasPrefix(entry, "[") {
		closeIndex := strings.Index(entry, "]")
		if closeIndex <= 1 {
			break
		}

		option := strings.ToUpper(strings.TrimSpace(entry[1:closeIndex]))
		switch option {
		case "RW":
			writable = true
		case "MIRROR":
			mirror = true
		}

		entry = strings.TrimSpace(entry[closeIndex+1:])
	}

	if entry == "" {
		return SyncTarget{}, false
	}

	separator := "||"
	if strings.Contains(entry, "->") {
		separator = "->"
	}

	parts := strings.SplitN(entry, separator, 2)
	source := normalizeSyncPath(strings.TrimSpace(parts[0]))
	destination := source

	if len(parts) == 2 {
		destination = normalizeSyncPath(strings.TrimSpace(parts[1]))
		if destination == "" {
			destination = source
		}
	}

	return SyncTarget{
		Source:      source,
		Destination: destination,
		Writable:    writable,
		Mirror:      mirror,
	}, true
}

func expandSyncTarget(baseDir string, target SyncTarget) []SyncTarget {
	source := normalizeSyncPath(target.Source)
	if source == "" {
		return nil
	}

	destination := normalizeSyncPath(target.Destination)
	if destination == "" {
		destination = defaultDestinationRoot(source)
	}

	sourceAbs, err := safeJoin(baseDir, source)
	if err != nil {
		return nil
	}

	if info, err := os.Stat(sourceAbs); err == nil && info.IsDir() {
		return expandDirectoryTarget(sourceAbs, source, destination, target.Writable)
	}

	if hasGlobMeta(source) {
		return expandGlobTarget(baseDir, sourceAbs, source, destination, target.Writable)
	}

	return []SyncTarget{{
		Source:      source,
		Destination: destination,
		Writable:    target.Writable,
	}}
}

func expandDirectoryTarget(sourceAbs, sourceRoot, destinationRoot string, writable bool) []SyncTarget {
	targets := make([]SyncTarget, 0)

	_ = filepath.Walk(sourceAbs, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(sourceAbs, path)
		if err != nil {
			return nil
		}

		rel = normalizeSyncPath(rel)
		targets = append(targets, SyncTarget{
			Source:      normalizeSyncPath(filepath.Join(sourceRoot, rel)),
			Destination: normalizeSyncPath(filepath.Join(destinationRoot, rel)),
			Writable:    writable,
		})

		return nil
	})

	return targets
}

func expandGlobTarget(baseDir, sourceAbsPattern, sourcePattern, destinationRoot string, writable bool) []SyncTarget {
	matches, err := filepath.Glob(sourceAbsPattern)
	if err != nil {
		return nil
	}

	sourceRoot := normalizeSyncPath(filepath.Dir(sourcePattern))
	if sourceRoot == "" {
		sourceRoot = "."
	}

	sourceRootAbs, err := safeJoin(baseDir, sourceRoot)
	if err != nil {
		return nil
	}

	targets := make([]SyncTarget, 0, len(matches))
	for _, match := range matches {
		info, err := os.Stat(match)
		if err != nil || info.IsDir() {
			continue
		}

		rel, err := filepath.Rel(sourceRootAbs, match)
		if err != nil {
			continue
		}

		rel = normalizeSyncPath(rel)
		targets = append(targets, SyncTarget{
			Source:      normalizeSyncPath(filepath.Join(sourceRoot, rel)),
			Destination: normalizeSyncPath(filepath.Join(destinationRoot, rel)),
			Writable:    writable,
		})
	}

	return targets
}

func defaultDestinationRoot(source string) string {
	if hasGlobMeta(source) {
		dir := normalizeSyncPath(filepath.Dir(source))
		if dir == "" {
			return "."
		}
		return dir
	}

	return source
}

func resolveSyncDestination(rule SyncTarget, filePath string) (string, bool) {
	ruleSource := normalizeSyncPath(rule.Source)
	filePath = normalizeSyncPath(filePath)
	if ruleSource == "" || filePath == "" {
		return "", false
	}

	destinationRoot := normalizeSyncPath(rule.Destination)
	if destinationRoot == "" {
		destinationRoot = defaultDestinationRoot(ruleSource)
	}

	if !hasGlobMeta(ruleSource) {
		if filePath == ruleSource {
			return destinationRoot, true
		}

		prefix := ruleSource + "/"
		if !strings.HasPrefix(filePath, prefix) {
			return "", false
		}

		rel := strings.TrimPrefix(filePath, prefix)
		if rel == "" {
			return "", false
		}

		return normalizeSyncPath(filepath.Join(destinationRoot, rel)), true
	}

	matched, err := path.Match(ruleSource, filePath)
	if err != nil || !matched {
		return "", false
	}

	sourceRoot := normalizeSyncPath(filepath.Dir(ruleSource))
	if sourceRoot == "." {
		return normalizeSyncPath(filepath.Join(destinationRoot, filepath.Base(filePath))), true
	}

	prefix := sourceRoot + "/"
	if !strings.HasPrefix(filePath, prefix) {
		return "", false
	}

	rel := strings.TrimPrefix(filePath, prefix)
	if rel == "" {
		return "", false
	}

	return normalizeSyncPath(filepath.Join(destinationRoot, rel)), true
}

func hasGlobMeta(path string) bool {
	return strings.ContainsAny(path, "*?[")
}

func normalizeSyncPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}

	cleaned := filepath.Clean(path)
	if cleaned == "." {
		return "."
	}

	return filepath.ToSlash(cleaned)
}

func findSyncTarget(targets []SyncTarget, source string) (SyncTarget, bool) {
	for _, target := range targets {
		if target.Source == source {
			return target, true
		}
	}

	return SyncTarget{}, false
}

func isWriteAllowed(entries []string, sourcePath string) bool {
	sourcePath = normalizeSyncPath(sourcePath)
	if sourcePath == "" {
		return false
	}

	for _, rule := range parseSyncRules(entries) {
		if !rule.Writable {
			continue
		}

		ruleSource := normalizeSyncPath(rule.Source)
		if ruleSource == "" {
			continue
		}

		if hasGlobMeta(ruleSource) {
			matched, err := path.Match(ruleSource, sourcePath)
			if err == nil && matched {
				return true
			}
			continue
		}

		if sourcePath == ruleSource || strings.HasPrefix(sourcePath, ruleSource+"/") {
			return true
		}
	}

	return false
}

func findRemoteFile(files []FileState, source string) (FileState, bool) {
	for _, file := range files {
		if file.Path == source {
			return file, true
		}
	}

	return FileState{}, false
}

func safeJoin(baseDir, userPath string) (string, error) {
	if strings.TrimSpace(baseDir) == "" {
		baseDir = "."
	}

	baseAbs, err := filepath.Abs(baseDir)
	if err != nil {
		return "", err
	}

	targetPath := userPath
	if !filepath.IsAbs(targetPath) {
		targetPath = filepath.Join(baseAbs, targetPath)
	}

	targetAbs, err := filepath.Abs(targetPath)
	if err != nil {
		return "", err
	}

	rel, err := filepath.Rel(baseAbs, targetAbs)
	if err != nil {
		return "", err
	}

	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", errors.New("invalid path outside sync base directory")
	}

	return targetAbs, nil
}
