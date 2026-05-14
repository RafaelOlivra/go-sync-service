package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
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

	UseTLS bool
	Cert   string
	Key    string
}

type SyncTarget struct {
	Source      string
	Destination string
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

		case "USE_TLS":
			cfg.UseTLS = strings.ToLower(value) == "true"

		case "TLS_CERT":
			cfg.Cert = value

		case "TLS_KEY":
			cfg.Key = value
		}
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

		go handleConnection(conn, cfg)
	}
}

func handleConnection(conn net.Conn, cfg *Config) {
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(30 * time.Second))

	var req Request

	dec := json.NewDecoder(io.LimitReader(conn, 100*1024*1024))
	if err := dec.Decode(&req); err != nil {
		log.Printf("json decode error: %v", err)
		return
	}

	if !authenticate(req.Key, cfg.APIKey) {
		sendResponse(conn, Response{
			Status: "error",
			Error:  "authentication failed",
		})

		log.Printf("authentication failed from %s", conn.RemoteAddr())
		return
	}

	switch req.Type {

	case "WRITE":
		err := handleWrite(cfg.BaseDir, req.File)

		if err != nil {
			sendResponse(conn, Response{
				Status: "error",
				Error:  err.Error(),
			})
			return
		}

		log.Printf("[Client] --> [Server] updated file: %s from %s", req.File.Path, conn.RemoteAddr())

		sendResponse(conn, Response{
			Status: "ok",
		})

	case "READ_ALL":
		files := readAllFiles(cfg.BaseDir, cfg.SyncFiles)

		sendResponse(conn, Response{
			Status: "ok",
			Files:  files,
		})

	default:
		sendResponse(conn, Response{
			Status: "error",
			Error:  "invalid request",
		})
	}
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

	mappings := parseSyncTargets(cfg.SyncFiles)
	lastLocalHashes := make(map[string]string)
	lastRemoteHashes := make(map[string]string)

	for {
		files, err := sendReadAll(cfg)
		if err != nil {
			log.Printf("sync error: %v", err)
			time.Sleep(cfg.PollInterval)
			continue
		}

		for _, mapping := range mappings {
			localFile, localErr := buildFileState(mapping.Destination, mapping.Destination)
			remoteFile, ok := findRemoteFile(files, mapping.Source)
			if localErr != nil && !ok {
				continue
			}

			if localErr != nil {
				if ok {
					if err := writeLocalFile(mapping.Destination, remoteFile.Content); err != nil {
						log.Printf("file write error: %v", err)
						continue
					}

					lastRemoteHashes[mapping.Source] = remoteFile.Hash
					lastLocalHashes[mapping.Destination] = remoteFile.Hash
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
					log.Printf("sync error: %v", err)
					continue
				}

				lastLocalHashes[mapping.Destination] = localFile.Hash
				lastRemoteHashes[mapping.Source] = localFile.Hash
				log.Printf("synced: %s -> %s", mapping.Destination, mapping.Source)
				continue
			}

			lastLocalHash := lastLocalHashes[mapping.Destination]
			lastRemoteHash := lastRemoteHashes[mapping.Source]
			localChanged := localFile.Hash != lastLocalHash
			remoteChanged := remoteFile.Hash != lastRemoteHash

			switch {
			case localFile.Hash == remoteFile.Hash:
				lastLocalHashes[mapping.Destination] = localFile.Hash
				lastRemoteHashes[mapping.Source] = remoteFile.Hash
				continue

			case localChanged && !remoteChanged:
				if err := sendWrite(cfg, FileState{
					Path:      mapping.Source,
					Content:   localFile.Content,
					Timestamp: localFile.Timestamp,
					Hash:      localFile.Hash,
				}); err != nil {
					log.Printf("sync error: %v", err)
					continue
				}

				lastLocalHashes[mapping.Destination] = localFile.Hash
				lastRemoteHashes[mapping.Source] = localFile.Hash
				log.Printf("[Client] --> [Server] %s -> %s", mapping.Destination, mapping.Source)

			case remoteChanged && !localChanged:
				if err := writeLocalFile(mapping.Destination, remoteFile.Content); err != nil {
					log.Printf("file write error: %v", err)
					continue
				}

				lastLocalHashes[mapping.Destination] = remoteFile.Hash
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
						log.Printf("sync error: %v", err)
						continue
					}

					lastLocalHashes[mapping.Destination] = localFile.Hash
					lastRemoteHashes[mapping.Source] = localFile.Hash
					log.Printf("[Client] --> [Server] %s -> %s", mapping.Destination, mapping.Source)
				} else {
					if err := writeLocalFile(mapping.Destination, remoteFile.Content); err != nil {
						log.Printf("file write error: %v", err)
						continue
					}

					lastLocalHashes[mapping.Destination] = remoteFile.Hash
					lastRemoteHashes[mapping.Source] = remoteFile.Hash
					log.Printf("[Server] --> [Client] %s -> %s", mapping.Source, mapping.Destination)
				}
			}
		}

		time.Sleep(cfg.PollInterval)
	}
}

func sendReadAll(cfg *Config) ([]FileState, error) {
	var conn net.Conn
	var err error

	if cfg.UseTLS {
		tlsCfg := &tls.Config{
			InsecureSkipVerify: true,
		}

		conn, err = tls.Dial("tcp", cfg.ServerAddr, tlsCfg)
	} else {
		conn, err = net.Dial("tcp", cfg.ServerAddr)
	}

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
		return nil, errors.New(resp.Error)
	}

	return resp.Files, nil
}

func sendWrite(cfg *Config, file FileState) error {
	var conn net.Conn
	var err error

	if cfg.UseTLS {
		tlsCfg := &tls.Config{
			InsecureSkipVerify: true,
		}

		conn, err = tls.Dial("tcp", cfg.ServerAddr, tlsCfg)
	} else {
		conn, err = net.Dial("tcp", cfg.ServerAddr)
	}

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
		return errors.New(resp.Error)
	}

	return nil
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

	for _, p := range paths {
		resolvedPath, err := safeJoin(baseDir, p)
		if err != nil {
			continue
		}

		f, err := buildFileState(resolvedPath, p)
		if err != nil {
			continue
		}

		files = append(files, f)
	}

	return files
}

func parseSyncTargets(entries []string) []SyncTarget {
	targets := make([]SyncTarget, 0, len(entries))

	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		separator := "||"
		if strings.Contains(entry, "->") {
			separator = "->"
		}

		parts := strings.SplitN(entry, separator, 2)
		source := strings.TrimSpace(parts[0])
		destination := source

		if len(parts) == 2 {
			destination = strings.TrimSpace(parts[1])
			if destination == "" {
				destination = source
			}
		}

		targets = append(targets, SyncTarget{
			Source:      source,
			Destination: destination,
		})
	}

	return targets
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
