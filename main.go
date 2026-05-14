package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"

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

	for _, line := range lines {
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

		case "SYNC_FILES":
			for _, item := range strings.Split(value, ",") {
				item = strings.TrimSpace(item)
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

	dec := json.NewDecoder(conn)
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
		err := handleWrite(req.File)

		if err != nil {
			sendResponse(conn, Response{
				Status: "error",
				Error:  err.Error(),
			})
			return
		}

		sendResponse(conn, Response{
			Status: "ok",
		})

	case "READ_ALL":
		files := readAllFiles(cfg.SyncFiles)

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

func handleWrite(file FileState) error {
	lock := getFileLock(file.Path)

	lock.Lock()
	defer lock.Unlock()

	versionMu.Lock()
	currentVersion := fileVersions[file.Path]

	if file.Timestamp < currentVersion {
		versionMu.Unlock()
		return errors.New("incoming file is older than current version")
	}

	fileVersions[file.Path] = file.Timestamp
	versionMu.Unlock()

	err := os.MkdirAll(filepath.Dir(file.Path), 0755)
	if err != nil {
		return err
	}

	err = os.WriteFile(file.Path, []byte(file.Content), 0644)
	if err != nil {
		return err
	}

	log.Printf("updated file: %s", file.Path)

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

	lastHashes := make(map[string]string)
	targets := parseSyncTargets(cfg.SyncFiles)

	for {
		for _, target := range targets {

			file, err := buildFileState(target.Source, target.Destination)
			if err != nil {
				log.Printf("file read error: %v", err)
				continue
			}

			if lastHashes[target.Source] == file.Hash {
				continue
			}

			err = sendWrite(cfg, file)
			if err != nil {
				log.Printf("sync error: %v", err)
				continue
			}

			lastHashes[target.Source] = file.Hash

			if target.Source == target.Destination {
				log.Printf("synced: %s", target.Source)
			} else {
				log.Printf("synced: %s -> %s", target.Source, target.Destination)
			}
		}

		time.Sleep(cfg.PollInterval)
	}
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

func readAllFiles(paths []string) []FileState {
	var files []FileState

	for _, p := range paths {
		f, err := buildFileState(p, p)
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

		parts := strings.SplitN(entry, "||", 2)
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
