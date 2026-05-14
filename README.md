# Secure File Sync Service

A lightweight, secure, single-binary file synchronization service written in Go.

The application can operate as either:

- **Server**
- **Client**

The role is determined dynamically through a `.env` configuration file.

---

# Features

- Single binary deployment
- API key authentication
- Optional TLS encryption
- Concurrent client handling with goroutines
- File-level locking to prevent race conditions
- Timestamp/version-based conflict resolution
- SHA256 hash change detection
- Configurable polling intervals
- Pure Go standard library implementation
- Minimal dependencies
- Cross-platform support

---

# Architecture

## Server

The server:

- Listens for incoming TCP/TLS connections
- Authenticates clients using an API key
- Handles concurrent connections
- Maintains file locks
- Rejects stale writes using timestamps

## Client

The client:

- Polls local files periodically
- Detects changes using SHA256 hashes
- Pushes updates to the server
- Authenticates every request

---

# Project Structure

```text
sync-service/
├── main.go
├── go.mod
├── .env
├── cert.pem
├── key.pem
└── synced/
    ├── file1.txt
    └── file2.txt
```

---

# Requirements

- Go 1.24+

Check version:

```bash
go version
```

---

# Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/sync-service.git
cd sync-service
```

Build:

```bash
go build -o sync-service
```

---

# Configuration

The application is configured entirely through a `.env` file.

---

# Example Server Configuration

```env
APP_MODE=server

SERVER_ADDRESS=0.0.0.0:8080

API_KEY=my_super_secret_key

SYNC_FILES=./synced/file1.txt,./synced/file2.txt

POLL_INTERVAL=10s

USE_TLS=false
TLS_CERT=cert.pem
TLS_KEY=key.pem
```

---

# Example Client Configuration

```env
APP_MODE=client

SERVER_ADDRESS=192.168.1.100:8080

API_KEY=my_super_secret_key

SYNC_FILES=./synced/file1.txt,./synced/file2.txt

POLL_INTERVAL=10s

USE_TLS=false
TLS_CERT=cert.pem
TLS_KEY=key.pem
```

---

# Environment Variables

| Variable | Description |
|---|---|
| `APP_MODE` | `server` or `client` |
| `SERVER_ADDRESS` | TCP address of server |
| `API_KEY` | Shared authentication key |
| `SYNC_FILES` | Comma-separated file list |
| `POLL_INTERVAL` | File polling interval |
| `USE_TLS` | Enable TLS encryption |
| `TLS_CERT` | TLS certificate path |
| `TLS_KEY` | TLS private key path |

---

# Running

## Start Server

```bash
./sync-service
```

Using:

```env
APP_MODE=server
```

---

## Start Client

```bash
./sync-service
```

Using:

```env
APP_MODE=client
```

---

# TLS Setup (Optional)

Generate a self-signed certificate:

```bash
openssl req -x509 -newkey rsa:4096 \
-keyout key.pem \
-out cert.pem \
-days 365 \
-nodes
```

Enable TLS:

```env
USE_TLS=true
```

---

# Synchronization Workflow

## Client Side

1. Poll local files
2. Compute SHA256 hashes
3. Detect modifications
4. Send changed files to server

## Server Side

1. Authenticate request
2. Acquire file lock
3. Compare timestamps
4. Reject stale writes
5. Write updated content
6. Release lock

---

# Conflict Resolution

The server prevents race conditions through:

- File-level mutex locking
- Timestamp validation

If an incoming file has an older timestamp than the current server version, the write is rejected.

---

# Security

## Authentication

Every request requires a valid API key.

Authentication uses constant-time comparison to mitigate timing attacks.

## TLS Encryption

Optional TLS prevents:

- Packet sniffing
- MITM attacks
- Plaintext data exposure

---

# Logging

The service logs:

- Connection failures
- Authentication failures
- File synchronization events
- File I/O errors
- JSON parsing errors
- Timeout events

---

# Example Logs

```text
server listening on 0.0.0.0:8080

client started

synced: ./synced/file1.txt

updated file: ./synced/file1.txt

authentication failed from 192.168.1.15
```

---

# Concurrency Model

The server uses:

- Goroutines for each client connection
- Mutexes for file locking
- Concurrent-safe version tracking

This allows multiple clients to sync simultaneously.

---

# Limitations

Current implementation:

- Syncs entire files
- No compression
- No delta synchronization
- No deletion propagation
- No bidirectional merge support
- In-memory version tracking only

---

# Recommended Improvements

## Performance

- Compression (gzip/zstd)
- Binary delta sync
- Chunked transfers

## Reliability

- Persistent metadata database
- Automatic reconnect/backoff
- Retry queue

## Security

- mTLS authentication
- JWT-based auth
- IP allowlists

## Features

- Bidirectional sync
- Directory recursion
- File deletion propagation
- File watcher support (`fsnotify`)
- Web dashboard
- Prometheus metrics

---

# Troubleshooting

## Connection Refused

Verify:

- Server is running
- Firewall allows port
- Correct IP/port

Example:

```bash
sudo ufw allow 8080/tcp
```

---

## TLS Errors

Ensure:

- `cert.pem` exists
- `key.pem` exists
- TLS paths are correct

---

## Authentication Failed

Verify:

- Same `API_KEY` on server/client
- No extra spaces in `.env`

---

# License

MIT License

---

# Author

Developed in Go using standard libraries:

- `net`
- `crypto/tls`
- `encoding/json`
- `sync`
- `os`
- `time`
