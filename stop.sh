#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$SCRIPT_DIR/sync-service.pid"

if [ ! -f "$PID_FILE" ]; then
    echo "Error: PID file '$PID_FILE' not found"
    exit 1
fi

PID="$(cat "$PID_FILE")"

if kill -0 "$PID" 2>/dev/null; then
    kill "$PID"
    echo "Sent stop signal to sync-service process $PID"
else
    echo "sync-service process $PID is not running"
fi

rm -f "$PID_FILE"