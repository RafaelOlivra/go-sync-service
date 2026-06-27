#!/bin/bash

set -euo pipefail

ENV_FILE_INPUT="${1:-.env}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PID_FILE="$SCRIPT_DIR/sync-service.pid"

if [ ! -f "$ENV_FILE_INPUT" ]; then
    echo "Error: env file '$ENV_FILE_INPUT' not found"
    exit 1
fi

ENV_FILE="$(cd "$(dirname "$ENV_FILE_INPUT")" && pwd)/$(basename "$ENV_FILE_INPUT")"

cd "$SCRIPT_DIR"

echo "Using env file: $ENV_FILE"

# Export variables from env file
set -a
source "$ENV_FILE"
set +a

if [ -z "${APP_MODE:-}" ]; then
    echo "Error: APP_MODE is not set in $ENV_FILE"
    exit 1
fi

# Check if the PID file exists and kill the process if it does
if [ -f "$PID_FILE" ]; then
    kill "$(cat "$PID_FILE")" 2>/dev/null || true
    rm -f "$PID_FILE"
fi

echo "Running in $APP_MODE mode..."

echo "Building sync-service..."
go build -o sync-service .

echo "Running sync-service in the background..."
nohup ./sync-service --env "$ENV_FILE" >/dev/null 2>&1 &
echo $! > "$PID_FILE"

echo "Started sync-service with PID $(cat "$PID_FILE")"
echo "Logs are written to ${LOG_FILE:-log.txt}"
echo "Stop with ./stop.sh"