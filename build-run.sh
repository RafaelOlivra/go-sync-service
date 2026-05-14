#!/bin/bash

set -e

ENV_FILE="${1:-.env}"

if [ ! -f "$ENV_FILE" ]; then
    echo "Error: env file '$ENV_FILE' not found"
    exit 1
fi

echo "Using env file: $ENV_FILE"

# Export variables from env file
set -a
source "$ENV_FILE"
set +a

if [ -z "$APP_MODE" ]; then
    echo "Error: APP_MODE is not set in $ENV_FILE"
    exit 1
fi

echo "Running in $APP_MODE mode..."

echo "Building sync-service..."
go build -o sync-service main.go

echo "Running sync-service..."
./sync-service