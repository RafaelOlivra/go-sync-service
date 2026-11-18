#!/usr/bin/env bash

set -euo pipefail

export PATH=/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin:$PATH

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
BINARY="$SCRIPT_DIR/sync-service"
SERVICE_NAME="sync-service"
UNIT_FILE="/etc/systemd/system/$SERVICE_NAME.service"

usage() {
    cat <<EOF
Usage: $0 COMMAND [ENV_FILE]

Linux systemd commands:
  build                Build sync-service
  install [ENV_FILE]   Build, install, enable, and start the service
  update [ENV_FILE]    Rebuild, update the unit, and restart the service
  start                Start the service
  stop                 Stop the service
  restart              Restart the service
  status               Show service status
  logs [LINES]         Follow crash/service logs (default: 100 lines)
  uninstall            Stop and remove the systemd service

Install and update must be run as root:
  sudo $0 install .env

The service is installed to run as \$SUDO_USER. Override it with:
  sudo SERVICE_USER=myuser $0 install .env
EOF
}

require_linux_systemd() {
    if [[ "$(uname -s)" != "Linux" ]]; then
        echo "Error: systemd service management is only supported on Linux." >&2
        exit 1
    fi

    if ! command -v systemctl >/dev/null 2>&1; then
        echo "Error: systemctl is required to manage this service." >&2
        exit 1
    fi
}

require_root() {
    if (( EUID != 0 )); then
        echo "Error: this command must be run with sudo." >&2
        exit 1
    fi
}

resolve_env_file() {
    local input="${1:-.env}"

    if [[ ! -f "$input" ]]; then
        echo "Error: env file '$input' not found." >&2
        exit 1
    fi

    printf '%s' "$(cd -- "$(dirname -- "$input")" && pwd -P)/$(basename -- "$input")"
}

build_binary() {
    echo "Building sync-service..."
    cd -- "$SCRIPT_DIR"
    go build -trimpath -o "$BINARY" .
}

install_unit() {
    local env_file="$1"
    local service_user="${SERVICE_USER:-${SUDO_USER:-root}}"

    if [[ "$service_user" == "root" ]]; then
        echo "Error: refusing to run the service as root. Set SERVICE_USER or invoke with sudo." >&2
        exit 1
    fi

    if ! id "$service_user" >/dev/null 2>&1; then
        echo "Error: service user '$service_user' does not exist." >&2
        exit 1
    fi

    if [[ "$SCRIPT_DIR" == *[$'\n\r"%']* || "$env_file" == *[$'\n\r"%']* ]]; then
        echo "Error: script and env paths cannot contain quotes, percent signs, or newlines." >&2
        exit 1
    fi

    cat >"$UNIT_FILE" <<EOF
[Unit]
Description=Go file synchronization service
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=$service_user
WorkingDirectory="$SCRIPT_DIR"
ExecStart="$BINARY" --env "$env_file"
Restart=always
RestartSec=5s
TimeoutStopSec=30s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$SERVICE_NAME

[Install]
WantedBy=multi-user.target
EOF

    echo "Installed $UNIT_FILE for user '$service_user'."
    echo "Environment: $env_file"
}

case "${1:-}" in
    build)
        build_binary
        ;;
    install|update)
        require_linux_systemd
        require_root
        env_file="$(resolve_env_file "${2:-.env}")"
        build_binary
        install_unit "$env_file"
        systemctl daemon-reload
        systemctl enable "$SERVICE_NAME"
        systemctl restart "$SERVICE_NAME"
        systemctl --no-pager --full status "$SERVICE_NAME" || true
        echo "Follow logs with: sudo $0 logs"
        ;;
    start|restart|stop)
        require_linux_systemd
        require_root
        systemctl "$1" "$SERVICE_NAME"
        ;;
    status)
        require_linux_systemd
        systemctl --no-pager --full status "$SERVICE_NAME"
        ;;
    logs)
        require_linux_systemd
        journalctl -u "$SERVICE_NAME" -n "${2:-100}" -f
        ;;
    uninstall)
        require_linux_systemd
        require_root
        systemctl disable --now "$SERVICE_NAME" 2>/dev/null || true
        rm -f "$UNIT_FILE"
        systemctl daemon-reload
        echo "Removed $SERVICE_NAME. The built binary and project files were kept."
        ;;
    -h|--help|help|"")
        usage
        ;;
    *)
        echo "Error: unknown command '$1'." >&2
        usage >&2
        exit 2
        ;;
esac
