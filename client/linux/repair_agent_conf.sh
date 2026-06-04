#!/usr/bin/env bash
set -euo pipefail

CONFIG_FILE="${1:-/etc/monitoring-agent/agent.conf}"

if [[ $EUID -ne 0 ]]; then
  echo "Bitte als root oder mit sudo ausfuehren." >&2
  exit 1
fi

mkdir -p "$(dirname "$CONFIG_FILE")"

if [[ -f "$CONFIG_FILE" ]]; then
  # shellcheck source=/dev/null
  source "$CONFIG_FILE"
fi

CANONICAL_SERVER_URL="https://infoboard.ang-schweiz.ch"
SECONDARY_SERVER_URL="https://infoboard.an-group.work"
LEGACY_SERVER_URL="https://monitoring.rolfwalker.ch"

server_url_reachable() {
  local candidate="${1:-}"
  [[ -z "$candidate" ]] && return 1
  local probe_args=(--silent --show-error --location --connect-timeout 10 --max-time 45 --output /dev/null)
  if [[ "${TLS_INSECURE:-0}" == "1" ]]; then
    probe_args+=(--insecure)
  fi
  curl "${probe_args[@]}" "${candidate%/}/api/v1/agent-commands" >/dev/null 2>&1
}

SERVER_URL="${SERVER_URL:-}"
if server_url_reachable "$CANONICAL_SERVER_URL"; then
  SERVER_URL="$CANONICAL_SERVER_URL"
elif server_url_reachable "$SECONDARY_SERVER_URL"; then
  SERVER_URL="$SECONDARY_SERVER_URL"
elif server_url_reachable "$LEGACY_SERVER_URL"; then
  SERVER_URL="$LEGACY_SERVER_URL"
elif [[ -z "$SERVER_URL" ]]; then
  SERVER_URL="$LEGACY_SERVER_URL"
fi

if [[ -z "${AGENT_ID:-}" ]]; then
  AGENT_ID="$(hostname -f 2>/dev/null || hostname)"
fi

if [[ -z "${DISPLAY_NAME:-}" ]]; then
  DISPLAY_NAME="$AGENT_ID"
fi

RAW_BASE_URL="${SERVER_URL%/}/updates"
UPDATE_BASE_URL="$RAW_BASE_URL"

if [[ -z "${INSTALL_DIR:-}" ]]; then
  INSTALL_DIR="/opt/monitoring-agent"
fi

if [[ -z "${AGENT_VERSION_FILE:-}" ]]; then
  AGENT_VERSION_FILE="$INSTALL_DIR/AGENT_VERSION"
fi

if [[ -z "${AGENT_QUEUE_DIR:-}" ]]; then
  AGENT_QUEUE_DIR="/var/lib/monitoring-agent/queue"
fi

if [[ -z "${UPDATE_HOURS:-}" ]]; then
  UPDATE_HOURS="1"
fi

if [[ -z "${PRIORITY_UPDATE_CHECK_MINUTES:-}" ]]; then
  PRIORITY_UPDATE_CHECK_MINUTES="60"
fi

if [[ -z "${UPDATE_LOG_FILE:-}" ]]; then
  UPDATE_LOG_FILE="/var/log/monitoring-agent-update.log"
fi

if [[ -z "${TLS_INSECURE:-}" ]]; then
  TLS_INSECURE="0"
fi

if [[ -z "${DIR_SCAN_DEEP_PATHS:-}" ]]; then
  DIR_SCAN_DEEP_PATHS=""
fi

if [[ -z "${HANA_SID:-}" ]] && [[ -d /hana/shared ]]; then
  HANA_SID="$(find /hana/shared -mindepth 1 -maxdepth 1 -type d 2>/dev/null \
    | awk -F/ '{print $NF}' \
    | grep -E '^[A-Z][A-Z0-9]{2}$' \
    | head -1 || true)"
fi

if [[ -z "${HANA_ADDONS_ENABLED:-}" ]]; then
  HANA_ADDONS_ENABLED="1"
fi
if [[ -z "${HANA_ADDONS_USER:-}" ]]; then
  HANA_ADDONS_USER="HARVEST"
fi
if [[ -z "${HANA_ADDONS_PASSWORD:-}" ]]; then
  HANA_ADDONS_PASSWORD="0djKUt&xbLK0AYr"
fi
if [[ -z "${HANA_ADDONS_QUERY_TIMEOUT_SEC:-}" ]]; then
  HANA_ADDONS_QUERY_TIMEOUT_SEC="15"
fi
if [[ -z "${HANA_ADDONS_HOST:-}" ]]; then
  HANA_ADDONS_HOST="127.0.0.1"
fi
if [[ -z "${HANA_ADDONS_PORT:-}" ]]; then
  HANA_ADDONS_PORT="30015"
fi

cat > "$CONFIG_FILE" <<EOF
SERVER_URL="$SERVER_URL"
API_KEY="${API_KEY:-}"
AGENT_ID="$AGENT_ID"
DISPLAY_NAME="$DISPLAY_NAME"
RAW_BASE_URL="$RAW_BASE_URL"
UPDATE_BASE_URL="$UPDATE_BASE_URL"
INSTALL_DIR="$INSTALL_DIR"
AGENT_VERSION_FILE="$AGENT_VERSION_FILE"
AGENT_QUEUE_DIR="$AGENT_QUEUE_DIR"
UPDATE_HOURS="$UPDATE_HOURS"
PRIORITY_UPDATE_CHECK_MINUTES="$PRIORITY_UPDATE_CHECK_MINUTES"
UPDATE_LOG_FILE="$UPDATE_LOG_FILE"
TLS_INSECURE="$TLS_INSECURE"
DIR_SCAN_DEEP_PATHS="$DIR_SCAN_DEEP_PATHS"
HANA_SID="$HANA_SID"
HANA_ADDONS_ENABLED="$HANA_ADDONS_ENABLED"
HANA_ADDONS_USER="$HANA_ADDONS_USER"
HANA_ADDONS_PASSWORD="$HANA_ADDONS_PASSWORD"
HANA_ADDONS_QUERY_TIMEOUT_SEC="$HANA_ADDONS_QUERY_TIMEOUT_SEC"
HANA_ADDONS_HOST="$HANA_ADDONS_HOST"
HANA_ADDONS_PORT="$HANA_ADDONS_PORT"
EOF

chmod 0600 "$CONFIG_FILE"
echo "OK: $CONFIG_FILE wurde ohne Rueckfragen neu aufgebaut."
