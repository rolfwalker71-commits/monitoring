#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/opt/monitoring-agent"
CONFIG_DIR="/etc/monitoring-agent"
CONFIG_FILE="$CONFIG_DIR/agent.conf"
CRON_FILE="/etc/cron.d/monitoring-agent"
LOG_FILE="/var/log/monitoring-agent.log"

SERVER_URL=""
API_KEY=""
AGENT_ID=""
INTERVAL_MINUTES="15"
COLLECT_SCRIPT_URL="https://raw.githubusercontent.com/rolfwalker71-commits/monitoring/main/client/collect_and_send.sh"

usage() {
  cat <<EOF
Usage: $0 --server-url URL [--api-key KEY] [--agent-id ID] [--interval-minutes 15] [--collect-script-url URL]

Example:
  curl -fsSL https://raw.githubusercontent.com/rolfwalker71-commits/monitoring/main/client/install_agent.sh \
    | sudo bash -s -- --server-url https://monitoring.example.com --interval-minutes 15
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --server-url)
      SERVER_URL="$2"
      shift 2
      ;;
    --api-key)
      API_KEY="$2"
      shift 2
      ;;
    --agent-id)
      AGENT_ID="$2"
      shift 2
      ;;
    --interval-minutes)
      INTERVAL_MINUTES="$2"
      shift 2
      ;;
    --collect-script-url)
      COLLECT_SCRIPT_URL="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$SERVER_URL" ]]; then
  echo "--server-url is required" >&2
  usage
  exit 1
fi

if ! [[ "$INTERVAL_MINUTES" =~ ^[0-9]+$ ]] || [[ "$INTERVAL_MINUTES" -lt 1 ]] || [[ "$INTERVAL_MINUTES" -gt 59 ]]; then
  echo "--interval-minutes must be a number between 1 and 59" >&2
  exit 1
fi

if [[ $EUID -ne 0 ]]; then
  echo "Please run as root (or via sudo)." >&2
  exit 1
fi

mkdir -p "$INSTALL_DIR" "$CONFIG_DIR"

curl -fsSL "$COLLECT_SCRIPT_URL" -o "$INSTALL_DIR/collect_and_send.sh"
chmod 0755 "$INSTALL_DIR/collect_and_send.sh"

if [[ -z "$AGENT_ID" ]]; then
  AGENT_ID="$(hostname -f 2>/dev/null || hostname)"
fi

cat > "$CONFIG_FILE" <<EOF
SERVER_URL="$SERVER_URL"
API_KEY="$API_KEY"
AGENT_ID="$AGENT_ID"
EOF

chmod 0600 "$CONFIG_FILE"

cat > "$CRON_FILE" <<EOF
*/$INTERVAL_MINUTES * * * * root CONFIG_FILE=$CONFIG_FILE $INSTALL_DIR/collect_and_send.sh >> $LOG_FILE 2>&1
EOF

chmod 0644 "$CRON_FILE"

if command -v systemctl >/dev/null 2>&1; then
  systemctl reload cron 2>/dev/null || systemctl reload crond 2>/dev/null || true
fi

echo "Monitoring agent installed."
echo "Config: $CONFIG_FILE"
echo "Collector: $INSTALL_DIR/collect_and_send.sh"
echo "Cron schedule: every $INTERVAL_MINUTES minutes"
echo "Log file: $LOG_FILE"
