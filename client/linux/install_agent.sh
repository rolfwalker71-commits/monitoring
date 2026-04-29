#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/opt/monitoring-agent"
CONFIG_DIR="/etc/monitoring-agent"
CONFIG_FILE="$CONFIG_DIR/agent.conf"
CRON_FILE="/etc/cron.d/monitoring-agent"
LOG_FILE="/var/log/monitoring-agent.log"
UPDATE_LOG_FILE="/var/log/monitoring-agent-update.log"
CRON_TAG="# monitoring-agent"

SERVER_URL=""
API_KEY=""
AGENT_ID=""
DISPLAY_NAME=""
INTERVAL_MINUTES="15"
RAW_BASE_URL="https://raw.githubusercontent.com/rolfwalker71-commits/monitoring/main"
AGENT_QUEUE_DIR="/var/lib/monitoring-agent/queue"
COLLECT_SCRIPT_URL=""
SELF_UPDATE_SCRIPT_URL=""
BUILD_VERSION_URL=""

usage() {
  cat <<EOF
Usage: $0 --server-url URL [--api-key KEY] [--agent-id ID] [--display-name NAME] [--interval-minutes 15] [--collect-script-url URL]

Example:
  curl -fsSL https://raw.githubusercontent.com/rolfwalker71-commits/monitoring/main/client/linux/install_agent.sh \
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
    --display-name)
      DISPLAY_NAME="$2"
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
    --raw-base-url)
      RAW_BASE_URL="$2"
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

if [[ -z "$COLLECT_SCRIPT_URL" ]]; then
  COLLECT_SCRIPT_URL="$RAW_BASE_URL/client/linux/collect_and_send.sh"
fi
if [[ -z "$SELF_UPDATE_SCRIPT_URL" ]]; then
  SELF_UPDATE_SCRIPT_URL="$RAW_BASE_URL/client/linux/self_update.sh"
fi
if [[ -z "$BUILD_VERSION_URL" ]]; then
  BUILD_VERSION_URL="$RAW_BASE_URL/BUILD_VERSION"
fi

install_cron_in_crond() {
  local collect_cron_line
  local update_cron_line
  collect_cron_line="*/$INTERVAL_MINUTES * * * * root CONFIG_FILE=$CONFIG_FILE AGENT_VERSION_FILE=$INSTALL_DIR/AGENT_VERSION $INSTALL_DIR/collect_and_send.sh >> $LOG_FILE 2>&1"
  update_cron_line="11 */6 * * * root CONFIG_FILE=$CONFIG_FILE AGENT_VERSION_FILE=$INSTALL_DIR/AGENT_VERSION $INSTALL_DIR/self_update.sh >> $UPDATE_LOG_FILE 2>&1"

  if [[ ! -d "/etc/cron.d" ]]; then
    return 1
  fi

  cat > "$CRON_FILE" <<EOF
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

$CRON_TAG collect
$collect_cron_line
$CRON_TAG update
$update_cron_line
EOF

  chmod 0644 "$CRON_FILE"
  return 0
}

install_cron_in_crontab() {
  local collect_cron_line
  local update_cron_line
  local existing
  collect_cron_line="*/$INTERVAL_MINUTES * * * * CONFIG_FILE=$CONFIG_FILE AGENT_VERSION_FILE=$INSTALL_DIR/AGENT_VERSION $INSTALL_DIR/collect_and_send.sh >> $LOG_FILE 2>&1"
  update_cron_line="11 */6 * * * CONFIG_FILE=$CONFIG_FILE AGENT_VERSION_FILE=$INSTALL_DIR/AGENT_VERSION $INSTALL_DIR/self_update.sh >> $UPDATE_LOG_FILE 2>&1"

  if ! command -v crontab >/dev/null 2>&1; then
    return 1
  fi

  existing="$(crontab -l 2>/dev/null | grep -v 'monitoring-agent' || true)"
  {
    printf '%s\n' "$existing"
    printf '%s collect\n' "$CRON_TAG"
    printf '%s\n' "$collect_cron_line"
    printf '%s update\n' "$CRON_TAG"
    printf '%s\n' "$update_cron_line"
  } | sed '/^$/N;/^\n$/D' | crontab -

  return 0
}

mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$AGENT_QUEUE_DIR"
chmod 0750 "$AGENT_QUEUE_DIR"

curl -fsSL "$COLLECT_SCRIPT_URL" -o "$INSTALL_DIR/collect_and_send.sh"
curl -fsSL "$SELF_UPDATE_SCRIPT_URL" -o "$INSTALL_DIR/self_update.sh"
chmod 0755 "$INSTALL_DIR/collect_and_send.sh"
chmod 0755 "$INSTALL_DIR/self_update.sh"

if ! curl -fsSL "$BUILD_VERSION_URL" -o "$INSTALL_DIR/AGENT_VERSION"; then
  printf '%s\n' "unknown" > "$INSTALL_DIR/AGENT_VERSION"
fi
chmod 0644 "$INSTALL_DIR/AGENT_VERSION"

if [[ -z "$AGENT_ID" ]]; then
  AGENT_ID="$(hostname -f 2>/dev/null || hostname)"
fi

if [[ -z "$DISPLAY_NAME" ]]; then
  prompt_default="$AGENT_ID"
  if [[ -r /dev/tty ]]; then
    printf 'Anzeigename fuer diesen Host [%s]: ' "$prompt_default" > /dev/tty
    if read -r DISPLAY_NAME < /dev/tty; then
      DISPLAY_NAME="${DISPLAY_NAME:-$prompt_default}"
    else
      DISPLAY_NAME="$prompt_default"
    fi
  else
    DISPLAY_NAME="$prompt_default"
  fi
fi

cat > "$CONFIG_FILE" <<EOF
SERVER_URL="$SERVER_URL"
API_KEY="$API_KEY"
AGENT_ID="$AGENT_ID"
DISPLAY_NAME="$DISPLAY_NAME"
RAW_BASE_URL="$RAW_BASE_URL"
INSTALL_DIR="$INSTALL_DIR"
AGENT_VERSION_FILE="$INSTALL_DIR/AGENT_VERSION"
AGENT_QUEUE_DIR="$AGENT_QUEUE_DIR"
EOF

chmod 0600 "$CONFIG_FILE"

CRON_TARGET=""
if install_cron_in_crond; then
  CRON_TARGET="$CRON_FILE"
elif install_cron_in_crontab; then
  CRON_TARGET="root crontab"
else
  echo "Failed to install cron job. Neither /etc/cron.d nor crontab worked." >&2
  exit 1
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl reload cron 2>/dev/null || systemctl reload crond 2>/dev/null || true
fi

echo "Monitoring agent installed."
echo "Config: $CONFIG_FILE"
echo "Display name: $DISPLAY_NAME"
echo "Collector: $INSTALL_DIR/collect_and_send.sh"
echo "Updater: $INSTALL_DIR/self_update.sh"
echo "Agent version file: $INSTALL_DIR/AGENT_VERSION"
echo "Queue dir: $AGENT_QUEUE_DIR"
echo "Cron schedule: every $INTERVAL_MINUTES minutes"
echo "Update check: every 6 hours"
echo "Cron target: $CRON_TARGET"
echo "Log file: $LOG_FILE"
echo "Update log file: $UPDATE_LOG_FILE"
