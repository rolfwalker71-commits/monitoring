#!/usr/bin/env bash
set -euo pipefail

CONFIG_FILE="${CONFIG_FILE:-/etc/monitoring-agent/agent.conf}"

if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "Config file not found: $CONFIG_FILE" >&2
  exit 1
fi

# shellcheck source=/dev/null
source "$CONFIG_FILE"

INSTALL_DIR="${INSTALL_DIR:-/opt/monitoring-agent}"
RAW_BASE_URL="${RAW_BASE_URL:-https://raw.githubusercontent.com/rolfwalker71-commits/monitoring/main}"
AGENT_VERSION_FILE="${AGENT_VERSION_FILE:-$INSTALL_DIR/AGENT_VERSION}"

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

remote_version="$(curl -fsSL "$RAW_BASE_URL/BUILD_VERSION" | tr -d '[:space:]')"
local_version="unknown"
if [[ -f "$AGENT_VERSION_FILE" ]]; then
  local_version="$(head -n 1 "$AGENT_VERSION_FILE" | tr -d '[:space:]')"
fi

if [[ -z "$remote_version" ]]; then
  echo "Remote version is empty; aborting update check." >&2
  exit 1
fi

if [[ "$remote_version" == "$local_version" ]]; then
  echo "Monitoring agent already up to date: $local_version"
  exit 0
fi

curl -fsSL "$RAW_BASE_URL/client/linux/collect_and_send.sh" -o "$tmp_dir/collect_and_send.sh"
curl -fsSL "$RAW_BASE_URL/client/linux/self_update.sh" -o "$tmp_dir/self_update.sh"
printf '%s\n' "$remote_version" > "$tmp_dir/AGENT_VERSION"

install -m 0755 "$tmp_dir/collect_and_send.sh" "$INSTALL_DIR/collect_and_send.sh"
install -m 0755 "$tmp_dir/self_update.sh" "$INSTALL_DIR/self_update.sh"
install -m 0644 "$tmp_dir/AGENT_VERSION" "$AGENT_VERSION_FILE"

echo "Monitoring agent updated from $local_version to $remote_version"
