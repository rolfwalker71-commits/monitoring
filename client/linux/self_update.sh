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
GITHUB_REPO="${GITHUB_REPO:-rolfwalker71-commits/monitoring}"
AGENT_VERSION_FILE="${AGENT_VERSION_FILE:-$INSTALL_DIR/AGENT_VERSION}"
TLS_INSECURE="${TLS_INSECURE:-0}"
CURL_CONNECT_TIMEOUT_SEC="${CURL_CONNECT_TIMEOUT_SEC:-10}"
CURL_MAX_TIME_SEC="${CURL_MAX_TIME_SEC:-45}"

CURL_BASE_ARGS=(--fail --silent --show-error --location --connect-timeout "$CURL_CONNECT_TIMEOUT_SEC" --max-time "$CURL_MAX_TIME_SEC")
if [[ "$TLS_INSECURE" == "1" ]]; then
  CURL_BASE_ARGS+=(--insecure)
fi
# Use GitHub API for downloads to avoid CDN caching issues
API_ACCEPT=(-H "Accept: application/vnd.github.v3.raw")
API_BASE_URL="https://api.github.com/repos/${GITHUB_REPO}/contents"

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

remote_version="$(curl "${CURL_BASE_ARGS[@]}" "${API_ACCEPT[@]}" "$API_BASE_URL/BUILD_VERSION" 2>/dev/null | tr -d '[:space:]' || true)"
if [[ -z "$remote_version" ]]; then
  remote_version="$(curl "${CURL_BASE_ARGS[@]}" "$RAW_BASE_URL/BUILD_VERSION" 2>/dev/null | tr -d '[:space:]' || true)"
fi
local_version="unknown"
if [[ -f "$AGENT_VERSION_FILE" ]]; then
  local_version="$(head -n 1 "$AGENT_VERSION_FILE" | tr -d '[:space:]')"
fi

if [[ -z "$remote_version" ]]; then
  echo "Remote version is empty; aborting update check." >&2
  exit 1
fi

curl "${CURL_BASE_ARGS[@]}" "${API_ACCEPT[@]}" "$API_BASE_URL/client/linux/collect_and_send.sh" -o "$tmp_dir/collect_and_send.sh"
curl "${CURL_BASE_ARGS[@]}" "${API_ACCEPT[@]}" "$API_BASE_URL/client/linux/self_update.sh" -o "$tmp_dir/self_update.sh"
printf '%s\n' "$remote_version" > "$tmp_dir/AGENT_VERSION"

install -m 0755 "$tmp_dir/collect_and_send.sh" "$INSTALL_DIR/collect_and_send.sh"
install -m 0755 "$tmp_dir/self_update.sh" "$INSTALL_DIR/self_update.sh"
install -m 0644 "$tmp_dir/AGENT_VERSION" "$AGENT_VERSION_FILE"

version_is_newer() {
  local newer older
  newer="$1"
  older="$2"
  if [[ "$newer" == "$older" ]]; then
    return 1
  fi
  local lowest
  lowest="$(printf '%s\n' "$newer" "$older" | sort -V | head -n 1)"
  [[ "$lowest" == "$older" ]]
}

if version_is_newer "$remote_version" "$local_version"; then
  ts="$(date +"%d.%m.%Y %H:%M" 2>/dev/null || true)"
  echo "${ts} Monitoring agent updated from $local_version to $remote_version"
fi

# Migration: remove old static DIR_SCAN_DEEP_PATHS that was auto-written by a
# previous agent version. The new agent performs a hostname-aware search and
# will re-write the correct value on the next run.
if grep -qE '^DIR_SCAN_DEEP_PATHS=/hana/shared/backup_service/backups/\*\/\*' "$CONFIG_FILE" 2>/dev/null; then
  sed -i '/^DIR_SCAN_DEEP_PATHS=\/hana\/shared\/backup_service\/backups\/\*\/\*/d' "$CONFIG_FILE"
  echo "Migration: removed stale DIR_SCAN_DEEP_PATHS from $CONFIG_FILE (will be re-detected on next run)"
fi
