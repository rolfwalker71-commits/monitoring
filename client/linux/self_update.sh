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
CANONICAL_SERVER_URL="https://infoboard.an-group.work"
SERVER_URL="$CANONICAL_SERVER_URL"
UPDATE_BASE_URL="${CANONICAL_SERVER_URL%/}/updates"
RAW_BASE_URL="$UPDATE_BASE_URL"
AGENT_VERSION_FILE="${AGENT_VERSION_FILE:-$INSTALL_DIR/AGENT_VERSION}"
TLS_INSECURE="${TLS_INSECURE:-0}"
CURL_CONNECT_TIMEOUT_SEC="${CURL_CONNECT_TIMEOUT_SEC:-10}"
CURL_MAX_TIME_SEC="${CURL_MAX_TIME_SEC:-45}"

CURL_BASE_ARGS=(--fail --silent --show-error --location --connect-timeout "$CURL_CONNECT_TIMEOUT_SEC" --max-time "$CURL_MAX_TIME_SEC")
if [[ "$TLS_INSECURE" == "1" ]]; then
  CURL_BASE_ARGS+=(--insecure)
fi

if [[ -z "$UPDATE_BASE_URL" ]]; then
  echo "No update source configured. Set SERVER_URL or UPDATE_BASE_URL in $CONFIG_FILE." >&2
  exit 1
fi

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

version_is_valid() {
  local ver="$1"
  [[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
}

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

fetch_remote_version_file() {
  local rel="$1"
  local candidate=""

  if [[ -n "$UPDATE_BASE_URL" ]]; then
    candidate="$(curl "${CURL_BASE_ARGS[@]}" "$UPDATE_BASE_URL/$rel" 2>/dev/null | tr -d '[:space:]' || true)"
    if version_is_valid "$candidate"; then
      printf '%s|%s\n' "$candidate" "$UPDATE_BASE_URL/$rel"
      return 0
    fi
  fi

  return 1
}

local_version="unknown"
if [[ -f "$AGENT_VERSION_FILE" ]]; then
  local_version="$(head -n 1 "$AGENT_VERSION_FILE" | tr -d '[:space:]')"
fi

agent_version=""
agent_source=""
agent_pair=""
if agent_pair="$(fetch_remote_version_file "AGENT_VERSION" 2>/dev/null)"; then
  agent_version="${agent_pair%%|*}"
  agent_source="${agent_pair#*|}"
fi

build_version=""
build_source=""
build_pair=""
if build_pair="$(fetch_remote_version_file "BUILD_VERSION" 2>/dev/null)"; then
  build_version="${build_pair%%|*}"
  build_source="${build_pair#*|}"
fi

remote_version=""
remote_version_source=""
if version_is_valid "$agent_version"; then
  remote_version="$agent_version"
  remote_version_source="$agent_source"
fi
if version_is_valid "$build_version"; then
  if [[ -z "$remote_version" ]] || version_is_newer "$build_version" "$remote_version"; then
    remote_version="$build_version"
    remote_version_source="$build_source"
  fi
fi

if [[ -z "$remote_version" ]]; then
  echo "Remote version lookup failed (AGENT_VERSION/BUILD_VERSION empty or invalid); aborting update check." >&2
  exit 1
fi

download_update_file() {
  local rel="$1"
  local out="$2"
  if [[ -n "$UPDATE_BASE_URL" ]] && curl "${CURL_BASE_ARGS[@]}" "$UPDATE_BASE_URL/$rel" -o "$out" 2>/dev/null; then
    return 0
  fi
  return 1
}

if ! download_update_file "client/linux/collect_and_send.sh" "$tmp_dir/collect_and_send.sh"; then
  echo "Failed to download collect_and_send.sh from configured update sources." >&2
  exit 1
fi
if ! download_update_file "client/linux/self_update.sh" "$tmp_dir/self_update.sh"; then
  echo "Failed to download self_update.sh from configured update sources." >&2
  exit 1
fi
printf '%s\n' "$remote_version" > "$tmp_dir/AGENT_VERSION"

install -m 0755 "$tmp_dir/collect_and_send.sh" "$INSTALL_DIR/collect_and_send.sh"
install -m 0755 "$tmp_dir/self_update.sh" "$INSTALL_DIR/self_update.sh"
install -m 0644 "$tmp_dir/AGENT_VERSION" "$AGENT_VERSION_FILE"

ts="$(date +"%d.%m.%Y %H:%M" 2>/dev/null || true)"
if [[ "$remote_version" == "$local_version" ]]; then
  echo "${ts} Monitoring agent already at ${local_version}, files refreshed (source: ${remote_version_source})"
else
  if [[ -n "$agent_version" && -n "$build_version" && "$agent_version" != "$build_version" ]]; then
    echo "${ts} Version selection: AGENT_VERSION=${agent_version}, BUILD_VERSION=${build_version}; chosen ${remote_version}"
  fi
  echo "${ts} Monitoring agent updated from ${local_version} to ${remote_version} (source: ${remote_version_source})"
fi

ensure_config_value() {
  local key="$1"
  local value="$2"
  if grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$CONFIG_FILE" 2>/dev/null; then
    sed -i -E "s|^[[:space:]]*${key}[[:space:]]*=.*$|${key}=\"$(printf '%s' "$value" | sed 's/[&|\\]/\\&/g')\"|" "$CONFIG_FILE"
  else
    printf '\n%s="%s"\n' "$key" "$value" >> "$CONFIG_FILE"
  fi
}

DETECTED_HANA_SID="${HANA_SID:-}"
if [[ -z "$DETECTED_HANA_SID" ]] && [[ -d /hana/shared ]]; then
  DETECTED_HANA_SID="$(find /hana/shared -mindepth 1 -maxdepth 1 -type d 2>/dev/null \
    | awk -F/ '{print $NF}' \
    | grep -E '^[A-Z][A-Z0-9]{2}$' \
    | head -1 || true)"
fi

ensure_config_value "HANA_SID" "$DETECTED_HANA_SID"
ensure_config_value "HANA_ADDONS_ENABLED" "1"
ensure_config_value "HANA_ADDONS_USER" "HARVEST"
ensure_config_value "HANA_ADDONS_PASSWORD" "0djKUt&xbLK0AYr"
ensure_config_value "HANA_ADDONS_QUERY_TIMEOUT_SEC" "15"
ensure_config_value "HANA_ADDONS_HOST" "127.0.0.1"
ensure_config_value "HANA_ADDONS_PORT" "30015"
if [[ -n "$UPDATE_BASE_URL" ]]; then
  ensure_config_value "UPDATE_BASE_URL" "$UPDATE_BASE_URL"
fi
if [[ -n "$SERVER_URL" ]]; then
  ensure_config_value "SERVER_URL" "$SERVER_URL"
fi
if [[ -n "$UPDATE_BASE_URL" ]]; then
  ensure_config_value "RAW_BASE_URL" "$UPDATE_BASE_URL"
fi
ensure_config_value "GITHUB_REPO" ""
# Migration: remove old static DIR_SCAN_DEEP_PATHS that was auto-written by a
# previous agent version. The new agent performs a hostname-aware search and
# will re-write the correct value on the next run.
if grep -qE '^[[:space:]]*DIR_SCAN_DEEP_PATHS[[:space:]]*=[[:space:]]*"?/hana/shared/backup_service/backups/\*/\*"?[[:space:]]*$' "$CONFIG_FILE" 2>/dev/null; then
  sed -i -E 's|^[[:space:]]*DIR_SCAN_DEEP_PATHS[[:space:]]*=.*$|DIR_SCAN_DEEP_PATHS=""|' "$CONFIG_FILE"
  echo "Migration: reset stale DIR_SCAN_DEEP_PATHS in $CONFIG_FILE (will be re-detected on next run)"
fi
