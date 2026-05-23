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
CONFIG_SERVER_URL="${SERVER_URL:-}"
CONFIG_UPDATE_BASE_URL="${UPDATE_BASE_URL:-}"
CONFIG_RAW_BASE_URL="${RAW_BASE_URL:-}"
CANONICAL_SERVER_URL="https://infoboard.an-group.work"
LEGACY_SERVER_URL="https://monitoring.rolfwalker.ch"
CANONICAL_UPDATE_BASE_URL="${CANONICAL_SERVER_URL%/}/updates"
LEGACY_UPDATE_BASE_URL="${LEGACY_SERVER_URL%/}/updates"
AGENT_VERSION_FILE="${AGENT_VERSION_FILE:-$INSTALL_DIR/AGENT_VERSION}"
TLS_INSECURE="${TLS_INSECURE:-0}"
CURL_CONNECT_TIMEOUT_SEC="${CURL_CONNECT_TIMEOUT_SEC:-10}"
CURL_MAX_TIME_SEC="${CURL_MAX_TIME_SEC:-45}"

UPDATE_BASE_CANDIDATES=()

add_update_base_candidate() {
  local candidate="${1:-}"
  candidate="${candidate%/}"
  [[ -z "$candidate" ]] && return
  local existing
  for existing in "${UPDATE_BASE_CANDIDATES[@]:-}"; do
    [[ "$existing" == "$candidate" ]] && return
  done
  UPDATE_BASE_CANDIDATES+=("$candidate")
}

add_update_base_candidate "$CANONICAL_UPDATE_BASE_URL"
add_update_base_candidate "$LEGACY_UPDATE_BASE_URL"
if [[ -n "$CONFIG_SERVER_URL" ]]; then
  add_update_base_candidate "${CONFIG_SERVER_URL%/}/updates"
fi
add_update_base_candidate "$CONFIG_UPDATE_BASE_URL"
add_update_base_candidate "$CONFIG_RAW_BASE_URL"

CURL_BASE_ARGS=(--fail --silent --show-error --location --connect-timeout "$CURL_CONNECT_TIMEOUT_SEC" --max-time "$CURL_MAX_TIME_SEC")
if [[ "$TLS_INSECURE" == "1" ]]; then
  CURL_BASE_ARGS+=(--insecure)
fi

if [[ "${#UPDATE_BASE_CANDIDATES[@]}" -eq 0 ]]; then
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
  local base=""

  for base in "${UPDATE_BASE_CANDIDATES[@]}"; do
    candidate="$(curl "${CURL_BASE_ARGS[@]}" "$base/$rel" 2>/dev/null | tr -d '[:space:]' || true)"
    if version_is_valid "$candidate"; then
      printf '%s|%s|%s\n' "$candidate" "$base/$rel" "$base"
      return 0
    fi
  done

  return 1
}

local_version="unknown"
if [[ -f "$AGENT_VERSION_FILE" ]]; then
  local_version="$(head -n 1 "$AGENT_VERSION_FILE" | tr -d '[:space:]')"
fi

agent_version=""
agent_source=""
agent_base=""
agent_pair=""
if agent_pair="$(fetch_remote_version_file "AGENT_VERSION" 2>/dev/null)"; then
  agent_version="$(printf '%s' "$agent_pair" | cut -d'|' -f1)"
  agent_source="$(printf '%s' "$agent_pair" | cut -d'|' -f2)"
  agent_base="$(printf '%s' "$agent_pair" | cut -d'|' -f3)"
fi

build_version=""
build_source=""
build_base=""
build_pair=""
if build_pair="$(fetch_remote_version_file "BUILD_VERSION" 2>/dev/null)"; then
  build_version="$(printf '%s' "$build_pair" | cut -d'|' -f1)"
  build_source="$(printf '%s' "$build_pair" | cut -d'|' -f2)"
  build_base="$(printf '%s' "$build_pair" | cut -d'|' -f3)"
fi

remote_version=""
remote_version_source=""
selected_update_base=""
if version_is_valid "$agent_version"; then
  remote_version="$agent_version"
  remote_version_source="$agent_source"
  selected_update_base="$agent_base"
fi
if version_is_valid "$build_version"; then
  if [[ -z "$remote_version" ]] || version_is_newer "$build_version" "$remote_version"; then
    remote_version="$build_version"
    remote_version_source="$build_source"
    selected_update_base="$build_base"
  fi
fi

if [[ -z "$remote_version" ]]; then
  echo "Remote version lookup failed (AGENT_VERSION/BUILD_VERSION empty or invalid); aborting update check." >&2
  exit 1
fi

download_update_file() {
  local rel="$1"
  local out="$2"
  local base=""
  if [[ -n "$selected_update_base" ]] && curl "${CURL_BASE_ARGS[@]}" "$selected_update_base/$rel" -o "$out" 2>/dev/null; then
    return 0
  fi
  for base in "${UPDATE_BASE_CANDIDATES[@]}"; do
    [[ "$base" == "$selected_update_base" ]] && continue
    if curl "${CURL_BASE_ARGS[@]}" "$base/$rel" -o "$out" 2>/dev/null; then
      selected_update_base="$base"
      return 0
    fi
  done
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
target_server_url="$CONFIG_SERVER_URL"
target_update_base_url="$selected_update_base"
if [[ -n "$selected_update_base" && "$selected_update_base" == "$CANONICAL_UPDATE_BASE_URL" ]]; then
  target_server_url="$CANONICAL_SERVER_URL"
  target_update_base_url="$CANONICAL_UPDATE_BASE_URL"
elif [[ -z "$target_server_url" && "$selected_update_base" =~ /updates$ ]]; then
  target_server_url="${selected_update_base%/updates}"
fi

if [[ -n "$target_update_base_url" ]]; then
  ensure_config_value "UPDATE_BASE_URL" "$target_update_base_url"
  ensure_config_value "RAW_BASE_URL" "$target_update_base_url"
fi
if [[ -n "$target_server_url" ]]; then
  ensure_config_value "SERVER_URL" "$target_server_url"
fi
ensure_config_value "GITHUB_REPO" ""
# Migration: remove old static DIR_SCAN_DEEP_PATHS that was auto-written by a
# previous agent version. The new agent performs a hostname-aware search and
# will re-write the correct value on the next run.
if grep -qE '^[[:space:]]*DIR_SCAN_DEEP_PATHS[[:space:]]*=[[:space:]]*"?/hana/shared/backup_service/backups/\*/\*"?[[:space:]]*$' "$CONFIG_FILE" 2>/dev/null; then
  sed -i -E 's|^[[:space:]]*DIR_SCAN_DEEP_PATHS[[:space:]]*=.*$|DIR_SCAN_DEEP_PATHS=""|' "$CONFIG_FILE"
  echo "Migration: reset stale DIR_SCAN_DEEP_PATHS in $CONFIG_FILE (will be re-detected on next run)"
fi
