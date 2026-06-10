#!/usr/bin/env bash
# Script guardian: refreshes collect_and_send, self_update, and AGENT_VERSION from /updates only.
# Does not update itself. Interval enforced via SCRIPT_GUARDIAN_INTERVAL_MINUTES (default 125).
set -euo pipefail

CONFIG_FILE="${CONFIG_FILE:-/etc/monitoring-agent/agent.conf}"
GUARDIAN_INTERVAL_MINUTES="${SCRIPT_GUARDIAN_INTERVAL_MINUTES:-125}"

if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "Config file not found: $CONFIG_FILE" >&2
  exit 1
fi

# shellcheck source=/dev/null
source "$CONFIG_FILE"

INSTALL_DIR="${INSTALL_DIR:-/opt/monitoring-agent}"
AGENT_VERSION_FILE="${AGENT_VERSION_FILE:-$INSTALL_DIR/AGENT_VERSION}"
GUARDIAN_LOG_FILE="${GUARDIAN_LOG_FILE:-/var/log/monitoring-agent-guardian.log}"
TLS_INSECURE="${TLS_INSECURE:-0}"
LOCK_FILE="${SCRIPT_GUARDIAN_LOCK_FILE:-$INSTALL_DIR/.script_guardian.lock}"
LAST_RUN_FILE="${SCRIPT_GUARDIAN_LAST_RUN_FILE:-$INSTALL_DIR/.script_guardian_last_run_epoch}"

CANONICAL_UPDATE_BASE_URL="https://infoboard.ang-schweiz.ch/updates"
SECONDARY_UPDATE_BASE_URL="https://infoboard.an-group.work/updates"
LEGACY_UPDATE_BASE_URL="https://monitoring.rolfwalker.ch/updates"
CONFIG_UPDATE_BASE_URL="${UPDATE_BASE_URL:-}"
CONFIG_RAW_BASE_URL="${RAW_BASE_URL:-}"
CONFIG_SERVER_URL="${SERVER_URL:-}"

CURL_CONNECT_TIMEOUT_SEC="${CURL_CONNECT_TIMEOUT_SEC:-10}"
CURL_MAX_TIME_SEC="${CURL_MAX_TIME_SEC:-45}"
CURL_BASE_ARGS=(--fail --silent --show-error --location --connect-timeout "$CURL_CONNECT_TIMEOUT_SEC" --max-time "$CURL_MAX_TIME_SEC")
if [[ "$TLS_INSECURE" == "1" ]]; then
  CURL_BASE_ARGS+=(--insecure)
fi

UPDATE_BASE_CANDIDATES=()

guardian_log() {
  local ts
  ts="$(date +"%d.%m.%Y %H:%M:%S" 2>/dev/null || date)"
  printf '%s %s\n' "$ts" "$*" >> "$GUARDIAN_LOG_FILE" 2>/dev/null || true
}

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
add_update_base_candidate "$SECONDARY_UPDATE_BASE_URL"
add_update_base_candidate "$LEGACY_UPDATE_BASE_URL"
if [[ -n "$CONFIG_SERVER_URL" ]]; then
  add_update_base_candidate "${CONFIG_SERVER_URL%/}/updates"
fi
add_update_base_candidate "$CONFIG_UPDATE_BASE_URL"
add_update_base_candidate "$CONFIG_RAW_BASE_URL"

normalize_guardian_interval_minutes() {
  local value="${1:-125}"
  if ! [[ "$value" =~ ^[0-9]+$ ]] || [[ "$value" -lt 30 ]] || [[ "$value" -gt 720 ]]; then
    printf '%s' "125"
    return 0
  fi
  printf '%s' "$value"
}

GUARDIAN_INTERVAL_MINUTES="$(normalize_guardian_interval_minutes "$GUARDIAN_INTERVAL_MINUTES")"
GUARDIAN_INTERVAL_SEC=$(( GUARDIAN_INTERVAL_MINUTES * 60 ))

should_skip_interval() {
  local last_epoch=0 now_epoch
  if [[ ! -f "$LAST_RUN_FILE" ]]; then
    return 1
  fi
  last_epoch="$(head -n 1 "$LAST_RUN_FILE" 2>/dev/null || echo 0)"
  if ! [[ "$last_epoch" =~ ^[0-9]+$ ]]; then
    return 1
  fi
  now_epoch="$(date +%s 2>/dev/null || echo 0)"
  if [[ "$now_epoch" -gt "$last_epoch" ]] && [[ $(( now_epoch - last_epoch )) -lt "$GUARDIAN_INTERVAL_SEC" ]]; then
    return 0
  fi
  return 1
}

acquire_guardian_lock() {
  exec 9>"$LOCK_FILE"
  if ! flock -n 9; then
    guardian_log "SKIP lock busy ($LOCK_FILE)"
    exit 0
  fi
}

version_is_valid() {
  local value="${1:-}"
  [[ "$value" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]
}

version_is_newer() {
  local newer="${1:-}"
  local older="${2:-}"
  [[ "$(printf '%s\n%s\n' "$older" "$newer" | sort -V | tail -n 1)" == "$newer" ]]
}

validate_collect_script() {
  local path="$1"
  [[ -f "$path" ]] || return 1
  local size
  size="$(wc -c < "$path" 2>/dev/null | tr -d ' ')"
  [[ "$size" =~ ^[0-9]+$ ]] && [[ "$size" -ge 20000 ]] || return 1
  bash -n "$path" 2>/dev/null || return 1
  grep -q 'post_payload' "$path" 2>/dev/null || grep -q 'agent-report' "$path" 2>/dev/null || return 1
  grep -q 'collect_and_send' "$path" 2>/dev/null || return 1
  return 0
}

validate_self_update_script() {
  local path="$1"
  [[ -f "$path" ]] || return 1
  local size
  size="$(wc -c < "$path" 2>/dev/null | tr -d ' ')"
  [[ "$size" =~ ^[0-9]+$ ]] && [[ "$size" -ge 1500 ]] || return 1
  bash -n "$path" 2>/dev/null || return 1
  grep -q 'self_update' "$path" 2>/dev/null || return 1
  grep -q 'download_update_file\|collect_and_send\.sh' "$path" 2>/dev/null || return 1
  return 0
}

validate_agent_version_file() {
  local path="$1"
  local ver=""
  [[ -f "$path" ]] || return 1
  ver="$(head -n 1 "$path" 2>/dev/null | tr -d '[:space:]')"
  version_is_valid "$ver"
}

download_update_file() {
  local rel="$1"
  local out="$2"
  local base=""
  for base in "${UPDATE_BASE_CANDIDATES[@]}"; do
    if curl "${CURL_BASE_ARGS[@]}" "$base/$rel" -o "$out" 2>/dev/null; then
      printf '%s' "$base"
      return 0
    fi
  done
  return 1
}

atomic_install_file() {
  local src="$1"
  local dest="$2"
  local mode="$3"
  local tmp_dest="${dest}.guardian.new"
  cp -f "$src" "$tmp_dest" 2>/dev/null || return 1
  chmod "$mode" "$tmp_dest" 2>/dev/null || true
  mv -f "$tmp_dest" "$dest"
}

mkdir -p "$(dirname "$GUARDIAN_LOG_FILE")" "$INSTALL_DIR" 2>/dev/null || true
touch "$GUARDIAN_LOG_FILE" 2>/dev/null || true
chmod 0640 "$GUARDIAN_LOG_FILE" 2>/dev/null || true

if should_skip_interval; then
  exit 0
fi

acquire_guardian_lock

if should_skip_interval; then
  exit 0
fi

guardian_log "START interval=${GUARDIAN_INTERVAL_MINUTES}min install_dir=$INSTALL_DIR"

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

selected_base=""
if selected_base="$(download_update_file "client/linux/collect_and_send.sh" "$tmp_dir/collect_and_send.sh")"; then
  :
else
  guardian_log "FAIL collect_and_send download"
  exit 1
fi

if ! validate_collect_script "$tmp_dir/collect_and_send.sh"; then
  guardian_log "FAIL collect_and_send validation; keeping local files"
  exit 1
fi

if ! download_update_file "client/linux/self_update.sh" "$tmp_dir/self_update.sh" >/dev/null; then
  guardian_log "FAIL self_update download"
  exit 1
fi

if ! validate_self_update_script "$tmp_dir/self_update.sh"; then
  guardian_log "FAIL self_update validation; keeping local files"
  exit 1
fi

if ! download_update_file "AGENT_VERSION" "$tmp_dir/AGENT_VERSION" >/dev/null; then
  if ! download_update_file "BUILD_VERSION" "$tmp_dir/AGENT_VERSION" >/dev/null; then
    guardian_log "FAIL AGENT_VERSION download"
    exit 1
  fi
fi

if ! validate_agent_version_file "$tmp_dir/AGENT_VERSION"; then
  guardian_log "FAIL AGENT_VERSION invalid; keeping local files"
  exit 1
fi

remote_version="$(head -n 1 "$tmp_dir/AGENT_VERSION" | tr -d '[:space:]')"
local_version="unknown"
if [[ -f "$AGENT_VERSION_FILE" ]]; then
  local_version="$(head -n 1 "$AGENT_VERSION_FILE" | tr -d '[:space:]')"
fi

if ! atomic_install_file "$tmp_dir/collect_and_send.sh" "$INSTALL_DIR/collect_and_send.sh" "0755"; then
  guardian_log "FAIL install collect_and_send"
  exit 1
fi
if ! atomic_install_file "$tmp_dir/self_update.sh" "$INSTALL_DIR/self_update.sh" "0755"; then
  guardian_log "FAIL install self_update"
  exit 1
fi
if ! atomic_install_file "$tmp_dir/AGENT_VERSION" "$AGENT_VERSION_FILE" "0644"; then
  guardian_log "FAIL install AGENT_VERSION"
  exit 1
fi

if download_update_file "client/linux/monitor_probe.sh" "$tmp_dir/monitor_probe.sh" >/dev/null \
  && bash -n "$tmp_dir/monitor_probe.sh" 2>/dev/null; then
  if atomic_install_file "$tmp_dir/monitor_probe.sh" "$INSTALL_DIR/monitor_probe.sh" "0755"; then
    guardian_log "OK refreshed monitor_probe.sh"
  else
    guardian_log "WARN monitor_probe install failed"
  fi
else
  guardian_log "SKIP monitor_probe (not available on update server)"
fi

date +%s > "$LAST_RUN_FILE" 2>/dev/null || true

if version_is_valid "$remote_version" && version_is_valid "$local_version" && version_is_newer "$remote_version" "$local_version"; then
  guardian_log "OK refreshed scripts; AGENT_VERSION ${local_version} -> ${remote_version} (source: ${selected_base:-updates})"
elif [[ "$remote_version" == "$local_version" ]]; then
  guardian_log "OK refreshed scripts; version unchanged (${remote_version})"
else
  guardian_log "OK refreshed scripts; version file now ${remote_version} (was ${local_version})"
fi

exit 0
