#!/usr/bin/env bash
set -euo pipefail

CONFIG_FILE="${CONFIG_FILE:-/etc/monitoring-agent/agent.conf}"
AGENT_VERSION_FILE="${AGENT_VERSION_FILE:-/opt/monitoring-agent/AGENT_VERSION}"
AGENT_QUEUE_DIR="${AGENT_QUEUE_DIR:-/var/lib/monitoring-agent/queue}"
PRIORITY_UPDATE_CHECK_MINUTES="${PRIORITY_UPDATE_CHECK_MINUTES:-60}"
PRIORITY_UPDATE_STATE_FILE="${PRIORITY_UPDATE_STATE_FILE:-/var/lib/monitoring-agent/last_priority_update_check}"
UPDATE_LOG_FILE="${UPDATE_LOG_FILE:-/var/log/monitoring-agent-update.log}"
UPDATE_LOG_LINES="${UPDATE_LOG_LINES:-40}"
JOURNAL_ERRORS_LIMIT="${JOURNAL_ERRORS_LIMIT:-20}"
JOURNAL_ERRORS_SINCE_MINUTES="${JOURNAL_ERRORS_SINCE_MINUTES:-180}"
TOP_PROCESSES_LIMIT="${TOP_PROCESSES_LIMIT:-8}"
CONTAINERS_LIMIT="${CONTAINERS_LIMIT:-30}"
LARGE_FILES_SCAN_ENABLED="${LARGE_FILES_SCAN_ENABLED:-1}"
LARGE_FILES_SCAN_INTERVAL_HOURS="${LARGE_FILES_SCAN_INTERVAL_HOURS:-24}"
LARGE_FILES_SCAN_RUN_HOUR_UTC="${LARGE_FILES_SCAN_RUN_HOUR_UTC:-2}"
LARGE_FILES_SCAN_TIMEOUT_SEC="${LARGE_FILES_SCAN_TIMEOUT_SEC:-900}"
LARGE_FILES_MIN_SIZE_MB="${LARGE_FILES_MIN_SIZE_MB:-500}"
LARGE_FILES_TOP_PER_FS="${LARGE_FILES_TOP_PER_FS:-10}"
LARGE_FILES_CACHE_FILE="${LARGE_FILES_CACHE_FILE:-/var/lib/monitoring-agent/large-files-cache.json}"
LARGE_FILES_EXCLUDE_PATHS="${LARGE_FILES_EXCLUDE_PATHS:-/hana/data/.snapshot}"
LARGE_FILES_SCAN_FORCE="${LARGE_FILES_SCAN_FORCE:-0}"

if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "Config file not found: $CONFIG_FILE" >&2
  exit 1
fi

# shellcheck source=/dev/null
source "$CONFIG_FILE"

if [[ -z "${SERVER_URL:-}" ]]; then
  echo "SERVER_URL is not set in $CONFIG_FILE" >&2
  exit 1
fi

TLS_INSECURE="${TLS_INSECURE:-0}"

mkdir -p "$AGENT_QUEUE_DIR"

if [[ -d "$(dirname "$PRIORITY_UPDATE_STATE_FILE")" ]]; then
  :
else
  mkdir -p "$(dirname "$PRIORITY_UPDATE_STATE_FILE")" 2>/dev/null || true
fi

count_queue_files() {
  local count
  shopt -s nullglob
  local queued_files=("$AGENT_QUEUE_DIR"/*.json)
  shopt -u nullglob
  count="${#queued_files[@]}"
  printf '%s' "$count"
}

json_escape() {
  printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

upsert_config_value() {
  local key="$1"
  local value="$2"
  local tmp_file

  tmp_file="$(mktemp)"
  awk -v key="$key" -v value="$value" '
    BEGIN { updated = 0 }
    $0 ~ "^[[:space:]]*" key "=" {
      print key "=\"" value "\""
      updated = 1
      next
    }
    { print }
    END {
      if (!updated) {
        print key "=\"" value "\""
      }
    }
  ' "$CONFIG_FILE" > "$tmp_file"
  mv "$tmp_file" "$CONFIG_FILE"
  chmod 0600 "$CONFIG_FILE" 2>/dev/null || true
}

apply_api_key_update() {
  local next_api_key="$1"

  if [[ -z "$next_api_key" ]]; then
    return 1
  fi

  upsert_config_value "API_KEY" "$next_api_key"
  API_KEY="$next_api_key"
  export API_KEY
  return 0
}

read_meminfo_kb() {
  local key="$1"
  awk -v key="$key" '$1 == key ":" {print $2; exit}' /proc/meminfo
}

calc_percent() {
  local used="$1"
  local total="$2"

  if [[ -z "$used" || -z "$total" || "$total" -le 0 ]]; then
    printf '0'
    return
  fi

  awk -v used="$used" -v total="$total" 'BEGIN { printf "%.2f", (used / total) * 100 }'
}

read_cpu_totals() {
  awk '/^cpu / {print $2, $3, $4, $5, $6, $7, $8, $9}' /proc/stat
}

calc_cpu_usage_percent() {
  local user1 nice1 system1 idle1 iowait1 irq1 softirq1 steal1
  local user2 nice2 system2 idle2 iowait2 irq2 softirq2 steal2
  local idle_delta total_delta

  read -r user1 nice1 system1 idle1 iowait1 irq1 softirq1 steal1 <<< "$(read_cpu_totals)"
  sleep 1
  read -r user2 nice2 system2 idle2 iowait2 irq2 softirq2 steal2 <<< "$(read_cpu_totals)"

  idle_delta=$(( (idle2 + iowait2) - (idle1 + iowait1) ))
  total_delta=$((
    (user2 + nice2 + system2 + idle2 + iowait2 + irq2 + softirq2 + steal2) -
    (user1 + nice1 + system1 + idle1 + iowait1 + irq1 + softirq1 + steal1)
  ))

  if [[ "$total_delta" -le 0 ]]; then
    printf '0'
    return
  fi

  awk -v idle_delta="$idle_delta" -v total_delta="$total_delta" 'BEGIN { printf "%.2f", (1 - (idle_delta / total_delta)) * 100 }'
}

append_json_entry() {
  local current="$1"
  local entry="$2"

  if [[ -z "$current" ]]; then
    printf '%s' "$entry"
  else
    printf '%s,%s' "$current" "$entry"
  fi
}

epoch_to_utc() {
  local epoch_value="$1"
  if [[ -z "$epoch_value" ]] || ! [[ "$epoch_value" =~ ^[0-9]+$ ]]; then
    printf ''
    return
  fi

  date -u -d "@$epoch_value" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || printf ''
}

collect_update_log_json() {
  local entries="" line line_count=0
  local last_epoch=0
  local next_epoch=0
  local last_priority_check_utc=""
  local next_priority_check_utc=""
  local recurring_update_hours="${UPDATE_HOURS:-6}"

  if ! [[ "$recurring_update_hours" =~ ^[0-9]+$ ]]; then
    recurring_update_hours=6
  fi

  if [[ -f "$PRIORITY_UPDATE_STATE_FILE" ]]; then
    last_epoch="$(head -n 1 "$PRIORITY_UPDATE_STATE_FILE" 2>/dev/null || echo 0)"
    if ! [[ "$last_epoch" =~ ^[0-9]+$ ]]; then
      last_epoch=0
    fi
  fi

  if [[ "$last_epoch" =~ ^[0-9]+$ ]] && [[ "$last_epoch" -gt 0 ]] && [[ "$PRIORITY_UPDATE_CHECK_MINUTES" =~ ^[0-9]+$ ]] && [[ "$PRIORITY_UPDATE_CHECK_MINUTES" -gt 0 ]]; then
    next_epoch=$(( last_epoch + (PRIORITY_UPDATE_CHECK_MINUTES * 60) ))
    last_priority_check_utc="$(epoch_to_utc "$last_epoch")"
    next_priority_check_utc="$(epoch_to_utc "$next_epoch")"
  fi

  if [[ ! -r "$UPDATE_LOG_FILE" ]]; then
    printf '{"available":false,"path":"%s","line_count":0,"lines":[],"priority_check_minutes":%s,"last_priority_check_utc":"%s","next_priority_check_utc":"%s","recurring_update_hours":%s,"recurring_update_hint":"%s"}' \
      "$(json_escape "$UPDATE_LOG_FILE")" \
      "${PRIORITY_UPDATE_CHECK_MINUTES:-0}" \
      "$(json_escape "$last_priority_check_utc")" \
      "$(json_escape "$next_priority_check_utc")" \
      "${recurring_update_hours}" \
      "$(json_escape "Linux-Fallback-Update per Cron standardmaessig Minute 11 alle ${recurring_update_hours} Stunden")"
    return
  fi

  while IFS= read -r line; do
    entries="$(append_json_entry "$entries" "\"$(json_escape "$line")\"")"
    line_count=$((line_count + 1))
  done < <(tail -n "$UPDATE_LOG_LINES" "$UPDATE_LOG_FILE" 2>/dev/null || true)

  printf '{"available":true,"path":"%s","line_count":%s,"lines":[%s],"priority_check_minutes":%s,"last_priority_check_utc":"%s","next_priority_check_utc":"%s","recurring_update_hours":%s,"recurring_update_hint":"%s"}' \
    "$(json_escape "$UPDATE_LOG_FILE")" \
    "$line_count" \
    "$entries" \
    "${PRIORITY_UPDATE_CHECK_MINUTES:-0}" \
    "$(json_escape "$last_priority_check_utc")" \
    "$(json_escape "$next_priority_check_utc")" \
    "${recurring_update_hours}" \
    "$(json_escape "Linux-Fallback-Update per Cron standardmaessig Minute 11 alle ${recurring_update_hours} Stunden")"
}

maybe_priority_self_update() {
  local interval_minutes now_epoch last_epoch

  if ! [[ "$PRIORITY_UPDATE_CHECK_MINUTES" =~ ^[0-9]+$ ]] || [[ "$PRIORITY_UPDATE_CHECK_MINUTES" -le 0 ]]; then
    return
  fi

  now_epoch="$(date +%s)"
  last_epoch=0
  if [[ -f "$PRIORITY_UPDATE_STATE_FILE" ]]; then
    last_epoch="$(head -n 1 "$PRIORITY_UPDATE_STATE_FILE" 2>/dev/null || echo 0)"
    if ! [[ "$last_epoch" =~ ^[0-9]+$ ]]; then
      last_epoch=0
    fi
  fi

  interval_minutes=$(( PRIORITY_UPDATE_CHECK_MINUTES * 60 ))
  if (( now_epoch - last_epoch < interval_minutes )); then
    return
  fi

  printf '%s\n' "$now_epoch" > "$PRIORITY_UPDATE_STATE_FILE" 2>/dev/null || true

  run_self_update_now || true
}

run_self_update_now() {
  local updater_path="${INSTALL_DIR:-/opt/monitoring-agent}/self_update.sh"
  local tmp_updater=""
  local curl_args=(--silent --show-error --fail)

  if [[ "$TLS_INSECURE" == "1" ]]; then
    curl_args+=(--insecure)
  fi

  if [[ -n "${RAW_BASE_URL:-}" ]]; then
    tmp_updater="$(mktemp)"
    if curl "${curl_args[@]}" "$RAW_BASE_URL/client/linux/self_update.sh" -o "$tmp_updater" 2>/dev/null; then
      chmod 0755 "$tmp_updater"
      if CONFIG_FILE="$CONFIG_FILE" AGENT_VERSION_FILE="$AGENT_VERSION_FILE" "$tmp_updater" >> "$UPDATE_LOG_FILE" 2>&1; then
        rm -f "$tmp_updater"
        return 0
      fi
    fi
    [[ -n "$tmp_updater" ]] && rm -f "$tmp_updater"
  fi

  if [[ -x "$updater_path" ]]; then
    CONFIG_FILE="$CONFIG_FILE" AGENT_VERSION_FILE="$AGENT_VERSION_FILE" "$updater_path" >> "$UPDATE_LOG_FILE" 2>&1
    return $?
  fi

  return 127
}

collect_agent_config_json() {
  local entries="" line key value masked_keys="API_KEY|PASSWORD|SECRET|TOKEN|PASS"
  if [[ ! -r "$CONFIG_FILE" ]]; then
    printf '{"available":false,"path":"%s","entries":[]}' "$(json_escape "$CONFIG_FILE")"
    return
  fi
  while IFS= read -r line; do
    # skip blank lines and comments
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    if [[ "$line" =~ ^[[:space:]]*([A-Za-z_][A-Za-z0-9_]*)[[:space:]]*=[[:space:]]*(.*)[[:space:]]*$ ]]; then
      key="${BASH_REMATCH[1]}"
      value="${BASH_REMATCH[2]}"
      # strip surrounding quotes
      value="${value%\"}"
      value="${value#\"}"
      if echo "$key" | grep -qiE "$masked_keys"; then
        value="***"
      fi
      entries="$(append_json_entry "$entries" "{\"key\":\"$(json_escape "$key")\",\"value\":\"$(json_escape "$value")\"}")"
    fi
  done < "$CONFIG_FILE"
  printf '{"available":true,"path":"%s","entries":[%s]}' "$(json_escape "$CONFIG_FILE")" "$entries"
}

collect_journal_errors_json() {
  local entries="" line timestamp message entry

  if ! command -v journalctl >/dev/null 2>&1; then
    printf ''
    return
  fi

  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    timestamp="${line:0:25}"
    message="${line:26}"
    entry=$(cat <<EOF
{"time":"$(json_escape "$timestamp")","priority":"err","unit":"-","message":"$(json_escape "$message")"}
EOF
)
    entries="$(append_json_entry "$entries" "$entry")"
  done < <(
    journalctl -p err..alert --since "-${JOURNAL_ERRORS_SINCE_MINUTES} minutes" --no-pager -o short-iso 2>/dev/null \
      | tail -n "$JOURNAL_ERRORS_LIMIT"
  )

  printf '%s' "$entries"
}

collect_top_processes_json() {
  local entries="" pid user pcpu pmem rss comm cmd entry

  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    read -r pid user pcpu pmem rss comm cmd <<< "$line"
    entry=$(cat <<EOF
{"pid":${pid:-0},"user":"$(json_escape "${user:-}")","cpu_percent":${pcpu:-0},"memory_percent":${pmem:-0},"rss_kb":${rss:-0},"name":"$(json_escape "${comm:-}")","command":"$(json_escape "${cmd:-}")"}
EOF
)
    entries="$(append_json_entry "$entries" "$entry")"
  done < <(
    ps -eo pid=,user=,pcpu=,pmem=,rss=,comm=,args= --sort=-pcpu 2>/dev/null | head -n "$TOP_PROCESSES_LIMIT"
  )

  printf '%s' "$entries"
}

collect_containers_json() {
  local entries="" line name image state status health restarts entry

  if ! command -v docker >/dev/null 2>&1; then
    printf ''
    return
  fi

  if ! docker info >/dev/null 2>&1; then
    printf ''
    return
  fi

  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    IFS='|' read -r name image state status <<< "$line"
    health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}n/a{{end}}' "$name" 2>/dev/null || echo n/a)"
    restarts="$(docker inspect -f '{{.RestartCount}}' "$name" 2>/dev/null || echo 0)"
    entry=$(cat <<EOF
{"name":"$(json_escape "$name")","image":"$(json_escape "$image")","state":"$(json_escape "$state")","status":"$(json_escape "$status")","health":"$(json_escape "$health")","restart_count":${restarts:-0}}
EOF
)
    entries="$(append_json_entry "$entries" "$entry")"
  done < <(
    docker ps -a --format '{{.Names}}|{{.Image}}|{{.State}}|{{.Status}}' 2>/dev/null | head -n "$CONTAINERS_LIMIT"
  )

  printf '%s' "$entries"
}

  collect_large_files_json() {
    if [[ "$LARGE_FILES_SCAN_ENABLED" != "1" ]]; then
    printf '{"enabled":false,"status":"disabled","filesystems":[]}'
    return
    fi

    if ! command -v python3 >/dev/null 2>&1; then
    printf '{"enabled":true,"status":"unavailable","error":"python3 missing","filesystems":[]}'
    return
    fi

    LARGE_FILES_SCAN_INTERVAL_HOURS="${LARGE_FILES_SCAN_INTERVAL_HOURS}" \
    LARGE_FILES_SCAN_RUN_HOUR_UTC="${LARGE_FILES_SCAN_RUN_HOUR_UTC}" \
    LARGE_FILES_SCAN_TIMEOUT_SEC="${LARGE_FILES_SCAN_TIMEOUT_SEC}" \
    LARGE_FILES_MIN_SIZE_MB="${LARGE_FILES_MIN_SIZE_MB}" \
    LARGE_FILES_TOP_PER_FS="${LARGE_FILES_TOP_PER_FS}" \
    LARGE_FILES_CACHE_FILE="${LARGE_FILES_CACHE_FILE}" \
    LARGE_FILES_EXCLUDE_PATHS="${LARGE_FILES_EXCLUDE_PATHS}" \
    LARGE_FILES_SCAN_FORCE="${LARGE_FILES_SCAN_FORCE}" \
    sed 's/^  //' <<'PY' | python3 -
  import datetime as dt
  import heapq
  import json
  import os
  import pwd
  import stat
  import subprocess
  import time


  def to_int(name: str, default: int, minimum: int = 0, maximum: int = 10**9) -> int:
    raw = os.getenv(name, str(default)).strip()
    try:
      value = int(raw)
    except Exception:
      value = default
    return max(minimum, min(value, maximum))


  def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


  def parse_iso(value: str):
    text = str(value or "").strip()
    if not text:
      return None
    try:
      return dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except Exception:
      return None


  def is_under(path: str, prefix: str) -> bool:
    if not prefix:
      return False
    p = os.path.normpath(path)
    pref = os.path.normpath(prefix)
    return p == pref or p.startswith(pref + os.sep)


  def collect_mountpoints() -> list[str]:
    try:
      output = subprocess.check_output(
        ["df", "-PT", "-x", "tmpfs", "-x", "devtmpfs"],
        text=True,
        stderr=subprocess.DEVNULL,
      )
    except Exception:
      return []
    mounts = []
    for line in output.splitlines()[1:]:
      parts = line.split()
      if len(parts) < 7:
        continue
      mounts.append(parts[6])
    return sorted(set(mounts))


  scan_interval_hours = to_int("LARGE_FILES_SCAN_INTERVAL_HOURS", 24, 1, 24 * 30)
  run_hour_utc = to_int("LARGE_FILES_SCAN_RUN_HOUR_UTC", 2, 0, 23)
  timeout_sec = to_int("LARGE_FILES_SCAN_TIMEOUT_SEC", 900, 30, 3600)
  min_size_mb = to_int("LARGE_FILES_MIN_SIZE_MB", 500, 1, 1024 * 1024)
  top_n = to_int("LARGE_FILES_TOP_PER_FS", 10, 1, 100)
  force_scan = str(os.getenv("LARGE_FILES_SCAN_FORCE", "0")).strip().lower() in {"1", "true", "yes", "on"}
  cache_file = os.getenv("LARGE_FILES_CACHE_FILE", "/var/lib/monitoring-agent/large-files-cache.json").strip()
  exclude_raw = os.getenv("LARGE_FILES_EXCLUDE_PATHS", "/hana/data/.snapshot")
  exclude_prefixes = [os.path.normpath(p.strip()) for p in exclude_raw.split(":") if p.strip()]

  cached = {}
  if cache_file and os.path.exists(cache_file):
    try:
      with open(cache_file, "r", encoding="utf-8") as fh:
        cached = json.load(fh)
    except Exception:
      cached = {}

  now = dt.datetime.now(dt.timezone.utc)
  cached_scan_time = parse_iso(cached.get("scanned_at_utc", "")) if isinstance(cached, dict) else None
  scan_due = cached_scan_time is None or (now - cached_scan_time).total_seconds() >= scan_interval_hours * 3600
  first_scan = cached_scan_time is None
  in_scan_hour = now.hour == run_hour_utc
  should_scan = force_scan or (scan_due and (first_scan or in_scan_hour))

  result = {
    "enabled": True,
    "status": "scheduled" if scan_due else "cached",
    "force_scan": force_scan,
    "scanned_at_utc": str(cached.get("scanned_at_utc", "")) if isinstance(cached, dict) else "",
    "scan_interval_hours": scan_interval_hours,
    "run_hour_utc": run_hour_utc,
    "min_size_mb": min_size_mb,
    "top_n": top_n,
    "timed_out": bool(cached.get("timed_out", False)) if isinstance(cached, dict) else False,
    "excluded_prefixes": exclude_prefixes,
    "filesystems": list(cached.get("filesystems", [])) if isinstance(cached.get("filesystems", []), list) else [],
  }

  if should_scan:
    started = time.time()
    deadline = started + timeout_sec
    timed_out = False
    filesystems = []
    try:
      for mountpoint in collect_mountpoints():
        if any(is_under(mountpoint, pref) for pref in exclude_prefixes):
          continue
        if time.time() > deadline:
          timed_out = True
          break
        try:
          root_stat = os.stat(mountpoint)
        except Exception:
          continue
        root_dev = root_stat.st_dev
        heap = []
        scanned_regular_files = 0
        for root, dirs, files in os.walk(mountpoint, topdown=True, followlinks=False):
          if time.time() > deadline:
            timed_out = True
            break
          kept_dirs = []
          for dirname in dirs:
            dpath = os.path.join(root, dirname)
            if any(is_under(dpath, pref) for pref in exclude_prefixes):
              continue
            try:
              dstat = os.lstat(dpath)
            except Exception:
              continue
            if not stat.S_ISDIR(dstat.st_mode):
              continue
            if dstat.st_dev != root_dev:
              continue
            kept_dirs.append(dirname)
          dirs[:] = kept_dirs

          for filename in files:
            if time.time() > deadline:
              timed_out = True
              break
            fpath = os.path.join(root, filename)
            if any(is_under(fpath, pref) for pref in exclude_prefixes):
              continue
            try:
              fstat = os.lstat(fpath)
            except Exception:
              continue
            if not stat.S_ISREG(fstat.st_mode):
              continue
            if fstat.st_dev != root_dev:
              continue
            scanned_regular_files += 1
            if fstat.st_size < min_size_mb * 1024 * 1024:
              continue
            row = (int(fstat.st_size), fpath, int(fstat.st_mtime), int(fstat.st_uid))
            if len(heap) < top_n:
              heapq.heappush(heap, row)
            elif row[0] > heap[0][0]:
              heapq.heapreplace(heap, row)

        top_files = []
        for size_bytes, path, mtime, uid in sorted(heap, key=lambda item: item[0], reverse=True):
          try:
            owner = pwd.getpwuid(uid).pw_name
          except Exception:
            owner = str(uid)
          top_files.append(
            {
              "path": path,
              "size_bytes": size_bytes,
              "modified_at_utc": dt.datetime.fromtimestamp(mtime, tz=dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
              "owner": owner,
            }
          )

        filesystems.append(
          {
            "mountpoint": mountpoint,
            "scanned_regular_files": scanned_regular_files,
            "top_files": top_files,
          }
        )

      result.update(
        {
          "status": "ok",
          "scanned_at_utc": utc_now_iso(),
          "timed_out": timed_out,
          "scan_duration_sec": round(time.time() - started, 2),
          "filesystems": filesystems,
        }
      )

      if cache_file:
        try:
          os.makedirs(os.path.dirname(cache_file), exist_ok=True)
          with open(cache_file, "w", encoding="utf-8") as fh:
            json.dump(result, fh, separators=(",", ":"))
        except Exception:
          pass
    except Exception as exc:
      result.update({"status": "error", "error": str(exc)[:240]})

  print(json.dumps(result, separators=(",", ":")))
PY
  }

post_payload() {
  local payload_data="$1"

  curl_args=(
    --silent
    --show-error
    --fail
    -X POST
    -H "Content-Type: application/json"
    --data "$payload_data"
  )

  if [[ -n "${API_KEY:-}" ]]; then
    curl_args+=( -H "X-Api-Key: ${API_KEY}" )
  fi

  if [[ "$TLS_INSECURE" == "1" ]]; then
    curl_args+=( --insecure )
  fi

  curl "${curl_args[@]}" "${SERVER_URL%/}/api/v1/agent-report"
}

post_command_result() {
  local command_id="$1"
  local status="$2"
  local message="$3"
  local payload_data

  payload_data=$(cat <<EOF
{"hostname":"$(json_escape "$HOSTNAME_VALUE")","agent_id":"$(json_escape "$AGENT_ID_VALUE")","command_id":$command_id,"status":"$(json_escape "$status")","result":{"message":"$(json_escape "$message")"}}
EOF
)

  curl_args=(
    --silent
    --show-error
    --fail
    -X POST
    -H "Content-Type: application/json"
    --data "$payload_data"
  )

  if [[ -n "${API_KEY:-}" ]]; then
    curl_args+=( -H "X-Api-Key: ${API_KEY}" )
  fi

  if [[ "$TLS_INSECURE" == "1" ]]; then
    curl_args+=( --insecure )
  fi

  curl "${curl_args[@]}" "${SERVER_URL%/}/api/v1/agent-command-result" >/dev/null || true
}

execute_remote_commands() {
  local response id status message command_type next_api_key

  curl_args=(
    --silent
    --show-error
    --fail
  )
  if [[ -n "${API_KEY:-}" ]]; then
    curl_args+=( -H "X-Api-Key: ${API_KEY}" )
  fi

  if [[ "$TLS_INSECURE" == "1" ]]; then
    curl_args+=( --insecure )
  fi

  response="$(curl "${curl_args[@]}" "${SERVER_URL%/}/api/v1/agent-commands?hostname=$(printf '%s' "$HOSTNAME_VALUE" | sed 's/ /%20/g')&agent_id=$(printf '%s' "$AGENT_ID_VALUE" | sed 's/ /%20/g')&limit=10" 2>/dev/null || true)"
  [[ -n "$response" ]] || return

  while IFS= read -r command_line; do
    [[ -n "$command_line" ]] || continue
    id="$(printf '%s' "$command_line" | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p')"
    [[ -n "$id" ]] || continue

    command_type="$(printf '%s' "$command_line" | sed -n 's/.*"command_type"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
    case "$command_type" in
      update-now)
        if run_self_update_now; then
          status="completed"
          message="update command executed"
        else
          if [[ -x "${INSTALL_DIR:-/opt/monitoring-agent}/self_update.sh" ]]; then
            status="failed"
            message="update command failed"
          else
            status="failed"
            message="self_update.sh not found"
          fi
        fi
        ;;
      set-api-key)
        next_api_key="$(printf '%s' "$command_line" | sed -n 's/.*"api_key"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
        if apply_api_key_update "$next_api_key"; then
          status="completed"
          message="api key updated"
        else
          status="failed"
          message="api key update failed"
        fi
        ;;
      *)
        continue
        ;;
    esac

    post_command_result "$id" "$status" "$message"
  done < <(printf '%s' "$response" | grep -o '{[^}]*"command_type"[[:space:]]*:[[:space:]]*"[^"]*"[^}]*}')
}

flush_queue() {
  local file payload_data

  shopt -s nullglob
  local queued_files=("$AGENT_QUEUE_DIR"/*.json)
  shopt -u nullglob

  for file in "${queued_files[@]}"; do
    payload_data="$(cat "$file")"
    if post_payload "$payload_data" >/dev/null; then
      rm -f "$file"
    else
      # Keep remaining queue files for the next run when connectivity recovers.
      return 1
    fi
  done

  return 0
}

HOSTNAME_VALUE="$(hostname -f 2>/dev/null || hostname)"
PRIMARY_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i=="src") {print $(i+1); exit}}')"
ALL_IPS="$(hostname -I 2>/dev/null | xargs || true)"
TIMESTAMP_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
UPTIME_SECONDS="$(cut -d. -f1 /proc/uptime)"
KERNEL="$(uname -r)"
OS_NAME="$(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}")"
AGENT_ID_VALUE="${AGENT_ID:-$HOSTNAME_VALUE}"
DISPLAY_NAME_VALUE="${DISPLAY_NAME:-$HOSTNAME_VALUE}"
AGENT_VERSION_VALUE="unknown"
if [[ -f "$AGENT_VERSION_FILE" ]]; then
  AGENT_VERSION_VALUE="$(head -n 1 "$AGENT_VERSION_FILE" | tr -d '[:space:]')"
fi

read -r LOAD_AVG_1 LOAD_AVG_5 LOAD_AVG_15 _ < /proc/loadavg
CPU_USAGE_PERCENT="$(calc_cpu_usage_percent)"
CPU_CORES="$(nproc 2>/dev/null || echo 1)"

MEM_TOTAL_KB="$(read_meminfo_kb MemTotal)"
MEM_AVAILABLE_KB="$(read_meminfo_kb MemAvailable)"
if [[ -z "$MEM_AVAILABLE_KB" ]]; then
  MEM_AVAILABLE_KB="$(read_meminfo_kb MemFree)"
fi
MEM_USED_KB=$(( MEM_TOTAL_KB - MEM_AVAILABLE_KB ))
MEM_USED_PERCENT="$(calc_percent "$MEM_USED_KB" "$MEM_TOTAL_KB")"

SWAP_TOTAL_KB="$(read_meminfo_kb SwapTotal)"
SWAP_FREE_KB="$(read_meminfo_kb SwapFree)"
SWAP_USED_KB=$(( SWAP_TOTAL_KB - SWAP_FREE_KB ))
SWAP_USED_PERCENT="$(calc_percent "$SWAP_USED_KB" "$SWAP_TOTAL_KB")"

DEFAULT_INTERFACE="$(ip -4 route show default 2>/dev/null | awk '/default/ {print $5; exit}')"
DEFAULT_GATEWAY="$(ip -4 route show default 2>/dev/null | awk '/default/ {print $3; exit}')"

DNS_SERVERS_JSON=""
while read -r dns_ip; do
  [[ -n "$dns_ip" ]] || continue
  DNS_SERVERS_JSON="$(append_json_entry "$DNS_SERVERS_JSON" "\"$(json_escape "$dns_ip")\"")"
done < <(awk '/^nameserver[[:space:]]+/ {print $2}' /etc/resolv.conf 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | awk '!seen[$0]++')

NETWORK_INTERFACES_JSON=""
for iface_path in /sys/class/net/*; do
  [[ -e "$iface_path" ]] || continue
  iface_name="$(basename "$iface_path")"
  rx_bytes="$(cat "$iface_path/statistics/rx_bytes" 2>/dev/null || echo 0)"
  tx_bytes="$(cat "$iface_path/statistics/tx_bytes" 2>/dev/null || echo 0)"
  rx_packets="$(cat "$iface_path/statistics/rx_packets" 2>/dev/null || echo 0)"
  tx_packets="$(cat "$iface_path/statistics/tx_packets" 2>/dev/null || echo 0)"
  rx_errors="$(cat "$iface_path/statistics/rx_errors" 2>/dev/null || echo 0)"
  tx_errors="$(cat "$iface_path/statistics/tx_errors" 2>/dev/null || echo 0)"
  rx_dropped="$(cat "$iface_path/statistics/rx_dropped" 2>/dev/null || echo 0)"
  tx_dropped="$(cat "$iface_path/statistics/tx_dropped" 2>/dev/null || echo 0)"
  operstate="$(cat "$iface_path/operstate" 2>/dev/null || echo unknown)"
  mac_address="$(cat "$iface_path/address" 2>/dev/null || echo unknown)"
  is_default=false
  if [[ "$iface_name" == "$DEFAULT_INTERFACE" ]]; then
    is_default=true
  fi

  entry=$(cat <<EOF
{"name":"$(json_escape "$iface_name")","state":"$(json_escape "$operstate")","mac_address":"$(json_escape "$mac_address")","is_default":$is_default,"rx_bytes":$rx_bytes,"tx_bytes":$tx_bytes,"rx_packets":$rx_packets,"tx_packets":$tx_packets,"rx_errors":$rx_errors,"tx_errors":$tx_errors,"rx_dropped":$rx_dropped,"tx_dropped":$tx_dropped}
EOF
)

  NETWORK_INTERFACES_JSON="$(append_json_entry "$NETWORK_INTERFACES_JSON" "$entry")"
done

FILESYSTEMS_JSON=""
while IFS=' ' read -r fs_type fs_name fs_blocks fs_used fs_avail fs_pct mountpoint; do
  fs_pct_clean="${fs_pct%%%}"
  entry=$(cat <<EOF
{"fs":"$(json_escape "$fs_name")","type":"$(json_escape "$fs_type")","mountpoint":"$(json_escape "$mountpoint")","blocks":$fs_blocks,"used":$fs_used,"available":$fs_avail,"used_percent":$fs_pct_clean}
EOF
)

  FILESYSTEMS_JSON="$(append_json_entry "$FILESYSTEMS_JSON" "$entry")"
done < <(df -PT -x tmpfs -x devtmpfs | awk 'NR>1 {print $2, $1, $3, $4, $5, $6, $7}')

JOURNAL_ERRORS_JSON="$(collect_journal_errors_json)"
TOP_PROCESSES_JSON="$(collect_top_processes_json)"
CONTAINERS_JSON="$(collect_containers_json)"
AGENT_UPDATE_JSON="$(collect_update_log_json)"
AGENT_CONFIG_JSON="$(collect_agent_config_json)"
LARGE_FILES_JSON="$(collect_large_files_json)"

DOCKER_AVAILABLE=false
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  DOCKER_AVAILABLE=true
fi

execute_remote_commands
maybe_priority_self_update

flush_queue || true
QUEUE_DEPTH_NOW="$(count_queue_files)"

PAYLOAD=$(cat <<EOF
{
  "agent_id": "$(json_escape "$AGENT_ID_VALUE")",
  "agent_version": "$(json_escape "$AGENT_VERSION_VALUE")",
  "display_name": "$(json_escape "$DISPLAY_NAME_VALUE")",
  "hostname": "$(json_escape "$HOSTNAME_VALUE")",
  "primary_ip": "$(json_escape "$PRIMARY_IP")",
  "all_ips": "$(json_escape "$ALL_IPS")",
  "kernel": "$(json_escape "$KERNEL")",
  "os": "$(json_escape "$OS_NAME")",
  "uptime_seconds": $UPTIME_SECONDS,
  "timestamp_utc": "$(json_escape "$TIMESTAMP_UTC")",
  "delivery_mode": "live",
  "is_delayed": false,
  "queued_at_utc": "",
  "queue_depth": $QUEUE_DEPTH_NOW,
  "cpu": {
    "usage_percent": $CPU_USAGE_PERCENT,
    "load_avg_1": $LOAD_AVG_1,
    "load_avg_5": $LOAD_AVG_5,
    "load_avg_15": $LOAD_AVG_15,
    "cores": $CPU_CORES
  },
  "memory": {
    "total_kb": $MEM_TOTAL_KB,
    "available_kb": $MEM_AVAILABLE_KB,
    "used_kb": $MEM_USED_KB,
    "used_percent": $MEM_USED_PERCENT
  },
  "swap": {
    "total_kb": $SWAP_TOTAL_KB,
    "free_kb": $SWAP_FREE_KB,
    "used_kb": $SWAP_USED_KB,
    "used_percent": $SWAP_USED_PERCENT
  },
  "network": {
    "default_interface": "$(json_escape "$DEFAULT_INTERFACE")",
    "default_gateway": "$(json_escape "$DEFAULT_GATEWAY")",
    "dns_servers": [${DNS_SERVERS_JSON}],
    "interfaces": [${NETWORK_INTERFACES_JSON}]
  },
  "filesystems": [${FILESYSTEMS_JSON}],
  "journal_errors": {
    "since_minutes": $JOURNAL_ERRORS_SINCE_MINUTES,
    "entries": [${JOURNAL_ERRORS_JSON}]
  },
  "top_processes": {
    "entries": [${TOP_PROCESSES_JSON}]
  },
  "containers": {
    "runtime": "docker",
    "available": $DOCKER_AVAILABLE,
    "entries": [${CONTAINERS_JSON}]
  },
  "agent_update": ${AGENT_UPDATE_JSON},
  "agent_config": ${AGENT_CONFIG_JSON},
  "large_files": ${LARGE_FILES_JSON}
}
EOF
)

if ! post_payload "$PAYLOAD" >/dev/null; then
  queued_at_utc="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  delayed_payload="${PAYLOAD/\"delivery_mode\": \"live\"/\"delivery_mode\": \"delayed\"}"
  delayed_payload="${delayed_payload/\"is_delayed\": false/\"is_delayed\": true}"
  delayed_payload="${delayed_payload/\"queued_at_utc\": \"\"/\"queued_at_utc\": \"$queued_at_utc\"}"
  queue_file="$AGENT_QUEUE_DIR/report-${TIMESTAMP_UTC//[:T-]/}-${RANDOM}.json"
  printf '%s\n' "$delayed_payload" > "$queue_file"
  queued_depth_now="$(count_queue_files)"
  delayed_payload="${delayed_payload/\"queue_depth\": $QUEUE_DEPTH_NOW/\"queue_depth\": $queued_depth_now}"
  printf '%s\n' "$delayed_payload" > "$queue_file"
  echo "Payload queued for retry: $queue_file" >&2
  exit 1
fi

