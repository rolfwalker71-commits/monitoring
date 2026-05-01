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

  if [[ -n "${RAW_BASE_URL:-}" ]]; then
    tmp_updater="$(mktemp)"
    if curl --silent --show-error --fail "$RAW_BASE_URL/client/linux/self_update.sh" -o "$tmp_updater" 2>/dev/null; then
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

  curl "${curl_args[@]}" "${SERVER_URL%/}/api/v1/agent-command-result" >/dev/null || true
}

execute_remote_commands() {
  local response id status message

  curl_args=(
    --silent
    --show-error
    --fail
  )
  if [[ -n "${API_KEY:-}" ]]; then
    curl_args+=( -H "X-Api-Key: ${API_KEY}" )
  fi

  response="$(curl "${curl_args[@]}" "${SERVER_URL%/}/api/v1/agent-commands?hostname=$(printf '%s' "$HOSTNAME_VALUE" | sed 's/ /%20/g')&agent_id=$(printf '%s' "$AGENT_ID_VALUE" | sed 's/ /%20/g')&limit=10" 2>/dev/null || true)"
  [[ -n "$response" ]] || return

  while IFS= read -r command_line; do
    [[ -n "$command_line" ]] || continue
    id="$(printf '%s' "$command_line" | sed -n 's/.*"id"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p')"
    [[ -n "$id" ]] || continue

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

    post_command_result "$id" "$status" "$message"
  done < <(printf '%s' "$response" | grep -o '{[^}]*"command_type"[[:space:]]*:[[:space:]]*"update-now"[^}]*}')
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

DEFAULT_INTERFACE="$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')"

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
  "agent_update": ${AGENT_UPDATE_JSON}
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

