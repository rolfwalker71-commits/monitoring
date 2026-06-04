#!/usr/bin/env bash
set -euo pipefail

CONFIG_FILE="${CONFIG_FILE:-/etc/monitoring-agent/agent.conf}"
AGENT_VERSION_FILE="${AGENT_VERSION_FILE:-/opt/monitoring-agent/AGENT_VERSION}"
AGENT_QUEUE_DIR="${AGENT_QUEUE_DIR:-/var/lib/monitoring-agent/queue}"
AGENT_QUEUE_QUARANTINE_DIR="${AGENT_QUEUE_QUARANTINE_DIR:-/var/lib/monitoring-agent/queue-quarantine}"
PAYLOAD_ARCHIVE_DIR="${PAYLOAD_ARCHIVE_DIR:-/var/lib/monitoring-agent/payload-history}"
PAYLOAD_ARCHIVE_KEEP="${PAYLOAD_ARCHIVE_KEEP:-4}"
COLLECT_LOCK_FILE="${COLLECT_LOCK_FILE:-/var/lib/monitoring-agent/collect.lock}"
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
SAP_B1_CATALINA_OUT_PATH="${SAP_B1_CATALINA_OUT_PATH:-/usr/sap/SAPBusinessOne/Common/tomcat/logs/catalina.out}"
SAP_B1_BUSINESSONE_LOG_DIR="${SAP_B1_BUSINESSONE_LOG_DIR:-/usr/sap/SAPBusinessOne/home/b1service0/SAP/SAP Business One/Log/BusinessOne}"
SAP_B1_SETUP_PATH="${SAP_B1_SETUP_PATH:-/usr/sap/SAPBusinessOne/setup}"
SAP_B1_SIZE_TIMEOUT_SEC="${SAP_B1_SIZE_TIMEOUT_SEC:-20}"
SAP_B1_VERSION_TIMEOUT_SEC="${SAP_B1_VERSION_TIMEOUT_SEC:-15}"
HANA_VERSION_TIMEOUT_SEC="${HANA_VERSION_TIMEOUT_SEC:-10}"
HANA_SID="${HANA_SID:-}"
HANA_ADDONS_ENABLED="${HANA_ADDONS_ENABLED:-1}"
HANA_ADDONS_USER="${HANA_ADDONS_USER:-HARVEST}"
HANA_ADDONS_PASSWORD="${HANA_ADDONS_PASSWORD:-0djKUt&xbLK0AYr}"
HANA_ADDONS_QUERY_TIMEOUT_SEC="${HANA_ADDONS_QUERY_TIMEOUT_SEC:-15}"
HANA_ADDONS_HOST="${HANA_ADDONS_HOST:-127.0.0.1}"
HANA_ADDONS_PORT="${HANA_ADDONS_PORT:-30015}"
DIR_SCAN_PATHS="${DIR_SCAN_PATHS:-}"
DIR_SCAN_MAX_ITEMS="${DIR_SCAN_MAX_ITEMS:-50}"
DIR_SCAN_DEEP_PATHS="${DIR_SCAN_DEEP_PATHS:-}"
DIR_SCAN_DEEP_MAX_ITEMS="${DIR_SCAN_DEEP_MAX_ITEMS:-5}"
DIR_SCAN_DEEP_TIMEOUT_SEC="${DIR_SCAN_DEEP_TIMEOUT_SEC:-15}"
CURL_CONNECT_TIMEOUT_SEC="${CURL_CONNECT_TIMEOUT_SEC:-10}"
CURL_MAX_TIME_SEC="${CURL_MAX_TIME_SEC:-45}"
SEND_JITTER_MAX_SEC="${SEND_JITTER_MAX_SEC:-300}"

DISABLE_JITTER=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-jitter)
      DISABLE_JITTER=true
      shift
      ;;
    --jitter-max-sec)
      if [[ $# -lt 2 ]]; then
        echo "Missing value for --jitter-max-sec" >&2
        exit 2
      fi
      SEND_JITTER_MAX_SEC="$2"
      shift 2
      ;;
    --help|-h)
      cat <<'EOF'
Usage: collect_and_send.sh [--no-jitter] [--jitter-max-sec <seconds>]

Options:
  --no-jitter              Skip startup jitter sleep (useful for manual tests)
  --jitter-max-sec <sec>   Override maximum jitter delay for this run
EOF
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      echo "Use --help for usage." >&2
      exit 2
      ;;
  esac
done

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

if [[ "$DISABLE_JITTER" != true ]] && [[ "$SEND_JITTER_MAX_SEC" =~ ^[0-9]+$ ]] && [[ "$SEND_JITTER_MAX_SEC" -gt 0 ]]; then
  jitter_identity="${AGENT_ID:-$(hostname -f 2>/dev/null || hostname)}"
  jitter_sec="$(printf '%s' "$jitter_identity" | cksum | awk -v max="$SEND_JITTER_MAX_SEC" '{print $1 % (max + 1)}')"
  if [[ "$jitter_sec" =~ ^[0-9]+$ ]] && [[ "$jitter_sec" -gt 0 ]]; then
    sleep "$jitter_sec"
  fi
fi

TLS_INSECURE="${TLS_INSECURE:-0}"

mkdir -p "$AGENT_QUEUE_DIR"
mkdir -p "$AGENT_QUEUE_QUARANTINE_DIR"
mkdir -p "$PAYLOAD_ARCHIVE_DIR" 2>/dev/null || true

if command -v flock >/dev/null 2>&1; then
  exec 9>"$COLLECT_LOCK_FILE"
  if ! flock -n 9; then
    echo "Another collect_and_send run is still active; skipping this cycle." >&2
    exit 0
  fi
fi

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
  local value="${1-}"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  printf '%s' "$value"
}

json_number_or_null() {
  local value="$1"
  if [[ "$value" =~ ^[0-9]+$ ]]; then
    printf '%s' "$value"
  else
    printf 'null'
  fi
}

backup_payload_snapshot() {
  local payload_data="$1"
  local keep_count file_path

  keep_count="$PAYLOAD_ARCHIVE_KEEP"
  [[ "$keep_count" =~ ^[0-9]+$ ]] || keep_count=4
  (( keep_count >= 0 )) || keep_count=4

  mkdir -p "$PAYLOAD_ARCHIVE_DIR" 2>/dev/null || return 0

  file_path="$PAYLOAD_ARCHIVE_DIR/payload-$(date -u +"%Y%m%dT%H%M%SZ")-${RANDOM}.json"
  if ! printf '%s\n' "$payload_data" > "$file_path"; then
    return 0
  fi

  mapfile -t __payload_files < <(find "$PAYLOAD_ARCHIVE_DIR" -maxdepth 1 -type f -name 'payload-*.json' -printf '%T@ %p\n' 2>/dev/null | sort -nr | awk '{ $1=""; sub(/^ /,""); print }')
  if (( ${#__payload_files[@]} > keep_count )); then
    local i
    for (( i=keep_count; i<${#__payload_files[@]}; i++ )); do
      rm -f -- "${__payload_files[$i]}"
    done
  fi
}

collect_sap_license_json() {
  local license_path=""
  local available="false"
  local hardware_key=""
  local instno=""
  local expiration=""
  local system_nr=""
  local system_type=""
  local customer_name=""
  local customer_no=""
  local file_mtime_utc=""
  local focus_license_types_json=""
  
  # Try multiple possible locations (with fallback paths)
  local license_paths=(
    "/usr/sap/SAPBusinessOne/B1_SHF/Lizenzen/B01.txt"
    "/usr/sap/SAPBusinessOne/B1_SHF/Lizenz/B01.txt"
  )
  
  for path in "${license_paths[@]}"; do
    if [[ -f "$path" ]]; then
      license_path="$path"
      break
    fi
  done
  
  if [[ -z "$license_path" ]]; then
    printf '{"available":false,"hardware_key":"","instno":"","expiration":"","system_nr":"","system_type":"","customer_name":"","customer_no":"","file_mtime_utc":"","focus_license_types":[]}'
    return
  fi
  
  # Get file modification time in UTC
  if command -v stat >/dev/null 2>&1; then
    file_mtime_utc="$(stat -c %Y "$license_path" 2>/dev/null | xargs -I {} date -u -d "@{}" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "")"
  fi
  
  local content=""
  if [[ -r "$license_path" ]]; then
    content="$(cat "$license_path" 2>/dev/null || echo "")"
  fi
  
  if [[ -z "$content" ]]; then
    printf '{"available":false,"hardware_key":"","instno":"","expiration":"","system_nr":"","system_type":"","customer_name":"","customer_no":"","file_mtime_utc":"%s","focus_license_types":[]}' "$(json_escape "$file_mtime_utc")"
    return
  fi
  
  # Try to extract from block format first, otherwise use whole content
  local block_content="$content"
  if [[ "$content" =~ -----[[:space:]]*Begin[[:space:]]+SAP[[:space:]]+License[[:space:]]*-----(.*)-----[[:space:]]*End[[:space:]]+SAP[[:space:]]+License[[:space:]]*----- ]]; then
    block_content="${BASH_REMATCH[1]}"
  fi
  
  # Extract license fields from content (works for both block and plain key=value format)
  [[ "$block_content" =~ HARDWARE-KEY[[:space:]]*=[[:space:]]*([^$'\n'$'\r']+) ]] && hardware_key="$(printf '%s' "${BASH_REMATCH[1]}" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  [[ "$block_content" =~ INSTNO[[:space:]]*=[[:space:]]*([^$'\n'$'\r']+) ]] && instno="$(printf '%s' "${BASH_REMATCH[1]}" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  [[ "$block_content" =~ EXPIRATION[[:space:]]*=[[:space:]]*([^$'\n'$'\r']+) ]] && expiration="$(printf '%s' "${BASH_REMATCH[1]}" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  [[ "$block_content" =~ SYSTEM-NR[[:space:]]*=[[:space:]]*([^$'\n'$'\r']+) ]] && system_nr="$(printf '%s' "${BASH_REMATCH[1]}" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  [[ "$block_content" =~ SYSTEM-TYPE[[:space:]]*=[[:space:]]*([^;$'\n'$'\r']+) ]] && system_type="$(printf '%s' "${BASH_REMATCH[1]}" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  [[ "$block_content" =~ CUSTOMER-NAME[[:space:]]*=[[:space:]]*([^$'\n'$'\r']+) ]] && customer_name="$(printf '%s' "${BASH_REMATCH[1]}" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"
  [[ "$block_content" =~ CUSTOMER-NO[[:space:]]*=[[:space:]]*([^$'\n'$'\r']+) ]] && customer_no="$(printf '%s' "${BASH_REMATCH[1]}" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')"

  # Extract and aggregate ALL license types
  while IFS=$'\t' read -r license_type license_count; do
    [[ -n "$license_type" ]] || continue
    [[ "$license_count" =~ ^[0-9]+$ ]] || license_count=0
    entry=$(cat <<EOF
{"license_type":"$(json_escape "$license_type")","count":$license_count}
EOF
)
    focus_license_types_json="$(append_json_entry "$focus_license_types_json" "$entry")"
  done < <(
    printf '%s\n' "$content" | awk '
      function trim(s) {
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", s)
        return s
      }
      {
        line = $0
        eq_pos = index(line, "=")
        if (!eq_pos) {
          next
        }
        key = trim(substr(line, 1, eq_pos - 1))
        val = trim(substr(line, eq_pos + 1))
        key_upper = toupper(key)

        if (key_upper == "SWPRODUCTNAME") {
          current_name = val
          next
        }
        if (key_upper == "SWPRODUCTLIMIT") {
          if (current_name != "") {
            limit_val = (val ~ /^[0-9]+$/) ? val + 0 : 0
            counts[current_name] += limit_val
          }
          current_name = ""
        }
      }
      END {
        for (name in counts) {
          printf "%s\t%d\n", name, counts[name]
        }
      }
    ' | sort
  )
  
  if [[ -n "$hardware_key" ]] || [[ -n "$instno" ]]; then
    available="true"
  fi
  
  printf '{"available":%s,"hardware_key":"%s","instno":"%s","expiration":"%s","system_nr":"%s","system_type":"%s","customer_name":"%s","customer_no":"%s","file_mtime_utc":"%s","focus_license_types":[%s]}' \
    "$available" \
    "$(json_escape "$hardware_key")" \
    "$(json_escape "$instno")" \
    "$(json_escape "$expiration")" \
    "$(json_escape "$system_nr")" \
    "$(json_escape "$system_type")" \
    "$(json_escape "$customer_name")" \
    "$(json_escape "$customer_no")" \
    "$(json_escape "$file_mtime_utc")" \
    "${focus_license_types_json}"
}

collect_sap_business_one_json() {
  local sap_services_json
  sap_services_json="$(collect_sap_b1_installed_services_json)"
  local catalina_path="$SAP_B1_CATALINA_OUT_PATH"
  local businessone_dir="$SAP_B1_BUSINESSONE_LOG_DIR"
  local setup_path="$SAP_B1_SETUP_PATH"
  local catalina_exists=false
  local catalina_size=""
  local catalina_error=""
  local businessone_exists=false
  local businessone_size=""
  local businessone_error=""
  local timeout_sec="$SAP_B1_SIZE_TIMEOUT_SEC"
  local version_timeout_sec="$SAP_B1_VERSION_TIMEOUT_SEC"
  local setup_exists=false
  local version_raw=""
  local version_text=""
  local version_error=""

  if ! [[ "$timeout_sec" =~ ^[0-9]+$ ]] || [[ "$timeout_sec" -lt 1 ]]; then
    timeout_sec=20
  fi
  if ! [[ "$version_timeout_sec" =~ ^[0-9]+$ ]] || [[ "$version_timeout_sec" -lt 1 ]]; then
    version_timeout_sec=15
  fi

  if [[ -f "$catalina_path" ]]; then
    catalina_exists=true
    catalina_size="$(stat -c%s "$catalina_path" 2>/dev/null || true)"
    if ! [[ "$catalina_size" =~ ^[0-9]+$ ]]; then
      catalina_size=""
      catalina_error="size read failed"
    fi
  fi

  if [[ -d "$businessone_dir" ]]; then
    businessone_exists=true
    if command -v timeout >/dev/null 2>&1; then
      businessone_size="$(timeout "${timeout_sec}s" du -sb "$businessone_dir" 2>/dev/null | awk '{print $1}' || true)"
    else
      businessone_size="$(du -sb "$businessone_dir" 2>/dev/null | awk '{print $1}' || true)"
    fi
    if ! [[ "$businessone_size" =~ ^[0-9]+$ ]]; then
      businessone_size=""
      businessone_error="size read failed or timeout"
    fi
  fi

  if [[ -x "$setup_path" ]]; then
    setup_exists=true
    if command -v timeout >/dev/null 2>&1; then
      version_raw="$(timeout "${version_timeout_sec}s" "$setup_path" --version 2>&1 || true)"
    else
      version_raw="$("$setup_path" --version 2>&1 || true)"
    fi
    version_raw="$(printf '%s' "$version_raw" | sed -e 's/[[:space:]]*$//')"
    version_text="$(printf '%s\n' "$version_raw" | awk -F'Version: ' '/Version: / {print $2; exit}')"
    if [[ -z "$version_raw" ]]; then
      version_error="setup --version returned empty output"
    elif [[ -z "$version_text" ]]; then
      version_error="version line not found"
    fi
  else
    version_error="setup not found or not executable"
  fi

  printf '{"catalina_out":{"path":"%s","exists":%s,"size_bytes":%s,"error":"%s"},"businessone_log_dir":{"path":"%s","exists":%s,"size_bytes":%s,"error":"%s"},"server_components_version":{"command":"%s --version","setup_path":"%s","available":%s,"raw_output":"%s","version":"%s","error":"%s"},"installed_services":%s}' \
    "$(json_escape "$catalina_path")" \
    "$catalina_exists" \
    "$(json_number_or_null "$catalina_size")" \
    "$(json_escape "$catalina_error")" \
    "$(json_escape "$businessone_dir")" \
    "$businessone_exists" \
    "$(json_number_or_null "$businessone_size")" \
    "$(json_escape "$businessone_error")" \
    "$(json_escape "$setup_path")" \
    "$(json_escape "$setup_path")" \
    "$setup_exists" \
    "$(json_escape "$version_raw")" \
    "$(json_escape "$version_text")" \
    "$(json_escape "$version_error")" \
    "$sap_services_json"
}

collect_sap_b1_installed_services_json() {
  local timeout_sec="${SAP_B1_SERVICES_TIMEOUT_SEC:-6}"
  local unit_names=""
  local service_entries=""

  if ! [[ "$timeout_sec" =~ ^[0-9]+$ ]] || [[ "$timeout_sec" -lt 1 ]]; then
    timeout_sec=6
  fi

  _sapb1_safe_timeout() {
    if command -v timeout >/dev/null 2>&1; then
      timeout "${timeout_sec}s" "$@" 2>/dev/null || true
    else
      "$@" 2>/dev/null || true
    fi
  }

  _sapb1_guess_ports_from_execstart() {
    local exec_start_raw="${1-}"
    local service_name_raw="${2-}"
    local guessed_ports=""

    guessed_ports="$(printf '%s\n' "$exec_start_raw" \
      | grep -Eo '(^|[[:space:]])(--server\.port=|--port=|-Dserver\.port=|-Dhttp\.port=|-Dhttps\.port=|port=)[0-9]{2,5}' \
      | grep -Eo '[0-9]{2,5}' \
      | awk '$1>=1024 && $1<=65535' \
      | sort -n -u \
      | paste -sd, - || true)"

    if [[ -z "$guessed_ports" ]]; then
      case "$service_name_raw" in
        *analytics*) guessed_ports="40003" ;;
        *authentication*) guessed_ports="8443" ;;
        *jobservice*) guessed_ports="40004" ;;
        *license*) guessed_ports="40002" ;;
        *servicelayercontroller*) guessed_ports="40005" ;;
        *ms365integration*) guessed_ports="40006" ;;
        *sapb1servertools.service) guessed_ports="40000" ;;
      esac
    fi

    printf '%s' "$guessed_ports"
  }

  unit_names="$(_sapb1_safe_timeout systemctl list-unit-files --type=service "sapb1servertools*" --no-legend \
    | awk '{print $1}' \
    | grep -E '^sapb1servertools.*\.service$' \
    | sort -u || true)"

  if [[ -z "$unit_names" ]]; then
    printf '{"available":false,"reason":"Keine SAPServices gefunden","services":[]}'
    return 0
  fi

  while IFS= read -r service_name; do
    [[ -n "$service_name" ]] || continue

    local description active_state sub_state main_pid exec_start
    local status_field live_field ports_field prot_field ss_rows

    description="$(_sapb1_safe_timeout systemctl show -p Description --value "$service_name" | head -n1 || true)"
    active_state="$(_sapb1_safe_timeout systemctl show -p ActiveState --value "$service_name" | head -n1 || true)"
    sub_state="$(_sapb1_safe_timeout systemctl show -p SubState --value "$service_name" | head -n1 || true)"
    main_pid="$(_sapb1_safe_timeout systemctl show -p MainPID --value "$service_name" | head -n1 || true)"
    exec_start="$(_sapb1_safe_timeout systemctl show -p ExecStart --value "$service_name" | head -n1 || true)"

    [[ -n "$description" ]] || description="-"
    [[ -n "$active_state" ]] || active_state="unknown"
    [[ -n "$sub_state" ]] || sub_state="unknown"
    [[ "$main_pid" =~ ^[0-9]+$ ]] || main_pid=0

    status_field="${active_state}/${sub_state}"
    ports_field=""
    prot_field=""
    ss_rows=""

    if [[ "$main_pid" -gt 0 ]]; then
      ss_rows="$(_sapb1_safe_timeout ss -H -ltnup | grep -E "pid=${main_pid}[,)]" || true)"
    fi

    if [[ -n "$ss_rows" ]]; then
      ports_field="$(printf '%s\n' "$ss_rows" \
        | awk '{print $5}' \
        | awk -F':' '{print $NF}' \
        | sed 's/[^0-9]//g' \
        | awk '$1>=1 && $1<=65535' \
        | sort -n -u \
        | paste -sd, - || true)"

      prot_field="$(printf '%s\n' "$ss_rows" \
        | awk '{print $1}' \
        | awk 'NF' \
        | sort -u \
        | paste -sd, - || true)"
    fi

    if [[ -z "$ports_field" ]]; then
      ports_field="$(_sapb1_guess_ports_from_execstart "$exec_start" "$service_name")"
      if [[ -n "$ports_field" ]] && [[ -z "$prot_field" ]]; then
        prot_field="tcp"
      fi
    fi

    if [[ "$active_state" == "active" ]] && [[ "$sub_state" == "running" ]]; then
      live_field="Live"
    elif [[ "$active_state" == "active" ]]; then
      live_field="ActiveNotRunning"
    else
      live_field="NotLive"
    fi

    [[ -n "$ports_field" ]] || ports_field="-"
    [[ -n "$prot_field" ]] || prot_field="-"

    local entry_json
    entry_json="$(printf '{"name":"%s","status":"%s","prot":"%s","live":"%s","ports":"%s","description":"%s"}' \
      "$(json_escape "$service_name")" \
      "$(json_escape "$status_field")" \
      "$(json_escape "$prot_field")" \
      "$(json_escape "$live_field")" \
      "$(json_escape "$ports_field")" \
      "$(json_escape "$description")")"

    service_entries="$(append_json_entry "$service_entries" "$entry_json")"
  done <<< "$unit_names"

  printf '{"available":true,"reason":"ok","services":[%s]}' "$service_entries"
  return 0
}

collect_hana_version_json() {
  local sid="${HANA_SID:-}"
  local sid_user=""
  local hdb_path=""
  local hdbnsutil_path=""
  local version_raw=""
  local version_text=""
  local branch_text=""
  local version_error=""

  # Auto-detect SID from /hana/shared/<SID> if not set in config
  if [[ -z "$sid" ]] && [[ -d /hana/shared ]]; then
    local detected_sid
    detected_sid="$(find /hana/shared -mindepth 1 -maxdepth 1 -type d 2>/dev/null \
      | awk -F/ '{print $NF}' \
      | grep -E '^[A-Z][A-Z0-9]{2}$' \
      | head -1 || true)"
    if [[ -n "$detected_sid" ]]; then
      sid="$detected_sid"
      # Write detected SID back to agent.conf for future runs
      if [[ -f "${CONFIG_FILE:-/etc/monitoring-agent/agent.conf}" ]] \
         && ! grep -q '^HANA_SID=' "${CONFIG_FILE:-/etc/monitoring-agent/agent.conf}" 2>/dev/null; then
        printf '\nHANA_SID="%s"\n' "$sid" >> "${CONFIG_FILE:-/etc/monitoring-agent/agent.conf}" 2>/dev/null || true
      fi
    fi
  fi

  if [[ -n "$sid" ]]; then
    sid_user="$(printf '%s' "$sid" | tr '[:upper:]' '[:lower:]')adm"
  fi

  # Find HDB under /usr/sap (prefer SID-specific path)
  # Use -not -type d to also match symlinks (HDB is often a symlink in HANA)
  if [[ -n "$sid" ]]; then
    local sid_search
    sid_search="$(find "/usr/sap/${sid}" -maxdepth 5 -name "HDB" -not -type d 2>/dev/null | head -1 || true)"
    if [[ -n "$sid_search" ]] && [[ -x "$sid_search" ]]; then
      hdb_path="$sid_search"
    fi
  fi
  if [[ -z "$hdb_path" ]]; then
    local generic_search
    generic_search="$(find /usr/sap -maxdepth 6 -name "HDB" -not -type d 2>/dev/null | head -1 || true)"
    if [[ -n "$generic_search" ]] && [[ -x "$generic_search" ]]; then
      hdb_path="$generic_search"
    fi
  fi

  # Fallback: derive HDB path from hdbnsutil directory
  if [[ -z "$hdb_path" ]]; then
    if [[ -n "$sid" ]]; then
      hdbnsutil_path="$(find "/usr/sap/${sid}" -maxdepth 5 -name "hdbnsutil" -not -type d 2>/dev/null | head -1 || true)"
    fi
    if [[ -z "$hdbnsutil_path" ]]; then
      hdbnsutil_path="$(find /usr/sap -maxdepth 6 -name "hdbnsutil" -not -type d 2>/dev/null | head -1 || true)"
    fi
    if [[ -n "$hdbnsutil_path" ]] && [[ -x "$hdbnsutil_path" ]]; then
      local sibling_hdb
      sibling_hdb="$(dirname "$hdbnsutil_path")/HDB"
      if [[ -x "$sibling_hdb" ]]; then
        hdb_path="$sibling_hdb"
      fi
    fi
  fi
  if [[ -z "$hdb_path" ]]; then
    hdb_path="$(command -v HDB 2>/dev/null || true)"
  fi

  # Last resort: resolve HDB from <sid>adm login shell PATH.
  if [[ -z "$hdb_path" ]] && [[ -n "$sid_user" ]] && id "$sid_user" >/dev/null 2>&1; then
    hdb_path="$(su - "$sid_user" -c 'command -v HDB' 2>/dev/null | head -1 || true)"
  fi

  if [[ -n "$hdb_path" ]] || ([[ -n "$sid_user" ]] && id "$sid_user" >/dev/null 2>&1); then
    local timeout_sec="$HANA_VERSION_TIMEOUT_SEC"
    if ! [[ "$timeout_sec" =~ ^[0-9]+$ ]] || [[ "$timeout_sec" -lt 1 ]]; then
      timeout_sec=10
    fi

    if [[ -n "$sid_user" ]] && id "$sid_user" >/dev/null 2>&1; then
      # Run as <sid>adm
      if command -v timeout >/dev/null 2>&1; then
        if [[ -n "$hdb_path" ]]; then
          version_raw="$(timeout "${timeout_sec}s" su - "$sid_user" -c "\"${hdb_path}\" version" 2>&1 | head -20 || true)"
        else
          version_raw="$(timeout "${timeout_sec}s" su - "$sid_user" -c "HDB version" 2>&1 | head -20 || true)"
        fi
      else
        if [[ -n "$hdb_path" ]]; then
          version_raw="$(su - "$sid_user" -c "\"${hdb_path}\" version" 2>&1 | head -20 || true)"
        else
          version_raw="$(su - "$sid_user" -c "HDB version" 2>&1 | head -20 || true)"
        fi
      fi
    else
      # Fallback: run directly (may fail if permissions are restricted)
      if command -v timeout >/dev/null 2>&1; then
        version_raw="$(timeout "${timeout_sec}s" "$hdb_path" version 2>&1 | head -20 || true)"
      else
        version_raw="$("$hdb_path" version 2>&1 | head -20 || true)"
      fi
      if [[ -n "$sid_user" ]] && ! id "$sid_user" >/dev/null 2>&1; then
        version_error="User ${sid_user} nicht gefunden"
      fi
    fi

    version_raw="$(printf '%s' "$version_raw" | sed -e 's/[[:space:]]*$//')"
    version_text="$(printf '%s\n' "$version_raw" | awk 'BEGIN { IGNORECASE=1 } /version:/ { gsub(/^[[:space:]]*[Vv]ersion:[[:space:]]+/, ""); print; exit }')"
    branch_text="$(printf '%s\n' "$version_raw" | awk 'BEGIN { IGNORECASE=1 } /branch:/ { gsub(/^[[:space:]]*[Bb]ranch:[[:space:]]+/, ""); print; exit }')"
    if [[ -z "$version_text" ]] && [[ -n "$version_raw" ]] && [[ -z "$version_error" ]]; then
      version_error="version nicht parsebar"
    elif [[ -z "$version_raw" ]] && [[ -z "$version_error" ]]; then
      version_error="HDB lieferte keine Ausgabe"
    fi
  else
    version_error="HDB nicht gefunden"
  fi

  printf '{"available":%s,"sid":"%s","sid_user":"%s","path":"%s","version":"%s","branch":"%s","raw_output":"%s","error":"%s"}' \
    "$([ -n "$hdb_path" ] && echo true || ([[ -n "$sid_user" ]] && id "$sid_user" >/dev/null 2>&1 && echo true || echo false))" \
    "$(json_escape "$sid")" \
    "$(json_escape "$sid_user")" \
    "$(json_escape "$hdb_path")" \
    "$(json_escape "$version_text")" \
    "$(json_escape "$branch_text")" \
    "$(json_escape "$version_raw")" \
    "$(json_escape "$version_error")"
}

collect_hana_addons_json() {
  # Collects HANA AddOns data (Lightweight + Legacy) via hdbsql queries.
  # Read-only operation: SELECT only, no modifications to hdbuserstore or HANA state.
  # Graceful failure: returns JSON with reason even if user/hdbsql not found or timeout.
  local sid="${HANA_SID:-}"
  local sid_user=""
  local addons_user="${HANA_ADDONS_USER:-HARVEST}"
  local addons_password="${HANA_ADDONS_PASSWORD:-0djKUt&xbLK0AYr}"
  local query_timeout_sec="${HANA_ADDONS_QUERY_TIMEOUT_SEC:-15}"
  local addons_host="${HANA_ADDONS_HOST:-127.0.0.1}"
  local addons_port="${HANA_ADDONS_PORT:-30015}"
  local detected_instance_no=""
  local detected_sql_port=""
  local hdbsql_target=""
  local lw_mode="explicit_target"
  local lg_mode="explicit_target"
  local last_hdbsql_mode="explicit_target"
  local available=false
  local reason="unknown"
  local error_msg=""
  local lightweight_entries=""
  local legacy_entries=""

  parse_hdbsql_row_fallback() {
    local line="${1-}"
    local parsed_name=""
    local parsed_version=""

    line="$(printf '%s' "$line" | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    [[ -z "$line" ]] && return 1

    # Skip headers/separators/diagnostic lines.
    if [[ "$line" =~ [Rr]ows[[:space:]]+selected ]] || [[ "$line" =~ [Oo]verall[[:space:]]+time ]] || [[ "$line" =~ [Ss]erver[[:space:]]+time ]] || [[ "$line" =~ ^[-=]+$ ]] || [[ "$line" =~ ^\* ]]; then
      return 1
    fi

    # Formats seen in the field:
    #   NAME|Version
    #   "NAME","Version"
    #   NAME,Version
    #   NAME;Version
    #   NAME    Version   (multiple spaces)
    if [[ "$line" == *"|"* ]]; then
      IFS='|' read -r parsed_name parsed_version _ <<< "$line"
    elif [[ "$line" =~ ^\"(.*)\",\"(.*)\"$ ]]; then
      parsed_name="${BASH_REMATCH[1]}"
      parsed_version="${BASH_REMATCH[2]}"
    elif [[ "$line" =~ ^([^,]+),(.+)$ ]]; then
      parsed_name="${BASH_REMATCH[1]}"
      parsed_version="${BASH_REMATCH[2]}"
    elif [[ "$line" == *";"* ]]; then
      IFS=';' read -r parsed_name parsed_version _ <<< "$line"
    elif [[ "$line" =~ ^(.+)[[:space:]][[:space:]]+(.+)$ ]]; then
      parsed_name="${BASH_REMATCH[1]}"
      parsed_version="${BASH_REMATCH[2]}"
    else
      return 1
    fi

    parsed_name="$(printf '%s' "$parsed_name" | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//; s/^"//; s/"$//')"
    parsed_version="$(printf '%s' "$parsed_version" | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//; s/^"//; s/"$//')"

    [[ -z "$parsed_name" ]] && return 1
    if [[ "$parsed_name" == "NAME" ]] || [[ "$parsed_name" == "AName" ]] || [[ "$parsed_version" == "Version" ]] || [[ "$parsed_version" == "AddOnVer" ]]; then
      return 1
    fi

    printf '%s\t%s' "$parsed_name" "$parsed_version"
    return 0
  }

  clean_hdbsql_output() {
    local raw_text="${1-}"
    printf '%s' "$raw_text" \
      | tr -d '\r' \
      | sed -E '
          s/[[:space:]]*[0-9]+[[:space:]]+rows selected.*$//I;
          s/[[:space:]]*[0-9]+[[:space:]]+row selected.*$//I;
          s/[[:space:]]*(overall|server)[[:space:]]+time.*$//I;
        '
  }

  append_hana_addon_json_entry() {
    local target_entries="${1-}"
    local entry_json="${2-}"
    printf '%s' "${target_entries:+$target_entries,}$entry_json"
  }

  summarize_hdbsql_output_for_diagnostics() {
    local raw_text="${1-}"
    local lines=""
    lines="$(printf '%s\n' "$raw_text" \
      | tr -d '\r' \
      | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//' \
      | grep -vE '^(|[-=]+)$' \
      | grep -viE 'rows selected|overall time|server time|^name[[:space:]]+version$|^aname[[:space:]]+addonver$' \
      | head -n 3 \
      | tr '\n' '|' \
      | sed -e 's/|$//' || true)"

    if [[ -z "$lines" ]]; then
      printf 'no-sample-lines'
      return
    fi
    printf '%s' "$lines"
  }

  detect_hdbsql_error_line() {
    local raw_text="${1-}"
    local first_error=""

    first_error="$(printf '%s\n' "$raw_text" | awk '
      BEGIN { IGNORECASE=1 }
      /authentication failed|sqlstate|insufficient privilege|invalid user|user is locked|connection failed|cannot connect|error:/ {
        line=$0
        sub(/^[[:space:]]+/, "", line)
        sub(/[[:space:]]+$/, "", line)
        print line
        exit
      }
    ')"

    if [[ -n "$first_error" ]]; then
      printf '%s' "$first_error"
      return 0
    fi
    return 1
  }

  is_hdbsql_connection_error() {
    local raw_text="${1-}"
    if printf '%s\n' "$raw_text" | grep -qiE 'connection failed|cannot connect|rc=111|rc=99'; then
      return 0
    fi
    return 1
  }

  run_hdbsql_query() {
    local sql_text="${1-}"
    local sql_escaped=""
    local implicit_output=""
    local explicit_output=""
    local alt_port=""
    local alt_host=""
    local alt_output=""
    local probe_hosts_csv=""
    local probe_host_list=""
    local tenant_scan_mode="${HANA_TENANT_SCAN_MODE:-0}"
    local tenant_db_name="${HANA_TENANT_DB:-}"

    sql_escaped="$(printf '%q' "$sql_text")"

    # Tenant mode: use DB-name based access (-d) only.
    if [[ "$tenant_scan_mode" == "1" ]]; then
      if [[ -z "$tenant_db_name" ]]; then
        tenant_db_name="$sid"
      fi

      if [[ -n "$tenant_db_name" ]]; then
        if command -v timeout >/dev/null 2>&1; then
          implicit_output="$(timeout "${query_timeout_sec}s" su - "$sid_user" -c "hdbsql -d \"$tenant_db_name\" -u \"$addons_user\" -p \"$addons_password\" $sql_escaped 2>&1" || true)"
        else
          implicit_output="$(su - "$sid_user" -c "hdbsql -d \"$tenant_db_name\" -u \"$addons_user\" -p \"$addons_password\" $sql_escaped 2>&1" || true)"
        fi
        if [[ -n "$implicit_output" ]]; then
          if is_hdbsql_connection_error "$implicit_output"; then
            last_hdbsql_mode="tenant_db_implicit_failed"
          else
            last_hdbsql_mode="tenant_db_implicit"
          fi
        else
          last_hdbsql_mode="tenant_db_implicit_empty"
        fi
        printf '%s' "$implicit_output"
        return
      fi
    fi

    # 1) Primary mode (legacy behavior from early stable releases): implicit
    # connection as <sid>adm without explicit -n target.
    if [[ "$tenant_scan_mode" != "1" ]]; then
      if command -v timeout >/dev/null 2>&1; then
        implicit_output="$(timeout "${query_timeout_sec}s" su - "$sid_user" -c "hdbsql -u \"$addons_user\" -p \"$addons_password\" $sql_escaped 2>&1" || true)"
      else
        implicit_output="$(su - "$sid_user" -c "hdbsql -u \"$addons_user\" -p \"$addons_password\" $sql_escaped 2>&1" || true)"
      fi
      if [[ -n "$implicit_output" ]] && ! is_hdbsql_connection_error "$implicit_output"; then
        last_hdbsql_mode="implicit_primary"
        printf '%s' "$implicit_output"
        return
      fi
    fi

    # 2) Fallback mode: explicit configured target (with runtime diagnostics).
    last_hdbsql_mode="explicit_target"
    if command -v timeout >/dev/null 2>&1; then
      explicit_output="$(timeout "${query_timeout_sec}s" su - "$sid_user" -c "hdbsql -n \"$hdbsql_target\" -u \"$addons_user\" -p \"$addons_password\" $sql_escaped 2>&1" || true)"
    else
      explicit_output="$(su - "$sid_user" -c "hdbsql -n \"$hdbsql_target\" -u \"$addons_user\" -p \"$addons_password\" $sql_escaped 2>&1" || true)"
    fi

    # If explicit host:port fails, try runtime local 3xx15 probe.
    if is_hdbsql_connection_error "$explicit_output"; then
      probe_hosts_csv="$addons_host,127.0.0.1,localhost,$(hostname -f 2>/dev/null || true),$(hostname 2>/dev/null || true)"
      probe_host_list="$(printf '%s' "$probe_hosts_csv" | tr ',' '\n' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//' | awk 'NF>0' | awk '!seen[$0]++')"

      while IFS= read -r alt_port; do
        [[ -z "$alt_port" ]] && continue
        while IFS= read -r alt_host; do
          [[ -z "$alt_host" ]] && continue
          if command -v timeout >/dev/null 2>&1; then
            alt_output="$(timeout "${query_timeout_sec}s" su - "$sid_user" -c "hdbsql -n \"${alt_host}:${alt_port}\" -u \"$addons_user\" -p \"$addons_password\" $sql_escaped 2>&1" || true)"
          else
            alt_output="$(su - "$sid_user" -c "hdbsql -n \"${alt_host}:${alt_port}\" -u \"$addons_user\" -p \"$addons_password\" $sql_escaped 2>&1" || true)"
          fi
          if [[ -n "$alt_output" ]] && ! is_hdbsql_connection_error "$alt_output"; then
            addons_host="$alt_host"
            addons_port="$alt_port"
            hdbsql_target="${addons_host}:${addons_port}"
            last_hdbsql_mode="auto_probe_${alt_host}_${alt_port}"
            printf '%s' "$alt_output"
            return
          fi
        done <<< "$probe_host_list"
      done < <(ss -lntH 2>/dev/null | awk '{print $4}' | sed -E 's/.*:([0-9]+)$/\1/' | grep -E '^3[0-9]{2}15$' | sort -u || true)

      # Last fallback: probe common HANA SQL ports (3xx15) even if ss is unavailable.
      for alt_port in 30015 30115 30215 30315 30415 30515 30615 30715 30815 30915 31015 31115 31215 31315 31415 31515 31615 31715 31815 31915 32015 32115 32215 32315 32415 32515 32615 32715 32815 32915 33015 33115 33215 33315 33415 33515 33615 33715 33815 33915 34015 34115 34215 34315 34415 34515 34615 34715 34815 34915 35015 35115 35215 35315 35415 35515 35615 35715 35815 35915 36015 36115 36215 36315 36415 36515 36615 36715 36815 36915 37015 37115 37215 37315 37415 37515 37615 37715 37815 37915 38015 38115 38215 38315 38415 38515 38615 38715 38815 38915 39015 39115 39215 39315 39415 39515 39615 39715 39815 39915; do
        while IFS= read -r alt_host; do
          [[ -z "$alt_host" ]] && continue
          if command -v timeout >/dev/null 2>&1; then
            alt_output="$(timeout "${query_timeout_sec}s" su - "$sid_user" -c "hdbsql -n \"${alt_host}:${alt_port}\" -u \"$addons_user\" -p \"$addons_password\" $sql_escaped 2>&1" || true)"
          else
            alt_output="$(su - "$sid_user" -c "hdbsql -n \"${alt_host}:${alt_port}\" -u \"$addons_user\" -p \"$addons_password\" $sql_escaped 2>&1" || true)"
          fi
          if [[ -n "$alt_output" ]] && ! is_hdbsql_connection_error "$alt_output"; then
            addons_host="$alt_host"
            addons_port="$alt_port"
            hdbsql_target="${addons_host}:${addons_port}"
            last_hdbsql_mode="auto_probe_common_${alt_host}_${alt_port}"
            printf '%s' "$alt_output"
            return
          fi
        done <<< "$probe_host_list"
      done
    fi

    printf '%s' "$explicit_output"
  }

  summarize_hana_sql_listener_diagnostics() {
    local listeners_csv=""
    local target_open="no"

    if command -v ss >/dev/null 2>&1; then
      listeners_csv="$(ss -lntH 2>/dev/null | awk '{print $4}' | sed -E 's/.*:([0-9]+)$/\1/' | grep -E '^3[0-9]{2}15$' | sort -u | tr '\n' ',' | sed -e 's/,$//' || true)"
    fi

    if [[ -z "$listeners_csv" ]]; then
      listeners_csv="none"
    elif printf '%s\n' "$listeners_csv" | tr ',' '\n' | grep -qx "$addons_port"; then
      target_open="yes"
    fi

    printf 'listener_target=%s; listeners_3xx15=%s; sid=%s; target=%s' "$target_open" "$listeners_csv" "${sid:-}" "$hdbsql_target"
  }

  is_hdbsql_invalid_column_error() {
    local raw_text="${1-}"
    if printf '%s\n' "$raw_text" | grep -qiE 'invalid column name'; then
      return 0
    fi
    return 1
  }

  run_hdbsql_query_candidates() {
    local query_group="${1-}"
    local output=""
    local err_line=""
    local selected_mode=""
    local q=""
    local -a queries=()

    if [[ "$query_group" == "lightweight" ]]; then
      queries=(
        'SELECT "NAME", "Version" FROM "SLDDATA"."EXTENSIONS" INNER JOIN "SLDDATA"."EXTENSIONDEPLOYMENTS" ON "SLDDATA"."EXTENSIONDEPLOYMENTS"."EXTENSION_ID" = "SLDDATA"."EXTENSIONS"."ID";'
        'SELECT "NAME", "VERSION" FROM "SLDDATA"."EXTENSIONS" INNER JOIN "SLDDATA"."EXTENSIONDEPLOYMENTS" ON "SLDDATA"."EXTENSIONDEPLOYMENTS"."EXTENSION_ID" = "SLDDATA"."EXTENSIONS"."ID";'
        'SELECT NAME, VERSION FROM "SLDDATA"."EXTENSIONS" INNER JOIN "SLDDATA"."EXTENSIONDEPLOYMENTS" ON "SLDDATA"."EXTENSIONDEPLOYMENTS"."EXTENSION_ID" = "SLDDATA"."EXTENSIONS"."ID";'
      )
    else
      queries=(
        'SELECT "AName", "AddOnVer" FROM "SBOCOMMON"."SARI";'
        'SELECT "ANAME", "ADDONVER" FROM "SBOCOMMON"."SARI";'
        'SELECT ANAME, ADDONVER FROM "SBOCOMMON"."SARI";'
      )
    fi

    for q in "${queries[@]}"; do
      output="$(run_hdbsql_query "$q")"
      selected_mode="$last_hdbsql_mode"
      err_line="$(detect_hdbsql_error_line "$output" || true)"
      if [[ -n "$err_line" ]] && is_hdbsql_invalid_column_error "$err_line"; then
        continue
      fi
      printf '%s' "$output"
      last_hdbsql_mode="$selected_mode"
      return
    done

    # Return output of last candidate if all variants failed.
    printf '%s' "$output"
  }

  # Auto-detect SID if not set
  if [[ -z "$sid" ]] && [[ -d /hana/shared ]]; then
    sid="$(find /hana/shared -mindepth 1 -maxdepth 1 -type d 2>/dev/null \
      | awk -F/ '{print $NF}' \
      | grep -E '^[A-Z][A-Z0-9]{2}$' \
      | head -1 || true)"
  fi

  # Validate timeout/port defaults
  [[ "$query_timeout_sec" =~ ^[0-9]+$ ]] || query_timeout_sec=15
  [[ "$addons_port" =~ ^[0-9]+$ ]] || addons_port=30015

  # Auto-detect local HANA SQL port if config is still on default 30015.
  # Example: HDB90 -> SQL port 39015.
  if [[ "$addons_port" == "30015" ]]; then
    if [[ -n "$sid" ]] && [[ -d "/usr/sap/${sid}" ]]; then
      detected_instance_no="$(find "/usr/sap/${sid}" -maxdepth 1 -type d -name 'HDB[0-9][0-9]' 2>/dev/null | sed -n 's|.*/HDB\([0-9][0-9]\)$|\1|p' | head -1 || true)"
      if [[ -z "$detected_instance_no" ]]; then
        detected_instance_no="$(grep -hE '^[[:space:]]*SAPSYSTEM[[:space:]]*=' "/usr/sap/${sid}/SYS/profile"/* 2>/dev/null | tail -1 | sed -E 's/.*=[[:space:]]*([0-9]{1,2}).*/\1/' | sed -E 's/^([0-9])$/0\1/' || true)"
      fi
      if [[ "$detected_instance_no" =~ ^[0-9]{2}$ ]]; then
        detected_sql_port="3${detected_instance_no}15"
        if [[ "$detected_sql_port" =~ ^[0-9]{5}$ ]]; then
          addons_port="$detected_sql_port"
        fi
      fi
    fi
  fi

  hdbsql_target="${addons_host}:${addons_port}"

  if [[ -z "$sid" ]]; then
    reason="missing_hana_sid"
    error_msg="HANA SID nicht gefunden"
    printf '{"available":false,"sid":"","user":"%s","target":"%s","lightweight":[],"legacy":[],"error":"%s","reason":"%s"}' \
      "$(json_escape "$addons_user")" \
      "$(json_escape "$hdbsql_target")" \
      "$(json_escape "$error_msg")" \
      "$reason"
    return
  fi

  sid_user="$(printf '%s' "$sid" | tr '[:upper:]' '[:lower:]')adm"

  # Check if sid_user exists
  if ! id "$sid_user" >/dev/null 2>&1; then
    reason="missing_sid_user"
    error_msg="User ${sid_user} nicht angelegt"
    printf '{"available":false,"sid":"%s","user":"%s","target":"%s","lightweight":[],"legacy":[],"error":"%s","reason":"%s"}' \
      "$(json_escape "$sid")" \
      "$(json_escape "$addons_user")" \
      "$(json_escape "$hdbsql_target")" \
      "$(json_escape "$error_msg")" \
      "$reason"
    return
  fi

  # Check if hdbsql is available (via sid_user's PATH)
  if ! su - "$sid_user" -c "command -v hdbsql" >/dev/null 2>&1; then
    reason="missing_hdbsql"
    error_msg="hdbsql nicht vorhanden"
    printf '{"available":false,"sid":"%s","user":"%s","target":"%s","lightweight":[],"legacy":[],"error":"%s","reason":"%s"}' \
      "$(json_escape "$sid")" \
      "$(json_escape "$addons_user")" \
      "$(json_escape "$hdbsql_target")" \
      "$(json_escape "$error_msg")" \
      "$reason"
    return
  fi

  if [[ "${HANA_TENANT_SCAN_MODE:-0}" != "1" ]] && [[ -n "$sid" ]]; then
    local tenant_targets=()
    mapfile -t tenant_targets < <(collect_hana_multitenant_targets "$sid")
    if (( ${#tenant_targets[@]} > 0 )); then
      local tenants_json=""
      local tenants_sep=""
      local any_available=false
      local target_line=""

      for target_line in "${tenant_targets[@]}"; do
        local tenant_id="${target_line%%|*}"
        local tenant_port="${target_line#*|}"
        local tenant_result=""
        tenant_result="$(HANA_TENANT_SCAN_MODE=1 HANA_TENANT_DB="$tenant_id" HANA_SID="$sid" collect_hana_addons_json)"
        if printf '%s' "$tenant_result" | grep -q '"available":true'; then
          any_available=true
        fi

        tenants_json+="${tenants_sep}{\"tenant_id\":\"$(json_escape "$tenant_id")\",\"tenant_port\":\"$(json_escape "$tenant_port")\",\"result\":${tenant_result}}"
        tenants_sep=","
      done

      printf '{"available":%s,"sid":"%s","user":"%s","target_mode":"multitenant","multitenant":true,"tenants":[%s],"lightweight":[],"legacy":[],"error":"","reason":"%s"}' \
        "$([ "$any_available" = true ] && echo true || echo false)" \
        "$(json_escape "$sid")" \
        "$(json_escape "$addons_user")" \
        "$tenants_json" \
        "$([ "$any_available" = true ] && echo success || echo partial)"
      return
    fi
  fi

  # Try Lightweight query against SLDDATA extensions with deployment join.
  local lightweight_output=""
  local lightweight_error=""
  lightweight_output="$(run_hdbsql_query_candidates "lightweight")"
  lw_mode="$last_hdbsql_mode"
  # Parse lightweight output.
  # Supports both hdbsql formats seen in the field:
  #   - pipe-delimited: NAME|Version
  #   - CSV-like:       "NAME","Version"
  if [[ -n "$lightweight_output" ]]; then
    if detect_hdbsql_error_line "$lightweight_output" >/dev/null; then
      lightweight_error="$(detect_hdbsql_error_line "$lightweight_output")"
    fi

    local cleaned_lightweight_output
    cleaned_lightweight_output="$(clean_hdbsql_output "$lightweight_output")"

    # First try robust CSV extraction. This handles concatenated rows and rows
    # that have timing footers appended to the same line.
    local csv_matches=""
    csv_matches="$(printf '%s\n' "$cleaned_lightweight_output" | grep -oE '"[^"]*","[^"]*"' || true)"
    if [[ -n "$csv_matches" ]]; then
      while IFS= read -r record; do
        local name=""
        local version=""
        [[ -z "$record" ]] && continue
        if [[ "$record" =~ \"([^\"]*)\",\"([^\"]*)\" ]]; then
          name="${BASH_REMATCH[1]}"
          version="${BASH_REMATCH[2]}"
        else
          continue
        fi

        name="$(printf '%s' "$name" | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
        version="$(printf '%s' "$version" | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"

        if [[ -z "$name" ]] || [[ "$name" == "NAME" ]] || [[ "$version" == "Version" ]]; then
          continue
        fi

        local entry
        entry="$(printf '{"name":"%s","version":"%s"}' "$(json_escape "$name")" "$(json_escape "$version")")"
        lightweight_entries="$(append_hana_addon_json_entry "$lightweight_entries" "$entry")"
      done <<< "$csv_matches"
    fi

    if [[ -z "$lightweight_entries" ]]; then
      while IFS= read -r line; do
        local parsed_row=""
        local name=""
        local version=""
        parsed_row="$(parse_hdbsql_row_fallback "$line" || true)"
        [[ -z "$parsed_row" ]] && continue
        name="${parsed_row%%$'\t'*}"
        version="${parsed_row#*$'\t'}"

        if [[ -n "$name" ]]; then
          local entry
          entry="$(printf '{"name":"%s","version":"%s"}' "$(json_escape "$name")" "$(json_escape "$version")")"
          lightweight_entries="$(append_hana_addon_json_entry "$lightweight_entries" "$entry")"
        fi
      done <<< "$cleaned_lightweight_output"
    fi
  fi

  # Try Legacy query: SELECT "AName", "AddOnVer" FROM "SBOCOMMON"."SARI"
  local legacy_output=""
  local legacy_error=""
  legacy_output="$(run_hdbsql_query_candidates "legacy")"
  lg_mode="$last_hdbsql_mode"
  # Parse legacy output.
  # Supports both hdbsql formats seen in the field:
  #   - pipe-delimited: AName|AddOnVer
  #   - CSV-like:       "AName","AddOnVer"
  if [[ -n "$legacy_output" ]]; then
    if detect_hdbsql_error_line "$legacy_output" >/dev/null; then
      legacy_error="$(detect_hdbsql_error_line "$legacy_output")"
    fi

    local cleaned_legacy_output
    cleaned_legacy_output="$(clean_hdbsql_output "$legacy_output")"

    local csv_matches=""
    csv_matches="$(printf '%s\n' "$cleaned_legacy_output" | grep -oE '"[^"]*","[^"]*"' || true)"
    if [[ -n "$csv_matches" ]]; then
      while IFS= read -r record; do
        local aname=""
        local addonver=""
        [[ -z "$record" ]] && continue
        if [[ "$record" =~ \"([^\"]*)\",\"([^\"]*)\" ]]; then
          aname="${BASH_REMATCH[1]}"
          addonver="${BASH_REMATCH[2]}"
        else
          continue
        fi

        aname="$(printf '%s' "$aname" | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
        addonver="$(printf '%s' "$addonver" | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"

        if [[ -z "$aname" ]] || [[ "$aname" == "AName" ]] || [[ "$addonver" == "AddOnVer" ]]; then
          continue
        fi

        local entry
        entry="$(printf '{"name":"%s","version":"%s"}' "$(json_escape "$aname")" "$(json_escape "$addonver")")"
        legacy_entries="$(append_hana_addon_json_entry "$legacy_entries" "$entry")"
      done <<< "$csv_matches"
    fi

    if [[ -z "$legacy_entries" ]]; then
      while IFS= read -r line; do
        local parsed_row=""
        local aname=""
        local addonver=""
        parsed_row="$(parse_hdbsql_row_fallback "$line" || true)"
        [[ -z "$parsed_row" ]] && continue
        aname="${parsed_row%%$'\t'*}"
        addonver="${parsed_row#*$'\t'}"

        if [[ -n "$aname" ]]; then
          local entry
          entry="$(printf '{"name":"%s","version":"%s"}' "$(json_escape "$aname")" "$(json_escape "$addonver")")"
          legacy_entries="$(append_hana_addon_json_entry "$legacy_entries" "$entry")"
        fi
      done <<< "$cleaned_legacy_output"
    fi
  fi

  # Determine final status
  if [[ -n "$lightweight_entries" ]] || [[ -n "$legacy_entries" ]]; then
    available=true
    if [[ -n "$lightweight_error" ]] || [[ -n "$legacy_error" ]]; then
      reason="partial_result"
      error_msg="$(printf '%s | %s' "$lightweight_error" "$legacy_error" | sed -E 's/^[[:space:]|]+//; s/[[:space:]|]+$//; s/[[:space:]]*\|[[:space:]]*/ | /g; s/( \| )+/ | /g')"
    else
      reason="success"
    fi
  else
    if [[ -n "$lightweight_error" ]] || [[ -n "$legacy_error" ]]; then
      local merged_error
      merged_error="$(printf '%s | %s' "$lightweight_error" "$legacy_error" | sed -E 's/^[[:space:]|]+//; s/[[:space:]|]+$//; s/[[:space:]]*\|[[:space:]]*/ | /g; s/( \| )+/ | /g')"
      error_msg="${merged_error:-hdbsql query failed} (target=${hdbsql_target}; mode=lw:${lw_mode},lg:${lg_mode})"
      if is_hdbsql_connection_error "$merged_error"; then
        local listener_diag
        listener_diag="$(summarize_hana_sql_listener_diagnostics)"
        error_msg="${error_msg}; ${listener_diag}"
      fi
      if [[ "$error_msg" =~ [Aa]uthentication[[:space:]]+failed ]] || [[ "$error_msg" =~ SQLSTATE:[[:space:]]*28000 ]]; then
        reason="auth_failed"
      else
        reason="query_failed"
      fi
    elif [[ -n "${lightweight_output:-}" ]] || [[ -n "${legacy_output:-}" ]]; then
      reason="parse_failed"
      local lw_sample lg_sample
      lw_sample="$(summarize_hdbsql_output_for_diagnostics "${lightweight_output:-}")"
      lg_sample="$(summarize_hdbsql_output_for_diagnostics "${legacy_output:-}")"
      error_msg="hdbsql output vorhanden, aber keine AddOn-Zeilen erkannt (target=${hdbsql_target}; mode=lw:${lw_mode},lg:${lg_mode}); LW=[${lw_sample}] LEG=[${lg_sample}]"
    else
      reason="empty_result"
      error_msg="Keine AddOns gefunden"
    fi
  fi

  printf '{"available":%s,"sid":"%s","user":"%s","target":"%s","target_mode":"lw:%s,lg:%s","lightweight":[%s],"legacy":[%s],"error":"%s","reason":"%s"}' \
    "$([ "$available" = true ] && echo true || echo false)" \
    "$(json_escape "$sid")" \
    "$(json_escape "$addons_user")" \
    "$(json_escape "$hdbsql_target")" \
    "$(json_escape "$lw_mode")" \
    "$(json_escape "$lg_mode")" \
    "$lightweight_entries" \
    "$legacy_entries" \
    "$(json_escape "$error_msg")" \
    "$reason"
}

collect_hana_multitenant_targets() {
  # Detect tenant directories only.
  # Output format per line: TENANT_ID|
  local sid="${1-}"
  local config_root=""
  local tenant_dir=""

  [[ -z "$sid" ]] && return 0
  config_root="/usr/sap/${sid}/SYS/global/hdb/custom/config"
  [[ -d "$config_root" ]] || return 0

  while IFS= read -r tenant_dir; do
    local tenant_name=""
    local tenant_id=""

    [[ -z "$tenant_dir" ]] && continue
    tenant_name="$(basename "$tenant_dir")"
    tenant_id="${tenant_name#DB_}"
    [[ "$tenant_id" =~ ^[A-Za-z0-9]{3}$ ]] || continue

    printf '%s|\n' "$tenant_id"
  done < <(find "$config_root" -mindepth 1 -maxdepth 1 -type d -name 'DB_???' 2>/dev/null | sort)
}

collect_hana_multitenant_discovery_json() {
  local sid="${HANA_SID:-}"
  local config_root=""
  local targets=()
  local tenants_json=""
  local sep=""
  local line=""

  if [[ -z "$sid" ]]; then
    printf '{"available":false,"sid":"","config_root":"","tenant_count":0,"with_port_count":0,"tenants":[],"reason":"missing_hana_sid"}'
    return
  fi

  config_root="/usr/sap/${sid}/SYS/global/hdb/custom/config"
  mapfile -t targets < <(collect_hana_multitenant_targets "$sid")

  for line in "${targets[@]}"; do
    local tenant_id="${line%%|*}"
    local tenant_port="${line#*|}"
    local has_port=false
    if [[ -n "$tenant_port" ]]; then
      has_port=true
    fi
    tenants_json+="${sep}{\"tenant_id\":\"$(json_escape "$tenant_id")\",\"tenant_port\":\"$(json_escape "$tenant_port")\",\"has_port\":$has_port}"
    sep=","
  done

  local tenant_count="${#targets[@]}"
  local with_port_count=0
  if (( tenant_count > 0 )); then
    with_port_count="$(printf '%s\n' "${targets[@]}" | awk -F'|' 'NF>=2 && $2 != "" {c++} END {print c+0}')"
  fi

  local reason="none_found"
  if (( tenant_count > 0 )); then
    reason="success"
  fi

  printf '{"available":%s,"sid":"%s","config_root":"%s","tenant_count":%s,"with_port_count":%s,"tenants":[%s],"reason":"%s"}' \
    "$([ "$tenant_count" -gt 0 ] && echo true || echo false)" \
    "$(json_escape "$sid")" \
    "$(json_escape "$config_root")" \
    "$tenant_count" \
    "$with_port_count" \
    "$tenants_json" \
    "$reason"
}

collect_hana_db_info_json() {
  # Collects HANA schema memory usage (read-only) via hdbsql.
  # Connection behavior intentionally mirrors collect_hana_addons_json.
  local sid="${HANA_SID:-}"
  local sid_user=""
  local db_user="${HANA_ADDONS_USER:-HARVEST}"
  local db_password="${HANA_ADDONS_PASSWORD:-0djKUt&xbLK0AYr}"
  local query_timeout_sec="${HANA_ADDONS_QUERY_TIMEOUT_SEC:-15}"
  local db_host="${HANA_ADDONS_HOST:-127.0.0.1}"
  local db_port="${HANA_ADDONS_PORT:-30015}"
  local detected_instance_no=""
  local detected_sql_port=""
  local hdbsql_target=""
  local last_hdbsql_mode="explicit_target"
  local available=false
  local reason="unknown"
  local error_msg=""
  local schema_entries=""

  clean_hdbsql_db_output() {
    local raw_text="${1-}"
    printf '%s' "$raw_text" \
      | tr -d '\r' \
      | sed -E '
          s/[[:space:]]*[0-9]+[[:space:]]+rows selected.*$//I;
          s/[[:space:]]*[0-9]+[[:space:]]+row selected.*$//I;
          s/[[:space:]]*(overall|server)[[:space:]]+time.*$//I;
        '
  }

  detect_hdbsql_db_error_line() {
    local raw_text="${1-}"
    local first_error=""

    first_error="$(printf '%s\n' "$raw_text" | awk '
      BEGIN { IGNORECASE=1 }
      /authentication failed|sqlstate|insufficient privilege|invalid user|user is locked|connection failed|cannot connect|error:/ {
        line=$0
        sub(/^[[:space:]]+/, "", line)
        sub(/[[:space:]]+$/, "", line)
        print line
        exit
      }
    ')"

    if [[ -n "$first_error" ]]; then
      printf '%s' "$first_error"
      return 0
    fi
    return 1
  }

  is_hdbsql_db_connection_error() {
    local raw_text="${1-}"
    if printf '%s\n' "$raw_text" | grep -qiE 'connection failed|cannot connect|rc=111|rc=99'; then
      return 0
    fi
    return 1
  }

  run_hdbsql_db_query() {
    local sql_text="${1-}"
    local sql_escaped=""
    local implicit_output=""
    local explicit_output=""
    local alt_port=""
    local alt_host=""
    local alt_output=""
    local probe_hosts_csv=""
    local probe_host_list=""
    local tenant_scan_mode="${HANA_TENANT_SCAN_MODE:-0}"
    local tenant_db_name="${HANA_TENANT_DB:-}"

    sql_escaped="$(printf '%q' "$sql_text")"

    # Tenant mode: use DB-name based access (-d) only.
    if [[ "$tenant_scan_mode" == "1" ]]; then
      if [[ -z "$tenant_db_name" ]]; then
        tenant_db_name="$sid"
      fi

      if [[ -n "$tenant_db_name" ]]; then
        if command -v timeout >/dev/null 2>&1; then
          implicit_output="$(timeout "${query_timeout_sec}s" su - "$sid_user" -c "hdbsql -d \"$tenant_db_name\" -u \"$db_user\" -p \"$db_password\" $sql_escaped 2>&1" || true)"
        else
          implicit_output="$(su - "$sid_user" -c "hdbsql -d \"$tenant_db_name\" -u \"$db_user\" -p \"$db_password\" $sql_escaped 2>&1" || true)"
        fi
        if [[ -n "$implicit_output" ]]; then
          if is_hdbsql_db_connection_error "$implicit_output"; then
            last_hdbsql_mode="tenant_db_implicit_failed"
          else
            last_hdbsql_mode="tenant_db_implicit"
          fi
        else
          last_hdbsql_mode="tenant_db_implicit_empty"
        fi
        printf '%s' "$implicit_output"
        return
      fi
    fi

    if [[ "$tenant_scan_mode" != "1" ]]; then
      if command -v timeout >/dev/null 2>&1; then
        implicit_output="$(timeout "${query_timeout_sec}s" su - "$sid_user" -c "hdbsql -u \"$db_user\" -p \"$db_password\" $sql_escaped 2>&1" || true)"
      else
        implicit_output="$(su - "$sid_user" -c "hdbsql -u \"$db_user\" -p \"$db_password\" $sql_escaped 2>&1" || true)"
      fi
      if [[ -n "$implicit_output" ]] && ! is_hdbsql_db_connection_error "$implicit_output"; then
        last_hdbsql_mode="implicit_primary"
        printf '%s' "$implicit_output"
        return
      fi
    fi

    last_hdbsql_mode="explicit_target"
    if command -v timeout >/dev/null 2>&1; then
      explicit_output="$(timeout "${query_timeout_sec}s" su - "$sid_user" -c "hdbsql -n \"$hdbsql_target\" -u \"$db_user\" -p \"$db_password\" $sql_escaped 2>&1" || true)"
    else
      explicit_output="$(su - "$sid_user" -c "hdbsql -n \"$hdbsql_target\" -u \"$db_user\" -p \"$db_password\" $sql_escaped 2>&1" || true)"
    fi

    if is_hdbsql_db_connection_error "$explicit_output"; then
      probe_hosts_csv="$db_host,127.0.0.1,localhost,$(hostname -f 2>/dev/null || true),$(hostname 2>/dev/null || true)"
      probe_host_list="$(printf '%s' "$probe_hosts_csv" | tr ',' '\n' | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//' | awk 'NF>0' | awk '!seen[$0]++')"

      while IFS= read -r alt_port; do
        [[ -z "$alt_port" ]] && continue
        while IFS= read -r alt_host; do
          [[ -z "$alt_host" ]] && continue
          if command -v timeout >/dev/null 2>&1; then
            alt_output="$(timeout "${query_timeout_sec}s" su - "$sid_user" -c "hdbsql -n \"${alt_host}:${alt_port}\" -u \"$db_user\" -p \"$db_password\" $sql_escaped 2>&1" || true)"
          else
            alt_output="$(su - "$sid_user" -c "hdbsql -n \"${alt_host}:${alt_port}\" -u \"$db_user\" -p \"$db_password\" $sql_escaped 2>&1" || true)"
          fi
          if [[ -n "$alt_output" ]] && ! is_hdbsql_db_connection_error "$alt_output"; then
            db_host="$alt_host"
            db_port="$alt_port"
            hdbsql_target="${db_host}:${db_port}"
            last_hdbsql_mode="auto_probe_${alt_host}_${alt_port}"
            printf '%s' "$alt_output"
            return
          fi
        done <<< "$probe_host_list"
      done < <(ss -lntH 2>/dev/null | awk '{print $4}' | sed -E 's/.*:([0-9]+)$/\1/' | grep -E '^3[0-9]{2}15$' | sort -u || true)

      for alt_port in 30015 30115 30215 30315 30415 30515 30615 30715 30815 30915 31015 31115 31215 31315 31415 31515 31615 31715 31815 31915 32015 32115 32215 32315 32415 32515 32615 32715 32815 32915 33015 33115 33215 33315 33415 33515 33615 33715 33815 33915 34015 34115 34215 34315 34415 34515 34615 34715 34815 34915 35015 35115 35215 35315 35415 35515 35615 35715 35815 35915 36015 36115 36215 36315 36415 36515 36615 36715 36815 36915 37015 37115 37215 37315 37415 37515 37615 37715 37815 37915 38015 38115 38215 38315 38415 38515 38615 38715 38815 38915 39015 39115 39215 39315 39415 39515 39615 39715 39815 39915; do
        while IFS= read -r alt_host; do
          [[ -z "$alt_host" ]] && continue
          if command -v timeout >/dev/null 2>&1; then
            alt_output="$(timeout "${query_timeout_sec}s" su - "$sid_user" -c "hdbsql -n \"${alt_host}:${alt_port}\" -u \"$db_user\" -p \"$db_password\" $sql_escaped 2>&1" || true)"
          else
            alt_output="$(su - "$sid_user" -c "hdbsql -n \"${alt_host}:${alt_port}\" -u \"$db_user\" -p \"$db_password\" $sql_escaped 2>&1" || true)"
          fi
          if [[ -n "$alt_output" ]] && ! is_hdbsql_db_connection_error "$alt_output"; then
            db_host="$alt_host"
            db_port="$alt_port"
            hdbsql_target="${db_host}:${db_port}"
            last_hdbsql_mode="auto_probe_common_${alt_host}_${alt_port}"
            printf '%s' "$alt_output"
            return
          fi
        done <<< "$probe_host_list"
      done
    fi

    printf '%s' "$explicit_output"
  }

  parse_hdbsql_db_row_fallback() {
    local line="${1-}"
    local parsed_name=""
    local parsed_value=""

    line="$(printf '%s' "$line" | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
    [[ -z "$line" ]] && return 1

    if [[ "$line" =~ [Rr]ows[[:space:]]+selected ]] || [[ "$line" =~ [Oo]verall[[:space:]]+time ]] || [[ "$line" =~ [Ss]erver[[:space:]]+time ]] || [[ "$line" =~ ^[-=]+$ ]] || [[ "$line" =~ ^\* ]]; then
      return 1
    fi

    if [[ "$line" == *"|"* ]]; then
      IFS='|' read -r parsed_name parsed_value _ <<< "$line"
    elif [[ "$line" =~ ^\"(.*)\",\"(.*)\"$ ]]; then
      parsed_name="${BASH_REMATCH[1]}"
      parsed_value="${BASH_REMATCH[2]}"
    elif [[ "$line" =~ ^([^,]+),(.+)$ ]]; then
      parsed_name="${BASH_REMATCH[1]}"
      parsed_value="${BASH_REMATCH[2]}"
    elif [[ "$line" =~ ^(.+)[[:space:]][[:space:]]+(.+)$ ]]; then
      parsed_name="${BASH_REMATCH[1]}"
      parsed_value="${BASH_REMATCH[2]}"
    else
      return 1
    fi

    parsed_name="$(printf '%s' "$parsed_name" | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//; s/^"//; s/"$//')"
    parsed_value="$(printf '%s' "$parsed_value" | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//; s/^"//; s/"$//')"

    [[ -z "$parsed_name" ]] && return 1
    if [[ "$parsed_name" == "SCHEMA_NAME" ]] || [[ "$parsed_value" == "MEMORY_GB" ]]; then
      return 1
    fi

    printf '%s\t%s' "$parsed_name" "$parsed_value"
    return 0
  }

  if [[ -z "$sid" ]] && [[ -d /hana/shared ]]; then
    sid="$(find /hana/shared -mindepth 1 -maxdepth 1 -type d 2>/dev/null \
      | awk -F/ '{print $NF}' \
      | grep -E '^[A-Z][A-Z0-9]{2}$' \
      | head -1 || true)"
  fi

  [[ "$query_timeout_sec" =~ ^[0-9]+$ ]] || query_timeout_sec=15
  [[ "$db_port" =~ ^[0-9]+$ ]] || db_port=30015

  if [[ "$db_port" == "30015" ]]; then
    if [[ -n "$sid" ]] && [[ -d "/usr/sap/${sid}" ]]; then
      detected_instance_no="$(find "/usr/sap/${sid}" -maxdepth 1 -type d -name 'HDB[0-9][0-9]' 2>/dev/null | sed -n 's|.*/HDB\([0-9][0-9]\)$|\1|p' | head -1 || true)"
      if [[ -z "$detected_instance_no" ]]; then
        detected_instance_no="$(grep -hE '^[[:space:]]*SAPSYSTEM[[:space:]]*=' "/usr/sap/${sid}/SYS/profile"/* 2>/dev/null | tail -1 | sed -E 's/.*=[[:space:]]*([0-9]{1,2}).*/\1/' | sed -E 's/^([0-9])$/0\1/' || true)"
      fi
      if [[ "$detected_instance_no" =~ ^[0-9]{2}$ ]]; then
        detected_sql_port="3${detected_instance_no}15"
        if [[ "$detected_sql_port" =~ ^[0-9]{5}$ ]]; then
          db_port="$detected_sql_port"
        fi
      fi
    fi
  fi

  hdbsql_target="${db_host}:${db_port}"

  if [[ -z "$sid" ]]; then
    reason="missing_hana_sid"
    error_msg="HANA SID nicht gefunden"
    printf '{"available":false,"sid":"","user":"%s","target":"%s","target_mode":"n/a","schemas":[],"error":"%s","reason":"%s"}' \
      "$(json_escape "$db_user")" \
      "$(json_escape "$hdbsql_target")" \
      "$(json_escape "$error_msg")" \
      "$reason"
    return
  fi

  sid_user="$(printf '%s' "$sid" | tr '[:upper:]' '[:lower:]')adm"
  if ! id "$sid_user" >/dev/null 2>&1; then
    reason="missing_sid_user"
    error_msg="User ${sid_user} nicht angelegt"
    printf '{"available":false,"sid":"%s","user":"%s","target":"%s","target_mode":"n/a","schemas":[],"error":"%s","reason":"%s"}' \
      "$(json_escape "$sid")" \
      "$(json_escape "$db_user")" \
      "$(json_escape "$hdbsql_target")" \
      "$(json_escape "$error_msg")" \
      "$reason"
    return
  fi

  if [[ "${HANA_TENANT_SCAN_MODE:-0}" != "1" ]] && [[ -n "$sid" ]]; then
    local tenant_targets=()
    mapfile -t tenant_targets < <(collect_hana_multitenant_targets "$sid")
    if (( ${#tenant_targets[@]} > 0 )); then
      local tenants_json=""
      local tenants_sep=""
      local any_available=false
      local target_line=""

      for target_line in "${tenant_targets[@]}"; do
        local tenant_id="${target_line%%|*}"
        local tenant_port="${target_line#*|}"
        local tenant_result=""
        tenant_result="$(HANA_TENANT_SCAN_MODE=1 HANA_TENANT_DB="$tenant_id" HANA_SID="$sid" collect_hana_db_info_json)"
        if printf '%s' "$tenant_result" | grep -q '"available":true'; then
          any_available=true
        fi

        tenants_json+="${tenants_sep}{\"tenant_id\":\"$(json_escape "$tenant_id")\",\"tenant_port\":\"$(json_escape "$tenant_port")\",\"result\":${tenant_result}}"
        tenants_sep=","
      done

      printf '{"available":%s,"sid":"%s","user":"%s","target_mode":"multitenant","multitenant":true,"tenants":[%s],"databases":[],"error":"","reason":"%s"}' \
        "$([ "$any_available" = true ] && echo true || echo false)" \
        "$(json_escape "$sid")" \
        "$(json_escape "$db_user")" \
        "$tenants_json" \
        "$([ "$any_available" = true ] && echo success || echo partial)"
      return
    fi
  fi

  if ! su - "$sid_user" -c "command -v hdbsql" >/dev/null 2>&1; then
    reason="missing_hdbsql"
    error_msg="hdbsql nicht vorhanden"
    printf '{"available":false,"sid":"%s","user":"%s","target":"%s","target_mode":"n/a","databases":[],"error":"%s","reason":"%s"}' \
      "$(json_escape "$sid")" \
      "$(json_escape "$db_user")" \
      "$(json_escape "$hdbsql_target")" \
      "$(json_escape "$error_msg")" \
      "$reason"
    return
  fi

  local db_output=""
  local db_error=""
  db_output="$(run_hdbsql_db_query 'SELECT "NAME","COMPANYNAME","LOCALIZATION" FROM "SLDDATA"."COMPANYDBS";')"

  if detect_hdbsql_db_error_line "$db_output" >/dev/null; then
    db_error="$(detect_hdbsql_db_error_line "$db_output")"
  fi

  if [[ -z "$db_error" ]]; then
    local cleaned_output=""
    cleaned_output="$(clean_hdbsql_db_output "$db_output")"

    local csv_matches=""
    csv_matches="$(printf '%s\n' "$cleaned_output" | grep -oE '"[^"]*","[^"]*","[^"]*"' || true)"
    if [[ -n "$csv_matches" ]]; then
      while IFS= read -r record; do
        local db_name=""
        local company_name=""
        local localization=""
        [[ -z "$record" ]] && continue
        if [[ "$record" =~ \"([^\"]*)\",\"([^\"]*)\",\"([^\"]*)\" ]]; then
          db_name="${BASH_REMATCH[1]}"
          company_name="${BASH_REMATCH[2]}"
          localization="${BASH_REMATCH[3]}"
        else
          continue
        fi

        db_name="$(printf '%s' "$db_name" | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
        company_name="$(printf '%s' "$company_name" | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"
        localization="$(printf '%s' "$localization" | sed -e 's/^[[:space:]]*//; s/[[:space:]]*$//')"

        [[ -z "$db_name" ]] && continue
        if [[ "${db_name^^}" == "NAME" ]] && [[ "${company_name^^}" == "COMPANYNAME" ]]; then
          continue
        fi

        local entry
        entry="$(printf '{\"name\":\"%s\",\"company_name\":\"%s\",\"localization\":\"%s\"}' "$(json_escape "$db_name")" "$(json_escape "$company_name")" "$(json_escape "$localization")")"
        schema_entries="${schema_entries:+$schema_entries,}$entry"
      done <<< "$csv_matches"
    fi

    if [[ -z "$schema_entries" ]]; then
      while IFS= read -r line; do
        local parsed_row=""
        local db_name=""
        local company_name=""
        local localization=""
        parsed_row="$(printf '%s' "$line" | awk '
          BEGIN { OFS="\t" }
          /[Rr]ows[[:space:]]+selected|[Oo]verall[[:space:]]+time|[Ss]erver[[:space:]]+time|^[-=]+$|^\*/ { next }
          {
            raw=$0
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", raw)
            if (raw == "") next
            if (raw ~ /^".*",".*",".*"$/) {
              sub(/^"/, "", raw)
              sub(/"$/, "", raw)
              gsub(/","/, OFS, raw)
              print raw
              exit
            }
            n=split(raw, parts, "|")
            if (n >= 3) {
              for (i = 1; i <= 3; i++) {
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", parts[i])
                gsub(/^"|"$/, "", parts[i])
              }
              print parts[1], parts[2], parts[3]
              exit
            }
          }
        ' || true)"
        [[ -z "$parsed_row" ]] && continue
        db_name="${parsed_row%%$'\t'*}"
        parsed_row="${parsed_row#*$'\t'}"
        company_name="${parsed_row%%$'\t'*}"
        localization="${parsed_row#*$'\t'}"

        [[ -z "$db_name" ]] && continue
        if [[ "${db_name^^}" == "NAME" ]] && [[ "${company_name^^}" == "COMPANYNAME" ]]; then
          continue
        fi

        local entry
        entry="$(printf '{\"name\":\"%s\",\"company_name\":\"%s\",\"localization\":\"%s\"}' "$(json_escape "$db_name")" "$(json_escape "$company_name")" "$(json_escape "$localization")")"
        schema_entries="${schema_entries:+$schema_entries,}$entry"
      done <<< "$cleaned_output"
    fi

    available=true
    if [[ -n "$schema_entries" ]]; then
      reason="success"
    else
      reason="empty_result"
    fi
  else
    error_msg="$db_error (target=${hdbsql_target}; mode=${last_hdbsql_mode})"
    if [[ "$error_msg" =~ [Aa]uthentication[[:space:]]+failed ]] || [[ "$error_msg" =~ SQLSTATE:[[:space:]]*28000 ]]; then
      reason="auth_failed"
    else
      reason="query_failed"
    fi
  fi

  printf '{"available":%s,"sid":"%s","user":"%s","target":"%s","target_mode":"%s","databases":[%s],"error":"%s","reason":"%s"}' \
    "$([ "$available" = true ] && echo true || echo false)" \
    "$(json_escape "$sid")" \
    "$(json_escape "$db_user")" \
    "$(json_escape "$hdbsql_target")" \
    "$(json_escape "$last_hdbsql_mode")" \
    "$schema_entries" \
    "$(json_escape "$error_msg")" \
    "$reason"
}

collect_cron_json() {
  # Collects additional HANA runtime info without requiring DB credentials:
  #   - Service status via "HDB info" (as <sid>adm)
  #   - Last backup timestamps from backup directory modification times
  # Designed to be forward-compatible: hdbsql-based schema info can be added later.
  local sid="${HANA_SID:-}"
  local sid_user=""
  local services_json="[]"
  local backup_json="{}"
  local volumes_json="{}"

  # Auto-detect SID (same logic as collect_hana_version_json)
  if [[ -z "$sid" ]] && [[ -d /hana/shared ]]; then
    local detected_sid
    detected_sid="$(find /hana/shared -mindepth 1 -maxdepth 1 -type d 2>/dev/null \
      | awk -F/ '{print $NF}' \
      | grep -E '^[A-Z][A-Z0-9]{2}$' \
      | head -1 || true)"
    [[ -n "$detected_sid" ]] && sid="$detected_sid"
  fi

  if [[ -z "$sid" ]]; then
    printf '{"available":false,"sid":"","services":[],"backup":{},"volumes":{}}'
    return
  fi

  sid_user="$(printf '%s' "$sid" | tr '[:upper:]' '[:lower:]')adm"
  local timeout_sec="${HANA_VERSION_TIMEOUT_SEC:-10}"
  [[ "$timeout_sec" =~ ^[0-9]+$ ]] || timeout_sec=10

  # --- Services via "HDB info" ---
  local hdb_info_raw=""
  if id "$sid_user" >/dev/null 2>&1; then
    if command -v timeout >/dev/null 2>&1; then
      hdb_info_raw="$(timeout "${timeout_sec}s" su - "$sid_user" -c 'HDB info' 2>/dev/null || true)"
    else
      hdb_info_raw="$(su - "$sid_user" -c 'HDB info' 2>/dev/null || true)"
    fi
  fi

  if [[ -n "$hdb_info_raw" ]]; then
    local svc_entries=""
    while IFS= read -r line; do
      # "HDB info" format: "  hdbindexserver      31001   30101  running"
      # Skip header line and empty lines
      local svc_name pid ppid status
      if [[ "$line" =~ ^[[:space:]]*(hdb[a-z]+)[[:space:]]+([0-9]+)[[:space:]]+([0-9]+)[[:space:]]+([a-z]+) ]]; then
        svc_name="${BASH_REMATCH[1]}"
        pid="${BASH_REMATCH[2]}"
        ppid="${BASH_REMATCH[3]}"
        status="${BASH_REMATCH[4]}"
        local entry
        entry="$(printf '{"name":"%s","pid":%s,"ppid":%s,"status":"%s"}' \
          "$(json_escape "$svc_name")" "$pid" "$ppid" "$(json_escape "$status")")"
        svc_entries="${svc_entries:+$svc_entries,}$entry"
      fi
    done <<< "$hdb_info_raw"
    [[ -n "$svc_entries" ]] && services_json="[$svc_entries]"
  fi

  # --- Backup info from filesystem ---
  # HANA stores backups under /hana/shared/<SID>/HDB<instance>/backup/
  # We look for the most recent data and log backup by directory mtime.
  local backup_base=""
  if [[ -d "/hana/shared/${sid}" ]]; then
    backup_base="$(find "/hana/shared/${sid}" -maxdepth 2 -type d -name "backup" 2>/dev/null | head -1 || true)"
  fi

  local last_data_backup="" last_log_backup="" backup_data_dir="" backup_log_dir=""
  if [[ -n "$backup_base" ]]; then
    backup_data_dir="${backup_base}/data"
    backup_log_dir="${backup_base}/log"

    if [[ -d "$backup_data_dir" ]]; then
      local newest_data
      newest_data="$(find "$backup_data_dir" -maxdepth 3 \( -name "*.bak" -o -name "*.complete" -o -name "COMPLETE_DATA_BACKUP*" \) \
        -newer /proc/1/cmdline -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | awk '{print $1}' || true)"
      if [[ -z "$newest_data" ]]; then
        # fallback: just mtime of the directory itself
        newest_data="$(stat -c '%Y' "$backup_data_dir" 2>/dev/null || true)"
      fi
      if [[ "$newest_data" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
        last_data_backup="$(date -u -d "@${newest_data%%.*}" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || true)"
      fi
    fi

    if [[ -d "$backup_log_dir" ]]; then
      local newest_log
      newest_log="$(find "$backup_log_dir" -maxdepth 3 -type f \
        -printf '%T@ %p\n' 2>/dev/null | sort -rn | head -1 | awk '{print $1}' || true)"
      if [[ "$newest_log" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
        last_log_backup="$(date -u -d "@${newest_log%%.*}" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || true)"
      fi
    fi
  fi

  backup_json="$(printf '{"data_backup_dir":"%s","log_backup_dir":"%s","last_data_backup":"%s","last_log_backup":"%s"}' \
    "$(json_escape "$backup_data_dir")" \
    "$(json_escape "$backup_log_dir")" \
    "$(json_escape "$last_data_backup")" \
    "$(json_escape "$last_log_backup")")"

  # --- Volume sizes from /hana mountpoints ---
  local data_size_gb=0 log_size_gb=0 shared_size_gb=0
  if command -v df >/dev/null 2>&1; then
    local df_data df_log df_shared
    df_data="$(df -BG "/hana/data" 2>/dev/null | awk 'NR==2{gsub(/G/,"",$2); print $2}' || echo 0)"
    df_log="$(df -BG "/hana/log" 2>/dev/null | awk 'NR==2{gsub(/G/,"",$2); print $2}' || echo 0)"
    df_shared="$(df -BG "/hana/shared" 2>/dev/null | awk 'NR==2{gsub(/G/,"",$2); print $2}' || echo 0)"
    [[ "$df_data" =~ ^[0-9]+$ ]] && data_size_gb=$df_data
    [[ "$df_log" =~ ^[0-9]+$ ]] && log_size_gb=$df_log
    [[ "$df_shared" =~ ^[0-9]+$ ]] && shared_size_gb=$df_shared
  fi
  volumes_json="$(printf '{"hana_data_gb":%s,"hana_log_gb":%s,"hana_shared_gb":%s}' \
    "$data_size_gb" "$log_size_gb" "$shared_size_gb")"

  printf '{"available":true,"sid":"%s","services":%s,"backup":%s,"volumes":%s}' \
    "$(json_escape "$sid")" \
    "$services_json" \
    "$backup_json" \
    "$volumes_json"
}

collect_cron_json() {
  local root_crontab_content="" root_crontab_lines=0 root_crontab_error="" root_crontab_available=false
  local cron_d_files_json="" cron_d_file_count=0 cron_d_available=false cron_d_error=""

  # root crontab
  if command -v crontab >/dev/null 2>&1; then
    local raw_crontab
    raw_crontab="$(crontab -u root -l 2>&1 || true)"
    if printf '%s\n' "$raw_crontab" | grep -qiE 'no crontab for|crontab: (no |cannot |usage)'; then
      root_crontab_available=false
      root_crontab_error="$(json_escape "$raw_crontab")"
    else
      root_crontab_available=true
      root_crontab_content="$(json_escape "$raw_crontab")"
      root_crontab_lines="$(printf '%s\n' "$raw_crontab" | grep -cE '^[^#[:space:]]' || echo 0)"
      [[ "$root_crontab_lines" =~ ^[0-9]+$ ]] || root_crontab_lines=0
    fi
  else
    root_crontab_error="crontab command not found"
  fi

  # /etc/cron.d
  if [[ -d /etc/cron.d ]]; then
    cron_d_available=true
    local fname
    while IFS= read -r -d $'\0' fpath; do
      fname="$(basename "$fpath")"
      local fcontent
      fcontent="$(cat "$fpath" 2>/dev/null || true)"
      local fentry
      fentry="$(printf '{"name":"%s","content":"%s"}' \
        "$(json_escape "$fname")" \
        "$(json_escape "$fcontent")")"
      cron_d_files_json="$(append_json_entry "$cron_d_files_json" "$fentry")"
      cron_d_file_count=$((cron_d_file_count + 1))
    done < <(find /etc/cron.d -maxdepth 1 -type f ! -name '.*' -print0 2>/dev/null | sort -z)
  else
    cron_d_error="\/etc\/cron.d not found"
  fi

  printf '{"root_crontab":{"available":%s,"active_lines":%s,"content":"%s","error":"%s"},"cron_d":{"available":%s,"file_count":%s,"files":[%s],"error":"%s"}}' \
    "$root_crontab_available" \
    "$root_crontab_lines" \
    "$root_crontab_content" \
    "${root_crontab_error:-}" \
    "$cron_d_available" \
    "$cron_d_file_count" \
    "$cron_d_files_json" \
    "${cron_d_error:-}"
}

collect_dir_listings_json() {
  if [[ -z "${DIR_SCAN_PATHS:-}" ]]; then
    printf '{"available":false,"entries":[]}'
    return
  fi

  local all_entries=""
  local max_items="${DIR_SCAN_MAX_ITEMS:-50}"
  if ! [[ "$max_items" =~ ^[0-9]+$ ]] || [[ "$max_items" -lt 1 ]]; then
    max_items=50
  fi

  local pattern
  while IFS= read -r -d ':' pattern; do
    [[ -n "$pattern" ]] || continue

    local old_nullglob
    old_nullglob="$(shopt -p nullglob 2>/dev/null || echo 'shopt -u nullglob')"
    shopt -s nullglob
    local expanded_paths=()
    for expanded in $pattern; do
      [[ -d "$expanded" ]] && expanded_paths+=("$expanded")
    done
    eval "$old_nullglob" 2>/dev/null || true

    for dir_path in "${expanded_paths[@]}"; do
      local items_json=""
      local item_count=0
      local truncated=false

      while IFS= read -r item_path; do
        if [[ "$item_count" -ge "$max_items" ]]; then
          truncated=true
          break
        fi

        local item_name item_type size_bytes mtime_epoch mtime_iso
        item_name="$(basename "$item_path")"
        item_type="file"
        if [[ -L "$item_path" ]]; then
          item_type="link"
        elif [[ -d "$item_path" ]]; then
          item_type="dir"
        fi

        size_bytes="$(stat -c '%s' "$item_path" 2>/dev/null || echo 0)"
        [[ "$size_bytes" =~ ^[0-9]+$ ]] || size_bytes=0
        mtime_epoch="$(stat -c '%Y' "$item_path" 2>/dev/null || echo 0)"
        mtime_iso=""
        if [[ "$mtime_epoch" =~ ^[0-9]+$ ]] && [[ "$mtime_epoch" -gt 0 ]]; then
          mtime_iso="$(date -u -d "@$mtime_epoch" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "")"
        fi

        local item_entry
        item_entry="$(printf '{"name":"%s","type":"%s","size_bytes":%s,"modified_utc":"%s"}' \
          "$(json_escape "$item_name")" \
          "$(json_escape "$item_type")" \
          "$size_bytes" \
          "$(json_escape "$mtime_iso")")"

        items_json="$(append_json_entry "$items_json" "$item_entry")"
        item_count=$((item_count + 1))
      done < <(find "$dir_path" -maxdepth 1 -mindepth 1 2>/dev/null | sort)

      local dir_entry
      dir_entry="$(printf '{"pattern":"%s","path":"%s","item_count":%s,"truncated":%s,"items":[%s]}' \
        "$(json_escape "$pattern")" \
        "$(json_escape "$dir_path")" \
        "$item_count" \
        "$truncated" \
        "$items_json")"

      all_entries="$(append_json_entry "$all_entries" "$dir_entry")"
    done
  done <<< "${DIR_SCAN_PATHS}:"

  if [[ -z "$all_entries" ]]; then
    printf '{"available":false,"entries":[]}'
  else
    printf '{"available":true,"entries":[%s]}' "$all_entries"
  fi
}

collect_dir_deep_listings_json() {
  # For each glob-expanded path: list subdirs, show N newest items per subdir
  # Auto-detect known backup structures if DIR_SCAN_DEEP_PATHS is not configured
  local effective_paths="${DIR_SCAN_DEEP_PATHS:-}"
  if [[ -z "$effective_paths" ]]; then
    local auto_paths=""
    # SAP HANA backup_service standard path
    # Find directories at any depth (up to 4 levels) whose name contains the
    # hostname (case-insensitive), then scan one level inside each match.
    if [[ -d "/hana/shared/backup_service/backups" ]]; then
      local _hn_lc
      _hn_lc="$(echo "${HOSTNAME_VALUE:-$(hostname -f 2>/dev/null || hostname)}" | tr '[:upper:]' '[:lower:]')"
      while IFS= read -r -d '' _candidate; do
        local _dir_lc
        _dir_lc="$(basename "$_candidate" | tr '[:upper:]' '[:lower:]')"
        if [[ "$_dir_lc" == *"$_hn_lc"* ]]; then
          if [[ -n "$auto_paths" ]]; then
            auto_paths="${auto_paths}:${_candidate}/*"
          else
            auto_paths="${_candidate}/*"
          fi
        fi
      done < <(find "/hana/shared/backup_service/backups" -mindepth 1 -maxdepth 4 -type d -print0 2>/dev/null)
    fi
    if [[ -n "$auto_paths" ]]; then
      # Persist to agent.conf so it shows up in the dashboard config view
      # and can be overridden manually from there on
      upsert_config_value "DIR_SCAN_DEEP_PATHS" "$auto_paths"
      DIR_SCAN_DEEP_PATHS="$auto_paths"
    fi
    effective_paths="$auto_paths"
  fi

  if [[ -z "$effective_paths" ]]; then
    printf '{"available":false,"entries":[]}'
    return
  fi

  local all_entries=""
  local max_items="${DIR_SCAN_DEEP_MAX_ITEMS:-5}"
  if ! [[  "$max_items" =~ ^[0-9]+$ ]] || [[ "$max_items" -lt 1 ]]; then
    max_items=5
  fi

  local pattern
  while IFS= read -r -d ':' pattern; do
    [[ -n "$pattern" ]] || continue

    local old_nullglob
    old_nullglob="$(shopt -p nullglob 2>/dev/null || echo 'shopt -u nullglob')"
    shopt -s nullglob
    local expanded_paths=()
    for expanded in $pattern; do
      [[ -d "$expanded" ]] && expanded_paths+=("$expanded")
    done
    eval "$old_nullglob" 2>/dev/null || true

    for dir_path in "${expanded_paths[@]}"; do
      local subdirs_json=""
      local scan_timeout="${DIR_SCAN_DEEP_TIMEOUT_SEC:-15}"
      local item_maxdepth="${DIR_SCAN_DEEP_ITEM_MAX_DEPTH:-2}"
      if ! [[ "$item_maxdepth" =~ ^[0-9]+$ ]] || [[ "$item_maxdepth" -lt 1 ]]; then
        item_maxdepth=2
      fi

      # Also include files directly inside the matched directory so
      # flat backup layouts (without per-run subdirectories) are visible.
      local root_items_json=""
      local root_find_cmd=(find "$dir_path" -maxdepth 1 -mindepth 1 ! -type d -printf '%T@\t%s\t%y\t%P\n')
      local root_find_raw
      if command -v timeout >/dev/null 2>&1 && [[ "$scan_timeout" =~ ^[0-9]+$ ]] && [[ "$scan_timeout" -gt 0 ]]; then
        root_find_raw="$(timeout "$scan_timeout" "${root_find_cmd[@]}" 2>/dev/null | sort -t$'\t' -k1 -rn || true)"
      else
        root_find_raw="$(${root_find_cmd[*]} 2>/dev/null | sort -t$'\t' -k1 -rn || true)"
      fi

      local root_total_count root_zip_total_count root_zip_latest_modified_utc
      if [[ -z "$root_find_raw" ]]; then
        root_total_count=0
        root_zip_total_count=0
        root_zip_latest_modified_utc=""
      else
        root_total_count="$(printf '%s\n' "$root_find_raw" | grep -c . || echo 0)"
        [[ "$root_total_count" =~ ^[0-9]+$ ]] || root_total_count=0
        root_zip_total_count="$(printf '%s\n' "$root_find_raw" | awk -F'\t' 'tolower($4) ~ /\.zip$/ { c++ } END { print c+0 }' 2>/dev/null || echo 0)"
        [[ "$root_zip_total_count" =~ ^[0-9]+$ ]] || root_zip_total_count=0
        root_zip_latest_modified_utc="$(printf '%s\n' "$root_find_raw" | awk -F'\t' 'tolower($4) ~ /\.zip$/ { print $1; exit }' 2>/dev/null || echo "")"
        if [[ -n "$root_zip_latest_modified_utc" ]]; then
          local _root_zip_epoch
          _root_zip_epoch="${root_zip_latest_modified_utc%%.*}"
          if [[ "$_root_zip_epoch" =~ ^[0-9]+$ ]] && [[ "$_root_zip_epoch" -gt 0 ]]; then
            root_zip_latest_modified_utc="$(date -u -d "@$_root_zip_epoch" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "")"
          else
            root_zip_latest_modified_utc=""
          fi
        fi
      fi

      local root_zip_shown=0
      while IFS=$'\t' read -r mtime_raw size_bytes ftype fname; do
        [[ -n "$fname" ]] || continue
        [[ "${fname,,}" == *.zip ]] || continue
        if [[ "$root_zip_shown" -ge "$max_items" ]]; then
          break
        fi
        local item_type mtime_epoch_int mtime_iso item_entry
        case "$ftype" in
          l) item_type="link" ;;
          *) item_type="file" ;;
        esac
        [[ "$size_bytes" =~ ^[0-9]+$ ]] || size_bytes=0
        mtime_epoch_int="${mtime_raw%%.*}"
        mtime_iso=""
        if [[ "$mtime_epoch_int" =~ ^[0-9]+$ ]] && [[ "$mtime_epoch_int" -gt 0 ]]; then
          mtime_iso="$(date -u -d "@$mtime_epoch_int" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "")"
        fi
        item_entry="$(printf '{"name":"%s","type":"%s","size_bytes":%s,"modified_utc":"%s"}' \
          "$(json_escape "$fname")" \
          "$(json_escape "$item_type")" \
          "$size_bytes" \
          "$(json_escape "$mtime_iso")")"
        root_items_json="$(append_json_entry "$root_items_json" "$item_entry")"
        root_zip_shown=$((root_zip_shown + 1))
      done < <(printf '%s\n' "$root_find_raw")

      if [[ "$root_total_count" -gt 0 ]]; then
        local root_entry
        root_entry="$(printf '{"name":"_root_files","path":"%s","item_count_total":%s,"zip_item_count_total":%s,"zip_latest_modified_utc":"%s","items":[%s]}' \
          "$(json_escape "$dir_path")" \
          "$root_total_count" \
          "$root_zip_total_count" \
          "$(json_escape "$root_zip_latest_modified_utc")" \
          "$root_items_json")"
        subdirs_json="$(append_json_entry "$subdirs_json" "$root_entry")"
      fi

      while IFS= read -r subdir_path; do
        local subdir_name total_count zip_total_count zip_latest_modified_utc items_json
        subdir_name="$(basename "$subdir_path")"
        items_json=""

        # Single find pass: get mtime, size, type, name — tab-separated.
        # %T@ = mtime epoch (float), %s = size bytes, %y = type (f/d/l), %P = name only (no path).
        # Scan recursively (default depth 2) so nested backup ZIP files are visible.
        local find_cmd=(find "$subdir_path" -maxdepth "$item_maxdepth" -mindepth 1 -printf '%T@\t%s\t%y\t%P\n')
        local find_raw
        if command -v timeout >/dev/null 2>&1 && [[ "$scan_timeout" =~ ^[0-9]+$ ]] && [[ "$scan_timeout" -gt 0 ]]; then
          find_raw="$(timeout "$scan_timeout" "${find_cmd[@]}" 2>/dev/null | sort -t$'\t' -k1 -rn || true)"
        else
          find_raw="$(${find_cmd[*]} 2>/dev/null | sort -t$'\t' -k1 -rn || true)"
        fi

        if [[ -z "$find_raw" ]]; then
          total_count=0
          zip_total_count=0
          zip_latest_modified_utc=""
        else
          total_count="$(printf '%s\n' "$find_raw" | grep -c . || echo 0)"
          [[ "$total_count" =~ ^[0-9]+$ ]] || total_count=0
          zip_total_count="$(printf '%s\n' "$find_raw" | awk -F'\t' 'tolower($4) ~ /\.zip$/ { c++ } END { print c+0 }' 2>/dev/null || echo 0)"
          [[ "$zip_total_count" =~ ^[0-9]+$ ]] || zip_total_count=0
          zip_latest_modified_utc="$(printf '%s\n' "$find_raw" | awk -F'\t' 'tolower($4) ~ /\.zip$/ { print $1; exit }' 2>/dev/null || echo "")"
          if [[ -n "$zip_latest_modified_utc" ]]; then
            local _zip_epoch
            _zip_epoch="${zip_latest_modified_utc%%.*}"
            if [[ "$_zip_epoch" =~ ^[0-9]+$ ]] && [[ "$_zip_epoch" -gt 0 ]]; then
              zip_latest_modified_utc="$(date -u -d "@$_zip_epoch" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "")"
            else
              zip_latest_modified_utc=""
            fi
          fi
        fi

        local zip_shown=0
        while IFS=$'\t' read -r mtime_raw size_bytes ftype fname; do
          [[ -n "$fname" ]] || continue
          [[ "${fname,,}" == *.zip ]] || continue
          if [[ "$zip_shown" -ge "$max_items" ]]; then
            break
          fi
          local item_type mtime_epoch_int mtime_iso item_entry
          case "$ftype" in
            d) item_type="dir" ;;
            l) item_type="link" ;;
            *) item_type="file" ;;
          esac
          [[ "$size_bytes" =~ ^[0-9]+$ ]] || size_bytes=0
          mtime_epoch_int="${mtime_raw%%.*}"
          mtime_iso=""
          if [[ "$mtime_epoch_int" =~ ^[0-9]+$ ]] && [[ "$mtime_epoch_int" -gt 0 ]]; then
            mtime_iso="$(date -u -d "@$mtime_epoch_int" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "")"
          fi
          item_entry="$(printf '{"name":"%s","type":"%s","size_bytes":%s,"modified_utc":"%s"}' \
            "$(json_escape "$fname")" \
            "$(json_escape "$item_type")" \
            "$size_bytes" \
            "$(json_escape "$mtime_iso")")"
          items_json="$(append_json_entry "$items_json" "$item_entry")"
          zip_shown=$((zip_shown + 1))
        done < <(printf '%s\n' "$find_raw")

        local subdir_entry
        subdir_entry="$(printf '{"name":"%s","path":"%s","item_count_total":%s,"zip_item_count_total":%s,"zip_latest_modified_utc":"%s","items":[%s]}' \
          "$(json_escape "$subdir_name")" \
          "$(json_escape "$subdir_path")" \
          "$total_count" \
          "$zip_total_count" \
          "$(json_escape "$zip_latest_modified_utc")" \
          "$items_json")"
        subdirs_json="$(append_json_entry "$subdirs_json" "$subdir_entry")"
      done < <(find "$dir_path" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | sort)

      local dir_entry
      dir_entry="$(printf '{"pattern":"%s","path":"%s","subdirs":[%s]}' \
        "$(json_escape "$pattern")" \
        "$(json_escape "$dir_path")" \
        "$subdirs_json")"
      all_entries="$(append_json_entry "$all_entries" "$dir_entry")"
    done
  done <<< "${effective_paths}:"

  if [[ -z "$all_entries" ]]; then
    printf '{"available":false,"entries":[]}'
  else
    printf '{"available":true,"entries":[%s]}' "$all_entries"
  fi
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

# Migration fallback: clear old static backup glob so hostname-aware
# auto-detection can rebuild DIR_SCAN_DEEP_PATHS.
if [[ "${DIR_SCAN_DEEP_PATHS:-}" == "/hana/shared/backup_service/backups/*/*" ]]; then
  DIR_SCAN_DEEP_PATHS=""
  upsert_config_value "DIR_SCAN_DEEP_PATHS" ""
fi

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
  local recurring_update_hours="${UPDATE_HOURS:-1}"

  if ! [[ "$recurring_update_hours" =~ ^[0-9]+$ ]]; then
    recurring_update_hours=1
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
  local canonical_update_base_url="https://infoboard.ang-schweiz.ch/updates"
  local secondary_update_base_url="https://infoboard.an-group.work/updates"
  local legacy_update_base_url="https://monitoring.rolfwalker.ch/updates"
  local update_base_url="${UPDATE_BASE_URL:-}"
  local update_base_candidates=()
  local tmp_updater=""
  local candidate=""
  local curl_args=(--silent --show-error --fail --connect-timeout "$CURL_CONNECT_TIMEOUT_SEC" --max-time "$CURL_MAX_TIME_SEC")

  add_update_candidate() {
    local value="${1:-}"
    value="${value%/}"
    [[ -z "$value" ]] && return
    local existing
    for existing in "${update_base_candidates[@]:-}"; do
      [[ "$existing" == "$value" ]] && return
    done
    update_base_candidates+=("$value")
  }

  if [[ "$TLS_INSECURE" == "1" ]]; then
    curl_args+=(--insecure)
  fi

  add_update_candidate "$canonical_update_base_url"
  add_update_candidate "$secondary_update_base_url"
  add_update_candidate "$legacy_update_base_url"
  add_update_candidate "$update_base_url"

  if [[ -z "$update_base_url" && -n "${SERVER_URL:-}" ]]; then
    update_base_url="${SERVER_URL%/}/updates"
  fi
  if [[ -z "$update_base_url" && -n "${RAW_BASE_URL:-}" ]]; then
    update_base_url="$RAW_BASE_URL"
  fi
  add_update_candidate "$update_base_url"
  if [[ -n "${SERVER_URL:-}" ]]; then
    add_update_candidate "${SERVER_URL%/}/updates"
  fi
  add_update_candidate "${RAW_BASE_URL:-}"

  if [[ "${#update_base_candidates[@]}" -gt 0 ]]; then
    for candidate in "${update_base_candidates[@]}"; do
      tmp_updater="$(mktemp)"
      if curl "${curl_args[@]}" "$candidate/client/linux/self_update.sh" -o "$tmp_updater" 2>/dev/null; then
        chmod 0755 "$tmp_updater"
        if CONFIG_FILE="$CONFIG_FILE" AGENT_VERSION_FILE="$AGENT_VERSION_FILE" "$tmp_updater" >> "$UPDATE_LOG_FILE" 2>&1; then
          rm -f "$tmp_updater"
          return 0
        fi
      fi
      [[ -n "$tmp_updater" ]] && rm -f "$tmp_updater"
    done
  fi

  if [[ -x "$updater_path" ]]; then
    CONFIG_FILE="$CONFIG_FILE" AGENT_VERSION_FILE="$AGENT_VERSION_FILE" "$updater_path" >> "$UPDATE_LOG_FILE" 2>&1
    return $?
  fi

  return 127
}

get_update_failure_hint() {
  if [[ ! -r "$UPDATE_LOG_FILE" ]]; then
    return
  fi

  tail -n 50 "$UPDATE_LOG_FILE" 2>/dev/null \
    | grep -Ei 'failed|error|exception|blocked|invalid|unsupported|abort|not found|cannot' \
    | tail -n 1 \
    | sed 's/[[:space:]]\+/ /g; s/^ //; s/ $//'
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
    message="${line:25}"
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

    _py_ver="$(python3 -c 'import sys; print("%d%02d" % sys.version_info[:2])' 2>/dev/null || echo 0)"
    if [[ "$_py_ver" -lt 306 ]]; then
    printf '{"enabled":true,"status":"unavailable","error":"python3 >= 3.6 required","filesystems":[]}'
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
    python3 - <<'PY'
import datetime as dt
import heapq
import json
import os
import pwd
import stat
import subprocess
import time


def to_int(name, default, minimum=0, maximum=10**9):
  raw = os.getenv(name, str(default)).strip()
  try:
    value = int(raw)
  except Exception:
    value = default
  return max(minimum, min(value, maximum))


def utc_now_iso():
  return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(value):
  text = str(value or "").strip()
  if not text:
    return None
  try:
    text = text.replace("Z", "").split("+")[0]
    naive = dt.datetime.strptime(text, "%Y-%m-%dT%H:%M:%S")
    return naive.replace(tzinfo=dt.timezone.utc)
  except Exception:
    return None


def is_under(path, prefix):
  if not prefix:
    return False
  p = os.path.normpath(path)
  pref = os.path.normpath(prefix)
  return p == pref or p.startswith(pref + os.sep)


def collect_mountpoints():
  mounts = []
  pseudo_fs = {
    "autofs", "bpf", "cgroup", "cgroup2", "configfs", "debugfs", "devpts", "devtmpfs",
    "fusectl", "hugetlbfs", "mqueue", "overlay", "proc", "pstore", "rpc_pipefs", "securityfs",
    "selinuxfs", "squashfs", "sysfs", "tmpfs", "tracefs",
  }

  # Preferred source: kernel mount table, independent of df output format quirks.
  try:
    with open("/proc/self/mountinfo", "r", encoding="utf-8", errors="replace") as fh:
      for line in fh:
        line = line.rstrip("\n")
        if not line:
          continue
        if " - " not in line:
          continue
        left, right = line.split(" - ", 1)
        left_parts = left.split()
        right_parts = right.split()
        if len(left_parts) < 5 or len(right_parts) < 3:
          continue
        mountpoint = left_parts[4].replace("\\040", " ").replace("\\011", "\t")
        fstype = right_parts[0]
        source = right_parts[1]
        if fstype in pseudo_fs:
          continue
        if source in {"none", "rootfs"}:
          continue
        if mountpoint.startswith("/proc") or mountpoint.startswith("/sys") or mountpoint.startswith("/dev"):
          continue
        mounts.append(mountpoint)
  except Exception:
    pass

  if not mounts:
    try:
      output = subprocess.check_output(["df", "-P"], text=True, stderr=subprocess.DEVNULL)
      for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 6:
          mounts.append(parts[-1])
    except Exception:
      pass

  if not mounts and os.path.isdir("/"):
    mounts.append("/")

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
  local curl_metrics=""
  local curl_exit=0
  local curl_error_file
  local http_code="000"
  local time_total="0"
  local time_connect="0"

  backup_payload_snapshot "$payload_data"

  curl_args=(
    --silent
    --show-error
    --fail
    --connect-timeout "$CURL_CONNECT_TIMEOUT_SEC"
    --max-time "$CURL_MAX_TIME_SEC"
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

  curl_error_file="$(mktemp)"
  curl_metrics="$(curl "${curl_args[@]}" -o /dev/null -w "%{http_code}|%{time_total}|%{time_connect}" "${SERVER_URL%/}/api/v1/agent-report" 2>"$curl_error_file")"
  curl_exit=$?

  if [[ -s "$curl_error_file" ]]; then
    cat "$curl_error_file" >&2
  fi
  rm -f "$curl_error_file"

  if [[ "$curl_metrics" == *"|"* ]]; then
    http_code="${curl_metrics%%|*}"
    local rest="${curl_metrics#*|}"
    time_total="${rest%%|*}"
    time_connect="${rest#*|}"
  fi


  POST_LAST_HTTP_CODE="$http_code"
  POST_LAST_CURL_EXIT="$curl_exit"
  echo "Payload delivery metrics: http_code=$http_code total_sec=$time_total connect_sec=$time_connect curl_exit=$curl_exit" >&2
  return "$curl_exit"
}


queue_file_is_client_error() {
  local curl_exit="$1"
  local http_code="$2"
  if [[ "$curl_exit" == "22" ]] && [[ "$http_code" =~ ^4[0-9][0-9]$ ]]; then
    return 0
  fi
  return 1
}

quarantine_queue_file() {
  local file="$1"
  local reason="$2"
  local stamp target base_name

  base_name="$(basename "$file")"
  stamp="$(date -u +"%Y%m%dT%H%M%SZ")"
  target="$AGENT_QUEUE_QUARANTINE_DIR/${base_name%.json}-${stamp}-${RANDOM}.bad.json"

  if mv -f -- "$file" "$target" 2>/dev/null; then
    echo "Quarantined queue payload: file=$file target=$target reason=$reason" >&2
    return 0
  fi

  echo "Failed to quarantine queue payload, deleting to unblock queue: file=$file reason=$reason" >&2
  rm -f -- "$file"
  return 0
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
    --connect-timeout "$CURL_CONNECT_TIMEOUT_SEC"
    --max-time "$CURL_MAX_TIME_SEC"
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
    --connect-timeout "$CURL_CONNECT_TIMEOUT_SEC"
    --max-time "$CURL_MAX_TIME_SEC"
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
          hint="$(get_update_failure_hint)"
          if [[ -x "${INSTALL_DIR:-/opt/monitoring-agent}/self_update.sh" ]]; then
            status="failed"
            message="update command failed"
          else
            status="failed"
            message="self_update.sh not found"
          fi
          if [[ -n "$hint" ]]; then
            message="$message | $hint"
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
    if ! payload_data="$(cat "$file" 2>/dev/null)"; then
      quarantine_queue_file "$file" "read_error"
      continue
    fi

    if post_payload "$payload_data" >/dev/null; then
      rm -f "$file"
    elif queue_file_is_client_error "${POST_LAST_CURL_EXIT:-1}" "${POST_LAST_HTTP_CODE:-000}"; then
      quarantine_queue_file "$file" "server_http_${POST_LAST_HTTP_CODE}"
    else
      # Keep remaining queue files for the next run when connectivity recovers.
      return 1
    fi
  done

  return 0
}

HOSTNAME_VALUE="$(hostname -f 2>/dev/null || hostname)"
PRIMARY_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i=="src") {print $(i+1); exit}}')"
HOST_UID_NIC_NAME="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1; i<=NF; i++) if ($i=="dev") {print $(i+1); exit}}')"
HOST_UID_NIC_MAC=""
if [[ -n "$HOST_UID_NIC_NAME" ]] && [[ -r "/sys/class/net/${HOST_UID_NIC_NAME}/address" ]]; then
  HOST_UID_NIC_MAC="$(tr '[:upper:]' '[:lower:]' < "/sys/class/net/${HOST_UID_NIC_NAME}/address" 2>/dev/null | tr -d '[:space:]')"
fi
ALL_IPS="$(hostname -I 2>/dev/null | xargs || true)"
TIMESTAMP_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
UPTIME_SECONDS="$(cut -d. -f1 /proc/uptime)"
KERNEL="$(uname -r)"
OS_NAME="$(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}")"
AGENT_ID_VALUE="${AGENT_ID:-$HOSTNAME_VALUE}"
DISPLAY_NAME_VALUE="${DISPLAY_NAME:-$HOSTNAME_VALUE}"
HOST_UID_VALUE="${HOST_UID:-}"
if [[ -z "$HOST_UID_VALUE" ]]; then
  MACHINE_ID_VALUE="$(tr -d '[:space:]' < /etc/machine-id 2>/dev/null || true)"
  if [[ -z "$MACHINE_ID_VALUE" ]]; then
    MACHINE_ID_VALUE="$(tr -d '[:space:]' < /var/lib/dbus/machine-id 2>/dev/null || true)"
  fi

  if [[ -n "$MACHINE_ID_VALUE" ]]; then
    if [[ -n "$HOST_UID_NIC_MAC" ]]; then
      HOST_UID_VALUE="${HOSTNAME_VALUE}::mid:${MACHINE_ID_VALUE}::mac:${HOST_UID_NIC_MAC}"
    else
      HOST_UID_VALUE="${HOSTNAME_VALUE}::mid:${MACHINE_ID_VALUE}"
    fi
  elif [[ -n "$AGENT_ID_VALUE" ]]; then
    HOST_UID_VALUE="${HOSTNAME_VALUE}::agent:${AGENT_ID_VALUE}"
  elif [[ -n "$PRIMARY_IP" ]]; then
    HOST_UID_VALUE="${HOSTNAME_VALUE}::ip:${PRIMARY_IP}"
  else
    HOST_UID_VALUE="$HOSTNAME_VALUE"
  fi
fi
AGENT_VERSION_VALUE="unknown"
if [[ -f "$AGENT_VERSION_FILE" ]]; then
  AGENT_VERSION_VALUE="$(head -n 1 "$AGENT_VERSION_FILE" | tr -d '[:space:]')"
fi

read -r LOAD_AVG_1 LOAD_AVG_5 LOAD_AVG_15 _ < /proc/loadavg
CPU_USAGE_PERCENT="$(calc_cpu_usage_percent)"
CPU_CORES="$(nproc 2>/dev/null || echo 1)"
# CPU model name (first line from /proc/cpuinfo)
CPU_MODEL_NAME="$(awk -F: '/^model name/ {gsub(/^ +/, "", $2); print $2; exit}' /proc/cpuinfo 2>/dev/null || echo unknown)"

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
SAP_LICENSE_JSON="$(collect_sap_license_json)"
SAP_BUSINESS_ONE_JSON="$(collect_sap_business_one_json)"
HANA_INFO_JSON="$(collect_hana_version_json)"
HANA_ADDONS_JSON="$(collect_hana_addons_json)"
HANA_DB_INFO_JSON="$(collect_hana_db_info_json)"
HANA_MULTITENANT_DISCOVERY_JSON="$(collect_hana_multitenant_discovery_json)"
DIR_LISTINGS_JSON="$(collect_dir_listings_json)"
DIR_DEEP_LISTINGS_JSON="$(collect_dir_deep_listings_json)"
CRON_INFO_JSON="$(collect_cron_json)"
SEND_STARTED_UTC="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

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
  "host_uid": "$(json_escape "$HOST_UID_VALUE")",
  "primary_ip": "$(json_escape "$PRIMARY_IP")",
  "all_ips": "$(json_escape "$ALL_IPS")",
  "kernel": "$(json_escape "$KERNEL")",
  "os": "$(json_escape "$OS_NAME")",
  "uptime_seconds": $UPTIME_SECONDS,
  "timestamp_utc": "$(json_escape "$TIMESTAMP_UTC")",
  "send_started_utc": "$(json_escape "$SEND_STARTED_UTC")",
  "delivery_mode": "live",
  "is_delayed": false,
  "queued_at_utc": "",
  "queue_depth": $QUEUE_DEPTH_NOW,
  "cpu": {
    "usage_percent": $CPU_USAGE_PERCENT,
    "load_avg_1": $LOAD_AVG_1,
    "load_avg_5": $LOAD_AVG_5,
    "load_avg_15": $LOAD_AVG_15,
    "cores": $CPU_CORES,
    "model_name": "$(json_escape "$CPU_MODEL_NAME")"
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
  "large_files": ${LARGE_FILES_JSON},
  "sap_license": ${SAP_LICENSE_JSON},
  "sap_business_one": ${SAP_BUSINESS_ONE_JSON},
  "hana_info": ${HANA_INFO_JSON},
  "hana_addons": ${HANA_ADDONS_JSON},
  "hana_db_info": ${HANA_DB_INFO_JSON},
  "hana_multitenant_discovery": ${HANA_MULTITENANT_DISCOVERY_JSON},
  "dir_listings": ${DIR_LISTINGS_JSON},
  "dir_deep_listings": ${DIR_DEEP_LISTINGS_JSON},
  "cron_info": ${CRON_INFO_JSON}
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

