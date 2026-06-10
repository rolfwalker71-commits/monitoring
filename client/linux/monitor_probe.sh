#!/usr/bin/env bash
# Lightweight internal service probe — separate from the monitoring agent.
# Fetches push-monitors from the server, checks them locally, pushes results back.
set -euo pipefail

CONFIG_FILE="${CONFIG_FILE:-/etc/monitoring-probe/probe.conf}"
INTERVAL_SEC="${INTERVAL_SEC:-300}"
RUN_ONCE="${RUN_ONCE:-0}"

if [[ -f "$CONFIG_FILE" ]]; then
  # shellcheck source=/dev/null
  source "$CONFIG_FILE"
fi

SERVER_URL="${SERVER_URL:-}"
PROBE_TOKEN="${PROBE_TOKEN:-}"
TLS_INSECURE="${TLS_INSECURE:-0}"

if [[ -z "$SERVER_URL" || -z "$PROBE_TOKEN" ]]; then
  echo "SERVER_URL and PROBE_TOKEN required (config: $CONFIG_FILE)" >&2
  exit 1
fi

CURL_ARGS=(--fail --silent --show-error --location --connect-timeout 10 --max-time 45)
if [[ "$TLS_INSECURE" == "1" ]]; then
  CURL_ARGS+=(--insecure)
fi

probe_log() {
  printf '%s %s\n' "$(date +"%d.%m.%Y %H:%M:%S" 2>/dev/null || date)" "$*"
}

fetch_config() {
  local request_body
  request_body="$(PROBE_TOKEN_VALUE="${PROBE_TOKEN}" python3 -c 'import json,os; print(json.dumps({"probe_token": os.environ["PROBE_TOKEN_VALUE"]}, separators=(",", ":")))')"
  curl "${CURL_ARGS[@]}" \
    -X POST \
    -H "X-Probe-Token: ${PROBE_TOKEN}" \
    -H "Authorization: Bearer ${PROBE_TOKEN}" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    --data-binary "$request_body" \
    "${SERVER_URL%/}/api/v1/external-monitor-probe/config"
}

push_results() {
  local payload="$1"
  local wrapped_payload endpoint encoding
  for encoding in b64 plain; do
    if [[ "$encoding" == "b64" ]]; then
      wrapped_payload="$(PROBE_TOKEN_VALUE="${PROBE_TOKEN}" PAYLOAD_JSON="${payload}" python3 -c 'import base64,json,os; raw=json.loads(os.environ["PAYLOAD_JSON"]); results=raw.get("results") or []; outer={"probe_token": os.environ["PROBE_TOKEN_VALUE"], "results_b64": base64.b64encode(json.dumps(results, separators=(",", ":")).encode()).decode()}; print(json.dumps(outer, separators=(",", ":")))')"
    else
      wrapped_payload="$(PROBE_TOKEN_VALUE="${PROBE_TOKEN}" PAYLOAD_JSON="${payload}" python3 -c 'import json,os; raw=json.loads(os.environ["PAYLOAD_JSON"]); print(json.dumps({"probe_token": os.environ["PROBE_TOKEN_VALUE"], **raw}, separators=(",", ":")))')"
    fi
    for endpoint in \
      "${SERVER_URL%/}/api/v1/external-monitor-probe/config" \
      "${SERVER_URL%/}/api/v1/external-monitor-probe/push"; do
      if curl "${CURL_ARGS[@]}" \
        -X POST \
        -H "X-Probe-Token: ${PROBE_TOKEN}" \
        -H "Authorization: Bearer ${PROBE_TOKEN}" \
        -H "Content-Type: application/json" \
        --data-binary "$wrapped_payload" \
        "$endpoint"; then
        return 0
      fi
      probe_log "Push via ${endpoint} (${encoding}) failed, trying next transport..."
    done
  done
  return 1
}

check_http_monitor() {
  local monitor_id="$1"
  local target_url="$2"
  local expected_status="$3"
  local keyword="$4"
  local timeout_sec="$5"
  local tls_verify="${6:-1}"
  local url="$target_url"
  if [[ "$url" != http://* && "$url" != https://* ]]; then
    url="https://${url}"
  fi
  local started end elapsed http_code body_file status error_msg response_ms
  local -a request_args=("${CURL_ARGS[@]}")
  if [[ "$url" == https://* ]]; then
    request_args+=(--insecure)
  elif [[ "$tls_verify" == "0" ]]; then
    request_args+=(--insecure)
  fi
  started=$(date +%s)
  body_file="$(mktemp)"
  set +e
  http_code=$(curl "${request_args[@]}" --max-time "$timeout_sec" -o "$body_file" -w '%{http_code}' "$url")
  curl_exit=$?
  set -e
  end=$(date +%s)
  response_ms=$(( (end - started) * 1000 ))
  status="up"
  error_msg=""
  if [[ $curl_exit -ne 0 ]]; then
    status="down"
    error_msg="curl exit ${curl_exit}"
  elif [[ -n "$expected_status" && "$http_code" != "$expected_status" ]]; then
    status="down"
    error_msg="expected HTTP ${expected_status}, got ${http_code}"
  elif [[ -n "$keyword" ]] && ! grep -q -- "$keyword" "$body_file"; then
    status="down"
    error_msg="keyword not found"
  fi
  rm -f "$body_file"
  printf '{"monitor_id":%s,"status":"%s","response_ms":%s,"http_status":%s,"error_message":"%s"}' \
    "$monitor_id" "$status" "$response_ms" "${http_code:-null}" "$(printf '%s' "$error_msg" | sed 's/"/\\"/g')"
}

check_tcp_monitor() {
  local monitor_id="$1"
  local target="$2"
  local timeout_sec="$3"
  local host port
  if [[ "$target" == *"://"* ]]; then
    host="$(printf '%s' "$target" | sed -E 's#^[a-zA-Z]+://([^/:]+).*#\1#')"
    port="$(printf '%s' "$target" | sed -nE 's#^[a-zA-Z]+://[^/:]+:([0-9]+).*#\1#p')"
    [[ -z "$port" ]] && port=443
  else
    host="${target%%:*}"
    port="${target##*:}"
  fi
  local started end response_ms status error_msg
  started=$(date +%s)
  if timeout "$timeout_sec" bash -c "echo >/dev/tcp/${host}/${port}" 2>/dev/null; then
    status="up"
    error_msg=""
  else
    status="down"
    error_msg="tcp connect failed"
  fi
  end=$(date +%s)
  response_ms=$(( (end - started) * 1000 ))
  printf '{"monitor_id":%s,"status":"%s","response_ms":%s,"http_status":null,"error_message":"%s"}' \
    "$monitor_id" "$status" "$response_ms" "$(printf '%s' "$error_msg" | sed 's/"/\\"/g')"
}

run_probe_cycle() {
  local config_json monitor_count idx monitor_id monitor_type target_url expected_status keyword timeout_sec result_parts
  config_json="$(fetch_config)"
  monitor_count=$(printf '%s' "$config_json" | python3 -c 'import json,sys; data=json.load(sys.stdin); print(len(data.get("monitors") or []))')
  if [[ "$monitor_count" -le 0 ]]; then
    probe_log "No push monitors assigned."
    return 0
  fi
  result_parts=()
  while IFS=$'\t' read -r monitor_id monitor_type target_url expected_status keyword timeout_sec tls_verify; do
    case "$monitor_type" in
      tcp)
        result_parts+=("$(check_tcp_monitor "$monitor_id" "$target_url" "$timeout_sec")")
        ;;
      http|ssl_cert|*)
        result_parts+=("$(check_http_monitor "$monitor_id" "$target_url" "$expected_status" "$keyword" "$timeout_sec" "$tls_verify")")
        ;;
    esac
  done < <(printf '%s' "$config_json" | python3 -c 'import json,sys
data=json.load(sys.stdin)
for m in data.get("monitors") or []:
    tls_verify = 1 if m.get("tls_verify", True) else 0
    print(
        m.get("id", 0),
        m.get("monitor_type", "http"),
        m.get("target_url", ""),
        "" if m.get("expected_status") is None else m.get("expected_status"),
        m.get("keyword", "") or "",
        m.get("timeout_sec", 15) or 15,
        tls_verify,
        sep="\t",
    )')
  local payload
  payload=$(printf '{"results":[%s]}' "$(IFS=,; echo "${result_parts[*]}")")
  push_results "$payload" >/dev/null
  probe_log "Pushed ${#result_parts[@]} result(s)."
}

probe_log "monitor_probe starting (server=${SERVER_URL}, interval=${INTERVAL_SEC}s)"
while true; do
  if ! run_probe_cycle; then
    probe_log "Probe cycle failed."
  fi
  if [[ "$RUN_ONCE" == "1" ]]; then
    break
  fi
  sleep "$INTERVAL_SEC"
done
