#!/usr/bin/env bash
# Monatliche Gesundheitsprüfung für SQLite vs. Postgres Entscheidung.
# Auf infoboard ausführen: ./scripts/check-monitoring-health.sh
# Optional: --json für maschinenlesbare Ausgabe
set -euo pipefail

SCRIPT_VERSION="20260602a"
JSON_MODE=0
PERF_HOURS=24

usage() {
  cat <<'EOF'
Usage: check-monitoring-health.sh [--json] [--perf-hours N]

Misst DB-Größe, RAM, langsame API-Endpoints und leitet einen Trigger-Score ab
(Plan A SQLite vs. Plan B Postgres).

Umgebungsvariablen:
  MONITORING_SERVER_DIR   Repo/Installationspfad (Default: aus monitoring.service)
  MONITORING_DB_PATH      SQLite-Datei (Default: $SERVER_DIR/server/data/monitoring.db)
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --json)
      JSON_MODE=1
      shift
      ;;
    --perf-hours)
      PERF_HOURS="${2:-24}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unbekanntes Argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

detect_server_dir() {
  if [ -n "${MONITORING_SERVER_DIR:-}" ]; then
    printf '%s\n' "$MONITORING_SERVER_DIR"
    return 0
  fi
  if [ -f /etc/systemd/system/monitoring.service ]; then
    local unit_dir
    unit_dir="$(sed -n 's/^WorkingDirectory=//p' /etc/systemd/system/monitoring.service | tail -n 1)"
    if [ -n "$unit_dir" ]; then
      printf '%s\n' "$unit_dir"
      return 0
    fi
  fi
  if [ -d /root/monitoring-server/server ]; then
    printf '%s\n' "/root/monitoring-server"
    return 0
  fi
  local script_dir
  script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)"
  if [ -d "$script_dir/server" ]; then
    printf '%s\n' "$script_dir"
    return 0
  fi
  return 1
}

bytes_to_gb() {
  awk -v b="${1:-0}" 'BEGIN { printf "%.2f", b / 1024 / 1024 / 1024 }'
}

mb_available() {
  free -m | awk '/^Mem:/ { print $7 }'
}

mem_total_mb() {
  free -m | awk '/^Mem:/ { print $2 }'
}

swap_total_mb() {
  free -m | awk '/^Swap:/ { print $2 }'
}

score_label() {
  case "$1" in
    0) printf 'gruen' ;;
    1) printf 'gelb' ;;
    2) printf 'rot' ;;
    *) printf 'unbekannt' ;;
  esac
}

decision_text() {
  local total="$1"
  if [ "$total" -le 2 ]; then
    printf 'Plan A — SQLite weiter optimieren'
  elif [ "$total" -le 5 ]; then
    printf 'Beobachten — SQLite + Postgres Phase 1 vorbereiten'
  else
    printf 'Plan B — Postgres-Migration priorisieren'
  fi
}

SERVER_DIR="$(detect_server_dir || true)"
if [ -z "${SERVER_DIR:-}" ]; then
  echo "FEHLER: Installationspfad nicht gefunden. Setze MONITORING_SERVER_DIR." >&2
  exit 1
fi

DB_PATH="${MONITORING_DB_PATH:-$SERVER_DIR/server/data/monitoring.db}"
DATA_DIR="$(dirname -- "$DB_PATH")"
PERF_LOG="${MONITORING_ENDPOINT_TIMING_FILE_LOG_PATH:-$DATA_DIR/endpoint_perf.log}"
BUILD_VERSION="$(tr -d ' \t\r\n' < "$SERVER_DIR/BUILD_VERSION" 2>/dev/null || echo '?')"

# --- DB size (bytes) ---
DB_BYTES=0
if [ -f "$DB_PATH" ]; then
  for f in "$DB_PATH" "$DB_PATH-wal" "$DB_PATH-shm"; do
    if [ -f "$f" ]; then
      sz=$(stat -c '%s' "$f" 2>/dev/null || echo 0)
      DB_BYTES=$((DB_BYTES + sz))
    fi
  done
else
  echo "WARNUNG: DB nicht gefunden: $DB_PATH" >&2
fi
DB_GB="$(bytes_to_gb "$DB_BYTES")"

DB_SCORE=0
if awk -v gb="$DB_GB" 'BEGIN { exit !(gb >= 6) }'; then
  DB_SCORE=2
elif awk -v gb="$DB_GB" 'BEGIN { exit !(gb >= 3) }'; then
  DB_SCORE=1
fi

# --- RAM ---
RAM_AVAIL_MB="$(mb_available)"
RAM_TOTAL_MB="$(mem_total_mb)"
SWAP_MB="$(swap_total_mb)"
RAM_SCORE=0
if [ "${RAM_AVAIL_MB:-0}" -lt 600 ]; then
  RAM_SCORE=2
elif [ "${RAM_AVAIL_MB:-0}" -lt 1200 ]; then
  RAM_SCORE=1
fi

# --- Reports total (maintenance snapshot) ---
REPORTS_TOTAL=""
REPORTS_SNAPSHOT_AT=""
if [ -f "$DB_PATH" ] && command -v sqlite3 >/dev/null 2>&1; then
  read -r REPORTS_TOTAL REPORTS_SNAPSHOT_AT < <(
    sqlite3 -separator $'\t' "$DB_PATH" \
      "SELECT COALESCE(reports_total, ''), COALESCE(computed_at_utc, '') FROM db_maintenance_history ORDER BY computed_at_utc DESC LIMIT 1;" \
      2>/dev/null || echo $'\t'
  )
fi
REPORTS_SCORE=0
if [ -n "${REPORTS_TOTAL:-}" ] && [ "${REPORTS_TOTAL:-0}" -gt 150000 ] 2>/dev/null; then
  REPORTS_SCORE=2
elif [ -n "${REPORTS_TOTAL:-}" ] && [ "${REPORTS_TOTAL:-0}" -gt 120000 ] 2>/dev/null; then
  REPORTS_SCORE=1
fi

# --- Slow endpoint latency (p95, ms) ---
PERF_TMP="$(mktemp)"
trap 'rm -f "$PERF_TMP"' EXIT

collect_perf_lines() {
  local since="${1}h"
  if [ -f "$PERF_LOG" ]; then
    grep '\[perf\]' "$PERF_LOG" 2>/dev/null || true
  fi
  if command -v journalctl >/dev/null 2>&1; then
    journalctl -u monitoring --since "$since" --no-pager 2>/dev/null | grep '\[perf\]' || true
  fi
}

collect_perf_lines "$PERF_HOURS" | grep -E 'hosts|reports|dashboard-db-kpis' > "$PERF_TMP" || true

LATENCY_P95_MS=""
LATENCY_SAMPLES=0
if [ -s "$PERF_TMP" ]; then
  LATENCY_P95_MS="$(
    grep -oE 'total=[0-9.]+' "$PERF_TMP" \
      | sed 's/total=//' \
      | sort -n \
      | awk '
        { a[NR] = $1 + 0 }
        END {
          if (NR == 0) { print ""; exit }
          idx = int((NR * 0.95) + 0.999999)
          if (idx < 1) idx = 1
          if (idx > NR) idx = NR
          printf "%.0f", a[idx]
        }'
  )"
  LATENCY_SAMPLES="$(grep -c '\[perf\]' "$PERF_TMP" 2>/dev/null || echo 0)"
fi

LATENCY_SCORE=0
if [ -n "${LATENCY_P95_MS:-}" ]; then
  if [ "$LATENCY_P95_MS" -gt 2000 ] 2>/dev/null; then
    LATENCY_SCORE=2
  elif [ "$LATENCY_P95_MS" -gt 500 ] 2>/dev/null; then
    LATENCY_SCORE=1
  fi
fi

TOTAL_SCORE=$((DB_SCORE + RAM_SCORE + REPORTS_SCORE + LATENCY_SCORE))
DECISION="$(decision_text "$TOTAL_SCORE")"
CHECKED_AT="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

if [ "$JSON_MODE" -eq 1 ]; then
  printf '{"script_version":"%s","checked_at_utc":"%s","build_version":"%s","server_dir":"%s","db_path":"%s","db_bytes":%s,"db_gb":%s,"db_score":%s,"ram_available_mb":%s,"ram_total_mb":%s,"swap_mb":%s,"ram_score":%s,"reports_total":%s,"reports_snapshot_at":"%s","reports_score":%s,"latency_p95_ms":%s,"latency_samples":%s,"latency_score":%s,"total_score":%s,"decision":"%s"}\n' \
    "$SCRIPT_VERSION" \
    "$CHECKED_AT" \
    "$BUILD_VERSION" \
    "$SERVER_DIR" \
    "$DB_PATH" \
    "${DB_BYTES:-0}" \
    "${DB_GB:-0}" \
    "$DB_SCORE" \
    "${RAM_AVAIL_MB:-0}" \
    "${RAM_TOTAL_MB:-0}" \
    "${SWAP_MB:-0}" \
    "$RAM_SCORE" \
    "${REPORTS_TOTAL:-null}" \
    "${REPORTS_SNAPSHOT_AT:-}" \
    "$REPORTS_SCORE" \
    "${LATENCY_P95_MS:-null}" \
    "${LATENCY_SAMPLES:-0}" \
    "$LATENCY_SCORE" \
    "$TOTAL_SCORE" \
    "$DECISION"
  exit 0
fi

cat <<EOF
Monitoring Health Check (v$SCRIPT_VERSION)
==========================================
Zeit (UTC):     $CHECKED_AT
BUILD_VERSION:  $BUILD_VERSION
Server-Verz.:   $SERVER_DIR
DB-Pfad:        $DB_PATH

Metrik                    Wert                    Score
-------------------------------------------------------
DB-Groesse (inkl. WAL)    ${DB_GB} GB (${DB_BYTES} B)   $(score_label "$DB_SCORE") ($DB_SCORE)
RAM verfuegbar            ${RAM_AVAIL_MB} MB / ${RAM_TOTAL_MB} MB   $(score_label "$RAM_SCORE") ($RAM_SCORE)
Swap                      ${SWAP_MB} MB             —
Berichte (Snapshot)       ${REPORTS_TOTAL:-?} (${REPORTS_SNAPSHOT_AT:-kein Snapshot})   $(score_label "$REPORTS_SCORE") ($REPORTS_SCORE)
API p95 (${PERF_HOURS}h)          ${LATENCY_P95_MS:-keine langsamen Samples} ms (${LATENCY_SAMPLES} Zeilen)   $(score_label "$LATENCY_SCORE") ($LATENCY_SCORE)

Scoring: gruen=0, gelb=1, rot=2  |  Summe: $TOTAL_SCORE / 8
Entscheidung: $DECISION

Hinweise:
  - Perf-Log: $PERF_LOG (nur Requests >= 250 ms)
  - Cold-Start und gleichzeitige Nutzer: manuell pruefen
  - Postgres bei Summe >= 6 oder 2 rote + DB > 4 GB
EOF

if [ "${SWAP_MB:-0}" -eq 0 ]; then
  echo "  - WARNUNG: Kein Swap konfiguriert — RAM-Spitzen ohne Puffer"
fi

if [ "$RAM_SCORE" -ge 1 ]; then
  echo "  - WARNUNG: Wenig freier RAM — Postgres-Migration auf diesem Host riskant"
fi

if [ ! -f "$DB_PATH" ]; then
  exit 1
fi
