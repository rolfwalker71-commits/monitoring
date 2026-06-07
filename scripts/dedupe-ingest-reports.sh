#!/usr/bin/env bash
# Entfernt Ingest-Duplikate aus monitoring.db (gleicher Host, received_at_utc, payload).
# Auf infoboard: sudo systemctl stop monitoring && ./scripts/dedupe-ingest-reports.sh --analyze
# Dann: ./scripts/dedupe-ingest-reports.sh --run && sudo systemctl start monitoring
set -euo pipefail

SCRIPT_VERSION="20260608a"
DRY_RUN=0
RUN=0
ANALYZE=0
DB_PATH="${MONITORING_DB_PATH:-}"

usage() {
  cat <<'EOF'
Usage: dedupe-ingest-reports.sh [--analyze] [--dry-run] [--run] [--db PATH]

  --analyze   Nur Duplikat-Kennzahlen anzeigen (Standard wenn kein --run)
  --dry-run   Wie --analyze über API-Logik (keine Löschung)
  --run       Duplikate löschen (monitoring-Dienst vorher stoppen empfohlen)
  --db PATH   SQLite-Datei (Default: aus monitoring.service / server/data/monitoring.db)
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --analyze) ANALYZE=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    --run) RUN=1; shift ;;
    --db) DB_PATH="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unbekanntes Argument: $1" >&2; usage >&2; exit 1 ;;
  esac
done

if [ -z "$DB_PATH" ]; then
  SERVICE_FILE="/etc/systemd/system/monitoring.service"
  if [ -f "$SERVICE_FILE" ]; then
    WORKDIR=$(grep -E '^WorkingDirectory=' "$SERVICE_FILE" | head -1 | cut -d= -f2- | tr -d ' ')
    DB_PATH="${WORKDIR}/server/data/monitoring.db"
  else
    DB_PATH="$(cd "$(dirname "$0")/.." && pwd)/server/data/monitoring.db"
  fi
fi

if [ ! -f "$DB_PATH" ]; then
  echo "DB nicht gefunden: $DB_PATH" >&2
  exit 1
fi

if [ "$RUN" -eq 0 ] && [ "$DRY_RUN" -eq 0 ] && [ "$ANALYZE" -eq 0 ]; then
  ANALYZE=1
fi

HOST_KEY="COALESCE(NULLIF(host_uid, ''), hostname)"

run_analyze() {
  sqlite3 -header -column "$DB_PATH" <<SQL
SELECT COUNT(*) AS reports_total FROM reports;
SELECT
  COUNT(*) AS duplicate_groups,
  COALESCE(SUM(group_count - 1), 0) AS redundant_rows,
  COALESCE(MAX(group_count), 0) AS max_group_size
FROM (
  SELECT COUNT(*) AS group_count
  FROM reports
  GROUP BY ${HOST_KEY}, received_at_utc, payload_json
  HAVING group_count > 1
);
SQL
  echo
  ls -lh "$DB_PATH" "${DB_PATH}-wal" 2>/dev/null || ls -lh "$DB_PATH"
}

if [ "$ANALYZE" -eq 1 ] || [ "$DRY_RUN" -eq 1 ]; then
  echo "=== Duplikat-Analyse ($DB_PATH) ==="
  run_analyze
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "Dry-run: keine Änderungen."
  fi
  exit 0
fi

echo "=== Duplikat-Bereinigung ($DB_PATH) ==="
run_analyze
echo
read -r -p "Duplikate jetzt löschen? [y/N] " confirm
if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
  echo "Abgebrochen."
  exit 0
fi

python3 - "$DB_PATH" <<'PY'
import sqlite3
import sys

db_path = sys.argv[1]
host_key = "COALESCE(NULLIF(host_uid, ''), hostname)"
batch_size = 2000

conn = sqlite3.connect(db_path, timeout=120)
conn.execute("PRAGMA busy_timeout = 120000")
deleted = 0

while True:
    rows = conn.execute(
        f"""
        WITH ranked AS (
            SELECT id,
                   ROW_NUMBER() OVER (
                       PARTITION BY {host_key}, received_at_utc, payload_json
                       ORDER BY id ASC
                   ) AS rn
            FROM reports
        )
        SELECT id FROM ranked WHERE rn > 1 ORDER BY id ASC LIMIT ?
        """,
        (batch_size,),
    ).fetchall()
    if not rows:
        break
    ids = [int(r[0]) for r in rows]
    ph = ",".join("?" * len(ids))
    conn.execute(f"UPDATE alerts SET report_id = NULL WHERE report_id IN ({ph})", ids)
    conn.execute(f"DELETE FROM host_config_changes WHERE report_id IN ({ph})", ids)
    conn.execute(f"DELETE FROM database_lifecycle WHERE report_id IN ({ph})", ids)
    conn.execute(f"DELETE FROM reports WHERE id IN ({ph})", ids)
    conn.commit()
    deleted += len(ids)
    print(f"deleted batch: {len(ids)} (total {deleted})", flush=True)

conn.close()
print(f"Fertig. Gelöschte Zeilen: {deleted}")
PY

echo
echo "=== Nach Bereinigung ==="
run_analyze
echo
echo "Empfehlung: monitoring starten, Admin → VACUUM ausführen, um Speicher zurückzugewinnen."
