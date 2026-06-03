#!/usr/bin/env bash
# Watch changelog inventur/rebuild job progress (run on infoboard).
# Usage: watch-inventur-job.sh [job_id]
#        watch-inventur-job.sh --once [job_id]
set -euo pipefail

DB="${MONITORING_DB_PATH:-/root/monitoring-server/server/data/monitoring.db}"
SERVER_DIR="${MONITORING_SERVER_DIR:-/root/monitoring-server}"
SCRIPT="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || realpath "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")"

ONCE=0
JOB_ID=""
for arg in "$@"; do
  if [ "$arg" = "--once" ]; then
    ONCE=1
  elif [ -z "$JOB_ID" ]; then
    JOB_ID="$arg"
  fi
done

if [ ! -f "$DB" ]; then
  echo "DB nicht gefunden: $DB" >&2
  exit 1
fi

show_status() {
  date -u '+%Y-%m-%d %H:%M:%S UTC'
  if [ -n "$JOB_ID" ]; then
    sqlite3 -header -column "$DB" <<SQL
SELECT id, status,
       json_extract(result_json,'$.progress.phase') AS phase,
       json_extract(result_json,'$.progress.reports_scanned') AS reports,
       json_extract(result_json,'$.progress.reports_total') AS total,
       json_extract(result_json,'$.progress.inserted_changes') AS cfg,
       json_extract(result_json,'$.progress.current_host') AS host,
       json_extract(result_json,'$.progress.updated_at_utc') AS updated
FROM changelog_rebuild_jobs
WHERE id = ${JOB_ID};
SQL
  else
    sqlite3 -header -column "$DB" <<'SQL'
SELECT id, status,
       json_extract(result_json,'$.progress.phase') AS phase,
       json_extract(result_json,'$.progress.reports_scanned') AS reports,
       json_extract(result_json,'$.progress.reports_total') AS total,
       json_extract(result_json,'$.progress.inserted_changes') AS cfg,
       json_extract(result_json,'$.progress.current_host') AS host,
       json_extract(result_json,'$.progress.updated_at_utc') AS updated
FROM changelog_rebuild_jobs
ORDER BY id DESC
LIMIT 3;
SQL
  fi
  echo "BUILD_VERSION: $(tr -d ' \t\r\n' < "$SERVER_DIR/BUILD_VERSION" 2>/dev/null || echo '?')"
}

if [ "$ONCE" -eq 1 ]; then
  show_status
  exit 0
fi

watch -n 5 "$SCRIPT" --once ${JOB_ID:+"$JOB_ID"}
