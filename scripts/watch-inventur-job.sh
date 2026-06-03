#!/usr/bin/env bash
# Watch changelog inventur/rebuild job progress (run on infoboard).
set -euo pipefail

DB="${MONITORING_DB_PATH:-/root/monitoring-server/server/data/monitoring.db}"
JOB_ID="${1:-}"

if [ ! -f "$DB" ]; then
  echo "DB nicht gefunden: $DB" >&2
  exit 1
fi

watch -n 5 "
sqlite3 -header -column '$DB' \"
SELECT id, status,
       json_extract(result_json,'\\\$.progress.phase') AS phase,
       json_extract(result_json,'\\\$.progress.reports_scanned') AS reports,
       json_extract(result_json,'\\\$.progress.reports_total') AS total,
       json_extract(result_json,'\\\$.progress.inserted_changes') AS cfg,
       json_extract(result_json,'\\\$.progress.current_host') AS host,
       json_extract(result_json,'\\\$.progress.updated_at_utc') AS updated
FROM changelog_rebuild_jobs
$(if [ -n \"$JOB_ID\" ]; then echo \"WHERE id=$JOB_ID\"; else echo 'ORDER BY id DESC LIMIT 3'; fi);
\""
echo \"BUILD_VERSION: \$(tr -d ' \\t\\r\\n' < \"\${MONITORING_SERVER_DIR:-/root/monitoring-server}/BUILD_VERSION\" 2>/dev/null || echo '?')\"
