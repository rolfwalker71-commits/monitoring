#!/usr/bin/env bash
# Emergency: install script_guardian on monitoring server (bypasses stale pull / MAIN_HEAD_SHA).
# Usage: curl -fsSL .../scripts/deploy-agent-guardian.sh | bash -s /root/monitoring-server
set -euo pipefail

TARGET_DIR="${1:-/root/monitoring-server}"
OWNER_REPO="${MONITORING_OWNER_REPO:-rolfwalker71-commits/monitoring}"
# bbbf646 = 1.7.385 with script_guardian; override with MONITORING_DEPLOY_REF=main if needed
REF="${MONITORING_DEPLOY_REF:-bbbf64606a1250309ddfa69c620154320d46a74a}"
BASE="https://raw.githubusercontent.com/${OWNER_REPO}/${REF}"

if [ ! -d "$TARGET_DIR" ]; then
  echo "FEHLER: TARGET_DIR existiert nicht: $TARGET_DIR" >&2
  exit 1
fi

mkdir -p \
  "$TARGET_DIR/client/linux" \
  "$TARGET_DIR/client/windows" \
  "$TARGET_DIR/updates/client/linux" \
  "$TARGET_DIR/updates/client/windows"

fetch_one() {
  local rel="$1"
  local dest="$2"
  local url="$BASE/$rel"
  if ! curl -fsSL --connect-timeout 15 --max-time 120 "$url" -o "$dest"; then
    echo "FEHLER: Download fehlgeschlagen: $url" >&2
    exit 1
  fi
  echo "OK $dest ($(wc -c < "$dest" | tr -d ' ') bytes, ref ${REF:0:12})"
}

echo "Deploy Guardian -> $TARGET_DIR (ref ${REF:0:12})"

fetch_one "client/linux/script_guardian.sh" "$TARGET_DIR/client/linux/script_guardian.sh"
fetch_one "client/windows/script_guardian.ps1" "$TARGET_DIR/client/windows/script_guardian.ps1"
if curl -fsSL --connect-timeout 15 --max-time 120 "$BASE/client/linux/monitor_probe.sh" \
  -o "$TARGET_DIR/client/linux/monitor_probe.sh" 2>/dev/null; then
  chmod 0755 "$TARGET_DIR/client/linux/monitor_probe.sh"
  cp -f "$TARGET_DIR/client/linux/monitor_probe.sh" "$TARGET_DIR/updates/client/linux/monitor_probe.sh"
  chmod 0755 "$TARGET_DIR/updates/client/linux/monitor_probe.sh"
  echo "OK monitor_probe.sh"
else
  echo "WARN monitor_probe.sh nicht auf ref ${REF:0:12} (optional)" >&2
fi
chmod 0755 "$TARGET_DIR/client/linux/script_guardian.sh"

cp -f "$TARGET_DIR/client/linux/script_guardian.sh" "$TARGET_DIR/updates/client/linux/script_guardian.sh"
cp -f "$TARGET_DIR/client/windows/script_guardian.ps1" "$TARGET_DIR/updates/client/windows/script_guardian.ps1"
chmod 0755 "$TARGET_DIR/updates/client/linux/script_guardian.sh"

for f in \
  "$TARGET_DIR/client/linux/script_guardian.sh" \
  "$TARGET_DIR/updates/client/linux/script_guardian.sh" \
  "$TARGET_DIR/client/windows/script_guardian.ps1" \
  "$TARGET_DIR/updates/client/windows/script_guardian.ps1"; do
  if [ ! -s "$f" ]; then
    echo "FEHLER: Datei leer oder fehlt: $f" >&2
    exit 1
  fi
done

echo "Fertig. Test-URL (Pfad anpassen):"
echo "  .../updates/client/linux/script_guardian.sh"
