#!/usr/bin/env bash
set -euo pipefail

# Vereinfachte Version für öffentliche Repos
# Nutzt direkte raw.githubusercontent.com URLs ohne GitHub API und Token

OWNER_REPO="rolfwalker71-commits/monitoring"
BRANCH="main"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"

detect_target_dir() {
  if [ -n "${1:-}" ]; then
    printf '%s\n' "$1"
    return 0
  fi

  # Prefer the currently installed service path to avoid deploying into a wrong default directory.
  if [ -f "/etc/systemd/system/monitoring.service" ]; then
    local unit_dir
    unit_dir="$(sed -n 's/^WorkingDirectory=//p' /etc/systemd/system/monitoring.service | tail -n 1)"
    if [ -n "$unit_dir" ]; then
      printf '%s\n' "$unit_dir"
      return 0
    fi
  fi

  # Fallback: if script is executed from a checked-out repo, use that repo root.
  if [ -d "$SCRIPT_DIR/server" ] && [ -f "$SCRIPT_DIR/server/receiver.py" ]; then
    printf '%s\n' "$SCRIPT_DIR"
    return 0
  fi

  printf '%s\n' "$HOME/monitoring-server"
}

TARGET_DIR="$(detect_target_dir "${1:-}")"

RAW_BASE="https://raw.githubusercontent.com/$OWNER_REPO/$BRANCH"

echo "Installiere Serverteil nach: $TARGET_DIR"

mkdir -p "$TARGET_DIR/server/static/icons" "$TARGET_DIR/server/data" "$TARGET_DIR/updates/client/windows" "$TARGET_DIR/updates/client/linux"

# Hilfsfunction für parallele downloads
download_file() {
  local source_path="$1"
  local target_path="$2"
  local url="$RAW_BASE/$source_path"
  mkdir -p "$(dirname "$target_path")"

  if curl -fsSL --retry 5 --retry-delay 1 -o "$target_path" "$url"; then
    local file_size_bytes=""
    local file_size_human=""
    file_size_bytes="$(wc -c < "$target_path" 2>/dev/null | tr -d ' ' || echo "")"
    if [ -n "$file_size_bytes" ] && [ "$file_size_bytes" -ge 1024 ] 2>/dev/null; then
      file_size_human="$(awk -v b="$file_size_bytes" 'BEGIN { printf "%.1f KiB", (b / 1024) }')"
    elif [ -n "$file_size_bytes" ]; then
      file_size_human="${file_size_bytes} B"
    fi

    if [ -n "$file_size_human" ]; then
      echo "✓ $source_path [$file_size_human]"
    else
      echo "✓ $source_path"
    fi
  else
    echo "✗ FEHLER: $source_path" >&2
    return 1
  fi
}

checksum_file() {
  local file_path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file_path" | awk '{print $1}'
    return 0
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file_path" | awk '{print $1}'
    return 0
  fi
  return 1
}

FILES_LIST="
server/receiver.py
server/static/index.html
server/static/app.js
server/static/styles.css
BUILD_VERSION
AGENT_VERSION
openapi.yaml
client/windows/collect_and_send.ps1
client/windows/collect_and_scan_sap_tables.ps1
client/windows/bootstrap_agent.ps1
client/windows/install_agent.ps1
client/windows/self_update.ps1
client/windows/setup_harvest_sql_user.ps1
client/linux/collect_and_send.sh
client/linux/self_update.sh
"

# Parallele downloads: bis zu 4 gleichzeitig
FILE_COUNT="$(printf '%s\n' "$FILES_LIST" | sed '/^$/d' | wc -l | tr -d ' ')"
echo "Lade ${FILE_COUNT} Dateien parallel (max 4 gleichzeitig)..."

export -f download_file
export RAW_BASE TARGET_DIR

if ! printf '%s\n' "$FILES_LIST" | sed '/^$/d' | xargs -P 4 -I {} bash -c 'download_file "{}" "$TARGET_DIR/{}"'; then
  echo "Fehler bei parallelen Downloads" >&2
  exit 1
fi
echo "Dateien geladen ✓"

# Mirror update payloads to /updates so agents can update from SERVER_URL.
cp -f "$TARGET_DIR/BUILD_VERSION" "$TARGET_DIR/updates/BUILD_VERSION"
cp -f "$TARGET_DIR/AGENT_VERSION" "$TARGET_DIR/updates/AGENT_VERSION"
cp -f "$TARGET_DIR/client/windows/collect_and_send.ps1" "$TARGET_DIR/updates/client/windows/collect_and_send.ps1"
cp -f "$TARGET_DIR/client/windows/collect_and_scan_sap_tables.ps1" "$TARGET_DIR/updates/client/windows/collect_and_scan_sap_tables.ps1"
cp -f "$TARGET_DIR/client/windows/bootstrap_agent.ps1" "$TARGET_DIR/updates/client/windows/bootstrap_agent.ps1"
cp -f "$TARGET_DIR/client/windows/install_agent.ps1" "$TARGET_DIR/updates/client/windows/install_agent.ps1"
cp -f "$TARGET_DIR/client/windows/self_update.ps1" "$TARGET_DIR/updates/client/windows/self_update.ps1"
cp -f "$TARGET_DIR/client/windows/setup_harvest_sql_user.ps1" "$TARGET_DIR/updates/client/windows/setup_harvest_sql_user.ps1"
cp -f "$TARGET_DIR/client/linux/collect_and_send.sh" "$TARGET_DIR/updates/client/linux/collect_and_send.sh"
cp -f "$TARGET_DIR/client/linux/self_update.sh" "$TARGET_DIR/updates/client/linux/self_update.sh"
echo "Update-Payloads gespiegelt ✓"

echo "Installation erfolgreich abgeschlossen!"
