#!/usr/bin/env bash
set -euo pipefail

OWNER_REPO="rolfwalker71-commits/monitoring"
GITHUB_TOKEN="${MONITORING_GITHUB_TOKEN:-${GITHUB_TOKEN:-${GH_TOKEN:-}}}"
GITHUB_API_BASE="https://api.github.com/repos/$OWNER_REPO"

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
TARGET_ENV_FILE="$TARGET_DIR/monitoring.env"

if [ -z "$GITHUB_TOKEN" ] && [ -f "$TARGET_ENV_FILE" ]; then
  # shellcheck disable=SC1090
  source "$TARGET_ENV_FILE"
  GITHUB_TOKEN="${MONITORING_GITHUB_TOKEN:-${GITHUB_TOKEN:-${GH_TOKEN:-}}}"
fi

curl_github() {
  local accept_header="${1:-application/vnd.github+json}"
  shift || true
  if [ -n "$GITHUB_TOKEN" ]; then
    curl -fsSL --retry 5 --retry-delay 1 \
      -H "Authorization: Bearer $GITHUB_TOKEN" \
      -H "Accept: $accept_header" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      -H "User-Agent: monitoring-pull-server-only" \
      "$@"
  else
    curl -fsSL --retry 5 --retry-delay 1 \
      -H "Accept: $accept_header" \
      -H "User-Agent: monitoring-pull-server-only" \
      "$@"
  fi
}

download_repo_file() {
  local source_path="$1"
  local target_path="$2"
  local api_url="$GITHUB_API_BASE/contents/$source_path?ref=$REF"
  local api_url_main="$GITHUB_API_BASE/contents/$source_path?ref=main"
  mkdir -p "$(dirname "$target_path")"

  if [ -n "$GITHUB_TOKEN" ]; then
    # Prefer pinned ref, then fallback to main if GitHub API returns not found.
    curl_github "application/vnd.github.raw" "$api_url" -o "$target_path" \
      || curl_github "application/vnd.github.raw" "$api_url_main" -o "$target_path"
  else
    curl_github "application/octet-stream" "$RAW_BASE/$source_path" -o "$target_path"
  fi
}

print_private_repo_hint() {
  cat >&2 <<'EOF'
Private GitHub repo detected or anonymous access blocked.
Provide a token via one of these variables before running pull-server-only.sh:
  export MONITORING_GITHUB_TOKEN=ghp_xxx
  export GITHUB_TOKEN=ghp_xxx
  export GH_TOKEN=ghp_xxx

Alternative: store MONITORING_GITHUB_TOKEN in monitoring.env on the server.
EOF
}

echo "Installiere Serverteil nach: $TARGET_DIR"

# Speed/strictness tuning:
# - VERIFY_SYNC=1 enables costly re-download + hash verification.
# - MAX_PARALLEL_DOWNLOADS controls concurrent downloads.
VERIFY_SYNC="${VERIFY_SYNC:-0}"
MAX_PARALLEL_DOWNLOADS="${MAX_PARALLEL_DOWNLOADS:-8}"

mkdir -p "$TARGET_DIR/server/static/icons" "$TARGET_DIR/server/data" "$TARGET_DIR/updates/client/windows" "$TARGET_DIR/updates/client/linux"

if ! COMMIT_META_JSON="$(curl_github "application/vnd.github+json" "$GITHUB_API_BASE/commits/main")"; then
  echo "Konnte Commit-Metadaten von GitHub nicht laden." >&2
  if [ -z "$GITHUB_TOKEN" ]; then
    print_private_repo_hint
  fi
  exit 1
fi

SHA=""
if command -v python3 >/dev/null 2>&1; then
  SHA="$(printf '%s\n' "$COMMIT_META_JSON" | python3 -c 'import json,sys; print((json.load(sys.stdin) or {}).get("sha", ""))' 2>/dev/null || true)"
fi
if [ -z "$SHA" ]; then
  SHA="$(printf '%s\n' "$COMMIT_META_JSON" \
    | awk 'match($0, /"sha"[[:space:]]*:[[:space:]]*"[0-9a-f]{40}"/) { m=substr($0, RSTART, RLENGTH); sub(/^.*"/, "", m); sub(/"$/, "", m); print m; exit }')"
fi

GITHUB_COMMIT_ISO="$(printf '%s\n' "$COMMIT_META_JSON" \
  | sed -n 's/.*"date":[[:space:]]*"\([0-9T:\-]\+Z\)".*/\1/p' \
  | head -n 1)"

GITHUB_COMMIT_TIME=""
if [ -n "$GITHUB_COMMIT_ISO" ]; then
  GITHUB_COMMIT_TIME="$(date -u -d "$GITHUB_COMMIT_ISO" '+%d.%m.%y %H:%M UTC' 2>/dev/null || date -u -j -f '%Y-%m-%dT%H:%M:%SZ' "$GITHUB_COMMIT_ISO" '+%d.%m.%y %H:%M UTC' 2>/dev/null || echo "")"
fi

if [ -z "$SHA" ]; then
  echo "Konnte Commit-SHA nicht ermitteln." >&2
  exit 1
fi

REF="$SHA"
RAW_BASE="https://raw.githubusercontent.com/$OWNER_REPO/$SHA"

# Hilfsfunction fuer parallele downloads
download_file() {
    local source_path="$1"
    local target_path="$2"
  if download_repo_file "$source_path" "$target_path"; then
    local file_size_bytes=""
    local file_size_human=""
    file_size_bytes="$(wc -c < "$target_path" 2>/dev/null | tr -d ' ' || echo "")"
    if [ -n "$file_size_bytes" ] && [ "$file_size_bytes" -ge 1024 ] 2>/dev/null; then
      file_size_human="$(awk -v b="$file_size_bytes" 'BEGIN { printf "%.1f KiB", (b / 1024) }')"
    elif [ -n "$file_size_bytes" ]; then
      file_size_human="${file_size_bytes} B"
    fi

    if [ -n "$GITHUB_COMMIT_TIME" ] && [ -n "$file_size_human" ]; then
      echo "✓ $source_path [GitHub: $GITHUB_COMMIT_TIME | $file_size_human]"
    elif [ -n "$GITHUB_COMMIT_TIME" ]; then
      echo "✓ $source_path [GitHub: $GITHUB_COMMIT_TIME]"
    elif [ -n "$file_size_human" ]; then
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

verify_synced_file() {
  local source_path="$1"
  local target_path="$2"
  local tmp_verify
  local local_hash
  local remote_hash

  if [ ! -f "$target_path" ]; then
    echo "✗ VERIFY: $source_path (lokale Datei fehlt: $target_path)" >&2
    return 1
  fi

  tmp_verify="$(mktemp)"
  if ! download_repo_file "$source_path" "$tmp_verify"; then
    echo "✗ VERIFY: $source_path (Remote-Download fehlgeschlagen)" >&2
    rm -f "$tmp_verify"
    return 1
  fi

  if ! local_hash="$(checksum_file "$target_path")"; then
    echo "✗ VERIFY: $source_path (kein sha256sum/shasum verfuegbar)" >&2
    rm -f "$tmp_verify"
    return 1
  fi
  if ! remote_hash="$(checksum_file "$tmp_verify")"; then
    echo "✗ VERIFY: $source_path (Remote-Hash fehlgeschlagen)" >&2
    rm -f "$tmp_verify"
    return 1
  fi

  rm -f "$tmp_verify"

  if [ "$local_hash" = "$remote_hash" ]; then
    echo "✓ VERIFY: $source_path"
    return 0
  fi

  echo "✗ VERIFY: $source_path (Hash-Mismatch)" >&2
  return 1
}

export -f download_file download_repo_file checksum_file curl_github
export RAW_BASE TARGET_DIR GITHUB_COMMIT_TIME GITHUB_TOKEN GITHUB_API_BASE SHA REF OWNER_REPO

FILES_LIST="
server/receiver.py
server/static/index.html
server/static/app.js
server/static/styles.css
server/static/ui-next.html
server/static/ui-next.css
server/static/ui-next.js
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
client/linux/install_agent.sh
client/linux/self_update.sh
"

# Parallele downloads: standardmaessig bis zu 8 gleichzeitig
FILE_COUNT="$(printf '%s\n' "$FILES_LIST" | sed '/^$/d' | wc -l | tr -d ' ')"
echo "Lade ${FILE_COUNT} Dateien parallel (max ${MAX_PARALLEL_DOWNLOADS} gleichzeitig)..."
if ! printf '%s\n' "$FILES_LIST" | sed '/^$/d' | xargs -P "$MAX_PARALLEL_DOWNLOADS" -I {} bash -c 'download_file "{}" "$TARGET_DIR/{}"'; then
  echo "Fehler bei parallelen Downloads" >&2
  exit 1
fi
echo "Dateien geladen ✓"

if [ "$VERIFY_SYNC" = "1" ]; then
  echo "Pruefe heruntergeladene Dateien gegen gepinnten Commit (VERIFY_SYNC=1)..."
  VERIFY_ERRORS=0
  while IFS= read -r source_path; do
    [ -n "$source_path" ] || continue
    if ! verify_synced_file "$source_path" "$TARGET_DIR/$source_path"; then
      VERIFY_ERRORS=$((VERIFY_ERRORS + 1))
    fi
  done < <(printf '%s\n' "$FILES_LIST" | sed '/^$/d')

  if [ "$VERIFY_ERRORS" -gt 0 ]; then
    echo "Verifikation fehlgeschlagen: $VERIFY_ERRORS Datei(en) stimmen nicht mit dem gepinnten Commit ueberein." >&2
    exit 1
  fi
  echo "Verifikation erfolgreich ✓ Alle Dateien entsprechen Commit $SHA"
else
  echo "Verifikation uebersprungen (VERIFY_SYNC=0, Standard fuer schnellen Pull)"
fi

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
cp -f "$TARGET_DIR/client/linux/install_agent.sh" "$TARGET_DIR/updates/client/linux/install_agent.sh"
cp -f "$TARGET_DIR/client/linux/self_update.sh" "$TARGET_DIR/updates/client/linux/self_update.sh"
chmod 0755 "$TARGET_DIR/updates/client/linux/collect_and_send.sh" "$TARGET_DIR/updates/client/linux/install_agent.sh" "$TARGET_DIR/updates/client/linux/self_update.sh"

# Selbst-Update: erst am Ende austauschen, damit das laufende Skript nicht waehrend
# des Parsens ueberschrieben wird.
NEW_PULL_SCRIPT="$TARGET_DIR/pull-server-only.sh.new"
if download_file "pull-server-only.sh" "$NEW_PULL_SCRIPT"; then
  chmod +x "$NEW_PULL_SCRIPT"
  mv -f "$NEW_PULL_SCRIPT" "$TARGET_DIR/pull-server-only.sh"
  echo "Self-Update abgeschlossen: pull-server-only.sh aktualisiert"
else
  echo "WARNUNG: Konnte neue pull-server-only.sh nicht laden." >&2
fi

ICONS_API="$GITHUB_API_BASE/contents/server/static/icons?ref=$SHA"
TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

ICONS_JSON="$TMP_DIR/icons.json"
if ! curl_github "application/vnd.github+json" "$ICONS_API" -o "$ICONS_JSON"; then
  echo "Konnte die Icon-Liste von GitHub nicht laden." >&2
  if [ -z "$GITHUB_TOKEN" ]; then
    print_private_repo_hint
  fi
  exit 1
fi

ICON_NAMES_FILE="$TMP_DIR/icon_names.txt"
grep -o '"name":[[:space:]]*"[^"]*\.png"' "$ICONS_JSON" \
  | cut -d '"' -f 4 \
  | sort -u > "$ICON_NAMES_FILE"

if [ ! -s "$ICON_NAMES_FILE" ]; then
  echo "Keine PNG-Icons geladen (Liste war leer oder ungeeignet)." >&2
  exit 1
fi

ICON_COUNT="$(wc -l < "$ICON_NAMES_FILE" | tr -d ' ')"
echo "Lade ${ICON_COUNT} PNG-Icons parallel..."
if ! sed 's#^#server/static/icons/#' "$ICON_NAMES_FILE" | xargs -P "$MAX_PARALLEL_DOWNLOADS" -I {} bash -c 'download_file "{}" "$TARGET_DIR/{}"'; then
  echo "Fehler bei Icon-Downloads (nicht kritisch)" >&2
fi
echo "Icons geladen ✓"
echo "$SHA" > "$TARGET_DIR/DEPLOYED_COMMIT_SHA"
DEPLOY_TIME="$(date '+%d.%m.%y %H:%M')"

LATEST_META_AFTER="$(curl_github "application/vnd.github+json" "$GITHUB_API_BASE/commits/main" || true)"
LATEST_SHA_AFTER="$(printf '%s\n' "$LATEST_META_AFTER" \
  | sed -n 's/.*"sha":[[:space:]]*"\([0-9a-f]\{40\}\)".*/\1/p' \
  | head -n 1)"

DEPLOYED_SHA_FILE="$(cat "$TARGET_DIR/DEPLOYED_COMMIT_SHA" 2>/dev/null || true)"

if [ -n "$GITHUB_COMMIT_TIME" ]; then
  echo "Fertig. Deploy-Commit: $SHA [GitHub: $GITHUB_COMMIT_TIME | Deploy: $DEPLOY_TIME]"
else
  echo "Fertig. Deploy-Commit: $SHA [Deploy: $DEPLOY_TIME]"
fi

if [ -n "$LATEST_SHA_AFTER" ] && [ "$DEPLOYED_SHA_FILE" = "$LATEST_SHA_AFTER" ]; then
  echo "Commit-Status: AKTUELL (deployter Commit entspricht repo/main)"
elif [ -n "$LATEST_SHA_AFTER" ]; then
  echo "Commit-Status: NICHT AKTUELL (deployt=$DEPLOYED_SHA_FILE, repo/main=$LATEST_SHA_AFTER)"
else
  echo "Commit-Status: UNBEKANNT (konnte latest main SHA nicht ermitteln)"
fi

echo -n "BUILD_VERSION lokal: "
cat "$TARGET_DIR/BUILD_VERSION"
echo -n "AGENT_VERSION lokal: "
cat "$TARGET_DIR/AGENT_VERSION"
ls -ld "$TARGET_DIR/server"

# --- venv sicherstellen ---
if [ ! -x "$TARGET_DIR/.venv/bin/python" ]; then
    echo "Erstelle Python-venv in $TARGET_DIR/.venv ..."
    python3 -m venv "$TARGET_DIR/.venv"
fi
if command -v apt-get >/dev/null 2>&1; then
  echo "Installiere Systembibliothek libcairo2 (falls noetig) ..."
  if ! apt-get install -y libcairo2 >/dev/null 2>&1; then
    echo "WARNUNG: libcairo2 konnte nicht automatisch installiert werden."
    echo "         PNG-Chart-Rendering faellt ggf. auf SVG zurueck."
  fi
fi
echo "Installiere/aktualisiere Python-Abhaengigkeiten ..."
"$TARGET_DIR/.venv/bin/pip" install --quiet --upgrade cairosvg

# --- EnvironmentFile anlegen (nur wenn noch nicht vorhanden) ---
ENV_FILE="$TARGET_DIR/monitoring.env"
if [ ! -f "$ENV_FILE" ]; then
    cat > "$ENV_FILE" <<'EOF'
# Monitoring Server – Umgebungsvariablen
# Diese Datei bleibt nur auf dem Server und kommt NIE ins Git!
MONITORING_API_KEY=HIER_API_KEY_EINTRAGEN
MONITORING_API_KEY_GRACE_ALLOW_KNOWN_HOSTS=0
MONITORING_GITHUB_TOKEN=HIER_GITHUB_TOKEN_EINTRAGEN
# MONITORING_SCHEDULE_TIMEZONE=Europe/Zurich
EOF
    chmod 600 "$ENV_FILE"
    echo "EnvironmentFile angelegt: $ENV_FILE"
    echo "  --> Bitte API-Key und GitHub-Token dort eintragen!"
else
    echo "EnvironmentFile bereits vorhanden: $ENV_FILE (unveraendert)"
fi

# --- systemd Service installieren/aktualisieren ---
SERVICE_FILE="/etc/systemd/system/monitoring.service"
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Monitoring Receiver
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$TARGET_DIR
EnvironmentFile=$TARGET_DIR/monitoring.env
ExecStart=$TARGET_DIR/.venv/bin/python $TARGET_DIR/server/receiver.py --host 0.0.0.0 --port 8080
Restart=on-failure
RestartSec=5
StandardOutput=append:$TARGET_DIR/server/data/receiver.log
StandardError=append:$TARGET_DIR/server/data/receiver.log

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable monitoring

echo ""
echo "systemd Service installiert: $SERVICE_FILE"

echo "Versuche monitoring-Service neu zu starten ..."
if systemctl restart monitoring; then
  echo "✓ monitoring wurde neu gestartet"
  systemctl --no-pager --full status monitoring | sed -n '1,14p' || true
else
  echo "✗ monitoring konnte nicht automatisch neu gestartet werden" >&2
  echo "  Bitte manuell ausführen: systemctl restart monitoring" >&2
fi

echo ""
echo "Nächste Schritte (falls nötig):"
echo "  1. API-Key prüfen:     nano $ENV_FILE"
echo "  2. Service-Status:     systemctl status monitoring"
