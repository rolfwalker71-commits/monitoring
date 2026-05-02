#!/usr/bin/env bash
set -euo pipefail

TARGET_DIR="${1:-$HOME/monitoring-server}"
OWNER_REPO="rolfwalker71-commits/monitoring"

echo "Installiere Serverteil nach: $TARGET_DIR"

mkdir -p "$TARGET_DIR/server/static/icons" "$TARGET_DIR/server/data"

SHA="$(curl -fsSL --retry 5 --retry-delay 1 "https://api.github.com/repos/$OWNER_REPO/commits/main" \
  | sed -n 's/.*"sha":[[:space:]]*"\([0-9a-f]\{40\}\)".*/\1/p' \
  | head -n 1)"

if [[ -z "$SHA" ]]; then
  echo "Konnte Commit-SHA nicht ermitteln." >&2
  exit 1
fi

RAW_BASE="https://raw.githubusercontent.com/$OWNER_REPO/$SHA"

# Hilfsfunction fuer parallele downloads
download_file() {
    local source_path="$1"
    local target_path="$2"
    mkdir -p "$(dirname "$target_path")"
    if curl -fsSL --retry 5 --retry-delay 1 "$RAW_BASE/$source_path" -o "$target_path"; then
        echo "✓ $source_path"
    else
        echo "✗ FEHLER: $source_path" >&2
        return 1
    fi
}

export -f download_file
export RAW_BASE TARGET_DIR

FILES=(
    "server/receiver.py"
    "server/static/index.html"
    "server/static/app.js"
    "server/static/styles.css"
    "BUILD_VERSION"
    "AGENT_VERSION"
    "openapi.yaml"
    "pull-server-only.sh"
)

# Parallele downloads: bis zu 4 gleichzeitig
echo "Lade ${#FILES[@]} Dateien parallel (max 4 gleichzeitig)..."
printf '%s\n' "${FILES[@]}" | xargs -P 4 -I {} bash -c 'download_file "{}" "$TARGET_DIR/{}"' || {
    echo "Fehler bei parallelen Downloads" >&2
    exit 1
}
echo "Dateien geladen ✓"

ICONS_API="https://api.github.com/repos/$OWNER_REPO/contents/server/static/icons?ref=$SHA"
TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

ICONS_JSON="$TMP_DIR/icons.json"
curl -fsSL --retry 5 --retry-delay 1 \
  -H "Accept: application/vnd.github+json" \
  -H "User-Agent: monitoring-pull-server-only" \
  "$ICONS_API" \
  -o "$ICONS_JSON"

mapfile -t ICON_NAMES < <(
  python3 - "$ICONS_JSON" <<'PY'
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
  data = json.load(f)

if isinstance(data, list):
  names = [
    str(item.get("name", ""))
    for item in data
    if isinstance(item, dict) and str(item.get("name", "")).lower().endswith(".png")
  ]
else:
  names = []

for name in sorted(set(names)):
  print(name)
PY
)

if [[ ${#ICON_NAMES[@]} -eq 0 ]]; then
  echo "Keine PNG-Icons geladen (Liste war leer oder ungeeignet)." >&2
  exit 1
fi

echo "Lade ${#ICON_NAMES[@]} PNG-Icons parallel..."
printf 'server/static/icons/%s\n' "${ICON_NAMES[@]}" | xargs -P 4 -I {} bash -c 'download_file "{}" "$TARGET_DIR/{}"' || {
    echo "Fehler bei Icon-Downloads (nicht kritisch)" >&2
}
echo "Icons geladen ✓"

echo "$SHA" > "$TARGET_DIR/DEPLOYED_COMMIT_SHA"
echo "Fertig. Deploy-Commit: $SHA"
echo -n "BUILD_VERSION lokal: "
cat "$TARGET_DIR/BUILD_VERSION"
echo -n "AGENT_VERSION lokal: "
cat "$TARGET_DIR/AGENT_VERSION"
ls -ld "$TARGET_DIR/server"

# --- venv sicherstellen ---
if [[ ! -x "$TARGET_DIR/.venv/bin/python" ]]; then
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
if [[ ! -f "$ENV_FILE" ]]; then
    cat > "$ENV_FILE" <<'EOF'
# Monitoring Server – Umgebungsvariablen
# Diese Datei bleibt nur auf dem Server und kommt NIE ins Git!
MONITORING_API_KEY=HIER_API_KEY_EINTRAGEN
MONITORING_API_KEY_GRACE_ALLOW_KNOWN_HOSTS=0
# MONITORING_SCHEDULE_TIMEZONE=Europe/Zurich
EOF
    chmod 600 "$ENV_FILE"
    echo "EnvironmentFile angelegt: $ENV_FILE"
    echo "  --> Bitte den API-Key dort eintragen!"
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
echo ""
echo "Naechste Schritte:"
echo "  1. API-Key eintragen:  nano $ENV_FILE"
echo "  2. Dienst starten:     systemctl restart monitoring"
