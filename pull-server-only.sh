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
download_file() {
    local source_path="$1"
    local target_path="$2"
    mkdir -p "$(dirname "$target_path")"
    curl -fsSL --retry 5 --retry-delay 1 "$RAW_BASE/$source_path" -o "$target_path"
    echo "Datei geladen: $source_path"
}

FILES=(
    "server/receiver.py"
    "server/static/index.html"
    "server/static/app.js"
    "server/static/styles.css"
    "BUILD_VERSION"
    "AGENT_VERSION"
    "openapi.yaml"
)

for rel_path in "${FILES[@]}"; do
    download_file "$rel_path" "$TARGET_DIR/$rel_path"
done

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
  sed -n 's/.*"name"[[:space:]]*:[[:space:]]*"\([^"]*\.png\)".*/\1/p' "$ICONS_JSON"
)

if [[ ${#ICON_NAMES[@]} -eq 0 ]]; then
  echo "Keine PNG-Icons geladen (Liste war leer oder ungeeignet)." >&2
  exit 1
fi

for icon_name in "${ICON_NAMES[@]}"; do
  download_file "server/static/icons/$icon_name" "$TARGET_DIR/server/static/icons/$icon_name"
done

echo "$SHA" > "$TARGET_DIR/DEPLOYED_COMMIT_SHA"
echo "Fertig. Deploy-Commit: $SHA"
echo -n "BUILD_VERSION lokal: "
cat "$TARGET_DIR/BUILD_VERSION"
echo -n "AGENT_VERSION lokal: "
cat "$TARGET_DIR/AGENT_VERSION"
ls -ld "$TARGET_DIR/server"