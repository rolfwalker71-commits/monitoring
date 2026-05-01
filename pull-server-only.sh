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

curl -fsSL --retry 5 --retry-delay 1 "$RAW_BASE/server/receiver.py" -o "$TARGET_DIR/server/receiver.py"
curl -fsSL --retry 5 --retry-delay 1 "$RAW_BASE/server/static/index.html" -o "$TARGET_DIR/server/static/index.html"
curl -fsSL --retry 5 --retry-delay 1 "$RAW_BASE/server/static/app.js" -o "$TARGET_DIR/server/static/app.js"
curl -fsSL --retry 5 --retry-delay 1 "$RAW_BASE/server/static/styles.css" -o "$TARGET_DIR/server/static/styles.css"
curl -fsSL --retry 5 --retry-delay 1 "$RAW_BASE/BUILD_VERSION" -o "$TARGET_DIR/BUILD_VERSION"

# Alle PNG-Icons aus server/static/icons dynamisch laden (robust ohne Pipe-Parsing)
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

python3 - "$ICONS_JSON" "$RAW_BASE" "$TARGET_DIR/server/static/icons" <<'PY'
import json
import os
import sys
import urllib.request

json_path = sys.argv[1]
raw_base = sys.argv[2]
target_dir = sys.argv[3]

with open(json_path, "r", encoding="utf-8") as f:
    raw = f.read().strip()

if not raw:
    raise SystemExit("Icons API lieferte leere Antwort.")

try:
    data = json.loads(raw)
except json.JSONDecodeError as exc:
    raise SystemExit(f"Icons API lieferte kein valides JSON: {exc}")

if isinstance(data, dict):
    msg = data.get("message")
    if msg:
        raise SystemExit(f"Icons API Fehler: {msg}")
    raise SystemExit("Icons API lieferte unerwartetes JSON-Objekt statt Liste.")

if not isinstance(data, list):
    raise SystemExit("Icons API lieferte unerwartetes Format.")

os.makedirs(target_dir, exist_ok=True)
loaded = 0
for item in data:
    if not isinstance(item, dict):
        continue
    if item.get("type") != "file":
        continue
    name = str(item.get("name", ""))
    if not name.lower().endswith(".png"):
        continue

    url = f"{raw_base}/server/static/icons/{name}"
    out = os.path.join(target_dir, name)

    with urllib.request.urlopen(url, timeout=20) as resp, open(out, "wb") as out_file:
        out_file.write(resp.read())

    loaded += 1
    print(f"Icon geladen: {name}")

if loaded == 0:
    raise SystemExit("Keine PNG-Icons geladen (Liste war leer oder ungeeignet).")
PY

echo "$SHA" > "$TARGET_DIR/DEPLOYED_COMMIT_SHA"
echo "Fertig. Deploy-Commit: $SHA"
echo -n "BUILD_VERSION lokal: "
cat "$TARGET_DIR/BUILD_VERSION"
