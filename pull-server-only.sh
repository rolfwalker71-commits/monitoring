#!/usr/bin/env bash
set -euo pipefail

on_pull_script_error() {
  local exit_code=$?
  echo "FEHLER in pull-server-only.sh (Zeile ${BASH_LINENO[0]:-?}, exit $exit_code)" >&2
  exit "$exit_code"
}
trap on_pull_script_error ERR

# Bump when pull-server-only.sh logic changes (shown at start for deploy verification).
PULL_SCRIPT_VERSION="20260625b"
# Bump when FILES_LIST changes (must match script_guardian entries).
PULL_FILES_MANIFEST="scripts-42-v1"
PULL_FILES_EXPECTED_COUNT=42
_DEPLOY_MAIN_SHA_CACHED=""

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

load_github_token_from_env_file() {
  local line key val
  [ -f "$TARGET_ENV_FILE" ] || return 1
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%%#*}"
    line="${line#"${line%%[![:space:]]*}"}"
    [[ "$line" =~ ^(MONITORING_GITHUB_TOKEN|GITHUB_TOKEN|GH_TOKEN)[[:space:]]*=[[:space:]]*(.+)$ ]] || continue
    val="${BASH_REMATCH[2]}"
    val="${val%\"}"
    val="${val#\"}"
    val="${val%\'}"
    val="${val#\'}"
    if [ -n "$val" ]; then
      GITHUB_TOKEN="$val"
      export GITHUB_TOKEN
      return 0
    fi
  done < "$TARGET_ENV_FILE"
  return 1
}

if [ -z "$GITHUB_TOKEN" ]; then
  load_github_token_from_env_file || true
fi

CURL_CONNECT_TIMEOUT="${CURL_CONNECT_TIMEOUT:-15}"
CURL_MAX_TIME="${CURL_MAX_TIME:-120}"

curl_github() {
  local accept_header="${1:-application/vnd.github+json}"
  shift || true
  if [ -n "$GITHUB_TOKEN" ]; then
    curl -fsSL --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" \
      --retry 5 --retry-delay 1 \
      -H "Authorization: Bearer $GITHUB_TOKEN" \
      -H "Accept: $accept_header" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      -H "User-Agent: monitoring-pull-server-only" \
      "$@"
  else
    curl -fsSL --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" \
      --retry 5 --retry-delay 1 \
      -H "Accept: $accept_header" \
      -H "User-Agent: monitoring-pull-server-only" \
      "$@"
  fi
}

curl_raw_github() {
  if [ -n "$GITHUB_TOKEN" ]; then
    curl -fsSL --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" \
      --retry 5 --retry-delay 1 \
      -H "Authorization: Bearer $GITHUB_TOKEN" \
      -H "User-Agent: monitoring-pull-server-only" \
      "$@"
  else
    curl -fsSL --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" \
      --retry 5 --retry-delay 1 \
      -H "User-Agent: monitoring-pull-server-only" \
      "$@"
  fi
}

# raw.githubusercontent.com caches branch aliases (e.g. /main/) aggressively.
append_raw_cache_bust() {
  local url="$1"
  local stamp="${2:-}"
  if [ -z "$stamp" ]; then
    stamp="$(date +%s)-$$-${RANDOM:-0}"
  fi
  if [[ "$url" == *"?"* ]]; then
    printf '%s&_=%s' "$url" "$stamp"
  else
    printf '%s?_=%s' "$url" "$stamp"
  fi
}

# Semver-ish compare for BUILD_VERSION (1.7.364 vs 1.7.365).
version_gt() {
  local a="${1:-}" b="${2:-}"
  [ -n "$a" ] && [ -n "$b" ] && [ "$a" != "$b" ] \
    && [ "$(printf '%s\n%s\n' "$b" "$a" | sort -V | tail -n 1)" = "$a" ]
}

fetch_build_version_at_ref() {
  local ref="$1"
  tr -d ' \t\r\n' <<< "$(fetch_repo_text_at_ref BUILD_VERSION "$ref" || true)"
}

# Pick SHA with highest BUILD_VERSION among candidates (handles stale MAIN_HEAD_SHA CDN).
# Bei gleicher BUILD_VERSION gewinnt der fruehere Kandidat (git ls-remote vor MAIN_HEAD_SHA CDN).
pick_best_sha_by_build_version() {
  local sha="" bv="" best_sha="" best_bv=""
  for sha in "$@"; do
    sha="$(normalize_sha_ref "$sha")"
    if ! is_full_git_sha "$sha"; then
      continue
    fi
    bv="$(fetch_build_version_at_ref "$sha")"
    [ -n "$bv" ] || continue
    if [ -z "$best_bv" ] || version_gt "$bv" "$best_bv"; then
      best_bv="$bv"
      best_sha="$sha"
    fi
  done
  if is_full_git_sha "$best_sha"; then
    printf '%s' "$best_sha"
    return 0
  fi
  return 1
}

is_branch_ref() {
  local ref
  ref="$(normalize_sha_ref "${1:-}")"
  [ "$ref" = "main" ] || [ "$ref" = "master" ]
}

resolve_branch_ref_to_commit_sha() {
  local branch_ref="${1:-main}"
  local sha=""
  if ! is_branch_ref "$branch_ref"; then
    return 1
  fi
  sha="$(resolve_latest_main_sha "$branch_ref" || true)"
  if is_full_git_sha "$sha"; then
    printf '%s' "$sha"
    return 0
  fi
  return 1
}

fetch_repo_text_at_ref() {
  local source_path="$1"
  local ref="$2"
  local value=""

  if [ -z "$ref" ]; then
    return 0
  fi

  if is_branch_ref "$ref"; then
    local resolved_ref=""
    resolved_ref="$(resolve_branch_ref_to_commit_sha "$ref" || true)"
    if is_full_git_sha "$resolved_ref"; then
      ref="$resolved_ref"
    fi
  fi

  if [ -n "$GITHUB_TOKEN" ]; then
    value="$(curl_github "application/vnd.github.raw" "$GITHUB_API_BASE/contents/$source_path?ref=$ref" 2>/dev/null \
      | tr -d ' \t\r\n' || true)"
  fi
  if [ -z "$value" ]; then
    value="$(curl_raw_github "$(append_raw_cache_bust "https://raw.githubusercontent.com/$OWNER_REPO/$ref/$source_path")" 2>/dev/null \
      | tr -d ' \t\r\n' || true)"
  fi
  printf '%s' "$value"
}

ensure_deploy_ref_is_latest_commit() {
  local latest_sha="" remote_bv="" ref_bv="" local_bv=""

  if [ -n "${MONITORING_DEPLOY_SHA:-}" ]; then
    return 0
  fi

  latest_sha="$(resolve_latest_main_sha main || true)"
  if ! is_full_git_sha "$latest_sha"; then
    if is_branch_ref "$REF"; then
      echo "WARNUNG: main-SHA nicht ermittelbar (git ls-remote / GitHub API)." >&2
      echo "  Deploy ueber raw/main mit Cache-Bust – Versions-Check nach dem Download." >&2
      echo "  Besser: export MONITORING_DEPLOY_SHA=\$(curl -fsSL \"https://raw.githubusercontent.com/$OWNER_REPO/main/MAIN_HEAD_SHA?_=\$(date +%s)\" | tr -d ' \\t\\r\\n')" >&2
      MONITORING_PULL_USE_RAW_ONLY=1
      export MONITORING_PULL_USE_RAW_ONLY
      return 0
    fi
    return 0
  fi

  remote_bv="$(fetch_repo_text_at_ref BUILD_VERSION "$latest_sha")"
  local_bv="$(tr -d ' \t\r\n' < "$TARGET_DIR/BUILD_VERSION" 2>/dev/null || true)"

  if is_full_git_sha "$REF"; then
    if [ "$REF" = "$latest_sha" ]; then
      :
    else
      ref_bv="$(fetch_repo_text_at_ref BUILD_VERSION "$REF")"
      if [ -n "$ref_bv" ] && [ -n "$remote_bv" ] && [ "$ref_bv" = "$remote_bv" ]; then
        return 0
      fi
      if [ -n "$ref_bv" ] && [ -n "$remote_bv" ] && version_gt "$ref_bv" "$remote_bv"; then
        echo "Deploy-Pin: behalte ${REF:0:12} (BUILD $ref_bv) – erkanntes main ${latest_sha:0:12} nur BUILD $remote_bv (stale MAIN_HEAD_SHA/CDN?)" >&2
        return 0
      fi
      echo "Deploy-Pin: ${REF:0:12} (${ref_bv:-?}) -> ${latest_sha:0:12} (${remote_bv:-?})" >&2
    fi
  elif is_branch_ref "$REF"; then
    echo "Deploy-Pin: ${latest_sha:0:12} (main HEAD, BUILD ${remote_bv:-?})" >&2
  fi

  REF="$latest_sha"
  invalidate_deploy_main_sha_cache
  MONITORING_PULL_USE_RAW_ONLY=0
  export MONITORING_PULL_USE_RAW_ONLY
}

is_full_git_sha() {
  [[ "${1:-}" =~ ^[0-9a-f]{40}$ ]]
}

normalize_sha_ref() {
  printf '%s' "${1:-}" | tr -d ' \t\r\n' | tr '[:upper:]' '[:lower:]'
}

is_hex_sha_ref() {
  local ref
  ref="$(normalize_sha_ref "${1:-}")"
  [[ "$ref" =~ ^[0-9a-f]{7,40}$ ]]
}

resolve_short_sha_via_github_api() {
  local ref
  ref="$(normalize_sha_ref "${1:-}")"
  if [ "${MONITORING_PULL_USE_RAW_ONLY:-0}" = "1" ] || ! is_hex_sha_ref "$ref"; then
    return 1
  fi

  local meta=""
  if ! meta="$(curl_github "application/vnd.github+json" "$GITHUB_API_BASE/commits/$ref" 2>/dev/null)"; then
    return 1
  fi

  local sha=""
  if command -v python3 >/dev/null 2>&1; then
    sha="$(printf '%s\n' "$meta" | python3 -c 'import json,sys; print((json.load(sys.stdin) or {}).get("sha", ""))' 2>/dev/null || true)"
  fi
  if [ -z "$sha" ]; then
    sha="$(printf '%s\n' "$meta" \
      | awk 'match($0, /"sha"[[:space:]]*:[[:space:]]*"[0-9a-f]{40}"/) { m=substr($0, RSTART, RLENGTH); sub(/^.*"/, "", m); sub(/"$/, "", m); print m; exit }')"
  fi
  if is_full_git_sha "$sha"; then
    printf '%s' "$sha"
    return 0
  fi
  return 1
}

probe_raw_ref_download() {
  local ref
  ref="$(normalize_sha_ref "${1:-}")"
  if [ -z "$ref" ]; then
    return 1
  fi
  local probe=""
  probe="$(fetch_repo_text_at_ref BUILD_VERSION "$ref")"
  [ -n "$probe" ] && [[ "$probe" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]]
}

expand_deploy_ref() {
  local ref
  ref="$(normalize_sha_ref "${1:-}")"
  if is_full_git_sha "$ref"; then
    printf '%s' "$ref"
    return 0
  fi
  if ! is_hex_sha_ref "$ref"; then
    return 1
  fi

  local full=""
  full="$(resolve_short_sha_via_github_api "$ref" || true)"
  if is_full_git_sha "$full"; then
    if [ "$full" != "$ref" ]; then
      echo "Deploy-SHA erweitert: ${ref} -> ${full:0:12}… (GitHub API)" >&2
    fi
    printf '%s' "$full"
    return 0
  fi

  if probe_raw_ref_download "$ref"; then
    if [ "${#ref}" -lt 40 ]; then
      echo "Deploy-Ref: $ref (Kurz-SHA, raw.githubusercontent.com erreichbar)" >&2
    fi
    printf '%s' "$ref"
    return 0
  fi
  return 1
}

extract_full_sha_from_commit_json() {
  local meta="${1:-}"
  local sha=""
  if [ -z "$meta" ]; then
    return 1
  fi
  if command -v python3 >/dev/null 2>&1; then
    sha="$(printf '%s\n' "$meta" | python3 -c 'import json,sys; print((json.load(sys.stdin) or {}).get("sha", ""))' 2>/dev/null || true)"
  fi
  if [ -z "$sha" ]; then
    sha="$(printf '%s\n' "$meta" \
      | awk 'match($0, /"sha"[[:space:]]*:[[:space:]]*"[0-9a-f]{40}"/) { m=substr($0, RSTART, RLENGTH); sub(/^.*"/, "", m); sub(/"$/, "", m); print m; exit }')"
  fi
  if is_full_git_sha "$sha"; then
    printf '%s' "$sha"
    return 0
  fi
  return 1
}

resolve_deploy_commit_ref() {
  local candidate=""
  local expanded=""

  candidate="$(normalize_sha_ref "${1:-}")"
  if is_full_git_sha "$candidate"; then
    printf '%s' "$candidate"
    return 0
  fi
  if [ -n "$candidate" ]; then
    expanded="$(expand_deploy_ref "$candidate" 2>/dev/null || true)"
    if is_full_git_sha "$expanded"; then
      printf '%s' "$expanded"
      return 0
    fi
  fi
  candidate="$(normalize_sha_ref "${REF:-}")"
  if is_full_git_sha "$candidate"; then
    printf '%s' "$candidate"
    return 0
  fi
  expanded="$(expand_deploy_ref "$candidate" 2>/dev/null || true)"
  if is_full_git_sha "$expanded"; then
    printf '%s' "$expanded"
    return 0
  fi
  return 1
}

extract_commit_message_from_json() {
  local meta="${1:-}"
  if [ -z "$meta" ]; then
    return 1
  fi
  if command -v python3 >/dev/null 2>&1; then
    printf '%s\n' "$meta" | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin) or {}
except Exception:
    sys.exit(1)
msg = str((data.get("commit") or {}).get("message") or "").strip()
if not msg:
    sys.exit(1)
print(msg)
' 2>/dev/null && return 0
  fi
  if command -v jq >/dev/null 2>&1; then
    local jq_msg=""
    jq_msg="$(printf '%s\n' "$meta" | jq -r '.commit.message // empty' 2>/dev/null || true)"
    if [ -n "$jq_msg" ]; then
      printf '%s' "$jq_msg"
      return 0
    fi
  fi
  return 1
}

fetch_commit_meta_json_for_ref() {
  local ref=""
  local expanded=""
  local cached_sha=""
  local meta=""

  ref="$(normalize_sha_ref "${1:-}")"
  if [ -z "$ref" ]; then
    return 1
  fi
  if ! is_full_git_sha "$ref"; then
    expanded="$(expand_deploy_ref "$ref" || true)"
    if is_full_git_sha "$expanded"; then
      ref="$expanded"
    else
      return 1
    fi
  fi

  if [ -n "${COMMIT_META_JSON:-}" ]; then
    cached_sha="$(extract_full_sha_from_commit_json "$COMMIT_META_JSON" || true)"
    if [ "$cached_sha" = "$ref" ]; then
      printf '%s' "$COMMIT_META_JSON"
      return 0
    fi
  fi

  # API auch bei RAW_ONLY versuchen, wenn Token gesetzt (private Repo).
  if [ "${MONITORING_PULL_USE_RAW_ONLY:-0}" != "1" ] || [ -n "$GITHUB_TOKEN" ]; then
    if meta="$(curl_github "application/vnd.github+json" "$GITHUB_API_BASE/commits/$ref" 2>/dev/null)"; then
      if extract_full_sha_from_commit_json "$meta" >/dev/null; then
        printf '%s' "$meta"
        return 0
      fi
    fi
    if [ -n "$GITHUB_TOKEN" ]; then
      meta="$(curl -fsSL --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" \
        --retry 3 --retry-delay 1 \
        -H "Authorization: Bearer $GITHUB_TOKEN" \
        -H "Accept: application/vnd.github+json" \
        -H "User-Agent: monitoring-pull-server-only" \
        "https://api.github.com/repos/$OWNER_REPO/commits/$ref" 2>/dev/null || true)"
    else
      meta="$(curl -fsSL --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" \
        --retry 3 --retry-delay 1 \
        -H "Accept: application/vnd.github+json" \
        -H "User-Agent: monitoring-pull-server-only" \
        "https://api.github.com/repos/$OWNER_REPO/commits/$ref" 2>/dev/null || true)"
    fi
    if extract_full_sha_from_commit_json "$meta" >/dev/null; then
      printf '%s' "$meta"
      return 0
    fi
  fi
  return 1
}

fetch_commit_message_via_github_patch() {
  local ref=""
  local expanded=""
  local patch=""
  local message=""
  local patch_url=""

  ref="$(normalize_sha_ref "${1:-}")"
  if ! is_full_git_sha "$ref"; then
    expanded="$(expand_deploy_ref "$ref" || true)"
    if is_full_git_sha "$expanded"; then
      ref="$expanded"
    else
      return 1
    fi
  fi

  patch_url="https://github.com/$OWNER_REPO/commit/${ref}.patch"
  if [ -n "$GITHUB_TOKEN" ]; then
    patch="$(curl -fsSL --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" \
      --retry 3 --retry-delay 1 \
      -H "Authorization: Bearer $GITHUB_TOKEN" \
      -H "User-Agent: monitoring-pull-server-only" \
      "$patch_url" 2>/dev/null || true)"
  else
    patch="$(curl -fsSL --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" \
      --retry 3 --retry-delay 1 \
      -H "User-Agent: monitoring-pull-server-only" \
      "$patch_url" 2>/dev/null || true)"
  fi
  if [ -z "$patch" ]; then
    return 1
  fi

  message="$(printf '%s\n' "$patch" | awk '
    /^Subject: / {
      line = $0
      sub(/^Subject: /, "", line)
      sub(/^\[PATCH\] /, "", line)
      if (line != "") {
        if (msg != "") msg = msg "\n" line
        else msg = line
      }
      in_body = 1
      next
    }
    in_body && /^---$/ { exit }
    in_body && /^diff --git / { exit }
    in_body && NF {
      if (msg == "") msg = $0
      else msg = msg "\n" $0
    }
    END { print msg }
  ')"
  message="$(printf '%s\n' "$message" | sed '/^$/d' | head -n 20)"
  if [ -n "$message" ]; then
    printf '%s' "$message"
    return 0
  fi
  return 1
}

COMMIT_MESSAGE_SOURCE=""

fetch_commit_message_for_ref() {
  local ref=""
  local meta=""
  local message=""

  COMMIT_MESSAGE_SOURCE=""
  ref="$(resolve_deploy_commit_ref "${1:-}")"
  if [ -z "$ref" ]; then
    return 1
  fi

  meta="$(fetch_commit_meta_json_for_ref "$ref" || true)"
  message="$(extract_commit_message_from_json "$meta" || true)"
  if [ -n "$message" ]; then
    COMMIT_MESSAGE_SOURCE="GitHub API"
    printf '%s' "$message"
    return 0
  fi

  message="$(fetch_commit_message_via_github_patch "$ref" || true)"
  if [ -n "$message" ]; then
    COMMIT_MESSAGE_SOURCE="github.com/commit/*.patch"
    printf '%s' "$message"
    return 0
  fi
  return 1
}

print_deployed_commit_message_summary() {
  local deploy_ref=""
  local message=""
  local line=""
  local source_hint=""

  deploy_ref="$(resolve_deploy_commit_ref "${1:-}")"
  if [ -z "$deploy_ref" ]; then
    echo "Commit-Text: nicht ermittelbar (Deploy-SHA fehlt, Ref='${REF:-?}')"
    return 0
  fi

  message="$(fetch_commit_message_for_ref "$deploy_ref" || true)"
  if [ -z "$message" ]; then
    echo "Commit-Text (${deploy_ref:0:12}): nicht verfuegbar"
    echo "  Tipp: MONITORING_GITHUB_TOKEN in monitoring.env setzen oder api.github.com / github.com erreichbar machen."
    return 0
  fi

  source_hint="${COMMIT_MESSAGE_SOURCE:-unbekannt}"
  echo "Commit-Text (${deploy_ref:0:12}, ${source_hint}):"
  while IFS= read -r line || [ -n "$line" ]; do
    echo "  $line"
  done <<< "$message"
}

resolve_latest_main_sha_via_github_api() {
  local branch_ref="${1:-main}"
  local meta=""
  if ! meta="$(curl_github "application/vnd.github+json" "$GITHUB_API_BASE/commits/$branch_ref" 2>/dev/null)"; then
    return 1
  fi
  extract_full_sha_from_commit_json "$meta"
}

# When api.github.com is blocked but raw.githubusercontent.com works (common on locked-down servers).
resolve_latest_main_sha_via_raw_main_head_file() {
  local sha_a="" sha_b="" sha_c="" pick=""
  sha_a="$(curl_raw_github "$(append_raw_cache_bust "https://raw.githubusercontent.com/$OWNER_REPO/main/MAIN_HEAD_SHA" "a-$(date +%s)-$$")" 2>/dev/null \
    | tr -d ' \t\r\n' || true)"
  sleep 0.4
  sha_b="$(curl_raw_github "$(append_raw_cache_bust "https://raw.githubusercontent.com/$OWNER_REPO/main/MAIN_HEAD_SHA" "b-${RANDOM:-0}-$(date +%s)")" 2>/dev/null \
    | tr -d ' \t\r\n' || true)"
  pick="$(pick_best_sha_by_build_version "$sha_a" "$sha_b" || true)"
  if ! is_full_git_sha "$pick"; then
    if is_full_git_sha "$sha_a"; then
      pick="$sha_a"
    elif is_full_git_sha "$sha_b"; then
      pick="$sha_b"
    fi
  fi
  if [ "$sha_a" != "$sha_b" ] && is_full_git_sha "$sha_a" && is_full_git_sha "$sha_b"; then
    sleep 0.6
    sha_c="$(curl_raw_github "$(append_raw_cache_bust "https://raw.githubusercontent.com/$OWNER_REPO/main/MAIN_HEAD_SHA" "c-${RANDOM:-0}-$(date +%s)")" 2>/dev/null \
      | tr -d ' \t\r\n' || true)"
    pick="$(pick_best_sha_by_build_version "$pick" "$sha_c" || true)"
    if ! is_full_git_sha "$pick"; then
      pick="$(pick_best_sha_by_build_version "$sha_a" "$sha_b" "$sha_c" || true)"
    fi
  fi
  if is_full_git_sha "$pick"; then
    echo "main-SHA via raw MAIN_HEAD_SHA: ${pick:0:12} (BUILD $(fetch_build_version_at_ref "$pick"))" >&2
    printf '%s' "$pick"
    return 0
  fi
  return 1
}

github_api_reachable() {
  curl -fsSL --connect-timeout 3 --max-time 8 -o /dev/null "https://api.github.com" 2>/dev/null
}

# Fallback when curl_github wrapper fails (proxy/SSL); still tries api.github.com.
resolve_latest_main_sha_via_plain_curl() {
  local branch_ref="${1:-main}"
  local meta=""
  meta="$(curl -fsSL --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" \
    --retry 3 --retry-delay 1 \
    -H "Accept: application/vnd.github+json" \
    -H "User-Agent: monitoring-pull-server-only" \
    "https://api.github.com/repos/$OWNER_REPO/commits/$branch_ref" 2>/dev/null || true)"
  extract_full_sha_from_commit_json "$meta"
}

resolve_latest_main_sha_via_git() {
  local sha=""
  if ! command -v git >/dev/null 2>&1; then
    return 0
  fi
  local git_url="https://github.com/$OWNER_REPO.git"
  if [ -n "$GITHUB_TOKEN" ]; then
    git_url="https://x-access-token:${GITHUB_TOKEN}@github.com/$OWNER_REPO.git"
  fi
  # Mit pipefail wuerde ein git-Fehler sonst bei set -e den ganzen Pull abbrechen.
  sha="$({ git ls-remote "$git_url" refs/heads/main 2>/dev/null || true; } | awk '{print $1; exit}')"
  if [ -n "$sha" ]; then
    printf '%s' "$sha"
  fi
  return 0
}

collect_main_sha_candidates() {
  local branch_ref="${1:-main}"
  local -a candidates=()
  local sha="" sha_a="" sha_b="" sha_c="" pick=""

  sha="$(resolve_latest_main_sha_via_git || true)"
  if is_full_git_sha "$sha"; then
    candidates+=("$sha")
    echo "main-SHA Kandidat git ls-remote: ${sha:0:12} (BUILD $(fetch_build_version_at_ref "$sha"))" >&2
  fi

  if github_api_reachable; then
    sha="$(resolve_latest_main_sha_via_github_api "$branch_ref" || true)"
    if is_full_git_sha "$sha"; then
      candidates+=("$sha")
      echo "main-SHA Kandidat GitHub API: ${sha:0:12} (BUILD $(fetch_build_version_at_ref "$sha"))" >&2
    fi
    sha="$(resolve_latest_main_sha_via_plain_curl "$branch_ref" || true)"
    if is_full_git_sha "$sha"; then
      candidates+=("$sha")
      echo "main-SHA Kandidat api.github.com (plain curl): ${sha:0:12} (BUILD $(fetch_build_version_at_ref "$sha"))" >&2
    fi
  else
    echo "Hinweis: api.github.com nicht erreichbar – nutze git ls-remote und raw MAIN_HEAD_SHA." >&2
  fi

  sha_a="$(curl_raw_github "$(append_raw_cache_bust "https://raw.githubusercontent.com/$OWNER_REPO/main/MAIN_HEAD_SHA" "a-$(date +%s)-$$")" 2>/dev/null \
    | tr -d ' \t\r\n' || true)"
  sleep 0.3
  sha_b="$(curl_raw_github "$(append_raw_cache_bust "https://raw.githubusercontent.com/$OWNER_REPO/main/MAIN_HEAD_SHA" "b-${RANDOM:-0}-$(date +%s)")" 2>/dev/null \
    | tr -d ' \t\r\n' || true)"
  for sha in "$sha_a" "$sha_b"; do
    if is_full_git_sha "$sha"; then
      candidates+=("$sha")
    fi
  done
  if [ "$sha_a" != "$sha_b" ] && is_full_git_sha "$sha_a" && is_full_git_sha "$sha_b"; then
    sleep 0.5
    sha_c="$(curl_raw_github "$(append_raw_cache_bust "https://raw.githubusercontent.com/$OWNER_REPO/main/MAIN_HEAD_SHA" "c-${RANDOM:-0}-$(date +%s)")" 2>/dev/null \
      | tr -d ' \t\r\n' || true)"
    if is_full_git_sha "$sha_c"; then
      candidates+=("$sha_c")
    fi
  fi

  if [ "${#candidates[@]}" -eq 0 ]; then
    return 1
  fi

  pick="$(pick_best_sha_by_build_version "${candidates[@]}" || true)"
  if ! is_full_git_sha "$pick"; then
    return 1
  fi
  echo "main-SHA gewaehlt: ${pick:0:12} (BUILD $(fetch_build_version_at_ref "$pick"), aus ${#candidates[@]} Kandidaten)" >&2
  printf '%s' "$pick"
  return 0
}

invalidate_deploy_main_sha_cache() {
  _DEPLOY_MAIN_SHA_CACHED=""
}

resolve_latest_main_sha() {
  local branch_ref="${1:-main}"
  if is_full_git_sha "$_DEPLOY_MAIN_SHA_CACHED"; then
    printf '%s' "$_DEPLOY_MAIN_SHA_CACHED"
    return 0
  fi
  _DEPLOY_MAIN_SHA_CACHED="$(collect_main_sha_candidates "$branch_ref" || true)"
  if ! is_full_git_sha "$_DEPLOY_MAIN_SHA_CACHED"; then
    invalidate_deploy_main_sha_cache
    return 1
  fi
  printf '%s' "$_DEPLOY_MAIN_SHA_CACHED"
  return 0
}

write_repo_text_to_target() {
  local source_path="$1"
  local ref="$2"
  local target_path="$3"
  local value=""

  value="$(fetch_repo_text_at_ref "$source_path" "$ref")"
  if [ -z "$value" ]; then
    return 1
  fi
  mkdir -p "$(dirname "$target_path")"
  printf '%s\n' "$value" > "$target_path"
}

force_refresh_version_files() {
  local version_ref="$1"
  local refreshed=0

  if ! is_full_git_sha "$version_ref"; then
    return 0
  fi

  for version_file in BUILD_VERSION AGENT_VERSION; do
    if write_repo_text_to_target "$version_file" "$version_ref" "$TARGET_DIR/$version_file"; then
      refreshed=1
    fi
  done

  if [ "$refreshed" -eq 1 ]; then
    cp -f "$TARGET_DIR/BUILD_VERSION" "$TARGET_DIR/updates/BUILD_VERSION" 2>/dev/null || true
    cp -f "$TARGET_DIR/AGENT_VERSION" "$TARGET_DIR/updates/AGENT_VERSION" 2>/dev/null || true
    echo "Version-Dateien neu geladen (Ref ${version_ref:0:12})."
  fi
}

is_valid_pull_script_file() {
  local candidate="$1"
  [ -s "$candidate" ] \
    && head -n 1 "$candidate" | grep -q '^#!/usr/bin/env bash' \
    && grep -q 'PULL_SCRIPT_VERSION=' "$candidate" \
    && grep -q 'resolve_deploy_ref' "$candidate"
}

pull_script_version_from_file() {
  local candidate="$1"
  sed -n 's/^PULL_SCRIPT_VERSION="\(.*\)".*/\1/p' "$candidate" 2>/dev/null | head -n 1
}

pull_script_manifest_from_file() {
  local candidate="$1"
  sed -n 's/^PULL_FILES_MANIFEST="\(.*\)".*/\1/p' "$candidate" 2>/dev/null | head -n 1
}

pull_script_has_guardian_files_list() {
  local candidate="$1"
  [ -f "$candidate" ] \
    && grep -q 'client/linux/script_guardian.sh' "$candidate" 2>/dev/null \
    && grep -q 'client/windows/script_guardian.ps1' "$candidate" 2>/dev/null
}

reexec_if_pull_script_missing_guardian_files() {
  local self="" new_script=""
  self="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || realpath "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")"
  if pull_script_has_guardian_files_list "$self"; then
    return 0
  fi

  echo "FEHLER: Dieses pull-server-only.sh hat keine Guardian-Dateien in FILES_LIST (typisch: 29 statt 32 Dateien)." >&2
  echo "Erzwinge Neu-Download von GitHub branch main ..." >&2
  new_script="$TARGET_DIR/pull-server-only.sh.forced"
  if ! curl_raw_github "$(append_raw_cache_bust "https://raw.githubusercontent.com/$OWNER_REPO/main/pull-server-only.sh" "force-$$-$(date +%s)")" \
    -o "$new_script" 2>/dev/null; then
    echo "FEHLER: Download von main/pull-server-only.sh fehlgeschlagen." >&2
    exit 1
  fi
  if ! pull_script_has_guardian_files_list "$new_script"; then
    echo "FEHLER: Auch frisch von main geladenes Skript enthaelt keine script_guardian-Eintraege (CDN?)." >&2
    echo "  Nutze: curl -fsSL .../scripts/deploy-agent-guardian.sh | bash -s $TARGET_DIR" >&2
    exit 1
  fi
  chmod +x "$new_script"
  mv -f "$new_script" "$TARGET_DIR/pull-server-only.sh"
  echo "pull-server-only.sh ersetzt – starte Deploy neu ..." >&2
  exec "$TARGET_DIR/pull-server-only.sh" "$@"
}

install_pull_script_from_main_branch() {
  local dest="$1"
  if curl_raw_github "$(append_raw_cache_bust "https://raw.githubusercontent.com/$OWNER_REPO/main/pull-server-only.sh" "main-pull-$$-$(date +%s)")" \
    -o "$dest" 2>/dev/null \
    && is_valid_pull_script_file "$dest" \
    && pull_script_has_guardian_files_list "$dest"; then
    chmod +x "$dest"
    return 0
  fi
  return 1
}

upgrade_local_pull_script_from_main() {
  if [ "${MONITORING_SKIP_PULL_SCRIPT_UPGRADE:-0}" = "1" ]; then
    return 0
  fi

  local latest_sha="" local_script="" remote_script="" local_pv="" remote_pv=""
  local_script="$TARGET_DIR/pull-server-only.sh"
  if [ ! -f "$local_script" ]; then
    local_script="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || realpath "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")"
  fi

  remote_script="$(mktemp "${TMPDIR:-/tmp}/pull-server-only.XXXXXX")"
  # Always fetch pull script from branch main (not stale MAIN_HEAD_SHA CDN pin).
  if ! curl_raw_github "$(append_raw_cache_bust "https://raw.githubusercontent.com/$OWNER_REPO/main/pull-server-only.sh")" \
    -o "$remote_script" 2>/dev/null; then
    rm -f "$remote_script"
    return 0
  fi
  if ! is_valid_pull_script_file "$remote_script"; then
    rm -f "$remote_script"
    return 0
  fi

  local_pv="$(pull_script_version_from_file "$local_script")"
  remote_pv="$(pull_script_version_from_file "$remote_script")"
  local_pm="$(pull_script_manifest_from_file "$local_script")"
  remote_pm="$(pull_script_manifest_from_file "$remote_script")"
  if [ -n "$local_pv" ] && [ -n "$remote_pv" ] && [ "$local_pv" = "$remote_pv" ] \
    && [ -n "$local_pm" ] && [ "$local_pm" = "$remote_pm" ] \
    && pull_script_has_guardian_files_list "$local_script" \
    && pull_script_has_guardian_files_list "$remote_script"; then
    rm -f "$remote_script"
    return 0
  fi
  if cmp -s "$remote_script" "$local_script" 2>/dev/null; then
    rm -f "$remote_script"
    return 0
  fi

  cp -f "$remote_script" "$local_script"
  chmod +x "$local_script"
  rm -f "$remote_script"
  echo "pull-server-only.sh aktualisiert (${local_pv:-?} -> ${remote_pv:-?}, Quelle branch main)." >&2
  echo "Bitte einmal erneut ausfuehren (kein automatischer Neustart – verhindert Endlosschleifen):" >&2
  echo "  cd $TARGET_DIR && ./pull-server-only.sh" >&2
  exit 0
}

redeploy_files_from_ref() {
  local redeploy_ref="$1"
  if ! is_full_git_sha "$redeploy_ref"; then
    return 1
  fi
  REF="$redeploy_ref"
  RAW_BASE="https://raw.githubusercontent.com/$OWNER_REPO/$REF"
  export REF RAW_BASE
  if ! printf '%s\n' "$FILES_LIST" | sed '/^$/d' | xargs -P "$MAX_PARALLEL_DOWNLOADS" -I {} bash -c 'download_file "{}" "$TARGET_DIR/{}"'; then
    return 1
  fi
  force_refresh_version_files "$REF"
  mirror_update_payloads
  echo "$REF" > "$TARGET_DIR/DEPLOYED_COMMIT_SHA"
  _DEPLOY_MAIN_SHA_CACHED="$redeploy_ref"
  return 0
}

mirror_update_payloads() {
  cp -f "$TARGET_DIR/BUILD_VERSION" "$TARGET_DIR/updates/BUILD_VERSION"
  cp -f "$TARGET_DIR/AGENT_VERSION" "$TARGET_DIR/updates/AGENT_VERSION"
  cp -f "$TARGET_DIR/client/windows/collect_and_send.ps1" "$TARGET_DIR/updates/client/windows/collect_and_send.ps1"
  cp -f "$TARGET_DIR/client/windows/collect_and_scan_sap_tables.ps1" "$TARGET_DIR/updates/client/windows/collect_and_scan_sap_tables.ps1"
  cp -f "$TARGET_DIR/client/windows/bootstrap_agent.ps1" "$TARGET_DIR/updates/client/windows/bootstrap_agent.ps1"
  cp -f "$TARGET_DIR/client/windows/install_agent.ps1" "$TARGET_DIR/updates/client/windows/install_agent.ps1"
  cp -f "$TARGET_DIR/client/windows/self_update.ps1" "$TARGET_DIR/updates/client/windows/self_update.ps1"
  cp -f "$TARGET_DIR/client/windows/setup_harvest_sql_user.ps1" "$TARGET_DIR/updates/client/windows/setup_harvest_sql_user.ps1"
  cp -f "$TARGET_DIR/client/windows/probe_sap_services.ps1" "$TARGET_DIR/updates/client/windows/probe_sap_services.ps1"
  cp -f "$TARGET_DIR/client/linux/collect_and_send.sh" "$TARGET_DIR/updates/client/linux/collect_and_send.sh"
  cp -f "$TARGET_DIR/client/linux/install_agent.sh" "$TARGET_DIR/updates/client/linux/install_agent.sh"
  cp -f "$TARGET_DIR/client/linux/self_update.sh" "$TARGET_DIR/updates/client/linux/self_update.sh"
  cp -f "$TARGET_DIR/client/linux/setup_harvest_hana_user.sql" "$TARGET_DIR/updates/client/linux/setup_harvest_hana_user.sql"
  cp -f "$TARGET_DIR/client/windows/script_guardian.ps1" "$TARGET_DIR/updates/client/windows/script_guardian.ps1"
  cp -f "$TARGET_DIR/client/linux/script_guardian.sh" "$TARGET_DIR/updates/client/linux/script_guardian.sh"
  cp -f "$TARGET_DIR/client/linux/monitor_probe.sh" "$TARGET_DIR/updates/client/linux/monitor_probe.sh"
  cp -f "$TARGET_DIR/client/windows/monitor_probe.ps1" "$TARGET_DIR/updates/client/windows/monitor_probe.ps1"
  chmod 0755 "$TARGET_DIR/updates/client/linux/collect_and_send.sh" "$TARGET_DIR/updates/client/linux/install_agent.sh" "$TARGET_DIR/updates/client/linux/self_update.sh" "$TARGET_DIR/updates/client/linux/script_guardian.sh" "$TARGET_DIR/updates/client/linux/monitor_probe.sh" 2>/dev/null || true
}

collect_ps1_embedded_version() {
  local ps1="$1"
  sed -n "s/^\$EmbeddedAgentVersion = '\([^']*\)'.*/\1/p" "$ps1" 2>/dev/null | head -n 1
}

collect_ps1_embedded_version_ok() {
  local ps1="$1" agent_ver="$2" embedded=""
  [ -f "$ps1" ] && [ -n "$agent_ver" ] || return 1
  embedded="$(collect_ps1_embedded_version "$ps1")"
  [ -n "$embedded" ] || return 1
  if [ "$embedded" = "$agent_ver" ]; then
    return 0
  fi
  # Agent liest AGENT_VERSION-Datei zuerst; embedded hinter Datei ist bei Server/CSS-Releases unkritisch.
  if version_gt "$agent_ver" "$embedded"; then
    return 0
  fi
  return 1
}

collect_ps1_mojibake_ok() {
  local ps1="$1"
  [ -f "$ps1" ] || return 1
  if grep -q 'function Get-AngLogMojibakeScore' "$ps1" 2>/dev/null \
    && ! grep -q '\[char\]0x00C3' "$ps1" 2>/dev/null; then
    return 1
  fi
  return 0
}

explain_deploy_integrity_failure() {
  local build_ver="" agent_ver="" embedded="" updates_embedded=""
  local ps1="$TARGET_DIR/client/windows/collect_and_send.ps1"
  local updates_ps1="$TARGET_DIR/updates/client/windows/collect_and_send.ps1"

  build_ver="$(tr -d ' \t\r\n' < "$TARGET_DIR/BUILD_VERSION" 2>/dev/null || true)"
  agent_ver="$(tr -d ' \t\r\n' < "$TARGET_DIR/AGENT_VERSION" 2>/dev/null || true)"
  echo "Integritaets-Details:" >&2
  echo "  BUILD_VERSION=$build_ver AGENT_VERSION=$agent_ver" >&2
  if [ -n "$build_ver" ] && [ -n "$agent_ver" ] && [ "$build_ver" != "$agent_ver" ]; then
    if version_gt "$build_ver" "$agent_ver"; then
      echo "  Hinweis: BUILD vor AGENT (unkritisch bei Server-only-Release)." >&2
    else
      echo "  FEHLER: AGENT neuer als BUILD – Version-Dateien inkonsistent." >&2
    fi
  fi
  if [ ! -f "$ps1" ]; then
    echo "  collect_and_send.ps1 fehlt unter $ps1" >&2
    return 0
  fi
  embedded="$(collect_ps1_embedded_version "$ps1")"
  echo "  EmbeddedAgentVersion (client)=${embedded:-?}" >&2
  if [ -n "$agent_ver" ] && [ -n "$embedded" ] && [ "$embedded" != "$agent_ver" ]; then
    if version_gt "$agent_ver" "$embedded"; then
      echo "  Hinweis: embedded hinter AGENT_VERSION (unkritisch – Agent nutzt AGENT_VERSION-Datei)." >&2
    else
      echo "  Hinweis: embedded neuer als AGENT_VERSION – BUILD/AGENT-Dateien vermutlich veraltet." >&2
    fi
  fi
  if ! collect_ps1_mojibake_ok "$ps1"; then
    echo "  FEHLER: Mojibake-Hilfsfunktion in collect_and_send.ps1 beschaedigt." >&2
  fi
  if [ -f "$updates_ps1" ]; then
    updates_embedded="$(collect_ps1_embedded_version "$updates_ps1")"
    echo "  EmbeddedAgentVersion (updates)=${updates_embedded:-?}" >&2
  fi
}

verify_deployed_payload_integrity() {
  local agent_ver="" build_ver="" ps1="" updates_ps1=""
  build_ver="$(tr -d ' \t\r\n' < "$TARGET_DIR/BUILD_VERSION" 2>/dev/null || true)"
  agent_ver="$(tr -d ' \t\r\n' < "$TARGET_DIR/AGENT_VERSION" 2>/dev/null || true)"
  [ -n "$agent_ver" ] && [ -n "$build_ver" ] || return 1
  if [ "$build_ver" != "$agent_ver" ]; then
    # Server-only releases bump BUILD without AGENT; embedded fallback may lag further behind.
    if version_gt "$agent_ver" "$build_ver"; then
      return 1
    fi
  fi

  ps1="$TARGET_DIR/client/windows/collect_and_send.ps1"
  if ! collect_ps1_mojibake_ok "$ps1"; then
    return 1
  fi
  if ! collect_ps1_embedded_version_ok "$ps1" "$agent_ver"; then
    return 1
  fi

  updates_ps1="$TARGET_DIR/updates/client/windows/collect_and_send.ps1"
  if [ -f "$updates_ps1" ] \
    && ! collect_ps1_embedded_version_ok "$updates_ps1" "$agent_ver"; then
    return 1
  fi
  return 0
}

sync_version_files_if_embedded_ahead() {
  local build_ver="" agent_ver="" embedded="" remote_ref="" remote_bv="" remote_av=""
  local ps1="$TARGET_DIR/client/windows/collect_and_send.ps1"

  build_ver="$(tr -d ' \t\r\n' < "$TARGET_DIR/BUILD_VERSION" 2>/dev/null || true)"
  agent_ver="$(tr -d ' \t\r\n' < "$TARGET_DIR/AGENT_VERSION" 2>/dev/null || true)"
  embedded="$(collect_ps1_embedded_version "$ps1" 2>/dev/null || true)"
  [ -n "$build_ver" ] && [ "$build_ver" = "$agent_ver" ] || return 1
  [ -n "$embedded" ] && version_gt "$embedded" "$agent_ver" || return 1

  remote_ref="$(resolve_latest_main_sha main || true)"
  if ! is_full_git_sha "$remote_ref"; then
    return 1
  fi
  remote_bv="$(fetch_build_version_at_ref "$remote_ref")"
  remote_av="$(fetch_repo_text_at_ref AGENT_VERSION "$remote_ref")"
  [ -n "$remote_bv" ] && [ -n "$remote_av" ] && [ "$remote_bv" = "$remote_av" ] || return 1
  if [ "$remote_bv" = "$agent_ver" ]; then
    return 1
  fi
  if version_gt "$remote_bv" "$agent_ver" || [ "$remote_bv" = "$embedded" ]; then
    echo "Version-Dateien nachziehen: BUILD/AGENT ${agent_ver} -> ${remote_bv} (embedded=${embedded})..." >&2
    force_refresh_version_files "$remote_ref"
    mirror_update_payloads
    return 0
  fi
  return 1
}

repair_deploy_if_integrity_failed() {
  local repair_ref="" remote_av=""
  if verify_deployed_payload_integrity; then
    return 0
  fi

  if sync_version_files_if_embedded_ahead && verify_deployed_payload_integrity; then
    echo "Reparatur: BUILD/AGENT-Dateien nachgezogen (ohne Voll-Redeploy)." >&2
    return 0
  fi

  echo "WARNUNG: Deploy-Inkonsistenz (BUILD/AGENT/collect_and_send.ps1)." >&2
  explain_deploy_integrity_failure
  repair_ref="$(resolve_latest_main_sha main || true)"
  if ! is_full_git_sha "$repair_ref"; then
    repair_ref="$(probe_ref_with_matching_version_files "$REF" || true)"
  fi
  if ! is_full_git_sha "$repair_ref"; then
    echo "FEHLER: Integritaets-Reparatur nicht moeglich (kein Commit-SHA)." >&2
    return 1
  fi

  remote_av="$(fetch_repo_text_at_ref AGENT_VERSION "$repair_ref")"
  echo "Reparatur-Deploy von Ref ${repair_ref:0:12} (AGENT_VERSION=${remote_av:-?})..." >&2
  if ! redeploy_files_from_ref "$repair_ref"; then
    return 1
  fi
  if ! verify_deployed_payload_integrity; then
    echo "FEHLER: Nach Reparatur-Deploy weiterhin inkonsistent." >&2
    explain_deploy_integrity_failure
    return 1
  fi
  echo "Reparatur-Deploy erfolgreich."
  return 0
}

probe_ref_with_matching_version_files() {
  local candidate_ref="" remote_bv="" remote_av=""
  for candidate_ref in "$@"; do
    [ -n "$candidate_ref" ] || continue
    if ! is_full_git_sha "$candidate_ref"; then
      expanded="$(expand_deploy_ref "$candidate_ref" || true)"
      if is_full_git_sha "$expanded"; then
        candidate_ref="$expanded"
      else
        continue
      fi
    fi
    remote_bv="$(fetch_repo_text_at_ref BUILD_VERSION "$candidate_ref")"
    remote_av="$(fetch_repo_text_at_ref AGENT_VERSION "$candidate_ref")"
    if [ -n "$remote_bv" ] && [ "$remote_bv" = "$remote_av" ]; then
      printf '%s' "$candidate_ref"
      return 0
    fi
  done
  return 1
}

reconcile_deploy_to_latest_main() {
  local latest_sha="" remote_bv="" local_bv="" local_av="" sync_ref=""

  local_bv="$(tr -d ' \t\r\n' < "$TARGET_DIR/BUILD_VERSION" 2>/dev/null || true)"
  local_av="$(tr -d ' \t\r\n' < "$TARGET_DIR/AGENT_VERSION" 2>/dev/null || true)"

  latest_sha="$(resolve_latest_main_sha main || true)"
  if is_full_git_sha "$latest_sha"; then
    remote_bv="$(fetch_repo_text_at_ref BUILD_VERSION "$latest_sha")"
    if [ -n "$remote_bv" ] && [ "$remote_bv" != "$local_bv" ]; then
      echo "Nachziehen: lokal BUILD ${local_bv:-?}, repo/main ${latest_sha:0:12} hat $remote_bv – lade Dateien erneut..." >&2
      if redeploy_files_from_ref "$latest_sha"; then
        return 0
      fi
      echo "FEHLER: Nachziehen auf ${latest_sha:0:12} fehlgeschlagen." >&2
      return 1
    fi
  fi

  sync_ref="$(probe_ref_with_matching_version_files "$latest_sha" "$REF" || true)"

  if [ -z "$sync_ref" ] && [ "$local_bv" != "$local_av" ] && is_full_git_sha "$REF"; then
    echo "Nachziehen: BUILD ($local_bv) und AGENT ($local_av) lokal unterschiedlich – synchronisiere von $REF..." >&2
    if redeploy_files_from_ref "$REF"; then
      return 0
    fi
  fi

  if [ -z "$sync_ref" ]; then
    if [ "$local_bv" != "$local_av" ]; then
      echo "WARNUNG: BUILD ($local_bv) != AGENT ($local_av). git ls-remote/API nicht erreichbar – Commit-SHA pinnen." >&2
      echo "  Beispiel: export MONITORING_DEPLOY_SHA=a0f294e6b4e63acae71f4af2d7cfdeb8f1b2b34c" >&2
    fi
    return 0
  fi

  remote_bv="$(fetch_repo_text_at_ref BUILD_VERSION "$sync_ref")"
  if [ -n "$remote_bv" ] && [ "$remote_bv" = "$local_bv" ] && [ "$local_bv" = "$local_av" ]; then
    if [ "$REF" != "$sync_ref" ]; then
      REF="$sync_ref"
      echo "$REF" > "$TARGET_DIR/DEPLOYED_COMMIT_SHA"
    fi
    return 0
  fi

  echo "Nachziehen: lokal BUILD $local_bv / AGENT $local_av, Ziel-Ref ${sync_ref:0:12} hat $remote_bv – lade Dateien erneut..." >&2
  if ! redeploy_files_from_ref "$sync_ref"; then
    echo "FEHLER: Nachziehen auf ${sync_ref:0:12} fehlgeschlagen." >&2
    return 1
  fi
  return 0
}

# One ./pull-server-only.sh should suffice: re-resolve MAIN_HEAD_SHA and redeploy if BUILD still lags.
finalize_deploy_until_version_match() {
  local attempt=1 max_attempts=3
  local latest_sha="" remote_bv="" local_bv="" deployed_sha=""

  while [ "$attempt" -le "$max_attempts" ]; do
    latest_sha="$(resolve_latest_main_sha main || true)"
    if ! is_full_git_sha "$latest_sha"; then
      return 0
    fi
    local_bv="$(tr -d ' \t\r\n' < "$TARGET_DIR/BUILD_VERSION" 2>/dev/null || true)"
    remote_bv="$(fetch_build_version_at_ref "$latest_sha")"
    deployed_sha="$(tr -d ' \t\r\n' < "$TARGET_DIR/DEPLOYED_COMMIT_SHA" 2>/dev/null || true)"
    # BUILD-Gleichheit reicht (MAIN_HEAD_SHA-Nachzieh-Commits haben gleiche BUILD_VERSION).
    if [ -n "$remote_bv" ] && [ "$local_bv" = "$remote_bv" ]; then
      if [ "$deployed_sha" != "$latest_sha" ]; then
        echo "Version-Sync OK: BUILD $local_bv (deploy ${deployed_sha:0:12}, main-Ziel ${latest_sha:0:12})" >&2
      elif [ "$attempt" -gt 1 ]; then
        echo "Version-Sync OK: BUILD $local_bv @ ${latest_sha:0:12} (Versuch $attempt)" >&2
      fi
      REF="${deployed_sha:-$latest_sha}"
      return 0
    fi
    if [ "$attempt" -ge "$max_attempts" ]; then
      echo "WARNUNG: BUILD lokal ${local_bv:-?}, Ziel ${remote_bv:-?} @ ${latest_sha:0:12} – bitte Pull in 1–2 Min. erneut oder MONITORING_DEPLOY_SHA pinnen." >&2
      return 1
    fi
    echo "Version-Nachzug (${attempt}/${max_attempts}): lokal BUILD ${local_bv:-?} -> ${remote_bv:-?} @ ${latest_sha:0:12}..." >&2
    if redeploy_files_from_ref "$latest_sha"; then
      REF="$latest_sha"
      mirror_update_payloads
      repair_deploy_if_integrity_failed || true
    else
      echo "WARNUNG: Nachzug-Versuch $attempt fehlgeschlagen." >&2
    fi
    attempt=$((attempt + 1))
    sleep 1
  done
  return 0
}

bootstrap_pull_script_if_needed() {
  # Default: off. Bootstrap hat ein altes Skript via raw/main ueberschrieben (CDN) und exec beendete den Lauf.
  if [ "${MONITORING_BOOTSTRAP_PULL_SCRIPT:-0}" != "1" ]; then
    return 0
  fi

  local latest_sha=""
  local bootstrap_ref=""
  local script_path
  script_path="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || realpath "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")"
  local new_script="$TARGET_DIR/pull-server-only.sh.bootstrap"

  if is_valid_pull_script_file "$script_path"; then
    return 0
  fi

  latest_sha="$(resolve_latest_main_sha main || true)"
  bootstrap_ref="${MONITORING_DEPLOY_SHA:-$latest_sha}"
  if ! is_full_git_sha "$bootstrap_ref"; then
    echo "Bootstrap übersprungen: kein Commit-SHA (git ls-remote fehlgeschlagen)." >&2
    echo "  Manuell: curl -fsSL https://raw.githubusercontent.com/$OWNER_REPO/<SHA>/pull-server-only.sh -o $TARGET_DIR/pull-server-only.sh" >&2
    return 0
  fi

  if ! curl_raw_github "$(append_raw_cache_bust "https://raw.githubusercontent.com/$OWNER_REPO/$bootstrap_ref/pull-server-only.sh")" \
    -o "$new_script" 2>/dev/null; then
    echo "Bootstrap fehlgeschlagen: Download pull-server-only.sh ($bootstrap_ref)." >&2
    return 0
  fi
  chmod +x "$new_script"

  if ! is_valid_pull_script_file "$new_script"; then
    echo "Bootstrap fehlgeschlagen: heruntergeladene Datei ist kein gueltiges pull-server-only.sh." >&2
    rm -f "$new_script"
    return 0
  fi

  if [ "$script_path" != "$TARGET_DIR/pull-server-only.sh" ] || ! cmp -s "$new_script" "$TARGET_DIR/pull-server-only.sh" 2>/dev/null; then
    echo "Bootstrap: pull-server-only.sh wird aktualisiert (Ref ${bootstrap_ref:0:12}) ..."
    cp -f "$new_script" "$TARGET_DIR/pull-server-only.sh"
    chmod +x "$TARGET_DIR/pull-server-only.sh"
    echo "Bitte erneut ausfuehren: $TARGET_DIR/pull-server-only.sh"
    exit 0
  fi
  rm -f "$new_script"
}

download_repo_file() {
  local source_path="$1"
  local target_path="$2"
  local api_url="$GITHUB_API_BASE/contents/$source_path?ref=$REF"
  local api_url_main="$GITHUB_API_BASE/contents/$source_path?ref=main"
  local raw_url="$RAW_BASE/$source_path"
  local raw_url_main="https://raw.githubusercontent.com/$OWNER_REPO/main/$source_path"
  local allow_main_fallback=1
  mkdir -p "$(dirname "$target_path")"

  if is_full_git_sha "$REF"; then
    allow_main_fallback=0
  fi

  if [ "${MONITORING_PULL_USE_RAW_ONLY:-0}" = "1" ]; then
    if curl_raw_github "$(append_raw_cache_bust "$raw_url")" -o "$target_path"; then
      return 0
    fi
    if [ "$allow_main_fallback" -eq 1 ]; then
      curl_raw_github "$(append_raw_cache_bust "$raw_url_main")" -o "$target_path"
      return $?
    fi
    return 1
  fi

  if [ -n "$GITHUB_TOKEN" ]; then
    # Prefer pinned ref, then fallback to main/raw (API errors suppressed on stderr).
    if curl_github "application/vnd.github.raw" "$api_url" -o "$target_path" 2>/dev/null; then
      return 0
    fi
    if [ "$allow_main_fallback" -eq 1 ] \
      && curl_github "application/vnd.github.raw" "$api_url_main" -o "$target_path" 2>/dev/null; then
      return 0
    fi
    if curl_raw_github "$(append_raw_cache_bust "$raw_url")" -o "$target_path"; then
      return 0
    fi
    if [ "$allow_main_fallback" -eq 1 ]; then
      curl_raw_github "$(append_raw_cache_bust "$raw_url_main")" -o "$target_path"
      return $?
    fi
    return 1
  fi

  if curl_raw_github "$(append_raw_cache_bust "$raw_url")" -o "$target_path"; then
    return 0
  fi
  if [ "$allow_main_fallback" -eq 1 ]; then
    curl_raw_github "$(append_raw_cache_bust "$raw_url_main")" -o "$target_path"
    return $?
  fi
  return 1
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

print_github_unreachable_hint() {
  cat >&2 <<EOF
GitHub API (api.github.com) ist vom Server aus nicht erreichbar.
Typische Ursachen: Firewall, Proxy, DNS, oder ausgehender HTTPS-Block.

Pull-Skript per MAIN_HEAD_SHA holen (nur raw.githubusercontent.com):
  SHA=\$(curl -fsSL "https://raw.githubusercontent.com/$OWNER_REPO/main/MAIN_HEAD_SHA?_=\$(date +%s)")
  curl -fsSL "https://raw.githubusercontent.com/$OWNER_REPO/\${SHA}/pull-server-only.sh?_=\$(date +%s)" \\
    -o $TARGET_DIR/pull-server-only.sh
  chmod +x $TARGET_DIR/pull-server-only.sh
  $TARGET_DIR/pull-server-only.sh

Pruefen:
  curl -I --connect-timeout 5 https://raw.githubusercontent.com

Wenn auch raw blockiert ist: Dateien per rsync/scp vom Entwicklungsrechner kopieren.
EOF
}

enable_raw_main_fallback() {
  local branch_ref="${1:-main}"
  REF="$branch_ref"
  MONITORING_PULL_USE_RAW_ONLY=1
  export MONITORING_PULL_USE_RAW_ONLY
  echo "Deploy-Ref: $REF (Branch-Alias, raw.githubusercontent.com mit Cache-Bust)" >&2
  echo "Modus: MONITORING_PULL_USE_RAW_ONLY=1 (kein MONITORING_DEPLOY_SHA noetig)" >&2
}

_resolve_deploy_ref_from_github_api() {
  local fallback_ref="$1"
  COMMIT_META_JSON=""

  if ! COMMIT_META_JSON="$(curl_github "application/vnd.github+json" "$GITHUB_API_BASE/commits/$fallback_ref" 2>/dev/null)"; then
    return 1
  fi

  local sha=""
  sha="$(extract_full_sha_from_commit_json "$COMMIT_META_JSON" || true)"
  if ! is_full_git_sha "$sha"; then
    return 1
  fi

  REF="$sha"
  local github_commit_iso=""
  github_commit_iso="$(printf '%s\n' "$COMMIT_META_JSON" \
    | sed -n 's/.*"date":[[:space:]]*"\([0-9T:\-]\+Z\)".*/\1/p' \
    | head -n 1)"
  if [ -n "$github_commit_iso" ]; then
    GITHUB_COMMIT_TIME="$(date -u -d "$github_commit_iso" '+%d.%m.%y %H:%M UTC' 2>/dev/null || date -u -j -f '%Y-%m-%dT%H:%M:%SZ' "$github_commit_iso" '+%d.%m.%y %H:%M UTC' 2>/dev/null || echo "")"
  fi
  echo "Deploy-Ref: $REF (via GitHub API /commits/$fallback_ref)"
  return 0
}

resolve_deploy_ref() {
  local fallback_ref="${MONITORING_DEPLOY_REF:-main}"
  local latest_sha=""
  COMMIT_META_JSON=""

  if [ -n "${MONITORING_DEPLOY_SHA:-}" ]; then
    REF="$(normalize_sha_ref "$MONITORING_DEPLOY_SHA")"
    if [ -z "$REF" ] || ! is_hex_sha_ref "$REF"; then
      echo "WARNUNG: MONITORING_DEPLOY_SHA ungueltig oder leer (api.github.com blockiert?) – ignoriere Pin." >&2
      REF=""
    elif ! is_full_git_sha "$REF"; then
      expanded="$(expand_deploy_ref "$REF" || true)"
      if [ -n "$expanded" ]; then
        REF="$expanded"
      fi
    fi
    if [ "${MONITORING_PULL_USE_RAW_ONLY:-0}" != "1" ] && { ! is_full_git_sha "$REF" || is_hex_sha_ref "$REF"; }; then
      MONITORING_PULL_USE_RAW_ONLY=1
      export MONITORING_PULL_USE_RAW_ONLY
    fi
    if [ -n "$REF" ]; then
      echo "Deploy-Ref: $REF (MONITORING_DEPLOY_SHA, optional)"
      return 0
    fi
  fi

  latest_sha="$(resolve_latest_main_sha "$fallback_ref" || true)"
  if is_full_git_sha "$latest_sha"; then
    REF="$latest_sha"
    echo "Deploy-Ref: $REF (repo/$fallback_ref, automatisch – kein MONITORING_DEPLOY_SHA noetig)"
    _resolve_deploy_ref_from_github_api "$fallback_ref" >/dev/null 2>&1 || true
    pin_build="$(fetch_repo_text_at_ref BUILD_VERSION "$REF" || true)"
    if [ -n "$pin_build" ]; then
      echo "Ziel BUILD_VERSION @ Ref: $pin_build"
    fi
    return 0
  fi

  if _resolve_deploy_ref_from_github_api "$fallback_ref"; then
    return 0
  fi

  echo "WARNUNG: Commit-SHA fuer $fallback_ref nicht ermittelbar (git ls-remote / GitHub API)." >&2
  enable_raw_main_fallback "$fallback_ref"
  return 0
}

reexec_if_pull_script_missing_guardian_files "$@"

echo "pull-server-only.sh Version: $PULL_SCRIPT_VERSION (Manifest: ${PULL_FILES_MANIFEST:-?}, erwartet ${PULL_FILES_EXPECTED_COUNT} Deploy-Dateien)"
echo "Installiere Serverteil nach: $TARGET_DIR"
echo "Hinweis: Ein Lauf genuegt – bei CDN-Verzoegerung wird BUILD_VERSION automatisch nachgezogen." >&2

if [ "${MONITORING_PULL_USE_RAW_ONLY:-0}" = "1" ]; then
  echo "Hinweis: MONITORING_PULL_USE_RAW_ONLY=1 – SHA-Aufloesung eingeschraenkt. Fuer neuestes main: unset MONITORING_PULL_USE_RAW_ONLY" >&2
fi

if [ -n "${MONITORING_DEPLOY_SHA:-}" ]; then
  echo "Hinweis: MONITORING_DEPLOY_SHA ist gesetzt (${MONITORING_DEPLOY_SHA}) – entfernen fuer automatisch neuestes main." >&2
elif [ -f "$TARGET_ENV_FILE" ] && grep -q '^MONITORING_DEPLOY_SHA=' "$TARGET_ENV_FILE" 2>/dev/null; then
  echo "Hinweis: $TARGET_ENV_FILE enthaelt MONITORING_DEPLOY_SHA (wird nicht mehr automatisch geladen)." >&2
  echo "  Nur aktiv per: export MONITORING_DEPLOY_SHA=<sha>" >&2
fi

upgrade_local_pull_script_from_main "$@"
bootstrap_pull_script_if_needed
echo "Starte Deploy (Ref wird ermittelt) ..."

# Speed/strictness tuning:
# - VERIFY_SYNC=1 enables costly re-download + hash verification.
# - MAX_PARALLEL_DOWNLOADS controls concurrent downloads.
VERIFY_SYNC="${VERIFY_SYNC:-0}"
MAX_PARALLEL_DOWNLOADS="${MAX_PARALLEL_DOWNLOADS:-8}"

mkdir -p "$TARGET_DIR/server/static/icons" "$TARGET_DIR/server/static/vendor" "$TARGET_DIR/server/data" "$TARGET_DIR/updates/client/windows" "$TARGET_DIR/updates/client/linux"

GITHUB_COMMIT_TIME=""
resolve_deploy_ref
if [ -z "${REF:-}" ]; then
  echo "FEHLER: Deploy-Ref leer nach resolve_deploy_ref." >&2
  exit 1
fi
if ! is_full_git_sha "$REF"; then
  expanded="$(expand_deploy_ref "$REF" || true)"
  if [ -n "$expanded" ]; then
    REF="$expanded"
  fi
fi
ensure_deploy_ref_is_latest_commit

if ! is_full_git_sha "$REF"; then
  if is_hex_sha_ref "$REF" && probe_raw_ref_download "$REF"; then
    echo "Deploy-Pin: $REF (Kurz-SHA oder Branch, raw.githubusercontent.com)"
  elif is_branch_ref "$REF"; then
    echo "Deploy-Pin: $REF (Branch – sollte durch ensure_deploy_ref abgefangen sein)" >&2
  else
    local_deployed="$(tr -d ' \t\r\n' < "$TARGET_DIR/DEPLOYED_COMMIT_SHA" 2>/dev/null || true)"
    echo "FEHLER: Deploy-Ref '$REF' ist weder aufloesbar noch als raw-Ref erreichbar." >&2
    if is_hex_sha_ref "$REF"; then
      echo "  Tipp: Kurz-SHA (7–40 Hex) oder MONITORING_DEPLOY_REF=main – kein 40-stelliger SHA zwingend." >&2
    fi
    if [ -n "$local_deployed" ] && is_full_git_sha "$local_deployed"; then
      echo "  Letzter erfolgreicher Deploy: $local_deployed" >&2
    fi
    echo "  Optional pinnen: export MONITORING_DEPLOY_SHA=<commit|kurz-sha>" >&2
    exit 1
  fi
else
  echo "Deploy-Pin: $REF"
fi
if is_full_git_sha "$REF"; then
  if [ -z "${COMMIT_META_JSON:-}" ] || [ "$(extract_full_sha_from_commit_json "$COMMIT_META_JSON" || true)" != "$REF" ]; then
    COMMIT_META_JSON="$(fetch_commit_meta_json_for_ref "$REF" || true)"
  fi
fi
RAW_BASE="https://raw.githubusercontent.com/$OWNER_REPO/$REF"

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

export -f download_file download_repo_file checksum_file curl_github curl_raw_github \
  append_raw_cache_bust fetch_repo_text_at_ref fetch_build_version_at_ref pick_best_sha_by_build_version \
  is_full_git_sha is_branch_ref resolve_branch_ref_to_commit_sha resolve_latest_main_sha \
  force_refresh_version_files redeploy_files_from_ref reconcile_deploy_to_latest_main \
  finalize_deploy_until_version_match mirror_update_payloads verify_deployed_payload_integrity \
  repair_deploy_if_integrity_failed
export RAW_BASE TARGET_DIR GITHUB_COMMIT_TIME GITHUB_TOKEN GITHUB_API_BASE REF OWNER_REPO CURL_CONNECT_TIMEOUT CURL_MAX_TIME MONITORING_PULL_USE_RAW_ONLY

FILES_LIST="
server/receiver.py
server/ingest_inbox.py
server/external_monitors.py
server/mfa.py
server/static/index.html
server/static/app.js
server/static/styles.css
server/static/dashboard-redesign.css
server/static/sw.js
server/static/manifest.json
server/static/manifest-mobile.json
server/static/mobile-common.js
server/static/mobile-alerts.html
server/static/mobile-alerts.css
server/static/mobile-alerts.js
server/static/vendor/html2canvas.min.js
server/static/mobile-alerts-mockup.html
server/static/icons/sap.png
BUILD_VERSION
AGENT_VERSION
requirements.txt
MAIN_HEAD_SHA
openapi.yaml
scripts/watch-inventur-job.sh
scripts/check-monitoring-health.sh
scripts/dedupe-ingest-reports.sh
scripts/deploy-agent-guardian.sh
client/windows/collect_and_send.ps1
client/windows/collect_and_scan_sap_tables.ps1
client/windows/bootstrap_agent.ps1
client/windows/install_agent.ps1
client/windows/self_update.ps1
client/windows/script_guardian.ps1
client/windows/setup_harvest_sql_user.ps1
client/windows/probe_sap_services.ps1
client/linux/collect_and_send.sh
client/linux/install_agent.sh
client/linux/self_update.sh
client/linux/script_guardian.sh
client/linux/monitor_probe.sh
client/linux/setup_harvest_hana_user.sql
client/windows/monitor_probe.ps1
"

# Parallele downloads: standardmaessig bis zu 8 gleichzeitig
FILE_COUNT="$(printf '%s\n' "$FILES_LIST" | sed '/^$/d' | wc -l | tr -d ' ')"
echo "Lade ${FILE_COUNT} Dateien parallel (max ${MAX_PARALLEL_DOWNLOADS} gleichzeitig)..."
if ! printf '%s\n' "$FILES_LIST" | sed '/^$/d' | xargs -P "$MAX_PARALLEL_DOWNLOADS" -I {} bash -c 'download_file "{}" "$TARGET_DIR/{}"'; then
  echo "Fehler bei parallelen Downloads" >&2
  exit 1
fi
echo "Dateien geladen ✓"

reconcile_deploy_to_latest_main
finalize_deploy_until_version_match || true
force_refresh_version_files "$REF"

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
  echo "Verifikation erfolgreich ✓ Alle Dateien entsprechen Commit $REF"
else
  echo "Verifikation uebersprungen (VERIFY_SYNC=0, Standard fuer schnellen Pull)"
fi

# Mirror update payloads to /updates so agents can update from SERVER_URL.
mirror_update_payloads
repair_deploy_if_integrity_failed || true
if [ ! -f "$TARGET_DIR/server/external_monitors.py" ]; then
  echo "FEHLER: server/external_monitors.py fehlt – receiver.py startet nicht (v1.8.0 Deploy-Luecke)." >&2
  echo "Bitte pull-server-only.sh erneut ausfuehren (>= v1.8.1)." >&2
  exit 1
fi
if [ ! -f "$TARGET_DIR/server/mfa.py" ]; then
  echo "FEHLER: server/mfa.py fehlt – receiver.py startet nicht (v1.8.78+ MFA)." >&2
  echo "Bitte pull-server-only.sh erneut ausfuehren." >&2
  exit 1
fi
if [ -f "$TARGET_DIR/scripts/watch-inventur-job.sh" ]; then
  chmod 0755 "$TARGET_DIR/scripts/watch-inventur-job.sh"
fi
if [ -f "$TARGET_DIR/scripts/check-monitoring-health.sh" ]; then
  chmod 0755 "$TARGET_DIR/scripts/check-monitoring-health.sh"
fi
if [ -f "$TARGET_DIR/scripts/dedupe-ingest-reports.sh" ]; then
  chmod 0755 "$TARGET_DIR/scripts/dedupe-ingest-reports.sh"
fi
if [ -f "$TARGET_DIR/client/linux/monitor_probe.sh" ]; then
  chmod 0755 "$TARGET_DIR/client/linux/monitor_probe.sh"
fi

# Selbst-Update am Ende: immer branch main (nie REF=a9edd8e o.ae. – sonst 29-Dateien-Skript zurueck).
NEW_PULL_SCRIPT="$TARGET_DIR/pull-server-only.sh.new"
if install_pull_script_from_main_branch "$NEW_PULL_SCRIPT"; then
  mv -f "$NEW_PULL_SCRIPT" "$TARGET_DIR/pull-server-only.sh"
  echo "Self-Update abgeschlossen: pull-server-only.sh von branch main (Manifest ${PULL_FILES_MANIFEST:-?})"
else
  rm -f "$NEW_PULL_SCRIPT"
  echo "WARNUNG: pull-server-only.sh Self-Update von main fehlgeschlagen (lokale Kopie unveraendert)." >&2
fi

ensure_guardian_update_files_present() {
  local missing=0 rel dest
  for rel in \
    "client/linux/script_guardian.sh" \
    "client/windows/script_guardian.ps1" \
    "updates/client/linux/script_guardian.sh" \
    "updates/client/windows/script_guardian.ps1"; do
    dest="$TARGET_DIR/$rel"
    if [ -s "$dest" ]; then
      continue
    fi
    missing=1
    echo "Guardian fehlt, lade nach: $rel" >&2
    mkdir -p "$(dirname "$dest")"
    if ! download_repo_file "$rel" "$dest"; then
      if ! curl_raw_github "$(append_raw_cache_bust "https://raw.githubusercontent.com/$OWNER_REPO/main/$rel")" \
        -o "$dest" 2>/dev/null; then
        echo "FEHLER: Guardian-Datei konnte nicht geladen werden: $rel" >&2
        return 1
      fi
    fi
    if [ "$rel" = "client/linux/script_guardian.sh" ] || [ "$rel" = "updates/client/linux/script_guardian.sh" ]; then
      chmod 0755 "$dest" 2>/dev/null || true
    fi
  done
  if [ "$missing" -eq 1 ]; then
    echo "Guardian-Dateien nachinstalliert." >&2
  fi
  return 0
}

ensure_guardian_update_files_present || true

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

ICON_NAMES_FILE="$TMP_DIR/icon_names.txt"
: > "$ICON_NAMES_FILE"

if [ "${MONITORING_PULL_USE_RAW_ONLY:-0}" != "1" ]; then
  ICONS_API="$GITHUB_API_BASE/contents/server/static/icons?ref=$REF"
  ICONS_JSON="$TMP_DIR/icons.json"
  if curl_github "application/vnd.github+json" "$ICONS_API" -o "$ICONS_JSON" 2>/dev/null; then
    grep -o '"name":[[:space:]]*"[^"]*\.png"' "$ICONS_JSON" \
      | cut -d '"' -f 4 \
      | sort -u > "$ICON_NAMES_FILE"
  else
    echo "WARNUNG: Icon-Liste via API nicht verfuegbar – ueberspringe dynamische Icon-Sync." >&2
  fi
else
  echo "Icon-Sync uebersprungen (MONITORING_PULL_USE_RAW_ONLY=1)."
fi

if [ -s "$ICON_NAMES_FILE" ]; then
  ICON_COUNT="$(wc -l < "$ICON_NAMES_FILE" | tr -d ' ')"
  echo "Lade ${ICON_COUNT} PNG-Icons parallel..."
  if ! sed 's#^#server/static/icons/#' "$ICON_NAMES_FILE" | xargs -P "$MAX_PARALLEL_DOWNLOADS" -I {} bash -c 'download_file "{}" "$TARGET_DIR/{}"'; then
    echo "Fehler bei Icon-Downloads (nicht kritisch)" >&2
  fi
  echo "Icons geladen ✓"
else
  echo "Keine zusaetzlichen Icons zu laden."
fi
echo "$REF" > "$TARGET_DIR/DEPLOYED_COMMIT_SHA"
DEPLOY_TIME="$(date '+%d.%m.%y %H:%M')"

if is_full_git_sha "$REF"; then
  force_refresh_version_files "$REF"
fi
finalize_deploy_until_version_match || true
repair_deploy_if_integrity_failed || true

print_deploy_consistency_summary() {
  local local_bv="" local_av="" remote_bv="" remote_av="" remote_ref=""
  local deployed_sha="" pull_version="" pull_manifest="" guardian_ok=1 rel dest
  local file_count=0

  local_bv="$(tr -d ' \t\r\n' < "$TARGET_DIR/BUILD_VERSION" 2>/dev/null || true)"
  local_av="$(tr -d ' \t\r\n' < "$TARGET_DIR/AGENT_VERSION" 2>/dev/null || true)"
  deployed_sha="$(tr -d ' \t\r\n' < "$TARGET_DIR/DEPLOYED_COMMIT_SHA" 2>/dev/null || true)"
  file_count="$(printf '%s\n' "$FILES_LIST" | sed '/^$/d' | wc -l | tr -d ' ')"
  pull_version="$(pull_script_version_from_file "$TARGET_DIR/pull-server-only.sh" 2>/dev/null || true)"
  pull_manifest="$(pull_script_manifest_from_file "$TARGET_DIR/pull-server-only.sh" 2>/dev/null || true)"

  invalidate_deploy_main_sha_cache
  remote_ref="$(resolve_latest_main_sha main || true)"
  if is_full_git_sha "$remote_ref"; then
    remote_bv="$(fetch_build_version_at_ref "$remote_ref")"
    remote_av="$(fetch_repo_text_at_ref AGENT_VERSION "$remote_ref")"
  fi

  for rel in \
    "client/linux/script_guardian.sh" \
    "updates/client/linux/script_guardian.sh" \
    "client/windows/script_guardian.ps1" \
    "updates/client/windows/script_guardian.ps1"; do
    dest="$TARGET_DIR/$rel"
    if [ ! -s "$dest" ]; then
      guardian_ok=0
      break
    fi
  done

  echo "--- Deploy-Konsistenz ---"
  echo "Pull-Skript lokal: Version ${pull_version:-?} / Manifest ${pull_manifest:-?} (erwartet ${PULL_FILES_EXPECTED_COUNT} Dateien, geladen ${file_count})"
  if pull_script_has_guardian_files_list "$TARGET_DIR/pull-server-only.sh"; then
    echo "Pull-Skript FILES_LIST: Guardian enthalten"
  else
    echo "WARNUNG: Pull-Skript FILES_LIST ohne Guardian – curl main/pull-server-only.sh" >&2
  fi
  if [ "$guardian_ok" -eq 1 ]; then
    echo "Guardian-Updates: vorhanden"
  else
    echo "WARNUNG: Guardian-Updates: fehlen unter $TARGET_DIR/updates/client/" >&2
  fi
  echo "Deploy-Commit: ${deployed_sha:-$REF}"
  if is_full_git_sha "$remote_ref"; then
    echo "repo/main Ziel: ${remote_ref:0:12} (BUILD ${remote_bv:-?})"
  fi
  echo "BUILD lokal: ${local_bv:-?} | AGENT lokal: ${local_av:-?}"
  if [ -n "$local_bv" ] && [ -n "$local_av" ] && [ "$local_bv" != "$local_av" ]; then
    if version_gt "$local_av" "$local_bv"; then
      echo "WARNUNG: AGENT lokal ($local_av) neuer als BUILD ($local_bv)." >&2
    else
      echo "Hinweis: BUILD ($local_bv) vor AGENT ($local_av) – normal bei Server-only-Release."
    fi
  fi
  if [ -n "$remote_bv" ] && [ -n "$local_bv" ] && [ "$local_bv" = "$remote_bv" ]; then
    echo "Version-Status: AKTUELL (BUILD $local_bv)"
  elif [ -n "$remote_bv" ] && [ -n "$local_bv" ]; then
    echo "WARNUNG: Version-Status: BUILD lokal $local_bv, repo/main $remote_bv – Pull erneut oder MONITORING_DEPLOY_SHA pinnen." >&2
  else
    echo "Version-Status: UNBEKANNT (repo/main BUILD nicht ermittelbar)"
  fi
  if [ -n "$deployed_sha" ] && [ -n "$remote_ref" ] && [ "$deployed_sha" != "$remote_ref" ] \
    && [ -n "$local_bv" ] && [ -n "$remote_bv" ] && [ "$local_bv" = "$remote_bv" ]; then
    echo "Hinweis: Commit-SHA weicht ab, BUILD ist gleich (typisch nach MAIN_HEAD_SHA-Nachzieh-Commit)." >&2
  fi
  echo "-------------------------"
}

DEPLOYED_SHA="$(tr -d ' \t\r\n' < "$TARGET_DIR/DEPLOYED_COMMIT_SHA" 2>/dev/null || true)"

if [ -n "$GITHUB_COMMIT_TIME" ]; then
  echo "Fertig. Deploy-Commit: $REF [GitHub: $GITHUB_COMMIT_TIME | Deploy: $DEPLOY_TIME]"
else
  echo "Fertig. Deploy-Commit: $REF [Deploy: $DEPLOY_TIME]"
fi

print_deploy_consistency_summary

LOCAL_BUILD_VERSION="$(tr -d ' \t\r\n' < "$TARGET_DIR/BUILD_VERSION" 2>/dev/null || true)"
LOCAL_AGENT_VERSION="$(tr -d ' \t\r\n' < "$TARGET_DIR/AGENT_VERSION" 2>/dev/null || true)"

echo "BUILD_VERSION deployiert: ${LOCAL_BUILD_VERSION:-?}"
echo "AGENT_VERSION deployiert: ${LOCAL_AGENT_VERSION:-?}"
echo ""
print_deployed_commit_message_summary "${DEPLOYED_SHA:-$REF}"
echo ""
if is_branch_ref "${REF:-}"; then
  echo "WARNUNG: Deploy lief ueber Branch-Alias '$REF' – fuer reproduzierbare Deploys Commit-SHA nutzen." >&2
fi
if ! is_full_git_sha "$REF" && [ -z "$LATEST_SHA_AFTER" ]; then
  echo "Hinweis: Commit-SHA unbekannt – Deploy lief ueber Branch $REF. Fuer Pin optional MONITORING_DEPLOY_SHA setzen." >&2
fi
if ! grep -q 'print_deployed_commit_message_summary' "$TARGET_DIR/pull-server-only.sh" 2>/dev/null; then
  echo "WARNUNG: $TARGET_DIR/pull-server-only.sh ohne Commit-Text-Funktion – Skript von main aktualisieren und Pull erneut starten." >&2
fi
if ! pull_script_has_guardian_files_list "$TARGET_DIR/pull-server-only.sh"; then
  echo "WARNUNG: $TARGET_DIR/pull-server-only.sh ist veraltet (keine Guardian-Dateien in FILES_LIST)." >&2
  echo "         Einmalig: curl -fsSL 'https://raw.githubusercontent.com/$OWNER_REPO/main/pull-server-only.sh' -o $TARGET_DIR/pull-server-only.sh" >&2
fi
if [ -f "$TARGET_DIR/server/static/index.html" ]; then
  if rg -q 'runInventoryChangelogRebuildButton' "$TARGET_DIR/server/static/index.html" 2>/dev/null; then
    echo "UI-Check: Inventur/Abbrechen-Buttons in index.html vorhanden"
  else
    echo "WARNUNG: index.html ohne Inventur/Abbrechen-Buttons (alter Stand?)." >&2
  fi
fi
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
if [ -f "$TARGET_DIR/requirements.txt" ]; then
  if ! "$TARGET_DIR/.venv/bin/pip" install --quiet --upgrade -r "$TARGET_DIR/requirements.txt"; then
    echo "WARNUNG: pip install -r requirements.txt fehlgeschlagen (MFA-QR ggf. ohne qrcode)."
    "$TARGET_DIR/.venv/bin/pip" install --quiet --upgrade cairosvg pywebpush || true
  fi
else
  "$TARGET_DIR/.venv/bin/pip" install --quiet --upgrade cairosvg pywebpush
fi

# --- EnvironmentFile anlegen (nur wenn noch nicht vorhanden) ---
ENV_FILE="$TARGET_DIR/monitoring.env"
if [ ! -f "$ENV_FILE" ]; then
    cat > "$ENV_FILE" <<'EOF'
# Monitoring Server – Umgebungsvariablen
# Diese Datei bleibt nur auf dem Server und kommt NIE ins Git!
MONITORING_API_KEY=HIER_API_KEY_EINTRAGEN
MONITORING_API_KEY_GRACE_ALLOW_KNOWN_HOSTS=0
MONITORING_GITHUB_TOKEN=HIER_GITHUB_TOKEN_EINTRAGEN
# MONITORING_WEB_PUSH_VAPID_PUBLIC_KEY=HIER_PUBLIC_KEY
# MONITORING_WEB_PUSH_VAPID_PRIVATE_KEY=HIER_PRIVATE_KEY
# MONITORING_WEB_PUSH_VAPID_SUBJECT=mailto:it@example.com
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
Environment=PYTHONUNBUFFERED=1
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

show_monitoring_service_brief() {
  local state sub main_pid mem_mb
  state="$(systemctl is-active monitoring 2>/dev/null || echo unknown)"
  sub="$(systemctl show monitoring -p SubState --value 2>/dev/null || echo "?")"
  main_pid="$(systemctl show monitoring -p MainPID --value 2>/dev/null || echo "?")"
  mem_mb="$(
    systemctl show monitoring -p MemoryCurrent --value 2>/dev/null \
      | awk '{ if ($1 > 0) printf "%.0f", $1 / 1024 / 1024; else print "?" }'
  )"
  echo "  monitoring: ${state} (${sub}), PID ${main_pid}, RAM ~${mem_mb}M"
}

changelog_jobs_blocking_restart() {
  local db_path="$TARGET_DIR/server/data/monitoring.db"
  if [ ! -f "$db_path" ] || ! command -v sqlite3 >/dev/null 2>&1; then
    return 1
  fi
  local running_count pending_count
  running_count="$(sqlite3 "$db_path" \
    "SELECT COUNT(*) FROM changelog_rebuild_jobs WHERE status = 'running';" 2>/dev/null || echo 0)"
  pending_count="$(sqlite3 "$db_path" \
    "SELECT COUNT(*) FROM changelog_rebuild_jobs WHERE status = 'pending';" 2>/dev/null || echo 0)"
  if [ "${running_count:-0}" -gt 0 ] || [ "${pending_count:-0}" -gt 0 ]; then
    sqlite3 -header -column "$db_path" \
      "SELECT id, status, COALESCE(job_mode, 'rebuild') AS mode,
              json_extract(result_json, '\$.progress.reports_scanned') AS reports,
              json_extract(result_json, '\$.progress.reports_total') AS total
       FROM changelog_rebuild_jobs
       WHERE status IN ('running', 'pending')
       ORDER BY id DESC
       LIMIT 5;" 2>/dev/null || true
    return 0
  fi
  return 1
}

SKIP_MONITORING_RESTART=0
if [ "${MONITORING_FORCE_RESTART:-0}" = "1" ]; then
  echo "MONITORING_FORCE_RESTART=1 – Neustart trotz laufendem Changelog-Job." >&2
elif changelog_jobs_blocking_restart; then
  SKIP_MONITORING_RESTART=1
  echo "" >&2
  echo "WARNUNG: Inventur/Rebuild-Job läuft oder ist pending – monitoring wird NICHT neu gestartet." >&2
  echo "  Ein Restart würde den Job abbrechen (Changelog-Tabellen ggf. inkonsistent)." >&2
  echo "  Dateien auf dem Server sind aktualisiert (BUILD_VERSION=${LOCAL_BUILD_VERSION:-?})." >&2
  echo "  Nach Job-Ende: sudo systemctl restart monitoring" >&2
  echo "  Nur UI-Änderungen (app.js): Hard-Refresh im Browser reicht bis zum Restart." >&2
  echo "  Erzwingen (Job bricht ab): MONITORING_FORCE_RESTART=1 $TARGET_DIR/pull-server-only.sh" >&2
fi

if [ "$SKIP_MONITORING_RESTART" = "1" ]; then
  echo "monitoring-Service läuft weiter mit bisherigem Prozess (kein Restart)."
  show_monitoring_service_brief
else
  echo "Versuche monitoring-Service neu zu starten ..."
  if systemctl restart monitoring; then
    echo "✓ monitoring wurde neu gestartet"
    show_monitoring_service_brief
    echo "  (Details: systemctl status monitoring --no-pager -n 20)"
  else
    echo "✗ monitoring konnte nicht automatisch neu gestartet werden" >&2
    echo "  Bitte manuell ausführen: systemctl restart monitoring" >&2
  fi
fi

echo "Deploy-Verifikation im Browser (nach Hard-Refresh Strg+Shift+R):"
echo "  fetch('/BUILD_VERSION').then(r=>r.text()).then(console.log)  // erwartet: $LOCAL_BUILD_VERSION"
echo ""
echo "Nächste Schritte (falls nötig):"
echo "  1. API-Key prüfen:     nano $ENV_FILE"
echo "  2. Service-Status:     systemctl status monitoring"
