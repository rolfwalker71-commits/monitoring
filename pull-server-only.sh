#!/usr/bin/env bash
set -euo pipefail

on_pull_script_error() {
  local exit_code=$?
  echo "FEHLER in pull-server-only.sh (Zeile ${BASH_LINENO[0]:-?}, exit $exit_code)" >&2
  exit "$exit_code"
}
trap on_pull_script_error ERR

# Bump when pull-server-only.sh logic changes (shown at start for deploy verification).
PULL_SCRIPT_VERSION="20260604m"

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
  local stamp
  stamp="$(date +%s)"
  if [[ "$url" == *"?"* ]]; then
    printf '%s&_=%s' "$url" "$stamp"
  else
    printf '%s?_=%s' "$url" "$stamp"
  fi
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
      echo "Deploy-Pin: ${REF:0:12} (${ref_bv:-?}) -> ${latest_sha:0:12} (${remote_bv:-?})" >&2
    fi
  elif is_branch_ref "$REF"; then
    echo "Deploy-Pin: ${latest_sha:0:12} (main HEAD, BUILD ${remote_bv:-?})" >&2
  fi

  REF="$latest_sha"
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
  local sha=""
  sha="$(curl_raw_github "$(append_raw_cache_bust "https://raw.githubusercontent.com/$OWNER_REPO/main/MAIN_HEAD_SHA")" 2>/dev/null \
    | tr -d ' \t\r\n' || true)"
  if is_full_git_sha "$sha"; then
    echo "main-SHA via raw MAIN_HEAD_SHA: ${sha:0:12}" >&2
    printf '%s' "$sha"
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

resolve_latest_main_sha() {
  local branch_ref="${1:-main}"
  local sha=""

  sha="$(resolve_latest_main_sha_via_raw_main_head_file || true)"
  if is_full_git_sha "$sha"; then
    printf '%s' "$sha"
    return 0
  fi

  sha="$(resolve_latest_main_sha_via_git || true)"
  if is_full_git_sha "$sha"; then
    printf '%s' "$sha"
    return 0
  fi

  if github_api_reachable; then
    sha="$(resolve_latest_main_sha_via_github_api "$branch_ref" || true)"
    if is_full_git_sha "$sha"; then
      printf '%s' "$sha"
      return 0
    fi

    sha="$(resolve_latest_main_sha_via_plain_curl "$branch_ref" || true)"
    if is_full_git_sha "$sha"; then
      echo "main-SHA via api.github.com (plain curl): ${sha:0:12}" >&2
      printf '%s' "$sha"
      return 0
    fi
  else
    echo "Hinweis: api.github.com nicht erreichbar – nutze raw MAIN_HEAD_SHA / raw/main." >&2
  fi

  sha="$(resolve_latest_main_sha_via_raw_main_head_file || true)"
  if is_full_git_sha "$sha"; then
    printf '%s' "$sha"
    return 0
  fi
  return 1
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

upgrade_local_pull_script_from_main() {
  if [ "${MONITORING_SKIP_PULL_SCRIPT_UPGRADE:-0}" = "1" ]; then
    return 0
  fi

  local latest_sha="" local_script="" remote_script=""
  latest_sha="$(resolve_latest_main_sha main || true)"
  if ! is_full_git_sha "$latest_sha"; then
    return 0
  fi

  local_script="$TARGET_DIR/pull-server-only.sh"
  if [ ! -f "$local_script" ]; then
    local_script="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || realpath "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")"
  fi

  remote_script="$(mktemp "${TMPDIR:-/tmp}/pull-server-only.XXXXXX")"
  if ! curl_raw_github "$(append_raw_cache_bust "https://raw.githubusercontent.com/$OWNER_REPO/$latest_sha/pull-server-only.sh")" \
    -o "$remote_script" 2>/dev/null; then
    rm -f "$remote_script"
    return 0
  fi
  if ! is_valid_pull_script_file "$remote_script"; then
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
  echo "pull-server-only.sh aktualisiert (main ${latest_sha:0:12}) – Deploy startet neu..."
  exec "$local_script" "$@"
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
  chmod 0755 "$TARGET_DIR/updates/client/linux/collect_and_send.sh" "$TARGET_DIR/updates/client/linux/install_agent.sh" "$TARGET_DIR/updates/client/linux/self_update.sh" 2>/dev/null || true
}

verify_deployed_payload_integrity() {
  local agent_ver="" expected_embedded="" ps1=""
  agent_ver="$(tr -d ' \t\r\n' < "$TARGET_DIR/AGENT_VERSION" 2>/dev/null || true)"
  [ -n "$agent_ver" ] || return 1

  ps1="$TARGET_DIR/client/windows/collect_and_send.ps1"
  if [ ! -f "$ps1" ]; then
    return 1
  fi
  expected_embedded="\$EmbeddedAgentVersion = '$agent_ver'"
  if ! grep -qF "$expected_embedded" "$ps1" 2>/dev/null; then
    return 1
  fi
  if grep -q 'function Get-AngLogMojibakeScore' "$ps1" 2>/dev/null \
    && ! grep -q '\[char\]0x00C3' "$ps1" 2>/dev/null; then
    return 1
  fi

  if [ -f "$TARGET_DIR/updates/client/windows/collect_and_send.ps1" ] \
    && ! grep -qF "$expected_embedded" "$TARGET_DIR/updates/client/windows/collect_and_send.ps1" 2>/dev/null; then
    return 1
  fi
  return 0
}

repair_deploy_if_integrity_failed() {
  local repair_ref="" remote_av=""
  if verify_deployed_payload_integrity; then
    return 0
  fi

  echo "WARNUNG: Deploy-Inkonsistenz (AGENT_VERSION passt nicht zu collect_and_send.ps1)." >&2
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

echo "pull-server-only.sh Version: $PULL_SCRIPT_VERSION"
echo "Installiere Serverteil nach: $TARGET_DIR"

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

mkdir -p "$TARGET_DIR/server/static/icons" "$TARGET_DIR/server/data" "$TARGET_DIR/updates/client/windows" "$TARGET_DIR/updates/client/linux"

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
  append_raw_cache_bust fetch_repo_text_at_ref is_full_git_sha is_branch_ref \
  resolve_branch_ref_to_commit_sha resolve_latest_main_sha \
  force_refresh_version_files redeploy_files_from_ref reconcile_deploy_to_latest_main \
  mirror_update_payloads verify_deployed_payload_integrity repair_deploy_if_integrity_failed
export RAW_BASE TARGET_DIR GITHUB_COMMIT_TIME GITHUB_TOKEN GITHUB_API_BASE REF OWNER_REPO CURL_CONNECT_TIMEOUT CURL_MAX_TIME MONITORING_PULL_USE_RAW_ONLY

FILES_LIST="
server/receiver.py
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
server/static/mobile-alerts-mockup.html
server/static/icons/sap.png
BUILD_VERSION
AGENT_VERSION
MAIN_HEAD_SHA
openapi.yaml
scripts/watch-inventur-job.sh
client/windows/collect_and_send.ps1
client/windows/collect_and_scan_sap_tables.ps1
client/windows/bootstrap_agent.ps1
client/windows/install_agent.ps1
client/windows/self_update.ps1
client/windows/setup_harvest_sql_user.ps1
client/windows/probe_sap_services.ps1
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

reconcile_deploy_to_latest_main
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
repair_deploy_if_integrity_failed
if [ -f "$TARGET_DIR/scripts/watch-inventur-job.sh" ]; then
  chmod 0755 "$TARGET_DIR/scripts/watch-inventur-job.sh"
fi

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

LATEST_META_AFTER="$(curl_github "application/vnd.github+json" "$GITHUB_API_BASE/commits/main" || true)"
LATEST_SHA_AFTER="$(extract_full_sha_from_commit_json "$LATEST_META_AFTER" || true)"
if [ -z "$LATEST_SHA_AFTER" ]; then
  LATEST_SHA_AFTER="$(resolve_latest_main_sha main || true)"
fi

if is_full_git_sha "$REF"; then
  force_refresh_version_files "$REF"
fi
LOCAL_BUILD_VERSION="$(tr -d ' \t\r\n' < "$TARGET_DIR/BUILD_VERSION" 2>/dev/null || true)"
if [ -n "$LATEST_SHA_AFTER" ] && is_full_git_sha "$LATEST_SHA_AFTER"; then
  REMOTE_LATEST_BV="$(fetch_repo_text_at_ref BUILD_VERSION "$LATEST_SHA_AFTER")"
  if [ -n "$REMOTE_LATEST_BV" ] && [ "$REMOTE_LATEST_BV" != "$LOCAL_BUILD_VERSION" ]; then
    echo "Nachziehen: BUILD_VERSION lokal ${LOCAL_BUILD_VERSION:-?}, main ${LATEST_SHA_AFTER:0:12} hat $REMOTE_LATEST_BV – erzwinge Voll-Deploy..." >&2
    if redeploy_files_from_ref "$LATEST_SHA_AFTER"; then
      REF="$LATEST_SHA_AFTER"
      LOCAL_BUILD_VERSION="$REMOTE_LATEST_BV"
      mirror_update_payloads
      repair_deploy_if_integrity_failed
    fi
  fi
fi
if [ -n "$LATEST_SHA_AFTER" ] && [ "$LATEST_SHA_AFTER" != "$REF" ]; then
  echo "Hinweis: repo/main (${LATEST_SHA_AFTER:0:12}) ist neuer als Deploy-Ref (${REF:0:12}) – ziehe Dateien nach..." >&2
  if redeploy_files_from_ref "$LATEST_SHA_AFTER"; then
    REF="$LATEST_SHA_AFTER"
    mirror_update_payloads
    repair_deploy_if_integrity_failed
  else
    echo "WARNUNG: Nachziehen auf neuestes main fehlgeschlagen." >&2
  fi
fi
repair_deploy_if_integrity_failed

DEPLOYED_SHA_FILE="$(cat "$TARGET_DIR/DEPLOYED_COMMIT_SHA" 2>/dev/null || true)"

if [ -n "$GITHUB_COMMIT_TIME" ]; then
  echo "Fertig. Deploy-Commit: $REF [GitHub: $GITHUB_COMMIT_TIME | Deploy: $DEPLOY_TIME]"
else
  echo "Fertig. Deploy-Commit: $REF [Deploy: $DEPLOY_TIME]"
fi

if [ -n "$LATEST_SHA_AFTER" ] && [ "$DEPLOYED_SHA_FILE" = "$LATEST_SHA_AFTER" ]; then
  echo "Commit-Status: AKTUELL (deployter Commit entspricht repo/main)"
elif [ -n "$LATEST_SHA_AFTER" ]; then
  echo "Commit-Status: NICHT AKTUELL (deployt=$DEPLOYED_SHA_FILE, repo/main=$LATEST_SHA_AFTER)"
else
  echo "Commit-Status: UNBEKANNT (konnte latest main SHA nicht ermitteln)"
fi

LOCAL_BUILD_VERSION="$(tr -d ' \t\r\n' < "$TARGET_DIR/BUILD_VERSION" 2>/dev/null || true)"
LOCAL_AGENT_VERSION="$(tr -d ' \t\r\n' < "$TARGET_DIR/AGENT_VERSION" 2>/dev/null || true)"
MAIN_HEAD_SHA="${LATEST_SHA_AFTER:-}"
if ! is_full_git_sha "$MAIN_HEAD_SHA"; then
  MAIN_HEAD_SHA="$(resolve_latest_main_sha main || true)"
fi
REMOTE_BUILD_REF="${MAIN_HEAD_SHA:-$REF}"
REMOTE_BUILD_VERSION=""
REMOTE_AGENT_VERSION=""
if is_full_git_sha "$REMOTE_BUILD_REF"; then
  REMOTE_BUILD_VERSION="$(fetch_repo_text_at_ref BUILD_VERSION "$REMOTE_BUILD_REF")"
  REMOTE_AGENT_VERSION="$(fetch_repo_text_at_ref AGENT_VERSION "$REMOTE_BUILD_REF")"
fi

echo "BUILD_VERSION deployiert: ${LOCAL_BUILD_VERSION:-?}"
echo "AGENT_VERSION deployiert: ${LOCAL_AGENT_VERSION:-?}"
if [ -n "$LOCAL_BUILD_VERSION" ] && [ -n "$LOCAL_AGENT_VERSION" ] && [ "$LOCAL_BUILD_VERSION" != "$LOCAL_AGENT_VERSION" ]; then
  echo "WARNUNG: BUILD und AGENT Version unterscheiden sich – Deploy ist inkonsistent." >&2
fi
if [ -n "$REMOTE_BUILD_VERSION" ]; then
  if is_full_git_sha "$REMOTE_BUILD_REF"; then
    echo "BUILD_VERSION GitHub (main @ ${REMOTE_BUILD_REF:0:12}): $REMOTE_BUILD_VERSION"
  else
    echo "BUILD_VERSION GitHub ($REMOTE_BUILD_REF): $REMOTE_BUILD_VERSION"
  fi
  if [ "$LOCAL_BUILD_VERSION" != "$REMOTE_BUILD_VERSION" ]; then
    echo "WARNUNG: Deploy-Ordner BUILD_VERSION weicht von main HEAD ab – Pull erneut oder MONITORING_DEPLOY_SHA pruefen." >&2
  fi
fi
if [ -n "$REMOTE_AGENT_VERSION" ]; then
  if is_full_git_sha "$REMOTE_BUILD_REF"; then
    echo "AGENT_VERSION GitHub (main @ ${REMOTE_BUILD_REF:0:12}): $REMOTE_AGENT_VERSION"
  else
    echo "AGENT_VERSION GitHub ($REMOTE_BUILD_REF): $REMOTE_AGENT_VERSION"
  fi
fi
if is_branch_ref "${REF:-}"; then
  echo "WARNUNG: Deploy lief ueber Branch-Alias '$REF' – fuer reproduzierbare Deploys Commit-SHA nutzen." >&2
fi
if ! is_full_git_sha "$REF" && [ -z "$LATEST_SHA_AFTER" ]; then
  echo "Hinweis: Commit-SHA unbekannt – Deploy lief ueber Branch $REF. Fuer Pin optional MONITORING_DEPLOY_SHA setzen." >&2
fi
if grep -q 'BUILD_VERSION GitHub main:' "$TARGET_DIR/pull-server-only.sh" 2>/dev/null; then
  echo "WARNUNG: $TARGET_DIR/pull-server-only.sh ist noch die alte Version (zeigt 'GitHub main')." >&2
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
"$TARGET_DIR/.venv/bin/pip" install --quiet --upgrade cairosvg
"$TARGET_DIR/.venv/bin/pip" install --quiet --upgrade pywebpush

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
  systemctl --no-pager --full status monitoring | sed -n '1,10p' || true
else
  echo "Versuche monitoring-Service neu zu starten ..."
  if systemctl restart monitoring; then
    echo "✓ monitoring wurde neu gestartet"
    systemctl --no-pager --full status monitoring | sed -n '1,14p' || true
  else
    echo "✗ monitoring konnte nicht automatisch neu gestartet werden" >&2
    echo "  Bitte manuell ausführen: systemctl restart monitoring" >&2
  fi
fi

echo ""
echo ""
echo "Deploy-Verifikation im Browser (nach Hard-Refresh Strg+Shift+R):"
echo "  fetch('/BUILD_VERSION').then(r=>r.text()).then(console.log)  // erwartet: $LOCAL_BUILD_VERSION"
echo ""
echo "Nächste Schritte (falls nötig):"
echo "  1. API-Key prüfen:     nano $ENV_FILE"
echo "  2. Service-Status:     systemctl status monitoring"
