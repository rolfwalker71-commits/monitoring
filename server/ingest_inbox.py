"""File-inbox ingest pipeline with ingest-status.db (decoupled from monitoring.db)."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

INGEST_SCHEMA_VERSION = 1
INGEST_ENVELOPE_SCHEMA_VERSION = 1

_process_job_callback: Callable[..., tuple[int, dict[str, object]]] | None = None
_should_pause_for_login: Callable[[], bool] | None = None
_wait_for_login_slot: Callable[[], None] | None = None
_record_ingest_written: Callable[..., None] | None = None
_schedule_post_commit: Callable[[dict[str, object]], None] | None = None
_invalidate_dashboard_kpis: Callable[[], None] | None = None
_adaptive_throttle_sleep: Callable[[int], None] | None = None
_runtime_metrics_snapshot: Callable[[], dict[str, object]] | None = None
_derive_queue_health: Callable[..., str] | None = None
_collect_audit_runtime_stats: Callable[..., dict[str, object]] | None = None
_sqlite_connect_main: Callable[[], sqlite3.Connection] | None = None
_get_alarm_settings: Callable[[sqlite3.Connection], dict] | None = None
_get_host_settings: Callable[[sqlite3.Connection, str], dict] | None = None
_quick_duplicate_report_id: Callable[..., int] | None = None
_agent_ingest_duration_ms: Callable[..., int] | None = None
_ingest_slow_log_ms: int = 500
_ingest_queue_warn_depth: int = 500
_ingest_queue_crit_depth: int = 2000

DATA_DIR: Path = Path("data")
INGEST_STATUS_DB_PATH: Path = DATA_DIR / "ingest-status.db"
INGEST_INBOX_DIR: Path = DATA_DIR / "ingest-inbox"
INGEST_INBOX_PENDING_DIR: Path = INGEST_INBOX_DIR / "pending"
INGEST_INBOX_STORAGE_DIR: Path = INGEST_INBOX_DIR / "storage"
INGEST_INBOX_FAILED_DIR: Path = INGEST_INBOX_DIR / "failed"

INGEST_FILE_INBOX_ENABLED = True
INGEST_SCANNER_INTERVAL_SECONDS = 0.1
INGEST_SCANNER_BATCH_SIZE = 50
INGEST_INBOX_FSYNC = True
INGEST_AUDIT_MAX_ROWS = 250
INGEST_MAX_ATTEMPTS = 30
INGEST_RETRY_MAX_BACKOFF_SECONDS = 300
INGEST_WORKER_IDLE_SECONDS = 0.5
INGEST_BATCH_SIZE = 4
INGEST_DB_TIMEOUT_SECONDS = 30

_wakeup = threading.Event()
_scanner_lock = threading.Lock()


def configure(
    *,
    data_dir: Path,
    enabled: bool,
    scanner_interval_seconds: float,
    scanner_batch_size: int,
    inbox_fsync: bool,
    audit_max_rows: int,
    max_attempts: int,
    retry_max_backoff_seconds: int,
    worker_idle_seconds: float,
    batch_size: int,
    db_timeout_seconds: int,
    slow_log_ms: int,
    queue_warn_depth: int,
    queue_crit_depth: int,
) -> None:
    global DATA_DIR, INGEST_STATUS_DB_PATH, INGEST_INBOX_DIR
    global INGEST_INBOX_PENDING_DIR, INGEST_INBOX_STORAGE_DIR, INGEST_INBOX_FAILED_DIR
    global INGEST_FILE_INBOX_ENABLED, INGEST_SCANNER_INTERVAL_SECONDS, INGEST_SCANNER_BATCH_SIZE
    global INGEST_INBOX_FSYNC, INGEST_AUDIT_MAX_ROWS, INGEST_MAX_ATTEMPTS
    global INGEST_RETRY_MAX_BACKOFF_SECONDS, INGEST_WORKER_IDLE_SECONDS, INGEST_BATCH_SIZE
    global INGEST_DB_TIMEOUT_SECONDS, _ingest_slow_log_ms, _ingest_queue_warn_depth, _ingest_queue_crit_depth

    DATA_DIR = data_dir
    INGEST_STATUS_DB_PATH = data_dir / "ingest-status.db"
    INGEST_INBOX_DIR = data_dir / "ingest-inbox"
    INGEST_INBOX_PENDING_DIR = INGEST_INBOX_DIR / "pending"
    INGEST_INBOX_STORAGE_DIR = INGEST_INBOX_DIR / "storage"
    INGEST_INBOX_FAILED_DIR = INGEST_INBOX_DIR / "failed"
    INGEST_FILE_INBOX_ENABLED = enabled
    INGEST_SCANNER_INTERVAL_SECONDS = scanner_interval_seconds
    INGEST_SCANNER_BATCH_SIZE = scanner_batch_size
    INGEST_INBOX_FSYNC = inbox_fsync
    INGEST_AUDIT_MAX_ROWS = audit_max_rows
    INGEST_MAX_ATTEMPTS = max_attempts
    INGEST_RETRY_MAX_BACKOFF_SECONDS = retry_max_backoff_seconds
    INGEST_WORKER_IDLE_SECONDS = worker_idle_seconds
    INGEST_BATCH_SIZE = batch_size
    INGEST_DB_TIMEOUT_SECONDS = db_timeout_seconds
    _ingest_slow_log_ms = slow_log_ms
    _ingest_queue_warn_depth = queue_warn_depth
    _ingest_queue_crit_depth = queue_crit_depth


def register_runtime_hooks(
    *,
    process_job: Callable[..., tuple[int, dict[str, object]]],
    should_pause_for_login: Callable[[], bool],
    wait_for_login_slot: Callable[[], None],
    record_ingest_written: Callable[..., None],
    schedule_post_commit: Callable[[dict[str, object]], None],
    invalidate_dashboard_kpis: Callable[[], None],
    adaptive_throttle_sleep: Callable[[int], None],
    runtime_metrics_snapshot: Callable[[], dict[str, object]],
    derive_queue_health: Callable[..., str],
    collect_audit_runtime_stats: Callable[..., dict[str, object]],
    sqlite_connect_main: Callable[[], sqlite3.Connection],
    get_alarm_settings: Callable[[sqlite3.Connection], dict],
    get_host_settings: Callable[[sqlite3.Connection, str], dict],
    quick_duplicate_report_id: Callable[..., int],
    agent_ingest_duration_ms: Callable[..., int],
) -> None:
    global _process_job_callback, _should_pause_for_login, _wait_for_login_slot
    global _record_ingest_written, _schedule_post_commit, _invalidate_dashboard_kpis
    global _adaptive_throttle_sleep, _runtime_metrics_snapshot, _derive_queue_health
    global _collect_audit_runtime_stats, _sqlite_connect_main, _get_alarm_settings
    global _get_host_settings, _quick_duplicate_report_id, _agent_ingest_duration_ms

    _process_job_callback = process_job
    _should_pause_for_login = should_pause_for_login
    _wait_for_login_slot = wait_for_login_slot
    _record_ingest_written = record_ingest_written
    _schedule_post_commit = schedule_post_commit
    _invalidate_dashboard_kpis = invalidate_dashboard_kpis
    _adaptive_throttle_sleep = adaptive_throttle_sleep
    _runtime_metrics_snapshot = runtime_metrics_snapshot
    _derive_queue_health = derive_queue_health
    _collect_audit_runtime_stats = collect_audit_runtime_stats
    _sqlite_connect_main = sqlite_connect_main
    _get_alarm_settings = get_alarm_settings
    _get_host_settings = get_host_settings
    _quick_duplicate_report_id = quick_duplicate_report_id
    _agent_ingest_duration_ms = agent_ingest_duration_ms


def ingest_file_inbox_enabled() -> bool:
    return bool(INGEST_FILE_INBOX_ENABLED)


def wakeup_worker() -> None:
    _wakeup.set()


def sqlite_connect_ingest_status() -> sqlite3.Connection:
    return sqlite3.connect(str(INGEST_STATUS_DB_PATH), timeout=INGEST_DB_TIMEOUT_SECONDS)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_utc_iso(value: object) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _ensure_inbox_dirs() -> None:
    INGEST_INBOX_PENDING_DIR.mkdir(parents=True, exist_ok=True)
    INGEST_INBOX_STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    INGEST_INBOX_FAILED_DIR.mkdir(parents=True, exist_ok=True)


def init_ingest_status_db() -> None:
    _ensure_inbox_dirs()
    INGEST_STATUS_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite_connect_ingest_status() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ingest_schema_migrations (
                version INTEGER PRIMARY KEY,
                applied_at_utc TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ingest_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                inbox_id TEXT NOT NULL UNIQUE,
                job_token TEXT NOT NULL UNIQUE,
                hostname TEXT NOT NULL,
                host_uid TEXT NOT NULL DEFAULT '',
                agent_id TEXT NOT NULL DEFAULT '',
                report_received_at_utc TEXT NOT NULL,
                inbox_written_at_utc TEXT NOT NULL,
                enqueued_at_utc TEXT NOT NULL,
                next_attempt_at_utc TEXT NOT NULL,
                processing_started_at_utc TEXT NOT NULL DEFAULT '',
                storage_path TEXT NOT NULL DEFAULT '',
                payload_bytes INTEGER NOT NULL DEFAULT 0,
                payload_sha256 TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'ready',
                attempt_count INTEGER NOT NULL DEFAULT 0,
                last_error TEXT NOT NULL DEFAULT '',
                updated_at_utc TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_ingest_jobs_ready
            ON ingest_jobs(status, next_attempt_at_utc, id)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_ingest_jobs_hostname
            ON ingest_jobs(hostname, id)
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ingest_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id INTEGER NOT NULL UNIQUE,
                inbox_id TEXT NOT NULL,
                hostname TEXT NOT NULL,
                host_uid TEXT NOT NULL DEFAULT '',
                report_received_at_utc TEXT NOT NULL,
                inbox_written_at_utc TEXT NOT NULL,
                enqueued_at_utc TEXT NOT NULL,
                db_written_at_utc TEXT NOT NULL DEFAULT '',
                payload_bytes INTEGER NOT NULL DEFAULT 0,
                storage_path TEXT NOT NULL DEFAULT '',
                main_report_id INTEGER NOT NULL DEFAULT 0,
                attempt_count INTEGER NOT NULL DEFAULT 0,
                inbox_wait_ms INTEGER NOT NULL DEFAULT 0,
                queue_wait_ms INTEGER NOT NULL DEFAULT 0,
                processing_ms INTEGER NOT NULL DEFAULT 0,
                end_to_end_ms INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'inbox',
                error_message TEXT NOT NULL DEFAULT '',
                updated_at_utc TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_ingest_audit_updated
            ON ingest_audit_log(updated_at_utc DESC, id DESC)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_ingest_audit_status
            ON ingest_audit_log(status, db_written_at_utc)
            """
        )
        row = conn.execute("SELECT version FROM ingest_schema_migrations WHERE version = ?", (INGEST_SCHEMA_VERSION,)).fetchone()
        if not row:
            conn.execute(
                "INSERT INTO ingest_schema_migrations(version, applied_at_utc) VALUES (?, ?)",
                (INGEST_SCHEMA_VERSION, _utc_now_iso()),
            )
        conn.commit()


def _atomic_write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_suffix(path.suffix + ".tmp")
    data = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    with tmp_path.open("w", encoding="utf-8") as handle:
        handle.write(data)
        handle.flush()
        if INGEST_INBOX_FSYNC:
            os.fsync(handle.fileno())
    tmp_path.replace(path)
    if INGEST_INBOX_FSYNC:
        try:
            dir_fd = os.open(str(path.parent), os.O_DIRECTORY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass


def accept_agent_report_to_inbox(
    payload: dict,
    *,
    report_received_at_utc: str,
    remote_addr: str = "",
) -> str:
    _ensure_inbox_dirs()
    hostname = str(payload.get("hostname", "") or "").strip()
    if not hostname:
        raise ValueError("hostname missing")

    inbox_id = str(uuid.uuid4())
    payload_json = json.dumps(payload, separators=(",", ":"))
    envelope = {
        "schema_version": INGEST_ENVELOPE_SCHEMA_VERSION,
        "inbox_id": inbox_id,
        "received_at_utc": report_received_at_utc,
        "remote_addr": str(remote_addr or "").strip(),
        "hostname": hostname,
        "host_uid": str(payload.get("host_uid", "") or "").strip(),
        "agent_id": str(payload.get("agent_id", "") or "").strip(),
        "payload_bytes": len(payload_json.encode("utf-8")),
        "payload": payload,
    }
    _atomic_write_json(INGEST_INBOX_PENDING_DIR / f"{inbox_id}.json", envelope)
    wakeup_worker()
    return inbox_id


def _pending_inbox_stats() -> tuple[int, int, str]:
    count = 0
    oldest_mtime = 0.0
    oldest_iso = ""
    try:
        for path in INGEST_INBOX_PENDING_DIR.glob("*.json"):
            if not path.is_file():
                continue
            count += 1
            mtime = path.stat().st_mtime
            if oldest_mtime <= 0.0 or mtime < oldest_mtime:
                oldest_mtime = mtime
                oldest_iso = datetime.fromtimestamp(mtime, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except OSError:
        pass
    oldest_age = 0
    if oldest_mtime > 0.0:
        oldest_age = max(0, int(time.time() - oldest_mtime))
    return count, oldest_age, oldest_iso


def _prune_ingest_audit_log(conn: sqlite3.Connection) -> None:
    rows = conn.execute(
        """
        SELECT id, storage_path
        FROM ingest_audit_log
        ORDER BY id DESC
        LIMIT -1 OFFSET ?
        """,
        (INGEST_AUDIT_MAX_ROWS,),
    ).fetchall()
    if not rows:
        return
    for row in rows:
        rel_path = str(row[1] or "").strip()
        if rel_path:
            file_path = INGEST_INBOX_DIR / rel_path
            try:
                if file_path.is_file():
                    file_path.unlink()
            except OSError:
                pass
    conn.execute(
        """
        DELETE FROM ingest_audit_log
        WHERE id IN (
            SELECT id FROM ingest_audit_log ORDER BY id DESC LIMIT -1 OFFSET ?
        )
        """,
        (INGEST_AUDIT_MAX_ROWS,),
    )


def _insert_audit_row(
    conn: sqlite3.Connection,
    *,
    job_id: int,
    inbox_id: str,
    hostname: str,
    host_uid: str,
    report_received_at_utc: str,
    inbox_written_at_utc: str,
    enqueued_at_utc: str,
    payload_bytes: int,
    storage_path: str,
    status: str,
    inbox_wait_ms: int = 0,
) -> None:
    now_utc = _utc_now_iso()
    conn.execute(
        """
        INSERT OR REPLACE INTO ingest_audit_log (
            job_id, inbox_id, hostname, host_uid, report_received_at_utc,
            inbox_written_at_utc, enqueued_at_utc, db_written_at_utc,
            payload_bytes, storage_path, main_report_id, attempt_count,
            inbox_wait_ms, queue_wait_ms, processing_ms, end_to_end_ms,
            status, error_message, updated_at_utc
        ) VALUES (?, ?, ?, ?, ?, ?, ?, '', ?, ?, 0, 0, ?, 0, 0, 0, ?, '', ?)
        """,
        (
            int(job_id),
            str(inbox_id),
            str(hostname),
            str(host_uid),
            str(report_received_at_utc),
            str(inbox_written_at_utc),
            str(enqueued_at_utc),
            max(0, int(payload_bytes or 0)),
            str(storage_path),
            max(0, int(inbox_wait_ms or 0)),
            str(status),
            now_utc,
        ),
    )
    _prune_ingest_audit_log(conn)


def _update_audit_row(
    conn: sqlite3.Connection,
    *,
    job_id: int,
    status: str,
    attempt_count: int,
    db_written_at_utc: str = "",
    main_report_id: int = 0,
    inbox_wait_ms: int = 0,
    queue_wait_ms: int = 0,
    processing_ms: int = 0,
    end_to_end_ms: int = 0,
    error_message: str = "",
) -> None:
    conn.execute(
        """
        UPDATE ingest_audit_log
        SET status = ?,
            updated_at_utc = ?,
            attempt_count = ?,
            db_written_at_utc = ?,
            main_report_id = ?,
            inbox_wait_ms = ?,
            queue_wait_ms = ?,
            processing_ms = ?,
            end_to_end_ms = ?,
            error_message = ?
        WHERE job_id = ?
        """,
        (
            str(status),
            _utc_now_iso(),
            max(0, int(attempt_count or 0)),
            str(db_written_at_utc or ""),
            max(0, int(main_report_id or 0)),
            max(0, int(inbox_wait_ms or 0)),
            max(0, int(queue_wait_ms or 0)),
            max(0, int(processing_ms or 0)),
            max(0, int(end_to_end_ms or 0)),
            str(error_message or ""),
            int(job_id),
        ),
    )


def _scan_single_pending_file(path: Path) -> bool:
    try:
        envelope = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        failed_name = f"{path.stem}-invalid-{int(time.time())}.json"
        try:
            path.replace(INGEST_INBOX_FAILED_DIR / failed_name)
        except OSError:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        print(f"[ingest-inbox-scanner] invalid pending file {path.name}: {exc}")
        return False

    if not isinstance(envelope, dict):
        return False

    inbox_id = str(envelope.get("inbox_id") or path.stem).strip()
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        return False

    hostname = str(envelope.get("hostname") or payload.get("hostname") or "").strip()
    if not hostname:
        return False

    report_received_at_utc = str(envelope.get("received_at_utc") or _utc_now_iso())
    inbox_written_at_utc = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    enqueued_at_utc = _utc_now_iso()
    host_uid = str(envelope.get("host_uid") or payload.get("host_uid") or "").strip()
    agent_id = str(envelope.get("agent_id") or payload.get("agent_id") or "").strip()
    payload_json = json.dumps(payload, separators=(",", ":"))
    payload_bytes = len(payload_json.encode("utf-8"))
    payload_sha256 = hashlib.sha256(payload_json.encode("utf-8")).hexdigest()
    inbox_wait_ms = 0
    inbox_dt = _parse_utc_iso(inbox_written_at_utc)
    enqueue_dt = _parse_utc_iso(enqueued_at_utc)
    if inbox_dt and enqueue_dt:
        inbox_wait_ms = max(0, int((enqueue_dt - inbox_dt).total_seconds() * 1000))

    with sqlite_connect_ingest_status() as conn:
        existing = conn.execute("SELECT id FROM ingest_jobs WHERE inbox_id = ?", (inbox_id,)).fetchone()
        if existing:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
            conn.commit()
            return True

        cursor = conn.execute(
            """
            INSERT INTO ingest_jobs (
                inbox_id, job_token, hostname, host_uid, agent_id,
                report_received_at_utc, inbox_written_at_utc, enqueued_at_utc,
                next_attempt_at_utc, storage_path, payload_bytes, payload_sha256,
                status, attempt_count, last_error, updated_at_utc
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '', ?, ?, 'ready', 0, '', ?)
            """,
            (
                inbox_id,
                inbox_id,
                hostname,
                host_uid,
                agent_id,
                report_received_at_utc,
                inbox_written_at_utc,
                enqueued_at_utc,
                enqueued_at_utc,
                payload_bytes,
                payload_sha256,
                enqueued_at_utc,
            ),
        )
        job_id = int(cursor.lastrowid)
        storage_rel = f"storage/{job_id}.json"
        storage_path = INGEST_INBOX_STORAGE_DIR / f"{job_id}.json"
        _atomic_write_json(storage_path, envelope)
        conn.execute(
            "UPDATE ingest_jobs SET storage_path = ?, updated_at_utc = ? WHERE id = ?",
            (storage_rel, enqueued_at_utc, job_id),
        )
        _insert_audit_row(
            conn,
            job_id=job_id,
            inbox_id=inbox_id,
            hostname=hostname,
            host_uid=host_uid,
            report_received_at_utc=report_received_at_utc,
            inbox_written_at_utc=inbox_written_at_utc,
            enqueued_at_utc=enqueued_at_utc,
            payload_bytes=payload_bytes,
            storage_path=storage_rel,
            status="queued",
            inbox_wait_ms=inbox_wait_ms,
        )
        conn.commit()

    try:
        path.unlink(missing_ok=True)
    except OSError as exc:
        print(f"[ingest-inbox-scanner] pending cleanup failed for {path.name}: {exc}")
    return True


def scan_pending_inbox_batch() -> int:
    if not ingest_file_inbox_enabled():
        return 0
    with _scanner_lock:
        pending_files = sorted(
            INGEST_INBOX_PENDING_DIR.glob("*.json"),
            key=lambda item: item.stat().st_mtime,
        )[: max(1, INGEST_SCANNER_BATCH_SIZE)]
        processed = 0
        for path in pending_files:
            if _scan_single_pending_file(path):
                processed += 1
        return processed


def _retry_backoff_seconds(attempt_count: int) -> int:
    safe_attempt = max(1, int(attempt_count))
    return min(INGEST_RETRY_MAX_BACKOFF_SECONDS, 2 ** min(safe_attempt, 10))


def _load_job_payload(job_row: sqlite3.Row | tuple) -> tuple[dict, dict]:
    storage_rel = str(job_row[12] if isinstance(job_row, tuple) else job_row["storage_path"] or "").strip()
    storage_path = INGEST_INBOX_DIR / storage_rel
    envelope = json.loads(storage_path.read_text(encoding="utf-8"))
    if not isinstance(envelope, dict):
        raise ValueError("storage envelope must be an object")
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("storage payload must be an object")
    return envelope, payload


def _schedule_job_retry(
    conn: sqlite3.Connection,
    *,
    job_id: int,
    attempt_count: int,
    error_message: str,
) -> None:
    backoff = _retry_backoff_seconds(attempt_count)
    retry_at = (datetime.now(timezone.utc) + timedelta(seconds=backoff)).strftime("%Y-%m-%dT%H:%M:%SZ")
    now_utc = _utc_now_iso()
    conn.execute(
        """
        UPDATE ingest_jobs
        SET status = 'retry',
            next_attempt_at_utc = ?,
            processing_started_at_utc = '',
            last_error = ?,
            updated_at_utc = ?,
            attempt_count = ?
        WHERE id = ?
        """,
        (retry_at, str(error_message or ""), now_utc, attempt_count, job_id),
    )
    _update_audit_row(
        conn,
        job_id=job_id,
        status="retry",
        attempt_count=attempt_count,
        error_message=str(error_message or ""),
    )
    conn.commit()


def _delete_job_and_storage(conn: sqlite3.Connection, job_id: int, storage_rel: str) -> None:
    conn.execute("DELETE FROM ingest_jobs WHERE id = ?", (job_id,))
    conn.commit()
    if storage_rel:
        storage_path = INGEST_INBOX_DIR / storage_rel
        try:
            if storage_path.is_file():
                storage_path.unlink()
        except OSError:
            pass


def migrate_legacy_agent_ingest_queue(main_conn: sqlite3.Connection) -> int:
    if not ingest_file_inbox_enabled():
        return 0
    try:
        rows = main_conn.execute(
            """
            SELECT id, payload_json, report_received_at_utc, enqueued_at_utc, hostname, host_uid, attempt_count
            FROM agent_ingest_queue
            ORDER BY id ASC
            """
        ).fetchall()
    except sqlite3.Error:
        return 0
    if not rows:
        return 0

    migrated = 0
    for row in rows:
        queue_id = int(row[0] or 0)
        payload_json = str(row[1] or "{}")
        try:
            payload = json.loads(payload_json)
        except json.JSONDecodeError:
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        hostname = str(row[4] or payload.get("hostname") or "").strip()
        if not hostname:
            continue
        report_received_at_utc = str(row[2] or _utc_now_iso())
        enqueued_at_utc = str(row[3] or report_received_at_utc)
        host_uid = str(row[5] or payload.get("host_uid") or "").strip()
        inbox_id = f"legacy-q{queue_id}"
        envelope = {
            "schema_version": INGEST_ENVELOPE_SCHEMA_VERSION,
            "inbox_id": inbox_id,
            "received_at_utc": report_received_at_utc,
            "remote_addr": "",
            "hostname": hostname,
            "host_uid": host_uid,
            "agent_id": str(payload.get("agent_id") or "").strip(),
            "payload_bytes": len(payload_json.encode("utf-8")),
            "payload": payload,
        }
        pending_path = INGEST_INBOX_PENDING_DIR / f"{inbox_id}.json"
        if not pending_path.exists():
            _atomic_write_json(pending_path, envelope)
            migrated += 1
        main_conn.execute("DELETE FROM agent_ingest_queue WHERE id = ?", (queue_id,))

    main_conn.commit()
    if migrated > 0:
        print(f"[ingest-inbox] migrated {migrated} legacy queue row(s) into pending inbox")
        scan_pending_inbox_batch()
    return migrated


def collect_ingest_queue_overview(
    ingest_conn: sqlite3.Connection,
    *,
    recent_errors_limit: int = 20,
) -> dict[str, object]:
    now_iso = _utc_now_iso()
    now_dt = datetime.now(timezone.utc)

    totals_row = ingest_conn.execute(
        """
        SELECT
            COUNT(*) AS queue_depth,
            SUM(CASE WHEN status = 'ready' AND next_attempt_at_utc <= ? THEN 1 ELSE 0 END) AS ready_count,
            SUM(CASE WHEN status = 'retry' OR attempt_count > 0 OR COALESCE(last_error, '') <> '' THEN 1 ELSE 0 END) AS retry_count,
            SUM(CASE WHEN status = 'processing' THEN 1 ELSE 0 END) AS in_flight_count,
            SUM(CASE WHEN status = 'retry' AND next_attempt_at_utc > ? THEN 1 ELSE 0 END) AS delayed_count,
            SUM(CASE WHEN status = 'ready' AND attempt_count <= 0 AND COALESCE(last_error, '') = '' THEN 1 ELSE 0 END) AS pending_count
        FROM ingest_jobs
        """,
        (now_iso, now_iso),
    ).fetchone()

    oldest_job_row = ingest_conn.execute(
        """
        SELECT enqueued_at_utc FROM ingest_jobs
        ORDER BY enqueued_at_utc ASC, id ASC LIMIT 1
        """
    ).fetchone()
    next_ready_row = ingest_conn.execute(
        """
        SELECT next_attempt_at_utc FROM ingest_jobs
        WHERE status IN ('ready', 'retry')
        ORDER BY next_attempt_at_utc ASC, id ASC LIMIT 1
        """
    ).fetchone()
    recent_errors_rows = ingest_conn.execute(
        """
        SELECT id, hostname, host_uid, attempt_count, updated_at_utc, next_attempt_at_utc, last_error
        FROM ingest_jobs
        WHERE COALESCE(last_error, '') <> ''
        ORDER BY updated_at_utc DESC, id DESC
        LIMIT ?
        """,
        (max(1, int(recent_errors_limit)),),
    ).fetchall()

    pending_inbox_count, pending_inbox_age, pending_inbox_oldest = _pending_inbox_stats()
    jobs_depth = int((totals_row[0] or 0) if totals_row else 0)
    queue_depth = jobs_depth + pending_inbox_count

    oldest_job_iso = str((oldest_job_row[0] if oldest_job_row else "") or "")
    oldest_job_dt = _parse_utc_iso(oldest_job_iso)
    oldest_job_age = max(0, int((now_dt - oldest_job_dt).total_seconds())) if oldest_job_dt else 0
    oldest_age_seconds = max(oldest_job_age, pending_inbox_age)

    next_attempt_at_utc = str((next_ready_row[0] if next_ready_row else "") or "")
    next_attempt_dt = _parse_utc_iso(next_attempt_at_utc)
    next_attempt_in_seconds = int((next_attempt_dt - now_dt).total_seconds()) if next_attempt_dt else 0

    recent_errors: list[dict[str, object]] = []
    for row in recent_errors_rows:
        updated_at = str(row[4] or "")
        next_attempt = str(row[5] or "")
        updated_dt = _parse_utc_iso(updated_at)
        next_attempt_dt_row = _parse_utc_iso(next_attempt)
        age_seconds = max(0, int((now_dt - updated_dt).total_seconds())) if updated_dt else 0
        retry_in_seconds = int((next_attempt_dt_row - now_dt).total_seconds()) if next_attempt_dt_row else 0
        recent_errors.append(
            {
                "id": int(row[0] or 0),
                "hostname": str(row[1] or ""),
                "host_uid": str(row[2] or ""),
                "attempt_count": int(row[3] or 0),
                "updated_at_utc": updated_at,
                "next_attempt_at_utc": next_attempt,
                "error_age_seconds": age_seconds,
                "retry_in_seconds": retry_in_seconds,
                "last_error": str(row[6] or ""),
            }
        )

    audit_runtime = (
        _collect_audit_runtime_stats(ingest_conn)
        if callable(_collect_audit_runtime_stats)
        else {}
    )
    runtime_metrics = _runtime_metrics_snapshot() if callable(_runtime_metrics_snapshot) else {}
    failed_last_hour = int(audit_runtime.get("failed_count") or 0)
    health_status = (
        _derive_queue_health(
            queue_depth=queue_depth,
            oldest_age_seconds=oldest_age_seconds,
            failed_last_hour=failed_last_hour,
        )
        if callable(_derive_queue_health)
        else "ok"
    )
    ingest_paused_for_login = _should_pause_for_login() if callable(_should_pause_for_login) else False

    return {
        "ingest_mode": "file-inbox",
        "queue_depth": queue_depth,
        "jobs_depth": jobs_depth,
        "pending_inbox_count": pending_inbox_count,
        "pending_inbox_oldest_age_seconds": pending_inbox_age,
        "pending_inbox_oldest_at_utc": pending_inbox_oldest,
        "ready_count": int((totals_row[1] or 0) if totals_row else 0),
        "retry_count": int((totals_row[2] or 0) if totals_row else 0),
        "in_flight_count": int((totals_row[3] or 0) if totals_row else 0),
        "delayed_count": int((totals_row[4] or 0) if totals_row else 0),
        "pending_count": int((totals_row[5] or 0) if totals_row else 0) + pending_inbox_count,
        "oldest_enqueued_at_utc": oldest_job_iso or pending_inbox_oldest,
        "oldest_age_seconds": oldest_age_seconds,
        "next_attempt_at_utc": next_attempt_at_utc,
        "next_attempt_in_seconds": next_attempt_in_seconds,
        "recent_errors": recent_errors,
        "health_status": health_status,
        "health_thresholds": {
            "queue_warn": _ingest_queue_warn_depth,
            "queue_critical": _ingest_queue_crit_depth,
        },
        "audit_runtime": audit_runtime,
        "runtime_metrics": runtime_metrics,
        "ingest_paused_for_login": ingest_paused_for_login,
    }


def _batch_customer_names_by_hostname(
    main_conn: sqlite3.Connection | None,
    hostnames: set[str],
) -> dict[str, str]:
    if main_conn is None:
        return {}
    safe_names = sorted({str(name or "").strip() for name in hostnames if str(name or "").strip()})
    if not safe_names:
        return {}
    placeholders = ",".join("?" * len(safe_names))
    rows = main_conn.execute(
        f"""
        SELECT hs.hostname, COALESCE(c.customer_name, '')
        FROM host_settings hs
        LEFT JOIN customers c ON c.id = hs.customer_id
        WHERE hs.hostname IN ({placeholders})
        """,
        safe_names,
    ).fetchall()
    return {str(row[0] or "").strip(): str(row[1] or "").strip() for row in rows}


def _lookup_customer_name(main_conn: sqlite3.Connection | None, hostname: str, host_uid: str) -> str:
    if main_conn is None:
        return ""
    safe_host_uid = str(host_uid or "").strip()
    safe_hostname = str(hostname or "").strip()
    if safe_host_uid:
        row = main_conn.execute(
            """
            SELECT COALESCE(c.customer_name, '')
            FROM reports r
            JOIN host_settings hs ON hs.hostname = r.hostname
            LEFT JOIN customers c ON c.id = hs.customer_id
            WHERE COALESCE(r.host_uid, '') = ?
            ORDER BY r.id DESC
            LIMIT 1
            """,
            (safe_host_uid,),
        ).fetchone()
        if row and str(row[0] or "").strip():
            return str(row[0] or "").strip()
    if safe_hostname:
        row = main_conn.execute(
            """
            SELECT COALESCE(c.customer_name, '')
            FROM host_settings hs
            LEFT JOIN customers c ON c.id = hs.customer_id
            WHERE hs.hostname = ?
            LIMIT 1
            """,
            (safe_hostname,),
        ).fetchone()
        if row:
            return str(row[0] or "").strip()
    return ""


def collect_ingest_audit_log(
    ingest_conn: sqlite3.Connection,
    main_conn: sqlite3.Connection | None,
    *,
    limit: int = INGEST_AUDIT_MAX_ROWS,
) -> dict[str, object]:
    safe_limit = max(10, min(2000, int(limit or INGEST_AUDIT_MAX_ROWS)))
    rows = ingest_conn.execute(
        """
        SELECT
            id, job_id, inbox_id, hostname, host_uid, report_received_at_utc,
            enqueued_at_utc, db_written_at_utc, payload_bytes, storage_path,
            attempt_count, inbox_wait_ms, queue_wait_ms, processing_ms, end_to_end_ms,
            status, error_message, updated_at_utc, main_report_id
        FROM ingest_audit_log
        ORDER BY id DESC
        LIMIT ?
        """,
        (safe_limit,),
    ).fetchall()

    hostnames = {str(row[3] or "").strip() for row in rows if str(row[3] or "").strip()}
    customer_by_hostname = _batch_customer_names_by_hostname(main_conn, hostnames)

    entries: list[dict[str, object]] = []
    for row in rows:
        storage_path = str(row[9] or "").strip()
        payload_stored = bool(storage_path)
        payload_file_name = Path(storage_path).name if storage_path else ""
        audit_id = int(row[0] or 0)
        payload_download_path = (
            f"/api/v1/admin/agent-ingest-log/payload?audit_id={audit_id}" if payload_stored else ""
        )
        entries.append(
            {
                "id": audit_id,
                "queue_id": int(row[1] or 0),
                "job_id": int(row[1] or 0),
                "inbox_id": str(row[2] or ""),
                "hostname": str(row[3] or ""),
                "host_uid": str(row[4] or ""),
                "report_received_at_utc": str(row[5] or ""),
                "enqueued_at_utc": str(row[6] or ""),
                "db_written_at_utc": str(row[7] or ""),
                "payload_bytes": int(row[8] or 0),
                "payload_stored": payload_stored,
                "payload_file_name": payload_file_name,
                "payload_download_path": payload_download_path,
                "attempt_count": int(row[10] or 0),
                "inbox_wait_ms": int(row[11] or 0),
                "queue_wait_ms": int(row[12] or 0),
                "processing_ms": int(row[13] or 0),
                "end_to_end_ms": int(row[14] or 0),
                "status": str(row[15] or "queued"),
                "error_message": str(row[16] or ""),
                "updated_at_utc": str(row[17] or ""),
                "main_report_id": int(row[18] or 0),
                "customer_name": customer_by_hostname.get(str(row[3] or "").strip(), ""),
            }
        )

    return {
        "limit": safe_limit,
        "retention_limit": INGEST_AUDIT_MAX_ROWS,
        "payload_capture_enabled": True,
        "payload_capture_mode": "inbox",
        "ingest_mode": "file-inbox",
        "entries": entries,
    }


def resolve_audit_payload_path(audit_id: int) -> Path | None:
    with sqlite_connect_ingest_status() as conn:
        row = conn.execute(
            "SELECT storage_path FROM ingest_audit_log WHERE id = ?",
            (int(audit_id),),
        ).fetchone()
    if not row:
        return None
    rel_path = str(row[0] or "").strip()
    if not rel_path:
        return None
    path = INGEST_INBOX_DIR / rel_path
    return path if path.is_file() else None


def _collect_audit_runtime_stats_local(conn: sqlite3.Connection, window_minutes: int = 60) -> dict[str, object]:
    cutoff_dt = datetime.now(timezone.utc) - timedelta(minutes=max(5, min(24 * 60, int(window_minutes))))
    cutoff_iso = cutoff_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    failed_last_hour = int(
        conn.execute(
            """
            SELECT COUNT(*) FROM ingest_audit_log
            WHERE updated_at_utc >= ? AND status = 'failed'
            """,
            (cutoff_iso,),
        ).fetchone()[0]
        or 0
    )
    sample_rows = conn.execute(
        """
        SELECT processing_ms, queue_wait_ms, inbox_wait_ms
        FROM ingest_audit_log
        WHERE updated_at_utc >= ? AND status = 'written'
        ORDER BY id DESC
        LIMIT 200
        """,
        (cutoff_iso,),
    ).fetchall()
    processing_samples = [max(0, int(row[0] or 0)) for row in sample_rows]
    queue_wait_samples = [max(0, int(row[1] or 0)) for row in sample_rows]
    inbox_wait_samples = [max(0, int(row[2] or 0)) for row in sample_rows]
    processing_avg_ms = int(sum(processing_samples) / len(processing_samples)) if processing_samples else 0
    queue_wait_avg_ms = int(sum(queue_wait_samples) / len(queue_wait_samples)) if queue_wait_samples else 0
    inbox_wait_avg_ms = int(sum(inbox_wait_samples) / len(inbox_wait_samples)) if inbox_wait_samples else 0
    processing_p95_ms = 0
    if processing_samples:
        ordered = sorted(processing_samples)
        p95_index = min(len(ordered) - 1, max(0, int(len(ordered) * 0.95) - 1))
        processing_p95_ms = int(ordered[p95_index])
    return {
        "window_minutes": window_minutes,
        "written_sample_count": len(processing_samples),
        "failed_count": failed_last_hour,
        "processing_avg_ms": processing_avg_ms,
        "processing_p95_ms": processing_p95_ms,
        "queue_wait_avg_ms": queue_wait_avg_ms,
        "inbox_wait_avg_ms": inbox_wait_avg_ms,
    }


def collect_ingest_audit_runtime_stats(conn: sqlite3.Connection, window_minutes: int = 60) -> dict[str, object]:
    return _collect_audit_runtime_stats_local(conn, window_minutes=window_minutes)


def _process_single_job(job_row: tuple) -> None:
    if not callable(_process_job_callback) or not callable(_sqlite_connect_main):
        raise RuntimeError("ingest inbox runtime hooks are not registered")

    job_id = int(job_row[0] or 0)
    attempt_count = int(job_row[15] or 0) + 1
    report_received_at_utc = str(job_row[6] or _utc_now_iso())
    enqueued_at_utc = str(job_row[8] or report_received_at_utc)
    inbox_written_at_utc = str(job_row[7] or enqueued_at_utc)
    storage_rel = str(job_row[12] or "").strip()
    processing_started_at_utc = _utc_now_iso()

    if attempt_count > INGEST_MAX_ATTEMPTS:
        error_message = f"max attempts ({INGEST_MAX_ATTEMPTS}) exceeded"
        with sqlite_connect_ingest_status() as ingest_conn:
            _update_audit_row(
                ingest_conn,
                job_id=job_id,
                status="failed",
                attempt_count=attempt_count,
                error_message=error_message,
            )
            ingest_conn.execute("DELETE FROM ingest_jobs WHERE id = ?", (job_id,))
            ingest_conn.commit()
        if storage_rel:
            src = INGEST_INBOX_DIR / storage_rel
            dst = INGEST_INBOX_FAILED_DIR / f"job-{job_id}-{int(time.time())}.json"
            try:
                if src.is_file():
                    src.replace(dst)
            except OSError:
                pass
        print(f"[ingest-inbox-worker] job_id={job_id} dropped: {error_message}")
        return

    envelope, payload = _load_job_payload(job_row)
    payload_json = json.dumps(payload, separators=(",", ":"))

    if callable(_quick_duplicate_report_id):
        duplicate_report_id = _quick_duplicate_report_id(payload, report_received_at_utc, payload_json)
        if duplicate_report_id > 0:
            written_at_utc = _utc_now_iso()
            duration = _agent_ingest_duration_ms if callable(_agent_ingest_duration_ms) else (lambda *_a, **_k: 0)
            queue_wait_ms = duration(enqueued_at_utc, processing_started_at_utc)
            processing_ms = duration(processing_started_at_utc, written_at_utc)
            end_to_end_ms = duration(report_received_at_utc, written_at_utc)
            inbox_wait_ms = duration(inbox_written_at_utc, enqueued_at_utc)
            with sqlite_connect_ingest_status() as ingest_conn:
                _update_audit_row(
                    ingest_conn,
                    job_id=job_id,
                    status="duplicate",
                    attempt_count=attempt_count,
                    db_written_at_utc=written_at_utc,
                    main_report_id=duplicate_report_id,
                    inbox_wait_ms=inbox_wait_ms,
                    queue_wait_ms=queue_wait_ms,
                    processing_ms=processing_ms,
                    end_to_end_ms=end_to_end_ms,
                    error_message="duplicate",
                )
                _delete_job_and_storage(ingest_conn, job_id, storage_rel)
            return

    if callable(_wait_for_login_slot):
        _wait_for_login_slot()

    with sqlite_connect_ingest_status() as ingest_conn:
        ingest_conn.execute("BEGIN IMMEDIATE")
        ingest_conn.execute(
            """
            UPDATE ingest_jobs
            SET status = 'processing',
                attempt_count = ?,
                processing_started_at_utc = ?,
                updated_at_utc = ?
            WHERE id = ?
            """,
            (attempt_count, processing_started_at_utc, processing_started_at_utc, job_id),
        )
        _update_audit_row(
            ingest_conn,
            job_id=job_id,
            status="processing",
            attempt_count=attempt_count,
        )
        ingest_conn.commit()

    try:
        with _sqlite_connect_main() as main_conn:
            batch_alarm_settings = _get_alarm_settings(main_conn) if callable(_get_alarm_settings) else {}
            hostname_key = str(payload.get("hostname", "") or "").strip()
            host_settings = (
                _get_host_settings(main_conn, hostname_key)
                if callable(_get_host_settings) and hostname_key
                else {}
            )
            report_id, post_commit_tasks = _process_job_callback(
                main_conn,
                payload,
                report_received_at_utc,
                alarm_settings=batch_alarm_settings,
                host_settings=host_settings,
            )
            main_conn.commit()

        written_at_utc = _utc_now_iso()
        duration = _agent_ingest_duration_ms if callable(_agent_ingest_duration_ms) else (lambda *_a, **_k: 0)
        inbox_wait_ms = duration(inbox_written_at_utc, enqueued_at_utc)
        queue_wait_ms = duration(enqueued_at_utc, processing_started_at_utc)
        processing_ms = duration(processing_started_at_utc, written_at_utc)
        end_to_end_ms = duration(report_received_at_utc, written_at_utc)

        if callable(_record_ingest_written):
            _record_ingest_written(processing_ms=processing_ms, queue_wait_ms=queue_wait_ms)
        if processing_ms >= _ingest_slow_log_ms:
            print(
                f"[ingest-inbox-worker] job_id={job_id} processing={processing_ms}ms "
                f"queue_wait={queue_wait_ms}ms host={hostname_key or '-'}"
            )

        with sqlite_connect_ingest_status() as ingest_conn:
            _update_audit_row(
                ingest_conn,
                job_id=job_id,
                status="written",
                attempt_count=attempt_count,
                db_written_at_utc=written_at_utc,
                main_report_id=int(report_id or 0),
                inbox_wait_ms=inbox_wait_ms,
                queue_wait_ms=queue_wait_ms,
                processing_ms=processing_ms,
                end_to_end_ms=end_to_end_ms,
            )
            _delete_job_and_storage(ingest_conn, job_id, storage_rel)

        if callable(_schedule_post_commit) and post_commit_tasks:
            _schedule_post_commit(post_commit_tasks)
        if callable(_invalidate_dashboard_kpis):
            _invalidate_dashboard_kpis()
    except Exception as exc:
        with sqlite_connect_ingest_status() as ingest_conn:
            _schedule_job_retry(
                ingest_conn,
                job_id=job_id,
                attempt_count=attempt_count,
                error_message=str(exc),
            )
        print(f"[ingest-inbox-worker] job_id={job_id} failed (attempt={attempt_count}): {exc}")


def ingest_worker_loop() -> None:
    while True:
        if callable(_should_pause_for_login) and _should_pause_for_login():
            _wakeup.wait(0.15)
            _wakeup.clear()
            continue

        had_work = False
        try:
            scan_pending_inbox_batch()
            now_iso = _utc_now_iso()
            with sqlite_connect_ingest_status() as ingest_conn:
                rows = ingest_conn.execute(
                    """
                    SELECT
                        id, inbox_id, job_token, hostname, host_uid, agent_id,
                        report_received_at_utc, inbox_written_at_utc, enqueued_at_utc,
                        next_attempt_at_utc, processing_started_at_utc, payload_bytes,
                        storage_path, payload_sha256, status, attempt_count, last_error, updated_at_utc
                    FROM ingest_jobs
                    WHERE status IN ('ready', 'retry')
                      AND next_attempt_at_utc <= ?
                    ORDER BY id ASC
                    LIMIT ?
                    """,
                    (now_iso, INGEST_BATCH_SIZE),
                ).fetchall()
                queue_depth = int(ingest_conn.execute("SELECT COUNT(*) FROM ingest_jobs").fetchone()[0] or 0)
                pending_count, _, _ = _pending_inbox_stats()
                queue_depth += pending_count

            if rows:
                had_work = True
                for job_row in rows:
                    if callable(_should_pause_for_login) and _should_pause_for_login():
                        break
                    _process_single_job(job_row)
                    if callable(_adaptive_throttle_sleep):
                        _adaptive_throttle_sleep(queue_depth)
        except Exception as exc:
            print(f"[ingest-inbox-worker] loop failure: {exc}")

        if had_work:
            continue
        _wakeup.wait(INGEST_WORKER_IDLE_SECONDS)
        _wakeup.clear()


def ingest_scanner_loop() -> None:
    while True:
        try:
            if ingest_file_inbox_enabled():
                processed = scan_pending_inbox_batch()
                if processed > 0:
                    wakeup_worker()
        except Exception as exc:
            print(f"[ingest-inbox-scanner] loop failure: {exc}")
        _wakeup.wait(INGEST_SCANNER_INTERVAL_SECONDS)
        _wakeup.clear()
