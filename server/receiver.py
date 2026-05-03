#!/usr/bin/env python3
import argparse
import base64
import csv
import hashlib
import hmac
import html
import io
import json
import os
import re
import secrets
import sqlite3
import tempfile
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from urllib import error, parse, request
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

try:
    import cairosvg as _cairosvg
    _CAIROSVG_AVAILABLE = True
except Exception:
    _cairosvg = None  # type: ignore
    _CAIROSVG_AVAILABLE = False

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "monitoring.db"
APP_LOGO_PATH = STATIC_DIR / "icons" / "logo.png"
ANG_LOGO_PATH = STATIC_DIR / "icons" / "ANG.png"
LINUX_LOGO_PATH = STATIC_DIR / "icons" / "linux.png"
WINDOWS_LOGO_PATH = STATIC_DIR / "icons" / "windows.png"
BUILD_VERSION_PATH = BASE_DIR.parent / "BUILD_VERSION"
AGENT_VERSION_PATH = BASE_DIR.parent / "AGENT_VERSION"
OPENAPI_SPEC_PATH = BASE_DIR.parent / "openapi.yaml"
API_KEY = os.getenv("MONITORING_API_KEY", "")
API_KEY_GRACE_ALLOW_KNOWN_HOSTS = os.getenv("MONITORING_API_KEY_GRACE_ALLOW_KNOWN_HOSTS", "1").strip().lower() in {"1", "true", "yes", "on"}
MAX_REPORTS_PER_HOST = int(os.getenv("MONITORING_MAX_REPORTS_PER_HOST", "2880"))
WARNING_THRESHOLD_PERCENT = float(os.getenv("MONITORING_WARNING_THRESHOLD", "80"))
CRITICAL_THRESHOLD_PERCENT = float(os.getenv("MONITORING_CRITICAL_THRESHOLD", "90"))
CPU_WARNING_THRESHOLD_PERCENT = 80.0
CPU_CRITICAL_THRESHOLD_PERCENT = 95.0
CPU_ALERT_WINDOW_REPORTS = 4
CPU_ALERT_MOUNTPOINT = "cpu"
RAM_WARNING_THRESHOLD_PERCENT = 85.0
RAM_CRITICAL_THRESHOLD_PERCENT = 95.0
RAM_ALERT_WINDOW_REPORTS = 4
RAM_ALERT_MOUNTPOINT = "ram"
TELEGRAM_ENABLED_DEFAULT = os.getenv("MONITORING_TELEGRAM_ENABLED", "0").strip().lower() in {"1", "true", "yes", "on"}
TELEGRAM_BOT_TOKEN_DEFAULT = os.getenv("MONITORING_TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID_DEFAULT = os.getenv("MONITORING_TELEGRAM_CHAT_ID", "")
WEB_DEFAULT_USERNAME = os.getenv("MONITORING_WEB_USER", "admin")
WEB_DEFAULT_PASSWORD = os.getenv("MONITORING_WEB_PASSWORD", "ChangeMe!2026")
WEB_SESSION_TTL_HOURS = 12
WEB_SESSION_COOKIE = "monitoring_session"
MIN_PASSWORD_LENGTH = 8
MICROSOFT_PROVIDER = "microsoft"
MICROSOFT_TENANT_ID_DEFAULT = os.getenv("MONITORING_MS_TENANT_ID", "organizations").strip() or "organizations"
MICROSOFT_CLIENT_ID_DEFAULT = os.getenv("MONITORING_MS_CLIENT_ID", "").strip()
MICROSOFT_CLIENT_SECRET_DEFAULT = os.getenv("MONITORING_MS_CLIENT_SECRET", "").strip()
MICROSOFT_OAUTH_ENABLED_DEFAULT = os.getenv("MONITORING_MS_OAUTH_ENABLED", "0").strip().lower() in {"1", "true", "yes", "on"}
MICROSOFT_OAUTH_SCOPES = [
    "offline_access",
    "openid",
    "profile",
    "email",
    "https://graph.microsoft.com/Mail.Send",
]
DEFAULT_TREND_DIGEST_TIME = "08:00"
DEFAULT_ALERT_DIGEST_TIME = "08:05"
SCHEDULE_TIMEZONE_NAME = os.getenv("MONITORING_SCHEDULE_TIMEZONE", "Europe/Zurich").strip() or "Europe/Zurich"
try:
    SCHEDULE_TIMEZONE = ZoneInfo(SCHEDULE_TIMEZONE_NAME)
except ZoneInfoNotFoundError:
    SCHEDULE_TIMEZONE = datetime.now().astimezone().tzinfo
    SCHEDULE_TIMEZONE_NAME = str(SCHEDULE_TIMEZONE) if SCHEDULE_TIMEZONE else "local"

DEFAULT_VISIBLE_FILESYSTEM_MOUNTPOINTS = {
    "/",
    "/usr/sap",
    "/hana",
    "/hana/log",
    "/hana/data",
    "/hana/shared",
    "/hana/shared/backup_service",
}


def parse_int(query: dict, key: str, default: int, min_value: int, max_value: int) -> int:
    raw = query.get(key, [str(default)])[0]
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(min_value, min(value, max_value))


def init_db() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                received_at_utc TEXT NOT NULL,
                agent_id TEXT,
                hostname TEXT,
                primary_ip TEXT,
                payload_json TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT NOT NULL,
                mountpoint TEXT NOT NULL,
                severity TEXT NOT NULL,
                used_percent REAL NOT NULL,
                status TEXT NOT NULL,
                created_at_utc TEXT NOT NULL,
                last_seen_at_utc TEXT NOT NULL,
                resolved_at_utc TEXT,
                report_id INTEGER,
                FOREIGN KEY(report_id) REFERENCES reports(id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS host_settings (
                hostname TEXT PRIMARY KEY,
                display_name_override TEXT,
                country_code_override TEXT NOT NULL DEFAULT '',
                is_favorite INTEGER NOT NULL DEFAULT 0,
                is_hidden INTEGER NOT NULL DEFAULT 0,
                updated_at_utc TEXT NOT NULL
            )
            """
        )
        existing_host_columns = {
            str(row[1])
            for row in conn.execute("PRAGMA table_info(host_settings)").fetchall()
        }
        if "is_favorite" not in existing_host_columns:
            conn.execute("ALTER TABLE host_settings ADD COLUMN is_favorite INTEGER NOT NULL DEFAULT 0")
        if "is_hidden" not in existing_host_columns:
            conn.execute("ALTER TABLE host_settings ADD COLUMN is_hidden INTEGER NOT NULL DEFAULT 0")
        if "country_code_override" not in existing_host_columns:
            conn.execute("ALTER TABLE host_settings ADD COLUMN country_code_override TEXT NOT NULL DEFAULT ''")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alarm_settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                warning_threshold_percent REAL NOT NULL,
                critical_threshold_percent REAL NOT NULL,
                warning_consecutive_hits INTEGER NOT NULL,
                warning_window_minutes INTEGER NOT NULL,
                critical_trigger_immediate INTEGER NOT NULL,
                cpu_warning_threshold_percent REAL NOT NULL,
                cpu_critical_threshold_percent REAL NOT NULL,
                cpu_alert_window_reports INTEGER NOT NULL,
                ram_warning_threshold_percent REAL NOT NULL,
                ram_critical_threshold_percent REAL NOT NULL,
                ram_alert_window_reports INTEGER NOT NULL,
                telegram_enabled INTEGER NOT NULL,
                telegram_bot_token TEXT NOT NULL,
                telegram_chat_id TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL
            )
            """
        )
        existing_alarm_columns = {
            str(row[1])
            for row in conn.execute("PRAGMA table_info(alarm_settings)").fetchall()
        }
        if "warning_consecutive_hits" not in existing_alarm_columns:
            conn.execute("ALTER TABLE alarm_settings ADD COLUMN warning_consecutive_hits INTEGER NOT NULL DEFAULT 2")
        if "warning_window_minutes" not in existing_alarm_columns:
            conn.execute("ALTER TABLE alarm_settings ADD COLUMN warning_window_minutes INTEGER NOT NULL DEFAULT 15")
        if "critical_trigger_immediate" not in existing_alarm_columns:
            conn.execute("ALTER TABLE alarm_settings ADD COLUMN critical_trigger_immediate INTEGER NOT NULL DEFAULT 1")
        if "cpu_warning_threshold_percent" not in existing_alarm_columns:
            conn.execute("ALTER TABLE alarm_settings ADD COLUMN cpu_warning_threshold_percent REAL NOT NULL DEFAULT 80")
        if "cpu_critical_threshold_percent" not in existing_alarm_columns:
            conn.execute("ALTER TABLE alarm_settings ADD COLUMN cpu_critical_threshold_percent REAL NOT NULL DEFAULT 95")
        if "cpu_alert_window_reports" not in existing_alarm_columns:
            conn.execute("ALTER TABLE alarm_settings ADD COLUMN cpu_alert_window_reports INTEGER NOT NULL DEFAULT 4")
        if "ram_warning_threshold_percent" not in existing_alarm_columns:
            conn.execute("ALTER TABLE alarm_settings ADD COLUMN ram_warning_threshold_percent REAL NOT NULL DEFAULT 85")
        if "ram_critical_threshold_percent" not in existing_alarm_columns:
            conn.execute("ALTER TABLE alarm_settings ADD COLUMN ram_critical_threshold_percent REAL NOT NULL DEFAULT 95")
        if "ram_alert_window_reports" not in existing_alarm_columns:
            conn.execute("ALTER TABLE alarm_settings ADD COLUMN ram_alert_window_reports INTEGER NOT NULL DEFAULT 4")
        if "alert_reminder_interval_hours" not in existing_alarm_columns:
            conn.execute("ALTER TABLE alarm_settings ADD COLUMN alert_reminder_interval_hours INTEGER NOT NULL DEFAULT 0")

        existing_alert_columns = {
            str(row[1])
            for row in conn.execute("PRAGMA table_info(alerts)").fetchall()
        }
        if "last_reminder_sent_utc" not in existing_alert_columns:
            conn.execute("ALTER TABLE alerts ADD COLUMN last_reminder_sent_utc TEXT")
        if "ack_note" not in existing_alert_columns:
            conn.execute("ALTER TABLE alerts ADD COLUMN ack_note TEXT")
        if "ack_by" not in existing_alert_columns:
            conn.execute("ALTER TABLE alerts ADD COLUMN ack_by TEXT")
        if "ack_at_utc" not in existing_alert_columns:
            conn.execute("ALTER TABLE alerts ADD COLUMN ack_at_utc TEXT")

        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alert_debounce (
                hostname TEXT NOT NULL,
                mountpoint TEXT NOT NULL,
                first_seen_at_utc TEXT NOT NULL,
                last_seen_at_utc TEXT NOT NULL,
                hit_count INTEGER NOT NULL,
                last_used_percent REAL NOT NULL,
                last_severity TEXT NOT NULL,
                PRIMARY KEY(hostname, mountpoint)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS web_users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0,
                is_disabled INTEGER NOT NULL DEFAULT 0,
                created_at_utc TEXT NOT NULL DEFAULT '',
                updated_at_utc TEXT NOT NULL
            )
            """
        )
        existing_web_user_columns = {
            str(row[1])
            for row in conn.execute("PRAGMA table_info(web_users)").fetchall()
        }
        if "is_admin" not in existing_web_user_columns:
            conn.execute("ALTER TABLE web_users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")
        if "is_disabled" not in existing_web_user_columns:
            conn.execute("ALTER TABLE web_users ADD COLUMN is_disabled INTEGER NOT NULL DEFAULT 0")
        if "created_at_utc" not in existing_web_user_columns:
            conn.execute("ALTER TABLE web_users ADD COLUMN created_at_utc TEXT NOT NULL DEFAULT ''")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS web_sessions (
                session_token TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                created_at_utc TEXT NOT NULL,
                expires_at_utc TEXT NOT NULL,
                last_activity_at_utc TEXT NOT NULL,
                FOREIGN KEY(username) REFERENCES web_users(username)
            )
            """
        )
        # Migration: Add last_activity_at_utc column if missing (for old databases)
        existing_web_sessions_columns = {
            str(row[1])
            for row in conn.execute("PRAGMA table_info(web_sessions)").fetchall()
        }
        if "last_activity_at_utc" not in existing_web_sessions_columns:
            conn.execute("ALTER TABLE web_sessions ADD COLUMN last_activity_at_utc TEXT NOT NULL DEFAULT ''")
            # Set activity timestamp to creation time for existing sessions
            conn.execute("UPDATE web_sessions SET last_activity_at_utc = created_at_utc WHERE last_activity_at_utc = ''")
        if "expires_at_utc" not in existing_web_sessions_columns:
            conn.execute("ALTER TABLE web_sessions ADD COLUMN expires_at_utc TEXT NOT NULL DEFAULT ''")
            # Backfill legacy/new rows for compatibility with older NOT NULL expectations
            conn.execute(
                """
                UPDATE web_sessions
                SET expires_at_utc = strftime('%Y-%m-%dT%H:%M:%SZ', datetime(last_activity_at_utc, '+1 hour'))
                WHERE COALESCE(expires_at_utc, '') = ''
                """
            )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at_utc TEXT NOT NULL,
                created_by TEXT NOT NULL,
                hostname TEXT NOT NULL,
                agent_id TEXT NOT NULL DEFAULT '',
                command_type TEXT NOT NULL,
                command_payload_json TEXT NOT NULL,
                status TEXT NOT NULL,
                expires_at_utc TEXT NOT NULL,
                executed_at_utc TEXT,
                result_json TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_agent_commands_host_status
            ON agent_commands(hostname, status, expires_at_utc, id)
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS muted_alert_rules (
                hostname TEXT NOT NULL,
                mountpoint TEXT NOT NULL,
                muted_by TEXT NOT NULL DEFAULT '',
                muted_at_utc TEXT NOT NULL,
                PRIMARY KEY(hostname, mountpoint)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS web_user_settings (
                username TEXT PRIMARY KEY,
                email_enabled INTEGER NOT NULL DEFAULT 0,
                email_recipient TEXT NOT NULL DEFAULT '',
                trend_email_enabled INTEGER NOT NULL DEFAULT 0,
                trend_email_time_hhmm TEXT NOT NULL DEFAULT '08:00',
                trend_email_last_sent_local_date TEXT NOT NULL DEFAULT '',
                alert_email_enabled INTEGER NOT NULL DEFAULT 0,
                alert_email_time_hhmm TEXT NOT NULL DEFAULT '08:05',
                alert_email_recipients TEXT NOT NULL DEFAULT '',
                alert_email_last_sent_local_date TEXT NOT NULL DEFAULT '',
                alert_instant_mail_enabled INTEGER NOT NULL DEFAULT 0,
                alert_instant_min_severity TEXT NOT NULL DEFAULT 'warning',
                updated_at_utc TEXT NOT NULL,
                FOREIGN KEY(username) REFERENCES web_users(username)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS web_user_filesystem_visibility_hidden (
                username TEXT NOT NULL,
                hostname TEXT NOT NULL,
                section TEXT NOT NULL,
                mountpoint TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL,
                PRIMARY KEY(username, hostname, section, mountpoint),
                FOREIGN KEY(username) REFERENCES web_users(username)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS web_user_filesystem_visibility_config (
                username TEXT NOT NULL,
                hostname TEXT NOT NULL,
                section TEXT NOT NULL,
                configured_at_utc TEXT NOT NULL,
                PRIMARY KEY(username, hostname, section),
                FOREIGN KEY(username) REFERENCES web_users(username)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS app_meta (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL
            )
            """
        )
        backup_service_migration_key = "fs_visibility_default_backup_service_v1"
        backup_service_migration_done = conn.execute(
            "SELECT 1 FROM app_meta WHERE key = ? LIMIT 1",
            (backup_service_migration_key,),
        ).fetchone()
        if not backup_service_migration_done:
            conn.execute(
                """
                DELETE FROM web_user_filesystem_visibility_hidden
                WHERE LOWER(mountpoint) = '/hana/shared/backup_service'
                  AND section IN ('fs-focus', 'large-files')
                """
            )
            conn.execute(
                """
                INSERT INTO app_meta (key, value, updated_at_utc)
                VALUES (?, '1', ?)
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at_utc = excluded.updated_at_utc
                """,
                (backup_service_migration_key, utc_now_iso()),
            )
        existing_web_user_settings_columns = {
            str(row[1])
            for row in conn.execute("PRAGMA table_info(web_user_settings)").fetchall()
        }
        if "trend_email_enabled" not in existing_web_user_settings_columns:
            conn.execute("ALTER TABLE web_user_settings ADD COLUMN trend_email_enabled INTEGER NOT NULL DEFAULT 0")
        if "trend_email_time_hhmm" not in existing_web_user_settings_columns:
            conn.execute("ALTER TABLE web_user_settings ADD COLUMN trend_email_time_hhmm TEXT NOT NULL DEFAULT '08:00'")
        if "trend_email_last_sent_local_date" not in existing_web_user_settings_columns:
            conn.execute("ALTER TABLE web_user_settings ADD COLUMN trend_email_last_sent_local_date TEXT NOT NULL DEFAULT ''")
        if "alert_email_enabled" not in existing_web_user_settings_columns:
            conn.execute("ALTER TABLE web_user_settings ADD COLUMN alert_email_enabled INTEGER NOT NULL DEFAULT 0")
        if "alert_email_time_hhmm" not in existing_web_user_settings_columns:
            conn.execute("ALTER TABLE web_user_settings ADD COLUMN alert_email_time_hhmm TEXT NOT NULL DEFAULT '08:05'")
        if "alert_email_recipients" not in existing_web_user_settings_columns:
            conn.execute("ALTER TABLE web_user_settings ADD COLUMN alert_email_recipients TEXT NOT NULL DEFAULT ''")
        if "alert_email_last_sent_local_date" not in existing_web_user_settings_columns:
            conn.execute("ALTER TABLE web_user_settings ADD COLUMN alert_email_last_sent_local_date TEXT NOT NULL DEFAULT ''")
        if "alert_instant_mail_enabled" not in existing_web_user_settings_columns:
            conn.execute("ALTER TABLE web_user_settings ADD COLUMN alert_instant_mail_enabled INTEGER NOT NULL DEFAULT 0")
        if "alert_instant_min_severity" not in existing_web_user_settings_columns:
            conn.execute("ALTER TABLE web_user_settings ADD COLUMN alert_instant_min_severity TEXT NOT NULL DEFAULT 'warning'")
        if "alert_instant_telegram_enabled" not in existing_web_user_settings_columns:
            conn.execute("ALTER TABLE web_user_settings ADD COLUMN alert_instant_telegram_enabled INTEGER NOT NULL DEFAULT 0")
        if "alert_telegram_chat_id" not in existing_web_user_settings_columns:
            conn.execute("ALTER TABLE web_user_settings ADD COLUMN alert_telegram_chat_id TEXT NOT NULL DEFAULT ''")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS web_user_alert_subscriptions (
                username TEXT NOT NULL,
                hostname TEXT NOT NULL,
                notify_mail INTEGER NOT NULL DEFAULT 1,
                notify_telegram INTEGER NOT NULL DEFAULT 0,
                updated_at_utc TEXT NOT NULL,
                PRIMARY KEY(username, hostname),
                FOREIGN KEY(username) REFERENCES web_users(username)
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_web_user_alert_subscriptions_host
            ON web_user_alert_subscriptions(hostname)
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS oauth_settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                microsoft_enabled INTEGER NOT NULL DEFAULT 0,
                microsoft_tenant_id TEXT NOT NULL DEFAULT '',
                microsoft_client_id TEXT NOT NULL DEFAULT '',
                microsoft_client_secret TEXT NOT NULL DEFAULT '',
                updated_at_utc TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS oauth_connections (
                username TEXT NOT NULL,
                provider TEXT NOT NULL,
                access_token TEXT NOT NULL,
                refresh_token TEXT NOT NULL,
                token_type TEXT NOT NULL DEFAULT 'Bearer',
                scopes TEXT NOT NULL DEFAULT '',
                expires_at_utc TEXT NOT NULL,
                external_email TEXT NOT NULL DEFAULT '',
                external_display_name TEXT NOT NULL DEFAULT '',
                updated_at_utc TEXT NOT NULL,
                PRIMARY KEY(username, provider),
                FOREIGN KEY(username) REFERENCES web_users(username)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS oauth_pending_states (
                state_token TEXT PRIMARY KEY,
                username TEXT NOT NULL,
                provider TEXT NOT NULL,
                redirect_path TEXT NOT NULL DEFAULT '/',
                created_at_utc TEXT NOT NULL,
                expires_at_utc TEXT NOT NULL,
                FOREIGN KEY(username) REFERENCES web_users(username)
            )
            """
        )
        conn.execute(
            """
            INSERT INTO alarm_settings (
                id,
                warning_threshold_percent,
                critical_threshold_percent,
                warning_consecutive_hits,
                warning_window_minutes,
                critical_trigger_immediate,
                cpu_warning_threshold_percent,
                cpu_critical_threshold_percent,
                cpu_alert_window_reports,
                ram_warning_threshold_percent,
                ram_critical_threshold_percent,
                ram_alert_window_reports,
                telegram_enabled,
                telegram_bot_token,
                telegram_chat_id,
                updated_at_utc
            )
            VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO NOTHING
            """,
            (
                WARNING_THRESHOLD_PERCENT,
                CRITICAL_THRESHOLD_PERCENT,
                2,
                15,
                1,
                CPU_WARNING_THRESHOLD_PERCENT,
                CPU_CRITICAL_THRESHOLD_PERCENT,
                CPU_ALERT_WINDOW_REPORTS,
                RAM_WARNING_THRESHOLD_PERCENT,
                RAM_CRITICAL_THRESHOLD_PERCENT,
                RAM_ALERT_WINDOW_REPORTS,
                1 if TELEGRAM_ENABLED_DEFAULT else 0,
                TELEGRAM_BOT_TOKEN_DEFAULT,
                TELEGRAM_CHAT_ID_DEFAULT,
                utc_now_iso(),
            ),
        )

        user_count = conn.execute("SELECT COUNT(*) FROM web_users").fetchone()[0]
        if int(user_count or 0) == 0:
            salt = secrets.token_hex(16)
            now_utc = utc_now_iso()
            conn.execute(
                """
                INSERT INTO web_users (
                    username,
                    password_hash,
                    password_salt,
                    is_admin,
                    is_disabled,
                    created_at_utc,
                    updated_at_utc
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    WEB_DEFAULT_USERNAME,
                    hash_password(WEB_DEFAULT_PASSWORD, salt),
                    salt,
                    1,
                    0,
                    now_utc,
                    now_utc,
                ),
            )
            conn.execute(
                """
                INSERT INTO web_user_settings (
                    username,
                    email_enabled,
                    email_recipient,
                    trend_email_enabled,
                    trend_email_time_hhmm,
                    trend_email_last_sent_local_date,
                    alert_email_enabled,
                    alert_email_time_hhmm,
                    alert_email_recipients,
                    alert_email_last_sent_local_date,
                    updated_at_utc
                )
                VALUES (?, 0, '', 0, ?, '', 0, ?, '', '', ?)
                ON CONFLICT(username) DO NOTHING
                """,
                (WEB_DEFAULT_USERNAME, DEFAULT_TREND_DIGEST_TIME, DEFAULT_ALERT_DIGEST_TIME, now_utc),
            )

        conn.execute(
            """
            INSERT INTO oauth_settings (
                id,
                microsoft_enabled,
                microsoft_tenant_id,
                microsoft_client_id,
                microsoft_client_secret,
                updated_at_utc
            )
            VALUES (1, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO NOTHING
            """,
            (
                1 if MICROSOFT_OAUTH_ENABLED_DEFAULT else 0,
                MICROSOFT_TENANT_ID_DEFAULT,
                MICROSOFT_CLIENT_ID_DEFAULT,
                MICROSOFT_CLIENT_SECRET_DEFAULT,
                utc_now_iso(),
            ),
        )

        conn.execute(
            "UPDATE web_users SET is_admin = 1 WHERE username = ?",
            (WEB_DEFAULT_USERNAME,),
        )
        conn.execute(
            "UPDATE web_users SET created_at_utc = updated_at_utc WHERE COALESCE(created_at_utc, '') = ''",
        )
        conn.execute(
            """
            INSERT INTO web_user_settings (
                username,
                email_enabled,
                email_recipient,
                trend_email_enabled,
                trend_email_time_hhmm,
                trend_email_last_sent_local_date,
                alert_email_enabled,
                alert_email_time_hhmm,
                alert_email_recipients,
                alert_email_last_sent_local_date,
                updated_at_utc
            )
            SELECT username, 0, '', 0, ?, '', 0, ?, '', '', updated_at_utc
            FROM web_users
            WHERE username NOT IN (SELECT username FROM web_user_settings)
            """
            ,
            (DEFAULT_TREND_DIGEST_TIME, DEFAULT_ALERT_DIGEST_TIME),
        )
        conn.execute(
            "UPDATE web_user_settings SET trend_email_time_hhmm = ? WHERE COALESCE(trend_email_time_hhmm, '') = ''",
            (DEFAULT_TREND_DIGEST_TIME,),
        )
        conn.execute(
            "UPDATE web_user_settings SET alert_email_time_hhmm = ? WHERE COALESCE(alert_email_time_hhmm, '') = ''",
            (DEFAULT_ALERT_DIGEST_TIME,),
        )

        session_cutoff_iso = utc_hours_ago_iso(1)
        conn.execute(
            "DELETE FROM web_sessions WHERE last_activity_at_utc <= ?",
            (session_cutoff_iso,),
        )
        conn.execute(
            "DELETE FROM oauth_pending_states WHERE expires_at_utc <= ?",
            (utc_now_iso(),),
        )
        conn.commit()


def create_sqlite_backup_bytes(source_path: Path) -> bytes:
    with tempfile.NamedTemporaryFile(prefix="monitoring-backup-", suffix=".db", delete=False) as tmp:
        temp_path = Path(tmp.name)

    try:
        with sqlite3.connect(f"file:{source_path}?mode=ro", uri=True) as source_conn:
            with sqlite3.connect(temp_path) as backup_conn:
                source_conn.backup(backup_conn)
                backup_conn.commit()
        return temp_path.read_bytes()
    finally:
        try:
            temp_path.unlink()
        except OSError:
            pass


def restore_sqlite_from_bytes(dest_path: Path, data: bytes) -> None:
    """Validate data is a SQLite file, then atomically replace dest_path."""
    if not data.startswith(b"SQLite format 3\x00"):
        raise ValueError("uploaded file is not a valid SQLite database")
    if len(data) < 100:
        raise ValueError("uploaded file is too small to be a valid database")

    with tempfile.NamedTemporaryFile(
        prefix="monitoring-restore-", suffix=".db",
        dir=dest_path.parent, delete=False
    ) as tmp:
        tmp_path = Path(tmp.name)
        tmp.write(data)

    try:
        # Verify the uploaded DB can be opened and read
        with sqlite3.connect(tmp_path) as test_conn:
            test_conn.execute("PRAGMA integrity_check").fetchone()
        # Atomic replace
        tmp_path.replace(dest_path)
    except Exception:
        try:
            tmp_path.unlink()
        except OSError:
            pass
        raise


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def format_mail_datetime(value: str | None = None) -> str:
    if not value:
        return datetime.now().astimezone().strftime("%d.%m.%Y %H:%M")
    raw = str(value).strip()
    if not raw:
        return datetime.now().astimezone().strftime("%d.%m.%Y %H:%M")
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone().strftime("%d.%m.%Y %H:%M")
    except ValueError:
        return raw


def utc_hours_ago_iso(hours: int) -> str:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    return cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")


def read_build_version() -> str:
    try:
        value = BUILD_VERSION_PATH.read_text(encoding="utf-8").strip()
        return value or "dev"
    except OSError:
        return "dev"


def parse_payload_json(payload_json: str) -> dict:
    try:
        value = json.loads(payload_json)
        if isinstance(value, dict):
            return value
    except json.JSONDecodeError:
        return {}
    return {}


def hash_password(password: str, salt_hex: str) -> str:
    salt = bytes.fromhex(salt_hex)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200000)
    return derived.hex()


def verify_password(password: str, password_hash: str, password_salt: str) -> bool:
    candidate = hash_password(password, password_salt)
    return hmac.compare_digest(candidate, password_hash)


def create_web_session(conn: sqlite3.Connection, username: str) -> tuple[str, str]:
    now = datetime.now(timezone.utc)
    session_token = secrets.token_urlsafe(32)
    now_iso = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    # Session expires 1 hour after last activity (inactivity timeout)
    expires = now + timedelta(hours=1)
    expires_iso = expires.strftime("%Y-%m-%dT%H:%M:%SZ")
    conn.execute(
        """
        INSERT INTO web_sessions (session_token, username, created_at_utc, expires_at_utc, last_activity_at_utc)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            session_token,
            username,
            now_iso,
            expires_iso,
            now_iso,
        ),
    )
    return session_token, expires_iso


def list_active_web_sessions(conn: sqlite3.Connection) -> list[dict]:
    now = datetime.now(timezone.utc)
    one_hour_ago = now - timedelta(hours=1)
    one_hour_ago_iso = one_hour_ago.strftime("%Y-%m-%dT%H:%M:%SZ")
    
    # Delete sessions that have been inactive for more than 1 hour
    conn.execute(
        "DELETE FROM web_sessions WHERE last_activity_at_utc <= ?",
        (one_hour_ago_iso,),
    )
    rows = conn.execute(
        """
        SELECT username, COUNT(*) AS session_count, MAX(last_activity_at_utc) AS latest_activity_at_utc
        FROM web_sessions
        WHERE last_activity_at_utc > ?
        GROUP BY username
        ORDER BY username COLLATE NOCASE ASC
        """,
        (one_hour_ago_iso,),
    ).fetchall()
    return [
        {
            "username": str(row[0] or ""),
            "session_count": int(row[1] or 0),
            "latest_activity_at_utc": str(row[2] or ""),
        }
        for row in rows
        if str(row[0] or "").strip()
    ]


def normalize_username(value: object) -> str:
    return str(value or "").strip()


def password_meets_policy(password: str) -> bool:
    return len(str(password or "")) >= MIN_PASSWORD_LENGTH


def parse_utc_iso(value: object) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def normalize_hhmm(value: object, fallback: str) -> str:
    text = str(value or "").strip()
    if len(text) != 5 or text[2] != ":":
        return fallback
    try:
        hour = int(text[:2])
        minute = int(text[3:5])
    except ValueError:
        return fallback
    if hour < 0 or hour > 23 or minute < 0 or minute > 59:
        return fallback
    return f"{hour:02d}:{minute:02d}"


def parse_email_recipients(value: object) -> list[str]:
    raw = str(value or "")
    parts = [item.strip() for item in re.split(r"[,;\n]+", raw) if item.strip()]
    unique: list[str] = []
    seen: set[str] = set()
    for item in parts:
        lowered = item.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        unique.append(item)
    return unique


def scheduled_digest_due(now_local: datetime, scheduled_hhmm: str, last_sent_local_date: str) -> bool:
    if not scheduled_hhmm:
        return False
    parts = scheduled_hhmm.split(":", 1)
    if len(parts) != 2:
        return False
    try:
        hour = int(parts[0])
        minute = int(parts[1])
    except ValueError:
        return False
    if hour < 0 or hour > 23 or minute < 0 or minute > 59:
        return False

    today = now_local.date().isoformat()
    if str(last_sent_local_date or "").strip() == today:
        return False
    return (now_local.hour, now_local.minute) >= (hour, minute)


def is_token_expiring_soon(expires_at_utc: str, within_minutes: int = 5) -> bool:
    expires_at = parse_utc_iso(expires_at_utc)
    if expires_at is None:
        return True
    return expires_at <= datetime.now(timezone.utc) + timedelta(minutes=max(1, within_minutes))


def decode_jwt_claims_unverified(token: str) -> dict:
    parts = str(token or "").split(".")
    if len(parts) < 2:
        return {}
    payload = parts[1]
    payload += "=" * (-len(payload) % 4)
    try:
        decoded = base64.urlsafe_b64decode(payload.encode("ascii"))
        value = json.loads(decoded.decode("utf-8"))
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def microsoft_scope_string() -> str:
    return " ".join(MICROSOFT_OAUTH_SCOPES)


def get_web_user(conn: sqlite3.Connection, username: str) -> dict | None:
    row = conn.execute(
        """
        SELECT username, password_hash, password_salt, COALESCE(is_admin, 0), COALESCE(is_disabled, 0),
               COALESCE(created_at_utc, ''), updated_at_utc
        FROM web_users
        WHERE username = ?
        """,
        (username,),
    ).fetchone()
    if not row:
        return None
    return {
        "username": str(row[0] or ""),
        "password_hash": str(row[1] or ""),
        "password_salt": str(row[2] or ""),
        "is_admin": bool(int(row[3] or 0)),
        "is_disabled": bool(int(row[4] or 0)),
        "created_at_utc": str(row[5] or ""),
        "updated_at_utc": str(row[6] or ""),
    }


def list_web_users(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        """
        SELECT u.username,
               COALESCE(u.is_admin, 0),
               COALESCE(u.is_disabled, 0),
               COALESCE(u.created_at_utc, ''),
               u.updated_at_utc,
               COALESCE(s.email_enabled, 0),
               COALESCE(s.email_recipient, ''),
             COALESCE(s.trend_email_enabled, 0),
             COALESCE(s.trend_email_time_hhmm, ''),
             COALESCE(s.alert_email_enabled, 0),
             COALESCE(s.alert_email_time_hhmm, ''),
               COALESCE(c.external_email, ''),
               COALESCE(c.updated_at_utc, '')
        FROM web_users u
        LEFT JOIN web_user_settings s ON s.username = u.username
        LEFT JOIN oauth_connections c ON c.username = u.username AND c.provider = ?
        ORDER BY LOWER(u.username)
        """,
        (MICROSOFT_PROVIDER,),
    ).fetchall()
    return [
        {
            "username": str(row[0] or ""),
            "is_admin": bool(int(row[1] or 0)),
            "is_disabled": bool(int(row[2] or 0)),
            "created_at_utc": str(row[3] or ""),
            "updated_at_utc": str(row[4] or ""),
            "email_enabled": bool(int(row[5] or 0)),
            "email_recipient": str(row[6] or ""),
            "trend_email_enabled": bool(int(row[7] or 0)),
            "trend_email_time_hhmm": normalize_hhmm(row[8], DEFAULT_TREND_DIGEST_TIME),
            "alert_email_enabled": bool(int(row[9] or 0)),
            "alert_email_time_hhmm": normalize_hhmm(row[10], DEFAULT_ALERT_DIGEST_TIME),
            "microsoft_connected_email": str(row[11] or ""),
            "microsoft_connected_at_utc": str(row[12] or ""),
            "has_microsoft_oauth": bool(str(row[11] or "").strip()),
        }
        for row in rows
    ]


def create_web_user(conn: sqlite3.Connection, username: str, password: str, is_admin: bool = False) -> dict:
    normalized_username = normalize_username(username)
    if not normalized_username:
        raise ValueError("username required")
    if not password_meets_policy(password):
        raise ValueError(f"password too short (min {MIN_PASSWORD_LENGTH})")
    if get_web_user(conn, normalized_username):
        raise ValueError("user already exists")

    now_utc = utc_now_iso()
    salt = secrets.token_hex(16)
    conn.execute(
        """
        INSERT INTO web_users (
            username,
            password_hash,
            password_salt,
            is_admin,
            is_disabled,
            created_at_utc,
            updated_at_utc
        )
        VALUES (?, ?, ?, ?, 0, ?, ?)
        """,
        (
            normalized_username,
            hash_password(password, salt),
            salt,
            1 if is_admin else 0,
            now_utc,
            now_utc,
        ),
    )
    conn.execute(
        """
        INSERT INTO web_user_settings (
            username,
            email_enabled,
            email_recipient,
            trend_email_enabled,
            trend_email_time_hhmm,
            trend_email_last_sent_local_date,
            alert_email_enabled,
            alert_email_time_hhmm,
            alert_email_last_sent_local_date,
            updated_at_utc
        )
        VALUES (?, 0, '', 0, ?, '', 0, ?, '', ?)
        """,
        (normalized_username, DEFAULT_TREND_DIGEST_TIME, DEFAULT_ALERT_DIGEST_TIME, now_utc),
    )
    created = get_web_user(conn, normalized_username)
    if created is None:
        raise ValueError("user creation failed")
    return created


def update_web_user_password(conn: sqlite3.Connection, username: str, new_password: str) -> None:
    if not password_meets_policy(new_password):
        raise ValueError(f"password too short (min {MIN_PASSWORD_LENGTH})")
    user = get_web_user(conn, username)
    if user is None:
        raise ValueError("user not found")
    new_salt = secrets.token_hex(16)
    conn.execute(
        """
        UPDATE web_users
        SET password_hash = ?, password_salt = ?, updated_at_utc = ?
        WHERE username = ?
        """,
        (hash_password(new_password, new_salt), new_salt, utc_now_iso(), username),
    )
    conn.execute("DELETE FROM web_sessions WHERE username = ?", (username,))


def update_web_user_flags(
    conn: sqlite3.Connection,
    username: str,
    *,
    is_admin: bool | None = None,
    is_disabled: bool | None = None,
) -> dict:
    user = get_web_user(conn, username)
    if user is None:
        raise ValueError("user not found")
    next_is_admin = user["is_admin"] if is_admin is None else bool(is_admin)
    next_is_disabled = user["is_disabled"] if is_disabled is None else bool(is_disabled)
    conn.execute(
        """
        UPDATE web_users
        SET is_admin = ?, is_disabled = ?, updated_at_utc = ?
        WHERE username = ?
        """,
        (1 if next_is_admin else 0, 1 if next_is_disabled else 0, utc_now_iso(), username),
    )
    if next_is_disabled:
        conn.execute("DELETE FROM web_sessions WHERE username = ?", (username,))
    updated = get_web_user(conn, username)
    if updated is None:
        raise ValueError("user update failed")
    return updated


def delete_web_user(conn: sqlite3.Connection, username: str) -> None:
    user = get_web_user(conn, username)
    if user is None:
        raise ValueError("user not found")
    conn.execute("DELETE FROM web_sessions WHERE username = ?", (username,))
    conn.execute("DELETE FROM oauth_pending_states WHERE username = ?", (username,))
    conn.execute("DELETE FROM oauth_connections WHERE username = ?", (username,))
    conn.execute("DELETE FROM web_user_alert_subscriptions WHERE username = ?", (username,))
    conn.execute("DELETE FROM web_user_settings WHERE username = ?", (username,))
    conn.execute("DELETE FROM web_users WHERE username = ?", (username,))


def get_web_user_settings(conn: sqlite3.Connection, username: str) -> dict:
    row = conn.execute(
        """
        SELECT COALESCE(email_enabled, 0),
               COALESCE(email_recipient, ''),
               COALESCE(trend_email_enabled, 0),
               COALESCE(trend_email_time_hhmm, ''),
               COALESCE(trend_email_last_sent_local_date, ''),
               COALESCE(alert_email_enabled, 0),
               COALESCE(alert_email_time_hhmm, ''),
               COALESCE(alert_email_recipients, ''),
               COALESCE(alert_email_last_sent_local_date, ''),
               COALESCE(alert_instant_mail_enabled, 0),
               COALESCE(alert_instant_min_severity, 'warning'),
             COALESCE(alert_instant_telegram_enabled, 0),
             COALESCE(alert_telegram_chat_id, ''),
               COALESCE(updated_at_utc, '')
        FROM web_user_settings
        WHERE username = ?
        """,
        (username,),
    ).fetchone()
    if not row:
        return {
            "email_enabled": False,
            "email_recipient": "",
            "trend_email_enabled": False,
            "trend_email_time_hhmm": DEFAULT_TREND_DIGEST_TIME,
            "trend_email_last_sent_local_date": "",
            "alert_email_enabled": False,
            "alert_email_time_hhmm": DEFAULT_ALERT_DIGEST_TIME,
            "alert_email_recipients": "",
            "alert_email_last_sent_local_date": "",
            "alert_instant_mail_enabled": False,
            "alert_instant_min_severity": "warning",
            "alert_instant_telegram_enabled": False,
            "alert_telegram_chat_id": "",
            "updated_at_utc": "",
        }
    return {
        "email_enabled": bool(int(row[0] or 0)),
        "email_recipient": str(row[1] or ""),
        "trend_email_enabled": bool(int(row[2] or 0)),
        "trend_email_time_hhmm": normalize_hhmm(row[3], DEFAULT_TREND_DIGEST_TIME),
        "trend_email_last_sent_local_date": str(row[4] or ""),
        "alert_email_enabled": bool(int(row[5] or 0)),
        "alert_email_time_hhmm": normalize_hhmm(row[6], DEFAULT_ALERT_DIGEST_TIME),
        "alert_email_recipients": str(row[7] or ""),
        "alert_email_last_sent_local_date": str(row[8] or ""),
        "alert_instant_mail_enabled": bool(int(row[9] or 0)),
        "alert_instant_min_severity": str(row[10] or "warning"),
        "alert_instant_telegram_enabled": bool(int(row[11] or 0)),
        "alert_telegram_chat_id": str(row[12] or ""),
        "updated_at_utc": str(row[13] or ""),
    }


def save_web_user_settings(conn: sqlite3.Connection, username: str, payload: dict) -> dict:
    existing = get_web_user_settings(conn, username)
    email_recipient = str(payload.get("email_recipient", existing.get("email_recipient", "")) or "").strip()
    email_enabled = coerce_bool(payload.get("email_enabled", existing.get("email_enabled", False)))
    trend_email_enabled = coerce_bool(payload.get("trend_email_enabled", existing.get("trend_email_enabled", False)))
    alert_email_enabled = coerce_bool(payload.get("alert_email_enabled", existing.get("alert_email_enabled", False)))
    trend_email_time_hhmm = normalize_hhmm(
        payload.get("trend_email_time_hhmm", existing.get("trend_email_time_hhmm", DEFAULT_TREND_DIGEST_TIME)),
        DEFAULT_TREND_DIGEST_TIME,
    )
    alert_email_time_hhmm = normalize_hhmm(
        payload.get("alert_email_time_hhmm", existing.get("alert_email_time_hhmm", DEFAULT_ALERT_DIGEST_TIME)),
        DEFAULT_ALERT_DIGEST_TIME,
    )
    alert_email_recipients = str(
        payload.get("alert_email_recipients", existing.get("alert_email_recipients", "")) or ""
    ).strip()
    trend_email_last_sent_local_date = str(
        payload.get("trend_email_last_sent_local_date", existing.get("trend_email_last_sent_local_date", "")) or ""
    ).strip()
    alert_email_last_sent_local_date = str(
        payload.get("alert_email_last_sent_local_date", existing.get("alert_email_last_sent_local_date", "")) or ""
    ).strip()
    alert_instant_mail_enabled = coerce_bool(payload.get("alert_instant_mail_enabled", existing.get("alert_instant_mail_enabled", False)))
    raw_min_sev = str(payload.get("alert_instant_min_severity", existing.get("alert_instant_min_severity", "warning")) or "warning").strip().lower()
    alert_instant_min_severity = raw_min_sev if raw_min_sev in {"warning", "critical"} else "warning"
    alert_instant_telegram_enabled = coerce_bool(
        payload.get("alert_instant_telegram_enabled", existing.get("alert_instant_telegram_enabled", False))
    )
    alert_telegram_chat_id = str(
        payload.get("alert_telegram_chat_id", existing.get("alert_telegram_chat_id", "")) or ""
    ).strip()
    now_utc = utc_now_iso()
    conn.execute(
        """
        INSERT INTO web_user_settings (
            username,
            email_enabled,
            email_recipient,
            trend_email_enabled,
            trend_email_time_hhmm,
            trend_email_last_sent_local_date,
            alert_email_enabled,
            alert_email_time_hhmm,
            alert_email_recipients,
            alert_email_last_sent_local_date,
            alert_instant_mail_enabled,
            alert_instant_min_severity,
            alert_instant_telegram_enabled,
            alert_telegram_chat_id,
            updated_at_utc
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(username) DO UPDATE SET
            email_enabled = excluded.email_enabled,
            email_recipient = excluded.email_recipient,
            trend_email_enabled = excluded.trend_email_enabled,
            trend_email_time_hhmm = excluded.trend_email_time_hhmm,
            trend_email_last_sent_local_date = excluded.trend_email_last_sent_local_date,
            alert_email_enabled = excluded.alert_email_enabled,
            alert_email_time_hhmm = excluded.alert_email_time_hhmm,
            alert_email_recipients = excluded.alert_email_recipients,
            alert_email_last_sent_local_date = excluded.alert_email_last_sent_local_date,
            alert_instant_mail_enabled = excluded.alert_instant_mail_enabled,
            alert_instant_min_severity = excluded.alert_instant_min_severity,
            alert_instant_telegram_enabled = excluded.alert_instant_telegram_enabled,
            alert_telegram_chat_id = excluded.alert_telegram_chat_id,
            updated_at_utc = excluded.updated_at_utc
        """,
        (
            username,
            1 if email_enabled else 0,
            email_recipient,
            1 if trend_email_enabled else 0,
            trend_email_time_hhmm,
            trend_email_last_sent_local_date,
            1 if alert_email_enabled else 0,
            alert_email_time_hhmm,
            alert_email_recipients,
            alert_email_last_sent_local_date,
            1 if alert_instant_mail_enabled else 0,
            alert_instant_min_severity,
            1 if alert_instant_telegram_enabled else 0,
            alert_telegram_chat_id,
            now_utc,
        ),
    )
    return {
        "email_enabled": email_enabled,
        "email_recipient": email_recipient,
        "trend_email_enabled": trend_email_enabled,
        "trend_email_time_hhmm": trend_email_time_hhmm,
        "trend_email_last_sent_local_date": trend_email_last_sent_local_date,
        "alert_email_enabled": alert_email_enabled,
        "alert_email_time_hhmm": alert_email_time_hhmm,
        "alert_email_recipients": alert_email_recipients,
        "alert_email_last_sent_local_date": alert_email_last_sent_local_date,
        "alert_instant_mail_enabled": alert_instant_mail_enabled,
        "alert_instant_min_severity": alert_instant_min_severity,
        "alert_instant_telegram_enabled": alert_instant_telegram_enabled,
        "alert_telegram_chat_id": alert_telegram_chat_id,
        "updated_at_utc": now_utc,
    }


def list_available_alert_hosts(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        """
        SELECT DISTINCT r.hostname, COALESCE(h.display_name_override, '')
        FROM reports r
        LEFT JOIN host_settings h ON h.hostname = r.hostname
        WHERE COALESCE(r.hostname, '') != ''
        ORDER BY LOWER(COALESCE(NULLIF(h.display_name_override, ''), r.hostname)), LOWER(r.hostname)
        """
    ).fetchall()
    return [
        {
            "hostname": str(row[0] or ""),
            "display_name": str(row[1] or "") if str(row[1] or "").strip() else str(row[0] or ""),
        }
        for row in rows
        if str(row[0] or "").strip()
    ]


def get_web_user_alert_subscriptions(conn: sqlite3.Connection, username: str) -> list[dict]:
    rows = conn.execute(
        """
        SELECT s.hostname,
               COALESCE(h.display_name_override, ''),
               COALESCE(s.notify_mail, 0),
               COALESCE(s.notify_telegram, 0),
               COALESCE(s.updated_at_utc, '')
        FROM web_user_alert_subscriptions s
        LEFT JOIN host_settings h ON h.hostname = s.hostname
        WHERE s.username = ?
        ORDER BY LOWER(COALESCE(NULLIF(h.display_name_override, ''), s.hostname)), LOWER(s.hostname)
        """,
        (username,),
    ).fetchall()
    return [
        {
            "hostname": str(row[0] or ""),
            "display_name": str(row[1] or "") if str(row[1] or "").strip() else str(row[0] or ""),
            "notify_mail": bool(int(row[2] or 0)),
            "notify_telegram": bool(int(row[3] or 0)),
            "updated_at_utc": str(row[4] or ""),
        }
        for row in rows
        if str(row[0] or "").strip()
    ]


def list_all_user_alert_subscriptions(conn: sqlite3.Connection) -> list[dict]:
    """Return all users together with their host alert subscriptions (admin view)."""
    users = list_web_users(conn)
    result = []
    for user in users:
        uname = user["username"]
        subs = get_web_user_alert_subscriptions(conn, uname)
        result.append(
            {
                "username": uname,
                "is_admin": user["is_admin"],
                "subscriptions": subs,
            }
        )
    return result


def replace_web_user_alert_subscriptions(conn: sqlite3.Connection, username: str, subscriptions: list[dict]) -> list[dict]:
    user = get_web_user(conn, username)
    if user is None:
        raise ValueError("user not found")

    now_utc = utc_now_iso()
    normalized: dict[str, dict] = {}
    for item in subscriptions:
        if not isinstance(item, dict):
            continue
        hostname = str(item.get("hostname", "") or "").strip()
        if not hostname:
            continue
        notify_mail = coerce_bool(item.get("notify_mail", False))
        notify_telegram = coerce_bool(item.get("notify_telegram", False))
        normalized[hostname] = {
            "notify_mail": notify_mail,
            "notify_telegram": notify_telegram,
        }

    conn.execute("DELETE FROM web_user_alert_subscriptions WHERE username = ?", (username,))

    for hostname, channel_settings in normalized.items():
        conn.execute(
            """
            INSERT INTO web_user_alert_subscriptions (
                username,
                hostname,
                notify_mail,
                notify_telegram,
                updated_at_utc
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                username,
                hostname,
                1 if channel_settings["notify_mail"] else 0,
                1 if channel_settings["notify_telegram"] else 0,
                now_utc,
            ),
        )

    return get_web_user_alert_subscriptions(conn, username)


def normalize_filesystem_visibility_section(value: object) -> str:
    section = str(value or "").strip().lower()
    return section if section in {"fs-focus", "large-files"} else ""


def normalize_mountpoint_for_visibility(value: object) -> str:
    mountpoint = str(value or "").strip()
    if not mountpoint:
        return ""
    return mountpoint[:512]


def normalize_mountpoint_key(value: object) -> str:
    return normalize_mountpoint_for_visibility(value).lower()


def is_default_visible_mountpoint(value: object) -> bool:
    return normalize_mountpoint_key(value) in DEFAULT_VISIBLE_FILESYSTEM_MOUNTPOINTS


def get_user_hidden_filesystems(conn: sqlite3.Connection, username: str, hostname: str, section: str) -> list[str]:
    rows = conn.execute(
        """
        SELECT mountpoint
        FROM web_user_filesystem_visibility_hidden
        WHERE username = ? AND hostname = ? AND section = ?
        ORDER BY LOWER(mountpoint), mountpoint
        """,
        (username, hostname, section),
    ).fetchall()
    return [str(row[0] or "") for row in rows if str(row[0] or "").strip()]


def is_user_filesystem_visibility_configured(conn: sqlite3.Connection, username: str, hostname: str, section: str) -> bool:
    row = conn.execute(
        """
        SELECT 1
        FROM web_user_filesystem_visibility_config
        WHERE username = ? AND hostname = ? AND section = ?
        LIMIT 1
        """,
        (username, hostname, section),
    ).fetchone()
    if row:
        return True

    legacy_row = conn.execute(
        """
        SELECT 1
        FROM web_user_filesystem_visibility_hidden
        WHERE username = ? AND hostname = ? AND section = ?
        LIMIT 1
        """,
        (username, hostname, section),
    ).fetchone()
    return bool(legacy_row)


def replace_user_hidden_filesystems(
    conn: sqlite3.Connection,
    username: str,
    hostname: str,
    section: str,
    hidden_mountpoints: list[object],
) -> list[str]:
    section_normalized = normalize_filesystem_visibility_section(section)
    if not section_normalized:
        raise ValueError("section must be fs-focus or large-files")

    hostname_normalized = str(hostname or "").strip()
    if not hostname_normalized:
        raise ValueError("hostname missing")

    unique_mountpoints: list[str] = []
    seen = set()
    for item in hidden_mountpoints:
        mountpoint = normalize_mountpoint_for_visibility(item)
        if not mountpoint:
            continue
        key = mountpoint.lower()
        if key in seen:
            continue
        seen.add(key)
        unique_mountpoints.append(mountpoint)

    now_utc = utc_now_iso()
    conn.execute(
        """
        DELETE FROM web_user_filesystem_visibility_hidden
        WHERE username = ? AND hostname = ? AND section = ?
        """,
        (username, hostname_normalized, section_normalized),
    )
    for mountpoint in unique_mountpoints:
        conn.execute(
            """
            INSERT INTO web_user_filesystem_visibility_hidden (
                username,
                hostname,
                section,
                mountpoint,
                updated_at_utc
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (username, hostname_normalized, section_normalized, mountpoint, now_utc),
        )

    conn.execute(
        """
        INSERT INTO web_user_filesystem_visibility_config (
            username,
            hostname,
            section,
            configured_at_utc
        )
        VALUES (?, ?, ?, ?)
        ON CONFLICT(username, hostname, section) DO UPDATE SET
            configured_at_utc = excluded.configured_at_utc
        """,
        (username, hostname_normalized, section_normalized, now_utc),
    )

    return get_user_hidden_filesystems(conn, username, hostname_normalized, section_normalized)


def unique_mountpoints(values: list[object]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        mountpoint = normalize_mountpoint_for_visibility(value)
        if not mountpoint:
            continue
        key = mountpoint.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(mountpoint)
    result.sort(key=lambda item: item.lower())
    return result


def ensure_default_user_filesystem_visibility(
    conn: sqlite3.Connection,
    username: str,
    hostname: str,
    section: str,
    available_mountpoints: list[object],
) -> list[str]:
    section_normalized = normalize_filesystem_visibility_section(section)
    if not section_normalized:
        return []

    hostname_normalized = str(hostname or "").strip()
    if not username or not hostname_normalized:
        return []

    candidates = unique_mountpoints(list(available_mountpoints or []))
    if is_user_filesystem_visibility_configured(conn, username, hostname_normalized, section_normalized):
        current_hidden = get_user_hidden_filesystems(conn, username, hostname_normalized, section_normalized)
        candidate_keys = {normalize_mountpoint_key(item) for item in candidates if normalize_mountpoint_key(item)}
        hidden_keys = {normalize_mountpoint_key(item) for item in current_hidden if normalize_mountpoint_key(item)}

        # Safety net: never keep a config that hides all currently available filesystems.
        if candidate_keys and candidate_keys.issubset(hidden_keys):
            if "/" in candidates:
                repaired_hidden = [item for item in current_hidden if normalize_mountpoint_key(item) != "/"]
            else:
                keep_visible_key = normalize_mountpoint_key(candidates[0])
                repaired_hidden = [item for item in current_hidden if normalize_mountpoint_key(item) != keep_visible_key]
            return replace_user_hidden_filesystems(conn, username, hostname_normalized, section_normalized, repaired_hidden)

        return current_hidden

    hidden_defaults = [mountpoint for mountpoint in candidates if not is_default_visible_mountpoint(mountpoint)]
    return replace_user_hidden_filesystems(conn, username, hostname_normalized, section_normalized, hidden_defaults)


def collect_critical_trends(conn: sqlite3.Connection, hours: int) -> list[dict]:
    cutoff_iso = utc_hours_ago_iso(hours)

    resource_metrics = [
        ("cpu_usage_percent", "CPU %"),
        ("memory_used_percent", "RAM %"),
        ("swap_used_percent", "Swap %"),
    ]

    def linear_regression_projected(values: list[float]) -> float | None:
        n = len(values)
        if n < 3:
            return None
        sum_x = n * (n - 1) // 2
        sum_x2 = (n - 1) * n * (2 * n - 1) // 6
        sum_y = sum(values)
        sum_xy = sum(i * v for i, v in enumerate(values))
        denom = n * sum_x2 - sum_x * sum_x
        if denom == 0:
            return None
        slope = (n * sum_xy - sum_x * sum_y) / denom
        intercept = (sum_y - slope * sum_x) / n
        return slope * (2 * (n - 1)) + intercept

    def trend_level(projected: float | None) -> str | None:
        if projected is None:
            return None
        if projected >= 100:
            return "crit"
        if projected >= 90:
            return "warn"
        return None

    warnings: list[dict] = []
    hostnames = [
        row[0]
        for row in conn.execute(
            "SELECT DISTINCT hostname FROM reports WHERE received_at_utc >= ? ORDER BY hostname ASC",
            (cutoff_iso,),
        ).fetchall()
    ]

    for hostname in hostnames:
        rows = conn.execute(
            """
            SELECT payload_json
            FROM reports
            WHERE hostname = ? AND received_at_utc >= ?
            ORDER BY id ASC
            """,
            (hostname, cutoff_iso),
        ).fetchall()

        if not rows:
            continue

        last_payload = parse_payload_json(rows[-1][0])
        host_settings = conn.execute(
            "SELECT COALESCE(display_name_override, ''), COALESCE(country_code_override, '') FROM host_settings WHERE hostname = ?",
            (hostname,),
        ).fetchone()
        muted_mountpoints = {
            str(item[0] or "").strip()
            for item in conn.execute(
                "SELECT mountpoint FROM muted_alert_rules WHERE hostname = ?",
                (hostname,),
            ).fetchall()
        }
        display_name_override = str(host_settings[0] or "").strip() if host_settings else ""
        country_code_override = normalize_country_code(host_settings[1] if host_settings else "")
        host_display_name = effective_display_name(last_payload, display_name_override, hostname)
        host_country_code = country_code_override or extract_country_code_from_payload(last_payload)
        host_os_family = normalize_os_family(last_payload.get("os", ""))
        host_primary_ip = str(last_payload.get("primary_ip", "") or "").strip()

        resource_series: dict[str, list[float]] = {
            "cpu_usage_percent": [],
            "memory_used_percent": [],
            "swap_used_percent": [],
        }
        fs_series: dict[str, list[float]] = {}

        for row in rows:
            payload = parse_payload_json(row[0])

            cpu = get_nested_number(payload, "cpu", "usage_percent")
            if cpu is not None:
                resource_series["cpu_usage_percent"].append(cpu)

            mem = get_nested_number(payload, "memory", "used_percent")
            if mem is not None:
                resource_series["memory_used_percent"].append(mem)

            swap = get_nested_number(payload, "swap", "used_percent")
            if swap is not None:
                resource_series["swap_used_percent"].append(swap)

            for fs in payload.get("filesystems", []):
                if not isinstance(fs, dict):
                    continue
                mountpoint = str(fs.get("mountpoint", "")).strip()
                try:
                    used_percent = float(fs["used_percent"])
                except (KeyError, TypeError, ValueError):
                    continue
                if mountpoint not in fs_series:
                    fs_series[mountpoint] = []
                fs_series[mountpoint].append(used_percent)

        for key, label in resource_metrics:
            values = resource_series[key]
            projected = linear_regression_projected(values)
            level = trend_level(projected)
            if not level:
                continue
            current = values[-1] if values else None
            warnings.append(
                {
                    "hostname": hostname,
                    "display_name": host_display_name,
                    "primary_ip": host_primary_ip,
                    "metric": label,
                    "metric_key": key,
                    "type": "resource",
                    "current": round(current, 1) if current is not None else None,
                    "projected": round(float(projected), 1),
                    "level": level,
                    "country_code": host_country_code,
                    "os_family": host_os_family,
                }
            )

        for mountpoint, values in fs_series.items():
            if mountpoint in muted_mountpoints:
                continue
            projected = linear_regression_projected(values)
            level = trend_level(projected)
            if not level:
                continue
            current = values[-1] if values else None
            warnings.append(
                {
                    "hostname": hostname,
                    "display_name": host_display_name,
                    "primary_ip": host_primary_ip,
                    "metric": mountpoint,
                    "metric_key": "filesystem",
                    "type": "filesystem",
                    "current": round(current, 1) if current is not None else None,
                    "projected": round(float(projected), 1),
                    "level": level,
                    "country_code": host_country_code,
                    "os_family": host_os_family,
                }
            )

    warnings.sort(key=lambda item: (0 if item["level"] == "crit" else 1, -item["projected"]))
    return warnings


def collect_inactive_hosts(conn: sqlite3.Connection, hours: int) -> list[dict]:
    cutoff_iso = utc_hours_ago_iso(hours)
    now_utc = datetime.now(timezone.utc)

    rows = conn.execute(
        """
        SELECT DISTINCT hostname FROM reports ORDER BY hostname
        """
    ).fetchall()

    inactive_hosts = []
    for (hostname,) in rows:
        last_report = conn.execute(
            """
            SELECT id, received_at_utc, payload_json
            FROM reports
            WHERE hostname = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (hostname,),
        ).fetchone()

        if not last_report:
            continue

        last_report_id, last_report_time_utc, payload_json_str = last_report
        if last_report_time_utc >= cutoff_iso:
            continue

        try:
            payload = json.loads(payload_json_str) if isinstance(payload_json_str, str) else {}
        except (json.JSONDecodeError, TypeError):
            payload = {}

        display_name = str(payload.get("agent_config", {}).get("DISPLAY_NAME", hostname) or hostname)
        os_name = str(payload.get("os", "") or "")
        primary_ip = str(payload.get("primary_ip", "") or "")

        host_settings = conn.execute(
            "SELECT display_name_override, country_code_override FROM host_settings WHERE hostname = ?",
            (hostname,),
        ).fetchone()
        if host_settings:
            override_name = host_settings[0]
            country_code = host_settings[1]
            if override_name:
                display_name = override_name
        else:
            country_code = ""

        open_alerts = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE hostname = ? AND status = 'open' AND (ack_at_utc IS NULL OR ack_at_utc = '')",
            (hostname,),
        ).fetchone()
        open_alert_count = open_alerts[0] if open_alerts else 0

        try:
            last_time = datetime.fromisoformat(last_report_time_utc.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            last_time = now_utc

        time_diff = now_utc - last_time
        hours_inactive = time_diff.total_seconds() / 3600

        inactive_hosts.append({
            "hostname": hostname,
            "display_name": display_name,
            "last_report_time_utc": last_report_time_utc,
            "hours_inactive": round(hours_inactive, 1),
            "os": os_name,
            "primary_ip": primary_ip,
            "country_code": country_code,
            "open_alert_count": open_alert_count,
        })

    inactive_hosts.sort(key=lambda item: -item["hours_inactive"])
    return inactive_hosts


def collect_open_alerts(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        """
        SELECT id, hostname, mountpoint, severity, used_percent, created_at_utc, last_seen_at_utc
        FROM alerts
        WHERE status = 'open'
          AND COALESCE((SELECT is_hidden FROM host_settings hs WHERE hs.hostname = alerts.hostname), 0) = 0
          AND NOT EXISTS (
              SELECT 1 FROM muted_alert_rules m
              WHERE m.hostname = alerts.hostname AND m.mountpoint = alerts.mountpoint
          )
        ORDER BY CASE severity WHEN 'critical' THEN 0 ELSE 1 END, used_percent DESC, id DESC
        """
    ).fetchall()

    hostnames = sorted({str(row[1] or "") for row in rows if str(row[1] or "")})
    display_names: dict[str, str] = {}
    country_codes: dict[str, str] = {}
    os_families: dict[str, str] = {}
    if hostnames:
        placeholders = ",".join("?" for _ in hostnames)
        settings_rows = conn.execute(
            f"SELECT hostname, display_name_override, COALESCE(country_code_override, '') FROM host_settings WHERE hostname IN ({placeholders})",
            tuple(hostnames),
        ).fetchall()
        overrides = {str(item[0]): str(item[1] or "") for item in settings_rows}
        country_overrides = {str(item[0]): normalize_country_code(item[2]) for item in settings_rows}

        latest_payload_rows = conn.execute(
            f"""
            SELECT hostname, COALESCE(primary_ip, ''), payload_json
            FROM reports
            WHERE id IN (
                SELECT MAX(id)
                FROM reports
                WHERE hostname IN ({placeholders})
                GROUP BY hostname
            )
            """,
            tuple(hostnames),
        ).fetchall()
        payload_by_hostname = {
            str(item[0]): parse_payload_json(str(item[2] or "{}"))
            for item in latest_payload_rows
        }
        primary_ip_by_hostname = {
            str(item[0]): str(item[1] or "").strip()
            for item in latest_payload_rows
        }

        for hostname in hostnames:
            payload = payload_by_hostname.get(hostname, {})
            display_names[hostname] = effective_display_name(payload, overrides.get(hostname, ""), hostname)
            country_codes[hostname] = country_overrides.get(hostname, "") or extract_country_code_from_payload(payload)
            os_families[hostname] = normalize_os_family(payload.get("os", ""))
    else:
        primary_ip_by_hostname = {}

    return [
        {
            "id": int(row[0] or 0),
            "hostname": str(row[1] or ""),
            "display_name": display_names.get(str(row[1] or ""), str(row[1] or "")),
            "primary_ip": primary_ip_by_hostname.get(str(row[1] or ""), ""),
            "mountpoint": str(row[2] or ""),
            "severity": str(row[3] or "warning"),
            "used_percent": float(row[4] or 0),
            "created_at_utc": str(row[5] or ""),
            "last_seen_at_utc": str(row[6] or ""),
            "country_code": country_codes.get(str(row[1] or ""), ""),
            "os_family": os_families.get(str(row[1] or ""), "linux"),
        }
        for row in rows
    ]


def _safe_attachment_token(value: str, fallback: str) -> str:
    token = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "")).strip("-._")
    return token or fallback


def _filesystem_usage_from_payload(payload: dict, mountpoint: str) -> float | None:
    mount = str(mountpoint or "").strip()
    if not mount:
        return None
    for item in payload.get("filesystems", []):
        if not isinstance(item, dict):
            continue
        if str(item.get("mountpoint", "")).strip() != mount:
            continue
        try:
            value = float(item.get("used_percent"))
        except (TypeError, ValueError):
            return None
        return max(0.0, min(value, 100.0))
    return None


def collect_filesystem_usage_series(
    conn: sqlite3.Connection,
    hostname: str,
    mountpoint: str,
    *,
    hours: int = 24,
    max_points: int = 72,
) -> list[float]:
    host = str(hostname or "").strip()
    mount = str(mountpoint or "").strip()
    if not host or not mount:
        return []

    cutoff_iso = utc_hours_ago_iso(hours)
    rows = conn.execute(
        """
        SELECT payload_json
        FROM reports
        WHERE hostname = ? AND received_at_utc >= ?
        ORDER BY id ASC
        """,
        (host, cutoff_iso),
    ).fetchall()

    values: list[float] = []
    for row in rows:
        payload = parse_payload_json(str(row[0] or "{}"))
        used = _filesystem_usage_from_payload(payload, mount)
        if used is not None:
            values.append(used)

    if len(values) <= max_points:
        return values

    step = max(1, len(values) // max_points)
    compact = [values[i] for i in range(0, len(values), step)]
    if compact and compact[-1] != values[-1]:
        compact.append(values[-1])
    return compact[-max_points:]


def render_usage_series_svg(
    values: list[float],
    *,
    warning_threshold: float = WARNING_THRESHOLD_PERCENT,
    critical_threshold: float = CRITICAL_THRESHOLD_PERCENT,
    severity: str = "warning",
    title: str = "Auslastung letzte 24h",
) -> str | None:
    if len(values) < 3:
        return None

    width = 640
    height = 220
    left = 44
    right = 16
    top = 16
    bottom = 32
    plot_width = width - left - right
    plot_height = height - top - bottom

    cleaned = [max(0.0, min(float(v), 100.0)) for v in values]
    n = len(cleaned)

    def x_at(index: int) -> float:
        if n <= 1:
            return float(left)
        return left + (plot_width * index / (n - 1))

    def y_at(percent: float) -> float:
        return top + (100.0 - percent) * plot_height / 100.0

    points = " ".join(f"{x_at(idx):.2f},{y_at(value):.2f}" for idx, value in enumerate(cleaned))
    fill_points = f"{left:.2f},{top + plot_height:.2f} {points} {left + plot_width:.2f},{top + plot_height:.2f}"

    warning_y = y_at(max(0.0, min(float(warning_threshold), 100.0)))
    critical_y = y_at(max(0.0, min(float(critical_threshold), 100.0)))
    last_value = cleaned[-1]
    line_color = "#dc2626" if severity == "critical" else "#d97706"
    if severity not in {"critical", "warning"}:
        line_color = "#2563eb"

    svg_title = html.escape(title)
    return (
        f"<svg xmlns='http://www.w3.org/2000/svg' width='{width}' height='{height}' viewBox='0 0 {width} {height}' role='img' aria-label='{svg_title}'>"
        "<defs>"
        "<linearGradient id='usageFill' x1='0' y1='0' x2='0' y2='1'>"
        "<stop offset='0%' stop-color='#93c5fd' stop-opacity='0.45'/>"
        "<stop offset='100%' stop-color='#93c5fd' stop-opacity='0.02'/>"
        "</linearGradient>"
        "</defs>"
        "<rect x='0' y='0' width='640' height='220' rx='12' fill='#ffffff'/>"
        f"<rect x='{left}' y='{top}' width='{plot_width}' height='{plot_height}' rx='10' fill='#f8fbff' stroke='#dbe4f0'/>"
        f"<line x1='{left}' y1='{warning_y:.2f}' x2='{left + plot_width}' y2='{warning_y:.2f}' stroke='#f59e0b' stroke-dasharray='5 4' stroke-width='1'/>"
        f"<line x1='{left}' y1='{critical_y:.2f}' x2='{left + plot_width}' y2='{critical_y:.2f}' stroke='#ef4444' stroke-dasharray='5 4' stroke-width='1'/>"
        f"<polyline points='{fill_points}' fill='url(#usageFill)' stroke='none'/>"
        f"<polyline points='{points}' fill='none' stroke='{line_color}' stroke-width='3' stroke-linecap='round' stroke-linejoin='round'/>"
        f"<circle cx='{x_at(n - 1):.2f}' cy='{y_at(last_value):.2f}' r='5' fill='{line_color}' stroke='#ffffff' stroke-width='2'/>"
        f"<text x='12' y='{y_at(100):.2f}' fill='#64748b' font-family='Segoe UI,Arial,sans-serif' font-size='11'>100%</text>"
        f"<text x='18' y='{y_at(50):.2f}' fill='#64748b' font-family='Segoe UI,Arial,sans-serif' font-size='11'>50%</text>"
        f"<text x='24' y='{y_at(0):.2f}' fill='#64748b' font-family='Segoe UI,Arial,sans-serif' font-size='11'>0%</text>"
        f"<text x='{left}' y='{height - 10}' fill='#64748b' font-family='Segoe UI,Arial,sans-serif' font-size='11'>letzte {n} Messpunkte</text>"
        f"<text x='{left + plot_width}' y='{height - 10}' text-anchor='end' fill='#0f172a' font-family='Segoe UI,Arial,sans-serif' font-size='12' font-weight='700'>aktuell {last_value:.1f}%</text>"
        "</svg>"
    )


def make_inline_svg_attachment(svg_content: str, *, cid: str, name: str) -> dict:
    return {
        "@odata.type": "#microsoft.graph.fileAttachment",
        "name": name,
        "contentType": "image/svg+xml",
        "isInline": True,
        "contentId": cid,
        "contentBytes": base64.b64encode(svg_content.encode("utf-8")).decode("ascii"),
    }


def svg_to_png_bytes(svg_content: str, *, scale: float = 1.5) -> bytes | None:
    """Convert SVG string to PNG bytes using cairosvg, returns None if unavailable."""
    if not _CAIROSVG_AVAILABLE or _cairosvg is None:
        return None
    try:
        return _cairosvg.svg2png(bytestring=svg_content.encode("utf-8"), scale=scale)
    except Exception:
        return None


def make_inline_png_attachment(png_bytes: bytes, *, cid: str, name: str) -> dict:
    return {
        "@odata.type": "#microsoft.graph.fileAttachment",
        "name": name,
        "contentType": "image/png",
        "isInline": True,
        "contentId": cid,
        "contentBytes": base64.b64encode(png_bytes).decode("ascii"),
    }


def build_alert_usage_graph_attachment(
    conn: sqlite3.Connection,
    hostname: str,
    mountpoint: str,
    *,
    severity: str,
    hours: int = 24,
) -> tuple[str | None, dict | None]:
    series = collect_filesystem_usage_series(conn, hostname, mountpoint, hours=hours)
    if len(series) < 3:
        return None, None

    graph_title = f"{hostname} {mountpoint} Auslastung (letzte {hours}h)"
    svg = render_usage_series_svg(series, severity=severity, title=graph_title)
    if not svg:
        return None, None

    safe_host = _safe_attachment_token(hostname, "host")
    safe_mount = _safe_attachment_token(mountpoint.replace("/", "-"), "mount")
    cid = f"graph-{safe_host}-{safe_mount}-{secrets.token_hex(4)}@monitoring"

    # Prefer PNG (works in Outlook); fall back to SVG if cairosvg unavailable
    png_bytes = svg_to_png_bytes(svg)
    if png_bytes:
        filename = f"graph-{safe_host}-{safe_mount}.png"
        return cid, make_inline_png_attachment(png_bytes, cid=cid, name=filename)

    filename = f"graph-{safe_host}-{safe_mount}.svg"
    return cid, make_inline_svg_attachment(svg, cid=cid, name=filename)


def build_alert_digest_graph_bundle(
    conn: sqlite3.Connection,
    alerts: list[dict],
    *,
    hours: int = 24,
    max_graphs: int = 8,
) -> tuple[dict[int, str], list[dict]]:
    graph_cids: dict[int, str] = {}
    attachments: list[dict] = []

    for item in alerts[:max_graphs]:
        alert_id = int(item.get("id") or 0)
        hostname = str(item.get("hostname") or "").strip()
        mountpoint = str(item.get("mountpoint") or "").strip()
        severity = str(item.get("severity") or "warning").strip().lower()
        if alert_id <= 0 or not hostname or not mountpoint or severity not in {"critical", "warning"}:
            continue

        cid, attachment = build_alert_usage_graph_attachment(
            conn,
            hostname,
            mountpoint,
            severity=severity,
            hours=hours,
        )
        if not cid or not attachment:
            continue
        graph_cids[alert_id] = cid
        attachments.append(attachment)

    return graph_cids, attachments


def host_badges_html(country_code: object, os_family: object) -> str:
    normalized_country_code = normalize_country_code(country_code)
    country_badge = normalized_country_code if normalized_country_code else "--"
    normalized_os_family = normalize_os_family(os_family)
    os_label = os_family_label(normalized_os_family)
    os_logo_uri = os_logo_data_uri(normalized_os_family)
    country_flag_uri = country_flag_data_uri(normalized_country_code)
    os_icon_html = (
        f"<img src='{html.escape(os_logo_uri)}' alt='{html.escape(os_label)}' width='13' height='13' style='display:block;'>"
        if os_logo_uri
        else ""
    )
    country_icon_html = (
        f"<img src='{html.escape(country_flag_uri)}' alt='{html.escape(country_badge)}' width='13' height='13' style='display:block;'>"
        if country_flag_uri
        else ""
    )
    os_badge = (
        f"<span style='display:inline-flex;align-items:center;padding:3px 6px;border-radius:999px;background:transparent;'>{os_icon_html}</span>"
        if os_icon_html else ""
    )
    country_badge_html = (
        f"<span style='display:inline-flex;align-items:center;padding:3px 6px;border-radius:999px;background:transparent;'>{country_icon_html}</span>"
        if country_icon_html else ""
    )
    return (
        "<div style='margin-top:4px;display:flex;gap:6px;flex-wrap:wrap;'>"
        f"{os_badge}{country_badge_html}"
        "</div>"
    )


def trend_digest_html(username: str, warnings: list[dict], hours: int) -> str:
    app_logo_uri = app_logo_data_uri()
    ang_logo_uri = ang_logo_data_uri()
    build_version = html.escape(read_build_version())
    rows_html = "".join(
        (
            "<tr>"
            f"<td style='padding:10px 8px;border-bottom:1px solid #e2e8f0;text-align:left;vertical-align:middle;'><div style='font-weight:600;'>{html.escape(str(item.get('display_name') or item.get('hostname') or '-'))}</div><div style='margin-top:3px;font-size:12px;color:#64748b;'>IP: {html.escape(str(item.get('primary_ip') or '-'))}</div>{host_badges_html(item.get('country_code', ''), item.get('os_family', 'linux'))}</td>"
            f"<td style='padding:10px 8px;border-bottom:1px solid #e2e8f0;text-align:left;vertical-align:middle;'>{html.escape(str(item.get('metric') or '-'))}</td>"
            f"<td style='padding:10px 8px;border-bottom:1px solid #e2e8f0;text-align:right;vertical-align:middle;font-variant-numeric:tabular-nums;'>{html.escape(str(item.get('current') if item.get('current') is not None else '-'))}%</td>"
            f"<td style='padding:10px 8px;border-bottom:1px solid #e2e8f0;text-align:right;vertical-align:middle;font-variant-numeric:tabular-nums;'><strong>{html.escape(str(item.get('projected') if item.get('projected') is not None else '-'))}%</strong></td>"
            f"<td style='padding:10px 8px;border-bottom:1px solid #e2e8f0;text-align:left;vertical-align:middle;'><span style='display:inline-block;padding:2px 8px;border-radius:999px;background:{'#fee2e2' if str(item.get('level')) == 'crit' else '#fef3c7'};color:{'#991b1b' if str(item.get('level')) == 'crit' else '#92400e'};font-weight:600;'>{'KRITISCH' if str(item.get('level')) == 'crit' else 'WARNUNG'}</span></td>"
            "</tr>"
        )
        for item in warnings
    )
    if not rows_html:
        rows_html = "<tr><td colspan='5' style='padding:12px 8px;text-align:left;color:#475569;'>Keine kritischen Trends im gewaehlten Zeitraum.</td></tr>"

    return (
        "<html><body style='margin:0;background:#ffffff;font-family:Segoe UI,Arial,sans-serif;color:#0f172a;'>"
        "<div style='max-width:900px;margin:24px auto;background:#ffffff;border:1px solid #d9dce3;border-radius:14px;overflow:hidden;'>"
        "<div style='padding:18px 20px;background-color:#eaf4ff;background-image:linear-gradient(180deg,#f4faff,#e6f1ff);color:#17324d;border-bottom:1px solid #cfe0f5;'>"
        "<div style='display:flex;align-items:center;gap:22px;margin-bottom:12px;'>"
        f"<img src='{app_logo_uri}' alt='Monitoring' width='44' height='44' style='display:block;width:44px;height:44px;'>"
        "<div>"
        "<div style='font-size:24px;font-weight:900;letter-spacing:.4px;line-height:1.05;'>MONITORING</div>"
        f"<div style='margin-top:4px;font-size:12px;color:#5f7590;'>powered by Rolf Walker &nbsp;&middot;&nbsp; v{build_version}</div>"
        "</div>"
        "</div>"
        "<h2 style='margin:0 0 6px 0;font-size:22px;color:#17324d;'>Daily Trend Digest</h2>"
        f"<div style='font-size:13px;color:#5f7590;'>Benutzer: {html.escape(username)} | Fenster: letzte {hours}h | Zeit: {html.escape(format_mail_datetime())}</div>"
        "</div>"
        "<div style='padding:18px 20px;'>"
        f"<p style='margin:0 0 14px 0;font-size:14px;'>Es wurden <strong>{len(warnings)}</strong> trend-kritische Signale erkannt.</p>"
        "<table style='width:100%;border-collapse:collapse;font-size:13px;'>"
        "<thead><tr style='background:#f1f5f9;'>"
        "<th style='text-align:left;padding:8px;border:1px solid #dbe3ef;'>Host</th>"
        "<th style='text-align:left;padding:8px;border:1px solid #dbe3ef;'>Trend</th>"
        "<th style='text-align:right;padding:8px;border:1px solid #dbe3ef;'>Aktuell</th>"
        "<th style='text-align:right;padding:8px;border:1px solid #dbe3ef;'>Prognose</th>"
        "<th style='text-align:left;padding:8px;border:1px solid #dbe3ef;'>Level</th>"
        "</tr></thead>"
        f"<tbody>{rows_html}</tbody>"
        "</table>"
        f"<div style='margin-top:18px;padding-top:14px;border-top:1px solid #e2e8f0;text-align:right;'><img src='{ang_logo_uri}' alt='ANG' width='110' style='display:inline-block;max-width:110px;height:auto;'></div>"
        "</div>"
        "</div>"
        "</body></html>"
    )


def trend_digest_subject(warnings: list[dict], local_date: str) -> str:
    critical_count = sum(1 for item in warnings if str(item.get("level")) == "crit")
    warning_count = sum(1 for item in warnings if str(item.get("level")) == "warn")
    if critical_count > 0:
        level = "KRITISCH"
    elif warning_count > 0:
        level = "WARNUNG"
    else:
        level = "INFO"
    return f"[Monitoring] [{level}] Trend Digest {local_date} (C:{critical_count} W:{warning_count})"


def alert_digest_html(username: str, alerts: list[dict], *, graph_cids: dict[int, str] | None = None, graph_hours: int = 24) -> str:
    app_logo_uri = app_logo_data_uri()
    ang_logo_uri = ang_logo_data_uri()
    build_version = html.escape(read_build_version())
    graph_lookup = graph_cids or {}
    row_parts: list[str] = []
    for item in alerts:
        severity = str(item.get("severity") or "warning")
        alert_id = int(item.get("id") or 0)
        graph_cid = graph_lookup.get(alert_id, "")
        graph_alt = html.escape(
            f"Verlaufsgrafik {str(item.get('display_name') or item.get('hostname') or '-')}: {str(item.get('mountpoint') or '-')}"
        )
        row_parts.append(
            f"<tr style='background:{'#fff1f2' if severity == 'critical' else '#fffaf0'};'>"
            f"<td style='padding:10px 8px;border-bottom:1px solid #fde2e2;text-align:left;vertical-align:middle;'><div style='font-weight:600;'>{html.escape(str(item.get('display_name') or item.get('hostname') or '-'))}</div><div style='margin-top:3px;font-size:12px;color:#64748b;'>IP: {html.escape(str(item.get('primary_ip') or '-'))}</div>{host_badges_html(item.get('country_code', ''), item.get('os_family', 'linux'))}</td>"
            f"<td style='padding:10px 8px;border-bottom:1px solid #fde2e2;text-align:left;vertical-align:middle;'>{html.escape(str(item.get('mountpoint') or '-'))}</td>"
            f"<td style='padding:10px 8px;border-bottom:1px solid #fde2e2;text-align:left;vertical-align:middle;'><strong style='color:{'#991b1b' if severity == 'critical' else '#9a3412'};'>{html.escape(str(item.get('severity') or '-').upper())}</strong></td>"
            f"<td style='padding:10px 8px;border-bottom:1px solid #fde2e2;text-align:right;vertical-align:middle;font-variant-numeric:tabular-nums;'>{html.escape('{:.1f}'.format(float(item.get('used_percent') or 0)))}%</td>"
            f"<td style='padding:10px 8px;border-bottom:1px solid #fde2e2;text-align:left;vertical-align:middle;font-variant-numeric:tabular-nums;'>{html.escape(format_mail_datetime(str(item.get('last_seen_at_utc') or '')))}</td>"
            "</tr>"
        )
        if graph_cid:
            row_parts.append(
                "<tr>"
                "<td colspan='5' style='padding:10px 8px 14px;border-bottom:1px solid #fde2e2;background:#ffffff;'>"
                f"<div style='margin:0 0 6px 0;font-size:12px;color:#64748b;'>Verlauf {graph_hours}h (Mountpoint-Auslastung)</div>"
                f"<img src='cid:{html.escape(graph_cid)}' alt='{graph_alt}' style='display:block;width:100%;max-width:620px;height:auto;border:1px solid #dbe3ef;border-radius:10px;background:#ffffff;'>"
                "</td>"
                "</tr>"
            )
    rows_html = "".join(row_parts)
    if not rows_html:
        rows_html = "<tr><td colspan='5' style='padding:12px 8px;text-align:left;color:#7f1d1d;'>Keine offenen Alarme vorhanden.</td></tr>"

    return (
        "<html><body style='margin:0;background:#ffffff;font-family:Segoe UI,Arial,sans-serif;color:#0f172a;'>"
        "<div style='max-width:900px;margin:24px auto;background:#ffffff;border:1px solid #d9dce3;border-radius:14px;overflow:hidden;'>"
        "<div style='padding:18px 20px;background-color:#eaf4ff;background-image:linear-gradient(180deg,#f4faff,#e6f1ff);color:#17324d;border-bottom:1px solid #cfe0f5;'>"
        "<div style='display:flex;align-items:center;gap:22px;margin-bottom:12px;'>"
        f"<img src='{app_logo_uri}' alt='Monitoring' width='44' height='44' style='display:block;width:44px;height:44px;'>"
        "<div>"
        "<div style='font-size:24px;font-weight:900;letter-spacing:.4px;line-height:1.05;'>MONITORING</div>"
        f"<div style='margin-top:4px;font-size:12px;color:#5f7590;'>powered by Rolf Walker &nbsp;&middot;&nbsp; v{build_version}</div>"
        "</div>"
        "</div>"
        "<h2 style='margin:0 0 6px 0;font-size:22px;color:#17324d;'>Open Alert Digest</h2>"
        f"<div style='font-size:13px;color:#5f7590;'>Benutzer: {html.escape(username)} | Zeit: {html.escape(format_mail_datetime())}</div>"
        "</div>"
        "<div style='padding:18px 20px;'>"
        f"<p style='margin:0 0 14px 0;font-size:14px;'>Aktuell <strong>{len(alerts)}</strong> offene, nicht stummgeschaltete Alarme.</p>"
        "<table style='width:100%;border-collapse:collapse;font-size:13px;'>"
        "<thead><tr style='background:#fee2e2;'>"
        "<th style='text-align:left;padding:8px;border:1px solid #fecaca;'>Host</th>"
        "<th style='text-align:left;padding:8px;border:1px solid #fecaca;'>Mountpoint</th>"
        "<th style='text-align:left;padding:8px;border:1px solid #fecaca;'>Severity</th>"
        "<th style='text-align:right;padding:8px;border:1px solid #fecaca;'>Used</th>"
        "<th style='text-align:left;padding:8px;border:1px solid #fecaca;'>Letztes Signal</th>"
        "</tr></thead>"
        f"<tbody>{rows_html}</tbody>"
        "</table>"
        f"<div style='margin-top:18px;padding-top:14px;border-top:1px solid #e2e8f0;text-align:right;'><img src='{ang_logo_uri}' alt='ANG' width='110' style='display:inline-block;max-width:110px;height:auto;'></div>"
        "</div>"
        "</div>"
        "</body></html>"
    )


def alert_digest_subject(alerts: list[dict], local_date: str) -> str:
    critical_count = sum(1 for item in alerts if str(item.get("severity")) == "critical")
    warning_count = sum(1 for item in alerts if str(item.get("severity")) == "warning")
    if critical_count > 0:
        level = "KRITISCH"
    elif warning_count > 0:
        level = "WARNUNG"
    else:
        level = "INFO"
    return f"[Monitoring] [{level}] Alert Digest {local_date} (C:{critical_count} W:{warning_count})"


def alert_instant_mail_subject(event_type: str, hostname: str, severity: str, display_name: str = "") -> str:
    sev_label = "KRITISCH" if severity == "critical" else "WARNUNG"
    event_label = {
        "opened": "Alarm ausgelöst",
        "escalated": "Alarm eskaliert",
        "resolved": "Alarm behoben",
        "reminder": "Heads-Up: Alert noch offen",
    }.get(event_type, "Alarm")
    title_target = display_name.strip() or hostname
    return f"[Monitoring] [{sev_label}] {event_label}: {title_target}"


def alert_instant_mail_html(
    username: str,
    event_type: str,
    hostname: str,
    mountpoint: str,
    severity: str,
    used_percent: float,
    display_name: str = "",
    primary_ip: str = "",
    country_code: str = "",
    os_family: str = "linux",
    reported_at_utc: str = "",
    graph_cid: str = "",
) -> str:
    normalized_severity = str(severity or "").strip().lower()
    if normalized_severity == "critical":
        sev_color, sev_bg, sev_text, sev_label = "#dc2626", "#fee2e2", "#991b1b", "KRITISCH"
    elif normalized_severity == "warning":
        sev_color, sev_bg, sev_text, sev_label = "#d97706", "#fef3c7", "#92400e", "WARNUNG"
    else:
        sev_color, sev_bg, sev_text, sev_label = "#2563eb", "#dbeafe", "#1e3a8a", "INFO"
    event_label = {
        "opened": "Alarm ausgelöst",
        "escalated": "Alarm eskaliert",
        "resolved": "Alarm behoben",
        "reminder": "Heads-Up: Alert noch offen",
    }.get(event_type, "Alarm")
    used_str = f"{used_percent:.1f}"
    customer_title = display_name.strip() or hostname
    normalized_country_code = normalize_country_code(country_code)
    country_badge = normalized_country_code if normalized_country_code else "--"
    normalized_os_family = normalize_os_family(os_family)
    os_label = os_family_label(normalized_os_family)
    os_logo_uri = os_logo_data_uri(normalized_os_family)
    country_flag_uri = country_flag_data_uri(normalized_country_code)
    os_icon_html = (
        f"<img src='{html.escape(os_logo_uri)}' alt='{html.escape(os_label)}' width='14' height='14' style='display:block;'>"
        if os_logo_uri
        else ""
    )
    country_icon_html = (
        f"<img src='{html.escape(country_flag_uri)}' alt='{html.escape(country_badge)}' width='14' height='14' style='display:block;'>"
        if country_flag_uri
        else ""
    )
    app_logo_uri = app_logo_data_uri()
    ang_logo_uri = ang_logo_data_uri()
    event_icon_uri = alert_event_icon_data_uri(event_type)
    linux_logo_uri = os_logo_data_uri("linux")
    windows_logo_uri = os_logo_data_uri("windows")
    event_icon_block = (
        f"<div style='margin-bottom:12px;'><img src='{html.escape(event_icon_uri)}' alt='{html.escape(event_label)}' width='52' height='52' style='display:block;'></div>"
        if event_icon_uri else ""
    )
    build_version = html.escape(read_build_version())
    reported_at = format_mail_datetime(reported_at_utc)
    graph_alt = html.escape(f"Auslastungsverlauf {customer_title}: {mountpoint}")
    is_cpu_alert = mountpoint == CPU_ALERT_MOUNTPOINT
    is_ram_alert = mountpoint == RAM_ALERT_MOUNTPOINT
    is_resource_alert = is_resource_alert_mountpoint(mountpoint)
    resource_row_label = "Ressource" if is_resource_alert else "Mountpoint"
    resource_row_value = "CPU" if is_cpu_alert else ("RAM" if is_ram_alert else mountpoint)
    value_row_label = "Auslastung"
    platform_row = (
        "<div style='margin-top:4px;display:flex;align-items:center;gap:8px;color:#5f7590;'>"
        f"<img src='{html.escape(linux_logo_uri)}' alt='Linux' width='16' height='16' style='display:block;'>"
        "<span style='font-size:14px;line-height:1;'>/</span>"
        f"<img src='{html.escape(windows_logo_uri)}' alt='Windows' width='16' height='16' style='display:block;'>"
        f"<span style='margin-left:10px;white-space:nowrap;'>v{build_version}</span>"
        "</div>"
    ) if linux_logo_uri and windows_logo_uri else ""
    graph_block = "" if is_resource_alert else (
        (
            "<div style='margin-top:14px;'>"
            "<div style='margin:0 0 6px 0;font-size:12px;color:#64748b;'>Verlauf letzte 24h (Mountpoint-Auslastung)</div>"
            f"<img src='cid:{html.escape(graph_cid)}' alt='{graph_alt}' style='display:block;width:100%;max-width:620px;height:auto;border:1px solid #dbe3ef;border-radius:10px;background:#ffffff;'>"
            "</div>"
        ) if graph_cid else (
            "<div style='margin-top:14px;padding:10px 12px;border-radius:10px;background:#f8fafc;border:1px solid #dbe3ef;color:#64748b;font-size:12px;'>"
            "Keine Verlaufsgrafik verfuegbar (zu wenig Datenpunkte).</div>"
        )
    )
    return (
        "<html><body style='margin:0;background:#ffffff;font-family:Segoe UI,Arial,sans-serif;color:#0f172a;'>"
        "<div style='max-width:700px;margin:24px auto;background:#ffffff;border:1px solid #d9dce3;border-radius:14px;overflow:hidden;'>"
        "<div style='padding:18px 20px;background-color:#eaf4ff;background-image:linear-gradient(180deg,#f4faff,#e6f1ff);color:#17324d;border-bottom:1px solid #cfe0f5;'>"
        "<div style='display:flex;align-items:center;gap:22px;margin-bottom:12px;'>"
        f"<img src='{app_logo_uri}' alt='Monitoring' width='44' height='44' style='display:block;width:44px;height:44px;'>"
        "<div>"
        "<div style='font-size:24px;font-weight:900;letter-spacing:.4px;line-height:1.05;'>Proaktives Monitoring</div>"
        f"{platform_row}"
        "</div>"
        "</div>"
        f"<div style='font-size:12px;color:#5f7590;margin-bottom:8px;'>Benutzer: {html.escape(username)} | {html.escape(format_mail_datetime())}</div>"
        f"<h1 style='margin:0;font-size:34px;line-height:1.05;font-weight:800;letter-spacing:.2px;color:#17324d;'>{html.escape(customer_title)}</h1>"
        f"<div style='margin-top:6px;font-size:14px;color:#5f7590;'>Host: {html.escape(hostname)}</div>"
        f"<div style='margin-top:4px;font-size:13px;color:#5f7590;'>IP: {html.escape(primary_ip or '-')}</div>"
        "<div style='margin-top:12px;display:flex;gap:8px;flex-wrap:wrap;'>"
        f"<span style='display:inline-flex;align-items:center;padding:3px 6px;border-radius:999px;background:transparent;'>{os_icon_html}</span>"
        f"<span style='display:inline-flex;align-items:center;padding:3px 6px;border-radius:999px;background:transparent;'>{country_icon_html}</span>"
        f"<span style='display:inline-flex;align-items:center;padding:4px 10px;border-radius:999px;background:{sev_bg};color:{sev_text};font-size:12px;font-weight:800;'>{sev_label}</span>"
        "</div>"
        "</div>"
        "<div style='padding:20px;'>"
        f"{event_icon_block}"
        f"<h2 style='margin:0 0 14px 0;font-size:20px;color:#0f172a;'>{html.escape(event_label)}</h2>"
        "<table style='width:100%;border-collapse:collapse;font-size:14px;'>"
        f"<tr><td style='padding:8px 0;color:#64748b;'>{html.escape(resource_row_label)}</td>"
        f"<td style='padding:8px 0;font-weight:600;'>{html.escape(resource_row_value)}</td></tr>"
        "<tr><td style='padding:8px 0;color:#64748b;'>Gemeldet am</td>"
        f"<td style='padding:8px 0;font-weight:600;'>{html.escape(reported_at)}</td></tr>"
        f"<tr><td style='padding:8px 0;color:#64748b;'>{html.escape(value_row_label)}</td>"
        f"<td style='padding:8px 0;font-weight:600;'>{used_str}%</td></tr>"
        "<tr><td style='padding:8px 0;color:#64748b;'>Schweregrad</td>"
        f"<td style='padding:8px 0;'><span style='display:inline-block;padding:2px 10px;border-radius:999px;background:{sev_bg};color:{sev_text};font-weight:700;font-size:12px;'>{sev_label}</span></td></tr>"
        "</table>"
        f"{graph_block}"
        f"<div style='margin-top:18px;padding-top:14px;border-top:1px solid #e2e8f0;text-align:right;'><img src='{ang_logo_uri}' alt='ANG' width='110' style='display:inline-block;max-width:110px;height:auto;'></div>"
        "</div>"
        "</div>"
        "</body></html>"
    )


def send_instant_alert_mails_to_users(
    conn: sqlite3.Connection,
    event_type: str,
    hostname: str,
    mountpoint: str,
    severity: str,
    used_percent: float,
) -> None:
    if event_type not in {"opened", "escalated", "resolved"}:
        return
    host_context = collect_host_mail_context(conn, hostname)
    reported_row = conn.execute(
        "SELECT created_at_utc FROM alerts WHERE hostname = ? AND mountpoint = ? ORDER BY id DESC LIMIT 1",
        (hostname, mountpoint),
    ).fetchone()
    reported_at_utc = str(reported_row[0] or "") if reported_row else utc_now_iso()
    try:
        rows = conn.execute(
            """
            SELECT u.username, COALESCE(s.alert_instant_min_severity, 'warning')
            FROM web_users u
            JOIN web_user_settings s ON s.username = u.username
                        JOIN web_user_alert_subscriptions sub ON sub.username = u.username
            WHERE COALESCE(u.is_disabled, 0) = 0
              AND COALESCE(s.alert_instant_mail_enabled, 0) = 1
              AND COALESCE(s.email_enabled, 0) = 1
              AND COALESCE(s.email_recipient, '') != ''
                            AND sub.hostname = ?
                            AND COALESCE(sub.notify_mail, 0) = 1
            """
                        ,
                        (hostname,),
        ).fetchall()
    except Exception:
        return

    for row in rows:
        username = str(row[0] or "").strip()
        min_severity = str(row[1] or "warning").strip().lower()
        if not username:
            continue
        if min_severity == "critical" and severity not in {"critical"}:
            continue
        user_settings = get_web_user_settings(conn, username)
        recipient = user_settings.get("email_recipient", "").strip()
        if not recipient:
            continue
        extra = parse_email_recipients(user_settings.get("alert_email_recipients", ""))
        all_recipients = parse_email_recipients(",".join([recipient] + extra))
        if not all_recipients:
            continue
        try:
            ok_token, access_token, _err = ensure_microsoft_access_token(conn, username)
            if not ok_token:
                continue
            if is_resource_alert_mountpoint(mountpoint):
                graph_cid = ""
                graph_attachments = []
            else:
                graph_cid, graph_attachment = build_alert_usage_graph_attachment(
                    conn,
                    hostname,
                    mountpoint,
                    severity=severity,
                    hours=24,
                )
                graph_attachments = [graph_attachment] if graph_attachment else []
            subject = alert_instant_mail_subject(
                event_type,
                hostname,
                severity,
                str(host_context.get("display_name", "") or ""),
            )
            body = alert_instant_mail_html(
                username,
                event_type,
                hostname,
                mountpoint,
                severity,
                used_percent,
                display_name=str(host_context.get("display_name", "") or ""),
                primary_ip=str(host_context.get("primary_ip", "") or ""),
                country_code=str(host_context.get("country_code", "") or ""),
                os_family=str(host_context.get("os_family", "linux") or "linux"),
                reported_at_utc=reported_at_utc,
                graph_cid=graph_cid or "",
            )
            send_microsoft_mail_multi(
                access_token,
                all_recipients,
                subject,
                body,
                content_type="HTML",
                attachments=graph_attachments,
            )
        except Exception:
            pass


def send_instant_alert_telegram_to_users(
    conn: sqlite3.Connection,
    event_type: str,
    hostname: str,
    mountpoint: str,
    severity: str,
    used_percent: float,
    display_name: str = "",
) -> None:
    if event_type not in {"opened", "escalated", "resolved"}:
        return

    alarm_settings = get_alarm_settings(conn)
    bot_token = str(alarm_settings.get("telegram_bot_token", "") or "").strip()
    if not alarm_settings.get("telegram_enabled") or not bot_token:
        return

    try:
        rows = conn.execute(
            """
            SELECT u.username,
                   COALESCE(s.alert_instant_min_severity, 'warning'),
                   COALESCE(s.alert_telegram_chat_id, '')
            FROM web_users u
            JOIN web_user_settings s ON s.username = u.username
            JOIN web_user_alert_subscriptions sub ON sub.username = u.username
            WHERE COALESCE(u.is_disabled, 0) = 0
              AND COALESCE(s.alert_instant_telegram_enabled, 0) = 1
              AND COALESCE(s.alert_telegram_chat_id, '') != ''
              AND sub.hostname = ?
              AND COALESCE(sub.notify_telegram, 0) = 1
            """,
            (hostname,),
        ).fetchall()
    except Exception:
        return

    alert_text = build_telegram_alert_text(event_type, hostname, mountpoint, severity, used_percent, display_name=display_name)
    icon_path = _ALERT_ICON_PATHS.get(event_type)

    for row in rows:
        username = str(row[0] or "").strip()
        min_severity = str(row[1] or "warning").strip().lower()
        chat_id = str(row[2] or "").strip()
        if not username or not chat_id:
            continue
        if min_severity == "critical" and severity not in {"critical"}:
            continue

        text = f"👤 *{_mdv2(username)}*\n{alert_text}"
        telegram_send_to_chat(bot_token, chat_id, text, image_path=icon_path)


def get_oauth_settings(conn: sqlite3.Connection) -> dict:
    row = conn.execute(
        """
        SELECT COALESCE(microsoft_enabled, 0), COALESCE(microsoft_tenant_id, ''),
               COALESCE(microsoft_client_id, ''), COALESCE(microsoft_client_secret, ''),
               COALESCE(updated_at_utc, '')
        FROM oauth_settings
        WHERE id = 1
        """
    ).fetchone()
    if not row:
        return {
            "microsoft_enabled": MICROSOFT_OAUTH_ENABLED_DEFAULT,
            "microsoft_tenant_id": MICROSOFT_TENANT_ID_DEFAULT,
            "microsoft_client_id": MICROSOFT_CLIENT_ID_DEFAULT,
            "microsoft_client_secret": MICROSOFT_CLIENT_SECRET_DEFAULT,
            "updated_at_utc": "",
        }
    return {
        "microsoft_enabled": bool(int(row[0] or 0)),
        "microsoft_tenant_id": str(row[1] or ""),
        "microsoft_client_id": str(row[2] or ""),
        "microsoft_client_secret": str(row[3] or ""),
        "updated_at_utc": str(row[4] or ""),
    }


def oauth_settings_public_view(settings: dict) -> dict:
    client_secret = str(settings.get("microsoft_client_secret", "") or "")
    return {
        "microsoft_enabled": bool(settings.get("microsoft_enabled")),
        "microsoft_tenant_id": str(settings.get("microsoft_tenant_id", "") or ""),
        "microsoft_client_id": str(settings.get("microsoft_client_id", "") or ""),
        "microsoft_client_secret_configured": bool(client_secret.strip()),
        "updated_at_utc": str(settings.get("updated_at_utc", "") or ""),
    }


def save_oauth_settings(conn: sqlite3.Connection, payload: dict) -> dict:
    existing = get_oauth_settings(conn)
    next_settings = {
        "microsoft_enabled": coerce_bool(payload.get("microsoft_enabled", existing.get("microsoft_enabled", False))),
        "microsoft_tenant_id": str(payload.get("microsoft_tenant_id", existing.get("microsoft_tenant_id", MICROSOFT_TENANT_ID_DEFAULT)) or "").strip() or "organizations",
        "microsoft_client_id": str(payload.get("microsoft_client_id", existing.get("microsoft_client_id", "")) or "").strip(),
        "microsoft_client_secret": str(payload.get("microsoft_client_secret", existing.get("microsoft_client_secret", "")) or "").strip(),
        "updated_at_utc": utc_now_iso(),
    }
    conn.execute(
        """
        INSERT INTO oauth_settings (
            id,
            microsoft_enabled,
            microsoft_tenant_id,
            microsoft_client_id,
            microsoft_client_secret,
            updated_at_utc
        )
        VALUES (1, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            microsoft_enabled = excluded.microsoft_enabled,
            microsoft_tenant_id = excluded.microsoft_tenant_id,
            microsoft_client_id = excluded.microsoft_client_id,
            microsoft_client_secret = excluded.microsoft_client_secret,
            updated_at_utc = excluded.updated_at_utc
        """,
        (
            1 if next_settings["microsoft_enabled"] else 0,
            next_settings["microsoft_tenant_id"],
            next_settings["microsoft_client_id"],
            next_settings["microsoft_client_secret"],
            next_settings["updated_at_utc"],
        ),
    )
    return next_settings


def oauth_is_configured(settings: dict) -> bool:
    return bool(
        settings.get("microsoft_enabled")
        and str(settings.get("microsoft_tenant_id", "")).strip()
        and str(settings.get("microsoft_client_id", "")).strip()
        and str(settings.get("microsoft_client_secret", "")).strip()
    )


def get_oauth_connection(conn: sqlite3.Connection, username: str, provider: str = MICROSOFT_PROVIDER) -> dict | None:
    row = conn.execute(
        """
        SELECT access_token, refresh_token, token_type, scopes, expires_at_utc,
               external_email, external_display_name, updated_at_utc
        FROM oauth_connections
        WHERE username = ? AND provider = ?
        """,
        (username, provider),
    ).fetchone()
    if not row:
        return None
    return {
        "username": username,
        "provider": provider,
        "access_token": str(row[0] or ""),
        "refresh_token": str(row[1] or ""),
        "token_type": str(row[2] or "Bearer"),
        "scopes": str(row[3] or ""),
        "expires_at_utc": str(row[4] or ""),
        "external_email": str(row[5] or ""),
        "external_display_name": str(row[6] or ""),
        "updated_at_utc": str(row[7] or ""),
    }


def upsert_oauth_connection(
    conn: sqlite3.Connection,
    username: str,
    provider: str,
    token_payload: dict,
    id_claims: dict | None = None,
) -> dict:
    id_token_claims = id_claims or decode_jwt_claims_unverified(token_payload.get("id_token", ""))
    expires_in = max(60, int(token_payload.get("expires_in", 3600) or 3600))
    expires_at_utc = (datetime.now(timezone.utc) + timedelta(seconds=expires_in)).strftime("%Y-%m-%dT%H:%M:%SZ")
    external_email = str(
        id_token_claims.get("preferred_username")
        or id_token_claims.get("email")
        or id_token_claims.get("upn")
        or ""
    ).strip()
    external_display_name = str(id_token_claims.get("name") or external_email or username).strip()
    scopes = token_payload.get("scope", "")
    if isinstance(scopes, list):
        scopes = " ".join(str(item).strip() for item in scopes if str(item).strip())
    now_utc = utc_now_iso()
    conn.execute(
        """
        INSERT INTO oauth_connections (
            username,
            provider,
            access_token,
            refresh_token,
            token_type,
            scopes,
            expires_at_utc,
            external_email,
            external_display_name,
            updated_at_utc
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(username, provider) DO UPDATE SET
            access_token = excluded.access_token,
            refresh_token = excluded.refresh_token,
            token_type = excluded.token_type,
            scopes = excluded.scopes,
            expires_at_utc = excluded.expires_at_utc,
            external_email = excluded.external_email,
            external_display_name = excluded.external_display_name,
            updated_at_utc = excluded.updated_at_utc
        """,
        (
            username,
            provider,
            str(token_payload.get("access_token", "") or ""),
            str(token_payload.get("refresh_token", "") or ""),
            str(token_payload.get("token_type", "Bearer") or "Bearer"),
            str(scopes or "").strip(),
            expires_at_utc,
            external_email,
            external_display_name,
            now_utc,
        ),
    )
    connection = get_oauth_connection(conn, username, provider)
    if connection is None:
        raise ValueError("oauth connection persistence failed")
    return connection


def delete_oauth_connection(conn: sqlite3.Connection, username: str, provider: str = MICROSOFT_PROVIDER) -> None:
    conn.execute(
        "DELETE FROM oauth_connections WHERE username = ? AND provider = ?",
        (username, provider),
    )


def create_oauth_state(
    conn: sqlite3.Connection,
    username: str,
    provider: str,
    redirect_path: str = "/",
    ttl_minutes: int = 10,
) -> str:
    state_token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=max(1, min(ttl_minutes, 30)))
    conn.execute(
        """
        INSERT INTO oauth_pending_states (
            state_token,
            username,
            provider,
            redirect_path,
            created_at_utc,
            expires_at_utc
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            state_token,
            username,
            provider,
            redirect_path,
            now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
        ),
    )
    return state_token


def consume_oauth_state(conn: sqlite3.Connection, state_token: str, provider: str) -> dict | None:
    conn.execute("DELETE FROM oauth_pending_states WHERE expires_at_utc <= ?", (utc_now_iso(),))
    row = conn.execute(
        """
        SELECT username, redirect_path, expires_at_utc
        FROM oauth_pending_states
        WHERE state_token = ? AND provider = ?
        """,
        (state_token, provider),
    ).fetchone()
    if not row:
        return None
    conn.execute("DELETE FROM oauth_pending_states WHERE state_token = ?", (state_token,))
    expires_at = parse_utc_iso(row[2])
    if expires_at is None or expires_at <= datetime.now(timezone.utc):
        return None
    return {
        "username": str(row[0] or ""),
        "redirect_path": str(row[1] or "/") or "/",
    }


def current_user_payload(conn: sqlite3.Connection, username: str) -> dict:
    user = get_web_user(conn, username)
    if user is None:
        raise ValueError("user not found")
    settings = get_web_user_settings(conn, username)
    oauth_settings = get_oauth_settings(conn)
    connection = get_oauth_connection(conn, username, MICROSOFT_PROVIDER)
    return {
        "username": user["username"],
        "is_admin": user["is_admin"],
        "is_disabled": user["is_disabled"],
        "created_at_utc": user["created_at_utc"],
        "updated_at_utc": user["updated_at_utc"],
        "email_enabled": settings["email_enabled"],
        "email_recipient": settings["email_recipient"],
        "trend_email_enabled": settings["trend_email_enabled"],
        "trend_email_time_hhmm": settings["trend_email_time_hhmm"],
        "alert_email_enabled": settings["alert_email_enabled"],
        "alert_email_time_hhmm": settings["alert_email_time_hhmm"],
        "alert_email_recipients": settings["alert_email_recipients"],
        "alert_instant_mail_enabled": settings["alert_instant_mail_enabled"],
        "alert_instant_min_severity": settings["alert_instant_min_severity"],
        "alert_instant_telegram_enabled": settings["alert_instant_telegram_enabled"],
        "alert_telegram_chat_id": settings["alert_telegram_chat_id"],
        "mail_oauth_available": oauth_is_configured(oauth_settings),
        "microsoft_oauth": {
            "connected": connection is not None,
            "external_email": connection["external_email"] if connection else "",
            "external_display_name": connection["external_display_name"] if connection else "",
            "expires_at_utc": connection["expires_at_utc"] if connection else "",
            "updated_at_utc": connection["updated_at_utc"] if connection else "",
        },
    }


def microsoft_authorize_endpoint(tenant_id: str) -> str:
    tenant = str(tenant_id or "organizations").strip() or "organizations"
    return f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"


def microsoft_token_endpoint(tenant_id: str) -> str:
    tenant = str(tenant_id or "organizations").strip() or "organizations"
    return f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"


def build_microsoft_authorize_url(settings: dict, redirect_uri: str, state_token: str) -> str:
    query = parse.urlencode(
        {
            "client_id": str(settings.get("microsoft_client_id", "") or "").strip(),
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "response_mode": "query",
            "scope": microsoft_scope_string(),
            "state": state_token,
            "prompt": "select_account",
        }
    )
    return f"{microsoft_authorize_endpoint(settings.get('microsoft_tenant_id', 'organizations'))}?{query}"


def request_json(
    url: str,
    *,
    method: str = "GET",
    payload: dict | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 15,
) -> tuple[int, dict, str]:
    data = None
    request_headers = dict(headers or {})
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/json")
    req = request.Request(url, data=data, method=method.upper())
    for key, value in request_headers.items():
        req.add_header(key, value)

    try:
        with request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            try:
                parsed_body = json.loads(body) if body else {}
            except json.JSONDecodeError:
                parsed_body = {}
            return resp.status, parsed_body if isinstance(parsed_body, dict) else {}, body
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            parsed_body = json.loads(body) if body else {}
        except json.JSONDecodeError:
            parsed_body = {}
        return exc.code, parsed_body if isinstance(parsed_body, dict) else {}, body


def request_form_encoded(
    url: str,
    form_data: dict[str, str],
    *,
    timeout: int = 15,
) -> tuple[int, dict, str]:
    encoded = parse.urlencode(form_data).encode("utf-8")
    req = request.Request(url, data=encoded, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            try:
                parsed_body = json.loads(body) if body else {}
            except json.JSONDecodeError:
                parsed_body = {}
            return resp.status, parsed_body if isinstance(parsed_body, dict) else {}, body
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            parsed_body = json.loads(body) if body else {}
        except json.JSONDecodeError:
            parsed_body = {}
        return exc.code, parsed_body if isinstance(parsed_body, dict) else {}, body
    except error.URLError as exc:
        return 0, {}, str(exc)


def exchange_microsoft_code_for_tokens(settings: dict, code: str, redirect_uri: str) -> tuple[bool, dict, str]:
    status, payload, raw = request_form_encoded(
        microsoft_token_endpoint(settings.get("microsoft_tenant_id", "organizations")),
        {
            "client_id": str(settings.get("microsoft_client_id", "") or ""),
            "client_secret": str(settings.get("microsoft_client_secret", "") or ""),
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "scope": microsoft_scope_string(),
        },
    )
    if status < 200 or status >= 300:
        return False, payload, raw
    return True, payload, raw


def refresh_microsoft_tokens(settings: dict, connection: dict) -> tuple[bool, dict, str]:
    status, payload, raw = request_form_encoded(
        microsoft_token_endpoint(settings.get("microsoft_tenant_id", "organizations")),
        {
            "client_id": str(settings.get("microsoft_client_id", "") or ""),
            "client_secret": str(settings.get("microsoft_client_secret", "") or ""),
            "grant_type": "refresh_token",
            "refresh_token": str(connection.get("refresh_token", "") or ""),
            "scope": microsoft_scope_string(),
        },
    )
    if status < 200 or status >= 300:
        return False, payload, raw
    if not payload.get("refresh_token"):
        payload["refresh_token"] = connection.get("refresh_token", "")
    return True, payload, raw


def ensure_microsoft_access_token(conn: sqlite3.Connection, username: str) -> tuple[bool, str, str]:
    settings = get_oauth_settings(conn)
    if not oauth_is_configured(settings):
        return False, "", "Microsoft OAuth ist noch nicht konfiguriert."
    connection = get_oauth_connection(conn, username, MICROSOFT_PROVIDER)
    if connection is None:
        return False, "", "Kein Microsoft OAuth Konto verbunden."
    if not connection.get("access_token"):
        return False, "", "Microsoft OAuth Token fehlt."
    if not is_token_expiring_soon(connection.get("expires_at_utc", "")):
        return True, str(connection.get("access_token", "") or ""), ""

    ok, payload, raw = refresh_microsoft_tokens(settings, connection)
    if not ok:
        return False, "", raw or payload.get("error_description", "Token-Refresh fehlgeschlagen")

    refreshed = upsert_oauth_connection(
        conn,
        username,
        MICROSOFT_PROVIDER,
        payload,
        {
            "preferred_username": connection.get("external_email", ""),
            "name": connection.get("external_display_name", ""),
        },
    )
    return True, refreshed["access_token"], ""


def send_microsoft_mail(
    access_token: str,
    recipient: str,
    subject: str,
    content: str,
    *,
    content_type: str = "Text",
    attachments: list[dict] | None = None,
) -> tuple[bool, str]:
    message_payload = {
        "subject": subject,
        "body": {
            "contentType": content_type,
            "content": content,
        },
        "toRecipients": [
            {
                "emailAddress": {
                    "address": recipient,
                }
            }
        ],
    }
    if attachments:
        message_payload["attachments"] = attachments

    status, payload, raw = request_json(
        "https://graph.microsoft.com/v1.0/me/sendMail",
        method="POST",
        payload={
            "message": message_payload,
            "saveToSentItems": True,
        },
        headers={
            "Authorization": f"Bearer {access_token}",
        },
    )
    if 200 <= status < 300:
        return True, raw or "accepted"
    return False, raw or payload.get("error_description", payload.get("error", "send failed"))


def send_microsoft_mail_multi(
    access_token: str,
    recipients: list[str],
    subject: str,
    content: str,
    *,
    content_type: str = "Text",
    attachments: list[dict] | None = None,
) -> tuple[bool, str]:
    if not recipients:
        return False, "no recipients"

    failures: list[str] = []
    sent_count = 0
    for recipient in recipients:
        ok, details = send_microsoft_mail(
            access_token,
            recipient,
            subject,
            content,
            content_type=content_type,
            attachments=attachments,
        )
        if ok:
            sent_count += 1
        else:
            failures.append(f"{recipient}: {details}")

    if failures:
        return False, "; ".join(failures)
    return True, f"sent to {sent_count} recipient(s)"


def maybe_send_alert_reminders(conn: sqlite3.Connection) -> None:
    alarm_settings = get_alarm_settings(conn)
    interval_hours = int(alarm_settings.get("alert_reminder_interval_hours") or 0)
    if interval_hours <= 0:
        return

    now_utc_dt = datetime.now(timezone.utc)
    cutoff_iso = (now_utc_dt - timedelta(hours=interval_hours)).strftime("%Y-%m-%dT%H:%M:%SZ")

    open_alerts = conn.execute(
        """
        SELECT id, hostname, mountpoint, severity, used_percent
        FROM alerts
        WHERE status = 'open'
          AND created_at_utc <= ?
          AND (last_reminder_sent_utc IS NULL OR last_reminder_sent_utc <= ?)
        ORDER BY CASE severity WHEN 'critical' THEN 0 ELSE 1 END, used_percent DESC
        """,
        (cutoff_iso, cutoff_iso),
    ).fetchall()

    if not open_alerts:
        return

    now_utc_iso = now_utc_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    host_context_cache: dict[str, dict] = {}

    try:
        user_rows = conn.execute(
            """
            SELECT u.username, COALESCE(s.alert_instant_min_severity, 'warning')
            FROM web_users u
            JOIN web_user_settings s ON s.username = u.username
            WHERE COALESCE(u.is_disabled, 0) = 0
              AND COALESCE(s.alert_instant_mail_enabled, 0) = 1
              AND COALESCE(s.email_enabled, 0) = 1
              AND COALESCE(s.email_recipient, '') != ''
            """
        ).fetchall()
    except Exception:
        return

    if not user_rows:
        return

    for alert_row in open_alerts:
        alert_id = int(alert_row[0])
        hostname = str(alert_row[1] or "")
        mountpoint = str(alert_row[2] or "")
        severity = str(alert_row[3] or "warning")
        used_percent = float(alert_row[4] or 0)

        if hostname not in host_context_cache:
            host_context_cache[hostname] = collect_host_mail_context(conn, hostname)
        host_ctx = host_context_cache[hostname]

        reported_row = conn.execute(
            "SELECT created_at_utc FROM alerts WHERE id = ?",
            (alert_id,),
        ).fetchone()
        reported_at_utc = str(reported_row[0] or "") if reported_row else now_utc_iso

        sent_to_anyone = False
        for urow in user_rows:
            username = str(urow[0] or "").strip()
            min_severity = str(urow[1] or "warning").strip().lower()
            if not username:
                continue
            if min_severity == "critical" and severity != "critical":
                continue

            sub = conn.execute(
                "SELECT notify_mail FROM web_user_alert_subscriptions WHERE username = ? AND hostname = ?",
                (username, hostname),
            ).fetchone()
            if not sub or not bool(sub[0]):
                continue

            user_settings = get_web_user_settings(conn, username)
            recipient = user_settings.get("email_recipient", "").strip()
            if not recipient:
                continue
            extra = parse_email_recipients(user_settings.get("alert_email_recipients", ""))
            all_recipients = parse_email_recipients(",".join([recipient] + extra))
            if not all_recipients:
                continue

            try:
                ok_token, access_token, _err = ensure_microsoft_access_token(conn, username)
                if not ok_token:
                    continue
                graph_cid, graph_attachment = build_alert_usage_graph_attachment(
                    conn, hostname, mountpoint, severity=severity, hours=24
                )
                graph_attachments = [graph_attachment] if graph_attachment else []
                subject = f"[Monitoring] [HEADS-UP] Offener Alert: {html.escape(str(host_ctx.get('display_name', hostname)))}"
                body = alert_instant_mail_html(
                    username,
                    "reminder",
                    hostname,
                    mountpoint,
                    severity,
                    used_percent,
                    display_name=str(host_ctx.get("display_name", "") or ""),
                    primary_ip=str(host_ctx.get("primary_ip", "") or ""),
                    country_code=str(host_ctx.get("country_code", "") or ""),
                    os_family=str(host_ctx.get("os_family", "linux") or "linux"),
                    reported_at_utc=reported_at_utc,
                    graph_cid=graph_cid or "",
                )
                send_microsoft_mail_multi(
                    access_token,
                    all_recipients,
                    subject,
                    body,
                    content_type="HTML",
                    attachments=graph_attachments,
                )
                sent_to_anyone = True
            except Exception:
                pass

        if sent_to_anyone:
            conn.execute(
                "UPDATE alerts SET last_reminder_sent_utc = ? WHERE id = ?",
                (now_utc_iso, alert_id),
            )


def maybe_send_scheduled_user_mails(conn: sqlite3.Connection) -> None:
    now_local = datetime.now(SCHEDULE_TIMEZONE)
    today_local = now_local.date().isoformat()

    rows = conn.execute(
        """
        SELECT u.username,
               COALESCE(u.is_disabled, 0),
               COALESCE(s.email_enabled, 0),
               COALESCE(s.email_recipient, ''),
               COALESCE(s.trend_email_enabled, 0),
               COALESCE(s.trend_email_time_hhmm, ''),
               COALESCE(s.trend_email_last_sent_local_date, ''),
               COALESCE(s.alert_email_enabled, 0),
               COALESCE(s.alert_email_time_hhmm, ''),
               COALESCE(s.alert_email_last_sent_local_date, '')
        FROM web_users u
        JOIN web_user_settings s ON s.username = u.username
        ORDER BY LOWER(u.username)
        """
    ).fetchall()

    for row in rows:
        username = str(row[0] or "").strip()
        if not username:
            continue
        if bool(int(row[1] or 0)):
            continue
        email_enabled = bool(int(row[2] or 0))
        recipient = str(row[3] or "").strip()
        trend_enabled = bool(int(row[4] or 0))
        trend_time = normalize_hhmm(row[5], DEFAULT_TREND_DIGEST_TIME)
        trend_last_sent = str(row[6] or "").strip()
        alert_enabled = bool(int(row[7] or 0))
        alert_time = normalize_hhmm(row[8], DEFAULT_ALERT_DIGEST_TIME)
        alert_last_sent = str(row[9] or "").strip()
        settings = get_web_user_settings(conn, username)
        extra_alert_recipients = parse_email_recipients(settings.get("alert_email_recipients", ""))
        all_alert_recipients = parse_email_recipients(",".join([recipient] + extra_alert_recipients))

        if not email_enabled:
            continue

        send_trend = trend_enabled and bool(recipient) and scheduled_digest_due(now_local, trend_time, trend_last_sent)
        send_alert = alert_enabled and bool(all_alert_recipients) and scheduled_digest_due(now_local, alert_time, alert_last_sent)
        if not send_trend and not send_alert:
            continue

        ok_token, access_token, _details = ensure_microsoft_access_token(conn, username)
        if not ok_token:
            continue

        if send_trend:
            warnings = collect_critical_trends(conn, 72)
            trend_ok, _trend_details = send_microsoft_mail(
                access_token,
                recipient,
                trend_digest_subject(warnings, today_local),
                trend_digest_html(username, warnings, 72),
                content_type="HTML",
            )
            if trend_ok:
                conn.execute(
                    """
                    UPDATE web_user_settings
                    SET trend_email_last_sent_local_date = ?, updated_at_utc = ?
                    WHERE username = ?
                    """,
                    (today_local, utc_now_iso(), username),
                )

        if send_alert:
            alerts = collect_open_alerts(conn)
            graph_cids, graph_attachments = build_alert_digest_graph_bundle(conn, alerts, hours=24)
            alert_ok, _alert_details = send_microsoft_mail_multi(
                access_token,
                all_alert_recipients,
                alert_digest_subject(alerts, today_local),
                alert_digest_html(username, alerts, graph_cids=graph_cids, graph_hours=24),
                content_type="HTML",
                attachments=graph_attachments,
            )
            if alert_ok:
                conn.execute(
                    """
                    UPDATE web_user_settings
                    SET alert_email_last_sent_local_date = ?, updated_at_utc = ?
                    WHERE username = ?
                    """,
                    (today_local, utc_now_iso(), username),
                )


def append_query_param(path: str, key: str, value: str) -> str:
    separator = "&" if "?" in path else "?"
    return f"{path}{separator}{parse.urlencode({key: value})}"


def clamp_threshold(value: float, min_value: float, max_value: float, fallback: float) -> float:
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return fallback
    return max(min_value, min(numeric, max_value))


def coerce_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    text = str(value).strip().lower()
    return text in {"1", "true", "yes", "on", "enabled"}


def get_alarm_settings(conn: sqlite3.Connection) -> dict:
    row = conn.execute(
        """
        SELECT warning_threshold_percent, critical_threshold_percent,
               warning_consecutive_hits, warning_window_minutes, critical_trigger_immediate,
               COALESCE(cpu_warning_threshold_percent, 80),
               COALESCE(cpu_critical_threshold_percent, 95),
               COALESCE(cpu_alert_window_reports, 4),
               COALESCE(ram_warning_threshold_percent, 85),
               COALESCE(ram_critical_threshold_percent, 95),
               COALESCE(ram_alert_window_reports, 4),
               telegram_enabled, telegram_bot_token, telegram_chat_id, updated_at_utc,
               COALESCE(alert_reminder_interval_hours, 0)
        FROM alarm_settings
        WHERE id = 1
        """
    ).fetchone()

    if not row:
        return {
            "warning_threshold_percent": WARNING_THRESHOLD_PERCENT,
            "critical_threshold_percent": CRITICAL_THRESHOLD_PERCENT,
            "warning_consecutive_hits": 2,
            "warning_window_minutes": 15,
            "critical_trigger_immediate": True,
            "cpu_warning_threshold_percent": CPU_WARNING_THRESHOLD_PERCENT,
            "cpu_critical_threshold_percent": CPU_CRITICAL_THRESHOLD_PERCENT,
            "cpu_alert_window_reports": CPU_ALERT_WINDOW_REPORTS,
            "ram_warning_threshold_percent": RAM_WARNING_THRESHOLD_PERCENT,
            "ram_critical_threshold_percent": RAM_CRITICAL_THRESHOLD_PERCENT,
            "ram_alert_window_reports": RAM_ALERT_WINDOW_REPORTS,
            "telegram_enabled": TELEGRAM_ENABLED_DEFAULT,
            "telegram_bot_token": TELEGRAM_BOT_TOKEN_DEFAULT,
            "telegram_chat_id": TELEGRAM_CHAT_ID_DEFAULT,
            "updated_at_utc": "",
            "alert_reminder_interval_hours": 0,
        }

    return {
        "warning_threshold_percent": clamp_threshold(row[0], 1, 99, WARNING_THRESHOLD_PERCENT),
        "critical_threshold_percent": clamp_threshold(row[1], 1, 100, CRITICAL_THRESHOLD_PERCENT),
        "warning_consecutive_hits": max(1, int(row[2] or 2)),
        "warning_window_minutes": max(1, int(row[3] or 15)),
        "critical_trigger_immediate": coerce_bool(row[4]),
        "cpu_warning_threshold_percent": clamp_threshold(row[5], 1, 99, CPU_WARNING_THRESHOLD_PERCENT),
        "cpu_critical_threshold_percent": clamp_threshold(row[6], 1, 100, CPU_CRITICAL_THRESHOLD_PERCENT),
        "cpu_alert_window_reports": max(2, min(int(row[7] or CPU_ALERT_WINDOW_REPORTS), 24)),
        "ram_warning_threshold_percent": clamp_threshold(row[8], 1, 99, RAM_WARNING_THRESHOLD_PERCENT),
        "ram_critical_threshold_percent": clamp_threshold(row[9], 1, 100, RAM_CRITICAL_THRESHOLD_PERCENT),
        "ram_alert_window_reports": max(2, min(int(row[10] or RAM_ALERT_WINDOW_REPORTS), 24)),
        "telegram_enabled": coerce_bool(row[11]),
        "telegram_bot_token": str(row[12] or ""),
        "telegram_chat_id": str(row[13] or ""),
        "updated_at_utc": str(row[14] or ""),
        "alert_reminder_interval_hours": max(0, int(row[15] or 0)) if row[15] is not None else 0,
    }


def normalize_alarm_settings_payload(payload: dict, existing: dict | None = None) -> dict:
    base = existing or {}
    warning = clamp_threshold(
        payload.get("warning_threshold_percent", base.get("warning_threshold_percent", WARNING_THRESHOLD_PERCENT)),
        1,
        99,
        WARNING_THRESHOLD_PERCENT,
    )
    critical = clamp_threshold(
        payload.get("critical_threshold_percent", base.get("critical_threshold_percent", CRITICAL_THRESHOLD_PERCENT)),
        1,
        100,
        CRITICAL_THRESHOLD_PERCENT,
    )

    if critical <= warning:
        critical = min(100.0, warning + 1.0)

    try:
        warning_hits = int(payload.get("warning_consecutive_hits", base.get("warning_consecutive_hits", 2)))
    except (TypeError, ValueError):
        warning_hits = 2
    warning_hits = max(1, min(warning_hits, 10))

    try:
        warning_window = int(payload.get("warning_window_minutes", base.get("warning_window_minutes", 15)))
    except (TypeError, ValueError):
        warning_window = 15
    warning_window = max(1, min(warning_window, 240))

    cpu_warning = clamp_threshold(
        payload.get("cpu_warning_threshold_percent", base.get("cpu_warning_threshold_percent", CPU_WARNING_THRESHOLD_PERCENT)),
        1,
        99,
        CPU_WARNING_THRESHOLD_PERCENT,
    )
    cpu_critical = clamp_threshold(
        payload.get("cpu_critical_threshold_percent", base.get("cpu_critical_threshold_percent", CPU_CRITICAL_THRESHOLD_PERCENT)),
        1,
        100,
        CPU_CRITICAL_THRESHOLD_PERCENT,
    )
    if cpu_critical <= cpu_warning:
        cpu_critical = min(100.0, cpu_warning + 1.0)

    ram_warning = clamp_threshold(
        payload.get("ram_warning_threshold_percent", base.get("ram_warning_threshold_percent", RAM_WARNING_THRESHOLD_PERCENT)),
        1,
        99,
        RAM_WARNING_THRESHOLD_PERCENT,
    )
    ram_critical = clamp_threshold(
        payload.get("ram_critical_threshold_percent", base.get("ram_critical_threshold_percent", RAM_CRITICAL_THRESHOLD_PERCENT)),
        1,
        100,
        RAM_CRITICAL_THRESHOLD_PERCENT,
    )
    if ram_critical <= ram_warning:
        ram_critical = min(100.0, ram_warning + 1.0)

    try:
        cpu_window = int(payload.get("cpu_alert_window_reports", base.get("cpu_alert_window_reports", CPU_ALERT_WINDOW_REPORTS)))
    except (TypeError, ValueError):
        cpu_window = CPU_ALERT_WINDOW_REPORTS
    cpu_window = max(2, min(cpu_window, 24))

    try:
        ram_window = int(payload.get("ram_alert_window_reports", base.get("ram_alert_window_reports", RAM_ALERT_WINDOW_REPORTS)))
    except (TypeError, ValueError):
        ram_window = RAM_ALERT_WINDOW_REPORTS
    ram_window = max(2, min(ram_window, 24))

    return {
        "warning_threshold_percent": warning,
        "critical_threshold_percent": critical,
        "warning_consecutive_hits": warning_hits,
        "warning_window_minutes": warning_window,
        "critical_trigger_immediate": coerce_bool(payload.get("critical_trigger_immediate", base.get("critical_trigger_immediate", True))),
        "cpu_warning_threshold_percent": cpu_warning,
        "cpu_critical_threshold_percent": cpu_critical,
        "cpu_alert_window_reports": cpu_window,
        "ram_warning_threshold_percent": ram_warning,
        "ram_critical_threshold_percent": ram_critical,
        "ram_alert_window_reports": ram_window,
        "telegram_enabled": coerce_bool(payload.get("telegram_enabled", base.get("telegram_enabled", False))),
        "telegram_bot_token": str(payload.get("telegram_bot_token", base.get("telegram_bot_token", "")) or "").strip(),
        "telegram_chat_id": str(payload.get("telegram_chat_id", base.get("telegram_chat_id", "")) or "").strip(),
        "alert_reminder_interval_hours": max(0, min(int(payload.get("alert_reminder_interval_hours", base.get("alert_reminder_interval_hours", 0)) or 0), 168)),
    }


def save_alarm_settings(conn: sqlite3.Connection, payload: dict) -> dict:
    current = get_alarm_settings(conn)
    normalized = normalize_alarm_settings_payload(payload, current)
    now_utc = utc_now_iso()

    conn.execute(
        """
        INSERT INTO alarm_settings (
            id,
            warning_threshold_percent,
            critical_threshold_percent,
            warning_consecutive_hits,
            warning_window_minutes,
            critical_trigger_immediate,
            cpu_warning_threshold_percent,
            cpu_critical_threshold_percent,
            cpu_alert_window_reports,
            ram_warning_threshold_percent,
            ram_critical_threshold_percent,
            ram_alert_window_reports,
            telegram_enabled,
            telegram_bot_token,
            telegram_chat_id,
            updated_at_utc,
            alert_reminder_interval_hours
        )
        VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            warning_threshold_percent = excluded.warning_threshold_percent,
            critical_threshold_percent = excluded.critical_threshold_percent,
            warning_consecutive_hits = excluded.warning_consecutive_hits,
            warning_window_minutes = excluded.warning_window_minutes,
            critical_trigger_immediate = excluded.critical_trigger_immediate,
            cpu_warning_threshold_percent = excluded.cpu_warning_threshold_percent,
            cpu_critical_threshold_percent = excluded.cpu_critical_threshold_percent,
            cpu_alert_window_reports = excluded.cpu_alert_window_reports,
            ram_warning_threshold_percent = excluded.ram_warning_threshold_percent,
            ram_critical_threshold_percent = excluded.ram_critical_threshold_percent,
            ram_alert_window_reports = excluded.ram_alert_window_reports,
            telegram_enabled = excluded.telegram_enabled,
            telegram_bot_token = excluded.telegram_bot_token,
            telegram_chat_id = excluded.telegram_chat_id,
            updated_at_utc = excluded.updated_at_utc,
            alert_reminder_interval_hours = excluded.alert_reminder_interval_hours
        """,
        (
            normalized["warning_threshold_percent"],
            normalized["critical_threshold_percent"],
            normalized["warning_consecutive_hits"],
            normalized["warning_window_minutes"],
            1 if normalized["critical_trigger_immediate"] else 0,
            normalized["cpu_warning_threshold_percent"],
            normalized["cpu_critical_threshold_percent"],
            normalized["cpu_alert_window_reports"],
            normalized["ram_warning_threshold_percent"],
            normalized["ram_critical_threshold_percent"],
            normalized["ram_alert_window_reports"],
            1 if normalized["telegram_enabled"] else 0,
            normalized["telegram_bot_token"],
            normalized["telegram_chat_id"],
            now_utc,
            normalized["alert_reminder_interval_hours"],
        ),
    )

    normalized["updated_at_utc"] = now_utc
    return normalized


def evaluate_severity_for_thresholds(used_percent: float, warning_threshold: float, critical_threshold: float) -> str:
    if used_percent >= critical_threshold:
        return "critical"
    if used_percent >= warning_threshold:
        return "warning"
    return "ok"


_LOGO_PATH = STATIC_DIR / "icons" / "logo.png"

_ALERT_ICON_PATHS: dict[str, Path] = {
    "opened": STATIC_DIR / "icons" / "alertopen.png",
    "escalated": STATIC_DIR / "icons" / "alertescalated.png",
    "resolved": STATIC_DIR / "icons" / "alertresolved.png",
    "reminder": STATIC_DIR / "icons" / "alertreminder.png",
}


def is_resource_alert_mountpoint(mountpoint: str) -> bool:
    return mountpoint in {CPU_ALERT_MOUNTPOINT, RAM_ALERT_MOUNTPOINT}

# Characters that must be escaped in Telegram MarkdownV2
_MDV2_RE = re.compile(r'([_*\[\]()~`>#+=|{}.!\\-])')


def _mdv2(text: object) -> str:
    return _MDV2_RE.sub(r'\\\1', str(text))


def _build_multipart(fields: dict, files: dict) -> tuple[bytes, str]:
    boundary = secrets.token_hex(16).encode()
    body = b""
    for name, value in fields.items():
        body += b"--" + boundary + b"\r\n"
        body += f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode()
        body += str(value).encode("utf-8") + b"\r\n"
    for name, (filename, data, content_type) in files.items():
        body += b"--" + boundary + b"\r\n"
        body += f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'.encode()
        body += f"Content-Type: {content_type}\r\n\r\n".encode()
        body += data + b"\r\n"
    body += b"--" + boundary + b"--\r\n"
    return body, f"multipart/form-data; boundary={boundary.decode()}"


def telegram_send_to_chat(bot_token: str, chat_id: str, text: str, image_path: Path | None = None) -> tuple[bool, str]:
    # Try sendPhoto with status icon; fall back to sendMessage on any error
    photo_path = (image_path if image_path and image_path.is_file() else (_LOGO_PATH if _LOGO_PATH.is_file() else None))
    if photo_path:
        try:
            photo_data = photo_path.read_bytes()
            fields = {"chat_id": chat_id, "caption": text[:1024], "parse_mode": "MarkdownV2"}
            files = {"photo": (photo_path.name, photo_data, "image/png")}
            body, content_type = _build_multipart(fields, files)
            endpoint = f"https://api.telegram.org/bot{bot_token}/sendPhoto"
            req = request.Request(endpoint, data=body, method="POST")
            req.add_header("Content-Type", content_type)
            with request.urlopen(req, timeout=10) as resp:
                resp_body = resp.read().decode("utf-8", errors="replace")
                if 200 <= resp.status < 300:
                    return True, resp_body
        except Exception:
            pass  # fall through to plain text

    endpoint = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = parse.urlencode(
        {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "MarkdownV2",
            "disable_web_page_preview": "true",
        }
    ).encode("utf-8")

    req = request.Request(endpoint, data=payload, method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")

    try:
        with request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            if 200 <= resp.status < 300:
                return True, body
            return False, f"http {resp.status}: {body}"
    except error.URLError as exc:
        return False, str(exc)


def telegram_send(settings: dict, text: str, image_path: Path | None = None) -> tuple[bool, str]:
    if not settings.get("telegram_enabled"):
        return False, "telegram disabled"

    bot_token = str(settings.get("telegram_bot_token", "")).strip()
    chat_id = str(settings.get("telegram_chat_id", "")).strip()
    if not bot_token or not chat_id:
        return False, "telegram bot token/chat id missing"

    return telegram_send_to_chat(bot_token, chat_id, text, image_path=image_path)


def build_telegram_alert_text(
    event_type: str,
    hostname: str,
    mountpoint: str,
    severity: str,
    used_percent: float,
    display_name: str = "",
) -> str:
    icon = {
        "opened": "🚨 ALERT OPEN",
        "escalated": "⬆️ ALERT ESCALATED",
        "resolved": "✅ ALERT RESOLVED",
    }.get(event_type, "⚠️ ALERT")
    sev_icon = {"critical": "🔴", "warning": "🟠", "ok": "🟢"}.get(severity, "⚪")
    title = display_name.strip() if display_name.strip() else hostname
    now_local = datetime.now().astimezone().strftime("%d.%m.%Y %H:%M")
    try:
        used_text = f"{float(used_percent):.1f}%"
    except (TypeError, ValueError):
        used_text = "-"

    # MarkdownV2: bold hostname/title, monospace usage
    hostname_part = f"🖥️ *{_mdv2(title)}*" if title == hostname else f"🖥️ *{_mdv2(title)}* \\({_mdv2(hostname)}\\)"
    if mountpoint == CPU_ALERT_MOUNTPOINT:
        resource_line = "🖥️ CPU\\-Auslastung"
    elif mountpoint == RAM_ALERT_MOUNTPOINT:
        resource_line = "🧠 RAM\\-Auslastung"
    else:
        resource_line = f"📂 {_mdv2(mountpoint)}"
    return (
        f"{hostname_part}\n"
        f"{resource_line}\n"
        f"{sev_icon} *{_mdv2(severity)}*\n"
        f"📊 `{_mdv2(used_text)}`\n"
        f"🕐 {_mdv2(now_local)}"
    )


def maybe_send_alert_message(
    settings: dict,
    event_type: str,
    hostname: str,
    mountpoint: str,
    severity: str,
    used_percent: float,
    conn: sqlite3.Connection | None = None,
    display_name: str = "",
) -> None:
    if settings.get("telegram_enabled"):
        text = build_telegram_alert_text(
            event_type,
            hostname,
            mountpoint,
            severity,
            used_percent,
            display_name=display_name,
        )
        telegram_send(settings, text, image_path=_ALERT_ICON_PATHS.get(event_type))
    if conn is not None:
        send_instant_alert_telegram_to_users(
            conn,
            event_type,
            hostname,
            mountpoint,
            severity,
            used_percent,
            display_name=display_name,
        )
        send_instant_alert_mails_to_users(conn, event_type, hostname, mountpoint, severity, used_percent)


def get_nested_number(payload: dict, section: str, key: str) -> float | None:
    value = payload.get(section, {})
    if not isinstance(value, dict):
        return None
    raw = value.get(key)
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def payload_int(payload: dict, key: str, default: int = 0) -> int:
    try:
        return int(payload.get(key, default))
    except (TypeError, ValueError):
        return default


def summarize_numeric_series(values: list[float]) -> dict | None:
    if not values:
        return None

    first_value = values[0]
    last_value = values[-1]
    return {
        "current": last_value,
        "min": min(values),
        "max": max(values),
        "avg": sum(values) / len(values),
        "delta": last_value - first_value,
        "sample_count": len(values),
    }


def get_display_name_override(conn: sqlite3.Connection, hostname: str) -> str:
    row = conn.execute(
        "SELECT display_name_override FROM host_settings WHERE hostname = ?",
        (hostname,),
    ).fetchone()
    if not row or not row[0]:
        return ""
    return str(row[0]).strip()


def parse_bool(value: object, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off"}:
            return False
    return default


def normalize_country_code(value: object) -> str:
    raw = str(value or "").strip().upper()
    if not raw:
        return ""
    if len(raw) != 2 or not raw.isalpha():
        return ""
    return raw


def normalize_os_family(value: object) -> str:
    os_text = str(value or "").strip().lower()
    if not os_text:
        return "linux"
    if "win" in os_text:
        return "windows"
    return "linux"


def os_family_label(os_family: str) -> str:
    return "Windows" if os_family == "windows" else "Linux"


def os_logo_data_uri(os_family: str) -> str:
    icon_path = WINDOWS_LOGO_PATH if os_family == "windows" else LINUX_LOGO_PATH
    try:
        encoded = base64.b64encode(icon_path.read_bytes()).decode("ascii")
        return f"data:image/png;base64,{encoded}"
    except OSError:
        return ""


def country_flag_data_uri(country_code: str) -> str:
    normalized_country_code = normalize_country_code(country_code)
    if not normalized_country_code:
        return ""
    icon_path = STATIC_DIR / "icons" / f"{normalized_country_code}.png"
    try:
        encoded = base64.b64encode(icon_path.read_bytes()).decode("ascii")
        return f"data:image/png;base64,{encoded}"
    except OSError:
        return ""


def app_logo_data_uri() -> str:
    try:
        encoded = base64.b64encode(APP_LOGO_PATH.read_bytes()).decode("ascii")
        return f"data:image/png;base64,{encoded}"
    except OSError:
        svg = (
            "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 28 28'>"
            "<rect x='1' y='1' width='26' height='26' rx='8' fill='#2f68d8'/>"
            "<path d='M7 15h5l2-5 3 9 2-4h4' fill='none' stroke='#ffffff' stroke-width='2.6' stroke-linecap='round' stroke-linejoin='round'/>"
            "</svg>"
        )
        return "data:image/svg+xml;utf8," + parse.quote(svg)


def ang_logo_data_uri() -> str:
    try:
        encoded = base64.b64encode(ANG_LOGO_PATH.read_bytes()).decode("ascii")
        return f"data:image/png;base64,{encoded}"
    except OSError:
        return ""


def alert_event_icon_data_uri(event_type: str) -> str:
    icon_path = _ALERT_ICON_PATHS.get(event_type)
    if not icon_path:
        return ""
    try:
        encoded = base64.b64encode(icon_path.read_bytes()).decode("ascii")
        return f"data:image/png;base64,{encoded}"
    except OSError:
        return ""


def collect_host_mail_context(conn: sqlite3.Connection, hostname: str) -> dict:
    settings_row = conn.execute(
        "SELECT COALESCE(display_name_override, ''), COALESCE(country_code_override, '') FROM host_settings WHERE hostname = ?",
        (hostname,),
    ).fetchone()
    display_name_override = str(settings_row[0] or "").strip() if settings_row else ""
    country_code_override = normalize_country_code(settings_row[1] if settings_row else "")

    latest_payload_row = conn.execute(
        "SELECT payload_json FROM reports WHERE hostname = ? ORDER BY id DESC LIMIT 1",
        (hostname,),
    ).fetchone()
    latest_payload = parse_payload_json(str(latest_payload_row[0] or "{}")) if latest_payload_row else {}

    display_name = effective_display_name(latest_payload, display_name_override, hostname)
    country_code = country_code_override or extract_country_code_from_payload(latest_payload)
    os_name = str(latest_payload.get("os", "") or "")
    os_family = normalize_os_family(os_name)
    primary_ip = str(latest_payload.get("primary_ip", "") or "").strip()
    return {
        "display_name": display_name,
        "country_code": country_code,
        "os_name": os_name,
        "os_family": os_family,
        "primary_ip": primary_ip,
    }


def extract_country_code_from_payload(payload: dict) -> str:
    direct = normalize_country_code(payload.get("country_code", ""))
    if direct:
        return direct

    agent_config = payload.get("agent_config", {})
    if not isinstance(agent_config, dict):
        return ""

    entries = agent_config.get("entries", [])
    if not isinstance(entries, list):
        return ""

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        key = str(entry.get("key", "")).strip().upper()
        if key in {"COUNTRY_CODE", "COUNTRY", "COUNTRY_ISO", "COUNTRY_ISO2", "LAND", "LAND_CODE", "LAND_ISO2"}:
            return normalize_country_code(entry.get("value", ""))
    return ""


def payload_has_agent_api_key(payload: dict) -> bool:
    agent_config = payload.get("agent_config", {})
    if not isinstance(agent_config, dict):
        return False

    entries = agent_config.get("entries", [])
    if not isinstance(entries, list):
        return False

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        key = str(entry.get("key", "")).strip().upper()
        if key != "API_KEY":
            continue
        value = str(entry.get("value", "") or "").strip()
        if value:
            return True
    return False


def build_agent_api_key_status(payload: dict, request_key: str, hostname: str) -> dict:
    configured = payload_has_agent_api_key(payload)
    server_requires_api_key = bool(API_KEY)
    request_authenticated = bool(API_KEY and request_key == API_KEY)
    grace_allowed = False

    if server_requires_api_key and not request_authenticated and not request_key and hostname and API_KEY_GRACE_ALLOW_KNOWN_HOSTS:
        with sqlite3.connect(DB_PATH) as conn:
            grace_allowed = is_known_hostname(conn, hostname)

    status = "off"
    if server_requires_api_key:
        if request_authenticated:
            status = "key-auth"
        elif grace_allowed:
            status = "grace"
        elif configured:
            status = "configured"
        else:
            status = "missing"

    return {
        "configured": configured,
        "request_authenticated": request_authenticated,
        "grace_allowed": grace_allowed,
        "server_requires_api_key": server_requires_api_key,
        "status": status,
    }


def normalize_command_type(value: object) -> str:
    command_type = str(value or "").strip().lower()
    if command_type in {"update-now", "set-api-key"}:
        return command_type
    return ""


def expire_old_agent_commands(conn: sqlite3.Connection) -> None:
    now_utc = utc_now_iso()
    conn.execute(
        """
        UPDATE agent_commands
        SET status = 'expired'
        WHERE status = 'pending' AND expires_at_utc <= ?
        """,
        (now_utc,),
    )


def queue_agent_command(
    conn: sqlite3.Connection,
    created_by: str,
    hostname: str,
    command_type: str,
    command_payload: dict,
    ttl_minutes: int,
) -> int:
    now_utc = datetime.now(timezone.utc)
    expires_at_utc = now_utc + timedelta(minutes=max(1, min(ttl_minutes, 24 * 60)))
    payload_json = json.dumps(command_payload or {}, separators=(",", ":"))
    cursor = conn.execute(
        """
        INSERT INTO agent_commands (
            created_at_utc,
            created_by,
            hostname,
            agent_id,
            command_type,
            command_payload_json,
            status,
            expires_at_utc
        )
        VALUES (?, ?, ?, '', ?, ?, 'pending', ?)
        """,
        (
            now_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
            created_by,
            hostname,
            command_type,
            payload_json,
            expires_at_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        ),
    )
    return int(cursor.lastrowid)


def find_pending_agent_command(conn: sqlite3.Connection, hostname: str, command_type: str, command_payload: dict) -> int:
    payload_json = json.dumps(command_payload or {}, separators=(",", ":"))
    row = conn.execute(
        """
        SELECT id
        FROM agent_commands
        WHERE hostname = ? AND command_type = ? AND command_payload_json = ? AND status = 'pending' AND expires_at_utc > ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (hostname, command_type, payload_json, utc_now_iso()),
    ).fetchone()
    if not row:
        return 0
    return int(row[0] or 0)


def queue_agent_command_once(
    conn: sqlite3.Connection,
    created_by: str,
    hostname: str,
    command_type: str,
    command_payload: dict,
    ttl_minutes: int,
) -> tuple[int, bool]:
    existing_command_id = find_pending_agent_command(conn, hostname, command_type, command_payload)
    if existing_command_id > 0:
        return existing_command_id, False

    return (
        queue_agent_command(
            conn,
            created_by=created_by,
            hostname=hostname,
            command_type=command_type,
            command_payload=command_payload,
            ttl_minutes=ttl_minutes,
        ),
        True,
    )


def get_known_hostnames(conn: sqlite3.Connection) -> list[str]:
    rows = conn.execute(
        """
        SELECT hostname, MAX(received_at_utc) AS last_seen_utc
        FROM reports
        GROUP BY hostname
        ORDER BY last_seen_utc DESC
        """
    ).fetchall()
    return [str(row[0] or "").strip() for row in rows if str(row[0] or "").strip()]


def is_known_hostname(conn: sqlite3.Connection, hostname: str) -> bool:
    normalized = str(hostname or "").strip()
    if not normalized:
        return False

    row = conn.execute("SELECT 1 FROM reports WHERE hostname = ? LIMIT 1", (normalized,)).fetchone()
    return bool(row)


def get_latest_update_command_rows(conn: sqlite3.Connection) -> dict[str, dict]:
    rows = conn.execute(
        """
        SELECT hostname, status, created_at_utc, executed_at_utc, expires_at_utc, result_json
        FROM agent_commands
        WHERE command_type = 'update-now'
          AND id IN (
              SELECT MAX(id)
              FROM agent_commands
              WHERE command_type = 'update-now'
              GROUP BY hostname
          )
        """
    ).fetchall()

    result: dict[str, dict] = {}
    for row in rows:
        hostname = str(row[0] or "").strip()
        if not hostname:
            continue
        result[hostname] = {
            "status": str(row[1] or ""),
            "created_at_utc": str(row[2] or ""),
            "executed_at_utc": str(row[3] or ""),
            "expires_at_utc": str(row[4] or ""),
            "result": parse_payload_json(str(row[5] or "{}")),
        }
    return result


def get_latest_report_rows_by_hostname(conn: sqlite3.Connection) -> dict[str, dict]:
    rows = conn.execute(
        """
        SELECT r.hostname, r.received_at_utc, r.payload_json
        FROM reports r
        WHERE r.id IN (
            SELECT MAX(id)
            FROM reports
            GROUP BY hostname
        )
        """
    ).fetchall()

    result: dict[str, dict] = {}
    for row in rows:
        hostname = str(row[0] or "").strip()
        if not hostname:
            continue
        result[hostname] = {
            "received_at_utc": str(row[1] or ""),
            "payload": parse_payload_json(str(row[2] or "{}")),
        }
    return result


def get_host_settings(conn: sqlite3.Connection, hostname: str) -> dict:
    row = conn.execute(
        """
        SELECT display_name_override, COALESCE(country_code_override, ''), COALESCE(is_favorite, 0), COALESCE(is_hidden, 0)
        FROM host_settings
        WHERE hostname = ?
        """,
        (hostname,),
    ).fetchone()
    if not row:
        return {
            "display_name_override": "",
            "country_code_override": "",
            "is_favorite": False,
            "is_hidden": False,
        }
    return {
        "display_name_override": str(row[0] or "").strip(),
        "country_code_override": normalize_country_code(row[1]),
        "is_favorite": bool(int(row[2] or 0)),
        "is_hidden": bool(int(row[3] or 0)),
    }


def is_alert_muted(conn: sqlite3.Connection, hostname: str, mountpoint: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM muted_alert_rules WHERE hostname = ? AND mountpoint = ?",
        (hostname, mountpoint),
    ).fetchone()
    return row is not None


def resolve_open_alerts_for_host(conn: sqlite3.Connection, hostname: str, report_id: int | None) -> None:
    now_utc = utc_now_iso()
    conn.execute(
        """
        UPDATE alerts
        SET status = 'resolved', resolved_at_utc = ?, last_seen_at_utc = ?, report_id = ?
        WHERE hostname = ? AND status = 'open'
        """,
        (now_utc, now_utc, report_id, hostname),
    )
    conn.execute("DELETE FROM alert_debounce WHERE hostname = ?", (hostname,))


def prune_reports_for_host(conn: sqlite3.Connection, hostname: str, keep_count: int) -> None:
    keep_count = max(1, int(keep_count))
    conn.execute(
        """
        UPDATE alerts
        SET report_id = NULL
        WHERE report_id IN (
            SELECT id
            FROM reports
            WHERE hostname = ?
            ORDER BY id DESC
            LIMIT -1 OFFSET ?
        )
        """,
        (hostname, keep_count),
    )
    conn.execute(
        """
        DELETE FROM reports
        WHERE id IN (
            SELECT id
            FROM reports
            WHERE hostname = ?
            ORDER BY id DESC
            LIMIT -1 OFFSET ?
        )
        """,
        (hostname, keep_count),
    )


def delete_host_card_data(conn: sqlite3.Connection, hostname: str) -> dict[str, int]:
    deleted: dict[str, int] = {}
    cleanup_plan = [
        ("muted_alert_rules", "hostname = ?"),
        ("alert_debounce", "hostname = ?"),
        ("alerts", "hostname = ?"),
        ("agent_commands", "hostname = ?"),
        ("host_settings", "hostname = ?"),
        ("reports", "hostname = ?"),
    ]

    for table_name, where_clause in cleanup_plan:
        row = conn.execute(
            f"SELECT COUNT(*) FROM {table_name} WHERE {where_clause}",
            (hostname,),
        ).fetchone()
        count = int(row[0] or 0) if row else 0
        conn.execute(
            f"DELETE FROM {table_name} WHERE {where_clause}",
            (hostname,),
        )
        deleted[table_name] = count

    return deleted


def effective_display_name(payload: dict, override_value: str, hostname: str) -> str:
    if override_value:
        return override_value

    payload_value = str(payload.get("display_name", "")).strip()
    if payload_value:
        return payload_value
    return hostname


def evaluate_severity(used_percent: float) -> str:
    if used_percent >= CRITICAL_THRESHOLD_PERCENT:
        return "critical"
    if used_percent >= WARNING_THRESHOLD_PERCENT:
        return "warning"
    return "ok"


def update_alerts_for_report(conn: sqlite3.Connection, hostname: str, report_id: int, filesystems: list, alarm_settings: dict) -> None:
    now_utc = utc_now_iso()
    mountpoints_seen = set()
    warning_hits_required = max(1, int(alarm_settings.get("warning_consecutive_hits", 2)))
    warning_window_minutes = max(1, int(alarm_settings.get("warning_window_minutes", 15)))
    critical_trigger_immediate = bool(alarm_settings.get("critical_trigger_immediate", True))
    display_name = get_display_name_override(conn, hostname) or hostname

    for fs in filesystems:
        if not isinstance(fs, dict):
            continue

        mountpoint = str(fs.get("mountpoint", "")).strip()
        if not mountpoint:
            continue

        mountpoints_seen.add(mountpoint)
        if is_alert_muted(conn, hostname, mountpoint):
            muted_open = conn.execute(
                "SELECT id FROM alerts WHERE hostname = ? AND mountpoint = ? AND status = 'open'",
                (hostname, mountpoint),
            ).fetchone()
            if muted_open:
                conn.execute(
                    "UPDATE alerts SET status = 'resolved', resolved_at_utc = ?, last_seen_at_utc = ? WHERE id = ?",
                    (now_utc, now_utc, muted_open[0]),
                )
            conn.execute("DELETE FROM alert_debounce WHERE hostname = ? AND mountpoint = ?", (hostname, mountpoint))
            continue
        try:
            used_percent = float(fs.get("used_percent"))
        except (TypeError, ValueError):
            continue

        warning_threshold = float(alarm_settings.get("warning_threshold_percent", WARNING_THRESHOLD_PERCENT))
        critical_threshold = float(alarm_settings.get("critical_threshold_percent", CRITICAL_THRESHOLD_PERCENT))
        severity = evaluate_severity_for_thresholds(used_percent, warning_threshold, critical_threshold)
        alert_started = False

        if severity == "critical" and critical_trigger_immediate:
            alert_started = True
        elif severity in {"warning", "critical"}:
            debounce_row = conn.execute(
                """
                SELECT first_seen_at_utc, last_seen_at_utc, hit_count
                FROM alert_debounce
                WHERE hostname = ? AND mountpoint = ?
                """,
                (hostname, mountpoint),
            ).fetchone()

            if debounce_row:
                try:
                    last_seen_dt = datetime.strptime(str(debounce_row[1]), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                    now_dt = datetime.strptime(now_utc, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
                    within_window = (now_dt - last_seen_dt) <= timedelta(minutes=warning_window_minutes)
                except ValueError:
                    within_window = False

                next_hit_count = int(debounce_row[2] or 0) + 1 if within_window else 1
                first_seen = str(debounce_row[0]) if within_window else now_utc
            else:
                next_hit_count = 1
                first_seen = now_utc

            conn.execute(
                """
                INSERT INTO alert_debounce (
                    hostname, mountpoint, first_seen_at_utc, last_seen_at_utc,
                    hit_count, last_used_percent, last_severity
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(hostname, mountpoint) DO UPDATE SET
                    first_seen_at_utc = excluded.first_seen_at_utc,
                    last_seen_at_utc = excluded.last_seen_at_utc,
                    hit_count = excluded.hit_count,
                    last_used_percent = excluded.last_used_percent,
                    last_severity = excluded.last_severity
                """,
                (hostname, mountpoint, first_seen, now_utc, next_hit_count, used_percent, severity),
            )

            alert_started = next_hit_count >= warning_hits_required

        open_alert = conn.execute(
            """
            SELECT id, severity
            FROM alerts
            WHERE hostname = ? AND mountpoint = ? AND status = 'open'
            ORDER BY id DESC
            LIMIT 1
            """,
            (hostname, mountpoint),
        ).fetchone()

        if severity == "ok":
            conn.execute(
                "DELETE FROM alert_debounce WHERE hostname = ? AND mountpoint = ?",
                (hostname, mountpoint),
            )
            if open_alert:
                conn.execute(
                    """
                    UPDATE alerts
                    SET status = 'resolved', resolved_at_utc = ?, last_seen_at_utc = ?, report_id = ?
                    WHERE id = ?
                    """,
                    (now_utc, now_utc, report_id, open_alert[0]),
                )
                maybe_send_alert_message(alarm_settings, "resolved", hostname, mountpoint, "ok", used_percent, conn=conn, display_name=display_name)
            continue

        if not open_alert and not alert_started:
            continue

        conn.execute(
            "DELETE FROM alert_debounce WHERE hostname = ? AND mountpoint = ?",
            (hostname, mountpoint),
        )

        if not open_alert:
            conn.execute(
                """
                INSERT INTO alerts (
                    hostname, mountpoint, severity, used_percent, status,
                    created_at_utc, last_seen_at_utc, resolved_at_utc, report_id
                )
                VALUES (?, ?, ?, ?, 'open', ?, ?, NULL, ?)
                """,
                (hostname, mountpoint, severity, used_percent, now_utc, now_utc, report_id),
            )
            maybe_send_alert_message(alarm_settings, "opened", hostname, mountpoint, severity, used_percent, conn=conn, display_name=display_name)
            continue

        previous_severity = str(open_alert[1] or "warning")

        conn.execute(
            """
            UPDATE alerts
            SET severity = ?, used_percent = ?, last_seen_at_utc = ?, report_id = ?
            WHERE id = ?
            """,
            (severity, used_percent, now_utc, report_id, open_alert[0]),
        )

        if previous_severity != "critical" and severity == "critical":
            maybe_send_alert_message(alarm_settings, "escalated", hostname, mountpoint, severity, used_percent, conn=conn, display_name=display_name)

    if mountpoints_seen:
        placeholders = ",".join("?" for _ in mountpoints_seen)
        conn.execute(
            f"DELETE FROM alert_debounce WHERE hostname = ? AND mountpoint NOT IN ({placeholders})",
            (hostname, *sorted(mountpoints_seen)),
        )
        conn.execute(
            f"""
            UPDATE alerts
            SET status = 'resolved', resolved_at_utc = ?, last_seen_at_utc = ?, report_id = ?
            WHERE hostname = ?
              AND status = 'open'
              AND mountpoint NOT IN ({placeholders})
            """,
            (now_utc, now_utc, report_id, hostname, *sorted(mountpoints_seen)),
        )
    else:
        conn.execute("DELETE FROM alert_debounce WHERE hostname = ?", (hostname,))


def update_cpu_alerts_for_report(
    conn: sqlite3.Connection, hostname: str, report_id: int, payload: dict, alarm_settings: dict
) -> None:
    cpu_warning_threshold = clamp_threshold(
        alarm_settings.get("cpu_warning_threshold_percent", CPU_WARNING_THRESHOLD_PERCENT),
        1,
        99,
        CPU_WARNING_THRESHOLD_PERCENT,
    )
    cpu_critical_threshold = clamp_threshold(
        alarm_settings.get("cpu_critical_threshold_percent", CPU_CRITICAL_THRESHOLD_PERCENT),
        1,
        100,
        CPU_CRITICAL_THRESHOLD_PERCENT,
    )
    if cpu_critical_threshold <= cpu_warning_threshold:
        cpu_critical_threshold = min(100.0, cpu_warning_threshold + 1.0)
    cpu_window_reports = max(
        2,
        min(
            int(alarm_settings.get("cpu_alert_window_reports", CPU_ALERT_WINDOW_REPORTS) or CPU_ALERT_WINDOW_REPORTS),
            24,
        ),
    )

    rows = conn.execute(
        """
        SELECT payload_json FROM reports
        WHERE hostname = ?
        ORDER BY id DESC
        LIMIT ?
        """,
        (hostname, cpu_window_reports),
    ).fetchall()

    if len(rows) < cpu_window_reports:
        return

    cpu_values: list[float] = []
    for row in rows:
        try:
            p = parse_payload_json(str(row[0] or "{}"))
            v = get_nested_number(p, "cpu", "usage_percent")
            if v is not None:
                cpu_values.append(float(v))
        except Exception:
            pass

    if len(cpu_values) < cpu_window_reports:
        return

    avg_cpu = sum(cpu_values) / len(cpu_values)
    severity = evaluate_severity_for_thresholds(
        avg_cpu, cpu_warning_threshold, cpu_critical_threshold
    )

    now_utc = utc_now_iso()
    display_name = get_display_name_override(conn, hostname) or hostname

    open_alert = conn.execute(
        """
        SELECT id, severity
        FROM alerts
        WHERE hostname = ? AND mountpoint = ? AND status = 'open'
        ORDER BY id DESC
        LIMIT 1
        """,
        (hostname, CPU_ALERT_MOUNTPOINT),
    ).fetchone()

    if severity == "ok":
        if open_alert:
            conn.execute(
                """
                UPDATE alerts
                SET status = 'resolved', resolved_at_utc = ?, last_seen_at_utc = ?, report_id = ?
                WHERE id = ?
                """,
                (now_utc, now_utc, report_id, open_alert[0]),
            )
            maybe_send_alert_message(
                alarm_settings, "resolved", hostname, CPU_ALERT_MOUNTPOINT, "ok", avg_cpu,
                conn=conn, display_name=display_name,
            )
        return

    if not open_alert:
        conn.execute(
            """
            INSERT INTO alerts (
                hostname, mountpoint, severity, used_percent, status,
                created_at_utc, last_seen_at_utc, resolved_at_utc, report_id
            )
            VALUES (?, ?, ?, ?, 'open', ?, ?, NULL, ?)
            """,
            (hostname, CPU_ALERT_MOUNTPOINT, severity, avg_cpu, now_utc, now_utc, report_id),
        )
        maybe_send_alert_message(
            alarm_settings, "opened", hostname, CPU_ALERT_MOUNTPOINT, severity, avg_cpu,
            conn=conn, display_name=display_name,
        )
        return

    previous_severity = str(open_alert[1] or "warning")
    conn.execute(
        """
        UPDATE alerts
        SET severity = ?, used_percent = ?, last_seen_at_utc = ?, report_id = ?
        WHERE id = ?
        """,
        (severity, avg_cpu, now_utc, report_id, open_alert[0]),
    )
    if previous_severity != "critical" and severity == "critical":
        maybe_send_alert_message(
            alarm_settings, "escalated", hostname, CPU_ALERT_MOUNTPOINT, severity, avg_cpu,
            conn=conn, display_name=display_name,
        )


def update_ram_alerts_for_report(
    conn: sqlite3.Connection, hostname: str, report_id: int, payload: dict, alarm_settings: dict
) -> None:
    ram_warning_threshold = clamp_threshold(
        alarm_settings.get("ram_warning_threshold_percent", RAM_WARNING_THRESHOLD_PERCENT),
        1,
        99,
        RAM_WARNING_THRESHOLD_PERCENT,
    )
    ram_critical_threshold = clamp_threshold(
        alarm_settings.get("ram_critical_threshold_percent", RAM_CRITICAL_THRESHOLD_PERCENT),
        1,
        100,
        RAM_CRITICAL_THRESHOLD_PERCENT,
    )
    if ram_critical_threshold <= ram_warning_threshold:
        ram_critical_threshold = min(100.0, ram_warning_threshold + 1.0)
    ram_window_reports = max(
        2,
        min(
            int(alarm_settings.get("ram_alert_window_reports", RAM_ALERT_WINDOW_REPORTS) or RAM_ALERT_WINDOW_REPORTS),
            24,
        ),
    )

    rows = conn.execute(
        """
        SELECT payload_json FROM reports
        WHERE hostname = ?
        ORDER BY id DESC
        LIMIT ?
        """,
        (hostname, ram_window_reports),
    ).fetchall()

    if len(rows) < ram_window_reports:
        return

    ram_values: list[float] = []
    for row in rows:
        try:
            p = parse_payload_json(str(row[0] or "{}"))
            v = get_nested_number(p, "memory", "used_percent")
            if v is not None:
                ram_values.append(float(v))
        except Exception:
            pass

    if len(ram_values) < ram_window_reports:
        return

    avg_ram = sum(ram_values) / len(ram_values)
    severity = evaluate_severity_for_thresholds(
        avg_ram, ram_warning_threshold, ram_critical_threshold
    )

    now_utc = utc_now_iso()
    display_name = get_display_name_override(conn, hostname) or hostname

    open_alert = conn.execute(
        """
        SELECT id, severity
        FROM alerts
        WHERE hostname = ? AND mountpoint = ? AND status = 'open'
        ORDER BY id DESC
        LIMIT 1
        """,
        (hostname, RAM_ALERT_MOUNTPOINT),
    ).fetchone()

    if severity == "ok":
        if open_alert:
            conn.execute(
                """
                UPDATE alerts
                SET status = 'resolved', resolved_at_utc = ?, last_seen_at_utc = ?, report_id = ?
                WHERE id = ?
                """,
                (now_utc, now_utc, report_id, open_alert[0]),
            )
            maybe_send_alert_message(
                alarm_settings, "resolved", hostname, RAM_ALERT_MOUNTPOINT, "ok", avg_ram,
                conn=conn, display_name=display_name,
            )
        return

    if not open_alert:
        conn.execute(
            """
            INSERT INTO alerts (
                hostname, mountpoint, severity, used_percent, status,
                created_at_utc, last_seen_at_utc, resolved_at_utc, report_id
            )
            VALUES (?, ?, ?, ?, 'open', ?, ?, NULL, ?)
            """,
            (hostname, RAM_ALERT_MOUNTPOINT, severity, avg_ram, now_utc, now_utc, report_id),
        )
        maybe_send_alert_message(
            alarm_settings, "opened", hostname, RAM_ALERT_MOUNTPOINT, severity, avg_ram,
            conn=conn, display_name=display_name,
        )
        return

    previous_severity = str(open_alert[1] or "warning")
    conn.execute(
        """
        UPDATE alerts
        SET severity = ?, used_percent = ?, last_seen_at_utc = ?, report_id = ?
        WHERE id = ?
        """,
        (severity, avg_ram, now_utc, report_id, open_alert[0]),
    )
    if previous_severity != "critical" and severity == "critical":
        maybe_send_alert_message(
            alarm_settings, "escalated", hostname, RAM_ALERT_MOUNTPOINT, severity, avg_ram,
            conn=conn, display_name=display_name,
        )


class MonitoringHandler(BaseHTTPRequestHandler):
    server_version = "MonitoringReceiver/0.1"

    def _swagger_ui_html(self) -> str:
        return """<!doctype html>
<html lang=\"en\">
    <head>
        <meta charset=\"utf-8\">
        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">
        <title>Monitoring API Docs</title>
        <link rel=\"stylesheet\" href=\"https://unpkg.com/swagger-ui-dist@5/swagger-ui.css\">
        <style>
            html, body {
                margin: 0;
                padding: 0;
                background: #f8fafc;
            }
            #swagger-ui {
                max-width: 1200px;
                margin: 0 auto;
            }
        </style>
    </head>
    <body>
        <div id=\"swagger-ui\"></div>
        <script src=\"https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js\"></script>
        <script>
            window.ui = SwaggerUIBundle({
                url: '/openapi.yaml',
                dom_id: '#swagger-ui',
                deepLinking: true,
                presets: [SwaggerUIBundle.presets.apis],
                layout: 'BaseLayout'
            });
        </script>
    </body>
</html>
"""

    def _send_json(self, status: int, payload: dict, extra_headers: dict[str, str] | None = None) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, status: int, html: str, extra_headers: dict[str, str] | None = None) -> None:
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _send_file(
        self,
        path: Path,
        content_type: str,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        if not path.exists() or not path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return

        content = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)
        self.end_headers()
        self.wfile.write(content)

    def _send_index_with_asset_version(self) -> None:
        path = STATIC_DIR / "index.html"
        if not path.exists() or not path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return

        html = path.read_text(encoding="utf-8")
        html = html.replace("__ASSET_VERSION__", read_build_version())
        content = html.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.end_headers()
        self.wfile.write(content)

    def _unauthorized_if_needed(self, hostname: str = "") -> bool:
        if not API_KEY:
            return False

        request_key = self.headers.get("X-Api-Key", "")
        if request_key == API_KEY:
            return False

        if not request_key and hostname and API_KEY_GRACE_ALLOW_KNOWN_HOSTS:
            with sqlite3.connect(DB_PATH) as conn:
                if is_known_hostname(conn, hostname):
                    return False

        if request_key != API_KEY:
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "invalid api key"})
            return True
        return False

    def _cookie_value(self, cookie_name: str) -> str:
        cookie_header = self.headers.get("Cookie", "")
        for part in cookie_header.split(";"):
            name, _, value = part.strip().partition("=")
            if name == cookie_name:
                return value
        return ""

    def _web_session_username(self) -> str:
        token = self._cookie_value(WEB_SESSION_COOKIE)
        if not token:
            return ""

        with sqlite3.connect(DB_PATH) as conn:
            session_cutoff_iso = utc_hours_ago_iso(1)
            conn.execute(
                "DELETE FROM web_sessions WHERE last_activity_at_utc <= ?",
                (session_cutoff_iso,),
            )
            row = conn.execute(
                """
                SELECT s.username
                FROM web_sessions s
                JOIN web_users u ON u.username = s.username
                WHERE s.session_token = ? AND COALESCE(u.is_disabled, 0) = 0
                """,
                (token,),
            ).fetchone()
            conn.commit()

        if not row:
            return ""
        return str(row[0] or "")

    def _require_web_session(self) -> str:
        username = self._web_session_username()
        if not username:
            self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "login required"})
            return ""
        return username

    def _require_admin_session(self) -> str:
        username = self._require_web_session()
        if not username:
            return ""
        with sqlite3.connect(DB_PATH) as conn:
            user = get_web_user(conn, username)
        if not user or not user.get("is_admin"):
            self._send_json(HTTPStatus.FORBIDDEN, {"error": "admin required"})
            return ""
        return username

    def _external_base_url(self) -> str:
        scheme = (self.headers.get("X-Forwarded-Proto", "") or "").split(",")[0].strip()
        host = (self.headers.get("X-Forwarded-Host", "") or "").split(",")[0].strip()
        if not scheme:
            scheme = "https" if self.headers.get("X-Forwarded-Ssl", "").lower() == "on" else "http"
        if not host:
            host = (self.headers.get("Host", "") or "").strip() or "localhost"
        return f"{scheme}://{host}"

    def _absolute_url(self, path: str) -> str:
        return f"{self._external_base_url()}{path}"

    def _oauth_callback_html(self, redirect_path: str) -> str:
        target = json.dumps(redirect_path)
        return (
            "<!doctype html><html lang=\"de\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            "<title>OAuth Verbindung</title></head><body>"
            "<p>Weiterleitung...</p>"
            f"<script>window.location.replace({target});</script>"
            f"<noscript><meta http-equiv=\"refresh\" content=\"0;url={parse.quote(redirect_path, safe='/:?=&%')}\"></noscript>"
            "</body></html>"
        )

    def do_GET(self) -> None:
        parsed = urlparse(self.path)

        if parsed.path == "/oauth/microsoft/callback":
            query = parse_qs(parsed.query)
            state_token = str(query.get("state", [""])[0] or "").strip()
            code = str(query.get("code", [""])[0] or "").strip()
            remote_error = str(query.get("error", [""])[0] or "").strip()
            remote_error_description = str(query.get("error_description", [""])[0] or "").strip()

            if not state_token:
                self._send_html(HTTPStatus.BAD_REQUEST, self._oauth_callback_html("/?oauth_status=error&oauth_message=missing_state"))
                return

            with sqlite3.connect(DB_PATH) as conn:
                state_row = consume_oauth_state(conn, state_token, MICROSOFT_PROVIDER)
                conn.commit()

            if not state_row:
                self._send_html(HTTPStatus.BAD_REQUEST, self._oauth_callback_html("/?oauth_status=error&oauth_message=invalid_state"))
                return

            redirect_path = state_row["redirect_path"]
            if remote_error:
                message = remote_error_description or remote_error
                target = append_query_param(append_query_param(redirect_path, "oauth_status", "error"), "oauth_message", message)
                self._send_html(HTTPStatus.OK, self._oauth_callback_html(target))
                return

            if not code:
                target = append_query_param(append_query_param(redirect_path, "oauth_status", "error"), "oauth_message", "missing_code")
                self._send_html(HTTPStatus.BAD_REQUEST, self._oauth_callback_html(target))
                return

            with sqlite3.connect(DB_PATH) as conn:
                oauth_settings = get_oauth_settings(conn)

            redirect_uri = self._absolute_url("/oauth/microsoft/callback")
            ok, token_payload, raw = exchange_microsoft_code_for_tokens(oauth_settings, code, redirect_uri)
            if not ok:
                target = append_query_param(append_query_param(redirect_path, "oauth_status", "error"), "oauth_message", raw or token_payload.get("error_description", "oauth_exchange_failed"))
                self._send_html(HTTPStatus.OK, self._oauth_callback_html(target))
                return

            with sqlite3.connect(DB_PATH) as conn:
                upsert_oauth_connection(conn, state_row["username"], MICROSOFT_PROVIDER, token_payload)
                conn.commit()

            target = append_query_param(redirect_path, "oauth_status", "success")
            self._send_html(HTTPStatus.OK, self._oauth_callback_html(target))
            return

        if parsed.path == "/health":
            self._send_json(HTTPStatus.OK, {"status": "ok", "time_utc": utc_now_iso()})
            return

        if parsed.path == "/api/v1/session":
            username = self._web_session_username()
            is_admin = False
            if username:
                with sqlite3.connect(DB_PATH) as conn:
                    user = get_web_user(conn, username)
                    is_admin = bool(user and user.get("is_admin"))
            self._send_json(
                HTTPStatus.OK,
                {
                    "authenticated": bool(username),
                    "username": username,
                    "is_admin": is_admin,
                },
            )
            return

        if parsed.path == "/api/v1/agent-commands":
            query = parse_qs(parsed.query)
            hostname = query.get("hostname", [""])[0].strip()
            agent_id = query.get("agent_id", [""])[0].strip()
            limit = parse_int(query, "limit", default=10, min_value=1, max_value=100)

            if not hostname:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "hostname query parameter is required"})
                return

            if self._unauthorized_if_needed(hostname):
                return

            with sqlite3.connect(DB_PATH) as conn:
                expire_old_agent_commands(conn)
                rows = conn.execute(
                    """
                    SELECT id, created_at_utc, command_type, command_payload_json, expires_at_utc
                    FROM agent_commands
                    WHERE hostname = ? AND status = 'pending' AND expires_at_utc > ?
                    ORDER BY id ASC
                    LIMIT ?
                    """,
                    (hostname, utc_now_iso(), limit),
                ).fetchall()
                conn.commit()

            commands = []
            for row in rows:
                payload = parse_payload_json(str(row[3] or "{}"))
                commands.append(
                    {
                        "id": int(row[0]),
                        "created_at_utc": str(row[1] or ""),
                        "command_type": str(row[2] or ""),
                        "command_payload": payload,
                        "expires_at_utc": str(row[4] or ""),
                    }
                )

            self._send_json(
                HTTPStatus.OK,
                {
                    "hostname": hostname,
                    "agent_id": agent_id,
                    "count": len(commands),
                    "commands": commands,
                },
            )
            return

        if parsed.path.startswith("/api/v1/"):
            if parsed.path != "/api/v1/agent-commands":
                if not self._require_web_session():
                    return

        if parsed.path == "/api/v1/user-profile":
            username = self._web_session_username()
            with sqlite3.connect(DB_PATH) as conn:
                payload = current_user_payload(conn, username)
            self._send_json(HTTPStatus.OK, payload)
            return

        if parsed.path == "/api/v1/session/refresh":
            username = self._web_session_username()
            if not username:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "Not authenticated"})
                return
            session_token = self.headers.get("Authorization", "").replace("Bearer ", "")
            if not session_token:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "No session token"})
                return
            now_iso = utc_now_iso()
            expires_iso = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute(
                    "UPDATE web_sessions SET last_activity_at_utc = ?, expires_at_utc = ? WHERE session_token = ?",
                    (now_iso, expires_iso, session_token),
                )
                conn.commit()
            self._send_json(
                HTTPStatus.OK,
                {
                    "username": username,
                    "expires_at_utc": expires_iso,
                },
            )
            return

        if parsed.path == "/api/v1/active-users":
            username = self._web_session_username()
            with sqlite3.connect(DB_PATH) as conn:
                users = list_active_web_sessions(conn)
                conn.commit()
            self._send_json(
                HTTPStatus.OK,
                {
                    "current_username": username,
                    "count": len(users),
                    "users": users,
                },
            )
            return

        if parsed.path == "/api/v1/user-alert-subscriptions":
            username = self._web_session_username()
            with sqlite3.connect(DB_PATH) as conn:
                user_settings = get_web_user_settings(conn, username)
                oauth_connection = get_oauth_connection(conn, username, MICROSOFT_PROVIDER)
                alarm_settings = get_alarm_settings(conn)
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "username": username,
                        "subscriptions": get_web_user_alert_subscriptions(conn, username),
                        "available_hosts": list_available_alert_hosts(conn),
                        "mail_available": oauth_connection is not None and bool(str(user_settings.get("email_recipient", "") or "").strip()),
                        "telegram_available": bool(alarm_settings.get("telegram_enabled")) and bool(str(alarm_settings.get("telegram_bot_token", "") or "").strip()),
                        "alert_instant_mail_enabled": bool(user_settings.get("alert_instant_mail_enabled", False)),
                        "alert_instant_telegram_enabled": bool(user_settings.get("alert_instant_telegram_enabled", False)),
                    },
                )
            return

        if parsed.path == "/api/v1/web-users":
            if not self._require_admin_session():
                return
            with sqlite3.connect(DB_PATH) as conn:
                self._send_json(HTTPStatus.OK, {"users": list_web_users(conn)})
            return

        if parsed.path == "/api/v1/admin/user-alert-subscriptions":
            if not self._require_admin_session():
                return
            with sqlite3.connect(DB_PATH) as conn:
                alarm_settings = get_alarm_settings(conn)
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "users": list_all_user_alert_subscriptions(conn),
                        "available_hosts": list_available_alert_hosts(conn),
                        "telegram_available": bool(alarm_settings.get("telegram_enabled")) and bool(str(alarm_settings.get("telegram_bot_token", "") or "").strip()),
                    },
                )
            return

        if parsed.path == "/api/v1/oauth-settings":
            if not self._require_admin_session():
                return
            with sqlite3.connect(DB_PATH) as conn:
                settings = oauth_settings_public_view(get_oauth_settings(conn))
            self._send_json(HTTPStatus.OK, settings)
            return

        if parsed.path == "/api/v1/backup/database":
            if not self._require_admin_session():
                return
            try:
                backup_content = create_sqlite_backup_bytes(DB_PATH)
            except Exception:
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "database backup failed"})
                return

            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")
            version = re.sub(r"[^0-9A-Za-z._-]", "-", read_build_version())
            filename = f"monitoring-backup-v{version}-{timestamp}.db"

            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/x-sqlite3")
            self.send_header("Content-Length", str(len(backup_content)))
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(backup_content)
            return

        if parsed.path == "/api/v1/oauth/microsoft/start":
            username = self._web_session_username()
            with sqlite3.connect(DB_PATH) as conn:
                settings = get_oauth_settings(conn)
                if not oauth_is_configured(settings):
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "microsoft oauth not configured"})
                    return
                state_token = create_oauth_state(conn, username, MICROSOFT_PROVIDER, "/")
                conn.commit()
            redirect_uri = self._absolute_url("/oauth/microsoft/callback")
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", build_microsoft_authorize_url(settings, redirect_uri, state_token))
            self.end_headers()
            return

        if parsed.path == "/api/v1/latest":
            query = parse_qs(parsed.query)
            limit = parse_int(query, "limit", default=20, min_value=1, max_value=200)

            with sqlite3.connect(DB_PATH) as conn:
                rows = conn.execute(
                    """
                    SELECT id, received_at_utc, agent_id, hostname, primary_ip, payload_json
                    FROM reports
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
                settings_rows = conn.execute(
                    "SELECT hostname, display_name_override, COALESCE(country_code_override, ''), COALESCE(is_favorite, 0), COALESCE(is_hidden, 0) FROM host_settings"
                ).fetchall()

            reports = []
            host_settings_by_name = {
                str(row[0]): {
                    "display_name_override": str(row[1] or ""),
                    "country_code_override": normalize_country_code(row[2]),
                    "is_favorite": bool(int(row[3] or 0)),
                    "is_hidden": bool(int(row[4] or 0)),
                }
                for row in settings_rows
            }

            for row in rows:
                payload = json.loads(row[5])
                hostname = row[3]
                delivery_mode = str(payload.get("delivery_mode", "live") or "live")
                reports.append(
                    {
                        "id": row[0],
                        "received_at_utc": row[1],
                        "agent_id": row[2],
                        "hostname": hostname,
                        "primary_ip": row[4],
                        "delivery_mode": delivery_mode,
                        "display_name": effective_display_name(
                            payload,
                            str(host_settings_by_name.get(str(hostname), {}).get("display_name_override", "")),
                            str(hostname),
                        ),
                        "payload": payload,
                    }
                )

            self._send_json(HTTPStatus.OK, {"count": len(reports), "reports": reports})
            return

        if parsed.path == "/api/v1/hosts":
            query = parse_qs(parsed.query)
            limit = parse_int(query, "limit", default=20, min_value=1, max_value=200)
            offset = parse_int(query, "offset", default=0, min_value=0, max_value=500000)

            with sqlite3.connect(DB_PATH) as conn:
                total_hosts = conn.execute(
                    "SELECT COUNT(DISTINCT hostname) FROM reports"
                ).fetchone()[0]

                rows = conn.execute(
                    """
                    SELECT
                      r.hostname,
                      MAX(r.received_at_utc) AS last_seen_utc,
                      COUNT(*) AS report_count,
                      (
                        SELECT primary_ip
                        FROM reports r2
                        WHERE r2.hostname = r.hostname
                        ORDER BY r2.id DESC
                        LIMIT 1
                      ) AS latest_primary_ip,
                      (
                        SELECT agent_id
                        FROM reports r3
                        WHERE r3.hostname = r.hostname
                        ORDER BY r3.id DESC
                        LIMIT 1
                                            ) AS latest_agent_id,
                                            (
                                                SELECT payload_json
                                                FROM reports r4
                                                WHERE r4.hostname = r.hostname
                                                ORDER BY r4.id DESC
                                                LIMIT 1
                                            ) AS latest_payload_json,
                                            (
                                                SELECT COUNT(*)
                                                FROM alerts a1
                                                WHERE a1.hostname = r.hostname AND a1.status = 'open'
                                                  AND NOT EXISTS (SELECT 1 FROM muted_alert_rules m WHERE m.hostname = a1.hostname AND m.mountpoint = a1.mountpoint)
                                                  AND (a1.ack_at_utc IS NULL OR a1.ack_at_utc = '')
                                            ) AS open_alert_count,
                                            (
                                                SELECT COUNT(*)
                                                FROM alerts a2
                                                WHERE a2.hostname = r.hostname AND a2.status = 'open' AND a2.severity = 'critical'
                                                  AND NOT EXISTS (SELECT 1 FROM muted_alert_rules m WHERE m.hostname = a2.hostname AND m.mountpoint = a2.mountpoint)
                                                  AND (a2.ack_at_utc IS NULL OR a2.ack_at_utc = '')
                                            ) AS open_critical_alert_count
                    FROM reports r
                    GROUP BY r.hostname
                    ORDER BY last_seen_utc DESC
                    LIMIT ? OFFSET ?
                    """,
                    (limit, offset),
                ).fetchall()

                settings_rows = conn.execute(
                    "SELECT hostname, display_name_override, COALESCE(country_code_override, ''), COALESCE(is_favorite, 0), COALESCE(is_hidden, 0) FROM host_settings"
                ).fetchall()

            settings_map = {
                str(row[0]): {
                    "display_name_override": str(row[1] or ""),
                    "country_code_override": normalize_country_code(row[2]),
                    "is_favorite": bool(int(row[3] or 0)),
                    "is_hidden": bool(int(row[4] or 0)),
                }
                for row in settings_rows
            }
            hosts = []
            for row in rows:
                latest_payload = parse_payload_json(row[5] or "{}")
                hostname = str(row[0])
                host_settings = settings_map.get(hostname, {
                    "display_name_override": "",
                    "country_code_override": "",
                    "is_favorite": False,
                    "is_hidden": False,
                })
                country_code = normalize_country_code(host_settings.get("country_code_override", ""))
                if not country_code:
                    country_code = extract_country_code_from_payload(latest_payload)
                hosts.append(
                    {
                        "hostname": hostname,
                        "display_name": effective_display_name(
                            latest_payload,
                            str(host_settings.get("display_name_override", "")),
                            hostname,
                        ),
                        "last_seen_utc": row[1],
                        "report_count": row[2],
                        "primary_ip": row[3] or "",
                        "agent_id": row[4] or "",
                        "agent_version": str(latest_payload.get("agent_version", "")),
                        "delivery_mode": str(latest_payload.get("delivery_mode", "live") or "live"),
                        "is_delayed": bool(latest_payload.get("is_delayed", False)),
                        "queue_depth": payload_int(latest_payload, "queue_depth", 0),
                        "open_alert_count": int(row[6] or 0),
                        "open_critical_alert_count": int(row[7] or 0),
                        "os": str(latest_payload.get("os", "")),
                        "country_code": country_code,
                        "is_favorite": bool(host_settings.get("is_favorite", False)),
                        "is_hidden": bool(host_settings.get("is_hidden", False)),
                        "agent_api_key_status": str((latest_payload.get("agent_api_key") or {}).get("status", "off")),
                    }
                )

            hidden_hosts = sum(1 for host in hosts if bool(host.get("is_hidden", False)))
            visible_hosts = len(hosts) - hidden_hosts

            self._send_json(
                HTTPStatus.OK,
                {
                    "count": len(hosts),
                    "limit": limit,
                    "offset": offset,
                    "total_hosts": total_hosts,
                    "visible_hosts": visible_hosts,
                    "hidden_hosts": hidden_hosts,
                    "hosts": hosts,
                },
            )
            return

        if parsed.path == "/api/v1/host-reports":
            query = parse_qs(parsed.query)
            hostname = query.get("hostname", [""])[0].strip()
            if not hostname:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "hostname query parameter is required"})
                return

            limit = parse_int(query, "limit", default=10, min_value=1, max_value=200)
            offset = parse_int(query, "offset", default=0, min_value=0, max_value=500000)
            jump_to_utc_raw = query.get("jump_to_utc", [""])[0].strip()
            jump_to_utc = ""
            jump_to_dt: datetime | None = None
            if jump_to_utc_raw:
                try:
                    parsed_jump = datetime.fromisoformat(jump_to_utc_raw.replace("Z", "+00:00"))
                    if parsed_jump.tzinfo is None:
                        parsed_jump = parsed_jump.replace(tzinfo=timezone.utc)
                    jump_to_dt = parsed_jump.astimezone(timezone.utc)
                    jump_to_utc = jump_to_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                except ValueError:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "jump_to_utc must be ISO datetime"})
                    return

            with sqlite3.connect(DB_PATH) as conn:
                total_reports = conn.execute(
                    "SELECT COUNT(*) FROM reports WHERE hostname = ?",
                    (hostname,),
                ).fetchone()[0]
                bounds_row = conn.execute(
                    "SELECT MIN(received_at_utc), MAX(received_at_utc) FROM reports WHERE hostname = ?",
                    (hostname,),
                ).fetchone()
                oldest_report_at_utc = str(bounds_row[0] or "") if bounds_row else ""
                newest_report_at_utc = str(bounds_row[1] or "") if bounds_row else ""

                resolved_offset = offset
                if jump_to_dt is not None and total_reports > 0:
                    newer_count = conn.execute(
                        "SELECT COUNT(*) FROM reports WHERE hostname = ? AND received_at_utc > ?",
                        (hostname, jump_to_utc),
                    ).fetchone()[0]
                    resolved_offset = min(max(0, int(newer_count or 0)), max(0, int(total_reports) - 1))

                rows = conn.execute(
                    """
                    SELECT id, received_at_utc, agent_id, hostname, primary_ip, payload_json
                    FROM reports
                    WHERE hostname = ?
                    ORDER BY id DESC
                    LIMIT ? OFFSET ?
                    """,
                    (hostname, limit, resolved_offset),
                ).fetchall()

                display_name_override = get_display_name_override(conn, hostname)

            reports = []
            for row in rows:
                payload = json.loads(row[5])
                delivery_mode = str(payload.get("delivery_mode", "live") or "live")
                reports.append(
                    {
                        "id": row[0],
                        "received_at_utc": row[1],
                        "agent_id": row[2],
                        "hostname": row[3],
                        "primary_ip": row[4],
                        "delivery_mode": delivery_mode,
                        "display_name": effective_display_name(payload, display_name_override, hostname),
                        "payload": payload,
                    }
                )

            self._send_json(
                HTTPStatus.OK,
                {
                    "count": len(reports),
                    "limit": limit,
                    "offset": resolved_offset,
                    "total_reports": total_reports,
                    "hostname": hostname,
                    "jump_to_utc": jump_to_utc,
                    "oldest_report_at_utc": oldest_report_at_utc,
                    "newest_report_at_utc": newest_report_at_utc,
                    "reports": reports,
                },
            )
            return

        if parsed.path == "/api/v1/host-settings":
            query = parse_qs(parsed.query)
            hostname = query.get("hostname", [""])[0].strip()
            if not hostname:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "hostname query parameter is required"})
                return

            with sqlite3.connect(DB_PATH) as conn:
                host_settings = get_host_settings(conn, hostname)

            self._send_json(
                HTTPStatus.OK,
                {
                    "hostname": hostname,
                    "display_name_override": host_settings["display_name_override"],
                    "country_code_override": host_settings["country_code_override"],
                    "is_favorite": host_settings["is_favorite"],
                    "is_hidden": host_settings["is_hidden"],
                },
            )
            return

        if parsed.path == "/api/v1/agent-update-status":
            with sqlite3.connect(DB_PATH) as conn:
                expire_old_agent_commands(conn)
                host_settings_rows = conn.execute(
                    "SELECT hostname, display_name_override FROM host_settings"
                ).fetchall()
                latest_reports = get_latest_report_rows_by_hostname(conn)
                latest_commands = get_latest_update_command_rows(conn)
                conn.commit()

            overrides = {str(row[0] or ""): str(row[1] or "") for row in host_settings_rows}
            hostnames = sorted(set(latest_reports.keys()) | set(latest_commands.keys()))
            hosts = []
            summary = {
                "idle": 0,
                "pending": 0,
                "completed": 0,
                "failed": 0,
                "expired": 0,
            }

            for hostname in hostnames:
                latest_report = latest_reports.get(hostname, {})
                payload = latest_report.get("payload", {}) if isinstance(latest_report, dict) else {}
                command = latest_commands.get(hostname, {}) if isinstance(latest_commands, dict) else {}
                command_status = str(command.get("status", "") or "idle")
                if command_status not in summary:
                    command_status = "idle"
                summary[command_status] += 1

                agent_update = payload.get("agent_update", {})
                if not isinstance(agent_update, dict):
                    agent_update = {}

                hosts.append(
                    {
                        "hostname": hostname,
                        "display_name": effective_display_name(payload, overrides.get(hostname, ""), hostname),
                        "agent_version": str(payload.get("agent_version", "")),
                        "last_report_utc": str(latest_report.get("received_at_utc", "")),
                        "command_status": command_status,
                        "command_created_at_utc": str(command.get("created_at_utc", "")),
                        "command_executed_at_utc": str(command.get("executed_at_utc", "")),
                        "command_expires_at_utc": str(command.get("expires_at_utc", "")),
                        "command_result_message": str(command.get("result", {}).get("message", "")),
                        "next_priority_check_utc": str(agent_update.get("next_priority_check_utc", "")),
                        "last_priority_check_utc": str(agent_update.get("last_priority_check_utc", "")),
                        "priority_check_minutes": payload_int(agent_update, "priority_check_minutes", 0),
                        "recurring_update_hours": payload_int(agent_update, "recurring_update_hours", 0),
                        "recurring_update_hint": str(agent_update.get("recurring_update_hint", "")),
                    }
                )

            hosts.sort(key=lambda item: (item["display_name"].lower(), item["hostname"].lower()))
            self._send_json(
                HTTPStatus.OK,
                {
                    "total_hosts": len(hosts),
                    "summary": summary,
                    "default_schedule_note": "Linux-Installer im Repo plant den Fallback-Check standardmaessig um 00:11, 06:11, 12:11 und 18:11 Uhr. Windows plant standardmaessig alle 6 Stunden relativ zum Installationszeitpunkt. Der priorisierte Zusatz-Check laeuft standardmaessig alle 60 Minuten seit dem letzten Check.",
                    "hosts": hosts,
                },
            )
            return

        if parsed.path == "/api/v1/critical-trends":
            query = parse_qs(parsed.query)
            hours = parse_int(query, "hours", default=72, min_value=1, max_value=24 * 30)
            with sqlite3.connect(DB_PATH) as conn:
                warnings = collect_critical_trends(conn, hours)

            self._send_json(HTTPStatus.OK, {
                "hours": hours,
                "warnings": warnings,
                "total": len(warnings),
            })
            return

        if parsed.path == "/api/v1/inactive-hosts":
            query = parse_qs(parsed.query)
            hours = parse_int(query, "hours", default=3, min_value=1, max_value=24 * 30)
            with sqlite3.connect(DB_PATH) as conn:
                inactive = collect_inactive_hosts(conn, hours)

            self._send_json(HTTPStatus.OK, {
                "hours": hours,
                "inactive_hosts": inactive,
                "total": len(inactive),
            })
            return

        if parsed.path == "/api/v1/analysis":
            query = parse_qs(parsed.query)
            hostname = query.get("hostname", [""])[0].strip()
            if not hostname:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "hostname query parameter is required"})
                return

            username = self._web_session_username()
            visibility_editable = bool(username)
            fs_focus_hidden: list[str] = []
            large_files_hidden: list[str] = []

            hours = parse_int(query, "hours", default=24, min_value=1, max_value=24 * 30)
            cutoff_iso = utc_hours_ago_iso(hours)

            with sqlite3.connect(DB_PATH) as conn:
                rows = conn.execute(
                    """
                    SELECT id, received_at_utc, payload_json
                    FROM reports
                    WHERE hostname = ? AND received_at_utc >= ?
                    ORDER BY id ASC
                    """,
                    (hostname, cutoff_iso),
                ).fetchall()
                total_rows = conn.execute(
                    """
                    SELECT received_at_utc, payload_json
                    FROM reports
                    WHERE hostname = ?
                    ORDER BY id ASC
                    """,
                    (hostname,),
                ).fetchall()

            fs_by_mountpoint = {}
            report_count = 0
            latest_report_time = ""
            latest_max_used_percent = None
            latest_hotspots = []
            cpu_usage_values: list[float] = []
            load_avg_1_values: list[float] = []
            memory_used_values: list[float] = []
            swap_used_values: list[float] = []
            cpu_usage_series: list[dict] = []
            load_avg_1_series: list[dict] = []
            memory_used_series: list[dict] = []
            swap_used_series: list[dict] = []
            delayed_report_count = 0
            live_report_count = 0
            latest_delivery_mode = "live"
            latest_is_delayed = False
            latest_queue_depth = 0
            total_delayed_report_count = 0
            total_live_report_count = 0
            latest_large_files: dict = {}

            for total_row in total_rows:
                total_payload = parse_payload_json(total_row[1])
                total_delivery_mode = str(total_payload.get("delivery_mode", "live") or "live").lower()
                total_is_delayed = total_delivery_mode == "delayed" or bool(total_payload.get("is_delayed", False))
                if total_is_delayed:
                    total_delayed_report_count += 1
                else:
                    total_live_report_count += 1
                latest_delivery_mode = "delayed" if total_is_delayed else "live"
                latest_is_delayed = total_is_delayed
                latest_queue_depth = payload_int(total_payload, "queue_depth", 0)

            for row in rows:
                report_count += 1
                latest_report_time = row[1]
                payload = parse_payload_json(row[2])
                delivery_mode = str(payload.get("delivery_mode", "live") or "live").lower()
                is_delayed = delivery_mode == "delayed" or bool(payload.get("is_delayed", False))
                if is_delayed:
                    delayed_report_count += 1
                else:
                    live_report_count += 1
                latest_delivery_mode = "delayed" if is_delayed else "live"
                latest_is_delayed = is_delayed
                latest_queue_depth = payload_int(payload, "queue_depth", 0)
                raw_large_files = payload.get("large_files", {})
                if isinstance(raw_large_files, dict):
                    latest_large_files = raw_large_files

                cpu_usage = get_nested_number(payload, "cpu", "usage_percent")
                if cpu_usage is not None:
                    cpu_usage_values.append(cpu_usage)
                    cpu_usage_series.append({"time_utc": row[1], "value": cpu_usage})

                load_avg_1 = get_nested_number(payload, "cpu", "load_avg_1")
                if load_avg_1 is not None:
                    load_avg_1_values.append(load_avg_1)
                    load_avg_1_series.append({"time_utc": row[1], "value": load_avg_1})

                memory_used = get_nested_number(payload, "memory", "used_percent")
                if memory_used is not None:
                    memory_used_values.append(memory_used)
                    memory_used_series.append({"time_utc": row[1], "value": memory_used})

                swap_used = get_nested_number(payload, "swap", "used_percent")
                if swap_used is not None:
                    swap_used_values.append(swap_used)
                    swap_used_series.append({"time_utc": row[1], "value": swap_used})

                filesystems = payload.get("filesystems", [])
                if not isinstance(filesystems, list):
                    continue

                latest_fs_entries = []
                for fs in filesystems:
                    if not isinstance(fs, dict):
                        continue

                    mountpoint = str(fs.get("mountpoint", "")).strip()
                    used_percent_raw = fs.get("used_percent")
                    try:
                        used_percent = float(used_percent_raw)
                    except (TypeError, ValueError):
                        continue

                    latest_fs_entries.append({
                        "mountpoint": mountpoint,
                        "used_percent": used_percent,
                    })

                    if mountpoint not in fs_by_mountpoint:
                        fs_by_mountpoint[mountpoint] = []

                    fs_by_mountpoint[mountpoint].append(
                        {
                            "time_utc": row[1],
                            "used_percent": used_percent,
                        }
                    )

                if latest_fs_entries:
                    latest_fs_entries.sort(key=lambda item: item["used_percent"], reverse=True)
                    latest_max_used_percent = latest_fs_entries[0]["used_percent"]
                    latest_hotspots = latest_fs_entries[:5]

            trends = []
            for mountpoint, points in fs_by_mountpoint.items():
                if not points:
                    continue

                values = [point["used_percent"] for point in points]
                first_value = values[0]
                last_value = values[-1]
                average_value = sum(values) / len(values)

                trends.append(
                    {
                        "mountpoint": mountpoint,
                        "sample_count": len(values),
                        "current_used_percent": last_value,
                        "min_used_percent": min(values),
                        "max_used_percent": max(values),
                        "avg_used_percent": average_value,
                        "delta_used_percent": last_value - first_value,
                        "series": points,
                    }
                )

            trends.sort(key=lambda item: item["current_used_percent"], reverse=True)

            if username:
                fs_mountpoints = [item.get("mountpoint", "") for item in trends if isinstance(item, dict)]
                raw_large_filesystems = latest_large_files.get("filesystems", []) if isinstance(latest_large_files, dict) else []
                lf_mountpoints = [
                    item.get("mountpoint", "")
                    for item in raw_large_filesystems
                    if isinstance(item, dict)
                ]
                with sqlite3.connect(DB_PATH) as conn:
                    fs_focus_hidden = ensure_default_user_filesystem_visibility(conn, username, hostname, "fs-focus", fs_mountpoints)
                    large_files_hidden = ensure_default_user_filesystem_visibility(conn, username, hostname, "large-files", lf_mountpoints)
                    conn.commit()

            self._send_json(
                HTTPStatus.OK,
                {
                    "hostname": hostname,
                    "window_hours": hours,
                    "cutoff_utc": cutoff_iso,
                    "report_count": report_count,
                    "latest_report_time_utc": latest_report_time,
                    "latest_max_used_percent": latest_max_used_percent,
                    "latest_hotspots": latest_hotspots,
                    "resource_trends": {
                        "cpu_usage_percent": summarize_numeric_series(cpu_usage_values),
                        "load_avg_1": summarize_numeric_series(load_avg_1_values),
                        "memory_used_percent": summarize_numeric_series(memory_used_values),
                        "swap_used_percent": summarize_numeric_series(swap_used_values),
                    },
                    "resource_series": {
                        "cpu_usage_percent": cpu_usage_series,
                        "load_avg_1": load_avg_1_series,
                        "memory_used_percent": memory_used_series,
                        "swap_used_percent": swap_used_series,
                    },
                    "delivery": {
                        "latest_mode": latest_delivery_mode,
                        "latest_is_delayed": latest_is_delayed,
                        "latest_queue_depth": latest_queue_depth,
                        "delayed_report_count": delayed_report_count,
                        "live_report_count": live_report_count,
                        "total_delayed_report_count": total_delayed_report_count,
                        "total_live_report_count": total_live_report_count,
                    },
                    "filesystem_visibility": {
                        "editable": visibility_editable,
                        "fs_focus_hidden": fs_focus_hidden,
                        "large_files_hidden": large_files_hidden,
                    },
                    "filesystem_trends": trends,
                    "large_files": latest_large_files,
                },
            )
            return

        if parsed.path == "/api/v1/alerts":
            query = parse_qs(parsed.query)
            status_filter = query.get("status", ["all"])[0].strip().lower()
            if status_filter not in {"all", "open", "resolved"}:
                status_filter = "all"

            severity_filter = query.get("severity", ["all"])[0].strip().lower()
            if severity_filter not in {"all", "warning", "critical"}:
                severity_filter = "all"

            acknowledged_filter = query.get("acknowledged", ["all"])[0].strip().lower()
            if acknowledged_filter not in {"all", "yes", "no"}:
                acknowledged_filter = "all"

            hostname_filter = query.get("hostname", [""])[0].strip()
            limit = parse_int(query, "limit", default=50, min_value=1, max_value=500)
            offset = parse_int(query, "offset", default=0, min_value=0, max_value=500000)

            where_parts = []
            args = []
            where_parts.append("COALESCE((SELECT is_hidden FROM host_settings hs WHERE hs.hostname = alerts.hostname), 0) = 0")
            if status_filter != "all":
                where_parts.append("status = ?")
                args.append(status_filter)
            if severity_filter != "all":
                where_parts.append("severity = ?")
                args.append(severity_filter)
            if acknowledged_filter == "no":
                where_parts.append("(ack_at_utc IS NULL OR ack_at_utc = '')")
            elif acknowledged_filter == "yes":
                where_parts.append("(ack_at_utc IS NOT NULL AND ack_at_utc != '')")
            if hostname_filter:
                where_parts.append("hostname = ?")
                args.append(hostname_filter)

            where_clause = ""
            if where_parts:
                where_clause = "WHERE " + " AND ".join(where_parts)

            with sqlite3.connect(DB_PATH) as conn:
                total = conn.execute(
                    f"SELECT COUNT(*) FROM alerts {where_clause}",
                    tuple(args),
                ).fetchone()[0]

                rows = conn.execute(
                    f"""
                      SELECT id, hostname, mountpoint, severity, used_percent, status,
                          created_at_utc, last_seen_at_utc, resolved_at_utc, report_id,
                          COALESCE(ack_note, ''), COALESCE(ack_by, ''), COALESCE(ack_at_utc, '')
                    FROM alerts
                    {where_clause}
                    ORDER BY id DESC
                    LIMIT ? OFFSET ?
                    """,
                    tuple(args + [limit, offset]),
                ).fetchall()

                hostnames = sorted({str(row[1]) for row in rows if row[1]})
                display_names: dict[str, str] = {}
                if hostnames:
                    placeholders = ",".join("?" for _ in hostnames)
                    settings_rows = conn.execute(
                        f"SELECT hostname, display_name_override FROM host_settings WHERE hostname IN ({placeholders})",
                        tuple(hostnames),
                    ).fetchall()
                    overrides = {str(item[0]): str(item[1] or "") for item in settings_rows}

                    latest_payload_rows = conn.execute(
                        f"""
                        SELECT hostname, payload_json
                        FROM reports
                        WHERE id IN (
                            SELECT MAX(id)
                            FROM reports
                            WHERE hostname IN ({placeholders})
                            GROUP BY hostname
                        )
                        """,
                        tuple(hostnames),
                    ).fetchall()
                    payload_by_hostname = {
                        str(item[0]): parse_payload_json(str(item[1] or "{}"))
                        for item in latest_payload_rows
                    }

                    for hostname in hostnames:
                        payload = payload_by_hostname.get(hostname, {})
                        display_names[hostname] = effective_display_name(
                            payload,
                            overrides.get(hostname, ""),
                            hostname,
                        )

            alerts = []
            with sqlite3.connect(DB_PATH) as conn_mute:
                muted_pairs = {
                    (str(r[0]), str(r[1]))
                    for r in conn_mute.execute("SELECT hostname, mountpoint FROM muted_alert_rules").fetchall()
                }
            for row in rows:
                hostname = str(row[1] or "")
                mountpoint = str(row[2] or "")
                alerts.append(
                    {
                        "id": row[0],
                        "hostname": hostname,
                        "display_name": display_names.get(hostname, hostname),
                        "mountpoint": mountpoint,
                        "severity": row[3],
                        "used_percent": row[4],
                        "status": row[5],
                        "created_at_utc": row[6],
                        "last_seen_at_utc": row[7],
                        "resolved_at_utc": row[8],
                        "report_id": row[9],
                        "ack_note": str(row[10] or ""),
                        "ack_by": str(row[11] or ""),
                        "ack_at_utc": str(row[12] or ""),
                        "is_acknowledged": bool(str(row[12] or "").strip()),
                        "is_muted": (hostname, mountpoint) in muted_pairs,
                    }
                )

            self._send_json(
                HTTPStatus.OK,
                {
                    "count": len(alerts),
                    "total": total,
                    "limit": limit,
                    "offset": offset,
                    "status": status_filter,
                    "severity": severity_filter,
                    "hostname": hostname_filter,
                    "alerts": alerts,
                },
            )
            return

        if parsed.path == "/api/v1/alerts-summary":
            query = parse_qs(parsed.query)
            hostname_filter = query.get("hostname", [""])[0].strip()

            where_clause = "WHERE status = 'open'"
            args = []
            where_clause += " AND COALESCE((SELECT is_hidden FROM host_settings hs WHERE hs.hostname = alerts.hostname), 0) = 0"
            where_clause += " AND NOT EXISTS (SELECT 1 FROM muted_alert_rules m WHERE m.hostname = alerts.hostname AND m.mountpoint = alerts.mountpoint)"
            where_clause += " AND (ack_at_utc IS NULL OR ack_at_utc = '')"
            if hostname_filter:
                where_clause += " AND hostname = ?"
                args.append(hostname_filter)

            with sqlite3.connect(DB_PATH) as conn:
                alarm_settings = get_alarm_settings(conn)
                total_open = conn.execute(
                    f"SELECT COUNT(*) FROM alerts {where_clause}",
                    tuple(args),
                ).fetchone()[0]
                warning_open = conn.execute(
                    f"SELECT COUNT(*) FROM alerts {where_clause} AND severity = 'warning'",
                    tuple(args),
                ).fetchone()[0]
                critical_open = conn.execute(
                    f"SELECT COUNT(*) FROM alerts {where_clause} AND severity = 'critical'",
                    tuple(args),
                ).fetchone()[0]

            self._send_json(
                HTTPStatus.OK,
                {
                    "hostname": hostname_filter,
                    "thresholds": {
                        "warning_percent": alarm_settings["warning_threshold_percent"],
                        "critical_percent": alarm_settings["critical_threshold_percent"],
                    },
                    "open": {
                        "total": total_open,
                        "warning": warning_open,
                        "critical": critical_open,
                    },
                },
            )
            return

        if parsed.path == "/api/v1/export/alerts.csv":
            query = parse_qs(parsed.query)
            status_filter = query.get("status", ["all"])[0].strip().lower()
            if status_filter not in {"all", "open", "resolved"}:
                status_filter = "all"
            severity_filter = query.get("severity", ["all"])[0].strip().lower()
            if severity_filter not in {"all", "warning", "critical"}:
                severity_filter = "all"
            hostname_filter = query.get("hostname", [""])[0].strip()

            where_parts = []
            args: list[object] = []
            where_parts.append("COALESCE((SELECT is_hidden FROM host_settings hs WHERE hs.hostname = alerts.hostname), 0) = 0")
            if status_filter != "all":
                where_parts.append("status = ?")
                args.append(status_filter)
            if severity_filter != "all":
                where_parts.append("severity = ?")
                args.append(severity_filter)
            if hostname_filter:
                where_parts.append("hostname = ?")
                args.append(hostname_filter)
            where_clause = "WHERE " + " AND ".join(where_parts) if where_parts else ""

            with sqlite3.connect(DB_PATH) as conn:
                rows = conn.execute(
                    f"""
                    SELECT id, hostname, mountpoint, severity, used_percent, status,
                           created_at_utc, last_seen_at_utc, resolved_at_utc,
                           COALESCE(ack_by, ''), COALESCE(ack_at_utc, ''), COALESCE(ack_note, '')
                    FROM alerts
                    {where_clause}
                    ORDER BY id DESC
                    """,
                    tuple(args),
                ).fetchall()

            buffer = io.StringIO()
            writer = csv.writer(buffer)
            writer.writerow([
                "id",
                "hostname",
                "mountpoint",
                "severity",
                "used_percent",
                "status",
                "created_at_utc",
                "last_seen_at_utc",
                "resolved_at_utc",
                "ack_by",
                "ack_at_utc",
                "ack_note",
            ])
            for row in rows:
                writer.writerow(row)

            csv_bytes = buffer.getvalue().encode("utf-8")
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")
            filename = f"monitoring-alerts-{timestamp}.csv"
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Length", str(len(csv_bytes)))
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(csv_bytes)
            return

        if parsed.path == "/api/v1/export/reports.json":
            query = parse_qs(parsed.query)
            hostname = query.get("hostname", [""])[0].strip()
            if not hostname:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "hostname query parameter is required"})
                return
            limit = parse_int(query, "limit", default=2000, min_value=1, max_value=50000)

            with sqlite3.connect(DB_PATH) as conn:
                rows = conn.execute(
                    """
                    SELECT id, received_at_utc, agent_id, hostname, primary_ip, payload_json
                    FROM reports
                    WHERE hostname = ?
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (hostname, limit),
                ).fetchall()

            reports = [
                {
                    "id": int(row[0]),
                    "received_at_utc": str(row[1] or ""),
                    "agent_id": str(row[2] or ""),
                    "hostname": str(row[3] or ""),
                    "primary_ip": str(row[4] or ""),
                    "payload": parse_payload_json(str(row[5] or "{}")),
                }
                for row in rows
            ]

            payload = {
                "hostname": hostname,
                "count": len(reports),
                "limit": limit,
                "exported_at_utc": utc_now_iso(),
                "reports": reports,
            }
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%SZ")
            safe_hostname = re.sub(r"[^0-9A-Za-z._-]", "-", hostname) or "host"
            filename = f"monitoring-reports-{safe_hostname}-{timestamp}.json"
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path == "/api/v1/alarm-settings":
            with sqlite3.connect(DB_PATH) as conn:
                settings = get_alarm_settings(conn)

            self._send_json(HTTPStatus.OK, settings)
            return

        if parsed.path == "/api/v1/alert-mutes":
            with sqlite3.connect(DB_PATH) as conn:
                rows = conn.execute(
                    "SELECT hostname, mountpoint, muted_by, muted_at_utc FROM muted_alert_rules ORDER BY hostname, mountpoint"
                ).fetchall()
            self._send_json(
                HTTPStatus.OK,
                {"mutes": [{"hostname": r[0], "mountpoint": r[1], "muted_by": r[2], "muted_at_utc": r[3]} for r in rows]},
            )
            return

        if parsed.path == "/":
            self._send_index_with_asset_version()
            return

        if parsed.path == "/app.js":
            self._send_file(STATIC_DIR / "app.js", "application/javascript; charset=utf-8")
            return

        if parsed.path == "/styles.css":
            self._send_file(STATIC_DIR / "styles.css", "text/css; charset=utf-8")
            return

        if parsed.path == "/openapi.yaml":
            self._send_file(
                OPENAPI_SPEC_PATH,
                "application/yaml; charset=utf-8",
                extra_headers={
                    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                    "Pragma": "no-cache",
                    "Expires": "0",
                },
            )
            return

        if parsed.path in {"/swagger", "/swagger/", "/docs", "/docs/"}:
            self._send_html(HTTPStatus.OK, self._swagger_ui_html())
            return

        if parsed.path.endswith("/BUILD_VERSION"):
            self._send_file(
                BUILD_VERSION_PATH,
                "text/plain; charset=utf-8",
                extra_headers={
                    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                    "Pragma": "no-cache",
                    "Expires": "0",
                },
            )
            return

        if parsed.path.endswith("/AGENT_VERSION"):
            if AGENT_VERSION_PATH.exists():
                self._send_file(AGENT_VERSION_PATH, "text/plain; charset=utf-8")
            else:
                self._send_file(BUILD_VERSION_PATH, "text/plain; charset=utf-8")
            return

        if parsed.path.startswith("/icons/"):
            icon_name = Path(parsed.path).name
            icon_path = STATIC_DIR / "icons" / icon_name
            if icon_path.exists() and icon_path.is_file():
                if icon_name.lower().endswith(".png"):
                    mime = "image/png"
                elif icon_name.lower().endswith(".svg"):
                    mime = "image/svg+xml"
                elif icon_name.lower().endswith(".jpg") or icon_name.lower().endswith(".jpeg"):
                    mime = "image/jpeg"
                else:
                    mime = "application/octet-stream"
                self._send_file(icon_path, mime)
                return

        self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path == "/api/v1/web-login":
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "empty body"})
                return

            raw_body = self.rfile.read(content_length)
            try:
                payload = json.loads(raw_body)
            except json.JSONDecodeError:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid json"})
                return

            username = str(payload.get("username", "")).strip()
            password = str(payload.get("password", ""))
            if not username or not password:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "username/password required"})
                return

            with sqlite3.connect(DB_PATH) as conn:
                user = get_web_user(conn, username)
                if not user or user.get("is_disabled"):
                    self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "invalid credentials"})
                    return
                if not verify_password(password, str(user["password_hash"]), str(user["password_salt"])):
                    self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "invalid credentials"})
                    return

                token, expires_at = create_web_session(conn, username)
                conn.commit()

            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "authenticated",
                    "username": username,
                    "expires_at_utc": expires_at,
                },
                extra_headers={
                    "Set-Cookie": f"{WEB_SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax",
                },
            )
            return

        if path == "/api/v1/web-logout":
            token = self._cookie_value(WEB_SESSION_COOKIE)
            if token:
                with sqlite3.connect(DB_PATH) as conn:
                    conn.execute("DELETE FROM web_sessions WHERE session_token = ?", (token,))
                    conn.commit()

            self._send_json(
                HTTPStatus.OK,
                {"status": "logged_out"},
                extra_headers={
                    "Set-Cookie": f"{WEB_SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0",
                },
            )
            return

        if path.startswith("/api/v1/") and path not in {"/api/v1/agent-report", "/api/v1/agent-command-result"}:
            if not self._require_web_session():
                return

        if path == "/api/v1/change-password":
            username = self._web_session_username()
            if not username:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "login required"})
                return

            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "empty body"})
                return

            raw_body = self.rfile.read(content_length)
            try:
                payload = json.loads(raw_body)
            except json.JSONDecodeError:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid json"})
                return

            current_password = str(payload.get("current_password", ""))
            new_password = str(payload.get("new_password", ""))
            if not password_meets_policy(new_password):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": f"new password too short (min {MIN_PASSWORD_LENGTH})"})
                return

            with sqlite3.connect(DB_PATH) as conn:
                user = get_web_user(conn, username)
                if not user or not verify_password(current_password, str(user["password_hash"]), str(user["password_salt"])):
                    self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "current password invalid"})
                    return

                update_web_user_password(conn, username, new_password)
                token, expires_at = create_web_session(conn, username)
                conn.commit()

            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "password_changed",
                    "username": username,
                    "expires_at_utc": expires_at,
                },
                extra_headers={
                    "Set-Cookie": f"{WEB_SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax",
                },
            )
            return

        if path == "/api/v1/alarm-settings":
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "empty body"})
                return

            raw_body = self.rfile.read(content_length)
            try:
                payload = json.loads(raw_body)
            except json.JSONDecodeError:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid json"})
                return

            with sqlite3.connect(DB_PATH) as conn:
                stored = save_alarm_settings(conn, payload)
                conn.commit()

            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "stored",
                    "settings": stored,
                },
            )
            return

        if path == "/api/v1/user-profile":
            username = self._web_session_username()
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "empty body"})
                return
            raw_body = self.rfile.read(content_length)
            try:
                payload = json.loads(raw_body)
            except json.JSONDecodeError:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid json"})
                return

            with sqlite3.connect(DB_PATH) as conn:
                settings = save_web_user_settings(conn, username, payload)
                conn.commit()
            self._send_json(HTTPStatus.OK, settings)
            return

        if path == "/api/v1/user-alert-subscriptions":
            username = self._web_session_username()
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "empty body"})
                return
            raw_body = self.rfile.read(content_length)
            try:
                payload = json.loads(raw_body)
            except json.JSONDecodeError:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid json"})
                return

            subscriptions = payload.get("subscriptions", [])
            if not isinstance(subscriptions, list):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "subscriptions must be a list"})
                return

            try:
                with sqlite3.connect(DB_PATH) as conn:
                    saved = replace_web_user_alert_subscriptions(conn, username, subscriptions)
                    conn.commit()
                self._send_json(HTTPStatus.OK, {"status": "stored", "subscriptions": saved})
            except ValueError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return

        if path == "/api/v1/user-alert-subscriptions/test":
            username = self._web_session_username()
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "empty body"})
                return
            raw_body = self.rfile.read(content_length)
            try:
                payload = json.loads(raw_body)
            except json.JSONDecodeError:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid json"})
                return

            hostname = str(payload.get("hostname", "") or "").strip()
            channel = str(payload.get("channel", "") or "").strip().lower()
            if not hostname:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "hostname missing"})
                return
            if channel not in {"mail", "telegram"}:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "channel must be mail or telegram"})
                return

            with sqlite3.connect(DB_PATH) as conn:
                subscriptions = get_web_user_alert_subscriptions(conn, username)
                matched = next((item for item in subscriptions if str(item.get("hostname", "")) == hostname), None)
                if matched is None:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "host not subscribed"})
                    return
                if channel == "mail" and not bool(matched.get("notify_mail", False)):
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "mail channel not enabled for host"})
                    return
                if channel == "telegram" and not bool(matched.get("notify_telegram", False)):
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "telegram channel not enabled for host"})
                    return

                host_context = collect_host_mail_context(conn, hostname)
                user_settings = get_web_user_settings(conn, username)

                if channel == "mail":
                    recipient = str(user_settings.get("email_recipient", "") or "").strip()
                    if not recipient:
                        self._send_json(HTTPStatus.BAD_REQUEST, {"error": "email recipient missing"})
                        return
                    ok_token, access_token, details = ensure_microsoft_access_token(conn, username)
                    if not ok_token:
                        self._send_json(HTTPStatus.BAD_REQUEST, {"error": details or "oauth unavailable"})
                        return
                    subject = f"[TEST] Host Alert Abo fuer {host_context.get('display_name', hostname)}"
                    body = (
                        "<html><body>"
                        f"<p>Test fuer Host Alert Abo.</p>"
                        f"<p>User: <strong>{html.escape(username)}</strong></p>"
                        f"<p>Host: <strong>{html.escape(str(host_context.get('display_name', hostname)))}</strong> ({html.escape(hostname)})</p>"
                        f"<p>Zeit: {html.escape(format_mail_datetime())}</p>"
                        "</body></html>"
                    )
                    mail_ok, mail_details = send_microsoft_mail(
                        access_token,
                        recipient,
                        subject,
                        body,
                        content_type="HTML",
                    )
                    status = HTTPStatus.OK if mail_ok else HTTPStatus.BAD_REQUEST
                    self._send_json(status, {"status": "sent" if mail_ok else "failed", "channel": "mail", "details": mail_details})
                    return

                alarm_settings = get_alarm_settings(conn)
                bot_token = str(alarm_settings.get("telegram_bot_token", "") or "").strip()
                if not alarm_settings.get("telegram_enabled") or not bot_token:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "telegram global not configured"})
                    return
                chat_id = str(user_settings.get("alert_telegram_chat_id", "") or "").strip()
                if not chat_id:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "personal telegram chat id missing"})
                    return

                telegram_ok, telegram_details = telegram_send_to_chat(
                    bot_token,
                    chat_id,
                    (
                        f"{_mdv2('[TEST]')} Host Alert Abo\n"
                        f"👤 *{_mdv2(username)}*\n"
                    ) + build_telegram_alert_text(
                        "opened",
                        hostname,
                        "/hana/data",
                        "critical",
                        min(100.0, float(alarm_settings.get("critical_threshold_percent", 90.0) or 90.0) + 2.0),
                        display_name=str(host_context.get("display_name", "") or ""),
                    ),
                    image_path=_ALERT_ICON_PATHS.get("opened"),
                )
                status = HTTPStatus.OK if telegram_ok else HTTPStatus.BAD_REQUEST
                self._send_json(status, {"status": "sent" if telegram_ok else "failed", "channel": "telegram", "details": telegram_details})
                return

        if path == "/api/v1/oauth-settings":
            if not self._require_admin_session():
                return
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "empty body"})
                return
            raw_body = self.rfile.read(content_length)
            try:
                payload = json.loads(raw_body)
            except json.JSONDecodeError:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid json"})
                return
            with sqlite3.connect(DB_PATH) as conn:
                settings = save_oauth_settings(conn, payload)
                conn.commit()
            self._send_json(HTTPStatus.OK, oauth_settings_public_view(settings))
            return

        if path == "/api/v1/oauth/microsoft/disconnect":
            username = self._web_session_username()
            with sqlite3.connect(DB_PATH) as conn:
                delete_oauth_connection(conn, username, MICROSOFT_PROVIDER)
                conn.commit()
                payload = current_user_payload(conn, username)
            self._send_json(HTTPStatus.OK, payload)
            return

        if path in {"/api/v1/mail-test", "/api/v1/mail-test/trends", "/api/v1/mail-test/alerts"}:
            username = self._web_session_username()
            endpoint_mode = "generic"
            if path.endswith("/trends"):
                endpoint_mode = "trends"
            elif path.endswith("/alerts"):
                endpoint_mode = "alerts"

            with sqlite3.connect(DB_PATH) as conn:
                settings = get_web_user_settings(conn, username)
                recipient = str(settings.get("email_recipient", "") or "").strip()
                if not recipient:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "email recipient missing"})
                    return
                ok, access_token, details = ensure_microsoft_access_token(conn, username)
                if not ok:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": details or "oauth unavailable"})
                    return
                if endpoint_mode == "trends":
                    warnings = collect_critical_trends(conn, 72)
                    mail_ok, mail_details = send_microsoft_mail(
                        access_token,
                        recipient,
                        trend_digest_subject(warnings, datetime.now().astimezone().date().isoformat()) + " [TEST]",
                        trend_digest_html(username, warnings, 72),
                        content_type="HTML",
                    )
                elif endpoint_mode == "alerts":
                    alarm_settings = get_alarm_settings(conn)
                    warning_threshold = float(alarm_settings.get("warning_threshold_percent", 80.0) or 80.0)
                    critical_threshold = float(alarm_settings.get("critical_threshold_percent", 90.0) or 90.0)

                    sample_row = conn.execute(
                        "SELECT hostname, mountpoint, severity FROM alerts WHERE status = 'open' ORDER BY id DESC LIMIT 1"
                    ).fetchone()
                    if sample_row:
                        sample_hostname = str(sample_row[0] or "").strip() or "monitoring-testhost"
                        sample_mountpoint = str(sample_row[1] or "").strip() or "/hana/data"
                        sample_severity = str(sample_row[2] or "critical").strip().lower()
                    else:
                        host_row = conn.execute(
                            "SELECT hostname FROM reports ORDER BY id DESC LIMIT 1"
                        ).fetchone()
                        sample_hostname = str(host_row[0] or "").strip() if host_row else ""
                        if not sample_hostname:
                            sample_hostname = "monitoring-testhost"
                        sample_mountpoint = "/hana/data"
                        sample_severity = "critical"

                    if sample_severity not in {"warning", "critical"}:
                        sample_severity = "critical"

                    sample_used_percent = (critical_threshold + 1.0) if sample_severity == "critical" else (warning_threshold + 1.0)
                    sample_used_percent = max(0.0, min(100.0, sample_used_percent))

                    host_context = collect_host_mail_context(conn, sample_hostname)
                    sample_display_name = str(host_context.get("display_name", "") or "")
                    sample_primary_ip = str(host_context.get("primary_ip", "") or "")
                    sample_country_code = str(host_context.get("country_code", "") or "")
                    sample_os_family = str(host_context.get("os_family", "linux") or "linux")

                    graph_cid, graph_attachment = build_alert_usage_graph_attachment(
                        conn,
                        sample_hostname,
                        sample_mountpoint,
                        severity=sample_severity,
                        hours=24,
                    )
                    graph_attachments = [graph_attachment] if graph_attachment else []

                    extra_alert_recipients = parse_email_recipients(settings.get("alert_email_recipients", ""))
                    all_alert_recipients = parse_email_recipients(",".join([recipient] + extra_alert_recipients))
                    if not all_alert_recipients:
                        self._send_json(HTTPStatus.BAD_REQUEST, {"error": "no alert recipients configured"})
                        return

                    subject = alert_instant_mail_subject(
                        "opened",
                        sample_hostname,
                        sample_severity,
                        sample_display_name,
                    )
                    body = alert_instant_mail_html(
                        username,
                        "opened",
                        sample_hostname,
                        sample_mountpoint,
                        sample_severity,
                        sample_used_percent,
                        display_name=sample_display_name,
                        primary_ip=sample_primary_ip,
                        country_code=sample_country_code,
                        os_family=sample_os_family,
                        reported_at_utc=utc_now_iso(),
                        graph_cid=graph_cid or "",
                    )

                    mail_ok, mail_details = send_microsoft_mail_multi(
                        access_token,
                        all_alert_recipients,
                        subject,
                        body,
                        content_type="HTML",
                        attachments=graph_attachments,
                    )
                else:
                    mail_ok, mail_details = send_microsoft_mail(
                        access_token,
                        recipient,
                        "[TEST] Monitoring OAuth Mail",
                        (
                            "Monitoring OAuth Test\n"
                            f"Benutzer: {username}\n"
                            f"Zeit: {utc_now_iso()}\n"
                            "Wenn diese Mail ankommt, funktioniert Microsoft Graph OAuth."
                        ),
                    )
                conn.commit()
            self._send_json(
                HTTPStatus.OK if mail_ok else HTTPStatus.BAD_REQUEST,
                {
                    "status": "sent" if mail_ok else "failed",
                    "mode": endpoint_mode,
                    "details": mail_details,
                },
            )
            return

        if path == "/api/v1/web-users":
            current_admin = self._require_admin_session()
            if not current_admin:
                return
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "empty body"})
                return
            raw_body = self.rfile.read(content_length)
            try:
                payload = json.loads(raw_body)
            except json.JSONDecodeError:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid json"})
                return

            action = str(payload.get("action", "") or "").strip().lower()
            target_username = normalize_username(payload.get("username", ""))
            try:
                with sqlite3.connect(DB_PATH) as conn:
                    if action == "create":
                        create_web_user(
                            conn,
                            target_username,
                            str(payload.get("password", "") or ""),
                            is_admin=coerce_bool(payload.get("is_admin", False)),
                        )
                    elif action == "set-password":
                        update_web_user_password(conn, target_username, str(payload.get("password", "") or ""))
                    elif action == "update-flags":
                        if current_admin == target_username and coerce_bool(payload.get("is_disabled", False)):
                            raise ValueError("current admin cannot disable self")
                        update_web_user_flags(
                            conn,
                            target_username,
                            is_admin=coerce_bool(payload["is_admin"]) if "is_admin" in payload else None,
                            is_disabled=coerce_bool(payload["is_disabled"]) if "is_disabled" in payload else None,
                        )
                    elif action == "delete":
                        if current_admin == target_username:
                            raise ValueError("current admin cannot delete self")
                        delete_web_user(conn, target_username)
                    else:
                        self._send_json(HTTPStatus.BAD_REQUEST, {"error": "unsupported action"})
                        return
                    users = list_web_users(conn)
                    conn.commit()
            except ValueError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return

            self._send_json(HTTPStatus.OK, {"status": "ok", "users": users})
            return

        if path == "/api/v1/admin/user-alert-subscriptions":
            if not self._require_admin_session():
                return
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "empty body"})
                return
            raw_body = self.rfile.read(content_length)
            try:
                payload = json.loads(raw_body)
            except json.JSONDecodeError:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid json"})
                return

            target_username = normalize_username(payload.get("username", ""))
            if not target_username:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "username missing"})
                return
            subscriptions = payload.get("subscriptions", [])
            if not isinstance(subscriptions, list):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "subscriptions must be a list"})
                return

            try:
                with sqlite3.connect(DB_PATH) as conn:
                    saved = replace_web_user_alert_subscriptions(conn, target_username, subscriptions)
                    conn.commit()
                self._send_json(HTTPStatus.OK, {"status": "stored", "username": target_username, "subscriptions": saved})
            except ValueError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return

        if path == "/api/v1/alarm-test":
            with sqlite3.connect(DB_PATH) as conn:
                settings = get_alarm_settings(conn)

            critical_threshold = float(settings.get("critical_threshold_percent", 90.0) or 90.0)
            sample_used_percent = min(100.0, critical_threshold + 2.0)
            sample_text = build_telegram_alert_text(
                "opened",
                "monitoring-testhost",
                "/hana/data",
                "critical",
                sample_used_percent,
                display_name="Monitoring Testhost",
            )

            ok, details = telegram_send(
                settings,
                sample_text,
                image_path=_ALERT_ICON_PATHS.get("opened"),
            )
            status = HTTPStatus.OK if ok else HTTPStatus.BAD_REQUEST
            self._send_json(
                status,
                {
                    "status": "sent" if ok else "failed",
                    "details": details,
                },
            )
            return

        if path == "/api/v1/host-settings":
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "empty body"})
                return

            raw_body = self.rfile.read(content_length)
            try:
                payload = json.loads(raw_body)
            except json.JSONDecodeError:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid json"})
                return

            hostname = str(payload.get("hostname", "")).strip()
            has_display_name = "display_name_override" in payload
            has_country_code = "country_code_override" in payload
            has_is_favorite = "is_favorite" in payload
            has_is_hidden = "is_hidden" in payload

            if not hostname:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "hostname missing"})
                return

            if not (has_display_name or has_country_code or has_is_favorite or has_is_hidden):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "no host setting provided"})
                return

            with sqlite3.connect(DB_PATH) as conn:
                current = get_host_settings(conn, hostname)
                display_name_override = current["display_name_override"]
                country_code_override = current["country_code_override"]
                is_favorite = bool(current["is_favorite"])
                is_hidden = bool(current["is_hidden"])

                if has_display_name:
                    display_name_override = str(payload.get("display_name_override", "")).strip()
                if has_country_code:
                    raw_country_code = str(payload.get("country_code_override", "") or "").strip()
                    if raw_country_code and not normalize_country_code(raw_country_code):
                        self._send_json(HTTPStatus.BAD_REQUEST, {"error": "country_code_override must be empty or a 2-letter code"})
                        return
                    country_code_override = normalize_country_code(raw_country_code)
                if has_is_favorite:
                    is_favorite = parse_bool(payload.get("is_favorite"), is_favorite)
                if has_is_hidden:
                    is_hidden = parse_bool(payload.get("is_hidden"), is_hidden)

                if display_name_override or country_code_override or is_favorite or is_hidden:
                    conn.execute(
                        """
                        INSERT INTO host_settings (hostname, display_name_override, country_code_override, is_favorite, is_hidden, updated_at_utc)
                        VALUES (?, ?, ?, ?, ?, ?)
                        ON CONFLICT(hostname) DO UPDATE SET
                          display_name_override = excluded.display_name_override,
                          country_code_override = excluded.country_code_override,
                          is_favorite = excluded.is_favorite,
                          is_hidden = excluded.is_hidden,
                          updated_at_utc = excluded.updated_at_utc
                        """,
                        (
                            hostname,
                            display_name_override,
                            country_code_override,
                            1 if is_favorite else 0,
                            1 if is_hidden else 0,
                            utc_now_iso(),
                        ),
                    )
                else:
                    conn.execute("DELETE FROM host_settings WHERE hostname = ?", (hostname,))

                if is_hidden:
                    resolve_open_alerts_for_host(conn, hostname, None)

                conn.commit()

            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "stored",
                    "hostname": hostname,
                    "display_name_override": display_name_override,
                    "country_code_override": country_code_override,
                    "is_favorite": is_favorite,
                    "is_hidden": is_hidden,
                },
            )
            return

        if path == "/api/v1/filesystem-visibility":
            username = self._require_web_session()
            if not username:
                return

            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "empty body"})
                return

            raw_body = self.rfile.read(content_length)
            try:
                payload = json.loads(raw_body)
            except json.JSONDecodeError:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid json"})
                return

            hostname = str(payload.get("hostname", "") or "").strip()
            section = normalize_filesystem_visibility_section(payload.get("section", ""))
            hidden_mountpoints = payload.get("hidden_mountpoints", [])

            if not hostname:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "hostname missing"})
                return
            if not section:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "section must be fs-focus or large-files"})
                return
            if not isinstance(hidden_mountpoints, list):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "hidden_mountpoints must be a list"})
                return

            try:
                with sqlite3.connect(DB_PATH) as conn:
                    stored = replace_user_hidden_filesystems(conn, username, hostname, section, hidden_mountpoints)
                    conn.commit()
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "status": "stored",
                        "username": username,
                        "hostname": hostname,
                        "section": section,
                        "hidden_mountpoints": stored,
                    },
                )
            except ValueError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return

        if path == "/api/v1/host-delete":
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "empty body"})
                return

            raw_body = self.rfile.read(content_length)
            try:
                payload = json.loads(raw_body)
            except json.JSONDecodeError:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid json"})
                return

            hostname = str(payload.get("hostname", "")).strip()
            if not hostname:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "hostname missing"})
                return

            with sqlite3.connect(DB_PATH) as conn:
                deleted = delete_host_card_data(conn, hostname)
                conn.commit()

            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "deleted",
                    "hostname": hostname,
                    "deleted": deleted,
                    "deleted_total": int(sum(deleted.values())),
                },
            )
            return

        if path == "/api/v1/alert-mute":
            content_length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(content_length) if content_length > 0 else b"{}"
            try:
                payload = json.loads(raw_body)
            except json.JSONDecodeError:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid json"})
                return
            hostname = str(payload.get("hostname", "")).strip()
            mountpoint = str(payload.get("mountpoint", "")).strip()
            if not hostname or not mountpoint:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "hostname and mountpoint required"})
                return
            muted_by = self._web_session_username() or "webclient"
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO muted_alert_rules (hostname, mountpoint, muted_by, muted_at_utc) VALUES (?, ?, ?, ?)",
                    (hostname, mountpoint, muted_by, utc_now_iso()),
                )
                conn.commit()
            self._send_json(HTTPStatus.OK, {"ok": True, "hostname": hostname, "mountpoint": mountpoint})
            return

        if path == "/api/v1/alert-unmute":
            content_length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(content_length) if content_length > 0 else b"{}"
            try:
                payload = json.loads(raw_body)
            except json.JSONDecodeError:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid json"})
                return
            hostname = str(payload.get("hostname", "")).strip()
            mountpoint = str(payload.get("mountpoint", "")).strip()
            if not hostname or not mountpoint:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "hostname and mountpoint required"})
                return
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute(
                    "DELETE FROM muted_alert_rules WHERE hostname = ? AND mountpoint = ?",
                    (hostname, mountpoint),
                )
                conn.commit()
            self._send_json(HTTPStatus.OK, {"ok": True, "hostname": hostname, "mountpoint": mountpoint})
            return

        if path == "/api/v1/alert-ack":
            content_length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(content_length) if content_length > 0 else b"{}"
            try:
                payload = json.loads(raw_body)
            except json.JSONDecodeError:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid json"})
                return

            hostname = str(payload.get("hostname", "")).strip()
            mountpoint = str(payload.get("mountpoint", "")).strip()
            note = str(payload.get("ack_note", "") or "").strip()
            if not hostname or not mountpoint:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "hostname and mountpoint required"})
                return
            if len(note) > 500:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "ack_note too long (max 500)"})
                return

            ack_by = self._web_session_username() or "webclient"
            ack_at_utc = utc_now_iso()

            with sqlite3.connect(DB_PATH) as conn:
                target = conn.execute(
                    """
                    SELECT id
                    FROM alerts
                    WHERE hostname = ? AND mountpoint = ? AND status = 'open'
                    ORDER BY id DESC
                    LIMIT 1
                    """,
                    (hostname, mountpoint),
                ).fetchone()
                if not target:
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": "open alert not found"})
                    return

                conn.execute(
                    """
                    UPDATE alerts
                    SET ack_note = ?, ack_by = ?, ack_at_utc = ?
                    WHERE id = ?
                    """,
                    (note, ack_by, ack_at_utc, int(target[0])),
                )
                conn.commit()

            self._send_json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "hostname": hostname,
                    "mountpoint": mountpoint,
                    "ack_note": note,
                    "ack_by": ack_by,
                    "ack_at_utc": ack_at_utc,
                },
            )
            return

        if path == "/api/v1/alert-unack":
            content_length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(content_length) if content_length > 0 else b"{}"
            try:
                payload = json.loads(raw_body)
            except json.JSONDecodeError:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid json"})
                return

            hostname = str(payload.get("hostname", "")).strip()
            mountpoint = str(payload.get("mountpoint", "")).strip()
            if not hostname or not mountpoint:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "hostname and mountpoint required"})
                return

            with sqlite3.connect(DB_PATH) as conn:
                target = conn.execute(
                    """
                    SELECT id
                    FROM alerts
                    WHERE hostname = ? AND mountpoint = ? AND status = 'open'
                    ORDER BY id DESC
                    LIMIT 1
                    """,
                    (hostname, mountpoint),
                ).fetchone()
                if not target:
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": "open alert not found"})
                    return

                conn.execute(
                    """
                    UPDATE alerts
                    SET ack_note = NULL, ack_by = NULL, ack_at_utc = NULL
                    WHERE id = ?
                    """,
                    (int(target[0]),),
                )
                conn.commit()

            self._send_json(
                HTTPStatus.OK,
                {"ok": True, "hostname": hostname, "mountpoint": mountpoint},
            )
            return

        if path == "/api/v1/restore/database":
            if not self._require_admin_session():
                return
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "no data received"})
                return
            max_restore_bytes = 512 * 1024 * 1024  # 512 MB hard cap
            if content_length > max_restore_bytes:
                self._send_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "file too large (max 512 MB)"})
                return
            data = self.rfile.read(content_length)
            try:
                restore_sqlite_from_bytes(DB_PATH, data)
            except ValueError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return
            except Exception:
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "restore failed – file may be corrupt"})
                return
            # Re-run migrations so the restored DB is compatible with current schema
            try:
                with sqlite3.connect(DB_PATH) as conn:
                    init_db(conn)
            except Exception:
                pass
            self._send_json(HTTPStatus.OK, {"ok": True, "restored_bytes": len(data)})
            return

        if path == "/api/v1/agent-command":
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "empty body"})
                return

            raw_body = self.rfile.read(content_length)
            try:
                payload = json.loads(raw_body)
            except json.JSONDecodeError:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid json"})
                return

            hostname = str(payload.get("hostname", "")).strip()
            command_type = normalize_command_type(payload.get("command_type"))
            if not hostname:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "hostname missing"})
                return
            if not command_type:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "unsupported command_type"})
                return

            try:
                ttl_minutes = int(payload.get("ttl_minutes", 240))
            except (TypeError, ValueError):
                ttl_minutes = 240

            created_by = self._web_session_username() or "webclient"
            command_payload = payload.get("command_payload", {})
            if not isinstance(command_payload, dict):
                command_payload = {}
            if command_type == "set-api-key":
                api_key_value = str(command_payload.get("api_key", "")).strip()
                if not api_key_value:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "command_payload.api_key missing"})
                    return
                command_payload = {"api_key": api_key_value}

            with sqlite3.connect(DB_PATH) as conn:
                expire_old_agent_commands(conn)
                command_id, created = queue_agent_command_once(
                    conn,
                    created_by=created_by,
                    hostname=hostname,
                    command_type=command_type,
                    command_payload=command_payload,
                    ttl_minutes=ttl_minutes,
                )
                conn.commit()

            self._send_json(
                HTTPStatus.CREATED if created else HTTPStatus.OK,
                {
                    "status": "queued" if created else "already_queued",
                    "command_id": command_id,
                    "hostname": hostname,
                    "command_type": command_type,
                },
            )
            return

        if path == "/api/v1/agent-command-bulk":
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "empty body"})
                return

            raw_body = self.rfile.read(content_length)
            try:
                payload = json.loads(raw_body)
            except json.JSONDecodeError:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid json"})
                return

            command_type = normalize_command_type(payload.get("command_type"))
            if not command_type:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "unsupported command_type"})
                return

            try:
                ttl_minutes = int(payload.get("ttl_minutes", 240))
            except (TypeError, ValueError):
                ttl_minutes = 240

            command_payload = payload.get("command_payload", {})
            if not isinstance(command_payload, dict):
                command_payload = {}
            if command_type == "set-api-key":
                api_key_value = str(command_payload.get("api_key", "")).strip()
                if not api_key_value:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "command_payload.api_key missing"})
                    return
                command_payload = {"api_key": api_key_value}

            created_by = self._web_session_username() or "webclient"
            queued_count = 0
            already_queued_count = 0

            with sqlite3.connect(DB_PATH) as conn:
                expire_old_agent_commands(conn)
                hostnames = get_known_hostnames(conn)
                if not hostnames:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "no hosts available"})
                    return

                for hostname in hostnames:
                    _command_id, created = queue_agent_command_once(
                        conn,
                        created_by=created_by,
                        hostname=hostname,
                        command_type=command_type,
                        command_payload=command_payload,
                        ttl_minutes=ttl_minutes,
                    )
                    if created:
                        queued_count += 1
                    else:
                        already_queued_count += 1
                conn.commit()

            self._send_json(
                HTTPStatus.CREATED if queued_count > 0 else HTTPStatus.OK,
                {
                    "status": "queued" if queued_count > 0 else "already_queued",
                    "command_type": command_type,
                    "total_hosts": len(hostnames),
                    "queued_count": queued_count,
                    "already_queued_count": already_queued_count,
                },
            )
            return

        if path == "/api/v1/agent-command-result":
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "empty body"})
                return

            raw_body = self.rfile.read(content_length)
            try:
                payload = json.loads(raw_body)
            except json.JSONDecodeError:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid json"})
                return

            hostname = str(payload.get("hostname", "")).strip()
            if self._unauthorized_if_needed(hostname):
                return

            try:
                command_id = int(payload.get("command_id", 0))
            except (TypeError, ValueError):
                command_id = 0
            status = str(payload.get("status", "")).strip().lower()
            if status not in {"completed", "failed"}:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "status must be completed or failed"})
                return
            if not hostname or command_id <= 0:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "hostname/command_id missing"})
                return

            result_payload = payload.get("result", {})
            if not isinstance(result_payload, dict):
                result_payload = {"message": str(result_payload)}

            with sqlite3.connect(DB_PATH) as conn:
                row = conn.execute(
                    "SELECT id, status, command_type FROM agent_commands WHERE id = ? AND hostname = ?",
                    (command_id, hostname),
                ).fetchone()
                if not row:
                    self._send_json(HTTPStatus.NOT_FOUND, {"error": "command not found"})
                    return
                if str(row[1] or "") != "pending":
                    self._send_json(HTTPStatus.OK, {"status": "ignored", "reason": "already handled"})
                    return

                conn.execute(
                    """
                    UPDATE agent_commands
                    SET status = ?, executed_at_utc = ?, result_json = ?,
                        command_payload_json = CASE WHEN command_type = 'set-api-key' THEN '{}' ELSE command_payload_json END
                    WHERE id = ?
                    """,
                    (
                        status,
                        utc_now_iso(),
                        json.dumps(result_payload, separators=(",", ":")),
                        command_id,
                    ),
                )
                conn.commit()

            self._send_json(HTTPStatus.OK, {"status": "stored", "command_id": command_id})
            return

        if path != "/api/v1/agent-report":
            self.send_error(HTTPStatus.NOT_FOUND, "Not found")
            return

        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length <= 0:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "empty body"})
            return

        raw_body = self.rfile.read(content_length)
        try:
            payload = json.loads(raw_body)
        except json.JSONDecodeError:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid json"})
            return

        hostname = str(payload.get("hostname", "")).strip()
        if self._unauthorized_if_needed(hostname):
            return

        payload["agent_api_key"] = build_agent_api_key_status(
            payload,
            str(self.headers.get("X-Api-Key", "") or ""),
            hostname,
        )

        filesystems = payload.get("filesystems", [])

        if not hostname:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "hostname missing"})
            return

        if not isinstance(filesystems, list):
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "filesystems must be an array"})
            return

        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.execute(
                """
                INSERT INTO reports (received_at_utc, agent_id, hostname, primary_ip, payload_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    utc_now_iso(),
                    str(payload.get("agent_id", "")),
                    hostname,
                    str(payload.get("primary_ip", "")),
                    json.dumps(payload, separators=(",", ":")),
                ),
            )
            report_id = int(cursor.lastrowid)
            prune_reports_for_host(conn, hostname, MAX_REPORTS_PER_HOST)
            alarm_settings = get_alarm_settings(conn)
            host_settings = get_host_settings(conn, hostname)
            if bool(host_settings.get("is_hidden", False)):
                resolve_open_alerts_for_host(conn, hostname, report_id)
            else:
                update_alerts_for_report(conn, hostname, report_id, filesystems, alarm_settings)
                update_cpu_alerts_for_report(conn, hostname, report_id, payload, alarm_settings)
                update_ram_alerts_for_report(conn, hostname, report_id, payload, alarm_settings)
            maybe_send_alert_reminders(conn)
            maybe_send_scheduled_user_mails(conn)
            conn.commit()

        self._send_json(HTTPStatus.CREATED, {"status": "stored"})


def main() -> None:
    parser = argparse.ArgumentParser(description="Simple monitoring receiver")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind")
    parser.add_argument("--port", default=8080, type=int, help="Port to bind")
    args = parser.parse_args()

    init_db()
    server = ThreadingHTTPServer((args.host, args.port), MonitoringHandler)
    print(f"Monitoring receiver running on http://{args.host}:{args.port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
