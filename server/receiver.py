#!/usr/bin/env python3
import argparse
import base64
import csv
import fnmatch
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import socket
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
SAP_B1_VERSION_MAP_PATH = DATA_DIR / "sap_b1_version_map.json"
SAP_LICENSE_TYPE_MAP_PATH = DATA_DIR / "sap_license_type_map.json"
BACKUP_TEMP_DIR = DATA_DIR / "backup_jobs"
AUTO_BACKUP_DIR = DATA_DIR / "auto_db_backups"
APP_LOGO_PATH = STATIC_DIR / "icons" / "logo.png"
ANG_LOGO_PATH = STATIC_DIR / "icons" / "ANG.png"
SAP_LOGO_PATH = STATIC_DIR / "icons" / "sap.png"
LINUX_LOGO_PATH = STATIC_DIR / "icons" / "linux.png"
WINDOWS_LOGO_PATH = STATIC_DIR / "icons" / "windows.png"
BUILD_VERSION_PATH = BASE_DIR.parent / "BUILD_VERSION"
AGENT_VERSION_PATH = BASE_DIR.parent / "AGENT_VERSION"
OPENAPI_SPEC_PATH = BASE_DIR.parent / "openapi.yaml"
UPDATES_DIR = BASE_DIR.parent / "updates"
API_KEY = os.getenv("MONITORING_API_KEY", "")
API_KEY_GRACE_ALLOW_KNOWN_HOSTS = os.getenv("MONITORING_API_KEY_GRACE_ALLOW_KNOWN_HOSTS", "1").strip().lower() in {"1", "true", "yes", "on"}
REPORT_RETENTION_DAYS = max(1, int(os.getenv("MONITORING_REPORT_RETENTION_DAYS", "42")))
MAX_REPORTS_PER_HOST = max(0, int(os.getenv("MONITORING_MAX_REPORTS_PER_HOST", "0")))
WARNING_THRESHOLD_PERCENT = float(os.getenv("MONITORING_WARNING_THRESHOLD", "80"))
CRITICAL_THRESHOLD_PERCENT = float(os.getenv("MONITORING_CRITICAL_THRESHOLD", "90"))
TELEGRAM_ENABLED_DEFAULT = os.getenv("MONITORING_TELEGRAM_ENABLED", "0").strip().lower() in {"1", "true", "yes", "on"}
TELEGRAM_BOT_TOKEN_DEFAULT = os.getenv("MONITORING_TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID_DEFAULT = os.getenv("MONITORING_TELEGRAM_CHAT_ID", "")
WEB_DEFAULT_USERNAME = os.getenv("MONITORING_WEB_USER", "admin")
WEB_DEFAULT_PASSWORD = os.getenv("MONITORING_WEB_PASSWORD", "ChangeMe!2026")
WEB_SESSION_INACTIVITY_MINUTES = max(5, int(os.getenv("MONITORING_WEB_SESSION_INACTIVITY_MINUTES", "30")))
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
DB_MAINTENANCE_INTERVAL_HOURS = max(1, min(24, int(os.getenv("MONITORING_DB_MAINT_INTERVAL_HOURS", "2") or "2")))
AUTO_BACKUP_DEFAULT_ENABLED = os.getenv("MONITORING_AUTO_BACKUP_ENABLED", "1").strip().lower() in {"1", "true", "yes", "on"}
DEFAULT_SAP_LICENSE_TYPE_MAP_ENTRIES = [
    {"match_text": "CRM-LTD", "display_name": "Limited CRM"},
    {"match_text": "LOGISTICS-LTD", "display_name": "Logistics CRM"},
    {"match_text": "PROFESSIONAL", "display_name": "Professional"},
    {"match_text": "FINANCE-LTD", "display_name": "Limited Finance"},
]
AUTO_BACKUP_DEFAULT_INTERVAL_HOURS = max(1, min(168, int(os.getenv("MONITORING_AUTO_BACKUP_INTERVAL_HOURS", "12") or "12")))
AUTO_BACKUP_DEFAULT_RETENTION_DAYS = max(1, min(365, int(os.getenv("MONITORING_AUTO_BACKUP_RETENTION_DAYS", "7") or "7")))
TELEGRAM_ACTION_BASE_URL = os.getenv(
    "MONITORING_TELEGRAM_ACTION_BASE_URL",
    os.getenv("MONITORING_PUBLIC_BASE_URL", ""),
).strip().rstrip("/")
TELEGRAM_ACTION_SIGNING_SECRET = os.getenv("MONITORING_TELEGRAM_ACTION_SIGNING_SECRET", "").strip()
TELEGRAM_ACTION_TTL_MINUTES = max(10, min(10080, int(os.getenv("MONITORING_TELEGRAM_ACTION_TTL_MINUTES", "1440") or "1440")))
try:
    SCHEDULE_TIMEZONE = ZoneInfo(SCHEDULE_TIMEZONE_NAME)
except ZoneInfoNotFoundError:
    SCHEDULE_TIMEZONE = datetime.now().astimezone().tzinfo
    SCHEDULE_TIMEZONE_NAME = str(SCHEDULE_TIMEZONE) if SCHEDULE_TIMEZONE else "local"


_backup_jobs_lock = threading.Lock()
_backup_jobs: dict[str, dict[str, str]] = {}
_auto_backup_lock = threading.Lock()


def parse_int(query: dict, key: str, default: int, min_value: int, max_value: int) -> int:
    raw = query.get(key, [str(default)])[0]
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(min_value, min(value, max_value))


def parse_positive_int(value: object, default: int = 0, max_value: int = 365) -> int:
    try:
        parsed = int(str(value or "").strip())
    except (TypeError, ValueError):
        return default
    if parsed <= 0:
        return default
    return min(parsed, max_value)


def reports_host_key_sql(alias: str = "") -> str:
    prefix = f"{alias}." if alias else ""
    # No implicit hostname merge: missing host_uid gets a unique legacy key per report row.
    return (
        f"CASE WHEN COALESCE({prefix}host_uid, '') <> '' "
        f"THEN {prefix}host_uid "
        f"ELSE '__legacy_report__:' || CAST({prefix}id AS TEXT) END"
    )


def init_db() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                received_at_utc TEXT NOT NULL,
                agent_id TEXT,
                hostname TEXT,
                host_uid TEXT,
                primary_ip TEXT,
                payload_json TEXT NOT NULL
            )
            """
        )
        existing_reports_columns = {
            str(row[1])
            for row in conn.execute("PRAGMA table_info(reports)").fetchall()
        }
        if "host_uid" not in existing_reports_columns:
            conn.execute("ALTER TABLE reports ADD COLUMN host_uid TEXT")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_reports_host_uid_id ON reports(host_uid, id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_reports_hostname_id ON reports(hostname, id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_reports_received_utc_id ON reports(received_at_utc, id)")
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_reports_host_key_id
            ON reports(COALESCE(NULLIF(host_uid, ''), hostname), id)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_reports_host_key_received
            ON reports(COALESCE(NULLIF(host_uid, ''), hostname), received_at_utc)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_reports_host_agent_ip_uid
            ON reports(hostname, agent_id, primary_ip, host_uid, id)
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
            CREATE INDEX IF NOT EXISTS idx_alerts_host_status_severity
            ON alerts(hostname, status, severity, mountpoint)
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS customers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                customer_name TEXT NOT NULL,
                maringo_project_number TEXT NOT NULL DEFAULT '',
                created_at_utc TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_customers_name_ci
            ON customers (LOWER(customer_name))
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
                customer_alert_emails TEXT NOT NULL DEFAULT '',
                customer_alert_mountpoints TEXT NOT NULL DEFAULT '',
                customer_alert_min_severity TEXT NOT NULL DEFAULT 'critical',
                customer_id INTEGER,
                environment_type TEXT NOT NULL DEFAULT '',
                updated_at_utc TEXT NOT NULL,
                FOREIGN KEY(customer_id) REFERENCES customers(id) ON DELETE SET NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS host_uid_settings (
                host_uid TEXT PRIMARY KEY,
                display_name_override TEXT,
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
        if "customer_alert_emails" not in existing_host_columns:
            conn.execute("ALTER TABLE host_settings ADD COLUMN customer_alert_emails TEXT NOT NULL DEFAULT ''")
        if "customer_alert_mountpoints" not in existing_host_columns:
            conn.execute("ALTER TABLE host_settings ADD COLUMN customer_alert_mountpoints TEXT NOT NULL DEFAULT ''")
        if "customer_alert_min_severity" not in existing_host_columns:
            conn.execute("ALTER TABLE host_settings ADD COLUMN customer_alert_min_severity TEXT NOT NULL DEFAULT 'critical'")
        if "customer_id" not in existing_host_columns:
            conn.execute("ALTER TABLE host_settings ADD COLUMN customer_id INTEGER")
        if "environment_type" not in existing_host_columns:
            conn.execute("ALTER TABLE host_settings ADD COLUMN environment_type TEXT NOT NULL DEFAULT ''")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alarm_settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                warning_threshold_percent REAL NOT NULL,
                critical_threshold_percent REAL NOT NULL,
                warning_consecutive_hits INTEGER NOT NULL,
                warning_window_minutes INTEGER NOT NULL,
                critical_trigger_immediate INTEGER NOT NULL,
                telegram_enabled INTEGER NOT NULL,
                telegram_bot_token TEXT NOT NULL,
                telegram_chat_id TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL,
                alert_reminder_interval_hours INTEGER NOT NULL DEFAULT 0,
                alert_telegram_reminder_interval_hours INTEGER NOT NULL DEFAULT 0,
                cpu_warning_threshold_percent REAL NOT NULL DEFAULT 80,
                cpu_critical_threshold_percent REAL NOT NULL DEFAULT 95,
                cpu_alert_window_reports INTEGER NOT NULL DEFAULT 4,
                ram_warning_threshold_percent REAL NOT NULL DEFAULT 85,
                ram_critical_threshold_percent REAL NOT NULL DEFAULT 95,
                ram_alert_window_reports INTEGER NOT NULL DEFAULT 4,
                inactive_host_alert_enabled INTEGER NOT NULL DEFAULT 0,
                inactive_host_alert_hours INTEGER NOT NULL DEFAULT 3,
                ai_troubleshoot_enabled INTEGER NOT NULL DEFAULT 1,
                openai_api_key TEXT NOT NULL DEFAULT '',
                openai_model TEXT NOT NULL DEFAULT 'gpt-4o-mini',
                openai_timeout_sec INTEGER NOT NULL DEFAULT 12,
                openai_max_tokens INTEGER NOT NULL DEFAULT 1200,
                ai_troubleshoot_cache_ttl_sec INTEGER NOT NULL DEFAULT 600
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
        if "alert_reminder_interval_hours" not in existing_alarm_columns:
            conn.execute("ALTER TABLE alarm_settings ADD COLUMN alert_reminder_interval_hours INTEGER NOT NULL DEFAULT 0")
        if "alert_telegram_reminder_interval_hours" not in existing_alarm_columns:
            conn.execute("ALTER TABLE alarm_settings ADD COLUMN alert_telegram_reminder_interval_hours INTEGER NOT NULL DEFAULT 0")
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
        if "inactive_host_alert_enabled" not in existing_alarm_columns:
            conn.execute("ALTER TABLE alarm_settings ADD COLUMN inactive_host_alert_enabled INTEGER NOT NULL DEFAULT 0")
        if "inactive_host_alert_hours" not in existing_alarm_columns:
            conn.execute("ALTER TABLE alarm_settings ADD COLUMN inactive_host_alert_hours INTEGER NOT NULL DEFAULT 3")
        if "ai_troubleshoot_enabled" not in existing_alarm_columns:
            conn.execute("ALTER TABLE alarm_settings ADD COLUMN ai_troubleshoot_enabled INTEGER NOT NULL DEFAULT 1")
        if "openai_api_key" not in existing_alarm_columns:
            conn.execute("ALTER TABLE alarm_settings ADD COLUMN openai_api_key TEXT NOT NULL DEFAULT ''")
        if "openai_model" not in existing_alarm_columns:
            conn.execute("ALTER TABLE alarm_settings ADD COLUMN openai_model TEXT NOT NULL DEFAULT 'gpt-4o-mini'")
        if "openai_timeout_sec" not in existing_alarm_columns:
            conn.execute("ALTER TABLE alarm_settings ADD COLUMN openai_timeout_sec INTEGER NOT NULL DEFAULT 12")
        if "openai_max_tokens" not in existing_alarm_columns:
            conn.execute("ALTER TABLE alarm_settings ADD COLUMN openai_max_tokens INTEGER NOT NULL DEFAULT 1200")
        if "ai_troubleshoot_cache_ttl_sec" not in existing_alarm_columns:
            conn.execute("ALTER TABLE alarm_settings ADD COLUMN ai_troubleshoot_cache_ttl_sec INTEGER NOT NULL DEFAULT 600")

        existing_alert_columns = {
            str(row[1])
            for row in conn.execute("PRAGMA table_info(alerts)").fetchall()
        }
        if "ack_note" not in existing_alert_columns:
            conn.execute("ALTER TABLE alerts ADD COLUMN ack_note TEXT")
        if "ack_by" not in existing_alert_columns:
            conn.execute("ALTER TABLE alerts ADD COLUMN ack_by TEXT")
        if "ack_at_utc" not in existing_alert_columns:
            conn.execute("ALTER TABLE alerts ADD COLUMN ack_at_utc TEXT")
        if "closed_at_utc" not in existing_alert_columns:
            conn.execute("ALTER TABLE alerts ADD COLUMN closed_at_utc TEXT")
        if "closed_by" not in existing_alert_columns:
            conn.execute("ALTER TABLE alerts ADD COLUMN closed_by TEXT")
        if "last_reminder_sent_utc" not in existing_alert_columns:
            conn.execute("ALTER TABLE alerts ADD COLUMN last_reminder_sent_utc TEXT")
        if "last_telegram_reminder_sent_utc" not in existing_alert_columns:
            conn.execute("ALTER TABLE alerts ADD COLUMN last_telegram_reminder_sent_utc TEXT")

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
            CREATE TABLE IF NOT EXISTS inactive_host_notification_state (
                hostname TEXT PRIMARY KEY,
                last_report_time_utc TEXT NOT NULL DEFAULT '',
                last_mail_notified_report_time_utc TEXT NOT NULL DEFAULT '',
                last_telegram_notified_report_time_utc TEXT NOT NULL DEFAULT '',
                updated_at_utc TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS host_config_snapshot (
                hostname TEXT PRIMARY KEY,
                os_release TEXT NOT NULL DEFAULT '-',
                kernel_release TEXT NOT NULL DEFAULT '-',
                cpu_cores TEXT NOT NULL DEFAULT '-',
                cpu_model_name TEXT NOT NULL DEFAULT '-',
                ram_gb TEXT NOT NULL DEFAULT '-',
                sap_release TEXT NOT NULL DEFAULT '-',
                hana_release TEXT NOT NULL DEFAULT '-',
                hana_sid TEXT NOT NULL DEFAULT '-',
                sql_release TEXT NOT NULL DEFAULT '-',
                updated_at_utc TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS changelog_rebuild_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                completed_at_utc TEXT NOT NULL,
                days INTEGER NOT NULL,
                reports_scanned INTEGER NOT NULL DEFAULT 0,
                inserted_host_config_changes INTEGER NOT NULL DEFAULT 0,
                inserted_database_lifecycle_events INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        existing_host_config_snapshot_columns = {
            str(row[1])
            for row in conn.execute("PRAGMA table_info(host_config_snapshot)").fetchall()
        }
        if "kernel_release" not in existing_host_config_snapshot_columns:
            conn.execute("ALTER TABLE host_config_snapshot ADD COLUMN kernel_release TEXT NOT NULL DEFAULT '-'")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS host_config_changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                detected_at_utc TEXT NOT NULL,
                hostname TEXT NOT NULL,
                field_key TEXT NOT NULL,
                old_value TEXT NOT NULL,
                new_value TEXT NOT NULL,
                report_id INTEGER,
                source TEXT NOT NULL DEFAULT 'agent-report'
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_host_config_changes_time
            ON host_config_changes(detected_at_utc DESC)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_host_config_changes_host_time
            ON host_config_changes(hostname, detected_at_utc DESC)
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS web_users (
                username TEXT PRIMARY KEY,
                display_name TEXT NOT NULL DEFAULT '',
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
        if "display_name" not in existing_web_user_columns:
            conn.execute("ALTER TABLE web_users ADD COLUMN display_name TEXT NOT NULL DEFAULT ''")
        if "created_at_utc" not in existing_web_user_columns:
            conn.execute("ALTER TABLE web_users ADD COLUMN created_at_utc TEXT NOT NULL DEFAULT ''")
        if "user_type" not in existing_web_user_columns:
            conn.execute("ALTER TABLE web_users ADD COLUMN user_type TEXT NOT NULL DEFAULT 'default'")
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
            CREATE TABLE IF NOT EXISTS web_login_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                logged_at_utc TEXT NOT NULL,
                username TEXT NOT NULL,
                display_name_snapshot TEXT NOT NULL DEFAULT '',
                source_ip TEXT NOT NULL DEFAULT '',
                auth_method TEXT NOT NULL DEFAULT 'password',
                user_agent TEXT NOT NULL DEFAULT ''
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_web_login_events_time
            ON web_login_events(logged_at_utc DESC)
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
                email_sender TEXT NOT NULL DEFAULT '',
                trend_email_enabled INTEGER NOT NULL DEFAULT 0,
                trend_email_time_hhmm TEXT NOT NULL DEFAULT '08:00',
                trend_email_last_sent_local_date TEXT NOT NULL DEFAULT '',
                alert_email_enabled INTEGER NOT NULL DEFAULT 0,
                alert_email_time_hhmm TEXT NOT NULL DEFAULT '08:05',
                alert_email_recipients TEXT NOT NULL DEFAULT '',
                alert_email_last_sent_local_date TEXT NOT NULL DEFAULT '',
                alert_instant_mail_enabled INTEGER NOT NULL DEFAULT 0,
                alert_instant_min_severity TEXT NOT NULL DEFAULT 'warning',
                backup_email_enabled INTEGER NOT NULL DEFAULT 0,
                backup_email_time_hhmm TEXT NOT NULL DEFAULT '08:15',
                backup_email_recipients TEXT NOT NULL DEFAULT '',
                updated_at_utc TEXT NOT NULL,
                FOREIGN KEY(username) REFERENCES web_users(username)
            )
            """
        )
        existing_web_user_settings_columns = {
            str(row[1])
            for row in conn.execute("PRAGMA table_info(web_user_settings)").fetchall()
        }
        if "trend_email_enabled" not in existing_web_user_settings_columns:
            conn.execute("ALTER TABLE web_user_settings ADD COLUMN trend_email_enabled INTEGER NOT NULL DEFAULT 0")
        if "email_sender" not in existing_web_user_settings_columns:
            conn.execute("ALTER TABLE web_user_settings ADD COLUMN email_sender TEXT NOT NULL DEFAULT ''")
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
        if "alert_warning_email_recipients" not in existing_web_user_settings_columns:
            conn.execute("ALTER TABLE web_user_settings ADD COLUMN alert_warning_email_recipients TEXT NOT NULL DEFAULT ''")
        if "alert_critical_email_recipients" not in existing_web_user_settings_columns:
            conn.execute("ALTER TABLE web_user_settings ADD COLUMN alert_critical_email_recipients TEXT NOT NULL DEFAULT ''")
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
        if "backup_email_enabled" not in existing_web_user_settings_columns:
            conn.execute("ALTER TABLE web_user_settings ADD COLUMN backup_email_enabled INTEGER NOT NULL DEFAULT 0")
        if "backup_email_time_hhmm" not in existing_web_user_settings_columns:
            conn.execute("ALTER TABLE web_user_settings ADD COLUMN backup_email_time_hhmm TEXT NOT NULL DEFAULT '08:15'")
        if "backup_email_recipients" not in existing_web_user_settings_columns:
            conn.execute("ALTER TABLE web_user_settings ADD COLUMN backup_email_recipients TEXT NOT NULL DEFAULT ''")
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
            CREATE TABLE IF NOT EXISTS user_preferences (
                username TEXT PRIMARY KEY,
                critical_trends_metrics TEXT NOT NULL DEFAULT 'filesystem',
                host_interest_mode TEXT NOT NULL DEFAULT 'all',
                host_interest_hosts TEXT NOT NULL DEFAULT '',
                updated_at_utc TEXT NOT NULL,
                FOREIGN KEY(username) REFERENCES web_users(username)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS filesystem_visibility (
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
            CREATE TABLE IF NOT EXISTS db_maintenance_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bucket_start_utc TEXT NOT NULL UNIQUE,
                computed_at_utc TEXT NOT NULL,
                retention_days INTEGER NOT NULL,
                reports_total INTEGER NOT NULL,
                hosts_with_reports INTEGER NOT NULL,
                hosts_total INTEGER NOT NULL,
                alerts_open INTEGER NOT NULL,
                avg_payload_bytes REAL NOT NULL,
                max_payload_bytes INTEGER NOT NULL,
                db_file_bytes INTEGER NOT NULL,
                wal_file_bytes INTEGER NOT NULL,
                shm_file_bytes INTEGER NOT NULL,
                total_file_bytes INTEGER NOT NULL,
                page_size INTEGER NOT NULL,
                page_count INTEGER NOT NULL,
                freelist_count INTEGER NOT NULL,
                used_pages INTEGER NOT NULL,
                free_ratio REAL NOT NULL,
                oldest_report_utc TEXT NOT NULL,
                newest_report_utc TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_db_maintenance_history_bucket
            ON db_maintenance_history(bucket_start_utc DESC)
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS backup_automation_settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                local_enabled INTEGER NOT NULL DEFAULT 1,
                local_interval_hours INTEGER NOT NULL DEFAULT 12,
                local_retention_days INTEGER NOT NULL DEFAULT 7,
                local_target_dir TEXT NOT NULL DEFAULT 'auto_db_backups',
                sftp_enabled INTEGER NOT NULL DEFAULT 0,
                sftp_host TEXT NOT NULL DEFAULT '',
                sftp_port INTEGER NOT NULL DEFAULT 22,
                sftp_username TEXT NOT NULL DEFAULT '',
                sftp_remote_path TEXT NOT NULL DEFAULT '',
                sftp_auth_mode TEXT NOT NULL DEFAULT 'key',
                sftp_key_path TEXT NOT NULL DEFAULT '',
                sftp_password TEXT NOT NULL DEFAULT '',
                updated_at_utc TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS backup_automation_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at_utc TEXT NOT NULL,
                finished_at_utc TEXT NOT NULL,
                trigger_source TEXT NOT NULL,
                status TEXT NOT NULL,
                backup_path TEXT NOT NULL DEFAULT '',
                backup_size_bytes INTEGER NOT NULL DEFAULT 0,
                uploaded_sftp INTEGER NOT NULL DEFAULT 0,
                error_message TEXT NOT NULL DEFAULT ''
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_backup_automation_runs_time
            ON backup_automation_runs(finished_at_utc DESC)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_filesystem_visibility_host_section
            ON filesystem_visibility(hostname, section)
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS filesystem_blacklist_patterns (
                id INTEGER PRIMARY KEY,
                pattern TEXT NOT NULL UNIQUE,
                description TEXT NOT NULL DEFAULT '',
                created_at_utc TEXT NOT NULL,
                updated_at_utc TEXT NOT NULL
            )
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
            CREATE TABLE IF NOT EXISTS database_lifecycle (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT NOT NULL,
                database_name TEXT NOT NULL,
                action TEXT NOT NULL,
                triggered_by TEXT NOT NULL DEFAULT 'system',
                triggered_at_utc TEXT NOT NULL,
                reason TEXT NOT NULL DEFAULT '',
                report_id INTEGER,
                instance_name TEXT NOT NULL DEFAULT 'MSSQLSERVER',
                UNIQUE(hostname, database_name, action, report_id)
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_database_lifecycle_host_time
            ON database_lifecycle(hostname, triggered_at_utc DESC)
            """
        )
        # Migration: Add instance_name column if missing (for old databases)
        existing_database_lifecycle_columns = {
            str(row[1])
            for row in conn.execute("PRAGMA table_info(database_lifecycle)").fetchall()
        }
        if "instance_name" not in existing_database_lifecycle_columns:
            conn.execute("ALTER TABLE database_lifecycle ADD COLUMN instance_name TEXT NOT NULL DEFAULT 'MSSQLSERVER'")
        conn.execute(
            """
            INSERT INTO alarm_settings (
                id,
                warning_threshold_percent,
                critical_threshold_percent,
                warning_consecutive_hits,
                warning_window_minutes,
                critical_trigger_immediate,
                telegram_enabled,
                telegram_bot_token,
                telegram_chat_id,
                updated_at_utc,
                alert_reminder_interval_hours,
                alert_telegram_reminder_interval_hours,
                cpu_warning_threshold_percent,
                cpu_critical_threshold_percent,
                cpu_alert_window_reports,
                ram_warning_threshold_percent,
                ram_critical_threshold_percent,
                ram_alert_window_reports,
                inactive_host_alert_enabled,
                inactive_host_alert_hours,
                ai_troubleshoot_enabled,
                openai_api_key,
                openai_model,
                openai_timeout_sec,
                openai_max_tokens,
                ai_troubleshoot_cache_ttl_sec
            )
            VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO NOTHING
            """,
            (
                WARNING_THRESHOLD_PERCENT,
                CRITICAL_THRESHOLD_PERCENT,
                2,
                15,
                1,
                1 if TELEGRAM_ENABLED_DEFAULT else 0,
                TELEGRAM_BOT_TOKEN_DEFAULT,
                TELEGRAM_CHAT_ID_DEFAULT,
                utc_now_iso(),
                0,
                0,
                80.0,
                95.0,
                4,
                85.0,
                95.0,
                4,
                0,
                3,
                1,
                "",
                "gpt-4o-mini",
                12,
                1200,
                600,
            ),
        )
        conn.execute(
            """
            INSERT INTO backup_automation_settings (
                id,
                local_enabled,
                local_interval_hours,
                local_retention_days,
                local_target_dir,
                sftp_enabled,
                sftp_host,
                sftp_port,
                sftp_username,
                sftp_remote_path,
                sftp_auth_mode,
                sftp_key_path,
                sftp_password,
                updated_at_utc
            )
            VALUES (1, ?, ?, ?, ?, 0, '', 22, '', '', 'key', '', '', ?)
            ON CONFLICT(id) DO NOTHING
            """,
            (
                1 if AUTO_BACKUP_DEFAULT_ENABLED else 0,
                AUTO_BACKUP_DEFAULT_INTERVAL_HOURS,
                AUTO_BACKUP_DEFAULT_RETENTION_DAYS,
                AUTO_BACKUP_DIR.name,
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
                    display_name,
                    password_hash,
                    password_salt,
                    is_admin,
                    is_disabled,
                    created_at_utc,
                    updated_at_utc
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    WEB_DEFAULT_USERNAME,
                    "",
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

        resolve_open_blacklisted_alerts(conn, get_filesystem_blacklist_pattern_strings(conn))

        session_cutoff_iso = utc_minutes_ago_iso(WEB_SESSION_INACTIVITY_MINUTES)
        conn.execute(
            "DELETE FROM web_sessions WHERE last_activity_at_utc <= ?",
            (session_cutoff_iso,),
        )
        conn.execute(
            "DELETE FROM oauth_pending_states WHERE expires_at_utc <= ?",
            (utc_now_iso(),),
        )

        # Backfill host_uid for historical reports without changing existing hostname data.
        _backfill_report_host_uids(conn)
        conn.commit()


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def web_session_cutoff_iso() -> str:
    return utc_minutes_ago_iso(WEB_SESSION_INACTIVITY_MINUTES)


def web_session_expires_iso() -> str:
    return (datetime.now(timezone.utc) + timedelta(minutes=WEB_SESSION_INACTIVITY_MINUTES)).strftime("%Y-%m-%dT%H:%M:%SZ")


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


def utc_minutes_ago_iso(minutes: int) -> str:
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)
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


def _is_valid_ipv4(text: object) -> bool:
    raw = str(text or "").strip()
    if not raw:
        return False
    try:
        socket.inet_aton(raw)
    except OSError:
        return False
    # inet_aton accepts shortened forms; enforce dotted-quad only.
    parts = raw.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False


def _first_ipv4_from_value(value: object) -> str:
    if value is None:
        return ""

    if isinstance(value, (list, tuple, set)):
        for entry in value:
            found = _first_ipv4_from_value(entry)
            if found:
                return found
        return ""

    raw = str(value or "").strip()
    if not raw:
        return ""
    if _is_valid_ipv4(raw):
        return raw

    for part in re.split(r"\s+", raw):
        if _is_valid_ipv4(part):
            return part
    return ""


def _resolve_std_nic_ipv4(payload: dict, fallback_primary_ip: str = "") -> str:
    if not isinstance(payload, dict):
        return _first_ipv4_from_value(fallback_primary_ip)

    network = payload.get("network") if isinstance(payload.get("network"), dict) else {}
    default_interface = str(network.get("default_interface", "") or "").strip()
    interfaces = network.get("interfaces") if isinstance(network.get("interfaces"), list) else []

    if default_interface and interfaces:
        for iface in interfaces:
            if not isinstance(iface, dict):
                continue
            if str(iface.get("name", "") or "") != default_interface:
                continue
            candidate = _first_ipv4_from_value([
                iface.get("ipv4"),
                iface.get("ip"),
                iface.get("address"),
                iface.get("addresses"),
            ])
            if candidate:
                return candidate

    from_primary = _first_ipv4_from_value(payload.get("primary_ip") or fallback_primary_ip)
    if from_primary:
        return from_primary

    return _first_ipv4_from_value(payload.get("all_ips"))


def _derive_host_uid(payload: dict, hostname: str, agent_id: str = "", primary_ip: str = "") -> str:
    safe_hostname = str(hostname or "").strip()
    safe_agent_id = str(agent_id or "").strip()
    explicit_uid = str(payload.get("host_uid", "") or "").strip() if isinstance(payload, dict) else ""
    if explicit_uid:
        return explicit_uid

    if safe_agent_id:
        return f"{safe_hostname}::agent:{safe_agent_id}"

    resolved_ip = _resolve_std_nic_ipv4(payload if isinstance(payload, dict) else {}, str(primary_ip or ""))
    if resolved_ip:
        return f"{safe_hostname}::ip:{resolved_ip}"

    return safe_hostname


def _reconcile_legacy_host_uids(
    conn: sqlite3.Connection,
    payload: dict,
    hostname: str,
    incoming_host_uid: str,
    agent_id: str = "",
    primary_ip: str = "",
) -> None:
    safe_hostname = str(hostname or "").strip()
    safe_host_uid = str(incoming_host_uid or "").strip()
    safe_agent_id = str(agent_id or "").strip()
    safe_primary_ip = str(primary_ip or "").strip()
    if not safe_hostname or not safe_host_uid:
        return

    # Nothing to reconcile when host_uid stays at plain hostname fallback.
    if safe_host_uid == safe_hostname:
        return

    candidates: set[str] = set()
    if safe_agent_id:
        candidates.add(f"{safe_hostname}::agent:{safe_agent_id}")

    resolved_ip = _resolve_std_nic_ipv4(payload if isinstance(payload, dict) else {}, safe_primary_ip)
    if resolved_ip:
        candidates.add(f"{safe_hostname}::ip:{resolved_ip}")
    if safe_primary_ip and _is_valid_ipv4(safe_primary_ip):
        candidates.add(f"{safe_hostname}::ip:{safe_primary_ip}")

    candidates.discard(safe_host_uid)
    if not candidates:
        return

    placeholders = ",".join(["?"] * len(candidates))
    where_parts = [
        "hostname = ?",
        f"COALESCE(host_uid, '') IN ({placeholders})",
    ]
    args: list = [safe_hostname, *sorted(candidates)]

    # Guard against false merges: require stable secondary identity axes.
    # If both agent_id and IP are available, both must match.
    ip_guard = ""
    if resolved_ip:
        ip_guard = resolved_ip
    elif safe_primary_ip and _is_valid_ipv4(safe_primary_ip):
        ip_guard = safe_primary_ip

    if safe_agent_id:
        where_parts.append("COALESCE(agent_id, '') = ?")
        args.append(safe_agent_id)

    if ip_guard:
        where_parts.append("COALESCE(primary_ip, '') = ?")
        args.append(ip_guard)

    # Reconciliation is unsafe without at least one stable secondary axis.
    if not safe_agent_id and not ip_guard:
        return

    # If multiple explicit non-legacy host_uids exist for the same hostname,
    # skip reconciliation to avoid collapsing distinct machines.
    ambiguous_values = [safe_host_uid, safe_hostname, *sorted(candidates)]
    ambiguous_placeholders = ",".join(["?"] * len(ambiguous_values))
    ambiguity_row = conn.execute(
        f"""
        SELECT 1
        FROM reports
        WHERE hostname = ?
          AND COALESCE(host_uid, '') <> ''
          AND COALESCE(host_uid, '') NOT IN ({ambiguous_placeholders})
        LIMIT 1
        """,
        (safe_hostname, *ambiguous_values),
    ).fetchone()
    if ambiguity_row:
        return

    where_clause = " AND ".join(where_parts)
    conn.execute(
        f"UPDATE reports SET host_uid = ? WHERE {where_clause}",
        (safe_host_uid, *args),
    )


def _ensure_reports_host_uid_support(conn: sqlite3.Connection) -> None:
    existing_reports_columns = {
        str(row[1])
        for row in conn.execute("PRAGMA table_info(reports)").fetchall()
    }
    if "host_uid" not in existing_reports_columns:
        conn.execute("ALTER TABLE reports ADD COLUMN host_uid TEXT")

    conn.execute("CREATE INDEX IF NOT EXISTS idx_reports_host_uid_id ON reports(host_uid, id)")
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_reports_host_key_id
        ON reports(COALESCE(NULLIF(host_uid, ''), hostname), id)
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_reports_host_key_received
        ON reports(COALESCE(NULLIF(host_uid, ''), hostname), received_at_utc)
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_reports_host_agent_ip_uid
        ON reports(hostname, agent_id, primary_ip, host_uid, id)
        """
    )


def _backfill_report_host_uids(conn: sqlite3.Connection, batch_size: int = 1000) -> None:
    _ensure_reports_host_uid_support(conn)
    safe_batch_size = max(100, min(int(batch_size or 1000), 5000))
    last_report_id = 0
    while True:
        rows = conn.execute(
            """
            SELECT id, COALESCE(hostname, ''), COALESCE(agent_id, ''), COALESCE(primary_ip, ''), COALESCE(payload_json, '{}')
            FROM reports
            WHERE COALESCE(host_uid, '') = ''
              AND id > ?
            ORDER BY id ASC
            LIMIT ?
            """,
            (last_report_id, safe_batch_size),
        ).fetchall()
        if not rows:
            return

        updates: list[tuple[str, int]] = []
        for row in rows:
            report_id = int(row[0] or 0)
            hostname = str(row[1] or "").strip()
            agent_id = str(row[2] or "").strip()
            primary_ip = str(row[3] or "").strip()
            payload = parse_payload_json(str(row[4] or "{}"))
            host_uid = _derive_host_uid(payload, hostname, agent_id, primary_ip)
            if host_uid:
                updates.append((host_uid, report_id))

        if updates:
            conn.executemany("UPDATE reports SET host_uid = ? WHERE id = ?", updates)

        last_report_id = int(rows[-1][0] or last_report_id)
        if len(rows) < safe_batch_size:
            return


def _repair_report_host_uids(conn: sqlite3.Connection, batch_size: int = 1000) -> dict:
    _ensure_reports_host_uid_support(conn)
    safe_batch_size = max(100, min(int(batch_size or 1000), 5000))
    host_key_expr = reports_host_key_sql()
    before_host_cards = int(
        conn.execute(
            f"SELECT COUNT(*) FROM (SELECT 1 FROM reports GROUP BY {host_key_expr})"
        ).fetchone()[0]
        or 0
    )

    scanned_reports = 0
    updated_reports = 0
    changed_hostnames: set[str] = set()
    last_report_id = 0

    while True:
        rows = conn.execute(
            """
            SELECT id,
                   COALESCE(hostname, ''),
                   COALESCE(agent_id, ''),
                   COALESCE(primary_ip, ''),
                   COALESCE(payload_json, '{}'),
                   COALESCE(host_uid, '')
            FROM reports
            WHERE id > ?
            ORDER BY id ASC
            LIMIT ?
            """,
            (last_report_id, safe_batch_size),
        ).fetchall()
        if not rows:
            break

        scanned_reports += len(rows)
        updates: list[tuple[str, int]] = []
        for row in rows:
            report_id = int(row[0] or 0)
            hostname = str(row[1] or "").strip()
            agent_id = str(row[2] or "").strip()
            primary_ip = str(row[3] or "").strip()
            payload = parse_payload_json(str(row[4] or "{}"))
            current_uid = str(row[5] or "").strip()
            expected_uid = _derive_host_uid(payload, hostname, agent_id, primary_ip)
            if not expected_uid:
                expected_uid = hostname
            if expected_uid and expected_uid != current_uid:
                updates.append((expected_uid, report_id))
                if hostname:
                    changed_hostnames.add(hostname)

        if updates:
            conn.executemany("UPDATE reports SET host_uid = ? WHERE id = ?", updates)
            updated_reports += len(updates)

        last_report_id = int(rows[-1][0] or last_report_id)
        if len(rows) < safe_batch_size:
            break

    after_host_cards = int(
        conn.execute(
            f"SELECT COUNT(*) FROM (SELECT 1 FROM reports GROUP BY {host_key_expr})"
        ).fetchone()[0]
        or 0
    )

    return {
        "status": "ok",
        "scanned_reports": scanned_reports,
        "updated_reports": updated_reports,
        "before_host_cards": before_host_cards,
        "after_host_cards": after_host_cards,
        "delta_host_cards": after_host_cards - before_host_cards,
        "changed_hostnames_count": len(changed_hostnames),
        "changed_hostnames_sample": sorted(changed_hostnames)[:30],
    }


def normalize_sap_b1_version_map_entries(entries_raw: object) -> list[dict[str, str]]:
    if not isinstance(entries_raw, list):
        return []
    normalized: list[dict[str, str]] = []
    seen_builds: set[str] = set()
    for item in entries_raw:
        if not isinstance(item, dict):
            continue
        build = str(item.get("build", "") or "").strip()
        if not build or build in seen_builds:
            continue
        seen_builds.add(build)
        normalized.append(
            {
                "build": build,
                "feature_pack": str(item.get("feature_pack", "") or "").strip(),
                "patch_level": str(item.get("patch_level", "") or "").strip(),
                "release_date": str(item.get("release_date", "") or "").strip(),
            }
        )
    return normalized


def load_sap_b1_version_map_entries() -> list[dict[str, str]]:
    try:
        raw = SAP_B1_VERSION_MAP_PATH.read_text(encoding="utf-8")
    except OSError:
        return []
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return []
    return normalize_sap_b1_version_map_entries(parsed)


def save_sap_b1_version_map_entries(entries_raw: object) -> list[dict[str, str]]:
    normalized = normalize_sap_b1_version_map_entries(entries_raw)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SAP_B1_VERSION_MAP_PATH.write_text(
        json.dumps(normalized, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return normalized


def normalize_sap_license_type_map_entries(entries_raw: object) -> list[dict[str, str]]:
    if not isinstance(entries_raw, list):
        return []
    normalized: list[dict[str, str]] = []
    seen_patterns: set[str] = set()
    for item in entries_raw:
        if not isinstance(item, dict):
            continue
        match_text = str(item.get("match_text", "") or "").strip()
        display_name = str(item.get("display_name", "") or "").strip()
        if not match_text:
            continue
        dedupe_key = match_text.upper()
        if dedupe_key in seen_patterns:
            continue
        seen_patterns.add(dedupe_key)
        normalized.append(
            {
                "match_text": match_text,
                "display_name": display_name,
            }
        )
    return normalized


def load_sap_license_type_map_entries() -> list[dict[str, str]]:
    try:
        raw = SAP_LICENSE_TYPE_MAP_PATH.read_text(encoding="utf-8")
    except OSError:
        return normalize_sap_license_type_map_entries(DEFAULT_SAP_LICENSE_TYPE_MAP_ENTRIES)
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return normalize_sap_license_type_map_entries(DEFAULT_SAP_LICENSE_TYPE_MAP_ENTRIES)
    normalized = normalize_sap_license_type_map_entries(parsed)
    if normalized:
        return normalized
    return normalize_sap_license_type_map_entries(DEFAULT_SAP_LICENSE_TYPE_MAP_ENTRIES)


def save_sap_license_type_map_entries(entries_raw: object) -> list[dict[str, str]]:
    normalized = normalize_sap_license_type_map_entries(entries_raw)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SAP_LICENSE_TYPE_MAP_PATH.write_text(
        json.dumps(normalized, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return normalized


def auto_sync_discovered_license_types(payload: object) -> None:
    """Auto-discover new SAP license types from agent report and add them to matrix."""
    if not isinstance(payload, dict):
        return
    
    sap_license = payload.get("sap_license")
    if not isinstance(sap_license, dict):
        return
    
    focus_license_types = sap_license.get("focus_license_types")
    if not isinstance(focus_license_types, list):
        return
    
    # Extract discovered license types
    discovered_types = set()
    for item in focus_license_types:
        if isinstance(item, dict):
            license_type = str(item.get("license_type", "")).strip()
            if license_type:
                discovered_types.add(license_type)
    
    if not discovered_types:
        return
    
    # Load current matrix
    current_matrix = load_sap_license_type_map_entries()
    existing_match_texts = {entry.get("match_text", "").upper() for entry in current_matrix}
    
    # Find new types not yet in matrix
    new_entries = []
    for discovered_type in sorted(discovered_types):
        if discovered_type.upper() not in existing_match_texts:
            new_entries.append({
                "match_text": discovered_type,
                "display_name": discovered_type,  # Default: use license type as display name
            })
    
    if not new_entries:
        return
    
    # Add new entries to matrix and save
    updated_matrix = current_matrix + new_entries
    try:
        save_sap_license_type_map_entries(updated_matrix)
    except OSError:
        pass  # Silent failure, don't block report storage


def _cleanup_backup_jobs(max_age_minutes: int = 30) -> None:
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=max_age_minutes)
    remove_ids: list[str] = []
    with _backup_jobs_lock:
        for job_id, job in _backup_jobs.items():
            created_raw = str(job.get("created_at_utc", "") or "").strip()
            try:
                created_at = datetime.fromisoformat(created_raw.replace("Z", "+00:00"))
            except ValueError:
                created_at = datetime.now(timezone.utc)
            if created_at < cutoff:
                remove_ids.append(job_id)

        for job_id in remove_ids:
            file_path = Path(str(_backup_jobs.get(job_id, {}).get("file_path", "") or ""))
            if file_path.exists():
                try:
                    file_path.unlink()
                except OSError:
                    pass
            _backup_jobs.pop(job_id, None)


def _create_database_backup_job() -> dict:
    _cleanup_backup_jobs()
    BACKUP_TEMP_DIR.mkdir(parents=True, exist_ok=True)

    if not DB_PATH.exists() or not DB_PATH.is_file():
        return {"status": "error", "error": "database file not found"}

    now_utc = datetime.now(timezone.utc)
    timestamp = now_utc.strftime("%Y%m%d-%H%M%S")
    job_id = secrets.token_urlsafe(10)
    backup_filename = f"monitoring-backup-{timestamp}.db"
    backup_path = BACKUP_TEMP_DIR / f"{job_id}.db"

    created_at = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    with _backup_jobs_lock:
        _backup_jobs[job_id] = {
            "status": "running",
            "created_at_utc": created_at,
            "updated_at_utc": created_at,
            "file_path": str(backup_path),
            "filename": backup_filename,
        }

    def _run_job() -> None:
        try:
            # Use SQLite's online backup API - WAL-aware and consistent under concurrent writes.
            with sqlite3.connect(DB_PATH) as src_conn:
                with sqlite3.connect(backup_path) as dst_conn:
                    src_conn.backup(dst_conn)
            with _backup_jobs_lock:
                job = _backup_jobs.get(job_id)
                if job is not None:
                    job["status"] = "ready"
                    job["updated_at_utc"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except (OSError, sqlite3.Error) as exc:
            with _backup_jobs_lock:
                job = _backup_jobs.get(job_id)
                if job is not None:
                    job["status"] = "error"
                    job["error"] = f"backup copy failed: {exc}"
                    job["updated_at_utc"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            if backup_path.exists():
                try:
                    backup_path.unlink()
                except OSError:
                    pass

    threading.Thread(target=_run_job, daemon=True).start()
    return {"status": "started", "job_id": job_id, "filename": backup_filename}


def _restore_database_from_bytes(raw_bytes: bytes) -> tuple[bool, str]:
    if not raw_bytes:
        return False, "empty upload"
    if not raw_bytes.startswith(b"SQLite format 3"):
        return False, "uploaded file is not a valid SQLite database"

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    temp_restore_path = DATA_DIR / f"restore-{secrets.token_hex(8)}.db"
    final_restore_path = DATA_DIR / f"restore-final-{secrets.token_hex(8)}.db"
    backup_current_path = DATA_DIR / f"monitoring.db.pre-restore-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.bak"

    try:
        # Write uploaded bytes to temp file
        temp_restore_path.write_bytes(raw_bytes)
        
        # Use VACUUM INTO to create a clean, non-WAL copy to avoid corruption
        # when WAL files are missing or incomplete
        try:
            conn = sqlite3.connect(str(temp_restore_path))
            conn.execute(f"VACUUM INTO '{final_restore_path}'")
            conn.close()
            cleaned_restore_path = final_restore_path
        except (sqlite3.DatabaseError, sqlite3.OperationalError):
            # If VACUUM INTO fails, use temp file directly (might still be valid)
            cleaned_restore_path = temp_restore_path
        
        # Backup current database if it exists
        if DB_PATH.exists():
            shutil.copy2(DB_PATH, backup_current_path)
            # Also backup any WAL/SHM files that exist
            for suffix in ("-wal", "-shm"):
                wal_path = DB_PATH.parent / f"{DB_PATH.name}{suffix}"
                if wal_path.exists():
                    backup_wal_path = DATA_DIR / f"monitoring.db{suffix}.pre-restore-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.bak"
                    try:
                        shutil.copy2(wal_path, backup_wal_path)
                    except OSError:
                        pass
        
        # Replace old DB with cleaned one
        os.replace(cleaned_restore_path, DB_PATH)
        
        # Clean up any old WAL/SHM files from the previous session
        for suffix in ("-wal", "-shm"):
            old_wal = DB_PATH.parent / f"{DB_PATH.name}{suffix}"
            if old_wal.exists():
                try:
                    old_wal.unlink()
                except OSError:
                    pass
        
        return True, str(backup_current_path.name)
    except OSError as exc:
        return False, f"restore failed: {exc}"
    finally:
        # Clean up temp files
        for path in (temp_restore_path, final_restore_path):
            if path.exists():
                try:
                    path.unlink()
                except OSError:
                    pass


def _normalize_backup_target_dir(value: object) -> str:
    raw = str(value or "").strip().replace("\\", "/")
    if not raw:
        return AUTO_BACKUP_DIR.name
    if raw.startswith("/") or ".." in raw:
        return AUTO_BACKUP_DIR.name
    if not re.fullmatch(r"[A-Za-z0-9._/-]+", raw):
        return AUTO_BACKUP_DIR.name
    return raw.strip("/") or AUTO_BACKUP_DIR.name


def _coerce_int(value: object, fallback: int, minimum: int, maximum: int) -> int:
    try:
        num = int(str(value or "").strip())
    except (TypeError, ValueError):
        num = fallback
    return max(minimum, min(maximum, num))


def get_backup_automation_settings(conn: sqlite3.Connection) -> dict[str, object]:
    row = conn.execute(
        """
        SELECT local_enabled,
               local_interval_hours,
               local_retention_days,
               local_target_dir,
               sftp_enabled,
               sftp_host,
               sftp_port,
               sftp_username,
               sftp_remote_path,
               sftp_auth_mode,
               sftp_key_path,
               sftp_password,
               updated_at_utc
        FROM backup_automation_settings
        WHERE id = 1
        """
    ).fetchone()
    if not row:
        now_utc = utc_now_iso()
        conn.execute(
            """
            INSERT INTO backup_automation_settings (
                id,
                local_enabled,
                local_interval_hours,
                local_retention_days,
                local_target_dir,
                sftp_enabled,
                sftp_host,
                sftp_port,
                sftp_username,
                sftp_remote_path,
                sftp_auth_mode,
                sftp_key_path,
                sftp_password,
                updated_at_utc
            ) VALUES (1, ?, ?, ?, ?, 0, '', 22, '', '', 'key', '', '', ?)
            """,
            (
                1 if AUTO_BACKUP_DEFAULT_ENABLED else 0,
                AUTO_BACKUP_DEFAULT_INTERVAL_HOURS,
                AUTO_BACKUP_DEFAULT_RETENTION_DAYS,
                AUTO_BACKUP_DIR.name,
                now_utc,
            ),
        )
        row = conn.execute(
            """
            SELECT local_enabled,
                   local_interval_hours,
                   local_retention_days,
                   local_target_dir,
                   sftp_enabled,
                   sftp_host,
                   sftp_port,
                   sftp_username,
                   sftp_remote_path,
                   sftp_auth_mode,
                   sftp_key_path,
                   sftp_password,
                   updated_at_utc
            FROM backup_automation_settings
            WHERE id = 1
            """
        ).fetchone()
    return {
        "local_enabled": bool(int(row[0] or 0)),
        "local_interval_hours": _coerce_int(row[1], AUTO_BACKUP_DEFAULT_INTERVAL_HOURS, 1, 168),
        "local_retention_days": _coerce_int(row[2], AUTO_BACKUP_DEFAULT_RETENTION_DAYS, 1, 365),
        "local_target_dir": _normalize_backup_target_dir(row[3]),
        "sftp_enabled": bool(int(row[4] or 0)),
        "sftp_host": str(row[5] or ""),
        "sftp_port": _coerce_int(row[6], 22, 1, 65535),
        "sftp_username": str(row[7] or ""),
        "sftp_remote_path": str(row[8] or ""),
        "sftp_auth_mode": "password" if str(row[9] or "").strip().lower() == "password" else "key",
        "sftp_key_path": str(row[10] or ""),
        "sftp_password": str(row[11] or ""),
        "updated_at_utc": str(row[12] or ""),
    }


def save_backup_automation_settings(conn: sqlite3.Connection, payload: dict) -> dict[str, object]:
    existing = get_backup_automation_settings(conn)
    local_enabled = coerce_bool(payload.get("local_enabled", existing.get("local_enabled", True)))
    local_interval_hours = _coerce_int(
        payload.get("local_interval_hours", existing.get("local_interval_hours", AUTO_BACKUP_DEFAULT_INTERVAL_HOURS)),
        AUTO_BACKUP_DEFAULT_INTERVAL_HOURS,
        1,
        168,
    )
    local_retention_days = _coerce_int(
        payload.get("local_retention_days", existing.get("local_retention_days", AUTO_BACKUP_DEFAULT_RETENTION_DAYS)),
        AUTO_BACKUP_DEFAULT_RETENTION_DAYS,
        1,
        365,
    )
    local_target_dir = _normalize_backup_target_dir(
        payload.get("local_target_dir", existing.get("local_target_dir", AUTO_BACKUP_DIR.name))
    )
    sftp_enabled = coerce_bool(payload.get("sftp_enabled", existing.get("sftp_enabled", False)))
    sftp_host = str(payload.get("sftp_host", existing.get("sftp_host", "")) or "").strip()
    sftp_port = _coerce_int(payload.get("sftp_port", existing.get("sftp_port", 22)), 22, 1, 65535)
    sftp_username = str(payload.get("sftp_username", existing.get("sftp_username", "")) or "").strip()
    sftp_remote_path = str(payload.get("sftp_remote_path", existing.get("sftp_remote_path", "")) or "").strip()
    sftp_auth_mode_raw = str(payload.get("sftp_auth_mode", existing.get("sftp_auth_mode", "key")) or "key").strip().lower()
    sftp_auth_mode = "password" if sftp_auth_mode_raw == "password" else "key"
    sftp_key_path = str(payload.get("sftp_key_path", existing.get("sftp_key_path", "")) or "").strip()
    sftp_password = str(payload.get("sftp_password", existing.get("sftp_password", "")) or "")
    now_utc = utc_now_iso()

    conn.execute(
        """
        INSERT INTO backup_automation_settings (
            id,
            local_enabled,
            local_interval_hours,
            local_retention_days,
            local_target_dir,
            sftp_enabled,
            sftp_host,
            sftp_port,
            sftp_username,
            sftp_remote_path,
            sftp_auth_mode,
            sftp_key_path,
            sftp_password,
            updated_at_utc
        ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            local_enabled = excluded.local_enabled,
            local_interval_hours = excluded.local_interval_hours,
            local_retention_days = excluded.local_retention_days,
            local_target_dir = excluded.local_target_dir,
            sftp_enabled = excluded.sftp_enabled,
            sftp_host = excluded.sftp_host,
            sftp_port = excluded.sftp_port,
            sftp_username = excluded.sftp_username,
            sftp_remote_path = excluded.sftp_remote_path,
            sftp_auth_mode = excluded.sftp_auth_mode,
            sftp_key_path = excluded.sftp_key_path,
            sftp_password = excluded.sftp_password,
            updated_at_utc = excluded.updated_at_utc
        """,
        (
            1 if local_enabled else 0,
            local_interval_hours,
            local_retention_days,
            local_target_dir,
            1 if sftp_enabled else 0,
            sftp_host,
            sftp_port,
            sftp_username,
            sftp_remote_path,
            sftp_auth_mode,
            sftp_key_path,
            sftp_password,
            now_utc,
        ),
    )
    return get_backup_automation_settings(conn)


def _sftp_batch_quote(value: str) -> str:
    return '"' + str(value or "").replace("\\", "\\\\").replace('"', '\\"') + '"'


def _resolve_sftp_config(payload: dict[str, object]) -> dict[str, object]:
    sftp_host = str(payload.get("sftp_host", "") or "").strip()
    sftp_port = _coerce_int(payload.get("sftp_port", 22), 22, 1, 65535)
    sftp_username = str(payload.get("sftp_username", "") or "").strip()
    sftp_remote_path = str(payload.get("sftp_remote_path", "") or "").strip()
    sftp_auth_mode_raw = str(payload.get("sftp_auth_mode", "key") or "key").strip().lower()
    sftp_auth_mode = "password" if sftp_auth_mode_raw == "password" else "key"
    sftp_key_path = str(payload.get("sftp_key_path", "") or "").strip()
    sftp_password = str(payload.get("sftp_password", "") or "")

    if not sftp_host:
        raise ValueError("sFTP Host fehlt")
    if not sftp_username:
        raise ValueError("sFTP Benutzer fehlt")
    if not sftp_remote_path:
        raise ValueError("Remote Pfad fehlt")

    try:
        with socket.create_connection((sftp_host, sftp_port), timeout=6):
            pass
    except OSError as exc:
        raise RuntimeError(f"sFTP Host/Port nicht erreichbar: {exc}")

    if shutil.which("sftp") is None:
        raise RuntimeError("Systembefehl 'sftp' nicht gefunden")

    if sftp_auth_mode == "key":
        if not sftp_key_path:
            raise ValueError("Key Pfad fehlt (Auth Modus: SSH Key)")
        key_path = Path(sftp_key_path).expanduser()
        if not key_path.exists() or not key_path.is_file():
            raise ValueError("Key Datei nicht gefunden")
        if not os.access(key_path, os.R_OK):
            raise ValueError("Key Datei ist nicht lesbar")
    else:
        if not sftp_password:
            raise ValueError("Passwort fehlt (Auth Modus: Passwort)")
        if shutil.which("sshpass") is None:
            raise RuntimeError("Passwort-Test erfordert 'sshpass' auf dem Server")

    return {
        "host": sftp_host,
        "port": sftp_port,
        "username": sftp_username,
        "remote_path": sftp_remote_path,
        "auth_mode": sftp_auth_mode,
        "key_path": sftp_key_path,
        "password": sftp_password,
    }


def _run_sftp_batch(sftp_cfg: dict[str, object], batch_lines: list[str], *, timeout_seconds: int = 30, error_prefix: str = "sFTP Aktion fehlgeschlagen") -> None:
    sftp_command = [
        "sftp",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "ConnectTimeout=8",
        "-P",
        str(int(sftp_cfg.get("port") or 22)),
    ]

    env = os.environ.copy()
    auth_mode = str(sftp_cfg.get("auth_mode") or "key")
    if auth_mode == "key":
        sftp_command.extend(["-o", "BatchMode=yes", "-i", str(Path(str(sftp_cfg.get("key_path") or "")).expanduser())])
    else:
        sftp_command.extend(["-o", "BatchMode=no"])
        sftp_command = ["sshpass", "-e"] + sftp_command
        env["SSHPASS"] = str(sftp_cfg.get("password") or "")

    sftp_command.append(f"{sftp_cfg.get('username')}@{sftp_cfg.get('host')}")
    batch_input = "\n".join(batch_lines) + "\n"

    proc = subprocess.run(
        sftp_command,
        input=batch_input,
        text=True,
        capture_output=True,
        timeout=timeout_seconds,
        env=env,
    )
    if proc.returncode != 0:
        details = (proc.stderr or proc.stdout or "").strip()
        if len(details) > 600:
            details = details[:600] + "..."
        raise RuntimeError(f"{error_prefix}: {details or 'unbekannter Fehler'}")


def upload_backup_file_to_sftp(payload: dict[str, object], local_file_path: Path, remote_filename: str | None = None) -> dict[str, object]:
    sftp_cfg = _resolve_sftp_config(payload)

    local_path = Path(local_file_path)
    if not local_path.exists() or not local_path.is_file():
        raise ValueError("Lokale Backup-Datei nicht gefunden")

    remote_name = str(remote_filename or local_path.name).strip() or local_path.name
    batch_lines = [
        f"cd {_sftp_batch_quote(str(sftp_cfg['remote_path']))}",
        f"put {_sftp_batch_quote(str(local_path))} {_sftp_batch_quote(remote_name)}",
        f"ls {_sftp_batch_quote(remote_name)}",
        "bye",
    ]
    _run_sftp_batch(sftp_cfg, batch_lines, error_prefix="sFTP Upload fehlgeschlagen")

    return {
        "host": str(sftp_cfg.get("host") or ""),
        "port": int(sftp_cfg.get("port") or 22),
        "username": str(sftp_cfg.get("username") or ""),
        "remote_path": str(sftp_cfg.get("remote_path") or ""),
        "auth_mode": str(sftp_cfg.get("auth_mode") or "key"),
        "remote_filename": remote_name,
    }


def run_sftp_upload_test(payload: dict[str, object]) -> dict[str, object]:
    sftp_cfg = _resolve_sftp_config(payload)

    BACKUP_TEMP_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    remote_name = f"monitoring-sftp-test-{timestamp}.txt"

    with tempfile.NamedTemporaryFile(mode="w", delete=False, dir=str(BACKUP_TEMP_DIR), prefix="sftp-test-", suffix=".txt") as tmp:
        tmp.write(f"Monitoring SFTP test at {utc_now_iso()}\n")
        local_path = Path(tmp.name)

    try:
        batch_lines = [
            f"cd {_sftp_batch_quote(str(sftp_cfg['remote_path']))}",
            f"put {_sftp_batch_quote(str(local_path))} {_sftp_batch_quote(remote_name)}",
            f"ls {_sftp_batch_quote(remote_name)}",
            f"rm {_sftp_batch_quote(remote_name)}",
            "bye",
        ]
        _run_sftp_batch(sftp_cfg, batch_lines, error_prefix="sFTP Test fehlgeschlagen")

        return {
            "status": "ok",
            "message": "sFTP Test erfolgreich (Upload + Entfernen der Testdatei abgeschlossen)",
            "details": {
                "host": str(sftp_cfg.get("host") or ""),
                "port": int(sftp_cfg.get("port") or 22),
                "username": str(sftp_cfg.get("username") or ""),
                "remote_path": str(sftp_cfg.get("remote_path") or ""),
                "auth_mode": str(sftp_cfg.get("auth_mode") or "key"),
                "remote_test_file": remote_name,
            },
        }
    finally:
        try:
            local_path.unlink(missing_ok=True)
        except Exception:
            pass


def list_backup_automation_runs(conn: sqlite3.Connection, limit: int = 20) -> list[dict[str, object]]:
    safe_limit = max(1, min(100, int(limit or 20)))
    rows = conn.execute(
        """
        SELECT id,
               started_at_utc,
               finished_at_utc,
               trigger_source,
               status,
               backup_path,
               backup_size_bytes,
               uploaded_sftp,
               error_message
        FROM backup_automation_runs
        ORDER BY id DESC
        LIMIT ?
        """,
        (safe_limit,),
    ).fetchall()
    return [
        {
            "id": int(row[0] or 0),
            "started_at_utc": str(row[1] or ""),
            "finished_at_utc": str(row[2] or ""),
            "trigger_source": str(row[3] or ""),
            "status": str(row[4] or ""),
            "backup_path": str(row[5] or ""),
            "backup_size_bytes": int(row[6] or 0),
            "uploaded_sftp": bool(int(row[7] or 0)),
            "error_message": str(row[8] or ""),
        }
        for row in rows
    ]


def _run_local_automated_backup(settings: dict[str, object], trigger_source: str) -> dict[str, object]:
    started_at = utc_now_iso()
    local_target_dir = _normalize_backup_target_dir(settings.get("local_target_dir", AUTO_BACKUP_DIR.name))
    target_dir = DATA_DIR / local_target_dir
    target_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    backup_file = target_dir / f"monitoring-auto-{timestamp}.db"
    temp_file = target_dir / f".{backup_file.name}.tmp"

    with sqlite3.connect(DB_PATH) as src_conn:
        with sqlite3.connect(temp_file) as dst_conn:
            src_conn.backup(dst_conn)
    os.replace(temp_file, backup_file)
    size_bytes = int(backup_file.stat().st_size)

    retention_days = _coerce_int(
        settings.get("local_retention_days", AUTO_BACKUP_DEFAULT_RETENTION_DAYS),
        AUTO_BACKUP_DEFAULT_RETENTION_DAYS,
        1,
        365,
    )
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    pruned_count = 0
    for path in target_dir.glob("monitoring-auto-*.db"):
        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        except OSError:
            continue
        if mtime < cutoff and path != backup_file:
            try:
                path.unlink()
                pruned_count += 1
            except OSError:
                pass

    uploaded_sftp = False
    upload_error_message = ""
    upload_details: dict[str, object] | None = None
    if bool(settings.get("sftp_enabled", False)):
        try:
            upload_details = upload_backup_file_to_sftp(settings, backup_file, backup_file.name)
            uploaded_sftp = True
        except Exception as exc:
            upload_error_message = str(exc)

    finished_at = utc_now_iso()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO backup_automation_runs (
                started_at_utc,
                finished_at_utc,
                trigger_source,
                status,
                backup_path,
                backup_size_bytes,
                uploaded_sftp,
                error_message
            ) VALUES (?, ?, ?, 'ok', ?, ?, ?, ?)
            """,
            (
                started_at,
                finished_at,
                trigger_source,
                str(backup_file.relative_to(DATA_DIR)),
                size_bytes,
                1 if uploaded_sftp else 0,
                upload_error_message,
            ),
        )
        conn.commit()

    return {
        "status": "ok",
        "started_at_utc": started_at,
        "finished_at_utc": finished_at,
        "backup_path": str(backup_file.relative_to(DATA_DIR)),
        "backup_size_bytes": size_bytes,
        "pruned_count": pruned_count,
        "uploaded_sftp": uploaded_sftp,
        "sftp_error": upload_error_message,
        "sftp_details": upload_details,
    }


def trigger_automated_backup_now(trigger_source: str = "manual", force_local: bool = True) -> dict[str, object]:
    if not _auto_backup_lock.acquire(blocking=False):
        raise RuntimeError("backup already running")
    try:
        with sqlite3.connect(DB_PATH) as conn:
            settings = get_backup_automation_settings(conn)

        if not force_local and not bool(settings.get("local_enabled", False)):
            return {"status": "skipped", "reason": "local backup disabled"}

        return _run_local_automated_backup(settings, trigger_source)
    except Exception as exc:
        finished_at = utc_now_iso()
        started_at = finished_at
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                """
                INSERT INTO backup_automation_runs (
                    started_at_utc,
                    finished_at_utc,
                    trigger_source,
                    status,
                    backup_path,
                    backup_size_bytes,
                    uploaded_sftp,
                    error_message
                ) VALUES (?, ?, ?, 'error', '', 0, 0, ?)
                """,
                (
                    started_at,
                    finished_at,
                    trigger_source,
                    str(exc),
                ),
            )
            conn.commit()
        raise
    finally:
        _auto_backup_lock.release()


def _auto_backup_scheduler_loop() -> None:
    while True:
        try:
            with sqlite3.connect(DB_PATH) as conn:
                settings = get_backup_automation_settings(conn)
                if bool(settings.get("local_enabled", False)):
                    latest_row = conn.execute(
                        """
                        SELECT finished_at_utc
                        FROM backup_automation_runs
                        ORDER BY id DESC
                        LIMIT 1
                        """
                    ).fetchone()
                    should_run = latest_row is None
                    if latest_row and not should_run:
                        last_iso = str(latest_row[0] or "").strip()
                        try:
                            last_dt = datetime.fromisoformat(last_iso.replace("Z", "+00:00"))
                        except ValueError:
                            last_dt = datetime.now(timezone.utc) - timedelta(hours=999)
                        interval_hours = _coerce_int(
                            settings.get("local_interval_hours", AUTO_BACKUP_DEFAULT_INTERVAL_HOURS),
                            AUTO_BACKUP_DEFAULT_INTERVAL_HOURS,
                            1,
                            168,
                        )
                        should_run = datetime.now(timezone.utc) >= (last_dt + timedelta(hours=interval_hours))
                    if should_run:
                        try:
                            trigger_automated_backup_now(trigger_source="scheduler", force_local=False)
                        except Exception as exc:
                            print(f"[auto-backup-scheduler] {exc}")
        except Exception as exc:
            print(f"[auto-backup-scheduler] {exc}")
        threading.Event().wait(60)


def _sqlite_sidecar_paths(db_path: Path) -> tuple[Path, Path]:
    return (
        db_path.parent / f"{db_path.name}-wal",
        db_path.parent / f"{db_path.name}-shm",
    )


def collect_database_maintenance_stats(conn: sqlite3.Connection) -> dict[str, object]:
    reports_row = conn.execute(
        """
        SELECT
            COUNT(*) AS reports_total,
            COUNT(DISTINCT hostname) AS hosts_with_reports,
            MIN(received_at_utc) AS oldest_report_utc,
            MAX(received_at_utc) AS newest_report_utc,
            AVG(LENGTH(payload_json)) AS avg_payload_bytes,
            MAX(LENGTH(payload_json)) AS max_payload_bytes
        FROM reports
        """
    ).fetchone()
    alerts_row = conn.execute(
        """
        SELECT
            COUNT(*) AS alerts_total,
            SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) AS alerts_open
        FROM alerts
        """
    ).fetchone()
    hosts_total_row = conn.execute("SELECT COUNT(DISTINCT hostname) FROM host_settings").fetchone()

    page_size = int((conn.execute("PRAGMA page_size").fetchone() or [0])[0] or 0)
    page_count = int((conn.execute("PRAGMA page_count").fetchone() or [0])[0] or 0)
    freelist_count = int((conn.execute("PRAGMA freelist_count").fetchone() or [0])[0] or 0)
    used_pages = max(0, page_count - freelist_count)

    db_file_bytes = int(DB_PATH.stat().st_size) if DB_PATH.exists() else 0
    wal_path, shm_path = _sqlite_sidecar_paths(DB_PATH)
    wal_file_bytes = int(wal_path.stat().st_size) if wal_path.exists() else 0
    shm_file_bytes = int(shm_path.stat().st_size) if shm_path.exists() else 0
    total_file_bytes = db_file_bytes + wal_file_bytes + shm_file_bytes

    free_ratio = (float(freelist_count) / float(page_count)) if page_count > 0 else 0.0

    return {
        "retention_days": int(REPORT_RETENTION_DAYS),
        "reports_total": int((reports_row[0] or 0) if reports_row else 0),
        "hosts_with_reports": int((reports_row[1] or 0) if reports_row else 0),
        "hosts_total": int((hosts_total_row[0] or 0) if hosts_total_row else 0),
        "oldest_report_utc": str((reports_row[2] or "") if reports_row else ""),
        "newest_report_utc": str((reports_row[3] or "") if reports_row else ""),
        "avg_payload_bytes": float((reports_row[4] or 0.0) if reports_row else 0.0),
        "max_payload_bytes": int((reports_row[5] or 0) if reports_row else 0),
        "alerts_total": int((alerts_row[0] or 0) if alerts_row else 0),
        "alerts_open": int((alerts_row[1] or 0) if alerts_row else 0),
        "db_file_bytes": db_file_bytes,
        "wal_file_bytes": wal_file_bytes,
        "shm_file_bytes": shm_file_bytes,
        "total_file_bytes": total_file_bytes,
        "page_size": page_size,
        "page_count": page_count,
        "freelist_count": freelist_count,
        "used_pages": used_pages,
        "free_ratio": free_ratio,
    }


def run_database_vacuum() -> dict[str, object]:
    started_at = datetime.now(timezone.utc)
    with sqlite3.connect(DB_PATH) as conn_before:
        before = collect_database_maintenance_stats(conn_before)

    with sqlite3.connect(DB_PATH) as conn:
        conn.isolation_level = None
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.execute("VACUUM")
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    with sqlite3.connect(DB_PATH) as conn_after:
        after = collect_database_maintenance_stats(conn_after)

    duration_ms = int((datetime.now(timezone.utc) - started_at).total_seconds() * 1000)
    reclaimed_bytes = int(before.get("total_file_bytes", 0) or 0) - int(after.get("total_file_bytes", 0) or 0)

    return {
        "before": before,
        "after": after,
        "reclaimed_bytes": reclaimed_bytes,
        "duration_ms": duration_ms,
    }


def _maintenance_bucket_start_utc(now_utc: datetime | None = None) -> datetime:
    ref_utc = now_utc or datetime.now(timezone.utc)
    local_now = ref_utc.astimezone(SCHEDULE_TIMEZONE)
    bucket_hour = (local_now.hour // DB_MAINTENANCE_INTERVAL_HOURS) * DB_MAINTENANCE_INTERVAL_HOURS
    local_bucket = local_now.replace(hour=bucket_hour, minute=0, second=0, microsecond=0)
    return local_bucket.astimezone(timezone.utc)


def _upsert_db_maintenance_snapshot_for_bucket(
    conn: sqlite3.Connection,
    *,
    bucket_start_utc: datetime,
) -> dict[str, object]:
    bucket_iso = bucket_start_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    stats = collect_database_maintenance_stats(conn)
    conn.execute(
        """
        INSERT INTO db_maintenance_history (
            bucket_start_utc,
            computed_at_utc,
            retention_days,
            reports_total,
            hosts_with_reports,
            hosts_total,
            alerts_open,
            avg_payload_bytes,
            max_payload_bytes,
            db_file_bytes,
            wal_file_bytes,
            shm_file_bytes,
            total_file_bytes,
            page_size,
            page_count,
            freelist_count,
            used_pages,
            free_ratio,
            oldest_report_utc,
            newest_report_utc
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(bucket_start_utc) DO UPDATE SET
            computed_at_utc = excluded.computed_at_utc,
            retention_days = excluded.retention_days,
            reports_total = excluded.reports_total,
            hosts_with_reports = excluded.hosts_with_reports,
            hosts_total = excluded.hosts_total,
            alerts_open = excluded.alerts_open,
            avg_payload_bytes = excluded.avg_payload_bytes,
            max_payload_bytes = excluded.max_payload_bytes,
            db_file_bytes = excluded.db_file_bytes,
            wal_file_bytes = excluded.wal_file_bytes,
            shm_file_bytes = excluded.shm_file_bytes,
            total_file_bytes = excluded.total_file_bytes,
            page_size = excluded.page_size,
            page_count = excluded.page_count,
            freelist_count = excluded.freelist_count,
            used_pages = excluded.used_pages,
            free_ratio = excluded.free_ratio,
            oldest_report_utc = excluded.oldest_report_utc,
            newest_report_utc = excluded.newest_report_utc
        """,
        (
            bucket_iso,
            utc_now_iso(),
            int(stats.get("retention_days", REPORT_RETENTION_DAYS) or REPORT_RETENTION_DAYS),
            int(stats.get("reports_total", 0) or 0),
            int(stats.get("hosts_with_reports", 0) or 0),
            int(stats.get("hosts_total", 0) or 0),
            int(stats.get("alerts_open", 0) or 0),
            float(stats.get("avg_payload_bytes", 0.0) or 0.0),
            int(stats.get("max_payload_bytes", 0) or 0),
            int(stats.get("db_file_bytes", 0) or 0),
            int(stats.get("wal_file_bytes", 0) or 0),
            int(stats.get("shm_file_bytes", 0) or 0),
            int(stats.get("total_file_bytes", 0) or 0),
            int(stats.get("page_size", 0) or 0),
            int(stats.get("page_count", 0) or 0),
            int(stats.get("freelist_count", 0) or 0),
            int(stats.get("used_pages", 0) or 0),
            float(stats.get("free_ratio", 0.0) or 0.0),
            str(stats.get("oldest_report_utc", "") or ""),
            str(stats.get("newest_report_utc", "") or ""),
        ),
    )
    return stats


def _insert_db_maintenance_snapshot_if_missing(
    conn: sqlite3.Connection,
    *,
    bucket_start_utc: datetime,
) -> bool:
    bucket_iso = bucket_start_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    exists = conn.execute(
        "SELECT 1 FROM db_maintenance_history WHERE bucket_start_utc = ? LIMIT 1",
        (bucket_iso,),
    ).fetchone()
    if exists:
        return False

    stats = collect_database_maintenance_stats(conn)
    conn.execute(
        """
        INSERT INTO db_maintenance_history (
            bucket_start_utc,
            computed_at_utc,
            retention_days,
            reports_total,
            hosts_with_reports,
            hosts_total,
            alerts_open,
            avg_payload_bytes,
            max_payload_bytes,
            db_file_bytes,
            wal_file_bytes,
            shm_file_bytes,
            total_file_bytes,
            page_size,
            page_count,
            freelist_count,
            used_pages,
            free_ratio,
            oldest_report_utc,
            newest_report_utc
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            bucket_iso,
            utc_now_iso(),
            int(stats.get("retention_days", REPORT_RETENTION_DAYS) or REPORT_RETENTION_DAYS),
            int(stats.get("reports_total", 0) or 0),
            int(stats.get("hosts_with_reports", 0) or 0),
            int(stats.get("hosts_total", 0) or 0),
            int(stats.get("alerts_open", 0) or 0),
            float(stats.get("avg_payload_bytes", 0.0) or 0.0),
            int(stats.get("max_payload_bytes", 0) or 0),
            int(stats.get("db_file_bytes", 0) or 0),
            int(stats.get("wal_file_bytes", 0) or 0),
            int(stats.get("shm_file_bytes", 0) or 0),
            int(stats.get("total_file_bytes", 0) or 0),
            int(stats.get("page_size", 0) or 0),
            int(stats.get("page_count", 0) or 0),
            int(stats.get("freelist_count", 0) or 0),
            int(stats.get("used_pages", 0) or 0),
            float(stats.get("free_ratio", 0.0) or 0.0),
            str(stats.get("oldest_report_utc", "") or ""),
            str(stats.get("newest_report_utc", "") or ""),
        ),
    )
    return True


def _ensure_db_maintenance_snapshot(conn: sqlite3.Connection, *, force_if_empty: bool = False) -> None:
    if force_if_empty:
        row = conn.execute("SELECT 1 FROM db_maintenance_history LIMIT 1").fetchone()
        if not row:
            _insert_db_maintenance_snapshot_if_missing(
                conn,
                bucket_start_utc=_maintenance_bucket_start_utc(),
            )
            conn.commit()
            return

    _insert_db_maintenance_snapshot_if_missing(
        conn,
        bucket_start_utc=_maintenance_bucket_start_utc(),
    )
    conn.commit()


def trigger_db_maintenance_snapshot_now(conn: sqlite3.Connection) -> dict[str, object]:
    bucket_start_utc = _maintenance_bucket_start_utc()
    stats = _upsert_db_maintenance_snapshot_for_bucket(
        conn,
        bucket_start_utc=bucket_start_utc,
    )
    conn.commit()
    return {
        "bucket_start_utc": bucket_start_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "stats": stats,
    }


def _coerce_number(value: object) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _forecast_linear_14d(history: list[dict], key: str) -> dict[str, object] | None:
    if len(history) < 2:
        return None

    points: list[tuple[float, float]] = []
    first_dt: datetime | None = None
    last_dt: datetime | None = None
    last_value = 0.0
    for row in history:
        bucket_iso = str(row.get("bucket_start_utc", "") or "")
        try:
            dt = datetime.fromisoformat(bucket_iso.replace("Z", "+00:00"))
        except ValueError:
            continue
        if first_dt is None:
            first_dt = dt
        last_dt = dt
        x_hours = (dt - first_dt).total_seconds() / 3600.0
        y = _coerce_number(row.get(key, 0))
        last_value = y
        points.append((x_hours, y))

    if len(points) < 2 or first_dt is None or last_dt is None:
        return None

    n = float(len(points))
    sum_x = sum(p[0] for p in points)
    sum_y = sum(p[1] for p in points)
    sum_xx = sum(p[0] * p[0] for p in points)
    sum_xy = sum(p[0] * p[1] for p in points)
    denom = (n * sum_xx) - (sum_x * sum_x)
    if abs(denom) < 1e-9:
        return None

    slope = ((n * sum_xy) - (sum_x * sum_y)) / denom
    intercept = (sum_y - (slope * sum_x)) / n

    horizon_hours = 14.0 * 24.0
    last_x = (last_dt - first_dt).total_seconds() / 3600.0
    target_x = last_x + horizon_hours
    projected = max(0.0, intercept + slope * target_x)
    delta = projected - last_value

    return {
        "metric": key,
        "current": last_value,
        "projected_14d": projected,
        "delta_14d": delta,
        "slope_per_day": slope * 24.0,
    }


def build_db_maintenance_dashboard(conn: sqlite3.Connection) -> dict[str, object]:
    rows = conn.execute(
        """
        SELECT bucket_start_utc,
               computed_at_utc,
               retention_days,
               reports_total,
               hosts_with_reports,
               hosts_total,
               alerts_open,
               avg_payload_bytes,
               max_payload_bytes,
               db_file_bytes,
               wal_file_bytes,
               shm_file_bytes,
               total_file_bytes,
               page_size,
               page_count,
               freelist_count,
               used_pages,
               free_ratio,
               oldest_report_utc,
               newest_report_utc
        FROM db_maintenance_history
        ORDER BY bucket_start_utc ASC
        LIMIT 240
        """
    ).fetchall()

    history: list[dict[str, object]] = []
    for row in rows:
        history.append(
            {
                "bucket_start_utc": str(row[0] or ""),
                "computed_at_utc": str(row[1] or ""),
                "retention_days": int(row[2] or 0),
                "reports_total": int(row[3] or 0),
                "hosts_with_reports": int(row[4] or 0),
                "hosts_total": int(row[5] or 0),
                "alerts_open": int(row[6] or 0),
                "avg_payload_bytes": float(row[7] or 0.0),
                "max_payload_bytes": int(row[8] or 0),
                "db_file_bytes": int(row[9] or 0),
                "wal_file_bytes": int(row[10] or 0),
                "shm_file_bytes": int(row[11] or 0),
                "total_file_bytes": int(row[12] or 0),
                "page_size": int(row[13] or 0),
                "page_count": int(row[14] or 0),
                "freelist_count": int(row[15] or 0),
                "used_pages": int(row[16] or 0),
                "free_ratio": float(row[17] or 0.0),
                "oldest_report_utc": str(row[18] or ""),
                "newest_report_utc": str(row[19] or ""),
            }
        )

    latest_stats = history[-1] if history else collect_database_maintenance_stats(conn)

    recent_rows: list[dict[str, object]] = []
    recent_src = history[-20:]
    for idx, row in enumerate(recent_src):
        prev = recent_src[idx - 1] if idx > 0 else None
        total_now = int(row.get("total_file_bytes", 0) or 0)
        reports_now = int(row.get("reports_total", 0) or 0)
        alerts_now = int(row.get("alerts_open", 0) or 0)
        recent_rows.append(
            {
                **row,
                "delta_total_file_bytes": None if prev is None else total_now - int(prev.get("total_file_bytes", 0) or 0),
                "delta_reports_total": None if prev is None else reports_now - int(prev.get("reports_total", 0) or 0),
                "delta_alerts_open": None if prev is None else alerts_now - int(prev.get("alerts_open", 0) or 0),
            }
        )

    forecasts: dict[str, dict[str, object]] = {}
    for metric in ("total_file_bytes", "reports_total", "alerts_open", "wal_file_bytes"):
        forecast = _forecast_linear_14d(history, metric)
        if forecast:
            forecasts[metric] = forecast

    now_local = datetime.now(SCHEDULE_TIMEZONE)
    next_bucket_local = now_local.replace(minute=0, second=0, microsecond=0)
    while (next_bucket_local.hour % DB_MAINTENANCE_INTERVAL_HOURS) != 0 or next_bucket_local <= now_local:
        next_bucket_local += timedelta(hours=1)

    return {
        "stats": latest_stats,
        "history": history,
        "recent_rows": recent_rows,
        "forecasts": forecasts,
        "schedule": {
            "timezone": SCHEDULE_TIMEZONE_NAME,
            "interval_hours": DB_MAINTENANCE_INTERVAL_HOURS,
            "next_bucket_local": next_bucket_local.isoformat(),
        },
    }


def _db_maintenance_scheduler_loop() -> None:
    while True:
        try:
            with sqlite3.connect(DB_PATH) as conn:
                _ensure_db_maintenance_snapshot(conn)
        except Exception as exc:
            print(f"[db-maintenance-scheduler] {exc}")
        threading.Event().wait(60)


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
    # Session expires after configured inactivity timeout.
    expires_iso = web_session_expires_iso()
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
    session_cutoff_iso = web_session_cutoff_iso()

    # Delete sessions that have been inactive longer than the configured timeout.
    conn.execute(
        "DELETE FROM web_sessions WHERE last_activity_at_utc <= ?",
        (session_cutoff_iso,),
    )
    rows = conn.execute(
        """
        SELECT s.username,
               COALESCE(u.display_name, ''),
               COUNT(*) AS session_count,
               MAX(s.expires_at_utc) AS latest_expires_at_utc,
               MAX(s.last_activity_at_utc) AS latest_activity_at_utc
        FROM web_sessions s
        LEFT JOIN web_users u ON u.username = s.username
        WHERE last_activity_at_utc > ?
        GROUP BY s.username, u.display_name
        ORDER BY s.username COLLATE NOCASE ASC
        """,
        (session_cutoff_iso,),
    ).fetchall()
    return [
        {
            "username": str(row[0] or ""),
            "display_name": str(row[1] or ""),
            "session_count": int(row[2] or 0),
            "latest_expires_at_utc": str(row[3] or ""),
            "latest_activity_at_utc": str(row[4] or ""),
        }
        for row in rows
        if str(row[0] or "").strip()
    ]


def record_web_login_event(
    conn: sqlite3.Connection,
    username: str,
    display_name: str,
    source_ip: str,
    auth_method: str,
    user_agent: str,
) -> None:
    try:
        conn.execute(
            """
            INSERT INTO web_login_events (
                logged_at_utc,
                username,
                display_name_snapshot,
                source_ip,
                auth_method,
                user_agent
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                utc_now_iso(),
                str(username or "").strip(),
                str(display_name or "").strip(),
                str(source_ip or "").strip(),
                str(auth_method or "password").strip() or "password",
                str(user_agent or "").strip(),
            ),
        )
    except sqlite3.OperationalError as exc:
        if "no such table: web_login_events" not in str(exc).lower():
            raise
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS web_login_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                logged_at_utc TEXT NOT NULL,
                username TEXT NOT NULL,
                display_name_snapshot TEXT NOT NULL DEFAULT '',
                source_ip TEXT NOT NULL DEFAULT '',
                auth_method TEXT NOT NULL DEFAULT 'password',
                user_agent TEXT NOT NULL DEFAULT ''
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_web_login_events_time
            ON web_login_events(logged_at_utc DESC)
            """
        )
        conn.execute(
            """
            INSERT INTO web_login_events (
                logged_at_utc,
                username,
                display_name_snapshot,
                source_ip,
                auth_method,
                user_agent
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                utc_now_iso(),
                str(username or "").strip(),
                str(display_name or "").strip(),
                str(source_ip or "").strip(),
                str(auth_method or "password").strip() or "password",
                str(user_agent or "").strip(),
            ),
        )


def list_web_login_events(conn: sqlite3.Connection, limit: int = 50) -> list[dict]:
    try:
        rows = conn.execute(
            """
            SELECT logged_at_utc,
                   username,
                   display_name_snapshot,
                   source_ip,
                   auth_method
            FROM web_login_events
            ORDER BY id DESC
            LIMIT ?
            """,
            (max(1, min(int(limit or 50), 200)),),
        ).fetchall()
    except sqlite3.OperationalError as exc:
        if "no such table: web_login_events" not in str(exc).lower():
            raise
        return []
    return [
        {
            "logged_at_utc": str(row[0] or ""),
            "username": str(row[1] or ""),
            "display_name": str(row[2] or ""),
            "source_ip": str(row[3] or ""),
            "auth_method": str(row[4] or "password"),
        }
        for row in rows
    ]


def normalize_username(value: object) -> str:
    return str(value or "").strip()


def normalize_customer_name(value: object) -> str:
    return " ".join(str(value or "").strip().split())


def normalize_maringo_project_number(value: object) -> str:
    return str(value or "").strip()


def list_customers(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        """
        SELECT id, customer_name, COALESCE(maringo_project_number, ''), created_at_utc, updated_at_utc
        FROM customers
        ORDER BY LOWER(customer_name), id
        """
    ).fetchall()
    return [
        {
            "id": int(row[0]),
            "customer_name": str(row[1] or ""),
            "maringo_project_number": str(row[2] or ""),
            "created_at_utc": str(row[3] or ""),
            "updated_at_utc": str(row[4] or ""),
        }
        for row in rows
    ]


def get_customer_by_id(conn: sqlite3.Connection, customer_id: object) -> dict | None:
    try:
        cid = int(customer_id)
    except (TypeError, ValueError):
        return None
    if cid <= 0:
        return None
    row = conn.execute(
        """
        SELECT id, customer_name, COALESCE(maringo_project_number, ''), created_at_utc, updated_at_utc
        FROM customers
        WHERE id = ?
        """,
        (cid,),
    ).fetchone()
    if not row:
        return None
    return {
        "id": int(row[0]),
        "customer_name": str(row[1] or ""),
        "maringo_project_number": str(row[2] or ""),
        "created_at_utc": str(row[3] or ""),
        "updated_at_utc": str(row[4] or ""),
    }


def upsert_customer(conn: sqlite3.Connection, customer_name: object, maringo_project_number: object = "") -> dict:
    name = normalize_customer_name(customer_name)
    project_no = normalize_maringo_project_number(maringo_project_number)
    if not name:
        raise ValueError("customer_name missing")

    existing = conn.execute(
        """
        SELECT id, customer_name, COALESCE(maringo_project_number, '')
        FROM customers
        WHERE LOWER(customer_name) = LOWER(?)
        LIMIT 1
        """,
        (name,),
    ).fetchone()

    now_utc = utc_now_iso()
    if existing:
        customer_id = int(existing[0])
        if project_no and project_no != str(existing[2] or ""):
            conn.execute(
                "UPDATE customers SET maringo_project_number = ?, updated_at_utc = ? WHERE id = ?",
                (project_no, now_utc, customer_id),
            )
    else:
        conn.execute(
            """
            INSERT INTO customers (customer_name, maringo_project_number, created_at_utc, updated_at_utc)
            VALUES (?, ?, ?, ?)
            """,
            (name, project_no, now_utc, now_utc),
        )
        customer_id = int(conn.execute("SELECT last_insert_rowid()").fetchone()[0])

    customer = get_customer_by_id(conn, customer_id)
    if not customer:
        raise ValueError("customer save failed")
    return customer


def update_customer_by_id(
    conn: sqlite3.Connection,
    customer_id: object,
    customer_name: object,
    maringo_project_number: object,
) -> dict:
    try:
        cid = int(str(customer_id or 0))
    except (TypeError, ValueError):
        cid = 0
    if cid <= 0:
        raise ValueError("Ungültige Kunden-ID.")
    name = normalize_customer_name(customer_name)
    if not name:
        raise ValueError("customer_name fehlt.")
    project_no = normalize_maringo_project_number(maringo_project_number)
    clash = conn.execute(
        "SELECT id FROM customers WHERE LOWER(customer_name) = LOWER(?) AND id != ?",
        (name, cid),
    ).fetchone()
    if clash:
        raise ValueError(f'Ein Kunde mit dem Namen "{name}" existiert bereits.')
    now_utc = utc_now_iso()
    conn.execute(
        "UPDATE customers SET customer_name = ?, maringo_project_number = ?, updated_at_utc = ? WHERE id = ?",
        (name, project_no, now_utc, cid),
    )
    if conn.execute("SELECT changes()").fetchone()[0] == 0:
        raise ValueError("Kunde nicht gefunden.")
    customer = get_customer_by_id(conn, cid)
    if not customer:
        raise ValueError("Kunde konnte nicht geladen werden.")
    return customer


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


def alert_mail_severity_bucket(severity: object) -> str:
    normalized = str(severity or "").strip().lower()
    if normalized == "critical":
        return "critical"
    if normalized == "warning":
        return "warning"
    return ""


def resolve_user_alert_mail_recipients(user_settings: dict, severity: object = "") -> list[str]:
    recipient = str(user_settings.get("email_recipient", "") or "").strip()
    extra = parse_email_recipients(user_settings.get("alert_email_recipients", ""))
    default_recipients = parse_email_recipients(",".join([recipient] + extra))

    bucket = alert_mail_severity_bucket(severity)
    if bucket == "warning":
        override = parse_email_recipients(user_settings.get("alert_warning_email_recipients", ""))
        if override:
            return override
    if bucket == "critical":
        override = parse_email_recipients(user_settings.get("alert_critical_email_recipients", ""))
        if override:
            return override
    return default_recipients


def alert_digest_recipient_severity(alerts: list[dict]) -> str:
    if any(str(item.get("severity") or "").strip().lower() == "critical" for item in alerts):
        return "critical"
    if any(str(item.get("severity") or "").strip().lower() == "warning" for item in alerts):
        return "warning"
    return ""


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
        SELECT username, COALESCE(display_name, ''), password_hash, password_salt, COALESCE(is_admin, 0), COALESCE(is_disabled, 0),
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
        "display_name": str(row[1] or ""),
        "password_hash": str(row[2] or ""),
        "password_salt": str(row[3] or ""),
        "is_admin": bool(int(row[4] or 0)),
        "is_disabled": bool(int(row[5] or 0)),
        "created_at_utc": str(row[6] or ""),
        "updated_at_utc": str(row[7] or ""),
    }


def list_web_users(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        """
        SELECT u.username,
             COALESCE(u.display_name, ''),
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
            "display_name": str(row[1] or ""),
            "is_admin": bool(int(row[2] or 0)),
            "is_disabled": bool(int(row[3] or 0)),
            "created_at_utc": str(row[4] or ""),
            "updated_at_utc": str(row[5] or ""),
            "email_enabled": bool(int(row[6] or 0)),
            "email_recipient": str(row[7] or ""),
            "trend_email_enabled": bool(int(row[8] or 0)),
            "trend_email_time_hhmm": normalize_hhmm(row[9], DEFAULT_TREND_DIGEST_TIME),
            "alert_email_enabled": bool(int(row[10] or 0)),
            "alert_email_time_hhmm": normalize_hhmm(row[11], DEFAULT_ALERT_DIGEST_TIME),
            "microsoft_connected_email": str(row[12] or ""),
            "microsoft_connected_at_utc": str(row[13] or ""),
            "has_microsoft_oauth": bool(str(row[12] or "").strip()),
        }
        for row in rows
    ]


def create_web_user(conn: sqlite3.Connection, username: str, password: str, is_admin: bool = False, display_name: str = "") -> dict:
    normalized_username = normalize_username(username)
    normalized_display_name = str(display_name or "").strip()
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
            display_name,
            password_hash,
            password_salt,
            is_admin,
            is_disabled,
            created_at_utc,
            updated_at_utc
        )
        VALUES (?, ?, ?, ?, ?, 0, ?, ?)
        """,
        (
            normalized_username,
            normalized_display_name,
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


def update_web_user_display_name(conn: sqlite3.Connection, username: str, display_name: str) -> dict:
    user = get_web_user(conn, username)
    if user is None:
        raise ValueError("user not found")
    normalized_display_name = str(display_name or "").strip()
    conn.execute(
        """
        UPDATE web_users
        SET display_name = ?, updated_at_utc = ?
        WHERE username = ?
        """,
        (normalized_display_name, utc_now_iso(), username),
    )
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
               COALESCE(email_sender, ''),
               COALESCE(trend_email_enabled, 0),
               COALESCE(trend_email_time_hhmm, ''),
               COALESCE(trend_email_last_sent_local_date, ''),
               COALESCE(alert_email_enabled, 0),
               COALESCE(alert_email_time_hhmm, ''),
               COALESCE(alert_email_recipients, ''),
             COALESCE(alert_warning_email_recipients, ''),
             COALESCE(alert_critical_email_recipients, ''),
               COALESCE(alert_email_last_sent_local_date, ''),
               COALESCE(alert_instant_mail_enabled, 0),
               COALESCE(alert_instant_min_severity, 'warning'),
             COALESCE(alert_instant_telegram_enabled, 0),
             COALESCE(alert_telegram_chat_id, ''),
                             COALESCE(backup_email_enabled, 0),
                             COALESCE(backup_email_time_hhmm, '08:15'),
                             COALESCE(backup_email_recipients, ''),
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
            "email_sender": "",
            "trend_email_enabled": False,
            "trend_email_time_hhmm": DEFAULT_TREND_DIGEST_TIME,
            "trend_email_last_sent_local_date": "",
            "alert_email_enabled": False,
            "alert_email_time_hhmm": DEFAULT_ALERT_DIGEST_TIME,
            "alert_email_recipients": "",
            "alert_warning_email_recipients": "",
            "alert_critical_email_recipients": "",
            "alert_email_last_sent_local_date": "",
            "alert_instant_mail_enabled": False,
            "alert_instant_min_severity": "warning",
            "alert_instant_telegram_enabled": False,
            "alert_telegram_chat_id": "",
            "backup_email_enabled": False,
            "backup_email_time_hhmm": "08:15",
            "backup_email_recipients": "",
            "updated_at_utc": "",
        }
    return {
        "email_enabled": bool(int(row[0] or 0)),
        "email_recipient": str(row[1] or ""),
        "email_sender": str(row[2] or ""),
        "trend_email_enabled": bool(int(row[3] or 0)),
        "trend_email_time_hhmm": normalize_hhmm(row[4], DEFAULT_TREND_DIGEST_TIME),
        "trend_email_last_sent_local_date": str(row[5] or ""),
        "alert_email_enabled": bool(int(row[6] or 0)),
        "alert_email_time_hhmm": normalize_hhmm(row[7], DEFAULT_ALERT_DIGEST_TIME),
        "alert_email_recipients": str(row[8] or ""),
        "alert_warning_email_recipients": str(row[9] or ""),
        "alert_critical_email_recipients": str(row[10] or ""),
        "alert_email_last_sent_local_date": str(row[11] or ""),
        "alert_instant_mail_enabled": bool(int(row[12] or 0)),
        "alert_instant_min_severity": str(row[13] or "warning"),
        "alert_instant_telegram_enabled": bool(int(row[14] or 0)),
        "alert_telegram_chat_id": str(row[15] or ""),
        "backup_email_enabled": bool(int(row[16] or 0)),
        "backup_email_time_hhmm": normalize_hhmm(row[17], "08:15"),
        "backup_email_recipients": str(row[18] or ""),
        "updated_at_utc": str(row[19] or ""),
    }


def save_web_user_settings(conn: sqlite3.Connection, username: str, payload: dict) -> dict:
    existing = get_web_user_settings(conn, username)
    email_recipient = str(payload.get("email_recipient", existing.get("email_recipient", "")) or "").strip()
    email_sender = str(payload.get("email_sender", existing.get("email_sender", "")) or "").strip()
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
    alert_warning_email_recipients = str(
        payload.get("alert_warning_email_recipients", existing.get("alert_warning_email_recipients", "")) or ""
    ).strip()
    alert_critical_email_recipients = str(
        payload.get("alert_critical_email_recipients", existing.get("alert_critical_email_recipients", "")) or ""
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
    backup_email_enabled = coerce_bool(payload.get("backup_email_enabled", existing.get("backup_email_enabled", False)))
    backup_email_time_hhmm = normalize_hhmm(
        payload.get("backup_email_time_hhmm", existing.get("backup_email_time_hhmm", "08:15")),
        "08:15",
    )
    backup_email_recipients = str(
        payload.get("backup_email_recipients", existing.get("backup_email_recipients", "")) or ""
    ).strip()
    now_utc = utc_now_iso()
    conn.execute(
        """
        INSERT INTO web_user_settings (
            username,
            email_enabled,
            email_recipient,
            email_sender,
            trend_email_enabled,
            trend_email_time_hhmm,
            trend_email_last_sent_local_date,
            alert_email_enabled,
            alert_email_time_hhmm,
            alert_email_recipients,
            alert_warning_email_recipients,
            alert_critical_email_recipients,
            alert_email_last_sent_local_date,
            alert_instant_mail_enabled,
            alert_instant_min_severity,
            alert_instant_telegram_enabled,
            alert_telegram_chat_id,
            backup_email_enabled,
            backup_email_time_hhmm,
            backup_email_recipients,
            updated_at_utc
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(username) DO UPDATE SET
            email_enabled = excluded.email_enabled,
            email_recipient = excluded.email_recipient,
            email_sender = excluded.email_sender,
            trend_email_enabled = excluded.trend_email_enabled,
            trend_email_time_hhmm = excluded.trend_email_time_hhmm,
            trend_email_last_sent_local_date = excluded.trend_email_last_sent_local_date,
            alert_email_enabled = excluded.alert_email_enabled,
            alert_email_time_hhmm = excluded.alert_email_time_hhmm,
            alert_email_recipients = excluded.alert_email_recipients,
            alert_warning_email_recipients = excluded.alert_warning_email_recipients,
            alert_critical_email_recipients = excluded.alert_critical_email_recipients,
            alert_email_last_sent_local_date = excluded.alert_email_last_sent_local_date,
            alert_instant_mail_enabled = excluded.alert_instant_mail_enabled,
            alert_instant_min_severity = excluded.alert_instant_min_severity,
            alert_instant_telegram_enabled = excluded.alert_instant_telegram_enabled,
            alert_telegram_chat_id = excluded.alert_telegram_chat_id,
            backup_email_enabled = excluded.backup_email_enabled,
            backup_email_time_hhmm = excluded.backup_email_time_hhmm,
            backup_email_recipients = excluded.backup_email_recipients,
            updated_at_utc = excluded.updated_at_utc
        """,
        (
            username,
            1 if email_enabled else 0,
            email_recipient,
            email_sender,
            1 if trend_email_enabled else 0,
            trend_email_time_hhmm,
            trend_email_last_sent_local_date,
            1 if alert_email_enabled else 0,
            alert_email_time_hhmm,
            alert_email_recipients,
            alert_warning_email_recipients,
            alert_critical_email_recipients,
            alert_email_last_sent_local_date,
            1 if alert_instant_mail_enabled else 0,
            alert_instant_min_severity,
            1 if alert_instant_telegram_enabled else 0,
            alert_telegram_chat_id,
            1 if backup_email_enabled else 0,
            backup_email_time_hhmm,
            backup_email_recipients,
            now_utc,
        ),
    )
    return {
        "email_enabled": email_enabled,
        "email_recipient": email_recipient,
        "email_sender": email_sender,
        "trend_email_enabled": trend_email_enabled,
        "trend_email_time_hhmm": trend_email_time_hhmm,
        "trend_email_last_sent_local_date": trend_email_last_sent_local_date,
        "alert_email_enabled": alert_email_enabled,
        "alert_email_time_hhmm": alert_email_time_hhmm,
        "alert_email_recipients": alert_email_recipients,
        "alert_warning_email_recipients": alert_warning_email_recipients,
        "alert_critical_email_recipients": alert_critical_email_recipients,
        "alert_email_last_sent_local_date": alert_email_last_sent_local_date,
        "alert_instant_mail_enabled": alert_instant_mail_enabled,
        "alert_instant_min_severity": alert_instant_min_severity,
        "alert_instant_telegram_enabled": alert_instant_telegram_enabled,
        "alert_telegram_chat_id": alert_telegram_chat_id,
        "backup_email_enabled": backup_email_enabled,
        "backup_email_time_hhmm": backup_email_time_hhmm,
        "backup_email_recipients": backup_email_recipients,
        "updated_at_utc": now_utc,
    }


def get_user_preferences(conn: sqlite3.Connection, username: str) -> dict:
    row = conn.execute(
        """
        SELECT COALESCE(critical_trends_metrics, 'filesystem'),
               COALESCE(host_interest_mode, 'all'),
               COALESCE(host_interest_hosts, ''),
               COALESCE(updated_at_utc, '')
        FROM user_preferences
        WHERE username = ?
        """,
        (username,),
    ).fetchone()
    if not row:
        return {
            "critical_trends_metrics": "filesystem",
            "host_interest_mode": "all",
            "host_interest_hosts": "",
            "updated_at_utc": "",
        }
    mode = str(row[1] or "all").strip().lower()
    if mode not in {"all", "interested_first", "interested_only"}:
        mode = "all"
    return {
        "critical_trends_metrics": str(row[0] or "filesystem").strip() or "filesystem",
        "host_interest_mode": mode,
        "host_interest_hosts": str(row[2] or ""),
        "updated_at_utc": str(row[3] or ""),
    }


def save_user_preferences(conn: sqlite3.Connection, username: str, payload: dict) -> dict:
    existing = get_user_preferences(conn, username)
    metrics = str(payload.get("critical_trends_metrics", existing.get("critical_trends_metrics", "filesystem")) or "filesystem").strip()
    mode = str(payload.get("host_interest_mode", existing.get("host_interest_mode", "all")) or "all").strip().lower()
    hosts = str(payload.get("host_interest_hosts", existing.get("host_interest_hosts", "")) or "").strip()
    if mode not in {"all", "interested_first", "interested_only"}:
        mode = "all"
    now_utc = utc_now_iso()
    conn.execute(
        """
        INSERT INTO user_preferences (username, critical_trends_metrics, host_interest_mode, host_interest_hosts, updated_at_utc)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(username) DO UPDATE SET
            critical_trends_metrics = excluded.critical_trends_metrics,
            host_interest_mode = excluded.host_interest_mode,
            host_interest_hosts = excluded.host_interest_hosts,
            updated_at_utc = excluded.updated_at_utc
        """,
        (username, metrics or "filesystem", mode, hosts, now_utc),
    )
    return get_user_preferences(conn, username)


def get_filesystem_visibility_hidden(
    conn: sqlite3.Connection,
    username: str,
    hostname: str,
    section: str,
) -> list[str]:
    rows = conn.execute(
        """
        SELECT mountpoint
        FROM filesystem_visibility
        WHERE username = ? AND hostname = ? AND section = ?
        ORDER BY mountpoint COLLATE NOCASE ASC
        """,
        (username, hostname, section),
    ).fetchall()
    return [str(row[0] or "") for row in rows if str(row[0] or "").strip()]


def normalize_mountpoint_key(value: object) -> str:
    mountpoint = str(value or "").strip()
    if mountpoint != "/":
        mountpoint = mountpoint.rstrip("/")
    return mountpoint.lower()


def save_filesystem_visibility_hidden(
    conn: sqlite3.Connection,
    username: str,
    hostname: str,
    section: str,
    hidden_mountpoints: list[str],
) -> list[str]:
    normalized = sorted(
        {
            str(item or "").strip()
            for item in hidden_mountpoints
            if str(item or "").strip()
        },
        key=lambda item: item.lower(),
    )
    conn.execute(
        "DELETE FROM filesystem_visibility WHERE username = ? AND hostname = ? AND section = ?",
        (username, hostname, section),
    )
    now_utc = utc_now_iso()
    for mountpoint in normalized:
        conn.execute(
            """
            INSERT INTO filesystem_visibility (username, hostname, section, mountpoint, updated_at_utc)
            VALUES (?, ?, ?, ?, ?)
            """,
            (username, hostname, section, mountpoint, now_utc),
        )
    return normalized


def get_filesystem_blacklist_patterns(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        """
        SELECT id, pattern, COALESCE(description, ''), created_at_utc, updated_at_utc
        FROM filesystem_blacklist_patterns
        ORDER BY pattern COLLATE NOCASE ASC
        """
    ).fetchall()
    return [
        {
            "id": int(row[0] or 0),
            "pattern": str(row[1] or ""),
            "description": str(row[2] or ""),
            "created_at_utc": str(row[3] or ""),
            "updated_at_utc": str(row[4] or ""),
        }
        for row in rows
    ]


def get_filesystem_blacklist_pattern_strings(conn: sqlite3.Connection) -> list[str]:
    rows = conn.execute("SELECT pattern FROM filesystem_blacklist_patterns").fetchall()
    return [str(row[0] or "").strip() for row in rows if str(row[0] or "").strip()]


def _filesystem_path_variants(value: str) -> set[str]:
    text = str(value or "").strip()
    if not text:
        return set()
    variants = {text}
    if text != "/":
        trimmed = text.rstrip("/")
        if trimmed:
            variants.add(trimmed)
        if not text.endswith("/"):
            variants.add(text + "/")
    return {item for item in variants if item}


def filesystem_blacklist_matches_mountpoint(pattern: str, mountpoint: str) -> bool:
    pattern_text = str(pattern or "").strip()
    mountpoint_text = str(mountpoint or "").strip()
    if not pattern_text or not mountpoint_text:
        return False

    mount_variants = _filesystem_path_variants(mountpoint_text)
    pattern_variants = _filesystem_path_variants(pattern_text)
    mount_variants_lower = {item.lower() for item in mount_variants}
    pattern_variants_lower = {item.lower() for item in pattern_variants}

    has_glob = any(token in pattern_text for token in "*?[")
    if not has_glob:
        pattern_key = normalize_mountpoint_key(pattern_text)
        return any(normalize_mountpoint_key(item) == pattern_key for item in mount_variants)

    # '/path/*' should also match '/path' itself.
    if pattern_text.endswith("/*"):
        base_pattern = pattern_text[:-2].rstrip("/") or "/"
        base_key = normalize_mountpoint_key(base_pattern)
        if any(normalize_mountpoint_key(item) == base_key for item in mount_variants):
            return True

    for candidate_mount in mount_variants:
        for candidate_pattern in pattern_variants:
            if fnmatch.fnmatch(candidate_mount, candidate_pattern):
                return True
    for candidate_mount in mount_variants_lower:
        for candidate_pattern in pattern_variants_lower:
            if fnmatch.fnmatch(candidate_mount, candidate_pattern):
                return True
    return False


def is_filesystem_blacklisted_by_patterns(mountpoint: str, patterns: list[str]) -> bool:
    if not mountpoint:
        return False
    for pattern in patterns:
        if filesystem_blacklist_matches_mountpoint(pattern, mountpoint):
            return True
    return False


def is_filesystem_blacklisted(conn: sqlite3.Connection, mountpoint: str) -> bool:
    return is_filesystem_blacklisted_by_patterns(mountpoint, get_filesystem_blacklist_pattern_strings(conn))


def resolve_open_blacklisted_alerts(conn: sqlite3.Connection, patterns: list[str]) -> int:
    if not patterns:
        return 0
    now_utc = utc_now_iso()
    open_rows = conn.execute(
        """
        SELECT id, hostname, mountpoint
        FROM alerts
        WHERE status = 'open'
        """
    ).fetchall()
    resolved_count = 0
    for row in open_rows:
        alert_id = int(row[0] or 0)
        hostname = str(row[1] or "").strip()
        mountpoint = str(row[2] or "").strip()
        if alert_id <= 0 or not hostname or not mountpoint:
            continue
        if not is_filesystem_blacklisted_by_patterns(mountpoint, patterns):
            continue
        conn.execute(
            "UPDATE alerts SET status = 'resolved', resolved_at_utc = ?, last_seen_at_utc = ? WHERE id = ?",
            (now_utc, now_utc, alert_id),
        )
        conn.execute("DELETE FROM alert_debounce WHERE hostname = ? AND mountpoint = ?", (hostname, mountpoint))
        resolved_count += 1
    return resolved_count


def log_database_lifecycle_event(
    conn: sqlite3.Connection,
    hostname: str,
    database_name: str,
    action: str,
    triggered_by: str = "system",
    reason: str = "",
    report_id: int | None = None,
    triggered_at_utc: str | None = None,
) -> None:
    """Log database creation/deletion/rename events.
    
    Supports composite keys in format 'INSTANCE::DBNAME' to track multiple SQL instances.
    If database_name contains '::', it will be split to extract instance_name.
    """
    event_time_utc = str(triggered_at_utc or "").strip() or utc_now_iso()
    
    # Parse composite key "INSTANCE::DBNAME" if present, otherwise default to "MSSQLSERVER"
    instance_name = "MSSQLSERVER"
    db_name = database_name
    if "::" in database_name:
        parts = database_name.split("::", 1)
        instance_name = str(parts[0] or "MSSQLSERVER").strip() or "MSSQLSERVER"
        db_name = str(parts[1] or "").strip()
    
    if not db_name:
        return  # Skip empty database names
    
    conn.execute(
        """
        INSERT OR IGNORE INTO database_lifecycle (
            hostname, database_name, action, triggered_by, triggered_at_utc, reason, report_id, instance_name
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (hostname, db_name, action, triggered_by, event_time_utc, reason, report_id, instance_name),
    )


def _extract_database_inventory(payload: dict) -> set[str]:
    if not isinstance(payload, dict):
        return set()

    inventory: set[str] = set()
    system_db_names = {"master", "model", "msdb", "tempdb"}

    def _add_name(raw_name: object, *, allow_system: bool = True, instance_name: str = "") -> None:
        name = str(raw_name or "").strip()
        if not name:
            return
        if not allow_system and name.lower() in system_db_names:
            return
        # Use composite key "INSTANCE::DBNAME" when instance_name is available to support multiple instances
        if instance_name:
            inventory.add(f"{instance_name}::{name}")
        else:
            inventory.add(name)

    legacy_databases = payload.get("databases")
    if isinstance(legacy_databases, dict):
        for db_name in legacy_databases.keys():
            _add_name(db_name)
    elif isinstance(legacy_databases, list):
        for db_entry in legacy_databases:
            if isinstance(db_entry, dict):
                _add_name(db_entry.get("name"))
            else:
                _add_name(db_entry)

    sql_info = payload.get("sql_server_info") if isinstance(payload.get("sql_server_info"), dict) else {}
    sql_instances = sql_info.get("instances") if isinstance(sql_info.get("instances"), list) else []
    for instance in sql_instances:
        if not isinstance(instance, dict):
            continue
        instance_name = str(instance.get("name", "")).strip() or "MSSQLSERVER"
        databases = instance.get("databases") if isinstance(instance.get("databases"), list) else []
        for db_entry in databases:
            if not isinstance(db_entry, dict):
                _add_name(db_entry, allow_system=False, instance_name=instance_name)
                continue
            db_name = db_entry.get("name")
            if bool(db_entry.get("system_db")):
                continue
            _add_name(db_name, allow_system=False, instance_name=instance_name)

    hana_info_candidates = [
        payload.get("hana_db_info"),
        payload.get("sap_hana"),
        payload.get("hana_info"),
    ]
    hana_info = next((item for item in hana_info_candidates if isinstance(item, dict)), {})
    hana_schemas = hana_info.get("schemas") if isinstance(hana_info.get("schemas"), list) else []
    for schema_entry in hana_schemas:
        if isinstance(schema_entry, dict):
            tenant_id = str(schema_entry.get("tenant_id", "")).strip()
            hana_instance = f"HANA-T{tenant_id}" if tenant_id else "HANA"
            _add_name(
                schema_entry.get("name")
                or schema_entry.get("schema")
                or schema_entry.get("schema_name"),
                instance_name=hana_instance,
            )
        else:
            _add_name(schema_entry, instance_name="HANA")

    hana_tenants = hana_info.get("tenants") if isinstance(hana_info.get("tenants"), list) else []
    for tenant_entry in hana_tenants:
        if not isinstance(tenant_entry, dict):
            continue
        tenant_id = str(tenant_entry.get("tenant_id", "")).strip()
        hana_instance = f"HANA-T{tenant_id}" if tenant_id else "HANA"
        tenant_result = tenant_entry.get("result") if isinstance(tenant_entry.get("result"), dict) else tenant_entry
        tenant_schemas = tenant_result.get("schemas") if isinstance(tenant_result.get("schemas"), list) else []
        for schema_entry in tenant_schemas:
            if isinstance(schema_entry, dict):
                _add_name(
                    schema_entry.get("name")
                    or schema_entry.get("schema")
                    or schema_entry.get("schema_name"),
                    instance_name=hana_instance,
                )
            else:
                _add_name(schema_entry, instance_name=hana_instance)

    return inventory


def _track_database_lifecycle(
    conn: sqlite3.Connection,
    hostname: str,
    payload: dict,
    report_id: int,
    detected_at_utc: str,
) -> None:
    if not hostname:
        return

    previous_row = conn.execute(
        """
        SELECT payload_json
        FROM reports
        WHERE hostname = ? AND id < ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (hostname, report_id),
    ).fetchone()
    if not previous_row:
        return

    previous_payload = parse_payload_json(str(previous_row[0] or "{}"))
    previous_dbs = _extract_database_inventory(previous_payload)
    current_dbs = _extract_database_inventory(payload)

    for db_name in sorted(current_dbs - previous_dbs, key=str.lower):
        log_database_lifecycle_event(
            conn,
            hostname,
            db_name,
            "create",
            triggered_by="system",
            reason="Detected from agent report",
            report_id=report_id,
            triggered_at_utc=detected_at_utc,
        )

    for db_name in sorted(previous_dbs - current_dbs, key=str.lower):
        log_database_lifecycle_event(
            conn,
            hostname,
            db_name,
            "delete",
            triggered_by="system",
            reason="Detected from agent report",
            report_id=report_id,
            triggered_at_utc=detected_at_utc,
        )


def get_database_lifecycle_for_host(
    conn: sqlite3.Connection,
    hostname: str,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    """Get database lifecycle events for a host."""
    rows = conn.execute(
        """
        SELECT id, database_name, action, triggered_by, triggered_at_utc, reason, COALESCE(instance_name, 'MSSQLSERVER')
        FROM database_lifecycle
        WHERE hostname = ?
        ORDER BY triggered_at_utc DESC
        LIMIT ? OFFSET ?
        """,
        (hostname, limit, offset),
    ).fetchall()
    total = conn.execute(
        "SELECT COUNT(*) FROM database_lifecycle WHERE hostname = ?",
        (hostname,),
    ).fetchone()[0]
    return {
        "events": [
            {
                "id": row[0],
                "database_name": row[1],
                "action": row[2],
                "triggered_by": row[3],
                "triggered_at_utc": row[4],
                "reason": row[5],
                "instance_name": row[6],
            }
            for row in rows
        ],
        "total": total,
        "returned": len(rows),
    }


def _format_database_lifecycle_name(database_name: object, instance_name: object) -> str:
    db_name = str(database_name or "").strip() or "-"
    instance = str(instance_name or "").strip() or "MSSQLSERVER"
    if instance.upper() == "HANA":
        return db_name
    if instance.upper() == "MSSQLSERVER":
        return db_name
    instance_display = re.sub(r"(?i)^HANA-T", "", instance).strip() or instance
    return f"{instance_display} - {db_name}"


def _database_lifecycle_values(action: str, database_display_name: str, instance_name: object = "MSSQLSERVER") -> tuple[str, str, str]:
    normalized = str(action or "").strip().lower()
    is_hana_schema = str(instance_name or "").strip().upper() == "HANA"
    if normalized == "create":
        if is_hana_schema:
            return "✨ HANA Schema erstellt", "-", database_display_name
        return "✨ DB erstellt", "-", database_display_name
    if normalized == "delete":
        if is_hana_schema:
            return "🗑️ HANA Schema gelöscht", database_display_name, "-"
        return "🗑️ DB gelöscht", database_display_name, "-"
    if normalized == "rename":
        if is_hana_schema:
            return "HANA Schema umbenannt", "-", database_display_name
        return "DB umbenannt", "-", database_display_name
    if is_hana_schema:
        return f"HANA Schema {normalized or 'event'}", "-", database_display_name
    return f"DB {normalized or 'event'}", "-", database_display_name


def _collect_database_lifecycle_change_items_for_host(conn: sqlite3.Connection, hostname: str) -> list[dict]:
    rows = conn.execute(
        """
        SELECT id,
               triggered_at_utc,
               database_name,
               action,
               COALESCE(instance_name, 'MSSQLSERVER')
        FROM database_lifecycle
        WHERE hostname = ?
        ORDER BY triggered_at_utc DESC, id DESC
        """,
        (hostname,),
    ).fetchall()

    items: list[dict] = []
    for row in rows:
        database_display_name = _format_database_lifecycle_name(row[2], row[4])
        action_label, old_value, new_value = _database_lifecycle_values(str(row[3] or ""), database_display_name, row[4])
        items.append(
            {
                "id": int(row[0] or 0),
                "detected_at_utc": str(row[1] or ""),
                "field_key": f"db_lifecycle::{str(row[3] or '').strip().lower()}::{database_display_name}",
                "field_label": action_label,
                "old_value": old_value,
                "new_value": new_value,
                "source": "database-lifecycle",
            }
        )

    return items


def _collect_database_lifecycle_change_items(conn: sqlite3.Connection, hours: int, limit: int) -> list[dict]:
    cutoff_iso = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    rows = conn.execute(
        """
        SELECT dl.id,
               dl.triggered_at_utc,
               dl.hostname,
               dl.database_name,
               dl.action,
               COALESCE(dl.instance_name, 'MSSQLSERVER'),
               COALESCE(h.display_name_override, ''),
               COALESCE(h.country_code_override, ''),
               COALESCE(cust.customer_name, '')
        FROM database_lifecycle dl
        LEFT JOIN host_settings h ON h.hostname = dl.hostname
        LEFT JOIN customers cust ON cust.id = h.customer_id
        WHERE dl.triggered_at_utc >= ?
        ORDER BY dl.triggered_at_utc DESC, dl.id DESC
        LIMIT ?
        """,
        (cutoff_iso, limit),
    ).fetchall()

    items: list[dict] = []
    for row in rows:
        hostname = str(row[2] or "")
        display_override = str(row[6] or "").strip()
        country_code = normalize_country_code(str(row[7] or ""))
        customer_name = str(row[8] or "").strip()
        database_display_name = _format_database_lifecycle_name(row[3], row[5])
        action_label, old_value, new_value = _database_lifecycle_values(str(row[4] or ""), database_display_name, row[5])
        items.append(
            {
                "id": int(row[0] or 0),
                "detected_at_utc": str(row[1] or ""),
                "hostname": hostname,
                "display_name": display_override or hostname,
                "customer_name": customer_name,
                "field_key": f"db_lifecycle::{str(row[4] or '').strip().lower()}::{database_display_name}",
                "field_label": action_label,
                "old_value": old_value,
                "new_value": new_value,
                "source": "database-lifecycle",
                "country_code": country_code,
            }
        )

    return items


def get_host_config_changes_for_host(
    conn: sqlite3.Connection,
    hostname: str,
    limit: int = 100,
    offset: int = 0,
) -> dict:
    """Get host config changes for a specific host."""
    safe_limit = max(1, min(int(limit or 100), 1000))
    safe_offset = max(0, int(offset or 0))

    rows = conn.execute(
        """
        SELECT c.id,
               c.detected_at_utc,
               c.field_key,
               c.old_value,
               c.new_value,
               COALESCE(c.source, 'agent-report')
        FROM host_config_changes c
        WHERE c.hostname = ?
        ORDER BY c.detected_at_utc DESC
        """,
        (hostname,),
    ).fetchall()

    items = [
        {
            "id": row[0],
            "detected_at_utc": row[1],
            "field_key": row[2],
            "field_label": HOST_CONFIG_FIELD_LABELS.get(row[2], row[2]),
            "old_value": row[3] or "-",
            "new_value": row[4] or "-",
            "source": row[5],
        }
        for row in rows
    ]

    addon_items = _collect_sap_addon_change_items_for_host(conn, hostname)
    if addon_items:
        items.extend(addon_items)

    items.sort(key=lambda item: (str(item.get("detected_at_utc") or ""), int(item.get("id") or 0)), reverse=True)

    total = len(items)
    paged_items = items[safe_offset : safe_offset + safe_limit]

    return {
        "items": paged_items,
        "total": total,
        "returned": len(paged_items),
    }


def backfill_database_lifecycle(conn: sqlite3.Connection, days: int = 7) -> dict:
    """Backfill database_lifecycle table from historical reports."""
    window_days = max(1, int(days or 7))
    cutoff_iso = (datetime.now(timezone.utc) - timedelta(days=window_days)).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Stream reports to avoid loading large payload windows into memory.
    row_iter = conn.execute(
        """
        SELECT id, received_at_utc, hostname, payload_json
        FROM reports
        WHERE received_at_utc >= ?
        ORDER BY hostname COLLATE NOCASE ASC, received_at_utc ASC
        """,
        (cutoff_iso,),
    )

    # Track databases per host over time
    prev_dbs_by_host: dict[str, set[str]] = {}
    report_count = 0
    inserted_events = 0

    for row in row_iter:
        report_id = int(row[0] or 0)
        report_time_utc = str(row[1] or "").strip()
        hostname = str(row[2] or "").strip()
        if not hostname:
            continue

        payload = parse_payload_json(str(row[3] or "{}"))
        report_count += 1

        current_dbs = _extract_database_inventory(payload)

        # Get previously known databases for this host
        prev_dbs = prev_dbs_by_host.get(hostname, set())

        # Find new and deleted databases
        new_dbs = current_dbs - prev_dbs
        deleted_dbs = prev_dbs - current_dbs

        # Insert events for new databases
        for db_name in new_dbs:
            # Parse composite key "INSTANCE::DBNAME" if present
            instance_name = "MSSQLSERVER"
            clean_db_name = db_name
            if "::" in db_name:
                parts = db_name.split("::", 1)
                instance_name = str(parts[0] or "MSSQLSERVER").strip() or "MSSQLSERVER"
                clean_db_name = str(parts[1] or "").strip()
            
            if not clean_db_name:
                continue
            
            conn.execute(
                """
                INSERT OR IGNORE INTO database_lifecycle (
                    hostname, database_name, action, triggered_by, triggered_at_utc, reason, report_id, instance_name
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (hostname, clean_db_name, "create", "system", report_time_utc, "Detected in backfill", report_id, instance_name),
            )
            inserted_events += 1

        # Insert events for deleted databases
        for db_name in deleted_dbs:
            # Parse composite key "INSTANCE::DBNAME" if present
            instance_name = "MSSQLSERVER"
            clean_db_name = db_name
            if "::" in db_name:
                parts = db_name.split("::", 1)
                instance_name = str(parts[0] or "MSSQLSERVER").strip() or "MSSQLSERVER"
                clean_db_name = str(parts[1] or "").strip()
            
            if not clean_db_name:
                continue
            
            conn.execute(
                """
                INSERT OR IGNORE INTO database_lifecycle (
                    hostname, database_name, action, triggered_by, triggered_at_utc, reason, report_id, instance_name
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (hostname, clean_db_name, "delete", "system", report_time_utc, "Detected in backfill", report_id, instance_name),
            )
            inserted_events += 1

        # Update state for next iteration
        prev_dbs_by_host[hostname] = current_dbs

        if report_count % 1000 == 0:
            conn.commit()

    return {
        "reports_scanned": report_count,
        "inserted_events": inserted_events,
    }


def rebuild_changelog_history(conn: sqlite3.Connection, days: int = 15) -> dict:
    """Reset changelog tables and rebuild them from the last N report days.

    This is intended as a one-time startup migration for hosts that need a clean
    greenfield rebuild of the changelog state.
    """
    window_days = max(1, min(int(days or 15), 365))

    existing_state = conn.execute(
        "SELECT completed_at_utc, days FROM changelog_rebuild_state WHERE id = 1"
    ).fetchone()
    if existing_state:
        return {
            "status": "skipped",
            "completed_at_utc": str(existing_state[0] or ""),
            "days": int(existing_state[1] or 0),
        }

    conn.execute("DELETE FROM host_config_changes")
    conn.execute("DELETE FROM database_lifecycle")
    conn.execute("DELETE FROM host_config_snapshot")

    config_result = backfill_host_config_changes(conn, days=window_days)
    db_result = backfill_database_lifecycle(conn, days=window_days)

    completed_at_utc = utc_now_iso()
    conn.execute(
        """
        INSERT INTO changelog_rebuild_state (
            id,
            completed_at_utc,
            days,
            reports_scanned,
            inserted_host_config_changes,
            inserted_database_lifecycle_events
        )
        VALUES (1, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            completed_at_utc = excluded.completed_at_utc,
            days = excluded.days,
            reports_scanned = excluded.reports_scanned,
            inserted_host_config_changes = excluded.inserted_host_config_changes,
            inserted_database_lifecycle_events = excluded.inserted_database_lifecycle_events
        """,
        (
            completed_at_utc,
            window_days,
            int(config_result.get("reports_scanned", 0) or 0),
            int(config_result.get("inserted_changes", 0) or 0),
            int(db_result.get("inserted_events", 0) or 0),
        ),
    )

    return {
        "status": "rebuilt",
        "completed_at_utc": completed_at_utc,
        "days": window_days,
        "config_result": config_result,
        "database_result": db_result,
    }



def add_filesystem_blacklist_pattern(
    conn: sqlite3.Connection,
    pattern: str,
    description: str = "",
) -> dict:
    pattern_normalized = str(pattern or "").strip()
    if not pattern_normalized:
        raise ValueError("pattern required")
    description_normalized = str(description or "").strip()
    now_utc = utc_now_iso()
    try:
        cursor = conn.execute(
            """
            INSERT INTO filesystem_blacklist_patterns (pattern, description, created_at_utc, updated_at_utc)
            VALUES (?, ?, ?, ?)
            """,
            (pattern_normalized, description_normalized, now_utc, now_utc),
        )
        result = {
            "id": cursor.lastrowid,
            "pattern": pattern_normalized,
            "description": description_normalized,
            "created_at_utc": now_utc,
            "updated_at_utc": now_utc,
        }
        resolve_open_blacklisted_alerts(conn, [pattern_normalized])
        return result
    except sqlite3.IntegrityError:
        raise ValueError("pattern already exists")


def delete_filesystem_blacklist_pattern(conn: sqlite3.Connection, pattern_id: int) -> None:
    conn.execute("DELETE FROM filesystem_blacklist_patterns WHERE id = ?", (int(pattern_id or 0),))


def list_available_alert_hosts(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        """
        SELECT r.hostname,
               COALESCE(h.display_name_override, ''),
               COALESCE(h.country_code_override, ''),
               COALESCE(r.payload_json, '{}')
        FROM reports r
        LEFT JOIN host_settings h ON h.hostname = r.hostname
        JOIN (
            SELECT hostname, MAX(id) AS latest_id
            FROM reports
            WHERE COALESCE(hostname, '') != ''
            GROUP BY hostname
        ) latest ON latest.latest_id = r.id
        WHERE COALESCE(r.hostname, '') != ''
        ORDER BY LOWER(COALESCE(NULLIF(h.display_name_override, ''), r.hostname)), LOWER(r.hostname)
        """
    ).fetchall()
    return [
        {
            "hostname": str(row[0] or ""),
            "display_name": str(row[1] or "") if str(row[1] or "").strip() else str(row[0] or ""),
            "country_code": normalize_country_code(str(row[2] or "")) or extract_country_code_from_payload(parse_payload_json(str(row[3] or "{}"))),
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


def parse_host_csv(value: object) -> set[str]:
    return {
        str(item or "").strip()
        for item in str(value or "").split(",")
        if str(item or "").strip()
    }


def parse_critical_trends_metrics(value: object) -> set[str]:
    allowed = {"cpu", "memory", "swap", "filesystem"}
    parsed = {
        str(item or "").strip().lower()
        for item in str(value or "").split(",")
        if str(item or "").strip()
    }
    selected = parsed & allowed
    return selected or {"filesystem"}


def get_user_trend_host_scope(conn: sqlite3.Connection, username: str) -> tuple[set[str] | None, set[str]]:
    preferences = get_user_preferences(conn, username)
    interested_hosts = parse_host_csv(preferences.get("host_interest_hosts", ""))
    mode = str(preferences.get("host_interest_mode", "all") or "all").strip().lower()
    if mode == "interested_only" and interested_hosts:
        return interested_hosts, interested_hosts
    if mode == "interested_first" and interested_hosts:
        return None, interested_hosts
    return None, set()


def get_user_alert_mail_host_scope(conn: sqlite3.Connection, username: str) -> set[str] | None:
    rows = conn.execute(
        """
        SELECT hostname, COALESCE(notify_mail, 0)
        FROM web_user_alert_subscriptions
        WHERE username = ?
        """,
        (username,),
    ).fetchall()
    if not rows:
        return None
    return {
        str(row[0] or "").strip()
        for row in rows
        if str(row[0] or "").strip() and bool(int(row[1] or 0))
    }


def collect_critical_trends(
    conn: sqlite3.Connection,
    hours: int,
    hidden_mountpoints_by_host: dict[str, set[str]] | None = None,
    allowed_hostnames: set[str] | None = None,
    prioritized_hostnames: set[str] | None = None,
    selected_metrics: set[str] | None = None,
) -> list[dict]:
    cutoff_iso = utc_hours_ago_iso(hours)
    blacklist_patterns = get_filesystem_blacklist_pattern_strings(conn)

    hidden_normalized_by_host: dict[str, set[str]] = {}
    if hidden_mountpoints_by_host:
        for host, mountpoints in hidden_mountpoints_by_host.items():
            keys = {
                normalize_mountpoint_key(item)
                for item in (mountpoints or [])
                if normalize_mountpoint_key(item)
            }
            if keys:
                hidden_normalized_by_host[host] = keys

    selected = (selected_metrics or {"filesystem"}) & {"cpu", "memory", "swap", "filesystem"}
    if not selected:
        selected = {"filesystem"}

    resource_metrics = [
        ("cpu", "cpu_usage_percent", "CPU %"),
        ("memory", "memory_used_percent", "RAM %"),
        ("swap", "swap_used_percent", "Swap %"),
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
    if allowed_hostnames is not None:
        hostnames = [hostname for hostname in hostnames if hostname in allowed_hostnames]

    prioritized = prioritized_hostnames or set()

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
            """
            SELECT COALESCE(h.display_name_override, ''),
                   COALESCE(h.country_code_override, ''),
                   COALESCE(c.customer_name, '')
            FROM host_settings h
            LEFT JOIN customers c ON c.id = h.customer_id
            WHERE h.hostname = ?
            """,
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
        host_customer_name = str(host_settings[2] or "").strip() if host_settings else ""
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
                if mountpoint and blacklist_patterns and is_filesystem_blacklisted_by_patterns(mountpoint, blacklist_patterns):
                    continue
                try:
                    used_percent = float(fs["used_percent"])
                except (KeyError, TypeError, ValueError):
                    continue
                if mountpoint not in fs_series:
                    fs_series[mountpoint] = []
                fs_series[mountpoint].append(used_percent)

        for metric_group, key, label in resource_metrics:
            if metric_group not in selected:
                continue
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
                    "customer_name": host_customer_name,
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

        if "filesystem" in selected:
            for mountpoint, values in fs_series.items():
                if mountpoint in muted_mountpoints:
                    continue
                if blacklist_patterns and is_filesystem_blacklisted_by_patterns(mountpoint, blacklist_patterns):
                    continue
                mountpoint_key = normalize_mountpoint_key(mountpoint)
                # Skip filesystem if it's hidden in user's visibility settings
                if hidden_normalized_by_host and hostname in hidden_normalized_by_host:
                    if mountpoint_key in hidden_normalized_by_host[hostname]:
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
                        "customer_name": host_customer_name,
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

    warnings.sort(
        key=lambda item: (
            0 if str(item.get("hostname") or "") in prioritized else 1,
            0 if item["level"] == "crit" else 1,
            -item["projected"],
        )
    )
    return warnings


def collect_inactive_hosts(conn: sqlite3.Connection, hours: int) -> list[dict]:
    cutoff_iso = utc_hours_ago_iso(hours)
    now_utc = datetime.now(timezone.utc)

    rows = _latest_report_rows_by_host_key(conn)
    inactive_hosts = []
    for row in rows:
        host_uid = str(row[0] or "").strip()
        hostname = str(row[1] or "").strip()
        last_report_time_utc = str(row[2] or "").strip()
        payload_json_str = str(row[3] or "{}")
        primary_ip = str(row[4] or "").strip()

        if not hostname or not last_report_time_utc:
            continue
        if last_report_time_utc >= cutoff_iso:
            continue

        try:
            payload = json.loads(payload_json_str) if isinstance(payload_json_str, str) else {}
        except (json.JSONDecodeError, TypeError):
            payload = {}

        display_name = get_display_name_override(conn, hostname, host_uid) or effective_display_name(payload, "", hostname)
        os_name = str(payload.get("os", "") or "")
        if not primary_ip:
            primary_ip = str(payload.get("primary_ip", "") or "")

        host_settings = conn.execute(
            """
            SELECT hs.country_code_override,
                   COALESCE(c.customer_name, '')
            FROM host_settings hs
            LEFT JOIN customers c ON c.id = hs.customer_id
            WHERE hs.hostname = ?
            """,
            (hostname,),
        ).fetchone()
        if host_settings:
            country_code = normalize_country_code(host_settings[0])
            customer_name = str(host_settings[1] or "").strip()
        else:
            country_code = ""
            customer_name = ""

        open_alerts = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE hostname = ? AND status = 'open'",
            (hostname,),
        ).fetchone()
        open_alert_count = int(open_alerts[0] or 0) if open_alerts else 0

        try:
            last_time = datetime.fromisoformat(last_report_time_utc.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            last_time = now_utc

        time_diff = now_utc - last_time
        hours_inactive = time_diff.total_seconds() / 3600

        inactive_hosts.append({
            "host_uid": host_uid,
            "hostname": hostname,
            "display_name": display_name,
            "customer_name": customer_name,
            "last_report_time_utc": last_report_time_utc,
            "hours_inactive": round(hours_inactive, 1),
            "os": os_name,
            "primary_ip": primary_ip,
            "country_code": country_code,
            "open_alert_count": open_alert_count,
        })

    inactive_hosts.sort(key=lambda item: -item["hours_inactive"])
    return inactive_hosts


def _latest_report_rows_by_host_key(conn: sqlite3.Connection) -> list[tuple]:
    host_key_expr = reports_host_key_sql()
    return conn.execute(
        f"""
        WITH latest AS (
            SELECT {host_key_expr} AS host_key,
                   MAX(id) AS latest_id
            FROM reports
            GROUP BY {host_key_expr}
        )
        SELECT latest.host_key,
               COALESCE(r.hostname, ''),
               COALESCE(r.received_at_utc, ''),
               COALESCE(r.payload_json, '{{}}'),
               COALESCE(r.primary_ip, '')
        FROM latest
        JOIN reports r ON r.id = latest.latest_id
        ORDER BY r.received_at_utc DESC
        """
    ).fetchall()

def _collect_latest_report_usage_by_host(conn: sqlite3.Connection, hostnames: list[str]) -> dict[str, dict[str, float]]:
    if not hostnames:
        return {}

    placeholders = ",".join("?" for _ in hostnames)
    latest_rows = conn.execute(
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

    usage_by_host: dict[str, dict[str, float]] = {}
    for row in latest_rows:
        hostname = str(row[0] or "").strip()
        if not hostname:
            continue
        payload = parse_payload_json(str(row[1] or "{}"))
        filesystems = payload.get("filesystems", [])
        if not isinstance(filesystems, list):
            continue
        usage_by_mountpoint: dict[str, float] = {}
        for fs in filesystems:
            if not isinstance(fs, dict):
                continue
            mountpoint = str(fs.get("mountpoint", "") or "").strip()
            if not mountpoint:
                continue
            try:
                used_percent = float(fs.get("used_percent"))
            except (TypeError, ValueError):
                continue
            usage_by_mountpoint[normalize_mountpoint_key(mountpoint)] = used_percent
        usage_by_host[hostname] = usage_by_mountpoint
    return usage_by_host


def collect_open_alerts(conn: sqlite3.Connection, allowed_hostnames: set[str] | None = None) -> list[dict]:
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
    blacklist_patterns = get_filesystem_blacklist_pattern_strings(conn)
    if blacklist_patterns:
        rows = [row for row in rows if not is_filesystem_blacklisted_by_patterns(str(row[2] or ""), blacklist_patterns)]
    if allowed_hostnames is not None:
        rows = [row for row in rows if str(row[1] or "") in allowed_hostnames]

    hostnames = sorted({str(row[1] or "") for row in rows if str(row[1] or "")})
    display_names: dict[str, str] = {}
    customer_names: dict[str, str] = {}
    country_codes: dict[str, str] = {}
    os_families: dict[str, str] = {}
    latest_usage_by_host = _collect_latest_report_usage_by_host(conn, hostnames)
    if hostnames:
        placeholders = ",".join("?" for _ in hostnames)
        settings_rows = conn.execute(
            f"SELECT h.hostname, h.display_name_override, COALESCE(h.country_code_override, ''), COALESCE(c.customer_name, '') FROM host_settings h LEFT JOIN customers c ON c.id = h.customer_id WHERE h.hostname IN ({placeholders})",
            tuple(hostnames),
        ).fetchall()
        overrides = {str(item[0]): str(item[1] or "") for item in settings_rows}
        country_overrides = {str(item[0]): normalize_country_code(item[2]) for item in settings_rows}
        customer_overrides = {str(item[0]): str(item[3] or "").strip() for item in settings_rows}

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
            customer_names[hostname] = customer_overrides.get(hostname, "")
            country_codes[hostname] = country_overrides.get(hostname, "") or extract_country_code_from_payload(payload)
            os_families[hostname] = normalize_os_family(payload.get("os", ""))
    else:
        primary_ip_by_hostname = {}

    result = []
    for row in rows:
        hostname = str(row[1] or "")
        mountpoint = str(row[2] or "")
        current_used_percent = None
        host_usage = latest_usage_by_host.get(hostname, {})
        if mountpoint:
            current_used_percent = host_usage.get(normalize_mountpoint_key(mountpoint))
        delta_used_percent = None
        if current_used_percent is not None:
            delta_used_percent = float(current_used_percent) - float(row[4] or 0)

        result.append(
            {
                "id": int(row[0] or 0),
                "hostname": hostname,
                "display_name": display_names.get(hostname, hostname),
                "customer_name": customer_names.get(hostname, ""),
                "primary_ip": primary_ip_by_hostname.get(hostname, ""),
                "mountpoint": mountpoint,
                "severity": str(row[3] or "warning"),
                "used_percent": float(row[4] or 0),
                "current_used_percent": current_used_percent,
                "delta_used_percent": delta_used_percent,
                "created_at_utc": str(row[5] or ""),
                "last_seen_at_utc": str(row[6] or ""),
                "country_code": country_codes.get(hostname, ""),
                "os_family": os_families.get(hostname, "linux"),
            }
        )
    return result


def _safe_attachment_token(value: str, fallback: str) -> str:
    token = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "")).strip("-._")
    return token or fallback


def _map_sql_release(version_str: str) -> str:
    value = str(version_str or "").strip()
    if not value:
        return "-"
    try:
        parts = value.split(".")
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
    except (TypeError, ValueError, IndexError):
        return value

    if major == 16:
        return "SQL Server 2022"
    if major == 15:
        return "SQL Server 2019"
    if major == 14:
        return "SQL Server 2017"
    if major == 13:
        return "SQL Server 2016"
    if major == 12:
        return "SQL Server 2014"
    if major == 11:
        return "SQL Server 2012"
    if major == 10:
        return "SQL Server 2008 R2" if minor >= 50 else "SQL Server 2008"
    if major == 9:
        return "SQL Server 2005"
    if major == 8:
        return "SQL Server 2000"
    return f"{major}.x"


def _extract_sap_hana_ram(payload: dict) -> dict:
    sap_release = "-"
    hana_version = "-"
    hana_sid = "-"
    ram_gb = "-"

    # Newer payload key used by current agents.
    sap_block = payload.get("sap_b1_info")
    if isinstance(sap_block, dict):
        components = sap_block.get("server_components_version")
        if isinstance(components, dict):
            sap_candidate = str(components.get("version", "")).strip()
            if sap_candidate:
                sap_release = sap_candidate

    # Backward-compatible key used by existing deployed agents.
    if sap_release == "-":
        legacy_sap_block = payload.get("sap_business_one")
        if isinstance(legacy_sap_block, dict):
            components = legacy_sap_block.get("server_components_version")
            if isinstance(components, dict):
                sap_candidate = str(components.get("version", "")).strip()
                if sap_candidate:
                    sap_release = sap_candidate

    if sap_release == "-":
        top_level_sap = str(payload.get("sap_release", "")).strip()
        if top_level_sap:
            sap_release = top_level_sap

    hana_block = payload.get("hana_db_info")
    if isinstance(hana_block, dict) and hana_block.get("available") is True:
        instances = hana_block.get("instances")
        if isinstance(instances, list) and instances:
            first = instances[0]
            if isinstance(first, dict):
                raw_hana = str(first.get("version", "")).strip()
                if raw_hana:
                    parts = raw_hana.split(".")
                    hana_version = ".".join(parts[:3]) if len(parts) >= 3 else raw_hana
                sid_value = str(first.get("sid", "")).strip()
                if sid_value:
                    hana_sid = sid_value

    if hana_version == "-" or hana_sid == "-":
        legacy_hana_block = payload.get("hana_info")
        if isinstance(legacy_hana_block, dict):
            if legacy_hana_block.get("available") is True:
                raw_hana = str(legacy_hana_block.get("version", "")).strip()
                if raw_hana and hana_version == "-":
                    parts = raw_hana.split(".")
                    hana_version = ".".join(parts[:3]) if len(parts) >= 3 else raw_hana
                sid_value = str(legacy_hana_block.get("sid", "")).strip()
                if sid_value and hana_sid == "-":
                    hana_sid = sid_value

    if hana_version == "-":
        top_level_hana = str(payload.get("hana_version", "")).strip()
        if top_level_hana:
            hana_version = top_level_hana
    if hana_sid == "-":
        top_level_sid = str(payload.get("hana_sid", "")).strip()
        if top_level_sid:
            hana_sid = top_level_sid

    memory_mb = payload_int(payload, "memory_mb", 0)
    if memory_mb > 0:
        ram_gb = str(int(round(memory_mb / 1024)))
    else:
        memory_block = payload.get("memory")
        if isinstance(memory_block, dict):
            total_kb = int(memory_block.get("total_kb") or 0)
            if total_kb > 0:
                ram_gb = str(int(round(total_kb / (1024 * 1024))))

    return {
        "sap_release": sap_release,
        "hana_version": hana_version,
        "hana_sid": hana_sid,
        "ram_gb": ram_gb,
    }


def _extract_cpu_overview(payload: dict) -> dict:
    cpu = payload.get("cpu") if isinstance(payload.get("cpu"), dict) else {}

    cores_raw = cpu.get("cores")
    if cores_raw is None:
        cores_raw = cpu.get("core_count")
    if cores_raw is None:
        cores_raw = cpu.get("logical_cores")

    cpu_cores = "-"
    try:
        if cores_raw is not None:
            cpu_cores_num = int(float(str(cores_raw).strip()))
            if cpu_cores_num > 0:
                cpu_cores = cpu_cores_num
    except (TypeError, ValueError):
        cpu_cores = "-"

    cpu_model_name = str(
        cpu.get("model_name")
        or cpu.get("model")
        or cpu.get("name")
        or "-"
    ).strip() or "-"

    return {
        "cpu_cores": cpu_cores,
        "cpu_model_name": cpu_model_name,
    }


HOST_CONFIG_TRACKED_FIELDS = (
    "os_release",
    "kernel_release",
    "cpu_cores",
    "cpu_model_name",
    "ram_gb",
    "sap_release",
    "hana_release",
    "hana_sid",
    "sql_release",
)

HOST_CONFIG_FIELD_LABELS = {
    "os_release": "💻 OS Release",
    "kernel_release": "💻 Kernel",
    "cpu_cores": "💻 CPU Cores",
    "cpu_model_name": "💻 CPU Modell",
    "ram_gb": "💻 RAM (GB)",
    "sap_release": "SAP Release",
    "hana_release": "HANA Release",
    "hana_sid": "HANA SID",
    "sql_release": "SQL Release",
}


def _ensure_host_config_snapshot_schema(conn: sqlite3.Connection) -> None:
    columns = {
        str(row[1])
        for row in conn.execute("PRAGMA table_info(host_config_snapshot)").fetchall()
    }
    if "kernel_release" not in columns:
        conn.execute("ALTER TABLE host_config_snapshot ADD COLUMN kernel_release TEXT NOT NULL DEFAULT '-'")


def _normalize_config_value(field_key: str, value: object) -> str:
    raw = str(value or "").strip()
    if not raw:
        return "-"

    lowered = raw.lower()
    if lowered in {"-", "na", "n/a", "none", "null", "unknown", "unbekannt", "not available"}:
        return "-"

    if field_key in {"ram_gb", "cpu_cores"}:
        try:
            parsed = int(float(raw))
            return str(parsed) if parsed > 0 else "-"
        except (TypeError, ValueError):
            return "-"

    normalized = re.sub(r"\s+", " ", raw)
    if field_key == "hana_sid":
        return normalized.upper()
    return normalized


def _canonical_config_value(field_key: str, value: str) -> str:
    if field_key in {"ram_gb", "cpu_cores"}:
        return value
    return value.lower()


def _is_significant_config_change(field_key: str, old_value: str, new_value: str) -> bool:
    if old_value == new_value:
        return False

    old_canonical = _canonical_config_value(field_key, old_value)
    new_canonical = _canonical_config_value(field_key, new_value)
    if old_canonical == new_canonical:
        return False

    if field_key == "ram_gb" and old_value != "-" and new_value != "-":
        try:
            return abs(int(new_value) - int(old_value)) >= 1
        except (TypeError, ValueError):
            return True

    return True


def _extract_os_release(payload: dict) -> str:
    os_value = payload.get("os") if isinstance(payload, dict) else ""
    return str(os_value or "").strip() or "-"


def _extract_kernel_release(payload: dict) -> str:
    kernel_value = payload.get("kernel") if isinstance(payload, dict) else ""
    return str(kernel_value or "").strip() or "-"


def _extract_sql_release(payload: dict) -> str:
    sql_release = "-"
    sql_block = payload.get("sql_server_info")
    if isinstance(sql_block, dict) and sql_block.get("available") is True:
        instances = sql_block.get("instances")
        if isinstance(instances, list) and instances:
            first = instances[0]
            if isinstance(first, dict):
                sql_release = _map_sql_release(str(first.get("version", "")).strip())
    return str(sql_release or "-").strip() or "-"


def _extract_host_config_snapshot(payload: dict) -> dict[str, str]:
    release_info = _extract_sap_hana_ram(payload)
    cpu_info = _extract_cpu_overview(payload)
    return {
        "os_release": _extract_os_release(payload),
        "kernel_release": _extract_kernel_release(payload),
        "cpu_cores": str(cpu_info["cpu_cores"]),
        "cpu_model_name": str(cpu_info["cpu_model_name"]),
        "ram_gb": str(release_info["ram_gb"]),
        "sap_release": str(release_info["sap_release"]),
        "hana_release": str(release_info["hana_version"]),
        "hana_sid": str(release_info["hana_sid"]),
        "sql_release": _extract_sql_release(payload),
    }


def _track_host_config_changes(
    conn: sqlite3.Connection,
    hostname: str,
    payload: dict,
    report_id: int,
    detected_at_utc: str,
) -> None:
    _ensure_host_config_snapshot_schema(conn)

    if not hostname:
        return

    new_snapshot_raw = _extract_host_config_snapshot(payload)
    new_snapshot = {
        key: _normalize_config_value(key, new_snapshot_raw.get(key, "-"))
        for key in HOST_CONFIG_TRACKED_FIELDS
    }

    existing_row = conn.execute(
        """
        SELECT os_release, kernel_release, cpu_cores, cpu_model_name, ram_gb, sap_release, hana_release, hana_sid, sql_release
        FROM host_config_snapshot
        WHERE hostname = ?
        """,
        (hostname,),
    ).fetchone()

    if existing_row:
        old_snapshot = {
            "os_release": _normalize_config_value("os_release", existing_row[0]),
            "kernel_release": _normalize_config_value("kernel_release", existing_row[1]),
            "cpu_cores": _normalize_config_value("cpu_cores", existing_row[2]),
            "cpu_model_name": _normalize_config_value("cpu_model_name", existing_row[3]),
            "ram_gb": _normalize_config_value("ram_gb", existing_row[4]),
            "sap_release": _normalize_config_value("sap_release", existing_row[5]),
            "hana_release": _normalize_config_value("hana_release", existing_row[6]),
            "hana_sid": _normalize_config_value("hana_sid", existing_row[7]),
            "sql_release": _normalize_config_value("sql_release", existing_row[8]),
        }

        dedupe_cutoff = (datetime.now(timezone.utc) - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        for field_key in HOST_CONFIG_TRACKED_FIELDS:
            old_value = old_snapshot.get(field_key, "-")
            new_value = new_snapshot.get(field_key, "-")
            if not _is_significant_config_change(field_key, old_value, new_value):
                continue

            duplicate = conn.execute(
                """
                SELECT 1
                FROM host_config_changes
                WHERE hostname = ?
                  AND field_key = ?
                  AND old_value = ?
                  AND new_value = ?
                  AND detected_at_utc >= ?
                ORDER BY id DESC
                LIMIT 1
                """,
                (hostname, field_key, old_value, new_value, dedupe_cutoff),
            ).fetchone()
            if duplicate:
                continue

            conn.execute(
                """
                INSERT INTO host_config_changes (
                    detected_at_utc,
                    hostname,
                    field_key,
                    old_value,
                    new_value,
                    report_id,
                    source
                )
                VALUES (?, ?, ?, ?, ?, ?, 'agent-report')
                """,
                (detected_at_utc, hostname, field_key, old_value, new_value, report_id),
            )

    conn.execute(
        """
        INSERT INTO host_config_snapshot (
            hostname,
            os_release,
            kernel_release,
            cpu_cores,
            cpu_model_name,
            ram_gb,
            sap_release,
            hana_release,
            hana_sid,
            sql_release,
            updated_at_utc
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(hostname) DO UPDATE SET
            os_release = excluded.os_release,
            kernel_release = excluded.kernel_release,
            cpu_cores = excluded.cpu_cores,
            cpu_model_name = excluded.cpu_model_name,
            ram_gb = excluded.ram_gb,
            sap_release = excluded.sap_release,
            hana_release = excluded.hana_release,
            hana_sid = excluded.hana_sid,
            sql_release = excluded.sql_release,
            updated_at_utc = excluded.updated_at_utc
        """,
        (
            hostname,
            new_snapshot["os_release"],
            new_snapshot["kernel_release"],
            new_snapshot["cpu_cores"],
            new_snapshot["cpu_model_name"],
            new_snapshot["ram_gb"],
            new_snapshot["sap_release"],
            new_snapshot["hana_release"],
            new_snapshot["hana_sid"],
            new_snapshot["sql_release"],
            detected_at_utc,
        ),
    )


def _extract_sap_addon_snapshot(payload: dict) -> dict[str, str]:
    sap_block = payload.get("sap_business_one") if isinstance(payload, dict) else None
    if not isinstance(sap_block, dict):
        return {}

    snapshot: dict[str, str] = {}

    def _clean_text(value: object) -> str:
        text = str(value or "").strip()
        if text.startswith('"'):
            text = text[1:].strip()
        if text.endswith('"'):
            text = text[:-1].strip()
        if text.startswith("'"):
            text = text[1:].strip()
        if text.endswith("'"):
            text = text[:-1].strip()
        return text

    def _looks_like_hdbsql_footer(raw_text: str) -> bool:
        lower = raw_text.strip().lower()
        return "rows selected" in lower or "overall time" in lower or "server time" in lower

    def _parse_combined_pair(raw_name: str) -> tuple[str, str] | None:
        candidates = [raw_name]
        if raw_name and not raw_name.startswith('"'):
            candidates.append(f'"{raw_name}')
        if raw_name and not raw_name.endswith('"'):
            candidates.append(f'{raw_name}"')
        if raw_name and not raw_name.startswith('"') and not raw_name.endswith('"'):
            candidates.append(f'"{raw_name}"')

        for candidate in candidates:
            try:
                parsed = next(csv.reader([candidate], skipinitialspace=True))
            except Exception:
                continue
            if len(parsed) < 2:
                continue
            left = _clean_text(parsed[0])
            right = _clean_text(parsed[1])
            if left:
                return left, right
        return None

    def _normalize_pair(name_value: object, version_value: object) -> tuple[str, str]:
        raw_name = str(name_value or "").strip()
        name = _clean_text(name_value)
        version = _clean_text(version_value)

        if _looks_like_hdbsql_footer(raw_name):
            return "", "-"

        # Some collectors delivered combined CSV-like pairs in the name field:
        #   "Addon Name","1.2.3"
        # Normalize those into clean name/version values.
        if not version or version in {"?", "-"}:
            parsed_pair = _parse_combined_pair(raw_name)
            if parsed_pair is not None:
                left, right = parsed_pair
                name = left or name
                version = right or version

        name = _clean_text(name)
        version = _clean_text(version)

        if _looks_like_hdbsql_footer(name):
            return "", "-"

        return name, (version or "-")

    ext_block = sap_block.get("extensions")
    ext_rows = ext_block.get("rows") if isinstance(ext_block, dict) else []
    if not isinstance(ext_rows, list):
        ext_rows = []
    for row in ext_rows:
        if not isinstance(row, dict):
            continue
        addon_name, addon_version = _normalize_pair(row.get("AddOnName"), row.get("Version"))
        if not addon_name:
            continue
        snapshot[f"extensions::{addon_name}"] = addon_version

    sari_block = sap_block.get("sari_addons")
    sari_rows = sari_block.get("rows") if isinstance(sari_block, dict) else []
    if not isinstance(sari_rows, list):
        sari_rows = []
    for row in sari_rows:
        if not isinstance(row, dict):
            continue
        addon_name, addon_version = _normalize_pair(row.get("AName"), row.get("AddOnVer"))
        if not addon_name:
            continue
        snapshot[f"sari::{addon_name}"] = addon_version

    hana_block = payload.get("hana_addons") if isinstance(payload, dict) else None
    if isinstance(hana_block, dict):
        hana_lw_rows = hana_block.get("lightweight")
        if not isinstance(hana_lw_rows, list):
            hana_lw_rows = []
        for row in hana_lw_rows:
            if not isinstance(row, dict):
                continue
            addon_name, addon_version = _normalize_pair(row.get("name"), row.get("version"))
            if not addon_name:
                continue
            snapshot[f"hana_extensions::{addon_name}"] = addon_version

        hana_legacy_rows = hana_block.get("legacy")
        if not isinstance(hana_legacy_rows, list):
            hana_legacy_rows = []
        for row in hana_legacy_rows:
            if not isinstance(row, dict):
                continue
            addon_name, addon_version = _normalize_pair(row.get("name"), row.get("version"))
            if not addon_name:
                continue
            snapshot[f"hana_sari::{addon_name}"] = addon_version

        tenant_rows = hana_block.get("tenants")
        if not isinstance(tenant_rows, list):
            tenant_rows = []
        for tenant_row in tenant_rows:
            if not isinstance(tenant_row, dict):
                continue
            tenant_id = _clean_text(tenant_row.get("tenant_id"))
            tenant_prefix = f"tenant{tenant_id}::" if tenant_id else "tenant::"
            tenant_result = tenant_row.get("result") if isinstance(tenant_row.get("result"), dict) else tenant_row

            tenant_lw_rows = tenant_result.get("lightweight")
            if not isinstance(tenant_lw_rows, list):
                tenant_lw_rows = []
            for row in tenant_lw_rows:
                if not isinstance(row, dict):
                    continue
                addon_name, addon_version = _normalize_pair(row.get("name"), row.get("version"))
                if not addon_name:
                    continue
                snapshot[f"hana_extensions::{tenant_prefix}{addon_name}"] = addon_version

            tenant_legacy_rows = tenant_result.get("legacy")
            if not isinstance(tenant_legacy_rows, list):
                tenant_legacy_rows = []
            for row in tenant_legacy_rows:
                if not isinstance(row, dict):
                    continue
                addon_name, addon_version = _normalize_pair(row.get("name"), row.get("version"))
                if not addon_name:
                    continue
                snapshot[f"hana_sari::{tenant_prefix}{addon_name}"] = addon_version

    return snapshot


def _describe_sap_addon_key(addon_name: str) -> tuple[str, str]:
    label_source = "Lightweight Extension"
    plain_name = addon_name
    if addon_name.startswith("extensions::"):
        plain_name = addon_name.split("::", 1)[1]
        label_source = "LW"
    elif addon_name.startswith("sari::"):
        plain_name = addon_name.split("::", 1)[1]
        label_source = "Legacy"
    elif addon_name.startswith("hana_extensions::"):
        plain_name = addon_name.split("::", 1)[1]
        label_source = "HANA LW"
    elif addon_name.startswith("hana_sari::"):
        plain_name = addon_name.split("::", 1)[1]
        label_source = "HANA Legacy"

    if plain_name:
        plain_name = re.sub(r"(?i)^tenant", "", plain_name)
        plain_name = plain_name.replace("::", ":").lstrip(":")
    return label_source, plain_name


def _collect_sap_addon_change_items_for_host(conn: sqlite3.Connection, hostname: str) -> list[dict]:
    rows = conn.execute(
        """
        SELECT id, received_at_utc, payload_json
        FROM reports
        WHERE hostname = ?
        ORDER BY id ASC
        """,
        (hostname,),
    ).fetchall()

    previous_snapshot: dict[str, str] | None = None
    changes: list[dict] = []

    for row in rows:
        report_id = int(row[0] or 0)
        detected_at_utc = str(row[1] or "")
        payload = parse_payload_json(str(row[2] or "{}"))
        current_snapshot = _extract_sap_addon_snapshot(payload)

        if previous_snapshot is not None:
            addon_names = sorted(set(previous_snapshot.keys()) | set(current_snapshot.keys()), key=lambda x: x.lower())
            for addon_name in addon_names:
                old_version = str(previous_snapshot.get(addon_name, "-") or "-")
                new_version = str(current_snapshot.get(addon_name, "-") or "-")
                if old_version == new_version:
                    continue

                label_source, plain_name = _describe_sap_addon_key(addon_name)
                changes.append(
                    {
                        "id": report_id,
                        "detected_at_utc": detected_at_utc,
                        "field_key": f"sap_addon::{addon_name}",
                        "field_label": f"{label_source}: {plain_name}",
                        "old_value": old_version,
                        "new_value": new_version,
                        "source": "agent-report:addon",
                    }
                )

        previous_snapshot = current_snapshot

    changes.sort(key=lambda item: (str(item.get("detected_at_utc") or ""), int(item.get("id") or 0)), reverse=True)
    return changes


def _collect_sap_addon_change_items(conn: sqlite3.Connection, hours: int, limit: int) -> list[dict]:
    cutoff_iso = (datetime.now(timezone.utc) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    rows = conn.execute(
        """
        SELECT r.id,
               r.received_at_utc,
               r.hostname,
               r.payload_json,
               COALESCE(h.display_name_override, ''),
               COALESCE(h.country_code_override, ''),
               COALESCE(cust.customer_name, '')
        FROM reports r
        LEFT JOIN host_settings h ON h.hostname = r.hostname
        LEFT JOIN customers cust ON cust.id = h.customer_id
        WHERE r.received_at_utc >= ?
        ORDER BY r.hostname COLLATE NOCASE ASC, r.id ASC
        """,
        (cutoff_iso,),
    ).fetchall()

    previous_by_host: dict[str, dict[str, str]] = {}
    changes: list[dict] = []

    for row in rows:
        report_id = int(row[0] or 0)
        detected_at_utc = str(row[1] or "")
        hostname = str(row[2] or "").strip()
        if not hostname:
            continue

        payload = parse_payload_json(str(row[3] or "{}"))
        current_snapshot = _extract_sap_addon_snapshot(payload)
        previous_snapshot = previous_by_host.get(hostname)

        if previous_snapshot is not None:
            addon_names = sorted(set(previous_snapshot.keys()) | set(current_snapshot.keys()), key=lambda x: x.lower())
            for addon_name in addon_names:
                old_version = str(previous_snapshot.get(addon_name, "-") or "-")
                new_version = str(current_snapshot.get(addon_name, "-") or "-")
                if old_version == new_version:
                    continue

                label_source, plain_name = _describe_sap_addon_key(addon_name)

                display_override = str(row[4] or "").strip()
                country_code = normalize_country_code(str(row[5] or ""))
                customer_name = str(row[6] or "").strip()
                changes.append(
                    {
                        "id": report_id,
                        "detected_at_utc": detected_at_utc,
                        "hostname": hostname,
                        "display_name": display_override or hostname,
                        "customer_name": customer_name,
                        "field_key": f"sap_addon::{addon_name}",
                        "field_label": f"{label_source}: {plain_name}",
                        "old_value": old_version,
                        "new_value": new_version,
                        "source": "agent-report:addon",
                        "country_code": country_code,
                    }
                )
        # No synthetic "init" entries: changelog should only show real deltas.

        previous_by_host[hostname] = current_snapshot

    changes.sort(key=lambda item: (str(item.get("detected_at_utc") or ""), int(item.get("id") or 0)), reverse=True)
    return changes[:limit]


def collect_host_config_changes(conn: sqlite3.Connection, hours: int = 24, limit: int = 300) -> dict:
    window_hours = max(1, int(hours or 24))
    row_limit = max(1, min(int(limit or 300), 1000))
    cutoff_iso = (datetime.now(timezone.utc) - timedelta(hours=window_hours)).strftime("%Y-%m-%dT%H:%M:%SZ")

    rows = conn.execute(
        """
        SELECT chg.id,
               chg.detected_at_utc,
               chg.hostname,
               COALESCE(h.display_name_override, ''),
               chg.field_key,
               chg.old_value,
               chg.new_value,
               COALESCE(chg.source, 'agent-report'),
               COALESCE(h.country_code_override, ''),
               COALESCE(cust.customer_name, '')
        FROM host_config_changes chg
        LEFT JOIN host_settings h ON h.hostname = chg.hostname
        LEFT JOIN customers cust ON cust.id = h.customer_id
        WHERE chg.detected_at_utc >= ?
        ORDER BY chg.detected_at_utc DESC, chg.id DESC
        LIMIT ?
        """,
        (cutoff_iso, row_limit),
    ).fetchall()

    items = []
    for row in rows:
        hostname = str(row[2] or "")
        display_override = str(row[3] or "").strip()
        country_code = normalize_country_code(str(row[8] or ""))
        customer_name = str(row[9] or "").strip()
        items.append(
            {
                "id": int(row[0] or 0),
                "detected_at_utc": str(row[1] or ""),
                "hostname": hostname,
                "display_name": display_override or hostname,
                "customer_name": customer_name,
                "field_key": str(row[4] or ""),
                "field_label": HOST_CONFIG_FIELD_LABELS.get(str(row[4] or ""), str(row[4] or "")),
                "old_value": str(row[5] or "-"),
                "new_value": str(row[6] or "-"),
                "source": str(row[7] or "agent-report"),
                "country_code": country_code,
            }
        )

    addon_items = _collect_sap_addon_change_items(conn, window_hours, row_limit)
    if addon_items:
        items.extend(addon_items)

    db_items = _collect_database_lifecycle_change_items(conn, window_hours, row_limit)
    if db_items:
        items.extend(db_items)

    if addon_items or db_items:
        items.sort(key=lambda item: (str(item.get("detected_at_utc") or ""), int(item.get("id") or 0)), reverse=True)
        items = items[:row_limit]

    return {
        "hours": window_hours,
        "limit": row_limit,
        "count": len(items),
        "items": items,
    }


def backfill_host_config_changes(conn: sqlite3.Connection, days: int = 7) -> dict:
    _ensure_host_config_snapshot_schema(conn)

    window_days = max(1, int(days or 7))
    cutoff_iso = (datetime.now(timezone.utc) - timedelta(days=window_days)).strftime("%Y-%m-%dT%H:%M:%SZ")

    row_iter = conn.execute(
        """
        SELECT id, received_at_utc, hostname, payload_json
        FROM reports
        WHERE received_at_utc >= ?
        ORDER BY hostname COLLATE NOCASE ASC, id ASC
        """,
        (cutoff_iso,),
    )

    last_snapshot_by_host: dict[str, dict[str, str]] = {}
    last_seen_at_by_host: dict[str, str] = {}
    report_count = 0
    inserted_changes = 0

    for row in row_iter:
        report_id = int(row[0] or 0)
        detected_at_utc = str(row[1] or "").strip()
        hostname = str(row[2] or "").strip()
        if not hostname:
            continue
        payload = parse_payload_json(str(row[3] or "{}"))
        report_count += 1

        current_snapshot = {
            key: _normalize_config_value(key, value)
            for key, value in _extract_host_config_snapshot(payload).items()
        }
        previous_snapshot = last_snapshot_by_host.get(hostname)

        if previous_snapshot is not None:
            for field_key in HOST_CONFIG_TRACKED_FIELDS:
                old_value = previous_snapshot.get(field_key, "-")
                new_value = current_snapshot.get(field_key, "-")
                if not _is_significant_config_change(field_key, old_value, new_value):
                    continue

                existing = conn.execute(
                    """
                    SELECT 1
                    FROM host_config_changes
                    WHERE hostname = ?
                      AND field_key = ?
                      AND report_id = ?
                      AND old_value = ?
                      AND new_value = ?
                    LIMIT 1
                    """,
                    (hostname, field_key, report_id, old_value, new_value),
                ).fetchone()
                if existing:
                    continue

                conn.execute(
                    """
                    INSERT INTO host_config_changes (
                        detected_at_utc,
                        hostname,
                        field_key,
                        old_value,
                        new_value,
                        report_id,
                        source
                    )
                    VALUES (?, ?, ?, ?, ?, ?, 'backfill')
                    """,
                    (detected_at_utc or utc_now_iso(), hostname, field_key, old_value, new_value, report_id),
                )
                inserted_changes += 1

        last_snapshot_by_host[hostname] = current_snapshot
        last_seen_at_by_host[hostname] = detected_at_utc or utc_now_iso()

        if report_count % 1000 == 0:
            conn.commit()

    for hostname, snapshot in last_snapshot_by_host.items():
        updated_at_utc = last_seen_at_by_host.get(hostname, utc_now_iso())
        conn.execute(
            """
            INSERT INTO host_config_snapshot (
                hostname,
                os_release,
                kernel_release,
                cpu_cores,
                cpu_model_name,
                ram_gb,
                sap_release,
                hana_release,
                hana_sid,
                sql_release,
                updated_at_utc
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(hostname) DO UPDATE SET
                os_release = excluded.os_release,
                kernel_release = excluded.kernel_release,
                cpu_cores = excluded.cpu_cores,
                cpu_model_name = excluded.cpu_model_name,
                ram_gb = excluded.ram_gb,
                sap_release = excluded.sap_release,
                hana_release = excluded.hana_release,
                hana_sid = excluded.hana_sid,
                sql_release = excluded.sql_release,
                updated_at_utc = excluded.updated_at_utc
            """,
            (
                hostname,
                snapshot["os_release"],
                snapshot["kernel_release"],
                snapshot["cpu_cores"],
                snapshot["cpu_model_name"],
                snapshot["ram_gb"],
                snapshot["sap_release"],
                snapshot["hana_release"],
                snapshot["hana_sid"],
                snapshot["sql_release"],
                updated_at_utc,
            ),
        )

    return {
        "days": window_days,
        "reports_scanned": report_count,
        "hosts_touched": len(last_snapshot_by_host),
        "inserted_changes": inserted_changes,
    }


def collect_system_overview(conn: sqlite3.Connection) -> dict:
    latest_rows = _latest_report_rows_by_host_key(conn)
    if not latest_rows:
        return {"by_country": {}, "total": 0}

    hostnames = sorted({str(row[1] or "").strip() for row in latest_rows if str(row[1] or "").strip()})
    settings_rows = []
    if hostnames:
        placeholders = ",".join("?" for _ in hostnames)
        settings_rows = conn.execute(
            f"""
            SELECT h.hostname,
                   h.display_name_override,
                   COALESCE(h.country_code_override, ''),
                   COALESCE(c.customer_name, '')
            FROM host_settings h
            LEFT JOIN customers c ON c.id = h.customer_id
            WHERE hostname IN ({placeholders})
            """,
            tuple(hostnames),
        ).fetchall()
    override_names = {str(row[0] or ""): str(row[1] or "") for row in settings_rows}
    override_countries = {str(row[0] or ""): normalize_country_code(str(row[2] or "")) for row in settings_rows}
    customer_names = {str(row[0] or ""): str(row[3] or "").strip() for row in settings_rows}

    host_uid_keys = [str(row[0] or "").strip() for row in latest_rows if str(row[0] or "").strip()]
    host_uid_display_name_map: dict[str, str] = {}
    if host_uid_keys:
        placeholders = ",".join(["?"] * len(host_uid_keys))
        host_uid_rows = conn.execute(
            f"""
            SELECT host_uid, COALESCE(display_name_override, '')
            FROM host_uid_settings
            WHERE host_uid IN ({placeholders})
            """,
            tuple(host_uid_keys),
        ).fetchall()
        host_uid_display_name_map = {
            str(row[0] or "").strip(): str(row[1] or "").strip()
            for row in host_uid_rows
            if str(row[0] or "").strip()
        }

    now_utc = datetime.now(timezone.utc)
    by_country: dict[str, dict[str, dict[str, list[dict]]]] = {}

    for row in latest_rows:
        host_uid = str(row[0] or "").strip()
        hostname = str(row[1] or "").strip()
        if not hostname:
            continue
        received_at_utc = str(row[2] or "").strip()
        payload = parse_payload_json(str(row[3] or "{}"))

        display_name_override = str(host_uid_display_name_map.get(host_uid, "") or "").strip()
        if not display_name_override:
            display_name_override = str(override_names.get(hostname, "") or "").strip()
        display_name = effective_display_name(payload, display_name_override, hostname)

        country = override_countries.get(hostname, "") or extract_country_code_from_payload(payload) or "XX"
        os_family = normalize_os_family(payload.get("os", ""))
        customer = customer_names.get(hostname, "") or "Ohne Kunde"

        release_info = _extract_sap_hana_ram(payload)
        cpu_info = _extract_cpu_overview(payload)

        sql_release = _extract_sql_release(payload)

        online = False
        if received_at_utc:
            try:
                last_dt = datetime.fromisoformat(received_at_utc.replace("Z", "+00:00"))
                online = (now_utc - last_dt) <= timedelta(minutes=20)
            except ValueError:
                online = False

        country_bucket = by_country.setdefault(country, {})
        os_bucket = country_bucket.setdefault(os_family, {})
        customer_bucket = os_bucket.setdefault(customer, [])
        customer_bucket.append(
            {
                "host_uid": host_uid,
                "hostname": hostname,
                "display_name": display_name,
                "online": online,
                "sap_release": release_info["sap_release"],
                "hana_version": release_info["hana_version"],
                "hana_sid": release_info["hana_sid"],
                "sql_release": sql_release,
                "ram_gb": release_info["ram_gb"],
                "cpu_cores": cpu_info["cpu_cores"],
                "cpu_model_name": cpu_info["cpu_model_name"],
                "last_update": received_at_utc or "-",
                "payload": payload,
            }
        )

    return {
        "by_country": by_country,
        "total": sum(
            len(hosts)
            for os_bucket in by_country.values()
            for customer_bucket in os_bucket.values()
            for hosts in customer_bucket.values()
        ),
    }


def collect_backup_status_overview(conn: sqlite3.Connection, hours: int = 24) -> dict:
    latest_rows = _latest_report_rows_by_host_key(conn)
    if not latest_rows:
        return {"generated_at": utc_now_iso(), "hours": max(1, int(hours or 24)), "total": 0, "missing_count": 0, "items": []}

    hostnames = sorted({str(row[1] or "").strip() for row in latest_rows if str(row[1] or "").strip()})
    settings_map: dict[str, dict] = {}
    if hostnames:
        placeholders = ",".join("?" for _ in hostnames)
        settings_rows = conn.execute(
            f"""
            SELECT h.hostname,
                   COALESCE(h.display_name_override, ''),
                   COALESCE(h.country_code_override, ''),
                   h.customer_id,
                   COALESCE(c.customer_name, ''),
                   COALESCE(c.maringo_project_number, '')
            FROM host_settings h
            LEFT JOIN customers c ON c.id = h.customer_id
            WHERE h.hostname IN ({placeholders})
            """,
            tuple(hostnames),
        ).fetchall()
        settings_map = {
            str(row[0] or "").strip(): {
                "display_name_override": str(row[1] or "").strip(),
                "country_code_override": normalize_country_code(str(row[2] or "")),
                "customer_id": int(row[3]) if row[3] is not None else None,
                "customer_name": str(row[4] or "").strip(),
                "customer_project": str(row[5] or "").strip(),
            }
            for row in settings_rows
            if str(row[0] or "").strip()
        }

    host_uid_keys = [str(row[0] or "").strip() for row in latest_rows if str(row[0] or "").strip()]
    host_uid_display_name_map: dict[str, str] = {}
    if host_uid_keys:
        placeholders = ",".join(["?"] * len(host_uid_keys))
        host_uid_rows = conn.execute(
            f"""
            SELECT host_uid, COALESCE(display_name_override, '')
            FROM host_uid_settings
            WHERE host_uid IN ({placeholders})
            """,
            tuple(host_uid_keys),
        ).fetchall()
        host_uid_display_name_map = {
            str(row[0] or "").strip(): str(row[1] or "").strip()
            for row in host_uid_rows
            if str(row[0] or "").strip()
        }

    now_utc = datetime.now(timezone.utc)
    age_limit = timedelta(hours=max(1, int(hours or 24)))
    items: list[dict] = []

    for row in latest_rows:
        host_uid = str(row[0] or "").strip()
        hostname = str(row[1] or "").strip()
        if not hostname:
            continue
        received_at = str(row[2] or "").strip()
        payload = parse_payload_json(str(row[3] or "{}"))
        host_settings = settings_map.get(hostname, {})
        display_name_override = str(host_uid_display_name_map.get(host_uid, "") or "").strip()
        if not display_name_override:
            display_name_override = str(host_settings.get("display_name_override", "") or "").strip()
        display_name = effective_display_name(payload, display_name_override, hostname)
        country_override = normalize_country_code(str(host_settings.get("country_code_override", "") or ""))
        customer_id = host_settings.get("customer_id")
        customer_name = str(host_settings.get("customer_name", "") or "").strip()
        customer_project = str(host_settings.get("customer_project", "") or "").strip()
        country_code = country_override or extract_country_code_from_payload(payload) or ""
        country_code = normalize_country_code(country_code)

        last_dt = None
        if received_at:
            try:
                last_dt = datetime.fromisoformat(received_at.replace("Z", "+00:00"))
            except ValueError:
                last_dt = None
        is_recent_report = bool(last_dt and ((now_utc - last_dt) <= age_limit))

        dir_block = payload.get("dir_deep_listings") if isinstance(payload.get("dir_deep_listings"), dict) else {}
        directories = dir_block.get("entries") if isinstance(dir_block.get("entries"), list) else []
        if not directories:
            # Backward compatibility with older payload shape.
            directories = dir_block.get("directories") if isinstance(dir_block.get("directories"), list) else []

        directory_items: list[dict] = []
        for directory in directories:
            if not isinstance(directory, dict):
                continue
            subdirs = directory.get("subdirs") if isinstance(directory.get("subdirs"), list) else []
            for subdir in subdirs:
                if not isinstance(subdir, dict):
                    continue
                subdir_name = str(subdir.get("name") or "").strip()
                subdir_path = str(subdir.get("path") or "").strip() or subdir_name or "-"
                latest_mod = str(subdir.get("zip_latest_modified_utc") or "").strip()
                latest_dt = None
                if latest_mod:
                    try:
                        latest_dt = datetime.fromisoformat(latest_mod.replace("Z", "+00:00"))
                    except ValueError:
                        latest_dt = None
                has_today_backup = bool(latest_dt and ((now_utc - latest_dt) <= age_limit))

                newest_name = ""
                newest_modified = ""
                newest_size_bytes = 0
                newest_dt = None
                entries = subdir.get("items") if isinstance(subdir.get("items"), list) else []
                for entry in entries:
                    if not isinstance(entry, dict):
                        continue
                    mod = str(entry.get("modified_utc") or "").strip()
                    mod_dt = None
                    if mod:
                        try:
                            mod_dt = datetime.fromisoformat(mod.replace("Z", "+00:00"))
                        except ValueError:
                            mod_dt = None
                    if newest_dt is None or (mod_dt is not None and mod_dt > newest_dt):
                        newest_dt = mod_dt
                        newest_name = str(entry.get("name") or entry.get("path") or "").strip()
                        newest_modified = mod
                        try:
                            newest_size_bytes = int(entry.get("size_bytes") or 0)
                        except (TypeError, ValueError):
                            newest_size_bytes = 0

                directory_items.append(
                    {
                        "subdir_name": subdir_name or "-",
                        "subdir_path": subdir_path,
                        "has_today_backup": has_today_backup,
                        "newest_item_name": newest_name,
                        "newest_item_modified": newest_modified,
                        "newest_item_size_bytes": max(0, newest_size_bytes),
                        "source_type": "filesystem",
                    }
                )

        # Include SQL database backup status for non-system databases.
        sql_info = payload.get("sql_server_info") if isinstance(payload.get("sql_server_info"), dict) else {}
        sql_instances = sql_info.get("instances") if isinstance(sql_info.get("instances"), list) else []
        system_db_names = {"master", "model", "msdb", "tempdb"}
        sql_user_db_count = 0

        for instance in sql_instances:
            if not isinstance(instance, dict):
                continue
            instance_name = str(instance.get("name") or "").strip() or "MSSQLSERVER"
            databases = instance.get("databases") if isinstance(instance.get("databases"), list) else []

            for db in databases:
                if not isinstance(db, dict):
                    continue
                db_name = str(db.get("name") or "").strip()
                if not db_name:
                    continue
                if bool(db.get("system_db")) or db_name.lower() in system_db_names:
                    continue
                sql_user_db_count += 1

                backup_candidates = [
                    str(db.get("last_full_backup") or "").strip(),
                    str(db.get("last_diff_backup") or "").strip(),
                    str(db.get("last_log_backup") or "").strip(),
                    str(db.get("last_full_backup_utc") or "").strip(),
                    str(db.get("last_diff_backup_utc") or "").strip(),
                    str(db.get("last_log_backup_utc") or "").strip(),
                ]
                latest_backup_text = ""
                latest_backup_dt = None
                for candidate in backup_candidates:
                    if not candidate:
                        continue
                    try:
                        candidate_dt = datetime.fromisoformat(candidate.replace("Z", "+00:00"))
                    except ValueError:
                        continue
                    if latest_backup_dt is None or candidate_dt > latest_backup_dt:
                        latest_backup_dt = candidate_dt
                        latest_backup_text = candidate

                has_today_backup = bool(latest_backup_dt and ((now_utc - latest_backup_dt) <= age_limit))

                data_mb = int(db.get("data_mb") or 0)
                log_mb = int(db.get("log_mb") or 0)
                db_size_bytes = max(0, (data_mb + log_mb) * 1024 * 1024)
                recovery_model = str(db.get("recovery_model") or "").strip()
                db_state = str(db.get("state") or "").strip()

                directory_items.append(
                    {
                        "subdir_name": f"SQL DB: {db_name}",
                        "subdir_path": f"{instance_name}/{db_name}",
                        "has_today_backup": has_today_backup,
                        "newest_item_name": f"{instance_name} · {db_state or '-'} · {recovery_model or '-'}",
                        "newest_item_modified": latest_backup_text,
                        "newest_item_size_bytes": db_size_bytes,
                        "source_type": "sql",
                    }
                )

        hana_info = payload.get("hana_info") if isinstance(payload.get("hana_info"), dict) else {}
        has_hana = bool(hana_info.get("available")) or bool(str(hana_info.get("sid") or "").strip())

        has_missing_backup = bool(directory_items) and any(not bool(item.get("has_today_backup")) for item in directory_items)
        items.append(
            {
                "host_uid": host_uid,
                "hostname": hostname,
                "display_name": display_name,
                "country_code": country_code,
                "customer_id": customer_id,
                "customer_name": customer_name,
                "customer_maringo_project_number": customer_project,
                "has_hana": has_hana,
                "has_sql": sql_user_db_count > 0,
                "sql_user_db_count": sql_user_db_count,
                "report_time_utc": received_at,
                "is_today_report": is_recent_report,
                "dirs": directory_items,
                "has_missing_backup": has_missing_backup,
            }
        )

    missing_count = sum(1 for item in items if bool(item.get("has_missing_backup")))
    return {
        "generated_at": utc_now_iso(),
        "hours": max(1, int(hours or 24)),
        "total": len(items),
        "missing_count": missing_count,
        "hosts": items,
    }


def collect_customer_overview(conn: sqlite3.Connection) -> dict:
    latest_rows = _latest_report_rows_by_host_key(conn)
    if not latest_rows:
        return {
            "generated_at": utc_now_iso(),
            "total_customers": 0,
            "total_hosts": 0,
            "customers": [],
        }

    hostnames = sorted({str(row[1] or "").strip() for row in latest_rows if str(row[1] or "").strip()})
    settings_map: dict[str, dict] = {}
    if hostnames:
        placeholders = ",".join("?" for _ in hostnames)
        settings_rows = conn.execute(
            f"""
            SELECT h.hostname,
                   COALESCE(h.display_name_override, ''),
                   COALESCE(h.country_code_override, ''),
                   COALESCE(h.is_hidden, 0),
                   h.customer_id,
                   COALESCE(c.customer_name, ''),
                   COALESCE(c.maringo_project_number, '')
            FROM host_settings h
            LEFT JOIN customers c ON c.id = h.customer_id
            WHERE h.hostname IN ({placeholders})
            """,
            tuple(hostnames),
        ).fetchall()
        settings_map = {
            str(row[0] or "").strip(): {
                "display_name_override": str(row[1] or "").strip(),
                "country_code_override": normalize_country_code(str(row[2] or "")),
                "is_hidden": bool(int(row[3] or 0)),
                "customer_id": int(row[4]) if row[4] is not None else None,
                "customer_name": str(row[5] or "").strip(),
                "customer_project": str(row[6] or "").strip(),
            }
            for row in settings_rows
            if str(row[0] or "").strip()
        }

    host_uid_keys = [str(row[0] or "").strip() for row in latest_rows if str(row[0] or "").strip()]
    host_uid_display_name_map: dict[str, str] = {}
    if host_uid_keys:
        placeholders = ",".join(["?"] * len(host_uid_keys))
        host_uid_rows = conn.execute(
            f"""
            SELECT host_uid, COALESCE(display_name_override, '')
            FROM host_uid_settings
            WHERE host_uid IN ({placeholders})
            """,
            tuple(host_uid_keys),
        ).fetchall()
        host_uid_display_name_map = {
            str(row[0] or "").strip(): str(row[1] or "").strip()
            for row in host_uid_rows
            if str(row[0] or "").strip()
        }

    alert_counts_rows = conn.execute(
        """
        SELECT a.hostname,
               SUM(CASE WHEN a.status = 'open' THEN 1 ELSE 0 END) AS open_count,
               SUM(CASE WHEN a.status = 'open' AND a.severity = 'critical' THEN 1 ELSE 0 END) AS critical_count
        FROM alerts a
        WHERE NOT EXISTS (
          SELECT 1 FROM muted_alert_rules m
          WHERE m.hostname = a.hostname AND m.mountpoint = a.mountpoint
        )
        GROUP BY a.hostname
        """
    ).fetchall()
    alert_counts_by_host = {
        str(row[0] or ""): {
            "open": int(row[1] or 0),
            "critical": int(row[2] or 0),
        }
        for row in alert_counts_rows
        if str(row[0] or "").strip()
    }

    backup_overview = collect_backup_status_overview(conn, 24)
    backup_missing_by_host = {
        str(item.get("host_uid") or item.get("hostname") or ""): bool(item.get("has_missing_backup", False))
        for item in backup_overview.get("hosts", [])
        if isinstance(item, dict) and str(item.get("hostname") or "").strip()
    }

    grouped: dict[str, dict] = {}
    for row in latest_rows:
        host_uid = str(row[0] or "").strip()
        hostname = str(row[1] or "").strip()
        if not hostname:
            continue

        host_settings = settings_map.get(hostname, {})
        if bool(host_settings.get("is_hidden", False)):
            continue

        payload = parse_payload_json(str(row[3] or "{}"))
        display_name_override = str(host_uid_display_name_map.get(host_uid, "") or "").strip()
        if not display_name_override:
            display_name_override = str(host_settings.get("display_name_override", "") or "").strip()
        display_name = effective_display_name(payload, display_name_override, hostname)
        country_override = normalize_country_code(str(host_settings.get("country_code_override", "") or ""))
        country_code = country_override or extract_country_code_from_payload(payload)
        country_code = normalize_country_code(country_code)

        customer_name = str(host_settings.get("customer_name", "") or "").strip() or "Ohne Kunde"
        customer_key = customer_name.lower()
        customer_project = str(host_settings.get("customer_project", "") or "").strip()

        if customer_key not in grouped:
            grouped[customer_key] = {
                "customer_id": host_settings.get("customer_id"),
                "customer_name": customer_name,
                "maringo_project_number": customer_project,
                "hosts": [],
                "hosts_count": 0,
                "open_alert_count": 0,
                "critical_alert_count": 0,
                "missing_backup_count": 0,
            }
        elif customer_project and not grouped[customer_key].get("maringo_project_number"):
            grouped[customer_key]["maringo_project_number"] = customer_project
        elif grouped[customer_key].get("customer_id") is None and host_settings.get("customer_id") is not None:
            grouped[customer_key]["customer_id"] = host_settings.get("customer_id")

        alert_counts = alert_counts_by_host.get(hostname, {"open": 0, "critical": 0})
        has_missing_backup = bool(backup_missing_by_host.get(host_uid or hostname, False))

        grouped[customer_key]["hosts"].append(
            {
                "host_uid": host_uid,
                "hostname": hostname,
                "display_name": display_name,
                "country_code": country_code,
                "report_time_utc": str(row[2] or ""),
                "open_alert_count": int(alert_counts.get("open", 0)),
                "critical_alert_count": int(alert_counts.get("critical", 0)),
                "has_missing_backup": has_missing_backup,
            }
        )
        grouped[customer_key]["hosts_count"] += 1
        grouped[customer_key]["open_alert_count"] += int(alert_counts.get("open", 0))
        grouped[customer_key]["critical_alert_count"] += int(alert_counts.get("critical", 0))
        if has_missing_backup:
            grouped[customer_key]["missing_backup_count"] += 1

    customers = sorted(
        grouped.values(),
        key=lambda item: str(item.get("customer_name", "")).lower(),
    )
    for customer in customers:
        customer["hosts"] = sorted(
            customer.get("hosts", []),
            key=lambda host: (
                str(host.get("display_name", "")).lower(),
                str(host.get("hostname", "")).lower(),
            ),
        )

    return {
        "generated_at": utc_now_iso(),
        "total_customers": len(customers),
        "total_hosts": sum(int(item.get("hosts_count", 0)) for item in customers),
        "customers": customers,
    }


def export_alerts_rows(conn: sqlite3.Connection, *, status: str | None = None, severity: str | None = None) -> list[dict]:
    status_filter = str(status or "").strip().lower()
    if status_filter not in {"active", "resolved", "all"}:
        status_filter = "active"
    severity_filter = str(severity or "").strip().lower()
    if severity_filter not in {"warning", "critical", "all"}:
        severity_filter = "all"

    clauses = []
    params: list[object] = []
    if status_filter == "active":
        clauses.append("a.resolved_at_utc IS NULL")
    elif status_filter == "resolved":
        clauses.append("a.resolved_at_utc IS NOT NULL")
    if severity_filter != "all":
        clauses.append("a.severity = ?")
        params.append(severity_filter)

    where_sql = ""
    if clauses:
        where_sql = "WHERE " + " AND ".join(clauses)

    rows = conn.execute(
        f"""
        SELECT a.id,
               a.hostname,
               a.mountpoint,
               a.severity,
               a.used_percent,
               a.created_at_utc,
               COALESCE(a.last_seen_at_utc, ''),
               COALESCE(a.resolved_at_utc, '')
        FROM alerts a
        {where_sql}
        ORDER BY a.created_at_utc DESC, a.id DESC
        """,
        tuple(params),
    ).fetchall()
    blacklist_patterns = get_filesystem_blacklist_pattern_strings(conn)
    hostnames = sorted({str(row[1] or "") for row in rows if str(row[1] or "")})
    latest_usage_by_host = _collect_latest_report_usage_by_host(conn, hostnames)

    result: list[dict] = []
    for row in rows:
        hostname = str(row[1] or "")
        mountpoint = str(row[2] or "")
        if is_filesystem_blacklisted_by_patterns(mountpoint, blacklist_patterns):
            continue
        current_used_percent = None
        host_usage = latest_usage_by_host.get(hostname, {})
        if mountpoint:
            current_used_percent = host_usage.get(normalize_mountpoint_key(mountpoint))
        delta_used_percent = None
        if current_used_percent is not None:
            delta_used_percent = abs(float(current_used_percent) - float(row[4] or 0.0))
        result.append(
            {
                "id": int(row[0] or 0),
                "hostname": hostname,
                "mountpoint": mountpoint,
                "severity": str(row[3] or "warning"),
                "used_percent": float(row[4] or 0.0),
                "current_used_percent": current_used_percent,
                "delta_used_percent": delta_used_percent,
                "created_at_utc": str(row[5] or ""),
                "last_seen_at_utc": str(row[6] or ""),
                "resolved_at_utc": str(row[7] or ""),
            }
        )
    return result


def export_reports_rows(conn: sqlite3.Connection, hostname: str = "", host_uid: str = "", limit: int = 500) -> list[dict]:
    host = str(hostname or "").strip()
    host_key = str(host_uid or "").strip()
    limited = max(1, min(int(limit or 500), 2000))
    host_key_expr = reports_host_key_sql()
    if host_key:
        rows = conn.execute(
            f"""
            SELECT id, hostname, received_at_utc, payload_json, {host_key_expr}
            FROM reports
            WHERE {host_key_expr} = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (host_key, limited),
        ).fetchall()
    elif host:
        rows = conn.execute(
            """
            SELECT id, hostname, received_at_utc, payload_json, COALESCE(host_uid, '')
            FROM reports
            WHERE hostname = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (host, limited),
        ).fetchall()
    else:
        rows = conn.execute(
            f"""
            SELECT id, hostname, received_at_utc, payload_json, {host_key_expr}
            FROM reports
            ORDER BY id DESC
            LIMIT ?
            """,
            (limited,),
        ).fetchall()
    data: list[dict] = []
    for row in rows:
        data.append(
            {
                "id": int(row[0] or 0),
                "hostname": str(row[1] or ""),
                "received_at_utc": str(row[2] or ""),
                "payload": parse_payload_json(str(row[3] or "{}")),
                "host_uid": str(row[4] or ""),
            }
        )
    return data


def build_ai_troubleshoot_response(conn: sqlite3.Connection, hostname: str, metric: str, hours: int) -> dict:
    host = str(hostname or "").strip()
    metric_key = str(metric or "").strip().lower()
    window_hours = max(1, min(int(hours or 24), 168))

    def build_analysis_payload(
        *,
        severity: str,
        confidence: str,
        summary: str,
        probable_causes: list[str] | None = None,
        recommended_steps: list[str] | None = None,
        quick_checks: list[str] | None = None,
        code_snippets: list[dict] | None = None,
    ) -> dict:
        return {
            "severity": severity,
            "confidence": confidence,
            "summary": summary,
            "probable_causes": probable_causes or [],
            "recommended_steps": recommended_steps or [],
            "quick_checks": quick_checks or [],
            "code_snippets": code_snippets or [],
        }

    if not host:
        return {
            "context": {"hostname": host, "metric": metric_key, "window_hours": window_hours, "samples": 0},
            "analysis": build_analysis_payload(
                severity="info",
                confidence="hoch",
                summary="Kein Hostname angegeben.",
            ),
            "model": "local-rules-v1",
            "cached": False,
        }

    cutoff_iso = utc_hours_ago_iso(window_hours)
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
    last_payload: dict = {}
    latest_report_time_utc = ""
    for row in rows:
        payload = parse_payload_json(str(row[0] or "{}"))
        last_payload = payload
        value = None
        if metric_key == "cpu_usage_percent":
            value = extract_cpu_usage(payload)
        elif metric_key == "load_avg_1":
            value = extract_load1(payload)
        elif metric_key == "memory_used_percent":
            value = extract_memory_used_percent(payload)
        elif metric_key == "swap_used_percent":
            value = extract_swap_used_percent(payload)
        elif metric_key == "filesystem":
            fs_values: list[float] = []
            for item in payload.get("filesystems", []):
                if not isinstance(item, dict):
                    continue
                try:
                    fs_values.append(float(item.get("used_percent")))
                except (TypeError, ValueError):
                    continue
            if fs_values:
                value = max(fs_values)
        if value is None:
            continue
        values.append(max(0.0, min(float(value), 100.0 if metric_key != "load_avg_1" else float(value))))

    last_row = conn.execute(
        """
        SELECT received_at_utc, payload_json
        FROM reports
        WHERE hostname = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (host,),
    ).fetchone()
    if last_row:
        latest_report_time_utc = str(last_row[0] or "")
        if not last_payload:
            last_payload = parse_payload_json(str(last_row[1] or "{}"))

    os_family = normalize_os_family(last_payload.get("os", "linux"))
    process_names = []
    for proc in last_payload.get("processes", []):
        if isinstance(proc, dict):
            process_names.append(str(proc.get("name") or proc.get("process_name") or ""))
        else:
            process_names.append(str(proc or ""))
    has_hana_processes = any(re.search(r"\bhdb(indexserver|nameserver|scriptserver|xsengine|daemon|webdispatcher)\b", name, re.IGNORECASE) for name in process_names)

    if not values:
        return {
            "context": {
                "hostname": host,
                "metric": metric_key,
                "window_hours": window_hours,
                "samples": 0,
                "latest_report_time_utc": latest_report_time_utc,
                "os_family": os_family,
                "has_hana_processes": has_hana_processes,
            },
            "analysis": build_analysis_payload(
                severity="info",
                confidence="hoch",
                summary="Keine ausreichenden Messdaten im gewählten Zeitraum.",
                probable_causes=["Im gewählten Zeitfenster liegen keine verwertbaren Werte für diese Kennzahl vor."],
                recommended_steps=["Zeitraum vergroessern oder pruefen, ob der Agent aktuelle Reports liefert."],
            ),
            "model": "local-rules-v1",
            "cached": False,
        }

    latest = values[-1]
    avg = sum(values) / len(values)
    peak = max(values)
    if len(values) >= 4:
        recent = values[-max(2, len(values) // 3):]
        baseline = values[: max(2, len(values) // 3)]
        trend = (sum(recent) / len(recent)) - (sum(baseline) / len(baseline))
    else:
        trend = 0.0

    severity = "info"
    confidence = "mittel"
    summary = ""
    probable_causes: list[str] = []
    recommended_steps: list[str] = []
    quick_checks: list[str] = []
    code_snippets: list[dict] = []

    if metric_key == "filesystem":
        severity = "critical" if peak >= CRITICAL_THRESHOLD_PERCENT else ("warning" if peak >= WARNING_THRESHOLD_PERCENT else "info")
        confidence = "hoch" if len(values) >= 12 else "mittel"
        summary = (
            f"Filesystem-Analyse für {host}: aktuell {latest:.1f}%, Mittelwert {avg:.1f}%, Spitze {peak:.1f}%."
        )
        probable_causes = [
            "Ein oder mehrere Mountpoints laufen in eine hohe Belegung hinein.",
            "Alte Logs, Backups oder Snapshots belegen mehr Platz als erwartet.",
        ]
        if trend > 3.0:
            probable_causes.append("Die Auslastung steigt im betrachteten Zeitraum sichtbar an.")
        recommended_steps = [
            "Betroffene Mountpoints in der Filesystem-Ansicht nach aktueller Auslastung und Delta sortieren.",
            "Groesste Verzeichnisse/Dateien pruefen und mit den Backup- bzw. Snapshot-Routinen abgleichen.",
        ]
        quick_checks = [
            f"Aktuell: {latest:.1f}% | Peak: {peak:.1f}% | Samples: {len(values)}",
            "Pruefen, ob hohe Werte von Snapshot- oder Backup-Mountpoints stammen.",
        ]
        code_snippets = [
            {
                "shell": "bash",
                "title": "Groesste Verzeichnisse finden",
                "command": "du -xhd1 / | sort -h | tail -20",
                "description": "Zeigt die groessten Verzeichnisse auf dem betroffenen Mountpoint.",
            }
        ]
    elif metric_key == "load_avg_1":
        severity = "critical" if peak >= 4.0 else ("warning" if peak >= 2.0 else "info")
        confidence = "mittel"
        summary = f"Load-Analyse für {host}: aktuell {latest:.2f}, Mittelwert {avg:.2f}, Spitze {peak:.2f}."
        probable_causes = [
            "CPU-intensive Prozesse oder I/O-Wartezeiten treiben den Load Average hoch.",
            "Kurzfristige Jobs oder Backups koennen Lastspitzen ausloesen.",
        ]
        recommended_steps = [
            "Top CPU/IO Prozesse im gleichen Zeitfenster pruefen.",
            "Mit CPU-, Memory- und Filesystem-Trends gegenpruefen.",
        ]
        quick_checks = [f"Aktuell: {latest:.2f} | Peak: {peak:.2f} | Samples: {len(values)}"]
        code_snippets = [
            {
                "shell": "bash",
                "title": "Last live pruefen",
                "command": "uptime && top -b -n1 | head -30",
                "description": "Zeigt aktuellen Load Average und die aktivsten Prozesse.",
            }
        ]
    else:
        severity = "critical" if peak >= CRITICAL_THRESHOLD_PERCENT else ("warning" if peak >= WARNING_THRESHOLD_PERCENT else "info")
        confidence = "hoch" if len(values) >= 12 else "mittel"
        direction = "steigend" if trend > 3.0 else ("fallend" if trend < -3.0 else "seitwaerts")
        summary = (
            f"Trend-Analyse für {host}: aktuell {latest:.1f}%, Mittelwert {avg:.1f}%, Spitze {peak:.1f}%. Trend: {direction}."
        )
        probable_causes = [
            "Die Kennzahl zeigt über das Zeitfenster eine anhaltende Last oder wiederkehrende Peaks.",
            "Parallele Jobs, Speicherdruck oder Hintergrundprozesse koennen den Verlauf erklaeren.",
        ]
        recommended_steps = [
            "Benachbarte Metriken im gleichen Zeitraum vergleichen, um CPU/Memory/FS-Korrelationen zu sehen.",
            "Bei wiederkehrenden Peaks geplante Jobs oder Backups zeitlich abgleichen.",
        ]
        quick_checks = [f"Aktuell: {latest:.1f}% | Peak: {peak:.1f}% | Trend: {direction}"]

    return {
        "context": {
            "hostname": host,
            "metric": metric_key,
            "window_hours": window_hours,
            "samples": len(values),
            "latest": round(latest, 2),
            "average": round(avg, 2),
            "peak": round(peak, 2),
            "latest_report_time_utc": latest_report_time_utc,
            "os_family": os_family,
            "has_hana_processes": has_hana_processes,
        },
        "analysis": build_analysis_payload(
            severity=severity,
            confidence=confidence,
            summary=summary,
            probable_causes=probable_causes,
            recommended_steps=recommended_steps,
            quick_checks=quick_checks,
            code_snippets=code_snippets,
        ),
        "model": "local-rules-v1",
        "cached": False,
    }


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


def mail_branding_header_html(
    app_logo_uri: str,
    build_version: str,
    meta_text: str = "",
    customer_name: str = "",
    host_label: str = "",
) -> str:
    safe_meta = html.escape(str(meta_text or "").strip())
    safe_customer = html.escape(str(customer_name or "").strip())
    safe_host = html.escape(str(host_label or "").strip())
    customer_host_html = ""
    if safe_customer:
        host_html = (
            f"<div style='margin-top:4px;font-size:14px;font-weight:600;line-height:1.25;color:#5f7590;'>{safe_host}</div>"
            if safe_host
            else ""
        )
        customer_host_html = (
            "<div style='margin-top:12px;'>"
            f"<div style='font-size:34px;line-height:1.05;font-weight:800;letter-spacing:.2px;color:#17324d;'>{safe_customer}</div>"
            f"{host_html}"
            "</div>"
        )
    meta_html = (
        f"<div style='margin-top:10px;font-size:13px;color:#5f7590;'>{safe_meta}</div>"
        if safe_meta
        else ""
    )
    return (
        "<table role='presentation' cellpadding='0' cellspacing='0' border='0' style='border-collapse:collapse;width:100%;'>"
        "<tr>"
        "<td width='72' style='width:72px;padding:0 30px 0 0;vertical-align:middle;'>"
        f"<img src='{app_logo_uri}' alt='Monitoring' width='44' height='44' style='display:block;width:44px;height:44px;border:0;outline:none;text-decoration:none;'>"
        "</td>"
        "<td style='vertical-align:middle;'>"
        "<div style='font-size:20px;font-weight:900;letter-spacing:.4px;line-height:1.1;'>System Infoboard</div>"
        f"<div style='font-size:12px;font-weight:700;color:#5f7590;line-height:1.2;'>v{build_version}</div>"
        "</td>"
        "</tr>"
        "</table>"
        f"{customer_host_html}"
        f"{meta_html}"
    )


def branded_info_mail_html(
    username: str,
    title: str,
    body_html: str,
    customer_name: str = "",
    host_label: str = "",
) -> str:
    app_logo_uri = app_logo_data_uri()
    ang_logo_uri = ang_logo_data_uri()
    sap_logo_uri = sap_logo_data_uri()
    build_version = html.escape(read_build_version())
    header_meta = f"Benutzer: {username} | Zeit: {format_mail_datetime()}"
    return (
        "<html><body style='margin:0;background:#ffffff;font-family:Segoe UI,Arial,sans-serif;color:#0f172a;'>"
        "<div style='max-width:760px;margin:24px auto;background:#ffffff;border:1px solid #d9dce3;border-radius:14px;overflow:hidden;'>"
        "<div style='padding:18px 20px;background-color:#eaf4ff;background-image:linear-gradient(180deg,#f4faff,#e6f1ff);color:#17324d;border-bottom:1px solid #cfe0f5;'>"
        f"{mail_branding_header_html(app_logo_uri, build_version, header_meta, customer_name, host_label)}"
        f"<h2 style='margin:10px 0 0 0;font-size:22px;color:#17324d;'>{html.escape(title)}</h2>"
        "</div>"
        f"<div style='padding:18px 20px;font-size:14px;line-height:1.5;color:#1f2937;'>{body_html}</div>"
        f"<div style='padding:0 20px 16px 20px;'>{mail_footer_logos_html(sap_logo_uri, ang_logo_uri)}</div>"
        "</div>"
        "</body></html>"
    )


def trend_digest_html(username: str, warnings: list[dict], hours: int) -> str:
    app_logo_uri = app_logo_data_uri()
    ang_logo_uri = ang_logo_data_uri()
    sap_logo_uri = sap_logo_data_uri()
    build_version = html.escape(read_build_version())
    header_meta = f"Benutzer: {username} | Fenster: letzte {hours}h | Zeit: {format_mail_datetime()}"
    rows_html = "".join(
        (
            "<tr>"
            f"<td style='padding:10px 8px;border-bottom:1px solid #e2e8f0;text-align:left;vertical-align:middle;'><div style='font-weight:600;'>{html.escape(str(item.get('display_name') or item.get('hostname') or '-'))}</div><div style='margin-top:3px;font-size:12px;color:#64748b;'>Kunde: {html.escape(str(item.get('customer_name') or '-'))} | IP: {html.escape(str(item.get('primary_ip') or '-'))}</div>{host_badges_html(item.get('country_code', ''), item.get('os_family', 'linux'))}</td>"
            f"<td style='padding:10px 8px;border-bottom:1px solid #e2e8f0;text-align:left;vertical-align:middle;'>{html.escape(str(item.get('metric') or '-'))}</td>"
            f"<td style='padding:10px 8px;border-bottom:1px solid #e2e8f0;text-align:right;vertical-align:middle;font-variant-numeric:tabular-nums;'>{html.escape(str(item.get('current') if item.get('current') is not None else '-'))}%</td>"
            f"<td style='padding:10px 8px;border-bottom:1px solid #e2e8f0;text-align:right;vertical-align:middle;font-variant-numeric:tabular-nums;'><strong>{html.escape(str(item.get('projected') if item.get('projected') is not None else '-'))}%</strong></td>"
            f"<td style='padding:10px 8px;border-bottom:1px solid #e2e8f0;text-align:left;vertical-align:middle;'><span style='display:inline-block;padding:2px 8px;border-radius:999px;background:{'#fee2e2' if str(item.get('level')) == 'crit' else '#fef3c7'};color:{'#991b1b' if str(item.get('level')) == 'crit' else '#92400e'};font-weight:600;'>{'KRITISCH' if str(item.get('level')) == 'crit' else 'WARNUNG'}</span></td>"
            "</tr>"
        )
        for item in warnings
    )
    if not rows_html:
        rows_html = "<tr><td colspan='5' style='padding:12px 8px;text-align:left;color:#475569;'>Keine kritischen Trends im gewählten Zeitraum.</td></tr>"

    return (
        "<html><body style='margin:0;background:#ffffff;font-family:Segoe UI,Arial,sans-serif;color:#0f172a;'>"
        "<div style='max-width:900px;margin:24px auto;background:#ffffff;border:1px solid #d9dce3;border-radius:14px;overflow:hidden;'>"
        "<div style='padding:18px 20px;background-color:#eaf4ff;background-image:linear-gradient(180deg,#f4faff,#e6f1ff);color:#17324d;border-bottom:1px solid #cfe0f5;'>"
        f"{mail_branding_header_html(app_logo_uri, build_version, header_meta)}"
        "<h2 style='margin:0 0 6px 0;font-size:22px;color:#17324d;'>Daily Trend Digest</h2>"
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
        f"{mail_footer_logos_html(sap_logo_uri, ang_logo_uri)}"
        "</div>"
        "</div>"
        "</body></html>"
    )


def trend_digest_subject(warnings: list[dict], local_date: str) -> str:
    critical_count = sum(1 for item in warnings if str(item.get("level")) == "crit")
    warning_count = sum(1 for item in warnings if str(item.get("level")) == "warn")
    return f"[Monitoring] Trend Digest {local_date} (C:{critical_count} W:{warning_count})"


def alert_digest_html(username: str, alerts: list[dict], *, graph_cids: dict[int, str] | None = None, graph_hours: int = 24) -> str:
    app_logo_uri = app_logo_data_uri()
    ang_logo_uri = ang_logo_data_uri()
    sap_logo_uri = sap_logo_data_uri()
    build_version = html.escape(read_build_version())
    header_meta = f"Benutzer: {username} | Zeit: {format_mail_datetime()}"
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
            f"<td style='padding:10px 8px;border-bottom:1px solid #fde2e2;text-align:left;vertical-align:middle;'><div style='font-weight:600;'>{html.escape(str(item.get('display_name') or item.get('hostname') or '-'))}</div><div style='margin-top:3px;font-size:12px;color:#64748b;'>Kunde: {html.escape(str(item.get('customer_name') or 'Ohne Kunde'))} | IP: {html.escape(str(item.get('primary_ip') or '-'))}</div>{host_badges_html(item.get('country_code', ''), item.get('os_family', 'linux'))}</td>"
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
        f"{mail_branding_header_html(app_logo_uri, build_version, header_meta)}"
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
        f"{mail_footer_logos_html(sap_logo_uri, ang_logo_uri)}"
        "</div>"
        "</div>"
        "</body></html>"
    )


def alert_digest_subject(alerts: list[dict], local_date: str) -> str:
    critical_count = sum(1 for item in alerts if str(item.get("severity")) == "critical")
    warning_count = sum(1 for item in alerts if str(item.get("severity")) == "warning")
    return f"[Monitoring] Alert Digest {local_date} (C:{critical_count} W:{warning_count})"


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
    customer_name: str = "",
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
    host_title = display_name.strip() or hostname
    customer_title = str(customer_name or "").strip() or host_title
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
    sap_logo_uri = sap_logo_data_uri()
    build_version = html.escape(read_build_version())
    header_meta = f"Benutzer: {username} | Zeit: {format_mail_datetime()}"
    reported_at = format_mail_datetime(reported_at_utc)
    graph_alt = html.escape(f"Auslastungsverlauf {customer_title}: {mountpoint}")
    graph_block = (
        "<div style='margin-top:14px;'>"
        "<div style='margin:0 0 6px 0;font-size:12px;color:#64748b;'>Verlauf letzte 24h (Mountpoint-Auslastung)</div>"
        f"<img src='cid:{html.escape(graph_cid)}' alt='{graph_alt}' style='display:block;width:100%;max-width:620px;height:auto;border:1px solid #dbe3ef;border-radius:10px;background:#ffffff;'>"
        "</div>"
    ) if graph_cid else (
        "<div style='margin-top:14px;padding:10px 12px;border-radius:10px;background:#f8fafc;border:1px solid #dbe3ef;color:#64748b;font-size:12px;'>"
        "Keine Verlaufsgrafik verfügbar (zu wenig Datenpunkte).</div>"
    )
    return (
        "<html><body style='margin:0;background:#ffffff;font-family:Segoe UI,Arial,sans-serif;color:#0f172a;'>"
        "<div style='max-width:700px;margin:24px auto;background:#ffffff;border:1px solid #d9dce3;border-radius:14px;overflow:hidden;'>"
        "<div style='padding:18px 20px;background-color:#eaf4ff;background-image:linear-gradient(180deg,#f4faff,#e6f1ff);color:#17324d;border-bottom:1px solid #cfe0f5;'>"
        f"{mail_branding_header_html(app_logo_uri, build_version, header_meta, customer_title, host_title)}"
        f"<div style='margin-top:6px;font-size:13px;color:#5f7590;'>Technischer Host: {html.escape(hostname)}</div>"
        f"<div style='margin-top:4px;font-size:13px;color:#5f7590;'>IP: {html.escape(primary_ip or '-')}</div>"
        "<div style='margin-top:12px;display:flex;gap:8px;flex-wrap:wrap;'>"
        f"<span style='display:inline-flex;align-items:center;padding:3px 6px;border-radius:999px;background:transparent;'>{os_icon_html}</span>"
        f"<span style='display:inline-flex;align-items:center;padding:3px 6px;border-radius:999px;background:transparent;'>{country_icon_html}</span>"
        f"<span style='display:inline-flex;align-items:center;padding:4px 10px;border-radius:999px;background:{sev_bg};color:{sev_text};font-size:12px;font-weight:800;'>{sev_label}</span>"
        "</div>"
        "</div>"
        "<div style='padding:20px;'>"
        f"<h2 style='margin:0 0 14px 0;font-size:20px;color:#0f172a;'>{html.escape(event_label)}</h2>"
        "<table style='width:100%;border-collapse:collapse;font-size:14px;'>"
        "<tr><td style='padding:8px 0;color:#64748b;'>Mountpoint</td>"
        f"<td style='padding:8px 0;font-weight:600;'>{html.escape(mountpoint)}</td></tr>"
        "<tr><td style='padding:8px 0;color:#64748b;'>Gemeldet am</td>"
        f"<td style='padding:8px 0;font-weight:600;'>{html.escape(reported_at)}</td></tr>"
        "<tr><td style='padding:8px 0;color:#64748b;'>Auslastung</td>"
        f"<td style='padding:8px 0;font-weight:600;'>{used_str}%</td></tr>"
        "<tr><td style='padding:8px 0;color:#64748b;'>Schweregrad</td>"
        f"<td style='padding:8px 0;'><span style='display:inline-block;padding:2px 10px;border-radius:999px;background:{sev_bg};color:{sev_text};font-weight:700;font-size:12px;'>{sev_label}</span></td></tr>"
        "</table>"
        f"{graph_block}"
        f"{mail_footer_logos_html(sap_logo_uri, ang_logo_uri)}"
        "</div>"
        "</div>"
        "</body></html>"
    )


def inactive_hosts_mail_subject(hosts: list[dict], threshold_hours: int) -> str:
    count = len(hosts or [])
    label = "Host" if count == 1 else "Hosts"
    return f"[Monitoring] [KRITISCH] Inaktive {label}: {count} (>{threshold_hours}h)"


def inactive_hosts_mail_html(username: str, hosts: list[dict], threshold_hours: int) -> str:
    app_logo_uri = app_logo_data_uri()
    ang_logo_uri = ang_logo_data_uri()
    sap_logo_uri = sap_logo_data_uri()
    build_version = html.escape(read_build_version())
    header_meta = f"Benutzer: {username} | Schwellwert: {threshold_hours}h | Zeit: {format_mail_datetime()}"

    row_parts: list[str] = []
    for item in hosts:
        hostname = str(item.get("hostname") or "")
        display_name = str(item.get("display_name") or hostname)
        customer_name = str(item.get("customer_name") or "").strip()
        customer_label = customer_name or "Ohne Kunde"
        primary_ip = str(item.get("primary_ip") or "-")
        country_code = str(item.get("country_code") or "")
        os_value = str(item.get("os") or "")
        os_family = normalize_os_family(os_value)
        last_report_time_utc = str(item.get("last_report_time_utc") or "")
        hours_inactive = float(item.get("hours_inactive") or 0)
        row_parts.append(
            "<tr style='background:#fff1f2;'>"
            f"<td style='padding:10px 8px;border-bottom:1px solid #fde2e2;text-align:left;vertical-align:middle;'><div style='font-weight:700;'>{html.escape(customer_label)}</div><div style='margin-top:3px;font-size:12px;color:#334155;'>Anzeigename: {html.escape(display_name)}</div><div style='margin-top:3px;font-size:12px;color:#64748b;'>Host: {html.escape(hostname)} | IP: {html.escape(primary_ip)}</div>{host_badges_html(country_code, os_family)}</td>"
            f"<td style='padding:10px 8px;border-bottom:1px solid #fde2e2;text-align:left;vertical-align:middle;font-variant-numeric:tabular-nums;'>{html.escape(format_mail_datetime(last_report_time_utc))}</td>"
            f"<td style='padding:10px 8px;border-bottom:1px solid #fde2e2;text-align:right;vertical-align:middle;font-variant-numeric:tabular-nums;'><strong>{hours_inactive:.1f} h</strong></td>"
            "<td style='padding:10px 8px;border-bottom:1px solid #fde2e2;text-align:left;vertical-align:middle;'><span style='display:inline-block;padding:2px 8px;border-radius:999px;background:#fee2e2;color:#991b1b;font-weight:700;'>DOWN</span></td>"
            "</tr>"
        )
    rows_html = "".join(row_parts)
    if not rows_html:
        rows_html = "<tr><td colspan='4' style='padding:12px 8px;text-align:left;color:#475569;'>Keine inaktiven Hosts gefunden.</td></tr>"

    return (
        "<html><body style='margin:0;background:#ffffff;font-family:Segoe UI,Arial,sans-serif;color:#0f172a;'>"
        "<div style='max-width:900px;margin:24px auto;background:#ffffff;border:1px solid #d9dce3;border-radius:14px;overflow:hidden;'>"
        "<div style='padding:18px 20px;background-color:#eaf4ff;background-image:linear-gradient(180deg,#f4faff,#e6f1ff);color:#17324d;border-bottom:1px solid #cfe0f5;'>"
        f"{mail_branding_header_html(app_logo_uri, build_version, header_meta)}"
        "<h2 style='margin:0 0 6px 0;font-size:22px;color:#17324d;'>Inaktive Hosts Alert</h2>"
        "</div>"
        "<div style='padding:18px 20px;'>"
        f"<p style='margin:0 0 14px 0;font-size:14px;'>Es wurden <strong>{len(hosts)}</strong> Hosts ohne neue Meldung erkannt.</p>"
        "<table style='width:100%;border-collapse:collapse;font-size:13px;'>"
        "<thead><tr style='background:#f8fafc;'>"
        "<th style='text-align:left;padding:8px;border:1px solid #dbe3ef;'>Host</th>"
        "<th style='text-align:left;padding:8px;border:1px solid #dbe3ef;'>Letzte Meldung</th>"
        "<th style='text-align:right;padding:8px;border:1px solid #dbe3ef;'>Inaktiv seit</th>"
        "<th style='text-align:left;padding:8px;border:1px solid #dbe3ef;'>Status</th>"
        "</tr></thead>"
        f"<tbody>{rows_html}</tbody>"
        "</table>"
        "<p style='margin:12px 0 0 0;font-size:12px;color:#64748b;'>Hinweis: Ein Host gilt als inaktiv, wenn seit dem Schwellwert keine neue Meldung eingegangen ist.</p>"
        f"{mail_footer_logos_html(sap_logo_uri, ang_logo_uri)}"
        "</div>"
        "</div>"
        "</body></html>"
    )


def inactive_hosts_telegram_text(username: str, hosts: list[dict], threshold_hours: int) -> str:
    lines = [
        "System Infoboard",
        "",
        "🚨 Inaktive Hosts erkannt",
        "",
        f"👤 {username}",
        f"Schwellwert: {threshold_hours}h",
        f"Betroffene Hosts: {len(hosts)}",
        "",
    ]

    max_items = 10
    for idx, item in enumerate(hosts[:max_items], start=1):
        display_name = str(item.get("display_name") or item.get("hostname") or "-")
        customer_name = str(item.get("customer_name") or "").strip() or "Ohne Kunde"
        country = str(item.get("country_code") or "--")
        hours_inactive = float(item.get("hours_inactive") or 0)
        last_report = format_mail_datetime(str(item.get("last_report_time_utc") or ""))
        lines.append(
            f"{idx}) {customer_name} | {display_name} ({country}) - {hours_inactive:.1f}h inaktiv - letzte Meldung {last_report}"
        )

    remaining = len(hosts) - max_items
    if remaining > 0:
        lines.append(f"... +{remaining} weitere Hosts")

    lines.extend(["", "Bitte Host-Erreichbarkeit und Agent-Status pruefen."])
    return "\n".join(lines)


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
        all_recipients = resolve_user_alert_mail_recipients(user_settings, severity)
        if not all_recipients:
            continue
        try:
            ok_token, access_token, _err = ensure_microsoft_access_token(conn, username)
            if not ok_token:
                continue
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
                customer_name=str(host_context.get("customer_name", "") or ""),
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

    icon = {
        "opened": "🚨 ALERT OPEN",
        "escalated": "⬆️ ALERT ESCALATED",
        "resolved": "✅ ALERT RESOLVED",
    }.get(event_type, "⚠️ ALERT")
    host_ctx = collect_host_mail_context(conn, hostname)
    title = display_name.strip() if display_name.strip() else str(host_ctx.get("display_name") or hostname)
    customer_label = str(host_ctx.get("customer_name") or "").strip() or "Ohne Kunde"
    now_local = datetime.now().astimezone().strftime("%d.%m.%Y %H:%M")

    for row in rows:
        username = str(row[0] or "").strip()
        min_severity = str(row[1] or "warning").strip().lower()
        chat_id = str(row[2] or "").strip()
        if not username or not chat_id:
            continue
        if min_severity == "critical" and severity not in {"critical"}:
            continue

        sev_icon = {"critical": "🔴", "warning": "🟠", "ok": "🟢"}.get(severity, "⚪")
        text = (
            "System Infoboard\n"
            "\n"
            f"{icon}\n"
            f"👤 {username}\n"
            f"👥 {customer_label}\n"
            f"🖥️ {title} ({hostname})\n"
            f"📂 {mountpoint}\n"
            f"{sev_icon} {severity}\n"
            f"📊 {used_percent:.1f}%\n"
            f"🕐 {now_local}"
        )
        reply_markup = build_telegram_alert_reply_markup(bot_token, hostname, mountpoint, event_type)
        telegram_send_to_chat(bot_token, chat_id, text, reply_markup=reply_markup)


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


def build_user_mail_logic_help() -> dict:
    return {
        "channels": {
            "title": "Mailversand über Microsoft OAuth",
            "items": [
                "Global muss zuerst die Microsoft OAuth App im Admin-Bereich konfiguriert und aktiviert sein.",
                "Zusätzlich muss jeder Benutzer sein eigenes Microsoft-Konto verbinden. Gesendet wird über dieses Benutzerkonto via Microsoft Graph.",
                "Mailversand für mich aktivieren schaltet nur die persönliche Versandfreigabe ein. Ohne Mail-Empfänger und ohne OAuth-Verbindung wird nichts versendet.",
                "Die Empfänger-Adresse hier ist die Basisadresse für Trend-Mail, Alert-Digest und Instant-Alert-Mail.",
            ],
        },
        "trend_digest": {
            "title": "Trend Mail Logik",
            "items": [
                "Der Versand läuft einmal pro Tag zur eingestellten Zeit in der festen Zeitzone Europe/Zurich.",
                "Voraussetzungen: persönlicher Mailversand aktiv, Mail-Empfänger gesetzt, Trend-Mail aktiv und Microsoft-OAuth verbunden.",
                "Hidden Mountpoints aus Kritische Trends und FS-Focus werden im Digest nicht gezeigt.",
                "Die Host-Auswahl folgt den gespeicherten Host-Interessen: Alle Hosts, Interessante Hosts zuerst oder Nur interessante Hosts.",
                "Interessante Hosts zuerst priorisiert nur die Sortierung. Nur interessante Hosts filtert den Digest inhaltlich auf diese Hosts ein.",
            ],
        },
        "alert_digest": {
            "title": "Alarm Digest Logik",
            "items": [
                "Der Alarm-Digest läuft einmal pro Tag zur eingestellten Zeit in Europe/Zurich.",
                "Voraussetzungen: persönlicher Mailversand aktiv, Basis-Empfänger gesetzt, Alarm-Mail aktiv und Microsoft-OAuth verbunden.",
                "Weitere Alarm Empfänger erweitern die Versandliste für diesen Digest zusätzlich zur Basisadresse.",
                "Der Inhalt respektiert jetzt die Mail-Host-Abos des Benutzers: nur Hosts mit aktiviertem Mail-Abo erscheinen im Alert-Digest.",
                "Wenn Empfänger nur für Warnung oder nur für Kritisch gesetzt sind, ersetzen diese Listen für den entsprechenden Schweregrad die Standard-Empfänger vollständig.",
            ],
        },
        "instant_alerts": {
            "title": "Sofort-Alerts per Mail und Telegram",
            "items": [
                "Sofort-Alerts reagieren auf einzelne Events: Alarm ausgeloest, eskaliert oder behoben.",
                "Mail respektiert pro Benutzer: Mailversand aktiv, Basis-Empfänger vorhanden, Instant-Mail aktiv, Mindest-Schweregrad passend und Mail-Host-Abo für den betroffenen Host gesetzt.",
                "Wenn für Warnung oder Kritisch eigene Empfängerlisten hinterlegt sind, ersetzen diese für Sofort-Mails die Standard-Empfänger des jeweiligen Schweregrads.",
                "Telegram respektiert pro Benutzer: Instant-Telegram aktiv, persönliche Chat-ID gesetzt, Mindest-Schweregrad passend und Telegram-Host-Abo für den betroffenen Host gesetzt.",
                "Telegram braucht zusätzlich global aktiviertes Telegram und einen global hinterlegten Bot-Token im Alarm-Setup.",
                "Die persönliche Chat-ID ist benutzerspezifisch. Bot-Token und Telegram global an/aus sind systemweit.",
            ],
        },
    }

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
        "display_name": user["display_name"],
        "is_admin": user["is_admin"],
        "is_disabled": user["is_disabled"],
        "created_at_utc": user["created_at_utc"],
        "updated_at_utc": user["updated_at_utc"],
        "email_enabled": settings["email_enabled"],
        "email_recipient": settings["email_recipient"],
        "email_sender": settings["email_sender"],
        "trend_email_enabled": settings["trend_email_enabled"],
        "trend_email_time_hhmm": settings["trend_email_time_hhmm"],
        "alert_email_enabled": settings["alert_email_enabled"],
        "alert_email_time_hhmm": settings["alert_email_time_hhmm"],
        "alert_email_recipients": settings["alert_email_recipients"],
        "alert_warning_email_recipients": settings["alert_warning_email_recipients"],
        "alert_critical_email_recipients": settings["alert_critical_email_recipients"],
        "alert_instant_mail_enabled": settings["alert_instant_mail_enabled"],
        "alert_instant_min_severity": settings["alert_instant_min_severity"],
        "alert_instant_telegram_enabled": settings["alert_instant_telegram_enabled"],
        "alert_telegram_chat_id": settings["alert_telegram_chat_id"],
        "backup_email_enabled": settings["backup_email_enabled"],
        "backup_email_time_hhmm": settings["backup_email_time_hhmm"],
        "backup_email_recipients": settings["backup_email_recipients"],
        "mail_oauth_available": oauth_is_configured(oauth_settings),
        "microsoft_oauth": {
            "connected": connection is not None,
            "external_email": connection["external_email"] if connection else "",
            "external_display_name": connection["external_display_name"] if connection else "",
            "expires_at_utc": connection["expires_at_utc"] if connection else "",
            "updated_at_utc": connection["updated_at_utc"] if connection else "",
        },
        "mail_logic_help": build_user_mail_logic_help(),
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
    sender_address: str = "",
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
    normalized_sender = str(sender_address or "").strip()
    if normalized_sender:
        message_payload["from"] = {
            "emailAddress": {
                "address": normalized_sender,
            }
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
    sender_address: str = "",
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
            sender_address=sender_address,
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
    mail_interval_hours = int(alarm_settings.get("alert_reminder_interval_hours") or 0)
    telegram_interval_hours = int(alarm_settings.get("alert_telegram_reminder_interval_hours") or 0)
    if mail_interval_hours <= 0 and telegram_interval_hours <= 0:
        return

    now_utc_dt = datetime.now(timezone.utc)
    cutoff_mail_iso = (now_utc_dt - timedelta(hours=mail_interval_hours)).strftime("%Y-%m-%dT%H:%M:%SZ") if mail_interval_hours > 0 else ""
    cutoff_telegram_iso = (now_utc_dt - timedelta(hours=telegram_interval_hours)).strftime("%Y-%m-%dT%H:%M:%SZ") if telegram_interval_hours > 0 else ""

    open_alerts = conn.execute(
        """
        SELECT id, hostname, mountpoint, severity, used_percent,
               created_at_utc, last_reminder_sent_utc, last_telegram_reminder_sent_utc
        FROM alerts
        WHERE status = 'open'
        ORDER BY CASE severity WHEN 'critical' THEN 0 ELSE 1 END, used_percent DESC
        """
    ).fetchall()

    if not open_alerts:
        return

    now_utc_iso = now_utc_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    host_context_cache: dict[str, dict] = {}
    blacklist_patterns = get_filesystem_blacklist_pattern_strings(conn)

    try:
        mail_user_rows = conn.execute(
            """
            SELECT u.username, COALESCE(s.alert_instant_min_severity, 'warning')
            FROM web_users u
            JOIN web_user_settings s ON s.username = u.username
            WHERE COALESCE(u.is_disabled, 0) = 0
              AND COALESCE(s.alert_instant_mail_enabled, 0) = 1
              AND COALESCE(s.email_enabled, 0) = 1
              AND COALESCE(s.email_recipient, '') != ''
            """
        ).fetchall() if mail_interval_hours > 0 else []
    except Exception:
        mail_user_rows = []

    telegram_enabled = bool(alarm_settings.get("telegram_enabled"))
    telegram_bot_token = str(alarm_settings.get("telegram_bot_token", "") or "").strip()
    telegram_channel_available = telegram_interval_hours > 0 and telegram_enabled and bool(telegram_bot_token)

    try:
        telegram_user_rows = conn.execute(
            """
            SELECT u.username,
                   COALESCE(s.alert_instant_min_severity, 'warning'),
                   COALESCE(s.alert_telegram_chat_id, '')
            FROM web_users u
            JOIN web_user_settings s ON s.username = u.username
            WHERE COALESCE(u.is_disabled, 0) = 0
              AND COALESCE(s.alert_instant_telegram_enabled, 0) = 1
              AND COALESCE(s.alert_telegram_chat_id, '') != ''
            """
        ).fetchall() if telegram_channel_available else []
    except Exception:
        telegram_user_rows = []

    if not mail_user_rows and not telegram_user_rows:
        return

    for alert_row in open_alerts:
        alert_id = int(alert_row[0])
        hostname = str(alert_row[1] or "")
        mountpoint = str(alert_row[2] or "")
        severity = str(alert_row[3] or "warning")
        used_percent = float(alert_row[4] or 0)
        created_at_utc = str(alert_row[5] or "")
        last_mail_reminder_sent_utc = str(alert_row[6] or "")
        last_telegram_reminder_sent_utc = str(alert_row[7] or "")

        due_mail = (
            mail_interval_hours > 0
            and created_at_utc <= cutoff_mail_iso
            and (not last_mail_reminder_sent_utc or last_mail_reminder_sent_utc <= cutoff_mail_iso)
        )
        due_telegram = (
            telegram_channel_available
            and created_at_utc <= cutoff_telegram_iso
            and (not last_telegram_reminder_sent_utc or last_telegram_reminder_sent_utc <= cutoff_telegram_iso)
        )

        if not due_mail and not due_telegram:
            continue

        if is_filesystem_blacklisted_by_patterns(mountpoint, blacklist_patterns):
            conn.execute(
                "UPDATE alerts SET status = 'resolved', resolved_at_utc = ?, last_seen_at_utc = ? WHERE id = ?",
                (now_utc_iso, now_utc_iso, alert_id),
            )
            conn.execute("DELETE FROM alert_debounce WHERE hostname = ? AND mountpoint = ?", (hostname, mountpoint))
            continue

        if hostname not in host_context_cache:
            host_context_cache[hostname] = collect_host_mail_context(conn, hostname)
        host_ctx = host_context_cache[hostname]

        reported_row = conn.execute(
            "SELECT created_at_utc FROM alerts WHERE id = ?",
            (alert_id,),
        ).fetchone()
        reported_at_utc = str(reported_row[0] or "") if reported_row else now_utc_iso

        sent_mail_to_anyone = False
        sent_telegram_to_anyone = False

        if due_mail:
            for urow in mail_user_rows:
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
                all_recipients = resolve_user_alert_mail_recipients(user_settings, severity)
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
                        customer_name=str(host_ctx.get("customer_name", "") or ""),
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
                        sender_address=str(user_settings.get("email_sender", "") or "").strip(),
                    )
                    sent_mail_to_anyone = True
                except Exception:
                    pass

        if due_telegram:
            title = str(host_ctx.get("display_name", "") or "").strip() or hostname
            customer_label = str(host_ctx.get("customer_name", "") or "").strip() or "Ohne Kunde"
            now_local = datetime.now().astimezone().strftime("%d.%m.%Y %H:%M")
            sev_icon = {"critical": "🔴", "warning": "🟠", "ok": "🟢"}.get(severity, "⚪")

            for trow in telegram_user_rows:
                username = str(trow[0] or "").strip()
                min_severity = str(trow[1] or "warning").strip().lower()
                chat_id = str(trow[2] or "").strip()
                if not username or not chat_id:
                    continue
                if min_severity == "critical" and severity != "critical":
                    continue

                sub = conn.execute(
                    "SELECT notify_telegram FROM web_user_alert_subscriptions WHERE username = ? AND hostname = ?",
                    (username, hostname),
                ).fetchone()
                if not sub or not bool(sub[0]):
                    continue

                text = (
                    "⏰ HEADS-UP REMINDER\n"
                    f"👤 {username}\n"
                    f"👥 {customer_label}\n"
                    f"🖥️ {title} ({hostname})\n"
                    f"📂 {mountpoint}\n"
                    f"{sev_icon} {severity}\n"
                    f"📊 {used_percent:.1f}%\n"
                    f"🕐 {now_local}"
                )

                try:
                    reply_markup = build_telegram_alert_reply_markup(telegram_bot_token, hostname, mountpoint, "reminder")
                    telegram_ok, _telegram_details = telegram_send_to_chat(
                        telegram_bot_token,
                        chat_id,
                        text,
                        reply_markup=reply_markup,
                    )
                    if telegram_ok:
                        sent_telegram_to_anyone = True
                except Exception:
                    pass

        if sent_mail_to_anyone:
            conn.execute(
                "UPDATE alerts SET last_reminder_sent_utc = ? WHERE id = ?",
                (now_utc_iso, alert_id),
            )
        if sent_telegram_to_anyone:
            conn.execute(
                "UPDATE alerts SET last_telegram_reminder_sent_utc = ? WHERE id = ?",
                (now_utc_iso, alert_id),
            )


def maybe_send_inactive_host_notifications(conn: sqlite3.Connection) -> None:
    alarm_settings = get_alarm_settings(conn)
    if not bool(alarm_settings.get("inactive_host_alert_enabled", False)):
        return

    try:
        threshold_hours = int(alarm_settings.get("inactive_host_alert_hours", 3) or 3)
    except (TypeError, ValueError):
        threshold_hours = 3
    threshold_hours = max(1, min(168, threshold_hours))

    inactive_hosts = collect_inactive_hosts(conn, threshold_hours)
    if not inactive_hosts:
        return

    now_utc_iso = utc_now_iso()
    state_rows = conn.execute(
        """
        SELECT hostname,
               COALESCE(last_mail_notified_report_time_utc, ''),
               COALESCE(last_telegram_notified_report_time_utc, '')
        FROM inactive_host_notification_state
        """
    ).fetchall()
    state_by_host = {
        str(row[0] or ""): {
            "mail": str(row[1] or ""),
            "telegram": str(row[2] or ""),
        }
        for row in state_rows
        if str(row[0] or "")
    }

    due_mail_hosts = [
        item for item in inactive_hosts
        if state_by_host.get(str(item.get("hostname") or ""), {}).get("mail", "") != str(item.get("last_report_time_utc") or "")
    ]
    due_telegram_hosts = [
        item for item in inactive_hosts
        if state_by_host.get(str(item.get("hostname") or ""), {}).get("telegram", "") != str(item.get("last_report_time_utc") or "")
    ]
    if not due_mail_hosts and not due_telegram_hosts:
        return

    for item in inactive_hosts:
        hostname = str(item.get("hostname") or "")
        if not hostname:
            continue
        conn.execute(
            """
            INSERT INTO inactive_host_notification_state (
                hostname,
                last_report_time_utc,
                last_mail_notified_report_time_utc,
                last_telegram_notified_report_time_utc,
                updated_at_utc
            )
            VALUES (?, ?, '', '', ?)
            ON CONFLICT(hostname) DO UPDATE SET
                last_report_time_utc = excluded.last_report_time_utc,
                updated_at_utc = excluded.updated_at_utc
            """,
            (hostname, str(item.get("last_report_time_utc") or ""), now_utc_iso),
        )

    sent_mail_hostnames: set[str] = set()
    sent_telegram_hostnames: set[str] = set()

    if due_mail_hosts:
        try:
            mail_user_rows = conn.execute(
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
            mail_user_rows = []

        for row in mail_user_rows:
            username = str(row[0] or "").strip()
            min_severity = str(row[1] or "warning").strip().lower()
            if not username:
                continue
            if min_severity == "critical":
                # Inactive host is always treated as critical; keep user preference handling explicit.
                pass

            user_settings = get_web_user_settings(conn, username)
            all_recipients = resolve_user_alert_mail_recipients(user_settings, "critical")
            if not all_recipients:
                continue

            subscribed_rows = conn.execute(
                """
                SELECT hostname
                FROM web_user_alert_subscriptions
                WHERE username = ? AND COALESCE(notify_mail, 0) = 1
                """,
                (username,),
            ).fetchall()
            subscribed_hosts = {str(sub_row[0] or "") for sub_row in subscribed_rows if str(sub_row[0] or "")}
            selected_hosts = [
                item for item in due_mail_hosts
                if str(item.get("hostname") or "") in subscribed_hosts
            ]
            if not selected_hosts:
                continue

            ok_token, access_token, _details = ensure_microsoft_access_token(conn, username)
            if not ok_token:
                continue

            mail_ok, _mail_details = send_microsoft_mail_multi(
                access_token,
                all_recipients,
                inactive_hosts_mail_subject(selected_hosts, threshold_hours),
                inactive_hosts_mail_html(username, selected_hosts, threshold_hours),
                content_type="HTML",
                sender_address=str(user_settings.get("email_sender", "") or "").strip(),
            )
            if mail_ok:
                sent_mail_hostnames.update(str(item.get("hostname") or "") for item in selected_hosts)

    telegram_enabled = bool(alarm_settings.get("telegram_enabled", False))
    telegram_bot_token = str(alarm_settings.get("telegram_bot_token", "") or "").strip()
    if due_telegram_hosts and telegram_enabled and telegram_bot_token:
        try:
            telegram_user_rows = conn.execute(
                """
                SELECT u.username,
                       COALESCE(s.alert_instant_min_severity, 'warning'),
                       COALESCE(s.alert_telegram_chat_id, '')
                FROM web_users u
                JOIN web_user_settings s ON s.username = u.username
                WHERE COALESCE(u.is_disabled, 0) = 0
                  AND COALESCE(s.alert_instant_telegram_enabled, 0) = 1
                  AND COALESCE(s.alert_telegram_chat_id, '') != ''
                """
            ).fetchall()
        except Exception:
            telegram_user_rows = []

        for row in telegram_user_rows:
            username = str(row[0] or "").strip()
            min_severity = str(row[1] or "warning").strip().lower()
            chat_id = str(row[2] or "").strip()
            if not username or not chat_id:
                continue
            if min_severity == "critical":
                # Inactive host is always treated as critical; keep user preference handling explicit.
                pass

            subscribed_rows = conn.execute(
                """
                SELECT hostname
                FROM web_user_alert_subscriptions
                WHERE username = ? AND COALESCE(notify_telegram, 0) = 1
                """,
                (username,),
            ).fetchall()
            subscribed_hosts = {str(sub_row[0] or "") for sub_row in subscribed_rows if str(sub_row[0] or "")}
            selected_hosts = [
                item for item in due_telegram_hosts
                if str(item.get("hostname") or "") in subscribed_hosts
            ]
            if not selected_hosts:
                continue

            telegram_ok, _telegram_details = telegram_send_to_chat(
                telegram_bot_token,
                chat_id,
                inactive_hosts_telegram_text(username, selected_hosts, threshold_hours),
            )
            if telegram_ok:
                sent_telegram_hostnames.update(str(item.get("hostname") or "") for item in selected_hosts)

    for hostname in sent_mail_hostnames:
        host_item = next((item for item in inactive_hosts if str(item.get("hostname") or "") == hostname), None)
        if not host_item:
            continue
        conn.execute(
            """
            UPDATE inactive_host_notification_state
            SET last_mail_notified_report_time_utc = ?, updated_at_utc = ?
            WHERE hostname = ?
            """,
            (str(host_item.get("last_report_time_utc") or ""), now_utc_iso, hostname),
        )

    for hostname in sent_telegram_hostnames:
        host_item = next((item for item in inactive_hosts if str(item.get("hostname") or "") == hostname), None)
        if not host_item:
            continue
        conn.execute(
            """
            UPDATE inactive_host_notification_state
            SET last_telegram_notified_report_time_utc = ?, updated_at_utc = ?
            WHERE hostname = ?
            """,
            (str(host_item.get("last_report_time_utc") or ""), now_utc_iso, hostname),
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
        all_alert_recipients = resolve_user_alert_mail_recipients(settings)

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
            trend_allowed_hosts, trend_prioritized_hosts = get_user_trend_host_scope(conn, username)
            preferences = get_user_preferences(conn, username)
            trend_selected_metrics = parse_critical_trends_metrics(preferences.get("critical_trends_metrics", "filesystem"))
            # Build hidden mountpoints dict for this user
            all_hostnames = {
                row[0]
                for row in conn.execute(
                    "SELECT DISTINCT hostname FROM reports WHERE received_at_utc >= ? ORDER BY hostname ASC",
                    (utc_hours_ago_iso(72),),
                ).fetchall()
            }
            relevant_hostnames = trend_allowed_hosts if trend_allowed_hosts is not None else all_hostnames
            hidden_mountpoints_by_host = {}
            for hostname in relevant_hostnames:
                hidden_critical = get_filesystem_visibility_hidden(conn, username, hostname, "critical-trends")
                hidden_fs_focus = get_filesystem_visibility_hidden(conn, username, hostname, "fs-focus")
                hidden = sorted({*(hidden_critical or []), *(hidden_fs_focus or [])}, key=lambda item: str(item).lower())
                if hidden:
                    hidden_mountpoints_by_host[hostname] = hidden

            warnings = collect_critical_trends(
                conn,
                72,
                hidden_mountpoints_by_host,
                allowed_hostnames=trend_allowed_hosts,
                prioritized_hostnames=trend_prioritized_hosts,
                selected_metrics=trend_selected_metrics,
            )
            trend_ok, _trend_details = send_microsoft_mail(
                access_token,
                recipient,
                trend_digest_subject(warnings, today_local),
                trend_digest_html(username, warnings, 72),
                content_type="HTML",
                sender_address=str(settings.get("email_sender", "") or "").strip(),
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
            alert_allowed_hosts = get_user_alert_mail_host_scope(conn, username)
            alerts = collect_open_alerts(conn, allowed_hostnames=alert_allowed_hosts)
            alert_recipients = resolve_user_alert_mail_recipients(
                settings,
                alert_digest_recipient_severity(alerts),
            )
            if not alert_recipients:
                continue
            graph_cids, graph_attachments = build_alert_digest_graph_bundle(conn, alerts, hours=24)
            alert_ok, _alert_details = send_microsoft_mail_multi(
                access_token,
                alert_recipients,
                alert_digest_subject(alerts, today_local),
                alert_digest_html(username, alerts, graph_cids=graph_cids, graph_hours=24),
                content_type="HTML",
                attachments=graph_attachments,
                sender_address=str(settings.get("email_sender", "") or "").strip(),
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
               telegram_enabled, telegram_bot_token, telegram_chat_id, updated_at_utc,
               COALESCE(alert_reminder_interval_hours, 0),
             COALESCE(alert_telegram_reminder_interval_hours, 0),
               COALESCE(cpu_warning_threshold_percent, 80),
               COALESCE(cpu_critical_threshold_percent, 95),
               COALESCE(cpu_alert_window_reports, 4),
               COALESCE(ram_warning_threshold_percent, 85),
               COALESCE(ram_critical_threshold_percent, 95),
               COALESCE(ram_alert_window_reports, 4),
               COALESCE(inactive_host_alert_enabled, 0),
               COALESCE(inactive_host_alert_hours, 3),
               COALESCE(ai_troubleshoot_enabled, 1),
               COALESCE(openai_api_key, ''),
               COALESCE(openai_model, 'gpt-4o-mini'),
               COALESCE(openai_timeout_sec, 12),
               COALESCE(openai_max_tokens, 1200),
               COALESCE(ai_troubleshoot_cache_ttl_sec, 600)
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
            "telegram_enabled": TELEGRAM_ENABLED_DEFAULT,
            "telegram_bot_token": TELEGRAM_BOT_TOKEN_DEFAULT,
            "telegram_chat_id": TELEGRAM_CHAT_ID_DEFAULT,
            "updated_at_utc": "",
            "alert_reminder_interval_hours": 0,
            "alert_telegram_reminder_interval_hours": 0,
            "cpu_warning_threshold_percent": 80.0,
            "cpu_critical_threshold_percent": 95.0,
            "cpu_alert_window_reports": 4,
            "ram_warning_threshold_percent": 85.0,
            "ram_critical_threshold_percent": 95.0,
            "ram_alert_window_reports": 4,
            "inactive_host_alert_enabled": False,
            "inactive_host_alert_hours": 3,
            "ai_troubleshoot_enabled": True,
            "openai_api_key": "",
            "openai_model": "gpt-4o-mini",
            "openai_timeout_sec": 12,
            "openai_max_tokens": 1200,
            "ai_troubleshoot_cache_ttl_sec": 600,
        }

    return {
        "warning_threshold_percent": clamp_threshold(row[0], 1, 99, WARNING_THRESHOLD_PERCENT),
        "critical_threshold_percent": clamp_threshold(row[1], 1, 100, CRITICAL_THRESHOLD_PERCENT),
        "warning_consecutive_hits": max(1, int(row[2] or 2)),
        "warning_window_minutes": max(1, int(row[3] or 15)),
        "critical_trigger_immediate": coerce_bool(row[4]),
        "telegram_enabled": coerce_bool(row[5]),
        "telegram_bot_token": str(row[6] or ""),
        "telegram_chat_id": str(row[7] or ""),
        "updated_at_utc": str(row[8] or ""),
        "alert_reminder_interval_hours": max(0, int(row[9] or 0)) if row[9] is not None else 0,
        "alert_telegram_reminder_interval_hours": max(0, int(row[10] or 0)) if row[10] is not None else 0,
        "cpu_warning_threshold_percent": clamp_threshold(row[11], 1, 99, 80.0),
        "cpu_critical_threshold_percent": clamp_threshold(row[12], 1, 100, 95.0),
        "cpu_alert_window_reports": max(2, min(24, int(row[13] or 4))) if row[13] is not None else 4,
        "ram_warning_threshold_percent": clamp_threshold(row[14], 1, 99, 85.0),
        "ram_critical_threshold_percent": clamp_threshold(row[15], 1, 100, 95.0),
        "ram_alert_window_reports": max(2, min(24, int(row[16] or 4))) if row[16] is not None else 4,
        "inactive_host_alert_enabled": coerce_bool(row[17]),
        "inactive_host_alert_hours": max(1, min(168, int(row[18] or 3))) if row[18] is not None else 3,
        "ai_troubleshoot_enabled": coerce_bool(row[19]),
        "openai_api_key": str(row[20] or ""),
        "openai_model": str(row[21] or "gpt-4o-mini"),
        "openai_timeout_sec": max(3, min(60, int(row[22] or 12))) if row[22] is not None else 12,
        "openai_max_tokens": max(256, min(4000, int(row[23] or 1200))) if row[23] is not None else 1200,
        "ai_troubleshoot_cache_ttl_sec": max(30, min(3600, int(row[24] or 600))) if row[24] is not None else 600,
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

    try:
        cpu_warning = float(payload.get("cpu_warning_threshold_percent", base.get("cpu_warning_threshold_percent", 80.0)))
    except (TypeError, ValueError):
        cpu_warning = 80.0
    cpu_warning = clamp_threshold(cpu_warning, 1, 99, 80.0)

    try:
        cpu_critical = float(payload.get("cpu_critical_threshold_percent", base.get("cpu_critical_threshold_percent", 95.0)))
    except (TypeError, ValueError):
        cpu_critical = 95.0
    cpu_critical = clamp_threshold(cpu_critical, 1, 100, 95.0)
    if cpu_critical <= cpu_warning:
        cpu_critical = min(100.0, cpu_warning + 1.0)

    try:
        cpu_window_reports = int(payload.get("cpu_alert_window_reports", base.get("cpu_alert_window_reports", 4)))
    except (TypeError, ValueError):
        cpu_window_reports = 4
    cpu_window_reports = max(2, min(cpu_window_reports, 24))

    try:
        ram_warning = float(payload.get("ram_warning_threshold_percent", base.get("ram_warning_threshold_percent", 85.0)))
    except (TypeError, ValueError):
        ram_warning = 85.0
    ram_warning = clamp_threshold(ram_warning, 1, 99, 85.0)

    try:
        ram_critical = float(payload.get("ram_critical_threshold_percent", base.get("ram_critical_threshold_percent", 95.0)))
    except (TypeError, ValueError):
        ram_critical = 95.0
    ram_critical = clamp_threshold(ram_critical, 1, 100, 95.0)
    if ram_critical <= ram_warning:
        ram_critical = min(100.0, ram_warning + 1.0)

    try:
        ram_window_reports = int(payload.get("ram_alert_window_reports", base.get("ram_alert_window_reports", 4)))
    except (TypeError, ValueError):
        ram_window_reports = 4
    ram_window_reports = max(2, min(ram_window_reports, 24))

    try:
        reminder_interval = int(payload.get("alert_reminder_interval_hours", base.get("alert_reminder_interval_hours", 0)) or 0)
    except (TypeError, ValueError):
        reminder_interval = 0
    reminder_interval = max(0, min(reminder_interval, 168))

    try:
        telegram_reminder_interval = int(payload.get("alert_telegram_reminder_interval_hours", base.get("alert_telegram_reminder_interval_hours", 0)) or 0)
    except (TypeError, ValueError):
        telegram_reminder_interval = 0
    telegram_reminder_interval = max(0, min(telegram_reminder_interval, 168))

    try:
        inactive_hours = int(payload.get("inactive_host_alert_hours", base.get("inactive_host_alert_hours", 3)) or 3)
    except (TypeError, ValueError):
        inactive_hours = 3
    inactive_hours = max(1, min(inactive_hours, 168))

    existing_openai_key = str(base.get("openai_api_key", "") or "").strip()
    incoming_openai_key = str(payload.get("openai_api_key", "") or "").strip()
    effective_openai_key = incoming_openai_key if incoming_openai_key else existing_openai_key

    openai_model = str(payload.get("openai_model", base.get("openai_model", "gpt-4o-mini")) or "gpt-4o-mini").strip()
    if not openai_model:
        openai_model = "gpt-4o-mini"

    try:
        openai_timeout_sec = int(payload.get("openai_timeout_sec", base.get("openai_timeout_sec", 12)) or 12)
    except (TypeError, ValueError):
        openai_timeout_sec = 12
    openai_timeout_sec = max(3, min(openai_timeout_sec, 60))

    try:
        openai_max_tokens = int(payload.get("openai_max_tokens", base.get("openai_max_tokens", 1200)) or 1200)
    except (TypeError, ValueError):
        openai_max_tokens = 1200
    openai_max_tokens = max(256, min(openai_max_tokens, 4000))

    try:
        ai_cache_ttl = int(payload.get("ai_troubleshoot_cache_ttl_sec", base.get("ai_troubleshoot_cache_ttl_sec", 600)) or 600)
    except (TypeError, ValueError):
        ai_cache_ttl = 600
    ai_cache_ttl = max(30, min(ai_cache_ttl, 3600))

    return {
        "warning_threshold_percent": warning,
        "critical_threshold_percent": critical,
        "warning_consecutive_hits": warning_hits,
        "warning_window_minutes": warning_window,
        "critical_trigger_immediate": coerce_bool(payload.get("critical_trigger_immediate", base.get("critical_trigger_immediate", True))),
        "telegram_enabled": coerce_bool(payload.get("telegram_enabled", base.get("telegram_enabled", False))),
        "telegram_bot_token": str(payload.get("telegram_bot_token", base.get("telegram_bot_token", "")) or "").strip(),
        "telegram_chat_id": str(payload.get("telegram_chat_id", base.get("telegram_chat_id", "")) or "").strip(),
        "alert_reminder_interval_hours": reminder_interval,
        "alert_telegram_reminder_interval_hours": telegram_reminder_interval,
        "cpu_warning_threshold_percent": cpu_warning,
        "cpu_critical_threshold_percent": cpu_critical,
        "cpu_alert_window_reports": cpu_window_reports,
        "ram_warning_threshold_percent": ram_warning,
        "ram_critical_threshold_percent": ram_critical,
        "ram_alert_window_reports": ram_window_reports,
        "inactive_host_alert_enabled": coerce_bool(payload.get("inactive_host_alert_enabled", base.get("inactive_host_alert_enabled", False))),
        "inactive_host_alert_hours": inactive_hours,
        "ai_troubleshoot_enabled": coerce_bool(payload.get("ai_troubleshoot_enabled", base.get("ai_troubleshoot_enabled", True))),
        "openai_api_key": effective_openai_key,
        "openai_model": openai_model,
        "openai_timeout_sec": openai_timeout_sec,
        "openai_max_tokens": openai_max_tokens,
        "ai_troubleshoot_cache_ttl_sec": ai_cache_ttl,
    }


def alarm_settings_public_view(settings: dict) -> dict:
    public = dict(settings or {})
    openai_key = str(public.pop("openai_api_key", "") or "")
    public["openai_api_key_is_set"] = bool(openai_key.strip())
    return public


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
            telegram_enabled,
            telegram_bot_token,
            telegram_chat_id,
            updated_at_utc,
            alert_reminder_interval_hours,
            alert_telegram_reminder_interval_hours,
            cpu_warning_threshold_percent,
            cpu_critical_threshold_percent,
            cpu_alert_window_reports,
            ram_warning_threshold_percent,
            ram_critical_threshold_percent,
            ram_alert_window_reports,
            inactive_host_alert_enabled,
            inactive_host_alert_hours,
            ai_troubleshoot_enabled,
            openai_api_key,
            openai_model,
            openai_timeout_sec,
            openai_max_tokens,
            ai_troubleshoot_cache_ttl_sec
        )
        VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            warning_threshold_percent = excluded.warning_threshold_percent,
            critical_threshold_percent = excluded.critical_threshold_percent,
            warning_consecutive_hits = excluded.warning_consecutive_hits,
            warning_window_minutes = excluded.warning_window_minutes,
            critical_trigger_immediate = excluded.critical_trigger_immediate,
            telegram_enabled = excluded.telegram_enabled,
            telegram_bot_token = excluded.telegram_bot_token,
            telegram_chat_id = excluded.telegram_chat_id,
            updated_at_utc = excluded.updated_at_utc,
            alert_reminder_interval_hours = excluded.alert_reminder_interval_hours,
            alert_telegram_reminder_interval_hours = excluded.alert_telegram_reminder_interval_hours,
            cpu_warning_threshold_percent = excluded.cpu_warning_threshold_percent,
            cpu_critical_threshold_percent = excluded.cpu_critical_threshold_percent,
            cpu_alert_window_reports = excluded.cpu_alert_window_reports,
            ram_warning_threshold_percent = excluded.ram_warning_threshold_percent,
            ram_critical_threshold_percent = excluded.ram_critical_threshold_percent,
            ram_alert_window_reports = excluded.ram_alert_window_reports,
            inactive_host_alert_enabled = excluded.inactive_host_alert_enabled,
            inactive_host_alert_hours = excluded.inactive_host_alert_hours,
            ai_troubleshoot_enabled = excluded.ai_troubleshoot_enabled,
            openai_api_key = excluded.openai_api_key,
            openai_model = excluded.openai_model,
            openai_timeout_sec = excluded.openai_timeout_sec,
            openai_max_tokens = excluded.openai_max_tokens,
            ai_troubleshoot_cache_ttl_sec = excluded.ai_troubleshoot_cache_ttl_sec
        """,
        (
            normalized["warning_threshold_percent"],
            normalized["critical_threshold_percent"],
            normalized["warning_consecutive_hits"],
            normalized["warning_window_minutes"],
            1 if normalized["critical_trigger_immediate"] else 0,
            1 if normalized["telegram_enabled"] else 0,
            normalized["telegram_bot_token"],
            normalized["telegram_chat_id"],
            now_utc,
            normalized["alert_reminder_interval_hours"],
            normalized["alert_telegram_reminder_interval_hours"],
            normalized["cpu_warning_threshold_percent"],
            normalized["cpu_critical_threshold_percent"],
            normalized["cpu_alert_window_reports"],
            normalized["ram_warning_threshold_percent"],
            normalized["ram_critical_threshold_percent"],
            normalized["ram_alert_window_reports"],
            1 if normalized["inactive_host_alert_enabled"] else 0,
            normalized["inactive_host_alert_hours"],
            1 if normalized["ai_troubleshoot_enabled"] else 0,
            normalized["openai_api_key"],
            normalized["openai_model"],
            normalized["openai_timeout_sec"],
            normalized["openai_max_tokens"],
            normalized["ai_troubleshoot_cache_ttl_sec"],
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


def _telegram_action_secret(bot_token: str) -> str:
    seed = TELEGRAM_ACTION_SIGNING_SECRET.strip() or str(bot_token or "").strip() or WEB_DEFAULT_PASSWORD
    return seed


def _sign_telegram_alert_action(action: str, hostname: str, mountpoint: str, expires_ts: int, bot_token: str) -> str:
    message = f"{action}\n{hostname}\n{mountpoint}\n{expires_ts}".encode("utf-8")
    secret = _telegram_action_secret(bot_token).encode("utf-8")
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def build_telegram_alert_action_url(action: str, hostname: str, mountpoint: str, bot_token: str) -> str:
    action_name = str(action or "").strip().lower()
    if action_name not in {"ack", "close"}:
        return ""
    base_url = TELEGRAM_ACTION_BASE_URL
    if not base_url:
        return ""
    safe_hostname = str(hostname or "").strip()
    safe_mountpoint = str(mountpoint or "").strip()
    if not safe_hostname or not safe_mountpoint:
        return ""
    expires_ts = int(datetime.now(timezone.utc).timestamp()) + (TELEGRAM_ACTION_TTL_MINUTES * 60)
    signature = _sign_telegram_alert_action(action_name, safe_hostname, safe_mountpoint, expires_ts, bot_token)
    query = parse.urlencode(
        {
            "a": action_name,
            "h": safe_hostname,
            "m": safe_mountpoint,
            "e": str(expires_ts),
            "s": signature,
        }
    )
    return f"{base_url}/api/v1/telegram/alert-action?{query}"


def build_telegram_alert_reply_markup(bot_token: str, hostname: str, mountpoint: str, event_type: str) -> dict | None:
    if event_type == "resolved":
        return None
    ack_url = build_telegram_alert_action_url("ack", hostname, mountpoint, bot_token)
    close_url = build_telegram_alert_action_url("close", hostname, mountpoint, bot_token)
    if not ack_url and not close_url:
        return None
    buttons = []
    if ack_url:
        buttons.append({"text": "Quittieren", "url": ack_url})
    if close_url:
        buttons.append({"text": "Schliessen", "url": close_url})
    if not buttons:
        return None
    return {"inline_keyboard": [buttons]}


def verify_telegram_alert_action_query(query: dict, bot_token: str) -> tuple[bool, str, str, str, str]:
    action = str(query.get("a", [""])[0] or "").strip().lower()
    hostname = str(query.get("h", [""])[0] or "").strip()
    mountpoint = str(query.get("m", [""])[0] or "").strip()
    signature = str(query.get("s", [""])[0] or "").strip().lower()
    expires_raw = str(query.get("e", [""])[0] or "").strip()

    if action not in {"ack", "close"}:
        return False, "", "", "", "Ungültige Aktion"
    if not hostname or not mountpoint:
        return False, "", "", "", "Hostname oder Mountpoint fehlt"
    if not signature or not expires_raw:
        return False, "", "", "", "Signatur fehlt"

    try:
        expires_ts = int(expires_raw)
    except ValueError:
        return False, "", "", "", "Ablaufzeit ungültig"

    now_ts = int(datetime.now(timezone.utc).timestamp())
    if expires_ts < now_ts:
        return False, "", "", "", "Aktion ist abgelaufen"

    expected = _sign_telegram_alert_action(action, hostname, mountpoint, expires_ts, bot_token)
    if not hmac.compare_digest(signature, expected):
        return False, "", "", "", "Signatur ungültig"

    return True, action, hostname, mountpoint, ""


def telegram_send_to_chat(bot_token: str, chat_id: str, text: str, reply_markup: dict | None = None) -> tuple[bool, str]:
    # Try sendPhoto with logo as thumbnail; fall back to sendMessage on any error
    if _LOGO_PATH.is_file():
        try:
            photo_data = _LOGO_PATH.read_bytes()
            fields = {"chat_id": chat_id, "caption": text[:1024]}
            if reply_markup:
                fields["reply_markup"] = json.dumps(reply_markup, separators=(",", ":"))
            files = {"photo": (_LOGO_PATH.name, photo_data, "image/png")}
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
            "disable_web_page_preview": "true",
            **({"reply_markup": json.dumps(reply_markup, separators=(",", ":"))} if reply_markup else {}),
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


def telegram_send(settings: dict, text: str) -> tuple[bool, str]:
    if not settings.get("telegram_enabled"):
        return False, "telegram disabled"

    bot_token = str(settings.get("telegram_bot_token", "")).strip()
    chat_id = str(settings.get("telegram_chat_id", "")).strip()
    if not bot_token or not chat_id:
        return False, "telegram bot token/chat id missing"

    return telegram_send_to_chat(bot_token, chat_id, text)


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
        icon = {
            "opened": "🚨 ALERT OPEN",
            "escalated": "⬆️ ALERT ESCALATED",
            "resolved": "✅ ALERT RESOLVED",
        }.get(event_type, "⚠️ ALERT")
        sev_icon = {"critical": "🔴", "warning": "🟠", "ok": "🟢"}.get(severity, "⚪")
        host_ctx = collect_host_mail_context(conn, hostname) if conn is not None else {}
        title = display_name.strip() if display_name.strip() else str(host_ctx.get("display_name") or hostname)
        customer_label = str(host_ctx.get("customer_name") or "").strip() or "Ohne Kunde"
        now_local = datetime.now().astimezone().strftime("%d.%m.%Y %H:%M")
        text = (
            f"{icon}\n"
            f"👥 {customer_label}\n"
            f"🖥️ {title} ({hostname})\n"
            f"📂 {mountpoint}\n"
            f"{sev_icon} {severity}\n"
            f"📊 {used_percent:.1f}%\n"
            f"🕐 {now_local}"
        )
        bot_token = str(settings.get("telegram_bot_token", "") or "").strip()
        chat_id = str(settings.get("telegram_chat_id", "") or "").strip()
        reply_markup = build_telegram_alert_reply_markup(bot_token, hostname, mountpoint, event_type)
        telegram_send_to_chat(bot_token, chat_id, text, reply_markup=reply_markup)
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


def get_display_name_override(conn: sqlite3.Connection, hostname: str, host_uid: str = "") -> str:
    safe_host_uid = str(host_uid or "").strip()
    if safe_host_uid:
        uid_row = conn.execute(
            "SELECT display_name_override FROM host_uid_settings WHERE host_uid = ?",
            (safe_host_uid,),
        ).fetchone()
        if uid_row and uid_row[0]:
            return str(uid_row[0]).strip()

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


def sap_logo_data_uri() -> str:
    try:
        encoded = base64.b64encode(SAP_LOGO_PATH.read_bytes()).decode("ascii")
        return f"data:image/png;base64,{encoded}"
    except OSError:
        return ""


def mail_footer_logos_html(sap_logo_uri: str, ang_logo_uri: str) -> str:
    sap_logo_html = (
        f"<img src='{sap_logo_uri}' alt='SAP' width='67' style='display:inline-block;max-width:67px;height:auto;'>"
        if sap_logo_uri
        else ""
    )
    ang_logo_html = (
        f"<img src='{ang_logo_uri}' alt='ANG' width='110' style='display:inline-block;max-width:110px;height:auto;'>"
        if ang_logo_uri
        else ""
    )
    return (
        "<table role='presentation' cellpadding='0' cellspacing='0' border='0' style='margin-top:18px;padding-top:14px;border-top:1px solid #e2e8f0;width:100%;border-collapse:collapse;'>"
        "<tr>"
        f"<td style='text-align:left;vertical-align:middle;'>{sap_logo_html}</td>"
        f"<td style='text-align:right;vertical-align:middle;'>{ang_logo_html}</td>"
        "</tr>"
        "</table>"
    )


def collect_host_mail_context(conn: sqlite3.Connection, hostname: str) -> dict:
    settings_row = conn.execute(
        """
        SELECT COALESCE(h.display_name_override, ''),
               COALESCE(h.country_code_override, ''),
               COALESCE(c.customer_name, '')
        FROM host_settings h
        LEFT JOIN customers c ON c.id = h.customer_id
        WHERE h.hostname = ?
        """,
        (hostname,),
    ).fetchone()
    display_name_override = str(settings_row[0] or "").strip() if settings_row else ""
    country_code_override = normalize_country_code(settings_row[1] if settings_row else "")
    customer_name = str(settings_row[2] or "").strip() if settings_row else ""

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
        "customer_name": customer_name,
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


def payload_agent_config_entries_map(payload: dict) -> dict[str, str]:
    agent_config = payload.get("agent_config", {})
    if not isinstance(agent_config, dict):
        return {}

    entries = agent_config.get("entries", [])
    if not isinstance(entries, list):
        return {}

    result: dict[str, str] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        key = str(entry.get("key", "") or "").strip().upper()
        if not key:
            continue
        result[key] = str(entry.get("value", "") or "").strip()
    return result


def collect_agent_source_status(conn: sqlite3.Connection) -> dict:
    known_hosts = get_known_hostnames(conn)
    if not known_hosts:
        return {
            "generated_at": utc_now_iso(),
            "total": 0,
            "ok": 0,
            "pending": 0,
            "items": [],
        }

    placeholders = ",".join("?" for _ in known_hosts)

    settings_rows = conn.execute(
        f"""
        SELECT hostname, COALESCE(display_name_override, ''), COALESCE(country_code_override, '')
        FROM host_settings
        WHERE hostname IN ({placeholders})
        """,
        tuple(known_hosts),
    ).fetchall()
    display_name_override_map = {str(row[0] or ""): str(row[1] or "") for row in settings_rows}
    country_override_map = {str(row[0] or ""): normalize_country_code(str(row[2] or "")) for row in settings_rows}

    latest_rows = conn.execute(
        f"""
        SELECT r.hostname, r.received_at_utc, r.payload_json
        FROM reports r
        JOIN (
            SELECT hostname, MAX(id) AS latest_id
            FROM reports
            WHERE hostname IN ({placeholders})
            GROUP BY hostname
        ) latest ON latest.latest_id = r.id
        ORDER BY LOWER(r.hostname)
        """,
        tuple(known_hosts),
    ).fetchall()

    items: list[dict] = []
    for row in latest_rows:
        hostname = str(row[0] or "").strip()
        if not hostname:
            continue
        received_at_utc = str(row[1] or "").strip()
        payload = parse_payload_json(str(row[2] or "{}"))

        entries_map = payload_agent_config_entries_map(payload)
        server_url = str(entries_map.get("SERVER_URL", "") or "").strip()
        update_base_url = str(entries_map.get("UPDATE_BASE_URL", "") or "").strip()
        raw_base_url = str(entries_map.get("RAW_BASE_URL", "") or "").strip()
        github_repo = str(entries_map.get("GITHUB_REPO", "") or "").strip()

        expected_update_base = f"{server_url.rstrip('/')}/updates" if server_url else ""

        server_ok = bool(server_url)
        update_ok = bool(update_base_url) and bool(expected_update_base) and (update_base_url == expected_update_base)
        raw_ok = (not raw_base_url) or (bool(update_base_url) and raw_base_url == update_base_url)
        github_ok = not github_repo

        is_ok = bool(server_ok and update_ok and raw_ok and github_ok)

        display_name = effective_display_name(
            payload,
            display_name_override_map.get(hostname, ""),
            hostname,
        )
        country_code = country_override_map.get(hostname, "") or extract_country_code_from_payload(payload)

        items.append(
            {
                "hostname": hostname,
                "display_name": display_name,
                "country_code": normalize_country_code(country_code),
                "received_at_utc": received_at_utc,
                "server_url": server_url,
                "update_base_url": update_base_url,
                "raw_base_url": raw_base_url,
                "github_repo": github_repo,
                "expected_update_base_url": expected_update_base,
                "checks": {
                    "server_url": server_ok,
                    "update_base_url": update_ok,
                    "raw_base_url": raw_ok,
                    "github_repo_empty": github_ok,
                },
                "is_ok": is_ok,
            }
        )

    items.sort(key=lambda item: (str(item.get("display_name", "")).lower(), str(item.get("hostname", "")).lower()))
    ok_count = sum(1 for item in items if bool(item.get("is_ok")))
    total_count = len(items)

    return {
        "generated_at": utc_now_iso(),
        "total": total_count,
        "ok": ok_count,
        "pending": max(0, total_count - ok_count),
        "items": items,
    }


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
        SELECT
                    COALESCE(h.display_name_override, ''),
                    COALESCE(h.country_code_override, ''),
                    COALESCE(h.is_favorite, 0),
                    COALESCE(h.is_hidden, 0),
                    COALESCE(h.customer_alert_emails, ''),
                    COALESCE(h.customer_alert_mountpoints, ''),
                    COALESCE(h.customer_alert_min_severity, 'critical'),
                    h.customer_id,
                    COALESCE(h.environment_type, ''),
                    COALESCE(c.customer_name, ''),
                    COALESCE(c.maringo_project_number, '')
                FROM host_settings h
                LEFT JOIN customers c ON c.id = h.customer_id
                WHERE h.hostname = ?
        """,
        (hostname,),
    ).fetchone()
    if not row:
        return {
            "display_name_override": "",
            "country_code_override": "",
            "is_favorite": False,
            "is_hidden": False,
            "customer_alert_emails": "",
            "customer_alert_mountpoints": "",
            "customer_alert_min_severity": "critical",
            "customer_id": None,
            "environment_type": "",
            "customer_name": "",
            "customer_maringo_project_number": "",
        }
    customer_alert_min_severity = str(row[6] or "critical").strip().lower()
    if customer_alert_min_severity not in {"warning", "critical"}:
        customer_alert_min_severity = "critical"
    environment_type = str(row[8] or "").strip().lower()
    if environment_type not in {"", "prod", "test"}:
        environment_type = ""
    return {
        "display_name_override": str(row[0] or "").strip(),
        "country_code_override": normalize_country_code(row[1]),
        "is_favorite": bool(int(row[2] or 0)),
        "is_hidden": bool(int(row[3] or 0)),
        "customer_alert_emails": str(row[4] or "").strip(),
        "customer_alert_mountpoints": str(row[5] or "").strip(),
        "customer_alert_min_severity": customer_alert_min_severity,
        "customer_id": int(row[7]) if row[7] is not None else None,
        "environment_type": environment_type,
        "customer_name": str(row[9] or "").strip(),
        "customer_maringo_project_number": str(row[10] or "").strip(),
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
    keep_count = max(0, int(keep_count))
    retention_days = max(1, int(REPORT_RETENTION_DAYS))
    cutoff_iso = (datetime.now(timezone.utc) - timedelta(days=retention_days)).strftime("%Y-%m-%dT%H:%M:%SZ")

    conn.execute(
        """
        UPDATE alerts
        SET report_id = NULL
        WHERE report_id IN (
            SELECT id
            FROM reports
            WHERE hostname = ? AND received_at_utc < ?
        )
        """,
        (hostname, cutoff_iso),
    )
    conn.execute(
        """
        DELETE FROM reports
        WHERE hostname = ? AND received_at_utc < ?
        """,
        (hostname, cutoff_iso),
    )

    if keep_count <= 0:
        return

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


def delete_host_card_data(conn: sqlite3.Connection, hostname: str, host_uid: str = "") -> dict[str, int]:
    deleted: dict[str, int] = {
        "muted_alert_rules": 0,
        "alert_debounce": 0,
        "alerts": 0,
        "agent_commands": 0,
        "host_settings": 0,
        "host_uid_settings": 0,
        "reports": 0,
    }

    normalized_hostname = str(hostname or "").strip()
    normalized_host_uid = str(host_uid or "").strip()

    if normalized_host_uid:
        host_key_expr = reports_host_key_sql()
        touched_hostnames = {
            str(row[0] or "").strip()
            for row in conn.execute(
                f"SELECT DISTINCT COALESCE(hostname, '') FROM reports WHERE {host_key_expr} = ?",
                (normalized_host_uid,),
            ).fetchall()
            if str(row[0] or "").strip()
        }

        conn.execute(
            f"DELETE FROM reports WHERE {host_key_expr} = ?",
            (normalized_host_uid,),
        )
        row = conn.execute("SELECT changes()").fetchone()
        deleted["reports"] = int(row[0] or 0) if row else 0

        conn.execute("DELETE FROM host_uid_settings WHERE host_uid = ?", (normalized_host_uid,))
        row = conn.execute("SELECT changes()").fetchone()
        deleted["host_uid_settings"] = int(row[0] or 0) if row else 0

        # Only clear hostname-scoped data when no reports for that hostname remain.
        for touched_hostname in touched_hostnames:
            remaining = conn.execute(
                "SELECT COUNT(*) FROM reports WHERE hostname = ?",
                (touched_hostname,),
            ).fetchone()
            remaining_count = int((remaining[0] if remaining else 0) or 0)
            if remaining_count > 0:
                continue

            for table_name in ("muted_alert_rules", "alert_debounce", "alerts", "agent_commands", "host_settings"):
                conn.execute(f"DELETE FROM {table_name} WHERE hostname = ?", (touched_hostname,))
                row = conn.execute("SELECT changes()").fetchone()
                deleted[table_name] += int(row[0] or 0) if row else 0

        return deleted

    cleanup_plan = [
        ("muted_alert_rules", "hostname = ?"),
        ("alert_debounce", "hostname = ?"),
        ("alerts", "hostname = ?"),
        ("agent_commands", "hostname = ?"),
        ("host_settings", "hostname = ?"),
        ("reports", "hostname = ?"),
    ]

    for table_name, where_clause in cleanup_plan:
        conn.execute(
            f"DELETE FROM {table_name} WHERE {where_clause}",
            (normalized_hostname,),
        )
        row = conn.execute("SELECT changes()").fetchone()
        deleted[table_name] = int(row[0] or 0) if row else 0

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
    blacklist_patterns = get_filesystem_blacklist_pattern_strings(conn)
    hidden_mountpoint_keys = {
        normalize_mountpoint_key(str(row[0] or ""))
        for row in conn.execute(
            """
            SELECT DISTINCT mountpoint
            FROM filesystem_visibility
            WHERE hostname = ?
              AND section IN ('analysis', 'fs-focus', 'critical-trends')
            """,
            (hostname,),
        ).fetchall()
        if str(row[0] or "").strip()
    }
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

        mountpoint_key = normalize_mountpoint_key(mountpoint)
        if mountpoint_key in hidden_mountpoint_keys:
            suppressed_open = conn.execute(
                "SELECT id FROM alerts WHERE hostname = ? AND mountpoint = ? AND status = 'open'",
                (hostname, mountpoint),
            ).fetchone()
            if suppressed_open:
                conn.execute(
                    "UPDATE alerts SET status = 'resolved', resolved_at_utc = ?, last_seen_at_utc = ? WHERE id = ?",
                    (now_utc, now_utc, suppressed_open[0]),
                )
            conn.execute("DELETE FROM alert_debounce WHERE hostname = ? AND mountpoint = ?", (hostname, mountpoint))
            continue

        if is_filesystem_blacklisted_by_patterns(mountpoint, blacklist_patterns):
            blacklisted_open = conn.execute(
                "SELECT id FROM alerts WHERE hostname = ? AND mountpoint = ? AND status = 'open'",
                (hostname, mountpoint),
            ).fetchone()
            if blacklisted_open:
                conn.execute(
                    "UPDATE alerts SET status = 'resolved', resolved_at_utc = ?, last_seen_at_utc = ? WHERE id = ?",
                    (now_utc, now_utc, blacklisted_open[0]),
                )
            conn.execute("DELETE FROM alert_debounce WHERE hostname = ? AND mountpoint = ?", (hostname, mountpoint))
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
    ) -> bool:
        if not path.exists() or not path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return False

        try:
            content_length = path.stat().st_size
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(content_length))
            if extra_headers:
                for key, value in extra_headers.items():
                    self.send_header(key, value)
            self.end_headers()

            with path.open("rb") as handle:
                while True:
                    chunk = handle.read(1024 * 1024)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
            return True
        except OSError:
            return False

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

    def _send_html_with_asset_version(self, path: Path) -> None:
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
            session_cutoff_iso = web_session_cutoff_iso()
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
            if row:
                now_iso = utc_now_iso()
                expires_iso = web_session_expires_iso()
                conn.execute(
                    "UPDATE web_sessions SET last_activity_at_utc = ?, expires_at_utc = ? WHERE session_token = ?",
                    (now_iso, expires_iso, token),
                )
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

    def _request_client_ip(self) -> str:
        forwarded_for = (self.headers.get("X-Forwarded-For", "") or "").split(",")[0].strip()
        if forwarded_for:
            return forwarded_for
        real_ip = (self.headers.get("X-Real-IP", "") or "").strip()
        if real_ip:
            return real_ip
        return str((self.client_address or [""])[0] or "")

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
            display_name = ""
            expires_at_utc = ""
            if username:
                token = self._cookie_value(WEB_SESSION_COOKIE)
                with sqlite3.connect(DB_PATH) as conn:
                    user = get_web_user(conn, username)
                    is_admin = bool(user and user.get("is_admin"))
                    display_name = str((user or {}).get("display_name", "") or "")
                    if token:
                        row = conn.execute(
                            "SELECT expires_at_utc FROM web_sessions WHERE session_token = ? AND username = ?",
                            (token, username),
                        ).fetchone()
                        if row:
                            expires_at_utc = str(row[0] or "")
            self._send_json(
                HTTPStatus.OK,
                {
                    "authenticated": bool(username),
                    "username": username,
                    "display_name": display_name,
                    "is_admin": is_admin,
                    "expires_at_utc": expires_at_utc,
                    "inactivity_timeout_minutes": WEB_SESSION_INACTIVITY_MINUTES,
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
            if parsed.path != "/api/v1/agent-commands" and parsed.path != "/api/v1/host-update-log":
                if not self._require_web_session():
                    return

        if parsed.path == "/api/v1/user-profile":
            username = self._web_session_username()
            with sqlite3.connect(DB_PATH) as conn:
                payload = current_user_payload(conn, username)
            self._send_json(HTTPStatus.OK, payload)
            return

        if parsed.path == "/api/v1/user-preferences":
            username = self._web_session_username()
            with sqlite3.connect(DB_PATH) as conn:
                payload = get_user_preferences(conn, username)
            self._send_json(HTTPStatus.OK, payload)
            return

        if parsed.path == "/api/v1/session/refresh":
            username = self._web_session_username()
            if not username:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "Not authenticated"})
                return
            session_token = self.headers.get("Authorization", "").replace("Bearer ", "").strip()
            if not session_token:
                session_token = self._cookie_value(WEB_SESSION_COOKIE)
            if not session_token:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "No session token"})
                return
            now_iso = utc_now_iso()
            expires_iso = web_session_expires_iso()
            with sqlite3.connect(DB_PATH) as conn:
                result = conn.execute(
                    "UPDATE web_sessions SET last_activity_at_utc = ?, expires_at_utc = ? WHERE session_token = ?",
                    (now_iso, expires_iso, session_token),
                )
                conn.commit()
            if result.rowcount <= 0:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "Session not found"})
                return
            self._send_json(
                HTTPStatus.OK,
                {
                    "username": username,
                    "expires_at_utc": expires_iso,
                    "inactivity_timeout_minutes": WEB_SESSION_INACTIVITY_MINUTES,
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

        if parsed.path == "/api/v1/customers":
            with sqlite3.connect(DB_PATH) as conn:
                self._send_json(HTTPStatus.OK, {"customers": list_customers(conn)})
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

        if parsed.path == "/api/v1/admin/login-events":
            if not self._require_admin_session():
                return
            query = parse_qs(parsed.query)
            limit = parse_int(query, "limit", default=50, min_value=1, max_value=200)
            with sqlite3.connect(DB_PATH) as conn:
                entries = list_web_login_events(conn, limit)
            self._send_json(HTTPStatus.OK, {"count": len(entries), "entries": entries})
            return

        if parsed.path == "/api/v1/admin/database-stats":
            if not self._require_admin_session():
                return
            with sqlite3.connect(DB_PATH) as conn:
                _ensure_db_maintenance_snapshot(conn, force_if_empty=True)
                payload = build_db_maintenance_dashboard(conn)
            self._send_json(HTTPStatus.OK, {"status": "ok", **payload})
            return

        if parsed.path == "/api/v1/admin/backup-automation":
            if not self._require_admin_session():
                return
            with sqlite3.connect(DB_PATH) as conn:
                settings = get_backup_automation_settings(conn)
                runs = list_backup_automation_runs(conn, limit=20)
            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "settings": settings,
                    "recent_runs": runs,
                },
            )
            return

        if parsed.path == "/api/v1/admin/backup-automation/download":
            if not self._require_admin_session():
                return
            query = parse_qs(parsed.query)
            run_id = parse_int(query, "run_id", default=0, min_value=1)
            if run_id <= 0:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "run_id query parameter is required"})
                return

            with sqlite3.connect(DB_PATH) as conn:
                row = conn.execute(
                    """
                    SELECT backup_path, status
                    FROM backup_automation_runs
                    WHERE id = ?
                    """,
                    (run_id,),
                ).fetchone()

            if not row:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "backup run not found"})
                return

            backup_path = str(row[0] or "").strip()
            status = str(row[1] or "").strip().lower()
            if not backup_path or status != "ok":
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "no downloadable backup for this run"})
                return

            file_path = (DATA_DIR / backup_path).resolve()
            try:
                file_path.relative_to(DATA_DIR.resolve())
            except ValueError:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid backup path"})
                return

            if not file_path.exists() or not file_path.is_file():
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "backup file not found"})
                return

            self._send_file(
                file_path,
                "application/octet-stream",
                extra_headers={
                    "Content-Disposition": f'attachment; filename="{file_path.name}"',
                    "Cache-Control": "no-store",
                },
            )
            return

        if parsed.path == "/api/v1/telegram/alert-action":
            query = parse_qs(parsed.query)
            with sqlite3.connect(DB_PATH) as conn:
                alarm_settings = get_alarm_settings(conn)
                bot_token = str(alarm_settings.get("telegram_bot_token", "") or "").strip()
                valid, action, hostname, mountpoint, error_message = verify_telegram_alert_action_query(query, bot_token)
                if not valid:
                    self._send_html(
                        HTTPStatus.BAD_REQUEST,
                        (
                            "<!doctype html><html lang=\"de\"><head><meta charset=\"utf-8\">"
                            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
                            "<title>Telegram Aktion</title></head><body>"
                            f"<h3>Aktion nicht möglich</h3><p>{html.escape(error_message or 'Ungültiger Link')}</p>"
                            "</body></html>"
                        ),
                    )
                    return

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
                    self._send_html(
                        HTTPStatus.OK,
                        (
                            "<!doctype html><html lang=\"de\"><head><meta charset=\"utf-8\">"
                            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
                            "<title>Telegram Aktion</title></head><body>"
                            "<h3>Hinweis</h3><p>Alert ist bereits erledigt oder nicht mehr offen.</p>"
                            "</body></html>"
                        ),
                    )
                    return

                alert_id = int(target[0])
                now_utc = utc_now_iso()
                if action == "ack":
                    conn.execute(
                        """
                        UPDATE alerts
                        SET ack_note = COALESCE(NULLIF(ack_note, ''), 'Telegram Quick Action'),
                            ack_by = 'telegram',
                            ack_at_utc = ?
                        WHERE id = ?
                        """,
                        (now_utc, alert_id),
                    )
                    action_label = "quittiert"
                else:
                    conn.execute(
                        """
                        UPDATE alerts
                        SET status = 'resolved',
                            closed_at_utc = ?,
                            closed_by = 'telegram'
                        WHERE id = ?
                        """,
                        (now_utc, alert_id),
                    )
                    action_label = "geschlossen"

                conn.commit()

            self._send_html(
                HTTPStatus.OK,
                (
                    "<!doctype html><html lang=\"de\"><head><meta charset=\"utf-8\">"
                    "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
                    "<title>Telegram Aktion</title></head><body>"
                    f"<h3>Erfolg</h3><p>Alert wurde {html.escape(action_label)}.</p>"
                    f"<p><strong>Host:</strong> {html.escape(hostname)}<br><strong>Mountpoint:</strong> {html.escape(mountpoint)}</p>"
                    "</body></html>"
                ),
            )
            return

        if parsed.path == "/api/v1/oauth-settings":
            if not self._require_admin_session():
                return
            with sqlite3.connect(DB_PATH) as conn:
                settings = oauth_settings_public_view(get_oauth_settings(conn))
            self._send_json(HTTPStatus.OK, settings)
            return

        if parsed.path == "/api/v1/filesystem-blacklist":
            if not self._require_admin_session():
                return
            with sqlite3.connect(DB_PATH) as conn:
                patterns = get_filesystem_blacklist_patterns(conn)
            self._send_json(HTTPStatus.OK, {"patterns": patterns})
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
                    """
                    SELECT h.hostname,
                           h.display_name_override,
                           COALESCE(h.country_code_override, ''),
                           COALESCE(h.is_favorite, 0),
                           COALESCE(h.is_hidden, 0),
                           h.customer_id,
                              COALESCE(h.environment_type, ''),
                           COALESCE(c.customer_name, ''),
                           COALESCE(c.maringo_project_number, '')
                    FROM host_settings h
                    LEFT JOIN customers c ON c.id = h.customer_id
                    """
                ).fetchall()

                host_uid_keys = [str(row[0] or "").strip() for row in rows if str(row[0] or "").strip()]
                host_uid_display_name_map: dict[str, str] = {}
                if host_uid_keys:
                    placeholders = ",".join(["?"] * len(host_uid_keys))
                    host_uid_rows = conn.execute(
                        f"""
                        SELECT host_uid, COALESCE(display_name_override, '')
                        FROM host_uid_settings
                        WHERE host_uid IN ({placeholders})
                        """,
                        tuple(host_uid_keys),
                    ).fetchall()
                    host_uid_display_name_map = {
                        str(row[0] or "").strip(): str(row[1] or "").strip()
                        for row in host_uid_rows
                        if str(row[0] or "").strip()
                    }

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
            host_key_expr = reports_host_key_sql()

            with sqlite3.connect(DB_PATH) as conn:
                rows = conn.execute(
                    f"""
                    WITH grouped AS (
                        SELECT
                            {host_key_expr} AS host_key,
                            MAX(received_at_utc) AS last_seen_utc,
                            COUNT(*) AS report_count,
                            MAX(id) AS latest_id
                        FROM reports
                        GROUP BY {host_key_expr}
                    ),
                    ordered AS (
                        SELECT
                            host_key,
                            last_seen_utc,
                            report_count,
                            latest_id,
                            COUNT(*) OVER() AS total_hosts
                        FROM grouped
                        ORDER BY last_seen_utc DESC
                        LIMIT ? OFFSET ?
                    )
                    SELECT
                        o.host_key,
                        o.last_seen_utc,
                        o.report_count,
                        COALESCE(r_latest.primary_ip, '') AS latest_primary_ip,
                        COALESCE(r_latest.agent_id, '') AS latest_agent_id,
                        COALESCE(r_latest.payload_json, '{{}}') AS latest_payload_json,
                        COALESCE(r_latest.hostname, '') AS latest_hostname,
                        o.total_hosts
                    FROM ordered o
                    JOIN reports r_latest ON r_latest.id = o.latest_id
                    ORDER BY o.last_seen_utc DESC
                    """,
                    (limit, offset),
                ).fetchall()

                total_hosts = int(rows[0][7] or 0) if rows else 0
                if not rows and offset > 0:
                    total_hosts = int(conn.execute(
                        f"SELECT COUNT(*) FROM (SELECT 1 FROM reports GROUP BY {host_key_expr})"
                    ).fetchone()[0] or 0)

                hostnames_for_counts = [str(row[6] or "").strip() for row in rows if str(row[6] or "").strip()]
                open_counts_by_hostname: dict[str, tuple[int, int]] = {}
                if hostnames_for_counts:
                    placeholders = ",".join(["?"] * len(hostnames_for_counts))
                    alert_rows = conn.execute(
                        f"""
                        SELECT a.hostname,
                               COUNT(*) AS open_alert_count,
                               SUM(CASE WHEN a.severity = 'critical' THEN 1 ELSE 0 END) AS open_critical_alert_count
                        FROM alerts a
                        LEFT JOIN muted_alert_rules m
                          ON m.hostname = a.hostname AND m.mountpoint = a.mountpoint
                        WHERE a.status = 'open'
                          AND m.hostname IS NULL
                          AND a.hostname IN ({placeholders})
                        GROUP BY a.hostname
                        """,
                        tuple(hostnames_for_counts),
                    ).fetchall()
                    open_counts_by_hostname = {
                        str(row[0] or ""): (int(row[1] or 0), int(row[2] or 0))
                        for row in alert_rows
                    }

                settings_rows = conn.execute(
                    """
                    SELECT h.hostname,
                           h.display_name_override,
                           COALESCE(h.country_code_override, ''),
                           COALESCE(h.is_favorite, 0),
                           COALESCE(h.is_hidden, 0),
                           h.customer_id,
                              COALESCE(h.environment_type, ''),
                           COALESCE(c.customer_name, ''),
                           COALESCE(c.maringo_project_number, '')
                    FROM host_settings h
                    LEFT JOIN customers c ON c.id = h.customer_id
                    """
                ).fetchall()

                host_uid_keys = [str(row[0] or "").strip() for row in rows if str(row[0] or "").strip()]
                host_uid_display_name_map: dict[str, str] = {}
                if host_uid_keys:
                    placeholders = ",".join(["?"] * len(host_uid_keys))
                    host_uid_rows = conn.execute(
                        f"""
                        SELECT host_uid, COALESCE(display_name_override, '')
                        FROM host_uid_settings
                        WHERE host_uid IN ({placeholders})
                        """,
                        tuple(host_uid_keys),
                    ).fetchall()
                    host_uid_display_name_map = {
                        str(row[0] or "").strip(): str(row[1] or "").strip()
                        for row in host_uid_rows
                        if str(row[0] or "").strip()
                    }

            settings_map = {
                str(row[0]): {
                    "display_name_override": str(row[1] or ""),
                    "country_code_override": normalize_country_code(row[2]),
                    "is_favorite": bool(int(row[3] or 0)),
                    "is_hidden": bool(int(row[4] or 0)),
                    "customer_id": int(row[5]) if row[5] is not None else None,
                    "environment_type": str(row[6] or "").strip().lower(),
                    "customer_name": str(row[7] or ""),
                    "customer_maringo_project_number": str(row[8] or ""),
                }
                for row in settings_rows
            }
            hosts = []
            for row in rows:
                latest_payload = parse_payload_json(row[5] or "{}")
                sap_license = latest_payload.get("sap_license") if isinstance(latest_payload, dict) else None
                has_sap_license_info = False
                if isinstance(sap_license, dict):
                    focus_types = sap_license.get("focus_license_types")
                    has_focus_types = isinstance(focus_types, list) and len(focus_types) > 0
                    has_license_core = any(
                        str(sap_license.get(field, "") or "").strip()
                        for field in ("hardware_key", "instno", "system_nr", "customer_no", "customer_name", "expiration")
                    )
                    has_sap_license_info = bool(has_focus_types or has_license_core)
                host_uid_key = str(row[0] or "").strip()
                hostname = str(row[6] or "").strip()
                host_settings = settings_map.get(hostname, {
                    "display_name_override": "",
                    "country_code_override": "",
                    "is_favorite": False,
                    "is_hidden": False,
                })
                display_name_override = str(host_uid_display_name_map.get(host_uid_key, "") or "").strip()
                if not display_name_override:
                    display_name_override = str(host_settings.get("display_name_override", "") or "").strip()
                country_code = normalize_country_code(host_settings.get("country_code_override", ""))
                if not country_code:
                    country_code = extract_country_code_from_payload(latest_payload)

                release_info = _extract_sap_hana_ram(latest_payload)

                hosts.append(
                    {
                        "host_uid": host_uid_key,
                        "hostname": hostname,
                        "display_name": effective_display_name(
                            latest_payload,
                            display_name_override,
                            hostname,
                        ),
                        "last_seen_utc": row[1],
                        "report_count": row[2],
                        "primary_ip": row[3] or "",
                        "std_nic_ip": _resolve_std_nic_ipv4(latest_payload, str(row[3] or "")),
                        "agent_id": row[4] or "",
                        "agent_version": str(latest_payload.get("agent_version", "")),
                        "delivery_mode": str(latest_payload.get("delivery_mode", "live") or "live"),
                        "is_delayed": bool(latest_payload.get("is_delayed", False)),
                        "queue_depth": payload_int(latest_payload, "queue_depth", 0),
                        "open_alert_count": int(open_counts_by_hostname.get(hostname, (0, 0))[0]),
                        "open_critical_alert_count": int(open_counts_by_hostname.get(hostname, (0, 0))[1]),
                        "os": str(latest_payload.get("os", "")),
                        "country_code": country_code,
                        "sap_release": release_info["sap_release"],
                        "sap_feature_pack": release_info["sap_release"],
                        "hana_release": release_info["hana_version"],
                        "hana_version": release_info["hana_version"],
                        "hana_sid": release_info["hana_sid"],
                        "ram_gb": release_info["ram_gb"],
                        "is_favorite": bool(host_settings.get("is_favorite", False)),
                        "is_hidden": bool(host_settings.get("is_hidden", False)),
                        "customer_id": host_settings.get("customer_id"),
                        "customer_name": str(host_settings.get("customer_name", "") or ""),
                        "customer_maringo_project_number": str(host_settings.get("customer_maringo_project_number", "") or ""),
                        "environment_type": str(host_settings.get("environment_type", "") or ""),
                        "agent_api_key_status": str((latest_payload.get("agent_api_key") or {}).get("status", "off")),
                        "has_sap_license_info": has_sap_license_info,
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
            host_uid = query.get("host_uid", [""])[0].strip()
            if not hostname and not host_uid:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "host_uid or hostname query parameter is required"})
                return

            host_key_expr = reports_host_key_sql()

            where_clause = "hostname = ?"
            where_args: tuple = (hostname,)
            if host_uid:
                where_clause = f"({host_key_expr} = ?)"
                where_args = (host_uid,)

            limit = parse_int(query, "limit", default=10, min_value=1, max_value=200)
            offset = parse_int(query, "offset", default=0, min_value=0, max_value=500000)
            jump_to_utc_raw = query.get("jump_to_utc", [""])[0].strip()

            jump_to_utc_iso = ""
            if jump_to_utc_raw:
                try:
                    jump_dt = datetime.fromisoformat(jump_to_utc_raw.replace("Z", "+00:00"))
                    if jump_dt.tzinfo is None:
                        jump_dt = jump_dt.replace(tzinfo=timezone.utc)
                    else:
                        jump_dt = jump_dt.astimezone(timezone.utc)
                    jump_to_utc_iso = jump_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
                except ValueError:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "jump_to_utc must be a valid ISO datetime"})
                    return

            with sqlite3.connect(DB_PATH) as conn:
                total_reports = conn.execute(
                    f"SELECT COUNT(*) FROM reports WHERE {where_clause}",
                    where_args,
                ).fetchone()[0]

                bounds_row = conn.execute(
                    f"SELECT MIN(received_at_utc), MAX(received_at_utc) FROM reports WHERE {where_clause}",
                    where_args,
                ).fetchone()
                oldest_report_at_utc = str((bounds_row[0] if bounds_row else "") or "")
                newest_report_at_utc = str((bounds_row[1] if bounds_row else "") or "")

                if jump_to_utc_iso and total_reports > 0:
                    jump_offset = conn.execute(
                        f"SELECT COUNT(*) FROM reports WHERE {where_clause} AND received_at_utc > ?",
                        (*where_args, jump_to_utc_iso),
                    ).fetchone()[0]
                    if jump_offset >= total_reports:
                        offset = max(0, total_reports - 1)
                    else:
                        offset = max(0, jump_offset)

                rows = conn.execute(
                    f"""
                    SELECT id, received_at_utc, agent_id, hostname, primary_ip, payload_json, {host_key_expr}
                    FROM reports
                    WHERE {where_clause}
                    ORDER BY id DESC
                    LIMIT ? OFFSET ?
                    """,
                    (*where_args, limit, offset),
                ).fetchall()

                resolved_hostname = ""
                if rows:
                    resolved_hostname = str(rows[0][3] or "").strip()
                display_name_override = get_display_name_override(conn, resolved_hostname or hostname, host_uid)

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
                        "host_uid": row[6],
                        "primary_ip": row[4],
                        "delivery_mode": delivery_mode,
                        "display_name": effective_display_name(payload, display_name_override, str(row[3] or "")),
                        "payload": payload,
                    }
                )

            self._send_json(
                HTTPStatus.OK,
                {
                    "count": len(reports),
                    "limit": limit,
                    "offset": offset,
                    "total_reports": total_reports,
                    "oldest_report_at_utc": oldest_report_at_utc,
                    "newest_report_at_utc": newest_report_at_utc,
                    "hostname": str(rows[0][3] if rows else hostname),
                    "host_uid": host_uid,
                    "reports": reports,
                },
            )
            return

        if parsed.path == "/api/v1/host-settings":
            query = parse_qs(parsed.query)
            hostname = query.get("hostname", [""])[0].strip()
            host_uid = query.get("host_uid", [""])[0].strip()
            if not hostname and not host_uid:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "hostname or host_uid query parameter is required"})
                return

            with sqlite3.connect(DB_PATH) as conn:
                resolved_hostname = hostname
                if not resolved_hostname and host_uid:
                    host_key_expr = reports_host_key_sql()
                    row = conn.execute(
                        f"""
                        SELECT COALESCE(hostname, '')
                        FROM reports
                        WHERE {host_key_expr} = ?
                        ORDER BY id DESC
                        LIMIT 1
                        """,
                        (host_uid,),
                    ).fetchone()
                    resolved_hostname = str((row[0] if row else "") or "").strip()

                host_settings = get_host_settings(conn, resolved_hostname)
                display_name_override = get_display_name_override(conn, resolved_hostname, host_uid)

            self._send_json(
                HTTPStatus.OK,
                {
                    "hostname": resolved_hostname or hostname,
                    "host_uid": host_uid,
                    "display_name_override": display_name_override,
                    "country_code_override": host_settings["country_code_override"],
                    "is_favorite": host_settings["is_favorite"],
                    "is_hidden": host_settings["is_hidden"],
                    "customer_alert_emails": host_settings["customer_alert_emails"],
                    "customer_alert_mountpoints": host_settings["customer_alert_mountpoints"],
                    "customer_alert_min_severity": host_settings["customer_alert_min_severity"],
                    "customer_id": host_settings["customer_id"],
                    "environment_type": host_settings["environment_type"],
                    "customer_name": host_settings["customer_name"],
                    "customer_maringo_project_number": host_settings["customer_maringo_project_number"],
                },
            )
            return

        if parsed.path == "/api/v1/database-lifecycle":
            query = parse_qs(parsed.query)
            hostname = query.get("hostname", [""])[0].strip()
            if not hostname:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "hostname query parameter is required"})
                return

            limit = parse_int(query, "limit", default=100, min_value=1, max_value=1000)
            offset = parse_int(query, "offset", default=0, min_value=0, max_value=500000)

            with sqlite3.connect(DB_PATH) as conn:
                data = get_database_lifecycle_for_host(conn, hostname, limit=limit, offset=offset)

            self._send_json(HTTPStatus.OK, data)
            return

        if parsed.path == "/api/v1/host-changelog":
            query = parse_qs(parsed.query)
            hostname = query.get("hostname", [""])[0].strip()
            if not hostname:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "hostname query parameter is required"})
                return

            limit = parse_int(query, "limit", default=100, min_value=1, max_value=1000)
            offset = parse_int(query, "offset", default=0, min_value=0, max_value=500000)

            with sqlite3.connect(DB_PATH) as conn:
                data = get_host_config_changes_for_host(conn, hostname, limit=limit, offset=offset)

            self._send_json(HTTPStatus.OK, data)
            return

        if parsed.path == "/api/v1/agent-update-status":
            with sqlite3.connect(DB_PATH) as conn:
                expire_old_agent_commands(conn)
                host_settings_rows = conn.execute(
                    """
                    SELECT h.hostname, h.display_name_override, COALESCE(c.customer_name, '')
                    FROM host_settings h
                    LEFT JOIN customers c ON c.id = h.customer_id
                    """
                ).fetchall()
                latest_reports = get_latest_report_rows_by_hostname(conn)
                latest_commands = get_latest_update_command_rows(conn)
                conn.commit()

            overrides = {str(row[0] or ""): str(row[1] or "") for row in host_settings_rows}
            customer_names = {str(row[0] or ""): str(row[2] or "").strip() for row in host_settings_rows}
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
                        "customer_name": customer_names.get(hostname, ""),
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
                    "default_schedule_note": "Linux-Installer im Repo plant den Fallback-Check standardmässig um 00:11, 06:11, 12:11 und 18:11 Uhr. Windows plant standardmässig alle 6 Stunden relativ zum Installationszeitpunkt. Der priorisierte Zusatz-Check läuft standardmässig alle 60 Minuten seit dem letzten Check.",
                    "hosts": hosts,
                },
            )
            return

        if parsed.path == "/api/v1/critical-trends":
            username = self._web_session_username()
            if not username:
                self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "authentication required"})
                return
            
            query = parse_qs(parsed.query)
            hours = parse_int(query, "hours", default=72, min_value=1, max_value=24 * 30)
            project_hours = parse_int(query, "project_hours", default=72, min_value=1, max_value=24 * 7)
            
            with sqlite3.connect(DB_PATH) as conn:
                preferences = get_user_preferences(conn, username)
                selected_metrics = parse_critical_trends_metrics(preferences.get("critical_trends_metrics", "filesystem"))
                # Get all hosts and their hidden filesystems for this user
                all_hostnames = {
                    row[0]
                    for row in conn.execute(
                        "SELECT DISTINCT hostname FROM reports WHERE received_at_utc >= ? ORDER BY hostname ASC",
                        (utc_hours_ago_iso(hours),),
                    ).fetchall()
                }
                hidden_mountpoints_by_host = {}
                for hostname in all_hostnames:
                    hidden_critical = get_filesystem_visibility_hidden(conn, username, hostname, "critical-trends")
                    hidden_fs_focus = get_filesystem_visibility_hidden(conn, username, hostname, "fs-focus")
                    hidden = sorted({*(hidden_critical or []), *(hidden_fs_focus or [])}, key=lambda item: str(item).lower())
                    if hidden:
                        hidden_mountpoints_by_host[hostname] = hidden
                
                warnings = collect_critical_trends(
                    conn,
                    hours,
                    hidden_mountpoints_by_host,
                    selected_metrics=selected_metrics,
                )

            self._send_json(HTTPStatus.OK, {
                "hours": hours,
                "project_hours": project_hours,
                "warnings": warnings,
                "total": len(warnings),
            })
            return

        if parsed.path == "/api/v1/host-update-log":
            query = parse_qs(parsed.query)
            hostname_param = (query.get("hostname") or [""])[0].strip()
            if not hostname_param:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "hostname parameter required"})
                return
            try:
                with sqlite3.connect(DB_PATH) as conn:
                    row = conn.execute(
                        "SELECT payload_json FROM reports WHERE hostname = ? ORDER BY id DESC LIMIT 1",
                        (hostname_param,),
                    ).fetchone()
                if not row:
                    self._send_json(HTTPStatus.OK, {"hostname": hostname_param, "lines": [], "crash_info": "", "available": False})
                    return
                payload = {}
                if row[0]:
                    try:
                        payload = json.loads(row[0])
                    except Exception as e:
                        pass
                agent_update = payload.get("agent_update", {}) if isinstance(payload.get("agent_update"), dict) else {}
                lines = agent_update.get("lines", []) if isinstance(agent_update.get("lines"), list) else []
                crash_info = str(agent_update.get("last_crash", "") or "")
                self._send_json(HTTPStatus.OK, {
                    "hostname": hostname_param,
                    "available": bool(lines or crash_info),
                    "lines": [str(l) for l in lines],
                    "crash_info": crash_info,
                    "log_path": str(agent_update.get("path", "")),
                })
            except Exception as e:
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"host-update-log endpoint error: {str(e)}"})
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

            hours = parse_int(query, "hours", default=24, min_value=1, max_value=24 * 30)
            cutoff_iso = utc_hours_ago_iso(hours)
            username = self._web_session_username()

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
                hidden_mountpoints = get_filesystem_visibility_hidden(conn, username, hostname, "analysis")
                fs_focus_hidden = get_filesystem_visibility_hidden(conn, username, hostname, "fs-focus")
                large_files_hidden = get_filesystem_visibility_hidden(conn, username, hostname, "large-files")
                blacklist_patterns = [row[0] for row in conn.execute("SELECT pattern FROM filesystem_blacklist_patterns").fetchall()]

            fs_by_mountpoint = {}
            fs_total_kb_by_mountpoint = {}
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
            latest_memory_total_kb = 0
            latest_large_files = {}
            delayed_report_count = 0
            live_report_count = 0
            latest_delivery_mode = "live"
            latest_is_delayed = False
            latest_queue_depth = 0

            for row in rows:
                report_count += 1
                latest_report_time = row[1]
                payload = parse_payload_json(row[2])
                large_files_raw = payload.get("large_files") if isinstance(payload, dict) else None
                if isinstance(large_files_raw, dict):
                    latest_large_files = large_files_raw
                elif isinstance(large_files_raw, str):
                    try:
                        parsed_large_files = json.loads(large_files_raw)
                        if isinstance(parsed_large_files, dict):
                            latest_large_files = parsed_large_files
                    except Exception:
                        pass
                delivery_mode = str(payload.get("delivery_mode", "live") or "live").lower()
                is_delayed = delivery_mode == "delayed" or bool(payload.get("is_delayed", False))
                if is_delayed:
                    delayed_report_count += 1
                else:
                    live_report_count += 1
                latest_delivery_mode = "delayed" if is_delayed else "live"
                latest_is_delayed = is_delayed
                latest_queue_depth = payload_int(payload, "queue_depth", 0)

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

                memory_block = payload.get("memory")
                if isinstance(memory_block, dict):
                    total_kb = int(memory_block.get("total_kb") or 0)
                    if total_kb > 0:
                        latest_memory_total_kb = total_kb
                if latest_memory_total_kb <= 0:
                    memory_mb = payload_int(payload, "memory_mb", 0)
                    if memory_mb > 0:
                        latest_memory_total_kb = int(memory_mb * 1024)

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
                    if not mountpoint:
                        continue
                    if any(fnmatch.fnmatch(mountpoint, pat) for pat in blacklist_patterns):
                        continue
                    used_percent_raw = fs.get("used_percent")
                    try:
                        used_percent = float(used_percent_raw)
                    except (TypeError, ValueError):
                        continue

                    total_kb_raw = fs.get("blocks", fs.get("total_kb", 0))
                    try:
                        total_kb = int(float(total_kb_raw or 0))
                    except (TypeError, ValueError):
                        total_kb = 0
                    if total_kb > 0:
                        fs_total_kb_by_mountpoint[mountpoint] = total_kb

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
                        "total_kb": int(fs_total_kb_by_mountpoint.get(mountpoint, 0) or 0),
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
                    "latest_memory_total_kb": latest_memory_total_kb,
                    "delivery": {
                        "latest_mode": latest_delivery_mode,
                        "latest_is_delayed": latest_is_delayed,
                        "latest_queue_depth": latest_queue_depth,
                        "delayed_report_count": delayed_report_count,
                        "live_report_count": live_report_count,
                    },
                    "filesystem_visibility": {
                        "section": "analysis",
                        "hidden_mountpoints": hidden_mountpoints,
                        "fs_focus_hidden": fs_focus_hidden,
                        "large_files_hidden": large_files_hidden,
                    },
                    "large_files": latest_large_files,
                    "filesystem_trends": trends,
                },
            )
            return

        if parsed.path == "/api/v1/backup-status-overview":
            query = parse_qs(parsed.query)
            hours = parse_int(query, "hours", default=24, min_value=1, max_value=24 * 30)
            with sqlite3.connect(DB_PATH) as conn:
                data = collect_backup_status_overview(conn, hours)
            self._send_json(HTTPStatus.OK, data)
            return

        if parsed.path == "/api/v1/customer-overview":
            with sqlite3.connect(DB_PATH) as conn:
                data = collect_customer_overview(conn)
            self._send_json(HTTPStatus.OK, data)
            return

        if parsed.path == "/api/v1/host-config-changes":
            query = parse_qs(parsed.query)
            hours = parse_int(query, "hours", default=24, min_value=1, max_value=24 * 30)
            limit = parse_int(query, "limit", default=300, min_value=1, max_value=1000)
            with sqlite3.connect(DB_PATH) as conn:
                data = collect_host_config_changes(conn, hours=hours, limit=limit)
            self._send_json(HTTPStatus.OK, data)
            return

        if parsed.path == "/api/v1/agent-source-status":
            with sqlite3.connect(DB_PATH) as conn:
                data = collect_agent_source_status(conn)
            self._send_json(HTTPStatus.OK, data)
            return

        if parsed.path == "/api/v1/export/alerts.csv":
            query = parse_qs(parsed.query)
            status = str(query.get("status", ["active"])[0] or "active").strip().lower()
            severity = str(query.get("severity", ["all"])[0] or "all").strip().lower()
            with sqlite3.connect(DB_PATH) as conn:
                rows = export_alerts_rows(conn, status=status, severity=severity)

            header = "id,hostname,mountpoint,severity,used_percent,current_used_percent,delta_used_percent,created_at_utc,last_seen_at_utc,resolved_at_utc\n"
            lines = [header]
            for item in rows:
                current_used_percent = item.get("current_used_percent")
                delta_used_percent = item.get("delta_used_percent")
                current_used_percent_text = "" if current_used_percent is None else format(float(current_used_percent), ".2f")
                delta_used_percent_text = "" if delta_used_percent is None else format(float(delta_used_percent), ".2f")
                line = (
                    f"{int(item.get('id', 0))},"
                    f"\"{str(item.get('hostname', '')).replace('"', '""')}\","
                    f"\"{str(item.get('mountpoint', '')).replace('"', '""')}\","
                    f"{str(item.get('severity', 'warning'))},"
                    f"{float(item.get('used_percent', 0.0)):.2f},"
                    f"{current_used_percent_text},"
                    f"{delta_used_percent_text},"
                    f"{str(item.get('created_at_utc', ''))},"
                    f"{str(item.get('last_seen_at_utc', ''))},"
                    f"{str(item.get('resolved_at_utc', ''))}\n"
                )
                lines.append(line)
            data = "".join(lines).encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/csv; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="alerts-export.csv"')
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        if parsed.path == "/api/v1/export/reports.json":
            query = parse_qs(parsed.query)
            hostname = str(query.get("hostname", [""])[0] or "").strip()
            host_uid = str(query.get("host_uid", [""])[0] or "").strip()
            limit = parse_int(query, "limit", default=500, min_value=1, max_value=2000)
            with sqlite3.connect(DB_PATH) as conn:
                rows = export_reports_rows(conn, hostname=hostname, host_uid=host_uid, limit=limit)
            payload = {
                "count": len(rows),
                "hostname": hostname,
                "host_uid": host_uid,
                "limit": limit,
                "reports": rows,
            }
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="reports-export.json"')
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
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

            closed_filter = query.get("closed", ["all"])[0].strip().lower()
            if closed_filter not in {"all", "yes", "no"}:
                closed_filter = "all"

            hostname_filter = query.get("hostname", [""])[0].strip()
            host_uid_filter = query.get("host_uid", [""])[0].strip()
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
            if closed_filter == "no":
                where_parts.append("(closed_at_utc IS NULL OR closed_at_utc = '')")
            elif closed_filter == "yes":
                where_parts.append("(closed_at_utc IS NOT NULL AND closed_at_utc != '')")
            if hostname_filter:
                where_parts.append("hostname = ?")
                args.append(hostname_filter)
            if host_uid_filter:
                host_key_expr = reports_host_key_sql("r.")
                where_parts.append(
                    f"EXISTS (SELECT 1 FROM reports r WHERE r.id = alerts.report_id AND {host_key_expr} = ?)"
                )
                args.append(host_uid_filter)

            where_clause = ""
            if where_parts:
                where_clause = "WHERE " + " AND ".join(where_parts)

            with sqlite3.connect(DB_PATH) as conn:
                all_rows = conn.execute(
                    f"""
                    SELECT id, hostname, mountpoint, severity, used_percent, status,
                          created_at_utc, last_seen_at_utc, resolved_at_utc, report_id,
                          COALESCE(ack_note, ''), COALESCE(ack_by, ''), COALESCE(ack_at_utc, ''),
                          COALESCE(closed_at_utc, ''), COALESCE(closed_by, '')
                    FROM alerts
                    {where_clause}
                    ORDER BY id DESC
                    """,
                    tuple(args),
                ).fetchall()
                blacklist_patterns = get_filesystem_blacklist_pattern_strings(conn)
                filtered_rows = [
                    row
                    for row in all_rows
                    if not is_filesystem_blacklisted_by_patterns(str(row[2] or ""), blacklist_patterns)
                ]
                total = len(filtered_rows)
                rows = filtered_rows[offset : offset + limit]

                hostnames = sorted({str(row[1]) for row in rows if row[1]})
                display_names: dict[str, str] = {}
                if hostnames:
                    placeholders = ",".join("?" for _ in hostnames)
                    settings_rows = conn.execute(
                        f"""
                        SELECT h.hostname,
                               h.display_name_override,
                               COALESCE(c.customer_name, '')
                        FROM host_settings h
                        LEFT JOIN customers c ON c.id = h.customer_id
                        WHERE h.hostname IN ({placeholders})
                        """,
                        tuple(hostnames),
                    ).fetchall()
                    overrides = {str(item[0]): str(item[1] or "") for item in settings_rows}
                    customer_names = {str(item[0]): str(item[2] or "").strip() for item in settings_rows}

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
                        if not customer_names.get(hostname):
                            host_settings = get_host_settings(conn, hostname)
                            customer_names[hostname] = str(host_settings.get("customer_name", "") or "").strip()

                latest_usage_by_host = _collect_latest_report_usage_by_host(conn, hostnames)

            alerts = []
            with sqlite3.connect(DB_PATH) as conn_mute:
                muted_pairs = {
                    (str(r[0]), str(r[1]))
                    for r in conn_mute.execute("SELECT hostname, mountpoint FROM muted_alert_rules").fetchall()
                }
            for row in rows:
                hostname = str(row[1] or "")
                mountpoint = str(row[2] or "")
                current_used_percent = None
                if mountpoint:
                    current_used_percent = latest_usage_by_host.get(hostname, {}).get(normalize_mountpoint_key(mountpoint))
                delta_used_percent = None
                if current_used_percent is not None:
                    delta_used_percent = abs(float(current_used_percent) - float(row[4] or 0.0))
                alerts.append(
                    {
                        "id": row[0],
                        "hostname": hostname,
                        "display_name": display_names.get(hostname, hostname),
                        "customer_name": customer_names.get(hostname, "") or "Ohne Kunde",
                        "mountpoint": mountpoint,
                        "severity": row[3],
                        "used_percent": row[4],
                        "current_used_percent": current_used_percent,
                        "delta_used_percent": delta_used_percent,
                        "status": row[5],
                        "created_at_utc": row[6],
                        "last_seen_at_utc": row[7],
                        "resolved_at_utc": row[8],
                        "report_id": row[9],
                        "ack_note": str(row[10] or ""),
                        "ack_by": str(row[11] or ""),
                        "ack_at_utc": str(row[12] or ""),
                        "is_acknowledged": bool(str(row[12] or "").strip()),
                        "closed_at_utc": str(row[13] or ""),
                        "closed_by": str(row[14] or ""),
                        "is_closed": bool(str(row[13] or "").strip()),
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
                    "host_uid": host_uid_filter,
                    "alerts": alerts,
                },
            )
            return

        if parsed.path == "/api/v1/alerts-summary":
            query = parse_qs(parsed.query)
            hostname_filter = query.get("hostname", [""])[0].strip()
            host_uid_filter = query.get("host_uid", [""])[0].strip()

            where_clause = "WHERE status = 'open' AND (ack_by IS NULL OR ack_by = '')"
            args = []
            where_clause += " AND COALESCE((SELECT is_hidden FROM host_settings hs WHERE hs.hostname = alerts.hostname), 0) = 0"
            where_clause += " AND NOT EXISTS (SELECT 1 FROM muted_alert_rules m WHERE m.hostname = alerts.hostname AND m.mountpoint = alerts.mountpoint)"
            if hostname_filter:
                where_clause += " AND hostname = ?"
                args.append(hostname_filter)
            if host_uid_filter:
                host_key_expr = reports_host_key_sql("r.")
                where_clause += f" AND EXISTS (SELECT 1 FROM reports r WHERE r.id = alerts.report_id AND {host_key_expr} = ?)"
                args.append(host_uid_filter)

            with sqlite3.connect(DB_PATH) as conn:
                alarm_settings = get_alarm_settings(conn)
                rows = conn.execute(
                    f"SELECT severity, mountpoint FROM alerts {where_clause}",
                    tuple(args),
                ).fetchall()
                blacklist_patterns = get_filesystem_blacklist_pattern_strings(conn)
                visible_rows = [
                    row
                    for row in rows
                    if not is_filesystem_blacklisted_by_patterns(str(row[1] or ""), blacklist_patterns)
                ]
                total_open = len(visible_rows)
                warning_open = sum(1 for row in visible_rows if str(row[0] or "").strip().lower() == "warning")
                critical_open = sum(1 for row in visible_rows if str(row[0] or "").strip().lower() == "critical")

            self._send_json(
                HTTPStatus.OK,
                {
                    "hostname": hostname_filter,
                    "host_uid": host_uid_filter,
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

        if parsed.path == "/api/v1/system-overview":
            with sqlite3.connect(DB_PATH) as conn:
                data = collect_system_overview(conn)
            self._send_json(HTTPStatus.OK, data)
            return

        if parsed.path == "/api/v1/backup/database/start":
            if not self._require_admin_session():
                return
            created = _create_database_backup_job()
            if created.get("status") == "error":
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(created.get("error") or "backup start failed")})
                return
            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "started",
                    "job_id": created["job_id"],
                    "filename": created["filename"],
                },
            )
            return

        if parsed.path == "/api/v1/backup/database/status":
            if not self._require_admin_session():
                return
            query = parse_qs(parsed.query)
            job_id = str(query.get("job_id", [""])[0] or "").strip()
            if not job_id:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "job_id query parameter is required"})
                return
            _cleanup_backup_jobs()
            with _backup_jobs_lock:
                job = _backup_jobs.get(job_id)
            if not job:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "backup job not found"})
                return
            self._send_json(
                HTTPStatus.OK,
                {
                    "job_id": job_id,
                    "status": str(job.get("status") or "error"),
                    "filename": str(job.get("filename") or ""),
                    "error": str(job.get("error") or ""),
                },
            )
            return

        if parsed.path == "/api/v1/backup/database/download":
            if not self._require_admin_session():
                return
            query = parse_qs(parsed.query)
            job_id = str(query.get("job_id", [""])[0] or "").strip()
            if not job_id:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "job_id query parameter is required"})
                return
            _cleanup_backup_jobs()
            with _backup_jobs_lock:
                job = _backup_jobs.get(job_id)
                if job and str(job.get("status") or "") == "ready":
                    job = _backup_jobs.pop(job_id, None)
            if not job:
                self._send_json(HTTPStatus.NOT_FOUND, {"error": "backup job not found"})
                return
            if str(job.get("status") or "") != "ready":
                if str(job.get("status") or "") == "error":
                    self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(job.get("error") or "database backup failed")})
                else:
                    self._send_json(HTTPStatus.CONFLICT, {"error": "backup not ready yet"})
                return
            file_path = Path(str(job.get("file_path") or ""))
            filename = str(job.get("filename") or "monitoring-backup.db")
            sent = self._send_file(
                file_path,
                "application/octet-stream",
                extra_headers={
                    "Content-Disposition": f'attachment; filename="{filename}"',
                    "Cache-Control": "no-store",
                },
            )
            if file_path.exists():
                try:
                    file_path.unlink()
                except OSError:
                    pass
            if not sent:
                return
            return

        if parsed.path == "/api/v1/backup/database":
            if not self._require_admin_session():
                return
            _cleanup_backup_jobs()
            jobs: list[dict] = []
            with _backup_jobs_lock:
                for job_id, job in _backup_jobs.items():
                    jobs.append(
                        {
                            "job_id": job_id,
                            "status": str(job.get("status") or "unknown"),
                            "filename": str(job.get("filename") or ""),
                            "created_at_utc": str(job.get("created_at_utc") or ""),
                            "updated_at_utc": str(job.get("updated_at_utc") or ""),
                        }
                    )
            jobs.sort(key=lambda item: str(item.get("updated_at_utc") or ""), reverse=True)
            self._send_json(HTTPStatus.OK, {"count": len(jobs), "jobs": jobs})
            return

        if parsed.path == "/api/v1/sap-b1-version-map":
            entries = load_sap_b1_version_map_entries()
            self._send_json(
                HTTPStatus.OK,
                {
                    "count": len(entries),
                    "entries": entries,
                },
            )
            return

        if parsed.path == "/api/v1/sap-license-type-map":
            entries = load_sap_license_type_map_entries()
            self._send_json(
                HTTPStatus.OK,
                {
                    "count": len(entries),
                    "entries": entries,
                },
            )
            return

        if parsed.path == "/api/v1/alarm-settings":
            with sqlite3.connect(DB_PATH) as conn:
                settings = get_alarm_settings(conn)

            self._send_json(HTTPStatus.OK, alarm_settings_public_view(settings))
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
            self._send_file(
                STATIC_DIR / "app.js",
                "application/javascript; charset=utf-8",
                extra_headers={
                    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                    "Pragma": "no-cache",
                    "Expires": "0",
                },
            )
            return

        if parsed.path == "/styles.css":
            self._send_file(
                STATIC_DIR / "styles.css",
                "text/css; charset=utf-8",
                extra_headers={
                    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                    "Pragma": "no-cache",
                    "Expires": "0",
                },
            )
            return

        if parsed.path == "/sw.js":
            self._send_file(
                STATIC_DIR / "sw.js",
                "application/javascript; charset=utf-8",
                extra_headers={
                    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                    "Pragma": "no-cache",
                    "Expires": "0",
                },
            )
            return

        if parsed.path == "/manifest.json":
            self._send_file(
                STATIC_DIR / "manifest.json",
                "application/manifest+json; charset=utf-8",
                extra_headers={
                    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                    "Pragma": "no-cache",
                    "Expires": "0",
                },
            )
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

        if parsed.path.startswith("/updates/"):
            rel_path_raw = parsed.path[len("/updates/"):].strip("/")
            if not rel_path_raw:
                self.send_error(HTTPStatus.NOT_FOUND, "Not found")
                return
            rel_path = Path(rel_path_raw)
            if rel_path.is_absolute() or ".." in rel_path.parts:
                self.send_error(HTTPStatus.BAD_REQUEST, "Invalid path")
                return

            file_path = UPDATES_DIR / rel_path
            if not (file_path.exists() and file_path.is_file()):
                fallback_root = BASE_DIR.parent
                fallback_candidates: list[Path] = []

                # Serve current repo scripts if updates/ is missing or stale.
                if rel_path_raw in {"AGENT_VERSION", "BUILD_VERSION"}:
                    fallback_candidates.append(fallback_root / rel_path_raw)
                elif len(rel_path.parts) >= 3 and rel_path.parts[0] == "client" and rel_path.parts[1] in {"windows", "linux"}:
                    fallback_candidates.append(fallback_root / rel_path)

                for candidate in fallback_candidates:
                    if candidate.exists() and candidate.is_file():
                        file_path = candidate
                        break

            suffix = file_path.suffix.lower()
            if suffix == ".ps1":
                mime = "text/plain; charset=utf-8"
            elif suffix == ".sh":
                mime = "text/plain; charset=utf-8"
            elif suffix in {".txt", ""}:
                mime = "text/plain; charset=utf-8"
            else:
                mime = "application/octet-stream"

            self._send_file(
                file_path,
                mime,
                extra_headers={
                    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                    "Pragma": "no-cache",
                    "Expires": "0",
                },
            )
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
                record_web_login_event(
                    conn,
                    username=username,
                    display_name=str(user.get("display_name", "") or ""),
                    source_ip=self._request_client_ip(),
                    auth_method="password",
                    user_agent=str(self.headers.get("User-Agent", "") or ""),
                )
                conn.commit()

            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "authenticated",
                    "username": username,
                    "display_name": str(user.get("display_name", "") or ""),
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
                    "settings": alarm_settings_public_view(stored),
                },
            )
            return

        if path == "/api/v1/sap-b1-version-map":
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

            entries = payload.get("entries", []) if isinstance(payload, dict) else []
            if not isinstance(entries, list):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "entries must be a list"})
                return

            try:
                saved_entries = save_sap_b1_version_map_entries(entries)
            except OSError as exc:
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"save failed: {exc}"})
                return

            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "saved": len(saved_entries),
                    "entries": saved_entries,
                },
            )
            return

        if path == "/api/v1/sap-license-type-map":
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

            entries = payload.get("entries", []) if isinstance(payload, dict) else []
            if not isinstance(entries, list):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "entries must be a list"})
                return

            try:
                saved_entries = save_sap_license_type_map_entries(entries)
            except OSError as exc:
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": f"save failed: {exc}"})
                return

            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "saved": len(saved_entries),
                    "entries": saved_entries,
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

        if path == "/api/v1/user-preferences":
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
            if not isinstance(payload, dict):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid payload"})
                return
            with sqlite3.connect(DB_PATH) as conn:
                saved = save_user_preferences(conn, username, payload)
                conn.commit()
            self._send_json(HTTPStatus.OK, saved)
            return

        if path == "/api/v1/filesystem-visibility":
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
            if not isinstance(payload, dict):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid payload"})
                return

            hostname = str(payload.get("hostname", "") or "").strip()
            section = str(payload.get("section", "analysis") or "analysis").strip().lower()
            hidden_mountpoints_raw = payload.get("hidden_mountpoints", [])
            if not hostname:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "hostname missing"})
                return
            if section not in {"analysis", "critical-trends", "large-files", "fs-focus"}:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid section"})
                return
            if not isinstance(hidden_mountpoints_raw, list):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "hidden_mountpoints must be a list"})
                return

            with sqlite3.connect(DB_PATH) as conn:
                saved_hidden = save_filesystem_visibility_hidden(
                    conn,
                    username,
                    hostname,
                    section,
                    [str(item or "") for item in hidden_mountpoints_raw],
                )
                conn.commit()

            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "stored",
                    "username": username,
                    "hostname": hostname,
                    "section": section,
                    "hidden_mountpoints": saved_hidden,
                },
            )
            return

        if path == "/api/v1/filesystem-blacklist":
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

            if not isinstance(payload, dict):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid payload"})
                return

            action = str(payload.get("action", "")).strip().lower()
            pattern = str(payload.get("pattern", "")).strip()
            description = str(payload.get("description", "")).strip()

            if action == "add":
                if not pattern:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "pattern required"})
                    return
                try:
                    with sqlite3.connect(DB_PATH) as conn:
                        result = add_filesystem_blacklist_pattern(conn, pattern, description)
                        conn.commit()
                    self._send_json(HTTPStatus.OK, {"status": "added", "entry": result})
                except ValueError as exc:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return

            if action == "delete":
                pattern_id = int(payload.get("id", 0))
                if pattern_id <= 0:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "id required"})
                    return
                with sqlite3.connect(DB_PATH) as conn:
                    delete_filesystem_blacklist_pattern(conn, pattern_id)
                    conn.commit()
                self._send_json(HTTPStatus.OK, {"status": "deleted"})
                return

            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid action"})
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
                    subject = f"[TEST] Host Alert Abo für {host_context.get('display_name', hostname)}"
                    body = branded_info_mail_html(
                        username,
                        "Test Host Alert Abo",
                        (
                            "<p>Test für Host Alert Abo.</p>"
                            f"<p>User: <strong>{html.escape(username)}</strong></p>"
                            f"<p>Host: <strong>{html.escape(str(host_context.get('display_name', hostname)))}</strong> ({html.escape(hostname)})</p>"
                        ),
                        customer_name=str(host_context.get("customer_name", "") or ""),
                        host_label=str(host_context.get("display_name", hostname) or hostname),
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
                        "[TEST] Host Alert Abo\n"
                        f"User: {username}\n"
                        f"Kunde: {str(host_context.get('customer_name') or 'Ohne Kunde')}\n"
                        f"Host: {str(host_context.get('display_name', hostname))} ({hostname})\n"
                        f"Zeit: {datetime.now().astimezone().strftime('%d.%m.%Y %H:%M')}"
                    ),
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

        if path in {"/api/v1/mail-test", "/api/v1/mail-test/trends", "/api/v1/mail-test/alerts", "/api/v1/mail-test/backup"}:
            username = self._web_session_username()
            endpoint_mode = "generic"
            if path.endswith("/trends"):
                endpoint_mode = "trends"
            elif path.endswith("/alerts"):
                endpoint_mode = "alerts"
            elif path.endswith("/backup"):
                endpoint_mode = "backup"

            with sqlite3.connect(DB_PATH) as conn:
                settings = get_web_user_settings(conn, username)
                recipient = str(settings.get("email_recipient", "") or "").strip()
                sender_address = str(settings.get("email_sender", "") or "").strip()
                if not recipient:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "email recipient missing"})
                    return
                ok, access_token, details = ensure_microsoft_access_token(conn, username)
                if not ok:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": details or "oauth unavailable"})
                    return
                if endpoint_mode == "trends":
                    preferences = get_user_preferences(conn, username)
                    trend_allowed_hosts, trend_prioritized_hosts = get_user_trend_host_scope(conn, username)
                    selected_metrics = parse_critical_trends_metrics(preferences.get("critical_trends_metrics", "filesystem"))
                    # Build hidden mountpoints dict for this user
                    all_hostnames = {
                        row[0]
                        for row in conn.execute(
                            "SELECT DISTINCT hostname FROM reports WHERE received_at_utc >= ? ORDER BY hostname ASC",
                            (utc_hours_ago_iso(72),),
                        ).fetchall()
                    }
                    if trend_allowed_hosts is not None:
                        all_hostnames = {hostname for hostname in all_hostnames if hostname in trend_allowed_hosts}
                    hidden_mountpoints_by_host = {}
                    for hostname in all_hostnames:
                        hidden_critical = get_filesystem_visibility_hidden(conn, username, hostname, "critical-trends")
                        hidden_fs_focus = get_filesystem_visibility_hidden(conn, username, hostname, "fs-focus")
                        hidden = sorted({*(hidden_critical or []), *(hidden_fs_focus or [])}, key=lambda item: str(item).lower())
                        if hidden:
                            hidden_mountpoints_by_host[hostname] = hidden

                    warnings = collect_critical_trends(
                        conn,
                        72,
                        hidden_mountpoints_by_host,
                        allowed_hostnames=trend_allowed_hosts,
                        prioritized_hostnames=trend_prioritized_hosts,
                        selected_metrics=selected_metrics,
                    )
                    mail_ok, mail_details = send_microsoft_mail(
                        access_token,
                        recipient,
                        trend_digest_subject(warnings, datetime.now().astimezone().date().isoformat()) + " [TEST]",
                        trend_digest_html(username, warnings, 72),
                        content_type="HTML",
                        sender_address=sender_address,
                    )
                elif endpoint_mode == "alerts":
                    alerts = collect_open_alerts(conn)
                    graph_cids, graph_attachments = build_alert_digest_graph_bundle(conn, alerts, hours=24)
                    all_alert_recipients = resolve_user_alert_mail_recipients(
                        settings,
                        alert_digest_recipient_severity(alerts),
                    )
                    if not all_alert_recipients:
                        self._send_json(HTTPStatus.BAD_REQUEST, {"error": "no alert recipients configured"})
                        return
                    mail_ok, mail_details = send_microsoft_mail_multi(
                        access_token,
                        all_alert_recipients,
                        alert_digest_subject(alerts, datetime.now().astimezone().date().isoformat()) + " [TEST]",
                        alert_digest_html(username, alerts, graph_cids=graph_cids, graph_hours=24),
                        content_type="HTML",
                        attachments=graph_attachments,
                        sender_address=sender_address,
                    )
                elif endpoint_mode == "backup":
                    overview = collect_backup_status_overview(conn, 24)
                    missing = int(overview.get("missing_count") or 0)
                    total = int(overview.get("total") or 0)
                    missing_hosts: list[str] = []
                    for item in overview.get("items", [])[:20]:
                        if not isinstance(item, dict):
                            continue
                        if not bool(item.get("has_missing_backup")):
                            continue
                        missing_hosts.append(str(item.get("display_name") or item.get("hostname") or "?"))
                    if missing_hosts:
                        missing_items_html = "".join(
                            f"<li>{html.escape(name)}</li>" for name in missing_hosts
                        )
                        missing_block_html = f"<p>Betroffene Hosts:</p><ul>{missing_items_html}</ul>"
                    else:
                        missing_block_html = "<p>Aktuell keine fehlenden Backups erkannt.</p>"
                    backup_body = branded_info_mail_html(
                        username,
                        "Test Backup-Status Übersicht",
                        (
                            f"<p>Hosts mit fehlendem Backup: <strong>{missing}</strong> von <strong>{total}</strong>.</p>"
                            f"{missing_block_html}"
                        ),
                    )
                    mail_ok, mail_details = send_microsoft_mail(
                        access_token,
                        recipient,
                        f"[TEST] Backup Status: {missing}/{total} mit Luecken",
                        backup_body,
                        content_type="HTML",
                        sender_address=sender_address,
                    )
                else:
                    generic_body = branded_info_mail_html(
                        username,
                        "Test Monitoring OAuth Mail",
                        "<p>Wenn diese Mail ankommt, funktioniert Microsoft Graph OAuth.</p>",
                    )
                    mail_ok, mail_details = send_microsoft_mail(
                        access_token,
                        recipient,
                        "[TEST] Monitoring OAuth Mail",
                        generic_body,
                        content_type="HTML",
                        sender_address=sender_address,
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

        if path == "/api/v1/ai-troubleshoot":
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
            if not isinstance(payload, dict):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid payload"})
                return

            hostname = str(payload.get("hostname", "") or "").strip()
            metric = str(payload.get("metric", "") or "").strip()
            hours = int(payload.get("window_hours") or payload.get("hours") or 24)
            with sqlite3.connect(DB_PATH) as conn:
                response_payload = build_ai_troubleshoot_response(conn, hostname, metric, hours)
            self._send_json(HTTPStatus.OK, response_payload)
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
                            display_name=str(payload.get("display_name", "") or ""),
                        )
                    elif action == "set-password":
                        update_web_user_password(conn, target_username, str(payload.get("password", "") or ""))
                    elif action == "update-display-name":
                        update_web_user_display_name(conn, target_username, str(payload.get("display_name", "") or ""))
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

        if path == "/api/v1/host-config-changes/backfill":
            if not self._require_admin_session():
                return
            content_length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(content_length) if content_length > 0 else b"{}"
            try:
                payload = json.loads(raw_body)
            except json.JSONDecodeError:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid json"})
                return

            days = 7
            if isinstance(payload, dict) and "days" in payload:
                try:
                    days = max(1, min(int(payload.get("days", 7)), 30))
                except (TypeError, ValueError):
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "days must be an integer between 1 and 30"})
                    return

            try:
                with sqlite3.connect(DB_PATH) as conn:
                    config_result = backfill_host_config_changes(conn, days=days)
                    db_result = backfill_database_lifecycle(conn, days=days)
                    conn.commit()

                self._send_json(
                    HTTPStatus.OK,
                    {
                        "status": "ok",
                        "result": {
                            "config_changes": config_result,
                            "database_lifecycle": db_result,
                            "inserted_changes": config_result.get("inserted_changes", 0),
                            "reports_scanned": config_result.get("reports_scanned", 0),
                            "inserted_events": db_result.get("inserted_events", 0),
                        },
                    },
                )
            except Exception as e:
                import traceback
                error_msg = f"{type(e).__name__}: {str(e)}"
                traceback.print_exc()
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": error_msg})
            return



        if path == "/api/v1/alarm-test":
            with sqlite3.connect(DB_PATH) as conn:
                settings = get_alarm_settings(conn)

            ok, details = telegram_send(
                settings,
                (
                    "[TEST] Monitoring Alarm-Kanal\n"
                    f"Serverzeit: {utc_now_iso()}\n"
                    "Wenn du diese Nachricht siehst, ist Telegram korrekt konfiguriert."
                ),
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

        if path == "/api/v1/customer-alert/test":
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
            if not isinstance(payload, dict):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid payload"})
                return

            username = self._web_session_username()
            hostname = str(payload.get("hostname", "") or "").strip()
            recipients = parse_email_recipients(payload.get("recipients") or payload.get("recipient") or "")
            if not recipients:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "no recipients"})
                return

            with sqlite3.connect(DB_PATH) as conn:
                ok_token, access_token, details = ensure_microsoft_access_token(conn, username)
                if not ok_token:
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": details or "oauth unavailable"})
                    return
                user_settings = get_web_user_settings(conn, username)

                host_context = collect_host_mail_context(conn, hostname) if hostname else {"display_name": "(ohne Host)", "hostname": "", "customer_name": ""}
                subject = f"[TEST] Kundenalarm {str(host_context.get('display_name') or hostname or '')}"
                body = branded_info_mail_html(
                    username,
                    "Test Kundenalarm",
                    (
                        "<p>Dies ist ein Test für den Kundenalarm.</p>"
                        f"<p>Host: <strong>{html.escape(str(host_context.get('display_name') or hostname or '-'))}</strong></p>"
                        f"<p>Ausgeloest von: <strong>{html.escape(username)}</strong></p>"
                    ),
                    customer_name=str(host_context.get("customer_name", "") or ""),
                    host_label=str(host_context.get("display_name") or hostname or "-"),
                )
                ok_send, send_details = send_microsoft_mail_multi(
                    access_token,
                    recipients,
                    subject,
                    body,
                    content_type="HTML",
                    sender_address=str(user_settings.get("email_sender", "") or "").strip(),
                )
                conn.commit()

            self._send_json(
                HTTPStatus.OK if ok_send else HTTPStatus.BAD_REQUEST,
                {
                    "status": "sent" if ok_send else "failed",
                    "details": send_details,
                    "recipients": recipients,
                },
            )
            return

        if path == "/api/v1/customers":
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

            if not isinstance(payload, dict):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid payload"})
                return

            customer_name = payload.get("customer_name", "")
            maringo_project_number = payload.get("maringo_project_number", "")

            try:
                with sqlite3.connect(DB_PATH) as conn:
                    customer = upsert_customer(conn, customer_name, maringo_project_number)
                    conn.commit()
                self._send_json(HTTPStatus.OK, {"status": "stored", "customer": customer})
            except ValueError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
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
            host_uid = str(payload.get("host_uid", "") or "").strip()
            has_display_name = "display_name_override" in payload
            has_country_code = "country_code_override" in payload
            has_is_favorite = "is_favorite" in payload
            has_is_hidden = "is_hidden" in payload
            has_customer_alert_emails = "customer_alert_emails" in payload
            has_customer_alert_mountpoints = "customer_alert_mountpoints" in payload
            has_customer_alert_min_severity = "customer_alert_min_severity" in payload
            has_customer_id = "customer_id" in payload
            has_environment_type = "environment_type" in payload

            if not hostname and not host_uid:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "hostname or host_uid missing"})
                return

            if not (
                has_display_name
                or has_country_code
                or has_is_favorite
                or has_is_hidden
                or has_customer_alert_emails
                or has_customer_alert_mountpoints
                or has_customer_alert_min_severity
                or has_customer_id
                or has_environment_type
            ):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "no host setting provided"})
                return

            with sqlite3.connect(DB_PATH) as conn:
                resolved_hostname = hostname
                if not resolved_hostname and host_uid:
                    host_key_expr = reports_host_key_sql()
                    row = conn.execute(
                        f"""
                        SELECT COALESCE(hostname, '')
                        FROM reports
                        WHERE {host_key_expr} = ?
                        ORDER BY id DESC
                        LIMIT 1
                        """,
                        (host_uid,),
                    ).fetchone()
                    resolved_hostname = str((row[0] if row else "") or "").strip()

                if not resolved_hostname and (
                    has_country_code
                    or has_is_favorite
                    or has_is_hidden
                    or has_customer_alert_emails
                    or has_customer_alert_mountpoints
                    or has_customer_alert_min_severity
                    or has_customer_id
                    or has_environment_type
                ):
                    self._send_json(HTTPStatus.BAD_REQUEST, {"error": "hostname required for non-display host settings"})
                    return

                current = get_host_settings(conn, resolved_hostname)
                display_name_override = get_display_name_override(conn, resolved_hostname, host_uid)
                country_code_override = current["country_code_override"]
                is_favorite = bool(current["is_favorite"])
                is_hidden = bool(current["is_hidden"])
                customer_alert_emails = current["customer_alert_emails"]
                customer_alert_mountpoints = current["customer_alert_mountpoints"]
                customer_alert_min_severity = current["customer_alert_min_severity"]
                customer_id = current["customer_id"]
                environment_type = current["environment_type"]

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
                if has_customer_alert_emails:
                    customer_alert_emails = str(payload.get("customer_alert_emails", "") or "").strip()
                if has_customer_alert_mountpoints:
                    customer_alert_mountpoints = str(payload.get("customer_alert_mountpoints", "") or "").strip()
                if has_customer_alert_min_severity:
                    customer_alert_min_severity = str(payload.get("customer_alert_min_severity", "critical") or "critical").strip().lower()
                    if customer_alert_min_severity not in {"warning", "critical"}:
                        self._send_json(HTTPStatus.BAD_REQUEST, {"error": "customer_alert_min_severity must be warning or critical"})
                        return
                if has_customer_id:
                    raw_customer_id = payload.get("customer_id")
                    if raw_customer_id in (None, "", 0, "0"):
                        customer_id = None
                    else:
                        customer = get_customer_by_id(conn, raw_customer_id)
                        if customer is None:
                            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "customer_id not found"})
                            return
                        customer_id = int(customer["id"])
                if has_environment_type:
                    raw_environment_type = str(payload.get("environment_type", "") or "").strip().lower()
                    if raw_environment_type in {"prod", "prod."}:
                        environment_type = "prod"
                    elif raw_environment_type == "test":
                        environment_type = "test"
                    elif raw_environment_type in {"", "none"}:
                        environment_type = ""
                    else:
                        self._send_json(HTTPStatus.BAD_REQUEST, {"error": "environment_type must be empty, prod or test"})
                        return

                if has_display_name and host_uid:
                    if display_name_override:
                        conn.execute(
                            """
                            INSERT INTO host_uid_settings (host_uid, display_name_override, updated_at_utc)
                            VALUES (?, ?, ?)
                            ON CONFLICT(host_uid) DO UPDATE SET
                              display_name_override = excluded.display_name_override,
                              updated_at_utc = excluded.updated_at_utc
                            """,
                            (host_uid, display_name_override, utc_now_iso()),
                        )
                    else:
                        conn.execute("DELETE FROM host_uid_settings WHERE host_uid = ?", (host_uid,))

                hostname_display_name_override = current["display_name_override"]
                if has_display_name and not host_uid:
                    hostname_display_name_override = display_name_override

                if (
                    resolved_hostname
                    and (
                        hostname_display_name_override
                        or country_code_override
                        or is_favorite
                        or is_hidden
                        or customer_alert_emails
                        or customer_alert_mountpoints
                        or customer_alert_min_severity != "critical"
                        or customer_id is not None
                        or environment_type
                    )
                ):
                    conn.execute(
                        """
                        INSERT INTO host_settings (
                          hostname,
                          display_name_override,
                          country_code_override,
                          is_favorite,
                          is_hidden,
                          customer_alert_emails,
                          customer_alert_mountpoints,
                          customer_alert_min_severity,
                                                    customer_id,
                                                    environment_type,
                          updated_at_utc
                        )
                                                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(hostname) DO UPDATE SET
                          display_name_override = excluded.display_name_override,
                          country_code_override = excluded.country_code_override,
                          is_favorite = excluded.is_favorite,
                          is_hidden = excluded.is_hidden,
                          customer_alert_emails = excluded.customer_alert_emails,
                          customer_alert_mountpoints = excluded.customer_alert_mountpoints,
                          customer_alert_min_severity = excluded.customer_alert_min_severity,
                                                    customer_id = excluded.customer_id,
                                                    environment_type = excluded.environment_type,
                          updated_at_utc = excluded.updated_at_utc
                        """,
                        (
                            resolved_hostname,
                            hostname_display_name_override,
                            country_code_override,
                            1 if is_favorite else 0,
                            1 if is_hidden else 0,
                            customer_alert_emails,
                            customer_alert_mountpoints,
                            customer_alert_min_severity,
                            customer_id,
                            environment_type,
                            utc_now_iso(),
                        ),
                    )
                elif resolved_hostname:
                    conn.execute("DELETE FROM host_settings WHERE hostname = ?", (resolved_hostname,))

                if is_hidden:
                    resolve_open_alerts_for_host(conn, resolved_hostname, None)

                stored_host_settings = get_host_settings(conn, resolved_hostname)

                conn.commit()

            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "stored",
                    "hostname": resolved_hostname or hostname,
                    "host_uid": host_uid,
                    "display_name_override": display_name_override,
                    "country_code_override": country_code_override,
                    "is_favorite": is_favorite,
                    "is_hidden": is_hidden,
                    "customer_alert_emails": customer_alert_emails,
                    "customer_alert_mountpoints": customer_alert_mountpoints,
                    "customer_alert_min_severity": customer_alert_min_severity,
                    "customer_id": stored_host_settings.get("customer_id"),
                    "environment_type": stored_host_settings.get("environment_type", ""),
                    "customer_name": stored_host_settings.get("customer_name", ""),
                    "customer_maringo_project_number": stored_host_settings.get("customer_maringo_project_number", ""),
                },
            )
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
            host_uid = str(payload.get("host_uid", "") or "").strip()
            if not hostname and not host_uid:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "hostname or host_uid missing"})
                return

            with sqlite3.connect(DB_PATH) as conn:
                resolved_hostname = hostname
                if not resolved_hostname and host_uid:
                    host_key_expr = reports_host_key_sql()
                    row = conn.execute(
                        f"""
                        SELECT COALESCE(hostname, '')
                        FROM reports
                        WHERE {host_key_expr} = ?
                        ORDER BY id DESC
                        LIMIT 1
                        """,
                        (host_uid,),
                    ).fetchone()
                    resolved_hostname = str((row[0] if row else "") or "").strip()

                deleted = delete_host_card_data(conn, resolved_hostname, host_uid)
                conn.commit()

            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "deleted",
                    "hostname": resolved_hostname or hostname,
                    "host_uid": host_uid,
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
                conn.execute(
                    """
                    UPDATE alerts
                    SET ack_note = NULL, ack_by = NULL, ack_at_utc = NULL
                    WHERE hostname = ? AND mountpoint = ? AND status = 'open'
                    """,
                    (hostname, mountpoint),
                )
                conn.commit()

            self._send_json(HTTPStatus.OK, {"ok": True, "hostname": hostname, "mountpoint": mountpoint})
            return

        if path == "/api/v1/alert-close":
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

            closed_by = self._web_session_username() or "webclient"
            closed_at_utc = utc_now_iso()

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
                    "UPDATE alerts SET status = 'resolved', closed_at_utc = ?, closed_by = ? WHERE id = ?",
                    (closed_at_utc, closed_by, int(target[0])),
                )
                conn.commit()

            self._send_json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "hostname": hostname,
                    "mountpoint": mountpoint,
                    "closed_by": closed_by,
                    "closed_at_utc": closed_at_utc,
                },
            )
            return

        if path == "/api/v1/alert-unclose":
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
                    "UPDATE alerts SET status = 'open', closed_at_utc = NULL, closed_by = NULL WHERE id = ?",
                    (int(target[0]),),
                )
                conn.commit()

            self._send_json(HTTPStatus.OK, {"ok": True, "hostname": hostname, "mountpoint": mountpoint})
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

        if path == "/api/v1/restore/database":
            if not self._require_admin_session():
                return

            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "empty body"})
                return

            raw_body = self.rfile.read(content_length)
            ok, details = _restore_database_from_bytes(raw_body)
            if not ok:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": details})
                return

            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "restored",
                    "backup_of_previous_db": details,
                },
            )
            return

        if path == "/api/v1/admin/backup-automation/settings":
            if not self._require_admin_session():
                return

            content_length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(content_length) if content_length > 0 else b"{}"
            try:
                payload = json.loads(raw_body)
            except json.JSONDecodeError:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid json"})
                return

            if not isinstance(payload, dict):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "json object required"})
                return

            try:
                with sqlite3.connect(DB_PATH) as conn:
                    settings = save_backup_automation_settings(conn, payload)
                    conn.commit()
            except Exception as exc:
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})
                return

            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "message": "Backup-Automation Einstellungen gespeichert",
                    "settings": settings,
                },
            )
            return

        if path == "/api/v1/admin/backup-automation/trigger-local":
            if not self._require_admin_session():
                return

            try:
                result = trigger_automated_backup_now(trigger_source="manual", force_local=True)
            except RuntimeError as exc:
                self._send_json(HTTPStatus.CONFLICT, {"error": str(exc)})
                return
            except Exception as exc:
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})
                return

            with sqlite3.connect(DB_PATH) as conn:
                runs = list_backup_automation_runs(conn, limit=20)

            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "message": "Lokales Backup erstellt",
                    "result": result,
                    "recent_runs": runs,
                },
            )
            return

        if path == "/api/v1/admin/backup-automation/test-sftp":
            if not self._require_admin_session():
                return

            content_length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(content_length) if content_length > 0 else b"{}"
            try:
                payload = json.loads(raw_body)
            except json.JSONDecodeError:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid json"})
                return

            if not isinstance(payload, dict):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "json object required"})
                return

            try:
                result = run_sftp_upload_test(payload)
            except ValueError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return
            except RuntimeError as exc:
                self._send_json(HTTPStatus.BAD_GATEWAY, {"error": str(exc)})
                return
            except subprocess.TimeoutExpired:
                self._send_json(HTTPStatus.GATEWAY_TIMEOUT, {"error": "sFTP Test Timeout"})
                return
            except Exception as exc:
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})
                return

            self._send_json(HTTPStatus.OK, result)
            return

        if path == "/api/v1/admin/fix-alert-status":
            if not self._require_admin_session():
                return

            try:
                with sqlite3.connect(DB_PATH) as conn:
                    # Fix alerts that are closed but still have status='open'
                    conn.execute(
                        "UPDATE alerts SET status = 'resolved' WHERE closed_at_utc IS NOT NULL AND closed_at_utc != '' AND status = 'open'"
                    )
                    conn.commit()
                    affected = conn.total_changes
                result = {
                    "status": "ok",
                    "message": f"Fixed {affected} alerts with closed_at_utc but status='open'",
                    "affected_count": affected,
                }
            except Exception as exc:
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})
                return

            self._send_json(HTTPStatus.OK, result)
            return

        if path == "/api/v1/admin/database-vacuum":
            if not self._require_admin_session():
                return

            try:
                result = run_database_vacuum()
            except Exception as exc:
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})
                return

            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "message": "VACUUM abgeschlossen",
                    "result": result,
                },
            )
            return

        if path == "/api/v1/admin/database-stats/trigger":
            if not self._require_admin_session():
                return

            try:
                with sqlite3.connect(DB_PATH) as conn:
                    snapshot = trigger_db_maintenance_snapshot_now(conn)
                    payload = build_db_maintenance_dashboard(conn)
            except Exception as exc:
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})
                return

            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "message": "DB Kennzahlen manuell neu berechnet",
                    "triggered": snapshot,
                    **payload,
                },
            )
            return

        if path == "/api/v1/admin/repair-host-uids":
            if not self._require_admin_session():
                return

            query = parse_qs(parsed.query)
            batch_size = parse_int(query, "batch_size", default=1000, min_value=100, max_value=5000)

            try:
                with sqlite3.connect(DB_PATH) as conn:
                    result = _repair_report_host_uids(conn, batch_size=batch_size)
                    conn.commit()
            except Exception as exc:
                self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})
                return

            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "message": "Host-UID-Reparatur abgeschlossen",
                    **result,
                },
            )
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

        report_received_at_utc = utc_now_iso()
        incoming_agent_id = str(payload.get("agent_id", "") or "")
        incoming_primary_ip = str(payload.get("primary_ip", "") or "")
        incoming_host_uid = _derive_host_uid(payload, hostname, incoming_agent_id, incoming_primary_ip)
        payload["host_uid"] = incoming_host_uid

        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.execute(
                """
                INSERT INTO reports (received_at_utc, agent_id, hostname, host_uid, primary_ip, payload_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    report_received_at_utc,
                    incoming_agent_id,
                    hostname,
                    incoming_host_uid,
                    incoming_primary_ip,
                    json.dumps(payload, separators=(",", ":")),
                ),
            )
            report_id = int(cursor.lastrowid)
            _track_host_config_changes(conn, hostname, payload, report_id, report_received_at_utc)
            _track_database_lifecycle(conn, hostname, payload, report_id, report_received_at_utc)
            prune_reports_for_host(conn, hostname, MAX_REPORTS_PER_HOST)
            alarm_settings = get_alarm_settings(conn)
            host_settings = get_host_settings(conn, hostname)
            if bool(host_settings.get("is_hidden", False)):
                resolve_open_alerts_for_host(conn, hostname, report_id)
            else:
                update_alerts_for_report(conn, hostname, report_id, filesystems, alarm_settings)
            maybe_send_alert_reminders(conn)
            maybe_send_inactive_host_notifications(conn)
            maybe_send_scheduled_user_mails(conn)
            conn.commit()

        # Auto-discover new license types from agent report
        auto_sync_discovered_license_types(payload)

        self._send_json(HTTPStatus.CREATED, {"status": "stored"})


    def do_PATCH(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        m = re.match(r"^/api/v1/customers/(\d+)$", path)
        if m:
            customer_id = int(m.group(1))
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
            if not isinstance(payload, dict):
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "invalid payload"})
                return
            try:
                with sqlite3.connect(DB_PATH) as conn:
                    customer = update_customer_by_id(
                        conn,
                        customer_id,
                        payload.get("customer_name", ""),
                        payload.get("maringo_project_number", ""),
                    )
                    conn.commit()
                self._send_json(HTTPStatus.OK, {"status": "updated", "customer": customer})
            except ValueError as exc:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Not found")


def main() -> None:
    parser = argparse.ArgumentParser(description="Simple monitoring receiver")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind")
    parser.add_argument("--port", default=8080, type=int, help="Port to bind")
    parser.add_argument(
        "--rebuild-changelog-days",
        default=0,
        type=int,
        help="Reset changelog tables and rebuild them from the last N report days once at startup",
    )
    args = parser.parse_args()

    init_db()
    startup_rebuild_days = parse_positive_int(os.getenv("MONITORING_REBUILD_CHANGELOG_DAYS", ""), default=18, max_value=365)
    if args.rebuild_changelog_days > 0:
        startup_rebuild_days = args.rebuild_changelog_days
    if startup_rebuild_days > 0:
        try:
            with sqlite3.connect(DB_PATH) as conn:
                rebuild_result = rebuild_changelog_history(conn, days=startup_rebuild_days)
                conn.commit()
            print(
                "[startup] changelog rebuild: "
                f"{rebuild_result.get('status')} (days={rebuild_result.get('days')}, "
                f"completed_at_utc={rebuild_result.get('completed_at_utc')})"
            )
        except Exception as exc:
            print(f"[startup] changelog rebuild failed: {exc}")
    try:
        with sqlite3.connect(DB_PATH) as conn:
            _ensure_db_maintenance_snapshot(conn, force_if_empty=True)
    except Exception as exc:
        print(f"[startup] db maintenance snapshot failed: {exc}")

    scheduler_thread = threading.Thread(
        target=_db_maintenance_scheduler_loop,
        name="db-maintenance-scheduler",
        daemon=True,
    )
    scheduler_thread.start()

    backup_scheduler_thread = threading.Thread(
        target=_auto_backup_scheduler_loop,
        name="auto-backup-scheduler",
        daemon=True,
    )
    backup_scheduler_thread.start()

    server = ThreadingHTTPServer((args.host, args.port), MonitoringHandler)
    print(f"Monitoring receiver running on http://{args.host}:{args.port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
