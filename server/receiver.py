#!/usr/bin/env python3
import argparse
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from urllib import error, parse, request

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "monitoring.db"
API_KEY = os.getenv("MONITORING_API_KEY", "")
WARNING_THRESHOLD_PERCENT = float(os.getenv("MONITORING_WARNING_THRESHOLD", "80"))
CRITICAL_THRESHOLD_PERCENT = float(os.getenv("MONITORING_CRITICAL_THRESHOLD", "90"))
TELEGRAM_ENABLED_DEFAULT = os.getenv("MONITORING_TELEGRAM_ENABLED", "0").strip().lower() in {"1", "true", "yes", "on"}
TELEGRAM_BOT_TOKEN_DEFAULT = os.getenv("MONITORING_TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID_DEFAULT = os.getenv("MONITORING_TELEGRAM_CHAT_ID", "")
WEB_DEFAULT_USERNAME = os.getenv("MONITORING_WEB_USER", "admin")
WEB_DEFAULT_PASSWORD = os.getenv("MONITORING_WEB_PASSWORD", "ChangeMe!2026")
WEB_SESSION_TTL_HOURS = 12
WEB_SESSION_COOKIE = "monitoring_session"


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
                updated_at_utc TEXT NOT NULL
            )
            """
        )
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
                updated_at_utc TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS web_sessions (
                session_token TEXT PRIMARY KEY,
                username TEXT NOT NULL,
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
                telegram_enabled,
                telegram_bot_token,
                telegram_chat_id,
                updated_at_utc
            )
            VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            ),
        )

        user_count = conn.execute("SELECT COUNT(*) FROM web_users").fetchone()[0]
        if int(user_count or 0) == 0:
            salt = secrets.token_hex(16)
            conn.execute(
                """
                INSERT INTO web_users (username, password_hash, password_salt, updated_at_utc)
                VALUES (?, ?, ?, ?)
                """,
                (
                    WEB_DEFAULT_USERNAME,
                    hash_password(WEB_DEFAULT_PASSWORD, salt),
                    salt,
                    utc_now_iso(),
                ),
            )

        conn.execute(
            "DELETE FROM web_sessions WHERE expires_at_utc <= ?",
            (utc_now_iso(),),
        )
        conn.commit()


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def utc_hours_ago_iso(hours: int) -> str:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    return cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")


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
    expires = now + timedelta(hours=WEB_SESSION_TTL_HOURS)
    session_token = secrets.token_urlsafe(32)
    conn.execute(
        """
        INSERT INTO web_sessions (session_token, username, created_at_utc, expires_at_utc)
        VALUES (?, ?, ?, ?)
        """,
        (
            session_token,
            username,
            now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
        ),
    )
    return session_token, expires.strftime("%Y-%m-%dT%H:%M:%SZ")


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
               telegram_enabled, telegram_bot_token, telegram_chat_id, updated_at_utc
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

    return {
        "warning_threshold_percent": warning,
        "critical_threshold_percent": critical,
        "warning_consecutive_hits": warning_hits,
        "warning_window_minutes": warning_window,
        "critical_trigger_immediate": coerce_bool(payload.get("critical_trigger_immediate", base.get("critical_trigger_immediate", True))),
        "telegram_enabled": coerce_bool(payload.get("telegram_enabled", base.get("telegram_enabled", False))),
        "telegram_bot_token": str(payload.get("telegram_bot_token", base.get("telegram_bot_token", "")) or "").strip(),
        "telegram_chat_id": str(payload.get("telegram_chat_id", base.get("telegram_chat_id", "")) or "").strip(),
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
            telegram_enabled,
            telegram_bot_token,
            telegram_chat_id,
            updated_at_utc
        )
        VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            warning_threshold_percent = excluded.warning_threshold_percent,
            critical_threshold_percent = excluded.critical_threshold_percent,
            warning_consecutive_hits = excluded.warning_consecutive_hits,
            warning_window_minutes = excluded.warning_window_minutes,
            critical_trigger_immediate = excluded.critical_trigger_immediate,
            telegram_enabled = excluded.telegram_enabled,
            telegram_bot_token = excluded.telegram_bot_token,
            telegram_chat_id = excluded.telegram_chat_id,
            updated_at_utc = excluded.updated_at_utc
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


def telegram_send(settings: dict, text: str) -> tuple[bool, str]:
    if not settings.get("telegram_enabled"):
        return False, "telegram disabled"

    bot_token = str(settings.get("telegram_bot_token", "")).strip()
    chat_id = str(settings.get("telegram_chat_id", "")).strip()
    if not bot_token or not chat_id:
        return False, "telegram bot token/chat id missing"

    endpoint = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = parse.urlencode(
        {
            "chat_id": chat_id,
            "text": text,
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


def maybe_send_alert_message(
    settings: dict,
    event_type: str,
    hostname: str,
    mountpoint: str,
    severity: str,
    used_percent: float,
) -> None:
    if not settings.get("telegram_enabled"):
        return

    icon = {
        "opened": "ALERT OPEN",
        "escalated": "ALERT ESCALATED",
        "resolved": "ALERT RESOLVED",
    }.get(event_type, "ALERT")
    text = (
        f"[{icon}] {hostname}\n"
        f"Mountpoint: {mountpoint}\n"
        f"Severity: {severity}\n"
        f"Used: {used_percent:.1f}%\n"
        f"Time: {utc_now_iso()}"
    )
    telegram_send(settings, text)


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

    for fs in filesystems:
        if not isinstance(fs, dict):
            continue

        mountpoint = str(fs.get("mountpoint", "")).strip()
        if not mountpoint:
            continue

        mountpoints_seen.add(mountpoint)
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
                maybe_send_alert_message(alarm_settings, "resolved", hostname, mountpoint, "ok", used_percent)
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
            maybe_send_alert_message(alarm_settings, "opened", hostname, mountpoint, severity, used_percent)
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
            maybe_send_alert_message(alarm_settings, "escalated", hostname, mountpoint, severity, used_percent)

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

    def _send_file(self, path: Path, content_type: str) -> None:
        if not path.exists() or not path.is_file():
            self.send_error(HTTPStatus.NOT_FOUND, "File not found")
            return

        content = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _unauthorized_if_needed(self) -> bool:
        if not API_KEY:
            return False

        request_key = self.headers.get("X-Api-Key", "")
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
            conn.execute(
                "DELETE FROM web_sessions WHERE expires_at_utc <= ?",
                (utc_now_iso(),),
            )
            row = conn.execute(
                "SELECT username FROM web_sessions WHERE session_token = ?",
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

    def do_GET(self) -> None:
        parsed = urlparse(self.path)

        if parsed.path == "/health":
            self._send_json(HTTPStatus.OK, {"status": "ok", "time_utc": utc_now_iso()})
            return

        if parsed.path == "/api/v1/session":
            username = self._web_session_username()
            self._send_json(
                HTTPStatus.OK,
                {
                    "authenticated": bool(username),
                    "username": username,
                },
            )
            return

        if parsed.path.startswith("/api/v1/"):
            if not self._require_web_session():
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
                    "SELECT hostname, display_name_override FROM host_settings"
                ).fetchall()

            reports = []
            overrides = {str(row[0]): str(row[1] or "") for row in settings_rows}

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
                        "display_name": effective_display_name(payload, overrides.get(str(hostname), ""), str(hostname)),
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
                                            ) AS open_alert_count,
                                            (
                                                SELECT COUNT(*)
                                                FROM alerts a2
                                                WHERE a2.hostname = r.hostname AND a2.status = 'open' AND a2.severity = 'critical'
                                            ) AS open_critical_alert_count
                    FROM reports r
                    GROUP BY r.hostname
                    ORDER BY last_seen_utc DESC
                    LIMIT ? OFFSET ?
                    """,
                    (limit, offset),
                ).fetchall()

                settings_rows = conn.execute(
                    "SELECT hostname, display_name_override FROM host_settings"
                ).fetchall()

            overrides = {str(row[0]): str(row[1] or "") for row in settings_rows}
            hosts = []
            for row in rows:
                latest_payload = parse_payload_json(row[5] or "{}")
                hostname = str(row[0])
                hosts.append(
                    {
                        "hostname": hostname,
                        "display_name": effective_display_name(latest_payload, overrides.get(hostname, ""), hostname),
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
                    }
                )

            self._send_json(
                HTTPStatus.OK,
                {
                    "count": len(hosts),
                    "limit": limit,
                    "offset": offset,
                    "total_hosts": total_hosts,
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

            with sqlite3.connect(DB_PATH) as conn:
                total_reports = conn.execute(
                    "SELECT COUNT(*) FROM reports WHERE hostname = ?",
                    (hostname,),
                ).fetchone()[0]

                rows = conn.execute(
                    """
                    SELECT id, received_at_utc, agent_id, hostname, primary_ip, payload_json
                    FROM reports
                    WHERE hostname = ?
                    ORDER BY id DESC
                    LIMIT ? OFFSET ?
                    """,
                    (hostname, limit, offset),
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
                    "offset": offset,
                    "total_reports": total_reports,
                    "hostname": hostname,
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
                override_value = get_display_name_override(conn, hostname)

            self._send_json(
                HTTPStatus.OK,
                {
                    "hostname": hostname,
                    "display_name_override": override_value,
                },
            )
            return

        if parsed.path == "/api/v1/analysis":
            query = parse_qs(parsed.query)
            hostname = query.get("hostname", [""])[0].strip()
            if not hostname:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "hostname query parameter is required"})
                return

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
                    },
                    "filesystem_trends": trends,
                },
            )
            return

        if parsed.path == "/api/v1/alerts":
            query = parse_qs(parsed.query)
            status_filter = query.get("status", ["all"])[0].strip().lower()
            if status_filter not in {"all", "open", "resolved"}:
                status_filter = "all"

            hostname_filter = query.get("hostname", [""])[0].strip()
            limit = parse_int(query, "limit", default=50, min_value=1, max_value=500)
            offset = parse_int(query, "offset", default=0, min_value=0, max_value=500000)

            where_parts = []
            args = []
            if status_filter != "all":
                where_parts.append("status = ?")
                args.append(status_filter)
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
                           created_at_utc, last_seen_at_utc, resolved_at_utc, report_id
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
            for row in rows:
                hostname = str(row[1] or "")
                alerts.append(
                    {
                        "id": row[0],
                        "hostname": hostname,
                        "display_name": display_names.get(hostname, hostname),
                        "mountpoint": row[2],
                        "severity": row[3],
                        "used_percent": row[4],
                        "status": row[5],
                        "created_at_utc": row[6],
                        "last_seen_at_utc": row[7],
                        "resolved_at_utc": row[8],
                        "report_id": row[9],
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

        if parsed.path == "/api/v1/alarm-settings":
            with sqlite3.connect(DB_PATH) as conn:
                settings = get_alarm_settings(conn)

            self._send_json(HTTPStatus.OK, settings)
            return

        if parsed.path == "/":
            self._send_file(STATIC_DIR / "index.html", "text/html; charset=utf-8")
            return

        if parsed.path == "/app.js":
            self._send_file(STATIC_DIR / "app.js", "application/javascript; charset=utf-8")
            return

        if parsed.path == "/styles.css":
            self._send_file(STATIC_DIR / "styles.css", "text/css; charset=utf-8")
            return

            if parsed.path in ("/icons/linux.png", "/icons/windows.png"):
                icon_name = parsed.path.split("/")[-1]
                self._send_file(STATIC_DIR / "icons" / icon_name, "image/png")
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
                row = conn.execute(
                    "SELECT password_hash, password_salt FROM web_users WHERE username = ?",
                    (username,),
                ).fetchone()
                if not row or not verify_password(password, str(row[0]), str(row[1])):
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

        if path == "/api/v1/agent-report":
            if self._unauthorized_if_needed():
                return
        elif path.startswith("/api/v1/"):
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
            if len(new_password) < 8:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "new password too short (min 8)"})
                return

            with sqlite3.connect(DB_PATH) as conn:
                row = conn.execute(
                    "SELECT password_hash, password_salt FROM web_users WHERE username = ?",
                    (username,),
                ).fetchone()
                if not row or not verify_password(current_password, str(row[0]), str(row[1])):
                    self._send_json(HTTPStatus.UNAUTHORIZED, {"error": "current password invalid"})
                    return

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
            display_name_override = str(payload.get("display_name_override", "")).strip()

            if not hostname:
                self._send_json(HTTPStatus.BAD_REQUEST, {"error": "hostname missing"})
                return

            with sqlite3.connect(DB_PATH) as conn:
                if display_name_override:
                    conn.execute(
                        """
                        INSERT INTO host_settings (hostname, display_name_override, updated_at_utc)
                        VALUES (?, ?, ?)
                        ON CONFLICT(hostname) DO UPDATE SET
                          display_name_override = excluded.display_name_override,
                          updated_at_utc = excluded.updated_at_utc
                        """,
                        (hostname, display_name_override, utc_now_iso()),
                    )
                else:
                    conn.execute("DELETE FROM host_settings WHERE hostname = ?", (hostname,))
                conn.commit()

            self._send_json(
                HTTPStatus.OK,
                {
                    "status": "stored",
                    "hostname": hostname,
                    "display_name_override": display_name_override,
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
            alarm_settings = get_alarm_settings(conn)
            update_alerts_for_report(conn, hostname, report_id, filesystems, alarm_settings)
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
