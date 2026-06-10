"""External / internal service monitors (Uptime-Kuma-style), separate from agent hosts."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import socket
import sqlite3
import ssl
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib import error, parse, request
from urllib.parse import urlparse

EXTERNAL_MONITOR_WORKER_INTERVAL_SEC = 30
EXTERNAL_MONITOR_RESULT_HISTORY_LIMIT = 80
PROBE_TOKEN_PREFIX = "mprb_"

_monitor_worker_wakeup = threading.Event()
_monitor_worker_started = False
_monitor_worker_lock = threading.Lock()


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _format_monitor_error_message(exc: BaseException | str) -> str:
    text = str(exc).strip()
    if text.lower().startswith("ssl:"):
        return _format_monitor_error_message(text[4:].strip())
    lower = text.lower()
    if "certificate_verify_failed" in lower or "cert certificate verify failed" in lower:
        if "unable to get local issuer certificate" in lower:
            return (
                "SSL-Zertifikatskette unvollständig oder Zwischenzertifikat auf dem "
                "Infoboard-Server unbekannt (Browser kann die Seite trotzdem öffnen). "
                "Webserver sollte die volle HTTPS-Kette liefern."
            )
        if "self signed certificate" in lower or "self-signed" in lower:
            return (
                "SSL-Zertifikat ist selbstsigniert oder nicht von einer vertrauenswürdigen "
                "Stelle ausgestellt."
            )
        if "certificate has expired" in lower or "has expired" in lower:
            return "SSL-Zertifikat ist abgelaufen."
        return (
            "SSL-Zertifikat konnte vom Infoboard-Server nicht verifiziert werden. "
            f"Technisch: {text}"
        )
    if "keyword '" in lower and "not found" in lower:
        return text.replace("keyword '", "Keyword „").replace("' not found", "“ nicht im Antwort-Body gefunden.")
    if lower.startswith("expected http "):
        return text.replace("expected HTTP ", "Erwartet HTTP ").replace(", got ", ", erhalten ")
    return text


def _parse_cert_not_after(cert: dict) -> tuple[str, int | None]:
    raw = str(cert.get("notAfter") or "").strip()
    if not raw:
        return "", None
    try:
        expires = datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days_left = int((expires - datetime.now(timezone.utc)).total_seconds() // 86400)
        return expires.strftime("%Y-%m-%dT%H:%M:%SZ"), days_left
    except ValueError:
        return "", None


def hash_probe_token(token: str) -> str:
    return hashlib.sha256(str(token or "").strip().encode("utf-8")).hexdigest()


def extract_probe_token_from_headers(headers: Any) -> str:
    get_header = getattr(headers, "get", None)
    if not callable(get_header):
        return ""
    direct = str(get_header("X-Probe-Token", "") or "").strip()
    if direct:
        return direct
    auth = str(get_header("Authorization", "") or "").strip()
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return ""


def extract_probe_token(
    headers: Any,
    *,
    query: dict[str, list[str]] | None = None,
    body: dict[str, Any] | None = None,
) -> str:
    token = extract_probe_token_from_headers(headers)
    if token:
        return token
    if isinstance(body, dict):
        body_token = str(body.get("probe_token") or "").strip()
        if body_token:
            return body_token
    if isinstance(query, dict):
        raw_values = query.get("probe_token") or []
        if raw_values:
            query_token = str(raw_values[0] or "").strip()
            if query_token:
                return query_token
    return ""


def verify_probe_site_token(conn: sqlite3.Connection, site_id: int, token: str) -> bool:
    row = conn.execute(
        "SELECT token_hash FROM external_monitor_probe_sites WHERE id = ? AND enabled = 1",
        (int(site_id),),
    ).fetchone()
    if not row:
        return False
    return hmac.compare_digest(hash_probe_token(token), str(row[0] or ""))


def generate_probe_token() -> str:
    return PROBE_TOKEN_PREFIX + secrets.token_urlsafe(24)


def init_external_monitor_tables(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS external_monitor_probe_sites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            related_host_uid TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1,
            last_seen_utc TEXT NOT NULL DEFAULT '',
            created_at_utc TEXT NOT NULL,
            updated_at_utc TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS external_monitors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            monitor_type TEXT NOT NULL DEFAULT 'http',
            probe_source TEXT NOT NULL DEFAULT 'server',
            probe_site_id INTEGER,
            target_url TEXT NOT NULL,
            customer_id INTEGER,
            related_host_uid TEXT NOT NULL DEFAULT '',
            interval_sec INTEGER NOT NULL DEFAULT 300,
            expected_status INTEGER,
            keyword TEXT NOT NULL DEFAULT '',
            timeout_sec INTEGER NOT NULL DEFAULT 15,
            enabled INTEGER NOT NULL DEFAULT 1,
            last_checked_at_utc TEXT NOT NULL DEFAULT '',
            last_status TEXT NOT NULL DEFAULT 'unknown',
            last_response_ms INTEGER,
            last_http_status INTEGER,
            last_cert_expires_at_utc TEXT NOT NULL DEFAULT '',
            last_cert_days_left INTEGER,
            last_error_message TEXT NOT NULL DEFAULT '',
            next_check_at_utc TEXT NOT NULL DEFAULT '',
            created_at_utc TEXT NOT NULL,
            updated_at_utc TEXT NOT NULL,
            FOREIGN KEY(probe_site_id) REFERENCES external_monitor_probe_sites(id)
        )
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_external_monitors_enabled_next
        ON external_monitors(enabled, probe_source, next_check_at_utc)
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_external_monitors_probe_site
        ON external_monitors(probe_site_id, enabled)
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS external_monitor_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            monitor_id INTEGER NOT NULL,
            checked_at_utc TEXT NOT NULL,
            status TEXT NOT NULL,
            response_ms INTEGER,
            http_status INTEGER,
            cert_expires_at_utc TEXT NOT NULL DEFAULT '',
            cert_days_left INTEGER,
            error_message TEXT NOT NULL DEFAULT '',
            FOREIGN KEY(monitor_id) REFERENCES external_monitors(id)
        )
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_external_monitor_results_monitor_checked
        ON external_monitor_results(monitor_id, checked_at_utc DESC)
        """
    )
    _ensure_external_monitor_columns(conn)


def _ensure_external_monitor_columns(conn: sqlite3.Connection) -> None:
    columns = {
        str(row[1])
        for row in conn.execute("PRAGMA table_info(external_monitors)").fetchall()
    }
    if "tls_verify" not in columns:
        conn.execute(
            "ALTER TABLE external_monitors ADD COLUMN tls_verify INTEGER NOT NULL DEFAULT 1"
        )


def _monitor_tls_verify_enabled(monitor: dict[str, Any]) -> bool:
    value = monitor.get("tls_verify", True)
    if isinstance(value, bool):
        return value
    if value in (None, ""):
        return True
    if isinstance(value, (int, float)):
        return int(value) != 0
    return str(value).strip().lower() not in {"0", "false", "no", "off"}


def _ssl_context(tls_verify: bool) -> ssl.SSLContext:
    if tls_verify:
        return ssl.create_default_context()
    return ssl._create_unverified_context()


def _row_to_monitor_dict(row: sqlite3.Row, *, include_history: bool = False, conn: sqlite3.Connection | None = None) -> dict[str, Any]:
    data = {
        "id": int(row["id"]),
        "name": str(row["name"] or ""),
        "monitor_type": str(row["monitor_type"] or "http"),
        "probe_source": str(row["probe_source"] or "server"),
        "probe_site_id": int(row["probe_site_id"]) if row["probe_site_id"] is not None else None,
        "target_url": str(row["target_url"] or ""),
        "customer_id": int(row["customer_id"]) if row["customer_id"] is not None else None,
        "related_host_uid": str(row["related_host_uid"] or ""),
        "interval_sec": int(row["interval_sec"] or 300),
        "expected_status": int(row["expected_status"]) if row["expected_status"] is not None else None,
        "keyword": str(row["keyword"] or ""),
        "timeout_sec": int(row["timeout_sec"] or 15),
        "tls_verify": bool(int(row["tls_verify"])) if "tls_verify" in row.keys() else True,
        "enabled": bool(int(row["enabled"] or 0)),
        "last_checked_at_utc": str(row["last_checked_at_utc"] or ""),
        "last_status": str(row["last_status"] or "unknown"),
        "last_response_ms": int(row["last_response_ms"]) if row["last_response_ms"] is not None else None,
        "last_http_status": int(row["last_http_status"]) if row["last_http_status"] is not None else None,
        "last_cert_expires_at_utc": str(row["last_cert_expires_at_utc"] or ""),
        "last_cert_days_left": int(row["last_cert_days_left"]) if row["last_cert_days_left"] is not None else None,
        "last_error_message": str(row["last_error_message"] or ""),
        "next_check_at_utc": str(row["next_check_at_utc"] or ""),
        "created_at_utc": str(row["created_at_utc"] or ""),
        "updated_at_utc": str(row["updated_at_utc"] or ""),
    }
    if include_history and conn is not None:
        history_rows = conn.execute(
            """
            SELECT checked_at_utc, status, response_ms, http_status, cert_days_left, error_message
            FROM external_monitor_results
            WHERE monitor_id = ?
            ORDER BY checked_at_utc DESC, id DESC
            LIMIT ?
            """,
            (data["id"], EXTERNAL_MONITOR_RESULT_HISTORY_LIMIT),
        ).fetchall()
        data["history"] = [
            {
                "checked_at_utc": str(item["checked_at_utc"] or ""),
                "status": str(item["status"] or ""),
                "response_ms": int(item["response_ms"]) if item["response_ms"] is not None else None,
                "http_status": int(item["http_status"]) if item["http_status"] is not None else None,
                "cert_days_left": int(item["cert_days_left"]) if item["cert_days_left"] is not None else None,
                "error_message": str(item["error_message"] or ""),
            }
            for item in history_rows
        ]
    return data


def _monitor_select_sql() -> str:
    return """
        SELECT
            id, name, monitor_type, probe_source, probe_site_id, target_url,
            customer_id, related_host_uid, interval_sec, expected_status, keyword,
            timeout_sec, tls_verify, enabled, last_checked_at_utc, last_status, last_response_ms,
            last_http_status, last_cert_expires_at_utc, last_cert_days_left,
            last_error_message, next_check_at_utc, created_at_utc, updated_at_utc
        FROM external_monitors
    """


def list_external_monitors(conn: sqlite3.Connection, *, monitor_id: int | None = None) -> list[dict[str, Any]]:
    conn.row_factory = sqlite3.Row
    if monitor_id is not None:
        row = conn.execute(_monitor_select_sql() + " WHERE id = ?", (int(monitor_id),)).fetchone()
        if not row:
            return []
        return [_row_to_monitor_dict(row, include_history=True, conn=conn)]
    rows = conn.execute(_monitor_select_sql() + " ORDER BY enabled DESC, name COLLATE NOCASE ASC, id ASC").fetchall()
    return [_row_to_monitor_dict(row) for row in rows]


def external_monitor_summary(conn: sqlite3.Connection) -> dict[str, int]:
    rows = conn.execute(
        """
        SELECT last_status, COUNT(*) AS cnt
        FROM external_monitors
        WHERE enabled = 1
        GROUP BY last_status
        """
    ).fetchall()
    summary = {"total": 0, "up": 0, "down": 0, "degraded": 0, "unknown": 0, "cert_warn": 0}
    for row in rows:
        status = str(row[0] or "unknown").lower()
        count = int(row[1] or 0)
        summary["total"] += count
        if status in summary:
            summary[status] += count
        else:
            summary["unknown"] += count
    cert_warn_row = conn.execute(
        """
        SELECT COUNT(*)
        FROM external_monitors
        WHERE enabled = 1
          AND last_cert_days_left IS NOT NULL
          AND last_cert_days_left <= 14
        """
    ).fetchone()
    summary["cert_warn"] = int(cert_warn_row[0] or 0) if cert_warn_row else 0
    return summary


def list_probe_sites(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """
        SELECT id, name, related_host_uid, enabled, last_seen_utc, created_at_utc, updated_at_utc
        FROM external_monitor_probe_sites
        ORDER BY name COLLATE NOCASE ASC, id ASC
        """
    ).fetchall()
    return [
        {
            "id": int(row["id"]),
            "name": str(row["name"] or ""),
            "related_host_uid": str(row["related_host_uid"] or ""),
            "enabled": bool(int(row["enabled"] or 0)),
            "last_seen_utc": str(row["last_seen_utc"] or ""),
            "created_at_utc": str(row["created_at_utc"] or ""),
            "updated_at_utc": str(row["updated_at_utc"] or ""),
        }
        for row in rows
    ]


def rotate_probe_site_token(conn: sqlite3.Connection, site_id: int) -> dict[str, Any] | None:
    row = conn.execute(
        "SELECT id, name FROM external_monitor_probe_sites WHERE id = ?",
        (int(site_id),),
    ).fetchone()
    if not row:
        return None
    token = generate_probe_token()
    now = utc_now_iso()
    conn.execute(
        """
        UPDATE external_monitor_probe_sites
        SET token_hash = ?, updated_at_utc = ?
        WHERE id = ?
        """,
        (hash_probe_token(token), now, int(site_id)),
    )
    return {
        "id": int(row[0]),
        "name": str(row[1] or ""),
        "token": token,
    }


def create_probe_site(conn: sqlite3.Connection, *, name: str, related_host_uid: str = "") -> dict[str, Any]:
    token = generate_probe_token()
    now = utc_now_iso()
    cursor = conn.execute(
        """
        INSERT INTO external_monitor_probe_sites (
            name, token_hash, related_host_uid, enabled, last_seen_utc, created_at_utc, updated_at_utc
        ) VALUES (?, ?, ?, 1, '', ?, ?)
        """,
        (name.strip(), hash_probe_token(token), related_host_uid.strip(), now, now),
    )
    site_id = int(cursor.lastrowid)
    return {"id": site_id, "name": name.strip(), "token": token, "related_host_uid": related_host_uid.strip()}


def create_external_monitor(conn: sqlite3.Connection, payload: dict[str, Any]) -> dict[str, Any]:
    now = utc_now_iso()
    probe_source = str(payload.get("probe_source") or "server").strip().lower()
    if probe_source not in {"server", "push"}:
        probe_source = "server"
    monitor_type = str(payload.get("monitor_type") or "http").strip().lower()
    if monitor_type not in {"http", "tcp", "ssl_cert"}:
        monitor_type = "http"
    probe_site_id = payload.get("probe_site_id")
    probe_site_id_value = int(probe_site_id) if probe_site_id not in (None, "") else None
    if probe_source == "push" and not probe_site_id_value:
        raise ValueError("probe_site_id required for push monitors")
    expected_status = payload.get("expected_status")
    expected_status_value = int(expected_status) if expected_status not in (None, "") else None
    customer_id = payload.get("customer_id")
    customer_id_value = int(customer_id) if customer_id not in (None, "") else None
    cursor = conn.execute(
        """
        INSERT INTO external_monitors (
            name, monitor_type, probe_source, probe_site_id, target_url, customer_id,
            related_host_uid, interval_sec, expected_status, keyword, timeout_sec,
            tls_verify, enabled, last_status, next_check_at_utc, created_at_utc, updated_at_utc
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'unknown', ?, ?, ?)
        """,
        (
            str(payload.get("name") or "").strip(),
            monitor_type,
            probe_source,
            probe_site_id_value,
            str(payload.get("target_url") or "").strip(),
            customer_id_value,
            str(payload.get("related_host_uid") or "").strip(),
            max(30, int(payload.get("interval_sec") or 300)),
            expected_status_value,
            str(payload.get("keyword") or "").strip(),
            max(3, min(120, int(payload.get("timeout_sec") or 15))),
            1 if _monitor_tls_verify_enabled({"tls_verify": payload.get("tls_verify", True)}) else 0,
            1 if payload.get("enabled", True) else 0,
            now,
            now,
            now,
        ),
    )
    monitor_id = int(cursor.lastrowid)
    monitors = list_external_monitors(conn, monitor_id=monitor_id)
    return monitors[0] if monitors else {"id": monitor_id}


def update_external_monitor(conn: sqlite3.Connection, monitor_id: int, payload: dict[str, Any]) -> dict[str, Any] | None:
    existing = conn.execute("SELECT id FROM external_monitors WHERE id = ?", (monitor_id,)).fetchone()
    if not existing:
        return None
    fields: list[str] = []
    values: list[Any] = []
    mapping = {
        "name": ("name", lambda v: str(v or "").strip()),
        "monitor_type": ("monitor_type", lambda v: str(v or "http").strip().lower()),
        "probe_source": ("probe_source", lambda v: str(v or "server").strip().lower()),
        "probe_site_id": ("probe_site_id", lambda v: int(v) if v not in (None, "") else None),
        "target_url": ("target_url", lambda v: str(v or "").strip()),
        "customer_id": ("customer_id", lambda v: int(v) if v not in (None, "") else None),
        "related_host_uid": ("related_host_uid", lambda v: str(v or "").strip()),
        "interval_sec": ("interval_sec", lambda v: max(30, int(v or 300))),
        "expected_status": ("expected_status", lambda v: int(v) if v not in (None, "") else None),
        "keyword": ("keyword", lambda v: str(v or "").strip()),
        "timeout_sec": ("timeout_sec", lambda v: max(3, min(120, int(v or 15)))),
        "tls_verify": (
            "tls_verify",
            lambda v: 1 if _monitor_tls_verify_enabled({"tls_verify": v}) else 0,
        ),
        "enabled": ("enabled", lambda v: 1 if v else 0),
    }
    interval_changed = False
    for key, (column, transform) in mapping.items():
        if key in payload:
            fields.append(f"{column} = ?")
            values.append(transform(payload[key]))
            if key == "interval_sec":
                interval_changed = True
    if not fields:
        monitors = list_external_monitors(conn, monitor_id=monitor_id)
        return monitors[0] if monitors else None
    if interval_changed:
        fields.append("next_check_at_utc = ?")
        values.append(utc_now_iso())
    fields.append("updated_at_utc = ?")
    values.append(utc_now_iso())
    values.append(monitor_id)
    conn.execute(f"UPDATE external_monitors SET {', '.join(fields)} WHERE id = ?", values)
    monitors = list_external_monitors(conn, monitor_id=monitor_id)
    return monitors[0] if monitors else None


def _run_ssl_cert_probe(
    host: str,
    port: int,
    timeout_sec: int,
    *,
    tls_verify: bool = True,
) -> tuple[str, int | None, str]:
    context = _ssl_context(tls_verify)
    with socket.create_connection((host, port), timeout=timeout_sec) as raw_sock:
        with context.wrap_socket(raw_sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert() or {}
    expires_at, days_left = _parse_cert_not_after(cert)
    return expires_at, days_left, ""


def run_monitor_check(monitor: dict[str, Any]) -> dict[str, Any]:
    monitor_type = str(monitor.get("monitor_type") or "http").lower()
    target_url = str(monitor.get("target_url") or "").strip()
    timeout_sec = max(3, min(120, int(monitor.get("timeout_sec") or 15)))
    expected_status = monitor.get("expected_status")
    keyword = str(monitor.get("keyword") or "")
    tls_verify = _monitor_tls_verify_enabled(monitor)
    started = time.monotonic()
    cert_expires_at = ""
    cert_days_left = None
    http_status = None
    error_message = ""

    try:
        if monitor_type == "tcp":
            if "://" in target_url:
                parsed = urlparse(target_url)
                host = parsed.hostname or ""
                port = parsed.port or 443
            elif ":" in target_url:
                host, port_text = target_url.rsplit(":", 1)
                host = host.strip("[]")
                port = int(port_text)
            else:
                raise ValueError("TCP target must be host:port or URL")
            if not host or port <= 0:
                raise ValueError("invalid TCP target")
            with socket.create_connection((host, int(port)), timeout=timeout_sec):
                pass
            response_ms = int((time.monotonic() - started) * 1000)
            return {
                "status": "up",
                "response_ms": response_ms,
                "http_status": None,
                "cert_expires_at_utc": "",
                "cert_days_left": None,
                "error_message": "",
            }

        if monitor_type == "ssl_cert":
            parsed = urlparse(target_url if "://" in target_url else f"https://{target_url}")
            host = parsed.hostname or target_url
            port = parsed.port or 443
            cert_expires_at, cert_days_left, error_message = _run_ssl_cert_probe(
                host,
                port,
                timeout_sec,
                tls_verify=tls_verify,
            )
            response_ms = int((time.monotonic() - started) * 1000)
            if cert_days_left is None:
                status = "degraded"
                error_message = error_message or "certificate expiry unknown"
            elif cert_days_left < 0:
                status = "down"
                error_message = "certificate expired"
            elif cert_days_left <= 14:
                status = "degraded"
                error_message = f"certificate expires in {cert_days_left} days"
            else:
                status = "up"
            return {
                "status": status,
                "response_ms": response_ms,
                "http_status": None,
                "cert_expires_at_utc": cert_expires_at,
                "cert_days_left": cert_days_left,
                "error_message": error_message,
            }

        url = target_url if "://" in target_url else f"https://{target_url}"
        parsed = urlparse(url)
        if parsed.scheme in {"https", "ssl"} and parsed.hostname:
            try:
                cert_expires_at, cert_days_left, _ = _run_ssl_cert_probe(
                    parsed.hostname,
                    parsed.port or 443,
                    timeout_sec,
                    tls_verify=tls_verify,
                )
            except Exception as cert_exc:
                cert_expires_at = ""
                cert_days_left = None
                error_message = _format_monitor_error_message(cert_exc)

        req = request.Request(url, method="GET", headers={"User-Agent": "monitoring-external-monitor/1.0"})
        with request.urlopen(req, timeout=timeout_sec, context=_ssl_context(tls_verify)) as resp:
            http_status = int(getattr(resp, "status", 0) or 0)
            body = resp.read(131072)
        response_ms = int((time.monotonic() - started) * 1000)
        status = "up"
        if expected_status is not None and http_status != int(expected_status):
            status = "down"
            error_message = _format_monitor_error_message(
                f"expected HTTP {expected_status}, got {http_status}"
            )
        if keyword and keyword.encode("utf-8") not in body:
            status = "down"
            error_message = error_message or _format_monitor_error_message(
                f"keyword '{keyword}' not found"
            )
        if cert_days_left is not None and cert_days_left <= 14 and status == "up":
            status = "degraded"
            error_message = error_message or f"certificate expires in {cert_days_left} days"
        return {
            "status": status,
            "response_ms": response_ms,
            "http_status": http_status,
            "cert_expires_at_utc": cert_expires_at,
            "cert_days_left": cert_days_left,
            "error_message": error_message,
        }
    except error.HTTPError as http_exc:
        response_ms = int((time.monotonic() - started) * 1000)
        http_status = int(http_exc.code or 0)
        if expected_status is not None and http_status == int(expected_status):
            return {
                "status": "up",
                "response_ms": response_ms,
                "http_status": http_status,
                "cert_expires_at_utc": cert_expires_at,
                "cert_days_left": cert_days_left,
                "error_message": "",
            }
        return {
            "status": "down",
            "response_ms": response_ms,
            "http_status": http_status,
            "cert_expires_at_utc": cert_expires_at,
            "cert_days_left": cert_days_left,
            "error_message": _format_monitor_error_message(http_exc),
        }
    except Exception as exc:
        response_ms = int((time.monotonic() - started) * 1000)
        return {
            "status": "down",
            "response_ms": response_ms,
            "http_status": http_status,
            "cert_expires_at_utc": cert_expires_at,
            "cert_days_left": cert_days_left,
            "error_message": _format_monitor_error_message(exc),
        }


def record_monitor_result(conn: sqlite3.Connection, monitor_id: int, result: dict[str, Any]) -> None:
    now = utc_now_iso()
    interval_row = conn.execute(
        "SELECT interval_sec FROM external_monitors WHERE id = ?",
        (monitor_id,),
    ).fetchone()
    interval_sec = int(interval_row[0] or 300) if interval_row else 300
    next_check = datetime.now(timezone.utc) + timedelta(seconds=interval_sec)
    conn.execute(
        """
        INSERT INTO external_monitor_results (
            monitor_id, checked_at_utc, status, response_ms, http_status,
            cert_expires_at_utc, cert_days_left, error_message
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            monitor_id,
            now,
            str(result.get("status") or "unknown"),
            result.get("response_ms"),
            result.get("http_status"),
            str(result.get("cert_expires_at_utc") or ""),
            result.get("cert_days_left"),
            str(result.get("error_message") or "")[:500],
        ),
    )
    conn.execute(
        """
        UPDATE external_monitors
        SET last_checked_at_utc = ?,
            last_status = ?,
            last_response_ms = ?,
            last_http_status = ?,
            last_cert_expires_at_utc = ?,
            last_cert_days_left = ?,
            last_error_message = ?,
            next_check_at_utc = ?,
            updated_at_utc = ?
        WHERE id = ?
        """,
        (
            now,
            str(result.get("status") or "unknown"),
            result.get("response_ms"),
            result.get("http_status"),
            str(result.get("cert_expires_at_utc") or ""),
            result.get("cert_days_left"),
            str(result.get("error_message") or "")[:500],
            next_check.strftime("%Y-%m-%dT%H:%M:%SZ"),
            now,
            monitor_id,
        ),
    )
    conn.execute(
        """
        DELETE FROM external_monitor_results
        WHERE monitor_id = ?
          AND id NOT IN (
            SELECT id FROM external_monitor_results
            WHERE monitor_id = ?
            ORDER BY checked_at_utc DESC, id DESC
            LIMIT ?
          )
        """,
        (monitor_id, monitor_id, EXTERNAL_MONITOR_RESULT_HISTORY_LIMIT),
    )


def _resolve_probe_site(conn: sqlite3.Connection, token: str) -> sqlite3.Row | None:
    conn.row_factory = sqlite3.Row
    token_hash = hash_probe_token(token)
    return conn.execute(
        """
        SELECT id, name, related_host_uid, enabled
        FROM external_monitor_probe_sites
        WHERE token_hash = ? AND enabled = 1
        """,
        (token_hash,),
    ).fetchone()


def get_probe_config(conn: sqlite3.Connection, token: str) -> dict[str, Any] | None:
    site = _resolve_probe_site(conn, token)
    if not site:
        return None
    conn.execute(
        "UPDATE external_monitor_probe_sites SET last_seen_utc = ?, updated_at_utc = ? WHERE id = ?",
        (utc_now_iso(), utc_now_iso(), int(site["id"])),
    )
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """
        SELECT
            id, name, monitor_type, target_url, interval_sec, expected_status,
            keyword, timeout_sec, tls_verify, related_host_uid
        FROM external_monitors
        WHERE enabled = 1 AND probe_source = 'push' AND probe_site_id = ?
        ORDER BY id ASC
        """,
        (int(site["id"]),),
    ).fetchall()
    monitors = [
        {
            "id": int(row["id"]),
            "name": str(row["name"] or ""),
            "monitor_type": str(row["monitor_type"] or "http"),
            "target_url": str(row["target_url"] or ""),
            "interval_sec": int(row["interval_sec"] or 300),
            "expected_status": int(row["expected_status"]) if row["expected_status"] is not None else None,
            "keyword": str(row["keyword"] or ""),
            "timeout_sec": int(row["timeout_sec"] or 15),
            "tls_verify": bool(int(row["tls_verify"])) if row["tls_verify"] is not None else True,
            "related_host_uid": str(row["related_host_uid"] or ""),
        }
        for row in rows
    ]
    return {
        "probe_site": {
            "id": int(site["id"]),
            "name": str(site["name"] or ""),
            "related_host_uid": str(site["related_host_uid"] or ""),
        },
        "monitors": monitors,
    }


def push_probe_results(conn: sqlite3.Connection, token: str, results: list[dict[str, Any]]) -> dict[str, Any]:
    site = _resolve_probe_site(conn, token)
    if not site:
        return {"accepted": 0, "error": "invalid_probe_token"}
    site_id = int(site["id"])
    accepted = 0
    for item in results:
        monitor_id = int(item.get("monitor_id") or 0)
        if monitor_id <= 0:
            continue
        row = conn.execute(
            """
            SELECT id FROM external_monitors
            WHERE id = ? AND enabled = 1 AND probe_source = 'push' AND probe_site_id = ?
            """,
            (monitor_id, site_id),
        ).fetchone()
        if not row:
            continue
        record_monitor_result(
            conn,
            monitor_id,
            {
                "status": str(item.get("status") or "unknown"),
                "response_ms": item.get("response_ms"),
                "http_status": item.get("http_status"),
                "cert_expires_at_utc": str(item.get("cert_expires_at_utc") or ""),
                "cert_days_left": item.get("cert_days_left"),
                "error_message": str(item.get("error_message") or ""),
            },
        )
        accepted += 1
    conn.execute(
        "UPDATE external_monitor_probe_sites SET last_seen_utc = ?, updated_at_utc = ? WHERE id = ?",
        (utc_now_iso(), utc_now_iso(), site_id),
    )
    return {"accepted": accepted, "probe_site_id": site_id}


def _fetch_due_server_monitors(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    conn.row_factory = sqlite3.Row
    now = utc_now_iso()
    rows = conn.execute(
        _monitor_select_sql()
        + """
        WHERE enabled = 1
          AND probe_source = 'server'
          AND (next_check_at_utc = '' OR next_check_at_utc <= ?)
        ORDER BY next_check_at_utc ASC, id ASC
        LIMIT 20
        """,
        (now,),
    ).fetchall()
    return [_row_to_monitor_dict(row) for row in rows]


def external_monitor_worker_loop(db_path: str) -> None:
    while True:
        _monitor_worker_wakeup.wait(timeout=EXTERNAL_MONITOR_WORKER_INTERVAL_SEC)
        _monitor_worker_wakeup.clear()
        try:
            with sqlite3.connect(db_path, timeout=30) as conn:
                due_monitors = _fetch_due_server_monitors(conn)
                for monitor in due_monitors:
                    result = run_monitor_check(monitor)
                    record_monitor_result(conn, int(monitor["id"]), result)
                conn.commit()
        except Exception as exc:
            print(f"[external-monitors] worker error: {exc}")


def start_external_monitor_worker(db_path: str) -> None:
    global _monitor_worker_started
    with _monitor_worker_lock:
        if _monitor_worker_started:
            return
        thread = threading.Thread(
            target=external_monitor_worker_loop,
            args=(db_path,),
            name="external-monitor-worker",
            daemon=True,
        )
        thread.start()
        _monitor_worker_started = True


def wake_external_monitor_worker() -> None:
    _monitor_worker_wakeup.set()


def test_external_monitor_now(conn: sqlite3.Connection, monitor_id: int) -> dict[str, Any] | None:
    monitors = list_external_monitors(conn, monitor_id=monitor_id)
    if not monitors:
        return None
    monitor = monitors[0]
    result = run_monitor_check(monitor)
    record_monitor_result(conn, int(monitor_id), result)
    refreshed = list_external_monitors(conn, monitor_id=monitor_id)
    return {
        "monitor": refreshed[0] if refreshed else monitor,
        "result": result,
    }


def verify_probe_token(provided: str, expected_hash: str) -> bool:
    return hmac.compare_digest(hash_probe_token(provided), str(expected_hash or ""))
