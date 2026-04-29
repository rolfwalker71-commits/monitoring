#!/usr/bin/env python3
import argparse
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "monitoring.db"
API_KEY = os.getenv("MONITORING_API_KEY", "")
WARNING_THRESHOLD_PERCENT = float(os.getenv("MONITORING_WARNING_THRESHOLD", "80"))
CRITICAL_THRESHOLD_PERCENT = float(os.getenv("MONITORING_CRITICAL_THRESHOLD", "90"))


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


def get_nested_number(payload: dict, section: str, key: str) -> float | None:
    value = payload.get(section, {})
    if not isinstance(value, dict):
        return None
    raw = value.get(key)
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


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


def evaluate_severity(used_percent: float) -> str:
    if used_percent >= CRITICAL_THRESHOLD_PERCENT:
        return "critical"
    if used_percent >= WARNING_THRESHOLD_PERCENT:
        return "warning"
    return "ok"


def update_alerts_for_report(conn: sqlite3.Connection, hostname: str, report_id: int, filesystems: list) -> None:
    now_utc = utc_now_iso()
    mountpoints_seen = set()

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

        severity = evaluate_severity(used_percent)
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
            if open_alert:
                conn.execute(
                    """
                    UPDATE alerts
                    SET status = 'resolved', resolved_at_utc = ?, last_seen_at_utc = ?, report_id = ?
                    WHERE id = ?
                    """,
                    (now_utc, now_utc, report_id, open_alert[0]),
                )
            continue

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
            continue

        conn.execute(
            """
            UPDATE alerts
            SET severity = ?, used_percent = ?, last_seen_at_utc = ?, report_id = ?
            WHERE id = ?
            """,
            (severity, used_percent, now_utc, report_id, open_alert[0]),
        )

    if mountpoints_seen:
        placeholders = ",".join("?" for _ in mountpoints_seen)
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


class MonitoringHandler(BaseHTTPRequestHandler):
    server_version = "MonitoringReceiver/0.1"

    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
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

    def do_GET(self) -> None:
        parsed = urlparse(self.path)

        if parsed.path == "/health":
            self._send_json(HTTPStatus.OK, {"status": "ok", "time_utc": utc_now_iso()})
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

            reports = []
            for row in rows:
                reports.append(
                    {
                        "id": row[0],
                        "received_at_utc": row[1],
                        "agent_id": row[2],
                        "hostname": row[3],
                        "primary_ip": row[4],
                        "payload": json.loads(row[5]),
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
                                            ) AS latest_payload_json
                    FROM reports r
                    GROUP BY r.hostname
                    ORDER BY last_seen_utc DESC
                    LIMIT ? OFFSET ?
                    """,
                    (limit, offset),
                ).fetchall()

            hosts = []
            for row in rows:
                latest_payload = parse_payload_json(row[5] or "{}")
                hosts.append(
                    {
                        "hostname": row[0],
                        "last_seen_utc": row[1],
                        "report_count": row[2],
                        "primary_ip": row[3] or "",
                        "agent_id": row[4] or "",
                        "agent_version": str(latest_payload.get("agent_version", "")),
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

            reports = []
            for row in rows:
                reports.append(
                    {
                        "id": row[0],
                        "received_at_utc": row[1],
                        "agent_id": row[2],
                        "hostname": row[3],
                        "primary_ip": row[4],
                        "payload": json.loads(row[5]),
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

            for row in rows:
                report_count += 1
                latest_report_time = row[1]
                payload = parse_payload_json(row[2])
                cpu_usage = get_nested_number(payload, "cpu", "usage_percent")
                if cpu_usage is not None:
                    cpu_usage_values.append(cpu_usage)

                load_avg_1 = get_nested_number(payload, "cpu", "load_avg_1")
                if load_avg_1 is not None:
                    load_avg_1_values.append(load_avg_1)

                memory_used = get_nested_number(payload, "memory", "used_percent")
                if memory_used is not None:
                    memory_used_values.append(memory_used)

                swap_used = get_nested_number(payload, "swap", "used_percent")
                if swap_used is not None:
                    swap_used_values.append(swap_used)

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

            alerts = []
            for row in rows:
                alerts.append(
                    {
                        "id": row[0],
                        "hostname": row[1],
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
                        "warning_percent": WARNING_THRESHOLD_PERCENT,
                        "critical_percent": CRITICAL_THRESHOLD_PERCENT,
                    },
                    "open": {
                        "total": total_open,
                        "warning": warning_open,
                        "critical": critical_open,
                    },
                },
            )
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

        self.send_error(HTTPStatus.NOT_FOUND, "Not found")

    def do_POST(self) -> None:
        if self.path != "/api/v1/agent-report":
            self.send_error(HTTPStatus.NOT_FOUND, "Not found")
            return

        if self._unauthorized_if_needed():
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
            update_alerts_for_report(conn, hostname, report_id, filesystems)
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
