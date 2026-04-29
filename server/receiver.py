#!/usr/bin/env python3
import argparse
import json
import os
import sqlite3
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "monitoring.db"
API_KEY = os.getenv("MONITORING_API_KEY", "")


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
        conn.commit()


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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
                      ) AS latest_agent_id
                    FROM reports r
                    GROUP BY r.hostname
                    ORDER BY last_seen_utc DESC
                    LIMIT ? OFFSET ?
                    """,
                    (limit, offset),
                ).fetchall()

            hosts = []
            for row in rows:
                hosts.append(
                    {
                        "hostname": row[0],
                        "last_seen_utc": row[1],
                        "report_count": row[2],
                        "primary_ip": row[3] or "",
                        "agent_id": row[4] or "",
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
            conn.execute(
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
