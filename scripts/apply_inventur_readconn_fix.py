#!/usr/bin/env python3
"""Apply inventur read/write connection split to receiver.py (idempotent on d03ebe1 base)."""
from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
TARGET = REPO / "server" / "receiver.py"

OLD_ITER = '''_CHANGELOG_REPORT_FETCH_BATCH_SIZE = 32


def _iter_changelog_report_batches(
    conn: sqlite3.Connection,
    reports_sql: str,
    reports_params: tuple,
):
    """Yield report rows in batches; commit between batches so progress writes are not blocked."""
    cursor = conn.execute(reports_sql, reports_params)
    try:
        while True:
            rows = cursor.fetchmany(_CHANGELOG_REPORT_FETCH_BATCH_SIZE)
            if not rows:
                break
            yield rows
            conn.commit()
    finally:
        cursor.close()'''

NEW_ITER = '''_CHANGELOG_REPORT_FETCH_BATCH_SIZE = 32
_CHANGELOG_INVENTORY_FETCH_BATCH_SIZE = 1


def _changelog_read_connect() -> sqlite3.Connection:
    read_conn = sqlite_connect()
    read_conn.execute(f"PRAGMA busy_timeout = {_maintenance_sqlite_busy_timeout_ms()}")
    return read_conn


def _iter_changelog_report_batches(
    read_conn: sqlite3.Connection,
    reports_sql: str,
    reports_params: tuple,
    *,
    batch_size: int | None = None,
):
    """Yield rows from a dedicated read connection (INSERTs use a separate write conn)."""
    cursor = read_conn.execute(reports_sql, reports_params)
    try:
        while True:
            rows = cursor.fetchmany(max(1, int(batch_size or _CHANGELOG_REPORT_FETCH_BATCH_SIZE)))
            if not rows:
                break
            yield rows
    finally:
        cursor.close()'''

LOOP_OLD = "    for batch in _iter_changelog_report_batches(conn, reports_sql, reports_params):"

LOOP_NEW = """    read_conn = _changelog_read_connect()
    try:
        for batch in _iter_changelog_report_batches(
            read_conn,
            reports_sql,
            reports_params,
            batch_size=_CHANGELOG_INVENTORY_FETCH_BATCH_SIZE if inventory_greenfield else _CHANGELOG_REPORT_FETCH_BATCH_SIZE,
        ):"""

BACKFILL_FUNCS = (
    "backfill_database_lifecycle",
    "backfill_sap_addon_changes",
    "backfill_host_config_changes",
)


def wrap_backfill_loop(lines: list[str], func_name: str) -> None:
    func_i = next(i for i, line in enumerate(lines) if line.startswith(f"def {func_name}("))
    loop_i = next(
        i
        for i in range(func_i, len(lines))
        if lines[i] == LOOP_OLD
    )
    end_i = next(
        i
        for i in range(loop_i + 1, len(lines))
        if lines[i].startswith("    for host_key, snapshot")
        or (
            lines[i].startswith("    return {")
            and i + 1 < len(lines)
            and "reports_scanned" in lines[i + 1]
        )
    )
    row_i = next(i for i in range(loop_i, end_i) if "for row in batch:" in lines[i])
    for i in range(row_i, end_i):
        if lines[i].strip():
            lines[i] = "    " + lines[i]
    lines[loop_i:end_i] = [
        *LOOP_NEW.split("\n"),
        *lines[loop_i + 1 : end_i],
        "    finally:",
        "        read_conn.close()",
    ]


def main() -> None:
    text = TARGET.read_text(encoding="utf-8")
    if OLD_ITER not in text:
        raise SystemExit("OLD_ITER block not found – wrong base revision?")
    text = text.replace(OLD_ITER, NEW_ITER, 1)

    text = text.replace(
        """            if not _should_flush_changelog_progress(
                progress,
                last_phase=self._last_phase,
                last_hosts=self._last_hosts,
                last_reports=self._last_reports,
            ) and not force and not time_flush_due:
                return""",
        """            if not force and not time_flush_due and not _should_flush_changelog_progress(
                progress,
                last_phase=self._last_phase,
                last_hosts=self._last_hosts,
                last_reports=self._last_reports,
            ):
                return""",
        1,
    )
    text = text.replace(
        '"updated_at_utc": utc_now_iso(),\n                }\n            }',
        '"updated_at_utc": utc_now_iso(),\n                    "build_version": read_build_version(),\n                }\n            }',
        1,
    )

    old_rebuild = '''    window_days = 0
    reports_total = _count_reports_for_changelog_days(conn, window_days)

    if callable(progress_callback):
        try:
            progress_callback({
                "phase": "reset",
                "phase_step": 1,
                "phase_steps_total": 4,
                "reports_total": reports_total,'''
    new_rebuild = '''    window_days = 0

    if callable(progress_callback):
        try:
            progress_callback({
                "phase": "reset",
                "phase_step": 1,
                "phase_steps_total": 4,
                "reports_total": 0,'''
    if old_rebuild not in text:
        raise SystemExit("rebuild block not found")
    text = text.replace(old_rebuild, new_rebuild, 1)
    insert = '''
    read_conn = _changelog_read_connect()
    try:
        reports_total = _count_reports_for_changelog_days(read_conn, window_days)
    finally:
        read_conn.close()

    if callable(progress_callback):
        try:
            progress_callback({
                "phase": "config_backfill",
                "phase_step": 2,
                "phase_steps_total": 4,
                "reports_total": reports_total,
                "reports_scanned": 0,
                "hosts_processed": 0,
                "hosts_total": 0,
                "inserted_changes": 0,
                "message": f"Inventur: starte {reports_total} Reports (Host-Config)…",
            })
        except Exception:
            pass
    conn.commit()
    print(f"[inventur] job={job_id} reports_total={reports_total} build={read_build_version()}")

'''
    marker = '    existing_state = conn.execute(\n        "SELECT completed_at_utc, days FROM changelog_rebuild_state WHERE id = 1"\n    ).fetchone()'
    text = text.replace(marker, insert + marker, 1)

    lines = text.splitlines()
    for func in BACKFILL_FUNCS:
        wrap_backfill_loop(lines, func)

    joined = "\n".join(lines) + "\n"
    joined = joined.replace(
        "if report_count == 1 or report_count % (25 if inventory_greenfield else 100) == 0:",
        "if report_count == 1 or report_count % (10 if inventory_greenfield else 100) == 0:",
        1,
    )
    TARGET.write_text(joined, encoding="utf-8")
    print(f"Patched {TARGET}")


if __name__ == "__main__":
    main()
