"""Optional TOTP MFA for web users (desktop login). Mobile login bypasses MFA."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import struct
import time
from datetime import datetime, timedelta, timezone
from io import BytesIO
from urllib.parse import quote

MFA_ISSUER = str(os.getenv("MONITORING_MFA_ISSUER", "System Infoboard") or "System Infoboard").strip()
MFA_CHALLENGE_TTL_SECONDS = max(60, int(os.getenv("MONITORING_MFA_CHALLENGE_TTL_SECONDS", "300")))
MFA_MAX_ATTEMPTS = max(3, int(os.getenv("MONITORING_MFA_MAX_ATTEMPTS", "5")))
TOTP_PERIOD = 30
TOTP_DIGITS = 6
TOTP_WINDOW = 1


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _master_key() -> bytes:
    material = (
        str(os.getenv("MONITORING_MFA_ENCRYPTION_KEY", "") or "").strip()
        or str(os.getenv("MONITORING_API_KEY", "") or "").strip()
        or "monitoring-mfa-dev-key"
    )
    return hashlib.sha256(material.encode("utf-8")).digest()


def _keystream(key: bytes, length: int, nonce: bytes) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hmac.new(key, nonce + struct.pack(">I", counter), hashlib.sha256).digest())
        counter += 1
    return bytes(out[:length])


def encrypt_secret(plain: str) -> str:
    data = str(plain or "").encode("utf-8")
    nonce = secrets.token_bytes(8)
    stream = _keystream(_master_key(), len(data), nonce)
    xored = bytes(a ^ b for a, b in zip(data, stream))
    return base64.urlsafe_b64encode(nonce + xored).decode("ascii")


def decrypt_secret(enc: str) -> str:
    raw = base64.urlsafe_b64decode(str(enc or "").encode("ascii"))
    nonce, xored = raw[:8], raw[8:]
    stream = _keystream(_master_key(), len(xored), nonce)
    plain = bytes(a ^ b for a, b in zip(xored, stream))
    return plain.decode("utf-8")


def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def build_otpauth_uri(username: str, secret: str, issuer: str | None = None) -> str:
    issuer_value = str(issuer or MFA_ISSUER or "Monitoring").strip() or "Monitoring"
    label = quote(f"{issuer_value}:{username}", safe="")
    issuer_q = quote(issuer_value, safe="")
    secret_q = quote(str(secret or "").strip(), safe="")
    return (
        f"otpauth://totp/{label}?secret={secret_q}&issuer={issuer_q}"
        f"&digits={TOTP_DIGITS}&period={TOTP_PERIOD}"
    )


def _totp_at(counter: int, secret: str) -> str:
    normalized = str(secret or "").strip().upper().replace(" ", "")
    pad = "=" * ((8 - len(normalized) % 8) % 8)
    key = base64.b32decode(normalized + pad, casefold=True)
    digest = hmac.new(key, struct.pack(">Q", int(counter)), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10**TOTP_DIGITS)).zfill(TOTP_DIGITS)


def verify_totp(secret: str, code: str, last_used_step: int = 0) -> tuple[bool, int]:
    normalized_code = re.sub(r"\s+", "", str(code or "").strip())
    if not re.fullmatch(rf"\d{{{TOTP_DIGITS}}}", normalized_code):
        return False, int(last_used_step or 0)

    now_step = int(time.time()) // TOTP_PERIOD
    last_step = int(last_used_step or 0)
    for delta in range(-TOTP_WINDOW, TOTP_WINDOW + 1):
        step = now_step + delta
        if step <= last_step:
            continue
        if hmac.compare_digest(_totp_at(step, secret), normalized_code):
            return True, step
    return False, last_step


def build_qr_svg(data: str) -> str:
    try:
        import qrcode
        import qrcode.image.svg

        buf = BytesIO()
        qrcode.make(str(data or ""), image_factory=qrcode.image.svg.SvgPathImage).save(buf)
        return buf.getvalue().decode("utf-8")
    except Exception:
        return ""


def init_mfa_tables(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS web_user_mfa (
            username TEXT PRIMARY KEY,
            totp_secret_enc TEXT NOT NULL DEFAULT '',
            totp_enabled INTEGER NOT NULL DEFAULT 0,
            totp_enrolled_at_utc TEXT NOT NULL DEFAULT '',
            totp_last_used_step INTEGER NOT NULL DEFAULT 0,
            pending_secret_enc TEXT NOT NULL DEFAULT '',
            FOREIGN KEY(username) REFERENCES web_users(username)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS web_mfa_challenges (
            challenge_token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            created_at_utc TEXT NOT NULL,
            expires_at_utc TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(username) REFERENCES web_users(username)
        )
        """
    )
    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_web_mfa_challenges_expires
        ON web_mfa_challenges(expires_at_utc)
        """
    )


def purge_expired_mfa_challenges(conn: sqlite3.Connection) -> None:
    conn.execute(
        "DELETE FROM web_mfa_challenges WHERE expires_at_utc <= ?",
        (_utc_now_iso(),),
    )


def ensure_mfa_schema(conn: sqlite3.Connection) -> None:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'web_user_mfa' LIMIT 1"
    ).fetchone()
    if not row:
        init_mfa_tables(conn)


def get_mfa_row(conn: sqlite3.Connection, username: str) -> dict | None:
    ensure_mfa_schema(conn)
    row = conn.execute(
        """
        SELECT username,
               totp_secret_enc,
               COALESCE(totp_enabled, 0),
               COALESCE(totp_enrolled_at_utc, ''),
               COALESCE(totp_last_used_step, 0),
               COALESCE(pending_secret_enc, '')
        FROM web_user_mfa
        WHERE username = ?
        """,
        (username,),
    ).fetchone()
    if not row:
        return None
    return {
        "username": str(row[0] or ""),
        "totp_secret_enc": str(row[1] or ""),
        "totp_enabled": bool(int(row[2] or 0)),
        "totp_enrolled_at_utc": str(row[3] or ""),
        "totp_last_used_step": int(row[4] or 0),
        "pending_secret_enc": str(row[5] or ""),
    }


def is_user_mfa_enabled(conn: sqlite3.Connection, username: str) -> bool:
    row = get_mfa_row(conn, username)
    return bool(row and row.get("totp_enabled"))


def mfa_status_payload(conn: sqlite3.Connection, username: str) -> dict:
    row = get_mfa_row(conn, username)
    enabled = bool(row and row.get("totp_enabled"))
    return {
        "enabled": enabled,
        "enrolled_at_utc": str(row.get("totp_enrolled_at_utc", "") or "") if row else "",
        "issuer": MFA_ISSUER,
    }


def start_mfa_enrollment(conn: sqlite3.Connection, username: str) -> dict:
    ensure_mfa_schema(conn)
    secret = generate_totp_secret()
    pending_enc = encrypt_secret(secret)
    now_iso = _utc_now_iso()
    conn.execute(
        """
        INSERT INTO web_user_mfa (
            username, totp_secret_enc, totp_enabled, totp_enrolled_at_utc,
            totp_last_used_step, pending_secret_enc
        )
        VALUES (?, '', 0, '', 0, ?)
        ON CONFLICT(username) DO UPDATE SET
            pending_secret_enc = excluded.pending_secret_enc,
            totp_enabled = CASE WHEN web_user_mfa.totp_enabled = 1 THEN 1 ELSE 0 END
        """,
        (username, pending_enc),
    )
    uri = build_otpauth_uri(username, secret)
    return {
        "secret": secret,
        "otpauth_uri": uri,
        "qr_svg": build_qr_svg(uri),
        "issuer": MFA_ISSUER,
        "started_at_utc": now_iso,
    }


def confirm_mfa_enrollment(conn: sqlite3.Connection, username: str, code: str) -> bool:
    row = get_mfa_row(conn, username)
    if not row or not row.get("pending_secret_enc"):
        raise ValueError("no pending enrollment")

    secret = decrypt_secret(str(row["pending_secret_enc"]))
    ok, step = verify_totp(secret, code, 0)
    if not ok:
        return False

    now_iso = _utc_now_iso()
    conn.execute(
        """
        UPDATE web_user_mfa
        SET totp_secret_enc = ?,
            totp_enabled = 1,
            totp_enrolled_at_utc = ?,
            totp_last_used_step = ?,
            pending_secret_enc = ''
        WHERE username = ?
        """,
        (encrypt_secret(secret), now_iso, step, username),
    )
    return True


def disable_mfa(conn: sqlite3.Connection, username: str, code: str) -> bool:
    row = get_mfa_row(conn, username)
    if not row or not row.get("totp_enabled") or not row.get("totp_secret_enc"):
        raise ValueError("mfa not enabled")

    secret = decrypt_secret(str(row["totp_secret_enc"]))
    ok, _ = verify_totp(secret, code, int(row.get("totp_last_used_step") or 0))
    if not ok:
        return False

    conn.execute("DELETE FROM web_user_mfa WHERE username = ?", (username,))
    return True


def verify_user_mfa_code(conn: sqlite3.Connection, username: str, code: str) -> bool:
    row = get_mfa_row(conn, username)
    if not row or not row.get("totp_enabled") or not row.get("totp_secret_enc"):
        raise ValueError("mfa not enabled")

    secret = decrypt_secret(str(row["totp_secret_enc"]))
    ok, step = verify_totp(secret, code, int(row.get("totp_last_used_step") or 0))
    if not ok:
        return False

    conn.execute(
        "UPDATE web_user_mfa SET totp_last_used_step = ? WHERE username = ?",
        (step, username),
    )
    return True


def create_mfa_challenge(conn: sqlite3.Connection, username: str) -> str:
    ensure_mfa_schema(conn)
    purge_expired_mfa_challenges(conn)
    challenge_token = secrets.token_urlsafe(32)
    now = datetime.now(timezone.utc)
    expires = now + timedelta(seconds=MFA_CHALLENGE_TTL_SECONDS)
    conn.execute(
        """
        INSERT INTO web_mfa_challenges (
            challenge_token, username, created_at_utc, expires_at_utc, attempts
        )
        VALUES (?, ?, ?, ?, 0)
        """,
        (
            challenge_token,
            username,
            now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            expires.strftime("%Y-%m-%dT%H:%M:%SZ"),
        ),
    )
    return challenge_token


def get_mfa_challenge(conn: sqlite3.Connection, challenge_token: str) -> dict | None:
    ensure_mfa_schema(conn)
    purge_expired_mfa_challenges(conn)
    row = conn.execute(
        """
        SELECT challenge_token, username, created_at_utc, expires_at_utc, COALESCE(attempts, 0)
        FROM web_mfa_challenges
        WHERE challenge_token = ?
        """,
        (str(challenge_token or "").strip(),),
    ).fetchone()
    if not row:
        return None
    expires_at = str(row[3] or "")
    if expires_at <= _utc_now_iso():
        conn.execute("DELETE FROM web_mfa_challenges WHERE challenge_token = ?", (row[0],))
        return None
    return {
        "challenge_token": str(row[0] or ""),
        "username": str(row[1] or ""),
        "created_at_utc": str(row[2] or ""),
        "expires_at_utc": expires_at,
        "attempts": int(row[4] or 0),
    }


def increment_mfa_challenge_attempts(conn: sqlite3.Connection, challenge_token: str) -> int:
    conn.execute(
        "UPDATE web_mfa_challenges SET attempts = COALESCE(attempts, 0) + 1 WHERE challenge_token = ?",
        (challenge_token,),
    )
    row = conn.execute(
        "SELECT COALESCE(attempts, 0) FROM web_mfa_challenges WHERE challenge_token = ?",
        (challenge_token,),
    ).fetchone()
    return int(row[0] or 0) if row else MFA_MAX_ATTEMPTS


def delete_mfa_challenge(conn: sqlite3.Connection, challenge_token: str) -> None:
    conn.execute("DELETE FROM web_mfa_challenges WHERE challenge_token = ?", (challenge_token,))
