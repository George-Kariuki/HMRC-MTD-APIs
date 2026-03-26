"""
database.py — SQLite-backed token and session store.

Stores OAuth tokens per session, plus transient OAuth state values used
to prevent CSRF during the authorisation code flow.
"""

import os
import sqlite3
import time
from contextlib import contextmanager
from typing import Optional

DB_PATH = os.getenv("DB_PATH", "hmrc_tokens.db")


# ── Schema ───────────────────────────────────────────────────────────────────────

def init_db() -> None:
    """Create tables if they don't already exist. Called once at startup."""
    with _conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS tokens (
                session_id   TEXT PRIMARY KEY,
                access_token  TEXT NOT NULL,
                refresh_token TEXT,
                expires_at    INTEGER,
                nino          TEXT,
                created_at    INTEGER DEFAULT (strftime('%s','now'))
            );

            CREATE TABLE IF NOT EXISTS oauth_states (
                state      TEXT PRIMARY KEY,
                created_at INTEGER DEFAULT (strftime('%s','now'))
            );

            -- Maps state → session_id so Adalo can poll for the session_id
            -- after the user completes the HMRC login flow in a browser.
            -- Rows are cleaned up after 30 minutes.
            CREATE TABLE IF NOT EXISTS pending_sessions (
                state      TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                created_at INTEGER DEFAULT (strftime('%s','now'))
            );
        """)


# ── Connection helper ────────────────────────────────────────────────────────────

@contextmanager
def _conn():
    """Yield a committed SQLite connection with Row factory enabled."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


# ── Token CRUD ───────────────────────────────────────────────────────────────────

def save_tokens(
    session_id: str,
    access_token: str,
    refresh_token: Optional[str],
    expires_at: int,
    nino: Optional[str] = None,
) -> None:
    with _conn() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO tokens
                (session_id, access_token, refresh_token, expires_at, nino)
            VALUES (?, ?, ?, ?, ?)
            """,
            (session_id, access_token, refresh_token, expires_at, nino),
        )


def get_tokens(session_id: str) -> Optional[dict]:
    with _conn() as conn:
        row = conn.execute(
            "SELECT * FROM tokens WHERE session_id = ?", (session_id,)
        ).fetchone()
        return dict(row) if row else None


def update_access_token(session_id: str, access_token: str, expires_at: int) -> None:
    """Overwrite just the access token and expiry after a token refresh."""
    with _conn() as conn:
        conn.execute(
            "UPDATE tokens SET access_token = ?, expires_at = ? WHERE session_id = ?",
            (access_token, expires_at, session_id),
        )


def update_nino(session_id: str, nino: str) -> None:
    """Associate a NINO with an existing session (called after /auth/set-nino)."""
    with _conn() as conn:
        conn.execute(
            "UPDATE tokens SET nino = ? WHERE session_id = ?",
            (nino, session_id),
        )


def delete_session(session_id: str) -> None:
    with _conn() as conn:
        conn.execute("DELETE FROM tokens WHERE session_id = ?", (session_id,))


# ── OAuth state CSRF helpers ─────────────────────────────────────────────────────

STATE_TTL_SECS = 1800  # 30 minutes — enough for HMRC's login page + user interaction


def save_state(state: str) -> None:
    """Persist a one-time OAuth state value before redirecting to HMRC."""
    with _conn() as conn:
        cutoff = int(time.time()) - STATE_TTL_SECS
        conn.execute("DELETE FROM oauth_states WHERE created_at < ?", (cutoff,))
        conn.execute("INSERT OR IGNORE INTO oauth_states (state) VALUES (?)", (state,))


def validate_and_delete_state(state: str) -> bool:
    """
    Consume the state value on callback.
    Returns True if the state existed (valid), False if it was unknown / already used.
    """
    with _conn() as conn:
        row = conn.execute(
            "SELECT state FROM oauth_states WHERE state = ?", (state,)
        ).fetchone()
        if row:
            conn.execute("DELETE FROM oauth_states WHERE state = ?", (state,))
            return True
        return False


# ── Pending session helpers (Adalo polling pattern) ──────────────────────────────

def store_pending_session(state: str, session_id: str) -> None:
    """
    After a successful callback, link the OAuth state to the new session_id.
    Adalo polls GET /auth/session?state=<state> to collect the session_id.
    """
    with _conn() as conn:
        cutoff = int(time.time()) - STATE_TTL_SECS
        conn.execute("DELETE FROM pending_sessions WHERE created_at < ?", (cutoff,))
        conn.execute(
            "INSERT OR REPLACE INTO pending_sessions (state, session_id) VALUES (?, ?)",
            (state, session_id),
        )


def pop_pending_session(state: str) -> Optional[str]:
    """
    Retrieve and immediately delete the session_id for a given state.
    Single-use: once collected by Adalo the record is removed.
    Returns None if the state has not yet completed or never existed.
    """
    with _conn() as conn:
        row = conn.execute(
            "SELECT session_id FROM pending_sessions WHERE state = ?", (state,)
        ).fetchone()
        if row:
            conn.execute("DELETE FROM pending_sessions WHERE state = ?", (state,))
            return row["session_id"]
        return None
