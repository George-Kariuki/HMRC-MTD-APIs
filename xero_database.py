"""
xero_database.py — SQLite store for Xero OAuth sessions.

Kept separate from database.py so HMRC and Xero data never interfere.
Uses the same DB_PATH env var — both sets of tables live in one SQLite file.
"""

import os
import sqlite3
import time
from contextlib import contextmanager
from typing import Optional

DB_PATH = os.getenv("DB_PATH", "hmrc_tokens.db")

STATE_TTL_SECS = 1800  # 30 minutes


def init_xero_db() -> None:
    """Create Xero tables. Called at startup alongside init_db()."""
    with _conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS xero_tokens (
                session_id    TEXT PRIMARY KEY,
                access_token  TEXT NOT NULL,
                refresh_token TEXT,
                expires_at    INTEGER,
                tenant_id     TEXT,
                created_at    INTEGER DEFAULT (strftime('%s','now'))
            );

            CREATE TABLE IF NOT EXISTS xero_states (
                state      TEXT PRIMARY KEY,
                created_at INTEGER DEFAULT (strftime('%s','now'))
            );

            -- Maps state → session_id + tenant_id for Adalo polling.
            CREATE TABLE IF NOT EXISTS xero_pending_sessions (
                state      TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                tenant_id  TEXT,
                created_at INTEGER DEFAULT (strftime('%s','now'))
            );
        """)


@contextmanager
def _conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


# ── Token CRUD ────────────────────────────────────────────────────────────────────

def save_xero_tokens(
    session_id: str,
    access_token: str,
    refresh_token: Optional[str],
    expires_at: int,
    tenant_id: str,
) -> None:
    with _conn() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO xero_tokens
                (session_id, access_token, refresh_token, expires_at, tenant_id)
            VALUES (?, ?, ?, ?, ?)
            """,
            (session_id, access_token, refresh_token, expires_at, tenant_id),
        )


def get_xero_tokens(session_id: str) -> Optional[dict]:
    with _conn() as conn:
        row = conn.execute(
            "SELECT * FROM xero_tokens WHERE session_id = ?", (session_id,)
        ).fetchone()
        return dict(row) if row else None


def update_xero_access_token(
    session_id: str,
    access_token: str,
    refresh_token: str,
    expires_at: int,
) -> None:
    """Overwrite access_token, refresh_token, and expiry after a token refresh."""
    with _conn() as conn:
        conn.execute(
            """UPDATE xero_tokens
               SET access_token = ?, refresh_token = ?, expires_at = ?
               WHERE session_id = ?""",
            (access_token, refresh_token, expires_at, session_id),
        )


# ── CSRF state helpers ────────────────────────────────────────────────────────────

def save_xero_state(state: str) -> None:
    with _conn() as conn:
        cutoff = int(time.time()) - STATE_TTL_SECS
        conn.execute("DELETE FROM xero_states WHERE created_at < ?", (cutoff,))
        conn.execute(
            "INSERT OR IGNORE INTO xero_states (state) VALUES (?)", (state,)
        )


def validate_and_delete_xero_state(state: str) -> bool:
    with _conn() as conn:
        row = conn.execute(
            "SELECT state FROM xero_states WHERE state = ?", (state,)
        ).fetchone()
        if row:
            conn.execute("DELETE FROM xero_states WHERE state = ?", (state,))
            return True
        return False


# ── Pending session helpers (Adalo polling) ───────────────────────────────────────

def store_xero_pending_session(state: str, session_id: str, tenant_id: str) -> None:
    """After a successful callback, store state → session_id for Adalo polling."""
    with _conn() as conn:
        cutoff = int(time.time()) - STATE_TTL_SECS
        conn.execute(
            "DELETE FROM xero_pending_sessions WHERE created_at < ?", (cutoff,)
        )
        conn.execute(
            """INSERT OR REPLACE INTO xero_pending_sessions (state, session_id, tenant_id)
               VALUES (?, ?, ?)""",
            (state, session_id, tenant_id),
        )


def pop_xero_pending_session(state: str) -> Optional[dict]:
    """
    Retrieve and delete the pending session for a given state.
    Returns {"session_id": ..., "tenant_id": ...} or None if not yet ready.
    Single-use — deleted immediately on retrieval.
    """
    with _conn() as conn:
        row = conn.execute(
            "SELECT session_id, tenant_id FROM xero_pending_sessions WHERE state = ?",
            (state,),
        ).fetchone()
        if row:
            conn.execute(
                "DELETE FROM xero_pending_sessions WHERE state = ?", (state,)
            )
            return {"session_id": row["session_id"], "tenant_id": row["tenant_id"]}
        return None
