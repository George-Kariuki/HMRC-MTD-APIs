"""
auth.py — HMRC OAuth 2.0 Authorization Code Flow.

Flow:
  1. /auth/login-url  → returns HMRC authorise URL (Adalo opens it in a browser/webview)
  2. /auth/callback   → HMRC redirects here with ?code=...&state=...
                        → exchange code for tokens, create session, return session_id
  3. Every subsequent request → include X-Session-ID header
                               → get_valid_access_token() transparently refreshes if needed

Token refresh:
  HMRC access tokens expire after 4 hours.  get_valid_access_token() checks expiry
  before every API call and uses the refresh_token automatically.
"""

import logging
import os
import time
import uuid
from typing import Tuple
from urllib.parse import urlencode

import httpx
from fastapi import HTTPException

logger = logging.getLogger(__name__)

from database import (
    get_tokens,
    save_state,
    save_tokens,
    update_access_token,
    validate_and_delete_state,
)

# Scopes required by the MTD Income Tax API
SCOPES = "read:self-assessment write:self-assessment"

# Proactive refresh window: refresh the token if it expires within 5 minutes
_REFRESH_WINDOW_SECS = 300


def _cfg() -> dict:
    """
    Read credentials from os.environ at call time (not at import time).
    This means changes to .env are always picked up without restarting.
    """
    return {
        "base":          os.getenv("HMRC_BASE_URL",      "https://test-api.service.hmrc.gov.uk"),
        "client_id":     os.getenv("HMRC_CLIENT_ID",     ""),
        "client_secret": os.getenv("HMRC_CLIENT_SECRET", ""),
        "redirect_uri":  os.getenv("REDIRECT_URI",       "http://localhost:8000/auth/callback"),
    }


# ── Build authorise URL ──────────────────────────────────────────────────────────

def build_auth_url() -> Tuple[str, str]:
    """
    Construct the HMRC OAuth authorisation URL with a random state value.

    The state is stored in the DB to prevent CSRF — it is validated and
    consumed in exchange_code_for_tokens().

    Returns (authorise_url, state).
    """
    cfg = _cfg()
    if not cfg["client_id"]:
        raise HTTPException(
            status_code=500,
            detail="HMRC_CLIENT_ID is not configured. Set it in your .env file.",
        )

    state = str(uuid.uuid4())
    save_state(state)

    params = {
        "response_type": "code",
        "client_id":     cfg["client_id"],
        "scope":         SCOPES,
        "redirect_uri":  cfg["redirect_uri"],
        "state":         state,
    }
    url = f"{cfg['base']}/oauth/authorize?{urlencode(params)}"
    return url, state


# ── Exchange code for tokens ─────────────────────────────────────────────────────

async def exchange_code_for_tokens(code: str, state: str) -> str:
    """
    Exchange the authorisation code for an access token and refresh token.

    Validates the CSRF state value, then POSTs to HMRC's token endpoint.
    Stores the tokens in SQLite and returns a new session_id that the
    Adalo frontend must include as the X-Session-ID header on all future calls.
    """
    if not validate_and_delete_state(state):
        logger.warning(
            "OAuth state validation failed — state not found in DB: %s. "
            "Likely causes: (1) state expired (>30 min), (2) callback URL opened twice, "
            "(3) login URL was re-generated after the HMRC flow started. "
            "Fix: call /auth/login-url again and complete the flow in one go.",
            state,
        )
        raise HTTPException(
            status_code=400,
            detail=(
                "OAuth state mismatch — this login link has expired or already been used. "
                "Please call GET /auth/login-url to get a fresh link and complete "
                "the HMRC login within 30 minutes."
            ),
        )

    cfg = _cfg()
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{cfg['base']}/oauth/token",
            data={
                "grant_type":    "authorization_code",
                "code":          code,
                "redirect_uri":  cfg["redirect_uri"],
                "client_id":     cfg["client_id"],
                "client_secret": cfg["client_secret"],
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    if resp.status_code != 200:
        raise HTTPException(
            status_code=502,
            detail=f"HMRC token exchange failed ({resp.status_code}): {resp.text}",
        )

    data = resp.json()
    session_id  = str(uuid.uuid4())
    expires_at  = int(time.time()) + data.get("expires_in", 14400)  # default 4 h

    save_tokens(
        session_id=session_id,
        access_token=data["access_token"],
        refresh_token=data.get("refresh_token"),
        expires_at=expires_at,
    )
    return session_id


# ── Token refresh ─────────────────────────────────────────────────────────────────

async def get_valid_access_token(session_id: str) -> str:
    """
    Return a valid access token for the session, refreshing transparently if needed.

    Token refresh is triggered proactively when the token will expire within
    _REFRESH_WINDOW_SECS (default 5 minutes), so API calls never fail mid-flight
    due to an expired token.
    """
    tokens = get_tokens(session_id)
    if not tokens:
        raise HTTPException(
            status_code=401,
            detail="Session not found. Please re-authenticate via /auth/login-url.",
        )

    expires_at = tokens.get("expires_at") or 0
    token_is_expiring = int(time.time()) > (expires_at - _REFRESH_WINDOW_SECS)

    if not token_is_expiring:
        return tokens["access_token"]

    # ── Refresh the token ────────────────────────────────────────────────────────
    refresh_token = tokens.get("refresh_token")
    if not refresh_token:
        raise HTTPException(
            status_code=401,
            detail="Access token expired and no refresh token is available. Please re-authenticate.",
        )

    cfg = _cfg()
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{cfg['base']}/oauth/token",
            data={
                "grant_type":    "refresh_token",
                "refresh_token": refresh_token,
                "client_id":     cfg["client_id"],
                "client_secret": cfg["client_secret"],
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    if resp.status_code != 200:
        raise HTTPException(
            status_code=401,
            detail=(
                f"Token refresh failed ({resp.status_code}). "
                "Please re-authenticate via /auth/login-url."
            ),
        )

    data = resp.json()
    new_expires_at = int(time.time()) + data.get("expires_in", 14400)
    update_access_token(session_id, data["access_token"], new_expires_at)
    return data["access_token"]
