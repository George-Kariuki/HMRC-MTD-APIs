"""
xero_auth.py — Xero OAuth 2.0 Authorization Code Flow + token lifecycle.

Endpoints that use this module:
  GET /xero/login-url  → build and return the Xero authorisation URL
  GET /xero/callback   → exchange ?code= for tokens, fetch tenant_id, store session
  GET /xero/session    → Adalo polls this to collect session_id after browser login

OAuth endpoints (from Postman collection):
  Authorise:  https://login.xero.com/identity/connect/authorize
  Token:      https://identity.xero.com/connect/token
  Tenants:    https://api.xero.com/connections

Token lifetime:
  access_token  — 30 minutes (1800 s)
  refresh_token — 60 days rolling; refreshed automatically before every API call
"""

import logging
import os
import time
import uuid
from typing import Optional, Tuple
from urllib.parse import urlencode

import httpx
from fastapi import HTTPException

from xero_database import (
    pop_xero_pending_session,
    save_xero_state,
    save_xero_tokens,
    store_xero_pending_session,
    update_xero_access_token,
    validate_and_delete_xero_state,
    get_xero_tokens,
)

logger = logging.getLogger(__name__)

# ── Xero OAuth endpoints (from Postman collection auth config) ────────────────────
XERO_AUTHORISE_URL = "https://login.xero.com/identity/connect/authorize"
XERO_TOKEN_URL     = "https://identity.xero.com/connect/token"
XERO_CONNECTIONS_URL = "https://api.xero.com/connections"

# Scopes required — matches Postman collection + accounting APIs
XERO_SCOPES = (
    "openid profile email offline_access "
    "accounting.transactions accounting.settings"
)

# Refresh proactively when token has less than 5 minutes remaining
_REFRESH_WINDOW_SECS = 300


def _cfg() -> dict:
    """Read Xero credentials from environment at call-time (not import-time)."""
    return {
        "client_id":     os.getenv("XERO_CLIENT_ID",     ""),
        "client_secret": os.getenv("XERO_CLIENT_SECRET", ""),
        "redirect_uri":  os.getenv(
            "XERO_REDIRECT_URI",
            "https://hmrc-mtd-ap-is.vercel.app/xero/callback",
        ),
    }


# ── Step 1: Build authorisation URL ──────────────────────────────────────────────

def build_xero_auth_url() -> Tuple[str, str]:
    """
    Construct the Xero OAuth authorisation URL.

    Generates a random `state` value, stores it to prevent CSRF, then
    returns (auth_url, state).  Adalo stores `state` and polls /xero/session
    once the user completes the Xero login flow.
    """
    cfg = _cfg()
    if not cfg["client_id"]:
        raise HTTPException(
            status_code=500,
            detail="XERO_CLIENT_ID is not configured. Add it to your .env / Vercel env vars.",
        )

    state = str(uuid.uuid4())
    save_xero_state(state)

    params = {
        "response_type": "code",
        "client_id":     cfg["client_id"],
        "redirect_uri":  cfg["redirect_uri"],
        "scope":         XERO_SCOPES,
        "state":         state,
    }
    url = f"{XERO_AUTHORISE_URL}?{urlencode(params)}"
    return url, state


# ── Step 2: Exchange code for tokens + fetch tenant_id ───────────────────────────

async def exchange_xero_code(code: str, state: str) -> str:
    """
    Exchange the one-time authorisation code for access + refresh tokens,
    then fetch the Xero tenant_id from /connections.

    Stores:
      - access_token, refresh_token, expires_at, tenant_id  (xero_tokens table)
      - state → session_id mapping  (xero_pending_sessions table, Adalo polling)

    Returns the new session_id.
    """
    if not validate_and_delete_xero_state(state):
        logger.warning(
            "Xero OAuth state invalid or expired: %s. "
            "Call /xero/login-url again.",
            state,
        )
        raise HTTPException(
            status_code=400,
            detail=(
                "Xero OAuth state mismatch — link expired or already used. "
                "Please call GET /xero/login-url for a fresh link."
            ),
        )

    cfg = _cfg()

    # ── Token exchange ────────────────────────────────────────────────────────────
    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            XERO_TOKEN_URL,
            data={
                "grant_type":    "authorization_code",
                "code":          code,
                "redirect_uri":  cfg["redirect_uri"],
                "client_id":     cfg["client_id"],
                "client_secret": cfg["client_secret"],
            },
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept":       "application/json",
            },
        )

    if token_resp.status_code != 200:
        raise HTTPException(
            status_code=502,
            detail=f"Xero token exchange failed ({token_resp.status_code}): {token_resp.text}",
        )

    token_data = token_resp.json()
    access_token  = token_data["access_token"]
    refresh_token = token_data.get("refresh_token")
    expires_at    = int(time.time()) + token_data.get("expires_in", 1800)

    # ── Fetch tenant_id from /connections ─────────────────────────────────────────
    # Xero requires a tenant_id (organisation ID) on every Accounting API call.
    # The /connections endpoint returns all orgs the user authorised.
    # We store the first one automatically; landlords typically have one org.
    async with httpx.AsyncClient() as client:
        conn_resp = await client.get(
            XERO_CONNECTIONS_URL,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept":        "application/json",
            },
        )

    if conn_resp.status_code != 200:
        raise HTTPException(
            status_code=502,
            detail=f"Xero /connections failed ({conn_resp.status_code}): {conn_resp.text}",
        )

    connections = conn_resp.json()
    if not connections:
        raise HTTPException(
            status_code=400,
            detail="No Xero organisations found. Make sure you authorised at least one Xero org.",
        )

    tenant_id   = connections[0]["tenantId"]
    tenant_name = connections[0].get("tenantName", "")
    logger.info("Xero connected: tenant=%s (%s)", tenant_name, tenant_id)

    # ── Persist session ───────────────────────────────────────────────────────────
    session_id = str(uuid.uuid4())
    save_xero_tokens(
        session_id=session_id,
        access_token=access_token,
        refresh_token=refresh_token,
        expires_at=expires_at,
        tenant_id=tenant_id,
    )
    store_xero_pending_session(state, session_id, tenant_id)

    return session_id


# ── Token refresh ─────────────────────────────────────────────────────────────────

async def get_valid_xero_token(session_id: str) -> Tuple[str, str]:
    """
    Return a valid (access_token, tenant_id) pair, refreshing if needed.

    Xero access tokens expire after 30 minutes.  This is called before every
    outbound Xero API call so tokens are always fresh without user interaction.
    """
    tokens = get_xero_tokens(session_id)
    if not tokens:
        raise HTTPException(
            status_code=401,
            detail="Xero session not found. Please re-authenticate via /xero/login-url.",
        )

    expires_at = tokens.get("expires_at") or 0
    if int(time.time()) <= (expires_at - _REFRESH_WINDOW_SECS):
        # Token still valid
        return tokens["access_token"], tokens["tenant_id"]

    # ── Refresh the access token using the refresh_token ─────────────────────────
    refresh_token = tokens.get("refresh_token")
    if not refresh_token:
        raise HTTPException(
            status_code=401,
            detail="Xero access token expired and no refresh token stored. Please re-authenticate.",
        )

    cfg = _cfg()
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            XERO_TOKEN_URL,
            data={
                "grant_type":    "refresh_token",
                "refresh_token": refresh_token,
                "client_id":     cfg["client_id"],
                "client_secret": cfg["client_secret"],
            },
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept":       "application/json",
            },
        )

    if resp.status_code != 200:
        raise HTTPException(
            status_code=401,
            detail=(
                f"Xero token refresh failed ({resp.status_code}). "
                "Please re-authenticate via /xero/login-url."
            ),
        )

    data = resp.json()
    new_access_token  = data["access_token"]
    new_refresh_token = data.get("refresh_token", refresh_token)
    new_expires_at    = int(time.time()) + data.get("expires_in", 1800)

    update_xero_access_token(
        session_id, new_access_token, new_refresh_token, new_expires_at
    )
    logger.info("Xero token refreshed for session %s…", session_id[:8])
    return new_access_token, tokens["tenant_id"]
