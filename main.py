"""
main.py — FastAPI application entry point.

Start locally:
    uvicorn main:app --reload --port 8000

The two auth endpoints live here (not in routes.py) because they are public
(no session required) and handle HTTP redirects, which need the full Request
and Response objects cleanly.
"""

import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse

load_dotenv(override=True)  # override=True ensures .env updates are picked up on reload

import logging
logging.basicConfig(level=logging.INFO)
_startup_logger = logging.getLogger("startup")
_startup_logger.info("HMRC_CLIENT_ID loaded: %s", os.getenv("HMRC_CLIENT_ID", "NOT SET")[:8] + "...")

from auth import build_auth_url, exchange_code_for_tokens
from database import init_db, pop_pending_session
from hmrc_client import _resolve_vendor_ip
from routes import router
from xero_database import init_xero_db
from xero_routes import router as xero_router


# ── Application lifespan ──────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Startup tasks:
      1. Initialise SQLite schema
      2. Pre-warm vendor IP detection so the first API call has no extra latency.
         If VENDOR_PUBLIC_IP env var is set, this is a no-op.
    """
    init_db()
    init_xero_db()
    vendor_ip = _resolve_vendor_ip()
    _startup_logger.info("Gov-Vendor-Public-IP will be: %s", vendor_ip)
    yield


# ── App factory ───────────────────────────────────────────────────────────────────

app = FastAPI(
    title="HMRC MTD & Xero Property Landlord API",
    description=(
        "Backend service for property landlords built on Adalo. "
        "Integrates HMRC Making Tax Digital (Income Tax Self Assessment) with full OAuth 2.0 "
        "and fraud prevention headers, plus Xero Accounting for bank accounts and transactions. "
        "All sensitive auth logic lives here — Adalo only calls simple REST endpoints."
    ),
    version="2.0.0",
    lifespan=lifespan,
)

# Allow Adalo and local dev origins.  Restrict ALLOW_ORIGINS in production.
_origins = os.getenv("ALLOW_ORIGINS", "*").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)
app.include_router(xero_router)


# ── Auth routes (public, no X-Session-ID required) ───────────────────────────────

@app.get("/auth/login", tags=["Auth"], include_in_schema=False)
async def auth_login():
    """
    Redirect the browser directly to HMRC's OAuth authorisation page.
    Useful for testing in a browser tab; Adalo should call /auth/login-url instead.
    """
    url, _ = build_auth_url()
    return RedirectResponse(url=url, status_code=302)


@app.get("/auth/login-url", tags=["Auth"])
async def auth_login_url():
    """
    **Step 1 of the Adalo auth flow.**

    Returns the HMRC OAuth authorisation URL AND the `state` token.

    Adalo workflow:
    1. Call this endpoint → store `state` in a hidden Adalo variable or user field.
    2. Open `auth_url` in the device browser (use Adalo's "Open URL" action).
    3. User logs in at HMRC — browser is redirected to the callback automatically.
    4. Poll `GET /auth/session?state=<state>` until `session_id` is returned.
    5. Store `session_id` in the Adalo user's profile.
    6. Call `POST /auth/set-nino` with the user's NINO.

    Response:
    ```json
    {
      "auth_url": "https://test-api.service.hmrc.gov.uk/oauth/authorize?...",
      "state": "ca945fed-bfed-4bc2-9340-0bfe6aae83e4"
    }
    ```
    """
    url, state = build_auth_url()
    return {"auth_url": url, "state": state}


@app.get("/auth/session", tags=["Auth"])
async def auth_session(state: str):
    """
    **Step 2 of the Adalo auth flow — poll this after the user logs in at HMRC.**

    Adalo calls this endpoint (every 3–5 seconds) after opening the HMRC login URL.
    Returns `session_id` once the user has completed the HMRC login; returns 202
    while still waiting.

    - `ready: false` → user hasn't finished logging in yet; poll again in 3–5 s
    - `ready: true`  → login complete; `session_id` is ready to store in Adalo

    The `session_id` is single-use from this endpoint — it is deleted from the
    pending store once collected, but remains valid for all subsequent API calls.
    """
    session_id = pop_pending_session(state)
    if not session_id:
        return JSONResponse(
            status_code=202,
            content={
                "ready": False,
                "message": "Login not yet completed. Poll again in a few seconds.",
            },
        )
    return JSONResponse(
        status_code=200,
        content={
            "ready": True,
            "session_id": session_id,
            "message": "Login successful. Store session_id and call POST /auth/set-nino next.",
        },
    )


@app.get("/auth/callback", tags=["Auth"])
async def auth_callback(code: str, state: str, request: Request):
    """
    OAuth 2.0 callback — HMRC redirects the user's browser here after login.

    This endpoint is called by HMRC (via browser redirect), NOT by Adalo.
    It exchanges the code for tokens and stores them, then shows a success page
    the user can close. Adalo collects the session_id via GET /auth/session.
    """
    session_id = await exchange_code_for_tokens(code, state)

    # Return a clean HTML page the user sees after HMRC login completes.
    # They can close this tab/window and return to the app.
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>HMRC Connected</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            display: flex; align-items: center; justify-content: center;
            min-height: 100vh; margin: 0; background: #f0fdf4; }}
    .card {{ background: white; border-radius: 12px; padding: 2rem 2.5rem;
             box-shadow: 0 4px 24px rgba(0,0,0,0.08); text-align: center;
             max-width: 400px; }}
    .tick {{ font-size: 3rem; }}
    h1 {{ color: #166534; font-size: 1.4rem; margin: 0.5rem 0; }}
    p {{ color: #64748b; font-size: 0.95rem; line-height: 1.5; }}
    small {{ color: #94a3b8; font-size: 0.8rem; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="tick">&#x2705;</div>
    <h1>HMRC Connected Successfully</h1>
    <p>You can now close this window and return to the app.</p>
    <small>Session: {session_id[:8]}…</small>
  </div>
</body>
</html>"""
    from fastapi.responses import HTMLResponse
    return HTMLResponse(content=html, status_code=200)


# ── Root ──────────────────────────────────────────────────────────────────────────

@app.get("/", tags=["Health"], include_in_schema=False)
async def root():
    """Root redirect — go to /docs for the interactive API reference."""
    return RedirectResponse(url="/docs", status_code=302)


# ── Health check ──────────────────────────────────────────────────────────────────

@app.get("/health", tags=["Health"])
async def health():
    """Simple liveness probe for deployment platforms."""
    return {"status": "ok", "service": "hmrc-mtd-xero-property-api", "version": "2.0.0"}
