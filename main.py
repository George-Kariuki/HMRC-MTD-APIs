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
from database import init_db
from hmrc_client import _resolve_vendor_ip
from routes import router


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
    vendor_ip = _resolve_vendor_ip()
    _startup_logger.info("Gov-Vendor-Public-IP will be: %s", vendor_ip)
    yield


# ── App factory ───────────────────────────────────────────────────────────────────

app = FastAPI(
    title="HMRC MTD Property Landlord API",
    description=(
        "Backend service for HMRC Making Tax Digital — Income Tax (Self Assessment). "
        "Handles OAuth 2.0, fraud prevention headers, and all property business API calls "
        "so that an Adalo frontend stays simple."
    ),
    version="1.0.0",
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
    Return the HMRC OAuth authorisation URL as JSON.

    Adalo external API actions cannot follow HTTP 302 redirects, so this
    endpoint returns the URL for the frontend to open in a webview or browser.

    Response:
        {"auth_url": "https://test-api.service.hmrc.gov.uk/oauth/authorize?..."}
    """
    url, _ = build_auth_url()
    return {"auth_url": url}


@app.get("/auth/callback", tags=["Auth"])
async def auth_callback(code: str, state: str, request: Request):
    """
    OAuth 2.0 callback — HMRC redirects here after the user authorises.

    Exchanges the one-time code for tokens, creates a session, and returns the
    session_id.  Adalo must persist this value and include it as the
    X-Session-ID header in every subsequent API request.

    After receiving the session_id:
      1. Prompt the user for their NINO
      2. Call POST /auth/set-nino  {"nino": "AA123456A"}
      3. Then call /business-details, /obligations, etc.
    """
    session_id = await exchange_code_for_tokens(code, state)
    return JSONResponse(
        content={
            "session_id": session_id,
            "message": (
                "Authentication successful. "
                "Store this session_id and send it as the X-Session-ID header "
                "on all future requests. Then call POST /auth/set-nino with your NINO."
            ),
        }
    )


# ── Health check ──────────────────────────────────────────────────────────────────

@app.get("/health", tags=["Health"])
async def health():
    """Simple liveness probe for deployment platforms."""
    return {"status": "ok", "service": "hmrc-mtd-property-api"}
