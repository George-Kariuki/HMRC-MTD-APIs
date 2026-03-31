"""
xero_routes.py — FastAPI route handlers for the Xero integration.

All endpoints live under the /xero/* prefix.
HMRC routes are completely untouched.

Authentication model (same pattern as HMRC):
  1. GET /xero/login-url → {"auth_url": "...", "state": "..."}
     Adalo stores `state` and opens `auth_url` in a browser.

  2. GET /xero/callback  (HMRC redirects browser here automatically)
     Backend exchanges code for tokens, fetches tenant_id.

  3. GET /xero/session?state=<state>
     Adalo polls this (202 = wait, 200 = ready) to collect session_id + tenant_id.

  4. Every subsequent call → X-Xero-Session-ID: <session_id>
"""

from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse

from xero_auth import build_xero_auth_url, exchange_xero_code, get_valid_xero_token
from xero_client import XeroClient
from xero_database import pop_xero_pending_session

router = APIRouter(prefix="/xero", tags=["Xero"])


# ── Helpers ───────────────────────────────────────────────────────────────────────

def _require_xero_session(x_xero_session_id: Optional[str]) -> str:
    if not x_xero_session_id:
        raise HTTPException(
            status_code=401,
            detail="Missing X-Xero-Session-ID header. Authenticate via GET /xero/login-url.",
        )
    return x_xero_session_id


async def _build_xero_client(session_id: str) -> XeroClient:
    """
    Get a fresh XeroClient for this request.
    Transparently refreshes the Xero access token if it is within 5 min of expiry.
    """
    access_token, tenant_id = await get_valid_xero_token(session_id)
    return XeroClient(access_token=access_token, tenant_id=tenant_id)


# ── Auth: login URL ───────────────────────────────────────────────────────────────

@router.get("/login-url")
async def xero_login_url():
    """
    **Step 1 — Adalo auth flow.**

    Returns the Xero OAuth authorisation URL and a `state` token.

    Adalo workflow:
    1. Call this endpoint → store `state` in a hidden Adalo variable.
    2. Open `auth_url` in the device browser ("Open URL" action).
    3. User logs in to Xero — browser auto-redirects to /xero/callback.
    4. Poll GET /xero/session?state=<state> until ready=true.
    5. Store `session_id` in Adalo user profile.

    ```json
    {
      "auth_url": "https://login.xero.com/identity/connect/authorize?...",
      "state": "uuid"
    }
    ```
    """
    url, state = build_xero_auth_url()
    return {"auth_url": url, "state": state}


# ── Auth: callback (browser redirect from Xero) ───────────────────────────────────

@router.get("/callback")
async def xero_callback(code: str, state: str):
    """
    **OAuth 2.0 callback — called by Xero (via browser redirect), not Adalo.**

    Exchanges the one-time code for tokens, fetches tenant_id, and stores
    the session.  Returns a success page the user can close.

    Adalo collects the session_id via GET /xero/session?state=<state>.
    """
    session_id = await exchange_xero_code(code, state)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Xero Connected</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            display: flex; align-items: center; justify-content: center;
            min-height: 100vh; margin: 0; background: #f0f9ff; }}
    .card {{ background: white; border-radius: 12px; padding: 2rem 2.5rem;
             box-shadow: 0 4px 24px rgba(0,0,0,0.08); text-align: center;
             max-width: 400px; }}
    .logo {{ font-size: 2.5rem; }}
    h1 {{ color: #13B5EA; font-size: 1.4rem; margin: 0.5rem 0; }}
    p {{ color: #64748b; font-size: 0.95rem; line-height: 1.5; }}
    small {{ color: #94a3b8; font-size: 0.8rem; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">&#x2705;</div>
    <h1>Xero Connected Successfully</h1>
    <p>Your Xero account has been linked. You can close this window and return to the app.</p>
    <small>Session: {session_id[:8]}…</small>
  </div>
</body>
</html>"""
    return HTMLResponse(content=html, status_code=200)


# ── Auth: session polling ─────────────────────────────────────────────────────────

@router.get("/session")
async def xero_session(state: str):
    """
    **Step 2 — Adalo polls this after opening the Xero login URL.**

    - HTTP 202 + `ready: false` → user hasn't finished yet; poll again in 3–5 s
    - HTTP 200 + `ready: true`  → `session_id` and `tenant_id` are ready

    ```json
    {
      "ready": true,
      "session_id": "...",
      "tenant_id": "..."
    }
    ```
    """
    result = pop_xero_pending_session(state)
    if not result:
        return JSONResponse(
            status_code=202,
            content={
                "ready": False,
                "message": "Xero login not yet completed. Poll again in a few seconds.",
            },
        )
    return JSONResponse(
        status_code=200,
        content={
            "ready":      True,
            "session_id": result["session_id"],
            "tenant_id":  result["tenant_id"],
            "message":    "Xero login successful. Store session_id and use it as X-Xero-Session-ID.",
        },
    )


# ── Bank Accounts ─────────────────────────────────────────────────────────────────

@router.get("/bank-accounts")
async def xero_bank_accounts(
    x_xero_session_id: Optional[str] = Header(None),
):
    """
    Fetch all BANK-type accounts from Xero.

    Xero endpoint:  GET /api.xro/2.0/Accounts?where=Type=="BANK"

    Returns:
    ```json
    [
      {
        "id": "38b4e08c-...",
        "name": "Barclays Business (UK)",
        "bank_number": "20346033730956",
        "currency": "GBP"
      }
    ]
    ```
    """
    session_id = _require_xero_session(x_xero_session_id)
    client = await _build_xero_client(session_id)
    accounts = await client.get_bank_accounts()
    return {"bank_accounts": accounts, "count": len(accounts)}


# ── Bank Transactions ─────────────────────────────────────────────────────────────

@router.get("/transactions")
async def xero_transactions(
    x_xero_session_id: Optional[str] = Header(None),
    from_date: Optional[str] = Query(
        None,
        alias="fromDate",
        description="Filter from date YYYY-MM-DD (optional)",
    ),
    to_date: Optional[str] = Query(
        None,
        alias="toDate",
        description="Filter to date YYYY-MM-DD (optional)",
    ),
    account_id: Optional[str] = Query(
        None,
        alias="accountId",
        description="Filter by Xero AccountID (optional)",
    ),
):
    """
    Fetch bank transactions of type RECEIVE (income) or SPEND (expense).

    Xero endpoint:  GET /api.xro/2.0/BankTransactions?where=Type=="RECEIVE"||Type=="SPEND"

    Type mapping:
      RECEIVE → `income`   (e.g. rent received)
      SPEND   → `expense`  (e.g. mortgage payment, repairs)

    Returns:
    ```json
    [
      {
        "id": "...",
        "amount": 1000.00,
        "type": "income",
        "date": "2026-03-07",
        "description": "George",
        "reference": "Test Rent",
        "notes": "Test Rent",
        "currency": "GBP"
      }
    ]
    ```
    """
    session_id = _require_xero_session(x_xero_session_id)
    client = await _build_xero_client(session_id)
    transactions = await client.get_bank_transactions(
        from_date=from_date,
        to_date=to_date,
        account_id=account_id,
    )
    return {
        "transactions": transactions,
        "count":        len(transactions),
        "query": {
            "fromDate":  from_date,
            "toDate":    to_date,
            "accountId": account_id,
        },
    }


# ── Sync ──────────────────────────────────────────────────────────────────────────

@router.post("/sync")
async def xero_sync(
    x_xero_session_id: Optional[str] = Header(None),
    from_date: Optional[str] = Query(None, alias="fromDate"),
    to_date: Optional[str] = Query(None, alias="toDate"),
):
    """
    Fetch and transform the latest Xero bank transactions into the
    standard app format for display or further processing.

    Returns a transformed list ready for Adalo to display or POST to other endpoints.

    ```json
    {
      "synced": 12,
      "transactions": [
        {
          "amount": 1000.00,
          "type": "income",
          "date": "2026-03-07",
          "notes": "Rent — George"
        }
      ]
    }
    ```
    """
    session_id = _require_xero_session(x_xero_session_id)
    client = await _build_xero_client(session_id)
    raw = await client.get_bank_transactions(from_date=from_date, to_date=to_date)

    # Transform to minimal app format
    transformed = [
        {
            "amount": t["amount"],
            "type":   t["type"],
            "date":   t["date"],
            "notes":  t["reference"] or t["description"],
        }
        for t in raw
    ]

    income_total  = sum(t["amount"] for t in raw if t["type"] == "income")
    expense_total = sum(t["amount"] for t in raw if t["type"] == "expense")

    return {
        "synced":          len(transformed),
        "income_total":    round(income_total, 2),
        "expense_total":   round(expense_total, 2),
        "net":             round(income_total - expense_total, 2),
        "transactions":    transformed,
    }
