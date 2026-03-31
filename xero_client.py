"""
xero_client.py — Reusable Xero Accounting API client.

Derived from the Postman collection:
  - Base URL:      https://api.xero.com/api.xro/2.0/
  - Connections:   https://api.xero.com/connections
  - Auth header:   Authorization: Bearer <access_token>
  - Tenant header: xero-tenant-id: <tenant_id>

Every method raises HTTPException on non-2xx Xero responses so FastAPI
can return structured errors to Adalo.

Xero date format:
  Dates come back as Xero's .NET-style epoch strings: /Date(1772668800000+0000)/
  _parse_xero_date() converts them to ISO YYYY-MM-DD strings.
"""

import re
from datetime import datetime, timezone
from typing import Optional

import httpx
from fastapi import HTTPException

XERO_BASE = "https://api.xero.com/api.xro/2.0"


# ── Date parsing ──────────────────────────────────────────────────────────────────

def _parse_xero_date(raw: Optional[str]) -> Optional[str]:
    """
    Convert Xero's .NET JSON date format to ISO 8601 date string.

    Input:  "/Date(1772668800000+0000)/"
    Output: "2026-03-05"
    Falls back to the DateString field if available.
    """
    if not raw:
        return None
    m = re.search(r"/Date\((\d+)", raw)
    if m:
        ts = int(m.group(1)) / 1000
        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")
    return raw


def _raise_for_xero_error(resp: httpx.Response) -> None:
    """Convert a non-2xx Xero response into a FastAPI HTTPException."""
    if resp.is_success:
        return
    try:
        detail = resp.json()
    except Exception:
        detail = {"raw": resp.text}
    raise HTTPException(status_code=resp.status_code, detail=detail)


# ── Client class ──────────────────────────────────────────────────────────────────

class XeroClient:
    """
    Authenticated Xero Accounting API client.

    Instantiate per-request with the current access_token and tenant_id.
    Both are fetched from the session via xero_auth.get_valid_xero_token()
    which also handles automatic token refresh.
    """

    def __init__(self, access_token: str, tenant_id: str):
        self.access_token = access_token
        self.tenant_id    = tenant_id

    def _headers(self, extra: Optional[dict] = None) -> dict:
        """
        Standard headers for every Xero Accounting API request.

        Required:
          Authorization    — Bearer token from OAuth flow
          xero-tenant-id   — The organisation ID from GET /connections
          Accept           — application/json
        """
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "xero-tenant-id": self.tenant_id,
            "Accept": "application/json",
        }
        if extra:
            headers.update(extra)
        return headers

    # ── Bank Accounts ─────────────────────────────────────────────────────────────

    async def get_bank_accounts(self) -> list[dict]:
        """
        GET /Accounts?where=Type=="BANK"

        Fetches only BANK-type accounts (as seen in Postman collection).
        Returns simplified list:
          [{"id", "name", "bank_number", "currency"}]
        """
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{XERO_BASE}/Accounts",
                headers=self._headers(),
                params={"where": 'Type=="BANK"'},
            )
        _raise_for_xero_error(resp)

        accounts = resp.json().get("Accounts", [])
        return [
            {
                "id":          a.get("AccountID"),
                "name":        a.get("Name"),
                "code":        a.get("Code"),
                "bank_number": a.get("BankAccountNumber"),
                "currency":    a.get("CurrencyCode"),
                "status":      a.get("Status"),
            }
            for a in accounts
            if a.get("Type") == "BANK"
        ]

    # ── Bank Transactions ─────────────────────────────────────────────────────────

    async def get_bank_transactions(
        self,
        from_date: Optional[str] = None,
        to_date: Optional[str] = None,
        account_id: Optional[str] = None,
    ) -> list[dict]:
        """
        GET /BankTransactions?where=Type=="RECEIVE"||Type=="SPEND"

        Fetches RECEIVE (income) and SPEND (expense) transactions.
        Optionally filters by date range and/or bank account.

        Type mapping (from Postman collection test script):
          RECEIVE → "income"
          SPEND   → "expense"

        Date filter uses Xero's where clause syntax:
          Date>=DateTime(YYYY,MM,DD)
        """
        where_parts = ['Type=="RECEIVE"||Type=="SPEND"']

        if from_date:
            # Xero OData-style date filter
            y, m, d = from_date.split("-")
            where_parts.append(f"Date>=DateTime({y},{m},{d})")
        if to_date:
            y, m, d = to_date.split("-")
            where_parts.append(f"Date<=DateTime({y},{m},{d})")
        if account_id:
            where_parts.append(f'BankAccount.AccountID==Guid("{account_id}")')

        params = {"where": "&&".join(where_parts)}

        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{XERO_BASE}/BankTransactions",
                headers=self._headers(),
                params=params,
            )
        _raise_for_xero_error(resp)

        raw_txns = resp.json().get("BankTransactions", [])
        return [_transform_transaction(t) for t in raw_txns]


# ── Transaction transformer ───────────────────────────────────────────────────────

def _transform_transaction(t: dict) -> dict:
    """
    Map a raw Xero BankTransaction to the simplified app format.

    Xero type mapping:
      RECEIVE → "income"   (money coming in — e.g. rent received)
      SPEND   → "expense"  (money going out — e.g. mortgage, repairs)

    The Contact.Name is used as the description / counterparty label.
    Reference is used as notes when available.
    """
    xero_type = t.get("Type", "")
    mapped_type = "income" if xero_type == "RECEIVE" else "expense"

    # DateString is ISO-like: "2026-03-05T00:00:00" — prefer it over epoch
    date_string = t.get("DateString", "")
    date_iso = date_string[:10] if date_string else _parse_xero_date(t.get("Date"))

    contact_name = (t.get("Contact") or {}).get("Name", "")
    bank_name    = (t.get("BankAccount") or {}).get("Name", "")
    reference    = t.get("Reference", "")

    return {
        "id":          t.get("BankTransactionID"),
        "amount":      float(t.get("Total", 0)),
        "sub_total":   float(t.get("SubTotal", 0)),
        "tax":         float(t.get("TotalTax", 0)),
        "type":        mapped_type,
        "date":        date_iso,
        "description": contact_name,
        "reference":   reference,
        "notes":       reference or contact_name,
        "currency":    t.get("CurrencyCode", "GBP"),
        "bank_account": bank_name,
        "status":      t.get("Status"),
        "is_reconciled": t.get("IsReconciled", False),
    }
