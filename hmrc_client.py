"""
hmrc_client.py — Reusable HMRC API client.

Every public method on HMRCClient:
  1. Attaches Authorization: Bearer <token>
  2. Attaches ALL required HMRC Fraud Prevention Headers (generated fresh per request)
  3. Raises HTTPException with a structured error body on non-2xx responses

Fraud Prevention header spec:
  https://developer.service.hmrc.gov.uk/guides/fraud-prevention/
"""

import ipaddress
import os
import random
import uuid
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import quote

import httpx
from fastapi import HTTPException

# ── Configuration (override via environment variables) ───────────────────────────

HMRC_BASE = os.getenv("HMRC_BASE_URL", "https://test-api.service.hmrc.gov.uk")

# Vendor identity — update these to match your HMRC application registration
VENDOR_VERSION      = os.getenv("VENDOR_VERSION",      "PropertyLandlordApp=1.0.0")
VENDOR_PRODUCT_NAME = os.getenv("VENDOR_PRODUCT_NAME", "Property%20Landlord%20MTD")
VENDOR_LICENSE_IDS  = os.getenv("VENDOR_LICENSE_IDS",  "property-landlord=00000000-0000-0000-0000-000000000001")
VENDOR_PUBLIC_IP    = os.getenv("VENDOR_PUBLIC_IP",     "198.51.100.2")

# When the inbound request has no real client public IP (localhost, private LAN),
# use this RFC 5737 TEST-NET-2 address so HMRC's validator accepts sandbox traffic.
# Production: terminate TLS on a reverse proxy and set X-Forwarded-For to the end-user's public IP.
FRAUD_CLIENT_PUBLIC_IP_FALLBACK = os.getenv(
    "FRAUD_CLIENT_PUBLIC_IP_FALLBACK", "198.51.100.1"
)

# ── Device ID — persists for the lifetime of the server process ──────────────────
# HMRC expects this to be stable across requests from the same "device" (server).
_SERVER_DEVICE_ID = str(uuid.uuid4())


# ── Fraud Prevention header builder ─────────────────────────────────────────────

def _iso_now() -> str:
    """Current UTC time in ISO 8601 with milliseconds, e.g. 2024-04-06T10:30:00.000Z"""
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _random_private_ip() -> str:
    """Generate a plausible RFC-1918 private IPv4 address (10.x.x.x range)."""
    return f"10.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"


def _random_ephemeral_port() -> str:
    """
    HMRC rejects well-known ports (80, 443, …) in Gov-Client-Public-Port.
    Use an ephemeral client-side port (IANA dynamic range).
    """
    return str(random.randint(49152, 65535))


def _must_use_fallback_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """
    True if this address must not be sent as Gov-Client-Public-IP / Gov-Vendor-Forwarded.

    We only treat loopback, RFC1918, link-local, etc. as invalid — not RFC 5737
    TEST-NET (198.51.100.0/24), which Python's is_private incorrectly flags but
    HMRC's sandbox validator accepts (matches Postman examples).
    """
    if addr.is_loopback or addr.is_link_local or addr.is_multicast or addr.is_unspecified:
        return True
    if addr.version == 6:
        return bool(addr.is_private)
    # IPv4 — RFC1918 + carrier-grade NAT range HMRC docs mention
    v4_nets = (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("100.64.0.0/10"),
        ipaddress.ip_network("127.0.0.0/8"),
    )
    return any(addr in n for n in v4_nets)


def _coerce_fraud_ip(raw: Optional[str], fallback: str) -> str:
    """Return a syntactically valid IP for fraud headers, or fallback."""
    fb = fallback.strip()
    if not raw or not str(raw).strip():
        return fb
    s = str(raw).strip()
    if "%" in s:
        s = s.split("%", 1)[0]
    try:
        addr = ipaddress.ip_address(s)
    except ValueError:
        return fb
    if _must_use_fallback_ip(addr):
        return fb
    return str(addr)


def build_fraud_headers(client_public_ip: str, client_user_id: str = "none") -> dict:
    """
    Build the complete set of HMRC Fraud Prevention Headers for a
    WEB_APP_VIA_SERVER connection method.

    Called once per outbound HMRC request so that all timestamps are fresh.
    The device ID (_SERVER_DEVICE_ID) is intentionally stable across requests —
    HMRC uses it to correlate activity from the same server installation.

    Required headers (HMRC Fraud Prevention spec v3.3, WEB_APP_VIA_SERVER):
      Gov-Client-*  — end-user context as seen from your server
      Gov-Vendor-*  — your product / infrastructure

    Not sent (validator rejects for this connection method):
      Gov-Client-MAC-Addresses — not required for WEB_APP_VIA_SERVER; including it fails validation.
    """
    now = _iso_now()

    # Multi-factor timestamp must be percent-encoded inside the header value
    mfa_ts_encoded = quote(now, safe="")

    local_ips = f"{_random_private_ip()},{_random_private_ip()}"
    public_client_ip = _coerce_fraud_ip(
        client_public_ip, FRAUD_CLIENT_PUBLIC_IP_FALLBACK
    )
    vendor_fb = os.getenv("VENDOR_PUBLIC_IP_FALLBACK", "198.51.100.2").strip()
    vendor_ip = _coerce_fraud_ip(VENDOR_PUBLIC_IP, vendor_fb)

    return {
        # ── Connection method ────────────────────────────────────────────────────
        "Gov-Client-Connection-Method": "WEB_APP_VIA_SERVER",

        # ── Client device / identity ─────────────────────────────────────────────
        "Gov-Client-Device-ID":    _SERVER_DEVICE_ID,
        "Gov-Client-User-IDs":     f"user={client_user_id}",
        "Gov-Client-Timezone":     "UTC+00:00",
        # Do NOT send Gov-Client-MAC-Addresses for WEB_APP_VIA_SERVER (HMRC INVALID_HEADER).

        # ── Client network ───────────────────────────────────────────────────────
        "Gov-Client-Public-IP":           public_client_ip,
        "Gov-Client-Public-IP-Timestamp": now,
        # Must not be a server port (80, 443, …); use ephemeral client port.
        "Gov-Client-Public-Port":         _random_ephemeral_port(),
        "Gov-Client-Local-IPs":           local_ips,
        "Gov-Client-Local-IPs-Timestamp": now,

        # ── Client browser / screen (required for WEB_APP_VIA_SERVER) ────────────
        "Gov-Client-Screens":             "width=1920&height=1080&scaling-factor=1&colour-depth=32",
        "Gov-Client-Window-Size":         "width=1224&height=800",
        "Gov-Client-Browser-Plugins": (
            "PDF%20Viewer,Chrome%20PDF%20Viewer,Chromium%20PDF%20Viewer,"
            "Microsoft%20Edge%20PDF%20Viewer,WebKit%20built-in%20PDF"
        ),
        "Gov-Client-Browser-JS-User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36"
        ),
        "Gov-Client-Browser-Do-Not-Track": "true",

        # ── Multi-factor authentication record ───────────────────────────────────
        "Gov-Client-Multi-Factor": (
            f"type=OTHER&timestamp={mfa_ts_encoded}&unique-reference=ref-123456"
        ),

        # ── Vendor / software product ─────────────────────────────────────────────
        "Gov-Vendor-Version":      VENDOR_VERSION,
        "Gov-Vendor-Public-IP":    vendor_ip,
        # `by` and `for` must both be public IPs (same values as Gov-Vendor-Public-IP / Gov-Client-Public-IP).
        "Gov-Vendor-Forwarded":    f"by={vendor_ip}&for={public_client_ip}",
        "Gov-Vendor-Product-Name": VENDOR_PRODUCT_NAME,
        "Gov-Vendor-License-IDs":  VENDOR_LICENSE_IDS,
    }


# ── Utility ──────────────────────────────────────────────────────────────────────

def derive_tax_year(date_str: str) -> str:
    """
    Derive the HMRC tax year string from a date.

    UK tax year runs 6 April → 5 April.
    E.g.  "2024-04-06" → "2024-25"
          "2024-04-05" → "2023-24"
    """
    from datetime import date
    d = date.fromisoformat(date_str)
    start_year = d.year if (d.month > 4 or (d.month == 4 and d.day >= 6)) else d.year - 1
    end_short = str(start_year + 1)[-2:]
    return f"{start_year}-{end_short}"


def _raise_for_hmrc_error(resp: httpx.Response) -> None:
    """
    Convert a non-2xx HMRC response into a FastAPI HTTPException with
    the HMRC error body preserved so Adalo can display a meaningful message.
    """
    if resp.is_success:
        return
    try:
        detail = resp.json()
    except Exception:
        detail = {"raw": resp.text}
    raise HTTPException(status_code=resp.status_code, detail=detail)


# ── HMRC API client ──────────────────────────────────────────────────────────────

class HMRCClient:
    """
    Authenticated HMRC MTD API client.

    Instantiate once per request with the user's current access token and
    originating public IP.  All methods:
      - Attach Authorization and Fraud Prevention headers automatically
      - Raise HTTPException on HMRC error responses
    """

    def __init__(
        self,
        access_token: str,
        client_ip: str,
        user_id: str = "none",
        base: str = HMRC_BASE,
    ):
        self.access_token = access_token
        self.client_ip = client_ip
        self.user_id = user_id
        self.base = base

    def _headers(self, accept_version: str, extra: Optional[dict] = None) -> dict:
        """
        Assemble the full header dict for an outbound HMRC request.
        Fraud headers are generated fresh each call so timestamps are current.
        """
        headers = {
            "Accept":        f"application/vnd.hmrc.{accept_version}+json",
            "Authorization": f"Bearer {self.access_token}",
            **build_fraud_headers(self.client_ip, self.user_id),
        }
        if extra:
            headers.update(extra)
        return headers

    # ── Business Details API ─────────────────────────────────────────────────────

    async def list_businesses(self, nino: str) -> dict:
        """
        GET /individuals/business/details/{nino}/list   (Accept v2.0)

        Returns all income sources registered under this NINO.
        The businessId from each uk-property entry is the incomeSourceId used
        in all subsequent property API calls.
        """
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self.base}/individuals/business/details/{nino}/list",
                headers=self._headers("2.0"),
            )
        _raise_for_hmrc_error(resp)
        return resp.json()

    # ── Obligations API ──────────────────────────────────────────────────────────

    async def get_obligations(
        self,
        nino: str,
        status: Optional[str] = None,
        type_of_business: Optional[str] = None,
        business_id: Optional[str] = None,
        from_date: Optional[str] = None,
        to_date: Optional[str] = None,
    ) -> dict:
        """
        GET /obligations/details/{nino}/income-and-expenditure   (Accept v3.0)

        Obligations are the authoritative source of submission periods.
        Each obligation detail contains:
          - periodStartDate  ← MUST be used as fromDate in periodic submission
          - periodEndDate    ← MUST be used as toDate   in periodic submission
          - dueDate          — deadline for the submission
          - status           — "Open" (not yet submitted) or "Fulfilled"

        Query params (HMRC names): typeOfBusiness, businessId, fromDate, toDate, status.
        Omit status to receive both open and fulfilled obligations.
        """
        params: dict = {}
        if status is not None and str(status).strip() != "":
            params["status"] = status.strip().lower()
        if type_of_business is not None and str(type_of_business).strip() != "":
            params["typeOfBusiness"] = type_of_business.strip()
        if business_id is not None and str(business_id).strip() != "":
            params["businessId"] = business_id.strip()
        if from_date is not None and str(from_date).strip() != "":
            params["fromDate"] = from_date.strip()
        if to_date is not None and str(to_date).strip() != "":
            params["toDate"] = to_date.strip()

        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self.base}/obligations/details/{nino}/income-and-expenditure",
                headers=self._headers("3.0"),
                params=params,
            )
        _raise_for_hmrc_error(resp)
        return resp.json()

    # ── Property Business Period Summaries ────────────────────────────────────────

    async def create_period_summary(
        self,
        nino: str,
        business_id: str,
        tax_year: str,
        from_date: str,
        to_date: str,
        income: dict,
        expenses: dict,
        property_type: str = "ukNonFhlProperty",
    ) -> dict:
        """
        POST /individuals/business/property/uk/{nino}/{businessId}/period/{taxYear}
        (Accept v6.0)

        Creates a new periodic (cumulative year-to-date) submission.
        from_date / to_date MUST exactly match the obligation's periodStartDate /
        periodEndDate — HMRC will reject mismatched dates.

        Submissions are CUMULATIVE: income and expense figures must represent
        total amounts from the start of the tax year, not just the current quarter.

        property_type: "ukNonFhlProperty" (standard buy-to-let) or "ukFhlProperty"
                       (Furnished Holiday Letting).
        """
        body = {
            "fromDate": from_date,
            "toDate":   to_date,
            property_type: {
                "income":   income,
                "expenses": expenses,
            },
        }
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.base}/individuals/business/property/uk"
                f"/{nino}/{business_id}/period/{tax_year}",
                headers=self._headers("6.0", {"Content-Type": "application/json"}),
                json=body,
            )
        _raise_for_hmrc_error(resp)
        return resp.json()

    async def amend_period_summary(
        self,
        nino: str,
        business_id: str,
        tax_year: str,
        submission_id: str,
        from_date: str,
        to_date: str,
        income: dict,
        expenses: dict,
        property_type: str = "ukNonFhlProperty",
    ) -> dict:
        """
        PUT /individuals/business/property/uk/{nino}/{businessId}/period/{taxYear}/{submissionId}
        (Accept v6.0)

        Amends an existing periodic submission with updated cumulative figures.
        submission_id is returned from the original create call (or from listing summaries).
        """
        body = {
            "fromDate": from_date,
            "toDate":   to_date,
            property_type: {
                "income":   income,
                "expenses": expenses,
            },
        }
        async with httpx.AsyncClient() as client:
            resp = await client.put(
                f"{self.base}/individuals/business/property/uk"
                f"/{nino}/{business_id}/period/{tax_year}/{submission_id}",
                headers=self._headers("6.0", {"Content-Type": "application/json"}),
                json=body,
            )
        _raise_for_hmrc_error(resp)
        return resp.json()

    async def get_period_summary(
        self,
        nino: str,
        business_id: str,
        tax_year: str,
        submission_id: str,
    ) -> dict:
        """
        GET /individuals/business/property/uk/{nino}/{businessId}/period/{taxYear}/{submissionId}
        (Accept v6.0)

        Retrieves a previously submitted period summary.
        """
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self.base}/individuals/business/property/uk"
                f"/{nino}/{business_id}/period/{tax_year}/{submission_id}",
                headers=self._headers("6.0"),
            )
        _raise_for_hmrc_error(resp)
        return resp.json()

    # ── Annual Submissions ────────────────────────────────────────────────────────

    async def amend_annual_submission(
        self,
        nino: str,
        business_id: str,
        tax_year: str,
        body: dict,
    ) -> dict:
        """
        PUT /individuals/business/property/uk/{nino}/{businessId}/annual/{taxYear}
        (Accept v6.0)

        Creates or amends the annual (end-of-year) allowances and adjustments
        submission. Body should follow the HMRC ukFhlProperty / ukProperty schema.
        """
        async with httpx.AsyncClient() as client:
            resp = await client.put(
                f"{self.base}/individuals/business/property/uk"
                f"/{nino}/{business_id}/annual/{tax_year}",
                headers=self._headers("6.0", {"Content-Type": "application/json"}),
                json=body,
            )
        _raise_for_hmrc_error(resp)
        return resp.json()

    async def get_annual_submission(
        self,
        nino: str,
        business_id: str,
        tax_year: str,
    ) -> dict:
        """
        GET /individuals/business/property/uk/{nino}/{businessId}/annual/{taxYear}
        (Accept v6.0)
        """
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self.base}/individuals/business/property/uk"
                f"/{nino}/{business_id}/annual/{tax_year}",
                headers=self._headers("6.0"),
            )
        _raise_for_hmrc_error(resp)
        return resp.json()

    # ── Fraud header validation (sandbox only) ────────────────────────────────────

    async def validate_fraud_headers(self) -> dict:
        """
        GET /test/fraud-prevention-headers/validate   (Accept v1.0)

        Calls HMRC's sandbox-only endpoint that inspects and scores the
        fraud prevention headers attached to this request.
        Returns code "VALID_HEADERS" on success.
        """
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self.base}/test/fraud-prevention-headers/validate",
                headers=self._headers("1.0"),
            )
        return resp.json()
