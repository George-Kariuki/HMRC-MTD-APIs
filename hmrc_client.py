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
import logging
import os
import random
import re
import uuid
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import quote

import httpx
from fastapi import HTTPException

logger = logging.getLogger(__name__)

# ── Configuration (override via environment variables) ───────────────────────────

HMRC_BASE = os.getenv("HMRC_BASE_URL", "https://test-api.service.hmrc.gov.uk")

# Vendor identity — update these to match your HMRC application registration
VENDOR_VERSION      = os.getenv("VENDOR_VERSION",      "PropertyLandlordApp=1.0.0")
VENDOR_PRODUCT_NAME = os.getenv("VENDOR_PRODUCT_NAME", "Property%20Landlord%20MTD")
VENDOR_LICENSE_IDS  = os.getenv("VENDOR_LICENSE_IDS",  "property-landlord=00000000-0000-0000-0000-000000000001")

# When the inbound request has no real client public IP (localhost, private LAN),
# use this RFC 5737 TEST-NET address. Sandbox-safe; real deployments should ensure
# X-Forwarded-For carries the end-user's public IP from the edge proxy.
FRAUD_CLIENT_PUBLIC_IP_FALLBACK = os.getenv(
    "FRAUD_CLIENT_PUBLIC_IP_FALLBACK", "198.51.100.1"
)

# ── Device ID — persists for the lifetime of the server process ──────────────────
# HMRC expects this to be stable across requests from the same "device" (server).
_SERVER_DEVICE_ID = str(uuid.uuid4())

# ── Vendor public IP — auto-detected at startup ───────────────────────────────────
# VENDOR_PUBLIC_IP env var takes priority (set it if you have a static IP).
# Otherwise we call ipify.org once per process to get the server's current outbound
# IP. On Vercel/serverless, IPs shift between cold starts — that's fine; HMRC only
# requires a syntactically valid public IP for Gov-Vendor-Public-IP, not a
# permanently fixed one.

_DETECTED_VENDOR_IP: Optional[str] = None


def _resolve_vendor_ip() -> str:
    """
    Return the vendor public IP to use in Gov-Vendor-Public-IP.

    Priority:
      1. VENDOR_PUBLIC_IP env var (explicit override — use if you have a static IP)
      2. Cached auto-detected IP from ipify.org (fetched once per process)
      3. FRAUD_CLIENT_PUBLIC_IP_FALLBACK (TEST-NET 198.51.100.2 — sandbox-safe fallback)
    """
    global _DETECTED_VENDOR_IP

    env_ip = os.getenv("VENDOR_PUBLIC_IP", "").strip()
    if env_ip:
        return env_ip

    if _DETECTED_VENDOR_IP:
        return _DETECTED_VENDOR_IP

    # Auto-detect outbound IP using ipify (plain-text endpoint, no auth required)
    try:
        resp = httpx.get("https://api4.ipify.org", timeout=4)
        ip = resp.text.strip()
        # Validate it's a real public IP before caching
        addr = ipaddress.ip_address(ip)
        if not _must_use_fallback_ip(addr):
            _DETECTED_VENDOR_IP = ip
            logger.info("Auto-detected vendor public IP: %s", ip)
            return ip
    except Exception as exc:
        logger.warning("Could not auto-detect vendor IP from ipify: %s", exc)

    fallback = os.getenv("VENDOR_PUBLIC_IP_FALLBACK", "198.51.100.2")
    logger.info("Using vendor IP fallback: %s", fallback)
    return fallback


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
    vendor_ip = _resolve_vendor_ip()

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

_TAX_YEAR_RE = re.compile(r"^(\d{4})-(\d{2})$")


def parse_tax_year(tax_year: str) -> int:
    """
    Validate an HMRC tax year string `YYYY-YY` and return the start calendar year.

    Raises HTTPException(400) for malformed values (never ValueError → 500).
    Also checks that YY == (YYYY + 1) % 100 (e.g. 2024-25 ok, 2024-99 rejected).
    """
    if not isinstance(tax_year, str) or not tax_year.strip():
        raise HTTPException(
            status_code=400,
            detail="taxYear must be a string in YYYY-YY format (e.g. '2024-25').",
        )
    match = _TAX_YEAR_RE.fullmatch(tax_year.strip())
    if not match:
        raise HTTPException(
            status_code=400,
            detail="taxYear must be in YYYY-YY format (e.g. '2024-25').",
        )
    start_year = int(match.group(1))
    end_short = int(match.group(2))
    if end_short != (start_year + 1) % 100:
        raise HTTPException(
            status_code=400,
            detail=(
                f"taxYear '{tax_year}' is invalid: the second part must be "
                f"the start year + 1 (e.g. '2024-25')."
            ),
        )
    return start_year


def derive_tax_year(date_str: str) -> str:
    """
    Derive the HMRC tax year string from a date.

    UK tax year runs 6 April → 5 April.
    E.g.  "2024-04-06" → "2024-25"
          "2024-04-05" → "2023-24"
    """
    from datetime import date
    try:
        d = date.fromisoformat(date_str)
    except (TypeError, ValueError):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid date '{date_str}'. Use YYYY-MM-DD.",
        )
    start_year = d.year if (d.month > 4 or (d.month == 4 and d.day >= 6)) else d.year - 1
    end_short = str(start_year + 1)[-2:]
    return f"{start_year}-{end_short}"


def tax_year_start_year(tax_year: str) -> int:
    """Return the start calendar year from an HMRC tax year string (e.g. '2025-26' → 2025)."""
    return parse_tax_year(tax_year)


def assert_tax_year_at_least(tax_year: str, minimum: str = "2025-26") -> None:
    """Reject tax years before the HMRC minimum for cumulative / accounting-type endpoints."""
    if parse_tax_year(tax_year) < parse_tax_year(minimum):
        raise HTTPException(
            status_code=400,
            detail=f"taxYear must be {minimum} or later for this endpoint.",
        )


def assert_tax_year_at_most(tax_year: str, maximum: str = "2024-25") -> None:
    """Reject tax years after the HMRC maximum for legacy period-summary endpoints."""
    if parse_tax_year(tax_year) > parse_tax_year(maximum):
        raise HTTPException(
            status_code=400,
            detail=(
                f"taxYear must be {maximum} or earlier for this endpoint. "
                f"From 2025-26 use the cumulative period summary endpoints."
            ),
        )


def assert_tax_year_in_range(
    tax_year: str,
    minimum: str = "2017-18",
    maximum: str = "2021-22",
) -> None:
    """Reject tax years outside the HMRC historic property submission range."""
    start = parse_tax_year(tax_year)
    if start < parse_tax_year(minimum) or start > parse_tax_year(maximum):
        raise HTTPException(
            status_code=400,
            detail=(
                f"taxYear must be between {minimum} and {maximum} for historic "
                f"property endpoints. For later years use the standard annual/period APIs."
            ),
        )


def assert_historic_period_from_date(from_date: str) -> str:
    """
    Derive tax year from fromDate and enforce historic range (2017-18 to 2021-22).
    Returns the derived tax year string.
    """
    tax_year = derive_tax_year(from_date)
    assert_tax_year_in_range(tax_year)
    return tax_year


def assert_historic_period_body(body: dict) -> str:
    """Validate historic period create body has fromDate within 2017-18..2021-22."""
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Request body must be a JSON object.")
    from_date = body.get("fromDate")
    if not from_date or not isinstance(from_date, str):
        raise HTTPException(
            status_code=400,
            detail="Body must include fromDate in YYYY-MM-DD format.",
        )
    return assert_historic_period_from_date(from_date)


def assert_historic_period_id(period_id: str) -> str:
    """
    Validate historic periodId (`YYYY-MM-DD_YYYY-MM-DD`) is within 2017-18..2021-22
    using the start date. Returns the derived tax year string.
    """
    if not isinstance(period_id, str) or "_" not in period_id:
        raise HTTPException(
            status_code=400,
            detail="periodId must be in the form YYYY-MM-DD_YYYY-MM-DD.",
        )
    start_date = period_id.split("_", 1)[0]
    return assert_historic_period_from_date(start_date)


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


def _json_or_empty(resp: httpx.Response) -> dict:
    """
    Safely parse a successful HMRC response.

    Some HMRC endpoints (and some sandbox scenarios) can return an empty body
    (e.g. 204 No Content, or occasionally 200 with no JSON). In those cases,
    return a small metadata object instead of raising JSONDecodeError.
    """
    # Prefer explicit no-content handling first
    if resp.status_code == 204:
        return {
            "status": resp.status_code,
            "correlationId": resp.headers.get("X-CorrelationId"),
        }

    # Empty body on a 2xx response
    if not resp.content or not resp.text or resp.text.strip() == "":
        return {
            "status": resp.status_code,
            "correlationId": resp.headers.get("X-CorrelationId"),
        }

    # If it's JSON, parse; otherwise return raw text
    ctype = (resp.headers.get("content-type") or "").lower()
    if "json" not in ctype:
        return {
            "status": resp.status_code,
            "correlationId": resp.headers.get("X-CorrelationId"),
            "raw": resp.text,
        }

    try:
        return resp.json()
    except Exception:
        return {
            "status": resp.status_code,
            "correlationId": resp.headers.get("X-CorrelationId"),
            "raw": resp.text,
        }


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
        return _json_or_empty(resp)

    async def retrieve_business(self, nino: str, business_id: str) -> dict:
        """
        GET /individuals/business/details/{nino}/{businessId}   (Accept v2.0)

        Returns the full details of a single income source identified by businessId.
        Useful for confirming commencementDate, latencyDetails and other metadata.
        For accounting type, use retrieve_accounting_type (not returned here since v2.0).

        Postman: Business Details API → Retrieve Business Details
        """
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self.base}/individuals/business/details/{nino}/{business_id}",
                headers=self._headers("2.0"),
            )
        _raise_for_hmrc_error(resp)
        return _json_or_empty(resp)

    async def retrieve_periods_of_account(
        self, nino: str, business_id: str, tax_year: str
    ) -> dict:
        """
        GET /individuals/business/details/{nino}/{businessId}/{taxYear}/periods-of-account
        (Accept v2.0)

        Returns the accounting periods available for submissions within the given
        tax year.  Use these to determine valid fromDate / toDate windows before
        creating cumulative period submissions.

        Postman: Business Details API → Retrieve Periods of Account
        """
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self.base}/individuals/business/details/{nino}"
                f"/{business_id}/{tax_year}/periods-of-account",
                headers=self._headers("2.0"),
            )
        _raise_for_hmrc_error(resp)
        return _json_or_empty(resp)

    async def retrieve_accounting_type(
        self,
        nino: str,
        business_id: str,
        tax_year: str,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """
        GET /individuals/business/details/{nino}/{businessId}/{taxYear}/accounting-type
        (Accept v2.0)

        Returns the accounting type (CASH or ACCRUALS) for the business in the
        given tax year.  Minimum tax year 2025-26 in production.
        """
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self.base}/individuals/business/details/{nino}"
                f"/{business_id}/{tax_year}/accounting-type",
                headers=self._headers(
                    "2.0",
                    {"Gov-Test-Scenario": gov_test_scenario} if gov_test_scenario else None,
                ),
            )
        _raise_for_hmrc_error(resp)
        return _json_or_empty(resp)

    async def update_accounting_type(
        self,
        nino: str,
        business_id: str,
        tax_year: str,
        body: dict,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """
        PUT /individuals/business/details/{nino}/{businessId}/{taxYear}/accounting-type
        (Accept v2.0)

        Creates or updates the accounting type for a business.  Body:
        {"accountingType": "CASH" | "ACCRUALS"}
        """
        async with httpx.AsyncClient() as client:
            resp = await client.put(
                f"{self.base}/individuals/business/details/{nino}"
                f"/{business_id}/{tax_year}/accounting-type",
                headers=self._headers(
                    "2.0",
                    {
                        "Content-Type": "application/json",
                        **(
                            {"Gov-Test-Scenario": gov_test_scenario}
                            if gov_test_scenario
                            else {}
                        ),
                    },
                ),
                json=body,
            )
        _raise_for_hmrc_error(resp)
        if resp.status_code == 204:
            return {"message": "Accounting type updated successfully."}
        return _json_or_empty(resp)

    async def create_or_update_periods_of_account(
        self,
        nino: str,
        business_id: str,
        tax_year: str,
        body: dict,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """
        PUT /individuals/business/details/{nino}/{businessId}/{taxYear}/periods-of-account
        (Accept v2.0)

        Creates or updates the periods of account for a business in the given tax year.
        """
        async with httpx.AsyncClient() as client:
            resp = await client.put(
                f"{self.base}/individuals/business/details/{nino}"
                f"/{business_id}/{tax_year}/periods-of-account",
                headers=self._headers(
                    "2.0",
                    {
                        "Content-Type": "application/json",
                        **(
                            {"Gov-Test-Scenario": gov_test_scenario}
                            if gov_test_scenario
                            else {}
                        ),
                    },
                ),
                json=body,
            )
        _raise_for_hmrc_error(resp)
        if resp.status_code == 204:
            return {"message": "Periods of account created/updated successfully."}
        return _json_or_empty(resp)

    async def create_amend_quarterly_period_type(
        self,
        nino: str,
        business_id: str,
        tax_year: str,
        body: dict,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """
        PUT /individuals/business/details/{nino}/{businessId}/{taxYear}
        (Accept v2.0)

        Creates or amends the quarterly period type for a business.
        Body: {"quarterlyPeriodType": "standard" | "calendar"}
        """
        async with httpx.AsyncClient() as client:
            resp = await client.put(
                f"{self.base}/individuals/business/details/{nino}"
                f"/{business_id}/{tax_year}",
                headers=self._headers(
                    "2.0",
                    {
                        "Content-Type": "application/json",
                        **(
                            {"Gov-Test-Scenario": gov_test_scenario}
                            if gov_test_scenario
                            else {}
                        ),
                    },
                ),
                json=body,
            )
        _raise_for_hmrc_error(resp)
        if resp.status_code == 204:
            return {"message": "Quarterly period type updated successfully."}
        return _json_or_empty(resp)

    async def retrieve_late_accounting_date_rule(
        self,
        nino: str,
        business_id: str,
        tax_year: str,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """
        GET /individuals/business/details/{nino}/{businessId}/{taxYear}/late-accounting-date-rule-election
        (Accept v2.0)
        """
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self.base}/individuals/business/details/{nino}"
                f"/{business_id}/{tax_year}/late-accounting-date-rule-election",
                headers=self._headers(
                    "2.0",
                    {"Gov-Test-Scenario": gov_test_scenario} if gov_test_scenario else None,
                ),
            )
        _raise_for_hmrc_error(resp)
        return _json_or_empty(resp)

    async def disapply_late_accounting_date_rule(
        self,
        nino: str,
        business_id: str,
        tax_year: str,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """
        POST .../late-accounting-date-rule-election/disapply  (Accept v2.0, no body)
        Only valid after the tax year has ended.
        """
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.base}/individuals/business/details/{nino}"
                f"/{business_id}/{tax_year}/late-accounting-date-rule-election/disapply",
                headers=self._headers(
                    "2.0",
                    {"Gov-Test-Scenario": gov_test_scenario} if gov_test_scenario else None,
                ),
            )
        _raise_for_hmrc_error(resp)
        if resp.status_code == 204:
            return {"message": "Late accounting date rule disapplied successfully."}
        return _json_or_empty(resp)

    async def withdraw_late_accounting_date_rule(
        self,
        nino: str,
        business_id: str,
        tax_year: str,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """
        DELETE .../late-accounting-date-rule-election/withdraw  (Accept v2.0)
        Only valid after the tax year has ended.
        """
        async with httpx.AsyncClient() as client:
            resp = await client.delete(
                f"{self.base}/individuals/business/details/{nino}"
                f"/{business_id}/{tax_year}/late-accounting-date-rule-election/withdraw",
                headers=self._headers(
                    "2.0",
                    {"Gov-Test-Scenario": gov_test_scenario} if gov_test_scenario else None,
                ),
            )
        _raise_for_hmrc_error(resp)
        if resp.status_code == 204:
            return {"message": "Late accounting date rule withdrawal successful."}
        return _json_or_empty(resp)

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
        return _json_or_empty(resp)

    async def get_final_declaration_obligations(
        self,
        nino: str,
        tax_year: Optional[str] = None,
        status: Optional[str] = None,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """
        GET /obligations/details/{nino}/crystallisation   (Accept v3.0)

        Retrieves final declaration (crystallisation) obligations.
        Optional query params: taxYear, status (open|fulfilled).
        If taxYear is omitted, HMRC returns obligations from 4 years before
        the current tax year through the current year.
        """
        params: dict = {}
        if tax_year is not None and str(tax_year).strip() != "":
            params["taxYear"] = tax_year.strip()
        if status is not None and str(status).strip() != "":
            params["status"] = status.strip().lower()

        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self.base}/obligations/details/{nino}/crystallisation",
                headers=self._headers(
                    "3.0",
                    {"Gov-Test-Scenario": gov_test_scenario} if gov_test_scenario else None,
                ),
                params=params or None,
            )
        _raise_for_hmrc_error(resp)
        return _json_or_empty(resp)

    # ── Property Business Period Summaries (≤ 2024-25) ────────────────────────────

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
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """
        POST /individuals/business/property/uk/{nino}/{businessId}/period/{taxYear}
        (Accept v6.0)

        Creates a new UK property period summary. Tax years ≤ 2024-25 only.
        from_date / to_date MUST exactly match the obligation period dates.
        property_type: "ukNonFhlProperty" or "ukFhlProperty".
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
                headers=self._headers(
                    "6.0",
                    {
                        "Content-Type": "application/json",
                        **(
                            {"Gov-Test-Scenario": gov_test_scenario}
                            if gov_test_scenario
                            else {}
                        ),
                    },
                ),
                json=body,
            )
        _raise_for_hmrc_error(resp)
        return _json_or_empty(resp)

    async def amend_period_summary(
        self,
        nino: str,
        business_id: str,
        tax_year: str,
        submission_id: str,
        income: dict,
        expenses: dict,
        property_type: str = "ukNonFhlProperty",
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """
        PUT /individuals/business/property/uk/{nino}/{businessId}/period/{taxYear}/{submissionId}
        (Accept v6.0)

        Amends an existing UK property period summary.
        Amend body must NOT include fromDate/toDate (create-only fields).
        """
        body = {
            property_type: {
                "income":   income,
                "expenses": expenses,
            },
        }
        async with httpx.AsyncClient() as client:
            resp = await client.put(
                f"{self.base}/individuals/business/property/uk"
                f"/{nino}/{business_id}/period/{tax_year}/{submission_id}",
                headers=self._headers(
                    "6.0",
                    {
                        "Content-Type": "application/json",
                        **(
                            {"Gov-Test-Scenario": gov_test_scenario}
                            if gov_test_scenario
                            else {}
                        ),
                    },
                ),
                json=body,
            )
        _raise_for_hmrc_error(resp)
        return _json_or_empty(resp)

    async def get_period_summary(
        self,
        nino: str,
        business_id: str,
        tax_year: str,
        submission_id: str,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """
        GET /individuals/business/property/uk/{nino}/{businessId}/period/{taxYear}/{submissionId}
        (Accept v6.0)
        """
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self.base}/individuals/business/property/uk"
                f"/{nino}/{business_id}/period/{tax_year}/{submission_id}",
                headers=self._headers(
                    "6.0",
                    {"Gov-Test-Scenario": gov_test_scenario} if gov_test_scenario else None,
                ),
            )
        _raise_for_hmrc_error(resp)
        return _json_or_empty(resp)

    async def list_property_period_summaries(
        self,
        nino: str,
        business_id: str,
        tax_year: str,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """
        GET /individuals/business/property/{nino}/{businessId}/period/{taxYear}
        (Accept v6.0)

        Lists period summaries for a UK or foreign property business (≤ 2024-25).
        Shared path — no uk/foreign segment.
        """
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self.base}/individuals/business/property"
                f"/{nino}/{business_id}/period/{tax_year}",
                headers=self._headers(
                    "6.0",
                    {"Gov-Test-Scenario": gov_test_scenario} if gov_test_scenario else None,
                ),
            )
        _raise_for_hmrc_error(resp)
        return _json_or_empty(resp)

    async def create_foreign_period_summary(
        self,
        nino: str,
        business_id: str,
        tax_year: str,
        body: dict,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """
        POST /individuals/business/property/foreign/{nino}/{businessId}/period/{taxYear}
        (Accept v6.0)

        Creates a foreign property period summary. Tax years ≤ 2024-25 only.
        Body: fromDate, toDate, optional foreignFhlEea, optional foreignNonFhlProperty[].
        """
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.base}/individuals/business/property/foreign"
                f"/{nino}/{business_id}/period/{tax_year}",
                headers=self._headers(
                    "6.0",
                    {
                        "Content-Type": "application/json",
                        **(
                            {"Gov-Test-Scenario": gov_test_scenario}
                            if gov_test_scenario
                            else {}
                        ),
                    },
                ),
                json=body,
            )
        _raise_for_hmrc_error(resp)
        return _json_or_empty(resp)

    async def get_foreign_period_summary(
        self,
        nino: str,
        business_id: str,
        tax_year: str,
        submission_id: str,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """
        GET /individuals/business/property/foreign/{nino}/{businessId}/period/{taxYear}/{submissionId}
        (Accept v6.0)
        """
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self.base}/individuals/business/property/foreign"
                f"/{nino}/{business_id}/period/{tax_year}/{submission_id}",
                headers=self._headers(
                    "6.0",
                    {"Gov-Test-Scenario": gov_test_scenario} if gov_test_scenario else None,
                ),
            )
        _raise_for_hmrc_error(resp)
        return _json_or_empty(resp)

    async def amend_foreign_period_summary(
        self,
        nino: str,
        business_id: str,
        tax_year: str,
        submission_id: str,
        body: dict,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """
        PUT /individuals/business/property/foreign/{nino}/{businessId}/period/{taxYear}/{submissionId}
        (Accept v6.0)

        Amend body must NOT include fromDate/toDate.
        """
        async with httpx.AsyncClient() as client:
            resp = await client.put(
                f"{self.base}/individuals/business/property/foreign"
                f"/{nino}/{business_id}/period/{tax_year}/{submission_id}",
                headers=self._headers(
                    "6.0",
                    {
                        "Content-Type": "application/json",
                        **(
                            {"Gov-Test-Scenario": gov_test_scenario}
                            if gov_test_scenario
                            else {}
                        ),
                    },
                ),
                json=body,
            )
        _raise_for_hmrc_error(resp)
        return _json_or_empty(resp)

    # ── Annual Submissions ────────────────────────────────────────────────────────

    async def amend_annual_submission(
        self,
        nino: str,
        business_id: str,
        tax_year: str,
        body: dict,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """
        PUT /individuals/business/property/uk/{nino}/{businessId}/annual/{taxYear}
        (Accept v6.0)

        Creates or amends the annual (end-of-year) allowances and adjustments
        submission. Body: ukProperty for 2025-26+ (ukFhlProperty / ukProperty for earlier).
        """
        async with httpx.AsyncClient() as client:
            resp = await client.put(
                f"{self.base}/individuals/business/property/uk"
                f"/{nino}/{business_id}/annual/{tax_year}",
                headers=self._headers(
                    "6.0",
                    {
                        "Content-Type": "application/json",
                        **(
                            {"Gov-Test-Scenario": gov_test_scenario}
                            if gov_test_scenario
                            else {}
                        ),
                    },
                ),
                json=body,
            )
        _raise_for_hmrc_error(resp)
        return _json_or_empty(resp)

    async def get_annual_submission(
        self,
        nino: str,
        business_id: str,
        tax_year: str,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """
        GET /individuals/business/property/uk/{nino}/{businessId}/annual/{taxYear}
        (Accept v6.0)
        """
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self.base}/individuals/business/property/uk"
                f"/{nino}/{business_id}/annual/{tax_year}",
                headers=self._headers(
                    "6.0",
                    {"Gov-Test-Scenario": gov_test_scenario} if gov_test_scenario else None,
                ),
            )
        _raise_for_hmrc_error(resp)
        return _json_or_empty(resp)

    async def amend_foreign_annual_submission(
        self,
        nino: str,
        business_id: str,
        tax_year: str,
        body: dict,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """
        PUT /individuals/business/property/foreign/{nino}/{businessId}/annual/{taxYear}
        (Accept v6.0)

        Body shapes by tax year:
        - ≤2024-25: foreignFhlEea and/or foreignProperty[{countryCode,...}]
        - 2025-26: foreignProperty[{countryCode,...}]
        - 2026-27+: foreignProperty[{propertyId,...}]
        """
        async with httpx.AsyncClient() as client:
            resp = await client.put(
                f"{self.base}/individuals/business/property/foreign"
                f"/{nino}/{business_id}/annual/{tax_year}",
                headers=self._headers(
                    "6.0",
                    {
                        "Content-Type": "application/json",
                        **(
                            {"Gov-Test-Scenario": gov_test_scenario}
                            if gov_test_scenario
                            else {}
                        ),
                    },
                ),
                json=body,
            )
        _raise_for_hmrc_error(resp)
        return _json_or_empty(resp)

    async def get_foreign_annual_submission(
        self,
        nino: str,
        business_id: str,
        tax_year: str,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """
        GET /individuals/business/property/foreign/{nino}/{businessId}/annual/{taxYear}
        (Accept v6.0)
        """
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self.base}/individuals/business/property/foreign"
                f"/{nino}/{business_id}/annual/{tax_year}",
                headers=self._headers(
                    "6.0",
                    {"Gov-Test-Scenario": gov_test_scenario} if gov_test_scenario else None,
                ),
            )
        _raise_for_hmrc_error(resp)
        return _json_or_empty(resp)

    async def delete_property_annual_submission(
        self,
        nino: str,
        business_id: str,
        tax_year: str,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """
        DELETE /individuals/business/property/{nino}/{businessId}/annual/{taxYear}
        (Accept v6.0)

        Deletes UK or Foreign property annual adjustments/allowances for the tax year.
        Note: path has no uk/foreign segment — shared for both property types.
        """
        async with httpx.AsyncClient() as client:
            resp = await client.delete(
                f"{self.base}/individuals/business/property"
                f"/{nino}/{business_id}/annual/{tax_year}",
                headers=self._headers(
                    "6.0",
                    {"Gov-Test-Scenario": gov_test_scenario} if gov_test_scenario else None,
                ),
            )
        _raise_for_hmrc_error(resp)
        if resp.status_code == 204:
            return {"message": "Property annual submission deleted successfully."}
        return _json_or_empty(resp)

    # ── Historic UK Property (FHL / Non-FHL, tax years 2017-18 to 2021-22) ─────────

    def _historic_headers(
        self,
        gov_test_scenario: Optional[str] = None,
        *,
        with_json: bool = False,
    ) -> dict:
        extra: dict = {}
        if with_json:
            extra["Content-Type"] = "application/json"
        if gov_test_scenario:
            extra["Gov-Test-Scenario"] = gov_test_scenario
        return self._headers("6.0", extra or None)

    async def amend_historic_fhl_annual(
        self,
        nino: str,
        tax_year: str,
        body: dict,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """PUT .../property/uk/annual/furnished-holiday-lettings/{nino}/{taxYear}"""
        async with httpx.AsyncClient() as client:
            resp = await client.put(
                f"{self.base}/individuals/business/property/uk/annual/"
                f"furnished-holiday-lettings/{nino}/{tax_year}",
                headers=self._historic_headers(gov_test_scenario, with_json=True),
                json=body,
            )
        _raise_for_hmrc_error(resp)
        return _json_or_empty(resp)

    async def get_historic_fhl_annual(
        self,
        nino: str,
        tax_year: str,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """GET .../property/uk/annual/furnished-holiday-lettings/{nino}/{taxYear}"""
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self.base}/individuals/business/property/uk/annual/"
                f"furnished-holiday-lettings/{nino}/{tax_year}",
                headers=self._historic_headers(gov_test_scenario),
            )
        _raise_for_hmrc_error(resp)
        return _json_or_empty(resp)

    async def delete_historic_fhl_annual(
        self,
        nino: str,
        tax_year: str,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """DELETE .../property/uk/annual/furnished-holiday-lettings/{nino}/{taxYear}"""
        async with httpx.AsyncClient() as client:
            resp = await client.delete(
                f"{self.base}/individuals/business/property/uk/annual/"
                f"furnished-holiday-lettings/{nino}/{tax_year}",
                headers=self._historic_headers(gov_test_scenario),
            )
        _raise_for_hmrc_error(resp)
        if resp.status_code == 204:
            return {"message": "Historic FHL annual submission deleted successfully."}
        return _json_or_empty(resp)

    async def amend_historic_non_fhl_annual(
        self,
        nino: str,
        tax_year: str,
        body: dict,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """PUT .../property/uk/annual/non-furnished-holiday-lettings/{nino}/{taxYear}"""
        async with httpx.AsyncClient() as client:
            resp = await client.put(
                f"{self.base}/individuals/business/property/uk/annual/"
                f"non-furnished-holiday-lettings/{nino}/{tax_year}",
                headers=self._historic_headers(gov_test_scenario, with_json=True),
                json=body,
            )
        _raise_for_hmrc_error(resp)
        return _json_or_empty(resp)

    async def get_historic_non_fhl_annual(
        self,
        nino: str,
        tax_year: str,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """GET .../property/uk/annual/non-furnished-holiday-lettings/{nino}/{taxYear}"""
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self.base}/individuals/business/property/uk/annual/"
                f"non-furnished-holiday-lettings/{nino}/{tax_year}",
                headers=self._historic_headers(gov_test_scenario),
            )
        _raise_for_hmrc_error(resp)
        return _json_or_empty(resp)

    async def delete_historic_non_fhl_annual(
        self,
        nino: str,
        tax_year: str,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """DELETE .../property/uk/annual/non-furnished-holiday-lettings/{nino}/{taxYear}"""
        async with httpx.AsyncClient() as client:
            resp = await client.delete(
                f"{self.base}/individuals/business/property/uk/annual/"
                f"non-furnished-holiday-lettings/{nino}/{tax_year}",
                headers=self._historic_headers(gov_test_scenario),
            )
        _raise_for_hmrc_error(resp)
        if resp.status_code == 204:
            return {"message": "Historic Non-FHL annual submission deleted successfully."}
        return _json_or_empty(resp)

    async def list_historic_fhl_periods(
        self,
        nino: str,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """GET .../property/uk/period/furnished-holiday-lettings/{nino}"""
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self.base}/individuals/business/property/uk/period/"
                f"furnished-holiday-lettings/{nino}",
                headers=self._historic_headers(gov_test_scenario),
            )
        _raise_for_hmrc_error(resp)
        return _json_or_empty(resp)

    async def create_historic_fhl_period(
        self,
        nino: str,
        body: dict,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """POST .../property/uk/period/furnished-holiday-lettings/{nino}"""
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.base}/individuals/business/property/uk/period/"
                f"furnished-holiday-lettings/{nino}",
                headers=self._historic_headers(gov_test_scenario, with_json=True),
                json=body,
            )
        _raise_for_hmrc_error(resp)
        return _json_or_empty(resp)

    async def get_historic_fhl_period(
        self,
        nino: str,
        period_id: str,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """GET .../property/uk/period/furnished-holiday-lettings/{nino}/{periodId}"""
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self.base}/individuals/business/property/uk/period/"
                f"furnished-holiday-lettings/{nino}/{period_id}",
                headers=self._historic_headers(gov_test_scenario),
            )
        _raise_for_hmrc_error(resp)
        return _json_or_empty(resp)

    async def amend_historic_fhl_period(
        self,
        nino: str,
        period_id: str,
        body: dict,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """PUT .../property/uk/period/furnished-holiday-lettings/{nino}/{periodId}"""
        async with httpx.AsyncClient() as client:
            resp = await client.put(
                f"{self.base}/individuals/business/property/uk/period/"
                f"furnished-holiday-lettings/{nino}/{period_id}",
                headers=self._historic_headers(gov_test_scenario, with_json=True),
                json=body,
            )
        _raise_for_hmrc_error(resp)
        return _json_or_empty(resp)

    async def list_historic_non_fhl_periods(
        self,
        nino: str,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """GET .../property/uk/period/non-furnished-holiday-lettings/{nino}"""
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self.base}/individuals/business/property/uk/period/"
                f"non-furnished-holiday-lettings/{nino}",
                headers=self._historic_headers(gov_test_scenario),
            )
        _raise_for_hmrc_error(resp)
        return _json_or_empty(resp)

    async def create_historic_non_fhl_period(
        self,
        nino: str,
        body: dict,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """POST .../property/uk/period/non-furnished-holiday-lettings/{nino}"""
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.base}/individuals/business/property/uk/period/"
                f"non-furnished-holiday-lettings/{nino}",
                headers=self._historic_headers(gov_test_scenario, with_json=True),
                json=body,
            )
        _raise_for_hmrc_error(resp)
        return _json_or_empty(resp)

    async def get_historic_non_fhl_period(
        self,
        nino: str,
        period_id: str,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """GET .../property/uk/period/non-furnished-holiday-lettings/{nino}/{periodId}"""
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self.base}/individuals/business/property/uk/period/"
                f"non-furnished-holiday-lettings/{nino}/{period_id}",
                headers=self._historic_headers(gov_test_scenario),
            )
        _raise_for_hmrc_error(resp)
        return _json_or_empty(resp)

    async def amend_historic_non_fhl_period(
        self,
        nino: str,
        period_id: str,
        body: dict,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """PUT .../property/uk/period/non-furnished-holiday-lettings/{nino}/{periodId}"""
        async with httpx.AsyncClient() as client:
            resp = await client.put(
                f"{self.base}/individuals/business/property/uk/period/"
                f"non-furnished-holiday-lettings/{nino}/{period_id}",
                headers=self._historic_headers(gov_test_scenario, with_json=True),
                json=body,
            )
        _raise_for_hmrc_error(resp)
        return _json_or_empty(resp)

    # ── UK Property Cumulative Period Summary ─────────────────────────────────────

    async def create_or_amend_uk_property_cumulative(
        self,
        nino: str,
        business_id: str,
        tax_year: str,
        body: dict,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """
        PUT /individuals/business/property/uk/{nino}/{businessId}/cumulative/{taxYear}
        (Accept v6.0, Content-Type application/json)

        Creates or amends a UK property cumulative period summary (income and
        expenses for the full year-to-date within the given tax year).

        The body should follow the HMRC ukFhlProperty / ukProperty schema with
        income and expenses nested inside.  Pass the raw HMRC body shape —
        the route handler validates and forwards it unchanged.

        Postman: Property Business → Income and Expenses Period Summaries →
                 Create or Amend a UK Property Cumulative Period Summary
        """
        async with httpx.AsyncClient() as client:
            resp = await client.put(
                f"{self.base}/individuals/business/property/uk"
                f"/{nino}/{business_id}/cumulative/{tax_year}",
                headers=self._headers(
                    "6.0",
                    {
                        "Content-Type": "application/json",
                        **(
                            {"Gov-Test-Scenario": gov_test_scenario}
                            if gov_test_scenario
                            else {}
                        ),
                    },
                ),
                json=body,
            )
        _raise_for_hmrc_error(resp)
        # HMRC returns 204 No Content on success for this endpoint
        if resp.status_code == 204:
            return {"message": "Cumulative period summary created/amended successfully."}
        return _json_or_empty(resp)

    async def retrieve_uk_property_cumulative(
        self,
        nino: str,
        business_id: str,
        tax_year: str,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """
        GET /individuals/business/property/uk/{nino}/{businessId}/cumulative/{taxYear}
        (Accept v6.0)

        Retrieves the current cumulative period summary (income and expenses
        year-to-date) for a UK property business.

        Postman: Property Business → Income and Expenses Period Summaries →
                 Retrieve a UK Property Cumulative Period Summary
        """
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self.base}/individuals/business/property/uk"
                f"/{nino}/{business_id}/cumulative/{tax_year}",
                headers=self._headers(
                    "6.0",
                    {"Gov-Test-Scenario": gov_test_scenario} if gov_test_scenario else None,
                ),
            )
        _raise_for_hmrc_error(resp)
        return _json_or_empty(resp)

    # ── Foreign Property Details (from 2026-27) ───────────────────────────────────

    async def create_foreign_property_details(
        self,
        nino: str,
        business_id: str,
        tax_year: str,
        body: dict,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """
        POST /individuals/business/property/foreign/{nino}/{businessId}/details/{taxYear}
        (Accept v6.0)

        Creates a foreign property details record. Returns {"propertyId": "<uuid>"}.
        Tax year 2026-27 onwards only.
        """
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.base}/individuals/business/property/foreign"
                f"/{nino}/{business_id}/details/{tax_year}",
                headers=self._headers(
                    "6.0",
                    {
                        "Content-Type": "application/json",
                        **(
                            {"Gov-Test-Scenario": gov_test_scenario}
                            if gov_test_scenario
                            else {}
                        ),
                    },
                ),
                json=body,
            )
        _raise_for_hmrc_error(resp)
        return _json_or_empty(resp)

    async def retrieve_foreign_property_details(
        self,
        nino: str,
        business_id: str,
        tax_year: str,
        property_id: Optional[str] = None,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """
        GET /individuals/business/property/foreign/{nino}/{businessId}/details/{taxYear}
        (Accept v6.0)

        Optional propertyId query filter. Tax year 2026-27 onwards.
        """
        params: dict = {}
        if property_id:
            params["propertyId"] = property_id
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self.base}/individuals/business/property/foreign"
                f"/{nino}/{business_id}/details/{tax_year}",
                headers=self._headers(
                    "6.0",
                    {"Gov-Test-Scenario": gov_test_scenario} if gov_test_scenario else None,
                ),
                params=params or None,
            )
        _raise_for_hmrc_error(resp)
        return _json_or_empty(resp)

    async def update_foreign_property_details(
        self,
        nino: str,
        property_id: str,
        tax_year: str,
        body: dict,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """
        PUT /individuals/business/property/foreign/{nino}/details/{propertyId}/{taxYear}
        (Accept v6.0)

        Note: no businessId in this HMRC path. Tax year 2026-27 onwards.
        """
        async with httpx.AsyncClient() as client:
            resp = await client.put(
                f"{self.base}/individuals/business/property/foreign"
                f"/{nino}/details/{property_id}/{tax_year}",
                headers=self._headers(
                    "6.0",
                    {
                        "Content-Type": "application/json",
                        **(
                            {"Gov-Test-Scenario": gov_test_scenario}
                            if gov_test_scenario
                            else {}
                        ),
                    },
                ),
                json=body,
            )
        _raise_for_hmrc_error(resp)
        if resp.status_code == 204:
            return {"message": "Foreign property details updated successfully."}
        return _json_or_empty(resp)

    # ── Foreign Property Cumulative Period Summary ────────────────────────────────

    async def create_or_amend_foreign_property_cumulative(
        self,
        nino: str,
        business_id: str,
        tax_year: str,
        body: dict,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """
        PUT /individuals/business/property/foreign/{nino}/{businessId}/cumulative/{taxYear}
        (Accept v6.0)

        Creates or amends a foreign property cumulative period summary.
        Tax year 2025-26 onwards. For 2026-27+, body entries need propertyId.
        """
        async with httpx.AsyncClient() as client:
            resp = await client.put(
                f"{self.base}/individuals/business/property/foreign"
                f"/{nino}/{business_id}/cumulative/{tax_year}",
                headers=self._headers(
                    "6.0",
                    {
                        "Content-Type": "application/json",
                        **(
                            {"Gov-Test-Scenario": gov_test_scenario}
                            if gov_test_scenario
                            else {}
                        ),
                    },
                ),
                json=body,
            )
        _raise_for_hmrc_error(resp)
        if resp.status_code == 204:
            return {"message": "Foreign property cumulative period summary created/amended successfully."}
        return _json_or_empty(resp)

    async def retrieve_foreign_property_cumulative(
        self,
        nino: str,
        business_id: str,
        tax_year: str,
        property_id: Optional[str] = None,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """
        GET /individuals/business/property/foreign/{nino}/{businessId}/cumulative/{taxYear}
        (Accept v6.0)

        Optional propertyId query param (required for tax years 2026-27+).
        """
        params: dict = {}
        if property_id:
            params["propertyId"] = property_id
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self.base}/individuals/business/property/foreign"
                f"/{nino}/{business_id}/cumulative/{tax_year}",
                headers=self._headers(
                    "6.0",
                    {"Gov-Test-Scenario": gov_test_scenario} if gov_test_scenario else None,
                ),
                params=params or None,
            )
        _raise_for_hmrc_error(resp)
        return _json_or_empty(resp)

    # ── Self-Employment Cumulative Period Summary ──────────────────────────────────

    async def create_or_amend_self_employment_cumulative(
        self,
        nino: str,
        business_id: str,
        tax_year: str,
        body: dict,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """
        PUT /individuals/business/self-employment/{nino}/{businessId}/cumulative/{taxYear}
        (Accept v5.0, Content-Type application/json)

        Creates or amends a self-employment cumulative period summary.

        The body must contain:
          periodDates:    { periodStartDate, periodEndDate }
          periodIncome:   { turnover, other }
          periodExpenses: { costOfGoods, paymentsToSubcontractors, wagesAndStaffCosts,
                            carVanTravelExpenses, premisesRunningCosts, maintenanceCosts,
                            adminCosts, businessEntertainmentCosts, advertisingCosts,
                            interestOnBankOtherLoans }

        All amounts are cumulative year-to-date (not quarter-only).

        Postman: Self Employment Business (MTD) → Self-Employment Cumulative Period Summary →
                 Create or Amend a Self-Employment Cumulative Period Summary
        """
        async with httpx.AsyncClient() as client:
            resp = await client.put(
                f"{self.base}/individuals/business/self-employment"
                f"/{nino}/{business_id}/cumulative/{tax_year}",
                headers=self._headers(
                    "5.0",
                    {
                        "Content-Type": "application/json",
                        **(
                            {"Gov-Test-Scenario": gov_test_scenario}
                            if gov_test_scenario
                            else {}
                        ),
                    },
                ),
                json=body,
            )
        _raise_for_hmrc_error(resp)
        if resp.status_code == 204:
            return {"message": "Self-employment cumulative period summary created/amended successfully."}
        return _json_or_empty(resp)

    async def retrieve_self_employment_cumulative(
        self,
        nino: str,
        business_id: str,
        tax_year: str,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """
        GET /individuals/business/self-employment/{nino}/{businessId}/cumulative/{taxYear}
        (Accept v5.0)

        Retrieves the current self-employment cumulative period summary for the
        given tax year.

        Postman: Self Employment Business (MTD) → Self-Employment Cumulative Period Summary →
                 Retrieve a Self-Employment Cumulative Period Summary
        """
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self.base}/individuals/business/self-employment"
                f"/{nino}/{business_id}/cumulative/{tax_year}",
                headers=self._headers(
                    "5.0",
                    {"Gov-Test-Scenario": gov_test_scenario} if gov_test_scenario else None,
                ),
            )
        _raise_for_hmrc_error(resp)
        return _json_or_empty(resp)

    # ── Self-Employment Annual Submission ─────────────────────────────────────────

    async def amend_self_employment_annual(
        self,
        nino: str,
        business_id: str,
        tax_year: str,
        body: dict,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """
        PUT /individuals/business/self-employment/{nino}/{businessId}/annual/{taxYear}
        (Accept v5.0)

        Creates or amends the self-employment annual submission (adjustments & allowances).
        """
        async with httpx.AsyncClient() as client:
            resp = await client.put(
                f"{self.base}/individuals/business/self-employment"
                f"/{nino}/{business_id}/annual/{tax_year}",
                headers=self._headers(
                    "5.0",
                    {
                        "Content-Type": "application/json",
                        **(
                            {"Gov-Test-Scenario": gov_test_scenario}
                            if gov_test_scenario
                            else {}
                        ),
                    },
                ),
                json=body,
            )
        _raise_for_hmrc_error(resp)
        if resp.status_code == 204:
            return {"message": "Self-employment annual submission created/amended successfully."}
        return _json_or_empty(resp)

    async def get_self_employment_annual(
        self,
        nino: str,
        business_id: str,
        tax_year: str,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """
        GET /individuals/business/self-employment/{nino}/{businessId}/annual/{taxYear}
        (Accept v5.0)
        """
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self.base}/individuals/business/self-employment"
                f"/{nino}/{business_id}/annual/{tax_year}",
                headers=self._headers(
                    "5.0",
                    {"Gov-Test-Scenario": gov_test_scenario} if gov_test_scenario else None,
                ),
            )
        _raise_for_hmrc_error(resp)
        return _json_or_empty(resp)

    async def delete_self_employment_annual(
        self,
        nino: str,
        business_id: str,
        tax_year: str,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """
        DELETE /individuals/business/self-employment/{nino}/{businessId}/annual/{taxYear}
        (Accept v5.0)
        """
        async with httpx.AsyncClient() as client:
            resp = await client.delete(
                f"{self.base}/individuals/business/self-employment"
                f"/{nino}/{business_id}/annual/{tax_year}",
                headers=self._headers(
                    "5.0",
                    {"Gov-Test-Scenario": gov_test_scenario} if gov_test_scenario else None,
                ),
            )
        _raise_for_hmrc_error(resp)
        if resp.status_code == 204:
            return {"message": "Self-employment annual submission deleted successfully."}
        return _json_or_empty(resp)

    # ── Self-Employment Period Summaries (tax years ≤ 2024-25) ─────────────────────

    async def create_self_employment_period(
        self,
        nino: str,
        business_id: str,
        body: dict,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """
        POST /individuals/business/self-employment/{nino}/{businessId}/period
        (Accept v5.0)

        Creates a periodic summary. Tax year is inferred from periodDates in the body.
        Only for tax years 2024-25 or earlier (use cumulative endpoints from 2025-26).
        Returns {"periodId": "YYYY-MM-DD_YYYY-MM-DD"}.
        """
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{self.base}/individuals/business/self-employment"
                f"/{nino}/{business_id}/period",
                headers=self._headers(
                    "5.0",
                    {
                        "Content-Type": "application/json",
                        **(
                            {"Gov-Test-Scenario": gov_test_scenario}
                            if gov_test_scenario
                            else {}
                        ),
                    },
                ),
                json=body,
            )
        _raise_for_hmrc_error(resp)
        return _json_or_empty(resp)

    async def list_self_employment_periods(
        self,
        nino: str,
        business_id: str,
        tax_year: str,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """
        GET /individuals/business/self-employment/{nino}/{businessId}/period/{taxYear}
        (Accept v5.0)
        """
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self.base}/individuals/business/self-employment"
                f"/{nino}/{business_id}/period/{tax_year}",
                headers=self._headers(
                    "5.0",
                    {"Gov-Test-Scenario": gov_test_scenario} if gov_test_scenario else None,
                ),
            )
        _raise_for_hmrc_error(resp)
        return _json_or_empty(resp)

    async def retrieve_self_employment_period(
        self,
        nino: str,
        business_id: str,
        tax_year: str,
        period_id: str,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """
        GET /individuals/business/self-employment/{nino}/{businessId}/period/{taxYear}/{periodId}
        (Accept v5.0)
        """
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{self.base}/individuals/business/self-employment"
                f"/{nino}/{business_id}/period/{tax_year}/{period_id}",
                headers=self._headers(
                    "5.0",
                    {"Gov-Test-Scenario": gov_test_scenario} if gov_test_scenario else None,
                ),
            )
        _raise_for_hmrc_error(resp)
        return _json_or_empty(resp)

    async def amend_self_employment_period(
        self,
        nino: str,
        business_id: str,
        tax_year: str,
        period_id: str,
        body: dict,
        gov_test_scenario: Optional[str] = None,
    ) -> dict:
        """
        PUT /individuals/business/self-employment/{nino}/{businessId}/period/{taxYear}/{periodId}
        (Accept v5.0)
        """
        async with httpx.AsyncClient() as client:
            resp = await client.put(
                f"{self.base}/individuals/business/self-employment"
                f"/{nino}/{business_id}/period/{tax_year}/{period_id}",
                headers=self._headers(
                    "5.0",
                    {
                        "Content-Type": "application/json",
                        **(
                            {"Gov-Test-Scenario": gov_test_scenario}
                            if gov_test_scenario
                            else {}
                        ),
                    },
                ),
                json=body,
            )
        _raise_for_hmrc_error(resp)
        if resp.status_code == 204:
            return {"message": "Self-employment period summary amended successfully."}
        return _json_or_empty(resp)

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
        return _json_or_empty(resp)
