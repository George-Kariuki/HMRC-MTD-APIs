"""
routes.py — FastAPI route handlers for the HMRC MTD Property Landlord backend.

All endpoints are designed to be called directly by Adalo via its External
Collections / API Request actions.  No OAuth logic is exposed here — the
frontend only ever needs to store a session_id and pass it as X-Session-ID.

Authentication model:
  1. Adalo opens GET /auth/login-url → receives {"auth_url": "..."}
  2. User's browser completes the HMRC login and lands on /auth/callback
  3. Callback returns {"session_id": "..."} → Adalo stores this
  4. Every subsequent call includes header:  X-Session-ID: <session_id>
  5. User calls POST /auth/set-nino to associate their NINO with the session
"""

from typing import Optional

from fastapi import APIRouter, Body, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field

from auth import get_valid_access_token
from database import get_tokens, update_nino
from hmrc_client import (
    HMRCClient,
    assert_tax_year_at_least,
    derive_tax_year,
    tax_year_start_year,
)

router = APIRouter()


# ── Shared helpers ────────────────────────────────────────────────────────────────

def _require_session(x_session_id: Optional[str]) -> str:
    """Validate that the caller provided an X-Session-ID header."""
    if not x_session_id:
        raise HTTPException(
            status_code=401,
            detail="Missing X-Session-ID header. Authenticate first via /auth/login-url.",
        )
    return x_session_id


def _require_nino(session_id: str) -> tuple[dict, str]:
    """Load token record and ensure a NINO is associated with the session."""
    tokens = get_tokens(session_id)
    if not tokens:
        raise HTTPException(status_code=401, detail="Invalid session_id.")
    if not tokens.get("nino"):
        raise HTTPException(
            status_code=400,
            detail="NINO not set for this session. Call POST /auth/set-nino first.",
        )
    return tokens, tokens["nino"]


def _client_ip(request: Request) -> str:
    """
    Extract the originating public IP.
    Respects X-Forwarded-For from Vercel / reverse proxies.
    This IP is used in the Gov-Client-Public-IP fraud prevention header.
    """
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


async def _build_client(request: Request, session_id: str) -> HMRCClient:
    """
    Create a ready-to-use HMRCClient for the current request.
    Transparently refreshes the access token if it is about to expire.
    """
    access_token = await get_valid_access_token(session_id)
    tokens = get_tokens(session_id)
    user_id = tokens.get("nino", "none") if tokens else "none"
    return HMRCClient(
        access_token=access_token,
        client_ip=_client_ip(request),
        user_id=user_id,
    )


# ── Auth: NINO binding ────────────────────────────────────────────────────────────

class SetNinoRequest(BaseModel):
    nino: str = Field(..., description="UK National Insurance Number, e.g. AA123456A")


@router.post("/auth/set-nino", tags=["Auth"])
async def set_nino(
    payload: SetNinoRequest,
    x_session_id: Optional[str] = Header(None),
):
    """
    Associate the user's NINO with their session.

    Call this once after a successful /auth/callback.
    Adalo should present a form asking for the NINO before making any
    business/obligation/submission calls.
    """
    session_id = _require_session(x_session_id)
    tokens = get_tokens(session_id)
    if not tokens:
        raise HTTPException(status_code=401, detail="Invalid session_id.")
    update_nino(session_id, payload.nino.strip().upper())
    return {"message": "NINO saved successfully.", "nino": payload.nino.strip().upper()}


# ── Business Details ──────────────────────────────────────────────────────────────

@router.get("/business-details", tags=["Business Details"])
async def business_details(
    request: Request,
    x_session_id: Optional[str] = Header(None),
):
    """
    List all income sources for the authenticated user.

    Returns HMRC's `listOfBusinesses` unchanged so every `businessId` is visible.
    `propertyBusinesses` is a subset for uk-property / FHL / foreign-property only —
    sandbox test users often have only `self-employment`, so that list can be empty
    even when `listOfBusinesses` has entries.

    HMRC endpoint:  GET /individuals/business/details/{nino}/list  (v2.0)
    """
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)

    client = await _build_client(request, session_id)
    data = await client.list_businesses(nino)

    all_businesses = data.get("listOfBusinesses", [])

    # Property-only subset (periodic property submissions need a uk-property business)
    property_types = {"uk-property", "uk-property-fhl", "foreign-property"}
    property_businesses = [
        {
            "businessId":       b.get("businessId"),
            "typeOfBusiness":   b.get("typeOfBusiness"),
            "tradingName":      b.get("tradingName"),
            "commencementDate": b.get("commencementDate"),
        }
        for b in all_businesses
        if b.get("typeOfBusiness") in property_types
    ]

    return {
        "nino":               nino,
        # Passthrough from HMRC — use this for businessId in all cases
        "listOfBusinesses":   all_businesses,
        "propertyBusinesses": property_businesses,
        "totalBusinesses":    len(all_businesses),
    }


# ── Obligations ───────────────────────────────────────────────────────────────────

@router.get("/obligations", tags=["Obligations"])
async def obligations(
    request: Request,
    x_session_id: Optional[str] = Header(None),
    type_of_business: Optional[str] = Query(
        None,
        alias="typeOfBusiness",
        description=(
            "HMRC: typeOfBusiness. Filters by income source type. "
            "Accepted: `self-employment`, `uk-property`, `foreign-property`. "
            "Required by HMRC if `businessId` is supplied."
        ),
    ),
    business_id: Optional[str] = Query(
        None,
        alias="businessId",
        description="HMRC: businessId. Income source id from Business Details (e.g. XAIS…).",
    ),
    from_date: Optional[str] = Query(
        None,
        alias="fromDate",
        description="HMRC: fromDate. Start date YYYY-MM-DD. Mandatory if `toDate` is set; max 366-day range with toDate.",
    ),
    to_date: Optional[str] = Query(
        None,
        alias="toDate",
        description="HMRC: toDate. End date YYYY-MM-DD. Mandatory if `fromDate` is set.",
    ),
    status: Optional[str] = Query(
        None,
        description=(
            "HMRC: status. `open` or `fulfilled` (case-insensitive). "
            "Omit this query parameter entirely to return obligations of both statuses."
        ),
    ),
):
    """
    Retrieve income & expenditure obligations for the authenticated user.

    Mirrors HMRC query parameters (also exposed under camelCase aliases for tools
    that match the official API). NINO comes from the session (`POST /auth/set-nino`).

    The periodStartDate and periodEndDate in each obligation MUST be passed
    as start_date / end_date when calling POST /submit-periodic.

    HMRC endpoint:  GET /obligations/details/{nino}/income-and-expenditure  (v3.0)
    """
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)

    if (from_date or to_date) and not (from_date and to_date):
        raise HTTPException(
            status_code=400,
            detail="fromDate and toDate must both be supplied together (HMRC rule).",
        )
    if business_id and not (type_of_business and type_of_business.strip()):
        raise HTTPException(
            status_code=400,
            detail="typeOfBusiness is required when businessId is provided (HMRC rule).",
        )

    client = await _build_client(request, session_id)
    data = await client.get_obligations(
        nino=nino,
        status=status,
        type_of_business=type_of_business,
        business_id=business_id,
        from_date=from_date,
        to_date=to_date,
    )

    raw_obligations = data.get("obligations", [])

    # Flatten into a simple list for easy consumption by Adalo
    flat_obligations = []
    for ob in raw_obligations:
        for detail in ob.get("obligationDetails", []):
            start = detail.get("periodStartDate", "")
            end   = detail.get("periodEndDate",   "")
            flat_obligations.append({
                "businessId":      ob.get("businessId"),
                "typeOfBusiness":  ob.get("typeOfBusiness"),
                "periodStartDate": start,
                "periodEndDate":   end,
                "dueDate":         detail.get("dueDate"),
                "status":          detail.get("status"),
                "taxYear":         derive_tax_year(start) if start else None,
            })

    return {
        "nino": nino,
        "query": {
            "typeOfBusiness": type_of_business,
            "businessId":     business_id,
            "fromDate":       from_date,
            "toDate":         to_date,
            "status":         status,
        },
        "obligations": flat_obligations,
        "count":       len(flat_obligations),
    }


@router.get("/obligations/final-declaration", tags=["Obligations"])
async def final_declaration_obligations(
    request: Request,
    x_session_id: Optional[str] = Header(None),
    tax_year: Optional[str] = Query(
        None,
        alias="taxYear",
        description=(
            "HMRC tax year e.g. '2025-26'. "
            "Omit to return obligations from 4 years before the current tax year."
        ),
    ),
    status: Optional[str] = Query(
        None,
        description=(
            "HMRC: status. `open` or `fulfilled` (case-insensitive). "
            "Omit to return obligations of both statuses."
        ),
    ),
    gov_test_scenario: Optional[str] = Query(
        None,
        alias="govTestScenario",
        description="Sandbox-only. Sets HMRC Gov-Test-Scenario header. Omit in production.",
    ),
):
    """
    Retrieve Income Tax (Self Assessment) Final Declaration obligations.

    Formerly called crystallisation obligations. NINO comes from the session.

    HMRC endpoint:  GET /obligations/details/{nino}/crystallisation  (v3.0)
    """
    session_id = _require_session(x_session_id)
    _tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)
    data = await client.get_final_declaration_obligations(
        nino=nino,
        tax_year=tax_year,
        status=status,
        gov_test_scenario=gov_test_scenario,
    )

    raw_obligations = data.get("obligations", [])
    flat_obligations = []
    for detail in raw_obligations:
        start = detail.get("periodStartDate", "")
        end = detail.get("periodEndDate", "")
        flat_obligations.append({
            "periodStartDate": start,
            "periodEndDate":   end,
            "dueDate":         detail.get("dueDate"),
            "status":          detail.get("status"),
            "receivedDate":    detail.get("receivedDate"),
            "taxYear":         derive_tax_year(start) if start else None,
        })

    return {
        "nino": nino,
        "query": {
            "taxYear": tax_year,
            "status":  status,
        },
        "obligations": flat_obligations,
        "count":       len(flat_obligations),
    }


# ── Periodic Submission ───────────────────────────────────────────────────────────

class PeriodicAmountsBody(BaseModel):
    """Income and expense amounts for a UK property periodic submission (all YTD)."""

    # ── Income ───────────────────────────────────────────────────────────────────
    rent_income:              float = Field(0.0,  description="Total rental income (YTD)")
    premiums_of_lease_grant:  float = Field(0.0,  description="Premiums of lease grant (YTD)")
    reverse_premiums:         float = Field(0.0,  description="Reverse premiums (YTD)")
    other_income:             float = Field(0.0,  description="Other property income (YTD)")
    tax_deducted:             float = Field(0.0,  description="Tax already deducted at source (YTD)")

    # ── Expenses ─────────────────────────────────────────────────────────────────
    premises_running_costs:    float = Field(0.0, description="Premises running costs (YTD)")
    repairs_and_maintenance:   float = Field(0.0, description="Repairs and maintenance (YTD)")
    financial_costs:           float = Field(0.0, description="Financial costs / mortgage interest (YTD)")
    professional_fees:         float = Field(0.0, description="Professional fees (YTD)")
    cost_of_services:          float = Field(0.0, description="Cost of services (YTD)")
    other_expenses:            float = Field(0.0, description="Other allowable expenses (YTD)")
    residential_financial_cost: float = Field(0.0, description="Residential financial cost (YTD)")
    travel_costs:              float = Field(0.0, description="Travel costs (YTD)")


@router.post("/submit-periodic", tags=["Property Business — Period Summaries"])
async def submit_periodic(
    amounts: PeriodicAmountsBody,
    request: Request,
    x_session_id: Optional[str] = Header(None),
    business_id: str = Query(
        ...,
        alias="businessId",
        description="businessId from GET /business-details (e.g. XAIS12345678901)",
    ),
    start_date: str = Query(
        ...,
        alias="startDate",
        description="Period start YYYY-MM-DD — must match obligation periodStartDate",
    ),
    end_date: str = Query(
        ...,
        alias="endDate",
        description="Period end YYYY-MM-DD — must match obligation periodEndDate",
    ),
    tax_year: Optional[str] = Query(
        None,
        alias="taxYear",
        description="HMRC tax year e.g. '2024-25'. Auto-derived from startDate if omitted.",
    ),
    property_type: str = Query(
        "ukNonFhlProperty",
        alias="propertyType",
        description="'ukNonFhlProperty' (standard BTL) or 'ukFhlProperty' (FHL)",
    ),
    submission_id: Optional[str] = Query(
        None,
        alias="submissionId",
        description="Provide to amend an existing submission. Omit to create a new one.",
    ),
):
    """
    Create or amend a cumulative year-to-date UK property income & expense return.

    **Routing parameters** (shown above): businessId, startDate, endDate, taxYear, propertyType, submissionId.
    **Financial amounts** (in the request body): all income and expense figures — all cumulative YTD.

    Workflow:
      1. `GET /obligations` → copy `periodStartDate` → `startDate`, `periodEndDate` → `endDate`
      2. Fill in all YTD income and expense totals in the request body
      3. No submissionId → creates new; provide submissionId → amends existing

    HMRC endpoint (create): POST /individuals/business/property/uk/{nino}/{bid}/period/{ty}  (v6.0)
    HMRC endpoint (amend):  PUT  /individuals/business/property/uk/{nino}/{bid}/period/{ty}/{sid}  (v6.0)
    """
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)

    resolved_tax_year = tax_year or derive_tax_year(start_date)

    income = {
        "periodAmount":         round(amounts.rent_income, 2),
        "premiumsOfLeaseGrant": round(amounts.premiums_of_lease_grant, 2),
        "reversePremiums":      round(amounts.reverse_premiums, 2),
        "otherIncome":          round(amounts.other_income, 2),
        "taxDeducted":          round(amounts.tax_deducted, 2),
    }
    expenses = {
        "premisesRunningCosts":     round(amounts.premises_running_costs, 2),
        "repairsAndMaintenance":    round(amounts.repairs_and_maintenance, 2),
        "financialCosts":           round(amounts.financial_costs, 2),
        "professionalFees":         round(amounts.professional_fees, 2),
        "costOfServices":           round(amounts.cost_of_services, 2),
        "other":                    round(amounts.other_expenses, 2),
        "residentialFinancialCost": round(amounts.residential_financial_cost, 2),
        "travelCosts":              round(amounts.travel_costs, 2),
    }

    client = await _build_client(request, session_id)

    if submission_id:
        result = await client.amend_period_summary(
            nino=nino,
            business_id=business_id,
            tax_year=resolved_tax_year,
            submission_id=submission_id,
            from_date=start_date,
            to_date=end_date,
            income=income,
            expenses=expenses,
            property_type=property_type,
        )
        action = "amended"
    else:
        result = await client.create_period_summary(
            nino=nino,
            business_id=business_id,
            tax_year=resolved_tax_year,
            from_date=start_date,
            to_date=end_date,
            income=income,
            expenses=expenses,
            property_type=property_type,
        )
        action = "created"

    return {
        "success":    True,
        "action":     action,
        "taxYear":    resolved_tax_year,
        "fromDate":   start_date,
        "toDate":     end_date,
        "businessId": business_id,
        "result":     result,
    }


# ── Business Details — retrieve single business + periods of account ───────────────

@router.get("/business-details/{business_id}", tags=["Business Details"])
async def retrieve_business(
    business_id: str,
    request: Request,
    x_session_id: Optional[str] = Header(None),
):
    """
    Retrieve the full details of a single income source by its businessId.

    Use this after GET /business-details (list all) to inspect a specific business:
    commencementDate, latencyDetails, etc.  For accounting type use
    GET /business-details/{businessId}/accounting-type?taxYear=.

    HMRC endpoint:  GET /individuals/business/details/{nino}/{businessId}  (v2.0)
    """
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)
    data = await client.retrieve_business(nino, business_id)
    return {"nino": nino, "businessId": business_id, **data}


@router.get("/business-details/{business_id}/periods-of-account", tags=["Business Details — Periods of Account"])
async def periods_of_account(
    business_id: str,
    request: Request,
    x_session_id: Optional[str] = Header(None),
    tax_year: str = Query(
        ...,
        alias="taxYear",
        description="HMRC tax year e.g. '2024-25'",
    ),
):
    """
    Retrieve the accounting periods available for a business in a given tax year.

    Use the period start and end dates returned here as the valid fromDate / toDate
    boundaries when calling PUT /property-cumulative or PUT /self-employment-cumulative.

    HMRC endpoint:
        GET /individuals/business/details/{nino}/{businessId}/{taxYear}/periods-of-account  (v2.0)
    """
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)
    data = await client.retrieve_periods_of_account(nino, business_id, tax_year)
    return {
        "nino":       nino,
        "businessId": business_id,
        "taxYear":    tax_year,
        **data,
    }


HMRC_PERIODS_OF_ACCOUNT_EXAMPLE = {
    "periodsOfAccount": True,
    "periodsOfAccountDates": [
        {
            "startDate": "2025-04-06",
            "endDate": "2026-04-05",
        }
    ],
}


@router.get("/business-details/{business_id}/accounting-type", tags=["Business Details — Accounting Type"])
async def get_accounting_type(
    business_id: str,
    request: Request,
    x_session_id: Optional[str] = Header(None),
    tax_year: str = Query(
        ...,
        alias="taxYear",
        description="HMRC tax year e.g. '2025-26' (minimum 2025-26 in production)",
    ),
    gov_test_scenario: Optional[str] = Query(
        None,
        alias="govTestScenario",
        description="Sandbox-only. Sets HMRC Gov-Test-Scenario header. Omit in production.",
    ),
):
    """
    Retrieve the accounting type (CASH or ACCRUALS) for a business in a tax year.

    HMRC removed `accountingType` from Retrieve Business Details — use this endpoint
    as the source of truth.

    HMRC endpoint:
        GET /individuals/business/details/{nino}/{businessId}/{taxYear}/accounting-type  (v2.0)
    """
    assert_tax_year_at_least(tax_year)
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)
    data = await client.retrieve_accounting_type(
        nino=nino,
        business_id=business_id,
        tax_year=tax_year,
        gov_test_scenario=gov_test_scenario,
    )
    return {
        "nino":       nino,
        "businessId": business_id,
        "taxYear":    tax_year,
        **data,
    }


@router.put("/business-details/{business_id}/accounting-type", tags=["Business Details — Accounting Type"])
async def update_accounting_type(
    business_id: str,
    request: Request,
    body: dict = Body(
        ...,
        description='HMRC body: {"accountingType": "CASH" | "ACCRUALS"}',
        openapi_examples={
            "cash": {
                "summary": "Cash basis",
                "value": {"accountingType": "CASH"},
            },
            "accruals": {
                "summary": "Accruals basis",
                "value": {"accountingType": "ACCRUALS"},
            },
        },
    ),
    x_session_id: Optional[str] = Header(None),
    tax_year: str = Query(
        ...,
        alias="taxYear",
        description="HMRC tax year e.g. '2025-26' (minimum 2025-26 in production)",
    ),
    gov_test_scenario: Optional[str] = Query(
        None,
        alias="govTestScenario",
        description="Sandbox-only. Sets HMRC Gov-Test-Scenario header. Omit in production.",
    ),
):
    """
    Create or update the accounting type for a business in a tax year.

    In-year updates are allowed in production (June 2026 changelog — HMRC removed
    `RULE_TAX_YEAR_NOT_ENDED` on this endpoint).

    HMRC endpoint:
        PUT /individuals/business/details/{nino}/{businessId}/{taxYear}/accounting-type  (v2.0)
    """
    assert_tax_year_at_least(tax_year)
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)
    result = await client.update_accounting_type(
        nino=nino,
        business_id=business_id,
        tax_year=tax_year,
        body=body,
        gov_test_scenario=gov_test_scenario,
    )
    return {
        "success":    True,
        "businessId": business_id,
        "taxYear":    tax_year,
        "result":     result,
    }


@router.put("/business-details/{business_id}/periods-of-account", tags=["Business Details — Periods of Account"])
async def update_periods_of_account(
    business_id: str,
    request: Request,
    body: dict = Body(
        ...,
        description="HMRC periods-of-account body (periodsOfAccount boolean + periodsOfAccountDates array).",
        openapi_examples={
            "hmrc_example": {
                "summary": "Single period of account",
                "value": HMRC_PERIODS_OF_ACCOUNT_EXAMPLE,
            }
        },
    ),
    x_session_id: Optional[str] = Header(None),
    tax_year: str = Query(
        ...,
        alias="taxYear",
        description="HMRC tax year e.g. '2025-26'",
    ),
    gov_test_scenario: Optional[str] = Query(
        None,
        alias="govTestScenario",
        description="Sandbox-only. Sets HMRC Gov-Test-Scenario header. Omit in production.",
    ),
):
    """
    Create or update the periods of account for a business in a given tax year.

    Pair with GET /business-details/{businessId}/periods-of-account to read back
    the periods after updating.

    HMRC endpoint:
        PUT /individuals/business/details/{nino}/{businessId}/{taxYear}/periods-of-account  (v2.0)
    """
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)
    result = await client.create_or_update_periods_of_account(
        nino=nino,
        business_id=business_id,
        tax_year=tax_year,
        body=body,
        gov_test_scenario=gov_test_scenario,
    )
    return {
        "success":    True,
        "businessId": business_id,
        "taxYear":    tax_year,
        "result":     result,
    }


@router.put(
    "/business-details/{business_id}/quarterly-period-type",
    tags=["Business Details"],
)
async def create_amend_quarterly_period_type(
    business_id: str,
    request: Request,
    body: dict = Body(
        ...,
        description='HMRC body: {"quarterlyPeriodType": "standard" | "calendar"}',
        openapi_examples={
            "standard": {
                "summary": "Standard quarters (6 Apr – 5 Jul first period)",
                "value": {"quarterlyPeriodType": "standard"},
            },
            "calendar": {
                "summary": "Calendar quarters (1 Apr – 30 Jun first period)",
                "value": {"quarterlyPeriodType": "calendar"},
            },
        },
    ),
    x_session_id: Optional[str] = Header(None),
    tax_year: str = Query(
        ...,
        alias="taxYear",
        description="HMRC tax year e.g. '2025-26' (current tax year only)",
    ),
    gov_test_scenario: Optional[str] = Query(
        None,
        alias="govTestScenario",
        description="Sandbox-only. Sets HMRC Gov-Test-Scenario header. Omit in production.",
    ),
):
    """
    Create or amend the quarterly period type for a business in a tax year.

    Cannot be changed after a submission has been made for that year.

    HMRC endpoint:
        PUT /individuals/business/details/{nino}/{businessId}/{taxYear}  (v2.0)
    """
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)
    result = await client.create_amend_quarterly_period_type(
        nino=nino,
        business_id=business_id,
        tax_year=tax_year,
        body=body,
        gov_test_scenario=gov_test_scenario,
    )
    return {
        "success":    True,
        "businessId": business_id,
        "taxYear":    tax_year,
        "result":     result,
    }


# ── Business Details — Late Accounting Date Rule ───────────────────────────────────

@router.get(
    "/business-details/{business_id}/late-accounting-date-rule-election",
    tags=["Business Details — Late Accounting Date Rule"],
)
async def get_late_accounting_date_rule(
    business_id: str,
    request: Request,
    x_session_id: Optional[str] = Header(None),
    tax_year: str = Query(
        ...,
        alias="taxYear",
        description="HMRC tax year e.g. '2024-25' (self-employment businessId only)",
    ),
    gov_test_scenario: Optional[str] = Query(
        None,
        alias="govTestScenario",
        description="Sandbox-only. Sets HMRC Gov-Test-Scenario header. Omit in production.",
    ),
):
    """
    Retrieve the Late Accounting Date Rule election for a self-employment business.

    HMRC endpoint:
        GET /individuals/business/details/{nino}/{businessId}/{taxYear}/late-accounting-date-rule-election  (v2.0)
    """
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)
    data = await client.retrieve_late_accounting_date_rule(
        nino=nino,
        business_id=business_id,
        tax_year=tax_year,
        gov_test_scenario=gov_test_scenario,
    )
    return {
        "nino":       nino,
        "businessId": business_id,
        "taxYear":    tax_year,
        **data,
    }


@router.post(
    "/business-details/{business_id}/late-accounting-date-rule-election/disapply",
    tags=["Business Details — Late Accounting Date Rule"],
)
async def disapply_late_accounting_date_rule(
    business_id: str,
    request: Request,
    x_session_id: Optional[str] = Header(None),
    tax_year: str = Query(
        ...,
        alias="taxYear",
        description="HMRC tax year that has already ended",
    ),
    gov_test_scenario: Optional[str] = Query(
        None,
        alias="govTestScenario",
        description="Sandbox-only. Sets HMRC Gov-Test-Scenario header. Omit in production.",
    ),
):
    """
    Disapply the automatic Late Accounting Date Rule for a tax year (no request body).

    Only valid after the tax year has ended.

    HMRC endpoint:
        POST .../late-accounting-date-rule-election/disapply  (v2.0)
    """
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)
    result = await client.disapply_late_accounting_date_rule(
        nino=nino,
        business_id=business_id,
        tax_year=tax_year,
        gov_test_scenario=gov_test_scenario,
    )
    return {
        "success":    True,
        "businessId": business_id,
        "taxYear":    tax_year,
        "result":     result,
    }


@router.delete(
    "/business-details/{business_id}/late-accounting-date-rule-election/withdraw",
    tags=["Business Details — Late Accounting Date Rule"],
)
async def withdraw_late_accounting_date_rule(
    business_id: str,
    request: Request,
    x_session_id: Optional[str] = Header(None),
    tax_year: str = Query(
        ...,
        alias="taxYear",
        description="HMRC tax year that has already ended",
    ),
    gov_test_scenario: Optional[str] = Query(
        None,
        alias="govTestScenario",
        description="Sandbox-only. Sets HMRC Gov-Test-Scenario header. Omit in production.",
    ),
):
    """
    Withdraw a Late Accounting Date Rule disapply election (no request body).

    Only valid after the tax year has ended.

    HMRC endpoint:
        DELETE .../late-accounting-date-rule-election/withdraw  (v2.0)
    """
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)
    result = await client.withdraw_late_accounting_date_rule(
        nino=nino,
        business_id=business_id,
        tax_year=tax_year,
        gov_test_scenario=gov_test_scenario,
    )
    return {
        "success":    True,
        "businessId": business_id,
        "taxYear":    tax_year,
        "result":     result,
    }


# ── Annual Submission ─────────────────────────────────────────────────────────────


HMRC_ANNUAL_SUBMISSION_EXAMPLE = {
    "submittedOn": "2020-06-17T10:59:47.544Z",
    "foreignFhlEea": {
        "adjustments": {
            "privateUseAdjustment": 34343.45,
            "balancingCharge": 53543.23,
            "periodOfGraceAdjustment": True,
        },
        "allowances": {
            "annualInvestmentAllowance": 3434.23,
            "otherCapitalAllowance": 1343.34,
            "electricChargePointAllowance": 6565.45,
            "zeroEmissionsCarAllowance": 3456.34,
        },
    },
    "foreignProperty": [
        {
            "countryCode": "LBN",
            "adjustments": {
                "privateUseAdjustment": 4553.34,
                "balancingCharge": 3453.34,
            },
            "allowances": {
                "annualInvestmentAllowance": 38330.95,
                "costOfReplacingDomesticItems": 41985.17,
                "zeroEmissionsGoodsVehicleAllowance": 9769.19,
                "otherCapitalAllowance": 1049.21,
                "electricChargePointAllowance": 3565.45,
                "structuredBuildingAllowance": [
                    {
                        "amount": 3545.12,
                        "firstYear": {
                            "qualifyingDate": "2020-03-29",
                            "qualifyingAmountExpenditure": 3453.34,
                        },
                        "building": {
                            "name": "Blue Oaks",
                            "number": "12",
                            "postcode": "TF3 4GH",
                        },
                    }
                ],
                "zeroEmissionsCarAllowance": 3456.34,
            },
        }
    ],
}


@router.put("/submit-annual", tags=["Property Business — Annual Submission"])
async def submit_annual(
    request: Request,
    body: dict = Body(
        ...,
        description=(
            "HMRC annual property business submission body. "
            "Pass the body exactly as HMRC documents for your tax year (e.g. ukProperty / foreignProperty, etc.)."
        ),
        # FastAPI `examples` expects a LIST. Use `openapi_examples` for Swagger UI named examples.
        openapi_examples={
            "hmrc_example": {
                "summary": "HMRC example body",
                "value": HMRC_ANNUAL_SUBMISSION_EXAMPLE,
            }
        },
    ),
    x_session_id: Optional[str] = Header(None),
    business_id: str = Query(
        ...,
        alias="businessId",
        description="businessId from GET /business-details",
    ),
    tax_year: str = Query(
        ...,
        alias="taxYear",
        description="HMRC tax year e.g. '2024-25'",
    ),
):
    """
    Create or amend the annual UK property business allowances and adjustments.

    **Routing parameters** (shown above): businessId, taxYear.\n
    **Request body**: pass the HMRC-shaped payload. Swagger shows a default example from HMRC docs.\n
    Note: NINO is taken from the session (POST /auth/set-nino), so it is not a parameter here.

    HMRC endpoint:
        PUT /individuals/business/property/uk/{nino}/{businessId}/annual/{taxYear}  (v6.0)
    """
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)

    result = await client.amend_annual_submission(
        nino=nino,
        business_id=business_id,
        tax_year=tax_year,
        body=body,
    )
    return {"success": True, "taxYear": tax_year, "businessId": business_id, "result": result}


@router.get("/annual-submission", tags=["Property Business — Annual Submission"])
async def get_annual_submission(
    request: Request,
    x_session_id: Optional[str] = Header(None),
    business_id: str = Query(
        ...,
        alias="businessId",
        description="businessId from GET /business-details (e.g. XAIS12345678901)",
    ),
    tax_year: str = Query(
        ...,
        alias="taxYear",
        description="HMRC tax year e.g. '2024-25'",
    ),
    gov_test_scenario: Optional[str] = Query(
        None,
        alias="govTestScenario",
        description=(
            "Sandbox-only. Sets HMRC Gov-Test-Scenario header (e.g. UK_PROPERTY, STATEFUL). "
            "Omit in production."
        ),
    ),
):
    """
    Retrieve an existing UK property business annual submission (allowances & adjustments).

    Use after PUT /submit-annual to confirm what was submitted, or to fetch the
    current values before amending them.

    HMRC endpoint:
        GET /individuals/business/property/uk/{nino}/{businessId}/annual/{taxYear}  (v6.0)
    """
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)

    data = await client.get_annual_submission(
        nino=nino,
        business_id=business_id,
        tax_year=tax_year,
        gov_test_scenario=gov_test_scenario,
    )
    return {
        "nino":       nino,
        "businessId": business_id,
        "taxYear":    tax_year,
        **data,
    }


@router.get("/period-summary", tags=["Property Business — Period Summaries"])
async def get_period_summary(
    request: Request,
    x_session_id: Optional[str] = Header(None),
    business_id: str = Query(
        ...,
        alias="businessId",
        description="businessId from GET /business-details",
    ),
    tax_year: str = Query(
        ...,
        alias="taxYear",
        description="HMRC tax year e.g. '2024-25'",
    ),
    submission_id: str = Query(
        ...,
        alias="submissionId",
        description="submissionId returned by POST /submit-periodic",
    ),
    gov_test_scenario: Optional[str] = Query(
        None,
        alias="govTestScenario",
        description=(
            "Sandbox-only. Sets HMRC Gov-Test-Scenario header (e.g. STATEFUL). "
            "If omitted, HMRC may respond 404 (no data found) in sandbox."
        ),
    ),
):
    """
    Retrieve an existing UK property income & expenses period summary.

    Use this to inspect a previously created periodic submission.
    The submissionId is returned by POST /submit-periodic and can also be
    found in the obligations response.

    HMRC endpoint:
        GET /individuals/business/property/uk/{nino}/{businessId}/period/{taxYear}/{submissionId}  (v6.0)
    """
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)

    data = await client.get_period_summary(
        nino=nino,
        business_id=business_id,
        tax_year=tax_year,
        submission_id=submission_id,
        gov_test_scenario=gov_test_scenario,
    )
    return {
        "nino":         nino,
        "businessId":   business_id,
        "taxYear":      tax_year,
        "submissionId": submission_id,
        **data,
    }


# ── Debug / Validation (sandbox only) ────────────────────────────────────────────

@router.get("/debug/validate-fraud-headers", tags=["Debug"])
async def validate_fraud_headers(
    request: Request,
    x_session_id: Optional[str] = Header(None),
):
    """
    Ask HMRC's sandbox endpoint to inspect and validate the fraud prevention
    headers produced by this backend.  Expect code "VALID_HEADERS" on success.

    Only works against the HMRC test environment (test-api.service.hmrc.gov.uk).
    """
    session_id = _require_session(x_session_id)
    client = await _build_client(request, session_id)
    return await client.validate_fraud_headers()


# ── UK Property Cumulative Period Summary ─────────────────────────────────────────


class PropertyIncomeBody(BaseModel):
    """
    Income and expense amounts for a UK property cumulative period summary (all YTD).

    HMRC spec: fromDate/toDate are part of the JSON body (not query params).
    They are optional for annual ITSA status / latent income sources.

    HMRC expects `ukProperty` (tax years 2025-26+).
    """

    from_date: Optional[str] = Field(
        None,
        description="fromDate in HMRC body (YYYY-MM-DD). Optional for annual/latent submissions.",
    )
    to_date: Optional[str] = Field(
        None,
        description="toDate in HMRC body (YYYY-MM-DD). Optional for annual/latent submissions.",
    )

    # ── Income ───────────────────────────────────────────────────────────────────
    rent_income: float              = Field(0.0, description="Total rental income received (YTD)")
    premiums_of_lease_grant: float  = Field(0.0, description="Premiums of lease grant (YTD)")
    reverse_premiums: float         = Field(0.0, description="Reverse premiums (YTD)")
    other_income: float             = Field(0.0, description="Other property income (YTD)")
    tax_deducted: float             = Field(0.0, description="Tax already deducted at source (YTD)")

    # ── Expenses ─────────────────────────────────────────────────────────────────
    premises_running_costs: float     = Field(0.0, description="Premises running costs e.g. rent, rates (YTD)")
    repairs_and_maintenance: float    = Field(0.0, description="Repairs and maintenance (YTD)")
    financial_costs: float            = Field(0.0, description="Financial costs e.g. mortgage interest (YTD)")
    professional_fees: float          = Field(0.0, description="Professional fees e.g. legal, accounting (YTD)")
    cost_of_services: float           = Field(0.0, description="Cost of services provided with the property (YTD)")
    other_expenses: float             = Field(0.0, description="Other allowable expenses (YTD)")
    residential_financial_cost: float = Field(0.0, description="Residential financial cost (YTD)")
    travel_costs: float               = Field(0.0, description="Travel costs (YTD)")


@router.put("/property-cumulative", tags=["Property Business — UK Cumulative"])
async def submit_property_cumulative(
    amounts: PropertyIncomeBody,
    request: Request,
    x_session_id: Optional[str] = Header(None),
    business_id: str = Query(..., alias="businessId", description="businessId from GET /business-details"),
    tax_year: str = Query(..., alias="taxYear", description="HMRC tax year e.g. '2025-26' (endpoint only supported from 2025-26)"),
    gov_test_scenario: Optional[str] = Query(
        None,
        alias="govTestScenario",
        description="Sandbox-only. Sets HMRC Gov-Test-Scenario header (e.g. STATEFUL). Omit in production.",
    ),
):
    """
    Create or amend a UK property cumulative income & expenses period summary (YTD).

    **Routing parameters** (shown above): businessId, taxYear.
    **Request body**: includes from_date/to_date (optional) and all income/expense amounts — cumulative YTD.

    HMRC endpoint:
        PUT /individuals/business/property/uk/{nino}/{businessId}/cumulative/{taxYear}  (v6.0)
    """
    assert_tax_year_at_least(tax_year)
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)

    body: dict = {
        "ukProperty": {
            "income": {
                "periodAmount":         round(amounts.rent_income, 2),
                "premiumsOfLeaseGrant": round(amounts.premiums_of_lease_grant, 2),
                "reversePremiums":      round(amounts.reverse_premiums, 2),
                "otherIncome":          round(amounts.other_income, 2),
                "taxDeducted":          round(amounts.tax_deducted, 2),
            },
            "expenses": {
                "premisesRunningCosts":     round(amounts.premises_running_costs, 2),
                "repairsAndMaintenance":    round(amounts.repairs_and_maintenance, 2),
                "financialCosts":           round(amounts.financial_costs, 2),
                "professionalFees":         round(amounts.professional_fees, 2),
                "costOfServices":           round(amounts.cost_of_services, 2),
                "other":                    round(amounts.other_expenses, 2),
                "residentialFinancialCost": round(amounts.residential_financial_cost, 2),
                "travelCosts":              round(amounts.travel_costs, 2),
            },
        }
    }
    if amounts.from_date:
        body["fromDate"] = amounts.from_date
    if amounts.to_date:
        body["toDate"] = amounts.to_date

    result = await client.create_or_amend_uk_property_cumulative(
        nino=nino,
        business_id=business_id,
        tax_year=tax_year,
        body=body,
        gov_test_scenario=gov_test_scenario,
    )
    return {
        "success":    True,
        "action":     "created_or_amended",
        "businessId": business_id,
        "taxYear":    tax_year,
        "fromDate":   amounts.from_date,
        "toDate":     amounts.to_date,
        "result":     result,
    }


@router.get("/property-cumulative", tags=["Property Business — UK Cumulative"])
async def get_property_cumulative(
    request: Request,
    x_session_id: Optional[str] = Header(None),
    business_id: str = Query(..., alias="businessId", description="businessId from GET /business-details"),
    tax_year: str = Query(..., alias="taxYear", description="HMRC tax year e.g. '2025-26' (endpoint only supported from 2025-26)"),
    gov_test_scenario: Optional[str] = Query(
        None,
        alias="govTestScenario",
        description=(
            "Sandbox-only. Sets HMRC Gov-Test-Scenario header (e.g. STATEFUL). "
            "Omit in production."
        ),
    ),
):
    """
    Retrieve the current cumulative period summary (income & expenses YTD) for a
    UK property business.

    HMRC endpoint:
        GET /individuals/business/property/uk/{nino}/{businessId}/cumulative/{taxYear}  (v6.0)
    """
    assert_tax_year_at_least(tax_year)
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)

    data = await client.retrieve_uk_property_cumulative(
        nino=nino,
        business_id=business_id,
        tax_year=tax_year,
        gov_test_scenario=gov_test_scenario,
    )
    return {
        "nino":       nino,
        "businessId": business_id,
        "taxYear":    tax_year,
        **data,
    }


# ── Foreign Property Details (from 2026-27) ────────────────────────────────────────

HMRC_FOREIGN_PROPERTY_DETAILS_CREATE_EXAMPLE = {
    "propertyName": "Bob & Bobby Co",
    "countryCode": "FRA",
}

HMRC_FOREIGN_PROPERTY_DETAILS_UPDATE_EXAMPLE = {
    "propertyName": "Bob & Bobby Co",
}


@router.post("/foreign-property-details", tags=["Property Business — Foreign Property Details"])
async def create_foreign_property_details(
    request: Request,
    body: dict = Body(
        ...,
        description=(
            "HMRC create body: propertyName + countryCode (ISO 3166-1 Alpha-3). "
            "Optional endDate / endReason."
        ),
        openapi_examples={
            "create": {
                "summary": "Create foreign property details",
                "value": HMRC_FOREIGN_PROPERTY_DETAILS_CREATE_EXAMPLE,
            }
        },
    ),
    x_session_id: Optional[str] = Header(None),
    business_id: str = Query(
        ...,
        alias="businessId",
        description="foreign-property businessId from GET /business-details",
    ),
    tax_year: str = Query(
        ...,
        alias="taxYear",
        description="HMRC tax year e.g. '2026-27' (minimum 2026-27)",
    ),
    gov_test_scenario: Optional[str] = Query(
        None,
        alias="govTestScenario",
        description="Sandbox-only. Sets HMRC Gov-Test-Scenario header. Omit in production.",
    ),
):
    """
    Create a foreign property details record. Returns propertyId (UUID).

    HMRC endpoint:
        POST /individuals/business/property/foreign/{nino}/{businessId}/details/{taxYear}  (v6.0)
    """
    assert_tax_year_at_least(tax_year, "2026-27")
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)
    data = await client.create_foreign_property_details(
        nino=nino,
        business_id=business_id,
        tax_year=tax_year,
        body=body,
        gov_test_scenario=gov_test_scenario,
    )
    return {
        "success":    True,
        "nino":       nino,
        "businessId": business_id,
        "taxYear":    tax_year,
        **data,
    }


@router.get("/foreign-property-details", tags=["Property Business — Foreign Property Details"])
async def get_foreign_property_details(
    request: Request,
    x_session_id: Optional[str] = Header(None),
    business_id: str = Query(
        ...,
        alias="businessId",
        description="foreign-property businessId from GET /business-details",
    ),
    tax_year: str = Query(
        ...,
        alias="taxYear",
        description="HMRC tax year e.g. '2026-27' (minimum 2026-27)",
    ),
    property_id: Optional[str] = Query(
        None,
        alias="propertyId",
        description="Optional UUID propertyId filter returned from create",
    ),
    gov_test_scenario: Optional[str] = Query(
        None,
        alias="govTestScenario",
        description="Sandbox-only. Sets HMRC Gov-Test-Scenario header. Omit in production.",
    ),
):
    """
    Retrieve foreign property details for a business / tax year.

    HMRC endpoint:
        GET /individuals/business/property/foreign/{nino}/{businessId}/details/{taxYear}  (v6.0)
    """
    assert_tax_year_at_least(tax_year, "2026-27")
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)
    data = await client.retrieve_foreign_property_details(
        nino=nino,
        business_id=business_id,
        tax_year=tax_year,
        property_id=property_id,
        gov_test_scenario=gov_test_scenario,
    )
    return {
        "nino":       nino,
        "businessId": business_id,
        "taxYear":    tax_year,
        **data,
    }


@router.put(
    "/foreign-property-details/{property_id}",
    tags=["Property Business — Foreign Property Details"],
)
async def update_foreign_property_details(
    property_id: str,
    request: Request,
    body: dict = Body(
        ...,
        description=(
            "HMRC update body: propertyName required. "
            "Optional endDate / endReason (includes added-in-error)."
        ),
        openapi_examples={
            "update": {
                "summary": "Update property name",
                "value": HMRC_FOREIGN_PROPERTY_DETAILS_UPDATE_EXAMPLE,
            }
        },
    ),
    x_session_id: Optional[str] = Header(None),
    tax_year: str = Query(
        ...,
        alias="taxYear",
        description="HMRC tax year e.g. '2026-27' (minimum 2026-27)",
    ),
    gov_test_scenario: Optional[str] = Query(
        None,
        alias="govTestScenario",
        description="Sandbox-only. Sets HMRC Gov-Test-Scenario header. Omit in production.",
    ),
):
    """
    Update foreign property details by propertyId.

    HMRC endpoint:
        PUT /individuals/business/property/foreign/{nino}/details/{propertyId}/{taxYear}  (v6.0)
    """
    assert_tax_year_at_least(tax_year, "2026-27")
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)
    result = await client.update_foreign_property_details(
        nino=nino,
        property_id=property_id,
        tax_year=tax_year,
        body=body,
        gov_test_scenario=gov_test_scenario,
    )
    return {
        "success":    True,
        "propertyId": property_id,
        "taxYear":    tax_year,
        "result":     result,
    }


# ── Foreign Property Cumulative Period Summary ─────────────────────────────────────

HMRC_FOREIGN_PROPERTY_CUMULATIVE_EXAMPLE = {
    "fromDate": "2026-04-06",
    "toDate": "2026-07-05",
    "foreignProperty": [
        {
            "propertyId": "8e8b8450-dc1b-4360-8109-7067337b42cb",
            "income": {
                "rentIncome": {"rentAmount": 5000.99},
                "foreignTaxCreditRelief": False,
                "premiumsOfLeaseGrant": 12000.50,
                "otherPropertyIncome": 3000.25,
                "foreignTaxPaidOrDeducted": 1500.75,
                "specialWithholdingTaxOrUkTaxPaid": 450.50,
            },
            "expenses": {
                "premisesRunningCosts": 5000.99,
                "repairsAndMaintenance": 2000.50,
                "financialCosts": 1000.00,
                "professionalFees": 750.75,
                "travelCosts": 300.50,
                "costOfServices": 4000.75,
                "other": 600.00,
                "residentialFinancialCost": 500.99,
                "broughtFwdResidentialFinancialCost": 250.25,
            },
        }
    ],
}


@router.put("/foreign-property-cumulative", tags=["Property Business — Foreign Cumulative"])
async def submit_foreign_property_cumulative(
    request: Request,
    body: dict = Body(
        ...,
        description=(
            "HMRC foreign property cumulative body. "
            "Pass fromDate/toDate and foreignProperty[] exactly as documented. "
            "For 2026-27+ each entry must include propertyId from Create Foreign Property Details."
        ),
        openapi_examples={
            "hmrc_2026_27": {
                "summary": "Full expenses (TY 2026-27+)",
                "value": HMRC_FOREIGN_PROPERTY_CUMULATIVE_EXAMPLE,
            }
        },
    ),
    x_session_id: Optional[str] = Header(None),
    business_id: str = Query(
        ...,
        alias="businessId",
        description="foreign-property businessId from GET /business-details",
    ),
    tax_year: str = Query(
        ...,
        alias="taxYear",
        description="HMRC tax year e.g. '2025-26' (minimum 2025-26)",
    ),
    gov_test_scenario: Optional[str] = Query(
        None,
        alias="govTestScenario",
        description="Sandbox-only. Sets HMRC Gov-Test-Scenario header. Omit in production.",
    ),
):
    """
    Create or amend a foreign property cumulative income & expenses period summary.

    HMRC endpoint:
        PUT /individuals/business/property/foreign/{nino}/{businessId}/cumulative/{taxYear}  (v6.0)
    """
    assert_tax_year_at_least(tax_year)
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)
    result = await client.create_or_amend_foreign_property_cumulative(
        nino=nino,
        business_id=business_id,
        tax_year=tax_year,
        body=body,
        gov_test_scenario=gov_test_scenario,
    )
    return {
        "success":    True,
        "action":     "created_or_amended",
        "businessId": business_id,
        "taxYear":    tax_year,
        "result":     result,
    }


@router.get("/foreign-property-cumulative", tags=["Property Business — Foreign Cumulative"])
async def get_foreign_property_cumulative(
    request: Request,
    x_session_id: Optional[str] = Header(None),
    business_id: str = Query(
        ...,
        alias="businessId",
        description="foreign-property businessId from GET /business-details",
    ),
    tax_year: str = Query(
        ...,
        alias="taxYear",
        description="HMRC tax year e.g. '2025-26' (minimum 2025-26)",
    ),
    property_id: Optional[str] = Query(
        None,
        alias="propertyId",
        description="propertyId filter — required for tax years 2026-27+",
    ),
    gov_test_scenario: Optional[str] = Query(
        None,
        alias="govTestScenario",
        description="Sandbox-only. Sets HMRC Gov-Test-Scenario header. Omit in production.",
    ),
):
    """
    Retrieve a foreign property cumulative period summary.

    HMRC endpoint:
        GET /individuals/business/property/foreign/{nino}/{businessId}/cumulative/{taxYear}  (v6.0)
    """
    assert_tax_year_at_least(tax_year)
    if tax_year_start_year(tax_year) >= 2026 and not (property_id or "").strip():
        raise HTTPException(
            status_code=400,
            detail="propertyId is required for tax years 2026-27 and later.",
        )
    session_id = _require_session(x_session_id)
    _tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)
    data = await client.retrieve_foreign_property_cumulative(
        nino=nino,
        business_id=business_id,
        tax_year=tax_year,
        property_id=(property_id or "").strip() or None,
        gov_test_scenario=gov_test_scenario,
    )
    return {
        "nino":       nino,
        "businessId": business_id,
        "taxYear":    tax_year,
        **data,
    }


# ── Self-Employment Cumulative Period Summary ──────────────────────────────────────

# Default example body (from HMRC docs)
HMRC_SELF_EMPLOYMENT_CUMULATIVE_EXAMPLE = {
    "periodDates": {
        "periodStartDate": "2025-04-06",
        "periodEndDate": "2025-07-05",
    },
    "periodIncome": {
        "turnover": 1000.99,
        "other": 1000.09,
        "taxTakenOffTradingIncome": 1000.99,
    },
    "periodExpenses": {
        "costOfGoods": 1000.99,
        "paymentsToSubcontractors": 1000.99,
        "wagesAndStaffCosts": 1000.99,
        "carVanTravelExpenses": 1000.99,
        "premisesRunningCosts": -1000.99,
        "maintenanceCosts": -1000.99,
        "adminCosts": 1000.99,
        "businessEntertainmentCosts": 1000.99,
        "advertisingCosts": 1000.99,
        "interestOnBankOtherLoans": -1000.99,
        "financeCharges": -1000.99,
        "irrecoverableDebts": -1000.99,
        "professionalFees": 1000.99,
        "depreciation": -1000.99,
        "otherExpenses": 1000.99,
    },
    "periodDisallowableExpenses": {
        "costOfGoodsDisallowable": 91000.99,
        "paymentsToSubcontractorsDisallowable": 1000.99,
        "wagesAndStaffCostsDisallowable": 1000.99,
        "carVanTravelExpensesDisallowable": 1000.99,
        "premisesRunningCostsDisallowable": -1000.99,
        "maintenanceCostsDisallowable": -999.99,
        "adminCostsDisallowable": 1000.99,
        "businessEntertainmentCostsDisallowable": 1000.99,
        "advertisingCostsDisallowable": 1000.99,
        "interestOnBankOtherLoansDisallowable": -1000.99,
        "financeChargesDisallowable": -1000.99,
        "irrecoverableDebtsDisallowable": 1000.99,
        "professionalFeesDisallowable": 1000.99,
        "depreciationDisallowable": -1000.99,
        "otherExpensesDisallowable": 1000.99,
    },
}


@router.put(
    "/self-employment-cumulative",
    tags=["Self-Employment — Cumulative Period Summary"],
)
async def submit_self_employment_cumulative(
    request: Request,
    body: dict = Body(
        ...,
        description=(
            "HMRC self-employment cumulative period summary body. "
            "Pass the payload exactly as HMRC documents (periodDates, periodIncome, periodExpenses, optional periodDisallowableExpenses)."
        ),
        openapi_examples={
            "hmrc_example": {
                "summary": "HMRC example body",
                "value": HMRC_SELF_EMPLOYMENT_CUMULATIVE_EXAMPLE,
            }
        },
    ),
    x_session_id: Optional[str] = Header(None),
    business_id: str = Query(..., alias="businessId", description="businessId for the self-employment income source"),
    tax_year: str = Query(..., alias="taxYear", description="HMRC tax year e.g. '2025-26' (endpoint only supported from 2025-26)"),
    gov_test_scenario: Optional[str] = Query(
        None,
        alias="govTestScenario",
        description="Sandbox-only. Sets HMRC Gov-Test-Scenario header (e.g. STATEFUL). Omit in production.",
    ),
):
    """
    Create or amend a self-employment cumulative period summary.

    **Routing parameters** (shown above): businessId, taxYear.
    **Request body**: pass the HMRC-shaped payload (periodDates, periodIncome, periodExpenses, optional periodDisallowableExpenses).

    HMRC endpoint:
        PUT /individuals/business/self-employment/{nino}/{businessId}/cumulative/{taxYear}  (v5.0)
    """
    assert_tax_year_at_least(tax_year)
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)

    result = await client.create_or_amend_self_employment_cumulative(
        nino=nino,
        business_id=business_id,
        tax_year=tax_year,
        body=body,
        gov_test_scenario=gov_test_scenario,
    )
    return {
        "success":         True,
        "action":          "created_or_amended",
        "businessId":      business_id,
        "taxYear":         tax_year,
        "result":          result,
    }


@router.get(
    "/self-employment-cumulative",
    tags=["Self-Employment — Cumulative Period Summary"],
)
async def get_self_employment_cumulative(
    request: Request,
    x_session_id: Optional[str] = Header(None),
    business_id: str = Query(..., alias="businessId", description="businessId for the self-employment business"),
    tax_year: str = Query(..., alias="taxYear", description="HMRC tax year e.g. '2025-26' (endpoint only supported from 2025-26)"),
    gov_test_scenario: Optional[str] = Query(
        None,
        alias="govTestScenario",
        description=(
            "Sandbox-only. Sets HMRC Gov-Test-Scenario header (e.g. STATEFUL). "
            "Omit in production."
        ),
    ),
):
    """
    Retrieve the current self-employment cumulative period summary for the given
    business and tax year.

    HMRC endpoint:
        GET /individuals/business/self-employment/{nino}/{businessId}/cumulative/{taxYear}  (v5.0)
    """
    assert_tax_year_at_least(tax_year)
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)

    data = await client.retrieve_self_employment_cumulative(
        nino=nino,
        business_id=business_id,
        tax_year=tax_year,
        gov_test_scenario=gov_test_scenario,
    )
    return {
        "nino":       nino,
        "businessId": business_id,
        "taxYear":    tax_year,
        **data,
    }


# ── Self-Employment Annual Submission ─────────────────────────────────────────────

HMRC_SELF_EMPLOYMENT_ANNUAL_EXAMPLE = {
    "adjustments": {
        "includedNonTaxableProfits": 500.00,
        "basisAdjustment": 100.00,
        "accountingAdjustment": 100.00,
        "adjustmentToProfitsForClass4": 123.45,
    },
    "allowances": {
        "annualInvestmentAllowance": 1000.00,
        "capitalAllowanceMainPool": 1000.00,
        "capitalAllowanceSpecialRatePool": 1000.00,
        "zeroEmissionsGoodsVehicleAllowance": 1000.00,
        "enhancedCapitalAllowance": 1000.00,
        "allowanceOnSales": 1000.00,
        "capitalAllowanceSingleAssetPool": 1000.00,
        "electricChargePointAllowance": 1000.00,
        "zeroEmissionsCarAllowance": 1000.00,
        "structuredBuildingAllowance": [
            {
                "amount": 1000.00,
                "firstYear": {
                    "qualifyingDate": "2025-04-06",
                    "qualifyingAmountExpenditure": 1000.00,
                },
                "building": {
                    "name": "Building Name",
                    "number": "1",
                    "postcode": "TF3 4NT",
                },
            }
        ],
    },
}


@router.put("/self-employment-annual", tags=["Self-Employment — Annual Submission"])
async def submit_self_employment_annual(
    request: Request,
    body: dict = Body(
        ...,
        description=(
            "HMRC self-employment annual submission body (adjustments and allowances). "
            "Pass the payload exactly as HMRC documents for your tax year."
        ),
        openapi_examples={
            "hmrc_example": {
                "summary": "HMRC example with Class 4 adjustment (2026-27+)",
                "value": HMRC_SELF_EMPLOYMENT_ANNUAL_EXAMPLE,
            }
        },
    ),
    x_session_id: Optional[str] = Header(None),
    business_id: str = Query(
        ...,
        alias="businessId",
        description="businessId for the self-employment income source",
    ),
    tax_year: str = Query(
        ...,
        alias="taxYear",
        description="HMRC tax year e.g. '2025-26'",
    ),
    gov_test_scenario: Optional[str] = Query(
        None,
        alias="govTestScenario",
        description="Sandbox-only. Sets HMRC Gov-Test-Scenario header (e.g. STATEFUL). Omit in production.",
    ),
):
    """
    Create or amend the self-employment annual submission (adjustments & allowances).

    **Routing parameters** (shown above): businessId, taxYear.
    **Request body**: pass the HMRC-shaped payload.

    `adjustmentToProfitsForClass4` in `adjustments` is available from tax year **2026-27**
    onwards.  Do not use deprecated fields `overlapReliefUsed` or `averagingAdjustment`
    for tax years 2024-25 onwards.

    HMRC endpoint:
        PUT /individuals/business/self-employment/{nino}/{businessId}/annual/{taxYear}  (v5.0)
    """
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)

    result = await client.amend_self_employment_annual(
        nino=nino,
        business_id=business_id,
        tax_year=tax_year,
        body=body,
        gov_test_scenario=gov_test_scenario,
    )
    return {
        "success":    True,
        "taxYear":    tax_year,
        "businessId": business_id,
        "result":     result,
    }


@router.get("/self-employment-annual", tags=["Self-Employment — Annual Submission"])
async def get_self_employment_annual(
    request: Request,
    x_session_id: Optional[str] = Header(None),
    business_id: str = Query(
        ...,
        alias="businessId",
        description="businessId for the self-employment income source",
    ),
    tax_year: str = Query(
        ...,
        alias="taxYear",
        description="HMRC tax year e.g. '2025-26'",
    ),
    gov_test_scenario: Optional[str] = Query(
        None,
        alias="govTestScenario",
        description=(
            "Sandbox-only. Sets HMRC Gov-Test-Scenario header (e.g. STATEFUL). "
            "Omit in production."
        ),
    ),
):
    """
    Retrieve an existing self-employment annual submission (adjustments & allowances).

    Use after PUT /self-employment-annual to confirm what was submitted.

    HMRC endpoint:
        GET /individuals/business/self-employment/{nino}/{businessId}/annual/{taxYear}  (v5.0)
    """
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)

    data = await client.get_self_employment_annual(
        nino=nino,
        business_id=business_id,
        tax_year=tax_year,
        gov_test_scenario=gov_test_scenario,
    )
    return {
        "nino":       nino,
        "businessId": business_id,
        "taxYear":    tax_year,
        **data,
    }


@router.delete("/self-employment-annual", tags=["Self-Employment — Annual Submission"])
async def delete_self_employment_annual(
    request: Request,
    x_session_id: Optional[str] = Header(None),
    business_id: str = Query(
        ...,
        alias="businessId",
        description="businessId for the self-employment income source",
    ),
    tax_year: str = Query(
        ...,
        alias="taxYear",
        description="HMRC tax year e.g. '2025-26'",
    ),
    gov_test_scenario: Optional[str] = Query(
        None,
        alias="govTestScenario",
        description="Sandbox-only. Sets HMRC Gov-Test-Scenario header. Omit in production.",
    ),
):
    """
    Delete a self-employment annual submission.

    HMRC endpoint:
        DELETE /individuals/business/self-employment/{nino}/{businessId}/annual/{taxYear}  (v5.0)
    """
    session_id = _require_session(x_session_id)
    _tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)
    result = await client.delete_self_employment_annual(
        nino=nino,
        business_id=business_id,
        tax_year=tax_year,
        gov_test_scenario=gov_test_scenario,
    )
    return {
        "success":    True,
        "businessId": business_id,
        "taxYear":    tax_year,
        "result":     result,
    }


# ── Self-Employment Period Summaries (≤ 2024-25) ───────────────────────────────────

HMRC_SELF_EMPLOYMENT_PERIOD_CREATE_EXAMPLE = {
    "periodDates": {
        "periodStartDate": "2024-04-06",
        "periodEndDate": "2024-07-05",
    },
    "periodIncome": {
        "turnover": 1000.99,
        "other": 1000.09,
        "taxTakenOffTradingIncome": 1000.99,
    },
    "periodExpenses": {
        "costOfGoods": 1000.99,
        "paymentsToSubcontractors": 1000.99,
        "wagesAndStaffCosts": 1000.99,
        "carVanTravelExpenses": 1000.99,
        "premisesRunningCosts": 1000.99,
        "maintenanceCosts": 1000.99,
        "adminCosts": 1000.99,
        "businessEntertainmentCosts": 1000.99,
        "advertisingCosts": 1000.99,
        "interestOnBankOtherLoans": 1000.99,
        "financeCharges": 1000.99,
        "irrecoverableDebts": 1000.99,
        "professionalFees": 1000.99,
        "depreciation": 1000.99,
        "otherExpenses": 1000.99,
    },
}

HMRC_SELF_EMPLOYMENT_PERIOD_AMEND_EXAMPLE = {
    "periodIncome": {
        "turnover": 1000.99,
        "other": 1000.99,
        "taxTakenOffTradingIncome": 1000.99,
    },
    "periodExpenses": {
        "costOfGoods": 1000.99,
        "paymentsToSubcontractors": 1000.99,
        "wagesAndStaffCosts": 1000.99,
        "carVanTravelExpenses": 1000.99,
        "premisesRunningCosts": 1000.99,
        "maintenanceCosts": 1000.99,
        "adminCosts": 1000.99,
        "businessEntertainmentCosts": 1000.99,
        "advertisingCosts": 1000.99,
        "interestOnBankOtherLoans": 1000.99,
        "financeCharges": 1000.99,
        "irrecoverableDebts": 1000.99,
        "professionalFees": 1000.99,
        "depreciation": 1000.99,
        "otherExpenses": 1000.99,
    },
}


@router.post(
    "/self-employment-period",
    tags=["Self-Employment — Period Summaries"],
)
async def create_self_employment_period(
    request: Request,
    body: dict = Body(
        ...,
        description=(
            "HMRC create period body: periodDates, periodIncome, periodExpenses "
            "(optional periodDisallowableExpenses). Tax year ≤ 2024-25 only."
        ),
        openapi_examples={
            "hmrc_example": {
                "summary": "Non-consolidated period create",
                "value": HMRC_SELF_EMPLOYMENT_PERIOD_CREATE_EXAMPLE,
            }
        },
    ),
    x_session_id: Optional[str] = Header(None),
    business_id: str = Query(
        ...,
        alias="businessId",
        description="businessId for the self-employment income source",
    ),
    gov_test_scenario: Optional[str] = Query(
        None,
        alias="govTestScenario",
        description="Sandbox-only. Sets HMRC Gov-Test-Scenario header. Omit in production.",
    ),
):
    """
    Create a self-employment period summary (tax years 2024-25 or earlier).

    From 2025-26 use PUT /self-employment-cumulative instead.

    HMRC endpoint:
        POST /individuals/business/self-employment/{nino}/{businessId}/period  (v5.0)
    """
    session_id = _require_session(x_session_id)
    _tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)
    data = await client.create_self_employment_period(
        nino=nino,
        business_id=business_id,
        body=body,
        gov_test_scenario=gov_test_scenario,
    )
    return {
        "success":    True,
        "businessId": business_id,
        **data,
    }


@router.get(
    "/self-employment-period",
    tags=["Self-Employment — Period Summaries"],
)
async def list_self_employment_periods(
    request: Request,
    x_session_id: Optional[str] = Header(None),
    business_id: str = Query(
        ...,
        alias="businessId",
        description="businessId for the self-employment income source",
    ),
    tax_year: str = Query(
        ...,
        alias="taxYear",
        description="HMRC tax year e.g. '2024-25' (period summaries ≤ 2024-25)",
    ),
    gov_test_scenario: Optional[str] = Query(
        None,
        alias="govTestScenario",
        description="Sandbox-only. Sets HMRC Gov-Test-Scenario header. Omit in production.",
    ),
):
    """
    List self-employment period summaries for a tax year.

    HMRC endpoint:
        GET /individuals/business/self-employment/{nino}/{businessId}/period/{taxYear}  (v5.0)
    """
    session_id = _require_session(x_session_id)
    _tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)
    data = await client.list_self_employment_periods(
        nino=nino,
        business_id=business_id,
        tax_year=tax_year,
        gov_test_scenario=gov_test_scenario,
    )
    return {
        "nino":       nino,
        "businessId": business_id,
        "taxYear":    tax_year,
        **data,
    }


@router.get(
    "/self-employment-period/{period_id}",
    tags=["Self-Employment — Period Summaries"],
)
async def get_self_employment_period(
    period_id: str,
    request: Request,
    x_session_id: Optional[str] = Header(None),
    business_id: str = Query(
        ...,
        alias="businessId",
        description="businessId for the self-employment income source",
    ),
    tax_year: str = Query(
        ...,
        alias="taxYear",
        description="HMRC tax year e.g. '2024-25'",
    ),
    gov_test_scenario: Optional[str] = Query(
        None,
        alias="govTestScenario",
        description="Sandbox-only. Sets HMRC Gov-Test-Scenario header. Omit in production.",
    ),
):
    """
    Retrieve a single self-employment period summary by periodId.

    periodId format from create response, e.g. `2024-04-06_2024-07-05`.

    HMRC endpoint:
        GET /individuals/business/self-employment/{nino}/{businessId}/period/{taxYear}/{periodId}  (v5.0)
    """
    session_id = _require_session(x_session_id)
    _tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)
    data = await client.retrieve_self_employment_period(
        nino=nino,
        business_id=business_id,
        tax_year=tax_year,
        period_id=period_id,
        gov_test_scenario=gov_test_scenario,
    )
    return {
        "nino":       nino,
        "businessId": business_id,
        "taxYear":    tax_year,
        "periodId":   period_id,
        **data,
    }


@router.put(
    "/self-employment-period/{period_id}",
    tags=["Self-Employment — Period Summaries"],
)
async def amend_self_employment_period(
    period_id: str,
    request: Request,
    body: dict = Body(
        ...,
        description=(
            "HMRC amend body: periodIncome, periodExpenses "
            "(optional periodDisallowableExpenses). No periodDates on amend."
        ),
        openapi_examples={
            "hmrc_example": {
                "summary": "Amend period income/expenses",
                "value": HMRC_SELF_EMPLOYMENT_PERIOD_AMEND_EXAMPLE,
            }
        },
    ),
    x_session_id: Optional[str] = Header(None),
    business_id: str = Query(
        ...,
        alias="businessId",
        description="businessId for the self-employment income source",
    ),
    tax_year: str = Query(
        ...,
        alias="taxYear",
        description="HMRC tax year e.g. '2024-25'",
    ),
    gov_test_scenario: Optional[str] = Query(
        None,
        alias="govTestScenario",
        description="Sandbox-only. Sets HMRC Gov-Test-Scenario header. Omit in production.",
    ),
):
    """
    Amend an existing self-employment period summary.

    HMRC endpoint:
        PUT /individuals/business/self-employment/{nino}/{businessId}/period/{taxYear}/{periodId}  (v5.0)
    """
    session_id = _require_session(x_session_id)
    _tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)
    result = await client.amend_self_employment_period(
        nino=nino,
        business_id=business_id,
        tax_year=tax_year,
        period_id=period_id,
        body=body,
        gov_test_scenario=gov_test_scenario,
    )
    return {
        "success":    True,
        "businessId": business_id,
        "taxYear":    tax_year,
        "periodId":   period_id,
        "result":     result,
    }
