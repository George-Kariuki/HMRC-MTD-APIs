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
    assert_historic_period_body,
    assert_historic_period_id,
    assert_tax_year_at_least,
    assert_tax_year_at_most,
    assert_tax_year_in_range,
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
    as start_date / end_date when calling POST /uk-period.

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


# ── Period Summaries (UK + Foreign, ≤ 2024-25) ────────────────────────────────────

class PeriodicAmountsBody(BaseModel):
    """Income and expense amounts for a UK property period summary."""

    # ── Income ───────────────────────────────────────────────────────────────────
    rent_income:              float = Field(0.0,  description="Total rental income → periodAmount")
    premiums_of_lease_grant:  float = Field(0.0,  description="Premiums of lease grant")
    reverse_premiums:         float = Field(0.0,  description="Reverse premiums")
    other_income:             float = Field(0.0,  description="Other property income")
    tax_deducted:             float = Field(0.0,  description="Tax already deducted at source")

    # ── Expenses ─────────────────────────────────────────────────────────────────
    premises_running_costs:     float = Field(0.0, description="Premises running costs")
    repairs_and_maintenance:    float = Field(0.0, description="Repairs and maintenance")
    financial_costs:            float = Field(0.0, description="Financial costs / mortgage interest")
    professional_fees:          float = Field(0.0, description="Professional fees")
    cost_of_services:           float = Field(0.0, description="Cost of services")
    other_expenses:             float = Field(0.0, description="Other allowable expenses → other")
    residential_financial_cost: float = Field(0.0, description="Residential financial cost")
    travel_costs:               float = Field(0.0, description="Travel costs")


def _uk_period_income_expenses(
    amounts: PeriodicAmountsBody,
    property_type: str = "ukNonFhlProperty",
) -> tuple[dict, dict]:
    """
    Map PeriodicAmountsBody to HMRC income/expenses.
    ukFhlProperty omits non-FHL-only fields (premiumsOfLeaseGrant, reversePremiums,
    otherIncome, residentialFinancialCost).
    """
    if property_type == "ukFhlProperty":
        income = {
            "periodAmount": round(amounts.rent_income, 2),
            "taxDeducted":  round(amounts.tax_deducted, 2),
        }
        expenses = {
            "premisesRunningCosts":  round(amounts.premises_running_costs, 2),
            "repairsAndMaintenance": round(amounts.repairs_and_maintenance, 2),
            "financialCosts":        round(amounts.financial_costs, 2),
            "professionalFees":      round(amounts.professional_fees, 2),
            "costOfServices":        round(amounts.cost_of_services, 2),
            "other":                 round(amounts.other_expenses, 2),
            "travelCosts":           round(amounts.travel_costs, 2),
        }
        return income, expenses

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
    return income, expenses


HMRC_FOREIGN_PERIOD_CREATE_EXAMPLE = {
    "fromDate": "2024-04-06",
    "toDate": "2024-07-05",
    "foreignNonFhlProperty": [
        {
            "countryCode": "FRA",
            "income": {
                "rentIncome": {"rentAmount": 5000.99},
                "foreignTaxCreditRelief": False,
                "premiumsOfLeaseGrant": 5000.99,
                "otherPropertyIncome": 5000.99,
                "foreignTaxPaidOrDeducted": 5000.99,
                "specialWithholdingTaxOrUkTaxPaid": 5000.99,
            },
            "expenses": {
                "premisesRunningCosts": 5000.99,
                "repairsAndMaintenance": 5000.99,
                "financialCosts": 5000.99,
                "professionalFees": 5000.99,
                "costOfServices": 5000.99,
                "travelCosts": 5000.99,
                "residentialFinancialCost": 5000.99,
                "broughtFwdResidentialFinancialCost": 5000.99,
                "other": 5000.99,
            },
        }
    ],
}

HMRC_FOREIGN_PERIOD_AMEND_EXAMPLE = {
    "foreignNonFhlProperty": [
        {
            "countryCode": "FRA",
            "income": {
                "rentIncome": {"rentAmount": 440.31},
                "foreignTaxCreditRelief": False,
                "premiumsOfLeaseGrant": 950.48,
                "otherPropertyIncome": 802.49,
                "foreignTaxPaidOrDeducted": 734.18,
                "specialWithholdingTaxOrUkTaxPaid": 85.47,
            },
            "expenses": {
                "premisesRunningCosts": 129.35,
                "repairsAndMaintenance": 7490.32,
                "financialCosts": 5000.99,
                "professionalFees": 847.90,
                "travelCosts": 69.20,
                "costOfServices": 478.23,
                "residentialFinancialCost": 879.28,
                "broughtFwdResidentialFinancialCost": 846.13,
                "other": 138.92,
            },
        }
    ],
}


@router.post("/uk-period", tags=["Property Business — Period Summaries"])
async def submit_periodic(
    amounts: PeriodicAmountsBody,
    request: Request,
    x_session_id: Optional[str] = Header(None),
    business_id: str = Query(
        ...,
        alias="businessId",
        description="uk-property businessId from GET /business-details",
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
        description="HMRC tax year e.g. '2024-25' (≤ 2024-25). Auto-derived from startDate if omitted.",
    ),
    property_type: str = Query(
        "ukNonFhlProperty",
        alias="propertyType",
        description="'ukNonFhlProperty' (standard BTL) or 'ukFhlProperty' (FHL)",
    ),
    gov_test_scenario: Optional[str] = Query(
        None,
        alias="govTestScenario",
        description="Sandbox-only. Sets HMRC Gov-Test-Scenario header. Omit in production.",
    ),
):
    """
    Create a UK property income & expenses period summary (tax years ≤ 2024-25).

    From 2025-26 use PUT /uk-cumulative instead.
    To amend an existing submission use PUT /uk-period.

    HMRC endpoint:
        POST /individuals/business/property/uk/{nino}/{businessId}/period/{taxYear}  (v6.0)
    """
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)

    resolved_tax_year = tax_year or derive_tax_year(start_date)
    assert_tax_year_at_most(resolved_tax_year)

    income, expenses = _uk_period_income_expenses(amounts, property_type)
    client = await _build_client(request, session_id)
    result = await client.create_period_summary(
        nino=nino,
        business_id=business_id,
        tax_year=resolved_tax_year,
        from_date=start_date,
        to_date=end_date,
        income=income,
        expenses=expenses,
        property_type=property_type,
        gov_test_scenario=gov_test_scenario,
    )
    return {
        "success":    True,
        "action":     "created",
        "taxYear":    resolved_tax_year,
        "fromDate":   start_date,
        "toDate":     end_date,
        "businessId": business_id,
        "result":     result,
    }


@router.put("/uk-period", tags=["Property Business — Period Summaries"])
async def amend_period_summary(
    amounts: PeriodicAmountsBody,
    request: Request,
    x_session_id: Optional[str] = Header(None),
    business_id: str = Query(
        ...,
        alias="businessId",
        description="uk-property businessId from GET /business-details",
    ),
    tax_year: str = Query(
        ...,
        alias="taxYear",
        description="HMRC tax year e.g. '2024-25' (≤ 2024-25)",
    ),
    submission_id: str = Query(
        ...,
        alias="submissionId",
        description="submissionId from POST /uk-period or GET /property-period-summaries",
    ),
    property_type: str = Query(
        "ukNonFhlProperty",
        alias="propertyType",
        description="'ukNonFhlProperty' or 'ukFhlProperty'",
    ),
    gov_test_scenario: Optional[str] = Query(
        None,
        alias="govTestScenario",
        description="Sandbox-only. Sets HMRC Gov-Test-Scenario header. Omit in production.",
    ),
):
    """
    Amend a UK property income & expenses period summary (tax years ≤ 2024-25).

    Amend body does not include fromDate/toDate (period dates are fixed at create).

    HMRC endpoint:
        PUT /individuals/business/property/uk/{nino}/{businessId}/period/{taxYear}/{submissionId}  (v6.0)
    """
    assert_tax_year_at_most(tax_year)
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)
    income, expenses = _uk_period_income_expenses(amounts, property_type)
    client = await _build_client(request, session_id)
    result = await client.amend_period_summary(
        nino=nino,
        business_id=business_id,
        tax_year=tax_year,
        submission_id=submission_id,
        income=income,
        expenses=expenses,
        property_type=property_type,
        gov_test_scenario=gov_test_scenario,
    )
    return {
        "success":      True,
        "action":       "amended",
        "taxYear":      tax_year,
        "businessId":   business_id,
        "submissionId": submission_id,
        "result":       result,
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
    boundaries when calling PUT /uk-cumulative or PUT /self-employment-cumulative.

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


# UK annual — TY 2025-26+ (ukProperty only; FHL merged into UK property from 2025-26)
HMRC_UK_ANNUAL_SUBMISSION_EXAMPLE = {
    "ukProperty": {
        "allowances": {
            "propertyIncomeAllowance": 678.45,
        },
        "adjustments": {
            "balancingCharge": 565.34,
            "businessPremisesRenovationAllowanceBalancingCharges": 563.34,
            "nonResidentLandlord": True,
            "rentARoom": {
                "jointlyLet": True,
            },
        },
    },
}

# Foreign annual — TY 2025-26 (countryCode). For 2026-27+ use propertyId instead of countryCode.
HMRC_FOREIGN_ANNUAL_SUBMISSION_EXAMPLE = {
    "foreignProperty": [
        {
            "countryCode": "FRA",
            "adjustments": {
                "balancingCharge": 3453.34,
            },
            "allowances": {
                "propertyIncomeAllowance": 200.25,
            },
        }
    ],
}

# Foreign annual — TY 2026-27+ (propertyId from POST /foreign-property-details)
HMRC_FOREIGN_ANNUAL_SUBMISSION_2026_EXAMPLE = {
    "foreignProperty": [
        {
            "propertyId": "8e8b8450-dc1b-4360-8109-7067337b42cb",
            "adjustments": {
                "balancingCharge": 3453.34,
            },
            "allowances": {
                "propertyIncomeAllowance": 200.25,
            },
        }
    ],
}


@router.put("/uk-annual", tags=["Property Business — Annual Submission"])
async def submit_annual(
    request: Request,
    body: dict = Body(
        ...,
        description=(
            "HMRC UK property annual submission body. "
            "For 2025-26+ use ukProperty only. "
            "For ≤2024-25 you may send ukFhlProperty and/or ukProperty."
        ),
        openapi_examples={
            "uk_2025_26_property_allowance": {
                "summary": "UK propertyIncomeAllowance (TY 2025-26+)",
                "value": HMRC_UK_ANNUAL_SUBMISSION_EXAMPLE,
            }
        },
    ),
    x_session_id: Optional[str] = Header(None),
    business_id: str = Query(
        ...,
        alias="businessId",
        description="uk-property businessId from GET /business-details",
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
    Create or amend the annual UK property business allowances and adjustments.

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
        gov_test_scenario=gov_test_scenario,
    )
    return {"success": True, "taxYear": tax_year, "businessId": business_id, "result": result}


@router.get("/uk-annual", tags=["Property Business — Annual Submission"])
async def get_annual_submission(
    request: Request,
    x_session_id: Optional[str] = Header(None),
    business_id: str = Query(
        ...,
        alias="businessId",
        description="uk-property businessId from GET /business-details",
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
    Retrieve an existing UK property business annual submission (allowances & adjustments).

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


@router.put("/foreign-annual", tags=["Property Business — Annual Submission"])
async def submit_foreign_annual(
    request: Request,
    body: dict = Body(
        ...,
        description=(
            "HMRC foreign property annual submission body. "
            "2025-26: foreignProperty[{countryCode,...}]. "
            "2026-27+: foreignProperty[{propertyId,...}]. "
            "≤2024-25 may include foreignFhlEea and/or foreignProperty with countryCode."
        ),
        openapi_examples={
            "foreign_2025_26": {
                "summary": "Foreign annual (TY 2025-26, countryCode)",
                "value": HMRC_FOREIGN_ANNUAL_SUBMISSION_EXAMPLE,
            },
            "foreign_2026_27": {
                "summary": "Foreign annual (TY 2026-27+, propertyId)",
                "value": HMRC_FOREIGN_ANNUAL_SUBMISSION_2026_EXAMPLE,
            },
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
        description="HMRC tax year e.g. '2025-26'",
    ),
    gov_test_scenario: Optional[str] = Query(
        None,
        alias="govTestScenario",
        description="Sandbox-only. Sets HMRC Gov-Test-Scenario header. Omit in production.",
    ),
):
    """
    Create or amend a foreign property annual submission (allowances & adjustments).

    HMRC endpoint:
        PUT /individuals/business/property/foreign/{nino}/{businessId}/annual/{taxYear}  (v6.0)
    """
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)

    result = await client.amend_foreign_annual_submission(
        nino=nino,
        business_id=business_id,
        tax_year=tax_year,
        body=body,
        gov_test_scenario=gov_test_scenario,
    )
    return {"success": True, "taxYear": tax_year, "businessId": business_id, "result": result}


@router.get("/foreign-annual", tags=["Property Business — Annual Submission"])
async def get_foreign_annual(
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
        description="HMRC tax year e.g. '2025-26'",
    ),
    gov_test_scenario: Optional[str] = Query(
        None,
        alias="govTestScenario",
        description="Sandbox-only. Sets HMRC Gov-Test-Scenario header. Omit in production.",
    ),
):
    """
    Retrieve a foreign property annual submission.

    HMRC endpoint:
        GET /individuals/business/property/foreign/{nino}/{businessId}/annual/{taxYear}  (v6.0)
    """
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)

    data = await client.get_foreign_annual_submission(
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


@router.delete("/property-annual", tags=["Property Business — Annual Submission"])
async def delete_annual_submission(
    request: Request,
    x_session_id: Optional[str] = Header(None),
    business_id: str = Query(
        ...,
        alias="businessId",
        description="UK or foreign property businessId from GET /business-details",
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
            "Sandbox-only. Default (omit) simulates success. "
            "STATEFUL requires a prior annual PUT. Omit in production."
        ),
    ),
):
    """
    Delete a UK or Foreign property annual submission.

    HMRC endpoint (shared path — no uk/foreign segment):
        DELETE /individuals/business/property/{nino}/{businessId}/annual/{taxYear}  (v6.0)
    """
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)

    result = await client.delete_property_annual_submission(
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


@router.get("/uk-period", tags=["Property Business — Period Summaries"])
async def get_period_summary(
    request: Request,
    x_session_id: Optional[str] = Header(None),
    business_id: str = Query(
        ...,
        alias="businessId",
        description="uk-property businessId from GET /business-details",
    ),
    tax_year: str = Query(
        ...,
        alias="taxYear",
        description="HMRC tax year e.g. '2024-25' (≤ 2024-25)",
    ),
    submission_id: str = Query(
        ...,
        alias="submissionId",
        description="submissionId from POST /uk-period or GET /property-period-summaries",
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
    Retrieve a UK property income & expenses period summary (tax years ≤ 2024-25).

    HMRC endpoint:
        GET /individuals/business/property/uk/{nino}/{businessId}/period/{taxYear}/{submissionId}  (v6.0)
    """
    assert_tax_year_at_most(tax_year)
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


@router.get("/property-period-summaries", tags=["Property Business — Period Summaries"])
async def list_period_summaries(
    request: Request,
    x_session_id: Optional[str] = Header(None),
    business_id: str = Query(
        ...,
        alias="businessId",
        description="UK or foreign property businessId from GET /business-details",
    ),
    tax_year: str = Query(
        ...,
        alias="taxYear",
        description="HMRC tax year e.g. '2024-25' (≤ 2024-25)",
    ),
    gov_test_scenario: Optional[str] = Query(
        None,
        alias="govTestScenario",
        description="Sandbox-only. Sets HMRC Gov-Test-Scenario header. Omit in production.",
    ),
):
    """
    List property income & expenses period summaries (UK or foreign, ≤ 2024-25).

    HMRC endpoint (shared path — no uk/foreign segment):
        GET /individuals/business/property/{nino}/{businessId}/period/{taxYear}  (v6.0)
    """
    assert_tax_year_at_most(tax_year)
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)

    data = await client.list_property_period_summaries(
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


@router.post("/foreign-period", tags=["Property Business — Period Summaries"])
async def create_foreign_period(
    request: Request,
    body: dict = Body(
        ...,
        description=(
            "HMRC foreign period create body: fromDate, toDate, and "
            "foreignFhlEea and/or foreignNonFhlProperty[] (with countryCode)."
        ),
        openapi_examples={
            "foreign_non_fhl": {
                "summary": "Foreign non-FHL create (TY 2024-25)",
                "value": HMRC_FOREIGN_PERIOD_CREATE_EXAMPLE,
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
        description="HMRC tax year e.g. '2024-25' (≤ 2024-25)",
    ),
    gov_test_scenario: Optional[str] = Query(
        None,
        alias="govTestScenario",
        description="Sandbox-only. Sets HMRC Gov-Test-Scenario header. Omit in production.",
    ),
):
    """
    Create a foreign property income & expenses period summary (≤ 2024-25).

    From 2025-26 use PUT /foreign-cumulative instead.

    HMRC endpoint:
        POST /individuals/business/property/foreign/{nino}/{businessId}/period/{taxYear}  (v6.0)
    """
    assert_tax_year_at_most(tax_year)
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)
    result = await client.create_foreign_period_summary(
        nino=nino,
        business_id=business_id,
        tax_year=tax_year,
        body=body,
        gov_test_scenario=gov_test_scenario,
    )
    return {
        "success":    True,
        "action":     "created",
        "businessId": business_id,
        "taxYear":    tax_year,
        "result":     result,
    }


@router.get("/foreign-period", tags=["Property Business — Period Summaries"])
async def get_foreign_period(
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
        description="HMRC tax year e.g. '2024-25' (≤ 2024-25)",
    ),
    submission_id: str = Query(
        ...,
        alias="submissionId",
        description="submissionId from POST /foreign-period or GET /property-period-summaries",
    ),
    gov_test_scenario: Optional[str] = Query(
        None,
        alias="govTestScenario",
        description="Sandbox-only. Sets HMRC Gov-Test-Scenario header. Omit in production.",
    ),
):
    """
    Retrieve a foreign property income & expenses period summary (≤ 2024-25).

    HMRC endpoint:
        GET /individuals/business/property/foreign/{nino}/{businessId}/period/{taxYear}/{submissionId}  (v6.0)
    """
    assert_tax_year_at_most(tax_year)
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)
    data = await client.get_foreign_period_summary(
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


@router.put("/foreign-period", tags=["Property Business — Period Summaries"])
async def amend_foreign_period(
    request: Request,
    body: dict = Body(
        ...,
        description=(
            "HMRC foreign period amend body. Do not include fromDate/toDate. "
            "Pass foreignFhlEea and/or foreignNonFhlProperty[]."
        ),
        openapi_examples={
            "foreign_non_fhl": {
                "summary": "Foreign non-FHL amend (TY 2024-25)",
                "value": HMRC_FOREIGN_PERIOD_AMEND_EXAMPLE,
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
        description="HMRC tax year e.g. '2024-25' (≤ 2024-25)",
    ),
    submission_id: str = Query(
        ...,
        alias="submissionId",
        description="submissionId from POST /foreign-period or GET /property-period-summaries",
    ),
    gov_test_scenario: Optional[str] = Query(
        None,
        alias="govTestScenario",
        description="Sandbox-only. Sets HMRC Gov-Test-Scenario header. Omit in production.",
    ),
):
    """
    Amend a foreign property income & expenses period summary (≤ 2024-25).

    HMRC endpoint:
        PUT /individuals/business/property/foreign/{nino}/{businessId}/period/{taxYear}/{submissionId}  (v6.0)
    """
    assert_tax_year_at_most(tax_year)
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)
    result = await client.amend_foreign_period_summary(
        nino=nino,
        business_id=business_id,
        tax_year=tax_year,
        submission_id=submission_id,
        body=body,
        gov_test_scenario=gov_test_scenario,
    )
    return {
        "success":      True,
        "action":       "amended",
        "businessId":   business_id,
        "taxYear":      tax_year,
        "submissionId": submission_id,
        "result":       result,
    }


# ── Historic UK Property (FHL / Non-FHL, 2017-18 to 2021-22) ───────────────────────
# No businessId — NINO (+ taxYear or periodId) only.

HMRC_HISTORIC_FHL_ANNUAL_EXAMPLE = {
    "annualAdjustments": {
        "lossBroughtForward": 200.00,
        "balancingCharge": 200.00,
        "privateUseAdjustment": 200.00,
        "periodOfGraceAdjustment": True,
        "businessPremisesRenovationAllowanceBalancingCharges": 200.02,
        "nonResidentLandlord": True,
        "rentARoom": {"jointlyLet": True},
    },
    "annualAllowances": {
        "annualInvestmentAllowance": 200.00,
        "otherCapitalAllowance": 200.00,
        "businessPremisesRenovationAllowance": 100.02,
        "propertyIncomeAllowance": 10.02,
    },
}

HMRC_HISTORIC_NON_FHL_ANNUAL_EXAMPLE = {
    "annualAdjustments": {
        "lossBroughtForward": 200.00,
        "balancingCharge": 200.00,
        "privateUseAdjustment": 200.00,
        "businessPremisesRenovationAllowanceBalancingCharges": 80.02,
        "nonResidentLandlord": True,
        "rentARoom": {"jointlyLet": True},
    },
    "annualAllowances": {
        "annualInvestmentAllowance": 200.00,
        "zeroEmissionGoodsVehicleAllowance": 200.00,
        "businessPremisesRenovationAllowance": 200.00,
        "otherCapitalAllowance": 200.00,
        "costOfReplacingDomesticGoods": 200.00,
        "propertyIncomeAllowance": 30.02,
    },
}

HMRC_HISTORIC_FHL_PERIOD_CREATE_EXAMPLE = {
    "fromDate": "2019-04-06",
    "toDate": "2019-07-05",
    "income": {
        "periodAmount": 100.25,
        "taxDeducted": 100.25,
        "rentARoom": {"rentsReceived": 100.25},
    },
    "expenses": {
        "premisesRunningCosts": 100.25,
        "repairsAndMaintenance": 100.25,
        "financialCosts": 100.25,
        "professionalFees": 100.25,
        "costOfServices": 100.25,
        "other": 100.25,
        "travelCosts": 100.25,
        "rentARoom": {"amountClaimed": 100.25},
    },
}

# HMRC amend schema uses singular premiseRunningCosts (create uses premisesRunningCosts).
HMRC_HISTORIC_FHL_PERIOD_AMEND_EXAMPLE = {
    "income": {
        "periodAmount": 1123.45,
        "taxDeducted": 2134.53,
        "rentARoom": {"rentsReceived": 5167.56},
    },
    "expenses": {
        "premiseRunningCosts": 5167.53,
        "repairsAndMaintenance": 424.65,
        "financialCosts": 853.56,
        "professionalFees": 835.78,
        "costOfServices": 978.34,
        "other": 382.34,
        "travelCosts": 145.56,
        "rentARoom": {"amountClaimed": 945.9},
    },
}

HMRC_HISTORIC_NON_FHL_PERIOD_CREATE_EXAMPLE = {
    "fromDate": "2019-04-06",
    "toDate": "2019-07-05",
    "income": {
        "periodAmount": 123.45,
        "premiumsOfLeaseGrant": 2355.45,
        "reversePremiums": 454.56,
        "otherIncome": 567.89,
        "taxDeducted": 234.53,
        "rentARoom": {"rentsReceived": 567.56},
    },
    "expenses": {
        "premisesRunningCosts": 567.53,
        "repairsAndMaintenance": 324.65,
        "financialCosts": 453.56,
        "professionalFees": 535.78,
        "costOfServices": 678.34,
        "other": 682.34,
        "travelCosts": 645.56,
        "residentialFinancialCostsCarriedForward": 672.34,
        "residentialFinancialCost": 1000.45,
        "rentARoom": {"amountClaimed": 545.9},
    },
}

HMRC_HISTORIC_NON_FHL_PERIOD_AMEND_EXAMPLE = {
    "income": {
        "periodAmount": 5000.99,
        "premiumsOfLeaseGrant": 5000.99,
        "reversePremiums": 5000.99,
        "otherIncome": 5000.99,
        "taxDeducted": 5000.99,
        "rentARoom": {"rentsReceived": 5000.99},
    },
    "expenses": {
        "premisesRunningCosts": 5000.99,
        "repairsAndMaintenance": 5000.99,
        "financialCosts": 5000.99,
        "professionalFees": 5000.99,
        "costOfServices": 5000.99,
        "other": 5000.99,
        "travelCosts": 5000.99,
        "residentialFinancialCostsCarriedForward": 5000.99,
        "residentialFinancialCost": 5000.99,
        "rentARoom": {"amountClaimed": 5000.99},
    },
}


@router.put("/historic-fhl-annual", tags=["Property Business — Historic"])
async def put_historic_fhl_annual(
    request: Request,
    body: dict = Body(
        ...,
        description="HMRC historic FHL annual body (annualAdjustments / annualAllowances).",
        openapi_examples={
            "fhl_annual": {
                "summary": "Historic FHL annual (2017-18 to 2021-22)",
                "value": HMRC_HISTORIC_FHL_ANNUAL_EXAMPLE,
            }
        },
    ),
    x_session_id: Optional[str] = Header(None),
    tax_year: str = Query(..., alias="taxYear", description="Tax year 2017-18 to 2021-22"),
    gov_test_scenario: Optional[str] = Query(None, alias="govTestScenario"),
):
    """
    Create/amend historic FHL UK property annual submission (2017-18 to 2021-22).

    HMRC: PUT /individuals/business/property/uk/annual/furnished-holiday-lettings/{nino}/{taxYear}
    """
    assert_tax_year_in_range(tax_year)
    session_id = _require_session(x_session_id)
    _tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)
    result = await client.amend_historic_fhl_annual(
        nino=nino, tax_year=tax_year, body=body, gov_test_scenario=gov_test_scenario,
    )
    return {"success": True, "taxYear": tax_year, "result": result}


@router.get("/historic-fhl-annual", tags=["Property Business — Historic"])
async def get_historic_fhl_annual(
    request: Request,
    x_session_id: Optional[str] = Header(None),
    tax_year: str = Query(..., alias="taxYear", description="Tax year 2017-18 to 2021-22"),
    gov_test_scenario: Optional[str] = Query(None, alias="govTestScenario"),
):
    """HMRC: GET .../uk/annual/furnished-holiday-lettings/{nino}/{taxYear}"""
    assert_tax_year_in_range(tax_year)
    session_id = _require_session(x_session_id)
    _tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)
    data = await client.get_historic_fhl_annual(
        nino=nino, tax_year=tax_year, gov_test_scenario=gov_test_scenario,
    )
    return {"nino": nino, "taxYear": tax_year, **data}


@router.delete("/historic-fhl-annual", tags=["Property Business — Historic"])
async def delete_historic_fhl_annual(
    request: Request,
    x_session_id: Optional[str] = Header(None),
    tax_year: str = Query(..., alias="taxYear", description="Tax year 2017-18 to 2021-22"),
    gov_test_scenario: Optional[str] = Query(None, alias="govTestScenario"),
):
    """HMRC: DELETE .../uk/annual/furnished-holiday-lettings/{nino}/{taxYear}"""
    assert_tax_year_in_range(tax_year)
    session_id = _require_session(x_session_id)
    _tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)
    result = await client.delete_historic_fhl_annual(
        nino=nino, tax_year=tax_year, gov_test_scenario=gov_test_scenario,
    )
    return {"success": True, "taxYear": tax_year, "result": result}


@router.put("/historic-non-fhl-annual", tags=["Property Business — Historic"])
async def put_historic_non_fhl_annual(
    request: Request,
    body: dict = Body(
        ...,
        description="HMRC historic Non-FHL annual body (annualAdjustments / annualAllowances).",
        openapi_examples={
            "non_fhl_annual": {
                "summary": "Historic Non-FHL annual (2017-18 to 2021-22)",
                "value": HMRC_HISTORIC_NON_FHL_ANNUAL_EXAMPLE,
            }
        },
    ),
    x_session_id: Optional[str] = Header(None),
    tax_year: str = Query(..., alias="taxYear", description="Tax year 2017-18 to 2021-22"),
    gov_test_scenario: Optional[str] = Query(None, alias="govTestScenario"),
):
    """HMRC: PUT .../uk/annual/non-furnished-holiday-lettings/{nino}/{taxYear}"""
    assert_tax_year_in_range(tax_year)
    session_id = _require_session(x_session_id)
    _tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)
    result = await client.amend_historic_non_fhl_annual(
        nino=nino, tax_year=tax_year, body=body, gov_test_scenario=gov_test_scenario,
    )
    return {"success": True, "taxYear": tax_year, "result": result}


@router.get("/historic-non-fhl-annual", tags=["Property Business — Historic"])
async def get_historic_non_fhl_annual(
    request: Request,
    x_session_id: Optional[str] = Header(None),
    tax_year: str = Query(..., alias="taxYear", description="Tax year 2017-18 to 2021-22"),
    gov_test_scenario: Optional[str] = Query(None, alias="govTestScenario"),
):
    """HMRC: GET .../uk/annual/non-furnished-holiday-lettings/{nino}/{taxYear}"""
    assert_tax_year_in_range(tax_year)
    session_id = _require_session(x_session_id)
    _tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)
    data = await client.get_historic_non_fhl_annual(
        nino=nino, tax_year=tax_year, gov_test_scenario=gov_test_scenario,
    )
    return {"nino": nino, "taxYear": tax_year, **data}


@router.delete("/historic-non-fhl-annual", tags=["Property Business — Historic"])
async def delete_historic_non_fhl_annual(
    request: Request,
    x_session_id: Optional[str] = Header(None),
    tax_year: str = Query(..., alias="taxYear", description="Tax year 2017-18 to 2021-22"),
    gov_test_scenario: Optional[str] = Query(None, alias="govTestScenario"),
):
    """HMRC: DELETE .../uk/annual/non-furnished-holiday-lettings/{nino}/{taxYear}"""
    assert_tax_year_in_range(tax_year)
    session_id = _require_session(x_session_id)
    _tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)
    result = await client.delete_historic_non_fhl_annual(
        nino=nino, tax_year=tax_year, gov_test_scenario=gov_test_scenario,
    )
    return {"success": True, "taxYear": tax_year, "result": result}


@router.get("/historic-fhl-period", tags=["Property Business — Historic"])
async def list_historic_fhl_periods(
    request: Request,
    x_session_id: Optional[str] = Header(None),
    gov_test_scenario: Optional[str] = Query(None, alias="govTestScenario"),
):
    """List historic FHL period summaries. HMRC: GET .../uk/period/furnished-holiday-lettings/{nino}"""
    session_id = _require_session(x_session_id)
    _tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)
    data = await client.list_historic_fhl_periods(nino=nino, gov_test_scenario=gov_test_scenario)
    return {"nino": nino, **data}


@router.post("/historic-fhl-period", tags=["Property Business — Historic"])
async def create_historic_fhl_period(
    request: Request,
    body: dict = Body(
        ...,
        description="fromDate, toDate, income, expenses. Tax year inferred from dates (2017-18 to 2021-22).",
        openapi_examples={
            "fhl_period_create": {
                "summary": "Historic FHL period create",
                "value": HMRC_HISTORIC_FHL_PERIOD_CREATE_EXAMPLE,
            }
        },
    ),
    x_session_id: Optional[str] = Header(None),
    gov_test_scenario: Optional[str] = Query(None, alias="govTestScenario"),
):
    """Create historic FHL period. Returns periodId. HMRC: POST .../furnished-holiday-lettings/{nino}"""
    assert_historic_period_body(body)
    session_id = _require_session(x_session_id)
    _tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)
    result = await client.create_historic_fhl_period(
        nino=nino, body=body, gov_test_scenario=gov_test_scenario,
    )
    return {"success": True, "action": "created", "result": result}


@router.get("/historic-fhl-period/{period_id}", tags=["Property Business — Historic"])
async def get_historic_fhl_period(
    period_id: str,
    request: Request,
    x_session_id: Optional[str] = Header(None),
    gov_test_scenario: Optional[str] = Query(None, alias="govTestScenario"),
):
    """Retrieve historic FHL period. periodId e.g. 2019-04-06_2019-07-05"""
    assert_historic_period_id(period_id)
    session_id = _require_session(x_session_id)
    _tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)
    data = await client.get_historic_fhl_period(
        nino=nino, period_id=period_id, gov_test_scenario=gov_test_scenario,
    )
    return {"nino": nino, "periodId": period_id, **data}


@router.put("/historic-fhl-period/{period_id}", tags=["Property Business — Historic"])
async def amend_historic_fhl_period(
    period_id: str,
    request: Request,
    body: dict = Body(
        ...,
        description=(
            "income/expenses only — no fromDate/toDate. "
            "Note: HMRC amend schema uses premiseRunningCosts (singular)."
        ),
        openapi_examples={
            "fhl_period_amend": {
                "summary": "Historic FHL period amend",
                "value": HMRC_HISTORIC_FHL_PERIOD_AMEND_EXAMPLE,
            }
        },
    ),
    x_session_id: Optional[str] = Header(None),
    gov_test_scenario: Optional[str] = Query(None, alias="govTestScenario"),
):
    """Amend historic FHL period. HMRC: PUT .../furnished-holiday-lettings/{nino}/{periodId}"""
    assert_historic_period_id(period_id)
    session_id = _require_session(x_session_id)
    _tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)
    result = await client.amend_historic_fhl_period(
        nino=nino, period_id=period_id, body=body, gov_test_scenario=gov_test_scenario,
    )
    return {"success": True, "action": "amended", "periodId": period_id, "result": result}


@router.get("/historic-non-fhl-period", tags=["Property Business — Historic"])
async def list_historic_non_fhl_periods(
    request: Request,
    x_session_id: Optional[str] = Header(None),
    gov_test_scenario: Optional[str] = Query(None, alias="govTestScenario"),
):
    """List historic Non-FHL period summaries. HMRC: GET .../non-furnished-holiday-lettings/{nino}"""
    session_id = _require_session(x_session_id)
    _tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)
    data = await client.list_historic_non_fhl_periods(
        nino=nino, gov_test_scenario=gov_test_scenario,
    )
    return {"nino": nino, **data}


@router.post("/historic-non-fhl-period", tags=["Property Business — Historic"])
async def create_historic_non_fhl_period(
    request: Request,
    body: dict = Body(
        ...,
        description="fromDate, toDate, income, expenses. Tax year inferred from dates (2017-18 to 2021-22).",
        openapi_examples={
            "non_fhl_period_create": {
                "summary": "Historic Non-FHL period create",
                "value": HMRC_HISTORIC_NON_FHL_PERIOD_CREATE_EXAMPLE,
            }
        },
    ),
    x_session_id: Optional[str] = Header(None),
    gov_test_scenario: Optional[str] = Query(None, alias="govTestScenario"),
):
    """Create historic Non-FHL period. Returns periodId."""
    assert_historic_period_body(body)
    session_id = _require_session(x_session_id)
    _tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)
    result = await client.create_historic_non_fhl_period(
        nino=nino, body=body, gov_test_scenario=gov_test_scenario,
    )
    return {"success": True, "action": "created", "result": result}


@router.get("/historic-non-fhl-period/{period_id}", tags=["Property Business — Historic"])
async def get_historic_non_fhl_period(
    period_id: str,
    request: Request,
    x_session_id: Optional[str] = Header(None),
    gov_test_scenario: Optional[str] = Query(None, alias="govTestScenario"),
):
    """Retrieve historic Non-FHL period."""
    assert_historic_period_id(period_id)
    session_id = _require_session(x_session_id)
    _tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)
    data = await client.get_historic_non_fhl_period(
        nino=nino, period_id=period_id, gov_test_scenario=gov_test_scenario,
    )
    return {"nino": nino, "periodId": period_id, **data}


@router.put("/historic-non-fhl-period/{period_id}", tags=["Property Business — Historic"])
async def amend_historic_non_fhl_period(
    period_id: str,
    request: Request,
    body: dict = Body(
        ...,
        description="income/expenses only — no fromDate/toDate.",
        openapi_examples={
            "non_fhl_period_amend": {
                "summary": "Historic Non-FHL period amend",
                "value": HMRC_HISTORIC_NON_FHL_PERIOD_AMEND_EXAMPLE,
            }
        },
    ),
    x_session_id: Optional[str] = Header(None),
    gov_test_scenario: Optional[str] = Query(None, alias="govTestScenario"),
):
    """Amend historic Non-FHL period."""
    assert_historic_period_id(period_id)
    session_id = _require_session(x_session_id)
    _tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)
    result = await client.amend_historic_non_fhl_period(
        nino=nino, period_id=period_id, body=body, gov_test_scenario=gov_test_scenario,
    )
    return {"success": True, "action": "amended", "periodId": period_id, "result": result}


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


@router.put("/uk-cumulative", tags=["Property Business — UK Cumulative"])
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


@router.get("/uk-cumulative", tags=["Property Business — UK Cumulative"])
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

HMRC_FOREIGN_PROPERTY_CUMULATIVE_2025_EXAMPLE = {
    "fromDate": "2025-04-06",
    "toDate": "2025-07-05",
    "foreignProperty": [
        {
            "countryCode": "FRA",
            "income": {
                "rentIncome": {"rentAmount": 4882.23},
                "foreignTaxCreditRelief": False,
                "premiumsOfLeaseGrant": 884.72,
                "otherPropertyIncome": 7713.09,
                "foreignTaxPaidOrDeducted": 884.12,
                "specialWithholdingTaxOrUkTaxPaid": 847.72,
            },
            "expenses": {
                "premisesRunningCosts": 129.35,
                "repairsAndMaintenance": 7490.32,
                "financialCosts": 5000.99,
                "professionalFees": 847.90,
                "travelCosts": 69.20,
                "costOfServices": 478.23,
                "residentialFinancialCost": 879.28,
                "broughtFwdResidentialFinancialCost": 846.13,
                "other": 138.92,
            },
        }
    ],
}


@router.put("/foreign-cumulative", tags=["Property Business — Foreign Cumulative"])
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
            "hmrc_2025_26": {
                "summary": "Full expenses (TY 2025-26, countryCode)",
                "value": HMRC_FOREIGN_PROPERTY_CUMULATIVE_2025_EXAMPLE,
            },
            "hmrc_2026_27": {
                "summary": "Full expenses (TY 2026-27+, propertyId)",
                "value": HMRC_FOREIGN_PROPERTY_CUMULATIVE_EXAMPLE,
            },
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


@router.get("/foreign-cumulative", tags=["Property Business — Foreign Cumulative"])
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
