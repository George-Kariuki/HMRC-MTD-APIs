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
from hmrc_client import HMRCClient, derive_tax_year

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

@router.get("/business-details", tags=["HMRC"])
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
            "accountingType":   b.get("accountingType"),
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

@router.get("/obligations", tags=["HMRC"])
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


@router.post("/submit-periodic", tags=["HMRC"])
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

@router.get("/business-details/{business_id}", tags=["HMRC"])
async def retrieve_business(
    business_id: str,
    request: Request,
    x_session_id: Optional[str] = Header(None),
):
    """
    Retrieve the full details of a single income source by its businessId.

    Use this after GET /business-details (list all) to inspect a specific business:
    accountingType, commencementDate, latencyDetails, etc.

    HMRC endpoint:  GET /individuals/business/details/{nino}/{businessId}  (v2.0)
    """
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)
    data = await client.retrieve_business(nino, business_id)
    return {"nino": nino, "businessId": business_id, **data}


@router.get("/business-details/{business_id}/periods-of-account", tags=["HMRC"])
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


@router.put("/submit-annual", tags=["HMRC"])
async def submit_annual(
    body: dict = Body(
        ...,
        description=(
            "HMRC annual property business submission body. "
            "Pass the body exactly as HMRC documents for your tax year (e.g. ukProperty / foreignProperty, etc.)."
        ),
        examples={"hmrc_example": {"summary": "HMRC example body", "value": HMRC_ANNUAL_SUBMISSION_EXAMPLE}},
    ),
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


@router.get("/annual-submission", tags=["HMRC"])
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
    )
    return {
        "nino":       nino,
        "businessId": business_id,
        "taxYear":    tax_year,
        **data,
    }


@router.get("/period-summary", tags=["HMRC"])
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
    """Income and expense amounts for a UK property cumulative period summary (all YTD)."""

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


@router.put("/property-cumulative", tags=["HMRC"])
async def submit_property_cumulative(
    amounts: PropertyIncomeBody,
    request: Request,
    x_session_id: Optional[str] = Header(None),
    business_id: str = Query(..., alias="businessId", description="businessId from GET /business-details"),
    tax_year: str = Query(..., alias="taxYear", description="HMRC tax year e.g. '2024-25'"),
    from_date: str = Query(..., alias="fromDate", description="Period start YYYY-MM-DD (from periods-of-account)"),
    to_date: str = Query(..., alias="toDate", description="Period end YYYY-MM-DD"),
    property_type: str = Query("ukNonFhlProperty", alias="propertyType", description="'ukNonFhlProperty' or 'ukFhlProperty'"),
):
    """
    Create or amend a UK property cumulative income & expenses period summary (YTD).

    **Routing parameters** (shown above): businessId, taxYear, fromDate, toDate, propertyType.
    **Financial amounts** (in the request body): all income and expense figures — cumulative YTD.

    HMRC endpoint:
        PUT /individuals/business/property/uk/{nino}/{businessId}/cumulative/{taxYear}  (v6.0)
    """
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)

    body = {
        "fromDate": from_date,
        "toDate":   to_date,
        property_type: {
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
        },
    }

    result = await client.create_or_amend_uk_property_cumulative(
        nino=nino,
        business_id=business_id,
        tax_year=tax_year,
        body=body,
    )
    return {
        "success":    True,
        "action":     "created_or_amended",
        "businessId": business_id,
        "taxYear":    tax_year,
        "fromDate":   from_date,
        "toDate":     to_date,
        "result":     result,
    }


@router.get("/property-cumulative", tags=["HMRC"])
async def get_property_cumulative(
    request: Request,
    x_session_id: Optional[str] = Header(None),
    business_id: str = Query(..., alias="businessId", description="businessId from GET /business-details"),
    tax_year: str = Query(..., alias="taxYear", description="HMRC tax year e.g. '2024-25'"),
):
    """
    Retrieve the current cumulative period summary (income & expenses YTD) for a
    UK property business.

    HMRC endpoint:
        GET /individuals/business/property/uk/{nino}/{businessId}/cumulative/{taxYear}  (v6.0)
    """
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)

    data = await client.retrieve_uk_property_cumulative(
        nino=nino,
        business_id=business_id,
        tax_year=tax_year,
    )
    return {
        "nino":       nino,
        "businessId": business_id,
        "taxYear":    tax_year,
        **data,
    }


# ── Self-Employment Cumulative Period Summary ──────────────────────────────────────


class SEIncomeBody(BaseModel):
    """Income and expense amounts for a self-employment cumulative period summary (all YTD)."""

    # ── Income ───────────────────────────────────────────────────────────────────
    turnover: float     = Field(0.0, description="Turnover / gross receipts (YTD)")
    other_income: float = Field(0.0, description="Other business income not included in turnover (YTD)")

    # ── Expenses ─────────────────────────────────────────────────────────────────
    cost_of_goods: float                  = Field(0.0, description="Cost of goods bought for resale (YTD)")
    payments_to_subcontractors: float     = Field(0.0, description="Payments to subcontractors (YTD)")
    wages_and_staff_costs: float          = Field(0.0, description="Wages, salaries and other staff costs (YTD)")
    car_van_travel_expenses: float        = Field(0.0, description="Car, van and travel expenses (YTD)")
    premises_running_costs: float         = Field(0.0, description="Rent, rates, power and insurance costs (YTD)")
    maintenance_costs: float              = Field(0.0, description="Repairs and maintenance of property and equipment (YTD)")
    admin_costs: float                    = Field(0.0, description="Phone, fax, stationery and other office costs (YTD)")
    business_entertainment_costs: float   = Field(0.0, description="Business entertainment costs (YTD)")
    advertising_costs: float              = Field(0.0, description="Advertising costs (YTD)")
    interest_on_bank_other_loans: float   = Field(0.0, description="Interest on bank and other loans (YTD)")


@router.put("/self-employment-cumulative", tags=["HMRC"])
async def submit_self_employment_cumulative(
    amounts: SEIncomeBody,
    request: Request,
    x_session_id: Optional[str] = Header(None),
    business_id: str = Query(..., alias="businessId", description="businessId for the self-employment income source"),
    tax_year: str = Query(..., alias="taxYear", description="HMRC tax year e.g. '2024-25'"),
    period_start_date: str = Query(..., alias="periodStartDate", description="Period start YYYY-MM-DD e.g. '2025-04-06'"),
    period_end_date: str = Query(..., alias="periodEndDate", description="Period end YYYY-MM-DD e.g. '2025-07-05'"),
):
    """
    Create or amend a self-employment cumulative period summary.

    **Routing parameters** (shown above): businessId, taxYear, periodStartDate, periodEndDate.
    **Financial amounts** (in the request body): turnover, other income, and all expense fields — cumulative YTD.

    HMRC endpoint:
        PUT /individuals/business/self-employment/{nino}/{businessId}/cumulative/{taxYear}  (v5.0)
    """
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)

    body = {
        "periodDates": {
            "periodStartDate": period_start_date,
            "periodEndDate":   period_end_date,
        },
        "periodIncome": {
            "turnover": round(amounts.turnover, 2),
            "other":    round(amounts.other_income, 2),
        },
        "periodExpenses": {
            "costOfGoods":                round(amounts.cost_of_goods, 2),
            "paymentsToSubcontractors":   round(amounts.payments_to_subcontractors, 2),
            "wagesAndStaffCosts":         round(amounts.wages_and_staff_costs, 2),
            "carVanTravelExpenses":       round(amounts.car_van_travel_expenses, 2),
            "premisesRunningCosts":       round(amounts.premises_running_costs, 2),
            "maintenanceCosts":           round(amounts.maintenance_costs, 2),
            "adminCosts":                 round(amounts.admin_costs, 2),
            "businessEntertainmentCosts": round(amounts.business_entertainment_costs, 2),
            "advertisingCosts":           round(amounts.advertising_costs, 2),
            "interestOnBankOtherLoans":   round(amounts.interest_on_bank_other_loans, 2),
        },
    }

    result = await client.create_or_amend_self_employment_cumulative(
        nino=nino,
        business_id=business_id,
        tax_year=tax_year,
        body=body,
    )
    return {
        "success":         True,
        "action":          "created_or_amended",
        "businessId":      business_id,
        "taxYear":         tax_year,
        "periodStartDate": period_start_date,
        "periodEndDate":   period_end_date,
        "result":          result,
    }


@router.get("/self-employment-cumulative", tags=["HMRC"])
async def get_self_employment_cumulative(
    request: Request,
    x_session_id: Optional[str] = Header(None),
    business_id: str = Query(..., alias="businessId", description="businessId for the self-employment business"),
    tax_year: str = Query(..., alias="taxYear", description="HMRC tax year e.g. '2024-25'"),
):
    """
    Retrieve the current self-employment cumulative period summary for the given
    business and tax year.

    HMRC endpoint:
        GET /individuals/business/self-employment/{nino}/{businessId}/cumulative/{taxYear}  (v5.0)
    """
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)

    data = await client.retrieve_self_employment_cumulative(
        nino=nino,
        business_id=business_id,
        tax_year=tax_year,
    )
    return {
        "nino":       nino,
        "businessId": business_id,
        "taxYear":    tax_year,
        **data,
    }
