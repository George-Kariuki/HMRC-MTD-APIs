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

from fastapi import APIRouter, Header, HTTPException, Query, Request
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

class PeriodicSubmissionRequest(BaseModel):
    """
    Payload for creating or amending a UK property periodic submission.

    All monetary figures must be CUMULATIVE YEAR-TO-DATE (not just the quarter).
    start_date / end_date must exactly match the obligation periodStartDate /
    periodEndDate returned by GET /obligations.
    """

    income_source_id: str = Field(
        ..., description="businessId from GET /business-details"
    )
    start_date: str = Field(
        ..., description="Period start date YYYY-MM-DD (must match obligation)"
    )
    end_date: str = Field(
        ..., description="Period end date YYYY-MM-DD (must match obligation)"
    )
    tax_year: Optional[str] = Field(
        None,
        description="HMRC tax year e.g. '2024-25'. Derived automatically if omitted.",
    )
    property_type: str = Field(
        "ukNonFhlProperty",
        description="'ukNonFhlProperty' (standard BTL) or 'ukFhlProperty' (FHL)",
    )

    # ── Income (cumulative YTD) ──────────────────────────────────────────────────
    rent_income:              float = Field(0.0,  description="Total rental income (YTD)")
    premiums_of_lease_grant:  float = Field(0.0,  description="Premiums of lease grant (YTD)")
    reverse_premiums:         float = Field(0.0,  description="Reverse premiums (YTD)")
    other_income:             float = Field(0.0,  description="Other property income (YTD)")
    tax_deducted:             float = Field(0.0,  description="Tax already deducted (YTD)")

    # ── Expenses (cumulative YTD) ────────────────────────────────────────────────
    premises_running_costs:   float = Field(0.0,  description="Premises running costs (YTD)")
    repairs_and_maintenance:  float = Field(0.0,  description="Repairs and maintenance (YTD)")
    financial_costs:          float = Field(0.0,  description="Financial costs / mortgage interest (YTD)")
    professional_fees:        float = Field(0.0,  description="Professional fees (YTD)")
    cost_of_services:         float = Field(0.0,  description="Cost of services (YTD)")
    other_expenses:           float = Field(0.0,  description="Other expenses (YTD)")
    residential_financial_cost: float = Field(0.0, description="Residential financial cost (YTD)")
    travel_costs:             float = Field(0.0,  description="Travel costs (YTD)")

    # ── Amendment ────────────────────────────────────────────────────────────────
    submission_id: Optional[str] = Field(
        None,
        description=(
            "If provided, amends an existing submission (PUT). "
            "Omit to create a new one (POST)."
        ),
    )


@router.post("/submit-periodic", tags=["HMRC"])
async def submit_periodic(
    payload: PeriodicSubmissionRequest,
    request: Request,
    x_session_id: Optional[str] = Header(None),
):
    """
    Create or amend a cumulative year-to-date periodic property income/expense return.

    Workflow:
      1. Call GET /obligations to get open obligation periods
      2. Use periodStartDate / periodEndDate from the obligation as start_date / end_date
      3. Call this endpoint with all YTD income + expense totals
      4. If amending (re-submitting for the same period), include the submission_id

    Behaviour:
      - No submission_id → POST (create new)
      - submission_id provided → PUT (amend existing)

    HMRC endpoint (create):  POST /individuals/business/property/uk/{nino}/{bid}/period/{ty}
    HMRC endpoint (amend):   PUT  /individuals/business/property/uk/{nino}/{bid}/period/{ty}/{sid}
    Both use Accept v6.0.
    """
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)

    # Derive tax year from the obligation start date if not explicitly supplied
    tax_year = payload.tax_year or derive_tax_year(payload.start_date)

    income = {
        "periodAmount":          round(payload.rent_income, 2),
        "premiumsOfLeaseGrant":  round(payload.premiums_of_lease_grant, 2),
        "reversePremiums":       round(payload.reverse_premiums, 2),
        "otherIncome":           round(payload.other_income, 2),
        "taxDeducted":           round(payload.tax_deducted, 2),
    }
    expenses = {
        "premisesRunningCosts":   round(payload.premises_running_costs, 2),
        "repairsAndMaintenance":  round(payload.repairs_and_maintenance, 2),
        "financialCosts":         round(payload.financial_costs, 2),
        "professionalFees":       round(payload.professional_fees, 2),
        "costOfServices":         round(payload.cost_of_services, 2),
        "other":                  round(payload.other_expenses, 2),
        "residentialFinancialCost": round(payload.residential_financial_cost, 2),
        "travelCosts":            round(payload.travel_costs, 2),
    }

    client = await _build_client(request, session_id)

    if payload.submission_id:
        result = await client.amend_period_summary(
            nino=nino,
            business_id=payload.income_source_id,
            tax_year=tax_year,
            submission_id=payload.submission_id,
            from_date=payload.start_date,
            to_date=payload.end_date,
            income=income,
            expenses=expenses,
            property_type=payload.property_type,
        )
        action = "amended"
    else:
        result = await client.create_period_summary(
            nino=nino,
            business_id=payload.income_source_id,
            tax_year=tax_year,
            from_date=payload.start_date,
            to_date=payload.end_date,
            income=income,
            expenses=expenses,
            property_type=payload.property_type,
        )
        action = "created"

    return {
        "success":    True,
        "action":     action,
        "taxYear":    tax_year,
        "fromDate":   payload.start_date,
        "toDate":     payload.end_date,
        "businessId": payload.income_source_id,
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


class AnnualSubmissionRequest(BaseModel):
    """
    Create or amend a UK property business annual submission (allowances & adjustments).

    Fields are split into FHL (Furnished Holiday Letting) and non-FHL (standard BTL).
    Only populate the section relevant to your property type — HMRC ignores the other.

    Postman reference: Property Business → Annual Submissions → Create and Amend
    HMRC endpoint: PUT /individuals/business/property/uk/{nino}/{businessId}/annual/{taxYear} v6.0
    """
    income_source_id: str = Field(..., description="businessId from GET /business-details")
    tax_year: str          = Field(..., description="HMRC tax year e.g. '2024-25'")

    # ── Non-FHL (Standard Buy-to-Let) ────────────────────────────────────────────
    uk_property_income_allowance: Optional[float] = Field(
        None, description="[Non-FHL] Property income allowance (£)"
    )
    uk_balancing_charge: Optional[float] = Field(
        None, description="[Non-FHL] Balancing charge (£)"
    )
    uk_bpra_balancing_charges: Optional[float] = Field(
        None,
        description="[Non-FHL] Business premises renovation allowance balancing charges (£)",
    )
    uk_non_resident_landlord: Optional[bool] = Field(
        None, description="[Non-FHL] Is the landlord non-resident?"
    )
    uk_rent_a_room_jointly_let: Optional[bool] = Field(
        None, description="[Non-FHL] Rent-a-room: is the property jointly let?"
    )

    # ── FHL (Furnished Holiday Letting) ──────────────────────────────────────────
    fhl_property_income_allowance: Optional[float] = Field(
        None, description="[FHL] Property income allowance (£)"
    )
    fhl_balancing_charge: Optional[float] = Field(
        None, description="[FHL] Balancing charge (£)"
    )
    fhl_period_of_grace_adjustment: Optional[bool] = Field(
        None, description="[FHL] Period of grace adjustment applies?"
    )
    fhl_bpra_balancing_charges: Optional[float] = Field(
        None,
        description="[FHL] Business premises renovation allowance balancing charges (£)",
    )
    fhl_non_resident_landlord: Optional[bool] = Field(
        None, description="[FHL] Is the landlord non-resident?"
    )
    fhl_rent_a_room_jointly_let: Optional[bool] = Field(
        None, description="[FHL] Rent-a-room: is the property jointly let?"
    )


@router.put("/submit-annual", tags=["HMRC"])
async def submit_annual(
    payload: AnnualSubmissionRequest,
    request: Request,
    x_session_id: Optional[str] = Header(None),
):
    """
    Create or amend the annual UK property business allowances and adjustments.

    Populate the Non-FHL fields for a standard buy-to-let, or the FHL fields for
    a Furnished Holiday Letting.  Fields left blank (None) are omitted from the
    HMRC request.

    HMRC endpoint:
        PUT /individuals/business/property/uk/{nino}/{businessId}/annual/{taxYear}  (v6.0)
    """
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)

    def _opt(v):
        return round(v, 2) if v is not None else None

    # Build ukProperty block (non-FHL) only if any field is set
    uk_allowances = {k: v for k, v in {
        "propertyIncomeAllowance": _opt(payload.uk_property_income_allowance),
    }.items() if v is not None}
    uk_adjustments = {k: v for k, v in {
        "balancingCharge":                                _opt(payload.uk_balancing_charge),
        "businessPremisesRenovationAllowanceBalancingCharges": _opt(payload.uk_bpra_balancing_charges),
        "nonResidentLandlord":                            payload.uk_non_resident_landlord,
        "rentARoom": {"jointlyLet": payload.uk_rent_a_room_jointly_let}
                     if payload.uk_rent_a_room_jointly_let is not None else None,
    }.items() if v is not None}
    uk_property = {}
    if uk_allowances:
        uk_property["allowances"] = uk_allowances
    if uk_adjustments:
        uk_property["adjustments"] = uk_adjustments

    # Build ukFhlProperty block only if any field is set
    fhl_allowances = {k: v for k, v in {
        "propertyIncomeAllowance": _opt(payload.fhl_property_income_allowance),
    }.items() if v is not None}
    fhl_adjustments = {k: v for k, v in {
        "balancingCharge":                                _opt(payload.fhl_balancing_charge),
        "periodOfGraceAdjustment":                        payload.fhl_period_of_grace_adjustment,
        "businessPremisesRenovationAllowanceBalancingCharges": _opt(payload.fhl_bpra_balancing_charges),
        "nonResidentLandlord":                            payload.fhl_non_resident_landlord,
        "rentARoom": {"jointlyLet": payload.fhl_rent_a_room_jointly_let}
                     if payload.fhl_rent_a_room_jointly_let is not None else None,
    }.items() if v is not None}
    fhl_property = {}
    if fhl_allowances:
        fhl_property["allowances"] = fhl_allowances
    if fhl_adjustments:
        fhl_property["adjustments"] = fhl_adjustments

    body: dict = {}
    if uk_property:
        body["ukProperty"] = uk_property
    if fhl_property:
        body["ukFhlProperty"] = fhl_property

    result = await client.amend_annual_submission(
        nino=nino,
        business_id=payload.income_source_id,
        tax_year=payload.tax_year,
        body=body,
    )
    return {"success": True, "taxYear": payload.tax_year, "businessId": payload.income_source_id, "result": result}


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


class UKPropertyCumulativeRequest(BaseModel):
    """
    Create or amend a UK property cumulative income & expenses period summary.

    All monetary values are CUMULATIVE YEAR-TO-DATE (not just the current quarter).
    from_date / to_date must fall within the accounting periods returned by
    GET /business-details/{businessId}/periods-of-account.

    Use property_type = "ukNonFhlProperty" for standard buy-to-let,
    or "ukFhlProperty" for Furnished Holiday Lettings.

    Postman reference: Property Business → Income and Expenses Period Summaries
    HMRC endpoint: PUT /individuals/business/property/uk/{nino}/{businessId}/cumulative/{taxYear} v6.0
    """
    income_source_id: str = Field(..., description="businessId from GET /business-details")
    tax_year: str          = Field(..., description="HMRC tax year e.g. '2024-25'")
    from_date: str         = Field(..., description="Period start date YYYY-MM-DD")
    to_date: str           = Field(..., description="Period end date YYYY-MM-DD")
    property_type: str     = Field(
        "ukNonFhlProperty",
        description="'ukNonFhlProperty' (standard BTL) or 'ukFhlProperty' (FHL)",
    )

    # ── Income (cumulative YTD) ───────────────────────────────────────────────────
    rent_income: float              = Field(0.0, description="Total rental income received (YTD)")
    premiums_of_lease_grant: float  = Field(0.0, description="Premiums of lease grant (YTD)")
    reverse_premiums: float         = Field(0.0, description="Reverse premiums (YTD)")
    other_income: float             = Field(0.0, description="Other property income (YTD)")
    tax_deducted: float             = Field(0.0, description="Tax already deducted at source (YTD)")

    # ── Expenses (cumulative YTD) ─────────────────────────────────────────────────
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
    payload: UKPropertyCumulativeRequest,
    request: Request,
    x_session_id: Optional[str] = Header(None),
):
    """
    Create or amend a UK property cumulative period summary (income & expenses YTD).

    Use GET /business-details/{businessId}/periods-of-account to find valid date ranges.
    All figures must be cumulative year-to-date totals.

    HMRC endpoint:
        PUT /individuals/business/property/uk/{nino}/{businessId}/cumulative/{taxYear}  (v6.0)
    """
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)

    body = {
        "fromDate": payload.from_date,
        "toDate":   payload.to_date,
        payload.property_type: {
            "income": {
                "periodAmount":         round(payload.rent_income, 2),
                "premiumsOfLeaseGrant": round(payload.premiums_of_lease_grant, 2),
                "reversePremiums":      round(payload.reverse_premiums, 2),
                "otherIncome":          round(payload.other_income, 2),
                "taxDeducted":          round(payload.tax_deducted, 2),
            },
            "expenses": {
                "premisesRunningCosts":     round(payload.premises_running_costs, 2),
                "repairsAndMaintenance":    round(payload.repairs_and_maintenance, 2),
                "financialCosts":           round(payload.financial_costs, 2),
                "professionalFees":         round(payload.professional_fees, 2),
                "costOfServices":           round(payload.cost_of_services, 2),
                "other":                    round(payload.other_expenses, 2),
                "residentialFinancialCost": round(payload.residential_financial_cost, 2),
                "travelCosts":              round(payload.travel_costs, 2),
            },
        },
    }

    result = await client.create_or_amend_uk_property_cumulative(
        nino=nino,
        business_id=payload.income_source_id,
        tax_year=payload.tax_year,
        body=body,
    )
    return {
        "success":    True,
        "action":     "created_or_amended",
        "businessId": payload.income_source_id,
        "taxYear":    payload.tax_year,
        "fromDate":   payload.from_date,
        "toDate":     payload.to_date,
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


class SelfEmploymentCumulativeRequest(BaseModel):
    """
    Create or amend a self-employment cumulative period summary.

    All monetary values are CUMULATIVE YEAR-TO-DATE (not just the current quarter).
    period_start_date / period_end_date are the accounting period boundaries.

    Postman reference: Self Employment Business (MTD) (5.0) → Self-Employment Cumulative Period Summary
    HMRC endpoint: PUT /individuals/business/self-employment/{nino}/{businessId}/cumulative/{taxYear} v5.0
    """
    income_source_id: str  = Field(..., description="businessId for the self-employment income source")
    tax_year: str          = Field(..., description="HMRC tax year e.g. '2024-25'")
    period_start_date: str = Field(..., description="Period start date YYYY-MM-DD e.g. '2025-04-06'")
    period_end_date: str   = Field(..., description="Period end date YYYY-MM-DD e.g. '2025-07-05'")

    # ── Income (cumulative YTD) ───────────────────────────────────────────────────
    turnover: float     = Field(0.0, description="Turnover / gross receipts (YTD)")
    other_income: float = Field(0.0, description="Other business income not included in turnover (YTD)")

    # ── Expenses (cumulative YTD) — from Postman collection body ─────────────────
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
    payload: SelfEmploymentCumulativeRequest,
    request: Request,
    x_session_id: Optional[str] = Header(None),
):
    """
    Create or amend a self-employment cumulative period summary.

    Provide cumulative year-to-date income and expense totals. HMRC assembles the
    submission from periodDates, periodIncome and periodExpenses automatically.

    HMRC endpoint:
        PUT /individuals/business/self-employment/{nino}/{businessId}/cumulative/{taxYear}  (v5.0)
    """
    session_id = _require_session(x_session_id)
    tokens, nino = _require_nino(session_id)
    client = await _build_client(request, session_id)

    body = {
        "periodDates": {
            "periodStartDate": payload.period_start_date,
            "periodEndDate":   payload.period_end_date,
        },
        "periodIncome": {
            "turnover": round(payload.turnover, 2),
            "other":    round(payload.other_income, 2),
        },
        "periodExpenses": {
            "costOfGoods":                round(payload.cost_of_goods, 2),
            "paymentsToSubcontractors":   round(payload.payments_to_subcontractors, 2),
            "wagesAndStaffCosts":         round(payload.wages_and_staff_costs, 2),
            "carVanTravelExpenses":       round(payload.car_van_travel_expenses, 2),
            "premisesRunningCosts":       round(payload.premises_running_costs, 2),
            "maintenanceCosts":           round(payload.maintenance_costs, 2),
            "adminCosts":                 round(payload.admin_costs, 2),
            "businessEntertainmentCosts": round(payload.business_entertainment_costs, 2),
            "advertisingCosts":           round(payload.advertising_costs, 2),
            "interestOnBankOtherLoans":   round(payload.interest_on_bank_other_loans, 2),
        },
    }

    result = await client.create_or_amend_self_employment_cumulative(
        nino=nino,
        business_id=payload.income_source_id,
        tax_year=payload.tax_year,
        body=body,
    )
    return {
        "success":         True,
        "action":          "created_or_amended",
        "businessId":      payload.income_source_id,
        "taxYear":         payload.tax_year,
        "periodStartDate": payload.period_start_date,
        "periodEndDate":   payload.period_end_date,
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
