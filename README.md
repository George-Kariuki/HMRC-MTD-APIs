# HMRC MTD & Xero — Property Landlord Backend API

A FastAPI backend for property landlords built with Adalo. Integrates:
- **HMRC Making Tax Digital** (Income Tax Self Assessment) — obligations, periodic submissions
- **Xero Accounting** — bank accounts and bank transactions

---

## Architecture

```
Adalo Frontend
    │
    │  Simple REST calls (X-Session-ID / X-Xero-Session-ID header)
    ▼
FastAPI Backend  ◄──► SQLite (tokens)
    │              │
    │  HMRC MTD    │  Xero Accounting
    │  OAuth 2.0   │  OAuth 2.0
    │  Fraud Hdrs  │  Token refresh
    ▼              ▼
HMRC API       Xero API
```

All OAuth 2.0 complexity lives here — Adalo only calls simple REST endpoints.

---

## Project Structure

```
.
├── main.py           # FastAPI app, public auth routes, startup
├── auth.py           # HMRC OAuth 2.0 flow + token refresh
├── hmrc_client.py    # HMRC API client + fraud header generation
├── routes.py         # HMRC: Business Details, Obligations, Submissions
├── database.py       # SQLite: HMRC token store
├── xero_auth.py      # Xero OAuth 2.0 flow + token refresh
├── xero_client.py    # Xero Accounting API client
├── xero_routes.py    # Xero: bank accounts, transactions, sync
├── xero_database.py  # SQLite: Xero token + session store
├── requirements.txt
├── .env.example      # Copy to .env and fill in credentials
├── vercel.json       # Vercel deployment config
└── README.md
```

---

## Setup

### 1. Register an HMRC Developer Application

1. Go to [HMRC Developer Hub](https://developer.service.hmrc.gov.uk/)
2. Create an application and enable these APIs:
   - Business Details (MTD)
   - Obligations API (MTD)
   - Property Business (MTD)
3. Set the redirect URI to your callback URL (e.g. `https://your-app.vercel.app/auth/callback`)
4. Copy the **Client ID** and **Client Secret**

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env with your credentials
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Run Locally

```bash
uvicorn main:app --reload --port 8000
```

API docs available at: http://localhost:8000/docs

---

## API Reference

### Authentication Flow

| Step | Call | Description |
|------|------|-------------|
| 1 | `GET /auth/login-url` | Returns `{"auth_url": "..."}` — open this in browser |
| 2 | User logs in at HMRC | HMRC redirects to your `/auth/callback` |
| 3 | `GET /auth/callback?code=...&state=...` | Returns `{"session_id": "..."}` |
| 4 | `POST /auth/set-nino` | Associate user's NINO with session |

> **Adalo**: Store the `session_id` in user profile. Send it as `X-Session-ID` header on all subsequent calls.

---

### Headers Required by Adalo

Every call after login must include:

```
X-Session-ID: <session_id from /auth/callback>
```

---

### Endpoints

#### `GET /auth/login-url`
Returns the HMRC OAuth URL for Adalo to open.

```json
{ "auth_url": "https://test-api.service.hmrc.gov.uk/oauth/authorize?..." }
```

#### `GET /auth/callback?code=...&state=...`
Exchanges code for tokens. Returns:

```json
{
  "session_id": "550e8400-e29b-41d4-a716-446655440000",
  "message": "Authentication successful. Store this session_id..."
}
```

#### `POST /auth/set-nino`
Associates the user's NINO with their session.

```json
{ "nino": "AA123456A" }
```

#### `GET /business-details`
Returns all property income sources for the user.

```json
{
  "nino": "AA123456A",
  "propertyBusinesses": [
    {
      "businessId": "XAIS12345678910",
      "typeOfBusiness": "uk-property",
      "tradingName": null,
      "commencementDate": "2020-01-01"
    }
  ]
}
```

#### `GET /obligations?status=Open`
Returns open (unfiled) obligation periods. The `periodStartDate` and `periodEndDate` **must** be used as `start_date` and `end_date` when submitting.

```json
{
  "obligations": [
    {
      "businessId": "XAIS12345678910",
      "typeOfBusiness": "uk-property",
      "periodStartDate": "2024-04-06",
      "periodEndDate": "2025-01-05",
      "dueDate": "2025-01-31",
      "status": "Open",
      "taxYear": "2024-25"
    }
  ]
}
```

#### `POST /submit-periodic`
Submit cumulative year-to-date income and expenses.

```json
{
  "income_source_id": "XAIS12345678910",
  "start_date": "2024-04-06",
  "end_date": "2025-01-05",
  "tax_year": "2024-25",
  "rent_income": 12000.00,
  "financial_costs": 3600.00,
  "repairs_and_maintenance": 500.00,
  "professional_fees": 200.00
}
```

> All monetary values must be **cumulative year-to-date** — not just the current quarter.

To amend an existing submission, add `"submission_id": "..."` to the payload.

---

## Fraud Prevention Headers

HMRC requires a specific set of `Gov-Client-*` and `Gov-Vendor-*` headers on every API call. These are **automatically generated** by `hmrc_client.py → build_fraud_headers()` and attached to every outbound request.

Key characteristics:
- `Gov-Client-Device-ID` — stable UUID generated once per server process
- `Gov-Client-Public-IP` — extracted from the incoming Adalo request (`X-Forwarded-For`)
- `Gov-Client-Multi-Factor` — generated with a fresh timestamp per request
- All timestamps are ISO 8601 UTC, regenerated per request

Validate them (sandbox only) with:
```
GET /debug/validate-fraud-headers
X-Session-ID: <your-session-id>
```

---

## Deployment (Vercel)

1. Push to GitHub
2. Import into Vercel
3. Set environment variables in Vercel Dashboard (same keys as `.env.example`)
4. Update `REDIRECT_URI` to your Vercel deployment URL
5. Update the redirect URI in your HMRC Developer Hub application

> **Note:** Vercel's filesystem is ephemeral. The SQLite DB is stored in `/tmp` (configured in `vercel.json`) and **will be reset between deployments**. For production, replace SQLite with a persistent store (Postgres, Redis, etc.).

---

## Submission Workflow (for Adalo)

```
1. User taps "Connect HMRC"
   → Call GET /auth/login-url
   → Open auth_url in browser/webview
   → On return, extract session_id from callback URL params
   → Store session_id in Adalo user profile

2. User enters their NINO
   → Call POST /auth/set-nino {"nino": "..."}

3. View current obligations
   → Call GET /obligations
   → Display list of open periods with due dates

4. Submit quarterly figures
   → User enters income + expenses for the period
   → Call POST /submit-periodic with YTD totals
   → Store returned submission_id for future amendments
```

---

## Xero Integration

### Overview

Xero is used to pull in bank transactions (income and expenses) from the landlord's connected bank accounts. This complements the HMRC submission flow — you can sync Xero transactions, then submit the totals to HMRC.

### Required Environment Variables

| Variable | Description |
|---|---|
| `XERO_CLIENT_ID` | Your Xero app's Client ID |
| `XERO_CLIENT_SECRET` | Your Xero app's Client Secret |
| `XERO_REDIRECT_URI` | Callback URL registered in Xero Developer Portal |

Register your app at [https://developer.xero.com/myapps](https://developer.xero.com/myapps):
- App type: **Web App**
- Grant type: **Authorization Code**
- Enable: **OpenID Connect**
- Add redirect URI: `https://hmrc-mtd-ap-is.vercel.app/xero/callback`

### Xero OAuth Flow (Adalo)

The same state-polling pattern used for HMRC:

```
1. GET /xero/login-url
   Response: { "auth_url": "https://login.xero.com/...", "state": "uuid" }
   → Store `state` in Adalo hidden variable
   → Open `auth_url` in device browser

2. User logs in to Xero (in browser)
   → Xero redirects to /xero/callback automatically
   → Backend exchanges code for tokens + fetches tenant_id

3. Poll GET /xero/session?state=<state>  (every 3–5 seconds)
   → 202: { "ready": false }  — still waiting
   → 200: { "ready": true, "session_id": "...", "tenant_id": "..." }
   → Store session_id and tenant_id in Adalo user profile

4. All subsequent Xero calls require header:
   X-Xero-Session-ID: <session_id>
```

### Xero Endpoints

| Endpoint | Description |
|---|---|
| `GET /xero/login-url` | Returns Xero OAuth URL + state for Adalo to open |
| `GET /xero/callback` | OAuth callback — exchanges code, stores tokens |
| `GET /xero/session?state=` | Adalo polls this to retrieve session_id |
| `GET /xero/bank-accounts` | Lists BANK-type accounts from Xero |
| `GET /xero/transactions` | Fetches RECEIVE/SPEND bank transactions |
| `POST /xero/sync` | Fetches + transforms transactions into app format |

### Xero Bank Accounts Response

```json
{
  "bank_accounts": [
    {
      "id": "38b4e08c-...",
      "name": "Barclays Business (UK)",
      "bank_number": "20346033730956",
      "currency": "GBP"
    }
  ]
}
```

### Xero Transactions Response

```json
{
  "transactions": [
    {
      "id": "565cce24-...",
      "amount": 1000.00,
      "type": "income",
      "date": "2026-03-07",
      "description": "Test Tenant",
      "reference": "Test Rent",
      "currency": "GBP"
    }
  ]
}
```

**Type mapping:**
- `RECEIVE` → `"income"` (e.g. rent received)
- `SPEND` → `"expense"` (e.g. mortgage payment, repairs)

### Optional Query Parameters for `/xero/transactions`

| Param | Example | Description |
|---|---|---|
| `fromDate` | `2026-01-01` | Filter transactions from this date |
| `toDate` | `2026-03-31` | Filter transactions up to this date |
| `accountId` | `38b4e08c-...` | Filter by specific bank account |

### Token Refresh

Xero access tokens expire after 30 minutes. The `get_valid_xero_token()` function in `xero_auth.py` automatically refreshes the token using the stored `refresh_token` before each API call — no user action required.

---

## Tax Year Notes

- UK tax year: **6 April → 5 April**
- HMRC format: `"2024-25"` (not `"2024-2025"`)
- The `tax_year` field in `POST /submit-periodic` is auto-derived from `start_date` if omitted
- Periodic submissions are **cumulative** — always send the full YTD total, not just the quarter's figures
