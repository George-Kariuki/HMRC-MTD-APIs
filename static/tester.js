/* HMRC MTD one-page API tester */

const STORAGE_KEYS = {
  sessionId: "hmrc_tester_session_id",
  nino: "hmrc_tester_nino",
  apiBase: "hmrc_tester_api_base",
  oauthState: "hmrc_tester_oauth_state",
  lastPropertyId: "hmrc_tester_last_property_id",
};

/** Sensitive values use sessionStorage (cleared when the tab closes). */
function sessionGet(key) {
  return sessionStorage.getItem(key) || "";
}

function sessionSet(key, value) {
  if (value) sessionStorage.setItem(key, value);
  else sessionStorage.removeItem(key);
}

const ENDPOINTS = [
  // Auth helpers (no X-Session-ID required except set-nino)
  {
    id: "auth-login-url",
    group: "Auth",
    name: "Get login URL",
    method: "GET",
    path: "/auth/login-url",
    needsSession: false,
    needsNino: false,
    params: [],
    sampleBody: null,
  },
  {
    id: "auth-session",
    group: "Auth",
    name: "Poll session",
    method: "GET",
    path: "/auth/session",
    needsSession: false,
    needsNino: false,
    params: [
      { key: "state", label: "state", default: "" },
    ],
    sampleBody: null,
  },
  {
    id: "auth-set-nino",
    group: "Auth",
    name: "Set NINO",
    method: "POST",
    path: "/auth/set-nino",
    needsSession: true,
    needsNino: false,
    params: [],
    sampleBody: { nino: "AA123456A" },
  },

  // Business Details
  {
    id: "bd-list",
    group: "Business Details",
    name: "List all businesses",
    method: "GET",
    path: "/business-details",
    needsSession: true,
    needsNino: true,
    params: [],
    sampleBody: null,
  },
  {
    id: "bd-retrieve",
    group: "Business Details",
    name: "Retrieve business details",
    method: "GET",
    path: "/business-details/{businessId}",
    needsSession: true,
    needsNino: true,
    params: [
      { key: "businessId", label: "businessId (path)", default: "XBIS12345678901", inPath: true },
    ],
    sampleBody: null,
  },
  {
    id: "bd-qpt",
    group: "Business Details",
    name: "Create/amend quarterly period type",
    method: "PUT",
    path: "/business-details/{businessId}/quarterly-period-type",
    needsSession: true,
    needsNino: true,
    params: [
      { key: "businessId", label: "businessId (path)", default: "XBIS12345678901", inPath: true },
      { key: "taxYear", label: "taxYear", default: "2025-26" },
      { key: "govTestScenario", label: "govTestScenario", default: "" },
    ],
    sampleBody: { quarterlyPeriodType: "standard" },
  },

  // Accounting Type
  {
    id: "bd-at-get",
    group: "Business Details — Accounting Type",
    name: "Retrieve accounting type",
    method: "GET",
    path: "/business-details/{businessId}/accounting-type",
    needsSession: true,
    needsNino: true,
    params: [
      { key: "businessId", label: "businessId (path)", default: "XBIS12345678901", inPath: true },
      { key: "taxYear", label: "taxYear", default: "2025-26" },
      { key: "govTestScenario", label: "govTestScenario", default: "" },
    ],
    sampleBody: null,
  },
  {
    id: "bd-at-put",
    group: "Business Details — Accounting Type",
    name: "Update accounting type",
    method: "PUT",
    path: "/business-details/{businessId}/accounting-type",
    needsSession: true,
    needsNino: true,
    params: [
      { key: "businessId", label: "businessId (path)", default: "XBIS12345678901", inPath: true },
      { key: "taxYear", label: "taxYear", default: "2025-26" },
      { key: "govTestScenario", label: "govTestScenario", default: "" },
    ],
    sampleBody: { accountingType: "CASH" },
  },

  // Periods of Account
  {
    id: "bd-poa-get",
    group: "Business Details — Periods of Account",
    name: "Retrieve periods of account",
    method: "GET",
    path: "/business-details/{businessId}/periods-of-account",
    needsSession: true,
    needsNino: true,
    params: [
      { key: "businessId", label: "businessId (path)", default: "XBIS12345678901", inPath: true },
      { key: "taxYear", label: "taxYear", default: "2025-26" },
    ],
    sampleBody: null,
  },
  {
    id: "bd-poa-put",
    group: "Business Details — Periods of Account",
    name: "Create/update periods of account",
    method: "PUT",
    path: "/business-details/{businessId}/periods-of-account",
    needsSession: true,
    needsNino: true,
    params: [
      { key: "businessId", label: "businessId (path)", default: "XBIS12345678901", inPath: true },
      { key: "taxYear", label: "taxYear", default: "2025-26" },
      { key: "govTestScenario", label: "govTestScenario", default: "" },
    ],
    sampleBody: {
      periodsOfAccount: true,
      periodsOfAccountDates: [
        { startDate: "2025-04-06", endDate: "2026-04-05" },
      ],
    },
  },

  // Late Accounting Date Rule
  {
    id: "bd-ladr-get",
    group: "Business Details — Late Accounting Date Rule",
    name: "Retrieve late accounting date rule",
    method: "GET",
    path: "/business-details/{businessId}/late-accounting-date-rule-election",
    needsSession: true,
    needsNino: true,
    params: [
      { key: "businessId", label: "businessId (path)", default: "XBIS12345678901", inPath: true },
      { key: "taxYear", label: "taxYear", default: "2024-25" },
      { key: "govTestScenario", label: "govTestScenario", default: "" },
    ],
    sampleBody: null,
  },
  {
    id: "bd-ladr-disapply",
    group: "Business Details — Late Accounting Date Rule",
    name: "Disapply late accounting date rule",
    method: "POST",
    path: "/business-details/{businessId}/late-accounting-date-rule-election/disapply",
    needsSession: true,
    needsNino: true,
    params: [
      { key: "businessId", label: "businessId (path)", default: "XBIS12345678901", inPath: true },
      { key: "taxYear", label: "taxYear", default: "2024-25" },
      { key: "govTestScenario", label: "govTestScenario", default: "" },
    ],
    sampleBody: null,
  },
  {
    id: "bd-ladr-withdraw",
    group: "Business Details — Late Accounting Date Rule",
    name: "Withdraw late accounting date rule",
    method: "DELETE",
    path: "/business-details/{businessId}/late-accounting-date-rule-election/withdraw",
    needsSession: true,
    needsNino: true,
    params: [
      { key: "businessId", label: "businessId (path)", default: "XBIS12345678901", inPath: true },
      { key: "taxYear", label: "taxYear", default: "2024-25" },
      { key: "govTestScenario", label: "govTestScenario", default: "" },
    ],
    sampleBody: null,
  },

  // Obligations
  {
    id: "obligations",
    group: "Obligations",
    name: "Retrieve income & expenditure obligations",
    method: "GET",
    path: "/obligations",
    needsSession: true,
    needsNino: true,
    params: [
      { key: "typeOfBusiness", label: "typeOfBusiness", default: "uk-property" },
      { key: "businessId", label: "businessId", default: "" },
      { key: "fromDate", label: "fromDate", default: "2025-04-06" },
      { key: "toDate", label: "toDate", default: "2026-04-05" },
      { key: "status", label: "status", default: "open" },
    ],
    sampleBody: null,
  },
  {
    id: "obligations-final-declaration",
    group: "Obligations",
    name: "Retrieve final declaration obligations",
    method: "GET",
    path: "/obligations/final-declaration",
    needsSession: true,
    needsNino: true,
    params: [
      { key: "taxYear", label: "taxYear", default: "2025-26" },
      { key: "status", label: "status", default: "open" },
      { key: "govTestScenario", label: "govTestScenario", default: "" },
    ],
    sampleBody: null,
  },

  // Period Summaries (legacy)
  {
    id: "period-submit",
    group: "Property Business — Period Summaries",
    name: "Create/amend period summary",
    method: "POST",
    path: "/submit-periodic",
    needsSession: true,
    needsNino: true,
    params: [
      { key: "businessId", label: "businessId", default: "XBIS12345678901" },
      { key: "startDate", label: "startDate", default: "2025-04-06" },
      { key: "endDate", label: "endDate", default: "2025-07-05" },
      { key: "taxYear", label: "taxYear", default: "2025-26" },
      { key: "propertyType", label: "propertyType", default: "ukNonFhlProperty" },
    ],
    sampleBody: {
      rent_income: 1000,
      premiums_of_lease_grant: 0,
      reverse_premiums: 0,
      other_income: 0,
      tax_deducted: 0,
      premises_running_costs: 100,
      repairs_and_maintenance: 50,
      financial_costs: 0,
      professional_fees: 0,
      cost_of_services: 0,
      other_expenses: 0,
      residential_financial_cost: 0,
      travel_costs: 0,
    },
  },
  {
    id: "period-get",
    group: "Property Business — Period Summaries",
    name: "Retrieve period summary",
    method: "GET",
    path: "/period-summary",
    needsSession: true,
    needsNino: true,
    params: [
      { key: "businessId", label: "businessId", default: "XBIS12345678901" },
      { key: "taxYear", label: "taxYear", default: "2025-26" },
      { key: "submissionId", label: "submissionId", default: "" },
    ],
    sampleBody: null,
  },

  // UK Cumulative
  {
    id: "uk-cum-put",
    group: "Property Business — UK Cumulative",
    name: "Create/amend UK cumulative",
    method: "PUT",
    path: "/property-cumulative",
    needsSession: true,
    needsNino: true,
    params: [
      { key: "businessId", label: "businessId", default: "XBIS12345678901" },
      { key: "taxYear", label: "taxYear", default: "2025-26" },
      { key: "govTestScenario", label: "govTestScenario", default: "STATEFUL" },
    ],
    sampleBody: {
      from_date: "2025-04-06",
      to_date: "2025-07-05",
      rent_income: 5000.99,
      premiums_of_lease_grant: 0,
      reverse_premiums: 0,
      other_income: 0,
      tax_deducted: 0,
      premises_running_costs: 500,
      repairs_and_maintenance: 200,
      financial_costs: 100,
      professional_fees: 75,
      cost_of_services: 0,
      other_expenses: 0,
      residential_financial_cost: 0,
      travel_costs: 0,
    },
  },
  {
    id: "uk-cum-get",
    group: "Property Business — UK Cumulative",
    name: "Retrieve UK cumulative",
    method: "GET",
    path: "/property-cumulative",
    needsSession: true,
    needsNino: true,
    params: [
      { key: "businessId", label: "businessId", default: "XBIS12345678901" },
      { key: "taxYear", label: "taxYear", default: "2025-26" },
      { key: "govTestScenario", label: "govTestScenario", default: "STATEFUL" },
    ],
    sampleBody: null,
  },

  // Annual
  {
    id: "annual-put",
    group: "Property Business — Annual Submission",
    name: "Create/amend annual submission",
    method: "PUT",
    path: "/submit-annual",
    needsSession: true,
    needsNino: true,
    params: [
      { key: "businessId", label: "businessId", default: "XBIS12345678901" },
      { key: "taxYear", label: "taxYear", default: "2025-26" },
      { key: "govTestScenario", label: "govTestScenario", default: "" },
    ],
    sampleBody: {
      ukProperty: {
        adjustments: {
          privateUseAdjustment: 0,
          balancingCharge: 0,
        },
        allowances: {
          annualInvestmentAllowance: 0,
          otherCapitalAllowance: 0,
        },
      },
    },
  },
  {
    id: "annual-get",
    group: "Property Business — Annual Submission",
    name: "Retrieve annual submission",
    method: "GET",
    path: "/annual-submission",
    needsSession: true,
    needsNino: true,
    params: [
      { key: "businessId", label: "businessId", default: "XBIS12345678901" },
      { key: "taxYear", label: "taxYear", default: "2025-26" },
      { key: "govTestScenario", label: "govTestScenario", default: "" },
    ],
    sampleBody: null,
  },

  // Foreign Property Details
  {
    id: "fpd-create",
    group: "Property Business — Foreign Property Details",
    name: "Create foreign property details",
    method: "POST",
    path: "/foreign-property-details",
    needsSession: true,
    needsNino: true,
    params: [
      { key: "businessId", label: "businessId", default: "XBIS12345678901" },
      { key: "taxYear", label: "taxYear", default: "2026-27" },
      { key: "govTestScenario", label: "govTestScenario", default: "STATEFUL" },
    ],
    sampleBody: {
      propertyName: "Bob & Bobby Co",
      countryCode: "FRA",
    },
  },
  {
    id: "fpd-get",
    group: "Property Business — Foreign Property Details",
    name: "Retrieve foreign property details",
    method: "GET",
    path: "/foreign-property-details",
    needsSession: true,
    needsNino: true,
    params: [
      { key: "businessId", label: "businessId", default: "XBIS12345678901" },
      { key: "taxYear", label: "taxYear", default: "2026-27" },
      { key: "propertyId", label: "propertyId", default: "" },
      { key: "govTestScenario", label: "govTestScenario", default: "STATEFUL" },
    ],
    sampleBody: null,
  },
  {
    id: "fpd-put",
    group: "Property Business — Foreign Property Details",
    name: "Update foreign property details",
    method: "PUT",
    path: "/foreign-property-details/{propertyId}",
    needsSession: true,
    needsNino: true,
    params: [
      { key: "propertyId", label: "propertyId (path)", default: "8e8b8450-dc1b-4360-8109-7067337b42cb", inPath: true },
      { key: "taxYear", label: "taxYear", default: "2026-27" },
      { key: "govTestScenario", label: "govTestScenario", default: "STATEFUL" },
    ],
    sampleBody: {
      propertyName: "Bob & Bobby Co",
    },
  },

  // Foreign Cumulative
  {
    id: "fp-cum-put",
    group: "Property Business — Foreign Cumulative",
    name: "Create/amend foreign cumulative",
    method: "PUT",
    path: "/foreign-property-cumulative",
    needsSession: true,
    needsNino: true,
    params: [
      { key: "businessId", label: "businessId", default: "XBIS12345678901" },
      { key: "taxYear", label: "taxYear", default: "2026-27" },
      { key: "govTestScenario", label: "govTestScenario", default: "STATEFUL" },
    ],
    sampleBody: {
      fromDate: "2026-04-06",
      toDate: "2026-07-05",
      foreignProperty: [
        {
          propertyId: "8e8b8450-dc1b-4360-8109-7067337b42cb",
          income: {
            rentIncome: { rentAmount: 5000.99 },
            foreignTaxCreditRelief: false,
            premiumsOfLeaseGrant: 12000.5,
            otherPropertyIncome: 3000.25,
            foreignTaxPaidOrDeducted: 1500.75,
            specialWithholdingTaxOrUkTaxPaid: 450.5,
          },
          expenses: {
            premisesRunningCosts: 5000.99,
            repairsAndMaintenance: 2000.5,
            financialCosts: 1000,
            professionalFees: 750.75,
            travelCosts: 300.5,
            costOfServices: 4000.75,
            other: 600,
            residentialFinancialCost: 500.99,
            broughtFwdResidentialFinancialCost: 250.25,
          },
        },
      ],
    },
  },
  {
    id: "fp-cum-get",
    group: "Property Business — Foreign Cumulative",
    name: "Retrieve foreign cumulative",
    method: "GET",
    path: "/foreign-property-cumulative",
    needsSession: true,
    needsNino: true,
    params: [
      { key: "businessId", label: "businessId", default: "XBIS12345678901" },
      { key: "taxYear", label: "taxYear", default: "2026-27" },
      { key: "propertyId", label: "propertyId", default: "8e8b8450-dc1b-4360-8109-7067337b42cb" },
      { key: "govTestScenario", label: "govTestScenario", default: "STATEFUL" },
    ],
    sampleBody: null,
  },

  // Self-Employment
  {
    id: "se-cum-put",
    group: "Self-Employment Business",
    name: "Create/amend SE cumulative",
    method: "PUT",
    path: "/self-employment-cumulative",
    needsSession: true,
    needsNino: true,
    params: [
      { key: "businessId", label: "businessId", default: "XBIS12345678901" },
      { key: "taxYear", label: "taxYear", default: "2025-26" },
      { key: "govTestScenario", label: "govTestScenario", default: "STATEFUL" },
    ],
    sampleBody: {
      periodDates: {
        periodStartDate: "2025-04-06",
        periodEndDate: "2025-07-05",
      },
      periodIncome: {
        turnover: 1000.99,
        other: 1000.09,
        taxTakenOffTradingIncome: 1000.99,
      },
      periodExpenses: {
        costOfGoods: 1000.99,
        paymentsToSubcontractors: 1000.99,
        wagesAndStaffCosts: 1000.99,
        carVanTravelExpenses: 1000.99,
        premisesRunningCosts: -1000.99,
        maintenanceCosts: -1000.99,
        adminCosts: 1000.99,
        businessEntertainmentCosts: 1000.99,
        advertisingCosts: 1000.99,
        interestOnBankOtherLoans: -1000.99,
        financeCharges: -1000.99,
        irrecoverableDebts: -1000.99,
        professionalFees: 1000.99,
        depreciation: -1000.99,
        otherExpenses: 1000.99,
      },
    },
  },
  {
    id: "se-cum-get",
    group: "Self-Employment Business",
    name: "Retrieve SE cumulative",
    method: "GET",
    path: "/self-employment-cumulative",
    needsSession: true,
    needsNino: true,
    params: [
      { key: "businessId", label: "businessId", default: "XBIS12345678901" },
      { key: "taxYear", label: "taxYear", default: "2025-26" },
      { key: "govTestScenario", label: "govTestScenario", default: "STATEFUL" },
    ],
    sampleBody: null,
  },
  {
    id: "se-annual-put",
    group: "Self-Employment Business",
    name: "Create/amend SE annual",
    method: "PUT",
    path: "/self-employment-annual",
    needsSession: true,
    needsNino: true,
    params: [
      { key: "businessId", label: "businessId", default: "XBIS12345678901" },
      { key: "taxYear", label: "taxYear", default: "2025-26" },
      { key: "govTestScenario", label: "govTestScenario", default: "" },
    ],
    sampleBody: {
      adjustments: {
        includedNonTaxableProfits: 0,
        basisAdjustment: 0,
      },
      allowances: {
        annualInvestmentAllowance: 0,
        capitalAllowanceMainPool: 0,
      },
    },
  },
  {
    id: "se-annual-get",
    group: "Self-Employment Business",
    name: "Retrieve SE annual",
    method: "GET",
    path: "/self-employment-annual",
    needsSession: true,
    needsNino: true,
    params: [
      { key: "businessId", label: "businessId", default: "XBIS12345678901" },
      { key: "taxYear", label: "taxYear", default: "2025-26" },
      { key: "govTestScenario", label: "govTestScenario", default: "" },
    ],
    sampleBody: null,
  },

  // Debug
  {
    id: "debug-fph",
    group: "Debug",
    name: "Validate fraud headers",
    method: "GET",
    path: "/debug/validate-fraud-headers",
    needsSession: true,
    needsNino: false,
    params: [],
    sampleBody: null,
  },
];

let selectedId = null;
let pollTimer = null;

function $(id) {
  return document.getElementById(id);
}

function getApiBase() {
  return $("apiBase").value.replace(/\/$/, "");
}

function updateAuthChip() {
  const sid = $("sessionId").value.trim();
  const chip = $("authChip");
  if (sid) {
    chip.textContent = `Session ${sid.slice(0, 8)}…`;
    chip.className = "chip ok";
  } else {
    chip.textContent = "Not connected";
    chip.className = "chip bad";
  }
}

function persist() {
  sessionSet(STORAGE_KEYS.sessionId, $("sessionId").value.trim());
  sessionSet(STORAGE_KEYS.nino, $("nino").value.trim());
  // API base is a non-sensitive preference — keep across reloads.
  localStorage.setItem(STORAGE_KEYS.apiBase, $("apiBase").value);
}

function restore() {
  // Prefer sessionStorage; clear any previously leaked localStorage credentials.
  const sid =
    sessionGet(STORAGE_KEYS.sessionId) ||
    localStorage.getItem(STORAGE_KEYS.sessionId) ||
    "";
  const nino =
    sessionGet(STORAGE_KEYS.nino) ||
    localStorage.getItem(STORAGE_KEYS.nino) ||
    "";
  localStorage.removeItem(STORAGE_KEYS.sessionId);
  localStorage.removeItem(STORAGE_KEYS.nino);

  const base =
    localStorage.getItem(STORAGE_KEYS.apiBase) ||
    "https://hmrc-mtd-ap-is.vercel.app";
  $("sessionId").value = sid;
  $("nino").value = nino;
  $("apiBase").value = base;
  if (sid) sessionSet(STORAGE_KEYS.sessionId, sid);
  if (nino) sessionSet(STORAGE_KEYS.nino, nino);
  updateAuthChip();
}

function clearSavedData() {
  if (pollTimer) clearInterval(pollTimer);
  sessionStorage.removeItem(STORAGE_KEYS.sessionId);
  sessionStorage.removeItem(STORAGE_KEYS.nino);
  sessionStorage.removeItem(STORAGE_KEYS.oauthState);
  sessionStorage.removeItem(STORAGE_KEYS.lastPropertyId);
  localStorage.removeItem(STORAGE_KEYS.sessionId);
  localStorage.removeItem(STORAGE_KEYS.nino);
  localStorage.removeItem(STORAGE_KEYS.oauthState);
  localStorage.removeItem(STORAGE_KEYS.lastPropertyId);
  $("sessionId").value = "";
  $("nino").value = "";
  updateAuthChip();
  $("respStatus").textContent = "Cleared";
  $("respStatus").style.color = "var(--muted)";
  $("respBody").textContent = "Session ID, NINO, OAuth state, and last propertyId cleared.";
}

function renderList() {
  const root = $("endpointList");
  root.innerHTML = "";
  let lastGroup = null;
  for (const ep of ENDPOINTS) {
    if (ep.group !== lastGroup) {
      lastGroup = ep.group;
      const title = document.createElement("div");
      title.className = "group-title";
      title.textContent = ep.group;
      root.appendChild(title);
    }
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "ep" + (ep.id === selectedId ? " active" : "");
    btn.innerHTML = `<span class="method ${ep.method}">${ep.method}</span><span>${ep.name}</span>`;
    btn.addEventListener("click", () => selectEndpoint(ep.id));
    root.appendChild(btn);
  }
}

function selectEndpoint(id) {
  selectedId = id;
  const ep = ENDPOINTS.find((e) => e.id === id);
  renderList();
  $("emptyState").hidden = true;
  $("runner").hidden = false;
  $("epTitle").textContent = `${ep.method} — ${ep.name}`;
  $("epPath").textContent = `${ep.method} ${ep.path}`;

  const paramsEl = $("epParams");
  paramsEl.innerHTML = "";
  for (const p of ep.params) {
    const label = document.createElement("label");
    label.textContent = p.label;
    const input = document.createElement("input");
    input.dataset.key = p.key;
    input.dataset.inPath = p.inPath ? "1" : "0";
    input.value = p.default || "";
    if (p.key === "state") {
      input.value = sessionGet(STORAGE_KEYS.oauthState);
    }
    if (p.key === "propertyId") {
      const savedId = sessionGet(STORAGE_KEYS.lastPropertyId);
      if (savedId) input.value = savedId;
    }
    label.appendChild(input);
    paramsEl.appendChild(label);
  }

  const hasBody = ep.sampleBody !== null;
  $("bodyLabel").style.display = hasBody ? "flex" : "none";
  $("epBody").value = hasBody ? JSON.stringify(ep.sampleBody, null, 2) : "";

  // Prefill set-nino body from NINO field
  if (ep.id === "auth-set-nino") {
    const n = $("nino").value.trim() || "AA123456A";
    $("epBody").value = JSON.stringify({ nino: n }, null, 2);
  }

  // Swap sample-body propertyId with last created id when present
  if (hasBody) {
    const savedId = sessionGet(STORAGE_KEYS.lastPropertyId);
    if (savedId) {
      try {
        const body = JSON.parse($("epBody").value);
        if (Array.isArray(body.foreignProperty)) {
          for (const entry of body.foreignProperty) {
            if (entry && typeof entry === "object") entry.propertyId = savedId;
          }
          $("epBody").value = JSON.stringify(body, null, 2);
        }
      } catch (_) {}
    }
  }
}

function buildUrl(ep) {
  let path = ep.path;
  const query = new URLSearchParams();
  const inputs = $("epParams").querySelectorAll("input");
  for (const input of inputs) {
    const key = input.dataset.key;
    const val = input.value.trim();
    if (input.dataset.inPath === "1") {
      path = path.replace(`{${key}}`, encodeURIComponent(val));
    } else if (val !== "") {
      query.set(key, val);
    }
  }
  const qs = query.toString();
  return getApiBase() + path + (qs ? `?${qs}` : "");
}

async function runRequest() {
  const ep = ENDPOINTS.find((e) => e.id === selectedId);
  if (!ep) return;

  const sessionId = $("sessionId").value.trim();
  if (ep.needsSession && !sessionId) {
    $("respStatus").textContent = "Blocked";
    $("respBody").textContent = "Set a session ID first (Connect HMRC).";
    return;
  }

  const nino = $("nino").value.trim();
  if (ep.needsNino && !nino) {
    $("respStatus").textContent = "Blocked";
    $("respBody").textContent = "Set a NINO first (use the Set NINO button).";
    return;
  }

  const headers = { Accept: "application/json" };
  if (ep.needsSession) headers["X-Session-ID"] = sessionId;

  const opts = { method: ep.method, headers };
  if (ep.sampleBody !== null) {
    headers["Content-Type"] = "application/json";
    try {
      opts.body = JSON.stringify(JSON.parse($("epBody").value));
    } catch (err) {
      $("respStatus").textContent = "Invalid JSON";
      $("respBody").textContent = String(err);
      return;
    }
  }

  const url = buildUrl(ep);
  $("respStatus").textContent = "Running…";
  $("respTime").textContent = "";
  $("btnRun").disabled = true;
  const t0 = performance.now();
  try {
    const res = await fetch(url, opts);
    const ms = Math.round(performance.now() - t0);
    let text = await res.text();
    let pretty = text;
    try {
      pretty = JSON.stringify(JSON.parse(text), null, 2);
    } catch (_) {
      /* keep raw */
    }
    $("respStatus").textContent = `${res.status} ${res.statusText}`;
    $("respStatus").style.color = res.ok ? "var(--ok)" : "var(--warn)";
    $("respTime").textContent = `${ms} ms · ${url}`;
    $("respBody").textContent = pretty || "(empty body)";

    // Auto-store propertyId from create foreign property details
    if (ep.id === "fpd-create" && res.ok) {
      try {
        const data = JSON.parse(text);
        if (data.propertyId) {
          sessionSet(STORAGE_KEYS.lastPropertyId, data.propertyId);
        }
      } catch (_) {}
    }
  } catch (err) {
    $("respStatus").textContent = "Network error";
    $("respStatus").style.color = "var(--warn)";
    $("respBody").textContent = String(err);
  } finally {
    $("btnRun").disabled = false;
  }
}

async function connectHmrc() {
  $("btnConnect").disabled = true;
  try {
    const res = await fetch(`${getApiBase()}/auth/login-url`);
    const data = await res.json();
    if (!data.auth_url || !data.state) {
      throw new Error("Unexpected login-url response: " + JSON.stringify(data));
    }
    sessionSet(STORAGE_KEYS.oauthState, data.state);
    window.open(data.auth_url, "_blank", "noopener");
    startPolling(data.state);
  } catch (err) {
    $("respStatus").textContent = "Auth error";
    $("respBody").textContent = String(err);
  } finally {
    $("btnConnect").disabled = false;
  }
}

function startPolling(state) {
  if (pollTimer) clearInterval(pollTimer);
  $("authChip").textContent = "Waiting for HMRC login…";
  $("authChip").className = "chip";
  let attempts = 0;
  pollTimer = setInterval(async () => {
    attempts += 1;
    if (attempts > 60) {
      clearInterval(pollTimer);
      $("authChip").textContent = "Login timed out";
      $("authChip").className = "chip bad";
      return;
    }
    try {
      const res = await fetch(
        `${getApiBase()}/auth/session?state=${encodeURIComponent(state)}`
      );
      const data = await res.json();
      if (data.ready && data.session_id) {
        clearInterval(pollTimer);
        $("sessionId").value = data.session_id;
        persist();
        updateAuthChip();
        $("respStatus").textContent = "200 Connected";
        $("respBody").textContent = JSON.stringify(data, null, 2);
      }
    } catch (_) {
      /* keep polling */
    }
  }, 3000);
}

async function setNino() {
  const sessionId = $("sessionId").value.trim();
  const nino = $("nino").value.trim().toUpperCase();
  if (!sessionId || !nino) {
    $("respStatus").textContent = "Need session + NINO";
    $("respBody").textContent = "Connect to HMRC and enter a NINO first.";
    return;
  }
  persist();
  const res = await fetch(`${getApiBase()}/auth/set-nino`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Session-ID": sessionId,
    },
    body: JSON.stringify({ nino }),
  });
  const text = await res.text();
  let pretty = text;
  try {
    pretty = JSON.stringify(JSON.parse(text), null, 2);
  } catch (_) {}
  $("respStatus").textContent = `${res.status} ${res.statusText}`;
  $("respStatus").style.color = res.ok ? "var(--ok)" : "var(--warn)";
  $("respBody").textContent = pretty;
}

function wire() {
  restore();
  renderList();

  $("apiBase").addEventListener("change", persist);
  $("sessionId").addEventListener("input", () => {
    persist();
    updateAuthChip();
  });
  $("nino").addEventListener("input", persist);
  $("btnConnect").addEventListener("click", connectHmrc);
  $("btnSetNino").addEventListener("click", setNino);
  $("btnClear").addEventListener("click", clearSavedData);
  $("btnRun").addEventListener("click", runRequest);
  $("btnReset").addEventListener("click", () => {
    if (selectedId) selectEndpoint(selectedId);
  });

  // Resume polling if a state was mid-flight
  const pending =
    sessionGet(STORAGE_KEYS.oauthState) ||
    localStorage.getItem(STORAGE_KEYS.oauthState) ||
    "";
  if (pending) {
    localStorage.removeItem(STORAGE_KEYS.oauthState);
    sessionSet(STORAGE_KEYS.oauthState, pending);
  }
  if (pending && !$("sessionId").value.trim()) {
    startPolling(pending);
  }
}

document.addEventListener("DOMContentLoaded", wire);
