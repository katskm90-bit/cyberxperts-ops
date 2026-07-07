import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { SUPABASE_URL, SUPABASE_ANON_KEY } from "./config.js";

const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// Departments map directly to the confirmed organogram directorates.
const DEPARTMENTS = {
  sales: "Sales & Bids",
  cybersecurity: "Cybersecurity",
  it_delivery: "IT Delivery",
  internal_it: "Internal IT & Staff Support",
  finance: "Finance",
  operations: "Operations"
};

let currentProfile = null;

// ---- Screen switching ----
// Every top level screen (login, MFA steps, the app itself) is a section in
// index.html with a matching id. Only one is visible at a time.
function showScreen(id) {
  document.querySelectorAll(".screen").forEach((el) => {
    el.classList.toggle("hidden", el.id !== id);
  });
}

function showModule(key) {
  document.querySelectorAll(".module").forEach((el) => {
    el.classList.toggle("hidden", el.dataset.module !== key);
  });
  document.querySelectorAll(".nav-link").forEach((el) => {
    el.classList.toggle("active", el.dataset.module === key);
  });
}

// ---- Building the navigation once a profile is known ----
function renderNav(profile) {
  const nav = document.getElementById("nav-links");
  nav.innerHTML = "";

  const items = [{ key: "overview", label: "Overview" }];

  Object.entries(DEPARTMENTS).forEach(([key, label]) => {
    const canSee = profile.role_tier === "system" || profile.department === key;
    if (canSee) items.push({ key, label });
  });

  if (profile.role_tier === "system") {
    items.push({ key: "settings", label: "Settings" });
  }

  items.forEach((item) => {
    const a = document.createElement("a");
    a.href = "#";
    a.textContent = item.label;
    a.dataset.module = item.key;
    a.className = "nav-link";
    a.addEventListener("click", (e) => {
      e.preventDefault();
      showModule(item.key);
      if (item.key === "sales") loadSalesModule();
    });
    nav.appendChild(a);
  });

  document.getElementById("nav-name").textContent = profile.full_name;
  document.getElementById("nav-role").textContent =
    (profile.department ? DEPARTMENTS[profile.department] : "System") +
    (profile.role_tier === "system" ? " · System Super User" : "");

  showModule("overview");
}

// ---- Auth state evaluation ----
// MFA is mandatory for every account. A session is only treated as signed in
// once Supabase reports it has reached AAL2, meaning a second factor has
// been verified, not just a password.
async function evaluateAuthState() {
  const { data: sessionData } = await supabase.auth.getSession();
  const session = sessionData.session;

  if (!session) {
    showScreen("screen-login");
    return;
  }

  const { data: aal } = await supabase.auth.mfa.getAuthenticatorAssuranceLevel();

  if (aal?.currentLevel === "aal2") {
    const { data: profile, error } = await supabase
      .from("profiles")
      .select("id, full_name, email, department, role_tier, mfa_enrolled")
      .eq("id", session.user.id)
      .single();

    if (error || !profile) {
      showScreen("screen-login");
      document.getElementById("login-error").textContent =
        "Signed in, but no profile record exists yet for this account. Ask your System Super User to create one.";
      return;
    }

    currentProfile = profile;
    renderNav(profile);
    showScreen("screen-app");
    return;
  }

  const { data: factors } = await supabase.auth.mfa.listFactors();
  const hasVerifiedFactor = (factors?.totp ?? []).some((f) => f.status === "verified");

  if (hasVerifiedFactor) {
    showScreen("screen-mfa-challenge");
  } else {
    await beginEnrollment();
    showScreen("screen-mfa-enroll");
  }
}

// ---- Login ----
document.getElementById("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const email = document.getElementById("login-email").value;
  const password = document.getElementById("login-password").value;
  const errorEl = document.getElementById("login-error");
  errorEl.textContent = "";

  const { error } = await supabase.auth.signInWithPassword({ email, password });
  if (error) {
    errorEl.textContent = error.message;
    return;
  }
  await evaluateAuthState();
});

// ---- MFA enrollment (first time setup) ----
let enrollFactorId = null;

async function beginEnrollment() {
  const { data, error } = await supabase.auth.mfa.enroll({ factorType: "totp" });
  if (error) {
    document.getElementById("enroll-error").textContent = error.message;
    return;
  }
  enrollFactorId = data.id;
  document.getElementById("enroll-qr").src = data.totp.qr_code;
}

document.getElementById("enroll-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const code = document.getElementById("enroll-code").value;
  const errorEl = document.getElementById("enroll-error");
  errorEl.textContent = "";

  const { data: challenge, error: challengeError } = await supabase.auth.mfa.challenge({
    factorId: enrollFactorId
  });
  if (challengeError) {
    errorEl.textContent = challengeError.message;
    return;
  }

  const { error: verifyError } = await supabase.auth.mfa.verify({
    factorId: enrollFactorId,
    challengeId: challenge.id,
    code
  });

  if (verifyError) {
    errorEl.textContent = "That code did not match. Check the time on your device and try again.";
    return;
  }

  await evaluateAuthState();
});

// ---- MFA challenge (returning sessions) ----
document.getElementById("challenge-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const code = document.getElementById("challenge-code").value;
  const errorEl = document.getElementById("challenge-error");
  errorEl.textContent = "";

  const { data: factors } = await supabase.auth.mfa.listFactors();
  const factor = factors?.totp.find((f) => f.status === "verified");
  if (!factor) {
    errorEl.textContent = "No verified authenticator found on this account.";
    return;
  }

  const { data: challenge, error: challengeError } = await supabase.auth.mfa.challenge({
    factorId: factor.id
  });
  if (challengeError) {
    errorEl.textContent = challengeError.message;
    return;
  }

  const { error: verifyError } = await supabase.auth.mfa.verify({
    factorId: factor.id,
    challengeId: challenge.id,
    code
  });

  if (verifyError) {
    errorEl.textContent = "That code did not match. Check the time on your device and try again.";
    return;
  }

  await evaluateAuthState();
});

// ---- Sign out ----
document.getElementById("sign-out").addEventListener("click", async () => {
  await supabase.auth.signOut();
  currentProfile = null;
  showScreen("screen-login");
});

// ---- Start up ----
supabase.auth.onAuthStateChange(() => {
  evaluateAuthState();
});
evaluateAuthState();

// ---- Sales module ----
// This is the first module built with real data behind it. The other
// modules stay as placeholders until each one gets the same treatment.

const STAGE_OPTIONS = ["lead", "qualifying", "scoping", "proposal", "submitted", "won", "lost"];

function formatRand(value) {
  if (value === null || value === undefined || value === "") return "—";
  return "R " + Number(value).toLocaleString("en-ZA", { minimumFractionDigits: 0 });
}

function daysUntil(dateString) {
  if (!dateString) return null;
  const target = new Date(dateString + "T00:00:00");
  const now = new Date();
  now.setHours(0, 0, 0, 0);
  return Math.round((target - now) / (1000 * 60 * 60 * 24));
}

async function loadPipeline(pipelineType, bodyId) {
  const tbody = document.getElementById(bodyId);

  const { data, error } = await supabase
    .from("opportunities")
    .select("id, stage, value, clients(name)")
    .eq("pipeline_type", pipelineType)
    .order("created_at", { ascending: false });

  if (error) {
    tbody.innerHTML = `<tr><td colspan="3" class="empty">Could not load this pipeline. ${error.message}</td></tr>`;
    return;
  }

  if (!data.length) {
    tbody.innerHTML = `<tr><td colspan="3" class="empty">No opportunities logged yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = "";
  data.forEach((row) => {
    const tr = document.createElement("tr");
    const clientName = row.clients ? row.clients.name : "Unknown client";
    tr.innerHTML = `
      <td>${clientName}</td>
      <td>
        <select data-id="${row.id}" class="stage-select">
          ${STAGE_OPTIONS.map(
            (s) => `<option value="${s}" ${s === row.stage ? "selected" : ""}>${s}</option>`
          ).join("")}
        </select>
      </td>
      <td>${formatRand(row.value)}</td>
    `;
    tbody.appendChild(tr);
  });

  tbody.querySelectorAll(".stage-select").forEach((select) => {
    select.addEventListener("change", async (e) => {
      const id = e.target.dataset.id;
      const { error: updateError } = await supabase
        .from("opportunities")
        .update({ stage: e.target.value })
        .eq("id", id);
      if (updateError) {
        alert("Could not update this opportunity. " + updateError.message);
      }
    });
  });
}

async function loadComplianceDocuments() {
  const tbody = document.getElementById("compliance-body");

  const { data, error } = await supabase
    .from("compliance_documents")
    .select("id, name, expiry_date")
    .order("expiry_date", { ascending: true });

  if (error) {
    tbody.innerHTML = `<tr><td colspan="3" class="empty">${error.message}</td></tr>`;
    return;
  }

  if (!data.length) {
    tbody.innerHTML = `<tr><td colspan="3" class="empty">No documents added yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = "";
  data.forEach((doc) => {
    const daysLeft = daysUntil(doc.expiry_date);
    let badge = "no-date";
    let label = "No expiry set";
    if (daysLeft !== null) {
      if (daysLeft < 0) {
        badge = "expired";
        label = "Expired";
      } else if (daysLeft <= 30) {
        badge = "expiring";
        label = daysLeft + " days left";
      } else if (daysLeft <= 90) {
        badge = "renew-soon";
        label = daysLeft + " days left";
      } else {
        badge = "valid";
        label = "Valid";
      }
    }
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${doc.name}</td>
      <td>${doc.expiry_date ?? "—"}</td>
      <td><span class="badge badge-${badge}">${label}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

async function getContractRenewalAlertDays() {
  const { data, error } = await supabase
    .from("settings")
    .select("value")
    .eq("key", "contract_renewal_alert_days")
    .maybeSingle();
  if (error || !data) return 60;
  return Number(data.value) || 60;
}

async function loadContracts() {
  const tbody = document.getElementById("contracts-body");
  const alertDays = await getContractRenewalAlertDays();

  const { data, error } = await supabase
    .from("contracts")
    .select("id, end_date, clients(name)")
    .order("end_date", { ascending: true });

  if (error) {
    tbody.innerHTML = `<tr><td colspan="3" class="empty">${error.message}</td></tr>`;
    return;
  }

  if (!data.length) {
    tbody.innerHTML = `<tr><td colspan="3" class="empty">No contracts recorded yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = "";
  data.forEach((c) => {
    const daysLeft = daysUntil(c.end_date);
    let badge = "no-date";
    let label = "No end date set";
    if (daysLeft !== null) {
      if (daysLeft < 0) {
        badge = "expired";
        label = "Lapsed";
      } else if (daysLeft <= alertDays) {
        badge = "expiring";
        label = "Renew, " + daysLeft + " days left";
      } else {
        badge = "valid";
        label = "Active";
      }
    }
    const clientName = c.clients ? c.clients.name : "Unknown client";
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${clientName}</td>
      <td>${c.end_date ?? "—"}</td>
      <td><span class="badge badge-${badge}">${label}</span></td>
    `;
    tbody.appendChild(tr);
  });
}

async function loadSalesModule() {
  await Promise.all([
    loadPipeline("tender", "sales-tender-body"),
    loadPipeline("private", "sales-private-body"),
    loadPipeline("partner", "sales-partner-body"),
    loadComplianceDocuments(),
    loadContracts()
  ]);
}

document.getElementById("add-opportunity-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const pipeline = document.getElementById("opp-pipeline").value;
  const clientName = document.getElementById("opp-client").value.trim();
  const rawValue = document.getElementById("opp-value").value;
  const value = rawValue === "" ? null : Number(rawValue);
  const errorEl = document.getElementById("add-opportunity-error");
  errorEl.textContent = "";

  const { data: existingClient } = await supabase
    .from("clients")
    .select("id")
    .eq("name", clientName)
    .maybeSingle();

  let clientId = existingClient ? existingClient.id : null;

  if (!clientId) {
    const { data: newClient, error: clientError } = await supabase
      .from("clients")
      .insert({ name: clientName })
      .select("id")
      .single();
    if (clientError) {
      errorEl.textContent = clientError.message;
      return;
    }
    clientId = newClient.id;
  }

  const { error: oppError } = await supabase.from("opportunities").insert({
    client_id: clientId,
    pipeline_type: pipeline,
    stage: "lead",
    value: value,
    owner_id: currentProfile.id
  });

  if (oppError) {
    errorEl.textContent = oppError.message;
    return;
  }

  form.reset();
  await loadSalesModule();
});

document.getElementById("add-compliance-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const name = document.getElementById("doc-name").value.trim();
  const expiry = document.getElementById("doc-expiry").value;
  const errorEl = document.getElementById("add-compliance-error");
  errorEl.textContent = "";

  const { error } = await supabase.from("compliance_documents").insert({
    name,
    expiry_date: expiry,
    owner_id: currentProfile.id
  });

  if (error) {
    errorEl.textContent = error.message;
    return;
  }

  form.reset();
  await loadComplianceDocuments();
});

// ---- Offline support ----
if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("sw.js");
  });
}
