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

  const items = [
    { key: "overview", label: "Home" },
    { key: "my_work", label: "My Work" },
    { key: "notifications", label: "Notifications" }
  ];

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
      if (MODULE_LOADERS[item.key]) MODULE_LOADERS[item.key]();
    });
    nav.appendChild(a);
  });

  document.getElementById("nav-name").textContent = profile.full_name;
  document.getElementById("nav-role").textContent =
    (profile.department ? DEPARTMENTS[profile.department] : "System") +
    (profile.role_tier === "system" ? " · System Super User" : "");

  showModule("overview");
  loadHomeModule();
  updateNotificationBadge();

  if (window.location.hash.startsWith("#client/")) {
    const clientId = window.location.hash.replace("#client/", "");
    openClientWorkspace(clientId);
  }
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
    .select("id, stage, value, client_id, clients(name)")
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
      <td><a href="#" class="client-link" data-client-id="${row.client_id}">${clientName}</a></td>
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
    .select("id, end_date, client_id, clients(name)")
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
      <td><a href="#" class="client-link" data-client-id="${c.client_id}">${clientName}</a></td>
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
    loadContracts(),
    loadLeads(),
    loadCampaigns(),
    loadEvents()
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

// ---- Cybersecurity module ----

async function loadProposals() {
  const tbody = document.getElementById("proposals-body");

  const { data, error } = await supabase
    .from("proposals")
    .select("id, scope, requires_second_reviewer, signed_off_by, second_reviewer_id, opportunities(clients(name))")
    .order("created_at", { ascending: false });

  if (error) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty">${error.message}</td></tr>`;
    return;
  }
  if (!data.length) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty">Nothing awaiting scoping yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = "";
  data.forEach((p) => {
    const clientName = p.opportunities && p.opportunities.clients ? p.opportunities.clients.name : "Unknown client";
    let status = "Awaiting sign off";
    let actionLabel = "Sign off";
    let disabled = false;

    if (p.signed_off_by && p.requires_second_reviewer && !p.second_reviewer_id) {
      status = "Signed off, awaiting second reviewer";
      actionLabel = "Second review";
    } else if (p.signed_off_by && (!p.requires_second_reviewer || p.second_reviewer_id)) {
      status = "Fully signed off";
      disabled = true;
    }

    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${clientName}</td>
      <td>${p.scope ?? "—"}</td>
      <td>${status}</td>
      <td>${disabled ? "" : `<button type="button" class="btn-primary btn-small" data-id="${p.id}" data-signed="${!!p.signed_off_by}">${actionLabel}</button>`}</td>
    `;
    tbody.appendChild(tr);
  });

  tbody.querySelectorAll("button[data-id]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const id = btn.dataset.id;
      const alreadySigned = btn.dataset.signed === "true";
      const patch = alreadySigned
        ? { second_reviewer_id: currentProfile.id }
        : { signed_off_by: currentProfile.id };
      const { error: updateError } = await supabase.from("proposals").update(patch).eq("id", id);
      if (updateError) alert("Could not update this proposal. " + updateError.message);
      await loadProposals();
    });
  });
}

async function populateProposalOpportunitySelect() {
  const select = document.getElementById("proposal-opportunity");
  const { data, error } = await supabase
    .from("opportunities")
    .select("id, value, clients(name)")
    .order("created_at", { ascending: false });

  if (error || !data) {
    select.innerHTML = `<option value="">Could not load opportunities</option>`;
    return;
  }
  select.innerHTML = data
    .map((o) => {
      const clientName = o.clients ? o.clients.name : "Unknown client";
      return `<option value="${o.id}" data-value="${o.value ?? 0}">${clientName}</option>`;
    })
    .join("");
}

document.getElementById("add-proposal-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const select = document.getElementById("proposal-opportunity");
  const opportunityId = select.value;
  const opportunityValue = Number(select.selectedOptions[0]?.dataset.value || 0);
  const scope = document.getElementById("proposal-scope").value.trim();
  const errorEl = document.getElementById("add-proposal-error");
  errorEl.textContent = "";

  const { data: thresholdRow } = await supabase
    .from("settings")
    .select("value")
    .eq("key", "second_reviewer_threshold")
    .maybeSingle();
  const threshold = Number(thresholdRow?.value || 0);

  const { error } = await supabase.from("proposals").insert({
    opportunity_id: opportunityId,
    scope,
    requires_second_reviewer: opportunityValue > threshold
  });

  if (error) {
    errorEl.textContent = error.message;
    return;
  }
  form.reset();
  await loadProposals();
});

document.getElementById("add-finding-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const clientName = document.getElementById("finding-client").value.trim();
  const note = document.getElementById("finding-note").value.trim();
  const errorEl = document.getElementById("add-finding-error");
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

  const { error } = await supabase.from("opportunities").insert({
    client_id: clientId,
    pipeline_type: "private",
    stage: "lead",
    notes: note,
    owner_id: currentProfile.id
  });

  if (error) {
    errorEl.textContent = error.message;
    return;
  }
  form.reset();
});

async function loadCybersecurityModule() {
  await Promise.all([loadProposals(), populateProposalOpportunitySelect()]);
}

// ---- IT Delivery module ----

const TICKET_STATUS_OPTIONS = ["open", "in_progress", "resolved"];

async function loadDeliveryTickets() {
  const tbody = document.getElementById("delivery-body");
  const { data, error } = await supabase
    .from("delivery_tickets")
    .select("id, title, sla_target, status")
    .eq("department", "it_delivery")
    .order("created_at", { ascending: false });

  if (error) {
    tbody.innerHTML = `<tr><td colspan="3" class="empty">${error.message}</td></tr>`;
    return;
  }
  if (!data.length) {
    tbody.innerHTML = `<tr><td colspan="3" class="empty">No engagements logged yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = "";
  data.forEach((t) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${t.title ?? "Untitled engagement"}</td>
      <td>${t.sla_target ?? "—"}</td>
      <td>
        <select data-id="${t.id}" class="ticket-status-select">
          ${TICKET_STATUS_OPTIONS.map(
            (s) => `<option value="${s}" ${s === t.status ? "selected" : ""}>${s.replace("_", " ")}</option>`
          ).join("")}
        </select>
      </td>
    `;
    tbody.appendChild(tr);
  });

  tbody.querySelectorAll(".ticket-status-select").forEach((select) => {
    select.addEventListener("change", async (e) => {
      const { error: updateError } = await supabase
        .from("delivery_tickets")
        .update({ status: e.target.value })
        .eq("id", e.target.dataset.id);
      if (updateError) alert("Could not update this engagement. " + updateError.message);
    });
  });
}

document.getElementById("add-delivery-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const title = document.getElementById("delivery-title").value.trim();
  const sla = document.getElementById("delivery-sla").value.trim();
  const errorEl = document.getElementById("add-delivery-error");
  errorEl.textContent = "";

  const { error } = await supabase.from("delivery_tickets").insert({
    department: "it_delivery",
    title,
    sla_target: sla || null,
    status: "open"
  });

  if (error) {
    errorEl.textContent = error.message;
    return;
  }
  form.reset();
  await loadDeliveryTickets();
});

async function loadITDeliveryModule() {
  await loadDeliveryTickets();
}

// ---- Internal IT module ----

const PROVISIONING_STATUS_OPTIONS = ["pending", "in_progress", "complete"];

async function loadStaffEvents() {
  const tbody = document.getElementById("staff-events-body");
  const { data, error } = await supabase
    .from("staff_events")
    .select("id, staff_name, event_type, provisioning_status")
    .order("created_at", { ascending: false });

  if (error) {
    tbody.innerHTML = `<tr><td colspan="3" class="empty">${error.message}</td></tr>`;
    return;
  }
  if (!data.length) {
    tbody.innerHTML = `<tr><td colspan="3" class="empty">No events logged yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = "";
  data.forEach((ev) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${ev.staff_name}</td>
      <td>${ev.event_type}</td>
      <td>
        <select data-id="${ev.id}" class="staff-status-select">
          ${PROVISIONING_STATUS_OPTIONS.map(
            (s) => `<option value="${s}" ${s === ev.provisioning_status ? "selected" : ""}>${s.replace("_", " ")}</option>`
          ).join("")}
        </select>
      </td>
    `;
    tbody.appendChild(tr);
  });

  tbody.querySelectorAll(".staff-status-select").forEach((select) => {
    select.addEventListener("change", async (e) => {
      const { error: updateError } = await supabase
        .from("staff_events")
        .update({ provisioning_status: e.target.value })
        .eq("id", e.target.dataset.id);
      if (updateError) alert("Could not update this event. " + updateError.message);
    });
  });
}

document.getElementById("add-staff-event-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const staffName = document.getElementById("staff-name").value.trim();
  const eventType = document.getElementById("staff-event-type").value;
  const errorEl = document.getElementById("add-staff-event-error");
  errorEl.textContent = "";

  const { error } = await supabase.from("staff_events").insert({
    staff_name: staffName,
    event_type: eventType,
    raised_by_hr_officer_id: currentProfile.id,
    provisioning_status: "pending"
  });

  if (error) {
    errorEl.textContent = error.message;
    return;
  }
  form.reset();
  await loadStaffEvents();
});

async function loadInternalITModule() {
  await loadStaffEvents();
}

// ---- Finance module ----

async function loadInvoices() {
  const tbody = document.getElementById("invoices-body");

  const { data: thresholdRow } = await supabase
    .from("settings")
    .select("value")
    .eq("key", "md_approval_threshold")
    .maybeSingle();
  const threshold = Number(thresholdRow?.value || 0);

  const { data, error } = await supabase
    .from("invoices")
    .select("id, description, amount, approval_status")
    .order("created_at", { ascending: false });

  if (error) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty">${error.message}</td></tr>`;
    return;
  }
  if (!data.length) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty">No invoices raised yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = "";
  data.forEach((inv) => {
    const needsSystemApproval = Number(inv.amount) > threshold;
    const canApprove =
      inv.approval_status !== "approved" &&
      (!needsSystemApproval || currentProfile.role_tier === "system");
    let statusLabel = inv.approval_status;
    if (inv.approval_status === "pending" && needsSystemApproval) {
      statusLabel = "pending, needs System Super User";
    }
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${inv.description ?? "—"}</td>
      <td>${formatRand(inv.amount)}</td>
      <td>${statusLabel}</td>
      <td>${canApprove ? `<button type="button" class="btn-primary btn-small" data-id="${inv.id}">Approve</button>` : ""}</td>
    `;
    tbody.appendChild(tr);
  });

  tbody.querySelectorAll("button[data-id]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const { error: updateError } = await supabase
        .from("invoices")
        .update({ approval_status: "approved", approved_by: currentProfile.id })
        .eq("id", btn.dataset.id);
      if (updateError) alert("Could not approve this invoice. " + updateError.message);
      await loadInvoices();
    });
  });
}

document.getElementById("add-invoice-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const description = document.getElementById("invoice-description").value.trim();
  const amount = Number(document.getElementById("invoice-amount").value);
  const errorEl = document.getElementById("add-invoice-error");
  errorEl.textContent = "";

  const { error } = await supabase.from("invoices").insert({
    description,
    amount,
    approval_status: "pending"
  });

  if (error) {
    errorEl.textContent = error.message;
    return;
  }
  form.reset();
  await loadInvoices();
});

async function loadFinanceModule() {
  await loadInvoices();
}

// ---- Operations module ----

const PROJECT_STATUS_OPTIONS = ["active", "on_hold", "complete"];

async function loadProjects() {
  const tbody = document.getElementById("projects-body");
  const { data, error } = await supabase
    .from("projects")
    .select("id, title, status")
    .order("created_at", { ascending: false });

  if (error) {
    tbody.innerHTML = `<tr><td colspan="2" class="empty">${error.message}</td></tr>`;
    return;
  }
  if (!data.length) {
    tbody.innerHTML = `<tr><td colspan="2" class="empty">No projects logged yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = "";
  data.forEach((p) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${p.title ?? "Untitled project"}</td>
      <td>
        <select data-id="${p.id}" class="project-status-select">
          ${PROJECT_STATUS_OPTIONS.map(
            (s) => `<option value="${s}" ${s === p.status ? "selected" : ""}>${s.replace("_", " ")}</option>`
          ).join("")}
        </select>
      </td>
    `;
    tbody.appendChild(tr);
  });

  tbody.querySelectorAll(".project-status-select").forEach((select) => {
    select.addEventListener("change", async (e) => {
      const { error: updateError } = await supabase
        .from("projects")
        .update({ status: e.target.value })
        .eq("id", e.target.dataset.id);
      if (updateError) alert("Could not update this project. " + updateError.message);
    });
  });
}

document.getElementById("add-project-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const title = document.getElementById("project-title").value.trim();
  const errorEl = document.getElementById("add-project-error");
  errorEl.textContent = "";

  const { error } = await supabase.from("projects").insert({
    title,
    project_manager_id: currentProfile.id,
    status: "active"
  });

  if (error) {
    errorEl.textContent = error.message;
    return;
  }
  form.reset();
  await loadProjects();
});

async function loadNonConformances() {
  const tbody = document.getElementById("nc-body");
  const { data, error } = await supabase
    .from("non_conformances")
    .select("id, finding, due_date, closed_at")
    .order("created_at", { ascending: false });

  if (error) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty">${error.message}</td></tr>`;
    return;
  }
  if (!data.length) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty">No findings logged yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = "";
  data.forEach((nc) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${nc.finding}</td>
      <td>${nc.due_date ?? "—"}</td>
      <td>${nc.closed_at ? "Closed" : "Open"}</td>
      <td>${nc.closed_at ? "" : `<button type="button" class="btn-primary btn-small" data-id="${nc.id}">Close</button>`}</td>
    `;
    tbody.appendChild(tr);
  });

  tbody.querySelectorAll("button[data-id]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const { error: updateError } = await supabase
        .from("non_conformances")
        .update({ closed_at: new Date().toISOString() })
        .eq("id", btn.dataset.id);
      if (updateError) alert("Could not close this finding. " + updateError.message);
      await loadNonConformances();
    });
  });
}

document.getElementById("add-nc-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const finding = document.getElementById("nc-finding").value.trim();
  const due = document.getElementById("nc-due").value || null;
  const errorEl = document.getElementById("add-nc-error");
  errorEl.textContent = "";

  const { error } = await supabase.from("non_conformances").insert({
    finding,
    due_date: due,
    owner_id: currentProfile.id
  });

  if (error) {
    errorEl.textContent = error.message;
    return;
  }
  form.reset();
  await loadNonConformances();
});

async function loadClientOffboarding() {
  const tbody = document.getElementById("offboarding-body");
  const { data, error } = await supabase
    .from("client_offboarding")
    .select("id, data_returned, access_revoked, retention_confirmed, client_id, clients(name)")
    .order("created_at", { ascending: false });

  if (error) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty">${error.message}</td></tr>`;
    return;
  }
  if (!data.length) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty">No offboarding records yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = "";
  data.forEach((row) => {
    const clientName = row.clients ? row.clients.name : "Unknown client";
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><a href="#" class="client-link" data-client-id="${row.client_id}">${clientName}</a></td>
      <td><input type="checkbox" data-id="${row.id}" data-field="data_returned" ${row.data_returned ? "checked" : ""} /></td>
      <td><input type="checkbox" data-id="${row.id}" data-field="access_revoked" ${row.access_revoked ? "checked" : ""} /></td>
      <td><input type="checkbox" data-id="${row.id}" data-field="retention_confirmed" ${row.retention_confirmed ? "checked" : ""} /></td>
    `;
    tbody.appendChild(tr);
  });

  tbody.querySelectorAll("input[type=checkbox]").forEach((box) => {
    box.addEventListener("change", async (e) => {
      const patch = {};
      patch[e.target.dataset.field] = e.target.checked;
      const { error: updateError } = await supabase
        .from("client_offboarding")
        .update(patch)
        .eq("id", e.target.dataset.id);
      if (updateError) alert("Could not update this record. " + updateError.message);
    });
  });
}

document.getElementById("add-offboarding-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const clientName = document.getElementById("offboarding-client").value.trim();
  const errorEl = document.getElementById("add-offboarding-error");
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

  const { error } = await supabase.from("client_offboarding").insert({ client_id: clientId });

  if (error) {
    errorEl.textContent = error.message;
    return;
  }
  form.reset();
  await loadClientOffboarding();
});

async function loadOperationsModule() {
  await Promise.all([loadProjects(), loadNonConformances(), loadClientOffboarding()]);
}

// ---- Settings module ----

async function loadSettingsModule() {
  const { data, error } = await supabase.from("settings").select("key, value");
  const errorEl = document.getElementById("settings-error");
  errorEl.textContent = "";
  if (error) {
    errorEl.textContent = error.message;
    return;
  }
  const values = {};
  data.forEach((row) => (values[row.key] = row.value));
  document.getElementById("setting-second-reviewer").value = values.second_reviewer_threshold ?? 0;
  document.getElementById("setting-md-approval").value = values.md_approval_threshold ?? 0;
  document.getElementById("setting-renewal-days").value = values.contract_renewal_alert_days ?? 60;
}

document.getElementById("settings-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const errorEl = document.getElementById("settings-error");
  const successEl = document.getElementById("settings-success");
  errorEl.textContent = "";
  successEl.textContent = "";

  const updates = [
    { key: "second_reviewer_threshold", value: document.getElementById("setting-second-reviewer").value },
    { key: "md_approval_threshold", value: document.getElementById("setting-md-approval").value },
    { key: "contract_renewal_alert_days", value: document.getElementById("setting-renewal-days").value }
  ];

  for (const update of updates) {
    const { error } = await supabase
      .from("settings")
      .update({ value: String(update.value), updated_by: currentProfile.id })
      .eq("key", update.key);
    if (error) {
      errorEl.textContent = error.message;
      return;
    }
  }

  successEl.textContent = "Saved.";
});

// ---- Module loaders, keyed by nav item ----

const MODULE_LOADERS = {
  overview: loadHomeModule,
  my_work: loadTasksModule,
  notifications: loadNotificationsModule,
  sales: loadSalesModule,
  cybersecurity: loadCybersecurityModule,
  it_delivery: loadITDeliveryModule,
  internal_it: loadInternalITModule,
  finance: loadFinanceModule,
  operations: loadOperationsModule,
  settings: loadSettingsModule
};

// ---- Home dashboard ----

function statCard(label, value) {
  const div = document.createElement("div");
  div.className = "card";
  div.innerHTML = `<h2>${label}</h2><p style="font-size: 20px; font-weight: 600; color: var(--ink-900);">${value}</p>`;
  return div;
}

async function loadHomeModule() {
  const container = document.getElementById("home-cards");
  container.innerHTML = "";
  const dept = currentProfile.department;
  const isSystem = currentProfile.role_tier === "system";

  if (isSystem || dept === "sales") {
    const { data: opps } = await supabase.from("opportunities").select("value, stage");
    const openOpps = (opps || []).filter((o) => o.stage !== "won" && o.stage !== "lost");
    const openValue = openOpps.reduce((sum, o) => sum + (Number(o.value) || 0), 0);
    container.appendChild(statCard("Open opportunities", openOpps.length));
    container.appendChild(statCard("Open pipeline value", formatRand(openValue)));

    const { data: docs } = await supabase.from("compliance_documents").select("expiry_date");
    const expiringSoon = (docs || []).filter((d) => {
      const days = daysUntil(d.expiry_date);
      return days !== null && days <= 30;
    }).length;
    container.appendChild(statCard("Compliance documents expiring soon", expiringSoon));
  }

  if (isSystem || dept === "cybersecurity") {
    const { data: props } = await supabase.from("proposals").select("signed_off_by");
    const awaiting = (props || []).filter((p) => !p.signed_off_by).length;
    container.appendChild(statCard("Proposals awaiting scoping", awaiting));
  }

  if (isSystem || dept === "it_delivery") {
    const { data: tickets } = await supabase
      .from("delivery_tickets")
      .select("status")
      .eq("department", "it_delivery");
    const open = (tickets || []).filter((t) => t.status !== "resolved").length;
    container.appendChild(statCard("Open IT Delivery engagements", open));
  }

  if (isSystem || dept === "finance") {
    const { data: invs } = await supabase.from("invoices").select("amount, approval_status");
    const pending = (invs || []).filter((i) => i.approval_status !== "approved");
    const pendingValue = pending.reduce((sum, i) => sum + (Number(i.amount) || 0), 0);
    container.appendChild(statCard("Invoices pending approval", pending.length));
    container.appendChild(statCard("Value pending approval", formatRand(pendingValue)));
  }

  if (isSystem || dept === "operations") {
    const { data: ncs } = await supabase.from("non_conformances").select("closed_at");
    const open = (ncs || []).filter((n) => !n.closed_at).length;
    container.appendChild(statCard("Open quality findings", open));

    const { data: projs } = await supabase.from("projects").select("status");
    const active = (projs || []).filter((p) => p.status === "active").length;
    container.appendChild(statCard("Active projects", active));
  }

  if (isSystem || dept === "internal_it") {
    const { data: evs } = await supabase.from("staff_events").select("provisioning_status");
    const pending = (evs || []).filter((e) => e.provisioning_status !== "complete").length;
    container.appendChild(statCard("Staff events pending action", pending));
  }

  if (!container.children.length) {
    container.innerHTML = `<p class="intro">Nothing to show yet for your department.</p>`;
  }
}

// ---- Tasks, My Work ----

async function loadTasksModule() {
  const tbody = document.getElementById("tasks-body");
  const { data, error } = await supabase
    .from("tasks")
    .select("id, title, due_date, status")
    .order("due_date", { ascending: true, nullsFirst: false });

  if (error) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty">${error.message}</td></tr>`;
    return;
  }
  if (!data.length) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty">No tasks yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = "";
  data.forEach((t) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${t.title}</td>
      <td>${t.due_date ?? "—"}</td>
      <td>${t.status}</td>
      <td><button type="button" class="btn-primary btn-small" data-id="${t.id}" data-status="${t.status}">${t.status === "open" ? "Mark done" : "Reopen"}</button></td>
    `;
    tbody.appendChild(tr);
  });

  tbody.querySelectorAll("button[data-id]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const newStatus = btn.dataset.status === "open" ? "done" : "open";
      const { error: updateError } = await supabase
        .from("tasks")
        .update({ status: newStatus })
        .eq("id", btn.dataset.id);
      if (updateError) alert("Could not update this task. " + updateError.message);
      await loadTasksModule();
    });
  });
}

document.getElementById("add-task-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const title = document.getElementById("task-title").value.trim();
  const due = document.getElementById("task-due").value || null;
  const note = document.getElementById("task-note").value.trim() || null;
  const errorEl = document.getElementById("add-task-error");
  errorEl.textContent = "";

  const { error } = await supabase.from("tasks").insert({
    title,
    due_date: due,
    note,
    assigned_to: currentProfile.id,
    created_by: currentProfile.id
  });

  if (error) {
    errorEl.textContent = error.message;
    return;
  }
  form.reset();
  await loadTasksModule();
});

// ---- Notifications ----

async function updateNotificationBadge() {
  const { data } = await supabase.from("notifications").select("id").eq("read", false);
  const link = document.querySelector('.nav-link[data-module="notifications"]');
  if (!link) return;
  const existingBadge = link.querySelector(".nav-badge");
  if (existingBadge) existingBadge.remove();
  if (data && data.length) {
    const badge = document.createElement("span");
    badge.className = "nav-badge";
    badge.textContent = data.length;
    link.appendChild(badge);
  }
}

async function loadNotificationsModule() {
  const tbody = document.getElementById("notifications-body");
  const { data, error } = await supabase
    .from("notifications")
    .select("id, message, read, created_at")
    .order("created_at", { ascending: false });

  if (error) {
    tbody.innerHTML = `<tr><td colspan="3" class="empty">${error.message}</td></tr>`;
    return;
  }
  if (!data.length) {
    tbody.innerHTML = `<tr><td colspan="3" class="empty">Nothing here yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = "";
  data.forEach((n) => {
    const tr = document.createElement("tr");
    tr.style.opacity = n.read ? "0.55" : "1";
    tr.innerHTML = `
      <td>${n.message}</td>
      <td>${new Date(n.created_at).toLocaleDateString("en-ZA")}</td>
      <td>${n.read ? "" : `<button type="button" class="btn-primary btn-small" data-id="${n.id}">Mark read</button>`}</td>
    `;
    tbody.appendChild(tr);
  });

  tbody.querySelectorAll("button[data-id]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const { error: updateError } = await supabase
        .from("notifications")
        .update({ read: true })
        .eq("id", btn.dataset.id);
      if (updateError) alert("Could not update this notification. " + updateError.message);
      await loadNotificationsModule();
      await updateNotificationBadge();
    });
  });
}

// ---- Leads ----

async function loadLeads() {
  const tbody = document.getElementById("leads-body");
  const { data, error } = await supabase
    .from("leads")
    .select("id, name, source, status")
    .order("created_at", { ascending: false });

  if (error) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty">${error.message}</td></tr>`;
    return;
  }
  if (!data.length) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty">No leads logged yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = "";
  data.forEach((lead) => {
    const tr = document.createElement("tr");
    const convertButton =
      lead.status === "converted"
        ? ""
        : `<button type="button" class="btn-primary btn-small" data-id="${lead.id}" data-name="${lead.name}">Convert</button>`;
    tr.innerHTML = `
      <td>${lead.name}</td>
      <td>${lead.source ?? "—"}</td>
      <td>${lead.status}</td>
      <td>${convertButton}</td>
    `;
    tbody.appendChild(tr);
  });

  tbody.querySelectorAll("button[data-id]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const leadId = btn.dataset.id;
      const leadName = btn.dataset.name;

      const { data: existingClient } = await supabase
        .from("clients")
        .select("id")
        .eq("name", leadName)
        .maybeSingle();

      let clientId = existingClient ? existingClient.id : null;
      if (!clientId) {
        const { data: newClient, error: clientError } = await supabase
          .from("clients")
          .insert({ name: leadName })
          .select("id")
          .single();
        if (clientError) {
          alert("Could not create the client record. " + clientError.message);
          return;
        }
        clientId = newClient.id;
      }

      const { error: oppError } = await supabase.from("opportunities").insert({
        client_id: clientId,
        pipeline_type: "private",
        stage: "lead",
        owner_id: currentProfile.id
      });
      if (oppError) {
        alert("Could not create the opportunity. " + oppError.message);
        return;
      }

      await supabase.from("leads").update({ status: "converted" }).eq("id", leadId);
      await loadLeads();
      await loadPipeline("private", "sales-private-body");
    });
  });
}

document.getElementById("add-lead-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const name = document.getElementById("lead-name").value.trim();
  const source = document.getElementById("lead-source").value.trim() || null;
  const rawValue = document.getElementById("lead-value").value;
  const value = rawValue === "" ? null : Number(rawValue);
  const errorEl = document.getElementById("add-lead-error");
  errorEl.textContent = "";

  const { error } = await supabase.from("leads").insert({
    name,
    source,
    value,
    owner_id: currentProfile.id
  });

  if (error) {
    errorEl.textContent = error.message;
    return;
  }
  form.reset();
  await loadLeads();
});

// ---- Campaigns ----

async function loadCampaigns() {
  const tbody = document.getElementById("campaigns-body");
  const { data, error } = await supabase
    .from("campaigns")
    .select("id, name, channel, budget, status")
    .order("created_at", { ascending: false });

  if (error) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty">${error.message}</td></tr>`;
    return;
  }
  if (!data.length) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty">No campaigns logged yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = "";
  data.forEach((c) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${c.name}</td>
      <td>${c.channel ?? "—"}</td>
      <td>${formatRand(c.budget)}</td>
      <td>${c.status}</td>
    `;
    tbody.appendChild(tr);
  });
}

document.getElementById("add-campaign-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const name = document.getElementById("campaign-name").value.trim();
  const channel = document.getElementById("campaign-channel").value.trim() || null;
  const rawBudget = document.getElementById("campaign-budget").value;
  const budget = rawBudget === "" ? null : Number(rawBudget);
  const errorEl = document.getElementById("add-campaign-error");
  errorEl.textContent = "";

  const { error } = await supabase.from("campaigns").insert({ name, channel, budget });

  if (error) {
    errorEl.textContent = error.message;
    return;
  }
  form.reset();
  await loadCampaigns();
});

// ---- Events ----

async function loadEvents() {
  const tbody = document.getElementById("events-body");
  const { data, error } = await supabase
    .from("events")
    .select("id, name, event_type, event_date")
    .order("event_date", { ascending: true });

  if (error) {
    tbody.innerHTML = `<tr><td colspan="3" class="empty">${error.message}</td></tr>`;
    return;
  }
  if (!data.length) {
    tbody.innerHTML = `<tr><td colspan="3" class="empty">No events logged yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = "";
  data.forEach((ev) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${ev.name}</td>
      <td>${ev.event_type ?? "—"}</td>
      <td>${ev.event_date ?? "—"}</td>
    `;
    tbody.appendChild(tr);
  });
}

document.getElementById("add-event-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const name = document.getElementById("event-name").value.trim();
  const eventType = document.getElementById("event-type").value.trim() || null;
  const eventDate = document.getElementById("event-date").value || null;
  const errorEl = document.getElementById("add-event-error");
  errorEl.textContent = "";

  const { error } = await supabase.from("events").insert({
    name,
    event_type: eventType,
    event_date: eventDate
  });

  if (error) {
    errorEl.textContent = error.message;
    return;
  }
  form.reset();
  await loadEvents();
});

// ---- Global search ----

let searchTimer = null;
const searchInput = document.getElementById("global-search");
const searchResults = document.getElementById("search-results");

searchInput.addEventListener("input", () => {
  clearTimeout(searchTimer);
  const query = searchInput.value.trim();
  if (query.length < 2) {
    searchResults.classList.add("hidden");
    return;
  }
  searchTimer = setTimeout(() => runSearch(query), 300);
});

document.addEventListener("click", (e) => {
  if (!e.target.closest(".sidebar-search")) {
    searchResults.classList.add("hidden");
  }
});

async function runSearch(query) {
  const results = [];

  const { data: clientMatches } = await supabase
    .from("clients")
    .select("id, name")
    .ilike("name", `%${query}%`)
    .limit(5);
  (clientMatches || []).forEach((c) => results.push({ type: "Client", label: c.name, module: "sales" }));

  const { data: projectMatches } = await supabase
    .from("projects")
    .select("id, title")
    .ilike("title", `%${query}%`)
    .limit(5);
  (projectMatches || []).forEach((p) =>
    results.push({ type: "Project", label: p.title ?? "Untitled project", module: "operations" })
  );

  const { data: invoiceMatches } = await supabase
    .from("invoices")
    .select("id, description")
    .ilike("description", `%${query}%`)
    .limit(5);
  (invoiceMatches || []).forEach((i) =>
    results.push({ type: "Invoice", label: i.description ?? "Untitled invoice", module: "finance" })
  );

  if (!results.length) {
    searchResults.innerHTML = `<div class="search-result-item">No matches</div>`;
    searchResults.classList.remove("hidden");
    return;
  }

  searchResults.innerHTML = results
    .map(
      (r) =>
        `<div class="search-result-item" data-module="${r.module}"><span class="result-type">${r.type}</span>${r.label}</div>`
    )
    .join("");
  searchResults.classList.remove("hidden");

  searchResults.querySelectorAll(".search-result-item[data-module]").forEach((item) => {
    item.addEventListener("click", () => {
      const moduleKey = item.dataset.module;
      showModule(moduleKey);
      if (MODULE_LOADERS[moduleKey]) MODULE_LOADERS[moduleKey]();
      document.querySelectorAll(".nav-link").forEach((el) => {
        el.classList.toggle("active", el.dataset.module === moduleKey);
      });
      searchResults.classList.add("hidden");
      searchInput.value = "";
    });
  });
}

// ---- Client workspace ----

let lastModuleBeforeWorkspace = "overview";

document.addEventListener("click", (e) => {
  const link = e.target.closest(".client-link");
  if (link) {
    e.preventDefault();
    openClientWorkspace(link.dataset.clientId);
  }
});

async function openClientWorkspace(clientId) {
  const currentActive = document.querySelector(".nav-link.active");
  if (currentActive) lastModuleBeforeWorkspace = currentActive.dataset.module;
  window.location.hash = "client/" + clientId;
  showModule("client_workspace");
  document.querySelectorAll(".nav-link").forEach((el) => el.classList.remove("active"));
  await loadClientWorkspace(clientId);
}

document.getElementById("workspace-back").addEventListener("click", (e) => {
  e.preventDefault();
  window.location.hash = "";
  showModule(lastModuleBeforeWorkspace);
  document.querySelectorAll(".nav-link").forEach((el) => {
    el.classList.toggle("active", el.dataset.module === lastModuleBeforeWorkspace);
  });
  if (MODULE_LOADERS[lastModuleBeforeWorkspace]) MODULE_LOADERS[lastModuleBeforeWorkspace]();
});

async function loadClientWorkspace(clientId) {
  const container = document.getElementById("client-workspace-content");
  container.innerHTML = `<p class="intro">Loading</p>`;

  const { data: client, error: clientError } = await supabase
    .from("clients")
    .select("id, name, sector")
    .eq("id", clientId)
    .single();

  if (clientError || !client) {
    container.innerHTML = `<p class="error">Could not load this client.</p>`;
    return;
  }

  const { data: opportunities } = await supabase
    .from("opportunities")
    .select("id, pipeline_type, stage, value")
    .eq("client_id", clientId);

  const { data: contracts } = await supabase
    .from("contracts")
    .select("id, end_date")
    .eq("client_id", clientId);

  const contractIds = (contracts || []).map((c) => c.id);
  const { data: projects } = contractIds.length
    ? await supabase.from("projects").select("id, title, status").in("contract_id", contractIds)
    : { data: [] };

  const projectIds = (projects || []).map((p) => p.id);
  const { data: invoices } = projectIds.length
    ? await supabase.from("invoices").select("id, description, amount, approval_status").in("project_id", projectIds)
    : { data: [] };

  const { data: notes } = await supabase
    .from("client_notes")
    .select("id, note, created_at")
    .eq("client_id", clientId)
    .order("created_at", { ascending: false });

  const { data: clientTasks } = await supabase
    .from("tasks")
    .select("id, title, due_date, status")
    .eq("client_id", clientId)
    .order("due_date", { ascending: true, nullsFirst: false });

  container.innerHTML = `
    <h1>${client.name}</h1>
    <p class="intro">${client.sector ?? "No sector recorded"}</p>

    <div class="section">
      <div class="section-header"><h2>Opportunities</h2></div>
      <table class="data-table">
        <thead><tr><th>Pipeline</th><th>Stage</th><th>Value</th></tr></thead>
        <tbody>
          ${
            (opportunities || []).length
              ? opportunities
                  .map((o) => `<tr><td>${o.pipeline_type}</td><td>${o.stage}</td><td>${formatRand(o.value)}</td></tr>`)
                  .join("")
              : `<tr><td colspan="3" class="empty">None yet.</td></tr>`
          }
        </tbody>
      </table>
    </div>

    <div class="section">
      <div class="section-header"><h2>Contracts</h2></div>
      <table class="data-table">
        <thead><tr><th>End date</th></tr></thead>
        <tbody>
          ${
            (contracts || []).length
              ? contracts.map((c) => `<tr><td>${c.end_date ?? "—"}</td></tr>`).join("")
              : `<tr><td class="empty">None yet.</td></tr>`
          }
        </tbody>
      </table>
    </div>

    <div class="section">
      <div class="section-header"><h2>Projects</h2></div>
      <table class="data-table">
        <thead><tr><th>Project</th><th>Status</th></tr></thead>
        <tbody>
          ${
            (projects || []).length
              ? projects.map((p) => `<tr><td>${p.title ?? "Untitled"}</td><td>${p.status}</td></tr>`).join("")
              : `<tr><td colspan="2" class="empty">None yet.</td></tr>`
          }
        </tbody>
      </table>
    </div>

    <div class="section">
      <div class="section-header"><h2>Invoices</h2></div>
      <table class="data-table">
        <thead><tr><th>Description</th><th>Amount</th><th>Status</th></tr></thead>
        <tbody>
          ${
            (invoices || []).length
              ? invoices
                  .map((i) => `<tr><td>${i.description ?? "—"}</td><td>${formatRand(i.amount)}</td><td>${i.approval_status}</td></tr>`)
                  .join("")
              : `<tr><td colspan="3" class="empty">None yet.</td></tr>`
          }
        </tbody>
      </table>
    </div>

    <div class="section">
      <div class="section-header"><h2>Notes</h2></div>
      <table class="data-table">
        <thead><tr><th>Note</th><th>When</th></tr></thead>
        <tbody>
          ${
            (notes || []).length
              ? notes
                  .map((n) => `<tr><td>${n.note}</td><td>${new Date(n.created_at).toLocaleDateString("en-ZA")}</td></tr>`)
                  .join("")
              : `<tr><td colspan="2" class="empty">None yet.</td></tr>`
          }
        </tbody>
      </table>
      <form id="add-note-form" class="inline-form">
        <input id="note-text" type="text" placeholder="Add a note" required />
        <button type="submit">Add note</button>
      </form>
      <p id="add-note-error" class="error"></p>
    </div>

    <div class="section">
      <div class="section-header"><h2>Tasks for this client</h2></div>
      <table class="data-table">
        <thead><tr><th>Task</th><th>Due date</th><th>Status</th></tr></thead>
        <tbody>
          ${
            (clientTasks || []).length
              ? clientTasks.map((t) => `<tr><td>${t.title}</td><td>${t.due_date ?? "—"}</td><td>${t.status}</td></tr>`).join("")
              : `<tr><td colspan="3" class="empty">None yet.</td></tr>`
          }
        </tbody>
      </table>
      <form id="add-client-task-form" class="inline-form">
        <input id="client-task-title" type="text" placeholder="Task" required />
        <input id="client-task-due" type="date" />
        <button type="submit">Add task</button>
      </form>
      <p id="add-client-task-error" class="error"></p>
    </div>
  `;

  document.getElementById("add-note-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const noteText = document.getElementById("note-text").value.trim();
    const errorEl = document.getElementById("add-note-error");
    errorEl.textContent = "";
    const { error } = await supabase.from("client_notes").insert({
      client_id: clientId,
      note: noteText,
      created_by: currentProfile.id
    });
    if (error) {
      errorEl.textContent = error.message;
      return;
    }
    await loadClientWorkspace(clientId);
  });

  document.getElementById("add-client-task-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const title = document.getElementById("client-task-title").value.trim();
    const due = document.getElementById("client-task-due").value || null;
    const errorEl = document.getElementById("add-client-task-error");
    errorEl.textContent = "";
    const { error } = await supabase.from("tasks").insert({
      title,
      due_date: due,
      client_id: clientId,
      assigned_to: currentProfile.id,
      created_by: currentProfile.id
    });
    if (error) {
      errorEl.textContent = error.message;
      return;
    }
    await loadClientWorkspace(clientId);
  });
}

// ---- Offline support ----
if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("sw.js");
  });
}
