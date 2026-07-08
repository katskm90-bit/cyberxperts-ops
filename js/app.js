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

  const canSeeApprovals =
    profile.role_tier === "system" || profile.department === "finance" || profile.department === "cybersecurity";
  if (canSeeApprovals) {
    items.push({ key: "approvals", label: "Approvals" });
  }

  const canSeePeople = profile.role_tier === "system" || profile.department === "operations";
  if (canSeePeople) {
    items.push({ key: "people", label: "People" });
  }

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

// Rule based deal health, not a machine learning score, every input is
// visible and explainable. Base of 50, adjusted by how recently the
// opportunity moved and how far along it is.
function computeRelationshipScore(contacts) {
  let score = 20;
  const list = contacts || [];
  if (list.some((c) => c.role_type === "decision_maker")) score += 25;
  if (list.some((c) => c.role_type === "champion")) score += 20;
  score += Math.min(list.length * 5, 20);
  const recentlyContacted = list.some((c) => {
    const days = daysUntil(c.last_contacted_at);
    return days !== null && days >= -30;
  });
  if (recentlyContacted) score += 15;
  score = Math.max(0, Math.min(100, score));
  let label = "Weak";
  let cls = "expired";
  if (score >= 70) {
    label = "Strong";
    cls = "valid";
  } else if (score >= 40) {
    label = "Developing";
    cls = "renew-soon";
  }
  return { score, label, cls };
}

function computeDealHealth(o) {
  let score = 50;
  const daysSinceUpdate = Math.round((new Date() - new Date(o.updated_at)) / (1000 * 60 * 60 * 24));

  if (daysSinceUpdate < 3) score += 10;
  else if (daysSinceUpdate >= 14) score -= 30;
  else if (daysSinceUpdate >= 7) score -= 15;

  if (o.stage && o.stage !== "lead") score += 15;
  if (o.value) score += 10;

  score = Math.max(0, Math.min(100, score));

  let label = "At risk";
  let cls = "expired";
  if (score >= 70) {
    label = "Healthy";
    cls = "valid";
  } else if (score >= 40) {
    label = "Watch";
    cls = "renew-soon";
  }
  return { score, label, cls };
}

async function loadPipeline(pipelineType, bodyId) {
  const tbody = document.getElementById(bodyId);

  const { data, error } = await supabase
    .from("opportunities")
    .select("id, stage, value, client_id, updated_at, clients(name)")
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
    const isOpen = row.stage !== "won" && row.stage !== "lost";
    let healthBadge = "";
    if (isOpen) {
      const health = computeDealHealth(row);
      healthBadge = `<span class="badge badge-${health.cls}" style="margin-left: 6px;" title="Score ${health.score} of 100">${health.label}</span>`;
    }
    tr.innerHTML = `
      <td><a href="#" class="client-link" data-client-id="${row.client_id}">${clientName}</a>${healthBadge}</td>
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

async function loadKanbanBoard() {
  const board = document.getElementById("kanban-board");
  const openStages = STAGE_OPTIONS.filter((s) => s !== "won" && s !== "lost");

  const { data, error } = await supabase
    .from("opportunities")
    .select("id, stage, value, updated_at, clients(name)")
    .not("stage", "in", "(won,lost)");

  if (error) {
    board.innerHTML = `<p class="error">${error.message}</p>`;
    return;
  }

  board.innerHTML = openStages
    .map((stage) => {
      const items = (data || []).filter((o) => o.stage === stage);
      return `
        <div class="kanban-column">
          <div class="kanban-column-header">${stage} · ${items.length}</div>
          <div class="kanban-cards" data-stage="${stage}">
            ${items
              .map((o) => {
                const clientName = o.clients ? o.clients.name : "Unknown client";
                const health = computeDealHealth(o);
                return `
                  <div class="kanban-card" draggable="true" data-id="${o.id}">
                    <div class="kanban-card-client">${clientName}</div>
                    <div class="kanban-card-meta">
                      ${formatRand(o.value)}
                      <span class="badge badge-${health.cls}">${health.label}</span>
                    </div>
                  </div>`;
              })
              .join("")}
          </div>
        </div>`;
    })
    .join("");

  document.querySelectorAll(".kanban-card").forEach((card) => {
    card.addEventListener("dragstart", (e) => {
      e.dataTransfer.setData("text/plain", card.dataset.id);
    });
  });

  document.querySelectorAll(".kanban-cards").forEach((col) => {
    col.addEventListener("dragover", (e) => e.preventDefault());
    col.addEventListener("drop", async (e) => {
      e.preventDefault();
      const id = e.dataTransfer.getData("text/plain");
      const newStage = col.dataset.stage;
      const { error: updateError } = await supabase
        .from("opportunities")
        .update({ stage: newStage })
        .eq("id", id);
      if (updateError) {
        alert("Could not move this opportunity. " + updateError.message);
        return;
      }
      await loadKanbanBoard();
      await loadPipeline("tender", "sales-tender-body");
      await loadPipeline("private", "sales-private-body");
      await loadPipeline("partner", "sales-partner-body");
    });
  });
}

async function loadWinLoss() {
  const container = document.getElementById("win-loss-cards");
  const { data, error } = await supabase.from("opportunities").select("stage, value");
  if (error) {
    container.innerHTML = `<p class="error">${error.message}</p>`;
    return;
  }
  const won = (data || []).filter((o) => o.stage === "won");
  const lost = (data || []).filter((o) => o.stage === "lost");
  const closed = won.length + lost.length;
  const winRate = closed ? Math.round((won.length / closed) * 100) : 0;
  const wonValue = won.reduce((sum, o) => sum + (Number(o.value) || 0), 0);

  container.innerHTML = "";
  container.appendChild(statCard("Win rate", closed ? winRate + "%" : "No closed deals yet"));
  container.appendChild(statCard("Won value", formatRand(wonValue)));
  container.appendChild(statCard("Lost deals", lost.length));
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
    loadEvents(),
    loadKanbanBoard(),
    loadWinLoss()
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
    .select("id, title, sla_target, sla_hours, status, created_at")
    .eq("department", "it_delivery")
    .order("created_at", { ascending: false });

  if (error) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty">${error.message}</td></tr>`;
    return;
  }
  if (!data.length) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty">No engagements logged yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = "";
  data.forEach((t) => {
    const tr = document.createElement("tr");
    let breachCell = "—";
    if (t.sla_hours && t.status !== "resolved") {
      const hoursElapsed = (new Date() - new Date(t.created_at)) / (1000 * 60 * 60);
      if (hoursElapsed > Number(t.sla_hours)) {
        breachCell = `<span class="badge badge-expired">Breached</span>`;
      } else {
        const hoursLeft = Math.round(Number(t.sla_hours) - hoursElapsed);
        breachCell = `<span class="badge badge-valid">${hoursLeft}h remaining</span>`;
      }
    }
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
      <td>${breachCell}</td>
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
      await loadDeliveryTickets();
    });
  });
}

document.getElementById("add-delivery-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const title = document.getElementById("delivery-title").value.trim();
  const sla = document.getElementById("delivery-sla").value.trim();
  const rawSlaHours = document.getElementById("delivery-sla-hours").value;
  const slaHours = rawSlaHours === "" ? null : Number(rawSlaHours);
  const errorEl = document.getElementById("add-delivery-error");
  errorEl.textContent = "";

  const { error } = await supabase.from("delivery_tickets").insert({
    department: "it_delivery",
    title,
    sla_target: sla || null,
    sla_hours: slaHours,
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
  const dueDate = document.getElementById("invoice-due").value || null;
  const errorEl = document.getElementById("add-invoice-error");
  errorEl.textContent = "";

  const { error } = await supabase.from("invoices").insert({
    description,
    amount,
    due_date: dueDate,
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
  await Promise.all([loadProjects(), loadNonConformances(), loadClientOffboarding(), populateMilestoneProjectSelect()]);
}

async function populateMilestoneProjectSelect() {
  const select = document.getElementById("milestone-project");
  const { data } = await supabase.from("projects").select("id, title").order("created_at", { ascending: false });
  select.innerHTML = (data || []).length
    ? data.map((p) => `<option value="${p.id}">${p.title ?? "Untitled project"}</option>`).join("")
    : `<option value="">No projects yet</option>`;
}

document.getElementById("add-milestone-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const projectId = document.getElementById("milestone-project").value;
  const title = document.getElementById("milestone-title").value.trim();
  const due = document.getElementById("milestone-due").value || null;
  const errorEl = document.getElementById("add-milestone-error");
  errorEl.textContent = "";

  if (!projectId) {
    errorEl.textContent = "Create a project first, then add milestones to it.";
    return;
  }

  const { error } = await supabase.from("milestones").insert({ project_id: projectId, title, due_date: due });
  if (error) {
    errorEl.textContent = error.message;
    return;
  }
  form.reset();
});

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
  document.getElementById("setting-revenue-target").value = values.monthly_revenue_target ?? 0;
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
    { key: "contract_renewal_alert_days", value: document.getElementById("setting-renewal-days").value },
    { key: "monthly_revenue_target", value: document.getElementById("setting-revenue-target").value }
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
  approvals: loadApprovalsModule,
  people: loadPeopleModule,
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

async function loadNeedsAttention() {
  const container = document.getElementById("needs-attention");
  const items = [];
  const dept = currentProfile.department;
  const isSystem = currentProfile.role_tier === "system";

  const { data: myTasks } = await supabase
    .from("tasks")
    .select("id, title, due_date")
    .eq("status", "open")
    .eq("assigned_to", currentProfile.id);
  (myTasks || []).forEach((t) =>
    items.push(`Task: ${t.title}${t.due_date ? " (due " + t.due_date + ")" : ""}`)
  );

  if (isSystem || dept === "cybersecurity") {
    const { data: props } = await supabase
      .from("proposals")
      .select("id, opportunities(clients(name))")
      .is("signed_off_by", null);
    (props || []).forEach((p) =>
      items.push(`Proposal awaiting scoping: ${p.opportunities?.clients?.name ?? "a client"}`)
    );
  }

  if (isSystem) {
    const { data: thresholdRow } = await supabase
      .from("settings")
      .select("value")
      .eq("key", "md_approval_threshold")
      .maybeSingle();
    const threshold = Number(thresholdRow?.value || 0);
    const { data: invs } = await supabase
      .from("invoices")
      .select("id, description, amount, approval_status")
      .neq("approval_status", "approved");
    (invs || [])
      .filter((i) => Number(i.amount) > threshold)
      .forEach((i) => items.push(`Invoice needs your approval: ${i.description ?? "invoice"}, ${formatRand(i.amount)}`));
  }

  if (!items.length) {
    container.innerHTML = `<p class="intro">Nothing needs your action right now.</p>`;
    return;
  }
  container.innerHTML = `<ul style="margin: 0; padding-left: 18px;">${items
    .map((i) => `<li style="margin-bottom: 6px; font-size: 14px;">${i}</li>`)
    .join("")}</ul>`;
}

function metricTile(label, value) {
  return `<div class="metric-tile"><div class="metric-label">${label}</div><div class="metric-value">${value}</div></div>`;
}

const STAGE_WEIGHT = {
  lead: 0.1,
  qualifying: 0.25,
  scoping: 0.4,
  proposal: 0.6,
  submitted: 0.8,
  won: 1,
  lost: 0
};

async function fetchSafely(queryPromise) {
  try {
    const { data, error } = await queryPromise;
    if (error) {
      console.error(error);
      return [];
    }
    return data || [];
  } catch (err) {
    console.error(err);
    return [];
  }
}

function safeChart(canvasId, config, hasData) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  if (!hasData) {
    const p = document.createElement("p");
    p.className = "intro";
    p.textContent = "No data available yet.";
    canvas.replaceWith(p);
    return;
  }
  if (typeof Chart === "undefined") {
    const p = document.createElement("p");
    p.className = "intro";
    p.textContent = "Chart library did not load. Figures are shown in the tables.";
    canvas.replaceWith(p);
    return;
  }
  try {
    const key = canvasId + "_instance";
    if (window[key]) window[key].destroy();
    window[key] = new Chart(canvas, config);
  } catch (err) {
    console.error(err);
    const p = document.createElement("p");
    p.className = "intro";
    p.textContent = "Could not render this chart.";
    canvas.replaceWith(p);
  }
}

function emptyRow(colspan, message) {
  return `<tr><td colspan="${colspan}" class="empty">${message}</td></tr>`;
}

function showSection(id, visible) {
  const el = document.getElementById(id);
  if (el) el.classList.toggle("hidden", !visible);
}

function monthKey(dateLike) {
  return new Date(dateLike).toLocaleDateString("en-ZA", { month: "short", year: "2-digit" });
}

function daysAgo(dateLike) {
  return Math.round((new Date() - new Date(dateLike)) / (1000 * 60 * 60 * 24));
}

// ---- Renderers, all synchronous, all fed from one prefetched object ----

function renderMetricRow(d, dept, isSystem) {
  const tiles = [];
  const now = new Date();
  const wonEvents = d.stageHistory.filter((h) => h.stage === "won");

  function wonInPeriod(from) {
    return wonEvents
      .filter((h) => new Date(h.changed_at) >= from)
      .reduce((s, h) => s + Number(h.opportunities?.value || 0), 0);
  }

  if (isSystem || dept === "sales") {
    const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);
    const quarterStart = new Date(now.getFullYear(), Math.floor(now.getMonth() / 3) * 3, 1);
    const yearStart = new Date(now.getFullYear(), 0, 1);
    tiles.push({ label: "Revenue this month", value: formatRand(wonInPeriod(monthStart)) });
    tiles.push({ label: "Revenue this quarter", value: formatRand(wonInPeriod(quarterStart)) });
    tiles.push({ label: "Revenue this year", value: formatRand(wonInPeriod(yearStart)) });

    const open = d.opportunities.filter((o) => o.stage !== "won" && o.stage !== "lost");
    tiles.push({ label: "Pipeline value", value: formatRand(open.reduce((s, o) => s + Number(o.value || 0), 0)) });
    tiles.push({
      label: "Forecast value",
      value: formatRand(open.reduce((s, o) => s + Number(o.value || 0) * (STAGE_WEIGHT[o.stage] ?? 0.1), 0))
    });

    const won = d.opportunities.filter((o) => o.stage === "won").length;
    const lost = d.opportunities.filter((o) => o.stage === "lost").length;
    tiles.push({ label: "Win rate", value: won + lost ? Math.round((won / (won + lost)) * 100) + "%" : "No closed deals" });
    tiles.push({ label: "Gross margin", value: "No expense data" });
    tiles.push({ label: "Contracts expiring", value: d.contractsNeedingRenewal.length });
    tiles.push({ label: "Compliance risks", value: d.complianceExpiringSoon.length });

    const activeClientIds = new Set();
    d.opportunities.filter((o) => o.stage !== "lost").forEach((o) => o.client_id && activeClientIds.add(o.client_id));
    d.contracts
      .filter((c) => {
        const days = daysUntil(c.end_date);
        return days === null || days >= 0;
      })
      .forEach((c) => c.client_id && activeClientIds.add(c.client_id));
    tiles.push({ label: "Active clients", value: activeClientIds.size });
  }

  if (isSystem || dept === "operations" || dept === "it_delivery") {
    tiles.push({ label: "Projects at risk", value: d.projectsAtRisk.length });
    tiles.push({ label: "Staff utilisation", value: d.utilisationPercent + "%" });
    tiles.push({ label: "Open support workload", value: d.tickets.filter((t) => t.status !== "resolved").length });
  }

  if (isSystem || dept === "finance") {
    const outstanding = d.invoices.filter((i) => i.approval_status !== "approved");
    tiles.push({ label: "Outstanding invoices", value: formatRand(outstanding.reduce((s, i) => s + Number(i.amount || 0), 0)) });
  }

  document.getElementById("metric-row").innerHTML = tiles.length
    ? tiles.map((t) => metricTile(t.label, t.value)).join("")
    : `<p class="intro">No figures available for your role yet.</p>`;
}

function renderSmartInsights(d, dept, isSystem) {
  const insights = [];
  const now = new Date();

  if (isSystem || dept === "sales") {
    const monthStart = new Date(now.getFullYear(), now.getMonth(), 1);
    const revenueThisMonth = d.stageHistory
      .filter((h) => h.stage === "won" && new Date(h.changed_at) >= monthStart)
      .reduce((s, h) => s + Number(h.opportunities?.value || 0), 0);
    if (d.revenueTarget > 0) {
      const pct = Math.round((revenueThisMonth / d.revenueTarget) * 100);
      if (pct < 100) insights.push(`Revenue is ${100 - pct}% behind this month's target.`);
      else insights.push(`Revenue is ${pct - 100}% ahead of this month's target.`);
    }

    const thisMonthNew = d.stageHistory.filter((h) => new Date(h.changed_at) >= monthStart).length;
    const lastMonthStart = new Date(now.getFullYear(), now.getMonth() - 1, 1);
    const lastMonthNew = d.stageHistory.filter(
      (h) => new Date(h.changed_at) >= lastMonthStart && new Date(h.changed_at) < monthStart
    ).length;
    if (lastMonthNew > 0 && thisMonthNew < lastMonthNew) {
      insights.push(`Sales pipeline activity has slowed compared to last month, ${thisMonthNew} movements against ${lastMonthNew}.`);
    }

    if (d.stalledOpportunities.length) {
      insights.push(`${d.stalledOpportunities.length} proposal${d.stalledOpportunities.length === 1 ? "" : "s"} have stalled for over fourteen days.`);
    }
    if (d.contractsNeedingRenewal.length) {
      insights.push(`${d.contractsNeedingRenewal.length} contract${d.contractsNeedingRenewal.length === 1 ? "" : "s"} expire within ${d.renewalAlertDays} days.`);
    }
  }

  if (isSystem || dept === "operations") {
    if (d.projectsAtRisk.length) insights.push(`${d.projectsAtRisk.length} project${d.projectsAtRisk.length === 1 ? "" : "s"} require immediate intervention.`);
    if (d.overAllocatedCount) insights.push(`${d.overAllocatedCount} staff member${d.overAllocatedCount === 1 ? "" : "s"} exceed 100% allocation.`);
  }

  if (isSystem || dept === "finance") {
    const pending = d.invoices.filter((i) => i.approval_status !== "approved");
    const pendingValue = pending.reduce((s, i) => s + Number(i.amount || 0), 0);
    if (pendingValue > 0) insights.push(`Finance has ${formatRand(pendingValue)} awaiting approval.`);
    if (d.overdueInvoices.length) insights.push(`${d.overdueInvoices.length} invoice${d.overdueInvoices.length === 1 ? "" : "s"} are overdue.`);
  }

  if (isSystem || dept === "sales" || dept === "operations") {
    if (d.complianceExpiringSoon.length) insights.push(`${d.complianceExpiringSoon.length} compliance document${d.complianceExpiringSoon.length === 1 ? "" : "s"} expire soon.`);
    if (d.noRecentContactClients.length) insights.push(`${d.noRecentContactClients.length} client${d.noRecentContactClients.length === 1 ? "" : "s"} have had no contact in over forty five days.`);
  }

  document.getElementById("smart-insights").innerHTML = insights.length
    ? `<ul style="margin: 0; padding-left: 18px;">${insights.map((i) => `<li style="margin-bottom: 6px; font-size: 14px;">${i}</li>`).join("")}</ul>`
    : `<p class="intro">No issues require executive attention.</p>`;
}

function renderSalesIntelligence(d, dept, isSystem) {
  const visible = isSystem || dept === "sales";
  showSection("section-revenue", visible);
  if (!visible) return;

  const wonEvents = d.stageHistory.filter((h) => h.stage === "won");
  const lostEvents = d.stageHistory.filter((h) => h.stage === "lost");

  const wonBuckets = {};
  wonEvents.forEach((h) => {
    const key = monthKey(h.changed_at);
    wonBuckets[key] = (wonBuckets[key] || 0) + Number(h.opportunities?.value || 0);
  });
  const wonLabels = Object.keys(wonBuckets).slice(-6);
  safeChart(
    "chart-monthly-revenue",
    {
      type: "line",
      data: { labels: wonLabels, datasets: [{ data: wonLabels.map((k) => wonBuckets[k]), borderColor: "#2b4d86", backgroundColor: "rgba(43,77,134,0.1)", fill: true, tension: 0.3 }] },
      options: { plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true } } }
    },
    wonLabels.length > 0
  );

  const createdBuckets = {};
  const firstSeen = {};
  d.stageHistory.forEach((h) => {
    if (!firstSeen[h.opportunity_id] || new Date(h.changed_at) < new Date(firstSeen[h.opportunity_id])) {
      firstSeen[h.opportunity_id] = h.changed_at;
    }
  });
  Object.values(firstSeen).forEach((at) => {
    const key = monthKey(at);
    createdBuckets[key] = (createdBuckets[key] || 0) + 1;
  });
  const createdLabels = Object.keys(createdBuckets).slice(-6);
  safeChart(
    "chart-pipeline-trend",
    {
      type: "bar",
      data: { labels: createdLabels, datasets: [{ data: createdLabels.map((k) => createdBuckets[k]), backgroundColor: "#2b4d86" }] },
      options: { plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } }
    },
    createdLabels.length > 0
  );

  const openStages = STAGE_OPTIONS.filter((s) => s !== "won" && s !== "lost");
  const funnelValues = openStages.map((s) =>
    d.opportunities.filter((o) => o.stage === s).reduce((sum, o) => sum + Number(o.value || 0), 0)
  );
  safeChart(
    "chart-funnel",
    {
      type: "bar",
      data: { labels: openStages, datasets: [{ data: funnelValues, backgroundColor: "#2b4d86" }] },
      options: { indexAxis: "y", plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true } } }
    },
    funnelValues.some((v) => v > 0)
  );

  const wlBuckets = {};
  [...wonEvents, ...lostEvents].forEach((h) => {
    const key = monthKey(h.changed_at);
    if (!wlBuckets[key]) wlBuckets[key] = { won: 0, lost: 0 };
    wlBuckets[key][h.stage] += 1;
  });
  const wlLabels = Object.keys(wlBuckets).slice(-6);
  safeChart(
    "chart-winloss",
    {
      type: "bar",
      data: {
        labels: wlLabels,
        datasets: [
          { label: "Won", data: wlLabels.map((k) => wlBuckets[k].won), backgroundColor: "#1f7a4d" },
          { label: "Lost", data: wlLabels.map((k) => wlBuckets[k].lost), backgroundColor: "#c02a2a" }
        ]
      },
      options: { plugins: { legend: { position: "bottom", labels: { boxWidth: 12, font: { size: 11 } } } }, scales: { y: { beginAtZero: true, ticks: { precision: 0 } } } }
    },
    wlLabels.length > 0
  );

  const avgDealSize = wonEvents.length
    ? formatRand(wonEvents.reduce((s, h) => s + Number(h.opportunities?.value || 0), 0) / wonEvents.length)
    : "No won deals yet";
  const byOpp = {};
  d.stageHistory.forEach((r) => {
    if (!byOpp[r.opportunity_id]) byOpp[r.opportunity_id] = [];
    byOpp[r.opportunity_id].push(r);
  });
  const cycles = [];
  Object.values(byOpp).forEach((rows) => {
    const wonRow = rows.find((r) => r.stage === "won");
    if (!wonRow) return;
    const earliest = rows.reduce((a, b) => (new Date(a.changed_at) < new Date(b.changed_at) ? a : b));
    const days = Math.round((new Date(wonRow.changed_at) - new Date(earliest.changed_at)) / (1000 * 60 * 60 * 24));
    if (days >= 0) cycles.push(days);
  });
  const avgCycle = cycles.length ? Math.round(cycles.reduce((s, c) => s + c, 0) / cycles.length) + " days" : "Not enough data yet";

  document.getElementById("revenue-stats").innerHTML = [
    metricTile("Average deal size", avgDealSize),
    metricTile("Average sales cycle", avgCycle)
  ].join("");

  const leaderboard = {};
  wonEvents.forEach((h) => {
    const name = h.opportunities?.profiles?.full_name ?? "Unassigned";
    leaderboard[name] = (leaderboard[name] || 0) + Number(h.opportunities?.value || 0);
  });
  const lbRows = Object.entries(leaderboard).sort((a, b) => b[1] - a[1]);
  document.getElementById("leaderboard-body").innerHTML = lbRows.length
    ? lbRows.map(([name, value]) => `<tr><td>${name}</td><td>${formatRand(value)}</td></tr>`).join("")
    : emptyRow(2, "No won deals recorded.");

  const largest = d.opportunities
    .filter((o) => o.stage !== "won" && o.stage !== "lost" && o.value)
    .sort((a, b) => Number(b.value) - Number(a.value))
    .slice(0, 5);
  document.getElementById("largest-opps-body").innerHTML = largest.length
    ? largest.map((o) => `<tr><td>${o.clients?.name ?? "Unknown client"}</td><td>${formatRand(o.value)}</td><td>${o.stage}</td></tr>`).join("")
    : emptyRow(3, "No opportunities recorded.");

  document.getElementById("stalled-opps-body").innerHTML = d.stalledOpportunities.length
    ? d.stalledOpportunities
        .map((o) => `<tr><td>${o.clients?.name ?? "Unknown client"}</td><td>${formatRand(o.value)}</td><td>${daysAgo(o.updated_at)}</td></tr>`)
        .join("")
    : emptyRow(3, "Nothing has stalled.");

  const reached = openStages.map((s, i) => {
    const stagesFromHere = STAGE_OPTIONS.slice(i);
    return new Set(d.stageHistory.filter((h) => stagesFromHere.includes(h.stage)).map((h) => h.opportunity_id)).size;
  });
  const convRows = [];
  for (let i = 0; i < openStages.length - 1; i++) {
    const pct = reached[i] ? Math.round((reached[i + 1] / reached[i]) * 100) + "%" : "—";
    convRows.push(`<tr><td>${openStages[i]}</td><td>${openStages[i + 1]}</td><td>${pct}</td></tr>`);
  }
  document.getElementById("conversion-body").innerHTML = d.stageHistory.length
    ? convRows.join("")
    : emptyRow(3, "No stage movements recorded.");

  const forecastBuckets = {};
  d.opportunities
    .filter((o) => o.stage !== "won" && o.stage !== "lost" && o.expected_close_date)
    .forEach((o) => {
      const key = monthKey(o.expected_close_date);
      forecastBuckets[key] = (forecastBuckets[key] || 0) + Number(o.value || 0) * (STAGE_WEIGHT[o.stage] ?? 0.1);
    });
  const fRows = Object.entries(forecastBuckets);
  document.getElementById("forecast-body").innerHTML = fRows.length
    ? fRows.map(([m, v]) => `<tr><td>${m}</td><td>${formatRand(v)}</td></tr>`).join("")
    : emptyRow(2, "No expected close dates recorded on open opportunities yet.");

  const reasons = {};
  d.opportunities.filter((o) => o.stage === "lost").forEach((o) => {
    const r = o.loss_reason || "Not recorded";
    reasons[r] = (reasons[r] || 0) + 1;
  });
  const rRows = Object.entries(reasons).sort((a, b) => b[1] - a[1]);
  document.getElementById("lost-reasons-body").innerHTML = rRows.length
    ? rRows.map(([r, c]) => `<tr><td>${r}</td><td>${c}</td></tr>`).join("")
    : emptyRow(2, "No lost opportunities recorded.");
}

function renderOperationsIntelligence(d, dept, isSystem) {
  const visible = isSystem || dept === "operations" || dept === "it_delivery";
  showSection("section-operations", visible);
  if (!visible) return;

  const slaTracked = d.tickets.filter((t) => t.sla_hours);
  const slaMet = slaTracked.length
    ? Math.round(((slaTracked.length - d.slaBreaches.length) / slaTracked.length) * 100) + "%"
    : "No SLA targets set";
  const bottlenecks = d.tickets.filter((t) => t.status !== "resolved" && daysAgo(t.created_at) > 7).length;
  const spareCapacity = d.staff.reduce((s, p) => s + Math.max(0, 100 - (d.allocationTotals[p.id] || 0)), 0);

  document.getElementById("operations-stats").innerHTML = [
    metricTile("Projects at risk", d.projectsAtRisk.length),
    metricTile("SLA performance", slaMet),
    metricTile("Delivery bottlenecks", bottlenecks),
    metricTile("Spare capacity", spareCapacity + "% across team"),
    metricTile("Overallocated staff", d.overAllocatedCount),
    metricTile("Idle staff", d.idleCount)
  ].join("");

  const active = d.projects.filter((p) => p.status !== "complete");
  document.getElementById("projects-health-body").innerHTML = active.length
    ? active
        .map((p) => {
          const idle = daysAgo(p.updated_at || p.created_at || new Date());
          let health = "On track";
          let cls = "valid";
          if (p.status === "on_hold") { health = "On hold"; cls = "expired"; }
          else if (idle >= 21) { health = "Stale, " + idle + " days"; cls = "expiring"; }
          return `<tr><td>${p.title ?? "Untitled"}</td><td>${p.status}</td><td><span class="badge badge-${cls}">${health}</span></td></tr>`;
        })
        .join("")
    : emptyRow(3, "No active projects.");

  const projectById = {};
  d.projects.forEach((p) => (projectById[p.id] = p.title ?? "Untitled"));
  const upcomingMilestones = d.milestones
    .filter((m) => !m.completed_at)
    .sort((a, b) => (a.due_date || "9999") < (b.due_date || "9999") ? -1 : 1);
  document.getElementById("milestones-body").innerHTML = upcomingMilestones.length
    ? upcomingMilestones
        .map((m) => `<tr><td>${m.title}</td><td>${projectById[m.project_id] ?? "—"}</td><td>${m.due_date ?? "—"}</td></tr>`)
        .join("")
    : emptyRow(3, "No milestones recorded. Add them in Operations.");

  document.getElementById("workload-body").innerHTML = d.staff.length
    ? d.staff
        .map((p) => {
          const total = d.allocationTotals[p.id] || 0;
          return `<tr><td>${p.full_name}</td><td>${total}%</td><td>${Math.max(0, 100 - total)}%</td></tr>`;
        })
        .join("")
    : emptyRow(3, "No staff records visible.");

  const deadlines = [];
  d.tasks.forEach((t) => {
    const days = daysUntil(t.due_date);
    if (days !== null && days >= 0 && days <= 14) deadlines.push({ item: t.title, type: "Task", due: t.due_date });
  });
  upcomingMilestones.forEach((m) => {
    const days = daysUntil(m.due_date);
    if (days !== null && days >= 0 && days <= 14) deadlines.push({ item: m.title, type: "Milestone", due: m.due_date });
  });
  deadlines.sort((a, b) => (a.due < b.due ? -1 : 1));
  document.getElementById("deadlines-body").innerHTML = deadlines.length
    ? deadlines.map((x) => `<tr><td>${x.item}</td><td>${x.type}</td><td>${x.due}</td></tr>`).join("")
    : emptyRow(3, "Nothing due in the next fourteen days.");
}

function renderFinancialIntelligence(d, dept, isSystem) {
  const visible = isSystem || dept === "finance";
  showSection("section-finance", visible);
  if (!visible) return;

  const cashBuckets = {};
  d.invoices
    .filter((i) => i.approval_status === "approved" && i.created_at)
    .forEach((i) => {
      const key = monthKey(i.created_at);
      cashBuckets[key] = (cashBuckets[key] || 0) + Number(i.amount || 0);
    });
  const cashLabels = Object.keys(cashBuckets).slice(-6);
  safeChart(
    "chart-cashflow",
    {
      type: "bar",
      data: { labels: cashLabels, datasets: [{ data: cashLabels.map((k) => cashBuckets[k]), backgroundColor: "#1f7a4d" }] },
      options: { plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true } } }
    },
    cashLabels.length > 0
  );

  const outstanding = d.invoices.filter((i) => i.approval_status !== "approved");
  const collected = d.invoices.filter((i) => i.approval_status === "approved");
  const overdueValue = d.overdueInvoices.reduce((s, i) => s + Number(i.amount || 0), 0);

  document.getElementById("finance-stats").innerHTML = [
    metricTile("Outstanding invoices", outstanding.length),
    metricTile("Outstanding value", formatRand(outstanding.reduce((s, i) => s + Number(i.amount || 0), 0))),
    metricTile("Collected value", formatRand(collected.reduce((s, i) => s + Number(i.amount || 0), 0))),
    metricTile("Collection risk", d.overdueInvoices.length ? formatRand(overdueValue) + " overdue" : "None overdue")
  ].join("");

  document.getElementById("approval-queue-body").innerHTML = outstanding.length
    ? outstanding
        .map((i) => `<tr><td>${i.description ?? "—"}</td><td>${formatRand(i.amount)}</td><td>${i.approval_status}</td></tr>`)
        .join("")
    : emptyRow(3, "No invoices awaiting approval.");

  const buckets = { "0 to 30 days": [], "31 to 60 days": [], "61 to 90 days": [], "Over 90 days": [] };
  d.overdueInvoices.forEach((i) => {
    const overdueDays = -daysUntil(i.due_date);
    if (overdueDays <= 30) buckets["0 to 30 days"].push(i);
    else if (overdueDays <= 60) buckets["31 to 60 days"].push(i);
    else if (overdueDays <= 90) buckets["61 to 90 days"].push(i);
    else buckets["Over 90 days"].push(i);
  });
  document.getElementById("aged-debtors-body").innerHTML = d.overdueInvoices.length
    ? Object.entries(buckets)
        .map(([label, list]) => `<tr><td>${label}</td><td>${list.length}</td><td>${formatRand(list.reduce((s, i) => s + Number(i.amount || 0), 0))}</td></tr>`)
        .join("")
    : emptyRow(3, "No overdue invoices.");

  const byClient = {};
  d.opportunities.filter((o) => o.stage === "won").forEach((o) => {
    const name = o.clients?.name ?? "Unknown client";
    byClient[name] = (byClient[name] || 0) + Number(o.value || 0);
  });
  const tcRows = Object.entries(byClient).sort((a, b) => b[1] - a[1]).slice(0, 5);
  document.getElementById("top-customers-body").innerHTML = tcRows.length
    ? tcRows.map(([n, v]) => `<tr><td>${n}</td><td>${formatRand(v)}</td></tr>`).join("")
    : emptyRow(2, "No won deals recorded.");

  const byPipeline = {};
  d.opportunities.filter((o) => o.stage === "won").forEach((o) => {
    const p = o.pipeline_type ?? "unspecified";
    byPipeline[p] = (byPipeline[p] || 0) + Number(o.value || 0);
  });
  const bpRows = Object.entries(byPipeline);
  document.getElementById("revenue-by-pipeline-body").innerHTML = bpRows.length
    ? bpRows.map(([p, v]) => `<tr><td>${p}</td><td>${formatRand(v)}</td></tr>`).join("")
    : emptyRow(2, "No won deals recorded.");
}

function renderComplianceIntelligence(d, dept, isSystem) {
  const visible = isSystem || dept === "sales" || dept === "operations" || dept === "cybersecurity";
  showSection("section-compliance", visible);
  if (!visible) return;

  const rows = [];
  d.complianceDocs.forEach((doc) => {
    const days = daysUntil(doc.expiry_date);
    let status = "No expiry set";
    if (days !== null) status = days < 0 ? "Expired" : days <= 30 ? days + " days left" : "Valid";
    rows.push({ item: doc.name, type: "Compliance document", status });
  });
  d.nonConformances
    .filter((n) => !n.closed_at)
    .forEach((n) => rows.push({ item: n.finding, type: "Corrective action", status: n.due_date ? "Due " + n.due_date : "Open" }));

  document.getElementById("compliance-workspace-body").innerHTML = rows.length
    ? rows.map((r) => `<tr><td>${r.item}</td><td>${r.type}</td><td>${r.status}</td></tr>`).join("")
    : emptyRow(3, "No outstanding actions.");

  const queue = d.proposals.filter((p) => !p.signed_off_by || (p.requires_second_reviewer && !p.second_reviewer_id));
  document.getElementById("proposal-queue-body").innerHTML = queue.length
    ? queue
        .map((p) => {
          const client = p.opportunities?.clients?.name ?? "Unknown client";
          const status = p.signed_off_by ? "Awaiting second reviewer" : "Awaiting sign off";
          return `<tr><td>${client}</td><td>${p.scope ?? "—"}</td><td>${status}</td></tr>`;
        })
        .join("")
    : emptyRow(3, "Nothing awaiting sign off.");

  document.getElementById("iso-note").textContent =
    "Client compliance scoring and ISO control readiness are not shown because no ISO control register or per client compliance assessments exist in the system yet.";
}

function renderClientIntelligence(d, dept, isSystem) {
  const visible = isSystem || dept === "sales" || dept === "operations";
  showSection("section-clients", visible);
  if (!visible) return;

  const perClient = {};
  function ensure(name) {
    if (!perClient[name]) perClient[name] = { contacts: [], lastContact: null, stalled: 0, expiring: 0, wonPipelines: new Set(), openOpps: 0 };
    return perClient[name];
  }

  d.contactRows.forEach((c) => {
    const name = c.clients?.name ?? "Unknown client";
    const rec = ensure(name);
    rec.contacts.push(c);
    if (c.last_contacted_at && (!rec.lastContact || c.last_contacted_at > rec.lastContact)) rec.lastContact = c.last_contacted_at;
  });
  d.opportunities.forEach((o) => {
    const name = o.clients?.name ?? "Unknown client";
    const rec = ensure(name);
    if (o.stage === "won") rec.wonPipelines.add(o.pipeline_type);
    else if (o.stage !== "lost") {
      rec.openOpps += 1;
      if (daysAgo(o.updated_at) >= 14) rec.stalled += 1;
    }
  });
  d.contractsNeedingRenewal.forEach((c) => {
    const name = c.clients?.name ?? "Unknown client";
    ensure(name).expiring += 1;
  });

  const rows = Object.entries(perClient).map(([name, rec]) => {
    const rel = computeRelationshipScore(rec.contacts);
    let risk = 0;
    risk += rec.stalled * 25;
    risk += rec.expiring * 25;
    const contactDays = rec.lastContact ? -daysUntil(rec.lastContact) : null;
    if (contactDays === null || contactDays > 45) risk += 25;
    if (rel.score < 40) risk += 25;
    risk = Math.min(100, risk);
    let riskLabel = "Low";
    let riskCls = "valid";
    if (risk >= 60) { riskLabel = "High"; riskCls = "expired"; }
    else if (risk >= 30) { riskLabel = "Medium"; riskCls = "expiring"; }

    let move = "Maintain contact";
    if (rec.expiring) move = "Start renewal conversation";
    else if (rec.wonPipelines.size && !rec.openOpps) move = "Cross sell, no open opportunities";
    else if (rec.stalled) move = "Revive stalled opportunity";

    return { name, rel, lastContact: rec.lastContact ?? "Never recorded", riskLabel, riskCls, move, risk };
  });
  rows.sort((a, b) => b.risk - a.risk);

  document.getElementById("clients-intel-body").innerHTML = rows.length
    ? rows
        .map(
          (r) =>
            `<tr><td>${r.name}</td><td><span class="badge badge-${r.rel.cls}">${r.rel.label}</span></td><td>${r.lastContact}</td><td><span class="badge badge-${r.riskCls}">${r.riskLabel}</span></td><td>${r.move}</td></tr>`
        )
        .join("")
    : emptyRow(5, "No client contacts or opportunities recorded yet.");
}

function renderPeopleIntelligence(d, dept, isSystem) {
  const visible = isSystem || dept === "operations";
  showSection("section-people", visible);
  if (!visible) return;

  document.getElementById("people-stats").innerHTML = [
    metricTile("Headcount", d.staff.length),
    metricTile("Staff utilisation", d.utilisationPercent + "%"),
    metricTile("On the bench", d.idleCount),
    metricTile("Certifications expiring", d.certsExpiring.length),
    metricTile("Performance indicators", "No review data recorded")
  ].join("");

  const skillsByPerson = {};
  d.skills.forEach((s) => {
    const name = s.profiles?.full_name ?? "Unknown";
    if (!skillsByPerson[name]) skillsByPerson[name] = [];
    skillsByPerson[name].push(s.skill_name + (s.is_certification ? " (cert)" : ""));
  });
  const smRows = Object.entries(skillsByPerson);
  document.getElementById("skills-matrix-body").innerHTML = smRows.length
    ? smRows.map(([n, list]) => `<tr><td>${n}</td><td>${list.join(", ")}</td></tr>`).join("")
    : emptyRow(2, "No skills recorded. Add them in People.");

  document.getElementById("certs-expiring-body").innerHTML = d.certsExpiring.length
    ? d.certsExpiring.map((s) => `<tr><td>${s.skill_name}</td><td>${s.expiry_date}</td></tr>`).join("")
    : emptyRow(2, "No certifications expiring within sixty days.");

  const upcoming = d.leaveEntries.filter((l) => {
    const days = daysUntil(l.end_date);
    return days !== null && days >= 0;
  });
  document.getElementById("leave-body").innerHTML = upcoming.length
    ? upcoming
        .map((l) => `<tr><td>${l.profiles?.full_name ?? "Unknown"}</td><td>${l.start_date}</td><td>${l.end_date}</td><td>${l.leave_type}</td></tr>`)
        .join("")
    : emptyRow(4, "No leave recorded. Leave is added in the People module by Operations.");
}

let activityFeedCache = [];
let activityPeriodDays = null;
let activityType = null;

function buildActivityFeed(d) {
  const feed = [];
  d.notifications.forEach((n) =>
    feed.push({ at: n.created_at, type: "Notification", text: (n.department ? "[" + DEPARTMENTS[n.department] + "] " : "") + n.message })
  );
  d.stageHistory
    .filter((h) => h.stage === "won")
    .forEach((h) => feed.push({ at: h.changed_at, type: "Win", text: "Opportunity won: " + (h.opportunities?.clients?.name ?? "a client") }));
  d.clients.forEach((c) => {
    if (c.created_at) feed.push({ at: c.created_at, type: "New client", text: "Client added: " + c.name });
  });
  d.projects.forEach((p) => {
    if (p.created_at) feed.push({ at: p.created_at, type: "New project", text: "Project created: " + (p.title ?? "Untitled") });
  });
  d.staffEvents.forEach((e) =>
    feed.push({ at: e.created_at, type: "Staff change", text: e.event_type + " event for " + e.staff_name })
  );
  feed.sort((a, b) => new Date(b.at) - new Date(a.at));
  return feed.slice(0, 60);
}

function renderActivityStream() {
  const container = document.getElementById("activity-stream");
  let list = activityFeedCache;
  if (activityPeriodDays) {
    const cutoff = new Date(Date.now() - activityPeriodDays * 24 * 60 * 60 * 1000);
    list = list.filter((e) => new Date(e.at) >= cutoff);
  }
  if (activityType) list = list.filter((e) => e.type === activityType);
  container.innerHTML = list.length
    ? list
        .map(
          (e) =>
            `<div class="activity-row"><span><strong style="color: var(--ink-500); font-weight: 600;">${e.type}</strong> ${e.text}</span><span class="activity-when">${new Date(e.at).toLocaleString("en-ZA")}</span></div>`
        )
        .join("")
    : `<div class="activity-row"><span>No activity in this view. Adjust the filters above or check back once more has happened.</span></div>`;
}

function renderActivityFilters() {
  const periods = [
    { label: "Today", days: 1 },
    { label: "This week", days: 7 },
    { label: "This month", days: 31 },
    { label: "Quarter", days: 92 },
    { label: "Year", days: 366 },
    { label: "All", days: null }
  ];
  const periodEl = document.getElementById("activity-period-filters");
  periodEl.innerHTML = periods
    .map((p) => `<button type="button" class="btn-primary btn-small" data-days="${p.days ?? ""}">${p.label}</button>`)
    .join("");
  periodEl.querySelectorAll("button").forEach((btn) => {
    btn.addEventListener("click", () => {
      activityPeriodDays = btn.dataset.days ? Number(btn.dataset.days) : null;
      renderActivityStream();
    });
  });

  const types = ["All", "Win", "New client", "New project", "Staff change", "Notification"];
  const typeEl = document.getElementById("activity-type-filters");
  typeEl.innerHTML = types
    .map((t) => `<button type="button" class="btn-primary btn-small" data-type="${t === "All" ? "" : t}">${t}</button>`)
    .join("");
  typeEl.querySelectorAll("button").forEach((btn) => {
    btn.addEventListener("click", () => {
      activityType = btn.dataset.type || null;
      renderActivityStream();
    });
  });
}

// ---- The orchestrator ----

async function loadExecutiveDashboard() {
  const dept = currentProfile.department;
  const isSystem = currentProfile.role_tier === "system";

  const [
    opportunities, contracts, complianceDocs, invoices, projects, tickets,
    allocations, staff, contactRows, nonConformances, skills, stageHistory,
    tasks, notifications, proposals, milestones, leaveEntries, clients,
    staffEvents, settingsRows
  ] = await Promise.all([
    fetchSafely(supabase.from("opportunities").select("id, value, stage, updated_at, owner_id, client_id, pipeline_type, expected_close_date, loss_reason, clients(name)")),
    fetchSafely(supabase.from("contracts").select("id, end_date, client_id, clients(name)")),
    fetchSafely(supabase.from("compliance_documents").select("id, name, expiry_date")),
    fetchSafely(supabase.from("invoices").select("id, description, amount, approval_status, due_date, created_at")),
    fetchSafely(supabase.from("projects").select("id, title, status, updated_at, created_at")),
    fetchSafely(supabase.from("delivery_tickets").select("id, status, sla_hours, created_at").eq("department", "it_delivery")),
    fetchSafely(supabase.from("resource_allocations").select("profile_id, allocation_percent, profiles(full_name)")),
    fetchSafely(supabase.from("profiles").select("id, full_name")),
    fetchSafely(supabase.from("contacts").select("id, last_contacted_at, client_id, role_type, clients(name)")),
    fetchSafely(supabase.from("non_conformances").select("id, finding, closed_at, due_date")),
    fetchSafely(supabase.from("skills").select("id, skill_name, is_certification, expiry_date, profiles(full_name)")),
    fetchSafely(supabase.from("opportunity_stage_history").select("opportunity_id, stage, changed_at, opportunities(value, owner_id, clients(name), profiles(full_name))")),
    fetchSafely(supabase.from("tasks").select("id, title, due_date, status").eq("status", "open")),
    fetchSafely(supabase.from("notifications").select("message, department, created_at").order("created_at", { ascending: false }).limit(30)),
    fetchSafely(supabase.from("proposals").select("id, scope, signed_off_by, requires_second_reviewer, second_reviewer_id, opportunities(clients(name))")),
    fetchSafely(supabase.from("milestones").select("id, project_id, title, due_date, completed_at")),
    fetchSafely(supabase.from("leave_entries").select("id, start_date, end_date, leave_type, profiles(full_name)")),
    fetchSafely(supabase.from("clients").select("id, name, created_at")),
    fetchSafely(supabase.from("staff_events").select("staff_name, event_type, created_at")),
    fetchSafely(supabase.from("settings").select("key, value"))
  ]);

  const settingsMap = {};
  settingsRows.forEach((r) => (settingsMap[r.key] = r.value));
  const renewalAlertDays = Number(settingsMap.contract_renewal_alert_days || 60);
  const revenueTarget = Number(settingsMap.monthly_revenue_target || 0);

  const stalledOpportunities = opportunities.filter(
    (o) => o.stage !== "won" && o.stage !== "lost" && daysAgo(o.updated_at) >= 14
  );
  const contractsNeedingRenewal = contracts.filter((c) => {
    const days = daysUntil(c.end_date);
    return days !== null && days >= 0 && days <= renewalAlertDays;
  });
  const complianceExpiringSoon = complianceDocs.filter((doc) => {
    const days = daysUntil(doc.expiry_date);
    return days !== null && days <= 30;
  });
  const overdueInvoices = invoices.filter((i) => {
    const days = daysUntil(i.due_date);
    return i.approval_status !== "approved" && days !== null && days < 0;
  });
  const slaBreaches = tickets.filter((t) => {
    if (t.status === "resolved" || !t.sla_hours) return false;
    return (new Date() - new Date(t.created_at)) / (1000 * 60 * 60) > Number(t.sla_hours);
  });
  const projectsAtRisk = projects.filter((p) => {
    if (p.status === "complete") return false;
    return p.status === "on_hold" || daysAgo(p.updated_at || p.created_at || new Date()) >= 21;
  });

  const allocationTotals = {};
  allocations.forEach((a) => {
    allocationTotals[a.profile_id] = (allocationTotals[a.profile_id] || 0) + Number(a.allocation_percent || 0);
  });
  const overAllocatedCount = Object.values(allocationTotals).filter((v) => v > 100).length;
  const idleCount = staff.filter((p) => !allocationTotals[p.id]).length;
  const utilisationPercent = staff.length
    ? Math.round((Object.values(allocationTotals).reduce((s, v) => s + Math.min(v, 100), 0) / (staff.length * 100)) * 100)
    : 0;

  const contactByClient = {};
  contactRows.forEach((c) => {
    const name = c.clients?.name ?? "Unknown client";
    if (!contactByClient[name] || (c.last_contacted_at && c.last_contacted_at > contactByClient[name])) {
      contactByClient[name] = c.last_contacted_at;
    }
  });
  const noRecentContactClients = Object.entries(contactByClient)
    .filter(([, lastDate]) => {
      const days = daysUntil(lastDate);
      return days !== null && days < -45;
    })
    .map(([name]) => name);

  const certsExpiring = skills.filter((s) => {
    if (!s.is_certification) return false;
    const days = daysUntil(s.expiry_date);
    return days !== null && days >= 0 && days <= 60;
  });

  const d = {
    opportunities, contracts, complianceDocs, invoices, projects, tickets,
    allocations, staff, contactRows, nonConformances, skills, stageHistory,
    tasks, notifications, proposals, milestones, leaveEntries, clients,
    staffEvents, renewalAlertDays, revenueTarget, stalledOpportunities,
    contractsNeedingRenewal, complianceExpiringSoon, overdueInvoices,
    slaBreaches, projectsAtRisk, allocationTotals, overAllocatedCount,
    idleCount, utilisationPercent, noRecentContactClients, certsExpiring
  };

  renderMetricRow(d, dept, isSystem);
  renderSmartInsights(d, dept, isSystem);
  renderSalesIntelligence(d, dept, isSystem);
  renderOperationsIntelligence(d, dept, isSystem);
  renderFinancialIntelligence(d, dept, isSystem);
  renderComplianceIntelligence(d, dept, isSystem);
  renderClientIntelligence(d, dept, isSystem);
  renderPeopleIntelligence(d, dept, isSystem);

  activityFeedCache = buildActivityFeed(d);
  renderActivityFilters();
  renderActivityStream();
}

async function loadHomeModule() {
  await loadNeedsAttention();
  await loadExecutiveDashboard();
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

function computeLeadScore(lead) {
  let score = 40;
  const src = (lead.source || "").toLowerCase();
  if (src.includes("referral") || src.includes("tender")) score += 20;
  if (lead.value) score += 15;
  if (lead.status !== "new") score += 10;
  const daysOld = Math.round((new Date() - new Date(lead.created_at)) / (1000 * 60 * 60 * 24));
  if (daysOld > 14 && lead.status === "new") score -= 10;
  score = Math.max(0, Math.min(100, score));
  let label = "Low";
  let cls = "expired";
  if (score >= 70) {
    label = "High";
    cls = "valid";
  } else if (score >= 45) {
    label = "Medium";
    cls = "renew-soon";
  }
  return { score, label, cls };
}

async function loadLeads() {
  const tbody = document.getElementById("leads-body");
  const { data, error } = await supabase
    .from("leads")
    .select("id, name, source, status, value, created_at")
    .order("created_at", { ascending: false });

  if (error) {
    tbody.innerHTML = `<tr><td colspan="5" class="empty">${error.message}</td></tr>`;
    return;
  }
  if (!data.length) {
    tbody.innerHTML = `<tr><td colspan="5" class="empty">No leads logged yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = "";
  data.forEach((lead) => {
    const tr = document.createElement("tr");
    const score = computeLeadScore(lead);
    const convertButton =
      lead.status === "converted"
        ? ""
        : `<button type="button" class="btn-primary btn-small" data-id="${lead.id}" data-name="${lead.name}">Convert</button>`;
    tr.innerHTML = `
      <td>${lead.name}</td>
      <td>${lead.source ?? "—"}</td>
      <td>${lead.status}</td>
      <td><span class="badge badge-${score.cls}" title="Score ${score.score} of 100">${score.label}</span></td>
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

// ---- Approvals centre ----
// Reuses the exact same actions already built in Cybersecurity and
// Finance. This screen exists so nobody has to know which module an
// approval originally belongs to, it collects them in one place.

async function loadApprovalsModule() {
  await Promise.all([loadApprovalsProposals(), loadApprovalsInvoices()]);
}

async function loadApprovalsProposals() {
  const tbody = document.getElementById("approvals-proposals-body");
  const { data, error } = await supabase
    .from("proposals")
    .select("id, scope, requires_second_reviewer, signed_off_by, second_reviewer_id, opportunities(clients(name))")
    .order("created_at", { ascending: false });

  if (error) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty">${error.message}</td></tr>`;
    return;
  }

  const outstanding = (data || []).filter(
    (p) => !p.signed_off_by || (p.requires_second_reviewer && !p.second_reviewer_id)
  );

  if (!outstanding.length) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty">Nothing outstanding.</td></tr>`;
    return;
  }

  tbody.innerHTML = "";
  outstanding.forEach((p) => {
    const clientName = p.opportunities && p.opportunities.clients ? p.opportunities.clients.name : "Unknown client";
    const status = p.signed_off_by ? "Signed off, awaiting second reviewer" : "Awaiting sign off";
    const actionLabel = p.signed_off_by ? "Second review" : "Sign off";
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${clientName}</td>
      <td>${p.scope ?? "—"}</td>
      <td>${status}</td>
      <td><button type="button" class="btn-primary btn-small" data-id="${p.id}" data-signed="${!!p.signed_off_by}">${actionLabel}</button></td>
    `;
    tbody.appendChild(tr);
  });

  tbody.querySelectorAll("button[data-id]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const alreadySigned = btn.dataset.signed === "true";
      const patch = alreadySigned ? { second_reviewer_id: currentProfile.id } : { signed_off_by: currentProfile.id };
      const { error: updateError } = await supabase.from("proposals").update(patch).eq("id", btn.dataset.id);
      if (updateError) alert("Could not update this proposal. " + updateError.message);
      await loadApprovalsProposals();
    });
  });
}

async function loadApprovalsInvoices() {
  const tbody = document.getElementById("approvals-invoices-body");

  const { data: thresholdRow } = await supabase
    .from("settings")
    .select("value")
    .eq("key", "md_approval_threshold")
    .maybeSingle();
  const threshold = Number(thresholdRow?.value || 0);

  const { data, error } = await supabase
    .from("invoices")
    .select("id, description, amount, approval_status")
    .neq("approval_status", "approved")
    .order("created_at", { ascending: false });

  if (error) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty">${error.message}</td></tr>`;
    return;
  }
  if (!data.length) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty">Nothing outstanding.</td></tr>`;
    return;
  }

  tbody.innerHTML = "";
  data.forEach((inv) => {
    const needsSystemApproval = Number(inv.amount) > threshold;
    const canApprove = !needsSystemApproval || currentProfile.role_tier === "system";
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${inv.description ?? "—"}</td>
      <td>${formatRand(inv.amount)}</td>
      <td>${needsSystemApproval ? "Needs System Super User" : "pending"}</td>
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
      await loadApprovalsInvoices();
    });
  });
}

// ---- People, resource directory ----

async function loadPeopleModule() {
  await Promise.all([
    loadStaffDirectory(),
    loadSkills(),
    populateSkillProfileSelect(),
    loadUtilisation(),
    populateAllocationSelects(),
    loadLeaveEntries(),
    populateLeaveProfileSelect()
  ]);
}

async function loadLeaveEntries() {
  const tbody = document.getElementById("people-leave-body");
  const { data, error } = await supabase
    .from("leave_entries")
    .select("id, start_date, end_date, leave_type, profiles(full_name)")
    .order("start_date", { ascending: true });

  if (error) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty">${error.message}</td></tr>`;
    return;
  }
  if (!data.length) {
    tbody.innerHTML = `<tr><td colspan="4" class="empty">No leave recorded yet.</td></tr>`;
    return;
  }
  tbody.innerHTML = data
    .map((l) => `<tr><td>${l.profiles?.full_name ?? "Unknown"}</td><td>${l.start_date}</td><td>${l.end_date}</td><td>${l.leave_type}</td></tr>`)
    .join("");
}

async function populateLeaveProfileSelect() {
  const select = document.getElementById("leave-profile");
  const { data } = await supabase.from("profiles").select("id, full_name").order("full_name");
  select.innerHTML = (data || []).map((p) => `<option value="${p.id}">${p.full_name}</option>`).join("");
}

document.getElementById("add-leave-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const errorEl = document.getElementById("add-leave-error");
  errorEl.textContent = "";

  const { error } = await supabase.from("leave_entries").insert({
    profile_id: document.getElementById("leave-profile").value,
    start_date: document.getElementById("leave-start").value,
    end_date: document.getElementById("leave-end").value,
    leave_type: document.getElementById("leave-type").value
  });
  if (error) {
    errorEl.textContent = error.message;
    return;
  }
  form.reset();
  await loadLeaveEntries();
});

async function loadUtilisation() {
  const tbody = document.getElementById("utilisation-body");
  const { data: staff } = await supabase.from("profiles").select("id, full_name");
  const { data: allocations, error } = await supabase
    .from("resource_allocations")
    .select("profile_id, allocation_percent");

  if (error) {
    tbody.innerHTML = `<tr><td colspan="3" class="empty">${error.message}</td></tr>`;
    return;
  }
  if (!staff || !staff.length) {
    tbody.innerHTML = `<tr><td colspan="3" class="empty">No staff records visible.</td></tr>`;
    return;
  }

  tbody.innerHTML = staff
    .map((p) => {
      const total = (allocations || [])
        .filter((a) => a.profile_id === p.id)
        .reduce((sum, a) => sum + Number(a.allocation_percent || 0), 0);
      let status = "On bench";
      let cls = "no-date";
      if (total > 100) {
        status = "Over allocated";
        cls = "expired";
      } else if (total >= 60) {
        status = "Fully allocated";
        cls = "valid";
      } else if (total > 0) {
        status = "Partially allocated";
        cls = "renew-soon";
      }
      return `<tr><td>${p.full_name}</td><td>${total}%</td><td><span class="badge badge-${cls}">${status}</span></td></tr>`;
    })
    .join("");
}

async function populateAllocationSelects() {
  const profileSelect = document.getElementById("allocation-profile");
  const projectSelect = document.getElementById("allocation-project");

  const { data: staff } = await supabase.from("profiles").select("id, full_name").order("full_name");
  profileSelect.innerHTML = (staff || []).map((p) => `<option value="${p.id}">${p.full_name}</option>`).join("");

  const { data: projectRows } = await supabase.from("projects").select("id, title").order("created_at", { ascending: false });
  projectSelect.innerHTML = (projectRows || [])
    .map((p) => `<option value="${p.id}">${p.title ?? "Untitled project"}</option>`)
    .join("");
}

document.getElementById("add-allocation-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const profileId = document.getElementById("allocation-profile").value;
  const projectId = document.getElementById("allocation-project").value;
  const percent = Number(document.getElementById("allocation-percent").value);
  const errorEl = document.getElementById("add-allocation-error");
  errorEl.textContent = "";

  const { error } = await supabase.from("resource_allocations").insert({
    profile_id: profileId,
    project_id: projectId,
    allocation_percent: percent
  });

  if (error) {
    errorEl.textContent = error.message;
    return;
  }
  form.reset();
  await loadUtilisation();
});

async function loadStaffDirectory() {
  const tbody = document.getElementById("staff-directory-body");
  const { data, error } = await supabase
    .from("profiles")
    .select("id, full_name, department, role_tier")
    .order("full_name", { ascending: true });

  if (error) {
    tbody.innerHTML = `<tr><td colspan="3" class="empty">${error.message}</td></tr>`;
    return;
  }
  if (!data.length) {
    tbody.innerHTML = `<tr><td colspan="3" class="empty">No staff records visible.</td></tr>`;
    return;
  }

  tbody.innerHTML = data
    .map(
      (p) =>
        `<tr><td>${p.full_name}</td><td>${p.department ? DEPARTMENTS[p.department] : "System"}</td><td>${p.role_tier}</td></tr>`
    )
    .join("");
}

async function populateSkillProfileSelect() {
  const select = document.getElementById("skill-profile");
  const { data, error } = await supabase.from("profiles").select("id, full_name").order("full_name");
  if (error || !data) {
    select.innerHTML = `<option value="">Could not load staff</option>`;
    return;
  }
  select.innerHTML = data.map((p) => `<option value="${p.id}">${p.full_name}</option>`).join("");
}

async function loadSkills() {
  const tbody = document.getElementById("skills-body");
  const { data, error } = await supabase
    .from("skills")
    .select("id, skill_name, is_certification, expiry_date, profiles(full_name)")
    .order("created_at", { ascending: false });

  if (error) {
    tbody.innerHTML = `<tr><td colspan="3" class="empty">${error.message}</td></tr>`;
    return;
  }
  if (!data.length) {
    tbody.innerHTML = `<tr><td colspan="3" class="empty">None recorded yet.</td></tr>`;
    return;
  }

  tbody.innerHTML = data
    .map((s) => {
      const staffName = s.profiles ? s.profiles.full_name : "Unknown";
      let status = "Skill";
      if (s.is_certification) {
        const days = daysUntil(s.expiry_date);
        if (days === null) status = "Certification, no expiry set";
        else if (days < 0) status = "Certification expired";
        else if (days <= 60) status = "Certification expiring, " + days + " days left";
        else status = "Certification valid";
      }
      return `<tr><td>${staffName}</td><td>${s.skill_name}</td><td>${status}</td></tr>`;
    })
    .join("");
}

document.getElementById("add-skill-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const form = e.target;
  const profileId = document.getElementById("skill-profile").value;
  const skillName = document.getElementById("skill-name").value.trim();
  const isCert = document.getElementById("skill-is-cert").checked;
  const expiry = document.getElementById("skill-expiry").value || null;
  const errorEl = document.getElementById("add-skill-error");
  errorEl.textContent = "";

  const { error } = await supabase.from("skills").insert({
    profile_id: profileId,
    skill_name: skillName,
    is_certification: isCert,
    expiry_date: isCert ? expiry : null
  });

  if (error) {
    errorEl.textContent = error.message;
    return;
  }
  form.reset();
  await loadSkills();
});

// ---- Command palette ----

const PALETTE_DESTINATIONS = [
  { key: "overview", label: "Home" },
  { key: "my_work", label: "My Work" },
  { key: "notifications", label: "Notifications" },
  { key: "approvals", label: "Approvals" },
  { key: "people", label: "People" },
  { key: "sales", label: "Sales & Bids" },
  { key: "cybersecurity", label: "Cybersecurity" },
  { key: "it_delivery", label: "IT Delivery" },
  { key: "internal_it", label: "Internal IT & Staff Support" },
  { key: "finance", label: "Finance" },
  { key: "operations", label: "Operations" },
  { key: "settings", label: "Settings" }
];

const palette = document.getElementById("command-palette");
const paletteInput = document.getElementById("command-palette-input");
const paletteResults = document.getElementById("command-palette-results");

function openPalette() {
  if (document.getElementById("screen-app").classList.contains("hidden")) return;
  palette.classList.remove("hidden");
  paletteInput.value = "";
  renderPaletteResults("");
  paletteInput.focus();
}

function closePalette() {
  palette.classList.add("hidden");
}

function renderPaletteResults(query) {
  const q = query.trim().toLowerCase();
  const matches = PALETTE_DESTINATIONS.filter((d) => d.label.toLowerCase().includes(q));
  paletteResults.innerHTML = matches
    .map((d, i) => `<div class="command-palette-item${i === 0 ? " active" : ""}" data-key="${d.key}">${d.label}</div>`)
    .join("");
  paletteResults.querySelectorAll(".command-palette-item").forEach((item) => {
    item.addEventListener("click", () => goToModuleFromPalette(item.dataset.key));
  });
}

function goToModuleFromPalette(key) {
  closePalette();
  showModule(key);
  document.querySelectorAll(".nav-link").forEach((el) => {
    el.classList.toggle("active", el.dataset.module === key);
  });
  if (MODULE_LOADERS[key]) MODULE_LOADERS[key]();
}

document.addEventListener("keydown", (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
    e.preventDefault();
    if (palette.classList.contains("hidden")) openPalette();
    else closePalette();
  }
  if (e.key === "Escape") closePalette();
});

paletteInput.addEventListener("input", () => renderPaletteResults(paletteInput.value));

paletteInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    const first = paletteResults.querySelector(".command-palette-item");
    if (first) goToModuleFromPalette(first.dataset.key);
  }
});

palette.addEventListener("click", (e) => {
  if (e.target === palette) closePalette();
});

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

  const { data: documents } = await supabase
    .from("documents")
    .select("id, file_name, file_path, kind, created_at")
    .eq("client_id", clientId)
    .order("created_at", { ascending: false });

  const { data: clientTasks } = await supabase
    .from("tasks")
    .select("id, title, due_date, status, created_at")
    .eq("client_id", clientId)
    .order("due_date", { ascending: true, nullsFirst: false });

  const { data: contacts } = await supabase
    .from("contacts")
    .select("id, full_name, role_type, email, phone, last_contacted_at")
    .eq("client_id", clientId)
    .order("created_at", { ascending: false });

  const oppIds = (opportunities || []).map((o) => o.id);
  const { data: stageHistory } = oppIds.length
    ? await supabase.from("opportunity_stage_history").select("stage, changed_at").in("opportunity_id", oppIds)
    : { data: [] };

  const timelineItems = [];
  (notes || []).forEach((n) => timelineItems.push({ type: "Note", text: n.note, at: n.created_at }));
  (documents || []).forEach((d) =>
    timelineItems.push({ type: d.kind === "voice" ? "Voice note" : "Document", text: d.file_name, at: d.created_at })
  );
  (clientTasks || []).forEach((t) => timelineItems.push({ type: "Task", text: t.title, at: t.created_at }));
  (stageHistory || []).forEach((s) => timelineItems.push({ type: "Stage change", text: "Moved to " + s.stage, at: s.changed_at }));
  timelineItems.sort((a, b) => new Date(b.at) - new Date(a.at));
  const relationshipScore = computeRelationshipScore(contacts);

  container.innerHTML = `
    <h1>${client.name}</h1>
    <p class="intro">
      ${client.sector ?? "No sector recorded"}
      <span class="badge badge-${relationshipScore.cls}" style="margin-left: 8px;" title="Score ${relationshipScore.score} of 100">Relationship: ${relationshipScore.label}</span>
    </p>

    <div class="section">
      <div class="section-header"><h2>Activity timeline</h2></div>
      <table class="data-table">
        <thead><tr><th>Type</th><th>What happened</th><th>When</th></tr></thead>
        <tbody>
          ${
            timelineItems.length
              ? timelineItems
                  .map(
                    (i) =>
                      `<tr><td>${i.type}</td><td>${i.text}</td><td>${new Date(i.at).toLocaleString("en-ZA")}</td></tr>`
                  )
                  .join("")
              : `<tr><td colspan="3" class="empty">Nothing recorded yet.</td></tr>`
          }
        </tbody>
      </table>
    </div>

    <div class="section">
      <div class="section-header"><h2>Contacts</h2></div>
      <table class="data-table">
        <thead><tr><th>Name</th><th>Role</th><th>Email</th><th>Last contacted</th></tr></thead>
        <tbody>
          ${
            (contacts || []).length
              ? contacts
                  .map(
                    (c) =>
                      `<tr><td>${c.full_name}</td><td>${c.role_type.replace("_", " ")}</td><td>${c.email ?? "—"}</td><td>${c.last_contacted_at ?? "—"}</td></tr>`
                  )
                  .join("")
              : `<tr><td colspan="4" class="empty">None recorded yet.</td></tr>`
          }
        </tbody>
      </table>
      <form id="add-contact-form" class="inline-form">
        <input id="contact-name" type="text" placeholder="Full name" required />
        <select id="contact-role">
          <option value="contact">Contact</option>
          <option value="decision_maker">Decision maker</option>
          <option value="champion">Champion</option>
          <option value="influencer">Influencer</option>
          <option value="procurement">Procurement</option>
          <option value="technical">Technical</option>
        </select>
        <input id="contact-email" type="text" placeholder="Email, optional" />
        <input id="contact-last-contacted" type="date" placeholder="Last contacted" />
        <button type="submit">Add contact</button>
      </form>
      <p id="add-contact-error" class="error"></p>
    </div>

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
      <div class="section-header"><h2>Documents and voice notes</h2></div>
      <table class="data-table">
        <thead><tr><th>Item</th><th>Uploaded</th><th></th></tr></thead>
        <tbody id="documents-body">
          ${
            (documents || []).length
              ? documents
                  .map((d) => {
                    const actionLabel = d.kind === "voice" ? "Play" : "Download";
                    return `<tr><td>${d.file_name}</td><td>${new Date(d.created_at).toLocaleDateString("en-ZA")}</td><td><button type="button" class="btn-primary btn-small download-doc" data-path="${d.file_path}" data-name="${d.file_name}" data-kind="${d.kind}">${actionLabel}</button></td></tr>`;
                  })
                  .join("")
              : `<tr><td colspan="3" class="empty">None yet.</td></tr>`
          }
        </tbody>
      </table>
      <form id="add-document-form" class="inline-form">
        <input id="document-file" type="file" required />
        <button type="submit">Upload</button>
      </form>
      <p id="add-document-error" class="error"></p>
      <div class="inline-form">
        <button type="button" id="record-voice-btn" class="btn-primary">Record voice note</button>
        <span id="voice-note-status" class="muted small"></span>
      </div>
      <p id="voice-note-error" class="error"></p>
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

  document.getElementById("add-document-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fileInput = document.getElementById("document-file");
    const file = fileInput.files[0];
    const errorEl = document.getElementById("add-document-error");
    errorEl.textContent = "";

    if (!file) {
      errorEl.textContent = "Choose a file first.";
      return;
    }

    const path = clientId + "/" + Date.now() + "_" + file.name;

    const { error: uploadError } = await supabase.storage.from("client-documents").upload(path, file);
    if (uploadError) {
      errorEl.textContent = uploadError.message;
      return;
    }

    const { error: recordError } = await supabase.from("documents").insert({
      client_id: clientId,
      file_name: file.name,
      file_path: path,
      uploaded_by: currentProfile.id
    });

    if (recordError) {
      errorEl.textContent = recordError.message;
      return;
    }

    await loadClientWorkspace(clientId);
  });

  document.querySelectorAll(".download-doc").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const { data, error } = await supabase.storage
        .from("client-documents")
        .createSignedUrl(btn.dataset.path, 60);
      if (error || !data) {
        alert("Could not create a link. " + (error ? error.message : ""));
        return;
      }
      if (btn.dataset.kind === "voice") {
        const audio = new Audio(data.signedUrl);
        audio.play();
      } else {
        window.open(data.signedUrl, "_blank");
      }
    });
  });

  let mediaRecorder = null;
  let recordedChunks = [];
  const recordBtn = document.getElementById("record-voice-btn");
  const voiceStatus = document.getElementById("voice-note-status");
  const voiceError = document.getElementById("voice-note-error");

  recordBtn.addEventListener("click", async () => {
    voiceError.textContent = "";

    if (!mediaRecorder || mediaRecorder.state === "inactive") {
      try {
        const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
        mediaRecorder = new MediaRecorder(stream);
        recordedChunks = [];

        mediaRecorder.ondataavailable = (e) => {
          if (e.data.size > 0) recordedChunks.push(e.data);
        };

        mediaRecorder.onstop = async () => {
          voiceStatus.textContent = "Saving";
          const blob = new Blob(recordedChunks, { type: "audio/webm" });
          const path = clientId + "/voice_" + Date.now() + ".webm";

          const { error: uploadError } = await supabase.storage
            .from("client-documents")
            .upload(path, blob);
          if (uploadError) {
            voiceError.textContent = uploadError.message;
            voiceStatus.textContent = "";
            return;
          }

          const { error: recordError } = await supabase.from("documents").insert({
            client_id: clientId,
            file_name: "Voice note, " + new Date().toLocaleString("en-ZA"),
            file_path: path,
            uploaded_by: currentProfile.id,
            kind: "voice"
          });
          if (recordError) {
            voiceError.textContent = recordError.message;
            voiceStatus.textContent = "";
            return;
          }

          await loadClientWorkspace(clientId);
        };

        mediaRecorder.start();
        recordBtn.textContent = "Stop recording";
        voiceStatus.textContent = "Recording";
      } catch (err) {
        voiceError.textContent = "Could not access the microphone. " + err.message;
      }
    } else {
      mediaRecorder.stop();
      mediaRecorder.stream.getTracks().forEach((track) => track.stop());
      recordBtn.textContent = "Record voice note";
    }
  });

  document.getElementById("add-contact-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fullName = document.getElementById("contact-name").value.trim();
    const roleType = document.getElementById("contact-role").value;
    const email = document.getElementById("contact-email").value.trim() || null;
    const lastContacted = document.getElementById("contact-last-contacted").value || null;
    const errorEl = document.getElementById("add-contact-error");
    errorEl.textContent = "";

    const { error } = await supabase.from("contacts").insert({
      client_id: clientId,
      full_name: fullName,
      role_type: roleType,
      email,
      last_contacted_at: lastContacted
    });

    if (error) {
      errorEl.textContent = error.message;
      return;
    }
    await loadClientWorkspace(clientId);
  });

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
