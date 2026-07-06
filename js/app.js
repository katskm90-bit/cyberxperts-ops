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

// ---- Offline support ----
if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("sw.js");
  });
}
