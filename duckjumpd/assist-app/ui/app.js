"use strict";

const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;
const $ = (id) => document.getElementById(id);

// Per-machine conveniences only (the last server); nothing depends on them.
const prefs = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); } catch { /* private mode */ } },
};

let identity = null;
let providers = null;
let connectedServer = null; // normalized URL of the gateway we are signed in to (or about to)
let mfaPending = false;
let timer = null;
let verifiedAt = 0;
let sessionCode = "";
let invite = null; // link waiting for the user's confirmation

function show(view) {
  for (const v of ["view-start", "view-session", "view-ended", "view-invite"]) $(v).hidden = v !== view;
}

function showError(err) {
  const el = $("error");
  el.textContent = typeof err === "string" ? err : (err && err.message) || String(err);
  el.hidden = false;
}

function clearError() {
  $("error").hidden = true;
}

async function busy(button, fn) {
  const label = button.textContent;
  button.disabled = true;
  try {
    return await fn();
  } finally {
    button.disabled = false;
    button.textContent = label;
  }
}

function formatCode(raw) {
  const c = (raw || "").replace(/\s+/g, "");
  return /^\d{6}$/.test(c) ? `${c.slice(0, 3)} ${c.slice(3)}` : (c || "— — —");
}

// ---- tabs ----

function selectTab(name) {
  for (const t of ["request", "join"]) {
    $(`tab-${t}`).setAttribute("aria-selected", String(t === name));
    $(`panel-${t}`).hidden = t !== name;
  }
  clearError();
}
$("tab-request").addEventListener("click", () => selectTab("request"));
$("tab-join").addEventListener("click", () => selectTab("join"));

// ---- server and sign-in ----

function account() {
  const checked = document.querySelector('input[name="account"]:checked');
  return checked ? checked.value : "local";
}

function onAccountChange() {
  const sso = account() === "sso";
  $("password-fields").hidden = sso;
  $("username").required = !sso;
  $("password").required = !sso;
  $("ad-hint").hidden = account() !== "ad";
  $("totp-field").hidden = true;
  mfaPending = false;
  const name = providers && providers.oidc ? providers.oidc.name : "SSO";
  $("login-btn").textContent = sso ? `Iniciar sesión con ${name}` : "Iniciar sesión";
}
for (const r of document.querySelectorAll('input[name="account"]')) r.addEventListener("change", onAccountChange);

async function connectServer() {
  clearError();
  const server = $("server").value.trim();
  $("login-form").hidden = true;
  $("request-form").hidden = true;
  connectedServer = null;
  providers = null;
  if (!server) {
    $("server-state").textContent = "";
    return false;
  }
  $("server-state").className = "hint";
  $("server-state").textContent = "Conectando…";
  try {
    const res = await invoke("connect", { server });
    providers = res.providers;
    connectedServer = res.server;
    prefs.set("server", server);
    $("server-state").className = "hint ok";
    $("server-state").textContent = `Conectado a ${res.server}`;
  } catch (e) {
    $("server-state").textContent = "";
    showError(e);
    return false;
  }

  const radios = Object.fromEntries([...document.querySelectorAll('input[name="account"]')].map((r) => [r.value, r]));
  radios.local.disabled = !providers.local;
  radios.ad.disabled = !providers.local;
  radios.sso.disabled = !providers.oidc;
  $("sso-label").textContent = providers.oidc ? `SSO corporativo (${providers.oidc.name})` : "SSO corporativo (no disponible)";
  if (document.querySelector('input[name="account"]:checked:disabled') || !document.querySelector('input[name="account"]:checked')) {
    const first = Object.values(radios).find((r) => !r.disabled);
    if (first) first.checked = true;
  }
  onAccountChange();
  $("login-form").hidden = false;
  return true;
}
$("server").addEventListener("change", connectServer);

function signedIn(user) {
  mfaPending = false;
  $("password").value = "";
  $("totp").value = "";
  $("login-form").hidden = true;
  $("request-form").hidden = false;
  $("whoami").textContent = `Sesión iniciada como ${user.display_name || user.username}`;
  $("reason").focus();
}

$("login-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  clearError();
  const btn = $("login-btn");
  await busy(btn, async () => {
    try {
      if (account() === "sso") {
        btn.textContent = "Complete el inicio de sesión en el navegador…";
        signedIn(await invoke("login_sso"));
      } else if (mfaPending) {
        signedIn(await invoke("login_totp", { code: $("totp").value }));
      } else {
        const res = await invoke("login_password", { username: $("username").value, password: $("password").value });
        if (res.mfa_required) {
          mfaPending = true;
          $("totp-field").hidden = false;
          $("totp").required = true;
          $("totp").focus();
        } else {
          signedIn(res.user);
        }
      }
    } catch (e) {
      showError(e);
    }
  });
});

$("logout-btn").addEventListener("click", async () => {
  await invoke("logout").catch(() => {});
  $("request-form").hidden = true;
  $("login-form").hidden = false;
  onAccountChange();
});

$("request-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  clearError();
  await busy($("request-btn"), async () => {
    try {
      const sess = await invoke("request_support", {
        reason: $("reason").value,
        ticket: $("ticket").value,
        accountType: account(),
      });
      await startSession(connectedServer, sess.token, sess.verification_code || null);
    } catch (e) {
      showError(e);
    }
  });
});

$("join-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  clearError();
  try {
    const inv = await invoke("parse_invite", { input: $("invite").value });
    const server = inv.server || $("server").value.trim();
    if (!server) {
      showError("El código no indica el servidor: complételo en la pestaña «Solicitar soporte» o pegue el enlace completo.");
      return;
    }
    await startSession(server, inv.token, null);
  } catch (e) {
    showError(e);
  }
});

// ---- session ----

function setStep(id, state) {
  const el = $(id);
  el.classList.toggle("current", state === "current");
  el.classList.toggle("done", state === "done");
}

function tick() {
  const s = Math.floor((Date.now() - verifiedAt) / 1000);
  $("timer").textContent = `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;
}

async function startSession(server, token, code) {
  sessionCode = (code || "").replace(/\s+/g, "");
  $("code").textContent = formatCode(code);
  $("timer").textContent = "00:00";
  $("stats").textContent = "—";
  $("stop-btn").disabled = false;
  setStep("step-connect", "current");
  setStep("step-wait", "");
  setStep("step-share", "");
  show("view-session");
  try {
    await invoke("start_session", { server, token, code });
  } catch (e) {
    show("view-start");
    showError(e);
  }
}

const ENDED = {
  local: ["Asistencia desconectada", "El técnico ya no tiene acceso a su equipo. Si necesita seguir, vuelva a abrir el enlace: sirve hasta que expire, con un código nuevo."],
  server: ["Asistencia finalizada", "El técnico cerró la sesión o se perdió la conexión. Si fue un corte, vuelva a abrir el enlace."],
  expired: ["El enlace ya no es válido", "El técnico cerró esta sesión o el enlace expiró. Pídale uno nuevo."],
  not_found: ["Código no válido", "El código o enlace de soporte no existe. Revise que lo haya copiado completo."],
};

function ended(p) {
  clearInterval(timer);
  timer = null;
  const [title, detail] = p.reason === "error"
    ? ["No se pudo completar la asistencia", p.error || "Error desconocido."]
    : ENDED[p.reason] || ENDED.server;
  $("ended-title").textContent = title;
  $("ended-detail").textContent = detail;
  show("view-ended");
}

listen("assist", ({ payload: p }) => {
  switch (p.type) {
    case "connected":
      setStep("step-connect", "done");
      setStep("step-wait", "current");
      break;
    case "code":
      sessionCode = p.code.replace(/\s+/g, "");
      $("code").textContent = p.code;
      break;
    case "verified":
      setStep("step-wait", "done");
      setStep("step-share", "current");
      verifiedAt = Date.now();
      clearInterval(timer);
      timer = setInterval(tick, 1000);
      break;
    case "streaming":
      setStep("step-share", "done");
      break;
    case "stats":
      $("stats").textContent = `${Math.round(p.fps)} fps · ${p.rtt_ms == null ? "…" : `${Math.round(p.rtt_ms)} ms`}`;
      break;
    case "ended":
      ended(p);
      break;
  }
});

$("stop-btn").addEventListener("click", async () => {
  $("stop-btn").disabled = true;
  $("stop-btn").textContent = "Desconectando…";
  await invoke("stop_session").catch(showError);
  $("stop-btn").textContent = "Finalizar asistencia y desconectar";
});

$("copy-btn").addEventListener("click", async () => {
  const btn = $("copy-btn");
  try {
    await navigator.clipboard.writeText(sessionCode);
    btn.textContent = "Copiado ✓";
  } catch {
    btn.textContent = "Seleccione el código y cópielo";
  }
  setTimeout(() => { btn.textContent = "Copiar código"; }, 1600);
});

$("back-btn").addEventListener("click", () => {
  show("view-start");
  if (!connectedServer) connectServer();
});

// ---- opened from a link ----

function onInvite(inv) {
  invoke("take_pending_invite").catch(() => {});
  if (!$("view-session").hidden) return; // one session at a time
  invite = inv;
  $("invite-server").textContent = inv.server;
  $("invite-insecure").hidden = !inv.server.startsWith("http://");
  clearError();
  show("view-invite");
}

listen("invite", ({ payload }) => onInvite(payload));
listen("invite-error", ({ payload }) => {
  if (!$("view-session").hidden) return;
  show("view-start");
  showError(`El enlace de asistencia no es válido: ${payload}`);
});

$("invite-accept").addEventListener("click", () => {
  const inv = invite;
  invite = null;
  if (inv) startSession(inv.server, inv.token, null);
});

$("invite-deny").addEventListener("click", () => {
  invite = null;
  show("view-start");
});

// ---- start ----

(async () => {
  try {
    identity = await invoke("detect_identity");
    const where = identity.account_type === "ad"
      ? `Dominio ${identity.domain || "(Kerberos)"} · Usuario ${identity.username}`
      : `Cuenta local · Usuario ${identity.username}`;
    $("identity").textContent = `${where} · Equipo ${identity.hostname || "—"}`;
    $("identity").hidden = false;
    $("username").value = identity.username;
    document.querySelector(`input[name="account"][value="${identity.account_type === "ad" ? "ad" : "local"}"]`).checked = true;
  } catch (e) {
    showError(e);
  }
  const pending = await invoke("take_pending_invite").catch(() => null);
  if (pending) onInvite(pending);
  const server = prefs.get("server");
  if (server) {
    $("server").value = server;
    await connectServer();
  } else {
    $("server").focus();
  }
})();
