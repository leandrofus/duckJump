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
let currentUser = null;
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
  for (const t of ["request", "join", "forward"]) {
    $(`tab-${t}`).setAttribute("aria-selected", String(t === name));
    $(`panel-${t}`).hidden = t !== name;
  }
  clearError();
  if (name === "forward") {
    updateForwardPanel();
  }
}
$("tab-request").addEventListener("click", () => selectTab("request"));
$("tab-join").addEventListener("click", () => selectTab("join"));
$("tab-forward").addEventListener("click", () => selectTab("forward"));
$("forward-go-login").addEventListener("click", () => selectTab("request"));
$("forward-refresh-btn").addEventListener("click", () => loadForwardConnections());

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
  currentUser = user;
  mfaPending = false;
  $("password").value = "";
  $("totp").value = "";
  $("login-form").hidden = true;
  $("request-form").hidden = false;
  $("whoami").textContent = `Sesión iniciada como ${user.display_name || user.username}`;
  $("reason").focus();
  if (!$("panel-forward").hidden) {
    updateForwardPanel();
  }
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
  currentUser = null;
  if (statsPollingTimer) {
    clearInterval(statsPollingTimer);
    statsPollingTimer = null;
  }
  await invoke("logout").catch(() => {});
  $("request-form").hidden = true;
  $("login-form").hidden = false;
  onAccountChange();
  if (!$("panel-forward").hidden) {
    updateForwardPanel();
  }
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

// ---- TCP Forwarding ----

let statsPollingTimer = null;

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${(bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0)} ${units[i]}`;
}

async function updateForwardPanel() {
  clearError();
  if (!currentUser) {
    $("forward-signed-out").hidden = false;
    $("forward-signed-in").hidden = true;
    return;
  }
  $("forward-signed-out").hidden = true;
  $("forward-signed-in").hidden = false;
  await loadForwardConnections();
}

async function loadForwardConnections() {
  try {
    const conns = await invoke("list_forward_connections");
    const forwardable = (conns || []).filter(c => c.protocol === "tcp" || c.can_forward);
    renderForwardList(forwardable);
    await refreshForwardStats();
  } catch (e) {
    showError(e);
  }
}

function renderForwardList(conns) {
  const container = $("forward-list");
  container.innerHTML = "";
  if (!conns || conns.length === 0) {
    $("forward-empty").hidden = false;
    return;
  }
  $("forward-empty").hidden = true;

  for (const c of conns) {
    const card = document.createElement("article");
    card.className = "forward-card";
    card.id = `forward-card-${c.id}`;

    let defaultPort = 5432;
    const lowerName = c.name.toLowerCase();
    const isWeb = c.protocol === "http" || c.protocol === "https";
    if (isWeb) defaultPort = 8080;
    else if (lowerName.includes("mysql") || lowerName.includes("3306")) defaultPort = 3306;
    else if (lowerName.includes("redis") || lowerName.includes("6379")) defaultPort = 6379;
    else if (lowerName.includes("mongo") || lowerName.includes("27017")) defaultPort = 27017;
    else if (c.protocol === "ssh" || lowerName.includes("2222")) defaultPort = 2222;

    card.innerHTML = `
      <div class="forward-info">
        <div class="forward-title">
          <strong>${escapeHtml(c.name)}</strong>
          <span class="badge protocol">${escapeHtml(c.protocol.toUpperCase())}</span>
          ${c.virtual_host ? `<span class="badge vhost" title="Virtual Host">vhost: ${escapeHtml(c.virtual_host)}</span>` : ""}
          <span class="badge status" id="forward-status-badge-${c.id}">Inactivo</span>
        </div>
        <div class="forward-desc hint">${escapeHtml(c.description || c.environment || "Sin descripción")}${c.folder_path ? ` · ${escapeHtml(c.folder_path)}` : ""}</div>
      </div>
      <div class="forward-controls">
        <label class="field-inline">
          <span>Puerto:</span>
          <input type="number" id="forward-port-${c.id}" min="1024" max="65535" value="${defaultPort}">
        </label>
        ${isWeb ? `
        <label class="field-inline">
          <span>Virtual Host:</span>
          <input type="text" id="forward-vhost-${c.id}" value="${escapeHtml(c.virtual_host || '')}" placeholder="ej. wiki.corp.local" style="width: 140px;">
        </label>` : ''}
        <button type="button" class="primary forward-toggle-btn" id="forward-toggle-${c.id}">Iniciar Túnel</button>
      </div>
      <div class="forward-active-info" id="forward-active-info-${c.id}" hidden>
        <p class="forward-address">
          <span>Escuchando en:</span>
          <code id="forward-addr-${c.id}">127.0.0.1:${defaultPort}</code>
          <button type="button" class="link" id="forward-copy-${c.id}">Copiar</button>
          ${isWeb ? `<a id="forward-open-${c.id}" href="http://127.0.0.1:${defaultPort}" target="_blank" class="link" style="margin-left: 8px;">Abrir en navegador ↗</a>` : ''}
        </p>
        <p class="forward-traffic hint" id="forward-traffic-${c.id}">↑ 0 B · ↓ 0 B · 0 clientes</p>
      </div>
    `;

    container.appendChild(card);

    const toggleBtn = $(`forward-toggle-${c.id}`);
    const portInput = $(`forward-port-${c.id}`);
    const copyBtn = $(`forward-copy-${c.id}`);

    toggleBtn.addEventListener("click", async () => {
      const isRunning = toggleBtn.getAttribute("data-running") === "true";
      if (isRunning) {
        await stopForwardTunnel(c.id);
      } else {
        await startForwardTunnel(c.id, portInput.value);
      }
    });

    copyBtn.addEventListener("click", async () => {
      const addr = $(`forward-addr-${c.id}`).textContent;
      try {
        await navigator.clipboard.writeText(addr);
        copyBtn.textContent = "Copiado ✓";
      } catch {
        copyBtn.textContent = "Error al copiar";
      }
      setTimeout(() => { copyBtn.textContent = "Copiar"; }, 1600);
    });
  }
}

async function startForwardTunnel(connId, localPort) {
  clearError();
  const toggleBtn = $(`forward-toggle-${connId}`);
  const vhostInput = $(`forward-vhost-${connId}`);
  const virtualHost = vhostInput ? vhostInput.value.trim() : null;
  await busy(toggleBtn, async () => {
    try {
      const stats = await invoke("start_tcp_forward", {
        connection: connId,
        localPort: parseInt(localPort, 10),
        remotePort: null,
        virtualHost: virtualHost || null,
      });
      updateCardRunningState(connId, stats);
      startStatsPolling();
    } catch (e) {
      showError(e);
    }
  });
}

async function stopForwardTunnel(connId) {
  clearError();
  const toggleBtn = $(`forward-toggle-${connId}`);
  await busy(toggleBtn, async () => {
    try {
      await invoke("stop_tcp_forward", { connection: connId });
      updateCardStoppedState(connId);
    } catch (e) {
      showError(e);
    }
  });
}

function updateCardRunningState(connId, stats) {
  const card = $(`forward-card-${connId}`);
  if (!card) return;
  card.classList.add("active");
  const badge = $(`forward-status-badge-${connId}`);
  if (badge) {
    badge.textContent = "Activo";
    badge.className = "badge status running";
  }

  const btn = $(`forward-toggle-${connId}`);
  if (btn) {
    btn.textContent = "Detener";
    btn.className = "secondary";
    btn.setAttribute("data-running", "true");
  }

  const portInput = $(`forward-port-${connId}`);
  if (portInput) portInput.disabled = true;

  const vhostInput = $(`forward-vhost-${connId}`);
  if (vhostInput) vhostInput.disabled = true;

  const openLink = $(`forward-open-${connId}`);
  if (openLink) {
    openLink.href = `http://127.0.0.1:${stats.local_port}`;
  }

  const info = $(`forward-active-info-${connId}`);
  if (info) info.hidden = false;

  const addrEl = $(`forward-addr-${connId}`);
  if (addrEl) addrEl.textContent = `127.0.0.1:${stats.local_port}`;

  const trafficEl = $(`forward-traffic-${connId}`);
  if (trafficEl) {
    trafficEl.textContent = `↑ ${formatBytes(stats.bytes_sent)} · ↓ ${formatBytes(stats.bytes_received)} · ${stats.active_clients} cliente${stats.active_clients === 1 ? '' : 's'}`;
  }
}

function updateCardStoppedState(connId) {
  const card = $(`forward-card-${connId}`);
  if (!card) return;
  card.classList.remove("active");
  const badge = $(`forward-status-badge-${connId}`);
  if (badge) {
    badge.textContent = "Inactivo";
    badge.className = "badge status";
  }

  const btn = $(`forward-toggle-${connId}`);
  if (btn) {
    btn.textContent = "Iniciar Túnel";
    btn.className = "primary";
    btn.setAttribute("data-running", "false");
  }

  const portInput = $(`forward-port-${connId}`);
  if (portInput) portInput.disabled = false;

  const vhostInput = $(`forward-vhost-${connId}`);
  if (vhostInput) vhostInput.disabled = false;

  const info = $(`forward-active-info-${connId}`);
  if (info) info.hidden = true;
}

function startStatsPolling() {
  if (statsPollingTimer) return;
  statsPollingTimer = setInterval(refreshForwardStats, 1500);
}

async function refreshForwardStats() {
  try {
    const list = await invoke("get_forward_stats");
    let hasRunning = false;
    for (const st of list || []) {
      if (st.running) {
        hasRunning = true;
        updateCardRunningState(st.connection, st);
      } else {
        updateCardStoppedState(st.connection);
      }
    }
    if (!hasRunning && statsPollingTimer) {
      clearInterval(statsPollingTimer);
      statsPollingTimer = null;
    }
  } catch {
    // ignore polling error
  }
}

function escapeHtml(str) {
  return String(str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
