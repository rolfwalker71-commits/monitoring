const state = {
  severity: "all",
  showAck: true,
  showClosed: false,
  pushSupported: false,
  pushConfigured: false,
  pushEnabled: false,
  vapidPublicKey: "",
  loadingPush: false,
  authenticated: false,
  username: "",
  highlightAlertId: 0,
};

let serviceWorkerRegistrationPromise = null;

function parseHighlightAlertId() {
  const raw = new URLSearchParams(window.location.search).get("alert_id");
  const parsed = Number(raw || 0);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
}

function setStatus(text, isError = false) {
  const line = document.getElementById("statusLine");
  if (!line) return;
  line.textContent = text;
  line.style.color = isError ? "#b42318" : "#4f6271";
}

function setLoginStatus(text, isError = false) {
  const line = document.getElementById("mobileLoginStatus");
  if (!line) return;
  line.textContent = text;
  line.style.color = isError ? "#b42318" : "#4f6271";
}

function showLoginOverlay(show) {
  document.getElementById("mobileLoginOverlay")?.classList.toggle("hidden", !show);
  document.getElementById("mobileAppShell")?.classList.toggle("hidden", show);
}

function updateUserLine() {
  const line = document.getElementById("mobileUserLine");
  if (!line) return;
  line.textContent = state.authenticated && state.username ? "Angemeldet als " + state.username : "";
}

function base64UrlToUint8Array(base64Url) {
  const input = String(base64Url || "").trim();
  if (!input) return new Uint8Array();
  const pad = "=".repeat((4 - (input.length % 4)) % 4);
  const normalized = (input + pad).replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(normalized);
  const output = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) output[i] = raw.charCodeAt(i);
  return output;
}

async function getServiceWorkerRegistration() {
  if (!("serviceWorker" in navigator)) {
    throw new Error("Service Worker wird auf diesem Browser nicht unterstützt");
  }
  if (!serviceWorkerRegistrationPromise) {
    serviceWorkerRegistrationPromise = navigator.serviceWorker.register("/sw.js");
  }
  const registration = await serviceWorkerRegistrationPromise;
  if (!registration) {
    throw new Error("Service Worker konnte nicht registriert werden");
  }
  return registration;
}

function renderPushButton() {
  const btn = document.getElementById("pushToggleButton");
  if (!btn) return;

  if (!state.authenticated) {
    btn.disabled = true;
    btn.textContent = "Push";
    return;
  }
  if (state.loadingPush) {
    btn.disabled = true;
    btn.textContent = "Push ...";
    return;
  }
  if (!state.pushSupported) {
    btn.disabled = true;
    btn.textContent = "Push n/v";
    return;
  }
  if (!state.pushConfigured) {
    btn.disabled = true;
    btn.textContent = "Push aus";
    return;
  }

  btn.disabled = false;
  btn.textContent = state.pushEnabled ? "Push an" : "Push aus";
}

async function refreshPushState() {
  if (!state.authenticated) {
    state.pushSupported = false;
    state.pushConfigured = false;
    state.pushEnabled = false;
    renderPushButton();
    return;
  }

  state.loadingPush = true;
  renderPushButton();
  try {
    const resp = await fetch("/api/v1/push-subscriptions", { credentials: "same-origin" });
    if (!resp.ok) throw new Error("HTTP " + resp.status);
    const payload = await resp.json();

    state.pushSupported = payload.supported === true && "serviceWorker" in navigator && "PushManager" in window;
    state.pushConfigured = payload.configured === true;
    state.vapidPublicKey = String(payload.vapid_public_key || "");

    let localEndpoint = "";
    if (state.pushSupported) {
      const registration = await getServiceWorkerRegistration();
      const localSub = await registration.pushManager.getSubscription();
      localEndpoint = String(localSub?.endpoint || "");
    }

    const serverSubs = Array.isArray(payload.subscriptions) ? payload.subscriptions : [];
    state.pushEnabled = Boolean(
      localEndpoint
      && serverSubs.some((item) => item && item.is_active === true && String(item.endpoint || "") === localEndpoint)
    );
  } catch (_error) {
    state.pushSupported = false;
    state.pushConfigured = false;
    state.pushEnabled = false;
  } finally {
    state.loadingPush = false;
    renderPushButton();
  }
}

async function togglePush() {
  if (!state.authenticated) {
    alert("Bitte zuerst anmelden.");
    return;
  }
  if (state.loadingPush) return;
  if (!state.pushSupported) {
    alert("Push wird auf diesem Gerät/Browsertyp nicht unterstützt.");
    return;
  }
  if (!state.pushConfigured) {
    alert("Push ist serverseitig noch nicht konfiguriert.");
    return;
  }

  state.loadingPush = true;
  renderPushButton();
  try {
    const registration = await getServiceWorkerRegistration();
    const existing = await registration.pushManager.getSubscription();

    if (existing && state.pushEnabled) {
      await fetch("/api/v1/push-subscriptions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({ action: "unsubscribe", endpoint: existing.endpoint }),
      });
      await existing.unsubscribe();
      state.pushEnabled = false;
      alert("Push deaktiviert.");
      return;
    }

    let sub = existing;
    if (!sub) {
      const permission = await Notification.requestPermission();
      if (permission !== "granted") throw new Error("Benachrichtigungsrechte nicht erlaubt");
      sub = await registration.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: base64UrlToUint8Array(state.vapidPublicKey),
      });
    }

    const saveResp = await fetch("/api/v1/push-subscriptions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ action: "subscribe", subscription: sub.toJSON() }),
    });
    if (!saveResp.ok) {
      const err = await saveResp.json().catch(() => ({}));
      throw new Error(String(err.error || ("HTTP " + saveResp.status)));
    }
    state.pushEnabled = true;
    alert("Push aktiviert.");
  } catch (error) {
    alert("Push-Umstellung fehlgeschlagen: " + (error?.message || String(error)));
  } finally {
    state.loadingPush = false;
    renderPushButton();
    void refreshPushState();
  }
}

async function sendTestPush() {
  const button = document.getElementById("testPushButton");
  if (button) {
    button.disabled = true;
    button.textContent = "Sende...";
  }
  try {
    const resp = await fetch("/api/v1/push-test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({
        title: "Monitoring Test Push",
        body: "Diese Nachricht wurde über den Test-Button ausgelöst.",
        url: "/mobile/alerts",
      }),
    });
    const payload = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      throw new Error(String(payload.error || ("HTTP " + resp.status)));
    }
    const success = Number(payload.success || 0);
    const failed = Number(payload.failed || 0);
    setStatus("Test Push gesendet (ok: " + success + ", failed: " + failed + ").");
    alert("Test Push wurde ausgelöst.");
  } catch (error) {
    const details = error?.message || String(error);
    setStatus("Test Push fehlgeschlagen: " + details, true);
    alert("Test Push fehlgeschlagen: " + details);
  } finally {
    if (button) {
      button.disabled = false;
      button.textContent = "Test Push";
    }
  }
}

async function callAlertAction(url, payload, okMessage) {
  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify(payload),
  });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error(String(data.error || ("HTTP " + resp.status)));
  setStatus(okMessage);
}

function buildEnvironmentChip(environmentType) {
  const label = mobileEnvironmentLabel(environmentType);
  if (!label) return "";
  const cssClass = label === "Prod." ? "env-prod" : "env-test";
  return '<span class="env-chip ' + cssClass + '">' + mobileEsc(label) + "</span>";
}

function highlightTargetCard() {
  if (!state.highlightAlertId) return;
  const card = document.querySelector('.alert-card[data-alert-id="' + state.highlightAlertId + '"]');
  if (!card) return;
  card.classList.add("alert-card-highlight");
  card.scrollIntoView({ behavior: "smooth", block: "center" });
  window.setTimeout(() => card.classList.remove("alert-card-highlight"), 4000);
}

function renderAlerts(items) {
  const list = document.getElementById("alertsList");
  if (!list) return;

  if (!Array.isArray(items) || items.length === 0) {
    list.innerHTML = '<div class="empty">Keine Alerts für den aktuellen Filter.</div>';
    return;
  }

  list.innerHTML = items.map((item) => {
    const sev = String(item.severity || "warning").toLowerCase();
    const id = Number(item.id || 0);
    const title = mobileEsc(item.display_name || item.hostname || "-");
    const hostname = mobileEsc(item.hostname || "-");
    const customer = mobileEsc(item.customer_name || "");
    const mountpoint = mobileEsc(item.mountpoint || "-");
    const used = Number(item.used_percent || 0).toFixed(1);
    const isAck = item.is_acknowledged === true;
    const contactLine = mobileEsc(item.it_provider_contact_line || "");
    const envChip = buildEnvironmentChip(item.environment_type);
    const highlightClass = id === state.highlightAlertId ? " alert-card-highlight" : "";

    return (
      '<article class="alert-card ' + sev + highlightClass + '" data-alert-id="' + id + '">' +
      '  <div class="alert-head">' +
      '    <div class="alert-host">' + title + envChip + '</div>' +
      '    <div class="alert-severity">' + mobileEsc(sev.toUpperCase()) + '</div>' +
      '  </div>' +
      (customer ? '  <div class="alert-meta">Kunde: ' + customer + "</div>" : "") +
      '  <div class="alert-meta">' + hostname + " · " + mountpoint + "</div>" +
      (contactLine ? '  <div class="alert-meta">IT: ' + contactLine + "</div>" : "") +
      '  <div class="alert-usage">Belegt: ' + used + "%</div>" +
      '  <div class="alert-actions">' +
      '    <button class="btn-ok" data-action="ack">Quittieren</button>' +
      '    <button data-action="unack">Unack</button>' +
      '    <button class="btn-danger" data-action="close">Schliessen</button>' +
      "  </div>" +
      (isAck ? '<div class="alert-meta">Bereits quittiert</div>' : "") +
      "</article>"
    );
  }).join("");

  list.querySelectorAll("button[data-action]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const card = btn.closest(".alert-card");
      const id = Number(card?.getAttribute("data-alert-id") || 0);
      const action = String(btn.getAttribute("data-action") || "");
      if (!id || !action) return;

      try {
        if (action === "ack") {
          const note = prompt("Optionale Notiz für Quittierung:", "") || "";
          await callAlertAction("/api/v1/alert-ack", { alert_id: id, ack_note: note }, "Alert quittiert.");
        } else if (action === "unack") {
          await callAlertAction("/api/v1/alert-unack", { alert_id: id }, "Quittierung aufgehoben.");
        } else if (action === "close") {
          if (!confirm("Alert wirklich schliessen?")) return;
          await callAlertAction("/api/v1/alert-close", { alert_id: id }, "Alert geschlossen.");
        }
        await loadAlerts();
      } catch (error) {
        setStatus("Aktion fehlgeschlagen: " + (error?.message || String(error)), true);
      }
    });
  });

  highlightTargetCard();
}

async function loadAlerts() {
  if (!state.authenticated) {
    showLoginOverlay(true);
    return;
  }

  setStatus("Lade Alerts...");
  const params = new URLSearchParams();
  params.set("status", state.showClosed ? "all" : "open");
  params.set("severity", state.severity);
  params.set("acknowledged", state.showAck ? "all" : "no");
  params.set("limit", "200");
  params.set("offset", "0");

  const resp = await fetch("/api/v1/alerts?" + params.toString(), { credentials: "same-origin" });
  if (resp.status === 401) {
    state.authenticated = false;
    showLoginOverlay(true);
    setLoginStatus("Session abgelaufen. Bitte erneut anmelden.", true);
    renderAlerts([]);
    return;
  }
  if (!resp.ok) throw new Error("HTTP " + resp.status);

  const payload = await resp.json();
  let alerts = Array.isArray(payload.alerts) ? payload.alerts : [];
  if (!state.showClosed) {
    alerts = alerts.filter((item) => item && item.is_closed !== true);
  }

  renderAlerts(alerts);
  setStatus(String(alerts.length) + " Alerts geladen.");
}

async function ensureAuthenticated() {
  const session = await mobileFetchSession();
  state.authenticated = session.authenticated === true;
  state.username = String(session.username || "");
  updateUserLine();
  showLoginOverlay(!state.authenticated);
  return state.authenticated;
}

async function submitLogin() {
  const username = document.getElementById("mobileLoginUsername")?.value.trim() || "";
  const password = document.getElementById("mobileLoginPassword")?.value || "";
  if (!username || !password) {
    setLoginStatus("Bitte Benutzername und Passwort eingeben.", true);
    return;
  }

  setLoginStatus("Anmeldung läuft...");
  try {
    const data = await mobileLogin(username, password);
    state.authenticated = true;
    state.username = String(data.username || username);
    updateUserLine();
    showLoginOverlay(false);
    setLoginStatus("");
    await refreshPushState();
    await loadAlerts();
  } catch (error) {
    state.authenticated = false;
    showLoginOverlay(true);
    setLoginStatus(error?.message || "Login fehlgeschlagen", true);
  }
}

function wirePullToRefresh() {
  let touchStartY = 0;
  document.addEventListener(
    "touchstart",
    (event) => {
      if (window.scrollY <= 0) {
        touchStartY = event.touches[0]?.clientY || 0;
      }
    },
    { passive: true }
  );
  document.addEventListener(
    "touchend",
    (event) => {
      if (!state.authenticated || window.scrollY > 4) return;
      const touchEndY = event.changedTouches[0]?.clientY || 0;
      if (touchEndY - touchStartY > 90) {
        void loadAlerts().catch((error) => setStatus("Fehler: " + error.message, true));
      }
    },
    { passive: true }
  );
}

function wire() {
  const refreshBtn = document.getElementById("refreshButton");
  const severityFilter = document.getElementById("severityFilter");
  const showAckToggle = document.getElementById("showAckToggle");
  const showClosedToggle = document.getElementById("showClosedToggle");
  const pushToggleButton = document.getElementById("pushToggleButton");
  const testPushButton = document.getElementById("testPushButton");
  const loginSubmit = document.getElementById("mobileLoginSubmit");
  const logoutButton = document.getElementById("mobileLogoutButton");
  const loginPassword = document.getElementById("mobileLoginPassword");

  if (refreshBtn) {
    refreshBtn.addEventListener("click", () => {
      void loadAlerts().catch((error) => setStatus("Fehler: " + error.message, true));
    });
  }
  if (severityFilter) {
    severityFilter.addEventListener("change", () => {
      state.severity = String(severityFilter.value || "all");
      void loadAlerts().catch((error) => setStatus("Fehler: " + error.message, true));
    });
  }
  if (showAckToggle) {
    showAckToggle.addEventListener("change", () => {
      state.showAck = showAckToggle.checked;
      void loadAlerts().catch((error) => setStatus("Fehler: " + error.message, true));
    });
  }
  if (showClosedToggle) {
    showClosedToggle.addEventListener("change", () => {
      state.showClosed = showClosedToggle.checked;
      void loadAlerts().catch((error) => setStatus("Fehler: " + error.message, true));
    });
  }
  if (pushToggleButton) {
    pushToggleButton.addEventListener("click", () => {
      void togglePush();
    });
  }
  if (testPushButton) {
    testPushButton.addEventListener("click", () => {
      void sendTestPush();
    });
  }
  if (loginSubmit) {
    loginSubmit.addEventListener("click", () => {
      void submitLogin();
    });
  }
  if (loginPassword) {
    loginPassword.addEventListener("keydown", (event) => {
      if (event.key === "Enter") {
        void submitLogin();
      }
    });
  }
  if (logoutButton) {
    logoutButton.addEventListener("click", async () => {
      await mobileLogout();
      state.authenticated = false;
      state.username = "";
      updateUserLine();
      showLoginOverlay(true);
      renderAlerts([]);
      setStatus("");
      renderPushButton();
    });
  }

  wirePullToRefresh();
}

async function init() {
  state.highlightAlertId = parseHighlightAlertId();
  wire();
  try {
    await ensureAuthenticated();
    if (state.authenticated) {
      await refreshPushState();
      await loadAlerts();
    } else {
      setLoginStatus("Bitte anmelden, um Alerts zu laden.");
    }
  } catch (error) {
    showLoginOverlay(true);
    setLoginStatus("Initialisierung fehlgeschlagen: " + (error?.message || String(error)), true);
  }
}

void init();
