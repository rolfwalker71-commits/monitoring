function esc(value) {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

const state = {
  severity: "all",
  showAck: true,
  showClosed: false,
  pushSupported: false,
  pushConfigured: false,
  pushEnabled: false,
  vapidPublicKey: "",
  loadingPush: false,
};

let serviceWorkerRegistrationPromise = null;

function setStatus(text, isError = false) {
  const line = document.getElementById("statusLine");
  if (!line) return;
  line.textContent = text;
  line.style.color = isError ? "#b42318" : "#4f6271";
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
    const title = esc(item.display_name || item.hostname || "-");
    const hostname = esc(item.hostname || "-");
    const mountpoint = esc(item.mountpoint || "-");
    const used = Number(item.used_percent || 0).toFixed(1);
    const isAck = item.is_acknowledged === true;

    return (
      '<article class="alert-card ' + sev + '" data-alert-id="' + id + '">' +
      '  <div class="alert-head">' +
      '    <div class="alert-host">' + title + '</div>' +
      '    <div>' + esc(sev.toUpperCase()) + '</div>' +
      '  </div>' +
      '  <div class="alert-meta">' + hostname + ' · ' + mountpoint + '</div>' +
      '  <div class="alert-usage">Used: ' + used + '%</div>' +
      '  <div class="alert-actions">' +
      '    <button class="btn-ok" data-action="ack">Quittieren</button>' +
      '    <button data-action="unack">Unack</button>' +
      '    <button class="btn-danger" data-action="close">Schliessen</button>' +
      '  </div>' +
      (isAck ? '<div class="alert-meta">Bereits quittiert</div>' : '') +
      '</article>'
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
}

async function loadAlerts() {
  setStatus("Lade Alerts...");
  const params = new URLSearchParams();
  params.set("status", state.showClosed ? "all" : "open");
  params.set("severity", state.severity);
  params.set("acknowledged", state.showAck ? "all" : "no");
  params.set("limit", "200");
  params.set("offset", "0");

  const resp = await fetch("/api/v1/alerts?" + params.toString(), { credentials: "same-origin" });
  if (resp.status === 401) {
    setStatus("Nicht eingeloggt. Bitte zuerst im Haupt-Webclient anmelden.", true);
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

function wire() {
  const refreshBtn = document.getElementById("refreshButton");
  const severityFilter = document.getElementById("severityFilter");
  const showAckToggle = document.getElementById("showAckToggle");
  const showClosedToggle = document.getElementById("showClosedToggle");
  const pushToggleButton = document.getElementById("pushToggleButton");
  const testPushButton = document.getElementById("testPushButton");

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
}

async function init() {
  wire();
  await refreshPushState();
  await loadAlerts();
}

void init().catch((error) => {
  setStatus("Initialisierung fehlgeschlagen: " + (error?.message || String(error)), true);
});
