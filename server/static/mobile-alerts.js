function mobileEsc(value) {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

async function mobileFetchSession() {
  const resp = await fetch("/api/v1/session", { credentials: "same-origin" });
  if (!resp.ok) {
    throw new Error("HTTP " + resp.status);
  }
  return resp.json();
}

async function mobileLogin(username, password) {
  const resp = await fetch("/api/v1/web-login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify({ username, password }),
  });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) {
    throw new Error(String(data.error || "Login fehlgeschlagen"));
  }
  return data;
}

async function mobileLogout() {
  await fetch("/api/v1/web-logout", {
    method: "POST",
    credentials: "same-origin",
  }).catch(() => {});
}

function mobileEnvironmentLabel(value) {
  const env = String(value || "").trim().toLowerCase();
  if (env === "prod") return "Prod.";
  if (env === "test") return "Test";
  return "";
}

function formatRelativeTime(iso) {
  const raw = String(iso || "").trim();
  if (!raw) return "";
  const normalized = raw.includes("T") ? raw : raw.replace(" ", "T");
  const parsed = new Date(normalized.endsWith("Z") ? normalized : normalized + "Z");
  if (Number.isNaN(parsed.getTime())) return "";
  const sec = Math.max(0, Math.floor((Date.now() - parsed.getTime()) / 1000));
  if (sec < 60) return "gerade eben";
  if (sec < 3600) return "vor " + Math.floor(sec / 60) + " Min";
  if (sec < 86400) return "vor " + Math.floor(sec / 3600) + " Std";
  return "vor " + Math.floor(sec / 86400) + " Tag";
}

const state = {
  severity: "all",
  country: "all",
  availableCountries: [],
  showAck: true,
  showClosed: false,
  focusedAlertIndex: 0,
  pushSupported: false,
  pushConfigured: false,
  pushEnabled: false,
  vapidPublicKey: "",
  loadingPush: false,
  authenticated: false,
  username: "",
  userDisplayName: "",
  highlightAlertId: 0,
  pendingAckAlertId: 0,
  pendingCloseAlertId: 0,
  lastAlerts: [],
  alertsLoading: false,
};

const SKELETON_CARD_COUNT = 4;

let serviceWorkerRegistrationPromise = null;
let toastTimer = null;
let customerLogoObserver = null;

function parseHighlightAlertId() {
  const raw = new URLSearchParams(window.location.search).get("alert_id");
  const parsed = Number(raw || 0);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : 0;
}

function setStatus(text, isError = false) {
  const line = document.getElementById("statusLine");
  if (!line) return;
  line.textContent = text;
  line.classList.toggle("is-error", isError);
}

function setLoginStatus(text, isError = false) {
  const line = document.getElementById("mobileLoginStatus");
  const banner = document.getElementById("mobileLoginBanner");
  if (line) {
    line.textContent = text;
    line.style.color = isError ? "var(--critical)" : "var(--muted)";
  }
  if (banner) {
    if (text && isError) {
      banner.textContent = text;
      banner.classList.remove("hidden");
      banner.classList.add("is-error");
    } else {
      banner.classList.add("hidden");
      banner.classList.remove("is-error");
      banner.textContent = "";
    }
  }
}

function showToast(message, isError = false) {
  const toast = document.getElementById("toast");
  if (!toast) return;
  toast.textContent = message;
  toast.classList.toggle("is-error", isError);
  toast.classList.remove("hidden");
  toast.classList.add("is-visible");
  if (toastTimer) window.clearTimeout(toastTimer);
  toastTimer = window.setTimeout(() => {
    toast.classList.remove("is-visible");
    window.setTimeout(() => toast.classList.add("hidden"), 280);
  }, 2600);
}

function showLoginOverlay(show) {
  document.getElementById("mobileLoginOverlay")?.classList.toggle("hidden", !show);
  document.getElementById("mobileAppShell")?.classList.toggle("hidden", show);
}

function resolveUserDisplayName(sessionOrLogin) {
  const displayName = String(sessionOrLogin?.display_name || "").trim();
  if (displayName) return displayName;
  return String(sessionOrLogin?.username || state.username || "").trim();
}

function updateUserLine() {
  const line = document.getElementById("mobileUserLine");
  if (!line) return;
  if (!state.authenticated) {
    line.textContent = "";
    return;
  }
  const label = state.userDisplayName || state.username;
  line.innerHTML = "User: <strong>" + mobileEsc(label) + "</strong>";
}

function openSheet(sheetId) {
  const sheet = document.getElementById(sheetId);
  const backdrop = document.getElementById("sheetBackdrop");
  if (!sheet || !backdrop) return;
  backdrop.classList.remove("hidden");
  backdrop.classList.add("is-open");
  backdrop.setAttribute("aria-hidden", "false");
  sheet.classList.remove("hidden");
  requestAnimationFrame(() => sheet.classList.add("is-open"));
}

function closeAllSheets() {
  document.querySelectorAll(".bottom-sheet.is-open").forEach((el) => el.classList.remove("is-open"));
  const backdrop = document.getElementById("sheetBackdrop");
  if (backdrop) {
    backdrop.classList.remove("is-open");
    backdrop.setAttribute("aria-hidden", "true");
    window.setTimeout(() => backdrop.classList.add("hidden"), 220);
  }
  window.setTimeout(() => {
    document.querySelectorAll(".bottom-sheet:not(.is-open)").forEach((el) => {
      if (!el.classList.contains("is-open")) el.classList.add("hidden");
    });
  }, 300);
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
    btn.textContent = "🔕";
    btn.title = "Push (nicht angemeldet)";
    return;
  }
  if (state.loadingPush) {
    btn.disabled = true;
    btn.textContent = "…";
    btn.title = "Push wird geladen";
    return;
  }
  if (!state.pushSupported) {
    btn.disabled = true;
    btn.textContent = "🔕";
    btn.title = "Push nicht unterstützt";
    return;
  }
  if (!state.pushConfigured) {
    btn.disabled = true;
    btn.textContent = "🔕";
    btn.title = "Push serverseitig nicht konfiguriert";
    return;
  }

  btn.disabled = false;
  btn.textContent = state.pushEnabled ? "🔔" : "🔕";
  btn.title = state.pushEnabled ? "Push deaktivieren" : "Push aktivieren";
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
    showToast("Bitte zuerst anmelden.", true);
    return;
  }
  if (state.loadingPush) return;
  if (!state.pushSupported) {
    showToast("Push wird auf diesem Gerät nicht unterstützt.", true);
    return;
  }
  if (!state.pushConfigured) {
    showToast("Push ist serverseitig noch nicht konfiguriert.", true);
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
      showToast("Push deaktiviert.");
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
    showToast("Push aktiviert.");
  } catch (error) {
    showToast("Push fehlgeschlagen: " + (error?.message || String(error)), true);
  } finally {
    state.loadingPush = false;
    renderPushButton();
    void refreshPushState();
  }
}

async function sendTestPush() {
  const button = document.getElementById("testPushButton");
  const menu = document.getElementById("headerMenu");
  if (button) {
    button.disabled = true;
    button.textContent = "Sende…";
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
    showToast("Test Push wurde ausgelöst.");
  } catch (error) {
    const details = error?.message || String(error);
    setStatus("Test Push fehlgeschlagen: " + details, true);
    showToast("Test Push fehlgeschlagen: " + details, true);
  } finally {
    if (button) {
      button.disabled = false;
      button.textContent = "Test Push senden";
    }
    menu?.classList.add("hidden");
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
  showToast(okMessage);
}

function getCountryFlagIconPath(countryCode) {
  const code = String(countryCode || "").trim().toUpperCase().slice(0, 2);
  const validCodes = ["CH", "DE", "FR", "AT", "ANG", "HO"];
  return validCodes.includes(code) ? "/icons/" + code + ".png" : null;
}

function buildCountryFlagHtml(countryCode) {
  const code = String(countryCode || "").trim().toUpperCase();
  const iconPath = getCountryFlagIconPath(code);
  if (!iconPath) return "";
  return (
    '<img class="alert-country-flag" src="' + mobileEsc(iconPath) + '" alt="' + mobileEsc(code) + '" '
    + 'title="' + mobileEsc(code) + '" width="22" height="16" loading="lazy" decoding="async" '
    + 'onerror="this.style.display=\'none\'" />'
  );
}

function resolveUserDisplayLabel(item, field) {
  const labelKey = field + "_label";
  const label = String(item?.[labelKey] || "").trim();
  if (label) return label;
  return String(item?.[field] || "").trim();
}

function isPlaceholderAckText(text) {
  const value = String(text || "").trim();
  if (!value) return true;
  return /^[-–—.\s]+$/.test(value);
}

function normalizeAckNote(note) {
  const text = String(note || "").trim();
  if (isPlaceholderAckText(text)) return "";
  return text;
}

function buildAckByDetailLines(item) {
  const ackByRaw = resolveUserDisplayLabel(item, "ack_by");
  const ackBy = isPlaceholderAckText(ackByRaw) ? "" : ackByRaw;
  const ackAt = formatIsoLabel(item.ack_at_utc);
  const valueParts = [];
  if (ackBy) valueParts.push(ackBy);
  if (ackAt && ackAt !== "—") valueParts.push(ackAt);
  return {
    label: "Quittiert von",
    value: valueParts.length ? valueParts.join(" · ") : "—",
    note: normalizeAckNote(item.ack_note),
  };
}

function buildAckStripHtml(item) {
  if (item.is_acknowledged !== true) return "";
  const { label, value, note } = buildAckByDetailLines(item);
  let html =
    '<p class="alert-ack-strip">'
    + '<span class="alert-ack-strip-label">' + mobileEsc(label) + "</span>"
    + '<span class="alert-ack-strip-value">' + mobileEsc(value) + "</span>";
  if (note) {
    html += '<span class="alert-ack-strip-note">' + mobileEsc(note) + "</span>";
  }
  return html + "</p>";
}

function buildEnvironmentChip(environmentType) {
  const label = mobileEnvironmentLabel(environmentType);
  if (!label) return "";
  const cssClass = label === "Prod." ? "env-prod" : "env-test";
  return '<span class="env-chip ' + cssClass + '">' + mobileEsc(label) + "</span>";
}

function buildDesktopHostUrl(hostUid, hostname) {
  const uid = String(hostUid || "").trim();
  if (uid) return "/?host_uid=" + encodeURIComponent(uid);
  const host = String(hostname || "").trim();
  if (host) return "/?hostname=" + encodeURIComponent(host);
  return "/";
}

function formatIsoLabel(iso) {
  const raw = String(iso || "").trim();
  if (!raw) return "—";
  const normalized = raw.includes("T") ? raw : raw.replace(" ", "T");
  const parsed = new Date(normalized.endsWith("Z") ? normalized : normalized + "Z");
  if (Number.isNaN(parsed.getTime())) return raw;
  return parsed.toLocaleString("de-CH", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function buildCustomerLogoHtml(item) {
  const logoUrl = String(item.customer_logo_url || "").trim();
  if (!logoUrl) return "";
  return (
    '<img class="customer-logo customer-logo-right" data-src="' + mobileEsc(logoUrl) + '" alt="" width="32" height="32" '
    + 'data-load-state="loading" decoding="async" />'
  );
}

function buildAlertIdentityHtml(item) {
  const customerName = String(item.customer_name || "").trim();
  const hostLabel = String(item.display_name || item.hostname || "-").trim();
  const logoHtml = buildCustomerLogoHtml(item);
  const hostRowAttrs =
    ' class="alert-host-row is-tappable" data-action="host-info" role="button" tabindex="0" aria-label="Host-Details"';
  const titleRowAttrs =
    ' class="alert-customer-row is-tappable" data-action="host-info" role="button" tabindex="0" aria-label="Host-Details"';

  if (customerName) {
    return (
      '<div class="alert-identity">'
      + '<div class="alert-customer-row">'
      + '<h2 class="alert-customer-name">' + mobileEsc(customerName) + "</h2>"
      + logoHtml
      + "</div>"
      + "<div" + hostRowAttrs + '><p class="alert-host-name">' + mobileEsc(hostLabel) + "</p></div>"
      + "</div>"
    );
  }

  return (
    '<div class="alert-identity">'
    + "<div" + titleRowAttrs + ">"
    + '<h2 class="alert-customer-name">' + mobileEsc(hostLabel) + "</h2>"
    + logoHtml
    + "</div></div>"
  );
}

function renderSkeletonCards(count = SKELETON_CARD_COUNT) {
  const list = document.getElementById("alertsList");
  if (!list) return;
  const chunks = [];
  for (let i = 0; i < count; i += 1) {
    chunks.push(
      '<article class="skeleton-card" aria-hidden="true">'
      + '<div class="skeleton-line wide"></div>'
      + '<div class="skeleton-line medium"></div>'
      + '<div class="skeleton-bar"></div>'
      + '<div class="skeleton-line short"></div>'
      + "</article>"
    );
  }
  list.innerHTML = chunks.join("");
}

function setAlertsLoading(loading) {
  state.alertsLoading = loading;
  document.getElementById("alertsList")?.classList.toggle("is-loading", loading);
}

function wireCustomerLogos(list) {
  const imgs = list.querySelectorAll("img.customer-logo[data-src]");
  if (!imgs.length) return;

  const applySrc = (img) => {
    const src = img.getAttribute("data-src");
    if (!src) return;
    img.src = src;
    img.removeAttribute("data-src");
    img.addEventListener(
      "load",
      () => img.setAttribute("data-load-state", "loaded"),
      { once: true }
    );
    img.addEventListener(
      "error",
      () => img.setAttribute("data-load-state", "error"),
      { once: true }
    );
  };

  if (!("IntersectionObserver" in window)) {
    imgs.forEach(applySrc);
    return;
  }

  if (!customerLogoObserver) {
    customerLogoObserver = new IntersectionObserver(
      (entries, observer) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;
          applySrc(entry.target);
          observer.unobserve(entry.target);
        });
      },
      { rootMargin: "120px 0px" }
    );
  }

  imgs.forEach((img) => {
    if (img.getAttribute("data-src")) {
      customerLogoObserver.observe(img);
    }
  });
}

function hostSheetFactRow(label, value) {
  const text = String(value || "").trim();
  if (!text) return "";
  return "<div><dt>" + mobileEsc(label) + "</dt><dd>" + mobileEsc(text) + "</dd></div>";
}

function hostSheetFactRowHtml(label, html) {
  const content = String(html || "").trim();
  if (!content) return "";
  return "<div><dt>" + mobileEsc(label) + "</dt><dd>" + content + "</dd></div>";
}

function hostSheetAckBlock(item) {
  if (item.is_acknowledged !== true) return "";
  const { label, value, note } = buildAckByDetailLines(item);
  let html =
    '<div class="host-sheet-fact-stack">'
    + "<dt>" + mobileEsc(label) + "</dt>"
    + "<dd>" + mobileEsc(value) + "</dd>";
  if (note) {
    html += '<dd class="host-sheet-ack-note">' + mobileEsc(note) + "</dd>";
  }
  return html + "</div>";
}

function openHostSheet(item) {
  if (!item) return;

  const displayName = String(item.display_name || item.hostname || "Host").trim();
  const hostname = String(item.hostname || "").trim();
  const hostUid = String(item.host_uid || "").trim();
  const subtitle = hostname && hostname !== displayName ? hostname : hostUid || "Host-Details";

  const titleEl = document.getElementById("hostSheetTitle");
  const subtitleEl = document.getElementById("hostSheetSubtitle");
  const factsEl = document.getElementById("hostSheetFacts");
  const logoEl = document.getElementById("hostSheetLogo");

  if (titleEl) titleEl.textContent = displayName;
  if (subtitleEl) subtitleEl.textContent = subtitle;

  const logoUrl = String(item.customer_logo_url || "").trim();
  if (logoEl) {
    if (logoUrl) {
      logoEl.src = logoUrl;
      logoEl.classList.remove("hidden");
      logoEl.onerror = () => logoEl.classList.add("hidden");
      logoEl.onload = () => logoEl.classList.remove("hidden");
    } else {
      logoEl.removeAttribute("src");
      logoEl.classList.add("hidden");
    }
  }

  const envLabel = mobileEnvironmentLabel(item.environment_type) || "—";
  const statusBits = [];
  if (item.is_acknowledged) statusBits.push("Quittiert");
  if (item.is_closed) statusBits.push("Geschlossen");
  if (item.is_muted) statusBits.push("Stumm");
  if (item.is_heads_up_suppressed) statusBits.push("Heads-up aus");

  const itContactHtml = buildItContactHtml(item);

  if (factsEl) {
    factsEl.innerHTML = [
      hostSheetFactRow("Hostname", hostname),
      hostSheetFactRow("Host-UID", hostUid),
      hostSheetFactRow("IP (letzter Report)", item.latest_report_ip),
      hostSheetFactRow("Kunde", item.customer_name),
      hostSheetFactRowHtml("Ansprechpartner", itContactHtml),
      hostSheetFactRow("Umgebung", envLabel),
      hostSheetFactRow("Mountpoint", item.mountpoint),
      hostSheetFactRow("Severity", String(item.severity || "").toUpperCase()),
      hostSheetFactRow("Belegt (Alert)", item.used_percent != null ? Number(item.used_percent).toFixed(1) + "%" : ""),
      hostSheetFactRow(
        "Aktuell",
        item.current_used_percent != null ? Number(item.current_used_percent).toFixed(1) + "%" : ""
      ),
      hostSheetFactRow("Erstellt", formatIsoLabel(item.created_at_utc)),
      hostSheetFactRow("Zuletzt gesehen", formatIsoLabel(item.last_seen_at_utc)),
      hostSheetFactRow("Status", statusBits.join(", ") || "Offen"),
      hostSheetAckBlock(item),
      hostSheetFactRow("Alert-ID", "#" + String(item.id || "")),
    ].join("");
  }

  openSheet("hostSheet");
}

function buildItContactHtml(item) {
  const line = String(item.it_provider_contact_line || "").trim();
  const email = String(item.it_provider_email || "").trim();
  const phone = String(item.it_provider_phone || "").trim();
  const parts = [];
  if (line) parts.push(mobileEsc(line));
  if (email) {
    parts.push('<a href="mailto:' + mobileEsc(email) + '">' + mobileEsc(email) + "</a>");
  }
  if (phone) {
    const tel = phone.replace(/[^\d+]/g, "");
    parts.push('<a href="tel:' + mobileEsc(tel) + '">' + mobileEsc(phone) + "</a>");
  }
  if (!parts.length) return "";
  return parts.join(" · ");
}

function usagePercentForBar(item) {
  const current = item.current_used_percent;
  if (current != null && Number.isFinite(Number(current))) {
    return Math.min(100, Math.max(0, Number(current)));
  }
  return Math.min(100, Math.max(0, Number(item.used_percent || 0)));
}

function buildUsageLine(item) {
  const used = Number(item.used_percent || 0).toFixed(1);
  const current = item.current_used_percent;
  const mount = mobileEsc(item.mountpoint || "-");
  if (current != null && Number.isFinite(Number(current))) {
    return mount + " · " + used + "% (jetzt " + Number(current).toFixed(1) + "%)";
  }
  return mount + " · " + used + "%";
}

function renderKpis(alerts) {
  const open = alerts.filter((item) => item && item.is_closed !== true);
  const critical = open.filter((item) => String(item.severity || "").toLowerCase() === "critical").length;
  const warning = open.filter((item) => String(item.severity || "").toLowerCase() === "warning").length;
  const elCritical = document.getElementById("kpiCritical");
  const elWarning = document.getElementById("kpiWarning");
  const elOpen = document.getElementById("kpiOpen");
  if (elCritical) elCritical.textContent = String(critical);
  if (elWarning) elWarning.textContent = String(warning);
  if (elOpen) elOpen.textContent = String(open.length);
}

function syncSeverityChips() {
  document.querySelectorAll(".filter-chips .chip[data-severity]").forEach((chip) => {
    chip.classList.toggle("active", chip.getAttribute("data-severity") === state.severity);
  });
}

function highlightTargetCard() {
  if (!state.highlightAlertId) return;
  const card = document.querySelector('.alert-card[data-alert-id="' + state.highlightAlertId + '"]');
  if (!card) return;
  card.classList.add("alert-card-highlight");
  card.scrollIntoView({ behavior: "smooth", inline: "center", block: "nearest" });
  const index = Number(card.getAttribute("data-alert-index") || 0);
  updateAlertDetailPanel(index);
  window.setTimeout(() => card.classList.remove("alert-card-highlight"), 4000);
}

function renderAlerts(items) {
  const list = document.getElementById("alertsList");
  if (!list) return;

  state.lastAlerts = Array.isArray(items) ? items : [];
  renderKpis(state.lastAlerts);

  if (!state.lastAlerts.length) {
    list.innerHTML = '<div class="empty-state carousel-empty">Keine Alerts für den aktuellen Filter.</div>';
    document.getElementById("alertDetailPanel")?.classList.add("hidden");
    return;
  }

  list.innerHTML = state.lastAlerts.map((item, index) => {
    const sev = String(item.severity || "warning").toLowerCase();
    const id = Number(item.id || 0);
    const hostname = mobileEsc(item.hostname || "-");
    const identityHtml = buildAlertIdentityHtml(item);
    const envChip = buildEnvironmentChip(item.environment_type);
    const isAck = item.is_acknowledged === true;
    const isClosed = item.is_closed === true;
    const highlightClass = id === state.highlightAlertId ? " alert-card-highlight" : "";
    const barPercent = usagePercentForBar(item);
    const barWidth = barPercent.toFixed(1);
    const timeLabel = formatRelativeTime(item.last_seen_at_utc || item.created_at_utc);
    const ackDetail = isAck ? buildAckByDetailLines(item) : null;
    const desktopUrl = "/?alert_id=" + id;

    let moreHtml = "Alert #" + id;
    if (item.is_muted) moreHtml += " · Stummgeschaltet";
    if (item.is_heads_up_suppressed) moreHtml += " · Heads-up unterdrückt";
    if (item.delta_used_percent != null) {
      moreHtml += " · Δ " + Number(item.delta_used_percent).toFixed(1) + "%";
    }
    moreHtml += ' · <a href="' + mobileEsc(desktopUrl) + '">Am Desktop öffnen</a>';
    if (isAck && ackDetail) {
      moreHtml += '<div class="ack-line ack-line-stacked">';
      moreHtml += "<span>" + mobileEsc(ackDetail.label) + "</span>";
      moreHtml += "<span>" + mobileEsc(ackDetail.value) + "</span>";
      if (ackDetail.note) {
        moreHtml += "<span>" + mobileEsc(ackDetail.note) + "</span>";
      }
      moreHtml += "</div>";
    }
    if (isClosed) {
      moreHtml += '<div class="ack-line">Geschlossen</div>';
    }

    const ackBtn = isAck
      ? '<button type="button" class="btn-secondary" data-action="unack">Unack</button>'
      : '<button type="button" class="btn-primary" data-action="ack">Quittieren</button>';

    const countryFlag = buildCountryFlagHtml(item.country_code);
    const ackStrip = buildAckStripHtml(item);

    return (
      '<article class="alert-card ' + sev + highlightClass + '" data-alert-id="' + id + '" data-alert-index="' + index + '">' +
      '  <div class="alert-card-head">' +
      '    <div class="alert-status-group">' +
      '      <span class="severity-badge ' + sev + '">' + mobileEsc(sev) + "</span>" +
      envChip +
      "    </div>" +
      '    <div class="alert-head-center">' + countryFlag + "</div>" +
      '    <span class="alert-time">' + mobileEsc(timeLabel || "—") + "</span>" +
      "  </div>" +
      "  " + identityHtml +
      '<div class="alert-card-body">' +
      ackStrip +
      '  <p class="alert-meta alert-usage-line">' + buildUsageLine(item) + "</p>" +
      '  <div class="usage-bar-block">' +
      '    <div class="usage-bar-row">' +
      '      <div class="usage-bar"><span class="usage-bar-fill" style="width:' + barWidth + '%"></span></div>' +
      '      <strong class="usage-bar-counter">' + barWidth + '%</strong>' +
      "    </div></div>" +
      '  <p class="alert-meta">' + hostname + "</p>" +
      '  <div class="alert-card-actions">' + ackBtn +
      '    <button type="button" class="btn-secondary btn-expand" data-action="toggle-more">Mehr</button>' +
      "  </div>" +
      '  <div class="alert-more">' + moreHtml +
      '    <div style="margin-top:10px;display:grid;grid-template-columns:1fr 1fr;gap:8px">' +
      '      <button type="button" class="btn-danger" data-action="close">Schliessen</button>' +
      "    </div></div></div>" +
      "</article>"
    );
  }).join("");

  wireCustomerLogos(list);
  wireAlertsCarousel(list);
  highlightTargetCard();
  syncFocusedCarouselCard(list);
}

function renderCountryFilterChips() {
  const container = document.getElementById("countryFilterChips");
  if (!container) return;
  const countries = Array.isArray(state.availableCountries) ? state.availableCountries : [];
  const chips = ['<button type="button" class="chip' + (state.country === "all" ? " active" : "") + '" data-country="all">Alle</button>'];
  countries.forEach((code) => {
    const normalized = String(code || "").trim().toUpperCase();
    if (!/^[A-Z]{2}$/.test(normalized)) return;
    const flag = buildCountryFlagHtml(normalized);
    chips.push(
      '<button type="button" class="chip' + (state.country === normalized ? " active" : "") + '" data-country="'
      + mobileEsc(normalized) + '">' + flag + "<span>" + mobileEsc(normalized) + "</span></button>"
    );
  });
  container.innerHTML = chips.join("");
  container.querySelectorAll(".chip[data-country]").forEach((chip) => {
    chip.addEventListener("click", () => {
      state.country = String(chip.getAttribute("data-country") || "all");
      container.querySelectorAll(".chip[data-country]").forEach((el) => {
        el.classList.toggle("active", el.getAttribute("data-country") === state.country);
      });
    });
  });
}

function buildAlertDetailHtml(item) {
  if (!item) return "";
  const lines = [];
  const push = (label, value) => {
    const text = String(value || "").trim();
    if (text) lines.push("<div><dt>" + mobileEsc(label) + "</dt><dd>" + mobileEsc(text) + "</dd></div>");
  };

  const displayHost = String(item.display_name || "").trim();
  const hostname = String(item.hostname || "").trim();
  if (hostname && hostname !== displayHost) {
    push("Hostname", hostname);
  }
  push("IP", item.latest_report_ip);
  if (item.delta_used_percent != null) {
    push("Delta", Number(item.delta_used_percent).toFixed(1) + "%");
  }
  push("Erstellt", formatIsoLabel(item.created_at_utc));
  push("Zuletzt gesehen", formatIsoLabel(item.last_seen_at_utc));

  const flags = [];
  if (item.is_muted) flags.push("Stummgeschaltet");
  if (item.is_heads_up_suppressed) flags.push("Heads-up unterdrückt");
  if (item.is_closed) flags.push("Geschlossen");
  if (flags.length) push("Hinweis", flags.join(", "));

  return (
    '<h4 class="alert-detail-title">Zusatzinfos · Alert #' + mobileEsc(String(item.id || "")) + "</h4>"
    + (lines.length ? '<dl class="alert-detail-facts">' + lines.join("") + "</dl>" : '<p class="sheet-hint">Keine weiteren Details.</p>')
  );
}

function updateAlertDetailPanel(index) {
  const panel = document.getElementById("alertDetailPanel");
  if (!panel) return;
  const item = state.lastAlerts[index];
  if (!item) {
    panel.classList.add("hidden");
    panel.innerHTML = "";
    return;
  }
  state.focusedAlertIndex = index;
  panel.classList.remove("hidden");
  panel.innerHTML = buildAlertDetailHtml(item);
}

function syncFocusedCarouselCard(list) {
  const cards = list.querySelectorAll(".alert-card");
  if (!cards.length) return;
  const listRect = list.getBoundingClientRect();
  const listCenter = listRect.left + listRect.width / 2;
  let bestIndex = 0;
  let bestDistance = Number.POSITIVE_INFINITY;
  cards.forEach((card) => {
    const rect = card.getBoundingClientRect();
    const cardCenter = rect.left + rect.width / 2;
    const distance = Math.abs(cardCenter - listCenter);
    if (distance < bestDistance) {
      bestDistance = distance;
      bestIndex = Number(card.getAttribute("data-alert-index") || 0);
    }
  });
  updateAlertDetailPanel(bestIndex);
}

function wireAlertsCarousel(list) {
  if (list.dataset.carouselWired === "1") return;
  list.dataset.carouselWired = "1";
  let scrollTimer = null;
  const settle = () => syncFocusedCarouselCard(list);
  list.addEventListener("scroll", () => {
    if (scrollTimer) window.clearTimeout(scrollTimer);
    scrollTimer = window.setTimeout(settle, 420);
  }, { passive: true });
  if ("onscrollend" in window) {
    list.addEventListener("scrollend", settle, { passive: true });
  }
}

function resolveAlertFromCard(card) {
  const index = Number(card?.getAttribute("data-alert-index"));
  if (Number.isFinite(index) && index >= 0 && index < state.lastAlerts.length) {
    return state.lastAlerts[index];
  }
  const id = Number(card?.getAttribute("data-alert-id") || 0);
  return state.lastAlerts.find((entry) => Number(entry?.id || 0) === id) || null;
}

async function handleAlertsListClick(event) {
  const hostTarget = event.target.closest('[data-action="host-info"]');
  if (hostTarget) {
    const card = hostTarget.closest(".alert-card");
    const item = resolveAlertFromCard(card);
    if (item) openHostSheet(item);
    return;
  }

  const btn = event.target.closest("button[data-action]");
  if (!btn) return;

  const card = btn.closest(".alert-card");
  const id = Number(card?.getAttribute("data-alert-id") || 0);
  const action = String(btn.getAttribute("data-action") || "");
  if (!id || !action) return;

  if (action === "toggle-more") {
    const expanded = card.classList.toggle("is-expanded");
    btn.textContent = expanded ? "weniger" : "Mehr";
    return;
  }

  try {
    if (action === "ack") {
      state.pendingAckAlertId = id;
      const noteInput = document.getElementById("ackNoteInput");
      if (noteInput) noteInput.value = "";
      openSheet("ackSheet");
    } else if (action === "unack") {
      await callAlertAction("/api/v1/alert-unack", { alert_id: id }, "Quittierung aufgehoben.");
      await loadAlerts();
    } else if (action === "close") {
      state.pendingCloseAlertId = id;
      openSheet("closeSheet");
    }
  } catch (error) {
    setStatus("Aktion fehlgeschlagen: " + (error?.message || String(error)), true);
    showToast("Aktion fehlgeschlagen: " + (error?.message || String(error)), true);
  }
}

function handleAlertsListKeydown(event) {
  if (event.key !== "Enter" && event.key !== " ") return;
  const hostTarget = event.target.closest('[data-action="host-info"]');
  if (!hostTarget) return;
  event.preventDefault();
  const card = hostTarget.closest(".alert-card");
  const item = resolveAlertFromCard(card);
  if (item) openHostSheet(item);
}

async function loadAlerts() {
  if (!state.authenticated) {
    showLoginOverlay(true);
    return;
  }

  const showSkeleton = state.lastAlerts.length === 0;
  setAlertsLoading(true);
  if (showSkeleton) {
    renderSkeletonCards();
    setStatus("Lade Alerts…");
  } else {
    setStatus("Aktualisiere…");
  }

  try {
    const params = new URLSearchParams();
    params.set("status", state.showClosed ? "all" : "open");
    params.set("severity", state.severity);
    params.set("acknowledged", state.showAck ? "all" : "no");
    params.set("limit", "200");
    params.set("offset", "0");
    if (state.country && state.country !== "all") {
      params.set("country", state.country);
    }

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
    if (Array.isArray(payload.available_countries)) {
      state.availableCountries = payload.available_countries;
      renderCountryFilterChips();
    }
    if (!state.showClosed) {
      alerts = alerts.filter((item) => item && item.is_closed !== true);
    }

    renderAlerts(alerts);
    setStatus(String(alerts.length) + " Alerts geladen.");
  } finally {
    setAlertsLoading(false);
  }
}

async function ensureAuthenticated() {
  const session = await mobileFetchSession();
  state.authenticated = session.authenticated === true;
  state.username = String(session.username || "");
  state.userDisplayName = resolveUserDisplayName(session);
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
    state.userDisplayName = resolveUserDisplayName(data);
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
  document.getElementById("refreshButton")?.addEventListener("click", () => {
    void loadAlerts().catch((error) => setStatus("Fehler: " + error.message, true));
  });

  document.querySelectorAll(".filter-chips .chip[data-severity]").forEach((chip) => {
    chip.addEventListener("click", () => {
      state.severity = String(chip.getAttribute("data-severity") || "all");
      syncSeverityChips();
      void loadAlerts().catch((error) => setStatus("Fehler: " + error.message, true));
    });
  });

  document.getElementById("filterMoreButton")?.addEventListener("click", () => openSheet("filterSheet"));
  document.getElementById("filterSheetApply")?.addEventListener("click", () => {
    state.showAck = document.getElementById("showAckToggle")?.checked === true;
    state.showClosed = document.getElementById("showClosedToggle")?.checked === true;
    closeAllSheets();
    void loadAlerts().catch((error) => setStatus("Fehler: " + error.message, true));
  });

  renderCountryFilterChips();

  document.getElementById("pushToggleButton")?.addEventListener("click", () => void togglePush());
  document.getElementById("testPushButton")?.addEventListener("click", () => void sendTestPush());

  document.getElementById("menuToggleButton")?.addEventListener("click", () => {
    document.getElementById("headerMenu")?.classList.toggle("hidden");
  });

  document.getElementById("mobileLogoutButton")?.addEventListener("click", async () => {
    await mobileLogout();
    state.authenticated = false;
    state.username = "";
    state.userDisplayName = "";
    updateUserLine();
    showLoginOverlay(true);
    renderAlerts([]);
    setStatus("");
    renderPushButton();
    document.getElementById("headerMenu")?.classList.add("hidden");
  });

  document.getElementById("mobileLoginSubmit")?.addEventListener("click", () => void submitLogin());
  document.getElementById("mobileLoginPassword")?.addEventListener("keydown", (event) => {
    if (event.key === "Enter") void submitLogin();
  });

  document.getElementById("sheetBackdrop")?.addEventListener("click", closeAllSheets);
  document.querySelectorAll("[data-sheet-close]").forEach((btn) => {
    btn.addEventListener("click", closeAllSheets);
  });

  document.getElementById("ackSheetConfirm")?.addEventListener("click", async () => {
    const id = state.pendingAckAlertId;
    if (!id) return;
    const note = document.getElementById("ackNoteInput")?.value || "";
    closeAllSheets();
    try {
      await callAlertAction("/api/v1/alert-ack", { alert_id: id, ack_note: note }, "Alert quittiert.");
      state.pendingAckAlertId = 0;
      await loadAlerts();
    } catch (error) {
      setStatus("Aktion fehlgeschlagen: " + (error?.message || String(error)), true);
      showToast("Aktion fehlgeschlagen: " + (error?.message || String(error)), true);
    }
  });

  document.getElementById("closeSheetConfirm")?.addEventListener("click", async () => {
    const id = state.pendingCloseAlertId;
    if (!id) return;
    closeAllSheets();
    try {
      await callAlertAction("/api/v1/alert-close", { alert_id: id }, "Alert geschlossen.");
      state.pendingCloseAlertId = 0;
      await loadAlerts();
    } catch (error) {
      setStatus("Aktion fehlgeschlagen: " + (error?.message || String(error)), true);
      showToast("Aktion fehlgeschlagen: " + (error?.message || String(error)), true);
    }
  });

  const alertsList = document.getElementById("alertsList");
  if (alertsList) {
    alertsList.addEventListener("click", (event) => {
      void handleAlertsListClick(event);
    });
    alertsList.addEventListener("keydown", handleAlertsListKeydown);
  }

  wirePullToRefresh();
  syncSeverityChips();
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
