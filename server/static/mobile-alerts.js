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
  stopMobileSessionKeepAlive();
  await fetch("/api/v1/web-logout", {
    method: "POST",
    credentials: "same-origin",
  }).catch(() => {});
}

function stopMobileSessionKeepAlive() {
  if (mobileSessionRefreshTimerId !== null) {
    window.clearInterval(mobileSessionRefreshTimerId);
    mobileSessionRefreshTimerId = null;
  }
}

async function mobileRefreshSession() {
  try {
    const response = await fetch("/api/v1/session/refresh", {
      method: "POST",
      credentials: "same-origin",
    });
    if (!response.ok) {
      if (response.status === 401 && Date.now() - mobileSessionEstablishedAtMs < MOBILE_SESSION_LOGIN_GRACE_MS) {
        return true;
      }
      return false;
    }
    const data = await response.json().catch(() => ({}));
    state.authenticated = true;
    if (data.username) {
      state.username = String(data.username || state.username);
    }
    // Refresh liefert display_name erst ab neuerer Server-Version; ohne Feld den
    // bereits aus /api/v1/session geladenen Anzeigenamen nicht überschreiben.
    if (Object.prototype.hasOwnProperty.call(data, "display_name")) {
      const displayName = String(data.display_name || "").trim();
      state.userDisplayName = displayName || state.username;
      updateUserLine();
    }
    return true;
  } catch (_error) {
    return false;
  }
}

function startMobileSessionKeepAlive() {
  if (!state.authenticated) {
    return;
  }
  stopMobileSessionKeepAlive();
  window.setTimeout(() => {
    if (state.authenticated) {
      void mobileRefreshSession();
    }
  }, 2500);
  mobileSessionRefreshTimerId = window.setInterval(() => {
    void mobileRefreshSession();
  }, MOBILE_SESSION_REFRESH_INTERVAL_MS);
}

async function mobileRecoverSessionAfter401() {
  if (Date.now() - mobileSessionEstablishedAtMs < MOBILE_SESSION_LOGIN_GRACE_MS) {
    return true;
  }
  if (!(await mobileRefreshSession())) {
    return false;
  }
  const session = await mobileFetchSession().catch(() => ({ authenticated: false }));
  if (session.authenticated !== true) {
    return false;
  }
  state.authenticated = true;
  state.username = String(session.username || state.username);
  state.userDisplayName = resolveUserDisplayName(session);
  updateUserLine();
  showLoginOverlay(false);
  startMobileSessionKeepAlive();
  return true;
}

function setInactiveHostsStatus(text, isError = false) {
  const line = document.getElementById("inactiveHostsStatusLine");
  if (!line) return;
  line.textContent = text;
  line.classList.toggle("is-error", isError);
}

function setActiveHostsStatus(text, isError = false) {
  const line = document.getElementById("activeHostsStatusLine");
  if (!line) return;
  line.textContent = text;
  line.classList.toggle("is-error", isError);
}

function isInactiveHostsViewActive() {
  return state.mobileView === "inactive-hosts";
}

function isActiveHostsViewActive() {
  return state.mobileView === "active-hosts";
}

function hideAllMobileSubViews() {
  document.getElementById("alertsHomeView")?.classList.add("hidden");
  document.getElementById("inactiveHostsView")?.classList.add("hidden");
  document.getElementById("activeHostsView")?.classList.add("hidden");
  document.getElementById("addonSearchView")?.classList.add("hidden");
}

function clearMobileKpiNavActive() {
  document.getElementById("kpiInactiveNav")?.classList.remove("is-active");
  document.getElementById("kpiActiveNav")?.classList.remove("is-active");
}

function showAlertsHomeView() {
  state.mobileView = "alerts";
  hideAllMobileSubViews();
  document.getElementById("alertsHomeView")?.classList.remove("hidden");
  clearMobileKpiNavActive();
}

function showInactiveHostsView() {
  state.mobileView = "inactive-hosts";
  hideAllMobileSubViews();
  document.getElementById("inactiveHostsView")?.classList.remove("hidden");
  clearMobileKpiNavActive();
  document.getElementById("kpiInactiveNav")?.classList.add("is-active");
  const hours = Math.max(1, Math.min(24 * 30, Number(state.hostKpisHours) || 1));
  state.inactiveHostsHours = hours;
  const subtitle = document.getElementById("inactiveHostsSubtitle");
  if (subtitle) {
    subtitle.textContent = "Keine Meldung seit " + hours + " Stunde" + (hours === 1 ? "" : "n");
  }
  void loadInactiveHostsList();
}

function showActiveHostsView() {
  state.mobileView = "active-hosts";
  hideAllMobileSubViews();
  document.getElementById("activeHostsView")?.classList.remove("hidden");
  clearMobileKpiNavActive();
  document.getElementById("kpiActiveNav")?.classList.add("is-active");
  const subtitle = document.getElementById("activeHostsSubtitle");
  if (subtitle) {
    subtitle.textContent = "Meldung in der letzten Stunde";
  }
  void loadActiveHostsList();
}

function isAddonSearchViewActive() {
  return state.mobileView === "addon-search";
}

function showAddonSearchView() {
  state.mobileView = "addon-search";
  hideAllMobileSubViews();
  document.getElementById("addonSearchView")?.classList.remove("hidden");
  clearMobileKpiNavActive();
  const input = document.getElementById("addonSearchInput");
  if (input && String(input.value || "") !== String(state.addonSearchQuery || "")) {
    input.value = String(state.addonSearchQuery || "");
  }
  syncAddonSearchGroupChips();
  updateAddonSearchView();
}

function buildCountryFlagIconHtml(countryCode) {
  const code = String(countryCode || "").trim().toUpperCase();
  if (!/^[A-Z]{2}$/.test(code)) return "";
  const lower = code.toLowerCase();
  return (
    '<img src="/icons/' + mobileEsc(code) + '.png" class="inactive-host-icon" alt="' + mobileEsc(code) + '" ' +
    'onerror="if(!this.dataset.f1){this.dataset.f1=\'1\';this.src=\'/icons/' + mobileEsc(lower) + '.png\';return;}if(!this.dataset.f2){this.dataset.f2=\'1\';this.src=\'/icons/' + mobileEsc(lower) + '.svg\';return;}this.style.display=\'none\';" />'
  );
}

function getHostListLabels(host) {
  const hostname = String(host.hostname || "").trim() || "—";
  const displayName = String(host.display_name || "").trim() || hostname;
  const customerName = String(host.customer_name || "").trim();
  const hasCustomer = customerName && customerName !== "-" && customerName !== "--";
  const customerLabel = hasCustomer ? customerName : displayName;
  const hostLabel = hasCustomer ? (displayName !== hostname ? displayName : hostname) : hostname;
  return { hostname, displayName, customerLabel, hostLabel, hasCustomer };
}

function collectHostListCountries(hosts) {
  const codes = new Set();
  (Array.isArray(hosts) ? hosts : []).forEach((host) => {
    const code = String(host.country_code || "").trim().toUpperCase();
    if (/^[A-Z]{2}$/.test(code)) {
      codes.add(code);
    }
  });
  return Array.from(codes).sort();
}

function filterHostListItems(hosts, countryFilter, searchQuery) {
  const country = String(countryFilter || "all").trim().toUpperCase();
  const query = String(searchQuery || "").trim().toLowerCase();
  return (Array.isArray(hosts) ? hosts : []).filter((host) => {
    if (country !== "ALL") {
      const hostCountry = String(host.country_code || "").trim().toUpperCase();
      if (hostCountry !== country) {
        return false;
      }
    }
    if (!query) {
      return true;
    }
    const haystack = [
      host.customer_name,
      host.display_name,
      host.hostname,
      host.host_uid,
      host.country_code,
      host.os,
      host.primary_ip,
      host.std_nic_ip,
    ]
      .join(" ")
      .toLowerCase();
    return haystack.includes(query);
  });
}

function renderHostCountryFilter(containerId, countries, selectedCountry, onSelect) {
  const container = document.getElementById(containerId);
  if (!container) return;
  const selected = String(selectedCountry || "all").trim().toUpperCase();
  const chips = [
    '<button type="button" class="host-country-chip' + (selected === "ALL" ? " active" : "") + '" data-country="all">Alle</button>',
  ];
  countries.forEach((code) => {
    const flag = buildCountryFlagHtml(code);
    chips.push(
      '<button type="button" class="host-country-chip' + (selected === code ? " active" : "") + '" data-country="'
      + mobileEsc(code) + '">' + flag + "<span>" + mobileEsc(code) + "</span></button>"
    );
  });
  container.innerHTML = chips.join("");
  container.querySelectorAll(".host-country-chip[data-country]").forEach((chip) => {
    chip.addEventListener("click", () => {
      onSelect(String(chip.getAttribute("data-country") || "all"));
    });
  });
}

function hostListStatusBadge(host, variant) {
  if (variant === "active") {
    const label = host.online === true ? "Online" : "Aktiv";
    return '<span class="online-status-badge">' + mobileEsc(label) + "</span>";
  }
  const hoursInactive = Number(host.hours_inactive || 0);
  const longInactive = hoursInactive > 12;
  return '<span class="inactive-hours-badge">' + hoursInactive.toFixed(1) + "h inaktiv</span>";
}

function buildHostListDetailFacts(host, variant) {
  const { hostname } = getHostListLabels(host);
  const hostUid = truncateMobileText(String(host.host_uid || hostname), 40);
  const primaryIp = String(host.primary_ip || host.std_nic_ip || "").trim() || "—";
  const osLabel = String(host.os || "").trim() || "—";
  const countryLabel = String(host.country_code || "").trim().toUpperCase() || "—";
  const openAlerts = Math.max(0, Number(host.open_alert_count || 0));
  const openCritical = Math.max(0, Number(host.open_critical_alert_count || 0));

  let alertsFact = "Keine";
  if (openAlerts > 0) {
    alertsFact = '<span class="inactive-alerts-pill">' + openAlerts + " offen</span>";
    if (openCritical > 0) {
      alertsFact += ' <span class="inactive-alerts-pill">' + openCritical + " kritisch</span>";
    }
  }

  const rows = [];
  const push = (label, value) => {
    rows.push(
      "    <div><dt>" + mobileEsc(label) + "</dt><dd>" + value + "</dd></div>"
    );
  };

  if (variant === "inactive") {
    const lastReport = formatUtcPlus2Mobile(host.last_report_time_utc);
    const relative = formatRelativeTime(host.last_report_time_utc);
    push("Letzter Report", mobileEsc(lastReport) + (relative ? " <span>(" + mobileEsc(relative) + ")</span>" : ""));
    push("Inaktiv seit", mobileEsc(Number(host.hours_inactive || 0).toFixed(1) + " Stunden"));
  } else {
    const lastReport = formatUtcPlus2Mobile(host.last_seen_utc);
    const relative = formatRelativeTime(host.last_seen_utc);
    push("Letzter Report", mobileEsc(lastReport) + (relative ? " <span>(" + mobileEsc(relative) + ")</span>" : ""));
    const envLabel = mobileEnvironmentLabel(host.environment_type);
    if (envLabel) push("Umgebung", mobileEsc(envLabel));
    push("Agent-Version", mobileEsc(String(host.agent_version || "").trim() || "—"));
    push("Reports (DB)", String(Math.max(0, Number(host.report_count || 0))));
  }

  push("Hostname", mobileEsc(hostname));
  push("Betriebssystem", mobileEsc(osLabel));
  push("IP", mobileEsc(primaryIp));
  push("Land", mobileEsc(countryLabel));
  push("Offene Alerts", alertsFact);
  push("Host-ID", "<code>" + mobileEsc(hostUid) + "</code>");

  return rows.join("\n");
}

function renderHostListCard(host, variant, index) {
  const { customerLabel, hostLabel } = getHostListLabels(host);
  const osIcon = resolveHostOsIconMobile(host.os);
  const countryHtml = buildCountryFlagIconHtml(host.country_code);
  const countryCode = String(host.country_code || "").trim().toUpperCase() || "—";
  const osLabel = String(host.os || "").trim() || "—";
  const longInactive = variant === "inactive" && Number(host.hours_inactive || 0) > 12;
  const cardClass =
    "host-list-card inactive-host-card"
    + (variant === "active" ? " is-active-host" : "")
    + (longInactive ? " is-long-inactive" : "");

  return (
    '<details class="' + cardClass + '">' +
    '  <summary class="host-list-summary">' +
    '    <div class="host-list-summary-main">' +
    '      <p class="host-list-customer">' + mobileEsc(customerLabel) + "</p>" +
    '      <p class="host-list-host-label">' + mobileEsc(hostLabel) + buildAgentVersionBadgeHtml(host.agent_version) + "</p>" +
    '      <div class="host-list-meta-row">' +
    '        <span class="host-list-meta-pill host-list-meta-pill-country">' + countryHtml + "<span>" + mobileEsc(countryCode) + "</span></span>" +
    '        <span class="host-list-meta-pill host-list-meta-pill-os"><img src="/icons/' + mobileEsc(osIcon) + '" alt="" onerror="this.src=\'/icons/linux.png\'" /><span>'
    + mobileEsc(osLabel) + "</span></span>" +
    "      </div>" +
    "    </div>" +
    '    <div class="host-list-summary-side">' +
    hostListStatusBadge(host, variant) +
    '      <span class="host-list-chevron" aria-hidden="true">▾</span>' +
    "    </div>" +
    "  </summary>" +
    '  <div class="host-list-details-body">' +
    '    <dl class="inactive-host-facts">' +
    buildHostListDetailFacts(host, variant) +
    "    </dl>" +
    (variant === "active"
      ? '<div class="host-list-actions">' +
        '  <button type="button" class="btn-secondary btn-host-list-sheet" data-action="sys-overview" data-host-list="active" data-host-index="' + index + '">Systemübersicht</button>' +
        '  <button type="button" class="btn-secondary btn-host-list-sheet" data-action="host-list-sheet" data-host-list="active" data-host-index="' + index + '">Einzelmeldungen</button>' +
        "</div>"
      : '<button type="button" class="btn-secondary btn-host-list-sheet" data-action="host-list-sheet" data-host-list="'
        + mobileEsc(variant) + '" data-host-index="' + index + '">Einzelmeldungen</button>') +
    "  </div>" +
    "</details>"
  );
}

function openMobileHostListSheet(host, variant) {
  if (!host) return;
  const { hostname, displayName, customerLabel } = getHostListLabels(host);
  const titleEl = document.getElementById("hostSheetTitle");
  const subtitleEl = document.getElementById("hostSheetSubtitle");
  const factsEl = document.getElementById("hostSheetFacts");
  const logoEl = document.getElementById("hostSheetLogo");

  if (titleEl) titleEl.textContent = customerLabel;
  if (subtitleEl) subtitleEl.textContent = hostname !== displayName ? hostname : String(host.host_uid || "").trim();

  const logoUrl = String(host.customer_logo_url || "").trim();
  if (logoEl) {
    if (logoUrl) {
      logoEl.src = logoUrl;
      logoEl.classList.remove("hidden");
      logoEl.onerror = () => logoEl.classList.add("hidden");
    } else {
      logoEl.removeAttribute("src");
      logoEl.classList.add("hidden");
    }
  }

  const rows = [];
  const push = (label, value) => {
    const text = String(value || "").trim();
    if (text) rows.push(hostSheetFactRow(label, text));
  };

  if (variant === "inactive") {
    push("Letzter Report", formatUtcPlus2Mobile(host.last_report_time_utc));
    push("Relativ", formatRelativeTime(host.last_report_time_utc));
    push("Inaktiv seit", Number(host.hours_inactive || 0).toFixed(1) + " h");
  } else {
    push("Letzter Report", formatUtcPlus2Mobile(host.last_seen_utc));
    push("Relativ", formatRelativeTime(host.last_seen_utc));
    push("Status", host.online === true ? "Online" : "Aktiv");
    push("Umgebung", mobileEnvironmentLabel(host.environment_type));
    push("Agent-Version", host.agent_version);
    push("Reports (DB)", String(host.report_count || 0));
  }

  push("Hostbezeichnung", displayName);
  push("Hostname", hostname);
  push("Host-ID", host.host_uid);
  push("Kunde", host.customer_name);
  push("Land", host.country_code);
  push("Betriebssystem", host.os);
  push("IP", host.primary_ip || host.std_nic_ip);
  push("Offene Alerts", host.open_alert_count > 0 ? String(host.open_alert_count) : "");

  if (factsEl) factsEl.innerHTML = rows.join("");
  openSheet("hostSheet");
}

const HOST_INSIGHT_SLIDE_DEFS = [
  { id: "system", icon: "🖥️", title: "System", short: "System" },
  { id: "journal", icon: "📰", title: "Journal", short: "Journal" },
  { id: "processes", icon: "⚡", title: "User / Prozesse", short: "Prozesse" },
  { id: "logfiles", icon: "📜", title: "Logfiles", short: "Logfiles" },
  { id: "sap-b1", icon: "📦", title: "SAP B1", short: "SAP B1" },
  { id: "containers", icon: "🐳", title: "Container", short: "Container" },
  { id: "export", icon: "📤", title: "Export", short: "Export" },
  { id: "agent", icon: "🤖", title: "Agent", short: "Agent" },
  { id: "network", icon: "🌐", title: "Netzwerk", short: "Netzwerk" },
  { id: "filesystems", icon: "💾", title: "Filesysteme", short: "FS" },
  { id: "databases", icon: "🗄️", title: "Datenbanken", short: "DB" },
];

let hostInsightScrollRaf = 0;

function mobileFormatPercent(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n.toFixed(1) + "%" : "—";
}

function mobileFormatKb(kbValue) {
  const kb = Number(kbValue);
  if (!Number.isFinite(kb) || kb < 0) return "—";
  const mib = kb / 1024;
  if (mib < 1024) return mib.toFixed(0) + " MiB";
  return (mib / 1024).toFixed(2) + " GiB";
}

function mobileMetricBarFillClass(percent) {
  const n = Number(percent);
  if (!Number.isFinite(n)) return "metric-bar-fill--low";
  if (n >= 85) return "metric-bar-fill--high";
  if (n >= 65) return "metric-bar-fill--mid";
  return "metric-bar-fill--low";
}

function mobileMetricBarRow(label, percent, sublineHtml) {
  const numeric = Number(percent);
  const width = Number.isFinite(numeric) ? Math.min(100, Math.max(0, numeric)) : 0;
  const fillClass = mobileMetricBarFillClass(numeric);
  const sub = String(sublineHtml || "").trim()
    ? '<div class="insight-metric-sub">' + sublineHtml + "</div>"
    : "";
  return (
    '<div class="insight-metric-bar">' +
    '<div class="insight-metric-head"><span>' + mobileEsc(label) + "</span><span>" + mobileEsc(mobileFormatPercent(numeric)) + "</span></div>" +
    '<div class="insight-metric-track"><div class="insight-metric-fill ' + fillClass + '" style="width:' + width + '%"></div></div>' +
    sub +
    "</div>"
  );
}

function mobileInsightFactRow(label, value) {
  const text = String(value || "").trim();
  if (!text) return "";
  return (
    '<div class="insight-fact-row"><dt>' + mobileEsc(label) + "</dt><dd>" + text + "</dd></div>"
  );
}

function mobileInsightKpi(label, value) {
  return (
    '<div class="insight-kpi">' +
    '<span class="insight-kpi-label">' + mobileEsc(label) + "</span>" +
    '<strong class="insight-kpi-value">' + mobileEsc(String(value || "").trim() || "—") + "</strong>" +
    "</div>"
  );
}

function insightSlideFooter(reportLabel) {
  return (
    '<footer class="host-insight-slide-footer">' +
    '<span class="host-insight-report-time">Letzter Report: ' + mobileEsc(reportLabel || "—") + "</span>" +
    "</footer>"
  );
}

function wrapInsightSlide(icon, title, bodyHtml, reportLabel) {
  return (
    '<article class="host-insight-slide" data-slide-title="' + mobileEsc(title) + '">' +
    '<div class="host-insight-slide-head"><span class="host-insight-slide-icon" aria-hidden="true">' + icon + "</span><h4>" + mobileEsc(title) + "</h4></div>" +
    '<div class="host-insight-slide-body">' + bodyHtml + "</div>" +
    insightSlideFooter(reportLabel) +
    "</article>"
  );
}

function resolveInsightReportLabel(report, payload, host, variant) {
  const fromReport = formatUtcPlus2Mobile(report?.received_at_utc || payload?.timestamp_utc || "");
  if (fromReport && fromReport !== "—") return fromReport;
  if (variant === "inactive") {
    return formatUtcPlus2Mobile(host?.last_report_time_utc || "");
  }
  return formatUtcPlus2Mobile(host?.last_seen_utc || host?.last_report_time_utc || "");
}

function parseAngLogsBlockMobile(raw) {
  if (raw === null || raw === undefined) return null;
  if (typeof raw === "string") {
    const trimmed = raw.trim();
    if (!trimmed) return null;
    try {
      const parsed = JSON.parse(trimmed);
      return parsed && typeof parsed === "object" ? parsed : null;
    } catch (_error) {
      return null;
    }
  }
  if (typeof raw === "object") return raw;
  return null;
}

function getAngLogsFromPayloadMobile(payload) {
  const p = payload && typeof payload === "object" ? payload : {};
  return parseAngLogsBlockMobile(p.ang_logs) || parseAngLogsBlockMobile(p.ang_skripte_logs);
}

const MOBILE_ANG_LOG_LINE_SPLIT_PATTERNS = [
  /(?=\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?\s)/,
  /(?=\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?\])/,
  /(?=\[\d{2}\.\d{2}\.\d{4} \d{2}:\d{2}(?::\d{2})?(?:[.,]\d{1,6})?\])/,
];

function repairUtf8MojibakeLatin1Mobile(text) {
  const raw = String(text ?? "");
  if (!raw || !/Ã.|â€/.test(raw)) return raw;
  try {
    const bytes = new Uint8Array(raw.length);
    for (let index = 0; index < raw.length; index += 1) {
      bytes[index] = raw.charCodeAt(index) & 0xff;
    }
    const repaired = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    if (repaired && repaired !== raw && !/Ã.|â€/.test(repaired)) return repaired;
  } catch (_error) {
    // keep original
  }
  return raw;
}

function asLogLineTextMobile(value) {
  if (value === null || value === undefined) return "";
  return repairUtf8MojibakeLatin1Mobile(String(value));
}

function looksLikeAngLogJsonLineMobile(line) {
  const trimmed = String(line || "").trim();
  if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return false;
  if (/^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}/.test(trimmed) || /^\[\d{2}\.\d{2}\.\d{4} \d{2}:\d{2}/.test(trimmed)) {
    return false;
  }
  return trimmed.startsWith("{") || trimmed.startsWith("[{") || trimmed.startsWith('["') || trimmed.startsWith("[\n");
}

function shouldSplitAngLogLogicalLineMobile(line) {
  const trimmed = asLogLineTextMobile(line).trim();
  if (!trimmed) return false;
  if (looksLikeAngLogJsonLineMobile(trimmed)) return false;
  return true;
}

function splitAngLogLogicalLineMobile(line) {
  const trimmed = asLogLineTextMobile(line).trim();
  if (!trimmed) return [];
  if (!shouldSplitAngLogLogicalLineMobile(trimmed)) return [trimmed];

  let parts = [trimmed];
  for (const pattern of MOBILE_ANG_LOG_LINE_SPLIT_PATTERNS) {
    const next = [];
    for (const part of parts) {
      const chunks = part
        .split(pattern)
        .map((chunk) => chunk.replace(/^\s+/, "").trimEnd())
        .filter((chunk) => chunk.length > 0);
      if (chunks.length > 1) next.push(...chunks);
      else if (part) next.push(part);
    }
    if (next.length > 1) parts = next;
  }
  return parts.length > 0 ? parts : [trimmed];
}

function normalizeAngSkripteLogLinesMobile(rawLines) {
  if (Array.isArray(rawLines)) {
    return rawLines.map((line) => asLogLineTextMobile(line));
  }
  if (typeof rawLines === "string") {
    const trimmed = rawLines.trim();
    if (!trimmed) return [];
    if (trimmed.startsWith("[")) {
      try {
        const parsed = JSON.parse(trimmed);
        if (Array.isArray(parsed)) {
          return parsed.map((line) => asLogLineTextMobile(line));
        }
      } catch (_error) {
        // plain-text split
      }
    }
    return trimmed.split(/\r\n|\n|\r/).map((line) => asLogLineTextMobile(line));
  }
  return [];
}

function expandAngSkripteLogLinesMobile(rawLines) {
  const normalized = normalizeAngSkripteLogLinesMobile(rawLines);
  if (!normalized.length) return [];

  const expanded = [];
  for (const line of normalized) {
    const logicalLines = splitAngLogLogicalLineMobile(line);
    if (logicalLines.length > 1) {
      expanded.push(...logicalLines);
      continue;
    }
    if (line.includes("\n") || line.includes("\r")) {
      expanded.push(
        ...line
          .split(/\r\n|\n|\r/)
          .map((entry) => asLogLineTextMobile(entry))
          .filter((entry) => entry.length > 0)
      );
      continue;
    }
    if (line) expanded.push(line);
  }
  return expanded.length > 0 ? expanded : normalized;
}

function takeLastLogLinesMobile(rawLines, maxLines) {
  const limit = Math.max(1, Number(maxLines) || 50);
  const expanded = expandAngSkripteLogLinesMobile(rawLines);
  if (expanded.length <= limit) return expanded;
  return expanded.slice(-limit);
}

function mobileFormatTerminalOutputLine(line) {
  if (!line) return "";
  if (/^\s*#/.test(line)) {
    return '<span class="terminal-token-comment">' + mobileEsc(line) + "</span>";
  }
  const trimmed = String(line).trim();
  if (/^\[[^\]]+\]$/.test(trimmed)) {
    const leadingWhitespace = String(line).match(/^\s*/)?.[0] || "";
    return mobileEsc(leadingWhitespace) + '<span class="terminal-token-heading">' + mobileEsc(trimmed) + "</span>";
  }
  const keyValueMatch = String(line).match(/^(\s*)([A-Z][A-Z0-9_ ]*)(=)(.*)$/);
  if (keyValueMatch) {
    const leadingWhitespace = keyValueMatch[1] || "";
    const key = keyValueMatch[2] || "";
    const separator = keyValueMatch[3] || "";
    const rawValue = keyValueMatch[4] || "";
    return (
      mobileEsc(leadingWhitespace) +
      '<span class="terminal-token-field">' + mobileEsc(key.trimEnd()) + "</span>" +
      '<span class="terminal-token-separator">' + mobileEsc(separator) + "</span>" +
      mobileFormatTerminalInline(rawValue)
    );
  }
  return mobileFormatTerminalInline(line);
}

function mobileRenderTerminalToken(token) {
  const value = String(token || "");
  const upperValue = value.toUpperCase();
  let className = "terminal-token-muted";

  if (/^\[[^\]]+\]$/.test(value)) {
    className = "terminal-token-heading";
  } else if (/^(PATH|STATUS|SIZE|VERSION|SID|BRANCH|BUILD|FEATURE_PACK|PATCH_LEVEL|RELEASE|ERROR|MESSAGE)$/i.test(value)) {
    className = "terminal-token-field";
  } else if (/^(SAP|HANA|SQL|SARI|CATALINA|BUSINESSONE|BUSINESS_ONE)$/i.test(value)) {
    className = "terminal-token-system";
  } else if (/^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}Z)?$/i.test(value)) {
    className = "terminal-token-date";
  } else if (/^\d+(?:\.\d+)?%$/i.test(value)) {
    className = "terminal-token-metric";
  } else if (/^(ERROR|ERR|WARN(?:ING)?|FAIL(?:ED)?|CRIT(?:ICAL)?|FATAL|MISSING|UNAVAILABLE|DISABLED|INACTIVE|ABSENT|NOT_FOUND|FALSE|NO|NEIN)$/i.test(value)) {
    className = upperValue.startsWith("WARN") ? "terminal-token-warn" : "terminal-token-bad";
  } else if (/^(OK|SUCCESS|DONE|RUNNING|AVAILABLE|ENABLED|ACTIVE|PRESENT|TRUE|YES|JA)$/i.test(value)) {
    className = "terminal-token-good";
  } else if (/^(INFO|DEBUG|TRACE|NOTICE)$/i.test(value)) {
    className = "terminal-token-info";
  } else if (/^[A-Z][A-Z0-9_]{2,}$/.test(value)) {
    className = "terminal-token-key";
  } else if (/^\d+(?:\.\d+){1,}$/.test(value)) {
    className = "terminal-token-version";
  } else if (/^\d+(?:KB|MB|GB|TB|PB)$/i.test(value)) {
    className = "terminal-token-size";
  } else if (/^(?:[A-Za-z]:\\|\/)/.test(value)) {
    className = "terminal-token-path";
  }

  return '<span class="' + className + '">' + mobileEsc(value) + "</span>";
}

function mobileFormatTerminalInline(text) {
  const source = String(text ?? "");
  const tokenRe =
    /(\b\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}Z)?\b|\b\d+(?:\.\d+)?%\b|\b(?:ERROR|ERR|WARN(?:ING)?|FAIL(?:ED)?|CRIT(?:ICAL)?|FATAL|MISSING|UNAVAILABLE|DISABLED|INACTIVE|ABSENT|NOT_FOUND)\b|\b(?:OK|SUCCESS|DONE|RUNNING|AVAILABLE|ENABLED|ACTIVE|PRESENT)\b|\b(?:INFO|DEBUG|TRACE|NOTICE)\b|\b(?:TRUE|FALSE|YES|NO|JA|NEIN)\b|\b(?:SAP|HANA|SQL|SARI|CATALINA|BUSINESSONE|BUSINESS_ONE|FEATURE_PACK|PATCH_LEVEL|SID|BRANCH|BUILD|RELEASE|VERSION|STATUS|PATH|SIZE|ERROR|MESSAGE)\b|\b[A-Z][A-Z0-9_]{2,}(?==)|\b\d+(?:\.\d+){1,}\b|\b\d+(?:KB|MB|GB|TB|PB)\b|(?:[A-Za-z]:\\[^\s]+|\/[^\s]+))/gi;
  let result = "";
  let lastIndex = 0;
  let match;
  while ((match = tokenRe.exec(source)) !== null) {
    const token = match[0];
    result += mobileEsc(source.slice(lastIndex, match.index));
    result += mobileRenderTerminalToken(token);
    lastIndex = match.index + token.length;
  }
  result += mobileEsc(source.slice(lastIndex));
  return result;
}

function mobileRenderLogfileLinesHtml(lines) {
  const expanded = Array.isArray(lines) ? lines : [];
  if (!expanded.length) {
    return '<div class="log-line log-line--empty">(leer)</div>';
  }
  return expanded
    .map((line) => {
      const html = line ? mobileFormatTerminalOutputLine(line) : "&nbsp;";
      const extraClass = line ? "" : " log-line--empty";
      return '<div class="log-line' + extraClass + '">' + html + "</div>";
    })
    .join("");
}

function mobileFormatUptime(seconds) {
  const s = Number(seconds);
  if (!Number.isFinite(s) || s < 0) return "—";
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return d + " T " + h + " h";
  if (h > 0) return h + " h " + m + " min";
  return m + " min";
}

let mobileSapB1VersionMap = null;

function getDefaultMobileSapB1VersionMap() {
  return new Map([
    ["10.00.330", { featurePack: "FP 2605", patchLevel: "PL 23", releaseDate: "May 2026" }],
    ["10.00.320", { featurePack: "FP 2602", patchLevel: "PL 22", releaseDate: "Feb 2026" }],
    ["10.00.310", { featurePack: "FP 2511", patchLevel: "PL 21", releaseDate: "Nov 2025" }],
    ["10.00.300", { featurePack: "FP 2508", patchLevel: "PL 20", releaseDate: "Aug 2025" }],
    ["10.00.291", { featurePack: "FP 2505 HF1", patchLevel: "PL 19", releaseDate: "Jun 2025" }],
    ["10.00.290", { featurePack: "FP 2505", patchLevel: "PL 19", releaseDate: "May 2025" }],
    ["10.00.280", { featurePack: "FP 2502", patchLevel: "PL 18", releaseDate: "Feb 2025" }],
    ["10.00.270", { featurePack: "FP 2411", patchLevel: "PL 17", releaseDate: "Nov 2024" }],
    ["10.00.261", { featurePack: "FP 2408 HF1", patchLevel: "PL 16 HF1", releaseDate: "Okt 2024" }],
    ["10.00.260", { featurePack: "FP 2408", patchLevel: "PL 16", releaseDate: "Aug 2024" }],
    ["10.00.250", { featurePack: "FP 2405", patchLevel: "PL 15", releaseDate: "May 2024" }],
    ["10.00.240", { featurePack: "FP 2402", patchLevel: "PL 14", releaseDate: "Feb 2024" }],
    ["10.00.230", { featurePack: "FP 2311", patchLevel: "PL 13", releaseDate: "Nov 2023" }],
    ["10.00.220", { featurePack: "FP 2308", patchLevel: "PL 12", releaseDate: "Aug 2023" }],
    ["10.00.210", { featurePack: "FP 2305", patchLevel: "PL 11", releaseDate: "May 2023" }],
    ["10.00.180", { featurePack: "FP 2208", patchLevel: "PL 08", releaseDate: "Aug 2022" }],
    ["10.00.170", { featurePack: "FP 2205", patchLevel: "PL 07", releaseDate: "May 2022" }],
    ["10.00.160", { featurePack: "FP 2202", patchLevel: "PL 06", releaseDate: "Feb 2022" }],
    ["10.00.150", { featurePack: "FP 2111", patchLevel: "PL 05", releaseDate: "Nov 2021" }],
    ["10.00.140", { featurePack: "FP 2108", patchLevel: "PL 04", releaseDate: "Aug 2021" }],
    ["10.00.130", { featurePack: "FP 2105", patchLevel: "PL 03", releaseDate: "May 2021" }],
    ["10.00.120", { featurePack: "FP 2102", patchLevel: "PL 02", releaseDate: "Feb 2021" }],
    ["10.00.110", { featurePack: "FP 2008", patchLevel: "PL 01", releaseDate: "Aug 2020" }],
    ["10.00.100", { featurePack: "FP 2005", patchLevel: "PL 00", releaseDate: "May 2020" }],
  ]);
}

function getMobileSapB1VersionMap() {
  if (!mobileSapB1VersionMap) {
    mobileSapB1VersionMap = getDefaultMobileSapB1VersionMap();
  }
  return mobileSapB1VersionMap;
}

async function loadMobileSapB1VersionMap() {
  try {
    const resp = await fetch("/api/v1/sap-b1-version-map", { credentials: "same-origin" });
    if (!resp.ok) return;
    const contentType = String(resp.headers.get("content-type") || "").toLowerCase();
    if (!contentType.includes("application/json")) return;
    const data = await resp.json().catch(() => ({}));
    if (!Array.isArray(data.entries)) return;
    mobileSapB1VersionMap = new Map(
      data.entries
        .map((entry) => {
          const build = String(entry.build || "").trim();
          if (!build) return null;
          return [
            build,
            {
              featurePack: String(entry.feature_pack || "").trim(),
              patchLevel: String(entry.patch_level || "").trim(),
              releaseDate: String(entry.release_date || "").trim(),
            },
          ];
        })
        .filter(Boolean)
    );
  } catch (_error) {
    // Built-in map bleibt aktiv.
  }
}

function resolveSapReleaseRawMobile(host, payload) {
  const p = payload && typeof payload === "object" ? payload : {};
  const h = host && typeof host === "object" ? host : {};
  const versionBlock =
    p.sap_business_one &&
    typeof p.sap_business_one === "object" &&
    p.sap_business_one.server_components_version &&
    typeof p.sap_business_one.server_components_version === "object"
      ? p.sap_business_one.server_components_version
      : null;
  const fromPayloadVersion = String(versionBlock?.version || "").trim();
  return String(
    fromPayloadVersion ||
      p.sap_release ||
      p.sap_feature_pack ||
      h.sap_release ||
      h.sap_feature_pack ||
      ""
  ).trim();
}

function resolveSapReleaseDisplayMobile(sapRelease) {
  const raw = String(sapRelease || "").trim();
  if (!raw) return "";
  if (/^(FP|SP)\s*\S/i.test(raw)) {
    return raw;
  }

  const map = getMobileSapB1VersionMap();
  const buildMatch = raw.match(/(10\.00\.\d{3})/i);
  const buildKey = buildMatch ? buildMatch[1] : raw.match(/\d+\.\d+\.\d+/)?.[0] || raw;
  const mapping = map.get(buildKey);
  if (mapping?.featurePack) {
    return String(mapping.featurePack).trim();
  }
  return raw;
}

function resolveHanaReleaseMobile(host, payload) {
  const p = payload && typeof payload === "object" ? payload : {};
  const h = host && typeof host === "object" ? host : {};
  const hi = p.hana_info && typeof p.hana_info === "object" ? p.hana_info : null;
  const raw = String(
    p.hana_release || p.hana_version || (hi?.available ? hi.version : "") || h.hana_release || h.hana_version || ""
  ).trim();
  if (!raw) return "";
  const parts = raw.split(".");
  return parts.length >= 3 ? parts.slice(0, 3).join(".") : raw;
}

function resolveHanaSidMobile(host, payload) {
  const p = payload && typeof payload === "object" ? payload : {};
  const h = host && typeof host === "object" ? host : {};
  const hi = p.hana_info && typeof p.hana_info === "object" ? p.hana_info : null;
  return String(p.hana_sid || (hi?.available ? hi.sid : "") || h.hana_sid || "").trim();
}

function buildInsightOverviewBody(host, variant) {
  const { hostname, displayName, customerLabel } = getHostListLabels(host);
  const envLabel = mobileEnvironmentLabel(host.environment_type);
  const primaryIp = String(host.primary_ip || host.std_nic_ip || "").trim() || "—";
  const country = String(host.country_code || "").trim().toUpperCase() || "—";
  const osLabel = String(host.os || "").trim() || "—";
  const alerts = Number(host.open_alert_count || 0);
  const rows = [
    mobileInsightFactRow("Kunde", mobileEsc(customerLabel)),
    mobileInsightFactRow("Hostbezeichnung", mobileEsc(displayName)),
    mobileInsightFactRow("Hostname", mobileEsc(hostname)),
    mobileInsightFactRow("IP", mobileEsc(primaryIp)),
    mobileInsightFactRow("Land", mobileEsc(country)),
    mobileInsightFactRow("Betriebssystem", mobileEsc(osLabel)),
  ];
  if (envLabel) rows.push(mobileInsightFactRow("Umgebung", mobileEsc(envLabel)));
  rows.push(mobileInsightFactRow("Offene Alerts", alerts > 0 ? mobileEsc(String(alerts)) : mobileEsc("keine")));
  if (variant === "inactive") {
    rows.push(
      mobileInsightFactRow("Inaktiv seit", mobileEsc(Number(host.hours_inactive || 0).toFixed(1) + " h")),
      mobileInsightFactRow(
        "Relativ",
        mobileEsc(formatRelativeTime(host.last_report_time_utc) || "—")
      )
    );
  } else {
    rows.push(
      mobileInsightFactRow("Status", mobileEsc(host.online === true ? "Online" : "Aktiv")),
      mobileInsightFactRow("Agent", mobileEsc(String(host.agent_version || "").trim() || "—") + buildAgentVersionBadgeHtml(host.agent_version)),
      mobileInsightFactRow("Reports (DB)", mobileEsc(String(Math.max(0, Number(host.report_count || 0)))))
    );
  }
  rows.push(mobileInsightFactRow("Host-ID", "<code>" + mobileEsc(String(host.host_uid || "").trim()) + "</code>"));
  return '<dl class="insight-facts">' + rows.filter(Boolean).join("") + "</dl>";
}

function buildInsightResourcesBody(payload) {
  const p = payload && typeof payload === "object" ? payload : {};
  const cpu = p.cpu && typeof p.cpu === "object" ? p.cpu : {};
  const memory = p.memory && typeof p.memory === "object" ? p.memory : {};
  const swap = p.swap && typeof p.swap === "object" ? p.swap : {};
  if (!Object.keys(cpu).length && !Object.keys(memory).length) {
    return '<p class="insight-empty">Keine Ressourcen-Daten im letzten Report.</p>';
  }
  const loadLine =
    "load " +
    [cpu.load_avg_1, cpu.load_avg_5, cpu.load_avg_15]
      .map((v) => (Number.isFinite(Number(v)) ? Number(v).toFixed(2) : "—"))
      .join(" / ");
  const ramSub = mobileFormatKb(memory.used_kb) + " / " + mobileFormatKb(memory.total_kb);
  const cores = Number(cpu.cores);
  const model = String(cpu.model_name || cpu.model || "").trim() || "—";
  const coresModel = (Number.isFinite(cores) && cores > 0 ? String(Math.floor(cores)) : "—") + " · " + model;
  return (
    mobileMetricBarRow("CPU", cpu.usage_percent, "<span>Load Ø</span><span>" + mobileEsc(loadLine) + "</span>") +
    mobileMetricBarRow("RAM", memory.used_percent, "<span>Belegung</span><span>" + mobileEsc(ramSub) + "</span>") +
    mobileMetricBarRow("SWAP", swap.used_percent, "<span>Kerne / Modell</span><span>" + mobileEsc(coresModel) + "</span>")
  );
}

function buildInsightSapBody(host, payload) {
  const sapRaw = resolveSapReleaseRawMobile(host, payload);
  const sap = resolveSapReleaseDisplayMobile(sapRaw) || "—";
  const hana = resolveHanaReleaseMobile(host, payload) || "—";
  const sid = resolveHanaSidMobile(host, payload) || "—";
  const sapHint =
    sapRaw && sap !== sapRaw
      ? '<p class="insight-hint">Build im Report: ' + mobileEsc(sapRaw) + "</p>"
      : '<p class="insight-hint">SAP Release aus Mapping-Tabelle (FP/SP), HANA/SID aus letztem Report.</p>';
  return (
    '<div class="insight-kpi-grid">' +
    mobileInsightKpi("SAP Release", sap) +
    mobileInsightKpi("HANA Release", hana) +
    mobileInsightKpi("HANA SID", sid) +
    "</div>" +
    sapHint
  );
}

function buildInsightFilesystemsBody(payload) {
  const list = Array.isArray(payload?.filesystems) ? payload.filesystems.slice() : [];
  if (!list.length) {
    return '<p class="insight-empty">Keine Dateisystem-Daten im letzten Report.</p>';
  }
  list.sort((a, b) => Number(b?.used_percent || 0) - Number(a?.used_percent || 0));
  const top = list.slice(0, 20);
  const rows = top
    .map((fs) => {
      const mount = String(fs.mountpoint || fs.fs || "—").trim();
      const pct = Number(fs.used_percent);
      const width = Number.isFinite(pct) ? Math.min(100, Math.max(0, pct)) : 0;
      const fillClass = mobileMetricBarFillClass(pct);
      const used = mobileFormatKb(fs.used);
      const total = mobileFormatKb(fs.blocks);
      return (
        '<div class="insight-fs-row">' +
        '<div class="insight-fs-head"><span class="insight-fs-mount">' + mobileEsc(mount) + "</span>" +
        '<span class="insight-fs-pct">' + mobileEsc(Number.isFinite(pct) ? pct.toFixed(1) + "%" : "—") + "</span></div>" +
        '<div class="insight-metric-track"><div class="insight-metric-fill ' + fillClass + '" style="width:' + width + '%"></div></div>' +
        '<p class="insight-fs-sub">' + mobileEsc(used) + " / " + mobileEsc(total) + "</p>" +
        "</div>"
      );
    })
    .join("");
  const more = list.length > top.length ? '<p class="insight-hint">+' + (list.length - top.length) + " weitere Mounts im Desktop-Report.</p>" : "";
  return rows + more;
}

function mobileFormatReportDateTime(value) {
  const text = String(value || "").trim();
  if (!text) return "—";
  const parsed = new Date(text);
  if (Number.isNaN(parsed.getTime())) return text;
  const parts = Object.fromEntries(
    new Intl.DateTimeFormat("de-CH", {
      timeZone: "Europe/Zurich",
      day: "2-digit",
      month: "2-digit",
      year: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    })
      .formatToParts(parsed)
      .map((part) => [part.type, part.value]),
  );
  return parts.day + "." + parts.month + "." + parts.year + " " + parts.hour + ":" + parts.minute;
}

function buildInsightProcessesBody(payload) {
  const block = payload?.top_processes && typeof payload.top_processes === "object" ? payload.top_processes : {};
  const entries = Array.isArray(block.entries) ? block.entries.slice(0, 15) : [];
  const sessionBlock = payload?.user_sessions && typeof payload.user_sessions === "object" ? payload.user_sessions : {};
  const sessionEntries = Array.isArray(sessionBlock.entries) ? sessionBlock.entries.slice(0, 10) : [];
  let html = "";
  if (sessionEntries.length) {
    const sessionRows = sessionEntries.map((entry) => {
      const username = String(entry.username || "—").trim();
      const state = String(entry.state || "—").trim();
      const sessionType = String(entry.session_type || "—").trim();
      const logon = mobileFormatReportDateTime(entry.logon_time_utc);
      return (
        '<li class="insight-process-item">' +
        '<div class="insight-process-head">' +
        '<span class="insight-process-stats">' + mobileEsc(username) + "</span>" +
        '<span class="insight-process-stats">' + mobileEsc(state) + " · " + mobileEsc(sessionType) + "</span>" +
        "</div>" +
        '<span class="insight-process-cmd">' + mobileEsc(logon) + "</span>" +
        "</li>"
      );
    });
    html += '<p class="insight-hint">Usersessions</p><ul class="insight-process-list">' + sessionRows.join("") + "</ul>";
  }
  if (!entries.length) {
    html += '<p class="insight-empty">Keine Prozessdaten im letzten Report.</p>';
  } else {
    const rows = entries.map((entry) => {
      const cmd = String(entry.command || entry.name || "—").trim();
      const pid = Number(entry.pid);
      const user = String(entry.user || "—").trim();
      const cpu = Number(entry.cpu_percent);
      const mem = Number(entry.memory_percent);
      const rssKb = Number(entry.rss_kb);
      const left = (Number.isFinite(pid) && pid > 0 ? String(pid) : "—") + " · " + user;
      const right =
        (Number.isFinite(cpu) ? cpu.toFixed(1) + "% CPU" : "—") +
        " · " +
        (Number.isFinite(mem) ? mem.toFixed(1) + "% RAM" : "—") +
        (Number.isFinite(rssKb) ? " · " + mobileFormatKb(rssKb) : "");
      return (
        '<li class="insight-process-item">' +
        '<div class="insight-process-head">' +
        '<span class="insight-process-stats">' + mobileEsc(left) + "</span>" +
        '<span class="insight-process-stats">' + mobileEsc(right) + "</span>" +
        "</div>" +
        '<span class="insight-process-cmd" title="' + mobileEsc(cmd) + '">' + mobileEsc(cmd) + "</span>" +
        "</li>"
      );
    });
    html += '<p class="insight-hint">Sortiert nach CPU-Auslastung</p><ul class="insight-process-list">' + rows.join("") + "</ul>";
  }
  return html;
}

function buildInsightLogsBody(payload) {
  const angLogs = getAngLogsFromPayloadMobile(payload);
  if (
    !angLogs ||
    (angLogs.available !== true && !(Array.isArray(angLogs.files) && angLogs.files.length))
  ) {
    return '<p class="insight-empty">Keine Logfile-Daten im letzten Report (Windows: *.log unter C:\\ang).</p>';
  }
  const files = Array.isArray(angLogs.files) ? angLogs.files.slice(0, 5) : [];
  if (!files.length) {
    return '<p class="insight-empty">Keine .log-Dateien im letzten Report gefunden.</p>';
  }
  return files
    .map((file) => {
      const name = String(file.relative_path || file.name || "Log").trim();
      const allLines = expandAngSkripteLogLinesMobile(file.lines);
      const lines = takeLastLogLinesMobile(file.lines, 50);
      const viewer = lines.length
        ? '<div class="insight-log-viewer">' + mobileRenderLogfileLinesHtml(lines) + "</div>"
        : '<p class="insight-empty">Datei leer oder nicht lesbar.</p>';
      const lineLabel =
        allLines.length > lines.length
          ? lines.length + " von " + allLines.length + " Zeilen (letzte)"
          : lines.length + " Zeile" + (lines.length !== 1 ? "n" : "");
      return (
        '<details class="insight-log-file">' +
        "<summary>" + mobileEsc(name) + " · " + mobileEsc(lineLabel) + "</summary>" +
        viewer +
        "</details>"
      );
    })
    .join("");
}

function buildInsightGuardianLogHtml(scriptGuardian) {
  const block = scriptGuardian && typeof scriptGuardian === "object" ? scriptGuardian : {};
  const lines = Array.isArray(block.lines) ? block.lines.map((line) => String(line || "")).filter(Boolean) : [];
  const tail = lines.slice(-12);
  if (!tail.length) {
    return "";
  }
  const meta =
    "Intervall " +
    (block.interval_minutes != null ? String(block.interval_minutes) : "125") +
    " min · " +
    (block.path ? String(block.path) : "guardian.log");
  return (
    '<details class="insight-log-file">' +
    "<summary>🛡️ Script Guardian · " + mobileEsc(meta) + "</summary>" +
    '<div class="insight-log-viewer">' +
    mobileRenderLogfileLinesHtml(tail) +
    "</div></details>"
  );
}

function mobileQueueDepthLabel(value) {
  const depth = Number(value);
  if (!Number.isFinite(depth) || depth < 0) return "0";
  return String(Math.floor(depth));
}

function mobileFormatAgentApiKeyStatus(agentApiKeyBlock, agentConfigBlock) {
  const block = agentApiKeyBlock && typeof agentApiKeyBlock === "object" ? agentApiKeyBlock : {};
  const status = String(block.status || "").trim().toLowerCase();
  const entries =
    agentConfigBlock && typeof agentConfigBlock === "object" && Array.isArray(agentConfigBlock.entries)
      ? agentConfigBlock.entries
      : [];
  const hasConfiguredApiKey = entries.some(
    (entry) => String(entry?.key || "").trim().toUpperCase() === "API_KEY" && String(entry?.value || "").trim()
  );
  if (status === "key-auth") return "aktiv | letzter Report mit API-Key authentifiziert";
  if (status === "grace") return "Grace | Host noch ohne Header zugelassen";
  if (status === "configured") return "konfiguriert | letzter Report noch nicht mit Key authentifiziert";
  if (status === "missing") return "fehlt | Server erwartet API-Key";
  if (hasConfiguredApiKey) return "konfiguriert | Status ab nächstem Report sichtbar";
  return "aus | Server verlangt aktuell keinen API-Key";
}

function mobileInsightSubsection(title, bodyHtml) {
  const content = String(bodyHtml || "").trim();
  if (!content) return "";
  return (
    '<section class="insight-subsection">' +
    '<h5 class="insight-subsection-title">' + mobileEsc(title) + "</h5>" +
    content +
    "</section>"
  );
}

function mobileDeliveryChipHtml(payload, report) {
  const p = payload && typeof payload === "object" ? payload : {};
  const deliveryMode = String(report?.delivery_mode || p.delivery_mode || "live").toLowerCase();
  const isDelayed = deliveryMode === "delayed" || p.is_delayed === true;
  const chipClass = isDelayed ? "insight-delivery-chip is-delayed" : "insight-delivery-chip is-live";
  return '<p class="insight-delivery-row"><span class="' + chipClass + '">' + (isDelayed ? "DELAYED" : "LIVE") + "</span></p>";
}

function buildInsightEinzelSystemBody(host, variant, report, payload) {
  const p = payload && typeof payload === "object" ? payload : {};
  const h = host && typeof host === "object" ? host : {};
  const network = p.network && typeof p.network === "object" ? p.network : {};
  const { hostname, displayName, customerLabel } = getHostListLabels(h);
  const envLabel = mobileEnvironmentLabel(h.environment_type) || "—";
  const country = String(h.country_code || "").trim().toUpperCase() || "—";
  const hostUid = String(report?.host_uid || p.host_uid || h.host_uid || "").trim() || "—";
  const totalReports = Number.isFinite(Number(h.report_count))
    ? Number(h.report_count).toLocaleString("de-CH")
    : "—";
  const primaryIp = String(report?.primary_ip || p.primary_ip || h.primary_ip || h.std_nic_ip || "").trim() || "—";
  const stdNicIp = String(p.std_nic_ipv4 || h.std_nic_ip || primaryIp).trim() || "—";
  const dns = Array.isArray(network.dns_servers)
    ? network.dns_servers.map((s) => String(s || "").trim()).filter(Boolean).join(", ")
    : String(network.dns_servers || "").trim();

  const hostAgentRows = [
    { label: "Kunde", value: customerLabel },
    { label: "Bezeichnung", value: displayName },
    { label: "Hostname", value: hostname },
    { label: "Host-UID", value: hostUid },
    { label: "Land", value: country },
    { label: "Umgebung", value: envLabel },
    { label: "Meldungen", value: totalReports },
    { label: "Agent ID", value: String(report?.agent_id || p.agent_id || hostname).trim() || "—" },
    {
      label: "Version",
      value: String(p.agent_version || h.agent_version || "").trim() || "—",
    },
    { label: "API-Key", value: mobileFormatAgentApiKeyStatus(p.agent_api_key, p.agent_config) },
    { label: "Queue", value: mobileQueueDepthLabel(p.queue_depth) + " Dateien" },
  ];

  const systemNetworkRows = [
    { label: "OS", value: String(p.os || h.os || "").trim() || "—" },
    { label: "Kernel", value: String(p.kernel || "").trim() || "—" },
    { label: "Uptime", value: mobileFormatUptime(p.uptime_seconds) },
    { label: "Architektur", value: String(p.architecture || p.arch || "").trim() || "—" },
    { label: "Primary IP", value: primaryIp },
    { label: "Std. NIC IP", value: stdNicIp },
    { label: "Default NIC", value: String(network.default_interface || "").trim() || "—" },
    { label: "Gateway", value: String(network.default_gateway || "").trim() || "—" },
    { label: "DNS", value: dns || "—" },
  ];

  const sapRaw = resolveSapReleaseRawMobile(h, p);
  const sapDisplay = resolveSapReleaseDisplayMobile(sapRaw);
  const hanaRelease = resolveHanaReleaseMobile(h, p);
  const hanaSid = resolveHanaSidMobile(h, p);
  const kpiHtml =
    sapDisplay || hanaRelease || hanaSid
      ? '<div class="insight-kpi-grid insight-kpi-grid--compact">' +
        (sapDisplay ? mobileInsightKpi("SAP Release", sapDisplay) : "") +
        (hanaRelease ? mobileInsightKpi("HANA Release", hanaRelease) : "") +
        (hanaSid ? mobileInsightKpi("HANA SID", hanaSid) : "") +
        "</div>"
      : "";

  const resourcesHtml = buildInsightResourcesBody(p);
  return (
    mobileDeliveryChipHtml(p, report) +
    kpiHtml +
    mobileInsightSubsection("Host & Agent", mobileInsightKvListHtml(hostAgentRows)) +
    mobileInsightSubsection("System & Netzwerk", mobileInsightKvListHtml(systemNetworkRows)) +
    mobileInsightSubsection("CPU & RAM", resourcesHtml)
  );
}

function buildInsightEinzelNetworkBody(payload) {
  const network = payload?.network && typeof payload.network === "object" ? payload.network : {};
  const interfaces = Array.isArray(network.interfaces) ? network.interfaces : [];
  if (!interfaces.length) {
    return '<p class="insight-empty">Keine Netzwerk-Details im letzten Report.</p>';
  }
  const summaryRows = [
    { label: "Default NIC", value: String(network.default_interface || "").trim() || "—" },
    { label: "Gateway", value: String(network.default_gateway || "").trim() || "—" },
    {
      label: "DNS",
      value: Array.isArray(network.dns_servers)
        ? network.dns_servers.map((s) => String(s || "").trim()).filter(Boolean).join(", ") || "—"
        : "—",
    },
  ];
  const ifaceItems = interfaces.slice(0, 16).map((iface) => {
    const name = String(iface.name || "—").trim();
    const state = String(iface.state || "—").trim();
    const defaultTag = iface.is_default ? " · default" : "";
    const rx = Number(iface.rx_bytes);
    const tx = Number(iface.tx_bytes);
    const errors = Number(iface.rx_errors || 0) + Number(iface.tx_errors || 0);
    const drops = Number(iface.rx_dropped || 0) + Number(iface.tx_dropped || 0);
    const meta =
      state +
      defaultTag +
      " · RX " +
      (Number.isFinite(rx) ? mobileFormatKb(rx / 1024) : "—") +
      " · TX " +
      (Number.isFinite(tx) ? mobileFormatKb(tx / 1024) : "—") +
      " · Err " +
      errors +
      " · Drop " +
      drops;
    return mobileInsightKvRow(name, meta);
  });
  const more =
    interfaces.length > 16
      ? '<p class="insight-hint">+' + (interfaces.length - 16) + " weitere Interfaces im Desktop-Report.</p>"
      : "";
  return (
    mobileInsightSubsection("Übersicht", mobileInsightKvListHtml(summaryRows)) +
    mobileInsightSubsection(
      "Interfaces",
      '<ul class="insight-kv-list">' + ifaceItems.filter(Boolean).join("") + "</ul>" + more
    )
  );
}

function buildInsightEinzelAgentBody(payload) {
  const p = payload && typeof payload === "object" ? payload : {};
  const parts = [];

  const agentUpdate = p.agent_update && typeof p.agent_update === "object" ? p.agent_update : null;
  if (agentUpdate) {
    const lines = Array.isArray(agentUpdate.lines) ? agentUpdate.lines.map((line) => String(line || "")).filter(Boolean) : [];
    const tail = lines.slice(-20);
    parts.push(
      '<details class="insight-log-file">' +
      "<summary>⟳ Agent Update Log · " +
      mobileEsc(String(agentUpdate.path || "agent-update.log")) +
      "</summary>" +
      (tail.length
        ? '<div class="insight-log-viewer">' + mobileRenderLogfileLinesHtml(tail) + "</div>"
        : '<p class="insight-empty">Kein Log-Inhalt.</p>') +
      "</details>"
    );
  }

  const guardianHtml = buildInsightGuardianLogHtml(p.script_guardian);
  if (guardianHtml) parts.push(guardianHtml);

  const agentConfig = p.agent_config && typeof p.agent_config === "object" ? p.agent_config : null;
  if (agentConfig && Array.isArray(agentConfig.entries) && agentConfig.entries.length) {
    const rows = agentConfig.entries.slice(0, 24).map((entry) => ({
      label: String(entry?.key || "—").trim(),
      value: String(entry?.value || "—").trim() || "—",
    }));
    parts.push(
      '<details class="insight-log-file" open>' +
      "<summary>🗂️ agent.conf · " +
      rows.length +
      " Einträge</summary>" +
      mobileInsightKvListHtml(rows) +
      "</details>"
    );
  }

  const cron = p.cron_info && typeof p.cron_info === "object" ? p.cron_info : null;
  if (cron) {
    const rootLines = Array.isArray(cron.root_crontab_lines) ? cron.root_crontab_lines : [];
    const cronDLines = Array.isArray(cron.cron_d_files) ? cron.cron_d_files : [];
    if (rootLines.length) {
      parts.push(
        '<details class="insight-log-file">' +
        "<summary>🕐 Root Crontab · " +
        rootLines.length +
        " Zeilen</summary>" +
        '<div class="insight-log-viewer">' +
        mobileRenderLogfileLinesHtml(rootLines.slice(0, 30)) +
        "</div></details>"
      );
    }
    if (cronDLines.length) {
      parts.push(
        '<details class="insight-log-file">' +
        "<summary>📅 cron.d · " +
        cronDLines.length +
        " Dateien</summary>" +
        '<div class="insight-log-viewer">' +
        mobileRenderLogfileLinesHtml(
          cronDLines.slice(0, 12).map((file) => String(file?.path || file?.name || "-") + ": " + String(file?.summary || "").trim())
        ) +
        "</div></details>"
      );
    }
  }

  if (!parts.length) {
    return '<p class="insight-empty">Keine Agent-Diagnose-Daten im letzten Report.</p>';
  }
  return parts.join("");
}

function buildInsightEinzelExportBody(payload) {
  const block = payload?.dir_listings && typeof payload.dir_listings === "object" ? payload.dir_listings : null;
  const deepBlock = payload?.dir_deep_listings && typeof payload.dir_deep_listings === "object" ? payload.dir_deep_listings : null;
  const parts = [];

  if (block?.available && Array.isArray(block.entries) && block.entries.length) {
    block.entries.slice(0, 8).forEach((entry) => {
      const path = String(entry.path || entry.pattern || "—").trim();
      const items = Array.isArray(entry.items) ? entry.items : [];
      const itemLines = items.slice(0, 6).map((item) => {
        const name = String(item.name || item.file_name || "—").trim();
        const size = item.size_bytes != null ? mobileFormatKb(Number(item.size_bytes) / 1024) : "—";
        const mtime = formatUtcPlus2Mobile(item.modified_utc || item.mtime_utc || "");
        return mobileInsightKvRow(name, size + " · " + mtime);
      });
      parts.push(
        mobileInsightSubsection(
          path,
          itemLines.length
            ? '<ul class="insight-kv-list">' + itemLines.join("") + "</ul>"
            : '<p class="insight-empty">Verzeichnis leer.</p>'
        )
      );
    });
  }

  if (deepBlock?.available && Array.isArray(deepBlock.entries) && deepBlock.entries.length) {
    deepBlock.entries.slice(0, 4).forEach((entry) => {
      const path = String(entry.path || entry.pattern || "—").trim();
      const subdirs = Array.isArray(entry.subdirs) ? entry.subdirs : [];
      const subLines = subdirs.slice(0, 8).map((subdir) => {
        const name = String(subdir.name || "—").trim();
        const zipCount = Number(subdir.zip_item_count_total || subdir.items?.length || 0);
        const latest = formatUtcPlus2Mobile(subdir.zip_latest_modified_utc || "");
        return mobileInsightKvRow(name, zipCount + " ZIP · " + (latest !== "—" ? latest : "—"));
      });
      parts.push(
        mobileInsightSubsection(
          "Deep · " + path,
          subLines.length
            ? '<ul class="insight-kv-list">' + subLines.join("") + "</ul>"
            : '<p class="insight-empty">Keine Unterordner.</p>'
        )
      );
    });
  }

  if (!parts.length) {
    return '<p class="insight-empty">Keine SAP-Export-Daten (DIR_SCAN_PATHS / DIR_SCAN_DEEP_PATHS).</p>';
  }
  return parts.join("");
}

function collectMobileSapAddonLabels(payload) {
  const sap = payload?.sap_business_one && typeof payload.sap_business_one === "object" ? payload.sap_business_one : null;
  const labels = [];
  const extRows = Array.isArray(sap?.extensions?.rows) ? sap.extensions.rows : [];
  extRows.forEach((row) => {
    const name = String(row?.AddOnName || row?.name || "").trim();
    const version = String(row?.Version || row?.version || "").trim();
    if (name) labels.push({ name, version });
  });
  const sariRows = Array.isArray(sap?.sari_addons?.rows) ? sap.sari_addons.rows : [];
  sariRows.forEach((row) => {
    const name = String(row?.AName || row?.name || "").trim();
    const version = String(row?.AddOnVer || row?.version || "").trim();
    if (name) labels.push({ name: name + " (Legacy)", version });
  });
  return labels;
}

function buildInsightEinzelSapB1Body(host, payload) {
  const p = payload && typeof payload === "object" ? payload : {};
  const sap = p.sap_business_one && typeof p.sap_business_one === "object" ? p.sap_business_one : null;
  const parts = [];

  const sapRaw = resolveSapReleaseRawMobile(host, p);
  const sapDisplay = resolveSapReleaseDisplayMobile(sapRaw) || "—";
  const hanaRelease = resolveHanaReleaseMobile(host, p) || "—";
  const hanaSid = resolveHanaSidMobile(host, p) || "—";
  parts.push(
    '<div class="insight-kpi-grid insight-kpi-grid--compact">' +
    mobileInsightKpi("SAP Release", sapDisplay) +
    mobileInsightKpi("HANA Release", hanaRelease) +
    mobileInsightKpi("HANA SID", hanaSid) +
    "</div>"
  );

  const addons = collectMobileSapAddonLabels(p);
  if (addons.length) {
    parts.push(
      '<details class="insight-log-file" open>' +
      "<summary>🧩 AddOns · " +
      addons.length +
      "</summary>" +
      mobileInsightAddonListHtml(addons, 40) +
      "</details>"
    );
  }

  const hi = p.hana_info && typeof p.hana_info === "object" ? p.hana_info : null;
  if (hi) {
    const hanaRows = [
      { label: "Status", value: hi.available === true ? "verfügbar" : "nicht gefunden" },
      { label: "SID", value: String(hi.sid || "").trim() || "—" },
      { label: "Version", value: String(hi.version || "").trim() || "—" },
      { label: "Branch", value: String(hi.branch || "").trim() || "—" },
    ];
    parts.push(
      '<details class="insight-log-file">' +
      "<summary>🗄️ HANA Versions-Scan</summary>" +
      mobileInsightKvListHtml(hanaRows) +
      "</details>"
    );
  }

  const sapLicense = p.sap_license && typeof p.sap_license === "object" ? p.sap_license : null;
  if (sapLicense) {
    const licenseRows = [
      { label: "Lizenzserver", value: String(sapLicense.license_server || "").trim() || "—" },
      { label: "System-ID", value: String(sapLicense.system_id || "").trim() || "—" },
      { label: "Installation", value: String(sapLicense.installation_number || "").trim() || "—" },
      { label: "Hardware-Key", value: String(sapLicense.hardware_key || "").trim() || "—" },
    ];
    parts.push(
      '<details class="insight-log-file">' +
      "<summary>📄 Lizenzinfos</summary>" +
      mobileInsightKvListHtml(licenseRows) +
      "</details>"
    );
  }

  const services = sap?.installed_services && typeof sap.installed_services === "object" ? sap.installed_services : null;
  if (services && Array.isArray(services.entries) && services.entries.length) {
    const serviceLines = services.entries.slice(0, 16).map((entry) =>
      mobileInsightKvRow(
        String(entry?.name || entry?.service_name || "—").trim(),
        String(entry?.status || entry?.state || "—").trim()
      )
    );
    parts.push(
      '<details class="insight-log-file">' +
      "<summary>⚙️ Installierte Services · " +
      services.entries.length +
      "</summary>" +
      '<ul class="insight-kv-list">' +
      serviceLines.join("") +
      "</ul></details>"
    );
  }

  if (!sap && !hi && !sapLicense) {
    return '<p class="insight-empty">Keine SAP-B1-Daten im letzten Report.</p>';
  }
  return parts.join("");
}

function buildHostInsightSlides(host, variant, report, payload) {
  const reportLabel = resolveInsightReportLabel(report, payload, host, variant);
  const hasPayload = payload && typeof payload === "object" && Object.keys(payload).length > 0;

  if (!hasPayload) {
    return [
      wrapInsightSlide(
        "ℹ️",
        "Kein Report",
        '<p class="insight-empty">Für diesen Host liegt kein aktueller Report-Payload vor.</p>' +
          buildInsightOverviewBody(host, variant),
        reportLabel
      ),
    ];
  }

  const builders = {
    system: () => buildInsightEinzelSystemBody(host, variant, report, payload),
    journal: () => buildInsightJournalBody(payload),
    processes: () => buildInsightProcessesBody(payload),
    logfiles: () => buildInsightLogsBody(payload),
    "sap-b1": () => buildInsightEinzelSapB1Body(host, payload),
    containers: () => buildInsightContainersBody(payload),
    export: () => buildInsightEinzelExportBody(payload),
    agent: () => buildInsightEinzelAgentBody(payload),
    network: () => buildInsightEinzelNetworkBody(payload),
    filesystems: () => buildInsightFilesystemsBody(payload),
    databases: () => buildInsightDatabasesBody(payload),
  };

  return HOST_INSIGHT_SLIDE_DEFS.map((def) =>
    wrapInsightSlide(def.icon, def.title, builders[def.id](), reportLabel)
  );
}

function scrollHostInsightToIndex(index, behavior) {
  const track = document.getElementById("hostInsightTrack");
  if (!track) return;
  const slides = track.querySelectorAll(".host-insight-slide");
  const target = slides[index];
  if (target) {
    target.scrollIntoView({ behavior: behavior || "smooth", inline: "center", block: "nearest" });
  }
}

function renderHostInsightSectionNav() {
  const nav = document.getElementById("hostInsightSectionNav");
  if (!nav) return;
  nav.innerHTML = HOST_INSIGHT_SLIDE_DEFS.map((def, index) => {
    const active = index === 0 ? " is-active" : "";
    return (
      '<button type="button" class="host-insight-section-chip' + active + '" data-insight-index="' + index + '" ' +
      'aria-label="' + mobileEsc(def.title) + '">' + mobileEsc(def.short || def.title) + "</button>"
    );
  }).join("");
}

function renderHostInsightDots(slideCount) {
  const dotsEl = document.getElementById("hostInsightDots");
  if (!dotsEl) return;
  if (slideCount <= 1) {
    dotsEl.innerHTML = "";
    dotsEl.classList.add("hidden");
    return;
  }
  dotsEl.classList.remove("hidden");
  dotsEl.innerHTML = Array.from({ length: slideCount }, (_, index) => {
    const active = index === 0 ? " is-active" : "";
    return (
      '<button type="button" class="host-insight-dot' + active + '" data-insight-index="' + index + '" ' +
      'role="tab" aria-label="Karte ' + (index + 1) + '" aria-selected="' + (index === 0 ? "true" : "false") + '"></button>'
    );
  }).join("");
}

function syncHostInsightCarouselUi() {
  const track = document.getElementById("hostInsightTrack");
  const counter = document.getElementById("hostInsightCounter");
  const dotsEl = document.getElementById("hostInsightDots");
  const navEl = document.getElementById("hostInsightSectionNav");
  if (!track) return;

  const slides = track.querySelectorAll(".host-insight-slide");
  const count = slides.length || 1;
  const slideWidth = slides[0]?.offsetWidth || track.clientWidth || 1;
  const index = Math.max(0, Math.min(count - 1, Math.round(track.scrollLeft / Math.max(slideWidth, 1))));

  if (counter) counter.textContent = index + 1 + " / " + count;

  if (dotsEl) {
    dotsEl.querySelectorAll(".host-insight-dot").forEach((dot, dotIndex) => {
      const active = dotIndex === index;
      dot.classList.toggle("is-active", active);
      dot.setAttribute("aria-selected", active ? "true" : "false");
    });
  }

  if (navEl) {
    navEl.querySelectorAll(".host-insight-section-chip").forEach((chip, chipIndex) => {
      chip.classList.toggle("is-active", chipIndex === index);
    });
    const activeChip = navEl.querySelector(".host-insight-section-chip.is-active");
    if (activeChip && typeof activeChip.scrollIntoView === "function") {
      activeChip.scrollIntoView({ behavior: "auto", inline: "nearest", block: "nearest" });
    }
  }
}

function bindHostInsightCarouselOnce() {
  const track = document.getElementById("hostInsightTrack");
  if (!track || track.dataset.bound === "1") return;
  track.dataset.bound = "1";

  track.addEventListener(
    "scroll",
    () => {
      if (hostInsightScrollRaf) window.cancelAnimationFrame(hostInsightScrollRaf);
      hostInsightScrollRaf = window.requestAnimationFrame(syncHostInsightCarouselUi);
    },
    { passive: true }
  );

  const handleInsightNavClick = (event) => {
    const target = event.target.closest(".host-insight-dot, .host-insight-section-chip");
    if (!target) return;
    const index = Number(target.getAttribute("data-insight-index") || 0);
    scrollHostInsightToIndex(index, "smooth");
  };

  document.getElementById("hostInsightDots")?.addEventListener("click", handleInsightNavClick);
  document.getElementById("hostInsightSectionNav")?.addEventListener("click", handleInsightNavClick);
}

function closeHostInsightCarousel() {
  const overlay = document.getElementById("hostInsightOverlay");
  if (overlay) overlay.classList.add("hidden");
  document.body.classList.remove("host-insight-open");
}

async function fetchLatestHostReport(host, options = {}) {
  const authRetried = options.authRetried === true;
  const hostUid = String(host?.host_uid || "").trim();
  const hostname = String(host?.hostname || "").trim();
  if (!hostUid && !hostname) {
    return { report: null, payload: null, error: "Kein Host-Identifier" };
  }

  const url = hostUid
    ? "/api/v1/host-reports?host_uid=" + encodeURIComponent(hostUid) + "&limit=1&offset=0"
    : "/api/v1/host-reports?hostname=" + encodeURIComponent(hostname) + "&limit=1&offset=0";

  try {
    const resp = await fetch(url, { credentials: "same-origin" });
    if (resp.status === 401) {
      if (!authRetried && (await mobileRecoverSessionAfter401())) {
        return fetchLatestHostReport(host, { authRetried: true });
      }
      return { report: null, payload: null, error: "Session abgelaufen" };
    }
    if (!resp.ok) {
      return { report: null, payload: null, error: "HTTP " + resp.status };
    }
    const data = await resp.json().catch(() => ({}));
    const reports = Array.isArray(data?.reports) ? data.reports : [];
    const report = reports[0] && typeof reports[0] === "object" ? reports[0] : null;
    const payload =
      report && typeof report.payload === "object" ? report.payload : null;
    return { report, payload, error: null };
  } catch (error) {
    return { report: null, payload: null, error: error?.message || String(error) };
  }
}

async function openHostInsightCarousel(host, variant) {
  if (!host) return;

  const overlay = document.getElementById("hostInsightOverlay");
  const track = document.getElementById("hostInsightTrack");
  const titleEl = document.getElementById("hostInsightTitle");
  const subtitleEl = document.getElementById("hostInsightSubtitle");
  if (!overlay || !track) return;

  const { hostname, displayName, customerLabel } = getHostListLabels(host);
  if (titleEl) titleEl.textContent = customerLabel;
  if (subtitleEl) {
    subtitleEl.textContent = hostname !== displayName ? hostname : String(host.host_uid || "").trim();
  }

  track.innerHTML =
    '<article class="host-insight-slide host-insight-slide--loading">' +
    '<p class="insight-loading">Lade letzten Report…</p>' +
    "</article>";

  overlay.classList.remove("hidden");
  document.body.classList.add("host-insight-open");
  bindHostInsightCarouselOnce();
  renderHostInsightSectionNav();
  renderHostInsightDots(1);
  syncHostInsightCarouselUi();

  await loadMobileSapB1VersionMap();
  const { report, payload, error } = await fetchLatestHostReport(host);
  if (overlay.classList.contains("hidden")) return;

  let slides = buildHostInsightSlides(host, variant, report, payload);
  if (error && (!payload || !Object.keys(payload || {}).length)) {
    const reportLabel = resolveInsightReportLabel(null, null, host, variant);
    slides = [
      wrapInsightSlide(
        "⚠️",
        "Hinweis",
        '<p class="insight-empty">' + mobileEsc(error) + "</p>" + buildInsightOverviewBody(host, variant),
        reportLabel
      ),
    ];
  }

  track.innerHTML = slides.join("");
  renderHostInsightSectionNav();
  renderHostInsightDots(slides.length);
  track.scrollLeft = 0;
  syncHostInsightCarouselUi();
}

const SYS_OVERVIEW_SLIDE_DEFS = [
  { id: "hardware", icon: "🖥️", title: "Hardware" },
  { id: "addons", icon: "🧩", title: "AddOns" },
  { id: "license_info", icon: "📄", title: "Lizenzinfos" },
  { id: "license_types", icon: "🏷️", title: "Lizenztypen" },
  { id: "data", icon: "📊", title: "Dateninfos" },
];

let mobileSapLicenseTypeMap = null;

async function loadMobileSapLicenseTypeMap() {
  if (mobileSapLicenseTypeMap) return mobileSapLicenseTypeMap;
  try {
    const resp = await fetch("/api/v1/sap-license-type-map", { credentials: "same-origin" });
    if (!resp.ok) {
      mobileSapLicenseTypeMap = [];
      return mobileSapLicenseTypeMap;
    }
    const data = await resp.json().catch(() => ({}));
    mobileSapLicenseTypeMap = Array.isArray(data.entries) ? data.entries : [];
  } catch {
    mobileSapLicenseTypeMap = [];
  }
  return mobileSapLicenseTypeMap;
}

function mobileNormalizeAddonPair(primaryValue, secondaryValue) {
  const name = String(primaryValue ?? "").trim();
  const version = String(secondaryValue ?? "").trim();
  if (!name) return null;
  return { name, version };
}

function mobileCollectHanaAddonTenantViews(hanaAddons) {
  if (!hanaAddons || typeof hanaAddons !== "object") return [];
  const parsePortFromTarget = (targetValue) => {
    const target = String(targetValue || "");
    const match = target.match(/:(\d{5})$/);
    return match ? match[1] : "";
  };
  const tenantRows = Array.isArray(hanaAddons.tenants) ? hanaAddons.tenants : [];
  if (tenantRows.length > 0) {
    return tenantRows
      .filter((tenantRow) => tenantRow && typeof tenantRow === "object")
      .map((tenantRow) => {
        const tenantResult = tenantRow.result && typeof tenantRow.result === "object" ? tenantRow.result : tenantRow;
        const targetValue = String(tenantResult.target || "");
        const tenantPortRaw = String(tenantRow.tenant_port || "").trim();
        return {
          tenantId: String(tenantRow.tenant_id || "").trim(),
          tenantPort: tenantPortRaw || parsePortFromTarget(targetValue),
          lightweight: Array.isArray(tenantResult.lightweight) ? tenantResult.lightweight : [],
          legacy: Array.isArray(tenantResult.legacy) ? tenantResult.legacy : [],
        };
      });
  }
  return [{
    tenantId: "",
    tenantPort: parsePortFromTarget(String(hanaAddons.target || "")),
    lightweight: Array.isArray(hanaAddons.lightweight) ? hanaAddons.lightweight : [],
    legacy: Array.isArray(hanaAddons.legacy) ? hanaAddons.legacy : [],
  }];
}

function mobileCollectSysOverviewAddonLabels(soHost) {
  const payload = soHost && typeof soHost.payload === "object" ? soHost.payload : {};
  const sap = payload.sap_business_one && typeof payload.sap_business_one === "object" ? payload.sap_business_one : null;
  const hana = payload.hana_addons && typeof payload.hana_addons === "object" ? payload.hana_addons : null;
  const osField = String(payload.os || "").toLowerCase();
  const isWindows = osField.includes("windows");
  const isLinux = osField.includes("linux");
  const showSql = !isLinux;
  const showHana = !isWindows;
  const labels = [];
  const seen = new Set();

  const pushPair = (primaryValue, secondaryValue) => {
    const pair = mobileNormalizeAddonPair(primaryValue, secondaryValue);
    if (!pair) return;
    const key = (pair.name + "||" + pair.version).toLowerCase();
    if (seen.has(key)) return;
    seen.add(key);
    labels.push(pair);
  };

  if (showSql && sap) {
    const extRows = Array.isArray(sap.extensions?.rows) ? sap.extensions.rows : [];
    extRows.forEach((row) => pushPair(row?.AddOnName, row?.Version));
    const legacyRows = Array.isArray(sap.sari_addons?.rows) ? sap.sari_addons.rows : [];
    legacyRows.forEach((row) => pushPair(row?.AName, row?.AddOnVer));
  }

  if (showHana && hana) {
    mobileCollectHanaAddonTenantViews(hana).forEach((tenantView) => {
      const lightRows = Array.isArray(tenantView.lightweight) ? tenantView.lightweight : [];
      lightRows.forEach((row) => pushPair(row?.name, row?.version));
      const legacyRows = Array.isArray(tenantView.legacy) ? tenantView.legacy : [];
      legacyRows.forEach((row) => pushPair(row?.name, row?.version));
    });
  }

  return labels.sort((a, b) => {
    const byName = String(a.name || "").localeCompare(String(b.name || ""), "de", { sensitivity: "base", numeric: true });
    if (byName !== 0) return byName;
    return String(a.version || "").localeCompare(String(b.version || ""), "de", { sensitivity: "base", numeric: true });
  });
}

function mobileTranslateLicenseType(rawType) {
  const upperRawType = String(rawType || "").trim().toUpperCase();
  if (!upperRawType) return null;
  const entries = Array.isArray(mobileSapLicenseTypeMap) ? mobileSapLicenseTypeMap : [];
  for (const mapEntry of entries) {
    const matchText = String(mapEntry?.match_text || "").trim().toUpperCase();
    const visible = mapEntry?.visible !== false;
    if (matchText && matchText === upperRawType && visible) {
      const displayName = String(mapEntry?.display_name || "").trim();
      return displayName || null;
    }
  }
  return null;
}

function mobileCollectSysOverviewLicenseTypes(sapLicense) {
  const rawFocusTypes = Array.isArray(sapLicense?.focus_license_types) ? sapLicense.focus_license_types : [];
  return rawFocusTypes
    .filter((entry) => entry && typeof entry === "object")
    .map((entry) => {
      const rawType = String(entry.license_type || "").trim();
      const translated = mobileTranslateLicenseType(rawType);
      if (!rawType || translated === null) return null;
      const countRaw = Number(entry.count);
      const count = Number.isFinite(countRaw) ? countRaw : 0;
      return { rawType, translated, count };
    })
    .filter((entry) => entry !== null);
}

function mobileFormatSysOverviewLastUpdate(value) {
  const raw = String(value || "").trim();
  if (!raw) return "—";
  const parsed = new Date(raw);
  if (Number.isNaN(parsed.getTime())) return raw;
  return parsed.toLocaleString("de-CH", {
    day: "2-digit",
    month: "2-digit",
    year: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function mobileFormatSysOverviewStatusText(soHost) {
  if (soHost?.online !== true) return "Offline";
  const payload = soHost?.payload && typeof soHost.payload === "object" ? soHost.payload : {};
  const alerts = Array.isArray(payload.alerts) ? payload.alerts : [];
  const openAlerts = alerts.filter((alert) => alert && alert.status !== "resolved" && alert.status !== "closed");
  if (!openAlerts.length) return "OK";
  const criticalCount = openAlerts.filter((alert) => String(alert.severity || "").toLowerCase() === "critical").length;
  if (criticalCount > 0) return criticalCount + " Critical";
  return openAlerts.length + " Warning";
}

function mobileInsightFactsHtml(rows) {
  const html = (Array.isArray(rows) ? rows : []).filter(Boolean).join("");
  return html ? '<dl class="insight-facts">' + html + "</dl>" : "";
}

function mobileInsightSplitRow(leftText, rightText, variant) {
  const left = String(leftText || "").trim();
  const right = String(rightText || "").trim();
  if (!left || !right) return "";
  const rowClass = variant === "addon" ? "insight-addon-row" : "insight-kv-row";
  const leftClass = variant === "addon" ? "insight-addon-name" : "insight-kv-label";
  const rightClass = variant === "addon" ? "insight-addon-version" : "insight-kv-value";
  return (
    '<li class="' + rowClass + '">' +
    '<span class="' + leftClass + '">' + mobileEsc(left) + "</span>" +
    '<span class="' + rightClass + '">' + mobileEsc(right) + "</span>" +
    "</li>"
  );
}

function mobileInsightAddonRow(name, version) {
  return mobileInsightSplitRow(name, version || "—", "addon");
}

function mobileInsightKvRow(label, value) {
  return mobileInsightSplitRow(label, value, "kv");
}

function mobileInsightKvListHtml(rows) {
  const items = (Array.isArray(rows) ? rows : [])
    .map((entry) => mobileInsightKvRow(entry?.label, entry?.value))
    .filter(Boolean);
  return items.length ? '<ul class="insight-kv-list">' + items.join("") + "</ul>" : "";
}

function mobileInsightAddonListHtml(labels, maxVisible) {
  const items = Array.isArray(labels) ? labels : [];
  if (!items.length) return '<p class="insight-empty">Keine AddOns vorhanden.</p>';
  const limit = Math.max(1, Number(maxVisible) || 25);
  const visible = items.slice(0, limit);
  const hiddenCount = Math.max(0, items.length - visible.length);
  const rows = visible.map((entry) => mobileInsightAddonRow(entry.name, entry.version)).filter(Boolean);
  const more = hiddenCount > 0
    ? '<p class="insight-empty">+' + hiddenCount + " weitere AddOns</p>"
    : "";
  return '<ul class="insight-addon-list">' + rows.join("") + "</ul>" + more;
}

function buildMobileSysOverviewHardwareBody(soHost, listHost) {
  const payload = soHost?.payload && typeof soHost.payload === "object" ? soHost.payload : {};
  const osLabel = String(payload.os || listHost?.os || "").trim() || "—";
  const ramGbRaw = Number(soHost?.ram_gb);
  const ramGb = Number.isFinite(ramGbRaw) ? ramGbRaw + " GB" : String(soHost?.ram_gb || "").trim() || "—";
  const cpuCoresRaw = Number(soHost?.cpu_cores);
  const cpuCores = Number.isFinite(cpuCoresRaw) ? String(cpuCoresRaw) + " vCPU" : "—";
  const systemModel = String(soHost?.model || soHost?.system_model || payload.model || "").trim() || "—";
  return mobileInsightKvListHtml([
    { label: "Betriebssystem", value: osLabel },
    { label: "CPU", value: cpuCores },
    { label: "CPU-Modell", value: String(soHost?.cpu_model_name || "").trim() || "—" },
    { label: "RAM", value: ramGb },
    { label: "Systemmodell", value: systemModel },
  ]);
}

function buildMobileSysOverviewAddonsBody(soHost) {
  return mobileInsightAddonListHtml(mobileCollectSysOverviewAddonLabels(soHost), 30);
}

function buildMobileSysOverviewLicenseInfoBody(soHost) {
  const payload = soHost?.payload && typeof soHost.payload === "object" ? soHost.payload : {};
  const sapLicense = payload.sap_license && typeof payload.sap_license === "object" ? payload.sap_license : null;
  if (!sapLicense) return '<p class="insight-empty">Keine Lizenzinfos vorhanden.</p>';

  const rawExpiration = String(sapLicense.expiration || "").trim();
  const formattedExpiration = /^\d{8}$/.test(rawExpiration)
    ? rawExpiration.substring(6, 8) + "." + rawExpiration.substring(4, 6) + "." + rawExpiration.substring(0, 4)
    : rawExpiration;

  const rows = [
    { label: "HW-Key", value: String(sapLicense.hardware_key || "").trim() },
    { label: "Installationsnummer", value: String(sapLicense.instno || "").trim() },
    { label: "Systemnummer", value: String(sapLicense.system_nr || "").trim() },
    { label: "Systemtyp", value: String(sapLicense.system_type || "").trim() },
    { label: "Kundennummer", value: String(sapLicense.customer_no || "").trim() },
    { label: "Lizenznehmer", value: String(sapLicense.customer_name || "").trim() },
    { label: "Gültig bis", value: formattedExpiration },
  ].filter((entry) => entry.value);

  if (!rows.length) return '<p class="insight-empty">Keine Lizenzinfos vorhanden.</p>';
  return mobileInsightKvListHtml(rows);
}

function buildMobileSysOverviewLicenseTypesBody(soHost) {
  const payload = soHost?.payload && typeof soHost.payload === "object" ? soHost.payload : {};
  const sapLicense = payload.sap_license && typeof payload.sap_license === "object" ? payload.sap_license : null;
  const entries = mobileCollectSysOverviewLicenseTypes(sapLicense);
  if (!entries.length) return '<p class="insight-empty">Keine Lizenztypen vorhanden.</p>';
  return mobileInsightAddonListHtml(
    entries.map((entry) => ({ name: entry.translated, version: String(entry.count) })),
    50
  );
}

function buildMobileSysOverviewDataBody(soHost, listHost) {
  const payload = soHost?.payload && typeof soHost.payload === "object" ? soHost.payload : {};
  const sapRelease = resolveSapReleaseDisplayMobile(
    String(soHost?.sap_release || resolveSapReleaseRawMobile(listHost, payload) || "").trim()
  ) || "—";
  const sqlRelease = String(soHost?.sql_release || "").trim() || "—";
  const hanaVersion = String(soHost?.hana_version || resolveHanaReleaseMobile(listHost, payload) || "").trim() || "—";
  const hanaSid = String(soHost?.hana_sid || resolveHanaSidMobile(listHost, payload) || "").trim() || "—";
  const status = mobileFormatSysOverviewStatusText(soHost);
  const lastUpdate = mobileFormatSysOverviewLastUpdate(soHost?.last_update);

  return mobileInsightAddonListHtml(
    [
      { name: "SQL Release", version: sqlRelease },
      { name: "SAP Release", version: sapRelease },
      { name: "HANA Release", version: hanaVersion },
      { name: "HANA SID", version: hanaSid },
      { name: "Status", version: status },
      { name: "Letztes Update", version: lastUpdate },
    ],
    20
  );
}

function findSystemOverviewHostInData(data, host) {
  const hostUid = String(host?.host_uid || "").trim();
  const hostname = String(host?.hostname || "").trim();
  const byCountry = data?.by_country;
  if (!byCountry || typeof byCountry !== "object") return null;

  for (const country of Object.values(byCountry)) {
    if (!country || typeof country !== "object") continue;
    for (const osGroup of Object.values(country)) {
      if (!osGroup || typeof osGroup !== "object") continue;
      for (const customerHosts of Object.values(osGroup)) {
        if (!Array.isArray(customerHosts)) continue;
        for (const entry of customerHosts) {
          if (!entry || typeof entry !== "object") continue;
          const entryUid = String(entry.host_uid || "").trim();
          const entryHost = String(entry.hostname || "").trim();
          if ((hostUid && entryUid === hostUid) || (hostname && entryHost === hostname)) {
            return entry;
          }
        }
      }
    }
  }
  return null;
}

async function fetchSystemOverviewHost(host, options = {}) {
  const authRetried = options.authRetried === true;
  const hostname = String(host?.hostname || "").trim();
  const hostUid = String(host?.host_uid || "").trim();
  const q = hostname || hostUid;
  if (!q) return { soHost: null, error: "Kein Hostname" };

  try {
    const resp = await fetch("/api/v1/system-overview?q=" + encodeURIComponent(q), { credentials: "same-origin" });
    if (resp.status === 401) {
      if (!authRetried && (await mobileRecoverSessionAfter401())) {
        return fetchSystemOverviewHost(host, { authRetried: true });
      }
      return { soHost: null, error: "Session abgelaufen" };
    }
    if (!resp.ok) return { soHost: null, error: "HTTP " + resp.status };
    const data = await resp.json().catch(() => ({}));
    const soHost = findSystemOverviewHostInData(data, host);
    return {
      soHost,
      error: soHost ? null : "Host nicht in Systemübersicht gefunden",
    };
  } catch (error) {
    return { soHost: null, error: error?.message || String(error) };
  }
}

function buildMobileSysOverviewSlides(soHost, listHost) {
  const label = mobileFormatSysOverviewLastUpdate(soHost?.last_update) || "—";
  const builders = {
    hardware: () => buildMobileSysOverviewHardwareBody(soHost, listHost),
    addons: () => buildMobileSysOverviewAddonsBody(soHost),
    license_info: () => buildMobileSysOverviewLicenseInfoBody(soHost),
    license_types: () => buildMobileSysOverviewLicenseTypesBody(soHost),
    data: () => buildMobileSysOverviewDataBody(soHost, listHost),
  };
  return SYS_OVERVIEW_SLIDE_DEFS.map((def) =>
    wrapInsightSlide(def.icon, def.title, builders[def.id](), "Stand: " + label)
  );
}

async function openSystemOverviewCarousel(listHost) {
  if (!listHost) return;

  const overlay = document.getElementById("hostInsightOverlay");
  const track = document.getElementById("hostInsightTrack");
  const titleEl = document.getElementById("hostInsightTitle");
  const subtitleEl = document.getElementById("hostInsightSubtitle");
  if (!overlay || !track) return;

  const { hostname, displayName, customerLabel } = getHostListLabels(listHost);
  if (titleEl) titleEl.textContent = customerLabel;
  if (subtitleEl) {
    subtitleEl.textContent = (displayName !== hostname ? displayName + " · " : "") + "Systemübersicht";
  }

  track.innerHTML =
    '<article class="host-insight-slide host-insight-slide--loading">' +
    '<p class="insight-loading">Lade Systemübersicht…</p>' +
    "</article>";

  overlay.classList.remove("hidden");
  document.body.classList.add("host-insight-open");
  bindHostInsightCarouselOnce();
  renderHostInsightDots(1);
  syncHostInsightCarouselUi();

  await Promise.all([loadMobileSapB1VersionMap(), loadMobileSapLicenseTypeMap()]);
  const { soHost, error } = await fetchSystemOverviewHost(listHost);
  if (overlay.classList.contains("hidden")) return;

  let slides;
  if (!soHost || error) {
    slides = [
      wrapInsightSlide(
        "⚠️",
        "Hinweis",
        '<p class="insight-empty">' + mobileEsc(error || "Keine Daten") + "</p>",
        "Systemübersicht"
      ),
    ];
  } else {
    slides = buildMobileSysOverviewSlides(soHost, listHost);
  }

  track.innerHTML = slides.join("");
  renderHostInsightDots(slides.length);
  track.scrollLeft = 0;
  syncHostInsightCarouselUi();
}

function handleHostListSheetClick(event) {
  const btn = event.target.closest('[data-action="host-list-sheet"], [data-action="sys-overview"]');
  if (!btn) return;
  event.preventDefault();
  event.stopPropagation();
  const variant = String(btn.getAttribute("data-host-list") || "");
  const index = Number(btn.getAttribute("data-host-index") || -1);
  if (index < 0) return;

  const hosts =
    variant === "active"
      ? filterHostListItems(state.activeHosts, state.activeHostsCountryFilter, state.activeHostsSearchQuery)
      : filterHostListItems(state.inactiveHosts, state.inactiveHostsCountryFilter, state.inactiveHostsSearchQuery);
  if (!hosts[index]) return;

  if (btn.getAttribute("data-action") === "sys-overview") {
    void openSystemOverviewCarousel(hosts[index]);
    return;
  }
  void openHostInsightCarousel(hosts[index], variant);
}

const ADDON_SEARCH_MIN_QUERY_LEN = 2;
const ADDON_SEARCH_DEBOUNCE_MS = 350;

function setAddonSearchStatus(text, isError = false) {
  const line = document.getElementById("addonSearchStatusLine");
  if (!line) return;
  line.textContent = text;
  line.classList.toggle("is-error", isError);
}

function collectAddonSearchCountriesFromData(data) {
  const byCountry = data?.by_country;
  if (!byCountry || typeof byCountry !== "object") return [];
  return Object.keys(byCountry)
    .map((code) => String(code || "").trim().toUpperCase())
    .filter((code) => /^[A-Z]{2}$/.test(code))
    .sort();
}

function collectAddonSearchHostEntries(data, countryFilter) {
  const byCountry = data?.by_country;
  const entries = [];
  if (!byCountry || typeof byCountry !== "object") return entries;

  const activeCountry = String(countryFilter || "all").trim().toUpperCase();
  Object.entries(byCountry).forEach(([country, osMap]) => {
    if (activeCountry !== "ALL" && String(country).toUpperCase() !== activeCountry) return;
    if (!osMap || typeof osMap !== "object") return;
    Object.entries(osMap).forEach(([osName, customerMap]) => {
      if (!customerMap || typeof customerMap !== "object") return;
      Object.entries(customerMap).forEach(([customer, hosts]) => {
        if (!Array.isArray(hosts)) return;
        hosts.forEach((host) => {
          if (!host || typeof host !== "object") return;
          entries.push({
            country: String(country || "").trim(),
            osName: String(osName || "").trim(),
            customer: String(customer || "Ohne Kunde").trim() || "Ohne Kunde",
            host,
          });
        });
      });
    });
  });
  return entries;
}

function resolveAddonSearchHostKey(host) {
  return String(host?.host_uid || host?.hostname || "").trim();
}

function normalizeAddonSearchGroupMode(value) {
  return String(value || "").trim() === "customer-version" ? "customer-version" : "version-customer";
}

function getAddonSearchGroupModeLabel(mode) {
  return normalizeAddonSearchGroupMode(mode) === "customer-version"
    ? "AddOn > Kunde > Version > Host"
    : "AddOn > Version > Kunde > Host";
}

function syncAddonSearchGroupChips() {
  const mode = normalizeAddonSearchGroupMode(state.addonSearchGroupMode);
  document.querySelectorAll(".addon-search-group-chip[data-addon-group]").forEach((chip) => {
    chip.classList.toggle("active", chip.getAttribute("data-addon-group") === mode);
  });
  const subtitle = document.getElementById("addonSearchSubtitle");
  if (subtitle) subtitle.textContent = getAddonSearchGroupModeLabel(mode);
}

function buildMobileAddonSearchTree(data, searchQuery, countryFilter, groupMode) {
  const query = String(searchQuery || "").trim().toLowerCase();
  const entries = collectAddonSearchHostEntries(data, countryFilter);
  const addonMap = new Map();
  const displayedHostKeys = new Set();
  const byCustomer = normalizeAddonSearchGroupMode(groupMode) === "customer-version";

  entries.forEach((entry) => {
    const addonItems = mobileCollectSysOverviewAddonLabels(entry.host).filter((addon) => {
      if (!query) return false;
      const haystack = (String(addon?.name || "") + " " + String(addon?.version || "")).toLowerCase();
      return haystack.includes(query);
    });
    if (!addonItems.length) return;

    addonItems.forEach((addon) => {
      const addonNameKey = String(addon?.name || "").trim();
      if (!addonNameKey) return;
      const versionKey = String(addon?.version || "").trim() || "—";
      const customerKey = String(entry.customer || "Ohne Kunde");

      if (!addonMap.has(addonNameKey)) addonMap.set(addonNameKey, new Map());
      const level2Map = addonMap.get(addonNameKey);

      if (byCustomer) {
        if (!level2Map.has(customerKey)) level2Map.set(customerKey, new Map());
        const versionMap = level2Map.get(customerKey);
        if (!versionMap.has(versionKey)) versionMap.set(versionKey, []);
        versionMap.get(versionKey).push(entry);
      } else {
        if (!level2Map.has(versionKey)) level2Map.set(versionKey, new Map());
        const customerMap = level2Map.get(versionKey);
        if (!customerMap.has(customerKey)) customerMap.set(customerKey, []);
        customerMap.get(customerKey).push(entry);
      }

      displayedHostKeys.add(resolveAddonSearchHostKey(entry.host));
    });
  });

  return {
    addonMap,
    hostCount: displayedHostKeys.size,
    groupMode: byCustomer ? "customer-version" : "version-customer",
  };
}

function sortAddonSearchHostEntries(entries) {
  return (Array.isArray(entries) ? entries : []).slice().sort((left, right) =>
    String(left.host?.display_name || left.host?.hostname || "").localeCompare(
      String(right.host?.display_name || right.host?.hostname || ""),
      "de",
      { sensitivity: "base", numeric: true }
    )
  );
}

function countAddonSearchNestedEntries(nestedMap, leafIsList) {
  let total = 0;
  (nestedMap instanceof Map ? nestedMap : new Map()).forEach((value) => {
    if (leafIsList) {
      total += Array.isArray(value) ? value.length : 0;
    } else {
      total += countAddonSearchNestedEntries(value, true);
    }
  });
  return total;
}

function renderMobileAddonSearchHostRow(entry, hostMap, options = {}) {
  const host = entry.host;
  const hostKey = resolveAddonSearchHostKey(host);
  if (hostKey) hostMap[hostKey] = host;

  const labels = getHostListLabels({
    hostname: host.hostname,
    display_name: host.display_name,
    customer_name: entry.customer,
  });
  const osLabel = String(entry.osName || "").trim() || "—";
  const country = String(entry.country || "").trim().toUpperCase() || "—";
  const status = mobileFormatSysOverviewStatusText(host);
  const sapRelease = resolveSapReleaseDisplayMobile(String(host.sap_release || "").trim()) || "—";
  const hostname = String(host.hostname || "").trim();
  const hideCustomer = options.hideCustomer === true;

  return (
    '<article class="mobile-addon-host-row">' +
    '<div class="mobile-addon-host-main">' +
    '<p class="mobile-addon-host-title">' + mobileEsc(labels.hostLabel) + "</p>" +
    (!hideCustomer && labels.hasCustomer && labels.customerLabel !== labels.hostLabel
      ? '<p class="mobile-addon-host-meta">' + mobileEsc(labels.customerLabel) + "</p>"
      : "") +
    (hostname && hostname !== labels.hostLabel
      ? '<p class="mobile-addon-host-meta">' + mobileEsc(hostname) + "</p>"
      : "") +
    '<p class="mobile-addon-host-meta">' + mobileEsc(osLabel) + " · " + mobileEsc(country) +
    " · SAP " + mobileEsc(sapRelease) + " · " + mobileEsc(status) + "</p>" +
    "</div>" +
    '<button type="button" class="btn-secondary" data-action="addon-search-sys-overview" data-host-key="' + mobileEsc(hostKey) + '">Systemübersicht</button>' +
    "</article>"
  );
}

function renderMobileAddonSearchCustomerSection(customer, entries, hostMap, options = {}) {
  const sortedEntries = sortAddonSearchHostEntries(entries);
  const hostRows = sortedEntries
    .map((entry) => renderMobileAddonSearchHostRow(entry, hostMap, options))
    .join("");
  return (
    '<details class="mobile-addon-tree-item mobile-addon-tree-item--customer">' +
    '<summary><span>👥 ' + mobileEsc(customer) + '</span><span class="mobile-addon-tree-count">' + sortedEntries.length + "</span></summary>" +
    '<div class="mobile-addon-tree-children">' + hostRows + "</div></details>"
  );
}

function renderMobileAddonSearchVersionSection(version, nestedMap, hostMap, groupMode) {
  const byCustomer = normalizeAddonSearchGroupMode(groupMode) === "customer-version";
  if (byCustomer) {
    const entries = Array.isArray(nestedMap) ? nestedMap : [];
    const sortedEntries = sortAddonSearchHostEntries(entries);
    const hostRows = sortedEntries
      .map((entry) => renderMobileAddonSearchHostRow(entry, hostMap, { hideCustomer: true }))
      .join("");
    return (
      '<details class="mobile-addon-tree-item mobile-addon-tree-item--version">' +
      '<summary><span>🏷️ ' + mobileEsc(version) + '</span><span class="mobile-addon-tree-count">' + sortedEntries.length + "</span></summary>" +
      '<div class="mobile-addon-tree-children">' + hostRows + "</div></details>"
    );
  }

  const customerSections = Array.from((nestedMap instanceof Map ? nestedMap : new Map()).entries())
    .sort((a, b) => String(a[0]).localeCompare(String(b[0]), "de", { sensitivity: "base", numeric: true }))
    .map(([customer, entries]) => renderMobileAddonSearchCustomerSection(customer, entries, hostMap))
    .join("");
  const versionCount = countAddonSearchNestedEntries(nestedMap, true);
  return (
    '<details class="mobile-addon-tree-item mobile-addon-tree-item--version">' +
    '<summary><span>🏷️ ' + mobileEsc(version) + '</span><span class="mobile-addon-tree-count">' + versionCount + "</span></summary>" +
    '<div class="mobile-addon-tree-children">' + customerSections + "</div></details>"
  );
}

function renderMobileAddonSearchLevel2Section(label, icon, nestedMap, hostMap, groupMode) {
  const byCustomer = normalizeAddonSearchGroupMode(groupMode) === "customer-version";
  const level2Class = byCustomer ? "mobile-addon-tree-item--customer" : "mobile-addon-tree-item--version";
  const level3Sections = Array.from((nestedMap instanceof Map ? nestedMap : new Map()).entries())
    .sort((a, b) => String(a[0]).localeCompare(String(b[0]), "de", { sensitivity: "base", numeric: true }))
    .map(([level3Key, level3Value]) => {
      if (byCustomer) {
        return renderMobileAddonSearchVersionSection(level3Key, level3Value, hostMap, groupMode);
      }
      return renderMobileAddonSearchCustomerSection(level3Key, level3Value, hostMap);
    })
    .join("");
  const level2Count = countAddonSearchNestedEntries(nestedMap, false);
  return (
    '<details class="mobile-addon-tree-item ' + level2Class + '">' +
    '<summary><span>' + icon + " " + mobileEsc(label) + '</span><span class="mobile-addon-tree-count">' + level2Count + "</span></summary>" +
    '<div class="mobile-addon-tree-children">' + level3Sections + "</div></details>"
  );
}

function renderMobileAddonSearchTreeHtml(tree) {
  const addonMap = tree?.addonMap;
  if (!addonMap || !(addonMap instanceof Map) || !addonMap.size) {
    return '<div class="mobile-ops-empty">Keine AddOns für diese Suche gefunden.</div>';
  }

  const hostMap = {};
  const groupMode = normalizeAddonSearchGroupMode(tree.groupMode || state.addonSearchGroupMode);
  const sortedAddons = Array.from(addonMap.entries()).sort((a, b) =>
    String(a[0]).localeCompare(String(b[0]), "de", { sensitivity: "base", numeric: true })
  );

  const html = sortedAddons.map(([addonName, level2Map]) => {
    const byCustomer = groupMode === "customer-version";
    const level2Sections = Array.from((level2Map instanceof Map ? level2Map : new Map()).entries())
      .sort((a, b) => String(a[0]).localeCompare(String(b[0]), "de", { sensitivity: "base", numeric: true }))
      .map(([level2Key, level3Map]) => {
        const icon = byCustomer ? "👥" : "🏷️";
        return renderMobileAddonSearchLevel2Section(level2Key, icon, level3Map, hostMap, groupMode);
      })
      .join("");
    const addonCount = countAddonSearchNestedEntries(level2Map, false);
    return (
      '<details class="mobile-addon-tree-item mobile-addon-tree-item--addon" open>' +
      '<summary><span>🧩 ' + mobileEsc(addonName) + '</span><span class="mobile-addon-tree-count">' + addonCount + "</span></summary>" +
      '<div class="mobile-addon-tree-children">' + level2Sections + "</div></details>"
    );
  }).join("");

  state.addonSearchHostMap = hostMap;
  return '<div class="mobile-addon-tree">' + html + "</div>";
}

function updateAddonSearchView() {
  const list = document.getElementById("addonSearchList");
  if (!list) return;

  const query = String(state.addonSearchQuery || "").trim();
  if (query.length < ADDON_SEARCH_MIN_QUERY_LEN) {
    list.innerHTML = '<div class="mobile-ops-empty">AddOn-Name eingeben, um Hosts zu finden.</div>';
    setAddonSearchStatus("AddOn-Name eingeben (mind. " + ADDON_SEARCH_MIN_QUERY_LEN + " Zeichen).");
    return;
  }

  if (!state.addonSearchLastData) {
    if (!state.addonSearchLoading) {
      list.innerHTML = '<div class="mobile-ops-empty">Noch keine Daten geladen.</div>';
    }
    return;
  }

  const tree = buildMobileAddonSearchTree(
    state.addonSearchLastData,
    query,
    state.addonSearchCountryFilter,
    state.addonSearchGroupMode
  );
  list.innerHTML = renderMobileAddonSearchTreeHtml(tree);
  const addonCount = tree.addonMap instanceof Map ? tree.addonMap.size : 0;
  setAddonSearchStatus(
    addonCount > 0
      ? addonCount + " AddOn(s) · " + tree.hostCount + " Host(s)"
      : "Keine Treffer für \"" + query + "\""
  );
}

function scheduleAddonSearchLoad() {
  if (state.addonSearchDebounceTimerId !== null) {
    window.clearTimeout(state.addonSearchDebounceTimerId);
  }
  state.addonSearchDebounceTimerId = window.setTimeout(() => {
    state.addonSearchDebounceTimerId = null;
    void loadAddonSearchResults();
  }, ADDON_SEARCH_DEBOUNCE_MS);
}

async function loadAddonSearchResults(options = {}) {
  if (!state.authenticated) return;
  const authRetried = options.authRetried === true;
  const force = options.force === true;
  const list = document.getElementById("addonSearchList");
  const query = String(state.addonSearchQuery || "").trim();

  if (query.length < ADDON_SEARCH_MIN_QUERY_LEN) {
    state.addonSearchLastData = null;
    state.addonSearchHostMap = {};
    updateAddonSearchView();
    return;
  }

  if (!isAddonSearchViewActive() && !force) return;

  state.addonSearchLoading = true;
  if (list) list.innerHTML = '<div class="mobile-ops-empty">Lade AddOns…</div>';
  setAddonSearchStatus("Lade Systemübersicht…");

  try {
    const resp = await fetch("/api/v1/system-overview?q=" + encodeURIComponent(query), { credentials: "same-origin" });
    if (resp.status === 401) {
      if (!authRetried && (await mobileRecoverSessionAfter401())) {
        return loadAddonSearchResults({ authRetried: true, force: true });
      }
      mobileForceLogout("Session abgelaufen. Bitte erneut anmelden.");
      return;
    }
    if (!resp.ok) throw new Error("HTTP " + resp.status);

    const data = await resp.json().catch(() => ({}));
    state.addonSearchLastData = data;
    const countries = collectAddonSearchCountriesFromData(data);
    renderHostCountryFilter("addonSearchCountryFilter", countries, state.addonSearchCountryFilter, (country) => {
      state.addonSearchCountryFilter = country;
      updateAddonSearchView();
    });
    updateAddonSearchView();
  } catch (error) {
    if (list) list.innerHTML = '<div class="mobile-ops-empty">Fehler beim Laden.</div>';
    setAddonSearchStatus("Fehler: " + (error?.message || String(error)), true);
  } finally {
    state.addonSearchLoading = false;
  }
}

function handleAddonSearchListClick(event) {
  const btn = event.target.closest('[data-action="addon-search-sys-overview"]');
  if (!btn) return;
  event.preventDefault();
  event.stopPropagation();
  const hostKey = String(btn.getAttribute("data-host-key") || "").trim();
  if (!hostKey) return;
  const host = state.addonSearchHostMap?.[hostKey];
  if (!host) return;
  void openSystemOverviewCarousel(host);
}

function updateActiveHostsListView() {
  const allHosts = Array.isArray(state.activeHosts) ? state.activeHosts : [];
  const filtered = filterHostListItems(allHosts, state.activeHostsCountryFilter, state.activeHostsSearchQuery);
  const countries = collectHostListCountries(allHosts);

  renderHostCountryFilter("activeHostsCountryFilter", countries, state.activeHostsCountryFilter, (country) => {
    state.activeHostsCountryFilter = country;
    updateActiveHostsListView();
  });

  const list = document.getElementById("activeHostsList");
  if (!list) return;

  if (!allHosts.length) {
    list.innerHTML = '<div class="inactive-hosts-empty">Keine aktiven Hosts in der letzten Stunde.</div>';
    setActiveHostsStatus("Keine aktiven Hosts");
    return;
  }

  if (!filtered.length) {
    list.innerHTML = '<div class="inactive-hosts-empty">Keine Hosts für Suche oder Land-Filter.</div>';
    setActiveHostsStatus("0 von " + allHosts.length + " Hosts (gefiltert)");
    return;
  }

  list.innerHTML = filtered.map((host, index) => renderHostListCard(host, "active", index)).join("");
  setActiveHostsStatus(
    filtered.length === allHosts.length
      ? filtered.length + " aktive Hosts"
      : filtered.length + " von " + allHosts.length + " Hosts"
  );
}

function updateInactiveHostsListView(hours) {
  const allHosts = Array.isArray(state.inactiveHosts) ? state.inactiveHosts : [];
  const filtered = filterHostListItems(allHosts, state.inactiveHostsCountryFilter, state.inactiveHostsSearchQuery);
  const countries = collectHostListCountries(allHosts);
  const resolvedHours = Number(hours || state.inactiveHostsHours || 1);

  renderHostCountryFilter("inactiveHostsCountryFilter", countries, state.inactiveHostsCountryFilter, (country) => {
    state.inactiveHostsCountryFilter = country;
    updateInactiveHostsListView(resolvedHours);
  });

  const list = document.getElementById("inactiveHostsList");
  if (!list) return;

  if (!allHosts.length) {
    list.innerHTML =
      '<div class="inactive-hosts-empty">Alle Hosts sind aktiv.<br>Keine Inaktivität seit '
      + resolvedHours
      + " Stunde"
      + (resolvedHours === 1 ? "" : "n")
      + ".</div>";
    setInactiveHostsStatus("Keine inaktiven Hosts");
    return;
  }

  if (!filtered.length) {
    list.innerHTML = '<div class="inactive-hosts-empty">Keine Hosts für Suche oder Land-Filter.</div>';
    setInactiveHostsStatus("0 von " + allHosts.length + " Hosts (gefiltert)");
    return;
  }

  list.innerHTML = filtered.map((host, index) => renderHostListCard(host, "inactive", index)).join("");
  setInactiveHostsStatus(
    filtered.length === allHosts.length
      ? filtered.length + " inaktive Hosts"
      : filtered.length + " von " + allHosts.length + " Hosts"
  );
}

async function loadActiveHostsList(options = {}) {
  if (!state.authenticated || !isActiveHostsViewActive()) {
    return;
  }
  const authRetried = options.authRetried === true;
  const list = document.getElementById("activeHostsList");

  state.activeHostsLoading = true;
  if (list && !options.silent) {
    list.innerHTML = '<div class="inactive-hosts-empty">Lade aktive Hosts…</div>';
  }
  setActiveHostsStatus("Lade aktive Hosts…");

  try {
    const resp = await fetch("/api/v1/hosts?limit=200&offset=0", { credentials: "same-origin" });

    if (resp.status === 401) {
      if (!authRetried && (await mobileRecoverSessionAfter401())) {
        return loadActiveHostsList({ authRetried: true, silent: options.silent });
      }
      mobileForceLogout("Session abgelaufen. Bitte erneut anmelden.");
      return;
    }

    if (!resp.ok) {
      throw new Error("HTTP " + resp.status);
    }

    const data = await resp.json();
    const allHosts = Array.isArray(data.hosts) ? data.hosts : [];
    const hosts = allHosts.filter((host) => isHostActive(host));
    hosts.sort((a, b) => {
      const ta = parseUtcIso(a?.last_seen_utc || "")?.getTime() || 0;
      const tb = parseUtcIso(b?.last_seen_utc || "")?.getTime() || 0;
      return tb - ta;
    });

    state.activeHosts = hosts;
    state.activeHostsCount = hosts.length;
    renderHostKpis();

    const subtitle = document.getElementById("activeHostsSubtitle");
    if (subtitle) {
      subtitle.textContent =
        state.activeHostsCount + " Host" + (state.activeHostsCount === 1 ? "" : "s") + " · letzte Stunde";
    }

    updateActiveHostsListView();
  } catch (error) {
    if (list) {
      list.innerHTML =
        '<div class="inactive-hosts-empty">Fehler beim Laden: ' + mobileEsc(error?.message || String(error)) + "</div>";
    }
    setActiveHostsStatus("Fehler: " + (error?.message || String(error)), true);
  } finally {
    state.activeHostsLoading = false;
  }
}

async function loadInactiveHostsList(options = {}) {
  if (!state.authenticated || !isInactiveHostsViewActive()) {
    return;
  }
  const authRetried = options.authRetried === true;
  const list = document.getElementById("inactiveHostsList");
  const hours = Math.max(1, Math.min(24 * 30, Number(state.inactiveHostsHours) || Number(state.hostKpisHours) || 1));

  state.inactiveHostsLoading = true;
  if (list && !options.silent) {
    list.innerHTML = '<div class="inactive-hosts-empty">Lade inaktive Hosts…</div>';
  }
  setInactiveHostsStatus("Lade inaktive Hosts…");

  try {
    const resp = await fetch("/api/v1/inactive-hosts?hours=" + encodeURIComponent(String(hours)), {
      credentials: "same-origin",
    });

    if (resp.status === 401) {
      if (!authRetried && (await mobileRecoverSessionAfter401())) {
        return loadInactiveHostsList({ authRetried: true, silent: options.silent });
      }
      mobileForceLogout("Session abgelaufen. Bitte erneut anmelden.");
      return;
    }

    if (!resp.ok) {
      throw new Error("HTTP " + resp.status);
    }

    const data = await resp.json();
    const hosts = Array.isArray(data.inactive_hosts) ? data.inactive_hosts : [];
    const resolvedHours = Number(data.hours || hours);
    state.inactiveHosts = hosts;
    state.inactiveHostsHours = resolvedHours;
    state.inactiveHostsCount = Math.max(0, Number(data.total || hosts.length || 0));
    renderHostKpis();

    const subtitle = document.getElementById("inactiveHostsSubtitle");
    if (subtitle) {
      subtitle.textContent =
        state.inactiveHostsCount + " Host" + (state.inactiveHostsCount === 1 ? "" : "s") + " · Schwelle " + resolvedHours + "h";
    }

    updateInactiveHostsListView(resolvedHours);
  } catch (error) {
    if (list) {
      list.innerHTML =
        '<div class="inactive-hosts-empty">Fehler beim Laden: ' + mobileEsc(error?.message || String(error)) + "</div>";
    }
    setInactiveHostsStatus("Fehler: " + (error?.message || String(error)), true);
  } finally {
    state.inactiveHostsLoading = false;
  }
}

function mobileForceLogout(message) {
  stopMobileSessionKeepAlive();
  stopMobileLiveReportPoll();
  state.authenticated = false;
  showAlertsHomeView();
  showLoginOverlay(true);
  if (message) {
    setLoginStatus(message, true);
  }
  renderAlerts([]);
  state.activeHostsCount = 0;
  state.inactiveHostsCount = 0;
  state.inactiveHosts = [];
  state.activeHosts = [];
  renderHostKpis();
  state.pushSupported = false;
  state.pushConfigured = false;
  state.pushEnabled = false;
  renderPushButton();
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

function formatUtcPlus2Mobile(value) {
  const text = String(value || "").trim();
  if (!text) return "—";
  const normalized = text.includes("T") ? text : text.replace(" ", "T");
  const parsed = new Date(normalized.endsWith("Z") ? normalized : normalized + "Z");
  if (Number.isNaN(parsed.getTime())) return text;
  const shifted = new Date(parsed.getTime() + 2 * 60 * 60 * 1000);
  return shifted.toLocaleString("de-DE", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
    timeZone: "UTC",
  });
}

function resolveHostOsIconMobile(osValue) {
  const osRaw = String(osValue || "").toLowerCase();
  if (osRaw.includes("windows")) {
    return "windows.png";
  }
  if (osRaw.includes("ubuntu")) return "ubuntu.png";
  if (osRaw.includes("debian")) return "debian.png";
  if (osRaw.includes("suse") || osRaw.includes("opensuse") || osRaw.includes("sles")) return "suse.png";
  return "linux.png";
}

function truncateMobileText(value, maxLen) {
  const text = String(value || "").trim();
  if (!text || text.length <= maxLen) return text;
  return text.slice(0, Math.max(0, maxLen - 1)) + "…";
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
  activeHostsCount: 0,
  inactiveHostsCount: 0,
  hostKpisHours: 1,
  mobileView: "alerts",
  inactiveHosts: [],
  inactiveHostsHours: 1,
  inactiveHostsLoading: false,
  inactiveHostsCountryFilter: "all",
  inactiveHostsSearchQuery: "",
  activeHosts: [],
  activeHostsLoading: false,
  activeHostsCountryFilter: "all",
  activeHostsSearchQuery: "",
  addonSearchQuery: "",
  addonSearchGroupMode: "version-customer",
  addonSearchCountryFilter: "all",
  addonSearchLoading: false,
  addonSearchLastData: null,
  addonSearchHostMap: {},
  addonSearchDebounceTimerId: null,
  latestAgentVersion: "",
};

const SKELETON_CARD_COUNT = 4;
/** Gleiches Intervall wie Desktop: Session bleibt bei offener App aktiv (Server-Timeout default 30 min). */
const MOBILE_SESSION_REFRESH_INTERVAL_MS = 4 * 60 * 1000;
const MOBILE_SESSION_LOGIN_GRACE_MS = 20000;
const LIVE_REPORT_FEED_MAX_ITEMS = 5;
const LIVE_REPORT_FEED_POSITION_KEY = "monitoring.liveReportFeedPosition";
const LIVE_REPORT_FEED_ENABLED_KEY = "monitoring.liveReportFeedEnabled";
const LIVE_REPORT_POLL_INTERVAL_MS = 25000;
const LIVE_REPORT_POLL_INTERVAL_FAST_MS = 8000;
const LIVE_REPORT_PUSH_COOLDOWN_MS = 15 * 60 * 1000;
const liveReportPushCooldownByHost = new Map();
let liveReportFeedItems = [];
let liveReportFeedMinimized = false;
let liveReportFeedEnabled = true;
let liveReportFeedWired = false;
let liveReportFeedDragState = null;
let liveReportPollTimerId = null;
let liveReportPollInFlight = false;
let liveReportPollCursorId = 0;
const USAGE_BAR_ANIMATION_MS = 1500;
let lastUsageBarCarouselIndex = -1;
const usageBarAnimStates = new WeakMap();

let serviceWorkerRegistrationPromise = null;
let toastTimer = null;
let customerLogoObserver = null;
let mobileSessionRefreshTimerId = null;
let mobileSessionEstablishedAtMs = 0;

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
  const label = String(state.userDisplayName || "").trim() || String(state.username || "").trim();
  line.innerHTML = '<span class="mobile-user-badge">' + mobileEsc(label) + "</span>";
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

function resolveMobileAssetVersion() {
  const script = document.querySelector('script[src*="mobile-alerts.js"]');
  if (!script) return "";
  const match = String(script.getAttribute("src") || "").match(/[?&]v=([^&]+)/);
  return match ? decodeURIComponent(match[1]) : "";
}

async function getServiceWorkerRegistration() {
  if (!("serviceWorker" in navigator)) {
    throw new Error("Service Worker wird auf diesem Browser nicht unterstützt");
  }
  if (!serviceWorkerRegistrationPromise) {
    const swVersion = resolveMobileAssetVersion() || String(Date.now());
    serviceWorkerRegistrationPromise = navigator.serviceWorker.register("/sw.js?v=" + encodeURIComponent(swVersion));
  }
  const registration = await serviceWorkerRegistrationPromise;
  if (!registration) {
    throw new Error("Service Worker konnte nicht registriert werden");
  }
  if (typeof registration.update === "function") {
    void registration.update();
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
  btn.title = state.pushEnabled
    ? "Push deaktivieren (Live-Reports + Alerts)"
    : "Push aktivieren (Live-Reports + Alerts)";
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
    const wasPushEnabled = state.pushEnabled;
    state.pushEnabled = Boolean(
      localEndpoint
      && serverSubs.some((item) => item && item.is_active === true && String(item.endpoint || "") === localEndpoint)
    );
    if (state.authenticated && wasPushEnabled !== state.pushEnabled) {
      startMobileLiveReportPoll();
    }
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
      body: JSON.stringify({
        action: "subscribe",
        subscription: sub.toJSON(),
        live_report_push: true,
      }),
    });
    if (!saveResp.ok) {
      const err = await saveResp.json().catch(() => ({}));
      throw new Error(String(err.error || ("HTTP " + saveResp.status)));
    }
    state.pushEnabled = true;
    startMobileLiveReportPoll();
    showToast("Push aktiviert (Live-Reports + Alerts).");
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

function buildEnvironmentCardClass(environmentType) {
  const env = String(environmentType || "").trim().toLowerCase();
  if (env === "prod") return " env-prod";
  if (env === "test") return " env-test";
  return "";
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
  const hostname = String(item.hostname || "").trim();
  const showFqdn = Boolean(hostname && hostname.toLowerCase() !== hostLabel.toLowerCase());
  const fqdnHtml = showFqdn ? '<p class="alert-host-fqdn">' + mobileEsc(hostname) + "</p>" : "";
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
      + "<div" + hostRowAttrs + '><div class="alert-host-main">'
      + '<p class="alert-host-name">' + mobileEsc(hostLabel) + "</p>"
      + fqdnHtml
      + "</div></div>"
      + "</div>"
    );
  }

  return (
    '<div class="alert-identity">'
    + "<div" + titleRowAttrs + ">"
    + '<div class="alert-host-main">'
    + '<h2 class="alert-customer-name">' + mobileEsc(hostLabel) + "</h2>"
    + fqdnHtml
    + "</div>"
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

function buildAlertItContactLineHtml(item) {
  const html = buildItContactHtml(item);
  if (!html) return "";
  return '<p class="alert-it-contact">IT: ' + html + "</p>";
}

function buildMuteButtonHtml(item) {
  const isMuted = item?.is_muted === true;
  const label = isMuted ? "🔇" : "🔔";
  const title = isMuted ? "Stummschaltung aufheben" : "Alert stummschalten";
  const extra = isMuted ? " is-muted" : "";
  return (
    '<button type="button" class="btn-secondary btn-mute' + extra + '" data-action="toggle-mute" '
    + 'data-muted="' + (isMuted ? "1" : "0") + '" title="' + mobileEsc(title) + '" aria-label="' + mobileEsc(title) + '">'
    + label + "</button>"
  );
}

function parseVersionPartsMobile(value) {
  const raw = String(value || "").trim();
  if (!raw) return null;
  const parts = raw.split(/[.\-_]/).map((part) => Number.parseInt(part, 10)).filter((n) => Number.isFinite(n));
  return parts.length ? parts : null;
}

function compareSemverLikeMobile(left, right) {
  const leftParts = parseVersionPartsMobile(left);
  const rightParts = parseVersionPartsMobile(right);
  if (!leftParts || !rightParts) return null;
  const maxLen = Math.max(leftParts.length, rightParts.length);
  for (let index = 0; index < maxLen; index += 1) {
    const l = leftParts[index] || 0;
    const r = rightParts[index] || 0;
    if (l !== r) return l < r ? -1 : 1;
  }
  return 0;
}

function getAgentVersionLagInfoMobile(latestVersion, hostVersion) {
  const latestParts = parseVersionPartsMobile(latestVersion);
  const hostParts = parseVersionPartsMobile(hostVersion);
  if (!latestParts || !hostParts) {
    return { isBehind: false, steps: null, majorMinorDifferent: false };
  }
  const compare = compareSemverLikeMobile(hostVersion, latestVersion);
  if (compare === null || compare >= 0) {
    return { isBehind: false, steps: 0, majorMinorDifferent: false };
  }
  const latest = [latestParts[0] || 0, latestParts[1] || 0, latestParts[2] || 0];
  const host = [hostParts[0] || 0, hostParts[1] || 0, hostParts[2] || 0];
  const sameMajorMinor = latest[0] === host[0] && latest[1] === host[1];
  if (sameMajorMinor) {
    return { isBehind: true, steps: Math.max(0, latest[2] - host[2]), majorMinorDifferent: false };
  }
  return { isBehind: true, steps: null, majorMinorDifferent: true };
}

function buildAgentVersionBadgeHtml(version) {
  const hostVersion = String(version || "").trim();
  if (!hostVersion) return "";
  const latest = String(state.latestAgentVersion || "").trim();
  if (!latest) return "";
  const lag = getAgentVersionLagInfoMobile(latest, hostVersion);
  if (!lag.isBehind) return "";
  const label = lag.majorMinorDifferent
    ? "Agent veraltet"
    : "Agent −" + String(lag.steps || 1);
  return '<span class="host-agent-badge" title="Neueste Agent-Version: ' + mobileEsc(latest) + '">⚠ ' + mobileEsc(label) + "</span>";
}

function getJournalEntriesFromPayload(payload) {
  const block = payload?.journal_errors;
  if (Array.isArray(block)) return block;
  if (block && typeof block === "object" && Array.isArray(block.entries)) return block.entries;
  return [];
}

function buildInsightJournalBody(payload) {
  const block = payload?.journal_errors && typeof payload.journal_errors === "object" ? payload.journal_errors : {};
  const entries = getJournalEntriesFromPayload(payload);
  const sinceMinutes = Number(block.since_minutes || 0);
  const sinceLabel =
    Number.isFinite(sinceMinutes) && sinceMinutes > 0
      ? "Fenster: letzte " + sinceMinutes + " Minuten"
      : "Fenster: unbekannt";
  if (!entries.length) {
    return (
      '<p class="insight-hint">' +
      mobileEsc(sinceLabel) +
      '</p><p class="insight-empty">Keine kritischen Journal-Fehler im letzten Report.</p>'
    );
  }
  const items = entries.slice(0, 20).map((entry) => {
    const time = formatUtcPlus2Mobile(entry.time_utc || entry.time || "");
    const priority = String(entry.priority || "-").trim();
    const unit = String(entry.unit || "-").trim();
    const message = String(entry.message || "-").trim();
    return (
      '<li class="insight-journal-item">' +
      "<time>" + mobileEsc(time) + " · " + mobileEsc(priority) + " · " + mobileEsc(unit) + "</time>" +
      "<span>" + mobileEsc(message) + "</span></li>"
    );
  });
  return (
    '<p class="insight-hint">' +
    mobileEsc(sinceLabel) +
    " · " +
    entries.length +
    ' Einträge</p><ul class="insight-journal-list">' +
    items.join("") +
    "</ul>"
  );
}

function buildInsightContainersBody(payload) {
  const p = payload && typeof payload === "object" ? payload : {};
  const block = p.containers && typeof p.containers === "object" ? p.containers : {};
  const entries = Array.isArray(block.entries) ? block.entries : [];
  if (!block.available && !entries.length) {
    return '<p class="insight-empty">Container-Runtime nicht verfügbar.</p>';
  }
  if (!entries.length) {
    return '<p class="insight-empty">Keine Container gefunden.</p>';
  }
  return (
    '<div class="insight-container-list">' +
    entries.slice(0, 24).map((entry) => {
      const state = String(entry.state || "-").trim().toLowerCase();
      const bad = state !== "running";
      const restarts = Number(entry.restart_count || 0);
      return (
        '<article class="insight-container-item' + (bad ? " is-bad" : "") + '">' +
        '<p class="insight-container-name">' + mobileEsc(String(entry.name || "-")) + "</p>" +
        '<p class="insight-container-meta">' + mobileEsc(String(entry.image || "-")) + " · " + mobileEsc(String(entry.state || "-")) +
        (entry.health ? " · " + mobileEsc(String(entry.health)) : "") +
        (Number.isFinite(restarts) ? " · Restarts " + restarts : "") +
        "</p>" +
        (entry.status ? '<p class="insight-container-status">' + mobileEsc(String(entry.status)) + "</p>" : "") +
        "</article>"
      );
    }).join("") +
    "</div>"
  );
}

function buildInsightDatabasesBody(payload) {
  const p = payload && typeof payload === "object" ? payload : {};
  const sqlInfo = p.sql_server_info && typeof p.sql_server_info === "object" ? p.sql_server_info : null;
  const hanaInfo = p.hana_db_info && typeof p.hana_db_info === "object" ? p.hana_db_info : null;
  const parts = [];

  if (sqlInfo) {
    if (sqlInfo.available === false) {
      parts.push('<p class="insight-empty">SQL Server nicht gefunden.</p>');
    } else {
      const instances = Array.isArray(sqlInfo.instances) ? sqlInfo.instances : [];
      instances.forEach((inst) => {
        const dbs = Array.isArray(inst.databases) ? inst.databases : [];
        const dbLines = dbs.slice(0, 8).map((db) => {
          const totalMb = Number(db.data_mb || 0) + Number(db.log_mb || 0);
          return (
            '<article class="insight-db-item">' +
            '<p class="insight-db-name">' + mobileEsc(String(db.name || "-")) + "</p>" +
            '<p class="insight-db-meta">' + mobileEsc(String(db.state || "-")) + " · " + mobileFormatMb(totalMb) + "</p></article>"
          );
        });
        parts.push(
          '<p class="insight-section-label">SQL · ' + mobileEsc(String(inst.name || "MSSQLSERVER")) + "</p>" +
          (dbLines.length ? '<div class="insight-db-list">' + dbLines.join("") + "</div>" : '<p class="insight-empty">Keine DB-Liste.</p>')
        );
      });
    }
  }

  if (hanaInfo && Array.isArray(hanaInfo.databases) && hanaInfo.databases.length) {
    const rows = hanaInfo.databases.slice(0, 12).map((db) =>
      '<article class="insight-db-item"><p class="insight-db-name">' + mobileEsc(String(db.database_name || db.name || "-")) +
      '</p><p class="insight-db-meta">' + mobileEsc(String(db.active_status || db.status || "-")) + "</p></article>"
    );
    parts.push('<p class="insight-section-label">HANA</p><div class="insight-db-list">' + rows.join("") + "</div>");
  }

  if (!parts.length) {
    return '<p class="insight-empty">Keine Datenbank-Informationen im letzten Report.</p>';
  }
  return parts.join("");
}

function mobileFormatMb(value) {
  const mb = Number(value);
  if (!Number.isFinite(mb) || mb <= 0) return "—";
  if (mb >= 1024) return (mb / 1024).toFixed(2) + " GiB";
  return mb.toFixed(0) + " MiB";
}

async function openCustomerInfoSheet() {
  const item = state.lastAlerts[state.focusedAlertIndex] || state.lastAlerts[0];
  if (!item) {
    showToast("Kein Alert fokussiert.", true);
    return;
  }
  const hostUid = String(item.host_uid || "").trim();
  const hostname = String(item.hostname || "").trim();
  if (!hostUid && !hostname) {
    showToast("Kein Host für Kundeninfos.", true);
    return;
  }
  const titleEl = document.getElementById("customerInfoSheetTitle");
  const hintEl = document.getElementById("customerInfoSheetHint");
  const factsEl = document.getElementById("customerInfoSheetFacts");
  if (titleEl) titleEl.textContent = String(item.customer_name || item.display_name || "Kundeninfos").trim() || "Kundeninfos";
  if (hintEl) hintEl.textContent = "Stammdaten zum fokussierten Alert #" + String(item.id || "");
  if (factsEl) factsEl.innerHTML = '<p class="sheet-hint">Lade…</p>';
  openSheet("customerInfoSheet");
  try {
    const params = new URLSearchParams();
    if (hostname) params.set("hostname", hostname);
    if (hostUid) params.set("host_uid", hostUid);
    const resp = await fetch("/api/v1/host-settings?" + params.toString(), { credentials: "same-origin" });
    if (!resp.ok) throw new Error("HTTP " + resp.status);
    const data = await resp.json();
    const rows = [];
    const push = (label, value) => {
      const text = String(value || "").trim();
      if (text) rows.push(hostSheetFactRow(label, text));
    };
    push("Kundenname", data.customer_name);
    push("Maringo-Projekt", data.customer_maringo_project_number);
    push("IT-Anbieter", data.it_provider_name);
    push("Ansprechpartner", data.it_provider_contact);
    push("E-Mail", data.it_provider_email);
    push("Telefon", data.it_provider_phone);
    push("IT-Anbieter 2", data.it_provider_name_2);
    push("Ansprechpartner 2", data.it_provider_contact_2);
    push("E-Mail 2", data.it_provider_email_2);
    push("Telefon 2", data.it_provider_phone_2);
    if (factsEl) {
      factsEl.innerHTML = rows.length ? rows.join("") : '<p class="sheet-hint">Keine Kundeninfos hinterlegt.</p>';
    }
  } catch (error) {
    if (factsEl) factsEl.innerHTML = '<p class="sheet-hint">Fehler: ' + mobileEsc(error?.message || String(error)) + "</p>";
  }
}

function usagePercentForBar(item) {
  const current = item.current_used_percent;
  if (current != null && Number.isFinite(Number(current))) {
    return Math.min(100, Math.max(0, Number(current)));
  }
  return Math.min(100, Math.max(0, Number(item.used_percent || 0)));
}

function buildMountpointLine(item) {
  return mobileEsc(String(item.mountpoint || "-").trim() || "-");
}

let html2canvasLoadPromise = null;

function resolveHtml2CanvasLib() {
  const lib = window.html2canvas;
  if (typeof lib === "function") return lib;
  if (lib && typeof lib.default === "function") return lib.default;
  return null;
}

function loadHtml2Canvas() {
  const existing = resolveHtml2CanvasLib();
  if (existing) return Promise.resolve(existing);
  if (!html2canvasLoadPromise) {
    html2canvasLoadPromise = new Promise((resolve, reject) => {
      const script = document.createElement("script");
      script.src = "/vendor/html2canvas.min.js";
      script.async = true;
      script.onload = () => {
        const lib = resolveHtml2CanvasLib();
        if (lib) {
          resolve(lib);
          return;
        }
        reject(new Error("html2canvas nicht verfügbar"));
      };
      script.onerror = () => reject(new Error("html2canvas konnte nicht geladen werden"));
      document.head.appendChild(script);
    });
  }
  return html2canvasLoadPromise;
}

async function withDetachedPageStylesheets(run) {
  const linkSnapshots = [];
  const styleSnapshots = [];
  document.querySelectorAll('link[rel="stylesheet"]').forEach((link) => {
    linkSnapshots.push({ link, parent: link.parentNode, next: link.nextSibling });
    link.remove();
  });
  document.querySelectorAll("style").forEach((style) => {
    styleSnapshots.push({ style, parent: style.parentNode, next: style.nextSibling });
    style.remove();
  });
  try {
    return await run();
  } finally {
    linkSnapshots.forEach(({ link, parent, next }) => {
      if (parent) parent.insertBefore(link, next);
    });
    styleSnapshots.forEach(({ style, parent, next }) => {
      if (parent) parent.insertBefore(style, next);
    });
  }
}

function syncClonedImages(source, clone) {
  const sourceImgs = source.querySelectorAll("img");
  const cloneImgs = clone.querySelectorAll("img");
  cloneImgs.forEach((cloneImg, index) => {
    const sourceImg = sourceImgs[index];
    if (!sourceImg) return;
    const src = sourceImg.currentSrc || sourceImg.src || sourceImg.getAttribute("data-src") || "";
    if (!src) return;
    cloneImg.src = src;
    cloneImg.removeAttribute("data-src");
    cloneImg.classList.remove("is-hidden", "hidden");
    cloneImg.style.display = "";
    cloneImg.crossOrigin = "anonymous";
  });
}

const HTML2CANVAS_INLINE_PROPS = [
  "display", "position", "top", "right", "bottom", "left", "z-index", "float", "clear",
  "width", "height", "min-width", "max-width", "min-height", "max-height",
  "margin", "margin-top", "margin-right", "margin-bottom", "margin-left",
  "padding", "padding-top", "padding-right", "padding-bottom", "padding-left",
  "border", "border-top", "border-right", "border-bottom", "border-left",
  "border-width", "border-top-width", "border-right-width", "border-bottom-width", "border-left-width",
  "border-style", "border-top-style", "border-right-style", "border-bottom-style", "border-left-style",
  "border-color", "border-top-color", "border-right-color", "border-bottom-color", "border-left-color",
  "border-radius", "border-top-left-radius", "border-top-right-radius", "border-bottom-left-radius", "border-bottom-right-radius",
  "background", "background-color", "background-image", "background-size", "background-position", "background-repeat",
  "color", "font-family", "font-size", "font-weight", "font-style", "line-height", "letter-spacing",
  "text-align", "text-transform", "text-decoration", "text-decoration-color", "white-space", "word-break",
  "flex", "flex-grow", "flex-shrink", "flex-basis", "flex-direction", "flex-wrap", "align-items", "align-self", "justify-content", "gap", "grid-template-columns",
  "opacity", "overflow", "overflow-x", "overflow-y", "box-shadow", "outline", "outline-color",
  "transform", "object-fit", "vertical-align",
];

function removeHtml2CanvasBlockingStyles(clonedDoc) {
  if (!clonedDoc) return;
  clonedDoc.querySelectorAll('link[rel="stylesheet"]').forEach((node) => node.remove());
  clonedDoc.querySelectorAll("style").forEach((node) => node.remove());
}

function inlineHtml2CanvasSafeStyles(sourceRoot, cloneRoot) {
  if (!sourceRoot || !cloneRoot) return;
  const sourceNodes = [sourceRoot, ...sourceRoot.querySelectorAll("*")];
  const cloneNodes = [cloneRoot, ...cloneRoot.querySelectorAll("*")];
  cloneNodes.forEach((cloneEl, index) => {
    const sourceEl = sourceNodes[index];
    if (!(sourceEl instanceof Element) || !(cloneEl instanceof Element)) return;
    const computed = window.getComputedStyle(sourceEl);
    HTML2CANVAS_INLINE_PROPS.forEach((prop) => {
      const value = computed.getPropertyValue(prop);
      if (value) cloneEl.style.setProperty(prop, value);
    });
  });
}

function addShareCapturePseudoBars(cardClone, sourceCard) {
  if (!cardClone || !sourceCard) return;
  const beforeStyle = window.getComputedStyle(sourceCard, "::before");
  if (beforeStyle.content && beforeStyle.content !== "none") {
    const bar = document.createElement("span");
    bar.setAttribute("aria-hidden", "true");
    bar.style.cssText =
      "position:absolute;left:0;top:0;bottom:0;width:" +
      beforeStyle.width +
      ";background:" +
      beforeStyle.backgroundColor +
      ";pointer-events:none;z-index:0;";
    cardClone.insertBefore(bar, cardClone.firstChild);
  }
  const afterStyle = window.getComputedStyle(sourceCard, "::after");
  if (afterStyle.content && afterStyle.content !== "none") {
    const bar = document.createElement("span");
    bar.setAttribute("aria-hidden", "true");
    bar.style.cssText =
      "position:absolute;right:0;top:0;bottom:0;width:" +
      afterStyle.width +
      ";background:" +
      afterStyle.backgroundColor +
      ";pointer-events:none;z-index:0;";
    cardClone.appendChild(bar);
  }
}

function prepareHtml2CanvasClone(clonedDoc, sourceWrapper, clonedWrapper, sourceCard) {
  removeHtml2CanvasBlockingStyles(clonedDoc);
  inlineHtml2CanvasSafeStyles(sourceWrapper, clonedWrapper);
  const cloneCard = clonedWrapper.querySelector(".alert-card");
  if (cloneCard && sourceCard) {
    addShareCapturePseudoBars(cloneCard, sourceCard);
  }
}

function waitForShareImages(root, timeoutMs = 4500) {
  const imgs = Array.from(root.querySelectorAll("img")).filter((img) => String(img.src || "").trim());
  if (!imgs.length) return Promise.resolve();
  return Promise.all(
    imgs.map(
      (img) =>
        new Promise((resolve) => {
          if (img.complete && img.naturalWidth > 0) {
            resolve();
            return;
          }
          const done = () => resolve();
          img.addEventListener("load", done, { once: true });
          img.addEventListener("error", done, { once: true });
          window.setTimeout(done, timeoutMs);
        })
    )
  );
}

function buildAlertShareCaptureElement(sourceCard, item) {
  const wrapper = document.createElement("div");
  wrapper.className = "mobile-share-capture";

  const cardClone = sourceCard.cloneNode(true);
  cardClone.classList.remove("alert-card-highlight", "is-expanded");
  cardClone.querySelectorAll(".alert-card-actions, .alert-card-headsup, .alert-more").forEach((el) => el.remove());
  setUsageBarFinalValue(cardClone);
  syncClonedImages(sourceCard, cardClone);

  const detail = document.createElement("section");
  detail.className = "alert-detail-panel mobile-share-capture-detail";
  detail.innerHTML = buildAlertDetailHtml(item);

  const cardWidth = Math.max(280, Math.round(sourceCard.getBoundingClientRect().width || 0));
  wrapper.style.width = cardWidth + "px";
  wrapper.appendChild(cardClone);
  wrapper.appendChild(detail);
  return wrapper;
}

function buildAlertShareText(item) {
  const customer = String(item.customer_name || "").trim();
  const hostLabel = String(item.display_name || item.hostname || "-").trim();
  const hostname = String(item.hostname || "").trim();
  const mount = String(item.mountpoint || "-").trim();
  const percent = usagePercentForBar(item).toFixed(1);
  const lines = [
    "SYSTEM Infoboard Alert #" + String(item.id || ""),
    "Severity: " + String(item.severity || "").toUpperCase(),
  ];
  if (customer) lines.push("Kunde: " + customer);
  lines.push("Host: " + hostLabel);
  if (hostname && hostname !== hostLabel) lines.push("Hostname: " + hostname);
  lines.push("Mountpoint: " + mount);
  lines.push("Aktuell: " + percent + "%");
  return lines.join("\n");
}

function downloadShareBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.rel = "noopener";
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 2000);
}

async function shareAlertCard(card) {
  const item = resolveAlertFromCard(card);
  if (!item || !card) return;

  showToast("Bild wird erstellt…", false);

  const captureRoot = document.getElementById("mobileShareCaptureRoot");
  if (!captureRoot) {
    showToast("Teilen nicht verfügbar.", true);
    return;
  }

  try {
    const html2canvas = await loadHtml2Canvas();
    const wrapper = buildAlertShareCaptureElement(card, item);
    captureRoot.innerHTML = "";
    captureRoot.appendChild(wrapper);
    await waitForShareImages(wrapper);
    inlineHtml2CanvasSafeStyles(wrapper, wrapper);
    const captureCard = wrapper.querySelector(".alert-card");
    if (captureCard) addShareCapturePseudoBars(captureCard, card);

    const canvas = await withDetachedPageStylesheets(() =>
      html2canvas(wrapper, {
        backgroundColor: "#ffffff",
        scale: Math.min(2, Math.max(1.5, window.devicePixelRatio || 1.5)),
        useCORS: true,
        logging: false,
        onclone: (clonedDoc, clonedWrapper) => {
          prepareHtml2CanvasClone(clonedDoc, wrapper, clonedWrapper, card);
        },
      })
    );
    captureRoot.innerHTML = "";

    const blob = await new Promise((resolve, reject) => {
      canvas.toBlob((value) => {
        if (value) resolve(value);
        else reject(new Error("PNG-Erstellung fehlgeschlagen"));
      }, "image/png", 0.95);
    });

    const alertId = Number(item.id || 0);
    const filename = "system-infoboard-alert-" + (alertId || "share") + ".png";
    const file = new File([blob], filename, { type: "image/png" });
    const title = "SYSTEM Infoboard · Alert #" + (alertId || "");

    if (navigator.share) {
      const sharePayload = { files: [file], title };
      if (!navigator.canShare || navigator.canShare({ files: [file] })) {
        await navigator.share(sharePayload);
        showToast("Geteilt.", false);
        return;
      }
      await navigator.share({ title, text: buildAlertShareText(item) });
      showToast("Als Text geteilt.", false);
      return;
    }

    downloadShareBlob(blob, filename);
    showToast("Bild gespeichert.", false);
  } catch (error) {
    captureRoot.innerHTML = "";
    if (error?.name === "AbortError") return;
    showToast("Teilen fehlgeschlagen: " + (error?.message || String(error)), true);
  }
}

function cancelUsageBarAnimation(card) {
  if (!card) return;
  const animState = usageBarAnimStates.get(card);
  if (animState?.frameId) {
    window.cancelAnimationFrame(animState.frameId);
  }
  if (animState) {
    animState.cancelled = true;
  }
  usageBarAnimStates.delete(card);
}

function resetUsageBarToZero(card) {
  if (!card) return;
  cancelUsageBarAnimation(card);
  const fill = card.querySelector(".usage-bar-fill");
  const counter = card.querySelector(".usage-bar-counter");
  if (!fill || !counter) return;
  fill.style.width = "0%";
  counter.textContent = "0.0%";
}

function setUsageBarFinalValue(card) {
  if (!card) return;
  cancelUsageBarAnimation(card);
  const fill = card.querySelector(".usage-bar-fill");
  const counter = card.querySelector(".usage-bar-counter");
  if (!fill || !counter) return;
  const target = Number(fill.getAttribute("data-target-percent"));
  if (!Number.isFinite(target)) return;
  fill.style.width = target + "%";
  counter.textContent = target.toFixed(1) + "%";
}

function animateUsageBarForCard(card) {
  if (!card) return;
  const fill = card.querySelector(".usage-bar-fill");
  const counter = card.querySelector(".usage-bar-counter");
  if (!fill || !counter) return;

  const target = Number(fill.getAttribute("data-target-percent"));
  if (!Number.isFinite(target)) return;

  cancelUsageBarAnimation(card);

  if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    setUsageBarFinalValue(card);
    return;
  }

  fill.style.width = "0%";
  counter.textContent = "0.0%";
  const start = performance.now();
  const animState = { cancelled: false, frameId: 0 };
  usageBarAnimStates.set(card, animState);

  const tick = (now) => {
    if (animState.cancelled) return;
    const progress = Math.min(1, (now - start) / USAGE_BAR_ANIMATION_MS);
    const eased = 1 - Math.pow(1 - progress, 3);
    const value = target * eased;
    fill.style.width = value + "%";
    counter.textContent = value.toFixed(1) + "%";
    if (progress < 1) {
      animState.frameId = window.requestAnimationFrame(tick);
    } else {
      fill.style.width = target + "%";
      counter.textContent = target.toFixed(1) + "%";
      usageBarAnimStates.delete(card);
    }
  };

  animState.frameId = window.requestAnimationFrame(tick);
}

function triggerUsageBarAnimationForCarouselIndex(list, index) {
  const cards = list.querySelectorAll(".alert-card");
  if (!cards.length) return;

  cards.forEach((card) => {
    const cardIndex = Number(card.getAttribute("data-alert-index"));
    if (cardIndex !== index) {
      resetUsageBarToZero(card);
    }
  });

  const focusedCard = Array.from(cards).find((card) => Number(card.getAttribute("data-alert-index")) === index);
  animateUsageBarForCard(focusedCard);
}

function buildHeadsUpActionButton(item) {
  const isSuppressed = item.is_heads_up_suppressed === true;
  const label = isSuppressed ? "Heads-up wieder aktivieren" : "Heads-up unterdrücken";
  const icon = isSuppressed ? "⏸️" : "📣";
  const extraClass = isSuppressed ? " is-suppressed" : "";
  return (
    '<button type="button" class="btn-secondary btn-headsup' + extraClass + '" data-action="toggle-headsup" '
    + 'data-headsup-suppressed="' + (isSuppressed ? "1" : "0") + '" aria-pressed="' + (isSuppressed ? "true" : "false") + '">'
    + mobileEsc(icon + " " + label) + "</button>"
  );
}

function parseUtcIso(value) {
  const raw = String(value || "").trim();
  if (!raw) return null;
  const normalized = raw.includes("T") ? raw : raw.replace(" ", "T");
  const withZone = /(?:Z|[+-]\d{2}:?\d{2})$/i.test(normalized) ? normalized : normalized + "Z";
  const parsed = new Date(withZone);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function isHostActive(host) {
  if (!host) return false;
  if (host.online === true) {
    return true;
  }
  const parsedLastSeen = parseUtcIso(host.last_seen_utc || host.last_report_utc || "");
  if (!parsedLastSeen) {
    return false;
  }
  return Date.now() - parsedLastSeen.getTime() <= 60 * 60 * 1000;
}

function countActiveHosts(hosts) {
  return (Array.isArray(hosts) ? hosts : []).filter((host) => isHostActive(host)).length;
}

function renderHostKpis() {
  const elActive = document.getElementById("kpiActiveHosts");
  const elInactive = document.getElementById("kpiInactiveHosts");
  if (elActive) elActive.textContent = String(Math.max(0, Number(state.activeHostsCount) || 0));
  if (elInactive) elInactive.textContent = String(Math.max(0, Number(state.inactiveHostsCount) || 0));
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
  renderHostKpis();
}

async function loadHostKpis(options = {}) {
  if (!state.authenticated) {
    return;
  }
  const authRetried = options.authRetried === true;

  const hours = Math.max(1, Math.min(24 * 30, Number(state.hostKpisHours) || 1));
  try {
    const [inactiveResp, hostsResp] = await Promise.all([
      fetch("/api/v1/inactive-hosts?hours=" + encodeURIComponent(String(hours)), { credentials: "same-origin" }),
      fetch("/api/v1/hosts?limit=200&offset=0", { credentials: "same-origin" }),
    ]);

    if (inactiveResp.status === 401 || hostsResp.status === 401) {
      if (!authRetried && (await mobileRecoverSessionAfter401())) {
        return loadHostKpis({ authRetried: true });
      }
      mobileForceLogout("Session abgelaufen. Bitte erneut anmelden.");
      return;
    }

    if (inactiveResp.ok) {
      const inactivePayload = await inactiveResp.json();
      state.inactiveHostsCount = Math.max(0, Number(inactivePayload.total || 0));
    }

    if (hostsResp.ok) {
      const hostsPayload = await hostsResp.json();
      const hosts = Array.isArray(hostsPayload.hosts) ? hostsPayload.hosts : [];
      state.activeHostsCount = countActiveHosts(hosts);
    }

    renderHostKpis();
  } catch (_error) {
    // Host-KPIs sind optional; Alert-Liste bleibt nutzbar.
  }
}

async function refreshMobileData() {
  if (isInactiveHostsViewActive()) {
    await Promise.all([loadInactiveHostsList(), loadHostKpis()]);
    return;
  }
  if (isActiveHostsViewActive()) {
    await Promise.all([loadActiveHostsList(), loadHostKpis()]);
    return;
  }
  if (isAddonSearchViewActive()) {
    await Promise.all([loadAddonSearchResults({ force: true }), loadHostKpis()]);
    return;
  }
  await Promise.all([loadAlerts(), loadHostKpis()]);
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
    const identityHtml = buildAlertIdentityHtml(item);
    const envClass = buildEnvironmentCardClass(item.environment_type);
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
    const itContactHtml = buildAlertItContactLineHtml(item);
    const muteBtn = buildMuteButtonHtml(item);

    return (
      '<article class="alert-card ' + sev + envClass + highlightClass + '" data-alert-id="' + id + '" data-alert-index="' + index + '">' +
      '  <div class="alert-card-head">' +
      '    <div class="alert-status-group">' +
      '      <span class="severity-badge ' + sev + '">' + mobileEsc(sev) + "</span>" +
      "    </div>" +
      '    <div class="alert-head-center">' + countryFlag + "</div>" +
      '    <span class="alert-time">' + mobileEsc(timeLabel || "—") + "</span>" +
      "  </div>" +
      "  " + identityHtml +
      '<div class="alert-card-body">' +
      ackStrip +
      itContactHtml +
      '  <p class="alert-meta alert-mountpoint-line">' + buildMountpointLine(item) + "</p>" +
      '  <div class="usage-bar-block">' +
      '    <div class="usage-bar-row">' +
      '      <div class="usage-bar"><span class="usage-bar-fill" data-target-percent="' + barWidth + '" style="width:0%"></span></div>' +
      '      <strong class="usage-bar-counter" data-target-percent="' + barWidth + '">0.0%</strong>' +
      "    </div></div>" +
      '  <div class="alert-card-actions">' + ackBtn + muteBtn +
      '    <button type="button" class="btn-secondary btn-share" data-action="share" title="Teilen" aria-label="Alert teilen">Teilen</button>' +
      '    <button type="button" class="btn-secondary btn-expand" data-action="toggle-more">Mehr</button>' +
      "  </div>" +
      '  <div class="alert-card-headsup">' + buildHeadsUpActionButton(item) + "</div>" +
      '  <div class="alert-more">' + moreHtml +
      '    <div style="margin-top:10px;display:grid;grid-template-columns:1fr 1fr;gap:8px">' +
      '      <button type="button" class="btn-danger" data-action="close">Schliessen</button>' +
      "    </div></div></div>" +
      "</article>"
    );
  }).join("");

  lastUsageBarCarouselIndex = -1;
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
  const itHtml = buildItContactHtml(item);
  if (itHtml) {
    lines.push("<div><dt>" + mobileEsc("IT-Kontakt") + "</dt><dd>" + itHtml + "</dd></div>");
  }
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
  if (bestIndex !== lastUsageBarCarouselIndex) {
    triggerUsageBarAnimationForCarouselIndex(list, bestIndex);
    lastUsageBarCarouselIndex = bestIndex;
  }
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

  if (action === "share") {
    void shareAlertCard(card);
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
    } else if (action === "toggle-headsup") {
      const item = resolveAlertFromCard(card);
      const suppressed = item?.is_heads_up_suppressed === true
        || btn.getAttribute("data-headsup-suppressed") === "1";
      const endpoint = suppressed
        ? "/api/v1/alert-headsup-unsuppress"
        : "/api/v1/alert-headsup-suppress";
      const okMessage = suppressed ? "Heads-up wieder aktiv." : "Heads-up unterdrückt.";
      await callAlertAction(endpoint, { alert_id: id }, okMessage);
      await loadAlerts();
    } else if (action === "toggle-mute") {
      const item = resolveAlertFromCard(card);
      const isMuted = item?.is_muted === true || btn.getAttribute("data-muted") === "1";
      const endpoint = isMuted ? "/api/v1/alert-unmute" : "/api/v1/alert-mute";
      await callAlertAction(endpoint, {
        alert_id: id,
        hostname: String(item?.hostname || ""),
        host_uid: String(item?.host_uid || ""),
        mountpoint: String(item?.mountpoint || ""),
      }, isMuted ? "Stummschaltung aufgehoben." : "Alert stummgeschaltet.");
      await loadAlerts();
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

async function loadAlerts(options = {}) {
  if (!state.authenticated) {
    showLoginOverlay(true);
    return;
  }
  const authRetried = options.authRetried === true;

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
      if (!authRetried && (await mobileRecoverSessionAfter401())) {
        return loadAlerts({ authRetried: true });
      }
      mobileForceLogout("Session abgelaufen. Bitte erneut anmelden.");
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
    mobileSessionEstablishedAtMs = Date.now();
    updateUserLine();
    showLoginOverlay(false);
    setLoginStatus("");
    startMobileSessionKeepAlive();
    initMobileLiveReportFeed();
    await loadMobileSapB1VersionMap();
    await refreshPushState();
    await refreshMobileData();
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
        void refreshMobileData().catch((error) => setStatus("Fehler: " + error.message, true));
      }
    },
    { passive: true }
  );
}

function mobileFormatNumber(value, digits = 0) {
  const num = Number(value);
  if (!Number.isFinite(num)) return "-";
  return num.toLocaleString("de-CH", {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  });
}

function formatHostLastReportClockMobile(reportUtcValue) {
  const raw = String(reportUtcValue || "").trim();
  if (!raw || raw === "-") {
    return {
      label: "--:--",
      title: "Noch kein Report empfangen",
    };
  }
  const parsed = new Date(raw.includes("T") ? raw : raw.replace(" ", "T") + (raw.endsWith("Z") ? "" : "Z"));
  if (Number.isNaN(parsed.getTime())) {
    return {
      label: "--:--",
      title: "Ungültiger Zeitstempel: " + raw,
    };
  }
  return {
    label: parsed.toLocaleTimeString("de-CH", { hour: "2-digit", minute: "2-digit" }),
    title: "Letzter Report: " + formatUtcPlus2Mobile(raw),
  };
}

function isMobileLiveReportEventVisible(event) {
  return Boolean(event && !event.is_hidden && String(event.hostname || "").trim());
}

function resolveMobileLiveReportCustomerLogoUrl(event) {
  return String(event?.customer_logo_url || "").trim();
}

function buildMobileLiveReportFeedPreviewFromEvent(event) {
  const deliveryMode = String(event?.delivery_mode || "live").toLowerCase();
  const deliveryLabel = deliveryMode === "delayed" ? "DELAYED" : "LIVE";
  const deliveryClass = deliveryMode === "delayed" ? "delivery-chip delayed" : "delivery-chip live";
  const customerName = String(event?.customer_name || "Kein Kunde").trim() || "Kein Kunde";
  const hostname = String(event?.hostname || "-");
  const hostIdentity = String(event?.host_uid || "").trim() || hostname;
  const customerLogoUrl = resolveMobileLiveReportCustomerLogoUrl(event);
  const designation = String(event?.display_name || hostname).trim() || hostname;
  const shortHostname = hostname.split(".")[0] || hostname;
  const ip = String(event?.std_nic_ip || event?.primary_ip || "-");
  const reportTs = String(event?.received_at_utc || "");
  const clock = formatHostLastReportClockMobile(reportTs);
  const metrics = [];
  if (Number.isFinite(Number(event?.cpu_usage_percent))) {
    metrics.push("CPU " + mobileFormatNumber(event.cpu_usage_percent, 1) + "%");
  }
  if (Number.isFinite(Number(event?.memory_used_percent))) {
    metrics.push("RAM " + mobileFormatNumber(event.memory_used_percent, 1) + "%");
  }
  return {
    id: hostIdentity + "|" + String(event?.report_id || reportTs || Date.now()),
    hostIdentity,
    hostname,
    customerName,
    customerLogoUrl,
    designation,
    shortHostname,
    ip,
    clockLabel: clock.label,
    clockTitle: clock.title,
    metricsText: metrics.join(" · "),
    deliveryMode,
    deliveryLabel,
    deliveryClass,
    receivedAtUtc: reportTs,
  };
}

function hostRecordFromLiveFeedItem(item) {
  return {
    hostname: item.hostname,
    host_uid: item.hostIdentity,
    display_name: item.designation,
    customer_name: item.customerName,
  };
}

async function fetchMobileHostRecord(hostUid, hostname, options = {}) {
  const authRetried = options.authRetried === true;
  const identity = String(hostUid || "").trim();
  const host = String(hostname || "").trim();
  if (!identity && !host) return null;

  try {
    const resp = await fetch("/api/v1/hosts?limit=200&offset=0", { credentials: "same-origin" });
    if (resp.status === 401) {
      if (!authRetried && (await mobileRecoverSessionAfter401())) {
        return fetchMobileHostRecord(hostUid, hostname, { authRetried: true });
      }
      return null;
    }
    if (!resp.ok) return null;
    const data = await resp.json().catch(() => ({}));
    const hosts = Array.isArray(data?.hosts) ? data.hosts : [];
    return (
      hosts.find((entry) => {
        const entryUid = String(entry?.host_uid || "").trim();
        const entryHost = String(entry?.hostname || "").trim();
        return (identity && entryUid === identity) || (host && entryHost === host);
      }) || null
    );
  } catch (_error) {
    return null;
  }
}

async function openHostInsightFromLiveFeedItem(item) {
  if (!item) return;
  const hostname = String(item.hostname || "").trim();
  const hostIdentity = String(item.hostIdentity || "").trim();
  const hostRecord = (await fetchMobileHostRecord(hostIdentity, hostname)) || hostRecordFromLiveFeedItem(item);
  const variant = isHostActive(hostRecord) ? "active" : "inactive";
  void openHostInsightCarousel(hostRecord, variant);
}

function loadMobileLiveReportFeedEnabled() {
  try {
    const raw = window.localStorage.getItem(LIVE_REPORT_FEED_ENABLED_KEY);
    if (raw === null) return true;
    return raw !== "0" && raw !== "false";
  } catch (_error) {
    return true;
  }
}

function persistMobileLiveReportFeedEnabled(enabled) {
  try {
    window.localStorage.setItem(LIVE_REPORT_FEED_ENABLED_KEY, enabled ? "1" : "0");
  } catch (_error) {
    // Ignore storage failures.
  }
}

function updateMobileLiveReportFeedToggleUi() {
  const button = document.getElementById("liveReportFeedToggleButton");
  if (!button) return;
  button.setAttribute("aria-pressed", liveReportFeedEnabled ? "true" : "false");
  const label = liveReportFeedEnabled ? "Live Meldungen ausblenden" : "Live Meldungen einblenden";
  button.title = label;
  button.setAttribute("aria-label", label);
}

function setMobileLiveReportFeedEnabled(enabled) {
  liveReportFeedEnabled = Boolean(enabled);
  persistMobileLiveReportFeedEnabled(liveReportFeedEnabled);
  updateMobileLiveReportFeedToggleUi();
  renderMobileLiveReportFeed();
}

function toggleMobileLiveReportFeedEnabled() {
  setMobileLiveReportFeedEnabled(!liveReportFeedEnabled);
}

function showMobileLiveReportFeedPanelFromMenu() {
  document.getElementById("headerMenu")?.classList.add("hidden");
  setMobileLiveReportFeedEnabled(true);
}

function openLatestMobileLiveReportDetailsFromMenu() {
  document.getElementById("headerMenu")?.classList.add("hidden");
  const latest = liveReportFeedItems[0];
  if (!latest) {
    showToast("Noch keine Live-Meldungen.", false);
    return;
  }
  void openHostInsightFromLiveFeedItem(latest);
}

function buildMobileLiveReportFeedCustomerWatermarkHtml(customerLogoUrl) {
  const url = String(customerLogoUrl || "").trim();
  if (!url) {
    return "";
  }
  return (
    '<div class="live-report-feed-customer-bg-watermark" aria-hidden="true">' +
      '<img src="' + mobileEsc(url) + '" alt="" class="live-report-feed-customer-bg-watermark-logo" loading="lazy" decoding="async" onerror="this.closest(\'.live-report-feed-customer-bg-watermark\')?.remove()">' +
    "</div>"
  );
}

function buildMobileLiveReportFeedItemInnerHtml(item) {
  const statsHtml = item.metricsText
    ? '<span class="live-report-feed-stats">' + mobileEsc(item.metricsText) + "</span>"
    : '<span class="live-report-feed-stats live-report-feed-stats--empty" aria-hidden="true"></span>';
  const customerWatermarkHtml = buildMobileLiveReportFeedCustomerWatermarkHtml(item.customerLogoUrl);
  return (
    customerWatermarkHtml +
    '<div class="live-report-feed-item-grid">' +
      '<div class="live-report-feed-item-head">' +
        '<span class="live-report-feed-customer-row">' +
          '<span class="live-report-feed-customer" title="' + mobileEsc(item.customerName) + '">' + mobileEsc(item.customerName) + "</span>" +
        "</span>" +
        '<time class="live-report-feed-time" datetime="' + mobileEsc(item.receivedAtUtc) + '" title="' + mobileEsc(item.clockTitle) + '">' + mobileEsc(item.clockLabel) + "</time>" +
      "</div>" +
      '<p class="live-report-feed-designation" title="' + mobileEsc(item.designation) + '">' + mobileEsc(item.designation) + "</p>" +
      '<p class="live-report-feed-hostline">' +
        '<span class="live-report-feed-host-meta">' +
          '<span class="live-report-feed-hostname" title="' + mobileEsc(item.shortHostname) + '">' + mobileEsc(item.shortHostname) + "</span>" +
          '<span class="live-report-feed-sep" aria-hidden="true">·</span>' +
          '<span class="live-report-feed-ip" title="' + mobileEsc(item.ip) + '">' + mobileEsc(item.ip) + "</span>" +
        "</span>" +
        '<span class="' + mobileEsc(item.deliveryClass) + '">' + mobileEsc(item.deliveryLabel) + "</span>" +
      "</p>" +
      '<div class="live-report-feed-item-foot">' +
        statsHtml +
      "</div>" +
    "</div>"
  );
}

function createMobileLiveReportFeedItemElement(item, extraClasses = []) {
  const button = document.createElement("button");
  button.type = "button";
  const classes = ["live-report-feed-item"];
  if (item.isNew) classes.push("is-new");
  extraClasses.forEach((extraClass) => {
    if (extraClass) classes.push(extraClass);
  });
  button.className = classes.join(" ");
  button.dataset.liveFeedId = item.id;
  button.dataset.liveFeedHost = item.hostname;
  button.dataset.liveFeedUid = item.hostIdentity;
  button.innerHTML = buildMobileLiveReportFeedItemInnerHtml(item);
  return button;
}

function renderMobileLiveReportFeedStatic(body) {
  body.innerHTML = liveReportFeedItems
    .map((item) => {
      const extraClass = item.isNew ? " is-new" : "";
      return (
        '<button type="button" class="live-report-feed-item' + extraClass + '" data-live-feed-id="' + mobileEsc(item.id) + '" data-live-feed-host="' + mobileEsc(item.hostname) + '" data-live-feed-uid="' + mobileEsc(item.hostIdentity) + '">' +
        buildMobileLiveReportFeedItemInnerHtml(item) +
        "</button>"
      );
    })
    .join("");
  liveReportFeedItems.forEach((item) => {
    item.isNew = false;
  });
}

function animateMobileLiveReportFeedDom(body) {
  const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (prefersReducedMotion) {
    renderMobileLiveReportFeedStatic(body);
    return;
  }

  const previousRects = new Map();
  body.querySelectorAll(".live-report-feed-item").forEach((element) => {
    const itemId = String(element.dataset.liveFeedId || "");
    if (itemId) previousRects.set(itemId, element.getBoundingClientRect());
  });

  const desiredIds = liveReportFeedItems.map((item) => item.id);
  const existingElements = new Map();
  body.querySelectorAll(".live-report-feed-item").forEach((element) => {
    const itemId = String(element.dataset.liveFeedId || "");
    if (itemId) existingElements.set(itemId, element);
  });

  for (const [itemId, element] of existingElements.entries()) {
    if (!desiredIds.includes(itemId)) element.remove();
  }

  body.classList.add("is-animating");
  for (let index = 0; index < liveReportFeedItems.length; index += 1) {
    const item = liveReportFeedItems[index];
    let element = existingElements.get(item.id);
    const extraClasses = [];
    if (!element) {
      if (item.isNew) extraClasses.push("is-entering");
      element = createMobileLiveReportFeedItemElement(item, extraClasses);
      body.insertBefore(element, body.children[index] || null);
      continue;
    }
    if (item.isNew) element.classList.add("is-new");
    if (body.children[index] !== element) {
      body.insertBefore(element, body.children[index] || null);
    }
  }

  window.requestAnimationFrame(() => {
    body.querySelectorAll(".live-report-feed-item:not(.is-exiting)").forEach((element) => {
      const itemId = String(element.dataset.liveFeedId || "");
      const previousRect = previousRects.get(itemId);
      if (!previousRect) return;
      const nextRect = element.getBoundingClientRect();
      const deltaY = previousRect.top - nextRect.top;
      if (Math.abs(deltaY) < 1) return;
      element.style.transform = "translateY(" + deltaY + "px)";
      element.style.transition = "none";
      window.requestAnimationFrame(() => {
        element.style.transition = "transform 0.38s cubic-bezier(0.22, 1, 0.36, 1)";
        element.style.transform = "";
      });
    });

    body.querySelectorAll(".live-report-feed-item.is-entering").forEach((element) => {
      window.requestAnimationFrame(() => element.classList.remove("is-entering"));
    });

    window.setTimeout(() => {
      body.classList.remove("is-animating");
      body.querySelectorAll(".live-report-feed-item").forEach((element) => {
        element.style.transition = "";
        element.style.transform = "";
      });
    }, 420);
  });

  liveReportFeedItems.forEach((item) => {
    item.isNew = false;
  });
}

function renderMobileLiveReportFeed(options = {}) {
  wireMobileLiveReportFeed();
  const panel = document.getElementById("liveReportFeed");
  const body = document.getElementById("liveReportFeedBody");
  const countEl = document.getElementById("liveReportFeedCount");
  if (!panel || !body) return;
  if (!liveReportFeedEnabled || liveReportFeedItems.length === 0) {
    panel.classList.add("hidden");
    return;
  }
  panel.classList.remove("hidden");
  panel.classList.toggle("is-minimized", liveReportFeedMinimized);
  if (countEl) countEl.textContent = String(liveReportFeedItems.length);

  const shouldAnimate = Boolean(options.animate) && body.childElementCount > 0;
  if (shouldAnimate) {
    animateMobileLiveReportFeedDom(body);
    return;
  }
  renderMobileLiveReportFeedStatic(body);
}

function applyMobileLiveReportFeedPosition() {
  const panel = document.getElementById("liveReportFeed");
  if (!panel) return;
  try {
    const raw = window.localStorage.getItem(LIVE_REPORT_FEED_POSITION_KEY);
    if (!raw) return;
    const parsed = JSON.parse(raw);
    const left = Number(parsed?.left);
    const top = Number(parsed?.top);
    if (!Number.isFinite(left) || !Number.isFinite(top)) return;
    panel.style.left = left + "px";
    panel.style.top = top + "px";
    panel.style.transform = "none";
  } catch (_error) {
    // Ignore invalid persisted position.
  }
}

function persistMobileLiveReportFeedPosition(panel) {
  if (!panel) return;
  const rect = panel.getBoundingClientRect();
  try {
    window.localStorage.setItem(
      LIVE_REPORT_FEED_POSITION_KEY,
      JSON.stringify({ left: Math.round(rect.left), top: Math.round(rect.top) })
    );
  } catch (_error) {
    // Ignore storage failures.
  }
}

function enqueueMobileLiveReportFeedFromEvents(events) {
  if (!Array.isArray(events) || events.length === 0) return;
  const sortedEvents = [...events].sort(
    (left, right) => (Number(right?.report_id) || 0) - (Number(left?.report_id) || 0)
  );
  for (const event of sortedEvents) {
    const preview = buildMobileLiveReportFeedPreviewFromEvent(event);
    preview.isNew = true;
    liveReportFeedItems = [preview, ...liveReportFeedItems.filter((item) => item.id !== preview.id)];
  }
  liveReportFeedItems = liveReportFeedItems.slice(0, LIVE_REPORT_FEED_MAX_ITEMS);
  renderMobileLiveReportFeed({ animate: true });
}

function stopMobileLiveReportPoll() {
  if (liveReportPollTimerId !== null) {
    window.clearInterval(liveReportPollTimerId);
    liveReportPollTimerId = null;
  }
  liveReportPollInFlight = false;
}

function resetMobileLiveReportFeed() {
  stopMobileLiveReportPoll();
  liveReportFeedItems = [];
  liveReportPollCursorId = 0;
  renderMobileLiveReportFeed();
}

function getLiveReportPollIntervalMs() {
  return state.pushEnabled ? LIVE_REPORT_POLL_INTERVAL_FAST_MS : LIVE_REPORT_POLL_INTERVAL_MS;
}

function buildLiveReportPushPayloadFromEvent(event) {
  const preview = buildMobileLiveReportFeedPreviewFromEvent(event);
  const hostUid = String(event?.host_uid || preview.hostIdentity || preview.hostname || "").trim();
  const hostname = String(event?.hostname || preview.hostname || "").trim();
  const hostKey = hostUid || hostname;
  const metricsLine = String(preview.metricsText || "").trim();
  const bodyLines = [
    preview.designation,
    preview.shortHostname + " · " + preview.ip,
  ];
  if (metricsLine) {
    bodyLines.push(metricsLine);
  }
  bodyLines.push(preview.deliveryLabel);
  const nowLabel = new Date().toLocaleTimeString("de-CH", { hour: "2-digit", minute: "2-digit" });
  let dashboardBody = "Neu " + nowLabel + ": " + preview.customerName + " · " + preview.shortHostname;
  if (metricsLine) {
    dashboardBody += " · " + metricsLine;
  }
  return {
    kind: "live-report",
    title: "📡 " + preview.customerName,
    body: bodyLines.filter(Boolean).join(" · "),
    icon: "/icons/logo.png",
    badge: "/icons/logo.png",
    tag: "live-report:" + hostKey,
    renotify: true,
    silent: false,
    autoCloseMs: 5 * 60 * 1000,
    vibrate: [70, 35, 70],
    actions: [{ action: "open", title: "Öffnen" }],
    dashboard: {
      kind: "live-dashboard",
      title: "Live Monitoring",
      body: dashboardBody,
      tag: "monitoring-live-dashboard",
      renotify: false,
      persistent: true,
    },
    data: {
      url: "/mobile/alerts",
      kind: "live-report",
      report_id: Number(event?.report_id || 0),
      hostname,
      host_uid: hostKey,
      delivery_mode: preview.deliveryMode,
    },
  };
}

function filterLiveReportEventsForPushCooldown(events) {
  const nowMs = Date.now();
  const eligible = [];
  for (const event of Array.isArray(events) ? events : []) {
    const hostKey = String(event?.host_uid || event?.hostname || "").trim();
    if (!hostKey) {
      continue;
    }
    const lastPushMs = Number(liveReportPushCooldownByHost.get(hostKey) || 0);
    if (lastPushMs > 0 && nowMs - lastPushMs < LIVE_REPORT_PUSH_COOLDOWN_MS) {
      continue;
    }
    liveReportPushCooldownByHost.set(hostKey, nowMs);
    eligible.push(event);
  }
  return eligible;
}

async function postLiveReportEventsToServiceWorker(events) {
  if (!Array.isArray(events) || !events.length || !("serviceWorker" in navigator)) {
    return;
  }
  const eligibleEvents = filterLiveReportEventsForPushCooldown(events);
  if (!eligibleEvents.length) {
    return;
  }
  try {
    const registration = await getServiceWorkerRegistration();
    const worker = registration.active || registration.waiting || registration.installing;
    if (!worker) {
      return;
    }
    worker.postMessage({
      type: "live-report-feed-update",
      events: eligibleEvents.map(buildLiveReportPushPayloadFromEvent),
    });
  } catch (_error) {
    // Best effort when polling finds events while the app is backgrounded.
  }
}

function startMobileLiveReportPoll() {
  stopMobileLiveReportPoll();
  if (!state.authenticated) return;
  void pollMobileLiveReportEvents();
  liveReportPollTimerId = window.setInterval(() => {
    void pollMobileLiveReportEvents();
  }, getLiveReportPollIntervalMs());
}

async function pollMobileLiveReportEvents() {
  if (!state.authenticated || liveReportPollInFlight) return;
  liveReportPollInFlight = true;
  try {
    const query =
      liveReportPollCursorId > 0
        ? "since_id=" + encodeURIComponent(String(liveReportPollCursorId)) + "&limit=20"
        : "limit=20";
    const response = await fetch("/api/v1/live-report-events?" + query, {
      credentials: "same-origin",
      cache: "no-store",
    });
    if (response.status === 401) {
      stopMobileLiveReportPoll();
      return;
    }
    if (!response.ok) return;
    const data = await response.json().catch(() => ({}));
    const cursorId = Number(data?.cursor_id);
    if (Number.isFinite(cursorId) && cursorId >= 0) {
      liveReportPollCursorId = cursorId;
    }
    const events = Array.isArray(data?.events) ? data.events : [];
    const visibleEvents = events.filter(isMobileLiveReportEventVisible);
    if (visibleEvents.length > 0) {
      enqueueMobileLiveReportFeedFromEvents(visibleEvents);
      if (state.pushEnabled && document.visibilityState !== "visible") {
        void postLiveReportEventsToServiceWorker(visibleEvents);
      }
    }
  } catch (_error) {
    // Keep polling on transient network failures.
  } finally {
    liveReportPollInFlight = false;
  }
}

function wireMobileLiveReportFeed() {
  if (liveReportFeedWired) return;
  const panel = document.getElementById("liveReportFeed");
  const body = document.getElementById("liveReportFeedBody");
  const minimizeBtn = document.getElementById("liveReportFeedMinimizeBtn");
  const closeBtn = document.getElementById("liveReportFeedCloseBtn");
  const dragHandle = panel ? panel.querySelector("[data-live-feed-drag-handle]") : null;
  if (!panel || !body || !dragHandle) return;
  liveReportFeedWired = true;

  applyMobileLiveReportFeedPosition();

  if (minimizeBtn) {
    minimizeBtn.addEventListener("click", (event) => {
      event.stopPropagation();
      liveReportFeedMinimized = !liveReportFeedMinimized;
      panel.classList.toggle("is-minimized", liveReportFeedMinimized);
      minimizeBtn.setAttribute("aria-expanded", liveReportFeedMinimized ? "false" : "true");
      minimizeBtn.textContent = liveReportFeedMinimized ? "+" : "−";
      minimizeBtn.title = liveReportFeedMinimized ? "Ausklappen" : "Einklappen";
    });
  }

  if (closeBtn) {
    closeBtn.addEventListener("click", (event) => {
      event.stopPropagation();
      setMobileLiveReportFeedEnabled(false);
    });
  }

  body.addEventListener("click", (event) => {
    const button = event.target instanceof Element ? event.target.closest(".live-report-feed-item") : null;
    if (!button) return;
    const itemId = String(button.getAttribute("data-live-feed-id") || "").trim();
    const item = liveReportFeedItems.find((entry) => entry.id === itemId);
    if (item) {
      void openHostInsightFromLiveFeedItem(item);
      return;
    }
    const hostname = String(button.getAttribute("data-live-feed-host") || "").trim();
    const hostUid = String(button.getAttribute("data-live-feed-uid") || "").trim();
    if (!hostname) return;
    void openHostInsightFromLiveFeedItem({
      hostname,
      hostIdentity: hostUid || hostname,
      designation: hostname,
      customerName: "",
    });
  });

  const onDragPointerMove = (event) => {
    if (!liveReportFeedDragState || liveReportFeedDragState.pointerId !== event.pointerId) return;
    const nextLeft = Math.max(8, Math.min(window.innerWidth - panel.offsetWidth - 8, event.clientX - liveReportFeedDragState.offsetX));
    const nextTop = Math.max(8, Math.min(window.innerHeight - 48, event.clientY - liveReportFeedDragState.offsetY));
    panel.style.left = nextLeft + "px";
    panel.style.top = nextTop + "px";
  };

  const endDrag = (event) => {
    if (!liveReportFeedDragState || liveReportFeedDragState.pointerId !== event.pointerId) return;
    liveReportFeedDragState = null;
    panel.classList.remove("is-dragging");
    persistMobileLiveReportFeedPosition(panel);
    document.removeEventListener("pointermove", onDragPointerMove);
    document.removeEventListener("pointerup", endDrag);
    document.removeEventListener("pointercancel", endDrag);
  };

  dragHandle.addEventListener("pointerdown", (event) => {
    if (event.button !== 0) return;
    const target = event.target instanceof Element ? event.target : null;
    if (target && target.closest("button")) return;
    event.preventDefault();
    const rect = panel.getBoundingClientRect();
    panel.style.left = rect.left + "px";
    panel.style.top = rect.top + "px";
    panel.style.transform = "none";
    liveReportFeedDragState = {
      pointerId: event.pointerId,
      offsetX: event.clientX - rect.left,
      offsetY: event.clientY - rect.top,
    };
    panel.classList.add("is-dragging");
    document.addEventListener("pointermove", onDragPointerMove);
    document.addEventListener("pointerup", endDrag);
    document.addEventListener("pointercancel", endDrag);
  });
}

function initMobileLiveReportFeed() {
  liveReportFeedEnabled = loadMobileLiveReportFeedEnabled();
  updateMobileLiveReportFeedToggleUi();
  wireMobileLiveReportFeed();
  renderMobileLiveReportFeed();
  startMobileLiveReportPoll();
}

function wire() {
  document.getElementById("kpiActiveNav")?.addEventListener("click", () => {
    if (!state.authenticated) return;
    showActiveHostsView();
  });

  document.getElementById("kpiInactiveNav")?.addEventListener("click", () => {
    if (!state.authenticated) return;
    showInactiveHostsView();
  });

  document.getElementById("menuAddonSearchButton")?.addEventListener("click", () => {
    document.getElementById("headerMenu")?.classList.add("hidden");
    showAddonSearchView();
  });

  document.getElementById("menuCustomerInfoButton")?.addEventListener("click", () => {
    document.getElementById("headerMenu")?.classList.add("hidden");
    void openCustomerInfoSheet();
  });

  document.getElementById("addonSearchBackButton")?.addEventListener("click", () => {
    showAlertsHomeView();
    setAddonSearchStatus("");
  });

  document.getElementById("addonSearchRefreshButton")?.addEventListener("click", () => {
    void loadAddonSearchResults({ force: true }).catch((error) => setAddonSearchStatus("Fehler: " + error.message, true));
  });

  document.querySelectorAll(".addon-search-group-chip[data-addon-group]").forEach((chip) => {
    chip.addEventListener("click", () => {
      const nextMode = normalizeAddonSearchGroupMode(chip.getAttribute("data-addon-group"));
      if (state.addonSearchGroupMode === nextMode) return;
      state.addonSearchGroupMode = nextMode;
      syncAddonSearchGroupChips();
      if (isAddonSearchViewActive()) updateAddonSearchView();
    });
  });

  document.getElementById("addonSearchInput")?.addEventListener("input", (event) => {
    state.addonSearchQuery = String(event.target?.value || "");
    if (!isAddonSearchViewActive()) return;
    if (state.addonSearchQuery.trim().length < ADDON_SEARCH_MIN_QUERY_LEN) {
      state.addonSearchLastData = null;
      state.addonSearchHostMap = {};
      updateAddonSearchView();
      return;
    }
    scheduleAddonSearchLoad();
  });

  document.getElementById("addonSearchList")?.addEventListener("click", handleAddonSearchListClick);

  document.getElementById("activeHostsBackButton")?.addEventListener("click", () => {
    showAlertsHomeView();
    setActiveHostsStatus("");
  });

  document.getElementById("inactiveHostsBackButton")?.addEventListener("click", () => {
    showAlertsHomeView();
    setInactiveHostsStatus("");
  });

  document.getElementById("activeHostsRefreshButton")?.addEventListener("click", () => {
    void loadActiveHostsList().catch((error) => setActiveHostsStatus("Fehler: " + error.message, true));
  });

  document.getElementById("inactiveHostsRefreshButton")?.addEventListener("click", () => {
    void loadInactiveHostsList().catch((error) => setInactiveHostsStatus("Fehler: " + error.message, true));
  });

  document.getElementById("activeHostsSearchInput")?.addEventListener("input", (event) => {
    state.activeHostsSearchQuery = String(event.target?.value || "");
    if (isActiveHostsViewActive() && !state.activeHostsLoading) {
      updateActiveHostsListView();
    }
  });

  document.getElementById("inactiveHostsSearchInput")?.addEventListener("input", (event) => {
    state.inactiveHostsSearchQuery = String(event.target?.value || "");
    if (isInactiveHostsViewActive() && !state.inactiveHostsLoading) {
      updateInactiveHostsListView(state.inactiveHostsHours);
    }
  });

  document.getElementById("activeHostsList")?.addEventListener("click", handleHostListSheetClick);
  document.getElementById("inactiveHostsList")?.addEventListener("click", handleHostListSheetClick);

  document.getElementById("hostInsightCloseBtn")?.addEventListener("click", closeHostInsightCarousel);
  document.getElementById("hostInsightOverlay")?.addEventListener("click", (event) => {
    if (event.target.id === "hostInsightOverlay") closeHostInsightCarousel();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape") return;
    const overlay = document.getElementById("hostInsightOverlay");
    if (overlay && !overlay.classList.contains("hidden")) closeHostInsightCarousel();
  });

  document.getElementById("refreshButton")?.addEventListener("click", () => {
    void refreshMobileData().catch((error) => {
      const msg = error?.message || String(error);
      if (isInactiveHostsViewActive()) {
        setInactiveHostsStatus("Fehler: " + msg, true);
      } else if (isActiveHostsViewActive()) {
        setActiveHostsStatus("Fehler: " + msg, true);
      } else if (isAddonSearchViewActive()) {
        setAddonSearchStatus("Fehler: " + msg, true);
      } else {
        setStatus("Fehler: " + msg, true);
      }
    });
  });

  document.querySelectorAll(".filter-chips .chip[data-severity]").forEach((chip) => {
    chip.addEventListener("click", () => {
      state.severity = String(chip.getAttribute("data-severity") || "all");
      syncSeverityChips();
      void refreshMobileData().catch((error) => setStatus("Fehler: " + error.message, true));
    });
  });

  document.getElementById("filterMoreButton")?.addEventListener("click", () => openSheet("filterSheet"));
  document.getElementById("filterSheetApply")?.addEventListener("click", () => {
    state.showAck = document.getElementById("showAckToggle")?.checked === true;
    state.showClosed = document.getElementById("showClosedToggle")?.checked === true;
    closeAllSheets();
    void refreshMobileData().catch((error) => setStatus("Fehler: " + error.message, true));
  });

  renderCountryFilterChips();

  document.getElementById("liveReportFeedToggleButton")?.addEventListener("click", () => toggleMobileLiveReportFeedEnabled());
  document.getElementById("liveFeedShowMenuButton")?.addEventListener("click", () => showMobileLiveReportFeedPanelFromMenu());
  document.getElementById("liveFeedDetailsMenuButton")?.addEventListener("click", () => openLatestMobileLiveReportDetailsFromMenu());

  document.getElementById("pushToggleButton")?.addEventListener("click", () => void togglePush());
  document.getElementById("testPushButton")?.addEventListener("click", () => void sendTestPush());

  document.getElementById("menuToggleButton")?.addEventListener("click", () => {
    document.getElementById("headerMenu")?.classList.toggle("hidden");
  });

  document.getElementById("mobileLogoutButton")?.addEventListener("click", async () => {
    await mobileLogout();
    mobileSessionEstablishedAtMs = 0;
    resetMobileLiveReportFeed();
    state.authenticated = false;
    state.username = "";
    state.userDisplayName = "";
    updateUserLine();
    showAlertsHomeView();
    showLoginOverlay(true);
    renderAlerts([]);
    state.activeHostsCount = 0;
    state.inactiveHostsCount = 0;
    state.inactiveHosts = [];
    state.activeHosts = [];
    renderHostKpis();
    setStatus("");
    setInactiveHostsStatus("");
    setActiveHostsStatus("");
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

  document.addEventListener("visibilitychange", () => {
    if (document.hidden || !state.authenticated) {
      return;
    }
    void (async () => {
      const ok = await mobileRefreshSession();
      if (!ok) {
        const recovered = await mobileRecoverSessionAfter401();
        if (!recovered) {
          mobileForceLogout("Session abgelaufen. Bitte erneut anmelden.");
          return;
        }
      }
      await refreshPushState();
      await refreshMobileData();
    })().catch((error) => setStatus("Fehler: " + (error?.message || String(error)), true));
  });

  window.addEventListener("focus", () => {
    if (!state.authenticated) {
      return;
    }
    void mobileRefreshSession();
  });
}

async function loadMobileReleaseVersions() {
  const buildVersionEls = [document.getElementById("mobileLoginBuildVersion")].filter(Boolean);
  const agentVersionEls = [document.getElementById("mobileLoginAgentVersion")].filter(Boolean);
  if (!buildVersionEls.length && !agentVersionEls.length) {
    return;
  }

  const setBuildVersions = (value) => {
    buildVersionEls.forEach((el) => {
      el.textContent = value;
    });
  };
  const setAgentVersions = (value) => {
    agentVersionEls.forEach((el) => {
      el.textContent = value;
    });
  };

  try {
    const [buildResp, agentResp] = await Promise.all([
      fetch("/BUILD_VERSION", { cache: "no-store", credentials: "same-origin" }),
      fetch("/AGENT_VERSION", { cache: "no-store", credentials: "same-origin" }),
    ]);
    if (!buildResp.ok) {
      throw new Error("BUILD_VERSION HTTP " + buildResp.status);
    }
    const buildText = (await buildResp.text()).trim();
    const agentText = agentResp.ok ? (await agentResp.text()).trim() : buildText;
    state.latestAgentVersion = agentText || "";
    setBuildVersions(buildText || "-");
    setAgentVersions(agentText || "-");
  } catch (_error) {
    setBuildVersions("-");
    setAgentVersions("-");
  }
}

async function init() {
  state.highlightAlertId = parseHighlightAlertId();
  wire();
  void loadMobileReleaseVersions();
  try {
    await ensureAuthenticated();
    if (state.authenticated) {
      mobileSessionEstablishedAtMs = Date.now();
      startMobileSessionKeepAlive();
      initMobileLiveReportFeed();
      await loadMobileSapB1VersionMap();
      await refreshPushState();
      await refreshMobileData();
    } else {
      setLoginStatus("Bitte anmelden, um Alerts zu laden.");
    }
  } catch (error) {
    showLoginOverlay(true);
    setLoginStatus("Initialisierung fehlgeschlagen: " + (error?.message || String(error)), true);
  }
}

void init();
