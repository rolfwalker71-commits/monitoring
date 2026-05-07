function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

const ANALYSIS_RANGE_STORAGE_KEY = "monitoring.analysisHours";
const THEME_STORAGE_KEY = "monitoring.theme";
const HOST_FILTERS_STORAGE_KEY_PREFIX = "monitoring.hostFilters.";
const AUTO_REFRESH_STORAGE_KEY = "monitoring.autoRefreshInterval";
const AUTO_REFRESH_INTERVAL_OPTIONS = new Map([
  [30, "30 Sek."],
  [60, "1 Min."],
  [300, "5 Min."],
  [480, "8 Min."],
  [0, "Aus"],
]);
const REPORT_SECTION_OPTIONS = new Set(["overview", "journal", "processes", "containers", "sap-b1-systeminfo", "agent-update", "dir-listings"]);

const SAP_B1_VERSION_MAP = new Map([
  ["10.00.320", { featurePack: "FP 2602", patchLevel: "PL 22", releaseDate: "Feb 2026" }],
  ["10.00.310", { featurePack: "FP 2511", patchLevel: "PL 21", releaseDate: "Nov 2025" }],
  ["10.00.300", { featurePack: "FP 2508", patchLevel: "PL 20", releaseDate: "Aug 2025" }],
  ["10.00.291", { featurePack: "FP 2505 HF1", patchLevel: "PL 19", releaseDate: "Jun 2025" }],
  ["10.00.290", { featurePack: "FP 2505", patchLevel: "PL 19", releaseDate: "May 2025" }],
  ["10.00.280", { featurePack: "FP 2502", patchLevel: "PL 18", releaseDate: "Feb 2025" }],
  ["10.00.270", { featurePack: "FP 2411", patchLevel: "PL 17", releaseDate: "Nov 2024" }],
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

const SAP_B1_HANA_PROCESS_RE = /\b(hdbindexserver|hdbnameserver|hdbscriptserver|hdbxsengine|hdbcompileserver|hdbpreprocessor|hdbwebdispatcher|hdbdaemon|hdbrsutil|sapstartsrv|hdb[a-z0-9_-]+)\b/i;

let autoRefreshTimerId = null;
let autoRefreshInProgress = false;
let autoRefreshCurrentIntervalSec = 480;
let autoRefreshLastRefreshAt = null;
let autoRefreshCountdownTimerId = null;

const state = {
  hostLimit: 500,
  hostOffset: 0,
  hosts: [],
  totalHosts: 0,
  selectedHost: "",
  selectedDisplayName: "",
  hostSearchQuery: "",
  hostAlertFilter: "all",
  hostMutedFilter: "all",
  hostOsFilter: "all",
  hostCountryFilter: "all",
  viewMode: "overview",
  userSettingsSubMode: "password",
  overviewSection: "main",
  globalSubMode: "global-alerts",
  criticalTrendsHours: 24,
  criticalTrendsProjectHours: 8,
  criticalTrendsMetrics: ["filesystem"],
  inactiveHostsHours: 1,
  inactiveHosts: [],
  reportLimit: 1,
  reportOffset: 0,
  totalReports: 0,
  currentReport: null,
  reportSection: "overview",
  analysisHours: 24,
  alarmSettingsLoaded: false,
  globalAlertsCollapsed: false,
  globalAlertsOffset: 0,
  globalAlertsTotal: 0,
  globalAlertsPageSize: 100,
  globalShowAcknowledged: false,
  globalShowClosed: false,
  hostAlertsCollapsed: false,
  globalSeverityFilter: "all",
  globalOpenAlertsCount: 0,
  criticalTrendsCount: 0,
  inactiveHostsCount: 0,
  authUser: "",
  authDisplayName: "",
  isAuthenticated: false,
  visibleHosts: 0,
  hiddenHosts: 0,
  hiddenHostsCollapsed: true,
  hiddenHostMutedAlertsCollapsed: {},
  mutedAlertsByHost: {},
  latestAgentRelease: "",
  agentUpdateStatusLoaded: false,
  isAdmin: false,
  userProfileLoaded: false,
  oauthSettingsLoaded: false,
  userManagementLoaded: false,
  hostFilterNoMatches: false,
  hostInterestMode: "all",
  hostInterestHosts: new Set(),
  hostInterestSearchQuery: "",
  adminAlertSubscriptionsLoaded: false,
  adminAlertSubscriptionsUsers: [],
  adminAlertAvailableHosts: [],
  adminAlertTelegramAvailable: false,
  fsVisibilityEditable: false,
  fsFocusHiddenMountpoints: [],
  largeFilesHiddenMountpoints: [],
  fsFocusAvailableMountpoints: [],
  largeFilesAvailableMountpoints: [],
  fsVisibilitySection: "",
  deliveryCountsCache: {},
  deliveryCountsLoading: false,
  analysisLatestDeliveryLabel: "LIVE",
  alertMutesRefreshInFlight: false,
};

function normalizeHostInterestMode(value) {
  const mode = String(value || "all").trim().toLowerCase();
  if (mode === "interested_first" || mode === "interested_only") {
    return mode;
  }
  return "all";
}

const ANALYSIS_RANGE_OPTIONS = new Map([
  [6, "Letzte 6 Std."],
  [24, "Letzte 24 Std."],
  [72, "Letzte 3 Tage"],
  [168, "Letzte 7 Tage"],
  [336, "Letzte 14 Tage"],
  [720, "Letzte 30 Tage"],
]);

function normalizeAnalysisHours(value) {
  const parsed = Number.parseInt(String(value || ""), 10);
  return ANALYSIS_RANGE_OPTIONS.has(parsed) ? parsed : 24;
}

function analysisWindowLabel(hours = state.analysisHours) {
  return ANALYSIS_RANGE_OPTIONS.get(normalizeAnalysisHours(hours)) || "Letzte 24 Std.";
}

function updateAnalysisRangeUi() {
  const select = document.getElementById("analysisRangeSelect");
  const analysisTitle = document.getElementById("analysisSectionTitle");
  const filesystemTitle = document.getElementById("filesystemSectionTitle");
  const label = analysisWindowLabel();

  if (select) {
    select.value = String(state.analysisHours);
  }
  if (analysisTitle) {
    analysisTitle.textContent = `📊 Analyse (${label})`;
  }
  if (filesystemTitle) {
    filesystemTitle.textContent = `💾 Filesystem Fokus (${label})`;
  }
}

function loadAnalysisRangePreference() {
  try {
    return normalizeAnalysisHours(window.localStorage.getItem(ANALYSIS_RANGE_STORAGE_KEY));
  } catch (_error) {
    return 24;
  }
}

function loadAutoRefreshPreference() {
  try {
    const raw = window.localStorage.getItem(AUTO_REFRESH_STORAGE_KEY);
    const parsed = Number.parseInt(String(raw || ""), 10);
    return AUTO_REFRESH_INTERVAL_OPTIONS.has(parsed) ? parsed : 480;
  } catch (_error) {
    return 480;
  }
}

function persistAutoRefreshPreference(seconds) {
  try {
    window.localStorage.setItem(AUTO_REFRESH_STORAGE_KEY, String(seconds));
  } catch (_error) { /* ignore */ }
}

function persistAnalysisRangePreference() {
  try {
    window.localStorage.setItem(ANALYSIS_RANGE_STORAGE_KEY, String(state.analysisHours));
  } catch (_error) {
    // Ignore storage failures and keep the current in-memory selection.
  }
}

function loadHostFilterPreferences() {
  state.hostSearchQuery = "";
  state.hostAlertFilter = "all";
  state.hostMutedFilter = "all";
  state.hostOsFilter = "all";
  state.hostCountryFilter = "all";

  const username = String(state.authUser || "").trim().toLowerCase();
  if (!username) {
    return;
  }

  try {
    const raw = window.localStorage.getItem(`${HOST_FILTERS_STORAGE_KEY_PREFIX}${username}`);
    if (!raw) return;
    const saved = JSON.parse(raw);
    if (saved.hostSearchQuery !== undefined) state.hostSearchQuery = String(saved.hostSearchQuery);
    if (saved.hostAlertFilter !== undefined) state.hostAlertFilter = String(saved.hostAlertFilter);
    if (saved.hostMutedFilter !== undefined) state.hostMutedFilter = String(saved.hostMutedFilter);
    if (saved.hostOsFilter !== undefined) state.hostOsFilter = String(saved.hostOsFilter);
    if (saved.hostCountryFilter !== undefined) state.hostCountryFilter = String(saved.hostCountryFilter);
  } catch (_error) {
    // Ignore
  }
}

async function loadUserPreferences() {
  try {
    const response = await fetch("/api/v1/user-preferences", { credentials: "same-origin" });
    if (!response.ok) return;
    const prefs = await response.json();
    if (prefs.critical_trends_metrics) {
      const metricsStr = String(prefs.critical_trends_metrics || "filesystem").trim();
      state.criticalTrendsMetrics = metricsStr.split(",").map((m) => m.trim()).filter((m) => m.length > 0);
    }
    state.hostInterestMode = normalizeHostInterestMode(prefs.host_interest_mode || "all");
    state.hostInterestHosts = new Set(
      String(prefs.host_interest_hosts || "")
        .split(",")
        .map((item) => item.trim())
        .filter((item) => item.length > 0)
    );
    updateCriticalTrendsMetricsCheckboxes();
    renderHostInterestsEditor();
  } catch (_error) {
    // Ignore
  }
}

function updateCriticalTrendsMetricsCheckboxes() {
  const checkboxes = {
    cpu: document.getElementById("ctMetricCpu"),
    memory: document.getElementById("ctMetricMemory"),
    swap: document.getElementById("ctMetricSwap"),
    filesystem: document.getElementById("ctMetricFilesystem"),
  };
  for (const [metric, checkbox] of Object.entries(checkboxes)) {
    if (checkbox) {
      checkbox.checked = state.criticalTrendsMetrics.includes(metric);
    }
  }
}

async function updateCriticalTrendsMetrics() {
  const metrics = [];
  const checkboxes = {
    cpu: document.getElementById("ctMetricCpu"),
    memory: document.getElementById("ctMetricMemory"),
    swap: document.getElementById("ctMetricSwap"),
    filesystem: document.getElementById("ctMetricFilesystem"),
  };
  for (const [metric, checkbox] of Object.entries(checkboxes)) {
    if (checkbox && checkbox.checked) {
      metrics.push(metric);
    }
  }
  state.criticalTrendsMetrics = metrics.length > 0 ? metrics : ["filesystem"];

  try {
    await fetch("/api/v1/user-preferences", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ critical_trends_metrics: state.criticalTrendsMetrics.join(",") }),
    });
  } catch (_error) {
    // Ignore
  }

  await loadCriticalTrends();
}

function persistHostFilterPreferences() {
  const username = String(state.authUser || "").trim().toLowerCase();
  if (!username) {
    return;
  }

  try {
    window.localStorage.setItem(`${HOST_FILTERS_STORAGE_KEY_PREFIX}${username}`, JSON.stringify({
      hostSearchQuery: state.hostSearchQuery,
      hostAlertFilter: state.hostAlertFilter,
      hostMutedFilter: state.hostMutedFilter,
      hostOsFilter: state.hostOsFilter,
      hostCountryFilter: state.hostCountryFilter,
    }));
  } catch (_error) {
    // Ignore
  }
}

function normalizeTheme(value) {
  return String(value || "").toLowerCase() === "dark" ? "dark" : "light";
}

function loadThemePreference() {
  try {
    return normalizeTheme(window.localStorage.getItem(THEME_STORAGE_KEY));
  } catch (_error) {
    return "light";
  }
}

function persistThemePreference(theme) {
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, normalizeTheme(theme));
  } catch (_error) {
    // Ignore storage failures and keep runtime theme.
  }
}

function updateThemeToggleUi(theme) {
  const button = document.getElementById("themeToggleButton");
  if (!button) {
    return;
  }
  const isDark = normalizeTheme(theme) === "dark";
  const label = button.querySelector(".theme-toggle-label");
  if (label) label.textContent = isDark ? "Light" : "Dark";
  button.setAttribute("aria-pressed", isDark ? "true" : "false");
  button.title = isDark ? "Zum Lightmode wechseln" : "Zum Darkmode wechseln";
}

function applyTheme(theme) {
  const normalized = normalizeTheme(theme);
  document.body.setAttribute("data-theme", normalized);
  updateThemeToggleUi(normalized);
}

function toggleTheme() {
  const current = normalizeTheme(document.body.getAttribute("data-theme"));
  const next = current === "dark" ? "light" : "dark";
  applyTheme(next);
  persistThemePreference(next);
}

function formatAutoRefreshTimestamp(value = new Date()) {
  return new Intl.DateTimeFormat("de-DE", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(value);
}

function isValidIpv4(value) {
  const text = String(value || "").trim();
  if (!/^\d{1,3}(?:\.\d{1,3}){3}$/.test(text)) {
    return false;
  }
  return text.split(".").every((part) => Number(part) >= 0 && Number(part) <= 255);
}

function firstIpv4FromValue(value) {
  if (Array.isArray(value)) {
    for (const entry of value) {
      const candidate = firstIpv4FromValue(entry);
      if (candidate) return candidate;
    }
    return "";
  }

  if (value && typeof value === "object") {
    const objectCandidates = [
      value.ipv4,
      value.ip,
      value.address,
      value.addr,
      value.local,
      value.value,
      value.addresses,
    ];
    for (const candidateValue of objectCandidates) {
      const candidate = firstIpv4FromValue(candidateValue);
      if (candidate) return candidate;
    }
    return "";
  }

  const text = String(value || "").trim();
  if (!text) {
    return "";
  }
  const parts = text.split(/\s+/);
  for (const part of parts) {
    if (isValidIpv4(part)) {
      return part;
    }
  }
  return isValidIpv4(text) ? text : "";
}

function resolveDefaultNicIpv4(report, payload, network) {
  const defaultInterface = String(network?.default_interface || "").trim();
  const interfaces = Array.isArray(network?.interfaces) ? network.interfaces : [];

  if (defaultInterface && interfaces.length > 0) {
    const iface = interfaces.find((entry) => String(entry?.name || "") === defaultInterface);
    if (iface) {
      const fromInterface = firstIpv4FromValue([
        iface.ipv4,
        iface.ip,
        iface.address,
        iface.addresses,
      ]);
      if (fromInterface) {
        return fromInterface;
      }
    }
  }

  const primary = firstIpv4FromValue(report?.primary_ip || payload?.primary_ip);
  if (primary) {
    return primary;
  }

  return firstIpv4FromValue(payload?.all_ips);
}

function formatDnsServers(value) {
  if (Array.isArray(value)) {
    const cleaned = value
      .map((entry) => String(entry || "").trim())
      .filter((entry) => entry.length > 0);
    return cleaned.length > 0 ? cleaned.join("<br>") : "-";
  }
  return asText(value);
}

function renderAutoRefreshStatus() {
  const statusEl = document.getElementById("autoRefreshStatus");
  if (!statusEl) return;
  if (!autoRefreshLastRefreshAt) {
    statusEl.textContent = "-";
    return;
  }
  if (autoRefreshCurrentIntervalSec <= 0) {
    statusEl.textContent = formatAutoRefreshTimestamp(autoRefreshLastRefreshAt);
    return;
  }
  const nextMs = autoRefreshLastRefreshAt.getTime() + autoRefreshCurrentIntervalSec * 1000;
  const secLeft = Math.max(0, Math.ceil((nextMs - Date.now()) / 1000));
  statusEl.textContent = `${formatAutoRefreshTimestamp(autoRefreshLastRefreshAt)} · in ${secLeft}s`;
}

function updateAutoRefreshStatus(lastRefreshAt = null) {
  autoRefreshLastRefreshAt = lastRefreshAt;
  renderAutoRefreshStatus();
  if (lastRefreshAt && autoRefreshCurrentIntervalSec > 0) {
    startAutoRefreshCountdown();
  }
  updateSummaryStrip();
}

function stopAutoRefreshTimer() {
  if (autoRefreshTimerId !== null) {
    window.clearInterval(autoRefreshTimerId);
    autoRefreshTimerId = null;
  }
  if (autoRefreshCountdownTimerId !== null) {
    window.clearInterval(autoRefreshCountdownTimerId);
    autoRefreshCountdownTimerId = null;
  }
}

function startAutoRefreshTimer() {
  stopAutoRefreshTimer();
  if (autoRefreshCurrentIntervalSec <= 0) return;
  autoRefreshTimerId = window.setInterval(() => {
    void refreshDashboard({ automatic: true, preserveScroll: true });
  }, autoRefreshCurrentIntervalSec * 1000);
}

function startAutoRefreshCountdown() {
  if (autoRefreshCountdownTimerId !== null) {
    window.clearInterval(autoRefreshCountdownTimerId);
  }
  autoRefreshCountdownTimerId = window.setInterval(renderAutoRefreshStatus, 1000);
}

function updateSummaryStrip() {
  const lastEl = document.getElementById("summaryLastUpdate");
  if (lastEl) {
    if (autoRefreshLastRefreshAt) {
      lastEl.textContent = `🕒 ${formatAutoRefreshTimestamp(autoRefreshLastRefreshAt)}`;
      lastEl.classList.remove("hidden");
    } else {
      lastEl.classList.add("hidden");
    }
  }
}

let sessionRefreshTimerId = null;

function startSessionRefreshTimer() {
  stopSessionRefreshTimer();
  // Refresh session every 8 minutes (480 seconds)
  sessionRefreshTimerId = window.setInterval(() => {
    void refreshSession();
  }, 8 * 60 * 1000);
}

function stopSessionRefreshTimer() {
  if (sessionRefreshTimerId !== null) {
    window.clearInterval(sessionRefreshTimerId);
    sessionRefreshTimerId = null;
  }
}

async function refreshSession() {
  const sessionToken = localStorage.getItem("sessionToken");
  if (!sessionToken) {
    return;
  }
  try {
    const response = await fetch("/api/v1/session/refresh", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${sessionToken}`,
        "Content-Type": "application/json",
      },
    });
    if (!response.ok) {
      console.warn("Session refresh failed:", response.status);
    }
  } catch (error) {
    console.warn("Session refresh error:", error);
  }
}

async function refreshDashboard(options = {}) {
  const automatic = options.automatic === true;
  const preserveScroll = options.preserveScroll === true;

  if (!state.isAuthenticated || autoRefreshInProgress) {
    return;
  }

  autoRefreshInProgress = true;
  try {
    const shouldRefreshGlobalAlertsList = state.viewMode === "global" && state.globalSubMode === "global-alerts";
    try {
      await loadWebclientVersion();
    } catch (error) {
      console.warn("loadWebclientVersion failed:", error);
    }
    try {
      await loadActiveUsers();
    } catch (error) {
      console.warn("loadActiveUsers failed:", error);
    }
    await Promise.allSettled([
      loadGlobalAlertsOverview({ updateList: shouldRefreshGlobalAlertsList }),
      loadCriticalTrends({ updateList: false }),
      loadInactiveHosts({ updateList: false }),
      loadHosts({ preserveScroll }),
    ]);
    try {
      await loadReportsForHost();
    } catch (error) {
      console.warn("loadReportsForHost failed:", error);
    }
    try {
      await loadAnalysisForHost();
    } catch (error) {
      console.warn("loadAnalysisForHost failed:", error);
    }
    try {
      await loadAlertsForHost();
    } catch (error) {
      console.warn("loadAlertsForHost failed:", error);
    }
    if (state.viewMode === "settings") {
      try {
        await loadSettingsPanel(true);
      } catch (error) {
        console.warn("loadSettingsPanel failed:", error);
      }
    }
    updateSummaryStrip();
    if (automatic) {
      updateAutoRefreshStatus(new Date());
    }
  } finally {
    autoRefreshInProgress = false;
  }
}

function parseVersionParts(value) {
  const raw = String(value || "").trim();
  if (!raw) {
    return null;
  }

  const normalized = raw.replace(/^v/i, "");
  const parts = normalized.split(".").map((part) => Number.parseInt(part, 10));
  if (parts.length === 0 || parts.some((part) => !Number.isFinite(part) || part < 0)) {
    return null;
  }
  return parts;
}

function compareSemverLike(leftVersion, rightVersion) {
  const left = parseVersionParts(leftVersion);
  const right = parseVersionParts(rightVersion);
  if (!left || !right) {
    return null;
  }

  const length = Math.max(left.length, right.length);
  for (let index = 0; index < length; index += 1) {
    const leftValue = left[index] ?? 0;
    const rightValue = right[index] ?? 0;
    if (leftValue > rightValue) {
      return 1;
    }
    if (leftValue < rightValue) {
      return -1;
    }
  }
  return 0;
}

async function loadWebclientVersion() {
  const versionEl = document.getElementById("webclientVersion");
  const agentVersionEl = document.getElementById("latestAgentVersion");
  if (!versionEl && !agentVersionEl) {
    return;
  }

  try {
    const [webResp, agentResp] = await Promise.all([
      fetch("BUILD_VERSION", {
        cache: "no-store",
        credentials: "same-origin",
      }),
      fetch("AGENT_VERSION", {
        cache: "no-store",
        credentials: "same-origin",
      }),
    ]);

    if (!webResp.ok) {
      throw new Error(`BUILD_VERSION HTTP ${webResp.status}`);
    }

    const webText = (await webResp.text()).trim();
    const agentText = agentResp.ok ? (await agentResp.text()).trim() : webText;
    const value = webText || "-";
    const agentValue = agentText || "-";

    if (versionEl) {
      versionEl.textContent = value;
    }
    if (agentVersionEl) {
      agentVersionEl.textContent = agentValue;
    }
    state.latestAgentRelease = agentValue;

    // Re-render host cards so update badges reflect the latest release value immediately.
    if (state.isAuthenticated && state.selectedHost) {
      await loadHosts();
    }
  } catch (_error) {
    if (versionEl) {
      versionEl.textContent = "-";
    }
    if (agentVersionEl) {
      agentVersionEl.textContent = "-";
    }
    state.latestAgentRelease = "";
  }
}

function normalizeReportSection(value) {
  const section = String(value || "overview").toLowerCase();
  return REPORT_SECTION_OPTIONS.has(section) ? section : "overview";
}

function updateReportSectionUi() {
  const section = normalizeReportSection(state.reportSection);
  state.reportSection = section;

  for (const button of document.querySelectorAll("[data-report-section]")) {
    const buttonSection = normalizeReportSection(button.getAttribute("data-report-section"));
    button.classList.toggle("active", buttonSection === section);
    button.setAttribute("aria-selected", buttonSection === section ? "true" : "false");
  }
}

function updateStatusBadgeLabel(status) {
  switch (String(status || "idle")) {
    case "pending":
      return "PENDING";
    case "completed":
      return "COMPLETED";
    case "failed":
      return "FAILED";
    case "expired":
      return "EXPIRED";
    default:
      return "IDLE";
  }
}

function renderAgentUpdateStatusRows(hosts) {
  if (!Array.isArray(hosts) || hosts.length === 0) {
    return '<p class="muted">Noch keine Host-Statusdaten vorhanden.</p>';
  }

  return hosts
    .slice(0, 6)
    .map((host) => {
      const displayName = asText(host.display_name || host.hostname);
      const hostname = asText(host.hostname);
      const status = asText(host.command_status || "idle").toLowerCase();
      const nextPriority = host.next_priority_check_utc ? formatUtcPlus2(host.next_priority_check_utc) : "-";
      const executedAt = host.command_executed_at_utc ? formatUtcPlus2(host.command_executed_at_utc) : "-";
      const resultMessage = asText(host.command_result_message || "");
      const recurringHint = asText(host.recurring_update_hint || "");

      return `
        <div class="agent-update-status-row">
          <strong>${escapeHtml(displayName)} <span class="agent-update-status-badge ${escapeHtml(status)}">${escapeHtml(updateStatusBadgeLabel(status))}</span></strong>
          <span>🖥️ ${escapeHtml(hostname)} | Letzte Ausfuehrung: ${escapeHtml(executedAt)}</span>
          <span>⏭️ Nächster priorisierter Check: ${escapeHtml(nextPriority)}</span>
          <span>🕒 ${escapeHtml(recurringHint || "Kein Scheduler-Hinweis vom Agenten vorhanden.")}</span>
          <span>${escapeHtml(resultMessage || "Kein Rueckkanal-Ergebnis gespeichert.")}</span>
        </div>
      `;
    })
    .join("");
}

async function loadAgentUpdateStatus() {
  const summaryEl = document.getElementById("agentUpdateStatusSummary");
  const listEl = document.getElementById("agentUpdateStatusList");
  if (!summaryEl || !listEl) {
    return;
  }

  summaryEl.textContent = "Lade Update-Status...";
  listEl.innerHTML = "";

  try {
    const response = await fetch("/api/v1/agent-update-status");
    if (!response.ok) {
      throw new Error("HTTP " + response.status);
    }

    const data = await response.json();
    const summary = data.summary || {};
    summaryEl.textContent = `Status: ${Number(summary.pending || 0)} pending | ${Number(summary.completed || 0)} completed | ${Number(summary.failed || 0)} failed | ${Number(summary.expired || 0)} expired | ${Number(summary.idle || 0)} idle. ${asText(data.default_schedule_note)}`;
    listEl.innerHTML = renderAgentUpdateStatusRows(data.hosts || []);
    state.agentUpdateStatusLoaded = true;
  } catch (error) {
    summaryEl.textContent = `Update-Status konnte nicht geladen werden: ${error.message}`;
    listEl.innerHTML = "";
  }
}

function updateViewMode() {
  const layout = document.getElementById("layout");
  const overviewView = document.getElementById("overviewView");
  const reportsView = document.getElementById("reportsView");
  const globalView = document.getElementById("globalView");
  const settingsView = document.getElementById("settingsView");
  const overviewTabButton = document.getElementById("overviewTabButton");
  const reportsTabButton = document.getElementById("reportsTabButton");
  const settingsTabButton = document.getElementById("settingsTabButton");
  const globalViewButton = document.getElementById("globalViewButton");

  const overviewActive = state.viewMode === "overview";
  const reportsActive = state.viewMode === "reports";
  const globalActive = state.viewMode === "global";
  const settingsActive = state.viewMode === "settings";

  // full-panel views hide the layout (host list + reports column)
  const fullPanelActive = globalActive || settingsActive;
  if (layout) layout.classList.toggle("hidden", fullPanelActive);

  if (globalView) globalView.classList.toggle("hidden", !globalActive);
  if (settingsView) settingsView.classList.toggle("hidden", !settingsActive);

  // tab views only relevant when layout is visible
  if (overviewView) overviewView.classList.toggle("hidden", !overviewActive);
  if (reportsView) reportsView.classList.toggle("hidden", !reportsActive);

  overviewTabButton.classList.toggle("active", overviewActive);
  reportsTabButton.classList.toggle("active", reportsActive);
  if (settingsTabButton) settingsTabButton.classList.toggle("active", settingsActive);
  if (globalViewButton) globalViewButton.classList.toggle("active", globalActive);
  overviewTabButton.setAttribute("aria-selected", overviewActive ? "true" : "false");
  reportsTabButton.setAttribute("aria-selected", reportsActive ? "true" : "false");
  if (settingsTabButton) settingsTabButton.setAttribute("aria-selected", settingsActive ? "true" : "false");
  updateReportSectionUi();
  if (settingsActive) {
    updateUserSettingsSubMode();
  }
}

function updateGlobalSubMode() {
  const globalAlertsView = document.getElementById("globalAlertsView");
  const criticalTrendsView = document.getElementById("criticalTrendsView");
  const inactiveHostsView = document.getElementById("inactiveHostsView");
  const backupStatusView = document.getElementById("backupStatusView");
  const globalAdminAlertSubsView = document.getElementById("globalAdminAlertSubsView");
  const globalAdminSettingsView = document.getElementById("globalAdminSettingsView");
  const globalAlertsTabButton = document.getElementById("globalAlertsTabButton");
  const criticalTrendsTabButton = document.getElementById("criticalTrendsTabButton");
  const inactiveHostsTabButton = document.getElementById("inactiveHostsTabButton");
  const backupStatusTabButton = document.getElementById("backupStatusTabButton");
  const globalAdminAlertSubsTabButton = document.getElementById("globalAdminAlertSubsTabButton");
  const globalAdminSettingsTabButton = document.getElementById("globalAdminSettingsTabButton");

  const alertsActive = state.globalSubMode === "global-alerts";
  const trendsActive = state.globalSubMode === "critical-trends";
  const inactiveActive = state.globalSubMode === "inactive-hosts";
  const backupActive = state.globalSubMode === "backup-status";
  const adminAlertSubsActive = state.globalSubMode === "admin-alert-subs";
  const adminSettingsActive = state.globalSubMode === "admin-settings";

  if (globalAlertsView) globalAlertsView.classList.toggle("hidden", !alertsActive);
  if (criticalTrendsView) criticalTrendsView.classList.toggle("hidden", !trendsActive);
  if (inactiveHostsView) inactiveHostsView.classList.toggle("hidden", !inactiveActive);
  if (backupStatusView) backupStatusView.classList.toggle("hidden", !backupActive);
  if (globalAdminAlertSubsView) globalAdminAlertSubsView.classList.toggle("hidden", !adminAlertSubsActive);
  if (globalAdminSettingsView) globalAdminSettingsView.classList.toggle("hidden", !adminSettingsActive);
  if (globalAlertsTabButton) { globalAlertsTabButton.classList.toggle("active", alertsActive); globalAlertsTabButton.setAttribute("aria-selected", alertsActive ? "true" : "false"); }
  if (criticalTrendsTabButton) { criticalTrendsTabButton.classList.toggle("active", trendsActive); criticalTrendsTabButton.setAttribute("aria-selected", trendsActive ? "true" : "false"); }
  if (inactiveHostsTabButton) { inactiveHostsTabButton.classList.toggle("active", inactiveActive); inactiveHostsTabButton.setAttribute("aria-selected", inactiveActive ? "true" : "false"); }
  if (backupStatusTabButton) { backupStatusTabButton.classList.toggle("active", backupActive); backupStatusTabButton.setAttribute("aria-selected", backupActive ? "true" : "false"); }
  if (globalAdminAlertSubsTabButton) { globalAdminAlertSubsTabButton.classList.toggle("active", adminAlertSubsActive); globalAdminAlertSubsTabButton.setAttribute("aria-selected", adminAlertSubsActive ? "true" : "false"); }
  if (globalAdminSettingsTabButton) { globalAdminSettingsTabButton.classList.toggle("active", adminSettingsActive); globalAdminSettingsTabButton.setAttribute("aria-selected", adminSettingsActive ? "true" : "false"); }
}

function updateUserSettingsSubMode() {
  const panels = {
    password: document.querySelectorAll("[data-user-settings-panel='password']"),
    channels: document.querySelectorAll("[data-user-settings-panel='channels']"),
    digests: document.querySelectorAll("[data-user-settings-panel='digests']"),
    hosts: document.querySelectorAll("[data-user-settings-panel='hosts']"),
  };
  const buttons = {
    password: document.getElementById("userSettingsPasswordTabButton"),
    channels: document.getElementById("userSettingsChannelsTabButton"),
    digests: document.getElementById("userSettingsDigestsTabButton"),
    hosts: document.getElementById("userSettingsHostsTabButton"),
  };

  const activeMode = String(state.userSettingsSubMode || "password");
  for (const [mode, nodeList] of Object.entries(panels)) {
    const active = mode === activeMode;
    nodeList.forEach((node) => {
      node.classList.toggle("hidden", !active);
    });
    const button = buttons[mode];
    if (button) {
      button.classList.toggle("active", active);
      button.setAttribute("aria-selected", active ? "true" : "false");
    }
  }
}

function renderHostInterestsEditor() {
  const listEl = document.getElementById("hostInterestsList");
  const summaryEl = document.getElementById("hostInterestsSummary");
  const modeSelect = document.getElementById("hostInterestModeSelect");
  if (!listEl) {
    return;
  }

  if (modeSelect) {
    modeSelect.value = normalizeHostInterestMode(state.hostInterestMode);
  }

  const allHosts = [...(state.hosts || [])].sort((a, b) => {
    const nameA = String(a.display_name || a.hostname || "").toLowerCase();
    const nameB = String(b.display_name || b.hostname || "").toLowerCase();
    return nameA.localeCompare(nameB);
  });
  const query = String(state.hostInterestSearchQuery || "").toLowerCase().trim();
  const visibleHosts = query
    ? allHosts.filter((host) => {
      const hostname = String(host.hostname || "").toLowerCase();
      const displayName = String(host.display_name || host.hostname || "").toLowerCase();
      return hostname.includes(query) || displayName.includes(query);
    })
    : allHosts;

  if (summaryEl) {
    const modeLabel = normalizeHostInterestMode(state.hostInterestMode).replaceAll("_", " ");
    summaryEl.textContent = `${state.hostInterestHosts.size} markiert | Modus: ${modeLabel}`;
  }

  if (allHosts.length === 0) {
    listEl.innerHTML = '<p class="muted">Noch keine Hosts geladen.</p>';
    return;
  }
  if (visibleHosts.length === 0) {
    listEl.innerHTML = '<p class="muted">Keine Treffer fuer die Suche.</p>';
    return;
  }

  listEl.innerHTML = visibleHosts.map((host) => {
    const hostname = String(host.hostname || "");
    const displayName = String(host.display_name || hostname || "");
    const checked = state.hostInterestHosts.has(hostname) ? "checked" : "";
    return `
      <label class="host-interest-item">
        <input type="checkbox" data-host-interest-host="${escapeHtml(hostname)}" ${checked} />
        <span class="host-interest-name">${escapeHtml(displayName)}</span>
        <span class="host-interest-hostname">(${escapeHtml(hostname)})</span>
      </label>
    `;
  }).join("");

  listEl.querySelectorAll("[data-host-interest-host]").forEach((checkbox) => {
    checkbox.addEventListener("change", () => {
      const hostname = String(checkbox.getAttribute("data-host-interest-host") || "");
      if (!hostname) {
        return;
      }
      if (checkbox.checked) {
        state.hostInterestHosts.add(hostname);
      } else {
        state.hostInterestHosts.delete(hostname);
      }
      renderHostInterestsEditor();
    });
  });
}

function updateOverviewSection() {
  const mainSection = document.getElementById("overviewMainSection");
  const filesystemSection = document.getElementById("overviewFilesystemSection");
  const mainTabButton = document.getElementById("overviewMainTabButton");
  const filesystemTabButton = document.getElementById("overviewFilesystemTabButton");

  if (!mainSection || !filesystemSection || !mainTabButton || !filesystemTabButton) {
    return;
  }

  const showMain = state.overviewSection === "main";
  const showFilesystem = state.overviewSection === "filesystem";

  mainSection.classList.toggle("hidden", !showMain);
  filesystemSection.classList.toggle("hidden", !showFilesystem);

  mainTabButton.classList.toggle("active", showMain);
  filesystemTabButton.classList.toggle("active", showFilesystem);
  mainTabButton.setAttribute("aria-selected", showMain ? "true" : "false");
  filesystemTabButton.setAttribute("aria-selected", showFilesystem ? "true" : "false");
}

function setAlarmSettingsStatus(message, isError = false) {
  const statusEl = document.getElementById("alarmSettingsStatus");
  if (!statusEl) {
    return;
  }
  statusEl.textContent = message;
  statusEl.classList.toggle("status-error", isError);
}

function setUserMailSettingsStatus(message, isError = false) {
  const statusEl = document.getElementById("userMailSettingsStatus");
  if (!statusEl) {
    return;
  }
  statusEl.textContent = message;
  statusEl.classList.toggle("status-error", isError);
}

function setHostInterestsStatus(message, isError = false) {
  const statusEl = document.getElementById("hostInterestsStatus");
  if (!statusEl) {
    return;
  }
  statusEl.textContent = message;
  statusEl.classList.toggle("status-error", isError);
}

function setOauthSettingsStatus(message, isError = false) {
  const statusEl = document.getElementById("oauthSettingsStatus");
  if (!statusEl) {
    return;
  }
  statusEl.textContent = message;
  statusEl.classList.toggle("status-error", isError);
}

function setUserManagementStatus(message, isError = false) {
  const statusEl = document.getElementById("userManagementStatus");
  if (!statusEl) {
    return;
  }
  statusEl.textContent = message;
  statusEl.classList.toggle("status-error", isError);
}

function setLoginStatus(message, isError = false) {
  const statusEl = document.getElementById("loginStatus");
  if (!statusEl) {
    return;
  }
  statusEl.textContent = message;
  statusEl.classList.toggle("status-error", isError);
}

function setPasswordChangeStatus(message, isError = false) {
  const statusEl = document.getElementById("passwordChangeStatus");
  if (!statusEl) {
    return;
  }
  statusEl.textContent = message;
  statusEl.classList.toggle("status-error", isError);
}

function setAuthUiState(authenticated) {
  const loginOverlay = document.getElementById("loginOverlay");
  const appPanel = document.getElementById("appPanel");
  const hostToolsHeader = document.getElementById("hostToolsHeader");
  const brandUserBadge = document.getElementById("brandUserBadge");
  const logoutButton = document.getElementById("logoutButton");
  loginOverlay.classList.toggle("hidden", authenticated);
  appPanel.classList.toggle("hidden", !authenticated);
  if (hostToolsHeader) {
    hostToolsHeader.classList.toggle("hidden", !authenticated);
  }
  if (brandUserBadge) {
    brandUserBadge.classList.toggle("hidden", !authenticated);
    if (authenticated && state.authUser) {
      brandUserBadge.textContent = state.authDisplayName || state.authUser;
    }
  }
  if (logoutButton) {
    logoutButton.classList.toggle("hidden", !authenticated);
  }
  state.isAuthenticated = authenticated;
  if (!authenticated) {
    state.isAdmin = false;
    state.userProfileLoaded = false;
    state.oauthSettingsLoaded = false;
    state.userManagementLoaded = false;
    state.adminAlertSubscriptionsLoaded = false;
    state.adminAlertSubscriptionsUsers = [];
    state.adminAlertAvailableHosts = [];
    state.adminAlertTelegramAvailable = false;
  }
  updateFilesystemVisibilityButtons();
  updateAdminSettingsVisibility();
}

function updateAdminSettingsVisibility() {
  const adminOauthSection = document.getElementById("adminOauthSettingsSection");
  const adminUserSection = document.getElementById("adminUserManagementSection");
  const globalAlarmSettingsSection = document.getElementById("globalAlarmSettingsSection");
  const globalAdminAlertSubsTab = document.getElementById("globalAdminAlertSubsTabButton");
  const globalAdminSettingsTab = document.getElementById("globalAdminSettingsTabButton");
  const globalAdminOpsSection = document.getElementById("globalAdminOpsSection");
  if (adminOauthSection) {
    adminOauthSection.classList.toggle("hidden", !state.isAdmin);
  }
  if (adminUserSection) {
    adminUserSection.classList.toggle("hidden", !state.isAdmin);
  }
  if (globalAlarmSettingsSection) {
    globalAlarmSettingsSection.classList.toggle("hidden", !state.isAdmin);
  }
  if (globalAdminAlertSubsTab) {
    globalAdminAlertSubsTab.classList.toggle("hidden", !state.isAdmin);
  }
  if (globalAdminSettingsTab) {
    globalAdminSettingsTab.classList.toggle("hidden", !state.isAdmin);
  }
  if (globalAdminOpsSection) {
    globalAdminOpsSection.classList.toggle("hidden", !state.isAdmin);
  }
  if (!state.isAdmin && state.globalSubMode === "admin-alert-subs") {
    state.globalSubMode = "global-alerts";
    updateGlobalSubMode();
  }
  if (!state.isAdmin && state.globalSubMode === "admin-settings") {
    state.globalSubMode = "global-alerts";
    updateGlobalSubMode();
  }
  if (state.userSettingsSubMode !== "password" && state.userSettingsSubMode !== "channels" && state.userSettingsSubMode !== "digests" && state.userSettingsSubMode !== "hosts") {
    state.userSettingsSubMode = "password";
    updateUserSettingsSubMode();
  }
}

async function fetchSessionState() {
  const response = await fetch("/api/v1/session");
  if (!response.ok) {
    throw new Error("HTTP " + response.status);
  }
  return response.json();
}

async function ensureAuthenticatedSession() {
  try {
    const session = await fetchSessionState();
    state.authUser = asText(session.username, "");
    state.authDisplayName = asText(session.display_name, "");
    state.isAdmin = session.is_admin === true;
    setAuthUiState(session.authenticated === true);
    if (session.authenticated === true) {
      loadHostFilterPreferences();
      await loadUserPreferences();
    }
    return session.authenticated === true;
  } catch {
    setAuthUiState(false);
    return false;
  }
}

async function loadActiveUsers() {
  const bar = document.getElementById("activeUsersBar");
  const list = document.getElementById("activeUsersList");
  if (!bar || !list) {
    return;
  }
  if (!state.isAuthenticated) {
    bar.classList.add("hidden");
    list.innerHTML = "";
    return;
  }

  try {
    const response = await fetch("/api/v1/active-users");
    if (!response.ok) {
      throw new Error("HTTP " + response.status);
    }

    const data = await response.json();
    const users = Array.isArray(data.users) ? data.users : [];
    if (users.length === 0) {
      bar.classList.remove("hidden");
      list.innerHTML = '<span class="muted">niemand</span>';
      return;
    }

    list.innerHTML = users.map((item) => {
      const username = asText(item.username, "-");
      const label = asText(item.display_name, "") || username;
      const isCurrent = username === state.authUser;
      const sessionCount = Number(item.session_count || 0);
      const latestExpires = asText(item.latest_expires_at_utc, "");
      return `
        <span class="active-user-chip${isCurrent ? " current" : ""}" title="Session gueltig bis ${escapeHtml(latestExpires || "-")}">
          <span>${escapeHtml(label)}${isCurrent ? " (du)" : ""}</span>
          ${sessionCount > 1 ? `<span class="active-user-chip-count">${sessionCount}</span>` : ""}
        </span>
      `;
    }).join("");
    bar.classList.remove("hidden");
  } catch (error) {
    bar.classList.remove("hidden");
    list.innerHTML = `<span class="muted">Fehler: ${escapeHtml(error.message)}</span>`;
  }
}

async function loginWebClient() {
  const usernameInput = document.getElementById("loginUsernameInput");
  const passwordInput = document.getElementById("loginPasswordInput");
  const username = usernameInput.value.trim();
  const password = passwordInput.value;

  if (!username || !password) {
    setLoginStatus("Bitte Benutzername und Passwort eingeben.", true);
    return false;
  }

  const response = await fetch("/api/v1/web-login", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ username, password }),
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    setLoginStatus(data.error || ("Login fehlgeschlagen (HTTP " + response.status + ")"), true);
    return false;
  }

  state.authUser = asText(data.username, username);
  try {
    const session = await fetchSessionState();
    state.isAdmin = session.is_admin === true;
    state.authDisplayName = asText(session.display_name, "");
  } catch {
    state.isAdmin = false;
  }
  loadHostFilterPreferences();
  setLoginStatus("Anmeldung erfolgreich.");
  setAuthUiState(true);
  passwordInput.value = "";
  return true;
}

async function logoutWebClient() {
  try {
    await fetch("/api/v1/web-logout", { method: "POST", credentials: "same-origin" });
  } catch {
    // ignore network errors – session will be cleared server-side anyway
  }
  stopAutoRefreshTimer();
  updateAutoRefreshStatus(null);
  state.authUser = "";
  state.isAdmin = false;
  setAuthUiState(false);
  const brandUserBadge = document.getElementById("brandUserBadge");
  if (brandUserBadge) {
    brandUserBadge.textContent = "";
  }
  state.authDisplayName = "";
}

async function changePassword() {
  const currentPasswordInput = document.getElementById("currentPasswordInput");
  const newPasswordInput = document.getElementById("newPasswordInput");
  const confirmPasswordInput = document.getElementById("confirmPasswordInput");

  const currentPassword = currentPasswordInput.value;
  const newPassword = newPasswordInput.value;
  const confirmPassword = confirmPasswordInput.value;

  if (!currentPassword || !newPassword) {
    setPasswordChangeStatus("Bitte aktuelle und neue Zugangsdaten eingeben.", true);
    return;
  }
  if (newPassword !== confirmPassword) {
    setPasswordChangeStatus("Neue Passwoerter stimmen nicht ueberein.", true);
    return;
  }

  const response = await fetch("/api/v1/change-password", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      current_password: currentPassword,
      new_password: newPassword,
    }),
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    setPasswordChangeStatus(data.error || ("Aenderung fehlgeschlagen (HTTP " + response.status + ")"), true);
    return;
  }

  currentPasswordInput.value = "";
  newPasswordInput.value = "";
  confirmPasswordInput.value = "";
  setPasswordChangeStatus("Passwort erfolgreich geaendert.", false);
}

async function loadAlarmSettings(force = false) {
  if (state.alarmSettingsLoaded && !force) {
    return;
  }

  const warningInput = document.getElementById("warningThresholdInput");
  const criticalInput = document.getElementById("criticalThresholdInput");
  const warningConsecutiveHitsInput = document.getElementById("warningConsecutiveHitsInput");
  const warningWindowMinutesInput = document.getElementById("warningWindowMinutesInput");
  const criticalImmediateInput = document.getElementById("criticalImmediateInput");
  const cpuWarningThresholdInput = document.getElementById("cpuWarningThresholdInput");
  const cpuCriticalThresholdInput = document.getElementById("cpuCriticalThresholdInput");
  const cpuAlertWindowReportsInput = document.getElementById("cpuAlertWindowReportsInput");
  const ramWarningThresholdInput = document.getElementById("ramWarningThresholdInput");
  const ramCriticalThresholdInput = document.getElementById("ramCriticalThresholdInput");
  const ramAlertWindowReportsInput = document.getElementById("ramAlertWindowReportsInput");
  const telegramEnabledInput = document.getElementById("telegramEnabledInput");
  const telegramBotTokenInput = document.getElementById("telegramBotTokenInput");
  const telegramChatIdInput = document.getElementById("telegramChatIdInput");
  const alertReminderIntervalHoursInput = document.getElementById("alertReminderIntervalHoursInput");
  const inactiveHostAlertEnabledInput = document.getElementById("inactiveHostAlertEnabledInput");
  const inactiveHostAlertHoursInput = document.getElementById("inactiveHostAlertHoursInput");
  const aiTroubleshootEnabledInput = document.getElementById("aiTroubleshootEnabledInput");
  const openaiApiKeyInput = document.getElementById("openaiApiKeyInput");
  const openaiApiKeyIsSetHint = document.getElementById("openaiApiKeyIsSetHint");
  const openaiModelInput = document.getElementById("openaiModelInput");
  const openaiTimeoutSecInput = document.getElementById("openaiTimeoutSecInput");
  const openaiMaxTokensInput = document.getElementById("openaiMaxTokensInput");
  const openaiCacheTtlSecInput = document.getElementById("openaiCacheTtlSecInput");

  try {
    const response = await fetch("/api/v1/alarm-settings");
    if (!response.ok) {
      throw new Error("HTTP " + response.status);
    }
    const settings = await response.json();

    warningInput.value = Number(settings.warning_threshold_percent || 80).toFixed(1);
    criticalInput.value = Number(settings.critical_threshold_percent || 90).toFixed(1);
    cpuWarningThresholdInput.value = Number(settings.cpu_warning_threshold_percent || 80).toFixed(1);
    cpuCriticalThresholdInput.value = Number(settings.cpu_critical_threshold_percent || 95).toFixed(1);
    cpuAlertWindowReportsInput.value = String(Number(settings.cpu_alert_window_reports || 4));
    ramWarningThresholdInput.value = Number(settings.ram_warning_threshold_percent || 85).toFixed(1);
    ramCriticalThresholdInput.value = Number(settings.ram_critical_threshold_percent || 95).toFixed(1);
    ramAlertWindowReportsInput.value = String(Number(settings.ram_alert_window_reports || 4));
    warningConsecutiveHitsInput.value = String(Number(settings.warning_consecutive_hits || 2));
    warningWindowMinutesInput.value = String(Number(settings.warning_window_minutes || 15));
    criticalImmediateInput.checked = settings.critical_trigger_immediate !== false;
    telegramEnabledInput.checked = settings.telegram_enabled === true;
    telegramBotTokenInput.value = asText(settings.telegram_bot_token, "") === "-" ? "" : String(settings.telegram_bot_token || "");
    telegramChatIdInput.value = asText(settings.telegram_chat_id, "") === "-" ? "" : String(settings.telegram_chat_id || "");
    alertReminderIntervalHoursInput.value = String(Number(settings.alert_reminder_interval_hours || 0));
    if (inactiveHostAlertEnabledInput) {
      inactiveHostAlertEnabledInput.checked = settings.inactive_host_alert_enabled === true;
    }
    if (inactiveHostAlertHoursInput) {
      const configuredHours = Number(settings.inactive_host_alert_hours || 3);
      const clampedHours = Number.isFinite(configuredHours) ? Math.max(1, Math.min(168, Math.floor(configuredHours))) : 3;
      inactiveHostAlertHoursInput.value = String(clampedHours);
    }
    if (aiTroubleshootEnabledInput) {
      aiTroubleshootEnabledInput.checked = settings.ai_troubleshoot_enabled !== false;
    }
    if (openaiApiKeyInput) {
      // Never show the real key — leave blank so user must re-enter to change
      openaiApiKeyInput.value = "";
    }
    if (openaiApiKeyIsSetHint) {
      openaiApiKeyIsSetHint.textContent = settings.openai_api_key_is_set ? "API Key ist gesetzt." : "Kein API Key gespeichert.";
    }
    if (openaiModelInput) {
      openaiModelInput.value = String(settings.openai_model || "gpt-4o-mini");
    }
    if (openaiTimeoutSecInput) {
      openaiTimeoutSecInput.value = String(Number(settings.openai_timeout_sec || 12));
    }
    if (openaiMaxTokensInput) {
      openaiMaxTokensInput.value = String(Number(settings.openai_max_tokens || 1200));
    }
    if (openaiCacheTtlSecInput) {
      openaiCacheTtlSecInput.value = String(Number(settings.ai_troubleshoot_cache_ttl_sec || 600));
    }

    state.alarmSettingsLoaded = true;
    setAlarmSettingsStatus("Einstellungen geladen.");
  } catch (error) {
    setAlarmSettingsStatus(`Fehler beim Laden: ${error.message}`, true);
  }
}

async function loadUserProfile(force = false) {
  if (state.userProfileLoaded && !force) {
    return;
  }

  const enabledInput = document.getElementById("userEmailEnabledInput");
  const recipientInput = document.getElementById("userEmailRecipientInput");
  const summaryEl = document.getElementById("userMailSettingsSummary");
  const connectButton = document.getElementById("connectMicrosoftOauthButton");
  const disconnectButton = document.getElementById("disconnectMicrosoftOauthButton");
  const trendEnabledInput = document.getElementById("trendEmailEnabledInput");
  const trendTimeInput = document.getElementById("trendEmailTimeInput");
  const alertEnabledInput = document.getElementById("alertEmailEnabledInput");
  const alertTimeInput = document.getElementById("alertEmailTimeInput");
  const alertRecipientsInput = document.getElementById("alertEmailRecipientsInput");
  const alertWarningRecipientsInput = document.getElementById("alertWarningEmailRecipientsInput");
  const alertCriticalRecipientsInput = document.getElementById("alertCriticalEmailRecipientsInput");
  const alertInstantEnabledInput = document.getElementById("alertInstantMailEnabledInput");
  const alertInstantMinSeveritySelect = document.getElementById("alertInstantMinSeveritySelect");
  const alertInstantTelegramEnabledInput = document.getElementById("alertInstantTelegramEnabledInput");
  const alertTelegramChatIdInput = document.getElementById("alertTelegramChatIdInput");
  const trendTestButton = document.getElementById("testTrendDigestMailButton");
  const alertTestButton = document.getElementById("testAlertDigestMailButton");

  try {
    const response = await fetch("/api/v1/user-profile");
    if (!response.ok) {
      throw new Error("HTTP " + response.status);
    }
    const profile = await response.json();
    enabledInput.checked = profile.email_enabled === true;
    recipientInput.value = asText(profile.email_recipient, "") === "-" ? "" : asText(profile.email_recipient, "");
    trendEnabledInput.checked = profile.trend_email_enabled === true;
    trendTimeInput.value = asText(profile.trend_email_time_hhmm, "08:00");
    const trendRecipientInput = document.getElementById("trendDigestRecipientInput");
    if (trendRecipientInput) trendRecipientInput.value = asText(profile.email_recipient, "") === "-" ? "" : asText(profile.email_recipient, "");
    const digestMetrics = (profile.digest_trend_metrics || "cpu,memory,swap,filesystem").split(",").map((m) => m.trim());
    ["digestMetricCpu", "digestMetricMemory", "digestMetricSwap", "digestMetricFilesystem"].forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.checked = digestMetrics.includes(id.replace("digestMetric", "").toLowerCase());
    });
    alertEnabledInput.checked = profile.alert_email_enabled === true;
    alertTimeInput.value = asText(profile.alert_email_time_hhmm, "08:05");
    alertRecipientsInput.value = asText(profile.alert_email_recipients, "") === "-" ? "" : asText(profile.alert_email_recipients, "");
    if (alertWarningRecipientsInput) {
      alertWarningRecipientsInput.value = asText(profile.alert_warning_email_recipients, "") === "-" ? "" : asText(profile.alert_warning_email_recipients, "");
    }
    if (alertCriticalRecipientsInput) {
      alertCriticalRecipientsInput.value = asText(profile.alert_critical_email_recipients, "") === "-" ? "" : asText(profile.alert_critical_email_recipients, "");
    }
    if (alertInstantEnabledInput) alertInstantEnabledInput.checked = profile.alert_instant_mail_enabled === true;
    if (alertInstantMinSeveritySelect) alertInstantMinSeveritySelect.value = profile.alert_instant_min_severity || "warning";
    if (alertInstantTelegramEnabledInput) alertInstantTelegramEnabledInput.checked = profile.alert_instant_telegram_enabled === true;
    if (alertTelegramChatIdInput) alertTelegramChatIdInput.value = asText(profile.alert_telegram_chat_id, "") === "-" ? "" : asText(profile.alert_telegram_chat_id, "");
    const senderInput = document.getElementById("userEmailSenderInput");
    if (senderInput) senderInput.value = asText(profile.email_sender, "") === "-" ? "" : asText(profile.email_sender, "");
    const backupEmailEnabledInput = document.getElementById("backupEmailEnabledInput");
    const backupEmailTimeInput = document.getElementById("backupEmailTimeInput");
    const backupEmailRecipientsInput = document.getElementById("backupEmailRecipientsInput");
    if (backupEmailEnabledInput) backupEmailEnabledInput.checked = profile.backup_email_enabled === true;
    if (backupEmailTimeInput) backupEmailTimeInput.value = asText(profile.backup_email_time_hhmm, "08:15");
    if (backupEmailRecipientsInput) backupEmailRecipientsInput.value = asText(profile.backup_email_recipients, "") === "-" ? "" : asText(profile.backup_email_recipients, "");
    state.hostInterestMode = normalizeHostInterestMode(profile.host_interest_mode || "all");
    state.hostInterestHosts = new Set(
      String(profile.host_interest_hosts || "")
        .split(",")
        .map((item) => item.trim())
        .filter((item) => item.length > 0)
    );
    renderHostInterestsEditor();

    const oauth = profile.microsoft_oauth || {};
    const oauthConnected = oauth.connected === true;
    const oauthLabel = oauthConnected
      ? `Verbunden: ${asText(oauth.external_email || oauth.external_display_name, "Microsoft Konto")}`
      : "Keine Microsoft Verbindung";
    const availabilityLabel = profile.mail_oauth_available
      ? "OAuth App konfiguriert"
      : "OAuth App noch nicht konfiguriert";
    if (summaryEl) {
      summaryEl.textContent = `${oauthLabel} | ${availabilityLabel}`;
    }
    if (connectButton) {
      connectButton.disabled = profile.mail_oauth_available !== true;
    }
    if (disconnectButton) {
      disconnectButton.disabled = !oauthConnected;
    }
    if (trendTestButton) {
      trendTestButton.disabled = !oauthConnected;
    }
    if (alertTestButton) {
      alertTestButton.disabled = !oauthConnected;
    }

    state.userProfileLoaded = true;
    setUserMailSettingsStatus("Benutzerspezifische Mail-Einstellungen geladen.");
  } catch (error) {
    setUserMailSettingsStatus(`Fehler beim Laden: ${error.message}`, true);
  }
}

async function saveUserProfile() {
  const enabledInput = document.getElementById("userEmailEnabledInput");
  const recipientInput = document.getElementById("userEmailRecipientInput");
  const trendRecipientInput = document.getElementById("trendDigestRecipientInput");
  // Sync digest recipient back to main email_recipient field if it changed
  if (trendRecipientInput && trendRecipientInput.value.trim()) {
    recipientInput.value = trendRecipientInput.value.trim();
  }
  const payload = {
    email_enabled: enabledInput.checked,
    email_recipient: recipientInput.value.trim(),
    trend_email_enabled: document.getElementById("trendEmailEnabledInput").checked,
    trend_email_time_hhmm: document.getElementById("trendEmailTimeInput").value || "08:00",
    digest_trend_metrics: ["digestMetricCpu", "digestMetricMemory", "digestMetricSwap", "digestMetricFilesystem"]
      .filter((id) => document.getElementById(id)?.checked)
      .map((id) => id.replace("digestMetric", "").toLowerCase())
      .join(",") || "cpu,memory,swap,filesystem",
    alert_email_enabled: document.getElementById("alertEmailEnabledInput").checked,
    alert_email_time_hhmm: document.getElementById("alertEmailTimeInput").value || "08:05",
    alert_email_recipients: document.getElementById("alertEmailRecipientsInput").value.trim(),
    alert_warning_email_recipients: document.getElementById("alertWarningEmailRecipientsInput")?.value.trim() || "",
    alert_critical_email_recipients: document.getElementById("alertCriticalEmailRecipientsInput")?.value.trim() || "",
    alert_instant_mail_enabled: document.getElementById("alertInstantMailEnabledInput")?.checked ?? false,
    alert_instant_min_severity: document.getElementById("alertInstantMinSeveritySelect")?.value || "warning",
    alert_instant_telegram_enabled: document.getElementById("alertInstantTelegramEnabledInput")?.checked ?? false,
    alert_telegram_chat_id: document.getElementById("alertTelegramChatIdInput")?.value.trim() || "",
    email_sender: document.getElementById("userEmailSenderInput")?.value.trim() || "",
    backup_email_enabled: document.getElementById("backupEmailEnabledInput")?.checked ?? false,
    backup_email_time_hhmm: document.getElementById("backupEmailTimeInput")?.value || "08:15",
    backup_email_recipients: document.getElementById("backupEmailRecipientsInput")?.value.trim() || "",
    host_interest_mode: normalizeHostInterestMode(document.getElementById("hostInterestModeSelect")?.value || state.hostInterestMode),
    host_interest_hosts: [...state.hostInterestHosts].sort().join(","),
  };

  if (payload.email_enabled && !payload.email_recipient) {
    throw new Error("Bitte zuerst einen Mail-Empfaenger eintragen.");
  }

  const response = await fetch("/api/v1/user-profile", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || ("HTTP " + response.status));
  }

  setUserMailSettingsStatus("Mail-Einstellungen gespeichert.");
  state.userProfileLoaded = false;
  await loadUserProfile(true);
  await loadHosts({ preserveScroll: true });
}

async function loadOauthSettings(force = false) {
  if (!state.isAdmin) {
    return;
  }
  if (state.oauthSettingsLoaded && !force) {
    return;
  }

  try {
    const response = await fetch("/api/v1/oauth-settings");
    if (!response.ok) {
      throw new Error("HTTP " + response.status);
    }
    const settings = await response.json();
    document.getElementById("microsoftOauthEnabledInput").checked = settings.microsoft_enabled === true;
    document.getElementById("microsoftTenantIdInput").value = asText(settings.microsoft_tenant_id, "") === "-" ? "" : asText(settings.microsoft_tenant_id, "");
    document.getElementById("microsoftClientIdInput").value = asText(settings.microsoft_client_id, "") === "-" ? "" : asText(settings.microsoft_client_id, "");
    document.getElementById("microsoftClientSecretInput").value = "";
    setOauthSettingsStatus(
      settings.microsoft_client_secret_configured
        ? "OAuth App geladen. Client Secret bleibt aus Sicherheitsgruenden verborgen."
        : "OAuth App geladen. Client Secret fehlt noch.",
    );
    state.oauthSettingsLoaded = true;
  } catch (error) {
    setOauthSettingsStatus(`Fehler beim Laden: ${error.message}`, true);
  }
}

async function saveOauthSettings() {
  const payload = {
    microsoft_enabled: document.getElementById("microsoftOauthEnabledInput").checked,
    microsoft_tenant_id: document.getElementById("microsoftTenantIdInput").value.trim(),
    microsoft_client_id: document.getElementById("microsoftClientIdInput").value.trim(),
  };
  const clientSecret = document.getElementById("microsoftClientSecretInput").value.trim();
  if (clientSecret) {
    payload.microsoft_client_secret = clientSecret;
  }

  const response = await fetch("/api/v1/oauth-settings", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || ("HTTP " + response.status));
  }
  state.oauthSettingsLoaded = false;
  state.userProfileLoaded = false;
  setOauthSettingsStatus("OAuth App gespeichert.");
  await loadOauthSettings(true);
  await loadUserProfile(true);
}

function renderUserManagementRows(users) {
  if (!Array.isArray(users) || users.length === 0) {
    return '<tr><td colspan="7" class="muted">Keine Benutzer vorhanden.</td></tr>';
  }

  return users.map((user) => {
    const username = asText(user.username, "");
    const usernameEnc = encodeURIComponent(username);
    const displayName = asText(user.display_name, "");
    const adminPill = `<span class="user-flag-pill ${user.is_admin ? "on" : "off"}">${user.is_admin ? "Admin" : "User"}</span>`;
    const activePill = `<span class="user-flag-pill ${user.is_disabled ? "off" : "on"}">${user.is_disabled ? "Gesperrt" : "Aktiv"}</span>`;
    const oauthPill = `<span class="oauth-state-pill ${user.has_microsoft_oauth ? "connected" : "disconnected"}">${user.has_microsoft_oauth ? asText(user.microsoft_connected_email, "verbunden") : "nicht verbunden"}</span>`;

    return `
      <tr>
        <td><strong>${escapeHtml(username)}</strong></td>
        <td>
          <span class="user-display-name-text">${displayName ? escapeHtml(displayName) : '<span class="muted">—</span>'}</span>
          <button type="button" class="inline-edit-btn" data-user-action="display-name" data-username-enc="${usernameEnc}" data-current-name="${escapeHtml(displayName)}" title="Anzeigename bearbeiten">✏️</button>
        </td>
        <td>${adminPill}</td>
        <td>${activePill}</td>
        <td>${escapeHtml(asText(user.email_recipient, "-"))}</td>
        <td>${oauthPill}</td>
        <td>
          <div class="user-management-actions">
            <button type="button" data-user-action="password" data-username-enc="${usernameEnc}">Passwort</button>
            <button type="button" data-user-action="admin" data-username-enc="${usernameEnc}" data-next="${user.is_admin ? "0" : "1"}">${user.is_admin ? "Admin aus" : "Admin an"}</button>
            <button type="button" data-user-action="disable" data-username-enc="${usernameEnc}" data-next="${user.is_disabled ? "0" : "1"}">${user.is_disabled ? "Aktivieren" : "Sperren"}</button>
            <button type="button" data-user-action="delete" data-username-enc="${usernameEnc}">Loeschen</button>
          </div>
        </td>
      </tr>
    `;
  }).join("");
}

async function submitWebUserAction(payload) {
  const response = await fetch("/api/v1/web-users", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || ("HTTP " + response.status));
  }
  return data;
}

function wireUserManagementActions() {
  const rows = document.getElementById("userManagementRows");
  if (!rows) {
    return;
  }

  rows.querySelectorAll("[data-user-action]").forEach((button) => {
    button.addEventListener("click", async () => {
      const action = button.getAttribute("data-user-action") || "";
      const username = decodeURIComponent(button.getAttribute("data-username-enc") || "");
      if (!action || !username) {
        return;
      }

      try {
        if (action === "password") {
          const password = window.prompt(`Neues Passwort fuer ${username}:`, "");
          if (password === null) {
            return;
          }
          await submitWebUserAction({ action: "set-password", username, password });
          setUserManagementStatus(`Passwort fuer ${username} aktualisiert.`);
        } else if (action === "display-name") {
          const current = button.getAttribute("data-current-name") || "";
          const newName = window.prompt(`Anzeigename fuer ${username}:`, current);
          if (newName === null) {
            return;
          }
          await submitWebUserAction({ action: "update-display-name", username, display_name: newName.trim() });
          setUserManagementStatus(`Anzeigename fuer ${username} aktualisiert.`);
        } else if (action === "admin") {
          await submitWebUserAction({
            action: "update-flags",
            username,
            is_admin: button.getAttribute("data-next") === "1",
          });
          setUserManagementStatus(`Admin-Flag fuer ${username} aktualisiert.`);
        } else if (action === "disable") {
          await submitWebUserAction({
            action: "update-flags",
            username,
            is_disabled: button.getAttribute("data-next") === "1",
          });
          setUserManagementStatus(`Status fuer ${username} aktualisiert.`);
        } else if (action === "delete") {
          if (!window.confirm(`Benutzer ${username} wirklich loeschen?`)) {
            return;
          }
          await submitWebUserAction({ action: "delete", username });
          setUserManagementStatus(`Benutzer ${username} geloescht.`);
        }
        state.userManagementLoaded = false;
        await loadWebUsers(true);
        // Refresh badge if the current user changed their own display name
        if (action === "display-name" && username === state.authUser) {
          try {
            const session = await fetchSessionState();
            state.authDisplayName = asText(session.display_name, "");
            const badge = document.getElementById("brandUserBadge");
            if (badge) badge.textContent = state.authDisplayName || state.authUser;
          } catch { /* non-critical */ }
        }
      } catch (error) {
        setUserManagementStatus(error.message, true);
      }
    });
  });
}

async function loadWebUsers(force = false) {
  if (!state.isAdmin) {
    return;
  }
  if (state.userManagementLoaded && !force) {
    return;
  }

  const rowsEl = document.getElementById("userManagementRows");
  rowsEl.innerHTML = '<tr><td colspan="6" class="muted">Lade Benutzer...</td></tr>';
  try {
    const response = await fetch("/api/v1/web-users");
    if (!response.ok) {
      throw new Error("HTTP " + response.status);
    }
    const data = await response.json();
    rowsEl.innerHTML = renderUserManagementRows(data.users || []);
    wireUserManagementActions();
    state.userManagementLoaded = true;
    setUserManagementStatus("Benutzerliste geladen.");
  } catch (error) {
    rowsEl.innerHTML = `<tr><td colspan="6" class="muted">Fehler: ${escapeHtml(error.message)}</td></tr>`;
    setUserManagementStatus(`Fehler beim Laden: ${error.message}`, true);
  }
}

async function createUser() {
  const usernameInput = document.getElementById("newUserUsernameInput");
  const displayNameInput = document.getElementById("newUserDisplayNameInput");
  const passwordInput = document.getElementById("newUserPasswordInput");
  const isAdminInput = document.getElementById("newUserIsAdminInput");

  const username = usernameInput.value.trim();
  const password = passwordInput.value;
  if (!username || !password) {
    throw new Error("Bitte Benutzername und Passwort eingeben.");
  }

  await submitWebUserAction({
    action: "create",
    username,
    password,
    is_admin: isAdminInput.checked,
    display_name: displayNameInput ? displayNameInput.value.trim() : "",
  });

  usernameInput.value = "";
  if (displayNameInput) displayNameInput.value = "";
  passwordInput.value = "";
  isAdminInput.checked = false;
  setUserManagementStatus(`Benutzer ${username} angelegt.`);
  state.userManagementLoaded = false;
  await loadWebUsers(true);
}

async function disconnectMicrosoftOauth() {
  const response = await fetch("/api/v1/oauth/microsoft/disconnect", {
    method: "POST",
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || ("HTTP " + response.status));
  }
  state.userProfileLoaded = false;
  setUserMailSettingsStatus("Microsoft Verbindung getrennt.");
  await loadUserProfile(true);
  if (state.isAdmin) {
    state.userManagementLoaded = false;
    await loadWebUsers(true);
  }
}

async function sendTrendDigestMailTest() {
  const response = await fetch("/api/v1/mail-test/trends", {
    method: "POST",
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || data.details || ("HTTP " + response.status));
  }
  setUserMailSettingsStatus("Trend-Testmail versendet.");
}

async function sendAlertDigestMailTest() {
  const response = await fetch("/api/v1/mail-test/alerts", {
    method: "POST",
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || data.details || ("HTTP " + response.status));
  }
  setUserMailSettingsStatus("Alarm-Testmail versendet.");
}

async function sendBackupDigestMailTest() {
  const response = await fetch("/api/v1/mail-test/backup", {
    method: "POST",
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || data.details || ("HTTP " + response.status));
  }
  setUserMailSettingsStatus("Backup-Testmail versendet.");
}

function setAdminAlertSubscriptionsStatus(message, isError = false) {
  const statusEl = document.getElementById("adminAlertSubscriptionsStatus");
  if (!statusEl) return;
  statusEl.textContent = message;
  statusEl.classList.toggle("error", isError);
}

function renderAdminAlertSubscriptionsContainer(users, availableHosts, telegramAvailable) {
  const container = document.getElementById("adminAlertSubscriptionsContainer");
  if (!container) return;

  if (!users || users.length === 0) {
    container.innerHTML = '<p class="muted">Keine Benutzer vorhanden.</p>';
    return;
  }

  const usersSorted = users.slice().sort((a, b) => String(a.username || "").localeCompare(String(b.username || ""), undefined, { sensitivity: "base" }));
  const hosts = (availableHosts || []).slice().sort((a, b) => {
    const la = String(a.display_name || a.hostname || "").toLowerCase();
    const lb = String(b.display_name || b.hostname || "").toLowerCase();
    return la.localeCompare(lb);
  });

  const userSubscriptionMaps = new Map();
  for (const userEntry of usersSorted) {
    const subMap = new Map();
    for (const sub of Array.isArray(userEntry.subscriptions) ? userEntry.subscriptions : []) {
      const hostname = String(sub.hostname || "").trim();
      if (hostname) {
        subMap.set(hostname, {
          notify_mail: sub.notify_mail !== false,
          notify_telegram: sub.notify_telegram !== false,
        });
      }
    }
    userSubscriptionMaps.set(String(userEntry.username || ""), subMap);
  }

  const rows = hosts.length === 0
    ? '<tr><td colspan="3" class="muted">Keine Hosts vorhanden.</td></tr>'
    : hosts.map((host) => {
        const hostnameRaw = String(host.hostname || "").trim();
        const displayNameRaw = String(host.display_name || hostnameRaw || "").trim();
        const hostname = escapeHtml(hostnameRaw);
        const displayName = escapeHtml(displayNameRaw || hostnameRaw);
        const hostLabel = displayNameRaw && hostnameRaw && displayNameRaw !== hostnameRaw
          ? `<strong>${displayName}</strong><span class="global-hostname-sub">(${hostname})</span>`
          : `<strong>${displayName || hostname}</strong>`;

        const renderChannelRows = (channel) => usersSorted.map((userEntry) => {
          const usernameRaw = String(userEntry.username || "");
          const username = escapeHtml(usernameRaw);
          const subMap = userSubscriptionMaps.get(usernameRaw) || new Map();
          const sub = subMap.get(hostnameRaw);
          const enabled = channel === "mail"
            ? (sub ? sub.notify_mail !== false : true)
            : (sub ? sub.notify_telegram !== false : true);
          const disabled = channel === "telegram" && !telegramAvailable;
          return `<label class="admin-sub-user-chip${userEntry.is_admin ? " is-admin" : ""}${disabled ? " is-disabled" : ""}">
            <input type="checkbox" class="admin-sub-cb" data-username="${username}" data-hostname="${hostname}" data-channel="${channel}" ${enabled ? "checked" : ""} ${disabled ? "disabled" : ""}>
            <span class="admin-sub-user-name">${username}</span>
          </label>`;
        }).join("");

        return `<tr>
          <td class="admin-sub-host-cell">${hostLabel}</td>
          <td><div class="admin-sub-user-stack">${renderChannelRows("mail")}</div></td>
          <td><div class="admin-sub-user-stack">${renderChannelRows("telegram")}</div></td>
        </tr>`;
      }).join("");

  container.innerHTML = `<div class="table-wrap user-management-table-wrap">
    <table class="user-management-table admin-alert-subscriptions-table">
      <thead><tr><th>Host</th><th>Mail</th><th>Telegram</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;

  container.querySelectorAll(".admin-sub-cb").forEach((checkbox) => {
    checkbox.addEventListener("change", () => {
      setAdminAlertSubscriptionsStatus("Ungespeicherte Aenderungen.");
    });
  });
}

async function saveAdminAlertSubscriptions() {
  const container = document.getElementById("adminAlertSubscriptionsContainer");
  if (!container) return;
  const toggles = Array.from(container.querySelectorAll(".admin-sub-cb[data-username][data-hostname][data-channel]"));
  const groupedByUser = new Map();

  for (const userEntry of state.adminAlertSubscriptionsUsers || []) {
    const username = String(userEntry.username || "");
    if (!username) continue;
    const hostMap = new Map();
    for (const host of state.adminAlertAvailableHosts || []) {
      const hostname = String(host.hostname || "").trim();
      if (!hostname) continue;
      hostMap.set(hostname, {
        hostname,
        notify_mail: true,
        notify_telegram: true,
      });
    }
    groupedByUser.set(username, hostMap);
  }

  for (const toggle of toggles) {
    const username = decodeURIComponent(toggle.dataset.username || "");
    const hostname = decodeURIComponent(toggle.dataset.hostname || "");
    const channel = toggle.dataset.channel || "";
    if (!username || !hostname || !groupedByUser.has(username)) continue;
    const hostMap = groupedByUser.get(username);
    if (!hostMap.has(hostname)) {
      hostMap.set(hostname, { hostname, notify_mail: true, notify_telegram: true });
    }
    const entry = hostMap.get(hostname);
    const enabled = toggle.checked;
    if (channel === "mail") entry.notify_mail = enabled;
    if (channel === "telegram") entry.notify_telegram = enabled;
  }

  for (const [username, hostMap] of groupedByUser.entries()) {
    const response = await fetch("/api/v1/admin/user-alert-subscriptions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, subscriptions: Array.from(hostMap.values()) }),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data.error || "HTTP " + response.status);
    }
  }
  setAdminAlertSubscriptionsStatus("Abos gespeichert.");
}

async function loadAdminAlertSubscriptions(force = false) {
  if (state.adminAlertSubscriptionsLoaded && !force) return;
  const container = document.getElementById("adminAlertSubscriptionsContainer");
  if (!container) return;
  container.innerHTML = '<p class="muted">Lade Admin-Daten...</p>';
  setAdminAlertSubscriptionsStatus("Lade...");
  try {
    const response = await fetch("/api/v1/admin/user-alert-subscriptions");
    if (!response.ok) throw new Error("HTTP " + response.status);
    const data = await response.json();
    state.adminAlertSubscriptionsUsers = Array.isArray(data.users) ? data.users : [];
    state.adminAlertAvailableHosts = Array.isArray(data.available_hosts) ? data.available_hosts : [];
    state.adminAlertTelegramAvailable = !!data.telegram_available;
    renderAdminAlertSubscriptionsContainer(
      state.adminAlertSubscriptionsUsers,
      state.adminAlertAvailableHosts,
      state.adminAlertTelegramAvailable,
    );
    state.adminAlertSubscriptionsLoaded = true;
    setAdminAlertSubscriptionsStatus("Geladen.");
  } catch (err) {
    container.innerHTML = `<p class="muted">Fehler: ${escapeHtml(err.message)}</p>`;
    setAdminAlertSubscriptionsStatus(`Fehler: ${err.message}`, true);
  }
}

function mountAdminSettingsIntoGlobalView() {
  const container = document.getElementById("globalAdminSettingsContainer");
  if (!container) {
    return;
  }
  const sections = [
    document.getElementById("adminOauthSettingsSection"),
    document.getElementById("adminUserManagementSection"),
    document.getElementById("globalAlarmSettingsSection"),
  ];
  for (const section of sections) {
    if (!section) {
      continue;
    }
    if (section.parentElement !== container) {
      container.appendChild(section);
    }
  }
}

async function loadGlobalAdminSettingsPanel(force = false) {
  updateAdminSettingsVisibility();
  if (!state.isAdmin) {
    return;
  }
  await loadAlarmSettings(force);
  await loadOauthSettings(force);
  await loadWebUsers(force);
}

async function loadSettingsPanel(force = false) {
  updateAdminSettingsVisibility();
  await loadUserProfile(force);
}

function consumeOauthStatusFromUrl() {
  const url = new URL(window.location.href);
  const oauthStatus = url.searchParams.get("oauth_status");
  const oauthMessage = url.searchParams.get("oauth_message");
  if (!oauthStatus) {
    return null;
  }
  url.searchParams.delete("oauth_status");
  url.searchParams.delete("oauth_message");
  window.history.replaceState({}, document.title, url.pathname + (url.search ? url.search : ""));
  return {
    status: oauthStatus,
    message: oauthMessage || "",
  };
}

async function saveAlarmSettings() {
  const warningInput = document.getElementById("warningThresholdInput");
  const criticalInput = document.getElementById("criticalThresholdInput");
  const cpuWarningThresholdInput = document.getElementById("cpuWarningThresholdInput");
  const cpuCriticalThresholdInput = document.getElementById("cpuCriticalThresholdInput");
  const cpuAlertWindowReportsInput = document.getElementById("cpuAlertWindowReportsInput");
  const ramWarningThresholdInput = document.getElementById("ramWarningThresholdInput");
  const ramCriticalThresholdInput = document.getElementById("ramCriticalThresholdInput");
  const ramAlertWindowReportsInput = document.getElementById("ramAlertWindowReportsInput");
  const warningConsecutiveHitsInput = document.getElementById("warningConsecutiveHitsInput");
  const warningWindowMinutesInput = document.getElementById("warningWindowMinutesInput");
  const criticalImmediateInput = document.getElementById("criticalImmediateInput");
  const telegramEnabledInput = document.getElementById("telegramEnabledInput");
  const telegramBotTokenInput = document.getElementById("telegramBotTokenInput");
  const telegramChatIdInput = document.getElementById("telegramChatIdInput");
  const inactiveHostAlertEnabledInput = document.getElementById("inactiveHostAlertEnabledInput");
  const inactiveHostAlertHoursInput = document.getElementById("inactiveHostAlertHoursInput");

  const warning = Number(warningInput.value);  const critical = Number(criticalInput.value);
  const cpuWarning = Number(cpuWarningThresholdInput.value);
  const cpuCritical = Number(cpuCriticalThresholdInput.value);
  const cpuWindowReports = Number(cpuAlertWindowReportsInput.value);
  const ramWarning = Number(ramWarningThresholdInput.value);
  const ramCritical = Number(ramCriticalThresholdInput.value);
  const ramWindowReports = Number(ramAlertWindowReportsInput.value);
  const warningConsecutiveHits = Number(warningConsecutiveHitsInput.value);
  const warningWindowMinutes = Number(warningWindowMinutesInput.value);
  const alertReminderIntervalHours = Number(document.getElementById("alertReminderIntervalHoursInput")?.value || 0);
  const inactiveHostAlertHours = Number(inactiveHostAlertHoursInput?.value || 3);

  if (!Number.isFinite(warning) || !Number.isFinite(critical) || warning < 1 || critical > 100 || warning >= critical) {
    throw new Error("Schwellwerte ungueltig: Warnung muss kleiner als Kritisch sein.");
  }
  if (!Number.isFinite(cpuWarning) || !Number.isFinite(cpuCritical) || cpuWarning < 1 || cpuCritical > 100 || cpuWarning >= cpuCritical) {
    throw new Error("CPU Schwellwerte ungueltig: Warnung muss kleiner als Kritisch sein.");
  }
  if (!Number.isFinite(ramWarning) || !Number.isFinite(ramCritical) || ramWarning < 1 || ramCritical > 100 || ramWarning >= ramCritical) {
    throw new Error("RAM Schwellwerte ungueltig: Warnung muss kleiner als Kritisch sein.");
  }
  if (!Number.isFinite(cpuWindowReports) || cpuWindowReports < 2 || cpuWindowReports > 24) {
    throw new Error("CPU Fenster muss zwischen 2 und 24 Meldungen liegen.");
  }
  if (!Number.isFinite(ramWindowReports) || ramWindowReports < 2 || ramWindowReports > 24) {
    throw new Error("RAM Fenster muss zwischen 2 und 24 Meldungen liegen.");
  }
  if (!Number.isFinite(warningConsecutiveHits) || warningConsecutiveHits < 1 || warningConsecutiveHits > 10) {
    throw new Error("Entprellung Treffer muss zwischen 1 und 10 liegen.");
  }
  if (!Number.isFinite(warningWindowMinutes) || warningWindowMinutes < 1 || warningWindowMinutes > 240) {
    throw new Error("Entprellung Fenster muss zwischen 1 und 240 Minuten liegen.");
  }

  const payload = {
    warning_threshold_percent: warning,
    critical_threshold_percent: critical,
    cpu_warning_threshold_percent: cpuWarning,
    cpu_critical_threshold_percent: cpuCritical,
    cpu_alert_window_reports: Math.floor(cpuWindowReports),
    ram_warning_threshold_percent: ramWarning,
    ram_critical_threshold_percent: ramCritical,
    ram_alert_window_reports: Math.floor(ramWindowReports),
    warning_consecutive_hits: Math.floor(warningConsecutiveHits),
    warning_window_minutes: Math.floor(warningWindowMinutes),
    critical_trigger_immediate: criticalImmediateInput.checked,
    telegram_enabled: telegramEnabledInput.checked,
    telegram_bot_token: telegramBotTokenInput.value.trim(),
    telegram_chat_id: telegramChatIdInput.value.trim(),
    alert_reminder_interval_hours: Number.isFinite(alertReminderIntervalHours) ? Math.max(0, Math.min(168, Math.floor(alertReminderIntervalHours))) : 0,
    inactive_host_alert_enabled: inactiveHostAlertEnabledInput?.checked === true,
    inactive_host_alert_hours: Number.isFinite(inactiveHostAlertHours) ? Math.max(1, Math.min(168, Math.floor(inactiveHostAlertHours))) : 3,
    ai_troubleshoot_enabled: document.getElementById("aiTroubleshootEnabledInput")?.checked === true,
    openai_api_key: document.getElementById("openaiApiKeyInput")?.value.trim() || "",
    openai_model: (document.getElementById("openaiModelInput")?.value.trim() || "gpt-4o-mini"),
    openai_timeout_sec: Math.max(3, Math.min(60, Math.floor(Number(document.getElementById("openaiTimeoutSecInput")?.value || 12)))),
    openai_max_tokens: Math.max(256, Math.min(4000, Math.floor(Number(document.getElementById("openaiMaxTokensInput")?.value || 1200)))),
    ai_troubleshoot_cache_ttl_sec: Math.max(30, Math.min(3600, Math.floor(Number(document.getElementById("openaiCacheTtlSecInput")?.value || 600)))),
  };

  const response = await fetch("/api/v1/alarm-settings", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || data.details || ("HTTP " + response.status));
  }

  setAlarmSettingsStatus("Einstellungen gespeichert.");
  // Refresh the "API key is set" hint from the server response
  const hint = document.getElementById("openaiApiKeyIsSetHint");
  if (hint) {
    hint.textContent = data.settings?.openai_api_key_is_set ? "API Key ist gesetzt." : "Kein API Key gespeichert.";
  }
  // Clear the API key input after save
  const keyInput = document.getElementById("openaiApiKeyInput");
  if (keyInput) keyInput.value = "";
  await loadAlertsForHost();
  await loadAnalysisForHost();
}

async function sendAlarmSettingsTest() {
  const response = await fetch("/api/v1/alarm-test", {
    method: "POST",
  });

  const data = await response.json().catch(() => ({ details: "Keine Details" }));
  if (!response.ok) {
    throw new Error(data.details || ("HTTP " + response.status));
  }

  setAlarmSettingsStatus("Testbenachrichtigung versendet.");
}

function formatPercent(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) {
    return "-";
  }
  return `${n.toFixed(1)}%`;
}

function renderAlertMountpointLabel(mountpoint, width = 60) {
  if (mountpoint === "cpu") return "🖥️ CPU-Auslastung";
  if (mountpoint === "ram") return "🧠 RAM-Auslastung";
  if (mountpoint === "__inactive_host__") return "💤 Host inaktiv";
  return renderPathCell(mountpoint, width);
}

function formatSignedPercent(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) {
    return "-";
  }
  const sign = n > 0 ? "+" : "";
  return `${sign}${n.toFixed(1)}%`;
}

function formatNumber(value, digits = 1) {
  const n = Number(value);
  if (!Number.isFinite(n)) {
    return "-";
  }
  return n.toFixed(digits);
}

function formatKilobytes(kbValue) {
  const kb = Number(kbValue);
  if (!Number.isFinite(kb) || kb < 0) {
    return "-";
  }

  const mib = kb / 1024;
  if (mib < 1024) {
    return `${mib.toFixed(0)} MiB`;
  }

  return `${(mib / 1024).toFixed(2)} GiB`;
}

function formatBytes(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) {
    return "-";
  }
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let amount = n;
  let unitIndex = 0;
  while (amount >= 1024 && unitIndex < units.length - 1) {
    amount /= 1024;
    unitIndex += 1;
  }
  const digits = amount >= 100 ? 0 : amount >= 10 ? 1 : 2;
  return `${amount.toFixed(digits)} ${units[unitIndex]}`;
}

function normalizeMountpointValue(value) {
  return String(value || "").trim();
}

function uniqueSortedMountpoints(values) {
  const seen = new Set();
  const result = [];
  for (const value of Array.isArray(values) ? values : []) {
    const mountpoint = normalizeMountpointValue(value);
    if (!mountpoint) continue;
    const key = mountpoint.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(mountpoint);
  }
  return result.sort((left, right) => left.localeCompare(right, "de", { numeric: true, sensitivity: "base" }));
}

function mountpointHiddenSet(values) {
  return new Set(uniqueSortedMountpoints(values).map((item) => item.toLowerCase()));
}

function hiddenMountpointsForSection(section) {
  if (section === "fs-focus") {
    return uniqueSortedMountpoints(state.fsFocusHiddenMountpoints);
  }
  if (section === "large-files") {
    return uniqueSortedMountpoints(state.largeFilesHiddenMountpoints);
  }
  return [];
}

function availableMountpointsForSection(section) {
  if (section === "fs-focus") {
    return uniqueSortedMountpoints(state.fsFocusAvailableMountpoints);
  }
  if (section === "large-files") {
    return uniqueSortedMountpoints(state.largeFilesAvailableMountpoints);
  }
  return [];
}

function setHiddenMountpointsForSection(section, values) {
  const normalized = uniqueSortedMountpoints(values);
  if (section === "fs-focus") {
    state.fsFocusHiddenMountpoints = normalized;
  } else if (section === "large-files") {
    state.largeFilesHiddenMountpoints = normalized;
  }
}

function filterFilesystemTrendsByVisibility(rows, hiddenMountpoints) {
  const hidden = mountpointHiddenSet(hiddenMountpoints);
  return (Array.isArray(rows) ? rows : []).filter((row) => {
    const mountpoint = normalizeMountpointValue(row?.mountpoint).toLowerCase();
    return mountpoint && !hidden.has(mountpoint);
  });
}

function collectLargeFilesMountpoints(largeFiles) {
  if (!largeFiles || typeof largeFiles !== "object") {
    return [];
  }
  const filesystems = Array.isArray(largeFiles.filesystems) ? largeFiles.filesystems : [];
  return uniqueSortedMountpoints(filesystems.map((item) => normalizeMountpointValue(item?.mountpoint)));
}

function setFilesystemVisibilityStatus(message, isError = false) {
  const statusEl = document.getElementById("filesystemVisibilityStatus");
  if (!statusEl) return;
  statusEl.textContent = message;
  statusEl.classList.toggle("status-error", isError);
}

function updateFilesystemVisibilityButtons() {
  const fsButton = document.getElementById("filesystemFocusSettingsButton");
  const lfButton = document.getElementById("largeFilesSettingsButton");
  const enabled = Boolean(state.isAuthenticated && state.fsVisibilityEditable && state.selectedHost);
  if (fsButton) fsButton.classList.toggle("hidden", !enabled);
  if (lfButton) lfButton.classList.toggle("hidden", !enabled);
}

function renderFilesystemVisibilityModalContent() {
  const listEl = document.getElementById("filesystemVisibilityList");
  const summaryEl = document.getElementById("filesystemVisibilitySummary");
  const titleEl = document.getElementById("filesystemVisibilityTitle");
  if (!listEl || !summaryEl || !titleEl) return;

  const section = state.fsVisibilitySection;
  const available = availableMountpointsForSection(section);
  const hidden = hiddenMountpointsForSection(section);
  const hiddenSet = mountpointHiddenSet(hidden);
  const visibleCount = available.filter((item) => !hiddenSet.has(item.toLowerCase())).length;

  titleEl.textContent = section === "large-files"
    ? "⚙️ Top-Dateien: Filesystem-Auswahl"
    : "⚙️ Filesystem Fokus: Filesystem-Auswahl";
  summaryEl.textContent = `Host: ${state.selectedDisplayName || state.selectedHost} | Sichtbar: ${visibleCount}/${available.length}`;

  if (available.length === 0) {
    listEl.innerHTML = '<p class="muted">Keine Filesysteme verfuegbar.</p>';
    return;
  }

  listEl.innerHTML = available
    .map((mountpoint, idx) => {
      const key = `fsVis-${idx}`;
      const checked = !hiddenSet.has(mountpoint.toLowerCase());
      return `
        <label class="filesystem-visibility-item" for="${key}">
          <input id="${key}" type="checkbox" data-mountpoint="${escapeHtml(mountpoint)}" ${checked ? "checked" : ""} />
          <span class="filesystem-visibility-mount">${escapeHtml(mountpoint)}</span>
        </label>
      `;
    })
    .join("");
}

function closeFilesystemVisibilityModal() {
  const modal = document.getElementById("filesystemVisibilityModal");
  if (!modal) return;
  modal.classList.add("hidden");
  state.fsVisibilitySection = "";
  setFilesystemVisibilityStatus("");
}

function openFilesystemVisibilityModal(section) {
  if (!state.selectedHost || !state.fsVisibilityEditable) return;
  state.fsVisibilitySection = section;
  setFilesystemVisibilityStatus("");
  renderFilesystemVisibilityModalContent();
  const modal = document.getElementById("filesystemVisibilityModal");
  if (modal) modal.classList.remove("hidden");
}

async function saveFilesystemVisibilityFromModal() {
  const section = state.fsVisibilitySection;
  if (!section || !state.selectedHost) return;
  const listEl = document.getElementById("filesystemVisibilityList");
  if (!listEl) return;

  const checkboxes = Array.from(listEl.querySelectorAll("input[type='checkbox'][data-mountpoint]"));
  const hiddenMountpoints = checkboxes
    .filter((item) => !item.checked)
    .map((item) => normalizeMountpointValue(item.getAttribute("data-mountpoint")));

  setFilesystemVisibilityStatus("Speichere...");
  const response = await fetch("/api/v1/filesystem-visibility", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      hostname: state.selectedHost,
      section,
      hidden_mountpoints: hiddenMountpoints,
    }),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload.error || ("HTTP " + response.status));
  }

  setHiddenMountpointsForSection(section, payload.hidden_mountpoints || hiddenMountpoints);
  setFilesystemVisibilityStatus("Gespeichert.");
  await loadAnalysisForHost();
  closeFilesystemVisibilityModal();
}

function renderLargeFilePathCell(value) {
  const full = asText(value, "-");
  if (full === "-") {
    return `<span class="path-cell">-</span>`;
  }
  const lastSlash = full.lastIndexOf("/");
  const hasSlash = lastSlash >= 0;
  const dir = hasSlash ? full.slice(0, lastSlash + 1) : "";
  const name = hasSlash ? full.slice(lastSlash + 1) : full;
  const displayName = name || "/";
  return `
    <div class="large-file-path" title="${escapeHtml(full)}">
      <span class="large-file-path-dir">${escapeHtml(dir)}</span><span class="large-file-path-name">${escapeHtml(displayName)}</span>
    </div>
  `;
}

function renderLargeFilesPanel(largeFiles, hiddenMountpoints = []) {
  const panel = document.getElementById("largeFilesPanel");
  const meta = document.getElementById("largeFilesMeta");
  const body = document.getElementById("largeFilesBody");
  if (!panel || !meta || !body) {
    return;
  }

  if (!largeFiles || typeof largeFiles !== "object") {
    panel.classList.add("hidden");
    body.innerHTML = "";
    meta.textContent = "";
    return;
  }

  const rawFilesystems = Array.isArray(largeFiles.filesystems) ? largeFiles.filesystems : [];
  const hiddenSet = mountpointHiddenSet(hiddenMountpoints);
  const filesystems = rawFilesystems.filter((fs) => !hiddenSet.has(normalizeMountpointValue(fs?.mountpoint).toLowerCase()));
  const scanStatus = asText(largeFiles.status, "");
  const scanTime = asText(largeFiles.scanned_at_utc, "");
  const scanTimeText = scanTime ? formatUtcPlus2(scanTime) : "-";
  const topN = Number(largeFiles.top_n || 10);
  const minSizeMb = Number(largeFiles.min_size_mb || 0);
  const timedOut = Boolean(largeFiles.timed_out);
  const scanIntervalHours = Number(largeFiles.scan_interval_hours);
  const runHourUtc = Number(largeFiles.run_hour_utc);
  const statusLabelMap = {
    ok: "OK",
    cached: "Cache",
    scheduled: "Geplant",
    error: "Fehler",
    unavailable: "Nicht verfuegbar",
    unsupported: "Nicht unterstuetzt",
    disabled: "Deaktiviert",
  };
  const statusLabel = statusLabelMap[scanStatus] || (scanStatus || "-");
  const runHourText = Number.isFinite(runHourUtc)
    ? `${String(Math.max(0, Math.min(23, Math.floor(runHourUtc)))).padStart(2, "0")}:00 UTC`
    : "-";

  panel.classList.remove("hidden");

  if (largeFiles.enabled === false) {
    const unsupportedReason = asText(largeFiles.status, "disabled") === "unsupported"
      ? "Nicht unterstuetzt auf diesem Host"
      : "Deaktiviert";
    meta.textContent = `📌 Status: ${unsupportedReason}`;
    body.innerHTML = '<p class="muted">Large-File-Scan ist fuer dieses Betriebssystem nicht verfuegbar.</p>';
    return;
  }

  meta.textContent = `🕒 Scan: ${scanTimeText} | 📌 Status: ${statusLabel} | 🧮 Min ${minSizeMb} MB / Top ${topN} | ⏰ Plan: ${Number.isFinite(scanIntervalHours) ? `${Math.max(1, Math.floor(scanIntervalHours))}h` : "-"} @ ${runHourText}${timedOut ? " | ⚠️ Timeout" : ""}`;


  if (filesystems.length === 0) {
    const statusText = scanStatus === "scheduled"
      ? "Nächster geplanter Scan steht noch aus (taeglicher Lauf)."
      : scanStatus === "unavailable"
        ? "Large-File-Scan nicht verfuegbar auf diesem Host."
        : scanStatus === "ok"
          ? "Scan abgeschlossen, aber es konnten keine Dateisysteme ausgewertet werden."
          : scanStatus === "error"
            ? `Scan fehlgeschlagen: ${escapeHtml(asText(largeFiles.error, "unbekannter Fehler"))}`
            : "Noch keine Large-File-Daten verfuegbar.";
    body.innerHTML = `<p class="muted">${statusText}</p>`;
    return;
  }

  body.innerHTML = filesystems
    .map((fs) => {
      const mountpoint = asText(fs.mountpoint, "-");
      const entries = Array.isArray(fs.top_files) ? fs.top_files : [];
      const scannedFiles = Number(fs.scanned_regular_files || 0).toLocaleString("de-DE");
      const rows = entries.length > 0
        ? entries
          .map((entry) => {
            const path = asText(entry.path, "-");
            const owner = asText(entry.owner, "-");
            const size = formatBytes(entry.size_bytes);
            const modified = formatUtcPlus2(entry.modified_at_utc);
            return `
              <tr>
                <td class="lf-row-cell" colspan="4">
                  ${renderLargeFilePathCell(path)}
                  <div class="large-file-meta-row">
                    <span><strong>📦 Groesse:</strong> ${escapeHtml(size)}</span>
                    <span><strong>👤 Owner:</strong> ${escapeHtml(owner)}</span>
                    <span><strong>🕒 Geaendert:</strong> ${escapeHtml(modified)}</span>
                  </div>
                </td>
              </tr>
            `;
          })
          .join("")
        : '<tr><td colspan="4" class="muted">Keine Dateien ueber Schwellwert gefunden.</td></tr>';
      return `
        <details class="large-files-fs">
          <summary>${escapeHtml(mountpoint)} <span>${entries.length} Treffer, ${scannedFiles} Dateien gescannt</span></summary>
          <div class="table-wrap">
            <table class="large-files-table">
              <thead>
                <tr>
                  <th>Datei / Details</th>
                </tr>
              </thead>
              <tbody>
                ${rows}
              </tbody>
            </table>
          </div>
        </details>
      `;
    })
    .join("");
}

function resourceTroubleshootingHint(label, value, suffix) {
  const v = Number(value?.current);
  if (!Number.isFinite(v)) return "";
  let hint = "";
  if (label.includes("Swap") && v >= 50) {
    hint = v >= 80
      ? "Swap kritisch: Speicherleck möglich. Prüfe: <code>ps aux --sort=-%mem | head -10</code> — ggf. Dienst neu starten oder RAM erweitern."
      : "Swap erhöht: RAM-Auslastung beobachten. Prüfe: <code>free -h</code> und speicherintensive Prozesse mit <code>top -o %MEM</code>.";
  } else if (label.includes("RAM") && v >= 85) {
    hint = v >= 95
      ? "RAM kritisch: Sofort prüfen. <code>ps aux --sort=-%mem | head -10</code> — Dienst mit Leak neu starten."
      : "RAM hoch: Prüfe mit <code>ps aux --sort=-%mem | head</code> welcher Prozess am meisten verbraucht.";
  } else if (label.includes("CPU") && v >= 80) {
    hint = v >= 95
      ? "CPU kritisch: <code>top</code> oder <code>htop</code> — überlastenden Prozess identifizieren und Logs prüfen."
      : "CPU hoch: Prüfe mit <code>top -o %CPU</code> welcher Prozess belastet. Cronjobs oder Backups als Ursache ausschliessen.";
  } else if (label.includes("Load") && v >= 4) {
    hint = "Load erhöht: Prüfe Prozessanzahl mit <code>ps aux | wc -l</code> und I/O-Last mit <code>iostat -x 1 5</code>.";
  }
  if (!hint) return "";
  return `<span class="trend-hint">💡 ${hint}</span>`;
}

function aiSeverityLabel(value) {
  const normalized = String(value || "").toLowerCase();
  if (normalized === "critical") return "Kritisch";
  if (normalized === "warning") return "Warnung";
  return "Info";
}

function aiConfidenceLabel(value) {
  const normalized = String(value || "").toLowerCase();
  if (normalized === "hoch") return "hoch";
  if (normalized === "niedrig") return "niedrig";
  return "mittel";
}

function renderAiList(items) {
  const list = Array.isArray(items) ? items.filter((item) => String(item || "").trim()) : [];
  if (list.length === 0) {
    return "<p class=\"muted\">Keine Eintraege.</p>";
  }
  return `<ul>${list.map((item) => `<li>${escapeHtml(String(item))}</li>`).join("")}</ul>`;
}

function renderAiCodeBlocks(blocks) {
  const snippets = Array.isArray(blocks) ? blocks : [];
  if (snippets.length === 0) {
    return "<p class=\"muted\">Keine Codeschnipsel vorhanden.</p>";
  }
  return snippets
    .map((item) => {
      const shell = String(item?.shell || "bash");
      const title = String(item?.title || "Befehl");
      const command = String(item?.command || "").trim();
      const description = String(item?.description || "").trim();
      return `
        <article class="ai-code-card">
          <header><strong>${escapeHtml(title)}</strong><span>${escapeHtml(shell)}</span></header>
          ${description ? `<p>${escapeHtml(description)}</p>` : ""}
          <pre><code>${escapeHtml(command)}</code></pre>
        </article>
      `;
    })
    .join("");
}

function renderResourceTrendCards(resourceTrends, latestReportTimeUtc, swapTotalKb) {
  const standText = formatUtcPlus2(latestReportTimeUtc);
  const entries = [
    ["🧠 CPU", resourceTrends.cpu_usage_percent, "%", "cpu_usage_percent"],
    ["📉 Load 1m", resourceTrends.load_avg_1, "", ""],
    ["🧮 RAM", resourceTrends.memory_used_percent, "%", "memory_used_percent"],
    ["💤 Swap", resourceTrends.swap_used_percent, "%", "swap_used_percent"],
  ];

  return entries
    .map(([label, value, suffix, metricKey]) => {
      if (!value) {
        return `
          <article class="trend-card muted">
            <strong>${label}</strong>
            <span>Keine Daten</span>
          </article>
        `;
      }

      const swapSizeLine = label.includes("Swap") && swapTotalKb != null && swapTotalKb > 0
        ? `<span>Gesamt: ${formatKilobytes(swapTotalKb)}</span>`
        : "";

      const aiButton = metricKey
        ? `<button class="btn-secondary btn-secondary--compact trend-ai-btn" type="button" data-ai-metric="${escapeHtml(metricKey)}" data-ai-label="${escapeHtml(label)}">🤖 KI Analyse</button>`
        : "";

      return `
        <article class="trend-card">
          <div class="trend-card-head">
            <strong>${label}</strong>
            ${aiButton}
          </div>
          <span class="trend-current">Aktuell: ${formatNumber(value.current)}${suffix} <span class="trend-stand">(${standText})</span></span>
          <span>Min/Max: ${formatNumber(value.min)}${suffix} / ${formatNumber(value.max)}${suffix}</span>
          <span>Avg: ${formatNumber(value.avg)}${suffix}</span>
          <span>Delta: ${formatSignedPercent(value.delta)}${suffix === "%" ? "" : ""}</span>
          ${swapSizeLine}
          ${resourceTroubleshootingHint(label, value, suffix)}
        </article>
      `;
    })
    .join("");
}

function normalizeSeries(series) {
  if (!Array.isArray(series)) {
    return [];
  }

  return series
    .map((point) => ({
      time_utc: asText(point.time_utc, ""),
      value: Number(point.value),
    }))
    .filter((point) => point.time_utc && Number.isFinite(point.value));
}

function buildChartFrame(width, height, margins = {}) {
  const left = Number.isFinite(margins.left) ? margins.left : 42;
  const right = Number.isFinite(margins.right) ? margins.right : 10;
  const top = Number.isFinite(margins.top) ? margins.top : 10;
  const bottom = Number.isFinite(margins.bottom) ? margins.bottom : 28;

  return {
    left,
    right,
    top,
    bottom,
    width: Math.max(1, width - left - right),
    height: Math.max(1, height - top - bottom),
  };
}

function formatAxisTick(value, suffix = "") {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) {
    return "-";
  }

  const absValue = Math.abs(numeric);
  let digits = 0;
  if (absValue < 10) {
    digits = 2;
  } else if (absValue < 100) {
    digits = 1;
  }

  return `${numeric.toFixed(digits)}${suffix}`;
}

function formatAxisTimeLabel(value) {
  const text = asText(value);
  if (text === "-") {
    return text;
  }

  const parsed = new Date(text);
  if (Number.isNaN(parsed.getTime())) {
    return text;
  }

  const shifted = new Date(parsed.getTime() + 2 * 60 * 60 * 1000);
  return shifted.toLocaleString("de-DE", {
    day: "2-digit",
    month: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
    timeZone: "UTC",
  });
}

function buildXAxisTimeLabels(series, width, height, options = {}) {
  if (!Array.isArray(series) || series.length === 0) {
    return "";
  }

  const frame = buildChartFrame(width, height, options.margins);
  const indexes = Array.from(new Set([
    0,
    Math.floor((series.length - 1) / 2),
    series.length - 1,
  ])).sort((left, right) => left - right);

  const labels = indexes.map((index) => {
    const point = series[index];
    const denominator = series.length > 1 ? series.length - 1 : 1;
    const x = frame.left + (index / denominator) * frame.width;
    const anchor = index === 0 ? "start" : index === series.length - 1 ? "end" : "middle";
    const tickTop = frame.top + frame.height;
    const tickBottom = tickTop + 4;
    const labelY = tickBottom + 11;

    return `
      <line class="chart-axis-tick" x1="${x.toFixed(2)}" y1="${tickTop.toFixed(2)}" x2="${x.toFixed(2)}" y2="${tickBottom.toFixed(2)}" />
      <text class="chart-axis-label chart-axis-label-x" x="${x.toFixed(2)}" y="${labelY.toFixed(2)}" text-anchor="${anchor}">${escapeHtml(formatAxisTimeLabel(point.time_utc))}</text>
    `;
  });

  return `<g class="chart-axis-x">${labels.join("")}</g>`;
}

function buildYAxisGuides(width, height, minValue, maxValue, options = {}) {
  const tickCount = Math.max(2, Number(options.tickCount) || 5);
  const suffix = options.suffix || "";
  const formatter = typeof options.labelFormatter === "function"
    ? options.labelFormatter
    : (value) => formatAxisTick(value, suffix);
  const frame = buildChartFrame(width, height, options.margins);
  const lines = [];
  const labels = [];

  for (let index = 0; index < tickCount; index += 1) {
    const ratio = tickCount === 1 ? 0 : index / (tickCount - 1);
    const y = frame.top + ratio * frame.height;
    const value = maxValue - ratio * (maxValue - minValue);
    lines.push(
      `<line class="chart-grid-line" x1="${frame.left.toFixed(2)}" y1="${y.toFixed(2)}" x2="${(frame.left + frame.width).toFixed(2)}" y2="${y.toFixed(2)}" />`,
    );
    labels.push(
      `<text class="chart-axis-label" x="${(frame.left - 6).toFixed(2)}" y="${(y + 3.5).toFixed(2)}" text-anchor="end">${escapeHtml(formatter(value))}</text>`,
    );
  }

  const xAxisY = frame.top + frame.height;
  return `
    <g class="chart-grid">
      <line class="chart-axis-line" x1="${frame.left.toFixed(2)}" y1="${frame.top.toFixed(2)}" x2="${frame.left.toFixed(2)}" y2="${xAxisY.toFixed(2)}" />
      <line class="chart-axis-line" x1="${frame.left.toFixed(2)}" y1="${xAxisY.toFixed(2)}" x2="${(frame.left + frame.width).toFixed(2)}" y2="${xAxisY.toFixed(2)}" />
      ${lines.join("")}
      ${labels.join("")}
    </g>
  `;
}

function buildPolylinePoints(series, width, height, minValue, maxValue, margins = {}) {
  if (!Array.isArray(series) || series.length < 2) {
    return "";
  }

  const frame = buildChartFrame(width, height, margins);
  const range = maxValue - minValue;
  const safeRange = range === 0 ? 1 : range;

  return series
    .map((point, index) => {
      const x = frame.left + (index / (series.length - 1)) * frame.width;
      const normalized = (point.value - minValue) / safeRange;
      const y = frame.top + (1 - normalized) * frame.height;
      return `${x.toFixed(2)},${y.toFixed(2)}`;
    })
    .join(" ");
}

function buildAreaPolygonPoints(series, width, height, minValue, maxValue, margins = {}) {
  if (!Array.isArray(series) || series.length < 2) {
    return "";
  }

  const frame = buildChartFrame(width, height, margins);
  const range = maxValue - minValue;
  const safeRange = range === 0 ? 1 : range;
  const baselineY = (frame.top + frame.height).toFixed(2);

  const coords = series.map((point, index) => {
    const x = frame.left + (index / (series.length - 1)) * frame.width;
    const normalized = (point.value - minValue) / safeRange;
    const y = frame.top + (1 - normalized) * frame.height;
    return { x: x.toFixed(2), y: y.toFixed(2) };
  });

  const linePoints = coords.map((p) => `${p.x},${p.y}`).join(" ");
  const firstX = coords[0].x;
  const lastX = coords[coords.length - 1].x;
  return `${firstX},${baselineY} ${linePoints} ${lastX},${baselineY}`;
}

function buildPointMarkers(series, width, height, minValue, maxValue, color, label, margins = {}) {
  if (!Array.isArray(series) || series.length === 0) {
    return "";
  }

  const frame = buildChartFrame(width, height, margins);
  const range = maxValue - minValue;
  const safeRange = range === 0 ? 1 : range;
  const denominator = series.length > 1 ? series.length - 1 : 1;

  return series
    .map((point, index) => {
      const x = frame.left + (index / denominator) * frame.width;
      const normalized = (point.value - minValue) / safeRange;
      const y = frame.top + (1 - normalized) * frame.height;
      const pointTime = formatUtcPlus2(point.time_utc);
      const pointValue = Number(point.value);
      const valueText = Number.isFinite(pointValue) ? pointValue.toFixed(2) : "-";

      return `<circle class="chart-point" cx="${x.toFixed(2)}" cy="${y.toFixed(2)}" r="3.3" fill="${color}"><title>${escapeHtml(label)}: ${escapeHtml(valueText)} (${escapeHtml(pointTime)})</title></circle>`;
    })
    .join("");
}

function computeLinearRegression(series) {
  if (!Array.isArray(series) || series.length < 3) {
    return null;
  }

  const n = series.length;
  const sumX = (n * (n - 1)) / 2;
  const sumX2 = ((n - 1) * n * (2 * n - 1)) / 6;
  let sumY = 0;
  let sumXY = 0;
  for (let i = 0; i < n; i++) {
    sumY += series[i].value;
    sumXY += i * series[i].value;
  }
  const denom = n * sumX2 - sumX * sumX;
  if (denom === 0) return null;

  const slope = (n * sumXY - sumX * sumY) / denom;
  const intercept = (sumY - slope * sumX) / n;
  const currentEnd = slope * (n - 1) + intercept;
  // Project forward by the same number of steps as the data window
  const projected = slope * (2 * (n - 1)) + intercept;

  return { slope, intercept, currentEnd, projected };
}

function trendAlertLevel(projected) {
  if (projected >= 100) return "crit";
  if (projected >= 90) return "warn";
  return null;
}

function trendLineColor(baseColor, alertLevel) {
  if (alertLevel === "crit") return "#dc2626";
  if (alertLevel === "warn") return "#d97706";
  return baseColor;
}

function buildTrendLine(series, width, height, minValue, maxValue, color, margins = {}) {
  const reg = computeLinearRegression(series);
  if (!reg) return "";

  const { intercept, currentEnd } = reg;
  const frame = buildChartFrame(width, height, margins);
  const range = maxValue - minValue;
  const safeRange = range === 0 ? 1 : range;

  const toSvgY = (val) => {
    const clamped = Math.max(minValue, Math.min(maxValue, val));
    return frame.top + (1 - (clamped - minValue) / safeRange) * frame.height;
  };

  const x1 = frame.left.toFixed(2);
  const x2 = (frame.left + frame.width).toFixed(2);
  const y1 = toSvgY(intercept).toFixed(2);
  const y2 = toSvgY(currentEnd).toFixed(2);

  return `<line class="chart-trend-line" x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="${color}" />`;
}

function buildSparklineSvg(series, color, width = 320, height = 82, options = {}) {
  const points = normalizeSeries(series);
  if (points.length === 0) {
    return "<p class=\"muted\">Keine Verlaufsdaten</p>";
  }

  const suffix = options.suffix || "";
  const labelFormatter = typeof options.labelFormatter === "function"
    ? options.labelFormatter
    : (value) => formatAxisTick(value, suffix);
  const margins = options.margins || { left: 42, right: 10, top: 10, bottom: 28 };

  if (points.length === 1) {
    const singleValue = Number(points[0].value);
    const minValue = Number.isFinite(options.minValue) ? options.minValue : (Number.isFinite(singleValue) ? singleValue : 0);
    const maxValue = Number.isFinite(options.maxValue) ? options.maxValue : (Number.isFinite(singleValue) ? singleValue : 1);
    const frame = buildChartFrame(width, height, margins);
    const centerY = (frame.top + frame.height / 2).toFixed(2);
    const singleTime = formatUtcPlus2(points[0].time_utc);
    const valueText = Number.isFinite(singleValue) ? singleValue.toFixed(2) : "-";
    const guides = buildYAxisGuides(width, height, minValue, maxValue, { margins, labelFormatter });
    const timeLabels = buildXAxisTimeLabels(points, width, height, { margins });
    return `<svg class=\"sparkline\" viewBox=\"0 0 ${width} ${height}\" role=\"img\" aria-label=\"Trend\">${guides}${timeLabels}<line x1=\"${frame.left.toFixed(2)}\" y1=\"${centerY}\" x2=\"${(frame.left + frame.width).toFixed(2)}\" y2=\"${centerY}\" stroke=\"${color}\" stroke-width=\"2.2\" /><circle class=\"chart-point\" cx=\"${(frame.left + frame.width / 2).toFixed(2)}\" cy=\"${centerY}\" r=\"3.6\" fill=\"${color}\"><title>${escapeHtml(valueText)} (${escapeHtml(singleTime)})</title></circle></svg>`;
  }

  const values = points.map((point) => point.value);
  const minValue = Number.isFinite(options.minValue) ? options.minValue : Math.min(...values);
  const maxValue = Number.isFinite(options.maxValue) ? options.maxValue : Math.max(...values);
  const guides = buildYAxisGuides(width, height, minValue, maxValue, { margins, labelFormatter });
  const timeLabels = buildXAxisTimeLabels(points, width, height, { margins });
  const polyline = buildPolylinePoints(points, width, height, minValue, maxValue, margins);
  const area = buildAreaPolygonPoints(points, width, height, minValue, maxValue, margins);
  const markers = buildPointMarkers(points, width, height, minValue, maxValue, color, "Wert", margins);
  const usedTrendColor = options.trendColor || color;
  const trendLine = buildTrendLine(points, width, height, minValue, maxValue, usedTrendColor, margins);

  return `
    <svg class="sparkline" viewBox="0 0 ${width} ${height}" role="img" aria-label="Trend">
      ${guides}
      ${timeLabels}
      <polygon class="chart-area" fill="${color}" fill-opacity="0.16" points="${area}" />
      <polyline fill="none" stroke="${color}" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" points="${polyline}" />
      ${trendLine}
      ${markers}
    </svg>
  `;
}

function renderResourceCharts(resourceSeries, latestReportTimeUtc) {
  const chartDefinitions = [
    { key: "cpu_usage_percent", label: "CPU %", color: "#0ea5a8" },
    { key: "memory_used_percent", label: "RAM %", color: "#f59e0b" },
    { key: "swap_used_percent", label: "Swap %", color: "#2563eb" },
    { key: "load_avg_1", label: "Load 1m", color: "#be185d" },
  ];

  const hasAnySeries = chartDefinitions.some((item) => normalizeSeries(resourceSeries[item.key]).length > 1);
  if (!hasAnySeries) {
    return "<p class=\"muted\">Keine Verlaufskurven verfuegbar.</p>";
  }

  const standText = formatUtcPlus2(latestReportTimeUtc);
  const trendWarnings = [];
  const miniCharts = chartDefinitions
    .map((item) => {
      const points = normalizeSeries(resourceSeries[item.key]);
      const values = points.map((point) => point.value);
      const minValue = values.length > 0 ? Math.min(...values) : null;
      const maxValue = values.length > 0 ? Math.max(...values) : null;
      const isPercent = item.label.includes("%");
      const reg = isPercent ? computeLinearRegression(points) : null;
      const alertLevel = reg ? trendAlertLevel(reg.projected) : null;
      const usedTrendColor = trendLineColor(item.color, alertLevel);
      if (alertLevel) {
        trendWarnings.push({ label: item.label, projected: reg.projected, alertLevel });
      }
      const trendBadge = alertLevel
        ? `<span class="trend-alert-badge trend-alert-${alertLevel}" title="Trend-Projektion: ${reg.projected.toFixed(1)}%">${alertLevel === "crit" ? "⬆ Kritisch" : "⬆ Warnung"} ~${reg.projected.toFixed(0)}%</span>`
        : "";
      return `
        <article class="mini-chart-card${alertLevel ? ` trend-alert-card-${alertLevel}` : ""}">
          <header>
            <strong>${item.label}</strong>
            <span>${points.length} Samples</span>
          </header>
          ${buildSparklineSvg(points, item.color, 420, 140, {
            suffix: isPercent ? "%" : "",
            trendColor: usedTrendColor,
            ...(isPercent ? { minValue: 0, maxValue: 100 } : {}),
          })}
          <footer>
            <span>Min: ${minValue === null ? "-" : formatNumber(minValue, 2)}</span>
            <span>Max: ${maxValue === null ? "-" : formatNumber(maxValue, 2)}</span>
            ${trendBadge}
          </footer>
        </article>
      `;
    })
    .join("");

  const trendWarningBlock = trendWarnings.length > 0
    ? `<div class="trend-warning-block">
        <strong>⚠ Trend-Projektion:</strong>
        <ul>${trendWarnings.map((w) => `<li class="trend-alert-${w.alertLevel}"><strong>${escapeHtml(w.label)}</strong> → ${w.projected.toFixed(1)}%</li>`).join("")}</ul>
      </div>`
    : "";

  return `
    <section class="resource-chart-layout">
    ${trendWarningBlock}
    <section class="mini-chart-grid">${miniCharts}</section>
    </section>
  `;
}

function openChartDrillModal(item, latestReportTimeUtc) {
  const modal = document.getElementById("chartDrillModal");
  const titleEl = document.getElementById("chartDrillTitle");
  const bodyEl = document.getElementById("chartDrillBody");
  if (!modal || !titleEl || !bodyEl) return;

  const points = normalizeSeries((item.series || []).map((p) => ({ time_utc: p.time_utc, value: p.used_percent })));
  const color = filesystemLineColor(item.current_used_percent);
  const reg = computeLinearRegression(points);
  const alertLevel = reg ? trendAlertLevel(reg.projected) : null;
  const usedTrendColor = trendLineColor(color, alertLevel);
  const standText = formatUtcPlus2(latestReportTimeUtc);

  titleEl.textContent = asText(item.mountpoint);
  const trendBadge = alertLevel
    ? `<span class="trend-alert-badge trend-alert-${alertLevel}">⬆ ${alertLevel === "crit" ? "Kritisch" : "Warnung"} ~${reg.projected.toFixed(0)}%</span>`
    : "";
  bodyEl.innerHTML = `
    <div class="chart-drill-svg-wrap">
      ${buildSparklineSvg(points, color, 700, 220, { suffix: "%", minValue: 0, maxValue: 100, trendColor: usedTrendColor })}
    </div>
    <div class="chart-drill-stats">
      <span class="stat-chip">Aktuell: ${escapeHtml(formatPercent(item.current_used_percent))}</span>
      <span class="stat-chip">Min: ${escapeHtml(formatPercent(item.min_used_percent))}</span>
      <span class="stat-chip">Max: ${escapeHtml(formatPercent(item.max_used_percent))}</span>
      <span class="stat-chip">Avg: ${escapeHtml(formatPercent(item.avg_used_percent))}</span>
      <span class="stat-chip">Delta: ${escapeHtml(formatSignedPercent(item.delta_used_percent))}</span>
      <span class="stat-chip">${Number(item.sample_count || 0).toLocaleString("de-DE")} Samples</span>
      ${trendBadge}
      <span class="stat-chip muted">${escapeHtml(standText)}</span>
    </div>
  `;
  modal.classList.remove("hidden");
}

function closeAiTroubleshootModal() {
  const modal = document.getElementById("aiTroubleshootModal");
  if (modal) {
    modal.classList.add("hidden");
  }
}

async function openAiTroubleshootModal(metricKey, metricLabel) {
  const modal = document.getElementById("aiTroubleshootModal");
  const titleEl = document.getElementById("aiTroubleshootTitle");
  const bodyEl = document.getElementById("aiTroubleshootBody");
  const statusEl = document.getElementById("aiTroubleshootStatus");
  if (!modal || !titleEl || !bodyEl || !statusEl) {
    return;
  }
  if (!state.selectedHost) {
    window.alert("Kein Host ausgewaehlt.");
    return;
  }

  titleEl.textContent = `🤖 KI Analyse: ${metricLabel}`;
  statusEl.textContent = "Analyse wird erstellt...";
  bodyEl.innerHTML = "<p class=\"muted\">Bitte warten...</p>";
  modal.classList.remove("hidden");

  try {
    const response = await fetch("/api/v1/ai-troubleshoot", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        hostname: state.selectedHost,
        metric: metricKey,
        window_hours: state.analysisHours,
      }),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data.details || data.error || ("HTTP " + response.status));
    }

    const context = data.context || {};
    const analysis = data.analysis || {};
    const osFamily = String(context.os_family || "linux");
    const hanaHint = context.has_hana_processes ? "HANA erkannt" : "kein HANA Prozess erkannt";
    const windowHours = Number(context.window_hours || state.analysisHours || 24);
    const latest = formatUtcPlus2(context.latest_report_time_utc || "");

    bodyEl.innerHTML = `
      <div class="ai-summary-row">
        <span class="stat-chip">Severity: ${escapeHtml(aiSeverityLabel(analysis.severity))}</span>
        <span class="stat-chip">Confidence: ${escapeHtml(aiConfidenceLabel(analysis.confidence))}</span>
        <span class="stat-chip">OS: ${escapeHtml(osFamily)}</span>
        <span class="stat-chip">Zeitraum: ${escapeHtml(String(windowHours))}h</span>
        <span class="stat-chip">${escapeHtml(hanaHint)}</span>
        <span class="stat-chip muted">Stand: ${escapeHtml(latest)}</span>
      </div>
      <section class="ai-block">
        <h5>Zusammenfassung</h5>
        <p>${escapeHtml(String(analysis.summary || "Keine Zusammenfassung"))}</p>
      </section>
      <section class="ai-block">
        <h5>Wahrscheinliche Ursachen</h5>
        ${renderAiList(analysis.probable_causes)}
      </section>
      <section class="ai-block">
        <h5>Empfohlene Schritte</h5>
        ${renderAiList(analysis.recommended_steps)}
      </section>
      <section class="ai-block">
        <h5>Quick Checks</h5>
        ${renderAiList(analysis.quick_checks)}
      </section>
      <section class="ai-block">
        <h5>Codeschnipsel</h5>
        <div class="ai-code-grid">${renderAiCodeBlocks(analysis.code_snippets)}</div>
      </section>
    `;
    statusEl.textContent = data.cached ? `Aus Cache (${escapeHtml(String(data.model || ""))})` : `Live Analyse (${escapeHtml(String(data.model || ""))})`;
  } catch (error) {
    bodyEl.innerHTML = `<p class=\"muted\">Fehler bei der KI-Analyse: ${escapeHtml(error.message)}</p>`;
    statusEl.textContent = "Fehler";
  }
}

function filesystemLineColor(currentUsedPercent) {
  const value = Number(currentUsedPercent);
  if (!Number.isFinite(value)) {
    return "#64748b";
  }
  if (value >= 90) {
    return "#dc2626";
  }
  if (value >= 80) {
    return "#d97706";
  }
  return "#0f766e";
}

function shouldShowFilesystemGraph(mountpoint) {
  if (!mountpoint) return false;
  const mp = mountpoint.replace(/\\/g, '/').toLowerCase();
  // Windows drive letters: C: / C:/ / D: / D:/ etc.
  if (/^[a-z]:(?:\/)?$/.test(mp)) return true;
  // Windows volume mount style: \\?\Volume{...}\
  if (mp.startsWith('//?/volume{')) return true;
  // Linux root and common SAP/HANA/data paths
  if (mp === '/') return true;
  if (mp.startsWith('/usr/sap')) return true;
  if (mp === '/hana' || mp.startsWith('/hana/')) return true;
  if (mp.startsWith('/mnt/') || mp === '/mnt') return true;
  return false;
}

function sortFilesystemByMountpointAscending(rows) {
  return [...rows].sort((left, right) => {
    const leftMount = asText(left?.mountpoint).toLowerCase();
    const rightMount = asText(right?.mountpoint).toLowerCase();
    return leftMount.localeCompare(rightMount, "de", { numeric: true, sensitivity: "base" });
  });
}

function renderFilesystemTrendCharts(filesystemTrends, latestReportTimeUtc) {
  if (!Array.isArray(filesystemTrends) || filesystemTrends.length === 0) {
    return "<p class=\"muted\">Keine Filesystem-Verlaufskurven verfuegbar.</p>";
  }

  const filtered = filesystemTrends.filter((item) => shouldShowFilesystemGraph(item.mountpoint));
  if (filtered.length === 0) {
    return "<p class=\"muted\">Keine relevanten Filesystem-Verlaufskurven verfuegbar.</p>";
  }
  const topTrends = sortFilesystemByMountpointAscending(filtered);
  const standText = formatUtcPlus2(latestReportTimeUtc);
  const fsTrendWarnings = [];

  const cards = topTrends
    .map((item) => {
      const points = normalizeSeries((item.series || []).map((point) => ({
        time_utc: point.time_utc,
        value: point.used_percent,
      })));
      const color = filesystemLineColor(item.current_used_percent);
      const mountpoint = renderPathCell(item.mountpoint, 42);
      const fsTotal = Number(item.total_kb);
      const fsTotalLabel = Number.isFinite(fsTotal) && fsTotal >= 0 ? formatKilobytes(fsTotal) : "-";
      const reg = computeLinearRegression(points);
      const alertLevel = reg ? trendAlertLevel(reg.projected) : null;
      const usedTrendColor = trendLineColor(color, alertLevel);
      if (alertLevel) {
        fsTrendWarnings.push({ label: item.mountpoint, projected: reg.projected, alertLevel });
      }
      const trendBadge = alertLevel
        ? `<span class="trend-alert-badge trend-alert-${alertLevel}" title="Trend-Projektion: ${reg.projected.toFixed(1)}%">${alertLevel === "crit" ? "⬆ Kritisch" : "⬆ Warnung"} ~${reg.projected.toFixed(0)}%</span>`
        : "";

      return `
        <article class="fs-chart-card${alertLevel ? ` trend-alert-card-${alertLevel}` : ""}">
          <header>
            <strong>${mountpoint}</strong>
            <span>${Number(item.sample_count || 0).toLocaleString("de-DE")} Samples | Grösse: ${escapeHtml(fsTotalLabel)}</span>
          </header>
          ${buildSparklineSvg(points, color, 520, 150, { suffix: "%", minValue: 0, maxValue: 100, trendColor: usedTrendColor })}
          <footer>
            <span>Aktuell: ${formatPercent(item.current_used_percent)}</span>
            <span>Delta: ${formatSignedPercent(item.delta_used_percent)}</span>
            ${trendBadge}
            <span>${escapeHtml(standText)}</span>
          </footer>
        </article>
      `;
    })
    .join("");

  const fsWarningBlock = fsTrendWarnings.length > 0
    ? `<div class="trend-warning-block">
        <strong>⚠ Trend-Projektion:</strong>
        <ul>${fsTrendWarnings.map((w) => `<li class="trend-alert-${w.alertLevel}"><strong>${escapeHtml(w.label)}</strong> → ${w.projected.toFixed(1)}%</li>`).join("")}</ul>
      </div>`
    : "";

  return fsWarningBlock + cards;
}

function renderNetworkTable(network) {
  if (!network || !Array.isArray(network.interfaces) || network.interfaces.length === 0) {
    return "<p class=\"muted\">Keine Netzwerk-Daten</p>";
  }

  const rows = network.interfaces
    .map((iface) => {
      const defaultBadge = iface.is_default ? "<span class=\"badge status-open\">default</span>" : "";
      return `
        <tr>
          <td>${escapeHtml(asText(iface.name))} ${defaultBadge}</td>
          <td>${escapeHtml(asText(iface.state))}</td>
          <td>${formatKilobytes(Number(iface.rx_bytes) / 1024)}</td>
          <td>${formatKilobytes(Number(iface.tx_bytes) / 1024)}</td>
          <td>${Number(iface.rx_errors || 0) + Number(iface.tx_errors || 0)}</td>
          <td>${Number(iface.rx_dropped || 0) + Number(iface.tx_dropped || 0)}</td>
        </tr>
      `;
    })
    .join("");

  return `
    <div class="table-wrap">
      <table class="network-table">
        <thead>
          <tr>
            <th>🌐 Interface</th>
            <th>🔌 State</th>
            <th>⬇️ RX</th>
            <th>⬆️ TX</th>
            <th>⚠️ Errors</th>
            <th>🧯 Drops</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `;
}

function shortPath(value, maxLen = 54) {
  const text = asText(value, "-");
  if (text === "-" || text.length <= maxLen) {
    return text;
  }
  return `${text.slice(0, maxLen - 1)}...`;
}

function renderPathCell(value, maxLen = 54) {
  const full = asText(value, "-");
  const compact = shortPath(full, maxLen);
  return `<span class="path-cell" title="${escapeHtml(full)}">${escapeHtml(compact)}</span>`;
}

function renderPathWithNameHighlight(value) {
  const full = asText(value, "-");
  if (full === "-") {
    return '<span class="sap-path-full">-</span>';
  }

  const separatorIndex = full.lastIndexOf("/");
  if (separatorIndex < 0) {
    return `<span class="sap-path-full"><span class="sap-path-name">${escapeHtml(full)}</span></span>`;
  }

  const dirPart = full.slice(0, separatorIndex + 1);
  const namePart = full.slice(separatorIndex + 1) || "/";
  return `<span class="sap-path-full"><span class="sap-path-dir">${escapeHtml(dirPart)}</span><span class="sap-path-name">${escapeHtml(namePart)}</span></span>`;
}

function renderSapPathSizeItem(title, item, missingText) {
  const block = item && typeof item === "object" ? item : {};
  const pathValue = asText(block.path, "-");
  const exists = block.exists === true;
  const sizeNumber = Number(block.size_bytes);
  const sizeText = exists
    ? (Number.isFinite(sizeNumber) && sizeNumber >= 0 ? formatBytes(sizeNumber) : "n/a")
    : missingText;

  return `
    <article class="sap-b1-item">
      <header>${escapeHtml(title)}</header>
      <div class="sap-b1-path" title="${escapeHtml(pathValue)}">${renderPathWithNameHighlight(pathValue)}</div>
      <div class="sap-b1-size-row">
        <span class="sap-b1-size-label">Groesse</span>
        <strong class="sap-b1-size-value">${escapeHtml(sizeText)}</strong>
      </div>
    </article>
  `;
}

function renderSapBusinessOneCard(payload) {
  const sap = payload && typeof payload.sap_business_one === "object" ? payload.sap_business_one : null;
  if (!sap) {
    return `
      <section class="detail-card sap-b1-card">
        <h4>📦 SAP Business One Files / Ordner</h4>
        <p class="muted">Keine SAP-Business-One-Daten im Payload vorhanden.</p>
      </section>
    `;
  }

  return `
    <section class="detail-card sap-b1-card">
      <h4>📦 SAP Business One Files / Ordner</h4>
      <div class="sap-b1-grid">
        ${renderSapPathSizeItem("catalina.out", sap.catalina_out, "Datei nicht vorhanden")}
        ${renderSapPathSizeItem("BusinessOne Log Ordner", sap.businessone_log_dir, "Ordner nicht vorhanden")}
      </div>
    </section>
  `;
}

function parseSapB1Version(versionText) {
  const text = String(versionText || "").trim();
  const match = text.match(/(10\.00\.\d{3})\s+(PL\s*\d{1,2})/i);
  if (!match) {
    return { build: "", patchLevel: "", mapping: null };
  }
  const build = match[1];
  const patchLevel = match[2].replace(/\s+/g, " ").toUpperCase();
  const mapping = SAP_B1_VERSION_MAP.get(build) || null;
  return { build, patchLevel, mapping };
}

function payloadHasHanaProcesses(payload) {
  const topProcesses = payload && payload.top_processes && Array.isArray(payload.top_processes.entries)
    ? payload.top_processes.entries
    : [];
  return topProcesses.some((entry) => {
    const name = asText(entry?.name, "");
    const command = asText(entry?.command, "");
    return SAP_B1_HANA_PROCESS_RE.test(name) || SAP_B1_HANA_PROCESS_RE.test(command);
  });
}

function getSapB1LandscapeStatus(payload) {
  const sap = payload && typeof payload.sap_business_one === "object" ? payload.sap_business_one : null;
  const versionBlock = sap && typeof sap.server_components_version === "object" ? sap.server_components_version : null;
  const versionText = asText(versionBlock?.version, "");
  const versionInfo = parseSapB1Version(versionText);
  const hasVersion = Boolean(versionInfo.build || versionText);
  const hasHana = payloadHasHanaProcesses(payload);

  if (hasHana && hasVersion) {
    return {
      label: `SAP B1 ${versionText || versionInfo.build}`.trim(),
      detail: `${versionInfo.mapping?.featurePack || "Version erkannt"} | HANA erkannt`,
      stateClass: "ok",
      compatible: true,
    };
  }
  if (hasHana) {
    return {
      label: "HANA erkannt",
      detail: "SAP B1 Version nicht erkannt",
      stateClass: "warn",
      compatible: false,
    };
  }
  if (hasVersion) {
    return {
      label: `SAP B1 ${versionText || versionInfo.build}`.trim(),
      detail: "keine HANA Prozesse erkannt",
      stateClass: "warn",
      compatible: false,
    };
  }
  return {
    label: "Keine SAP B1/HANA Info",
    detail: "weder B1 Version noch HANA Prozesse erkannt",
    stateClass: "muted",
    compatible: false,
  };
}

function renderSapB1LandscapeBadge(payload) {
  const info = getSapB1LandscapeStatus(payload);
  return `<span class="sap-b1-inline-badge ${escapeHtml(info.stateClass)}" title="${escapeHtml(info.detail)}">${escapeHtml(info.label)}</span>`;
}

function renderSapB1SystemSummary(payload) {
  const sap = payload && typeof payload.sap_business_one === "object" ? payload.sap_business_one : null;
  const versionBlock = sap && typeof sap.server_components_version === "object" ? sap.server_components_version : null;
  const versionText = asText(versionBlock?.version, "");
  const versionInfo = parseSapB1Version(versionText);
  const fp = asText(versionInfo.mapping?.featurePack, "");
  const releaseDate = asText(versionInfo.mapping?.releaseDate, "");
  if (!fp && !releaseDate) {
    return "-";
  }
  if (fp && releaseDate) {
    return `<strong>${escapeHtml(fp)}</strong> ${escapeHtml(releaseDate)}`;
  }
  return fp ? `<strong>${escapeHtml(fp)}</strong>` : escapeHtml(releaseDate);
}

function renderSapB1SystemInfoCard(payload) {
  const sap = payload && typeof payload.sap_business_one === "object" ? payload.sap_business_one : null;
  const versionBlock = sap && typeof sap.server_components_version === "object" ? sap.server_components_version : null;
  if (!versionBlock) {
    return `
      <section class="detail-card sap-b1-card">
        <h4>🧾 SAP B1</h4>
        <p class="muted">Keine SAP Business One Versionsdaten im Payload vorhanden.</p>
      </section>
    `;
  }

  const rawOutput = asText(versionBlock.raw_output, "");
  const hanaInfo = payload && typeof payload.hana_info === "object" ? payload.hana_info : null;
  const hanaRawOutput = asText(hanaInfo?.raw_output, "");
  const hanaVersion = asText(hanaInfo?.version, "");
  const hanaBranch = asText(hanaInfo?.branch, "");
  const hanaSid = asText(hanaInfo?.sid, "");
  const hanaAvailable = hanaInfo?.available === true;
  const hanaError = asText(hanaInfo?.error, "");

  let hanaInfoRows = "";
  if (!hanaInfo) {
    hanaInfoRows = `<p class="muted">Kein HANA-Scan im Payload (Agent-Update erforderlich)</p>`;
  } else if (!hanaAvailable) {
    hanaInfoRows = `<p class="muted">HANA nicht gefunden${hanaError ? " — " + escapeHtml(hanaError) : ""}</p>`;
  } else {
    hanaInfoRows = `
      <table class="sap-b1-info-table">
        <tbody>
          ${hanaSid ? `<tr><th>SID</th><td>${escapeHtml(hanaSid)}</td></tr>` : ""}
          ${hanaVersion ? `<tr><th>Version</th><td>${escapeHtml(hanaVersion)}</td></tr>` : ""}
          ${hanaBranch ? `<tr><th>Branch</th><td>${escapeHtml(hanaBranch)}</td></tr>` : ""}
        </tbody>
      </table>
    `;
  }

  return `
    <section class="detail-card sap-b1-card">
      <h4>🧾 SAP B1</h4>
      <div class="sap-b1-grid">
        <details class="sap-b1-raw-details">
          <summary class="sap-b1-raw-summary">SAP B1 Setup Roh-Output</summary>
          <pre class="sap-b1-raw-output">${escapeHtml(rawOutput || "-")}</pre>
        </details>
        <details class="sap-b1-raw-details">
          <summary class="sap-b1-raw-summary">HANA Versions-Scan</summary>
          ${hanaInfoRows}
          ${hanaRawOutput ? `<pre class="sap-b1-raw-output">${escapeHtml(hanaRawOutput)}</pre>` : ""}
        </details>
      </div>
    </section>
  `;
}

function getBackupCurrentInfo() {
  const now = new Date();
  const yyyy = String(now.getFullYear());
  const mm = String(now.getMonth() + 1).padStart(2, "0");
  const dd = String(now.getDate()).padStart(2, "0");
  const yearShort = yyyy.slice(2);

  return {
    year: yyyy,
    month: mm,
    day: dd,
    nowMs: now.getTime(),
    tokens: [
      `${yyyy}${mm}${dd}`,
      `${yyyy}-${mm}-${dd}`,
      `${yyyy}_${mm}_${dd}`,
      `${dd}${mm}${yyyy}`,
      `${dd}-${mm}-${yyyy}`,
      `${dd}_${mm}_${yyyy}`,
      `${dd}${mm}${yearShort}`,
      `${dd}-${mm}-${yearShort}`,
      `${dd}_${mm}_${yearShort}`,
    ],
  };
}

function itemMatchesCurrent(item, currentInfo) {
  const name = asText(item && item.name, "").toLowerCase();
  const nameMatch = currentInfo.tokens.some((token) => name.includes(token.toLowerCase()));
  if (nameMatch) {
    return true;
  }

  const modRaw = asText(item && item.modified_utc, "");
  if (!modRaw) {
    return false;
  }

  const parsed = new Date(modRaw);
  if (Number.isNaN(parsed.getTime())) {
    return false;
  }

  const ageMs = currentInfo.nowMs - parsed.getTime();
  return ageMs >= 0 && ageMs <= 24 * 60 * 60 * 1000;
}

function timestampIsCurrent(modRaw, currentInfo) {
  const raw = asText(modRaw, "");
  if (!raw) {
    return false;
  }
  const parsed = new Date(raw);
  if (Number.isNaN(parsed.getTime())) {
    return false;
  }
  const ageMs = currentInfo.nowMs - parsed.getTime();
  return ageMs >= 0 && ageMs <= 24 * 60 * 60 * 1000;
}

function renderCurrentStatusBadge(hasCurrent) {
  if (hasCurrent) {
    return '<span class="dir-status-badge ok">Backup gefunden (&lt;24h)</span>';
  }
  return '<span class="dir-status-badge missing">kein Backup (&gt;24h)</span>';
}

function isBackupZipItem(item) {
  const type = asText(item && item.type, "").toLowerCase();
  const name = asText(item && item.name, "");
  const leafName = name.includes("/") ? name.slice(name.lastIndexOf("/") + 1) : name;
  return type === "file" && /\.zip$/i.test(leafName);
}

function renderDirItemRows(items, currentInfo) {
  return items.map((item) => {
    const name = asText(item.name, "-");
    const slashIndex = name.lastIndexOf("/");
    const namePath = slashIndex >= 0 ? name.slice(0, slashIndex) : "";
    const leafName = slashIndex >= 0 ? name.slice(slashIndex + 1) : name;
    const isZipFile = leafName.toLowerCase().endsWith(".zip");
    const type = asText(item.type, "file");
    const sizeBytes = Number(item.size_bytes);
    const sizeText = Number.isFinite(sizeBytes) && sizeBytes >= 0 ? formatBytes(sizeBytes) : "-";
    const modRaw = asText(item.modified_utc, "");
    const modText = modRaw ? formatUtcPlus2Short(modRaw) : "-";
    const typeIcon = type === "dir" ? "📁" : type === "link" ? "🔗" : "📄";
    const isCurrent = itemMatchesCurrent(item, currentInfo);
    const rowClass = isCurrent ? " class=\"dir-item-today\"" : "";
    return `
      <tr${rowClass}>
        <td class="dir-item-icon">${typeIcon}</td>
        <td class="dir-item-name${isZipFile ? " dir-item-name--zip" : ""}" title="${escapeHtml(name)}">${namePath ? `<span class="dir-item-name-path">${escapeHtml(namePath)}/</span>` : ""}<span class="dir-item-name-leaf${isZipFile ? " dir-item-name-leaf--zip" : ""}">${escapeHtml(leafName)}</span></td>
        <td class="dir-item-size">${escapeHtml(sizeText)}</td>
        <td class="dir-item-date">${escapeHtml(modText)}${isCurrent ? ' <span class="dir-item-today-chip">&lt;24H</span>' : ""}</td>
      </tr>
    `;
  }).join("");
}

function renderDirItemTable(items, currentInfo) {
  return `
    <div class="table-wrap">
      <table class="report-subtable dir-listing-table">
        <colgroup>
          <col style="width:28px;">
          <col>
          <col style="width:120px;">
          <col style="width:250px;">
        </colgroup>
        <thead>
          <tr>
            <th style="width:28px;"></th>
            <th>📝 Name</th>
            <th class="dir-item-size-head">📦 Grösse</th>
            <th class="dir-item-date-head">🕒 Geändert (UTC+2)</th>
          </tr>
        </thead>
        <tbody>${renderDirItemRows(items, currentInfo)}</tbody>
      </table>
    </div>
  `;
}

function renderDirListingsCard(payload) {
  const block = payload && typeof payload.dir_listings === "object" ? payload.dir_listings : null;
  const deepBlock = payload && typeof payload.dir_deep_listings === "object" ? payload.dir_deep_listings : null;
  const currentInfo = getBackupCurrentInfo();

  const hasRegular = block && block.available && Array.isArray(block.entries) && block.entries.length > 0;
  const hasDeep = deepBlock && deepBlock.available && Array.isArray(deepBlock.entries) && deepBlock.entries.length > 0;

  if (!hasRegular && !hasDeep) {
    return `
      <section class="detail-card dir-listings-card">
        <h4>📂 SAP Exports</h4>
        <p class="muted">Keine SAP Exports Daten vorhanden. (DIR_SCAN_PATHS oder DIR_SCAN_DEEP_PATHS in agent.conf konfigurieren)</p>
      </section>
    `;
  }

  let html = `<section class="detail-card dir-listings-card"><h4>📂 SAP Exports</h4>`;

  // Regular flat listings
  if (hasRegular) {
    const scanSections = block.entries.map((entry) => {
      const pattern = asText(entry.pattern, "-");
      const path = asText(entry.path, pattern);
      const items = Array.isArray(entry.items) ? entry.items : [];
      const truncated = entry.truncated === true;
      const hasToday = items.some((item) => itemMatchesCurrent(item, currentInfo));

      if (items.length === 0) {
        return `
          <div class="dir-listing-entry">
            <div class="dir-listing-header">
              <span class="dir-listing-path" title="${escapeHtml(path)}">${escapeHtml(path)}</span>
              <span class="dir-listing-pattern muted">${escapeHtml(pattern)}</span>
            </div>
            ${renderTodayStatusBadge(false)}
            <p class="muted">Verzeichnis ist leer.</p>
          </div>
        `;
      }

      const truncatedNote = truncated
        ? `<p class="muted" style="margin-top:4px;">Liste gekürzt (max. ${items.length} Einträge)</p>`
        : "";

      return `
        <div class="dir-listing-entry">
          <div class="dir-listing-header">
            <span class="dir-listing-path" title="${escapeHtml(path)}">${escapeHtml(path)}</span>
            <span class="dir-listing-pattern muted">${escapeHtml(pattern)}</span>
          </div>
          ${renderCurrentStatusBadge(hasToday)}
          ${renderDirItemTable(items, currentInfo)}
          ${truncatedNote}
        </div>
      `;
    }).join("");
    html += scanSections;
  }

  // Deep listings (subdirs with newest N items each)
  if (hasDeep) {
    const deepSections = deepBlock.entries.map((entry) => {
      const pattern = asText(entry.pattern, "-");
      const path = asText(entry.path, pattern);
      const subdirs = Array.isArray(entry.subdirs) ? entry.subdirs : [];

      if (subdirs.length === 0) {
        return `
          <div class="dir-listing-entry">
            <div class="dir-listing-header">
              <span class="dir-listing-path" title="${escapeHtml(path)}">${escapeHtml(path)}</span>
              <span class="dir-listing-pattern muted">${escapeHtml(pattern)}</span>
            </div>
            <p class="muted">Keine Unterordner gefunden.</p>
          </div>
        `;
      }

      const subdirBlocks = subdirs.map((subdir) => {
        const subdirName = asText(subdir.name, "-");
        const subdirPath = asText(subdir.path, subdirName);
        const rawItems = Array.isArray(subdir.items) ? subdir.items : [];
        const items = rawItems.filter((item) => isBackupZipItem(item));
        const latestZipTs = asText(subdir.zip_latest_modified_utc, "");
        const hasToday = latestZipTs
          ? timestampIsCurrent(latestZipTs, currentInfo)
          : items.some((item) => itemMatchesCurrent(item, currentInfo));
        const zipTotal = Number(subdir.zip_item_count_total || 0);
        const totalNote = Number.isFinite(zipTotal) && zipTotal > items.length
          ? ` <span class="muted">(${items.length} ZIP von ${zipTotal} gezeigt)</span>`
          : Number.isFinite(zipTotal) && zipTotal === items.length && zipTotal > 0
          ? ` <span class="muted">(${items.length} ZIP)</span>`
          : "";

        return `
          <details class="dir-deep-subdir">
            <summary class="dir-deep-subdir-title">
              📁 <span title="${escapeHtml(subdirPath)}">${escapeHtml(subdirName)}</span>${totalNote} ${renderCurrentStatusBadge(hasToday)}
            </summary>
            ${items.length === 0
              ? `<p class="muted" style="margin:4px 0 0 0;">Keine *.zip-Dateien gefunden.</p>`
              : renderDirItemTable(items, currentInfo)
            }
          </details>
        `;
      }).join("");

      return `
        <div class="dir-listing-entry">
          <div class="dir-listing-header">
            <span class="dir-listing-path" title="${escapeHtml(path)}">${escapeHtml(path)}</span>
            <span class="dir-listing-pattern muted">${escapeHtml(pattern)}</span>
          </div>
          ${subdirBlocks}
        </div>
      `;
    }).join("");
    html += deepSections;
  }

  html += `</section>`;
  return html;
}

function deliveryLabel(modeValue, isDelayedValue) {
  const mode = asText(modeValue, "live").toLowerCase();
  return mode === "delayed" || isDelayedValue === true ? "DELAYED" : "LIVE";
}

function queueDepthLabel(value) {
  const depth = Number(value);
  if (!Number.isFinite(depth) || depth < 0) {
    return "0";
  }
  return String(Math.floor(depth));
}

function deliveryLagLabel(value) {
  const sec = Number(value);
  if (!Number.isFinite(sec) || sec < 0) {
    return "-";
  }
  return `${Math.floor(sec)}s`;
}

function getDeliveryCountsCacheKey(hostname = state.selectedHost, hours = state.analysisHours) {
  return `${String(hostname || "").trim()}|${Number(hours || 24)}`;
}

function renderDeliveryStatsBar() {
  const deliveryStats = document.getElementById("deliveryStats");
  if (!deliveryStats) {
    return;
  }

  if (!state.selectedHost) {
    deliveryStats.textContent = "";
    return;
  }

  const latestLabel = state.analysisLatestDeliveryLabel || "LIVE";
  const cacheKey = getDeliveryCountsCacheKey();
  const cached = state.deliveryCountsCache[cacheKey] || null;
  const hasCounts = Boolean(cached);
  const delayedRaw = hasCounts ? Number(cached.delayed_report_count || 0) : null;
  const liveRaw = hasCounts ? Number(cached.live_report_count || 0) : null;
  const delayedText = hasCounts ? delayedRaw.toLocaleString("de-DE") : "N/A";
  const liveText = hasCounts ? liveRaw.toLocaleString("de-DE") : "N/A";
  const delayedClass = hasCounts ? (delayedRaw > 0 ? " delayed" : " live") : "";
  const liveClass = hasCounts ? " live" : "";
  const buttonLabel = state.deliveryCountsLoading ? "Berechne..." : (hasCounts ? "Neu berechnen" : "Berechnen");
  const disabledAttr = state.deliveryCountsLoading ? " disabled" : "";

  deliveryStats.innerHTML = [
    `<span class="stat-chip">📡 ${latestLabel}</span>`,
    `<span class="stat-chip${delayedClass}">⏳ ${delayedText} Verzögert (Zeitraum)</span>`,
    `<span class="stat-chip${liveClass}">⚡ ${liveText} LIVE (Zeitraum)</span>`,
    `<button id="computeDeliveryCountsButton" class="btn-secondary delivery-calc-button" type="button"${disabledAttr}>${buttonLabel}</button>`,
  ].join("");

  const computeButton = document.getElementById("computeDeliveryCountsButton");
  if (computeButton) {
    computeButton.addEventListener("click", async () => {
      await loadDeliveryCountsForHost(true);
    });
  }
}

async function loadDeliveryCountsForHost(force = false) {
  if (!state.selectedHost) {
    return;
  }

  const cacheKey = getDeliveryCountsCacheKey();
  if (!force && state.deliveryCountsCache[cacheKey]) {
    renderDeliveryStatsBar();
    return;
  }

  state.deliveryCountsLoading = true;
  renderDeliveryStatsBar();

  try {
    const hostNameParam = encodeURIComponent(state.selectedHost);
    const url = `/api/v1/analysis-delivery?hostname=${hostNameParam}&hours=${state.analysisHours}`;
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error("HTTP " + response.status);
    }

    const data = await response.json();
    state.deliveryCountsCache[cacheKey] = {
      delayed_report_count: Number(data.delayed_report_count || 0),
      live_report_count: Number(data.live_report_count || 0),
    };
  } catch (_error) {
    delete state.deliveryCountsCache[cacheKey];
  } finally {
    state.deliveryCountsLoading = false;
    renderDeliveryStatsBar();
  }
}

function asText(value, fallback = "-") {
  if (value === null || value === undefined) {
    return fallback;
  }

  const text = String(value).trim();
  return text === "" ? fallback : text;
}

function formatUtcPlus2(value) {
  const text = asText(value);
  if (text === "-") {
    return text;
  }

  const parsed = new Date(text);
  if (Number.isNaN(parsed.getTime())) {
    return text;
  }

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

function formatFileSize(bytes) {
  if (!bytes || bytes <= 0) return "-";
  if (bytes >= 1073741824) return (bytes / 1073741824).toFixed(2) + " GB";
  if (bytes >= 1048576) return (bytes / 1048576).toFixed(1) + " MB";
  if (bytes >= 1024) return (bytes / 1024).toFixed(0) + " KB";
  return bytes + " B";
}

function formatUtcPlus2Short(isoUtc) {
  // Returns "DD.MM. HH:MM" (no year, no seconds) for compact inline display
  const parsed = new Date(isoUtc);
  if (Number.isNaN(parsed.getTime())) return isoUtc;
  const shifted = new Date(parsed.getTime() + 2 * 60 * 60 * 1000);
  return shifted.toLocaleString("de-DE", {
    day: "2-digit",
    month: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
    timeZone: "UTC",
  });
}

function toLocalDateTimeInputValue(value) {
  const text = asText(value, "");
  if (!text) {
    return "";
  }
  const parsed = new Date(text);
  if (Number.isNaN(parsed.getTime())) {
    return "";
  }
  const yyyy = parsed.getFullYear();
  const mm = String(parsed.getMonth() + 1).padStart(2, "0");
  const dd = String(parsed.getDate()).padStart(2, "0");
  const hh = String(parsed.getHours()).padStart(2, "0");
  const mi = String(parsed.getMinutes()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd}T${hh}:${mi}`;
}

function formatUptime(secondsValue) {
  const seconds = Number(secondsValue);
  if (!Number.isFinite(seconds) || seconds < 0) {
    return "-";
  }

  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);

  return `${days}d ${hours}h ${minutes}m`;
}

function renderFilesystemTable(filesystems) {
  if (!Array.isArray(filesystems) || filesystems.length === 0) {
    return "<p class=\"muted\">Keine Filesystem-Daten</p>";
  }

  const rows = filesystems
    .map((fs) => {
      const mountpoint = renderPathCell(fs.mountpoint, 64);
      const fsName = renderPathCell(fs.fs, 32);
      const fsType = escapeHtml(asText(fs.type));
      const usedPercent = Number(fs.used_percent);
      const usedKb = Number(fs.used);
      const totalKb = Number(fs.blocks);
      const availKb = Number(fs.available);

      const usedStr = Number.isFinite(usedKb) && usedKb >= 0 ? formatKilobytes(usedKb) : "-";
      const totalStr = Number.isFinite(totalKb) && totalKb >= 0 ? formatKilobytes(totalKb) : "-";
      const availStr = Number.isFinite(availKb) && availKb >= 0 ? formatKilobytes(availKb) : "-";
      const pct = Number.isFinite(usedPercent) ? usedPercent : 0;
      const pctText = Number.isFinite(usedPercent) ? `${usedPercent}%` : "-";
      const barColor = pct >= 90 ? "#ef4444" : pct >= 75 ? "#f59e0b" : "#22c55e";
      const progressBar = `
        <div class="fs-bar-wrap">
          <div class="fs-bar-fill" style="width:${Math.min(pct,100)}%;background:${barColor};"></div>
        </div>
        <span class="fs-pct-label">${pctText}</span>
      `;

      return `
        <tr>
          <td class="fs-col-mountpoint">${mountpoint}</td>
          <td class="fs-col-filesystem">${fsName}</td>
          <td class="fs-col-type">${fsType}</td>
          <td class="fs-size-cell">${totalStr}</td>
          <td class="fs-size-cell">${usedStr}</td>
          <td class="fs-avail-cell">${availStr}</td>
          <td class="fs-bar-cell">${progressBar}</td>
        </tr>
      `;
    })
    .join("");

  return `
    <div class="table-wrap">
      <table class="fs-table">
        <thead>
          <tr>
            <th class="fs-col-mountpoint">📁 Mountpoint</th>
            <th class="fs-col-filesystem">💽 Filesystem</th>
            <th class="fs-col-type">🧩 Typ</th>
            <th class="fs-col-size">📦 Gesamt</th>
            <th class="fs-col-size">📊 Belegt</th>
            <th class="fs-col-size">✅ Frei</th>
            <th class="fs-col-usage">📈 Auslastung</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `;
}

function renderJournalErrorsTable(journalErrors) {
  const block = journalErrors && typeof journalErrors === "object" ? journalErrors : {};
  const entries = Array.isArray(block.entries) ? block.entries : [];
  const sinceMinutes = Number(block.since_minutes || 0);
  const sinceLabel = Number.isFinite(sinceMinutes) && sinceMinutes > 0
    ? `Fenster: letzte ${sinceMinutes} Minuten`
    : "Fenster: unbekannt";

  if (entries.length === 0) {
    return `<p class="muted">Keine kritischen Journal-Fehler gefunden. ${escapeHtml(sinceLabel)}</p>`;
  }

  const rows = entries
    .map((entry) => {
      const time = formatUtcPlus2(entry.time_utc || entry.time || "");
      const unit = asText(entry.unit, "-");
      const priority = asText(entry.priority, "-");
      const message = asText(entry.message, "-");
      return `
        <tr>
          <td>${escapeHtml(time)}</td>
          <td>${escapeHtml(priority)}</td>
          <td>${escapeHtml(unit)}</td>
          <td title="${escapeHtml(message)}">${escapeHtml(message)}</td>
        </tr>
      `;
    })
    .join("");

  return `
    <p class="count compact">${escapeHtml(sinceLabel)} | Eintraege: ${entries.length}</p>
    <div class="table-wrap">
      <table class="report-subtable">
        <thead>
          <tr>
            <th>🕒 Zeit</th>
            <th>⚠️ Prio</th>
            <th>🧩 Unit</th>
            <th>📝 Meldung</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `;
}

function renderTopProcessesTable(topProcesses) {
  const block = topProcesses && typeof topProcesses === "object" ? topProcesses : {};
  const entries = Array.isArray(block.entries) ? block.entries : [];

  if (entries.length === 0) {
    return "<p class=\"muted\">Keine Prozessdaten verfuegbar.</p>";
  }

  const rows = entries
    .map((entry) => {
      const pid = Number(entry.pid || 0);
      const cpu = Number(entry.cpu_percent);
      const mem = Number(entry.memory_percent);
      const rssKb = Number(entry.rss_kb);
      const cmd = asText(entry.command || entry.name, "-");
      return `
        <tr>
          <td>${Number.isFinite(pid) && pid > 0 ? pid : "-"}</td>
          <td>${escapeHtml(asText(entry.user, "-"))}</td>
          <td>${Number.isFinite(cpu) ? `${cpu.toFixed(1)}%` : "-"}</td>
          <td>${Number.isFinite(mem) ? `${mem.toFixed(1)}%` : "-"}</td>
          <td>${Number.isFinite(rssKb) ? formatKilobytes(rssKb) : "-"}</td>
          <td title="${escapeHtml(cmd)}">${escapeHtml(cmd)}</td>
        </tr>
      `;
    })
    .join("");

  return `
    <p class="count compact">Top Prozesse nach CPU-Auslastung</p>
    <div class="table-wrap">
      <table class="report-subtable">
        <thead>
          <tr>
            <th>🆔 PID</th>
            <th>👤 User</th>
            <th>🧠 CPU</th>
            <th>🧮 RAM</th>
            <th>💾 RSS</th>
            <th>⚙️ Command</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `;
}

function renderContainersTable(containersBlock) {
  const block = containersBlock && typeof containersBlock === "object" ? containersBlock : {};
  const entries = Array.isArray(block.entries) ? block.entries : [];
  const runtime = asText(block.runtime, "docker");
  const available = block.available === true;

  if (!available && entries.length === 0) {
    return `<p class="muted">Container-Runtime nicht verfuegbar (${escapeHtml(runtime)}).</p>`;
  }
  if (entries.length === 0) {
    return "<p class=\"muted\">Keine Container gefunden.</p>";
  }

  const rows = entries
    .map((entry) => {
      const restartCount = Number(entry.restart_count || 0);
      return `
        <tr>
          <td>${escapeHtml(asText(entry.name, "-"))}</td>
          <td>${escapeHtml(asText(entry.image, "-"))}</td>
          <td>${escapeHtml(asText(entry.state, "-"))}</td>
          <td>${escapeHtml(asText(entry.health, "-"))}</td>
          <td>${Number.isFinite(restartCount) ? restartCount : "-"}</td>
          <td title="${escapeHtml(asText(entry.status, "-"))}">${escapeHtml(asText(entry.status, "-"))}</td>
        </tr>
      `;
    })
    .join("");

  return `
    <p class="count compact">Runtime: ${escapeHtml(runtime)} | Container: ${entries.length}</p>
    <div class="table-wrap">
      <table class="report-subtable">
        <thead>
          <tr>
            <th>📦 Name</th>
            <th>🖼️ Image</th>
            <th>📌 State</th>
            <th>❤️ Health</th>
            <th>🔁 Restarts</th>
            <th>📝 Status</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `;
}

function renderAgentConfig(agentConfigBlock) {
  const block = agentConfigBlock && typeof agentConfigBlock === "object" ? agentConfigBlock : {};
  const available = block.available === true;
  const path = asText(block.path);
  const entries = Array.isArray(block.entries) ? block.entries : [];
  if (!available && entries.length === 0) {
    return `<p class="muted">Keine Agent-Konfiguration übertragen.</p>`;
  }
  const rows = entries.map(e => {
    const k = escapeHtml(asText(e.key));
    const v = asText(e.value) === "***"
      ? `<span style="color:#94a3b8;font-style:italic;">***</span>`
      : `<span>${escapeHtml(asText(e.value))}</span>`;
    return `<tr><td style="padding:4px 10px 4px 0;color:#64748b;white-space:nowrap;vertical-align:top;">${k}</td><td style="padding:4px 0;word-break:break-all;">${v}</td></tr>`;
  }).join("");
  return `
    <p class="count compact">Pfad: ${escapeHtml(path || "-")}</p>
    <table style="width:100%;border-collapse:collapse;font-size:12px;font-family:monospace;">${rows}</table>
  `;
}

function renderAgentUpdateLog(agentUpdateBlock) {
  const block = agentUpdateBlock && typeof agentUpdateBlock === "object" ? agentUpdateBlock : {};
  const available = block.available === true;
  const path = asText(block.path);
  const allLines = Array.isArray(block.lines) ? block.lines.map((line) => asText(line)) : [];
  const lineCount = Number(block.line_count || allLines.length || 0);
  const lines = allLines.slice(-10);

  if (!available && lines.length === 0) {
    return `
      <p class="muted">Kein Update-Log uebertragen.</p>
      <p class="count compact">Pfad: ${escapeHtml(path || "-")}</p>
    `;
  }

  return `
    <p class="count compact">Pfad: ${escapeHtml(path || "-")} | Zeilen: ${Number.isFinite(lineCount) ? lineCount : allLines.length} (letzte 10)</p>
    <pre class="log-viewer">${escapeHtml(lines.join("\n") || "Log-Datei ist vorhanden, enthaelt aber aktuell keine Zeilen.")}</pre>
  `;
}

function formatAgentApiKeyStatus(agentApiKeyBlock, agentConfigBlock) {
  const block = agentApiKeyBlock && typeof agentApiKeyBlock === "object" ? agentApiKeyBlock : {};
  const status = asText(block.status).toLowerCase();
  const entries = agentConfigBlock && typeof agentConfigBlock === "object" && Array.isArray(agentConfigBlock.entries)
    ? agentConfigBlock.entries
    : [];
  const hasConfiguredApiKey = entries.some((entry) => asText(entry && entry.key).toUpperCase() === "API_KEY" && asText(entry && entry.value));

  if (status === "key-auth") {
    return "aktiv | letzter Report mit API-Key authentifiziert";
  }
  if (status === "grace") {
    return "Grace | Host noch ohne Header zugelassen";
  }
  if (status === "configured") {
    return "konfiguriert | letzter Report noch nicht mit Key authentifiziert";
  }
  if (status === "missing") {
    return "fehlt | Server erwartet API-Key";
  }
  if (hasConfiguredApiKey) {
    return "konfiguriert | Status ab nächstem Report exakt sichtbar";
  }
  return "aus | Server verlangt aktuell keinen API-Key";
}

function formatCronTabSummary(cronInfo) {
  if (!cronInfo || typeof cronInfo !== "object") return escapeHtml("-");
  const rc = cronInfo.root_crontab;
  if (!rc || typeof rc !== "object") return escapeHtml("-");
  if (!rc.available) return `<span class="muted">${escapeHtml(rc.error || "nicht verfügbar")}</span>`;
  const lines = typeof rc.active_lines === "number" ? rc.active_lines : 0;
  if (lines === 0) return escapeHtml("leer (keine aktiven Einträge)");
  const content = typeof rc.content === "string" ? rc.content : "";
  const activeLines = content.split("\n").filter((l) => l.trim() && !l.trim().startsWith("#")).join("\n");
  return `<details class="cron-details"><summary>${escapeHtml(lines + " aktive Einträge")}</summary><pre class="cron-content">${escapeHtml(activeLines || content)}</pre></details>`;
}

function formatCronDSummary(cronInfo) {
  if (!cronInfo || typeof cronInfo !== "object") return escapeHtml("-");
  const cd = cronInfo.cron_d;
  if (!cd || typeof cd !== "object") return escapeHtml("-");
  if (!cd.available) return `<span class="muted">${escapeHtml(cd.error || "nicht verfügbar")}</span>`;
  const count = typeof cd.file_count === "number" ? cd.file_count : 0;
  if (count === 0) return escapeHtml("leer");
  const files = Array.isArray(cd.files) ? cd.files : [];
  const fileBlocks = files.map((f) => {
    const name = escapeHtml(f && f.name ? f.name : "unbekannt");
    const content = f && typeof f.content === "string" ? f.content : "";
    return `<details class="cron-details"><summary>${name}</summary><pre class="cron-content">${escapeHtml(content)}</pre></details>`;
  }).join("");
  return `${escapeHtml(count + " Datei" + (count !== 1 ? "en" : ""))} ${fileBlocks}`;
}

function renderReportCard(report) {
  const payload = report && report.payload ? report.payload : {};
  const cpu = payload.cpu || {};
  const memory = payload.memory || {};
  const swap = payload.swap || {};
  const network = payload.network || {};
  const defaultNicIpv4 = resolveDefaultNicIpv4(report, payload, network);
  const title = asText(report.display_name || payload.display_name || report.hostname || payload.hostname);
  const technicalHostname = asText(report.hostname || payload.hostname);
  const deliveryMode = asText(report.delivery_mode || payload.delivery_mode || "live", "live").toLowerCase();
  const isDelayed = deliveryMode === "delayed" || payload.is_delayed === true;
  const chipClass = isDelayed ? "delivery-chip delayed" : "delivery-chip live";
  const chipText = isDelayed ? "DELAYED" : "LIVE";
  const queueDepth = queueDepthLabel(payload.queue_depth);
  const section = normalizeReportSection(state.reportSection);
  const sapB1Summary = renderSapB1SystemSummary(payload);
  const hanaInfoMeta = (function() {
    const hi = payload && typeof payload.hana_info === "object" ? payload.hana_info : null;
    if (!hi || !hi.available) return "-";
    const v = asText(hi.version, "");
    const b = asText(hi.branch, "");
    if (v && b) return `${v} (${b})`;
    return v || b || "-";
  })();

  const hanaSid = (function() {
    const hi = payload && typeof payload.hana_info === "object" ? payload.hana_info : null;
    return hi && hi.available ? asText(hi.sid, "") : "";
  })();

  // Helper function to render meta-group items
  function renderMetaItem(icon, label, value) {
    return `<p class="meta-group-item"><strong>${icon} ${label}</strong><span>${escapeHtml(asText(value || "-"))}</span></p>`;
  }

  function renderMetaItemHtml(icon, label, html) {
    return `<p class="meta-group-item"><strong>${icon} ${label}</strong><span>${html}</span></p>`;
  }

  // Build grouped meta sections
  const agentGroup = `
    <div class="meta-group">
      <div class="meta-group-title">🤖 Agent-Info</div>
      <div class="meta-group-content">
        ${renderMetaItem("🆔", "Agent ID", report.agent_id || payload.agent_id)}
        ${renderMetaItem("🧷", "Version", payload.agent_version)}
        ${renderMetaItem("🔐", "API-Key", formatAgentApiKeyStatus(payload.agent_api_key, payload.agent_config))}
      </div>
    </div>
  `;

  const systemGroup = `
    <div class="meta-group">
      <div class="meta-group-title">🖥️ System</div>
      <div class="meta-group-content">
        ${renderMetaItem("🐧", "OS", payload.os)}
        ${renderMetaItem("⚙️", "Kernel", payload.kernel)}
        ${renderMetaItem("⏱️", "Uptime", formatUptime(payload.uptime_seconds))}
        ${renderMetaItem("🗃️", "Queue", queueDepth + " Dateien")}
      </div>
    </div>
  `;

  const resourcesGroup = `
    <div class="meta-group">
      <div class="meta-group-title">📊 Ressourcen</div>
      <div class="meta-group-content">
        ${renderMetaItem("🧠", "CPU", formatPercent(cpu.usage_percent) + " | load " + formatNumber(cpu.load_avg_1, 2) + " / " + formatNumber(cpu.load_avg_5, 2) + " / " + formatNumber(cpu.load_avg_15, 2))}
        ${renderMetaItem("🧮", "RAM", formatPercent(memory.used_percent) + " | " + formatKilobytes(memory.used_kb) + " / " + formatKilobytes(memory.total_kb))}
        ${renderMetaItem("💤", "Swap", formatPercent(swap.used_percent) + " | " + formatKilobytes(swap.used_kb) + " / " + formatKilobytes(swap.total_kb))}
      </div>
    </div>
  `;

  const networkGroup = `
    <div class="meta-group">
      <div class="meta-group-title">🌐 Netzwerk</div>
      <div class="meta-group-content">
        ${renderMetaItem("🌍", "Primary IP", report.primary_ip || payload.primary_ip)}
        ${renderMetaItem("🔌", "Std. NIC IP", defaultNicIpv4 || "-")}
        ${renderMetaItem("🌍", "Default NIC", network.default_interface)}
        ${renderMetaItem("🛣️", "Default GW", network.default_gateway)}
        ${renderMetaItemHtml("🧭", "DNS", formatDnsServers(network.dns_servers))}
      </div>
    </div>
  `;

  let detailContent = "";
  if (section === "journal") {
    detailContent = `
      <section class="detail-card">
        <h4>🚨 Journal Fehler (kritisch)</h4>
        ${renderJournalErrorsTable(payload.journal_errors)}
      </section>
    `;
  } else if (section === "processes") {
    detailContent = `
      <section class="detail-card">
        <h4>🏎️ Top Prozesse</h4>
        ${renderTopProcessesTable(payload.top_processes)}
      </section>
    `;
  } else if (section === "containers") {
    detailContent = `
      <section class="detail-card">
        <h4>🐳 Container Status</h4>
        ${renderContainersTable(payload.containers)}
      </section>
    `;
  } else if (section === "sap-b1-systeminfo") {
    detailContent = `
      <div class="detail-cards">
        ${renderSapB1SystemInfoCard(payload)}
      </div>
    `;
  } else if (section === "agent-update") {
    detailContent = `
      <div class="detail-cards">
        <details class="detail-card detail-card-collapsible">
          <summary>⟳ Agent Update Log</summary>
          ${renderAgentUpdateLog(payload.agent_update)}
        </details>

        <details class="detail-card detail-card-collapsible">
          <summary>🗂️ agent.conf</summary>
          ${renderAgentConfig(payload.agent_config)}
        </details>

        ${payload.cron_info ? `
        <details class="detail-card detail-card-collapsible">
          <summary>🕐 Root Crontab</summary>
          ${formatCronTabSummary(payload.cron_info)}
        </details>

        <details class="detail-card detail-card-collapsible">
          <summary>📅 cron.d</summary>
          ${formatCronDSummary(payload.cron_info)}
        </details>` : ""}
      </div>
    `;
  } else if (section === "dir-listings") {
    detailContent = `
      <div class="detail-cards">
        ${renderDirListingsCard(payload)}
      </div>
    `;
  } else {
    detailContent = `
      <div class="detail-cards">
        ${renderSapBusinessOneCard(payload)}
        <section class="detail-card">
          <h4>🌐 Netzwerk-Details</h4>
          ${renderNetworkTable(network)}
        </section>

        <section class="detail-card">
          <h4>💾 Filesysteme</h4>
          ${renderFilesystemTable(payload.filesystems)}
        </section>
      </div>
    `;
  }

  return `
    <article class="report-card">
      <div class="report-header">
        <div>
          <h3>${escapeHtml(title)} <span class="${chipClass}">${chipText}</span></h3>
          <p class="report-subtitle">🖥️ ${escapeHtml(technicalHostname)}${sapB1Summary !== "-" ? ` <span class="sap-hana-chip sap-b1-chip">🧾 ${escapeHtml(sapB1Summary.replace(/<[^>]+>/g, ""))}</span>` : ""}${hanaInfoMeta !== "-" ? ` <span class="sap-hana-chip hana-chip">🟢 ${escapeHtml(hanaInfoMeta)}</span>` : ""}${hanaSid ? ` <span class="sap-hana-chip hana-sid-chip">🏷️ ${escapeHtml(hanaSid)}</span>` : ""}</p>
        </div>
        <span class="report-time">${escapeHtml(formatUtcPlus2(report.received_at_utc || payload.timestamp_utc))}</span>
      </div>

      <div class="meta-groups">
        ${agentGroup}
        ${systemGroup}
        ${resourcesGroup}
        ${networkGroup}
      </div>
      ${detailContent}
    </article>
  `;
}

function updatePagerButtons() {
  const hostsPrevButton = document.getElementById("hostsPrevButton");
  const hostsNextButton = document.getElementById("hostsNextButton");
  const reportsPrevButton = document.getElementById("reportsPrevButton");
  const reportsNextButton = document.getElementById("reportsNextButton");
  const reportsPrevButtonTop = document.getElementById("reportsPrevButtonTop");
  const reportsNextButtonTop = document.getElementById("reportsNextButtonTop");

  hostsPrevButton.disabled = state.hostOffset <= 0;
  hostsNextButton.disabled = state.hostOffset + state.hostLimit >= state.totalHosts;

  reportsPrevButton.disabled = state.reportOffset <= 0 || !state.selectedHost;
  reportsNextButton.disabled =
    !state.selectedHost || state.reportOffset + state.reportLimit >= state.totalReports;

  if (reportsPrevButtonTop) {
    reportsPrevButtonTop.disabled = reportsPrevButton.disabled;
  }
  if (reportsNextButtonTop) {
    reportsNextButtonTop.disabled = reportsNextButton.disabled;
  }
}

async function goToPreviousReport() {
  if (state.reportOffset <= 0) {
    return;
  }
  state.reportOffset = Math.max(0, state.reportOffset - state.reportLimit);
  await loadReportsForHost();
  await loadAnalysisForHost();
  await loadAlertsForHost();
}

async function goToNextReport() {
  if (state.reportOffset + state.reportLimit >= state.totalReports) {
    return;
  }
  state.reportOffset += state.reportLimit;
  await loadReportsForHost();
  await loadAnalysisForHost();
  await loadAlertsForHost();
}

function normalizeHostOsFamily(host) {
  const osRaw = asText(host?.os || "", "").toLowerCase();
  if (osRaw.includes("windows")) {
    return "windows";
  }
  return "linux";
}

function normalizeHostCountryCode(host) {
  return asText(host?.country_code || "", "").trim().toUpperCase();
}

function renderHostIconFilters(hosts) {
  const osContainer = document.getElementById("hostOsFilterChips");
  const countryContainer = document.getElementById("hostCountryFilterChips");
  if (!osContainer || !countryContainer) {
    return;
  }

  const osFamilies = Array.from(new Set((hosts || []).map((host) => normalizeHostOsFamily(host))));
  const osOptions = ["all", ...osFamilies.filter((item) => item !== "all")];
  if (!osOptions.includes(state.hostOsFilter)) {
    state.hostOsFilter = "all";
  }
  osContainer.innerHTML = osOptions.map((item) => {
    if (item === "all") {
      return `<button class="icon-filter-chip${state.hostOsFilter === "all" ? " active" : ""}" type="button" data-os-filter="all" title="Alle Betriebssysteme">Alle</button>`;
    }
    const iconName = item === "windows" ? "windows.png" : "linux.png";
    const label = item === "windows" ? "Windows" : "Linux";
    return `<button class="icon-filter-chip${state.hostOsFilter === item ? " active" : ""}" type="button" data-os-filter="${item}" title="${label}"><img src="icons/${iconName}" alt="${label}" onerror="if(!this.dataset.fallback){this.dataset.fallback='1';this.src='/icons/${iconName}';}"></button>`;
  }).join("");

  const countryCodes = Array.from(
    new Set((hosts || []).map((host) => normalizeHostCountryCode(host)).filter((code) => /^[A-Z]{2}$/.test(code))),
  ).sort();
  const countryOptions = ["all", ...countryCodes];
  if (state.hostCountryFilter !== "all" && !countryOptions.includes(state.hostCountryFilter)) {
    state.hostCountryFilter = "all";
  }
  countryContainer.innerHTML = countryOptions.map((code) => {
    if (code === "all") {
      return `<button class="icon-filter-chip${state.hostCountryFilter === "all" ? " active" : ""}" type="button" data-country-filter="all" title="Alle Länder">Alle</button>`;
    }
    const lower = code.toLowerCase();
    return `<button class="icon-filter-chip${state.hostCountryFilter === code ? " active" : ""}" type="button" data-country-filter="${code}" title="Land ${code}"><img src="icons/${code}.png" alt="${code}" onerror="if(!this.dataset.fallback1){this.dataset.fallback1='1';this.src='/icons/${code}.png';return;}if(!this.dataset.fallback2){this.dataset.fallback2='1';this.src='/icons/${lower}.png';return;}if(!this.dataset.fallback3){this.dataset.fallback3='1';this.src='/icons/${lower}.svg';return;}this.parentElement.style.display='none';"></button>`;
  }).join("");

  osContainer.querySelectorAll("[data-os-filter]").forEach((button) => {
    button.addEventListener("click", async () => {
      const nextFilter = String(button.getAttribute("data-os-filter") || "all");
      if (state.hostOsFilter === nextFilter) {
        return;
      }
      state.hostOsFilter = nextFilter;
      state.hostOffset = 0;
      persistHostFilterPreferences();
      await loadHosts();
    });
  });

  countryContainer.querySelectorAll("[data-country-filter]").forEach((button) => {
    button.addEventListener("click", async () => {
      const nextFilterRaw = String(button.getAttribute("data-country-filter") || "all");
      const nextFilter = nextFilterRaw.toUpperCase() === "ALL" ? "all" : nextFilterRaw.toUpperCase();
      if (state.hostCountryFilter === nextFilter) {
        return;
      }
      state.hostCountryFilter = nextFilter;
      state.hostOffset = 0;
      persistHostFilterPreferences();
      await loadHosts();
    });
  });
}

function filterAndSortHosts(hosts) {
  const query = state.hostSearchQuery.toLowerCase().trim();
  const alertFilter = String(state.hostAlertFilter || "all");
  const mutedFilter = String(state.hostMutedFilter || "all");
  const osFilter = String(state.hostOsFilter || "all");
  const countryFilter = String(state.hostCountryFilter || "all").toUpperCase();

  let filtered = hosts;
  if (query.length > 0) {
    filtered = hosts.filter((host) => {
      const displayName = (host.display_name || host.hostname || "").toLowerCase();
      const hostname = (host.hostname || "").toLowerCase();
      return displayName.includes(query) || hostname.includes(query);
    });
  }

  if (alertFilter === "with-alerts") {
    filtered = filtered.filter((host) => Number(host.open_alert_count || 0) > 0);
  } else if (alertFilter === "without-alerts") {
    filtered = filtered.filter((host) => Number(host.open_alert_count || 0) <= 0);
  }

  if (mutedFilter === "with-muted") {
    filtered = filtered.filter((host) => {
      const hostname = asText(host.hostname, "");
      const muted = Array.isArray(state.mutedAlertsByHost[hostname]) ? state.mutedAlertsByHost[hostname] : [];
      return muted.length > 0;
    });
  } else if (mutedFilter === "without-muted") {
    filtered = filtered.filter((host) => {
      const hostname = asText(host.hostname, "");
      const muted = Array.isArray(state.mutedAlertsByHost[hostname]) ? state.mutedAlertsByHost[hostname] : [];
      return muted.length === 0;
    });
  }

  if (osFilter !== "all") {
    filtered = filtered.filter((host) => normalizeHostOsFamily(host) === osFilter);
  }

  if (countryFilter !== "ALL") {
    filtered = filtered.filter((host) => normalizeHostCountryCode(host) === countryFilter);
  }

  const interestMode = normalizeHostInterestMode(state.hostInterestMode);
  const interestSet = state.hostInterestHosts;
  if (interestMode === "interested_only" && interestSet.size > 0) {
    filtered = filtered.filter((host) => interestSet.has(String(host.hostname || "")));
  }

  filtered.sort((a, b) => {
    if (interestMode === "interested_first" && interestSet.size > 0) {
      const interestedA = interestSet.has(String(a.hostname || "")) ? 1 : 0;
      const interestedB = interestSet.has(String(b.hostname || "")) ? 1 : 0;
      if (interestedA !== interestedB) {
        return interestedB - interestedA;
      }
    }

    const favoriteA = Boolean(a.is_favorite) ? 1 : 0;
    const favoriteB = Boolean(b.is_favorite) ? 1 : 0;
    if (favoriteA !== favoriteB) {
      return favoriteB - favoriteA;
    }

    const nameA = (a.display_name || a.hostname || "").toLowerCase();
    const nameB = (b.display_name || b.hostname || "").toLowerCase();
    return nameA.localeCompare(nameB);
  });

  return filtered;
}

function splitHosts(hosts) {
  const sorted = filterAndSortHosts(hosts);
  return {
    visibleHosts: sorted.filter((host) => !Boolean(host.is_hidden)),
    hiddenHosts: sorted.filter((host) => Boolean(host.is_hidden)),
  };
}

function hasActiveHostFilters() {
  return Boolean(
    String(state.hostSearchQuery || "").trim().length > 0
    || String(state.hostAlertFilter || "all") !== "all"
    || String(state.hostMutedFilter || "all") !== "all"
    || String(state.hostOsFilter || "all") !== "all"
    || String(state.hostCountryFilter || "all") !== "all"
  );
}

function hiddenHostsToggleLabel(collapsed) {
  return collapsed ? "▸" : "▾";
}

function hiddenHostMutedAlertsToggleLabel(collapsed) {
  return collapsed ? "▸" : "▾";
}

async function loadAlertMutes() {
  try {
    const response = await fetch("/api/v1/alert-mutes");
    if (!response.ok) {
      throw new Error("HTTP " + response.status);
    }

    const data = await response.json();
    const grouped = {};
    for (const item of (data.mutes || [])) {
      const hostname = asText(item.hostname, "");
      const mountpoint = asText(item.mountpoint, "");
      if (!hostname || !mountpoint) {
        continue;
      }
      if (!grouped[hostname]) {
        grouped[hostname] = [];
      }
      grouped[hostname].push({
        hostname,
        mountpoint,
        muted_by: asText(item.muted_by, "-"),
        muted_at_utc: asText(item.muted_at_utc, "-"),
      });
    }

    for (const hostname of Object.keys(grouped)) {
      grouped[hostname].sort((left, right) => left.mountpoint.localeCompare(right.mountpoint));
    }

    state.mutedAlertsByHost = grouped;
  } catch (_error) {
    // Keep host list usable even if the mutes endpoint is temporarily unavailable.
    state.mutedAlertsByHost = {};
  }
}

function renderSingleHostCard(host) {
  const hostname = asText(host.hostname);
  const displayName = asText(host.display_name || host.hostname);
  const selectedClass = hostname === state.selectedHost ? "host-item selected" : "host-item";
  const hostDelivery = deliveryLabel(host.delivery_mode, host.is_delayed);
  const hostQueueDepth = queueDepthLabel(host.queue_depth);
  const hostDeliveryLag = deliveryLagLabel(host.delivery_lag_sec);
  const openAlertCount = Number(host.open_alert_count || 0);
  const openCriticalAlertCount = Number(host.open_critical_alert_count || 0);
  const hasOpenAlerts = openAlertCount > 0;
  const isFavorite = Boolean(host.is_favorite);
  const isHidden = Boolean(host.is_hidden);
  const hiddenClass = isHidden ? " host-item-hidden" : "";
  const favoriteClass = isFavorite ? " host-item-favorite" : "";
  const statusBarClass = openCriticalAlertCount > 0 ? "host-status-bar host-status-bar--critical"
    : openAlertCount > 0 ? "host-status-bar host-status-bar--warning"
    : "host-status-bar host-status-bar--ok";
  const chipClass = openCriticalAlertCount > 0 ? "host-alert-chip critical" : "host-alert-chip";
  const alertChip = hasOpenAlerts ? `<span class="${chipClass}">🔔 ${openAlertCount}</span>` : "";
  const apiKeyStatus = asText(host.agent_api_key_status || "off").toLowerCase();
  const apiKeyChipMod = apiKeyStatus === "key-auth" ? "ok"
    : apiKeyStatus === "grace" ? "grace"
    : apiKeyStatus === "configured" ? "configured"
    : apiKeyStatus === "missing" ? "missing"
    : "off";
  const apiKeyChipTitle = apiKeyStatus === "key-auth" ? "API-Key: aktiv"
    : apiKeyStatus === "grace" ? "API-Key: Grace (noch kein Key)"
    : apiKeyStatus === "configured" ? "API-Key: konfiguriert"
    : apiKeyStatus === "missing" ? "API-Key: fehlt"
    : "API-Key: nicht konfiguriert";
  const apiKeyChip = `<span class="host-apikey-chip ${apiKeyChipMod}" title="${escapeHtml(apiKeyChipTitle)}">API</span>`;

  const osRaw = asText(host.os || "").toLowerCase();
  const countryCode = asText(host.country_code || "", "").toUpperCase();
  const countryCodeLower = countryCode.toLowerCase();
  const iconName = osRaw.includes("windows") ? "windows.png" : "linux.png";
  const osLabel = osRaw.includes("windows") ? "Windows" : "Linux";
  const osIcon = `<img src="icons/${iconName}" class="host-os-icon" alt="${osLabel}" title="${escapeHtml(asText(host.os))}" onerror="if(!this.dataset.fallback){this.dataset.fallback='1';this.src='/icons/${iconName}';}">`;
  const flagIcon = countryCode
    ? `<img src="icons/${countryCode}.png" class="host-flag-icon" alt="${countryCode}" title="Land: ${countryCode}" onerror="if(!this.dataset.fallback1){this.dataset.fallback1='1';this.src='/icons/${countryCode}.png';return;}if(!this.dataset.fallback2){this.dataset.fallback2='1';this.src='/icons/${countryCodeLower}.png';return;}if(!this.dataset.fallback3){this.dataset.fallback3='1';this.src='/icons/${countryCodeLower}.svg';return;}this.style.display='none'">`
    : "";
  const mutedAlerts = Array.isArray(state.mutedAlertsByHost[hostname]) ? state.mutedAlertsByHost[hostname] : [];
  const hasMutedAlerts = mutedAlerts.length > 0;
  const mutedCollapsed = state.hiddenHostMutedAlertsCollapsed[hostname] !== false;
  const mutedBodyClass = mutedCollapsed ? "hidden" : "";

  let mutedAlertsSection = "";
  if (isHidden && hasMutedAlerts) {
    const hostnameEncForList = encodeURIComponent(hostname);
    const rows = mutedAlerts
      .map((item) => {
        const hostnameEnc = encodeURIComponent(hostname);
        const mountpointEnc = encodeURIComponent(item.mountpoint);
        return `
          <li>
            <span class="host-muted-path" title="${escapeHtml(item.mountpoint)}">${escapeHtml(shortPath(item.mountpoint, 34))}</span>
            <button class="host-unmute-action" type="button" data-action="unmute-alert" data-host-enc="${hostnameEnc}" data-mount-enc="${mountpointEnc}" title="Alert wieder aktivieren">🔔</button>
          </li>
        `;
      })
      .join("");

    mutedAlertsSection = `
      <section class="host-muted-section">
        <div class="host-muted-row">
          <span class="host-muted-title">🔇 Gemutet: ${mutedAlerts.length}</span>
          <button class="host-group-toggle host-muted-toggle" type="button" data-action="toggle-muted-list" data-host-enc="${hostnameEncForList}" aria-expanded="${mutedCollapsed ? "false" : "true"}">${hiddenHostMutedAlertsToggleLabel(mutedCollapsed)}</button>
        </div>
        <ul class="host-muted-list ${mutedBodyClass}" data-muted-body-enc="${hostnameEncForList}">
          ${rows}
        </ul>
      </section>
    `;
  }

  return `
    <article class="${selectedClass}${hiddenClass}${favoriteClass}" tabindex="0" role="button" data-host="${escapeHtml(hostname)}">
      <div class="${statusBarClass}"></div>
      ${flagIcon}
      <strong class="host-title-line">
        <span>${escapeHtml(displayName)}</span>
      </strong>
      <span>🖥️ ${escapeHtml(hostname)}</span>
      <span>🌐 ${escapeHtml(asText(host.primary_ip))}</span>
      <span>⏱️ Zustellung: ${escapeHtml(hostDeliveryLag)}</span>
      <span>🧷 ${escapeHtml(asText(host.agent_version))} &nbsp;·&nbsp; 📦 ${Number(host.report_count || 0).toLocaleString("de-DE")}</span>
      <span>🕒 ${escapeHtml(formatUtcPlus2(host.last_seen_utc))}</span>
      <span class="host-card-actions">
        <button class="host-mini-action visibility${isHidden ? " active" : ""}" type="button" data-action="hidden" data-host="${escapeHtml(hostname)}" data-current="${isHidden ? "1" : "0"}" title="${isHidden ? "Einblenden" : "Ausblenden"}">${isHidden ? "👀" : "🫣"}</button>
        <button class="host-mini-action favorite${isFavorite ? " active" : ""}" type="button" data-action="favorite" data-host="${escapeHtml(hostname)}" data-current="${isFavorite ? "1" : "0"}" title="Favorit umschalten">★</button>
        ${apiKeyChip}
        ${alertChip}
      </span>
      ${mutedAlertsSection}
      ${osIcon}
    </article>
  `;
}

async function saveHostSettings(hostname, partialSettings) {
  const response = await fetch("/api/v1/host-settings", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      hostname,
      ...partialSettings,
    }),
  });

  if (!response.ok) {
    throw new Error("HTTP " + response.status);
  }

  return response.json();
}

async function deleteHostCard(hostname) {
  const response = await fetch("/api/v1/host-delete", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ hostname }),
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || ("HTTP " + response.status));
  }
  return data;
}

function closeHostContextMenu() {
  const menu = document.getElementById("hostContextMenu");
  if (!menu) {
    return;
  }
  menu.classList.add("hidden");
  delete menu.dataset.hostname;
}

function ensureHostContextMenu() {
  let menu = document.getElementById("hostContextMenu");
  if (menu) {
    return menu;
  }

  menu = document.createElement("div");
  menu.id = "hostContextMenu";
  menu.className = "host-context-menu hidden";
  menu.innerHTML = `
    <div class="host-context-menu-label"></div>
    <button type="button" data-action="delete-host-card">🗑️ Karte löschen…</button>
  `;
  document.body.appendChild(menu);

  menu.addEventListener("click", async (event) => {
    const trigger = event.target.closest("button[data-action='delete-host-card']");
    if (!trigger) {
      return;
    }

    event.preventDefault();
    event.stopPropagation();
    const hostname = String(menu.dataset.hostname || "").trim();
    closeHostContextMenu();
    if (!hostname) {
      return;
    }

    const confirmed = window.confirm(
      `Karte fuer ${hostname} wirklich loeschen?\n\nDas entfernt Reports, Alerts und Host-Settings dauerhaft.`
    );
    if (!confirmed) {
      return;
    }

    try {
      await deleteHostCard(hostname);
      if (state.selectedHost === hostname) {
        state.selectedHost = "";
        state.selectedDisplayName = "";
        state.currentReport = null;
        state.reportOffset = 0;
      }

      await loadHosts();
      await loadReportsForHost();
      await loadAnalysisForHost();
      await loadAlertsForHost();
    } catch (error) {
      window.alert(`Host-Karte konnte nicht geloescht werden: ${error.message}`);
    }
  });

  document.addEventListener("click", () => closeHostContextMenu());
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      closeHostContextMenu();
    }
  });
  document.addEventListener("scroll", () => closeHostContextMenu(), true);
  window.addEventListener("resize", () => closeHostContextMenu());

  return menu;
}

function openHostContextMenu(hostname, clientX, clientY) {
  const menu = ensureHostContextMenu();
  const normalizedHost = String(hostname || "").trim();
  if (!normalizedHost) {
    return;
  }

  const label = menu.querySelector(".host-context-menu-label");
  if (label) {
    label.textContent = normalizedHost;
  }
  menu.dataset.hostname = normalizedHost;
  menu.classList.remove("hidden");

  const viewportWidth = window.innerWidth;
  const viewportHeight = window.innerHeight;
  const rect = menu.getBoundingClientRect();
  const menuWidth = rect.width || 220;
  const menuHeight = rect.height || 88;
  const margin = 8;
  const left = Math.min(Math.max(clientX, margin), viewportWidth - menuWidth - margin);
  const top = Math.min(Math.max(clientY, margin), viewportHeight - menuHeight - margin);

  menu.style.left = `${left}px`;
  menu.style.top = `${top}px`;
}

async function triggerAgentUpdate(hostname) {
  const response = await fetch("/api/v1/agent-command", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      hostname,
      command_type: "update-now",
      ttl_minutes: 240,
    }),
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || ("HTTP " + response.status));
  }
  return data;
}

async function triggerAgentUpdateForAllHosts() {
  const response = await fetch("/api/v1/agent-command-bulk", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      command_type: "update-now",
      ttl_minutes: 240,
    }),
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || ("HTTP " + response.status));
  }
  return data;
}

async function triggerAgentApiKeyRolloutForAllHosts(apiKey) {
  const response = await fetch("/api/v1/agent-command-bulk", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      command_type: "set-api-key",
      ttl_minutes: 240,
      command_payload: {
        api_key: String(apiKey || "").trim(),
      },
    }),
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || ("HTTP " + response.status));
  }
  return data;
}

async function triggerFileDownload(requestUrl, fallbackFilename) {
  const response = await fetch(requestUrl, {
    method: "GET",
    credentials: "same-origin",
  });

  if (!response.ok) {
    const data = await response.json().catch(() => ({}));
    throw new Error(data.error || ("HTTP " + response.status));
  }

  const blob = await response.blob();
  const disposition = String(response.headers.get("Content-Disposition") || "");
  const match = disposition.match(/filename="([^"]+)"/i);
  const filename = (match && match[1])
    ? match[1]
    : fallbackFilename;

  const downloadUrl = window.URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = downloadUrl;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.URL.revokeObjectURL(downloadUrl);
  return filename;
}

function triggerNativeDownload(requestUrl, fallbackFilename) {
  const anchor = document.createElement("a");
  anchor.href = requestUrl;
  anchor.download = fallbackFilename;
  anchor.rel = "noopener";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  return fallbackFilename;
}

function waitMs(ms) {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

async function downloadDatabaseBackup() {
  const fallbackFilename = `monitoring-backup-${new Date().toISOString().replace(/[.:]/g, "-")}.db`;
  const startResponse = await fetch("/api/v1/backup/database/start", {
    method: "GET",
    credentials: "same-origin",
  });
  const startData = await startResponse.json().catch(() => ({}));
  if (!startResponse.ok) {
    throw new Error(startData.error || ("HTTP " + startResponse.status));
  }

  const jobId = String(startData.job_id || "").trim();
  if (!jobId) {
    throw new Error("backup job start failed");
  }

  const startTs = Date.now();
  const timeoutMs = 180000;
  while (Date.now() - startTs < timeoutMs) {
    await waitMs(1200);
    const statusResponse = await fetch(`/api/v1/backup/database/status?job_id=${encodeURIComponent(jobId)}`, {
      method: "GET",
      credentials: "same-origin",
    });
    const statusData = await statusResponse.json().catch(() => ({}));
    if (!statusResponse.ok) {
      throw new Error(statusData.error || ("HTTP " + statusResponse.status));
    }
    const status = String(statusData.status || "");
    if (status === "ready") {
      return triggerNativeDownload(
        `/api/v1/backup/database/download?job_id=${encodeURIComponent(jobId)}`,
        fallbackFilename,
      );
    }
    if (status === "error") {
      throw new Error(String(statusData.error || "database backup failed"));
    }
  }

  throw new Error("backup timeout");
}

async function restoreDatabaseFromFile(file) {
  const data = await file.arrayBuffer();
  const response = await fetch("/api/v1/restore/database", {
    method: "POST",
    headers: {
      "Content-Type": "application/octet-stream",
    },
    body: data,
    credentials: "same-origin",
  });
  const json = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(json.error || ("HTTP " + response.status));
  }
  return json;
}

async function exportGlobalAlertsCsv() {
  const severity = String(state.globalSeverityFilter || "all").trim().toLowerCase();
  const severityParam = (severity && severity !== "all")
    ? `?severity=${encodeURIComponent(severity)}`
    : "";
  return triggerFileDownload(
    `/api/v1/export/alerts.csv${severityParam}`,
    `monitoring-alerts-${new Date().toISOString().replace(/[.:]/g, "-")}.csv`,
  );
}

async function exportSelectedHostReportsJson() {
  if (!state.selectedHost) {
    throw new Error("Bitte zuerst einen Host auswaehlen.");
  }
  const hostname = encodeURIComponent(state.selectedHost);
  return triggerFileDownload(
    `/api/v1/export/reports.json?hostname=${hostname}`,
    `monitoring-reports-${new Date().toISOString().replace(/[.:]/g, "-")}.json`,
  );
}

function wireHostListInteractions() {
  const hostList = document.getElementById("hostList");

  for (const item of hostList.querySelectorAll(".host-item")) {
    item.addEventListener("click", () => {
      const hostname = item.getAttribute("data-host") || "";
      if (!hostname || hostname === state.selectedHost) {
        return;
      }

      const previousScrollTop = hostList.scrollTop;
      state.selectedHost = hostname;
      state.selectedDisplayName = item.querySelector("strong")?.textContent || hostname;
      state.reportOffset = 0;
      renderHosts(state.hosts);
      hostList.scrollTop = previousScrollTop;
      loadReportsForHost();
      loadAnalysisForHost();
      loadAlertsForHost();
    });

    item.addEventListener("keydown", (event) => {
      if (event.key !== "Enter" && event.key !== " ") {
        return;
      }
      event.preventDefault();
      item.click();
    });

    item.addEventListener("contextmenu", (event) => {
      const hostname = item.getAttribute("data-host") || "";
      if (!hostname) {
        return;
      }
      event.preventDefault();
      event.stopPropagation();
      openHostContextMenu(hostname, event.clientX, event.clientY);
    });
  }

  for (const button of hostList.querySelectorAll(".host-mini-action")) {
    button.addEventListener("click", async (event) => {
      event.preventDefault();
      event.stopPropagation();

      const hostname = button.getAttribute("data-host") || "";
      const action = button.getAttribute("data-action") || "";
      const current = button.getAttribute("data-current") === "1";
      if (!hostname || !action) {
        return;
      }

      try {
        if (action === "favorite") {
          await saveHostSettings(hostname, { is_favorite: !current });
        } else if (action === "hidden") {
          await saveHostSettings(hostname, { is_hidden: !current });
        }

        await loadHosts();
        await loadReportsForHost();
        await loadAnalysisForHost();
        await loadAlertsForHost();
      } catch (error) {
        window.alert(`Host-Einstellung konnte nicht gespeichert werden: ${error.message}`);
      }
    });
  }

  const hiddenToggle = hostList.querySelector("#hiddenHostsToggleButton");
  if (hiddenToggle) {
    hiddenToggle.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      state.hiddenHostsCollapsed = !state.hiddenHostsCollapsed;
      const body = hostList.querySelector("#hiddenHostsBody");
      if (body) {
        body.classList.toggle("hidden", state.hiddenHostsCollapsed);
      }
      hiddenToggle.textContent = hiddenHostsToggleLabel(state.hiddenHostsCollapsed);
      hiddenToggle.setAttribute("aria-expanded", state.hiddenHostsCollapsed ? "false" : "true");
    });
  }

  for (const button of hostList.querySelectorAll("[data-action='toggle-muted-list']")) {
    button.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();

      const hostnameEnc = button.getAttribute("data-host-enc") || "";
      const hostname = decodeURIComponent(hostnameEnc);
      if (!hostname) {
        return;
      }

      const currentlyCollapsed = state.hiddenHostMutedAlertsCollapsed[hostname] !== false;
      const nextCollapsed = !currentlyCollapsed;
      state.hiddenHostMutedAlertsCollapsed[hostname] = nextCollapsed;

      const body = hostList.querySelector(`[data-muted-body-enc='${hostnameEnc}']`);
      if (body) {
        body.classList.toggle("hidden", nextCollapsed);
      }
      button.textContent = hiddenHostMutedAlertsToggleLabel(nextCollapsed);
      button.setAttribute("aria-expanded", nextCollapsed ? "false" : "true");
    });
  }

  for (const button of hostList.querySelectorAll("[data-action='unmute-alert']")) {
    button.addEventListener("click", async (event) => {
      event.preventDefault();
      event.stopPropagation();

      const hostname = decodeURIComponent(button.getAttribute("data-host-enc") || "");
      const mountpoint = decodeURIComponent(button.getAttribute("data-mount-enc") || "");
      if (!hostname || !mountpoint) {
        return;
      }

      try {
        await toggleAlertMute(hostname, mountpoint, true);
      } catch (error) {
        window.alert(`Alert konnte nicht reaktiviert werden: ${error.message}`);
      }
    });
  }
}

function renderHosts(hosts) {
  const hostList = document.getElementById("hostList");
  const hostListHeader = document.getElementById("hostListHeader");
  const hostCount = document.getElementById("hostCount");
  const triggerAllButton = document.getElementById("triggerAllAgentsUpdateButton");

  if (triggerAllButton) {
    triggerAllButton.disabled = state.totalHosts <= 0;
    triggerAllButton.textContent = state.totalHosts > 0
      ? `⟳ Update fuer alle Hosts (${state.totalHosts})`
      : "⟳ Update fuer alle Hosts";
  }

  if (!Array.isArray(hosts) || hosts.length === 0) {
    hostCount.textContent = "0 Hosts gesamt";
    hostListHeader.innerHTML = "";
    hostList.innerHTML = "<p class=\"muted\">Keine Hosts vorhanden.</p>";
    renderHostIconFilters([]);
    return;
  }

  const { visibleHosts, hiddenHosts } = splitHosts(hosts);
  hostCount.textContent = `${state.totalHosts} Hosts gesamt | aktiv ${visibleHosts.length} | ausgeblendet ${hiddenHosts.length}`;

  if (visibleHosts.length === 0 && hiddenHosts.length === 0) {
    hostListHeader.innerHTML = "";
    hostList.innerHTML = "<p class=\"muted\">Keine Hosts passen zum Suchfilter.</p>";
    renderHostIconFilters(hosts);
    return;
  }

  const visibleHtml = visibleHosts.map(renderSingleHostCard).join("");
  const hiddenHtml = hiddenHosts.map(renderSingleHostCard).join("");
  const hiddenCollapsedClass = state.hiddenHostsCollapsed ? "hidden" : "";

  hostListHeader.innerHTML = `<h4 class="host-group-title">Aktive Hosts (${visibleHosts.length})</h4>`;

  hostList.innerHTML = `
    <section class="host-group">
      ${visibleHtml || '<p class="muted">Keine aktiven Hosts im Suchfilter.</p>'}
    </section>
    <section class="host-group host-group-hidden">
      <div class="host-group-title-row">
        <h4 class="host-group-title">Ausgeblendete Hosts (${hiddenHosts.length})</h4>
        <button id="hiddenHostsToggleButton" class="host-group-toggle" type="button" aria-expanded="${state.hiddenHostsCollapsed ? "false" : "true"}">${hiddenHostsToggleLabel(state.hiddenHostsCollapsed)}</button>
      </div>
      <div id="hiddenHostsBody" class="${hiddenCollapsedClass}">
        ${hiddenHtml || '<p class="muted">Keine ausgeblendeten Hosts.</p>'}
      </div>
    </section>
  `;

  renderHostIconFilters(hosts);
  wireHostListInteractions();
}

async function loadHosts(options = {}) {
  const preserveScroll = Boolean(options && options.preserveScroll);
  const hostList = document.getElementById("hostList");
  const hostListHeader = document.getElementById("hostListHeader");
  const previousScrollTop = hostList ? hostList.scrollTop : 0;

  if (!preserveScroll) {
    hostListHeader.innerHTML = "<h4 class=\"host-group-title\">Aktive Hosts</h4>";
  }

  try {
    const url = `/api/v1/hosts?limit=${state.hostLimit}&offset=${state.hostOffset}`;
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error("HTTP " + response.status);
    }

    const data = await response.json();
    state.totalHosts = Number(data.total_hosts || 0);
    const hosts = data.hosts || [];
    state.hosts = hosts;
    renderHostInterestsEditor();
    const { visibleHosts, hiddenHosts } = splitHosts(hosts);
    state.visibleHosts = Number(data.visible_hosts || visibleHosts.length || 0);
    state.hiddenHosts = Number(data.hidden_hosts || hiddenHosts.length || 0);
    const orderedHosts = [...visibleHosts, ...hiddenHosts];
    state.hostFilterNoMatches = hosts.length > 0 && orderedHosts.length === 0 && hasActiveHostFilters();

    if (orderedHosts.length === 0) {
      state.selectedHost = "";
      state.selectedDisplayName = "";
      state.reportOffset = 0;
    } else if (!state.selectedHost) {
      state.selectedHost = String(orderedHosts[0].hostname || "");
      state.selectedDisplayName = String(orderedHosts[0].display_name || orderedHosts[0].hostname || "");
      state.reportOffset = 0;
    }

    const selectedStillVisible = orderedHosts.some((host) => String(host.hostname || "") === state.selectedHost);
    if (!selectedStillVisible && orderedHosts.length > 0) {
      state.selectedHost = String(orderedHosts[0].hostname || "");
      state.selectedDisplayName = String(orderedHosts[0].display_name || orderedHosts[0].hostname || "");
      state.reportOffset = 0;
      renderHosts(hosts);
      if (preserveScroll && hostList) hostList.scrollTop = previousScrollTop;
      updatePagerButtons();
      loadReportsForHost();
      loadAnalysisForHost();
      loadAlertsForHost();
      return;
    }

    const selectedHost = orderedHosts.find((host) => String(host.hostname || "") === state.selectedHost);
    if (selectedHost) {
      state.selectedDisplayName = String(selectedHost.display_name || selectedHost.hostname || "");
    }

    renderHosts(hosts);
    if (preserveScroll && hostList) {
      hostList.scrollTop = previousScrollTop;
    }
    updatePagerButtons();

    // Refresh muted-alert metadata in the background so host cards appear fast.
    if (!state.alertMutesRefreshInFlight) {
      state.alertMutesRefreshInFlight = true;
      loadAlertMutes()
        .then(() => {
          const currentScrollTop = hostList ? hostList.scrollTop : 0;
          renderHosts(state.hosts || []);
          if (hostList) {
            hostList.scrollTop = currentScrollTop;
          }
        })
        .finally(() => {
          state.alertMutesRefreshInFlight = false;
        });
    }
  } catch (error) {
    hostList.innerHTML = `<p class=\"muted\">Fehler: ${escapeHtml(error.message)}</p>`;
  }
}

async function loadReportsForHost(options = {}) {
  const jumpToUtc = typeof options?.jumpToUtc === "string" ? options.jumpToUtc.trim() : "";
  const list = document.getElementById("reportList");
  const count = document.getElementById("reportCount");
  const selectedHostTitle = document.getElementById("selectedHostTitle");
  const reportJumpDateInput = document.getElementById("reportJumpDateTimeInput");
  const reportJumpBounds = document.getElementById("reportJumpBounds");

  if (!state.selectedHost) {
    state.currentReport = null;
    selectedHostTitle.textContent = "🗂️ Meldungen";
    count.textContent = "";
    if (reportJumpDateInput) {
      reportJumpDateInput.value = "";
      reportJumpDateInput.removeAttribute("min");
      reportJumpDateInput.removeAttribute("max");
    }
    if (reportJumpBounds) {
      reportJumpBounds.textContent = "";
    }
    list.innerHTML = state.hostFilterNoMatches
      ? "<p class=\"muted\">Keine Daten zum Suchfilter vorhanden.</p>"
      : "<p class=\"muted\">Kein Host ausgewaehlt.</p>";
    updatePagerButtons();
    return;
  }

  const selectedLabel = state.selectedDisplayName || state.selectedHost;
  selectedHostTitle.textContent = `🗂️ ${selectedLabel}`;
  list.innerHTML = "<p class=\"muted\">Lade Daten...</p>";
  count.textContent = "";

  try {
    const hostNameParam = encodeURIComponent(state.selectedHost);
    const jumpParam = jumpToUtc ? `&jump_to_utc=${encodeURIComponent(jumpToUtc)}` : "";
    const url = `/api/v1/host-reports?hostname=${hostNameParam}&limit=${state.reportLimit}&offset=${state.reportOffset}${jumpParam}`;
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error("HTTP " + response.status);
    }

    const data = await response.json();
    const oldestReportAtUtc = asText(data.oldest_report_at_utc, "");
    const newestReportAtUtc = asText(data.newest_report_at_utc, "");
    if (reportJumpDateInput) {
      const minDateTime = toLocalDateTimeInputValue(oldestReportAtUtc);
      const maxDateTime = toLocalDateTimeInputValue(newestReportAtUtc);
      if (minDateTime) {
        reportJumpDateInput.min = minDateTime;
      } else {
        reportJumpDateInput.removeAttribute("min");
      }
      if (maxDateTime) {
        reportJumpDateInput.max = maxDateTime;
      } else {
        reportJumpDateInput.removeAttribute("max");
      }
      if (!reportJumpDateInput.value && maxDateTime) {
        reportJumpDateInput.value = maxDateTime;
      }
    }
    if (reportJumpBounds) {
      reportJumpBounds.textContent = oldestReportAtUtc
        ? `Erste Nachricht: ${formatUtcPlus2(oldestReportAtUtc)}`
        : "";
    }
    if (Number.isFinite(Number(data.offset))) {
      state.reportOffset = Math.max(0, Number(data.offset));
    }
    state.totalReports = Number(data.total_reports || 0);
    const reports = data.reports || [];

    if (reports.length === 0) {
      state.currentReport = null;
      list.innerHTML = "<p class=\"muted\">Noch keine Daten vorhanden.</p>";
      count.textContent = `0 von ${state.totalReports} Meldungen`;
      if (reportJumpDateInput) {
        reportJumpDateInput.value = "";
      }
      updatePagerButtons();
      return;
    }

    const shownIndex = state.reportOffset + 1;
    count.textContent = `Meldung ${shownIndex} von ${state.totalReports}`;
    state.selectedDisplayName = String(reports[0].display_name || reports[0].hostname || state.selectedHost);
    selectedHostTitle.textContent = `🗂️ ${state.selectedDisplayName}`;
    state.currentReport = reports[0];
    list.innerHTML = renderReportCard(state.currentReport);
    updatePagerButtons();
  } catch (error) {
    state.currentReport = null;
    list.innerHTML = `<p class=\"muted\">Fehler: ${escapeHtml(error.message)}</p>`;
  }
}

async function jumpToReportDateTime() {
  if (!state.selectedHost) {
    return;
  }
  const input = document.getElementById("reportJumpDateTimeInput");
  if (!input) {
    return;
  }
  const raw = String(input.value || "").trim();
  if (!raw) {
    window.alert("Bitte Datum/Uhrzeit waehlen.");
    return;
  }
  const parsed = new Date(raw);
  if (Number.isNaN(parsed.getTime())) {
    window.alert("Ungueltiges Datum/Uhrzeit.");
    return;
  }

  await loadReportsForHost({ jumpToUtc: parsed.toISOString() });
  await loadAnalysisForHost();
  await loadAlertsForHost();
}

async function jumpToLatestReport() {
  if (!state.selectedHost) {
    return;
  }
  state.reportOffset = 0;
  await loadReportsForHost();
  await loadAnalysisForHost();
  await loadAlertsForHost();
}

function renderCurrentReportInView() {
  const list = document.getElementById("reportList");
  if (!state.currentReport) {
    return;
  }
  list.innerHTML = renderReportCard(state.currentReport);
}

async function editDisplayName() {
  if (!state.selectedHost) {
    return;
  }

  const nextValue = window.prompt(
    `Sprechenden Titel fuer ${state.selectedHost} setzen. Leer lassen entfernt den Override.`,
    state.selectedDisplayName || state.selectedHost,
  );

  if (nextValue === null) {
    return;
  }

  const currentHost = Array.isArray(state.hosts)
    ? state.hosts.find((item) => asText(item.hostname, "") === state.selectedHost)
    : null;
  const currentCountryCode = currentHost ? asText(currentHost.country_code || "", "") : "";
  const nextCountryCodeRaw = window.prompt(
    `2-stelliges Laenderkuerzel fuer ${state.selectedHost} (z.B. CH, DE). Leer entfernt den Override.`,
    currentCountryCode,
  );
  if (nextCountryCodeRaw === null) {
    return;
  }
  const nextCountryCode = nextCountryCodeRaw.trim().toUpperCase();
  if (nextCountryCode && !/^[A-Z]{2}$/.test(nextCountryCode)) {
    throw new Error("Laenderkuerzel muss genau 2 Buchstaben haben (z.B. CH).");
  }

  await saveHostSettings(state.selectedHost, {
    display_name_override: nextValue.trim(),
    country_code_override: nextCountryCode,
  });

  await loadHosts();
  await loadReportsForHost();
}

async function loadAnalysisForHost() {
  const analysisSummary = document.getElementById("analysisSummary");
  const analysisRows = document.getElementById("analysisRows");
  const resourceCharts = document.getElementById("resourceCharts");
  const filesystemStats = document.getElementById("filesystemStats");
  const filesystemCharts = document.getElementById("filesystemCharts");
  const resourceTrendCards = document.getElementById("resourceTrendCards");
  const deliveryStats = document.getElementById("deliveryStats");
  const largeFilesPanel = document.getElementById("largeFilesPanel");
  const largeFilesBody = document.getElementById("largeFilesBody");

  if (!state.selectedHost) {
    state.fsVisibilityEditable = false;
    state.fsFocusHiddenMountpoints = [];
    state.largeFilesHiddenMountpoints = [];
    state.fsFocusAvailableMountpoints = [];
    state.largeFilesAvailableMountpoints = [];
    updateFilesystemVisibilityButtons();
    analysisSummary.textContent = "";
    state.analysisLatestDeliveryLabel = "LIVE";
    state.deliveryCountsLoading = false;
    deliveryStats.textContent = "";
    resourceCharts.innerHTML = "";
    filesystemStats.textContent = "";
    filesystemCharts.innerHTML = "";
    resourceTrendCards.innerHTML = "";
    if (largeFilesPanel) largeFilesPanel.classList.add("hidden");
    if (largeFilesBody) largeFilesBody.innerHTML = "";
    analysisRows.innerHTML = state.hostFilterNoMatches
      ? "<tr><td colspan=\"7\" class=\"muted\">Keine Daten zum Suchfilter vorhanden.</td></tr>"
      : "<tr><td colspan=\"7\"><div class=\"empty-state\"><span>🖥️</span><p>Wähle einen Host in der linken Spalte.</p></div></td></tr>";
    filesystemCharts.innerHTML = state.hostFilterNoMatches
      ? "<p class=\"muted\">Keine Daten zum Suchfilter vorhanden.</p>"
      : "<div class=\"empty-state\"><span>💾</span><p>Wähle einen Host, um Filesystem-Trends zu sehen.</p></div>";
    return;
  }

  analysisRows.innerHTML = "<tr><td colspan=\"7\" class=\"muted\">Lade Analyse...</td></tr>";
  resourceCharts.innerHTML = "";
  filesystemCharts.innerHTML = "";
  resourceTrendCards.innerHTML = "";
  if (largeFilesPanel) largeFilesPanel.classList.add("hidden");
  if (largeFilesBody) largeFilesBody.innerHTML = "";
  analysisSummary.textContent = "";
  state.deliveryCountsLoading = false;
  deliveryStats.textContent = "";
  filesystemStats.textContent = "";
  updateFilesystemVisibilityButtons();

  try {
    const hostNameParam = encodeURIComponent(state.selectedHost);
    const url = `/api/v1/analysis?hostname=${hostNameParam}&hours=${state.analysisHours}`;
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error("HTTP " + response.status);
    }

    const data = await response.json();
    const trendRows = Array.isArray(data.filesystem_trends) ? data.filesystem_trends : [];
    const visibility = data.filesystem_visibility || {};
    state.fsVisibilityEditable = visibility.editable !== false;
    state.fsFocusHiddenMountpoints = uniqueSortedMountpoints(visibility.fs_focus_hidden || []);
    state.largeFilesHiddenMountpoints = uniqueSortedMountpoints(visibility.large_files_hidden || []);
    state.fsFocusAvailableMountpoints = uniqueSortedMountpoints(trendRows.map((item) => normalizeMountpointValue(item?.mountpoint)));
    state.largeFilesAvailableMountpoints = collectLargeFilesMountpoints(data.large_files || {});
    updateFilesystemVisibilityButtons();

    const visibleTrendRows = filterFilesystemTrendsByVisibility(trendRows, state.fsFocusHiddenMountpoints);
    const sortedTrendRows = sortFilesystemByMountpointAscending(visibleTrendRows);
    const resourceTrends = data.resource_trends || {};
    const resourceSeries = data.resource_series || {};
    const delivery = data.delivery || {};
    const latestMax = formatPercent(data.latest_max_used_percent);
    const reportCount = Number(data.report_count || 0).toLocaleString("de-DE");
    const latestDelivery = deliveryLabel(delivery.latest_mode, delivery.latest_is_delayed);
    const latestDeliveryLabel = latestDelivery === "DELAYED" ? "Verzögert" : "LIVE";

    analysisSummary.textContent = `${reportCount} Reports, hoechste aktuelle FS-Auslastung: ${latestMax}`;
    state.analysisLatestDeliveryLabel = latestDeliveryLabel;
    renderDeliveryStatsBar();
    resourceCharts.innerHTML = renderResourceCharts(resourceSeries, data.latest_report_time_utc);
    resourceTrendCards.innerHTML = renderResourceTrendCards(resourceTrends, data.latest_report_time_utc, data.latest_swap_total_kb);
    filesystemCharts.innerHTML = renderFilesystemTrendCharts(sortedTrendRows, data.latest_report_time_utc);
    renderLargeFilesPanel(data.large_files || {}, state.largeFilesHiddenMountpoints);

    const fsCurrentValues = sortedTrendRows.map((row) => Number(row.current_used_percent)).filter((value) => Number.isFinite(value));
    const fsAvgCurrent = fsCurrentValues.length > 0
      ? fsCurrentValues.reduce((sum, value) => sum + value, 0) / fsCurrentValues.length
      : null;
    const fsRising = sortedTrendRows.filter((row) => Number(row.delta_used_percent) > 0).length;
    const fsWarnOrCritical = sortedTrendRows.filter((row) => Number(row.current_used_percent) >= 80).length;
    filesystemStats.textContent = `${sortedTrendRows.length} FS-Charts | Avg aktuell: ${fsAvgCurrent === null ? "-" : formatNumber(fsAvgCurrent, 1) + "%"} | Steigend: ${fsRising} | >=80%: ${fsWarnOrCritical}`;

    const fsTabBtn = document.getElementById("overviewFilesystemTabButton");
    if (fsTabBtn) {
      fsTabBtn.textContent = fsWarnOrCritical > 0
        ? `💾 Filesystem Fokus ⚠ ${fsWarnOrCritical}`
        : "💾 Filesystem Fokus";
    }

    filesystemCharts.querySelectorAll(".fs-chart-card").forEach((card, idx) => {
      card.style.cursor = "zoom-in";
      card.addEventListener("click", () => {
        const item = sortedTrendRows[idx];
        if (item) openChartDrillModal(item, data.latest_report_time_utc);
      });
    });

    if (sortedTrendRows.length === 0) {
      filesystemCharts.innerHTML = "<p class=\"muted\">Keine Filesystem-Verlaufskurven verfuegbar.</p>";
      analysisRows.innerHTML =
        "<tr><td colspan=\"7\" class=\"muted\">Keine Analyse-Daten im gewaehlten Zeitfenster.</td></tr>";
      return;
    }

    analysisRows.innerHTML = sortedTrendRows
      .map((row) => {
        const deltaClass = Number(row.delta_used_percent) > 0 ? "delta-up" : "delta-down";
        return `
          <tr>
            <td>${renderPathCell(row.mountpoint, 64)}</td>
            <td>${Number(row.sample_count || 0).toLocaleString("de-DE")}</td>
            <td>${formatPercent(row.current_used_percent)}</td>
            <td>${formatPercent(row.min_used_percent)}</td>
            <td>${formatPercent(row.max_used_percent)}</td>
            <td>${formatPercent(row.avg_used_percent)}</td>
            <td class="${deltaClass}">${formatSignedPercent(row.delta_used_percent)}</td>
          </tr>
        `;
      })
      .join("");
  } catch (error) {
    analysisRows.innerHTML = `<tr><td colspan=\"7\" class=\"muted\">Fehler: ${escapeHtml(error.message)}</td></tr>`;
  }
}

async function toggleAlertMute(hostname, mountpoint, currentlyMuted) {
  const endpoint = currentlyMuted ? "/api/v1/alert-unmute" : "/api/v1/alert-mute";
  await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ hostname, mountpoint }),
  });
  await loadAlertsForHost();
  await loadGlobalAlertsOverview();
  await loadHosts();
}

let _ackModalResolve = null;

function openAckModal(hostname, mountpoint, currentNote, isAcknowledged) {
  return new Promise((resolve) => {
    _ackModalResolve = resolve;
    const modal = document.getElementById("ackModal");
    const titleEl = document.getElementById("ackModalTitle");
    const subtitleEl = document.getElementById("ackModalSubtitle");
    const noteInput = document.getElementById("ackModalNoteInput");
    const confirmBtn = document.getElementById("ackModalConfirmBtn");
    const unackBtn = document.getElementById("ackModalUnackBtn");
    const statusEl = document.getElementById("ackModalStatus");
    if (!modal) { resolve(null); return; }
    titleEl.textContent = isAcknowledged ? "Quittierung bearbeiten" : "Alert quittieren";
    subtitleEl.textContent = `${hostname} – ${mountpoint}`;
    noteInput.value = String(currentNote || "");
    statusEl.textContent = "";
    confirmBtn.textContent = isAcknowledged ? "Aktualisieren" : "Quittieren";
    unackBtn.classList.toggle("hidden", !isAcknowledged);
    modal.classList.remove("hidden");
    noteInput.focus();
  });
}

function closeAckModal(result) {
  const modal = document.getElementById("ackModal");
  if (modal) modal.classList.add("hidden");
  if (_ackModalResolve) {
    _ackModalResolve(result !== undefined ? result : null);
    _ackModalResolve = null;
  }
}

async function acknowledgeAlert(hostname, mountpoint, currentNote = "", isAcknowledged = false) {
  const result = await openAckModal(hostname, mountpoint, currentNote, isAcknowledged);
  if (!result) return;

  const statusEl = document.getElementById("ackModalStatus");
  if (statusEl) statusEl.textContent = "Wird gespeichert…";

  try {
    if (result.unack) {
      const response = await fetch("/api/v1/alert-unack", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ hostname, mountpoint }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || ("HTTP " + response.status));
    } else {
      const response = await fetch("/api/v1/alert-ack", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          hostname,
          mountpoint,
          ack_note: String(result.note || "").trim(),
        }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || ("HTTP " + response.status));
    }
  } catch (err) {
    if (statusEl) statusEl.textContent = `Fehler: ${err.message}`;
    return;
  }

  closeAckModal(null);
  await loadAlertsForHost();
  await loadGlobalAlertsOverview();
  await loadHosts();
}

async function closeAlert(hostname, mountpoint, isClosed) {
  try {
    const url = isClosed ? "/api/v1/alert-unclose" : "/api/v1/alert-close";
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hostname, mountpoint }),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || ("HTTP " + response.status));
  } catch (err) {
    alert(`Fehler: ${err.message}`);
    return;
  }
  await loadAlertsForHost();
  await loadGlobalAlertsOverview();
  await loadHosts();
}

async function loadAlertsForHost() {
  const alertsSummary = document.getElementById("alertsSummary");
  const alertsRows = document.getElementById("alertsRows");
  const toggleButton = document.getElementById("toggleHostAlertsPanelButton");
  const panelBody = document.getElementById("hostAlertsPanelBody");

  panelBody.classList.toggle("hidden", state.hostAlertsCollapsed);
  toggleButton.textContent = state.hostAlertsCollapsed ? "▸" : "▾";

  if (!state.selectedHost) {
    alertsSummary.textContent = "";
    alertsRows.innerHTML = state.hostFilterNoMatches
      ? "<tr><td colspan=\"6\" class=\"muted\">Keine Daten zum Suchfilter vorhanden.</td></tr>"
      : "<tr><td colspan=\"6\"><div class=\"empty-state\"><span>🔕</span><p>Wähle einen Host, um Alerts zu sehen.</p></div></td></tr>";
    return;
  }

  alertsRows.innerHTML = "<tr><td colspan=\"6\" class=\"muted\">Lade Alerts...</td></tr>";
  alertsSummary.textContent = "";

  try {
    const hostNameParam = encodeURIComponent(state.selectedHost);
    const [summaryResp, listResp] = await Promise.all([
      fetch(`/api/v1/alerts-summary?hostname=${hostNameParam}`),
      fetch(`/api/v1/alerts?hostname=${hostNameParam}&status=open&limit=50&offset=0`),
    ]);

    if (!summaryResp.ok) {
      throw new Error("Summary HTTP " + summaryResp.status);
    }
    if (!listResp.ok) {
      throw new Error("List HTTP " + listResp.status);
    }

    const summaryData = await summaryResp.json();
    const listData = await listResp.json();
    const alerts = listData.alerts || [];

    alertsSummary.textContent = `Offen: ${summaryData.open.total} (kritisch ${summaryData.open.critical}, warn ${summaryData.open.warning})`;

    if (alerts.length === 0) {
      alertsRows.innerHTML = "<tr><td colspan=\"6\" class=\"muted\">Keine Alerts vorhanden.</td></tr>";
      return;
    }

    alertsRows.innerHTML = alerts
      .map((item) => {
        const statusClass = item.status === "open" ? "status-open" : "status-resolved";
        const severityClass = item.severity === "critical" ? "severity-critical" : "severity-warning";
        const isMuted = Boolean(item.is_muted);
        const isAcknowledged = Boolean(item.is_acknowledged);
        const isClosed = Boolean(item.is_closed);
        const ackNote = asText(item.ack_note);
        const ackTitle = isAcknowledged
          ? `Quittiert von ${asText(item.ack_by, "-")} am ${formatUtcPlus2(item.ack_at_utc)}${ackNote ? ` | Notiz: ${ackNote}` : ""}`
          : "Alert quittieren";
        const closeTitle = isClosed
          ? `Abgeschlossen von ${asText(item.closed_by, "-")} am ${formatUtcPlus2(item.closed_at_utc)} – klicken zum Wiederöffnen`
          : "Alert abschliessen (stoppt Heads-Up)";
        const muteBtn = `<button class="alert-mute-btn${isMuted ? " muted" : ""}" type="button" data-action="toggle-mute" data-hostname="${escapeHtml(asText(item.hostname))}" data-mountpoint="${escapeHtml(asText(item.mountpoint))}" data-muted="${isMuted ? "1" : "0"}" title="${isMuted ? "Stummschaltung aufheben" : "Alert stummschalten"}">${isMuted ? "🔔" : "🔇"}</button>`;
        const ackBtn = `<button class="alert-ack-btn${isAcknowledged ? " acknowledged" : ""}" type="button" data-action="ack" data-acknowledged="${isAcknowledged ? "1" : "0"}" data-hostname="${escapeHtml(asText(item.hostname))}" data-mountpoint="${escapeHtml(asText(item.mountpoint))}" data-ack-note="${encodeURIComponent(ackNote)}" title="${escapeHtml(ackTitle)}">${isAcknowledged ? "✅" : "✓"}</button>`;
        const closeBtn = `<button class="alert-close-btn${isClosed ? " closed" : ""}" type="button" data-action="close" data-hostname="${escapeHtml(asText(item.hostname))}" data-mountpoint="${escapeHtml(asText(item.mountpoint))}" data-closed="${isClosed ? "1" : "0"}" title="${escapeHtml(closeTitle)}">${isClosed ? "🔓" : "🔒"}</button>`;
        const ackMeta = isAcknowledged
          ? `<div class="count compact">✅ ${escapeHtml(asText(item.ack_by, "-"))} | ${escapeHtml(formatUtcPlus2(item.ack_at_utc))}</div>`
          : "";
        const closeMeta = isClosed
          ? `<div class="count compact alert-closed-meta">🔒 ${escapeHtml(asText(item.closed_by, "-"))} | ${escapeHtml(formatUtcPlus2(item.closed_at_utc))}</div>`
          : "";
        return `
          <tr class="${isMuted ? "alert-row-muted" : ""}${isClosed ? " alert-row-closed" : ""}">
            <td><span class="badge ${statusClass}">${escapeHtml(asText(item.status))}</span></td>
            <td><span class="badge ${severityClass}">${escapeHtml(asText(item.severity))}</span></td>
            <td>${renderAlertMountpointLabel(item.mountpoint, 60)}</td>
            <td>${formatPercent(item.used_percent)}</td>
            <td title="Zuletzt gesehen: ${escapeHtml(formatUtcPlus2(item.last_seen_at_utc))}">${escapeHtml(formatUtcPlus2(item.created_at_utc))}${ackMeta}${closeMeta}</td>
            <td><div class="alert-action-buttons">${muteBtn}${ackBtn}${closeBtn}</div></td>
          </tr>
        `;
      })
      .join("");

    alertsRows.querySelectorAll("[data-action='toggle-mute']").forEach((btn) => {
      btn.addEventListener("click", async (e) => {
        e.stopPropagation();
        const hostname = btn.getAttribute("data-hostname");
        const mountpoint = btn.getAttribute("data-mountpoint");
        const isMuted = btn.getAttribute("data-muted") === "1";
        await toggleAlertMute(hostname, mountpoint, isMuted);
      });
    });
    alertsRows.querySelectorAll("[data-action='ack']").forEach((btn) => {
      btn.addEventListener("click", async (e) => {
        e.stopPropagation();
        const hostname = btn.getAttribute("data-hostname");
        const mountpoint = btn.getAttribute("data-mountpoint");
        const currentNote = decodeURIComponent(btn.getAttribute("data-ack-note") || "");
        const isAlreadyAcknowledged = btn.getAttribute("data-acknowledged") === "1";
        await acknowledgeAlert(hostname, mountpoint, currentNote, isAlreadyAcknowledged);
      });
    });
    alertsRows.querySelectorAll("[data-action='close']").forEach((btn) => {
      btn.addEventListener("click", async (e) => {
        e.stopPropagation();
        const hostname = btn.getAttribute("data-hostname");
        const mountpoint = btn.getAttribute("data-mountpoint");
        const isClosed = btn.getAttribute("data-closed") === "1";
        await closeAlert(hostname, mountpoint, isClosed);
      });
    });
  } catch (error) {
    alertsRows.innerHTML = `<tr><td colspan="6" class="muted">Fehler: ${escapeHtml(error.message)}</td></tr>`;
  }
}

function renderCriticalTrends(data) {
  const { warnings, hours, project_hours: projectHours } = data;
  if (!warnings || warnings.length === 0) {
    return `<div class="ct-empty"><span class="ct-empty-icon">✓</span><p>Keine kritischen Trends im Zeitraum der letzten ${hours} Std. erkannt (Projektion: ${projectHours} Std.).</p></div>`;
  }

  // Filter by selected metrics
  const filteredWarnings = warnings.filter((w) => state.criticalTrendsMetrics.includes(w.type));
  if (filteredWarnings.length === 0) {
    return `<div class="ct-empty"><span class="ct-empty-icon">✓</span><p>Keine Trends für die ausgewählten Metriken im Zeitraum der letzten ${hours} Std. erkannt.</p></div>`;
  }

  // Group by hostname
  const byHost = new Map();
  for (const w of filteredWarnings) {
    if (!byHost.has(w.hostname)) byHost.set(w.hostname, []);
    byHost.get(w.hostname).push(w);
  }

  const critCount = filteredWarnings.filter((w) => w.level === "crit").length;
  const warnCount = filteredWarnings.filter((w) => w.level === "warn").length;

  const dataEndTimeMs = Date.now();
  const projectionTargetIso = new Date(dataEndTimeMs + projectHours * 3600 * 1000).toISOString();
  const projectionTargetFormatted = formatUtcPlus2(projectionTargetIso);

  const summary = `
    <div class="ct-summary">
      <span class="ct-summary-label">Datenbasis: letzte ${hours} Std.</span>
      ${critCount > 0 ? `<span class="ct-badge ct-badge-crit">${critCount} Kritisch</span>` : ""}
      ${warnCount > 0 ? `<span class="ct-badge ct-badge-warn">${warnCount} Warnung</span>` : ""}
      <span class="ct-summary-label">${byHost.size} betroffene Host${byHost.size !== 1 ? "s" : ""}</span>
      <span class="ct-summary-label ct-projection-horizon">📅 Projektion bis: <strong>${escapeHtml(projectionTargetFormatted)}</strong> (+${projectHours} Std.)</span>
    </div>
  `;

  const cards = [...byHost.entries()].map(([hostname, items]) => {
    const hostCrit = items.filter((w) => w.level === "crit").length;
    const hostWarn = items.filter((w) => w.level === "warn").length;
    const hostBadge = hostCrit > 0
      ? `<span class="ct-host-badge ct-badge-crit">Kritisch</span>`
      : `<span class="ct-host-badge ct-badge-warn">Warnung</span>`;
    const displayName = items[0].display_name || hostname;
    const showHostname = displayName !== hostname;

    const rows = items.map((w) => {
      const bar = Math.min(100, Math.max(0, w.projected));
      const barClass = w.level === "crit" ? "ct-bar-crit" : "ct-bar-warn";
      const icon = w.type === "filesystem" ? "💾" : w.type === "cpu" ? "⚙️" : w.type === "memory" ? "🧠" : w.type === "swap" ? "🔃" : "📊";
      const diff = w.current !== null ? w.projected - w.current : 0;
      const trendArrow = diff > 0.05
        ? `<span class="ct-trend-arrow ct-trend-up">🔺</span>`
        : diff < -0.05
          ? `<span class="ct-trend-arrow ct-trend-down">🔻</span>`
          : `<span class="ct-trend-arrow ct-trend-flat">➖</span>`;
      const etaHtml = (w.level === "warn" && w.critical_eta_utc)
        ? `<span class="ct-critical-eta" title="Kritisch (≥${w.critical_threshold != null ? w.critical_threshold.toFixed(0) : "?"}%) voraussichtlich ab diesem Zeitpunkt">🔴 Kritisch ca. ${escapeHtml(formatUtcPlus2Short(w.critical_eta_utc))}</span>`
        : "";
      return `
        <div class="ct-row ct-row-${w.level}">
          <span class="ct-row-icon">${icon}</span>
          <span class="ct-row-metric">${escapeHtml(w.metric)}</span>
          <span class="ct-row-current">Aktuell: <strong>${w.current !== null ? w.current.toFixed(1) + "%" : "–"}</strong></span>
          <span class="ct-row-arrow">·</span>
          <span class="ct-row-projected ct-projected-${w.level}">${trendArrow} Projektion: <strong>${w.projected.toFixed(1)}%</strong></span>
          ${etaHtml}
          <div class="ct-bar-wrap"><div class="ct-bar ${barClass}" style="width:${bar.toFixed(1)}%"></div></div>
        </div>
      `;
    }).join("");

    return `
      <div class="ct-host-card ct-host-card-${hostCrit > 0 ? "crit" : "warn"}">
        <div class="ct-host-header">
          <span class="ct-hostname">${escapeHtml(displayName)}${showHostname ? ` <span class="ct-hostname-sub">(${escapeHtml(hostname)})</span>` : ""}</span>
          ${hostBadge}
          <span class="ct-host-meta">${hostCrit > 0 ? hostCrit + " kritisch" : ""}${hostCrit > 0 && hostWarn > 0 ? ", " : ""}${hostWarn > 0 ? hostWarn + " Warnung" : ""}</span>
        </div>
        <div class="ct-rows">${rows}</div>
      </div>
    `;
  }).join("");

  return summary + cards;
}

async function loadCriticalTrends(options = {}) {
  const updateList = options.updateList !== false;
  const listEl = document.getElementById("criticalTrendsList");
  const tabButton = document.getElementById("criticalTrendsTabButton");
  if (updateList && !listEl) return;

  if (updateList && listEl) {
    listEl.innerHTML = "<p class=\"muted\">Lade Trend-Daten…</p>";
  }
  try {
    const response = await fetch(`/api/v1/critical-trends?hours=${state.criticalTrendsHours}&project_hours=${state.criticalTrendsProjectHours}`, {
      credentials: "same-origin",
    });
    if (!response.ok) throw new Error("HTTP " + response.status);
    const data = await response.json();
    if (updateList && listEl) {
      listEl.innerHTML = renderCriticalTrends(data);
    }

    const critCount = (data.warnings || []).filter((w) => w.level === "crit").length;
    const warnCount = (data.warnings || []).filter((w) => w.level === "warn").length;
    state.criticalTrendsCount = critCount + warnCount;
    updateHeaderStatChips();
    if (tabButton) {
      if (critCount > 0) {
        tabButton.dataset.alertBadge = String(critCount);
        tabButton.classList.add("tab-has-crit");
        tabButton.classList.remove("tab-has-warn");
      } else if (warnCount > 0) {
        tabButton.dataset.alertBadge = String(warnCount);
        tabButton.classList.remove("tab-has-crit");
        tabButton.classList.add("tab-has-warn");
      } else {
        delete tabButton.dataset.alertBadge;
        tabButton.classList.remove("tab-has-crit", "tab-has-warn");
      }
    }
  } catch (error) {
    if (updateList && listEl) {
      listEl.innerHTML = `<p class="muted">Fehler beim Laden: ${escapeHtml(error.message)}</p>`;
    }
  }
}

function renderInactiveHosts(data) {
  const { inactive_hosts, hours } = data;
  if (!inactive_hosts || inactive_hosts.length === 0) {
    return `<div class="ih-empty"><span class="ih-empty-icon">✓</span><p>Alle Hosts sind aktiv. Keine Hosts inaktiv seit ${hours} Stunde${hours !== 1 ? "n" : ""}.</p></div>`;
  }

  const cards = inactive_hosts.map((host) => {
    const displayName = host.display_name || host.hostname;
    const showHostname = displayName !== host.hostname;
    
    // Determine OS icon
    const osFamily = host.os.toLowerCase().includes("windows") ? "windows" : "linux";
    const osIconSrc = `icons/${osFamily}.png`;
    
    // Determine country icon
    const countryCode = (host.country_code || "").toUpperCase();
    const countryIconSrc = /^[A-Z]{2}$/.test(countryCode) ? `icons/${countryCode}.png` : null;
    const countryIconFallback = countryCode.toLowerCase();
    
    const alertsHtml = host.open_alert_count > 0
      ? `<span class="ih-alerts-badge">${host.open_alert_count} Alert${host.open_alert_count !== 1 ? "s" : ""}</span>`
      : "";
    const hoursClass = host.hours_inactive > 12 ? "critical" : "";
    const lastSeenText = formatUtcPlus2(host.last_report_time_utc);

    return `
      <div class="ih-host-card">
        <div class="ih-host-info">
          <div class="ih-host-icons">
            ${countryIconSrc ? `<img src="${countryIconSrc}" class="ih-host-icon" alt="${escapeHtml(host.country_code)}" onerror="if(!this.dataset.fallback1){this.dataset.fallback1='1';this.src='/icons/${countryCode}.png';return;}if(!this.dataset.fallback2){this.dataset.fallback2='1';this.src='/icons/${countryIconFallback}.png';return;}if(!this.dataset.fallback3){this.dataset.fallback3='1';this.src='/icons/${countryIconFallback}.svg';return;}this.style.display='none';" />` : ""}
            <img src="${osIconSrc}" class="ih-host-icon" alt="${escapeHtml(host.os)}" onerror="if(!this.dataset.fallback){this.dataset.fallback='1';this.src='/icons/${osFamily}.png';}" />
          </div>
          <div class="ih-host-details">
            <span class="ih-hostname">${escapeHtml(displayName)}${showHostname ? ` <span class="ih-hostname-sub">(${escapeHtml(host.hostname)})</span>` : ""}</span>
            <div class="ih-meta-row">
              <span class="ih-meta-item">Letzter Kontakt: <span class="ih-last-seen">${escapeHtml(lastSeenText)}</span></span>
              <span class="ih-meta-item"><span class="ih-hours-badge ${hoursClass}">${host.hours_inactive.toFixed(1)}h inaktiv</span></span>
              ${alertsHtml}
            </div>
          </div>
        </div>
      </div>
    `;
  }).join("");

  return cards;
}

async function loadInactiveHosts(options = {}) {
  const updateList = options.updateList !== false;
  const listEl = document.getElementById("inactiveHostsList");
  const tabButton = document.getElementById("inactiveHostsTabButton");
  if (updateList && !listEl) return;

  if (updateList && listEl) {
    listEl.innerHTML = "<p class=\"muted\">Lade Daten…</p>";
  }
  try {
    const response = await fetch(`/api/v1/inactive-hosts?hours=${state.inactiveHostsHours}`, {
      credentials: "same-origin",
    });
    if (!response.ok) throw new Error("HTTP " + response.status);
    const data = await response.json();
    state.inactiveHosts = data.inactive_hosts || [];
    if (updateList && listEl) {
      listEl.innerHTML = renderInactiveHosts(data);
    }

    const total = (data.total || 0);
    state.inactiveHostsCount = total;
    updateHeaderStatChips();
    if (tabButton) {
      if (total > 0) {
        tabButton.dataset.alertBadge = String(total);
        tabButton.classList.add("tab-has-warn");
      } else {
        delete tabButton.dataset.alertBadge;
        tabButton.classList.remove("tab-has-warn");
      }
    }
  } catch (error) {
    if (updateList && listEl) {
      listEl.innerHTML = `<p class="muted">Fehler beim Laden: ${escapeHtml(error.message)}</p>`;
    }
  }
}

function renderBackupStatus(data) {
  const hosts = data.hosts || [];
  if (hosts.length === 0) {
    return "<p class=\"muted\">Keine Hosts mit Backup-Konfiguration gefunden. (DIR_SCAN_DEEP_PATHS oder auto-erkannter HANA-Pfad in agent.conf)</p>";
  }
  return hosts.map((host) => {
    const displayName = asText(host.display_name || host.hostname, "-");
    const hostname = asText(host.hostname, "-");
    const isToday = host.is_today_report !== false;
    const reportTimeUtc = asText(host.report_time_utc, "");
    let reportTimeFmt = "-";
    if (reportTimeUtc) {
      try {
        const d = new Date(reportTimeUtc);
        reportTimeFmt = d.toLocaleString("de-CH", { timeZone: "Europe/Zurich", day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" });
      } catch (_) { reportTimeFmt = reportTimeUtc.slice(0, 16); }
    }
    const staleNote = isToday ? "" : ` <span class="backup-status-stale" title="Kein heutiger Report vorhanden">Stand: ${escapeHtml(reportTimeFmt)}</span>`;
    const hasMissing = host.has_missing_backup;
    const headerClass = hasMissing ? "backup-host-header backup-host-header--missing" : "backup-host-header backup-host-header--ok";

    const dirs = host.dirs || [];
    const currentCount = dirs.filter((d) => d.has_today_backup === true).length;
    const missingCount = Math.max(0, dirs.length - currentCount);
    const detailsOpenAttr = hasMissing ? " open" : "";
    const dirRows = dirs.map((d) => {
      const ok = d.has_today_backup;
      const badgeClass = ok ? "dir-status-badge ok" : "dir-status-badge missing";
      const badgeText = ok ? "✓ Backup aktuell (<24h)" : "✗ kein aktuelles Backup";
      const subdirName = escapeHtml(asText(d.subdir_name || d.subdir_path, "-"));
      const newestRaw = asText(d.newest_item_name, "-");
      const newestSlashIndex = newestRaw.lastIndexOf("/");
      const newestLeaf = newestSlashIndex >= 0 ? newestRaw.slice(newestSlashIndex + 1) : newestRaw;
      const newestParent = newestSlashIndex >= 0 ? newestRaw.slice(0, newestSlashIndex) : "";
      const newestName = escapeHtml(newestLeaf || newestRaw || "-");
      const newestPath = newestParent ? `<div class="backup-status-newest-path" title="${escapeHtml(newestRaw)}">📁 ${escapeHtml(newestParent)}</div>` : "";
      const newestMod = d.newest_item_modified ? formatUtcPlus2Short(d.newest_item_modified) : "-";
      const sizeBytes = d.newest_item_size_bytes || 0;
      const sizeText = sizeBytes > 0 ? formatFileSize(sizeBytes) : "-";
      return `
        <tr>
          <td class="backup-status-dir-name" title="${escapeHtml(asText(d.subdir_path, ""))}">${subdirName}</td>
          <td class="backup-status-newest" title="${escapeHtml(newestRaw)}">${newestPath}<span class="backup-status-newest-name">${newestName}</span></td>
          <td class="backup-status-mod">${escapeHtml(newestMod)}</td>
          <td class="backup-status-size">${escapeHtml(sizeText)}</td>
          <td class="backup-status-badge-cell"><span class="${badgeClass}">${badgeText}</span></td>
        </tr>`;
    }).join("");

    return `
      <details class="backup-host-card backup-host-details"${detailsOpenAttr}>
        <summary class="${headerClass}">
          <span class="backup-host-name">${escapeHtml(displayName)}</span>
          <span class="backup-host-hostname muted">${escapeHtml(hostname)}</span>
          <span class="backup-host-stats">
            <span class="backup-host-count backup-host-count--ok">Aktuelles Backup: ${currentCount}</span>
            <span class="backup-host-count backup-host-count--missing">kein aktuelles Backup: ${missingCount}</span>
          </span>
          ${staleNote}
        </summary>
        <div class="table-wrap backup-host-body">
          <table class="report-subtable backup-status-table">
            <thead><tr>
              <th>Verzeichnis</th>
              <th>Neuester Eintrag</th>
              <th>Geändert (UTC+2)</th>
              <th>Grösse</th>
              <th>Status (&lt;24h)</th>
            </tr></thead>
            <tbody>${dirRows}</tbody>
          </table>
        </div>
      </details>`;
  }).join("");
}

async function loadBackupStatus() {
  const listEl = document.getElementById("backupStatusList");
  const summaryEl = document.getElementById("backupStatusSummary");
  const tabButton = document.getElementById("backupStatusTabButton");
  if (!listEl) return;
  listEl.innerHTML = "<p class=\"muted\">Lade Daten…</p>";
  try {
    const response = await fetch("/api/v1/backup-status-overview", { credentials: "same-origin" });
    if (!response.ok) throw new Error("HTTP " + response.status);
    const data = await response.json();
    listEl.innerHTML = renderBackupStatus(data);
    const missing = data.missing_count || 0;
    const total = data.total || 0;
    if (summaryEl) {
      summaryEl.textContent = missing > 0
        ? `${missing} von ${total} Host(s) ohne aktuelles Backup (<24h)`
        : `${total} Host(s) — alle Backups aktuell (<24h)`;
    }
    if (tabButton) {
      if (missing > 0) {
        tabButton.dataset.alertBadge = String(missing);
        tabButton.classList.add("tab-has-warn");
      } else {
        delete tabButton.dataset.alertBadge;
        tabButton.classList.remove("tab-has-warn");
      }
    }
  } catch (error) {
    listEl.innerHTML = `<p class="muted">Fehler beim Laden: ${escapeHtml(error.message)}</p>`;
  }
}

function updateHeaderStatChips() {
  const alertChip = document.getElementById("headerAlertChip");
  const alertCount = document.getElementById("headerAlertCount");
  const trendsChip = document.getElementById("headerTrendsChip");
  const trendsCount = document.getElementById("headerTrendsCount");
  const inactiveChip = document.getElementById("headerInactiveChip");
  const inactiveCount = document.getElementById("headerInactiveCount");
  if (alertChip && alertCount) {
    alertCount.textContent = String(state.globalOpenAlertsCount);
    alertChip.classList.toggle("hidden", state.globalOpenAlertsCount === 0);
  }
  if (trendsChip && trendsCount) {
    trendsCount.textContent = String(state.criticalTrendsCount);
    trendsChip.classList.toggle("hidden", state.criticalTrendsCount === 0);
  }
  if (inactiveChip && inactiveCount) {
    inactiveCount.textContent = String(state.inactiveHostsCount);
    inactiveChip.classList.toggle("hidden", state.inactiveHostsCount === 0);
  }
}

async function loadGlobalAlertsOverview(options = {}) {
  const updateList = options.updateList !== false;
  const append = options.append === true;
  const summaryEl = document.getElementById("globalAlertsSummary");
  const rowsEl = document.getElementById("globalAlertsRows");
  const globalAlertsTabButton = document.getElementById("globalAlertsTabButton");
  const toggleButton = document.getElementById("toggleGlobalAlertsPanelButton");
  const panelBody = document.getElementById("globalAlertsPanelBody");
  const loadMoreButton = document.getElementById("globalAlertsLoadMoreButton");
  const pagingStatus = document.getElementById("globalAlertsPagingStatus");
  const requestOffset = append ? state.globalAlertsOffset : 0;
  const requestLimit = Math.max(20, Number(state.globalAlertsPageSize || 100));
  const severityQuery = state.globalSeverityFilter && state.globalSeverityFilter !== "all"
    ? `&severity=${encodeURIComponent(state.globalSeverityFilter)}`
    : "";
  const acknowledgedQuery = state.globalShowAcknowledged ? "" : "&acknowledged=no";
  const closedQuery = state.globalShowClosed ? "" : "&closed=no";

  if (updateList && rowsEl && !append) {
    rowsEl.innerHTML = "<tr><td colspan=\"6\" class=\"muted\">Lade globale Alerts...</td></tr>";
  }
  if (updateList && summaryEl && !append) {
    summaryEl.textContent = "";
  }
  if (!append) {
    state.globalAlertsOffset = 0;
    state.globalAlertsTotal = 0;
  }
  if (panelBody && toggleButton) {
    panelBody.classList.toggle("hidden", state.globalAlertsCollapsed);
    toggleButton.textContent = state.globalAlertsCollapsed ? "▸" : "▾";
  }

  try {
    const summaryResp = await fetch("/api/v1/alerts-summary", {
      credentials: "same-origin",
      cache: "no-store",
    });
    if (!summaryResp.ok) throw new Error("Summary HTTP " + summaryResp.status);
    const summaryData = await summaryResp.json();

    // Header and tab counters are always based on ALL open alerts.
    state.globalOpenAlertsCount = Number(summaryData?.open?.total || 0);

    globalAlertsTabButton.textContent = state.globalOpenAlertsCount > 0
      ? `Globale Alerts (${state.globalOpenAlertsCount})`
      : "Globale Alerts";
    globalAlertsTabButton.classList.toggle("alert-active", state.globalOpenAlertsCount > 0);
    updateHeaderStatChips();

    if (!updateList || !rowsEl || !summaryEl) {
      return;
    }

    const listResp = await fetch(`/api/v1/alerts?status=open&limit=${requestLimit}&offset=${requestOffset}${severityQuery}${acknowledgedQuery}${closedQuery}`, {
      credentials: "same-origin",
      cache: "no-store",
    });
    if (!listResp.ok) throw new Error("List HTTP " + listResp.status);

    const listData = await listResp.json();
    const alerts = listData.alerts || [];
    const totalForFilter = Number(listData.total || 0);
    state.globalAlertsTotal = totalForFilter;

    summaryEl.textContent = `Offen: ${summaryData.open.total} (kritisch ${summaryData.open.critical}, warn ${summaryData.open.warning}) | Filter: ${state.globalSeverityFilter === "all" ? "alle" : state.globalSeverityFilter}`;

    if (!append && alerts.length === 0) {
      rowsEl.innerHTML = "<tr><td colspan=\"6\" class=\"muted\">Keine offenen Alerts fuer den gesetzten Filter.</td></tr>";
      if (loadMoreButton) loadMoreButton.classList.add("hidden");
      if (pagingStatus) pagingStatus.textContent = "0 / 0";
      return;
    }

    const rowsHtml = alerts
      .map((item) => {
        const severityClass = item.severity === "critical" ? "severity-critical" : "severity-warning";
        const hostDisplayName = asText(item.display_name || item.hostname);
        const hostName = asText(item.hostname);
        const isMuted = Boolean(item.is_muted);
        const isAcknowledged = Boolean(item.is_acknowledged);
        const isClosed = Boolean(item.is_closed);
        const ackNote = asText(item.ack_note);
        const ackTitle = isAcknowledged
          ? `Quittiert von ${asText(item.ack_by, "-")} am ${formatUtcPlus2(item.ack_at_utc)}${ackNote ? ` | Notiz: ${ackNote}` : ""}`
          : "Alert quittieren";
        const closeTitle = isClosed
          ? `Abgeschlossen von ${asText(item.closed_by, "-")} am ${formatUtcPlus2(item.closed_at_utc)} – klicken zum Wiederöffnen`
          : "Alert abschliessen (stoppt Heads-Up)";
        const muteBtn = `<button class="alert-mute-btn${isMuted ? " muted" : ""}" type="button" data-action="toggle-mute" data-hostname="${escapeHtml(hostName)}" data-mountpoint="${escapeHtml(asText(item.mountpoint))}" data-muted="${isMuted ? "1" : "0"}" title="${isMuted ? "Stummschaltung aufheben" : "Alert stummschalten"}">${isMuted ? "🔔" : "🔇"}</button>`;
        const ackBtn = `<button class="alert-ack-btn${isAcknowledged ? " acknowledged" : ""}" type="button" data-action="ack" data-acknowledged="${isAcknowledged ? "1" : "0"}" data-hostname="${escapeHtml(hostName)}" data-mountpoint="${escapeHtml(asText(item.mountpoint))}" data-ack-note="${encodeURIComponent(ackNote)}" title="${escapeHtml(ackTitle)}">${isAcknowledged ? "✅" : "✓"}</button>`;
        const closeBtn = `<button class="alert-close-btn${isClosed ? " closed" : ""}" type="button" data-action="close" data-hostname="${escapeHtml(hostName)}" data-mountpoint="${escapeHtml(asText(item.mountpoint))}" data-closed="${isClosed ? "1" : "0"}" title="${escapeHtml(closeTitle)}">${isClosed ? "🔓" : "🔒"}</button>`;
        const ackMeta = isAcknowledged
          ? `<div class="count compact">✅ ${escapeHtml(asText(item.ack_by, "-"))} | ${escapeHtml(formatUtcPlus2(item.ack_at_utc))}</div>`
          : "";
        const closeMeta = isClosed
          ? `<div class="count compact alert-closed-meta">🔒 ${escapeHtml(asText(item.closed_by, "-"))} | ${escapeHtml(formatUtcPlus2(item.closed_at_utc))}</div>`
          : "";
        return `
          <tr class="${isMuted ? "alert-row-muted" : ""}${isClosed ? " alert-row-closed" : ""}">
            <td>
              <div class="global-host-cell">
                <span class="global-host-label">${escapeHtml(hostDisplayName)}</span>
                <span class="global-hostname-sub">(${escapeHtml(hostName)})</span>
                <span class="global-hostname-sub alert-id-sub">#${item.id}</span>
              </div>
            </td>
            <td><span class="badge ${severityClass}">${escapeHtml(asText(item.severity))}</span></td>
            <td>${renderAlertMountpointLabel(item.mountpoint, 56)}</td>
            <td>${formatPercent(item.used_percent)}</td>
            <td title="Zuletzt gesehen: ${escapeHtml(formatUtcPlus2(item.last_seen_at_utc))}">${escapeHtml(formatUtcPlus2(item.created_at_utc))}${ackMeta}${closeMeta}</td>
            <td><div class="alert-action-buttons">${muteBtn}${ackBtn}${closeBtn}</div></td>
          </tr>
        `;
      })
      .join("");

    if (append && requestOffset > 0) {
      rowsEl.insertAdjacentHTML("beforeend", rowsHtml);
    } else {
      rowsEl.innerHTML = rowsHtml;
    }

    state.globalAlertsOffset = requestOffset + alerts.length;
    const shownCount = state.globalAlertsOffset;
    const hasMore = shownCount < totalForFilter;
    if (loadMoreButton) {
      loadMoreButton.classList.toggle("hidden", !hasMore);
      loadMoreButton.disabled = !hasMore;
    }
    if (pagingStatus) {
      pagingStatus.textContent = `${Math.min(shownCount, totalForFilter)} / ${totalForFilter}`;
    }

    rowsEl.querySelectorAll("[data-action='toggle-mute']").forEach((btn) => {
      btn.addEventListener("click", async (e) => {
        e.stopPropagation();
        const hostname = btn.getAttribute("data-hostname");
        const mountpoint = btn.getAttribute("data-mountpoint");
        const isMuted = btn.getAttribute("data-muted") === "1";
        await toggleAlertMute(hostname, mountpoint, isMuted);
      });
    });
    rowsEl.querySelectorAll("[data-action='ack']").forEach((btn) => {
      btn.addEventListener("click", async (e) => {
        e.stopPropagation();
        const hostname = btn.getAttribute("data-hostname");
        const mountpoint = btn.getAttribute("data-mountpoint");
        const currentNote = decodeURIComponent(btn.getAttribute("data-ack-note") || "");
        const isAlreadyAcknowledged = btn.getAttribute("data-acknowledged") === "1";
        await acknowledgeAlert(hostname, mountpoint, currentNote, isAlreadyAcknowledged);
      });
    });
    rowsEl.querySelectorAll("[data-action='close']").forEach((btn) => {
      btn.addEventListener("click", async (e) => {
        e.stopPropagation();
        const hostname = btn.getAttribute("data-hostname");
        const mountpoint = btn.getAttribute("data-mountpoint");
        const isClosed = btn.getAttribute("data-closed") === "1";
        await closeAlert(hostname, mountpoint, isClosed);
      });
    });
  } catch (error) {
    rowsEl.innerHTML = `<tr><td colspan="6" class="muted">Fehler: ${escapeHtml(error.message)}</td></tr>`;
    globalAlertsTabButton.textContent = "Globale Alerts";
    globalAlertsTabButton.classList.remove("alert-active");
    if (updateList && rowsEl) {
      rowsEl.innerHTML = `<tr><td colspan="6" class="muted">Fehler beim Laden: ${escapeHtml(error.message)}</td></tr>`;
    }
  }
}

function wireEvents() {
  const themeToggleButton = document.getElementById("themeToggleButton");
  if (themeToggleButton) {
    themeToggleButton.addEventListener("click", () => {
      toggleTheme();
    });
  }


  const arSelect = document.getElementById("autoRefreshIntervalSelect");
  if (arSelect) {
    arSelect.addEventListener("change", () => {
      autoRefreshCurrentIntervalSec = Number.parseInt(arSelect.value, 10) || 0;
      persistAutoRefreshPreference(autoRefreshCurrentIntervalSec);
      if (autoRefreshCurrentIntervalSec <= 0) {
        stopAutoRefreshTimer();
        renderAutoRefreshStatus();
      } else {
        startAutoRefreshTimer();
        if (autoRefreshLastRefreshAt) startAutoRefreshCountdown();
      }
    });
  }

  const chartDrillCloseBtn = document.getElementById("chartDrillCloseBtn");
  if (chartDrillCloseBtn) {
    chartDrillCloseBtn.addEventListener("click", () => {
      document.getElementById("chartDrillModal").classList.add("hidden");
    });
  }
  const chartDrillBackdrop = document.querySelector(".chart-drill-backdrop");
  if (chartDrillBackdrop) {
    chartDrillBackdrop.addEventListener("click", () => {
      document.getElementById("chartDrillModal").classList.add("hidden");
    });
  }

  const aiModalCloseBtn = document.getElementById("aiTroubleshootCloseBtn");
  if (aiModalCloseBtn) {
    aiModalCloseBtn.addEventListener("click", () => {
      closeAiTroubleshootModal();
    });
  }
  const aiModalBackdrop = document.getElementById("aiTroubleshootBackdrop");
  if (aiModalBackdrop) {
    aiModalBackdrop.addEventListener("click", () => {
      closeAiTroubleshootModal();
    });
  }

  const resourceTrendCards = document.getElementById("resourceTrendCards");
  if (resourceTrendCards) {
    resourceTrendCards.addEventListener("click", async (event) => {
      const button = event.target instanceof Element ? event.target.closest(".trend-ai-btn") : null;
      if (!button) {
        return;
      }
      event.preventDefault();
      event.stopPropagation();
      const metricKey = String(button.getAttribute("data-ai-metric") || "").trim();
      const metricLabel = String(button.getAttribute("data-ai-label") || metricKey || "Metrik");
      if (!metricKey) {
        return;
      }
      await openAiTroubleshootModal(metricKey, metricLabel);
    });
  }

  const filesystemAiTroubleshootButton = document.getElementById("filesystemAiTroubleshootButton");
  if (filesystemAiTroubleshootButton) {
    filesystemAiTroubleshootButton.addEventListener("click", async () => {
      await openAiTroubleshootModal("filesystem", "Filesystem (alle Mountpoints)");
    });
  }

  const filesystemVisibilityBackdrop = document.getElementById("filesystemVisibilityBackdrop");
  if (filesystemVisibilityBackdrop) {
    filesystemVisibilityBackdrop.addEventListener("click", () => {
      closeFilesystemVisibilityModal();
    });
  }
  const filesystemVisibilityCloseButton = document.getElementById("filesystemVisibilityCloseButton");
  if (filesystemVisibilityCloseButton) {
    filesystemVisibilityCloseButton.addEventListener("click", () => {
      closeFilesystemVisibilityModal();
    });
  }
  const filesystemVisibilityCancelButton = document.getElementById("filesystemVisibilityCancelButton");
  if (filesystemVisibilityCancelButton) {
    filesystemVisibilityCancelButton.addEventListener("click", () => {
      closeFilesystemVisibilityModal();
    });
  }
  const filesystemVisibilitySaveButton = document.getElementById("filesystemVisibilitySaveButton");
  if (filesystemVisibilitySaveButton) {
    filesystemVisibilitySaveButton.addEventListener("click", async () => {
      try {
        await saveFilesystemVisibilityFromModal();
      } catch (error) {
        setFilesystemVisibilityStatus(`Fehler: ${error.message}`, true);
      }
    });
  }

  const filesystemFocusSettingsButton = document.getElementById("filesystemFocusSettingsButton");
  if (filesystemFocusSettingsButton) {
    filesystemFocusSettingsButton.addEventListener("click", () => {
      openFilesystemVisibilityModal("fs-focus");
    });
  }
  const largeFilesSettingsButton = document.getElementById("largeFilesSettingsButton");
  if (largeFilesSettingsButton) {
    largeFilesSettingsButton.addEventListener("click", () => {
      openFilesystemVisibilityModal("large-files");
    });
  }


  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      const fsModal = document.getElementById("filesystemVisibilityModal");
      if (fsModal && !fsModal.classList.contains("hidden")) {
        closeFilesystemVisibilityModal();
        return;
      }
      const modal = document.getElementById("chartDrillModal");
      if (modal && !modal.classList.contains("hidden")) {
        modal.classList.add("hidden");
      }
      const aiModal = document.getElementById("aiTroubleshootModal");
      if (aiModal && !aiModal.classList.contains("hidden")) {
        closeAiTroubleshootModal();
      }
    }
  });

  const toggleMountpointBtn = document.getElementById("toggleMountpointTableButton");
  if (toggleMountpointBtn) {
    toggleMountpointBtn.addEventListener("click", (e) => {
      e.stopPropagation();
      const tableWrap = document.getElementById("mountpointTableWrap");
      if (!tableWrap) return;
      const collapsed = !tableWrap.classList.contains("hidden");
      tableWrap.classList.toggle("hidden", collapsed);
      toggleMountpointBtn.textContent = collapsed ? "▸" : "▾";
      toggleMountpointBtn.setAttribute("aria-expanded", String(!collapsed));
    });
  }

  document.getElementById("overviewTabButton").addEventListener("click", () => {
    state.viewMode = "overview";
    updateViewMode();
  });

  document.getElementById("globalAlertsTabButton").addEventListener("click", async () => {
    state.globalSubMode = "global-alerts";
    updateGlobalSubMode();
    await loadGlobalAlertsOverview();
  });

  document.getElementById("criticalTrendsTabButton").addEventListener("click", async () => {
    state.globalSubMode = "critical-trends";
    updateGlobalSubMode();
    await loadCriticalTrends();
  });

  document.getElementById("refreshCriticalTrendsButton").addEventListener("click", async () => {
    await loadCriticalTrends();
  });

  document.getElementById("criticalTrendsRangeSelect").addEventListener("change", async (event) => {
    state.criticalTrendsHours = Number(event.target.value) || 24;
    state.criticalTrendsProjectHours = state.criticalTrendsHours;
    await loadCriticalTrends();
  });

  document.getElementById("criticalTrendsProjectSelect").addEventListener("change", async (event) => {
    state.criticalTrendsProjectHours = Number(event.target.value) || 8;
    await loadCriticalTrends();
  });

  ["ctMetricCpu", "ctMetricMemory", "ctMetricSwap", "ctMetricFilesystem"].forEach((checkboxId) => {
    const checkbox = document.getElementById(checkboxId);
    if (checkbox) {
      checkbox.addEventListener("change", async () => {
        updateCriticalTrendsMetrics();
      });
    }
  });

  document.getElementById("inactiveHostsTabButton").addEventListener("click", async () => {
    state.globalSubMode = "inactive-hosts";
    updateGlobalSubMode();
    await loadInactiveHosts();
  });

  const backupStatusTabButton = document.getElementById("backupStatusTabButton");
  if (backupStatusTabButton) {
    backupStatusTabButton.addEventListener("click", async () => {
      state.globalSubMode = "backup-status";
      updateGlobalSubMode();
      await loadBackupStatus();
    });
  }
  const refreshBackupStatusButton = document.getElementById("refreshBackupStatusButton");
  if (refreshBackupStatusButton) {
    refreshBackupStatusButton.addEventListener("click", async () => {
      await loadBackupStatus();
    });
  }

  const globalAdminAlertSubsTabButton = document.getElementById("globalAdminAlertSubsTabButton");
  if (globalAdminAlertSubsTabButton) {
    globalAdminAlertSubsTabButton.addEventListener("click", async () => {
      state.globalSubMode = "admin-alert-subs";
      updateGlobalSubMode();
      await loadAdminAlertSubscriptions();
    });
  }
  const globalAdminSettingsTabButton = document.getElementById("globalAdminSettingsTabButton");
  if (globalAdminSettingsTabButton) {
    globalAdminSettingsTabButton.addEventListener("click", async () => {
      if (!state.isAdmin) {
        return;
      }
      state.globalSubMode = "admin-settings";
      updateGlobalSubMode();
      await loadGlobalAdminSettingsPanel();
    });
  }

  document.getElementById("globalViewButton").addEventListener("click", async () => {
    state.viewMode = "global";
    updateViewMode();
    state.globalSubMode = state.globalSubMode || "global-alerts";
    if (state.globalSubMode === "admin-alert-subs" && !state.isAdmin) {
      state.globalSubMode = "global-alerts";
    }
    updateGlobalSubMode();
    if (state.globalSubMode === "global-alerts") await loadGlobalAlertsOverview();
    else if (state.globalSubMode === "critical-trends") await loadCriticalTrends();
    else if (state.globalSubMode === "inactive-hosts") await loadInactiveHosts();
    else if (state.globalSubMode === "backup-status") await loadBackupStatus();
    else if (state.globalSubMode === "admin-alert-subs") await loadAdminAlertSubscriptions();
    else if (state.globalSubMode === "admin-settings") await loadGlobalAdminSettingsPanel();
  });

  document.getElementById("headerAlertChip").addEventListener("click", async () => {
    state.viewMode = "global";
    state.globalSubMode = "global-alerts";
    updateViewMode();
    updateGlobalSubMode();
    await loadGlobalAlertsOverview();
  });

  document.getElementById("headerTrendsChip").addEventListener("click", async () => {
    state.viewMode = "global";
    state.globalSubMode = "critical-trends";
    updateViewMode();
    updateGlobalSubMode();
    await loadCriticalTrends();
  });

  document.getElementById("headerInactiveChip").addEventListener("click", async () => {
    state.viewMode = "global";
    state.globalSubMode = "inactive-hosts";
    updateViewMode();
    updateGlobalSubMode();
    await loadInactiveHosts();
  });

  document.getElementById("refreshInactiveHostsButton").addEventListener("click", async () => {
    await loadInactiveHosts();
  });

  document.getElementById("inactiveHostsRangeSelect").addEventListener("change", async (event) => {
    state.inactiveHostsHours = Number(event.target.value) || 1;
    await loadInactiveHosts();
  });

  document.getElementById("reportsTabButton").addEventListener("click", () => {
    state.viewMode = "reports";
    updateViewMode();
  });

  const settingsTabButton = document.getElementById("settingsTabButton");
  if (settingsTabButton) {
    settingsTabButton.addEventListener("click", async () => {
      state.viewMode = "settings";
      updateViewMode();
      await loadSettingsPanel(true);
    });
  }

  const settingsBackToOverviewButton = document.getElementById("settingsBackToOverviewButton");
  if (settingsBackToOverviewButton) {
    settingsBackToOverviewButton.addEventListener("click", () => {
      state.viewMode = "overview";
      updateViewMode();
    });
  }

  const openUserSettingsButton = document.getElementById("openUserSettingsButton");
  if (openUserSettingsButton) {
    openUserSettingsButton.addEventListener("click", async () => {
      state.viewMode = "settings";
      state.userSettingsSubMode = "password";
      updateViewMode();
      await loadSettingsPanel(true);
    });
  }

  const userSettingsPasswordTabButton = document.getElementById("userSettingsPasswordTabButton");
  if (userSettingsPasswordTabButton) {
    userSettingsPasswordTabButton.addEventListener("click", () => {
      state.userSettingsSubMode = "password";
      updateUserSettingsSubMode();
    });
  }
  const userSettingsChannelsTabButton = document.getElementById("userSettingsChannelsTabButton");
  if (userSettingsChannelsTabButton) {
    userSettingsChannelsTabButton.addEventListener("click", () => {
      state.userSettingsSubMode = "channels";
      updateUserSettingsSubMode();
    });
  }
  const userSettingsDigestsTabButton = document.getElementById("userSettingsDigestsTabButton");
  if (userSettingsDigestsTabButton) {
    userSettingsDigestsTabButton.addEventListener("click", () => {
      state.userSettingsSubMode = "digests";
      updateUserSettingsSubMode();
    });
  }
  const userSettingsHostsTabButton = document.getElementById("userSettingsHostsTabButton");
  if (userSettingsHostsTabButton) {
    userSettingsHostsTabButton.addEventListener("click", () => {
      state.userSettingsSubMode = "hosts";
      updateUserSettingsSubMode();
      renderHostInterestsEditor();
    });
  }
  const globalViewBackButton = document.getElementById("globalViewBackButton");
  if (globalViewBackButton) {
    globalViewBackButton.addEventListener("click", () => {
      state.viewMode = "overview";
      updateViewMode();
    });
  }

  document.getElementById("triggerAllAgentsUpdateButton").addEventListener("click", async () => {
    try {
      const result = await triggerAgentUpdateForAllHosts();
      const totalHosts = Number(result.total_hosts || 0);
      const queuedCount = Number(result.queued_count || 0);
      const alreadyQueuedCount = Number(result.already_queued_count || 0);
      window.alert(`Update-Trigger gesetzt: ${queuedCount} Hosts neu gequeued, ${alreadyQueuedCount} bereits pending, gesamt ${totalHosts}.`);
    } catch (error) {
      window.alert(`Globaler Update-Trigger fehlgeschlagen: ${error.message}`);
    }
  });

  document.getElementById("rolloutApiKeyButton").addEventListener("click", async () => {
    const apiKey = window.prompt("API-Key fuer alle bekannten Hosts verteilen:", "");
    if (apiKey === null) {
      return;
    }

    const normalizedApiKey = String(apiKey).trim();
    if (!normalizedApiKey) {
      window.alert("Kein API-Key eingegeben.");
      return;
    }

    const confirmed = window.confirm(
      "API-Key jetzt an alle bekannten Hosts verteilen?\n\nBestehende Hosts duerfen waehrend der Grace-Phase weiter ohne Key pollen, bis ihre agent.conf aktualisiert wurde."
    );
    if (!confirmed) {
      return;
    }

    try {
      const result = await triggerAgentApiKeyRolloutForAllHosts(normalizedApiKey);
      const totalHosts = Number(result.total_hosts || 0);
      const queuedCount = Number(result.queued_count || 0);
      const alreadyQueuedCount = Number(result.already_queued_count || 0);
      window.alert(`API-Key-Rollout gesetzt: ${queuedCount} Hosts neu gequeued, ${alreadyQueuedCount} bereits pending, gesamt ${totalHosts}.`);
    } catch (error) {
      window.alert(`API-Key-Rollout fehlgeschlagen: ${error.message}`);
    }
  });

  const backupButton = document.getElementById("downloadDatabaseBackupButton");
  if (backupButton) {
    backupButton.addEventListener("click", async () => {
      try {
        const filename = await downloadDatabaseBackup();
        window.alert(`Datenbank-Backup heruntergeladen: ${filename}`);
      } catch (error) {
        window.alert(`DB-Backup fehlgeschlagen: ${error.message}`);
      }
    });
  }

  const restoreButton = document.getElementById("restoreDatabaseButton");
  const restoreFileInput = document.getElementById("restoreDatabaseFileInput");
  if (restoreButton && restoreFileInput) {
    restoreButton.addEventListener("click", () => {
      restoreFileInput.value = "";
      restoreFileInput.click();
    });
    restoreFileInput.addEventListener("change", async () => {
      const file = restoreFileInput.files?.[0];
      if (!file) return;
      const confirmed = window.confirm(
        `Datenbank wirklich aus "${file.name}" (${(file.size / 1024).toFixed(0)} KB) wiederherstellen?\n\nDie aktuelle Datenbank wird dabei UEBERSCHRIEBEN. Vorher ein Backup anlegen!`
      );
      if (!confirmed) return;
      restoreButton.disabled = true;
      restoreButton.textContent = "Wiederherstellen...";
      try {
        await restoreDatabaseFromFile(file);
        window.alert(`Datenbank erfolgreich wiederhergestellt aus: ${file.name}\n\nBitte den Server neu starten, damit alle Aenderungen wirksam werden.`);
      } catch (error) {
        window.alert(`DB-Restore fehlgeschlagen: ${error.message}`);
      } finally {
        restoreButton.disabled = false;
        restoreButton.innerHTML = "&#x267B;&#xFE0F; DB wiederherstellen";
        restoreFileInput.value = "";
      }
    });
  }

  for (const button of document.querySelectorAll("[data-report-section]")) {
    button.addEventListener("click", () => {
      state.reportSection = normalizeReportSection(button.getAttribute("data-report-section"));
      updateReportSectionUi();
      renderCurrentReportInView();
    });
  }

  document.getElementById("loginSubmitButton").addEventListener("click", async () => {
    const ok = await loginWebClient();
    if (!ok) {
      return;
    }
    await refreshDashboard({ preserveScroll: false });
    startAutoRefreshTimer();
  });

  document.getElementById("loginPasswordInput").addEventListener("keydown", async (event) => {
    if (event.key !== "Enter") {
      return;
    }
    const ok = await loginWebClient();
    if (!ok) {
      return;
    }
    await refreshDashboard({ preserveScroll: false });
    startAutoRefreshTimer();
  });

  document.getElementById("logoutButton").addEventListener("click", async () => {
    await logoutWebClient();
  });

  document.getElementById("savePasswordButton").addEventListener("click", async () => {
    await changePassword();
  });

  const exportHostReportsButton = document.getElementById("exportHostReportsButton");
  if (exportHostReportsButton) {
    exportHostReportsButton.addEventListener("click", async () => {
      try {
        const filename = await exportSelectedHostReportsJson();
        window.alert(`Meldungen exportiert: ${filename}`);
      } catch (error) {
        window.alert(`Reports Export fehlgeschlagen: ${error.message}`);
      }
    });
  }

  document.getElementById("globalSeverityFilter").addEventListener("change", async (event) => {
    state.globalSeverityFilter = String(event.target?.value || "all");
    state.globalAlertsOffset = 0;
    await loadGlobalAlertsOverview({ append: false });
  });

  const globalShowAcknowledgedCheckbox = document.getElementById("globalShowAcknowledgedCheckbox");
  if (globalShowAcknowledgedCheckbox) {
    globalShowAcknowledgedCheckbox.checked = state.globalShowAcknowledged;
    globalShowAcknowledgedCheckbox.addEventListener("change", async (event) => {
      state.globalShowAcknowledged = event.target.checked;
      state.globalAlertsOffset = 0;
      await loadGlobalAlertsOverview({ append: false });
    });
  }

  const globalShowClosedCheckbox = document.getElementById("globalShowClosedCheckbox");
  if (globalShowClosedCheckbox) {
    globalShowClosedCheckbox.checked = state.globalShowClosed;
    globalShowClosedCheckbox.addEventListener("change", async (event) => {
      state.globalShowClosed = event.target.checked;
      state.globalAlertsOffset = 0;
      await loadGlobalAlertsOverview({ append: false });
    });
  }

  // Ack modal wiring
  const ackModalCloseBtn = document.getElementById("ackModalCloseBtn");
  const ackModalCancelBtn = document.getElementById("ackModalCancelBtn");
  const ackModalConfirmBtn = document.getElementById("ackModalConfirmBtn");
  const ackModalUnackBtn = document.getElementById("ackModalUnackBtn");
  const ackModalBackdrop = document.getElementById("ackModalBackdrop");
  if (ackModalCloseBtn) ackModalCloseBtn.addEventListener("click", () => closeAckModal(null));
  if (ackModalCancelBtn) ackModalCancelBtn.addEventListener("click", () => closeAckModal(null));
  if (ackModalBackdrop) ackModalBackdrop.addEventListener("click", () => closeAckModal(null));
  if (ackModalConfirmBtn) {
    ackModalConfirmBtn.addEventListener("click", () => {
      const note = (document.getElementById("ackModalNoteInput")?.value || "").trim();
      closeAckModal({ note });
    });
  }
  if (ackModalUnackBtn) {
    ackModalUnackBtn.addEventListener("click", () => {
      closeAckModal({ unack: true });
    });
  }
  // Close modal on Escape
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      const modal = document.getElementById("ackModal");
      if (modal && !modal.classList.contains("hidden")) {
        closeAckModal(null);
      }
    }
  });

  const exportGlobalAlertsButton = document.getElementById("exportGlobalAlertsButton");
  if (exportGlobalAlertsButton) {
    exportGlobalAlertsButton.addEventListener("click", async () => {
      try {
        const filename = await exportGlobalAlertsCsv();
        window.alert(`Alerts exportiert: ${filename}`);
      } catch (error) {
        window.alert(`Alerts Export fehlgeschlagen: ${error.message}`);
      }
    });
  }

  const globalAlertsLoadMoreButton = document.getElementById("globalAlertsLoadMoreButton");
  if (globalAlertsLoadMoreButton) {
    globalAlertsLoadMoreButton.addEventListener("click", async () => {
      await loadGlobalAlertsOverview({ append: true });
    });
  }

  document.getElementById("toggleGlobalAlertsPanelButton").addEventListener("click", async () => {
    state.globalAlertsCollapsed = !state.globalAlertsCollapsed;
    await loadGlobalAlertsOverview();
  });

  document.getElementById("overviewMainTabButton").addEventListener("click", () => {
    state.overviewSection = "main";
    updateOverviewSection();
  });

  document.getElementById("overviewFilesystemTabButton").addEventListener("click", () => {
    state.overviewSection = "filesystem";
    updateOverviewSection();
  });

  document.getElementById("toggleHostAlertsPanelButton").addEventListener("click", async () => {
    state.hostAlertsCollapsed = !state.hostAlertsCollapsed;
    await loadAlertsForHost();
  });

  document.getElementById("analysisRangeSelect").addEventListener("change", async (event) => {
    state.analysisHours = normalizeAnalysisHours(event.target?.value);
    persistAnalysisRangePreference();
    updateAnalysisRangeUi();
    await loadAnalysisForHost();
  });

  document.getElementById("editDisplayNameButton").addEventListener("click", async () => {
    try {
      await editDisplayName();
    } catch (error) {
      window.alert(`Titel konnte nicht gespeichert werden: ${error.message}`);
    }
  });

  document.getElementById("refreshButton").addEventListener("click", async () => {
    await refreshDashboard({ preserveScroll: false });
    updateAutoRefreshStatus(new Date());
    if (autoRefreshCurrentIntervalSec > 0) startAutoRefreshTimer();
  });

  document.getElementById("openAlarmSettingsButton").addEventListener("click", async () => {
    if (state.isAdmin) {
      state.viewMode = "global";
      state.globalSubMode = "admin-settings";
      updateViewMode();
      updateGlobalSubMode();
      await loadGlobalAdminSettingsPanel(true);
      return;
    }
    state.viewMode = "settings";
    state.userSettingsSubMode = "password";
    updateViewMode();
    await loadSettingsPanel(true);
  });

  document.getElementById("saveAlarmSettingsButton").addEventListener("click", async () => {
    try {
      await saveAlarmSettings();
    } catch (error) {
      setAlarmSettingsStatus(`Speichern fehlgeschlagen: ${error.message}`, true);
    }
  });

  document.getElementById("testAlarmSettingsButton").addEventListener("click", async () => {
    try {
      await sendAlarmSettingsTest();
    } catch (error) {
      setAlarmSettingsStatus(`Test fehlgeschlagen: ${error.message}`, true);
    }
  });

  document.getElementById("saveUserMailSettingsButton").addEventListener("click", async () => {
    try {
      await saveUserProfile();
    } catch (error) {
      setUserMailSettingsStatus(error.message, true);
    }
  });

  const saveDigestSettingsButton = document.getElementById("saveDigestSettingsButton");
  if (saveDigestSettingsButton) {
    saveDigestSettingsButton.addEventListener("click", async () => {
      try {
        await saveUserProfile();
      } catch (error) {
        setUserMailSettingsStatus(error.message, true);
      }
    });
  }

  const hostInterestModeSelect = document.getElementById("hostInterestModeSelect");
  if (hostInterestModeSelect) {
    hostInterestModeSelect.addEventListener("change", async (event) => {
      state.hostInterestMode = normalizeHostInterestMode(event.target?.value || "all");
      renderHostInterestsEditor();
      await loadHosts({ preserveScroll: true });
    });
  }
  const hostInterestSearchInput = document.getElementById("hostInterestSearchInput");
  if (hostInterestSearchInput) {
    hostInterestSearchInput.addEventListener("input", () => {
      state.hostInterestSearchQuery = String(hostInterestSearchInput.value || "");
      renderHostInterestsEditor();
    });
  }
  const hostInterestsSelectAllButton = document.getElementById("hostInterestsSelectAllButton");
  if (hostInterestsSelectAllButton) {
    hostInterestsSelectAllButton.addEventListener("click", () => {
      state.hostInterestHosts = new Set((state.hosts || []).map((host) => String(host.hostname || "")).filter((item) => item));
      renderHostInterestsEditor();
    });
  }
  const hostInterestsClearButton = document.getElementById("hostInterestsClearButton");
  if (hostInterestsClearButton) {
    hostInterestsClearButton.addEventListener("click", () => {
      state.hostInterestHosts = new Set();
      renderHostInterestsEditor();
    });
  }
  const saveHostInterestsButton = document.getElementById("saveHostInterestsButton");
  if (saveHostInterestsButton) {
    saveHostInterestsButton.addEventListener("click", async () => {
      try {
        await saveUserProfile();
        setHostInterestsStatus("Host-Interessen gespeichert.");
      } catch (error) {
        setHostInterestsStatus(error.message, true);
      }
    });
  }

  const reloadAdminAlertSubBtn = document.getElementById("reloadAdminAlertSubscriptionsButton");
  if (reloadAdminAlertSubBtn) {
    reloadAdminAlertSubBtn.addEventListener("click", async () => {
      state.adminAlertSubscriptionsLoaded = false;
      await loadAdminAlertSubscriptions(true);
    });
  }

  const saveAdminAlertSubscriptionsButton = document.getElementById("saveAdminAlertSubscriptionsButton");
  if (saveAdminAlertSubscriptionsButton) {
    saveAdminAlertSubscriptionsButton.addEventListener("click", async () => {
      try {
        await saveAdminAlertSubscriptions();
      } catch (error) {
        setAdminAlertSubscriptionsStatus(error.message, true);
      }
    });
  }

  document.getElementById("connectMicrosoftOauthButton").addEventListener("click", () => {
    setUserMailSettingsStatus("Weiterleitung zu Microsoft...");
    window.location.assign("/api/v1/oauth/microsoft/start");
  });

  document.getElementById("disconnectMicrosoftOauthButton").addEventListener("click", async () => {
    try {
      await disconnectMicrosoftOauth();
    } catch (error) {
      setUserMailSettingsStatus(error.message, true);
    }
  });

  document.getElementById("testTrendDigestMailButton").addEventListener("click", async () => {
    try {
      await sendTrendDigestMailTest();
    } catch (error) {
      setUserMailSettingsStatus(error.message, true);
    }
  });

  document.getElementById("testAlertDigestMailButton").addEventListener("click", async () => {
    try {
      await sendAlertDigestMailTest();
    } catch (error) {
      setUserMailSettingsStatus(error.message, true);
    }
  });

  document.getElementById("testBackupDigestMailButton").addEventListener("click", async () => {
    try {
      await sendBackupDigestMailTest();
    } catch (error) {
      setUserMailSettingsStatus(error.message, true);
    }
  });

  document.getElementById("saveOauthSettingsButton").addEventListener("click", async () => {
    try {
      await saveOauthSettings();
    } catch (error) {
      setOauthSettingsStatus(error.message, true);
    }
  });

  document.getElementById("createUserButton").addEventListener("click", async () => {
    try {
      await createUser();
    } catch (error) {
      setUserManagementStatus(error.message, true);
    }
  });

  document.getElementById("reportsPrevButton").addEventListener("click", goToPreviousReport);
  document.getElementById("reportsNextButton").addEventListener("click", goToNextReport);

  const reportJumpDateTimeInput = document.getElementById("reportJumpDateTimeInput");
  const reportJumpLatestButton = document.getElementById("reportJumpLatestButton");
  if (reportJumpDateTimeInput) {
    reportJumpDateTimeInput.addEventListener("change", async () => {
      await jumpToReportDateTime();
    });
    reportJumpDateTimeInput.addEventListener("keydown", async (event) => {
      if (event.key !== "Enter") {
        return;
      }
      event.preventDefault();
      await jumpToReportDateTime();
    });
  }
  if (reportJumpLatestButton) {
    reportJumpLatestButton.addEventListener("click", async () => {
      await jumpToLatestReport();
    });
  }

  const reportsPrevButtonTop = document.getElementById("reportsPrevButtonTop");
  const reportsNextButtonTop = document.getElementById("reportsNextButtonTop");
  if (reportsPrevButtonTop) {
    reportsPrevButtonTop.addEventListener("click", goToPreviousReport);
  }
  if (reportsNextButtonTop) {
    reportsNextButtonTop.addEventListener("click", goToNextReport);
  }

  document.getElementById("hostSearchInput").addEventListener("input", async (event) => {
    state.hostSearchQuery = event.target.value;
    state.hostOffset = 0;
    persistHostFilterPreferences();
    await loadHosts();
  });

  document.getElementById("hostAlertFilterSelect").addEventListener("change", async (event) => {
    state.hostAlertFilter = String(event.target?.value || "all");
    persistHostFilterPreferences();
    state.hostOffset = 0;
    await loadHosts();
  });

  document.getElementById("hostMutedFilterSelect").addEventListener("change", async (event) => {
    state.hostMutedFilter = String(event.target?.value || "all");
    persistHostFilterPreferences();
    state.hostOffset = 0;
    await loadHosts();
  });

  document.getElementById("hostFiltersResetButton").addEventListener("click", async () => {
    state.hostSearchQuery = "";
    state.hostAlertFilter = "all";
    state.hostMutedFilter = "all";
    state.hostOsFilter = "all";
    state.hostCountryFilter = "all";
    state.hostOffset = 0;
    persistHostFilterPreferences();
    document.getElementById("hostSearchInput").value = "";
    document.getElementById("hostAlertFilterSelect").value = "all";
    document.getElementById("hostMutedFilterSelect").value = "all";
    await loadHosts();
  });
}

async function init() {
  state.analysisHours = loadAnalysisRangePreference();
  applyTheme(loadThemePreference());
    autoRefreshCurrentIntervalSec = loadAutoRefreshPreference();
    const arSelect = document.getElementById("autoRefreshIntervalSelect");
    if (arSelect) arSelect.value = String(autoRefreshCurrentIntervalSec);
  updateAutoRefreshStatus(null);
  const oauthResult = consumeOauthStatusFromUrl();
  try {
    await loadWebclientVersion();
  } catch (error) {
    console.warn("initial loadWebclientVersion failed:", error);
  }
  wireEvents();
  mountAdminSettingsIntoGlobalView();
  updateViewMode();
  updateOverviewSection();
  updateAnalysisRangeUi();
  document.getElementById("criticalTrendsRangeSelect").value = String(state.criticalTrendsHours);
  document.getElementById("criticalTrendsProjectSelect").value = String(state.criticalTrendsProjectHours);
  document.getElementById("inactiveHostsRangeSelect").value = String(state.inactiveHostsHours);
  document.getElementById("globalSeverityFilter").value = state.globalSeverityFilter;
  document.getElementById("hostAlertFilterSelect").value = state.hostAlertFilter;
  document.getElementById("hostMutedFilterSelect").value = state.hostMutedFilter;
  document.getElementById("hostSearchInput").value = state.hostSearchQuery;
  document.getElementById("loginUsernameInput").value = "";
  document.getElementById("loginPasswordInput").value = "";
  const isAuthenticated = await ensureAuthenticatedSession();
  if (!isAuthenticated) {
    setLoginStatus("Bitte anmelden, um den Webclient zu nutzen.");
    return;
  }
  document.getElementById("hostAlertFilterSelect").value = state.hostAlertFilter;
  document.getElementById("hostMutedFilterSelect").value = state.hostMutedFilter;
  document.getElementById("hostSearchInput").value = state.hostSearchQuery;
  if (oauthResult) {
    state.viewMode = "settings";
    state.userSettingsSubMode = "channels";
    updateViewMode();
    setUserMailSettingsStatus(
      oauthResult.status === "success"
        ? "Microsoft Verbindung erfolgreich hergestellt."
        : `Microsoft OAuth Fehler: ${oauthResult.message || "unbekannt"}`,
      oauthResult.status !== "success",
    );
    await loadSettingsPanel(true);
  }
  await refreshDashboard({ preserveScroll: false });
  startAutoRefreshTimer();
  startSessionRefreshTimer();
}

init();
