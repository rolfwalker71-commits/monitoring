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
const HOST_FILTERS_STORAGE_KEY = "monitoring.hostFilters";
const AUTO_REFRESH_INTERVAL_MS = 8 * 60 * 1000;
const REPORT_SECTION_OPTIONS = new Set(["overview", "journal", "processes", "containers", "agent-update"]);

let autoRefreshTimerId = null;
let autoRefreshInProgress = false;

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
  overviewSection: "main",
  globalSubMode: "global-alerts",
  criticalTrendsHours: 24,
  inactiveHostsHours: 3,
  inactiveHosts: [],
  reportLimit: 1,
  reportOffset: 0,
  totalReports: 0,
  currentReport: null,
  reportSection: "overview",
  analysisHours: 24,
  alarmSettingsLoaded: false,
  globalAlertsCollapsed: false,
  hostAlertsCollapsed: false,
  globalSeverityFilter: "all",
  globalOpenAlertsCount: 0,
  criticalTrendsCount: 0,
  authUser: "",
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
  adminAlertSubscriptionsLoaded: false,
  adminAlertSubscriptionsUsers: [],
  adminAlertAvailableHosts: [],
  adminAlertTelegramAvailable: false,
};

const ANALYSIS_RANGE_OPTIONS = new Map([
  [6, "Letzte 6 Std."],
  [24, "Letzte 24 Std."],
  [72, "Letzte 3 Tage"],
  [168, "Letzte 7 Tage"],
  [336, "Letzte 14 Tage"],
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

function persistAnalysisRangePreference() {
  try {
    window.localStorage.setItem(ANALYSIS_RANGE_STORAGE_KEY, String(state.analysisHours));
  } catch (_error) {
    // Ignore storage failures and keep the current in-memory selection.
  }
}

function loadHostFilterPreferences() {
  try {
    const raw = window.localStorage.getItem(HOST_FILTERS_STORAGE_KEY);
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

function persistHostFilterPreferences() {
  try {
    window.localStorage.setItem(HOST_FILTERS_STORAGE_KEY, JSON.stringify({
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

function updateAutoRefreshStatus(lastRefreshAt = null) {
  const statusEl = document.getElementById("autoRefreshStatus");
  if (!statusEl) {
    return;
  }
  statusEl.textContent = lastRefreshAt
    ? `🔄 ${formatAutoRefreshTimestamp(lastRefreshAt)}`
    : "🔄 -";
}

function stopAutoRefreshTimer() {
  if (autoRefreshTimerId !== null) {
    window.clearInterval(autoRefreshTimerId);
    autoRefreshTimerId = null;
  }
}

function startAutoRefreshTimer() {
  stopAutoRefreshTimer();
  autoRefreshTimerId = window.setInterval(() => {
    void refreshDashboard({ automatic: true, preserveScroll: true });
  }, AUTO_REFRESH_INTERVAL_MS);
}

async function refreshDashboard(options = {}) {
  const automatic = options.automatic === true;
  const preserveScroll = options.preserveScroll === true;

  if (!state.isAuthenticated || autoRefreshInProgress) {
    return;
  }

  autoRefreshInProgress = true;
  try {
    await loadWebclientVersion();
    await loadGlobalAlertsOverview();
    await loadHosts({ preserveScroll });
    await loadReportsForHost();
    await loadAnalysisForHost();
    await loadAlertsForHost();
    if (state.viewMode === "settings") {
      await loadSettingsPanel(true);
    }
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
          <span>⏭️ Naechster priorisierter Check: ${escapeHtml(nextPriority)}</span>
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
}

function updateGlobalSubMode() {
  const globalAlertsView = document.getElementById("globalAlertsView");
  const criticalTrendsView = document.getElementById("criticalTrendsView");
  const inactiveHostsView = document.getElementById("inactiveHostsView");
  const globalAdminAlertSubsView = document.getElementById("globalAdminAlertSubsView");
  const globalAlertsTabButton = document.getElementById("globalAlertsTabButton");
  const criticalTrendsTabButton = document.getElementById("criticalTrendsTabButton");
  const inactiveHostsTabButton = document.getElementById("inactiveHostsTabButton");
  const globalAdminAlertSubsTabButton = document.getElementById("globalAdminAlertSubsTabButton");

  const alertsActive = state.globalSubMode === "global-alerts";
  const trendsActive = state.globalSubMode === "critical-trends";
  const inactiveActive = state.globalSubMode === "inactive-hosts";
  const adminAlertSubsActive = state.globalSubMode === "admin-alert-subs";

  if (globalAlertsView) globalAlertsView.classList.toggle("hidden", !alertsActive);
  if (criticalTrendsView) criticalTrendsView.classList.toggle("hidden", !trendsActive);
  if (inactiveHostsView) inactiveHostsView.classList.toggle("hidden", !inactiveActive);
  if (globalAdminAlertSubsView) globalAdminAlertSubsView.classList.toggle("hidden", !adminAlertSubsActive);
  if (globalAlertsTabButton) { globalAlertsTabButton.classList.toggle("active", alertsActive); globalAlertsTabButton.setAttribute("aria-selected", alertsActive ? "true" : "false"); }
  if (criticalTrendsTabButton) { criticalTrendsTabButton.classList.toggle("active", trendsActive); criticalTrendsTabButton.setAttribute("aria-selected", trendsActive ? "true" : "false"); }
  if (inactiveHostsTabButton) { inactiveHostsTabButton.classList.toggle("active", inactiveActive); inactiveHostsTabButton.setAttribute("aria-selected", inactiveActive ? "true" : "false"); }
  if (globalAdminAlertSubsTabButton) { globalAdminAlertSubsTabButton.classList.toggle("active", adminAlertSubsActive); globalAdminAlertSubsTabButton.setAttribute("aria-selected", adminAlertSubsActive ? "true" : "false"); }
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
      brandUserBadge.textContent = state.authUser;
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
  updateAdminSettingsVisibility();
}

function updateAdminSettingsVisibility() {
  const adminOauthSection = document.getElementById("adminOauthSettingsSection");
  const adminUserSection = document.getElementById("adminUserManagementSection");
  const globalAdminAlertSubsTab = document.getElementById("globalAdminAlertSubsTabButton");
  if (adminOauthSection) {
    adminOauthSection.classList.toggle("hidden", !state.isAdmin);
  }
  if (adminUserSection) {
    adminUserSection.classList.toggle("hidden", !state.isAdmin);
  }
  if (globalAdminAlertSubsTab) {
    globalAdminAlertSubsTab.classList.toggle("hidden", !state.isAdmin);
  }
  if (!state.isAdmin && state.globalSubMode === "admin-alert-subs") {
    state.globalSubMode = "global-alerts";
    updateGlobalSubMode();
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
    state.isAdmin = session.is_admin === true;
    setAuthUiState(session.authenticated === true);
    return session.authenticated === true;
  } catch {
    setAuthUiState(false);
    return false;
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
  } catch {
    state.isAdmin = false;
  }
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
  const telegramEnabledInput = document.getElementById("telegramEnabledInput");
  const telegramBotTokenInput = document.getElementById("telegramBotTokenInput");
  const telegramChatIdInput = document.getElementById("telegramChatIdInput");

  try {
    const response = await fetch("/api/v1/alarm-settings");
    if (!response.ok) {
      throw new Error("HTTP " + response.status);
    }
    const settings = await response.json();

    warningInput.value = Number(settings.warning_threshold_percent || 80).toFixed(1);
    criticalInput.value = Number(settings.critical_threshold_percent || 90).toFixed(1);
    warningConsecutiveHitsInput.value = String(Number(settings.warning_consecutive_hits || 2));
    warningWindowMinutesInput.value = String(Number(settings.warning_window_minutes || 15));
    criticalImmediateInput.checked = settings.critical_trigger_immediate !== false;
    telegramEnabledInput.checked = settings.telegram_enabled === true;
    telegramBotTokenInput.value = asText(settings.telegram_bot_token, "") === "-" ? "" : String(settings.telegram_bot_token || "");
    telegramChatIdInput.value = asText(settings.telegram_chat_id, "") === "-" ? "" : String(settings.telegram_chat_id || "");

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
    alertEnabledInput.checked = profile.alert_email_enabled === true;
    alertTimeInput.value = asText(profile.alert_email_time_hhmm, "08:05");
    alertRecipientsInput.value = asText(profile.alert_email_recipients, "") === "-" ? "" : asText(profile.alert_email_recipients, "");
    if (alertInstantEnabledInput) alertInstantEnabledInput.checked = profile.alert_instant_mail_enabled === true;
    if (alertInstantMinSeveritySelect) alertInstantMinSeveritySelect.value = profile.alert_instant_min_severity || "warning";
    if (alertInstantTelegramEnabledInput) alertInstantTelegramEnabledInput.checked = profile.alert_instant_telegram_enabled === true;
    if (alertTelegramChatIdInput) alertTelegramChatIdInput.value = asText(profile.alert_telegram_chat_id, "") === "-" ? "" : asText(profile.alert_telegram_chat_id, "");

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
  const payload = {
    email_enabled: enabledInput.checked,
    email_recipient: recipientInput.value.trim(),
    trend_email_enabled: document.getElementById("trendEmailEnabledInput").checked,
    trend_email_time_hhmm: document.getElementById("trendEmailTimeInput").value || "08:00",
    alert_email_enabled: document.getElementById("alertEmailEnabledInput").checked,
    alert_email_time_hhmm: document.getElementById("alertEmailTimeInput").value || "08:05",
    alert_email_recipients: document.getElementById("alertEmailRecipientsInput").value.trim(),
    alert_instant_mail_enabled: document.getElementById("alertInstantMailEnabledInput")?.checked ?? false,
    alert_instant_min_severity: document.getElementById("alertInstantMinSeveritySelect")?.value || "warning",
    alert_instant_telegram_enabled: document.getElementById("alertInstantTelegramEnabledInput")?.checked ?? false,
    alert_telegram_chat_id: document.getElementById("alertTelegramChatIdInput")?.value.trim() || "",
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
    return '<tr><td colspan="6" class="muted">Keine Benutzer vorhanden.</td></tr>';
  }

  return users.map((user) => {
    const username = asText(user.username, "");
    const usernameEnc = encodeURIComponent(username);
    const adminPill = `<span class="user-flag-pill ${user.is_admin ? "on" : "off"}">${user.is_admin ? "Admin" : "User"}</span>`;
    const activePill = `<span class="user-flag-pill ${user.is_disabled ? "off" : "on"}">${user.is_disabled ? "Gesperrt" : "Aktiv"}</span>`;
    const oauthPill = `<span class="oauth-state-pill ${user.has_microsoft_oauth ? "connected" : "disconnected"}">${user.has_microsoft_oauth ? asText(user.microsoft_connected_email, "verbunden") : "nicht verbunden"}</span>`;

    return `
      <tr>
        <td><strong>${escapeHtml(username)}</strong></td>
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
  });

  usernameInput.value = "";
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

async function loadSettingsPanel(force = false) {
  updateAdminSettingsVisibility();
  await loadAlarmSettings(force);
  await loadUserProfile(force);
  if (state.isAdmin) {
    await loadOauthSettings(force);
    await loadWebUsers(force);
  }
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
  const warningConsecutiveHitsInput = document.getElementById("warningConsecutiveHitsInput");
  const warningWindowMinutesInput = document.getElementById("warningWindowMinutesInput");
  const criticalImmediateInput = document.getElementById("criticalImmediateInput");
  const telegramEnabledInput = document.getElementById("telegramEnabledInput");
  const telegramBotTokenInput = document.getElementById("telegramBotTokenInput");
  const telegramChatIdInput = document.getElementById("telegramChatIdInput");

  const warning = Number(warningInput.value);
  const critical = Number(criticalInput.value);
  const warningConsecutiveHits = Number(warningConsecutiveHitsInput.value);
  const warningWindowMinutes = Number(warningWindowMinutesInput.value);

  if (!Number.isFinite(warning) || !Number.isFinite(critical) || warning < 1 || critical > 100 || warning >= critical) {
    throw new Error("Schwellwerte ungueltig: Warnung muss kleiner als Kritisch sein.");
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
    warning_consecutive_hits: Math.floor(warningConsecutiveHits),
    warning_window_minutes: Math.floor(warningWindowMinutes),
    critical_trigger_immediate: criticalImmediateInput.checked,
    telegram_enabled: telegramEnabledInput.checked,
    telegram_bot_token: telegramBotTokenInput.value.trim(),
    telegram_chat_id: telegramChatIdInput.value.trim(),
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

function renderResourceTrendCards(resourceTrends, latestReportTimeUtc) {
  const standText = formatUtcPlus2(latestReportTimeUtc);
  const entries = [
    ["🧠 CPU", resourceTrends.cpu_usage_percent, "%"],
    ["📉 Load 1m", resourceTrends.load_avg_1, ""],
    ["🧮 RAM", resourceTrends.memory_used_percent, "%"],
    ["💤 Swap", resourceTrends.swap_used_percent, "%"],
  ];

  return entries
    .map(([label, value, suffix]) => {
      if (!value) {
        return `
          <article class="trend-card muted">
            <strong>${label}</strong>
            <span>Keine Daten</span>
          </article>
        `;
      }

      return `
        <article class="trend-card">
          <strong>${label}</strong>
          <span class="trend-current">Aktuell: ${formatNumber(value.current)}${suffix} <span class="trend-stand">(${standText})</span></span>
          <span>Min/Max: ${formatNumber(value.min)}${suffix} / ${formatNumber(value.max)}${suffix}</span>
          <span>Avg: ${formatNumber(value.avg)}${suffix}</span>
          <span>Delta: ${formatSignedPercent(value.delta)}${suffix === "%" ? "" : ""}</span>
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
            <span>${Number(item.sample_count || 0).toLocaleString("de-DE")} Samples</span>
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

  return `${shifted.toLocaleString("de-DE", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
    timeZone: "UTC",
  })} UTC+2`;
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
      const usedPercentText = Number.isFinite(usedPercent) ? `${usedPercent}%` : "-";
      const usedBlocks = Number(fs.used);
      const totalBlocks = Number(fs.blocks);
      const usedBlocksText = Number.isFinite(usedBlocks) ? usedBlocks.toLocaleString("de-DE") : "-";
      const totalBlocksText = Number.isFinite(totalBlocks) ? totalBlocks.toLocaleString("de-DE") : "-";

      return `
        <tr>
          <td>${mountpoint}</td>
          <td>${fsName}</td>
          <td>${fsType}</td>
          <td>${usedPercentText}</td>
          <td>${usedBlocksText} / ${totalBlocksText}</td>
        </tr>
      `;
    })
    .join("");

  return `
    <div class="table-wrap">
      <table class="fs-table">
        <thead>
          <tr>
            <th>📁 Mountpoint</th>
            <th>💽 Filesystem</th>
            <th>🧩 Typ</th>
            <th>📈 Belegt</th>
            <th>🧮 Used / Total (Blocks)</th>
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
    return "konfiguriert | Status ab naechstem Report exakt sichtbar";
  }
  return "aus | Server verlangt aktuell keinen API-Key";
}

function renderReportCard(report) {
  const payload = report && report.payload ? report.payload : {};
  const cpu = payload.cpu || {};
  const memory = payload.memory || {};
  const swap = payload.swap || {};
  const network = payload.network || {};
  const title = asText(report.display_name || payload.display_name || report.hostname || payload.hostname);
  const technicalHostname = asText(report.hostname || payload.hostname);
  const deliveryMode = asText(report.delivery_mode || payload.delivery_mode || "live", "live").toLowerCase();
  const isDelayed = deliveryMode === "delayed" || payload.is_delayed === true;
  const chipClass = isDelayed ? "delivery-chip delayed" : "delivery-chip live";
  const chipText = isDelayed ? "DELAYED" : "LIVE";
  const queueDepth = queueDepthLabel(payload.queue_depth);
  const section = normalizeReportSection(state.reportSection);

  let detailContent = "";
  if (section === "journal") {
    detailContent = `
      <h4>🚨 Journal Fehler (kritisch)</h4>
      ${renderJournalErrorsTable(payload.journal_errors)}
    `;
  } else if (section === "processes") {
    detailContent = `
      <h4>🏎️ Top Prozesse</h4>
      ${renderTopProcessesTable(payload.top_processes)}
    `;
  } else if (section === "containers") {
    detailContent = `
      <h4>🐳 Container Status</h4>
      ${renderContainersTable(payload.containers)}
    `;
  } else if (section === "agent-update") {
    detailContent = `
      <h4>⟳ Agent Update Log</h4>
      ${renderAgentUpdateLog(payload.agent_update)}
    `;
    detailContent += `
      <h4>🗂️ agent.conf</h4>
      ${renderAgentConfig(payload.agent_config)}
    `;
  } else {
    detailContent = `
      <h4>🌐 Netzwerk</h4>
      ${renderNetworkTable(network)}

      <h4>💾 Filesysteme</h4>
      ${renderFilesystemTable(payload.filesystems)}
    `;
  }

  return `
    <article class="report-card">
      <div class="report-header">
        <div>
          <h3>${escapeHtml(title)}</h3>
          <p class="report-subtitle">🖥️ ${escapeHtml(technicalHostname)} <span class="${chipClass}">${chipText}</span></p>
        </div>
        <span class="report-time">${escapeHtml(formatUtcPlus2(report.received_at_utc || payload.timestamp_utc))}</span>
      </div>

      <div class="meta-grid">
        <p><strong>🆔 Agent ID</strong><span>${escapeHtml(asText(report.agent_id || payload.agent_id))}</span></p>
        <p><strong>🧷 Agent Version</strong><span>${escapeHtml(asText(payload.agent_version))}</span></p>
        <p><strong>🔐 API-Key</strong><span>${escapeHtml(formatAgentApiKeyStatus(payload.agent_api_key, payload.agent_config))}</span></p>
        <p><strong>🌐 Primary IP</strong><span>${escapeHtml(asText(report.primary_ip || payload.primary_ip))}</span></p>
        <p><strong>🔌 Alle IPs</strong><span>${escapeHtml(asText(payload.all_ips))}</span></p>
        <p><strong>🐧 OS</strong><span>${escapeHtml(asText(payload.os))}</span></p>
        <p><strong>⚙️ Kernel</strong><span>${escapeHtml(asText(payload.kernel))}</span></p>
        <p><strong>⏱️ Uptime</strong><span>${escapeHtml(formatUptime(payload.uptime_seconds))}</span></p>
        <p><strong>🗃️ Queue</strong><span>${queueDepth} Dateien</span></p>
        <p><strong>🧠 CPU</strong><span>${formatPercent(cpu.usage_percent)} | load ${formatNumber(cpu.load_avg_1, 2)} / ${formatNumber(cpu.load_avg_5, 2)} / ${formatNumber(cpu.load_avg_15, 2)}</span></p>
        <p><strong>🧮 RAM</strong><span>${formatPercent(memory.used_percent)} | ${formatKilobytes(memory.used_kb)} / ${formatKilobytes(memory.total_kb)}</span></p>
        <p><strong>💤 Swap</strong><span>${formatPercent(swap.used_percent)} | ${formatKilobytes(swap.used_kb)} / ${formatKilobytes(swap.total_kb)}</span></p>
        <p><strong>🌍 Default NIC</strong><span>${escapeHtml(asText(network.default_interface))}</span></p>
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

  filtered.sort((a, b) => {
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
  const openAlertCount = Number(host.open_alert_count || 0);
  const openCriticalAlertCount = Number(host.open_critical_alert_count || 0);
  const hasOpenAlerts = openAlertCount > 0;
  const isFavorite = Boolean(host.is_favorite);
  const isHidden = Boolean(host.is_hidden);
  const hiddenClass = isHidden ? " host-item-hidden" : "";
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
    <article class="${selectedClass}${hiddenClass}" tabindex="0" role="button" data-host="${escapeHtml(hostname)}">
      ${flagIcon}
      <strong class="host-title-line">
        <span>${escapeHtml(displayName)}</span>
      </strong>
      <span>🖥️ ${escapeHtml(hostname)} &nbsp;·&nbsp; 🧷 ${escapeHtml(asText(host.agent_version))}</span>
      <span>🌐 ${escapeHtml(asText(host.primary_ip))} &nbsp;·&nbsp; 📬 ${hostDelivery} | 🗃️ Q${hostQueueDepth}</span>
      <span>🚨 ${openAlertCount} (krit. ${openCriticalAlertCount}) &nbsp;·&nbsp; 📦 ${Number(host.report_count || 0).toLocaleString("de-DE")}</span>
      <span>🕒 ${escapeHtml(formatUtcPlus2(host.last_seen_utc))}</span>
      <span class="host-card-actions">
        <button class="host-mini-action visibility${isHidden ? " active" : ""}" type="button" data-action="hidden" data-host="${escapeHtml(hostname)}" data-current="${isHidden ? "1" : "0"}" title="${isHidden ? "Einblenden" : "Ausblenden"}">${isHidden ? "👁️" : "🙈"}</button>
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

function wireHostListInteractions() {
  const hostList = document.getElementById("hostList");

  for (const item of hostList.querySelectorAll(".host-item")) {
    item.addEventListener("click", () => {
      const hostname = item.getAttribute("data-host") || "";
      if (!hostname || hostname === state.selectedHost) {
        return;
      }

      state.selectedHost = hostname;
      state.selectedDisplayName = item.querySelector("strong")?.textContent || hostname;
      state.reportOffset = 0;
      loadHosts({ preserveScroll: true });
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
    hostList.innerHTML = "<p class=\"muted\">Lade Host-Liste...</p>";
  }

  try {
    const url = `/api/v1/hosts?limit=${state.hostLimit}&offset=${state.hostOffset}`;
    const [response] = await Promise.all([
      fetch(url),
      loadAlertMutes(),
    ]);
    if (!response.ok) {
      throw new Error("HTTP " + response.status);
    }

    const data = await response.json();
    state.totalHosts = Number(data.total_hosts || 0);
    const hosts = data.hosts || [];
    state.hosts = hosts;
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
  } catch (error) {
    hostList.innerHTML = `<p class=\"muted\">Fehler: ${escapeHtml(error.message)}</p>`;
  }
}

async function loadReportsForHost() {
  const list = document.getElementById("reportList");
  const count = document.getElementById("reportCount");
  const selectedHostTitle = document.getElementById("selectedHostTitle");

  if (!state.selectedHost) {
    state.currentReport = null;
    selectedHostTitle.textContent = "🗂️ Meldungen";
    count.textContent = "";
    list.innerHTML = state.hostFilterNoMatches
      ? "<p class=\"muted\">Keine Daten zum Suchfilter vorhanden.</p>"
      : "<p class=\"muted\">Kein Host ausgewaehlt.</p>";
    updatePagerButtons();
    return;
  }

  const selectedLabel = state.selectedDisplayName || state.selectedHost;
  selectedHostTitle.textContent = `🗂️ Meldungen fuer ${selectedLabel}`;
  list.innerHTML = "<p class=\"muted\">Lade Daten...</p>";
  count.textContent = "";

  try {
    const hostNameParam = encodeURIComponent(state.selectedHost);
    const url = `/api/v1/host-reports?hostname=${hostNameParam}&limit=${state.reportLimit}&offset=${state.reportOffset}`;
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error("HTTP " + response.status);
    }

    const data = await response.json();
    state.totalReports = Number(data.total_reports || 0);
    const reports = data.reports || [];

    if (reports.length === 0) {
      state.currentReport = null;
      list.innerHTML = "<p class=\"muted\">Noch keine Daten vorhanden.</p>";
      count.textContent = `0 von ${state.totalReports} Meldungen`;
      updatePagerButtons();
      return;
    }

    const shownIndex = state.reportOffset + 1;
    count.textContent = `Meldung ${shownIndex} von ${state.totalReports}`;
    state.selectedDisplayName = String(reports[0].display_name || reports[0].hostname || state.selectedHost);
    selectedHostTitle.textContent = `🗂️ Meldungen fuer ${state.selectedDisplayName}`;
    state.currentReport = reports[0];
    list.innerHTML = renderReportCard(state.currentReport);
    updatePagerButtons();
  } catch (error) {
    state.currentReport = null;
    list.innerHTML = `<p class=\"muted\">Fehler: ${escapeHtml(error.message)}</p>`;
  }
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

  if (!state.selectedHost) {
    analysisSummary.textContent = "";
    deliveryStats.textContent = "";
    resourceCharts.innerHTML = "";
    filesystemStats.textContent = "";
    filesystemCharts.innerHTML = "";
    resourceTrendCards.innerHTML = "";
    analysisRows.innerHTML = state.hostFilterNoMatches
      ? "<tr><td colspan=\"7\" class=\"muted\">Keine Daten zum Suchfilter vorhanden.</td></tr>"
      : "<tr><td colspan=\"7\" class=\"muted\">Kein Host ausgewaehlt.</td></tr>";
    if (state.hostFilterNoMatches) {
      filesystemCharts.innerHTML = "<p class=\"muted\">Keine Daten zum Suchfilter vorhanden.</p>";
    }
    return;
  }

  analysisRows.innerHTML = "<tr><td colspan=\"7\" class=\"muted\">Lade Analyse...</td></tr>";
  resourceCharts.innerHTML = "";
  filesystemCharts.innerHTML = "";
  resourceTrendCards.innerHTML = "";
  analysisSummary.textContent = "";
  deliveryStats.textContent = "";
  filesystemStats.textContent = "";

  try {
    const hostNameParam = encodeURIComponent(state.selectedHost);
    const url = `/api/v1/analysis?hostname=${hostNameParam}&hours=${state.analysisHours}`;
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error("HTTP " + response.status);
    }

    const data = await response.json();
    const trendRows = data.filesystem_trends || [];
    const sortedTrendRows = sortFilesystemByMountpointAscending(trendRows);
    const resourceTrends = data.resource_trends || {};
    const resourceSeries = data.resource_series || {};
    const delivery = data.delivery || {};
    const latestMax = formatPercent(data.latest_max_used_percent);
    const reportCount = Number(data.report_count || 0).toLocaleString("de-DE");
    const delayedCount = Number(delivery.delayed_report_count || 0).toLocaleString("de-DE");
    const liveCount = Number(delivery.live_report_count || 0).toLocaleString("de-DE");
    const latestDelivery = deliveryLabel(delivery.latest_mode, delivery.latest_is_delayed);
    const latestQueue = queueDepthLabel(delivery.latest_queue_depth);

    analysisSummary.textContent = `${reportCount} Reports, hoechste aktuelle FS-Auslastung: ${latestMax}`;
    deliveryStats.innerHTML = [
      `<span class="stat-chip">📬 ${latestDelivery}</span>`,
      `<span class="stat-chip">Q${latestQueue}</span>`,
      `<span class="stat-chip ${Number(delivery.delayed_report_count || 0) > 0 ? 'delayed' : 'live'}">${delayedCount} delayed</span>`,
      `<span class="stat-chip live">${liveCount} live</span>`,
    ].join("");
    resourceCharts.innerHTML = renderResourceCharts(resourceSeries, data.latest_report_time_utc);
    resourceTrendCards.innerHTML = renderResourceTrendCards(resourceTrends, data.latest_report_time_utc);
    filesystemCharts.innerHTML = renderFilesystemTrendCharts(sortedTrendRows, data.latest_report_time_utc);

    const fsCurrentValues = sortedTrendRows.map((row) => Number(row.current_used_percent)).filter((value) => Number.isFinite(value));
    const fsAvgCurrent = fsCurrentValues.length > 0
      ? fsCurrentValues.reduce((sum, value) => sum + value, 0) / fsCurrentValues.length
      : null;
    const fsRising = sortedTrendRows.filter((row) => Number(row.delta_used_percent) > 0).length;
    const fsWarnOrCritical = sortedTrendRows.filter((row) => Number(row.current_used_percent) >= 80).length;
    filesystemStats.textContent = `${sortedTrendRows.length} FS-Charts | Avg aktuell: ${fsAvgCurrent === null ? "-" : formatNumber(fsAvgCurrent, 1) + "%"} | Steigend: ${fsRising} | >=80%: ${fsWarnOrCritical}`;

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
      : "<tr><td colspan=\"6\" class=\"muted\">Kein Host ausgewaehlt.</td></tr>";
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
        const muteBtn = `<button class="alert-mute-btn${isMuted ? " muted" : ""}" type="button" data-action="toggle-mute" data-hostname="${escapeHtml(asText(item.hostname))}" data-mountpoint="${escapeHtml(asText(item.mountpoint))}" data-muted="${isMuted ? "1" : "0"}" title="${isMuted ? "Stummschaltung aufheben" : "Alert stummschalten"}">${isMuted ? "🔔" : "🔇"}</button>`;
        return `
          <tr class="${isMuted ? "alert-row-muted" : ""}">
            <td><span class="badge ${statusClass}">${escapeHtml(asText(item.status))}</span></td>
            <td><span class="badge ${severityClass}">${escapeHtml(asText(item.severity))}</span></td>
            <td>${renderPathCell(item.mountpoint, 60)}</td>
            <td>${formatPercent(item.used_percent)}</td>
            <td>${escapeHtml(formatUtcPlus2(item.last_seen_at_utc))}</td>
            <td>${muteBtn}</td>
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
  } catch (error) {
    alertsRows.innerHTML = `<tr><td colspan="6" class="muted">Fehler: ${escapeHtml(error.message)}</td></tr>`;
  }
}

function renderCriticalTrends(data) {
  const { warnings, hours } = data;
  if (!warnings || warnings.length === 0) {
    return `<div class="ct-empty"><span class="ct-empty-icon">✓</span><p>Keine kritischen Trends im Zeitraum der letzten ${hours} Std. erkannt.</p></div>`;
  }

  // Group by hostname
  const byHost = new Map();
  for (const w of warnings) {
    if (!byHost.has(w.hostname)) byHost.set(w.hostname, []);
    byHost.get(w.hostname).push(w);
  }

  const critCount = warnings.filter((w) => w.level === "crit").length;
  const warnCount = warnings.filter((w) => w.level === "warn").length;

  const summary = `
    <div class="ct-summary">
      <span class="ct-summary-label">Zeitraum: letzte ${hours} Std.</span>
      ${critCount > 0 ? `<span class="ct-badge ct-badge-crit">${critCount} Kritisch</span>` : ""}
      ${warnCount > 0 ? `<span class="ct-badge ct-badge-warn">${warnCount} Warnung</span>` : ""}
      <span class="ct-summary-label">${byHost.size} betroffene Host${byHost.size !== 1 ? "s" : ""}</span>
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
      const icon = w.type === "filesystem" ? "💾" : "📊";
      const diff = w.current !== null ? w.projected - w.current : 0;
      const trendArrow = diff > 0.05
        ? `<span class="ct-trend-arrow ct-trend-up">🔺</span>`
        : diff < -0.05
          ? `<span class="ct-trend-arrow ct-trend-down">🔻</span>`
          : `<span class="ct-trend-arrow ct-trend-flat">➖</span>`;
      return `
        <div class="ct-row ct-row-${w.level}">
          <span class="ct-row-icon">${icon}</span>
          <span class="ct-row-metric">${escapeHtml(w.metric)}</span>
          <span class="ct-row-current">Aktuell: <strong>${w.current !== null ? w.current.toFixed(1) + "%" : "–"}</strong></span>
          <span class="ct-row-arrow">·</span>
          <span class="ct-row-projected ct-projected-${w.level}">${trendArrow} Projektion: <strong>${w.projected.toFixed(1)}%</strong></span>
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

async function loadCriticalTrends() {
  const listEl = document.getElementById("criticalTrendsList");
  const tabButton = document.getElementById("criticalTrendsTabButton");
  if (!listEl) return;

  listEl.innerHTML = "<p class=\"muted\">Lade Trend-Daten…</p>";
  try {
    const response = await fetch(`/api/v1/critical-trends?hours=${state.criticalTrendsHours}`, {
      credentials: "same-origin",
    });
    if (!response.ok) throw new Error("HTTP " + response.status);
    const data = await response.json();
    listEl.innerHTML = renderCriticalTrends(data);

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
    listEl.innerHTML = `<p class="muted">Fehler beim Laden: ${escapeHtml(error.message)}</p>`;
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

async function loadInactiveHosts() {
  const listEl = document.getElementById("inactiveHostsList");
  const tabButton = document.getElementById("inactiveHostsTabButton");
  if (!listEl) return;

  listEl.innerHTML = "<p class=\"muted\">Lade Daten…</p>";
  try {
    const response = await fetch(`/api/v1/inactive-hosts?hours=${state.inactiveHostsHours}`, {
      credentials: "same-origin",
    });
    if (!response.ok) throw new Error("HTTP " + response.status);
    const data = await response.json();
    state.inactiveHosts = data.inactive_hosts || [];
    listEl.innerHTML = renderInactiveHosts(data);

    const total = (data.total || 0);
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
    listEl.innerHTML = `<p class="muted">Fehler beim Laden: ${escapeHtml(error.message)}</p>`;
  }
}

function updateHeaderStatChips() {
  const alertChip = document.getElementById("headerAlertChip");
  const alertCount = document.getElementById("headerAlertCount");
  const trendsChip = document.getElementById("headerTrendsChip");
  const trendsCount = document.getElementById("headerTrendsCount");
  if (alertChip && alertCount) {
    alertCount.textContent = String(state.globalOpenAlertsCount);
    alertChip.classList.toggle("hidden", state.globalOpenAlertsCount === 0);
  }
  if (trendsChip && trendsCount) {
    trendsCount.textContent = String(state.criticalTrendsCount);
    trendsChip.classList.toggle("hidden", state.criticalTrendsCount === 0);
  }
}

async function loadGlobalAlertsOverview() {
  const summaryEl = document.getElementById("globalAlertsSummary");
  const rowsEl = document.getElementById("globalAlertsRows");
  const globalAlertsTabButton = document.getElementById("globalAlertsTabButton");
  const toggleButton = document.getElementById("toggleGlobalAlertsPanelButton");
  const panelBody = document.getElementById("globalAlertsPanelBody");

  rowsEl.innerHTML = "<tr><td colspan=\"6\" class=\"muted\">Lade globale Alerts...</td></tr>";
  summaryEl.textContent = "";
  panelBody.classList.toggle("hidden", state.globalAlertsCollapsed);
  toggleButton.textContent = state.globalAlertsCollapsed ? "▸" : "▾";

  try {
    const [summaryResp, listResp] = await Promise.all([
      fetch("/api/v1/alerts-summary"),
      fetch("/api/v1/alerts?status=open&limit=100&offset=0"),
    ]);

    if (!summaryResp.ok) {
      throw new Error("Summary HTTP " + summaryResp.status);
    }
    if (!listResp.ok) {
      throw new Error("List HTTP " + listResp.status);
    }

    const summaryData = await summaryResp.json();
    const listData = await listResp.json();
    const allOpenAlerts = listData.alerts || [];
    state.globalOpenAlertsCount = Number(summaryData?.open?.total || 0);

    globalAlertsTabButton.textContent = state.globalOpenAlertsCount > 0
      ? `Globale Alerts (${state.globalOpenAlertsCount})`
      : "Globale Alerts";
    globalAlertsTabButton.classList.toggle("alert-active", state.globalOpenAlertsCount > 0);
    updateHeaderStatChips();

    const alerts = allOpenAlerts.filter((item) => {
      if (state.globalSeverityFilter === "all") {
        return true;
      }
      return String(item.severity || "") === state.globalSeverityFilter;
    });

    summaryEl.textContent = `Offen: ${summaryData.open.total} (kritisch ${summaryData.open.critical}, warn ${summaryData.open.warning}) | Filter: ${state.globalSeverityFilter === "all" ? "alle" : state.globalSeverityFilter}`;

    if (alerts.length === 0) {
      rowsEl.innerHTML = "<tr><td colspan=\"6\" class=\"muted\">Keine offenen Alerts fuer den gesetzten Filter.</td></tr>";
      return;
    }

    rowsEl.innerHTML = alerts
      .map((item) => {
        const severityClass = item.severity === "critical" ? "severity-critical" : "severity-warning";
        const hostDisplayName = asText(item.display_name || item.hostname);
        const hostName = asText(item.hostname);
        const isMuted = Boolean(item.is_muted);
        const muteBtn = `<button class="alert-mute-btn${isMuted ? " muted" : ""}" type="button" data-action="toggle-mute" data-hostname="${escapeHtml(hostName)}" data-mountpoint="${escapeHtml(asText(item.mountpoint))}" data-muted="${isMuted ? "1" : "0"}" title="${isMuted ? "Stummschaltung aufheben" : "Alert stummschalten"}">${isMuted ? "🔔" : "🔇"}</button>`;
        return `
          <tr class="${isMuted ? "alert-row-muted" : ""}">
            <td>
              <div class="global-host-cell">
                <span class="global-host-label">${escapeHtml(hostDisplayName)}</span>
                <span class="global-hostname-sub">(${escapeHtml(hostName)})</span>
              </div>
            </td>
            <td><span class="badge ${severityClass}">${escapeHtml(asText(item.severity))}</span></td>
            <td>${renderPathCell(item.mountpoint, 56)}</td>
            <td>${formatPercent(item.used_percent)}</td>
            <td>${escapeHtml(formatUtcPlus2(item.last_seen_at_utc))}</td>
            <td>${muteBtn}</td>
          </tr>
        `;
      })
      .join("");

    rowsEl.querySelectorAll("[data-action='toggle-mute']").forEach((btn) => {
      btn.addEventListener("click", async (e) => {
        e.stopPropagation();
        const hostname = btn.getAttribute("data-hostname");
        const mountpoint = btn.getAttribute("data-mountpoint");
        const isMuted = btn.getAttribute("data-muted") === "1";
        await toggleAlertMute(hostname, mountpoint, isMuted);
      });
    });
  } catch (error) {
    rowsEl.innerHTML = `<tr><td colspan="6" class="muted">Fehler: ${escapeHtml(error.message)}</td></tr>`;
    globalAlertsTabButton.textContent = "Globale Alerts";
    globalAlertsTabButton.classList.remove("alert-active");
  }
}

function wireEvents() {
  const themeToggleButton = document.getElementById("themeToggleButton");
  if (themeToggleButton) {
    themeToggleButton.addEventListener("click", () => {
      toggleTheme();
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
    await loadCriticalTrends();
  });

  document.getElementById("inactiveHostsTabButton").addEventListener("click", async () => {
    state.globalSubMode = "inactive-hosts";
    updateGlobalSubMode();
    await loadInactiveHosts();
  });

  const globalAdminAlertSubsTabButton = document.getElementById("globalAdminAlertSubsTabButton");
  if (globalAdminAlertSubsTabButton) {
    globalAdminAlertSubsTabButton.addEventListener("click", async () => {
      state.globalSubMode = "admin-alert-subs";
      updateGlobalSubMode();
      await loadAdminAlertSubscriptions();
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
    else if (state.globalSubMode === "admin-alert-subs") await loadAdminAlertSubscriptions();
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

  document.getElementById("refreshInactiveHostsButton").addEventListener("click", async () => {
    await loadInactiveHosts();
  });

  document.getElementById("inactiveHostsRangeSelect").addEventListener("change", async (event) => {
    state.inactiveHostsHours = Number(event.target.value) || 3;
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

  document.getElementById("openChangePasswordButton").addEventListener("click", () => {
    document.getElementById("changePasswordModal").classList.remove("hidden");
    setPasswordChangeStatus("");
  });

  document.getElementById("logoutButton").addEventListener("click", async () => {
    await logoutWebClient();
  });

  document.getElementById("cancelPasswordButton").addEventListener("click", () => {
    document.getElementById("changePasswordModal").classList.add("hidden");
  });

  document.getElementById("savePasswordButton").addEventListener("click", async () => {
    await changePassword();
  });

  document.getElementById("globalSeverityFilter").addEventListener("change", async (event) => {
    state.globalSeverityFilter = String(event.target?.value || "all");
    await loadGlobalAlertsOverview();
  });

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
  });

  document.getElementById("openAlarmSettingsButton").addEventListener("click", async () => {
    state.viewMode = "settings";
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
  loadHostFilterPreferences();
  applyTheme(loadThemePreference());
  updateAutoRefreshStatus(null);
  const oauthResult = consumeOauthStatusFromUrl();
  await loadWebclientVersion();
  wireEvents();
  updateViewMode();
  updateOverviewSection();
  updateAnalysisRangeUi();
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
  if (oauthResult) {
    state.viewMode = "settings";
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
}

init();
