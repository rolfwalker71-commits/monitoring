// Republish marker: app.js refreshed for deploy verification
function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function formatApiLoadError(message, fallbackLabel = "Daten") {
  const text = String(message || "").trim();
  if (/502/.test(text)) {
    return `Gateway-Fehler (502): ${fallbackLabel} vorübergehend nicht verfügbar. Bitte in 30 Sekunden erneut laden.`;
  }
  if (/503/.test(text)) {
    return `Server vorübergehend überlastet (503). Bitte kurz warten und erneut laden.`;
  }
  return text.startsWith("HTTP ") ? `Fehler beim Laden: ${text}` : text;
}

function resolveHostOsIcon(osValue) {
  const osRaw = asText(osValue || "", "").toLowerCase();
  if (osRaw.includes("windows")) {
    return { iconName: "windows.png", osLabel: "Windows" };
  }

  const distroMappings = [
    { iconName: "ubuntu.png", keywords: ["ubuntu"] },
    { iconName: "debian.png", keywords: ["debian"] },
    { iconName: "suse.png", keywords: ["suse", "opensuse", "sles"] },
  ];

  for (const mapping of distroMappings) {
    if (mapping.keywords.some((keyword) => osRaw.includes(keyword))) {
      return { iconName: mapping.iconName, osLabel: "Linux" };
    }
  }

  return { iconName: "linux.png", osLabel: "Linux" };
}

const ANALYSIS_RANGE_STORAGE_KEY = "monitoring.analysisHours";
const THEME_STORAGE_KEY = "monitoring.theme";
const HOST_FILTERS_STORAGE_KEY_PREFIX = "monitoring.hostFilters.";
const AUTO_REFRESH_STORAGE_KEY = "monitoring.autoRefreshInterval";
const ADMIN_UI_STATE_STORAGE_KEY = "monitoring.adminUiState";
const AUTO_REFRESH_INTERVAL_OPTIONS = new Map([
  [30, "30 Sek."],
  [60, "1 Min."],
  [300, "5 Min."],
  [480, "8 Min."],
  [0, "Aus"],
]);
const REPORT_SECTION_OPTIONS = new Set(["overview", "journal", "processes", "logfiles", "containers", "sap-b1-systeminfo", "agent-update", "dir-listings", "network", "filesystems", "databases"]);

let SAP_B1_VERSION_MAP = new Map([
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

let SAP_LICENSE_TYPE_MAP = [
  { matchText: "CRM-LTD", displayName: "Limited CRM", visible: true },
  { matchText: "LOGISTICS-LTD", displayName: "Logistics CRM", visible: true },
  { matchText: "PROFESSIONAL", displayName: "Professional", visible: true },
  { matchText: "FINANCE-LTD", displayName: "Limited Finance", visible: true },
];

const SAP_B1_HANA_PROCESS_RE = /\b(hdbindexserver|hdbnameserver|hdbscriptserver|hdbxsengine|hdbcompileserver|hdbpreprocessor|hdbwebdispatcher|hdbdaemon|hdbrsutil|sapstartsrv|hdb[a-z0-9_-]+)\b/i;

let autoRefreshTimerId = null;
let autoRefreshInProgress = false;
let autoRefreshCurrentIntervalSec = 480;
let autoRefreshLastRefreshAt = null;
let autoRefreshCountdownTimerId = null;
let sessionRefreshTimerId = null;
let sessionCountdownTimerId = null;
let hostSearchFilterDebounceTimerId = null;
let systemOverviewSearchDebounceTimerId = null;
let hostLicenseHoverPopupEl = null;
let hostLicenseHoverActiveHost = "";
let hostLicenseHoverPinnedKey = "";
let hostLicenseOutsideClickWired = false;
let hostLicenseSuppressOutsideCloseUntil = 0;
let changelogRebuildPollTimerId = null;
const CHANGELOG_REBUILD_DAYS = 7;
const CHANGELOG_MAINTENANCE_PANEL_OPEN_KEY = "monitoring.changelogMaintenancePanelOpen";
let headerKpiWidthSyncFrameId = null;
let headerKpiTrendPreviousValues = null;
const LIVE_REPORT_FEED_ENABLED_KEY = "monitoring.liveReportFeedEnabled";
const LIVE_REPORT_POLL_INTERVAL_MS = 10000;
let liveReportFeedItems = [];
let liveReportFeedEnabled = true;
let liveReportFeedWired = false;
let liveReportPollTimerId = null;
let liveReportPollCursorId = 0;
let liveReportPollInFlight = false;
const HEADER_KPI_WIDTH_STORAGE_KEY = "monitoring.headerKpiUniformWidth";
const HEADER_SECTIONS_STORAGE_KEY_PREFIX = "monitoring.headerSections.";
const LEGACY_HEADER_KPI_SECTION_OPEN_KEY = "monitoring.headerKpiSectionOpen";
const LEGACY_HEADER_FILTERS_SECTION_OPEN_KEY = "monitoring.headerFiltersSectionOpen";
const DEFAULT_HEADER_SECTION_PREFS = {
  kpiOpen: true,
  filtersOpen: false,
};
let headerSectionCollapsiblesWired = false;
const HEADER_KPI_DEFAULT_WIDTH_PX = 142;
const HEADER_KPI_MIN_WIDTH_PX = 104;
const HEADER_KPI_MAX_WIDTH_PX = 190;
const hostLicenseHoverCache = new Map();
const SESSION_REFRESH_INTERVAL_SECONDS = 240;
const SESSION_LOGIN_GRACE_MS = 20000;
let sessionEstablishedAtMs = 0;

function resolveHeaderKpiTrendDirection(previousValue, currentValue) {
  if (!Number.isFinite(previousValue) || !Number.isFinite(currentValue)) {
    return "flat";
  }
  if (currentValue > previousValue) {
    return "up";
  }
  if (currentValue < previousValue) {
    return "down";
  }
  return "flat";
}

function ensureHeaderKpiTrendArrow(countElement) {
  if (!countElement) {
    return null;
  }
  const existing = countElement.querySelector(":scope > .header-chip-trend");
  if (existing) {
    return existing;
  }
  const trendEl = document.createElement("span");
  trendEl.className = "header-chip-trend header-chip-trend-flat";
  trendEl.setAttribute("aria-hidden", "true");
  countElement.appendChild(trendEl);
  return trendEl;
}

function setHeaderKpiTrendArrow(chipElement, countElement, direction) {
  const trendEl = ensureHeaderKpiTrendArrow(countElement);
  if (!chipElement || !trendEl) {
    return;
  }
  const safeDirection = direction === "up" || direction === "down" ? direction : "flat";
  trendEl.classList.remove("header-chip-trend-up", "header-chip-trend-down", "header-chip-trend-flat");
  trendEl.classList.add(`header-chip-trend-${safeDirection}`);
  trendEl.textContent = safeDirection === "up" ? "↑" : safeDirection === "down" ? "↓" : "→";
  chipElement.setAttribute("data-kpi-trend", safeDirection);
}

function clampHeaderKpiWidth(widthValue) {
  const numeric = Number(widthValue || 0);
  if (!Number.isFinite(numeric) || numeric <= 0) {
    return 0;
  }
  return Math.max(HEADER_KPI_MIN_WIDTH_PX, Math.min(HEADER_KPI_MAX_WIDTH_PX, Math.round(numeric)));
}

function readStoredHeaderKpiWidth() {
  try {
    return clampHeaderKpiWidth(window.localStorage.getItem(HEADER_KPI_WIDTH_STORAGE_KEY));
  } catch {
    return 0;
  }
}

function persistHeaderKpiWidth(widthValue) {
  const clamped = clampHeaderKpiWidth(widthValue);
  if (!clamped) {
    return;
  }
  try {
    window.localStorage.setItem(HEADER_KPI_WIDTH_STORAGE_KEY, String(clamped));
  } catch {
    // Storage might be unavailable in hardened browser contexts.
  }
}

function getHeaderSectionsStorageKey() {
  const username = String(state.authUser || "").trim().toLowerCase();
  if (!username) {
    return "";
  }
  return `${HEADER_SECTIONS_STORAGE_KEY_PREFIX}${username}`;
}

function normalizeHeaderSectionOpenValue(value, defaultOpen) {
  if (value === undefined || value === null || value === "") {
    return defaultOpen;
  }
  if (typeof value === "boolean") {
    return value;
  }
  const normalized = String(value).trim().toLowerCase();
  if (normalized === "1" || normalized === "true" || normalized === "yes" || normalized === "on") {
    return true;
  }
  if (normalized === "0" || normalized === "false" || normalized === "no" || normalized === "off") {
    return false;
  }
  return defaultOpen;
}

function readLegacyHeaderSectionOpenPreference(storageKey, defaultOpen) {
  try {
    const raw = window.localStorage.getItem(storageKey);
    if (raw === null || raw === undefined || raw === "") {
      return defaultOpen;
    }
    return normalizeHeaderSectionOpenValue(raw, defaultOpen);
  } catch {
    return defaultOpen;
  }
}

function loadHeaderSectionPreferences() {
  const defaults = {
    kpiOpen: DEFAULT_HEADER_SECTION_PREFS.kpiOpen,
    filtersOpen: DEFAULT_HEADER_SECTION_PREFS.filtersOpen,
  };
  const storageKey = getHeaderSectionsStorageKey();
  if (!storageKey) {
    return defaults;
  }

  try {
    const raw = window.localStorage.getItem(storageKey);
    if (!raw) {
      const migrated = {
        kpiOpen: readLegacyHeaderSectionOpenPreference(
          LEGACY_HEADER_KPI_SECTION_OPEN_KEY,
          defaults.kpiOpen,
        ),
        filtersOpen: readLegacyHeaderSectionOpenPreference(
          LEGACY_HEADER_FILTERS_SECTION_OPEN_KEY,
          defaults.filtersOpen,
        ),
      };
      window.localStorage.setItem(storageKey, JSON.stringify(migrated));
      return migrated;
    }
    const saved = JSON.parse(raw);
    return {
      kpiOpen: normalizeHeaderSectionOpenValue(saved.kpiOpen, defaults.kpiOpen),
      filtersOpen: normalizeHeaderSectionOpenValue(saved.filtersOpen, defaults.filtersOpen),
    };
  } catch {
    return defaults;
  }
}

function persistHeaderSectionPreferences(updates = {}) {
  const storageKey = getHeaderSectionsStorageKey();
  if (!storageKey) {
    return;
  }
  const current = loadHeaderSectionPreferences();
  const next = {
    kpiOpen: normalizeHeaderSectionOpenValue(
      updates.kpiOpen !== undefined ? updates.kpiOpen : current.kpiOpen,
      current.kpiOpen,
    ),
    filtersOpen: normalizeHeaderSectionOpenValue(
      updates.filtersOpen !== undefined ? updates.filtersOpen : current.filtersOpen,
      current.filtersOpen,
    ),
  };
  try {
    window.localStorage.setItem(storageKey, JSON.stringify(next));
  } catch {
    // Storage might be unavailable in hardened browser contexts.
  }
}

function applyHeaderSectionExpanded(toggleButton, bodyElement, collapsibleElement, expanded) {
  if (!toggleButton || !bodyElement) {
    return;
  }
  const isExpanded = expanded === true;
  toggleButton.setAttribute("aria-expanded", isExpanded ? "true" : "false");
  bodyElement.classList.toggle("hidden", !isExpanded);
  if (collapsibleElement) {
    collapsibleElement.classList.toggle("is-expanded", isExpanded);
  }
  const chevron = toggleButton.querySelector(".header-collapsible-chevron");
  if (chevron) {
    chevron.textContent = isExpanded ? "▼" : "▶";
  }
}

function applyHeaderSectionPreferences() {
  const prefs = loadHeaderSectionPreferences();
  const kpiToggle = document.getElementById("toggleHeaderKpiSection");
  const kpiBody = document.getElementById("headerKpiSectionBody");
  const kpiCollapsible = document.getElementById("headerKpiCollapsible");
  const filtersToggle = document.getElementById("toggleHeaderFiltersSection");
  const filtersBody = document.getElementById("headerFiltersSectionBody");
  const filtersCollapsible = document.getElementById("headerFiltersCollapsible");

  if (kpiToggle && kpiBody) {
    applyHeaderSectionExpanded(kpiToggle, kpiBody, kpiCollapsible, prefs.kpiOpen);
    if (prefs.kpiOpen) {
      scheduleHeaderKpiUniformCardWidthSync();
    }
  }
  if (filtersToggle && filtersBody) {
    applyHeaderSectionExpanded(filtersToggle, filtersBody, filtersCollapsible, prefs.filtersOpen);
  }
}

function wireHeaderSectionCollapsibles() {
  if (headerSectionCollapsiblesWired) {
    return;
  }

  const kpiToggle = document.getElementById("toggleHeaderKpiSection");
  const kpiBody = document.getElementById("headerKpiSectionBody");
  const kpiCollapsible = document.getElementById("headerKpiCollapsible");
  const filtersToggle = document.getElementById("toggleHeaderFiltersSection");
  const filtersBody = document.getElementById("headerFiltersSectionBody");
  const filtersCollapsible = document.getElementById("headerFiltersCollapsible");

  if (kpiToggle && kpiBody) {
    kpiToggle.addEventListener("click", () => {
      const nextOpen = kpiBody.classList.contains("hidden");
      applyHeaderSectionExpanded(kpiToggle, kpiBody, kpiCollapsible, nextOpen);
      persistHeaderSectionPreferences({ kpiOpen: nextOpen });
      if (nextOpen) {
        scheduleHeaderKpiUniformCardWidthSync();
      }
    });
  }

  if (filtersToggle && filtersBody) {
    filtersToggle.addEventListener("click", () => {
      const nextOpen = filtersBody.classList.contains("hidden");
      applyHeaderSectionExpanded(filtersToggle, filtersBody, filtersCollapsible, nextOpen);
      persistHeaderSectionPreferences({ filtersOpen: nextOpen });
    });
  }

  headerSectionCollapsiblesWired = true;
}

function initHeaderSectionCollapsibles() {
  wireHeaderSectionCollapsibles();
  applyHeaderSectionPreferences();
}

function reloadHeaderSectionPreferencesForUser() {
  applyHeaderSectionPreferences();
}

function applyInitialHeaderKpiWidth() {
  const strips = Array.from(document.querySelectorAll(".panel-header .panel-actions .header-kpi-strip"));
  if (strips.length === 0) {
    return;
  }
  const storedWidth = readStoredHeaderKpiWidth();
  const initialWidth = clampHeaderKpiWidth(storedWidth || HEADER_KPI_DEFAULT_WIDTH_PX);
  for (const strip of strips) {
    if (strip.querySelector(".header-kpi-group")) {
      strip.style.removeProperty("--kpi-uniform-card-width");
      continue;
    }
    if (!strip.style.getPropertyValue("--kpi-uniform-card-width")) {
      strip.style.setProperty("--kpi-uniform-card-width", `${initialWidth}px`);
    }
  }
}

function syncHeaderKpiUniformCardWidth() {
  const strips = Array.from(document.querySelectorAll(".panel-header .panel-actions .header-kpi-strip"));
  const storedWidth = readStoredHeaderKpiWidth();
  let widthToPersist = 0;
  for (const strip of strips) {
    if (strip.querySelector(".header-kpi-group")) {
      strip.style.removeProperty("--kpi-uniform-card-width");
      continue;
    }
    const cssCurrent = parseFloat(strip.style.getPropertyValue("--kpi-uniform-card-width") || "0");
    const currentWidth = clampHeaderKpiWidth(cssCurrent || storedWidth || HEADER_KPI_DEFAULT_WIDTH_PX);
    const cards = Array.from(
      strip.querySelectorAll(":scope > .header-stat-chip:not(.header-stat-chip-license):not(.hidden)")
    );
    let nextWidth = currentWidth;
    if (cards.length === 0) {
      strip.style.setProperty("--kpi-uniform-card-width", `${nextWidth}px`);
      widthToPersist = Math.max(widthToPersist, nextWidth);
      continue;
    }
    let maxMeasuredWidth = 0;
    for (const card of cards) {
      const renderedWidth = Math.ceil(card.getBoundingClientRect().width || 0);
      const naturalContentWidth = Math.ceil(card.scrollWidth || 0) + 2;
      const width = Math.max(renderedWidth, naturalContentWidth);
      if (width > maxMeasuredWidth) {
        maxMeasuredWidth = width;
      }
    }
    if (maxMeasuredWidth > 0) {
      const desiredWidth = clampHeaderKpiWidth(maxMeasuredWidth);
      const stripWidth = Math.floor(strip.clientWidth || 0);
      const totalGap = Math.max(0, (cards.length - 1) * 6);
      const fitWidth = stripWidth > totalGap ? Math.floor((stripWidth - totalGap) / cards.length) : 0;
      const fitClampedWidth = clampHeaderKpiWidth(fitWidth);
      if (fitClampedWidth > 0) {
        // Keep cards in one row by honoring the available strip width cap.
        nextWidth = Math.min(desiredWidth, fitClampedWidth);
      } else {
        nextWidth = desiredWidth;
      }
    }
    strip.style.setProperty("--kpi-uniform-card-width", `${nextWidth}px`);
    widthToPersist = Math.max(widthToPersist, nextWidth);
  }
  if (widthToPersist > 0) {
    persistHeaderKpiWidth(widthToPersist);
  }
}

function scheduleHeaderKpiUniformCardWidthSync() {
  if (headerKpiWidthSyncFrameId !== null) {
    window.cancelAnimationFrame(headerKpiWidthSyncFrameId);
  }
  headerKpiWidthSyncFrameId = window.requestAnimationFrame(() => {
    headerKpiWidthSyncFrameId = null;
    syncHeaderKpiUniformCardWidth();
  });
}

const state = {
  hostLimit: 200,
  hostOffset: 0,
  reportLimit: 1,
  reportOffset: 0,
  totalReports: 0,
  hostReportMeta: null,
  currentReport: null,
  reportSection: "overview",
  analysisHours: 24,
  hosts: [],
  totalHosts: 0,
  selectedHost: "",
  selectedHostUid: "",
  selectedDisplayName: "",
  hostSearchQuery: "",
  hostOsFilter: "all",
  hostCountryFilter: "all",
  hostSortMode: "customer_alpha",
  systemOverviewCountryFilter: "all",
  systemOverviewSearchQuery: "",
  systemOverviewAddonsExpanded: false,
  systemOverviewSortMode: "country-os-host",
  viewMode: "overview",
  userSettingsSubMode: "password",
  overviewSection: "main",
  globalSubMode: "global-alerts",
  adminSubMode: "agent-source-status",
  adminSettingsSubMode: "operations",
  adminOperationsSubMode: "quick",
  criticalTrendsHours: 24,
  criticalTrendsProjectHours: 72,
  criticalTrendsMetrics: ["filesystem"],
  inactiveHostsHours: 1,
  hostConfigChangesHours: 72,
  hostConfigChangesSearchQuery: "",
  hostConfigChangesCountryFilter: "all",
  hostConfigChangesAvailableCountries: [],
  changelogActiveJobId: 0,
  changelogActiveJobStatus: "",
  inactiveHosts: [],
  alarmSettingsLoaded: false,
  globalAlertsCollapsed: false,
  globalAlertsOffset: 0,
  globalAlertsTotal: 0,
  globalAlertsPageSize: 100,
  globalShowAcknowledged: true,
  globalShowClosed: false,
  globalShowMutedOnly: false,
  globalHeadsUpBaselineCollapsed: false,
  globalHeadsUpBaselineCount: 0,
  hostAlertsCollapsed: true,
  hostAlertsCollapseHostKey: "",
  hostAlertsUserToggled: false,
  globalSeverityFilter: "all",
  globalCountryFilter: "all",
  globalAvailableCountries: [],
  globalOpenAlertsCount: 0,
  globalCriticalOpenAlertsCount: 0,
  globalAcknowledgedOpenAlertsCount: 0,
  globalMutedOpenAlertsCount: 0,
  globalHeadsUpSuppressedOpenAlertsCount: 0,
  criticalTrendsCount: 0,
  inactiveHostsCount: 0,
  dbReportsTotal: null,
  dbReportsLastHour: 0,
  dbTotalFileBytes: null,
  dbSizeDelta1hBytes: null,
  authUser: "",
  authDisplayName: "",
  isAuthenticated: false,
  sessionExpiresAtUtc: "",
  sessionInactivityTimeoutMinutes: 30,
  visibleHosts: 0,
  hiddenHosts: 0,
  hiddenHostsCollapsed: true,
  hiddenHostMutedAlertsCollapsed: {},
  hostChipDebugLoggedHosts: new Set(),
  mutedAlertsByHost: {},
  latestAgentRelease: "",
  agentUpdateStatusLoaded: false,
  isAdmin: false,
  userProfileLoaded: false,
  oauthSettingsLoaded: false,
  userManagementLoaded: false,
  hostFilterNoMatches: false,
  hostInterestMode: "all",
  hostInterestCountryCodes: new Set(),
  hostInterestHostAdditions: new Set(),
  hostInterestHostExclusions: new Set(),
  hostInterestHosts: new Set(),
  hostInterestTargetHosts: [],
  hostInterestTargetsLoaded: false,
  hostInterestTargetsLoading: false,
  hostInterestTargetsLoadingPromise: null,
  hostInterestsLoadedFor: "",
  hostInterestSearchQuery: "",
  hostInterestShowUnselectedOnly: false,
  adminAlertSubscriptionsLoaded: false,
  adminAlertSubscriptionsViewMode: "user-focus",
  adminAlertSubscriptionsSelectedUser: "",
  adminAlertSubscriptionsUsers: [],
  adminAlertAvailableHosts: [],
  adminAlertTelegramAvailable: false,
  agentUpdateStatusHosts: [],
  agentSilentThresholdHours: 6,
  pushSupported: false,
  pushConfigured: false,
  pushEnabled: false,
  pushLoading: false,
  pushVapidPublicKey: "",
  fsVisibilityEditable: false,
  fsFocusHiddenMountpoints: [],
  largeFilesHiddenMountpoints: [],
  fsFocusAvailableMountpoints: [],
  largeFilesAvailableMountpoints: [],
  fsVisibilitySection: "",
  alertMutesRefreshInFlight: false,
  backupStatusData: null,
  backupStatusFilterSql: false,
  backupStatusFilterHana: false,
  backupStatusCountryFilter: "all",
  agentSourceStatusLoaded: false,
  filesystemBlacklistPatterns: [],
  showBlacklistedFilesystems: false,
  sapB1VmapDirty: false,
  sapLicenseTypeMapDirty: false,
  sapB1VmapBeforeUnloadWired: false,
  backupAutomationLoaded: false,
  mutedAlertsSignature: "",
  deferredDashboardTasksInFlight: false,
  hostListDelegatedWired: false,
  alertRowActionsDelegated: false,
  // Add a new user type "readOnly" to the state
  userType: "default", // Possible values: "default", "readOnly", "admin"
};

function resolveHostIdentity(host) {
  const hostUid = asText(host?.host_uid, "").trim();
  const hostname = asText(host?.hostname, "").trim();
  return hostUid || hostname;
}

function getSelectedHostRecord() {
  if (!Array.isArray(state.hosts) || state.hosts.length === 0) {
    return null;
  }
  const selectedIdentity = asText(state.selectedHostUid, "").trim() || asText(state.selectedHost, "").trim();
  if (!selectedIdentity) {
    return null;
  }
  return state.hosts.find((host) => resolveHostIdentity(host) === selectedIdentity) || null;
}

function hasSapB1VersionMapUnsavedChanges() {
  return state.viewMode === "global"
    && state.globalSubMode === "admin-settings"
    && (state.sapB1VmapDirty || state.sapLicenseTypeMapDirty);
}

function markSapB1VersionMapDirty(isDirty) {
  state.sapB1VmapDirty = Boolean(isDirty);
}

function markSapLicenseTypeMapDirty(isDirty) {
  state.sapLicenseTypeMapDirty = Boolean(isDirty);
}

function confirmDiscardSapB1VersionMapChanges() {
  if (!hasSapB1VersionMapUnsavedChanges()) {
    return true;
  }
  const ok = window.confirm("Ungespeicherte Änderungen in den Admin-Mappings verwerfen?");
  if (ok) {
    markSapB1VersionMapDirty(false);
    markSapLicenseTypeMapDirty(false);
  }
  return ok;
}

function normalizeHostInterestMode(value) {
  const mode = String(value || "all").trim().toLowerCase();
  if (mode === "interested_first" || mode === "interested_only") {
    return mode;
  }
  return "all";
}

const ADMIN_SUBMODE_TO_GLOBAL_MAP = {
  "agent-source-status": "agent-source-status",
  "admin-alert-subs": "admin-alert-subs",
  "admin-login-audit": "admin-login-audit",
  "admin-settings": "admin-settings",
};

const GLOBAL_TO_ADMIN_SUBMODE_MAP = Object.fromEntries(
  Object.entries(ADMIN_SUBMODE_TO_GLOBAL_MAP).map(([adminSubMode, globalSubMode]) => [globalSubMode, adminSubMode])
);

const ADMIN_SETTINGS_GROUP_TO_SECTION_IDS = {
  operations: ["globalAdminOpsSection"],
  security: ["adminUserManagementSection", "adminOauthSettingsSection"],
  alerting: ["globalAlarmSettingsSection", "customerAlertTestSection"],
  sap: ["sapB1VersionMapAdminSection", "sapLicenseTypeMapAdminSection"],
  data: ["filesystemBlacklistAdminSection"],
};

const ADMIN_OPERATIONS_GROUP_TO_SECTION_IDS = {
  quick: ["adminOpsQuickGroup"],
  database: ["adminOpsDbMaintenanceCard"],
  ingest: ["adminOpsIngestCard"],
  backup: ["adminOpsBackupCard"],
  agents: ["adminOpsAgentUpdateCard"],
};

function normalizeAdminSubMode(value) {
  const mode = String(value || "").trim();
  if (Object.prototype.hasOwnProperty.call(ADMIN_SUBMODE_TO_GLOBAL_MAP, mode)) {
    return mode;
  }
  return "agent-source-status";
}

function syncAdminSubModeFromGlobal() {
  const mapped = GLOBAL_TO_ADMIN_SUBMODE_MAP[state.globalSubMode];
  if (mapped) {
    state.adminSubMode = mapped;
  }
}

function setAdminSubMode(mode) {
  const normalized = normalizeAdminSubMode(mode);
  state.adminSubMode = normalized;
  state.globalSubMode = ADMIN_SUBMODE_TO_GLOBAL_MAP[normalized];
}

function normalizeAdminSettingsSubMode(value) {
  const mode = String(value || "").trim();
  if (Object.prototype.hasOwnProperty.call(ADMIN_SETTINGS_GROUP_TO_SECTION_IDS, mode)) {
    return mode;
  }
  return "operations";
}

function normalizeAdminOperationsSubMode(value) {
  const mode = String(value || "").trim();
  if (Object.prototype.hasOwnProperty.call(ADMIN_OPERATIONS_GROUP_TO_SECTION_IDS, mode)) {
    return mode;
  }
  return "quick";
}

function persistAdminUiState() {
  try {
    window.sessionStorage.setItem(
      ADMIN_UI_STATE_STORAGE_KEY,
      JSON.stringify({
        adminSettingsSubMode: state.adminSettingsSubMode,
        adminOperationsSubMode: state.adminOperationsSubMode,
        agentSilentThresholdHours: state.agentSilentThresholdHours,
      }),
    );
  } catch (_error) {
    // Ignore storage failures (private mode, quota).
  }
}

function restoreAdminUiStateFromStorage() {
  try {
    const raw = window.sessionStorage.getItem(ADMIN_UI_STATE_STORAGE_KEY);
    if (!raw) {
      return;
    }
    const data = JSON.parse(raw);
    if (data && typeof data === "object") {
      state.adminSettingsSubMode = normalizeAdminSettingsSubMode(data.adminSettingsSubMode);
      state.adminOperationsSubMode = normalizeAdminOperationsSubMode(data.adminOperationsSubMode);
      const thresholdHours = Number.parseInt(String(data.agentSilentThresholdHours || ""), 10);
      if (thresholdHours > 0) {
        state.agentSilentThresholdHours = thresholdHours;
      }
    }
  } catch (_error) {
    // Ignore corrupt storage payloads.
  }
}

function reapplyAdminWorkspaceUi() {
  if (!state.isAdmin) {
    return;
  }

  mountAdminSettingsIntoGlobalView();
  const container = document.getElementById("globalAdminSettingsContainer");
  if (container) {
    ensureAdminSettingsSplitLayout(container);
  }

  const opsSection = document.getElementById("globalAdminOpsSection");
  if (opsSection && state.globalSubMode === "admin-settings") {
    applyAdminOperationsSubMode(opsSection);
  }

  const thresholdSelect = document.getElementById("agentSilentThresholdSelect");
  if (thresholdSelect) {
    thresholdSelect.value = String(state.agentSilentThresholdHours || 6);
  }
}

function applyAdminOperationsSubMode(section) {
  if (!section) {
    return;
  }
  const activeMode = normalizeAdminOperationsSubMode(state.adminOperationsSubMode);
  state.adminOperationsSubMode = activeMode;

  const allManagedIds = Object.values(ADMIN_OPERATIONS_GROUP_TO_SECTION_IDS).flat();
  const visibleIds = new Set(ADMIN_OPERATIONS_GROUP_TO_SECTION_IDS[activeMode] || []);

  allManagedIds.forEach((sectionId) => {
    const card = document.getElementById(sectionId);
    if (!card) {
      return;
    }
    card.classList.toggle("hidden", !visibleIds.has(sectionId));
  });

  section.querySelectorAll(".admin-ops-nav-button").forEach((button) => {
    const buttonMode = String(button.getAttribute("data-admin-ops-mode") || "");
    const active = buttonMode === activeMode;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", active ? "true" : "false");
  });
}

function ensureAdminOperationsSplitLayout(section) {
  if (!section) {
    return;
  }
  const shell = section.querySelector("#adminOpsSplitShell");
  if (!shell) {
    return;
  }

  if (shell.getAttribute("data-wired") !== "1") {
    shell.querySelectorAll(".admin-ops-nav-button").forEach((button) => {
      button.addEventListener("click", () => {
        state.adminOperationsSubMode = normalizeAdminOperationsSubMode(button.getAttribute("data-admin-ops-mode"));
        applyAdminOperationsSubMode(section);
        persistAdminUiState();
      });
    });
    shell.setAttribute("data-wired", "1");
  }

  applyAdminOperationsSubMode(section);
}

function applyAdminSettingsSubMode(container) {
  if (!container) {
    return;
  }
  const activeMode = normalizeAdminSettingsSubMode(state.adminSettingsSubMode);
  state.adminSettingsSubMode = activeMode;

  const allManagedIds = Object.values(ADMIN_SETTINGS_GROUP_TO_SECTION_IDS).flat();
  const visibleIds = new Set(ADMIN_SETTINGS_GROUP_TO_SECTION_IDS[activeMode] || []);

  allManagedIds.forEach((sectionId) => {
    const section = document.getElementById(sectionId);
    if (!section) {
      return;
    }
    if (!state.isAdmin) {
      section.classList.add("hidden");
      return;
    }
    section.classList.toggle("hidden", !visibleIds.has(sectionId));
  });

  container.querySelectorAll(".admin-settings-nav-button").forEach((button) => {
    const buttonMode = String(button.getAttribute("data-admin-settings-mode") || "");
    const active = buttonMode === activeMode;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", active ? "true" : "false");
  });

  if (activeMode === "operations") {
    ensureAdminOperationsSplitLayout(document.getElementById("globalAdminOpsSection"));
  }
}

function ensureAdminSettingsSplitLayout(container) {
  if (!container) {
    return;
  }
  let shell = container.querySelector("#adminSettingsSplitShell");
  if (!shell) {
    container.insertAdjacentHTML("afterbegin", `
      <section id="adminSettingsSplitShell" class="admin-settings-split-shell">
        <div class="admin-settings-split-head">
          <h5>Admin Einstellungen</h5>
          <p class="count compact">Funktionsgruppen statt ein langer Gesamtblock.</p>
        </div>
        <div class="admin-settings-nav-buttons" role="tablist" aria-label="Admin Einstellungsgruppen">
          <button type="button" class="tab-button admin-settings-nav-button" data-admin-settings-mode="operations" role="tab" aria-selected="false">Betrieb</button>
          <button type="button" class="tab-button admin-settings-nav-button" data-admin-settings-mode="security" role="tab" aria-selected="false">Sicherheit</button>
          <button type="button" class="tab-button admin-settings-nav-button" data-admin-settings-mode="alerting" role="tab" aria-selected="false">Alerting</button>
          <button type="button" class="tab-button admin-settings-nav-button" data-admin-settings-mode="sap" role="tab" aria-selected="false">SAP Mappings</button>
          <button type="button" class="tab-button admin-settings-nav-button" data-admin-settings-mode="data" role="tab" aria-selected="false">Datenhygiene</button>
        </div>
      </section>
    `);
    shell = container.querySelector("#adminSettingsSplitShell");
  }

  if (shell && shell.getAttribute("data-wired") !== "1") {
    shell.querySelectorAll(".admin-settings-nav-button").forEach((button) => {
      button.addEventListener("click", () => {
        state.adminSettingsSubMode = normalizeAdminSettingsSubMode(button.getAttribute("data-admin-settings-mode"));
        applyAdminSettingsSubMode(container);
        persistAdminUiState();
        void loadAdminSettingsGroup(state.adminSettingsSubMode);
      });
    });
    shell.setAttribute("data-wired", "1");
  }

  applyAdminSettingsSubMode(container);
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
    filesystemTitle.textContent = `Filesysteme (${label})`;
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

const HOST_SORT_MODES = new Set([
  "customer_alpha",
  "report_desc",
  "report_asc",
  "online_first",
]);

function normalizeHostSortMode(value) {
  const mode = String(value || "").trim().toLowerCase();
  return HOST_SORT_MODES.has(mode) ? mode : "customer_alpha";
}

function loadHostFilterPreferences() {
  state.hostSearchQuery = "";
  state.hostOsFilter = "all";
  state.hostCountryFilter = "all";
  state.hostSortMode = "customer_alpha";

  const username = String(state.authUser || "").trim().toLowerCase();
  if (!username) {
    syncHostSortControl();
    return;
  }

  try {
    const raw = window.localStorage.getItem(`${HOST_FILTERS_STORAGE_KEY_PREFIX}${username}`);
    if (!raw) {
      syncHostSortControl();
      return;
    }
    const saved = JSON.parse(raw);
    if (saved.hostSearchQuery !== undefined) state.hostSearchQuery = String(saved.hostSearchQuery);
    if (saved.hostOsFilter !== undefined) state.hostOsFilter = String(saved.hostOsFilter);
    if (saved.hostCountryFilter !== undefined) state.hostCountryFilter = String(saved.hostCountryFilter);
    if (saved.hostSortMode !== undefined) state.hostSortMode = normalizeHostSortMode(saved.hostSortMode);
  } catch (_error) {
    // Ignore
  }
  syncHostSortControl();
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
    const parsedCountryCodes = new Set(
      String(prefs.host_interest_country_codes || "")
        .split(",")
        .map((item) => String(item || "").trim().toUpperCase())
        .filter((item) => /^[A-Z]{2}$/.test(item))
    );
    const parsedHostAdditions = new Set(
      String(prefs.host_interest_host_additions || "")
        .split(",")
        .map((item) => String(item || "").trim())
        .filter((item) => item.length > 0)
    );
    const parsedHostExclusions = new Set(
      String(prefs.host_interest_host_exclusions || "")
        .split(",")
        .map((item) => String(item || "").trim())
        .filter((item) => item.length > 0)
    );
    state.hostInterestCountryCodes = parsedCountryCodes;
    state.hostInterestHostAdditions = parsedHostAdditions;
    state.hostInterestHostExclusions = parsedHostExclusions;
    state.hostInterestHosts = getEffectiveHostInterestHosts();
    state.hostInterestsLoadedFor = String(state.authDisplayName || state.authUser || "").trim();
    updateCriticalTrendsMetricsCheckboxes();
    renderHostInterestsEditor();
  } catch (_error) {
    // Ignore
  }
}

function resetUserScopedPreferences() {
  state.criticalTrendsMetrics = ["filesystem"];
  state.hostInterestMode = "all";
  state.hostInterestCountryCodes = new Set();
  state.hostInterestHostAdditions = new Set();
  state.hostInterestHostExclusions = new Set();
  state.hostInterestHosts = new Set();
  state.hostInterestsLoadedFor = "";
  updateCriticalTrendsMetricsCheckboxes();
  renderHostInterestsEditor();
}

function getHostInterestCountryCode(host) {
  return asText(host?.country_code || "", "").trim().toUpperCase();
}

function getHostInterestIdentity(host) {
  return resolveHostIdentity(host);
}

function hostInterestTokensForHost(host) {
  const tokens = new Set();
  const identity = getHostInterestIdentity(host);
  const hostname = asText(host?.hostname, "").trim();
  if (identity) tokens.add(identity);
  if (hostname) tokens.add(hostname);
  return tokens;
}

function hostInterestSetHasHost(setRef, host) {
  for (const token of hostInterestTokensForHost(host)) {
    if (setRef.has(token)) {
      return true;
    }
  }
  return false;
}

function getHostInterestSelectedCountries() {
  return new Set(Array.from(state.hostInterestCountryCodes || []).filter((code) => /^[A-Z]{2}$/.test(String(code || ""))));
}

function getHostInterestManualAdditions() {
  return new Set(Array.from(state.hostInterestHostAdditions || []).map((hostname) => String(hostname || "").trim()).filter((item) => item.length > 0));
}

function getHostInterestManualExclusions() {
  return new Set(Array.from(state.hostInterestHostExclusions || []).map((hostname) => String(hostname || "").trim()).filter((item) => item.length > 0));
}

function getHostInterestSelectorHosts() {
  const rawHosts = Array.isArray(state.hostInterestTargetHosts) && state.hostInterestTargetHosts.length > 0
    ? state.hostInterestTargetHosts
    : (state.hosts || []);
  const byIdentity = new Map();

  for (const host of rawHosts) {
    const identity = getHostInterestIdentity(host);
    const hostname = String(host?.hostname || "").trim();
    if (!identity || !hostname) continue;

    const existing = byIdentity.get(identity);
    if (!existing) {
      byIdentity.set(identity, {
        ...host,
        host_uid: asText(host?.host_uid, "").trim(),
        hostname,
        display_name: String(host?.display_name || "").trim() || hostname,
        customer_name: String(host?.customer_name || "").trim(),
        country_code: getHostInterestCountryCode(host),
      });
      continue;
    }

    const nextDisplayName = String(existing.display_name || "").trim() || String(host?.display_name || "").trim() || hostname;
    const nextCustomerName = String(existing.customer_name || "").trim() || String(host?.customer_name || "").trim();
    const nextCountryCode = String(existing.country_code || "").trim() || getHostInterestCountryCode(host);
    byIdentity.set(identity, {
      ...existing,
      ...host,
      host_uid: asText(existing.host_uid || host?.host_uid, "").trim(),
      hostname,
      display_name: nextDisplayName,
      customer_name: nextCustomerName,
      country_code: nextCountryCode,
    });
  }

  return Array.from(byIdentity.values());
}

function getEffectiveHostInterestHosts() {
  const selectedCountries = getHostInterestSelectedCountries();
  const additions = getHostInterestManualAdditions();
  const exclusions = getHostInterestManualExclusions();
  const selectorHosts = getHostInterestSelectorHosts();
  const effective = new Set();
  const hasExplicitBaseSelection = selectedCountries.size > 0 || additions.size > 0;

  for (const host of selectorHosts) {
    const identity = getHostInterestIdentity(host);
    const hostname = String(host.hostname || "").trim();
    if (!identity || !hostname) continue;
    const countryCode = getHostInterestCountryCode(host);
    const enabledByDefault = !hasExplicitBaseSelection;
    const enabledByCountry = selectedCountries.has(countryCode);
    if ((enabledByDefault || enabledByCountry) && !hostInterestSetHasHost(exclusions, host)) {
      effective.add(identity);
    }
  }

  for (const host of selectorHosts) {
    const identity = getHostInterestIdentity(host);
    if (!identity) continue;
    if (hostInterestSetHasHost(additions, host) && !hostInterestSetHasHost(exclusions, host)) {
      effective.add(identity);
    }
  }

  return effective;
}

function syncEffectiveHostInterestSelection() {
  state.hostInterestHosts = getEffectiveHostInterestHosts();
}

async function loadHostInterestTargets(force = false) {
  if (state.hostInterestTargetsLoaded && !force) {
    return state.hostInterestTargetsLoadingPromise || Promise.resolve();
  }
  if (state.hostInterestTargetsLoadingPromise) {
    return state.hostInterestTargetsLoadingPromise;
  }

  state.hostInterestTargetsLoading = true;
  state.hostInterestTargetsLoadingPromise = (async () => {
    try {
      const response = await fetch("/api/v1/host-interest-targets", { credentials: "same-origin" });
      if (!response.ok) {
        throw new Error("HTTP " + response.status);
      }
      const data = await response.json();
      state.hostInterestTargetHosts = Array.isArray(data.hosts) ? data.hosts : [];
      state.hostInterestTargetsLoaded = true;
      syncEffectiveHostInterestSelection();
      if (state.userSettingsSubMode === "hosts") {
        renderHostInterestsEditor();
      }
    } catch (_error) {
      // Ignore host-selector load errors; the editor falls back to the current host page.
    } finally {
      state.hostInterestTargetsLoading = false;
      state.hostInterestTargetsLoadingPromise = null;
    }
  })();
  return state.hostInterestTargetsLoadingPromise;
}

function updateCriticalTrendsMetricsCheckboxes() {
  const checkboxByMetric = {
    cpu: ["ctMetricCpu", "digestMetricCpu"],
    memory: ["ctMetricMemory", "digestMetricMemory"],
    swap: ["ctMetricSwap", "digestMetricSwap"],
    filesystem: ["ctMetricFilesystem", "digestMetricFilesystem"],
  };
  for (const [metric, ids] of Object.entries(checkboxByMetric)) {
    const checked = state.criticalTrendsMetrics.includes(metric);
    ids.forEach((id) => {
      const checkbox = document.getElementById(id);
      if (checkbox) checkbox.checked = checked;
    });
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
      hostOsFilter: state.hostOsFilter,
      hostCountryFilter: state.hostCountryFilter,
      hostSortMode: normalizeHostSortMode(state.hostSortMode),
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
  button.setAttribute("aria-pressed", isDark ? "true" : "false");
  button.setAttribute("aria-label", isDark ? "Zum Lightmode wechseln" : "Zum Darkmode wechseln");
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
  const statusEl = document.getElementById("autoRefreshStatus");
  if (!statusEl) {
    return;
  }
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

function startSessionRefreshTimer() {
  if (!state.isAuthenticated) {
    return;
  }
  stopSessionRefreshTimer();
  // First refresh delayed so the login Set-Cookie is applied before POST /session/refresh.
  window.setTimeout(() => {
    if (state.isAuthenticated) {
      void refreshSession();
    }
  }, 2500);
  sessionRefreshTimerId = window.setInterval(() => {
    void refreshSession();
  }, SESSION_REFRESH_INTERVAL_SECONDS * 1000);
}

function stopSessionRefreshTimer() {
  if (sessionRefreshTimerId !== null) {
    window.clearInterval(sessionRefreshTimerId);
    sessionRefreshTimerId = null;
  }
}

async function refreshSession() {
  if (!state.isAuthenticated) {
    return;
  }
  try {
    const response = await fetch("/api/v1/session/refresh", {
      method: "POST",
      credentials: "same-origin",
    });
    if (!response.ok) {
      console.warn("Session refresh failed:", response.status);
      if (response.status === 401) {
        if (Date.now() - sessionEstablishedAtMs < SESSION_LOGIN_GRACE_MS) {
          console.warn("Session refresh 401 ignored during login grace window");
          return;
        }
        setAuthUiState(false);
        setLoginStatus("Session abgelaufen. Bitte neu anmelden.", true);
      }
      return;
    }
    const data = await response.json().catch(() => ({}));
    updateSessionExpiry(
      asText(data.expires_at_utc, ""),
      Number.parseInt(String(data.inactivity_timeout_minutes || ""), 10)
    );
  } catch (error) {
    console.warn("Session refresh error:", error);
  }
}

function parseUtcIso(value) {
  const raw = asText(value, "").trim();
  if (!raw) return null;
  const parsed = new Date(raw);
  if (Number.isNaN(parsed.getTime())) return null;
  return parsed;
}

function hostClusterKey(hostname) {
  const value = String(hostname || "").trim().toLowerCase();
  if (!value) {
    return "";
  }
  const dotIndex = value.indexOf(".");
  return dotIndex === -1 ? value : value.slice(0, dotIndex);
}

function isCanonicalHostCard(host) {
  return Boolean(host && typeof host === "object" && !host.is_temporary_identity);
}

function isHostRecentlyActive(host, windowMs = 60 * 60 * 1000) {
  if (!host || typeof host !== "object") {
    return false;
  }
  if (host.online === true) {
    return true;
  }
  const parsedLastSeen = parseUtcIso(host.last_seen_utc || "");
  if (!parsedLastSeen) {
    return false;
  }
  return (Date.now() - parsedLastSeen.getTime()) <= windowMs;
}

function formatSessionRemaining(seconds) {
  const safeSeconds = Math.max(0, Number.parseInt(String(seconds || 0), 10) || 0);
  const h = Math.floor(safeSeconds / 3600);
  const m = Math.floor((safeSeconds % 3600) / 60);
  const s = safeSeconds % 60;
  if (h > 0) {
    return `${h}h ${String(m).padStart(2, "0")}m`;
  }
  return `${m}m ${String(s).padStart(2, "0")}s`;
}

function renderSessionStatus() {
  const badge = document.getElementById("brandSessionBadge");
  if (!badge) {
    return;
  }
  if (!state.isAuthenticated) {
    badge.classList.add("hidden");
    badge.textContent = "";
    return;
  }

  const expiry = parseUtcIso(state.sessionExpiresAtUtc);
  if (!expiry) {
    badge.classList.remove("hidden");
    badge.textContent = `Session`;
    return;
  }

  const secondsLeft = Math.max(0, Math.floor((expiry.getTime() - Date.now()) / 1000));
  const timeoutMinutes = Number.isFinite(state.sessionInactivityTimeoutMinutes)
    ? Math.max(1, Math.floor(state.sessionInactivityTimeoutMinutes))
    : 30;
  badge.classList.remove("hidden");
  badge.textContent = `Session ${formatSessionRemaining(secondsLeft)} (${timeoutMinutes}m)`;
}

function webUserDisplayLabel(username, displayName) {
  const label = asText(displayName, "").trim();
  if (label) return label;
  return asText(username, "");
}

function resolveWebUserActionLabel(item, field) {
  if (!item || typeof item !== "object") {
    return asText(item, "");
  }
  const labelKey = `${field}_label`;
  const resolved = asText(item[labelKey], "").trim();
  if (resolved) return resolved;
  return asText(item[field], "");
}

function getBrandProfileInitials(value) {
  const parts = asText(value, "")
    .trim()
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2);
  if (parts.length === 0) {
    return "--";
  }
  return parts.map((part) => part.slice(0, 1).toUpperCase()).join("");
}

function syncBrandProfileIdentity() {
  const badge = document.getElementById("brandUserBadge");
  const displayName = state.authDisplayName || state.authUser || "";
  if (badge) {
    badge.textContent = displayName;
  }
}

function stopSessionCountdownTimer() {
  if (sessionCountdownTimerId !== null) {
    window.clearInterval(sessionCountdownTimerId);
    sessionCountdownTimerId = null;
  }
}

function startSessionCountdownTimer() {
  stopSessionCountdownTimer();
  renderSessionStatus();
  sessionCountdownTimerId = window.setInterval(() => {
    renderSessionStatus();
  }, 1000);
}

function updateSessionExpiry(expiresAtUtc, inactivityTimeoutMinutes = null) {
  state.sessionExpiresAtUtc = asText(expiresAtUtc, "");
  const parsedMinutes = Number.parseInt(String(inactivityTimeoutMinutes ?? ""), 10);
  if (Number.isFinite(parsedMinutes) && parsedMinutes > 0) {
    state.sessionInactivityTimeoutMinutes = parsedMinutes;
  }
  if (state.isAuthenticated) {
    startSessionCountdownTimer();
  } else {
    stopSessionCountdownTimer();
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

    const hostsPromise = loadHosts({ preserveScroll });
    void loadHeaderDatabaseKpis().catch((error) => {
      console.warn("loadHeaderDatabaseKpis failed:", error);
    });
    let kpiPromise = Promise.resolve();
    if (!state.deferredDashboardTasksInFlight) {
      state.deferredDashboardTasksInFlight = true;
      kpiPromise = Promise.allSettled([
        loadGlobalAlertsOverview({ updateList: shouldRefreshGlobalAlertsList }),
        loadInactiveHosts({ updateList: false }),
        loadWebclientVersion(),
        loadCriticalTrends({ updateList: false }),
      ])
        .then(() => {
          updateSummaryStrip();
          if (automatic) {
            updateAutoRefreshStatus(new Date());
          }
        })
        .finally(() => {
          state.deferredDashboardTasksInFlight = false;
        });
    }

    await hostsPromise;
    if (state.selectedHost || state.selectedHostUid) {
      void loadReportsForHost().then(() => {
        void Promise.allSettled([
          loadAnalysisForHost(),
          loadAlertsForHost(),
        ]);
      });
    }
    void kpiPromise;

    if (state.viewMode === "settings") {
      try {
        await loadSettingsPanel(true);
      } catch (error) {
        console.warn("loadSettingsPanel failed:", error);
      }
    }
    if (state.viewMode === "global" && state.globalSubMode === "admin-settings" && state.isAdmin) {
      reapplyAdminWorkspaceUi();
    }
    updateSummaryStrip();
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
  const buildVersionEls = [
    document.getElementById("webclientVersion"),
    document.getElementById("loginBuildVersion"),
  ].filter(Boolean);
  const agentVersionEls = [
    document.getElementById("latestAgentVersion"),
    document.getElementById("loginAgentVersion"),
  ].filter(Boolean);
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

    setBuildVersions(value);
    setAgentVersions(agentValue);
    updateChangelogToolsBuildVersionBadge(value);
    state.latestAgentRelease = agentValue;
  } catch (_error) {
    setBuildVersions("-");
    setAgentVersions("-");
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
          <span>${escapeHtml(resultMessage || "Kein Rückkanal-Ergebnis gespeichert.")}</span>
        </div>
      `;
    })
    .join("");
}

function agentUpdateStatusSortWeight(status) {
  switch (String(status || "idle").toLowerCase()) {
    case "failed":
      return 0;
    case "expired":
      return 1;
    case "pending":
      return 2;
    case "idle":
      return 3;
    case "completed":
      return 4;
    default:
      return 5;
  }
}

function renderAgentUpdateStatusTableRows(hosts) {
  if (!Array.isArray(hosts) || hosts.length === 0) {
    return '<tr><td colspan="13" class="muted">Noch keine Host-Statusdaten vorhanden.</td></tr>';
  }

  const sorted = [...hosts].sort((a, b) => {
    const aVersion = asText(a.agent_version || "");
    const bVersion = asText(b.agent_version || "");
    const versionCompare = compareSemverLike(bVersion, aVersion);
    if (versionCompare !== null && versionCompare !== 0) return versionCompare;
    if (aVersion !== bVersion) return bVersion.localeCompare(aVersion);

    const wa = agentUpdateStatusSortWeight(a.command_status);
    const wb = agentUpdateStatusSortWeight(b.command_status);
    if (wa !== wb) return wa - wb;

    const aReport = Date.parse(asText(a.last_report_utc || "")) || 0;
    const bReport = Date.parse(asText(b.last_report_utc || "")) || 0;
    if (aReport !== bReport) return bReport - aReport;

    return asText(a.display_name || a.hostname).localeCompare(asText(b.display_name || b.hostname));
  });

  const rows = [];
  let currentVersionGroup = null;

  for (const host of sorted) {
      const status = asText(host.command_status || "idle").toLowerCase();
      const displayName = asText(host.display_name || host.hostname);
      const hostname = asText(host.hostname || "-");
      const hostUid = asText(host.host_uid || "", "").trim();
      const agentVersion = asText(host.agent_version || "-");
      const customerName = asText(host.customer_name || "-") || "-";
      const lastReport = host.last_report_utc ? formatUtcPlus2(host.last_report_utc) : "-";
      const cmdCreated = host.command_created_at_utc ? formatUtcPlus2(host.command_created_at_utc) : "-";
      const cmdExecuted = host.command_executed_at_utc ? formatUtcPlus2(host.command_executed_at_utc) : "-";
      const cmdExpires = host.command_expires_at_utc ? formatUtcPlus2(host.command_expires_at_utc) : "-";
      const nextPriority = host.next_priority_check_utc ? formatUtcPlus2(host.next_priority_check_utc) : "-";
      const lastPriority = host.last_priority_check_utc ? formatUtcPlus2(host.last_priority_check_utc) : "-";
      const priorityMinutes = Number(host.priority_check_minutes || 0) > 0 ? Number(host.priority_check_minutes || 0) : "-";
      const recurringHours = Number(host.recurring_update_hours || 0) > 0 ? Number(host.recurring_update_hours || 0) : "-";
      const recurringHint = asText(host.recurring_update_hint || "");
      const commandMessage = asText(host.command_result_message || "Kein Rückkanal-Ergebnis.");
      const showLogBtn = (status === "failed" || status === "completed")
        ? ` <button class="chip-btn" onclick="showHostUpdateLog(${escapeHtml(JSON.stringify(hostname))}, ${escapeHtml(JSON.stringify(hostUid))})" title="Update-Log anzeigen">Log</button>`
        : "";

      if (currentVersionGroup !== agentVersion) {
        currentVersionGroup = agentVersion;
        rows.push(`
          <tr class="agent-update-admin-group-row">
            <td colspan="13">Agent-Version ${escapeHtml(agentVersion)}</td>
          </tr>
        `);
      }

      rows.push(`
        <tr>
          <td><span class="agent-update-status-badge ${escapeHtml(status)}">${escapeHtml(updateStatusBadgeLabel(status))}</span></td>
          <td>
            <div class="agent-update-admin-host">
              <strong>${escapeHtml(displayName)}</strong>
              <span class="agent-update-admin-hostname">${escapeHtml(hostname)}</span>
            </div>
          </td>
          <td>${escapeHtml(customerName)}</td>
          <td>${escapeHtml(agentVersion)}</td>
          <td>${escapeHtml(lastReport)}</td>
          <td>${escapeHtml(cmdCreated)}</td>
          <td>${escapeHtml(cmdExecuted)}</td>
          <td>${escapeHtml(cmdExpires)}</td>
          <td>${escapeHtml(nextPriority)}</td>
          <td>${escapeHtml(lastPriority)}</td>
          <td>${escapeHtml(String(priorityMinutes))}</td>
          <td title="${escapeHtml(recurringHint)}">${escapeHtml(String(recurringHours))}</td>
          <td class="agent-update-admin-message">${escapeHtml(commandMessage)}${showLogBtn}</td>
        </tr>
      `);
  }

  return rows.join("");
}

function getAgentVersionLagInfo(latestVersion, hostVersion) {
  const latestPartsRaw = parseVersionParts(latestVersion);
  const hostPartsRaw = parseVersionParts(hostVersion);
  if (!latestPartsRaw || !hostPartsRaw) {
    return { isBehind: false, steps: null, majorMinorDifferent: false };
  }

  const compare = compareSemverLike(hostVersion, latestVersion);
  if (compare === null || compare >= 0) {
    return { isBehind: false, steps: 0, majorMinorDifferent: false };
  }

  const latestParts = [latestPartsRaw[0] || 0, latestPartsRaw[1] || 0, latestPartsRaw[2] || 0];
  const hostParts = [hostPartsRaw[0] || 0, hostPartsRaw[1] || 0, hostPartsRaw[2] || 0];
  const sameMajorMinor = latestParts[0] === hostParts[0] && latestParts[1] === hostParts[1];
  if (sameMajorMinor) {
    return {
      isBehind: true,
      steps: Math.max(0, latestParts[2] - hostParts[2]),
      majorMinorDifferent: false,
    };
  }

  return { isBehind: true, steps: null, majorMinorDifferent: true };
}

function getHostMinutesSinceReport(host) {
  const fromApi = Number(host?.minutes_since_report);
  if (Number.isFinite(fromApi) && fromApi >= 0) {
    return fromApi;
  }
  const lastReport = asText(host?.last_report_utc || "");
  const parsed = Date.parse(lastReport);
  if (!Number.isFinite(parsed)) {
    return null;
  }
  return Math.max(0, Math.floor((Date.now() - parsed) / 60000));
}

function formatMinutesAsSilenceDuration(minutes) {
  if (minutes === null || minutes === undefined || !Number.isFinite(minutes)) {
    return "-";
  }
  const total = Math.max(0, Math.floor(minutes));
  if (total < 60) {
    return `${total} min`;
  }
  const hours = Math.floor(total / 60);
  const mins = total % 60;
  if (hours < 48) {
    return mins ? `${hours} h ${mins} min` : `${hours} h`;
  }
  const days = Math.floor(hours / 24);
  const remHours = hours % 24;
  return remHours ? `${days} T ${remHours} h` : `${days} T`;
}

function filterSilentHosts(hosts, thresholdHours) {
  const thresholdMinutes = Math.max(1, Number(thresholdHours) || 6) * 60;
  return (Array.isArray(hosts) ? hosts : []).filter((host) => {
    const minutes = getHostMinutesSinceReport(host);
    return minutes === null || minutes >= thresholdMinutes;
  });
}

function renderSilentHostsTableRows(hosts, thresholdHours) {
  const silentHosts = filterSilentHosts(hosts, thresholdHours)
    .sort((left, right) => {
      const leftMinutes = getHostMinutesSinceReport(left);
      const rightMinutes = getHostMinutesSinceReport(right);
      const leftWeight = leftMinutes === null ? 99999999 : leftMinutes;
      const rightWeight = rightMinutes === null ? 99999999 : rightMinutes;
      if (leftWeight !== rightWeight) {
        return rightWeight - leftWeight;
      }
      const versionCompare = compareSemverLike(asText(left?.agent_version || ""), asText(right?.agent_version || ""));
      if (versionCompare !== null && versionCompare !== 0) {
        return versionCompare;
      }
      return asText(left?.display_name || left?.hostname).localeCompare(asText(right?.display_name || right?.hostname));
    });

  if (!silentHosts.length) {
    return `<tr><td colspan="8" class="muted">Keine Hosts mit letztem Report älter als ${thresholdHours} Stunden.</td></tr>`;
  }

  return silentHosts.map((host) => {
    const displayName = asText(host?.display_name || host?.hostname, "-");
    const hostname = asText(host?.hostname, "-");
    const customerName = asText(host?.customer_name || "-") || "-";
    const agentVersion = asText(host?.agent_version || "-", "-");
    const lastReport = host?.last_report_utc ? formatUtcPlus2(host.last_report_utc) : "nie";
    const silence = formatMinutesAsSilenceDuration(getHostMinutesSinceReport(host));
    const status = asText(host?.command_status || "idle").toLowerCase();
    const recurringHours = Number(host?.recurring_update_hours || 0) > 0 ? Number(host.recurring_update_hours) : "-";
    const recurringHint = asText(host?.recurring_update_hint || "");
    const lastCrash = asText(host?.agent_update_last_crash || "");
    const commandMessage = asText(host?.command_result_message || "");
    const hintParts = [];
    if (lastCrash) {
      hintParts.push(lastCrash);
    }
    if (commandMessage && status === "failed") {
      hintParts.push(commandMessage);
    }
    if (!hintParts.length && recurringHint) {
      hintParts.push(recurringHint);
    }
    const hint = hintParts.join(" | ") || "—";

    return `
      <tr class="agent-silent-host-row">
        <td>
          <div class="agent-update-admin-host">
            <strong>${escapeHtml(displayName)}</strong>
            <span class="agent-update-admin-hostname">${escapeHtml(hostname)}</span>
          </div>
        </td>
        <td>${escapeHtml(customerName)}</td>
        <td>${escapeHtml(agentVersion)}</td>
        <td>${escapeHtml(lastReport)}</td>
        <td>${escapeHtml(silence)}</td>
        <td><span class="agent-update-status-badge ${escapeHtml(status)}">${escapeHtml(updateStatusBadgeLabel(status))}</span></td>
        <td title="${escapeHtml(recurringHint)}">${escapeHtml(String(recurringHours))}</td>
        <td class="agent-update-admin-message">${escapeHtml(hint)}</td>
      </tr>
    `;
  }).join("");
}

function renderAgentSilentHostsSection(hosts, thresholdHours, latestVersion) {
  const summaryEl = document.getElementById("agentSilentHostsSummary");
  const tableBodyEl = document.getElementById("agentSilentHostsTableBody");
  if (!summaryEl || !tableBodyEl) {
    return;
  }

  const silentHosts = filterSilentHosts(hosts, thresholdHours);
  const pendingSilent = silentHosts.filter((host) => asText(host?.command_status || "idle").toLowerCase() === "pending").length;
  const oldVersionSilent = silentHosts.filter((host) => {
    const lag = getAgentVersionLagInfo(latestVersion, host?.agent_version || "");
    return lag.isBehind && (lag.majorMinorDifferent || Number(lag.steps || 0) >= 3);
  }).length;

  summaryEl.textContent = `${silentHosts.length} Host(s) ohne Meldung seit ≥ ${thresholdHours} h`
    + (latestVersion !== "-" ? ` | Repo: ${latestVersion}` : "")
    + ` | ${pendingSilent} mit pending update-now`
    + (oldVersionSilent ? ` | ${oldVersionSilent} mit veralteter Agent-Version (≥3 zurück)` : "")
    + ". Recurring (h) = letzter bekannter Wert aus dem letzten Report.";

  tableBodyEl.innerHTML = renderSilentHostsTableRows(hosts, thresholdHours);
}

function renderLaggingAgentVersionRows(hosts, latestVersion, threshold = 5) {
  if (!Array.isArray(hosts) || hosts.length === 0) {
    return '<tr><td colspan="6" class="muted">Keine Hostdaten vorhanden.</td></tr>';
  }

  const laggingHosts = hosts
    .map((host) => {
      const lagInfo = getAgentVersionLagInfo(latestVersion, host?.agent_version || "");
      return { host, lagInfo };
    })
    .filter(({ lagInfo }) => lagInfo.isBehind && (lagInfo.majorMinorDifferent || Number(lagInfo.steps || 0) >= threshold))
    .sort((left, right) => {
      const leftWeight = left.lagInfo.majorMinorDifferent ? 999999 : Number(left.lagInfo.steps || 0);
      const rightWeight = right.lagInfo.majorMinorDifferent ? 999999 : Number(right.lagInfo.steps || 0);
      if (leftWeight !== rightWeight) return rightWeight - leftWeight;

      const leftReport = Date.parse(asText(left.host?.last_report_utc || "")) || 0;
      const rightReport = Date.parse(asText(right.host?.last_report_utc || "")) || 0;
      if (leftReport !== rightReport) return rightReport - leftReport;

      return asText(left.host?.display_name || left.host?.hostname).localeCompare(asText(right.host?.display_name || right.host?.hostname));
    });

  if (!laggingHosts.length) {
    return '<tr><td colspan="6" class="muted">Keine Hosts mit mindestens 5 Versionen Rückstand gefunden.</td></tr>';
  }

  return laggingHosts.map(({ host, lagInfo }) => {
    const displayName = asText(host?.display_name || host?.hostname, "-");
    const hostname = asText(host?.hostname, "-");
    const hostVersion = asText(host?.agent_version || "-", "-");
    const lastReport = host?.last_report_utc ? formatUtcPlus2(host.last_report_utc) : "-";
    const status = asText(host?.command_status || "idle").toLowerCase();
    const lagText = lagInfo.majorMinorDifferent
      ? "Major/Minor abweichend"
      : `${Number(lagInfo.steps || 0)} Versionen`;

    return `
      <tr>
        <td>
          <div class="agent-update-admin-host">
            <strong>${escapeHtml(displayName)}</strong>
            <span class="agent-update-admin-hostname">${escapeHtml(hostname)}</span>
          </div>
        </td>
        <td>${escapeHtml(hostVersion)}</td>
        <td>${escapeHtml(asText(latestVersion, "-"))}</td>
        <td>${escapeHtml(lagText)}</td>
        <td>${escapeHtml(lastReport)}</td>
        <td><span class="agent-update-status-badge ${escapeHtml(status)}">${escapeHtml(updateStatusBadgeLabel(status))}</span></td>
      </tr>
    `;
  }).join("");
}

async function loadAgentUpdateStatus() {
  const summaryEl = document.getElementById("agentUpdateStatusSummary");
  const listEl = document.getElementById("agentUpdateStatusList");
  const tableBodyEl = document.getElementById("agentUpdateStatusTableBody");
  const lagSummaryEl = document.getElementById("agentVersionLagSummary");
  const lagTableBodyEl = document.getElementById("agentVersionLagTableBody");
  const recoveryNoteEl = document.getElementById("agentRecoveryNote");
  const silentSummaryEl = document.getElementById("agentSilentHostsSummary");
  const silentTableBodyEl = document.getElementById("agentSilentHostsTableBody");
  const lagThreshold = 5;
  const silentThresholdHours = Number(state.agentSilentThresholdHours) > 0
    ? Number(state.agentSilentThresholdHours)
    : 6;
  if (!summaryEl) {
    return;
  }

  summaryEl.textContent = "Lade Update-Status...";
  if (silentSummaryEl) {
    silentSummaryEl.textContent = "Lade stille Hosts...";
  }
  if (silentTableBodyEl) {
    silentTableBodyEl.innerHTML = '<tr><td colspan="8" class="muted">Lade Daten...</td></tr>';
  }
  if (listEl) {
    listEl.innerHTML = "";
  }
  if (tableBodyEl) {
    tableBodyEl.innerHTML = '<tr><td colspan="13" class="muted">Lade Daten...</td></tr>';
  }
  if (lagSummaryEl) {
    lagSummaryEl.textContent = "Lade Versionsvergleich...";
  }
  if (lagTableBodyEl) {
    lagTableBodyEl.innerHTML = '<tr><td colspan="6" class="muted">Lade Daten...</td></tr>';
  }

  try {
    const response = await fetch("/api/v1/agent-update-status");
    if (!response.ok) {
      throw new Error("HTTP " + response.status);
    }

    const data = await response.json();
    const latestVersion = asText(state.latestAgentRelease, "-");
    const hosts = Array.isArray(data.hosts) ? data.hosts : [];
    state.agentUpdateStatusHosts = hosts;
    const summary = data.summary || {};
    const silentCount = filterSilentHosts(hosts, silentThresholdHours).length;
    if (recoveryNoteEl) {
      const recoveryNote = asText(data.recovery_note || "");
      const scheduleNote = asText(data.default_schedule_note || "");
      recoveryNoteEl.textContent = [recoveryNote, scheduleNote].filter(Boolean).join(" ");
    }
    summaryEl.textContent = `Status: ${Number(summary.pending || 0)} pending | ${Number(summary.completed || 0)} completed | ${Number(summary.failed || 0)} failed | ${Number(summary.expired || 0)} expired | ${Number(summary.idle || 0)} idle | ${silentCount} stille Hosts (≥${silentThresholdHours} h). ${asText(data.default_schedule_note)}`;
    renderAgentSilentHostsSection(hosts, silentThresholdHours, latestVersion);
    if (listEl) {
      listEl.innerHTML = renderAgentUpdateStatusRows(hosts);
    }
    if (tableBodyEl) {
      tableBodyEl.innerHTML = renderAgentUpdateStatusTableRows(hosts);
    }

    if (lagSummaryEl) {
      if (latestVersion === "-") {
        lagSummaryEl.textContent = "Repo-Agent-Version nicht verfügbar. Vergleich derzeit nicht möglich.";
      } else {
        const laggingCount = hosts.filter((host) => {
          const info = getAgentVersionLagInfo(latestVersion, host?.agent_version || "");
          return info.isBehind && (info.majorMinorDifferent || Number(info.steps || 0) >= lagThreshold);
        }).length;
        lagSummaryEl.textContent = `${laggingCount} Host(s) sind mindestens ${lagThreshold} Versionen hinter ${latestVersion}.`;
      }
    }
    if (lagTableBodyEl) {
      if (latestVersion === "-") {
        lagTableBodyEl.innerHTML = '<tr><td colspan="6" class="muted">Repo-Agent-Version nicht verfügbar.</td></tr>';
      } else {
        lagTableBodyEl.innerHTML = renderLaggingAgentVersionRows(hosts, latestVersion, lagThreshold);
      }
    }
    state.agentUpdateStatusLoaded = true;
  } catch (error) {
    if (silentSummaryEl) {
      silentSummaryEl.textContent = `Stille Hosts konnten nicht geladen werden: ${error.message}`;
    }
    if (silentTableBodyEl) {
      silentTableBodyEl.innerHTML = '<tr><td colspan="8" class="muted">Fehler beim Laden.</td></tr>';
    }
    summaryEl.textContent = `Update-Status konnte nicht geladen werden: ${error.message}`;
    if (listEl) {
      listEl.innerHTML = "";
    }
    if (tableBodyEl) {
      tableBodyEl.innerHTML = '<tr><td colspan="13" class="muted">Fehler beim Laden der Statusdaten.</td></tr>';
    }
    if (lagSummaryEl) {
      lagSummaryEl.textContent = `Versionsvergleich konnte nicht geladen werden: ${error.message}`;
    }
    if (lagTableBodyEl) {
      lagTableBodyEl.innerHTML = '<tr><td colspan="6" class="muted">Fehler beim Laden der Versionsdaten.</td></tr>';
    }
  }
}

async function showHostUpdateLog(hostname, hostUid = "") {
  let modal = document.getElementById("hostUpdateLogModal");
  if (!modal) {
    modal = document.createElement("div");
    modal.id = "hostUpdateLogModal";
    modal.style.cssText = "position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.7);display:flex;align-items:center;justify-content:center;";
    modal.innerHTML = `
      <div style="background:#2a2a3a;border:1px solid #444;border-radius:10px;padding:1.4rem 1.6rem;max-width:720px;width:95%;max-height:82vh;display:flex;flex-direction:column;gap:.8rem;">
        <div style="display:flex;align-items:center;justify-content:space-between;gap:1rem;">
          <strong id="hostUpdateLogModalTitle" style="font-size:1rem;color:#fff;">Update-Log</strong>
          <button onclick="document.getElementById('hostUpdateLogModal').remove()" style="background:none;border:none;cursor:pointer;font-size:1.3rem;color:#999;">✕</button>
        </div>
        <div id="hostUpdateLogModalBody" style="overflow-y:auto;flex:1;font-family:monospace;font-size:.8rem;white-space:pre-wrap;background:#1a1a2a;border-radius:6px;padding:.8rem;color:#e0e0e0;min-height:200px;line-height:1.4;">Lade...</div>
      </div>`;
    modal.addEventListener("click", (e) => { if (e.target === modal) modal.remove(); });
    document.body.appendChild(modal);
  }

  const titleEl = document.getElementById("hostUpdateLogModalTitle");
  const bodyEl = document.getElementById("hostUpdateLogModalBody");
  if (titleEl) titleEl.textContent = `Update-Log: ${hostname}`;
  if (bodyEl) bodyEl.textContent = "Lade...";

  try {
    const query = hostUid
      ? `host_uid=${encodeURIComponent(hostUid)}`
      : `hostname=${encodeURIComponent(hostname)}`;
    const res = await fetch(`/api/v1/host-update-log?${query}`);
    if (!res.ok) throw new Error("HTTP " + res.status);
    const data = await res.json();
    if (!bodyEl) return;
    if (!data.available) {
      bodyEl.textContent = "Kein Update-Log verfügbar (Host hat noch keinen Bericht gesendet).";
      return;
    }
    let text = "";
    if (data.crash_info) {
      text += "=== LETZTER ABSTURZ ===\n" + data.crash_info + "\n\n";
    }
    if (data.lines && data.lines.length > 0) {
      text += "=== UPDATE-LOG (letzte Einträge) ===\n" + data.lines.join("\n");
    }
    bodyEl.textContent = text || "(Keine Einträge)";
  } catch (err) {
    if (bodyEl) bodyEl.textContent = "Fehler beim Laden: " + err.message;
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
  if (reportsView) {
    reportsView.classList.toggle("hidden", !reportsActive);
    reportsView.classList.toggle("reports-mode-active", reportsActive);
  }

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
  syncAdminSubModeFromGlobal();

  const globalAlertsView = document.getElementById("globalAlertsView");
  const criticalTrendsView = document.getElementById("criticalTrendsView");
  const inactiveHostsView = document.getElementById("inactiveHostsView");
  const systemOverviewView = document.getElementById("systemOverviewView");
  const backupStatusView = document.getElementById("backupStatusView");
  const hostConfigChangesView = document.getElementById("hostConfigChangesView");
  const agentSourceStatusView = document.getElementById("agentSourceStatusView");
  const globalAdminAlertSubsView = document.getElementById("globalAdminAlertSubsView");
  const globalAdminLoginAuditView = document.getElementById("globalAdminLoginAuditView");
  const globalAdminSettingsView = document.getElementById("globalAdminSettingsView");
  const globalAlertsTabButton = document.getElementById("globalAlertsTabButton");
  const criticalTrendsTabButton = document.getElementById("criticalTrendsTabButton");
  const inactiveHostsTabButton = document.getElementById("inactiveHostsTabButton");
  const systemOverviewTabButton = document.getElementById("systemOverviewTabButton");
  const backupStatusTabButton = document.getElementById("backupStatusTabButton");
  const hostConfigChangesTabButton = document.getElementById("hostConfigChangesTabButton");
  const agentSourceStatusTabButton = document.getElementById("agentSourceStatusTabButton");
  const globalAdminAlertSubsTabButton = document.getElementById("globalAdminAlertSubsTabButton");
  const globalAdminLoginAuditTabButton = document.getElementById("globalAdminLoginAuditTabButton");
  const globalAdminSettingsTabButton = document.getElementById("globalAdminSettingsTabButton");
  const globalAdminNavShell = document.getElementById("globalAdminNavShell");
  const adminNavAgentSourceButton = document.getElementById("adminNavAgentSourceButton");
  const adminNavAlertSubsButton = document.getElementById("adminNavAlertSubsButton");
  const adminNavLoginAuditButton = document.getElementById("adminNavLoginAuditButton");
  const adminNavSettingsButton = document.getElementById("adminNavSettingsButton");
  const globalSettingsPage = document.querySelector("#globalView .settings-page");
  const globalSubviewTabsShell = document.querySelector("#globalView .subview-tabs-shell");

  const alertsActive = state.globalSubMode === "global-alerts";
  const trendsActive = state.globalSubMode === "critical-trends";
  const inactiveActive = state.globalSubMode === "inactive-hosts";
  const systemOverviewActive = state.globalSubMode === "system-overview";
  const backupActive = state.globalSubMode === "backup-status";
  const hostConfigChangesActive = state.globalSubMode === "host-config-changes";
  const agentSourceStatusActive = state.globalSubMode === "agent-source-status";
  const adminAlertSubsActive = state.globalSubMode === "admin-alert-subs";
  const adminLoginAuditActive = state.globalSubMode === "admin-login-audit";
  const adminSettingsActive = state.globalSubMode === "admin-settings";
  const adminSourceActive = state.globalSubMode === "agent-source-status";
  const anyAdminSectionActive = adminSourceActive || adminAlertSubsActive || adminLoginAuditActive || adminSettingsActive;

  if (globalAlertsView) globalAlertsView.classList.toggle("hidden", !alertsActive);
  if (criticalTrendsView) criticalTrendsView.classList.toggle("hidden", !trendsActive);
  if (inactiveHostsView) inactiveHostsView.classList.toggle("hidden", !inactiveActive);
  if (systemOverviewView) systemOverviewView.classList.toggle("hidden", !systemOverviewActive);
  if (backupStatusView) backupStatusView.classList.toggle("hidden", !backupActive);
  if (hostConfigChangesView) hostConfigChangesView.classList.toggle("hidden", !hostConfigChangesActive);
  if (agentSourceStatusView) agentSourceStatusView.classList.toggle("hidden", !agentSourceStatusActive);
  if (globalAdminAlertSubsView) globalAdminAlertSubsView.classList.toggle("hidden", !adminAlertSubsActive);
  if (globalAdminLoginAuditView) globalAdminLoginAuditView.classList.toggle("hidden", !adminLoginAuditActive);
  if (globalAdminSettingsView) globalAdminSettingsView.classList.toggle("hidden", !adminSettingsActive);
  if (globalAlertsTabButton) { globalAlertsTabButton.classList.toggle("active", alertsActive); globalAlertsTabButton.setAttribute("aria-selected", alertsActive ? "true" : "false"); }
  if (criticalTrendsTabButton) { criticalTrendsTabButton.classList.toggle("active", trendsActive); criticalTrendsTabButton.setAttribute("aria-selected", trendsActive ? "true" : "false"); }
  if (inactiveHostsTabButton) { inactiveHostsTabButton.classList.toggle("active", inactiveActive); inactiveHostsTabButton.setAttribute("aria-selected", inactiveActive ? "true" : "false"); }
  if (systemOverviewTabButton) { systemOverviewTabButton.classList.toggle("active", systemOverviewActive); systemOverviewTabButton.setAttribute("aria-selected", systemOverviewActive ? "true" : "false"); }
  if (backupStatusTabButton) { backupStatusTabButton.classList.toggle("active", backupActive); backupStatusTabButton.setAttribute("aria-selected", backupActive ? "true" : "false"); }
  if (hostConfigChangesTabButton) { hostConfigChangesTabButton.classList.toggle("active", hostConfigChangesActive); hostConfigChangesTabButton.setAttribute("aria-selected", hostConfigChangesActive ? "true" : "false"); }
  if (agentSourceStatusTabButton) { agentSourceStatusTabButton.classList.toggle("active", agentSourceStatusActive); agentSourceStatusTabButton.setAttribute("aria-selected", agentSourceStatusActive ? "true" : "false"); }
  if (globalAdminAlertSubsTabButton) { globalAdminAlertSubsTabButton.classList.toggle("active", adminAlertSubsActive); globalAdminAlertSubsTabButton.setAttribute("aria-selected", adminAlertSubsActive ? "true" : "false"); }
  if (globalAdminLoginAuditTabButton) { globalAdminLoginAuditTabButton.classList.toggle("active", adminLoginAuditActive); globalAdminLoginAuditTabButton.setAttribute("aria-selected", adminLoginAuditActive ? "true" : "false"); }
  if (globalAdminSettingsTabButton) { globalAdminSettingsTabButton.classList.toggle("active", adminSettingsActive); globalAdminSettingsTabButton.setAttribute("aria-selected", adminSettingsActive ? "true" : "false"); }
  if (globalAdminNavShell) {
    globalAdminNavShell.classList.toggle("hidden", !state.isAdmin || !anyAdminSectionActive);
    globalAdminNavShell.classList.toggle("global-admin-nav-shell-active", anyAdminSectionActive);
  }
  if (globalSettingsPage) {
    globalSettingsPage.classList.toggle("admin-workspace-mode", state.isAdmin && anyAdminSectionActive);
  }
  if (globalSubviewTabsShell) {
    globalSubviewTabsShell.classList.toggle("admin-tabs-muted", state.isAdmin && anyAdminSectionActive);
  }
  if (adminNavAgentSourceButton) {
    adminNavAgentSourceButton.classList.toggle("active", state.adminSubMode === "agent-source-status");
    adminNavAgentSourceButton.setAttribute("aria-selected", state.adminSubMode === "agent-source-status" ? "true" : "false");
  }
  if (adminNavAlertSubsButton) {
    adminNavAlertSubsButton.classList.toggle("active", state.adminSubMode === "admin-alert-subs");
    adminNavAlertSubsButton.setAttribute("aria-selected", state.adminSubMode === "admin-alert-subs" ? "true" : "false");
  }
  if (adminNavLoginAuditButton) {
    adminNavLoginAuditButton.classList.toggle("active", state.adminSubMode === "admin-login-audit");
    adminNavLoginAuditButton.setAttribute("aria-selected", state.adminSubMode === "admin-login-audit" ? "true" : "false");
  }
  if (adminNavSettingsButton) {
    adminNavSettingsButton.classList.toggle("active", state.adminSubMode === "admin-settings");
    adminNavSettingsButton.setAttribute("aria-selected", state.adminSubMode === "admin-settings" ? "true" : "false");
  }

  if (adminSettingsActive) {
    reapplyAdminWorkspaceUi();
  }
}

async function loadActiveGlobalSubMode() {
  if (state.globalSubMode === "global-alerts") {
    await loadGlobalAlertsOverview();
    return;
  }
  if (state.globalSubMode === "critical-trends") {
    await loadCriticalTrends();
    return;
  }
  if (state.globalSubMode === "inactive-hosts") {
    await loadInactiveHosts();
    return;
  }
  if (state.globalSubMode === "system-overview") {
    await loadSystemOverview();
    return;
  }
  if (state.globalSubMode === "backup-status") {
    await loadBackupStatus();
    return;
  }
  if (state.globalSubMode === "host-config-changes") {
    showHostConfigChangesIdleState("Bitte Filter setzen und dann Suchen/Refresh klicken.");
    refreshHostConfigChangesCountryFilter();
    await loadChangelogRebuildJobsStatus();
    return;
  }
  if (state.globalSubMode === "agent-source-status") {
    await loadAgentSourceStatus();
    return;
  }
  if (state.globalSubMode === "admin-alert-subs") {
    await loadAdminAlertSubscriptions();
    return;
  }
  if (state.globalSubMode === "admin-login-audit") {
    await loadAdminLoginAudit();
    return;
  }
  if (state.globalSubMode === "admin-settings") {
    await loadGlobalAdminSettingsPanel();
  }
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
  const loadedForEl = document.getElementById("hostInterestsLoadedFor");
  const countrySummaryEl = document.getElementById("hostInterestCountrySummary");
  const countryChipsEl = document.getElementById("hostInterestCountryChips");
  const showUnselectedOnlyInput = document.getElementById("hostInterestShowUnselectedOnlyInput");
  if (!listEl) {
    return;
  }

  if (showUnselectedOnlyInput) {
    showUnselectedOnlyInput.checked = state.hostInterestShowUnselectedOnly === true;
  }

  syncHostInterestModeControls();
  syncEffectiveHostInterestSelection();

  if (!state.hostInterestTargetsLoaded && !state.hostInterestTargetsLoading) {
    void loadHostInterestTargets();
  }

  const selectorHosts = Array.isArray(state.hostInterestTargetHosts) && state.hostInterestTargetHosts.length > 0
    ? state.hostInterestTargetHosts
    : (state.hosts || []);
  const allHosts = [...selectorHosts].sort((a, b) => {
    const customerA = String(a.customer_name || "").toLowerCase();
    const customerB = String(b.customer_name || "").toLowerCase();
    if (customerA !== customerB) {
      return customerA.localeCompare(customerB);
    }
    const nameA = String(a.display_name || a.hostname || "").toLowerCase();
    const nameB = String(b.display_name || b.hostname || "").toLowerCase();
    return nameA.localeCompare(nameB);
  });
  const query = String(state.hostInterestSearchQuery || "").toLowerCase().trim();
  const visibleHosts = query
    ? allHosts.filter((host) => hostMatchesSearchQuery(host, query))
    : allHosts;

  const selectedCountries = getHostInterestSelectedCountries();
  const manualAdditions = getHostInterestManualAdditions();
  const manualExclusions = getHostInterestManualExclusions();
  const effectiveHosts = getEffectiveHostInterestHosts();
  const totalHosts = allHosts.length;
  const showUnselectedOnly = state.hostInterestShowUnselectedOnly === true;
  const filteredHosts = showUnselectedOnly
    ? visibleHosts.filter((host) => !hostInterestSetHasHost(effectiveHosts, host))
    : visibleHosts;
  const countryGroups = new Map();
  for (const host of filteredHosts) {
    const countryCode = getHostInterestCountryCode(host) || "__NONE__";
    if (!countryGroups.has(countryCode)) countryGroups.set(countryCode, []);
    countryGroups.get(countryCode).push(host);
  }
  const countryCodes = Array.from(countryGroups.keys()).sort((a, b) => {
    if (a === "__NONE__") return 1;
    if (b === "__NONE__") return -1;
    return a.localeCompare(b);
  });

  if (summaryEl) {
    const modeLabel = normalizeHostInterestMode(state.hostInterestMode).replaceAll("_", " ");
    const unselectedCount = Math.max(0, totalHosts - effectiveHosts.size);
    const filterHint = showUnselectedOnly ? " | Filter: nur nicht markierte" : "";
    summaryEl.textContent = `${effectiveHosts.size} von ${totalHosts} Hosts für Mail aktiv | ${unselectedCount} nicht markiert | ${selectedCountries.size} Länder | ${manualAdditions.size} manuell | ${manualExclusions.size} Ausnahmen | Modus: ${modeLabel}${filterHint}`;
  }
  if (loadedForEl) {
    loadedForEl.textContent = state.hostInterestsLoadedFor
      ? `Geladene Präferenzen: ${state.hostInterestsLoadedFor}`
      : "Geladene Präferenzen: -";
  }
  if (countrySummaryEl) {
    countrySummaryEl.textContent = selectedCountries.size > 0
      ? `Vorselektion aktiv für ${selectedCountries.size} Länder. ${effectiveHosts.size} von ${totalHosts} Hosts im Mailversand.`
      : `${effectiveHosts.size} von ${totalHosts} Hosts im Mailversand.`;
  }

  if (allHosts.length === 0) {
    listEl.innerHTML = '<p class="muted">Noch keine Hosts geladen.</p>';
    if (countryChipsEl) {
      countryChipsEl.innerHTML = '<p class="muted">Keine Länder verfügbar.</p>';
    }
    return;
  }

  const allCountryGroups = new Map();
  for (const host of allHosts) {
    const countryCode = getHostInterestCountryCode(host) || "__NONE__";
    if (!allCountryGroups.has(countryCode)) allCountryGroups.set(countryCode, []);
    allCountryGroups.get(countryCode).push(host);
  }

  if (countryChipsEl) {
    const countryCodesAll = Array.from(allCountryGroups.keys()).sort((a, b) => {
      if (a === "__NONE__") return 1;
      if (b === "__NONE__") return -1;
      return a.localeCompare(b);
    });
    countryChipsEl.innerHTML = countryCodesAll.map((countryCode) => {
      const hostsInCountry = allCountryGroups.get(countryCode) || [];
      const label = countryCode === "__NONE__" ? "Ohne Land" : countryCode;
      const flagPath = countryCode === "__NONE__" ? "" : getCountryFlagIconPath(countryCode);
      const active = selectedCountries.has(countryCode);
      return `<button type="button" class="host-interest-country-chip${active ? " is-active" : ""}" data-country-code="${escapeHtml(countryCode)}">
        ${flagPath ? `<img src="${flagPath}" alt="${escapeHtml(countryCode)}" class="host-interest-country-flag" />` : ""}
        <span class="host-interest-country-chip-label">${escapeHtml(label)}</span>
        <span class="host-interest-country-chip-count">${hostsInCountry.length}</span>
      </button>`;
    }).join("");

    countryChipsEl.querySelectorAll("[data-country-code]").forEach((button) => {
      button.addEventListener("click", () => {
        const countryCode = String(button.getAttribute("data-country-code") || "").trim().toUpperCase();
        if (countryCode !== "__NONE__" && !/^[A-Z]{2}$/.test(countryCode)) {
          return;
        }
        if (selectedCountries.has(countryCode)) {
          selectedCountries.delete(countryCode);
        } else {
          selectedCountries.add(countryCode);
          // Country selection means all hosts in this country are active by default.
          for (const host of allHosts) {
            const hostname = String(host.hostname || "").trim();
            if (!hostname) continue;
            const hostCountryCode = getHostInterestCountryCode(host) || "__NONE__";
            if (hostCountryCode === countryCode) {
              const hostIdentity = getHostInterestIdentity(host);
              if (hostIdentity) {
                manualExclusions.delete(hostIdentity);
              }
              manualExclusions.delete(hostname);
            }
          }
        }
        state.hostInterestCountryCodes = selectedCountries;
        state.hostInterestHostExclusions = manualExclusions;
        syncEffectiveHostInterestSelection();
        renderHostInterestsEditor();
      });
    });
  }

  if (filteredHosts.length === 0) {
    listEl.innerHTML = showUnselectedOnly
      ? '<p class="muted">Keine nicht markierten Hosts für den aktuellen Filter.</p>'
      : '<p class="muted">Keine Treffer für die Suche.</p>';
    return;
  }

  const renderHostRow = (host) => {
    const identity = getHostInterestIdentity(host);
    const hostname = String(host.hostname || "").trim();
    const displayName = String(host.display_name || hostname || "").trim();
    const customerName = String(host.customer_name || "").trim() || "Ohne Kunde";
    const countryCode = getHostInterestCountryCode(host);
    const selectedByCountry = selectedCountries.has(countryCode);
    const manualAdded = hostInterestSetHasHost(manualAdditions, host);
    const excluded = hostInterestSetHasHost(manualExclusions, host);
    const effective = hostInterestSetHasHost(effectiveHosts, host);
    const hostLabel = displayName || hostname || "Host";
    const badges = [];
    if (selectedByCountry && !excluded) badges.push(`<span class="host-interest-source-pill country">Land</span>`);
    if (manualAdded) badges.push(`<span class="host-interest-source-pill manual">Manuell</span>`);
    if (excluded) badges.push(`<span class="host-interest-source-pill excluded">Ausnahme</span>`);
    return `<label class="host-interest-item${effective ? " is-active" : ""}" data-host-interest-key="${escapeHtml(identity || hostname)}" data-host-interest-hostname="${escapeHtml(hostname)}" data-host-country-code="${escapeHtml(countryCode)}">
      <input class="host-interest-toggle" type="checkbox" ${effective ? "checked" : ""} />
      <span class="host-interest-meta">
        <span class="host-interest-customer">${escapeHtml(customerName)}</span>
        <span class="host-interest-name">${escapeHtml(hostLabel)}</span>
        <span class="host-interest-hostname">${escapeHtml(hostname)}</span>
      </span>
      <span class="host-interest-badges">${badges.join("")}</span>
    </label>`;
  };

  const groupedSections = countryCodes.map((countryCode) => {
    const hostsInCountry = countryGroups.get(countryCode) || [];
    const label = countryCode === "__NONE__" ? "Ohne Land" : countryCode;
    const flagPath = countryCode === "__NONE__" ? "" : getCountryFlagIconPath(countryCode);
    const sectionOpen = selectedCountries.has(countryCode) || query.length > 0;
    return `<details class="host-interest-country-group" ${sectionOpen ? "open" : ""} data-country-code="${escapeHtml(countryCode)}">
      <summary title="${escapeHtml(label)}">${flagPath ? `<img src="${flagPath}" alt="${escapeHtml(countryCode)}" class="host-interest-country-flag" />` : `<span class="host-interest-country-no-flag">${escapeHtml(label)}</span>`}<span class="host-interest-country-count">${hostsInCountry.length}</span></summary>
      <div class="host-interest-country-group-body">
        ${hostsInCountry.map(renderHostRow).join("")}
      </div>
    </details>`;
  }).join("");

  listEl.innerHTML = groupedSections || '<p class="muted">Keine Treffer für die Suche.</p>';

  listEl.querySelectorAll("[data-host-interest-key]").forEach((row) => {
    const checkbox = row.querySelector(".host-interest-toggle");
    if (!checkbox) return;
    checkbox.addEventListener("change", () => {
      const hostKey = String(row.getAttribute("data-host-interest-key") || "").trim();
      const hostname = String(row.getAttribute("data-host-interest-hostname") || "").trim();
      const countryCode = String(row.getAttribute("data-host-country-code") || "").trim().toUpperCase();
      if (!hostKey) {
        return;
      }
      const countrySelected = selectedCountries.has(countryCode);
      if (checkbox.checked) {
        manualExclusions.delete(hostKey);
        manualExclusions.delete(hostname);
        if (!countrySelected) {
          manualAdditions.add(hostKey);
        }
      } else {
        if (countrySelected) {
          manualExclusions.add(hostKey);
        } else {
          manualAdditions.delete(hostKey);
          manualAdditions.delete(hostname);
        }
      }
      state.hostInterestHostAdditions = manualAdditions;
      state.hostInterestHostExclusions = manualExclusions;
      syncEffectiveHostInterestSelection();
      renderHostInterestsEditor();
    });
  });
}

function updateOverviewSection() {
  const mainSection = document.getElementById("overviewMainSection");
  const langzeitSection = document.getElementById("overviewLangzeitSection");
  const filesystemSection = document.getElementById("overviewFilesystemSection");
  const notificationSection = document.getElementById("overviewNotificationSection");
  const databaseChangelogSection = document.getElementById("overviewDatabaseChangelogSection");
  const configChangelogSection = document.getElementById("overviewConfigChangelogSection");
  const mainTabButton = document.getElementById("overviewMainTabButton");
  const langzeitTabButton = document.getElementById("overviewLangzeitTabButton");
  const filesystemTabButton = document.getElementById("overviewFilesystemTabButton");
  const notificationTabButton = document.getElementById("overviewNotificationTabButton");
  const databaseChangelogTabButton = document.getElementById("overviewDatabaseChangelogTabButton");
  const configChangelogTabButton = document.getElementById("overviewConfigChangelogTabButton");

  if (!mainSection || !filesystemSection || !mainTabButton || !filesystemTabButton) {
    return;
  }

  const showMain = state.overviewSection === "main";
  const showLangzeit = state.overviewSection === "langzeit";
  const showFilesystem = state.overviewSection === "filesystem";
  const showNotification = state.overviewSection === "notification";
  const showDatabaseChangelog = state.overviewSection === "database-changelog";
  const showConfigChangelog = state.overviewSection === "config-changelog";

  mainSection.classList.toggle("hidden", !showMain);
  if (langzeitSection) langzeitSection.classList.toggle("hidden", !showLangzeit);
  filesystemSection.classList.toggle("hidden", !showFilesystem);
  if (notificationSection) notificationSection.classList.toggle("hidden", !showNotification);
  if (databaseChangelogSection) databaseChangelogSection.classList.toggle("hidden", !showDatabaseChangelog);
  if (configChangelogSection) configChangelogSection.classList.toggle("hidden", !showConfigChangelog);

  mainTabButton.classList.toggle("active", showMain);
  if (langzeitTabButton) langzeitTabButton.classList.toggle("active", showLangzeit);
  filesystemTabButton.classList.toggle("active", showFilesystem);
  if (notificationTabButton) notificationTabButton.classList.toggle("active", showNotification);
  if (databaseChangelogTabButton) databaseChangelogTabButton.classList.toggle("active", showDatabaseChangelog);
  if (configChangelogTabButton) configChangelogTabButton.classList.toggle("active", showConfigChangelog);
  
  mainTabButton.setAttribute("aria-selected", showMain ? "true" : "false");
  if (langzeitTabButton) langzeitTabButton.setAttribute("aria-selected", showLangzeit ? "true" : "false");
  filesystemTabButton.setAttribute("aria-selected", showFilesystem ? "true" : "false");
  if (notificationTabButton) notificationTabButton.setAttribute("aria-selected", showNotification ? "true" : "false");
  if (databaseChangelogTabButton) databaseChangelogTabButton.setAttribute("aria-selected", showDatabaseChangelog ? "true" : "false");
  if (configChangelogTabButton) configChangelogTabButton.setAttribute("aria-selected", showConfigChangelog ? "true" : "false");

  const rangeWrap = document.querySelector("#overviewView .overview-sidebar-range");
  if (rangeWrap) {
    const hideRange = showMain || showNotification || showDatabaseChangelog || showConfigChangelog;
    rangeWrap.classList.toggle("hidden", hideRange);
  }
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

function renderSettingsLogicHelp(targetId, helpBlock) {
  const container = document.getElementById(targetId);
  if (!container) {
    return;
  }

  const title = asText(helpBlock?.title, "");
  const items = Array.isArray(helpBlock?.items)
    ? helpBlock.items.map((item) => asText(item, "")).filter((item) => item && item !== "-")
    : [];

  if (!title && items.length === 0) {
    container.innerHTML = "";
    container.classList.add("hidden");
    return;
  }

  const listHtml = items.length > 0
    ? `<ul class="settings-logic-help-list">${items.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`
    : "";

  container.innerHTML = `
    <div class="settings-logic-help-card">
      ${title ? `<h6>${escapeHtml(title)}</h6>` : ""}
      ${listHtml}
    </div>
  `;
  container.classList.remove("hidden");
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

function setLoginBusy(busy) {
  const submitButton = document.getElementById("loginSubmitButton");
  const usernameInput = document.getElementById("loginUsernameInput");
  const passwordInput = document.getElementById("loginPasswordInput");
  if (submitButton) {
    submitButton.disabled = busy;
  }
  if (usernameInput) {
    usernameInput.disabled = busy;
  }
  if (passwordInput) {
    passwordInput.disabled = busy;
  }
}

function setPasswordChangeStatus(message, isError = false) {
  const statusEl = document.getElementById("passwordChangeStatus");
  if (!statusEl) {
    return;
  }
  statusEl.textContent = message;
  statusEl.classList.toggle("status-error", isError);
}

function renderMobilePushButton() {
  const button = document.getElementById("mobilePushToggleButton");
  if (!button) {
    return;
  }
  button.classList.toggle("hidden", !state.isAuthenticated);
  if (!state.isAuthenticated) {
    button.disabled = true;
    button.textContent = "🔕";
    button.title = "Mobile Push";
    button.setAttribute("aria-label", "Mobile Push (inaktiv)");
    return;
  }

  const supported = state.pushSupported === true;
  const configured = state.pushConfigured === true;
  const enabled = state.pushEnabled === true;
  const loading = state.pushLoading === true;

  if (loading) {
    button.disabled = true;
    button.textContent = "⏳";
    button.title = "Push wird aktualisiert";
    button.setAttribute("aria-label", "Mobile Push wird aktualisiert");
    return;
  }
  if (!supported) {
    button.disabled = true;
    button.textContent = "🔕";
    button.title = "Browser unterstützt Web Push nicht";
    button.setAttribute("aria-label", "Mobile Push nicht verfügbar");
    return;
  }
  if (!configured) {
    button.disabled = true;
    button.textContent = "🔕";
    button.title = "Serverseitig nicht konfiguriert";
    button.setAttribute("aria-label", "Mobile Push serverseitig nicht konfiguriert");
    return;
  }

  button.disabled = false;
  button.textContent = enabled ? "🔔" : "🔕";
  button.title = enabled
    ? "Push für dieses Gerät deaktivieren"
    : "Push für dieses Gerät aktivieren";
  button.setAttribute("aria-label", enabled ? "Mobile Push aktiv" : "Mobile Push inaktiv");
}

function base64UrlToUint8Array(base64Url) {
  const input = String(base64Url || "").trim();
  if (!input) {
    return new Uint8Array();
  }
  const padding = "=".repeat((4 - (input.length % 4)) % 4);
  const normalized = (input + padding).replace(/-/g, "+").replace(/_/g, "/");
  const raw = window.atob(normalized);
  const output = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) {
    output[i] = raw.charCodeAt(i);
  }
  return output;
}

async function refreshMobilePushState() {
  if (!state.isAuthenticated) {
    state.pushSupported = false;
    state.pushConfigured = false;
    state.pushEnabled = false;
    state.pushVapidPublicKey = "";
    state.pushLoading = false;
    renderMobilePushButton();
    return;
  }

  state.pushLoading = true;
  renderMobilePushButton();
  try {
    const response = await fetch("/api/v1/push-subscriptions", { credentials: "same-origin" });
    if (!response.ok) {
      throw new Error("HTTP " + response.status);
    }
    const payload = await response.json();
    state.pushSupported = payload.supported === true && "serviceWorker" in navigator && "PushManager" in window;
    state.pushConfigured = payload.configured === true;
    state.pushVapidPublicKey = String(payload.vapid_public_key || "");

    let localEndpoint = "";
    if (state.pushSupported) {
      const registration = await navigator.serviceWorker.ready;
      const existing = await registration.pushManager.getSubscription();
      localEndpoint = String(existing?.endpoint || "");
    }

    const serverSubscriptions = Array.isArray(payload.subscriptions) ? payload.subscriptions : [];
    state.pushEnabled = Boolean(
      localEndpoint
      && serverSubscriptions.some((item) => (
        item
        && item.is_active === true
        && String(item.endpoint || "") === localEndpoint
      ))
    );
  } catch (error) {
    state.pushSupported = false;
    state.pushConfigured = false;
    state.pushEnabled = false;
    state.pushVapidPublicKey = "";
    console.warn("refreshMobilePushState failed:", error);
  } finally {
    state.pushLoading = false;
    renderMobilePushButton();
  }
}

async function toggleMobilePush() {
  if (state.pushLoading) {
    return;
  }
  if (!state.pushSupported) {
    window.alert("Push wird in diesem Browser nicht unterstützt.");
    return;
  }
  if (!state.pushConfigured) {
    window.alert("Push ist serverseitig noch nicht konfiguriert.");
    return;
  }

  state.pushLoading = true;
  renderMobilePushButton();
  try {
    const registration = await navigator.serviceWorker.ready;
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
      window.alert("Push für dieses Gerät deaktiviert.");
      return;
    }

    let subscription = existing;
    if (!subscription) {
      const permission = await Notification.requestPermission();
      if (permission !== "granted") {
        throw new Error("Benachrichtigungsberechtigung wurde nicht erteilt");
      }
      const vapidKey = base64UrlToUint8Array(state.pushVapidPublicKey);
      subscription = await registration.pushManager.subscribe({
        userVisibleOnly: true,
        applicationServerKey: vapidKey,
      });
    }

    const saveResponse = await fetch("/api/v1/push-subscriptions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify({ action: "subscribe", subscription: subscription.toJSON() }),
    });
    if (!saveResponse.ok) {
      const errPayload = await saveResponse.json().catch(() => ({}));
      throw new Error(String(errPayload.error || ("HTTP " + saveResponse.status)));
    }

    state.pushEnabled = true;
    window.alert("Push für dieses Gerät aktiviert.");
  } catch (error) {
    window.alert("Push konnte nicht umgestellt werden: " + (error?.message || String(error)));
  } finally {
    state.pushLoading = false;
    renderMobilePushButton();
    void refreshMobilePushState();
  }
}

function setAuthUiState(authenticated) {
  const loginOverlay = document.getElementById("loginOverlay");
  const appPanel = document.getElementById("appPanel");
  const headerFiltersCollapsible = document.getElementById("headerFiltersCollapsible");
  const brandAccountShell = document.getElementById("brandAccountShell");
  const brandUserBadge = document.getElementById("brandUserBadge");
  const logoutButton = document.getElementById("logoutButton");
  loginOverlay.classList.toggle("hidden", authenticated);
  appPanel.classList.toggle("hidden", !authenticated);
  if (headerFiltersCollapsible) {
    headerFiltersCollapsible.classList.toggle("hidden", !authenticated);
  }
  if (brandAccountShell) {
    brandAccountShell.classList.toggle("hidden", !authenticated);
  }
  if (brandUserBadge) {
    brandUserBadge.classList.toggle("hidden", !authenticated);
    if (authenticated && state.authUser) {
      syncBrandProfileIdentity();
    }
  }
  if (logoutButton) {
    logoutButton.classList.toggle("hidden", !authenticated);
  }
  state.isAuthenticated = authenticated;
  syncBrandProfileIdentity();
  if (authenticated) {
    startSessionRefreshTimer();
    startSessionCountdownTimer();
    startLiveReportPoll();
  } else {
    stopSessionRefreshTimer();
    stopSessionCountdownTimer();
    stopLiveReportPoll();
    state.sessionExpiresAtUtc = "";
  }
  if (!authenticated) {
    state.isAdmin = false;
    state.userProfileLoaded = false;
    state.oauthSettingsLoaded = false;
    state.userManagementLoaded = false;
    state.adminAlertSubscriptionsLoaded = false;
    state.adminAlertSubscriptionsViewMode = "host";
    state.adminAlertSubscriptionsUsers = [];
    state.adminAlertAvailableHosts = [];
    state.adminAlertTelegramAvailable = false;
    state.pushSupported = false;
    state.pushConfigured = false;
    state.pushEnabled = false;
    state.pushVapidPublicKey = "";
  }
  renderSessionStatus();
  updateFilesystemVisibilityButtons();
  updateAdminSettingsVisibility();
  renderMobilePushButton();
  if (authenticated) {
    void refreshMobilePushState();
  }
}

function updateAdminSettingsVisibility() {
  const adminOauthSection = document.getElementById("adminOauthSettingsSection");
  const adminUserSection = document.getElementById("adminUserManagementSection");
  const globalAlarmSettingsSection = document.getElementById("globalAlarmSettingsSection");
  const agentSourceStatusTab = document.getElementById("agentSourceStatusTabButton");
  const globalAdminAlertSubsTab = document.getElementById("globalAdminAlertSubsTabButton");
  const globalAdminLoginAuditTab = document.getElementById("globalAdminLoginAuditTabButton");
  const globalAdminSettingsTab = document.getElementById("globalAdminSettingsTabButton");
  const adminOnlyTabsLegend = document.getElementById("adminOnlyTabsLegend");
  const globalAdminNavShell = document.getElementById("globalAdminNavShell");
  const globalAdminOpsSection = document.getElementById("globalAdminOpsSection");
  const changelogMaintenancePanel = document.getElementById("changelogMaintenancePanel");
  const cancelChangelogRebuildJobButton = document.getElementById("cancelChangelogRebuildJobButton");
  const changelogRebuildProgress = document.getElementById("changelogRebuildProgress");
  const anyAdminSectionActive = [
    "agent-source-status",
    "admin-alert-subs",
    "admin-login-audit",
    "admin-settings",
  ].includes(String(state.globalSubMode || ""));
  if (adminOauthSection) {
    adminOauthSection.classList.toggle("hidden", !state.isAdmin);
  }
  if (adminUserSection) {
    adminUserSection.classList.toggle("hidden", !state.isAdmin);
  }
  if (globalAlarmSettingsSection) {
    globalAlarmSettingsSection.classList.toggle("hidden", !state.isAdmin);
  }
  if (agentSourceStatusTab) {
    agentSourceStatusTab.classList.toggle("hidden", !state.isAdmin);
  }
  if (globalAdminAlertSubsTab) {
    globalAdminAlertSubsTab.classList.toggle("hidden", !state.isAdmin);
  }
  if (globalAdminLoginAuditTab) {
    globalAdminLoginAuditTab.classList.toggle("hidden", !state.isAdmin);
  }
  if (globalAdminSettingsTab) {
    globalAdminSettingsTab.classList.toggle("hidden", !state.isAdmin);
  }
  if (adminOnlyTabsLegend) {
    adminOnlyTabsLegend.classList.toggle("hidden", true);
  }
  if (globalAdminNavShell) {
    globalAdminNavShell.classList.toggle("hidden", !state.isAdmin || !anyAdminSectionActive);
  }
  if (state.isAdmin && state.globalSubMode === "admin-settings") {
    reapplyAdminWorkspaceUi();
  } else if (globalAdminOpsSection) {
    globalAdminOpsSection.classList.toggle("hidden", !state.isAdmin);
  }
  if (changelogMaintenancePanel) {
    changelogMaintenancePanel.classList.toggle("hidden", !state.isAdmin);
  }
  if (cancelChangelogRebuildJobButton) {
    const canCancel = state.isAdmin && Number(state.changelogActiveJobId || 0) > 0;
    cancelChangelogRebuildJobButton.classList.toggle("hidden", !canCancel);
  }
  if (changelogRebuildProgress && !state.isAdmin) {
    changelogRebuildProgress.classList.add("hidden");
  }
  const overviewNotificationTab = document.getElementById("overviewNotificationTabButton");
  if (overviewNotificationTab) {
    overviewNotificationTab.classList.remove("hidden");
  }
  if (!state.isAdmin && state.globalSubMode === "admin-alert-subs") {
    state.globalSubMode = "global-alerts";
    updateGlobalSubMode();
  }
  if (!state.isAdmin && state.globalSubMode === "agent-source-status") {
    state.globalSubMode = "global-alerts";
    updateGlobalSubMode();
  }
  if (!state.isAdmin && state.globalSubMode === "admin-settings") {
    state.globalSubMode = "global-alerts";
    updateGlobalSubMode();
  }
  if (!state.isAdmin && state.globalSubMode === "admin-login-audit") {
    state.globalSubMode = "global-alerts";
    updateGlobalSubMode();
  }
  if (!state.isAdmin) {
    state.adminSubMode = "agent-source-status";
    state.adminSettingsSubMode = "operations";
    state.adminOperationsSubMode = "quick";
  }
  if (state.userSettingsSubMode !== "password" && state.userSettingsSubMode !== "channels" && state.userSettingsSubMode !== "digests" && state.userSettingsSubMode !== "hosts") {
    state.userSettingsSubMode = "password";
    updateUserSettingsSubMode();
  }
}

function syncHostInterestModeControls() {
  const normalizedMode = normalizeHostInterestMode(state.hostInterestMode);
  const settingsSelect = document.getElementById("hostInterestModeSelect");
  const sidebarSelect = document.getElementById("hostSidebarInterestModeSelect");
  if (settingsSelect) {
    settingsSelect.value = normalizedMode;
  }
  if (sidebarSelect) {
    sidebarSelect.value = normalizedMode;
  }
}

async function saveHostInterestsPreferences() {
  await loadHostInterestTargets();
  syncEffectiveHostInterestSelection();
  const preferencesPayload = {
    critical_trends_metrics: state.criticalTrendsMetrics.join(","),
    host_interest_mode: normalizeHostInterestMode(state.hostInterestMode),
    host_interest_country_codes: Array.from(getHostInterestSelectedCountries()).sort().join(","),
    host_interest_host_additions: Array.from(getHostInterestManualAdditions()).sort().join(","),
    host_interest_host_exclusions: Array.from(getHostInterestManualExclusions()).sort().join(","),
  };
  const prefsResponse = await fetch("/api/v1/user-preferences", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(preferencesPayload),
  });
  const prefsData = await prefsResponse.json().catch(() => ({}));
  if (!prefsResponse.ok) {
    throw new Error(prefsData.error || ("HTTP " + prefsResponse.status));
  }

  // Auto-sync mail subscriptions for selected hosts
  try {
    const subsResponse = await fetch("/api/v1/user-alert-subscriptions", {
      method: "GET",
      headers: { "Content-Type": "application/json" },
    });
    const currentSubs = subsResponse.ok ? await subsResponse.json() : [];
    const currentSubsByHost = new Map(
      (Array.isArray(currentSubs) ? currentSubs : []).map((sub) => [
        String(sub?.hostname || "").trim(),
        {
          notify_mail: Boolean(sub?.notify_mail),
          notify_telegram: Boolean(sub?.notify_telegram),
        },
      ]).filter(([hostname]) => hostname.length > 0)
    );

    const selectorHosts = getHostInterestSelectorHosts();
    const selectedHostKeys = new Set(state.hostInterestHosts);
    const selectedHostnames = new Set();
    const allSelectorHostnames = new Set();

    for (const host of selectorHosts) {
      const hostname = asText(host?.hostname, "").trim();
      if (!hostname) continue;
      allSelectorHostnames.add(hostname);
      if (hostInterestSetHasHost(selectedHostKeys, host)) {
        selectedHostnames.add(hostname);
      }
    }

    const initiallySelectedHostnames = new Set(selectedHostnames);
    const newSubs = [];

    // Persist explicit notify_mail values for every known selector host.
    for (const hostname of allSelectorHostnames) {
      const existing = currentSubsByHost.get(hostname);
      newSubs.push({
        hostname,
        notify_mail: selectedHostnames.has(hostname),
        notify_telegram: Boolean(existing?.notify_telegram || false),
      });
    }

    // Preserve subscriptions for hosts that are currently not in selector scope.
    for (const [hostname, existing] of currentSubsByHost.entries()) {
      if (allSelectorHostnames.has(hostname)) continue;
      newSubs.push({
        hostname,
        notify_mail: Boolean(existing.notify_mail),
        notify_telegram: Boolean(existing.notify_telegram),
      });
    }
    
    // Save updated subscriptions
    if (newSubs.length > 0) {
      const updateResponse = await fetch("/api/v1/user-alert-subscriptions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ subscriptions: newSubs }),
      });
      
      if (updateResponse.ok) {
        // Show notification about auto-activated mail subscriptions
        const activatedHosts = Array.from(initiallySelectedHostnames).sort();
        if (activatedHosts.length > 0) {
          const message = activatedHosts.length === 1
            ? `Mail-Abo automatisch aktiviert für: ${activatedHosts[0]}`
            : `Mail-Abos automatisch aktiviert für ${activatedHosts.length} Hosts`;
          showToast("success", message, 4000);
        }
      }
    }
  } catch (err) {
    // Silently fail subscription sync - preferences are already saved
    console.debug("Subscription sync failed:", err);
  }
}

async function fetchSessionState() {
  const controller = new AbortController();
  const timeoutId = window.setTimeout(() => controller.abort(), 8000);
  try {
    const response = await fetch("/api/v1/session", {
      credentials: "same-origin",
      signal: controller.signal,
    });
    if (!response.ok) {
      throw new Error("HTTP " + response.status);
    }
    return response.json();
  } finally {
    window.clearTimeout(timeoutId);
  }
}

async function ensureAuthenticatedSession() {
  try {
    const session = await fetchSessionState();
    state.authUser = asText(session.username, "");
    state.authDisplayName = asText(session.display_name, "");
    state.isAdmin = session.is_admin === true;
    updateSessionExpiry(
      asText(session.expires_at_utc, ""),
      Number.parseInt(String(session.inactivity_timeout_minutes || ""), 10)
    );
    setAuthUiState(session.authenticated === true);
    if (session.authenticated === true) {
      loadHostFilterPreferences();
      reloadHeaderSectionPreferencesForUser();
      // Load user preferences in background — does not block hosts from rendering.
      // Re-render host list once prefs arrive so hostInterestMode filter is applied.
      loadUserPreferences().then(() => {
        if (state.hosts && state.hosts.length > 0) {
          renderHosts(state.hosts);
        }
      });
    }
    return session.authenticated === true;
  } catch (error) {
    setAuthUiState(false);
    if (error?.name === "AbortError") {
      setLoginStatus("Sitzungsprüfung Zeitüberschreitung – bitte anmelden.", true);
    }
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

  setLoginBusy(true);
  setLoginStatus("Anmeldung läuft…");
  const loginAbort = new AbortController();
  const loginTimeoutId = window.setTimeout(() => loginAbort.abort(), 15000);
  try {
    const response = await fetch("/api/v1/web-login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      credentials: "same-origin",
      signal: loginAbort.signal,
      body: JSON.stringify({ username, password }),
    });

    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      if (response.status === 503 && data.code === "database_locked") {
        setLoginStatus(data.error || "Datenbank vorübergehend gesperrt. Bitte kurz warten und erneut versuchen.", true);
        return false;
      }
      if (response.status === 502) {
        setLoginStatus(
          "Gateway-Fehler (502): Server/DB überlastet. 30 Sekunden warten, dann erneut anmelden.",
          true
        );
        return false;
      }
      setLoginStatus(data.error || ("Login fehlgeschlagen (HTTP " + response.status + ")"), true);
      return false;
    }

    state.authUser = asText(data.username, username);
    state.authDisplayName = asText(data.display_name, "");
    state.isAdmin = data.is_admin === true;
    state.viewMode = "overview";
    state.overviewSection = "main";
    updateSessionExpiry(
      asText(data.expires_at_utc, ""),
      Number.parseInt(String(data.inactivity_timeout_minutes || ""), 10)
    );
    loadHostFilterPreferences();
    reloadHeaderSectionPreferencesForUser();
    resetUserScopedPreferences();
    sessionEstablishedAtMs = Date.now();
    setAuthUiState(true);
    passwordInput.value = "";
    setLoginStatus("Anmeldung erfolgreich.");
    const hostList = document.getElementById("hostList");
    if (hostList) {
      hostList.innerHTML = '<p class="muted">Lade Hosts…</p>';
    }
    void loadUserPreferences().then(() => {
      if (state.hosts && state.hosts.length > 0) {
        renderHosts(state.hosts);
      }
    });
    return true;
  } catch (error) {
    let message = error?.message || "Anmeldung fehlgeschlagen.";
    if (error?.name === "AbortError") {
      message = "Zeitüberschreitung: Server antwortet nicht (Wartungsjob oder Service hängt). Bitte monitoring-Service prüfen.";
    } else if (/failed to fetch/i.test(message)) {
      message = "Verbindung fehlgeschlagen (Netzwerk/Proxy). F12 → Netzwerk → web-login prüfen; auf dem Server: systemctl status monitoring";
    }
    setLoginStatus(message, true);
    return false;
  } finally {
    window.clearTimeout(loginTimeoutId);
    setLoginBusy(false);
  }
}

async function logoutWebClient() {
  try {
    await fetch("/api/v1/web-logout", { method: "POST", credentials: "same-origin" });
  } catch {
    // ignore network errors – session will be cleared server-side anyway
  }
  stopAutoRefreshTimer();
  stopSessionRefreshTimer();
  stopSessionCountdownTimer();
  updateAutoRefreshStatus(null);
  state.authUser = "";
  state.isAdmin = false;
  state.viewMode = "overview";
  state.overviewSection = "main";
  resetUserScopedPreferences();
  setAuthUiState(false);
  const brandUserBadge = document.getElementById("brandUserBadge");
  if (brandUserBadge) {
    brandUserBadge.textContent = "";
  }
  state.authDisplayName = "";
  state.sessionExpiresAtUtc = "";
  liveReportFeedItems = [];
  liveReportPollCursorId = 0;
  stopLiveReportPoll();
  renderLiveReportFeed();
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
    setPasswordChangeStatus("Neue Passwörter stimmen nicht überein.", true);
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
    setPasswordChangeStatus(data.error || ("Änderung fehlgeschlagen (HTTP " + response.status + ")"), true);
    return;
  }

  currentPasswordInput.value = "";
  newPasswordInput.value = "";
  confirmPasswordInput.value = "";
  setPasswordChangeStatus("Passwort erfolgreich geändert.", false);
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
  const alertTelegramReminderIntervalHoursInput = document.getElementById("alertTelegramReminderIntervalHoursInput");
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
    if (alertTelegramReminderIntervalHoursInput) {
      alertTelegramReminderIntervalHoursInput.value = String(Number(settings.alert_telegram_reminder_interval_hours || 0));
    }
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
    const logicHelp = profile.mail_logic_help || {};
    enabledInput.checked = profile.email_enabled === true;
    recipientInput.value = asText(profile.email_recipient, "") === "-" ? "" : asText(profile.email_recipient, "");
    trendEnabledInput.checked = profile.trend_email_enabled === true;
    trendTimeInput.value = asText(profile.trend_email_time_hhmm, "08:00");
    const trendRecipientInput = document.getElementById("trendDigestRecipientInput");
    if (trendRecipientInput) trendRecipientInput.value = asText(profile.email_recipient, "") === "-" ? "" : asText(profile.email_recipient, "");
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
    try {
      const prefsResponse = await fetch("/api/v1/user-preferences", { credentials: "same-origin" });
      if (prefsResponse.ok) {
        const prefs = await prefsResponse.json();
        const metricsStr = String(prefs.critical_trends_metrics || "filesystem").trim();
        const metrics = metricsStr.split(",").map((m) => m.trim()).filter((m) => m.length > 0);
        state.criticalTrendsMetrics = metrics.length > 0 ? metrics : ["filesystem"];
        state.hostInterestMode = normalizeHostInterestMode(prefs.host_interest_mode || "all");
        state.hostInterestCountryCodes = new Set(
          String(prefs.host_interest_country_codes || "")
            .split(",")
            .map((item) => String(item || "").trim().toUpperCase())
            .filter((item) => /^[A-Z]{2}$/.test(item))
        );
        state.hostInterestHostAdditions = new Set(
          String(prefs.host_interest_host_additions || "")
            .split(",")
            .map((item) => String(item || "").trim())
            .filter((item) => item.length > 0)
        );
        state.hostInterestHostExclusions = new Set(
          String(prefs.host_interest_host_exclusions || "")
            .split(",")
            .map((item) => String(item || "").trim())
            .filter((item) => item.length > 0)
        );
        syncEffectiveHostInterestSelection();
      }
    } catch (_error) {
      // Keep existing in-memory preferences if loading fails.
    }
    updateCriticalTrendsMetricsCheckboxes();
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
    renderSettingsLogicHelp("mailChannelsLogicHelp", logicHelp.channels);
    renderSettingsLogicHelp("trendDigestLogicHelp", logicHelp.trend_digest);
    renderSettingsLogicHelp("alertDigestLogicHelp", logicHelp.alert_digest);
    renderSettingsLogicHelp("instantAlertsLogicHelp", logicHelp.instant_alerts);
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
  const selectedDigestMetrics = ["digestMetricCpu", "digestMetricMemory", "digestMetricSwap", "digestMetricFilesystem"]
    .filter((id) => document.getElementById(id)?.checked)
    .map((id) => id.replace("digestMetric", "").toLowerCase());
  const digestMetrics = selectedDigestMetrics.length > 0 ? selectedDigestMetrics : ["filesystem"];

  const payload = {
    email_enabled: enabledInput.checked,
    email_recipient: recipientInput.value.trim(),
    trend_email_enabled: document.getElementById("trendEmailEnabledInput").checked,
    trend_email_time_hhmm: document.getElementById("trendEmailTimeInput").value || "08:00",
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
  };

  if (payload.email_enabled && !payload.email_recipient) {
    throw new Error("Bitte zuerst einen Mail-Empfänger eintragen.");
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

  state.hostInterestMode = normalizeHostInterestMode(document.getElementById("hostInterestModeSelect")?.value || state.hostInterestMode);
  syncHostInterestModeControls();
  await saveHostInterestsPreferences();
  state.criticalTrendsMetrics = digestMetrics;
  updateCriticalTrendsMetricsCheckboxes();

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
    const userLabel = webUserDisplayLabel(username, displayName);
    const adminPill = `<span class="user-flag-pill ${user.is_admin ? "on" : "off"}">${user.is_admin ? "Admin" : "User"}</span>`;
    const activePill = `<span class="user-flag-pill ${user.is_disabled ? "off" : "on"}">${user.is_disabled ? "Gesperrt" : "Aktiv"}</span>`;
    const oauthPill = `<span class="oauth-state-pill ${user.has_microsoft_oauth ? "connected" : "disconnected"}">${user.has_microsoft_oauth ? asText(user.microsoft_connected_email, "verbunden") : "nicht verbunden"}</span>`;

    return `
      <tr>
        <td>
          <strong>${escapeHtml(userLabel)}</strong>
          ${displayName && displayName !== username ? `<div class="muted compact">Login: ${escapeHtml(username)}</div>` : ""}
        </td>
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
            <button type="button" data-user-action="delete" data-username-enc="${usernameEnc}">Löschen</button>
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
          const password = window.prompt(`Neues Passwort für ${username}:`, "");
          if (password === null) {
            return;
          }
          await submitWebUserAction({ action: "set-password", username, password });
          setUserManagementStatus(`Passwort für ${username} aktualisiert.`);
        } else if (action === "display-name") {
          const current = button.getAttribute("data-current-name") || "";
          const newName = window.prompt(`Anzeigename für ${username}:`, current);
          if (newName === null) {
            return;
          }
          await submitWebUserAction({ action: "update-display-name", username, display_name: newName.trim() });
          setUserManagementStatus(`Anzeigename für ${username} aktualisiert.`);
        } else if (action === "admin") {
          await submitWebUserAction({
            action: "update-flags",
            username,
            is_admin: button.getAttribute("data-next") === "1",
          });
          setUserManagementStatus(`Admin-Flag für ${username} aktualisiert.`);
        } else if (action === "disable") {
          await submitWebUserAction({
            action: "update-flags",
            username,
            is_disabled: button.getAttribute("data-next") === "1",
          });
          setUserManagementStatus(`Status für ${username} aktualisiert.`);
        } else if (action === "delete") {
          if (!window.confirm(`Benutzer ${username} wirklich löschen?`)) {
            return;
          }
          await submitWebUserAction({ action: "delete", username });
          setUserManagementStatus(`Benutzer ${username} gelöscht.`);
        }
        state.userManagementLoaded = false;
        await loadWebUsers(true);
        // Refresh badge if the current user changed their own display name
        if (action === "display-name" && username === state.authUser) {
          try {
            const session = await fetchSessionState();
            state.authDisplayName = asText(session.display_name, "");
            syncBrandProfileIdentity();
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
  rowsEl.innerHTML = '<tr><td colspan="7" class="muted">Lade Benutzer...</td></tr>';
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
    rowsEl.innerHTML = `<tr><td colspan="7" class="muted">Fehler: ${escapeHtml(error.message)}</td></tr>`;
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

function setAdminLoginAuditStatus(message, isError = false) {
  const statusEl = document.getElementById("adminLoginAuditStatus");
  if (!statusEl) return;
  statusEl.textContent = message;
  statusEl.classList.toggle("error", isError);
}

async function loadAdminLoginAudit() {
  const rowsEl = document.getElementById("adminLoginAuditRows");
  if (!rowsEl) return;
  rowsEl.innerHTML = '<tr><td colspan="4" class="muted">Lade Login-Changelog...</td></tr>';
  setAdminLoginAuditStatus("Lade...");
  try {
    const response = await fetch("/api/v1/admin/login-events");
    if (!response.ok) throw new Error("HTTP " + response.status);
    const data = await response.json();
    const entries = Array.isArray(data.entries) ? data.entries : [];
    if (entries.length === 0) {
      rowsEl.innerHTML = '<tr><td colspan="4" class="muted">Keine Einträge vorhanden.</td></tr>';
      setAdminLoginAuditStatus("Keine Einträge.");
      return;
    }
    rowsEl.innerHTML = entries.map((entry) => {
      const username = asText(entry.username, "-");
      const displayName = asText(entry.display_name, "");
      const who = webUserDisplayLabel(username, displayName);
      const timeText = asText(entry.logged_at_utc, "") ? formatUtcPlus2(asText(entry.logged_at_utc, "")) : "-";
      const sourceIp = asText(entry.source_ip, "-");
      const method = asText(entry.auth_method, "password");
      return `<tr>
        <td>${escapeHtml(timeText)}</td>
        <td>${escapeHtml(who)}</td>
        <td>${escapeHtml(sourceIp)}</td>
        <td>${escapeHtml(method)}</td>
      </tr>`;
    }).join("");
    setAdminLoginAuditStatus(`Geladen (${entries.length}).`);
  } catch (error) {
    rowsEl.innerHTML = `<tr><td colspan="4" class="muted">Fehler: ${escapeHtml(error.message)}</td></tr>`;
    setAdminLoginAuditStatus(`Fehler: ${error.message}`, true);
  }
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

  const normalizeCountryCode = (value) => {
    const normalized = String(value || "").trim().toUpperCase();
    return /^[A-Z]{2}$/.test(normalized) ? normalized : "";
  };
  let userFocusCountryFilter = "ALL";

  const normalizeAdminAlertViewMode = () => {
    if (state.adminAlertSubscriptionsViewMode === "user") return "user";
    if (state.adminAlertSubscriptionsViewMode === "user-focus") return "user-focus";
    return "user-focus";
  };

  const originalSubscriptions = new Map();
  const currentSubscriptions = new Map();

  const ensureHostEntry = (targetMap, username, hostname) => {
    if (!targetMap.has(username)) {
      targetMap.set(username, new Map());
    }
    const hostMap = targetMap.get(username);
    if (!hostMap.has(hostname)) {
      hostMap.set(hostname, { hostname, notify_mail: true, notify_telegram: true, is_admin_override: false });
    }
    return hostMap.get(hostname);
  };

  for (const userEntry of usersSorted) {
    const username = String(userEntry.username || "").trim();
    if (!username) continue;
    for (const host of hosts) {
      const hostname = String(host.hostname || "").trim();
      if (!hostname) continue;
      ensureHostEntry(originalSubscriptions, username, hostname);
      ensureHostEntry(currentSubscriptions, username, hostname);
    }
    for (const sub of Array.isArray(userEntry.subscriptions) ? userEntry.subscriptions : []) {
      const hostname = String(sub.hostname || "").trim();
      if (!hostname) continue;
      const originalEntry = ensureHostEntry(originalSubscriptions, username, hostname);
      originalEntry.notify_mail = sub.notify_mail !== false;
      originalEntry.notify_telegram = sub.notify_telegram !== false;
      originalEntry.is_admin_override = sub.is_admin_override === true;
      const currentEntry = ensureHostEntry(currentSubscriptions, username, hostname);
      currentEntry.notify_mail = originalEntry.notify_mail;
      currentEntry.notify_telegram = originalEntry.notify_telegram;
      currentEntry.is_admin_override = originalEntry.is_admin_override;
    }
  }

  const userOptions = usersSorted
    .map((userEntry) => {
      const usernameRaw = String(userEntry.username || "").trim();
      const username = escapeHtml(usernameRaw);
      const userLabel = escapeHtml(webUserDisplayLabel(usernameRaw, userEntry.display_name));
      const selectedAttr = usernameRaw && usernameRaw === String(state.adminAlertSubscriptionsSelectedUser || "").trim() ? " selected" : "";
      return `<option value="${username}"${selectedAttr}>${userLabel}</option>`;
    })
    .join("");

  container.innerHTML = `<div class="admin-alert-sub-controls">
    <label>
      Ansicht
      <select id="adminAlertSubsViewModeSelect">
        <option value="host">Host-Ansicht</option>
        <option value="user">User-Ansicht</option>
        <option value="user-focus">User-Fokus (Flags)</option>
      </select>
    </label>
    <label>
      Hostsuche
      <input id="adminAlertSubsHostSearchInput" type="text" placeholder="Host oder Anzeigename" />
    </label>
    <label>
      Benutzerfilter
      <select id="adminAlertSubsUserFilterSelect">
        <option value="">Alle Benutzer</option>
        ${userOptions}
      </select>
    </label>
    <label class="checkbox-line">
      <input id="adminAlertSubsOnlyChangedInput" type="checkbox" />
      Nur Änderungen
    </label>
    <div class="admin-sub-bulk-group">
      <button type="button" class="btn-secondary" id="adminAlertSubsBulkMailOnButton">Sichtbar: Mail an</button>
      <button type="button" class="btn-secondary" id="adminAlertSubsBulkMailOffButton">Sichtbar: Mail aus</button>
      <button type="button" class="btn-secondary" id="adminAlertSubsBulkTelegramOnButton" ${telegramAvailable ? "" : "disabled"}>Sichtbar: Telegram an</button>
      <button type="button" class="btn-secondary" id="adminAlertSubsBulkTelegramOffButton" ${telegramAvailable ? "" : "disabled"}>Sichtbar: Telegram aus</button>
    </div>
  </div>
  <div id="adminAlertSubscriptionsTableWrap"></div>`;

  const userFilterSelectInit = document.getElementById("adminAlertSubsUserFilterSelect");
  if (userFilterSelectInit) {
    const desiredUser = String(state.adminAlertSubscriptionsSelectedUser || "").trim();
    if (desiredUser) {
      userFilterSelectInit.value = desiredUser;
    }
  }

  const getCurrentEntry = (username, hostname) => {
    const userMap = currentSubscriptions.get(username);
    if (!userMap) return { hostname, notify_mail: true, notify_telegram: true, is_admin_override: false };
    return userMap.get(hostname) || { hostname, notify_mail: true, notify_telegram: true, is_admin_override: false };
  };

  const getOriginalEntry = (username, hostname) => {
    const userMap = originalSubscriptions.get(username);
    if (!userMap) return { hostname, notify_mail: true, notify_telegram: true, is_admin_override: false };
    return userMap.get(hostname) || { hostname, notify_mail: true, notify_telegram: true, is_admin_override: false };
  };

  const captureCurrentFromDom = () => {
    container.querySelectorAll(".admin-sub-cb[data-username][data-hostname][data-channel]").forEach((checkbox) => {
      const username = String(checkbox.dataset.username || "");
      const hostname = String(checkbox.dataset.hostname || "");
      const channel = String(checkbox.dataset.channel || "");
      if (!username || !hostname || (channel !== "mail" && channel !== "telegram")) return;
      const entry = ensureHostEntry(currentSubscriptions, username, hostname);
      if (channel === "mail") entry.notify_mail = checkbox.checked;
      if (channel === "telegram") entry.notify_telegram = checkbox.checked;
    });
  };

  const wireDynamicTableEvents = () => {
    container.querySelectorAll(".admin-sub-cb").forEach((checkbox) => {
      checkbox.addEventListener("change", () => {
        markUnsavedStatus();
      });
    });

    container.querySelectorAll(".admin-sub-row-bulk[data-scope][data-channel][data-value]").forEach((button) => {
      button.addEventListener("click", () => {
        const scope = button.dataset.scope || "";
        const key = scope === "user" ? (button.dataset.username || "") : (button.dataset.hostname || "");
        const channel = button.dataset.channel || "";
        const enabled = button.dataset.value === "on";
        if (!key || (scope !== "host" && scope !== "user") || (channel !== "mail" && channel !== "telegram")) return;
        applyRowBulk(scope, key, channel, enabled);
      });
    });
  };

  const renderTable = () => {
    const tableWrap = document.getElementById("adminAlertSubscriptionsTableWrap");
    if (!tableWrap) return;
    const viewMode = normalizeAdminAlertViewMode();

    const renderAdminHostLabel = (host) => {
      const hostnameRaw = String(host.hostname || "").trim();
      const displayNameRaw = String(host.display_name || hostnameRaw || "").trim();
      const customerNameRaw = String(host.customer_name || "").trim();
      const hostname = escapeHtml(hostnameRaw);
      const displayName = escapeHtml(displayNameRaw || hostnameRaw);
      const customerName = escapeHtml(customerNameRaw);
      const title = displayNameRaw && hostnameRaw && displayNameRaw !== hostnameRaw
        ? `<strong>${displayName}</strong><span class="global-hostname-sub">(${hostname})</span>`
        : `<strong>${displayName || hostname}</strong>`;
      const customerLine = customerNameRaw
        ? `<span class="admin-sub-host-customer">${customerName}</span>`
        : "";
      return `${title}${customerLine}`;
    };

    const renderHostRows = () => {
      if (hosts.length === 0) {
        return '<tr data-row-type="host"><td colspan="3" class="muted">Keine Hosts vorhanden.</td></tr>';
      }
      const groupedByCountry = new Map();
      for (const host of hosts) {
        const countryCode = normalizeCountryCode(host.country_code) || "__NONE__";
        if (!groupedByCountry.has(countryCode)) groupedByCountry.set(countryCode, []);
        groupedByCountry.get(countryCode).push(host);
      }

      const countryCodes = Array.from(groupedByCountry.keys()).sort((a, b) => {
        if (a === "__NONE__") return 1;
        if (b === "__NONE__") return -1;
        return a.localeCompare(b);
      });

      return countryCodes.map((countryCode) => {
        const hostsInCountry = groupedByCountry.get(countryCode) || [];
        const countryLabel = countryCode === "__NONE__" ? "Ohne Land" : countryCode;

        const hostRows = hostsInCountry.map((host) => {
        const hostnameRaw = String(host.hostname || "").trim();
        const displayNameRaw = String(host.display_name || hostnameRaw || "").trim();
        const hostname = escapeHtml(hostnameRaw);
        const displayName = escapeHtml(displayNameRaw || hostnameRaw);
        const hostLabel = renderAdminHostLabel(host);

        const rowActions = `<div class="admin-sub-row-actions">
          <button type="button" class="admin-sub-row-bulk" data-scope="host" data-hostname="${hostname}" data-channel="mail" data-value="on">Mail alle an</button>
          <button type="button" class="admin-sub-row-bulk" data-scope="host" data-hostname="${hostname}" data-channel="mail" data-value="off">Mail alle aus</button>
          <button type="button" class="admin-sub-row-bulk" data-scope="host" data-hostname="${hostname}" data-channel="telegram" data-value="on" ${telegramAvailable ? "" : "disabled"}>Telegram alle an</button>
          <button type="button" class="admin-sub-row-bulk" data-scope="host" data-hostname="${hostname}" data-channel="telegram" data-value="off" ${telegramAvailable ? "" : "disabled"}>Telegram alle aus</button>
        </div>`;

        const renderChannelRows = (channel) => usersSorted.map((userEntry) => {
          const usernameRaw = String(userEntry.username || "");
          const username = escapeHtml(usernameRaw);
          const currentEntry = getCurrentEntry(usernameRaw, hostnameRaw);
          const originalEntry = getOriginalEntry(usernameRaw, hostnameRaw);
          const enabled = channel === "mail" ? currentEntry.notify_mail : currentEntry.notify_telegram;
          const originalEnabled = channel === "mail" ? originalEntry.notify_mail : originalEntry.notify_telegram;
          const disabled = channel === "telegram" && !telegramAvailable;
          const overrideBadge = currentEntry.is_admin_override ? '<span class="admin-sub-override-pill" title="Admin-Override">Admin</span>' : "";
          return `<label class="admin-sub-user-chip${userEntry.is_admin ? " is-admin" : ""}${currentEntry.is_admin_override ? " is-admin-override" : ""}${disabled ? " is-disabled" : ""}" data-username="${username}" title="${currentEntry.is_admin_override ? "Admin-Override" : ""}">
            <input type="checkbox" class="admin-sub-cb" data-username="${username}" data-hostname="${hostname}" data-channel="${channel}" data-original-checked="${originalEnabled ? "1" : "0"}" ${enabled ? "checked" : ""} ${disabled ? "disabled" : ""}>
            <span class="admin-sub-user-name">${escapeHtml(webUserDisplayLabel(usernameRaw, userEntry.display_name))}</span>
            ${overrideBadge}
          </label>`;
        }).join("");

        return `<tr data-row-type="host" data-country-code="${escapeHtml(countryCode)}" data-hostname="${hostname}" data-display-name="${displayName}">
          <td class="admin-sub-host-cell">${hostLabel}${rowActions}</td>
          <td><div class="admin-sub-user-stack">${renderChannelRows("mail")}</div></td>
          <td><div class="admin-sub-user-stack">${renderChannelRows("telegram")}</div></td>
        </tr>`;
        }).join("");

        return `<tr data-row-type="country" data-country-code="${escapeHtml(countryCode)}" class="admin-sub-country-row">
          <td colspan="3">
            <span class="admin-sub-country-title">Land: ${escapeHtml(countryLabel)}</span>
            <span class="admin-sub-country-count">${hostsInCountry.length} Host${hostsInCountry.length === 1 ? "" : "s"}</span>
          </td>
        </tr>${hostRows}`;
      }).join("");
    };

    const renderUserRows = () => {
      if (usersSorted.length === 0) {
        return '<tr data-row-type="user"><td colspan="3" class="muted">Keine Benutzer vorhanden.</td></tr>';
      }
      return usersSorted.map((userEntry) => {
        const usernameRaw = String(userEntry.username || "").trim();
        const username = escapeHtml(usernameRaw);
        const rowActions = `<div class="admin-sub-row-actions">
          <button type="button" class="admin-sub-row-bulk" data-scope="user" data-username="${username}" data-channel="mail" data-value="on">Mail alle Hosts an</button>
          <button type="button" class="admin-sub-row-bulk" data-scope="user" data-username="${username}" data-channel="mail" data-value="off">Mail alle Hosts aus</button>
          <button type="button" class="admin-sub-row-bulk" data-scope="user" data-username="${username}" data-channel="telegram" data-value="on" ${telegramAvailable ? "" : "disabled"}>Telegram alle Hosts an</button>
          <button type="button" class="admin-sub-row-bulk" data-scope="user" data-username="${username}" data-channel="telegram" data-value="off" ${telegramAvailable ? "" : "disabled"}>Telegram alle Hosts aus</button>
        </div>`;

        const hostSearchBlob = hosts.map((host) => {
          return `${String(host.display_name || "")} ${String(host.hostname || "")}`.toLowerCase();
        }).join(" ");

        const renderChannelRows = (channel) => hosts.map((host) => {
          const hostnameRaw = String(host.hostname || "").trim();
          const displayNameRaw = String(host.display_name || hostnameRaw || "").trim();
          const displayName = escapeHtml(displayNameRaw || hostnameRaw);
          const hostname = escapeHtml(hostnameRaw);
          const currentEntry = getCurrentEntry(usernameRaw, hostnameRaw);
          const originalEntry = getOriginalEntry(usernameRaw, hostnameRaw);
          const enabled = channel === "mail" ? currentEntry.notify_mail : currentEntry.notify_telegram;
          const originalEnabled = channel === "mail" ? originalEntry.notify_mail : originalEntry.notify_telegram;
          const disabled = channel === "telegram" && !telegramAvailable;
          const hostLabel = displayNameRaw && hostnameRaw && displayNameRaw !== hostnameRaw
            ? `${displayName} (${hostname})`
            : `${displayName || hostname}`;
          const overrideBadge = currentEntry.is_admin_override ? '<span class="admin-sub-override-pill" title="Admin-Override">Admin</span>' : "";
          return `<label class="admin-sub-user-chip${currentEntry.is_admin_override ? " is-admin-override" : ""}${disabled ? " is-disabled" : ""}" data-hostname="${hostname}" title="${currentEntry.is_admin_override ? "Admin-Override" : ""}">
            <input type="checkbox" class="admin-sub-cb" data-username="${username}" data-hostname="${hostname}" data-channel="${channel}" data-original-checked="${originalEnabled ? "1" : "0"}" ${enabled ? "checked" : ""} ${disabled ? "disabled" : ""}>
            <span class="admin-sub-user-name">${hostLabel}</span>
            ${overrideBadge}
          </label>`;
        }).join("");

        const userRowLabel = escapeHtml(webUserDisplayLabel(usernameRaw, userEntry.display_name));
        return `<tr data-row-type="user" data-username="${username}" data-host-search="${escapeHtml(hostSearchBlob)}">
          <td class="admin-sub-host-cell"><strong>${userRowLabel}</strong>${rowActions}</td>
          <td><div class="admin-sub-user-stack">${renderChannelRows("mail")}</div></td>
          <td><div class="admin-sub-user-stack">${renderChannelRows("telegram")}</div></td>
        </tr>`;
      }).join("");
    };

    const renderUserFocusRows = () => {
      if (hosts.length === 0) {
        return {
          chips: '<p class="muted">Keine Länder verfügbar.</p>',
          list: '<p class="muted">Keine Hosts vorhanden.</p>',
          selectedUser: "",
        };
      }

      const userFilterSelect = document.getElementById("adminAlertSubsUserFilterSelect");
      let selectedUser = String(state.adminAlertSubscriptionsSelectedUser || userFilterSelect?.value || "").trim();
      if (!selectedUser) {
        selectedUser = String(usersSorted[0]?.username || "").trim();
        if (userFilterSelect && selectedUser) {
          userFilterSelect.value = selectedUser;
        }
        state.adminAlertSubscriptionsSelectedUser = selectedUser;
      }
      if (!selectedUser) {
        return {
          chips: '<p class="muted">Keine Benutzer vorhanden.</p>',
          list: '<p class="muted">Keine Benutzer vorhanden.</p>',
          selectedUser: "",
        };
      }

      const groupedByCountry = new Map();
      for (const host of hosts) {
        const countryCode = normalizeCountryCode(host.country_code) || "__NONE__";
        if (!groupedByCountry.has(countryCode)) groupedByCountry.set(countryCode, []);
        groupedByCountry.get(countryCode).push(host);
      }
      const countryCodes = Array.from(groupedByCountry.keys()).sort((a, b) => {
        if (a === "__NONE__") return 1;
        if (b === "__NONE__") return -1;
        return a.localeCompare(b);
      });

      const chips = `<div class="host-interest-country-head admin-user-focus-country-head">${countryCodes.map((countryCode) => {
        const hostsInCountry = groupedByCountry.get(countryCode) || [];
        const label = countryCode === "__NONE__" ? "Ohne Land" : countryCode;
        const flagPath = countryCode === "__NONE__" ? "" : getCountryFlagIconPath(countryCode);
        const active = userFocusCountryFilter === countryCode;
        return `<button type="button" class="host-interest-country-chip admin-sub-country-filter-chip${active ? " is-active" : ""}" data-country-filter="${escapeHtml(countryCode)}">
          ${flagPath ? `<img src="${flagPath}" alt="${escapeHtml(countryCode)}" class="host-interest-country-flag" />` : ""}
          <span class="host-interest-country-chip-label">${escapeHtml(label)}</span>
          <span class="host-interest-country-chip-count">${hostsInCountry.length}</span>
        </button>`;
      }).join("")}</div>`;

      const controls = `<div class="admin-user-focus-actions">
        <button type="button" class="btn-secondary" id="adminUserFocusAllHostsButton">Alle Hosts anzeigen</button>
      </div>`;

      const list = countryCodes.map((countryCode) => {
        const hostsInCountry = groupedByCountry.get(countryCode) || [];
        const countryLabel = countryCode === "__NONE__" ? "Ohne Land" : countryCode;
        const flagPath = countryCode === "__NONE__" ? "" : getCountryFlagIconPath(countryCode);
        const hostRows = hostsInCountry.map((host) => {
          const hostnameRaw = String(host.hostname || "").trim();
          const hostname = escapeHtml(hostnameRaw);
          const hostLabel = renderAdminHostLabel(host);
          const currentEntry = getCurrentEntry(selectedUser, hostnameRaw);
          const originalEntry = getOriginalEntry(selectedUser, hostnameRaw);
          const mailChecked = currentEntry.notify_mail;
          const telegramChecked = currentEntry.notify_telegram;
          const displaySearch = `${String(host.display_name || "").trim()} ${hostnameRaw}`.toLowerCase();

          return `<div class="host-interest-item admin-user-focus-host-row" data-row-type="host" data-country-code="${escapeHtml(countryCode)}" data-hostname="${hostname}" data-display-name="${escapeHtml(displaySearch)}" data-username="${escapeHtml(selectedUser)}">
            <span class="host-interest-meta">${hostLabel}</span>
            <span class="admin-user-focus-channels">
              <label class="admin-sub-user-chip${currentEntry.is_admin_override ? " is-admin-override" : ""}">
                <input type="checkbox" class="admin-sub-cb" data-username="${escapeHtml(selectedUser)}" data-hostname="${hostname}" data-channel="mail" data-original-checked="${originalEntry.notify_mail ? "1" : "0"}" ${mailChecked ? "checked" : ""}>
                <span class="admin-sub-user-name">Mail aktiv</span>
              </label>
              <label class="admin-sub-user-chip${currentEntry.is_admin_override ? " is-admin-override" : ""}${telegramAvailable ? "" : " is-disabled"}">
                <input type="checkbox" class="admin-sub-cb" data-username="${escapeHtml(selectedUser)}" data-hostname="${hostname}" data-channel="telegram" data-original-checked="${originalEntry.notify_telegram ? "1" : "0"}" ${telegramChecked ? "checked" : ""} ${telegramAvailable ? "" : "disabled"}>
                <span class="admin-sub-user-name">Telegram aktiv</span>
              </label>
            </span>
          </div>`;
        }).join("");

        const openByDefault = userFocusCountryFilter === "ALL" || userFocusCountryFilter === countryCode;
        return `<details class="host-interest-country-group admin-user-focus-country-group" data-row-type="country" data-country-code="${escapeHtml(countryCode)}" ${openByDefault ? "open" : ""}>
          <summary title="${escapeHtml(countryLabel)}">${flagPath ? `<img src="${flagPath}" alt="${escapeHtml(countryCode)}" class="host-interest-country-flag" />` : `<span class="host-interest-country-no-flag">${escapeHtml(countryLabel)}</span>`}<span class="host-interest-country-count">${hostsInCountry.length}</span></summary>
          <div class="host-interest-country-group-body">${hostRows}</div>
        </details>`;
      }).join("");

      return { chips: `${chips}${controls}`, list, selectedUser };
    };

    let rows = "";
    let firstColTitle = "Host";
    let chips = "";
    let userFocusList = "";
    if (viewMode === "user") {
      rows = renderUserRows();
      firstColTitle = "Benutzer";
    } else if (viewMode === "user-focus") {
      const result = renderUserFocusRows();
      userFocusList = result.list;
      chips = result.chips;
    } else {
      rows = renderHostRows();
      firstColTitle = "Host";
    }

    if (viewMode === "user-focus") {
      tableWrap.innerHTML = `${chips}<div class="admin-user-focus-list">${userFocusList}</div>`;
      const allHostsButton = document.getElementById("adminUserFocusAllHostsButton");
      if (allHostsButton) {
        allHostsButton.addEventListener("click", () => {
          userFocusCountryFilter = "ALL";
          const userFilterSelect = document.getElementById("adminAlertSubsUserFilterSelect");
          if (userFilterSelect && state.adminAlertSubscriptionsSelectedUser) {
            userFilterSelect.value = state.adminAlertSubscriptionsSelectedUser;
          }
          renderTable();
          markUnsavedStatus();
        });
      }
    } else {
      tableWrap.innerHTML = `${chips}<div class="table-wrap user-management-table-wrap">
        <table class="user-management-table admin-alert-subscriptions-table">
          <thead><tr><th>${firstColTitle}</th><th>Mail</th><th>Telegram</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;
    }

    tableWrap.querySelectorAll(".admin-sub-country-filter-chip[data-country-filter]").forEach((button) => {
      button.addEventListener("click", () => {
        const selected = String(button.getAttribute("data-country-filter") || "").trim().toUpperCase();
        userFocusCountryFilter = userFocusCountryFilter === selected ? "ALL" : selected;
        renderTable();
        markUnsavedStatus();
      });
    });

    wireDynamicTableEvents();
  };

  const refreshChangedState = () => {
    const allRows = Array.from(container.querySelectorAll("[data-row-type]"));
    let changedCount = 0;
    for (const checkbox of container.querySelectorAll(".admin-sub-cb")) {
      const originalChecked = checkbox.dataset.originalChecked === "1";
      const isChanged = checkbox.checked !== originalChecked;
      checkbox.classList.toggle("is-changed", isChanged);
      const chip = checkbox.closest(".admin-sub-user-chip");
      if (chip) chip.classList.toggle("has-change", isChanged);
      if (isChanged) changedCount += 1;
    }
    for (const row of allRows) {
      const rowHasChange = !!row.querySelector(".admin-sub-cb.is-changed");
      row.classList.toggle("has-change", rowHasChange);
    }
    return changedCount;
  };

  const applyFilters = () => {
    const hostQuery = String(document.getElementById("adminAlertSubsHostSearchInput")?.value || "").trim().toLowerCase();
    const selectedUser = String(document.getElementById("adminAlertSubsUserFilterSelect")?.value || "").trim();
    const onlyChanged = document.getElementById("adminAlertSubsOnlyChangedInput")?.checked === true;
    const viewMode = normalizeAdminAlertViewMode();
    const rowsEls = Array.from(container.querySelectorAll("[data-row-type]"));
    const dataRows = rowsEls.filter((row) => {
      const rowType = String(row.dataset.rowType || "");
      return viewMode === "user" ? rowType === "user" : rowType === "host";
    });

    for (const row of dataRows) {
      let hostMatch = true;
      let userMatch = true;
      if (viewMode === "user") {
        const hostSearchBlob = String(row.dataset.hostSearch || "").toLowerCase();
        hostMatch = !hostQuery || hostSearchBlob.includes(hostQuery);
        const rowUser = String(row.dataset.username || "");
        userMatch = !selectedUser || rowUser === selectedUser;
      } else {
        const hostname = String(row.dataset.hostname || "").toLowerCase();
        const displayName = String(row.dataset.displayName || "").toLowerCase();
        hostMatch = !hostQuery || hostname.includes(hostQuery) || displayName.includes(hostQuery);
        if (viewMode === "user-focus") {
          const rowUser = String(row.dataset.username || "");
          userMatch = !selectedUser || rowUser === selectedUser;
        } else {
          userMatch = !selectedUser || Array.from(row.querySelectorAll(".admin-sub-cb[data-username]")).some((cb) => {
            return String(cb.dataset.username || "") === selectedUser;
          });
        }
      }
      const changedMatch = !onlyChanged || !!row.querySelector(".admin-sub-cb.is-changed");
      const countryCode = String(row.dataset.countryCode || "").trim().toUpperCase();
      const countryMatch = viewMode !== "user-focus" || userFocusCountryFilter === "ALL" || countryCode === userFocusCountryFilter;
      const showRow = hostMatch && userMatch && changedMatch && countryMatch;
      row.classList.toggle("admin-sub-row-hidden", !showRow);

      if (viewMode === "host") {
        const chips = row.querySelectorAll(".admin-sub-user-chip[data-username]");
        for (const chip of chips) {
          const chipUser = chip.getAttribute("data-username") || "";
          const showChip = !selectedUser || chipUser === selectedUser;
          chip.classList.toggle("admin-sub-chip-hidden", !showChip);
        }
      }
    }

    const countryRows = rowsEls.filter((row) => String(row.dataset.rowType || "") === "country");
    for (const countryRow of countryRows) {
      if (viewMode !== "host" && viewMode !== "user-focus") {
        countryRow.classList.add("admin-sub-row-hidden");
        continue;
      }
      const countryCode = String(countryRow.dataset.countryCode || "");
      const hasVisibleHost = dataRows.some((hostRow) => {
        return String(hostRow.dataset.countryCode || "") === countryCode
          && !hostRow.classList.contains("admin-sub-row-hidden");
      });
      countryRow.classList.toggle("admin-sub-row-hidden", !hasVisibleHost);
    }
  };

  const markUnsavedStatus = () => {
    const changedCount = refreshChangedState();
    applyFilters();
    if (changedCount > 0) {
      setAdminAlertSubscriptionsStatus(`Ungespeicherte Änderungen (${changedCount}).`);
    } else {
      setAdminAlertSubscriptionsStatus("Keine Änderungen.");
    }
  };

  const applyBulkToVisible = (channel, enabled) => {
    const selectedUser = String(document.getElementById("adminAlertSubsUserFilterSelect")?.value || "").trim();
    const rowsEls = Array.from(container.querySelectorAll("[data-row-type]"));
    let changedAny = false;
    for (const row of rowsEls) {
      if (row.classList.contains("admin-sub-row-hidden")) continue;
      const toggles = Array.from(row.querySelectorAll(`.admin-sub-cb[data-channel="${channel}"]`));
      for (const toggle of toggles) {
        const username = toggle.dataset.username || "";
        if (selectedUser && username !== selectedUser) continue;
        if (toggle.disabled) continue;
        if (toggle.checked !== enabled) {
          toggle.checked = enabled;
          changedAny = true;
        }
      }
    }
    if (changedAny) {
      markUnsavedStatus();
    }
  };

  const applyRowBulk = (scope, key, channel, enabled) => {
    const rows = Array.from(container.querySelectorAll("[data-row-type]"));
    let changedAny = false;
    for (const row of rows) {
      if (scope === "host" && String(row.dataset.hostname || "") !== key) continue;
      if (scope === "user" && String(row.dataset.username || "") !== key) continue;
      for (const toggle of row.querySelectorAll(`.admin-sub-cb[data-channel="${channel}"]`)) {
        if (toggle.disabled) continue;
        if (toggle.checked !== enabled) {
          toggle.checked = enabled;
          changedAny = true;
        }
      }
    }
    if (changedAny) {
      markUnsavedStatus();
    }
  };

  const hostSearchInput = document.getElementById("adminAlertSubsHostSearchInput");
  if (hostSearchInput) hostSearchInput.addEventListener("input", () => applyFilters());

  const userFilterSelect = document.getElementById("adminAlertSubsUserFilterSelect");
  if (userFilterSelect) {
    userFilterSelect.addEventListener("change", () => {
      const selectedUser = String(userFilterSelect.value || "").trim();
      const viewModeSelect = document.getElementById("adminAlertSubsViewModeSelect");
      state.adminAlertSubscriptionsSelectedUser = selectedUser;
      if (selectedUser && normalizeAdminAlertViewMode() !== "user-focus") {
        captureCurrentFromDom();
        state.adminAlertSubscriptionsViewMode = "user-focus";
        if (viewModeSelect) {
          viewModeSelect.value = "user-focus";
        }
        state.adminAlertSubscriptionsLoaded = false;
        void loadAdminAlertSubscriptions(true);
        return;
      }
      if (normalizeAdminAlertViewMode() === "user-focus") {
        captureCurrentFromDom();
        state.adminAlertSubscriptionsLoaded = false;
        void loadAdminAlertSubscriptions(true);
        return;
      }
      applyFilters();
    });
  }

  const viewModeSelect = document.getElementById("adminAlertSubsViewModeSelect");
  if (viewModeSelect) {
    viewModeSelect.value = normalizeAdminAlertViewMode();
    viewModeSelect.addEventListener("change", () => {
      captureCurrentFromDom();
      if (viewModeSelect.value === "user") {
        state.adminAlertSubscriptionsViewMode = "user";
      } else if (viewModeSelect.value === "user-focus") {
        state.adminAlertSubscriptionsViewMode = "user-focus";
      } else {
        state.adminAlertSubscriptionsViewMode = "host";
      }
      if (state.adminAlertSubscriptionsViewMode !== "user-focus") {
        userFocusCountryFilter = "ALL";
        state.adminAlertSubscriptionsSelectedUser = "";
      }
      renderTable();
      markUnsavedStatus();
    });
  }

  const onlyChangedInput = document.getElementById("adminAlertSubsOnlyChangedInput");
  if (onlyChangedInput) onlyChangedInput.addEventListener("change", () => applyFilters());

  const bulkMailOnButton = document.getElementById("adminAlertSubsBulkMailOnButton");
  if (bulkMailOnButton) bulkMailOnButton.addEventListener("click", () => applyBulkToVisible("mail", true));
  const bulkMailOffButton = document.getElementById("adminAlertSubsBulkMailOffButton");
  if (bulkMailOffButton) bulkMailOffButton.addEventListener("click", () => applyBulkToVisible("mail", false));
  const bulkTelegramOnButton = document.getElementById("adminAlertSubsBulkTelegramOnButton");
  if (bulkTelegramOnButton) bulkTelegramOnButton.addEventListener("click", () => applyBulkToVisible("telegram", true));
  const bulkTelegramOffButton = document.getElementById("adminAlertSubsBulkTelegramOffButton");
  if (bulkTelegramOffButton) bulkTelegramOffButton.addEventListener("click", () => applyBulkToVisible("telegram", false));

  renderTable();
  refreshChangedState();
  applyFilters();
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
  state.adminAlertSubscriptionsLoaded = false;
  await loadAdminAlertSubscriptions(true);
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
    document.getElementById("globalAdminOpsSection"),
    document.getElementById("adminOauthSettingsSection"),
    document.getElementById("adminUserManagementSection"),
    document.getElementById("globalAlarmSettingsSection"),
    document.getElementById("filesystemBlacklistAdminSection"),
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

// ---------------------------------------------------------------------------
// Filesystem Blacklist — Admin-verwaltete Wildcard-Patterns
// ---------------------------------------------------------------------------

async function loadFilesystemBlacklist() {
  try {
    const resp = await fetch("/api/v1/filesystem-blacklist", { credentials: "same-origin" });
    if (!resp.ok) return;
    const data = await resp.json();
    if (Array.isArray(data.patterns)) {
      state.filesystemBlacklistPatterns = data.patterns;
    }
  } catch (err) {
    console.error("Fehler beim Laden der Filesystem-Blacklist:", err);
  }
}

function isFilesystemBlacklisted(mountpoint) {
  if (!state.showBlacklistedFilesystems && state.filesystemBlacklistPatterns) {
    for (const entry of state.filesystemBlacklistPatterns) {
      const pattern = str(entry.pattern || "");
      if (matchGlobPattern(pattern, mountpoint)) {
        return true;
      }
    }
  }
  return false;
}

function matchGlobPattern(pattern, text) {
  // Einfaches Wildcard-Matching: * = beliebig, ? = einzelnes Zeichen
  const regexStr = "^" + pattern
    .replace(/\./g, "\\.")
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".")
    + "$";
  try {
    return new RegExp(regexStr).test(text);
  } catch {
    return false;
  }
}

function renderFilesystemBlacklistAdminSection() {
  const patterns = state.filesystemBlacklistPatterns || [];
  const patternCount = patterns.length;
  const rows = patterns.map((entry, idx) => `
    <tr>
      <td class="fs-bl-pattern" style="font-family:monospace;word-break:break-all;">${escapeHtml(entry.pattern)}</td>
      <td>${escapeHtml(entry.description || "")}</td>
      <td style="text-align:right;">
        <button type="button" class="fs-bl-del-btn" data-id="${escapeHtml(entry.id)}" title="Löschen">🗑</button>
      </td>
    </tr>`).join("");

  return `
    <section class="settings-subsection" id="filesystemBlacklistAdminSection">
      <div class="settings-subsection-head">
        <h5>🚫 Filesystem-Blacklist (<span id="fsBlPatternCount">${patternCount}</span>)</h5>
        <p class="count compact">Automatisch von Alerts, Trends und Filesystem-Listen ausschließen (es sei denn, "Geblacklistete anzeigen" ist aktiviert)</p>
      </div>
      <div class="alarm-settings-group">
        <p style="font-size:12px;color:#64748b;margin:0 0 10px 0;">
          <strong>Wildcard-Syntax:</strong> <code>*</code> = beliebig, <code>?</code> = einzelnes Zeichen. Beispiele: <code>/hana/shared/.snapshot/*</code>, <code>*/cache/*</code>, <code>/var/log/*</code>
        </p>
      </div>
      <div class="table-wrap" style="margin-bottom:8px;max-height:300px;overflow-y:auto;">
        <table class="report-subtable" id="filesystemBlacklistTable">
          <thead>
            <tr>
              <th>Pattern</th>
              <th>Beschreibung</th>
              <th></th>
            </tr>
          </thead>
          <tbody id="filesystemBlacklistBody">${rows}</tbody>
        </table>
      </div>
      <div class="alarm-settings-actions">
        <label for="fsBlNewPattern" style="display:inline-block;margin-right:8px;">Neues Pattern:</label>
        <input id="fsBlNewPattern" type="text" class="settings-input" placeholder="/hana/shared/.snapshot/*" style="width:200px;display:inline-block;">
        <input id="fsBlNewDescription" type="text" class="settings-input" placeholder="Beschreibung (optional)" style="width:200px;display:inline-block;margin-left:8px;">
        <button type="button" id="fsBlAddBtn" class="btn-secondary" style="display:inline-block;margin-left:8px;">+ Hinzufügen</button>
        <span id="fsBlStatus" class="count compact" style="margin-left:16px;"></span>
      </div>
    </section>`;
}

function wireFilesystemBlacklistAdminSection(container) {
  const section = (container || document).querySelector("#filesystemBlacklistAdminSection");
  if (!section) return;

  function updatePatternCount() {
    const countEl = section.querySelector("#fsBlPatternCount");
    if (countEl) {
      countEl.textContent = String((state.filesystemBlacklistPatterns || []).length);
    }
  }

  section.querySelector("#fsBlAddBtn")?.addEventListener("click", async () => {
    const patternInput = section.querySelector("#fsBlNewPattern");
    const descInput = section.querySelector("#fsBlNewDescription");
    const pattern = (patternInput?.value || "").trim();
    const description = (descInput?.value || "").trim();

    if (!pattern) {
      const status = section.querySelector("#fsBlStatus");
      status.textContent = "❌ Pattern erforderlich";
      setTimeout(() => { status.textContent = ""; }, 2000);
      return;
    }

    const status = section.querySelector("#fsBlStatus");
    status.textContent = "Speichern…";
    try {
      const resp = await fetch("/api/v1/filesystem-blacklist", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "add", pattern, description }),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || resp.statusText);

      // Reload list
      await loadFilesystemBlacklist();
      const container = section.querySelector("#filesystemBlacklistBody");
      if (container) {
        const newRows = (state.filesystemBlacklistPatterns || []).map((entry, idx) => `
          <tr>
            <td class="fs-bl-pattern" style="font-family:monospace;word-break:break-all;">${escapeHtml(entry.pattern)}</td>
            <td>${escapeHtml(entry.description || "")}</td>
            <td style="text-align:right;">
              <button type="button" class="fs-bl-del-btn" data-id="${escapeHtml(entry.id)}" title="Löschen">🗑</button>
            </td>
          </tr>`).join("");
        container.innerHTML = newRows;
        wireDeleteButtons();
        updatePatternCount();
      }

      patternInput.value = "";
      descInput.value = "";
      status.textContent = "✅ Pattern hinzugefügt";
    } catch (err) {
      status.textContent = `❌ ${err.message}`;
    }
    setTimeout(() => { status.textContent = ""; }, 2500);
  });

  function wireDeleteButtons() {
    section.querySelectorAll(".fs-bl-del-btn").forEach(btn => {
      btn.removeEventListener("click", onDelete);
      btn.addEventListener("click", onDelete);
    });
  }

  const onDelete = async (e) => {
    const btn = e.target;
    const id = btn.dataset.id;
    if (!confirm("Pattern wirklich löschen?")) return;

    const status = section.querySelector("#fsBlStatus");
    status.textContent = "Löschen…";
    try {
      const resp = await fetch("/api/v1/filesystem-blacklist", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: "delete", id: parseInt(id, 10) }),
      });
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || resp.statusText);

      // Reload list
      await loadFilesystemBlacklist();
      const container = section.querySelector("#filesystemBlacklistBody");
      if (container) {
        const newRows = (state.filesystemBlacklistPatterns || []).map((entry, idx) => `
          <tr>
            <td class="fs-bl-pattern" style="font-family:monospace;word-break:break-all;">${escapeHtml(entry.pattern)}</td>
            <td>${escapeHtml(entry.description || "")}</td>
            <td style="text-align:right;">
              <button type="button" class="fs-bl-del-btn" data-id="${escapeHtml(entry.id)}" title="Löschen">🗑</button>
            </td>
          </tr>`).join("");
        container.innerHTML = newRows;
        wireDeleteButtons();
        updatePatternCount();
      }
      status.textContent = "✅ Pattern gelöscht";
    } catch (err) {
      status.textContent = `❌ ${err.message}`;
    }
    setTimeout(() => { status.textContent = ""; }, 2500);
  };

  updatePatternCount();
  wireDeleteButtons();
}

// ---------------------------------------------------------------------------
// SAP B1 Version Map — server-backed, editable by admins
// ---------------------------------------------------------------------------

async function loadSapB1VersionMap() {
  try {
    const resp = await fetch("/api/v1/sap-b1-version-map", { credentials: "same-origin" });
    if (!resp.ok) return;
    const contentType = String(resp.headers.get("content-type") || "").toLowerCase();
    if (!contentType.includes("application/json")) return;
    const data = await resp.json();
    if (Array.isArray(data.entries)) {
      SAP_B1_VERSION_MAP = new Map(
        data.entries.map(e => [e.build, { featurePack: e.feature_pack, patchLevel: e.patch_level, releaseDate: e.release_date }])
      );
    }
  } catch { /* keep built-in map on error */ }
}

async function loadSapLicenseTypeMap() {
  try {
    const resp = await fetch("/api/v1/sap-license-type-map", { credentials: "same-origin" });
    if (!resp.ok) return;
    const contentType = String(resp.headers.get("content-type") || "").toLowerCase();
    if (!contentType.includes("application/json")) return;
    const data = await resp.json();
    if (!Array.isArray(data.entries)) return;
    const normalized = data.entries
      .filter((entry) => entry && typeof entry === "object")
      .map((entry) => ({
        matchText: asText(entry.match_text, "").trim(),
        displayName: asText(entry.display_name, "").trim(),
        visible: Boolean(entry.visible),
      }))
      .filter((entry) => entry.matchText);
    SAP_LICENSE_TYPE_MAP = normalized;
  } catch { /* keep built-in map on error */ }
}

function renderSapB1VersionMapAdminSection() {
  const rows = Array.from(SAP_B1_VERSION_MAP.entries()).map(([build, info], idx) => `
    <tr data-idx="${idx}">
      <td><input class="vmap-input" data-field="build" value="${escapeHtml(build)}" style="width:90px;font-family:monospace"></td>
      <td><input class="vmap-input" data-field="feature_pack" value="${escapeHtml(info.featurePack)}" style="width:115px"></td>
      <td><input class="vmap-input" data-field="patch_level" value="${escapeHtml(info.patchLevel)}" style="width:90px"></td>
      <td><input class="vmap-input" data-field="release_date" value="${escapeHtml(info.releaseDate)}" style="width:75px"></td>
      <td><button type="button" class="vmap-del-btn" data-idx="${idx}" title="Zeile löschen">🗑</button></td>
    </tr>`).join("");

  return `
    <section class="settings-subsection" id="sapB1VersionMapAdminSection">
      <div class="settings-subsection-head">
        <h5>🗂️ SAP B1 Version Map</h5>
        <p class="count compact">Mapping von Build-Nummern zu Feature Packs — wird server-seitig gespeichert</p>
      </div>
      <div class="table-wrap" style="margin-bottom:8px;max-height:420px;overflow-y:auto;">
        <table class="report-subtable sap-vmap-table" id="sapB1VmapAdminTable">
          <thead>
            <tr>
              <th>Build</th>
              <th>Feature Pack</th>
              <th>Patch Level</th>
              <th>Release</th>
              <th></th>
            </tr>
          </thead>
          <tbody id="sapB1VmapAdminBody">${rows}</tbody>
        </table>
      </div>
      <div class="alarm-settings-actions">
        <button type="button" id="sapB1VmapAddRowBtn" class="btn-secondary">+ Zeile hinzufügen</button>
        <button type="button" id="sapB1VmapSaveBtn">💾 Speichern</button>
        <button type="button" id="sapB1VmapCopyBtn" class="btn-secondary">📋 Kopieren</button>
        <span id="sapB1VmapStatus" class="count compact"></span>
      </div>
    </section>`;
}

function wireSapB1VersionMapAdminSection(container) {
  const section = (container || document).querySelector("#sapB1VersionMapAdminSection");
  if (!section) return;
  markSapB1VersionMapDirty(false);

  function getTableEntries() {
    return Array.from(section.querySelectorAll("#sapB1VmapAdminBody tr")).map(tr => ({
      build: tr.querySelector('[data-field="build"]')?.value.trim() || "",
      feature_pack: tr.querySelector('[data-field="feature_pack"]')?.value.trim() || "",
      patch_level: tr.querySelector('[data-field="patch_level"]')?.value.trim() || "",
      release_date: tr.querySelector('[data-field="release_date"]')?.value.trim() || "",
    })).filter(e => e.build);
  }

  section.querySelector("#sapB1VmapAddRowBtn")?.addEventListener("click", () => {
    const tbody = section.querySelector("#sapB1VmapAdminBody");
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><input class="vmap-input" data-field="build" value="" style="width:90px;font-family:monospace" placeholder="10.00.xxx"></td>
      <td><input class="vmap-input" data-field="feature_pack" value="" style="width:115px" placeholder="FP 26xx"></td>
      <td><input class="vmap-input" data-field="patch_level" value="" style="width:90px" placeholder="PL xx"></td>
      <td><input class="vmap-input" data-field="release_date" value="" style="width:75px" placeholder="Mmm YYYY"></td>
      <td><button type="button" class="vmap-del-btn" title="Zeile löschen">🗑</button></td>`;
    tbody.insertBefore(tr, tbody.firstChild);
    tr.querySelector("input").focus();
    markSapB1VersionMapDirty(true);
  });

  section.addEventListener("click", (e) => {
    if (e.target.classList.contains("vmap-del-btn")) {
      e.target.closest("tr")?.remove();
      markSapB1VersionMapDirty(true);
    }
  });

  section.addEventListener("input", (e) => {
    if (e.target instanceof Element && e.target.classList.contains("vmap-input")) {
      markSapB1VersionMapDirty(true);
    }
  });

  section.querySelector("#sapB1VmapSaveBtn")?.addEventListener("click", async () => {
    const status = section.querySelector("#sapB1VmapStatus");
    const entries = getTableEntries();
    status.textContent = "Speichern…";
    try {
      const resp = await fetch("/api/v1/sap-b1-version-map", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ entries }),
      });
      const contentType = String(resp.headers.get("content-type") || "").toLowerCase();
      if (!contentType.includes("application/json")) {
        throw new Error(`Ungültige Server-Antwort (HTTP ${resp.status})`);
      }
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || resp.statusText);
      // Update in-memory map
      SAP_B1_VERSION_MAP = new Map(
        entries.map(e => [e.build, { featurePack: e.feature_pack, patchLevel: e.patch_level, releaseDate: e.release_date }])
      );
      markSapB1VersionMapDirty(false);
      status.textContent = `✅ ${data.saved} Einträge gespeichert`;
    } catch (err) {
      status.textContent = `❌ ${err.message}`;
    }
    setTimeout(() => { status.textContent = ""; }, 3000);
  });

  section.querySelector("#sapB1VmapCopyBtn")?.addEventListener("click", async () => {
    const entries = getTableEntries();
    const text = entries.map(e => `${e.build}\t${e.feature_pack}\t${e.patch_level}\t${e.release_date}`).join("\n");
    try {
      await navigator.clipboard.writeText(text);
      const btn = section.querySelector("#sapB1VmapCopyBtn");
      const orig = btn.textContent;
      btn.textContent = "✅ Kopiert!";
      setTimeout(() => { btn.textContent = orig; }, 1500);
    } catch { /* ignore */ }
  });
}

function renderSapLicenseTypeMapAdminSection() {
  const rows = SAP_LICENSE_TYPE_MAP.map((entry, idx) => `
    <tr data-idx="${idx}">
      <td><input class="vmap-input" data-field="match_text" value="${escapeHtml(entry.matchText)}" style="width:180px;font-family:monospace" placeholder="z.B. CRM-LTD"></td>
      <td><input class="vmap-input" data-field="display_name" value="${escapeHtml(entry.displayName)}" style="width:220px" placeholder="z.B. Limited CRM"></td>
      <td><label class="checkbox-label compact"><input type="checkbox" data-field="visible" ${entry.visible ? "checked" : ""}> Sichtbar</label></td>
      <td><button type="button" class="license-map-del-btn" data-idx="${idx}" title="Zeile löschen">🗑</button></td>
    </tr>`).join("");

  return `
    <section class="settings-subsection" id="sapLicenseTypeMapAdminSection">
      <div class="settings-subsection-head">
        <h5>🪪 SAP Lizenztyp Übersetzungsmatrix</h5>
        <p class="count compact">Exaktes Matching der Lizenztypen aus B01 auf Anzeigename — Sichtbarkeit wird je Zeile über Checkbox gesteuert</p>
      </div>
      <div class="table-wrap" style="margin-bottom:8px;max-height:340px;overflow-y:auto;">
        <table class="report-subtable sap-vmap-table" id="sapLicenseMapAdminTable">
          <thead>
            <tr>
              <th>Lizenztyp (exakt)</th>
              <th>Anzeigename in UI</th>
              <th>Sichtbar</th>
              <th></th>
            </tr>
          </thead>
          <tbody id="sapLicenseMapAdminBody">${rows}</tbody>
        </table>
      </div>
      <div class="alarm-settings-actions">
        <button type="button" id="sapLicenseMapAddRowBtn" class="btn-secondary">+ Zeile hinzufügen</button>
        <button type="button" id="sapLicenseMapSaveBtn">💾 Speichern</button>
        <button type="button" id="sapLicenseMapCopyBtn" class="btn-secondary">📋 Kopieren</button>
        <span id="sapLicenseMapStatus" class="count compact"></span>
      </div>
    </section>`;
}

function wireSapLicenseTypeMapAdminSection(container) {
  const section = (container || document).querySelector("#sapLicenseTypeMapAdminSection");
  if (!section) return;
  markSapLicenseTypeMapDirty(false);

  function getTableEntries() {
    return Array.from(section.querySelectorAll("#sapLicenseMapAdminBody tr")).map((tr) => ({
      match_text: tr.querySelector('[data-field="match_text"]')?.value.trim() || "",
      display_name: tr.querySelector('[data-field="display_name"]')?.value.trim() || "",
      visible: tr.querySelector('[data-field="visible"]')?.checked === true,
    })).filter((entry) => entry.match_text);
  }

  section.querySelector("#sapLicenseMapAddRowBtn")?.addEventListener("click", () => {
    const tbody = section.querySelector("#sapLicenseMapAdminBody");
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><input class="vmap-input" data-field="match_text" value="" style="width:180px;font-family:monospace" placeholder="z.B. FINANCE-LTD"></td>
      <td><input class="vmap-input" data-field="display_name" value="" style="width:220px" placeholder="z.B. Limited Finance"></td>
      <td><label class="checkbox-label compact"><input type="checkbox" data-field="visible"> Sichtbar</label></td>
      <td><button type="button" class="license-map-del-btn" title="Zeile löschen">🗑</button></td>`;
    tbody.insertBefore(tr, tbody.firstChild);
    tr.querySelector("input")?.focus();
    markSapLicenseTypeMapDirty(true);
  });

  section.addEventListener("click", (event) => {
    if (event.target.classList.contains("license-map-del-btn")) {
      event.target.closest("tr")?.remove();
      markSapLicenseTypeMapDirty(true);
    }
  });

  section.addEventListener("input", (event) => {
    if (event.target instanceof Element && event.target.classList.contains("vmap-input")) {
      markSapLicenseTypeMapDirty(true);
    }
  });

  section.addEventListener("change", (event) => {
    if (!(event.target instanceof Element)) return;
    if (event.target.getAttribute("data-field") === "visible") {
      markSapLicenseTypeMapDirty(true);
    }
  });

  section.querySelector("#sapLicenseMapSaveBtn")?.addEventListener("click", async () => {
    const status = section.querySelector("#sapLicenseMapStatus");
    const entries = getTableEntries();
    status.textContent = "Speichern…";
    try {
      const resp = await fetch("/api/v1/sap-license-type-map", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ entries }),
      });
      const contentType = String(resp.headers.get("content-type") || "").toLowerCase();
      if (!contentType.includes("application/json")) {
        throw new Error(`Ungültige Server-Antwort (HTTP ${resp.status})`);
      }
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || resp.statusText);

      SAP_LICENSE_TYPE_MAP = entries.map((entry) => ({
        matchText: entry.match_text,
        displayName: entry.display_name,
        visible: Boolean(entry.visible),
      }));

      markSapLicenseTypeMapDirty(false);
      status.textContent = `✅ ${data.saved} Einträge gespeichert`;
    } catch (err) {
      status.textContent = `❌ ${err.message}`;
    }
    setTimeout(() => { status.textContent = ""; }, 3000);
  });

  section.querySelector("#sapLicenseMapCopyBtn")?.addEventListener("click", async () => {
    const entries = getTableEntries();
    const text = entries.map((entry) => `${entry.match_text}\t${entry.display_name}\t${entry.visible ? "ja" : "nein"}`).join("\n");
    try {
      await navigator.clipboard.writeText(text);
      const btn = section.querySelector("#sapLicenseMapCopyBtn");
      const orig = btn.textContent;
      btn.textContent = "✅ Kopiert!";
      setTimeout(() => { btn.textContent = orig; }, 1500);
    } catch { /* ignore */ }
  });
}

function normalizeItProviderContacts(rawContacts, fallbackResolver) {
  const contacts = [];
  if (Array.isArray(rawContacts)) {
    for (const item of rawContacts.slice(0, 3)) {
      contacts.push({
        it_provider_name: asText(item?.it_provider_name, "").trim(),
        it_provider_contact: asText(item?.it_provider_contact, "").trim(),
        it_provider_email: asText(item?.it_provider_email, "").trim(),
        it_provider_phone: asText(item?.it_provider_phone, "").trim(),
      });
    }
  }
  while (contacts.length < 3) {
    const idx = contacts.length;
    const slot = typeof fallbackResolver === "function"
      ? fallbackResolver(idx)
      : {};
    contacts.push({
      it_provider_name: asText(slot?.it_provider_name, "").trim(),
      it_provider_contact: asText(slot?.it_provider_contact, "").trim(),
      it_provider_email: asText(slot?.it_provider_email, "").trim(),
      it_provider_phone: asText(slot?.it_provider_phone, "").trim(),
    });
  }
  return contacts.slice(0, 3);
}

function getItProviderContactsFromHostSettings(settings) {
  return normalizeItProviderContacts(settings?.customer_it_provider_contacts, (index) => {
    if (index === 0) {
      return {
        it_provider_name: settings?.customer_it_provider_name,
        it_provider_contact: settings?.customer_it_provider_contact,
        it_provider_email: settings?.customer_it_provider_email,
        it_provider_phone: settings?.customer_it_provider_phone,
      };
    }
    if (index === 1) {
      return {
        it_provider_name: settings?.customer_it_provider_name_2,
        it_provider_contact: settings?.customer_it_provider_contact_2,
        it_provider_email: settings?.customer_it_provider_email_2,
        it_provider_phone: settings?.customer_it_provider_phone_2,
      };
    }
    return {
      it_provider_name: settings?.customer_it_provider_name_3,
      it_provider_contact: settings?.customer_it_provider_contact_3,
      it_provider_email: settings?.customer_it_provider_email_3,
      it_provider_phone: settings?.customer_it_provider_phone_3,
    };
  });
}

function getItProviderContactsFromCustomer(customer) {
  return normalizeItProviderContacts(customer?.it_provider_contacts, (index) => {
    if (index === 0) {
      return {
        it_provider_name: customer?.it_provider_name,
        it_provider_contact: customer?.it_provider_contact,
        it_provider_email: customer?.it_provider_email,
        it_provider_phone: customer?.it_provider_phone,
      };
    }
    if (index === 1) {
      return {
        it_provider_name: customer?.it_provider_name_2,
        it_provider_contact: customer?.it_provider_contact_2,
        it_provider_email: customer?.it_provider_email_2,
        it_provider_phone: customer?.it_provider_phone_2,
      };
    }
    return {
      it_provider_name: customer?.it_provider_name_3,
      it_provider_contact: customer?.it_provider_contact_3,
      it_provider_email: customer?.it_provider_email_3,
      it_provider_phone: customer?.it_provider_phone_3,
    };
  });
}

function itProviderContactHasData(contact) {
  return Boolean(
    asText(contact?.it_provider_name, "").trim()
    || asText(contact?.it_provider_contact, "").trim()
    || asText(contact?.it_provider_email, "").trim()
    || asText(contact?.it_provider_phone, "").trim()
  );
}

function deriveInitialVisibleItProviderRows(contacts) {
  const normalized = normalizeItProviderContacts(contacts);
  let highestFilled = -1;
  for (let index = 0; index < normalized.length; index += 1) {
    if (itProviderContactHasData(normalized[index])) {
      highestFilled = index;
    }
  }
  if (highestFilled < 0) {
    return 1;
  }
  return Math.max(1, Math.min(3, highestFilled + 2));
}

function renderCustomerNotificationPanel(hostname, settings) {
  const customerId = Number(settings.customer_id || 0) || null;
  const customerName = asText(settings.customer_name, "");
  const customerProjectNo = asText(settings.customer_maringo_project_number, "");
  const itProviderContacts = getItProviderContactsFromHostSettings(settings);
  const providerRowsHtml = itProviderContacts.map((entry, index) => {
    const slot = index + 1;
    return `<div class="customer-provider-row" data-provider-row data-provider-slot="${slot}">
      <p class="settings-helper-text customer-provider-row-title">Ansprechpartner ${slot}</p>
      <div class="alarm-settings-group">
        <label for="customerItProviderNameInput${slot}" class="settings-label">IT Provider Name</label>
        <input id="customerItProviderNameInput${slot}" type="text" class="settings-input" placeholder="IT Provider Name" value="${escapeHtml(entry.it_provider_name)}">
      </div>
      <div class="alarm-settings-group">
        <label for="customerItProviderContactInput${slot}" class="settings-label">Ansprechpartner</label>
        <input id="customerItProviderContactInput${slot}" type="text" class="settings-input" placeholder="Ansprechpartner" value="${escapeHtml(entry.it_provider_contact)}">
      </div>
      <div class="alarm-settings-group">
        <label for="customerItProviderEmailInput${slot}" class="settings-label">E-Mail</label>
        <input id="customerItProviderEmailInput${slot}" type="email" class="settings-input" placeholder="it@example.com" value="${escapeHtml(entry.it_provider_email)}">
      </div>
      <div class="alarm-settings-group">
        <label for="customerItProviderPhoneInput${slot}" class="settings-label">Telefon</label>
        <input id="customerItProviderPhoneInput${slot}" type="text" class="settings-input" placeholder="+41 ..." value="${escapeHtml(entry.it_provider_phone)}">
      </div>
      ${slot > 1 ? `<div class="customer-provider-row-actions"><button type="button" class="btn-secondary btn-secondary--compact" data-provider-remove-slot="${slot}">Ansprechpartner ${slot} entfernen</button></div>` : ""}
    </div>`;
  }).join("");
  const customerLogoUrl = asText(settings.customer_logo_url, "").trim();
  const logoPreview = customerLogoUrl
    ? `<img src="${escapeHtml(customerLogoUrl)}" alt="Kundenlogo ${escapeHtml(customerName || "Kunde")}" class="customer-logo-preview" onerror="this.style.display='none'">`
    : '<span class="customer-logo-preview-placeholder">Noch kein Logo</span>';
  return `<details class="customer-notif-panel detail-card" id="customerNotificationDetails" open>
    <summary style="font-weight:700;font-size:14px;cursor:pointer;padding:4px 0;">Kundeninfos</summary>
    <div style="padding:10px 0 4px 0;">
      <p style="font-size:12px;color:#64748b;margin:0 0 10px 0;">Kundenname des dem Host zugeordneten Kunden ändern.</p>
      <div class="alarm-settings-group">
        <label for="customerNameInput" class="settings-label">Kundenname</label>
        <input id="customerNameInput" type="text" class="settings-input" placeholder="Kundenname" value="${escapeHtml(customerName)}">
      </div>
      <div class="alarm-settings-group">
        <label for="customerProjectInput" class="settings-label">Maringo Projektnummer</label>
        <input id="customerProjectInput" type="text" class="settings-input" placeholder="z.B. MAR-12345" value="${escapeHtml(customerProjectNo)}">
      </div>
      ${providerRowsHtml}
      <div class="alarm-settings-actions">
        <button id="customerAddProviderRowBtn" type="button" class="btn-secondary btn-secondary--compact">+ Ansprechpartner hinzufügen</button>
        <button id="saveCustomerNameBtn" type="button" class="btn-primary btn-primary--compact">Kundendaten speichern</button>
        <span id="customerNameStatus" class="settings-status"></span>
      </div>
      <div class="customer-logo-upload-block">
        <p class="settings-helper-text">Kundenlogo (PNG/JPG/WebP, max. 2 MB)</p>
        <div class="customer-logo-preview-wrap">${logoPreview}</div>
        <div class="alarm-settings-actions customer-logo-upload-actions">
          <input id="customerLogoInput" type="file" class="settings-input customer-logo-file-input" accept="image/png,image/jpeg,image/webp">
          <button id="saveCustomerLogoBtn" type="button" class="btn-secondary btn-secondary--compact">Logo hochladen</button>
          <span id="customerLogoStatus" class="settings-status"></span>
        </div>
      </div>
      <p class="settings-helper-text">${customerId ? `Kunde-ID: ${customerId}` : "Kein Kunde für diesen Host zugeordnet."}</p>
    </div>
  </details>`;
}

async function loadAndRenderCustomerNotificationPanel(hostname, hostUid = "") {
  const container = document.getElementById("customerNotificationPanel");
  if (!container) return;
  const normalizedHostname = asText(hostname, "").trim();
  const normalizedHostUid = asText(hostUid, "").trim();
  if (!normalizedHostname && !normalizedHostUid) {
    container.classList.remove("hidden");
    container.innerHTML = '<p class="muted">Wähle einen Host, um die Kundeninfos zu sehen.</p>';
    return;
  }
  try {
    const params = new URLSearchParams();
    if (normalizedHostname) params.set("hostname", normalizedHostname);
    if (normalizedHostUid) params.set("host_uid", normalizedHostUid);
    const resp = await fetch(`/api/v1/host-settings?${params.toString()}`);
    if (!resp.ok) throw new Error("HTTP " + resp.status);
    const data = await resp.json();
    container.innerHTML = renderCustomerNotificationPanel(normalizedHostname, data);
    container.classList.remove("hidden");

    const saveButton = container.querySelector("#saveCustomerNameBtn");
    const addProviderRowButton = container.querySelector("#customerAddProviderRowBtn");
    const logoButton = container.querySelector("#saveCustomerLogoBtn");
    const logoInput = container.querySelector("#customerLogoInput");
    const providerRows = [1, 2, 3].map((slot) => ({
      slot,
      row: container.querySelector(`[data-provider-row][data-provider-slot="${slot}"]`),
      removeBtn: container.querySelector(`[data-provider-remove-slot="${slot}"]`),
    }));
    let visibleProviderRows = deriveInitialVisibleItProviderRows(getItProviderContactsFromHostSettings(data));

    const syncProviderRowsUi = () => {
      for (const entry of providerRows) {
        if (!entry.row) continue;
        entry.row.classList.toggle("hidden", entry.slot > visibleProviderRows);
        if (entry.removeBtn) {
          entry.removeBtn.classList.toggle("hidden", entry.slot !== visibleProviderRows || visibleProviderRows <= 1);
        }
      }
      if (addProviderRowButton) {
        addProviderRowButton.classList.toggle("hidden", visibleProviderRows >= 3);
      }
    };

    const clearProviderSlot = (slot) => {
      const nameInput = container.querySelector(`#customerItProviderNameInput${slot}`);
      const contactInput = container.querySelector(`#customerItProviderContactInput${slot}`);
      const emailInput = container.querySelector(`#customerItProviderEmailInput${slot}`);
      const phoneInput = container.querySelector(`#customerItProviderPhoneInput${slot}`);
      if (nameInput) nameInput.value = "";
      if (contactInput) contactInput.value = "";
      if (emailInput) emailInput.value = "";
      if (phoneInput) phoneInput.value = "";
    };

    addProviderRowButton?.addEventListener("click", () => {
      visibleProviderRows = Math.min(3, visibleProviderRows + 1);
      syncProviderRowsUi();
    });

    for (const entry of providerRows) {
      entry.removeBtn?.addEventListener("click", () => {
        if (entry.slot <= 1) {
          return;
        }
        for (let slot = entry.slot; slot <= 3; slot += 1) {
          clearProviderSlot(slot);
        }
        visibleProviderRows = Math.max(1, entry.slot - 1);
        syncProviderRowsUi();
      });
    }

    syncProviderRowsUi();

    const customerId = Number(data?.customer_id || 0) || null;
    if (saveButton && !customerId) {
      saveButton.disabled = true;
      saveButton.title = "Nur bei einem zugeordneten Kunden verfügbar";
    }
    if (logoButton && !customerId) {
      logoButton.disabled = true;
      logoButton.title = "Nur bei einem zugeordneten Kunden verfügbar";
    }
    if (logoInput && !customerId) {
      logoInput.disabled = true;
      logoInput.title = "Nur bei einem zugeordneten Kunden verfügbar";
    }

    saveButton?.addEventListener("click", async () => {
      const status = container.querySelector("#customerNameStatus");
      const customerName = container.querySelector("#customerNameInput")?.value.trim() || "";
      const customerProject = container.querySelector("#customerProjectInput")?.value.trim() || "";
      const providerContacts = [1, 2, 3].map((slot) => ({
        it_provider_name: container.querySelector(`#customerItProviderNameInput${slot}`)?.value.trim() || "",
        it_provider_contact: container.querySelector(`#customerItProviderContactInput${slot}`)?.value.trim() || "",
        it_provider_email: container.querySelector(`#customerItProviderEmailInput${slot}`)?.value.trim() || "",
        it_provider_phone: container.querySelector(`#customerItProviderPhoneInput${slot}`)?.value.trim() || "",
      }));
      if (!customerName) {
        if (status) {
          status.textContent = "❌ Kundenname darf nicht leer sein";
          setTimeout(() => { status.textContent = ""; }, 3000);
        }
        return;
      }
      if (!customerId) {
        if (status) {
          status.textContent = "❌ Kein Kunde zugeordnet";
          setTimeout(() => { status.textContent = ""; }, 3000);
        }
        return;
      }
      try {
        const r = await fetch(`/api/v1/customers/${encodeURIComponent(customerId)}`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          credentials: "same-origin",
          body: JSON.stringify({
            customer_name: customerName,
            maringo_project_number: customerProject,
            it_provider_name: providerContacts[0].it_provider_name,
            it_provider_contact: providerContacts[0].it_provider_contact,
            it_provider_email: providerContacts[0].it_provider_email,
            it_provider_phone: providerContacts[0].it_provider_phone,
            it_provider_name_2: providerContacts[1].it_provider_name,
            it_provider_contact_2: providerContacts[1].it_provider_contact,
            it_provider_email_2: providerContacts[1].it_provider_email,
            it_provider_phone_2: providerContacts[1].it_provider_phone,
            it_provider_name_3: providerContacts[2].it_provider_name,
            it_provider_contact_3: providerContacts[2].it_provider_contact,
            it_provider_email_3: providerContacts[2].it_provider_email,
            it_provider_phone_3: providerContacts[2].it_provider_phone,
          }),
        });
        if (!r.ok) {
          const d = await r.json().catch(() => ({}));
          throw new Error(d.error || "HTTP " + r.status);
        }
        if (status) { status.textContent = "✅ Gespeichert"; setTimeout(() => { status.textContent = ""; }, 2500); }
        state.selectedDisplayName = state.selectedDisplayName || normalizedHostname;
        await loadHosts({ preserveScroll: true });
        await loadAndRenderCustomerNotificationPanel(normalizedHostname, normalizedHostUid);
      } catch (err) {
        if (status) { status.textContent = `❌ ${err.message}`; setTimeout(() => { status.textContent = ""; }, 3000); }
      }
    });

    logoButton?.addEventListener("click", async () => {
      const status = container.querySelector("#customerLogoStatus");
      const file = logoInput && logoInput.files && logoInput.files.length > 0 ? logoInput.files[0] : null;
      if (!customerId) {
        if (status) {
          status.textContent = "❌ Kein Kunde zugeordnet";
          setTimeout(() => { status.textContent = ""; }, 3000);
        }
        return;
      }
      if (!file) {
        if (status) {
          status.textContent = "❌ Bitte eine Datei auswählen";
          setTimeout(() => { status.textContent = ""; }, 3000);
        }
        return;
      }

      if (status) {
        status.textContent = "⏳ Upload läuft...";
      }
      if (logoButton) {
        logoButton.disabled = true;
      }
      try {
        await uploadCustomerLogo(customerId, file);
        if (status) {
          status.textContent = "✅ Logo gespeichert";
        }
        await loadHosts({ preserveScroll: true });
        updateReportCustomerChip();
        await loadAndRenderCustomerNotificationPanel(normalizedHostname, normalizedHostUid);
      } catch (err) {
        if (status) {
          status.textContent = `❌ ${err.message || "Upload fehlgeschlagen"}`;
          setTimeout(() => { status.textContent = ""; }, 3500);
        }
      } finally {
        if (logoButton) {
          logoButton.disabled = false;
        }
      }
    });
  } catch {
    container.classList.add("hidden");
    container.innerHTML = "";
  }
}

function renderCustomerAlertTestSection() {
  return `<section id="customerAlertTestSection" class="settings-subsection">
    <h3>Kunden-Benachrichtigung Testmail</h3>
    <div class="alarm-settings-group">
      <label for="custTestHostSelect" class="settings-label">Host auswählen</label>
      <select id="custTestHostSelect" class="settings-input">
        <option value="">— Host wählen —</option>
      </select>
    </div>
    <div class="alarm-settings-group">
      <label for="custTestRecipient" class="settings-label">Empfänger-E-Mail</label>
      <input id="custTestRecipient" type="email" class="settings-input" placeholder="test@example.com">
    </div>
    <div class="alarm-settings-actions">
      <button id="custTestSendBtn" type="button" class="btn-primary btn-primary--compact">Testmail senden</button>
      <span id="custTestStatus" class="settings-status"></span>
    </div>
  </section>`;
}

async function wireCustomerAlertTestSection(container) {
  const section = container.querySelector("#customerAlertTestSection");
  if (!section) return;

  // Populate host dropdown from state.hosts
  const select = section.querySelector("#custTestHostSelect");
  if (select && Array.isArray(state.hosts)) {
    for (const h of state.hosts) {
      const hn = String(h.hostname || "");
      const dn = String(h.display_name || h.hostname || "");
      const opt = document.createElement("option");
      opt.value = hn;
      opt.textContent = dn !== hn ? `${dn} (${hn})` : hn;
      select.appendChild(opt);
    }
  }

  section.querySelector("#custTestSendBtn")?.addEventListener("click", async () => {
    const status = section.querySelector("#custTestStatus");
    const hostname = section.querySelector("#custTestHostSelect")?.value?.trim();
    const recipient = section.querySelector("#custTestRecipient")?.value?.trim();
    if (!hostname || !recipient) {
      if (status) { status.textContent = "❌ Host und E-Mail erforderlich"; setTimeout(() => { status.textContent = ""; }, 3000); }
      return;
    }
    try {
      const r = await fetch("/api/v1/customer-alert/test", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ hostname, recipient_email: recipient }),
      });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(d.error || "HTTP " + r.status);
      if (status) { status.textContent = `✅ Testmail gesendet an ${recipient}`; setTimeout(() => { status.textContent = ""; }, 3000); }
    } catch (err) {
      if (status) { status.textContent = `❌ ${err.message}`; setTimeout(() => { status.textContent = ""; }, 3000); }
    }
  });
}

async function loadAdminSettingsGroup(mode, force = false) {
  if (!state.isAdmin) {
    return;
  }
  const normalized = normalizeAdminSettingsSubMode(mode);
  const container = document.getElementById("globalAdminSettingsContainer");

  if (normalized === "operations") {
    setDbMaintenanceStatus("Lade DB Kennzahlen-Verlauf...");
    setBackupAutomationStatus("Lade Backup-Automation...");
    setAgentIngestQueueStatus("Lade Queue-Status...");
    setAgentIngestAuditStatus("Lade Ingest-Lieferlog...");
    const opsResults = await Promise.allSettled([
      loadAdminDatabaseStats(),
      loadAdminBackupAutomation(),
      loadAdminAgentIngestQueue(),
      loadAdminAgentIngestAuditLog(),
    ]);
    if (opsResults[0]?.status === "rejected") {
      setDbMaintenanceStatus(`Fehler: ${opsResults[0].reason?.message || opsResults[0].reason}`, true);
    }
    if (opsResults[1]?.status === "rejected") {
      setBackupAutomationStatus(`Fehler: ${opsResults[1].reason?.message || opsResults[1].reason}`, true);
    }
    if (opsResults[2]?.status === "rejected") {
      setAgentIngestQueueStatus(`Fehler: ${opsResults[2].reason?.message || opsResults[2].reason}`, true);
    }
    if (opsResults[3]?.status === "rejected") {
      setAgentIngestAuditStatus(`Fehler: ${opsResults[3].reason?.message || opsResults[3].reason}`, true);
    }
    return;
  }

  if (normalized === "security") {
    await Promise.allSettled([
      loadOauthSettings(force),
      loadWebUsers(force),
    ]);
    return;
  }

  if (normalized === "alerting") {
    await loadAlarmSettings(force);
    if (container && !container.querySelector("#customerAlertTestSection")) {
      container.insertAdjacentHTML("beforeend", renderCustomerAlertTestSection());
    }
    if (container) {
      await wireCustomerAlertTestSection(container);
    }
    return;
  }

  if (normalized === "sap") {
    await Promise.allSettled([
      loadSapB1VersionMap(),
      loadSapLicenseTypeMap(),
    ]);
    if (container) {
      container.querySelector("#sapB1VersionMapAdminSection")?.remove();
      container.insertAdjacentHTML("beforeend", renderSapB1VersionMapAdminSection());
      wireSapB1VersionMapAdminSection(container);

      container.querySelector("#sapLicenseTypeMapAdminSection")?.remove();
      container.insertAdjacentHTML("beforeend", renderSapLicenseTypeMapAdminSection());
      wireSapLicenseTypeMapAdminSection(container);
    }
    return;
  }

  if (normalized === "data") {
    await loadFilesystemBlacklist(force);
    if (container && !container.querySelector("#filesystemBlacklistAdminSection")) {
      container.insertAdjacentHTML("beforeend", renderFilesystemBlacklistAdminSection());
      wireFilesystemBlacklistAdminSection(container);
    }
  }
}

async function loadGlobalAdminSettingsPanel(force = false) {
  updateAdminSettingsVisibility();
  if (!state.isAdmin) {
    return;
  }
  mountAdminSettingsIntoGlobalView();
  const container = document.getElementById("globalAdminSettingsContainer");
  ensureAdminSettingsSplitLayout(container);
  reapplyAdminWorkspaceUi();
  await loadAdminSettingsGroup(state.adminSettingsSubMode, force);
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

function consumeStartRouteFromUrl() {
  const url = new URL(window.location.href);
  const startRoute = String(url.searchParams.get("start") || "").trim().toLowerCase();
  if (!startRoute) {
    return "";
  }
  url.searchParams.delete("start");
  window.history.replaceState({}, document.title, url.pathname + (url.search ? url.search : ""));
  return startRoute;
}

async function applyStartRoute(startRoute) {
  const route = String(startRoute || "").trim().toLowerCase();
  if (!route) {
    return;
  }

  if (route === "settings-password") {
    state.viewMode = "settings";
    state.userSettingsSubMode = "password";
    updateViewMode();
    await loadSettingsPanel(true);
    return;
  }

  if (route === "settings-channels") {
    state.viewMode = "settings";
    state.userSettingsSubMode = "channels";
    updateViewMode();
    await loadSettingsPanel(true);
    return;
  }

  if (route === "settings-digests") {
    state.viewMode = "settings";
    state.userSettingsSubMode = "digests";
    updateViewMode();
    await loadSettingsPanel(true);
    return;
  }

  if (route === "settings-hosts") {
    state.viewMode = "settings";
    state.userSettingsSubMode = "hosts";
    updateViewMode();
    await loadSettingsPanel(true);
    renderHostInterestsEditor();
    return;
  }

  if (route === "alarm-settings") {
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
    return;
  }

  if (route === "global-critical-trends") {
    state.viewMode = "global";
    state.globalSubMode = "critical-trends";
    updateViewMode();
    updateGlobalSubMode();
    await loadCriticalTrends();
    return;
  }

  if (route === "global-inactive-hosts") {
    state.viewMode = "global";
    state.globalSubMode = "inactive-hosts";
    updateViewMode();
    updateGlobalSubMode();
    await loadInactiveHosts();
    return;
  }

  if (route === "global-admin-settings") {
    if (!state.isAdmin) {
      state.viewMode = "global";
      state.globalSubMode = "global-alerts";
      updateViewMode();
      updateGlobalSubMode();
      await loadGlobalAlertsOverview();
      return;
    }
    state.viewMode = "global";
    state.globalSubMode = "admin-settings";
    updateViewMode();
    updateGlobalSubMode();
    await loadGlobalAdminSettingsPanel(true);
    return;
  }

  // default: global alert overview
  state.viewMode = "global";
  state.globalSubMode = "global-alerts";
  updateViewMode();
  updateGlobalSubMode();
  await loadGlobalAlertsOverview();
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
  const alertTelegramReminderIntervalHours = Number(document.getElementById("alertTelegramReminderIntervalHoursInput")?.value || 0);
  const inactiveHostAlertHours = Number(inactiveHostAlertHoursInput?.value || 3);

  if (!Number.isFinite(warning) || !Number.isFinite(critical) || warning < 1 || critical > 100 || warning >= critical) {
    throw new Error("Schwellwerte ungültig: Warnung muss kleiner als Kritisch sein.");
  }
  if (!Number.isFinite(cpuWarning) || !Number.isFinite(cpuCritical) || cpuWarning < 1 || cpuCritical > 100 || cpuWarning >= cpuCritical) {
    throw new Error("CPU Schwellwerte ungültig: Warnung muss kleiner als Kritisch sein.");
  }
  if (!Number.isFinite(ramWarning) || !Number.isFinite(ramCritical) || ramWarning < 1 || ramCritical > 100 || ramWarning >= ramCritical) {
    throw new Error("RAM Schwellwerte ungültig: Warnung muss kleiner als Kritisch sein.");
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
    alert_telegram_reminder_interval_hours: Number.isFinite(alertTelegramReminderIntervalHours) ? Math.max(0, Math.min(168, Math.floor(alertTelegramReminderIntervalHours))) : 0,
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

function formatMegabytesFromBytes(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) {
    return "-";
  }
  const mb = n / (1024 * 1024);
  const digits = mb >= 100 ? 0 : 1;
  return Number(mb.toFixed(digits)).toLocaleString("de-CH", {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  });
}

function formatGigabytesFromBytes(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0) {
    return "-";
  }
  const gb = n / (1024 * 1024 * 1024);
  return `${gb.toFixed(1)} GB`;
}

function formatSignedMegabytesFromBytes(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) {
    return "+0";
  }
  const mb = Math.abs(n) / (1024 * 1024);
  const digits = mb >= 100 ? 0 : 1;
  const sign = n >= 0 ? "+" : "-";
  const formatted = Number(mb.toFixed(digits)).toLocaleString("de-CH", {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  });
  return `${sign}${formatted}`;
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

let _filesystemVisibilitySaveAbortController = null;

function setFilesystemVisibilityModalSaving(isSaving) {
  const saveBtn = document.getElementById("filesystemVisibilitySaveButton");
  if (saveBtn) saveBtn.disabled = Boolean(isSaving);
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
    : "⚙️ Filesysteme: Filesystem-Auswahl";
  summaryEl.textContent = `Host: ${state.selectedDisplayName || state.selectedHost} | Sichtbar: ${visibleCount}/${available.length}`;

  if (available.length === 0) {
    listEl.innerHTML = '<p class="muted">Keine Filesysteme verfügbar.</p>';
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
  if (_filesystemVisibilitySaveAbortController) {
    try {
      _filesystemVisibilitySaveAbortController.abort();
    } catch (_) {
      // Ignore abort errors while closing the modal.
    }
    _filesystemVisibilitySaveAbortController = null;
  }
  const modal = document.getElementById("filesystemVisibilityModal");
  if (!modal) return;
  modal.classList.add("hidden");
  state.fsVisibilitySection = "";
  setFilesystemVisibilityModalSaving(false);
  setFilesystemVisibilityStatus("");
}

function openFilesystemVisibilityModal(section) {
  if (!state.selectedHost || !state.fsVisibilityEditable) return;
  state.fsVisibilitySection = section;
  setFilesystemVisibilityStatus("");
  setFilesystemVisibilityModalSaving(false);
  renderFilesystemVisibilityModalContent();
  const modal = document.getElementById("filesystemVisibilityModal");
  const backdrop = document.getElementById("filesystemVisibilityBackdrop");
  const closeButton = document.getElementById("filesystemVisibilityCloseButton");
  const cancelButton = document.getElementById("filesystemVisibilityCancelButton");
  const saveButton = document.getElementById("filesystemVisibilitySaveButton");

  if (backdrop) backdrop.onclick = () => closeFilesystemVisibilityModal();
  if (closeButton) closeButton.onclick = () => closeFilesystemVisibilityModal();
  if (cancelButton) cancelButton.onclick = () => closeFilesystemVisibilityModal();
  if (saveButton) {
    saveButton.onclick = async () => {
      try {
        await saveFilesystemVisibilityFromModal();
      } catch (error) {
        const message = error && error.message ? error.message : "Unbekannter Fehler";
        setFilesystemVisibilityStatus(`Fehler: ${message}`, true);
      }
    };
  }

  if (modal) modal.classList.remove("hidden");
}

async function saveFilesystemVisibilityFromModal() {
  const section = state.fsVisibilitySection;
  if (!section || !state.selectedHost) return;
  if (_filesystemVisibilitySaveAbortController) return;
  const listEl = document.getElementById("filesystemVisibilityList");
  if (!listEl) return;

  const checkboxes = Array.from(listEl.querySelectorAll("input[type='checkbox'][data-mountpoint]"));
  const hiddenMountpoints = checkboxes
    .filter((item) => !item.checked)
    .map((item) => normalizeMountpointValue(item.getAttribute("data-mountpoint")));

  setFilesystemVisibilityStatus("Speichere...");
  setFilesystemVisibilityModalSaving(true);

  let timeoutId = null;
  try {
    const controller = typeof AbortController !== "undefined" ? new AbortController() : null;
    _filesystemVisibilitySaveAbortController = controller;
    if (controller) {
      timeoutId = window.setTimeout(() => {
        controller.abort();
      }, 15000);
    }

    const response = await fetch("/api/v1/filesystem-visibility", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        hostname: state.selectedHost,
        host_uid: state.selectedHostUid || "",
        section,
        hidden_mountpoints: hiddenMountpoints,
      }),
      ...(controller ? { signal: controller.signal } : {}),
    });
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(payload.error || ("HTTP " + response.status));
    }

    setHiddenMountpointsForSection(section, payload.hidden_mountpoints || hiddenMountpoints);
    closeFilesystemVisibilityModal();
    try {
      await loadAnalysisForHost();
    } catch (reloadError) {
      console.warn("loadAnalysisForHost after filesystem visibility save failed:", reloadError);
    }
  } catch (error) {
    if (error && error.name === "AbortError") {
      throw new Error("Speichern abgebrochen oder Timeout (15s)");
    }
    throw error;
  } finally {
    if (timeoutId !== null) {
      window.clearTimeout(timeoutId);
    }
    _filesystemVisibilitySaveAbortController = null;
    setFilesystemVisibilityModalSaving(false);
  }
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
    unavailable: "Nicht verfügbar",
    unsupported: "Nicht unterstützt",
    disabled: "Deaktiviert",
  };
  const statusLabel = statusLabelMap[scanStatus] || (scanStatus || "-");
  const runHourText = Number.isFinite(runHourUtc)
    ? `${String(Math.max(0, Math.min(23, Math.floor(runHourUtc)))).padStart(2, "0")}:00 UTC`
    : "-";

  panel.classList.remove("hidden");

  if (largeFiles.enabled === false) {
    const unsupportedReason = asText(largeFiles.status, "disabled") === "unsupported"
      ? "Nicht unterstützt auf diesem Host"
      : "Deaktiviert";
    meta.textContent = `📌 Status: ${unsupportedReason}`;
    body.innerHTML = '<p class="muted">Large-File-Scan ist für dieses Betriebssystem nicht verfügbar.</p>';
    return;
  }

  meta.textContent = `🕒 Scan: ${scanTimeText} | 📌 Status: ${statusLabel} | 🧮 Min ${minSizeMb} MB / Top ${topN} | ⏰ Plan: ${Number.isFinite(scanIntervalHours) ? `${Math.max(1, Math.floor(scanIntervalHours))}h` : "-"} @ ${runHourText}${timedOut ? " | ⚠️ Timeout" : ""}`;


  if (filesystems.length === 0) {
    const statusText = scanStatus === "scheduled"
      ? "Nächster geplanter Scan steht noch aus (taeglicher Lauf)."
      : scanStatus === "unavailable"
        ? "Large-File-Scan nicht verfügbar auf diesem Host."
        : scanStatus === "ok"
          ? "Scan abgeschlossen, aber es konnten keine Dateisysteme ausgewertet werden."
          : scanStatus === "error"
            ? `Scan fehlgeschlagen: ${escapeHtml(asText(largeFiles.error, "unbekannter Fehler"))}`
            : "Noch keine Large-File-Daten verfügbar.";
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
        : '<tr><td colspan="4" class="muted">Keine Dateien über Schwellwert gefunden.</td></tr>';
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
let sparklineGradientSequence = 0;

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
  const gradientId = `sparkline-area-${sparklineGradientSequence++}`;

  return `
    <svg class="sparkline" viewBox="0 0 ${width} ${height}" role="img" aria-label="Trend">
      <defs>
        <linearGradient id="${gradientId}" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="${color}" stop-opacity="0.24" />
          <stop offset="65%" stop-color="${color}" stop-opacity="0.08" />
          <stop offset="100%" stop-color="${color}" stop-opacity="0.02" />
        </linearGradient>
      </defs>
      ${guides}
      ${timeLabels}
      <polygon class="chart-area" fill="url(#${gradientId})" points="${area}" />
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
    return "<p class=\"muted\">Keine Verlaufskurven verfügbar.</p>";
  }

  const standText = formatUtcPlus2(latestReportTimeUtc);
  const trendWarnings = [];
  const miniCharts = chartDefinitions
    .map((item) => {
      const points = normalizeSeries(resourceSeries[item.key]);
      const values = points.map((point) => point.value);
      const currentValue = values.length > 0 ? values[values.length - 1] : null;
      const minValue = values.length > 0 ? Math.min(...values) : null;
      const maxValue = values.length > 0 ? Math.max(...values) : null;
      const avgValue = values.length > 0 ? values.reduce((sum, value) => sum + value, 0) / values.length : null;
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
          <p class="mini-chart-main-value">${currentValue === null ? "-" : `${formatNumber(currentValue, 1)}${isPercent ? "%" : ""}`}</p>
          ${buildSparklineSvg(points, item.color, 420, 140, {
            suffix: isPercent ? "%" : "",
            trendColor: usedTrendColor,
            ...(isPercent ? { minValue: 0, maxValue: 100 } : {}),
          })}
          <footer class="mini-chart-history">
            <span>Min: ${minValue === null ? "-" : formatNumber(minValue, 2)}</span>
            <span>Max: ${maxValue === null ? "-" : formatNumber(maxValue, 2)}</span>
            <span>Avg: ${avgValue === null ? "-" : formatNumber(avgValue, 2)}</span>
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

function closeChartDrillModal() {
  const modal = document.getElementById("chartDrillModal");
  if (modal) {
    modal.classList.add("hidden");
  }
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
    window.alert("Kein Host ausgewählt.");
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
    return "<p class=\"muted\">Keine Filesystem-Verlaufskurven verfügbar.</p>";
  }
  const standText = formatUtcPlus2(latestReportTimeUtc);
  const fsTrendWarnings = [];

  const cards = filesystemTrends
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

function formatTerminalOutput(text, fallback = "-") {
  const source = asText(text, "");
  const lines = source ? source.split("\n") : [fallback];
  return lines.map((line) => formatTerminalOutputLine(line)).join("\n");
}

function formatTerminalOutputLine(line) {
  if (!line) {
    return "";
  }
  if (/^\s*#/.test(line)) {
    return `<span class="terminal-token-comment">${escapeHtml(line)}</span>`;
  }

  const trimmed = line.trim();
  if (/^\[[^\]]+\]$/.test(trimmed)) {
    const leadingWhitespace = line.match(/^\s*/)?.[0] || "";
    return `${escapeHtml(leadingWhitespace)}<span class="terminal-token-heading">${escapeHtml(trimmed)}</span>`;
  }

  const keyValueMatch = line.match(/^(\s*)([A-Z][A-Z0-9_ ]*)(=)(.*)$/);
  if (keyValueMatch) {
    const [, leadingWhitespace, key, separator, rawValue] = keyValueMatch;
    return `${escapeHtml(leadingWhitespace)}<span class="terminal-token-field">${escapeHtml(key.trimEnd())}</span><span class="terminal-token-separator">${escapeHtml(separator)}</span>${formatTerminalInline(rawValue)}`;
  }

  return formatTerminalInline(line);
}

function formatTerminalInline(text) {
  const tokenRe = /(\b\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}:\d{2}Z)?\b|\b\d+(?:\.\d+)?%\b|\b(?:ERROR|ERR|WARN(?:ING)?|FAIL(?:ED)?|CRIT(?:ICAL)?|FATAL|MISSING|UNAVAILABLE|DISABLED|INACTIVE|ABSENT|NOT_FOUND)\b|\b(?:OK|SUCCESS|DONE|RUNNING|AVAILABLE|ENABLED|ACTIVE|PRESENT)\b|\b(?:INFO|DEBUG|TRACE|NOTICE)\b|\b(?:TRUE|FALSE|YES|NO|JA|NEIN)\b|\b(?:SAP|HANA|SQL|SARI|CATALINA|BUSINESSONE|BUSINESS_ONE|FEATURE_PACK|PATCH_LEVEL|SID|BRANCH|BUILD|RELEASE|VERSION|STATUS|PATH|SIZE|ERROR|MESSAGE)\b|\b[A-Z][A-Z0-9_]{2,}(?==)|\b\d+(?:\.\d+){1,}\b|\b\d+(?:KB|MB|GB|TB|PB)\b|(?:[A-Za-z]:\\[^\s]+|\/[^\s]+))/gi;
  let result = "";
  let lastIndex = 0;
  let match;

  while ((match = tokenRe.exec(text)) !== null) {
    const [token] = match;
    result += escapeHtml(text.slice(lastIndex, match.index));
    result += renderTerminalToken(token);
    lastIndex = match.index + token.length;
  }

  result += escapeHtml(text.slice(lastIndex));
  return result;
}

function renderTerminalToken(token) {
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

  return `<span class="${className}">${escapeHtml(value)}</span>`;
}

function renderTerminalViewer(content, metaLine = "", extraClasses = "") {
  const metaHtml = metaLine ? `<p class="count compact">${escapeHtml(metaLine)}</p>` : "";
  const classSuffix = extraClasses ? ` ${extraClasses}` : "";
  return `
    <div class="terminal-viewer-section">
      ${metaHtml}
      <pre class="log-viewer${classSuffix}">${formatTerminalOutput(content)}</pre>
    </div>
  `;
}

function formatSapPathSizeTerminalEntry(title, block, missingText) {
  const item = block && typeof block === "object" ? block : {};
  const pathValue = asText(item.path, "-");
  const exists = item.exists === true;
  const sizeNumber = Number(item.size_bytes);
  const sizeText = exists
    ? (Number.isFinite(sizeNumber) && sizeNumber >= 0 ? formatBytes(sizeNumber) : "n/a")
    : missingText;

  return [
    `[${title}]`,
    `PATH=${pathValue || "-"}`,
    `STATUS=${exists ? "PRESENT" : "MISSING"}`,
    `SIZE=${sizeText || "-"}`,
  ].join("\n");
}

function renderSapBusinessOneCard(payload) {
  const sap = payload && typeof payload.sap_business_one === "object" ? payload.sap_business_one : null;
  if (!sap) {
    return `
      <section class="detail-card sap-b1-card">
        <h4>SAP Business One Files / Ordner</h4>
        ${renderTerminalViewer("STATUS=UNAVAILABLE\nMESSAGE=Keine SAP-Business-One-Daten im Payload vorhanden.")}
      </section>
    `;
  }

  return `
    <section class="detail-card sap-b1-card">
      <h4>SAP Business One Files / Ordner</h4>
      ${renderTerminalViewer([
        formatSapPathSizeTerminalEntry("catalina.out", sap.catalina_out, "Datei nicht vorhanden"),
        formatSapPathSizeTerminalEntry("BusinessOne Log Ordner", sap.businessone_log_dir, "Ordner nicht vorhanden"),
      ].join("\n\n"), "Zwei SAP-B1-Pfade geprueft")}
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
  if (fp) {
    return `<strong>${escapeHtml(fp)}</strong>`;
  }
  return escapeHtml(releaseDate);
}


function renderHarvestStatusSection(payload) {
  const sap = payload && typeof payload.sap_business_one === "object" ? payload.sap_business_one : null;
  const harvest = sap && typeof sap.harvest_status === "object" ? sap.harvest_status : null;
  
  if (!harvest) {
    return `<p class="muted">Kein Harvest-Status im Payload vorhanden.</p>`;
  }
  
  const enabled = harvest.harvest_enabled === true;
  const userExists = harvest.user_exists === true;
  const canConnect = harvest.can_connect === true;
  const databases = Array.isArray(harvest.databases_accessible) ? harvest.databases_accessible : [];
  const error = asText(harvest.error, "");
  const diagnostics = asText(harvest.diagnostics, "");
  
  const statusIcon = (canConnect && userExists) ? "✅" : "❌";
  
  return `
    <div style="padding: 8px; background: #f5f5f5; border-radius: 4px; margin-bottom: 8px;">
      <p><strong>${statusIcon} Harvest-Status:</strong></p>
      <p class="muted">
        • Aktiviert: ${enabled ? "✅" : "❌"}<br/>
        • Benutzer existiert: ${userExists ? "✅" : "❌"}<br/>
        • Verbindung möglich: ${canConnect ? "✅" : "❌"}<br/>
        ${databases.length > 0 ? `• Zugängliche Datenbanken: ${databases.length}<br/>` : ""}
        ${error ? `• Fehler: ${escapeHtml(error)}<br/>` : ""}
        ${diagnostics ? `• Details: ${escapeHtml(diagnostics)}<br/>` : ""}
      </p>
    </div>
  `;
}

function renderSapB1ServicePorts(portsRaw) {
  const parts = asText(portsRaw, "").split(",").map((part) => asText(part, "").trim()).filter(Boolean);
  if (parts.length === 0) {
    return "-";
  }
  return parts.map((part) => {
    const safe = escapeHtml(part);
    if (/^4\d{3,}$/.test(part)) {
      return `<strong>${safe}</strong>`;
    }
    return safe;
  }).join(", ");
}

function renderSapB1InstalledServicesSection(payload) {
  const sap = payload && typeof payload.sap_business_one === "object" ? payload.sap_business_one : null;
  const installed = sap && typeof sap.installed_services === "object" ? sap.installed_services : null;
  const services = Array.isArray(installed?.services) ? installed.services : [];
  const reason = asText(installed?.reason, "").trim();

  let contentHtml = '<p class="muted">Keine SAPServices gefunden</p>';
  if (services.length > 0) {
    const sorted = [...services].sort((a, b) => {
      const ad = asText(a?.description, "").toLowerCase();
      const bd = asText(b?.description, "").toLowerCase();
      return ad.localeCompare(bd);
    });

    const rowsHtml = sorted.map((service) => {
      const description = asText(service?.description, "-");
      const name = asText(service?.name, "-");
      const ports = asText(service?.ports, "-");
      const status = asText(service?.status, "-");
      const live = asText(service?.live, "-");
      const statusLower = status.toLowerCase();
      const isActive = statusLower.startsWith("active") || statusLower.startsWith("running");
      const statusClass = isActive ? "sap-b1-service-status-active" : "sap-b1-service-status-inactive";
      return `
        <tr>
          <td>
            <div>${escapeHtml(description)}</div>
            <div class="sap-b1-service-subname"><span class="sap-b1-service-subname-icon" aria-hidden="true">i</span><span class="sap-b1-service-subname-text">${escapeHtml(name)}</span></div>
          </td>
          <td>${renderSapB1ServicePorts(ports)}</td>
          <td><span class="${statusClass}">${escapeHtml(status)}</span></td>
          <td>${escapeHtml(live)}</td>
        </tr>
      `;
    }).join("");

    contentHtml = `
      <div class="table-wrap">
        <table class="report-subtable sap-b1-services-table">
          <thead>
            <tr>
              <th>Beschreibung</th>
              <th>Port(s)</th>
              <th>Status</th>
              <th>Live</th>
            </tr>
          </thead>
          <tbody>${rowsHtml}</tbody>
        </table>
      </div>
    `;
  } else if (reason) {
    contentHtml = `<p class="muted">${escapeHtml(reason)}</p>`;
  }

  return `
    <details class="sap-b1-raw-details">
      <summary class="sap-b1-raw-summary">Installierte Services</summary>
      ${contentHtml}
    </details>
  `;
}

function renderSapB1ExtensionsSection(payload) {
  const sap = payload && typeof payload.sap_business_one === "object" ? payload.sap_business_one : null;
  const ext = sap && typeof sap.extensions === "object" ? sap.extensions : null;
  const sariAddons = sap && typeof sap.sari_addons === "object" ? sap.sari_addons : null;
  const hanaAddons = payload && typeof payload.hana_addons === "object" ? payload.hana_addons : null;
  const osField = asText(payload?.os, "").toLowerCase();

  const isWindows = osField.includes("windows");
  const isLinux = osField.includes("linux");
  const showSql = !isLinux;
  const showHana = !isWindows;

  // SQL B1: Lightweight Extensions
  const rows = Array.isArray(ext?.rows) ? ext.rows : [];
  const extCount = rows.length;
  let extContent = '<p class="muted">Keine Daten vorhanden.</p>';
  if (rows.length > 0) {
    const bodyHtml = rows.map((row) => {
      const pair = normalizeAddonPair(row?.AddOnName, row?.Version);
      if (!pair.name) return "";
      const addOnName = escapeHtml(pair.name);
      const version = escapeHtml(pair.version || "-");
      return `<tr><td>${addOnName}</td><td>${version}</td></tr>`;
    }).filter(Boolean).join("");
    if (bodyHtml) {
      extContent = `
        <div class="table-wrap">
          <table class="report-subtable sap-addon-subtable">
            <thead><tr><th>AddOnName</th><th>Version</th></tr></thead>
            <tbody>${bodyHtml}</tbody>
          </table>
        </div>
      `;
    }
  }

  // SQL B1: Legacy AddOns
  const sariRows = Array.isArray(sariAddons?.rows) ? sariAddons.rows : [];
  const sariCount = sariRows.length;
  const sariAvailable = sariAddons?.available === true;
  const sariSourceDb = asText(sariAddons?.source_db, "");
  const sariError = asText(sariAddons?.error, "");
  let sariContent = '<p class="muted">Keine Daten vorhanden.</p>';
  if (sariRows.length > 0) {
    const sariBodyHtml = sariRows.map((row) => {
      const pair = normalizeAddonPair(row?.AName, row?.AddOnVer);
      if (!pair.name) return "";
      const addOnName = escapeHtml(pair.name);
      const version = escapeHtml(pair.version || "-");
      return `<tr><td>${addOnName}</td><td>${version}</td></tr>`;
    }).filter(Boolean).join("");
    if (sariBodyHtml) {
      sariContent = `
        <div class="table-wrap">
          <table class="report-subtable sap-addon-subtable">
            <thead><tr><th>AName</th><th>AddOnVer</th></tr></thead>
            <tbody>${sariBodyHtml}</tbody>
          </table>
        </div>
      `;
    }
  } else if (sariError) {
    sariContent = `<p class="muted">SARI-Check gelaufen, aber keine Daten gefunden. Fehler: ${escapeHtml(sariError)}</p>`;
  } else if (sariAddons) {
    if (sariAvailable) {
      sariContent = "<p class=\"muted\">SARI-Check gelaufen, aber keine Legacy AddOns gefunden.</p>";
    } else {
      sariContent = "<p class=\"muted\">SARI-Check gelaufen, aber keine Daten zum Anzeigen gefunden.</p>";
    }
  }

  const hanaTenantViews = collectHanaAddonTenantViews(hanaAddons);
  const hanaAddonCount = hanaTenantViews.reduce((sum, tenantView) => {
    return sum
      + (Array.isArray(tenantView?.lightweight) ? tenantView.lightweight.length : 0)
      + (Array.isArray(tenantView?.legacy) ? tenantView.legacy.length : 0);
  }, 0);

  const renderHanaRows = (rows) => {
    return (Array.isArray(rows) ? rows : [])
      .map((row) => {
        const pair = normalizeAddonPair(row?.name, row?.version);
        if (!pair.name) return "";
        const name = escapeHtml(pair.name);
        const version = escapeHtml(pair.version || "-");
        return `<tr><td>${name}</td><td>${version}</td></tr>`;
      })
      .filter(Boolean)
      .join("");
  };

  const hanaTenantContent = hanaTenantViews
    .map((tenantView) => {
      const tenantLabel = tenantView.tenantId ? `Tenant ${tenantView.tenantId}` : "SystemDB";
      const tenantHeader = tenantLabel;

      const lwBody = renderHanaRows(tenantView.lightweight);
      const lgBody = renderHanaRows(tenantView.legacy);
      const lwCount = Array.isArray(tenantView.lightweight) ? tenantView.lightweight.length : 0;
      const lgCount = Array.isArray(tenantView.legacy) ? tenantView.legacy.length : 0;

      const lwContent = lwBody
        ? `<div class="table-wrap"><table class="report-subtable sap-addon-subtable"><thead><tr><th>Name</th><th>Version</th></tr></thead><tbody>${lwBody}</tbody></table></div>`
        : '<p class="muted">Keine Lightweight Extensions vorhanden.</p>';
      const lgContent = lgBody
        ? `<div class="table-wrap"><table class="report-subtable sap-addon-subtable"><thead><tr><th>Name</th><th>Version</th></tr></thead><tbody>${lgBody}</tbody></table></div>`
        : '<p class="muted">Keine Legacy AddOns vorhanden.</p>';

      const tenantError = tenantView.error ? `<p class="muted">Fehler: ${escapeHtml(tenantView.error)}</p>` : "";
      const tenantReason = !tenantView.available && tenantView.reason
        ? `<p class="muted">Status: ${escapeHtml(tenantView.reason)}</p>`
        : "";

      return `
        <details class="sap-b1-raw-details sap-b1-sub-details">
          <summary class="sap-b1-raw-summary">${escapeHtml(tenantHeader)} (${lwCount + lgCount})</summary>
            <details class="sap-b1-raw-details sap-b1-sub-details">
            <summary class="sap-b1-raw-summary">Lightweight Extensions (HANA) (${lwCount})</summary>
            ${lwContent}
          </details>
            <details class="sap-b1-raw-details sap-b1-sub-details">
            <summary class="sap-b1-raw-summary">Legacy AddOns (HANA) (${lgCount})</summary>
            ${lgContent}
          </details>
          ${tenantReason}
          ${tenantError}
        </details>
      `;
    })
    .join("");

  return `
    ${showSql ? `
    <details class="sap-b1-raw-details sap-b1-sub-details">
      <summary class="sap-b1-raw-summary">Lightweight Extensions (SQL) (${extCount})</summary>
      ${extContent}
    </details>
    <details class="sap-b1-raw-details sap-b1-sub-details">
      <summary class="sap-b1-raw-summary">Legacy AddOns (SQL) (${sariCount})</summary>
      ${sariContent}
    </details>
    ` : ""}
    ${showHana && hanaAddons ? `
    <details class="sap-b1-raw-details sap-b1-sub-details">
      <summary class="sap-b1-raw-summary">HANA AddOns (${hanaAddonCount})</summary>
      ${hanaTenantContent || '<p class="muted">Keine HANA AddOn-Daten vorhanden.</p>'}
    </details>
    ` : ''}
  `;
}

function collectHanaAddonTenantViews(hanaAddons) {
  if (!hanaAddons || typeof hanaAddons !== "object") {
    return [];
  }

  const parsePortFromTarget = (targetValue) => {
    const target = asText(targetValue, "");
    const match = target.match(/:(\d{5})$/);
    return match ? match[1] : "";
  };

  const tenantRows = Array.isArray(hanaAddons.tenants) ? hanaAddons.tenants : [];
  if (tenantRows.length > 0) {
    return tenantRows
      .filter((tenantRow) => tenantRow && typeof tenantRow === "object")
      .map((tenantRow) => {
        const tenantResult = tenantRow.result && typeof tenantRow.result === "object" ? tenantRow.result : tenantRow;
        const targetValue = asText(tenantResult.target, "");
        const tenantPortRaw = asText(tenantRow.tenant_port, "").trim();
        return {
          tenantId: asText(tenantRow.tenant_id, "").trim(),
          tenantPort: tenantPortRaw || parsePortFromTarget(targetValue),
          target: targetValue,
          lightweight: Array.isArray(tenantResult.lightweight) ? tenantResult.lightweight : [],
          legacy: Array.isArray(tenantResult.legacy) ? tenantResult.legacy : [],
          available: tenantResult.available === true,
          reason: asText(tenantResult.reason, ""),
          error: asText(tenantResult.error, "")
        };
      });
  }

  return [{
    tenantId: "",
    tenantPort: parsePortFromTarget(asText(hanaAddons.target, "")),
    target: asText(hanaAddons.target, ""),
    lightweight: Array.isArray(hanaAddons.lightweight) ? hanaAddons.lightweight : [],
    legacy: Array.isArray(hanaAddons.legacy) ? hanaAddons.legacy : [],
    available: hanaAddons.available === true,
    reason: asText(hanaAddons.reason, ""),
    error: asText(hanaAddons.error, "")
  }];
}

function collectHanaDbTenantViews(hanaInfo) {
  if (!hanaInfo || typeof hanaInfo !== "object") {
    return [];
  }

  const parsePortFromTarget = (targetValue) => {
    const target = asText(targetValue, "");
    const match = target.match(/:(\d{5})$/);
    return match ? match[1] : "";
  };

  const tenantRows = Array.isArray(hanaInfo.tenants) ? hanaInfo.tenants : [];
  if (tenantRows.length > 0) {
    return tenantRows
      .filter((tenantRow) => tenantRow && typeof tenantRow === "object")
      .map((tenantRow) => {
        const tenantResult = tenantRow.result && typeof tenantRow.result === "object" ? tenantRow.result : tenantRow;
        const targetValue = asText(tenantResult.target, "");
        const tenantPortRaw = asText(tenantRow.tenant_port, "").trim();
        return {
          tenantId: asText(tenantRow.tenant_id, "").trim(),
          tenantPort: tenantPortRaw || parsePortFromTarget(targetValue),
          target: targetValue,
          databases: Array.isArray(tenantResult.databases) ? tenantResult.databases : [],
          available: tenantResult.available === true,
          reason: asText(tenantResult.reason, ""),
          error: asText(tenantResult.error, "")
        };
      });
  }

  return [{
    tenantId: "",
    tenantPort: parsePortFromTarget(asText(hanaInfo.target, "")),
    target: asText(hanaInfo.target, ""),
    databases: Array.isArray(hanaInfo.databases) ? hanaInfo.databases : [],
    available: hanaInfo.available === true,
    reason: asText(hanaInfo.reason, ""),
    error: asText(hanaInfo.error, "")
  }];
}

function renderHanaMultitenantDiscoverySummary(discovery) {
  if (!discovery || typeof discovery !== "object") {
    return "";
  }

  const sid = asText(discovery.sid, "").trim();
  const reason = asText(discovery.reason, "").trim();
  const tenants = Array.isArray(discovery.tenants)
    ? discovery.tenants.filter((entry) => entry && typeof entry === "object")
    : [];
  const tenantLabels = tenants
    .map((entry) => {
      const tenantId = asText(entry.tenant_id, "").trim();
      if (!tenantId) return "";
      return tenantId;
    })
    .filter(Boolean);

  const reasonText = {
    success: "Tenant-Verzeichnisse erkannt",
    partial_missing_port: "Tenant-Verzeichnisse erkannt",
    none_found: "Keine Tenant-Verzeichnisse erkannt",
    missing_hana_sid: "HANA SID fehlt"
  }[reason] || reason;

  const title = sid
    ? `Multitenant Discovery (SID ${escapeHtml(sid)})`
    : "Multitenant Discovery";
  const details = tenantLabels.length > 0
    ? `Erkannte Tenants: ${escapeHtml(tenantLabels.join(", "))}`
    : "Erkannte Tenants: keine";

  return `
    <details class="sap-b1-raw-details sap-b1-sub-details">
      <summary class="sap-b1-raw-summary">${title} (${tenantLabels.length})</summary>
      <p class="muted">${escapeHtml(reasonText || "Status unbekannt")}</p>
      <p class="muted">${details}</p>
    </details>
  `;
}

function renderSapLicenseInfoSection(payload) {
  const sapLicense = payload && typeof payload.sap_license === "object" ? payload.sap_license : null;
  const systemType = asText(sapLicense?.system_type, "").trim();
  const rawFocusTypes = Array.isArray(sapLicense?.focus_license_types) ? sapLicense.focus_license_types : [];

  const translatedFocusTypes = rawFocusTypes
    .filter((entry) => entry && typeof entry === "object")
    .map((entry) => {
      const rawType = asText(entry.license_type, "");
      const upperRawType = rawType.toUpperCase();
      let translated = null;
      for (const mapEntry of SAP_LICENSE_TYPE_MAP) {
        const isVisible = Boolean(mapEntry?.visible);
        const matchText = asText(mapEntry?.matchText, "").toUpperCase();
        if (matchText && matchText === upperRawType && isVisible) {
          translated = asText(mapEntry?.displayName, null);
          break;
        }
      }
      const countRaw = Number(entry.count);
      const count = Number.isFinite(countRaw) ? countRaw : 0;
      return {
        rawType,
        translated,
        count,
      };
    })
    .filter((entry) => entry.rawType && entry.translated !== null);

  const copyText = translatedFocusTypes
    .map((entry) => `${String(entry.count)}  ${entry.translated} (${entry.rawType})`)
    .join("\n");

  const focusTypeRows = translatedFocusTypes
    .map((entry) => {
      const countDisplay = String(entry.count);
      const label = `${escapeHtml(entry.translated)} <span class="sap-license-raw-type">(${escapeHtml(entry.rawType)})</span>`;
      return `<p class="sap-license-list-item"><span class="sap-license-count">${countDisplay}</span><strong>${label}</strong></p>`;
    })
    .join("");

  const focusTypeContent = focusTypeRows
    ? `<div class="sap-license-list">${focusTypeRows}</div>`
    : '<p class="muted">Lizenztypen ohne Übersetzung in der Matrix — Admin: bitte hinzufügen und übersetzen.</p>';

  const locationHintHtml = `
    <div class="sap-license-location-hint">
      <p><strong>SQL</strong>: gesucht wird <code>B01.txt</code> unter <code>C:\\ANG\\Lizenzen\\B01.txt</code>, <code>C:\\ANG\\Lizenz\\B01.txt</code>, <code>C:\\ANG\\B01.txt</code>, <code>C:\\Program Files (x86)\\SAP\\SAP Business One Server\\B1_SHR\\Lizenz\\B01.txt</code> oder <code>C:\\Program Files (x86)\\SAP\\SAP Business One Server\\B1_SHR\\Lizenzen\\B01.txt</code>.</p>
      <p><strong>HANA</strong>: gesucht wird <code>B01.txt</code> unter <code>/usr/sap/SAPBusinessOne/B1_SHF/Lizenzen/B01.txt</code> oder <code>/usr/sap/SAPBusinessOne/B1_SHF/Lizenz/B01.txt</code>.</p>
    </div>
  `;

  return `
    <details class="sap-b1-raw-details">
      <summary class="sap-b1-raw-summary">Lizenzinfos</summary>
      <div class="sap-license-list-wrap">
        ${systemType ? `<p class="muted"><strong>Systemtyp:</strong> ${escapeHtml(systemType)}</p>` : ""}
        <p class="sap-license-list-meta">
          <span>SAP B1 Lizenztypen (übersetzt)</span>
          ${focusTypeRows ? `<button class="sap-vmap-copy-btn" type="button" title="In Zwischenablage kopieren" data-copy="${escapeHtml(copyText)}">📋 Kopieren</button>` : ""}
        </p>
        ${focusTypeContent}
        ${locationHintHtml}
      </div>
    </details>
  `;
}


function renderSapB1VersionMapCard() {
  const sortedEntries = Array.from(SAP_B1_VERSION_MAP.entries())
    .sort(([a], [b]) => b.localeCompare(a));
  const copyText = sortedEntries
    .map(([build, info]) => `${build}\t${info.featurePack}\t${info.patchLevel}\t${info.releaseDate}`)
    .join("\n");

  return `
    <details class="sap-b1-raw-details">
      <summary class="sap-b1-raw-summary">
        SAP B1 Version-Referenztabelle (${SAP_B1_VERSION_MAP.size} Einträge) 📋
        <button class="sap-vmap-copy-btn" type="button" title="In Zwischenablage kopieren" data-copy="${escapeHtml(copyText)}">📋 Kopieren</button>
      </summary>
      ${renderSapVersionMapTerminalTable(sortedEntries, `${SAP_B1_VERSION_MAP.size} Referenzeintraege`)}
    </details>
  `;
}

function renderSapVersionMapTerminalTable(sortedEntries, metaLine = "") {
  const rowsHtml = sortedEntries.map(([build, info]) => {
    const featurePack = asText(info?.featurePack, "-");
    const patchLevel = asText(info?.patchLevel, "-");
    const releaseDate = asText(info?.releaseDate, "-");
    return `
      <tr>
        <td class="sap-vmap-col-build">${escapeHtml(build)}</td>
        <td>${escapeHtml(featurePack)}</td>
        <td>${escapeHtml(patchLevel)}</td>
        <td class="sap-vmap-col-release">${escapeHtml(releaseDate)}</td>
      </tr>
    `;
  }).join("");

  const metaHtml = metaLine ? `<p class="count compact">${escapeHtml(metaLine)}</p>` : "";
  return `
    <div class="terminal-viewer-section sap-vmap-terminal-section">
      ${metaHtml}
      <div class="sap-vmap-terminal-wrap" role="region" aria-label="SAP B1 Version Referenztabelle">
        <table class="sap-vmap-terminal-table">
          <thead>
            <tr>
              <th>BUILD</th>
              <th>FEATURE_PACK</th>
              <th>PATCH_LEVEL</th>
              <th>RELEASE</th>
            </tr>
          </thead>
          <tbody>${rowsHtml}</tbody>
        </table>
      </div>
    </div>
  `;
}

function wireSapVersionMapCopyButtons(container) {
  for (const btn of (container || document).querySelectorAll(".sap-vmap-copy-btn")) {
    btn.addEventListener("click", async (e) => {
      e.stopPropagation();
      const text = btn.getAttribute("data-copy") || "";
      try {
        await navigator.clipboard.writeText(text);
        const orig = btn.textContent;
        btn.textContent = "✅ Kopiert!";
        setTimeout(() => { btn.textContent = orig; }, 1500);
      } catch {
        btn.textContent = "❌ Fehler";
        setTimeout(() => { btn.textContent = "📋 Kopieren"; }, 1500);
      }
    });
  }
}

function wireReportHierarchyToggleButtons(container) {
  for (const button of (container || document).querySelectorAll("[data-action='report-hierarchy-toggle']")) {
    button.addEventListener("click", () => {
      const mode = asText(button.getAttribute("data-toggle-mode"), "").toLowerCase();
      const targetClass = asText(button.getAttribute("data-target-class"), "").trim();
      if (!targetClass || (mode !== "expand" && mode !== "collapse")) {
        return;
      }
      const reportCard = button.closest(".report-card");
      if (!reportCard) {
        return;
      }
      const targetRoot = reportCard.querySelector(`.${targetClass}`);
      if (!targetRoot) {
        return;
      }
      const detailsNodes = [
        ...(targetRoot.matches("details") ? [targetRoot] : []),
        ...targetRoot.querySelectorAll("details"),
      ];
      const open = mode === "expand";
      for (const detailsNode of detailsNodes) {
        detailsNode.open = open;
      }
    });
  }
}

function renderSapB1CombinedCard(payload) {
  const sap = payload && typeof payload.sap_business_one === "object" ? payload.sap_business_one : null;
  const versionBlock = sap && typeof sap.server_components_version === "object" ? sap.server_components_version : null;
  const rawOutput = asText(versionBlock?.raw_output, "");
  const osField = asText(payload?.os, "").toLowerCase();
  const isWindows = osField.includes("windows");
  const isLinux = osField.includes("linux");

  // Files / Ordner section
  let filesContent;
  if (!sap) {
    filesContent = renderTerminalViewer("STATUS=UNAVAILABLE\nMESSAGE=Keine SAP-Business-One-Daten im Payload vorhanden.");
  } else {
    filesContent = renderTerminalViewer([
      formatSapPathSizeTerminalEntry("catalina.out", sap.catalina_out, "Datei nicht vorhanden"),
      formatSapPathSizeTerminalEntry("BusinessOne Log Ordner", sap.businessone_log_dir, "Ordner nicht vorhanden"),
    ].join("\n\n"), "Zwei SAP-B1-Pfade geprueft");
  }

  // HANA section
  const hanaInfo = payload && typeof payload.hana_info === "object" ? payload.hana_info : null;
  const hanaRawOutput = asText(hanaInfo?.raw_output, "");
  const hanaVersion = asText(hanaInfo?.version, "");
  const hanaBranch = asText(hanaInfo?.branch, "");
  const hanaSid = asText(hanaInfo?.sid, "");
  const hanaAvailable = hanaInfo?.available === true;
  const hanaError = asText(hanaInfo?.error, "");

  let hanaInfoRows;
  if (!hanaInfo) {
    hanaInfoRows = renderTerminalViewer("STATUS=UNAVAILABLE\nMESSAGE=Kein HANA-Scan im Payload (Agent-Update erforderlich)");
  } else if (!hanaAvailable) {
    hanaInfoRows = renderTerminalViewer(`STATUS=MISSING\nERROR=${hanaError || "HANA nicht gefunden"}`);
  } else {
    hanaInfoRows = renderTerminalViewer([
      "STATUS=AVAILABLE",
      hanaSid ? `SID=${hanaSid}` : "",
      hanaVersion ? `VERSION=${hanaVersion}` : "",
      hanaBranch ? `BRANCH=${hanaBranch}` : "",
    ].filter(Boolean).join("\n"));
  }

  // Version map section
  const sortedEntries = Array.from(SAP_B1_VERSION_MAP.entries()).sort(([a], [b]) => b.localeCompare(a));
  const copyText = sortedEntries
    .map(([build, info]) => `${build}\t${info.featurePack}\t${info.patchLevel}\t${info.releaseDate}`)
    .join("\n");
  const sapB1RawOutputDetails = state.isAdmin
    ? `
      <details class="sap-b1-raw-details sap-b1-admin-only-subsection">
        <summary class="sap-b1-raw-summary">SAP B1 Setup Roh-Output <span class="sap-b1-admin-badge">Admin</span></summary>
        ${renderTerminalViewer(rawOutput || "-")}
      </details>
      `
    : "";

  return `
    <section class="detail-card sap-b1-card sap-b1-combined-card">
      <div class="report-section-head">
        <h4>SAP B1</h4>
        <div class="report-section-head-actions">
          <button type="button" class="btn-secondary btn-secondary--compact" data-action="report-hierarchy-toggle" data-toggle-mode="expand" data-target-class="report-addons-hierarchy">Alle aufklappen</button>
          <button type="button" class="btn-secondary btn-secondary--compact" data-action="report-hierarchy-toggle" data-toggle-mode="collapse" data-target-class="report-addons-hierarchy">Alle zuklappen</button>
        </div>
      </div>

      <div class="sap-b1-scroll-region">
        <details class="sap-b1-raw-details report-addons-hierarchy">
          <summary class="sap-b1-raw-summary">AddOns</summary>
          ${renderSapB1ExtensionsSection(payload)}
        </details>

        ${isLinux ? `
        <details class="sap-b1-raw-details">
          <summary class="sap-b1-raw-summary">SAP Business One Files / Ordner</summary>
          ${filesContent}
        </details>
        ` : ""}

        ${renderSapB1InstalledServicesSection(payload)}

        ${sapB1RawOutputDetails}

        ${isLinux ? `
        <details class="sap-b1-raw-details">
          <summary class="sap-b1-raw-summary">HANA Versions-Scan</summary>
          ${hanaInfoRows}
          ${hanaRawOutput ? renderTerminalViewer(hanaRawOutput, "Roh-Output") : ""}
        </details>
        ` : ""}

          ${isWindows ? `
          <details class="sap-b1-raw-details">
            <summary class="sap-b1-raw-summary">Harvest SQL-Benutzer Status</summary>
            ${renderHarvestStatusSection(payload)}
          </details>
          ` : ""}

        ${renderSapLicenseInfoSection(payload)}

        <details class="sap-b1-raw-details">
          <summary class="sap-b1-raw-summary">
            SAP B1 Version-Referenztabelle (${SAP_B1_VERSION_MAP.size} Einträge) 📋
            <button class="sap-vmap-copy-btn" type="button" title="In Zwischenablage kopieren" data-copy="${escapeHtml(copyText)}">📋 Kopieren</button>
          </summary>
          ${renderSapVersionMapTerminalTable(sortedEntries, `${SAP_B1_VERSION_MAP.size} Referenzeintraege`)}
        </details>
      </div>
    </section>
  `;
}

function renderSapB1SystemInfoCard(payload) {
  const sap = payload && typeof payload.sap_business_one === "object" ? payload.sap_business_one : null;
  const versionBlock = sap && typeof sap.server_components_version === "object" ? sap.server_components_version : null;
  if (!versionBlock) {
    return `
      <section class="detail-card sap-b1-card">
        <h4>SAP B1</h4>
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
    hanaInfoRows = renderTerminalViewer("STATUS=UNAVAILABLE\nMESSAGE=Kein HANA-Scan im Payload (Agent-Update erforderlich)");
  } else if (!hanaAvailable) {
    hanaInfoRows = renderTerminalViewer(`STATUS=MISSING\nERROR=${hanaError || "HANA nicht gefunden"}`);
  } else {
    hanaInfoRows = renderTerminalViewer([
      "STATUS=AVAILABLE",
      hanaSid ? `SID=${hanaSid}` : "",
      hanaVersion ? `VERSION=${hanaVersion}` : "",
      hanaBranch ? `BRANCH=${hanaBranch}` : "",
    ].filter(Boolean).join("\n"));
  }
  const sapB1RawOutputDetails = state.isAdmin
    ? `
        <details class="sap-b1-raw-details sap-b1-admin-only-subsection">
          <summary class="sap-b1-raw-summary">SAP B1 Setup Roh-Output <span class="sap-b1-admin-badge">Admin</span></summary>
          ${renderTerminalViewer(rawOutput || "-")}
        </details>
      `
    : "";

  return `
    <section class="detail-card sap-b1-card">
      <h4>SAP B1</h4>
      <div class="sap-b1-grid">
        ${sapB1RawOutputDetails}
        <details class="sap-b1-raw-details">
          <summary class="sap-b1-raw-summary">HANA Versions-Scan</summary>
          ${hanaInfoRows}
          ${hanaRawOutput ? renderTerminalViewer(hanaRawOutput, "Roh-Output") : ""}
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
            <th>Name</th>
            <th class="dir-item-size-head">Grösse</th>
            <th class="dir-item-date-head">Geändert (UTC+2)</th>
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
        <h4>SAP Exports</h4>
        <p class="muted">Keine SAP Exports Daten vorhanden. (DIR_SCAN_PATHS oder DIR_SCAN_DEEP_PATHS in agent.conf konfigurieren)</p>
      </section>
    `;
  }

  let html = `<section class="detail-card dir-listings-card"><h4>SAP Exports</h4>`;

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

function asText(value, fallback = "-") {
  if (value === null || value === undefined) {
    return fallback;
  }

  const text = String(value).trim();
  return text === "" ? fallback : text;
}

function cleanAddonCellText(value, fallback = "-") {
  const text = asText(value, fallback);
  if (text === fallback) {
    return text;
  }

  return text
    .replace(/["“”]/g, "")
    .replace(/\s*[0-9]+\s+rows? selected.*$/i, "")
    .replace(/\s*(overall|server)\s+time.*$/i, "")
    .trim() || fallback;
}

function isAddonNoiseLine(value) {
  const text = String(value || "").trim().toLowerCase();
  if (!text) return false;
  return text.includes("rows selected") || text.includes("overall time") || text.includes("server time");
}

function normalizeAddonPair(primaryValue, secondaryValue) {
  const rawPrimary = String(primaryValue ?? "").trim();
  const secondary = cleanAddonCellText(secondaryValue, "");

  if (!rawPrimary || isAddonNoiseLine(rawPrimary)) {
    return { name: "", version: "" };
  }

  let name = cleanAddonCellText(rawPrimary, "");
  let version = secondary;

  if (!version || version === "?" || version === "-") {
    const normalized = rawPrimary
      .replace(/^['"]+/, "")
      .replace(/['"]+$/, "")
      .replace(/"\s*,\s*"/g, ",")
      .replace(/"\s*,\s*/g, ",")
      .replace(/\s*,\s*"/g, ",")
      .trim();

    if (normalized.includes(",")) {
      const splitIndex = normalized.indexOf(",");
      const left = normalized.slice(0, splitIndex).trim();
      const right = normalized.slice(splitIndex + 1).trim();
      name = cleanAddonCellText(left, name || "");
      version = cleanAddonCellText(right, version || "");
    }
  }

  if (isAddonNoiseLine(name)) {
    return { name: "", version: "" };
  }

  if (version === "?" || !version) {
    version = "-";
  }

  return { name, version };
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

function formatReportDateTime(value) {
  const text = asText(value, "");
  if (!text) {
    return "-";
  }
  const parsed = new Date(text);
  if (Number.isNaN(parsed.getTime())) {
    return text;
  }
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
  return `${parts.day}.${parts.month}.${parts.year} ${parts.hour}:${parts.minute}`;
}

function formatIdleDuration(seconds) {
  const total = Number(seconds);
  if (!Number.isFinite(total) || total <= 0) {
    return "-";
  }
  const hours = Math.floor(total / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  if (hours > 0) {
    return `${hours}h ${minutes}m`;
  }
  if (minutes > 0) {
    return `${minutes}m`;
  }
  return "<1m";
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
            <th class="fs-col-mountpoint">Mountpoint</th>
            <th class="fs-col-filesystem">Filesystem</th>
            <th class="fs-col-type">Typ</th>
            <th class="fs-col-size">Gesamt</th>
            <th class="fs-col-size">Belegt</th>
            <th class="fs-col-size">Frei</th>
            <th class="fs-col-usage">Auslastung</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `;
}

function renderDatabasesSection(payload) {
  const sqlInfo = payload.sql_server_info;
  const hanaInfo = payload.hana_db_info; // reserved for future HANA DB user data
  const hanaDiscovery = payload && typeof payload.hana_multitenant_discovery === "object"
    ? payload.hana_multitenant_discovery
    : null;

  const sqlReleaseMap = [
    { major: 16, label: "SQL Server 2022" },
    { major: 15, label: "SQL Server 2019" },
    { major: 14, label: "SQL Server 2017" },
    { major: 13, label: "SQL Server 2016" },
    { major: 12, label: "SQL Server 2014" },
    { major: 11, label: "SQL Server 2012" },
    { major: 10, label: "SQL Server 2008 / 2008 R2" },
    { major: 9, label: "SQL Server 2005" },
    { major: 8, label: "SQL Server 2000" },
  ];

  const resolveSqlRelease = (versionText) => {
    const raw = asText(versionText, "");
    if (!raw) {
      return { label: "unbekannt", detail: "Keine Versionsnummer vorhanden" };
    }

    const versionParts = raw.split(".");
    const major = Number(versionParts[0]);
    const minor = Number(versionParts[1] || "0");
    if (!Number.isFinite(major)) {
      return { label: "unbekannt", detail: `Nicht parsebar: ${raw}` };
    }

    if (major === 10) {
      if (minor >= 50) {
        return { label: "SQL Server 2008 R2", detail: `${major}.${minor}x` };
      }
      return { label: "SQL Server 2008", detail: `${major}.${minor}x` };
    }

    const mapped = sqlReleaseMap.find((entry) => entry.major === major);
    if (mapped) {
      return { label: mapped.label, detail: `${major}.x` };
    }
    return { label: "Unbekannte SQL-Generation", detail: `${major}.x` };
  };

  const sqlReleaseMapText = sqlReleaseMap
    .map((entry) => `${entry.major}.x -> ${entry.label}`)
    .join(" | ");

  const parts = [];

  // ---- SQL Server (Windows) ----
  if (sqlInfo && typeof sqlInfo === "object") {
    if (sqlInfo.available === false) {
      parts.push(`<section class="detail-card"><h4>🗃️ SQL Server</h4><p class="muted">SQL Server nicht gefunden (Registry-Schlüssel fehlt).</p></section>`);
    } else {
      const instances = Array.isArray(sqlInfo.instances) ? sqlInfo.instances : [];
      for (const inst of instances) {
        const instName = asText(inst.name, "MSSQLSERVER");
        const version  = asText(inst.version, "");
        const edition  = asText(inst.edition, "");
        const releaseInfo = resolveSqlRelease(version);
        const svcStatus = asText(inst.service_status, "unknown");
        const connErr  = asText(inst.connection_error, "");
        const sqlSystemUser = asText(inst.sql_system_user, "");
        const sqlOriginalLogin = asText(inst.sql_original_login, "");
        const sqlSuserSname = asText(inst.sql_suser_sname, "");
        const masterFilesRows = Number(inst.master_files_rows || 0);
        const sqlSizeHintSnippet = "GRANT VIEW SERVER STATE TO [NT AUTHORITY\\SYSTEM];\nGRANT VIEW ANY DEFINITION TO [NT AUTHORITY\\SYSTEM];";
        const sqlGrantSnippet = String.raw`-- 1) Logins anlegen (falls noch nicht vorhanden)
IF SUSER_ID(N'NT-AUTORITÄT\SYSTEM') IS NULL
    CREATE LOGIN [NT-AUTORITÄT\SYSTEM] FROM WINDOWS;

IF SUSER_ID(N'AD\LMS-AP01$') IS NULL
    CREATE LOGIN [AD\LMS-AP01$] FROM WINDOWS;

-- 2) Benötigte Server-Rechte vergeben
GRANT VIEW SERVER STATE TO [NT-AUTORITÄT\SYSTEM];
GRANT VIEW ANY DEFINITION TO [NT-AUTORITÄT\SYSTEM];

GRANT VIEW SERVER STATE TO [AD\LMS-AP01$];
GRANT VIEW ANY DEFINITION TO [AD\LMS-AP01$];`;
        
        const svcBadge = svcStatus.toLowerCase() === "running"
          ? `<span class="db-status-badge db-status-ok">Running</span>`
          : `<span class="db-status-badge db-status-warn">${escapeHtml(svcStatus)}</span>`;

        let diagHtml = "";
        if (sqlSystemUser || sqlOriginalLogin || sqlSuserSname || masterFilesRows > 0) {
          diagHtml = `
              <details class="db-diag-info db-diag-collapsible">
                <summary class="db-diag-label">🔐 SQL Authentifizierung (für Diag):</summary>
              ${sqlSystemUser ? `<span class="db-diag-item"><strong>SYSTEM_USER:</strong> <code>${escapeHtml(sqlSystemUser)}</code></span>` : ""}
              ${sqlOriginalLogin ? `<span class="db-diag-item"><strong>ORIGINAL_LOGIN:</strong> <code>${escapeHtml(sqlOriginalLogin)}</code></span>` : ""}
              ${sqlSuserSname ? `<span class="db-diag-item"><strong>SUSER_SNAME:</strong> <code>${escapeHtml(sqlSuserSname)}</code></span>` : ""}
              ${masterFilesRows > 0 ? `<span class="db-diag-item"><strong>sys.master_files Zeilen:</strong> ${masterFilesRows}</span>` : ""}
                ${sqlGrantSnippet ? `<p class="db-diag-snippet-label">SQL Script:</p><pre class="db-diag-sql"><code>${escapeHtml(sqlGrantSnippet)}</code></pre>` : ""}
                ${sqlGrantSnippet ? `<p class="count compact">Hinweis: Das Skript muss ggf. anhand der Diagnose-Werte angepasst werden. Basis: <code>AD\\LMS-AP01$</code> durch den Wert in <strong>ORIGINAL_LOGIN</strong> ersetzen und <code>NT-AUTORITÄT\\SYSTEM</code> durch den Wert in <strong>SYSTEM_USER</strong>.</p>` : ""}
              </details>`;
        }

          const metaHtml = `
            <div class="db-instance-meta">
              <span class="db-meta-item"><strong>Instanz:</strong> ${escapeHtml(instName)}</span>
              ${version ? `<span class="db-meta-item"><strong>Version:</strong> ${escapeHtml(version)}</span>` : ""}
              <span class="db-meta-item"><strong>Release:</strong> ${escapeHtml(releaseInfo.label)}${releaseInfo.detail ? ` <span class="count compact">(${escapeHtml(releaseInfo.detail)})</span>` : ""}</span>
              ${edition ? `<span class="db-meta-item"><strong>Edition:</strong> ${escapeHtml(edition)}</span>` : ""}
              <span class="db-meta-item"><strong>Dienst:</strong> ${svcBadge}</span>
            </div>
            <p class="count compact">Version-Mapping: ${escapeHtml(sqlReleaseMapText)}. Spezialfall: 10.50.x = SQL Server 2008 R2.</p>
            ${diagHtml}`;

        let dbTableHtml = "";
        if (connErr) {
          dbTableHtml = `<p class="muted db-conn-error">⚠️ Kein DB-Zugriff (Windows Auth): ${escapeHtml(connErr)}</p>`;
        } else {
          const dbs = Array.isArray(inst.databases) ? inst.databases : [];
          if (dbs.length === 0) {
            dbTableHtml = `<p class="muted">Keine Datenbanken gefunden.</p>`;
          } else {
            const rows = dbs.map((db) => {
              const name = asText(db.name, "-");
              const instanceName = asText(db.instance_name, instName);
              const isSystem = db.system_db === true;
              const state = asText(db.state, "-");
              const recovery = asText(db.recovery_model, "-");
              const dataMb = Number(db.data_mb || 0);
              const logMb  = Number(db.log_mb  || 0);
              const totalMb = dataMb + logMb;
              const sizeStr = totalMb >= 1024
                ? `${(totalMb / 1024).toFixed(1)} GB`
                : `${totalMb} MB`;
              const dataSizeStr = dataMb >= 1024 ? `${(dataMb/1024).toFixed(1)} GB` : `${dataMb} MB`;
              const logSizeStr  = logMb  >= 1024 ? `${(logMb /1024).toFixed(1)} GB` : `${logMb} MB`;

              const fullBk  = asText(db.last_full_backup, "");

              const fmtBk = (utc) => utc ? formatUtcPlus2(utc) : '<span class="muted">—</span>';

              const stateClass = state.toLowerCase() === "online" ? "" : " db-state-warn";
              const systemClass = isSystem ? " db-row-system" : "";
              const instanceCol = instances.length > 1 
                ? `<td class="db-instance-cell">${escapeHtml(instanceName)}</td>`
                : '';
              return `
                <tr class="${stateClass}${systemClass}">
                  ${instanceCol}
                  <td>${escapeHtml(name)}${isSystem ? ' <span class="db-sys-badge">sys</span>' : ""}</td>
                  <td>${escapeHtml(state)}</td>
                  <td>${escapeHtml(recovery)}</td>
                  <td class="db-size-cell" title="Data: ${escapeHtml(dataSizeStr)} · Log: ${escapeHtml(logSizeStr)}">${escapeHtml(sizeStr)}</td>
                  <td class="db-bk-cell">${fmtBk(fullBk)}</td>
                </tr>`;
            }).join("");
            const instanceHeaderCol = instances.length > 1 ? '<th class="db-instance-cell">Instanz</th>' : '';
            dbTableHtml = `
              <div class="table-wrap">
                <table class="db-table">
                  <thead>
                    <tr>
                      ${instanceHeaderCol}
                      <th>Datenbank</th>
                      <th>Status</th>
                      <th>Recovery</th>
                      <th class="db-size-cell">Grösse</th>
                      <th>Letztes Full-Backup</th>
                    </tr>
                  </thead>
                  <tbody>${rows}</tbody>
                </table>
              </div>
              <div class="db-size-hint">
                <p class="db-size-hint-title">Hinweis bei fehlenden DB-Grössen</p>
                <p class="db-size-hint-text">Wenn in der SQL-Backup-Übersicht keine DB-Grössen angezeigt werden, dieses Skript mit dem <strong>sa</strong>-User ausführen:</p>
                ${renderTerminalViewer(sqlSizeHintSnippet, "mit sa ausführen", "db-size-hint-terminal")}
              </div>`;
          }
        }

        parts.push(`
          <section class="detail-card">
            <h4>🗃️ SQL Server${instances.length > 1 ? ` — ${escapeHtml(instName)}` : ""}</h4>
            ${metaHtml}
            ${dbTableHtml}
          </section>`);
      }
    }
  }

  // ---- HANA DB (company databases) ----
  if (hanaInfo && typeof hanaInfo === "object") {
    const discoveryHtml = renderHanaMultitenantDiscoverySummary(hanaDiscovery);
    if (hanaInfo.available !== true && !Array.isArray(hanaInfo.tenants)) {
      const reason = asText(hanaInfo.reason, "");
      const error = asText(hanaInfo.error, "");
      const reasonText = {
        "missing_hana_sid": "HANA SID nicht gefunden",
        "missing_sid_user": "SID-Benutzer nicht vorhanden",
        "missing_hdbsql": "hdbsql nicht gefunden",
        "auth_failed": "Authentifizierung fehlgeschlagen",
        "query_failed": "Abfrage fehlgeschlagen"
      }[reason] || (reason || "HANA Datenbank-Scan nicht verfügbar");
      parts.push(`<section class="detail-card sap-hana-databases-card"><h4>🔶 SAP HANA Datenbanken</h4><div class="sap-hana-databases-scroll">${discoveryHtml}<p class="muted">${escapeHtml(reasonText)}${error ? `: ${escapeHtml(error)}` : ""}</p></div></section>`);
    } else {
      const tenantViews = collectHanaDbTenantViews(hanaInfo);
      const renderFilteredDatabases = (databases) => {
        return (Array.isArray(databases) ? databases : []).filter((entry) => {
          const name = asText(entry?.name, "").trim();
          return !!name;
        });
      };

      const tenantBlocks = tenantViews.map((tenantView) => {
        const databases = renderFilteredDatabases(tenantView.databases);
        const tenantLabel = tenantView.tenantId ? `Tenant ${tenantView.tenantId}` : "SystemDB";
        const tenantMeta = [tenantLabel];

        if (databases.length === 0) {
          const tenantStatus = tenantView.error
            ? ` (${escapeHtml(tenantView.error)})`
            : (tenantView.reason ? ` (${escapeHtml(tenantView.reason)})` : "");
          return `<p class="muted">${escapeHtml(tenantMeta.join(" | "))}: Keine Eintraege${tenantStatus}.</p>`;
        }

        const rows = databases.map((entry) => {
          const name = asText(entry.name, "-");
          const companyName = asText(entry.company_name, "-");
          const localization = asText(entry.localization, "-");
          return `
            <tr>
              <td>${escapeHtml(name)}</td>
              <td>${escapeHtml(companyName || "-")}</td>
              <td>${escapeHtml(localization || "-")}</td>
            </tr>`;
        }).join("");

        return `
          <details class="sap-b1-raw-details sap-b1-sub-details">
            <summary class="sap-b1-raw-summary">${escapeHtml(tenantMeta.join(" | "))} (${databases.length})</summary>
            <div class="table-wrap">
              <table class="db-table hana-db-table">
                <colgroup>
                  <col class="hana-db-col-name">
                  <col class="hana-db-col-company">
                  <col class="hana-db-col-loc">
                </colgroup>
                <thead>
                  <tr>
                    <th>Datenbank</th>
                    <th>Firma</th>
                    <th>Lokalisierung</th>
                  </tr>
                </thead>
                <tbody>${rows}</tbody>
              </table>
            </div>
          </details>`;
      }).join("");

      parts.push(`
        <section class="detail-card sap-hana-databases-card">
          <div class="report-section-head">
            <h4>🔶 SAP HANA Datenbanken</h4>
            <div class="report-section-head-actions">
              <button type="button" class="btn-secondary btn-secondary--compact" data-action="report-hierarchy-toggle" data-toggle-mode="expand" data-target-class="report-hana-db-hierarchy">Alle aufklappen</button>
              <button type="button" class="btn-secondary btn-secondary--compact" data-action="report-hierarchy-toggle" data-toggle-mode="collapse" data-target-class="report-hana-db-hierarchy">Alle zuklappen</button>
            </div>
          </div>
          <div class="sap-hana-databases-scroll report-hana-db-hierarchy">
            ${discoveryHtml}
            ${tenantBlocks || '<p class="muted">Keine Eintraege gefunden.</p>'}
          </div>
        </section>`);
    }
  }

  if (parts.length === 0) {
    return `<section class="detail-card"><h4>🗃️ Datenbanken</h4><p class="muted">Keine Datenbankdaten in diesem Report vorhanden.</p></section>`;
  }
  return `<div class="detail-cards">${parts.join("")}</div>`;
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
            <th>Zeit</th>
            <th>Prio</th>
            <th>Unit</th>
            <th>Meldung</th>
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
    return "<p class=\"muted\">Keine Prozessdaten verfügbar.</p>";
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
    <p class="count compact">Prozesse nach CPU-Auslastung</p>
    <div class="table-wrap">
      <table class="report-subtable top-processes-table">
        <thead>
          <tr>
            <th>PID</th>
            <th>User</th>
            <th>CPU</th>
            <th>RAM</th>
            <th>RSS</th>
            <th>Command</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `;
}

function renderUserSessionsTable(userSessions, osFamily = "") {
  const block = userSessions && typeof userSessions === "object" ? userSessions : {};
  const entries = Array.isArray(block.entries) ? block.entries : [];
  const normalizedOs = asText(osFamily, "").toLowerCase();

  if (entries.length === 0) {
    if (normalizedOs.includes("windows")) {
      return "<p class=\"muted\">Keine angemeldeten Benutzer-Sessions im letzten Report.</p>";
    }
    return "<p class=\"muted\">User-Sessions werden aktuell nur vom Windows-Agent erfasst.</p>";
  }

  const rows = entries
    .map((entry) => {
      const username = asText(entry.username, "-");
      const sessionId = Number(entry.session_id);
      const sessionName = asText(entry.session_name, "-");
      const state = asText(entry.state, "-");
      const sessionType = asText(entry.session_type, "-");
      const clientAddress = asText(entry.client_address, "-");
      const logonTime = formatReportDateTime(entry.logon_time_utc);
      const idle = formatIdleDuration(entry.idle_seconds);
      return `
        <tr>
          <td>${escapeHtml(username)}</td>
          <td>${Number.isFinite(sessionId) && sessionId > 0 ? sessionId : "-"}</td>
          <td>${escapeHtml(sessionName)}</td>
          <td>${escapeHtml(state)}</td>
          <td>${escapeHtml(sessionType)}</td>
          <td>${escapeHtml(idle)}</td>
          <td>${escapeHtml(logonTime)}</td>
          <td>${escapeHtml(clientAddress)}</td>
        </tr>
      `;
    })
    .join("");

  return `
    <p class="count compact">${entries.length} angemeldete Session${entries.length === 1 ? "" : "s"}</p>
    <div class="table-wrap">
      <table class="report-subtable user-sessions-table">
        <thead>
          <tr>
            <th>Benutzer</th>
            <th>Session-ID</th>
            <th>Session</th>
            <th>Status</th>
            <th>Typ</th>
            <th>Idle</th>
            <th>Anmeldung</th>
            <th>Client</th>
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
    return `<p class="muted">Container-Runtime nicht verfügbar (${escapeHtml(runtime)}).</p>`;
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
      <table class="report-subtable containers-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Image</th>
            <th>State</th>
            <th>Health</th>
            <th>Restarts</th>
            <th>Status</th>
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
  const lines = entries.map((entry) => {
    const key = escapeHtml(asText(entry.key));
    const rawValue = asText(entry.value);
    const value = rawValue === "***"
      ? `<span class="agent-config-secret">***</span>`
      : `<span class="agent-config-value">${escapeHtml(rawValue)}</span>`;
    return `<span class="agent-config-key">${key}</span>=${value}`;
  }).join("\n");
  return `
    <div class="terminal-viewer-section">
      <p class="count compact">Pfad: ${escapeHtml(path || "-")}</p>
      <pre class="log-viewer agent-config-viewer">${lines || "Konfigurationsdatei ist vorhanden, enthält aber aktuell keine Einträge."}</pre>
    </div>
  `;
}

function repairUtf8MojibakeLatin1(text) {
  const raw = String(text ?? "");
  if (!raw || !/Ã.|â€/.test(raw)) {
    return raw;
  }
  try {
    const bytes = new Uint8Array(raw.length);
    for (let index = 0; index < raw.length; index += 1) {
      bytes[index] = raw.charCodeAt(index) & 0xff;
    }
    const repaired = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    if (repaired && repaired !== raw && !/Ã.|â€/.test(repaired)) {
      return repaired;
    }
  } catch (_error) {
    // keep original when repair is not valid UTF-8
  }
  return raw;
}

function asLogLineText(value) {
  if (value === null || value === undefined) {
    return "";
  }
  return repairUtf8MojibakeLatin1(String(value));
}

function parseAngLogsBlock(raw) {
  if (raw === null || raw === undefined) {
    return null;
  }
  if (typeof raw === "string") {
    const trimmed = raw.trim();
    if (!trimmed) {
      return null;
    }
    try {
      const parsed = JSON.parse(trimmed);
      return parsed && typeof parsed === "object" ? parsed : null;
    } catch (_error) {
      return null;
    }
  }
  if (typeof raw === "object") {
    return raw;
  }
  return null;
}

function getAngLogsBlockFromPayload(payload) {
  return parseAngLogsBlock(payload?.ang_logs) || parseAngLogsBlock(payload?.ang_skripte_logs);
}

// Split merged log blobs (often one physical line / no newlines in file) before each timestamp.
const ANG_LOG_LINE_SPLIT_PATTERNS = [
  /(?=\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?\s)/,
  /(?=\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:[.,]\d{1,6})?\])/,
  /(?=\[\d{2}\.\d{2}\.\d{4} \d{2}:\d{2}(?::\d{2})?(?:[.,]\d{1,6})?\])/,
];

function looksLikeAngLogJsonLine(line) {
  const trimmed = String(line || "").trim();
  if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) {
    return false;
  }
  if (/^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}/.test(trimmed) || /^\[\d{2}\.\d{2}\.\d{4} \d{2}:\d{2}/.test(trimmed)) {
    return false;
  }
  return trimmed.startsWith("{") || trimmed.startsWith("[{") || trimmed.startsWith('["') || trimmed.startsWith("[\n");
}

function shouldSplitAngLogLogicalLine(line) {
  const trimmed = asLogLineText(line).trim();
  if (!trimmed) {
    return false;
  }
  if (looksLikeAngLogJsonLine(trimmed)) {
    return false;
  }
  return true;
}

function splitAngLogLogicalLine(line) {
  const trimmed = asLogLineText(line).trim();
  if (!trimmed) {
    return [];
  }

  if (!shouldSplitAngLogLogicalLine(trimmed)) {
    return [trimmed];
  }

  let parts = [trimmed];
  for (const pattern of ANG_LOG_LINE_SPLIT_PATTERNS) {
    const next = [];
    for (const part of parts) {
      const chunks = part
        .split(pattern)
        .map((chunk) => chunk.replace(/^\s+/, "").trimEnd())
        .filter((chunk) => chunk.length > 0);
      if (chunks.length > 1) {
        next.push(...chunks);
      } else if (part) {
        next.push(part);
      }
    }
    if (next.length > 1) {
      parts = next;
    }
  }
  return parts.length > 0 ? parts : [trimmed];
}

function normalizeAngSkripteLogLines(rawLines) {
  if (Array.isArray(rawLines)) {
    return rawLines.map((line) => asLogLineText(line));
  }
  if (typeof rawLines === "string") {
    const trimmed = rawLines.trim();
    if (!trimmed) {
      return [];
    }
    if (trimmed.startsWith("[")) {
      try {
        const parsed = JSON.parse(trimmed);
        if (Array.isArray(parsed)) {
          return parsed.map((line) => asLogLineText(line));
        }
      } catch (_error) {
        // fall through to plain-text split
      }
    }
    return trimmed.split(/\r\n|\n|\r/).map((line) => asLogLineText(line));
  }
  return [];
}

function expandAngSkripteLogLines(rawLines) {
  const normalized = normalizeAngSkripteLogLines(rawLines);
  if (!normalized.length) {
    return [];
  }

  const expanded = [];
  for (const line of normalized) {
    const logicalLines = splitAngLogLogicalLine(line);
    if (logicalLines.length > 1) {
      expanded.push(...logicalLines);
      continue;
    }
    if (line.includes("\n") || line.includes("\r")) {
      expanded.push(
        ...line
          .split(/\r\n|\n|\r/)
          .map((entry) => asLogLineText(entry))
          .filter((entry) => entry.length > 0),
      );
      continue;
    }
    if (line) {
      expanded.push(line);
    }
  }

  return expanded.length > 0 ? expanded : normalized;
}

function renderLogfileLinesHtml(rawLines) {
  const expanded = expandAngSkripteLogLines(rawLines);
  if (!expanded.length) {
    return '<div class="log-line log-line--empty">(leer)</div>';
  }
  return expanded.map((line) => {
    const html = line ? formatTerminalOutputLine(line) : "&nbsp;";
    const extraClass = line ? "" : " log-line--empty";
    return `<div class="log-line${extraClass}">${html}</div>`;
  }).join("");
}

function renderAngLogTerminal(rawLines, metaLine = "") {
  const metaHtml = metaLine ? `<p class="count compact">${escapeHtml(metaLine)}</p>` : "";
  return `
    <div class="terminal-viewer-section">
      ${metaHtml}
      <div class="log-viewer ang-log-viewer">${renderLogfileLinesHtml(rawLines)}</div>
    </div>
  `;
}

function renderAngLogFileSummary(file) {
  const name = asText(file?.name, "unbekannt");
  const relativePath = asText(file?.relative_path);
  const label = relativePath && relativePath !== name ? relativePath : name;
  const displayLines = expandAngSkripteLogLines(file?.lines);
  const lineCount = displayLines.length;
  const sizeBytes = Number(file?.size_bytes);
  const sizeLabel = Number.isFinite(sizeBytes) && sizeBytes >= 0
    ? ` · ${formatBytes(sizeBytes)}`
    : "";
  const lineLabel = lineCount > 0
    ? `${lineCount} Zeile${lineCount !== 1 ? "n" : ""}`
    : "leer";
  const fileError = String(file?.error || "").trim();
  const errorLabel = fileError ? " · Fehler" : "";
  return `${escapeHtml(label)} · ${escapeHtml(lineLabel)}${escapeHtml(sizeLabel)}${escapeHtml(errorLabel)}`;
}

function renderAngLogFileBody(file) {
  const filePath = asText(file?.path);
  const fileError = String(file?.error || "").trim();
  const sizeBytes = Number(file?.size_bytes);
  const displayLines = expandAngSkripteLogLines(file?.lines);
  const lineCount = displayLines.length;
  const sizeLabel = Number.isFinite(sizeBytes) && sizeBytes >= 0
    ? ` | Größe: ${formatBytes(sizeBytes)}`
    : "";
  if (fileError) {
    return `
      <p class="muted">${escapeHtml(fileError)}</p>
      <p class="count compact">Pfad: ${escapeHtml(filePath || "-")}${escapeHtml(sizeLabel)}</p>
    `;
  }
  const logMeta = lineCount > 0
    ? `Pfad: ${filePath || "-"} | ${lineCount} Zeile${lineCount !== 1 ? "n" : ""} angezeigt${sizeLabel}`
    : `Pfad: ${filePath || "-"} | keine lesbaren Zeilen${sizeLabel}`;
  if (lineCount > 0) {
    return renderAngLogTerminal(file?.lines, logMeta);
  }
  return renderTerminalViewer(
    [
      "STATUS=EMPTY",
      "MESSAGE=Datei erkannt, aber keine lesbaren Zeilen im Payload.",
    ].join("\n"),
    logMeta
  );
}

function renderAngLogs(angLogsBlock) {
  const block = angLogsBlock || {};
  const path = asText(block.path, "C:\\ang");
  const files = Array.isArray(block.files) ? block.files : [];
  const dirError = asText(block.error);

  if (block.available !== true && files.length === 0) {
    const hint = dirError || `Keine Logfile-Infos unter ${path}.`;
    return `<p class="muted">${escapeHtml(hint)}</p><p class="count compact">Wurzel: ${escapeHtml(path)} (rekursiv *.log)</p>`;
  }

  if (!files.length) {
    return `<p class="muted">Keine .log-Dateien unter ${escapeHtml(path)} gefunden.</p>`;
  }

  const fileBlocks = files.map((file) => `
    <details class="detail-card detail-card-collapsible ang-log-file-card">
      <summary>${renderAngLogFileSummary(file)}</summary>
      ${renderAngLogFileBody(file)}
    </details>
  `).join("");

  const discoveredCount = Number(block.discovered_file_count);
  const maxAgeDays = Number(block.max_age_days);
  const rotationKeep = Number(block.rotation_keep_per_group) || 2;
  const filterParts = [];
  if (Number.isFinite(maxAgeDays) && maxAgeDays > 0) {
    filterParts.push(`max. ${maxAgeDays} Tage alt`);
  }
  filterParts.push(`Rotation: je Gruppe max. ${rotationKeep} aktuellste`);
  const filterHint = filterParts.join(" · ");
  const countHint = Number.isFinite(discoveredCount) && discoveredCount > files.length
    ? `${files.length} von ${discoveredCount} Log-Dateien (${filterHint})`
    : `${files.length} Datei${files.length !== 1 ? "en" : ""}${files.length > 0 ? ` (${filterHint})` : ""}`;
  return `
    <p class="count compact">Wurzel: ${escapeHtml(path)} · rekursiv *.log · ${escapeHtml(countHint)}</p>
    <div class="ang-logs-grid">${fileBlocks}</div>
  `;
}

function renderLogfilesSection(payload) {
  const defaultPath = "C:\\ang";
  const angLogs = getAngLogsBlockFromPayload(payload);
  if (!angLogs) {
    return `
      <section class="detail-card">
        <h4>📜 Logfiles</h4>
        <p class="muted">Keine Logfile-Infos unter ${escapeHtml(defaultPath)}.</p>
        <p class="count compact">Windows-Agent meldet rekursiv alle *.log unter ${escapeHtml(defaultPath)}.</p>
      </section>
    `;
  }
  return `
    <section class="detail-card">
      <h4>📜 Logfiles</h4>
      ${renderAngLogs(angLogs)}
    </section>
  `;
}

function renderScriptGuardianLog(scriptGuardianBlock) {
  const block = scriptGuardianBlock && typeof scriptGuardianBlock === "object" ? scriptGuardianBlock : {};
  const available = block.available === true;
  const path = asText(block.path);
  const allLines = Array.isArray(block.lines) ? block.lines.map((line) => asText(line)) : [];
  const lineCount = Number(block.line_count || allLines.length || 0);
  const lines = allLines.slice(-15);
  const intervalMinutes = Number(block.interval_minutes || 125);
  const lastRun = asText(block.last_run_utc);
  const nextRun = asText(block.next_run_utc);
  const scheduleHint = asText(block.schedule_hint);

  if (!available && lines.length === 0) {
    return `
      <p class="muted">Kein Script-Guardian-Log übertragen.</p>
      <p class="count compact">Pfad: ${escapeHtml(path || "-")} | Intervall: ${Number.isFinite(intervalMinutes) ? intervalMinutes : 125} min</p>
      ${scheduleHint ? `<p class="count compact">${escapeHtml(scheduleHint)}</p>` : ""}
    `;
  }

  const meta = [
    `Pfad: ${path || "-"}`,
    `Zeilen: ${Number.isFinite(lineCount) ? lineCount : allLines.length} (letzte 15)`,
    `Intervall: ${Number.isFinite(intervalMinutes) ? intervalMinutes : 125} min`,
    lastRun ? `Letzter Lauf: ${lastRun}` : "",
    nextRun ? `Nächster Lauf: ${nextRun}` : "",
    scheduleHint || "",
  ].filter(Boolean).join(" | ");

  return `
    ${renderTerminalViewer(
      lines.join("\n") || "Log-Datei ist vorhanden, enthaelt aber aktuell keine Zeilen.",
      meta
    )}
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
      <p class="muted">Kein Update-Log übertragen.</p>
      <p class="count compact">Pfad: ${escapeHtml(path || "-")}</p>
    `;
  }

  return `
    ${renderTerminalViewer(
      lines.join("\n") || "Log-Datei ist vorhanden, enthaelt aber aktuell keine Zeilen.",
      `Pfad: ${path || "-"} | Zeilen: ${Number.isFinite(lineCount) ? lineCount : allLines.length} (letzte 10)`
    )}
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
  return `<details class="cron-details"><summary>${escapeHtml(lines + " aktive Einträge")}</summary><pre class="log-viewer cron-content">${formatTerminalOutput(activeLines || content)}</pre></details>`;
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
    return `<details class="cron-details"><summary>${name}</summary><pre class="log-viewer cron-content">${formatTerminalOutput(content)}</pre></details>`;
  }).join("");
  return `${escapeHtml(count + " Datei" + (count !== 1 ? "en" : ""))} ${fileBlocks}`;
}

function renderReportCard(report) {
  const payload = report && report.payload ? report.payload : {};
  const network = payload.network || {};
  const defaultNicIpv4 = resolveDefaultNicIpv4(report, payload, network);
  const technicalHostname = asText(report.hostname || payload.hostname);
  const deliveryMode = asText(report.delivery_mode || payload.delivery_mode || "live", "live").toLowerCase();
  const isDelayed = deliveryMode === "delayed" || payload.is_delayed === true;
  const chipClass = isDelayed ? "delivery-chip delayed" : "delivery-chip live";
  const chipText = isDelayed ? "DELAYED" : "LIVE";
  const queueDepth = queueDepthLabel(payload.queue_depth);
  const section = normalizeReportSection(state.reportSection);
  const selectedHostMeta = Array.isArray(state.hosts)
    ? state.hosts.find((host) => asText(host.hostname) === technicalHostname)
    : null;
  const hi = payload && typeof payload.hana_info === "object" ? payload.hana_info : null;
  const sapReleaseRaw = asText(
    payload.sap_release
      || payload.sap_feature_pack
      || selectedHostMeta?.sap_release
      || selectedHostMeta?.sap_feature_pack
      || ""
  ).trim();
  const sapVersionInfo = parseSapB1Version(sapReleaseRaw);
  const sapFeaturePackChip = asText(
    sapVersionInfo.mapping?.featurePack
      || (sapReleaseRaw.toUpperCase().startsWith("FP") ? sapReleaseRaw : "")
      || sapReleaseRaw
  ).trim();
  const hanaVersionRaw = asText(
    payload.hana_release
      || payload.hana_version
      || (hi?.available ? hi.version : "")
      || selectedHostMeta?.hana_release
      || selectedHostMeta?.hana_version
      || ""
  ).trim();
  const hanaVersionChip = hanaVersionRaw
    ? (hanaVersionRaw.split(".").slice(0, 3).join(".") || hanaVersionRaw)
    : "";
  const hanaSidChip = asText(
    payload.hana_sid
      || (hi?.available ? hi.sid : "")
      || selectedHostMeta?.hana_sid
      || ""
  ).trim();
  const hasKpiCardData = Boolean(sapFeaturePackChip || hanaVersionChip || hanaSidChip);
  const featurePackKpiValue = sapFeaturePackChip || "-";
  const patchLevelKpiValue = hanaVersionChip || "-";
  const buildKpiValue = hanaSidChip || "-";
  const reportTimestampFull = asText(
    formatUtcPlus2(report.received_at_utc || payload.timestamp_utc),
    "-"
  ).trim();
  const reportTimestampParts = reportTimestampFull.split(",");
  const reportTimestampDate = asText(reportTimestampParts.shift(), reportTimestampFull).trim();
  const reportTimestampTime = asText(reportTimestampParts.join(","), "").trim();

  const hostMeta = selectedHostMeta || {};
  const customerLabel = asText(hostMeta.customer_name, "Kein Kunde");
  const displayLabel = asText(hostMeta.display_name || technicalHostname, technicalHostname);
  const hostUid = asText(report.host_uid || payload.host_uid || hostMeta.host_uid, "").trim();
  const countryCode = normalizeHostCountryCode(hostMeta) || "-";
  const envLabel = asText(hostMeta.environment_type, "").trim().toUpperCase() || "-";
  const customerProject = asText(hostMeta.customer_maringo_project_number, "").trim();
  const totalReports = Number.isFinite(Number(state.totalReports))
    ? Number(state.totalReports).toLocaleString("de-CH")
    : Number.isFinite(Number(hostMeta.report_count))
      ? Number(hostMeta.report_count).toLocaleString("de-CH")
      : "-";
  const primaryIp = asText(report.primary_ip || payload.primary_ip || hostMeta.primary_ip || hostMeta.std_nic_ip, "-");
  const stdNicIp = asText(defaultNicIpv4 || hostMeta.std_nic_ip, "-");
  const dnsValue = Array.isArray(network.dns_servers)
    ? network.dns_servers.filter(Boolean).join(", ") || "-"
    : asText(network.dns_servers, "-");

  const metricRow = (label, value, options = {}) => {
    let valueHtml = escapeHtml(asText(value, "-"));
    if (options.ellipsisFull) {
      valueHtml = renderFullValueWithEllipsisHtml(value);
    } else if (options.truncate === "hostname") {
      valueHtml = renderTruncatedHostnameHtml(value, { maxLen: options.truncateMaxLen });
    } else if (options.truncate === "uid") {
      valueHtml = renderTruncatedHostUidHtml(value);
    } else if (options.truncate) {
      valueHtml = renderTruncatedTextHtml(value);
    } else if (options.html) {
      valueHtml = value;
    }
    const valueClass = options.nowrap ? " metric-value--nowrap" : "";
    return `
    <div class="metric-row">
      <span class="metric-label">${escapeHtml(label)}</span>
      <span class="metric-value${valueClass}">${valueHtml}</span>
    </div>
  `;
  };

  const hostIdentityRows = [
    metricRow("Kunde", customerLabel, { truncate: true }),
    metricRow("Bezeichnung", displayLabel, { truncate: true }),
    metricRow("Hostname", technicalHostname, { ellipsisFull: true }),
    metricRow("Host-UID", hostUid, { truncate: "uid" }),
    metricRow("Land", countryCode),
    metricRow("Umgebung", envLabel),
    customerProject ? metricRow("Projekt", customerProject) : "",
    metricRow("Meldungen", totalReports),
    metricRow("Agent ID", report.agent_id || payload.agent_id || "-", { ellipsisFull: true }),
    metricRow("Version", payload.agent_version || hostMeta.agent_version || "-"),
    metricRow("API-Key", formatAgentApiKeyStatus(payload.agent_api_key, payload.agent_config)),
    metricRow("Queue", `${queueDepth} Dateien`),
  ].filter(Boolean).join("");

  const systemNetworkRows = [
    metricRow("OS", payload.os || hostMeta.os || "-"),
    metricRow("Kernel", payload.kernel || "-"),
    metricRow("Uptime", formatUptime(payload.uptime_seconds)),
    metricRow("Architektur", payload.architecture || payload.arch || "-"),
    metricRow("Primary IP", primaryIp, { nowrap: true }),
    metricRow("Std. NIC IP", stdNicIp, { nowrap: true }),
    metricRow("Default NIC", network.default_interface || "-"),
    metricRow("Gateway", network.default_gateway || "-", { nowrap: true }),
    metricRow("DNS", dnsValue, { nowrap: true }),
  ].join("");

  const reportMetricsGrid = `
    <div class="overview-metrics-grid">
      <article class="metric-card">
        <h4>Host &amp; Agent</h4>
        ${hostIdentityRows}
      </article>
      <article class="metric-card">
        <h4>System &amp; Netzwerk</h4>
        ${systemNetworkRows}
      </article>
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
        <h4>👤 Usersessions</h4>
        ${renderUserSessionsTable(payload.user_sessions, payload.os)}
      </section>
      <section class="detail-card">
        <h4>🏎️ Prozesse</h4>
        ${renderTopProcessesTable(payload.top_processes)}
      </section>
    `;
  } else if (section === "logfiles") {
    detailContent = renderLogfilesSection(payload);
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
        ${renderSapB1CombinedCard(payload)}
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
          <summary>🛡️ Script Guardian Log</summary>
          ${renderScriptGuardianLog(payload.script_guardian)}
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
  } else if (section === "network") {
    detailContent = `
      <section class="detail-card">
        <h4>🌐 Netzwerk-Details</h4>
        ${renderNetworkTable(network)}
      </section>
    `;
  } else if (section === "filesystems") {
    detailContent = `
      <section class="detail-card">
        <h4>💾 Filesysteme</h4>
        ${renderFilesystemTable(payload.filesystems)}
      </section>
    `;
  } else if (section === "databases") {
    detailContent = renderDatabasesSection(payload);
  }

  const showMetaGroups = section === "overview";

  return `
    <article class="report-card">
      <div class="report-header">
        ${hasKpiCardData ? `<div class="report-sap-kpi-row">
          <article class="report-sap-kpi-card report-sap-kpi-card--sap-release" title="SAP Release">
            <h4>SAP RELEASE</h4>
            <p>${escapeHtml(featurePackKpiValue)}</p>
          </article>
          <article class="report-sap-kpi-card report-sap-kpi-card--patch" title="HANA Release">
            <h4>HANA RELEASE</h4>
            <p>${escapeHtml(patchLevelKpiValue)}</p>
          </article>
          <article class="report-sap-kpi-card report-sap-kpi-card--build" title="HANA SID">
            <h4>HANA SID</h4>
            <p>${escapeHtml(buildKpiValue)}</p>
          </article>
        </div>` : ""}
        <div class="report-header-meta">
          <span class="report-time"><span class="report-time-date">${escapeHtml(reportTimestampDate)}</span>${reportTimestampTime ? `<span class="report-time-clock">${escapeHtml(reportTimestampTime)}</span>` : ""}</span>
          <span class="${chipClass}">${chipText}</span>
        </div>
      </div>

      ${showMetaGroups ? reportMetricsGrid : ""}
      ${detailContent}
    </article>
  `;
}

function updatePagerButtons() {
  const hostsPrevButton = document.getElementById("hostsPrevButton");
  const hostsNextButton = document.getElementById("hostsNextButton");
  const reportsPrevButtonTop = document.getElementById("reportsPrevButtonTop");
  const reportsNextButtonTop = document.getElementById("reportsNextButtonTop");

  hostsPrevButton.disabled = state.hostOffset <= 0;
  hostsNextButton.disabled = state.hostOffset + state.hostLimit >= state.totalHosts;

  const reportsPrevDisabled = state.reportOffset <= 0 || (!state.selectedHost && !state.selectedHostUid);
  const reportsNextDisabled =
    (!state.selectedHost && !state.selectedHostUid) || state.reportOffset + state.reportLimit >= state.totalReports;

  if (reportsPrevButtonTop) {
    reportsPrevButtonTop.disabled = reportsPrevDisabled;
  }
  if (reportsNextButtonTop) {
    reportsNextButtonTop.disabled = reportsNextDisabled;
  }
}

async function refreshSelectedHostPanels(options = {}) {
  const reportOptions = options && typeof options.reportOptions === "object" ? options.reportOptions : undefined;
  const reportsOnly = Boolean(options && options.reportsOnly);
  const includeDatabaseLifecycle = Boolean(options && options.includeDatabaseLifecycle);
  const includeConfigChangelog = Boolean(options && options.includeConfigChangelog);
  await loadReportsForHost(reportOptions || {});
  if (reportsOnly) {
    return;
  }
  const tasks = [
    loadAnalysisForHost(),
    loadAlertsForHost(),
  ];
  if (includeDatabaseLifecycle) {
    tasks.push(loadDatabaseLifecycleForHost());
  }
  if (includeConfigChangelog) {
    tasks.push(loadConfigChangelogForHost());
  }
  const results = await Promise.allSettled(tasks);
  const firstRejected = results.find((result) => result.status === "rejected");
  if (firstRejected && firstRejected.status === "rejected") {
    throw firstRejected.reason;
  }
}

async function goToPreviousReport() {
  if (state.reportOffset <= 0 || !state.currentReport?.id) {
    return;
  }
  state.reportOffset = Math.max(0, state.reportOffset - state.reportLimit);
  await refreshSelectedHostPanels({
    reportsOnly: true,
    reportOptions: { beforeId: state.currentReport.id },
  });
}

async function goToNextReport() {
  if (state.reportOffset + state.reportLimit >= state.totalReports || !state.currentReport?.id) {
    return;
  }
  state.reportOffset += state.reportLimit;
  await refreshSelectedHostPanels({
    reportsOnly: true,
    reportOptions: { afterId: state.currentReport.id },
  });
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

let hostOsFilterSelectWired = false;
let hostCountryFilterSelectWired = false;
let hostSortSelectWired = false;

function syncHostSortControl() {
  const sortSelect = document.getElementById("hostSortSelect");
  if (!sortSelect) {
    return;
  }
  sortSelect.value = normalizeHostSortMode(state.hostSortMode);
}

function renderHostIconFilters(hosts) {
  const osSelect = document.getElementById("hostOsFilterSelect");
  const countrySelect = document.getElementById("hostCountryFilterSelect");
  const osContainer = document.getElementById("hostOsFilterChips");
  const countryContainer = document.getElementById("hostCountryFilterChips");

  const osFamilies = Array.from(new Set((hosts || []).map((host) => normalizeHostOsFamily(host))));
  const osOptions = ["all", ...osFamilies.filter((item) => item !== "all")];
  if (!osOptions.includes(state.hostOsFilter)) {
    state.hostOsFilter = "all";
  }

  const countryCodes = Array.from(
    new Set((hosts || []).map((host) => normalizeHostCountryCode(host)).filter((code) => /^[A-Z]{2}$/.test(code))),
  ).sort();
  const countryOptions = ["all", ...countryCodes];
  if (state.hostCountryFilter !== "all" && !countryOptions.includes(state.hostCountryFilter)) {
    state.hostCountryFilter = "all";
  }

  if (osSelect) {
    osSelect.innerHTML = osOptions.map((item) => {
      const label = item === "all" ? "Alle" : (item === "windows" ? "Windows" : "Linux");
      return `<option value="${escapeHtml(item)}">${escapeHtml(label)}</option>`;
    }).join("");
    osSelect.value = state.hostOsFilter;
    if (!hostOsFilterSelectWired) {
      hostOsFilterSelectWired = true;
      osSelect.addEventListener("change", async (event) => {
        const nextFilter = String(event.target?.value || "all");
        if (state.hostOsFilter === nextFilter) {
          return;
        }
        state.hostOsFilter = nextFilter;
        state.hostOffset = 0;
        persistHostFilterPreferences();
        await applyHostFiltersLocally({ preserveScroll: true });
      });
    }
  }

  if (countrySelect) {
    countrySelect.innerHTML = countryOptions.map((code) => {
      const label = code === "all" ? "Alle" : code;
      return `<option value="${escapeHtml(code)}">${escapeHtml(label)}</option>`;
    }).join("");
    countrySelect.value = state.hostCountryFilter;
    if (!hostCountryFilterSelectWired) {
      hostCountryFilterSelectWired = true;
      countrySelect.addEventListener("change", async (event) => {
        const nextFilterRaw = String(event.target?.value || "all");
        const nextFilter = nextFilterRaw.toUpperCase() === "ALL" ? "all" : nextFilterRaw.toUpperCase();
        if (state.hostCountryFilter === nextFilter) {
          return;
        }
        state.hostCountryFilter = nextFilter;
        state.hostOffset = 0;
        persistHostFilterPreferences();
        await applyHostFiltersLocally({ preserveScroll: true });
      });
    }
  }

  if (!osContainer || !countryContainer) {
    return;
  }
  osContainer.innerHTML = "";
  countryContainer.innerHTML = "";
}

function getHostSearchBlob(host) {
  const hostname = String(host?.hostname || "").trim();
  const shortHostname = hostname.includes(".") ? hostname.split(".")[0] : hostname;
  const customerName = String(host?.customer_name || "").trim();
  const customerProject = String(host?.customer_maringo_project_number || "").trim();
  const customerChipLabel = customerProject && customerName
    ? `${customerName} · ${customerProject}`
    : customerName;
  const parts = [
    host?.display_name,
    hostname,
    shortHostname,
    customerName,
    customerProject,
    customerChipLabel,
    host?.std_nic_ip,
    host?.primary_ip,
    host?.host_uid,
  ];
  return parts
    .map((value) => String(value || "").trim().toLowerCase())
    .filter((value) => value.length > 0)
    .join(" ");
}

function hostMatchesSearchQuery(host, query) {
  const q = String(query || "").toLowerCase().trim();
  if (!q) return true;
  return getHostSearchBlob(host).includes(q);
}

function hostReportSortTimestamp(host) {
  const raw = asText(
    host?.last_report_utc
    || host?.last_seen_utc
    || host?.report_time_utc
    || host?.last_report_time_utc
    || "",
  ).trim();
  if (!raw) {
    return 0;
  }
  const ms = Date.parse(raw);
  return Number.isFinite(ms) ? ms : 0;
}

function compareHostsCustomerAlpha(a, b) {
  const customerA = String(a.customer_name || "").trim();
  const customerB = String(b.customer_name || "").trim();
  const hasCustomerA = customerA.length > 0;
  const hasCustomerB = customerB.length > 0;
  if (hasCustomerA !== hasCustomerB) {
    return hasCustomerA ? -1 : 1;
  }
  if (customerA !== customerB) {
    return customerA.localeCompare(customerB, "de", { sensitivity: "base" });
  }
  const nameA = String(a.display_name || a.hostname || "").toLowerCase();
  const nameB = String(b.display_name || b.hostname || "").toLowerCase();
  return nameA.localeCompare(nameB, "de", { sensitivity: "base" });
}

function compareHostsByReportTime(a, b, direction) {
  const tsA = hostReportSortTimestamp(a);
  const tsB = hostReportSortTimestamp(b);
  const hasA = tsA > 0;
  const hasB = tsB > 0;
  if (!hasA && !hasB) {
    return compareHostsCustomerAlpha(a, b);
  }
  if (!hasA) {
    return 1;
  }
  if (!hasB) {
    return -1;
  }
  const diff = direction === "asc" ? tsA - tsB : tsB - tsA;
  if (diff !== 0) {
    return diff;
  }
  return compareHostsCustomerAlpha(a, b);
}

function isTemporaryHostIdentity(host) {
  if (host?.is_temporary_identity === true) {
    return true;
  }
  const reportCount = Number(host?.report_count || 0);
  return Number.isFinite(reportCount) && reportCount > 0 && reportCount <= 3;
}

function compareTemporaryHostPlacement(a, b) {
  const temporaryA = isTemporaryHostIdentity(a) ? 1 : 0;
  const temporaryB = isTemporaryHostIdentity(b) ? 1 : 0;
  if (temporaryA !== temporaryB) {
    return temporaryA - temporaryB;
  }
  return 0;
}

function compareHostsBySortMode(a, b, sortMode) {
  const temporaryPlacement = compareTemporaryHostPlacement(a, b);
  if (temporaryPlacement !== 0) {
    return temporaryPlacement;
  }
  const mode = normalizeHostSortMode(sortMode);
  if (mode === "report_desc") {
    return compareHostsByReportTime(a, b, "desc");
  }
  if (mode === "report_asc") {
    return compareHostsByReportTime(a, b, "asc");
  }
  if (mode === "online_first") {
    const onlineA = a?.online === true ? 1 : 0;
    const onlineB = b?.online === true ? 1 : 0;
    if (onlineA !== onlineB) {
      return onlineB - onlineA;
    }
    return compareHostsCustomerAlpha(a, b);
  }
  return compareHostsCustomerAlpha(a, b);
}

function filterAndSortHosts(hosts) {
  const query = state.hostSearchQuery.toLowerCase().trim();
  const osFilter = String(state.hostOsFilter || "all");
  const countryFilter = String(state.hostCountryFilter || "all").toUpperCase();

  let filtered = hosts;
  if (query.length > 0) {
    filtered = hosts.filter((host) => hostMatchesSearchQuery(host, query));
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
    filtered = filtered.filter((host) => hostInterestSetHasHost(interestSet, host));
  }

  const sortMode = normalizeHostSortMode(state.hostSortMode);
  filtered.sort((a, b) => {
    const temporaryPlacement = compareTemporaryHostPlacement(a, b);
    if (temporaryPlacement !== 0) {
      return temporaryPlacement;
    }
    if (interestMode === "interested_first" && interestSet.size > 0) {
      const interestedA = hostInterestSetHasHost(interestSet, a) ? 1 : 0;
      const interestedB = hostInterestSetHasHost(interestSet, b) ? 1 : 0;
      if (interestedA !== interestedB) {
        return interestedB - interestedA;
      }
    }
    return compareHostsBySortMode(a, b, sortMode);
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
    || String(state.hostOsFilter || "all") !== "all"
    || String(state.hostCountryFilter || "all") !== "all"
  );
}

async function applyHostFiltersLocally(options = {}) {
  const preserveScroll = Boolean(options && options.preserveScroll);
  const hostList = document.getElementById("hostList");
  const previousScrollTop = hostList ? hostList.scrollTop : 0;
  const hosts = Array.isArray(state.hosts) ? state.hosts : [];

  const { visibleHosts, hiddenHosts } = splitHosts(hosts);
  const orderedHosts = [...visibleHosts, ...hiddenHosts];
  state.hostFilterNoMatches = hosts.length > 0 && orderedHosts.length === 0 && hasActiveHostFilters();

  const selectedIdentity = asText(state.selectedHostUid, "").trim() || asText(state.selectedHost, "").trim();
  const selectedStillVisible = !selectedIdentity || orderedHosts.some((host) => resolveHostIdentity(host) === selectedIdentity);
  if (!selectedStillVisible) {
    state.selectedHost = "";
    state.selectedHostUid = "";
    state.selectedDisplayName = "";
    state.reportOffset = 0;
    loadAndRenderCustomerNotificationPanel("");
    await refreshSelectedHostPanels({ includeDatabaseLifecycle: true, includeConfigChangelog: true });
  }

  renderHosts(hosts);
  if (preserveScroll && hostList) {
    hostList.scrollTop = previousScrollTop;
  }
  updatePagerButtons();
}

function hiddenHostsToggleLabel(collapsed) {
  return collapsed ? "▸" : "▾";
}

function hiddenHostMutedAlertsToggleLabel(collapsed) {
  return collapsed ? "▸" : "▾";
}

function formatHostLastReportAge(reportUtcValue) {
  const raw = asText(reportUtcValue, "").trim();
  if (!raw || raw === "-") {
    return {
      label: "kein Report",
      statusClass: "host-last-report-dot--unknown",
      title: "Noch kein Report empfangen",
    };
  }

  const parsed = new Date(raw);
  if (Number.isNaN(parsed.getTime())) {
    return {
      label: "Zeitstempel ungueltig",
      statusClass: "host-last-report-dot--unknown",
      title: `Ungültiger Zeitstempel: ${raw}`,
    };
  }

  const nowMs = Date.now();
  const ageMinutes = Math.max(0, Math.floor((nowMs - parsed.getTime()) / 60000));

  let statusClass = "host-last-report-dot--ok";
  if (ageMinutes >= 50) {
    statusClass = "host-last-report-dot--critical";
  } else if (ageMinutes >= 20) {
    statusClass = "host-last-report-dot--warning";
  }

  let ageLabel = "gerade eben";
  if (ageMinutes >= 1440) {
    const days = Math.floor(ageMinutes / 1440);
    const remHours = Math.floor((ageMinutes % 1440) / 60);
    ageLabel = `${days}d ${remHours}h`;
  } else if (ageMinutes >= 60) {
    const hours = Math.floor(ageMinutes / 60);
    const remMinutes = ageMinutes % 60;
    ageLabel = remMinutes > 0 ? `${hours}h ${remMinutes}m` : `${hours}h`;
  } else if (ageMinutes > 0) {
    ageLabel = `${ageMinutes} Min.`;
  }

  const exactText = formatUtcPlus2(raw);
  return {
    label: `Report vor ${ageLabel}`,
    statusClass,
    title: `Letzter Report: ${exactText}`,
  };
}

function formatHostLastReportClock(reportUtcValue) {
  const raw = asText(reportUtcValue, "").trim();
  if (!raw || raw === "-") {
    return {
      label: "--:--",
      title: "Noch kein Report empfangen",
    };
  }

  const parsed = new Date(raw);
  if (Number.isNaN(parsed.getTime())) {
    return {
      label: "--:--",
      title: `Ungültiger Zeitstempel: ${raw}`,
    };
  }

  const timeLabel = parsed.toLocaleTimeString("de-CH", {
    hour: "2-digit",
    minute: "2-digit",
  });

  return {
    label: timeLabel,
    title: `Letzter Report: ${formatUtcPlus2(raw)}`,
  };
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

    const signature = Object.keys(grouped)
      .sort((a, b) => a.localeCompare(b))
      .map((hostname) => {
        const mountpoints = grouped[hostname].map((item) => String(item.mountpoint || "")).join(",");
        return `${hostname}:${mountpoints}`;
      })
      .join("|");
    const changed = signature !== state.mutedAlertsSignature;
    state.mutedAlertsByHost = grouped;
    state.mutedAlertsSignature = signature;
    return changed;
  } catch (_error) {
    // Keep host list usable even if the mutes endpoint is temporarily unavailable.
    const changed = state.mutedAlertsSignature !== "" || Object.keys(state.mutedAlertsByHost || {}).length > 0;
    state.mutedAlertsByHost = {};
    state.mutedAlertsSignature = "";
    return changed;
  }
}

function renderSingleHostCard(host) {
  const hostname = asText(host.hostname);
  const hostIdentity = resolveHostIdentity(host);
  const displayName = asText(host.display_name || host.hostname);
  const selectedClass = hostIdentity === (state.selectedHostUid || state.selectedHost) ? "host-item selected" : "host-item";
  const openAlertCount = Number(host.open_alert_count || 0);
  const hasOpenAlerts = openAlertCount > 0;
  const isFavorite = Boolean(host.is_favorite);
  const isHidden = Boolean(host.is_hidden);
  const isTemporaryIdentity = isTemporaryHostIdentity(host);
  const environmentType = asText(host.environment_type, "").trim().toLowerCase();
  const envCardClass = environmentType === "prod" ? " host-item--env-prod" : "";
  const hiddenClass = isHidden ? " host-item-hidden" : "";
  const favoriteClass = isFavorite ? " host-item-favorite" : "";
  const temporaryClass = isTemporaryIdentity ? " host-item-temporary" : "";

  const osIconInfo = resolveHostOsIcon(host.os);
  const countryCode = asText(host.country_code || "", "").toUpperCase();
  const countryCodeLower = countryCode.toLowerCase();
  const iconName = osIconInfo.iconName;
  const osLabel = osIconInfo.osLabel;
  const osIcon = `<img src="icons/${iconName}" class="host-os-icon host-os-icon--inline" alt="${osLabel}" title="${escapeHtml(asText(host.os))}" onerror="if(!this.dataset.fallback){this.dataset.fallback='1';this.src='/icons/${iconName}';}">`;
  const flagIcon = countryCode
    ? `<img src="icons/${countryCode}.png" class="host-flag-icon host-flag-icon--inline" alt="${countryCode}" title="Land: ${countryCode}" onerror="if(!this.dataset.fallback1){this.dataset.fallback1='1';this.src='/icons/${countryCode}.png';return;}if(!this.dataset.fallback2){this.dataset.fallback2='1';this.src='/icons/${countryCodeLower}.png';return;}if(!this.dataset.fallback3){this.dataset.fallback3='1';this.src='/icons/${countryCodeLower}.svg';return;}this.style.display='none'">`
    : "";
  const mutedAlerts = Array.isArray(state.mutedAlertsByHost[hostname]) ? state.mutedAlertsByHost[hostname] : [];
  const hasMutedAlerts = mutedAlerts.length > 0;
  const mutedCollapsed = state.hiddenHostMutedAlertsCollapsed[hostname] !== false;
  const mutedBodyClass = mutedCollapsed ? "hidden" : "";
  const cleanHostValue = (value) => {
    const text = asText(value, "").trim();
    return text === "-" ? "" : text;
  };
  const sapReleaseRaw = cleanHostValue(host.sap_release || host.sap_feature_pack || "");
  const sapVersionInfo = parseSapB1Version(sapReleaseRaw);
  const sapFeaturePack = cleanHostValue(
    sapVersionInfo.mapping?.featurePack
      || (sapReleaseRaw.toUpperCase().startsWith("FP") ? sapReleaseRaw : "")
      || sapReleaseRaw
  );
  const hanaReleaseRaw = cleanHostValue(host.hana_release || host.hana_version || "");
  const hanaReleaseValue = hanaReleaseRaw
    ? hanaReleaseRaw.split(".").slice(0, 3).join(".") || hanaReleaseRaw
    : "";
  const hanaSidValue = cleanHostValue(host.hana_sid || "");
  const customerNameValue = cleanHostValue(host.customer_name || "");
  const customerProjectValue = cleanHostValue(host.customer_maringo_project_number || "");
  const customerLogoUrl = asText(host.customer_logo_url || "", "").trim();
  const customerChipLabel = customerProjectValue
    ? `${customerNameValue} · ${customerProjectValue}`
    : customerNameValue;
  const shortHostname = hostname.split(".")[0];
  const hostCardIp = asText(host.std_nic_ip || host.primary_ip);
  const hostDesignationLabel = cleanHostValue(displayName || shortHostname) || shortHostname;
  const valueChipStack = [
    sapFeaturePack
      ? `<span class="host-value-chip host-value-chip--sap" title="SAP Feature Pack">${escapeHtml(sapFeaturePack)}</span>`
      : "",
    hanaReleaseValue
      ? `<span class="host-value-chip host-value-chip--hana" title="HANA Release: ${escapeHtml(hanaReleaseRaw)}">${escapeHtml(hanaReleaseValue)}</span>`
      : "",
    hanaSidValue
      ? `<span class="host-value-chip host-value-chip--sid" title="HANA SID">${escapeHtml(hanaSidValue)}</span>`
      : "",
  ].filter(Boolean).join("");
  const lastReportInfo = formatHostLastReportAge(host.last_report_utc || host.last_seen_utc);
  const lastReportClock = formatHostLastReportClock(host.last_report_utc || host.last_seen_utc);
  const statusPulseClass = lastReportInfo.statusClass === "host-last-report-dot--critical"
    ? "host-status-pulse host-status-pulse--critical"
    : lastReportInfo.statusClass === "host-last-report-dot--warning"
      ? "host-status-pulse host-status-pulse--warning"
      : lastReportInfo.statusClass === "host-last-report-dot--ok"
        ? "host-status-pulse host-status-pulse--ok"
        : "host-status-pulse host-status-pulse--unknown";

  const latestAgentVersion = asText(state.latestAgentRelease || "", "").trim();
  const hostAgentVersion = asText(host.agent_version || "", "").trim();
  const versionCompare = compareSemverLike(hostAgentVersion, latestAgentVersion);
  const lagInfo = getAgentVersionLagInfo(latestAgentVersion, hostAgentVersion);
  const lagSteps = Number(lagInfo?.steps || 0);

  let versionSideBarClass = "host-version-side-bar host-version-side-bar--unknown";
  let versionSideBarText = "Version nicht vergleichbar.";

  if (versionCompare !== null) {
    if (versionCompare >= 0) {
      versionSideBarClass = "host-version-side-bar host-version-side-bar--ok";
      versionSideBarText = "Agent-Version ist aktuell.";
    } else if (lagInfo?.majorMinorDifferent || lagSteps >= 5) {
      versionSideBarClass = "host-version-side-bar host-version-side-bar--critical";
      versionSideBarText = "Agent-Version hat grossen Rueckstand (>= 5 oder Major/Minor abweichend).";
    } else {
      versionSideBarClass = "host-version-side-bar host-version-side-bar--warning";
      versionSideBarText = "Agent-Version hat Rueckstand (>= 1).";
    }
  }

  const versionSideBarTitle = `Version Host ${hostAgentVersion || "-"} vs Repo ${latestAgentVersion || "-"} | ${versionSideBarText}`;
  const versionSideBarHtml = `<div class="${versionSideBarClass}" title="${escapeHtml(versionSideBarTitle)}" aria-hidden="true"></div>`;
  const hasSapLicenseInfo = Boolean(host.has_sap_license_info);
  const licenseDotHtml = hasSapLicenseInfo
    ? `<button type="button" class="host-license-dot host-license-info-badge" data-host-license-host="${escapeHtml(hostname)}" data-host-license-uid="${escapeHtml(hostIdentity)}" title="SAP-Lizenzdatei (B01.txt) hinterlegt — Klicken für Lizenzinfos" aria-label="Lizenzdatei vorhanden"></button>`
    : "";
  const countryCodeHtml = /^[A-Z]{2}$/.test(countryCode)
    ? `<span class="host-card-country-code">${escapeHtml(countryCode)}</span>`
    : "";
  const cornerIcons = "";
  const customerTitleLine = customerNameValue
    ? `<div class="host-customer-title-line"><span class="host-customer-row host-customer-row--top"><span class="host-customer-line" title="Kunde${customerProjectValue ? ` · Maringo ${escapeHtml(customerProjectValue)}` : ""}">${escapeHtml(customerChipLabel)}</span></span></div>`
    : "";
  const customerCardWatermark = "";
  const designationBadgeLine = `<div class="host-designation-row"><span class="host-detail-line">${escapeHtml(hostDesignationLabel)}</span><span class="host-detail-clock" title="${escapeHtml(lastReportClock.title)}">${escapeHtml(lastReportClock.label)}</span></div>`;

  const sapRawForDebug = asText(host.sap_release || host.sap_feature_pack || "", "").trim();
  const hanaRawForDebug = asText(host.hana_release || host.hana_version || "", "").trim();
  const sidRawForDebug = asText(host.hana_sid || "", "").trim();
  const hasRawChipCandidate = [sapRawForDebug, hanaRawForDebug, sidRawForDebug].some((value) => value && value !== "-");
  if (hasRawChipCandidate && !valueChipStack) {
    const debugKey = asText(host.hostname || "", "").trim();
    if (debugKey && !state.hostChipDebugLoggedHosts.has(debugKey)) {
      state.hostChipDebugLoggedHosts.add(debugKey);
      console.warn("[host-card-chips] Raw values present but no chips rendered", {
        hostname: debugKey,
        sap_release: sapRawForDebug,
        hana_release: hanaRawForDebug,
        hana_sid: sidRawForDebug,
      });
    }
  }

  let mutedAlertsSection = "";
  if (hasMutedAlerts) {
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
    <article class="${selectedClass}${envCardClass}${hiddenClass}${favoriteClass}${temporaryClass}" tabindex="0" role="button" data-host="${escapeHtml(hostname)}" data-host-uid="${escapeHtml(hostIdentity)}"${isTemporaryIdentity ? ' title="Temporäre Host-Identität (wenige Reports) – unten angepinnt"' : ""}>
      ${versionSideBarHtml}
      ${countryCodeHtml}
      ${cornerIcons}
      ${customerCardWatermark}
      <div class="host-card-main">
        ${customerTitleLine}
        ${designationBadgeLine}
        <div class="host-tech-line">
          <span class="host-tech-row host-tech-row--host"><span class="${statusPulseClass}" aria-hidden="true"></span>${licenseDotHtml}<span class="host-meta-v" title="${escapeHtml(shortHostname)}">${escapeHtml(shortHostname)}</span></span>
          <span class="host-tech-row host-tech-row--ip"><span class="host-meta-v" title="${escapeHtml(hostCardIp)}">${escapeHtml(hostCardIp)}</span></span>
        </div>
      </div>
      ${mutedAlertsSection}
    </article>
  `;
}

function formatSapLicenseExpiry(value) {
  const raw = asText(value, "").trim();
  if (!raw) return "";
  if (/^\d{8}$/.test(raw)) {
    return `${raw.substring(6, 8)}.${raw.substring(4, 6)}.${raw.substring(0, 4)}`;
  }
  return raw;
}

function mapSapLicenseFocusTypes(sapLicense) {
  const rawEntries = Array.isArray(sapLicense?.focus_license_types) ? sapLicense.focus_license_types : [];
  return rawEntries
    .map((entry) => {
      const rawType = asText(entry?.license_type, "").trim();
      const count = Number.parseInt(String(entry?.count ?? 0), 10);
      if (!rawType) return null;
      const normalizedRaw = rawType.toUpperCase();
      const mapped = SAP_LICENSE_TYPE_MAP.find((mapEntry) => {
        if (!Boolean(mapEntry?.visible)) return false;
        return normalizedRaw === asText(mapEntry?.matchText, "").toUpperCase();
      });
      const displayType = asText(mapped?.displayName, "").trim();
      if (!displayType) return null;
      return {
        rawType,
        displayType,
        count: Number.isFinite(count) && count >= 0 ? count : 0,
      };
    })
    .filter(Boolean);
}

async function loadHostLicenseInfoForHover(hostname, hostUid = "") {
  const key = asText(hostUid, "").trim() || asText(hostname, "").trim();
  if (!key) {
    return { hasData: false, message: "Kein Host angegeben." };
  }
  if (hostLicenseHoverCache.has(key)) {
    return hostLicenseHoverCache.get(key);
  }

  const url = asText(hostUid, "").trim()
    ? `/api/v1/host-reports?host_uid=${encodeURIComponent(asText(hostUid, "").trim())}&limit=1&offset=0&include_meta=0`
    : `/api/v1/host-reports?hostname=${encodeURIComponent(asText(hostname, "").trim())}&limit=1&offset=0&include_meta=0`;
  const response = await fetch(url, { credentials: "same-origin" });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  const data = await response.json().catch(() => ({}));
  const reports = Array.isArray(data?.reports) ? data.reports : [];
  const payload = reports.length > 0 && reports[0] && typeof reports[0].payload === "object" ? reports[0].payload : {};
  const sapLicense = payload && typeof payload.sap_license === "object" ? payload.sap_license : null;
  if (!sapLicense) {
    const result = { hasData: false, message: "Keine SAP Lizenzinfos verfügbar." };
    hostLicenseHoverCache.set(key, result);
    return result;
  }

  const fields = {
    hw: asText(sapLicense.hardware_key, "").trim(),
    inst: asText(sapLicense.instno, "").trim(),
    system: asText(sapLicense.system_nr, "").trim(),
    systemType: asText(sapLicense.system_type, "").trim(),
    customerNo: asText(sapLicense.customer_no, "").trim(),
    holder: asText(sapLicense.customer_name, "").trim(),
    expiry: formatSapLicenseExpiry(sapLicense.expiration),
    b01FileMtimeRaw: asText(sapLicense.file_mtime_utc, "").trim(),
  };
  const b01FileMtimeFormatted = fields.b01FileMtimeRaw ? formatUtcPlus2(fields.b01FileMtimeRaw) : "";
  const types = mapSapLicenseFocusTypes(sapLicense);
  const hasCore = [
    fields.hw,
    fields.inst,
    fields.system,
    fields.systemType,
    fields.customerNo,
    fields.holder,
    fields.expiry,
    b01FileMtimeFormatted,
  ].some((value) => Boolean(value));
  const hasData = hasCore || types.length > 0;

  const copyLines = [
    `HW-Key: ${fields.hw || "-"}`,
    `Installationsnummer: ${fields.inst || "-"}`,
    `Systemnummer: ${fields.system || "-"}`,
    `Systemtyp: ${fields.systemType || "-"}`,
    `Kundennummer: ${fields.customerNo || "-"}`,
    `Lizenznehmer: ${fields.holder || "-"}`,
    `Gültig bis: ${fields.expiry || "-"}`,
    `B01.txt Stand: ${b01FileMtimeFormatted || "-"}`,
  ];
  if (types.length > 0) {
    copyLines.push("");
    copyLines.push("Lizenztypen:");
    for (const item of types) {
      copyLines.push(`${String(item.count)}  ${item.displayType} (${item.rawType})`);
    }
  }

  const result = {
    hasData,
    message: hasData ? "" : "Keine SAP Lizenzinfos verfügbar.",
    fields,
    types,
    copyText: copyLines.join("\n"),
  };
  hostLicenseHoverCache.set(key, result);
  return result;
}

function ensureHostLicenseHoverPopup() {
  if (hostLicenseHoverPopupEl) {
    return hostLicenseHoverPopupEl;
  }
  const popup = document.createElement("div");
  popup.id = "hostLicenseHoverPopup";
  popup.className = "host-license-hover-popup hidden";
  popup.innerHTML = "<p class=\"muted\">Lade Lizenzinfos…</p>";
  popup.addEventListener("click", async (event) => {
    const button = event.target instanceof Element ? event.target.closest("[data-host-license-copy]") : null;
    if (!button) return;
    event.preventDefault();
    event.stopPropagation();
    const text = asText(button.getAttribute("data-host-license-copy"), "").trim();
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      const original = button.textContent;
      button.textContent = "✅ Kopiert";
      setTimeout(() => { button.textContent = original; }, 1200);
    } catch {
      button.textContent = "❌ Fehler";
      setTimeout(() => { button.textContent = "📋 Kopieren"; }, 1200);
    }
  });
  document.body.appendChild(popup);
  hostLicenseHoverPopupEl = popup;
  return popup;
}

function positionHostLicenseHoverPopup() {
  if (!hostLicenseHoverPopupEl) {
    return;
  }
  const popup = hostLicenseHoverPopupEl;
  const margin = 16;
  const width = popup.offsetWidth || popup.getBoundingClientRect().width;
  const height = popup.offsetHeight || popup.getBoundingClientRect().height;
  const left = Math.max(margin, (window.innerWidth - width) / 2);
  const top = Math.max(margin, (window.innerHeight - height) / 2);
  popup.style.left = `${Math.round(left)}px`;
  popup.style.top = `${Math.round(top)}px`;
}

function hideHostLicenseHoverPopup(clearPin = true) {
  if (hostLicenseHoverPopupEl) {
    hostLicenseHoverPopupEl.classList.add("hidden");
  }
  hostLicenseHoverActiveHost = "";
  if (clearPin) {
    hostLicenseHoverPinnedKey = "";
  }
}

function toggleHostLicensePopupFromBadge(licenseBadge) {
  if (!licenseBadge) {
    return;
  }
  const hostAttr = asText(licenseBadge.getAttribute("data-host-license-host"), "").trim();
  const uidAttr = asText(licenseBadge.getAttribute("data-host-license-uid"), "").trim();
  const activeKey = uidAttr || hostAttr;
  if (!hostAttr || !activeKey) {
    return;
  }
  if (hostLicenseHoverPopupEl && !hostLicenseHoverPopupEl.classList.contains("hidden") && hostLicenseHoverActiveHost === activeKey) {
    hideHostLicenseHoverPopup(true);
    return;
  }
  hostLicenseSuppressOutsideCloseUntil = Date.now() + 500;
  void showHostLicenseHoverPopup(licenseBadge, hostAttr, uidAttr);
}

function ensureHostLicenseOutsideClickHandler() {
  if (hostLicenseOutsideClickWired) {
    return;
  }
  hostLicenseOutsideClickWired = true;
  document.addEventListener("click", (event) => {
    if (Date.now() < hostLicenseSuppressOutsideCloseUntil) {
      return;
    }
    if (!hostLicenseHoverPinnedKey || !hostLicenseHoverPopupEl || hostLicenseHoverPopupEl.classList.contains("hidden")) {
      return;
    }
    const target = event.target instanceof Element ? event.target : null;
    if (!target) {
      return;
    }
    if (target.closest(".host-license-info-badge, #hostLicenseHoverPopup, #hostContextMenu")) {
      return;
    }
    hideHostLicenseHoverPopup(true);
  });
  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape" || !hostLicenseHoverPinnedKey) {
      return;
    }
    hideHostLicenseHoverPopup(true);
  });
  window.addEventListener("resize", () => {
    if (!hostLicenseHoverPopupEl || hostLicenseHoverPopupEl.classList.contains("hidden")) {
      return;
    }
    positionHostLicenseHoverPopup();
  });
}

function renderHostLicensePopupHostIdHtml(hostKey) {
  const key = asText(hostKey, "").trim() || "-";
  return `<span class="host-license-hover-host-id">${renderTruncatedHostnameHtml(key, { maxLen: 22 })}</span>`;
}

function renderHostLicenseHoverPopupContent(hostname, data) {
  if (!data?.hasData) {
    return `<div class="host-license-hover-head"><strong>ℹ️ SAP Lizenzinfos</strong>${renderHostLicensePopupHostIdHtml(hostname)}</div><p class="muted">${escapeHtml(data?.message || "Keine SAP Lizenzinfos verfügbar.")}</p>`;
  }
  const f = data.fields || {};
  const rows = [
    ["HW-Key", f.hw || "-", ""],
    ["Instno", f.inst || "-", ""],
    ["System", f.system || "-", ""],
    ["Systemtyp", f.systemType || "-", ""],
    ["Kundnr", f.customerNo || "-", ""],
    ["Inhaber", f.holder || "-", "host-license-hover-item--holder"],
    ["Gültig bis", f.expiry || "-", ""],
  ].map(([label, value, modifierClass]) => `<div class="host-license-hover-item ${modifierClass}"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`).join("");

  const types = Array.isArray(data.types) ? data.types : [];
  const typesHtml = types.length === 0
    ? ""
    : `<div class="host-license-hover-types"><div class="host-license-hover-types-head"><span class="host-license-hover-type-name-label">Lizenztyp</span><span class="host-license-hover-type-count-label">Anzahl</span></div>${types
      .map((item) => `<div class="host-license-hover-type-row"><span class="host-license-hover-type-name-wrap"><span class="host-license-hover-type-name">${escapeHtml(item.displayType)}</span><span class=\"host-license-hover-type-raw\">(${escapeHtml(item.rawType)})</span></span><span class=\"host-license-hover-type-count\">${String(item.count)}</span></div>`)
      .join("")}</div>`;
  const b01FileMtimeText = asText(f.b01FileMtimeRaw, "").trim()
    ? formatUtcPlus2(asText(f.b01FileMtimeRaw, "").trim())
    : "";
  const b01FileMetaHtml = b01FileMtimeText
    ? `<p class="host-license-hover-filemeta">B01.txt Stand: <strong>${escapeHtml(b01FileMtimeText)}</strong></p>`
    : "";

  return `
    <div class="host-license-hover-head">
      <strong>ℹ️ SAP Lizenzinfos</strong>
      ${renderHostLicensePopupHostIdHtml(hostname)}
      <button type="button" class="header-license-copy-btn" data-host-license-copy="${escapeHtml(data.copyText || "")}">📋 Kopieren</button>
    </div>
    <div class="host-license-hover-grid">${rows}</div>
    ${b01FileMetaHtml}
    ${typesHtml}
  `;
}

async function showHostLicenseHoverPopup(anchorEl, hostname, hostUid = "") {
  const key = asText(hostUid, "").trim() || asText(hostname, "").trim();
  if (!anchorEl || !key) return;
  ensureHostLicenseOutsideClickHandler();
  const popup = ensureHostLicenseHoverPopup();
  hostLicenseHoverPinnedKey = key;
  hostLicenseHoverActiveHost = key;
  popup.innerHTML = `<div class="host-license-hover-head"><strong>ℹ️ SAP Lizenzinfos</strong>${renderHostLicensePopupHostIdHtml(key)}</div><p class="muted">Lade Lizenzinfos…</p>`;
  popup.classList.remove("hidden");
  requestAnimationFrame(() => positionHostLicenseHoverPopup());

  try {
    const data = await loadHostLicenseInfoForHover(hostname, hostUid);
    if (hostLicenseHoverActiveHost !== key || !hostLicenseHoverPopupEl) {
      return;
    }
    hostLicenseHoverPopupEl.innerHTML = renderHostLicenseHoverPopupContent(key, data);
    requestAnimationFrame(() => positionHostLicenseHoverPopup());
  } catch (error) {
    if (hostLicenseHoverActiveHost !== key || !hostLicenseHoverPopupEl) {
      return;
    }
    hostLicenseHoverPopupEl.innerHTML = `<div class="host-license-hover-head"><strong>ℹ️ SAP Lizenzinfos</strong>${renderHostLicensePopupHostIdHtml(key)}</div><p class="muted">Fehler beim Laden: ${escapeHtml(error.message || "Unbekannt")}</p>`;
    requestAnimationFrame(() => positionHostLicenseHoverPopup());
  }
}

function renderApiKeyChip(host) {
  const apiKeyStatus = asText(host?.agent_api_key_status || "off").toLowerCase();
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
  return `<span class="host-apikey-chip ${apiKeyChipMod}" title="${escapeHtml(apiKeyChipTitle)}">API</span>`;
}

function renderHostOsMetaChip(host) {
  if (!host) {
    return "";
  }
  const osInfo = resolveHostOsIcon(host.os);
  const osLabel = asText(osInfo?.osLabel, "OS");
  const osTitle = asText(host.os, osLabel).trim() || osLabel;
  const iconName = asText(osInfo?.iconName, "linux.png");
  return `<span class="selected-host-meta-chip selected-host-meta-chip--os-logo" title="${escapeHtml(osTitle)}"><img src="icons/${escapeHtml(iconName)}" class="selected-host-os-logo-inline" alt="${escapeHtml(osLabel)}" onerror="if(!this.dataset.fallback){this.dataset.fallback='1';this.src='/icons/${escapeHtml(iconName)}';}"></span>`;
}

function renderHeaderFirstRowControls(host) {
  if (!host) {
    return "";
  }

  const reportCount = Number(host.report_count || 0).toLocaleString("de-DE");
  const currentReportIndex = state.currentReport ? Math.max(1, Number(state.reportOffset || 0) + 1) : 0;
  const osChip = renderHostOsMetaChip(host);
  const reportIndexChip = `<span class="selected-host-meta-chip selected-host-meta-chip--report-index" title="Aktuelle Meldung">🔔 ${currentReportIndex}</span>`;

  return `
    ${renderApiKeyChip(host)}
    ${osChip}
    ${reportIndexChip}
    <span class="selected-host-meta-chip" title="Gesendete Meldungen">📦 ${reportCount}</span>
  `;
}

function renderReportJumpHostUidChip(host) {
  return "";
}

function updateReportJumpHostUidChip(host) {
  const chipWrap = document.getElementById("reportJumpHostUidChip");
  if (!chipWrap) {
    return;
  }
  const chip = renderReportJumpHostUidChip(host);
  if (!chip) {
    chipWrap.innerHTML = "";
    chipWrap.classList.add("hidden");
    return;
  }
  chipWrap.innerHTML = chip;
  chipWrap.classList.remove("hidden");
}

function renderSelectedHostControls(host) {
  if (!host) {
    return "";
  }

  const hostname = asText(host.hostname);
  const hostUid = asText(host.host_uid || hostname);
  const isFavorite = Boolean(host.is_favorite);
  const isHidden = Boolean(host.is_hidden);

  return `
    <button class="host-mini-action visibility${isHidden ? " active" : ""}" type="button" data-action="hidden" data-host="${escapeHtml(hostname)}" data-host-uid="${escapeHtml(hostUid)}" data-current="${isHidden ? "1" : "0"}" title="${isHidden ? "Einblenden" : "Ausblenden"}">${isHidden ? "👀" : "🫣"}</button>
    <button class="host-mini-action favorite${isFavorite ? " active" : ""}" type="button" data-action="favorite" data-host="${escapeHtml(hostname)}" data-host-uid="${escapeHtml(hostUid)}" data-current="${isFavorite ? "1" : "0"}" title="Favorit umschalten">★</button>
  `;
}


function buildCustomerLogoHoverPopupHtml(logoUrl, altText = "") {
  if (!asText(logoUrl, "").trim()) {
    return "";
  }
  return `<span class="customer-logo-hover-popup" role="presentation" aria-hidden="true">
    <img src="${escapeHtml(logoUrl)}" alt="${escapeHtml(altText)}" class="customer-logo-hover-popup-img">
  </span>`;
}

function positionCustomerLogoHoverPopup(wrap, popup) {
  if (!wrap || !popup) {
    return;
  }
  const rect = wrap.getBoundingClientRect();
  const popupWidth = 300;
  const popupHeight = 132;
  let left = rect.left + (rect.width / 2) - (popupWidth / 2);
  let top = rect.top - popupHeight - 10;
  if (top < 8) {
    top = rect.bottom + 10;
    popup.classList.add("is-below");
  } else {
    popup.classList.remove("is-below");
  }
  left = Math.max(8, Math.min(left, window.innerWidth - popupWidth - 8));
  top = Math.max(8, Math.min(top, window.innerHeight - popupHeight - 8));
  popup.style.left = `${left}px`;
  popup.style.top = `${top}px`;
}

function wireCustomerLogoHoverPopup(wrap) {
  if (!wrap || wrap.dataset.customerLogoPopupWired === "1") {
    return;
  }
  const popup = wrap.querySelector(".customer-logo-hover-popup");
  if (!popup) {
    return;
  }
  wrap.dataset.customerLogoPopupWired = "1";
  wrap.classList.add("customer-logo-hover-target");
  if (!wrap.hasAttribute("tabindex")) {
    wrap.setAttribute("tabindex", "0");
  }

  const show = () => {
    positionCustomerLogoHoverPopup(wrap, popup);
    popup.classList.add("is-visible");
    popup.setAttribute("aria-hidden", "false");
  };
  const hide = () => {
    popup.classList.remove("is-visible");
    popup.setAttribute("aria-hidden", "true");
  };

  wrap.addEventListener("mouseenter", show);
  wrap.addEventListener("mouseleave", hide);
  wrap.addEventListener("focusin", show);
  wrap.addEventListener("focusout", (event) => {
    if (!wrap.contains(event.relatedTarget)) {
      hide();
    }
  });
}

function renderSelectedHostCustomerChip(host) {
  if (!host) {
    return "";
  }
  const customerName = asText(host.customer_name || "", "").trim();
  const customerProject = asText(host.customer_maringo_project_number || "", "").trim();
  const customerLogoUrl = asText(host.customer_logo_url || "", "").trim();
  const hostLabelRaw = asText(host.display_name || host.hostname || "Host", "Host").trim() || "Host";
  const environmentType = asText(host.environment_type, "").trim().toLowerCase();
  const envLabel = environmentType === "prod"
    ? "Prod."
    : environmentType === "test"
      ? "Test"
      : "";
  const hasCustomerLogo = Boolean(customerLogoUrl);
  const envChipFloatingClass = hasCustomerLogo ? " selected-host-meta-chip--env-floating" : "";
  const envChip = envLabel
    ? `<span class="selected-host-meta-chip selected-host-meta-chip--env selected-host-meta-chip--env-inline${envChipFloatingClass} selected-host-meta-chip--env-${escapeHtml(environmentType)}" title="Host-Umgebung">${escapeHtml(envLabel)}</span>`
    : "";
  const customerLabel = customerName
    ? (customerProject ? `${customerName} · ${customerProject}` : customerName)
    : "Kein Kunde";
  const customerTitle = customerName && customerProject
    ? `Kunde · Maringo ${customerProject}`
    : (customerName ? "Kunde" : "Kein Kunde hinterlegt");
  const customerLogoHtml = customerLogoUrl
    ? `<span class="selected-host-customer-logo-wrap">
        <img src="${escapeHtml(customerLogoUrl)}" alt="Logo ${escapeHtml(customerLabel)}" class="selected-host-customer-logo" onerror="this.closest('.selected-host-customer-logo-wrap').style.display='none'">
        ${buildCustomerLogoHoverPopupHtml(customerLogoUrl, `Logo ${customerLabel}`)}
      </span>`
    : "";
  const cardBodyClass = customerLogoHtml
    ? "selected-host-meta-card-body selected-host-meta-card-body--with-logo"
    : "selected-host-meta-card-body";
  return `<span class="selected-host-meta-card" title="${escapeHtml(customerTitle)}">
    <span class="${cardBodyClass}">
      <span class="selected-host-meta-card-copy">
        <strong class="selected-host-meta-card-main"><span class="selected-host-customer-main-row"><span class="selected-host-customer-main-text">${escapeHtml(customerLabel)}</span></span></strong>
        <span class="selected-host-meta-card-sub-row">
          <span class="selected-host-meta-card-sub">Name: ${escapeHtml(hostLabelRaw)}</span>
          ${hasCustomerLogo ? "" : envChip}
        </span>
      </span>
      ${hasCustomerLogo ? envChip : ""}
      ${customerLogoHtml}
    </span>
  </span>`;
}

function renderSelectedHostPlaceholderChip() {
  return `<span class="selected-host-meta-card selected-host-meta-card--placeholder" title="Kein Host gewählt">
    <strong class="selected-host-meta-card-placeholder-text">Host auswählen ...</strong>
  </span>`;
}

function metricBarFillClass(percent) {
  const value = Number(percent);
  if (!Number.isFinite(value)) {
    return "metric-bar-fill--low";
  }
  if (value >= 85) {
    return "metric-bar-fill--high";
  }
  if (value >= 70) {
    return "metric-bar-fill--mid";
  }
  return "metric-bar-fill--low";
}

function renderMetricBarRow(label, percent, sublineHtml = "") {
  const numeric = Number(percent);
  const width = Number.isFinite(numeric) ? Math.min(100, Math.max(0, numeric)) : 0;
  const fillClass = metricBarFillClass(numeric);
  const subline = asText(sublineHtml, "").trim()
    ? `<div class="metric-row" style="border:0;padding-top:4px">${sublineHtml}</div>`
    : "";
  return `
    <div class="metric-bar-row">
      <div class="metric-bar-head"><span>${escapeHtml(label)}</span><span>${escapeHtml(formatPercent(numeric))}</span></div>
      <div class="metric-bar-track"><div class="metric-bar-fill ${fillClass}" style="width:${width}%"></div></div>
      ${subline}
    </div>
  `;
}

function updateReportChromeBar() {
  const titleEl = document.getElementById("reportChromeTitle");
  const envEl = document.getElementById("reportChromeEnv");
  const dateEl = document.getElementById("reportChromeDate");
  const logoWrap = document.getElementById("reportChromeLogoWrap");
  const logoImg = document.getElementById("reportChromeLogo");
  const logoPopupImg = document.getElementById("reportChromeLogoPopupImg");
  if (!titleEl) {
    return;
  }

  const host = getSelectedHostRecord();
  if (!host) {
    titleEl.innerHTML = '<span class="report-chrome-placeholder">Host auswählen …</span>';
    if (envEl) {
      envEl.textContent = "";
      envEl.classList.add("hidden");
    }
    if (dateEl) {
      dateEl.textContent = "";
    }
    if (logoWrap) {
      logoWrap.classList.add("hidden");
    }
    if (logoImg) {
      logoImg.removeAttribute("src");
      logoImg.alt = "";
    }
    return;
  }

  const customerName = asText(host.customer_name, "").trim();
  const displayName = asText(host.display_name || host.hostname, "").trim();
  const customerPart = customerName || "Kein Kunde";
  const customerLogoUrl = asText(host.customer_logo_url, "").trim();
  titleEl.innerHTML = `<span class="report-chrome-customer">${escapeHtml(customerPart)}</span><span class="sep" aria-hidden="true">|</span><span class="report-chrome-host">${escapeHtml(displayName)}</span>`;

  if (logoWrap && logoImg) {
    if (customerLogoUrl) {
      logoImg.src = customerLogoUrl;
      logoImg.alt = `Logo ${customerPart}`;
      logoImg.removeAttribute("title");
      if (logoPopupImg) {
        logoPopupImg.src = customerLogoUrl;
        logoPopupImg.alt = `Logo ${customerPart}`;
      }
      logoImg.onerror = function onReportChromeLogoError() {
        logoWrap.classList.add("hidden");
      };
      logoWrap.classList.remove("hidden");
      logoWrap.removeAttribute("aria-hidden");
      wireCustomerLogoHoverPopup(logoWrap);
    } else {
      logoImg.removeAttribute("src");
      logoImg.alt = "";
      if (logoPopupImg) {
        logoPopupImg.removeAttribute("src");
        logoPopupImg.alt = "";
      }
      logoWrap.classList.add("hidden");
      logoWrap.setAttribute("aria-hidden", "true");
    }
  }

  const environmentType = asText(host.environment_type, "").trim().toLowerCase();
  if (envEl) {
    if (environmentType === "prod" || environmentType === "test") {
      envEl.textContent = environmentType === "prod" ? "PROD" : "TEST";
      envEl.classList.remove("hidden");
      envEl.classList.toggle("env-prod", environmentType === "prod");
    } else {
      envEl.textContent = "";
      envEl.classList.add("hidden");
      envEl.classList.remove("env-prod");
    }
  }

  if (dateEl) {
    const report = state.currentReport;
    const payload = report && typeof report.payload === "object" ? report.payload : {};
    const ts = formatUtcPlus2(report?.received_at_utc || payload.timestamp_utc || host.last_report_utc || "");
    dateEl.textContent = ts && ts !== "-" ? ts.replace(",", " ·") : "";
  }
}

function renderOverviewHostMetrics() {
  const container = document.getElementById("overviewHostMetrics");
  if (!container) {
    return;
  }

  const host = getSelectedHostRecord();
  if (!host) {
    container.innerHTML = "";
    return;
  }

  const report = state.currentReport;
  const payload = report && typeof report.payload === "object" ? report.payload : {};
  const cpu = payload.cpu || {};
  const memory = payload.memory || {};
  const swap = payload.swap || {};
  const network = payload.network || {};
  const cpuCores = Number(cpu.cores ?? cpu.core_count ?? cpu.logical_cores ?? payload.cpu_cores);
  const cpuModelName = asText(cpu.model_name || cpu.model || cpu.name || payload.cpu_model_name || "-");
  const defaultNicIpv4 = resolveDefaultNicIpv4(report, payload, network);
  const deliveryMode = asText(report?.delivery_mode || payload.delivery_mode || "live", "live").toLowerCase();
  const deliveryLabel = deliveryMode === "delayed" ? "DELAYED" : "LIVE";
  const reportTimestamp = formatUtcPlus2(report?.received_at_utc || payload.timestamp_utc || host.last_report_utc || "");
  const sapReleaseRaw = asText(
    payload.sap_release || payload.sap_feature_pack || host.sap_release || host.sap_feature_pack || "",
  ).trim();
  const sapVersionInfo = parseSapB1Version(sapReleaseRaw);
  const sapChip = asText(
    sapVersionInfo.mapping?.featurePack
      || (sapReleaseRaw.toUpperCase().startsWith("FP") ? sapReleaseRaw : "")
      || sapReleaseRaw
      || "-",
  );
  const hanaVersionRaw = asText(
    payload.hana_release || payload.hana_version || host.hana_release || host.hana_version || "",
  ).trim();
  const hanaChip = hanaVersionRaw ? (hanaVersionRaw.split(".").slice(0, 3).join(".") || hanaVersionRaw) : "-";
  const hanaSidChip = asText(payload.hana_sid || host.hana_sid || "", "-");
  const hostname = asText(host.hostname, "-");
  const hostUid = asText(host.host_uid, "").trim();
  const countryCode = normalizeHostCountryCode(host) || "-";
  const envLabel = asText(host.environment_type, "").trim().toUpperCase() || "-";
  const customerProject = asText(host.customer_maringo_project_number, "").trim();
  const customerLabel = asText(host.customer_name, "Kein Kunde");
  const displayLabel = asText(host.display_name || hostname, hostname);
  const totalReports = Number.isFinite(Number(host.report_count)) ? Number(host.report_count).toLocaleString("de-CH") : "-";
  const primaryIp = asText(report?.primary_ip || payload.primary_ip || host.primary_ip || host.std_nic_ip, "-");
  const stdNicIp = asText(defaultNicIpv4 || host.std_nic_ip, "-");
  const loadLine = `load ${formatNumber(cpu.load_avg_1, 2)} / ${formatNumber(cpu.load_avg_5, 2)} / ${formatNumber(cpu.load_avg_15, 2)}`;
  const ramSub = `${formatKilobytes(memory.used_kb)} / ${formatKilobytes(memory.total_kb)}`;
  const coresModel = `${Number.isFinite(cpuCores) && cpuCores > 0 ? String(Math.floor(cpuCores)) : "-"} · ${cpuModelName}`;

  const metricRow = (label, value, options = {}) => {
    let valueHtml = escapeHtml(asText(value, "-"));
    if (options.ellipsisFull) {
      valueHtml = renderFullValueWithEllipsisHtml(value);
    } else if (options.truncate === "hostname") {
      valueHtml = renderTruncatedHostnameHtml(value, { maxLen: options.truncateMaxLen });
    } else if (options.truncate === "uid") {
      valueHtml = renderTruncatedHostUidHtml(value);
    } else if (options.truncate) {
      valueHtml = renderTruncatedTextHtml(value);
    }
    const valueClass = options.nowrap ? " metric-value--nowrap" : "";
    return `
    <div class="metric-row">
      <span class="metric-label">${escapeHtml(label)}</span>
      <span class="metric-value${valueClass}">${valueHtml}</span>
    </div>
  `;
  };

  const sapChipsHtml = `
    <div class="overview-sap-chips">
      <div class="overview-sap-chip">SAP RELEASE<span>${escapeHtml(sapChip)}</span></div>
      <div class="overview-sap-chip">HANA RELEASE<span>${escapeHtml(hanaChip)}</span></div>
      <div class="overview-sap-chip">HANA SID<span>${escapeHtml(hanaSidChip)}</span></div>
      <div class="overview-sap-chip">LETZTE MELDUNG<span>${escapeHtml(reportTimestamp)}</span></div>
      <div class="overview-sap-chip">ZUSTELLUNG<span>${escapeHtml(deliveryLabel)}</span></div>
    </div>
  `;

  const hostIdentityRows = [
    metricRow("Kunde", customerLabel, { truncate: true }),
    metricRow("Bezeichnung", displayLabel, { truncate: true }),
    metricRow("Hostname", hostname, { ellipsisFull: true }),
    metricRow("Host-UID", hostUid, { truncate: "uid" }),
    metricRow("Land", countryCode),
    metricRow("Umgebung", envLabel),
    customerProject ? metricRow("Projekt", customerProject) : "",
    metricRow("Meldungen", totalReports),
    metricRow("Agent ID", report?.agent_id || payload.agent_id || "-", { ellipsisFull: true }),
    metricRow("Version", payload.agent_version || host.agent_version || "-"),
    metricRow("API-Key", formatAgentApiKeyStatus(payload.agent_api_key, payload.agent_config)),
    metricRow("Queue", `${queueDepthLabel(payload.queue_depth)} Dateien`),
  ].filter(Boolean).join("");

  const systemNetworkRows = [
    metricRow("OS", payload.os || host.os || "-"),
    metricRow("Kernel", payload.kernel || "-"),
    metricRow("Uptime", formatUptime(payload.uptime_seconds)),
    metricRow("Architektur", payload.architecture || payload.arch || "-"),
    metricRow("Primary IP", primaryIp, { nowrap: true }),
    metricRow("Std. NIC IP", stdNicIp, { nowrap: true }),
    metricRow("Default NIC", network.default_interface || "-"),
    metricRow("Gateway", network.default_gateway || "-", { nowrap: true }),
    metricRow("DNS", Array.isArray(network.dns_servers) ? network.dns_servers.filter(Boolean).join(", ") || "-" : asText(network.dns_servers, "-"), { nowrap: true }),
  ].join("");

  container.innerHTML = `
    ${sapChipsHtml}
    <div class="overview-metrics-grid">
      <article class="metric-card">
        <h4>Host &amp; Agent</h4>
        ${hostIdentityRows}
      </article>
      <article class="metric-card">
        <h4>System &amp; Netzwerk</h4>
        ${systemNetworkRows}
      </article>
      <article class="metric-card metric-card--wide">
        <h4>Ressourcen (aktuell)</h4>
        <div class="overview-resource-bars">
          ${renderMetricBarRow("CPU", cpu.usage_percent, `<span class="metric-label">Load Ø</span><span class="metric-value">${escapeHtml(loadLine)}</span>`)}
          ${renderMetricBarRow("RAM", memory.used_percent, `<span class="metric-label">Belegung</span><span class="metric-value">${escapeHtml(ramSub)}</span>`)}
          ${renderMetricBarRow("SWAP", swap.used_percent, `<span class="metric-label">Kerne / Modell</span><span class="metric-value">${escapeHtml(coresModel)}</span>`)}
        </div>
      </article>
    </div>
  `;
}

function updateReportCustomerChip() {
  const chipWrap = document.getElementById("reportCustomerChip");
  if (!chipWrap) {
    return;
  }
  const customerCard = chipWrap.closest(".report-customer-main-card");
  chipWrap.classList.remove("hidden");
  const selectedHost = getSelectedHostRecord();
  if ((!state.selectedHost && !state.selectedHostUid) || !selectedHost) {
    if (customerCard) {
      customerCard.classList.add("report-customer-main-card--placeholder");
    }
    chipWrap.innerHTML = renderSelectedHostPlaceholderChip();
    updateReportChromeBar();
    renderOverviewHostMetrics();
    return;
  }
  if (customerCard) {
    customerCard.classList.remove("report-customer-main-card--placeholder");
  }
  const customerChip = renderSelectedHostCustomerChip(selectedHost);
  if (!asText(customerChip, "").trim()) {
    if (customerCard) {
      customerCard.classList.add("report-customer-main-card--placeholder");
    }
    chipWrap.innerHTML = renderSelectedHostPlaceholderChip();
    return;
  }
  chipWrap.innerHTML = customerChip;
  const customerLogoWrap = chipWrap.querySelector(".selected-host-customer-logo-wrap");
  if (customerLogoWrap) {
    wireCustomerLogoHoverPopup(customerLogoWrap);
  }
  updateReportChromeBar();
  renderOverviewHostMetrics();
}

function updateReportHeaderOsLogo(host) {
  const wrap = document.getElementById("reportHeaderOsLogoWrap");
  const img = document.getElementById("reportHeaderOsLogo");
  if (!wrap || !img) {
    return;
  }

  // Operations focus: keep header center clear, OS appears as compact chip in first-row controls.
  img.removeAttribute("src");
  img.removeAttribute("title");
  img.alt = "";
  wrap.classList.add("hidden");
  return;

  if (!host) {
    img.removeAttribute("src");
    img.removeAttribute("title");
    img.alt = "";
    wrap.classList.add("hidden");
    return;
  }

  const osInfo = resolveHostOsIcon(host.os);
  const iconName = asText(osInfo.iconName, "linux.png");
  const osLabel = asText(osInfo.osLabel, "OS");
  const osTitle = asText(host.os, osLabel);
  img.src = `icons/${iconName}`;
  img.alt = osLabel;
  img.title = osTitle;
  img.onerror = function onReportHeaderLogoError() {
    if (!this.dataset.fallback) {
      this.dataset.fallback = "1";
      this.src = `/icons/${iconName}`;
      return;
    }
    this.onerror = null;
    this.style.display = "none";
    wrap.classList.add("hidden");
  };
  img.style.display = "block";
  wrap.classList.remove("hidden");
}

function wireHostActionButtons(root) {
  if (!root) {
    return;
  }

  for (const button of root.querySelectorAll(".host-mini-action[data-action]")) {
    button.addEventListener("click", async (event) => {
      event.preventDefault();
      event.stopPropagation();

      const hostname = button.getAttribute("data-host") || "";
      const hostUid = button.getAttribute("data-host-uid") || "";
      const action = button.getAttribute("data-action") || "";
      const current = button.getAttribute("data-current") === "1";
      if (!hostname || !action) {
        return;
      }

      try {
        if (action === "favorite") {
          await saveHostSettings(hostname, { is_favorite: !current }, hostUid);
        } else if (action === "hidden") {
          await saveHostSettings(hostname, { is_hidden: !current }, hostUid);
        }

        await loadHosts();
        await refreshSelectedHostPanels();
      } catch (error) {
        window.alert(`Host-Einstellung konnte nicht gespeichert werden: ${error.message}`);
      }
    });
  }
}

function updateHeaderFirstRowControls() {
  const container = document.getElementById("headerFirstRowControls");
  if (!container) {
    return;
  }

  const selectedHost = getSelectedHostRecord();

  if (!selectedHost) {
    container.innerHTML = "";
    container.classList.add("hidden");
    return;
  }

  container.innerHTML = renderHeaderFirstRowControls(selectedHost);
  container.classList.remove("hidden");
}

function updateReportControlsCardState(selectedHost) {
  const controlsCard = document.querySelector(".reports-column .section-head .report-controls-card");
  if (!controlsCard) {
    return;
  }
  const chipsRow = controlsCard.querySelector(".report-controls-row--chips");
  const actionsRow = controlsCard.querySelector(".report-controls-row--actions");
  if (selectedHost) {
    controlsCard.classList.add("report-controls-card--active");
    controlsCard.classList.remove("report-controls-card--empty");
    if (chipsRow) {
      chipsRow.classList.remove("hidden");
    }
    if (actionsRow) {
      actionsRow.classList.remove("hidden");
    }
    return;
  }
  controlsCard.classList.add("report-controls-card--empty");
  controlsCard.classList.remove("report-controls-card--active");
  if (chipsRow) {
    chipsRow.classList.add("hidden");
  }
  if (actionsRow) {
    actionsRow.classList.add("hidden");
  }
}

function updateSelectedHostControls() {
  updateHeaderFirstRowControls();

  const controls = document.getElementById("selectedHostControls");
  if (!controls) {
    return;
  }

  const selectedHost = getSelectedHostRecord();
  updateReportControlsCardState(selectedHost);

  if ((!state.selectedHost && !state.selectedHostUid) || !selectedHost) {
    controls.innerHTML = "";
    controls.classList.add("hidden");
    updateReportCustomerChip();
    updateReportHeaderOsLogo(null);
    updateReportJumpHostUidChip(null);
    return;
  }

  controls.innerHTML = renderSelectedHostControls(selectedHost);
  controls.classList.remove("hidden");
  wireHostActionButtons(controls);
  updateReportCustomerChip();
  updateReportHeaderOsLogo(selectedHost);
  updateReportJumpHostUidChip(selectedHost);
}

async function saveHostSettings(hostname, partialSettings, hostUid = "") {
  const response = await fetch("/api/v1/host-settings", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      hostname,
      host_uid: hostUid,
      ...partialSettings,
    }),
  });

  if (!response.ok) {
    throw new Error("HTTP " + response.status);
  }

  return response.json();
}

async function deleteHostCard(hostname, hostUid = "") {
  const response = await fetch("/api/v1/host-delete", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      hostname,
      host_uid: asText(hostUid, "").trim(),
    }),
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
  delete menu.dataset.hostUid;
}

function ensureHostContextMenu() {
  let menu = document.getElementById("hostContextMenu");
  if (menu) {
    if (!menu.querySelector("button[data-action='show-license']")) {
      menu.innerHTML = `
        <div class="host-context-menu-label"></div>
        <button type="button" data-action="copy-host">In Zwischenablage kopieren</button>
        <button type="button" data-action="show-license">Lizenzinfos anzeigen</button>
        <button type="button" data-action="agent-update">Agent-Update anstoßen</button>
        <button type="button" data-action="delete-host-card">Karte löschen…</button>
      `;
    }
    return menu;
  }

  menu = document.createElement("div");
  menu.id = "hostContextMenu";
  menu.className = "host-context-menu hidden";
  menu.innerHTML = `
    <div class="host-context-menu-label"></div>
    <button type="button" data-action="copy-host">In Zwischenablage kopieren</button>
    <button type="button" data-action="show-license">Lizenzinfos anzeigen</button>
    <button type="button" data-action="agent-update">Agent-Update anstoßen</button>
    <button type="button" data-action="delete-host-card">Karte löschen…</button>
  `;
  document.body.appendChild(menu);

  menu.addEventListener("click", async (event) => {
    const copyTrigger = event.target.closest("button[data-action='copy-host']");
    const licenseTrigger = event.target.closest("button[data-action='show-license']");
    const updateTrigger = event.target.closest("button[data-action='agent-update']");
    const deleteTrigger = event.target.closest("button[data-action='delete-host-card']");
    if (!copyTrigger && !licenseTrigger && !updateTrigger && !deleteTrigger) {
      return;
    }

    event.preventDefault();
    event.stopPropagation();
    const hostname = String(menu.dataset.hostname || "").trim();
    const hostUid = String(menu.dataset.hostUid || "").trim();
    closeHostContextMenu();
    if (!hostname && !hostUid) {
      return;
    }

    if (licenseTrigger) {
      const host = (Array.isArray(state.hosts) ? state.hosts : []).find((entry) => {
        const uid = asText(entry?.host_uid, "").trim();
        const name = asText(entry?.hostname, "").trim();
        return (hostUid && uid === hostUid) || (hostname && name === hostname);
      });
      const effectiveHostname = hostname || asText(host?.hostname, "").trim();
      if (!effectiveHostname && !hostUid) {
        window.alert("Kein Host angegeben.");
        return;
      }
      hostLicenseSuppressOutsideCloseUntil = Date.now() + 500;
      void showHostLicenseHoverPopup(licenseTrigger, effectiveHostname, hostUid);
      return;
    }

    if (copyTrigger) {
      const host = (Array.isArray(state.hosts) ? state.hosts : []).find((entry) => {
        const uid = asText(entry?.host_uid, "").trim();
        const name = asText(entry?.hostname, "").trim();
        return (hostUid && uid === hostUid) || (hostname && name === hostname);
      });
      const lines = [
        asText(host?.display_name || hostname, hostname),
        asText(host?.hostname, hostname),
        asText(host?.std_nic_ip || host?.primary_ip, ""),
      ].filter(Boolean);
      try {
        await navigator.clipboard.writeText(lines.join("\n"));
      } catch {
        window.prompt("Kopieren:", lines.join("\n"));
      }
      return;
    }

    if (updateTrigger) {
      if (!hostname) {
        window.alert("Agent-Update benötigt einen Hostnamen.");
        return;
      }
      try {
        await triggerAgentUpdate(hostname);
        window.alert(`Agent-Update für ${hostname} angestoßen.`);
      } catch (error) {
        window.alert(`Agent-Update fehlgeschlagen: ${error.message}`);
      }
      return;
    }

    const hostLabel = hostUid || hostname;
    const hostLabelShort = hostLabel.length > 54 ? `${hostLabel.slice(0, 51)}...` : hostLabel;

    const confirmed = window.confirm(
      `Karte für ${hostLabelShort} wirklich löschen?\n\nDas entfernt Reports, Alerts und Host-Settings dauerhaft.`
    );
    if (!confirmed) {
      return;
    }

    try {
      await deleteHostCard(hostname, hostUid);
      const selectedIdentity = asText(state.selectedHostUid, "").trim() || asText(state.selectedHost, "").trim();
      if (selectedIdentity && selectedIdentity === (hostUid || hostname)) {
        state.selectedHost = "";
        state.selectedHostUid = "";
        state.selectedDisplayName = "";
        state.currentReport = null;
        state.reportOffset = 0;
      }

      await loadHosts();
      await refreshSelectedHostPanels();
    } catch (error) {
      window.alert(`Host-Karte konnte nicht gelöscht werden: ${error.message}`);
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

function openHostContextMenu(hostname, hostUid, clientX, clientY) {
  const menu = ensureHostContextMenu();
  const normalizedHost = String(hostname || "").trim();
  const normalizedHostUid = String(hostUid || "").trim();
  if (!normalizedHost && !normalizedHostUid) {
    return;
  }
  const labelText = normalizedHostUid || normalizedHost;

  const label = menu.querySelector(".host-context-menu-label");
  if (label) {
    label.textContent = labelText;
  }
  menu.dataset.hostname = normalizedHost;
  menu.dataset.hostUid = normalizedHostUid;
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
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      hostname,
      command_type: "update-now",
      ttl_minutes: 10080,
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
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      command_type: "update-now",
      ttl_minutes: 10080,
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
    credentials: "same-origin",
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

async function downloadDatabaseBackup(onProgress) {
  const fallbackFilename = `monitoring-backup-${new Date().toISOString().replace(/[.:]/g, "-")}.db`;
  onProgress?.({ pct: null, label: "Backup-Job wird gestartet..." });
  const startResponse = await fetch("/api/v1/backup/database/start", {
    method: "GET",
    credentials: "same-origin",
  });
  const startData = await startResponse.json().catch(() => ({}));
  if (!startResponse.ok) {
    throw new Error(startData.error || ("HTTP " + startResponse.status));
  }

  const jobId = String(startData.job_id || "").trim();
  const jobToken = String(startData.job_token || "").trim();
  if (!jobId || !jobToken) {
    throw new Error("backup job start failed");
  }

  const startTs = Date.now();
  const timeoutMs = 600000;
  let transientFailures = 0;
  onProgress?.({ pct: null, label: "Datenbank wird gesichert..." });
  while (Date.now() - startTs < timeoutMs) {
    await waitMs(2000);
    const statusResponse = await fetch(
      `/api/v1/backup/database/status?job_id=${encodeURIComponent(jobId)}&job_token=${encodeURIComponent(jobToken)}`,
      {
        method: "GET",
        credentials: "same-origin",
      },
    );
    const statusData = await statusResponse.json().catch(() => ({}));
    if (!statusResponse.ok) {
      const retryableStatus = statusResponse.status === 502
        || statusResponse.status === 503
        || statusResponse.status === 404;
      if (retryableStatus && transientFailures < 90) {
        transientFailures += 1;
        const retryLabel = statusResponse.status === 404
          ? `Backup-Job wird gesucht (Server-Neustart?, ${transientFailures})...`
          : `Backup läuft (Server kurz beschäftigt, Wiederholung ${transientFailures})...`;
        onProgress?.({
          pct: null,
          label: retryLabel,
        });
        continue;
      }
      throw new Error(statusData.error || ("HTTP " + statusResponse.status));
    }
    transientFailures = 0;
    const status = String(statusData.status || "");
    if (status === "running") {
      onProgress?.({ pct: null, label: "Datenbank wird gesichert (läuft)..." });
    }
    if (status === "ready") {
      onProgress?.({ pct: 100, label: "Download wird gestartet..." });
      return triggerNativeDownload(
        `/api/v1/backup/database/download?job_id=${encodeURIComponent(jobId)}&job_token=${encodeURIComponent(jobToken)}&t=${Date.now()}`,
        String(statusData.filename || fallbackFilename),
      );
    }
    if (status === "error") {
      throw new Error(String(statusData.error || "database backup failed"));
    }
  }

  throw new Error("backup timeout nach 10 Minuten");
}

async function restoreDatabaseFromFile(file, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/v1/restore/database");
    xhr.withCredentials = true;
    xhr.setRequestHeader("Content-Type", "application/octet-stream");
    xhr.responseType = "text";

    xhr.upload.addEventListener("progress", (e) => {
      if (e.lengthComputable) {
        const pct = Math.round((e.loaded / e.total) * 90); // up to 90% for upload
        onProgress?.({ pct, label: `Upload: ${pct}% (${(e.loaded / 1024).toFixed(0)} / ${(e.total / 1024).toFixed(0)} KB)` });
      }
    });

    xhr.upload.addEventListener("load", () => {
      onProgress?.({ pct: null, label: "Datenbank wird wiederhergestellt..." });
    });

    xhr.addEventListener("load", () => {
      let json = {};
      try { json = JSON.parse(xhr.responseText); } catch (_) { /* ignore */ }
      if (xhr.status >= 200 && xhr.status < 300) {
        onProgress?.({ pct: 100, label: "Erfolgreich wiederhergestellt!" });
        resolve(json);
      } else {
        reject(new Error(json.error || ("HTTP " + xhr.status)));
      }
    });

    xhr.addEventListener("error", () => reject(new Error("Netzwerkfehler beim Upload")));
    xhr.addEventListener("abort", () => reject(new Error("Upload abgebrochen")));

    xhr.send(file);
  });
}

function formatInteger(value) {
  const num = Number(value || 0);
  if (!Number.isFinite(num)) return "0";
  return Math.round(num).toLocaleString("de-DE");
}

function setDbMaintenanceStatus(message, isError = false) {
  const el = document.getElementById("dbMaintenanceStatus");
  if (!el) return;
  el.textContent = message;
  el.classList.toggle("error", !!isError);
}

function setBackupAutomationStatus(message, isError = false) {
  const el = document.getElementById("backupAutomationStatus");
  if (!el) return;
  el.textContent = message;
  el.classList.toggle("error", !!isError);
}

function setAgentIngestQueueStatus(message, isError = false) {
  const el = document.getElementById("agentIngestQueueStatus");
  if (!el) return;
  el.textContent = message;
  el.classList.toggle("error", !!isError);
}

function setAgentIngestAuditStatus(message, isError = false) {
  const el = document.getElementById("agentIngestAuditStatus");
  if (!el) return;
  el.textContent = message;
  el.classList.toggle("error", !!isError);
}

function formatDurationCompact(seconds) {
  const total = Math.max(0, Math.floor(Number(seconds || 0)));
  const days = Math.floor(total / 86400);
  const hours = Math.floor((total % 86400) / 3600);
  const minutes = Math.floor((total % 3600) / 60);
  const secs = total % 60;
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m ${secs}s`;
  return `${secs}s`;
}

function renderAgentIngestQueueOverview(data) {
  const depthEl = document.getElementById("agentIngestQueueDepth");
  const readyEl = document.getElementById("agentIngestQueueReady");
  const retryEl = document.getElementById("agentIngestQueueRetry");
  const inFlightEl = document.getElementById("agentIngestQueueInFlight");
  const delayedEl = document.getElementById("agentIngestQueueDelayed");
  const oldestAgeEl = document.getElementById("agentIngestQueueOldestAge");
  const bodyEl = document.getElementById("agentIngestQueueErrorRows");

  if (depthEl) depthEl.textContent = formatInteger(data?.queue_depth || 0);
  if (readyEl) readyEl.textContent = formatInteger(data?.ready_count || 0);
  if (retryEl) retryEl.textContent = formatInteger(data?.retry_count || 0);
  if (inFlightEl) inFlightEl.textContent = formatInteger(data?.in_flight_count || 0);
  if (delayedEl) delayedEl.textContent = formatInteger(data?.delayed_count || 0);
  if (oldestAgeEl) {
    const ageSeconds = Number(data?.oldest_age_seconds || 0);
    oldestAgeEl.textContent = ageSeconds > 0 ? formatDurationCompact(ageSeconds) : "-";
  }

  if (!bodyEl) return;
  const recentErrors = Array.isArray(data?.recent_errors) ? data.recent_errors : [];
  if (recentErrors.length === 0) {
    bodyEl.innerHTML = '<tr><td colspan="6" class="muted">Keine Queue-Fehler vorhanden.</td></tr>';
    return;
  }

  bodyEl.innerHTML = recentErrors.map((item) => {
    const queueId = Number(item?.id || 0);
    const host = asText(item?.hostname || item?.host_uid, "-");
    const attempts = Number(item?.attempt_count || 0);
    const updatedAt = formatUtcPlus2(asText(item?.updated_at_utc, ""));
    const retryAt = formatUtcPlus2(asText(item?.next_attempt_at_utc, ""));
    const errorMsg = asText(item?.last_error, "-");
    return `
      <tr>
        <td>${escapeHtml(String(queueId || "-"))}</td>
        <td>${escapeHtml(host)}</td>
        <td>${escapeHtml(String(attempts))}</td>
        <td>${escapeHtml(updatedAt)}</td>
        <td>${escapeHtml(retryAt)}</td>
        <td class="agent-update-admin-message">${escapeHtml(errorMsg)}</td>
      </tr>
    `;
  }).join("");
}

async function loadAdminAgentIngestQueue() {
  const response = await fetch("/api/v1/admin/agent-ingest-queue?recent_limit=20", {
    method: "GET",
    credentials: "same-origin",
    cache: "no-store",
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || ("HTTP " + response.status));
  }
  renderAgentIngestQueueOverview(data);

  const oldestAge = Number(data?.oldest_age_seconds || 0);
  const nextAttemptSeconds = Number(data?.next_attempt_in_seconds || 0);
  const oldestText = oldestAge > 0 ? formatDurationCompact(oldestAge) : "-";
  const nextText = nextAttemptSeconds > 0 ? `in ${formatDurationCompact(nextAttemptSeconds)}` : "sofort";
  const pendingCount = Number(data?.pending_count || 0);
  const retryCount = Number(data?.retry_count || 0);
  setAgentIngestQueueStatus(
    `Queue: ${formatInteger(data?.queue_depth || 0)} · Neu: ${formatInteger(pendingCount)} · Retry: ${formatInteger(retryCount)} · Fällig: ${formatInteger(data?.ready_count || 0)} · Ältestes: ${oldestText} · Nächster Versuch: ${nextText}`
  );
  return data;
}

function formatLatencyMs(valueMs) {
  const ms = Math.max(0, Math.floor(Number(valueMs || 0)));
  if (ms < 1000) return `${ms} ms`;
  return formatDurationCompact(ms / 1000);
}

function renderAgentIngestAuditLog(data) {
  const bodyEl = document.getElementById("agentIngestAuditRows");
  if (!bodyEl) return;

  const entries = Array.isArray(data?.entries) ? data.entries : [];
  if (entries.length === 0) {
    bodyEl.innerHTML = '<tr><td colspan="9" class="muted">Noch keine Ingest-Lieferdaten vorhanden.</td></tr>';
    return;
  }

  bodyEl.innerHTML = entries.map((item) => {
    const queueId = Number(item?.queue_id || 0);
    const host = asText(item?.hostname || item?.host_uid, "-");
    const customerName = asText(item?.customer_name, "").trim() || "-";
    const receivedAt = formatUtcPlus2(asText(item?.report_received_at_utc, ""));
    const writtenAt = formatUtcPlus2(asText(item?.db_written_at_utc, ""));
    const payloadBytes = Number(item?.payload_bytes || 0);
    const latencyText = formatLatencyMs(item?.end_to_end_ms || 0);
    const status = asText(item?.status, "-");
    const payloadStored = !!item?.payload_stored;
    const payloadPath = asText(item?.payload_download_path, "");
    const payloadLinkHtml = payloadStored && payloadPath
      ? `<a class="backup-run-link" href="${escapeHtml(payloadPath)}" target="_blank" rel="noopener noreferrer">anzeigen</a>`
      : "-";
    return `
      <tr>
        <td>${escapeHtml(String(queueId || "-"))}</td>
        <td>${escapeHtml(host)}</td>
        <td>${escapeHtml(customerName)}</td>
        <td>${escapeHtml(receivedAt)}</td>
        <td>${escapeHtml(formatBytes(payloadBytes))}</td>
        <td>${escapeHtml(writtenAt)}</td>
        <td>${escapeHtml(latencyText)}</td>
        <td>${payloadLinkHtml}</td>
        <td>${escapeHtml(status)}</td>
      </tr>
    `;
  }).join("");
}

async function loadAdminAgentIngestAuditLog() {
  const response = await fetch("/api/v1/admin/agent-ingest-log?limit=250", {
    method: "GET",
    credentials: "same-origin",
    cache: "no-store",
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || ("HTTP " + response.status));
  }

  renderAgentIngestAuditLog(data);
  const count = Array.isArray(data?.entries) ? data.entries.length : 0;
  const mode = asText(data?.payload_capture_mode, "off");
  const payloadMode = mode === "disk" ? "Payload auf Disk" : "Payload aus";
  setAgentIngestAuditStatus(`Einträge: ${formatInteger(count)} · Limit: ${formatInteger(data?.retention_limit || 250)} · ${payloadMode}`);
  return data;
}

function renderDbMaintenanceStats(stats) {
  const el = document.getElementById("dbMaintenanceStats");
  if (!el) return;
  el.innerHTML = "";
}

function formatSignedInteger(value) {
  if (value === null || value === undefined || value === "") return "-";
  const num = Number(value);
  if (!Number.isFinite(num)) return "-";
  const rounded = Math.round(num);
  if (rounded === 0) return "0";
  return `${rounded > 0 ? "+" : "-"}${Math.abs(rounded).toLocaleString("de-DE")}`;
}

function formatSignedBytes(value) {
  if (value === null || value === undefined || value === "") return "-";
  const num = Number(value);
  if (!Number.isFinite(num)) return "-";
  if (Math.abs(num) < 1) return "0 B";
  const prefix = num > 0 ? "+" : "-";
  return `${prefix}${formatBytes(Math.abs(num))}`;
}

function deltaSignClass(value) {
  if (value === null || value === undefined || value === "") return "delta-neutral";
  const num = Number(value);
  if (!Number.isFinite(num) || Math.abs(num) < 1e-9) return "delta-neutral";
  return num > 0 ? "delta-positive" : "delta-negative";
}

function buildDbMaintenanceChartScale(values, forecast) {
  const nums = values.map((v) => Number(v || 0));
  let min = Math.min(...nums);
  let max = Math.max(...nums);
  if (forecast && Number.isFinite(Number(forecast.projected_14d))) {
    const projected = Number(forecast.projected_14d);
    min = Math.min(min, projected);
    max = Math.max(max, projected);
  }
  if (max <= min) {
    max = min + 1;
  }
  return { min, max, span: max - min };
}

function buildDbMaintenanceLineLayout(values, forecast, options = {}) {
  const width = options.width ?? 360;
  const height = options.height ?? 132;
  const padLeft = options.padLeft ?? 44;
  const padRight = options.padRight ?? 12;
  const padTop = options.padTop ?? 8;
  const padBottom = options.padBottom ?? 24;
  const { min, max, span } = buildDbMaintenanceChartScale(values, forecast);
  const toY = (v) => height - padBottom - (((Number(v) - min) / span) * (height - padTop - padBottom));
  const n = values.length;
  const xAt = (i) => padLeft + (i * ((width - padLeft - padRight) / Math.max(1, n - 1)));
  const points = values.map((v, i) => `${xAt(i).toFixed(2)},${toY(v).toFixed(2)}`).join(" ");
  return { width, height, padLeft, padRight, padTop, padBottom, min, max, span, toY, xAt, points };
}

function dbMaintenanceLast14dStartIndex(rows) {
  if (!Array.isArray(rows) || rows.length < 2) {
    return 0;
  }
  const lastIso = String(rows[rows.length - 1]?.bucket_start_utc || "").trim();
  const lastMs = Date.parse(lastIso.replace("Z", "+00:00"));
  if (!Number.isFinite(lastMs)) {
    return 0;
  }
  const cutoffMs = lastMs - (14 * 24 * 60 * 60 * 1000);
  for (let i = 0; i < rows.length; i += 1) {
    const bucketIso = String(rows[i]?.bucket_start_utc || "").trim();
    const bucketMs = Date.parse(bucketIso.replace("Z", "+00:00"));
    if (Number.isFinite(bucketMs) && bucketMs >= cutoffMs) {
      return i;
    }
  }
  return 0;
}

function computeIndexedLinearRegression(series) {
  if (!Array.isArray(series) || series.length < 2) {
    return null;
  }
  const n = series.length;
  let sumX = 0;
  let sumY = 0;
  let sumXX = 0;
  let sumXY = 0;
  for (let i = 0; i < n; i += 1) {
    const y = Number(series[i] || 0);
    sumX += i;
    sumY += y;
    sumXX += i * i;
    sumXY += i * y;
  }
  const denom = (n * sumXX) - (sumX * sumX);
  if (Math.abs(denom) < 1e-9) {
    return null;
  }
  const slope = ((n * sumXY) - (sumX * sumY)) / denom;
  const intercept = (sumY - (slope * sumX)) / n;
  return { slope, intercept };
}

function buildDbMaintenanceForecastSvg(values, forecast, line, intervalHours, rows) {
  if (!forecast || typeof forecast !== "object" || values.length < 2) {
    return "";
  }

  const n = values.length;
  const windowStart = dbMaintenanceLast14dStartIndex(rows);
  const windowValues = values.slice(windowStart);
  const regression = computeIndexedLinearRegression(windowValues);
  const parts = [];
  if (regression) {
    const yStart = line.toY(regression.intercept);
    const yEnd = line.toY(regression.slope * (windowValues.length - 1) + regression.intercept);
    parts.push(
      `<line class="db-maintenance-chart-trend" x1="${line.xAt(windowStart).toFixed(2)}" y1="${yStart.toFixed(2)}" x2="${line.xAt(n - 1).toFixed(2)}" y2="${yEnd.toFixed(2)}" />`,
    );
  }

  const lastValue = Number(values[n - 1] || 0);

  const projected = Number(forecast.projected_14d);
  if (Number.isFinite(projected)) {
    const lastX = line.xAt(n - 1);
    const extWidth = (line.width - line.padLeft - line.padRight) * 0.22;
    const extX = Math.min(line.width - line.padRight, lastX + extWidth);
    const lastY = line.toY(lastValue);
    const targetY = line.toY(projected);
    parts.push(
      `<line class="db-maintenance-chart-projection" x1="${lastX.toFixed(2)}" y1="${lastY.toFixed(2)}" x2="${extX.toFixed(2)}" y2="${targetY.toFixed(2)}" />`,
      `<line class="db-maintenance-chart-target" x1="${line.padLeft}" y1="${targetY.toFixed(2)}" x2="${(line.width - line.padRight).toFixed(2)}" y2="${targetY.toFixed(2)}" />`,
      `<text x="${(line.width - line.padRight - 2).toFixed(2)}" y="${Math.max(line.padTop + 8, targetY - 4).toFixed(2)}" text-anchor="end" class="db-maintenance-chart-target-label">Ziel</text>`,
    );
  }

  return parts.join("");
}

function dbMaintenanceChartLegendHtml(hasForecast) {
  if (!hasForecast) {
    return "";
  }
  return `<p class="db-maintenance-chart-legend"><span class="db-maintenance-legend-trend">Trend (14d)</span> · <span class="db-maintenance-legend-projection">Prognose</span> · <span class="db-maintenance-legend-target">Ziel</span></p>`;
}

function renderDbMaintenanceCharts(history, forecasts, intervalHours = 2) {
  const el = document.getElementById("dbMaintenanceCharts");
  if (!el) return;
  const rows = Array.isArray(history) ? history : [];
  if (rows.length < 2) {
    el.innerHTML = `<p class="muted">Noch zu wenige Datenpunkte für Charts. Nach dem nächsten ${escapeHtml(String(intervalHours))}h-Lauf erscheinen Verläufe.</p>`;
    return;
  }

  const chartDefs = [
    { key: "total_file_bytes", title: "DB gesamt", formatter: (v) => formatBytes(v), deltaFormatter: (v) => formatSignedBytes(v) },
    { key: "wal_file_bytes", title: "WAL", formatter: (v) => formatBytes(v), deltaFormatter: (v) => formatSignedBytes(v) },
    { key: "reports_total", title: "Reports", formatter: (v) => formatInteger(v), deltaFormatter: (v) => formatSignedInteger(v) },
    { key: "avg_payload_bytes", title: "Payload Ø", formatter: (v) => formatBytes(v), deltaFormatter: (v) => formatSignedBytes(v) },
    { key: "alerts_open", title: "Alerts offen", formatter: (v) => formatInteger(v), deltaFormatter: (v) => formatSignedInteger(v) },
    { key: "free_ratio", title: "Free Ratio", formatter: (v) => `${(Number(v || 0) * 100).toFixed(1)}%`, deltaFormatter: (v) => `${Number(v || 0) >= 0 ? "+" : "-"}${Math.abs(Number(v || 0) * 100).toFixed(2)}%` },
  ];

  const openDbMaintenanceChartDrillModal = (def) => {
    const modal = document.getElementById("chartDrillModal");
    const titleEl = document.getElementById("chartDrillTitle");
    const bodyEl = document.getElementById("chartDrillBody");
    if (!modal || !titleEl || !bodyEl) return;

    const values = rows.map((row) => Number(row?.[def.key] || 0));
    if (!values.length) return;

    const width = 900;
    const height = 320;
    const padLeft = 64;
    const padRight = 18;
    const padTop = 14;
    const padBottom = 40;
    const forecast = forecasts && typeof forecasts === "object" ? forecasts[def.key] : null;
    const line = buildDbMaintenanceLineLayout(values, forecast, { width, height, padLeft, padRight, padTop, padBottom });
    const forecastSvg = buildDbMaintenanceForecastSvg(values, forecast, line, intervalHours, rows);

    const latest = values[values.length - 1];
    const prev = values.length > 1 ? values[values.length - 2] : latest;
    const deltaWindow = latest - prev;
    const forecastText = forecast && typeof forecast === "object"
      ? `14d: ${def.deltaFormatter ? def.deltaFormatter(forecast.delta_14d) : formatSignedInteger(forecast.delta_14d)} · Ziel: ${def.formatter(forecast.projected_14d || 0)}`
      : "14d Trend: n/a";
    const ticks = [0, 0.25, 0.5, 0.75, 1];
    const gridMarkup = ticks.map((t) => {
      const y = line.padTop + ((line.height - line.padTop - line.padBottom) * t);
      const value = line.max - ((line.max - line.min) * t);
      const label = def.formatter(value);
      return `<line x1="${line.padLeft}" y1="${y.toFixed(2)}" x2="${(line.width - line.padRight).toFixed(2)}" y2="${y.toFixed(2)}" class="db-maintenance-chart-grid"></line><text x="8" y="${(y + 4).toFixed(2)}" class="db-maintenance-chart-label">${escapeHtml(String(label))}</text>`;
    }).join("");

    const firstBucketLabel = formatUtcPlus2Short(rows[0]?.bucket_start_utc || "") || "-";
    const lastBucketLabel = formatUtcPlus2Short(rows[rows.length - 1]?.bucket_start_utc || "") || "-";

    titleEl.textContent = `${asText(def.title)} (vergrößert)`;
    bodyEl.innerHTML = `
      <div class="chart-drill-svg-wrap db-chart-drill-wrap">
        <svg viewBox="0 0 ${line.width} ${line.height}" class="db-maintenance-chart-svg db-maintenance-chart-svg-drill" role="img" aria-label="${escapeHtml(def.title)} Verlauf (groß)">
          ${gridMarkup}
          <line x1="${line.padLeft}" y1="${line.height - line.padBottom}" x2="${line.width - line.padRight}" y2="${line.height - line.padBottom}" class="db-maintenance-chart-axis"></line>
          ${forecastSvg}
          <polyline points="${line.points}" class="db-maintenance-chart-line"></polyline>
          <text x="${line.padLeft}" y="${line.height - 8}" text-anchor="start" class="db-maintenance-chart-label db-maintenance-chart-label-x">${escapeHtml(firstBucketLabel)}</text>
          <text x="${line.width - line.padRight}" y="${line.height - 8}" text-anchor="end" class="db-maintenance-chart-label db-maintenance-chart-label-x">${escapeHtml(lastBucketLabel)}</text>
        </svg>
      </div>
      ${dbMaintenanceChartLegendHtml(Boolean(forecast))}
      <div class="chart-drill-stats">
        <span class="stat-chip">Aktuell: ${escapeHtml(def.formatter(latest || 0))}</span>
        <span class="stat-chip">Δ${escapeHtml(String(intervalHours))}h: ${escapeHtml(def.deltaFormatter ? def.deltaFormatter(deltaWindow) : formatSignedInteger(deltaWindow))}</span>
        <span class="stat-chip">Min: ${escapeHtml(def.formatter(line.min))}</span>
        <span class="stat-chip">Max: ${escapeHtml(def.formatter(line.max))}</span>
        <span class="stat-chip">${escapeHtml(forecastText)}</span>
      </div>
    `;

    modal.classList.remove("hidden");
  };

  const trendIndicator = (deltaValue) => {
    const n = Number(deltaValue || 0);
    if (!Number.isFinite(n) || Math.abs(n) < 1e-9) {
      return { arrow: "→", cls: "flat", label: "stabil" };
    }
    if (n > 0) {
      return { arrow: "↑", cls: "up", label: "steigend" };
    }
    return { arrow: "↓", cls: "down", label: "fallend" };
  };

  el.innerHTML = chartDefs.map((def, index) => {
    const values = rows.map((row) => Number(row?.[def.key] || 0));
    const forecast = forecasts && typeof forecasts === "object" ? forecasts[def.key] : null;
    const line = buildDbMaintenanceLineLayout(values, forecast);
    const forecastSvg = buildDbMaintenanceForecastSvg(values, forecast, line, intervalHours, rows);
    const firstBucketLabel = formatUtcPlus2Short(rows[0]?.bucket_start_utc || "") || "-";
    const lastBucketLabel = formatUtcPlus2Short(rows[rows.length - 1]?.bucket_start_utc || "") || "-";
    const latest = values[values.length - 1];
    const prev = values.length > 1 ? values[values.length - 2] : latest;
    const deltaWindow = latest - prev;
    const trend = trendIndicator(forecast?.delta_14d ?? deltaWindow);
    const forecastText = forecast && typeof forecast === "object"
      ? `14d: ${def.deltaFormatter ? def.deltaFormatter(forecast.delta_14d) : formatSignedInteger(forecast.delta_14d)} · Ziel: ${def.formatter(forecast.projected_14d || 0)}`
      : "14d Trend: n/a";
    const ticks = [0, 0.25, 0.5, 0.75, 1];
    const gridMarkup = ticks.map((t) => {
      const y = line.padTop + ((line.height - line.padTop - line.padBottom) * t);
      const value = line.max - ((line.max - line.min) * t);
      const label = def.formatter(value);
      return `<line x1="${line.padLeft}" y1="${y.toFixed(2)}" x2="${(line.width - line.padRight).toFixed(2)}" y2="${y.toFixed(2)}" class="db-maintenance-chart-grid"></line><text x="4" y="${(y + 3).toFixed(2)}" class="db-maintenance-chart-label">${escapeHtml(String(label))}</text>`;
    }).join("");

    return `<div class="db-maintenance-chart-card" data-db-chart-index="${index}">
      <p class="db-chart-current-value">${escapeHtml(def.formatter(latest || 0))}</p>
      <div class="db-maintenance-chart-head">
        <strong>${escapeHtml(def.title)}</strong>
        <span class="db-trend-chip ${trend.cls}" title="Trendindikator">${trend.arrow} ${escapeHtml(trend.label)}</span>
      </div>
      <p class="count compact db-chart-main-value db-chart-delta-line">Δ${escapeHtml(String(intervalHours))}h ${escapeHtml(def.deltaFormatter ? def.deltaFormatter(deltaWindow) : formatSignedInteger(deltaWindow))}</p>
      <svg viewBox="0 0 ${line.width} ${line.height}" class="db-maintenance-chart-svg" role="img" aria-label="${escapeHtml(def.title)} Verlauf">
        ${gridMarkup}
        <line x1="${line.padLeft}" y1="${line.height - line.padBottom}" x2="${line.width - line.padRight}" y2="${line.height - line.padBottom}" class="db-maintenance-chart-axis"></line>
        ${forecastSvg}
        <polyline points="${line.points}" class="db-maintenance-chart-line"></polyline>
        <text x="${line.padLeft}" y="${line.height - 4}" text-anchor="start" class="db-maintenance-chart-label db-maintenance-chart-label-x">${escapeHtml(firstBucketLabel)}</text>
        <text x="${line.width - line.padRight}" y="${line.height - 4}" text-anchor="end" class="db-maintenance-chart-label db-maintenance-chart-label-x">${escapeHtml(lastBucketLabel)}</text>
      </svg>
      ${dbMaintenanceChartLegendHtml(Boolean(forecast))}
      <p class="count compact">Min: ${escapeHtml(def.formatter(line.min))} · Max: ${escapeHtml(def.formatter(line.max))}</p>
      <p class="count compact">${escapeHtml(forecastText)}</p>
    </div>`;
  }).join("");

  el.querySelectorAll(".db-maintenance-chart-card").forEach((card) => {
    const idx = Number(card.getAttribute("data-db-chart-index") || -1);
    if (!Number.isFinite(idx) || idx < 0 || idx >= chartDefs.length) {
      return;
    }
    const targetSvg = card.querySelector(".db-maintenance-chart-svg");
    if (!targetSvg) {
      return;
    }
    targetSvg.style.cursor = "zoom-in";
    targetSvg.title = "Klicken zum Vergrößern";
    targetSvg.addEventListener("click", () => {
      openDbMaintenanceChartDrillModal(chartDefs[idx]);
    });
  });
}

function renderDbMaintenanceHistoryRows(rows) {
  const body = document.getElementById("dbMaintenanceHistoryRows");
  if (!body) return;
  const list = Array.isArray(rows) ? rows.slice().reverse() : [];
  if (list.length === 0) {
    body.innerHTML = '<tr><td colspan="7" class="muted">Noch keine Verlaufsdaten vorhanden.</td></tr>';
    return;
  }

  body.innerHTML = list.map((row) => {
    const time = formatUtcPlus2(row.bucket_start_utc || "") || "-";
    const deltaDbText = formatSignedBytes(row.delta_total_file_bytes);
    const deltaReportsText = formatSignedInteger(row.delta_reports_total);
    const deltaAlertsText = formatSignedInteger(row.delta_alerts_open);
    const deltaDbClass = deltaSignClass(row.delta_total_file_bytes);
    const deltaReportsClass = deltaSignClass(row.delta_reports_total);
    const deltaAlertsClass = deltaSignClass(row.delta_alerts_open);
    return `<tr>
      <td>${escapeHtml(time)}</td>
      <td>${escapeHtml(formatBytes(row.total_file_bytes || 0))}</td>
      <td><span class="${deltaDbClass}">${escapeHtml(deltaDbText)}</span></td>
      <td>${escapeHtml(formatInteger(row.reports_total || 0))}</td>
      <td><span class="${deltaReportsClass}">${escapeHtml(deltaReportsText)}</span></td>
      <td>${escapeHtml(formatInteger(row.alerts_open || 0))}</td>
      <td><span class="${deltaAlertsClass}">${escapeHtml(deltaAlertsText)}</span></td>
    </tr>`;
  }).join("");
}

function renderDbMaintenanceEffect(result) {
  const el = document.getElementById("dbMaintenanceEffect");
  if (!el) return;
  if (!result || typeof result !== "object") {
    el.textContent = "";
    return;
  }
  const reclaimed = Number(result.reclaimed_bytes || 0);
  const durationMs = Number(result.duration_ms || 0);
  if (!Number.isFinite(reclaimed) || !Number.isFinite(durationMs)) {
    el.textContent = "";
    return;
  }
  const signed = reclaimed >= 0 ? `-${formatBytes(reclaimed)}` : `+${formatBytes(Math.abs(reclaimed))}`;
  const seconds = (durationMs / 1000).toFixed(1);
  el.textContent = `Letzter VACUUM Effekt: ${signed} | Dauer: ${seconds}s`;
}

function updateBackupAutomationAuthModeUi() {
  const mode = String(document.getElementById("backupAutomationSftpAuthMode")?.value || "key").toLowerCase();
  const keyWrap = document.getElementById("backupAutomationSftpKeyPathWrap");
  const passwordWrap = document.getElementById("backupAutomationSftpPasswordWrap");
  if (keyWrap) keyWrap.classList.toggle("hidden", mode !== "key");
  if (passwordWrap) passwordWrap.classList.toggle("hidden", mode !== "password");
}

function applyBackupAutomationSettingsToInputs(settings) {
  document.getElementById("backupAutomationLocalEnabled").checked = !!settings.local_enabled;
  document.getElementById("backupAutomationIntervalHours").value = String(settings.local_interval_hours || 12);
  document.getElementById("backupAutomationRetentionMaxFiles").value = String(
    settings.local_retention_max_files ?? 4
  );
  document.getElementById("backupAutomationRetentionDays").value = String(settings.local_retention_days || 3);
  document.getElementById("backupAutomationTargetDir").value = String(settings.local_target_dir || "auto_db_backups");
  document.getElementById("backupAutomationSftpEnabled").checked = !!settings.sftp_enabled;
  document.getElementById("backupAutomationSftpHost").value = String(settings.sftp_host || "");
  document.getElementById("backupAutomationSftpPort").value = String(settings.sftp_port || 22);
  document.getElementById("backupAutomationSftpUsername").value = String(settings.sftp_username || "");
  document.getElementById("backupAutomationSftpRemotePath").value = String(settings.sftp_remote_path || "");
  document.getElementById("backupAutomationSftpAuthMode").value = settings.sftp_auth_mode === "password" ? "password" : "key";
  document.getElementById("backupAutomationSftpKeyPath").value = String(settings.sftp_key_path || "");
  document.getElementById("backupAutomationSftpPassword").value = String(settings.sftp_password || "");
  updateBackupAutomationAuthModeUi();
}

function readBackupAutomationSettingsFromInputs() {
  return {
    local_enabled: !!document.getElementById("backupAutomationLocalEnabled")?.checked,
    local_interval_hours: Number(document.getElementById("backupAutomationIntervalHours")?.value || 12),
    local_retention_max_files: Number(document.getElementById("backupAutomationRetentionMaxFiles")?.value || 4),
    local_retention_days: Number(document.getElementById("backupAutomationRetentionDays")?.value || 3),
    local_target_dir: String(document.getElementById("backupAutomationTargetDir")?.value || "auto_db_backups").trim(),
    sftp_enabled: !!document.getElementById("backupAutomationSftpEnabled")?.checked,
    sftp_host: String(document.getElementById("backupAutomationSftpHost")?.value || "").trim(),
    sftp_port: Number(document.getElementById("backupAutomationSftpPort")?.value || 22),
    sftp_username: String(document.getElementById("backupAutomationSftpUsername")?.value || "").trim(),
    sftp_remote_path: String(document.getElementById("backupAutomationSftpRemotePath")?.value || "").trim(),
    sftp_auth_mode: String(document.getElementById("backupAutomationSftpAuthMode")?.value || "key"),
    sftp_key_path: String(document.getElementById("backupAutomationSftpKeyPath")?.value || "").trim(),
    sftp_password: String(document.getElementById("backupAutomationSftpPassword")?.value || ""),
  };
}

function renderBackupAutomationRuns(rows) {
  const body = document.getElementById("backupAutomationRunsRows");
  if (!body) return;
  const list = Array.isArray(rows) ? rows : [];
  if (list.length === 0) {
    body.innerHTML = '<tr><td colspan="9" class="muted">Noch keine Backup-Läufe vorhanden.</td></tr>';
    return;
  }

  const formatRunDate = (isoText) => {
    const raw = String(isoText || "").trim();
    if (!raw) return "-";
    const parsed = new Date(raw);
    if (Number.isNaN(parsed.getTime())) return "-";
    return parsed.toLocaleDateString("de-CH", { timeZone: "Europe/Zurich" });
  };

  const formatRunTime = (isoText) => {
    const raw = String(isoText || "").trim();
    if (!raw) return "-";
    const parsed = new Date(raw);
    if (Number.isNaN(parsed.getTime())) return "-";
    return parsed.toLocaleTimeString("de-CH", {
      timeZone: "Europe/Zurich",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  };

  body.innerHTML = list.map((row) => {
    const finishedDate = formatRunDate(row.finished_at_utc || "");
    const finishedTime = formatRunTime(row.finished_at_utc || "");
    const source = String(row.trigger_source || "-");
    const status = String(row.status || "-");
    const filePath = String(row.backup_path || "-");
    const size = Number(row.backup_size_bytes || 0);
    const uploadedSftp = !!row.uploaded_sftp;
    const error = String(row.error_message || "");
    const runId = Number(row.id || 0);
    const statusClass = status === "ok" ? "delta-positive" : (status === "error" ? "delta-negative" : "delta-neutral");
    const uploadedClass = uploadedSftp ? "delta-positive" : "delta-neutral";
    const canDownload = runId > 0 && status === "ok" && filePath && filePath !== "-";
    const downloadHtml = canDownload
      ? `<a class="backup-run-link" href="/api/v1/admin/backup-automation/download?run_id=${encodeURIComponent(String(runId))}" title="Backup herunterladen">Download</a>`
      : "-";
    return `<tr>
      <td>${escapeHtml(finishedDate)}</td>
      <td>${escapeHtml(finishedTime)}</td>
      <td>${escapeHtml(source)}</td>
      <td><span class="${statusClass}">${escapeHtml(status)}</span></td>
      <td>${escapeHtml(filePath)}</td>
      <td>${escapeHtml(formatBytes(size))}</td>
      <td>${downloadHtml}</td>
      <td><span class="${uploadedClass}">${uploadedSftp ? "ja" : "nein"}</span></td>
      <td>${escapeHtml(error || "-")}</td>
    </tr>`;
  }).join("");
}

async function loadAdminBackupAutomation() {
  const response = await fetch("/api/v1/admin/backup-automation", {
    method: "GET",
    credentials: "same-origin",
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || ("HTTP " + response.status));
  }
  const settings = data && typeof data.settings === "object" ? data.settings : {};
  const runs = Array.isArray(data?.recent_runs) ? data.recent_runs : [];
  applyBackupAutomationSettingsToInputs(settings);
  renderBackupAutomationRuns(runs);
  state.backupAutomationLoaded = true;
  const updated = settings.updated_at_utc ? formatUtcPlus2(settings.updated_at_utc) : "-";
  setBackupAutomationStatus(
    `Lokales Backup: ${settings.local_enabled ? "aktiv" : "inaktiv"} · Intervall: ${settings.local_interval_hours || 12}h · Lokale Kopien: ${settings.local_retention_max_files ?? 4} · Max. Alter: ${settings.local_retention_days || 3} Tage · Letztes Settings-Update: ${updated}`
  );
  return data;
}

async function saveAdminBackupAutomationSettings() {
  const payload = readBackupAutomationSettingsFromInputs();
  const response = await fetch("/api/v1/admin/backup-automation/settings", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify(payload),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || ("HTTP " + response.status));
  }
  return data;
}

async function triggerAdminAutoBackupNow() {
  const response = await fetch("/api/v1/admin/backup-automation/trigger-local", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify({}),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || ("HTTP " + response.status));
  }
  return data;
}

async function testAdminBackupAutomationSftp() {
  const payload = readBackupAutomationSettingsFromInputs();
  const response = await fetch("/api/v1/admin/backup-automation/test-sftp", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify(payload),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || ("HTTP " + response.status));
  }
  return data;
}

function applyAdminDatabaseStatsPayload(data, options = {}) {
  const stats = data && typeof data.stats === "object" ? data.stats : {};
  const history = Array.isArray(data?.history) ? data.history : [];
  const recentRows = Array.isArray(data?.recent_rows) ? data.recent_rows : [];
  const forecasts = data && typeof data.forecasts === "object" ? data.forecasts : {};
  const schedule = data && typeof data.schedule === "object" ? data.schedule : {};
  const intervalHours = Math.max(1, Number(schedule?.interval_hours || 2));
  renderDbMaintenanceStats(stats);
  renderDbMaintenanceCharts(history, forecasts, intervalHours);
  renderDbMaintenanceHistoryRows(recentRows);
  const lastHistory = history.length > 0 ? history[history.length - 1] : null;
  const lastComputed = String(
    options.computedAtUtc
      || data?.triggered?.computed_at_utc
      || lastHistory?.computed_at_utc
      || lastHistory?.bucket_start_utc
      || ""
  ).trim();
  const lastRunLabel = lastComputed ? formatUtcPlus2(lastComputed) : "-";
  const nextLocal = schedule?.next_bucket_local
    ? new Date(schedule.next_bucket_local).toLocaleString("de-CH", { timeZone: schedule.timezone || "Europe/Zurich" })
    : "-";
  const prefix = options.manualRun ? "Manuell berechnet" : "Letzter Lauf";
  setDbMaintenanceStatus(`${prefix}: ${lastRunLabel} · Nächster ${intervalHours}h-Lauf: ${nextLocal} (${schedule.timezone || "Europe/Zurich"})`);
  return stats;
}

async function loadAdminDatabaseStats(retryCount = 0) {
  const response = await fetch("/api/v1/admin/database-stats", {
    method: "GET",
    credentials: "same-origin",
    cache: "no-store",
  });
  if (response.status === 503 && retryCount < 3) {
    await new Promise((resolve) => setTimeout(resolve, 1500 * (retryCount + 1)));
    return loadAdminDatabaseStats(retryCount + 1);
  }
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || ("HTTP " + response.status));
  }
  return applyAdminDatabaseStatsPayload(data);
}

async function loadHeaderDatabaseKpis() {
  const response = await fetch("/api/v1/dashboard-db-kpis", {
    method: "GET",
    credentials: "same-origin",
    cache: "no-store",
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || ("HTTP " + response.status));
  }
  const stats = data && typeof data.stats === "object" ? data.stats : {};
  const reportsTotalRaw = stats.reports_total;
  const reportsLastHour = Number(stats.reports_last_hour || 0);
  const totalFileBytes = Number(stats.total_file_bytes);
  const dbSizeDelta1hBytes = Number(stats.db_size_delta_1h_bytes);
  if (reportsTotalRaw === null || reportsTotalRaw === undefined) {
    state.dbReportsTotal = null;
  } else {
    const reportsTotal = Number(reportsTotalRaw);
    state.dbReportsTotal = Number.isFinite(reportsTotal) && reportsTotal >= 0 ? reportsTotal : null;
  }
  state.dbReportsLastHour = Number.isFinite(reportsLastHour) && reportsLastHour >= 0 ? reportsLastHour : 0;
  state.dbTotalFileBytes = Number.isFinite(totalFileBytes) && totalFileBytes >= 0 ? totalFileBytes : null;
  state.dbSizeDelta1hBytes = Number.isFinite(dbSizeDelta1hBytes) ? dbSizeDelta1hBytes : null;
  const dbReportsChip = document.getElementById("headerDbReportsChip");
  const dbReportsHourChip = document.getElementById("headerDbReportsHourChip");
  const dbSizeDeltaChip = document.getElementById("headerDbSizeDeltaChip");
  const computedAt = String(stats.reports_total_computed_at_utc || "").trim();
  if (dbReportsChip) {
    dbReportsChip.title = computedAt
      ? `Berichte in der Datenbank (Wartungssnapshot ${computedAt})`
      : "Berichte in der Datenbank";
  }
  if (dbReportsHourChip) {
    dbReportsHourChip.title = "In der letzten Stunde in die DB geschriebene Agent-Reports";
  }
  if (dbSizeDeltaChip) {
    dbSizeDeltaChip.title = "Wachstum der monitoring.db-Datei in 1h (ohne WAL-Schwankungen)";
  }
  updateHeaderStatChips();
  return stats;
}

async function analyzeAdminReportDuplicates() {
  const response = await fetch("/api/v1/admin/database-dedupe/analyze", {
    method: "GET",
    credentials: "same-origin",
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || ("HTTP " + response.status));
  }
  return data && typeof data.analysis === "object" ? data.analysis : {};
}

async function runAdminReportDedupe(dryRun = false) {
  const response = await fetch("/api/v1/admin/database-dedupe/run", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify({ dry_run: dryRun }),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || ("HTTP " + response.status));
  }
  return data;
}

function renderReportDedupeEffect(analysisOrResult) {
  const el = document.getElementById("dbMaintenanceEffect");
  if (!el) return;
  const payload = analysisOrResult?.result || analysisOrResult || {};
  const before = payload.before || payload;
  const after = payload.after || {};
  const redundant = Number(before.redundant_rows || 0);
  const deleted = Number(payload.deleted_rows || 0);
  const dbMb = formatMegabytesFromBytes(Number(before.db_file_bytes || 0));
  const reclaimMb = formatMegabytesFromBytes(Number(before.estimated_reclaim_bytes || 0));
  const lines = [
    `Reports gesamt: ${Number(before.reports_total || 0).toLocaleString("de-CH")}`,
    `Redundante Duplikate: ${redundant.toLocaleString("de-CH")}`,
    `DB-Datei: ${dbMb} MB (geschätzt freigebbar ~${reclaimMb} MB)`,
  ];
  if (deleted > 0) {
    lines.push(`Gelöscht: ${deleted.toLocaleString("de-CH")}`);
    lines.push(`Verbleibend: ${Number(after.reports_total || 0).toLocaleString("de-CH")}`);
    lines.push("Hinweis: VACUUM ausführen, um Speicherplatz zurückzugewinnen.");
  }
  el.textContent = lines.join(" · ");
}

async function runAdminDatabaseVacuum() {
  const response = await fetch("/api/v1/admin/database-vacuum", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify({}),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || ("HTTP " + response.status));
  }
  return data && typeof data.result === "object" ? data.result : {};
}

async function triggerAdminDatabaseStatsNow() {
  const response = await fetch("/api/v1/admin/database-stats/trigger", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify({}),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || ("HTTP " + response.status));
  }
  return data;
}

async function exportGlobalAlertsCsv() {
  const severity = String(state.globalSeverityFilter || "all").trim().toLowerCase();
  const country = String(state.globalCountryFilter || "all").trim().toUpperCase();
  const params = new URLSearchParams();
  if (severity && severity !== "all") params.set("severity", severity);
  if (country && country !== "ALL") params.set("country", country);
  const query = params.toString() ? `?${params.toString()}` : "";
  return triggerFileDownload(
    `/api/v1/export/alerts.csv${query}`,
    `monitoring-alerts-${new Date().toISOString().replace(/[.:]/g, "-")}.csv`,
  );
}

function wireHostListInteractions() {
  const hostList = document.getElementById("hostList");
  if (!hostList || state.hostListDelegatedWired) {
    return;
  }

  const selectHostFromItem = (item) => {
    if (!item) {
      return;
    }
    const hostname = item.getAttribute("data-host") || "";
    const hostUid = item.getAttribute("data-host-uid") || hostname;
    if (!hostname || (hostname === state.selectedHost && hostUid === state.selectedHostUid)) {
      return;
    }

    const previousScrollTop = hostList.scrollTop;
    state.selectedHost = hostname;
    state.selectedHostUid = hostUid;
    state.selectedDisplayName = item.querySelector("strong")?.textContent || hostname;
    state.reportOffset = 0;
    state.hostReportMeta = null;
    renderHosts(state.hosts);
    hostList.scrollTop = previousScrollTop;
    void loadReportsForHost().then(() => {
      window.setTimeout(() => {
        void loadAnalysisForHost();
        void loadAlertsForHost();
        void loadDatabaseLifecycleForHost();
        void loadConfigChangelogForHost();
        void loadAndRenderCustomerNotificationPanel(hostname, hostUid);
      }, 300);
    });
  };

  hostList.addEventListener("click", (event) => {
    const target = event.target instanceof Element ? event.target : null;
    const licenseBadge = target ? target.closest(".host-license-info-badge") : null;
    if (licenseBadge) {
      event.preventDefault();
      event.stopPropagation();
      event.stopImmediatePropagation();
      toggleHostLicensePopupFromBadge(licenseBadge);
    }
  }, true);

  hostList.addEventListener("click", async (event) => {
    const target = event.target instanceof Element ? event.target : null;
    if (!target) {
      return;
    }

    if (target.closest(".host-license-info-badge")) {
      return;
    }

    const hiddenToggle = target.closest("#hiddenHostsToggleButton");
    if (hiddenToggle) {
      event.preventDefault();
      event.stopPropagation();
      state.hiddenHostsCollapsed = !state.hiddenHostsCollapsed;
      const body = hostList.querySelector("#hiddenHostsBody");
      if (body) {
        body.classList.toggle("hidden", state.hiddenHostsCollapsed);
      }
      hiddenToggle.textContent = hiddenHostsToggleLabel(state.hiddenHostsCollapsed);
      hiddenToggle.setAttribute("aria-expanded", state.hiddenHostsCollapsed ? "false" : "true");
      return;
    }

    const toggleMutedButton = target.closest("[data-action='toggle-muted-list']");
    if (toggleMutedButton) {
      event.preventDefault();
      event.stopPropagation();
      const hostnameEnc = toggleMutedButton.getAttribute("data-host-enc") || "";
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
      toggleMutedButton.textContent = hiddenHostMutedAlertsToggleLabel(nextCollapsed);
      toggleMutedButton.setAttribute("aria-expanded", nextCollapsed ? "false" : "true");
      return;
    }

    const unmuteButton = target.closest("[data-action='unmute-alert']");
    if (unmuteButton) {
      event.preventDefault();
      event.stopPropagation();
      const hostname = decodeURIComponent(unmuteButton.getAttribute("data-host-enc") || "");
      const mountpoint = decodeURIComponent(unmuteButton.getAttribute("data-mount-enc") || "");
      if (!hostname || !mountpoint) {
        return;
      }
      try {
        await toggleAlertMute(hostname, mountpoint, true);
      } catch (error) {
        window.alert(`Alert konnte nicht reaktiviert werden: ${error.message}`);
      }
      return;
    }

    const miniAction = target.closest(".host-mini-action[data-action]");
    if (miniAction) {
      event.preventDefault();
      event.stopPropagation();
      const hostname = miniAction.getAttribute("data-host") || "";
      const hostUid = miniAction.getAttribute("data-host-uid") || "";
      const action = miniAction.getAttribute("data-action") || "";
      const current = miniAction.getAttribute("data-current") === "1";
      if (!hostname || !action) {
        return;
      }
      try {
        if (action === "favorite") {
          await saveHostSettings(hostname, { is_favorite: !current }, hostUid);
        } else if (action === "hidden") {
          await saveHostSettings(hostname, { is_hidden: !current }, hostUid);
        }
        await loadHosts();
        await refreshSelectedHostPanels();
      } catch (error) {
        window.alert(`Host-Einstellung konnte nicht gespeichert werden: ${error.message}`);
      }
      return;
    }

    const hostItem = target.closest(".host-item");
    if (!hostItem) {
      return;
    }

    if (target.closest(".host-mini-action, .host-license-info-badge, .host-license-dot, [data-action='toggle-muted-list'], [data-action='unmute-alert']")) {
      return;
    }

    selectHostFromItem(hostItem);
  });

  hostList.addEventListener("keydown", (event) => {
    if (event.key !== "Enter" && event.key !== " ") {
      return;
    }
    const target = event.target instanceof Element ? event.target : null;
    if (target && target.closest(".host-license-info-badge")) {
      event.preventDefault();
      toggleHostLicensePopupFromBadge(target.closest(".host-license-info-badge"));
      return;
    }
    const hostItem = target ? target.closest(".host-item") : null;
    if (!hostItem) {
      return;
    }
    event.preventDefault();
    selectHostFromItem(hostItem);
  });

  hostList.addEventListener("contextmenu", (event) => {
    const target = event.target instanceof Element ? event.target : null;
    const hostItem = target ? target.closest(".host-item") : null;
    if (!hostItem) {
      return;
    }
    const hostname = hostItem.getAttribute("data-host") || "";
    const hostUid = hostItem.getAttribute("data-host-uid") || "";
    if (!hostname && !hostUid) {
      return;
    }
    event.preventDefault();
    event.stopPropagation();
    openHostContextMenu(hostname, hostUid, event.clientX, event.clientY);
  });

  state.hostListDelegatedWired = true;
}

function renderHosts(hosts) {
  const hostList = document.getElementById("hostList");
  const triggerAllButton = document.getElementById("triggerAllAgentsUpdateButton");

  if (triggerAllButton) {
    triggerAllButton.disabled = state.totalHosts <= 0;
    triggerAllButton.textContent = state.totalHosts > 0
      ? `⟳ Update für alle Hosts (${state.totalHosts})`
      : "⟳ Update für alle Hosts";
  }

  if (!Array.isArray(hosts) || hosts.length === 0) {
    hostList.innerHTML = "<p class=\"muted\">Keine Hosts vorhanden.</p>";
    renderHostIconFilters([]);
    return;
  }

  const { visibleHosts, hiddenHosts } = splitHosts(hosts);

  if (visibleHosts.length === 0 && hiddenHosts.length === 0) {
    hostList.innerHTML = "<p class=\"muted\">Keine Hosts passen zum Suchfilter.</p>";
    renderHostIconFilters(hosts);
    return;
  }

  const visibleHtml = visibleHosts.map(renderSingleHostCard).join("");
  const hiddenHtml = hiddenHosts.map(renderSingleHostCard).join("");
  const hiddenCollapsedClass = state.hiddenHostsCollapsed ? "hidden" : "";

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

function isLiveReportEventVisible(event) {
  if (!event || event.is_hidden) {
    return false;
  }
  const host = {
    hostname: asText(event.hostname, "").trim(),
    host_uid: asText(event.host_uid, "").trim(),
    country_code: asText(event.country_code, "").trim().toUpperCase(),
  };
  if (!host.hostname) {
    return false;
  }
  const exclusions = getHostInterestManualExclusions();
  if (hostInterestSetHasHost(exclusions, host)) {
    return false;
  }
  const selectedCountries = getHostInterestSelectedCountries();
  const additions = getHostInterestManualAdditions();
  const hasExplicitBaseSelection = selectedCountries.size > 0 || additions.size > 0;
  if (!hasExplicitBaseSelection) {
    return true;
  }
  if (hostInterestSetHasHost(additions, host)) {
    return true;
  }
  return selectedCountries.has(host.country_code);
}

function resolveLiveReportCustomerLogoUrl(event, hostIdentity, hostname) {
  const fromEvent = asText(event?.customer_logo_url, "").trim();
  if (fromEvent) {
    return fromEvent;
  }
  const hostRecord = Array.isArray(state.hosts)
    ? state.hosts.find((host) => {
      const identity = resolveHostIdentity(host);
      return identity === hostIdentity || asText(host.hostname, "") === hostname;
    })
    : null;
  return asText(hostRecord?.customer_logo_url, "").trim();
}

function buildLiveReportFeedPreviewFromEvent(event) {
  const deliveryMode = asText(event?.delivery_mode, "live").toLowerCase();
  const deliveryLabel = deliveryMode === "delayed" ? "DELAYED" : "LIVE";
  const deliveryClass = deliveryMode === "delayed" ? "delivery-chip delayed" : "delivery-chip live";
  const customerName = asText(event?.customer_name, "Kein Kunde") || "Kein Kunde";
  const hostname = asText(event?.hostname, "-");
  const hostIdentity = asText(event?.host_uid, "").trim() || hostname;
  const customerLogoUrl = resolveLiveReportCustomerLogoUrl(event, hostIdentity, hostname);
  const designation = asText(event?.display_name, hostname) || hostname;
  const shortHostname = hostname.split(".")[0] || hostname;
  const ip = asText(event?.std_nic_ip || event?.primary_ip, "-");
  const reportTs = asText(event?.received_at_utc, "");
  const clock = formatHostLastReportClock(reportTs);
  const metrics = [];
  if (Number.isFinite(Number(event?.cpu_usage_percent))) {
    metrics.push(`CPU ${formatNumber(event.cpu_usage_percent, 1)}%`);
  }
  if (Number.isFinite(Number(event?.memory_used_percent))) {
    metrics.push(`RAM ${formatNumber(event.memory_used_percent, 1)}%`);
  }
  return {
    id: `${hostIdentity}|${asText(event?.report_id, reportTs || Date.now())}`,
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

function loadLiveReportFeedEnabled() {
  try {
    const raw = window.localStorage.getItem(LIVE_REPORT_FEED_ENABLED_KEY);
    if (raw === null) {
      return true;
    }
    return raw !== "0" && raw !== "false";
  } catch (_error) {
    return true;
  }
}

function persistLiveReportFeedEnabled(enabled) {
  try {
    window.localStorage.setItem(LIVE_REPORT_FEED_ENABLED_KEY, enabled ? "1" : "0");
  } catch (_error) {
    // Ignore storage failures.
  }
}

function updateLiveReportFeedToggleUi() {
  const button = document.getElementById("liveReportFeedToggleButton");
  if (!button) {
    return;
  }
  button.setAttribute("aria-pressed", liveReportFeedEnabled ? "true" : "false");
  const label = liveReportFeedEnabled ? "Live Meldungen ausblenden" : "Live Meldungen einblenden";
  button.title = label;
  button.setAttribute("aria-label", label);
}

function setLiveReportFeedEnabled(enabled) {
  liveReportFeedEnabled = Boolean(enabled);
  persistLiveReportFeedEnabled(liveReportFeedEnabled);
  updateLiveReportFeedToggleUi();
  renderLiveReportFeed();
}

function toggleLiveReportFeedEnabled() {
  setLiveReportFeedEnabled(!liveReportFeedEnabled);
}

function hydrateLiveReportFeedItemLogos() {
  for (const item of liveReportFeedItems) {
    if (!item.customerLogoUrl) {
      item.customerLogoUrl = resolveLiveReportCustomerLogoUrl(
        { customer_logo_url: "" },
        item.hostIdentity,
        item.hostname,
      );
    }
  }
}

function buildLiveReportFeedItemInnerHtml(item) {
  const statsHtml = item.metricsText
    ? `<span class="live-report-feed-stats">${escapeHtml(item.metricsText)}</span>`
    : `<span class="live-report-feed-stats live-report-feed-stats--empty" aria-hidden="true"></span>`;
  const customerLogoHtml = item.customerLogoUrl
    ? `<span class="live-report-feed-customer-logo-wrap" aria-hidden="true">
        <img src="${escapeHtml(item.customerLogoUrl)}" alt="" class="live-report-feed-customer-logo" loading="lazy" decoding="async" onerror="this.closest('.live-report-feed-customer-logo-wrap').style.display='none'">
      </span>`
    : "";
  return `
      <div class="live-report-feed-item-head">
        <span class="live-report-feed-customer-row">
          ${customerLogoHtml}
          <span class="live-report-feed-customer" title="${escapeHtml(item.customerName)}">${escapeHtml(item.customerName)}</span>
        </span>
        <time class="live-report-feed-time" datetime="${escapeHtml(item.receivedAtUtc)}" title="${escapeHtml(item.clockTitle)}">${escapeHtml(item.clockLabel)}</time>
      </div>
      <p class="live-report-feed-designation" title="${escapeHtml(item.designation)}">${escapeHtml(item.designation)}</p>
      <p class="live-report-feed-hostline">
        <span class="live-report-feed-host-meta">
          <span class="live-report-feed-hostname" title="${escapeHtml(item.shortHostname)}">${escapeHtml(item.shortHostname)}</span>
          <span class="live-report-feed-sep" aria-hidden="true">·</span>
          <span class="live-report-feed-ip" title="${escapeHtml(item.ip)}">${escapeHtml(item.ip)}</span>
        </span>
        <span class="${item.deliveryClass}">${escapeHtml(item.deliveryLabel)}</span>
      </p>
      <div class="live-report-feed-item-foot">
        ${statsHtml}
      </div>
  `;
}

function createHeaderLiveReportCardElement(item) {
  const button = document.createElement("button");
  button.type = "button";
  const classes = ["live-report-feed-item", "header-live-report-card"];
  if (item.isNew) {
    classes.push("is-new");
  }
  button.className = classes.join(" ");
  button.dataset.liveFeedId = item.id;
  button.dataset.liveFeedHost = item.hostname;
  button.dataset.liveFeedUid = item.hostIdentity;
  button.title = "Zum Host wechseln";
  button.innerHTML = buildLiveReportFeedItemInnerHtml(item);
  return button;
}

function animateHeaderLiveReportReplacement(stack, item) {
  const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const oldCard = stack.querySelector(".header-live-report-card");
  const newCard = createHeaderLiveReportCardElement(item);

  if (!oldCard || prefersReducedMotion) {
    stack.innerHTML = "";
    stack.classList.remove("is-animating");
    stack.appendChild(newCard);
    return;
  }

  stack.classList.add("is-animating");
  newCard.classList.add("is-entering");
  stack.appendChild(newCard);
  oldCard.classList.add("is-exiting");

  window.requestAnimationFrame(() => {
    window.requestAnimationFrame(() => {
      oldCard.classList.add("is-exiting-active");
      newCard.classList.remove("is-entering");
    });
  });

  const removeOldCard = () => {
    if (oldCard.isConnected) {
      oldCard.remove();
    }
    if (!stack.querySelector(".is-exiting")) {
      stack.classList.remove("is-animating");
    }
  };
  oldCard.addEventListener("transitionend", removeOldCard, { once: true });
  window.setTimeout(removeOldCard, 1440);
}

function renderLiveReportFeed(options = {}) {
  wireLiveReportFeed();
  const slot = document.getElementById("headerLiveReportSlot");
  const stack = document.getElementById("headerLiveReportStack");
  if (!slot || !stack) {
    return;
  }
  if (!liveReportFeedEnabled || liveReportFeedItems.length === 0) {
    slot.classList.add("hidden");
    stack.innerHTML = "";
    stack.classList.remove("is-animating");
    return;
  }
  slot.classList.remove("hidden");
  hydrateLiveReportFeedItemLogos();

  const item = liveReportFeedItems[0];
  const shouldAnimate = Boolean(options.animate) && Boolean(stack.querySelector(".header-live-report-card"));
  if (shouldAnimate) {
    animateHeaderLiveReportReplacement(stack, item);
  } else {
    stack.classList.remove("is-animating");
    stack.innerHTML = "";
    stack.appendChild(createHeaderLiveReportCardElement(item));
  }
  item.isNew = false;
}

function enqueueLiveReportFeedFromEvents(events) {
  if (!Array.isArray(events) || events.length === 0) {
    return;
  }
  const visibleEvents = events.filter(isLiveReportEventVisible);
  if (visibleEvents.length === 0) {
    return;
  }
  const sortedEvents = [...visibleEvents].sort(
    (left, right) => (Number(right?.report_id) || 0) - (Number(left?.report_id) || 0),
  );
  const preview = buildLiveReportFeedPreviewFromEvent(sortedEvents[0]);
  const previousId = liveReportFeedItems[0]?.id || "";
  const shouldAnimate = Boolean(previousId) && previousId !== preview.id;
  preview.isNew = shouldAnimate || !previousId;
  liveReportFeedItems = [preview];
  renderLiveReportFeed({ animate: shouldAnimate });
}

function stopLiveReportPoll() {
  if (liveReportPollTimerId !== null) {
    window.clearInterval(liveReportPollTimerId);
    liveReportPollTimerId = null;
  }
  liveReportPollInFlight = false;
}

function startLiveReportPoll() {
  stopLiveReportPoll();
  if (!state.isAuthenticated) {
    return;
  }
  void pollLiveReportEvents();
  liveReportPollTimerId = window.setInterval(() => {
    void pollLiveReportEvents();
  }, LIVE_REPORT_POLL_INTERVAL_MS);
}

async function pollLiveReportEvents() {
  if (!state.isAuthenticated || liveReportPollInFlight) {
    return;
  }
  liveReportPollInFlight = true;
  try {
    const query = liveReportPollCursorId > 0
      ? `since_id=${encodeURIComponent(String(liveReportPollCursorId))}&limit=20`
      : "limit=20";
    const response = await fetch(`/api/v1/live-report-events?${query}`, {
      credentials: "same-origin",
      cache: "no-store",
    });
    if (response.status === 401) {
      stopLiveReportPoll();
      return;
    }
    if (!response.ok) {
      return;
    }
    const data = await response.json().catch(() => ({}));
    const cursorId = Number(data?.cursor_id);
    if (Number.isFinite(cursorId) && cursorId >= 0) {
      liveReportPollCursorId = cursorId;
    }
    const events = Array.isArray(data?.events) ? data.events : [];
    const visibleEvents = events.filter(isLiveReportEventVisible);
    if (visibleEvents.length > 0) {
      enqueueLiveReportFeedFromEvents(visibleEvents);
      const selectedIdentity = asText(state.selectedHostUid, "").trim() || asText(state.selectedHost, "").trim();
      const shouldRefreshSelectedReport = visibleEvents.some((event) => {
        const eventIdentity = asText(event?.host_uid, "").trim() || asText(event?.hostname, "").trim();
        return Boolean(selectedIdentity && eventIdentity && eventIdentity === selectedIdentity);
      });
      if (shouldRefreshSelectedReport) {
        void loadReportsForHost();
      }
    }
  } catch (_error) {
    // Keep polling on transient network failures.
  } finally {
    liveReportPollInFlight = false;
  }
}

function selectHostFromLiveReportFeed(hostname, hostUid) {
  const hostList = document.getElementById("hostList");
  const previousScrollTop = hostList ? hostList.scrollTop : 0;
  state.selectedHost = hostname;
  state.selectedHostUid = hostUid || hostname;
  const hostRecord = Array.isArray(state.hosts)
    ? state.hosts.find((host) => resolveHostIdentity(host) === (hostUid || hostname))
    : null;
  state.selectedDisplayName = asText(hostRecord?.display_name || hostname, hostname);
  state.reportOffset = 0;
  state.viewMode = "overview";
  state.overviewSection = "main";
  state.reportSection = "overview";
  renderHosts(state.hosts || []);
  if (hostList) {
    hostList.scrollTop = previousScrollTop;
  }
  updateOverviewSection();
  void loadReportsForHost();
  void loadAnalysisForHost();
  void loadAlertsForHost();
  void loadDatabaseLifecycleForHost();
  void loadConfigChangelogForHost();
  loadAndRenderCustomerNotificationPanel(hostname, hostUid || "");
}

function wireLiveReportFeed() {
  if (liveReportFeedWired) {
    return;
  }
  const stack = document.getElementById("headerLiveReportStack");
  if (!stack) {
    return;
  }
  liveReportFeedWired = true;

  stack.addEventListener("click", (event) => {
    const button = event.target instanceof Element ? event.target.closest(".header-live-report-card") : null;
    if (!button) {
      return;
    }
    const hostname = String(button.getAttribute("data-live-feed-host") || "").trim();
    const hostUid = String(button.getAttribute("data-live-feed-uid") || "").trim();
    if (!hostname) {
      return;
    }
    selectHostFromLiveReportFeed(hostname, hostUid);
  });
}

function initLiveReportFeed() {
  liveReportFeedEnabled = loadLiveReportFeedEnabled();
  updateLiveReportFeedToggleUi();
  wireLiveReportFeed();
  renderLiveReportFeed();
}

async function loadHosts(options = {}) {
  const preserveScroll = Boolean(options && options.preserveScroll);
  const silent = Boolean(options && options.silent);
  const hostList = document.getElementById("hostList");
  const previousScrollTop = hostList ? hostList.scrollTop : 0;

  if (!silent && hostList && (!Array.isArray(state.hosts) || state.hosts.length === 0)) {
    hostList.innerHTML = '<p class="muted">Lade Hosts…</p>';
  }

  try {
    const url = `/api/v1/hosts?limit=${state.hostLimit}&offset=${state.hostOffset}`;
    const response = await fetch(url, { credentials: "same-origin", cache: "no-store" });
    if (!response.ok) {
      throw new Error("HTTP " + response.status);
    }

    const data = await response.json();
    state.totalHosts = Number(data.total_hosts || 0);
    const hosts = data.hosts || [];
    state.hosts = hosts;
    if (state.globalSubMode === "host-config-changes") {
      refreshHostConfigChangesCountryFilter();
    }
    syncEffectiveHostInterestSelection();
    updateHeaderStatChips();
    renderHostInterestsEditor();
    const { visibleHosts, hiddenHosts } = splitHosts(hosts);
    state.visibleHosts = Number(data.visible_hosts || visibleHosts.length || 0);
    state.hiddenHosts = Number(data.hidden_hosts || hiddenHosts.length || 0);
    const orderedHosts = [...visibleHosts, ...hiddenHosts];
    state.hostFilterNoMatches = hosts.length > 0 && orderedHosts.length === 0 && hasActiveHostFilters();

    if (orderedHosts.length === 0) {
      state.selectedHost = "";
      state.selectedHostUid = "";
      state.selectedDisplayName = "";
      state.reportOffset = 0;
      loadAndRenderCustomerNotificationPanel("");
    }
    // No auto-selection: user picks a host explicitly

    const selectedIdentity = asText(state.selectedHostUid, "").trim() || asText(state.selectedHost, "").trim();
    const selectedStillVisible = !selectedIdentity || orderedHosts.some((host) => resolveHostIdentity(host) === selectedIdentity);
    if (!selectedStillVisible && orderedHosts.length > 0) {
      // Previously selected host disappeared (e.g. hidden/deleted) — deselect instead of jumping
      state.selectedHost = "";
      state.selectedHostUid = "";
      state.selectedDisplayName = "";
      state.reportOffset = 0;
      renderHosts(hosts);
      if (preserveScroll && hostList) hostList.scrollTop = previousScrollTop;
      updatePagerButtons();
      return;
    }

    const selectedHost = orderedHosts.find((host) => resolveHostIdentity(host) === selectedIdentity);
    if (selectedHost) {
      state.selectedHost = String(selectedHost.hostname || "");
      state.selectedHostUid = resolveHostIdentity(selectedHost);
      state.selectedDisplayName = String(selectedHost.display_name || selectedHost.hostname || "");
    }

    renderHosts(hosts);
    if (preserveScroll && hostList) {
      hostList.scrollTop = previousScrollTop;
    }
    updatePagerButtons();
    loadAndRenderCustomerNotificationPanel(state.selectedHost || "", state.selectedHostUid || "");

    // Refresh muted-alert metadata in the background so host cards appear fast.
    if (!state.alertMutesRefreshInFlight) {
      state.alertMutesRefreshInFlight = true;
      loadAlertMutes()
        .then((changed) => {
          if (!changed) {
            return;
          }
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

function buildHostReportsUrl(options = {}) {
  const hostNameParam = encodeURIComponent(state.selectedHost);
  const hostUidParam = encodeURIComponent(state.selectedHostUid || "");
  const jumpToUtc = typeof options.jumpToUtc === "string" ? options.jumpToUtc.trim() : "";
  const beforeId = Number(options.beforeId || 0);
  const afterId = Number(options.afterId || 0);
  const useKeyset = beforeId > 0 || afterId > 0;
  const includeMeta = !useKeyset && options.includeMeta !== false;
  const queryParts = [`limit=${state.reportLimit}`];
  if (beforeId > 0) {
    queryParts.push(`before_id=${beforeId}`, "include_meta=0");
  } else if (afterId > 0) {
    queryParts.push(`after_id=${afterId}`, "include_meta=0");
  } else {
    queryParts.push(`offset=${state.reportOffset}`);
    if (!includeMeta) {
      queryParts.push("include_meta=0");
    }
  }
  if (jumpToUtc) {
    queryParts.push(`jump_to_utc=${encodeURIComponent(jumpToUtc)}`);
  }
  const query = queryParts.join("&");
  return state.selectedHostUid
    ? `/api/v1/host-reports?host_uid=${hostUidParam}&${query}`
    : `/api/v1/host-reports?hostname=${hostNameParam}&${query}`;
}

async function loadReportsForHost(options = {}) {
  const jumpToUtc = typeof options?.jumpToUtc === "string" ? options.jumpToUtc.trim() : "";
  const list = document.getElementById("reportList");
  const count = document.getElementById("reportCount");
  const reportJumpDateInput = document.getElementById("reportJumpDateTimeInput");
  const reportJumpBounds = document.getElementById("reportJumpBounds");

  if (!state.selectedHost && !state.selectedHostUid) {
    state.currentReport = null;
    count.textContent = "";
    updateSelectedHostControls();
    if (reportJumpDateInput) {
      reportJumpDateInput.value = "";
      reportJumpDateInput.removeAttribute("min");
      reportJumpDateInput.removeAttribute("max");
    }
    if (reportJumpBounds) {
      reportJumpBounds.textContent = "";
      reportJumpBounds.classList.add("hidden");
    }
    list.innerHTML = state.hostFilterNoMatches
      ? "<p class=\"muted\">Keine Daten zum Suchfilter vorhanden.</p>"
      : "<p class=\"muted\">Bitte einen Host auswählen, um Daten zu laden.</p>";
    updateHeaderStatChips();
    updatePagerButtons();
    return;
  }

  list.innerHTML = "<p class=\"muted\">Lade Daten...</p>";
  count.textContent = "";
  updateSelectedHostControls();

  try {
    const url = buildHostReportsUrl(options);
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error("HTTP " + response.status);
    }

    const data = await response.json();
    const hostKey = asText(state.selectedHostUid, "").trim() || asText(state.selectedHost, "").trim();
    let totalReports = Number(data.total_reports || 0);
    let oldestReportAtUtc = asText(data.oldest_report_at_utc, "");
    let newestReportAtUtc = asText(data.newest_report_at_utc, "");
    if (totalReports > 0) {
      state.hostReportMeta = {
        hostKey,
        total_reports: totalReports,
        oldest_report_at_utc: oldestReportAtUtc,
        newest_report_at_utc: newestReportAtUtc,
      };
    } else if (state.hostReportMeta && state.hostReportMeta.hostKey === hostKey) {
      totalReports = Number(state.hostReportMeta.total_reports || 0);
      oldestReportAtUtc = asText(state.hostReportMeta.oldest_report_at_utc, oldestReportAtUtc);
      newestReportAtUtc = asText(state.hostReportMeta.newest_report_at_utc, newestReportAtUtc);
    }
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
      if (oldestReportAtUtc) {
        const oldestReportText = asText(formatUtcPlus2(oldestReportAtUtc), "-").trim();
        reportJumpBounds.textContent = `Erste Nachricht: ${oldestReportText}`;
        reportJumpBounds.title = `Älteste gespeicherte Meldung für diesen Host (${oldestReportText})`;
        reportJumpBounds.classList.remove("hidden");
      } else {
        reportJumpBounds.textContent = "";
        reportJumpBounds.removeAttribute("title");
        reportJumpBounds.classList.add("hidden");
      }
    }
    const usedKeyset = Number(options.beforeId || 0) > 0 || Number(options.afterId || 0) > 0;
    if (!usedKeyset && Number.isFinite(Number(data.offset))) {
      state.reportOffset = Math.max(0, Number(data.offset));
    }
    state.totalReports = totalReports;
    const reports = data.reports || [];

    if (reports.length === 0) {
      state.currentReport = null;
      list.innerHTML = "<p class=\"muted\">Noch keine Daten vorhanden.</p>";
      count.textContent = "Meldung 0";
      if (reportJumpDateInput) {
        reportJumpDateInput.value = "";
      }
      updateHeaderFirstRowControls();
      updateHeaderStatChips();
      updatePagerButtons();
      return;
    }

    const shownIndex = state.reportOffset + 1;
    count.textContent = `Meldung ${shownIndex}`;
    state.selectedDisplayName = String(reports[0].display_name || reports[0].hostname || state.selectedHost);
    state.currentReport = reports[0];
    list.innerHTML = renderReportCard(state.currentReport);
    wireSapVersionMapCopyButtons(list);
    wireReportHierarchyToggleButtons(list);
    updateHeaderFirstRowControls();
    updateHeaderStatChips();
    updateReportChromeBar();
    renderOverviewHostMetrics();
    updatePagerButtons();
  } catch (error) {
    state.currentReport = null;
    list.innerHTML = `<p class=\"muted\">${escapeHtml(formatApiLoadError(error.message, "Einzelmeldungen"))}</p>`;
    updateHeaderStatChips();
    updateReportChromeBar();
    renderOverviewHostMetrics();
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
    window.alert("Ungültiges Datum/Uhrzeit.");
    return;
  }

  await refreshSelectedHostPanels({ reportOptions: { jumpToUtc: parsed.toISOString() } });
}

async function jumpToLatestReport() {
  if (!state.selectedHost) {
    return;
  }
  state.reportOffset = 0;
  await refreshSelectedHostPanels();
}

function renderCurrentReportInView() {
  const list = document.getElementById("reportList");
  if (!state.currentReport) {
    return;
  }
  list.innerHTML = renderReportCard(state.currentReport);
  wireSapVersionMapCopyButtons(list);
  wireReportHierarchyToggleButtons(list);
  updateReportChromeBar();
  renderOverviewHostMetrics();
}

async function editDisplayName() {
  if (!state.selectedHost) {
    return;
  }

  const [hostSettingsResp, customersResp] = await Promise.all([
    fetch(`/api/v1/host-settings?hostname=${encodeURIComponent(state.selectedHost)}&host_uid=${encodeURIComponent(state.selectedHostUid || "")}`),
    fetch("/api/v1/customers"),
  ]);
  if (!hostSettingsResp.ok) {
    throw new Error("Host-Einstellungen konnten nicht geladen werden (HTTP " + hostSettingsResp.status + ")");
  }
  if (!customersResp.ok) {
    throw new Error("Kundenliste konnte nicht geladen werden (HTTP " + customersResp.status + ")");
  }

  const hostSettings = await hostSettingsResp.json();
  const customersPayload = await customersResp.json();
  const customers = Array.isArray(customersPayload.customers) ? customersPayload.customers : [];

  const result = await openHostMetadataEditorDialog({
    hostname: state.selectedHost,
    currentDisplayName: asText(hostSettings.display_name_override, state.selectedDisplayName || state.selectedHost),
    currentCountryCode: asText(hostSettings.country_code_override, ""),
    currentEnvironmentType: asText(hostSettings.environment_type, ""),
    currentCustomerId: hostSettings.customer_id,
    currentCustomerName: asText(hostSettings.customer_name, ""),
    currentCustomerProjectNo: asText(hostSettings.customer_maringo_project_number, ""),
    currentItProviderContacts: getItProviderContactsFromHostSettings(hostSettings),
    customers,
  });
  if (!result) return;

  let customerId = null;
  if (result.customerMode === "existing") {
    customerId = Number(result.existingCustomerId || 0);
    if (!Number.isFinite(customerId) || customerId <= 0) {
      throw new Error("Bitte einen gültigen Kunden auswählen.");
    }
  } else if (result.customerMode === "new") {
    const createResp = await fetch("/api/v1/customers", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        customer_name: result.newCustomerName,
        maringo_project_number: result.newCustomerProjectNo,
        it_provider_name: result.itProviderContacts[0].it_provider_name,
        it_provider_contact: result.itProviderContacts[0].it_provider_contact,
        it_provider_email: result.itProviderContacts[0].it_provider_email,
        it_provider_phone: result.itProviderContacts[0].it_provider_phone,
        it_provider_name_2: result.itProviderContacts[1].it_provider_name,
        it_provider_contact_2: result.itProviderContacts[1].it_provider_contact,
        it_provider_email_2: result.itProviderContacts[1].it_provider_email,
        it_provider_phone_2: result.itProviderContacts[1].it_provider_phone,
        it_provider_name_3: result.itProviderContacts[2].it_provider_name,
        it_provider_contact_3: result.itProviderContacts[2].it_provider_contact,
        it_provider_email_3: result.itProviderContacts[2].it_provider_email,
        it_provider_phone_3: result.itProviderContacts[2].it_provider_phone,
      }),
    });
    const createData = await createResp.json().catch(() => ({}));
    if (!createResp.ok) {
      throw new Error(createData.error || ("HTTP " + createResp.status));
    }
    customerId = Number(createData?.customer?.id || 0);
    if (!Number.isFinite(customerId) || customerId <= 0) {
      throw new Error("Kunde konnte nicht angelegt werden.");
    }
  }

  if (result.customerMode === "existing" && customerId) {
    const patchResp = await fetch(`/api/v1/customers/${encodeURIComponent(customerId)}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        customer_name: result.existingCustomerName,
        maringo_project_number: result.existingCustomerProjectNo,
        it_provider_name: result.itProviderContacts[0].it_provider_name,
        it_provider_contact: result.itProviderContacts[0].it_provider_contact,
        it_provider_email: result.itProviderContacts[0].it_provider_email,
        it_provider_phone: result.itProviderContacts[0].it_provider_phone,
        it_provider_name_2: result.itProviderContacts[1].it_provider_name,
        it_provider_contact_2: result.itProviderContacts[1].it_provider_contact,
        it_provider_email_2: result.itProviderContacts[1].it_provider_email,
        it_provider_phone_2: result.itProviderContacts[1].it_provider_phone,
        it_provider_name_3: result.itProviderContacts[2].it_provider_name,
        it_provider_contact_3: result.itProviderContacts[2].it_provider_contact,
        it_provider_email_3: result.itProviderContacts[2].it_provider_email,
        it_provider_phone_3: result.itProviderContacts[2].it_provider_phone,
      }),
    });
    const patchData = await patchResp.json().catch(() => ({}));
    if (!patchResp.ok) {
      throw new Error(patchData.error || ("HTTP " + patchResp.status));
    }
  }

  await saveHostSettings(state.selectedHost, {
    display_name_override: result.displayName,
    country_code_override: result.countryCode,
    environment_type: result.environmentType,
    customer_id: customerId,
  }, state.selectedHostUid || "");

  let logoUploadError = "";
  if (result.customerLogoFile) {
    if (!customerId) {
      logoUploadError = "Bitte zuerst einen Kunden auswählen oder anlegen, bevor ein Logo hochgeladen wird.";
    } else {
      try {
        await uploadCustomerLogo(customerId, result.customerLogoFile);
      } catch (error) {
        logoUploadError = error.message || "Logo-Upload fehlgeschlagen.";
      }
    }
  }

  await loadHosts();
  await loadReportsForHost();
  if (logoUploadError) {
    window.alert(`Kundenlogo konnte nicht gespeichert werden: ${logoUploadError}`);
  }
}

function readFileAsDataUrl(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("Datei konnte nicht gelesen werden."));
    reader.onload = () => resolve(String(reader.result || ""));
    reader.readAsDataURL(file);
  });
}

async function uploadCustomerLogo(customerId, file) {
  const cid = Number(customerId || 0);
  if (!Number.isFinite(cid) || cid <= 0) {
    throw new Error("Ungültige Kunden-ID.");
  }
  if (!(file instanceof File)) {
    throw new Error("Kein Logo ausgewählt.");
  }
  if (Number(file.size || 0) <= 0) {
    throw new Error("Leere Datei.");
  }
  if (Number(file.size || 0) > 2 * 1024 * 1024) {
    throw new Error("Logo ist zu groß (max. 2 MB).");
  }

  const imageData = await readFileAsDataUrl(file);
  const response = await fetch("/api/v1/customers/logo", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      customer_id: cid,
      file_name: String(file.name || "logo.png"),
      image_data: imageData,
    }),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(payload?.error || ("HTTP " + response.status));
  }
  return payload;
}

async function openHostMetadataEditorDialog({
  hostname,
  currentDisplayName,
  currentCountryCode,
  currentEnvironmentType,
  currentCustomerId,
  currentCustomerName,
  currentCustomerProjectNo,
  currentItProviderContacts,
  customers,
}) {
  const sortedCustomers = (Array.isArray(customers) ? customers : [])
    .slice()
    .sort((a, b) => String(a.customer_name || "").localeCompare(String(b.customer_name || ""), undefined, { sensitivity: "base" }));
  const initialSelectedCustomer = sortedCustomers.find((item) => Number(item.id || 0) === Number(currentCustomerId || 0)) || null;
  const initialCustomerLogoUrl = asText(initialSelectedCustomer?.logo_url, "").trim();
  const initialProviderContacts = normalizeItProviderContacts(currentItProviderContacts);
  const providerRowsHtml = initialProviderContacts.map((entry, index) => {
    const slot = index + 1;
    return `<div class="host-meta-provider-row" data-provider-row data-provider-slot="${slot}">
      <p class="settings-helper-text host-meta-provider-row-title">Ansprechpartner ${slot}</p>
      <div class="host-meta-customer-provider-grid">
        <label class="host-meta-customer-provider-span">IT Provider Name
          <input id="hostMetaItProviderNameInput${slot}" type="text" placeholder="IT Provider Name" value="${escapeHtml(entry.it_provider_name)}" />
        </label>
        <label class="host-meta-customer-provider-span">Ansprechpartner
          <input id="hostMetaItProviderContactInput${slot}" type="text" placeholder="Ansprechpartner" value="${escapeHtml(entry.it_provider_contact)}" />
        </label>
        <label>Mail
          <input id="hostMetaItProviderEmailInput${slot}" type="email" placeholder="it@example.com" value="${escapeHtml(entry.it_provider_email)}" />
        </label>
        <label>Telefon
          <input id="hostMetaItProviderPhoneInput${slot}" type="text" placeholder="+41 ..." value="${escapeHtml(entry.it_provider_phone)}" />
        </label>
      </div>
      ${slot > 1 ? `<div class="host-meta-provider-row-actions"><button type="button" class="btn-secondary btn-secondary--compact" data-provider-remove-slot="${slot}">Ansprechpartner ${slot} entfernen</button></div>` : ""}
    </div>`;
  }).join("");

  const modal = document.createElement("div");
  modal.className = "host-meta-modal";
  modal.innerHTML = `<div class="host-meta-modal-backdrop"></div>
    <div class="host-meta-modal-inner" role="dialog" aria-modal="true" aria-label="Host bearbeiten">
      <div class="chart-drill-header">
        <div class="chart-drill-title">Host bearbeiten: ${escapeHtml(hostname || "")}</div>
        <button type="button" class="btn-secondary btn-secondary--compact" data-action="cancel">Schließen</button>
      </div>
      <div class="chart-drill-body host-meta-modal-body">
        <div class="host-meta-modal-grid">
          <label>Sprechender Titel
            <input id="hostMetaDisplayNameInput" type="text" placeholder="z.B. Kunde XY PROD" value="${escapeHtml(currentDisplayName || "")}" />
          </label>
          <label>Land (2-stellig)
            <input id="hostMetaCountryCodeInput" type="text" maxlength="2" placeholder="CH, DE ..." value="${escapeHtml((currentCountryCode || "").toUpperCase())}" />
          </label>
          <label>Umgebung
            <select id="hostMetaEnvironmentTypeSelect">
              <option value="">Keine Angabe</option>
              <option value="prod" ${String(currentEnvironmentType || "").toLowerCase() === "prod" ? "selected" : ""}>Prod.</option>
              <option value="test" ${String(currentEnvironmentType || "").toLowerCase() === "test" ? "selected" : ""}>Test</option>
            </select>
          </label>
          <label>Kunde
            <select id="hostMetaCustomerSelect">
              <option value="__none__">Kein Kunde</option>
              ${sortedCustomers.map((item) => {
                const id = Number(item.id || 0);
                const name = String(item.customer_name || "");
                const project = String(item.maringo_project_number || "");
                const selected = currentCustomerId === id ? "selected" : "";
                const label = project ? `${name} (Maringo: ${project})` : name;
                return `<option value="${id}" ${selected}>${escapeHtml(label)}</option>`;
              }).join("")}
              <option value="__new__">+ Neuer Kunde ...</option>
            </select>
          </label>
        </div>
        <div id="hostMetaNewCustomerWrap" class="host-meta-new-customer hidden">
          <label>Neuer Kundenname
            <input id="hostMetaNewCustomerNameInput" type="text" placeholder="Kundenname" value="${escapeHtml(currentCustomerId ? "" : (currentCustomerName || ""))}" />
          </label>
          <label>Maringo Projektnummer (optional)
            <input id="hostMetaNewCustomerProjectInput" type="text" placeholder="z.B. MAR-12345" value="${escapeHtml(currentCustomerId ? "" : (currentCustomerProjectNo || ""))}" />
          </label>
        </div>
        <div class="host-meta-customer-provider">
          <h4>IT-Provider (kundenspezifisch)</h4>
          <div class="host-meta-provider-toolbar">
            <button id="hostMetaAddProviderRowBtn" type="button" class="btn-secondary btn-secondary--compact">+ Ansprechpartner hinzufügen</button>
          </div>
          ${providerRowsHtml}
        </div>
        <div class="host-meta-logo-upload-row">
          <label>Kundenlogo (PNG/JPG/WebP, max. 2 MB)
            <input id="hostMetaCustomerLogoInput" type="file" accept="image/png,image/jpeg,image/webp" />
          </label>
        </div>
        <div class="host-meta-logo-preview-row">
          <p class="settings-helper-text">Hinterlegtes Kundenlogo</p>
          <div id="hostMetaCustomerLogoPreviewWrap" class="customer-logo-preview-wrap">
            ${initialCustomerLogoUrl
              ? `<img src="${escapeHtml(initialCustomerLogoUrl)}" alt="Kundenlogo" class="customer-logo-preview">`
              : '<span class="customer-logo-preview-placeholder">Noch kein Logo</span>'}
          </div>
        </div>
        <p class="settings-helper-text">Hinweis: Bestehende Kunden bitte aus dem Dropdown wählen, um Dubletten zu vermeiden.</p>
        <div class="host-meta-modal-actions">
          <button type="button" class="btn-secondary" data-action="cancel">Abbrechen</button>
          <button type="button" class="btn-primary" data-action="save">Speichern</button>
        </div>
      </div>
    </div>`;

  document.body.appendChild(modal);

  const selectEl = modal.querySelector("#hostMetaCustomerSelect");
  const wrapNew = modal.querySelector("#hostMetaNewCustomerWrap");
  const displayNameInput = modal.querySelector("#hostMetaDisplayNameInput");
  const countryCodeInput = modal.querySelector("#hostMetaCountryCodeInput");
  const environmentTypeSelect = modal.querySelector("#hostMetaEnvironmentTypeSelect");
  const newCustomerNameInput = modal.querySelector("#hostMetaNewCustomerNameInput");
  const newCustomerProjectInput = modal.querySelector("#hostMetaNewCustomerProjectInput");
  const addProviderRowButton = modal.querySelector("#hostMetaAddProviderRowBtn");
  const logoPreviewWrap = modal.querySelector("#hostMetaCustomerLogoPreviewWrap");
  const providerInputRows = [1, 2, 3].map((slot) => ({
    slot,
    row: modal.querySelector(`[data-provider-row][data-provider-slot="${slot}"]`),
    removeBtn: modal.querySelector(`[data-provider-remove-slot="${slot}"]`),
    itProviderNameInput: modal.querySelector(`#hostMetaItProviderNameInput${slot}`),
    itProviderContactInput: modal.querySelector(`#hostMetaItProviderContactInput${slot}`),
    itProviderEmailInput: modal.querySelector(`#hostMetaItProviderEmailInput${slot}`),
    itProviderPhoneInput: modal.querySelector(`#hostMetaItProviderPhoneInput${slot}`),
  }));
  const customerLogoInput = modal.querySelector("#hostMetaCustomerLogoInput");
  let visibleProviderRows = deriveInitialVisibleItProviderRows(initialProviderContacts);

  const buildLogoPreviewUrl = (url) => {
    const raw = asText(url, "").trim();
    if (!raw) return "";
    const separator = raw.includes("?") ? "&" : "?";
    return `${raw}${separator}preview_ts=${Date.now()}`;
  };

  const updateLogoPreview = (logoUrl) => {
    if (!logoPreviewWrap) {
      return;
    }
    const previewUrl = buildLogoPreviewUrl(logoUrl);
    if (!previewUrl) {
      logoPreviewWrap.innerHTML = '<span class="customer-logo-preview-placeholder">Noch kein Logo</span>';
      return;
    }
    logoPreviewWrap.innerHTML = `<img src="${escapeHtml(previewUrl)}" alt="Kundenlogo" class="customer-logo-preview" onerror="this.parentElement.innerHTML='&lt;span class=&quot;customer-logo-preview-placeholder&quot;&gt;Logo konnte nicht geladen werden&lt;/span&gt;'">`;
  };

  const syncProviderRowsUi = () => {
    for (const rowInputs of providerInputRows) {
      if (rowInputs.row) {
        rowInputs.row.classList.toggle("hidden", rowInputs.slot > visibleProviderRows);
      }
      if (rowInputs.removeBtn) {
        rowInputs.removeBtn.classList.toggle("hidden", rowInputs.slot !== visibleProviderRows || visibleProviderRows <= 1);
      }
    }
    if (addProviderRowButton) {
      addProviderRowButton.classList.toggle("hidden", visibleProviderRows >= 3);
    }
  };

  const clearProviderSlot = (slot) => {
    const rowInputs = providerInputRows[slot - 1];
    if (!rowInputs) return;
    if (rowInputs.itProviderNameInput) rowInputs.itProviderNameInput.value = "";
    if (rowInputs.itProviderContactInput) rowInputs.itProviderContactInput.value = "";
    if (rowInputs.itProviderEmailInput) rowInputs.itProviderEmailInput.value = "";
    if (rowInputs.itProviderPhoneInput) rowInputs.itProviderPhoneInput.value = "";
  };

  const setProviderRowsFromContacts = (contacts) => {
    const normalized = normalizeItProviderContacts(contacts);
    for (let index = 0; index < providerInputRows.length; index += 1) {
      const rowInputs = providerInputRows[index];
      const values = normalized[index] || {};
      if (rowInputs.itProviderNameInput) rowInputs.itProviderNameInput.value = asText(values.it_provider_name, "");
      if (rowInputs.itProviderContactInput) rowInputs.itProviderContactInput.value = asText(values.it_provider_contact, "");
      if (rowInputs.itProviderEmailInput) rowInputs.itProviderEmailInput.value = asText(values.it_provider_email, "");
      if (rowInputs.itProviderPhoneInput) rowInputs.itProviderPhoneInput.value = asText(values.it_provider_phone, "");
    }
    visibleProviderRows = deriveInitialVisibleItProviderRows(normalized);
    syncProviderRowsUi();
  };

  const updateNewSection = () => {
    if (!selectEl || !wrapNew) return;
    wrapNew.classList.toggle("hidden", selectEl.value !== "__new__");

    if (selectEl.value === "__new__") {
      updateLogoPreview("");
      return;
    }

    if (selectEl.value === "__none__") {
      setProviderRowsFromContacts([]);
      updateLogoPreview("");
      return;
    }

    const selectedId = Number(selectEl.value || 0);
    const selectedCustomer = sortedCustomers.find((item) => Number(item.id || 0) === selectedId) || null;
    if (!selectedCustomer) {
      updateLogoPreview("");
      return;
    }
    setProviderRowsFromContacts(getItProviderContactsFromCustomer(selectedCustomer));
    updateLogoPreview(selectedCustomer.logo_url);
  };
  updateNewSection();
  if (selectEl) selectEl.addEventListener("change", updateNewSection);

  addProviderRowButton?.addEventListener("click", () => {
    visibleProviderRows = Math.min(3, visibleProviderRows + 1);
    syncProviderRowsUi();
  });

  for (const rowInputs of providerInputRows) {
    rowInputs.removeBtn?.addEventListener("click", () => {
      if (rowInputs.slot <= 1) {
        return;
      }
      for (let slot = rowInputs.slot; slot <= 3; slot += 1) {
        clearProviderSlot(slot);
      }
      visibleProviderRows = Math.max(1, rowInputs.slot - 1);
      syncProviderRowsUi();
    });
  }

  syncProviderRowsUi();

  if (displayNameInput) displayNameInput.focus();

  return await new Promise((resolve) => {
    let closed = false;
    const close = (value) => {
      if (closed) return;
      closed = true;
      modal.remove();
      resolve(value);
    };

    modal.querySelectorAll("[data-action='cancel']").forEach((button) => {
      button.addEventListener("click", () => close(null));
    });
    modal.querySelector(".host-meta-modal-backdrop")?.addEventListener("click", () => close(null));

    modal.querySelector("[data-action='save']")?.addEventListener("click", () => {
      const displayName = String(displayNameInput?.value || "").trim();
      const countryCode = String(countryCodeInput?.value || "").trim().toUpperCase();
      const environmentType = String(environmentTypeSelect?.value || "").trim().toLowerCase();
      if (countryCode && !/^[A-Z]{2}$/.test(countryCode)) {
        window.alert("Länderkürzel muss genau 2 Buchstaben haben (z.B. CH). ");
        countryCodeInput?.focus();
        return;
      }

      const customerSelectValue = String(selectEl?.value || "__none__");
      let customerMode = "none";
      let existingCustomerId = null;
      let existingCustomerName = "";
      let existingCustomerProjectNo = "";
      let newCustomerName = "";
      let newCustomerProjectNo = "";
      const itProviderContacts = providerInputRows.map((rowInputs) => ({
        it_provider_name: String(rowInputs.itProviderNameInput?.value || "").trim(),
        it_provider_contact: String(rowInputs.itProviderContactInput?.value || "").trim(),
        it_provider_email: String(rowInputs.itProviderEmailInput?.value || "").trim(),
        it_provider_phone: String(rowInputs.itProviderPhoneInput?.value || "").trim(),
      }));

      if (customerSelectValue === "__new__") {
        customerMode = "new";
        newCustomerName = String(newCustomerNameInput?.value || "").trim();
        newCustomerProjectNo = String(newCustomerProjectInput?.value || "").trim();
        if (!newCustomerName) {
          window.alert("Bitte einen Kundennamen für den neuen Kunden eingeben.");
          newCustomerNameInput?.focus();
          return;
        }
      } else if (customerSelectValue !== "__none__") {
        customerMode = "existing";
        existingCustomerId = Number(customerSelectValue);
        const selectedCustomer = sortedCustomers.find((item) => Number(item.id || 0) === existingCustomerId) || null;
        existingCustomerName = asText(selectedCustomer?.customer_name, "");
        existingCustomerProjectNo = asText(selectedCustomer?.maringo_project_number, "");
      }

      const customerLogoFile = customerLogoInput && customerLogoInput.files && customerLogoInput.files.length > 0
        ? customerLogoInput.files[0]
        : null;
      if (customerLogoFile && customerMode === "none") {
        window.alert("Bitte zuerst einen Kunden auswählen oder anlegen, damit das Logo gespeichert werden kann.");
        selectEl?.focus();
        return;
      }

      close({
        displayName,
        countryCode,
        environmentType,
        customerMode,
        existingCustomerId,
        existingCustomerName,
        existingCustomerProjectNo,
        newCustomerName,
        newCustomerProjectNo,
        itProviderContacts,
        customerLogoFile,
      });
    });

    const onEsc = (event) => {
      if (event.key === "Escape") {
        event.preventDefault();
        document.removeEventListener("keydown", onEsc);
        close(null);
      }
    };
    document.addEventListener("keydown", onEsc, { once: true });
  });
}

async function loadAnalysisForHost() {
  const analysisSummary = document.getElementById("analysisSummary");
  const analysisRows = document.getElementById("analysisRows");
  const resourceCharts = document.getElementById("resourceCharts");
  const filesystemStats = document.getElementById("filesystemStats");
  const filesystemCharts = document.getElementById("filesystemCharts");
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
    resourceCharts.innerHTML = "";
    filesystemStats.textContent = "";
    filesystemCharts.innerHTML = "";
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
  if (largeFilesPanel) largeFilesPanel.classList.add("hidden");
  if (largeFilesBody) largeFilesBody.innerHTML = "";
  analysisSummary.textContent = "";
  filesystemStats.textContent = "";
  updateFilesystemVisibilityButtons();

  try {
    const hostNameParam = encodeURIComponent(state.selectedHost);
    const hostUidParam = encodeURIComponent(state.selectedHostUid || "");
    const hostQuery = state.selectedHostUid
      ? `host_uid=${hostUidParam}`
      : `hostname=${hostNameParam}`;
    const url = `/api/v1/analysis?${hostQuery}&hours=${state.analysisHours}`;
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
    const chartEligibleRows = visibleTrendRows.filter((row) => shouldShowFilesystemGraph(row?.mountpoint));
    const sortedTrendRows = sortFilesystemByMountpointAscending(chartEligibleRows);
    const resourceSeries = data.resource_series || {};
    const latestMax = formatPercent(data.latest_max_used_percent);
    const reportCount = Number(data.report_count || 0).toLocaleString("de-DE");

    analysisSummary.textContent = `${reportCount} Reports, hoechste aktuelle FS-Auslastung: ${latestMax}`;
    resourceCharts.innerHTML = renderResourceCharts(resourceSeries, data.latest_report_time_utc);
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
      fsTabBtn.innerHTML = fsWarnOrCritical > 0
        ? `<span class="osi-icon">💾</span> Filesysteme ⚠ ${fsWarnOrCritical}`
        : `<span class="osi-icon">💾</span> Filesysteme`;
    }

    filesystemCharts.querySelectorAll(".fs-chart-card").forEach((card, idx) => {
      card.style.cursor = "zoom-in";
      card.addEventListener("click", () => {
        const item = sortedTrendRows[idx];
        if (item) openChartDrillModal(item, data.latest_report_time_utc);
      });
    });

    if (sortedTrendRows.length === 0) {
      filesystemCharts.innerHTML = "<p class=\"muted\">Keine Filesystem-Verlaufskurven verfügbar.</p>";
      analysisRows.innerHTML =
        "<tr><td colspan=\"7\" class=\"muted\">Keine Analyse-Daten im gewählten Zeitfenster.</td></tr>";
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

async function refreshAlertsAfterMutation() {
  if (state.selectedHost) {
    await loadAlertsForHost();
  }
  const onGlobalAlerts = state.viewMode === "global" && state.globalSubMode === "global-alerts";
  await loadGlobalAlertsOverview({ updateList: onGlobalAlerts });
  void loadHosts();
}

async function toggleAlertMute(hostname, hostUid, mountpoint, alertId, currentlyMuted) {
  const endpoint = currentlyMuted ? "/api/v1/alert-unmute" : "/api/v1/alert-mute";
  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify({ hostname, host_uid: hostUid, mountpoint, alert_id: alertId }),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || ("HTTP " + response.status));
  }
  await refreshAlertsAfterMutation();
}

async function toggleAlertHeadsUpSuppression(hostname, hostUid, mountpoint, alertId, currentlySuppressed) {
  const endpoint = currentlySuppressed ? "/api/v1/alert-headsup-unsuppress" : "/api/v1/alert-headsup-suppress";
  const response = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify({ hostname, host_uid: hostUid, mountpoint, alert_id: alertId }),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.error || ("HTTP " + response.status));
  }
  await refreshAlertsAfterMutation();
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
    const closeBtn = document.getElementById("ackModalCloseBtn");
    const cancelBtn = document.getElementById("ackModalCancelBtn");
    const backdrop = document.getElementById("ackModalBackdrop");
    const statusEl = document.getElementById("ackModalStatus");

    if (!modal || !titleEl || !subtitleEl || !noteInput || !confirmBtn || !unackBtn || !statusEl) {
      resolve(null);
      return;
    }

    // Bind modal actions on every open to avoid stale or missing listeners.
    confirmBtn.onclick = () => {
      const note = String(noteInput.value || "").trim();
      closeAckModal({ note });
    };
    unackBtn.onclick = () => {
      closeAckModal({ unack: true });
    };
    if (closeBtn) closeBtn.onclick = () => closeAckModal(null);
    if (cancelBtn) cancelBtn.onclick = () => closeAckModal(null);
    if (backdrop) backdrop.onclick = () => closeAckModal(null);

    titleEl.textContent = isAcknowledged ? "Quittierung bearbeiten" : "Alert quittieren";
    subtitleEl.textContent = `${hostname} - ${mountpoint}`;
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

async function acknowledgeAlert(hostname, hostUid, mountpoint, alertId, currentNote = "", isAcknowledged = false) {
  const result = await openAckModal(hostname, mountpoint, currentNote, isAcknowledged);
  if (!result) return;

  const statusEl = document.getElementById("ackModalStatus");
  if (statusEl) statusEl.textContent = "Wird gespeichert…";

  try {
    if (result.unack) {
      const response = await fetch("/api/v1/alert-unack", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ hostname, host_uid: hostUid, mountpoint, alert_id: alertId }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || ("HTTP " + response.status));
    } else {
      const response = await fetch("/api/v1/alert-ack", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          hostname,
          host_uid: hostUid,
          mountpoint,
          alert_id: alertId,
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
  await refreshAlertsAfterMutation();
}

async function closeAlert(hostname, hostUid, mountpoint, alertId, isClosed) {
  try {
    const url = isClosed ? "/api/v1/alert-unclose" : "/api/v1/alert-close";
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hostname, host_uid: hostUid, mountpoint, alert_id: alertId }),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || ("HTTP " + response.status));
  } catch (err) {
    alert(`Fehler: ${err.message}`);
    return;
  }
  await refreshAlertsAfterMutation();
}

function currentHostAlertsCollapseKey() {
  return `${asText(state.selectedHostUid, "").trim()}|${asText(state.selectedHost, "").trim()}`;
}

function applyHostAlertsPanelCollapsed(collapsed) {
  const panelBody = document.getElementById("hostAlertsPanelBody");
  const toggleButton = document.getElementById("toggleHostAlertsPanelButton");
  const panel = document.querySelector("#overviewMainSection .alerts-panel--overview-top");
  state.hostAlertsCollapsed = collapsed === true;
  if (panelBody) {
    panelBody.classList.toggle("hidden", state.hostAlertsCollapsed);
  }
  if (toggleButton) {
    toggleButton.textContent = state.hostAlertsCollapsed ? "▸" : "▾";
    toggleButton.setAttribute("aria-expanded", state.hostAlertsCollapsed ? "false" : "true");
  }
  if (panel) {
    panel.classList.toggle("alerts-panel--collapsed", state.hostAlertsCollapsed);
  }
}

function setHostAlertsCollapsedAuto(openAlertCount) {
  const hostKey = currentHostAlertsCollapseKey();
  const openCount = Number(openAlertCount || 0);
  if (hostKey !== state.hostAlertsCollapseHostKey) {
    state.hostAlertsCollapseHostKey = hostKey;
    state.hostAlertsUserToggled = false;
  }
  if (openCount > 0) {
    state.hostAlertsUserToggled = false;
    applyHostAlertsPanelCollapsed(false);
    return;
  }
  if (!state.hostAlertsUserToggled) {
    applyHostAlertsPanelCollapsed(true);
  } else {
    applyHostAlertsPanelCollapsed(state.hostAlertsCollapsed);
  }
}

async function loadAlertsForHost() {
  const alertsSummary = document.getElementById("alertsSummary");
  const alertsRows = document.getElementById("alertsRows");

  if (!state.selectedHost) {
    state.hostAlertsCollapseHostKey = "";
    state.hostAlertsUserToggled = false;
    applyHostAlertsPanelCollapsed(true);
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
    const hostUidParam = encodeURIComponent(state.selectedHostUid || "");
    const hostQuery = state.selectedHostUid
      ? `host_uid=${hostUidParam}`
      : `hostname=${hostNameParam}`;
    const [summaryResp, listResp] = await Promise.all([
      fetch(`/api/v1/alerts-summary?${hostQuery}`),
      fetch(`/api/v1/alerts?${hostQuery}&status=open&limit=50&offset=0`),
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

    const openTotal = Number(summaryData.open?.total || 0);
    alertsSummary.textContent = `Offen: ${openTotal} (kritisch ${summaryData.open.critical}, warn ${summaryData.open.warning})`;
    setHostAlertsCollapsedAuto(openTotal);

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
          ? `Quittiert von ${resolveWebUserActionLabel(item, "ack_by") || "-"} am ${formatUtcPlus2(item.ack_at_utc)}${ackNote ? ` | Notiz: ${ackNote}` : ""}`
          : "Alert quittieren";
        const isHeadsUpSuppressed = Boolean(item.is_heads_up_suppressed);
        const headsUpTitle = isHeadsUpSuppressed
          ? "Heads-Up wieder aktivieren"
          : "Heads-Up für diesen Alert unterdrücken";
        const closeTitle = isClosed
          ? `Abgeschlossen von ${resolveWebUserActionLabel(item, "closed_by") || "-"} am ${formatUtcPlus2(item.closed_at_utc)} – klicken zum Wiederöffnen`
          : "Alert abschliessen";
        const hostUid = asText(item.host_uid || item.hostname);
        const alertId = Number(item.id || 0);
        const muteBtn = `<button class="alert-mute-btn${isMuted ? " muted" : ""}" type="button" data-action="toggle-mute" data-alert-id="${alertId}" data-hostname="${escapeHtml(asText(item.hostname))}" data-host-uid="${escapeHtml(hostUid)}" data-mountpoint="${escapeHtml(asText(item.mountpoint))}" data-muted="${isMuted ? "1" : "0"}" title="${isMuted ? "Stummschaltung aufheben" : "Alert stummschalten"}">${isMuted ? "🔇" : "🔔"}</button>`;
        const headsUpBtn = `<button class="alert-headsup-btn${isHeadsUpSuppressed ? " suppressed" : ""}" type="button" data-action="toggle-headsup" data-alert-id="${alertId}" data-hostname="${escapeHtml(asText(item.hostname))}" data-host-uid="${escapeHtml(hostUid)}" data-mountpoint="${escapeHtml(asText(item.mountpoint))}" data-headsup-suppressed="${isHeadsUpSuppressed ? "1" : "0"}" title="${escapeHtml(headsUpTitle)}">${isHeadsUpSuppressed ? "⏸️" : "📣"}</button>`;
        const ackBtn = `<button class="alert-ack-btn${isAcknowledged ? " acknowledged" : ""}" type="button" data-action="ack" data-alert-id="${alertId}" data-acknowledged="${isAcknowledged ? "1" : "0"}" data-hostname="${escapeHtml(asText(item.hostname))}" data-host-uid="${escapeHtml(hostUid)}" data-mountpoint="${escapeHtml(asText(item.mountpoint))}" data-ack-note="${encodeURIComponent(ackNote)}" title="${escapeHtml(ackTitle)}">${isAcknowledged ? "✅" : "✓"}</button>`;
        const closeBtn = `<button class="alert-close-btn${isClosed ? " closed" : ""}" type="button" data-action="close" data-alert-id="${alertId}" data-hostname="${escapeHtml(asText(item.hostname))}" data-host-uid="${escapeHtml(hostUid)}" data-mountpoint="${escapeHtml(asText(item.mountpoint))}" data-closed="${isClosed ? "1" : "0"}" title="${escapeHtml(closeTitle)}">${isClosed ? "↺" : "✕"}</button>`;
        const ackMeta = isAcknowledged
          ? `<div class="count compact">✅ ${escapeHtml(resolveWebUserActionLabel(item, "ack_by") || "-")} | ${escapeHtml(formatUtcPlus2(item.ack_at_utc))}</div>`
          : "";
        const closeMeta = isClosed
          ? `<div class="count compact alert-closed-meta">🔒 ${escapeHtml(resolveWebUserActionLabel(item, "closed_by") || "-")} | ${escapeHtml(formatUtcPlus2(item.closed_at_utc))}</div>`
          : "";
        const currentReportStand = asText(item.current_report_at_utc, "").trim();
        const currentReportStandHtml = currentReportStand
          ? `<div class="count compact">Stand: ${escapeHtml(formatUtcPlus2(currentReportStand))}</div>`
          : "";
        return `
          <tr class="${isMuted ? "alert-row-muted" : ""}${isClosed ? " alert-row-closed" : ""}">
            <td><span class="badge ${statusClass}">${escapeHtml(asText(item.status))}</span></td>
            <td><span class="badge ${severityClass}">${escapeHtml(asText(item.severity))}</span></td>
            <td>${renderAlertMountpointLabel(item.mountpoint, 60)}</td>
            <td>${formatPercent(item.used_percent)}</td>
            <td title="Zuletzt gesehen: ${escapeHtml(formatUtcPlus2(item.last_seen_at_utc))}">${escapeHtml(formatUtcPlus2(item.created_at_utc))}${ackMeta}${closeMeta}</td>
            <td><div class="alert-action-buttons">${muteBtn}${headsUpBtn}${ackBtn}${closeBtn}</div></td>
          </tr>
        `;
      })
      .join("");

  } catch (error) {
    alertsRows.innerHTML = `<tr><td colspan="6" class="muted">Fehler: ${escapeHtml(error.message)}</td></tr>`;
  }
}

async function loadConfigChangelogForHost() {
  const configChangelogRows = document.getElementById("configChangelogRows");
  const configChangelogSummary = document.getElementById("configChangelogSummary");
  const pagingStatus = document.getElementById("configChangelogPagingStatus");
  const loadMoreBtn = document.getElementById("configChangelogLoadMoreButton");

  if (!state.selectedHost) {
    configChangelogSummary.textContent = "";
    configChangelogRows.innerHTML = state.hostFilterNoMatches
      ? "<tr><td colspan=\"5\" class=\"muted\">Keine Daten zum Suchfilter vorhanden.</td></tr>"
      : "<tr><td colspan=\"5\"><div class=\"empty-state\"><span>📝</span><p>Wähle einen Host, um den Changelog zu sehen.</p></div></td></tr>";
    pagingStatus.textContent = "";
    loadMoreBtn.classList.add("hidden");
    return;
  }

  configChangelogRows.innerHTML = "<tr><td colspan=\"4\" class=\"muted\">Lade Changelog...</td></tr>";
  configChangelogSummary.textContent = "";
  pagingStatus.textContent = "";

  try {
    const hostNameParam = encodeURIComponent(state.selectedHost);
    const hostUidParam = state.selectedHostUid ? `&host_uid=${encodeURIComponent(state.selectedHostUid)}` : "";
    const resp = await fetch(`/api/v1/host-changelog?hostname=${hostNameParam}${hostUidParam}&limit=100&offset=0`);

    if (!resp.ok) {
      throw new Error("HTTP " + resp.status);
    }

    const data = await resp.json();
    const items = data.items || [];
    const total = data.total || 0;
    const returned = data.returned || 0;

    configChangelogSummary.textContent = `Insgesamt: ${total} Changelog-Einträge`;

    if (items.length === 0) {
      configChangelogRows.innerHTML = "<tr><td colspan=\"4\" class=\"muted\">Keine Changelog-Einträge vorhanden.</td></tr>";
      pagingStatus.textContent = "";
      loadMoreBtn.classList.add("hidden");
      return;
    }

    configChangelogRows.innerHTML = items
      .map((item) => {
        const fieldLabel = asText(item.field_label || item.field_key);
        const oldValue = asText(item.old_value || "-");
        const newValue = asText(item.new_value || "-");
        const fieldKey = String(item.field_key || "");
        const licenseDeltaHtml = renderLicenseTypeCountDelta(fieldKey, oldValue, newValue);
        const numericDeltaHtml = renderHostConfigNumericDelta(fieldKey, oldValue, newValue);
        const deltaHtml = licenseDeltaHtml || numericDeltaHtml;
        let oldFpInfo = "";
        let newFpInfo = "";
        let oldValueHtml = `<code>${escapeHtml(oldValue)}</code>`;
        let newValueHtml = `<code>${escapeHtml(newValue)}</code>`;
        if (fieldKey === "sap_release") {
          const oldFp = resolveSapReleaseDisplay(oldValue, SAP_B1_VERSION_MAP);
          if (oldFp && oldFp !== "-" && oldFp !== oldValue) {
            oldFpInfo = ` <strong>(${escapeHtml(oldFp)})</strong>`;
          }
          const newFp = resolveSapReleaseDisplay(newValue, SAP_B1_VERSION_MAP);
          if (newFp && newFp !== "-" && newFp !== newValue) {
            newFpInfo = ` <strong>(${escapeHtml(newFp)})</strong>`;
          }
        }
        if (deltaHtml) {
          newValueHtml = `<code>${escapeHtml(newValue)}</code> ${deltaHtml}`;
        }

        return `
          <tr>
            <td><strong>${escapeHtml(fieldLabel)}</strong></td>
            <td>${oldValueHtml}${oldFpInfo}</td>
            <td>${newValueHtml}${newFpInfo}</td>
            
            <td>${escapeHtml(formatUtcPlus2(item.detected_at_utc))}</td>
          </tr>
        `;
      })
      .join("");

    pagingStatus.textContent = `Zeige ${returned} von ${total}`;
    loadMoreBtn.classList.toggle("hidden", returned >= total);
  } catch (error) {
    configChangelogRows.innerHTML = `<tr><td colspan="4" class="muted">Fehler: ${escapeHtml(error.message)}</td></tr>`;
    loadMoreBtn.classList.add("hidden");
  }
}

async function loadDatabaseLifecycleForHost() {
  const databaseLifecycleRows = document.getElementById("databaseLifecycleRows");
  const databaseLifecycleSummary = document.getElementById("databaseLifecycleSummary");
  const pagingStatus = document.getElementById("databaseLifecyclePagingStatus");
  const loadMoreBtn = document.getElementById("databaseLifecycleLoadMoreButton");

  if (!databaseLifecycleRows || !databaseLifecycleSummary || !pagingStatus || !loadMoreBtn) {
    return;
  }

  if (!state.selectedHost) {
    databaseLifecycleSummary.textContent = "";
    databaseLifecycleRows.innerHTML = state.hostFilterNoMatches
      ? "<tr><td colspan=\"5\" class=\"muted\">Keine Daten zum Suchfilter vorhanden.</td></tr>"
      : "<tr><td colspan=\"5\"><div class=\"empty-state\"><span>🗄️</span><p>Wähle einen Host, um den DB Changelog zu sehen.</p></div></td></tr>";
    pagingStatus.textContent = "";
    loadMoreBtn.classList.add("hidden");
    return;
  }

  databaseLifecycleRows.innerHTML = "<tr><td colspan=\"5\" class=\"muted\">Lade DB Changelog...</td></tr>";
  databaseLifecycleSummary.textContent = "";
  pagingStatus.textContent = "";

  try {
    const hostNameParam = encodeURIComponent(state.selectedHost);
    const hostUidParam = encodeURIComponent(state.selectedHostUid || "");
    const hostQuery = state.selectedHostUid
      ? `host_uid=${hostUidParam}`
      : `hostname=${hostNameParam}`;
    const resp = await fetch(`/api/v1/database-lifecycle?${hostQuery}&limit=100&offset=0`);

    if (!resp.ok) {
      throw new Error("HTTP " + resp.status);
    }

    const data = await resp.json();
    const events = data.events || [];
    const total = data.total || 0;
    const returned = data.returned || 0;

    databaseLifecycleSummary.textContent = `Insgesamt: ${total} DB-Changelog-Einträge`;

    if (events.length === 0) {
      databaseLifecycleRows.innerHTML = "<tr><td colspan=\"5\" class=\"muted\">Keine DB-Changelog-Einträge vorhanden.</td></tr>";
      pagingStatus.textContent = "";
      loadMoreBtn.classList.add("hidden");
      return;
    }

    databaseLifecycleRows.innerHTML = events
      .map((item) => {
        const actionBadgeClass = item.action === "create" ? "badge-success" : item.action === "delete" ? "badge-danger" : "badge-info";
        const triggeredByLabel = item.triggered_by === "system" ? "🖥️ System" : item.triggered_by === "admin" ? "👤 Admin" : "🤖 Agent";
        const reason = asText(item.reason || "-");
        const dbName = asText(item.database_name || "-");
        const instanceName = asText(item.instance_name || "MSSQLSERVER");
        const isHana = instanceName.toUpperCase() === "HANA";
        const instanceDisplay = instanceName.replace(/^HANA-T/i, "").trim() || instanceName;
        const actionLabel = isHana
          ? (item.action === "create" ? "✨ erstellt" : item.action === "delete" ? "🗑️ gelöscht" : "umbenannt")
          : (item.action === "create" ? "✨ Erstellt" : item.action === "delete" ? "🗑️ Gelöscht" : "Umbenannt");
        const dbLabel = isHana
          ? `Schema: ${dbName}`
          : (instanceName && instanceName.toUpperCase() !== "MSSQLSERVER" ? `${instanceDisplay} - ${dbName}` : dbName);

        return `
          <tr>
            <td>${escapeHtml(dbLabel)}</td>
            <td><span class="badge ${actionBadgeClass}">${actionLabel}</span></td>
            <td>${triggeredByLabel}</td>
            <td>${escapeHtml(formatUtcPlus2(item.triggered_at_utc))}</td>
            <td>${escapeHtml(reason)}</td>
          </tr>
        `;
      })
      .join("");

    pagingStatus.textContent = `Zeige ${returned} von ${total}`;
    loadMoreBtn.classList.toggle("hidden", returned >= total);
  } catch (error) {
    databaseLifecycleRows.innerHTML = `<tr><td colspan="5" class="muted">Fehler: ${escapeHtml(error.message)}</td></tr>`;
    loadMoreBtn.classList.add("hidden");
  }
}

function renderCriticalTrends(data) {
  const { warnings, hours, project_hours: projectHours } = data;
  if (!warnings || warnings.length === 0) {
    const safeProjectHoursEmpty = Number(projectHours) || 72;
    return `<div class="ct-empty"><span class="ct-empty-icon">✓</span><p>Keine kritischen Trends im Zeitraum der letzten ${hours} Std. erkannt (Projektion: ${safeProjectHoursEmpty} Std.).</p></div>`;
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
  const safeProjectHours = Number(projectHours) || 72;
  const projectionTargetIso = new Date(dataEndTimeMs + safeProjectHours * 3600 * 1000).toISOString();
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
    const customerName = asText(items[0].customer_name, "");
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
          <span class="ct-host-title-block">
            ${customerName ? `<span class="ct-host-customer">${escapeHtml(customerName)}</span>` : ""}
            <span class="ct-hostname">${escapeHtml(displayName)}${showHostname ? ` <span class="ct-hostname-sub">(${escapeHtml(hostname)})</span>` : ""}</span>
          </span>
          ${hostBadge}
          <span class="ct-host-meta">${hostCrit > 0 ? hostCrit + " kritisch" : ""}${hostCrit > 0 && hostWarn > 0 ? ", " : ""}${hostWarn > 0 ? hostWarn + " Warnung" : ""}</span>
        </div>
        <div class="ct-rows">${rows}</div>
      </div>
    `;
  }).join("");

  return summary + cards;
}

async function fetchCriticalTrendsWithRetry() {
  const url = `/api/v1/critical-trends?hours=${state.criticalTrendsHours}&project_hours=${state.criticalTrendsProjectHours}`;
  const timeoutMs = 180000;
  let transientFailures = 0;
  const startedAt = Date.now();

  while (Date.now() - startedAt < timeoutMs) {
    const controller = new AbortController();
    const requestTimeout = window.setTimeout(() => controller.abort(), 45000);
    try {
      const response = await fetch(url, {
        credentials: "same-origin",
        cache: "no-store",
        signal: controller.signal,
      });
      window.clearTimeout(requestTimeout);
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        if ((response.status === 502 || response.status === 503) && transientFailures < 8) {
          transientFailures += 1;
          await waitMs(2000);
          continue;
        }
        throw new Error(data.error || ("HTTP " + response.status));
      }
      return data;
    } catch (error) {
      window.clearTimeout(requestTimeout);
      if (error && error.name === "AbortError" && transientFailures < 8) {
        transientFailures += 1;
        await waitMs(1500);
        continue;
      }
      throw error;
    }
  }
  throw new Error("Trend-Daten Timeout nach 3 Minuten");
}

async function loadCriticalTrends(options = {}) {
  const updateList = options.updateList !== false;
  const listEl = document.getElementById("criticalTrendsList");
  const tabButton = document.getElementById("criticalTrendsTabButton");
  if (updateList && !listEl) return;

  const loadingStartedAt = Date.now();
  if (updateList && listEl) {
    listEl.innerHTML = "<p class=\"muted\">Lade Trend-Daten…</p>";
  }
  const loadingTicker = updateList && listEl
    ? window.setInterval(() => {
      const elapsedSec = Math.max(1, Math.round((Date.now() - loadingStartedAt) / 1000));
      listEl.innerHTML = `<p class="muted">Lade Trend-Daten… (${elapsedSec}s)</p>`;
    }, 1000)
    : null;
  try {
    const data = await fetchCriticalTrendsWithRetry();
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
      listEl.innerHTML = `<p class="muted">${escapeHtml(formatApiLoadError(error?.message, "Kritische Trends"))}</p>`;
    }
  } finally {
    if (loadingTicker !== null) {
      window.clearInterval(loadingTicker);
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
    const hostUid = asText(host.host_uid || host.hostname, "").trim();
    const hostUidShort = hostUid.length > 34 ? `${hostUid.slice(0, 31)}...` : hostUid;
    const customerNameRaw = asText(host.customer_name || "").trim();
    const hasRealCustomerName = customerNameRaw && customerNameRaw !== "-" && customerNameRaw !== "--";
    const displayTitle = hasRealCustomerName ? `${customerNameRaw} · ${displayName}` : displayName;
    const showHostname = displayName !== host.hostname;
    
    const osIconInfo = resolveHostOsIcon(host.os);
    const osIconName = osIconInfo.iconName;
    const osIconSrc = `icons/${osIconName}`;
    
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
            <img src="${osIconSrc}" class="ih-host-icon" alt="${escapeHtml(host.os)}" onerror="if(!this.dataset.fallback){this.dataset.fallback='1';this.src='/icons/${osIconName}';}" />
          </div>
          <div class="ih-host-details">
            <span class="ih-hostname">${escapeHtml(displayTitle)}${showHostname ? ` <span class="ih-hostname-sub">(${escapeHtml(host.hostname)})</span>` : ""}</span>
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
      listEl.innerHTML = `<p class="muted">${escapeHtml(formatApiLoadError(error?.message, "Inaktive Hosts"))}</p>`;
    }
  }
}

function renderBackupStatus(data) {
  const allHosts = Array.isArray(data.hosts) ? data.hosts : [];
  const countryFilterEl = document.getElementById("backupStatusCountryFilter");
  const sqlFilterEl = document.getElementById("backupStatusFilterSql");
  const hanaFilterEl = document.getElementById("backupStatusFilterHana");

  if (countryFilterEl) {
    const countries = [...new Set(allHosts
      .map((host) => String(host?.country_code || "").trim().toUpperCase())
      .filter((code) => /^[A-Z]{2}$/.test(code)))].sort();
    const selected = countries.includes(String(state.backupStatusCountryFilter || "").toUpperCase())
      ? String(state.backupStatusCountryFilter || "").toUpperCase()
      : "all";
    state.backupStatusCountryFilter = selected;
    renderCountryFlagFilter(countryFilterEl, countries, selected, (nextFilter) => {
      state.backupStatusCountryFilter = nextFilter;
      loadBackupStatus();
    });
  }
  if (sqlFilterEl) sqlFilterEl.checked = state.backupStatusFilterSql === true;
  if (hanaFilterEl) hanaFilterEl.checked = state.backupStatusFilterHana === true;

  const hosts = allHosts.filter((host) => {
    const hostCountry = String(host?.country_code || "").trim().toUpperCase();
    const countryFilter = String(state.backupStatusCountryFilter || "all").toUpperCase();
    if (countryFilter !== "ALL" && hostCountry !== countryFilter) {
      return false;
    }
    const wantSql = state.backupStatusFilterSql === true;
    const wantHana = state.backupStatusFilterHana === true;
    if (!wantSql && !wantHana) {
      return true;
    }
    const hasSql = Boolean(host?.has_sql);
    const hasHana = Boolean(host?.has_hana);
    return (wantSql && hasSql) || (wantHana && hasHana);
  });

  if (allHosts.length === 0) {
    return "<p class=\"muted\">Keine Hosts mit Backup-Konfiguration gefunden. (DIR_SCAN_DEEP_PATHS oder auto-erkannter HANA-Pfad in agent.conf)</p>";
  }
  if (hosts.length === 0) {
    return "<p class=\"muted\">Keine Hosts im aktuellen Filter.</p>";
  }

  const renderHostCard = (host) => {
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
    const hostTagSql = host.has_sql ? `<span class="backup-host-tag backup-host-tag--sql">SQL</span>` : "";
    const hostTagHana = host.has_hana ? `<span class="backup-host-tag backup-host-tag--hana">HANA</span>` : "";
    const hostCountryCode = String(host.country_code || "").trim().toUpperCase();
    const hostCountryFlagPath = getCountryFlagIconPath(hostCountryCode);
    const hostCountry = hostCountryFlagPath
      ? `<span class="backup-host-tag backup-host-tag--country" title="Land: ${escapeHtml(hostCountryCode)}"><img src="${hostCountryFlagPath}" class="backup-country-flag" alt="${escapeHtml(hostCountryCode)}" /></span>`
      : "";

    const dirs = host.dirs || [];
    const hasSqlEntries = dirs.some((d) => asText(d.source_type || "filesystem", "filesystem").toLowerCase() === "sql");
    const currentCount = dirs.filter((d) => d.has_today_backup === true).length;
    const missingCount = Math.max(0, dirs.length - currentCount);
    const detailsOpenAttr = hasMissing ? " open" : "";
    const dirRows = dirs.map((d) => {
      const sourceType = asText(d.source_type || "filesystem", "filesystem").toLowerCase();
      const isSql = sourceType === "sql";
      const isHana = !isSql && /\/hana\//i.test(asText(d.subdir_path, ""));
      const ok = d.has_today_backup;
      const badgeClass = ok ? "dir-status-badge ok" : "dir-status-badge missing";
      const badgeText = ok ? "✓ Backup aktuell (<24h)" : "✗ kein aktuelles Backup";
      const sourceChip = isSql
        ? '<span class="backup-source-chip backup-source-chip--sql">SQL</span>'
        : isHana
          ? '<span class="backup-source-chip backup-source-chip--hana">HANA</span>'
          : '<span class="backup-source-chip backup-source-chip--fs">FS</span>';
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
      const rowClass = isSql ? "backup-row backup-row--sql" : isHana ? "backup-row backup-row--hana" : "backup-row backup-row--fs";
      return `
        <tr class="${rowClass}">
          <td class="backup-status-dir-name" title="${escapeHtml(asText(d.subdir_path, ""))}">${sourceChip}<span>${subdirName}</span></td>
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
          ${hostTagSql}
          ${hostTagHana}
          ${hostCountry}
          <span class="backup-host-stats">
            <span class="backup-host-count backup-host-count--ok">Aktuelles Backup: ${currentCount}</span>
            <span class="backup-host-count backup-host-count--missing">kein aktuelles Backup: ${missingCount}</span>
          </span>
          ${staleNote}
        </summary>
        <div class="table-wrap backup-host-body">
          <table class="report-subtable backup-status-table ${hasSqlEntries ? "backup-status-table--sql" : "backup-status-table--default"}">
            <colgroup>
              <col class="backup-col-dir" />
              <col class="backup-col-newest" />
              <col class="backup-col-mod" />
              <col class="backup-col-size" />
              <col class="backup-col-status" />
            </colgroup>
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
  };

  const customerGroups = new Map();
  hosts.forEach((host) => {
    const customerName = asText(host?.customer_name, "").trim() || "Ohne Kunde";
    const customerProject = asText(host?.customer_maringo_project_number, "").trim();
    const customerIdRaw = Number(host?.customer_id || 0);
    const customerId = Number.isFinite(customerIdRaw) && customerIdRaw > 0 ? customerIdRaw : null;
    const key = `${customerName.toLowerCase()}\u0000${customerProject.toLowerCase()}\u0000${customerId || ""}`;
    if (!customerGroups.has(key)) {
      customerGroups.set(key, {
        customerName,
        customerProject,
        customerId,
        hosts: [],
        missingHosts: 0,
        totalDirs: 0,
        currentDirs: 0,
      });
    }
    const group = customerGroups.get(key);
    const dirs = Array.isArray(host?.dirs) ? host.dirs : [];
    const currentCount = dirs.filter((item) => item?.has_today_backup === true).length;
    group.hosts.push(host);
    group.totalDirs += dirs.length;
    group.currentDirs += currentCount;
    if (Boolean(host?.has_missing_backup)) {
      group.missingHosts += 1;
    }
  });

  const sortedGroups = Array.from(customerGroups.values()).sort((a, b) => {
    return String(a.customerName || "").localeCompare(String(b.customerName || ""), undefined, { sensitivity: "base" });
  });

  return sortedGroups.map((group) => {
    const hostsCount = group.hosts.length;
    const missingHosts = Number(group.missingHosts || 0);
    const currentDirs = Number(group.currentDirs || 0);
    const totalDirs = Number(group.totalDirs || 0);
    const missingDirs = Math.max(0, totalDirs - currentDirs);
    const groupOpenAttr = "";
    const groupClass = missingHosts > 0
      ? "backup-customer-summary backup-customer-summary--missing"
      : "backup-customer-summary backup-customer-summary--ok";
    const projectHtml = group.customerProject
      ? `<span class="backup-customer-project">Maringo: ${escapeHtml(group.customerProject)}</span>`
      : "";
    const hostCardsHtml = group.hosts
      .slice()
      .sort((left, right) => {
        const nameLeft = String(left?.display_name || left?.hostname || "").toLowerCase();
        const nameRight = String(right?.display_name || right?.hostname || "").toLowerCase();
        return nameLeft.localeCompare(nameRight);
      })
      .map((host) => renderHostCard(host))
      .join("");

    return `<details class="backup-customer-group"${groupOpenAttr}>
      <summary class="${groupClass}">
        <span class="backup-customer-name">${escapeHtml(group.customerName)}</span>
        ${projectHtml}
        <span class="backup-customer-chip">Hosts: ${hostsCount}</span>
        <span class="backup-customer-chip backup-customer-chip--ok">Aktuelle Backups: ${currentDirs}</span>
        <span class="backup-customer-chip backup-customer-chip--missing">kein aktuelles Backup: ${missingDirs}</span>
      </summary>
      <div class="backup-customer-body">${hostCardsHtml}</div>
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
    state.backupStatusData = data;
    listEl.innerHTML = renderBackupStatus(data);
    const allHosts = Array.isArray(data.hosts) ? data.hosts : [];
    const filteredHosts = allHosts.filter((host) => {
      const hostCountry = String(host?.country_code || "").trim().toUpperCase();
      const countryFilter = String(state.backupStatusCountryFilter || "all").toUpperCase();
      if (countryFilter !== "ALL" && hostCountry !== countryFilter) return false;
      const wantSql = state.backupStatusFilterSql === true;
      const wantHana = state.backupStatusFilterHana === true;
      if (!wantSql && !wantHana) return true;
      return (wantSql && Boolean(host?.has_sql)) || (wantHana && Boolean(host?.has_hana));
    });
    const missing = filteredHosts.filter((host) => Boolean(host?.has_missing_backup)).length;
    const total = filteredHosts.length;
    const totalAll = Number(data.total || allHosts.length || 0);
    if (summaryEl) {
      const baseText = missing > 0
        ? `${missing} von ${total} Host(s) ohne aktuelles Backup (<24h)`
        : `${total} Host(s) — alle Backups aktuell (<24h)`;
      summaryEl.textContent = total !== totalAll ? `${baseText} · gefiltert aus ${totalAll}` : baseText;
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
    listEl.innerHTML = `<p class="muted">${escapeHtml(formatApiLoadError(error?.message, "Backup-Stati"))}</p>`;
  }
}

function expandAllBackupStatusCustomers() {
  const listEl = document.getElementById("backupStatusList");
  if (!listEl) return;
  listEl.querySelectorAll("details.backup-customer-group").forEach((detailsEl) => {
    detailsEl.open = true;
  });
}

function expandAllSystemOverviewGroups() {
  const container = document.getElementById("systemOverviewContainer");
  if (!container) return;
  container.querySelectorAll(".system-overview-toggle").forEach((button) => {
    const targetId = String(button.getAttribute("data-target-id") || "");
    const target = targetId ? document.getElementById(targetId) : null;
    if (!target) return;
    target.classList.remove("hidden");
    button.setAttribute("aria-expanded", "true");
    const chevron = button.querySelector(".system-overview-chevron");
    if (chevron) chevron.textContent = "▼";
  });
}

function renderCustomerOverview(data) {
  const customersAll = Array.isArray(data?.customers) ? data.customers : [];
  const query = String(state.customerOverviewSearchQuery || "").trim().toLowerCase();
  const customers = !query
    ? customersAll
    : customersAll.filter((customer) => {
      const customerName = String(customer?.customer_name || "").toLowerCase();
      const projectNo = String(customer?.maringo_project_number || "").toLowerCase();
      if (customerName.includes(query) || projectNo.includes(query)) return true;
      const hosts = Array.isArray(customer?.hosts) ? customer.hosts : [];
      return hosts.some((host) => {
        const displayName = String(host?.display_name || "").toLowerCase();
        const hostname = String(host?.hostname || "").toLowerCase();
        return displayName.includes(query) || hostname.includes(query);
      });
    });

  const summaryEl = document.getElementById("customerOverviewSummary");
  const totalCustomers = customers.length;
  const totalHosts = customers.reduce((sum, item) => sum + Number(item?.hosts_count || 0), 0);
  const totalOpen = customers.reduce((sum, item) => sum + Number(item?.open_alert_count || 0), 0);
  const totalCritical = customers.reduce((sum, item) => sum + Number(item?.critical_alert_count || 0), 0);
  const totalBackupMissing = customers.reduce((sum, item) => sum + Number(item?.missing_backup_count || 0), 0);
  if (summaryEl) {
    summaryEl.textContent = `${totalCustomers} Kunde(n) · ${totalHosts} Hosts · ${totalOpen} offene Alerts (${totalCritical} kritisch) · ${totalBackupMissing} Host(s) ohne aktuelles Backup`;
  }

  if (customers.length === 0) {
    return '<p class="muted">Keine Kundendaten für den aktuellen Filter.</p>';
  }

  return customers.map((customer) => {
    const customerName = asText(customer?.customer_name, "Ohne Kunde");
    const projectNo = asText(customer?.maringo_project_number, "");
    const customerId = Number(customer?.customer_id || 0) || null;
    const hosts = Array.isArray(customer?.hosts) ? customer.hosts : [];
    const detailsOpen = Number(customer?.critical_alert_count || 0) > 0 || Number(customer?.missing_backup_count || 0) > 0 ? " open" : "";
    const hostRows = hosts.map((host) => {
      const hostName = asText(host?.display_name || host?.hostname, "-");
      const hostname = asText(host?.hostname, "-");
      const countryCode = asText(host?.country_code, "").toUpperCase();
      const countryBadge = /^[A-Z]{2}$/.test(countryCode)
        ? `<span class="customer-overview-host-country">${escapeHtml(countryCode)}</span>`
        : '<span class="customer-overview-host-country muted">--</span>';
      const openAlerts = Number(host?.open_alert_count || 0);
      const criticalAlerts = Number(host?.critical_alert_count || 0);
      const missingBackup = Boolean(host?.has_missing_backup);
      const backupText = missingBackup ? "kein aktuelles Backup" : "Backup ok";
      const backupClass = missingBackup ? "is-missing" : "is-ok";
      return `<tr>
        <td><div class="customer-overview-host-title">${escapeHtml(hostName)}</div><div class="muted">${escapeHtml(hostname)}</div></td>
        <td class="center">${countryBadge}</td>
        <td class="center">${openAlerts}</td>
        <td class="center">${criticalAlerts}</td>
        <td class="center"><span class="customer-overview-backup ${backupClass}">${backupText}</span></td>
      </tr>`;
    }).join("");

    return `<details class="customer-overview-card"${detailsOpen}>
      <summary class="customer-overview-head">
        <span class="customer-overview-title">${escapeHtml(customerName)}</span>
        ${projectNo ? `<span class="customer-overview-project">Maringo: ${escapeHtml(projectNo)}</span>` : ""}
        <span class="customer-overview-chip">Hosts: ${Number(customer?.hosts_count || 0)}</span>
        <span class="customer-overview-chip">Offen: ${Number(customer?.open_alert_count || 0)}</span>
        <span class="customer-overview-chip">Kritisch: ${Number(customer?.critical_alert_count || 0)}</span>
        <span class="customer-overview-chip ${Number(customer?.missing_backup_count || 0) > 0 ? "warn" : "ok"}">Backup-Lücken: ${Number(customer?.missing_backup_count || 0)}</span>
        ${customerId ? `<button type="button" class="customer-overview-edit-btn" data-action="edit-customer" data-customer-id="${customerId}" data-customer-name="${escapeHtml(customerName)}" data-customer-project="${escapeHtml(projectNo)}" title="Kunde bearbeiten">✏️</button>` : ""}
      </summary>
      <div class="table-wrap">
        <table class="report-subtable customer-overview-table">
          <thead>
            <tr>
              <th>Host</th>
              <th class="center">Land</th>
              <th class="center">Alerts offen</th>
              <th class="center">kritisch</th>
              <th class="center">Backup</th>
            </tr>
          </thead>
          <tbody>${hostRows}</tbody>
        </table>
      </div>
    </details>`;
  }).join("");
}

async function loadCustomerOverview() {
  const listEl = document.getElementById("customerOverviewList");
  if (!listEl) return;
  listEl.innerHTML = '<p class="muted">Lade Daten…</p>';
  try {
    const response = await fetch("/api/v1/customer-overview", { credentials: "same-origin" });
    if (!response.ok) throw new Error("HTTP " + response.status);
    const data = await response.json();
    state.customerOverviewData = data;
    listEl.innerHTML = renderCustomerOverview(data);
  } catch (error) {
    listEl.innerHTML = `<p class="muted">Fehler beim Laden: ${escapeHtml(error.message)}</p>`;
  }
}

async function openCustomerEditorDialog({ customerId, currentName, currentProject }) {
  const modal = document.createElement("div");
  modal.className = "host-meta-modal";
  modal.innerHTML = `<div class="host-meta-modal-backdrop"></div>
    <div class="host-meta-modal-inner" role="dialog" aria-modal="true" aria-label="Kunde bearbeiten">
      <div class="chart-drill-header">
        <div class="chart-drill-title">Kunde bearbeiten</div>
        <button type="button" class="btn-secondary btn-secondary--compact" data-action="cancel">Schließen</button>
      </div>
      <div class="chart-drill-body host-meta-modal-body">
        <div class="host-meta-modal-grid">
          <label>Kundenname
            <input id="customerEditorNameInput" type="text" placeholder="z.B. Mecasonics GmbH" value="${escapeHtml(currentName || "")}" />
          </label>
          <label>Maringo Projektnummer (optional)
            <input id="customerEditorProjectInput" type="text" placeholder="z.B. MAR-12345" value="${escapeHtml(currentProject || "")}" />
          </label>
        </div>
        <div class="host-meta-modal-actions">
          <button type="button" class="btn-secondary" data-action="cancel">Abbrechen</button>
          <button type="button" class="btn-primary" data-action="save">Speichern</button>
        </div>
        <p id="customerEditorError" class="settings-status error" style="display:none;"></p>
      </div>
    </div>`;
  document.body.appendChild(modal);

  const nameInput = modal.querySelector("#customerEditorNameInput");
  const projectInput = modal.querySelector("#customerEditorProjectInput");
  const errorEl = modal.querySelector("#customerEditorError");
  if (nameInput) nameInput.focus();

  return await new Promise((resolve) => {
    let closed = false;
    const close = (result) => {
      if (closed) return;
      closed = true;
      modal.remove();
      resolve(result);
    };
    modal.addEventListener("click", async (e) => {
      const action = e.target.closest("[data-action]")?.dataset.action;
      if (action === "cancel") { close(null); return; }
      if (action === "save") {
        const newName = String(nameInput?.value || "").trim();
        const newProject = String(projectInput?.value || "").trim();
        if (!newName) {
          if (errorEl) { errorEl.textContent = "Kundenname darf nicht leer sein."; errorEl.style.display = ""; }
          nameInput?.focus();
          return;
        }
        const saveBtn = modal.querySelector("[data-action='save']");
        if (saveBtn) saveBtn.disabled = true;
        try {
          const resp = await fetch(`/api/v1/customers/${encodeURIComponent(customerId)}`, {
            method: "PATCH",
            headers: { "Content-Type": "application/json" },
            credentials: "same-origin",
            body: JSON.stringify({ customer_name: newName, maringo_project_number: newProject }),
          });
          const data = await resp.json().catch(() => ({}));
          if (!resp.ok) {
            if (errorEl) { errorEl.textContent = data.error || ("HTTP " + resp.status); errorEl.style.display = ""; }
            if (saveBtn) saveBtn.disabled = false;
            return;
          }
          close(data.customer || true);
        } catch (err) {
          if (errorEl) { errorEl.textContent = err.message || "Unbekannter Fehler."; errorEl.style.display = ""; }
          if (saveBtn) saveBtn.disabled = false;
        }
      }
    });
    modal.querySelector(".host-meta-modal-backdrop")?.addEventListener("click", () => close(null));
    modal.addEventListener("keydown", (e) => { if (e.key === "Escape") close(null); });
  });
}

function getDateGroupLabel(isoDateStr) {
  if (!isoDateStr) return "Unbekannt";
  const itemDate = new Date(isoDateStr + "Z");
  const today = new Date();
  const yesterday = new Date(today);
  yesterday.setDate(yesterday.getDate() - 1);

  const normalizeDay = (d) => new Date(d.getFullYear(), d.getMonth(), d.getDate());
  const itemNorm = normalizeDay(itemDate);
  const todayNorm = normalizeDay(today);
  const yesterdayNorm = normalizeDay(yesterday);

  const sevenDaysAgo = new Date(today);
  sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
  const thirtyDaysAgo = new Date(today);
  thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

  if (itemNorm.getTime() === todayNorm.getTime()) return "Heute";
  if (itemNorm.getTime() === yesterdayNorm.getTime()) return "Gestern";
  if (itemDate >= sevenDaysAgo) return "Letzte 7 Tage";
  if (itemDate >= thirtyDaysAgo) return "Letzte 30 Tage";
  return "Älter";
}

function groupByDateAndHost(items) {
  const dateGroups = new Map();
  items.forEach((item) => {
    const dateLabel = getDateGroupLabel(item.detected_at_utc);
    if (!dateGroups.has(dateLabel)) {
      dateGroups.set(dateLabel, []);
    }
    dateGroups.get(dateLabel).push(item);
  });

  const dateOrder = ["Heute", "Gestern", "Letzte 7 Tage", "Letzte 30 Tage", "Älter"];
  const sortedDateGroups = [];
  dateOrder.forEach((dateLabel) => {
    if (dateGroups.has(dateLabel)) {
      sortedDateGroups.push({
        dateLabel,
        items: dateGroups.get(dateLabel),
      });
    }
  });

  return sortedDateGroups;
}

function parseChangelogCount(value) {
  const text = String(value ?? "").trim();
  if (!text || text === "-") {
    return null;
  }
  if (!/^-?\d+$/.test(text)) {
    return null;
  }
  const parsed = Number.parseInt(text, 10);
  return Number.isFinite(parsed) ? parsed : null;
}

function renderLicenseTypeCountDelta(fieldKey, oldValue, newValue) {
  const key = String(fieldKey || "");
  if (!key.startsWith("sap_license_type::")) {
    return "";
  }

  const oldCount = parseChangelogCount(oldValue);
  const newCount = parseChangelogCount(newValue);
  if (oldCount === null || newCount === null) {
    return "";
  }

  const delta = newCount - oldCount;
  if (delta === 0) {
    return "";
  }

  const signText = delta > 0 ? `+${delta}` : String(delta);
  const cssClass = delta > 0 ? "host-config-license-delta-up" : "host-config-license-delta-down";
  return `<span class="host-config-license-delta ${cssClass}">(${escapeHtml(signText)})</span>`;
}

function renderHostConfigNumericDelta(fieldKey, oldValue, newValue) {
  const key = String(fieldKey || "").trim();
  if (key !== "ram_gb" && key !== "cpu_cores") {
    return "";
  }

  const oldCount = parseChangelogCount(oldValue);
  const newCount = parseChangelogCount(newValue);
  if (oldCount === null || newCount === null) {
    return "";
  }

  const delta = newCount - oldCount;
  if (delta === 0) {
    return "";
  }

  const signText = delta > 0 ? `+${delta}` : String(delta);
  const cssClass = delta > 0 ? "host-config-license-delta-up" : "host-config-license-delta-down";
  return `<span class="host-config-license-delta ${cssClass}">(${escapeHtml(signText)})</span>`;
}

function collectHostConfigChangesCountryCodes(extraCodes = []) {
  const codes = new Set();
  const addCode = (raw) => {
    const code = String(raw || "").trim().toUpperCase();
    if (/^[A-Z]{2}$/.test(code)) {
      codes.add(code);
    }
  };

  (Array.isArray(extraCodes) ? extraCodes : []).forEach(addCode);
  (Array.isArray(state.hostConfigChangesAvailableCountries) ? state.hostConfigChangesAvailableCountries : []).forEach(addCode);
  (Array.isArray(state.hosts) ? state.hosts : []).forEach((host) => addCode(host?.country_code));
  try {
    getHostInterestSelectedCountries().forEach(addCode);
  } catch (_error) {
    // Ignore if host-interest helpers are unavailable during early init.
  }

  const result = [...codes].sort();
  if (!result.length) {
    return ["AT", "CH", "DE", "FR"];
  }
  return result;
}

function refreshHostConfigChangesCountryFilter(extraCodes = []) {
  const countryFilterEl = document.getElementById("hostConfigChangesCountryFilter");
  if (!countryFilterEl) {
    return;
  }
  const countriesForFilter = collectHostConfigChangesCountryCodes(extraCodes);
  if (countriesForFilter.length) {
    state.hostConfigChangesAvailableCountries = countriesForFilter;
  }
  const selected = countriesForFilter.includes(String(state.hostConfigChangesCountryFilter || "").toUpperCase())
    ? String(state.hostConfigChangesCountryFilter || "").toUpperCase()
    : "all";
  state.hostConfigChangesCountryFilter = selected;
  renderCountryFlagFilter(countryFilterEl, countriesForFilter, selected, (nextFilter) => {
    state.hostConfigChangesCountryFilter = nextFilter;
    showHostConfigChangesIdleState();
  });
}

function renderCountryFlagFilter(filterEl, countryCodes, selectedCountryCode, onSelect) {
  if (!filterEl) return;
  const normalized = Array.from(new Set((Array.isArray(countryCodes) ? countryCodes : [])
    .map((code) => String(code || "").trim().toUpperCase())
    .filter((code) => /^[A-Z]{2}$/.test(code))))
    .sort();

  if (!normalized.length) {
    filterEl.innerHTML = "";
    return;
  }

  const current = normalized.includes(String(selectedCountryCode || "").toUpperCase())
    ? String(selectedCountryCode || "").toUpperCase()
    : "all";

  const buttons = [
    `<button type="button" class="so-country-filter-btn ${current === "all" ? "active" : ""}" data-country-filter="all">Alle</button>`,
    ...normalized.map((code) => {
      const iconPath = getCountryFlagIconPath(code);
      const icon = iconPath
        ? `<img src="${iconPath}" alt="${escapeHtml(code)}" class="so-country-filter-flag" />`
        : "";
      return `<button type="button" class="so-country-filter-btn ${current === code ? "active" : ""}" data-country-filter="${escapeHtml(code)}">${icon}<span>${escapeHtml(code)}</span></button>`;
    }),
  ].join("");

  filterEl.innerHTML = `<div class="so-country-filter-list">${buttons}</div>`;
  filterEl.querySelectorAll(".so-country-filter-btn").forEach((button) => {
    button.addEventListener("click", () => {
      const nextFilter = String(button.getAttribute("data-country-filter") || "all");
      if (nextFilter === String(selectedCountryCode || "all")) return;
      if (typeof onSelect === "function") onSelect(nextFilter);
    });
  });
}

function showHostConfigChangesIdleState(message = "Filter gesetzt. Bitte auf Suchen oder Refresh klicken.") {
  const groupsEl = document.getElementById("hostConfigChangesGroups");
  const summaryEl = document.getElementById("hostConfigChangesSummary");
  if (groupsEl) {
    groupsEl.innerHTML = `<p class="muted">${escapeHtml(message)}</p>`;
  }
  if (summaryEl && !String(summaryEl.textContent || "").trim()) {
    const hours = Number(state.hostConfigChangesHours || 72);
    summaryEl.textContent = `Changelog · ${hours}h · Suchen/↻ zum Laden`;
  }
  refreshHostConfigChangesCountryFilter();
}

async function loadHostConfigChanges() {
  const groupsEl = document.getElementById("hostConfigChangesGroups");
  const summaryEl = document.getElementById("hostConfigChangesSummary");
  const filterEl = document.getElementById("hostConfigChangesHoursFilter");
  if (!groupsEl) return;
  const searchEl = document.getElementById("hostConfigChangesSearchInput");
  if (searchEl) searchEl.value = state.hostConfigChangesSearchQuery;

  groupsEl.innerHTML = '<p class="muted">Lade Daten…</p>';
  if (summaryEl) summaryEl.textContent = "";

  try {
    const hours = state.hostConfigChangesHours || 720;
    if (filterEl) filterEl.value = hours;
    const response = await fetch(`/api/v1/host-config-changes?hours=${hours}&limit=500`, {
      credentials: "same-origin",
      cache: "no-store",
    });
    if (!response.ok) throw new Error("HTTP " + response.status);

    const data = await response.json();
    const items = Array.isArray(data.items) ? data.items : [];
    if (summaryEl) {
      summaryEl.textContent = `${items.length} Changelog-Eintrag/Einträge in den letzten ${hours}h`;
    }

    if (!items.length) {
      groupsEl.innerHTML = '<p class="muted">Keine Änderungen im gewählten Zeitraum.</p>';
      refreshHostConfigChangesCountryFilter();
      return;
    }

    const countriesFromItems = [];
    items.forEach((item) => {
      const cc = asText(item.country_code, "").toUpperCase();
      if (cc && cc !== "-") {
        countriesFromItems.push(cc);
      }
    });
    refreshHostConfigChangesCountryFilter(countriesFromItems);

    // Apply country filter
    let filteredItems = items;
    if (state.hostConfigChangesCountryFilter && state.hostConfigChangesCountryFilter !== "all") {
      filteredItems = items.filter((item) => {
        const itemCountry = asText(item.country_code, "").toUpperCase();
        const filterCountry = String(state.hostConfigChangesCountryFilter).toUpperCase();
        return itemCountry === filterCountry;
      });
    }

    // Apply search query
    if (state.hostConfigChangesSearchQuery) {
      const q = String(state.hostConfigChangesSearchQuery).toLowerCase();
      filteredItems = filteredItems.filter((item) => {
        const hostMatch = String(item.hostname || "").toLowerCase().includes(q);
        const hostUidMatch = String(item.host_uid || "").toLowerCase().includes(q);
        const customerMatch = String(item.customer_name || "").toLowerCase().includes(q);
        const displayMatch = String(item.display_name || "").toLowerCase().includes(q);
        const fieldMatch = String(item.field_label || item.field_key || "").toLowerCase().includes(q);
        const oldMatch = String(item.old_value || "").toLowerCase().includes(q);
        const newMatch = String(item.new_value || "").toLowerCase().includes(q);
        return hostMatch || hostUidMatch || customerMatch || displayMatch || fieldMatch || oldMatch || newMatch;
      });
    }

    // Update summary with filtered count
    if (summaryEl) {
      const filteredCount = filteredItems.length;
      const countryMsg = state.hostConfigChangesCountryFilter && state.hostConfigChangesCountryFilter !== "all"
        ? ` (Land: ${state.hostConfigChangesCountryFilter})`
        : "";
      const searchMsg = state.hostConfigChangesSearchQuery ? ` - gefiltert` : "";
      summaryEl.textContent = `${filteredCount} Changelog-Eintrag/Einträge in den letzten ${hours}h${countryMsg}${searchMsg}`;
    }

    if (!filteredItems.length) {
      const reason = state.hostConfigChangesSearchQuery
        ? `Keine Changelog-Einträge gefunden für "${state.hostConfigChangesSearchQuery}"`
        : state.hostConfigChangesCountryFilter && state.hostConfigChangesCountryFilter !== "all"
          ? `Keine Changelog-Einträge für Land ${state.hostConfigChangesCountryFilter}`
          : "Keine Changelog-Einträge im gewählten Zeitraum.";
      groupsEl.innerHTML = `<p class="muted">${escapeHtml(reason)}</p>`;
      return;
    }

    // Group by customer -> host.
    const itemsByCustomer = new Map();
    filteredItems.forEach((item) => {
      const hostname = asText(item.hostname, "");
      const displayName = asText(item.display_name, "") || hostname;
      const customerName = asText(item.customer_name, "") || displayName;
      const groupKey = customerName;
      if (!itemsByCustomer.has(groupKey)) {
        itemsByCustomer.set(groupKey, { customerName, items: [] });
      }
      itemsByCustomer.get(groupKey).items.push(item);
    });

    const customerGroups = Array.from(itemsByCustomer.values()).sort((a, b) => {
      return String(a.customerName || "").toLowerCase().localeCompare(String(b.customerName || "").toLowerCase(), "de", { sensitivity: "base", numeric: true });
    });

    // Auto-expand for active search and for 24h quick-review refresh workflow.
    const autoExpandGroups = !!state.hostConfigChangesSearchQuery || Number(hours) <= 24;

    const renderCustomerGroupHtml = (customerGroup) => {
      const itemsByHost = new Map();
      customerGroup.items.forEach((item) => {
        const hostUid = asText(item.host_uid, "") || asText(item.hostname, "");
        const hostname = asText(item.hostname, "");
        const displayName = asText(item.display_name, "") || hostname;
        const countryCode = asText(item.country_code, "");
        const hostKey = `${hostUid}::${hostname}`;
        if (!itemsByHost.has(hostKey)) {
          itemsByHost.set(hostKey, { hostUid, hostname, displayName, items: [], country_code: countryCode });
        }
        itemsByHost.get(hostKey).items.push(item);
      });

      const hostGroups = Array.from(itemsByHost.values()).sort((a, b) => {
        return String(a.displayName || "").toLowerCase().localeCompare(String(b.displayName || "").toLowerCase(), "de", { sensitivity: "base", numeric: true });
      });

      const hostRowsHtml = hostGroups
        .map((hostGroup) => {
          const sortedItems = [...hostGroup.items].sort((left, right) => {
            return String(right.detected_at_utc || "").localeCompare(String(left.detected_at_utc || ""));
          });

          const rows = sortedItems.map((item) => {
            const fieldKey = String(item.field_key || "");
            const oldValue = asText(item.old_value, "-");
            const newValue = asText(item.new_value, "-");
            const licenseDeltaHtml = renderLicenseTypeCountDelta(fieldKey, oldValue, newValue);

            let oldFpInfo = "";
            let newFpInfo = "";
            let oldValueHtml = `<div class="host-config-main-value">${escapeHtml(oldValue)}</div>`;
            let newValueHtml = `<div class="host-config-main-value"><strong>${escapeHtml(newValue)}</strong></div>`;
            if (fieldKey === "sap_release") {
              const oldFp = resolveSapReleaseDisplay(oldValue, SAP_B1_VERSION_MAP);
              if (oldFp && oldFp !== "-") {
                oldFpInfo = `<div class="host-config-change-subline"><strong>(${escapeHtml(oldFp)})</strong></div>`;
              }
              const newFp = resolveSapReleaseDisplay(newValue, SAP_B1_VERSION_MAP);
              if (newFp && newFp !== "-") {
                newFpInfo = `<div class="host-config-change-subline"><strong>(${escapeHtml(newFp)})</strong></div>`;
              }
            }
            if (licenseDeltaHtml) {
              newValueHtml = `<div class="host-config-main-value"><strong>${escapeHtml(newValue)}</strong> ${licenseDeltaHtml}</div>`;
            }

            return `
              <tr>
                <td>${escapeHtml(formatUtcPlus2(item.detected_at_utc))}</td>
                <td>${escapeHtml(asText(item.field_label || item.field_key, "-"))}</td>
                <td>
                  ${oldValueHtml}
                  ${oldFpInfo}
                </td>
                <td>
                  ${newValueHtml}
                  ${newFpInfo}
                </td>
              </tr>
            `;
          }).join("");

          const showHostSub = hostGroup.displayName !== hostGroup.hostname;
          const showHostUid = hostGroup.hostUid && hostGroup.hostUid !== hostGroup.hostname;
          return `
            <details class="host-config-change-group" ${autoExpandGroups ? "open" : ""}>
              <summary class="host-config-change-summary">
                <span class="global-host-label">${escapeHtml(hostGroup.displayName)}${showHostSub ? ` <span class="global-hostname-sub">(${escapeHtml(hostGroup.hostname)})</span>` : ""}${showHostUid ? ` <span class="global-hostname-sub" title="Host UID">[${escapeHtml(hostGroup.hostUid)}]</span>` : ""}</span>
                ${hostGroup.country_code && getCountryFlagIconPath(hostGroup.country_code)
                  ? `<span class="host-config-country-badge" title="Land: ${escapeHtml(hostGroup.country_code)}"><img src="${getCountryFlagIconPath(hostGroup.country_code)}" class="host-config-country-flag" alt="${escapeHtml(hostGroup.country_code)}" /></span>`
                  : ""}
                <span class="host-config-change-count">${sortedItems.length} Changelog-Eintrag/Einträge</span>
              </summary>
              <div class="table-wrap host-config-changes-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Zeit</th>
                      <th>Feld</th>
                      <th>Vorher</th>
                      <th>Neu</th>
                    </tr>
                  </thead>
                  <tbody>${rows}</tbody>
                </table>
              </div>
            </details>
          `;
        })
        .join("");

      return `
        <details class="host-config-change-date-group" ${autoExpandGroups ? "open" : ""}>
          <summary class="host-config-change-date-summary">
            <span class="host-config-date-label">${escapeHtml(customerGroup.customerName)}</span>
            <span class="host-config-date-count">${customerGroup.items.length} Changelog-Eintrag/Einträge</span>
          </summary>
          <div class="host-config-date-group-content">
            ${hostRowsHtml}
          </div>
        </details>
      `;
    };

    groupsEl.innerHTML = "";
    for (let index = 0; index < customerGroups.length; index += 1) {
      groupsEl.insertAdjacentHTML("beforeend", renderCustomerGroupHtml(customerGroups[index]));
      if (index === 0 || (index + 1) % 4 === 0) {
        await new Promise((resolve) => window.requestAnimationFrame(() => resolve()));
      }
    }
  } catch (error) {
    groupsEl.innerHTML = `<p class="muted">${escapeHtml(formatApiLoadError(error?.message, "Changelog"))}</p>`;
  }
}

function renderAgentSourceStatusCell(value, ok) {
  const text = asText(value, "-");
  const cls = ok ? "agent-source-cell-ok" : "agent-source-cell-bad";
  return `<span class="${cls}">${escapeHtml(text || "-")}</span>`;
}

async function loadAgentSourceStatus() {
  const summaryEl = document.getElementById("agentSourceStatusSummary");
  const rowsEl = document.getElementById("agentSourceStatusRows");
  if (!rowsEl) return;

  rowsEl.innerHTML = '<tr><td colspan="8" class="muted">Lade Daten...</td></tr>';
  if (summaryEl) summaryEl.textContent = "";

  try {
    const response = await fetch("/api/v1/agent-source-status", {
      credentials: "same-origin",
      cache: "no-store",
    });
    if (!response.ok) throw new Error("HTTP " + response.status);

    const data = await response.json();
    const items = Array.isArray(data.items) ? data.items : [];
    const total = Number(data.total || items.length || 0);
    const okCount = Number(data.ok || 0);
    const pendingCount = Number(data.pending || Math.max(0, total - okCount));
    if (summaryEl) {
      const targetBaseUrl = asText(items[0]?.canonical_update_base_url || items[0]?.expected_update_base_url, "");
      summaryEl.textContent = targetBaseUrl
        ? `${okCount}/${total} umgestellt, ${pendingCount} offen · Grün = ${targetBaseUrl}`
        : `${okCount}/${total} umgestellt, ${pendingCount} offen`;
    }

    if (!items.length) {
      rowsEl.innerHTML = '<tr><td colspan="8" class="muted">Keine Host-Daten vorhanden.</td></tr>';
      return;
    }

    rowsEl.innerHTML = items.map((item) => {
      const checks = item && typeof item.checks === "object" ? item.checks : {};
      const host = asText(item.display_name || item.hostname, "-");
      const customerName = asText(item.customer_name || "", "").trim() || "Ohne Kunde";
      const hostname = asText(item.hostname, "-");
      const showHostname = host !== hostname;
      const statusOk = Boolean(item.is_ok);
      const statusBadge = statusOk
        ? '<span class="agent-source-status-badge ok">OK</span>'
        : '<span class="agent-source-status-badge pending">Offen</span>';
      return `
        <tr>
          <td>${statusBadge}</td>
          <td>
            <div class="global-host-cell">
              <span class="global-host-label">${escapeHtml(host)}</span>
              <span class="global-host-customer">${escapeHtml(customerName)}</span>
              ${showHostname ? `<span class="global-hostname-sub">(${escapeHtml(hostname)})</span>` : ""}
            </div>
          </td>
          <td class="agent-source-mono">${renderAgentSourceStatusCell(item.server_url, Boolean(checks.server_url))}</td>
          <td class="agent-source-mono">${renderAgentSourceStatusCell(item.update_base_url, Boolean(checks.update_base_url))}</td>
          <td class="agent-source-mono">${renderAgentSourceStatusCell(item.raw_base_url, Boolean(checks.raw_base_url))}</td>
          <td class="agent-source-mono">${renderAgentSourceStatusCell(item.github_repo, Boolean(checks.github_repo_empty))}</td>
          <td class="agent-source-mono">${escapeHtml(asText(item.expected_update_base_url, "-"))}</td>
          <td>${escapeHtml(formatUtcPlus2(asText(item.received_at_utc, "")))}</td>
        </tr>
      `;
    }).join("");

    state.agentSourceStatusLoaded = true;
  } catch (error) {
    rowsEl.innerHTML = `<tr><td colspan="8" class="muted">Fehler beim Laden: ${escapeHtml(error.message)}</td></tr>`;
  }
}

function setHostConfigChangesBackfillStatus(message, isError = false) {
  const statusEl = document.getElementById("hostConfigChangesBackfillStatus");
  if (!statusEl) return;
  statusEl.textContent = String(message || "");
  statusEl.classList.toggle("status-error", Boolean(isError));
}

function setChangelogRebuildJobStatus(message, isError = false) {
  const statusEl = document.getElementById("changelogRebuildJobStatus");
  if (!statusEl) return;
  statusEl.textContent = String(message || "");
  statusEl.classList.toggle("status-error", Boolean(isError));
}

async function buildHttpErrorFromResponse(response) {
  const statusText = Number(response?.status || 0) > 0 ? `HTTP ${response.status}` : "HTTP Fehler";
  let backendMessage = "";
  try {
    const payload = await response.clone().json();
    if (payload && typeof payload === "object") {
      const rawError = String(payload.error || payload.message || "").trim();
      if (rawError) {
        backendMessage = rawError;
      }
    }
  } catch (_jsonError) {
    try {
      const text = String(await response.clone().text() || "").trim();
      if (text) {
        backendMessage = text.slice(0, 240);
      }
    } catch (_textError) {
      backendMessage = "";
    }
  }

  return new Error(backendMessage ? `${statusText}: ${backendMessage}` : statusText);
}

function clearChangelogRebuildPollTimer() {
  if (changelogRebuildPollTimerId !== null) {
    window.clearTimeout(changelogRebuildPollTimerId);
    changelogRebuildPollTimerId = null;
  }
}

function shouldPollChangelogRebuildJobs() {
  const onChangelogTab = state.viewMode === "global" && state.globalSubMode === "host-config-changes";
  const activeJobId = Number(state.changelogActiveJobId || 0);
  const activeStatus = String(state.changelogActiveJobStatus || "").toLowerCase();
  const jobStillActive = activeJobId > 0 && (activeStatus === "running" || activeStatus === "pending");
  return onChangelogTab || jobStillActive;
}

function scheduleChangelogRebuildPoll(delayMs = 2000) {
  clearChangelogRebuildPollTimer();
  changelogRebuildPollTimerId = window.setTimeout(() => {
    if (!shouldPollChangelogRebuildJobs()) {
      return;
    }
    void loadChangelogRebuildJobsStatus();
  }, Math.max(800, Number(delayMs) || 2000));
}

function formatChangelogProgressCount(value) {
  const n = Math.max(0, Number(value) || 0);
  try {
    return new Intl.NumberFormat("de-CH").format(n);
  } catch (_error) {
    return String(n);
  }
}

function changelogPhaseTitle(phase, jobModeLabel, phaseStepsTotal = 3) {
  const phaseKey = String(phase || "").toLowerCase();
  const steps = Math.max(1, Number(phaseStepsTotal) || 3);
  if (phaseKey === "reset") return `Schritt 1/${steps} · Tabellen leeren (${jobModeLabel})`;
  if (phaseKey === "config_backfill") return `Schritt 2/${steps} · Host-Config (${jobModeLabel})`;
  if (phaseKey === "addon_backfill") return `Schritt 3/${steps} · SAP-Add-ons (${jobModeLabel})`;
  if (phaseKey === "database_backfill") {
    const dbStep = steps >= 4 ? 4 : 3;
    return `Schritt ${dbStep}/${steps} · DB-Lifecycle (${jobModeLabel})`;
  }
  if (phaseKey === "completed") return `${jobModeLabel} abgeschlossen`;
  return `${jobModeLabel} läuft`;
}

function buildChangelogRebuildProgressView(progress, jobModeLabel) {
  const phase = asText(progress?.phase, "running").toLowerCase();
  const phaseStep = Number(progress?.phase_step || 0);
  const phaseStepsTotal = Math.max(1, Number(progress?.phase_steps_total || 3));
  const phaseSpanByKey = phaseStepsTotal >= 4
    ? { config_backfill: [5, 22], addon_backfill: [22, 40], database_backfill: [40, 95] }
    : { config_backfill: [5, 50], database_backfill: [50, 95] };
  const reportsTotal = Math.max(0, Number(progress?.reports_total || 0));
  const reportsScanned = Math.max(0, Number(progress?.reports_scanned || 0));
  const hostsTotal = Math.max(0, Number(progress?.hosts_total || 0));
  const hostsProcessed = Math.max(0, Number(progress?.hosts_processed || 0));
  const insertedChanges = Math.max(0, Number(progress?.inserted_changes || 0));
  const insertedEvents = Math.max(0, Number(progress?.inserted_events || 0));
  const currentHost = asText(progress?.current_host, "");
  const message = asText(progress?.message, "");

  let percent = 0;
  let indeterminate = false;
  if (phase === "completed") {
    percent = 100;
  } else if (phase === "reset") {
    percent = 3;
    indeterminate = reportsTotal <= 0;
  } else if (reportsTotal > 0 && phaseSpanByKey[phase]) {
    const [phaseStart, phaseEnd] = phaseSpanByKey[phase];
    const reportRatio = Math.max(0, Math.min(1, reportsScanned / reportsTotal));
    percent = Math.round(phaseStart + reportRatio * (phaseEnd - phaseStart));
  } else if (hostsTotal > 0) {
    percent = Math.round((hostsProcessed / hostsTotal) * 100);
  } else {
    indeterminate = true;
  }

  const title = phaseStep > 0
    ? changelogPhaseTitle(phase, jobModeLabel, phaseStepsTotal).replace(/^Schritt \d+\/\d+/, `Schritt ${phaseStep}/${phaseStepsTotal}`)
    : changelogPhaseTitle(phase, jobModeLabel, phaseStepsTotal);

  const detailParts = [];
  if (message && message !== title) detailParts.push(message);
  if (reportsTotal > 0) {
    detailParts.push(
      `Reports ${formatChangelogProgressCount(reportsScanned)} / ${formatChangelogProgressCount(reportsTotal)}`
    );
  }
  if (hostsTotal > 0) {
    detailParts.push(`Hosts ${formatChangelogProgressCount(hostsProcessed)} / ${formatChangelogProgressCount(hostsTotal)}`);
  }
  if (phase === "config_backfill" && insertedChanges > 0) {
    const cfgLabel = reportsScanned <= 0
      ? `${formatChangelogProgressCount(insertedChanges)} Config-Einträge (Report wird verarbeitet…)`
      : `${formatChangelogProgressCount(insertedChanges)} Config-Einträge`;
    detailParts.push(cfgLabel);
  }
  if (phase === "database_backfill" && insertedEvents > 0) {
    detailParts.push(`${formatChangelogProgressCount(insertedEvents)} DB-Events`);
  }
  if (currentHost) detailParts.push(`aktuell: ${currentHost}`);
  const buildVersion = asText(progress?.build_version, "");
  const updatedAtUtc = asText(progress?.updated_at_utc, "");
  if (buildVersion) detailParts.push(`Code ${buildVersion}`);
  if (updatedAtUtc) detailParts.push(`Update ${formatUtcPlus2(updatedAtUtc)}`);

  return {
    label: title,
    detail: detailParts.join(" · "),
    percent,
    indeterminate,
  };
}

function setChangelogRebuildProgress({
  visible = false,
  processed = 0,
  total = 0,
  label = "",
  detail = "",
  indeterminate = false,
  isError = false,
  percent = null,
} = {}) {
  const wrapEl = document.getElementById("changelogRebuildProgress");
  const barEl = document.getElementById("changelogRebuildProgressBar");
  const labelEl = document.getElementById("changelogRebuildProgressLabel");
  const detailEl = document.getElementById("changelogRebuildProgressDetail");
  if (!wrapEl || !barEl || !labelEl) {
    return;
  }

  wrapEl.classList.toggle("hidden", !visible);
  if (!visible) {
    barEl.classList.remove("db-ops-progress-bar--indeterminate");
    barEl.style.width = "0%";
    labelEl.textContent = "";
    labelEl.className = "db-ops-progress-label";
    if (detailEl) {
      detailEl.textContent = "";
      detailEl.classList.add("hidden");
    }
    return;
  }

  const useIndeterminate = indeterminate && percent === null;
  if (useIndeterminate) {
    barEl.classList.add("db-ops-progress-bar--indeterminate");
    barEl.style.width = "40%";
  } else {
    let pct = percent;
    if (pct === null || pct === undefined) {
      const safeTotal = Math.max(0, Number(total) || 0);
      const safeProcessed = Math.max(0, Number(processed) || 0);
      pct = safeTotal > 0 ? Math.max(0, Math.min(100, Math.round((safeProcessed / safeTotal) * 100))) : 0;
    }
    barEl.classList.remove("db-ops-progress-bar--indeterminate");
    barEl.style.width = `${Math.max(0, Math.min(100, Number(pct) || 0))}%`;
  }

  labelEl.textContent = String(label || "");
  labelEl.className = `db-ops-progress-label${isError ? " error" : ""}`;
  if (detailEl) {
    const detailText = String(detail || "").trim();
    detailEl.textContent = detailText;
    detailEl.classList.toggle("hidden", !detailText);
  }
}

function parseBuildVersionParts(versionText) {
  const match = String(versionText || "").trim().match(/^(\d+)\.(\d+)\.(\d+)/);
  if (!match) {
    return null;
  }
  return [Number(match[1]), Number(match[2]), Number(match[3])];
}

function isChangelogToolsStaleBuild(versionText) {
  const parts = parseBuildVersionParts(versionText);
  if (!parts) {
    return true;
  }
  const [major, minor, patch] = parts;
  if (major !== 1 || minor !== 7) {
    return major < 1 || (major === 1 && minor < 7);
  }
  return patch < 314;
}

function updateChangelogToolsBuildVersionBadge(versionText) {
  const badgeEl = document.getElementById("changelogToolsBuildVersion");
  if (!badgeEl) {
    return;
  }
  const value = String(versionText || "").trim() || "-";
  badgeEl.textContent = `Server v${value}`;
  const stale = isChangelogToolsStaleBuild(value);
  badgeEl.classList.toggle("changelog-tools-version--stale", stale);
  badgeEl.title = stale
    ? "Alte Server-Version: auf infoboard pull-server-only.sh ausfuehren und Hard-Refresh (Strg+Shift+R)."
    : "Server-Build aktiv (Inventur/Abbrechen verfuegbar ab v1.7.314).";
}

function initChangelogMaintenancePanel() {
  const panelEl = document.getElementById("changelogMaintenancePanel");
  if (!panelEl) {
    return;
  }
  const stored = localStorage.getItem(CHANGELOG_MAINTENANCE_PANEL_OPEN_KEY);
  if (stored === "0") {
    panelEl.open = false;
  } else if (stored === "1") {
    panelEl.open = true;
  } else {
    panelEl.open = false;
  }
  panelEl.addEventListener("toggle", () => {
    localStorage.setItem(CHANGELOG_MAINTENANCE_PANEL_OPEN_KEY, panelEl.open ? "1" : "0");
  });
}

function setChangelogMaintenanceSummaryHint(text) {
  const hintEl = document.getElementById("changelogMaintenanceSummaryHint");
  if (!hintEl) {
    return;
  }
  const value = String(text || "").trim();
  hintEl.textContent = value ? ` — ${value}` : "";
}

function syncChangelogMaintenancePanelOpen({ forceOpen = false } = {}) {
  const panelEl = document.getElementById("changelogMaintenancePanel");
  if (!panelEl) {
    return;
  }
  if (forceOpen) {
    panelEl.open = true;
    localStorage.setItem(CHANGELOG_MAINTENANCE_PANEL_OPEN_KEY, "1");
  }
}

function updateChangelogCancelButton() {
  const button = document.getElementById("cancelChangelogRebuildJobButton");
  if (!button) return;
  const jobId = Number(state.changelogActiveJobId || 0);
  const canCancel = state.isAdmin && jobId > 0;
  button.classList.toggle("hidden", !canCancel);
  if (canCancel) {
    const statusText = asText(state.changelogActiveJobStatus, "running");
    button.title = `Job #${jobId} (${statusText}) abbrechen`;
    button.textContent = `⏹ #${jobId} abbrechen`;
  } else {
    button.title = "Laufenden Rebuild/Backfill-Job abbrechen";
    button.textContent = "⏹ Abbrechen";
  }
}

async function cancelActiveChangelogRebuildJob() {
  const jobId = Number(state.changelogActiveJobId || 0);
  if (!jobId) return;

  const confirmed = window.confirm(
    `Job #${jobId} wirklich abbrechen?\n\nDie Verarbeitung stoppt spätestens nach dem nächsten Fortschritts-Checkpoint (ca. alle 200 Reports).`
  );
  if (!confirmed) return;

  const button = document.getElementById("cancelChangelogRebuildJobButton");
  if (button) button.disabled = true;
  setChangelogRebuildJobStatus(`Abbruch für Job #${jobId} wird angefordert…`);

  try {
    const response = await fetch("/api/v1/admin/changelog-rebuild/cancel", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        job_id: jobId,
        reason: "Manuell in der UI abgebrochen",
      }),
    });
    if (!response.ok) throw await buildHttpErrorFromResponse(response);

    setChangelogRebuildProgress({
      visible: true,
      label: `Abbruch Job #${jobId}…`,
      detail: "Warte auf Stopp am nächsten Checkpoint.",
      indeterminate: true,
    });
    await loadChangelogRebuildJobsStatus();
  } catch (error) {
    setChangelogRebuildJobStatus(`Abbruch fehlgeschlagen: ${error.message}`, true);
  } finally {
    if (button) button.disabled = false;
    updateChangelogCancelButton();
  }
}

async function fetchChangelogRebuildJobs(limit = 5) {
  const controller = new AbortController();
  const timeoutMs = 6000;
  const timer = window.setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(`/api/v1/admin/changelog-rebuild/jobs?limit=${limit}`, {
      credentials: "same-origin",
      cache: "no-store",
      signal: controller.signal,
    });
  } finally {
    window.clearTimeout(timer);
  }
}

async function loadChangelogRebuildJobsStatus() {
  const statusEl = document.getElementById("changelogRebuildJobStatus");
  if (!statusEl) return;
  setChangelogMaintenanceSummaryHint("");
  clearChangelogRebuildPollTimer();
  let pollAfterLoad = false;
  let pollDelayMs = 2000;
  try {
    const response = await fetchChangelogRebuildJobs(5);
    if (response.status === 503) {
      const data = await response.json().catch(() => ({}));
      setChangelogRebuildJobStatus(
        `${asText(data.message, "Datenbank beschäftigt (Inventur/Rebuild läuft).")} · Konsole: scripts/watch-inventur-job.sh --once`,
        false,
      );
      setChangelogRebuildProgress({
        visible: true,
        label: "Job läuft – API kurz blockiert",
        detail: "Fortschritt per SSH: /root/monitoring-server/scripts/watch-inventur-job.sh --once",
        indeterminate: true,
      });
      pollAfterLoad = true;
      pollDelayMs = 5000;
      return;
    }
    if (!response.ok) throw await buildHttpErrorFromResponse(response);
    const data = await response.json().catch(() => ({}));
    const jobs = Array.isArray(data.jobs) ? data.jobs : [];
    if (!jobs.length) {
      state.changelogActiveJobId = 0;
      state.changelogActiveJobStatus = "";
      updateChangelogCancelButton();
      setChangelogRebuildJobStatus("Keine Rebuild-Jobs vorhanden.");
      setChangelogRebuildProgress({ visible: false });
      return;
    }
    const latest = jobs[0] || {};
    const latestStatus = asText(latest.status, "-").toLowerCase();
    const latestId = Number(latest.id || 0);
    const latestDays = Number(latest.days || 0);
    const latestMode = asText(latest.job_mode, "rebuild");
    const jobModeLabel = latestMode === "inventory_rebuild"
      ? "Inventur-Rebuild"
      : latestMode === "backfill"
        ? "Backfill"
        : "Rebuild";
    const daysLabel = latestDays <= 0 ? "alle Reports" : `${latestDays} Tag(e)`;
    if (latestStatus === "running" || latestStatus === "pending") {
      state.changelogActiveJobId = latestId;
      state.changelogActiveJobStatus = latestStatus;
    } else {
      state.changelogActiveJobId = 0;
      state.changelogActiveJobStatus = "";
    }
    updateChangelogCancelButton();
    const latestResult = latest && typeof latest.result === "object" ? latest.result : {};
    const latestProgress = latestResult && typeof latestResult.progress === "object" ? latestResult.progress : {};
    if (latestStatus === "completed") {
      const finishedAt = asText(latest.finished_at_utc, "");
      const finishedAtMs = Date.parse(finishedAt);
      const completedTooOld = Number.isFinite(finishedAtMs) && (Date.now() - finishedAtMs) > 24 * 60 * 60 * 1000;
      if (completedTooOld) {
        setChangelogRebuildJobStatus("Kein laufender Wartungs-Job.");
        setChangelogRebuildProgress({ visible: false });
        return;
      }
      const configResult = latestResult && typeof latestResult.config_result === "object" ? latestResult.config_result : {};
      const hostsTotal = Number(configResult.hosts_total || configResult.hosts_touched || 0);
      const hostsProcessed = Number(configResult.hosts_processed || configResult.hosts_touched || 0);
      const insertedChanges = Number(
        latestResult.inserted_changes ?? configResult.inserted_changes ?? 0
      );
      const insertedEvents = Number(
        latestResult.inserted_events ?? latestResult.database_result?.inserted_events ?? 0
      );
      const resultHint =
        insertedChanges > 0 || insertedEvents > 0
          ? ` · ${insertedChanges} Config + ${insertedEvents} DB-Events`
          : "";
      setChangelogRebuildJobStatus(
        `${jobModeLabel} #${latestId} abgeschlossen (${daysLabel})${resultHint} · ${formatUtcPlus2(finishedAt)}`
      );
      const completedView = buildChangelogRebuildProgressView(
        {
          phase: "completed",
          hosts_total: hostsTotal,
          hosts_processed: hostsProcessed,
          reports_total: Number(configResult.reports_scanned || latestResult.reports_scanned || 0),
          reports_scanned: Number(configResult.reports_scanned || latestResult.reports_scanned || 0),
          inserted_changes: insertedChanges,
          inserted_events: insertedEvents,
        },
        jobModeLabel
      );
      const completedDetailParts = [completedView.detail];
      if (insertedChanges > 0 || insertedEvents > 0) {
        completedDetailParts.push(
          `Gesamt: ${formatChangelogProgressCount(insertedChanges)} Config + ${formatChangelogProgressCount(insertedEvents)} DB-Events`
        );
      }
      setChangelogRebuildProgress({
        visible: true,
        label: completedView.label,
        detail: completedDetailParts.filter(Boolean).join(" · "),
        percent: 100,
        indeterminate: false,
      });
      return;
    }
    if (latestStatus === "failed") {
      syncChangelogMaintenancePanelOpen({ forceOpen: true });
      const errorMessage = asText(latest.error_message, "Unbekannter Fehler");
      const cancelledHint = /abgebrochen|unterbrochen|ueberholt|überholt/i.test(errorMessage) ? " (abgebrochen)" : "";
      const restartHint = /neu gestartet|unterbrochen/i.test(errorMessage)
        ? " — vermutlich Deploy/Restart während des Laufs; Inventur neu starten."
        : "";
      setChangelogMaintenanceSummaryHint(`${jobModeLabel} #${latestId} fehlgeschlagen`, true);
      setChangelogRebuildJobStatus(
        `${jobModeLabel} #${latestId} fehlgeschlagen${cancelledHint}: ${errorMessage}${restartHint}`,
        true
      );
      setChangelogRebuildProgress({
        visible: true,
        label: `${jobModeLabel} #${latestId} fehlgeschlagen`,
        detail: errorMessage,
        percent: 0,
        indeterminate: false,
        isError: true,
      });
      return;
    }
    if (latestStatus === "running") {
      syncChangelogMaintenancePanelOpen({ forceOpen: true });
      const runningView = buildChangelogRebuildProgressView(latestProgress, jobModeLabel);
      setChangelogRebuildProgress({
        visible: true,
        label: runningView.label,
        detail: runningView.detail,
        percent: runningView.percent,
        indeterminate: runningView.indeterminate,
      });
      const reportsScannedRunning = Number(latestProgress.reports_scanned || 0);
      const reportsTotalRunning = Number(latestProgress.reports_total || 0);
      const progressMessage = asText(latestProgress.message, "");
      const reportPulseMatch = progressMessage.match(/Report\s+(\d+)\s*\/\s*([\d'.,\s]+)/i);
      let reportsHint = "";
      if (reportsTotalRunning > 0) {
        if (reportsScannedRunning <= 0 && reportPulseMatch) {
          const activeReport = Number(String(reportPulseMatch[1] || "").replace(/[^\d]/g, "") || 0);
          reportsHint = ` · Report ${formatChangelogProgressCount(activeReport)}/${formatChangelogProgressCount(reportsTotalRunning)} in Arbeit`;
        } else {
          reportsHint = ` · Reports ${formatChangelogProgressCount(reportsScannedRunning)}/${formatChangelogProgressCount(reportsTotalRunning)}`;
        }
      }
      setChangelogRebuildJobStatus(
        `${jobModeLabel} #${latestId} läuft (${daysLabel}${reportsHint})…`
      );
      setChangelogMaintenanceSummaryHint(`${jobModeLabel} #${latestId} läuft`);
      pollAfterLoad = true;
      pollDelayMs = latestMode === "inventory_rebuild" ? 15000 : 5000;
      return;
    }
    if (latestStatus === "pending") {
      syncChangelogMaintenancePanelOpen({ forceOpen: true });
      setChangelogMaintenanceSummaryHint(`${jobModeLabel} #${latestId} geplant`);
      pollAfterLoad = true;
      pollDelayMs = 1500;
    }
    const scheduledAt = asText(latest.scheduled_for_utc, "");
    setChangelogRebuildJobStatus(`${jobModeLabel} #${latestId} geplant (${daysLabel}) · ${formatUtcPlus2(scheduledAt)}`);
    setChangelogRebuildProgress({
      visible: true,
      label: `${jobModeLabel}-Job geplant...`,
      indeterminate: true,
    });
    if (latestStatus === "pending") {
      return;
    }
  } catch (error) {
    const errorText = asText(error?.message, "unbekannter Fehler");
    const isAbort = error?.name === "AbortError";
    const isGatewayTimeout = isAbort || /\b504\b/i.test(errorText) || /gateway timeout/i.test(errorText) || /aborted/i.test(errorText);
    const isDbBusy = /\b503\b/i.test(errorText) || /service unavailable/i.test(errorText);
    const activeJobId = Number(state.changelogActiveJobId || 0);
    const activeRunning = asText(state.changelogActiveJobStatus, "").toLowerCase() === "running";
    if ((isGatewayTimeout || isDbBusy) && activeJobId > 0 && activeRunning) {
      setChangelogRebuildJobStatus(
        `Inventur/Rebuild #${activeJobId} läuft vermutlich weiter (API blockiert durch DB-Last).`,
        false,
      );
      setChangelogRebuildProgress({
        visible: true,
        label: `Job #${activeJobId} – Status per Konsole`,
        detail: "/root/monitoring-server/scripts/watch-inventur-job.sh --once",
        indeterminate: true,
        isError: false,
      });
      pollAfterLoad = shouldPollChangelogRebuildJobs();
      pollDelayMs = 20000;
      return;
    }
    const hint = isGatewayTimeout || isDbBusy
      ? " · Konsole: scripts/watch-inventur-job.sh --once"
      : "";
    setChangelogRebuildJobStatus(`Job-Status Fehler: ${errorText}${hint}`, true);
    setChangelogRebuildProgress({
      visible: true,
      label: `Job-Status Fehler: ${errorText}`,
      detail: hint ? hint.replace(/^ · /, "") : "",
      indeterminate: isGatewayTimeout || isDbBusy,
      isError: !isGatewayTimeout && !isDbBusy,
    });
    pollAfterLoad = shouldPollChangelogRebuildJobs();
    pollDelayMs = isGatewayTimeout ? 20000 : 2500;
  } finally {
    if (pollAfterLoad && shouldPollChangelogRebuildJobs()) {
      scheduleChangelogRebuildPoll(pollDelayMs);
    }
  }
}

async function runInventoryChangelogRebuildNow() {
  const button = document.getElementById("runInventoryChangelogRebuildButton");
  const confirmed = window.confirm(
    "WARNUNG: Inventur-Rebuild über ALLE Reports.\n\n"
    + "1) Changelog-Tabellen werden geleert\n"
    + "2) Erster Report pro Host = Inventur (Hardware, Lizenzen, Add-ons, DBs)\n"
    + "3) Weitere Reports = Changelog-Deltas bis heute\n"
    + "4) Danach Live-Tracking bei neuen Reports\n\n"
    + "Der Lauf kann bei vielen Reports lange dauern. Fortfahren?"
  );
  if (!confirmed) return;

  const safetyToken = window.prompt(
    "Sicherheitsabfrage: Bitte INVENTUR eingeben, um den Inventur-Rebuild zu starten.",
    ""
  );
  if (safetyToken !== "INVENTUR") {
    setChangelogRebuildJobStatus("Abgebrochen: Sicherheitsbestätigung nicht erfüllt.", true);
    return;
  }

  if (button) button.disabled = true;
  setChangelogRebuildJobStatus("Inventur-Rebuild wird im Hintergrund gestartet…");
  setChangelogRebuildProgress({
    visible: true,
    label: "Inventur-Rebuild startet…",
    indeterminate: true,
  });

  try {
    const response = await fetch("/api/v1/admin/changelog-rebuild/schedule", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        days: 0,
        run_now: true,
        force_rebuild: true,
        job_mode: "inventory_rebuild",
      }),
    });
    if (!response.ok) throw await buildHttpErrorFromResponse(response);
    const data = await response.json().catch(() => ({}));
    const scheduledJobId = Number(data?.scheduled?.job?.id || 0);
    setChangelogRebuildJobStatus(
      scheduledJobId > 0
        ? `Inventur-Rebuild #${scheduledJobId} gestartet. Fortschritt wird automatisch aktualisiert.`
        : "Inventur-Rebuild gestartet. Fortschritt wird automatisch aktualisiert."
    );
    await loadHostConfigChanges();
    if (state.selectedHost) {
      await loadConfigChangelogForHost();
      await loadDatabaseLifecycleForHost();
    }
    await loadChangelogRebuildJobsStatus();
  } catch (error) {
    setChangelogRebuildJobStatus(`Inventur-Rebuild Fehler: ${error.message}`, true);
    setChangelogRebuildProgress({
      visible: true,
      label: `Inventur-Rebuild Fehler: ${error.message}`,
      isError: true,
    });
  } finally {
    if (button) button.disabled = false;
  }
}

async function runChangelogRebuildNow(days = CHANGELOG_REBUILD_DAYS) {
  const button = document.getElementById("runChangelogRebuildNowButton");
  const targetDays = Math.max(1, Math.min(365, Number(days) || CHANGELOG_REBUILD_DAYS));
  const confirmed = window.confirm(
    `WARNUNG: Das globale Changelog wird komplett neu aufgebaut (Stichtag heute, ${targetDays} Tag(e)).\n\nDabei werden alle vorhandenen Changelog-Daten gelöscht und aus Reports neu erzeugt (Host-Config + DB-Lifecycle).\n\nFortfahren?`
  );
  if (!confirmed) return;

  const safetyToken = window.prompt("Sicherheitsabfrage: Bitte REBUILD eingeben, um den vollständigen Changelog-Neuaufbau zu starten.", "");
  if (safetyToken !== "REBUILD") {
    setChangelogRebuildJobStatus("Abgebrochen: Sicherheitsbestätigung nicht erfüllt.", true);
    return;
  }

  if (button) button.disabled = true;
  setChangelogRebuildJobStatus("Rebuild-Job wird im Hintergrund gestartet (niedrige Priorität)...");
  setChangelogRebuildProgress({
    visible: true,
    label: "Rebuild startet im Hintergrund...",
    indeterminate: true,
  });

  try {
    const response = await fetch("/api/v1/admin/changelog-rebuild/schedule", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        days: targetDays,
        run_now: true,
        force_rebuild: true,
      }),
    });
    if (!response.ok) throw await buildHttpErrorFromResponse(response);
    const data = await response.json().catch(() => ({}));

    const scheduledJobId = Number(data?.scheduled?.job?.id || 0);
    setChangelogRebuildJobStatus(
      scheduledJobId > 0
        ? `Rebuild-Job #${scheduledJobId} im Hintergrund gestartet. Fortschritt wird automatisch aktualisiert.`
        : "Rebuild-Job im Hintergrund gestartet. Fortschritt wird automatisch aktualisiert."
    );

    await loadHostConfigChanges();
    if (state.selectedHost) {
      await loadConfigChangelogForHost();
      await loadDatabaseLifecycleForHost();
    }
    await loadChangelogRebuildJobsStatus();
  } catch (error) {
    setChangelogRebuildJobStatus(`Rebuild Fehler: ${error.message}`, true);
    setChangelogRebuildProgress({
      visible: true,
      label: `Rebuild Fehler: ${error.message}`,
      indeterminate: false,
      isError: true,
    });
  } finally {
    if (button) button.disabled = false;
  }
}

async function runCombinedBackfill(days = 7) {
  const button = document.getElementById("backfillHostConfigChangesButton");
  const targetDays = Math.max(1, Math.min(30, Number(days) || 7));
  const confirmed = window.confirm(
    `Backfill (Config-Changes + DB-Lifecycle) für die letzten ${targetDays} Tage im Hintergrund starten?\n\nDie UI bleibt nutzbar; Fortschritt siehst du beim Rebuild-Status.`
  );
  if (!confirmed) return;

  if (button) button.disabled = true;
  setHostConfigChangesBackfillStatus("Backfill-Job wird im Hintergrund gestartet...");
  setChangelogRebuildProgress({
    visible: true,
    label: "Backfill startet im Hintergrund...",
    indeterminate: true,
  });

  try {
    const response = await fetch("/api/v1/host-config-changes/backfill", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ days: targetDays, async: true, run_now: true }),
    });

    if (!response.ok) throw await buildHttpErrorFromResponse(response);
    const data = await response.json();
    const scheduledJobId = Number(data?.scheduled?.job?.id || 0);
    const statusText = asText(data?.scheduled?.status, "");
    if (statusText === "already_scheduled") {
      setHostConfigChangesBackfillStatus("Backfill läuft bereits (siehe Status unten).");
    } else {
      setHostConfigChangesBackfillStatus(
        scheduledJobId > 0
          ? `Backfill-Job #${scheduledJobId} im Hintergrund gestartet (niedrige Priorität).`
          : "Backfill-Job im Hintergrund gestartet (niedrige Priorität)."
      );
    }
    await loadChangelogRebuildJobsStatus();
  } catch (error) {
    setHostConfigChangesBackfillStatus(`Backfill Fehler: ${error.message}`, true);
    setChangelogRebuildProgress({
      visible: true,
      label: `Backfill Fehler: ${error.message}`,
      indeterminate: false,
      isError: true,
    });
  } finally {
    if (button) button.disabled = false;
  }
}

function updateHeaderStatChips() {
  const alertChip = document.getElementById("headerAlertChip");
  const alertCount = document.getElementById("headerAlertCount");
  const inactiveChip = document.getElementById("headerInactiveChip");
  const inactiveCount = document.getElementById("headerInactiveCount");
  const criticalChip = document.getElementById("headerCriticalChip");
  const criticalCount = document.getElementById("headerCriticalCount");
  const acknowledgedChip = document.getElementById("headerAcknowledgedChip");
  const acknowledgedCount = document.getElementById("headerAcknowledgedCount");
  const mutedChip = document.getElementById("headerMutedChip");
  const mutedCount = document.getElementById("headerMutedCount");
  const activeHostsChip = document.getElementById("headerActiveHostsChip");
  const activeHostsCount = document.getElementById("headerActiveHostsCount");
  const dbReportsChip = document.getElementById("headerDbReportsChip");
  const dbReportsCount = document.getElementById("headerDbReportsCount");
  const dbReportsHourChip = document.getElementById("headerDbReportsHourChip");
  const dbReportsHourCount = document.getElementById("headerDbReportsHourCount");
  const dbSizeChip = document.getElementById("headerDbSizeChip");
  const dbSizeValue = document.getElementById("headerDbSizeValue");
  const dbSizeDeltaChip = document.getElementById("headerDbSizeDeltaChip");
  const dbSizeDeltaValue = document.getElementById("headerDbSizeDeltaValue");
  const licenseChip = document.getElementById("headerLicenseChip");
  const licenseHw = document.getElementById("headerLicenseHw");
  const licenseInst = document.getElementById("headerLicenseInst");
  const licenseSystem = document.getElementById("headerLicenseSystem");
  const licenseCustomer = document.getElementById("headerLicenseCustomer");
  const licenseHolder = document.getElementById("headerLicenseHolder");
  const licenseExpiry = document.getElementById("headerLicenseExpiry");
  const licenseExpiryItem = document.getElementById("headerLicenseExpiryItem");
  const licenseCopyTechButton = document.getElementById("headerLicenseCopyTechButton");
  const currentTrendValues = {};
  if (alertChip && alertCount) {
    const alertValue = Math.max(0, Number(state.globalOpenAlertsCount || 0));
    alertCount.textContent = String(alertValue);
    currentTrendValues.alert = alertValue;
    alertChip.classList.remove("hidden");
  }
  if (inactiveChip && inactiveCount) {
    const inactiveValue = Math.max(0, Number(state.inactiveHostsCount || 0));
    inactiveCount.textContent = String(inactiveValue);
    currentTrendValues.inactive = inactiveValue;
    inactiveChip.classList.remove("hidden");
  }
  if (criticalChip && criticalCount) {
    const fallbackCritical = (Array.isArray(state.hosts) ? state.hosts : []).reduce((sum, host) => {
      const direct = Number(host?.open_critical_alert_count);
      if (Number.isFinite(direct) && direct >= 0) {
        return sum + direct;
      }
      const payloadAlerts = Array.isArray(host?.payload?.alerts)
        ? host.payload.alerts.filter((item) => item?.severity === "critical" && item?.status !== "resolved" && item?.status !== "closed").length
        : 0;
      return sum + payloadAlerts;
    }, 0);
    const criticalOpen = Math.max(0, Number(state.globalCriticalOpenAlertsCount || 0) || fallbackCritical);
    criticalCount.textContent = String(criticalOpen);
    currentTrendValues.critical = criticalOpen;
    criticalChip.classList.remove("hidden");
  }
  if (acknowledgedChip && acknowledgedCount) {
    const acknowledgedValue = Math.max(0, Number(state.globalAcknowledgedOpenAlertsCount || 0));
    acknowledgedCount.textContent = String(acknowledgedValue);
    currentTrendValues.acknowledged = acknowledgedValue;
    acknowledgedChip.classList.remove("hidden");
  }
  if (mutedChip && mutedCount) {
    const mutedValue = Math.max(0, Number(state.globalMutedOpenAlertsCount || 0));
    mutedCount.textContent = String(mutedValue);
    currentTrendValues.muted = mutedValue;
    mutedChip.classList.remove("hidden");
  }
  if (activeHostsChip && activeHostsCount) {
    const inactiveCount = Math.max(0, Number(state.inactiveHostsCount || 0));
    const canonicalHosts = (Array.isArray(state.hosts) ? state.hosts : []).filter((host) => isCanonicalHostCard(host));
    const activeFromCards = canonicalHosts.filter((host) => isHostRecentlyActive(host)).length;
    const totalCanonical = Number(state.totalHosts || 0) > 0
      ? Math.max(0, Number(state.totalHosts || 0) - (Array.isArray(state.hosts) ? state.hosts.filter((host) => host?.is_temporary_identity).length : 0))
      : canonicalHosts.length;
    const activeFromTotals = Math.max(0, totalCanonical - inactiveCount);
    const activeHosts = Math.max(activeFromCards, activeFromTotals);
    activeHostsCount.textContent = String(activeHosts);
    currentTrendValues.activeHosts = activeHosts;
    activeHostsChip.classList.remove("hidden");
  }
  if (dbReportsChip && dbReportsCount) {
    const dbReportsValue = state.dbReportsTotal === null ? null : Number(state.dbReportsTotal);
    dbReportsCount.textContent = dbReportsValue === null ? "-" : dbReportsValue.toLocaleString("de-CH");
    currentTrendValues.dbReports = dbReportsValue === null ? Number.NaN : dbReportsValue;
    dbReportsChip.classList.remove("hidden");
  }
  if (dbReportsHourChip && dbReportsHourCount) {
    const dbReportsHourValue = Number(state.dbReportsLastHour || 0);
    dbReportsHourCount.textContent = dbReportsHourValue.toLocaleString("de-CH");
    currentTrendValues.dbReportsHour = dbReportsHourValue;
    dbReportsHourChip.classList.remove("hidden");
  }
  if (dbSizeChip && dbSizeValue) {
    const dbSizeBytes = Number(state.dbTotalFileBytes);
    dbSizeValue.textContent = state.dbTotalFileBytes === null
      ? "-"
      : `${formatMegabytesFromBytes(state.dbTotalFileBytes)} MB`;
    currentTrendValues.dbSize = Number.isFinite(dbSizeBytes) ? dbSizeBytes : Number.NaN;
    dbSizeChip.classList.remove("hidden");
  }
  if (dbSizeDeltaChip && dbSizeDeltaValue) {
    const dbSizeDeltaBytes = Number(state.dbSizeDelta1hBytes);
    dbSizeDeltaValue.textContent = state.dbSizeDelta1hBytes === null
      ? "-"
      : `${formatSignedMegabytesFromBytes(state.dbSizeDelta1hBytes)} MB`;
    currentTrendValues.dbSizeDelta = Number.isFinite(dbSizeDeltaBytes) ? dbSizeDeltaBytes : Number.NaN;
    dbSizeDeltaChip.classList.remove("hidden");
  }
  if (licenseChip) {
    const payload = state.currentReport && typeof state.currentReport.payload === "object" ? state.currentReport.payload : {};
    const sapLicense = payload && typeof payload.sap_license === "object" ? payload.sap_license : {};
    const selectedHost = asText(state.selectedHost, "").trim();
    const reportHost = asText(state.currentReport?.hostname, "").trim();
    const hw = asText(sapLicense.hardware_key, "").trim();
    const inst = asText(sapLicense.instno, "").trim();
    const system = asText(sapLicense.system_nr, "").trim();
    const systemType = asText(sapLicense.system_type, "").trim();
    const customerNo = asText(sapLicense.customer_no, "").trim();
    const holder = asText(sapLicense.customer_name, "").trim();
    const expiryRaw = asText(sapLicense.expiration, "").trim();
    const expiry = /^\d{8}$/.test(expiryRaw)
      ? `${expiryRaw.substring(6, 8)}.${expiryRaw.substring(4, 6)}.${expiryRaw.substring(0, 4)}`
      : expiryRaw;
    const hasData = [hw, inst, system, systemType, customerNo, holder, expiry].some((entry) => Boolean(entry));
    const hasSelectedHost = Boolean(selectedHost);
    const hostMatchesSelection = Boolean(hasSelectedHost && reportHost && reportHost === selectedHost);
    const showLicenseChip = Boolean(hasData && hasSelectedHost && hostMatchesSelection);
    const technicalCopy = [
      `HW-Key: ${hw || "-"}`,
      `Installationsnummer: ${inst || "-"}`,
      `Systemnummer: ${system || "-"}`,
    ].join("\n");

    licenseChip.classList.toggle("hidden", !showLicenseChip);
    if (licenseCopyTechButton) {
      licenseCopyTechButton.disabled = !showLicenseChip;
      licenseCopyTechButton.setAttribute("data-copy", showLicenseChip ? technicalCopy : "");
      licenseCopyTechButton.title = showLicenseChip
        ? "HW-Key, Instno und System in Zwischenablage kopieren"
        : "Nur bei vorhandenen Lizenzdaten verfügbar";
    }

    if (showLicenseChip) {
      if (licenseHw) licenseHw.textContent = hw || "-";
      if (licenseInst) licenseInst.textContent = inst || "-";
      if (licenseSystem) licenseSystem.textContent = system || "-";
      if (licenseCustomer) licenseCustomer.textContent = customerNo || "-";
      if (licenseHolder) licenseHolder.textContent = holder || "-";
      if (licenseExpiry) licenseExpiry.textContent = expiry || "-";
      if (licenseExpiryItem) licenseExpiryItem.classList.toggle("hidden", !expiry);
      const titleLines = [
        `HW-Key: ${hw || "-"}`,
        `Installationsnummer: ${inst || "-"}`,
        `Systemnummer: ${system || "-"}`,
        `Systemtyp: ${systemType || "-"}`,
        `Kundennummer: ${customerNo || "-"}`,
        `Lizenznehmer: ${holder || "-"}`,
      ];
      if (expiry) {
        titleLines.push(`Gültig bis: ${expiry}`);
      }
      licenseChip.title = titleLines.join("\n");
    } else {
      licenseChip.title = "SAP B1 Lizenzinfos";
      if (licenseExpiryItem) licenseExpiryItem.classList.add("hidden");
    }
  }

  const previousTrendValues = headerKpiTrendPreviousValues || {};
  const trendBindings = [
    ["alert", alertChip, alertCount],
    ["critical", criticalChip, criticalCount],
    ["acknowledged", acknowledgedChip, acknowledgedCount],
    ["muted", mutedChip, mutedCount],
    ["activeHosts", activeHostsChip, activeHostsCount],
    ["inactive", inactiveChip, inactiveCount],
    ["dbReports", dbReportsChip, dbReportsCount],
    ["dbSize", dbSizeChip, dbSizeValue],
    ["dbReportsHour", dbReportsHourChip, dbReportsHourCount],
    ["dbSizeDelta", dbSizeDeltaChip, dbSizeDeltaValue],
  ];
  for (const [key, chipEl, countEl] of trendBindings) {
    if (!chipEl || !countEl) {
      continue;
    }
    const previousValue = Number(previousTrendValues[key]);
    const currentValue = Number(currentTrendValues[key]);
    const direction = resolveHeaderKpiTrendDirection(previousValue, currentValue);
    setHeaderKpiTrendArrow(chipEl, countEl, direction);
  }
  headerKpiTrendPreviousValues = { ...currentTrendValues };

  if (alertChip) {
    const alertValue = Math.max(0, Number(state.globalOpenAlertsCount || 0));
    alertChip.classList.toggle("header-stat-chip--alarm-active", alertValue > 0);
  }
  if (criticalChip) {
    const criticalValue = Math.max(0, Number.parseInt(String(criticalCount?.textContent || "0"), 10) || 0);
    criticalChip.classList.toggle("header-stat-chip--alarm-active", criticalValue > 0);
  }

  scheduleHeaderKpiUniformCardWidthSync();
}

function wireHeaderLicenseCopyButton() {
  const button = document.getElementById("headerLicenseCopyTechButton");
  if (!button || button.dataset.wired === "1") {
    return;
  }
  button.dataset.wired = "1";
  button.addEventListener("click", async (event) => {
    event.preventDefault();
    event.stopPropagation();
    const text = String(button.getAttribute("data-copy") || "").trim();
    if (!text) {
      return;
    }
    try {
      await navigator.clipboard.writeText(text);
      const original = button.textContent;
      button.textContent = "✅";
      setTimeout(() => {
        button.textContent = original;
      }, 1200);
    } catch {
      const original = button.textContent;
      button.textContent = "❌";
      setTimeout(() => {
        button.textContent = original;
      }, 1200);
    }
  });
}

function globalHeadsUpBaselineToggleLabel(collapsed) {
  return collapsed ? "▸" : "▾";
}

function renderGlobalAlertRowHtml(item) {
  const severityClass = item.severity === "critical" ? "severity-critical" : "severity-warning";
  const hostDisplayName = asText(item.display_name || item.hostname);
  const customerName = asText(item.customer_name || "");
  const hostName = asText(item.hostname);
  const isMuted = Boolean(item.is_muted);
  const isAcknowledged = Boolean(item.is_acknowledged);
  const isClosed = Boolean(item.is_closed);
  const ackNote = asText(item.ack_note);
  const ackTitle = isAcknowledged
    ? `Quittiert von ${resolveWebUserActionLabel(item, "ack_by") || "-"} am ${formatUtcPlus2(item.ack_at_utc)}${ackNote ? ` | Notiz: ${ackNote}` : ""}`
    : "Alert quittieren";
  const isHeadsUpSuppressed = Boolean(item.is_heads_up_suppressed);
  const headsUpTitle = isHeadsUpSuppressed
    ? "Heads-Up wieder aktivieren"
    : "Heads-Up für diesen Alert unterdrücken";
  const closeTitle = isClosed
    ? `Abgeschlossen von ${resolveWebUserActionLabel(item, "closed_by") || "-"} am ${formatUtcPlus2(item.closed_at_utc)} – klicken zum Wiederöffnen`
    : "Alert abschliessen";
  const hostUid = asText(item.host_uid || hostName);
  const alertId = Number(item.id || 0);
  const muteBtn = `<button class="alert-mute-btn${isMuted ? " muted" : ""}" type="button" data-action="toggle-mute" data-alert-id="${alertId}" data-hostname="${escapeHtml(hostName)}" data-host-uid="${escapeHtml(hostUid)}" data-mountpoint="${escapeHtml(asText(item.mountpoint))}" data-muted="${isMuted ? "1" : "0"}" title="${isMuted ? "Stummschaltung aufheben" : "Alert stummschalten"}">${isMuted ? "🔇" : "🔔"}</button>`;
  const headsUpBtn = `<button class="alert-headsup-btn${isHeadsUpSuppressed ? " suppressed" : ""}" type="button" data-action="toggle-headsup" data-alert-id="${alertId}" data-hostname="${escapeHtml(hostName)}" data-host-uid="${escapeHtml(hostUid)}" data-mountpoint="${escapeHtml(asText(item.mountpoint))}" data-headsup-suppressed="${isHeadsUpSuppressed ? "1" : "0"}" title="${escapeHtml(headsUpTitle)}">${isHeadsUpSuppressed ? "⏸️" : "📣"}</button>`;
  const ackBtn = `<button class="alert-ack-btn${isAcknowledged ? " acknowledged" : ""}" type="button" data-action="ack" data-alert-id="${alertId}" data-acknowledged="${isAcknowledged ? "1" : "0"}" data-hostname="${escapeHtml(hostName)}" data-host-uid="${escapeHtml(hostUid)}" data-mountpoint="${escapeHtml(asText(item.mountpoint))}" data-ack-note="${encodeURIComponent(ackNote)}" title="${escapeHtml(ackTitle)}">${isAcknowledged ? "✅" : "✓"}</button>`;
  const closeBtn = `<button class="alert-close-btn${isClosed ? " closed" : ""}" type="button" data-action="close" data-alert-id="${alertId}" data-hostname="${escapeHtml(hostName)}" data-host-uid="${escapeHtml(hostUid)}" data-mountpoint="${escapeHtml(asText(item.mountpoint))}" data-closed="${isClosed ? "1" : "0"}" title="${escapeHtml(closeTitle)}">${isClosed ? "↺" : "✕"}</button>`;
  const ackMeta = isAcknowledged
    ? `<div class="count compact">✅ ${escapeHtml(resolveWebUserActionLabel(item, "ack_by") || "-")} | ${escapeHtml(formatUtcPlus2(item.ack_at_utc))}</div>`
    : "";
  const closeMeta = isClosed
    ? `<div class="count compact alert-closed-meta">🔒 ${escapeHtml(resolveWebUserActionLabel(item, "closed_by") || "-")} | ${escapeHtml(formatUtcPlus2(item.closed_at_utc))}</div>`
    : "";
  const mutedMeta = isMuted && asText(item.muted_at_utc, "").trim()
    ? `<div class="count compact alert-muted-meta">🔇 ${escapeHtml(resolveWebUserActionLabel(item, "muted_by") || asText(item.muted_by, "-"))} | ${escapeHtml(formatUtcPlus2(item.muted_at_utc))}</div>`
    : "";
  const currentReportStand = asText(item.current_report_at_utc, "").trim();
  const currentReportStandHtml = currentReportStand
    ? `<div class="count compact">Stand: ${escapeHtml(formatUtcPlus2(currentReportStand))}</div>`
    : "";
  return `
    <tr class="${isMuted ? "alert-row-muted" : ""}${isClosed ? " alert-row-closed" : ""}">
      <td>
        <div class="global-host-cell">
          ${customerName ? `<span class="global-host-customer">${escapeHtml(customerName)}</span>` : ""}
          <span class="global-host-label">${escapeHtml(hostDisplayName)}</span>
          <span class="global-hostname-sub">(${escapeHtml(hostName)})</span>
          <span class="global-hostname-sub alert-id-sub">#${item.id}</span>
        </div>
      </td>
      <td><span class="badge ${severityClass}">${escapeHtml(asText(item.severity))}</span></td>
      <td>${renderAlertMountpointLabel(item.mountpoint, 56)}</td>
      <td>${formatPercent(item.used_percent)}</td>
      <td>${formatPercent(item.current_used_percent)}${currentReportStandHtml}</td>
      <td><span class="${deltaSignClass(item.delta_used_percent)}">${formatSignedPercent(item.delta_used_percent)}</span></td>
      <td title="Zuletzt gesehen: ${escapeHtml(formatUtcPlus2(item.last_seen_at_utc))}">${escapeHtml(formatUtcPlus2(item.created_at_utc))}${mutedMeta}${ackMeta}${closeMeta}</td>
      <td><div class="alert-action-buttons">${muteBtn}${headsUpBtn}${ackBtn}${closeBtn}</div></td>
    </tr>
  `;
}

function renderGlobalHeadsUpBaselineSection(baselineAlerts, totalCount) {
  const sectionEl = document.getElementById("globalHeadsUpBaselineSection");
  const rowsEl = document.getElementById("globalHeadsUpBaselineRows");
  const bodyEl = document.getElementById("globalHeadsUpBaselineBody");
  const countEl = document.getElementById("globalHeadsUpBaselineCount");
  const toggleButton = document.getElementById("toggleGlobalHeadsUpBaselineButton");
  if (!sectionEl || !rowsEl || !bodyEl) {
    return;
  }

  const count = Math.max(0, Number(totalCount || baselineAlerts.length || 0));
  state.globalHeadsUpBaselineCount = count;
  if (state.globalShowMutedOnly || count <= 0) {
    sectionEl.classList.add("hidden");
    rowsEl.innerHTML = "";
    return;
  }

  sectionEl.classList.remove("hidden");
  if (countEl) {
    countEl.textContent = `${count}`;
  }
  const collapsed = state.globalHeadsUpBaselineCollapsed === true;
  bodyEl.classList.toggle("hidden", collapsed);
  if (toggleButton) {
    toggleButton.textContent = globalHeadsUpBaselineToggleLabel(collapsed);
    toggleButton.setAttribute("aria-expanded", collapsed ? "false" : "true");
  }

  if (!Array.isArray(baselineAlerts) || baselineAlerts.length === 0) {
    rowsEl.innerHTML = '<tr><td colspan="8" class="muted">Keine Dauerzustands-Alerts für den gesetzten Filter.</td></tr>';
    return;
  }

  rowsEl.innerHTML = baselineAlerts.map((item) => renderGlobalAlertRowHtml(item)).join("");
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
  const mutedQuery = state.globalShowMutedOnly ? "&muted=yes" : "";
  const headsUpSuppressedQuery = state.globalShowMutedOnly ? "" : "&heads_up_suppressed=no";
  const countryQuery = state.globalCountryFilter && state.globalCountryFilter !== "all"
    ? `&country=${encodeURIComponent(state.globalCountryFilter)}`
    : "";
  const statusParam = state.globalShowMutedOnly ? "all" : "open";

  if (updateList && rowsEl && !append) {
    rowsEl.innerHTML = "<tr><td colspan=\"8\" class=\"muted\">Lade globale Alerts...</td></tr>";
  }
  if (updateList && summaryEl && !append) {
    summaryEl.textContent = "";
  }
  if (!append) {
    state.globalAlertsOffset = 0;
    state.globalAlertsTotal = 0;
    state.globalAlertsLoadedItems = [];
  }
  if (panelBody && toggleButton) {
    panelBody.classList.toggle("hidden", state.globalAlertsCollapsed);
    toggleButton.textContent = state.globalAlertsCollapsed ? "▸" : "▾";
  }

  try {
    const summaryPromise = fetch("/api/v1/alerts-summary", {
      credentials: "same-origin",
      cache: "no-store",
    });
    const acknowledgedPromise = fetch("/api/v1/alerts?status=open&acknowledged=yes&limit=1&offset=0", {
      credentials: "same-origin",
      cache: "no-store",
    }).catch(() => null);
    const listPromise = updateList && rowsEl
      ? fetch(`/api/v1/alerts?status=${statusParam}&limit=${requestLimit}&offset=${requestOffset}${severityQuery}${acknowledgedQuery}${closedQuery}${mutedQuery}${headsUpSuppressedQuery}${countryQuery}`, {
        credentials: "same-origin",
        cache: "no-store",
      })
      : null;
    const baselinePromise = updateList && rowsEl && !state.globalShowMutedOnly
      ? fetch(`/api/v1/alerts?status=open&limit=500&offset=0&heads_up_suppressed=yes${severityQuery}${acknowledgedQuery}${closedQuery}${countryQuery}`, {
        credentials: "same-origin",
        cache: "no-store",
      }).catch(() => null)
      : null;

    if (!updateList || !rowsEl || !summaryEl) {
      const summaryResp = await summaryPromise;
      if (!summaryResp.ok) throw new Error("Summary HTTP " + summaryResp.status);
      const summaryData = await summaryResp.json();
      state.globalOpenAlertsCount = Number(summaryData?.open?.total || 0);
      state.globalCriticalOpenAlertsCount = Number(summaryData?.open?.critical || 0);
      state.globalMutedOpenAlertsCount = Number(summaryData?.muted?.total || 0);
      state.globalHeadsUpSuppressedOpenAlertsCount = Number(summaryData?.heads_up_suppressed?.total || 0);
      const acknowledgedResp = await acknowledgedPromise;
      if (acknowledgedResp && acknowledgedResp.ok) {
        const acknowledgedData = await acknowledgedResp.json();
        state.globalAcknowledgedOpenAlertsCount = Number(acknowledgedData?.total || 0);
      }
      globalAlertsTabButton.textContent = state.globalOpenAlertsCount > 0
        ? `Globale Alerts (${state.globalOpenAlertsCount})`
        : "Globale Alerts";
      globalAlertsTabButton.classList.toggle("alert-active", state.globalOpenAlertsCount > 0);
      updateHeaderStatChips();
      return;
    }

    let listData = null;
    let listLoadFailed = false;
    let listLoadError = "";
    if (listPromise) {
      try {
        const listResp = await listPromise;
        if (!listResp.ok) {
          listLoadFailed = true;
          listLoadError = "List HTTP " + listResp.status;
        } else {
          listData = await listResp.json();
        }
      } catch (listError) {
        listLoadFailed = true;
        listLoadError = listError?.message || "List request failed";
      }
    }

    const alerts = listData?.alerts || [];
    if (Array.isArray(listData?.available_countries)) {
      state.globalAvailableCountries = listData.available_countries;
      renderGlobalCountryFilterOptions();
    }
    const accumulatedAlerts = append
      ? (Array.isArray(state.globalAlertsLoadedItems) ? state.globalAlertsLoadedItems : []).concat(alerts)
      : alerts;
    state.globalAlertsLoadedItems = accumulatedAlerts;
    const totalForFilter = Number(listData?.total || 0);
    state.globalAlertsTotal = totalForFilter;

    if (listLoadFailed && !append && rowsEl) {
      const listHint = /502/.test(listLoadError)
        ? "Gateway-Fehler (502): Server/DB überlastet. Bitte in 30 Sekunden erneut laden."
        : `Fehler beim Laden: ${escapeHtml(listLoadError)}`;
      rowsEl.innerHTML = `<tr><td colspan="8" class="muted">${listHint}</td></tr>`;
      if (loadMoreButton) loadMoreButton.classList.add("hidden");
      if (pagingStatus) pagingStatus.textContent = "– / –";
      if (summaryEl) {
        summaryEl.textContent = /502/.test(listLoadError)
          ? "Alert-Liste vorübergehend nicht verfügbar (502)"
          : `Alert-Liste: ${listLoadError}`;
      }
    } else if (!listLoadFailed && !append && alerts.length === 0) {
      const emptyMessage = state.globalShowMutedOnly
        ? "Keine stummgeschalteten Alerts vorhanden."
        : "Keine offenen Alerts für den gesetzten Filter.";
      rowsEl.innerHTML = `<tr><td colspan="8" class="muted">${emptyMessage}</td></tr>`;
      if (loadMoreButton) loadMoreButton.classList.add("hidden");
      if (pagingStatus) pagingStatus.textContent = "0 / 0";
    } else if (!listLoadFailed) {
      const rowsHtml = alerts.map((item) => renderGlobalAlertRowHtml(item)).join("");

      if (append && requestOffset > 0) {
        rowsEl.insertAdjacentHTML("beforeend", rowsHtml);
      } else {
        rowsEl.innerHTML = rowsHtml;
      }
    }

    let baselineData = null;
    if (baselinePromise) {
      try {
        const baselineResp = await baselinePromise;
        if (baselineResp && baselineResp.ok) {
          baselineData = await baselineResp.json();
        }
      } catch (baselineError) {
        console.warn("heads-up baseline alerts load failed:", baselineError);
      }
    }

    if (!listLoadFailed) {
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
    }

    let summaryData = null;
    try {
      const summaryResp = await summaryPromise;
      if (summaryResp.ok) {
        summaryData = await summaryResp.json();
      } else {
        console.warn("alerts-summary failed:", summaryResp.status);
      }
    } catch (summaryError) {
      console.warn("alerts-summary error:", summaryError);
    }

    if (summaryData) {
      state.globalOpenAlertsCount = Number(summaryData?.open?.total || 0);
      state.globalCriticalOpenAlertsCount = Number(summaryData?.open?.critical || 0);
      state.globalMutedOpenAlertsCount = Number(summaryData?.muted?.total || 0);
      state.globalHeadsUpSuppressedOpenAlertsCount = Number(summaryData?.heads_up_suppressed?.total || 0);
    } else if (!state.globalShowMutedOnly) {
      state.globalOpenAlertsCount = Math.max(Number(state.globalOpenAlertsCount || 0), totalForFilter);
    }

    if (updateList && rowsEl) {
      renderGlobalHeadsUpBaselineSection(
        baselineData?.alerts || [],
        Number(
          baselineData?.total
          || summaryData?.heads_up_suppressed?.total
          || state.globalHeadsUpSuppressedOpenAlertsCount
          || 0,
        ),
      );
    }

    const acknowledgedResp = await acknowledgedPromise;
    if (acknowledgedResp && acknowledgedResp.ok) {
      const acknowledgedData = await acknowledgedResp.json();
      state.globalAcknowledgedOpenAlertsCount = Number(acknowledgedData?.total || 0);
    }

    globalAlertsTabButton.textContent = state.globalOpenAlertsCount > 0
      ? `Globale Alerts (${state.globalOpenAlertsCount})`
      : "Globale Alerts";
    globalAlertsTabButton.classList.toggle("alert-active", state.globalOpenAlertsCount > 0);
    updateHeaderStatChips();
    const mutedScope = state.globalShowMutedOnly ? " · Stummgeschaltete" : "";
    const baselineScope = !state.globalShowMutedOnly && state.globalHeadsUpSuppressedOpenAlertsCount > 0
      ? ` · Dauerzustand: ${state.globalHeadsUpSuppressedOpenAlertsCount}`
      : "";
    const countryScope = state.globalCountryFilter && state.globalCountryFilter !== "all"
      ? ` | Land: ${state.globalCountryFilter}`
      : "";
    if (summaryData) {
      summaryEl.textContent = state.globalShowMutedOnly
        ? `Stummgeschaltet: ${totalForFilter} | Filter: ${state.globalSeverityFilter === "all" ? "alle" : state.globalSeverityFilter}${countryScope}`
        : `Offen: ${summaryData.open.total} (kritisch ${summaryData.open.critical}, warn ${summaryData.open.warning})${baselineScope} | Filter: ${state.globalSeverityFilter === "all" ? "alle" : state.globalSeverityFilter}${countryScope}${mutedScope}`;
    } else if (summaryEl) {
      summaryEl.textContent = state.globalShowMutedOnly
        ? `Stummgeschaltet: ${totalForFilter} | Summary vorübergehend nicht verfügbar`
        : `Offen (Liste): ${totalForFilter} | Summary vorübergehend nicht verfügbar`;
    }

  } catch (error) {
    state.globalAlertsLoadedItems = [];
    globalAlertsTabButton.textContent = "Globale Alerts";
    globalAlertsTabButton.classList.remove("alert-active");
    if (updateList && rowsEl) {
      rowsEl.innerHTML = `<tr><td colspan="8" class="muted">Fehler beim Laden: ${escapeHtml(error.message)}</td></tr>`;
      renderGlobalHeadsUpBaselineSection([], 0);
    }
    if (summaryEl) {
      summaryEl.textContent = `Fehler: ${error.message}`;
    }
  }
}

async function handleAlertRowActionClick(event) {
  const btn = event.target instanceof Element ? event.target.closest("button[data-action]") : null;
  if (!btn) {
    return;
  }
  const action = String(btn.getAttribute("data-action") || "").trim();
  if (!action) {
    return;
  }
  event.preventDefault();
  event.stopPropagation();
  const hostname = btn.getAttribute("data-hostname") || "";
  const hostUid = btn.getAttribute("data-host-uid") || "";
  const mountpoint = btn.getAttribute("data-mountpoint") || "";
  const alertId = Number(btn.getAttribute("data-alert-id") || 0);
  try {
    btn.disabled = true;
    if (action === "toggle-mute") {
      await toggleAlertMute(hostname, hostUid, mountpoint, alertId, btn.getAttribute("data-muted") === "1");
    } else if (action === "toggle-headsup") {
      await toggleAlertHeadsUpSuppression(hostname, hostUid, mountpoint, alertId, btn.getAttribute("data-headsup-suppressed") === "1");
    } else if (action === "ack") {
      const currentNote = decodeURIComponent(btn.getAttribute("data-ack-note") || "");
      const isAlreadyAcknowledged = btn.getAttribute("data-acknowledged") === "1";
      await acknowledgeAlert(hostname, hostUid, mountpoint, alertId, currentNote, isAlreadyAcknowledged);
    } else if (action === "close") {
      await closeAlert(hostname, hostUid, mountpoint, alertId, btn.getAttribute("data-closed") === "1");
    }
  } catch (error) {
    window.alert(formatApiLoadError(error?.message, "Alert-Aktion"));
  } finally {
    btn.disabled = false;
  }
}

function wireAlertRowActions() {
  if (state.alertRowActionsDelegated) {
    return;
  }
  ["globalAlertsRows", "globalHeadsUpBaselineRows", "alertsRows"].forEach((elementId) => {
    const root = document.getElementById(elementId);
    if (!root) {
      return;
    }
    root.addEventListener("click", (event) => {
      void handleAlertRowActionClick(event);
    });
  });
  state.alertRowActionsDelegated = true;
}

function wireEvents() {
  wireAlertRowActions();
  wireHeaderLicenseCopyButton();

  if (!state.sapB1VmapBeforeUnloadWired) {
    window.addEventListener("beforeunload", (event) => {
      if (!hasSapB1VersionMapUnsavedChanges()) {
        return;
      }
      event.preventDefault();
      event.returnValue = "";
    });
    state.sapB1VmapBeforeUnloadWired = true;
  }

  document.addEventListener("click", (event) => {
    const target = event.target instanceof Element ? event.target.closest("#overviewTabButton, #reportsTabButton, #globalViewButton, #globalAlertsTabButton, #criticalTrendsTabButton, #inactiveHostsTabButton, #backupStatusTabButton, #systemOverviewTabButton, #hostConfigChangesTabButton, #agentSourceStatusTabButton, #globalAdminAlertSubsTabButton, #globalAdminLoginAuditTabButton, #globalAdminSettingsTabButton, #adminNavAgentSourceButton, #adminNavAlertSubsButton, #adminNavLoginAuditButton, #adminNavSettingsButton, #headerAlertChip, #headerMutedChip, #headerInactiveChip") : null;
    if (!target) {
      return;
    }
    if (!confirmDiscardSapB1VersionMapChanges()) {
      event.preventDefault();
      event.stopImmediatePropagation();
    }
  }, true);

  document.addEventListener("click", (event) => {
    const element = event.target instanceof Element ? event.target : null;
    if (!element) {
      return;
    }

    if (element.closest("#chartDrillCloseBtn")) {
      event.preventDefault();
      event.stopPropagation();
      closeChartDrillModal();
      return;
    }

    if (element.matches("#chartDrillModal .chart-drill-backdrop")) {
      event.preventDefault();
      event.stopPropagation();
      closeChartDrillModal();
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape") {
      return;
    }
    const modal = document.getElementById("chartDrillModal");
    if (modal && !modal.classList.contains("hidden")) {
      closeChartDrillModal();
    }
  });

  const themeToggleButton = document.getElementById("themeToggleButton");
  if (themeToggleButton) {
    themeToggleButton.addEventListener("click", () => {
      toggleTheme();
    });
  }

  const liveReportFeedToggleButton = document.getElementById("liveReportFeedToggleButton");
  if (liveReportFeedToggleButton) {
    liveReportFeedToggleButton.addEventListener("click", () => {
      toggleLiveReportFeedEnabled();
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
  const expandAllBackupStatusButton = document.getElementById("expandAllBackupStatusButton");
  if (expandAllBackupStatusButton) {
    expandAllBackupStatusButton.addEventListener("click", () => {
      expandAllBackupStatusCustomers();
    });
  }
  const backupStatusFilterSql = document.getElementById("backupStatusFilterSql");
  if (backupStatusFilterSql) {
    backupStatusFilterSql.addEventListener("change", async () => {
      state.backupStatusFilterSql = backupStatusFilterSql.checked;
      await loadBackupStatus();
    });
  }
  const backupStatusFilterHana = document.getElementById("backupStatusFilterHana");
  if (backupStatusFilterHana) {
    backupStatusFilterHana.addEventListener("change", async () => {
      state.backupStatusFilterHana = backupStatusFilterHana.checked;
      await loadBackupStatus();
    });
  }
  const globalAdminAlertSubsTabButton = document.getElementById("globalAdminAlertSubsTabButton");
  if (globalAdminAlertSubsTabButton) {
    globalAdminAlertSubsTabButton.addEventListener("click", async () => {
      setAdminSubMode("admin-alert-subs");
      updateGlobalSubMode();
      await loadAdminAlertSubscriptions();
    });
  }
  const globalAdminLoginAuditTabButton = document.getElementById("globalAdminLoginAuditTabButton");
  if (globalAdminLoginAuditTabButton) {
    globalAdminLoginAuditTabButton.addEventListener("click", async () => {
      if (!state.isAdmin) {
        return;
      }
      setAdminSubMode("admin-login-audit");
      updateGlobalSubMode();
      await loadAdminLoginAudit();
    });
  }
  const globalAdminSettingsTabButton = document.getElementById("globalAdminSettingsTabButton");
  if (globalAdminSettingsTabButton) {
    globalAdminSettingsTabButton.addEventListener("click", async () => {
      if (!state.isAdmin) {
        return;
      }
      setAdminSubMode("admin-settings");
      updateGlobalSubMode();
      await loadGlobalAdminSettingsPanel();
    });
  }
  const adminNavAgentSourceButton = document.getElementById("adminNavAgentSourceButton");
  if (adminNavAgentSourceButton) {
    adminNavAgentSourceButton.addEventListener("click", async () => {
      if (!state.isAdmin) {
        return;
      }
      setAdminSubMode("agent-source-status");
      updateGlobalSubMode();
      await loadAgentSourceStatus();
    });
  }
  const adminNavAlertSubsButton = document.getElementById("adminNavAlertSubsButton");
  if (adminNavAlertSubsButton) {
    adminNavAlertSubsButton.addEventListener("click", async () => {
      if (!state.isAdmin) {
        return;
      }
      setAdminSubMode("admin-alert-subs");
      updateGlobalSubMode();
      await loadAdminAlertSubscriptions();
    });
  }
  const adminNavLoginAuditButton = document.getElementById("adminNavLoginAuditButton");
  if (adminNavLoginAuditButton) {
    adminNavLoginAuditButton.addEventListener("click", async () => {
      if (!state.isAdmin) {
        return;
      }
      setAdminSubMode("admin-login-audit");
      updateGlobalSubMode();
      await loadAdminLoginAudit();
    });
  }
  const adminNavSettingsButton = document.getElementById("adminNavSettingsButton");
  if (adminNavSettingsButton) {
    adminNavSettingsButton.addEventListener("click", async () => {
      if (!state.isAdmin) {
        return;
      }
      setAdminSubMode("admin-settings");
      updateGlobalSubMode();
      await loadGlobalAdminSettingsPanel();
    });
  }

  const systemOverviewTabButton = document.getElementById("systemOverviewTabButton");
  if (systemOverviewTabButton) {
    systemOverviewTabButton.addEventListener("click", async () => {
      state.globalSubMode = "system-overview";
      updateGlobalSubMode();
      await loadSystemOverview();
    });
  }
  const refreshSystemOverviewButton = document.getElementById("refreshSystemOverviewButton");
  if (refreshSystemOverviewButton) {
    refreshSystemOverviewButton.addEventListener("click", async () => {
      await loadSystemOverview();
    });
  }
  const expandAllSystemOverviewButton = document.getElementById("expandAllSystemOverviewButton");
  if (expandAllSystemOverviewButton) {
    expandAllSystemOverviewButton.addEventListener("click", () => {
      expandAllSystemOverviewGroups();
    });
  }
  const toggleSystemOverviewAddonsButton = document.getElementById("toggleSystemOverviewAddonsButton");
  if (toggleSystemOverviewAddonsButton) {
    toggleSystemOverviewAddonsButton.addEventListener("click", async () => {
      state.systemOverviewAddonsExpanded = !state.systemOverviewAddonsExpanded;
      updateSystemOverviewAddonsToggleButton();
      await loadSystemOverview();
    });
  }
  const toggleSystemOverviewSortModeButton = document.getElementById("toggleSystemOverviewSortModeButton");
  if (toggleSystemOverviewSortModeButton) {
    toggleSystemOverviewSortModeButton.addEventListener("click", async () => {
      state.systemOverviewSortMode = state.systemOverviewSortMode === "addon-customer-os"
        ? "country-os-host"
        : "addon-customer-os";
      updateSystemOverviewSortModeButton();
      await loadSystemOverview();
    });
  }
  const systemOverviewSearchInput = document.getElementById("systemOverviewSearchInput");
  if (systemOverviewSearchInput) {
    systemOverviewSearchInput.addEventListener("input", () => {
      state.systemOverviewSearchQuery = String(systemOverviewSearchInput.value || "");
      if (systemOverviewSearchDebounceTimerId !== null) {
        window.clearTimeout(systemOverviewSearchDebounceTimerId);
      }
      systemOverviewSearchDebounceTimerId = window.setTimeout(() => {
        systemOverviewSearchDebounceTimerId = null;
        void loadSystemOverview();
      }, 280);
    });
  }
  const hostConfigChangesTabButton = document.getElementById("hostConfigChangesTabButton");
  if (hostConfigChangesTabButton) {
    hostConfigChangesTabButton.addEventListener("click", async () => {
      state.globalSubMode = "host-config-changes";
      updateGlobalSubMode();
      showHostConfigChangesIdleState("Bitte Filter setzen und dann Suchen/Refresh klicken.");
      refreshHostConfigChangesCountryFilter();
      await loadChangelogRebuildJobsStatus();
    });
  }
  const applyHostConfigChangesFiltersButton = document.getElementById("applyHostConfigChangesFiltersButton");
  if (applyHostConfigChangesFiltersButton) {
    applyHostConfigChangesFiltersButton.addEventListener("click", async () => {
      await loadHostConfigChanges();
    });
  }
  const refreshHostConfigChangesButton = document.getElementById("refreshHostConfigChangesButton");
  if (refreshHostConfigChangesButton) {
    refreshHostConfigChangesButton.addEventListener("click", async () => {
      await loadHostConfigChanges();
    });
  }
  const backfillHostConfigChangesButton = document.getElementById("backfillHostConfigChangesButton");
  if (backfillHostConfigChangesButton) {
    backfillHostConfigChangesButton.addEventListener("click", async () => {
      const hoursFilterEl = document.getElementById("hostConfigChangesHoursFilter");
      const days = 30;
      state.hostConfigChangesHours = 720;
      if (hoursFilterEl) {
        hoursFilterEl.value = "720";
      }
      await runCombinedBackfill(days);
    });
  }
  const runChangelogRebuildNowButton = document.getElementById("runChangelogRebuildNowButton");
  if (runChangelogRebuildNowButton) {
    runChangelogRebuildNowButton.addEventListener("click", async () => {
      await runChangelogRebuildNow(CHANGELOG_REBUILD_DAYS);
    });
  }
  const runInventoryChangelogRebuildButton = document.getElementById("runInventoryChangelogRebuildButton");
  if (runInventoryChangelogRebuildButton) {
    runInventoryChangelogRebuildButton.addEventListener("click", async () => {
      await runInventoryChangelogRebuildNow();
    });
  }
  const refreshChangelogRebuildJobsButton = document.getElementById("refreshChangelogRebuildJobsButton");
  if (refreshChangelogRebuildJobsButton) {
    refreshChangelogRebuildJobsButton.addEventListener("click", async () => {
      await loadChangelogRebuildJobsStatus();
    });
  }
  const cancelChangelogRebuildJobButton = document.getElementById("cancelChangelogRebuildJobButton");
  if (cancelChangelogRebuildJobButton) {
    cancelChangelogRebuildJobButton.addEventListener("click", async () => {
      await cancelActiveChangelogRebuildJob();
    });
  }
  initChangelogMaintenancePanel();
  const hostConfigChangesHoursFilter = document.getElementById("hostConfigChangesHoursFilter");
  if (hostConfigChangesHoursFilter) {
    hostConfigChangesHoursFilter.addEventListener("change", () => {
      state.hostConfigChangesHours = Number(hostConfigChangesHoursFilter.value);
      showHostConfigChangesIdleState();
    });
  }
  const hostConfigChangesSearchInput = document.getElementById("hostConfigChangesSearchInput");
  if (hostConfigChangesSearchInput) {
    hostConfigChangesSearchInput.addEventListener("input", () => {
      state.hostConfigChangesSearchQuery = hostConfigChangesSearchInput.value.trim();
      showHostConfigChangesIdleState();
    });
    hostConfigChangesSearchInput.addEventListener("keydown", async (event) => {
      if (event.key !== "Enter") {
        return;
      }
      event.preventDefault();
      state.hostConfigChangesSearchQuery = hostConfigChangesSearchInput.value.trim();
      await loadHostConfigChanges();
    });
  }
  const agentSourceStatusTabButton = document.getElementById("agentSourceStatusTabButton");
  if (agentSourceStatusTabButton) {
    agentSourceStatusTabButton.addEventListener("click", async () => {
      setAdminSubMode("agent-source-status");
      updateGlobalSubMode();
      await loadAgentSourceStatus();
    });
  }
  const refreshAgentSourceStatusButton = document.getElementById("refreshAgentSourceStatusButton");
  if (refreshAgentSourceStatusButton) {
    refreshAgentSourceStatusButton.addEventListener("click", async () => {
      await loadAgentSourceStatus();
    });
  }
  const reloadAdminLoginAuditButton = document.getElementById("reloadAdminLoginAuditButton");
  if (reloadAdminLoginAuditButton) {
    reloadAdminLoginAuditButton.addEventListener("click", async () => {
      await loadAdminLoginAudit();
    });
  }
  document.getElementById("globalViewButton").addEventListener("click", async () => {
    const previousViewMode = state.viewMode;
    state.viewMode = "global";
    // From settings/admin modes, the globe button should always return to the main global landing tab.
    if (previousViewMode !== "global" || state.globalSubMode === "admin-settings" || state.globalSubMode === "admin-login-audit") {
      state.globalSubMode = "global-alerts";
    } else {
      state.globalSubMode = state.globalSubMode || "global-alerts";
    }
    if (state.globalSubMode === "admin-alert-subs" && !state.isAdmin) {
      state.globalSubMode = "global-alerts";
    }
    if (state.globalSubMode === "admin-login-audit" && !state.isAdmin) {
      state.globalSubMode = "global-alerts";
    }
    updateViewMode();
    updateGlobalSubMode();
    await loadActiveGlobalSubMode();
  });

  document.getElementById("headerAlertChip").addEventListener("click", async () => {
    state.viewMode = "global";
    state.globalSubMode = "global-alerts";
    updateViewMode();
    updateGlobalSubMode();
    await loadGlobalAlertsOverview();
  });

  const headerMutedChip = document.getElementById("headerMutedChip");
  if (headerMutedChip) {
    headerMutedChip.addEventListener("click", async () => {
      state.viewMode = "global";
      state.globalSubMode = "global-alerts";
      state.globalShowMutedOnly = true;
      const mutedCheckbox = document.getElementById("globalShowMutedOnlyCheckbox");
      if (mutedCheckbox) mutedCheckbox.checked = true;
      updateViewMode();
      updateGlobalSubMode();
      await loadGlobalAlertsOverview();
    });
  }

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

  async function handleTriggerAllAgentsUpdateClick() {
    try {
      const result = await triggerAgentUpdateForAllHosts();
      const totalHosts = Number(result.total_hosts || 0);
      const queuedCount = Number(result.queued_count || 0);
      const alreadyQueuedCount = Number(result.already_queued_count || 0);
      window.alert(`Update-Trigger gesetzt: ${queuedCount} Hosts neu gequeued, ${alreadyQueuedCount} bereits pending, gesamt ${totalHosts}.`);
      await loadAgentUpdateStatus();
    } catch (error) {
      window.alert(`Globaler Update-Trigger fehlgeschlagen: ${error.message}`);
    }
  }

  const triggerAllAgentsUpdateButton = document.getElementById("triggerAllAgentsUpdateButton");
  if (triggerAllAgentsUpdateButton) {
    triggerAllAgentsUpdateButton.addEventListener("click", handleTriggerAllAgentsUpdateClick);
  }

  const triggerAllAgentsUpdateFromAgentCardButton = document.getElementById("triggerAllAgentsUpdateFromAgentCardButton");
  if (triggerAllAgentsUpdateFromAgentCardButton) {
    triggerAllAgentsUpdateFromAgentCardButton.addEventListener("click", handleTriggerAllAgentsUpdateClick);
  }

  const agentSilentThresholdSelect = document.getElementById("agentSilentThresholdSelect");
  if (agentSilentThresholdSelect) {
    agentSilentThresholdSelect.value = String(state.agentSilentThresholdHours || 6);
    agentSilentThresholdSelect.addEventListener("change", () => {
      const nextHours = Number(agentSilentThresholdSelect.value) || 6;
      state.agentSilentThresholdHours = nextHours;
      persistAdminUiState();
      renderAgentSilentHostsSection(
        state.agentUpdateStatusHosts,
        nextHours,
        asText(state.latestAgentRelease, "-"),
      );
    });
  }

  const refreshAgentUpdateStatusButton = document.getElementById("refreshAgentUpdateStatusButton");
  if (refreshAgentUpdateStatusButton) {
    refreshAgentUpdateStatusButton.addEventListener("click", async () => {
      await loadAgentUpdateStatus();
    });
  }

  document.getElementById("rolloutApiKeyButton").addEventListener("click", async () => {
    const apiKey = window.prompt("API-Key für alle bekannten Hosts verteilen:", "");
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
      const progressEl   = document.getElementById("dbOpsProgress");
      const barEl        = document.getElementById("dbOpsProgressBar");
      const labelEl      = document.getElementById("dbOpsProgressLabel");

      function showProgress({ pct, label }) {
        progressEl.classList.remove("hidden");
        labelEl.className = "db-ops-progress-label";
        labelEl.textContent = label || "";
        if (pct === null) {
          barEl.style.width = "40%";
          barEl.classList.add("db-ops-progress-bar--indeterminate");
        } else {
          barEl.classList.remove("db-ops-progress-bar--indeterminate");
          barEl.style.width = pct + "%";
        }
      }

      backupButton.disabled = true;
      try {
        await downloadDatabaseBackup(showProgress);
        barEl.classList.remove("db-ops-progress-bar--indeterminate");
        barEl.style.width = "100%";
        labelEl.className = "db-ops-progress-label success";
        labelEl.textContent = "Backup heruntergeladen.";
        setTimeout(() => progressEl.classList.add("hidden"), 4000);
      } catch (error) {
        barEl.classList.remove("db-ops-progress-bar--indeterminate");
        labelEl.className = "db-ops-progress-label error";
        labelEl.textContent = formatApiLoadError(error.message, "Datenbank-Backup");
      } finally {
        backupButton.disabled = false;
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
        `Datenbank wirklich aus "${file.name}" (${(file.size / 1024).toFixed(0)} KB) wiederherstellen?\n\nDie aktuelle Datenbank wird dabei ÜBERSCHRIEBEN. Vorher ein Backup anlegen!`
      );
      if (!confirmed) return;

      const progressEl = document.getElementById("dbOpsProgress");
      const barEl      = document.getElementById("dbOpsProgressBar");
      const labelEl    = document.getElementById("dbOpsProgressLabel");

      function showProgress({ pct, label }) {
        progressEl.classList.remove("hidden");
        labelEl.textContent = label || "";
        if (pct === null) {
          barEl.style.width = "40%";
          barEl.classList.add("db-ops-progress-bar--indeterminate");
        } else {
          barEl.classList.remove("db-ops-progress-bar--indeterminate");
          barEl.style.width = pct + "%";
        }
      }

      restoreButton.disabled = true;
      restoreButton.textContent = "Wiederherstellen...";
      try {
        await restoreDatabaseFromFile(file, showProgress);
        labelEl.className = "db-ops-progress-label success";
        window.alert(`Datenbank erfolgreich wiederhergestellt aus: ${file.name}\n\nBitte den Server neu starten, damit alle Änderungen wirksam werden.`);
        setTimeout(() => progressEl.classList.add("hidden"), 5000);
      } catch (error) {
        barEl.classList.remove("db-ops-progress-bar--indeterminate");
        labelEl.className = "db-ops-progress-label error";
        labelEl.textContent = formatApiLoadError(error.message, "Datenbank-Backup");
      } finally {
        restoreButton.disabled = false;
        restoreButton.innerHTML = "&#x267B;&#xFE0F; DB wiederherstellen";
        restoreFileInput.value = "";
      }
    });
  }

  const fixAlertStatusButton = document.getElementById("fixAlertStatusButton");
  if (fixAlertStatusButton) {
    fixAlertStatusButton.addEventListener("click", async () => {
      const confirmed = window.confirm(
        "Alle Alerts mit closed_at_utc aber status='open' auf status='resolved' setzen?\n\nDies behebt verwaiste geschlossene Alerts."
      );
      if (!confirmed) return;

      fixAlertStatusButton.disabled = true;
      fixAlertStatusButton.textContent = "Werden korrigiert...";
      try {
        const resp = await fetch("/api/v1/admin/fix-alert-status", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "same-origin",
          body: JSON.stringify({}),
        });
        if (!resp.ok) {
          const errorData = await resp.json();
          throw new Error(errorData.error || `HTTP ${resp.status}`);
        }
        const result = await resp.json();
        window.alert(`✓ Erfolgreich!\n\n${result.message}`);
      } catch (error) {
        window.alert(`✗ Fehler bei der Korrektur:\n\n${error.message}`);
      } finally {
        fixAlertStatusButton.disabled = false;
        fixAlertStatusButton.textContent = "🔧 Alert-Status korrigieren";
      }
    });
  }

  const vacuumDatabaseButton = document.getElementById("vacuumDatabaseButton");
  const triggerDatabaseStatsButton = document.getElementById("triggerDatabaseStatsButton");
  const analyzeReportDuplicatesButton = document.getElementById("analyzeReportDuplicatesButton");
  const dedupeReportDuplicatesButton = document.getElementById("dedupeReportDuplicatesButton");
  const saveBackupAutomationSettingsButton = document.getElementById("saveBackupAutomationSettingsButton");
  const triggerAutoBackupNowButton = document.getElementById("triggerAutoBackupNowButton");
  const testBackupAutomationSftpButton = document.getElementById("testBackupAutomationSftpButton");
  const backupAutomationSftpAuthMode = document.getElementById("backupAutomationSftpAuthMode");
  const refreshAgentIngestQueueButton = document.getElementById("refreshAgentIngestQueueButton");

  function setDbMaintenanceActionButtonsDisabled(disabled) {
    if (triggerDatabaseStatsButton) triggerDatabaseStatsButton.disabled = disabled;
    if (vacuumDatabaseButton) vacuumDatabaseButton.disabled = disabled;
    if (analyzeReportDuplicatesButton) analyzeReportDuplicatesButton.disabled = disabled;
    if (dedupeReportDuplicatesButton) dedupeReportDuplicatesButton.disabled = disabled;
  }

  if (analyzeReportDuplicatesButton) {
    analyzeReportDuplicatesButton.addEventListener("click", async () => {
      setDbMaintenanceActionButtonsDisabled(true);
      setDbMaintenanceStatus("Analysiere Report-Duplikate...");
      try {
        const analysis = await analyzeAdminReportDuplicates();
        renderReportDedupeEffect(analysis);
        setDbMaintenanceStatus(
          `Duplikat-Analyse: ${Number(analysis.redundant_rows || 0).toLocaleString("de-CH")} redundante Reports`
        );
      } catch (error) {
        setDbMaintenanceStatus(`Fehler: ${error.message}`, true);
      } finally {
        setDbMaintenanceActionButtonsDisabled(false);
      }
    });
  }

  if (dedupeReportDuplicatesButton) {
    dedupeReportDuplicatesButton.addEventListener("click", async () => {
      const confirmed = window.confirm(
        "Ingest-Duplikate jetzt entfernen?\n\nPro Host/Zeit/Payload bleibt nur der älteste Report. Danach VACUUM empfohlen."
      );
      if (!confirmed) return;

      setDbMaintenanceActionButtonsDisabled(true);
      setDbMaintenanceStatus("Duplikat-Bereinigung läuft...");
      try {
        const result = await runAdminReportDedupe(false);
        renderReportDedupeEffect(result);
        await loadAdminDatabaseStats();
        await loadHeaderDatabaseKpis();
        setDbMaintenanceStatus("Duplikat-Bereinigung abgeschlossen. VACUUM empfohlen.");
      } catch (error) {
        setDbMaintenanceStatus(`Fehler: ${error.message}`, true);
      } finally {
        setDbMaintenanceActionButtonsDisabled(false);
      }
    });
  }

  if (triggerDatabaseStatsButton) {
    triggerDatabaseStatsButton.addEventListener("click", async () => {
      setDbMaintenanceActionButtonsDisabled(true);
      setDbMaintenanceStatus("DB Kennzahlen werden neu berechnet (Vollscan, kann 1–2 Min. dauern)...");
      try {
        const data = await triggerAdminDatabaseStatsNow();
        applyAdminDatabaseStatsPayload(data, { manualRun: true });
        await loadHeaderDatabaseKpis().catch((error) => {
          console.warn("loadHeaderDatabaseKpis after stats trigger failed:", error);
        });
      } catch (error) {
        setDbMaintenanceStatus(`Fehler: ${error.message}`, true);
      } finally {
        setDbMaintenanceActionButtonsDisabled(false);
      }
    });
  }

  if (vacuumDatabaseButton) {
    vacuumDatabaseButton.addEventListener("click", async () => {
      const confirmed = window.confirm(
        "SQLite VACUUM jetzt starten?\n\nWährenddessen kann die Oberfläche kurz langsamer reagieren."
      );
      if (!confirmed) return;

      const progressEl = document.getElementById("dbOpsProgress");
      const barEl = document.getElementById("dbOpsProgressBar");
      const labelEl = document.getElementById("dbOpsProgressLabel");

      setDbMaintenanceActionButtonsDisabled(true);
      progressEl.classList.remove("hidden");
      barEl.style.width = "40%";
      barEl.classList.add("db-ops-progress-bar--indeterminate");
      labelEl.className = "db-ops-progress-label";
      labelEl.textContent = "VACUUM läuft...";
      setDbMaintenanceStatus("VACUUM läuft...");

      try {
        const result = await runAdminDatabaseVacuum();
        await loadAdminDatabaseStats();
        renderDbMaintenanceEffect(result);
        setDbMaintenanceStatus("VACUUM abgeschlossen.");
        barEl.classList.remove("db-ops-progress-bar--indeterminate");
        barEl.style.width = "100%";
        labelEl.className = "db-ops-progress-label success";
        labelEl.textContent = "VACUUM erfolgreich abgeschlossen.";
        setTimeout(() => progressEl.classList.add("hidden"), 3500);
      } catch (error) {
        barEl.classList.remove("db-ops-progress-bar--indeterminate");
        labelEl.className = "db-ops-progress-label error";
        labelEl.textContent = `Fehler: ${error.message}`;
        setDbMaintenanceStatus(`Fehler: ${error.message}`, true);
      } finally {
        setDbMaintenanceActionButtonsDisabled(false);
      }
    });
  }

  if (backupAutomationSftpAuthMode) {
    backupAutomationSftpAuthMode.addEventListener("change", () => {
      updateBackupAutomationAuthModeUi();
    });
  }

  if (saveBackupAutomationSettingsButton) {
    saveBackupAutomationSettingsButton.addEventListener("click", async () => {
      saveBackupAutomationSettingsButton.disabled = true;
      if (triggerAutoBackupNowButton) triggerAutoBackupNowButton.disabled = true;
      setBackupAutomationStatus("Speichere Backup-Automation...");
      try {
        const result = await saveAdminBackupAutomationSettings();
        if (result && typeof result.settings === "object") {
          applyBackupAutomationSettingsToInputs(result.settings);
        }
        await loadAdminBackupAutomation();
      } catch (error) {
        setBackupAutomationStatus(`Fehler: ${error.message}`, true);
      } finally {
        saveBackupAutomationSettingsButton.disabled = false;
        if (triggerAutoBackupNowButton) triggerAutoBackupNowButton.disabled = false;
      }
    });
  }

  if (triggerAutoBackupNowButton) {
    triggerAutoBackupNowButton.addEventListener("click", async () => {
      triggerAutoBackupNowButton.disabled = true;
      if (saveBackupAutomationSettingsButton) saveBackupAutomationSettingsButton.disabled = true;
      setBackupAutomationStatus("Starte lokales Backup...");
      try {
        await triggerAdminAutoBackupNow();
        await loadAdminBackupAutomation();
      } catch (error) {
        setBackupAutomationStatus(`Fehler: ${error.message}`, true);
      } finally {
        triggerAutoBackupNowButton.disabled = false;
        if (saveBackupAutomationSettingsButton) saveBackupAutomationSettingsButton.disabled = false;
      }
    });
  }

  if (testBackupAutomationSftpButton) {
    testBackupAutomationSftpButton.addEventListener("click", async () => {
      testBackupAutomationSftpButton.disabled = true;
      if (saveBackupAutomationSettingsButton) saveBackupAutomationSettingsButton.disabled = true;
      if (triggerAutoBackupNowButton) triggerAutoBackupNowButton.disabled = true;
      setBackupAutomationStatus("Teste sFTP Verbindung und Upload...");
      try {
        const result = await testAdminBackupAutomationSftp();
        setBackupAutomationStatus(String(result?.message || "sFTP Test erfolgreich."));
      } catch (error) {
        setBackupAutomationStatus(`Fehler: ${error.message}`, true);
      } finally {
        testBackupAutomationSftpButton.disabled = false;
        if (saveBackupAutomationSettingsButton) saveBackupAutomationSettingsButton.disabled = false;
        if (triggerAutoBackupNowButton) triggerAutoBackupNowButton.disabled = false;
      }
    });
  }

  if (refreshAgentIngestQueueButton) {
    refreshAgentIngestQueueButton.addEventListener("click", async () => {
      refreshAgentIngestQueueButton.disabled = true;
      setAgentIngestQueueStatus("Queue-Status wird aktualisiert...");
      setAgentIngestAuditStatus("Ingest-Lieferlog wird aktualisiert...");
      try {
        await loadAdminAgentIngestQueue();
        await loadAdminAgentIngestAuditLog();
      } catch (error) {
        setAgentIngestQueueStatus(`Fehler: ${error.message}`, true);
        setAgentIngestAuditStatus(`Fehler: ${error.message}`, true);
      } finally {
        refreshAgentIngestQueueButton.disabled = false;
      }
    });
  }

  if (state.isAdmin) {
    void loadAdminDatabaseStats().catch((error) => {
      setDbMaintenanceStatus(`Fehler: ${error.message}`, true);
    });
    void loadAdminBackupAutomation().catch((error) => {
      setBackupAutomationStatus(`Fehler: ${error.message}`, true);
    });
    void loadAdminAgentIngestQueue().catch((error) => {
      setAgentIngestQueueStatus(`Fehler: ${error.message}`, true);
    });
    void loadAdminAgentIngestAuditLog().catch((error) => {
      setAgentIngestAuditStatus(`Fehler: ${error.message}`, true);
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
    void refreshDashboard({ preserveScroll: false });
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
    void refreshDashboard({ preserveScroll: false });
    startAutoRefreshTimer();
  });

  document.getElementById("logoutButton").addEventListener("click", async () => {
    await logoutWebClient();
  });

  document.getElementById("savePasswordButton").addEventListener("click", async () => {
    await changePassword();
  });

  document.getElementById("globalSeverityFilter").addEventListener("change", async (event) => {
    state.globalSeverityFilter = String(event.target?.value || "all");
    state.globalAlertsOffset = 0;
    await loadGlobalAlertsOverview({ append: false });
  });

  const globalCountryFilter = document.getElementById("globalCountryFilter");
  if (globalCountryFilter) {
    globalCountryFilter.value = state.globalCountryFilter || "all";
    globalCountryFilter.addEventListener("change", async (event) => {
      state.globalCountryFilter = String(event.target?.value || "all");
      state.globalAlertsOffset = 0;
      await loadGlobalAlertsOverview({ append: false });
    });
  }

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

  const globalShowMutedOnlyCheckbox = document.getElementById("globalShowMutedOnlyCheckbox");
  if (globalShowMutedOnlyCheckbox) {
    globalShowMutedOnlyCheckbox.checked = state.globalShowMutedOnly;
    globalShowMutedOnlyCheckbox.addEventListener("change", async (event) => {
      state.globalShowMutedOnly = event.target.checked;
      state.globalAlertsOffset = 0;
      await loadGlobalAlertsOverview({ append: false });
    });
  }

  const toggleGlobalHeadsUpBaselineButton = document.getElementById("toggleGlobalHeadsUpBaselineButton");
  if (toggleGlobalHeadsUpBaselineButton) {
    toggleGlobalHeadsUpBaselineButton.addEventListener("click", () => {
      state.globalHeadsUpBaselineCollapsed = !state.globalHeadsUpBaselineCollapsed;
      const bodyEl = document.getElementById("globalHeadsUpBaselineBody");
      if (bodyEl) {
        bodyEl.classList.toggle("hidden", state.globalHeadsUpBaselineCollapsed);
      }
      toggleGlobalHeadsUpBaselineButton.textContent = globalHeadsUpBaselineToggleLabel(state.globalHeadsUpBaselineCollapsed);
      toggleGlobalHeadsUpBaselineButton.setAttribute(
        "aria-expanded",
        state.globalHeadsUpBaselineCollapsed ? "false" : "true",
      );
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

  document.getElementById("overviewLangzeitTabButton").addEventListener("click", () => {
    state.overviewSection = "langzeit";
    updateOverviewSection();
    if (state.selectedHost) {
      void loadAnalysisForHost();
    }
  });

  document.getElementById("overviewFilesystemTabButton").addEventListener("click", () => {
    state.overviewSection = "filesystem";
    updateOverviewSection();
  });

  document.getElementById("overviewNotificationTabButton").addEventListener("click", () => {
    state.overviewSection = "notification";
    updateOverviewSection();
    // Reload panel for current host when switching to this tab
    if (state.selectedHost) {
      loadAndRenderCustomerNotificationPanel(state.selectedHost, state.selectedHostUid || "");
    }
  });

  document.getElementById("overviewDatabaseChangelogTabButton").addEventListener("click", () => {
    state.overviewSection = "database-changelog";
    updateOverviewSection();
    if (state.selectedHost) {
      loadDatabaseLifecycleForHost();
    }
  });

  document.getElementById("overviewConfigChangelogTabButton").addEventListener("click", () => {
    state.overviewSection = "config-changelog";
    updateOverviewSection();
    if (state.selectedHost) {
      loadConfigChangelogForHost();
    }
  });

  document.getElementById("toggleHostAlertsPanelButton").addEventListener("click", async () => {
    state.hostAlertsUserToggled = true;
    applyHostAlertsPanelCollapsed(!state.hostAlertsCollapsed);
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

  const mobilePushToggleButton = document.getElementById("mobilePushToggleButton");
  if (mobilePushToggleButton) {
    mobilePushToggleButton.addEventListener("click", async () => {
      await toggleMobilePush();
    });
  }

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

  const wireMailSettingsSaveButton = (buttonId) => {
    const button = document.getElementById(buttonId);
    if (!button) return;
    button.addEventListener("click", async () => {
      try {
        await saveUserProfile();
      } catch (error) {
        setUserMailSettingsStatus(error.message, true);
      }
    });
  };

  // Primary save action (placed at the end of the digest section).
  wireMailSettingsSaveButton("saveAllMailSettingsButton");
  // Backward compatibility for older cached HTML shells.
  wireMailSettingsSaveButton("saveUserMailSettingsButton");
  wireMailSettingsSaveButton("saveDigestSettingsButton");

  const hostInterestModeSelect = document.getElementById("hostInterestModeSelect");
  if (hostInterestModeSelect) {
    hostInterestModeSelect.addEventListener("change", async (event) => {
      state.hostInterestMode = normalizeHostInterestMode(event.target?.value || "all");
      syncHostInterestModeControls();
      renderHostInterestsEditor();
      await applyHostFiltersLocally({ preserveScroll: true });
    });
  }
  const hostSidebarInterestModeSelect = document.getElementById("hostSidebarInterestModeSelect");
  if (hostSidebarInterestModeSelect) {
    hostSidebarInterestModeSelect.addEventListener("change", async (event) => {
      state.hostInterestMode = normalizeHostInterestMode(event.target?.value || "all");
      syncHostInterestModeControls();
      renderHostInterestsEditor();
      try {
        await saveHostInterestsPreferences();
      } catch (error) {
        setHostInterestsStatus(`Modus konnte nicht gespeichert werden: ${error.message}`, true);
      }
      await applyHostFiltersLocally({ preserveScroll: true });
    });
  }
  const hostInterestSearchInput = document.getElementById("hostInterestSearchInput");
  if (hostInterestSearchInput) {
    hostInterestSearchInput.addEventListener("input", () => {
      state.hostInterestSearchQuery = String(hostInterestSearchInput.value || "");
      renderHostInterestsEditor();
    });
  }
  const hostInterestShowUnselectedOnlyInput = document.getElementById("hostInterestShowUnselectedOnlyInput");
  if (hostInterestShowUnselectedOnlyInput) {
    hostInterestShowUnselectedOnlyInput.checked = state.hostInterestShowUnselectedOnly === true;
    hostInterestShowUnselectedOnlyInput.addEventListener("change", () => {
      state.hostInterestShowUnselectedOnly = hostInterestShowUnselectedOnlyInput.checked === true;
      renderHostInterestsEditor();
    });
  }
  const hostInterestsSelectAllButton = document.getElementById("hostInterestsSelectAllButton");
  if (hostInterestsSelectAllButton) {
    hostInterestsSelectAllButton.addEventListener("click", () => {
      const selectorHosts = Array.isArray(state.hostInterestTargetHosts) && state.hostInterestTargetHosts.length > 0
        ? state.hostInterestTargetHosts
        : (state.hosts || []);
      state.hostInterestCountryCodes = new Set(selectorHosts.map((host) => getHostInterestCountryCode(host)).filter((item) => /^[A-Z]{2}$/.test(item)));
      const noCountryHosts = selectorHosts.filter((host) => !getHostInterestCountryCode(host)).map((host) => String(host.hostname || "").trim()).filter((item) => item.length > 0);
      state.hostInterestHostAdditions = new Set([...(state.hostInterestHostAdditions || []), ...noCountryHosts]);
      syncEffectiveHostInterestSelection();
      renderHostInterestsEditor();
    });
  }
  const hostInterestsClearButton = document.getElementById("hostInterestsClearButton");
  if (hostInterestsClearButton) {
    hostInterestsClearButton.addEventListener("click", () => {
      const selectorHosts = Array.isArray(state.hostInterestTargetHosts) && state.hostInterestTargetHosts.length > 0
        ? state.hostInterestTargetHosts
        : (state.hosts || []);
      state.hostInterestCountryCodes = new Set();
      const noCountryHosts = selectorHosts.filter((host) => !getHostInterestCountryCode(host)).map((host) => String(host.hostname || "").trim()).filter((item) => item.length > 0);
      state.hostInterestHostAdditions = new Set(Array.from(state.hostInterestHostAdditions || []).filter((hostname) => !noCountryHosts.includes(hostname)));
      syncEffectiveHostInterestSelection();
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

  const reportJumpDateTimeInput = document.getElementById("reportJumpDateTimeInput");
  const reportJumpLatestButton = document.getElementById("reportJumpLatestButton");
  if (reportJumpDateTimeInput) {
    reportJumpDateTimeInput.addEventListener("change", async () => {
      await jumpToReportDateTime();
    });
    reportJumpDateTimeInput.addEventListener("input", async () => {
      const value = String(reportJumpDateTimeInput.value || "").trim();
      if (value.length < 16) {
        return;
      }
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

  document.getElementById("hostSearchInput").addEventListener("input", (event) => {
    state.hostSearchQuery = event.target.value;
    state.hostOffset = 0;
    persistHostFilterPreferences();

    if (hostSearchFilterDebounceTimerId !== null) {
      window.clearTimeout(hostSearchFilterDebounceTimerId);
    }
    hostSearchFilterDebounceTimerId = window.setTimeout(() => {
      hostSearchFilterDebounceTimerId = null;
      void applyHostFiltersLocally({ preserveScroll: true });
    }, 120);
  });

  const hostSortSelect = document.getElementById("hostSortSelect");
  if (hostSortSelect && !hostSortSelectWired) {
    hostSortSelectWired = true;
    syncHostSortControl();
    hostSortSelect.addEventListener("change", async (event) => {
      const nextSort = normalizeHostSortMode(event.target?.value || "customer_alpha");
      if (state.hostSortMode === nextSort) {
        return;
      }
      state.hostSortMode = nextSort;
      persistHostFilterPreferences();
      await applyHostFiltersLocally({ preserveScroll: true });
    });
  }

  document.addEventListener("visibilitychange", () => {
    if (document.hidden || !state.isAuthenticated) {
      return;
    }
    if (sessionRefreshTimerId === null) {
      startSessionRefreshTimer();
    }
    void refreshSession();
  });

  window.addEventListener("focus", () => {
    if (!state.isAuthenticated) {
      return;
    }
    if (sessionRefreshTimerId === null) {
      startSessionRefreshTimer();
    }
    void refreshSession();
  });

}

async function init() {
  window.__monitoringAppBooted = true;
  setAuthUiState(false);
  setLoginStatus("Sitzung wird geprüft…");
  wireEvents();

  const isAuthenticated = await ensureAuthenticatedSession();
  if (!isAuthenticated) {
    setAuthUiState(false);
    setLoginStatus("Bitte anmelden, um den Webclient zu nutzen.");
    void loadWebclientVersion().catch((error) => {
      console.warn("initial loadWebclientVersion failed:", error);
    });
    return;
  }

  state.analysisHours = loadAnalysisRangePreference();
  applyTheme(loadThemePreference());
  autoRefreshCurrentIntervalSec = loadAutoRefreshPreference();
  const arSelect = document.getElementById("autoRefreshIntervalSelect");
  if (arSelect) arSelect.value = String(autoRefreshCurrentIntervalSec);
  updateAutoRefreshStatus(null);
  const oauthResult = consumeOauthStatusFromUrl();
  const startRoute = consumeStartRouteFromUrl();

  const webclientVersionPromise = loadWebclientVersion().catch((error) => {
    console.warn("initial loadWebclientVersion failed:", error);
  });
  const sapB1VersionMapPromise = loadSapB1VersionMap();
  const sapLicenseTypeMapPromise = loadSapLicenseTypeMap();

  initLiveReportFeed();
  initHeaderSectionCollapsibles();
  applyInitialHeaderKpiWidth();
  window.addEventListener("resize", scheduleHeaderKpiUniformCardWidthSync);
  if (document.fonts && document.fonts.ready) {
    document.fonts.ready.then(() => {
      scheduleHeaderKpiUniformCardWidthSync();
    }).catch(() => {
      // Ignore font readiness failures; regular sync paths still run.
    });
  }
  mountAdminSettingsIntoGlobalView();
  restoreAdminUiStateFromStorage();
  updateViewMode();
  updateOverviewSection();
  updateAnalysisRangeUi();
  updateSystemOverviewAddonsToggleButton();
  document.getElementById("criticalTrendsRangeSelect").value = String(state.criticalTrendsHours);
  document.getElementById("criticalTrendsProjectSelect").value = String(state.criticalTrendsProjectHours);
  document.getElementById("inactiveHostsRangeSelect").value = String(state.inactiveHostsHours);
  document.getElementById("globalSeverityFilter").value = state.globalSeverityFilter;
  const globalShowMutedOnlyCheckbox = document.getElementById("globalShowMutedOnlyCheckbox");
  if (globalShowMutedOnlyCheckbox) {
    globalShowMutedOnlyCheckbox.checked = state.globalShowMutedOnly;
  }
  document.getElementById("hostSearchInput").value = state.hostSearchQuery;
  document.getElementById("loginUsernameInput").value = "";
  document.getElementById("loginPasswordInput").value = "";
  sessionEstablishedAtMs = Date.now();
  // SAP maps already started above; hosts render immediately, badges fill in once ready.
  sapB1VersionMapPromise.then(() => {
    if (state.hosts && state.hosts.length > 0) {
      renderHosts(state.hosts);
    }
  });
  sapLicenseTypeMapPromise.then(() => {
    if (state.currentReport) {
      renderCurrentReportInView();
    }
  });
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
  } else if (startRoute) {
    await applyStartRoute(startRoute);
  }
  await refreshDashboard({ preserveScroll: false });
  await loadAgentUpdateStatus();
  startAutoRefreshTimer();
  startSessionRefreshTimer();
}

init();

function formatSystemOverviewLastUpdate(value) {
  const raw = asText(value, "-");
  if (raw === "-") return raw;
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

function getCountryFlagIconPath(countryCode) {
  const code = String(countryCode || "XX").toUpperCase().slice(0, 2);
  const validCodes = ["CH", "DE", "FR", "AT", "ANG", "HO"];
  return validCodes.includes(code) ? `/icons/${code}.png` : null;
}

function renderGlobalCountryFilterOptions() {
  const select = document.getElementById("globalCountryFilter");
  if (!select) return;
  const current = String(state.globalCountryFilter || "all").trim().toUpperCase();
  const countries = Array.isArray(state.globalAvailableCountries) ? state.globalAvailableCountries : [];
  const options = ['<option value="all">Alle</option>'];
  for (const code of countries) {
    const normalized = String(code || "").trim().toUpperCase();
    if (!/^[A-Z]{2}$/.test(normalized)) continue;
    const selected = current === normalized ? " selected" : "";
    options.push(`<option value="${escapeHtml(normalized)}"${selected}>${escapeHtml(normalized)}</option>`);
  }
  select.innerHTML = options.join("");
  if (current !== "ALL" && current !== "" && !countries.map((c) => String(c).toUpperCase()).includes(current)) {
    state.globalCountryFilter = "all";
    select.value = "all";
  } else if (current !== "ALL" && current !== "") {
    select.value = current;
  }
}

function getOsIconPath(osName) {
  const os = String(osName || "").toLowerCase();
  if (os.includes("windows")) return "/icons/windows.png";
  if (os.includes("linux")) return "/icons/linux.png";
  return null;
}

function getOsEmoji(osName) {
  const os = String(osName || "").toLowerCase();
  if (os.includes("windows")) return "🪟";
  if (os.includes("linux")) return "🐧";
  return "🖥️";
}

function parseOsRelease(payload, osName) {
  if (!payload || typeof payload !== "object") return "";
  const osField = payload.os || "";
  if (typeof osField === "string" && osField.trim()) return osField.trim();
  return "";
}

function extractOpenAlertCount(payload) {
  if (!payload || typeof payload !== "object") return 0;
  try {
    const alerts = payload.alerts || payload.active_alerts || [];
    if (!Array.isArray(alerts)) return 0;
    return alerts.filter((a) => a && a.status !== "resolved" && a.status !== "closed").length;
  } catch {
    return 0;
  }
}

function formatSystemOverviewStatus(host) {
  const online = host?.online === true;
  if (!online) {
    return `<span class="so-status-badge so-status-offline">Offline</span>`;
  }

  const openAlerts = extractOpenAlertCount(host?.payload || {});
  if (openAlerts <= 0) {
    return `<span class="so-status-badge so-status-ok">OK</span>`;
  }

  const criticalCount = Array.isArray(host?.payload?.alerts)
    ? host.payload.alerts.filter((a) => a?.severity === "critical" && a?.status !== "resolved" && a?.status !== "closed").length
    : 0;
  const warningCount = Math.max(0, openAlerts - criticalCount);
  if (criticalCount > 0) {
    return `<span class="so-status-badge so-status-critical">${criticalCount} Critical</span>`;
  }
  return `<span class="so-status-badge so-status-warning">${warningCount} Warning</span>`;
}

function resolveSapReleaseDisplay(sapRelease, sapVersionMap) {
  if (!sapRelease) return "-";
  const releaseText = String(sapRelease);
  const buildMatch = releaseText.match(/\d+\.\d+\.\d+/);
  const buildKey = buildMatch ? buildMatch[0] : releaseText;
  const versionInfo = sapVersionMap.get(buildKey);
  // Return Feature Pack if found, else return the release text for fallback display
  // This ensures dynamically updated versions show current FP mapping at display time
  if (versionInfo?.featurePack) {
    return versionInfo.featurePack;
  }
  // If not found, return original release text (preserves old data for reference)
  return releaseText;
}

function formatShortHostname(hostname) {
  const raw = String(hostname || "").trim();
  if (!raw) return "-";
  return raw.split(".")[0] || raw;
}

function truncateDisplayText(value, options = {}) {
  const full = asText(value, "");
  const fallback = options.fallback ?? "-";
  if (!full || full === "-") {
    return { display: fallback, full: "", truncated: false };
  }
  const maxLen = Number(options.maxLen) > 0 ? Number(options.maxLen) : 28;
  if (full.length <= maxLen) {
    return { display: full, full, truncated: false };
  }
  const headLen = Number(options.headLen) > 0
    ? Number(options.headLen)
    : Math.max(8, Math.floor(maxLen * 0.5));
  const tailLen = Number(options.tailLen) > 0
    ? Number(options.tailLen)
    : Math.max(6, maxLen - headLen - 1);
  return {
    display: `${full.slice(0, headLen)}…${full.slice(-tailLen)}`,
    full,
    truncated: true,
  };
}

function truncateHostnameForDisplay(hostname, options = {}) {
  const full = asText(hostname, "").trim();
  if (!full || full === "-") {
    return { display: "-", full: "", truncated: false };
  }
  const maxLen = Number(options.maxLen) > 0 ? Number(options.maxLen) : 22;
  const parts = full.split(".").filter(Boolean);
  // FQDN immer als Erster…Letzter-Label kuerzen (auch unter maxLen – sonst bricht CSS unschoen ab).
  if (parts.length >= 2) {
    const display = `${parts[0]}…${parts[parts.length - 1]}`;
    if (display !== full) {
      return { display, full, truncated: true };
    }
  }
  if (full.length <= maxLen) {
    return { display: full, full, truncated: false };
  }
  const headLen = Math.min(14, Math.max(8, Math.floor(maxLen * 0.55)));
  const tailLen = Math.max(6, maxLen - headLen - 1);
  return truncateDisplayText(full, { headLen, tailLen, maxLen });
}

function renderFullValueWithEllipsisHtml(value) {
  const full = asText(value, "-");
  const display = escapeHtml(full);
  if (!full || full === "-") {
    return '<span class="text-truncate-mid">-</span>';
  }
  return `<span class="text-truncate-mid" title="${escapeHtml(full)}">${display}</span>`;
}

function renderTruncatedSpanHtml(info) {
  const display = escapeHtml(info.display);
  if (!info.full || info.full === info.display) {
    return `<span class="text-truncate-mid">${display}</span>`;
  }
  return `<span class="text-truncate-mid" title="${escapeHtml(info.full)}">${display}</span>`;
}

function renderTruncatedHostnameHtml(hostname, options = {}) {
  return renderTruncatedSpanHtml(truncateHostnameForDisplay(hostname, options));
}

function renderTruncatedTextHtml(value, options = {}) {
  return renderTruncatedSpanHtml(truncateDisplayText(value, options));
}

function renderTruncatedHostUidHtml(hostUid) {
  const full = asText(hostUid, "").trim();
  if (!full) {
    return '<span class="text-truncate-mid">-</span>';
  }
  const display = full.length > 12 ? `${full.slice(0, 8)}…${full.slice(-4)}` : full;
  return renderTruncatedSpanHtml({ display, full, truncated: full.length > 12 });
}

function updateSystemOverviewAddonsToggleButton() {
  const button = document.getElementById("toggleSystemOverviewAddonsButton");
  if (!button) {
    return;
  }
  const expanded = state.systemOverviewAddonsExpanded === true;
  button.textContent = expanded ? "AddOns zuklappen" : "AddOns aufklappen";
  button.setAttribute("aria-pressed", expanded ? "true" : "false");
}

function updateSystemOverviewSortModeButton() {
  const button = document.getElementById("toggleSystemOverviewSortModeButton");
  if (!button) {
    return;
  }
  const addonMode = state.systemOverviewSortMode === "addon-customer-os";
  button.textContent = addonMode ? "Sort: AddOn > Version > Kunde" : "Sort: Land > Kunde";
  button.setAttribute("aria-pressed", addonMode ? "true" : "false");
}

function updateSystemOverviewSearchInputMode() {
  const input = document.getElementById("systemOverviewSearchInput");
  if (!input) {
    return;
  }
  const addonMode = state.systemOverviewSortMode === "addon-customer-os";
  input.placeholder = addonMode
    ? "AddOn-Name filtern..."
    : "Host/Kunde/OS/AddOn suchen...";
}

function collectSystemOverviewHostAddonLabels(host) {
  const payload = host && typeof host.payload === "object" ? host.payload : {};
  const sap = payload && typeof payload.sap_business_one === "object" ? payload.sap_business_one : null;
  const hana = payload && typeof payload.hana_addons === "object" ? payload.hana_addons : null;
  const osField = String(payload?.os || "").toLowerCase();

  const isWindows = osField.includes("windows");
  const isLinux = osField.includes("linux");
  const showSql = !isLinux;
  const showHana = !isWindows;

  const labels = [];
  const seen = new Set();

  const pushPair = (primaryValue, secondaryValue) => {
    const pair = normalizeAddonPair(primaryValue, secondaryValue);
    const name = asText(pair?.name, "").trim();
    if (!name) {
      return;
    }
    const version = asText(pair?.version, "").trim();
    const key = `${name}||${version}`.toLowerCase();
    if (seen.has(key)) {
      return;
    }
    seen.add(key);
    labels.push({ name, version });
  };

  if (showSql && sap) {
    const extRows = Array.isArray(sap?.extensions?.rows) ? sap.extensions.rows : [];
    extRows.forEach((row) => pushPair(row?.AddOnName, row?.Version));
    const legacyRows = Array.isArray(sap?.sari_addons?.rows) ? sap.sari_addons.rows : [];
    legacyRows.forEach((row) => pushPair(row?.AName, row?.AddOnVer));
  }

  if (showHana && hana) {
    const tenantViews = collectHanaAddonTenantViews(hana);
    tenantViews.forEach((tenantView) => {
      const lightRows = Array.isArray(tenantView?.lightweight) ? tenantView.lightweight : [];
      lightRows.forEach((row) => pushPair(row?.name, row?.version));
      const legacyRows = Array.isArray(tenantView?.legacy) ? tenantView.legacy : [];
      legacyRows.forEach((row) => pushPair(row?.name, row?.version));
    });
  }

  return labels.sort((a, b) => {
    const byName = String(a.name || "").localeCompare(String(b.name || ""), "de", { sensitivity: "base", numeric: true });
    if (byName !== 0) return byName;
    return String(a.version || "").localeCompare(String(b.version || ""), "de", { sensitivity: "base", numeric: true });
  });
}

function renderSystemOverviewAddons(payload, addonFilterQuery = "") {
  const sap = payload && typeof payload.sap_business_one === "object" ? payload.sap_business_one : null;
  const hana = payload && typeof payload.hana_addons === "object" ? payload.hana_addons : null;
  const osField = (payload?.os || "").toLowerCase();
  const normalizedAddonQuery = String(addonFilterQuery || "").trim().toLowerCase();
  
  // Determine which addons to show based on OS
  const isWindows = osField.includes("windows");
  const isLinux = osField.includes("linux");
  
  // Linux → HANA only; Windows → SQL only; Unknown/Both → show both
  const showSql = !isLinux;  // Show SQL for Windows or unknown OS
  const showHana = !isWindows; // Show HANA for Linux or unknown OS
  
  const sapToShow = showSql && sap ? sap : null;
  const hanaToShow = showHana && hana ? hana : null;
  
  if (!sapToShow && !hanaToShow) {
    return "";
  }

  const renderListItems = (rows, nameKey, versionKey) => {
    const maxVisible = 10;
    const renderRow = (row) => {
      const name = escapeHtml(asText(row?.[nameKey], "-"));
      const versionRaw = asText(row?.[versionKey], "").trim();
      const version = versionRaw ? escapeHtml(versionRaw) : "";
      return `<li>${name}${version ? ` <span class="so-addon-version">${version}</span>` : ""}</li>`;
    };

    const visibleRowsHtml = rows.slice(0, maxVisible).map(renderRow).join("");
    if (rows.length <= maxVisible) {
      return visibleRowsHtml;
    }

    const hiddenRowsHtml = rows.slice(maxVisible).map(renderRow).join("");
    const hiddenCount = rows.length - maxVisible;
    return `${visibleRowsHtml}<li class="so-addon-more"><details><summary>+${hiddenCount} weitere</summary><ul class="so-addon-list so-addon-list-nested">${hiddenRowsHtml}</ul></details></li>`;
  };

  const filterAddonRows = (rows, nameKey, versionKey) => {
    const sourceRows = Array.isArray(rows) ? rows : [];
    if (!normalizedAddonQuery) {
      return sourceRows;
    }

    return sourceRows.filter((row) => {
      const haystack = `${asText(row?.[nameKey], "")} ${asText(row?.[versionKey], "")}`.toLowerCase();
      return haystack.includes(normalizedAddonQuery);
    });
  };

  const renderAddonColumn = (title, rows, nameKey, versionKey) => {
    if (!Array.isArray(rows) || rows.length === 0) {
      return "";
    }
    const content = `<ul class="so-addon-list">${renderListItems(rows, nameKey, versionKey)}</ul>`;
    return `<div class="so-addon-col"><h6>${escapeHtml(title)}</h6>${content}</div>`;
  };

  let result = "";

  // SQL AddOns (Windows or unknown OS)
  if (sapToShow) {
    const extRaw = Array.isArray(sapToShow?.extensions?.rows) ? sapToShow.extensions.rows : [];
    const legacyRaw = Array.isArray(sapToShow?.sari_addons?.rows) ? sapToShow.sari_addons.rows : [];
    const extRows = filterAddonRows(extRaw, "AddOnName", "Version");
    const legacyRows = filterAddonRows(legacyRaw, "AName", "AddOnVer");
    const extCount = extRows.length;
    const legacyCount = legacyRows.length;
    const sqlTotalCount = extCount + legacyCount;

    if (sqlTotalCount > 0) {
      const columns = [
        renderAddonColumn("Lightweight", extRows, "AddOnName", "Version"),
        renderAddonColumn("Legacy", legacyRows, "AName", "AddOnVer"),
      ].filter(Boolean).join("");
      const sqlSummary = `SQL AddOns (${extCount} LW / ${legacyCount} Legacy)`;
      const openAttr = state.systemOverviewAddonsExpanded === true ? " open" : "";

      result += `
    <details class="so-addon-details"${openAttr}>
      <summary>${escapeHtml(sqlSummary)}</summary>
      <div class="so-addon-grid">
        ${columns}
      </div>
    </details>`;
    }
  }

  // HANA AddOns (Linux or unknown OS)
  if (hanaToShow) {
    const tenantViews = collectHanaAddonTenantViews(hanaToShow);
    const hanaTotalCount = tenantViews.reduce((sum, tenantView) => {
      const lightRows = filterAddonRows(tenantView?.lightweight, "name", "version");
      const legacyRows = filterAddonRows(tenantView?.legacy, "name", "version");
      return sum + lightRows.length + legacyRows.length;
    }, 0);

    if (hanaTotalCount > 0) {
      const openAttr = state.systemOverviewAddonsExpanded === true ? " open" : "";
      const tenantSections = tenantViews.map((tenantView) => {
        const lightRows = filterAddonRows(tenantView?.lightweight, "name", "version");
        const legacyRows = filterAddonRows(tenantView?.legacy, "name", "version");
        const tenantCount = lightRows.length + legacyRows.length;
        if (tenantCount === 0) {
          return "";
        }

        const tenantLabel = tenantView.tenantId ? `Tenant ${tenantView.tenantId}` : "SystemDB";
        const tenantPort = tenantView.tenantPort ? ` | Port ${tenantView.tenantPort}` : "";
        const tenantSummary = `${tenantLabel}${tenantPort} (${lightRows.length} LW / ${legacyRows.length} Legacy)`;
        const tenantColumns = [
          renderAddonColumn("Lightweight", lightRows, "name", "version"),
          renderAddonColumn("Legacy", legacyRows, "name", "version"),
        ].filter(Boolean).join("");

        return `
        <details class="so-addon-details so-addon-tenant-details"${openAttr}>
          <summary>${escapeHtml(tenantSummary)}</summary>
          <div class="so-addon-grid">
            ${tenantColumns}
          </div>
        </details>`;
      }).join("");

      result += `
    <details class="so-addon-details"${openAttr}>
      <summary>${escapeHtml(`HANA AddOns (${hanaTotalCount})`)}</summary>
      ${tenantSections}
    </details>`;
    }
  }

  return result;
}

function collectSystemOverviewTranslatedLicenseTypes(sapLicense) {
  const rawFocusTypes = Array.isArray(sapLicense?.focus_license_types) ? sapLicense.focus_license_types : [];
  if (!rawFocusTypes.length) {
    return [];
  }

  return rawFocusTypes
    .filter((entry) => entry && typeof entry === "object")
    .map((entry) => {
      const rawType = asText(entry.license_type, "").trim();
      const upperRawType = rawType.toUpperCase();
      let translated = null;
      for (const mapEntry of SAP_LICENSE_TYPE_MAP) {
        const isVisible = Boolean(mapEntry?.visible);
        const matchText = asText(mapEntry?.matchText, "").toUpperCase();
        if (matchText && matchText === upperRawType && isVisible) {
          translated = asText(mapEntry?.displayName, null);
          break;
        }
      }
      if (!rawType || translated === null) {
        return null;
      }
      const countRaw = Number(entry.count);
      const count = Number.isFinite(countRaw) ? countRaw : 0;
      return {
        rawType,
        translated,
        count,
      };
    })
    .filter((entry) => entry !== null);
}

function hasSystemOverviewLicenseInfo(payload) {
  const sapLicense = payload && typeof payload.sap_license === "object" ? payload.sap_license : null;
  if (!sapLicense) {
    return false;
  }

  const rawExpiration = asText(sapLicense.expiration, "").trim();
  const formattedExpiration = /^\d{8}$/.test(rawExpiration)
    ? `${rawExpiration.substring(6, 8)}.${rawExpiration.substring(4, 6)}.${rawExpiration.substring(0, 4)}`
    : rawExpiration;

  const values = [
    asText(sapLicense.hardware_key, "").trim(),
    asText(sapLicense.instno, "").trim(),
    asText(sapLicense.system_nr, "").trim(),
    asText(sapLicense.system_type, "").trim(),
    asText(sapLicense.customer_no, "").trim(),
    asText(sapLicense.customer_name, "").trim(),
    formattedExpiration,
  ];

  return values.some((value) => Boolean(value));
}

function buildSystemOverviewCustomerDataIndicators(hostEntries) {
  const hosts = Array.isArray(hostEntries) ? hostEntries : [];
  let hasAddons = false;
  let hasLicenseFile = false;
  let hasLicenseTypes = false;

  for (const host of hosts) {
    const payload = host && typeof host.payload === "object" ? host.payload : {};

    if (!hasAddons && collectSystemOverviewHostAddonLabels(host).length > 0) {
      hasAddons = true;
    }
    if (!hasLicenseFile && hasSystemOverviewLicenseInfo(payload)) {
      hasLicenseFile = true;
    }
    if (!hasLicenseTypes) {
      const sapLicense = payload && typeof payload.sap_license === "object" ? payload.sap_license : null;
      if (collectSystemOverviewTranslatedLicenseTypes(sapLicense).length > 0) {
        hasLicenseTypes = true;
      }
    }

    if (hasAddons && hasLicenseFile && hasLicenseTypes) {
      break;
    }
  }

  const items = [];
  if (hasAddons) items.push({ emoji: "🧩", label: "AddOns" });
  if (hasLicenseFile) items.push({ emoji: "📄", label: "Lizenzfile" });
  if (hasLicenseTypes) items.push({ emoji: "🏷️", label: "Lizenztypen" });

  return {
    emojiText: items.map((item) => item.emoji).join(" "),
    titleText: items.length > 0
      ? `Daten vorhanden: ${items.map((item) => item.label).join(", ")}`
      : "",
  };
}

function renderSystemOverviewLicenseInfos(payload) {
  const sapLicense = payload && typeof payload.sap_license === "object" ? payload.sap_license : null;
  if (!sapLicense) {
    return "";
  }

  if (!hasSystemOverviewLicenseInfo(payload)) {
    return "";
  }

  const rawExpiration = asText(sapLicense.expiration, "").trim();
  const formattedExpiration = /^\d{8}$/.test(rawExpiration)
    ? `${rawExpiration.substring(6, 8)}.${rawExpiration.substring(4, 6)}.${rawExpiration.substring(0, 4)}`
    : rawExpiration;

  const rows = [
    { label: "HW-Key", value: asText(sapLicense.hardware_key, "").trim() },
    { label: "Installationsnummer", value: asText(sapLicense.instno, "").trim() },
    { label: "Systemnummer", value: asText(sapLicense.system_nr, "").trim() },
    { label: "Systemtyp", value: asText(sapLicense.system_type, "").trim() },
    { label: "Kundennummer", value: asText(sapLicense.customer_no, "").trim() },
    { label: "Lizenznehmer", value: asText(sapLicense.customer_name, "").trim() },
    { label: "Gültig bis", value: formattedExpiration }
  ].filter((entry) => entry.value);

  if (rows.length === 0) {
    return "";
  }

  const openAttr = state.systemOverviewAddonsExpanded === true ? " open" : "";
  const rowsHtml = rows.map((entry) => {
    return `<li><strong class="so-license-label">${escapeHtml(entry.label)}:</strong> <span class="so-license-value">${escapeHtml(entry.value)}</span></li>`;
  }).join("");

  return `
    <details class="so-addon-details so-license-details"${openAttr}>
      <summary>Lizenzinfos (${rows.length})</summary>
      <div class="so-addon-grid">
        <ul class="so-license-list">${rowsHtml}</ul>
      </div>
    </details>
  `;
}

function renderSystemOverviewLicenseTypes(payload) {
  const sapLicense = payload && typeof payload.sap_license === "object" ? payload.sap_license : null;
  const translatedFocusTypes = collectSystemOverviewTranslatedLicenseTypes(sapLicense);

  if (!translatedFocusTypes.length) {
    return "";
  }

  const openAttr = state.systemOverviewAddonsExpanded === true ? " open" : "";
  const rowsHtml = translatedFocusTypes
    .map((entry) => {
      const countDisplay = String(entry.count);
      const hasTranslatedLabel = entry.translated && entry.translated !== entry.rawType;
      const labelHtml = hasTranslatedLabel
        ? `${escapeHtml(entry.translated)} <span class="so-license-type-raw">(${escapeHtml(entry.rawType)})</span>`
        : `${escapeHtml(entry.rawType)}`;
      return `<li><span class="so-license-type-count">${escapeHtml(countDisplay)}</span><span class="so-license-type-name">${labelHtml}</span></li>`;
    })
    .join("");

  return `
    <details class="so-addon-details so-license-types-details"${openAttr}>
      <summary>Lizenztypen (${translatedFocusTypes.length})</summary>
      <div class="so-addon-grid">
        <ul class="so-license-list so-license-type-list">${rowsHtml}</ul>
      </div>
    </details>
  `;
}

function collectSystemOverviewAddonSearchText(payload) {
  if (!payload || typeof payload !== "object") {
    return "";
  }

  const tokens = [];

  const sap = payload.sap_business_one && typeof payload.sap_business_one === "object"
    ? payload.sap_business_one
    : null;
  const hana = payload.hana_addons && typeof payload.hana_addons === "object"
    ? payload.hana_addons
    : null;

  const pushValue = (value) => {
    const text = String(value || "").trim();
    if (text) tokens.push(text.toLowerCase());
  };

  if (sap) {
    const extRows = Array.isArray(sap.extensions?.rows) ? sap.extensions.rows : [];
    extRows.forEach((row) => {
      pushValue(row?.AddOnName);
      pushValue(row?.Version);
    });

    const legacyRows = Array.isArray(sap.sari_addons?.rows) ? sap.sari_addons.rows : [];
    legacyRows.forEach((row) => {
      pushValue(row?.AName);
      pushValue(row?.AddOnVer);
    });
  }

  if (hana) {
    const tenantViews = collectHanaAddonTenantViews(hana);
    tenantViews.forEach((tenantView) => {
      pushValue(tenantView?.tenantId);
      pushValue(tenantView?.tenantPort);

      const lightweight = Array.isArray(tenantView?.lightweight) ? tenantView.lightweight : [];
      lightweight.forEach((row) => {
        pushValue(row?.name);
        pushValue(row?.version);
      });

      const legacy = Array.isArray(tenantView?.legacy) ? tenantView.legacy : [];
      legacy.forEach((row) => {
        pushValue(row?.name);
        pushValue(row?.version);
      });
    });
  }

  return tokens.join(" ");
}

function renderSystemOverviewLandChipHtml() {
  const scope = state.systemOverviewCountryFilter === "all"
    ? "Alle Länder"
    : String(state.systemOverviewCountryFilter || "all");
  return `<span class="system-overview-stat-chip system-overview-land-chip">Land: ${escapeHtml(scope)}</span>`;
}

function syncSystemOverviewCountryFilterUi(filterEl) {
  if (!filterEl) {
    return;
  }
  const landChip = filterEl.querySelector(".system-overview-land-chip");
  if (landChip) {
    const scope = state.systemOverviewCountryFilter === "all"
      ? "Alle Länder"
      : String(state.systemOverviewCountryFilter || "all");
    landChip.textContent = `Land: ${scope}`;
  }
  filterEl.querySelectorAll(".so-country-filter-btn").forEach((button) => {
    const code = String(button.getAttribute("data-country-filter") || "all");
    button.classList.toggle("active", code === state.systemOverviewCountryFilter);
  });
}

function renderSystemOverviewCountryFilter(countryCodes) {
  const filterEl = document.getElementById("systemOverviewCountryFilter");
  if (!filterEl) return;

  const normalized = Array.from(new Set((Array.isArray(countryCodes) ? countryCodes : [])
    .map((code) => String(code || "").trim().toUpperCase())
    .filter((code) => code)));

  if (!normalized.length) {
    filterEl.innerHTML = "";
    filterEl.dataset.signature = "";
    return;
  }

  if (state.systemOverviewCountryFilter !== "all" && !normalized.includes(state.systemOverviewCountryFilter)) {
    state.systemOverviewCountryFilter = "all";
  }

  const signature = normalized.join("|");
  if (filterEl.dataset.signature === signature && filterEl.querySelector(".so-country-filter-list")) {
    syncSystemOverviewCountryFilterUi(filterEl);
    return;
  }
  filterEl.dataset.signature = signature;

  const buttons = [
    `<button type="button" class="so-country-filter-btn ${state.systemOverviewCountryFilter === "all" ? "active" : ""}" data-country-filter="all">Alle</button>`,
    ...normalized.map((code) => {
      const iconPath = getCountryFlagIconPath(code);
      const icon = iconPath
        ? `<img src="${iconPath}" alt="${escapeHtml(code)}" class="so-country-filter-flag" />`
        : "";
      return `<button type="button" class="so-country-filter-btn ${state.systemOverviewCountryFilter === code ? "active" : ""}" data-country-filter="${escapeHtml(code)}">${icon}<span>${escapeHtml(code)}</span></button>`;
    }),
  ].join("");

  filterEl.innerHTML = `${renderSystemOverviewLandChipHtml()}<div class="so-country-filter-list">${buttons}</div>`;
  filterEl.querySelectorAll(".so-country-filter-btn").forEach((button) => {
    button.addEventListener("click", () => {
      const nextFilter = String(button.getAttribute("data-country-filter") || "all");
      if (state.systemOverviewCountryFilter === nextFilter) return;
      state.systemOverviewCountryFilter = nextFilter;
      loadSystemOverview();
    });
  });
}

function formatSystemOverviewTableRow(host, osName, customerName, sapVersionMap, onRowClick, searchQuery = "") {
  if (!host) return "";

  const hostnameRaw = String(host.hostname || "-");
  const hostUidRaw = String(resolveHostIdentity(host) || hostnameRaw);
  const hostname = escapeHtml(hostnameRaw);
  const hostUid = escapeHtml(hostUidRaw);
  const shortHostname = escapeHtml(formatShortHostname(hostnameRaw));
  const hostTitle = escapeHtml(String(host.display_name || host.hostname || "-").trim() || "-");
  const hostUidShort = escapeHtml(hostUidRaw.length > 32 ? `${hostUidRaw.slice(0, 29)}...` : hostUidRaw);
  const osEmoji = getOsEmoji(osName);
  const osRelease = parseOsRelease(host.payload || {}, osName);
  const osReleaseDisplay = escapeHtml(osRelease || String(osName || "-").trim() || "-");

  const sapReleaseDisplay = escapeHtml(resolveSapReleaseDisplay(host.sap_release, sapVersionMap));
  const hanaVersion = escapeHtml(String(host.hana_version || "-"));
  const hanaSid = escapeHtml(String(host.hana_sid || "-"));
  const sqlRelease = escapeHtml(String(host.sql_release || "-"));
  const ramGbRaw = Number.isFinite(host.ram_gb) ? String(host.ram_gb) : String(host.ram_gb || "-");
  const ramGb = escapeHtml(ramGbRaw === "-" ? "-" : `${ramGbRaw} GB`);
  const cpuCores = Number.isFinite(host.cpu_cores) ? host.cpu_cores : "-";
  const cpuModel = escapeHtml(String(host.cpu_model_name || "-"));
  const systemModel = escapeHtml(String(host.model || host.system_model || host.payload?.model || "-"));
  const lastUpdate = formatSystemOverviewLastUpdate(host.last_update);
  const statusBadge = formatSystemOverviewStatus(host);
  const payload = host.payload || {};
  const addOnSection = renderSystemOverviewAddons(payload, searchQuery);
  const licenseInfoSection = renderSystemOverviewLicenseInfos(payload);
  const licenseTypeSection = renderSystemOverviewLicenseTypes(payload);

  const rowClickClass = onRowClick ? "so-row-clickable" : "";
  const rowClickAttr = onRowClick ? `data-hostname="${hostname}" data-host-uid="${hostUid}"` : "";

  return `
    <tr class="${rowClickClass}" ${rowClickAttr}>
      <td class="so-host-cell">
        <div class="so-host-title">${hostTitle}</div>
        <div class="so-host-short">${shortHostname}</div>
        ${addOnSection ? `<div class="so-host-addons">${addOnSection}</div>` : ""}
      </td>
      <td>
        <div class="so-cell-main">${osReleaseDisplay}</div>
        <div class="so-os-spacer">&nbsp;</div>
        ${licenseInfoSection ? `<div class="so-os-license">${licenseInfoSection}</div>` : ""}
      </td>
      <td>
        <div class="so-cell-main">${cpuCores} vCPU</div>
        <div class="so-cell-sub">${cpuModel}</div>
        ${licenseTypeSection ? `<div class="so-cpu-license-types">${licenseTypeSection}</div>` : ""}
      </td>
      <td>
        <div class="so-cell-main">${ramGb}</div>
        <div class="so-cell-sub">${systemModel}</div>
      </td>
      <td>
        <div class="so-cell-main">SQL: ${sqlRelease}</div>
        <div class="so-cell-sub">SAP Release: ${sapReleaseDisplay}</div>
        <div class="so-cell-sub">HANA Release: ${hanaVersion}</div>
        <div class="so-cell-sub">HANA SID: ${hanaSid}</div>
      </td>
      <td class="so-status-cell">
        <div class="so-cell-main">${statusBadge}</div>
        <div class="so-status-time" title="${escapeHtml(lastUpdate)}">${escapeHtml(lastUpdate)}</div>
      </td>
    </tr>
  `;
}

async function loadSystemOverview() {
  const container = document.getElementById("systemOverviewContainer");
  const statsEl = document.getElementById("systemOverviewStats");
  const filterEl = document.getElementById("systemOverviewCountryFilter");
  const searchEl = document.getElementById("systemOverviewSearchInput");
  updateSystemOverviewAddonsToggleButton();
  updateSystemOverviewSortModeButton();
  updateSystemOverviewSearchInputMode();
  if (!container) return;

  if (searchEl && document.activeElement !== searchEl) {
    searchEl.value = String(state.systemOverviewSearchQuery || "");
  }

  container.innerHTML = '<p class="muted">Lade Systemdaten...</p>';

  try {
    const searchQuery = String(state.systemOverviewSearchQuery || "").trim().toLowerCase();
    const overviewParams = new URLSearchParams();
    if (searchQuery) {
      overviewParams.set("q", searchQuery);
    }
    const overviewUrl = `/api/v1/system-overview${overviewParams.toString() ? `?${overviewParams.toString()}` : ""}`;
    const response = await fetch(overviewUrl, { credentials: "same-origin" });
    if (!response.ok) throw new Error("HTTP " + response.status);
    const data = await response.json();
    const byCountry = data && typeof data === "object" ? (data.by_country || {}) : {};
    const allCountries = Object.keys(byCountry || {}).sort((a, b) => String(a).localeCompare(String(b)));
    renderSystemOverviewCountryFilter(allCountries);

    const activeCountryFilter = String(state.systemOverviewCountryFilter || "all");
    const filteredEntries = Object.entries(byCountry)
      .filter(([country]) => activeCountryFilter === "all" || String(country).toUpperCase() === activeCountryFilter)
      .sort((a, b) => String(a[0]).localeCompare(String(b[0])));

    const isAddonSortMode = state.systemOverviewSortMode === "addon-customer-os";
    const filteredHostEntries = [];
    filteredEntries.forEach(([country, osMap]) => {
      Object.entries(osMap || {}).forEach(([osName, customerMap]) => {
        Object.entries(customerMap || {}).forEach(([customer, hosts]) => {
          (Array.isArray(hosts) ? hosts : []).forEach((host) => {
            const payload = host && typeof host.payload === "object" ? host.payload : {};
            if (!isAddonSortMode && searchQuery) {
              const addonText = collectSystemOverviewAddonSearchText(payload);
              const haystack = [
                host?.hostname,
                host?.display_name,
                payload?.display_name,
                payload?.hostname,
                payload?.agent_id,
                customer,
                osName,
                country,
                addonText,
              ].map((v) => String(v || "").toLowerCase()).join(" ");
              if (!haystack.includes(searchQuery)) {
                return;
              }
            }
            filteredHostEntries.push({ country, osName, customer, host });
          });
        });
      });
    });

    const uniqueHostCount = new Set(filteredHostEntries.map((entry) => String(resolveHostIdentity(entry.host) || ""))).size;
    let displayedHostCount = uniqueHostCount;
    let treeHtml = "";

    if (isAddonSortMode) {
      const addonMap = new Map();
      const displayedHostnames = new Set();

      filteredHostEntries.forEach((entry) => {
        const addonItems = collectSystemOverviewHostAddonLabels(entry.host)
          .filter((addon) => {
            if (!searchQuery) return true;
            const haystack = `${addon?.name || ""} ${addon?.version || ""}`.toLowerCase();
            return haystack.includes(searchQuery);
          });
        if (!addonItems.length) {
          return;
        }

        addonItems.forEach((addon) => {
          const addonNameKey = String(addon?.name || "").trim();
          if (!addonNameKey) {
            return;
          }
          if (!addonMap.has(addonNameKey)) {
            addonMap.set(addonNameKey, new Map());
          }
          const versionMap = addonMap.get(addonNameKey);
          const versionKey = String(addon?.version || "").trim() || "-";
          if (!versionMap.has(versionKey)) {
            versionMap.set(versionKey, new Map());
          }
          const customerMap = versionMap.get(versionKey);
          const customerKey = String(entry.customer || "-");
          if (!customerMap.has(customerKey)) {
            customerMap.set(customerKey, []);
          }
          customerMap.get(customerKey).push(entry);
          displayedHostnames.add(String(resolveHostIdentity(entry.host) || ""));
        });
      });

      displayedHostCount = displayedHostnames.size;

      const sortedAddons = Array.from(addonMap.entries())
        .sort((a, b) => String(a[0]).localeCompare(String(b[0]), "de", { sensitivity: "base", numeric: true }));

      treeHtml = sortedAddons
        .map(([addonName, versionMap], addonIndex) => {
          const versionSections = Array.from(versionMap.entries())
            .sort((a, b) => String(a[0]).localeCompare(String(b[0]), "de", { sensitivity: "base", numeric: true }))
            .map(([version, customerMap], versionIndex) => {
              const customerSections = Array.from(customerMap.entries())
                .sort((a, b) => String(a[0]).localeCompare(String(b[0]), "de", { sensitivity: "base", numeric: true }))
                .map(([customer, entries], customerIndex) => {
                  const customerIndicators = buildSystemOverviewCustomerDataIndicators(entries.map((entry) => entry.host));
                  const customerIndicatorHtml = customerIndicators.emojiText
                    ? `<span class="so-customer-data-indicators" title="${escapeHtml(customerIndicators.titleText)}">${escapeHtml(customerIndicators.emojiText)}</span>`
                    : "";
                  const rowHtml = entries
                    .sort((left, right) => String(left.host?.display_name || left.host?.hostname || "").localeCompare(String(right.host?.display_name || right.host?.hostname || ""), "de", { sensitivity: "base", numeric: true }))
                    .map((entry) => formatSystemOverviewTableRow(entry.host, entry.osName, entry.customer, SAP_B1_VERSION_MAP, true, searchQuery))
                    .join("");
                  const customerId = `so-addon-customer-${addonIndex}-${versionIndex}-${customerIndex}`;
                  return `
                    <section class="system-overview-country-group">
                      <button class="system-overview-toggle system-overview-toggle--customer" type="button" data-target-id="${customerId}" aria-expanded="false">
                        <span class="system-overview-chevron">▶</span>
                        <span class="so-country-header">👥 ${escapeHtml(customer)}${customerIndicatorHtml} (${entries.length})</span>
                      </button>
                      <div id="${customerId}" class="system-overview-customer-list hidden">
                        <div class="system-overview-table-wrap">
                          <table class="system-overview-table">
                            <thead>
                              <tr>
                                <th>Host</th>
                                <th>OS</th>
                                <th>CPU</th>
                                <th>RAM / Modell</th>
                                <th>SAP / DB</th>
                                <th>Status</th>
                              </tr>
                            </thead>
                            <tbody>${rowHtml}</tbody>
                          </table>
                        </div>
                      </div>
                    </section>
                  `;
                })
                .join("");

              const versionEntryCount = Array.from(customerMap.values()).reduce((sum, entries) => sum + entries.length, 0);
              const versionId = `so-addon-version-${addonIndex}-${versionIndex}`;
              return `
                <section class="system-overview-country-group">
                  <button class="system-overview-toggle" type="button" data-target-id="${versionId}" aria-expanded="false">
                    <span class="system-overview-chevron">▶</span>
                    <span class="so-country-header">🏷️ ${escapeHtml(version)} (${versionEntryCount})</span>
                  </button>
                  <div id="${versionId}" class="system-overview-os-list hidden">${customerSections}</div>
                </section>
              `;
            })
            .join("");

          const addonEntryCount = Array.from(versionMap.values())
            .reduce((sum, customerMap) => sum + Array.from(customerMap.values()).reduce((innerSum, entries) => innerSum + entries.length, 0), 0);
          const addonId = `so-addon-${addonIndex}`;
          return `
            <section class="system-overview-country-group">
              <button class="system-overview-toggle" type="button" data-target-id="${addonId}" aria-expanded="false">
                <span class="system-overview-chevron">▶</span>
                <span class="so-country-header">🧩 ${escapeHtml(addonName)} (${addonEntryCount})</span>
              </button>
              <div id="${addonId}" class="system-overview-os-list hidden">${versionSections}</div>
            </section>
          `;
        })
        .join("");
    } else {
      treeHtml = filteredEntries
        .map(([country, osMap], countryIndex) => {
          const countryCode = country;
          const flagIconPath = getCountryFlagIconPath(countryCode);
          const flagImg = flagIconPath ? `<img src="${flagIconPath}" alt="${escapeHtml(country)}" class="so-country-flag" />` : "";

          const customerMapByCountry = new Map();
          Object.entries(osMap || {}).forEach(([osName, customerMap]) => {
            Object.entries(customerMap || {}).forEach(([customer, hosts]) => {
              const matchingHosts = (Array.isArray(hosts) ? hosts : []).filter((host) => {
                const payload = host && typeof host.payload === "object" ? host.payload : {};
                const addonText = collectSystemOverviewAddonSearchText(payload);
                const haystack = [
                  host?.hostname,
                  host?.display_name,
                  payload?.display_name,
                  payload?.hostname,
                  payload?.agent_id,
                  customer,
                  osName,
                  country,
                  addonText,
                ].map((v) => String(v || "").toLowerCase()).join(" ");
                if (!searchQuery) {
                  return true;
                }
                return haystack.includes(searchQuery);
              });

              if (!matchingHosts.length) {
                return;
              }

              const customerKey = String(customer || "-");
              if (!customerMapByCountry.has(customerKey)) {
                customerMapByCountry.set(customerKey, new Map());
              }
              const osMapForCustomer = customerMapByCountry.get(customerKey);
              if (!osMapForCustomer.has(osName)) {
                osMapForCustomer.set(osName, []);
              }
              osMapForCustomer.get(osName).push(...matchingHosts);
            });
          });

          const customerSections = Array.from(customerMapByCountry.entries())
            .sort((a, b) => String(a[0]).localeCompare(String(b[0]), "de", { sensitivity: "base", numeric: true }))
            .map(([customer, osMapForCustomer], customerIndex) => {
              const customerHostEntries = Array.from(osMapForCustomer.entries())
                .flatMap(([osName, hostsForOs]) => (Array.isArray(hostsForOs) ? hostsForOs : []).map((host) => ({ host, osName })))
                .sort((left, right) => String(left.host?.display_name || left.host?.hostname || "").localeCompare(String(right.host?.display_name || right.host?.hostname || ""), "de", { sensitivity: "base", numeric: true }));

              if (!customerHostEntries.length) {
                return "";
              }

              const rowHtml = customerHostEntries
                .map((entry) => formatSystemOverviewTableRow(entry.host, entry.osName, customer, SAP_B1_VERSION_MAP, true, searchQuery))
                .join("");

              const customerHostCount = Array.from(osMapForCustomer.values()).reduce(
                (sum, hostList) => sum + (Array.isArray(hostList) ? hostList.length : 0),
                0,
              );
              const customerIndicators = buildSystemOverviewCustomerDataIndicators(customerHostEntries.map((entry) => entry.host));
              const customerIndicatorHtml = customerIndicators.emojiText
                ? `<span class="so-customer-data-indicators" title="${escapeHtml(customerIndicators.titleText)}">${escapeHtml(customerIndicators.emojiText)}</span>`
                : "";
              const customerId = `so-customer-${countryIndex}-${customerIndex}`;
              return `
                <section class="system-overview-country-group">
                  <button class="system-overview-toggle system-overview-toggle--customer" type="button" data-target-id="${customerId}" aria-expanded="false">
                    <span class="system-overview-chevron">▶</span>
                    <span class="so-country-header">👥 ${escapeHtml(customer)}${customerIndicatorHtml} (${customerHostCount})</span>
                  </button>
                  <div id="${customerId}" class="system-overview-customer-list hidden">
                    <div class="system-overview-table-wrap">
                      <table class="system-overview-table">
                        <thead>
                          <tr>
                            <th>Host</th>
                            <th>OS</th>
                            <th>CPU</th>
                            <th>RAM / Modell</th>
                            <th>SAP / DB</th>
                            <th>Status</th>
                          </tr>
                        </thead>
                        <tbody>${rowHtml}</tbody>
                      </table>
                    </div>
                  </div>
                </section>
              `;
            })
            .filter(Boolean)
            .join("");

          if (!customerSections) {
            return "";
          }

          const countryId = `so-country-${countryIndex}`;
          return `
            <section class="system-overview-country-group">
              <button class="system-overview-toggle" type="button" data-target-id="${countryId}" aria-expanded="true">
                <span class="system-overview-chevron">▼</span>
                <span class="so-country-header">${flagImg} ${escapeHtml(country)}</span>
              </button>
              <div id="${countryId}" class="system-overview-os-list">${customerSections}</div>
            </section>
          `;
        })
        .filter(Boolean)
        .join("");
    }

    if (statsEl) {
      const modeLabel = state.systemOverviewSortMode === "addon-customer-os"
        ? "Sicht: AddOn > Version > Kunde"
        : "Sicht: Land > Kunde";
      const chips = [
        `${displayedHostCount} Systeme`,
        modeLabel,
      ];
      statsEl.innerHTML = chips
        .map((chip, idx) => `<span class="system-overview-stat-chip${idx === 0 ? " is-primary" : ""}">${escapeHtml(chip)}</span>`)
        .join("");
    }

    if (!displayedHostCount || !treeHtml) {
      container.innerHTML = '<p class="muted">Keine Systeme für den aktuellen Filter gefunden.</p>';
      return;
    }

    container.innerHTML = `<div class="system-overview-tree">${treeHtml}</div>`;
    
    // Expand/Collapse handlers
    container.querySelectorAll(".system-overview-toggle").forEach((button) => {
      button.addEventListener("click", () => {
        const targetId = String(button.getAttribute("data-target-id") || "");
        const target = targetId ? document.getElementById(targetId) : null;
        if (!target) return;

        const expand = target.classList.contains("hidden");
        target.classList.toggle("hidden", !expand);
        button.setAttribute("aria-expanded", expand ? "true" : "false");
        const chevron = button.querySelector(".system-overview-chevron");
        if (chevron) chevron.textContent = expand ? "▼" : "▶";
      });
    });
    
    // Row click handlers
    container.querySelectorAll(".so-row-clickable").forEach((row) => {
      row.addEventListener("click", () => {
        const hostAttr = row.getAttribute("data-hostname");
        const hostUidAttr = row.getAttribute("data-host-uid") || hostAttr || "";
        if (hostAttr) {
          state.selectedHost = hostAttr;
          state.selectedHostUid = hostUidAttr;
          state.viewMode = "overview";
          state.overviewSection = "main";
          state.reportSection = "overview";
          state.reportOffset = 0;
          loadHostReport();
        }
      });
    });
  } catch (error) {
    container.innerHTML = `<p class="muted">${escapeHtml(formatApiLoadError(error?.message, "Systemübersicht"))}</p>`;
  }
}
