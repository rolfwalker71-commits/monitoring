function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function asText(value, fallback = "-") {
  const text = String(value ?? "").trim();
  return text || fallback;
}

function asNum(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function shortTime(iso) {
  if (!iso) return "-";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  return d.toLocaleString("de-CH", { hour: "2-digit", minute: "2-digit", day: "2-digit", month: "2-digit" });
}

const state = {
  hosts: [],
  sapVersionMap: new Map(),
  selectedHost: "",
  hostFilterMode: "all",
  hostSearch: "",
  countryFilter: "all",
  ownHostsOnly: false,
  ownHosts: new Set(),
  reportOffset: 0,
  totalReports: 0,
  currentReport: null,
  analysis: null,
  dbLifecycle: null,
  activeTab: "overview",
};

function resolveSapReleaseDisplay(sapRelease) {
  if (!sapRelease) return "SAP -";
  const releaseText = String(sapRelease).trim();
  if (!releaseText) return "SAP -";

  const buildMatch = releaseText.match(/\d+\.\d+\.\d+/);
  const buildKey = buildMatch ? buildMatch[0] : releaseText;
  const versionInfo = state.sapVersionMap.get(buildKey);
  if (versionInfo?.featurePack) {
    return versionInfo.featurePack;
  }

  return releaseText;
}

function resolveHostSapChip(host) {
  const raw = asText(
    host?.sap_feature_pack
      || host?.sap_release
      || host?.sap_version
      || "",
    ""
  );
  return resolveSapReleaseDisplay(raw);
}

async function apiGet(path) {
  const response = await fetch(path, { credentials: "same-origin" });
  if (!response.ok) {
    throw new Error(`${path}: ${response.status}`);
  }
  return response.json();
}

function wireTopButtons() {
  const backBtn = document.getElementById("nextBackButton");
  const logoutBtn = document.getElementById("nextLogoutButton");
  const openMainLogin = document.getElementById("nextOpenMainLogin");

  backBtn?.addEventListener("click", () => window.location.assign("/"));
  openMainLogin?.addEventListener("click", () => window.location.assign("/"));

  logoutBtn?.addEventListener("click", async () => {
    try {
      await fetch("/api/v1/web-logout", { method: "POST", credentials: "same-origin" });
    } catch (error) {
      // ignore and reload
    }
    window.location.reload();
  });
}

function openLegacyStart(route) {
  const target = `/?start=${encodeURIComponent(route)}`;
  window.location.assign(target);
}

function wireLegacyShortcuts() {
  const byId = {
    nextOpenUserSettings: "settings-password",
    nextOpenGlobalView: "global-alerts",
    nextOpenGlobalAlerts: "global-alerts",
    nextOpenCriticalTrends: "global-critical-trends",
    nextOpenInactiveHosts: "global-inactive-hosts",
    nextOpenAlarmSettings: "alarm-settings",
    nextOpenAdminSettings: "global-admin-settings",
  };

  for (const [id, route] of Object.entries(byId)) {
    const el = document.getElementById(id);
    if (!el) continue;
    el.addEventListener("click", () => openLegacyStart(route));
  }
}

function wireFilters() {
  const search = document.getElementById("nextHostSearch");
  const country = document.getElementById("nextCountryFilter");
  const all = document.getElementById("nextFilterAll");
  const alerts = document.getElementById("nextFilterAlerts");
  const critical = document.getElementById("nextFilterCritical");
  const own = document.getElementById("nextFilterOwn");

  search?.addEventListener("input", (event) => {
    state.hostSearch = String(event.target.value || "").trim().toLowerCase();
    renderHosts();
  });

  country?.addEventListener("change", (event) => {
    state.countryFilter = String(event.target.value || "all");
    renderHosts();
  });

  all?.addEventListener("click", () => {
    state.hostFilterMode = "all";
    updateFilterButtons();
    renderHosts();
  });
  alerts?.addEventListener("click", () => {
    state.hostFilterMode = "alerts";
    updateFilterButtons();
    renderHosts();
  });
  critical?.addEventListener("click", () => {
    state.hostFilterMode = "critical";
    updateFilterButtons();
    renderHosts();
  });
  own?.addEventListener("click", () => {
    state.ownHostsOnly = !state.ownHostsOnly;
    updateFilterButtons();
    renderHosts();
  });

  updateFilterButtons();
}

function updateFilterButtons() {
  const byMode = {
    all: document.getElementById("nextFilterAll"),
    alerts: document.getElementById("nextFilterAlerts"),
    critical: document.getElementById("nextFilterCritical"),
  };
  for (const [mode, button] of Object.entries(byMode)) {
    if (button) {
      button.classList.toggle("active", mode === state.hostFilterMode);
    }
  }

  const own = document.getElementById("nextFilterOwn");
  if (own) {
    own.classList.toggle("active", state.ownHostsOnly);
  }
}

function wirePaging() {
  document.getElementById("nextNewestReport")?.addEventListener("click", async () => {
    state.reportOffset = 0;
    await loadSelectedHostData();
  });

  document.getElementById("nextNewerReport")?.addEventListener("click", async () => {
    if (state.reportOffset <= 0) return;
    state.reportOffset -= 1;
    await loadSelectedHostData();
  });

  document.getElementById("nextOlderReport")?.addEventListener("click", async () => {
    if (state.reportOffset + 1 >= state.totalReports) return;
    state.reportOffset += 1;
    await loadSelectedHostData();
  });
}

function wireTabs() {
  for (const btn of document.querySelectorAll("[data-tab]")) {
    btn.addEventListener("click", () => {
      state.activeTab = String(btn.getAttribute("data-tab") || "overview");
      for (const b of document.querySelectorAll("[data-tab]")) {
        b.classList.toggle("active", b === btn);
      }
      renderDetail();
    });
  }
}

function matchesHostFilter(host) {
  if (Boolean(host?.is_hidden)) return false;

  if (state.hostFilterMode === "alerts" && asNum(host.open_alert_count, 0) <= 0) return false;
  if (state.hostFilterMode === "critical" && asNum(host.open_critical_alert_count, 0) <= 0) return false;

  if (state.countryFilter !== "all") {
    const hostCountry = String(host.country_code || "").trim().toUpperCase();
    if (hostCountry !== state.countryFilter) return false;
  }

  if (state.ownHostsOnly) {
    const hostKey = String(host.hostname || "").trim().toLowerCase();
    if (!state.ownHosts.has(hostKey)) return false;
  }

  if (!state.hostSearch) return true;
  const blob = [
    host.display_name,
    host.hostname,
    host.customer_name,
    host.os,
    host.sap_feature_pack,
    host.sap_release,
    host.hana_release,
  ]
    .map((v) => String(v || "").toLowerCase())
    .join(" ");

  return blob.includes(state.hostSearch);
}

function renderCountryFilter() {
  const select = document.getElementById("nextCountryFilter");
  if (!select) return;

  const countries = new Set();
  for (const host of state.hosts) {
    const cc = String(host.country_code || "").trim().toUpperCase();
    if (cc) countries.add(cc);
  }

  const sorted = [...countries].sort((a, b) => a.localeCompare(b));
  const previous = state.countryFilter;
  const hasPrev = previous === "all" || sorted.includes(previous);
  if (!hasPrev) state.countryFilter = "all";

  select.innerHTML = [
    '<option value="all">Land: Alle</option>',
    ...sorted.map((cc) => `<option value="${escapeHtml(cc)}">Land: ${escapeHtml(cc)}</option>`),
  ].join("");
  select.value = state.countryFilter;
}

async function loadOwnHosts() {
  try {
    const prefs = await apiGet("/api/v1/user-preferences");
    const raw = String(prefs?.host_interest_hosts || "");
    state.ownHosts = new Set(
      raw
        .split(",")
        .map((item) => item.trim().toLowerCase())
        .filter(Boolean)
    );
  } catch (error) {
    state.ownHosts = new Set();
  }
}

function renderHosts() {
  const container = document.getElementById("nextHostList");
  const status = document.getElementById("nextStatusText");
  if (!container) return;

  const visible = state.hosts.filter(matchesHostFilter);
  const hiddenTotal = state.hosts.filter((host) => Boolean(host?.is_hidden)).length;
  status.textContent = hiddenTotal > 0
    ? `${visible.length} von ${state.hosts.length - hiddenTotal} Hosts (${hiddenTotal} ausgeblendet)`
    : `${visible.length} von ${state.hosts.length} Hosts`;

  if (visible.length === 0) {
    container.innerHTML = '<p class="next-muted">Keine Hosts mit aktuellem Filter.</p>';
    return;
  }

  if (!visible.some((host) => host.hostname === state.selectedHost)) {
    state.selectedHost = visible[0].hostname;
    state.reportOffset = 0;
    void loadSelectedHostData();
  }

  container.innerHTML = visible
    .map((host) => {
      const active = host.hostname === state.selectedHost ? "active" : "";
      const alertText = asNum(host.open_alert_count, 0) > 0 ? `🚨 ${host.open_alert_count}` : "OK";
      const customerName = asText(host.customer_name, "Ohne Kunde");
      const hostName = asText(host.hostname, "-");
      const hostIp = asText(host.primary_ip || host.ip_address || host.ip || host.ipv4, "-");
      const sapChip = resolveHostSapChip(host);
      return `
        <article class="next-host-item ${active}" data-host="${escapeHtml(host.hostname)}">
          <div class="next-host-head">
            <p class="next-host-customer">${escapeHtml(customerName)}</p>
            <span class="next-host-health">${escapeHtml(alertText)}</span>
          </div>
          <h4>${escapeHtml(asText(host.display_name, host.hostname))}</h4>
          <p class="next-host-meta">${escapeHtml(hostName)} · ${escapeHtml(hostIp)}</p>
          <div class="next-host-chips">
            <span class="next-chip">${escapeHtml(asText(host.os, "OS -"))}</span>
            <span class="next-chip">${escapeHtml(sapChip)}</span>
            <span class="next-chip">${escapeHtml(asText(host.hana_release, "HANA -"))}</span>
          </div>
        </article>
      `;
    })
    .join("");

  for (const el of container.querySelectorAll(".next-host-item")) {
    el.addEventListener("click", async () => {
      const host = String(el.getAttribute("data-host") || "");
      if (!host || host === state.selectedHost) return;
      state.selectedHost = host;
      state.reportOffset = 0;
      renderHosts();
      await loadSelectedHostData();
    });
  }
}

function getPayload() {
  return (state.currentReport && state.currentReport.payload && typeof state.currentReport.payload === "object")
    ? state.currentReport.payload
    : {};
}

function renderOverview() {
  const payload = getPayload();
  const cpu = asNum(payload?.cpu?.usage_percent, 0);
  const ram = asNum(payload?.memory?.used_percent, 0);
  const swap = asNum(payload?.swap?.used_percent, 0);
  const fsMax = Array.isArray(payload?.filesystems)
    ? payload.filesystems.reduce((m, fs) => Math.max(m, asNum(fs?.used_percent, 0)), 0)
    : 0;

  return `
    <div class="next-grid-4">
      <article class="next-stat"><div class="label">CPU</div><div class="value">${cpu.toFixed(0)}%</div></article>
      <article class="next-stat"><div class="label">RAM</div><div class="value">${ram.toFixed(0)}%</div></article>
      <article class="next-stat"><div class="label">SWAP</div><div class="value">${swap.toFixed(0)}%</div></article>
      <article class="next-stat"><div class="label">FS Peak</div><div class="value">${fsMax.toFixed(0)}%</div></article>
    </div>
    <div class="next-panels">
      <section class="next-panel">
        <h3>Host Basis</h3>
        <table class="next-table">
          <tbody>
            <tr><th>Hostname</th><td>${escapeHtml(asText(state.currentReport?.hostname, state.selectedHost))}</td></tr>
            <tr><th>IP</th><td>${escapeHtml(asText(state.currentReport?.primary_ip, "-"))}</td></tr>
            <tr><th>OS</th><td>${escapeHtml(asText(payload?.os, "-"))}</td></tr>
            <tr><th>Agent Version</th><td>${escapeHtml(asText(payload?.agent_version, "-"))}</td></tr>
            <tr><th>Report Zeit</th><td>${escapeHtml(shortTime(state.currentReport?.received_at_utc))}</td></tr>
          </tbody>
        </table>
      </section>
      <section class="next-panel">
        <h3>Journaleintrag Vorschau</h3>
        <p class="next-muted">${escapeHtml(renderJournalPreview(payload))}</p>
      </section>
    </div>
  `;
}

function renderJournalPreview(payload) {
  const entries = Array.isArray(payload?.journal_errors) ? payload.journal_errors : [];
  if (entries.length === 0) return "Keine aktuellen Journal Fehler/Warnungen.";
  return String(entries[0] || "-");
}

function renderDatabases() {
  const payload = getPayload();
  const sqlInfo = payload?.sql_server_info && typeof payload.sql_server_info === "object" ? payload.sql_server_info : {};
  const sqlInstances = Array.isArray(sqlInfo.instances) ? sqlInfo.instances : [];
  const hanaInfo = payload?.hana_db_info && typeof payload.hana_db_info === "object" ? payload.hana_db_info : {};
  const hanaSchemas = Array.isArray(hanaInfo.schemas) ? hanaInfo.schemas : [];
  const lifecycle = Array.isArray(state.dbLifecycle?.items) ? state.dbLifecycle.items : [];

  return `
    <div class="next-panels">
      <section class="next-panel">
        <h3>SQL / HANA Instanzen</h3>
        <table class="next-table">
          <thead><tr><th>Typ</th><th>Name</th><th>Version</th></tr></thead>
          <tbody>
            ${sqlInstances.map((instance) => `<tr><td>SQL</td><td>${escapeHtml(asText(instance?.name, "MSSQLSERVER"))}</td><td>${escapeHtml(asText(instance?.version, "-"))}</td></tr>`).join("") || "<tr><td colspan=\"3\">Keine SQL Instanzen</td></tr>"}
            <tr><td>HANA</td><td>${escapeHtml(asText(hanaInfo?.sid, "-"))}</td><td>${escapeHtml(asText(hanaInfo?.version, "-"))}</td></tr>
          </tbody>
        </table>
        <h3 style="margin-top:10px;">HANA Schemas</h3>
        <table class="next-table">
          <thead><tr><th>Schema</th><th>Status</th></tr></thead>
          <tbody>
            ${hanaSchemas.slice(0, 12).map((schema) => {
              const name = typeof schema === "object" ? asText(schema?.name || schema?.schema || schema?.schema_name, "-") : asText(schema, "-");
              return `<tr><td>${escapeHtml(name)}</td><td>aktiv</td></tr>`;
            }).join("") || "<tr><td colspan=\"2\">Keine Schema-Daten</td></tr>"}
          </tbody>
        </table>
      </section>
      <section class="next-panel">
        <h3>DB Changelog Verlauf</h3>
        <table class="next-table">
          <thead><tr><th>Zeit</th><th>DB</th><th>Aktion</th><th>Grund</th></tr></thead>
          <tbody>
            ${lifecycle.slice(0, 14).map((item) => `<tr><td>${escapeHtml(shortTime(item?.triggered_at_utc))}</td><td>${escapeHtml(asText(item?.database_name, "-"))}</td><td>${escapeHtml(asText(item?.action, "-"))}</td><td>${escapeHtml(asText(item?.reason, "-"))}</td></tr>`).join("") || "<tr><td colspan=\"4\">Keine Lifecycle-Eintraege</td></tr>"}
          </tbody>
        </table>
      </section>
    </div>
  `;
}

function renderSapB1() {
  const payload = getPayload();
  const sap = payload?.sap_b1_systeminfo && typeof payload.sap_b1_systeminfo === "object"
    ? payload.sap_b1_systeminfo
    : payload?.sap_b1 && typeof payload.sap_b1 === "object"
      ? payload.sap_b1
      : {};

  const components = Array.isArray(sap?.server_components_version) ? sap.server_components_version : [];
  const addons = Array.isArray(sap?.addons) ? sap.addons : [];

  return `
    <div class="next-grid-4">
      <article class="next-stat"><div class="label">Feature Pack</div><div class="value">${escapeHtml(asText(sap?.feature_pack || sap?.release || "-"))}</div></article>
      <article class="next-stat"><div class="label">Patch Level</div><div class="value">${escapeHtml(asText(sap?.patch_level || "-"))}</div></article>
      <article class="next-stat"><div class="label">Build</div><div class="value">${escapeHtml(asText(sap?.version || sap?.build || "-"))}</div></article>
      <article class="next-stat"><div class="label">AddOns</div><div class="value">${addons.length}</div></article>
    </div>
    <div class="next-panels">
      <section class="next-panel">
        <h3>Server Components</h3>
        <table class="next-table">
          <thead><tr><th>Komponente</th><th>Version</th></tr></thead>
          <tbody>
            ${components.map((entry) => {
              if (typeof entry === "string") {
                return `<tr><td colspan=\"2\">${escapeHtml(entry)}</td></tr>`;
              }
              return `<tr><td>${escapeHtml(asText(entry?.name, "-"))}</td><td>${escapeHtml(asText(entry?.version, "-"))}</td></tr>`;
            }).join("") || "<tr><td colspan=\"2\">Keine Component-Daten</td></tr>"}
          </tbody>
        </table>
      </section>
      <section class="next-panel">
        <h3>AddOn Status</h3>
        <table class="next-table">
          <thead><tr><th>AddOn</th><th>Version</th><th>Status</th></tr></thead>
          <tbody>
            ${addons.slice(0, 20).map((entry) => `<tr><td>${escapeHtml(asText(entry?.name, "-"))}</td><td>${escapeHtml(asText(entry?.version, "-"))}</td><td>${escapeHtml(asText(entry?.status, "enabled"))}</td></tr>`).join("") || "<tr><td colspan=\"3\">Keine AddOn-Daten</td></tr>"}
          </tbody>
        </table>
      </section>
    </div>
  `;
}

function renderFilesystems() {
  const payload = getPayload();
  const filesystems = Array.isArray(payload?.filesystems) ? [...payload.filesystems] : [];
  filesystems.sort((a, b) => asNum(b?.used_percent, 0) - asNum(a?.used_percent, 0));
  const trends = Array.isArray(state.analysis?.filesystem_trends) ? state.analysis.filesystem_trends : [];

  return `
    <div class="next-panels">
      <section class="next-panel">
        <h3>Mountpoints (aktuell)</h3>
        <table class="next-table">
          <thead><tr><th>Mount</th><th>Used</th><th>Total</th></tr></thead>
          <tbody>
            ${filesystems.slice(0, 30).map((fs) => `<tr><td>${escapeHtml(asText(fs?.mountpoint, "-"))}</td><td>${asNum(fs?.used_percent, 0).toFixed(1)}%</td><td>${escapeHtml(asText(fs?.size_human || fs?.total_human || "-"))}</td></tr>`).join("") || "<tr><td colspan=\"3\">Keine Filesystem-Daten</td></tr>"}
          </tbody>
        </table>
      </section>
      <section class="next-panel">
        <h3>Trends (${asText(state.analysis?.window_hours, "24")}h)</h3>
        <table class="next-table">
          <thead><tr><th>Mount</th><th>Aktuell</th><th>Delta</th><th>Samples</th></tr></thead>
          <tbody>
            ${trends.slice(0, 20).map((t) => `<tr><td>${escapeHtml(asText(t?.mountpoint, "-"))}</td><td>${asNum(t?.current_used_percent, 0).toFixed(1)}%</td><td>${asNum(t?.delta_used_percent, 0).toFixed(1)}%</td><td>${asNum(t?.sample_count, 0)}</td></tr>`).join("") || "<tr><td colspan=\"4\">Keine Trend-Daten</td></tr>"}
          </tbody>
        </table>
      </section>
    </div>
  `;
}

function renderDetail() {
  const body = document.getElementById("nextDetailBody");
  const title = document.getElementById("nextHostTitle");
  const meta = document.getElementById("nextHostMeta");
  const pos = document.getElementById("nextReportPos");
  if (!body || !title || !meta || !pos) return;

  const selected = state.hosts.find((h) => h.hostname === state.selectedHost);
  const report = state.currentReport;

  title.textContent = selected?.display_name || state.selectedHost || "Kein Host";
  meta.textContent = `${selected?.hostname || "-"} · ${selected?.customer_name || "Ohne Kunde"} · letzte Meldung ${shortTime(report?.received_at_utc)}`;
  pos.textContent = `Report ${state.totalReports > 0 ? state.reportOffset + 1 : 0}/${state.totalReports}`;

  if (!report) {
    body.innerHTML = '<p class="next-muted">Keine Report-Daten fuer diesen Host.</p>';
    return;
  }

  if (state.activeTab === "databases") {
    body.innerHTML = renderDatabases();
    return;
  }
  if (state.activeTab === "sap") {
    body.innerHTML = renderSapB1();
    return;
  }
  if (state.activeTab === "filesystems") {
    body.innerHTML = renderFilesystems();
    return;
  }

  body.innerHTML = renderOverview();
}

async function loadKpis() {
  const [alerts, trends, inactive, hosts] = await Promise.all([
    apiGet("/api/v1/alerts-summary"),
    apiGet("/api/v1/critical-trends?hours=24&project_hours=24"),
    apiGet("/api/v1/inactive-hosts?hours=1"),
    apiGet("/api/v1/hosts?limit=500&offset=0"),
  ]);

  const totalHosts = asNum(hosts?.total_hosts, Array.isArray(hosts?.hosts) ? hosts.hosts.length : 0);
  const hostList = Array.isArray(hosts?.hosts) ? hosts.hosts : [];
  const healthy = hostList.filter((h) => asNum(h?.open_alert_count, 0) <= 0).length;

  document.getElementById("kpiAlerts").textContent = String(asNum(alerts?.open?.total, 0));
  document.getElementById("kpiAlertsSub").textContent = `${asNum(alerts?.open?.critical, 0)} kritisch / ${asNum(alerts?.open?.warning, 0)} warning`;

  document.getElementById("kpiTrends").textContent = String(asNum(trends?.total, 0));
  document.getElementById("kpiTrendsSub").textContent = "24h Projektion aktiv";

  document.getElementById("kpiInactive").textContent = String(asNum(inactive?.total, 0));
  document.getElementById("kpiInactiveSub").textContent = "Schwelle 1h";

  document.getElementById("kpiHealthy").textContent = String(healthy);
  document.getElementById("kpiHealthySub").textContent = `von ${totalHosts} total`;
}

async function loadHosts() {
  const data = await apiGet("/api/v1/hosts?limit=500&offset=0");
  state.hosts = Array.isArray(data?.hosts) ? data.hosts : [];

  if (!state.selectedHost && state.hosts.length > 0) {
    state.selectedHost = state.hosts[0].hostname;
  }

  renderCountryFilter();
  renderHosts();
}

async function loadSapB1VersionMap() {
  try {
    const data = await apiGet("/api/v1/sap-b1-version-map");
    const entries = Array.isArray(data?.entries) ? data.entries : [];
    state.sapVersionMap = new Map(
      entries
        .map((entry) => {
          const build = String(entry?.build || "").trim();
          if (!build) return null;
          return [build, { featurePack: String(entry?.feature_pack || "").trim() }];
        })
        .filter(Boolean)
    );
  } catch (error) {
    state.sapVersionMap = new Map();
  }
}

async function loadSelectedHostData() {
  if (!state.selectedHost) {
    state.currentReport = null;
    renderDetail();
    return;
  }

  const host = encodeURIComponent(state.selectedHost);
  const reports = await apiGet(`/api/v1/host-reports?hostname=${host}&limit=1&offset=${state.reportOffset}`);
  state.totalReports = asNum(reports?.total_reports, 0);
  state.currentReport = Array.isArray(reports?.reports) && reports.reports.length > 0 ? reports.reports[0] : null;

  if (!state.currentReport && state.reportOffset > 0) {
    state.reportOffset = 0;
    await loadSelectedHostData();
    return;
  }

  const [analysis, dbLifecycle] = await Promise.all([
    apiGet(`/api/v1/analysis?hostname=${host}&hours=24`).catch(() => ({})),
    apiGet(`/api/v1/database-lifecycle?hostname=${host}&limit=100&offset=0`).catch(() => ({})),
  ]);

  state.analysis = analysis;
  state.dbLifecycle = dbLifecycle;
  renderDetail();
}

async function loadVersion() {
  try {
    const response = await fetch("/BUILD_VERSION", { cache: "no-store" });
    if (!response.ok) return;
    const version = (await response.text()).trim();
    const el = document.getElementById("nextVersion");
    if (el) el.textContent = version;
  } catch (error) {
    // ignore
  }
}

async function init() {
  wireTopButtons();
  wireLegacyShortcuts();
  wireFilters();
  wirePaging();
  wireTabs();
  await loadVersion();

  let session;
  try {
    session = await apiGet("/api/v1/session");
  } catch (error) {
    session = { authenticated: false };
  }

  const app = document.getElementById("nextApp");
  const gate = document.getElementById("nextLoginGate");
  const userBadge = document.getElementById("nextUserBadge");
  const logoutBtn = document.getElementById("nextLogoutButton");

  if (!session?.authenticated) {
    gate?.classList.remove("hidden");
    app?.classList.add("hidden");
    return;
  }

  gate?.classList.add("hidden");
  app?.classList.remove("hidden");

  userBadge.textContent = session.display_name || session.username || "User";
  userBadge.classList.remove("hidden");
  logoutBtn.classList.remove("hidden");

  await loadKpis();
  await loadOwnHosts();
  await loadSapB1VersionMap();
  await loadHosts();
  await loadSelectedHostData();
}

window.addEventListener("DOMContentLoaded", () => {
  init().catch((error) => {
    const body = document.getElementById("nextDetailBody");
    if (body) {
      body.innerHTML = `<p class="next-muted">Fehler beim Laden der Parallel UI: ${escapeHtml(String(error?.message || error))}</p>`;
    }
  });
});
