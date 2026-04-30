function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

const state = {
  hostLimit: 20,
  hostOffset: 0,
  totalHosts: 0,
  selectedHost: "",
  selectedDisplayName: "",
  hostSearchQuery: "",
  viewMode: "overview",
  overviewSection: "main",
  reportLimit: 1,
  reportOffset: 0,
  totalReports: 0,
  analysisHours: 24,
  alarmSettingsLoaded: false,
  globalAlertsCollapsed: false,
  hostAlertsCollapsed: false,
  globalSeverityFilter: "all",
  globalOpenAlertsCount: 0,
  authUser: "",
  isAuthenticated: false,
  visibleHosts: 0,
  hiddenHosts: 0,
};

async function loadWebclientVersion() {
  const versionEl = document.getElementById("webclientVersion");
  if (!versionEl) {
    return;
  }

  try {
    const response = await fetch("BUILD_VERSION", {
      cache: "no-store",
      credentials: "same-origin",
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}`);
    }
    const text = (await response.text()).trim();
    versionEl.textContent = text || "-";
  } catch (_error) {
    versionEl.textContent = "-";
  }
}

function updateViewMode() {
  const overviewView = document.getElementById("overviewView");
  const reportsView = document.getElementById("reportsView");
  const globalAlertsView = document.getElementById("globalAlertsView");
  const overviewTabButton = document.getElementById("overviewTabButton");
  const globalAlertsTabButton = document.getElementById("globalAlertsTabButton");
  const reportsTabButton = document.getElementById("reportsTabButton");

  const overviewActive = state.viewMode === "overview";
  const reportsActive = state.viewMode === "reports";
  const globalAlertsActive = state.viewMode === "global-alerts";

  overviewView.classList.toggle("hidden", !overviewActive);
  reportsView.classList.toggle("hidden", !reportsActive);
  globalAlertsView.classList.toggle("hidden", !globalAlertsActive);
  overviewTabButton.classList.toggle("active", overviewActive);
  globalAlertsTabButton.classList.toggle("active", globalAlertsActive);
  reportsTabButton.classList.toggle("active", reportsActive);
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
}

function toggleAlarmSettingsPanel(show) {
  const panel = document.getElementById("alarmSettingsPanel");
  if (!panel) {
    return;
  }
  panel.classList.toggle("hidden", !show);
}

function setAlarmSettingsStatus(message, isError = false) {
  const statusEl = document.getElementById("alarmSettingsStatus");
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
  loginOverlay.classList.toggle("hidden", authenticated);
  appPanel.classList.toggle("hidden", !authenticated);
  state.isAuthenticated = authenticated;
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
  setLoginStatus("Anmeldung erfolgreich.");
  setAuthUiState(true);
  passwordInput.value = "";
  return true;
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

function buildPolylinePoints(series, width, height, minValue, maxValue) {
  if (!Array.isArray(series) || series.length < 2) {
    return "";
  }

  const pad = 8;
  const chartWidth = Math.max(1, width - pad * 2);
  const chartHeight = Math.max(1, height - pad * 2);
  const range = maxValue - minValue;
  const safeRange = range === 0 ? 1 : range;

  return series
    .map((point, index) => {
      const x = pad + (index / (series.length - 1)) * chartWidth;
      const normalized = (point.value - minValue) / safeRange;
      const y = pad + (1 - normalized) * chartHeight;
      return `${x.toFixed(2)},${y.toFixed(2)}`;
    })
    .join(" ");
}

function buildPointMarkers(series, width, height, minValue, maxValue, color, label) {
  if (!Array.isArray(series) || series.length === 0) {
    return "";
  }

  const pad = 8;
  const chartWidth = Math.max(1, width - pad * 2);
  const chartHeight = Math.max(1, height - pad * 2);
  const range = maxValue - minValue;
  const safeRange = range === 0 ? 1 : range;
  const denominator = series.length > 1 ? series.length - 1 : 1;

  return series
    .map((point, index) => {
      const x = pad + (index / denominator) * chartWidth;
      const normalized = (point.value - minValue) / safeRange;
      const y = pad + (1 - normalized) * chartHeight;
      const pointTime = formatUtcPlus2(point.time_utc);
      const pointValue = Number(point.value);
      const valueText = Number.isFinite(pointValue) ? pointValue.toFixed(2) : "-";

      return `<circle class="chart-point" cx="${x.toFixed(2)}" cy="${y.toFixed(2)}" r="3.3" fill="${color}"><title>${escapeHtml(label)}: ${escapeHtml(valueText)} (${escapeHtml(pointTime)})</title></circle>`;
    })
    .join("");
}

function buildSparklineSvg(series, color, width = 320, height = 82) {
  const points = normalizeSeries(series);
  if (points.length === 0) {
    return "<p class=\"muted\">Keine Verlaufsdaten</p>";
  }

  if (points.length === 1) {
    const centerY = (height / 2).toFixed(2);
    const singleTime = formatUtcPlus2(points[0].time_utc);
    const singleValue = Number(points[0].value);
    const valueText = Number.isFinite(singleValue) ? singleValue.toFixed(2) : "-";
    return `<svg class=\"sparkline\" viewBox=\"0 0 ${width} ${height}\" role=\"img\" aria-label=\"Trend\"><line x1=\"8\" y1=\"${centerY}\" x2=\"${(width - 8).toFixed(2)}\" y2=\"${centerY}\" stroke=\"${color}\" stroke-width=\"2.2\" /><circle class=\"chart-point\" cx=\"${(width / 2).toFixed(2)}\" cy=\"${centerY}\" r=\"3.6\" fill=\"${color}\"><title>${escapeHtml(valueText)} (${escapeHtml(singleTime)})</title></circle></svg>`;
  }

  const values = points.map((point) => point.value);
  const minValue = Math.min(...values);
  const maxValue = Math.max(...values);
  const polyline = buildPolylinePoints(points, width, height, minValue, maxValue);
  const markers = buildPointMarkers(points, width, height, minValue, maxValue, color, "Wert");

  return `
    <svg class="sparkline" viewBox="0 0 ${width} ${height}" role="img" aria-label="Trend">
      <line x1="8" y1="${(height - 8).toFixed(2)}" x2="${(width - 8).toFixed(2)}" y2="${(height - 8).toFixed(2)}" stroke="#dde5ee" stroke-width="1" />
      <polyline fill="none" stroke="${color}" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" points="${polyline}" />
      ${markers}
    </svg>
  `;
}

function normalizeForCombined(series) {
  const points = normalizeSeries(series);
  if (points.length === 0) {
    return [];
  }

  const values = points.map((point) => point.value);
  const minValue = Math.min(...values);
  const maxValue = Math.max(...values);
  const range = maxValue - minValue;
  const safeRange = range === 0 ? 1 : range;

  return points.map((point) => ({
    time_utc: point.time_utc,
    value: ((point.value - minValue) / safeRange) * 100,
  }));
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

  const combinedWidth = 920;
  const combinedHeight = 250;
  const axisLeft = 12;
  const axisTop = 12;
  const axisBottom = combinedHeight - 12;
  const axisRight = combinedWidth - 12;
  const axisMid = Math.round((axisTop + axisBottom) / 2);

  const combinedLines = chartDefinitions
    .map((item) => {
      const normalized = normalizeForCombined(resourceSeries[item.key]);
      if (normalized.length < 2) {
        return "";
      }
      const polyline = buildPolylinePoints(normalized, combinedWidth, combinedHeight, 0, 100);
      const markers = buildPointMarkers(normalized, combinedWidth, combinedHeight, 0, 100, item.color, `${item.label} (norm.)`);
      return `<polyline fill=\"none\" stroke=\"${item.color}\" stroke-width=\"2.1\" stroke-linecap=\"round\" stroke-linejoin=\"round\" points=\"${polyline}\" />${markers}`;
    })
    .join("");

  const combinedLegend = chartDefinitions
    .map((item) => `<span><i style=\"background:${item.color}\"></i>${item.label}</span>`)
    .join("");

  const standText = formatUtcPlus2(latestReportTimeUtc);
  const miniCharts = chartDefinitions
    .map((item) => {
      const points = normalizeSeries(resourceSeries[item.key]);
      const values = points.map((point) => point.value);
      const minValue = values.length > 0 ? Math.min(...values) : null;
      const maxValue = values.length > 0 ? Math.max(...values) : null;
      return `
        <article class="mini-chart-card">
          <header>
            <strong>${item.label}</strong>
            <span>${points.length} Samples</span>
          </header>
          ${buildSparklineSvg(points, item.color, 420, 120)}
          <footer>
            <span>Min: ${minValue === null ? "-" : formatNumber(minValue, 2)}</span>
            <span>Max: ${maxValue === null ? "-" : formatNumber(maxValue, 2)}</span>
          </footer>
        </article>
      `;
    })
    .join("");

  return `
    <section class="resource-chart-layout">
    <section class="combined-chart combined-wide">
      <div class="combined-chart-head">
        <strong>Verlauf kombiniert (normalisiert)</strong>
        <span>${escapeHtml(standText)}</span>
      </div>
      <svg class="combined-chart-svg" viewBox="0 0 ${combinedWidth} ${combinedHeight}" role="img" aria-label="Kombinierter Verlauf">
        <line x1="${axisLeft}" y1="${axisTop}" x2="${axisLeft}" y2="${axisBottom}" stroke="#dbe5ef" stroke-width="1" />
        <line x1="${axisLeft}" y1="${axisBottom}" x2="${axisRight}" y2="${axisBottom}" stroke="#dbe5ef" stroke-width="1" />
        <line x1="${axisLeft}" y1="${axisMid}" x2="${axisRight}" y2="${axisMid}" stroke="#edf2f7" stroke-width="1" />
        ${combinedLines}
      </svg>
      <div class="combined-legend">${combinedLegend}</div>
    </section>
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
  if (mp === '/') return true;
  if (mp.startsWith('/usr/sap')) return true;
  if (mp === '/hana' || mp.startsWith('/hana/')) return true;
  if (mp.startsWith('/mnt/') || mp === '/mnt') return true;
  return false;
}

function renderFilesystemTrendCharts(filesystemTrends, latestReportTimeUtc) {
  if (!Array.isArray(filesystemTrends) || filesystemTrends.length === 0) {
    return "<p class=\"muted\">Keine Filesystem-Verlaufskurven verfuegbar.</p>";
  }

  const filtered = filesystemTrends.filter((item) => shouldShowFilesystemGraph(item.mountpoint));
  if (filtered.length === 0) {
    return "<p class=\"muted\">Keine relevanten Filesystem-Verlaufskurven verfuegbar.</p>";
  }
  const topTrends = filtered;
  const standText = formatUtcPlus2(latestReportTimeUtc);

  return topTrends
    .map((item) => {
      const points = normalizeSeries((item.series || []).map((point) => ({
        time_utc: point.time_utc,
        value: point.used_percent,
      })));
      const color = filesystemLineColor(item.current_used_percent);
      const mountpoint = renderPathCell(item.mountpoint, 42);

      return `
        <article class="fs-chart-card">
          <header>
            <strong>${mountpoint}</strong>
            <span>${Number(item.sample_count || 0).toLocaleString("de-DE")} Samples</span>
          </header>
          ${buildSparklineSvg(points, color, 520, 130)}
          <footer>
            <span>Aktuell: ${formatPercent(item.current_used_percent)}</span>
            <span>Delta: ${formatSignedPercent(item.delta_used_percent)}</span>
            <span>${escapeHtml(standText)}</span>
          </footer>
        </article>
      `;
    })
    .join("");
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

      <h4>🌐 Netzwerk</h4>
      ${renderNetworkTable(network)}

      <h4>💾 Filesysteme</h4>
      ${renderFilesystemTable(payload.filesystems)}
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

function filterAndSortHosts(hosts) {
  const query = state.hostSearchQuery.toLowerCase().trim();

  let filtered = hosts;
  if (query.length > 0) {
    filtered = hosts.filter((host) => {
      const displayName = (host.display_name || host.hostname || "").toLowerCase();
      const hostname = (host.hostname || "").toLowerCase();
      return displayName.includes(query) || hostname.includes(query);
    });
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
  const alertChip = hasOpenAlerts ? `<span class="${chipClass}">Alerts ${openAlertCount}</span>` : "";

  const osRaw = asText(host.os || "").toLowerCase();
  const iconName = osRaw.includes("windows") ? "windows.png" : "linux.png";
  const osLabel = osRaw.includes("windows") ? "Windows" : "Linux";
  const osIcon = `<img src="icons/${iconName}" class="host-os-icon" alt="${osLabel}" title="${escapeHtml(asText(host.os))}" onerror="if(!this.dataset.fallback){this.dataset.fallback='1';this.src='/icons/${iconName}';}">`;

  return `
    <article class="${selectedClass}${hiddenClass}" tabindex="0" role="button" data-host="${escapeHtml(hostname)}">
      <strong class="host-title-line">
        <span>${escapeHtml(displayName)}</span>
        <span class="host-title-actions">
          ${alertChip}
          <button class="host-mini-action favorite${isFavorite ? " active" : ""}" type="button" data-action="favorite" data-host="${escapeHtml(hostname)}" data-current="${isFavorite ? "1" : "0"}" title="Favorit umschalten">★</button>
          <button class="host-mini-action visibility${isHidden ? " active" : ""}" type="button" data-action="hidden" data-host="${escapeHtml(hostname)}" data-current="${isHidden ? "1" : "0"}" title="${isHidden ? "Einblenden" : "Ausblenden"}">${isHidden ? "👁️" : "🙈"}</button>
        </span>
      </strong>
      <span>🖥️ ${escapeHtml(hostname)}</span>
      <span>🧷 ${escapeHtml(asText(host.agent_version))}</span>
      <span>🌐 ${escapeHtml(asText(host.primary_ip))}</span>
      <span>📬 ${hostDelivery} | 🗃️ Queue ${hostQueueDepth}</span>
      <span>🚨 Offen: ${openAlertCount} (kritisch ${openCriticalAlertCount})</span>
      <span>📦 ${Number(host.report_count || 0).toLocaleString("de-DE")} Meldungen</span>
      <span>🕒 Transfer: ${escapeHtml(formatUtcPlus2(host.last_seen_utc))}</span>
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
      loadHosts();
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
}

function renderHosts(hosts) {
  const hostList = document.getElementById("hostList");
  const hostCount = document.getElementById("hostCount");

  if (!Array.isArray(hosts) || hosts.length === 0) {
    hostCount.textContent = "0 Hosts gesamt";
    hostList.innerHTML = "<p class=\"muted\">Keine Hosts vorhanden.</p>";
    return;
  }

  const { visibleHosts, hiddenHosts } = splitHosts(hosts);
  hostCount.textContent = `${state.totalHosts} Hosts gesamt | aktiv ${visibleHosts.length} | ausgeblendet ${hiddenHosts.length}`;

  if (visibleHosts.length === 0 && hiddenHosts.length === 0) {
    hostList.innerHTML = "<p class=\"muted\">Keine Hosts passen zum Suchfilter.</p>";
    return;
  }

  const visibleHtml = visibleHosts.map(renderSingleHostCard).join("");
  const hiddenHtml = hiddenHosts.map(renderSingleHostCard).join("");

  hostList.innerHTML = `
    <section class="host-group">
      <h4 class="host-group-title">Aktive Hosts (${visibleHosts.length})</h4>
      ${visibleHtml || '<p class="muted">Keine aktiven Hosts im Suchfilter.</p>'}
    </section>
    <section class="host-group host-group-hidden">
      <h4 class="host-group-title">Ausgeblendete Hosts (${hiddenHosts.length})</h4>
      ${hiddenHtml || '<p class="muted">Keine ausgeblendeten Hosts.</p>'}
    </section>
  `;

  wireHostListInteractions();
}

async function loadHosts() {
  const hostList = document.getElementById("hostList");
  hostList.innerHTML = "<p class=\"muted\">Lade Host-Liste...</p>";

  try {
    const url = `/api/v1/hosts?limit=${state.hostLimit}&offset=${state.hostOffset}`;
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error("HTTP " + response.status);
    }

    const data = await response.json();
    state.totalHosts = Number(data.total_hosts || 0);
    const hosts = data.hosts || [];
    const { visibleHosts, hiddenHosts } = splitHosts(hosts);
    state.visibleHosts = Number(data.visible_hosts || visibleHosts.length || 0);
    state.hiddenHosts = Number(data.hidden_hosts || hiddenHosts.length || 0);
    const orderedHosts = [...visibleHosts, ...hiddenHosts];

    if (!state.selectedHost && orderedHosts.length > 0) {
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
    selectedHostTitle.textContent = "🗂️ Meldungen";
    count.textContent = "";
    list.innerHTML = "<p class=\"muted\">Kein Host ausgewaehlt.</p>";
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
      list.innerHTML = "<p class=\"muted\">Noch keine Daten vorhanden.</p>";
      count.textContent = `0 von ${state.totalReports} Meldungen`;
      updatePagerButtons();
      return;
    }

    const shownIndex = state.reportOffset + 1;
    count.textContent = `Meldung ${shownIndex} von ${state.totalReports}`;
    state.selectedDisplayName = String(reports[0].display_name || reports[0].hostname || state.selectedHost);
    selectedHostTitle.textContent = `🗂️ Meldungen fuer ${state.selectedDisplayName}`;
    list.innerHTML = renderReportCard(reports[0]);
    updatePagerButtons();
  } catch (error) {
    list.innerHTML = `<p class=\"muted\">Fehler: ${escapeHtml(error.message)}</p>`;
  }
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

  await saveHostSettings(state.selectedHost, {
    display_name_override: nextValue.trim(),
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
    analysisRows.innerHTML = "<tr><td colspan=\"7\" class=\"muted\">Kein Host ausgewaehlt.</td></tr>";
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
    deliveryStats.textContent = `📬 Letzte Meldung: ${latestDelivery} | 🗃️ Queue: ${latestQueue} | Fenster: ${delayedCount} delayed / ${liveCount} live`;
    resourceCharts.innerHTML = renderResourceCharts(resourceSeries, data.latest_report_time_utc);
    resourceTrendCards.innerHTML = renderResourceTrendCards(resourceTrends, data.latest_report_time_utc);
    filesystemCharts.innerHTML = renderFilesystemTrendCharts(trendRows, data.latest_report_time_utc);

    const fsCurrentValues = trendRows.map((row) => Number(row.current_used_percent)).filter((value) => Number.isFinite(value));
    const fsAvgCurrent = fsCurrentValues.length > 0
      ? fsCurrentValues.reduce((sum, value) => sum + value, 0) / fsCurrentValues.length
      : null;
    const fsRising = trendRows.filter((row) => Number(row.delta_used_percent) > 0).length;
    const fsWarnOrCritical = trendRows.filter((row) => Number(row.current_used_percent) >= 80).length;
    filesystemStats.textContent = `${trendRows.length} FS-Charts | Avg aktuell: ${fsAvgCurrent === null ? "-" : formatNumber(fsAvgCurrent, 1) + "%"} | Steigend: ${fsRising} | >=80%: ${fsWarnOrCritical}`;

    if (trendRows.length === 0) {
      filesystemCharts.innerHTML = "<p class=\"muted\">Keine Filesystem-Verlaufskurven verfuegbar.</p>";
      analysisRows.innerHTML =
        "<tr><td colspan=\"7\" class=\"muted\">Keine Analyse-Daten im gewaehlten Zeitfenster.</td></tr>";
      return;
    }

    analysisRows.innerHTML = trendRows
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

async function loadAlertsForHost() {
  const alertsSummary = document.getElementById("alertsSummary");
  const alertsRows = document.getElementById("alertsRows");
  const toggleButton = document.getElementById("toggleHostAlertsPanelButton");
  const panelBody = document.getElementById("hostAlertsPanelBody");

  panelBody.classList.toggle("hidden", state.hostAlertsCollapsed);
  toggleButton.textContent = state.hostAlertsCollapsed ? "Aufklappen" : "Zuklappen";

  if (!state.selectedHost) {
    alertsSummary.textContent = "";
    alertsRows.innerHTML = "<tr><td colspan=\"5\" class=\"muted\">Kein Host ausgewaehlt.</td></tr>";
    return;
  }

  alertsRows.innerHTML = "<tr><td colspan=\"5\" class=\"muted\">Lade Alerts...</td></tr>";
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
      alertsRows.innerHTML = "<tr><td colspan=\"5\" class=\"muted\">Keine Alerts vorhanden.</td></tr>";
      return;
    }

    alertsRows.innerHTML = alerts
      .map((item) => {
        const statusClass = item.status === "open" ? "status-open" : "status-resolved";
        const severityClass = item.severity === "critical" ? "severity-critical" : "severity-warning";
        return `
          <tr>
            <td><span class="badge ${statusClass}">${escapeHtml(asText(item.status))}</span></td>
            <td><span class="badge ${severityClass}">${escapeHtml(asText(item.severity))}</span></td>
            <td>${renderPathCell(item.mountpoint, 48)}</td>
            <td>${formatPercent(item.used_percent)}</td>
            <td>${escapeHtml(formatUtcPlus2(item.last_seen_at_utc))}</td>
          </tr>
        `;
      })
      .join("");
  } catch (error) {
    alertsRows.innerHTML = `<tr><td colspan=\"5\" class=\"muted\">Fehler: ${escapeHtml(error.message)}</td></tr>`;
  }
}

async function loadGlobalAlertsOverview() {
  const summaryEl = document.getElementById("globalAlertsSummary");
  const rowsEl = document.getElementById("globalAlertsRows");
  const globalAlertsTabButton = document.getElementById("globalAlertsTabButton");
  const toggleButton = document.getElementById("toggleGlobalAlertsPanelButton");
  const panelBody = document.getElementById("globalAlertsPanelBody");

  rowsEl.innerHTML = "<tr><td colspan=\"5\" class=\"muted\">Lade globale Alerts...</td></tr>";
  summaryEl.textContent = "";
  panelBody.classList.toggle("hidden", state.globalAlertsCollapsed);
  toggleButton.textContent = state.globalAlertsCollapsed ? "Aufklappen" : "Zuklappen";

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

    const alerts = allOpenAlerts.filter((item) => {
      if (state.globalSeverityFilter === "all") {
        return true;
      }
      return String(item.severity || "") === state.globalSeverityFilter;
    });

    summaryEl.textContent = `Offen: ${summaryData.open.total} (kritisch ${summaryData.open.critical}, warn ${summaryData.open.warning}) | Filter: ${state.globalSeverityFilter === "all" ? "alle" : state.globalSeverityFilter}`;

    if (alerts.length === 0) {
      rowsEl.innerHTML = "<tr><td colspan=\"5\" class=\"muted\">Keine offenen Alerts fuer den gesetzten Filter.</td></tr>";
      return;
    }

    rowsEl.innerHTML = alerts
      .map((item) => {
        const severityClass = item.severity === "critical" ? "severity-critical" : "severity-warning";
        const hostDisplayName = asText(item.display_name || item.hostname);
        const hostName = asText(item.hostname);
        return `
          <tr>
            <td>
              <div class="global-host-cell">
                <span class="global-host-label">${escapeHtml(hostDisplayName)}</span>
                <span class="global-hostname-sub">(${escapeHtml(hostName)})</span>
              </div>
            </td>
            <td><span class="badge ${severityClass}">${escapeHtml(asText(item.severity))}</span></td>
            <td>${renderPathCell(item.mountpoint, 42)}</td>
            <td>${formatPercent(item.used_percent)}</td>
            <td>${escapeHtml(formatUtcPlus2(item.last_seen_at_utc))}</td>
          </tr>
        `;
      })
      .join("");
  } catch (error) {
    rowsEl.innerHTML = `<tr><td colspan="5" class="muted">Fehler: ${escapeHtml(error.message)}</td></tr>`;
    globalAlertsTabButton.textContent = "Globale Alerts";
    globalAlertsTabButton.classList.remove("alert-active");
  }
}

function wireEvents() {
  document.getElementById("overviewTabButton").addEventListener("click", () => {
    state.viewMode = "overview";
    updateViewMode();
  });

  document.getElementById("globalAlertsTabButton").addEventListener("click", async () => {
    state.viewMode = "global-alerts";
    updateViewMode();
    await loadGlobalAlertsOverview();
  });

  document.getElementById("reportsTabButton").addEventListener("click", () => {
    state.viewMode = "reports";
    updateViewMode();
  });

  document.getElementById("loginSubmitButton").addEventListener("click", async () => {
    const ok = await loginWebClient();
    if (!ok) {
      return;
    }
    await loadGlobalAlertsOverview();
    await loadHosts();
    await loadReportsForHost();
    await loadAnalysisForHost();
    await loadAlertsForHost();
  });

  document.getElementById("loginPasswordInput").addEventListener("keydown", async (event) => {
    if (event.key !== "Enter") {
      return;
    }
    const ok = await loginWebClient();
    if (!ok) {
      return;
    }
    await loadGlobalAlertsOverview();
    await loadHosts();
    await loadReportsForHost();
    await loadAnalysisForHost();
    await loadAlertsForHost();
  });

  document.getElementById("openChangePasswordButton").addEventListener("click", () => {
    document.getElementById("changePasswordModal").classList.remove("hidden");
    setPasswordChangeStatus("");
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

  document.getElementById("editDisplayNameButton").addEventListener("click", async () => {
    try {
      await editDisplayName();
    } catch (error) {
      window.alert(`Titel konnte nicht gespeichert werden: ${error.message}`);
    }
  });

  document.getElementById("refreshButton").addEventListener("click", async () => {
    await loadGlobalAlertsOverview();
    await loadHosts();
    await loadReportsForHost();
    await loadAnalysisForHost();
    await loadAlertsForHost();
  });

  document.getElementById("openAlarmSettingsButton").addEventListener("click", async () => {
    toggleAlarmSettingsPanel(true);
    await loadAlarmSettings(true);
  });

  document.getElementById("closeAlarmSettingsButton").addEventListener("click", () => {
    toggleAlarmSettingsPanel(false);
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

  document.getElementById("hostsPrevButton").addEventListener("click", async () => {
    if (state.hostOffset <= 0) {
      return;
    }
    state.hostOffset = Math.max(0, state.hostOffset - state.hostLimit);
    await loadHosts();
    await loadReportsForHost();
    await loadAnalysisForHost();
    await loadAlertsForHost();
  });

  document.getElementById("hostsNextButton").addEventListener("click", async () => {
    if (state.hostOffset + state.hostLimit >= state.totalHosts) {
      return;
    }
    state.hostOffset += state.hostLimit;
    await loadHosts();
    await loadReportsForHost();
    await loadAnalysisForHost();
    await loadAlertsForHost();
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
    await loadHosts();
  });
}

async function init() {
  await loadWebclientVersion();
  wireEvents();
  updateViewMode();
  updateOverviewSection();
  toggleAlarmSettingsPanel(false);
  document.getElementById("globalSeverityFilter").value = state.globalSeverityFilter;
  document.getElementById("loginUsernameInput").value = "admin";
  const isAuthenticated = await ensureAuthenticatedSession();
  if (!isAuthenticated) {
    setLoginStatus("Bitte anmelden, um den Webclient zu nutzen.");
    return;
  }
  await loadGlobalAlertsOverview();
  await loadHosts();
  await loadReportsForHost();
  await loadAnalysisForHost();
  await loadAlertsForHost();
}

init();
