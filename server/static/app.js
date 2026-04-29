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
  viewMode: "overview",
  overviewSection: "alerts",
  reportLimit: 1,
  reportOffset: 0,
  totalReports: 0,
  analysisHours: 24,
};

function updateViewMode() {
  const overviewView = document.getElementById("overviewView");
  const reportsView = document.getElementById("reportsView");
  const overviewTabButton = document.getElementById("overviewTabButton");
  const reportsTabButton = document.getElementById("reportsTabButton");

  const overviewActive = state.viewMode === "overview";
  overviewView.classList.toggle("hidden", !overviewActive);
  reportsView.classList.toggle("hidden", overviewActive);
  overviewTabButton.classList.toggle("active", overviewActive);
  reportsTabButton.classList.toggle("active", !overviewActive);
}

function updateOverviewSection() {
  const alertsSection = document.getElementById("overviewAlertsSection");
  const analysisSection = document.getElementById("overviewAnalysisSection");
  const filesystemSection = document.getElementById("overviewFilesystemSection");
  const alertsTabButton = document.getElementById("overviewAlertsTabButton");
  const analysisTabButton = document.getElementById("overviewAnalysisTabButton");
  const filesystemTabButton = document.getElementById("overviewFilesystemTabButton");

  if (!alertsSection || !analysisSection || !filesystemSection || !alertsTabButton || !analysisTabButton || !filesystemTabButton) {
    return;
  }

  const showAlerts = state.overviewSection === "alerts";
  const showAnalysis = state.overviewSection === "analysis";
  const showFilesystem = state.overviewSection === "filesystem";

  alertsSection.classList.toggle("hidden", !showAlerts);
  analysisSection.classList.toggle("hidden", !showAnalysis);
  filesystemSection.classList.toggle("hidden", !showFilesystem);

  alertsTabButton.classList.toggle("active", showAlerts);
  analysisTabButton.classList.toggle("active", showAnalysis);
  filesystemTabButton.classList.toggle("active", showFilesystem);
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

function renderFilesystemTrendCharts(filesystemTrends, latestReportTimeUtc) {
  if (!Array.isArray(filesystemTrends) || filesystemTrends.length === 0) {
    return "<p class=\"muted\">Keine Filesystem-Verlaufskurven verfuegbar.</p>";
  }

  const topTrends = filesystemTrends.slice(0, 6);
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
        <p><strong>📬 Delivery</strong><span>${chipText}${payload.queued_at_utc ? ` | queued ${escapeHtml(formatUtcPlus2(payload.queued_at_utc))}` : ""}</span></p>
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

  hostsPrevButton.disabled = state.hostOffset <= 0;
  hostsNextButton.disabled = state.hostOffset + state.hostLimit >= state.totalHosts;

  reportsPrevButton.disabled = state.reportOffset <= 0 || !state.selectedHost;
  reportsNextButton.disabled =
    !state.selectedHost || state.reportOffset + state.reportLimit >= state.totalReports;
}

function renderHosts(hosts) {
  const hostList = document.getElementById("hostList");
  const hostCount = document.getElementById("hostCount");

  hostCount.textContent = `${state.totalHosts} Hosts gesamt`;

  if (!Array.isArray(hosts) || hosts.length === 0) {
    hostList.innerHTML = "<p class=\"muted\">Keine Hosts vorhanden.</p>";
    return;
  }

  hostList.innerHTML = hosts
    .map((host) => {
      const hostname = asText(host.hostname);
      const displayName = asText(host.display_name || host.hostname);
      const selectedClass = hostname === state.selectedHost ? "host-item selected" : "host-item";
      const hostDelivery = deliveryLabel(host.delivery_mode, host.is_delayed);
      const hostQueueDepth = queueDepthLabel(host.queue_depth);

      return `
        <button class="${selectedClass}" type="button" data-host="${escapeHtml(hostname)}">
          <strong>${escapeHtml(displayName)}</strong>
          <span>🖥️ ${escapeHtml(hostname)}</span>
          <span>🧷 ${escapeHtml(asText(host.agent_version))}</span>
          <span>🌐 ${escapeHtml(asText(host.primary_ip))}</span>
          <span>📬 ${hostDelivery} | 🗃️ Queue ${hostQueueDepth}</span>
          <span>📦 ${Number(host.report_count || 0).toLocaleString("de-DE")} Meldungen</span>
          <span>🕒 Transfer: ${escapeHtml(formatUtcPlus2(host.last_seen_utc))}</span>
        </button>
      `;
    })
    .join("");

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
  }
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

    if (!state.selectedHost && hosts.length > 0) {
      state.selectedHost = String(hosts[0].hostname || "");
      state.selectedDisplayName = String(hosts[0].display_name || hosts[0].hostname || "");
      state.reportOffset = 0;
    }

    const selectedStillVisible = hosts.some((host) => String(host.hostname || "") === state.selectedHost);
    if (!selectedStillVisible && hosts.length > 0) {
      state.selectedHost = String(hosts[0].hostname || "");
      state.selectedDisplayName = String(hosts[0].display_name || hosts[0].hostname || "");
      state.reportOffset = 0;
    }

    const selectedHost = hosts.find((host) => String(host.hostname || "") === state.selectedHost);
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

  const response = await fetch("/api/v1/host-settings", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      hostname: state.selectedHost,
      display_name_override: nextValue.trim(),
    }),
  });

  if (!response.ok) {
    throw new Error("HTTP " + response.status);
  }

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
    filesystemStats.textContent = `Top ${Math.min(6, trendRows.length)} FS-Charts | Avg aktuell: ${fsAvgCurrent === null ? "-" : formatNumber(fsAvgCurrent, 1) + "%"} | Steigend: ${fsRising} | >=80%: ${fsWarnOrCritical}`;

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
      fetch(`/api/v1/alerts?hostname=${hostNameParam}&status=all&limit=15&offset=0`),
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

function wireEvents() {
  document.getElementById("overviewTabButton").addEventListener("click", () => {
    state.viewMode = "overview";
    updateViewMode();
  });

  document.getElementById("reportsTabButton").addEventListener("click", () => {
    state.viewMode = "reports";
    updateViewMode();
  });

  document.getElementById("overviewAlertsTabButton").addEventListener("click", () => {
    state.overviewSection = "alerts";
    updateOverviewSection();
  });

  document.getElementById("overviewAnalysisTabButton").addEventListener("click", () => {
    state.overviewSection = "analysis";
    updateOverviewSection();
  });

  document.getElementById("overviewFilesystemTabButton").addEventListener("click", () => {
    state.overviewSection = "filesystem";
    updateOverviewSection();
  });

  document.getElementById("editDisplayNameButton").addEventListener("click", async () => {
    try {
      await editDisplayName();
    } catch (error) {
      window.alert(`Titel konnte nicht gespeichert werden: ${error.message}`);
    }
  });

  document.getElementById("refreshButton").addEventListener("click", async () => {
    await loadHosts();
    await loadReportsForHost();
    await loadAnalysisForHost();
    await loadAlertsForHost();
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

  document.getElementById("reportsPrevButton").addEventListener("click", async () => {
    if (state.reportOffset <= 0) {
      return;
    }
    state.reportOffset = Math.max(0, state.reportOffset - state.reportLimit);
    await loadReportsForHost();
    await loadAnalysisForHost();
    await loadAlertsForHost();
  });

  document.getElementById("reportsNextButton").addEventListener("click", async () => {
    if (state.reportOffset + state.reportLimit >= state.totalReports) {
      return;
    }
    state.reportOffset += state.reportLimit;
    await loadReportsForHost();
    await loadAnalysisForHost();
    await loadAlertsForHost();
  });
}

async function init() {
  wireEvents();
  updateViewMode();
  updateOverviewSection();
  await loadHosts();
  await loadReportsForHost();
  await loadAnalysisForHost();
  await loadAlertsForHost();
}

init();
