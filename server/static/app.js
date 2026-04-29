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
          <span>🕒 Last seen: ${escapeHtml(formatUtcPlus2(host.last_seen_utc))}</span>
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
  const resourceTrendCards = document.getElementById("resourceTrendCards");
  const deliveryStats = document.getElementById("deliveryStats");

  if (!state.selectedHost) {
    analysisSummary.textContent = "";
    deliveryStats.textContent = "";
    resourceTrendCards.innerHTML = "";
    analysisRows.innerHTML = "<tr><td colspan=\"7\" class=\"muted\">Kein Host ausgewaehlt.</td></tr>";
    return;
  }

  analysisRows.innerHTML = "<tr><td colspan=\"7\" class=\"muted\">Lade Analyse...</td></tr>";
  resourceTrendCards.innerHTML = "";
  analysisSummary.textContent = "";
  deliveryStats.textContent = "";

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
    const delivery = data.delivery || {};
    const latestMax = formatPercent(data.latest_max_used_percent);
    const reportCount = Number(data.report_count || 0).toLocaleString("de-DE");
    const delayedCount = Number(delivery.delayed_report_count || 0).toLocaleString("de-DE");
    const liveCount = Number(delivery.live_report_count || 0).toLocaleString("de-DE");
    const latestDelivery = deliveryLabel(delivery.latest_mode, delivery.latest_is_delayed);
    const latestQueue = queueDepthLabel(delivery.latest_queue_depth);

    analysisSummary.textContent = `${reportCount} Reports, hoechste aktuelle FS-Auslastung: ${latestMax}`;
    deliveryStats.textContent = `📬 Letzte Meldung: ${latestDelivery} | 🗃️ Queue: ${latestQueue} | Fenster: ${delayedCount} delayed / ${liveCount} live`;
    resourceTrendCards.innerHTML = renderResourceTrendCards(resourceTrends, data.latest_report_time_utc);

    if (trendRows.length === 0) {
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
  await loadHosts();
  await loadReportsForHost();
  await loadAnalysisForHost();
  await loadAlertsForHost();
}

init();
