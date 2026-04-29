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
  reportLimit: 1,
  reportOffset: 0,
  totalReports: 0,
  analysisHours: 24,
};

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

function asText(value, fallback = "-") {
  if (value === null || value === undefined) {
    return fallback;
  }

  const text = String(value).trim();
  return text === "" ? fallback : text;
}

function formatUtc(value) {
  const text = asText(value);
  if (text === "-") {
    return text;
  }

  const parsed = new Date(text);
  if (Number.isNaN(parsed.getTime())) {
    return text;
  }

  return parsed.toLocaleString("de-DE", {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
    timeZone: "UTC",
    timeZoneName: "short",
  });
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
            <th>Mountpoint</th>
            <th>Filesystem</th>
            <th>Typ</th>
            <th>Belegt</th>
            <th>Used / Total (Blocks)</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `;
}

function renderReportCard(report) {
  const payload = report && report.payload ? report.payload : {};

  return `
    <article class="report-card">
      <div class="report-header">
        <h3>${escapeHtml(asText(report.hostname || payload.hostname))}</h3>
        <span class="report-time">${escapeHtml(formatUtc(report.received_at_utc || payload.timestamp_utc))}</span>
      </div>

      <div class="meta-grid">
        <p><strong>Agent ID</strong><span>${escapeHtml(asText(report.agent_id || payload.agent_id))}</span></p>
        <p><strong>Primary IP</strong><span>${escapeHtml(asText(report.primary_ip || payload.primary_ip))}</span></p>
        <p><strong>Alle IPs</strong><span>${escapeHtml(asText(payload.all_ips))}</span></p>
        <p><strong>OS</strong><span>${escapeHtml(asText(payload.os))}</span></p>
        <p><strong>Kernel</strong><span>${escapeHtml(asText(payload.kernel))}</span></p>
        <p><strong>Uptime</strong><span>${escapeHtml(formatUptime(payload.uptime_seconds))}</span></p>
      </div>

      <h4>Filesysteme</h4>
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
      const selectedClass = hostname === state.selectedHost ? "host-item selected" : "host-item";

      return `
        <button class="${selectedClass}" type="button" data-host="${escapeHtml(hostname)}">
          <strong>${escapeHtml(hostname)}</strong>
          <span>${escapeHtml(asText(host.primary_ip))}</span>
          <span>${Number(host.report_count || 0).toLocaleString("de-DE")} Meldungen</span>
          <span>Last seen: ${escapeHtml(formatUtc(host.last_seen_utc))}</span>
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
      state.reportOffset = 0;
    }

    const selectedStillVisible = hosts.some((host) => String(host.hostname || "") === state.selectedHost);
    if (!selectedStillVisible && hosts.length > 0) {
      state.selectedHost = String(hosts[0].hostname || "");
      state.reportOffset = 0;
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
    selectedHostTitle.textContent = "Meldungen";
    count.textContent = "";
    list.innerHTML = "<p class=\"muted\">Kein Host ausgewaehlt.</p>";
    updatePagerButtons();
    return;
  }

  selectedHostTitle.textContent = `Meldungen fuer ${state.selectedHost}`;
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
    list.innerHTML = renderReportCard(reports[0]);
    updatePagerButtons();
  } catch (error) {
    list.innerHTML = `<p class=\"muted\">Fehler: ${escapeHtml(error.message)}</p>`;
  }
}

async function loadAnalysisForHost() {
  const analysisSummary = document.getElementById("analysisSummary");
  const analysisRows = document.getElementById("analysisRows");

  if (!state.selectedHost) {
    analysisSummary.textContent = "";
    analysisRows.innerHTML = "<tr><td colspan=\"7\" class=\"muted\">Kein Host ausgewaehlt.</td></tr>";
    return;
  }

  analysisRows.innerHTML = "<tr><td colspan=\"7\" class=\"muted\">Lade Analyse...</td></tr>";
  analysisSummary.textContent = "";

  try {
    const hostNameParam = encodeURIComponent(state.selectedHost);
    const url = `/api/v1/analysis?hostname=${hostNameParam}&hours=${state.analysisHours}`;
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error("HTTP " + response.status);
    }

    const data = await response.json();
    const trendRows = data.filesystem_trends || [];
    const latestMax = formatPercent(data.latest_max_used_percent);
    const reportCount = Number(data.report_count || 0).toLocaleString("de-DE");

    analysisSummary.textContent = `${reportCount} Reports, hoechste aktuelle FS-Auslastung: ${latestMax}`;

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
            <td>${escapeHtml(formatUtc(item.last_seen_at_utc))}</td>
          </tr>
        `;
      })
      .join("");
  } catch (error) {
    alertsRows.innerHTML = `<tr><td colspan=\"5\" class=\"muted\">Fehler: ${escapeHtml(error.message)}</td></tr>`;
  }
}

function wireEvents() {
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
  await loadHosts();
  await loadReportsForHost();
  await loadAnalysisForHost();
  await loadAlertsForHost();
}

init();
