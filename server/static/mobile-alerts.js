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
      state.userDisplayName = resolveUserDisplayName(data);
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

function showAlertsHomeView() {
  state.mobileView = "alerts";
  document.getElementById("alertsHomeView")?.classList.remove("hidden");
  document.getElementById("inactiveHostsView")?.classList.add("hidden");
  document.getElementById("activeHostsView")?.classList.add("hidden");
  document.getElementById("kpiInactiveNav")?.classList.remove("is-active");
  document.getElementById("kpiActiveNav")?.classList.remove("is-active");
}

function showInactiveHostsView() {
  state.mobileView = "inactive-hosts";
  document.getElementById("alertsHomeView")?.classList.add("hidden");
  document.getElementById("activeHostsView")?.classList.add("hidden");
  document.getElementById("inactiveHostsView")?.classList.remove("hidden");
  document.getElementById("kpiInactiveNav")?.classList.add("is-active");
  document.getElementById("kpiActiveNav")?.classList.remove("is-active");
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
  document.getElementById("alertsHomeView")?.classList.add("hidden");
  document.getElementById("inactiveHostsView")?.classList.add("hidden");
  document.getElementById("activeHostsView")?.classList.remove("hidden");
  document.getElementById("kpiActiveNav")?.classList.add("is-active");
  document.getElementById("kpiInactiveNav")?.classList.remove("is-active");
  const subtitle = document.getElementById("activeHostsSubtitle");
  if (subtitle) {
    subtitle.textContent = "Meldung in der letzten Stunde";
  }
  void loadActiveHostsList();
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
  const osShort = truncateMobileText(String(host.os || "").trim() || "—", 28);
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
    '      <p class="host-list-host-label">' + mobileEsc(hostLabel) + "</p>" +
    '      <div class="host-list-meta-row">' +
    '        <span class="host-list-meta-pill">' + countryHtml + "<span>" + mobileEsc(countryCode) + "</span></span>" +
    '        <span class="host-list-meta-pill"><img src="/icons/' + mobileEsc(osIcon) + '" alt="" onerror="this.src=\'/icons/linux.png\'" /><span>'
    + mobileEsc(osShort) + "</span></span>" +
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
    '    <button type="button" class="btn-secondary btn-host-list-sheet" data-action="host-list-sheet" data-host-list="'
    + mobileEsc(variant) + '" data-host-index="' + index + '">Alle Details</button>' +
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

function handleHostListSheetClick(event) {
  const btn = event.target.closest('[data-action="host-list-sheet"]');
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
  openMobileHostListSheet(hosts[index], variant);
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
};

const SKELETON_CARD_COUNT = 4;
const FLOATING_LOGO_STORAGE_KEY = "monitoring.mobile.floatingLogo";
const FLOATING_LOGO_WIDTH_PX = 80;
const FLOATING_LOGO_HEIGHT_PX = 48;
const FLOATING_LOGO_MARGIN_PX = 12;
/** Gleiches Intervall wie Desktop: Session bleibt bei offener App aktiv (Server-Timeout default 30 min). */
const MOBILE_SESSION_REFRESH_INTERVAL_MS = 4 * 60 * 1000;
const MOBILE_SESSION_LOGIN_GRACE_MS = 20000;

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
  const label = state.userDisplayName || state.username;
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
    const hostname = mobileEsc(item.hostname || "-");
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
      '  <div class="alert-card-headsup">' + buildHeadsUpActionButton(item) + "</div>" +
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
    await refreshPushState();
    await refreshMobileData();
  } catch (error) {
    state.authenticated = false;
    showLoginOverlay(true);
    setLoginStatus(error?.message || "Login fehlgeschlagen", true);
  }
}

function readFloatingLogoPosition() {
  try {
    const raw = window.localStorage.getItem(FLOATING_LOGO_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    const left = Number(parsed?.left);
    const top = Number(parsed?.top);
    if (!Number.isFinite(left) || !Number.isFinite(top)) return null;
    return { left, top };
  } catch (_err) {
    return null;
  }
}

function saveFloatingLogoPosition(left, top) {
  try {
    window.localStorage.setItem(
      FLOATING_LOGO_STORAGE_KEY,
      JSON.stringify({ left: Math.round(left), top: Math.round(top) })
    );
  } catch (_err) {
    // Ignore storage failures.
  }
}

function defaultFloatingLogoPosition() {
  const safeBottom = parseFloat(
    getComputedStyle(document.documentElement).getPropertyValue("--safe-bottom") || "0"
  ) || 0;
  return {
    left: window.innerWidth - FLOATING_LOGO_WIDTH_PX - FLOATING_LOGO_MARGIN_PX,
    top: window.innerHeight - FLOATING_LOGO_HEIGHT_PX - FLOATING_LOGO_MARGIN_PX - safeBottom,
  };
}

function clampFloatingLogoPosition(left, top) {
  const maxLeft = Math.max(
    FLOATING_LOGO_MARGIN_PX,
    window.innerWidth - FLOATING_LOGO_WIDTH_PX - FLOATING_LOGO_MARGIN_PX
  );
  const maxTop = Math.max(
    FLOATING_LOGO_MARGIN_PX,
    window.innerHeight - FLOATING_LOGO_HEIGHT_PX - FLOATING_LOGO_MARGIN_PX
  );
  return {
    left: Math.min(maxLeft, Math.max(FLOATING_LOGO_MARGIN_PX, left)),
    top: Math.min(maxTop, Math.max(FLOATING_LOGO_MARGIN_PX, top)),
  };
}

function applyFloatingLogoPosition(el, left, top, persist) {
  const clamped = clampFloatingLogoPosition(left, top);
  el.style.left = clamped.left + "px";
  el.style.top = clamped.top + "px";
  el.style.right = "auto";
  el.style.bottom = "auto";
  if (persist) {
    saveFloatingLogoPosition(clamped.left, clamped.top);
  }
  return clamped;
}

function wireFloatingLogo() {
  const el = document.getElementById("mobileFloatingLogo");
  if (!el) return;

  const saved = readFloatingLogoPosition();
  const initial = saved || defaultFloatingLogoPosition();
  applyFloatingLogoPosition(el, initial.left, initial.top, false);

  let dragActive = false;
  let dragOffsetX = 0;
  let dragOffsetY = 0;

  const endDrag = (event) => {
    if (!dragActive) return;
    dragActive = false;
    el.classList.remove("is-dragging");
    if (event?.pointerId != null && el.hasPointerCapture(event.pointerId)) {
      el.releasePointerCapture(event.pointerId);
    }
    const rect = el.getBoundingClientRect();
    applyFloatingLogoPosition(el, rect.left, rect.top, true);
  };

  el.addEventListener("pointerdown", (event) => {
    if (event.button !== 0) return;
    dragActive = true;
    el.classList.add("is-dragging");
    const rect = el.getBoundingClientRect();
    dragOffsetX = event.clientX - rect.left;
    dragOffsetY = event.clientY - rect.top;
    el.setPointerCapture(event.pointerId);
    event.preventDefault();
  });

  el.addEventListener("pointermove", (event) => {
    if (!dragActive) return;
    applyFloatingLogoPosition(el, event.clientX - dragOffsetX, event.clientY - dragOffsetY, false);
    event.preventDefault();
  });

  el.addEventListener("pointerup", endDrag);
  el.addEventListener("pointercancel", endDrag);

  window.addEventListener("resize", () => {
    const rect = el.getBoundingClientRect();
    applyFloatingLogoPosition(el, rect.left, rect.top, true);
  });
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

function wire() {
  document.getElementById("kpiActiveNav")?.addEventListener("click", () => {
    if (!state.authenticated) return;
    showActiveHostsView();
  });

  document.getElementById("kpiInactiveNav")?.addEventListener("click", () => {
    if (!state.authenticated) return;
    showInactiveHostsView();
  });

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

  document.getElementById("refreshButton")?.addEventListener("click", () => {
    void refreshMobileData().catch((error) => {
      const msg = error?.message || String(error);
      if (isInactiveHostsViewActive()) {
        setInactiveHostsStatus("Fehler: " + msg, true);
      } else if (isActiveHostsViewActive()) {
        setActiveHostsStatus("Fehler: " + msg, true);
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

  document.getElementById("pushToggleButton")?.addEventListener("click", () => void togglePush());
  document.getElementById("testPushButton")?.addEventListener("click", () => void sendTestPush());

  document.getElementById("menuToggleButton")?.addEventListener("click", () => {
    document.getElementById("headerMenu")?.classList.toggle("hidden");
  });

  document.getElementById("mobileLogoutButton")?.addEventListener("click", async () => {
    await mobileLogout();
    mobileSessionEstablishedAtMs = 0;
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
  wireFloatingLogo();
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

async function init() {
  state.highlightAlertId = parseHighlightAlertId();
  wire();
  try {
    await ensureAuthenticated();
    if (state.authenticated) {
      mobileSessionEstablishedAtMs = Date.now();
      startMobileSessionKeepAlive();
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
