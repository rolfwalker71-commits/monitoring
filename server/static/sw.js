// Monitoring Dashboard – Service Worker
// Purpose: enables PWA installability; no offline caching of dynamic
// dashboard data (live sensor readings should never come from cache).

const CACHE_NAME = "monitoring-shell-v5";
const LIVE_DASHBOARD_TAG = "monitoring-live-dashboard";
const LIVE_REPORT_PUSH_TTL_MS = 5 * 60 * 1000;
const notificationCloseTimers = new Map();

function resolveAssetUrl(path) {
  const raw = String(path || "").trim();
  if (!raw) {
    return new URL("/icons/logo.png", self.location.origin).href;
  }
  try {
    return new URL(raw, self.location.origin).href;
  } catch (_err) {
    return raw;
  }
}

function normalizeNotificationBody(body, fallback = "Neues Monitoring-Ereignis") {
  const collapsed = String(body || "")
    .replace(/\r\n/g, "\n")
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .join(" · ");
  return collapsed || fallback;
}

function formatNotificationTimeLabel(date = new Date()) {
  return date.toLocaleTimeString("de-CH", { hour: "2-digit", minute: "2-digit" });
}

// Only static shell assets are cached so the app loads faster on re-open.
const SHELL_ASSETS = [
  "/",
  "/styles.css",
  "/app.js",
  "/manifest.json",
  "/icons/pwa-icon-192.png",
  "/icons/pwa-icon-512.png",
  "/icons/logo.png",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(SHELL_ASSETS))
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys
          .filter((key) => key !== CACHE_NAME)
          .map((key) => caches.delete(key))
      )
    )
  );
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);

  // API calls and non-GET requests are always fetched live.
  if (
    event.request.method !== "GET" ||
    url.pathname.startsWith("/api/")
  ) {
    return;
  }

  // For shell assets: network-first so updates propagate immediately;
  // fall back to cache only when offline.
  event.respondWith(
    fetch(event.request)
      .then((response) => {
        if (response && response.status === 200) {
          const clone = response.clone();
          caches.open(CACHE_NAME).then((cache) =>
            cache.put(event.request, clone)
          );
        }
        return response;
      })
      .catch(() => caches.match(event.request))
  );
});

function scheduleNotificationAutoClose(tag, autoCloseMs) {
  const safeTag = String(tag || "").trim();
  const delayMs = Number(autoCloseMs);
  if (!safeTag || !Number.isFinite(delayMs) || delayMs <= 0) {
    return;
  }
  const existingTimer = notificationCloseTimers.get(safeTag);
  if (existingTimer) {
    clearTimeout(existingTimer);
  }
  const timerId = setTimeout(() => {
    notificationCloseTimers.delete(safeTag);
    self.registration.getNotifications({ tag: safeTag }).then((items) => {
      items.forEach((item) => item.close());
    });
  }, delayMs);
  notificationCloseTimers.set(safeTag, timerId);
}

function buildNotificationOptions(payload, overrides = {}) {
  const merged = { ...payload, ...overrides };
  const fallbackBody =
    merged.kind === "live-dashboard"
      ? "Warte auf Live-Meldungen…"
      : "Neues Monitoring-Ereignis";
  const options = {
    body: normalizeNotificationBody(merged.body, fallbackBody),
    tag: String(merged.tag || "monitoring-alert"),
    renotify: Boolean(merged.renotify),
    requireInteraction: Boolean(merged.requireInteraction || merged.persistent),
    silent: Boolean(merged.silent),
    timestamp: Number(merged.timestamp) > 0 ? Number(merged.timestamp) : Date.now(),
    data:
      merged.data && typeof merged.data === "object"
        ? merged.data
        : { url: "/mobile/alerts" },
    icon: resolveAssetUrl(merged.icon || "/icons/logo.png"),
    badge: resolveAssetUrl(merged.badge || "/icons/logo.png"),
  };

  const image = String(merged.image || "").trim();
  if (image) {
    options.image = resolveAssetUrl(image);
  }

  if (Array.isArray(merged.vibrate) && merged.vibrate.length) {
    options.vibrate = merged.vibrate;
  }

  if (Array.isArray(merged.actions) && merged.actions.length) {
    options.actions = merged.actions
      .filter((item) => item && typeof item === "object")
      .map((item) => ({
        action: String(item.action || "open"),
        title: String(item.title || "Öffnen"),
      }))
      .slice(0, 2);
  }

  return options;
}

async function showLiveReportNotifications(payload) {
  const hostTitle = String(payload.title || "Live Report");
  const hostOptions = buildNotificationOptions(payload, {
    tag: String(payload.tag || "live-report"),
    renotify: payload.renotify !== false,
    requireInteraction: false,
    silent: Boolean(payload.silent),
  });
  await self.registration.showNotification(hostTitle, hostOptions);
  scheduleNotificationAutoClose(
    hostOptions.tag,
    Number(payload.autoCloseMs) > 0 ? Number(payload.autoCloseMs) : LIVE_REPORT_PUSH_TTL_MS
  );

  const dashboard = payload.dashboard;
  if (!dashboard || typeof dashboard !== "object") {
    return;
  }

  const dashboardBody = normalizeNotificationBody(
    dashboard.body,
    "Warte auf Live-Meldungen…"
  );
  const dashboardTitle = String(dashboard.title || "Live Monitoring").trim() || "Live Monitoring";
  const dashboardOptions = buildNotificationOptions(
    {
      kind: "live-dashboard",
      icon: payload.icon,
      badge: payload.badge,
      data: payload.data,
      body: dashboardBody,
      title: dashboardTitle,
      actions: [{ action: "open", title: "Öffnen" }],
      timestamp: Date.now(),
      ...dashboard,
    },
    {
      tag: String(dashboard.tag || LIVE_DASHBOARD_TAG),
      renotify: false,
      requireInteraction: true,
      silent: false,
    }
  );
  await self.registration.showNotification(dashboardTitle, dashboardOptions);
}

async function showMonitoringNotification(payload) {
  const title = String(payload.title || "Monitoring Alert");
  const options = buildNotificationOptions(payload);
  await self.registration.showNotification(title, options);
  if (Number(payload.autoCloseMs) > 0) {
    scheduleNotificationAutoClose(options.tag, Number(payload.autoCloseMs));
  }
}

self.addEventListener("push", (event) => {
  let payload = {};
  try {
    payload = event.data ? event.data.json() : {};
  } catch (_err) {
    payload = { body: event.data ? event.data.text() : "" };
  }

  const kind = String(payload.kind || "").trim().toLowerCase();
  if (kind === "live-report") {
    event.waitUntil(showLiveReportNotifications(payload));
    return;
  }

  event.waitUntil(showMonitoringNotification(payload));
});

self.addEventListener("message", (event) => {
  const message = event.data;
  if (!message || typeof message !== "object") {
    return;
  }
  if (message.type !== "live-report-feed-update") {
    return;
  }
  const events = Array.isArray(message.events) ? message.events : [];
  if (!events.length) {
    return;
  }
  event.waitUntil(
    Promise.all(
      events.map((item) => {
        if (!item || typeof item !== "object") {
          return Promise.resolve();
        }
        const kind = String(item.kind || "live-report").trim().toLowerCase();
        if (kind === "live-report") {
          return showLiveReportNotifications(item);
        }
        return showMonitoringNotification(item);
      })
    )
  );
});

self.addEventListener("notificationclick", (event) => {
  const clickedTag = String(event.notification.tag || "");
  if (clickedTag !== LIVE_DASHBOARD_TAG) {
    event.notification.close();
  }
  const rawTarget = String((event.notification.data && event.notification.data.url) || "/mobile/alerts");
  const targetUrl = new URL(rawTarget, self.location.origin).href;

  event.waitUntil(
    clients.matchAll({ type: "window", includeUncontrolled: true }).then((clientList) => {
      for (const client of clientList) {
        if (!client.url || !("focus" in client)) {
          continue;
        }
        if ("navigate" in client) {
          return client.navigate(targetUrl).then(() => client.focus());
        }
        return client.focus();
      }
      if (clients.openWindow) {
        return clients.openWindow(targetUrl);
      }
      return undefined;
    })
  );
});
