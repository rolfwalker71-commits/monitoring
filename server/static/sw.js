// Monitoring Dashboard – Service Worker
// Purpose: enables PWA installability; no offline caching of dynamic
// dashboard data (live sensor readings should never come from cache).

const CACHE_NAME = "monitoring-shell-v3";

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

self.addEventListener("push", (event) => {
  let payload = {};
  try {
    payload = event.data ? event.data.json() : {};
  } catch (_err) {
    payload = { body: event.data ? event.data.text() : "" };
  }

  const title = String(payload.title || "Monitoring Alert");
  const options = {
    body: String(payload.body || "Neues Monitoring-Ereignis"),
    tag: String(payload.tag || "monitoring-alert"),
    renotify: Boolean(payload.renotify),
    requireInteraction: Boolean(payload.requireInteraction),
    silent: Boolean(payload.silent),
    data: payload.data && typeof payload.data === "object" ? payload.data : { url: "/" },
    icon: String(payload.icon || "/icons/logo.png"),
    badge: String(payload.badge || "/icons/logo.png"),
  };

  const image = String(payload.image || "").trim();
  if (image) {
    options.image = image;
  }

  if (Array.isArray(payload.vibrate) && payload.vibrate.length) {
    options.vibrate = payload.vibrate;
  }

  if (Array.isArray(payload.actions) && payload.actions.length) {
    options.actions = payload.actions
      .filter((item) => item && typeof item === "object")
      .map((item) => ({
        action: String(item.action || "open"),
        title: String(item.title || "Öffnen"),
      }))
      .slice(0, 2);
  }

  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
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
