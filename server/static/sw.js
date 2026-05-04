// Monitoring Dashboard – Service Worker
// Purpose: enables PWA installability; no offline caching of dynamic
// dashboard data (live sensor readings should never come from cache).

const CACHE_NAME = "monitoring-shell-v1";

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
