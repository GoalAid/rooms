const CACHE = "hotel-app-v1";
const APP_FILES = [ 
  "/rooms.html",
  "/assets/icon/icon-192.png"
];

self.addEventListener("install", event => {
  event.waitUntil(
    caches.open(CACHE).then(cache => cache.addAll(APP_FILES))
  );
  self.skipWaiting();
});

self.addEventListener("activate", event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys.filter(key => key !== CACHE).map(key => caches.delete(key))
      )
    )
  );
  self.clients.claim();
});

self.addEventListener("fetch", event => {
  if (event.request.method !== "GET") return;

  const url = new URL(event.request.url);

  // Don't serve cached account/API responses as though they were current.
  if (url.origin !== location.origin || url.pathname.startsWith("/api/")) return;

  event.respondWith(
  fetch(event.request).catch(async () => {
    const cached = await caches.match(event.request);
    return cached || Response.error();
    })
  );
});
