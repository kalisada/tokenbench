/*
 * S32: the tools work offline after the first load. This is a feature, but it is
 * also a privacy proof — a page that keeps working with the network unplugged
 * demonstrably is not sending your tokens anywhere.
 *
 * Two rules this worker must never break:
 *   1. Only same-origin GETs are touched. The JWKS fetch (S13) is cross-origin
 *      and must go straight to the network, uncached — it is the user's request
 *      to another party's server, and none of our business.
 *   2. Nothing a user types can reach here. Only URLs are ever cached.
 */

const CACHE = "tokenbench-v1";

const CORE = [
  "/",
  "/jwt-decoder",
  "/jwt-validator",
  "/jwt-generator",
  "/jwt-secret-key-generator",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE).then((cache) => cache.addAll(CORE)).then(() => self.skipWaiting()),
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(keys.filter((key) => key !== CACHE).map((key) => caches.delete(key))),
      )
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("fetch", (event) => {
  const { request } = event;

  if (request.method !== "GET") return;

  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return; // rule 1 — JWKS goes straight out

  event.respondWith(
    caches.match(request).then((cached) => {
      // Cache-first: the site is static, and a stale asset is corrected on the
      // next activation via the cache version.
      const network = fetch(request)
        .then((response) => {
          if (response.ok && response.type === "basic") {
            const copy = response.clone();
            void caches.open(CACHE).then((cache) => cache.put(request, copy));
          }
          return response;
        })
        .catch(() => cached ?? Response.error());

      return cached ?? network;
    }),
  );
});
