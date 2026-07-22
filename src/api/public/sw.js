/*
 * Service worker — the app shell only.
 *
 * The rule this file exists to enforce: **no message data is ever cached**.
 * Everything under /api is fetched from the network every time and never
 * written to storage. A security tool that leaves someone's mail sitting in a
 * browser cache on a shared or lost phone has created the problem it was
 * bought to prevent.
 *
 * What is cached is the shell — HTML, CSS, JS, icons — so the app opens
 * instantly and tells you it is offline rather than showing a browser error.
 *
 * Crafted by SoyRage Agency — https://soyrage.es/
 * Attribution must remain intact (see LICENSE).
 */
"use strict";

// Bump this to retire every previous cache in one step.
const CACHE = "mailaegis-shell-v2";

const SHELL = [
  "/",
  "/index.html",
  "/styles.css",
  "/app.js",
  "/channel.js",
  "/favicon.svg",
  "/icon-192.png",
  "/icon-512.png",
  "/manifest.webmanifest",
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE)
      // One missing file must not fail the whole install, so each is added
      // on its own and a failure is simply skipped.
      .then((cache) => Promise.all(SHELL.map((url) => cache.add(url).catch(() => undefined))))
      .then(() => self.skipWaiting()),
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener("fetch", (event) => {
  const request = event.request;
  if (request.method !== "GET") return;

  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;

  // Mail data: network only. Never cached, never stored, no stale fallback —
  // an out-of-date verdict is worse than no verdict.
  if (url.pathname.startsWith("/api/")) return;

  // The shell: serve from cache, refresh in the background.
  event.respondWith(
    caches.match(request).then((hit) => {
      const live = fetch(request)
        .then((response) => {
          if (response && response.ok) {
            const copy = response.clone();
            caches.open(CACHE).then((cache) => cache.put(request, copy));
          }
          return response;
        })
        .catch(() => hit);
      return hit || live;
    }),
  );
});
