// gatekeeper PWA service worker — Stub.
// Bewusst KEINE Cache-Logik: /ui liefert personenbezogene Audit-/Rechte-Daten
// (Cache-Control: no-store, ui.py:2036). Der Worker existiert nur, damit die
// Seite installierbar wird; jeder Request geht unverändert ans Netz.
const VERSION = "gatekeeper-sw-1";

self.addEventListener("install", () => {
  // Sofort aktiver werden; VERSION dient als sichtbarer Änderungsanker.
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    Promise.all([
      self.clients.claim(),
      // Etwaige Alt-Caches aus früheren Versionen entfernen.
      caches.keys().then((keys) =>
        Promise.all(keys.map((key) => caches.delete(key))),
      ),
    ]),
  );
});

self.addEventListener("fetch", (event) => {
  // Passthrough: kein respondWith => Standard-Netzverhalten (kein Cache).
  return;
});
