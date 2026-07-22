/*
 * The update & announcement card.
 *
 * Reads /api/updates (the server proxies channel/updates.json from the repo)
 * and slides a small card into the bottom corner: a new release with its
 * changelog, or whatever the maintainer announced. One card at a time, never
 * over the message list, and it remembers what you dismissed.
 *
 * Crafted by SoyRage Agency — https://soyrage.es/
 * Attribution must remain intact (see LICENSE).
 */
(function () {
  "use strict";

  var SEEN = "mailaegis.channel.seen";     // ids the user dismissed for good
  var SNOOZE = "mailaegis.channel.snooze"; // id -> timestamp to stay quiet until
  var DAY = 24 * 60 * 60 * 1000;

  /** localStorage is unavailable in some kiosk/private modes — degrade quietly. */
  function read(key) {
    try { return JSON.parse(localStorage.getItem(key) || "{}") || {}; } catch (e) { return {}; }
  }
  function write(key, value) {
    try { localStorage.setItem(key, JSON.stringify(value)); } catch (e) { /* nothing we can do */ }
  }

  function dismissed(id) {
    if (read(SEEN)[id]) return true;
    var until = read(SNOOZE)[id];
    return typeof until === "number" && Date.now() < until;
  }

  /** Pick the installer that matches this machine, else the release page. */
  function downloadFor(update) {
    var d = update.downloads || {};
    var ua = navigator.userAgent || "";
    if (/Windows/i.test(ua)) return d.win || update.url;
    if (/Mac OS X|Macintosh/i.test(ua)) {
      // Apple Silicon Safari still reports Intel, so prefer arm64 when we
      // cannot tell — an Intel binary on Apple Silicon runs under Rosetta,
      // but an arm64 binary on Intel does not run at all.
      var arm = /arm|aarch64/i.test((navigator.userAgentData && navigator.userAgentData.platform) || "");
      return (arm ? d["mac-arm64"] : d["mac-arm64"] || d["mac-x64"]) || update.url;
    }
    if (/Linux|Android/i.test(ua)) return d.linux || update.url;
    return update.url;
  }

  var ICONS = {
    update: '<path d="M12 3v11m0 0 4-4m-4 4-4-4"/><path d="M4 17v2a2 2 0 002 2h12a2 2 0 002-2v-2"/>',
    info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>',
    success: '<circle cx="12" cy="12" r="9"/><path d="m8.5 12.5 2.5 2.5 4.5-5"/>',
    warn: '<path d="M12 4 3 19h18L12 4Z"/><path d="M12 10v4M12 17h.01"/>',
    critical: '<circle cx="12" cy="12" r="9"/><path d="M12 7v6M12 16h.01"/>',
  };

  function icon(kind) {
    return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" ' +
      'stroke-linecap="round" stroke-linejoin="round">' + (ICONS[kind] || ICONS.info) + "</svg>";
  }

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  var host = null;

  function close(card) {
    card.classList.add("out");
    setTimeout(function () { card.remove(); }, 260);
  }

  /**
   * Render one card. `card` is {id, level, title, body, bullets, primary, secondary, dismissible}.
   */
  function show(card) {
    if (!host) {
      host = document.createElement("div");
      host.className = "chan";
      document.body.appendChild(host);
    }

    var el = document.createElement("aside");
    el.className = "chancard lvl-" + card.level;
    el.setAttribute("role", card.level === "critical" ? "alert" : "status");

    var bullets = (card.bullets || []).length
      ? "<ul>" + card.bullets.map(function (b) { return "<li>" + esc(b) + "</li>"; }).join("") + "</ul>"
      : "";

    el.innerHTML =
      '<div class="chanhead">' +
        '<span class="chanic">' + icon(card.icon || card.level) + "</span>" +
        '<div class="chantitle">' + esc(card.title) +
          (card.tag ? '<span class="chantag">' + esc(card.tag) + "</span>" : "") +
        "</div>" +
        (card.dismissible ? '<button class="chanx" aria-label="Dismiss">' +
          '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"><path d="M6 6l12 12M18 6 6 18"/></svg></button>' : "") +
      "</div>" +
      (card.body ? '<p class="chanbody">' + esc(card.body) + "</p>" : "") +
      bullets +
      '<div class="chanfoot">' +
        (card.primary ? '<a class="chanbtn" href="' + esc(card.primary.url) + '" target="_blank" rel="noreferrer">' + esc(card.primary.label) + "</a>" : "") +
        (card.secondary ? '<button class="chanlater">' + esc(card.secondary) + "</button>" : "") +
      "</div>";

    var forget = function () {
      var seen = read(SEEN); seen[card.id] = true; write(SEEN, seen);
      close(el);
    };
    var later = function () {
      var snooze = read(SNOOZE); snooze[card.id] = Date.now() + DAY; write(SNOOZE, snooze);
      close(el);
    };

    var x = el.querySelector(".chanx");
    if (x) x.addEventListener("click", forget);
    var l = el.querySelector(".chanlater");
    if (l) l.addEventListener("click", later);
    // Following the call to action means it has served its purpose.
    var p = el.querySelector(".chanbtn");
    if (p) p.addEventListener("click", forget);

    host.appendChild(el);
    // Next frame, so the slide-in transition actually runs.
    requestAnimationFrame(function () { el.classList.add("in"); });
  }

  async function check() {
    var state;
    try {
      var res = await fetch("/api/updates");
      if (!res.ok) return;
      state = await res.json();
    } catch (e) { return; } // offline: say nothing
    if (!state || !state.enabled) return;

    var queue = [];

    if (state.update) {
      var u = state.update;
      var id = "release:" + u.version;
      if (u.mandatory || !dismissed(id)) {
        queue.push({
          id: id,
          level: "info",
          icon: "update",
          tag: "v" + u.version,
          title: "MailAegis " + u.version + " is available",
          body: u.notes || "",
          bullets: u.changelog,
          primary: { label: "Install", url: downloadFor(u) },
          secondary: u.mandatory ? null : "Remind me later",
          dismissible: !u.mandatory,
        });
      }
    }

    (state.announcements || []).forEach(function (a) {
      if (a.dismissible && dismissed(a.id)) return;
      queue.push({
        id: a.id,
        level: a.level,
        title: a.title,
        body: a.body,
        bullets: [],
        primary: a.link,
        secondary: null,
        dismissible: a.dismissible,
      });
    });

    // Stagger them so two cards do not fly in on top of each other.
    queue.slice(0, 3).forEach(function (card, i) { setTimeout(function () { show(card); }, 900 + i * 320); });
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", check);
  else check();
})();
