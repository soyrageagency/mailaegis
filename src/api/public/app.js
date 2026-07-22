/*
 * MailAegis web UI — a three-pane mail client with an antivirus layer.
 * Vanilla JS, no build step.
 * Crafted by SoyRage Agency — https://soyrage.es/
 * Attribution must remain intact (see LICENSE).
 */
"use strict";
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const SEV_COLOR = { info: "#8b8b86", low: "#6b8fb0", medium: "#b8892a", high: "#c9722a", critical: "#c8524a" };
const FOLDER_ICON = { inbox: "inbox", sent: "sent", drafts: "drafts", junk: "junk", trash: "trash", archive: "archive", other: "folder" };

// Custom, hand-drawn line icons.
const IP = {
  shield: '<path d="M12 3l8 3.5V11c0 4.5-3.4 7.6-8 9-4.6-1.4-8-4.5-8-9V6.5z"/>',
  mail: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3.5 7l8.5 6 8.5-6"/>',
  inbox: '<path d="M3 13h5l1.5 3h5L16 13h5"/><path d="M4.5 5.5h15L21 13v5a2 2 0 01-2 2H5a2 2 0 01-2-2v-5z"/>',
  sent: '<path d="M21 3L10.5 13.5"/><path d="M21 3l-6.8 18-3.7-7.5L3 9.8z"/>',
  drafts: '<path d="M14 3H6a2 2 0 00-2 2v14a2 2 0 002 2h12a2 2 0 002-2v-8"/><path d="M17.5 3.5a2.1 2.1 0 013 3L12 15l-4 1 1-4z"/>',
  junk: '<circle cx="12" cy="12" r="9"/><path d="M12 7.5v5.5M12 16.5h.01"/>',
  trash: '<path d="M4 7h16M10 11v6M14 11v6"/><path d="M6 7l1 13h10l1-13M9 7V4h6v3"/>',
  archive: '<rect x="3" y="4" width="18" height="4" rx="1"/><path d="M5 8v11a1 1 0 001 1h12a1 1 0 001-1V8M10 12h4"/>',
  folder: '<path d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2z"/>',
  paperclip: '<path d="M20 11.5l-8.2 8.2a5 5 0 01-7.1-7.1l9-9a3.5 3.5 0 015 5l-9 9a2 2 0 01-2.8-2.8l8.2-8.2"/>',
  link: '<path d="M9 15l6-6M10.5 6.5l1-1a4 4 0 015.5 5.5l-1 1M13.5 17.5l-1 1a4 4 0 01-5.5-5.5l1-1"/>',
  check: '<circle cx="12" cy="12" r="9"/><path d="M8 12l3 3 5-6"/>',
  alert: '<path d="M12 3.5L22 20H2z"/><path d="M12 10v4M12 17h.01"/>',
  danger: '<circle cx="12" cy="12" r="9"/><path d="M12 7.5v5.5M12 16.5h.01"/>',
  engine: '<rect x="4" y="4" width="16" height="16" rx="3"/><path d="M9 9h6v6H9z"/>',
  auth: '<rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 018 0v3"/>',
};
// Extra glyphs for the forensic sections.
IP.route = '<circle cx="5.5" cy="6" r="2.2"/><circle cx="18.5" cy="18" r="2.2"/><path d="M7.7 6h6.3a3.5 3.5 0 010 7H10a3.5 3.5 0 000 7h6.3"/>';
IP.globe = '<circle cx="12" cy="12" r="9"/><path d="M3.2 9.5h17.6M3.2 14.5h17.6"/><path d="M12 3a15 15 0 010 18a15 15 0 010-18z"/>';
IP.flask = '<path d="M10 3v6.2L4.6 18a2 2 0 001.7 3h11.4a2 2 0 001.7-3L14 9.2V3"/><path d="M8.5 3h7M7.5 15h9"/>';

const icon = (n, cls = "ic") => `<svg class="${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">${IP[n] || ""}</svg>`;

const S = { status: null, messages: [], selected: null, categories: [], threats: {}, providers: [], provider: "", filter: { threat: "", label: "", q: "" } };

// ------------------------------------------------------------------ helpers
function when(dateStr) {
  const d = new Date(dateStr);
  if (isNaN(d)) return "";
  const now = new Date();
  const sameDay = d.toDateString() === now.toDateString();
  return sameDay ? d.toTimeString().slice(0, 5) : d.toLocaleDateString(undefined, { day: "2-digit", month: "short" });
}
const vIcon = (v) => (v === "clean" ? "check" : v === "suspicious" ? "alert" : "danger");
const vTitle = (v) => (v === "clean" ? "Clean" : v === "suspicious" ? "Suspicious" : "Malicious — quarantine");

// ------------------------------------------------------------ sound & toast
/*
 * Cues are synthesised rather than shipped as audio files: a few sine tones
 * weigh nothing, work offline in the desktop build, and cannot be mistaken for
 * a system alert. Off by default is wrong for a security tool — you want to
 * hear that something malicious arrived — but it is one click to silence, and
 * the choice is remembered.
 */
const SOUND_KEY = "mailaegis.sound";
let audio = null;

function soundOn() {
  try { return localStorage.getItem(SOUND_KEY) !== "off"; } catch { return true; }
}

const TONES = {
  // [frequency, start, length] — kept short and soft; this is an office tool.
  sent: [[660, 0, 0.08], [990, 0.07, 0.12]],
  clean: [[880, 0, 0.09]],
  warn: [[520, 0, 0.11], [415, 0.1, 0.16]],
  alert: [[400, 0, 0.13], [320, 0.14, 0.13], [400, 0.28, 0.2]],
};

function chime(kind) {
  if (!soundOn() || !TONES[kind]) return;
  try {
    audio = audio || new (window.AudioContext || window.webkitAudioContext)();
    if (audio.state === "suspended") audio.resume();
    for (const [freq, at, len] of TONES[kind]) {
      const osc = audio.createOscillator();
      const gain = audio.createGain();
      osc.type = "sine";
      osc.frequency.value = freq;
      const t0 = audio.currentTime + at;
      // A tiny attack and a real decay: an abrupt gate is what makes a
      // synthesised tone sound like a click rather than a note.
      gain.gain.setValueAtTime(0, t0);
      gain.gain.linearRampToValueAtTime(0.075, t0 + 0.012);
      gain.gain.exponentialRampToValueAtTime(0.0001, t0 + len);
      osc.connect(gain).connect(audio.destination);
      osc.start(t0);
      osc.stop(t0 + len + 0.02);
    }
  } catch { /* no audio device, or the browser refused — never fatal */ }
}

// ---------------------------------------------------------------- dialogs
/*
 * confirm(), alert() and prompt() are never used here. They freeze the page,
 * they cannot be styled, and — the part that matters for a security tool —
 * Chrome labels them with the bare origin ("127.0.0.1:4850 says"), which is
 * exactly the chrome a phishing page wears. Our own dialogs look like the
 * product they belong to.
 */
function dialog({ title, body = "", confirmLabel = "Confirm", cancelLabel = "Cancel", danger = false, input = null }) {
  return new Promise((resolve) => {
    const host = document.createElement("div");
    host.className = "modal";
    host.innerHTML = `
      <div class="mbox" role="dialog" aria-modal="true" aria-label="${esc(title)}">
        <h3>${esc(title)}</h3>
        ${body ? `<p>${esc(body)}</p>` : ""}
        ${input !== null ? `<input class="minput" value="${esc(input)}" />` : ""}
        <div class="mrowbtns">
          <button class="ghost sm" data-no>${esc(cancelLabel)}</button>
          <button class="mgo ${danger ? "danger" : ""}" data-yes>${esc(confirmLabel)}</button>
        </div>
      </div>`;
    document.body.appendChild(host);
    requestAnimationFrame(() => host.classList.add("in"));

    const field = host.querySelector(".minput");
    if (field) { field.focus(); field.select(); }
    else host.querySelector("[data-yes]").focus();

    const done = (value) => {
      host.classList.remove("in");
      setTimeout(() => host.remove(), 200);
      document.removeEventListener("keydown", onKey);
      resolve(value);
    };
    const accept = () => done(field ? field.value.trim() : true);
    const onKey = (e) => {
      if (e.key === "Escape") { e.preventDefault(); done(null); }
      if (e.key === "Enter" && field) { e.preventDefault(); accept(); }
    };

    host.querySelector("[data-yes]").addEventListener("click", accept);
    host.querySelector("[data-no]").addEventListener("click", () => done(null));
    // Clicking the backdrop is a cancel, but only the backdrop itself.
    host.addEventListener("mousedown", (e) => { if (e.target === host) done(null); });
    document.addEventListener("keydown", onKey);
  });
}

const ask = (title, body, opts = {}) => dialog({ title, body, confirmLabel: "Confirm", ...opts }).then(Boolean);
const askText = (title, value = "", opts = {}) => dialog({ title, input: value, confirmLabel: "Save", ...opts });
const notify = (title, body) => dialog({ title, body, confirmLabel: "Got it", cancelLabel: "" }).then(() => undefined);

function toast(text, kind = "") {
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.textContent = text;
  document.body.appendChild(el);
  requestAnimationFrame(() => el.classList.add("in"));
  setTimeout(() => { el.classList.remove("in"); setTimeout(() => el.remove(), 250); }, 4200);
}

async function api(path, options) {
  const r = await fetch(path, options);
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(body.error || r.statusText);
  return body;
}

// ------------------------------------------------------------------- boot
async function init() {
  try {
    const m = await api("/api/meta");
    const on = Object.entries(m.engines).filter(([, v]) => v).map(([k]) => k).join(" · ");
    $("#engines").textContent = on || "heuristics";
    if (m.demo) $("#demo").classList.remove("hidden");
  } catch {}

  try {
    const c = await api("/api/categories");
    S.categories = c.categories; S.threats = c.threats;
  } catch {}

  // Pre-fill the form from any server-side configuration.
  try {
    const st = await api("/api/mailbox/status");
    if (st.preset && st.preset.host) {
      const f = $("#form");
      f.host.value = st.preset.host; f.port.value = st.preset.port;
      f.user.value = st.preset.user; f.mailbox.value = st.preset.mailbox;
      f.tls.value = String(st.preset.tls);
      if (st.preset.hasPassword) f.password.placeholder = "using the configured password";
    }
    if (st.connected) { S.status = st; await loadMessages(); showClient(); }
  } catch {}

  $("#form").addEventListener("submit", onConnect);
  $("#tryDemo").addEventListener("click", () => connect({ demo: true }));
  $("#pick").addEventListener("click", () => $("#file").click());
  $("#analyseFile").addEventListener("click", () => $("#file").click());
  $("#file").addEventListener("change", async (e) => {
    const f = e.target.files && e.target.files[0];
    if (f) analyseRaw(await f.text());
  });
  $("#disconnect").addEventListener("click", async () => {
    await api("/api/mailbox/disconnect", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    S.status = null; S.messages = []; S.selected = null;
    showConnect();
    $("#backToClient").classList.add("hidden");
    $("#disconnect").classList.add("hidden"); $("#analyseFile").classList.add("hidden");
  });
  $("#backToClient").addEventListener("click", showClient);
  wirePicker();
  await loadProviders();
  wireComposer();
  $("#q").addEventListener("input", () => { S.filter.q = $("#q").value.toLowerCase(); renderList(); });
  $("#newLabel").addEventListener("click", createLabel);
}

function busy(on, msg) {
  $("#loading").classList.toggle("hidden", !on);
  if (msg) $("#loading").textContent = msg;
}

// ------------------------------------------------------- provider presets
/** Fill `{domain}` from whatever address the user has typed so far. */
function resolveHost(template, address) {
  const domain = String(address).includes("@") ? String(address).split("@").pop() : "";
  return template.replace("{domain}", domain || "yourdomain.com");
}

function applyProvider(p) {
  S.provider = p.id;
  const f = $("#form");
  f.host.value = resolveHost(p.host, f.user.value.trim());
  f.port.value = p.port;
  f.tls.value = String(p.tls);
  const note = $("#providerNote");
  note.innerHTML = `<b>${esc(p.name)}</b> — ${esc(p.note)} <a href="${esc(p.docs)}" target="_blank" rel="noreferrer">Vendor guide &rarr;</a>`;
  note.classList.remove("hidden");
  // An app password is a different secret from the login password, and saying
  // so in the field itself saves the most common failed connection.
  f.password.placeholder = p.auth === "app-password-required" ? "app password — not your login password" : "••••••••";
  renderProviders();
}

function renderProviders() {
  $("#providers").innerHTML = S.providers.map((p) => `
    <button type="button" class="pchip ${S.provider === p.id ? "active" : ""}" data-provider="${esc(p.id)}" title="${esc(p.blurb)}">${esc(p.name)}</button>`).join("");
}

async function loadProviders() {
  try {
    const r = await api("/api/providers");
    S.providers = r.providers || [];
  } catch { return; }
  renderProviders();
  $("#providers").onclick = (e) => {
    const b = e.target.closest("[data-provider]"); if (!b) return;
    applyProvider(S.providers.find((p) => p.id === b.dataset.provider));
  };
  // Typing the address is usually enough to know the platform.
  $("#form").user.addEventListener("blur", () => {
    const address = $("#form").user.value.trim().toLowerCase();
    const domain = address.split("@").pop();
    if (!domain) return;
    const hit = S.providers.find((p) => (p.domains || []).some((d) => domain === d || domain.endsWith("." + d)));
    if (hit && S.provider !== hit.id) applyProvider(hit);
    // A self-hosted preset templates its host on the domain, so refresh it.
    else if (S.provider) {
      const p = S.providers.find((x) => x.id === S.provider);
      if (p && p.selfHosted) $("#form").host.value = resolveHost(p.host, address);
    }
  });
}

// ---------------------------------------------------------------- connect
function onConnect(e) {
  e.preventDefault();
  const f = e.target;
  connect({
    host: f.host.value.trim(), port: Number(f.port.value) || 993,
    user: f.user.value.trim(), password: f.password.value,
    tls: f.tls.value === "true", mailbox: f.mailbox.value.trim() || "INBOX",
    limit: Number(f.limit.value) || 25,
  });
}

async function connect(body) {
  $("#connectError").classList.add("hidden");
  busy(true, "Connecting & scanning…");
  try {
    S.status = await api("/api/mailbox/connect", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    await loadMessages();
    showClient();
  } catch (err) {
    $("#connectError").textContent = `Could not connect: ${err.message}`;
    $("#connectError").classList.remove("hidden");
  } finally { busy(false); }
}

function showClient() {
  $("#connect").classList.add("hidden");
  $("#client").classList.remove("hidden");
  $("#disconnect").classList.remove("hidden");
  $("#analyseFile").classList.remove("hidden");
  renderRail(); renderList();
}

/** Back to the connect form without dropping the mailboxes already open. */
function showConnect() {
  $("#client").classList.add("hidden");
  $("#connect").classList.remove("hidden");
  const some = S.status && (S.status.accounts || []).length > 0;
  $("#backToClient").classList.toggle("hidden", !some);
}

async function loadMessages() {
  const r = await api("/api/mailbox/messages");
  S.status = { ...S.status, ...r.status };
  S.messages = r.messages;
}

// ------------------------------------------------------------------- rail
/** The mailbox currently in focus, or null when the unified view is showing. */
function activeAccount() {
  const st = S.status || {};
  return (st.accounts || []).find((a) => a.id === st.activeId) || null;
}

/**
 * The mailbox picker.
 *
 * A rail-height list does not survive a company with eight mailboxes, so the
 * switcher collapses to one line showing where you are, and opens a menu with
 * the rest. Each entry carries its own risk count, because the point of
 * running several is noticing which one is being attacked.
 */
function renderAccounts() {
  const st = S.status || {};
  const accounts = st.accounts || [];
  const active = accounts.find((a) => a.id === st.activeId);
  const risky = (a) => a.counts.malicious + a.counts.suspicious;
  const totalRisk = accounts.reduce((t, a) => t + risky(a), 0);

  $("#pickerBtn").innerHTML = accounts.length === 0
    ? `${icon("mail")}<span class="ptext"><span class="plabel">No mailbox</span><span class="psub">Connect one to begin</span></span>${caret()}`
    : active
      ? `${icon("mail")}<span class="ptext"><span class="plabel">${esc(active.label)}</span>
         <span class="psub">${esc(active.demo ? "demo mailbox" : active.host)} · ${esc(active.mailbox)}</span></span>
         ${risky(active) ? `<span class="pn bad">${risky(active)}</span>` : ""}${caret()}`
      : `${icon("inbox")}<span class="ptext"><span class="plabel">All mailboxes</span>
         <span class="psub">${accounts.length} connected</span></span>
         ${totalRisk ? `<span class="pn bad">${totalRisk}</span>` : ""}${caret()}`;

  const entry = (id, glyph, label, sub, count, drop) => `
    <button class="popt ${id === st.activeId ? "active" : ""}" role="option" data-account="${esc(id)}">
      ${icon(glyph)}
      <span class="ptext"><span class="plabel">${esc(label)}</span><span class="psub">${esc(sub)}</span></span>
      ${count ? `<span class="pn bad">${count}</span>` : ""}
      ${drop ? `<span class="x" data-drop="${esc(id)}" title="Disconnect">×</span>` : ""}
    </button>`;

  $("#pickerMenu").innerHTML =
    (accounts.length > 1 ? entry("", "inbox", "All mailboxes", `${accounts.length} connected · everything in one list`, totalRisk, false) : "") +
    accounts.map((a) => entry(a.id, "mail", a.label, `${a.demo ? "demo mailbox" : a.host} · ${a.fetched} scanned`, risky(a), true)).join("") +
    `<button class="popt add" data-add>${icon("drafts")}<span class="ptext"><span class="plabel">Connect another mailbox…</span><span class="psub">IMAP, or the demo corpus</span></span></button>`;
}

function caret() {
  return '<svg class="pcaret" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M7 10l5 5 5-5"/></svg>';
}

function togglePicker(open) {
  const menu = $("#pickerMenu");
  const show = open === undefined ? menu.classList.contains("hidden") : open;
  menu.classList.toggle("hidden", !show);
  $("#picker").classList.toggle("open", show);
  $("#pickerBtn").setAttribute("aria-expanded", String(show));
}

function wirePicker() {
  $("#pickerBtn").addEventListener("click", (e) => { e.stopPropagation(); togglePicker(); });
  document.addEventListener("click", (e) => { if (!e.target.closest("#picker")) togglePicker(false); });

  $("#pickerMenu").addEventListener("click", async (e) => {
    const drop = e.target.closest("[data-drop]");
    if (drop) {
      e.stopPropagation();
      const account = (S.status.accounts || []).find((a) => a.id === drop.dataset.drop);
      togglePicker(false);
      if (!await ask("Disconnect this mailbox?", `${account ? account.label : "This mailbox"} will be closed. Nothing is deleted on the server — reconnect any time.`, { confirmLabel: "Disconnect", danger: true })) return;
      S.status = await api("/api/mailbox/disconnect", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ account: drop.dataset.drop }) });
      if (!S.status.connected) { S.messages = []; S.selected = null; showConnect(); $("#disconnect").classList.add("hidden"); return; }
      await loadMessages(); clearRead(); renderRail(); renderList();
      toast(`${account ? account.label : "Mailbox"} disconnected.`);
      return;
    }
    if (e.target.closest("[data-add]")) { togglePicker(false); $("#form").reset(); showConnect(); return; }

    const b = e.target.closest("[data-account]"); if (!b) return;
    togglePicker(false);
    S.status = await api("/api/mailbox/active", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ account: b.dataset.account }) });
    await loadMessages(); clearRead(); renderRail(); renderList();
  });
}

function clearRead() {
  S.selected = null;
  $("#read").innerHTML = '<div class="empty muted">Select a message to see its full analysis.</div>';
}

function renderRail() {
  const st = S.status;
  renderAccounts();

  // Folders belong to one mailbox, so they only make sense with one in focus.
  const acct = activeAccount() || ((st.accounts || []).length === 1 ? st.accounts[0] : null);
  $("#foldersHead").classList.toggle("hidden", !acct);
  $("#folders").innerHTML = !acct ? "" : (acct.folders || []).map((f) => `
    <button class="frow ${f.name === acct.mailbox ? "active" : ""}" data-folder="${esc(f.name)}">
      ${icon(FOLDER_ICON[f.role] || "folder")}<span>${esc(f.label)}</span>
      ${f.name === acct.mailbox ? `<span class="n">${acct.fetched}</span>` : ""}
    </button>`).join("");
  $("#folders").onclick = async (e) => {
    const b = e.target.closest("[data-folder]"); if (!b || !acct) return;
    busy(true);
    try {
      S.status = await api("/api/mailbox/select", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ account: acct.id, folder: b.dataset.folder }) });
      await loadMessages(); clearRead();
      renderRail(); renderList();
    } catch (err) { toast(err.message, "bad"); } finally { busy(false); }
  };

  const tc = st.threatCounts || {};
  const threats = Object.keys(S.threats).filter((t) => tc[t]);
  $("#threats").innerHTML = threats.map((t) => `
    <button class="chip ${S.filter.threat === t ? "active" : ""}" data-threat="${esc(t)}">
      <span class="dot" style="background:${esc(S.threats[t].colour)}"></span>${esc(S.threats[t].label)}<span class="n">${tc[t]}</span>
    </button>`).join("") || '<div class="empty2">Nothing flagged.</div>';
  $("#threats").onclick = (e) => {
    const b = e.target.closest("[data-threat]"); if (!b) return;
    S.filter.threat = S.filter.threat === b.dataset.threat ? "" : b.dataset.threat;
    renderRail(); renderList();
  };

  $("#labels").innerHTML = S.categories.map((c) => `
    <button class="chip ${S.filter.label === c.id ? "active" : ""}" data-label="${esc(c.id)}">
      <span class="dot" style="background:${esc(c.colour)}"></span>${esc(c.name)}
      <span class="n">${S.messages.filter((m) => (m.labels || []).includes(c.id)).length}</span>
      <span class="x" data-del="${esc(c.id)}" title="Delete label">×</span>
    </button>`).join("") || '<div class="empty2">No labels yet.</div>';
  $("#labels").onclick = async (e) => {
    const del = e.target.closest("[data-del]");
    if (del) {
      e.stopPropagation();
      if (!await ask("Delete this label?", "It is removed from every message that carries it. The messages themselves are untouched.", { confirmLabel: "Delete", danger: true })) return;
      const r = await api(`/api/categories/${encodeURIComponent(del.dataset.del)}`, { method: "DELETE" });
      S.categories = r.categories; S.messages = r.messages;
      if (S.filter.label === del.dataset.del) S.filter.label = "";
      renderRail(); renderList(); if (S.selected) openMessage(S.selected);
      return;
    }
    const b = e.target.closest("[data-label]"); if (!b) return;
    S.filter.label = S.filter.label === b.dataset.label ? "" : b.dataset.label;
    renderRail(); renderList();
  };
}

async function createLabel() {
  const name = await askText("New label", "", { confirmLabel: "Create" });
  if (!name) return;
  try {
    const r = await api("/api/categories", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name }) });
    S.categories = r.categories;
    renderRail();
  } catch (err) { toast(err.message, "bad"); }
}

// ------------------------------------------------------------------- list
function visibleMessages() {
  return S.messages.filter((m) => {
    if (S.filter.threat && !(m.threat || []).includes(S.filter.threat)) return false;
    if (S.filter.label && !(m.labels || []).includes(S.filter.label)) return false;
    if (S.filter.q) {
      const hay = `${m.from.name} ${m.from.address} ${m.subject} ${m.snippet}`.toLowerCase();
      if (!hay.includes(S.filter.q)) return false;
    }
    return true;
  });
}

function renderList() {
  const rows = visibleMessages();
  // In the unified view a row is ambiguous without saying which mailbox it
  // landed in — that is the whole point of running several.
  const showAccount = S.status && S.status.activeId === "" && (S.status.accounts || []).length > 1;
  $("#listCount").textContent = `${rows.length}/${S.messages.length}`;
  $("#list").innerHTML = rows.map((m, i) => `
    <button class="mrow ${m.verdict} ${S.selected === m.id ? "active" : ""}" data-id="${esc(m.id)}" style="--i:${Math.min(i, 14)}">
      <span class="bar"></span>
      <span class="body">
        ${showAccount ? `<span class="inbox">${icon("mail")}${esc(m.accountLabel || "")}</span>` : ""}
        <span class="top"><span class="who">${esc(m.from.name || m.from.address)}</span><span class="when">${esc(when(m.date))}</span></span>
        <div class="subj">${esc(m.subject || "(no subject)")}</div>
        <div class="snip">${esc(m.snippet)}</div>
        <div class="tags">
          ${(m.threat || []).filter((t) => t !== "clean").map((t) => `<span class="tag" style="background:${esc((S.threats[t] || {}).colour || "#8b8b86")}">${esc((S.threats[t] || {}).label || t)}</span>`).join("")}
          ${(m.labels || []).map((id) => { const c = S.categories.find((x) => x.id === id); return c ? `<span class="tag" style="background:${esc(c.colour)}">${esc(c.name)}</span>` : ""; }).join("")}
          ${m.attachmentCount ? `<span class="meta">${icon("paperclip")}${m.attachmentCount}</span>` : ""}
          ${m.urlCount ? `<span class="meta">${icon("link")}${m.urlCount}</span>` : ""}
          ${m.verdict !== "clean" ? `<span class="meta">${m.score}/100</span>` : ""}
        </div>
      </span>
    </button>`).join("") || '<div class="empty2" style="padding:18px">No messages match.</div>';
  $("#list").onclick = (e) => {
    const b = e.target.closest("[data-id]"); if (!b) return;
    openMessage(b.dataset.id);
  };
}

// -------------------------------------------------------------- read pane
async function openMessage(id) {
  S.selected = id;
  renderList();
  try {
    const a = await api(`/api/mailbox/messages/${encodeURIComponent(id)}`);
    renderRead(a, S.messages.find((m) => m.id === id));
  } catch (err) { $("#read").innerHTML = `<div class="empty muted">${esc(err.message)}</div>`; }
}

function analyseRaw(raw) {
  busy(true, "Analysing…");
  fetch("/api/analyze", { method: "POST", headers: { "Content-Type": "message/rfc822" }, body: raw })
    .then((r) => r.json())
    .then((a) => {
      if (a.error) throw new Error(a.error);
      if (!S.status) { S.status = { connected: true, accounts: [], activeId: "", fetched: 1, counts: {}, threatCounts: {} }; showClient(); }
      renderRead(a, null);
    })
    .catch((e) => toast("Analysis failed: " + e.message, "bad"))
    .finally(() => busy(false));
}

function renderRead(a, item) {
  const m = a.message;
  const threat = (item && item.threat) || [];
  const labels = (item && item.labels) || [];

  const findings = a.findings.length ? a.findings.map((f) => `
    <div class="find">
      <span class="sev" style="background:${SEV_COLOR[f.severity] || "#8b8b86"}">${esc(f.severity)}</span>
      <div><b>${esc(f.title)}</b><div class="d">${esc(f.detail)}</div>${f.evidence ? `<div class="e">${esc(String(f.evidence).slice(0, 200))}</div>` : ""}</div>
      <span class="sc">${f.score}</span>
    </div>`).join("") : '<div class="empty2">Nothing of concern found.</div>';

  const rows = (arr, cols, empty) => arr.length
    ? `<table><thead><tr>${cols.head.map((h) => `<th>${h}</th>`).join("")}</tr></thead><tbody>${arr.map(cols.row).join("")}</tbody></table>`
    : `<div class="empty2">${empty}</div>`;

  $("#read").innerHTML = `
    <div class="rhead">
      <div class="vline">
        <div class="vbadge ${a.verdict}">${icon(vIcon(a.verdict))}</div>
        <div><div class="vtitle">${esc(vTitle(a.verdict))}</div><div class="vsum">${esc(a.summary)}</div></div>
        <div class="vscore"><div class="n">${a.score}</div><div class="l">RISK / 100</div></div>
      </div>
      <div class="rsubject">${esc(m.subject || "(no subject)")}</div>
      <div class="rfrom"><b>${esc(m.from.name || m.from.address)}</b> <span class="muted">&lt;${esc(m.from.address)}&gt;</span></div>
      <div class="rmeta">to ${esc(m.to.map((t) => t.address).join(", ") || "—")} · ${esc(m.date || "")}${m.replyTo ? ` · reply-to ${esc(m.replyTo.address)}` : ""}</div>
      ${item ? `<div class="ractions">
        <button class="ghost sm" data-act="reply">Reply</button>
        <button class="ghost sm" data-act="replyAll">Reply all</button>
        <button class="ghost sm" data-act="forward">Forward</button>
      </div>` : ""}
      <div class="rtags">
        ${threat.filter((t) => t !== "clean").map((t) => `<span class="tag" style="background:${esc((S.threats[t] || {}).colour || "#8b8b86")}">${esc((S.threats[t] || {}).label || t)}</span>`).join("")}
        ${labels.map((id) => { const c = S.categories.find((x) => x.id === id); return c ? `<span class="tag" style="background:${esc(c.colour)}">${esc(c.name)}</span>` : ""; }).join("")}
        ${item ? `<button class="labelbtn" id="editLabels">+ label</button>` : ""}
      </div>
    </div>
    <div class="rbody">
      <div class="rsec"><h3>${icon("alert")} Findings (${a.findings.length})</h3>${findings}</div>

      <div class="rsec"><h3>${icon("auth")} Authentication</h3>
        <table class="kv"><tbody>
          <tr><td>SPF</td><td><b>${esc(a.auth.spf)}</b></td></tr>
          <tr><td>DKIM</td><td><b>${esc(a.auth.dkim)}</b></td></tr>
          <tr><td>DMARC</td><td><b>${esc(a.auth.dmarc)}</b></td></tr>
          <tr><td>Envelope alignment</td><td>${a.auth.alignmentMismatch ? "<b>mismatch</b>" : "aligned"}</td></tr>
        </tbody></table></div>

      <div class="rsec"><h3>${icon("route")} Delivery path${a.trace.originatingIp ? ` — really from ${esc(a.trace.originatingIp)}` : ""}</h3>
        ${a.trace.hops.length ? `
        <div class="origin">
          ${icon("globe")}
          <div>
            <b>${esc(a.trace.originatingIp || "no public origin recorded")}</b>
            ${a.trace.originatingHost ? `<span class="muted"> · ${esc(a.trace.originatingHost)}</span>` : ""}
            <div class="muted">${a.trace.hops.length} hop(s) · ${a.trace.transitSec}s in transit${a.trace.ipReputation && !a.trace.ipReputation.unknown ? ` · VirusTotal: <b>${a.trace.ipReputation.malicious}</b> malicious / ${a.trace.ipReputation.harmless} harmless` : ""}</div>
          </div>
        </div>
        <ol class="hops">
          ${a.trace.hops.map((h) => `
            <li>
              <span class="hopn">${h.index}</span>
              <div>
                <div><b class="mono">${esc(h.ip || "no IP")}</b>${h.privateIp ? '<span class="tagx">internal</span>' : ""}
                  ${h.delaySec ? `<span class="muted"> +${h.delaySec}s</span>` : ""}</div>
                <div class="muted">from <b>${esc(h.from || "?")}</b>${h.rdns && h.rdns !== h.from ? ` <span class="mono">(${esc(h.rdns)})</span>` : ""} → by <b>${esc(h.by || "?")}</b>${h.protocol ? ` <span class="mono">${esc(h.protocol)}</span>` : ""}</div>
              </div>
            </li>`).join("")}
        </ol>` : '<div class="empty2">No Received headers — the delivery path could not be reconstructed.</div>'}
      </div>

      <div class="rsec"><h3>${icon("paperclip")} Attachments (${a.attachments.length})</h3>
        ${rows(a.attachments, { head: ["File", "Type", "Size", "SHA-256"], row: (x) => `<tr><td><b>${esc(x.filename)}</b></td><td class="muted">${esc(x.contentType)}</td><td>${x.size}</td><td class="mono muted">${esc(x.sha256.slice(0, 24))}…</td></tr>` }, "No attachments.")}</div>

      <div class="rsec"><h3>${icon("link")} Links (${a.urls.length})</h3>
        ${rows(a.urls, { head: ["URL", "Host", "Shown as"], row: (u) => `<tr><td class="mono">${esc(u.url.slice(0, 80))}</td><td>${esc(u.host)}</td><td class="muted">${esc(u.text || "—")}</td></tr>` }, "No links.")}</div>

      <div class="rsec"><h3>${icon("shield")} VirusTotal</h3>
        ${rows(a.virustotal, { head: ["Target", "Kind", "Detections", "Engines"], row: (v) => `<tr><td class="mono">${esc(v.target.slice(0, 46))}</td><td>${esc(v.kind)}</td><td>${v.unknown ? '<span class="muted">never seen</span>' : `<b>${v.malicious}</b> / ${v.malicious + v.suspicious + v.harmless + v.undetected}`}</td><td class="muted">${esc(v.detections.slice(0, 2).join("; ") || v.error || "—")}</td></tr>` }, "VirusTotal was not consulted.")}</div>

      <div class="rsec"><h3>${icon("shield")} ClamAV</h3>
        ${rows(a.clamav, { head: ["File", "Result", "Signature"], row: (c) => `<tr><td><b>${esc(c.filename)}</b></td><td>${c.infected ? "<b>INFECTED</b>" : "clean"}</td><td class="mono muted">${esc(c.signature || c.error || "—")}</td></tr>` }, "ClamAV was not consulted.")}</div>

      <div class="rsec"><h3>${icon("flask")} Hybrid Analysis (sandbox)</h3>
        ${rows(a.hybrid || [], { head: ["File", "Verdict", "Threat score", "AV", "Environment"], row: (h) => `<tr><td><b>${esc(h.submitName || h.sha256.slice(0, 16))}</b></td><td>${h.unknown ? '<span class="muted">never detonated</span>' : `<b>${esc(h.verdict || "—")}</b>`}</td><td class="mono">${h.threatScore || 0}/100</td><td class="mono">${h.avDetect || 0}%</td><td class="muted">${esc(h.environment || h.error || "—")}</td></tr>` }, "Hybrid Analysis was not consulted.")}</div>

      <div class="rsec"><h3>${icon("engine")} Engines</h3>
        <table><thead><tr><th>Engine</th><th>Ran</th><th>Notes</th></tr></thead><tbody>
        ${a.engines.map((e) => `<tr><td><b>${esc(e.name)}</b></td><td>${e.ran ? "yes" : "no"}</td><td class="muted">${esc(e.note)}</td></tr>`).join("")}
        </tbody></table></div>
    </div>`;

  const btn = $("#editLabels");
  if (btn) btn.addEventListener("click", () => editLabels(a.id, labels));

  const actions = $("#read").querySelector(".ractions");
  if (actions) actions.addEventListener("click", (e) => {
    const b = e.target.closest("[data-act]");
    if (b) openComposer(b.dataset.act, a, item);
  });
}

// --------------------------------------------------------------- composer
const C = { attachments: [], reply: null, force: false };

function openComposer(mode, analysis, item) {
  const accounts = (S.status && S.status.accounts) || [];
  // Reply from the mailbox the message landed in, not from whichever one
  // happens to be selected — answering a finance@ thread as security@ is a
  // mistake nobody notices until the customer replies to the wrong address.
  const preferred = (item && item.accountId) || S.status.activeId || (accounts[0] || {}).id || "";
  $("#cfrom").innerHTML = accounts.map((a) => `<option value="${esc(a.id)}" ${a.id === preferred ? "selected" : ""}>${esc(a.label)}</option>`).join("")
    || '<option value="">no mailbox connected</option>';

  C.attachments = []; C.force = false; C.reply = null;
  $("#cscan").className = "cscan hidden";
  $("#cto").value = ""; $("#ccc").value = ""; $("#cbcc").value = "";
  $("#csubject").value = ""; $("#cbody").value = "";
  renderAttachments();
  setCarbon(false);

  if (mode !== "new" && analysis) {
    const m = analysis.message;
    const sender = m.replyTo ? m.replyTo.address : m.from.address;
    const quoted = `\n\nOn ${m.date || "an earlier date"}, ${m.from.name || m.from.address} wrote:\n` +
      String(analysis.message.textPreview || item.snippet || "").split("\n").map((l) => `> ${l}`).join("\n");

    if (mode === "forward") {
      $("#csubject").value = /^(fwd?|rv):/i.test(m.subject) ? m.subject : `Fwd: ${m.subject}`;
      $("#cbody").value = `\n\n---------- Forwarded message ----------\nFrom: ${m.from.name || ""} <${m.from.address}>\nDate: ${m.date}\nSubject: ${m.subject}\nTo: ${m.to.map((t) => t.address).join(", ")}\n\n${analysis.message.textPreview || item.snippet || ""}`;
    } else {
      $("#csubject").value = /^re:/i.test(m.subject) ? m.subject : `Re: ${m.subject}`;
      $("#cto").value = sender;
      if (mode === "replyAll") {
        // Everyone on the original except us, so a reply-all does not mail
        // the sender's own address back to them twice.
        const mine = (accounts.find((a) => a.id === preferred) || {}).label || "";
        const others = m.to.map((t) => t.address).concat((m.cc || []).map((t) => t.address))
          .filter((a) => a && a.toLowerCase() !== mine.toLowerCase() && a.toLowerCase() !== sender.toLowerCase());
        if (others.length) { $("#ccc").value = [...new Set(others)].join(", "); setCarbon(true); }
      }
      $("#cbody").value = quoted;
      C.reply = { messageId: m.messageId || "", references: m.references || [] };
    }
  }

  // Replying to something the scanner flagged is how a BEC succeeds: the
  // victim answers the attacker's Reply-To in good faith. A mail client would
  // fill that address in silently. A security tool has to say so.
  if (mode !== "new" && item && analysis) {
    const m = analysis.message;
    const redirected = m.replyTo && m.replyTo.address && m.replyTo.address.toLowerCase() !== m.from.address.toLowerCase();
    if (item.verdict !== "clean" || redirected) {
      $("#cscan").className = "cscan warn";
      $("#cscan").innerHTML =
        `<b>Careful — you are answering a ${esc(item.verdict)} message (${item.score}/100).</b>` +
        (redirected ? `<div>Its <b>Reply-To</b> points at <span class="mono">${esc(m.replyTo.address)}</span>, not at the address it claims to be from (<span class="mono">${esc(m.from.address)}</span>). Your reply goes to the first one.</div>` : "") +
        `<div class="muted">Check the recipient before sending.</div>`;
      chime("warn");
    }
  }

  $("#cwhat").textContent = mode === "new" ? "New message" : mode === "forward" ? "Forward" : mode === "replyAll" ? "Reply to all" : "Reply";
  $("#composer").classList.remove("hidden");
  requestAnimationFrame(() => $("#composer").classList.add("in"));
  (mode === "new" ? $("#cto") : $("#cbody")).focus();
  if (mode !== "new" && mode !== "forward") $("#cbody").setSelectionRange(0, 0);
}

function closeComposer() {
  $("#composer").classList.remove("in");
  setTimeout(() => $("#composer").classList.add("hidden"), 200);
}

function setCarbon(on) {
  $("#cccrow").classList.toggle("hidden", !on);
  $("#cbccrow").classList.toggle("hidden", !on);
}

function renderAttachments() {
  $("#cfiles").innerHTML = C.attachments.map((a, i) => `
    <span class="cfile">${icon("paperclip")}${esc(a.filename)}
      <span class="sz">${Math.max(1, Math.round(a.size / 1024))} KB</span>
      <button data-rm="${i}" aria-label="Remove">×</button></span>`).join("");
  $("#cfiles").onclick = (e) => {
    const b = e.target.closest("[data-rm]"); if (!b) return;
    C.attachments.splice(Number(b.dataset.rm), 1);
    renderAttachments();
  };
}

/** Read a file into base64 without loading it twice. */
function readAsBase64(file) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onerror = () => reject(new Error(`Could not read ${file.name}.`));
    r.onload = () => resolve(String(r.result).split(",", 2)[1] || "");
    r.readAsDataURL(file);
  });
}

async function sendComposed() {
  const btn = $("#csend");
  btn.disabled = true;
  const original = btn.innerHTML;
  btn.innerHTML = "Scanning…";
  try {
    const payload = {
      account: $("#cfrom").value,
      to: $("#cto").value, cc: $("#ccc").value, bcc: $("#cbcc").value,
      subject: $("#csubject").value, text: $("#cbody").value,
      attachments: C.attachments.map((a) => ({ filename: a.filename, contentType: a.contentType, base64: a.base64 })),
      inReplyTo: C.reply ? C.reply.messageId : undefined,
      references: C.reply ? C.reply.references : undefined,
      force: C.force,
    };
    const r = await fetch("/api/mailbox/send", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    const body = await r.json();

    if (r.status === 422 && body.blocked) {
      // The outbound scan refused it. Show why, and let the sender override
      // deliberately rather than silently.
      C.force = true;
      $("#cscan").className = "cscan blocked";
      $("#cscan").innerHTML = `<b>Held back — ${esc(body.analysis.verdict)} (${body.analysis.score}/100)</b>
        <div>${esc(body.reason)}</div>
        <ul>${body.analysis.findings.slice(0, 4).map((f) => `<li>${esc(f.title)}</li>`).join("")}</ul>
        <div class="muted">Press send again to submit it anyway. The override is logged.</div>`;
      return;
    }
    if (!r.ok) throw new Error(body.error || r.statusText);

    S.status = body.status;
    await loadMessages();
    renderRail(); renderList();
    chime(body.analysis.verdict === "clean" ? "sent" : "warn");
    closeComposer();
    toast(body.simulated
      ? `Composed and scanned — nothing was sent, this is the demo mailbox.`
      : `Sent to ${body.accepted.length} recipient(s).${body.rejected.length ? ` ${body.rejected.length} refused.` : ""}`);
  } catch (err) {
    $("#cscan").className = "cscan blocked";
    $("#cscan").textContent = err.message;
  } finally {
    btn.disabled = false;
    btn.innerHTML = original;
  }
}

function wireComposer() {
  $("#compose").addEventListener("click", () => openComposer("new"));
  $("#cclose").addEventListener("click", closeComposer);
  $("#csend").addEventListener("click", sendComposed);
  $("#ccarbon").addEventListener("click", () => setCarbon($("#cccrow").classList.contains("hidden")));
  $("#cattach").addEventListener("click", () => $("#cfileinput").click());
  $("#cfileinput").addEventListener("change", async (e) => {
    for (const file of [...e.target.files]) {
      C.attachments.push({ filename: file.name, contentType: file.type || "application/octet-stream", size: file.size, base64: await readAsBase64(file) });
    }
    e.target.value = "";
    renderAttachments();
  });
  // Escape closes, Ctrl/Cmd+Enter sends — what every mail client has taught
  // people to expect.
  document.addEventListener("keydown", (e) => {
    if ($("#composer").classList.contains("hidden")) return;
    if (e.key === "Escape") closeComposer();
    if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) sendComposed();
  });
}

async function editLabels(id, current) {
  if (!S.categories.length) { await notify("No labels yet", 'Create one first with the "+" next to Labels in the sidebar.'); return; }
  const chosen = await pickLabels(current);
  if (chosen === null) return;
  try {
    const r = await api(`/api/mailbox/messages/${encodeURIComponent(id)}/labels`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ labels: chosen }) });
    S.messages = r.messages;
    renderRail(); renderList(); openMessage(id);
  } catch (err) { toast(err.message, "bad"); }
}

/** Tick the labels to apply. Returns null when the user backs out. */
function pickLabels(current) {
  return new Promise((resolve) => {
    const host = document.createElement("div");
    host.className = "modal";
    host.innerHTML = `
      <div class="mbox" role="dialog" aria-modal="true" aria-label="Labels">
        <h3>Labels for this message</h3>
        <div class="mpick">
          ${S.categories.map((c) => `
            <label class="mopt">
              <input type="checkbox" value="${esc(c.id)}" ${current.includes(c.id) ? "checked" : ""} />
              <span class="dot" style="background:${esc(c.colour)}"></span>${esc(c.name)}
            </label>`).join("")}
        </div>
        <div class="mrowbtns">
          <button class="ghost sm" data-no>Cancel</button>
          <button class="mgo" data-yes>Apply</button>
        </div>
      </div>`;
    document.body.appendChild(host);
    requestAnimationFrame(() => host.classList.add("in"));

    const done = (value) => {
      host.classList.remove("in");
      setTimeout(() => host.remove(), 200);
      document.removeEventListener("keydown", onKey);
      resolve(value);
    };
    const onKey = (e) => { if (e.key === "Escape") done(null); };
    host.querySelector("[data-yes]").addEventListener("click", () =>
      done([...host.querySelectorAll("input:checked")].map((i) => i.value)));
    host.querySelector("[data-no]").addEventListener("click", () => done(null));
    host.addEventListener("mousedown", (e) => { if (e.target === host) done(null); });
    document.addEventListener("keydown", onKey);
  });
}

init();
