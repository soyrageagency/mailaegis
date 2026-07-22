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

const S = { status: null, messages: [], selected: null, categories: [], threats: {}, filter: { threat: "", label: "", q: "" } };

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
  $("#addAcct").addEventListener("click", () => { $("#form").reset(); showConnect(); });
  $("#backToClient").addEventListener("click", showClient);
  $("#q").addEventListener("input", () => { S.filter.q = $("#q").value.toLowerCase(); renderList(); });
  $("#newLabel").addEventListener("click", createLabel);
}

function busy(on, msg) {
  $("#loading").classList.toggle("hidden", !on);
  if (msg) $("#loading").textContent = msg;
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

function renderAccounts() {
  const st = S.status || {};
  const accounts = st.accounts || [];
  const unified = accounts.length > 1
    ? `<button class="arow ${st.activeId === "" ? "active" : ""}" data-account="">
         ${icon("inbox")}
         <span class="atext"><span class="alabel">All mailboxes</span>
         <span class="ahost">${accounts.length} connected</span></span>
         <span class="n">${accounts.reduce((t, a) => t + a.fetched, 0)}</span>
       </button>`
    : "";

  $("#accounts").innerHTML = unified + accounts.map((a) => {
    const bad = a.counts.malicious + a.counts.suspicious;
    return `<button class="arow ${a.id === st.activeId ? "active" : ""}" data-account="${esc(a.id)}" title="${esc(a.label)} · ${esc(a.host)}">
      ${icon("mail")}
      <span class="atext"><span class="alabel">${esc(a.label)}</span>
      <span class="ahost">${esc(a.demo ? "demo mailbox" : a.host)} · ${esc(a.mailbox)}</span></span>
      ${bad ? `<span class="n bad">${bad}</span>` : `<span class="n">${a.fetched}</span>`}
      <span class="x" data-drop="${esc(a.id)}" title="Disconnect this mailbox">×</span>
    </button>`;
  }).join("") || '<div class="empty2">No mailbox connected.</div>';

  $("#accounts").onclick = async (e) => {
    const drop = e.target.closest("[data-drop]");
    if (drop) {
      e.stopPropagation();
      if (!confirm("Disconnect this mailbox?")) return;
      S.status = await api("/api/mailbox/disconnect", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ account: drop.dataset.drop }) });
      if (!S.status.connected) { S.messages = []; S.selected = null; showConnect(); $("#disconnect").classList.add("hidden"); return; }
      await loadMessages(); clearRead(); renderRail(); renderList();
      return;
    }
    const b = e.target.closest("[data-account]"); if (!b) return;
    S.status = await api("/api/mailbox/active", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ account: b.dataset.account }) });
    await loadMessages(); clearRead(); renderRail(); renderList();
  };
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
    } catch (err) { alert(err.message); } finally { busy(false); }
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
      if (!confirm("Delete this label?")) return;
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
  const name = prompt("Name for the new label:");
  if (!name) return;
  try {
    const r = await api("/api/categories", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name }) });
    S.categories = r.categories;
    renderRail();
  } catch (err) { alert(err.message); }
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
    .catch((e) => alert("Analysis failed: " + e.message))
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
}

async function editLabels(id, current) {
  if (!S.categories.length) { alert('No labels yet — create one with the "+" next to Labels.'); return; }
  const names = S.categories.map((c, i) => `${i + 1}. ${c.name}${current.includes(c.id) ? " ✓" : ""}`).join("\n");
  const answer = prompt(`Labels for this message — enter the numbers to apply, comma separated (empty clears):\n\n${names}`, current.map((id2) => S.categories.findIndex((c) => c.id === id2) + 1).filter((n) => n > 0).join(","));
  if (answer === null) return;
  const chosen = answer.split(",").map((x) => Number(x.trim())).filter((n) => n >= 1 && n <= S.categories.length).map((n) => S.categories[n - 1].id);
  try {
    const r = await api(`/api/mailbox/messages/${encodeURIComponent(id)}/labels`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ labels: chosen }) });
    S.messages = r.messages;
    renderRail(); renderList(); openMessage(id);
  } catch (err) { alert(err.message); }
}

init();
