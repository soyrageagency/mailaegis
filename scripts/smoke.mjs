/**
 * Smoke test — parses and analyses the built-in corpus, checks the verdicts,
 * the MIME/attachment/URL extraction, the reports and the HTTP API.
 * No VirusTotal key and no ClamAV daemon required.
 *
 * Crafted by SoyRage Agency — https://soyrage.es/
 */
import { spawn, spawnSync } from "node:child_process";
import { existsSync, readFileSync, rmSync } from "node:fs";

const results = [];
const ok = (name, cond, detail = "") => results.push({ name, ok: !!cond, detail });
const OUT = "./.smoke-reports";
const env = { ...process.env, MAILAEGIS_DEMO: "true", MAILAEGIS_OUT_DIR: OUT, MAILAEGIS_LOG_LEVEL: "error" };

// ---- Unit: parser, engine and scoring --------------------------------------
process.env.MAILAEGIS_DEMO = "true";
const { loadConfig } = await import("../dist/config.js");
const { parseMessage, parseAddress, extractUrls } = await import("../dist/core/parse.js");
const { analyzeRaw } = await import("../dist/core/analyze.js");
const { demoMessages } = await import("../dist/core/demo.js");
const { zipEntries, magicType } = await import("../dist/core/engine.js");
const config = loadConfig();

const addr = parseAddress('"Marta Torres | CEO corp.example" <m.torres.ceo@gmail.com>');
ok("parses display name and address", addr.address === "m.torres.ceo@gmail.com" && addr.domain === "gmail.com" && addr.name.includes("Marta"));

ok("decodes RFC-2047 subjects", parseMessage("Subject: =?utf-8?B?SG9sYSBtdW5kbw==?=\r\n\r\nbody").subject === "Hola mundo");

const urls = extractUrls("see https://a.example/x", '<a href="https://evil.example/login">https://portal.corp.example</a>');
ok("extracts URLs with their anchor text", urls.length === 2 && urls.some((u) => u.host === "evil.example" && (u.text || "").includes("portal.corp.example")));

ok("magicType detects an executable", magicType(Buffer.from("MZ\x90\x00")) === "exe");
ok("zipEntries tolerates non-zip input", zipEntries(Buffer.from("not a zip")).names.length === 0);

// Evasion regression: declaring multipart with no boundary must NOT hide the
// body from analysis (mail clients still render it).
const evasive = [
  'From: "Partner Ltd Billing" <billing@partner.example>',
  "Return-Path: <billing@partner.example>",
  "To: accounts@corp.example",
  "Subject: Invoice ready",
  "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass",
  "Content-Type: multipart/mixed",
  "",
  "Please confirm your credentials: https://secure-corp-login.example/verify?u=staff",
].join("\r\n");
const evasiveAnalysis = await analyzeRaw(evasive, config);
ok("malformed multipart (no boundary) is still scanned", evasiveAnalysis.urls.length === 1 && evasiveAnalysis.findings.some((f) => f.rule === "credential-landing"), `urls=${evasiveAnalysis.urls.length}`);

const samples = demoMessages();
ok("corpus has five samples", samples.length === 5);

const byId = {};
for (const s of samples) byId[s.id] = await analyzeRaw(s.raw, config);

ok("clean invoice is clean", byId["clean-invoice"].verdict === "clean", byId["clean-invoice"].verdict);
ok("newsletter is clean", byId["newsletter"].verdict === "clean", byId["newsletter"].verdict);
ok("CEO fraud is malicious", byId["bec-ceo-fraud"].verdict === "malicious", `${byId["bec-ceo-fraud"].verdict} score=${byId["bec-ceo-fraud"].score}`);
ok("credential phishing is malicious", byId["phishing-credentials"].verdict === "malicious", `${byId["phishing-credentials"].verdict} score=${byId["phishing-credentials"].score}`);
ok("malware attachment is malicious", byId["malware-attachment"].verdict === "malicious", `${byId["malware-attachment"].verdict} score=${byId["malware-attachment"].score}`);

const bec = byId["bec-ceo-fraud"];
ok("BEC: catches executive impersonation", bec.findings.some((f) => f.rule === "exec-impersonation"));
ok("BEC: catches the reply-to divergence", bec.findings.some((f) => f.rule === "reply-to-divergence"));
ok("BEC: catches the bank-detail language", bec.findings.some((f) => f.rule === "bank-detail-change"));

const phish = byId["phishing-credentials"];
ok("phishing: catches the look-alike domain", phish.findings.some((f) => f.rule === "lookalike-domain"));
ok("phishing: catches the anchor-text deception", phish.findings.some((f) => f.rule === "anchor-text-deception"));
ok("phishing: records the DMARC failure", phish.auth.dmarc === "fail");

const mal = byId["malware-attachment"];
ok("malware: extracts both attachments", mal.attachments.length === 2);
ok("malware: ClamAV flags the payload", mal.clamav.some((c) => c.infected));
ok("malware: VirusTotal flags the payload", mal.virustotal.some((v) => v.malicious > 0));
ok("malware: catches the double extension", mal.findings.some((f) => f.rule === "double-extension"));
ok("malware: catches the macro document", mal.findings.some((f) => f.rule === "macro-document"));
ok("malware: hashes attachments (sha256)", mal.attachments.every((a) => /^[0-9a-f]{64}$/.test(a.sha256)));
ok("engines are reported honestly", mal.engines.length === 6 && mal.engines.every((e) => typeof e.ran === "boolean"), `${mal.engines.length} engines`);
ok("malware: Hybrid Analysis flags the payload", mal.hybrid.some((h) => h.verdict === "malicious") && mal.findings.some((f) => f.rule === "hybrid-malicious"));

// ---- Delivery-path forensics ------------------------------------------------
const clean = byId["clean-invoice"];
ok("trace: reconstructs the delivery path", clean.trace.hops.length === 2 && clean.trace.hops[0].index === 0);
ok("trace: identifies the originating public IP", clean.trace.originatingIp === "203.0.113.44", clean.trace.originatingIp);
ok("trace: marks internal hops as private", clean.trace.hops.some((h) => h.privateIp && h.ip === "10.10.20.5"));
ok("trace: parses hop hosts and protocol", clean.trace.hops[0].by === "mx01.corp.example" && clean.trace.hops[0].from === "smtp-out-3.partner.example");
ok("trace: computes transit time", clean.trace.transitSec > 0 && clean.trace.transitSec < 120, `${clean.trace.transitSec}s`);
ok("trace: a clean relay raises no trace findings", !clean.findings.some((f) => f.source === "trace"));

ok("trace: exposes the BEC sender's real origin", bec.trace.originatingIp === "45.146.130.22" && bec.trace.originatingHost.includes("bulletproof"), bec.trace.originatingIp);
ok("trace: flags reverse-DNS that contradicts the From domain", bec.findings.some((f) => f.rule === "rdns-mismatch"));
ok("trace: checks the originating IP reputation", bec.trace.ipReputation && bec.trace.ipReputation.malicious > 0 && bec.findings.some((f) => f.rule === "origin-ip-reputation"));

// ---- CLI --------------------------------------------------------------------
rmSync(OUT, { recursive: true, force: true });
const demoRun = spawnSync("node", ["dist/index.js", "demo"], { env, encoding: "utf8" });
ok("CLI demo exits 0", demoRun.status === 0, demoRun.stderr?.slice(0, 200));
ok("CLI demo prints verdicts", /MALICIOUS/.test(demoRun.stdout) && /CLEAN/.test(demoRun.stdout));

const eml = samples.find((s) => s.id === "malware-attachment").raw;
const piped = spawnSync("node", ["dist/index.js", "scan", "--report"], { env, input: eml, encoding: "utf8" });
ok("CLI scan reads stdin and exits 2 on malicious", piped.status === 2, `status=${piped.status}`);
ok("CLI writes an HTML report", existsSync(OUT) && readFileSync(`${OUT}/${/MA-\d{8}-[0-9a-f]{6}/.exec(piped.stdout)?.[0] ?? ""}.html`, "utf8").includes("MailAegis"));

const cleanEml = samples.find((s) => s.id === "clean-invoice").raw;
const cleanRun = spawnSync("node", ["dist/index.js", "scan", "--json"], { env, input: cleanEml, encoding: "utf8" });
ok("CLI scan exits 0 on clean mail", cleanRun.status === 0, `status=${cleanRun.status}`);
ok("CLI --json emits a parsable analysis", (() => { try { return JSON.parse(cleanRun.stdout).verdict === "clean"; } catch { return false; } })());
rmSync(OUT, { recursive: true, force: true });

// ---- HTTP API ---------------------------------------------------------------
const server = spawn("node", ["dist/index.js", "serve"], { env: { ...env, MAILAEGIS_PORT: "4877" }, stdio: "ignore" });
let up = false;
for (let i = 0; i < 40; i++) {
  try { const r = await fetch("http://127.0.0.1:4877/api/meta"); if (r.ok) { up = true; break; } } catch {}
  await new Promise((r) => setTimeout(r, 150));
}
ok("API /api/meta responds", up);
if (up) {
  const analysis = await (await fetch("http://127.0.0.1:4877/api/analyze", { method: "POST", body: eml })).json();
  ok("API /api/analyze returns a malicious verdict", analysis.verdict === "malicious" && analysis.score > 0);
  const samplesRes = await (await fetch("http://127.0.0.1:4877/api/samples")).json();
  ok("API /api/samples lists the corpus", samplesRes.samples.length === 5);
  const empty = await fetch("http://127.0.0.1:4877/api/analyze", { method: "POST", body: "" });
  ok("API rejects an empty body", empty.status === 400);

  // ---- Mail client: mailbox, folders, categories ---------------------------
  const B = "http://127.0.0.1:4877";
  const post = (p, body) => fetch(B + p, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body ?? {}) }).then((r) => r.json());

  const connected = await post("/api/mailbox/connect", { demo: true });
  ok("mailbox connects to the demo corpus", connected.connected === true && connected.fetched === 5, JSON.stringify(connected).slice(0, 120));
  ok("mailbox advertises folders incl. Sent", (connected.folders || []).some((f) => f.role === "inbox") && connected.folders.some((f) => f.role === "sent"));
  ok("mailbox counts verdicts", connected.counts.malicious === 3 && connected.counts.clean === 2, JSON.stringify(connected.counts));
  ok("mailbox derives threat categories", Object.keys(connected.threatCounts || {}).length > 0);

  const listed = await (await fetch(`${B}/api/mailbox/messages`)).json();
  ok("mailbox lists messages newest/most-dangerous first", listed.messages.length === 5 && listed.messages[0].verdict === "malicious");
  ok("message rows carry threat classes", listed.messages.some((m) => (m.threat || []).includes("malware")) && listed.messages.some((m) => (m.threat || []).includes("fraud")));
  ok("message rows carry a snippet and counts", listed.messages.every((m) => typeof m.snippet === "string" && typeof m.attachmentCount === "number"));

  const sent = await post("/api/mailbox/select", { folder: "Sent" });
  ok("switching to the Sent folder works", sent.mailbox === "Sent" && sent.fetched >= 1, JSON.stringify(sent).slice(0, 120));
  await post("/api/mailbox/select", { folder: "INBOX" });

  const made = await post("/api/categories", { name: "Reported to SOC" });
  ok("creates a user label", made.category && made.category.id === "reported-to-soc");
  const target = (await (await fetch(`${B}/api/mailbox/messages`)).json()).messages[0].id;
  const labelled = await fetch(`${B}/api/mailbox/messages/${encodeURIComponent(target)}/labels`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ labels: ["reported-to-soc"] }) }).then((r) => r.json());
  ok("assigns a label to a message", labelled.labels.includes("reported-to-soc") && labelled.messages.some((m) => (m.labels || []).includes("reported-to-soc")));
  const afterDelete = await fetch(`${B}/api/categories/reported-to-soc`, { method: "DELETE" }).then((r) => r.json());
  ok("deleting a label removes it everywhere", !afterDelete.categories.some((c) => c.id === "reported-to-soc") && afterDelete.messages.every((m) => !(m.labels || []).includes("reported-to-soc")));

  const disconnected = await post("/api/mailbox/disconnect");
  ok("disconnect clears the session", disconnected.ok === true);
}
server.kill();
await new Promise((r) => setTimeout(r, 150));

// ---- IMAP client against a fake IMAP server ---------------------------------
{
  const net = await import("node:net");
  const { fetchRecent, listMailboxes } = await import("../dist/mailbox/imap.js");
  const bodies = demoMessages().slice(0, 3).map((s) => Buffer.from(s.raw, "utf8"));

  const fake = net.createServer((sock) => {
    sock.write("* OK MailAegis fake IMAP ready\r\n");
    let buf = "";
    sock.on("data", (d) => {
      buf += d.toString();
      let i;
      while ((i = buf.indexOf("\r\n")) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 2);
        const [tag, cmdRaw] = line.split(" ");
        const cmd = (cmdRaw || "").toUpperCase();
        if (cmd === "LOGIN") sock.write(`${tag} OK LOGIN completed\r\n`);
        else if (cmd === "LIST") sock.write(`* LIST (\\HasNoChildren) "/" "INBOX"\r\n* LIST (\\HasNoChildren \\Sent) "/" "Sent"\r\n* LIST (\\Noselect) "/" "Skip"\r\n${tag} OK LIST completed\r\n`);
        else if (cmd === "SELECT") sock.write(`* 3 EXISTS\r\n${tag} OK [READ-WRITE] SELECT completed\r\n`);
        else if (cmd === "FETCH") {
          bodies.forEach((raw, n) => { sock.write(`* ${n + 1} FETCH (BODY[] {${raw.length}}\r\n`); sock.write(raw); sock.write(")\r\n"); });
          sock.write(`${tag} OK FETCH completed\r\n`);
        } else if (cmd === "LOGOUT") sock.write(`* BYE\r\n${tag} OK LOGOUT completed\r\n`);
        else sock.write(`${tag} BAD unknown\r\n`);
      }
    });
  });
  await new Promise((r) => fake.listen(0, "127.0.0.1", r));
  const creds = { host: "127.0.0.1", port: fake.address().port, user: "u", password: "p", tls: false, mailbox: "INBOX" };

  const fetched = await fetchRecent(creds, 10);
  ok("IMAP: reads EXISTS and fetches every message", fetched.total === 3 && fetched.messages.length === 3);
  ok("IMAP: message bodies round-trip intact", fetched.messages.every((m) => m.raw.length > 0) && fetched.messages[0].raw.toString("utf8").includes("Subject:"));
  ok("IMAP: returns newest first", fetched.messages[0].seq === 3 && fetched.messages[2].seq === 1);

  const folders = await listMailboxes(creds);
  ok("IMAP: lists folders and detects \\Sent", folders.some((f) => f.role === "inbox") && folders.some((f) => f.role === "sent"));
  ok("IMAP: skips \\Noselect folders", !folders.some((f) => f.name === "Skip"));
  fake.close();
}

let pass = 0, fail = 0;
for (const t of results) { if (t.ok) { pass++; console.log(`  \x1b[32m✓\x1b[0m ${t.name}`); } else { fail++; console.log(`  \x1b[31m✗ ${t.name}\x1b[0m  ${t.detail}`); } }
console.log(`\nTOTAL: ${pass} passed, ${fail} failed`);
process.exitCode = fail ? 1 : 0;
