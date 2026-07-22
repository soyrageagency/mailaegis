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
  const first = (connected.accounts || [])[0] || { folders: [] };
  ok("mailbox advertises folders incl. Sent", first.folders.some((f) => f.role === "inbox") && first.folders.some((f) => f.role === "sent"));
  ok("mailbox counts verdicts", connected.counts.malicious === 3 && connected.counts.clean === 2, JSON.stringify(connected.counts));
  ok("mailbox derives threat categories", Object.keys(connected.threatCounts || {}).length > 0);

  const listed = await (await fetch(`${B}/api/mailbox/messages`)).json();
  ok("mailbox lists messages newest/most-dangerous first", listed.messages.length === 5 && listed.messages[0].verdict === "malicious");
  ok("message rows carry threat classes", listed.messages.some((m) => (m.threat || []).includes("malware")) && listed.messages.some((m) => (m.threat || []).includes("fraud")));
  ok("message rows carry a snippet and counts", listed.messages.every((m) => typeof m.snippet === "string" && typeof m.attachmentCount === "number"));

  const sent = await post("/api/mailbox/select", { folder: "Sent" });
  ok("switching to the Sent folder works", sent.accounts[0].mailbox === "Sent" && sent.fetched >= 1, JSON.stringify(sent).slice(0, 140));
  await post("/api/mailbox/select", { folder: "INBOX" });

  // ---- Several mailboxes at once -------------------------------------------
  const two = await post("/api/mailbox/connect", { demo: true });
  ok("a second mailbox connects alongside the first", two.accounts.length === 2 && two.accounts[1].id !== two.accounts[0].id, JSON.stringify(two.accounts.map((a) => a.id)));
  ok("each mailbox keeps its own counts", two.accounts[0].fetched === 5 && two.accounts[1].fetched === 3, JSON.stringify(two.accounts.map((a) => a.fetched)));

  const unified = await post("/api/mailbox/active", { account: "" });
  ok("the unified view spans every mailbox", unified.activeId === "" && unified.fetched === 8, JSON.stringify({ id: unified.activeId, n: unified.fetched }));
  const unifiedRows = await (await fetch(`${B}/api/mailbox/messages`)).json();
  ok("unified rows say which mailbox they came from", new Set(unifiedRows.messages.map((m) => m.accountId)).size === 2);

  const focused = await post("/api/mailbox/active", { account: two.accounts[1].id });
  ok("focusing one mailbox narrows the list", focused.activeId === two.accounts[1].id && focused.fetched === 3);

  const dropped = await post("/api/mailbox/disconnect", { account: two.accounts[1].id });
  ok("disconnecting one mailbox leaves the others", dropped.connected === true && dropped.accounts.length === 1);
  await post("/api/mailbox/active", { account: "" });

  const made = await post("/api/categories", { name: "Reported to SOC" });
  ok("creates a user label", made.category && made.category.id === "reported-to-soc");
  const target = (await (await fetch(`${B}/api/mailbox/messages`)).json()).messages[0].id;
  const labelled = await fetch(`${B}/api/mailbox/messages/${encodeURIComponent(target)}/labels`, { method: "PUT", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ labels: ["reported-to-soc"] }) }).then((r) => r.json());
  ok("assigns a label to a message", labelled.labels.includes("reported-to-soc") && labelled.messages.some((m) => (m.labels || []).includes("reported-to-soc")));
  const afterDelete = await fetch(`${B}/api/categories/reported-to-soc`, { method: "DELETE" }).then((r) => r.json());
  ok("deleting a label removes it everywhere", !afterDelete.categories.some((c) => c.id === "reported-to-soc") && afterDelete.messages.every((m) => !(m.labels || []).includes("reported-to-soc")));

  const disconnected = await post("/api/mailbox/disconnect");
  ok("disconnect clears every mailbox", disconnected.connected === false && disconnected.accounts.length === 0);

  // ---- Sending through the API ---------------------------------------------
  // The block above ends disconnected, so open a mailbox to send from.
  await post("/api/mailbox/connect", { demo: true });
  const sent1 = await post("/api/mailbox/send", { to: "bob@partner.example", subject: "Quarterly figures", text: "Attached as agreed." });
  ok("send: a benign message goes out", sent1.ok === true && sent1.blocked === false && sent1.accepted.includes("bob@partner.example"), JSON.stringify(sent1).slice(0, 140));
  ok("send: the demo mailbox never actually transmits", sent1.simulated === true);
  ok("send: what you send is scanned too", sent1.analysis && typeof sent1.analysis.score === "number");

  const sentFolder = await post("/api/mailbox/select", { folder: "Sent" });
  const sentRows = await (await fetch(`${B}/api/mailbox/messages`)).json();
  ok("send: it appears in Sent straight away", sentRows.messages.some((m) => m.subject === "Quarterly figures"), JSON.stringify(sentFolder.fetched));
  await post("/api/mailbox/select", { folder: "INBOX" });

  const noOne = await fetch(`${B}/api/mailbox/send`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ subject: "nobody" }) });
  ok("send: refuses a message with no recipients", noOne.status === 502 || noOne.status === 400);

  // A message carrying a blocked extension must not leave quietly.
  const evil = await fetch(`${B}/api/mailbox/send`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      to: "victim@partner.example", subject: "Invoice", text: "See attached.",
      attachments: [{ filename: "invoice.exe", contentType: "application/octet-stream", base64: Buffer.from("MZ  fake").toString("base64") }],
    }),
  });
  const evilBody = await evil.json();
  ok("send: the outbound scan holds a dangerous attachment back", evil.status === 422 && evilBody.blocked === true, `${evil.status} ${JSON.stringify(evilBody).slice(0, 120)}`);
  const forced = await post("/api/mailbox/send", {
    to: "victim@partner.example", subject: "Invoice", text: "See attached.", force: true,
    attachments: [{ filename: "invoice.exe", contentType: "application/octet-stream", base64: Buffer.from("MZ  fake").toString("base64") }],
  });
  ok("send: an explicit override is honoured", forced.ok === true && forced.blocked === false);

  // ---- Raw export ----------------------------------------------------------
  const anyId = (await (await fetch(`${B}/api/mailbox/messages`)).json()).messages[0].id;
  const rawRes = await fetch(`${B}/api/mailbox/messages/${encodeURIComponent(anyId)}/raw`);
  const rawText = await rawRes.text();
  ok("export: the original bytes come back as message/rfc822", rawRes.ok && (rawRes.headers.get("content-type") || "").startsWith("message/rfc822"));
  ok("export: it really is the source, headers and all", /^(From|Received|Subject|Return-Path|Date):/im.test(rawText) && rawText.length > 100);
  ok("export: the filename cannot escape the download folder", !/[\\/]/.test((rawRes.headers.get("content-disposition") || "").split("filename=")[1] || ""));
  ok("export: an unknown id is a 404", (await fetch(`${B}/api/mailbox/messages/nope/raw`)).status === 404);

  // ---- Malformed input is the caller's fault, not a server fault -----------
  for (const [p, payload, what] of [
    ["/api/mailbox/send", "not json", "garbage"],
    ["/api/mailbox/send", "[1,2,3]", "an array"],
    ["/api/mailbox/connect", '"a string"', "a bare string"],
    ["/api/lists", "null", "null"],
    ["/api/categories", "{oops}", "broken JSON"],
  ]) {
    const r = await fetch(B + p, { method: "POST", headers: { "Content-Type": "application/json" }, body: payload });
    ok(`400: ${what} to ${p} is a 400, never a 500`, r.status === 400, String(r.status));
  }
  ok("400: an empty body still means 'no options'", (await fetch(`${B}/api/mailbox/connect`, { method: "POST" })).status === 200);

  // ---- Sender lists over the API -------------------------------------------
  const corpus = (await (await fetch(`${B}/api/samples`)).json()).samples;
  const cleanSample = corpus.find((s) => s.id === "clean-invoice") || corpus[0];
  const before = await (await fetch(`${B}/api/samples/${cleanSample.id}`, { method: "POST" })).json();
  ok("policy: the sample is clean before any rule", before.verdict === "clean", `${before.verdict} ${before.score}`);

  await post("/api/lists", { kind: "blocked", value: before.message.from.address, note: "smoke test" });
  const blockedNow = await (await fetch(`${B}/api/samples/${cleanSample.id}`, { method: "POST" })).json();
  ok("policy: blocking a sender makes it malicious whatever else was found",
    blockedNow.verdict === "malicious" && blockedNow.findings.some((f) => f.rule === "sender-blocked"),
    `${blockedNow.verdict} ${blockedNow.score}`);

  await fetch(`${B}/api/lists/blocked/${encodeURIComponent(before.message.from.address)}`, { method: "DELETE" });
  const unblocked = await (await fetch(`${B}/api/samples/${cleanSample.id}`, { method: "POST" })).json();
  ok("policy: removing the rule restores the verdict", unblocked.verdict === "clean");

  // The dangerous case: allow-listing a sender whose mail does not authenticate.
  const bec = corpus.find((s) => s.id === "bec-ceo-fraud");
  const becBefore = await (await fetch(`${B}/api/samples/${bec.id}`, { method: "POST" })).json();
  await post("/api/lists", { kind: "allowed", value: becBefore.message.from.address, note: "smoke test" });
  const becAfter = await (await fetch(`${B}/api/samples/${bec.id}`, { method: "POST" })).json();
  ok("policy: an allow list does NOT rescue an unauthenticated sender",
    becAfter.verdict === "malicious" && becAfter.findings.some((f) => f.rule === "allow-list-not-honoured"),
    `${becAfter.verdict} ${becAfter.score}`);
  await fetch(`${B}/api/lists/allowed/${encodeURIComponent(becBefore.message.from.address)}`, { method: "DELETE" });

  const emptied = await (await fetch(`${B}/api/lists`)).json();
  ok("policy: lists round-trip and clear", emptied.blocked.length === 0 && emptied.allowed.length === 0);

  // ---- Provider presets ----------------------------------------------------
  const { providers } = await (await fetch(`${B}/api/providers`)).json();
  ok("presets cover the big corporate platforms", ["microsoft365", "google-workspace", "mailcow"].every((id) => providers.some((p) => p.id === id)));
  ok("every preset carries an implicit-TLS IMAP port", providers.every((p) => p.port > 0 && typeof p.tls === "boolean" && p.note && p.docs.startsWith("https://")));
  const { detectProvider, resolveHost } = await import("../dist/mailbox/providers.js");
  ok("presets are detected from the address", detectProvider("ana@gmail.com").id === "google-workspace" && detectProvider("j@corp.onmicrosoft.com").id === "microsoft365");
  ok("an unknown corporate domain is not guessed at", detectProvider("ana@corp.example") === null);
  ok("self-hosted presets template the host from the domain", resolveHost("mail.{domain}", "ana@corp.example") === "mail.corp.example");

  // ---- The update & announcement channel -----------------------------------
  const channel = await (await fetch(`${B}/api/updates`)).json();
  ok("the channel reports the running version", typeof channel.current === "string" && channel.current.length > 0, JSON.stringify(channel).slice(0, 140));
  ok("the channel never advertises an update to itself", channel.update === null || channel.update.version !== channel.current);
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

// ---- Composing outbound mail ------------------------------------------------
{
  const { buildMime, quotedPrintable, encodeWord, formatAddress, envelopeRecipients, replySubject, forwardSubject, sanitiseHeaderValue } =
    await import("../dist/mailbox/compose.js");

  const draft = (over = {}) => ({
    from: "Ana López <ana@corp.example>", to: ["bob@partner.example"], cc: [], bcc: [],
    subject: "Hello", text: "Hi there", html: "", attachments: [], date: new Date("2026-07-22T10:00:00Z"), ...over,
  });

  const plain = buildMime(draft()).toString("utf8");
  ok("compose: a plain note is not wrapped in a pointless multipart", !/multipart/.test(plain) && /Content-Type: text\/plain/.test(plain));
  ok("compose: encodes a non-ASCII display name", /=\?UTF-8\?B\?/.test(formatAddress("Ana López <ana@corp.example>")));
  ok("compose: leaves plain ASCII alone", formatAddress("Bob <bob@x.example>") === '"Bob" <bob@x.example>' && encodeWord("Hello") === "Hello");

  // Header injection: the oldest trick there is.
  const injected = buildMime(draft({ subject: "Payroll\r\nBcc: rival@other.example" })).toString("utf8");
  ok("compose: a newline in the subject cannot invent a header", !/^Bcc:/m.test(injected) && /Payroll Bcc: rival/.test(injected));
  ok("compose: sanitiser folds CR and LF away", sanitiseHeaderValue("a\r\nb\nc") === "a b c");

  // Bcc belongs in the envelope, never in the message.
  const blind = draft({ bcc: ["secret@corp.example"], cc: ["cc@corp.example"] });
  const withBcc = buildMime(blind).toString("utf8");
  ok("compose: Bcc never reaches the headers", !/Bcc:/i.test(withBcc) && /Cc: /.test(withBcc));
  ok("compose: Bcc still reaches the envelope", envelopeRecipients(blind).includes("secret@corp.example"));
  ok("compose: the envelope deduplicates recipients", envelopeRecipients(draft({ to: ["a@x.example"], cc: ["A@X.example"] })).length === 1);

  // Quoted-printable is where non-ASCII bodies go wrong.
  ok("compose: encodes non-ASCII bodies", quotedPrintable("café") === "caf=C3=A9");
  ok("compose: encodes trailing whitespace so relays cannot strip it", quotedPrintable("hi \nthere").startsWith("hi=20"));
  ok("compose: escapes the equals sign itself", quotedPrintable("a=b") === "a=3Db");
  ok("compose: wraps at the 76-column limit", quotedPrintable("x".repeat(200)).split("\r\n").every((l) => l.length <= 76));

  const withFile = buildMime(draft({ attachments: [{ filename: "informe año.pdf", contentType: "application/pdf", content: Buffer.from("PDFDATA") }] })).toString("utf8");
  ok("compose: attachments become base64 parts", /multipart\/mixed/.test(withFile) && /Content-Transfer-Encoding: base64/.test(withFile) && withFile.includes(Buffer.from("PDFDATA").toString("base64")));
  ok("compose: non-ASCII filenames use RFC 2231, not an encoded-word", /filename\*=UTF-8''/.test(withFile) && !/filename="=\?/.test(withFile));

  const both = buildMime(draft({ html: "<p>Hi</p>" })).toString("utf8");
  ok("compose: text and HTML become multipart/alternative", /multipart\/alternative/.test(both) && /text\/plain/.test(both) && /text\/html/.test(both));

  ok("compose: Re: and Fwd: do not stack", replySubject("Re: Hi") === "Re: Hi" && replySubject("Hi") === "Re: Hi" && forwardSubject("Fwd: Hi") === "Fwd: Hi");

  // The composed message must be readable by our own parser.
  const { parseMessage } = await import("../dist/core/parse.js");
  const round = parseMessage(buildMime(draft({ subject: "Año nuevo", text: "Hola señor" })));
  ok("compose: our parser reads back what we wrote", round.subject === "Año nuevo" && round.text.includes("Hola señor") && round.from.address === "ana@corp.example");
}

// ---- SMTP against a fake submission server ----------------------------------
{
  const net = await import("node:net");
  const { sendMail, dotStuff } = await import("../dist/mailbox/smtp.js");

  ok("smtp: dot-stuffs a line that would end DATA", dotStuff(Buffer.from(".hidden\r\nok\r\n")).toString() === "..hidden\r\nok\r\n");

  let seen = { auth: "", from: "", rcpt: [], data: "", wire: "" };
  const fake = net.createServer((sock) => {
    let mode = "cmd", body = "", stage = 0;
    // A deliberately multi-line greeting and EHLO: the reply reader has to
    // wait for the line whose fourth character is a space.
    sock.write("220-mail.corp.example ESMTP\r\n220 ready\r\n");
    sock.on("data", (chunk) => {
      for (const line of chunk.toString().split("\r\n")) {
        if (line === "" && mode === "cmd") continue;
        if (mode === "data") {
          if (line === ".") { seen.data = body; mode = "cmd"; sock.write("250 2.0.0 Ok: queued as ABC123\r\n"); }
          // A real server removes the stuffing dot, which is what makes the
          // round trip lossless — so this one does too.
          else { seen.wire += line + "\r\n"; body += line.replace(/^\.\./, ".") + "\r\n"; }
          continue;
        }
        const up = line.toUpperCase();
        if (up.startsWith("EHLO")) sock.write("250-mail.corp.example\r\n250-PIPELINING\r\n250-AUTH LOGIN\r\n250 SIZE 35882577\r\n");
        else if (up === "AUTH LOGIN") { stage = 1; sock.write("334 VXNlcm5hbWU6\r\n"); }
        else if (stage === 1) { seen.auth = Buffer.from(line, "base64").toString(); stage = 2; sock.write("334 UGFzc3dvcmQ6\r\n"); }
        else if (stage === 2) { stage = 0; sock.write("235 2.7.0 Authentication successful\r\n"); }
        else if (up.startsWith("MAIL FROM")) { seen.from = line; sock.write("250 2.1.0 Ok\r\n"); }
        else if (up.startsWith("RCPT TO")) {
          const address = /<([^>]*)>/.exec(line)?.[1] ?? "";
          seen.rcpt.push(address);
          // One address is refused, to prove a partial send is reported.
          if (address === "nope@partner.example") sock.write("550 5.1.1 No such user\r\n");
          else sock.write("250 2.1.5 Ok\r\n");
        } else if (up === "DATA") { mode = "data"; sock.write("354 End data with <CR><LF>.<CR><LF>\r\n"); }
        else if (up === "QUIT") sock.write("221 2.0.0 Bye\r\n");
        else if (line) sock.write("500 5.5.1 Unknown\r\n");
      }
    });
  });
  await new Promise((r) => fake.listen(0, "127.0.0.1", r));
  const creds = { host: "127.0.0.1", port: fake.address().port, user: "ana@corp.example", password: "s3cret", tls: false };

  const raw = Buffer.from("Subject: Test\r\n\r\nbody line\r\n.dotted line\r\n");
  const result = await sendMail(creds, "ana@corp.example", ["bob@partner.example", "nope@partner.example"], raw);
  ok("smtp: authenticates with AUTH LOGIN", seen.auth === "ana@corp.example");
  ok("smtp: survives multi-line greetings and EHLO", seen.from === "MAIL FROM:<ana@corp.example>");
  ok("smtp: reports a partial send rather than failing", result.accepted.length === 1 && result.rejected.length === 1 && /550/.test(result.rejected[0].reply));
  ok("smtp: the body arrives un-truncated and un-stuffed", seen.data.includes("body line") && seen.data.includes(".dotted line") && !seen.data.includes("..dotted"));
  ok("smtp: returns the queue id the server gave", /ABC123/.test(result.response));

  let threw = "";
  await sendMail(creds, "ana@corp.example", ["nope@partner.example"], raw).catch((e) => { threw = e.message; });
  ok("smtp: every recipient refused is an error", /Every recipient was refused/.test(threw), threw);
  fake.close();
}

// ---- RFC 2047: folded encoded-words --------------------------------------
{
  const { decodeWords } = await import("../dist/core/parse.js");

  // Encoders break long headers wherever the 75-column limit falls, so a
  // Spanish or Japanese subject almost always arrives as several words. The
  // whitespace between two of them is a fold and must be discarded — leaving
  // it in puts a space inside a word and every subject rule misses.
  ok("2047: adjacent encoded-words join without a space",
    decodeWords("=?UTF-8?B?Q29uZmlybWFjacOzbiBkZSBsYSA=?= =?UTF-8?B?dHJhbnNmZXJlbmNpYQ==?=") === "Confirmación de la transferencia",
    decodeWords("=?UTF-8?B?Q29uZmlybWFjacOzbiBkZSBsYSA=?= =?UTF-8?B?dHJhbnNmZXJlbmNpYQ==?="));
  ok("2047: a fold across lines joins too",
    decodeWords("=?UTF-8?B?Q29uZmlybWFjacOzbiBkZSBsYSA=?=\r\n =?UTF-8?B?dHJhbnNmZXJlbmNpYQ==?=") === "Confirmación de la transferencia");
  ok("2047: quoted-printable words join as well",
    decodeWords("=?UTF-8?Q?Confirmaci=C3=B3n_de_la_?= =?UTF-8?Q?transferencia?=") === "Confirmación de la transferencia");
  // A space that is not between two encoded-words is a real space.
  ok("2047: a real space before plain text survives", decodeWords("=?UTF-8?B?SG9sYQ==?= mundo") === "Hola mundo");
  ok("2047: a real space after plain text survives", decodeWords("Re: =?UTF-8?B?QcOxbw==?=") === "Re: Año");
  ok("2047: plain subjects are untouched", decodeWords("Invoice INV-2026-0418") === "Invoice INV-2026-0418");

  // And what we compose must survive our own parser.
  const { buildMime } = await import("../dist/mailbox/compose.js");
  const long = "ñ".repeat(60);
  const round = parseMessage(buildMime({ from: "a@x.example", to: ["b@y.example"], cc: [], bcc: [], subject: long, text: "x", html: "", attachments: [] }));
  ok("2047: a long composed subject round-trips through our parser", round.subject === long, round.subject.slice(0, 30));
}

// ---- Audit trail and the SIEM webhook ---------------------------------------
{
  const http = await import("node:http");
  const { audit, auditAnalysis, recentEvents, resetWebhookState } = await import("../dist/core/audit.js");

  const AUDIT_DIR = "./.smoke-audit";
  rmSync(AUDIT_DIR, { recursive: true, force: true });

  // A fake SIEM that records what it was sent.
  const received = [];
  const sink = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => { body += c; });
    req.on("end", () => {
      received.push({ auth: req.headers.authorization || "", body });
      res.writeHead(204); res.end();
    });
  });
  await new Promise((r) => sink.listen(0, "127.0.0.1", r));
  const sinkUrl = `http://127.0.0.1:${sink.address().port}/events`;

  resetWebhookState();
  const auditConfig = { ...config, outDir: AUDIT_DIR, webhookUrl: sinkUrl, webhookToken: "s3cret", auditMinVerdict: "suspicious" };

  auditAnalysis(auditConfig, byId["bec-ceo-fraud"]);
  auditAnalysis(auditConfig, byId["clean-invoice"]);
  audit(auditConfig, { action: "policy.blocked", from: "@rival.example", detail: "test" });

  const events = recentEvents(auditConfig, 50);
  ok("audit: records a malicious verdict", events.some((e) => e.action === "message.analysed" && e.verdict === "malicious"));
  ok("audit: skips clean mail below the threshold", !events.some((e) => e.verdict === "clean"));
  ok("audit: records policy changes", events.some((e) => e.action === "policy.blocked" && e.from === "@rival.example"));
  ok("audit: newest first", events[0].action === "policy.blocked");
  ok("audit: stamps the product and version", events.every((e) => e.product === "MailAegis" && typeof e.version === "string"));

  // The trail is a record of decisions, not a second copy of everyone's mail.
  const raw = readFileSync(`${AUDIT_DIR}/audit.jsonl`, "utf8");
  const becSubject = byId["bec-ceo-fraud"].message.subject;
  ok("audit: never carries the subject or body", !raw.includes(becSubject) && !raw.includes("bank account details"), becSubject);
  ok("audit: carries rule names, not their evidence", /"rules":\["/.test(raw) && !raw.includes("m.torres.ceo@gmail.com\",\"evidence"));

  // Give the fire-and-forget POSTs a moment to land.
  await new Promise((r) => setTimeout(r, 700));
  ok("siem: forwards events to the webhook", received.length >= 2, `${received.length} received`);
  ok("siem: sends the bearer token", received.every((r) => r.auth === "Bearer s3cret"));
  ok("siem: the payload is the event", (() => { try { return JSON.parse(received[0].body).action === "message.analysed"; } catch { return false; } })());

  // An unreachable endpoint must never throw or block.
  resetWebhookState();
  let blew = false;
  try { audit({ ...auditConfig, webhookUrl: "http://127.0.0.1:1/nope" }, { action: "policy.removed", from: "x" }); }
  catch { blew = true; }
  ok("siem: an unreachable endpoint is survivable", !blew);

  sink.close();
  rmSync(AUDIT_DIR, { recursive: true, force: true });
}

// ---- Sender lists: the safety property is the whole point -------------------
{
  const { entryMatches, normaliseEntry, senderIsProven } = await import("../dist/core/lists.js");

  ok("lists: an address rule matches only that address",
    entryMatches("ana@corp.example", "ana@corp.example") && !entryMatches("ana@corp.example", "bob@corp.example"));
  ok("lists: a domain rule matches the domain",
    entryMatches("@corp.example", "anyone@corp.example") && !entryMatches("@corp.example", "anyone@other.example"));
  ok("lists: a domain rule is not defeated by a subdomain",
    entryMatches("@rival.example", "spam@mail.rival.example"));
  ok("lists: a domain rule does not match a look-alike suffix",
    !entryMatches("@rival.example", "spam@notrival.example"));
  ok("lists: a bare domain is normalised to a domain rule",
    normaliseEntry("Corp.Example") === "@corp.example" && normaliseEntry(" ana@Corp.Example ") === "ana@corp.example");

  // The allow list must never take effect on an unauthenticated message: if it
  // did, spoofing an allow-listed sender would be the cheapest way past every
  // other engine.
  ok("lists: DMARC pass proves the sender", senderIsProven({ spf: "none", dkim: "none", dmarc: "pass", alignmentMismatch: false }));
  ok("lists: SPF+DKIM aligned proves the sender", senderIsProven({ spf: "pass", dkim: "pass", dmarc: "none", alignmentMismatch: false }));
  ok("lists: SPF+DKIM misaligned does NOT prove the sender", !senderIsProven({ spf: "pass", dkim: "pass", dmarc: "none", alignmentMismatch: true }));
  ok("lists: SPF alone does NOT prove the sender", !senderIsProven({ spf: "pass", dkim: "fail", dmarc: "none", alignmentMismatch: false }));
  ok("lists: a DMARC failure never proves the sender", !senderIsProven({ spf: "pass", dkim: "pass", dmarc: "fail", alignmentMismatch: false }));
}

// ---- Update channel: the rules that decide whether a user gets nagged -------
{
  const { interpretFeed, compareVersions } = await import("../dist/core/updates.js");
  const now = new Date("2026-07-22T12:00:00Z");

  ok("channel: semver ordering", compareVersions("1.10.0", "1.9.0") > 0 && compareVersions("1.2.0", "1.2.0") === 0);
  ok("channel: a final release beats its own pre-release", compareVersions("1.2.0", "1.2.0-rc.1") > 0);

  const feed = {
    latest: { version: "1.2.0", changelog: ["a", "b"], url: "https://example.com/r", downloads: { win: "https://example.com/w.exe" } },
    announcements: [
      { id: "always", title: "Always" },
      { id: "expired", title: "Expired", ends: "2026-01-01" },
      { id: "future", title: "Future", starts: "2027-01-01" },
      { id: "newer-only", title: "Newer only", minVersion: "9.0.0" },
      { id: "no-title" },
      { id: "bad-link", title: "Bad link", link: { url: "javascript:alert(1)" } },
    ],
  };
  const seen = interpretFeed(feed, "1.1.0", now);
  ok("channel: offers a newer release", seen.update && seen.update.version === "1.2.0" && seen.update.changelog.length === 2);
  ok("channel: stays silent when already current", interpretFeed(feed, "1.2.0", now).update === null);
  ok("channel: stays silent when ahead of the feed", interpretFeed(feed, "1.3.0", now).update === null);

  const ids = seen.announcements.map((a) => a.id);
  ok("channel: honours date windows", ids.includes("always") && !ids.includes("expired") && !ids.includes("future"), ids.join(","));
  ok("channel: honours version targeting", !ids.includes("newer-only"));
  ok("channel: drops entries with no title", !ids.includes("no-title"));
  ok("channel: refuses non-https links", seen.announcements.find((a) => a.id === "bad-link").link === null);
  ok("channel: survives a malformed feed", interpretFeed(null, "1.1.0", now).announcements.length === 0);
}

let pass = 0, fail = 0;
for (const t of results) { if (t.ok) { pass++; console.log(`  \x1b[32m✓\x1b[0m ${t.name}`); } else { fail++; console.log(`  \x1b[31m✗ ${t.name}\x1b[0m  ${t.detail}`); } }
console.log(`\nTOTAL: ${pass} passed, ${fail} failed`);
process.exitCode = fail ? 1 : 0;
