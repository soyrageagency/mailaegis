/**
 * The in-house detection engine.
 *
 * This is MailAegis' own opinion, independent of any external service: it
 * reasons about *identity* (display-name spoofing, look-alike domains, reply-to
 * divergence), *payload* (dangerous and double extensions, macro-enabled Office
 * files, magic-byte/extension mismatch, executables hidden inside archives),
 * *links* (anchor-text deception, IP-literal hosts, punycode, shorteners) and
 * *intent* (BEC wording: bank-detail changes, urgency, gift cards, credential
 * harvesting).
 *
 * Every rule returns a `Finding` with a score; `score.ts` turns them into a
 * verdict. Rules are pure and side-effect free, so they are trivially testable.
 *
 * Part of MailAegis — Corporate Email Threat Analyzer.
 * Crafted by SoyRage Agency — https://soyrage.es/
 * Licensed under the SoyRage Attribution License (see LICENSE).
 */

import type { AppConfig } from "../config.js";
import { baseDomain } from "./auth.js";
import type { AuthResults, Finding, ParsedMessage } from "./types.js";

const MACRO_EXTENSIONS = new Set(["docm", "xlsm", "pptm", "dotm", "xltm", "xlam"]);
const ARCHIVE_EXTENSIONS = new Set(["zip", "7z", "rar", "gz", "tar", "iso", "img"]);
const SHORTENERS = new Set([
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
  "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "s.id",
]);
const FREEMAIL = new Set([
  "gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "aol.com",
  "proton.me", "protonmail.com", "gmx.com", "mail.com", "yandex.com",
]);
const EXEC_TITLES = /\b(ceo|cfo|coo|cto|president|director|managing director|head of finance|chief)\b/i;

/** Levenshtein distance, capped for speed. */
function distance(a: string, b: string): number {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > 3) return 99;
  const prev = new Array<number>(b.length + 1);
  for (let j = 0; j <= b.length; j++) prev[j] = j;
  for (let i = 1; i <= a.length; i++) {
    let last = prev[0];
    prev[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const tmp = prev[j];
      prev[j] = Math.min(prev[j] + 1, prev[j - 1] + 1, last + (a[i - 1] === b[j - 1] ? 0 : 1));
      last = tmp;
    }
  }
  return prev[b.length];
}

/** Fold characters commonly used to build look-alike domains. */
function deconfuse(domain: string): string {
  return domain
    .replace(/0/g, "o").replace(/1/g, "l").replace(/3/g, "e").replace(/5/g, "s")
    .replace(/rn/g, "m").replace(/vv/g, "w").replace(/-/g, "");
}

/** Sniff a file's real type from its leading bytes. */
export function magicType(content: Buffer): string {
  if (content.length >= 2 && content[0] === 0x4d && content[1] === 0x5a) return "exe";
  if (content.length >= 4 && content.subarray(0, 4).toString("ascii") === "%PDF") return "pdf";
  if (content.length >= 4 && content[0] === 0x50 && content[1] === 0x4b) return "zip";
  if (content.length >= 8 && content.subarray(0, 8).toString("hex") === "d0cf11e0a1b11ae1") return "ole";
  if (content.length >= 3 && content[0] === 0x1f && content[1] === 0x8b) return "gzip";
  if (content.length >= 4 && content.subarray(0, 4).toString("ascii") === "Rar!") return "rar";
  return "";
}

/** List entry names inside a ZIP by walking its central directory. */
export function zipEntries(content: Buffer): { names: string[]; encrypted: boolean } {
  const names: string[] = [];
  let encrypted = false;
  // Central directory file headers start with PK\x01\x02.
  for (let i = 0; i + 46 <= content.length; i++) {
    if (content[i] === 0x50 && content[i + 1] === 0x4b && content[i + 2] === 0x01 && content[i + 3] === 0x02) {
      const flags = content.readUInt16LE(i + 8);
      const nameLen = content.readUInt16LE(i + 28);
      const extraLen = content.readUInt16LE(i + 30);
      const commentLen = content.readUInt16LE(i + 32);
      const name = content.subarray(i + 46, i + 46 + nameLen).toString("utf8");
      if (name) names.push(name);
      if (flags & 0x1) encrypted = true;
      i += 46 + nameLen + extraLen + commentLen - 1;
      if (names.length > 500) break;
    }
  }
  return { names, encrypted };
}

const add = (out: Finding[], f: Finding) => { out.push(f); };

/** Run every in-house rule over a parsed message. */
export function runHeuristics(message: ParsedMessage, auth: AuthResults, config: AppConfig): Finding[] {
  const findings: Finding[] = [];
  const corporate = config.corporateDomains.map(baseDomain).filter(Boolean);
  const fromBase = baseDomain(message.from.domain);
  const isInternalSender = corporate.includes(fromBase);

  // ---- Authentication -----------------------------------------------------
  if (auth.spf === "fail") add(findings, { rule: "spf-fail", severity: "high", title: "SPF failed", detail: "The sending server is not authorised to send for this domain.", score: 25, source: "auth" });
  else if (auth.spf === "softfail") add(findings, { rule: "spf-softfail", severity: "medium", title: "SPF soft-failed", detail: "The sending server is not listed, but the domain only asks for a soft fail.", score: 12, source: "auth" });
  if (auth.dkim === "fail") add(findings, { rule: "dkim-fail", severity: "medium", title: "DKIM signature invalid", detail: "The message body or headers were altered after signing.", score: 18, source: "auth" });
  if (auth.dmarc === "fail") add(findings, { rule: "dmarc-fail", severity: "high", title: "DMARC failed", detail: "The message fails the domain's published DMARC policy.", score: 28, source: "auth" });
  if (auth.alignmentMismatch) add(findings, { rule: "envelope-misalignment", severity: "medium", title: "Envelope/From mismatch", detail: `Return-Path domain "${message.returnPath?.domain}" does not align with From domain "${message.from.domain}".`, score: 14, source: "auth" });

  // ---- Identity & BEC -----------------------------------------------------
  const displayName = message.from.name;
  if (displayName) {
    const embedded = /[\w.+-]+@[\w.-]+\.\w+/.exec(displayName);
    if (embedded && embedded[0].toLowerCase() !== message.from.address) {
      add(findings, { rule: "display-name-address-spoof", severity: "high", title: "Display name contains a different address", detail: `Shows "${embedded[0]}" but actually sends from "${message.from.address}".`, score: 30, source: "heuristics", evidence: displayName });
    }
    for (const domain of corporate) {
      if (displayName.toLowerCase().includes(domain) && !isInternalSender) {
        add(findings, { rule: "display-name-brand-spoof", severity: "high", title: "Display name impersonates a corporate domain", detail: `Display name mentions "${domain}" but the message comes from "${message.from.domain}".`, score: 28, source: "heuristics", evidence: displayName });
        break;
      }
    }
    if (EXEC_TITLES.test(displayName) && !isInternalSender && FREEMAIL.has(message.from.domain)) {
      add(findings, { rule: "exec-impersonation", severity: "critical", title: "Executive impersonation from a free mailbox", detail: `An executive-sounding display name ("${displayName}") sending from the consumer domain "${message.from.domain}" is the classic BEC pattern.`, score: 38, source: "heuristics" });
    }
  }

  // Look-alike detection has two shapes: a typo-squat of the whole domain
  // (c0rp.example) and your brand embedded in a foreign domain
  // (c0rp-example.com, corp-example.attacker.net). Separators and common
  // character swaps are folded away before comparing.
  const flatten = (d: string) => deconfuse(d.toLowerCase().replace(/[.\-_]/g, ""));
  const fromFlat = flatten(message.from.domain);
  for (const domain of corporate) {
    if (fromBase === domain) continue; // genuinely ours (incl. subdomains)
    const corpFlat = flatten(domain);
    const typo = distance(deconfuse(fromBase), deconfuse(domain));
    const embeds = corpFlat.length >= 6 && fromFlat !== corpFlat && fromFlat.includes(corpFlat);
    if ((typo > 0 && typo <= 2) || embeds) {
      const detail = embeds
        ? `"${message.from.domain}" embeds your domain name "${domain}" but is not one of yours.`
        : `"${message.from.domain}" is only ${typo} character(s) away from your domain "${domain}".`;
      add(findings, { rule: "lookalike-domain", severity: "high", title: "Look-alike sender domain", detail, score: 32, source: "heuristics", evidence: message.from.domain });
      break;
    }
  }

  if (message.replyTo && message.replyTo.address && message.replyTo.address !== message.from.address) {
    const replyBase = baseDomain(message.replyTo.domain);
    if (replyBase !== fromBase) {
      add(findings, { rule: "reply-to-divergence", severity: "medium", title: "Replies go to a different domain", detail: `From "${message.from.address}" but replies are directed to "${message.replyTo.address}".`, score: 20, source: "heuristics", evidence: message.replyTo.address });
    }
  }

  // ---- Attachments --------------------------------------------------------
  for (const a of message.attachments) {
    const lower = a.filename.toLowerCase();
    if (config.blockedExtensions.includes(a.extension)) {
      add(findings, { rule: "dangerous-attachment", severity: "critical", title: "Executable attachment", detail: `"${a.filename}" has the blocked extension .${a.extension}.`, score: 45, source: "heuristics", evidence: a.filename });
    }
    if (/\.(pdf|doc|docx|xls|xlsx|jpg|png|txt|zip)\.[a-z0-9]{2,4}$/i.test(lower)) {
      add(findings, { rule: "double-extension", severity: "critical", title: "Double file extension", detail: `"${a.filename}" hides its real type behind a decoy extension.`, score: 40, source: "heuristics", evidence: a.filename });
    }
    if (MACRO_EXTENSIONS.has(a.extension)) {
      add(findings, { rule: "macro-document", severity: "high", title: "Macro-enabled Office document", detail: `"${a.filename}" can execute code when opened.`, score: 26, source: "heuristics", evidence: a.filename });
    }
    const magic = magicType(a.content);
    if (magic === "exe" && a.extension !== "exe") {
      add(findings, { rule: "magic-mismatch", severity: "critical", title: "File content is an executable", detail: `"${a.filename}" declares .${a.extension || "?"} but its bytes are a Windows executable.`, score: 45, source: "heuristics", evidence: a.filename });
    } else if (magic === "pdf" && a.extension && a.extension !== "pdf") {
      add(findings, { rule: "magic-mismatch-soft", severity: "low", title: "Extension does not match content", detail: `"${a.filename}" is really a PDF.`, score: 5, source: "heuristics", evidence: a.filename });
    }
    if (magic === "zip" || ARCHIVE_EXTENSIONS.has(a.extension)) {
      const { names, encrypted } = zipEntries(a.content);
      const risky = names.filter((n) => config.blockedExtensions.includes((n.split(".").pop() ?? "").toLowerCase()));
      if (risky.length) {
        add(findings, { rule: "archive-contains-executable", severity: "critical", title: "Archive contains an executable", detail: `"${a.filename}" contains ${risky.slice(0, 3).join(", ")}.`, score: 45, source: "heuristics", evidence: risky.join(", ") });
      }
      if (encrypted) {
        add(findings, { rule: "encrypted-archive", severity: "medium", title: "Password-protected archive", detail: `"${a.filename}" is encrypted, so no scanner can inspect its contents.`, score: 22, source: "heuristics", evidence: a.filename });
      }
    }
    if (a.size > config.maxAttachmentMb * 1024 * 1024) {
      add(findings, { rule: "oversized-attachment", severity: "info", title: "Attachment exceeds the scan limit", detail: `"${a.filename}" is ${(a.size / 1048576).toFixed(1)} MB and was not sent to the scanners.`, score: 4, source: "heuristics", evidence: a.filename });
    }
  }

  // ---- Links --------------------------------------------------------------
  for (const u of message.urls) {
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(u.host)) {
      add(findings, { rule: "ip-literal-url", severity: "high", title: "Link points at a bare IP address", detail: `Legitimate corporate links use names, not "${u.host}".`, score: 24, source: "heuristics", evidence: u.url });
    }
    if (SHORTENERS.has(u.host)) {
      add(findings, { rule: "url-shortener", severity: "medium", title: "Shortened link hides its destination", detail: `"${u.host}" conceals where the user actually lands.`, score: 14, source: "heuristics", evidence: u.url });
    }
    if (u.host.startsWith("xn--") || u.host.includes(".xn--")) {
      add(findings, { rule: "punycode-url", severity: "medium", title: "Internationalised (punycode) link host", detail: `"${u.host}" can render as a look-alike of a familiar brand.`, score: 18, source: "heuristics", evidence: u.url });
    }
    // Anchor text claims one domain, href goes somewhere else.
    if (u.text) {
      const claimed = /(?:https?:\/\/)?((?:[\w-]+\.)+[a-z]{2,})/i.exec(u.text);
      if (claimed) {
        const claimedBase = baseDomain(claimed[1].toLowerCase());
        const realBase = baseDomain(u.host);
        if (claimedBase && realBase && claimedBase !== realBase) {
          add(findings, { rule: "anchor-text-deception", severity: "high", title: "Link text does not match its destination", detail: `The text says "${claimed[1]}" but the link goes to "${u.host}".`, score: 30, source: "heuristics", evidence: u.url });
        }
      }
    }
    if (/\b(login|signin|verify|account|password|secure|update|confirm)\b/i.test(u.url) && !corporate.includes(baseDomain(u.host))) {
      add(findings, { rule: "credential-landing", severity: "medium", title: "External credential-style landing page", detail: `"${u.host}" asks for a sign-in flow but is not one of your domains.`, score: 16, source: "heuristics", evidence: u.url });
    }
  }

  // ---- Intent -------------------------------------------------------------
  const body = `${message.subject}\n${message.text}\n${message.html.replace(/<[^>]+>/g, " ")}`.toLowerCase();
  const intent: Array<[RegExp, string, string, number]> = [
    [/\b(change|update|new)\b[^.]{0,40}\b(bank|iban|account)\b[^.]{0,40}\b(details|number|information)\b/, "bank-detail-change", "Request to change bank details", 34],
    [/\b(wire|transfer|remit)\b[^.]{0,40}\b(urgent|immediately|today|asap)\b/, "urgent-payment", "Urgent payment request", 24],
    [/\b(gift card|steam card|itunes card|voucher code)\b/, "gift-card-scam", "Gift-card request", 26],
    [/\b(password|account)\b[^.]{0,30}\b(expire|expiring|suspend|suspended|deactivat)/, "credential-urgency", "Account-expiry pressure", 20],
    [/\b(confidential|do not (tell|inform|contact)|keep this between)\b/, "secrecy-pressure", "Secrecy pressure", 18],
    [/\b(invoice|payment)\b[^.]{0,30}\b(overdue|outstanding|final notice)\b/, "invoice-pressure", "Invoice pressure", 14],
  ];
  for (const [re, rule, title, score] of intent) {
    const m = re.exec(body);
    if (m) add(findings, { rule, severity: score >= 30 ? "high" : "medium", title, detail: "Language strongly associated with business e-mail compromise.", score, source: "heuristics", evidence: m[0].slice(0, 120) });
  }

  if (isInternalSender && (auth.spf === "fail" || auth.dmarc === "fail")) {
    add(findings, { rule: "internal-spoof", severity: "critical", title: "Spoofed internal sender", detail: `The message claims to be from your own domain "${fromBase}" but fails authentication.`, score: 40, source: "heuristics" });
  }

  return findings;
}
