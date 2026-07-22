/**
 * The analysis pipeline.
 *
 * parse → authenticate → in-house heuristics → ClamAV → VirusTotal → score.
 *
 * Each engine contributes `Finding`s with a weight; the total (capped at 100)
 * becomes the risk score, and the configured thresholds turn that into a
 * verdict. The report always records which engines actually ran, so an
 * "all clear" from a degraded pipeline can never be mistaken for a real one.
 *
 * Part of MailAegis — Corporate Email Threat Analyzer.
 * Crafted by SoyRage Agency — https://soyrage.es/
 * Licensed under the SoyRage Attribution License (see LICENSE).
 */

import { randomBytes } from "node:crypto";
import type { AppConfig } from "../config.js";
import { evaluateAuth } from "./auth.js";
import { clamEnabled, scanAttachment } from "./clamav.js";
import { runHeuristics } from "./engine.js";
import { hybridEnabled, lookupHash } from "./hybrid.js";
import { senderLists } from "./lists.js";
import { parseMessage } from "./parse.js";
import { buildTrace, traceFindings } from "./trace.js";
import type { Analysis, Finding, ParsedMessage, Verdict } from "./types.js";
import { lookupFile, lookupIp, lookupUrl, vtEnabled } from "./virustotal.js";

/** Cap the number of URLs sent to VirusTotal (public API quotas are small). */
const MAX_URL_LOOKUPS = 20;

/** A short, sortable analysis id. */
function analysisId(): string {
  const d = new Date();
  const stamp = `${d.getUTCFullYear()}${String(d.getUTCMonth() + 1).padStart(2, "0")}${String(d.getUTCDate()).padStart(2, "0")}`;
  return `MA-${stamp}-${randomBytes(3).toString("hex")}`;
}

/** Turn the raw score into a verdict using the configured thresholds. */
export function verdictFor(score: number, config: AppConfig): Verdict {
  if (score >= config.quarantineScore) return "malicious";
  if (score >= config.suspiciousScore) return "suspicious";
  return "clean";
}

/** Analyse an already-parsed message. */
export async function analyzeParsed(message: ParsedMessage, config: AppConfig): Promise<Analysis> {
  const auth = evaluateAuth(message);
  const findings: Finding[] = runHeuristics(message, auth, config);

  // ---- Delivery path ------------------------------------------------------
  const trace = buildTrace(message.received);
  findings.push(...traceFindings(trace, message.from.domain));

  const scannable = message.attachments.filter((a) => a.size <= config.maxAttachmentMb * 1024 * 1024);

  // ---- ClamAV -------------------------------------------------------------
  const clamav = clamEnabled(config)
    ? await Promise.all(scannable.map((a) => scanAttachment(a, config)))
    : [];
  for (const r of clamav) {
    if (r.infected) {
      findings.push({
        rule: "clamav-detection", severity: "critical", source: "clamav",
        title: "ClamAV detected malware",
        detail: `"${r.filename}" matched the signature ${r.signature ?? "(unnamed)"}.`,
        score: 50, evidence: r.signature,
      });
    } else if (r.error) {
      findings.push({
        rule: "clamav-error", severity: "info", source: "clamav",
        title: "ClamAV could not scan an attachment",
        detail: `"${r.filename}": ${r.error}`, score: 3, evidence: r.filename,
      });
    }
  }

  // ---- VirusTotal ---------------------------------------------------------
  const virustotal = [];
  if (vtEnabled(config)) {
    virustotal.push(...(await Promise.all(scannable.map((a) => lookupFile(a, config)))));
    virustotal.push(...(await Promise.all(message.urls.slice(0, MAX_URL_LOOKUPS).map((u) => lookupUrl(u, config)))));
  }
  for (const r of virustotal) {
    const label = r.kind === "file" ? "attachment" : "link";
    if (r.error) {
      findings.push({ rule: "virustotal-error", severity: "info", source: "virustotal", title: "VirusTotal lookup failed", detail: `${label} ${r.target.slice(0, 60)}: ${r.error}`, score: 2 });
      continue;
    }
    if (r.malicious >= config.vtMaliciousThreshold) {
      findings.push({
        rule: r.kind === "file" ? "virustotal-file-malicious" : "virustotal-url-malicious",
        severity: "critical", source: "virustotal",
        title: `VirusTotal flags this ${label}`,
        detail: `${r.malicious} engines report it as malicious${r.detections.length ? ` (${r.detections.slice(0, 3).join("; ")})` : ""}.`,
        score: r.kind === "file" ? 45 : 32, evidence: r.target,
      });
    } else if (r.malicious > 0 || r.suspicious > 0) {
      findings.push({
        rule: "virustotal-low-detection", severity: "medium", source: "virustotal",
        title: `VirusTotal has a few detections for this ${label}`,
        detail: `${r.malicious} malicious / ${r.suspicious} suspicious — below the configured threshold of ${config.vtMaliciousThreshold}.`,
        score: 12, evidence: r.target,
      });
    } else if (r.unknown && r.kind === "file") {
      findings.push({
        rule: "virustotal-unknown-file", severity: "low", source: "virustotal",
        title: "Attachment is unknown to VirusTotal",
        detail: "Never-before-seen files arriving at a company deserve a second look.",
        score: 8, evidence: r.target,
      });
    }
  }

  // ---- Hybrid Analysis (behavioural sandbox verdicts) ---------------------
  const hybrid = hybridEnabled(config) ? await Promise.all(scannable.map((a) => lookupHash(a, config))) : [];
  for (const h of hybrid) {
    if (h.error) {
      findings.push({ rule: "hybrid-error", severity: "info", source: "hybrid", title: "Hybrid Analysis lookup failed", detail: h.error, score: 2 });
      continue;
    }
    if (h.verdict === "malicious") {
      findings.push({
        rule: "hybrid-malicious", severity: "critical", source: "hybrid",
        title: "Sandbox detonation says malicious",
        detail: `Hybrid Analysis scored ${h.threatScore}/100 (${h.threatLevel || "malicious"})${h.avDetect ? `, ${h.avDetect}% of AV engines agree` : ""}.`,
        score: 45, evidence: h.submitName || h.sha256,
      });
    } else if (h.verdict === "suspicious") {
      findings.push({
        rule: "hybrid-suspicious", severity: "high", source: "hybrid",
        title: "Sandbox detonation says suspicious",
        detail: `Hybrid Analysis scored ${h.threatScore}/100 in ${h.environment || "a sandbox"}.`,
        score: 24, evidence: h.submitName || h.sha256,
      });
    }
  }

  // ---- Reputation of the IP the message really came from ------------------
  let ipReputation;
  if (vtEnabled(config) && trace.originatingIp) {
    ipReputation = await lookupIp(trace.originatingIp, config);
    if (ipReputation.malicious >= config.vtMaliciousThreshold) {
      findings.push({
        rule: "origin-ip-reputation", severity: "high", source: "virustotal",
        title: "The originating IP has a bad reputation",
        detail: `${trace.originatingIp} is flagged by ${ipReputation.malicious} engines${ipReputation.detections.length ? ` (${ipReputation.detections.slice(0, 2).join("; ")})` : ""}.`,
        score: 28, evidence: trace.originatingIp,
      });
    } else if (ipReputation.malicious > 0 || ipReputation.suspicious > 0) {
      findings.push({
        rule: "origin-ip-low-reputation", severity: "medium", source: "virustotal",
        title: "The originating IP has some detections",
        detail: `${trace.originatingIp}: ${ipReputation.malicious} malicious / ${ipReputation.suspicious} suspicious.`,
        score: 12, evidence: trace.originatingIp,
      });
    }
  }

  // ---- Sender lists -------------------------------------------------------
  // Applied last, so a decision is made against everything the engines found
  // rather than short-circuiting them: a block still shows you why the message
  // was bad, and an allow still shows you what it suppressed.
  const decision = senderLists(config.outDir).decide(message.from.address, auth);

  if (decision.blocked) {
    findings.push({
      rule: "sender-blocked", severity: "critical", source: "policy",
      title: "The sender is on your block list",
      detail: decision.blocked.note
        ? `Blocked by "${decision.blocked.value}" — ${decision.blocked.note}`
        : `Blocked by the rule "${decision.blocked.value}".`,
      score: 100, evidence: message.from.address,
    });
  }

  // Only findings the heuristic engine raised can be waived, and only for a
  // sender that proved who it is. A scanner detection is never waived.
  const waivable = new Set(["heuristics", "auth"]);
  const suppressed = decision.allowHonoured
    ? findings.filter((f) => waivable.has(f.source) && f.severity !== "critical")
    : [];
  const counted = suppressed.length ? findings.filter((f) => !suppressed.includes(f)) : findings;

  if (decision.allowed && !decision.allowHonoured) {
    findings.push({
      rule: "allow-list-not-honoured", severity: "medium", source: "policy",
      title: "Allow-listed sender, but the message did not authenticate",
      detail: `"${decision.allowed.value}" is on your allow list, which is why this was not waived: the message fails DMARC (and SPF/DKIM alignment), so there is nothing proving it really came from them. Spoofing an allow-listed sender is the cheapest way past a filter.`,
      score: 10, evidence: message.from.address,
    });
  } else if (suppressed.length) {
    findings.push({
      rule: "allow-list-applied", severity: "info", source: "policy",
      title: `Allow list waived ${suppressed.length} heuristic finding(s)`,
      detail: `"${decision.allowed!.value}" is on your allow list and the message authenticated, so tone and identity heuristics were not counted. Scanner detections are never waived.`,
      score: 0, evidence: suppressed.map((f) => f.title).join("; "),
    });
  }

  const score = Math.min(100, counted.reduce((sum, f) => sum + f.score, 0));
  const verdict = verdictFor(score, config);
  const critical = findings.filter((f) => f.severity === "critical").length;
  const high = findings.filter((f) => f.severity === "high").length;

  const summary = verdict === "malicious"
    ? `Quarantine: ${critical} critical and ${high} high-severity findings (score ${score}/100).`
    : verdict === "suspicious"
      ? `Suspicious: ${findings.length} finding(s), score ${score}/100 — review before delivery.`
      : findings.length === 0
        ? "Clean: nothing of concern found."
        : `Clean: only ${findings.length} low-weight observation(s), score ${score}/100.`;

  return {
    id: analysisId(),
    analysedAt: new Date().toISOString(),
    demo: config.demo,
    verdict,
    score,
    summary,
    message: {
      from: message.from,
      replyTo: message.replyTo,
      to: message.to,
      cc: message.cc,
      subject: message.subject,
      date: message.date,
      messageId: message.messageId,
      // Enough of the body to quote in a reply or a forward. Capped, because
      // an analysis is a summary and nobody needs a 4 MB newsletter inlined.
      textPreview: (message.text || "").slice(0, 4000),
      sizeBytes: message.rawSize,
      attachmentCount: message.attachments.length,
      urlCount: message.urls.length,
    },
    auth,
    trace: { ...trace, ipReputation },
    findings: findings.sort((a, b) => b.score - a.score),
    attachments: message.attachments.map(({ content, ...rest }) => { void content; return rest; }),
    urls: message.urls,
    virustotal,
    clamav,
    hybrid,
    engines: [
      { name: "Heuristics (MailAegis)", ran: true, note: "always on" },
      { name: "SPF / DKIM / DMARC", ran: true, note: "read from Authentication-Results" },
      { name: "Delivery path", ran: trace.hops.length > 0, note: trace.hops.length ? `${trace.hops.length} hop(s) reconstructed from Received headers` : "no Received headers present" },
      { name: "ClamAV", ran: clamEnabled(config), note: config.demo ? "simulated (demo mode)" : config.clamHost ? `clamd at ${config.clamHost}:${config.clamPort}` : "not configured — set CLAMAV_HOST" },
      { name: "VirusTotal", ran: vtEnabled(config), note: config.demo ? "simulated (demo mode)" : config.vtApiKey ? "API v3 file, URL & IP lookup" : "not configured — set VIRUSTOTAL_API_KEY" },
      { name: "Hybrid Analysis", ran: hybridEnabled(config), note: config.demo ? "simulated (demo mode)" : config.hybridApiKey ? "Falcon Sandbox hash search" : "not configured — set HYBRID_ANALYSIS_API_KEY" },
    ],
  };
}

/** Parse and analyse a raw `.eml` message. */
export function analyzeRaw(raw: Buffer | string, config: AppConfig): Promise<Analysis> {
  return analyzeParsed(parseMessage(raw), config);
}

/** Process exit code convention for mail-pipeline integration. */
export function exitCodeFor(verdict: Verdict): 0 | 1 | 2 {
  return verdict === "malicious" ? 2 : verdict === "suspicious" ? 1 : 0;
}
