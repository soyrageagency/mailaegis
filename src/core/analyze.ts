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
import { parseMessage } from "./parse.js";
import type { Analysis, Finding, ParsedMessage, Verdict } from "./types.js";
import { lookupFile, lookupUrl, vtEnabled } from "./virustotal.js";

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

  const score = Math.min(100, findings.reduce((sum, f) => sum + f.score, 0));
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
      subject: message.subject,
      date: message.date,
      messageId: message.messageId,
      sizeBytes: message.rawSize,
      attachmentCount: message.attachments.length,
      urlCount: message.urls.length,
    },
    auth,
    findings: findings.sort((a, b) => b.score - a.score),
    attachments: message.attachments.map(({ content, ...rest }) => { void content; return rest; }),
    urls: message.urls,
    virustotal,
    clamav,
    engines: [
      { name: "Heuristics (MailAegis)", ran: true, note: "always on" },
      { name: "SPF / DKIM / DMARC", ran: true, note: "read from Authentication-Results" },
      { name: "ClamAV", ran: clamEnabled(config), note: config.demo ? "simulated (demo mode)" : config.clamHost ? `clamd at ${config.clamHost}:${config.clamPort}` : "not configured — set CLAMAV_HOST" },
      { name: "VirusTotal", ran: vtEnabled(config), note: config.demo ? "simulated (demo mode)" : config.vtApiKey ? "API v3 hash & URL lookup" : "not configured — set VIRUSTOTAL_API_KEY" },
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
