/**
 * Hybrid Analysis (Falcon Sandbox) API v2 enrichment.
 *
 * A third opinion, and a qualitatively different one: where ClamAV matches
 * signatures and VirusTotal aggregates static engines, Hybrid Analysis reports
 * what a file actually *did* when detonated in a sandbox — its behavioural
 * threat score.
 *
 * We only ever *search by hash* (`GET /search/hash`), never submit a file, so
 * no corporate attachment is uploaded to a third party. A free "restricted"
 * API key is enough for hash lookups.
 *
 * Docs: https://hybrid-analysis.com/docs/api/v2
 *
 * Part of MailAegis — Corporate Email Threat Analyzer.
 * Crafted by SoyRage Agency — https://soyrage.es/
 * Licensed under the SoyRage Attribution License (see LICENSE).
 */

import type { AppConfig } from "../config.js";
import type { Attachment, HybridResult } from "./types.js";

const EICAR = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE";

/** Whether the Hybrid Analysis enrichment is active. */
export function hybridEnabled(config: AppConfig): boolean {
  return config.demo || config.hybridApiKey !== "";
}

const unknownResult = (sha256: string): HybridResult => ({
  sha256, unknown: true, verdict: "", threatScore: 0, threatLevel: "", avDetect: 0,
  submitName: "", fileType: "", environment: "",
});

/** One report entry as returned by /search/hash. */
interface HaReport {
  verdict?: string;
  threat_score?: number;
  threat_level?: number;
  threat_level_readable?: string;
  av_detect?: number;
  submit_name?: string;
  type?: string;
  type_short?: string[];
  environment_description?: string;
  sha256?: string;
  job_id?: string;
}

/** Pick the most alarming report when the sandbox returns several runs. */
function worstReport(reports: HaReport[]): HaReport | undefined {
  const rank = (r: HaReport) => (r.verdict === "malicious" ? 3 : r.verdict === "suspicious" ? 2 : r.verdict ? 1 : 0);
  return [...reports].sort((a, b) => rank(b) - rank(a) || (b.threat_score ?? 0) - (a.threat_score ?? 0))[0];
}

// ---- Demo simulation --------------------------------------------------------

function demoLookup(attachment: Attachment): HybridResult {
  const isEicar = attachment.content.includes(EICAR);
  const dangerous = ["exe", "scr", "js", "vbs", "docm", "xlsm", "hta", "jar"].includes(attachment.extension);
  if (isEicar || dangerous) {
    return {
      sha256: attachment.sha256, unknown: false,
      verdict: "malicious",
      threatScore: isEicar ? 100 : 87,
      threatLevel: "malicious",
      avDetect: isEicar ? 78 : 64,
      submitName: attachment.filename,
      fileType: dangerous ? "PE32 executable" : "ASCII text",
      environment: "Windows 10 64 bit",
      link: `https://hybrid-analysis.com/sample/${attachment.sha256}`,
    };
  }
  if (["pdf", "docx", "xlsx", "png", "jpg", "txt"].includes(attachment.extension)) {
    return {
      sha256: attachment.sha256, unknown: false, verdict: "no specific threat",
      threatScore: 0, threatLevel: "no threat", avDetect: 0,
      submitName: attachment.filename, fileType: attachment.contentType,
      environment: "Windows 10 64 bit",
      link: `https://hybrid-analysis.com/sample/${attachment.sha256}`,
    };
  }
  return unknownResult(attachment.sha256);
}

// ---- Public API -------------------------------------------------------------

/** Look up one attachment's hash in the sandbox database. */
export async function lookupHash(attachment: Attachment, config: AppConfig): Promise<HybridResult> {
  if (config.demo) return demoLookup(attachment);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), config.hybridTimeoutMs);
  try {
    const url = `${config.hybridEndpoint}/search/hash?hash=${encodeURIComponent(attachment.sha256)}`;
    const res = await fetch(url, {
      method: "GET",
      headers: {
        "api-key": config.hybridApiKey,
        // Falcon Sandbox rejects requests without its expected user agent.
        "user-agent": "Falcon Sandbox",
        accept: "application/json",
      },
      signal: controller.signal,
    });
    if (res.status === 404) return unknownResult(attachment.sha256);
    if (!res.ok) return { ...unknownResult(attachment.sha256), error: `Hybrid Analysis returned ${res.status}` };

    const body = (await res.json().catch(() => [])) as HaReport[] | HaReport;
    const reports = Array.isArray(body) ? body : [body];
    if (reports.length === 0) return unknownResult(attachment.sha256);

    const report = worstReport(reports);
    if (!report) return unknownResult(attachment.sha256);
    return {
      sha256: attachment.sha256,
      unknown: false,
      verdict: report.verdict ?? "",
      threatScore: Number(report.threat_score ?? 0),
      threatLevel: report.threat_level_readable ?? String(report.threat_level ?? ""),
      avDetect: Number(report.av_detect ?? 0),
      submitName: report.submit_name ?? "",
      fileType: report.type ?? (report.type_short ?? []).join(", "),
      environment: report.environment_description ?? "",
      link: `https://hybrid-analysis.com/sample/${attachment.sha256}`,
    };
  } catch (err) {
    return { ...unknownResult(attachment.sha256), error: (err as Error).message };
  } finally {
    clearTimeout(timer);
  }
}
