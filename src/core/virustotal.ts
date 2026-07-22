/**
 * VirusTotal API v3 enrichment.
 *
 * Attachments are looked up by SHA-256 and URLs by their VirusTotal id — a
 * *lookup*, never an upload, so no corporate content ever leaves your network.
 * A 404 simply means "VirusTotal has never seen this", which for an attachment
 * arriving at a company is itself a mild signal.
 *
 * Without an API key (or in demo mode) the client returns simulated verdicts so
 * the whole pipeline stays testable offline.
 *
 * Part of MailAegis — Corporate Email Threat Analyzer.
 * Crafted by SoyRage Agency — https://soyrage.es/
 * Licensed under the SoyRage Attribution License (see LICENSE).
 */

import type { AppConfig } from "../config.js";
import type { Attachment, UrlRef, VtResult } from "./types.js";

/** The EICAR test string — every real engine flags it, so demos stay honest. */
const EICAR = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE";

const DEMO_ENGINES = ["Kaspersky", "ESET-NOD32", "Microsoft", "BitDefender", "Sophos", "Fortinet", "Avast", "McAfee"];

/** VirusTotal's URL identifier: unpadded base64url of the URL. */
export function urlId(url: string): string {
  return Buffer.from(url, "utf8").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Whether the VirusTotal enrichment is active. */
export function vtEnabled(config: AppConfig): boolean {
  return config.demo || config.vtApiKey !== "";
}

async function vtGet(path: string, config: AppConfig): Promise<{ status: number; body: unknown }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), config.vtTimeoutMs);
  try {
    const res = await fetch(`${config.vtEndpoint}${path}`, {
      headers: { "x-apikey": config.vtApiKey, accept: "application/json" },
      signal: controller.signal,
    });
    const body = res.status === 204 ? {} : await res.json().catch(() => ({}));
    return { status: res.status, body };
  } finally {
    clearTimeout(timer);
  }
}

interface VtStats { malicious?: number; suspicious?: number; harmless?: number; undetected?: number }

function fromAttributes(target: string, kind: "file" | "url", attributes: Record<string, unknown>): VtResult {
  const stats = (attributes.last_analysis_stats ?? {}) as VtStats;
  const results = (attributes.last_analysis_results ?? {}) as Record<string, { category?: string; result?: string }>;
  const detections = Object.entries(results)
    .filter(([, r]) => r.category === "malicious")
    .map(([engine, r]) => `${engine}: ${r.result ?? "malicious"}`)
    .slice(0, 8);
  return {
    target,
    kind,
    unknown: false,
    malicious: stats.malicious ?? 0,
    suspicious: stats.suspicious ?? 0,
    harmless: stats.harmless ?? 0,
    undetected: stats.undetected ?? 0,
    detections,
    link: kind === "file" ? `https://www.virustotal.com/gui/file/${target}` : `https://www.virustotal.com/gui/url/${urlId(target)}`,
  };
}

const unknownResult = (target: string, kind: "file" | "url"): VtResult => ({
  target, kind, unknown: true, malicious: 0, suspicious: 0, harmless: 0, undetected: 0, detections: [],
});

// ---- Demo simulation --------------------------------------------------------

function demoFile(attachment: Attachment): VtResult {
  const isEicar = attachment.content.includes(EICAR);
  const dangerous = ["exe", "scr", "js", "vbs", "docm", "xlsm", "hta", "jar"].includes(attachment.extension);
  if (isEicar || dangerous) {
    const malicious = isEicar ? 58 : 41;
    return {
      target: attachment.sha256, kind: "file", unknown: false,
      malicious, suspicious: 2, harmless: 0, undetected: 72 - malicious,
      detections: DEMO_ENGINES.slice(0, 5).map((e) => `${e}: ${isEicar ? "EICAR-Test-File" : "Trojan.GenericKD.72104"}`),
      link: `https://www.virustotal.com/gui/file/${attachment.sha256}`,
    };
  }
  if (["pdf", "docx", "xlsx", "png", "jpg", "txt"].includes(attachment.extension)) {
    return { target: attachment.sha256, kind: "file", unknown: false, malicious: 0, suspicious: 0, harmless: 68, undetected: 4, detections: [], link: `https://www.virustotal.com/gui/file/${attachment.sha256}` };
  }
  return unknownResult(attachment.sha256, "file");
}

function demoUrl(ref: UrlRef): VtResult {
  const bad = /(secure-|verify|login-|-portal|account-update|billing-)/i.test(ref.host) || /^\d{1,3}(\.\d{1,3}){3}$/.test(ref.host);
  if (bad) {
    return {
      target: ref.url, kind: "url", unknown: false, malicious: 12, suspicious: 3, harmless: 50, undetected: 25,
      detections: ["Fortinet: Phishing", "Kaspersky: Phishing", "Sophos: Phishing"],
      link: `https://www.virustotal.com/gui/url/${urlId(ref.url)}`,
    };
  }
  return { target: ref.url, kind: "url", unknown: false, malicious: 0, suspicious: 0, harmless: 72, undetected: 18, detections: [], link: `https://www.virustotal.com/gui/url/${urlId(ref.url)}` };
}

// ---- Public API -------------------------------------------------------------

/** Look up one attachment by hash. */
export async function lookupFile(attachment: Attachment, config: AppConfig): Promise<VtResult> {
  if (config.demo) return demoFile(attachment);
  try {
    const { status, body } = await vtGet(`/files/${attachment.sha256}`, config);
    if (status === 404) return unknownResult(attachment.sha256, "file");
    if (status !== 200) return { ...unknownResult(attachment.sha256, "file"), error: `VirusTotal returned ${status}` };
    const attributes = ((body as { data?: { attributes?: Record<string, unknown> } }).data?.attributes ?? {});
    return fromAttributes(attachment.sha256, "file", attributes);
  } catch (err) {
    return { ...unknownResult(attachment.sha256, "file"), error: (err as Error).message };
  }
}

/** Look up one URL. */
export async function lookupUrl(ref: UrlRef, config: AppConfig): Promise<VtResult> {
  if (config.demo) return demoUrl(ref);
  try {
    const { status, body } = await vtGet(`/urls/${urlId(ref.url)}`, config);
    if (status === 404) return unknownResult(ref.url, "url");
    if (status !== 200) return { ...unknownResult(ref.url, "url"), error: `VirusTotal returned ${status}` };
    const attributes = ((body as { data?: { attributes?: Record<string, unknown> } }).data?.attributes ?? {});
    return fromAttributes(ref.url, "url", attributes);
  } catch (err) {
    return { ...unknownResult(ref.url, "url"), error: (err as Error).message };
  }
}
