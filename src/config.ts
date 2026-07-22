/**
 * Runtime configuration.
 *
 * Driven by environment variables (a local `.env` is loaded automatically) so
 * the same binary runs unattended in a mail gateway, in CI, or interactively.
 *
 * Part of MailAegis — Corporate Email Threat Analyzer.
 * Crafted by SoyRage Agency — https://soyrage.es/
 * Licensed under the SoyRage Attribution License (see LICENSE).
 */

import { readFileSync, existsSync } from "node:fs";
import { resolve } from "node:path";
import type { LogLevel } from "./logger.js";

function loadDotEnv(): void {
  const path = resolve(process.cwd(), ".env");
  if (!existsSync(path)) return;
  for (const line of readFileSync(path, "utf8").split(/\r?\n/)) {
    const t = line.trim();
    if (!t || t.startsWith("#")) continue;
    const eq = t.indexOf("=");
    if (eq === -1) continue;
    const k = t.slice(0, eq).trim();
    let v = t.slice(eq + 1).trim();
    if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
    if (k && process.env[k] === undefined) process.env[k] = v;
  }
}

const flag = (n: string, d = false): boolean => {
  const v = process.env[n];
  return v === undefined || v === "" ? d : /^(1|true|yes|on)$/i.test(v.trim());
};
const str = (n: string, d = ""): string => (process.env[n] ?? d).trim();
const num = (n: string, d: number): number => {
  const v = Number(process.env[n]);
  return Number.isFinite(v) && v > 0 ? v : d;
};
const list = (n: string, d: string[] = []): string[] => {
  const v = process.env[n];
  if (v === undefined || v.trim() === "") return d;
  return v.split(",").map((x) => x.trim().toLowerCase()).filter(Boolean);
};

/** Fully-resolved, immutable configuration. */
export interface AppConfig {
  /** Analyse with simulated VirusTotal/ClamAV verdicts — no keys, no daemon. */
  readonly demo: boolean;

  /** VirusTotal API v3 key. Empty disables the VirusTotal enrichment. */
  readonly vtApiKey: string;
  /** VirusTotal API base URL. */
  readonly vtEndpoint: string;
  /** Number of engines that must flag a file/URL before it counts as malicious. */
  readonly vtMaliciousThreshold: number;
  /** Per-request timeout (ms) for VirusTotal. */
  readonly vtTimeoutMs: number;

  /** Hybrid Analysis (Falcon Sandbox) API key. Empty disables the enrichment. */
  readonly hybridApiKey: string;
  readonly hybridEndpoint: string;
  readonly hybridTimeoutMs: number;

  /** clamd host (TCP). Empty disables the ClamAV scan. */
  readonly clamHost: string;
  readonly clamPort: number;
  /** Per-scan timeout (ms) for clamd. */
  readonly clamTimeoutMs: number;

  /** Domains considered internal — used for display-name/BEC spoof detection. */
  readonly corporateDomains: readonly string[];
  /** Attachment extensions always treated as dangerous. */
  readonly blockedExtensions: readonly string[];
  /** Maximum attachment size to hash/scan, in MB. */
  readonly maxAttachmentMb: number;

  /** Score at/above which a message is quarantined (exit code 2). */
  readonly quarantineScore: number;
  /** Score at/above which a message is flagged suspicious (exit code 1). */
  readonly suspiciousScore: number;

  /** Mailbox to pull messages from (IMAP over TLS). Empty = connect from the UI. */
  readonly imapHost: string;
  readonly imapPort: number;
  readonly imapUser: string;
  readonly imapPassword: string;
  readonly imapTls: boolean;
  readonly imapMailbox: string;
  /** How many of the most recent messages to fetch. */
  readonly imapFetchLimit: number;

  /** Poll the update & announcement channel. False = never any outbound call. */
  readonly updateCheck: boolean;
  /** Which feed to poll — re-point it at an intranet copy to address a fleet. */
  readonly updateFeed: string;
  /** How long a fetched feed is cached, in minutes. */
  readonly updateTtlMinutes: number;

  /** HTTP API / web UI bind address. */
  readonly host: string;
  readonly port: number;
  /** Optional bearer token required by the HTTP API. */
  readonly apiToken: string;
  /** Where analysis reports are written. */
  readonly outDir: string;
  readonly logLevel: LogLevel;
}

export function loadConfig(): AppConfig {
  loadDotEnv();
  const level = str("MAILAEGIS_LOG_LEVEL", "info").toLowerCase();
  const logLevel: LogLevel = ["debug", "info", "warn", "error"].includes(level) ? (level as LogLevel) : "info";

  return Object.freeze({
    demo: flag("MAILAEGIS_DEMO", false),

    vtApiKey: str("VIRUSTOTAL_API_KEY"),
    vtEndpoint: str("VIRUSTOTAL_ENDPOINT", "https://www.virustotal.com/api/v3").replace(/\/+$/, ""),
    vtMaliciousThreshold: num("VIRUSTOTAL_MALICIOUS_THRESHOLD", 3),
    vtTimeoutMs: num("VIRUSTOTAL_TIMEOUT_MS", 8000),

    hybridApiKey: str("HYBRID_ANALYSIS_API_KEY"),
    hybridEndpoint: str("HYBRID_ANALYSIS_ENDPOINT", "https://hybrid-analysis.com/api/v2").replace(/\/+$/, ""),
    hybridTimeoutMs: num("HYBRID_ANALYSIS_TIMEOUT_MS", 8000),

    clamHost: str("CLAMAV_HOST"),
    clamPort: num("CLAMAV_PORT", 3310),
    clamTimeoutMs: num("CLAMAV_TIMEOUT_MS", 15000),

    // In demo mode we pretend the company is "corp.example" so the identity
    // rules (look-alike domains, display-name spoofing) have something to
    // protect. Configure your real domains for production use.
    corporateDomains: Object.freeze(list("MAILAEGIS_CORPORATE_DOMAINS", flag("MAILAEGIS_DEMO") ? ["corp.example"] : [])),
    blockedExtensions: Object.freeze(
      list("MAILAEGIS_BLOCKED_EXTENSIONS", [
        "exe", "scr", "com", "pif", "bat", "cmd", "js", "jse", "vbs", "vbe",
        "wsf", "wsh", "hta", "msi", "jar", "lnk", "ps1", "reg", "cpl", "iso", "img",
      ]),
    ),
    maxAttachmentMb: num("MAILAEGIS_MAX_ATTACHMENT_MB", 25),

    quarantineScore: num("MAILAEGIS_QUARANTINE_SCORE", 70),
    suspiciousScore: num("MAILAEGIS_SUSPICIOUS_SCORE", 35),

    imapHost: str("IMAP_HOST"),
    imapPort: num("IMAP_PORT", 993),
    imapUser: str("IMAP_USER"),
    imapPassword: str("IMAP_PASSWORD"),
    imapTls: flag("IMAP_TLS", true),
    imapMailbox: str("IMAP_MAILBOX", "INBOX"),
    imapFetchLimit: num("IMAP_FETCH_LIMIT", 25),

    updateCheck: flag("MAILAEGIS_UPDATE_CHECK", true),
    updateFeed: str("MAILAEGIS_UPDATE_FEED", "https://raw.githubusercontent.com/soyrageagency/mailaegis/main/channel/updates.json"),
    updateTtlMinutes: num("MAILAEGIS_UPDATE_TTL_MIN", 360),

    host: str("MAILAEGIS_HOST", "127.0.0.1"),
    port: num("MAILAEGIS_PORT", 4850),
    apiToken: str("MAILAEGIS_API_TOKEN"),
    outDir: str("MAILAEGIS_OUT_DIR", "./reports"),
    logLevel,
  });
}
