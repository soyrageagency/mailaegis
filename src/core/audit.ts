/**
 * The audit trail, and the bridge to your SIEM.
 *
 * Two jobs, one shape. Every decision worth defending later — a message
 * quarantined, an outbound message held back, a send that overrode that
 * refusal, a sender added to a list — is appended to a local JSONL file, and
 * optionally forwarded to a webhook so Splunk, Sentinel, Wazuh or an n8n flow
 * sees it live.
 *
 * Three deliberate constraints:
 *
 *   **It never blocks.** Writing the line is synchronous and tiny; the webhook
 *   is fire-and-forget with a short timeout. A SIEM that is down must not stop
 *   mail from being analysed.
 *
 *   **It never carries message content.** Subjects, bodies and attachments stay
 *   out of it. An audit trail is a record of decisions, not a second copy of
 *   everyone's mail sitting in a log directory with different permissions.
 *
 *   **It is append-only and rotated by size**, so it cannot quietly fill a disk
 *   on a busy gateway.
 *
 * Part of MailAegis — Corporate Email Threat Analyzer.
 * Crafted by SoyRage Agency — https://soyrage.es/
 * Licensed under the SoyRage Attribution License (see LICENSE).
 */

import { appendFileSync, existsSync, mkdirSync, readFileSync, renameSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { BRAND } from "../branding.js";
import type { AppConfig } from "../config.js";
import type { Analysis } from "./types.js";

export type AuditAction =
  | "message.analysed"
  | "outbound.sent"
  | "outbound.blocked"
  | "outbound.overridden"
  | "policy.blocked"
  | "policy.allowed"
  | "policy.removed"
  | "mailbox.connected"
  | "mailbox.disconnected";

export interface AuditEvent {
  at: string;
  action: AuditAction;
  /** The analysis id, when the event is about a message. */
  id?: string;
  verdict?: string;
  score?: number;
  from?: string;
  /** Recipients, for outbound events. Addresses only. */
  to?: string[];
  /** Which mailbox this happened in. */
  account?: string;
  /** Rule names that drove the decision — never the evidence itself. */
  rules?: string[];
  /** Free text for policy events. */
  detail?: string;
  product: string;
  version: string;
}

/** Keep one log to a sane size; a busy gateway writes a lot of lines. */
const MAX_BYTES = 8 * 1024 * 1024;

let webhookFailures = 0;

function logPath(config: AppConfig): string {
  return join(resolve(config.outDir), "audit.jsonl");
}

/** Roll the file over once, so there is always at most one previous log. */
function rotate(path: string): void {
  try {
    if (existsSync(path) && statSync(path).size > MAX_BYTES) renameSync(path, `${path}.1`);
  } catch { /* a failed rotation must not stop the write */ }
}

/**
 * Record an event.
 *
 * Synchronous by design: the write is a single small line, and making it async
 * would mean an event could be lost when the process exits right after the
 * decision it describes.
 */
export function audit(config: AppConfig, event: Omit<AuditEvent, "at" | "product" | "version">): void {
  const full: AuditEvent = {
    at: new Date().toISOString(),
    ...event,
    product: BRAND.short,
    version: BRAND.version,
  };

  try {
    const path = logPath(config);
    mkdirSync(resolve(config.outDir), { recursive: true });
    rotate(path);
    appendFileSync(path, `${JSON.stringify(full)}\n`, "utf8");
  } catch { /* an unwritable log must not break the analyser */ }

  void forward(config, full);
}

/** POST the event to the configured webhook. Never awaited, never throws. */
async function forward(config: AppConfig, event: AuditEvent): Promise<void> {
  if (!config.webhookUrl) return;
  // Stop hammering an endpoint that is clearly not there. It resets on
  // restart, which is the right granularity for a fault someone has to fix.
  if (webhookFailures >= 10) return;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 5000);
  try {
    const res = await fetch(config.webhookUrl, {
      method: "POST",
      signal: controller.signal,
      headers: {
        "content-type": "application/json",
        "user-agent": `MailAegis/${BRAND.version}`,
        ...(config.webhookToken ? { authorization: `Bearer ${config.webhookToken}` } : {}),
      },
      body: JSON.stringify(event),
    });
    if (!res.ok) throw new Error(String(res.status));
    webhookFailures = 0;
  } catch {
    webhookFailures++;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Record an analysis, if it is interesting enough.
 *
 * Logging every clean message on a mail gateway is how an audit trail becomes
 * noise nobody reads, so the threshold is configurable and defaults to
 * "suspicious or worse".
 */
export function auditAnalysis(config: AppConfig, analysis: Analysis, account?: string): void {
  const rank = { clean: 0, suspicious: 1, malicious: 2 } as const;
  const floor = config.auditMinVerdict === "clean" ? 0 : config.auditMinVerdict === "malicious" ? 2 : 1;
  if (rank[analysis.verdict] < floor) return;

  audit(config, {
    action: "message.analysed",
    id: analysis.id,
    verdict: analysis.verdict,
    score: analysis.score,
    from: analysis.message.from.address,
    to: analysis.message.to.map((t) => t.address).slice(0, 20),
    account,
    // Rule names travel; the evidence they matched on does not.
    rules: analysis.findings.filter((f) => f.score > 0).slice(0, 12).map((f) => f.rule),
  });
}

/** The most recent events, newest first — for the UI and for `mailaegis audit`. */
export function recentEvents(config: AppConfig, limit = 200): AuditEvent[] {
  const path = logPath(config);
  if (!existsSync(path)) return [];
  try {
    const lines = readFileSync(path, "utf8").split("\n").filter(Boolean);
    return lines
      .slice(-limit)
      .map((line) => { try { return JSON.parse(line) as AuditEvent; } catch { return null; } })
      .filter((e): e is AuditEvent => e !== null)
      .reverse();
  } catch {
    return [];
  }
}

/** Reset the webhook back-off — used by tests. */
export function resetWebhookState(): void {
  webhookFailures = 0;
}
