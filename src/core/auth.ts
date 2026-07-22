/**
 * E-mail authentication evaluation (SPF · DKIM · DMARC).
 *
 * MailAegis reads the results your MTA already published in
 * `Authentication-Results:` / `Received-SPF:` rather than re-resolving DNS —
 * that keeps the analyzer fast, side-effect free and safe to run inside a mail
 * pipeline. It also checks *alignment*: the RFC5321 envelope domain against the
 * RFC5322 From domain, which is what DMARC actually cares about and what most
 * spoofing gets wrong.
 *
 * Part of MailAegis — Corporate Email Threat Analyzer.
 * Crafted by SoyRage Agency — https://soyrage.es/
 * Licensed under the SoyRage Attribution License (see LICENSE).
 */

import type { AuthResults, ParsedMessage } from "./types.js";

/** Read a mechanism's verdict out of an Authentication-Results header. */
function verdictFor(authResults: string, mechanism: string): string {
  const m = new RegExp(`\\b${mechanism}\\s*=\\s*([a-z]+)`, "i").exec(authResults);
  return m ? m[1].toLowerCase() : "";
}

/** Registrable-ish domain: keep the last two labels (good enough for alignment). */
export function baseDomain(domain: string): string {
  const parts = (domain || "").toLowerCase().split(".").filter(Boolean);
  if (parts.length <= 2) return parts.join(".");
  // Handle the common two-part public suffixes we care about in corporate mail.
  const twoPart = ["co.uk", "com.au", "co.jp", "com.br", "com.mx", "co.nz", "com.ar", "com.es"];
  const lastTwo = parts.slice(-2).join(".");
  if (twoPart.includes(lastTwo) && parts.length >= 3) return parts.slice(-3).join(".");
  return lastTwo;
}

/** Evaluate the published authentication results for a message. */
export function evaluateAuth(message: ParsedMessage): AuthResults {
  const ar = [message.headers["authentication-results"] ?? "", message.headers["arc-authentication-results"] ?? ""].join(" ");
  const receivedSpf = message.headers["received-spf"] ?? "";

  let spf = verdictFor(ar, "spf");
  if (!spf && receivedSpf) spf = (/^\s*(\w+)/.exec(receivedSpf)?.[1] ?? "").toLowerCase();
  let dkim = verdictFor(ar, "dkim");
  if (!dkim && message.headers["dkim-signature"]) dkim = "none"; // present but unverified by the MTA
  const dmarc = verdictFor(ar, "dmarc");

  const norm = <T extends string>(value: string, allowed: readonly T[], fallback: T): T =>
    (allowed as readonly string[]).includes(value) ? (value as T) : fallback;

  const envelopeDomain = baseDomain(message.returnPath?.domain ?? "");
  const fromDomain = baseDomain(message.from.domain);
  const alignmentMismatch = Boolean(envelopeDomain && fromDomain && envelopeDomain !== fromDomain);

  return {
    spf: norm(spf, ["pass", "fail", "softfail", "neutral", "none"] as const, "none"),
    dkim: norm(dkim, ["pass", "fail", "none"] as const, "none"),
    dmarc: norm(dmarc, ["pass", "fail", "none"] as const, "none"),
    alignmentMismatch,
  };
}
