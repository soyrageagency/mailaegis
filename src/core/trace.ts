/**
 * Delivery-path forensics — the `Received:` chain.
 *
 * Every hop a message took is stamped into a `Received:` header, oldest last.
 * Reading that chain backwards tells you where the message *actually* entered
 * your infrastructure — the originating IP — regardless of what the From header
 * claims. It is the single most useful forensic artefact in a phishing report,
 * and the one thing users always ask for: "where did this really come from?"
 *
 * Headers are attacker-controlled below your own perimeter, so this module
 * treats the chain as untrusted: it reports what each hop *claims*, and flags
 * the inconsistencies rather than believing them.
 *
 * Part of MailAegis — Corporate Email Threat Analyzer.
 * Crafted by SoyRage Agency — https://soyrage.es/
 * Licensed under the SoyRage Attribution License (see LICENSE).
 */

import type { Finding, Hop } from "./types.js";

/** Pull the first IPv4/IPv6 literal out of a string. */
function firstIp(text: string): string {
  const v4 = /\[?((?:\d{1,3}\.){3}\d{1,3})\]?/.exec(text);
  if (v4 && v4[1].split(".").every((o) => Number(o) <= 255)) return v4[1];
  const v6 = /\[?(?:IPv6:)?([0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7})\]?/i.exec(text);
  return v6 ? v6[1] : "";
}

/** RFC 1918 / loopback / link-local / CGNAT / unique-local. */
export function isPrivateIp(ip: string): boolean {
  if (!ip) return false;
  if (/^(::1|fe80:|fc|fd)/i.test(ip)) return true;
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => Number.isNaN(n))) return false;
  return (
    p[0] === 10 ||
    p[0] === 127 ||
    (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
    (p[0] === 192 && p[1] === 168) ||
    (p[0] === 169 && p[1] === 254) ||
    (p[0] === 100 && p[1] >= 64 && p[1] <= 127)
  );
}

/** Parse one `Received:` value into a structured hop. */
function parseHop(value: string, index: number): Hop {
  // Received: from <claimed> (<rdns> [<ip>]) by <host> with <proto> id <id>; <date>
  const fromMatch = /\bfrom\s+([^\s;()]+)/i.exec(value);
  const byMatch = /\bby\s+([^\s;()]+)/i.exec(value);
  const withMatch = /\bwith\s+([A-Za-z0-9/._-]+)/i.exec(value);
  const idMatch = /\bid\s+([A-Za-z0-9._-]+)/i.exec(value);
  const forMatch = /\bfor\s+<?([^\s;<>]+@[^\s;<>]+)>?/i.exec(value);

  // The date is whatever follows the last semicolon.
  const semi = value.lastIndexOf(";");
  const dateText = semi >= 0 ? value.slice(semi + 1).trim() : "";
  const parsed = dateText ? new Date(dateText) : new Date(NaN);

  // Prefer an IP written inside the parenthesised "(rdns [ip])" clause.
  const paren = /\(([^)]*)\)/.exec(value);
  const ip = firstIp(paren ? paren[1] : "") || firstIp(value);

  // The reverse-DNS name the receiving MTA resolved, when it recorded one.
  let rdns = "";
  if (paren) {
    const host = /([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+)/.exec(paren[1].replace(/\[[^\]]*\]/g, " "));
    if (host) rdns = host[1];
  }

  return {
    index,
    from: fromMatch ? fromMatch[1] : "",
    rdns,
    ip,
    privateIp: isPrivateIp(ip),
    by: byMatch ? byMatch[1] : "",
    protocol: withMatch ? withMatch[1] : "",
    id: idMatch ? idMatch[1] : "",
    recipient: forMatch ? forMatch[1] : "",
    date: Number.isNaN(parsed.getTime()) ? "" : parsed.toISOString(),
    delaySec: 0,
    raw: value.length > 400 ? `${value.slice(0, 400)}…` : value,
  };
}

/** The reconstructed delivery path plus what it tells us. */
export interface Trace {
  /** Hops in delivery order — index 0 is the ORIGIN, the last is your MTA. */
  hops: Hop[];
  /** First public IP in the path: where the message really came from. */
  originatingIp: string;
  /** The host that IP claimed to be, if recorded. */
  originatingHost: string;
  /** Total time the message spent in transit, in seconds. */
  transitSec: number;
}

/**
 * Build the delivery path. `received` arrives newest-first (as in the raw
 * message), so we reverse it: hop 0 becomes the origin.
 */
export function buildTrace(received: string[]): Trace {
  const hops = received.map(parseHop).reverse().map((h, i) => ({ ...h, index: i }));

  // Per-hop dwell time, computed forwards along the path.
  for (let i = 1; i < hops.length; i++) {
    const prev = hops[i - 1].date ? new Date(hops[i - 1].date).getTime() : NaN;
    const cur = hops[i].date ? new Date(hops[i].date).getTime() : NaN;
    hops[i].delaySec = Number.isNaN(prev) || Number.isNaN(cur) ? 0 : Math.max(0, Math.round((cur - prev) / 1000));
  }

  const origin = hops.find((h) => h.ip && !h.privateIp);
  const first = hops[0]?.date ? new Date(hops[0].date).getTime() : NaN;
  const last = hops[hops.length - 1]?.date ? new Date(hops[hops.length - 1].date).getTime() : NaN;

  return {
    hops,
    originatingIp: origin?.ip ?? "",
    originatingHost: origin?.rdns || origin?.from || "",
    transitSec: Number.isNaN(first) || Number.isNaN(last) ? 0 : Math.max(0, Math.round((last - first) / 1000)),
  };
}

/** Findings derived purely from the delivery path. */
export function traceFindings(trace: Trace, fromDomain: string): Finding[] {
  const findings: Finding[] = [];
  if (trace.hops.length === 0) return findings;

  const origin = trace.hops.find((h) => h.ip && !h.privateIp);

  if (!origin) {
    findings.push({
      rule: "no-public-origin", severity: "low", source: "trace",
      title: "No public originating IP in the delivery path",
      detail: "Every recorded hop is private or unparseable — the path may have been stripped or forged.",
      score: 8,
    });
  }

  // A message that claims an external sender but only ever touched one hop is
  // typical of direct-to-MX injection.
  if (trace.hops.length === 1 && fromDomain) {
    findings.push({
      rule: "single-hop-delivery", severity: "low", source: "trace",
      title: "Delivered in a single hop",
      detail: "The message reached your server directly, with no intermediate relay recorded.",
      score: 6,
    });
  }

  // The origin claiming to be one of the receiving hosts is a classic forgery.
  if (origin && origin.from && trace.hops.some((h) => h.by && h.by.toLowerCase() === origin.from.toLowerCase() && h.index !== origin.index)) {
    findings.push({
      rule: "hop-identity-loop", severity: "medium", source: "trace",
      title: "A hop claims to be one of your own relays",
      detail: `The originating hop introduced itself as "${origin.from}", which also appears as a receiving host in the path.`,
      score: 16, evidence: origin.raw,
    });
  }

  // Reverse DNS that has nothing to do with the From domain is worth noting.
  if (origin && origin.rdns && fromDomain) {
    const rdnsTail = origin.rdns.toLowerCase().split(".").slice(-2).join(".");
    const fromTail = fromDomain.toLowerCase().split(".").slice(-2).join(".");
    if (rdnsTail && fromTail && rdnsTail !== fromTail) {
      findings.push({
        rule: "rdns-mismatch", severity: "info", source: "trace",
        title: "Origin host does not belong to the sender's domain",
        detail: `The message entered from "${origin.rdns}" (${origin.ip}) while claiming to be from "${fromDomain}". Common for legitimate mail relays too — read it alongside SPF.`,
        score: 4, evidence: `${origin.rdns} [${origin.ip}]`,
      });
    }
  }

  // Long dwell times can indicate a store-and-forward staging host.
  const slowest = [...trace.hops].sort((a, b) => b.delaySec - a.delaySec)[0];
  if (slowest && slowest.delaySec > 6 * 3600) {
    findings.push({
      rule: "delayed-hop", severity: "info", source: "trace",
      title: "Unusually long delay between hops",
      detail: `The message sat for ${Math.round(slowest.delaySec / 3600)} h between two relays.`,
      score: 3,
    });
  }

  return findings;
}
