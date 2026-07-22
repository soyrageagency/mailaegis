/**
 * Core domain model for a message under analysis.
 *
 * Part of MailAegis — Corporate Email Threat Analyzer.
 * Crafted by SoyRage Agency — https://soyrage.es/
 * Licensed under the SoyRage Attribution License (see LICENSE).
 */

/** A parsed e-mail address with its optional display name. */
export interface Address {
  /** Display name as written in the header ("Finance Dept"). */
  name: string;
  /** Normalised address ("ops@corp.example"). Empty when unparseable. */
  address: string;
  /** Lower-cased domain part. */
  domain: string;
}

/** An extracted attachment. */
export interface Attachment {
  filename: string;
  /** Declared MIME type. */
  contentType: string;
  /** Decoded size in bytes. */
  size: number;
  /** SHA-256 of the decoded content (hex) — the VirusTotal lookup key. */
  sha256: string;
  /** Lower-cased final extension, without the dot. */
  extension: string;
  /** Decoded bytes (kept in memory for scanning; never written to disk). */
  content: Buffer;
}

/** A URL found in the message body. */
export interface UrlRef {
  url: string;
  /** Lower-cased host. */
  host: string;
  /** The anchor text, when the URL came from an HTML link. */
  text?: string;
}

/** Result of the published e-mail authentication checks. */
export interface AuthResults {
  spf: "pass" | "fail" | "softfail" | "neutral" | "none";
  dkim: "pass" | "fail" | "none";
  dmarc: "pass" | "fail" | "none";
  /** True when the envelope/From domains disagree. */
  alignmentMismatch: boolean;
}

/** A fully parsed message. */
export interface ParsedMessage {
  /** All headers, lower-cased keys → raw values (last wins for duplicates). */
  headers: Record<string, string>;
  /** Every Received: header, oldest last. */
  received: string[];
  from: Address;
  replyTo?: Address;
  returnPath?: Address;
  to: Address[];
  cc: Address[];
  subject: string;
  date: string;
  messageId: string;
  /** text/plain body, decoded. */
  text: string;
  /** text/html body, decoded. */
  html: string;
  attachments: Attachment[];
  urls: UrlRef[];
  /** Total raw size of the message in bytes. */
  rawSize: number;
}

/** How serious a finding is. */
export type Severity = "info" | "low" | "medium" | "high" | "critical";

/** One thing the analysis noticed. */
export interface Finding {
  /** Stable rule id, e.g. "display-name-spoof". */
  rule: string;
  severity: Severity;
  /** Human title. */
  title: string;
  /** What exactly was seen. */
  detail: string;
  /** Points contributed to the risk score. */
  score: number;
  /** Which subsystem raised it. */
  /** `policy` is your own decision — the sender allow and block lists. */
  source: "heuristics" | "auth" | "virustotal" | "clamav" | "trace" | "hybrid" | "policy";
  /** Optional evidence (filename, URL, hash…). */
  evidence?: string;
}

/** A VirusTotal lookup outcome for one file hash or URL. */
export interface VtResult {
  /** The hash, URL or IP that was looked up. */
  target: string;
  kind: "file" | "url" | "ip";
  /** True when VirusTotal had never seen it. */
  unknown: boolean;
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  /** Names of the engines that flagged it (first few). */
  detections: string[];
  /** Permalink for an analyst. */
  link?: string;
  /** Set when the lookup failed. */
  error?: string;
}

/** One hop in the delivery path, reconstructed from a `Received:` header. */
export interface Hop {
  /** 0 = origin, last = your own MTA. */
  index: number;
  /** The name the sending host introduced itself as (HELO/EHLO). */
  from: string;
  /** Reverse DNS the receiving MTA resolved for the connecting IP. */
  rdns: string;
  /** The connecting IP address. */
  ip: string;
  privateIp: boolean;
  /** The host that accepted this hop. */
  by: string;
  protocol: string;
  id: string;
  recipient: string;
  /** ISO timestamp, or "" when unparseable. */
  date: string;
  /** Seconds spent since the previous hop. */
  delaySec: number;
  raw: string;
}

/** A Hybrid Analysis (Falcon Sandbox) lookup outcome for one file. */
export interface HybridResult {
  /** SHA-256 that was searched. */
  sha256: string;
  /** True when the sandbox has never seen the file. */
  unknown: boolean;
  /** "malicious" | "suspicious" | "no specific threat" | "whitelisted" | "". */
  verdict: string;
  /** 0–100 sandbox threat score. */
  threatScore: number;
  threatLevel: string;
  /** Percentage of AV engines that flagged it. */
  avDetect: number;
  /** The name the sample was submitted under. */
  submitName: string;
  fileType: string;
  environment: string;
  link?: string;
  error?: string;
}

/** A ClamAV scan outcome for one attachment. */
export interface ClamResult {
  filename: string;
  infected: boolean;
  /** Signature name reported by clamd. */
  signature?: string;
  error?: string;
}

/** Overall verdict. */
export type Verdict = "clean" | "suspicious" | "malicious";

/** The complete analysis of one message. */
export interface Analysis {
  id: string;
  analysedAt: string;
  /** True when VirusTotal/ClamAV verdicts were simulated. */
  demo: boolean;
  verdict: Verdict;
  /** 0–100 risk score. */
  score: number;
  /** One-line explanation. */
  summary: string;
  message: {
    from: Address;
    replyTo?: Address;
    to: Address[];
    cc: Address[];
    subject: string;
    date: string;
    messageId: string;
    /** The first few kilobytes of the plain-text body, for quoting in a reply. */
    textPreview: string;
    sizeBytes: number;
    attachmentCount: number;
    urlCount: number;
  };
  auth: AuthResults;
  /** The reconstructed delivery path: every hop, and where it really came from. */
  trace: {
    hops: Hop[];
    originatingIp: string;
    originatingHost: string;
    transitSec: number;
    /** Reputation of the originating IP, when it could be checked. */
    ipReputation?: VtResult;
  };
  findings: Finding[];
  attachments: Array<Omit<Attachment, "content">>;
  urls: UrlRef[];
  virustotal: VtResult[];
  clamav: ClamResult[];
  hybrid: HybridResult[];
  /** Which engines actually ran (for honest evidence). */
  engines: Array<{ name: string; ran: boolean; note: string }>;
}
