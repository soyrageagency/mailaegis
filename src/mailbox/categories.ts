/**
 * Categories — the triage layer on top of the raw verdict.
 *
 * Two kinds live here:
 *   • **Automatic threat categories**, derived from which rules fired, so an
 *     analyst instantly sees *what kind* of bad a message is (malware vs
 *     phishing vs invoice fraud vs spoofing) rather than just "malicious".
 *   • **User categories** — free-form labels you create and assign, the way you
 *     would tag mail in any professional client. They live in memory and, when
 *     an output directory is configured, are persisted to a small JSON file.
 *
 * Part of MailAegis — Corporate Email Threat Analyzer.
 * Crafted by SoyRage Agency — https://soyrage.es/
 * Licensed under the SoyRage Attribution License (see LICENSE).
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import type { Analysis } from "../core/types.js";

/** An automatic threat class. */
export type ThreatCategory = "malware" | "phishing" | "fraud" | "spoofing" | "spam" | "clean";

/** Which rules imply which threat class. */
const RULE_CATEGORY: Record<string, ThreatCategory> = {
  // Malware
  "clamav-detection": "malware",
  "virustotal-file-malicious": "malware",
  "dangerous-attachment": "malware",
  "archive-contains-executable": "malware",
  "macro-document": "malware",
  "magic-mismatch": "malware",
  "double-extension": "malware",
  "encrypted-archive": "malware",
  // Phishing
  "anchor-text-deception": "phishing",
  "credential-landing": "phishing",
  "credential-urgency": "phishing",
  "virustotal-url-malicious": "phishing",
  "lookalike-domain": "phishing",
  "punycode-url": "phishing",
  "ip-literal-url": "phishing",
  "url-shortener": "phishing",
  // Fraud / BEC
  "exec-impersonation": "fraud",
  "bank-detail-change": "fraud",
  "urgent-payment": "fraud",
  "gift-card-scam": "fraud",
  "secrecy-pressure": "fraud",
  "display-name-address-spoof": "fraud",
  "display-name-brand-spoof": "fraud",
  "reply-to-divergence": "fraud",
  "invoice-pressure": "fraud",
  // Spoofing / authentication
  "spf-fail": "spoofing",
  "spf-softfail": "spoofing",
  "dkim-fail": "spoofing",
  "dmarc-fail": "spoofing",
  "internal-spoof": "spoofing",
  "envelope-misalignment": "spoofing",
};

/** Presentation metadata for the automatic categories. */
export const THREAT_META: Record<ThreatCategory, { label: string; colour: string }> = {
  malware: { label: "Malware", colour: "#c8524a" },
  phishing: { label: "Phishing", colour: "#c9722a" },
  fraud: { label: "Fraud / BEC", colour: "#b8892a" },
  spoofing: { label: "Spoofing", colour: "#6b8fb0" },
  spam: { label: "Spam", colour: "#8b8b86" },
  clean: { label: "Clean", colour: "#3a8f5c" },
};

/**
 * Derive the threat categories for an analysis, strongest first.
 * A clean message gets exactly one category: `clean`.
 */
export function deriveCategories(analysis: Analysis): ThreatCategory[] {
  const weight = new Map<ThreatCategory, number>();
  for (const f of analysis.findings) {
    const category = RULE_CATEGORY[f.rule];
    if (!category) continue;
    weight.set(category, (weight.get(category) ?? 0) + f.score);
  }
  if (weight.size === 0) return ["clean"];
  return [...weight.entries()].sort((a, b) => b[1] - a[1]).map(([c]) => c);
}

/** A user-defined label. */
export interface UserCategory {
  id: string;
  name: string;
  colour: string;
}

const PALETTE = ["#3b9ee8", "#3a8f5c", "#b8892a", "#c8524a", "#8b5cf6", "#0ea5e9", "#ec4899", "#6b8fb0"];

/** In-memory (optionally persisted) store of user labels and their assignments. */
export class CategoryStore {
  private categories: UserCategory[] = [];
  /** message id → category ids */
  private assigned = new Map<string, Set<string>>();
  private readonly file: string;

  constructor(outDir: string) {
    this.file = resolve(join(outDir, "categories.json"));
    this.load();
  }

  list(): UserCategory[] {
    return this.categories;
  }

  /** Create a label (idempotent by name). */
  create(name: string, colour?: string): UserCategory {
    const trimmed = name.trim().slice(0, 40);
    if (!trimmed) throw new Error("A category needs a name.");
    const existing = this.categories.find((c) => c.name.toLowerCase() === trimmed.toLowerCase());
    if (existing) return existing;
    const category: UserCategory = {
      id: trimmed.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || `cat-${this.categories.length + 1}`,
      name: trimmed,
      colour: colour ?? PALETTE[this.categories.length % PALETTE.length],
    };
    this.categories.push(category);
    this.save();
    return category;
  }

  /** Delete a label and drop it from every message. */
  remove(id: string): void {
    this.categories = this.categories.filter((c) => c.id !== id);
    for (const set of this.assigned.values()) set.delete(id);
    this.save();
  }

  /** Replace the labels assigned to a message. */
  assign(messageId: string, categoryIds: string[]): string[] {
    const valid = categoryIds.filter((id) => this.categories.some((c) => c.id === id));
    this.assigned.set(messageId, new Set(valid));
    this.save();
    return valid;
  }

  /** Labels currently on a message. */
  for(messageId: string): string[] {
    return [...(this.assigned.get(messageId) ?? [])];
  }

  private load(): void {
    if (!existsSync(this.file)) return;
    try {
      const data = JSON.parse(readFileSync(this.file, "utf8")) as { categories?: UserCategory[]; assigned?: Record<string, string[]> };
      this.categories = data.categories ?? [];
      this.assigned = new Map(Object.entries(data.assigned ?? {}).map(([k, v]) => [k, new Set(v)]));
    } catch {
      /* a corrupt label file must never stop mail analysis */
    }
  }

  private save(): void {
    try {
      mkdirSync(resolve(this.file, ".."), { recursive: true });
      const assigned: Record<string, string[]> = {};
      for (const [k, v] of this.assigned) if (v.size) assigned[k] = [...v];
      writeFileSync(this.file, JSON.stringify({ categories: this.categories, assigned }, null, 2));
    } catch {
      /* persistence is a convenience, not a requirement */
    }
  }
}
