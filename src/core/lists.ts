/**
 * Sender allow and block lists.
 *
 * The two halves are deliberately asymmetric, because they carry very
 * different risk.
 *
 * **Blocking** is unconditional. If you have decided that `invoices@rival.example`
 * or the whole of `@bulk-mailer.example` is unwanted, that is the end of the
 * conversation, and the message is marked malicious no matter how clean it
 * looks.
 *
 * **Allowing is not.** An allow list that simply zeroes the score is the most
 * dangerous feature an email security tool can ship: the moment a supplier is
 * on it, spoofing that supplier becomes the cheapest way past every other
 * engine — and spoofing a From address costs nothing. So an entry here only
 * takes effect when the message **also proves it is really from that sender**,
 * with DMARC, or with SPF and DKIM both passing and aligned. An unauthenticated
 * message from an allow-listed address is scored exactly as if the list were
 * empty, and the report says so.
 *
 * Even then, allowing only suppresses *heuristic* suspicion — tone, urgency,
 * look-alike scoring. A ClamAV hit, a VirusTotal detection or a sandbox verdict
 * is never waived: a trusted supplier with a compromised mailbox is a normal
 * Tuesday.
 *
 * Part of MailAegis — Corporate Email Threat Analyzer.
 * Crafted by SoyRage Agency — https://soyrage.es/
 * Licensed under the SoyRage Attribution License (see LICENSE).
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import type { AuthResults } from "./types.js";

export type ListKind = "blocked" | "allowed";

export interface ListEntry {
  /** An address (`ana@corp.example`) or a whole domain (`@corp.example`). */
  value: string;
  /** Free text: why this was added, for whoever reads it in six months. */
  note: string;
  added: string;
}

interface ListFile {
  blocked: ListEntry[];
  allowed: ListEntry[];
}

const EMPTY: ListFile = { blocked: [], allowed: [] };

/**
 * Normalise an entry.
 *
 * A bare domain and an `@domain` mean the same thing, and people type both.
 */
export function normaliseEntry(raw: string): string {
  const value = String(raw ?? "").trim().toLowerCase();
  if (!value) return "";
  // `@example.com` is already a domain rule; `ana@example.com` is an address
  // rule. Either way it is used verbatim — only a bare domain needs the `@`.
  if (value.includes("@")) return value;
  return `@${value}`;
}

/** Does this address match the entry — exactly, or by its domain? */
export function entryMatches(entry: string, address: string): boolean {
  const target = String(address ?? "").trim().toLowerCase();
  if (!target || !entry) return false;
  if (entry.startsWith("@")) {
    const domain = target.split("@").pop() ?? "";
    // A domain rule covers its subdomains: blocking @rival.example should
    // not be defeated by mail.rival.example.
    return domain === entry.slice(1) || domain.endsWith(`.${entry.slice(1)}`);
  }
  return target === entry;
}

/**
 * Is this message authenticated well enough to trust its From address?
 *
 * Exported because it is the entire safety property of the allow list, and
 * something that important should be testable on its own.
 */
export function senderIsProven(auth: AuthResults): boolean {
  // An explicit DMARC failure is authoritative and cannot be argued with by
  // the layers underneath it: the domain owner published a policy and this
  // message failed it. Falling back to "but SPF and DKIM passed" would let a
  // message the domain itself disowns satisfy the allow list.
  if (auth.dmarc === "fail") return false;
  if (auth.dmarc === "pass") return true;
  // No DMARC record published — the common case for small suppliers. Then
  // SPF and DKIM both passing, and aligned, is the strongest available proof.
  return auth.spf === "pass" && auth.dkim === "pass" && !auth.alignmentMismatch;
}

/** What the lists say about one sender. */
export interface ListDecision {
  blocked: ListEntry | null;
  /** Present when the address is listed, whether or not it was proven. */
  allowed: ListEntry | null;
  /** True only when `allowed` is set *and* the sender authenticated. */
  allowHonoured: boolean;
}

/** Persisted sender lists. */
export class SenderLists {
  private data: ListFile = { blocked: [], allowed: [] };
  private readonly path: string;

  constructor(outDir: string) {
    this.path = join(resolve(outDir), "sender-lists.json");
    this.load();
  }

  private load(): void {
    if (!existsSync(this.path)) { this.data = { ...EMPTY, blocked: [], allowed: [] }; return; }
    try {
      const parsed = JSON.parse(readFileSync(this.path, "utf8")) as Partial<ListFile>;
      this.data = {
        blocked: Array.isArray(parsed.blocked) ? parsed.blocked.filter((e) => e && typeof e.value === "string") : [],
        allowed: Array.isArray(parsed.allowed) ? parsed.allowed.filter((e) => e && typeof e.value === "string") : [],
      };
    } catch {
      // A corrupt file must not stop the analyzer from running; an empty list
      // is the safe interpretation for `allowed`, and losing `blocked` is
      // visible the moment someone looks.
      this.data = { blocked: [], allowed: [] };
    }
  }

  private save(): void {
    mkdirSync(resolve(this.path, ".."), { recursive: true });
    writeFileSync(this.path, `${JSON.stringify(this.data, null, 2)}\n`, "utf8");
  }

  list(): ListFile {
    return { blocked: [...this.data.blocked], allowed: [...this.data.allowed] };
  }

  add(kind: ListKind, raw: string, note = ""): ListEntry {
    const value = normaliseEntry(raw);
    if (!value) throw new Error("Enter an address or a domain.");
    if (value === "@") throw new Error("That is not an address or a domain.");
    // The same sender on both lists is a contradiction, and the block wins
    // either way — so adding to one removes it from the other.
    const other: ListKind = kind === "blocked" ? "allowed" : "blocked";
    this.data[other] = this.data[other].filter((e) => e.value !== value);
    this.data[kind] = this.data[kind].filter((e) => e.value !== value);
    const entry: ListEntry = { value, note: String(note ?? "").slice(0, 200), added: new Date().toISOString() };
    this.data[kind].push(entry);
    this.save();
    return entry;
  }

  remove(kind: ListKind, raw: string): void {
    const value = normaliseEntry(raw);
    this.data[kind] = this.data[kind].filter((e) => e.value !== value);
    this.save();
  }

  /** Decide what the lists say about a sender. */
  decide(address: string, auth: AuthResults): ListDecision {
    const blocked = this.data.blocked.find((e) => entryMatches(e.value, address)) ?? null;
    const allowed = this.data.allowed.find((e) => entryMatches(e.value, address)) ?? null;
    return { blocked, allowed, allowHonoured: Boolean(allowed) && senderIsProven(auth) };
  }
}

/**
 * The process-wide lists.
 *
 * The analyzer runs as a CLI, a server and a filter, and all three should see
 * the same decisions without threading an object through every call site.
 */
let shared: SenderLists | null = null;
export function senderLists(outDir: string): SenderLists {
  if (!shared) shared = new SenderLists(outDir);
  return shared;
}

/** Drop the cached instance — used by tests. */
export function resetSenderLists(): void {
  shared = null;
}
