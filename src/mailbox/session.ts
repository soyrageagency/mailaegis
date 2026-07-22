/**
 * Connected mailboxes.
 *
 * A company never has one mailbox: there is `security@`, `finance@`, `info@`,
 * the CEO's, the shared abuse box… so MailAegis holds **many accounts at once**
 * and can show them individually or as one unified inbox, with the antivirus
 * verdict on every row.
 *
 * Everything lives in memory. Credentials stay in this process for as long as
 * an account is connected (switching folders re-authenticates) and are never
 * written to disk, never logged and never returned by the API.
 *
 * Part of MailAegis — Corporate Email Threat Analyzer.
 * Crafted by SoyRage Agency — https://soyrage.es/
 * Licensed under the SoyRage Attribution License (see LICENSE).
 */

import type { AppConfig } from "../config.js";
import { analyzeRaw } from "../core/analyze.js";
import { demoMessages } from "../core/demo.js";
import { parseMessage } from "../core/parse.js";
import type { Analysis, Verdict } from "../core/types.js";
import { deriveCategories, type CategoryStore, type ThreatCategory } from "./categories.js";
import { fetchRecent, listMailboxes, type MailboxCredentials, type MailboxFolder } from "./imap.js";
import { bareAddress, buildMime, envelopeRecipients, makeMessageId, type OutgoingMessage } from "./compose.js";
import { smtpFor } from "./providers.js";
import { sendMail } from "./smtp.js";

/** A row in the message list. */
export interface InboxItem {
  id: string;
  accountId: string;
  accountLabel: string;
  seq: number;
  from: { name: string; address: string };
  to: string;
  subject: string;
  date: string;
  snippet: string;
  verdict: Verdict;
  score: number;
  attachmentCount: number;
  urlCount: number;
  findingCount: number;
  threat: ThreatCategory[];
  labels: string[];
}

/** A connected mailbox, as the UI sees it (never includes credentials). */
export interface AccountView {
  id: string;
  label: string;
  host: string;
  mailbox: string;
  demo: boolean;
  folders: MailboxFolder[];
  total: number;
  fetched: number;
  counts: Record<Verdict, number>;
}

/** Everything the chrome needs. */
export interface MailboxStatus {
  connected: boolean;
  accounts: AccountView[];
  /** "" means the unified view across every account. */
  activeId: string;
  fetched: number;
  counts: Record<Verdict, number>;
  threatCounts: Record<string, number>;
}

interface Entry { item: InboxItem; analysis: Analysis }

interface Account {
  view: AccountView;
  creds: MailboxCredentials | null;
  /** Submission settings, guessed at connect time and correctable by the user. */
  smtp: { host: string; port: number; tls: boolean } | null;
  limit: number;
  entries: Entry[];
  /**
   * Messages sent from here this session. A real server files them into Sent
   * eventually, but the user expects to see what they just sent immediately.
   */
  outbox: Entry[];
}

/** What `send` reports back — including a refusal. */
export interface SendResult {
  ok: boolean;
  /** True when the outbound scan stopped the message. */
  blocked: boolean;
  reason: string;
  analysis: Analysis;
  accepted: string[];
  rejected: Array<{ address: string; reply: string }>;
  /** True in demo mode: nothing left the machine. */
  simulated: boolean;
}

const DEMO_FOLDERS: MailboxFolder[] = [
  { name: "INBOX", label: "Inbox", role: "inbox" },
  { name: "Sent", label: "Sent", role: "sent" },
  { name: "Drafts", label: "Drafts", role: "drafts" },
  { name: "Archive", label: "Archive", role: "archive" },
  { name: "Junk", label: "Junk", role: "junk" },
  { name: "Trash", label: "Trash", role: "trash" },
];

/** The mailboxes a mid-sized company actually runs, for the demo. */
const DEMO_PERSONAS = ["security@corp.example", "finance@corp.example", "info@corp.example"];

const zero = (): Record<Verdict, number> => ({ clean: 0, suspicious: 0, malicious: 0 });

/** Strip a body down to a short preview line. */
function snippetOf(text: string, html: string): string {
  const source = text || html.replace(/<style[\s\S]*?<\/style>/gi, " ").replace(/<[^>]+>/g, " ");
  return source.replace(/\s+/g, " ").trim().slice(0, 160);
}

/**
 * A stable id for an account. IMAP usernames are usually the address already,
 * so only fall back to `user@host` when the username is a bare login.
 */
function accountId(user: string, host: string): string {
  const raw = user.includes("@") ? user : `${user}@${host}`;
  return raw.toLowerCase().replace(/[^a-z0-9@._-]/g, "-");
}

/** Is this account currently showing a Sent folder? */
function isSentFolder(view: AccountView): boolean {
  const folder = view.folders.find((f) => f.name === view.mailbox);
  return folder?.role === "sent" || /sent/i.test(view.mailbox);
}

/** Most dangerous first, then newest — what a security inbox should show. */
const RANK: Record<Verdict, number> = { malicious: 0, suspicious: 1, clean: 2 };
function sortItems(entries: Entry[]): Entry[] {
  return [...entries].sort((a, b) => RANK[a.item.verdict] - RANK[b.item.verdict] || b.item.seq - a.item.seq);
}

/** All the mailboxes this process currently has open. */
export class MailboxSession {
  private accounts = new Map<string, Account>();
  private activeId = "";

  constructor(private readonly categories: CategoryStore) {}

  // ---- Reads --------------------------------------------------------------

  getStatus(): MailboxStatus {
    const views = [...this.accounts.values()].map((a) => a.view);
    const items = this.list();
    const counts = zero();
    const threatCounts: Record<string, number> = {};
    for (const e of this.entriesFor(this.activeId)) {
      counts[e.item.verdict]++;
      for (const t of e.item.threat) threatCounts[t] = (threatCounts[t] ?? 0) + 1;
    }
    return {
      connected: this.accounts.size > 0,
      accounts: views,
      activeId: this.activeId,
      fetched: items.length,
      counts,
      threatCounts,
    };
  }

  /**
   * Entries for one account, or every account when id is "".
   *
   * Anything sent this session is folded in while a Sent folder is showing,
   * so a message appears the moment it leaves rather than whenever the server
   * gets round to filing it.
   */
  private entriesFor(id: string): Entry[] {
    const of = (a: Account) => (isSentFolder(a.view) ? [...a.outbox, ...a.entries] : a.entries);
    if (!id) return sortItems([...this.accounts.values()].flatMap(of));
    const account = this.accounts.get(id);
    return account ? of(account) : [];
  }

  list(): InboxItem[] {
    return this.entriesFor(this.activeId).map((e) => e.item);
  }

  get(messageId: string): Analysis | undefined {
    for (const account of this.accounts.values()) {
      const hit = account.entries.find((e) => e.item.id === messageId);
      if (hit) return hit.analysis;
    }
    return undefined;
  }

  /** Switch the view to one account, or "" for the unified inbox. */
  setActive(id: string): MailboxStatus {
    this.activeId = id && this.accounts.has(id) ? id : "";
    return this.getStatus();
  }

  refreshLabels(): void {
    for (const account of this.accounts.values()) {
      for (const e of account.entries) e.item.labels = this.categories.for(e.item.id);
    }
  }

  // ---- Connecting ---------------------------------------------------------

  /**
   * Add the built-in corpus as a demo account. Called repeatedly it walks the
   * persona list, so clicking "open the demo mailbox" twice gives you two
   * different mailboxes to switch between rather than reloading the same one.
   */
  async connectDemo(config: AppConfig, label = "", folder = "INBOX"): Promise<MailboxStatus> {
    if (!label) label = DEMO_PERSONAS.find((p) => !this.accounts.has(accountId(p, "demo.mailbox"))) ?? DEMO_PERSONAS[0]!;
    const id = accountId(label, "demo.mailbox");
    const samples = demoMessages();
    // Later personas see a different slice, so the unified inbox and the
    // per-account counts are visibly different.
    const isSecond = DEMO_PERSONAS.indexOf(label) > 0;
    const chosen = folder.toLowerCase() === "sent"
      ? samples.filter((s) => s.id === "clean-invoice")
      : isSecond
        ? samples.filter((s) => ["clean-invoice", "bec-ceo-fraud", "newsletter"].includes(s.id))
        : samples;

    const account: Account = {
      view: { id, label, host: "demo.mailbox", mailbox: folder, demo: true, folders: DEMO_FOLDERS, total: chosen.length, fetched: 0, counts: zero() },
      creds: null, smtp: null, limit: chosen.length, entries: [],
      outbox: this.accounts.get(id)?.outbox ?? [],
    };
    this.accounts.set(id, account);
    await this.ingest(account, chosen.map((s, i) => ({ seq: chosen.length - i, raw: Buffer.from(s.raw, "utf8") })), config);
    this.activeId = id;
    return this.getStatus();
  }

  /** Connect a real mailbox and add it as an account. */
  async connect(creds: MailboxCredentials, config: AppConfig, limit: number, smtp?: { host: string; port: number; tls: boolean }): Promise<MailboxStatus> {
    const folders = await listMailboxes(creds);
    const { total, messages } = await fetchRecent(creds, limit);
    const id = accountId(creds.user, creds.host);
    const account: Account = {
      view: {
        id, label: creds.user, host: creds.host, mailbox: creds.mailbox || "INBOX", demo: false,
        folders: folders.length ? folders : [{ name: creds.mailbox || "INBOX", label: creds.mailbox || "Inbox", role: "inbox" }],
        total, fetched: 0, counts: zero(),
      },
      creds,
      // The user can override this from the compose window; the guess just
      // means sending usually works without asking for more settings.
      smtp: smtp?.host ? smtp : smtpFor(creds.host, creds.user),
      limit, entries: [],
      outbox: this.accounts.get(id)?.outbox ?? [],
    };
    this.accounts.set(id, account);
    await this.ingest(account, messages, config);
    this.activeId = id;
    return this.getStatus();
  }

  /** Switch folder within one account. */
  async selectFolder(id: string, folder: string, config: AppConfig): Promise<MailboxStatus> {
    const account = this.accounts.get(id);
    if (!account) throw new Error("Unknown account.");
    if (account.view.demo || !account.creds) {
      await this.connectDemo(config, account.view.label, folder);
      return this.getStatus();
    }
    const creds = { ...account.creds, mailbox: folder };
    const { total, messages } = await fetchRecent(creds, account.limit);
    account.creds = creds;
    account.view = { ...account.view, mailbox: folder, total };
    await this.ingest(account, messages, config);
    this.activeId = id;
    return this.getStatus();
  }

  /** Remove one account, or every account when no id is given. */
  disconnect(id?: string): MailboxStatus {
    if (id) this.accounts.delete(id);
    else this.accounts.clear();
    if (!this.accounts.has(this.activeId)) this.activeId = "";
    return this.getStatus();
  }

  // ---- Sending ------------------------------------------------------------

  /** Where a message from this account should say it comes from. */
  fromAddress(id: string): string {
    const account = this.accounts.get(id);
    if (!account) return "";
    return account.creds?.user || account.view.label;
  }

  /**
   * Send a message.
   *
   * The message is analysed **before** it is submitted, by the same engine that
   * scores inbound mail. A tool that scans what arrives but not what leaves is
   * only watching half the door: a compromised account sending malware to your
   * customers is the more expensive incident. A malicious verdict refuses the
   * submission unless the sender explicitly overrides it, and the refusal is
   * recorded either way.
   */
  async send(id: string, draft: OutgoingMessage, config: AppConfig, force = false): Promise<SendResult> {
    const account = this.accounts.get(id);
    if (!account) throw new Error("Unknown account.");

    const recipients = envelopeRecipients(draft);
    if (!recipients.length) throw new Error("Add at least one recipient.");

    const messageId = makeMessageId(draft.from);
    const raw = buildMime(draft, messageId);
    const analysis = await analyzeRaw(raw, config);

    if (analysis.verdict === "malicious" && !force) {
      return {
        ok: false, blocked: true, simulated: false, accepted: [], rejected: [],
        reason: `Outbound scan scored this ${analysis.score}/100: ${analysis.summary}`,
        analysis,
      };
    }

    let accepted = recipients;
    let rejected: SendResult["rejected"] = [];
    const simulated = account.view.demo || !account.creds || !account.smtp;

    if (!simulated) {
      const result = await sendMail(
        { ...account.smtp!, user: account.creds!.user, password: account.creds!.password },
        bareAddress(draft.from),
        recipients,
        raw,
      );
      accepted = result.accepted;
      rejected = result.rejected;
    }

    // File it so the Sent folder shows it straight away.
    const parsed = parseMessage(raw);
    account.outbox.unshift({
      analysis,
      item: {
        id: analysis.id,
        accountId: account.view.id,
        accountLabel: account.view.label,
        // Sent items sort above anything fetched, which is what "just sent"
        // should look like.
        seq: Number.MAX_SAFE_INTEGER - account.outbox.length,
        from: { name: parsed.from.name, address: parsed.from.address },
        to: recipients.join(", "),
        subject: parsed.subject,
        date: parsed.date,
        snippet: snippetOf(parsed.text, parsed.html),
        verdict: analysis.verdict,
        score: analysis.score,
        attachmentCount: parsed.attachments.length,
        urlCount: parsed.urls.length,
        findingCount: analysis.findings.length,
        threat: deriveCategories(analysis),
        labels: this.categories.for(analysis.id),
      },
    });

    return {
      ok: true, blocked: false, simulated, accepted, rejected, analysis,
      reason: rejected.length ? `${rejected.length} recipient(s) refused by the server.` : "",
    };
  }

  // ---- Analysis -----------------------------------------------------------

  private async ingest(account: Account, messages: Array<{ seq: number; raw: Buffer }>, config: AppConfig): Promise<void> {
    const entries: Entry[] = [];
    const counts = zero();

    for (const m of messages) {
      const parsed = parseMessage(m.raw);
      const analysis = await analyzeRaw(m.raw, config);
      const threat = deriveCategories(analysis);
      counts[analysis.verdict]++;
      entries.push({
        analysis,
        item: {
          id: analysis.id,
          accountId: account.view.id,
          accountLabel: account.view.label,
          seq: m.seq,
          from: { name: parsed.from.name, address: parsed.from.address },
          to: parsed.to.map((t) => t.address).join(", "),
          subject: parsed.subject,
          date: parsed.date,
          snippet: snippetOf(parsed.text, parsed.html),
          verdict: analysis.verdict,
          score: analysis.score,
          attachmentCount: parsed.attachments.length,
          urlCount: parsed.urls.length,
          findingCount: analysis.findings.length,
          threat,
          labels: this.categories.for(analysis.id),
        },
      });
    }

    account.entries = sortItems(entries);
    account.view = { ...account.view, fetched: entries.length, counts };
  }
}
