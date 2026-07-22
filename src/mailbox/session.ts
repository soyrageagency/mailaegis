/**
 * The connected-mailbox session.
 *
 * Holds, in memory only, the folders and messages pulled from a mailbox plus
 * the analysis of each message, so the web UI can behave like a professional
 * mail client: a folder rail, a scannable message list, and a reading pane —
 * with an antivirus verdict on every row.
 *
 * The credentials live in this process for as long as you stay connected
 * (switching folders needs to re-authenticate) and are never written to disk,
 * never logged, and never returned by the API.
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

/** A row in the message list. */
export interface InboxItem {
  id: string;
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
  /** Automatic threat classes, strongest first. */
  threat: ThreatCategory[];
  /** User label ids assigned to this message. */
  labels: string[];
}

/** What the UI needs to render the chrome. */
export interface MailboxStatus {
  connected: boolean;
  demo: boolean;
  host: string;
  user: string;
  mailbox: string;
  folders: MailboxFolder[];
  total: number;
  fetched: number;
  counts: Record<Verdict, number>;
  threatCounts: Record<string, number>;
}

interface Entry { item: InboxItem; analysis: Analysis }

/** Demo folders, so the mail-client chrome is complete without a server. */
const DEMO_FOLDERS: MailboxFolder[] = [
  { name: "INBOX", label: "Inbox", role: "inbox" },
  { name: "Sent", label: "Sent", role: "sent" },
  { name: "Drafts", label: "Drafts", role: "drafts" },
  { name: "Archive", label: "Archive", role: "archive" },
  { name: "Junk", label: "Junk", role: "junk" },
  { name: "Trash", label: "Trash", role: "trash" },
];

function emptyStatus(): MailboxStatus {
  return {
    connected: false, demo: false, host: "", user: "", mailbox: "", folders: [],
    total: 0, fetched: 0,
    counts: { clean: 0, suspicious: 0, malicious: 0 },
    threatCounts: {},
  };
}

/** Strip a body down to a short preview line. */
function snippetOf(text: string, html: string): string {
  const source = text || html.replace(/<style[\s\S]*?<\/style>/gi, " ").replace(/<[^>]+>/g, " ");
  return source.replace(/\s+/g, " ").trim().slice(0, 160);
}

/** One process-wide mailbox session (the API is single-tenant by design). */
export class MailboxSession {
  private entries: Entry[] = [];
  private status: MailboxStatus = emptyStatus();
  /** Kept only while connected, so folders can be switched. Never persisted. */
  private creds: MailboxCredentials | null = null;
  private limit = 25;

  constructor(private readonly categories: CategoryStore) {}

  getStatus(): MailboxStatus { return this.status; }
  list(): InboxItem[] { return this.entries.map((e) => e.item); }
  get(id: string): Analysis | undefined { return this.entries.find((e) => e.item.id === id)?.analysis; }

  disconnect(): void {
    this.entries = [];
    this.status = emptyStatus();
    this.creds = null;
  }

  /** Re-read the labels for every loaded message (after an assignment). */
  refreshLabels(): void {
    for (const e of this.entries) e.item.labels = this.categories.for(e.item.id);
  }

  /** Load the built-in corpus as if it were a mailbox. */
  async connectDemo(config: AppConfig, folder = "INBOX"): Promise<MailboxStatus> {
    const samples = demoMessages();
    // "Sent" shows only the messages our own company would have sent.
    const chosen = folder.toLowerCase() === "sent" ? samples.filter((s) => s.id === "clean-invoice") : samples;
    const raws = chosen.map((s, i) => ({ seq: chosen.length - i, raw: Buffer.from(s.raw, "utf8") }));
    this.creds = null;
    this.status = { ...emptyStatus(), connected: true, demo: true, host: "demo.mailbox", user: "security@corp.example", mailbox: folder, folders: DEMO_FOLDERS, total: chosen.length };
    await this.ingest(raws, config);
    return this.status;
  }

  /** Connect to a real mailbox: enumerate folders, fetch and analyse. */
  async connect(creds: MailboxCredentials, config: AppConfig, limit: number): Promise<MailboxStatus> {
    const folders = await listMailboxes(creds);
    const { total, messages } = await fetchRecent(creds, limit);
    this.creds = creds;
    this.limit = limit;
    this.status = {
      ...emptyStatus(), connected: true, demo: config.demo,
      host: creds.host, user: creds.user, mailbox: creds.mailbox || "INBOX",
      folders: folders.length ? folders : [{ name: creds.mailbox || "INBOX", label: creds.mailbox || "Inbox", role: "inbox" }],
      total,
    };
    await this.ingest(messages, config);
    return this.status;
  }

  /** Switch to another folder using the credentials already in the session. */
  async selectFolder(name: string, config: AppConfig): Promise<MailboxStatus> {
    if (this.status.demo || !this.creds) return this.connectDemo(config, name);
    const creds = { ...this.creds, mailbox: name };
    const { total, messages } = await fetchRecent(creds, this.limit);
    this.creds = creds;
    this.status = { ...this.status, mailbox: name, total, counts: { clean: 0, suspicious: 0, malicious: 0 }, threatCounts: {} };
    await this.ingest(messages, config);
    return this.status;
  }

  /** Analyse a batch of raw messages and build the list. */
  private async ingest(messages: Array<{ seq: number; raw: Buffer }>, config: AppConfig): Promise<void> {
    const entries: Entry[] = [];
    const counts: Record<Verdict, number> = { clean: 0, suspicious: 0, malicious: 0 };
    const threatCounts: Record<string, number> = {};

    for (const m of messages) {
      const parsed = parseMessage(m.raw);
      const analysis = await analyzeRaw(m.raw, config);
      const threat = deriveCategories(analysis);
      counts[analysis.verdict]++;
      for (const t of threat) threatCounts[t] = (threatCounts[t] ?? 0) + 1;
      entries.push({
        analysis,
        item: {
          id: analysis.id,
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

    // Most dangerous first, then newest — what a security inbox should show.
    const rank: Record<Verdict, number> = { malicious: 0, suspicious: 1, clean: 2 };
    entries.sort((a, b) => rank[a.item.verdict] - rank[b.item.verdict] || b.item.seq - a.item.seq);
    this.entries = entries;
    this.status = { ...this.status, fetched: entries.length, counts, threatCounts };
  }
}
