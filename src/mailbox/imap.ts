/**
 * Minimal IMAP client (dependency-free, TLS or plain).
 *
 * Enough of RFC 3501 to do the one job MailAegis needs: log in, select a
 * mailbox, and pull the raw bytes of the most recent messages so they can be
 * analysed. Messages are fetched with `BODY.PEEK[]`, which does **not** set the
 * \Seen flag — reading a mailbox leaves it exactly as it was found.
 *
 * There is exactly one write in this file: `moveMessage`, the quarantine
 * action, and it happens only because a person pressed a button and named a
 * folder. Nothing here ever writes on its own.
 *
 * Credentials are used for the length of a request and are never written to
 * disk by this module.
 *
 * Part of MailAegis — Corporate Email Threat Analyzer.
 * Crafted by SoyRage Agency — https://soyrage.es/
 * Licensed under the SoyRage Attribution License (see LICENSE).
 */

import { connect as netConnect, type Socket } from "node:net";
import { connect as tlsConnect } from "node:tls";
import { accessToken, oauthConfigured, xoauth2, type OAuthSettings } from "./oauth.js";

/** Where and how to reach the mailbox. */
export interface MailboxCredentials {
  host: string;
  port: number;
  user: string;
  password: string;
  /** Implicit TLS (port 993). Set false only for localhost testing. */
  tls: boolean;
  mailbox: string;
  /**
   * When present, authenticate with SASL XOAUTH2 instead of LOGIN — the only
   * way in to a Microsoft 365 tenant with basic auth switched off.
   */
  oauth?: OAuthSettings;
}

/**
 * Authenticate: XOAUTH2 when OAuth is configured, LOGIN otherwise.
 *
 * A failed XOAUTH2 exchange gets a continuation (`+`) carrying a base64 JSON
 * error rather than a plain NO, and the client is expected to send an empty
 * line to end it. Skipping that leaves the connection wedged, so it is handled
 * explicitly instead of being left to the timeout.
 */
async function authenticate(session: ImapSession, creds: MailboxCredentials): Promise<void> {
  if (!creds.oauth || !oauthConfigured(creds.oauth)) {
    await session.command(`LOGIN ${quote(creds.user)} ${quote(creds.password)}`);
    return;
  }
  const token = await accessToken(creds.oauth);
  await session.command(`AUTHENTICATE XOAUTH2 ${xoauth2(creds.user, token)}`);
}

/** One fetched message. */
export interface FetchedMessage {
  /** IMAP sequence number. Valid only for this session — it shifts on expunge. */
  seq: number;
  /**
   * The UID: stable for the life of the mailbox, and the only safe handle for
   * a write. Sequence numbers renumber the moment anything is moved or
   * deleted, so acting on one is how you quarantine the wrong message.
   */
  uid: number;
  raw: Buffer;
}

/** Quote a string for an IMAP command. */
function quote(value: string): string {
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

/**
 * A tiny IMAP conversation driver.
 *
 * IMAP mixes line-oriented responses with `{n}` byte literals, so the reader
 * consumes the buffer explicitly rather than splitting on newlines.
 */
class ImapSession {
  private buffer = Buffer.alloc(0);
  private tag = 0;
  /** Raw message bodies collected from FETCH literals, in arrival order. */
  private literals: Buffer[] = [];
  private lines: string[] = [];

  constructor(private readonly socket: Socket, private readonly timeoutMs: number) {}

  /** Feed new bytes and pull out complete lines and literals. */
  private drain(): void {
    for (;;) {
      const nl = this.buffer.indexOf(0x0a);
      if (nl === -1) return;
      const line = this.buffer.subarray(0, nl).toString("utf8").replace(/\r$/, "");
      const literal = /\{(\d+)\}$/.exec(line);
      if (literal) {
        const size = Number(literal[1]);
        // Wait until the whole literal has arrived.
        if (this.buffer.length < nl + 1 + size) return;
        const body = this.buffer.subarray(nl + 1, nl + 1 + size);
        this.literals.push(Buffer.from(body));
        this.buffer = this.buffer.subarray(nl + 1 + size);
        this.lines.push(line);
        continue;
      }
      this.buffer = this.buffer.subarray(nl + 1);
      this.lines.push(line);
    }
  }

  /** Send a command and resolve with every line up to its tagged completion. */
  command(text: string): Promise<string[]> {
    const tag = `a${++this.tag}`;
    const collected: string[] = [];
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { cleanup(); reject(new Error(`IMAP timeout waiting for "${text.split(" ")[0]}"`)); }, this.timeoutMs);
      const onData = (chunk: Buffer) => {
        this.buffer = Buffer.concat([this.buffer, chunk]);
        this.drain();
        while (this.lines.length) {
          const line = this.lines.shift()!;
          collected.push(line);
          if (line.startsWith(`${tag} `)) {
            cleanup();
            if (/^\S+ OK/i.test(line)) resolve(collected);
            else reject(new Error(line.replace(/^\S+\s+/, "")));
            return;
          }
        }
      };
      const onError = (err: Error) => { cleanup(); reject(err); };
      const cleanup = () => {
        clearTimeout(timer);
        this.socket.off("data", onData);
        this.socket.off("error", onError);
      };
      this.socket.on("data", onData);
      this.socket.on("error", onError);
      this.socket.write(`${tag} ${text}\r\n`);
    });
  }

  /** Wait for the server greeting. */
  greeting(): Promise<void> {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { cleanup(); reject(new Error("IMAP server did not greet us")); }, this.timeoutMs);
      const onData = (chunk: Buffer) => {
        this.buffer = Buffer.concat([this.buffer, chunk]);
        this.drain();
        if (this.lines.some((l) => l.startsWith("* OK"))) { this.lines = []; cleanup(); resolve(); }
      };
      const onError = (err: Error) => { cleanup(); reject(err); };
      const cleanup = () => { clearTimeout(timer); this.socket.off("data", onData); this.socket.off("error", onError); };
      this.socket.on("data", onData);
      this.socket.on("error", onError);
    });
  }

  takeLiterals(): Buffer[] {
    const out = this.literals;
    this.literals = [];
    return out;
  }
}

/** Open a socket to the mail server. */
function openSocket(creds: MailboxCredentials, timeoutMs: number): Promise<Socket> {
  return new Promise((resolve, reject) => {
    const socket = creds.tls
      ? tlsConnect({ host: creds.host, port: creds.port, servername: creds.host })
      : netConnect({ host: creds.host, port: creds.port });
    const timer = setTimeout(() => { socket.destroy(); reject(new Error(`Could not reach ${creds.host}:${creds.port}`)); }, timeoutMs);
    socket.once(creds.tls ? "secureConnect" : "connect", () => { clearTimeout(timer); resolve(socket as Socket); });
    socket.once("error", (err) => { clearTimeout(timer); reject(err); });
  });
}

/**
 * Log in, select the mailbox and fetch the most recent `limit` messages.
 * Always closes the connection, even on failure.
 */
export async function fetchRecent(
  creds: MailboxCredentials,
  limit: number,
  timeoutMs = 20000,
): Promise<{ total: number; messages: FetchedMessage[] }> {
  const socket = await openSocket(creds, timeoutMs);
  const session = new ImapSession(socket, timeoutMs);
  try {
    await session.greeting();
    await authenticate(session, creds);
    const selected = await session.command(`SELECT ${quote(creds.mailbox || "INBOX")}`);

    const existsLine = selected.find((l) => /^\*\s+\d+\s+EXISTS/i.test(l)) ?? "";
    const total = Number(/^\*\s+(\d+)\s+EXISTS/i.exec(existsLine)?.[1] ?? 0);
    if (total === 0) {
      await session.command("LOGOUT").catch(() => {});
      return { total: 0, messages: [] };
    }

    const first = Math.max(1, total - limit + 1);
    const lines = await session.command(`FETCH ${first}:${total} (UID BODY.PEEK[])`);
    const bodies = session.takeLiterals();
    // Sequence numbers and UIDs both appear on the "* <seq> FETCH (UID <n> …"
    // lines, in the same order the literals arrived.
    const headers = lines.filter((l) => /^\*\s+\d+\s+FETCH/i.test(l));
    const seqs = headers.map((l) => Number(/^\*\s+(\d+)/.exec(l)?.[1] ?? 0));
    const uids = headers.map((l) => Number(/UID\s+(\d+)/i.exec(l)?.[1] ?? 0));

    const messages: FetchedMessage[] = bodies.map((raw, i) => ({ seq: seqs[i] ?? first + i, uid: uids[i] ?? 0, raw }));
    await session.command("LOGOUT").catch(() => {});
    return { total, messages: messages.reverse() }; // newest first
  } finally {
    socket.destroy();
  }
}

/**
 * Move one message to another folder — the quarantine action.
 *
 * This is the **only** write MailAegis performs, and it happens solely because
 * a person pressed a button. Everything else in this client is `BODY.PEEK` and
 * leaves the mailbox exactly as it found it.
 *
 * Three routes, tried in order of safety:
 *
 *   `UID MOVE` (RFC 6851) is atomic — the server copies and removes in one
 *   operation, and nothing is left behind if it fails halfway.
 *
 *   `UID COPY` + `UID STORE \Deleted` + `UID EXPUNGE` (RFC 4315) is the
 *   fallback. The point of *UID* EXPUNGE is that it removes only the message
 *   we just flagged; a plain EXPUNGE would also purge anything else in the
 *   mailbox that someone had already marked deleted, in another client, an
 *   hour ago.
 *
 *   If the server offers neither, we copy and flag but **refuse to expunge**,
 *   and say so. Silently destroying mail that was not ours to destroy is worse
 *   than an incomplete move.
 */
export interface MoveResult {
  /** Which route was used: "move", "copy-expunge" or "copy-only". */
  method: "move" | "copy-expunge" | "copy-only";
  /** True when the original is gone from the source folder. */
  removed: boolean;
  /** Set when the folder had to be created first. */
  createdFolder: boolean;
}

export async function moveMessage(
  creds: MailboxCredentials,
  uid: number,
  target: string,
  timeoutMs = 20000,
): Promise<MoveResult> {
  if (!Number.isInteger(uid) || uid <= 0) throw new Error("A valid message UID is required to move a message.");
  const folder = target.trim();
  if (!folder) throw new Error("Name the folder to move it to.");
  if (folder.toLowerCase() === (creds.mailbox || "INBOX").toLowerCase()) {
    throw new Error("The message is already in that folder.");
  }

  const socket = await openSocket(creds, timeoutMs);
  const session = new ImapSession(socket, timeoutMs);
  try {
    await session.greeting();
    await authenticate(session, creds);

    const caps = (await session.command("CAPABILITY")).join(" ").toUpperCase();
    const canMove = /\bMOVE\b/.test(caps);
    const canUidExpunge = /\bUIDPLUS\b/.test(caps);

    // SELECT, not EXAMINE: EXAMINE opens read-only and every write below
    // would be refused.
    await session.command(`SELECT ${quote(creds.mailbox || "INBOX")}`);

    // Create the folder on demand. An ALREADYEXISTS is the normal answer on
    // the second quarantine and is not an error.
    let createdFolder = false;
    try {
      await session.command(`CREATE ${quote(folder)}`);
      createdFolder = true;
    } catch (err) {
      if (!/ALREADYEXISTS|already exists/i.test((err as Error).message)) throw err;
    }

    if (canMove) {
      await session.command(`UID MOVE ${uid} ${quote(folder)}`);
      await session.command("LOGOUT").catch(() => {});
      return { method: "move", removed: true, createdFolder };
    }

    await session.command(`UID COPY ${uid} ${quote(folder)}`);
    await session.command(`UID STORE ${uid} +FLAGS (\\Deleted)`);

    if (!canUidExpunge) {
      await session.command("LOGOUT").catch(() => {});
      return { method: "copy-only", removed: false, createdFolder };
    }
    await session.command(`UID EXPUNGE ${uid}`);
    await session.command("LOGOUT").catch(() => {});
    return { method: "copy-expunge", removed: true, createdFolder };
  } finally {
    socket.destroy();
  }
}

/** A mailbox folder as advertised by the server. */
export interface MailboxFolder {
  /** Full IMAP name, e.g. "INBOX" or "[Gmail]/Sent Mail". */
  name: string;
  /** Friendly label for the UI. */
  label: string;
  /** RFC 6154 special use, when the server declares it. */
  role: "inbox" | "sent" | "drafts" | "junk" | "trash" | "archive" | "other";
}

/** Guess a folder's role from its LIST flags and its name. */
function roleOf(flags: string, name: string): MailboxFolder["role"] {
  const f = flags.toLowerCase();
  const n = name.toLowerCase();
  if (n === "inbox") return "inbox";
  if (f.includes("\\sent") || /\bsent\b|enviados|gesendet|envoy/.test(n)) return "sent";
  if (f.includes("\\drafts") || /draft|borrador/.test(n)) return "drafts";
  if (f.includes("\\junk") || /junk|spam|correo no deseado/.test(n)) return "junk";
  if (f.includes("\\trash") || /trash|deleted|papelera/.test(n)) return "trash";
  if (f.includes("\\archive") || /archive|archivo/.test(n)) return "archive";
  return "other";
}

/** Enumerate the mailboxes the account can see. */
export async function listMailboxes(creds: MailboxCredentials, timeoutMs = 15000): Promise<MailboxFolder[]> {
  const socket = await openSocket(creds, timeoutMs);
  const session = new ImapSession(socket, timeoutMs);
  try {
    await session.greeting();
    await authenticate(session, creds);
    const lines = await session.command('LIST "" "*"');
    await session.command("LOGOUT").catch(() => {});

    const folders: MailboxFolder[] = [];
    for (const line of lines) {
      // * LIST (\HasNoChildren \Sent) "/" "Sent Items"
      const m = /^\*\s+LIST\s+\(([^)]*)\)\s+(?:"[^"]*"|NIL)\s+(?:"([^"]+)"|(\S+))\s*$/i.exec(line);
      if (!m) continue;
      const flags = m[1] ?? "";
      const name = m[2] ?? m[3] ?? "";
      if (!name || /\\noselect/i.test(flags)) continue;
      const label = name.split(/[/.]/).pop() || name;
      folders.push({ name, label, role: roleOf(flags, name) });
    }
    // Inbox first, then Sent, then the rest alphabetically.
    const order: Record<MailboxFolder["role"], number> = { inbox: 0, sent: 1, drafts: 2, archive: 3, junk: 4, trash: 5, other: 6 };
    return folders.sort((a, b) => order[a.role] - order[b.role] || a.label.localeCompare(b.label));
  } finally {
    socket.destroy();
  }
}

/** Verify credentials without fetching anything. */
export async function verify(creds: MailboxCredentials, timeoutMs = 15000): Promise<{ total: number }> {
  const socket = await openSocket(creds, timeoutMs);
  const session = new ImapSession(socket, timeoutMs);
  try {
    await session.greeting();
    await authenticate(session, creds);
    const selected = await session.command(`SELECT ${quote(creds.mailbox || "INBOX")}`);
    const existsLine = selected.find((l) => /^\*\s+\d+\s+EXISTS/i.test(l)) ?? "";
    await session.command("LOGOUT").catch(() => {});
    return { total: Number(/^\*\s+(\d+)\s+EXISTS/i.exec(existsLine)?.[1] ?? 0) };
  } finally {
    socket.destroy();
  }
}
