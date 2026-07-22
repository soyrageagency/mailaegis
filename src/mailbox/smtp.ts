/**
 * Minimal SMTP submission client (dependency-free, implicit TLS or STARTTLS).
 *
 * Enough of RFC 5321 and RFC 4954 to hand a message to a corporate submission
 * server: greeting, EHLO, optional STARTTLS upgrade, AUTH, envelope, DATA.
 *
 * Two details that decide whether mail actually arrives, and that this file
 * therefore does properly: the reply reader understands multi-line responses
 * (`250-PIPELINING` … `250 SIZE`), and DATA is dot-stuffed — a body line that
 * begins with a period would otherwise end the message early and truncate it.
 *
 * Credentials live for the length of one submission and are never written to
 * disk or logged by this module.
 *
 * Part of MailAegis — Corporate Email Threat Analyzer.
 * Crafted by SoyRage Agency — https://soyrage.es/
 * Licensed under the SoyRage Attribution License (see LICENSE).
 */

import { connect as netConnect, type Socket } from "node:net";
import { connect as tlsConnect } from "node:tls";
import { hostname } from "node:os";

/** Where and how to reach the submission server. */
export interface SmtpCredentials {
  host: string;
  port: number;
  user: string;
  password: string;
  /** Implicit TLS (465). False means plain 587 upgraded with STARTTLS. */
  tls: boolean;
}

export interface SmtpResult {
  /** The server's reply to the final dot — useful in a delivery log. */
  response: string;
  accepted: string[];
  rejected: Array<{ address: string; reply: string }>;
}

/** One SMTP reply: a status code and everything the server said with it. */
interface Reply { code: number; text: string }

class SmtpSession {
  private buffer = "";
  private waiter: ((reply: Reply) => void) | null = null;
  private failure: ((err: Error) => void) | null = null;
  private pending: Reply[] = [];

  constructor(private socket: Socket, private readonly timeoutMs: number) {
    this.attach(socket);
  }

  private attach(socket: Socket): void {
    this.socket = socket;
    socket.setEncoding("utf8");
    socket.on("data", (chunk: string) => this.drain(chunk));
    socket.on("error", (err) => this.failure?.(err));
  }

  /**
   * Collect complete replies. A reply is a run of lines sharing a code; only
   * the line whose fourth character is a space terminates it.
   */
  private drain(chunk: string): void {
    this.buffer += chunk;
    for (;;) {
      const nl = this.buffer.indexOf("\n");
      if (nl === -1) return;
      const line = this.buffer.slice(0, nl).replace(/\r$/, "");
      this.buffer = this.buffer.slice(nl + 1);
      this.collected.push(line);
      if (line.length >= 4 && line[3] !== "-") {
        const reply: Reply = { code: Number(line.slice(0, 3)) || 0, text: this.collected.join("\n") };
        this.collected = [];
        if (this.waiter) { const w = this.waiter; this.waiter = null; w(reply); }
        else this.pending.push(reply);
      } else if (line.length < 4) {
        // Not a well-formed reply line; treat the run as finished so we fail
        // with the server's own words rather than hanging until the timeout.
        const reply: Reply = { code: 0, text: this.collected.join("\n") };
        this.collected = [];
        if (this.waiter) { const w = this.waiter; this.waiter = null; w(reply); }
        else this.pending.push(reply);
      }
    }
  }

  private collected: string[] = [];

  /** Wait for the next reply. */
  read(): Promise<Reply> {
    const queued = this.pending.shift();
    if (queued) return Promise.resolve(queued);
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.waiter = null; reject(new Error("SMTP server did not reply in time.")); }, this.timeoutMs);
      this.waiter = (reply) => { clearTimeout(timer); resolve(reply); };
      this.failure = (err) => { clearTimeout(timer); reject(err); };
    });
  }

  write(line: string): void {
    this.socket.write(`${line}\r\n`);
  }

  /** Push an already-terminated payload, used for the DATA body. */
  writeRaw(payload: Buffer): void {
    this.socket.write(payload);
  }

  /** Send a command and insist on an expected status class. */
  async command(line: string, expect: number[], redact = false): Promise<Reply> {
    this.write(line);
    const reply = await this.read();
    if (!expect.includes(Math.floor(reply.code / 100))) {
      const shown = redact ? "(credentials)" : line;
      throw new Error(`SMTP ${shown} rejected: ${reply.text.trim()}`);
    }
    return reply;
  }

  /** Swap the plain socket for a TLS one after STARTTLS. */
  upgrade(host: string): Promise<void> {
    return new Promise((resolve, reject) => {
      this.socket.removeAllListeners("data");
      this.socket.removeAllListeners("error");
      const secure = tlsConnect({ socket: this.socket, servername: host }, () => { this.attach(secure); resolve(); });
      secure.once("error", reject);
    });
  }

  end(): void {
    try { this.socket.end(); } catch { /* already gone */ }
    this.socket.destroy();
  }
}

/** Dot-stuffing: a body line starting with "." would otherwise end DATA. */
export function dotStuff(raw: Buffer): Buffer {
  const body = raw.toString("binary").replace(/\r?\n/g, "\r\n").replace(/^\./gm, "..");
  return Buffer.from(body.endsWith("\r\n") ? body : `${body}\r\n`, "binary");
}

/**
 * Submit one message.
 *
 * A recipient the server refuses is recorded rather than thrown: sending to
 * nine of ten addresses is a partial success worth reporting, not a failure
 * worth discarding. Every recipient failing is an error.
 */
export async function sendMail(
  creds: SmtpCredentials,
  envelopeFrom: string,
  recipients: string[],
  raw: Buffer,
  timeoutMs = 20000,
): Promise<SmtpResult> {
  if (!recipients.length) throw new Error("No recipients.");
  const session = await openSession(creds, timeoutMs);

  try {
    await session.command(`MAIL FROM:<${envelopeFrom}>`, [2]);

    const accepted: string[] = [];
    const rejected: SmtpResult["rejected"] = [];
    for (const address of recipients) {
      session.write(`RCPT TO:<${address}>`);
      const reply = await session.read();
      if (Math.floor(reply.code / 100) === 2) accepted.push(address);
      else rejected.push({ address, reply: reply.text.trim() });
    }
    if (!accepted.length) throw new Error(`Every recipient was refused: ${rejected.map((r) => `${r.address} — ${r.reply}`).join("; ")}`);

    await session.command("DATA", [3]);
    session.writeRaw(dotStuff(raw));
    session.write(".");
    const done = await session.read();
    if (Math.floor(done.code / 100) !== 2) throw new Error(`Message refused: ${done.text.trim()}`);

    try { await session.command("QUIT", [2]); } catch { /* a rude goodbye is harmless */ }
    return { response: done.text.trim(), accepted, rejected };
  } finally {
    session.end();
  }
}

/** Connect, negotiate TLS and authenticate — everything before the envelope. */
async function openSession(creds: SmtpCredentials, timeoutMs: number): Promise<SmtpSession> {
  const socket = creds.tls
    ? tlsConnect({ host: creds.host, port: creds.port, servername: creds.host })
    : netConnect({ host: creds.host, port: creds.port });
  socket.setTimeout(timeoutMs);

  await new Promise<void>((resolve, reject) => {
    socket.once(creds.tls ? "secureConnect" : "connect", () => resolve());
    socket.once("error", reject);
    socket.once("timeout", () => reject(new Error(`Timed out connecting to ${creds.host}:${creds.port}.`)));
  });

  const session = new SmtpSession(socket, timeoutMs);
  const me = hostname() || "mailaegis.local";

  try {
    const greeting = await session.read();
    if (Math.floor(greeting.code / 100) !== 2) throw new Error(`SMTP greeting refused: ${greeting.text.trim()}`);

    let ehlo = await session.command(`EHLO ${me}`, [2]);

    if (!creds.tls && /STARTTLS/i.test(ehlo.text)) {
      await session.command("STARTTLS", [2]);
      await session.upgrade(creds.host);
      // The capability list before and after the upgrade may differ, and only
      // the second one counts — that is the whole point of STARTTLS.
      ehlo = await session.command(`EHLO ${me}`, [2]);
    }

    if (creds.user) {
      if (/AUTH[ =-][^\n]*PLAIN/i.test(ehlo.text)) {
        const token = Buffer.from(`\0${creds.user}\0${creds.password}`, "utf8").toString("base64");
        await session.command(`AUTH PLAIN ${token}`, [2], true);
      } else {
        await session.command("AUTH LOGIN", [3], true);
        await session.command(Buffer.from(creds.user, "utf8").toString("base64"), [3], true);
        await session.command(Buffer.from(creds.password, "utf8").toString("base64"), [2], true);
      }
    }

    return session;
  } catch (err) {
    session.end();
    throw err;
  }
}

/** Check credentials without sending anything — used by the compose form. */
export async function verifySmtp(creds: SmtpCredentials, timeoutMs = 12000): Promise<void> {
  const session = await openSession(creds, timeoutMs);
  try { await session.command("QUIT", [2]); } catch { /* nothing to salvage */ }
  session.end();
}
