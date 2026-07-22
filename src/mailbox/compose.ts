/**
 * Building outbound messages.
 *
 * MailAegis parses RFC-822 already; composing it is the same grammar in
 * reverse, and doing it by hand keeps the zero-dependency promise while the
 * usual libraries drag in a hundred transitive packages to concatenate strings.
 *
 * The parts that are easy to get subtly wrong, and that this file therefore
 * takes seriously: non-ASCII in headers (RFC 2047), non-ASCII in bodies
 * (quoted-printable, with the 76-column limit and the trailing-whitespace rule),
 * filenames in attachments (RFC 2231 rather than the broken RFC 2047 form some
 * clients emit), and header injection — a subject with a newline in it must
 * never be able to invent a Bcc.
 *
 * Part of MailAegis — Corporate Email Threat Analyzer.
 * Crafted by SoyRage Agency — https://soyrage.es/
 * Licensed under the SoyRage Attribution License (see LICENSE).
 */

import { randomBytes } from "node:crypto";

export interface OutgoingAttachment {
  filename: string;
  contentType: string;
  /** Raw bytes. The API accepts base64 and decodes before it gets here. */
  content: Buffer;
  /** Set for inline images referenced by cid: in the HTML part. */
  contentId?: string;
}

export interface OutgoingMessage {
  from: string;
  to: string[];
  cc: string[];
  bcc: string[];
  subject: string;
  text: string;
  html: string;
  attachments: OutgoingAttachment[];
  /** Threading, when this is a reply. */
  inReplyTo?: string;
  references?: string[];
  /** Overrides the generated date — used by the demo so output is stable. */
  date?: Date;
}

const CRLF = "\r\n";

/**
 * Strip anything that could start a new header line.
 *
 * A subject is user input, and `Subject: hi\r\nBcc: everyone@rival.example`
 * is the oldest trick in the book. Folding whitespace goes too: we re-fold
 * ourselves where it is legitimate.
 */
export function sanitiseHeaderValue(value: string): string {
  return String(value ?? "").replace(/[\r\n]+/g, " ").trim();
}

/** True when the string is plain 7-bit and needs no encoding at all. */
const isAscii = (s: string): boolean => !/[^\x20-\x7e]/.test(s);

/**
 * RFC 2047 encoded-word, base64 flavour.
 *
 * Chunked on character boundaries rather than byte boundaries: splitting a
 * multi-byte UTF-8 sequence across two encoded-words produces mojibake in
 * every client that decodes them independently, which is all of them.
 */
export function encodeWord(value: string): string {
  if (isAscii(value)) return value;
  const limit = 39; // 39 base64 chars ≈ 75-column encoded-word with the wrapper
  const words: string[] = [];
  let chunk = "";
  for (const ch of value) {
    const candidate = chunk + ch;
    if (Buffer.byteLength(candidate, "utf8") > limit) { words.push(chunk); chunk = ch; }
    else chunk = candidate;
  }
  if (chunk) words.push(chunk);
  return words.map((w) => `=?UTF-8?B?${Buffer.from(w, "utf8").toString("base64")}?=`).join(`${CRLF} `);
}

/** Format one address, encoding the display name when it is not plain ASCII. */
export function formatAddress(raw: string): string {
  const value = sanitiseHeaderValue(raw);
  const match = /^\s*(.*?)\s*<([^>]+)>\s*$/.exec(value);
  if (!match) return value;
  const [, name, address] = match;
  if (!name) return `<${address}>`;
  // A quoted string cannot contain a bare quote or backslash.
  const safe = name.replace(/["\\]/g, "");
  return isAscii(safe) ? `"${safe}" <${address}>` : `${encodeWord(safe)} <${address}>`;
}

/** Just the addr-spec, for the SMTP envelope. */
export function bareAddress(raw: string): string {
  const value = sanitiseHeaderValue(raw);
  const match = /<([^>]+)>/.exec(value);
  return (match ? match[1] : value).trim();
}

/**
 * Quoted-printable, per RFC 2045.
 *
 * The rule people forget is the last one: a space or tab at the end of a line
 * must be encoded, because every mail transfer agent between here and the
 * recipient is entitled to strip it.
 */
export function quotedPrintable(input: string): string {
  const bytes = Buffer.from(input.replace(/\r?\n/g, "\n"), "utf8");
  let out = "";
  let column = 0;

  const push = (token: string) => {
    if (column + token.length > 75) { out += `=${CRLF}`; column = 0; }
    out += token;
    column += token.length;
  };

  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i]!;
    if (b === 0x0a) { out += CRLF; column = 0; continue; }
    const literal = b >= 0x20 && b <= 0x7e && b !== 0x3d;
    // Trailing whitespace only survives if it is encoded.
    const atLineEnd = i + 1 >= bytes.length || bytes[i + 1] === 0x0a;
    if (literal && !((b === 0x20 || b === 0x09) && atLineEnd)) push(String.fromCharCode(b));
    else push(`=${b.toString(16).toUpperCase().padStart(2, "0")}`);
  }
  return out;
}

/** Base64 in 76-column lines, as every MIME body part expects. */
function base64Lines(buffer: Buffer): string {
  return (buffer.toString("base64").match(/.{1,76}/g) ?? []).join(CRLF);
}

/**
 * RFC 2231 filename parameter.
 *
 * The RFC 2047 encoded-word form inside a parameter is technically illegal and
 * Outlook renders it literally, so non-ASCII names get percent-encoding and the
 * plain `filename=` is kept alongside for ancient clients.
 */
function filenameParams(name: string): string {
  const clean = sanitiseHeaderValue(name).replace(/["\\/]/g, "_") || "attachment";
  if (isAscii(clean)) return `; filename="${clean}"`;
  const ascii = clean.replace(/[^\x20-\x7e]/g, "_");
  const encoded = encodeURIComponent(clean).replace(/'/g, "%27");
  return `; filename="${ascii}"${CRLF} filename*=UTF-8''${encoded}`;
}

/** A Message-ID whose right-hand side is the sender's own domain. */
export function makeMessageId(from: string): string {
  const domain = bareAddress(from).split("@")[1] || "mailaegis.local";
  return `<${Date.now().toString(36)}.${randomBytes(8).toString("hex")}@${domain}>`;
}

/** Build the full RFC-822 message, ready to hand to SMTP or to the analyzer. */
export function buildMime(message: OutgoingMessage, messageId = makeMessageId(message.from)): Buffer {
  const boundary = `--=_MailAegis_${randomBytes(12).toString("hex")}`;
  const altBoundary = `--=_MailAegis_alt_${randomBytes(12).toString("hex")}`;
  const headers: string[] = [];

  const addressList = (list: string[]) => list.map(formatAddress).filter(Boolean).join(", ");

  headers.push(`From: ${formatAddress(message.from)}`);
  if (message.to.length) headers.push(`To: ${addressList(message.to)}`);
  if (message.cc.length) headers.push(`Cc: ${addressList(message.cc)}`);
  // Bcc is deliberately absent: it belongs in the envelope, never in the body,
  // or every recipient learns who else was blind-copied.
  headers.push(`Subject: ${encodeWord(sanitiseHeaderValue(message.subject))}`);
  headers.push(`Date: ${(message.date ?? new Date()).toUTCString().replace("GMT", "+0000")}`);
  headers.push(`Message-ID: ${messageId}`);
  if (message.inReplyTo) headers.push(`In-Reply-To: ${sanitiseHeaderValue(message.inReplyTo)}`);
  if (message.references?.length) headers.push(`References: ${message.references.map(sanitiseHeaderValue).join(" ")}`);
  headers.push("MIME-Version: 1.0");
  headers.push("X-Mailer: MailAegis (SoyRage Agency)");

  const textPart = () => [
    "Content-Type: text/plain; charset=UTF-8",
    "Content-Transfer-Encoding: quoted-printable",
    "",
    quotedPrintable(message.text || ""),
  ].join(CRLF);

  const htmlPart = () => [
    "Content-Type: text/html; charset=UTF-8",
    "Content-Transfer-Encoding: quoted-printable",
    "",
    quotedPrintable(message.html),
  ].join(CRLF);

  // The body shape depends on what is actually present — a plain note with no
  // attachments should not arrive as a multipart with one part.
  let body: string;
  const alternative = message.html
    ? [
        `Content-Type: multipart/alternative; boundary="${altBoundary}"`,
        "",
        `--${altBoundary}`, textPart(),
        `--${altBoundary}`, htmlPart(),
        `--${altBoundary}--`,
      ].join(CRLF)
    : textPart();

  if (message.attachments.length) {
    headers.push(`Content-Type: multipart/mixed; boundary="${boundary}"`);
    const parts = [`--${boundary}`, alternative];
    for (const a of message.attachments) {
      parts.push(`--${boundary}`);
      parts.push([
        `Content-Type: ${sanitiseHeaderValue(a.contentType) || "application/octet-stream"}`,
        `Content-Transfer-Encoding: base64`,
        `Content-Disposition: ${a.contentId ? "inline" : "attachment"}${filenameParams(a.filename)}`,
        ...(a.contentId ? [`Content-ID: <${sanitiseHeaderValue(a.contentId)}>`] : []),
        "",
        base64Lines(a.content),
      ].join(CRLF));
    }
    parts.push(`--${boundary}--`);
    body = parts.join(CRLF);
  } else if (message.html) {
    headers.push(`Content-Type: multipart/alternative; boundary="${altBoundary}"`);
    body = [`--${altBoundary}`, textPart(), `--${altBoundary}`, htmlPart(), `--${altBoundary}--`].join(CRLF);
  } else {
    headers.push("Content-Type: text/plain; charset=UTF-8");
    headers.push("Content-Transfer-Encoding: quoted-printable");
    body = quotedPrintable(message.text || "");
  }

  return Buffer.from(`${headers.join(CRLF)}${CRLF}${CRLF}${body}${CRLF}`, "utf8");
}

/** Everyone the envelope has to deliver to, deduplicated. */
export function envelopeRecipients(message: OutgoingMessage): string[] {
  const all = [...message.to, ...message.cc, ...message.bcc].map(bareAddress).filter(Boolean);
  return [...new Set(all.map((a) => a.toLowerCase()))];
}

// ---- Replying and forwarding ----------------------------------------------

/** The quoted block a reply carries below the new text. */
export function quoteBody(from: string, date: string, text: string): string {
  const attribution = `On ${date || "an earlier date"}, ${from} wrote:`;
  const quoted = String(text || "").split(/\r?\n/).map((l) => `> ${l}`).join("\n");
  return `\n\n${attribution}\n${quoted}\n`;
}

/** "Re:" / "Fwd:" without stacking them on every round trip. */
export function replySubject(subject: string): string {
  const s = sanitiseHeaderValue(subject);
  return /^re:/i.test(s) ? s : `Re: ${s}`;
}

export function forwardSubject(subject: string): string {
  const s = sanitiseHeaderValue(subject);
  return /^(fwd?|rv):/i.test(s) ? s : `Fwd: ${s}`;
}
