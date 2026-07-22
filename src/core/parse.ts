/**
 * MIME / RFC-822 message parser (dependency-free).
 *
 * Turns a raw `.eml` byte stream into a `ParsedMessage`: unfolded headers,
 * RFC-2047 decoded subjects and display names, decoded text/HTML bodies,
 * recursively extracted attachments (with their SHA-256), and every URL found
 * in the body — with the anchor text it was hiding behind.
 *
 * Deliberately tolerant: real-world mail is malformed constantly, and a parser
 * that throws is a parser that lets threats through.
 *
 * Part of MailAegis — Corporate Email Threat Analyzer.
 * Crafted by SoyRage Agency — https://soyrage.es/
 * Licensed under the SoyRage Attribution License (see LICENSE).
 */

import { createHash } from "node:crypto";
import type { Address, Attachment, ParsedMessage, UrlRef } from "./types.js";

/** Split the raw message into its header block and body. */
function splitHeadersBody(raw: Buffer): { head: string; body: Buffer } {
  for (let i = 0; i < raw.length - 1; i++) {
    if (raw[i] === 0x0a && raw[i + 1] === 0x0a) return { head: raw.subarray(0, i).toString("utf8"), body: raw.subarray(i + 2) };
    if (raw[i] === 0x0d && raw[i + 1] === 0x0a && raw[i + 2] === 0x0d && raw[i + 3] === 0x0a) {
      return { head: raw.subarray(0, i).toString("utf8"), body: raw.subarray(i + 4) };
    }
  }
  return { head: raw.toString("utf8"), body: Buffer.alloc(0) };
}

/** Unfold continuation lines and split "Name: value" pairs. */
function parseHeaderBlock(head: string): { headers: Record<string, string>; received: string[] } {
  const headers: Record<string, string> = {};
  const received: string[] = [];
  const lines = head.split(/\r?\n/);
  const unfolded: string[] = [];
  for (const line of lines) {
    if (/^[ \t]/.test(line) && unfolded.length > 0) unfolded[unfolded.length - 1] += " " + line.trim();
    else unfolded.push(line);
  }
  for (const line of unfolded) {
    const colon = line.indexOf(":");
    if (colon <= 0) continue;
    const key = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    if (key === "received") received.push(value);
    // Last occurrence wins, except Received which we keep in full.
    headers[key] = key in headers && key !== "received" ? headers[key] : value;
    if (key !== "received") headers[key] = value;
  }
  return { headers, received };
}

/** Decode an RFC-2047 encoded-word run ("=?utf-8?B?…?=" / "=?…?Q?…?="). */
export function decodeWords(input: string): string {
  if (!input.includes("=?")) return input;
  return input.replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g, (_m, charset: string, enc: string, data: string) => {
    try {
      const bytes = enc.toUpperCase() === "B"
        ? Buffer.from(data, "base64")
        : Buffer.from(data.replace(/_/g, " ").replace(/=([0-9A-Fa-f]{2})/g, (_x, h: string) => String.fromCharCode(parseInt(h, 16))), "binary");
      return decodeBytes(bytes, charset);
    } catch {
      return data;
    }
  }).replace(/\?=\s+=\?/g, "");
}

/** Decode bytes using a charset label, falling back to UTF-8. */
function decodeBytes(bytes: Buffer, charset = "utf-8"): string {
  const label = (charset || "utf-8").toLowerCase().replace(/['"]/g, "");
  try {
    return new TextDecoder(label).decode(bytes);
  } catch {
    return bytes.toString("utf8");
  }
}

/** Decode a Content-Transfer-Encoding payload. */
function decodeTransfer(body: Buffer, encoding: string): Buffer {
  const enc = encoding.toLowerCase().trim();
  if (enc === "base64") return Buffer.from(body.toString("ascii").replace(/[^A-Za-z0-9+/=]/g, ""), "base64");
  if (enc === "quoted-printable") {
    const text = body.toString("binary").replace(/=\r?\n/g, "");
    const out: number[] = [];
    for (let i = 0; i < text.length; i++) {
      if (text[i] === "=" && /[0-9A-Fa-f]{2}/.test(text.slice(i + 1, i + 3))) {
        out.push(parseInt(text.slice(i + 1, i + 3), 16));
        i += 2;
      } else out.push(text.charCodeAt(i) & 0xff);
    }
    return Buffer.from(out);
  }
  return body;
}

/** Pull a parameter out of a structured header ("…; filename=\"x.pdf\""). */
function param(value: string, name: string): string {
  const quoted = new RegExp(`${name}\\s*=\\s*"([^"]*)"`, "i").exec(value);
  if (quoted) return quoted[1];
  const bare = new RegExp(`${name}\\s*=\\s*([^;\\s]+)`, "i").exec(value);
  if (bare) return bare[1];
  // RFC-2231 continuation: filename*0="a"; filename*1="b"
  const parts: string[] = [];
  const re = new RegExp(`${name}\\*(\\d+)\\*?\\s*=\\s*"?([^";]*)"?`, "gi");
  let m: RegExpExecArray | null;
  while ((m = re.exec(value))) parts.push(m[2]);
  return parts.join("");
}

/** Parse a single address ("Name <a@b.c>" / "a@b.c"). */
export function parseAddress(raw: string): Address {
  const value = decodeWords((raw || "").trim());
  const angle = /<([^>]*)>/.exec(value);
  const address = (angle ? angle[1] : value).trim().replace(/^["']|["']$/g, "").toLowerCase();
  let name = angle ? value.slice(0, angle.index).trim() : "";
  name = name.replace(/^["']|["']$/g, "").trim();
  const at = address.lastIndexOf("@");
  return { name, address, domain: at >= 0 ? address.slice(at + 1) : "" };
}

/** Parse a comma-separated address list, respecting quoted display names. */
export function parseAddressList(raw: string): Address[] {
  if (!raw) return [];
  const out: string[] = [];
  let cur = "";
  let inQuote = false;
  let inAngle = false;
  for (const ch of raw) {
    if (ch === '"') inQuote = !inQuote;
    if (ch === "<") inAngle = true;
    if (ch === ">") inAngle = false;
    if (ch === "," && !inQuote && !inAngle) { out.push(cur); cur = ""; continue; }
    cur += ch;
  }
  if (cur.trim()) out.push(cur);
  return out.map(parseAddress).filter((a) => a.address);
}

interface Part {
  headers: Record<string, string>;
  body: Buffer;
}

/** Recursively walk a MIME tree, collecting leaf parts. */
function walk(headers: Record<string, string>, body: Buffer, out: Part[], depth = 0): void {
  if (depth > 12) return; // pathological nesting guard
  const ctype = headers["content-type"] ?? "text/plain";
  if (/^multipart\//i.test(ctype)) {
    const boundary = param(ctype, "boundary");
    if (!boundary) { out.push({ headers, body }); return; }
    const marker = `--${boundary}`;
    const text = body.toString("binary");
    const segments: Buffer[] = [];
    let index = text.indexOf(marker);
    while (index !== -1) {
      const start = text.indexOf("\n", index) + 1;
      const next = text.indexOf(marker, start);
      if (start === 0) break;
      const end = next === -1 ? text.length : next;
      segments.push(Buffer.from(text.slice(start, end), "binary"));
      if (next === -1 || text.startsWith(`${marker}--`, next)) break;
      index = next;
    }
    for (const seg of segments) {
      const { head, body: sub } = splitHeadersBody(seg);
      const { headers: subHeaders } = parseHeaderBlock(head);
      walk(subHeaders, sub, out, depth + 1);
    }
    return;
  }
  out.push({ headers, body });
}

/** Extract every URL from the plain-text and HTML bodies. */
export function extractUrls(text: string, html: string): UrlRef[] {
  const seen = new Map<string, UrlRef>();
  const add = (url: string, anchor?: string) => {
    const clean = url.replace(/[)\]}>.,;'"]+$/, "").trim();
    if (!/^https?:\/\//i.test(clean)) return;
    let host = "";
    try { host = new URL(clean).hostname.toLowerCase(); } catch { return; }
    const prev = seen.get(clean);
    if (prev) { if (!prev.text && anchor) prev.text = anchor; return; }
    seen.set(clean, { url: clean, host, text: anchor });
  };

  // HTML anchors first, so we keep the visible text the link hid behind.
  const anchorRe = /<a\b[^>]*href\s*=\s*["']?([^"'>\s]+)["']?[^>]*>([\s\S]*?)<\/a>/gi;
  let m: RegExpExecArray | null;
  while ((m = anchorRe.exec(html))) {
    const anchor = m[2].replace(/<[^>]+>/g, "").replace(/&nbsp;/g, " ").trim();
    add(decodeEntities(m[1]), anchor || undefined);
  }
  // Strip whole anchors before hunting bare URLs: their hrefs are already
  // captured, and their *text* is display-only — a phishing mail that shows
  // "https://portal.corp.example" while linking elsewhere must not have the
  // decoy counted as a real destination.
  const htmlWithoutAnchors = html.replace(/<a\b[^>]*>[\s\S]*?<\/a>/gi, " ").replace(/<[^>]+>/g, " ");
  const bare = /\bhttps?:\/\/[^\s<>"')]+/gi;
  for (const source of [text, htmlWithoutAnchors]) {
    bare.lastIndex = 0;
    while ((m = bare.exec(source))) add(decodeEntities(m[0]));
  }
  return [...seen.values()];
}

function decodeEntities(s: string): string {
  return s.replace(/&amp;/g, "&").replace(/&#(\d+);/g, (_m, d: string) => String.fromCharCode(Number(d)));
}

/** Parse a raw message into the analysable model. */
export function parseMessage(raw: Buffer | string): ParsedMessage {
  const buf = Buffer.isBuffer(raw) ? raw : Buffer.from(raw, "utf8");
  const { head, body } = splitHeadersBody(buf);
  const { headers, received } = parseHeaderBlock(head);

  const parts: Part[] = [];
  walk(headers, body, parts);

  let text = "";
  let html = "";
  const attachments: Attachment[] = [];

  for (const part of parts) {
    const ctype = part.headers["content-type"] ?? "text/plain";
    const disposition = part.headers["content-disposition"] ?? "";
    const encoding = part.headers["content-transfer-encoding"] ?? "7bit";
    const decoded = decodeTransfer(part.body, encoding);
    const filename = decodeWords(param(disposition, "filename") || param(ctype, "name"));
    const isAttachment = /attachment/i.test(disposition) || (filename !== "" && !/^text\/(plain|html)/i.test(ctype));

    if (isAttachment) {
      const dot = filename.lastIndexOf(".");
      attachments.push({
        filename: filename || "(unnamed)",
        contentType: ctype.split(";")[0].trim().toLowerCase(),
        size: decoded.length,
        sha256: createHash("sha256").update(decoded).digest("hex"),
        extension: dot > 0 ? filename.slice(dot + 1).toLowerCase() : "",
        content: decoded,
      });
      continue;
    }
    const charset = param(ctype, "charset") || "utf-8";
    if (/^text\/html/i.test(ctype)) html += decodeBytes(decoded, charset);
    else if (/^text\//i.test(ctype)) text += decodeBytes(decoded, charset);
  }

  const from = parseAddress(headers["from"] ?? "");
  const replyToRaw = headers["reply-to"];
  const returnPathRaw = headers["return-path"];

  return {
    headers,
    received,
    from,
    replyTo: replyToRaw ? parseAddress(replyToRaw) : undefined,
    returnPath: returnPathRaw ? parseAddress(returnPathRaw) : undefined,
    to: parseAddressList(headers["to"] ?? ""),
    subject: decodeWords(headers["subject"] ?? ""),
    date: headers["date"] ?? "",
    messageId: (headers["message-id"] ?? "").replace(/[<>]/g, ""),
    text,
    html,
    attachments,
    urls: extractUrls(text, html),
    rawSize: buf.length,
  };
}
