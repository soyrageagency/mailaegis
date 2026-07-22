/**
 * Robustness probe for the MIME parser and URL extractor.
 *
 * A mail parser reads attacker-controlled bytes, so it must never hang, throw
 * or blow up on malformed input. Every case is timed; anything slow is a
 * potential denial-of-service in a mail pipeline.
 *
 * Run: node scripts/fuzz-check.mjs
 *
 * Crafted by SoyRage Agency — https://soyrage.es/
 */
import { parseMessage, extractUrls } from "../dist/core/parse.js";
import { zipEntries, magicType } from "../dist/core/engine.js";

let slow = 0, threw = 0;
const NUL = String.fromCharCode(0);

function probe(name, fn) {
  const started = Date.now();
  try {
    const result = fn();
    const ms = Date.now() - started;
    if (ms > 2000) slow++;
    console.log(`${ms > 2000 ? "SLOW" : "ok  "} ${String(ms).padStart(5)}ms  ${name}${result !== undefined ? `  → ${result}` : ""}`);
  } catch (err) {
    threw++;
    console.log(`THROW       ${name}  → ${String(err.message).slice(0, 80)}`);
  }
}

// ---- structural edge cases --------------------------------------------------
probe("empty buffer", () => `${parseMessage(Buffer.alloc(0)).subject === "" ? "no crash" : "?"}`);
probe("headers only, no blank line", () => parseMessage("From: a@b.c\r\nSubject: hi").subject);
probe("no headers at all", () => parseMessage("just a body\r\n").text.trim());
probe("truncated CRLF at end (bounds)", () => parseMessage(Buffer.from("A: b\r\n\r")).headers["a"]);
probe("lone CR", () => parseMessage(Buffer.from("A: b\r")).headers["a"]);
probe("single byte", () => `${parseMessage(Buffer.from("x")).rawSize} bytes`);
probe("NUL bytes in a header", () => `${parseMessage(`Subject: a${NUL}b\r\n\r\nx`).subject.length} chars`);
probe("binary garbage 5KB", () => {
  const b = Buffer.alloc(5000);
  for (let i = 0; i < b.length; i++) b[i] = (i * 7) % 256;
  return `${parseMessage(b).attachments.length} att`;
});

// ---- size / repetition ------------------------------------------------------
probe("1MB single header line", () => `${parseMessage(`Subject: ${"A".repeat(1_000_000)}\r\n\r\nbody`).subject.length} chars`);
probe("10k headers", () => {
  let h = "";
  for (let i = 0; i < 10000; i++) h += `X-H-${i}: v\r\n`;
  return `${Object.keys(parseMessage(`${h}\r\nbody`).headers).length} hdrs`;
});
probe("5MB body", () => `${parseMessage(`Subject: x\r\n\r\n${"b".repeat(5_000_000)}`).text.length} chars`);

// ---- multipart abuse --------------------------------------------------------
probe("multipart with no boundary param", () =>
  parseMessage("Content-Type: multipart/mixed\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\nhi\r\n--x--").text.trim().slice(0, 24));
probe("boundary token appears inside the body", () =>
  parseMessage(['Content-Type: multipart/mixed; boundary="BB"', "", "--BB", "Content-Type: text/plain", "", "we discuss --BB in prose", "--BB--"].join("\r\n")).text.trim().slice(0, 24));
probe("empty boundary value", () =>
  parseMessage('Content-Type: multipart/mixed; boundary=""\r\n\r\nbody').text.trim().slice(0, 20));
probe("nesting x40 (depth guard)", () => {
  let body = "text";
  for (let i = 0; i < 40; i++) body = `Content-Type: multipart/mixed; boundary="b${i}"\r\n\r\n--b${i}\r\nContent-Type: text/plain\r\n\r\n${body}\r\n--b${i}--`;
  return `${parseMessage(body).text.length} chars`;
});
probe("unterminated multipart", () =>
  `${parseMessage('Content-Type: multipart/mixed; boundary="B"\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nhi').text.trim()}`);

// ---- encoding abuse ---------------------------------------------------------
probe("invalid base64 attachment", () =>
  `${parseMessage(['Content-Type: multipart/mixed; boundary="B"', "", "--B", 'Content-Type: application/octet-stream; name="x.bin"', "Content-Transfer-Encoding: base64", "", "!!!!not base64!!!!", "--B--"].join("\r\n")).attachments.length} att`);
probe("unknown charset", () => parseMessage('Content-Type: text/plain; charset="nonsense-9000"\r\n\r\nhola').text.trim());
probe("malformed RFC-2047 word", () => parseMessage("Subject: =?utf-8?B?!!!notb64!!!?=\r\n\r\nx").subject.slice(0, 24));
probe("RFC-2231 filename continuation", () =>
  parseMessage(['Content-Type: multipart/mixed; boundary="B"', "", "--B", 'Content-Disposition: attachment; filename*0="in"; filename*1="voice.exe"', "", "x", "--B--"].join("\r\n")).attachments[0]?.filename);
probe("regex-special filename", () =>
  parseMessage(['Content-Type: multipart/mixed; boundary="B"', "", "--B", 'Content-Disposition: attachment; filename="(a|b)*+.exe"', "", "x", "--B--"].join("\r\n")).attachments[0]?.filename);

// ---- URL extraction (ReDoS surface) ----------------------------------------
probe("2000 anchors", () => `${extractUrls("", '<a href="https://e.example/a">text</a>'.repeat(2000)).length} urls`);
probe("unclosed anchor + 200KB", () => `${extractUrls("", `<a href="https://e.example/a">${"x".repeat(200_000)}`).length} urls`);
probe("5000 bare URLs", () => `${extractUrls("https://a.example/1 ".repeat(5000), "").length} urls`);
probe("50KB single URL", () => `${extractUrls(`http://${"a".repeat(50_000)}`, "").length} urls`);
probe("nested anchors", () => `${extractUrls("", '<a href="https://a.example"><a href="https://b.example">x</a></a>'.repeat(500)).length} urls`);

// ---- archive / magic parsing ------------------------------------------------
probe("zipEntries on random bytes", () => {
  const b = Buffer.alloc(20000);
  for (let i = 0; i < b.length; i++) b[i] = (i * 13) % 256;
  return `${zipEntries(b).names.length} names`;
});
probe("zipEntries on a truncated central directory", () => {
  const b = Buffer.from([0x50, 0x4b, 0x01, 0x02, 0xff, 0xff]);
  return `${zipEntries(b).names.length} names`;
});
probe("magicType on empty", () => `"${magicType(Buffer.alloc(0))}"`);

console.log(`\n${slow} slow (>2s), ${threw} threw.`);
process.exitCode = slow || threw ? 1 : 0;
