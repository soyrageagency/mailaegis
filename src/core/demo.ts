/**
 * A small corpus of realistic corporate messages, built at runtime.
 *
 * It lets anyone see exactly what MailAegis catches without wiring up a mail
 * server, a VirusTotal key or a ClamAV daemon — and it is what CI runs.
 * The "malicious" samples carry the EICAR test string, never real malware.
 *
 * The fictional company is `corp.example`.
 *
 * Part of MailAegis — Corporate Email Threat Analyzer.
 * Crafted by SoyRage Agency — https://soyrage.es/
 * Licensed under the SoyRage Attribution License (see LICENSE).
 */

/** The industry-standard antivirus test file — harmless, universally detected. */
export const EICAR_TEST_STRING =
  "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

interface DemoAttachment {
  filename: string;
  type: string;
  content: Buffer;
}

interface EmlOptions {
  headers: Record<string, string>;
  text?: string;
  html?: string;
  attachments?: DemoAttachment[];
}

/** Wrap base64 at 76 columns, as real MUAs do. */
function b64(content: Buffer): string {
  return (content.toString("base64").match(/.{1,76}/g) ?? []).join("\r\n");
}

/** Build a syntactically correct MIME message. */
function eml({ headers, text = "", html = "", attachments = [] }: EmlOptions): string {
  const lines: string[] = [];
  const outer = "----=_MA_MIXED_9f2b";
  const inner = "----=_MA_ALT_4c1d";
  const multipart = attachments.length > 0;

  for (const [k, v] of Object.entries(headers)) lines.push(`${k}: ${v}`);
  lines.push("MIME-Version: 1.0");

  const bodyBlock: string[] = [];
  if (html && text) {
    bodyBlock.push(`Content-Type: multipart/alternative; boundary="${inner}"`, "");
    bodyBlock.push(`--${inner}`, "Content-Type: text/plain; charset=utf-8", "Content-Transfer-Encoding: 8bit", "", text);
    bodyBlock.push(`--${inner}`, "Content-Type: text/html; charset=utf-8", "Content-Transfer-Encoding: 8bit", "", html);
    bodyBlock.push(`--${inner}--`);
  } else if (html) {
    bodyBlock.push("Content-Type: text/html; charset=utf-8", "Content-Transfer-Encoding: 8bit", "", html);
  } else {
    bodyBlock.push("Content-Type: text/plain; charset=utf-8", "Content-Transfer-Encoding: 8bit", "", text);
  }

  if (!multipart) {
    lines.push(...bodyBlock);
    return lines.join("\r\n");
  }

  lines.push(`Content-Type: multipart/mixed; boundary="${outer}"`, "");
  lines.push(`--${outer}`);
  lines.push(...bodyBlock);
  for (const a of attachments) {
    lines.push(`--${outer}`);
    lines.push(`Content-Type: ${a.type}; name="${a.filename}"`);
    lines.push("Content-Transfer-Encoding: base64");
    lines.push(`Content-Disposition: attachment; filename="${a.filename}"`);
    lines.push("");
    lines.push(b64(a.content));
  }
  lines.push(`--${outer}--`);
  return lines.join("\r\n");
}

/** One labelled sample. */
export interface DemoMessage {
  id: string;
  label: string;
  expectation: string;
  raw: string;
}

const PASS_AUTH = "mx.corp.example; spf=pass smtp.mailfrom=partner.example; dkim=pass header.d=partner.example; dmarc=pass header.from=partner.example";

/** The demo corpus, ordered from benign to hostile. */
export function demoMessages(): DemoMessage[] {
  return [
    {
      id: "clean-invoice",
      label: "Legitimate supplier invoice",
      expectation: "clean",
      raw: eml({
        headers: {
          "Return-Path": "<billing@partner.example>",
          From: '"Partner Ltd Billing" <billing@partner.example>',
          To: "accounts@corp.example",
          Subject: "Invoice INV-2026-0418",
          Date: "Mon, 19 Jan 2026 09:14:02 +0100",
          "Message-ID": "<a1b2c3@partner.example>",
          "Authentication-Results": PASS_AUTH,
          "DKIM-Signature": "v=1; a=rsa-sha256; d=partner.example; s=mail; b=AbCdEf",
        },
        text: "Hello,\n\nPlease find attached invoice INV-2026-0418 for January services.\nPayment terms are unchanged, 30 days.\n\nKind regards,\nPartner Ltd Billing",
        attachments: [{ filename: "INV-2026-0418.pdf", type: "application/pdf", content: Buffer.from("%PDF-1.7\n% demo invoice\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n") }],
      }),
    },
    {
      id: "newsletter",
      label: "Marketing newsletter",
      expectation: "clean",
      raw: eml({
        headers: {
          "Return-Path": "<news@vendor.example>",
          From: '"Vendor Insights" <news@vendor.example>',
          To: "team@corp.example",
          Subject: "Your February product digest",
          Date: "Thu, 05 Feb 2026 08:00:00 +0100",
          "Message-ID": "<news-202602@vendor.example>",
          "Authentication-Results": "mx.corp.example; spf=pass smtp.mailfrom=vendor.example; dkim=pass header.d=vendor.example; dmarc=pass header.from=vendor.example",
        },
        text: "This month: three new integrations and a faster dashboard.\nRead more: https://www.vendor.example/blog/february-digest",
        html: '<p>This month: three new integrations and a faster dashboard.</p><p><a href="https://www.vendor.example/blog/february-digest">Read the February digest</a></p>',
      }),
    },
    {
      id: "bec-ceo-fraud",
      label: "CEO fraud / bank-detail change (BEC)",
      expectation: "malicious",
      raw: eml({
        headers: {
          "Return-Path": "<m.torres.ceo@gmail.com>",
          From: '"Marta Torres | CEO corp.example" <m.torres.ceo@gmail.com>',
          "Reply-To": '"Marta Torres" <finance.director@secure-corp-payments.example>',
          To: "accounts@corp.example",
          Subject: "Urgent - update supplier bank details before 14:00",
          Date: "Tue, 10 Feb 2026 11:42:17 +0100",
          "Message-ID": "<bec-9931@gmail.com>",
          "Authentication-Results": "mx.corp.example; spf=softfail smtp.mailfrom=gmail.com; dkim=none; dmarc=none",
        },
        text:
          "Hi,\n\nI am in back-to-back meetings so I can only be reached by email.\n" +
          "We need to change the bank account details for our supplier before the 14:00 payment run.\n" +
          "Please wire the outstanding invoice urgently to the new account I will send you.\n" +
          "Keep this between us until the announcement.\n\nMarta Torres\nCEO",
      }),
    },
    {
      id: "phishing-credentials",
      label: "Credential phishing from a look-alike domain",
      expectation: "malicious",
      raw: eml({
        headers: {
          "Return-Path": "<it-support@c0rp-example.com>",
          From: '"corp.example IT Support" <it-support@c0rp-example.com>',
          To: "staff@corp.example",
          Subject: "Action required: your password expires today",
          Date: "Wed, 11 Feb 2026 07:05:44 +0100",
          "Message-ID": "<phish-4410@c0rp-example.com>",
          "Authentication-Results": "mx.corp.example; spf=fail smtp.mailfrom=c0rp-example.com; dkim=none; dmarc=fail header.from=c0rp-example.com",
        },
        text: "Your account password expires today. Confirm your credentials to avoid suspension: https://secure-corp-login.example/verify?u=staff",
        html:
          '<p>Your account password will <b>expire today</b>. Please confirm your credentials to avoid your account being suspended.</p>' +
          '<p><a href="https://secure-corp-login.example/verify?u=staff">https://portal.corp.example/account</a></p>' +
          '<p>IT Support</p>',
      }),
    },
    {
      id: "malware-attachment",
      label: "Macro-enabled attachment carrying malware",
      expectation: "malicious",
      raw: eml({
        headers: {
          "Return-Path": "<accounts@billing-notice.example>",
          From: '"Accounts Payable" <accounts@billing-notice.example>',
          To: "finance@corp.example",
          Subject: "Overdue invoice - final notice",
          Date: "Fri, 13 Feb 2026 16:21:09 +0100",
          "Message-ID": "<mal-7781@billing-notice.example>",
          "Authentication-Results": "mx.corp.example; spf=fail smtp.mailfrom=billing-notice.example; dkim=fail header.d=billing-notice.example; dmarc=fail",
        },
        text: "Your invoice is overdue. Enable content in the attached document to view the final notice.",
        attachments: [
          { filename: "Invoice_Feb2026.docm", type: "application/vnd.ms-word.document.macroEnabled.12", content: Buffer.from(EICAR_TEST_STRING) },
          { filename: "statement.pdf.exe", type: "application/octet-stream", content: Buffer.concat([Buffer.from("MZ"), Buffer.from(EICAR_TEST_STRING)]) },
        ],
      }),
    },
  ];
}
