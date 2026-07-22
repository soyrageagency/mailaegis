/**
 * ClamAV integration — clamd INSTREAM over TCP, dependency-free.
 *
 * Attachments are streamed to your own clamd daemon, so the bytes never leave
 * your infrastructure. This is the "second opinion" that complements the
 * VirusTotal reputation lookup: ClamAV inspects the actual content, including
 * files VirusTotal has never seen.
 *
 * Protocol: `zINSTREAM\0`, then <4-byte BE length><chunk> frames, terminated by
 * a zero-length frame; clamd answers `stream: OK` or `stream: <Sig> FOUND`.
 *
 * Part of MailAegis — Corporate Email Threat Analyzer.
 * Crafted by SoyRage Agency — https://soyrage.es/
 * Licensed under the SoyRage Attribution License (see LICENSE).
 */

import { connect } from "node:net";
import type { AppConfig } from "../config.js";
import type { Attachment, ClamResult } from "./types.js";

const EICAR = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE";
const CHUNK = 64 * 1024;

/** Whether the ClamAV scan is active. */
export function clamEnabled(config: AppConfig): boolean {
  return config.demo || config.clamHost !== "";
}

/** Simulated verdicts so the pipeline is testable without a daemon. */
function demoScan(attachment: Attachment): ClamResult {
  if (attachment.content.includes(EICAR)) {
    return { filename: attachment.filename, infected: true, signature: "Win.Test.EICAR_HDB-1" };
  }
  if (["exe", "scr", "js", "vbs", "hta", "jar"].includes(attachment.extension)) {
    return { filename: attachment.filename, infected: true, signature: "Win.Trojan.Agent-1234567" };
  }
  if (["docm", "xlsm", "pptm"].includes(attachment.extension)) {
    return { filename: attachment.filename, infected: true, signature: "Doc.Downloader.Emotet-9876543" };
  }
  return { filename: attachment.filename, infected: false };
}

/** Stream one attachment to clamd and interpret the reply. */
export function scanAttachment(attachment: Attachment, config: AppConfig): Promise<ClamResult> {
  if (config.demo) return Promise.resolve(demoScan(attachment));

  return new Promise((resolve) => {
    const socket = connect({ host: config.clamHost, port: config.clamPort });
    let reply = "";
    let settled = false;
    const finish = (result: ClamResult) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(result);
    };

    socket.setTimeout(config.clamTimeoutMs);
    socket.once("timeout", () => finish({ filename: attachment.filename, infected: false, error: "clamd timed out" }));
    socket.once("error", (err) => finish({ filename: attachment.filename, infected: false, error: err.message }));

    socket.once("connect", () => {
      socket.write("zINSTREAM\0");
      for (let offset = 0; offset < attachment.content.length; offset += CHUNK) {
        const slice = attachment.content.subarray(offset, offset + CHUNK);
        const header = Buffer.alloc(4);
        header.writeUInt32BE(slice.length, 0);
        socket.write(header);
        socket.write(slice);
      }
      socket.write(Buffer.from([0, 0, 0, 0])); // end of stream
    });

    socket.on("data", (chunk) => { reply += chunk.toString("utf8"); });
    socket.once("close", () => {
      const text = reply.replace(/\0/g, "").trim();
      if (/FOUND$/.test(text)) {
        const signature = text.replace(/^stream:\s*/i, "").replace(/\s*FOUND$/, "").trim();
        finish({ filename: attachment.filename, infected: true, signature });
      } else if (/OK$/i.test(text)) {
        finish({ filename: attachment.filename, infected: false });
      } else {
        finish({ filename: attachment.filename, infected: false, error: text || "no reply from clamd" });
      }
    });
  });
}

/** Ask clamd for its version — used by `mailaegis doctor`. */
export function clamVersion(config: AppConfig): Promise<string> {
  if (config.demo) return Promise.resolve("ClamAV 1.3.1/27300 (simulated)");
  return new Promise((resolve) => {
    const socket = connect({ host: config.clamHost, port: config.clamPort });
    let reply = "";
    socket.setTimeout(config.clamTimeoutMs);
    socket.once("timeout", () => { socket.destroy(); resolve(""); });
    socket.once("error", () => resolve(""));
    socket.once("connect", () => socket.write("zVERSION\0"));
    socket.on("data", (c) => { reply += c.toString("utf8"); });
    socket.once("close", () => resolve(reply.replace(/\0/g, "").trim()));
  });
}
