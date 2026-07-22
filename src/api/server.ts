/**
 * HTTP API + web UI — the "easy to integrate" surface.
 *
 *   POST /api/analyze     raw RFC-822 message in the body → JSON verdict
 *   GET  /api/meta        which engines are active
 *   GET  /api/samples     the built-in demo corpus
 *   POST /api/samples/:id analyse one demo sample
 *
 * A gateway, a milter, a Rspamd worker or a Power Automate flow only needs to
 * POST the message and read `verdict` / `score`. Binds to 127.0.0.1 by default;
 * set MAILAEGIS_API_TOKEN to require a bearer token.
 *
 * Part of MailAegis — Corporate Email Threat Analyzer.
 * Crafted by SoyRage Agency — https://soyrage.es/
 * Licensed under the SoyRage Attribution License (see LICENSE).
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, extname, join, normalize, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { BRAND } from "../branding.js";
import type { AppConfig } from "../config.js";
import type { Logger } from "../logger.js";
import { analyzeRaw } from "../core/analyze.js";
import { clamEnabled } from "../core/clamav.js";
import { vtEnabled } from "../core/virustotal.js";
import { demoMessages } from "../core/demo.js";
import { readChannel } from "../core/updates.js";
import { senderLists } from "../core/lists.js";
import { MailboxSession } from "../mailbox/session.js";
import { CategoryStore, THREAT_META } from "../mailbox/categories.js";
import { PROVIDERS } from "../mailbox/providers.js";

const PUBLIC_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "public");
const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8", ".svg": "image/svg+xml",
  ".png": "image/png", ".ico": "image/x-icon",
  // Browsers ignore a manifest served as anything else.
  ".webmanifest": "application/manifest+json",
};
/** Refuse absurd bodies outright — a mail gateway must not be a memory bomb. */
const MAX_BODY_BYTES = 40 * 1024 * 1024;

function json(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" });
  res.end(JSON.stringify(body));
}

/** Collect the request body, refusing anything over the cap. */
function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolvePromise, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY_BYTES) { reject(new Error("Message exceeds the 40 MB limit.")); req.destroy(); return; }
      chunks.push(chunk);
    });
    req.on("end", () => resolvePromise(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

/** Constant-time-ish bearer check. */
function authorised(req: IncomingMessage, config: AppConfig): boolean {
  if (!config.apiToken) return true;
  const header = req.headers.authorization ?? "";
  return header === `Bearer ${config.apiToken}`;
}

export function startServer(config: AppConfig, logger: Logger): Promise<void> {
  const categories = new CategoryStore(config.outDir);
  const mailbox = new MailboxSession(categories);
  const lists = senderLists(config.outDir);

  const server = createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    const path = url.pathname;
    try {
      if (path === "/api/meta") {
        return json(res, 200, {
          product: BRAND.product, short: BRAND.short, author: BRAND.author, url: BRAND.url, donate: BRAND.donate,
          demo: config.demo,
          engines: {
            heuristics: true,
            auth: true,
            clamav: clamEnabled(config),
            virustotal: vtEnabled(config),
          },
          thresholds: { suspicious: config.suspiciousScore, quarantine: config.quarantineScore },
          corporateDomains: config.corporateDomains,
        });
      }

      // The update & announcement channel. Proxied through the server so the
      // browser makes no third-party request, and so an air-gapped deployment
      // can switch the whole thing off in one place.
      if (path === "/api/updates" && req.method === "GET") {
        return json(res, 200, await readChannel(config, url.searchParams.get("force") === "1"));
      }

      // Quick-connect presets, so nobody has to look up an IMAP hostname.
      if (path === "/api/providers" && req.method === "GET") {
        return json(res, 200, { providers: PROVIDERS });
      }

      if (path === "/api/samples" && req.method === "GET") {
        return json(res, 200, { samples: demoMessages().map(({ id, label, expectation }) => ({ id, label, expectation })) });
      }

      if (path.startsWith("/api/samples/") && req.method === "POST") {
        if (!authorised(req, config)) return json(res, 401, { error: "Unauthorised." });
        const id = decodeURIComponent(path.slice("/api/samples/".length));
        const sample = demoMessages().find((s) => s.id === id);
        if (!sample) return json(res, 404, { error: "Unknown sample." });
        return json(res, 200, await analyzeRaw(sample.raw, config));
      }

      // ---- Mailbox (the mail-client view) ---------------------------------
      if (path === "/api/mailbox/status") {
        return json(res, 200, { ...mailbox.getStatus(), preset: { host: config.imapHost, port: config.imapPort, user: config.imapUser, tls: config.imapTls, mailbox: config.imapMailbox, hasPassword: config.imapPassword !== "" } });
      }

      if (path === "/api/mailbox/connect" && req.method === "POST") {
        if (!authorised(req, config)) return json(res, 401, { error: "Unauthorised." });
        const body = JSON.parse((await readBody(req)).toString("utf8") || "{}") as Record<string, unknown>;
        if (body.demo === true || (config.demo && !config.imapHost && !body.host)) {
          logger.info("mailbox: loading the demo corpus");
          return json(res, 200, await mailbox.connectDemo(config, String(body.label ?? "")));
        }
        const creds = {
          host: String(body.host ?? config.imapHost),
          port: Number(body.port ?? config.imapPort),
          user: String(body.user ?? config.imapUser),
          // Fall back to the configured password so credentials never have to
          // travel through the browser in a server-configured deployment.
          password: String(body.password ?? "") || config.imapPassword,
          tls: body.tls === undefined ? config.imapTls : Boolean(body.tls),
          mailbox: String(body.mailbox ?? config.imapMailbox),
        };
        if (!creds.host || !creds.user) return json(res, 400, { error: "host and user are required." });
        const limit = Number(body.limit ?? config.imapFetchLimit);
        const smtp = body.smtpHost
          ? { host: String(body.smtpHost), port: Number(body.smtpPort ?? 465), tls: body.smtpTls === undefined ? true : Boolean(body.smtpTls) }
          : undefined;
        logger.info(`mailbox: connecting to ${creds.host} as ${creds.user}`);
        const status = await mailbox.connect(creds, config, limit, smtp);
        return json(res, 200, status);
      }

      if (path === "/api/mailbox/select" && req.method === "POST") {
        if (!authorised(req, config)) return json(res, 401, { error: "Unauthorised." });
        const body = JSON.parse((await readBody(req)).toString("utf8") || "{}") as { folder?: string; account?: string };
        const status = mailbox.getStatus();
        if (!status.connected) return json(res, 409, { error: "Not connected." });
        // Folders belong to an account, so fall back to whichever one is in
        // focus — and to the only account when the unified view is showing.
        const account = String(body.account ?? "") || status.activeId || status.accounts[0]!.id;
        return json(res, 200, await mailbox.selectFolder(account, String(body.folder ?? "INBOX"), config));
      }

      // Switch the view between one account and the unified inbox ("" = all).
      if (path === "/api/mailbox/active" && req.method === "POST") {
        if (!authorised(req, config)) return json(res, 401, { error: "Unauthorised." });
        const body = JSON.parse((await readBody(req)).toString("utf8") || "{}") as { account?: string };
        return json(res, 200, mailbox.setActive(String(body.account ?? "")));
      }

      if (path === "/api/mailbox/messages" && req.method === "GET") {
        return json(res, 200, { status: mailbox.getStatus(), messages: mailbox.list() });
      }

      // ---- Sender allow / block lists -------------------------------------
      if (path === "/api/lists" && req.method === "GET") {
        return json(res, 200, lists.list());
      }

      if (path === "/api/lists" && req.method === "POST") {
        if (!authorised(req, config)) return json(res, 401, { error: "Unauthorised." });
        const body = JSON.parse((await readBody(req)).toString("utf8") || "{}") as { kind?: string; value?: string; note?: string };
        const kind = body.kind === "allowed" ? "allowed" : "blocked";
        try {
          lists.add(kind, String(body.value ?? ""), String(body.note ?? ""));
          logger.info(`policy: ${String(body.value ?? "")} added to the ${kind} list`);
          return json(res, 200, lists.list());
        } catch (err) {
          return json(res, 400, { error: (err as Error).message });
        }
      }

      if (path.startsWith("/api/lists/") && req.method === "DELETE") {
        if (!authorised(req, config)) return json(res, 401, { error: "Unauthorised." });
        const [, , , kindRaw, ...rest] = path.split("/");
        const kind = kindRaw === "allowed" ? "allowed" : "blocked";
        lists.remove(kind, decodeURIComponent(rest.join("/")));
        return json(res, 200, lists.list());
      }

      // ---- Categories -----------------------------------------------------
      if (path === "/api/categories" && req.method === "GET") {
        return json(res, 200, { categories: categories.list(), threats: THREAT_META });
      }

      if (path === "/api/categories" && req.method === "POST") {
        if (!authorised(req, config)) return json(res, 401, { error: "Unauthorised." });
        const body = JSON.parse((await readBody(req)).toString("utf8") || "{}") as { name?: string; colour?: string };
        try {
          const created = categories.create(String(body.name ?? ""), body.colour);
          return json(res, 200, { category: created, categories: categories.list() });
        } catch (err) {
          return json(res, 400, { error: (err as Error).message });
        }
      }

      if (path.startsWith("/api/categories/") && req.method === "DELETE") {
        if (!authorised(req, config)) return json(res, 401, { error: "Unauthorised." });
        categories.remove(decodeURIComponent(path.slice("/api/categories/".length)));
        mailbox.refreshLabels();
        return json(res, 200, { categories: categories.list(), messages: mailbox.list() });
      }

      if (/^\/api\/mailbox\/messages\/[^/]+\/labels$/.test(path) && req.method === "PUT") {
        if (!authorised(req, config)) return json(res, 401, { error: "Unauthorised." });
        const id = decodeURIComponent(path.split("/")[4]);
        if (!mailbox.get(id)) return json(res, 404, { error: "Unknown message." });
        const body = JSON.parse((await readBody(req)).toString("utf8") || "{}") as { labels?: string[] };
        const applied = categories.assign(id, Array.isArray(body.labels) ? body.labels.map(String) : []);
        mailbox.refreshLabels();
        return json(res, 200, { labels: applied, messages: mailbox.list() });
      }

      // The original bytes: "Download .eml" and the raw-source viewer. An
      // analyst who cannot read the headers they are being told about has to
      // take the tool's word for it.
      if (/^\/api\/mailbox\/messages\/[^/]+\/raw$/.test(path) && req.method === "GET") {
        const id = decodeURIComponent(path.split("/")[4]!);
        const raw = mailbox.getRaw(id);
        if (!raw) return json(res, 404, { error: "Unknown message." });
        res.writeHead(200, {
          "Content-Type": "message/rfc822",
          // A filename that cannot escape the download folder, whatever the
          // message called itself.
          "Content-Disposition": `attachment; filename="${id.replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 60)}.eml"`,
          "Cache-Control": "no-store",
        });
        return void res.end(raw);
      }

      if (path.startsWith("/api/mailbox/messages/") && req.method === "GET") {
        const id = decodeURIComponent(path.slice("/api/mailbox/messages/".length));
        const analysis = mailbox.get(id);
        if (!analysis) return json(res, 404, { error: "Unknown message." });
        return json(res, 200, analysis);
      }

      // Send — and scan on the way out. A tool that inspects what arrives but
      // not what leaves is only watching half the door.
      if (path === "/api/mailbox/send" && req.method === "POST") {
        if (!authorised(req, config)) return json(res, 401, { error: "Unauthorised." });
        const body = JSON.parse((await readBody(req)).toString("utf8") || "{}") as Record<string, unknown>;
        const status = mailbox.getStatus();
        if (!status.connected) return json(res, 409, { error: "Connect a mailbox first." });
        const account = String(body.account ?? "") || status.activeId || status.accounts[0]!.id;

        const list = (v: unknown): string[] =>
          (Array.isArray(v) ? v : String(v ?? "").split(","))
            .map((x) => String(x).trim()).filter(Boolean);

        const attachments = (Array.isArray(body.attachments) ? body.attachments : []).slice(0, 20).map((a) => {
          const item = a as Record<string, unknown>;
          return {
            filename: String(item.filename ?? "attachment"),
            contentType: String(item.contentType ?? "application/octet-stream"),
            content: Buffer.from(String(item.base64 ?? ""), "base64"),
          };
        });

        const draft = {
          from: String(body.from ?? "") || mailbox.fromAddress(account),
          to: list(body.to), cc: list(body.cc), bcc: list(body.bcc),
          subject: String(body.subject ?? ""),
          text: String(body.text ?? ""),
          html: String(body.html ?? ""),
          attachments,
          inReplyTo: body.inReplyTo ? String(body.inReplyTo) : undefined,
          references: Array.isArray(body.references) ? body.references.map(String) : undefined,
        };

        try {
          const result = await mailbox.send(account, draft, config, body.force === true);
          logger.info(result.blocked
            ? `outbound blocked (${result.analysis.score}/100) from ${account}`
            : `sent ${result.analysis.id} from ${account} to ${result.accepted.length} recipient(s)${result.simulated ? " (simulated)" : ""}`);
          return json(res, result.blocked ? 422 : 200, { ...result, status: mailbox.getStatus() });
        } catch (err) {
          return json(res, 502, { error: (err as Error).message });
        }
      }

      // No body (or no account) disconnects everything; naming one account
      // leaves the other mailboxes connected.
      if (path === "/api/mailbox/disconnect" && req.method === "POST") {
        const body = JSON.parse((await readBody(req)).toString("utf8") || "{}") as { account?: string };
        return json(res, 200, mailbox.disconnect(String(body.account ?? "") || undefined));
      }

      if (path === "/api/analyze" && req.method === "POST") {
        if (!authorised(req, config)) return json(res, 401, { error: "Unauthorised." });
        const raw = await readBody(req);
        if (raw.length === 0) return json(res, 400, { error: "Empty body: POST the raw RFC-822 message." });
        const analysis = await analyzeRaw(raw, config);
        logger.info(`analysed ${analysis.id}: ${analysis.verdict} (${analysis.score})`);
        return json(res, 200, analysis);
      }

      if (req.method === "GET") return await serveStatic(res, path);
      res.writeHead(405); res.end("Method not allowed");
    } catch (err) {
      logger.error(`Request ${path} failed`, err);
      json(res, 500, { error: err instanceof Error ? err.message : "error" });
    }
  });

  return new Promise((resolvePromise) => {
    server.listen(config.port, config.host, () => {
      logger.info(`MailAegis API ready at http://${config.host}:${config.port}${config.demo ? "  (DEMO mode)" : ""}`);
      resolvePromise();
    });
  });
}

async function serveStatic(res: ServerResponse, urlPath: string): Promise<void> {
  const rel = urlPath === "/" ? "index.html" : urlPath.replace(/^\/+/, "");
  const target = normalize(join(PUBLIC_DIR, rel));
  const inside = target === PUBLIC_DIR || target.startsWith(PUBLIC_DIR + sep);
  if (!inside || !existsSync(target)) { res.writeHead(404); return void res.end("Not found"); }
  const body = await readFile(target);
  res.writeHead(200, { "Content-Type": MIME[extname(target)] ?? "application/octet-stream" });
  res.end(body);
}
