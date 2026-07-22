/**
 * `mailaegis oauth` — the one-time sign-in that produces a refresh token.
 *
 * The loopback flow for installed applications: a local server listens on a
 * random port, your browser is sent to the provider's consent screen, and the
 * authorization code comes back to that port and is exchanged. Nothing is
 * pasted by hand and no secret crosses a terminal.
 *
 * PKCE is used even when a client secret is configured. The redirect lands on
 * 127.0.0.1, which every other process on the machine can also listen for on a
 * different port and race for; the verifier means a stolen code is worthless
 * without it.
 *
 * Part of MailAegis — Corporate Email Threat Analyzer.
 * Crafted by SoyRage Agency — https://soyrage.es/
 * Licensed under the SoyRage Attribution License (see LICENSE).
 */

import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import type { AppConfig } from "../config.js";
import { authorizeUrl, endpointsFor, exchangeCode, type OAuthSettings } from "./oauth.js";

/** base64url, which OAuth uses everywhere and Node does not default to. */
const b64url = (buf: Buffer): string => buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

/** Ask the desktop to open a URL. Best-effort: the URL is always printed too. */
function openBrowser(url: string): void {
  const [cmd, args] = process.platform === "win32"
    ? ["cmd", ["/c", "start", "", url]]
    : process.platform === "darwin"
      ? ["open", [url]]
      : ["xdg-open", [url]];
  try {
    spawn(cmd, args, { stdio: "ignore", detached: true }).unref();
  } catch { /* headless box — the printed URL is the fallback */ }
}

const PAGE = (title: string, body: string): string => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>MailAegis</title><style>
 body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f3f1ea;color:#111;
      font-family:Inter,"Segoe UI",system-ui,sans-serif;text-align:center;padding:24px}
 .c{max-width:420px}h1{font-size:22px;letter-spacing:-.02em;margin:0 0 10px}
 p{color:#8b8b86;font-size:14px;line-height:1.6;margin:0}
 .m{width:46px;height:46px;border-radius:13px;background:#111;margin:0 auto 20px;display:grid;place-items:center}
 .m svg{width:25px;height:25px}
</style></head><body><div class="c">
 <div class="m"><svg viewBox="0 0 120 120"><path fill="#f3f1ea" fill-rule="evenodd"
   d="M20 12 H68 L92 32 V54 L72 69 L101 108 H73 L51 74 H42 V108 H20 Z M42 32 V56 H64 L74 48 V40 L64 32 Z"/>
   <path fill="#3b9ee8" d="M78 6 H106 L86 28 Z"/></svg></div>
 <h1>${title}</h1><p>${body}</p></div></body></html>`;

export interface OAuthLoginResult {
  refreshToken: string;
  settings: OAuthSettings;
}

/**
 * Run the flow. Resolves with the refresh token; the caller prints it.
 *
 * Times out after five minutes — long enough for a password, an MFA prompt and
 * a consent screen, short enough that a forgotten terminal does not leave a
 * port listening all day.
 */
export function oauthLogin(config: AppConfig, timeoutMs = 5 * 60_000): Promise<OAuthLoginResult> {
  const settings: OAuthSettings = {
    provider: config.oauthProvider,
    clientId: config.oauthClientId,
    clientSecret: config.oauthClientSecret,
    refreshToken: "",
    tenant: config.oauthTenant,
  };

  if (!settings.clientId) {
    const { console: where } = endpointsFor(settings);
    return Promise.reject(new Error(
      `OAUTH_CLIENT_ID is not set.\n\n` +
      `Register an application first at:\n  ${where}\n\n` +
      `Add a redirect URI of type "Mobile and desktop" / "Desktop app" pointing at\n` +
      `  http://localhost\n` +
      `then put its client id in OAUTH_CLIENT_ID.`,
    ));
  }

  const verifier = b64url(randomBytes(32));
  const challenge = b64url(createHash("sha256").update(verifier).digest());
  const state = b64url(randomBytes(16));

  return new Promise((resolve, reject) => {
    const server = createServer(async (req, res) => {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      if (url.pathname !== "/") { res.writeHead(404); res.end(); return; }

      const send = (status: number, title: string, body: string) => {
        res.writeHead(status, { "content-type": "text/html; charset=utf-8" });
        res.end(PAGE(title, body));
      };

      const error = url.searchParams.get("error");
      if (error) {
        send(400, "Sign-in was refused", `${url.searchParams.get("error_description") ?? error}. You can close this tab.`);
        finish(new Error(`The provider refused the sign-in: ${url.searchParams.get("error_description") ?? error}`));
        return;
      }

      // A mismatched state means this callback did not come from our request.
      if (url.searchParams.get("state") !== state) {
        send(400, "That did not come from MailAegis", "The sign-in was ignored. Please try again.");
        return;
      }

      const code = url.searchParams.get("code");
      if (!code) { send(400, "No authorization code", "Please try again."); return; }

      try {
        const { refreshToken } = await exchangeCode(settings, code, redirectUri, verifier);
        send(200, "Signed in", "MailAegis has its refresh token. You can close this tab and go back to the terminal.");
        finish(null, refreshToken);
      } catch (err) {
        send(500, "Could not complete the sign-in", (err as Error).message);
        finish(err as Error);
      }
    });

    let redirectUri = "";
    let done = false;
    const timer = setTimeout(() => finish(new Error("Timed out waiting for the sign-in to complete.")), timeoutMs);

    const finish = (err: Error | null, refreshToken?: string) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      // Give the browser a moment to receive the page before the socket dies.
      setTimeout(() => server.close(), 250);
      if (err) reject(err);
      else resolve({ refreshToken: refreshToken!, settings: { ...settings, refreshToken: refreshToken! } });
    };

    server.on("error", (err) => finish(err));
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = typeof address === "object" && address ? address.port : 0;
      // Both providers accept any port on http://localhost for a desktop app
      // registration, which is what makes a random port workable.
      redirectUri = `http://localhost:${port}`;
      const url = authorizeUrl(settings, redirectUri, challenge, state);
      process.stdout.write(`\n  Opening your browser to sign in…\n  If it does not open, paste this:\n\n  ${url}\n\n`);
      openBrowser(url);
    });
  });
}
