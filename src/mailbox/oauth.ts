/**
 * OAuth 2.0 for IMAP and SMTP (XOAUTH2).
 *
 * Microsoft has been switching basic authentication off tenant by tenant, and
 * Google only accepts an app password if the account has 2-Step Verification.
 * Both of those are workarounds. This is the sanctioned way in: an access
 * token, presented over the SASL `XOAUTH2` mechanism.
 *
 * The shape of it:
 *
 *   1. You register an application once, in Entra ID or the Google Cloud
 *      console, and get a client id.
 *   2. `mailaegis oauth` opens your browser, you consent, and it prints a
 *      **refresh token** — the long-lived credential.
 *   3. That refresh token goes in your configuration. From then on MailAegis
 *      exchanges it for a short-lived access token whenever it needs one.
 *
 * The refresh token is the secret worth protecting: it is stored where you put
 * it and never leaves this process except to the provider's own token
 * endpoint. Access tokens are held in memory only, and re-fetched a minute
 * before they expire so a long fetch cannot expire mid-flight.
 *
 * Part of MailAegis — Corporate Email Threat Analyzer.
 * Crafted by SoyRage Agency — https://soyrage.es/
 * Licensed under the SoyRage Attribution License (see LICENSE).
 */

export type OAuthProvider = "microsoft" | "google";

export interface OAuthSettings {
  provider: OAuthProvider;
  clientId: string;
  /** Optional: "installed app" registrations often have no secret. */
  clientSecret: string;
  refreshToken: string;
  /** Microsoft only — the directory to authenticate against. */
  tenant: string;
}

interface Endpoints {
  authorize: string;
  token: string;
  scopes: string[];
  /** Where to register the application, for the error message. */
  console: string;
}

/**
 * `offline_access` (Microsoft) and `access_type=offline` (Google) are what
 * actually produce a refresh token; without them the flow succeeds and then
 * stops working an hour later, which is a miserable thing to debug.
 */
export function endpointsFor(settings: OAuthSettings): Endpoints {
  if (settings.provider === "google") {
    return {
      authorize: "https://accounts.google.com/o/oauth2/v2/auth",
      token: "https://oauth2.googleapis.com/token",
      scopes: ["https://mail.google.com/"],
      console: "https://console.cloud.google.com/apis/credentials",
    };
  }
  const tenant = settings.tenant || "common";
  return {
    authorize: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/authorize`,
    token: `https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`,
    scopes: [
      "offline_access",
      "https://outlook.office.com/IMAP.AccessAsUser.All",
      "https://outlook.office.com/SMTP.Send",
    ],
    console: "https://entra.microsoft.com/#view/Microsoft_AAD_RegisteredApps",
  };
}

/** True when there is enough configuration to attempt OAuth at all. */
export function oauthConfigured(settings: OAuthSettings): boolean {
  return Boolean(settings.clientId && settings.refreshToken);
}

/**
 * The SASL XOAUTH2 initial response.
 *
 * The format is fixed and unforgiving — `user=…^Aauth=Bearer …^A^A`, where ^A
 * is a literal 0x01. A missing control byte produces an authentication failure
 * that reads exactly like a wrong password, which is why it is worth having
 * this in one tested place rather than inline at two call sites.
 */
export function xoauth2(user: string, accessToken: string): string {
  return Buffer.from(`user=${user}\x01auth=Bearer ${accessToken}\x01\x01`, "utf8").toString("base64");
}

interface CachedToken { value: string; expiresAt: number }
const cache = new Map<string, CachedToken>();

/** Forget every cached access token — used by tests. */
export function resetTokenCache(): void {
  cache.clear();
}

/**
 * An access token, from cache or freshly exchanged.
 *
 * Refreshed a minute early: a token that expires while a mailbox is being
 * fetched fails halfway through, and the retry costs more than the minute.
 */
export async function accessToken(settings: OAuthSettings, timeoutMs = 12000): Promise<string> {
  const key = `${settings.provider}:${settings.clientId}:${settings.refreshToken.slice(-12)}`;
  const hit = cache.get(key);
  if (hit && Date.now() < hit.expiresAt) return hit.value;

  const { token: tokenUrl, scopes, console: consoleUrl } = endpointsFor(settings);
  const form = new URLSearchParams({
    client_id: settings.clientId,
    grant_type: "refresh_token",
    refresh_token: settings.refreshToken,
    scope: scopes.join(" "),
  });
  if (settings.clientSecret) form.set("client_secret", settings.clientSecret);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(tokenUrl, {
      method: "POST",
      signal: controller.signal,
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: form.toString(),
    });
    const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
    if (!res.ok || typeof body.access_token !== "string") {
      // The provider's own description is far more useful than ours — it says
      // "the refresh token has expired" or "IMAP.AccessAsUser.All is not
      // consented", and those need different fixes.
      const reason = String(body.error_description ?? body.error ?? `HTTP ${res.status}`);
      throw new Error(`OAuth token refresh failed: ${reason}. Re-run "mailaegis oauth", or check the registration at ${consoleUrl}`);
    }

    const lifetime = Number(body.expires_in) || 3600;
    cache.set(key, { value: body.access_token, expiresAt: Date.now() + Math.max(30, lifetime - 60) * 1000 });

    // Google and Microsoft both sometimes rotate the refresh token. We cannot
    // rewrite the operator's configuration for them, so say so loudly rather
    // than fail silently in a month.
    if (typeof body.refresh_token === "string" && body.refresh_token !== settings.refreshToken) {
      process.emitWarning(
        `The provider issued a new refresh token. Update your configuration with:\n  OAUTH_REFRESH_TOKEN=${body.refresh_token}`,
        "MailAegisOAuth",
      );
    }
    return body.access_token;
  } finally {
    clearTimeout(timer);
  }
}

// ---- The one-time interactive flow -----------------------------------------

/**
 * Build the authorization URL for the loopback ("installed application") flow.
 *
 * PKCE is used even when a client secret is present: the code is exchanged
 * from a loopback redirect, which any local process could otherwise race for.
 */
export function authorizeUrl(settings: OAuthSettings, redirectUri: string, challenge: string, state: string): string {
  const { authorize, scopes } = endpointsFor(settings);
  const params = new URLSearchParams({
    client_id: settings.clientId,
    response_type: "code",
    redirect_uri: redirectUri,
    scope: scopes.join(" "),
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  // Google needs to be told explicitly that we want a refresh token, and
  // needs the consent screen forced to re-issue one.
  if (settings.provider === "google") {
    params.set("access_type", "offline");
    params.set("prompt", "consent");
  }
  return `${authorize}?${params.toString()}`;
}

/** Exchange an authorization code for the refresh token. */
export async function exchangeCode(
  settings: OAuthSettings,
  code: string,
  redirectUri: string,
  verifier: string,
): Promise<{ refreshToken: string; accessToken: string }> {
  const { token: tokenUrl, scopes } = endpointsFor(settings);
  const form = new URLSearchParams({
    client_id: settings.clientId,
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectUri,
    code_verifier: verifier,
    scope: scopes.join(" "),
  });
  if (settings.clientSecret) form.set("client_secret", settings.clientSecret);

  const res = await fetch(tokenUrl, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form.toString(),
  });
  const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  if (!res.ok || typeof body.refresh_token !== "string") {
    const reason = String(body.error_description ?? body.error ?? `HTTP ${res.status}`);
    throw new Error(
      typeof body.access_token === "string"
        ? `Signed in, but the provider returned no refresh token: ${reason}. The scopes must include offline access.`
        : `Could not exchange the authorization code: ${reason}`,
    );
  }
  return { refreshToken: body.refresh_token, accessToken: String(body.access_token ?? "") };
}
