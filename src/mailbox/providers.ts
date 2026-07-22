/**
 * Quick-connect presets for the mail platforms companies actually run.
 *
 * Nobody remembers whether Microsoft 365 wants `outlook.office365.com` on 993
 * or `imap.outlook.com` on 143, and getting it wrong produces a timeout rather
 * than a useful error. So MailAegis ships the settings, guesses the platform
 * from the address you typed, and — more importantly — tells you the thing that
 * actually blocks people: Google and Microsoft both refuse your normal password
 * over IMAP, and want an app password instead.
 *
 * Self-hosted platforms (Mailcow, Zimbra, generic) have no fixed hostname, so
 * their `host` is a template filled in from the address's own domain.
 *
 * Part of MailAegis — Corporate Email Threat Analyzer.
 * Crafted by SoyRage Agency — https://soyrage.es/
 * Licensed under the SoyRage Attribution License (see LICENSE).
 */

/** How a provider expects you to authenticate. */
export type AuthStyle = "password" | "app-password" | "app-password-required";

export interface MailProvider {
  id: string;
  name: string;
  /** One line for the chip's tooltip. */
  blurb: string;
  /** IMAP host. `{domain}` is replaced with the domain of the address. */
  host: string;
  port: number;
  tls: boolean;
  /** SMTP submission, for when MailAegis sends on your behalf. */
  smtpHost: string;
  smtpPort: number;
  /** True for implicit TLS (465); false means STARTTLS on 587. */
  smtpTls: boolean;
  auth: AuthStyle;
  /** Domains that identify this provider outright. */
  domains: string[];
  /** What the user has to do before this will work. Shown under the form. */
  note: string;
  /** Vendor documentation for that step. */
  docs: string;
  /** Self-hosted platforms cannot be auto-detected from the address. */
  selfHosted: boolean;
}

export const PROVIDERS: readonly MailProvider[] = Object.freeze([
  {
    id: "microsoft365",
    name: "Microsoft 365",
    blurb: "Exchange Online / Outlook / Azure-hosted mail",
    host: "outlook.office365.com", port: 993, tls: true,
    smtpHost: "smtp.office365.com", smtpPort: 587, smtpTls: false,
    auth: "app-password-required",
    domains: ["outlook.com", "hotmail.com", "live.com", "msn.com", "office365.com", "onmicrosoft.com"],
    note: "Microsoft disabled basic authentication for IMAP on most tenants. Either create an app password (requires MFA to be enabled on the account) or ask your Entra ID admin to re-enable IMAP for this mailbox.",
    docs: "https://learn.microsoft.com/exchange/clients-and-mobile-in-exchange-online/pop3-and-imap4/enable-or-disable-pop3-or-imap4-access",
    selfHosted: false,
  },
  {
    id: "google-workspace",
    name: "Google Workspace",
    blurb: "Gmail and Workspace mailboxes",
    host: "imap.gmail.com", port: 993, tls: true,
    smtpHost: "smtp.gmail.com", smtpPort: 465, smtpTls: true,
    auth: "app-password-required",
    domains: ["gmail.com", "googlemail.com"],
    note: "Your normal Google password will be rejected. Turn on 2-Step Verification, then create a 16-character app password and paste that here. Workspace admins must also leave IMAP enabled for the organisational unit.",
    docs: "https://support.google.com/mail/answer/185833",
    selfHosted: false,
  },
  {
    id: "mailcow",
    name: "Mailcow",
    blurb: "Self-hosted Mailcow (dockerised)",
    host: "mail.{domain}", port: 993, tls: true,
    smtpHost: "mail.{domain}", smtpPort: 465, smtpTls: true,
    auth: "password",
    domains: [],
    note: "Mailcow serves IMAP on the hostname you gave it during setup — usually mail.yourdomain. Your mailbox password works directly unless you enabled two-factor, in which case create an app password in SOGo.",
    docs: "https://docs.mailcow.email/",
    selfHosted: true,
  },
  {
    id: "zoho",
    name: "Zoho Mail",
    blurb: "Zoho-hosted business mail",
    host: "imap.zoho.eu", port: 993, tls: true,
    smtpHost: "smtp.zoho.eu", smtpPort: 465, smtpTls: true,
    auth: "app-password",
    domains: ["zoho.com", "zohomail.com", "zoho.eu"],
    note: "Use imap.zoho.com instead of .eu if your account was created in the US region. IMAP has to be enabled once under Settings → Mail Accounts.",
    docs: "https://www.zoho.com/mail/help/imap-access.html",
    selfHosted: false,
  },
  {
    id: "zimbra",
    name: "Zimbra",
    blurb: "Self-hosted Zimbra Collaboration",
    host: "mail.{domain}", port: 993, tls: true,
    smtpHost: "mail.{domain}", smtpPort: 465, smtpTls: true,
    auth: "password",
    domains: [],
    note: "Point this at your Zimbra MTA — commonly mail.yourdomain or zimbra.yourdomain. IMAP is on by default in the Class of Service.",
    docs: "https://wiki.zimbra.com/",
    selfHosted: true,
  },
  {
    id: "fastmail",
    name: "Fastmail",
    blurb: "Fastmail business accounts",
    host: "imap.fastmail.com", port: 993, tls: true,
    smtpHost: "smtp.fastmail.com", smtpPort: 465, smtpTls: true,
    auth: "app-password-required",
    domains: ["fastmail.com", "fastmail.fm", "messagingengine.com"],
    note: "Fastmail requires an app password with the \"Mail (IMAP)\" scope — your login password will not authenticate.",
    docs: "https://www.fastmail.help/hc/en-us/articles/1500000278342",
    selfHosted: false,
  },
  {
    id: "icloud",
    name: "iCloud Mail",
    blurb: "iCloud and custom-domain Apple mail",
    host: "imap.mail.me.com", port: 993, tls: true,
    smtpHost: "smtp.mail.me.com", smtpPort: 587, smtpTls: false,
    auth: "app-password-required",
    domains: ["icloud.com", "me.com", "mac.com"],
    note: "Generate an app-specific password at appleid.apple.com. The username is your full iCloud address.",
    docs: "https://support.apple.com/en-us/102654",
    selfHosted: false,
  },
  {
    id: "ionos",
    name: "IONOS",
    blurb: "IONOS / 1&1 hosted mail",
    host: "imap.ionos.es", port: 993, tls: true,
    smtpHost: "smtp.ionos.es", smtpPort: 465, smtpTls: true,
    auth: "password",
    domains: ["ionos.es", "ionos.com", "1and1.com"],
    note: "Swap the .es for your own IONOS region (imap.ionos.de, imap.ionos.co.uk, imap.ionos.com).",
    docs: "https://www.ionos.com/help/email/",
    selfHosted: false,
  },
  {
    id: "ovh",
    name: "OVHcloud",
    blurb: "OVH hosted and Exchange mail",
    host: "ssl0.ovh.net", port: 993, tls: true,
    smtpHost: "ssl0.ovh.net", smtpPort: 465, smtpTls: true,
    auth: "password",
    domains: ["ovh.net", "ovh.com"],
    note: "OVH's shared mail platform answers on ssl0.ovh.net. Hosted Exchange customers use ex*.mail.ovh.net instead — check your control panel.",
    docs: "https://help.ovhcloud.com/csm/en-web-hosting-email-configuration",
    selfHosted: false,
  },
  {
    id: "workmail",
    name: "Amazon WorkMail",
    blurb: "AWS-hosted corporate mail",
    host: "imap.mail.eu-west-1.awsapps.com", port: 993, tls: true,
    smtpHost: "smtp.mail.eu-west-1.awsapps.com", smtpPort: 465, smtpTls: true,
    auth: "password",
    domains: ["awsapps.com"],
    note: "Replace eu-west-1 with the region your WorkMail organisation lives in (us-east-1, us-west-2, eu-west-1).",
    docs: "https://docs.aws.amazon.com/workmail/latest/userguide/using_IMAP.html",
    selfHosted: false,
  },
  {
    id: "proton-bridge",
    name: "Proton Bridge",
    blurb: "Proton Mail via the local Bridge",
    host: "127.0.0.1", port: 1143, tls: false,
    smtpHost: "127.0.0.1", smtpPort: 1025, smtpTls: false,
    auth: "app-password-required",
    domains: ["proton.me", "protonmail.com", "pm.me"],
    note: "Proton has no public IMAP. Run Proton Mail Bridge on this machine and use the host, port and generated password it shows you — the ports below are its defaults.",
    docs: "https://proton.me/mail/bridge",
    selfHosted: true,
  },
  {
    id: "generic",
    name: "Other / generic IMAP",
    blurb: "Dovecot, Postfix, Exchange on-premises, anything else",
    host: "imap.{domain}", port: 993, tls: true,
    smtpHost: "smtp.{domain}", smtpPort: 465, smtpTls: true,
    auth: "password",
    domains: [],
    note: "Any RFC 3501 server works. If you terminate TLS on 143 with STARTTLS instead of implicit TLS on 993, MailAegis needs the implicit-TLS port.",
    docs: "https://github.com/soyrageagency/mailaegis#readme",
    selfHosted: true,
  },
]);

/** Fill `{domain}` from the address, so self-hosted presets are still useful. */
export function resolveHost(template: string, address: string): string {
  const domain = address.includes("@") ? address.split("@").pop()! : "";
  return template.replace("{domain}", domain || "example.com");
}

/**
 * Best-guess submission settings for a mailbox we already reach over IMAP.
 *
 * If the IMAP host matches a known preset we use that vendor's documented
 * submission server. Otherwise we assume the common convention of swapping
 * `imap.` for `smtp.` on port 465, which is right far more often than it is
 * wrong — and the compose form lets the user correct it either way.
 */
export function smtpFor(imapHost: string, address: string): { host: string; port: number; tls: boolean } {
  const host = String(imapHost).toLowerCase();
  for (const p of PROVIDERS) {
    if (p.selfHosted) continue;
    if (host === p.host.toLowerCase()) return { host: p.smtpHost, port: p.smtpPort, tls: p.smtpTls };
  }
  // Self-hosted platforms usually answer submission on the same hostname.
  if (/^mail\./i.test(host)) return { host: imapHost, port: 465, tls: true };
  if (/^imap\./i.test(host)) return { host: imapHost.replace(/^imap\./i, "smtp."), port: 465, tls: true };
  return { host: resolveHost("smtp.{domain}", address), port: 465, tls: true };
}

/**
 * Guess the platform from an email address.
 *
 * Only well-known domains give a confident answer; a corporate domain on
 * Microsoft 365 is indistinguishable from one on Mailcow without a DNS lookup,
 * so we return null rather than guess wrong and send someone chasing a
 * hostname that was never theirs.
 */
export function detectProvider(address: string): MailProvider | null {
  const domain = String(address).toLowerCase().split("@").pop() ?? "";
  if (!domain) return null;
  for (const p of PROVIDERS) {
    if (p.domains.some((d) => domain === d || domain.endsWith(`.${d}`))) return p;
  }
  return null;
}
