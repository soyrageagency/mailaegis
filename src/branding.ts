/**
 * Branding, identity & attribution.
 *
 * Single source of truth for the SoyRage Agency identity carried by the tool:
 * the ASCII banner, product metadata and report footers.
 *
 * Part of MailAegis — Corporate Email Threat Analyzer.
 * Crafted by SoyRage Agency — https://soyrage.es/
 * Licensed under the SoyRage Attribution License (see LICENSE).
 */

/** Immutable identity of the project's author. Do not fork without credit. */
export const BRAND = Object.freeze({
  product: "MailAegis — Corporate Email Threat Analyzer",
  short: "MailAegis",
  author: "SoyRage Agency",
  url: "https://soyrage.es/",
  donate: "https://www.paypal.com/paypalme/soyrageagency",
  repo: "https://github.com/soyrageagency/mailaegis",
  tagline: "Every message inspected — attachments, links, headers and intent.",
  version: "1.4.0",
  accent: "#3b9ee8",
});

/** SoyRage brand design tokens — minimalist: cream, ink, one blue accent. */
export const THEME = Object.freeze({
  bg: "#f3f1ea",
  panel: "#ffffff",
  ink: "#111111",
  mute: "#8b8b86",
  line: "#e7e3da",
  accent: "#3b9ee8",
  grid: "rgba(17,17,17,.035)",
  tints: ["#dbe8f2", "#dcebdf", "#f0ebcf", "#f1ddd9"],
});

/** ASCII welcome banner. */
export const ASCII_BANNER = String.raw`
 ███╗   ███╗ █████╗ ██╗██╗      █████╗ ███████╗ ██████╗ ██╗███████╗
 ████╗ ████║██╔══██╗██║██║     ██╔══██╗██╔════╝██╔════╝ ██║██╔════╝
 ██╔████╔██║███████║██║██║     ███████║█████╗  ██║  ███╗██║███████╗
 ██║╚██╔╝██║██╔══██║██║██║     ██╔══██║██╔══╝  ██║   ██║██║╚════██║
 ██║ ╚═╝ ██║██║  ██║██║███████╗██║  ██║███████╗╚██████╔╝██║███████║
 ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝╚══════╝
      Corporate Email Threat Analyzer · by SoyRage Agency
   VirusTotal · ClamAV · SPF/DKIM/DMARC · phishing & BEC heuristics
`;
