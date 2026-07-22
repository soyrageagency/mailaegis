/**
 * Custom, hand-drawn line icons (minimalist, stroke-based, no icon library).
 *
 * Part of MailAegis — Corporate Email Threat Analyzer.
 * Crafted by SoyRage Agency — https://soyrage.es/
 * Licensed under the SoyRage Attribution License (see LICENSE).
 */

export const ICON_PATHS: Record<string, string> = {
  shield: '<path d="M12 3l8 3.5V11c0 4.5-3.4 7.6-8 9-4.6-1.4-8-4.5-8-9V6.5z"/>',
  mail: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3.5 7l8.5 6 8.5-6"/>',
  paperclip: '<path d="M20 11.5l-8.2 8.2a5 5 0 01-7.1-7.1l9-9a3.5 3.5 0 015 5l-9 9a2 2 0 01-2.8-2.8l8.2-8.2"/>',
  link: '<path d="M9 15l6-6M10.5 6.5l1-1a4 4 0 015.5 5.5l-1 1M13.5 17.5l-1 1a4 4 0 01-5.5-5.5l1-1"/>',
  check: '<circle cx="12" cy="12" r="9"/><path d="M8 12l3 3 5-6"/>',
  alert: '<path d="M12 3.5L22 20H2z"/><path d="M12 10v4M12 17h.01"/>',
  danger: '<circle cx="12" cy="12" r="9"/><path d="M12 7.5v5.5M12 16.5h.01"/>',
  engine: '<rect x="4" y="4" width="16" height="16" rx="3"/><path d="M9 9h6v6H9z"/><path d="M9 2.5v2M15 2.5v2M9 19.5v2M15 19.5v2M2.5 9h2M2.5 15h2M19.5 9h2M19.5 15h2"/>',
  auth: '<rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 018 0v3"/><path d="M12 14v2"/>',
  download: '<path d="M12 3v12M7 10l5 5 5-5M5 21h14"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="M21 21l-4-4"/>',
  logo: '<path d="M12 2.5l8.5 3.6V11c0 5-3.7 8.4-8.5 10C7.2 19.4 3.5 16 3.5 11V6.1z"/><path d="M7.5 9.5l7 5M14.5 9.5l-7 5"/>',
};

/** Render an icon as an inline SVG string. */
export function icon(name: string, cls = "ic"): string {
  return `<svg class="${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICON_PATHS[name] ?? ""}</svg>`;
}

/** The glyph that best represents a severity. */
export function severityIcon(severity: string, cls = "ic"): string {
  const name = severity === "critical" ? "danger" : severity === "high" ? "alert" : severity === "info" ? "check" : "alert";
  return icon(name, cls);
}
