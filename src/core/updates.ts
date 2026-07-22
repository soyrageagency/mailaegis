/**
 * The update & announcement channel.
 *
 * A single JSON file in the repository (`channel/updates.json`) is the whole
 * mechanism: MailAegis fetches it, compares the advertised version against the
 * running build **inside this process**, and hands the UI a card to show in the
 * corner — a release with its changelog, or any announcement the maintainer
 * wrote.
 *
 * Deliberately unremarkable in what it sends: one unauthenticated GET, no
 * identifiers, no telemetry, no mailbox data. `MAILAEGIS_UPDATE_CHECK=false`
 * removes even that, and `MAILAEGIS_UPDATE_FEED` re-points it at your own
 * intranet so a fleet can be addressed privately. Every failure is silent — an
 * offline analyzer must not nag.
 *
 * Part of MailAegis — Corporate Email Threat Analyzer.
 * Crafted by SoyRage Agency — https://soyrage.es/
 * Licensed under the SoyRage Attribution License (see LICENSE).
 */

import { BRAND } from "../branding.js";
import type { AppConfig } from "../config.js";

export type AnnouncementLevel = "info" | "success" | "warn" | "critical";

export interface Release {
  version: string;
  published: string;
  mandatory: boolean;
  notes: string;
  changelog: string[];
  url: string;
  downloads: Record<string, string>;
}

export interface Announcement {
  id: string;
  level: AnnouncementLevel;
  title: string;
  body: string;
  link: { label: string; url: string } | null;
  dismissible: boolean;
}

/** What `/api/updates` answers — already filtered for this build. */
export interface ChannelState {
  /** False when the operator disabled the check; the UI then stays quiet. */
  enabled: boolean;
  current: string;
  /** Present only when the feed advertises something newer than `current`. */
  update: Release | null;
  announcements: Announcement[];
  /** When the feed was last read, ISO-8601. Empty if never (or offline). */
  checked: string;
}

// ---- Version comparison ----------------------------------------------------

/**
 * Compare two semver-ish strings. Returns >0 when `a` is newer.
 *
 * Pre-releases sort *below* their release (1.2.0-rc.1 < 1.2.0), which is what
 * you want: someone on a release candidate should still be offered the final.
 */
export function compareVersions(a: string, b: string): number {
  const split = (v: string) => {
    const [core = "", pre = ""] = String(v).trim().replace(/^v/i, "").split("-", 2);
    return { nums: core.split(".").map((n) => Number.parseInt(n, 10) || 0), pre };
  };
  const x = split(a);
  const y = split(b);
  for (let i = 0; i < Math.max(x.nums.length, y.nums.length, 3); i++) {
    const d = (x.nums[i] ?? 0) - (y.nums[i] ?? 0);
    if (d !== 0) return d > 0 ? 1 : -1;
  }
  if (x.pre === y.pre) return 0;
  if (x.pre === "") return 1; // a is the final release, b a pre-release
  if (y.pre === "") return -1;
  return x.pre > y.pre ? 1 : -1;
}

// ---- Feed parsing ----------------------------------------------------------

const asString = (v: unknown, d = ""): string => (typeof v === "string" ? v : d);
const asBool = (v: unknown, d: boolean): boolean => (typeof v === "boolean" ? v : d);
const LEVELS: AnnouncementLevel[] = ["info", "success", "warn", "critical"];

/** `""` means "no bound", so an absent window always matches. */
function withinWindow(starts: string, ends: string, now: Date): boolean {
  if (starts) { const t = Date.parse(starts); if (Number.isFinite(t) && now.getTime() < t) return false; }
  if (ends) { const t = Date.parse(ends); if (Number.isFinite(t) && now.getTime() > t) return false; }
  return true;
}

function withinVersions(min: string, max: string, current: string): boolean {
  if (min && compareVersions(current, min) < 0) return false;
  if (max && compareVersions(current, max) > 0) return false;
  return true;
}

/**
 * Turn a raw feed into what this build should see.
 *
 * Exported so the filtering is testable without a network: every rule that
 * decides whether a user gets nagged is worth pinning down.
 */
export function interpretFeed(raw: unknown, current: string, now: Date): Omit<ChannelState, "enabled" | "checked"> {
  const feed = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;

  let update: Release | null = null;
  const latest = feed.latest as Record<string, unknown> | undefined;
  const version = asString(latest?.version).replace(/^v/i, "");
  if (version && compareVersions(version, current) > 0) {
    const downloads: Record<string, string> = {};
    const rawDownloads = latest?.downloads;
    if (rawDownloads && typeof rawDownloads === "object") {
      for (const [k, v] of Object.entries(rawDownloads as Record<string, unknown>)) {
        if (typeof v === "string" && /^https:\/\//i.test(v)) downloads[k] = v;
      }
    }
    update = {
      version,
      published: asString(latest?.published),
      mandatory: asBool(latest?.mandatory, false),
      notes: asString(latest?.notes),
      changelog: Array.isArray(latest?.changelog) ? (latest!.changelog as unknown[]).filter((c): c is string => typeof c === "string").slice(0, 12) : [],
      url: /^https:\/\//i.test(asString(latest?.url)) ? asString(latest?.url) : BRAND.repo,
      downloads,
    };
  }

  const announcements: Announcement[] = [];
  for (const item of Array.isArray(feed.announcements) ? feed.announcements : []) {
    const a = (item && typeof item === "object" ? item : {}) as Record<string, unknown>;
    const id = asString(a.id);
    const title = asString(a.title);
    if (!id || !title) continue;
    if (!withinWindow(asString(a.starts), asString(a.ends), now)) continue;
    if (!withinVersions(asString(a.minVersion), asString(a.maxVersion), current)) continue;
    const level = asString(a.level, "info") as AnnouncementLevel;
    const link = a.link as Record<string, unknown> | undefined;
    const url = asString(link?.url);
    announcements.push({
      id,
      level: LEVELS.includes(level) ? level : "info",
      title,
      body: asString(a.body),
      // Only https links, and only ones the maintainer actually labelled — the
      // feed is trusted, but a typo should not render a bare "undefined" chip.
      link: /^https:\/\//i.test(url) ? { label: asString(link?.label, "Read more"), url } : null,
      dismissible: asBool(a.dismissible, true),
    });
    if (announcements.length >= 5) break;
  }

  return { current, update, announcements };
}

// ---- Fetching --------------------------------------------------------------

let cache: { at: number; state: ChannelState } | null = null;

/** Drop the cached feed — used by tests and by an explicit "check now". */
export function resetChannelCache(): void {
  cache = null;
}

/**
 * Read the channel, honouring the cache. Never throws and never blocks for
 * long: on any failure the caller gets an empty, harmless state.
 */
export async function readChannel(config: AppConfig, force = false): Promise<ChannelState> {
  const current = BRAND.version;
  const quiet: ChannelState = { enabled: config.updateCheck, current, update: null, announcements: [], checked: "" };
  if (!config.updateCheck) return quiet;

  const ttl = config.updateTtlMinutes * 60_000;
  if (!force && cache && Date.now() - cache.at < ttl) return cache.state;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 6000);
  try {
    const res = await fetch(config.updateFeed, {
      signal: controller.signal,
      headers: { accept: "application/json", "user-agent": `MailAegis/${current}` },
    });
    if (!res.ok) throw new Error(`feed responded ${res.status}`);
    const state: ChannelState = {
      enabled: true,
      checked: new Date().toISOString(),
      ...interpretFeed(await res.json(), current, new Date()),
    };
    cache = { at: Date.now(), state };
    return state;
  } catch {
    // Offline, blocked by a proxy, or the feed is malformed. Say nothing, and
    // keep the last good answer if we have one.
    if (cache) return cache.state;
    return quiet;
  } finally {
    clearTimeout(timer);
  }
}
