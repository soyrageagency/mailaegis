/**
 * Tiny structured logger (stderr), with a `debug` gate.
 *
 * Part of NetAtlas — Living Infrastructure Documentation.
 * Crafted by SoyRage Agency — https://soyrage.es/
 * Licensed under the SoyRage Attribution License (see LICENSE).
 */

export type LogLevel = "debug" | "info" | "warn" | "error";
const WEIGHT: Record<LogLevel, number> = { debug: 10, info: 20, warn: 30, error: 40 };

export class Logger {
  constructor(private readonly threshold: LogLevel = "info") {}

  debug(m: string, meta?: unknown): void { this.write("debug", m, meta); }
  info(m: string, meta?: unknown): void { this.write("info", m, meta); }
  warn(m: string, meta?: unknown): void { this.write("warn", m, meta); }
  error(m: string, meta?: unknown): void { this.write("error", m, meta); }

  private write(level: LogLevel, message: string, meta?: unknown): void {
    if (WEIGHT[level] < WEIGHT[this.threshold]) return;
    let line = `${new Date().toISOString()} ${level.toUpperCase().padEnd(5)} ${message}`;
    if (meta !== undefined) line += ` ${meta instanceof Error ? meta.stack ?? meta.message : safe(meta)}`;
    process.stderr.write(line + "\n");
  }
}

function safe(v: unknown): string {
  try { return typeof v === "string" ? v : JSON.stringify(v); } catch { return String(v); }
}
