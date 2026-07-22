#!/usr/bin/env node
/**
 * MailAegis — Corporate Email Threat Analyzer — entry point / CLI router.
 *
 * Commands:
 *   scan [file.eml]   analyse a message (reads stdin when no file is given)
 *   demo              analyse the built-in corpus of sample corporate messages
 *   serve             start the HTTP API + web UI
 *   menu              interactive, arrow-key menu
 *   doctor            check the configuration and reach the scanners
 *   help              show this help
 *
 * Exit codes (so it drops straight into a mail pipeline):
 *   0 = clean · 1 = suspicious · 2 = malicious · 3 = error
 *
 * Part of MailAegis — Corporate Email Threat Analyzer.
 * Crafted by SoyRage Agency — https://soyrage.es/
 * Licensed under the SoyRage Attribution License (see LICENSE).
 */

import { readFileSync } from "node:fs";
import { ASCII_BANNER, BRAND } from "./branding.js";
import { loadConfig } from "./config.js";
import { Logger } from "./logger.js";
import { analyzeRaw, exitCodeFor } from "./core/analyze.js";
import { consoleSummary, writeReports } from "./core/report.js";
import { demoMessages } from "./core/demo.js";
import { clamEnabled, clamVersion } from "./core/clamav.js";
import { vtEnabled } from "./core/virustotal.js";

const argv = process.argv.slice(2);
if (argv.includes("--demo")) process.env.MAILAEGIS_DEMO = "true";
const command = (argv.find((a) => !a.startsWith("-")) || "help").toLowerCase();
const positional = argv.filter((a) => !a.startsWith("-")).slice(1);

const c = {
  reset: "\x1b[0m", dim: "\x1b[2m", bold: "\x1b[1m",
  blue: "\x1b[38;5;39m", green: "\x1b[32m", yellow: "\x1b[33m", red: "\x1b[31m",
};
const say = (s = "") => process.stdout.write(s + "\n");

/** Read the whole of stdin (used by MTA content filters). */
function readStdin(): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    process.stdin.on("data", (d) => chunks.push(Buffer.from(d)));
    process.stdin.on("end", () => resolve(Buffer.concat(chunks)));
    process.stdin.on("error", reject);
  });
}

async function main(): Promise<void> {
  const config = loadConfig();
  const log = new Logger(config.logLevel);

  if (command === "help" || argv.includes("-h") || argv.includes("--help")) return printHelp();
  if (command === "menu") { const { runMenu } = await import("./menu/menu.js"); return runMenu(config, log); }
  if (command === "serve") { const { startServer } = await import("./api/server.js"); await startServer(config, log); return; }
  if (command === "doctor") return doctor(config);

  if (command === "demo") {
    say(`${c.blue}${c.bold}  ${BRAND.short}${c.reset} ${c.dim}— analysing the built-in corpus${c.reset}\n`);
    let worst = 0;
    for (const sample of demoMessages()) {
      const analysis = await analyzeRaw(sample.raw, config);
      const colour = analysis.verdict === "clean" ? c.green : analysis.verdict === "suspicious" ? c.yellow : c.red;
      const match = analysis.verdict === sample.expectation ? `${c.green}✓${c.reset}` : `${c.yellow}!${c.reset}`;
      say(`  ${match} ${colour}${analysis.verdict.toUpperCase().padEnd(10)}${c.reset} ${c.dim}score ${String(analysis.score).padStart(3)}/100${c.reset}  ${sample.label}`);
      worst = Math.max(worst, exitCodeFor(analysis.verdict));
    }
    say(`\n  ${c.dim}Run a single sample in full:${c.reset} ${c.bold}mailaegis demo --report${c.reset}`);
    if (argv.includes("--report")) {
      const sample = demoMessages()[4];
      const analysis = await analyzeRaw(sample.raw, config);
      const paths = writeReports(analysis, config);
      say(`\n${consoleSummary(analysis)}`);
      say(`\n  ${c.green}✓ Report written${c.reset} → ${c.bold}${paths.html}${c.reset}`);
    }
    say(`\n  ${c.dim}${BRAND.author} · ${BRAND.url} · ${BRAND.donate}${c.reset}`);
    return;
  }

  if (command === "scan") {
    const file = positional[0];
    const raw = file && file !== "-" ? readFileSync(file) : await readStdin();
    if (raw.length === 0) throw new Error("Nothing to analyse: pass a .eml file or pipe a message on stdin.");
    const analysis = await analyzeRaw(raw, config);

    if (argv.includes("--json")) {
      say(JSON.stringify(analysis, null, 2));
    } else {
      say(`${c.blue}${c.bold}  ${BRAND.short}${c.reset} ${c.dim}— ${config.demo ? "DEMO mode (simulated scanners)" : "analysis"}${c.reset}\n`);
      say(consoleSummary(analysis));
    }
    if (argv.includes("--report")) {
      const paths = writeReports(analysis, config);
      say(`\n  ${c.green}✓ Report written${c.reset} → ${c.bold}${paths.html}${c.reset}`);
    }
    log.debug(`verdict=${analysis.verdict} score=${analysis.score}`);
    process.exitCode = exitCodeFor(analysis.verdict);
    return;
  }

  printHelp();
}

function doctor(config: ReturnType<typeof loadConfig>): void {
  say(`${c.bold}  ${BRAND.short} doctor${c.reset}\n`);
  const line = (ok: boolean, label: string, note: string) =>
    say(`  ${ok ? `${c.green}✓${c.reset}` : `${c.yellow}!${c.reset}`} ${label.padEnd(22)} ${c.dim}${note}${c.reset}`);
  line(true, "Heuristics engine", "always available");
  line(true, "Corporate domains", config.corporateDomains.length ? config.corporateDomains.join(", ") : "none set — identity rules are weaker (MAILAEGIS_CORPORATE_DOMAINS)");
  line(vtEnabled(config), "VirusTotal", config.demo ? "simulated (demo mode)" : config.vtApiKey ? "API key present" : "no VIRUSTOTAL_API_KEY");
  line(clamEnabled(config), "ClamAV", config.demo ? "simulated (demo mode)" : config.clamHost ? `${config.clamHost}:${config.clamPort}` : "no CLAMAV_HOST");
  line(true, "Thresholds", `suspicious ≥ ${config.suspiciousScore} · quarantine ≥ ${config.quarantineScore}`);
  if (clamEnabled(config) && !config.demo) {
    void clamVersion(config).then((v) => say(`\n  ${c.dim}clamd says:${c.reset} ${v || "(no response)"}`));
  }
}

function printHelp(): void {
  process.stderr.write(ASCII_BANNER + "\n");
  say(`${c.bold}${BRAND.product}${c.reset}  v${BRAND.version}`);
  say(`${c.dim}${BRAND.tagline}${c.reset}`);
  say();
  say(`${c.bold}Usage:${c.reset} mailaegis <command> [--demo] [--json] [--report]`);
  say();
  say("  scan [file.eml]   analyse a message (reads stdin when no file is given)");
  say("  demo              analyse the built-in corpus of sample corporate messages");
  say("  serve             start the HTTP API + web UI");
  say("  menu              interactive, arrow-key menu (great for first-timers)");
  say("  doctor            check the configuration and reach the scanners");
  say("  help              show this help");
  say();
  say(`${c.bold}Exit codes:${c.reset} 0 clean · 1 suspicious · 2 malicious · 3 error  ${c.dim}(ready for Postfix/procmail)${c.reset}`);
  say();
  say(`${c.dim}Try it with no keys and no daemon:${c.reset}  ${c.bold}mailaegis demo --demo${c.reset}`);
  say(`${c.dim}Pipe a message:${c.reset}                    ${c.bold}cat message.eml | mailaegis scan${c.reset}`);
  say();
  say(`  ${BRAND.author} · ${BRAND.url} · ${BRAND.donate}`);
}

main().catch((err) => {
  process.stderr.write(`\n\x1b[31m✗ ${err instanceof Error ? err.message : err}\x1b[0m\n`);
  process.stderr.write(`\x1b[2mTip: try 'mailaegis demo --demo' to see it work with no configuration.\x1b[0m\n`);
  process.exitCode = 3;
});
