/**
 * Interactive arrow-key menu — a friendly front door for people who don't live
 * in a terminal. Run `mailaegis menu`, use ↑/↓ and Enter.
 *
 * Part of MailAegis — Corporate Email Threat Analyzer.
 * Crafted by SoyRage Agency — https://soyrage.es/
 * Licensed under the SoyRage Attribution License (see LICENSE).
 */

import { createInterface } from "node:readline";
import { ASCII_BANNER, BRAND } from "../branding.js";
import type { AppConfig } from "../config.js";
import type { Logger } from "../logger.js";
import { analyzeRaw, exitCodeFor } from "../core/analyze.js";
import { consoleSummary, writeReports } from "../core/report.js";
import { demoMessages } from "../core/demo.js";
import { clamEnabled } from "../core/clamav.js";
import { vtEnabled } from "../core/virustotal.js";

const C = {
  reset: "\x1b[0m", dim: "\x1b[2m", bold: "\x1b[1m", inv: "\x1b[7m",
  blue: "\x1b[38;5;39m", green: "\x1b[32m", yellow: "\x1b[33m", red: "\x1b[31m", gray: "\x1b[90m",
};
const clear = "\x1b[2J\x1b[H";
const out = (s: string) => process.stdout.write(s);

interface Item { label: string; hint: string; run: () => Promise<boolean> }

export function runMenu(config: AppConfig, log: Logger): void {
  const items: Item[] = [
    { label: "Analyse the sample corpus", hint: "five realistic corporate messages, benign → hostile", run: () => doCorpus(config) },
    { label: "Full report for the worst sample", hint: "writes HTML + JSON + Markdown to the reports folder", run: () => doReport(config) },
    { label: "Start the API & web UI", hint: "drop an .eml in your browser, or POST /api/analyze", run: () => doServe(config, log) },
    { label: "Check my configuration", hint: "which engines are active right now", run: () => doDoctor(config) },
    { label: "Quit", hint: "", run: async () => true },
  ];
  let sel = 0;

  const render = () => {
    out(clear);
    out(`${C.blue}${ASCII_BANNER}${C.reset}\n`);
    out(`  ${C.bold}What would you like to do?${C.reset}   ${C.dim}(↑/↓ to move, Enter to choose)${C.reset}\n`);
    if (config.demo) out(`  ${C.yellow}DEMO mode — VirusTotal and ClamAV verdicts are simulated.${C.reset}\n`);
    out("\n");
    items.forEach((it, i) => {
      const active = i === sel;
      out(`  ${active ? `${C.green}❯${C.reset}` : " "} ${active ? `${C.inv} ${it.label} ${C.reset}` : `  ${it.label}`}   ${C.gray}${it.hint}${C.reset}\n`);
    });
    out(`\n  ${C.gray}${BRAND.author} · ${BRAND.url} · ${BRAND.donate}${C.reset}\n`);
  };

  const stdin = process.stdin;

  // Arrow keys only exist on a real terminal. Piped through a task runner, an
  // IDE console or `tsx watch` — which keeps stdin for its own commands —
  // raw mode is unavailable and the menu would silently ignore every key.
  // Fall back to typing a number, which works everywhere.
  if (!stdin.isTTY) return runNumberedMenu(items, config);

  stdin.setRawMode(true);
  stdin.resume();
  stdin.setEncoding("utf8");
  let busy = false;
  render();

  stdin.on("data", async (key: string) => {
    if (busy) return;
    if (key === "\x03" || key === "q") return quit();
    if (key === "\x1b[A" || key === "k") { sel = (sel - 1 + items.length) % items.length; render(); return; }
    if (key === "\x1b[B" || key === "j") { sel = (sel + 1) % items.length; render(); return; }
    if (key === "\r" || key === "\n") {
      busy = true;
      stdin.setRawMode(false);
      out(clear);
      const done = await items[sel].run().catch((e) => { out(`\n  ${C.red}✗ ${e.message}${C.reset}\n`); return false; });
      if (done) return quit();
      out(`\n  ${C.dim}Press any key to return to the menu…${C.reset}`);
      if (stdin.isTTY) stdin.setRawMode(true);
      busy = false;
      const once = () => { stdin.removeListener("data", once); render(); };
      stdin.once("data", once);
    }
  });
}

/**
 * The menu without a terminal: print the options, read a number per line.
 *
 * Not as pretty, but a menu that cannot be operated is worse than an ugly one.
 */
function runNumberedMenu(items: Item[], config: AppConfig): void {
  const rl = createInterface({ input: process.stdin, output: process.stdout });

  const render = () => {
    out(`\n${C.blue}${ASCII_BANNER}${C.reset}\n`);
    out(`  ${C.bold}What would you like to do?${C.reset}   ${C.dim}(type a number, then Enter)${C.reset}\n`);
    if (config.demo) out(`  ${C.yellow}DEMO mode — VirusTotal and ClamAV verdicts are simulated.${C.reset}\n`);
    out(`  ${C.dim}No arrow keys here: this is not an interactive terminal. Run ${C.reset}${C.bold}npx mailaegis menu${C.reset}${C.dim} in a real one for the full version.${C.reset}\n\n`);
    items.forEach((it, i) => out(`  ${C.bold}${i + 1}${C.reset}) ${it.label}   ${C.gray}${it.hint}${C.reset}\n`));
    out(`\n  ${C.gray}${BRAND.author} · ${BRAND.url}${C.reset}\n`);
    rl.setPrompt(`\n  Choice [1-${items.length}]: `);
    rl.prompt();
  };

  rl.on("line", async (line) => {
    const choice = Number(line.trim());
    if (!Number.isInteger(choice) || choice < 1 || choice > items.length) {
      out(`  ${C.yellow}Enter a number between 1 and ${items.length}.${C.reset}\n`);
      rl.prompt();
      return;
    }
    const done = await items[choice - 1]!.run().catch((e: Error) => { out(`\n  ${C.red}✗ ${e.message}${C.reset}\n`); return false; });
    if (done) { rl.close(); return quit(); }
    render();
  });
  rl.on("close", () => quit());

  render();
}

function quit(): never {
  process.stdout.write(`\n  ${C.green}Thanks for using ${BRAND.short}!${C.reset} A ★ helps: ${C.blue}${BRAND.repo}${C.reset}\n\n`);
  process.exit(0);
}

async function doCorpus(config: AppConfig): Promise<boolean> {
  out(`${C.dim}Analysing the built-in corpus…${C.reset}\n\n`);
  for (const sample of demoMessages()) {
    const a = await analyzeRaw(sample.raw, config);
    const colour = a.verdict === "clean" ? C.green : a.verdict === "suspicious" ? C.yellow : C.red;
    const match = a.verdict === sample.expectation ? `${C.green}✓${C.reset}` : `${C.yellow}!${C.reset}`;
    out(`  ${match} ${colour}${a.verdict.toUpperCase().padEnd(10)}${C.reset} ${C.dim}score ${String(a.score).padStart(3)}/100${C.reset}  ${sample.label}\n`);
    void exitCodeFor(a.verdict);
  }
  return false;
}

async function doReport(config: AppConfig): Promise<boolean> {
  const sample = demoMessages().find((s) => s.id === "malware-attachment") ?? demoMessages()[0];
  const a = await analyzeRaw(sample.raw, config);
  out(consoleSummary(a) + "\n\n");
  const paths = writeReports(a, config);
  out(`${C.green}✓ Report written.${C.reset} Open ${C.bold}${paths.html}${C.reset}\n  Also: ${paths.json} · ${paths.markdown}\n`);
  return false;
}

async function doDoctor(config: AppConfig): Promise<boolean> {
  const line = (ok: boolean, label: string, note: string) =>
    out(`  ${ok ? `${C.green}✓${C.reset}` : `${C.yellow}!${C.reset}`} ${label.padEnd(22)} ${C.dim}${note}${C.reset}\n`);
  out(`${C.bold}  Configuration${C.reset}\n\n`);
  line(true, "Heuristics engine", "always available");
  line(config.corporateDomains.length > 0, "Corporate domains", config.corporateDomains.join(", ") || "none set (MAILAEGIS_CORPORATE_DOMAINS)");
  line(vtEnabled(config), "VirusTotal", config.demo ? "simulated (demo mode)" : config.vtApiKey ? "API key present" : "no VIRUSTOTAL_API_KEY");
  line(clamEnabled(config), "ClamAV", config.demo ? "simulated (demo mode)" : config.clamHost ? `${config.clamHost}:${config.clamPort}` : "no CLAMAV_HOST");
  line(true, "Thresholds", `suspicious ≥ ${config.suspiciousScore} · quarantine ≥ ${config.quarantineScore}`);
  return false;
}

async function doServe(config: AppConfig, log: Logger): Promise<boolean> {
  const { startServer } = await import("../api/server.js");
  await startServer(config, log);
  out(`\n  ${C.green}API & web UI running${C.reset} at ${C.blue}http://${config.host}:${config.port}${C.reset}  ${C.dim}— press Ctrl-C to stop.${C.reset}\n`);
  // startServer resolves once the socket is listening; park so the process
  // stays alive (and the menu doesn't quit) until the user interrupts.
  await new Promise<void>(() => {});
  return true; // unreachable
}
