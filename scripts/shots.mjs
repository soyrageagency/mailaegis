/**
 * Generate documentation screenshots for the README with Playwright.
 * Crafted by SoyRage Agency — https://soyrage.es/
 */
import { chromium } from "playwright";
import { spawn } from "node:child_process";
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";
import { mkdirSync, writeFileSync, rmSync } from "node:fs";

mkdirSync("assets/screenshots", { recursive: true });
process.env.MAILAEGIS_DEMO = "true";

const PORT = "4879";
const srv = spawn("node", ["dist/index.js", "serve"], {
  env: { ...process.env, MAILAEGIS_DEMO: "true", MAILAEGIS_PORT: PORT, MAILAEGIS_LOG_LEVEL: "error" },
  stdio: "ignore",
});
const B = `http://127.0.0.1:${PORT}`;
for (let i = 0; i < 40; i++) { try { const r = await fetch(`${B}/api/meta`); if (r.ok) break; } catch {} await new Promise((r) => setTimeout(r, 150)); }

const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1280, height: 900 }, deviceScaleFactor: 2 });
const page = await ctx.newPage();

await page.goto(B, { waitUntil: "networkidle" });
await page.waitForTimeout(300);
await page.screenshot({ path: "assets/screenshots/connect.png" });
console.log("connect");

// Open the demo mailbox → the three-pane mail client.
await page.click("#tryDemo");
await page.waitForSelector("#client:not(.hidden)", { timeout: 10000 });
await page.waitForTimeout(500);
await page.screenshot({ path: "assets/screenshots/inbox.png" });
console.log("inbox");

// Open the worst message → the reading pane with the full verdict.
await page.click(".mrow");
await page.waitForSelector(".rhead", { timeout: 8000 });
await page.waitForTimeout(400);
await page.screenshot({ path: "assets/screenshots/message.png" });
console.log("message");

// Scroll the reading pane to show the scanners.
await page.evaluate(() => { const r = document.querySelector("#read"); if (r) r.scrollTop = r.scrollHeight; });
await page.waitForTimeout(300);
await page.screenshot({ path: "assets/screenshots/scanners.png" });
console.log("scanners");

// The printable HTML report, rendered in-process from the malware sample.
const url = (p) => pathToFileURL(resolve(p)).href;
const { loadConfig } = await import(url("dist/config.js"));
const { demoMessages } = await import(url("dist/core/demo.js"));
const { analyzeRaw } = await import(url("dist/core/analyze.js"));
const { renderHtml } = await import(url("dist/core/report.js"));

const sample = demoMessages().find((s) => s.id === "malware-attachment");
const analysis = await analyzeRaw(sample.raw, loadConfig());
const tmp = resolve("assets/screenshots/_report.html");
writeFileSync(tmp, renderHtml(analysis));
await page.goto(pathToFileURL(tmp).href, { waitUntil: "networkidle" });
await page.waitForTimeout(300);
await page.screenshot({ path: "assets/screenshots/report.png", fullPage: true });
rmSync(tmp, { force: true });
console.log("report");

await browser.close();
srv.kill();
