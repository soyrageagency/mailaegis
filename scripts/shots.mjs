/**
 * Generate the documentation screenshots with Playwright.
 *
 * Everything runs against the demo mailbox, so the images in the README show
 * exactly what someone gets from `npx mailaegis serve --demo` — no staged
 * data, no mock-ups. Desktop, dark and phone viewports all come from the same
 * running instance.
 *
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
  // The announcement card would drift into a screenshot on its own schedule,
  // so the documentation build never polls the channel.
  env: { ...process.env, MAILAEGIS_DEMO: "true", MAILAEGIS_PORT: PORT, MAILAEGIS_LOG_LEVEL: "error", MAILAEGIS_UPDATE_CHECK: "false" },
  stdio: "ignore",
});
const B = `http://127.0.0.1:${PORT}`;
for (let i = 0; i < 40; i++) { try { const r = await fetch(`${B}/api/meta`); if (r.ok) break; } catch {} await new Promise((r) => setTimeout(r, 150)); }

const browser = await chromium.launch();
const shot = (page, name, opts) => page.screenshot({ path: `assets/screenshots/${name}.png`, ...opts }).then(() => console.log(`  ${name}`));

// ---------------------------------------------------------------- desktop
console.log("desktop");
const ctx = await browser.newContext({ viewport: { width: 1360, height: 900 }, deviceScaleFactor: 2 });
const page = await ctx.newPage();

await page.goto(B, { waitUntil: "networkidle" });
await page.waitForTimeout(400);
await shot(page, "connect");

// Two mailboxes, so the unified inbox and the picker are both real.
await page.click("#tryDemo");
await page.waitForSelector("#client:not(.hidden)", { timeout: 10000 });
await page.waitForTimeout(600);
await shot(page, "inbox");

await page.click(".mrow");
await page.waitForSelector(".rhead", { timeout: 8000 });
await page.waitForTimeout(700);
await shot(page, "message");

// Scroll the reading pane to the scanner tables.
await page.evaluate(() => { const r = document.querySelector("#read"); if (r) r.scrollTop = r.scrollHeight; });
await page.waitForTimeout(400);
await shot(page, "scanners");

// The composer, opened as a reply — which is where the Reply-To warning shows.
await page.click("[data-act=reply]");
await page.waitForTimeout(600);
await shot(page, "compose");
await page.keyboard.press("Escape");
await page.waitForTimeout(400);

// A second mailbox, then the picker open over the unified inbox.
await page.evaluate(() => fetch("/api/mailbox/connect", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{\"demo\":true}" }));
await page.reload({ waitUntil: "networkidle" });
await page.waitForTimeout(500);
await page.evaluate(() => fetch("/api/mailbox/active", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{\"account\":\"\"}" }));
await page.reload({ waitUntil: "networkidle" });
await page.waitForTimeout(600);
await page.click(".pbtn");
await page.waitForTimeout(400);
await shot(page, "mailboxes");

// Search operators against the unified list.
await page.keyboard.press("Escape");
await page.click("body", { position: { x: 1100, y: 800 } });
await page.fill("#q", "is:malicious has:attachment");
await page.waitForTimeout(400);
await shot(page, "search");
await page.fill("#q", "");

// ------------------------------------------------------------------- dark
console.log("dark");
await page.evaluate(() => localStorage.setItem("mailaegis.theme", "dark"));
await page.reload({ waitUntil: "networkidle" });
await page.waitForTimeout(500);
await page.click(".mrow");
await page.waitForTimeout(700);
await shot(page, "dark");
await page.evaluate(() => localStorage.setItem("mailaegis.theme", "light"));

// ------------------------------------------------------------------ phone
console.log("phone");
const phone = await browser.newContext({
  viewport: { width: 390, height: 844 }, deviceScaleFactor: 3, isMobile: true, hasTouch: true,
});
const mob = await phone.newPage();
// The mailbox session lives in the server, so by now it is already connected
// from the desktop pass. Disconnect first, capture the connect screen, then
// open the demo again — otherwise the phone lands straight in the client.
await mob.goto(B, { waitUntil: "networkidle" });
await mob.evaluate(() => fetch("/api/mailbox/disconnect", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" }));
await mob.reload({ waitUntil: "networkidle" });
await mob.waitForTimeout(500);
await shot(mob, "phone-connect");

await mob.click("#tryDemo");
await mob.waitForSelector(".mrow", { timeout: 10000 });
await mob.waitForTimeout(600);
await shot(mob, "phone-inbox");

await mob.click(".mrow");
await mob.waitForTimeout(800);
await shot(mob, "phone-message");

await mob.click("#backToList");
await mob.waitForTimeout(400);
await mob.click("#menu");
await mob.waitForTimeout(500);
await shot(mob, "phone-folders");

// Close the drawer and open the composer. The Compose button is fixed to the
// bottom corner, which Playwright's viewport check dislikes on a mobile
// context, so it is clicked directly.
await mob.evaluate(() => {
  document.body.classList.remove("rail-open", "reading");
  scrollTo(0, 0);
});
await mob.waitForTimeout(300);
await mob.evaluate(() => document.getElementById("compose").click());
await mob.waitForTimeout(800);
await shot(mob, "phone-compose");

// ----------------------------------------------------------------- report
console.log("report");
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
await shot(page, "report", { fullPage: true });
rmSync(tmp, { force: true });

await browser.close();
srv.kill();
console.log("Done.");
