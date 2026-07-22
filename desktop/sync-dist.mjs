/**
 * Copy the compiled analyzer into the desktop app before packaging.
 *
 * The core has zero runtime dependencies, so shipping the desktop app is just
 * a matter of bundling `dist/` next to the Electron shell.
 *
 * Crafted by SoyRage Agency — https://soyrage.es/
 */
import { cpSync, existsSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const from = resolve(here, "..", "dist");
const to = resolve(here, "dist");

if (!existsSync(from)) {
  console.error("[sync-dist] ../dist not found — run `npm run build` in the repository root first.");
  process.exit(1);
}
rmSync(to, { recursive: true, force: true });
cpSync(from, to, { recursive: true });

// The analyzer is ESM but the Electron shell is CommonJS. Scoping "type":
// "module" to this folder lets both live in one package without Node having to
// guess (and warn) about the module type of every file it loads.
writeFileSync(join(to, "package.json"), JSON.stringify({ type: "module" }, null, 2) + "\n");

console.log(`[sync-dist] copied analyzer → ${to}`);
