/**
 * Post-build: copy the web UI static assets into dist/.
 * Crafted by SoyRage Agency — https://soyrage.es/
 */
import { cpSync, existsSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const from = resolve(root, "src/api/public");
const to = resolve(root, "dist/api/public");
if (!existsSync(from)) { console.error(`[copy-public] missing ${from}`); process.exit(1); }
mkdirSync(dirname(to), { recursive: true });
cpSync(from, to, { recursive: true });
console.log(`[copy-public] copied web assets → ${to}`);
