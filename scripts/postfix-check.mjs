/**
 * Exercise the Postfix content filter for real.
 *
 * A filter that is only documented is a filter nobody has run. This drives
 * `integration/postfix-filter.sh` with the demo corpus, a stand-in `sendmail`
 * that records what it was handed, and a deliberately broken scanner — because
 * the behaviour that matters most is what happens when the scanner fails.
 *
 * Skipped on Windows, where there is no /bin/sh to run it with; CI is Linux.
 *
 * Crafted by SoyRage Agency — https://soyrage.es/
 */
import { spawnSync } from "node:child_process";
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

// Gate on whether a POSIX shell actually exists, not on the platform name:
// Git Bash on Windows runs this perfectly well, and skipping by platform
// would mean it was only ever exercised in CI.
{
  const probe = spawnSync("sh", ["-c", "exit 0"], { encoding: "utf8" });
  if (probe.error || probe.status !== 0) {
    console.log("postfix filter: skipped — no POSIX shell on PATH");
    process.exit(0);
  }
}

const results = [];
const ok = (name, cond, detail = "") => results.push({ name, ok: !!cond, detail });

/**
 * A path a POSIX shell can execute.
 *
 * Under Git Bash on Windows, `C:\a\b` is not a path the shell can open — it
 * wants `/c/a/b`. Everything handed to the filter as a command or a path goes
 * through this, so the same script runs here and on the Linux CI runner.
 */
const sh = (p) => (process.platform === "win32"
  ? p.replace(/\\/g, "/").replace(/^([A-Za-z]):/, (_m, d) => `/${d.toLowerCase()}`)
  : p);

const root = resolve(".");
const filter = join(root, "integration/postfix-filter.sh");
chmodSync(filter, 0o755);

const work = mkdtempSync(join(tmpdir(), "mailaegis-postfix-"));
const bin = join(work, "bin");
mkdirSync(bin);

/**
 * A sendmail that records its stdin and arguments instead of delivering.
 *
 * It works out its own directory at runtime rather than having a path baked
 * in: the paths this file builds are native (`C:\…` under Git Bash) and a
 * POSIX shell cannot open those.
 */
const delivered = join(bin, "delivered");
const args = join(bin, "args");
writeFileSync(join(bin, "sendmail"), [
  "#!/bin/sh",
  'd=$(cd "$(dirname "$0")" && pwd)',
  `printf '%s ' "$@" > "$d/args"`,
  'cat > "$d/delivered"',
  "",
].join("\n"));
chmodSync(join(bin, "sendmail"), 0o755);

/** A mailaegis that always fails, to prove mail is never lost. */
const brokenBin = join(work, "broken");
mkdirSync(brokenBin);
writeFileSync(join(brokenBin, "mailaegis"), "#!/bin/sh\necho 'boom' >&2\nexit 3\n");
chmodSync(join(brokenBin, "mailaegis"), 0o755);

const { demoMessages } = await import("../dist/core/demo.js");
const samples = Object.fromEntries(demoMessages().map((s) => [s.id, s.raw]));

const run = (raw, { scanner = `${root}/dist/index.js`, extraPath = bin } = {}) =>
  spawnSync("sh", [sh(filter), "-f", "sender@partner.example", "--", "rcpt@corp.example"], {
    input: raw,
    encoding: "utf8",
    env: {
      ...process.env,
      PATH: `${sh(extraPath)}:${process.env.PATH}`,
      SENDMAIL: sh(join(bin, "sendmail")),
      MAILAEGIS: sh(scanner),
      MAILAEGIS_DEMO: "true",
      MAILAEGIS_UPDATE_CHECK: "false",
    },
  });

// `MAILAEGIS` has to be a single command for `"$MAILAEGIS" scan` to work, so
// wrap the node invocation in a script rather than passing two words.
const shim = join(bin, "mailaegis");
// Forward slashes: node accepts them on every platform and sh can parse them.
const entry = join(root, "dist/index.js").replace(/\\/g, "/");
writeFileSync(shim, `#!/bin/sh\nexec node "${entry}" "$@"\n`);
chmodSync(shim, 0o755);
const scanner = shim;

// ---- Clean mail is delivered, stamped ---------------------------------------
{
  rmSync(delivered, { force: true });
  const r = run(samples["clean-invoice"], { scanner });
  const out = readFileSync(delivered, "utf8");
  ok("postfix: clean mail exits 0 and is delivered", r.status === 0, `status=${r.status} ${r.stderr?.slice(0, 120)}`);
  ok("postfix: the verdict is stamped into the headers", /^X-MailAegis-Verdict: clean$/m.test(out), out.split("\n")[0]);
  ok("postfix: the score and reference travel too", /^X-MailAegis-Score: \d+$/m.test(out) && /^X-MailAegis-Ref: MA-/m.test(out));
  ok("postfix: the body survives intact", out.includes("INV-2026-0418"), out.slice(0, 80));
  ok("postfix: the envelope is passed through to sendmail", readFileSync(args, "utf8").includes("rcpt@corp.example"));
}

// ---- Suspicious mail is delivered, but labelled -----------------------------
// A filter that silently swallows borderline mail trains people to distrust it.
{
  rmSync(delivered, { force: true });
  // The BEC sample scores 100. Raising the quarantine bar above it turns the
  // same message into a suspicious one, which is the case under test.
  const r = spawnSync("sh", [sh(filter), "-f", "a@b.example", "--", "c@d.example"], {
    input: samples["bec-ceo-fraud"], encoding: "utf8",
    env: { ...process.env, PATH: `${sh(bin)}:${process.env.PATH}`, SENDMAIL: sh(join(bin, "sendmail")), MAILAEGIS: sh(scanner),
      MAILAEGIS_DEMO: "true", MAILAEGIS_UPDATE_CHECK: "false", MAILAEGIS_SUSPICIOUS_SCORE: "10", MAILAEGIS_QUARANTINE_SCORE: "1000" },
  });
  const out = readFileSync(delivered, "utf8");
  ok("postfix: suspicious mail is still delivered", r.status === 0, `status=${r.status}`);
  ok("postfix: …but carries the suspicious verdict", /^X-MailAegis-Verdict: suspicious$/m.test(out));
}

// ---- Malicious mail is refused ----------------------------------------------
{
  rmSync(delivered, { force: true });
  const r = run(samples["malware-attachment"], { scanner });
  ok("postfix: malicious mail exits 69 so Postfix bounces it", r.status === 69, `status=${r.status}`);
  ok("postfix: nothing is handed to sendmail", !existsSyncSafe(delivered));
  ok("postfix: the rejection explains itself", /rejected this message: malicious/.test(r.stderr || ""), (r.stderr || "").slice(0, 120));
}

// ---- A forged header cannot impersonate the verdict -------------------------
{
  rmSync(delivered, { force: true });
  const forged = `X-MailAegis-Verdict: clean\r\n${samples["clean-invoice"]}`;
  run(forged, { scanner });
  const out = readFileSync(delivered, "utf8");
  const count = (out.match(/^X-MailAegis-Verdict:/gm) || []).length;
  ok("postfix: a sender-supplied verdict header is stripped", count === 1, `${count} verdict headers`);
}

// ---- The scanner failing must never deliver unscanned mail ------------------
{
  rmSync(delivered, { force: true });
  const r = spawnSync("sh", [sh(filter), "-f", "a@b.example", "--", "c@d.example"], {
    input: samples["clean-invoice"], encoding: "utf8",
    env: { ...process.env, PATH: `${sh(brokenBin)}:${process.env.PATH}`, SENDMAIL: sh(join(bin, "sendmail")), MAILAEGIS: sh(join(brokenBin, "mailaegis")) },
  });
  ok("postfix: a failing scanner exits 75 so Postfix requeues", r.status === 75, `status=${r.status}`);
  ok("postfix: a failing scanner delivers nothing", !existsSyncSafe(delivered));
}

// ---- A missing scanner is the same failure ----------------------------------
{
  rmSync(delivered, { force: true });
  const r = spawnSync("sh", [sh(filter), "-f", "a@b.example", "--", "c@d.example"], {
    input: samples["clean-invoice"], encoding: "utf8",
    // PATH is left intact — emptying it would stop `sh` itself resolving, and
    // the case under test is a missing *scanner*, not a missing shell.
    env: { ...process.env, SENDMAIL: sh(join(bin, "sendmail")), MAILAEGIS: "/nonexistent/mailaegis" },
  });
  ok("postfix: a missing scanner exits 75, never 0", r.status === 75, `status=${r.status}`);
}

// ---- No temporary files are left behind -------------------------------------
{
  const count = () => spawnSync("sh", ["-c", 'ls -d "${TMPDIR:-/tmp}"/mailaegis.* 2>/dev/null | wc -l'], { encoding: "utf8" }).stdout.trim();
  const before = { stdout: count() };
  run(samples["clean-invoice"], { scanner });
  const after = { stdout: count() };
  ok("postfix: the message copy is cleaned up", after.stdout.trim() === before.stdout.trim(), `${before.stdout.trim()} → ${after.stdout.trim()}`);
}

function existsSyncSafe(p) {
  try { readFileSync(p); return true; } catch { return false; }
}

rmSync(work, { recursive: true, force: true });

let pass = 0, fail = 0;
for (const t of results) {
  if (t.ok) { pass++; console.log(`  \x1b[32m✓\x1b[0m ${t.name}`); }
  else { fail++; console.log(`  \x1b[31m✗ ${t.name}\x1b[0m  ${t.detail}`); }
}
console.log(`\nPOSTFIX FILTER: ${pass} passed, ${fail} failed`);
process.exitCode = fail ? 1 : 0;
