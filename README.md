<div align="center">

<a href="https://soyrage.es/"><img src="./assets/soyrage-banner.svg" alt="SoyRage Agency — Full-Stack Developer × Infrastructure Engineer · soyrage.es" width="100%"></a>

<br/><br/>

# 🛡️ MailAegis — Corporate Email Threat Analyzer

**Your inbox, with an antivirus layer.**

Connect your corporate mailbox over IMAP and MailAegis reads it like a real mail client — folders, senders, subjects, categories — while scoring **every** message: SPF/DKIM/DMARC, **VirusTotal** reputation, **ClamAV** content scanning, and its own phishing/BEC heuristic engine.

Use it as a **desktop app**, a **web UI**, an **HTTP API**, or a **Postfix/SMTPS content filter** with proper exit codes.

<br/>

<img src="./assets/screenshots/inbox.png" alt="MailAegis three-pane mail client: folders, threat categories, labels, and a message list with a verdict on every row" width="100%">

<sub>📬 A professional three-pane client — folders, **threat categories**, custom labels — with a colour-coded verdict on every message. <a href="#-see-it">More screenshots ↓</a></sub>

<br/><br/>

[![CI](https://github.com/soyrageagency/mailaegis/actions/workflows/ci.yml/badge.svg)](https://github.com/soyrageagency/mailaegis/actions/workflows/ci.yml)
[![Release](https://github.com/soyrageagency/mailaegis/actions/workflows/release.yml/badge.svg)](https://github.com/soyrageagency/mailaegis/releases)
[![Node](https://img.shields.io/badge/Node-%3E%3D18-3c873a?logo=node.js&logoColor=white)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5-3178c6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Zero deps](https://img.shields.io/badge/runtime%20deps-0-3b9ee8)](#-how-it-works)
[![License: SRAL](https://img.shields.io/badge/License-SoyRage%20Attribution-orange)](./LICENSE)
[![Donate](https://img.shields.io/badge/Support-PayPal-00457C?logo=paypal&logoColor=white)](https://www.paypal.com/paypalme/soyrageagency)

### Designed, built & maintained by **[SoyRage Agency](https://soyrage.es/)** · **https://soyrage.es/**

**⚡ New here? → [Quick start](#-quick-start).**  ·  **💻 [Desktop app for macOS & Windows](#-desktop-app-macos--windows)**  ·  **☕ [Support the project](https://www.paypal.com/paypalme/soyrageagency)**

</div>

---

## 📑 Table of contents

- [Why MailAegis](#-why-mailaegis)
- [Quick start](#-quick-start)
- [See it](#-see-it)
- [What it detects](#-what-it-detects)
- [How it works](#-how-it-works)
- [Desktop app (macOS & Windows)](#-desktop-app-macos--windows)
- [Integrate it](#-integrate-it)
- [Configuration](#-configuration)
- [Privacy & safety](#-privacy--safety)
- [Project structure](#-project-structure)
- [Development](#-development)
- [More from the SoyRage suite](#-more-from-the-soyrage-suite)
- [Support the project](#-support-the-project)
- [Credits & License](#-credits--license)

---

## 💡 Why MailAegis

Corporate mail filters give you a binary answer — delivered or quarantined — and almost no explanation. When a finance clerk asks *"is this invoice real?"*, nobody can tell them **why** in under a minute.

MailAegis is built for that moment:

- **It explains itself.** Every verdict is a list of findings with a severity, a plain-English reason and the evidence: *"the text says `portal.corp.example` but the link goes to `secure-corp-login.example`"*.
- **Three opinions, one verdict.** Your own ClamAV, VirusTotal's reputation data, and an in-house heuristic engine that understands *identity* and *intent* — not just signatures.
- **It reads like a mail client.** Folders, Sent, search, threat categories and your own labels. Triage a mailbox the way you actually work, not through a log file.
- **It drops into a pipeline.** `cat message.eml | mailaegis scan` exits `0/1/2` for clean/suspicious/malicious — that is all Postfix, procmail or a milter needs.
- **Zero runtime dependencies.** MIME parsing, the IMAP client, the ClamAV protocol and the web server are all hand-written on Node core.

---

## ⚡ Quick start

**You need [Node.js ≥ 18](https://nodejs.org/).** Prefer a desktop app? → [download a build](#-desktop-app-macos--windows).

**macOS / Linux**
```bash
curl -fsSL https://raw.githubusercontent.com/soyrageagency/mailaegis/main/install.sh | bash
```

**Windows (PowerShell)**
```powershell
irm https://raw.githubusercontent.com/soyrageagency/mailaegis/main/install.ps1 | iex
```

Or by hand:

```bash
git clone https://github.com/soyrageagency/mailaegis.git && cd mailaegis
npm install && npm run build

node dist/index.js demo --demo     # analyse the built-in corpus, no keys needed
node dist/index.js serve --demo    # open http://127.0.0.1:4850
```

> 💡 **Everything works with no VirusTotal key and no ClamAV daemon.** In demo mode both scanners are simulated, so you can evaluate the whole product offline — that is exactly what CI runs.

```text
$ mailaegis demo --demo

  ✓ CLEAN      score   0/100  Legitimate supplier invoice
  ✓ CLEAN      score   0/100  Marketing newsletter
  ✓ MALICIOUS  score 100/100  CEO fraud / bank-detail change (BEC)
  ✓ MALICIOUS  score 100/100  Credential phishing from a look-alike domain
  ✓ MALICIOUS  score 100/100  Macro-enabled attachment carrying malware
```

---

## 🖼️ See it

<div align="center">

### Connect a mailbox — or open the simulated one
<img src="./assets/screenshots/connect.png" alt="MailAegis connection screen with IMAP settings and a demo mailbox option" width="92%">

### Reading pane — the verdict, and exactly why
<img src="./assets/screenshots/message.png" alt="MailAegis reading pane showing a malicious BEC message with its findings" width="100%">

### A printable report for the ticket
<img src="./assets/screenshots/report.png" alt="MailAegis printable HTML analysis report" width="82%">

<sub>Rendered in <b>demo mode</b> · watermarked © SoyRage Agency · soyrage.es</sub>

</div>

---

## 🔍 What it detects

| Layer | Examples |
| --- | --- |
| 🪪 **Identity & BEC** | Executive impersonation from a free mailbox · display name embedding a different address or your brand · **look-alike domains** (`c0rp-example.com`, typo-squats) · replies redirected to another domain |
| 🎣 **Phishing** | Link text that doesn't match its destination · credential landing pages · bare-IP and punycode hosts · URL shorteners |
| 📎 **Attachments** | Executables and blocked extensions · **double extensions** (`statement.pdf.exe`) · macro-enabled Office files · **magic-byte/extension mismatch** · executables inside archives · password-protected archives |
| 🔐 **Authentication** | SPF fail/softfail · DKIM invalid · DMARC fail · envelope/From misalignment · spoofed *internal* senders |
| 🧠 **Intent** | Bank-detail change requests · urgent wire transfers · gift-card scams · account-expiry pressure · secrecy pressure |
| 🦠 **Scanners** | **ClamAV** signature hits · **VirusTotal** file & URL detections · files VirusTotal has never seen |

Each finding carries a weight; the total (capped at 100) is the risk score, and your thresholds turn it into **clean · suspicious · malicious**. Findings are also grouped into **threat categories** — Malware, Phishing, Fraud/BEC, Spoofing — so an analyst sees *what kind* of bad it is at a glance.

---

## 🛠️ How it works

```
 parse → authenticate → heuristics → ClamAV → VirusTotal → score → verdict
 (MIME)   (SPF/DKIM/DMARC)  (in-house)  (your daemon)  (reputation)
```

Every report records **which engines actually ran**, so an "all clear" from a degraded pipeline can never be mistaken for a real one.

**Zero runtime dependencies** — the MIME parser, the IMAP client, the clamd INSTREAM protocol, the VirusTotal client and the HTTP server are all written directly on Node core.

---

## 💻 Desktop app (macOS & Windows)

MailAegis ships as a native-feeling desktop app so analysts don't need a terminal.

**[⬇️ Download the latest release](https://github.com/soyrageagency/mailaegis/releases/latest)** — `.dmg` for macOS (Intel + Apple Silicon) and `.exe` for Windows.

The desktop build starts the analyzer locally and opens the mail client in its own window — nothing is exposed to the network. Builds are produced by GitHub Actions on every tagged release; see [`.github/workflows/release.yml`](./.github/workflows/release.yml).

```bash
# Build it yourself
cd desktop && npm install && npm run dist
```

> The apps are **not code-signed** (no paid Apple/Microsoft certificates). macOS: right-click → Open the first time. Windows: "More info" → "Run anyway".

---

## 🔌 Integrate it

### 1. Command line (Postfix / procmail / any MTA)

```bash
cat message.eml | mailaegis scan          # exit 0 clean · 1 suspicious · 2 malicious · 3 error
mailaegis scan message.eml --json         # full analysis as JSON
mailaegis scan message.eml --report       # also write HTML + JSON + Markdown
```

A minimal Postfix `content_filter` wrapper:

```bash
#!/bin/sh
# /usr/local/bin/mailaegis-filter — invoked by Postfix with the message on stdin
tee /tmp/in.$$ | mailaegis scan >/dev/null 2>&1
case $? in
  2) exit 69 ;;                                   # malicious → bounce (EX_UNAVAILABLE)
  1) exec sendmail -i -X quarantine "$@" </tmp/in.$$ ;;   # suspicious → quarantine
  *) exec sendmail -i "$@" </tmp/in.$$ ;;         # clean → deliver
esac
```

### 2. HTTP API

```bash
mailaegis serve                      # http://127.0.0.1:4850
curl -s --data-binary @message.eml http://127.0.0.1:4850/api/analyze | jq .verdict
```

| Endpoint | Purpose |
| --- | --- |
| `POST /api/analyze` | Raw RFC-822 message in the body → JSON verdict |
| `GET /api/meta` | Which engines are active, and your thresholds |
| `POST /api/mailbox/connect` | Connect an IMAP mailbox (or `{"demo":true}`) |
| `GET /api/mailbox/messages` | The analysed message list |
| `GET /api/mailbox/messages/:id` | One full analysis |
| `POST /api/mailbox/select` | Switch folder (Inbox, Sent, …) |
| `GET/POST /api/categories` · `PUT …/labels` | Manage and assign labels |

Set `MAILAEGIS_API_TOKEN` to require `Authorization: Bearer …`.

### 3. Mail client UI

`mailaegis serve` (or the desktop app) gives you the three-pane client: folders, search, threat categories, labels and a full analysis per message.

---

## ⚙️ Configuration

All configuration is environment variables (a local `.env` is loaded automatically).

| Variable | Default | Purpose |
| --- | --- | --- |
| `MAILAEGIS_DEMO` | `false` | Simulate VirusTotal & ClamAV — no keys, no daemon. |
| `VIRUSTOTAL_API_KEY` | — | Enables the VirusTotal hash/URL lookups. |
| `VIRUSTOTAL_MALICIOUS_THRESHOLD` | `3` | Engines required before a detection counts as malicious. |
| `CLAMAV_HOST` / `CLAMAV_PORT` | — / `3310` | Your clamd daemon. |
| `MAILAEGIS_CORPORATE_DOMAINS` | — | **Set this.** Your domains, for impersonation & look-alike detection. |
| `MAILAEGIS_BLOCKED_EXTENSIONS` | `exe,scr,js,vbs,…` | Attachment extensions treated as dangerous. |
| `MAILAEGIS_SUSPICIOUS_SCORE` / `_QUARANTINE_SCORE` | `35` / `70` | Verdict thresholds. |
| `IMAP_HOST` / `_PORT` / `_USER` / `_PASSWORD` / `_TLS` / `_MAILBOX` | — / `993` / … / `true` / `INBOX` | Pre-configure the mailbox so credentials never pass through the browser. |
| `MAILAEGIS_HOST` / `_PORT` | `127.0.0.1` / `4850` | API & UI bind address. |
| `MAILAEGIS_API_TOKEN` | — | Require a bearer token on the API. |
| `MAILAEGIS_OUT_DIR` | `./reports` | Where reports and labels are written. |

Run `mailaegis doctor` to see exactly which engines are live.

---

## 🔒 Privacy & safety

- **VirusTotal receives only SHA-256 hashes and URL identifiers** — never file contents, never message bodies.
- **ClamAV runs on your own infrastructure**; attachment bytes never leave your network.
- **IMAP uses `BODY.PEEK`**, so connecting MailAegis never marks mail as read.
- **Credentials are never written to disk** and never returned by the API; they live in the process only while you are connected.
- The API **binds to `127.0.0.1`** by default.
- The bundled "malicious" samples carry the **EICAR test string** — never real malware.

---

## 🗂️ Project structure

```
mailaegis/
├── desktop/                    # Electron wrapper (macOS & Windows builds)
├── scripts/                    # copy-public · smoke · shots
└── src/
    ├── index.ts                # CLI: scan · demo · serve · menu · doctor
    ├── branding.ts · config.ts · logger.ts
    ├── core/
    │   ├── parse.ts            # Dependency-free MIME/RFC-822 parser
    │   ├── auth.ts             # SPF/DKIM/DMARC + alignment
    │   ├── engine.ts           # The in-house heuristic engine
    │   ├── clamav.ts           # clamd INSTREAM client
    │   ├── virustotal.ts       # VirusTotal API v3 lookups
    │   ├── analyze.ts          # The pipeline + scoring
    │   ├── report.ts           # Console · HTML · Markdown · JSON
    │   ├── demo.ts             # Built-in corpus (EICAR-based)
    │   └── icons.ts · types.ts
    ├── mailbox/
    │   ├── imap.ts             # Minimal IMAP client (TLS)
    │   ├── session.ts          # Folders, messages, analyses
    │   └── categories.ts       # Threat classes + user labels
    ├── api/                    # HTTP API + the mail-client web UI
    └── menu/menu.ts
├── LICENSE · NOTICE · README.md
```

---

## 🧪 Development

```bash
npm run dev        # hot-reload with tsx
npm run typecheck  # strict type check
npm run build      # compile to dist/
npm run demo       # analyse the built-in corpus
npm run smoke      # 51-check end-to-end suite (what CI runs)
npm run shots      # regenerate the README screenshots
```

The smoke suite covers the MIME parser, every detection rule that matters, the CLI exit codes, the HTTP API, the mailbox/folder/label flows, and the **IMAP client against a real IMAP conversation** (a fake server is spun up in-process).

---

## 🧰 More from the SoyRage suite

Same design, same care. **If one of these saves you time, a ⭐ genuinely helps.**

| Project | What it does | Star |
| --- | --- | --- |
| 🛡️ **[MailAegis](https://github.com/soyrageagency/mailaegis)** | *(you are here)* Corporate email threat analysis — VirusTotal, ClamAV and an in-house phishing/BEC engine, in a mail client. | [![Star](https://img.shields.io/github/stars/soyrageagency/mailaegis?style=social)](https://github.com/soyrageagency/mailaegis) |
| 🗺️ **[NetAtlas](https://github.com/soyrageagency/netatlas)** | Living infrastructure documentation — agentless discovery that draws and maintains your network map. | [![Star](https://img.shields.io/github/stars/soyrageagency/netatlas?style=social)](https://github.com/soyrageagency/netatlas) |
| 🖧 **[Proxmox MCP Server](https://github.com/soyrageagency/proxmox-mcp-server)** | Chat with your Proxmox VE cluster; signed ISO 27001 / NIS2 / DORA resilience evidence. | [![Star](https://img.shields.io/github/stars/soyrageagency/proxmox-mcp-server?style=social)](https://github.com/soyrageagency/proxmox-mcp-server) |
| 🐳 **[Docker MCP Server](https://github.com/soyrageagency/docker-mcp-server)** | Chat with your Docker host — live web panel and a TUI with an AI copilot. | [![Star](https://img.shields.io/github/stars/soyrageagency/docker-mcp-server?style=social)](https://github.com/soyrageagency/docker-mcp-server) |
| 🚚 **[VMware → Proxmox (V2P)](https://github.com/soyrageagency/vmware-to-proxmox)** | Leaving vSphere? Inventory, compatibility, cost/time and a PDF assessment. | [![Star](https://img.shields.io/github/stars/soyrageagency/vmware-to-proxmox?style=social)](https://github.com/soyrageagency/vmware-to-proxmox) |

---

## 💙 Support the project

MailAegis is built and maintained in the open by **SoyRage Agency**. If it stops one invoice-fraud e-mail, it has already paid for itself — please consider supporting continued development.

<div align="center">

[![Support on PayPal](https://img.shields.io/badge/Support%20on-PayPal-00457C?logo=paypal&logoColor=white&style=for-the-badge)](https://www.paypal.com/paypalme/soyrageagency)

**Need this wired into your corporate mail gateway?** [**SoyRage Agency**](https://soyrage.es/) does hands-on e-mail security engineering.

**paypal.me/soyrageagency** · a ⭐ on the repo helps too!

</div>

---

## 🖋️ Credits & License

<div align="center">

**Designed, built and maintained by [SoyRage Agency](https://soyrage.es/) — https://soyrage.es/**

Licensed under the **SoyRage Attribution License (SRAL)** — free to use, modify and distribute, provided the attribution to SoyRage Agency stays intact. See [LICENSE](./LICENSE).

MailAegis is a detection aid, not a guarantee. Always keep a second layer in your mail flow.

_Every message inspected — attachments, links, headers and intent._

</div>
