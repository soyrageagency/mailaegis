# The MailAegis channel

`updates.json` in this folder is the **broadcast channel** for every copy of MailAegis
in the world. Edit it, commit, push — and within a few hours each running instance
shows a small card in the bottom corner: a new release with its changelog, or
whatever announcement you wrote.

There is no server to operate. Clients read the raw file from GitHub:

```
https://raw.githubusercontent.com/soyrageagency/mailaegis/main/channel/updates.json
```

## Publishing a release

Bump `latest.version` and write the `changelog`. Anyone running an older version
gets the card; anyone already up to date sees nothing.

```jsonc
"latest": {
  "version": "1.2.0",              // semver — compared against the running build
  "published": "2026-08-01",
  "mandatory": false,              // true → the card cannot be dismissed
  "notes": "One line, shown as the card's subtitle.",
  "changelog": ["Bullet one.", "Bullet two."],
  "url": "https://github.com/soyrageagency/mailaegis/releases/tag/v1.2.0",
  "downloads": {                   // the Install button picks the right one
    "win": "…/MailAegis-1.2.0-win-x64.exe",
    "mac-arm64": "…/MailAegis-1.2.0-mac-arm64.dmg",
    "mac-x64": "…/MailAegis-1.2.0-mac-x64.dmg",
    "source": "https://github.com/soyrageagency/mailaegis"
  }
}
```

## Announcing anything else

`announcements` is a free-form list — a security advisory, a maintenance window,
a new feature, an offer. Each entry is shown once until the user dismisses it.

```jsonc
{
  "id": "advisory-2026-08",        // stable id — changing it re-shows the card
  "level": "warn",                 // info | success | warn | critical
  "title": "Rotate your VirusTotal keys",
  "body": "Keys issued before July 2026 stop working on 1 September.",
  "link": { "label": "Read the advisory", "url": "https://soyrage.es/…" },
  "starts": "2026-08-01",          // optional window; "" means always
  "ends": "2026-09-01",
  "minVersion": "1.0.0",           // optional targeting; "" means any version
  "maxVersion": "",
  "dismissible": true
}
```

Everything is optional except `id` and `title`. An entry outside its date window,
or outside its version range, is filtered out **server-side** and never reaches
the browser.

## What operators control

The channel is a convenience, not a leash. Any deployment can:

| Variable | Effect |
| --- | --- |
| `MAILAEGIS_UPDATE_CHECK=false` | No outbound request is ever made. Air-gapped installs stay silent. |
| `MAILAEGIS_UPDATE_FEED=https://intranet/…json` | Point at your own feed and broadcast to your own fleet. |
| `MAILAEGIS_UPDATE_TTL_MIN=360` | How long a fetched feed is cached (default 6 h). |

The check is a single unauthenticated `GET`. It sends no telemetry, no identifiers
and no mailbox data — the running version is compared **inside your own process**,
not on a server. If the request fails, MailAegis carries on without a word.

---

Crafted by [SoyRage Agency](https://soyrage.es/) · Licensed under the SoyRage Attribution License.
