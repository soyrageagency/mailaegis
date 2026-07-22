#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# MailAegis — Corporate Email Threat Analyzer — one-command installer
#
#   curl -fsSL https://raw.githubusercontent.com/soyrageagency/mailaegis/main/install.sh | bash
#
# Clones, installs, builds, then drops you into the friendly menu.
#
# Crafted by SoyRage Agency — https://soyrage.es/
# Support: https://www.paypal.com/paypalme/soyrageagency
# ---------------------------------------------------------------------------
set -euo pipefail
REPO="https://github.com/soyrageagency/mailaegis.git"
DIR="${MAILAEGIS_DIR:-$HOME/mailaegis}"

echo ""
echo "  MailAegis — Corporate Email Threat Analyzer — by SoyRage Agency"
echo "     https://soyrage.es/"
echo ""
command -v git  >/dev/null 2>&1 || { echo "git is required."; exit 1; }
command -v node >/dev/null 2>&1 || { echo "Node.js >= 18 is required (https://nodejs.org)."; exit 1; }
[ "$(node -p 'process.versions.node.split(".")[0]')" -ge 18 ] || { echo "Node.js >= 18 required."; exit 1; }

if [ -d "$DIR/.git" ]; then echo "-> Updating $DIR"; git -C "$DIR" pull --ff-only || true
else echo "-> Cloning into $DIR"; git clone --depth 1 "$REPO" "$DIR"; fi

cd "$DIR"
echo "-> Installing…"; npm install --silent
echo "-> Building…";   npm run build --silent
echo ""
echo "  Ready! Try it with no keys and no daemon:"
echo "    node dist/index.js demo --demo        # analyse the sample corpus"
echo "    node dist/index.js serve --demo       # web UI + API on :4850"
echo "    node dist/index.js menu               # friendly menu"
echo ""
echo "  Wire it into a mail pipeline:"
echo "    cat message.eml | node dist/index.js scan    # exit 0/1/2 = clean/suspicious/malicious"
echo ""
echo "  For production, set VIRUSTOTAL_API_KEY and CLAMAV_HOST in .env"
echo ""
if [ -e /dev/tty ]; then node dist/index.js menu < /dev/tty; else echo "Run: node dist/index.js menu"; fi
