# ---------------------------------------------------------------------------
# MailAegis - Corporate Email Threat Analyzer - one-command installer (Windows)
#
#   irm https://raw.githubusercontent.com/soyrageagency/mailaegis/main/install.ps1 | iex
#
# Clones, installs, builds, then drops you into the friendly menu.
#
# Crafted by SoyRage Agency - https://soyrage.es/
# Support: https://www.paypal.com/paypalme/soyrageagency
# ---------------------------------------------------------------------------
$ErrorActionPreference = "Stop"
$Repo = "https://github.com/soyrageagency/mailaegis.git"
$Dir  = if ($env:MAILAEGIS_DIR) { $env:MAILAEGIS_DIR } else { Join-Path $HOME "mailaegis" }

Write-Host ""
Write-Host "  MailAegis - Corporate Email Threat Analyzer - by SoyRage Agency" -ForegroundColor Cyan
Write-Host "     https://soyrage.es/" -ForegroundColor DarkGray
Write-Host ""
if (-not (Get-Command git  -ErrorAction SilentlyContinue)) { throw "git is required (https://git-scm.com)." }
if (-not (Get-Command node -ErrorAction SilentlyContinue)) { throw "Node.js >= 18 is required (https://nodejs.org)." }
if ([int](node -p "process.versions.node.split('.')[0]") -lt 18) { throw "Node.js >= 18 required." }

if (Test-Path (Join-Path $Dir ".git")) { Write-Host "-> Updating $Dir"; git -C $Dir pull --ff-only }
else { Write-Host "-> Cloning into $Dir"; git clone --depth 1 $Repo $Dir }

Set-Location $Dir
Write-Host "-> Installing..."; npm install
Write-Host "-> Building...";   npm run build
Write-Host ""
Write-Host "  Ready! Try it with no keys and no daemon:" -ForegroundColor Green
Write-Host "    node dist/index.js demo --demo        # analyse the sample corpus"
Write-Host "    node dist/index.js serve --demo       # web UI + API on :4850"
Write-Host "    node dist/index.js menu               # friendly menu"
Write-Host ""
Write-Host "  For production, set VIRUSTOTAL_API_KEY and CLAMAV_HOST in .env"
Write-Host ""
node dist/index.js menu
