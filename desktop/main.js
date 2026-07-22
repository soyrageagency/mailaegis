/**
 * MailAegis desktop shell (Electron).
 *
 * Starts the analyzer's HTTP server in-process on a free loopback port and
 * opens the mail client in a native window. Nothing is exposed to the network:
 * the server binds to 127.0.0.1 and dies with the app.
 *
 * Optional configuration lives in `settings.json` inside the app's user-data
 * folder (Help → Open settings folder) and is applied as environment variables,
 * e.g. { "VIRUSTOTAL_API_KEY": "…", "CLAMAV_HOST": "127.0.0.1",
 *        "MAILAEGIS_CORPORATE_DOMAINS": "corp.example" }.
 *
 * Part of MailAegis — Corporate Email Threat Analyzer.
 * Crafted by SoyRage Agency — https://soyrage.es/
 * Licensed under the SoyRage Attribution License (see LICENSE).
 */

const { app, BrowserWindow, shell, Menu, dialog } = require("electron");
const path = require("node:path");
const fs = require("node:fs");
const net = require("node:net");
const { pathToFileURL } = require("node:url");

/** Ask the OS for a free loopback port. */
function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

/** Apply the user's settings.json as environment variables. */
function applySettings() {
  const file = path.join(app.getPath("userData"), "settings.json");
  if (!fs.existsSync(file)) return file;
  try {
    const settings = JSON.parse(fs.readFileSync(file, "utf8"));
    for (const [key, value] of Object.entries(settings)) {
      if (process.env[key] === undefined) process.env[key] = String(value);
    }
  } catch (err) {
    dialog.showErrorBox("MailAegis", `Could not read settings.json:\n${err.message}`);
  }
  return file;
}

/** Boot the bundled analyzer and return the URL to load. */
async function startBackend() {
  applySettings();
  process.env.MAILAEGIS_HOST = "127.0.0.1";
  if (!process.env.MAILAEGIS_PORT) process.env.MAILAEGIS_PORT = String(await freePort());
  if (!process.env.MAILAEGIS_OUT_DIR) process.env.MAILAEGIS_OUT_DIR = path.join(app.getPath("userData"), "reports");

  const dist = path.join(__dirname, "dist");
  const load = (rel) => import(pathToFileURL(path.join(dist, rel)).href);
  const { loadConfig } = await load("config.js");
  const { Logger } = await load("logger.js");
  const { startServer } = await load("api/server.js");

  const config = loadConfig();
  await startServer(config, new Logger("error"));
  return `http://${config.host}:${config.port}`;
}

function buildMenu() {
  const template = [
    ...(process.platform === "darwin" ? [{ role: "appMenu" }] : []),
    { role: "editMenu" },
    { role: "viewMenu" },
    {
      label: "Help",
      submenu: [
        {
          label: "Open settings folder",
          click: () => shell.openPath(app.getPath("userData")),
        },
        {
          label: "Documentation",
          click: () => shell.openExternal("https://github.com/soyrageagency/mailaegis#readme"),
        },
        {
          label: "SoyRage Agency",
          click: () => shell.openExternal("https://soyrage.es/"),
        },
      ],
    },
  ];
  Menu.setApplicationMenu(Menu.buildFromTemplate(template));
}

async function createWindow() {
  const win = new BrowserWindow({
    width: 1360,
    height: 900,
    minWidth: 960,
    minHeight: 600,
    backgroundColor: "#f3f1ea",
    title: "MailAegis — Corporate Email Threat Analyzer",
    autoHideMenuBar: process.platform !== "darwin",
    webPreferences: { nodeIntegration: false, contextIsolation: true },
  });

  // Anything that isn't our own UI opens in the real browser.
  win.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: "deny" };
  });

  try {
    const url = await startBackend();
    await win.loadURL(url);
  } catch (err) {
    dialog.showErrorBox("MailAegis could not start", String(err && err.stack ? err.stack : err));
    app.quit();
  }
}

app.whenReady().then(() => {
  buildMenu();
  createWindow();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
