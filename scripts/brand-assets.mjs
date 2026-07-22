/**
 * Generate every brand raster from one vector source.
 *
 * Favicons, PWA icons, the Electron app icon and — the reason this exists —
 * the NSIS installer artwork and the DMG background. A default electron-builder
 * wizard shows a stock blue arrow that looks like malware; a cream panel with
 * the mark, the wordmark and the agency's name looks like software someone
 * sells.
 *
 * The designs below are plain SVG. Chromium rasterises them onto a canvas, we
 * read the pixels back and encode PNG / ICO / BMP ourselves — so the whole
 * pipeline stays inside the project's zero-runtime-dependency philosophy
 * (Playwright is already a dev dependency for the screenshots).
 *
 *   npm run assets
 *
 * Crafted by SoyRage Agency — https://soyrage.es/
 */
import { chromium } from "playwright";
import { deflateSync } from "node:zlib";
import { mkdirSync, writeFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const INK = "#111111";
const CREAM = "#f3f1ea";
const ACCENT = "#3b9ee8";
const MUTE = "#8b8b86";
const LINE = "#e7e3da";
const FONT = "Inter,'Segoe UI',Helvetica,Arial,sans-serif";

// ---------------------------------------------------------------- encoders

const CRC = (() => {
  const t = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c;
  }
  return t;
})();

function crc32(buf) {
  let c = -1;
  for (let i = 0; i < buf.length; i++) c = CRC[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, "ascii"), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
}

/** Encode straight RGBA bytes as a PNG (colour type 6, no interlace). */
function encodePng(width, height, rgba) {
  const stride = width * 4;
  const raw = Buffer.alloc((stride + 1) * height);
  for (let y = 0; y < height; y++) {
    raw[y * (stride + 1)] = 0; // filter: none — these are small, tidy images
    rgba.copy(raw, y * (stride + 1) + 1, y * stride, y * stride + stride);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; ihdr[9] = 6; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", ihdr),
    chunk("IDAT", deflateSync(raw, { level: 9 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

/** Wrap PNGs in an ICO container — the modern, lossless way to ship a .ico. */
function encodeIco(images) {
  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0); header.writeUInt16LE(1, 2); header.writeUInt16LE(images.length, 4);
  const dir = Buffer.alloc(16 * images.length);
  let offset = header.length + dir.length;
  images.forEach((img, i) => {
    const p = i * 16;
    dir[p] = img.size >= 256 ? 0 : img.size;     // 0 means 256
    dir[p + 1] = img.size >= 256 ? 0 : img.size;
    dir[p + 2] = 0; dir[p + 3] = 0;
    dir.writeUInt16LE(1, p + 4);                 // colour planes
    dir.writeUInt16LE(32, p + 6);                // bits per pixel
    dir.writeUInt32LE(img.png.length, p + 8);
    dir.writeUInt32LE(offset, p + 12);
    offset += img.png.length;
  });
  return Buffer.concat([header, dir, ...images.map((i) => i.png)]);
}

/**
 * Encode a 24-bit bottom-up BMP. NSIS will not read a PNG and is unreliable
 * with alpha, so transparency is flattened onto the cream backdrop first.
 */
function encodeBmp(width, height, rgba) {
  const rowSize = Math.ceil((width * 3) / 4) * 4;
  const pixels = Buffer.alloc(rowSize * height);
  const bg = [0xf3, 0xf1, 0xea]; // r,g,b of the brand cream
  for (let y = 0; y < height; y++) {
    const dst = (height - 1 - y) * rowSize; // BMP rows run bottom-to-top
    for (let x = 0; x < width; x++) {
      const s = (y * width + x) * 4;
      const a = rgba[s + 3] / 255;
      const r = Math.round(rgba[s] * a + bg[0] * (1 - a));
      const g = Math.round(rgba[s + 1] * a + bg[1] * (1 - a));
      const b = Math.round(rgba[s + 2] * a + bg[2] * (1 - a));
      pixels[dst + x * 3] = b; pixels[dst + x * 3 + 1] = g; pixels[dst + x * 3 + 2] = r;
    }
  }
  const file = Buffer.alloc(14);
  const info = Buffer.alloc(40);
  file.write("BM", 0, "ascii");
  file.writeUInt32LE(14 + 40 + pixels.length, 2);
  file.writeUInt32LE(14 + 40, 10);
  info.writeUInt32LE(40, 0);
  info.writeInt32LE(width, 4);
  info.writeInt32LE(height, 8);
  info.writeUInt16LE(1, 12);
  info.writeUInt16LE(24, 14);
  info.writeUInt32LE(pixels.length, 20);
  info.writeInt32LE(2835, 24); info.writeInt32LE(2835, 28); // ~72 dpi
  return Buffer.concat([file, info, pixels]);
}

// ----------------------------------------------------------------- artwork

/** The angular SoyRage "R", drawn inside a 120×120 box. */
function monogram(fill, shard) {
  return `<path fill="${fill}" fill-rule="evenodd" clip-rule="evenodd"
      d="M20 12 H68 L92 32 V54 L72 69 L101 108 H73 L51 74 H42 V108 H20 Z
         M42 32 V56 H64 L74 48 V40 L64 32 Z"/>
    <path fill="${shard}" d="M78 6 H106 L86 28 Z"/>`;
}

/** The app mark: an ink squircle with the monogram knocked out of it. */
function tile(size, radius = 0.225) {
  const r = size * radius;
  const inner = size * 0.75;
  const pad = (size - inner) / 2;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
    <rect width="${size}" height="${size}" rx="${r}" fill="${INK}"/>
    <g transform="translate(${pad} ${pad}) scale(${inner / 120})">${monogram(CREAM, ACCENT)}</g>
  </svg>`;
}

/** The faint 46px grid that runs through every SoyRage surface. */
function grid(w, h, step = 23, opacity = 0.05) {
  let d = "";
  for (let x = step; x < w; x += step) d += `M${x} 0V${h}`;
  for (let y = step; y < h; y += step) d += `M0 ${y}H${w}`;
  return `<path d="${d}" stroke="${INK}" stroke-width="1" opacity="${opacity}"/>`;
}

/** A plain fill — the adaptive icon's background layer. */
function flat(size, colour) {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
    <rect width="${size}" height="${size}" fill="${colour}"/>
  </svg>`;
}

/**
 * The adaptive icon's foreground layer.
 *
 * Android crops this to whatever shape the launcher uses, keeping only the
 * middle ~66%. So the mark is drawn at that scale on transparency; anything
 * larger loses its corners on a circular launcher.
 */
function androidForeground(size) {
  const art = size * 0.42;
  const offset = (size - art) / 2;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
    <g transform="translate(${offset} ${offset}) scale(${art / 120})">${monogram(CREAM, ACCENT)}</g>
  </svg>`;
}

/** The launch screen: the mark and the wordmark, centred on the brand grid. */
function splash(size, background, ink) {
  const c = size / 2;
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
    <rect width="${size}" height="${size}" fill="${background}"/>
    ${grid(size, size, size / 24, 0.035)}
    <g transform="translate(${c - size * 0.075} ${c - size * 0.115})">
      <rect width="${size * 0.15}" height="${size * 0.15}" rx="${size * 0.034}" fill="${ink}"/>
      <g transform="translate(${size * 0.019} ${size * 0.019}) scale(${(size * 0.112) / 120})">${monogram(background, ACCENT)}</g>
    </g>
    <text x="${c}" y="${c + size * 0.075}" text-anchor="middle" font-family="${FONT}"
          font-size="${size * 0.042}" font-weight="800" letter-spacing="${-size * 0.0012}"
          fill="${ink}">Mail<tspan fill="${ACCENT}">Aegis</tspan></text>
    <text x="${c}" y="${c + size * 0.105}" text-anchor="middle" font-family="${FONT}"
          font-size="${size * 0.0155}" fill="${ink}" opacity="0.55">Corporate Email Threat Analyzer</text>
  </svg>`;
}

/** NSIS welcome/finish sidebar — the panel that currently looks like a virus. */
function sidebar(w = 164, h = 314) {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}">
    <rect width="${w}" height="${h}" fill="${CREAM}"/>
    ${grid(w, h)}
    <!-- an oversized monogram bleeding off the bottom-right corner: reads as
         deliberate composition, where a centred crop reads as a mistake -->
    <g transform="translate(66 148) scale(1.6)" opacity="0.045">${monogram(INK, INK)}</g>
    <g transform="translate(20 26)">
      <rect width="44" height="44" rx="10" fill="${INK}"/>
      <g transform="translate(5.5 5.5) scale(0.275)">${monogram(CREAM, ACCENT)}</g>
    </g>
    <text x="20" y="98" font-family="${FONT}" font-size="19" font-weight="800" fill="${INK}" letter-spacing="-0.5">Mail<tspan fill="${ACCENT}">Aegis</tspan></text>
    <rect x="20" y="108" width="26" height="3" fill="${ACCENT}"/>
    <text x="20" y="130" font-family="${FONT}" font-size="9.5" font-weight="600" fill="${INK}" opacity="0.75">Corporate Email</text>
    <text x="20" y="143" font-family="${FONT}" font-size="9.5" font-weight="600" fill="${INK}" opacity="0.75">Threat Analyzer</text>
    <text x="20" y="166" font-family="${FONT}" font-size="8" fill="${MUTE}">VirusTotal · ClamAV</text>
    <text x="20" y="177" font-family="${FONT}" font-size="8" fill="${MUTE}">SPF · DKIM · DMARC</text>
    <text x="20" y="188" font-family="${FONT}" font-size="8" fill="${MUTE}">Phishing &amp; BEC engine</text>
    <rect x="20" y="${h - 52}" width="${w - 40}" height="1" fill="${LINE}"/>
    <text x="20" y="${h - 34}" font-family="${FONT}" font-size="8.5" font-weight="700" fill="${INK}">SoyRage Agency</text>
    <text x="20" y="${h - 22}" font-family="${FONT}" font-size="8" fill="${MUTE}">soyrage.es</text>
  </svg>`;
}

/** NSIS header strip, shown on every page after the welcome screen. */
function headerStrip(w = 150, h = 57) {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}">
    <rect width="${w}" height="${h}" fill="#ffffff"/>
    <g transform="translate(12 16)">
      <rect width="26" height="26" rx="7" fill="${INK}"/>
      <g transform="translate(3.5 3.5) scale(0.158)">${monogram(CREAM, ACCENT)}</g>
    </g>
    <text x="46" y="28" font-family="${FONT}" font-size="12.5" font-weight="800" fill="${INK}" letter-spacing="-0.3">Mail<tspan fill="${ACCENT}">Aegis</tspan></text>
    <text x="46" y="39" font-family="${FONT}" font-size="7" fill="${MUTE}" letter-spacing="0.4">SOYRAGE AGENCY</text>
  </svg>`;
}

/** macOS DMG backdrop — drag-to-Applications, with the arrow drawn in. */
function dmgBackground(w = 540, h = 380) {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}">
    <rect width="${w}" height="${h}" fill="${CREAM}"/>
    ${grid(w, h, 46, 0.04)}
    <g transform="translate(30 26)">
      <rect width="30" height="30" rx="8" fill="${INK}"/>
      <g transform="translate(4 4) scale(0.183)">${monogram(CREAM, ACCENT)}</g>
    </g>
    <text x="70" y="41" font-family="${FONT}" font-size="17" font-weight="800" fill="${INK}" letter-spacing="-0.4">Mail<tspan fill="${ACCENT}">Aegis</tspan></text>
    <text x="70" y="55" font-family="${FONT}" font-size="10" fill="${MUTE}">Corporate Email Threat Analyzer · by SoyRage Agency</text>
    <text x="${w / 2}" y="120" text-anchor="middle" font-family="${FONT}" font-size="12.5" font-weight="600" fill="${INK}" opacity="0.8">Drag MailAegis into your Applications folder</text>
    <!-- the arrow sits between the two icons electron-builder places at y=220 -->
    <g stroke="${ACCENT}" stroke-width="2.4" fill="none" stroke-linecap="round" stroke-linejoin="round" opacity="0.85">
      <path d="M214 232 H322" stroke-dasharray="6 7"/>
      <path d="M316 224 l10 8 -10 8"/>
    </g>
    <text x="${w / 2}" y="${h - 26}" text-anchor="middle" font-family="${FONT}" font-size="9" fill="${MUTE}">Unsigned build · right-click → Open the first time · soyrage.es</text>
  </svg>`;
}

// -------------------------------------------------------------- rasterising

const browser = await chromium.launch();
const page = await browser.newPage();

/** Draw an SVG string at an exact pixel size and hand back its RGBA bytes. */
async function raster(svg, width, height) {
  const data = await page.evaluate(
    async ({ svg, width, height }) => {
      const url = "data:image/svg+xml;charset=utf-8," + encodeURIComponent(svg);
      const img = new Image();
      img.width = width; img.height = height;
      await new Promise((ok, fail) => { img.onload = ok; img.onerror = fail; img.src = url; });
      const canvas = document.createElement("canvas");
      canvas.width = width; canvas.height = height;
      const ctx = canvas.getContext("2d");
      ctx.drawImage(img, 0, 0, width, height);
      return Array.from(ctx.getImageData(0, 0, width, height).data);
    },
    { svg, width, height },
  );
  return Buffer.from(data);
}

async function png(svg, size, out, height = size) {
  const rgba = await raster(svg, size, height);
  const file = resolve(ROOT, out);
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, encodePng(size, height, rgba));
  console.log(`  ${out}  ${size}×${height}`);
  return rgba;
}

async function bmp(svg, width, height, out) {
  const rgba = await raster(svg, width, height);
  const file = resolve(ROOT, out);
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, encodeBmp(width, height, rgba));
  console.log(`  ${out}  ${width}×${height}`);
}

async function ico(sizes, out) {
  const images = [];
  for (const size of sizes) {
    // Tiny favicons need a tighter corner radius or they read as a blob.
    const rgba = await raster(tile(size, size <= 32 ? 0.16 : 0.225), size, size);
    images.push({ size, png: encodePng(size, size, rgba) });
  }
  const file = resolve(ROOT, out);
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, encodeIco(images));
  console.log(`  ${out}  ${sizes.join("/")}`);
}

console.log("Brand assets");

console.log("• web");
await ico([16, 32, 48, 64, 128, 256], "src/api/public/favicon.ico");
await png(tile(180), 180, "src/api/public/icon-180.png");
await png(tile(192), 192, "src/api/public/icon-192.png");
await png(tile(512), 512, "src/api/public/icon-512.png");
// Android masks icons to its own shape, so the maskable variant keeps the
// mark inside the safe zone and fills the corners with ink.
await png(tile(512, 0), 512, "src/api/public/icon-maskable-512.png");

console.log("• desktop app");
await png(tile(1024), 1024, "desktop/build/icon.png");
await ico([16, 24, 32, 48, 64, 128, 256], "desktop/build/icon.ico");

console.log("• installers");
await bmp(sidebar(), 164, 314, "desktop/build/installerSidebar.bmp");
await bmp(sidebar(), 164, 314, "desktop/build/uninstallerSidebar.bmp");
await bmp(headerStrip(), 150, 57, "desktop/build/installerHeader.bmp");
await png(dmgBackground(), 540, "desktop/build/dmg-background.png", 380);

console.log("• android");
// @capacitor/assets expands these into every density and the adaptive-icon
// layers. The foreground keeps the mark inside Android's safe zone — the
// launcher can crop a circle out of it, and a mark drawn edge to edge loses
// its corners.
await png(tile(1024), 1024, "mobile/assets/icon.png");
await png(androidForeground(1024), 1024, "mobile/assets/icon-foreground.png");
await png(flat(1024, INK), 1024, "mobile/assets/icon-background.png");
await png(splash(2732, CREAM, INK), 2732, "mobile/assets/splash.png");
await png(splash(2732, "#141412", CREAM), 2732, "mobile/assets/splash-dark.png");

console.log("• docs");
await png(tile(512), 512, "assets/mark-tile.png");

await browser.close();
console.log("Done.");
