#!/usr/bin/env node
// Regenerate every app and tray icon from src-tauri/icons/app-icon.svg.
// Needs: node and `npm i @resvg/resvg-js` (a development tool, not a dependency
// of the app). Run from the repository root: node scripts/regen-icons.mjs
import { readFileSync, writeFileSync, readdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createRequire } from "node:module";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const DIR = join(ROOT, "src-tauri", "icons");
const { Resvg } = createRequire(join(process.cwd(), "package.json"))("@resvg/resvg-js");

const render = (svg, size) =>
  new Resvg(svg, { fitTo: { mode: "width", value: size } }).render().asPng();
const app = readFileSync(join(DIR, "app-icon.svg"), "utf8");
const png = (size) => render(app, size);

// Plain PNGs: the size is part of the file name, or listed here.
const fixed = { "icon.png": 512, "StoreLogo.png": 50, "128x128@2x.png": 256 };
for (const f of readdirSync(DIR)) {
  if (!f.endsWith(".png") || f.startsWith("tray")) continue;
  const m = f.match(/^(?:Square)?(\d+)x\d+(?:Logo)?\.png$/);
  const size = fixed[f] ?? (m && +m[1]);
  if (size) writeFileSync(join(DIR, f), png(size));
}

// Windows .ico: PNG-compressed entries.
const icoSizes = [16, 24, 32, 48, 64, 256];
const imgs = icoSizes.map(png);
const head = Buffer.alloc(6 + 16 * imgs.length);
head.writeUInt16LE(1, 2);
head.writeUInt16LE(imgs.length, 4);
let off = head.length;
imgs.forEach((b, i) => {
  const e = 6 + 16 * i, s = icoSizes[i];
  head[e] = s === 256 ? 0 : s;
  head[e + 1] = s === 256 ? 0 : s;
  head.writeUInt16LE(1, e + 4);
  head.writeUInt16LE(32, e + 6);
  head.writeUInt32LE(b.length, e + 8);
  head.writeUInt32LE(off, e + 12);
  off += b.length;
});
writeFileSync(join(DIR, "icon.ico"), Buffer.concat([head, ...imgs]));

// macOS .icns: PNG-compressed entries.
const icnsTypes = [["icp4", 16], ["icp5", 32], ["icp6", 64], ["ic07", 128], ["ic08", 256], ["ic09", 512], ["ic10", 1024]];
const chunks = icnsTypes.map(([t, s]) => {
  const d = png(s), h = Buffer.alloc(8);
  h.write(t, 0, "ascii");
  h.writeUInt32BE(8 + d.length, 4);
  return Buffer.concat([h, d]);
});
const total = 8 + chunks.reduce((n, c) => n + c.length, 0);
const ih = Buffer.alloc(8);
ih.write("icns", 0, "ascii");
ih.writeUInt32BE(total, 4);
writeFileSync(join(DIR, "icon.icns"), Buffer.concat([ih, ...chunks]));

// Tray: colour mark, and the same with a red unread dot (top-right).
writeFileSync(join(DIR, "tray.png"), png(128));
const dot = `<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128" viewBox="0 0 128 128"><image href="data:image/png;base64,${png(128).toString("base64")}" width="128" height="128"/><circle cx="99" cy="29" r="20" fill="#EA4335" stroke="#fff" stroke-width="3"/></svg>`;
writeFileSync(join(DIR, "tray-unread.png"), render(dot, 128));

// macOS menu bar template: a one-colour silhouette (bubble with the Z knocked
// out); AppKit tints it. 36px = 18pt @2x. The unread variant adds a dot.
const silhouette = (badge) => `<svg xmlns="http://www.w3.org/2000/svg" width="36" height="36" viewBox="40 40 432 432">
<mask id="m"><rect x="0" y="0" width="512" height="512" fill="#fff"/><path d="M192 176h128L192 288h128" fill="none" stroke="#000" stroke-width="40" stroke-miterlimit="10"/></mask>
<path mask="url(#m)" fill="#000" d="M148 112h216a56 56 0 0 1 56 56v128a56 56 0 0 1-56 56H236l-72 56v-56h-16a56 56 0 0 1-56-56V168a56 56 0 0 1 56-56z"/>${badge ? '<circle cx="420" cy="92" r="64" fill="#000"/>' : ""}</svg>`;
writeFileSync(join(DIR, "tray-macos-template.png"), render(silhouette(false), 36));
writeFileSync(join(DIR, "tray-macos-template-unread.png"), render(silhouette(true), 36));
console.log("Icons regenerated from app-icon.svg");
