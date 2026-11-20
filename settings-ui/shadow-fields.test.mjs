// Wiring checks for the Shadow storage settings section (batch 7 G1).
// Run: node settings-ui/shadow-fields.test.mjs   (exit non-zero on failure)
//
// main.js needs window.__TAURI__, so it cannot be imported like
// dialog.js/notes.js; like i18n.test.mjs this file therefore checks the
// wiring statically: the section's inputs exist, load() fills them from
// the stored settings object, save() writes exactly those three fields
// back (never replacing the whole `shadow` object, so untouched fields
// keep their stored values), and the folder picker reuses the
// download-dir picker command.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const html = readFileSync(join(here, "index.html"), "utf8");
const mainJs = readFileSync(join(here, "main.js"), "utf8");
const i18nJs = readFileSync(join(here, "i18n.js"), "utf8");

let failures = 0;
function ok(cond, label) {
  if (cond) console.log("  ok  " + label);
  else { failures++; console.error("FAIL  " + label); }
}
const count = (re, s) => (s.match(re) || []).length;

// --- the section and its inputs -------------------------------------------
ok(count(/<section class="group" id="sec-shadow">/g, html) === 1,
  "index.html has exactly one #sec-shadow section");
ok(count(/href="#sec-shadow"/g, html) === 1, "the nav links to #sec-shadow once");
for (const id of ["media_store", "own_uid", "own_uin_hash"]) {
  ok(count(new RegExp(`<input type="text" id="${id}"`, "g"), html) === 1,
    `index.html has the #${id} text input`);
}
ok(count(/id="choose_media_store"/g, html) === 1, "the media-store pick button exists");
ok(html.includes("As alterações desta seção são aplicadas após reiniciar o Zalo."),
  "the section shows the restart note");
// Both languages: every new Portuguese source string has an English
// entry in the EN map (the Vietnamese side is checked by i18n.test.mjs
// through vi.json/vi.js).
for (const pt of [
  "Armazenamento", "Armazenamento shadow", "Pasta de armazenamento de mídia",
  "Onde os arquivos de mídia capturados são gravados. Vazio usa a pasta padrão.",
  "Uid da própria conta",
  "O userId do Zalo desta conta (5 a 32 dígitos). Vazio mantém o aprendido pela sessão.",
  "Hash UIN",
  "sha256 do UIN em 12 caracteres hexadecimais minúsculos. Vazio não grava a linha da conta.",
  "As alterações desta seção são aplicadas após reiniciar o Zalo.",
]) {
  ok(new RegExp(`"${pt.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}":`).test(i18nJs),
    `i18n.js maps the Portuguese source to English: ${pt.slice(0, 40)}…`);
}

// --- load(): the page shows the stored values ------------------------------
for (const [id, field] of [
  ["media_store", "media_store"],
  ["own_uid", "own_uid"],
  ["own_uin_hash", "own_uin_hash"],
]) {
  ok(new RegExp(`getElementById\\("${id}"\\)\\.value = s\\.shadow\\?\\.${field} \\|\\| ""`).test(mainJs),
    `load() fills #${id} from the stored settings`);
}

// --- save(): exactly the three fields, empty text -> null ------------------
ok(/const s = await invoke\("get_settings"\)/.test(mainJs),
  "save() starts from the stored settings object (round-trip base)");
for (const [id, field] of [
  ["media_store", "media_store"],
  ["own_uid", "own_uid"],
  ["own_uin_hash", "own_uin_hash"],
]) {
  ok(new RegExp(`s\\.shadow\\.${field} = document\\.getElementById\\("${id}"\\)\\.value\\.trim\\(\\) \\|\\| null`).test(mainJs),
    `save() writes s.shadow.${field} from #${id}, empty -> null`);
}
ok(!/\bs\.shadow\s*=(?!\.)/.test(mainJs),
  "save() never replaces the whole shadow object (untouched fields survive)");

// --- the folder picker reuses the download-dir picker -----------------------
ok(/async function chooseMediaStore\(\)/.test(mainJs), "chooseMediaStore() exists");
ok(/invoke\("pick_download_dir"\)[\s\S]{0,200}if \(!dir\) return;/.test(mainJs),
  "chooseMediaStore() reuses pick_download_dir and returns on cancel");
ok(/if \(!\(await save\(\)\)\) input\.value = previous;/.test(mainJs),
  "a refused path is rolled back out of the input");
ok(/getElementById\("choose_media_store"\)\.addEventListener\("click", chooseMediaStore\)/.test(mainJs),
  "the pick button is wired");

if (failures) { console.error(`\n${failures} failing assertion(s)`); process.exit(1); }
console.log("\nall shadow-fields tests passed");
