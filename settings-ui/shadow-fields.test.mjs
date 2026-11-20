// Wiring checks for the Shadow storage settings section (batch 7 G1,
// extended by batch 8 H4 with the backup fields).
// Run: node settings-ui/shadow-fields.test.mjs   (exit non-zero on failure)
//
// main.js needs window.__TAURI__, so it cannot be imported like
// dialog.js/notes.js; like i18n.test.mjs this file therefore checks the
// wiring statically: the section's inputs exist, load() fills them from
// the stored settings object, save() writes exactly those fields
// back (never replacing the whole `shadow` object, so untouched fields
// keep their stored values), and the folder pickers reuse the
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
// Batch 8 H4: the backup rows.
ok(count(/<input type="checkbox" class="switch" id="backup_enabled" \/>/g, html) === 1,
  "index.html has the #backup_enabled switch");
for (const id of ["backup_dir", "backup_interval_hours", "disk_warn_pct", "disk_stop_pct"]) {
  ok(count(new RegExp(`<input type="text" id="${id}"`, "g"), html) === 1,
    `index.html has the #${id} text input`);
}
ok(count(/id="choose_backup_dir"/g, html) === 1, "the backup pick button exists");
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
  // batch 8 H4
  "Backup automático do shadow",
  "Copia o banco de dados e os arquivos de mídia para a pasta de backup em intervalos regulares. Mantém 7 backups diários e 4 semanais.",
  "Pasta de backup",
  "Onde o banco de dados e as mídias são copiados. Escolha uma pasta que já exista.",
  "Intervalo de backup (horas)",
  "Horas entre backups; o primeiro roda cerca de 2 minutos após iniciar.",
  "Aviso de espaço em disco (%)",
  "Porcentagem livre na pasta de mídia abaixo da qual um aviso é registrado.",
  "Pausar download de mídia (%)",
  "Abaixo desta porcentagem livre o download de mídia pausa; a captura de texto continua.",
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
ok(/getElementById\("backup_enabled"\)\.checked = !!s\.shadow\?\.backup_enabled/.test(mainJs),
  "load() ticks #backup_enabled from the stored settings");
ok(/getElementById\("backup_dir"\)\.value = s\.shadow\?\.backup_dir \|\| ""/.test(mainJs),
  "load() fills #backup_dir from the stored settings");
for (const [id, field, def] of [
  ["backup_interval_hours", "backup_interval_hours", 6],
  ["disk_warn_pct", "disk_warn_pct", 10],
  ["disk_stop_pct", "disk_stop_pct", 3],
]) {
  ok(new RegExp(`getElementById\\("${id}"\\)\\.value = String\\(s\\.shadow\\?\\.${field} \\?\\? ${def}\\)`).test(mainJs),
    `load() fills #${id} with the stored value or the default ${def}`);
}

// --- save(): exactly the fields, empty text -> null, numbers in range ------
ok(/const s = await invoke\("get_settings"\)/.test(mainJs),
  "save() starts from the stored settings object (round-trip base)");
for (const [id, field] of [
  ["media_store", "media_store"],
  ["own_uid", "own_uid"],
  ["own_uin_hash", "own_uin_hash"],
  ["backup_dir", "backup_dir"],
]) {
  ok(new RegExp(`s\\.shadow\\.${field} = document\\.getElementById\\("${id}"\\)\\.value\\.trim\\(\\) \\|\\| null`).test(mainJs),
    `save() writes s.shadow.${field} from #${id}, empty -> null`);
}
ok(/s\.shadow\.backup_enabled = document\.getElementById\("backup_enabled"\)\.checked/.test(mainJs),
  "save() writes s.shadow.backup_enabled from the switch");
ok(/function intField\(id, fallback, min, max\) \{/.test(mainJs),
  "intField() bounds the numeric fields");
for (const [field, id, def, min, max] of [
  ["backup_interval_hours", "backup_interval_hours", 6, 1, 168],
  ["disk_warn_pct", "disk_warn_pct", 10, 0, 100],
  ["disk_stop_pct", "disk_stop_pct", 3, 0, 100],
]) {
  ok(new RegExp(`s\\.shadow\\.${field} = intField\\("${id}", ${def}, ${min}, ${max}\\)`).test(mainJs),
    `save() writes s.shadow.${field} through intField (default ${def})`);
}
ok(!/\bs\.shadow\s*=(?!\.)/.test(mainJs),
  "save() never replaces the whole shadow object (untouched fields survive)");

// --- the folder pickers reuse the download-dir picker -----------------------
ok(/async function chooseMediaStore\(\)/.test(mainJs), "chooseMediaStore() exists");
ok(/async function chooseBackupDir\(\)/.test(mainJs), "chooseBackupDir() exists");
ok(count(/invoke\("pick_download_dir"\)/g, mainJs) === 3,
  "both shadow pickers reuse pick_download_dir");
ok(/invoke\("pick_download_dir"\)[\s\S]{0,200}if \(!dir\) return;/.test(mainJs),
  "chooseMediaStore() reuses pick_download_dir and returns on cancel");
ok(/if \(!\(await save\(\)\)\) input\.value = previous;/.test(mainJs),
  "a refused path is rolled back out of the input");
ok(/getElementById\("choose_media_store"\)\.addEventListener\("click", chooseMediaStore\)/.test(mainJs),
  "the media pick button is wired");
ok(/getElementById\("choose_backup_dir"\)\.addEventListener\("click", chooseBackupDir\)/.test(mainJs),
  "the backup pick button is wired");

if (failures) { console.error(`\n${failures} failing assertion(s)`); process.exit(1); }
console.log("\nall shadow-fields tests passed");
