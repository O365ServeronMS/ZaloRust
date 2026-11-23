// Run: node settings-ui/archive.test.mjs
// Batch 11 (audit §4 Phase 3 item 3.2): the Lưu trữ renderer —
// conversation/message/search-hit rows with FAKE data, attachment
// states, recalled/deleted flags, the media URL builder, the search
// debounce, and the no-innerHTML guarantee.
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import assert from "node:assert/strict";

const require = createRequire(import.meta.url);
require("./vi.js"); // defines globalThis.WR_VI before i18n.js reads it
require("./i18n.js"); // defines globalThis.t (PT source -> EN -> VI)
const A = require("./archive.js");
const t = globalThis.t;

let failures = 0;
function check(name, fn) {
  try { fn(); console.log("  ok  " + name); }
  catch (e) { failures++; console.log("  FAIL " + name + "\n       " + e.message.split("\n").join("\n       ")); }
}

// A DOM that only offers createElement/createTextNode/textContent: the
// renderer builds rows exclusively from these, so any innerHTML path
// (which the fake does not have) would throw here.
function fakeDoc() {
  const mk = (tag) => ({
    tag, children: [], _text: "", dataset: {}, type: "",
    get firstChild() { return this.children[0] || null; },
    appendChild(c) { this.children.push(c); return c; },
    set textContent(v) { this._text = String(v); this.children = []; },
    get textContent() { return this._text + this.children.map((c) => c.textContent ?? c.data ?? "").join(""); },
  });
  return { createElement: mk, createTextNode: (data) => ({ data, textContent: data }) };
}
const tags = (el, acc = new Set()) => { for (const c of el.children) if (c.tag) { acc.add(c.tag); tags(c, acc); } return acc; };
const find = (el, tag, out = []) => { for (const c of el.children) { if (c.tag === tag) out.push(c); find(c, tag, out); } return out; };

// --- the media URL: ids only, never a path -------------------------------

check("media URLs are ids-only and follow the injected scheme base", () => {
  globalThis.__ZR_ARCHIVE_MEDIA__ = "http://zrarchive.localhost";
  assert.equal(A.mediaUrl("m1", 0), "http://zrarchive.localhost/media/m1/0");
  assert.equal(A.mediaUrl("8506747288934", 2), "http://zrarchive.localhost/media/8506747288934/2");
  // Anything odd in an id is percent-encoded — it can never smuggle a path.
  assert.equal(A.mediaUrl("a b/c", 1), "http://zrarchive.localhost/media/a%20b%2Fc/1");
  // Dots are not percent-encoded — the URL can still be built, but the
  // Rust parser (parse_media_uri) refuses non-alphanumeric ids, so this
  // never reaches a file: the DB row is the only path source.
  assert.equal(A.mediaUrl("..", 0), "http://zrarchive.localhost/media/../0");
  delete globalThis.__ZR_ARCHIVE_MEDIA__;
  assert.equal(A.mediaUrl("m1", 3), "zrarchive://localhost/media/m1/3", "default base on macOS/Linux");
});

check("media URLs take only the three known variants as ?v=", () => {
  globalThis.__ZR_ARCHIVE_MEDIA__ = "http://zrarchive.localhost";
  assert.equal(A.mediaUrl("m1", 0, "thumb"), "http://zrarchive.localhost/media/m1/0?v=thumb");
  assert.equal(A.mediaUrl("m1", 0, "view"), "http://zrarchive.localhost/media/m1/0?v=view");
  assert.equal(A.mediaUrl("m1", 2, "orig"), "http://zrarchive.localhost/media/m1/2?v=orig");
  // No variant, or anything else: no query at all (never a value the
  // server refuses, never an injected parameter).
  for (const bad of [undefined, null, "", "full", "THUMB", "thumb&v=view", "__proto__", "toString", 7, {}]) {
    assert.equal(A.mediaUrl("m1", 0, bad), "http://zrarchive.localhost/media/m1/0", String(bad));
  }
  delete globalThis.__ZR_ARCHIVE_MEDIA__;
});

check("the bubble rule: thumb up to a 150% display, view on denser ones", () => {
  // .att-media is <= 320 CSS px wide: 320 x dpr <= 480 -> thumb.
  assert.equal(A.imageVariant(1), "thumb");
  assert.equal(A.imageVariant(1.25), "thumb");
  assert.equal(A.imageVariant(1.5), "thumb");
  assert.equal(A.imageVariant(1.75), "view");
  assert.equal(A.imageVariant(2), "view");
  assert.equal(A.imageVariant(3), "view");
  // A missing / invalid ratio counts as 1.
  for (const bad of [undefined, null, 0, -1, NaN, "x"]) assert.equal(A.imageVariant(bad), "thumb", String(bad));
});

check("an image in a bubble asks for ?v=view on a dense display, a video never gets a variant", () => {
  globalThis.__ZR_ARCHIVE_MEDIA__ = "http://zrarchive.localhost";
  const doc = fakeDoc();
  globalThis.devicePixelRatio = 2;
  try {
    const img = find(A.renderAttachment(doc, "m1", { idx: 0, kind: "image", status: "downloaded", has_local: true }), "img")[0];
    assert.equal(img.src, "http://zrarchive.localhost/media/m1/0?v=view");
    const vid = find(A.renderAttachment(doc, "m1", { idx: 1, kind: "video", status: "downloaded", has_local: true }), "video")[0];
    assert.equal(vid.src, "http://zrarchive.localhost/media/m1/1", "video rows are unchanged");
  } finally {
    delete globalThis.devicePixelRatio;
    delete globalThis.__ZR_ARCHIVE_MEDIA__;
  }
});

// --- conversation rows ----------------------------------------------------

check("a conversation row shows the name and the preview through textContent", () => {
  const doc = fakeDoc();
  const row = A.renderConversation(doc, { id: "c9", type: 0, name: "Bạn Hoa", last_ts: 123, last_msg_preview: "Hẹn gặp lại bạn nhé" });
  assert.equal(row.tag, "button");
  assert.equal(row.className, "conv-row");
  assert.equal(row.dataset.convId, "c9");
  assert.deepEqual(row.children.map((c) => c.className), ["conv-name", "conv-preview"]);
  assert.equal(row.children[0].textContent, "Bạn Hoa");
  assert.equal(row.children[1].textContent, "Hẹn gặp lại bạn nhé");
});

check("a conversation without a name or preview falls back honestly", () => {
  const doc = fakeDoc();
  const row = A.renderConversation(doc, { id: "c7", type: 1, last_ts: null, last_msg_preview: null });
  assert.equal(row.children[0].textContent, "c7", "the id when no name is stored");
  assert.equal(row.children[1].textContent, "", "no preview renders empty, never 'undefined'");
});

// --- message rows + attachment states --------------------------------------

check("a message row renders sender, time, text and every attachment state", () => {
  globalThis.__ZR_ARCHIVE_MEDIA__ = "http://zrarchive.localhost";
  const doc = fakeDoc();
  const today = Date.now();
  const msg = {
    msg_id: "m1", sender_id: "u1", sender_name: "Bạn Mai", ts: today, type: 1,
    text: "Chào bạn, mình gửi ảnh đây", deleted: false, rev: 0,
    attachments: [
      { idx: 0, kind: "image", status: "downloaded", has_local: true },
      { idx: 1, kind: "video", status: "downloaded", has_local: true },
      { idx: 2, kind: "file", status: "downloaded", has_local: true },
      { idx: 3, kind: "image", status: "ref", has_local: false },
      { idx: 4, kind: "image", status: "failed", has_local: false },
      { idx: 5, kind: "voice", status: "ref-encrypted", has_local: false },
    ],
  };
  const item = A.renderMessage(doc, msg);
  assert.equal(item.className, "msg");
  assert.equal(item.dataset.msgId, "m1");
  assert.deepEqual([...tags(item)].sort(), ["div", "img", "span", "video"]);
  const [head, body] = item.children;
  assert.equal(head.className, "msg-head");
  assert.equal(head.children[0].textContent, "Bạn Mai");
  assert.match(head.children[1].textContent, /:/, "a time is always shown");
  assert.equal(body.children[0].className, "msg-text");
  assert.equal(body.children[0].textContent, "Chào bạn, mình gửi ảnh đây");
  // downloaded image + video go through the media scheme, ids only
  const img = find(item, "img")[0];
  // Batch 28: an image in a bubble asks for a derivative (dpr 1 -> thumb).
  assert.equal(img.src, "http://zrarchive.localhost/media/m1/0?v=thumb");
  assert.equal(img.loading, "lazy");
  const vid = find(item, "video")[0];
  assert.equal(vid.src, "http://zrarchive.localhost/media/m1/1");
  assert.equal(vid.controls, true);
  // a downloaded file is a label, not media
  const label = find(item, "span").find((s) => s.className === "att-label");
  assert.equal(label.textContent, "Tệp đính kèm · file");
  // non-downloaded media shows its status label (VI through the shared table)
  const missing = find(item, "span").filter((s) => s.className === "att-missing").map((s) => s.textContent);
  assert.deepEqual(missing, [
    "Media chưa tải xuống (ref)",
    "Media chưa tải xuống (failed)",
    "Media chưa tải xuống (ref-encrypted)",
  ]);
  delete globalThis.__ZR_ARCHIVE_MEDIA__;
});

check("a message without a sender shows the unknown label, never null", () => {
  const doc = fakeDoc();
  const item = A.renderMessage(doc, { msg_id: "m2", sender_id: null, sender_name: null, ts: 99, type: 1, text: "alo", deleted: false, rev: 0, attachments: [] });
  assert.equal(item.children[0].children[0].textContent, "Không rõ");
  // sender_id present but no contact name: the id itself.
  const item2 = A.renderMessage(doc, { msg_id: "m3", sender_id: "u77", sender_name: null, ts: 99, type: 1, text: "alo", deleted: false, rev: 0, attachments: [] });
  assert.equal(item2.children[0].children[0].textContent, "u77");
});

check("recalled and deleted messages render greyed with their label", () => {
  const doc = fakeDoc();
  // A recall (msgType chat.delete, code 8): greyed + the recall label.
  const recalled = A.renderMessage(doc, { msg_id: "r1", sender_id: "u1", ts: 50, type: 8, text: null, deleted: true, rev: 2, attachments: [] });
  assert.match(recalled.className, /(^| )gone( |$)/);
  const gone = find(recalled, "span").find((s) => s.className === "msg-gone") || find(recalled, "div").find((s) => s.className === "msg-gone");
  assert.equal(gone.textContent, "Tin nhắn đã thu hồi");
  // A deleted (non-recall) message: the deleted label.
  const deleted = A.renderMessage(doc, { msg_id: "d1", sender_id: "u1", ts: 51, type: 1, text: "text cũ", deleted: true, rev: 0, attachments: [] });
  assert.match(deleted.className, /gone/);
  const gone2 = find(deleted, "div").find((s) => s.className === "msg-gone");
  assert.equal(gone2.textContent, "Tin nhắn đã bị xoá");
  // And a plain message is not greyed.
  const plain = A.renderMessage(doc, { msg_id: "p1", sender_id: "u1", ts: 52, type: 1, text: "bình thường", deleted: false, rev: 0, attachments: [] });
  assert.doesNotMatch(plain.className, /gone/);
  assert.equal(A.isGone({ deleted: false, type: 1 }), false);
  assert.equal(A.isGone({ deleted: false, type: 8 }), true);
  assert.equal(A.isGone({ deleted: true, type: 1 }), true);
  assert.equal(A.isRecalled({ type: 8 }), true);
  assert.equal(A.isRecalled({ type: 1 }), false);
});

// --- search hits ----------------------------------------------------------

check("a search hit shows the conversation, the matching text and the time", () => {
  const doc = fakeDoc();
  const hit = A.renderSearchHit(doc, { conv_id: "g1", conv_name: "Nhóm lớp học", msg_id: "m5", ts: 1731987201000, type: 1, text: "Hà Nội hôm nay mưa" });
  assert.equal(hit.tag, "button");
  assert.equal(hit.dataset.convId, "g1");
  assert.equal(hit.dataset.msgId, "m5");
  assert.equal(hit.children[0].textContent, "Nhóm lớp học");
  assert.equal(hit.children[1].textContent, "Hà Nội hôm nay mưa");
  assert.equal(hit.children[2].textContent, A.fmtTs(1731987201000));
  // No stored conversation name: the id.
  const bare = A.renderSearchHit(doc, { conv_id: "zz", conv_name: null, msg_id: "m6", ts: 5, type: 1, text: "" });
  assert.equal(bare.children[0].textContent, "zz");
  assert.equal(bare.children[1].textContent, "");
});

// --- the debounce -----------------------------------------------------------

check("the search debounce fires once per burst, with the last query", async () => {
  const calls = [];
  const d = A.makeDebounce((q) => calls.push(q), 20);
  d("h"); d("hà"); d("hà nội");
  assert.deepEqual(calls, [], "nothing fires inside the burst");
  await new Promise((r) => setTimeout(r, 60));
  assert.deepEqual(calls, ["hà nội"], "one trailing call with the last query");
  d("x");
  await new Promise((r) => setTimeout(r, 60));
  assert.deepEqual(calls, ["hà nội", "x"], "the next burst fires again");
});

// --- safety: never innerHTML -------------------------------------------------

check("the renderer source never mentions innerHTML and friends", () => {
  const src = readFileSync(new URL("archive.js", import.meta.url), "utf8");
  for (const forbidden of ["innerHTML", "insertAdjacentHTML", "outerHTML", "document.write", "srcdoc", "eval("]) {
    assert.ok(!src.includes(forbidden), `archive.js must never use ${forbidden}`);
  }
});

check("rendered rows only ever contain the expected element names", () => {
  const doc = fakeDoc();
  const item = A.renderMessage(doc, {
    msg_id: "m1", sender_id: "u1", ts: 1, type: 2, text: "ảnh nè", deleted: false, rev: 0,
    attachments: [
      { idx: 0, kind: "image", status: "downloaded", has_local: true },
      { idx: 1, kind: "image", status: "ref", has_local: false },
    ],
  });
  assert.deepEqual([...tags(item)].sort(), ["div", "img", "span"]);
  const conv = A.renderConversation(doc, { id: "c1", name: "x", last_msg_preview: "y" });
  assert.deepEqual([...tags(conv)], ["span"]);
  const hit = A.renderSearchHit(doc, { conv_id: "c1", msg_id: "m", ts: 1, text: "z" });
  assert.deepEqual([...tags(hit)], ["span"]);
});

// --- i18n through the shared tables ----------------------------------------

check("the archive labels translate through the shared vi tables", () => {
  assert.equal(t("Mensagem desfeita"), "Tin nhắn đã thu hồi");
  assert.equal(t("Mensagem excluída"), "Tin nhắn đã bị xoá");
  assert.equal(t("Mídia não baixada ({0})", ["failed"]), "Media chưa tải xuống (failed)");
  assert.equal(t("Abrir o armazenamento"), "Mở Lưu trữ");
  assert.equal(t("Conversas: {0}", [7]), "Cuộc trò chuyện: 7");
});

// --- time formatting ----------------------------------------------------------

check("fmtTs shows a time for today and a date otherwise", () => {
  assert.equal(A.fmtTs(0), "");
  const now = A.fmtTs(Date.now());
  assert.match(now, /:/);
  const old = A.fmtTs(Date.UTC(2020, 0, 2, 3, 4));
  assert.ok(old.length > now.length, "an older message carries its date: " + old);
});

if (failures) { console.log(`\n${failures} archive test(s) failed`); process.exit(1); }
console.log("\nall archive tests passed");
