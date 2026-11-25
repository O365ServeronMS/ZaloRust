// Run: node settings-ui/archive.test.mjs
// Batch 11 (audit §4 Phase 3 item 3.2), extended in batch 29b: the
// Lưu trữ renderer and its pure helpers with FAKE data — relative and
// day times, message grouping, bubbles, file/link/quote cards, the
// info panel, the storage view, the media URL builder, the search
// debounce and the no-HTML-parsing guarantee.
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import assert from "node:assert/strict";

const require = createRequire(import.meta.url);
require("./vi.js"); // defines globalThis.WR_VI before i18n.js reads it
require("./i18n.js"); // defines globalThis.t (PT source -> EN -> VI)
const A = require("./archive.js");
const t = globalThis.t;

let failures = 0;
const pending = [];
function check(name, fn) {
  try {
    const r = fn();
    if (r && typeof r.then === "function") {
      pending.push(r.then(() => console.log("  ok  " + name), (e) => { failures++; console.log("  FAIL " + name + "\n       " + e.message); }));
      return;
    }
    console.log("  ok  " + name);
  } catch (e) { failures++; console.log("  FAIL " + name + "\n       " + e.message.split("\n").join("\n       ")); }
}

// A DOM that only offers createElement/createElementNS/createTextNode/
// setAttribute/textContent: the renderer builds everything from these,
// so any innerHTML path (which the fake does not have) would throw here.
function fakeDoc() {
  const mk = (tag) => ({
    tag, children: [], _text: "", dataset: {}, type: "", attrs: {}, className: "",
    get firstChild() { return this.children[0] || null; },
    appendChild(c) { this.children.push(c); return c; },
    setAttribute(k, v) { this.attrs[k] = String(v); },
    getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; },
    set textContent(v) { this._text = String(v); this.children = []; },
    get textContent() { return this._text + this.children.map((c) => c.textContent ?? c.data ?? "").join(""); },
  });
  return { createElement: mk, createElementNS: (_ns, tag) => mk(tag), createTextNode: (data) => ({ data, textContent: data, nodeType: 3 }) };
}
const tags = (el, acc = new Set()) => { for (const c of el.children) if (c.tag) { acc.add(c.tag); tags(c, acc); } return acc; };
const find = (el, tag, out = []) => { for (const c of el.children) { if (c.tag === tag) out.push(c); find(c, tag, out); } return out; };
const byClass = (el, cls, out = []) => {
  for (const c of el.children) {
    if (c.className && String(c.className).split(" ").includes(cls)) out.push(c);
    if (c.children) byClass(c, cls, out);
  }
  return out;
};
const has = (el, cls) => byClass(el, cls).length > 0;
const local = (y, mo, d, h = 0, mi = 0) => new Date(y, mo - 1, d, h, mi).getTime();

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
  for (const bad of [undefined, null, "", "full", "THUMB", "thumb&v=view", "__proto__", "toString", 7, {}]) {
    assert.equal(A.mediaUrl("m1", 0, bad), "http://zrarchive.localhost/media/m1/0", String(bad));
  }
  delete globalThis.__ZR_ARCHIVE_MEDIA__;
});

check("the thumbnail rule: thumb up to a 200% display, view on denser ones", () => {
  // .att-img boxes are <= 240 CSS px wide: 240 x dpr <= 480 -> thumb.
  for (const d of [1, 1.25, 1.5, 2]) assert.equal(A.imageVariant(d), "thumb", String(d));
  for (const d of [2.25, 3]) assert.equal(A.imageVariant(d), "view", String(d));
  for (const bad of [undefined, null, 0, -1, NaN, "x"]) assert.equal(A.imageVariant(bad), "thumb", String(bad));
});

// --- time helpers ---------------------------------------------------------

check("relative time: now, minutes, hours, days, then dd/MM/yy", () => {
  const now = local(2026, 11, 25, 12, 0);
  assert.equal(A.relTime(now - 20 * 1000, now), "Vừa xong");
  assert.equal(A.relTime(now - 4 * 60000, now), "4 phút");
  assert.equal(A.relTime(now - 59 * 60000, now), "59 phút");
  assert.equal(A.relTime(now - 60 * 60000, now), "1 giờ");
  assert.equal(A.relTime(now - 2 * 3600000 - 5 * 60000, now), "2 giờ");
  assert.equal(A.relTime(now - 23 * 3600000, now), "23 giờ");
  assert.equal(A.relTime(now - 24 * 3600000, now), "1 ngày");
  assert.equal(A.relTime(now - 7 * 86400000, now), "7 ngày");
  assert.equal(A.relTime(local(2026, 11, 17, 11, 0), now), "17/11/26", "older than a week: dd/MM/yy");
  assert.equal(A.relTime(0, now), "");
  assert.equal(A.relTime(now + 5000, now), "Vừa xong", "a clock skew into the future is not negative");
});

check("day separator labels: today, yesterday, a date", () => {
  const now = local(2026, 11, 25, 9, 30);
  assert.equal(A.dayLabel(local(2026, 11, 25, 0, 1), now), "Hôm nay");
  assert.equal(A.dayLabel(local(2026, 11, 24, 23, 59), now), "Hôm qua");
  assert.equal(A.dayLabel(local(2026, 11, 23, 12, 0), now), "23/11/2026");
  assert.equal(A.dayLabel(local(2025, 1, 5, 12, 0), now), "05/01/2025");
  assert.equal(A.fmtHM(local(2026, 11, 25, 7, 5)), "07:05");
  assert.equal(A.fmtDate(local(2026, 11, 3, 1, 0), false), "03/11/26");
  assert.equal(A.fmtDate(local(2026, 11, 3, 1, 0), true), "03/11/2026");
});

check("day labels count calendar days across a 23 h and a 25 h DST day", () => {
  const before = process.env.TZ;
  process.env.TZ = "Europe/Berlin";
  try {
    // 2026-03-29 is 23 hours long, 2026-10-25 is 25 hours long.
    const nowSpring = local(2026, 3, 29, 23, 30);
    assert.equal(A.dayLabel(local(2026, 3, 28, 23, 45), nowSpring), "Hôm qua");
    assert.equal(A.dayLabel(local(2026, 3, 27, 23, 45), nowSpring), "27/03/2026");
    const nowFall = local(2026, 10, 25, 23, 50);
    assert.equal(A.dayLabel(local(2026, 10, 25, 0, 10), nowFall), "Hôm nay");
    assert.equal(A.dayLabel(local(2026, 10, 24, 0, 10), nowFall), "Hôm qua");
    assert.equal(A.dayLabel(local(2026, 10, 23, 23, 59), nowFall), "23/10/2026");
    assert.equal(A.dayKey(local(2026, 3, 29, 12, 0)) - A.dayKey(local(2026, 3, 28, 12, 0)), 1);
    assert.equal(A.dayKey(local(2026, 10, 26, 0, 5)) - A.dayKey(local(2026, 10, 25, 0, 5)), 1);
  } finally {
    if (before === undefined) delete process.env.TZ; else process.env.TZ = before;
  }
});

check("sizes: bytes, KB and MB with one decimal; empty when unknown", () => {
  assert.equal(A.fmtSize(512), "512 B");
  assert.equal(A.fmtSize(1536), "1.5 KB");
  assert.equal(A.fmtSize(402_770), "393.3 KB");
  assert.equal(A.fmtSize(5 * 1048576), "5.0 MB");
  assert.equal(A.fmtSize(1073741824 * 2), "2.0 GB");
  for (const bad of [null, undefined, -1, NaN, "x"]) assert.equal(A.fmtSize(bad), "", String(bad));
});

check("extension -> colour class and label", () => {
  assert.equal(A.extClass("pdf"), "ext-pdf");
  assert.equal(A.extClass("PDF"), "ext-pdf");
  assert.equal(A.extClass("doc"), "ext-doc");
  assert.equal(A.extClass("docx"), "ext-doc");
  assert.equal(A.extClass("xls"), "ext-xls");
  assert.equal(A.extClass("xlsx"), "ext-xls");
  assert.equal(A.extClass("pptx"), "ext-ppt");
  assert.equal(A.extClass("zip"), "ext-zip");
  assert.equal(A.extClass("7z"), "ext-zip");
  for (const other of ["png", "txt", "", null, undefined, "__proto__", "constructor"]) assert.equal(A.extClass(other), "ext-other", String(other));
  assert.equal(A.extLabel("docx"), "DOCX");
  assert.equal(A.extLabel("torrent"), "TORR");
  assert.equal(A.extLabel(""), "FILE");
});

// --- reactions --------------------------------------------------------------

check("reactions: up to 3 glyphs, the total count, an unknown code shows a dot", () => {
  const rs = A.reactionSummary([
    { code: "/-strong", emoji: "👍", count: 3 },
    { code: ":>", emoji: "😆", count: 2 },
    { code: "???", emoji: null, count: 1 },
    { code: ":o", emoji: "😮", count: 1 },
  ]);
  assert.deepEqual(rs.glyphs, ["👍", "😆", "•"], "at most three glyphs, most used first");
  assert.equal(rs.total, 7);
  assert.deepEqual(A.reactionSummary([]), { glyphs: [], total: 0 });
  assert.deepEqual(A.reactionSummary(undefined), { glyphs: [], total: 0 });
  assert.deepEqual(A.reactionSummary([{ code: "a", emoji: "👍", count: 0 }]), { glyphs: [], total: 0 });
  assert.equal(A.reactionGlyph({ code: "x", emoji: null, count: 1 }), "•");
  assert.equal(A.reactionGlyph({ code: "x", emoji: "", count: 1 }), "•");
  assert.equal(A.reactionGlyph({ code: "x", emoji: "👍", count: 1 }), "👍");
  // Two codes with the same emoji count once in the glyph list.
  assert.deepEqual(A.reactionSummary([{ code: "a", emoji: "🙏", count: 2 }, { code: "b", emoji: "🙏", count: 1 }]).glyphs, ["🙏"]);
});

// --- the left column: previews and rows ----------------------------------------

check("preview prefix: Bạn, the sender in a group, kind labels", () => {
  const base = { id: "c", is_group: false, last_sender_is_self: false, last_sender_name: null, last_kind: 1, last_msg_preview: "xin chào" };
  assert.equal(A.previewText(base), "xin chào");
  assert.equal(A.previewText({ ...base, last_sender_is_self: true }), "Bạn: xin chào");
  assert.equal(A.previewText({ ...base, is_group: true, last_sender_name: "Lan" }), "Lan: xin chào");
  assert.equal(A.previewText({ ...base, is_group: true, last_sender_is_self: true }), "Bạn: xin chào");
  assert.equal(A.previewText({ ...base, is_group: false, last_sender_name: "Lan" }), "xin chào", "a private chat shows no sender");
  assert.equal(A.previewText({ ...base, is_group: true, last_sender_name: null }), "xin chào");
  // Rust's label for a text-less message becomes Zalo's.
  const kinds = [[2, "[ảnh]", "[Hình ảnh]"], [4, "[file]", "[File]"], [6, "[video]", "[Video]"], [7, "[liên kết]", "[Link]"], [3, "[sticker]", "[Sticker]"], [11, "[gif]", "[Sticker]"], [8, "[đã thu hồi]", "Tin nhắn đã được thu hồi"], [12, "[doodle]", "[Tin nhắn không hỗ trợ]"]];
  for (const [kind, rust, ui] of kinds) {
    assert.equal(A.previewText({ ...base, last_kind: kind, last_msg_preview: rust, last_sender_is_self: true }), "Bạn: " + ui, rust);
  }
  // A caption on an image is real text and stays.
  assert.equal(A.previewText({ ...base, last_kind: 2, last_msg_preview: "ảnh đẹp" }), "ảnh đẹp");
  // A system line has no sender prefix, even from self.
  assert.equal(A.previewText({ ...base, last_kind: 10, last_msg_preview: "Bạn đã thêm Lan vào nhóm", last_sender_is_self: true }), "Bạn đã thêm Lan vào nhóm");
  assert.equal(A.previewText({ ...base, last_msg_preview: null }), "");
});

check("a conversation row: avatar, name, relative time, preview, active state", () => {
  const doc = fakeDoc();
  const now = local(2026, 11, 25, 12, 0);
  const row = A.renderConversation(doc, { id: "c9", is_group: false, name: "Bạn Hoa", initials: "BH", color_idx: 3, last_ts: now - 4 * 60000, last_msg_preview: "Hẹn gặp lại bạn nhé", last_kind: 1, last_sender_is_self: true }, { now });
  assert.equal(row.tag, "button");
  assert.equal(row.className, "conv-row");
  assert.equal(row.dataset.convId, "c9");
  assert.equal(row.dataset.group, "0");
  assert.equal(byClass(row, "avatar")[0].textContent, "BH");
  assert.equal(byClass(row, "avatar")[0].className, "avatar av-c3");
  assert.equal(byClass(row, "conv-name")[0].textContent, "Bạn Hoa");
  assert.equal(byClass(row, "conv-time")[0].textContent, "4 phút");
  assert.equal(byClass(row, "conv-preview")[0].textContent, "Bạn: Hẹn gặp lại bạn nhé");
  assert.ok(!has(row, "av-badge"), "no member badge on a private chat");
  const active = A.renderConversation(doc, { id: "c9", name: "x", initials: "X", color_idx: 0 }, { active: true });
  assert.equal(active.className, "conv-row active");
});

check("a group row shows the member-count badge; no count -> no badge; no name -> the id", () => {
  const doc = fakeDoc();
  const g = A.renderConversation(doc, { id: "g1", is_group: true, name: "Lớp 12A", initials: "L1", color_idx: 1, member_count: 25, last_ts: 5, last_msg_preview: "ok", last_kind: 1, last_sender_name: "Lan" });
  assert.equal(g.dataset.group, "1");
  assert.equal(byClass(g, "av-badge")[0].textContent, "25");
  assert.equal(byClass(g, "conv-preview")[0].textContent, "Lan: ok");
  const nogroup = A.renderConversation(doc, { id: "g2", is_group: true, name: "", initials: "", color_idx: 0, member_count: null, last_ts: null, last_msg_preview: null });
  assert.ok(!has(nogroup, "av-badge"));
  assert.equal(byClass(nogroup, "conv-name")[0].textContent, "g2", "the id when no name is stored");
  assert.equal(byClass(nogroup, "conv-preview")[0].textContent, "", "no preview renders empty, never 'undefined'");
  assert.equal(byClass(nogroup, "conv-time")[0].textContent, "");
  assert.equal(byClass(nogroup, "avatar")[0].textContent, "?");
});

// --- grouping + separators --------------------------------------------------------

const msg = (id, ts, over = {}) => ({ msg_id: id, sender_id: "u1", sender_name: "Mai", sender_initials: "M", sender_color: 2, ts, type: 1, text: "t" + id, deleted: false, rev: 0, attachments: [], is_self: false, reactions: [], quote: null, link: null, raw_type: null, ...over });

check("grouping: same sender within 5 minutes shares one group; time and avatar on the last bubble", () => {
  const now = local(2026, 11, 25, 12, 0);
  const d = local(2026, 11, 25, 10, 0);
  const l = A.layoutMessages([msg("a", d), msg("b", d + 60000), msg("c", d + 120000)], now, true);
  assert.deepEqual(l.map((e) => e.kind), ["pill", "msg", "msg", "msg"]);
  assert.deepEqual(l.slice(1).map((e) => e.showSender), [true, false, false], "sender name once, on top");
  assert.deepEqual(l.slice(1).map((e) => e.showTime), [false, false, true], "time only on the last bubble");
  assert.deepEqual(l.slice(1).map((e) => e.showAvatar), [false, false, true], "avatar once, at the bottom");
});

check("grouping: a different sender, a gap over 5 minutes and a day change each start a new group", () => {
  const now = local(2026, 11, 25, 12, 0);
  const d = local(2026, 11, 25, 10, 0);
  // different sender
  let l = A.layoutMessages([msg("a", d), msg("b", d + 1000, { sender_id: "u2", sender_name: "Lan" })], now, true).filter((e) => e.kind === "msg");
  assert.deepEqual(l.map((e) => [e.showSender, e.showTime, e.showAvatar]), [[true, true, true], [true, true, true]]);
  // exactly 5 minutes is already a new group; just under is the same one
  l = A.layoutMessages([msg("a", d), msg("b", d + 5 * 60000)], now, true).filter((e) => e.kind === "msg");
  assert.deepEqual(l.map((e) => e.showTime), [true, true]);
  l = A.layoutMessages([msg("a", d), msg("b", d + 5 * 60000 - 1)], now, true).filter((e) => e.kind === "msg");
  assert.deepEqual(l.map((e) => e.showTime), [false, true]);
  // across midnight
  l = A.layoutMessages([msg("a", local(2026, 11, 24, 23, 59)), msg("b", local(2026, 11, 25, 0, 1))], now, true);
  assert.deepEqual(l.map((e) => e.kind), ["pill", "msg", "pill", "msg"]);
  assert.deepEqual([l[0].text, l[2].text], ["Hôm qua", "Hôm nay"]);
  assert.deepEqual([l[1].showTime, l[3].showTime], [true, true]);
  // mine never shows a sender name or an avatar; private chats never show the name
  l = A.layoutMessages([msg("a", d, { is_self: true }), msg("b", d + 1000, { is_self: true })], now, true).filter((e) => e.kind === "msg");
  assert.deepEqual(l.map((e) => [e.showSender, e.showAvatar, e.showTime]), [[false, false, false], [false, false, true]]);
  l = A.layoutMessages([msg("a", d)], now, false).filter((e) => e.kind === "msg");
  assert.equal(l[0].showSender, false);
});

check("separators: a day pill first, an HH:mm pill after a gap over an hour", () => {
  const now = local(2026, 11, 25, 18, 0);
  const l = A.layoutMessages([msg("a", local(2026, 11, 25, 9, 0)), msg("b", local(2026, 11, 25, 9, 59)), msg("c", local(2026, 11, 25, 10, 59)), msg("d", local(2026, 11, 25, 12, 0))], now, false);
  assert.deepEqual(l.filter((e) => e.kind === "pill").map((e) => e.text), ["Hôm nay", "12:00"], "59 min and exactly 1 h are no gap; 61 min is");
  assert.deepEqual(A.layoutMessages([], now, false), []);
});

check("a system line is never grouped and breaks the group around it", () => {
  const now = local(2026, 11, 25, 12, 0);
  const d = local(2026, 11, 25, 10, 0);
  const l = A.layoutMessages([msg("a", d), msg("s", d + 1000, { type: 10, text: "Bạn đã thêm Lan vào nhóm" }), msg("b", d + 2000)], now, true);
  assert.deepEqual(l.map((e) => e.kind), ["pill", "msg", "sys", "msg"]);
  assert.deepEqual([l[1].showTime, l[3].showSender], [true, true]);
});

// --- message rendering ----------------------------------------------------------------

check("mine vs others' bubbles: classes, avatar, sender and time follow the layout", () => {
  const doc = fakeDoc();
  const others = A.renderMessage(doc, msg("m1", local(2026, 11, 25, 9, 5)), { showSender: true, showAvatar: true, showTime: true });
  assert.equal(others.className, "msg msg-row theirs");
  assert.equal(others.dataset.msgId, "m1");
  assert.equal(byClass(others, "msg-sender")[0].textContent, "Mai");
  assert.equal(byClass(others, "avatar")[0].textContent, "M");
  assert.equal(byClass(others, "bubble-time")[0].textContent, "09:05");
  assert.equal(byClass(others, "msg-text")[0].textContent, "tm1");
  const mine = A.renderMessage(doc, msg("m2", local(2026, 11, 25, 9, 6), { is_self: true }), { showSender: true, showAvatar: true, showTime: true });
  assert.equal(mine.className, "msg msg-row mine");
  assert.ok(!has(mine, "msg-sender"), "mine never shows a sender name");
  assert.ok(!has(mine, "avatar") && !has(mine, "msg-av"), "mine has no avatar slot");
  // A middle bubble of a group: no time; the avatar slot stays so bubbles align.
  const mid = A.renderMessage(doc, msg("m3", local(2026, 11, 25, 9, 7)), { showSender: false, showAvatar: false, showTime: false });
  assert.ok(!has(mid, "bubble-time") && !has(mid, "avatar") && !has(mid, "msg-sender"));
  assert.ok(has(mid, "msg-av"), "the avatar column is kept");
  // Default options: time and avatar on, name off.
  const dflt = A.renderMessage(doc, msg("m4", 1000));
  assert.ok(has(dflt, "bubble-time") && has(dflt, "avatar") && !has(dflt, "msg-sender"));
});

check("a timeline shows the time only on the last bubble of each group", () => {
  const doc = fakeDoc();
  const now = local(2026, 11, 25, 12, 0);
  const d = local(2026, 11, 25, 10, 0);
  const nodes = A.renderTimeline(doc, [msg("a", d), msg("b", d + 60000), msg("c", d + 3 * 3600000)], now, true, "b");
  const rows = nodes.filter((n) => n.dataset && n.dataset.msgId);
  assert.deepEqual(rows.map((r) => has(r, "bubble-time")), [false, true, true]);
  assert.match(rows[1].className, /highlight/);
  assert.deepEqual(nodes.filter((n) => n.className === "pill-row").map((n) => n.textContent), ["Hôm nay", "13:00"]);
});

check("a system line is a centred text line: no avatar, bubble or reactions", () => {
  const doc = fakeDoc();
  const line = A.renderMessage(doc, msg("s1", 5, { type: 10, text: "Bạn đã thêm Lan vào nhóm", reactions: [{ code: "x", emoji: "👍", count: 2 }] }), { showTime: true });
  assert.equal(line.className, "msg-sys");
  assert.equal(line.textContent, "Bạn đã thêm Lan vào nhóm");
  assert.ok(!has(line, "avatar") && !has(line, "bubble") && !has(line, "reactions"));
  assert.deepEqual([...tags(line)], ["span"]);
});

check("a file card: has_local true is clickable with a check, false is dimmed with the status", () => {
  const doc = fakeDoc();
  const ok = A.renderFileCard(doc, "m7", { idx: 0, kind: "file", status: "downloaded", has_local: true, name: "Báo cáo.pdf", ext: "pdf", size: 402770 });
  assert.equal(ok.className, "file-card");
  assert.equal(ok.dataset.act, "save");
  assert.equal(ok.dataset.msgId, "m7");
  assert.equal(ok.dataset.idx, "0");
  assert.equal(ok.getAttribute("role"), "button");
  assert.equal(byClass(ok, "file-ico")[0].className, "file-ico ext-pdf");
  assert.equal(byClass(ok, "file-ext")[0].textContent, "PDF");
  assert.equal(byClass(ok, "file-name")[0].textContent, "Báo cáo.pdf");
  assert.equal(byClass(ok, "file-size")[0].textContent, "393.3 KB");
  assert.equal(byClass(ok, "file-ok")[0].textContent, "✓");
  const dim = A.renderFileCard(doc, "m8", { idx: 1, kind: "file", status: "ref", has_local: false, name: "bang.xlsx", ext: "xlsx", size: null });
  assert.equal(dim.className, "file-card dim");
  assert.equal(dim.dataset.act, undefined, "a missing file is not clickable");
  assert.equal(dim.getAttribute("role"), null);
  assert.ok(!has(dim, "file-ok") && !has(dim, "file-size"));
  assert.equal(byClass(dim, "att-missing")[0].textContent, "Media chưa tải xuống (ref)");
  assert.equal(byClass(dim, "file-ico")[0].className, "file-ico ext-xls");
  const hist = A.renderFileCard(doc, "m9", { idx: 0, kind: "file", status: "ref-import", has_local: false, name: null, ext: null, size: null });
  assert.equal(byClass(hist, "file-name")[0].textContent, "Tệp không tên");
  assert.equal(byClass(hist, "att-history")[0].textContent, "Media chưa tải xuống (lịch sử)");
});

// Every attribute name and property key of a rendered tree.
function allKeys(el, acc = new Set()) {
  for (const k of Object.keys(el)) acc.add(k);
  for (const k of Object.keys(el.attrs || {})) acc.add("attr:" + k);
  for (const c of el.children || []) allKeys(c, acc);
  return acc;
}

check("a link card shows title, domain and description, and carries no href anywhere", () => {
  const doc = fakeDoc();
  const m = msg("l1", 9, { type: 7, text: null, link: { title: "Bài viết hay", description_preview: "Mô tả ngắn", domain: "example.com" } });
  const row = A.renderMessage(doc, m, {});
  const card = byClass(row, "link-card")[0];
  assert.equal(card.dataset.act, "link");
  assert.equal(card.dataset.msgId, "l1");
  assert.equal(byClass(card, "link-title")[0].textContent, "Bài viết hay");
  assert.equal(byClass(card, "link-domain")[0].textContent, "example.com");
  assert.equal(byClass(card, "link-desc")[0].textContent, "Mô tả ngắn");
  const keys = [...allKeys(row)];
  assert.ok(!keys.some((k) => /href|^attr:src$|url/i.test(k)), "no href/url key: " + keys.join(","));
  assert.ok(!tags(row).has("a"), "no <a> element");
  assert.ok(!tags(row).has("img"), "no thumbnail (CSP)");
  // No title: the domain stands in; no description: no description node.
  const bare = A.renderLinkCard(doc, "l2", { title: null, description_preview: null, domain: "zalo.me" });
  assert.equal(byClass(bare, "link-title")[0].textContent, "zalo.me");
  assert.ok(!has(bare, "link-desc"));
});

check("a quote block: sender in bold on top, a one-line preview", () => {
  const doc = fakeDoc();
  const row = A.renderMessage(doc, msg("q1", 9, { quote: { sender_name: "Lan", text_preview: "Chiều nay họp lúc mấy giờ?" } }), {});
  const bubble = byClass(row, "bubble")[0];
  assert.equal(bubble.children[0].className, "quote", "the quote comes before the text");
  assert.equal(byClass(row, "quote-name")[0].textContent, "Lan");
  assert.equal(byClass(row, "quote-text")[0].textContent, "Chiều nay họp lúc mấy giờ?");
  assert.equal(bubble.children[1].className, "msg-text");
  const anon = A.renderMessage(doc, msg("q2", 9, { quote: { sender_name: null, text_preview: "x" } }), {});
  assert.equal(byClass(anon, "quote-name")[0].textContent, "Không rõ");
});

check("recalled and deleted messages render as an outlined, dim, italic label", () => {
  const doc = fakeDoc();
  const recalled = A.renderMessage(doc, msg("r1", 50, { type: 8, text: null, deleted: true, rev: 2, reactions: [{ code: "x", emoji: "👍", count: 1 }] }), {});
  assert.match(recalled.className, /(^| )gone( |$)/);
  assert.equal(byClass(recalled, "msg-gone")[0].textContent, "Tin nhắn đã được thu hồi");
  assert.ok(!has(recalled, "reactions"), "no reactions on a recalled message");
  const deleted = A.renderMessage(doc, msg("d1", 51, { type: 1, text: "text cũ", deleted: true }), {});
  assert.match(deleted.className, /gone/);
  assert.equal(byClass(deleted, "msg-gone")[0].textContent, "Tin nhắn đã bị xoá");
  assert.equal(byClass(deleted, "msg-text")[0].textContent, "text cũ", "the archived text of a deleted message is kept");
  const plain = A.renderMessage(doc, msg("p1", 52), {});
  assert.doesNotMatch(plain.className, /gone/);
  assert.equal(A.isGone({ deleted: false, type: 1 }), false);
  assert.equal(A.isGone({ deleted: false, type: 8 }), true);
  assert.equal(A.isGone({ deleted: true, type: 1 }), true);
  assert.equal(A.isRecalled({ type: 8 }), true);
  assert.equal(A.isRecalled({ type: 1 }), false);
});

check("reactions: a pill with up to three emoji and the total; unknown -> a dot", () => {
  const doc = fakeDoc();
  const row = A.renderMessage(doc, msg("x1", 9, { reactions: [{ code: "a", emoji: "👍", count: 2 }, { code: "b", emoji: null, count: 1 }] }), {});
  const pill = byClass(row, "reactions")[0];
  assert.deepEqual(byClass(pill, "react-emo").map((e) => e.textContent), ["👍", "•"]);
  assert.equal(byClass(pill, "react-n")[0].textContent, "3");
  assert.ok(!has(A.renderMessage(doc, msg("x2", 9), {}), "reactions"));
});

check("unknown kinds and stickers get a chip, never raw data", () => {
  const doc = fakeDoc();
  const unk = A.renderMessage(doc, msg("u1", 9, { type: 100, text: null, raw_type: "-4" }), {});
  assert.equal(byClass(unk, "chip")[0].textContent, "[Tin nhắn không hỗ trợ]");
  assert.ok(!unk.textContent.includes("-4"));
  const st = A.renderMessage(doc, msg("u2", 9, { type: 3, text: null }), {});
  assert.equal(byClass(st, "chip")[0].textContent, "[Sticker]");
  const gif = A.renderMessage(doc, msg("u3", 9, { type: 11, text: null }), {});
  assert.equal(byClass(gif, "chip")[0].textContent, "[Sticker]");
  // A message with text never gets a chip.
  assert.ok(!has(A.renderMessage(doc, msg("u4", 9), {}), "chip"));
});

check("images: thumbs through the media scheme, a grid for 2+, a placeholder when missing", () => {
  globalThis.__ZR_ARCHIVE_MEDIA__ = "http://zrarchive.localhost";
  const doc = fakeDoc();
  const img = (idx, has_local = true, status = "downloaded") => ({ idx, kind: "image", status, has_local });
  const one = A.renderMessage(doc, msg("i1", 9, { type: 2, text: null, attachments: [img(0)] }), {});
  const grid1 = byClass(one, "att-grid")[0];
  assert.match(grid1.className, /\bone\b/);
  const thumb = find(one, "img")[0];
  assert.equal(thumb.src, "http://zrarchive.localhost/media/i1/0?v=thumb");
  assert.equal(thumb.loading, "lazy");
  assert.equal(thumb.decoding, "async");
  assert.equal(thumb.alt, "");
  assert.match(byClass(one, "bubble")[0].className, /has-media/);
  const tile = byClass(one, "att-tile")[0];
  assert.equal(tile.dataset.act, "lightbox");
  assert.equal(tile.dataset.msgId, "i1");
  for (const [n, cls] of [[2, "cols-2"], [3, "cols-3"], [4, "cols-2"], [5, "cols-3"]]) {
    const many = A.renderMessage(doc, msg("i" + n, 9, { type: 2, text: null, attachments: Array.from({ length: n }, (_, i) => img(i)) }), {});
    assert.match(byClass(many, "att-grid")[0].className, new RegExp("\\b" + cls + "\\b"), "n=" + n);
    assert.equal(find(many, "img").length, n);
  }
  // A missing image: grey placeholder with the existing status text, not clickable.
  const miss = A.renderMessage(doc, msg("i9", 9, { type: 2, text: null, attachments: [img(0, false, "failed"), img(1, false, "expired")] }), {});
  assert.equal(find(miss, "img").length, 0);
  assert.deepEqual(byClass(miss, "att-missing").map((s) => s.textContent), ["Media chưa tải xuống (failed)", "Liên kết đã hết hạn"]);
  assert.ok(byClass(miss, "att-ph").every((p) => p.dataset.act === undefined && p.disabled === true));
  delete globalThis.__ZR_ARCHIVE_MEDIA__;
});

check("a video is a poster box with a play overlay that opens the lightbox; no autoplay inline", () => {
  globalThis.__ZR_ARCHIVE_MEDIA__ = "http://zrarchive.localhost";
  const doc = fakeDoc();
  const row = A.renderMessage(doc, msg("v1", 9, { type: 6, text: null, attachments: [{ idx: 1, kind: "video", status: "downloaded", has_local: true }] }), {});
  const vid = find(row, "video")[0];
  assert.equal(vid.src, "http://zrarchive.localhost/media/v1/1", "a video never gets a variant");
  assert.equal(vid.preload, "metadata");
  assert.notEqual(vid.controls, true);
  assert.notEqual(vid.autoplay, true);
  assert.ok(has(row, "play-ico"));
  assert.equal(byClass(row, "att-tile")[0].dataset.act, "lightbox");
  delete globalThis.__ZR_ARCHIVE_MEDIA__;
});

check("a bubble holds quote, text, files and images in order, with the time last", () => {
  const doc = fakeDoc();
  const row = A.renderMessage(doc, msg("o1", local(2026, 11, 25, 8, 0), {
    quote: { sender_name: "Lan", text_preview: "q" }, text: "kèm theo",
    attachments: [{ idx: 0, kind: "image", status: "downloaded", has_local: true }, { idx: 1, kind: "file", status: "downloaded", has_local: true, name: "a.zip", ext: "zip", size: 10 }, { idx: 2, kind: "voice", status: "downloaded", has_local: true }],
  }), {});
  const bubble = byClass(row, "bubble")[0];
  assert.deepEqual(bubble.children.map((c) => c.className.split(" ")[0]), ["quote", "msg-text", "att-grid", "msg-att", "msg-att", "bubble-time"]);
  assert.equal(byClass(row, "att-label")[0].textContent, "Tệp đính kèm · voice");
});

// --- search hits ----------------------------------------------------------

check("snippet highlighting: case- and diacritic-insensitive, pure data", () => {
  const parts = A.snippetParts("Hà Nội hôm nay mưa to", "ha NOI");
  assert.deepEqual(parts, [{ text: "Hà", hit: true }, { text: " ", hit: false }, { text: "Nội", hit: true }, { text: " hôm nay mưa to", hit: false }]);
  assert.deepEqual(A.snippetParts("đường đi", "duong"), [{ text: "đường", hit: true }, { text: " đi", hit: false }]);
  assert.deepEqual(A.snippetParts("abc", "zzz"), [{ text: "abc", hit: false }]);
  assert.deepEqual(A.snippetParts("abc", ""), [{ text: "abc", hit: false }]);
  assert.deepEqual(A.snippetParts("", "x"), []);
  // Two terms, merged when they touch.
  assert.deepEqual(A.snippetParts("an ban", "an ban").map((p) => p.hit), [true, false, true]);
  // Whitespace collapses, so the snippet is one line.
  assert.equal(A.snippetParts("a\n\n b", "q").map((p) => p.text).join(""), "a b");
  // A long text is cut around the first hit with ellipses.
  const long = "x".repeat(200) + " target " + "y".repeat(200);
  const cut = A.snippetParts(long, "target");
  assert.equal(cut[0].text, "…");
  assert.ok(cut.some((p) => p.hit && p.text === "target"));
  assert.equal(cut[cut.length - 1].text, "…");
  assert.ok(cut.map((p) => p.text).join("").length < 130);
  // The fold keeps the length so indexes map back to the original.
  for (const s of ["Đường Hà Nội ẤẶ", "İstanbul", "ǅ"]) assert.equal(A.fold(s).length, s.length, s);
});

check("a search hit shows text nodes and <mark> elements only", () => {
  const doc = fakeDoc();
  const hit = A.renderSearchHit(doc, { conv_id: "g1", conv_name: "Nhóm lớp học", msg_id: "m5", ts: 1731987201000, type: 1, text: "Hà Nội hôm nay mưa" }, { query: "hom nay" });
  assert.equal(hit.tag, "button");
  assert.equal(hit.dataset.convId, "g1");
  assert.equal(hit.dataset.msgId, "m5");
  assert.equal(hit.dataset.ts, "1731987201000");
  assert.equal(hit.children[0].textContent, "Nhóm lớp học");
  const text = hit.children[1];
  assert.equal(text.textContent, "Hà Nội hôm nay mưa");
  assert.ok(text.children.every((c) => c.nodeType === 3 || c.tag === "mark"), "children are text nodes or <mark>");
  assert.deepEqual(text.children.filter((c) => c.tag === "mark").map((m) => m.textContent), ["hôm", "nay"]);
  assert.deepEqual([...tags(text)], ["mark"]);
  assert.equal(hit.children[2].textContent, A.fmtTs(1731987201000));
  // A tag in the text stays text.
  const evil = A.renderSearchHit(doc, { conv_id: "c", msg_id: "m", ts: 1, text: "<b>x</b> <img src=x>" }, { query: "x" });
  assert.deepEqual([...tags(evil.children[1])], ["mark"]);
  assert.ok(evil.children[1].textContent.includes("<b>"));
  // In-conversation search hides the conversation name; no name -> the id.
  const inconv = A.renderSearchHit(doc, { conv_id: "c", msg_id: "m", ts: 1, text: "z" }, { showConv: false });
  assert.deepEqual(inconv.children.map((c) => c.className), ["hit-text", "hit-ts"]);
  const bare = A.renderSearchHit(doc, { conv_id: "zz", conv_name: null, msg_id: "m6", ts: 5, type: 1, text: "" });
  assert.equal(bare.children[0].textContent, "zz");
  assert.equal(bare.children[1].textContent, "");
});

// --- the right panel and the storage view -----------------------------------------------

check("the info panel renders its header and the three sections from fake data", () => {
  globalThis.__ZR_ARCHIVE_MEDIA__ = "http://zrarchive.localhost";
  const doc = fakeDoc();
  const media = Array.from({ length: 10 }, (_, i) => ({ msg_id: "p" + i, idx: 0, kind: i === 1 ? "video" : "image", ts: 1700000000000 - i, has_local: i !== 2, status: i === 2 ? "ref" : "downloaded" }));
  const panel = A.renderInfoPanel(doc, {
    info: { name: "Nhóm bạn bè", is_group: true, member_count: 25, initials: "NB", color_idx: 4, first_ts: local(2024, 1, 5, 9, 0), last_ts: local(2026, 11, 25, 9, 0), msg_count: 1234 },
    counts: { media: 40, file: 7, link: 0 },
    media,
    files: [{ msg_id: "f1", idx: 0, ts: local(2026, 11, 19, 8, 0), name: "Kế hoạch.docx", ext: "docx", size: 38500, has_local: true, status: "downloaded", sender_name: "Lan" }, { msg_id: "f2", idx: 0, ts: local(2026, 11, 18, 8, 0), name: null, ext: null, size: null, has_local: false, status: "expired", sender_name: null }],
    links: [],
  });
  assert.equal(byClass(panel, "pi-name")[0].textContent, "Nhóm bạn bè");
  assert.deepEqual(byClass(panel, "pi-line").map((l) => l.textContent), ["25 thành viên", "Từ 05/01/2024 đến 25/11/2026", "1234 tin nhắn"]);
  assert.equal(byClass(panel, "avatar")[0].textContent, "NB");
  const secs = byClass(panel, "p-sec");
  assert.deepEqual(secs.map((s) => s.dataset.sec), ["media", "file", "link"]);
  assert.deepEqual(secs.map((s) => byClass(s, "p-sec-title")[0].textContent), ["Ảnh/Video", "File", "Link"]);
  assert.deepEqual(secs.map((s) => byClass(s, "p-sec-count")[0].textContent), ["40", "7", "0"], "counts next to the titles");
  assert.ok(secs.every((s) => byClass(s, "p-sec-head")[0].dataset.act === "sec-toggle" && has(s, "p-caret")), "every section collapses with a caret");
  // media: 8 tiles at most, a video box, a placeholder, "Xem tất cả"
  assert.equal(byClass(secs[0], "pm-thumb").length, 8);
  assert.ok(has(secs[0], "play-ico"));
  assert.equal(find(secs[0], "img")[0].src, "http://zrarchive.localhost/media/p0/0?v=thumb");
  assert.equal(byClass(secs[0], "pm-thumb")[0].dataset.src, "panel");
  assert.equal(byClass(secs[0], "pm-thumb")[3].dataset.index, "3");
  assert.equal(byClass(secs[0], "att-ph").length, 1, "the missing one is a placeholder");
  assert.equal(byClass(secs[0], "p-more")[0].textContent, "Xem tất cả");
  assert.equal(byClass(secs[0], "p-more")[0].dataset.tab, "media");
  // files: icon, name, size, date; a missing file is dimmed and not clickable
  const rows = byClass(secs[1], "pf-row");
  assert.equal(rows.length, 2);
  assert.equal(byClass(rows[0], "pf-name")[0].textContent, "Kế hoạch.docx");
  assert.equal(byClass(rows[0], "pf-size")[0].textContent, "37.6 KB");
  assert.equal(byClass(rows[0], "pf-date")[0].textContent, "19/11/2026");
  assert.equal(rows[0].dataset.act, "save");
  assert.match(rows[1].className, /dim/);
  assert.equal(rows[1].dataset.act, undefined);
  // links: empty section says so and has no "Xem tất cả"
  assert.equal(byClass(secs[2], "p-empty")[0].textContent, "Chưa có link");
  assert.ok(!has(secs[2], "p-more"));
  delete globalThis.__ZR_ARCHIVE_MEDIA__;
});

check("the info panel: a private chat has no member line; collapsed sections are marked; empty states", () => {
  const doc = fakeDoc();
  const panel = A.renderInfoPanel(doc, { info: { name: "Mai", is_group: false, member_count: null, initials: "M", color_idx: 0, first_ts: null, last_ts: null, msg_count: 0 }, counts: { media: 0, file: 0, link: 0 }, media: [], files: [], links: [], open: { media: false, file: true, link: true } });
  assert.deepEqual(byClass(panel, "pi-line").map((l) => l.textContent), ["0 tin nhắn"]);
  const secs = byClass(panel, "p-sec");
  assert.match(secs[0].className, /collapsed/);
  assert.doesNotMatch(secs[1].className, /collapsed/);
  assert.equal(byClass(secs[0], "p-sec-head")[0].getAttribute("aria-expanded"), "false");
  assert.deepEqual(secs.map((s) => byClass(s, "p-empty")[0].textContent), ["Chưa có ảnh/video", "Chưa có file", "Chưa có link"]);
  // counts not loaded -> no count node
  const nocount = A.renderInfoPanel(doc, { info: { name: "x" }, counts: null, media: [], files: [], links: [] });
  assert.ok(!has(nocount, "p-sec-count"));
});

check("the storage view groups rows under month headers across pages", () => {
  globalThis.__ZR_ARCHIVE_MEDIA__ = "http://zrarchive.localhost";
  const doc = fakeDoc();
  const list = doc.createElement("div");
  const ctx = { month: null, grid: null, count: 0 };
  const m = (id, y, mo, d) => ({ msg_id: id, idx: 0, kind: "image", ts: local(y, mo, d, 10, 0), has_local: true, status: "downloaded" });
  A.appendStoreRows(doc, list, ctx, "media", [m("a", 2026, 11, 20), m("b", 2026, 11, 2), m("c", 2026, 10, 30)]);
  A.appendStoreRows(doc, list, ctx, "media", [m("d", 2026, 10, 1), m("e", 2026, 9, 5)]); // the next page continues October
  assert.deepEqual(byClass(list, "store-month").map((h) => h.textContent), ["Tháng 11/2026", "Tháng 10/2026", "Tháng 9/2026"]);
  assert.deepEqual(byClass(list, "store-grid").map((g) => g.children.length), [2, 2, 1], "a grid per month; the second page joins October's grid");
  const tiles = byClass(list, "pm-thumb");
  assert.deepEqual(tiles.map((x) => x.dataset.index), ["0", "1", "2", "3", "4"], "indexes run over the loaded list");
  assert.ok(tiles.every((x) => x.dataset.src === "store"));
  // files and links are plain rows under the same headers
  const l2 = doc.createElement("div");
  const c2 = { month: null, grid: null, count: 0 };
  A.appendStoreRows(doc, l2, c2, "file", [{ msg_id: "f", idx: 0, ts: local(2026, 11, 1, 1, 0), name: "a.pdf", ext: "pdf", size: 1, has_local: true }]);
  A.appendStoreRows(doc, l2, c2, "link", [{ msg_id: "k", ts: local(2026, 11, 1, 1, 0), title: "T", domain: "d.com" }]);
  assert.equal(byClass(l2, "pf-row").length, 1);
  assert.equal(byClass(l2, "pl-row")[0].dataset.act, "link");
  assert.equal(byClass(l2, "pl-title")[0].textContent, "T");
  assert.equal(byClass(l2, "pl-domain")[0].textContent, "d.com");
  assert.equal(A.rowCursor({ ts: 5, msg_id: "x", idx: 2 })[2], 2);
  assert.deepEqual(A.rowCursor({ ts: 5, msg_id: "x" }), [5, "x", 0], "a link row has no idx");
  delete globalThis.__ZR_ARCHIVE_MEDIA__;
});

check("the lightbox list from loaded messages is newest first, images and videos only", () => {
  const items = A.mediaItemsFromMessages([
    msg("a", 100, { attachments: [{ idx: 0, kind: "image", has_local: true, status: "downloaded" }, { idx: 1, kind: "image", has_local: true, status: "downloaded" }] }),
    msg("b", 200, { attachments: [{ idx: 0, kind: "file", has_local: true }] }),
    msg("c", 300, { is_self: true, attachments: [{ idx: 0, kind: "video", has_local: false, status: "ref" }] }),
  ]);
  assert.deepEqual(items.map((i) => [i.msg_id, i.idx, i.kind]), [["c", 0, "video"], ["a", 1, "image"], ["a", 0, "image"]]);
  assert.equal(items[0].sender_name, "Bạn");
  assert.equal(items[1].sender_name, "Mai");
  assert.equal(items[0].has_local, false);
});

// --- errors ---------------------------------------------------------------------------

check("command error kinds become short toasts", () => {
  assert.equal(A.errorMessage("no-link"), "Tin nhắn này không có liên kết.");
  assert.equal(A.errorMessage("bad-scheme"), "Liên kết không được hỗ trợ.");
  assert.equal(A.errorMessage("not-found"), "Không tìm thấy tệp.");
  assert.equal(A.errorMessage("copy-failed"), "Không thể lưu tệp.");
  assert.equal(A.errorMessage("bad-id"), "Không thể thực hiện thao tác.");
  assert.equal(A.errorMessage("locked"), "Không thể truy vấn kho lưu trữ.");
  assert.equal(A.errorMessage("Một câu đã được địa phương hoá."), "Một câu đã được địa phương hoá.");
  assert.equal(A.errorMessage(undefined), "Không thể thực hiện thao tác.");
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

// --- safety: never HTML parsing ---------------------------------------------------

check("the page source never parses HTML from data", () => {
  const src = readFileSync(new URL("archive.js", import.meta.url), "utf8");
  for (const forbidden of ["innerHTML", "insertAdjacentHTML", "outerHTML", "document.write", "srcdoc", "eval(", "new Function", "DOMParser", "createContextualFragment"]) {
    assert.ok(!src.includes(forbidden), `archive.js must never use ${forbidden}`);
  }
  // Whatever the wording, no assignment to those sinks either.
  assert.ok(!/\.(inner|outer)HTML\s*=/.test(src));
  assert.ok(!/document\s*\.\s*write/.test(src));
  // No remote resources or data: URLs anywhere in the page's own files.
  const html = readFileSync(new URL("archive.html", import.meta.url), "utf8");
  const css = readFileSync(new URL("archive.css", import.meta.url), "utf8");
  for (const [name, text] of [["archive.js", src], ["archive.css", css]]) {
    const literals = text.match(/["'`]https?:\/\/[^"'`]*["'`]/g) || [];
    assert.deepEqual(literals.filter((l) => !/www\.w3\.org\/2000\/svg|zrarchive\.localhost/.test(l)), [], name + " has a remote URL");
    assert.ok(!/data:[a-z]+\/[a-z0-9.+-]+[;,]/i.test(text), name + " has a data: URL");
  }
  // The CSP is the one from batch 11: only the internal scheme for media.
  assert.ok(html.includes("img-src zrarchive: http://zrarchive.localhost; media-src zrarchive: http://zrarchive.localhost; connect-src ipc: http://ipc.localhost"));
  assert.ok(!/<script(?![^>]*\bsrc=)[^>]*>/.test(html), "no inline scripts");
});

check("every page string goes through textContent or a node, and the icons are SVG nodes", () => {
  const doc = fakeDoc();
  const svg = A.icon(doc, "search", 18);
  assert.equal(svg.tag, "svg");
  assert.equal(svg.getAttribute("aria-hidden"), "true");
  assert.deepEqual([...tags(svg)], ["path"]);
  for (const name of ["search", "panel", "play", "back", "next", "down", "file", "close"]) assert.equal(A.icon(doc, name).tag, "svg", name);
});

check("rendered rows only ever contain the expected element names", () => {
  const doc = fakeDoc();
  const item = A.renderMessage(doc, msg("m1", 1, {
    type: 2, text: "ảnh nè", quote: { sender_name: "a", text_preview: "b" },
    reactions: [{ code: "a", emoji: "👍", count: 1 }],
    attachments: [
      { idx: 0, kind: "image", status: "downloaded", has_local: true },
      { idx: 1, kind: "image", status: "ref", has_local: false },
      { idx: 2, kind: "video", status: "downloaded", has_local: true },
      { idx: 3, kind: "file", status: "downloaded", has_local: true, name: "n", ext: "pdf", size: 1 },
    ],
    link: { title: "t", description_preview: "d", domain: "x.com" },
  }), { showSender: true });
  const allowed = new Set(["div", "span", "button", "img", "video", "svg", "path"]);
  for (const tag of tags(item)) assert.ok(allowed.has(tag), "unexpected <" + tag + ">");
  const conv = A.renderConversation(doc, { id: "c1", name: "x", last_msg_preview: "y", initials: "X", color_idx: 0 });
  for (const tag of tags(conv)) assert.ok(["span"].includes(tag), "unexpected <" + tag + ">");
});

// --- i18n through the shared tables ----------------------------------------

check("the archive labels translate through the shared vi tables", () => {
  assert.equal(t("Mensagem desfeita"), "Tin nhắn đã thu hồi");
  assert.equal(t("Mensagem excluída"), "Tin nhắn đã bị xoá");
  assert.equal(t("Mídia não baixada ({0})", ["failed"]), "Media chưa tải xuống (failed)");
  assert.equal(t("Abrir o armazenamento"), "Mở Lưu trữ");
  assert.equal(t("Conversas: {0}", [7]), "Cuộc trò chuyện: 7");
  for (const [pt, vi] of [["Hoje", "Hôm nay"], ["Ontem", "Hôm qua"], ["Você", "Bạn"], ["Informações da conversa", "Thông tin hội thoại"], ["Imagens/Vídeos", "Ảnh/Video"], ["Arquivos", "File"], ["Links", "Link"], ["Ver tudo", "Xem tất cả"], ["Acervo", "Kho lưu trữ"], ["Arquivo · somente leitura", "Lưu trữ · chỉ xem"], ["Imagem original", "Ảnh gốc"], ["Salvo", "Đã lưu"], ["Todas", "Tất cả"], ["Pessoais", "Cá nhân"], ["Grupos", "Nhóm"]]) {
    assert.equal(t(pt), vi, pt);
  }
  assert.equal(t("Mês {0}/{1}", [11, 2026]), "Tháng 11/2026");
});

// --- time formatting (kept from batch 11) -------------------------------------

check("fmtTs shows a time for today and a date otherwise", () => {
  assert.equal(A.fmtTs(0), "");
  const now = A.fmtTs(Date.now());
  assert.match(now, /:/);
  const old = A.fmtTs(Date.UTC(2020, 0, 2, 3, 4));
  assert.ok(old.length > now.length, "an older message carries its date: " + old);
});

await Promise.all(pending);
if (failures) { console.log(`\n${failures} archive test(s) failed`); process.exit(1); }
console.log("\nall archive tests passed");
