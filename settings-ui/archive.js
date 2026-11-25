"use strict";
// Lưu trữ (archive) window — audit §4 Phase 3 item 3.2 (batch 11),
// rebuilt in batch 29b to look and behave like Zalo PC.
//
// Layout: three columns. Left: search box, "Tất cả / Cá nhân / Nhóm"
// tabs and the conversation list (infinite scroll through the
// (last_ts, id) keyset cursor). Middle: chat header, bubbles (older
// pages prepend), a read-only bar. Right: "Thông tin hội thoại" and the
// "Kho lưu trữ" view (media / files / links, keyset paged), plus a
// lightbox for images and videos.
//
// SAFETY: every piece of shadow-DB data is rendered through
// createElement + textContent — never HTML-string parsing (the node
// test pins both the source and the rendered structure). Media is
// loaded exclusively through the internal zrarchive:// scheme (K3),
// keyed by msg_id/idx; the URL never carries a file path, and JS never
// sees a path, sha or href (links and saves go through commands that
// re-read them server-side).
(function (root) {
  // ---- pure helpers (node-tested) ----------------------------------------

  function t(s, args) {
    return root.t ? root.t(s, args) : fillPlain(s, args);
  }
  function fillPlain(s, args) {
    if (!args) return s;
    for (var i = 0; i < args.length; i++) s = s.split("{" + i + "}").join(String(args[i]));
    return s;
  }

  // The media-scheme base Rust injected (WebView2 maps custom schemes
  // onto http://<scheme>.localhost; macOS/Linux keep scheme://localhost).
  function mediaBase() {
    return root.__ZR_ARCHIVE_MEDIA__ || "zrarchive://localhost";
  }

  // Media URL for one attachment: ids only, never a path.
  // Batch 28: an image is served as a WebP derivative; `variant` is
  // "thumb" (long edge <= 480), "view" (<= 2048) or "orig" (the full
  // size of a JPEG XL; the original bytes for JPEG/PNG). No variant =
  // no query, which the server reads as "view". Anything else is
  // dropped, so a URL never carries a value the server would refuse.
  var VARIANTS = { thumb: 1, view: 1, orig: 1 };
  function mediaUrl(msgId, idx, variant) {
    var url = mediaBase() + "/media/" + encodeURIComponent(String(msgId)) + "/" + Number(idx);
    if (typeof variant === "string" && Object.prototype.hasOwnProperty.call(VARIANTS, variant)) {
      url += "?v=" + variant;
    }
    return url;
  }

  // The one rule for a thumbnail <img> in a bubble (.att-img boxes are at
  // most 240 CSS px wide, see archive.css): when that box needs no more
  // than 480 device pixels (240 x devicePixelRatio <= 480, i.e. up to a
  // 200% display) the 480 px thumb is sharp enough; on denser displays
  // the 2048 px view is used.
  var BUBBLE_CSS_MAX_PX = 240;
  var THUMB_EDGE_PX = 480;
  function imageVariant(dpr) {
    var d = Number(dpr);
    if (!(d > 0)) d = 1;
    return BUBBLE_CSS_MAX_PX * d <= THUMB_EDGE_PX ? "thumb" : "view";
  }

  function isRecalled(msg) {
    // normalize::msg_type_code's recall family (batch 25: chat.delete,
    // chat.undo, chat.delete.everyone, V1 recall — all code 8).
    return msg.type === 8;
  }
  function isGone(msg) {
    return !!(msg.deleted || msg.type === 8);
  }
  // Batch 30: group events ("Bạn đã thêm … vào nhóm") are type 10.
  function isSystem(msg) {
    return msg.type === 10;
  }

  // ---- time ----

  function pad2(n) {
    return (n < 10 ? "0" : "") + n;
  }
  // "HH:mm", local time, locale-independent.
  function fmtHM(ts) {
    var d = new Date(ts);
    return pad2(d.getHours()) + ":" + pad2(d.getMinutes());
  }
  // "dd/MM/yy" (or "dd/MM/yyyy" when full).
  function fmtDate(ts, full) {
    var d = new Date(ts);
    var y = d.getFullYear();
    return pad2(d.getDate()) + "/" + pad2(d.getMonth() + 1) + "/" + (full ? y : pad2(y % 100));
  }
  // Calendar-day number of a timestamp in LOCAL time. Built from the
  // local y/m/d through Date.UTC so a DST day of 23 or 25 hours still
  // counts as exactly one day.
  function dayKey(ts) {
    var d = new Date(ts);
    return Math.round(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate()) / 86400000);
  }
  // Day separator: "Hôm nay" / "Hôm qua" / dd/MM/yyyy.
  function dayLabel(ts, now) {
    var diff = dayKey(now == null ? Date.now() : now) - dayKey(ts);
    if (diff === 0) return t("Hoje");
    if (diff === 1) return t("Ontem");
    return fmtDate(ts, true);
  }
  // The left column's relative time: "Vừa xong", "4 phút", "2 giờ",
  // "7 ngày", then dd/MM/yy.
  function relTime(ts, now) {
    if (!ts) return "";
    var n = now == null ? Date.now() : now;
    var diff = Math.max(0, n - ts);
    var min = Math.floor(diff / 60000);
    if (min < 1) return t("agora");
    if (min < 60) return t("{0} min", [min]);
    var h = Math.floor(min / 60);
    if (h < 24) return t("{0} h", [h]);
    var days = Math.floor(diff / 86400000);
    if (days <= 7) return t("{0} d", [days]);
    return fmtDate(ts, false);
  }
  // "HH:mm" for today, else "DD/MM/YY HH:MM" (kept from batch 11).
  function fmtTs(ts) {
    if (!ts) return "";
    var d = new Date(ts);
    var locale = root.I18n && root.I18n.locale ? root.I18n.locale() : "vi-VN";
    var time = d.toLocaleTimeString(locale, { hour: "2-digit", minute: "2-digit" });
    var sameDay = d.toDateString() === new Date().toDateString();
    if (sameDay) return time;
    var date = d.toLocaleDateString(locale, { day: "2-digit", month: "2-digit", year: "2-digit" });
    return date + " " + time;
  }
  // Month headers of the storage view: "Tháng 11/2026".
  function monthKey(ts) {
    var d = new Date(ts);
    return d.getFullYear() * 12 + d.getMonth();
  }
  function monthLabel(ts) {
    var d = new Date(ts);
    return t("Mês {0}/{1}", [d.getMonth() + 1, d.getFullYear()]);
  }

  // ---- small formatters ----

  // KB / MB with one decimal ("1.5 KB"); bytes below 1 KB.
  function fmtSize(n) {
    var v = Number(n);
    if (n == null || !isFinite(v) || v < 0) return "";
    if (v < 1024) return Math.round(v) + " B";
    if (v < 1048576) return (v / 1024).toFixed(1) + " KB";
    if (v < 1073741824) return (v / 1048576).toFixed(1) + " MB";
    return (v / 1073741824).toFixed(1) + " GB";
  }
  // The file icon's colour class, by extension (CSS only).
  var EXT_GROUPS = {
    pdf: "ext-pdf",
    doc: "ext-doc", docx: "ext-doc", odt: "ext-doc", rtf: "ext-doc",
    xls: "ext-xls", xlsx: "ext-xls", csv: "ext-xls", ods: "ext-xls",
    ppt: "ext-ppt", pptx: "ext-ppt", odp: "ext-ppt",
    zip: "ext-zip", rar: "ext-zip", "7z": "ext-zip", tar: "ext-zip", gz: "ext-zip",
  };
  function extClass(ext) {
    var e = String(ext == null ? "" : ext).toLowerCase().replace(/^\./, "");
    return Object.prototype.hasOwnProperty.call(EXT_GROUPS, e) ? EXT_GROUPS[e] : "ext-other";
  }
  function extLabel(ext) {
    var e = String(ext == null ? "" : ext).replace(/^\./, "").toUpperCase();
    return e ? e.slice(0, 4) : "FILE";
  }

  // ---- conversation preview ----

  // What the Rust side writes as `last_msg_preview` when a message has
  // no text (archive.rs preview_label), keyed by `last_kind`, and the
  // Zalo-style label the list shows instead. Anything else is shown as
  // it came (real text).
  var RUST_LABELS = {
    2: "[ảnh]", 3: "[sticker]", 4: "[file]", 5: "[giọng nói]", 6: "[video]",
    7: "[liên kết]", 8: "[đã thu hồi]", 9: "[nội dung web]", 10: "[thông báo]",
    11: "[gif]", 12: "[doodle]", 13: "[vị trí]", 14: "[danh sách]", 15: "[thiệp]",
    16: "[bình chọn]", 17: "[to-do]", 100: "[khác]",
  };
  var KIND_LABELS = {
    2: "[Imagem]", 3: "[Sticker]", 4: "[Arquivo]", 5: "[Voz]", 6: "[Vídeo]",
    7: "[Link]", 9: "[Link]", 11: "[Sticker]",
  };
  function kindLabel(kind) {
    if (kind === 8) return t("Mensagem recolhida");
    if (Object.prototype.hasOwnProperty.call(KIND_LABELS, kind)) return t(KIND_LABELS[kind]);
    return t("[Mensagem não suportada]");
  }
  // "Bạn: …" / "<sender>: …" (groups only) / just the preview.
  function previewText(conv) {
    var text = conv.last_msg_preview || "";
    var kind = conv.last_kind | 0;
    if (text && RUST_LABELS[kind] === text && kind !== 10) text = kindLabel(kind);
    if (!text) return "";
    if (kind === 10) return text; // a system line has no sender
    if (conv.last_sender_is_self) return t("Você") + ": " + text;
    if (conv.is_group && conv.last_sender_name) return conv.last_sender_name + ": " + text;
    return text;
  }

  // ---- reactions ----

  // The glyph of one reaction bucket. The code -> emoji table lives in
  // Rust (archive.rs REACTION_CODES, one source of truth); a bucket the
  // table does not know arrives with `emoji: null` and shows "•".
  function reactionGlyph(r) {
    return r && typeof r.emoji === "string" && r.emoji ? r.emoji : "•";
  }
  // Up to 3 distinct glyphs (in the order given: most used first) and
  // the total count, for the small pill under a bubble.
  function reactionSummary(reactions) {
    var glyphs = [];
    var total = 0;
    (reactions || []).forEach(function (r) {
      var n = Number(r && r.count);
      if (!(n > 0)) return;
      total += n;
      var g = reactionGlyph(r);
      if (glyphs.length < 3 && glyphs.indexOf(g) < 0) glyphs.push(g);
    });
    return { glyphs: glyphs, total: total };
  }

  // ---- search snippet highlighting ----

  // Length-preserving, case- and diacritic-insensitive fold, so a match
  // found on the folded text maps 1:1 to the original (like the FTS).
  function fold(s) {
    var out = "";
    for (var i = 0; i < s.length; i++) {
      var c = s.charAt(i);
      var base = c.normalize ? c.normalize("NFD").charAt(0) : c;
      if (base === "đ" || base === "Đ") base = "d";
      out += base.toLowerCase().charAt(0) || c;
    }
    return out;
  }
  // [{text, hit}] pieces of a snippet around the first hit. Pure data:
  // the renderer turns each into a text node or a <mark> element.
  function snippetParts(text, query, maxLen) {
    var flat = String(text == null ? "" : text).replace(/\s+/g, " ").trim();
    var max = maxLen || 90;
    var terms = fold(String(query == null ? "" : query)).split(/\s+/).filter(Boolean);
    var folded = fold(flat);
    var marks = [];
    terms.forEach(function (term) {
      var from = 0;
      for (;;) {
        var at = folded.indexOf(term, from);
        if (at < 0) break;
        marks.push([at, at + term.length]);
        from = at + term.length;
      }
    });
    marks.sort(function (a, b) { return a[0] - b[0] || b[1] - a[1]; });
    var merged = [];
    marks.forEach(function (m) {
      var last = merged[merged.length - 1];
      if (last && m[0] <= last[1]) last[1] = Math.max(last[1], m[1]);
      else merged.push([m[0], m[1]]);
    });
    var start = 0;
    if (merged.length && merged[0][0] > 24) start = merged[0][0] - 24;
    var end = Math.min(flat.length, start + max);
    var parts = [];
    if (start > 0) parts.push({ text: "…", hit: false });
    var pos = start;
    merged.forEach(function (m) {
      if (m[1] <= pos || m[0] >= end) return;
      var a = Math.max(m[0], pos);
      var b = Math.min(m[1], end);
      if (a > pos) parts.push({ text: flat.slice(pos, a), hit: false });
      parts.push({ text: flat.slice(a, b), hit: true });
      pos = b;
    });
    if (pos < end) parts.push({ text: flat.slice(pos, end), hit: false });
    if (end < flat.length) parts.push({ text: "…", hit: false });
    return parts;
  }

  // ---- message layout (day pills, time pills, grouping) ----

  var GROUP_GAP_MS = 5 * 60 * 1000;
  var TIME_PILL_GAP_MS = 60 * 60 * 1000;

  function senderKey(m) {
    if (m.is_self) return "self";
    return String(m.sender_id || m.sender_name || "?");
  }
  // Ascending messages -> a flat list of entries:
  //   {kind:"pill", text}            a day or HH:mm separator
  //   {kind:"sys", msg}              a group event line (never grouped)
  //   {kind:"msg", msg, showSender, showAvatar, showTime}
  // A bubble continues the previous one when it has the same sender, is
  // within 5 minutes and no pill / system line lies between. The sender
  // name shows on the first bubble of a group, the avatar and the time
  // on the last.
  function layoutMessages(msgs, now, isGroup) {
    var out = [];
    var prev = null; // previous message of any kind (for pills)
    var prevEntry = null; // previous bubble entry, null after a pill/system line
    msgs.forEach(function (m) {
      var pill = null;
      if (!prev || dayKey(m.ts) !== dayKey(prev.ts)) pill = dayLabel(m.ts, now);
      else if (m.ts - prev.ts > TIME_PILL_GAP_MS) pill = fmtHM(m.ts);
      if (pill !== null) {
        out.push({ kind: "pill", text: pill });
        prevEntry = null;
      }
      prev = m;
      if (isSystem(m)) {
        out.push({ kind: "sys", msg: m });
        prevEntry = null;
        return;
      }
      var cont = !!(prevEntry &&
        senderKey(prevEntry.msg) === senderKey(m) &&
        Math.abs(m.ts - prevEntry.msg.ts) < GROUP_GAP_MS);
      var entry = { kind: "msg", msg: m, cont: cont, showSender: false, showAvatar: false, showTime: false };
      out.push(entry);
      prevEntry = entry;
    });
    for (var i = 0; i < out.length; i++) {
      var e = out[i];
      if (e.kind !== "msg") continue;
      var next = out[i + 1];
      var last = !(next && next.kind === "msg" && next.cont);
      e.showTime = last;
      e.showAvatar = last && !e.msg.is_self;
      e.showSender = !e.cont && !!isGroup && !e.msg.is_self;
    }
    return out;
  }

  // Image/video attachments of loaded messages, newest first — the
  // lightbox's starting list (older pages then come from
  // archive_conv_media).
  function mediaItemsFromMessages(msgs) {
    var items = [];
    for (var i = msgs.length - 1; i >= 0; i--) {
      var m = msgs[i];
      var atts = m.attachments || [];
      for (var j = atts.length - 1; j >= 0; j--) {
        var a = atts[j];
        if (a.kind !== "image" && a.kind !== "video") continue;
        items.push({
          msg_id: m.msg_id, idx: a.idx, kind: a.kind, ts: m.ts,
          has_local: !!a.has_local, status: a.status || null,
          sender_name: m.is_self ? t("Você") : m.sender_name || null,
        });
      }
    }
    return items;
  }
  // The keyset cursor of a storage-view row, to pass back as `before`.
  function rowCursor(row) {
    return [row.ts, row.msg_id, row.idx == null ? 0 : row.idx];
  }

  // Error kinds the commands return -> a short, Vietnamese-capable toast.
  // A message that already is a sentence (the commands localise their
  // own failures) passes through.
  function errorMessage(e) {
    var s = String(e == null ? "" : e);
    if (s === "locked") return t("Não foi possível consultar o armazenamento.");
    if (s === "no-link") return t("Esta mensagem não tem link.");
    if (s === "bad-scheme") return t("Link não suportado.");
    if (s === "not-found") return t("Arquivo não encontrado.");
    if (s === "copy-failed" || s === "bad-path") return t("Não foi possível salvar o arquivo.");
    if (/\s/.test(s)) return s;
    return t("Não foi possível concluir a ação.");
  }

  // Debounce (the search boxes, 300 ms): trailing edge, one call per burst.
  function makeDebounce(fn, ms) {
    var timer = 0;
    return function () {
      var args = arguments;
      var self = this;
      if (timer) clearTimeout(timer);
      timer = setTimeout(function () {
        timer = 0;
        fn.apply(self, args);
      }, ms);
    };
  }

  // ---- DOM building blocks (shared by the renderers) ----

  function el(doc, tag, cls, text) {
    var e = doc.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }
  function act(e, name, data) {
    e.dataset.act = name;
    if (data) for (var k in data) if (Object.prototype.hasOwnProperty.call(data, k)) e.dataset[k] = String(data[k]);
    return e;
  }
  function label(e, text) {
    e.setAttribute("aria-label", text);
    return e;
  }

  // Inline SVG icons (createElementNS; no icon font, no images).
  var SVGNS = "http://www.w3.org/2000/svg";
  var ICONS = {
    search: { d: "M10.5 4a6.5 6.5 0 1 0 0 13 6.5 6.5 0 0 0 0-13zM15.5 15.5L21 21" },
    panel: { d: "M4 5h16v14H4zM14 5v14" },
    play: { d: "M8 5v14l11-7z", fill: true },
    back: { d: "M15 5l-7 7 7 7" },
    next: { d: "M9 5l7 7-7 7" },
    down: { d: "M6 9l6 6 6-6" },
    file: { d: "M6 3h8l4 4v14H6zM14 3v4h4" },
    close: { d: "M6 6l12 12M18 6L6 18" },
  };
  function icon(doc, name, size) {
    var def = ICONS[name];
    var mk = function (tag) {
      return doc.createElementNS ? doc.createElementNS(SVGNS, tag) : doc.createElement(tag);
    };
    var svg = mk("svg");
    var px = String(size || 20);
    svg.setAttribute("viewBox", "0 0 24 24");
    svg.setAttribute("width", px);
    svg.setAttribute("height", px);
    svg.setAttribute("class", "ico");
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("fill", def.fill ? "currentColor" : "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "2");
    svg.setAttribute("stroke-linecap", "round");
    svg.setAttribute("stroke-linejoin", "round");
    var path = mk("path");
    path.setAttribute("d", def.d);
    svg.appendChild(path);
    return svg;
  }

  // The avatar circle: initials on a colour (`color_idx`), with a small
  // member-count badge for a group.
  function renderAvatar(doc, who, size, badge) {
    var wrap = el(doc, "span", "av-wrap av-" + (size || "md"));
    var idx = Number(who && who.color_idx);
    var circle = el(doc, "span", "avatar av-c" + ((idx >= 0 && idx < 8 ? idx : 0) | 0));
    circle.textContent = (who && who.initials) || "?";
    wrap.appendChild(circle);
    if (badge != null && badge !== "") wrap.appendChild(el(doc, "span", "av-badge", String(badge)));
    return wrap;
  }

  // ---- left column ----

  // One conversation row: avatar, name, relative time, preview.
  function renderConversation(doc, conv, opts) {
    opts = opts || {};
    var row = el(doc, "button", "conv-row" + (opts.active ? " active" : ""));
    row.type = "button";
    row.dataset.convId = conv.id;
    row.dataset.group = conv.is_group ? "1" : "0";
    var showBadge = conv.is_group && conv.member_count != null;
    row.appendChild(renderAvatar(doc, { initials: conv.initials, color_idx: conv.color_idx }, "lg", showBadge ? conv.member_count : null));
    var main = el(doc, "span", "conv-main");
    var top = el(doc, "span", "conv-top");
    top.appendChild(el(doc, "span", "conv-name", conv.name || conv.id));
    top.appendChild(el(doc, "span", "conv-time", relTime(conv.last_ts, opts.now)));
    main.appendChild(top);
    main.appendChild(el(doc, "span", "conv-preview", previewText(conv)));
    row.appendChild(main);
    return row;
  }

  // Append `text` to `target` with <mark> around the query hits: only
  // text nodes and <mark> elements, never parsed markup.
  function appendHighlighted(doc, target, text, query) {
    snippetParts(text, query).forEach(function (p) {
      if (p.hit) target.appendChild(el(doc, "mark", "hit-mark", p.text));
      else target.appendChild(doc.createTextNode(p.text));
    });
  }

  // One search hit row: conversation name (global search only), the
  // highlighted snippet, time.
  function renderSearchHit(doc, hit, opts) {
    opts = opts || {};
    var row = el(doc, "button", "hit-row");
    row.type = "button";
    row.dataset.convId = hit.conv_id;
    row.dataset.msgId = hit.msg_id;
    row.dataset.ts = String(hit.ts);
    row.dataset.convName = hit.conv_name || "";
    if (opts.showConv !== false) row.appendChild(el(doc, "span", "hit-conv", hit.conv_name || hit.conv_id));
    var text = el(doc, "span", "hit-text");
    appendHighlighted(doc, text, hit.text || "", opts.query || "");
    row.appendChild(text);
    row.appendChild(el(doc, "span", "hit-ts", fmtTs(hit.ts)));
    return row;
  }

  // ---- attachments ----

  // The state of a message whose file is not on disk: import history the
  // live thread never picks, a dead link, or the raw status.
  function statusClass(a) {
    if (a.status === "ref-import") return "att-missing att-history";
    if (a.status === "expired") return "att-missing att-expired";
    return "att-missing";
  }
  function statusText(a) {
    if (a.status === "ref-import") return t("Mídia não baixada (histórico)");
    if (a.status === "expired") return t("Link expirado");
    return t("Mídia não baixada ({0})", [String(a.status || "ref")]);
  }

  // A small media tile (image thumb or video poster box with a play
  // overlay) for a message bubble, the info panel and the storage view.
  // `item` needs msg_id, idx, kind, has_local, status.
  function renderMediaTile(doc, item, cls) {
    var btn = el(doc, "button", "att-tile " + (cls || "att-img"));
    btn.type = "button";
    if (item.has_local && item.kind === "image") {
      var img = el(doc, "img", "att-thumb");
      img.alt = "";
      img.loading = "lazy";
      img.decoding = "async";
      img.src = mediaUrl(item.msg_id, item.idx, imageVariant(root.devicePixelRatio));
      btn.appendChild(img);
    } else if (item.has_local && item.kind === "video") {
      btn.className += " att-video";
      var vid = el(doc, "video", "att-thumb");
      vid.preload = "metadata";
      vid.muted = true;
      vid.src = mediaUrl(item.msg_id, item.idx);
      btn.appendChild(vid);
      var play = el(doc, "span", "play-ico");
      play.appendChild(icon(doc, "play", 20));
      btn.appendChild(play);
    } else {
      btn.className += " att-ph";
      btn.disabled = true;
      btn.appendChild(el(doc, "span", statusClass(item), statusText(item)));
      return btn;
    }
    act(btn, "lightbox", { msgId: item.msg_id, idx: item.idx });
    label(btn, item.kind === "video" ? t("Vídeo") : t("Imagem"));
    return btn;
  }

  // The coloured extension square of a file card.
  function renderFileIcon(doc, ext) {
    var ic = el(doc, "span", "file-ico " + extClass(ext));
    ic.appendChild(el(doc, "span", "file-ext", extLabel(ext)));
    return ic;
  }

  // A file card: coloured icon, name (2 lines), size and a check when
  // the file is on disk. Clickable (save) only when it is.
  function renderFileCard(doc, msgId, a) {
    var card = el(doc, "div", "file-card" + (a.has_local ? "" : " dim"));
    card.appendChild(renderFileIcon(doc, a.ext));
    var meta = el(doc, "span", "file-meta");
    meta.appendChild(el(doc, "span", "file-name", a.name || t("Arquivo sem nome")));
    var sub = el(doc, "span", "file-sub");
    var size = fmtSize(a.size);
    if (size) sub.appendChild(el(doc, "span", "file-size", size));
    if (a.has_local) sub.appendChild(el(doc, "span", "file-ok", "✓"));
    else sub.appendChild(el(doc, "span", statusClass(a), statusText(a)));
    meta.appendChild(sub);
    card.appendChild(meta);
    if (a.has_local) {
      card.setAttribute("role", "button");
      card.setAttribute("tabindex", "0");
      act(card, "save", { msgId: msgId, idx: a.idx });
    }
    return card;
  }

  // A link card: title, domain, description. No thumbnail (CSP) and no
  // href anywhere — a click asks the backend to open it.
  function renderLinkCard(doc, msgId, link) {
    var card = el(doc, "div", "link-card");
    card.setAttribute("role", "button");
    card.setAttribute("tabindex", "0");
    act(card, "link", { msgId: msgId });
    card.appendChild(el(doc, "span", "link-title", link.title || link.domain));
    card.appendChild(el(doc, "span", "link-domain", link.domain));
    if (link.description_preview) card.appendChild(el(doc, "span", "link-desc", link.description_preview));
    return card;
  }

  // One attachment of a bubble (not an image: images are grouped by
  // renderMessage). A downloaded voice/other kind is a label; anything
  // not downloaded shows its state. Never a url.
  function renderAttachment(doc, msgId, a) {
    var kind = String(a.kind || "other");
    var wrap = el(doc, "div", "msg-att att-" + kind);
    if (kind === "image" || kind === "video") {
      var item = { msg_id: msgId, idx: a.idx, kind: kind, has_local: a.has_local, status: a.status };
      wrap.appendChild(renderMediaTile(doc, item, "att-img"));
    } else if (kind === "file") {
      wrap.appendChild(renderFileCard(doc, msgId, a));
    } else if (a.has_local) {
      wrap.appendChild(el(doc, "span", "att-label", t("Anexo") + " · " + kind));
    } else {
      wrap.appendChild(el(doc, "span", statusClass(a), statusText(a)));
    }
    return wrap;
  }

  // ---- messages ----

  function renderSystemLine(doc, msg) {
    var line = el(doc, "div", "msg-sys");
    line.dataset.msgId = msg.msg_id;
    line.appendChild(el(doc, "span", "msg-sys-text", msg.text || ""));
    return line;
  }

  function renderQuote(doc, q) {
    var box = el(doc, "div", "quote");
    box.appendChild(el(doc, "span", "quote-name", q.sender_name || t("Desconhecido")));
    box.appendChild(el(doc, "span", "quote-text", q.text_preview || ""));
    return box;
  }

  // The images of one bubble: 1 alone, 2+ in a 2- or 3-column grid.
  function renderImageGroup(doc, msgId, imgs) {
    var n = imgs.length;
    var cls = n === 1 ? "att-grid one" : n === 2 || n === 4 ? "att-grid cols-2" : "att-grid cols-3";
    var grid = el(doc, "div", cls);
    imgs.forEach(function (a) {
      grid.appendChild(renderMediaTile(doc, { msg_id: msgId, idx: a.idx, kind: "image", has_local: a.has_local, status: a.status }, "att-img"));
    });
    return grid;
  }

  // One message: a system line, or a bubble row. `opts` carries the
  // layout decisions (showSender / showAvatar / showTime); by default the
  // avatar and the time show and the sender name does not.
  function renderMessage(doc, msg, opts) {
    if (isSystem(msg)) return renderSystemLine(doc, msg);
    opts = opts || {};
    var mine = !!msg.is_self;
    var gone = isGone(msg);
    var row = el(doc, "div", "msg msg-row " + (mine ? "mine" : "theirs") + (gone ? " gone" : ""));
    row.dataset.msgId = msg.msg_id;
    if (!mine) {
      var slot = el(doc, "div", "msg-av");
      if (opts.showAvatar !== false) {
        slot.appendChild(renderAvatar(doc, { initials: msg.sender_initials, color_idx: msg.sender_color }, "sm"));
      }
      row.appendChild(slot);
    }
    var col = el(doc, "div", "msg-col");
    if (opts.showSender && !mine) {
      col.appendChild(el(doc, "div", "msg-sender", msg.sender_name || t("Desconhecido")));
    }
    var wrap = el(doc, "div", "bubble-wrap");
    var bubble = el(doc, "div", "bubble");
    var content = false;
    if (gone) {
      bubble.appendChild(el(doc, "div", "msg-gone", isRecalled(msg) ? t("Mensagem recolhida") : t("Mensagem excluída")));
      content = true;
    }
    if (msg.quote) {
      bubble.appendChild(renderQuote(doc, msg.quote));
      content = true;
    }
    if (msg.text) {
      bubble.appendChild(el(doc, "div", "msg-text", msg.text));
      content = true;
    }
    var atts = msg.attachments || [];
    var imgs = [];
    var flush = function () {
      if (imgs.length) {
        bubble.appendChild(renderImageGroup(doc, msg.msg_id, imgs));
        content = true;
        imgs = [];
      }
    };
    atts.forEach(function (a) {
      if (a.kind === "image") {
        imgs.push(a);
        return;
      }
      flush();
      bubble.appendChild(renderAttachment(doc, msg.msg_id, a));
      content = true;
    });
    flush();
    if (atts.length && !msg.text && !msg.quote && !gone) bubble.className += " has-media";
    if (msg.link) {
      bubble.appendChild(renderLinkCard(doc, msg.msg_id, msg.link));
      content = true;
    }
    if (!content) {
      var chip = msg.type === 3 || msg.type === 11 ? t("[Sticker]") : t("[Mensagem não suportada]");
      bubble.appendChild(el(doc, "span", "chip", chip));
    }
    if (opts.showTime !== false) bubble.appendChild(el(doc, "span", "bubble-time", fmtHM(msg.ts)));
    wrap.appendChild(bubble);
    var rs = reactionSummary(msg.reactions);
    if (rs.total > 0 && !gone) {
      var pill = el(doc, "span", "reactions");
      rs.glyphs.forEach(function (g) { pill.appendChild(el(doc, "span", "react-emo", g)); });
      pill.appendChild(el(doc, "span", "react-n", String(rs.total)));
      wrap.appendChild(pill);
    }
    col.appendChild(wrap);
    row.appendChild(col);
    return row;
  }

  // A separator pill (day or time).
  function renderPill(doc, text) {
    var row = el(doc, "div", "pill-row");
    row.appendChild(el(doc, "span", "pill", text));
    return row;
  }

  // Every message of a conversation as DOM nodes, in order.
  function renderTimeline(doc, msgs, now, isGroup, highlightId) {
    return layoutMessages(msgs, now, isGroup).map(function (e) {
      if (e.kind === "pill") return renderPill(doc, e.text);
      if (e.kind === "sys") return renderSystemLine(doc, e.msg);
      var node = renderMessage(doc, e.msg, { showSender: e.showSender, showAvatar: e.showAvatar, showTime: e.showTime });
      if (highlightId && e.msg.msg_id === highlightId) node.className += " highlight";
      return node;
    });
  }

  // ---- right panel: info + storage view ----

  function rowDate(ts) {
    return ts ? fmtDate(ts, true) : "";
  }
  // A file row (info panel + storage view): icon, name, size, date.
  function renderFileRow(doc, f) {
    var row = el(doc, "div", "pf-row" + (f.has_local ? "" : " dim"));
    row.appendChild(renderFileIcon(doc, f.ext));
    var meta = el(doc, "span", "pf-meta");
    meta.appendChild(el(doc, "span", "pf-name", f.name || t("Arquivo sem nome")));
    var sub = el(doc, "span", "pf-sub");
    var size = fmtSize(f.size);
    if (size) sub.appendChild(el(doc, "span", "pf-size", size));
    if (f.has_local) sub.appendChild(el(doc, "span", "file-ok", "✓"));
    sub.appendChild(el(doc, "span", "pf-date", rowDate(f.ts)));
    meta.appendChild(sub);
    row.appendChild(meta);
    if (f.has_local) {
      row.setAttribute("role", "button");
      row.setAttribute("tabindex", "0");
      act(row, "save", { msgId: f.msg_id, idx: f.idx });
    }
    return row;
  }
  // A link row: title, domain, date.
  function renderLinkRow(doc, l) {
    var row = el(doc, "div", "pl-row");
    row.setAttribute("role", "button");
    row.setAttribute("tabindex", "0");
    act(row, "link", { msgId: l.msg_id });
    row.appendChild(el(doc, "span", "pl-title", l.title || l.domain));
    var sub = el(doc, "span", "pl-sub");
    sub.appendChild(el(doc, "span", "pl-domain", l.domain));
    sub.appendChild(el(doc, "span", "pl-date", rowDate(l.ts)));
    row.appendChild(sub);
    return row;
  }

  function sectionTitle(sec) {
    if (sec === "media") return t("Imagens/Vídeos");
    if (sec === "file") return t("Arquivos");
    return t("Links");
  }
  function emptyText(sec) {
    if (sec === "media") return t("Ainda não há imagens ou vídeos");
    if (sec === "file") return t("Ainda não há arquivos");
    return t("Ainda não há links");
  }

  // The "Thông tin hội thoại" body. `d` = {info, counts, media, files,
  // links, open:{media,file,link}} — all plain data from the commands.
  function renderInfoPanel(doc, d) {
    var info = d.info || {};
    var body = el(doc, "div", "pi-body");
    var hero = el(doc, "div", "pi-hero");
    hero.appendChild(renderAvatar(doc, { initials: info.initials, color_idx: info.color_idx }, "xl"));
    hero.appendChild(el(doc, "div", "pi-name", info.name || ""));
    if (info.is_group && info.member_count != null) {
      hero.appendChild(el(doc, "div", "pi-line", t("{0} membros", [info.member_count])));
    }
    if (info.first_ts && info.last_ts) {
      hero.appendChild(el(doc, "div", "pi-line", t("De {0} até {1}", [fmtDate(info.first_ts, true), fmtDate(info.last_ts, true)])));
    }
    if (info.msg_count != null) hero.appendChild(el(doc, "div", "pi-line", t("{0} mensagens", [info.msg_count])));
    body.appendChild(hero);
    var counts = d.counts || {};
    var open = d.open || { media: true, file: true, link: true };
    ["media", "file", "link"].forEach(function (sec) {
      var section = el(doc, "section", "p-sec" + (open[sec] === false ? " collapsed" : ""));
      section.dataset.sec = sec;
      var head = el(doc, "button", "p-sec-head");
      head.type = "button";
      act(head, "sec-toggle", { sec: sec });
      head.setAttribute("aria-expanded", open[sec] === false ? "false" : "true");
      head.appendChild(el(doc, "span", "p-sec-title", sectionTitle(sec)));
      if (counts[sec] != null) head.appendChild(el(doc, "span", "p-sec-count", String(counts[sec])));
      var caret = el(doc, "span", "p-caret");
      caret.appendChild(icon(doc, "down", 18));
      head.appendChild(caret);
      section.appendChild(head);
      var inner = el(doc, "div", "p-sec-body");
      var rows = sec === "media" ? d.media : sec === "file" ? d.files : d.links;
      rows = rows || [];
      if (!rows.length) {
        inner.appendChild(el(doc, "div", "p-empty", emptyText(sec)));
      } else {
        if (sec === "media") {
          var grid = el(doc, "div", "pm-grid");
          rows.slice(0, 8).forEach(function (m, i) {
            var tile = renderMediaTile(doc, m, "pm-thumb");
            if (tile.dataset.act) tile.dataset.src = "panel";
            tile.dataset.index = String(i);
            grid.appendChild(tile);
          });
          inner.appendChild(grid);
        } else if (sec === "file") {
          rows.slice(0, 3).forEach(function (f) { inner.appendChild(renderFileRow(doc, f)); });
        } else {
          rows.slice(0, 3).forEach(function (l) { inner.appendChild(renderLinkRow(doc, l)); });
        }
        var more = el(doc, "button", "p-more", t("Ver tudo"));
        more.type = "button";
        act(more, "store", { tab: sec });
        inner.appendChild(more);
      }
      section.appendChild(inner);
      body.appendChild(section);
    });
    return body;
  }

  // One row of the storage view; media tiles carry their index in the
  // loaded list so the lightbox can start there.
  function renderStoreItem(doc, tab, row, index) {
    if (tab === "media") {
      var tile = renderMediaTile(doc, row, "pm-thumb");
      if (tile.dataset.act) tile.dataset.src = "store";
      tile.dataset.index = String(index);
      return tile;
    }
    return tab === "file" ? renderFileRow(doc, row) : renderLinkRow(doc, row);
  }
  // Append rows to the storage list, opening a new month header (and a
  // new grid for media) whenever the month changes. `ctx` persists
  // between pages: {month, grid, count}.
  function appendStoreRows(doc, listEl, ctx, tab, rows) {
    rows.forEach(function (row) {
      var mk = monthKey(row.ts);
      if (ctx.month !== mk) {
        ctx.month = mk;
        listEl.appendChild(el(doc, "div", "store-month", monthLabel(row.ts)));
        ctx.grid = tab === "media" ? el(doc, "div", "store-grid") : null;
        if (ctx.grid) listEl.appendChild(ctx.grid);
      }
      var node = renderStoreItem(doc, tab, row, ctx.count);
      ctx.count++;
      (ctx.grid || listEl).appendChild(node);
    });
  }

  var api = {
    mediaBase: mediaBase,
    mediaUrl: mediaUrl,
    imageVariant: imageVariant,
    isRecalled: isRecalled,
    isGone: isGone,
    isSystem: isSystem,
    fmtTs: fmtTs,
    fmtHM: fmtHM,
    fmtDate: fmtDate,
    dayKey: dayKey,
    dayLabel: dayLabel,
    relTime: relTime,
    monthKey: monthKey,
    monthLabel: monthLabel,
    fmtSize: fmtSize,
    extClass: extClass,
    extLabel: extLabel,
    kindLabel: kindLabel,
    previewText: previewText,
    reactionGlyph: reactionGlyph,
    reactionSummary: reactionSummary,
    fold: fold,
    snippetParts: snippetParts,
    layoutMessages: layoutMessages,
    mediaItemsFromMessages: mediaItemsFromMessages,
    rowCursor: rowCursor,
    errorMessage: errorMessage,
    makeDebounce: makeDebounce,
    icon: icon,
    renderAvatar: renderAvatar,
    renderConversation: renderConversation,
    renderSearchHit: renderSearchHit,
    renderMediaTile: renderMediaTile,
    renderFileCard: renderFileCard,
    renderLinkCard: renderLinkCard,
    renderAttachment: renderAttachment,
    renderMessage: renderMessage,
    renderPill: renderPill,
    renderTimeline: renderTimeline,
    renderFileRow: renderFileRow,
    renderLinkRow: renderLinkRow,
    renderInfoPanel: renderInfoPanel,
    renderStoreItem: renderStoreItem,
    appendStoreRows: appendStoreRows,
  };
  root.Archive = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  if (typeof document === "undefined" || !document.getElementById) return;

  // ---- DOM wiring ----------------------------------------------------------

  var invoke = root.__TAURI__.core.invoke;
  var $ = function (id) { return document.getElementById(id); };
  var convListEl = $("conv-list");
  var convRowsEl = $("conv-rows");
  var convEmptyEl = $("conv-empty");
  var convSentinel = $("conv-sentinel");
  var filterTabsEl = $("filter-tabs");
  var searchEl = $("search");
  var searchClearEl = $("search-clear");
  var resultsEl = $("search-results");
  var headEl = $("chat-head");
  var headAvatarEl = $("head-avatar");
  var headNameEl = $("head-name");
  var headSubEl = $("head-sub");
  var btnChatSearch = $("btn-chat-search");
  var btnPanel = $("btn-panel");
  var inchatEl = $("inchat");
  var inchatInput = $("inchat-input");
  var inchatCount = $("inchat-count");
  var inchatResults = $("inchat-results");
  var msgEmptyEl = $("msg-empty");
  var msgsEl = $("msgs");
  var msgListEl = $("msg-list");
  var msgSentinel = $("msg-sentinel");
  var jumpLatestEl = $("jump-latest");
  var panelEl = $("right-panel");
  var lbEl = $("lightbox");
  var lbStage = $("lb-stage");
  var lbCaption = $("lb-caption");
  var lbPrev = $("lb-prev");
  var lbNext = $("lb-next");
  var lbOrig = $("lb-orig");
  var lbGoto = $("lb-goto");
  var toastEl = $("toast");

  var PAGE = 50;
  var MAX_MSGS = 600; // DOM cap: the newest end is dropped beyond this

  var S = {
    convs: [], convCursor: null, convExhausted: false, convLoading: false, filter: "all",
    searchQ: "",
    cur: null, gen: 0,
    msgs: [], msgCursor: null, msgExhausted: false, msgLoading: false, hasNewer: false,
    highlight: null, stick: false,
    info: null, counts: null, pmedia: [], pfiles: [], plinks: [],
    open: { media: true, file: true, link: true },
    panelOpen: true,
    store: null,
    lb: null,
  };

  // Panel state is remembered per viewer; storage can be blocked.
  try {
    if (root.localStorage && root.localStorage.getItem("zr.archive.panelOpen") === "0") S.panelOpen = false;
  } catch (_) { /* storage unavailable: keep the default */ }
  function savePanelOpen() {
    try {
      if (root.localStorage) root.localStorage.setItem("zr.archive.panelOpen", S.panelOpen ? "1" : "0");
    } catch (_) { /* storage unavailable */ }
  }

  var toastTimer = 0;
  function toast(text) {
    toastEl.textContent = text || "";
    toastEl.hidden = !text;
    if (toastTimer) clearTimeout(toastTimer);
    if (text) toastTimer = setTimeout(function () { toastEl.hidden = true; }, 3200);
  }
  function fail(e) {
    toast(errorMessage(e));
  }

  function put(slotId, name, size) {
    var slot = typeof slotId === "string" ? $(slotId) : slotId;
    slot.textContent = "";
    slot.appendChild(icon(document, name, size));
  }
  put("ico-search", "search", 18);
  put("ico-inchat", "search", 18);
  put(searchClearEl, "close", 14);
  put($("inchat-close"), "close", 16);
  put(btnChatSearch, "search", 20);
  put(btnPanel, "panel", 20);
  put($("lb-close"), "close", 24);
  put(lbPrev, "back", 28);
  put(lbNext, "next", 28);

  // -- the left column: conversations (infinite scroll, keyset cursor) --

  function visibleConvs() {
    return S.convs.filter(function (c) {
      return S.filter === "all" || (S.filter === "group" ? c.is_group : !c.is_group);
    });
  }
  function convRow(c) {
    return renderConversation(document, c, { active: !!(S.cur && S.cur.id === c.id), now: Date.now() });
  }
  function renderConvList() {
    convRowsEl.textContent = "";
    var list = visibleConvs();
    list.forEach(function (c) { convRowsEl.appendChild(convRow(c)); });
    convEmptyEl.hidden = list.length > 0 || S.convLoading || !S.convExhausted;
    fillList();
  }
  function markActive() {
    for (var n = convRowsEl.firstChild; n; n = n.nextSibling) {
      if (n.classList) n.classList.toggle("active", !!(S.cur && n.dataset.convId === S.cur.id));
    }
  }

  async function loadConversations() {
    if (S.convLoading || S.convExhausted) return;
    S.convLoading = true;
    try {
      var rows = await invoke("archive_list_conversations", { before: S.convCursor, limit: PAGE });
      if (!rows.length) S.convExhausted = true;
      rows.forEach(function (c) {
        S.convs.push(c);
        S.convCursor = [c.last_ts == null ? 0 : c.last_ts, c.id];
        if (S.filter === "all" || (S.filter === "group" ? c.is_group : !c.is_group)) convRowsEl.appendChild(convRow(c));
      });
      convEmptyEl.hidden = visibleConvs().length > 0 || !S.convExhausted;
    } catch (e) {
      S.convExhausted = true; // do not hammer a failing backend
      fail(e);
    } finally {
      S.convLoading = false;
    }
    fillList();
  }
  // A filter can hide most of a page: keep loading while the list does
  // not even fill its box (the observer only fires on a change).
  function fillList() {
    if (S.convExhausted || S.convLoading) return;
    if (convListEl.scrollHeight <= convListEl.clientHeight + 160) setTimeout(loadConversations, 0);
  }
  if (root.IntersectionObserver) {
    new root.IntersectionObserver(function (es) {
      if (es.some(function (x) { return x.isIntersecting; })) loadConversations();
    }, { root: convListEl, rootMargin: "240px" }).observe(convSentinel);
  } else {
    convListEl.addEventListener("scroll", function () {
      if (convListEl.scrollTop + convListEl.clientHeight >= convListEl.scrollHeight - 240) loadConversations();
    });
  }

  convRowsEl.addEventListener("click", function (ev) {
    var row = ev.target.closest(".conv-row");
    if (!row) return;
    var c = S.convs.filter(function (x) { return x.id === row.dataset.convId; })[0];
    if (c) openConv(c, null);
  });
  filterTabsEl.addEventListener("click", function (ev) {
    var tab = ev.target.closest(".tab");
    if (!tab) return;
    S.filter = tab.dataset.filter;
    for (var n = filterTabsEl.firstChild; n; n = n.nextSibling) {
      if (!n.classList) continue;
      var on = n === tab;
      n.classList.toggle("active", on);
      n.setAttribute("aria-selected", on ? "true" : "false");
    }
    renderConvList();
  });
  // Up / down moves through the conversations while the list has focus.
  convListEl.addEventListener("keydown", function (ev) {
    if (ev.key !== "ArrowDown" && ev.key !== "ArrowUp") return;
    var rows = Array.prototype.slice.call(convRowsEl.querySelectorAll(".conv-row"));
    if (!rows.length) return;
    ev.preventDefault();
    var at = -1;
    rows.forEach(function (r, i) { if (S.cur && r.dataset.convId === S.cur.id) at = i; });
    var focused = rows.indexOf(document.activeElement);
    if (focused >= 0) at = focused;
    var next = Math.max(0, Math.min(rows.length - 1, at + (ev.key === "ArrowDown" ? 1 : -1)));
    if (at < 0) next = 0;
    rows[next].focus();
    rows[next].click();
    rows[next].scrollIntoView({ block: "nearest" });
  });

  // -- global search: results replace the list while the box has text --

  var runSearch = makeDebounce(doSearch, 300);

  function showSearchMode(on) {
    resultsEl.hidden = !on;
    convListEl.hidden = on;
    filterTabsEl.hidden = on;
    searchClearEl.hidden = !searchEl.value;
  }
  function clearSearch() {
    searchEl.value = "";
    S.searchQ = "";
    resultsEl.textContent = "";
    showSearchMode(false);
  }
  async function doSearch(q) {
    if (searchEl.value.trim() !== q) return; // a newer keystroke won
    try {
      var rows = await invoke("archive_search", { query: q, limit: PAGE });
      if (searchEl.value.trim() !== q) return;
      resultsEl.textContent = "";
      if (!rows.length) {
        resultsEl.appendChild(el(document, "div", "hit-empty", t("Nenhuma mensagem encontrada.")));
        return;
      }
      resultsEl.appendChild(el(document, "div", "hit-title", t("Resultados")));
      rows.forEach(function (h) { resultsEl.appendChild(renderSearchHit(document, h, { query: q })); });
    } catch (e) {
      fail(e);
    }
  }
  searchEl.addEventListener("input", function () {
    var q = searchEl.value.trim();
    S.searchQ = q;
    if (!q) {
      clearSearch();
      return;
    }
    showSearchMode(true);
    runSearch(q);
  });
  searchClearEl.addEventListener("click", function () {
    clearSearch();
    searchEl.focus();
  });
  resultsEl.addEventListener("click", function (ev) {
    var row = ev.target.closest(".hit-row");
    if (!row) return;
    openConv({ id: row.dataset.convId, name: row.dataset.convName }, { msg_id: row.dataset.msgId, ts: Number(row.dataset.ts) });
  });

  // -- selecting a conversation --

  function convFromRow(c) {
    return {
      id: c.id, name: c.name || c.id, is_group: !!c.is_group, member_count: c.member_count == null ? null : c.member_count,
      initials: c.initials || "?", color_idx: c.color_idx | 0,
    };
  }
  function renderHead() {
    var c = S.cur;
    headEl.hidden = !c;
    if (!c) return;
    headAvatarEl.textContent = "";
    headAvatarEl.appendChild(renderAvatar(document, c, "md"));
    headNameEl.textContent = c.name || c.id;
    headSubEl.textContent = c.is_group && c.member_count != null ? t("{0} membros", [c.member_count]) : "";
    headSubEl.hidden = !headSubEl.textContent;
  }

  // Open a conversation (optionally at a message). The same conversation
  // with a jump only reloads the messages.
  function openConv(c, jump) {
    var same = S.cur && S.cur.id === c.id;
    var known = S.convs.filter(function (x) { return x.id === c.id; })[0];
    if (!same) {
      S.gen++;
      S.cur = known ? convFromRow(known) : { id: c.id, name: c.name || c.id, is_group: false, member_count: null, initials: "?", color_idx: 0 };
      S.store = null;
      S.info = null; S.counts = null; S.pmedia = []; S.pfiles = []; S.plinks = [];
      closeInchat();
      renderHead();
      markActive();
      loadPanelData(S.gen);
    }
    renderPanel();
    resetMessages();
    msgsEl.hidden = false;
    msgEmptyEl.hidden = true;
    loadMessages(jump ? { jump: jump } : {});
  }

  // -- messages (newest at the bottom; older pages prepend) --

  function resetMessages() {
    S.msgGen = (S.msgGen || 0) + 1;
    S.msgs = [];
    S.msgCursor = null;
    S.msgExhausted = false;
    S.msgLoading = false;
    S.hasNewer = false;
    S.highlight = null;
    S.stick = false;
    msgListEl.textContent = "";
    jumpLatestEl.hidden = true;
  }

  function renderTimelineNow(opts) {
    var prevHeight = msgsEl.scrollHeight;
    var nodes = renderTimeline(document, S.msgs, Date.now(), !!(S.cur && S.cur.is_group), S.highlight);
    var frag = document.createDocumentFragment();
    nodes.forEach(function (n) { frag.appendChild(n); });
    msgListEl.textContent = "";
    msgListEl.appendChild(frag);
    jumpLatestEl.hidden = !S.hasNewer;
    if (opts && opts.older) {
      // Keep the viewport anchored on what the user was reading.
      msgsEl.scrollTop += msgsEl.scrollHeight - prevHeight;
    } else if (opts && opts.jump) {
      var hitEl = msgListEl.querySelector(".msg.highlight");
      if (hitEl) hitEl.scrollIntoView({ block: "center" });
      S.stick = false;
      var keep = S.highlight;
      setTimeout(function () {
        if (S.highlight === keep) S.highlight = null;
        var h = msgListEl.querySelector(".msg.highlight");
        if (h) h.classList.remove("highlight");
      }, 4000);
    } else {
      S.stick = true;
      msgsEl.scrollTop = msgsEl.scrollHeight;
    }
  }

  async function loadMessages(opts) {
    if (!S.cur || S.msgLoading || S.msgExhausted) return;
    S.msgLoading = true;
    var gen = S.msgGen;
    var convId = S.cur.id;
    var older = !!(opts && opts.older);
    try {
      var before = null;
      if (older) before = S.msgCursor;
      else if (opts && opts.jump) before = [opts.jump.ts, opts.jump.msg_id + "\uffff"]; // the hit itself included
      var rows = await invoke("archive_list_messages", { convId: convId, before: before, limit: PAGE });
      if (gen !== S.msgGen) return; // another conversation was opened meanwhile
      if (!rows.length) {
        S.msgExhausted = true;
        return;
      }
      rows.reverse(); // the command returns newest first; the chat reads oldest first
      S.msgCursor = [rows[0].ts, rows[0].msg_id];
      if (older) {
        S.msgs = rows.concat(S.msgs);
        if (S.msgs.length > MAX_MSGS) {
          // Drop the far (newest) end; the oldest cursor stays valid and
          // a "latest messages" button reloads from the newest.
          S.msgs = S.msgs.slice(0, MAX_MSGS);
          S.hasNewer = true;
        }
      } else {
        S.msgs = rows;
        if (opts && opts.jump) {
          S.hasNewer = true;
          S.highlight = opts.jump.msg_id;
        }
      }
      renderTimelineNow(older ? { older: true } : opts && opts.jump ? { jump: true } : null);
    } catch (e) {
      fail(e);
    } finally {
      if (gen === S.msgGen) S.msgLoading = false;
    }
    if (gen === S.msgGen && !S.msgExhausted && msgsEl.scrollTop < 240) setTimeout(function () { loadMessages({ older: true }); }, 0);
  }

  if (root.IntersectionObserver) {
    new root.IntersectionObserver(function (es) {
      if (S.msgs.length && es.some(function (x) { return x.isIntersecting; })) loadMessages({ older: true });
    }, { root: msgsEl, rootMargin: "240px" }).observe(msgSentinel);
  }
  msgsEl.addEventListener("scroll", function () {
    S.stick = msgsEl.scrollHeight - msgsEl.scrollTop - msgsEl.clientHeight < 80;
    if (!root.IntersectionObserver && msgsEl.scrollTop < 240 && S.msgs.length) loadMessages({ older: true });
  });
  // Images load after the first paint and grow the list: stay at the
  // bottom while the user has not scrolled away.
  msgsEl.addEventListener("load", function () {
    if (S.stick) msgsEl.scrollTop = msgsEl.scrollHeight;
  }, true);
  jumpLatestEl.addEventListener("click", function () {
    resetMessages();
    loadMessages({});
  });

  // -- header buttons and the in-conversation search --

  function closeInchat() {
    inchatEl.hidden = true;
    inchatInput.value = "";
    inchatResults.textContent = "";
    inchatResults.hidden = true;
    inchatCount.textContent = "";
    btnChatSearch.classList.remove("on");
  }
  btnChatSearch.addEventListener("click", function () {
    if (!inchatEl.hidden) {
      closeInchat();
      return;
    }
    inchatEl.hidden = false;
    btnChatSearch.classList.add("on");
    inchatInput.focus();
  });
  $("inchat-close").addEventListener("click", closeInchat);
  var runInchat = makeDebounce(doInchat, 300);
  async function doInchat(q) {
    if (!S.cur || inchatInput.value.trim() !== q) return;
    var gen = S.gen;
    try {
      // One page only: this search has no cursor, so no "load more".
      var rows = await invoke("archive_search", { query: q, convId: S.cur.id, limit: PAGE });
      if (gen !== S.gen || inchatInput.value.trim() !== q) return;
      inchatResults.textContent = "";
      inchatResults.hidden = false;
      inchatCount.textContent = rows.length ? t("{0} resultados", [rows.length]) : "";
      if (!rows.length) {
        inchatResults.appendChild(el(document, "div", "hit-empty", t("Nenhuma mensagem encontrada.")));
        return;
      }
      rows.forEach(function (h) { inchatResults.appendChild(renderSearchHit(document, h, { query: q, showConv: false })); });
    } catch (e) {
      fail(e);
    }
  }
  inchatInput.addEventListener("input", function () {
    var q = inchatInput.value.trim();
    if (!q) {
      inchatResults.textContent = "";
      inchatResults.hidden = true;
      inchatCount.textContent = "";
      return;
    }
    runInchat(q);
  });
  inchatResults.addEventListener("click", function (ev) {
    var row = ev.target.closest(".hit-row");
    if (!row || !S.cur) return;
    inchatResults.hidden = true;
    openConv(S.cur, { msg_id: row.dataset.msgId, ts: Number(row.dataset.ts) });
  });
  btnPanel.addEventListener("click", function () {
    S.panelOpen = !S.panelOpen;
    savePanelOpen();
    renderPanel();
  });

  // -- the right panel --

  async function loadPanelData(gen) {
    var id = S.cur.id;
    var ok = function (p, fallback) { return p.catch(function () { return fallback; }); };
    var res = await Promise.all([
      ok(invoke("archive_conv_info", { convId: id }), null),
      ok(invoke("archive_conv_media_counts", { convId: id }), null),
      ok(invoke("archive_conv_media", { convId: id, tab: "media", before: null, limit: 8 }), []),
      ok(invoke("archive_conv_media", { convId: id, tab: "file", before: null, limit: 3 }), []),
      ok(invoke("archive_conv_media", { convId: id, tab: "link", before: null, limit: 3 }), []),
    ]);
    if (gen !== S.gen) return;
    S.info = res[0];
    S.counts = res[1];
    S.pmedia = res[2];
    S.pfiles = res[3];
    S.plinks = res[4];
    if (S.info) {
      var wasGroup = S.cur.is_group;
      S.cur.name = S.info.name || S.cur.name;
      S.cur.is_group = !!S.info.is_group;
      S.cur.member_count = S.info.member_count == null ? null : S.info.member_count;
      S.cur.initials = S.info.initials || S.cur.initials;
      S.cur.color_idx = S.info.color_idx | 0;
      renderHead();
      if (wasGroup !== S.cur.is_group && S.msgs.length) renderTimelineNow({ older: true });
    }
    renderPanel();
  }

  function panelHeader(title, back) {
    var head = el(document, "div", "panel-head");
    if (back) {
      var b = el(document, "button", "icon-btn");
      b.type = "button";
      label(b, t("Voltar"));
      act(b, "store-back");
      b.appendChild(icon(document, "back", 20));
      head.appendChild(b);
    }
    head.appendChild(el(document, "div", "panel-title", title));
    return head;
  }

  function renderPanel() {
    panelEl.hidden = !S.panelOpen;
    btnPanel.classList.toggle("on", S.panelOpen);
    btnPanel.setAttribute("aria-pressed", S.panelOpen ? "true" : "false");
    panelEl.textContent = "";
    if (!S.panelOpen) return;
    if (S.store) {
      renderStoreFrame();
      return;
    }
    panelEl.appendChild(panelHeader(t("Informações da conversa"), false));
    var scroller = el(document, "div", "panel-scroll");
    if (!S.cur) {
      scroller.appendChild(el(document, "div", "archive-empty", t("Selecione uma conversa")));
    } else if (!S.info) {
      scroller.appendChild(el(document, "div", "archive-empty", t("Carregando…")));
    } else {
      scroller.appendChild(renderInfoPanel(document, {
        info: S.info, counts: S.counts, media: S.pmedia, files: S.pfiles, links: S.plinks, open: S.open,
      }));
    }
    panelEl.appendChild(scroller);
  }

  // -- the "Kho lưu trữ" view: media / files / links, infinite lists --

  var STORE_TABS = ["media", "file", "link"];
  function renderStoreFrame() {
    var st = S.store;
    if (st.io) st.io.disconnect();
    panelEl.appendChild(panelHeader(t("Acervo"), true));
    var tabs = el(document, "div", "store-tabs");
    tabs.setAttribute("role", "tablist");
    STORE_TABS.forEach(function (tab) {
      var b = el(document, "button", "tab" + (st.tab === tab ? " active" : ""), sectionTitle(tab));
      b.type = "button";
      b.setAttribute("role", "tab");
      b.setAttribute("aria-selected", st.tab === tab ? "true" : "false");
      act(b, "store-tab", { tab: tab });
      tabs.appendChild(b);
    });
    panelEl.appendChild(tabs);
    var list = el(document, "div", "store-list");
    list.setAttribute("tabindex", "0");
    st.listEl = list;
    var sentinel = el(document, "div", "sentinel");
    st.sentinel = sentinel;
    list.appendChild(sentinel);
    panelEl.appendChild(list);
    if (root.IntersectionObserver) {
      var io = new root.IntersectionObserver(function (es) {
        if (es.some(function (x) { return x.isIntersecting; })) loadStore();
      }, { root: list, rootMargin: "200px" });
      io.observe(sentinel);
      st.io = io;
    } else {
      list.addEventListener("scroll", function () {
        if (list.scrollTop + list.clientHeight >= list.scrollHeight - 200) loadStore();
      });
    }
    replayStore();
  }
  // (Re)build the list from the rows already loaded, then continue.
  function replayStore() {
    var st = S.store;
    st.ctx = { month: null, grid: null, count: 0 };
    var frag = document.createDocumentFragment();
    appendStoreRows(document, frag, st.ctx, st.tab, st.rows);
    st.listEl.insertBefore(frag, st.sentinel);
    if (!st.exhausted) setTimeout(loadStore, 0);
    else if (!st.rows.length) st.listEl.insertBefore(el(document, "div", "archive-empty", emptyText(st.tab)), st.sentinel);
  }
  function openStore(tab) {
    if (!S.cur) return;
    S.store = { tab: tab, rows: [], cursor: null, exhausted: false, loading: false, id: S.cur.id, gen: 0 };
    S.panelOpen = true;
    renderPanel();
  }
  function closeStore() {
    S.store = null;
    renderPanel();
  }
  async function loadStore() {
    var st = S.store;
    if (!st || st.loading || st.exhausted) return;
    st.loading = true;
    var tab = st.tab;
    var gen = st.gen;
    try {
      var rows = await invoke("archive_conv_media", { convId: st.id, tab: tab, before: st.cursor, limit: PAGE });
      if (S.store !== st || st.tab !== tab || st.gen !== gen) return;
      if (!rows.length) {
        st.exhausted = true;
        if (!st.rows.length) st.listEl.insertBefore(el(document, "div", "archive-empty", emptyText(tab)), st.sentinel);
        return;
      }
      st.cursor = rowCursor(rows[rows.length - 1]);
      st.rows = st.rows.concat(rows);
      var frag = document.createDocumentFragment();
      appendStoreRows(document, frag, st.ctx, tab, rows);
      st.listEl.insertBefore(frag, st.sentinel);
      if (S.lb && S.lb.fromStore === st) S.lb.items = st.rows;
    } catch (e) {
      st.exhausted = true;
      fail(e);
    } finally {
      st.loading = false;
    }
    if (S.store === st && st.tab === tab && !st.exhausted && st.listEl.scrollHeight <= st.listEl.clientHeight + 160) {
      setTimeout(loadStore, 0);
    }
  }
  function switchStoreTab(tab) {
    var st = S.store;
    if (!st || st.tab === tab) return;
    st.tab = tab;
    st.rows = [];
    st.cursor = null;
    st.exhausted = false;
    st.loading = false;
    st.gen++;
    panelEl.textContent = "";
    renderStoreFrame();
  }

  // -- delegated clicks inside the panel and the bubbles --

  async function saveAttachment(msgId, idx) {
    try {
      var r = await invoke("archive_save_attachment", { msgId: msgId, idx: Number(idx) });
      if (r && r.saved) toast(t("Salvo"));
    } catch (e) {
      fail(e);
    }
  }
  async function openLink(msgId) {
    try {
      await invoke("archive_open_link", { msgId: msgId });
    } catch (e) {
      fail(e);
    }
  }

  function handleAct(ev) {
    var node = ev.target.closest ? ev.target.closest("[data-act]") : null;
    if (!node) return;
    var a = node.dataset.act;
    if (a === "lightbox") {
      if (node.dataset.src === "panel") openLightbox(S.pmedia, Number(node.dataset.index), null);
      else if (node.dataset.src === "store" && S.store) openLightbox(S.store.rows, Number(node.dataset.index), S.store);
      else openLightboxFromChat(node.dataset.msgId, Number(node.dataset.idx));
    } else if (a === "save") saveAttachment(node.dataset.msgId, node.dataset.idx);
    else if (a === "link") openLink(node.dataset.msgId);
    else if (a === "store") openStore(node.dataset.tab);
    else if (a === "store-back") closeStore();
    else if (a === "store-tab") switchStoreTab(node.dataset.tab);
    else if (a === "sec-toggle") {
      var sec = node.dataset.sec;
      S.open[sec] = S.open[sec] === false;
      var section = node.closest(".p-sec");
      section.classList.toggle("collapsed", S.open[sec] === false);
      node.setAttribute("aria-expanded", S.open[sec] === false ? "false" : "true");
    }
  }
  [msgListEl, panelEl].forEach(function (host) {
    host.addEventListener("click", handleAct);
    // Cards behave like buttons from the keyboard too.
    host.addEventListener("keydown", function (ev) {
      if ((ev.key === "Enter" || ev.key === " ") && ev.target.getAttribute && ev.target.getAttribute("role") === "button") {
        ev.preventDefault();
        handleAct(ev);
      }
    });
  });

  // -- the lightbox --

  function openLightboxFromChat(msgId, idx) {
    var items = mediaItemsFromMessages(S.msgs);
    var at = -1;
    items.forEach(function (m, i) { if (m.msg_id === msgId && m.idx === idx) at = i; });
    if (at < 0) return;
    openLightbox(items, at, null);
  }
  function openLightbox(items, index, fromStore) {
    if (!items.length || !(index >= 0 && index < items.length)) return;
    S.lb = {
      items: items, index: index, orig: false, loading: false, fromStore: fromStore,
      exhausted: false, restore: document.activeElement,
    };
    lbEl.hidden = false;
    showLightbox();
    $("lb-close").focus();
  }
  function closeLightbox() {
    if (!S.lb) return;
    var back = S.lb.restore;
    S.lb = null;
    lbEl.hidden = true;
    lbStage.textContent = "";
    if (back && back.focus) back.focus();
  }
  function senderOf(item) {
    if (item.sender_name) return item.sender_name;
    for (var i = 0; i < S.msgs.length; i++) {
      if (S.msgs[i].msg_id === item.msg_id) return S.msgs[i].is_self ? t("Você") : S.msgs[i].sender_name || "";
    }
    return "";
  }
  function showLightbox() {
    var lb = S.lb;
    var item = lb.items[lb.index];
    lbStage.textContent = "";
    if (item.has_local && item.kind === "video") {
      var v = document.createElement("video");
      v.className = "lb-media";
      v.controls = true;
      v.autoplay = true;
      v.preload = "metadata";
      v.src = mediaUrl(item.msg_id, item.idx);
      lbStage.appendChild(v);
    } else if (item.has_local) {
      var img = document.createElement("img");
      img.className = "lb-media";
      img.alt = "";
      img.decoding = "async";
      img.src = mediaUrl(item.msg_id, item.idx, lb.orig ? "orig" : "view");
      lbStage.appendChild(img);
    } else {
      lbStage.appendChild(el(document, "span", statusClass(item) + " lb-missing", statusText(item)));
    }
    var who = senderOf(item);
    lbCaption.textContent = (who ? who + " · " : "") + fmtDate(item.ts, true) + " " + fmtHM(item.ts);
    lbOrig.hidden = !(item.has_local && item.kind === "image");
    lbOrig.disabled = lb.orig;
    lbPrev.hidden = !(lb.index + 1 < lb.items.length || !lbExhausted());
    lbNext.hidden = lb.index <= 0;
  }
  function lbExhausted() {
    var lb = S.lb;
    return !lb || (lb.fromStore ? lb.fromStore.exhausted : lb.exhausted);
  }
  // Older media: the storage view pages itself; chat/panel lists continue
  // with the next page of archive_conv_media after the last item held.
  async function lbMore() {
    var lb = S.lb;
    if (!lb || lb.loading || lbExhausted() || !S.cur) return;
    lb.loading = true;
    try {
      if (lb.fromStore) {
        await loadStore();
        if (S.lb === lb) lb.items = lb.fromStore.rows;
      } else {
        var last = lb.items[lb.items.length - 1];
        var rows = await invoke("archive_conv_media", { convId: S.cur.id, tab: "media", before: rowCursor(last), limit: PAGE });
        if (S.lb !== lb) return;
        if (!rows.length) lb.exhausted = true;
        else lb.items = lb.items.concat(rows);
      }
    } catch (e) {
      lb.exhausted = true;
      fail(e);
    } finally {
      lb.loading = false;
    }
  }
  async function lbStep(dir) {
    var lb = S.lb;
    if (!lb) return;
    if (dir > 0 && lb.index + 1 >= lb.items.length) await lbMore(); // older = further down the list
    if (S.lb !== lb) return;
    var next = lb.index + dir;
    if (next < 0 || next >= lb.items.length) {
      showLightbox();
      return;
    }
    lb.index = next;
    lb.orig = false;
    showLightbox();
  }
  lbPrev.addEventListener("click", function () { lbStep(1); });
  lbNext.addEventListener("click", function () { lbStep(-1); });
  $("lb-close").addEventListener("click", closeLightbox);
  lbOrig.addEventListener("click", function () {
    if (!S.lb) return;
    S.lb.orig = true;
    showLightbox();
  });
  lbGoto.addEventListener("click", function () {
    if (!S.lb || !S.cur) return;
    var item = S.lb.items[S.lb.index];
    closeLightbox();
    S.store = null;
    openConv(S.cur, { msg_id: item.msg_id, ts: item.ts });
  });
  lbEl.addEventListener("click", function (ev) {
    if (ev.target === lbEl || ev.target === lbStage) closeLightbox();
  });

  // -- keyboard: Esc closes the lightbox, then the storage view, then
  //    the in-conversation search, then the global search --

  document.addEventListener("keydown", function (ev) {
    if (S.lb) {
      if (ev.key === "Escape") closeLightbox();
      else if (ev.key === "ArrowLeft") lbStep(1);
      else if (ev.key === "ArrowRight") lbStep(-1);
      else return;
      ev.preventDefault();
      return;
    }
    if (ev.key !== "Escape") return;
    if (S.store) closeStore();
    else if (!inchatEl.hidden) closeInchat();
    else if (searchEl.value) clearSearch();
  });

  // -- boot --

  renderPanel();
  loadConversations();
})(typeof window !== "undefined" ? window : globalThis);
