"use strict";
// Lưu trữ (archive) window — audit §4 Phase 3 item 3.2, batch 11.
//
// Layout: conversation list on the left (infinite scroll via the
// (last_ts, id) keyset cursor), messages on the right (newest at the
// bottom, older pages prepend on scroll up), a debounced search box
// whose results jump to the hit, and a small header with counts.
//
// SAFETY: every piece of shadow-DB data is rendered through
// createElement + textContent — never HTML-string parsing (the node
// test pins both the source and the rendered structure). Media is
// loaded exclusively through the internal zrarchive:// scheme (K3),
// keyed by msg_id/idx; the URL never carries a file path.
(function (root) {
  // ---- pure helpers (node-tested) ----------------------------------------

  // The media-scheme base Rust injected (WebView2 maps custom schemes
  // onto http://<scheme>.localhost; macOS/Linux keep scheme://localhost).
  function mediaBase() {
    return root.__ZR_ARCHIVE_MEDIA__ || "zrarchive://localhost";
  }

  // Media URL for one attachment: ids only, never a path.
  function mediaUrl(msgId, idx) {
    return mediaBase() + "/media/" + encodeURIComponent(String(msgId)) + "/" + Number(idx);
  }

  function isRecalled(msg) {
    // normalize::msg_type_code's recall family (batch 25: chat.delete,
    // chat.undo, chat.delete.everyone, V1 recall — all code 8).
    return msg.type === 8;
  }
  function isGone(msg) {
    return !!(msg.deleted || msg.type === 8);
  }

  // "HH:MM" for today, else "DD/MM/YY HH:MM" — the archive reads
  // better with the local convention; I18n picks the locale.
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

  function t(s, args) {
    return root.t ? root.t(s, args) : s;
  }

  // One conversation row for the left pane.
  function renderConversation(doc, conv) {
    var row = doc.createElement("button");
    row.type = "button";
    row.className = "conv-row";
    row.dataset.convId = conv.id;
    var name = doc.createElement("span");
    name.className = "conv-name";
    name.textContent = conv.name || conv.id;
    var preview = doc.createElement("span");
    preview.className = "conv-preview";
    preview.textContent = conv.last_msg_preview || "";
    row.appendChild(name);
    row.appendChild(preview);
    return row;
  }

  // One attachment: a downloaded image/video through the media scheme;
  // other downloaded kinds as a label; anything not downloaded shows
  // its status (ref | failed | ref-encrypted).
  function renderAttachment(doc, msgId, a) {
    var wrap = doc.createElement("div");
    wrap.className = "msg-att att-" + String(a.kind || "other");
    if (a.has_local && a.kind === "image") {
      var img = doc.createElement("img");
      img.className = "att-media";
      img.alt = "";
      img.loading = "lazy";
      img.src = mediaUrl(msgId, a.idx);
      wrap.appendChild(img);
    } else if (a.has_local && a.kind === "video") {
      var vid = doc.createElement("video");
      vid.className = "att-media";
      vid.controls = true;
      vid.preload = "metadata";
      vid.src = mediaUrl(msgId, a.idx);
      wrap.appendChild(vid);
    } else if (a.has_local) {
      var lbl = doc.createElement("span");
      lbl.className = "att-label";
      lbl.textContent = t("Anexo") + " · " + String(a.kind || "");
      wrap.appendChild(lbl);
    } else {
      var miss = doc.createElement("span");
      miss.className = "att-missing";
      miss.textContent = t("Mídia não baixada ({0})", [String(a.status || "ref")]);
      wrap.appendChild(miss);
    }
    return wrap;
  }

  // One message row: sender, time, text, attachments; recalled/deleted
  // messages render greyed with their label.
  function renderMessage(doc, msg) {
    var item = doc.createElement("div");
    item.className = "msg" + (isGone(msg) ? " gone" : "");
    item.dataset.msgId = msg.msg_id;
    var head = doc.createElement("div");
    head.className = "msg-head";
    var sender = doc.createElement("span");
    sender.className = "msg-sender";
    sender.textContent = msg.sender_name || msg.sender_id || t("Desconhecido");
    var when = doc.createElement("span");
    when.className = "msg-ts";
    when.textContent = fmtTs(msg.ts);
    head.appendChild(sender);
    head.appendChild(when);
    item.appendChild(head);
    var body = doc.createElement("div");
    body.className = "msg-body";
    if (msg.text) {
      var text = doc.createElement("div");
      text.className = "msg-text";
      text.textContent = msg.text;
      body.appendChild(text);
    }
    if (isGone(msg)) {
      var gone = doc.createElement("div");
      gone.className = "msg-gone";
      gone.textContent = isRecalled(msg) ? t("Mensagem desfeita") : t("Mensagem excluída");
      body.appendChild(gone);
    }
    (msg.attachments || []).forEach(function (a) {
      body.appendChild(renderAttachment(doc, msg.msg_id, a));
    });
    item.appendChild(body);
    return item;
  }

  // One search hit row: conversation name, the matching text, time.
  function renderSearchHit(doc, hit) {
    var row = doc.createElement("button");
    row.type = "button";
    row.className = "hit-row";
    row.dataset.convId = hit.conv_id;
    row.dataset.msgId = hit.msg_id;
    var name = doc.createElement("span");
    name.className = "hit-conv";
    name.textContent = hit.conv_name || hit.conv_id;
    var text = doc.createElement("span");
    text.className = "hit-text";
    text.textContent = hit.text || "";
    var when = doc.createElement("span");
    when.className = "hit-ts";
    when.textContent = fmtTs(hit.ts);
    row.appendChild(name);
    row.appendChild(text);
    row.appendChild(when);
    return row;
  }

  // Debounce (the search box, 300 ms): trailing edge, one call per burst.
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

  var api = {
    mediaBase: mediaBase,
    mediaUrl: mediaUrl,
    isRecalled: isRecalled,
    isGone: isGone,
    fmtTs: fmtTs,
    renderConversation: renderConversation,
    renderAttachment: renderAttachment,
    renderMessage: renderMessage,
    renderSearchHit: renderSearchHit,
    makeDebounce: makeDebounce,
  };
  root.Archive = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  if (typeof document === "undefined" || !document.getElementById) return;

  // ---- DOM wiring ----------------------------------------------------------

  var invoke = root.__TAURI__.core.invoke;
  var convListEl = document.getElementById("conv-list");
  var convEmptyEl = document.getElementById("conv-empty");
  var msgsEl = document.getElementById("msgs");
  var msgEmptyEl = document.getElementById("msg-empty");
  var resultsEl = document.getElementById("search-results");
  var searchEl = document.getElementById("search");
  var countsEl = document.getElementById("archive-counts");
  var titleEl = document.getElementById("archive-title");
  var noteEl = document.getElementById("archive-note");

  var convCursor = null; // [ts, id] of the last loaded conversation row
  var convCount = 0;
  var msgCursor = null; // [ts, msg_id] of the oldest loaded message
  var msgCount = 0;
  var msgExhausted = false;
  var currentConv = null; // { id, name }
  var convLoading = false;
  var msgLoading = false;

  function note(text) {
    noteEl.textContent = text || "";
    if (text) setTimeout(function () { if (noteEl.textContent === text) noteEl.textContent = ""; }, 6000);
  }

  function updateCounts() {
    countsEl.textContent = t("Conversas: {0}", [convCount]) + " · " + t("Mensagens: {0}", [msgCount]);
    titleEl.textContent = currentConv ? currentConv.name || currentConv.id : "";
  }

  function errText(e) {
    var s = String(e);
    if (s === "locked") return t("Não foi possível consultar o armazenamento.");
    return s;
  }

  // -- conversations (infinite scroll, keyset cursor) --

  async function loadConversations() {
    if (convLoading) return;
    convLoading = true;
    try {
      var rows = await invoke("archive_list_conversations", { before: convCursor, limit: 50 });
      if (!convCount && rows.length) convEmptyEl.hidden = true;
      rows.forEach(function (c) {
        var row = renderConversation(document, c);
        row.addEventListener("click", function () {
          selectConv({ id: c.id, name: c.name || c.id }, null);
        });
        convListEl.appendChild(row);
        convCursor = [c.last_ts == null ? 0 : c.last_ts, c.id];
        convCount++;
      });
      updateCounts();
    } catch (e) {
      note(errText(e));
    } finally {
      convLoading = false;
    }
  }

  convListEl.addEventListener("scroll", function () {
    if (convListEl.scrollTop + convListEl.clientHeight >= convListEl.scrollHeight - 240) {
      loadConversations();
    }
  });

  // -- messages (newest at the bottom; older pages prepend) --

  function clearMessages() {
    msgCursor = null;
    msgCount = 0;
    msgExhausted = false;
    msgsEl.textContent = "";
  }

  function selectConv(conv, jump) {
    currentConv = conv;
    clearMessages();
    msgsEl.hidden = false;
    msgEmptyEl.hidden = true;
    // Highlight the selected row in the list.
    for (var c = convListEl.firstChild; c; c = c.nextSibling) {
      if (c.dataset && c.dataset.convId === conv.id) c.classList.add("active");
      else if (c.classList) c.classList.remove("active");
    }
    updateCounts();
    if (jump) loadMessages({ before: [jump.ts, jump.msg_id], highlight: jump.msg_id });
    else loadMessages({});
  }

  async function loadMessages(opts) {
    if (!currentConv || msgLoading || msgExhausted) return;
    msgLoading = true;
    var older = !!(opts && opts.older);
    try {
      var before = older ? msgCursor : (opts && opts.before) || null;
      var rows = await invoke("archive_list_messages", {
        convId: currentConv.id,
        before: before,
        limit: 50,
      });
      if (!rows.length) {
        msgExhausted = true;
        if (msgCount) note(t("Não há mais mensagens."));
        return;
      }
      var frag = document.createDocumentFragment();
      var highlight = opts && opts.highlight;
      rows.forEach(function (m) {
        var el = renderMessage(document, m);
        if (highlight && m.msg_id === highlight) el.classList.add("highlight");
        frag.appendChild(el);
        msgCursor = [m.ts, m.msg_id];
        msgCount++;
      });
      if (older) {
        var prevHeight = msgsEl.scrollHeight;
        msgsEl.insertBefore(frag, msgsEl.firstChild);
        // Keep the viewport anchored on what the user was reading.
        msgsEl.scrollTop += msgsEl.scrollHeight - prevHeight;
      } else {
        msgsEl.appendChild(frag);
        if (highlight) {
          var hitEl = msgsEl.querySelector(".msg.highlight");
          if (hitEl) {
            hitEl.scrollIntoView({ block: "center" });
            setTimeout(function () { hitEl.classList.remove("highlight"); }, 4000);
          }
        } else {
          // Newest at the bottom.
          msgsEl.scrollTop = msgsEl.scrollHeight;
        }
      }
      updateCounts();
    } catch (e) {
      note(errText(e));
    } finally {
      msgLoading = false;
    }
  }

  msgsEl.addEventListener("scroll", function () {
    if (msgsEl.scrollTop < 240) loadMessages({ older: true });
  });

  // -- search (debounced 300 ms; a hit jumps to its conversation) --

  var runSearch = makeDebounce(doSearch, 300);

  async function doSearch(q) {
    if (searchEl.value.trim() !== q) return; // a newer keystroke won
    try {
      var rows = await invoke("archive_search", { query: q, limit: 50 });
      resultsEl.textContent = "";
      resultsEl.hidden = false;
      if (!rows.length) {
        var empty = document.createElement("div");
        empty.className = "hit-empty";
        empty.textContent = t("Nenhuma mensagem encontrada.");
        resultsEl.appendChild(empty);
        return;
      }
      var title = document.createElement("div");
      title.className = "hit-title";
      title.textContent = t("Resultados");
      resultsEl.appendChild(title);
      rows.forEach(function (h) {
        var el = renderSearchHit(document, h);
        el.addEventListener("click", function () {
          resultsEl.hidden = true;
          selectConv({ id: h.conv_id, name: h.conv_name || h.conv_id }, { ts: h.ts, msg_id: h.msg_id });
        });
        resultsEl.appendChild(el);
      });
    } catch (e) {
      note(errText(e));
    }
  }

  searchEl.addEventListener("input", function () {
    var q = searchEl.value.trim();
    if (!q) {
      resultsEl.hidden = true;
      resultsEl.textContent = "";
      return;
    }
    runSearch(q);
  });

  // Hide the results when clicking outside the search area.
  document.addEventListener("click", function (ev) {
    if (!resultsEl.hidden && !ev.target.closest || !ev.target.closest(".archive-search")) {
      resultsEl.hidden = true;
    }
  });

  // -- boot --

  loadConversations();
})(typeof window !== "undefined" ? window : globalThis);
