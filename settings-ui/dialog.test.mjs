// Zero-dependency behavioral tests for dialog.js, the in-page replacement for
// window.alert/confirm/prompt. Run: node settings-ui/dialog.test.mjs
// Exits nonzero on failure. Same standalone pattern as bridge.test.mjs.
//
// These exist because the native dialogs silently do nothing under WKWebView
// (wry implements no WKUIDelegate JS panel methods), which is invisible on
// Windows and Linux: a regression here would look like a dead button on macOS
// only. The harness stubs the DOM surface dialog.js touches, evals the real
// script, and drives it through clicks and key events.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const dialogSrc = readFileSync(join(here, "dialog.js"), "utf8");

let failures = 0;
function assert(cond, msg) {
  if (cond) {
    console.log("  ok  " + msg);
  } else {
    failures++;
    console.error("FAIL  " + msg);
  }
}
const settled = () => new Promise((r) => setTimeout(r, 0));

// --- minimal DOM stubs -------------------------------------------------------

class FakeNode {
  constructor(tag, doc) {
    this.tagName = tag.toUpperCase();
    this.doc = doc;
    this.children = [];
    this.parent = null;
    this.listeners = Object.create(null);
    this.className = "";
    this.textContent = "";
    this.hidden = false;
    this.value = "";
    this.attrs = Object.create(null);
  }
  appendChild(child) {
    child.parent = this;
    this.children.push(child);
    return child;
  }
  remove() {
    if (!this.parent) return;
    this.parent.children = this.parent.children.filter((c) => c !== this);
    this.parent = null;
  }
  setAttribute(k, v) { this.attrs[k] = v; }
  addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); }
  removeEventListener(type, fn) {
    this.listeners[type] = (this.listeners[type] || []).filter((f) => f !== fn);
  }
  dispatch(type, event) {
    for (const fn of this.listeners[type] || []) fn({ target: this, preventDefault() {}, ...event });
  }
  focus() { this.doc.activeElement = this; }
  select() {}
  /** Depth-first search by class name, for the test's own assertions. */
  find(cls) {
    if (String(this.className).split(" ").includes(cls)) return this;
    for (const c of this.children) {
      const hit = c.find(cls);
      if (hit) return hit;
    }
    return null;
  }
  contains(node) {
    if (node === this) return true;
    return this.children.some((c) => c.contains(node));
  }
}

function makeHarness() {
  const doc = {
    listeners: Object.create(null),
    createElement(tag) { return new FakeNode(tag, doc); },
    addEventListener(type, fn) { (doc.listeners[type] ||= []).push(fn); },
    removeEventListener(type, fn) {
      doc.listeners[type] = (doc.listeners[type] || []).filter((f) => f !== fn);
    },
    contains(node) { return doc.body.contains(node); },
    /** Fire a document-level key event the way the capture listener sees it. */
    key(key, extra) {
      const target = doc.activeElement || doc.body;
      for (const fn of doc.listeners.keydown || []) {
        fn({ key, target, shiftKey: false, preventDefault() {}, ...extra });
      }
    },
  };
  doc.body = new FakeNode("body", doc);
  doc.activeElement = doc.body;

  const window = { document: doc };
  const fn = new Function("window", "document", `"use strict";\n${dialogSrc}`);
  fn(window, doc);
  return { window, doc, Dlg: window.Dlg };
}

/** The backdrop of the dialog currently on screen, or null. */
const backdropOf = (doc) => doc.body.children.find((c) => c.className === "dlg-backdrop") || null;
const buttons = (doc) => backdropOf(doc).find("dlg-actions").children;
const clickOk = (doc) => { const b = buttons(doc); b[b.length - 1].dispatch("click"); };
const clickCancel = (doc) => buttons(doc)[0].dispatch("click");

// --- tests -------------------------------------------------------------------

async function testAlertResolvesOnDismiss() {
  console.log("alert shows one button and resolves when dismissed");
  const { doc, Dlg } = makeHarness();
  let done = false;
  const p = Dlg.alert("Something failed.", { title: "Oops" }).then(() => (done = true));
  await settled();
  assert(!!backdropOf(doc), "dialog is on screen");
  assert(buttons(doc).length === 1, "alert has no Cancel button");
  assert(!done, "does not resolve before dismissal");
  clickOk(doc);
  await p;
  assert(done, "resolves after OK");
  assert(!backdropOf(doc), "dialog removed from the page");
}

async function testConfirmOutcomes() {
  console.log("confirm resolves true only when confirmed");
  const { doc, Dlg } = makeHarness();

  let p = Dlg.confirm("Remove it?");
  await settled();
  clickOk(doc);
  assert((await p) === true, "OK resolves true");

  p = Dlg.confirm("Remove it?");
  await settled();
  clickCancel(doc);
  assert((await p) === false, "Cancel resolves false");

  p = Dlg.confirm("Remove it?");
  await settled();
  doc.key("Escape");
  assert((await p) === false, "Escape resolves false");

  p = Dlg.confirm("Remove it?");
  await settled();
  const backdrop = backdropOf(doc);
  backdrop.dispatch("mousedown", { target: backdrop });
  assert((await p) === false, "clicking outside resolves false");
}

async function testConfirmIgnoresClicksInsideTheBox() {
  console.log("a click on the dialog body does not dismiss it");
  const { doc, Dlg } = makeHarness();
  const p = Dlg.confirm("Remove it?");
  await settled();
  const backdrop = backdropOf(doc);
  backdrop.dispatch("mousedown", { target: backdrop.children[0] });
  await settled();
  assert(!!backdropOf(doc), "still on screen");
  clickCancel(doc);
  await p;
}

async function testPromptReturnsTextOrNull() {
  console.log("prompt returns the entered text, or null when cancelled");
  const { doc, Dlg } = makeHarness();

  let p = Dlg.prompt("", { title: "Rename account", value: "Work" });
  await settled();
  const input = backdropOf(doc).find("dlg-input");
  assert(input.value === "Work", "prefilled with the current value");
  assert(input.type === "text", "plain text input by default");
  input.value = "  Personal  ";
  clickOk(doc);
  assert((await p) === "Personal", "resolves the trimmed text");

  p = Dlg.prompt("", { title: "Rename account", value: "Work" });
  await settled();
  clickCancel(doc);
  assert((await p) === null, "Cancel resolves null, distinct from an empty string");

  p = Dlg.prompt("", { title: "Rename account", value: "Work" });
  await settled();
  doc.key("Escape");
  assert((await p) === null, "Escape resolves null");
}

async function testEnterAccepts() {
  console.log("Enter in the text field accepts");
  const { doc, Dlg } = makeHarness();
  const p = Dlg.prompt("", { title: "Rename account", value: "Work" });
  await settled();
  backdropOf(doc).find("dlg-input").value = "Family";
  doc.key("Enter");
  assert((await p) === "Family", "Enter resolves the value");
}

async function testEmptyInputIsRefusedNotResolved() {
  console.log("an empty required field blocks instead of resolving empty");
  const { doc, Dlg } = makeHarness();
  let resolved;
  const p = Dlg.prompt("", { title: "Rename account", value: "Work" }).then((v) => (resolved = v));
  await settled();
  const input = backdropOf(doc).find("dlg-input");
  input.value = "   ";
  clickOk(doc);
  await settled();
  assert(resolved === undefined, "does not resolve");
  assert(!!backdropOf(doc), "dialog stays open");
  assert(backdropOf(doc).find("dlg-error").hidden === false, "an error is shown");
  input.value = "Family";
  clickOk(doc);
  await p;
  assert(resolved === "Family", "resolves once a name is given");
}

async function testPasswordIsNotTrimmed() {
  console.log("a password keeps its surrounding whitespace");
  const { doc, Dlg } = makeHarness();
  const p = Dlg.prompt("", { title: "Current password", password: true });
  await settled();
  const input = backdropOf(doc).find("dlg-input");
  assert(input.type === "password", "masked input");
  input.value = " hunter2 ";
  clickOk(doc);
  assert((await p) === " hunter2 ", "value passed through untrimmed");
}

async function testFocusIsRestored() {
  console.log("focus returns to whatever opened the dialog");
  const { doc, Dlg } = makeHarness();
  const opener = doc.createElement("button");
  doc.body.appendChild(opener);
  opener.focus();
  const p = Dlg.confirm("Remove it?");
  await settled();
  assert(doc.activeElement !== opener, "focus moves into the dialog");
  clickCancel(doc);
  await p;
  assert(doc.activeElement === opener, "focus restored to the opener");
}

async function testKeyListenerIsReleased() {
  console.log("the document key listener is removed when the dialog closes");
  const { doc, Dlg } = makeHarness();
  const p = Dlg.confirm("Remove it?");
  await settled();
  assert((doc.listeners.keydown || []).length === 1, "listener attached while open");
  clickCancel(doc);
  await p;
  assert((doc.listeners.keydown || []).length === 0, "listener detached after close");
}

const tests = [
  testAlertResolvesOnDismiss,
  testConfirmOutcomes,
  testConfirmIgnoresClicksInsideTheBox,
  testPromptReturnsTextOrNull,
  testEnterAccepts,
  testEmptyInputIsRefusedNotResolved,
  testPasswordIsNotTrimmed,
  testFocusIsRestored,
  testKeyListenerIsReleased,
];

for (const t of tests) await t();

if (failures) {
  console.error(`\n${failures} dialog test(s) failed`);
  process.exit(1);
}
console.log("\nall dialog tests passed");
