#!/usr/bin/env node
// settings-ui/vi.json is the single source of the Vietnamese text (keyed by the
// English text); Rust includes it directly. This writes the copy the pages load.
import { readFileSync, writeFileSync } from "node:fs";
const dir = new URL("../settings-ui/", import.meta.url);
const vi = JSON.parse(readFileSync(new URL("vi.json", dir), "utf8"));
writeFileSync(new URL("vi.js", dir),
  '"use strict";\n// Generated from vi.json by scripts/gen-vi.mjs. Vietnamese text keyed by the English text.\n(function (root) { root.WR_VI = ' +
  JSON.stringify(vi, null, 1) + '; })(typeof window !== "undefined" ? window : globalThis);\n');
