# Desktop → shadow mapping (Phase 2.3/2.4 tooling)

This is the how-to for the tools batch 12 added to `zalors import`,
the batch-14 addition, the batch-15 additions, the batch-16
additions, the batch-23a content-shape additions, the batch-24
BasicEncryption decode additions, the batch-25 completed msgType
code table, and the batch-27 Zalo PC local-media tools:

- `--inventory` — what tables/columns a cold snapshot actually holds
  (audit §4 item 2.2/2.3 groundwork);
- `--distinct` — whitelisted distinct values of one CODE column in a
  sample DB (batch 14 N1: the tool that settles code tables without
  ever printing content); with `--all-dbs` (batch 15) it sums the
  same aggregation across EVERY DB of a message kind;
- `--mapping <file>` + `--shadow-copy <dir>` (+ `--delta`, and batch
  15's `--own-uid-from-settings`) — the declarative mapping dry run
  with a read-only classification against a temp COPY of your shadow
  store (item 2.4); batch 24: the extraction now DECODES the Desktop
  `message` cell (BasicEncryption) and reports the outcome counts;
  batch 25: the summary also prints the unmapped-code census (the
  SAME fixed aggregation the apply preflight runs), so you see
  exactly what an apply would refuse on;
- `probe_import_overlap` — the 2.3 acceptance probe (≥99% msgId
  overlap, 100% type/ts/sender on the matches) that a mapping must
  pass before any apply step is even proposed; batch 15 adds the
  `type_str` axis (the meaningful type comparison today);
- `probe_import_codes` (batch 15) — the code cross-tab that resolves
  the Desktop NUMERIC msgType codes against the shadow payload's
  original wire `$.msgType` strings, matched by msgId — the type
  arbiter that needs no deploy;
- `--content-shape <kind>:<table>.<col> --by <code_col>` (batch 23a)
  — the content-SHAPE probe over a snapshot: per distinct code, the
  JSON-shape census of one content column plus its top key
  signatures, unable by construction to print a value; batch 24 adds
  `--decrypt-basic`, which decodes each raw cell first;
- `probe_shadow_content_shape` (batch 23a) — the shadow half of the
  same shape census, grouped by the payload's wire `$.msgType` on a
  temp COPY of the store; batch 23b combines the two halves with the
  batch-15 cross-tab to fill the mapping's `msgType` table;
- `probe_import_content_agree` (batch 23b) — the transform-hunting
  probe (counts only); batch 24 adds its `decrypted` section, the
  direct verification that the BasicEncryption decode reproduces the
  shadow `$.content`;
- `--apply` (batch 16, §7) — the guarded write step (item 2.5): all
  preconditions enforced in code, a verified pre-import backup,
  batched savepoint writes with per-DB resume cursors, and a
  zero-change second run; batch 24 adds the decode-census gate
  (refuse when more than 1% of the census rows fail to decode);
- `--media-plan` (batch 16, §8) — the media hardlink PREP dry run
  (item 2.6): counts only, no hashing, no hardlinks;
- the batch-25 code table itself (§1g): `msgType` now maps every
  Desktop code the Zalo PC 26.11.12 source names with a wire string
  — only the Desktop-LOCAL rows `-4` (MSG_INFO) and `-1909`
  (MSG_INFO_CHAT) stay unmapped by design, so the preflight/hatch
  path is only for them (plus any code the source did not name);
- batch 26 (§9) — what happens to MEDIA refs from imported history:
  the `ref-import`/`expired` statuses, the `media_import_requeue`
  repair step, the opt-in `shadow.media_backfill_import` backfill,
  and the read-only `zalors media --shape` census tool;
- batch 27 (§10) — the Zalo PC LOCAL media tools: the `--inventory`
  coverage of the top-level snapshot DBs, the read-only
  `--local-media-probe` census, the `--local-media-plan` DRY-RUN copy
  planner, and JPEG XL joining the image magic family.

Everything here is **dry-run only** up to and including §5: nothing in
the pipeline writes to the snapshot, the shadow store, or the live
Desktop data — source DBs open `mode=ro&immutable=1`, and the shadow
store is only ever file-copied to a temp dir and opened `query_only`
there. The ONE write step — `--apply` (§7) — is guarded by its own
preconditions and still requires an explicit, user-approved invocation;
nothing in this tooling ever writes on its own.

---

## 0. What still needs you (the human)

These steps touch real data and real processes; the tools refuse to
do them on their own:

1. **Quit Zalo Desktop** before making a snapshot (the snapshot script
   enforces this — a snapshot of a live DB would be torn, KQ4).
2. **Make the cold snapshot**:
   ```powershell
   powershell -File tools\snapshot.ps1 -Source "D:\Zalo Data\message\Database\_production\<uid>" -Dest "D:\ZaloRust Data\import-snapshot\2026-MM-DD"
   ```
   The script copies every `*.db` + `-wal`/`-shm`, proves the source is
   unchanged after the copy, and writes the
   `snapshot-manifest.json` the import refuses to run without.
   (Synthetic runs under `$env:TEMP` may use `-Force` — never against
   the real tree.)
3. **The real D7 key file** — the DPAPI-wrapped Desktop key capture.
   It is passed as `--key-file`, never as text, never printed; only
   its sha256-12 appears in output, cross-checked against
   `--uin-hash`.
4. **Approve `--apply` later** — item 2.5 is now WIRED (§7) but every
   invocation is a separate, explicit, user-approved step: it needs
   `--apply --i-have-a-backup-plan --target <store>` plus a mapping,
   and it refuses to start unless every precondition holds. The tools
   in §1–§5 are how you earn the confidence to run it.
5. **Run the overlap probe on the real pair** (reviewer step, below)
   and iterate the mapping until the AC is met.

## 1. Inventory the snapshot

```powershell
Set-Location D:\ZaloRust\src-tauri
target\debug\zalors.exe import `
  --from-snapshot "D:\ZaloRust Data\import-snapshot\2026-MM-DD" `
  --account default --uin-hash dca62c394a68 `
  --key-file D:\.opencode\d7\zalo-desktop-uin-key-2026-11-19.bin `
  --inventory --out inventory.json
```

- Prints the schema of `Core\Index.db` plus ONE sample per message-DB
  kind (the first 1-1, the first group, `stranger_box`), and the
  message-DB enumeration counts. **Names, declared types, row counts
  and index names only — never row values.**
- `--out <file>` writes the same as JSON (`DbInventory` per kind,
  with the `Core/...` source path each sample came from) — this file
  is what you write the mapping against.
- The mode is dry-run only: `--inventory` + `--apply` is a parse
  error, and `--out` without `--inventory` is refused.
- One unopenable sample among the 1 471 message DBs is REPORTED and
  skipped, not fatal; `Core\Index.db` failing is fatal (the key or
  profile is wrong).

## 1a. Peek at a code column (`--distinct`, batch 14)

When the inventory names are not enough to write a mapping — the
message type column stores INTEGER codes whose meaning no name can
tell you — `--distinct` reports the distinct values of ONE column of
a sample DB, under privacy rules that make the tool unable to print
content:

```powershell
target\debug\zalors.exe import `
  --from-snapshot "D:\ZaloRust Data\import-snapshot\2026-MM-DD" `
  --account default --uin-hash dca62c394a68 `
  --key-file D:\.opencode\d7\zalo-desktop-uin-key-2026-11-19.bin `
  --distinct one2one:message.msgType `
  --distinct index:conversation.isGroup
```

- The spec is `<dbkind>:<table>.<column>` with dbkind one of
  `index`, `one2one`, `group`, `stranger`; the DB probed is the
  FIRST sample of that kind — the very one `--inventory` reports.
  Repeatable, **max 10 per run**; its own mode (cannot combine with
  `--inventory`/`--mapping`/`--shadow-copy`/`--delta`); dry-run only
  (parse refuses `--apply`).
- Three layered guards, all enforced in code (unit-tested):
  1. the column NAME must match the code-column whitelist
     `^(.*_)?(type|kind|status|state|cmd|subcmd|sub_cmd|msgtype|msg_type|flag|flags|ver|version|src|source|unit|is[a-z_]*|has[a-z_]*)$`
     (case-insensitive) — `message`, `content`, `displayName`,
     `serverTime` and every other content-bearing name are refused
     BEFORE any row is read, with an error quoting the rule;
  2. the read is exactly
     `SELECT col, COUNT(*) FROM t GROUP BY col ORDER BY COUNT(*) DESC LIMIT 51`;
  3. a value is only ever printed as: the INTEGER/REAL number,
     `NULL`, a code-shaped TEXT token (non-empty, ≤ 32 chars, every
     char in `[A-Za-z0-9._:-]` — e.g. `chat.photo`), the
     fingerprint `text(len=N,h12=…)` for any other TEXT, or
     `blob(len=N)` for a BLOB.
- More than 50 distinct values print the first 50 plus
  `… (more than 50 distinct — not a code column?)` — a column that
  trips this (batch 14 found `friend.status` does: >50 distinct
  sentence-like TEXT values) is not a code column in practice.
- Output of a good code column looks like
  `  1 x 57` — value `1`, seen on 57 rows of the sample.

## 1b. The whole kind at once (`--all-dbs`, batch 15)

A sample DB can miss most of a code vocabulary (the batch-14 sample
had 61 rows and a 3-code vocabulary; the real one2one kind turned out
to hold 16 codes). Adding `--all-dbs` runs the SAME fixed aggregation
in EVERY DB of the requested message kind and sums the counts:

```powershell
target\debug\zalors.exe import `
  --from-snapshot "D:\ZaloRust Data\import-snapshot\2026-MM-DD" `
  --account default --uin-hash dca62c394a68 `
  --key-file D:\.opencode\d7\zalo-desktop-uin-key-2026-11-19.bin `
  --distinct one2one:message.msgType --distinct group:message.msgType `
  --distinct stranger:message.msgType --all-dbs
```

- Message kinds only — an `index` spec with `--all-dbs` is a parse
  error (there is exactly one `Core\Index.db`); it rides the
  `--distinct` mode (max 10 specs per run, dry-run only).
- Same whitelist, same renderer, cap 50 summed values. The sums are
  exact for any column with ≤ 50 distinct values per DB; a column
  that trips the per-DB cap in ANY DB is flagged with the >50 marker.
- Open/query failures are counted in the header
  (`dbs=<kind count> opened=<counted> failed=<skipped>`), not
  printed one DB at a time.

## 1c. Resolving the codes (`probe_import_codes`, batch 15)

`--distinct` gives you the vocabulary but not the meaning. The code
cross-tab joins EVERY snapshot message DB's (msgId, msgType) pairs —
read through the mapping's own `msgId`/`msgType` column names only —
against the shadow copy's `messages.payload_json $.msgType` (the
ORIGINAL wire string the capture path stored, even while the soaking
build's numeric `type` is degenerate):

```powershell
$env:ZR_SNAPSHOT_DIR = "D:\ZaloRust Data\import-snapshot\2026-MM-DD"
$env:ZR_D7_KEY_FILE  = "D:\.opencode\d7\zalo-desktop-uin-key-2026-11-19.bin"
$env:ZR_UIN_HASH     = "dca62c394a68"
$env:ZR_MAPPING      = "D:\...\mapping.json"
cargo test --lib probe_import_codes -- --ignored --nocapture
```

Output: `code-cross-tab: <desktop_code> | <shadow msgType> | <count>`
rows, then per-code totals with the no-shadow-match counts, the
dominant msgType and its purity. Fill the mapping's `msgType` table
from the codes with **purity ≥ 90% and ≥ 5 matched rows**; leave the
rest for a re-run after more soak coverage.

## 1d. The content shapes (batch 23a)

The cross-tab needs matched rows, and ~12.6k Desktop rows carry
codes whose matches never reached that bar (19 ×8418, 20 ×2119,
21 ×459, 52 ×343, 26 ×334, -4 ×278, -1909 ×128, 17 ×120, 7 ×79,
25 ×65, -27 ×41, 3 ×30, 5 ×1). A second, INDEPENDENT arbiter is the
SHAPE of the content: the top-level JSON key names and value types.
A code whose content reads like `{href,params,title}` with `params`
holding `fileSize/fileExt`, and whose few cross-tab hits say
`share.file`, can be mapped with confidence. (Every code in that
list except the local-info pair `-4`/`-1909` is mapped since batch
25 — §1g; this section keeps the batch-23a motivation.)

Two halves, one shared pure implementation
(`shadow/import/content_shape.rs`):

**The Desktop half — `--content-shape` (C1):**

```powershell
target\debug\zalors.exe import `
  --from-snapshot "D:\ZaloRust Data\import-snapshot\2026-MM-DD" `
  --account default --uin-hash dca62c394a68 `
  --key-file "D:\.opencode\d7\zalo-desktop-uin-key-2026-11-19.bin" `
  --content-shape one2one:message.message --by msgType `
  [--all-dbs] [--decrypt-basic] [--out shapes.json]
```

- The spec is `<dbkind>:<table>.<content_col>` (the `--distinct`
  spec shape); `--by <code_col>` is REQUIRED with it and must pass
  the batch-14 code-column whitelist — the shapes are grouped by a
  CODE column, and a content-bearing name is refused with the rule
  quoted before any row is read. Dry-run only (`--apply` conflicts),
  its own mode (cannot combine with `--inventory`/`--mapping`/
  `--shadow-copy`/`--delta`/`--distinct`/`--media-plan`).
- Without `--all-dbs` it reads the FIRST sample DB of the kind (the
  very one `--inventory` reports); with `--all-dbs` (message kinds
  only — an `index` spec is a parse error) it reads EVERY DB of the
  kind and sums the groups, reporting `dbs=/opened=/failed=`.
- Per distinct code (cap 64 codes, the rest merged into an `other`
  group that always prints last — nothing is dropped), it prints:

  ```
  content-shape: code=19 rows=8418 json_object=8390 json_array=0 json_string_scalar=1 not_json=27 null=0
  content-shape:  {action:s,childnumber:s,description:s,href:s,params:s{fileExt:s,fileSize:s},thumb:s,title:s,type:s} x 8000
  ```

  the per-code `rows` line is the check against the counts in the
  mapping's `_notes` (the notes list them per code). `--out <file>`
  writes the same data as JSON (BOM-less UTF-8).
- The five buckets partition every row: `json_object` (the content
  text parses as a JSON object), `json_array`, `json_string_scalar`
  (the text parses as a JSON string), `not_json` (prose, blobs,
  INTEGER/REAL cells, and number/bool/null JSON scalars), `null`.
- A key signature is the sorted top-level keys with type letters
  `s` string, `n` number, `b` bool, `o` object, `a` array, `z` null.
  ONE level of nesting: a string value that itself parses as a JSON
  object adds `key{inner}` (so `params:s` becomes
  `params:s{fileExt:s,fileSize:s}` — the Desktop content column
  stores `params` as JSON *text*); inner values are letters only, no
  deeper nesting. Each signature caps at 24 keys with `…+N` appended
  (the inner list gets the same cap inside the braces). The top 8
  signatures print, most frequent first.
- PRIVACY, by construction: a key name prints only when it matches
  `^[A-Za-z_][A-Za-z0-9_]{0,31}$`, anything else prints
  `k:<sha256-12>`; codes render through the `--distinct` renderer;
  NO text, id, url, number or file name taken from the content can
  appear — the unit tests feed sentinel-bearing contents and assert
  every output line clean.
- `--decrypt-basic` (batch 24, valid only with `--content-shape`):
  decode each RAW cell through the Desktop `BasicEncryption`
  transform FIRST — the exact pipeline Claude read out of the Zalo PC
  app code (§1f) — using the snapshot passphrase (in memory only,
  never printed). A decoded cell then folds through the SHADOW-side
  classifier, so each code's shapes become directly comparable with
  the C2 `msgType=` families (the decoded value IS the wire
  `$.content` value); a cell that fails to decode folds as the raw
  cell it is. The header gains ` decrypt=basic`; the output stays
  shape only.

**The shadow half — `probe_shadow_content_shape` (C2):**

```powershell
cargo test --lib probe_shadow_content_shape -- --ignored --nocapture
```

No required env: it copies the live store to a temp dir
(`ZR_PROBE_DIR` overrides the source) and opens the COPY; the
optional `ZR_PROBE_SINCE_MS` cuts the census to messages with
`ts >= <epoch ms>`. It groups the messages by the payload's wire
`$.msgType` (a code-like token `^[A-Za-z0-9._:-]{1,40}$` prints
verbatim, anything else prints its h12; a missing msgType groups
under `NULL`) and folds `$.content` through the SAME shared
functions — the same buckets, signatures, nesting rule and caps
(grouped as `msgType=` lines). The one representation difference to
know when comparing: the wire payload's `params` is a real JSON
object (letter `o`), while the Desktop column stores it as JSON text
(`params:s{…}` with the inner keys expanded) — the key NAMES are the
comparable part.

## 1e. Batch 23b — mapping from the two shapes plus the cross-tab

Batch 23b edits the mapping's `msgType` table from three pieces of
evidence, in this order of trust:

1. **The batch-15 cross-tab** (`probe_import_codes`): the direct
   arbiter — a code whose matched rows reach purity ≥ 90% with ≥ 5
   rows maps on that alone, as entries 1/2/4/6/18 already did.
2. **The content shapes**: run C1 (`--content-shape … --by msgType
   --all-dbs` over every message kind) and C2
   (`probe_shadow_content_shape`) and compare each unmapped code's
   signatures against every shadow msgType family's signatures.
   **Promote a code only when its shape matches exactly ONE shadow
   msgType family** (one family whose signatures share the code's
   dominant key names — e.g. a code whose content is
   `{href:s,params:s{fileExt:s,fileSize:s},title:s,type:s}` against
   a family whose `$.content` shows `{href,params(o),title,type}`),
   **AND any cross-tab hits it does have AGREE** (a code whose 1-2
   matched rows point at a different msgType stays unmapped — the
   shapes corroborate the cross-tab, they never outvote it).
   Zero-match codes (7/17/26/3/25/5, -4/-27/-1909) may be promoted
   on shape agreement alone, but only into the msgType the shadow
   evidence pins uniquely; otherwise they stay unmapped for the
   apply step's `--unmapped-as-raw` path.
3. Record every promotion in the mapping's `_notes` with its
   evidence (shape match + agreeing cross-tab hits), then re-run the
   batch-15 cross-tab and the overlap probe before proposing an
   apply; the apply preflight (§7 precondition 4) is the final gate
   that lists anything still unmapped.

## 1f. Batch 24 — the Desktop `message` BasicEncryption decode

Claude read the Zalo PC 26.11.12 app code (static, read-only): the
Desktop data-transform layer (`main-dist/utility-process-sqlite.js`)
configures the SQLite adapter's `message` table with exactly ONE
field transform — `version 0, sentiveFields ["message"], methodology
BasicEncryption` — and initialises the transformer with the
partition's `cipherKey`: the SAME string the DB is opened with, i.e.
the D7 passphrase the import already uses. The column stores a JSON
string literal whose value is the XOR of the content's JSON text
with that passphrase (UTF-16 units, key cycling from the start), so
decoding is: JSON-unwrap the cell → XOR → `JSON.parse` — which
yields the content value (a string for webchat, an object for
media). Batch 23b's length evidence agrees: the length is preserved
and webchat D is longer than S by the JSON quotes and escapes.

The shared implementation is `shadow/import/desktop_cipher.rs`
(`basic_xor_utf16` + `decode_field`), used by:

- **the extraction** (§2/§4/§7): the mapped `content` column's raw
  cell is decoded BEFORE the payload build, with the same passphrase
  that opened the DB — a decoded value becomes the payload content
  (a plain string for webchat, the parsed object for media). Each
  extract counts `content_decoded` / `content_not_encrypted` /
  `content_failed`, surfaced in the dry-run summary and the apply
  output. A cell that is not a JSON string scalar keeps its own
  JSON meaning (or the raw text) as it was; a `Failed` decode keeps
  the raw cell value and is counted. Only a PLAIN column mapping is
  decoded — a const/expr content is a mapping product, not the raw
  cell.
- **`--content-shape --decrypt-basic`** (§1d).
- **`probe_import_content_agree`'s `decrypted` section** (batch 23b +
  24): per msgType family, the decode outcome counts plus, for a
  string `S`, whether the decoded value equals it (`eq`, `eq_trim`)
  and, for an object `S`, whether the decoded object has the same
  key set and per identifier key whether the string values are
  equal (`obj_eq[key]=n/m`). Counts only.

The passphrase is passed in memory only, exactly the way
`import::prepare` already passes it — nothing in this path logs,
prints, stores or hashes it, and no probe or tool ever prints a
decrypted value.

## 1g. Batch 25 — the completed code table (the Zalo PC 26.11.12 source)

Batch 25 replaces the cross-tab bar with a better source of truth:
Claude's STATIC read of the Zalo PC 26.11.12 app bundle
`pc-dist/sync-v2-sub-worker.*.js`. The Desktop `message.msgType`
column holds a numeric `MSG_*` constant exported by ONE module of
that bundle, and the same bundle carries the switch that turns each
constant into its wire msgType string. Combined, numeric code → wire
string, every code that HAS one is now in the mapping's `msgType`
table (`tools/import-mapping/zalo-desktop-26.11.json`):

| Desktop code | constant | wire msgType |
|---|---|---|
| 1 | MSG_TEXT | webchat |
| 2 / 11 | MSG_PHOTO / MSG_PHOTO_2 | chat.photo |
| 3 | MSG_VOICE | chat.voice |
| 4 | MSG_STICKER | chat.sticker |
| 5 | MSG_DOODLE | chat.doodle |
| 6 | MSG_CONTACT | chat.recommended |
| 7 | MSG_GIF | chat.gif |
| 17 | MSG_LOCATION | chat.location.new |
| 18 | MSG_VIDEO | chat.video.msg |
| 19 | MSG_FILE | share.file |
| 20 | MSG_UNDO | chat.undo |
| 21 | MSG_OA | chat.list.action |
| 25 | MSG_ECARD | chat.ecard |
| 26 | MSG_POLL | group.poll |
| 52 | MSG_ZINSTANT | chat.webcontent |
| -27 | MSG_DEL_EVERYONE | chat.delete.everyone |
| 2506 | MSG_TODO | chat.todo |

Two codes are DELIBERATELY still unmapped: `-4` (MSG_INFO) and
`-1909` (MSG_INFO_CHAT). The source's switch has NO wire string for
them — they are local info rows the Desktop writes into its own
message table as bookkeeping. There is nothing a Desktop→wire table
could map them to, so the apply's `--unmapped-as-raw` path (kind 100,
text NULL, content only in payload_json) is their only import path
today; skipping them at extract time is a possible later user
decision (recorded in the mapping's `_notes`, not implemented).

Corroborating evidence (kept in the mapping's `_notes`): the
batch-15 cross-tab agrees for 1/2/4/6/18, 19→share.file,
21→chat.list.action and 52→chat.webcontent; the batch-24 decrypted
content shapes agree (19 has checksum/fileExt/fileSize; 17 has
lat/lo; 25 has versionEcardNewFr; 52 has customMsg/pcItem; 7 is
photo-like with contentId; 21 is a JSON array; 20 has
`{cliMsgId, deleteMsg, globalMsgId}`). ONE conflict was found and
resolved by the code: a single batch-15 cross-tab hit said
20→webchat; the source says MSG_UNDO→`chat.undo`, so 20 maps to
`chat.undo`.

The shadow side changed consistently with the table
(`normalize::msg_type_code`):

- `chat.undo` and `chat.delete.everyone` join the recall family
  **8** (with `chat.delete` / V1 `recall`) — `writer::is_recall_msg`
  recognises the whole family, so their revisions land as `recall`;
- `chat.webcontent.v2` joins **9** (`chat.webcontent`);
- new codes: `chat.list.action` = **14**, `chat.ecard` = **15**,
  `group.poll` = **16**, `chat.todo` = **17**;
- `import_map::MEDIA_CODES` (the kinds whose wire content is a JSON
  object/array, so the Desktop's JSON-text cell is re-parsed into
  the capture shape) extends beyond the downloadable media kinds to
  8, 9, 13, 14, 15, 16 and 17 — a parsed object/array never becomes
  `messages.text`, so the new kinds can never leak JSON-as-text;
- `archive::preview_label` labels 14-17 (`[danh sách]`, `[thiệp]`,
  `[bình chọn]`, `[to-do]`), and the archive UI's recalled-message
  rendering (type 8) covers the whole recall family.

The one pre-existing inconsistency left as-is (out of batch-25
scope, flagged for a follow-up): kind 7 (`chat.recommended`) also
carries an object content on the wire but is NOT in `MEDIA_CODES` —
batch 15 scoped the parsing to the "media kinds" only. Its import
rows keep the JSON text as a string today.

After batch 25, the unmapped-code census has exactly three possible
kinds of finding, and the dry-run summary (§4) plus the apply
refusal (§7) both list them clearly: the local-info pair `-4` /
`-1909`, and any code the Zalo PC 26.11.12 source did not name
(e.g. an unknown `999`) — treat the latter as new evidence and
re-run `probe_import_codes` before mapping it.

## 2. Write the mapping JSON

A mapping is a declarative JSON file. **There is no free SQL in it,
ever** — every table/column name is validated against the inventory
before anything is read, and the extraction SELECT is built only from
those validated, identifier-quoted names.

```json
{
  "msgType": { "chat.text.v2": "webchat" },
  "entities": {
    "message": {
      "db": ["one2one", "group"],
      "table": "msg",
      "columns": {
        "msgId": "id",
        "uidFrom": "fromUid",
        "idTo": "toUid",
        "ts": { "expr": "s_to_ms", "of": "ts" },
        "msgType": "type",
        "content": "content",
        "cliMsgId": "cliId"
      }
    }
  }
}
```

Top level: `msgType` (a Desktop→web msgType string table; anything
unlisted passes through unchanged) and `entities` (only the five
known names: `conversation`, `contact`, `group`, `message`,
`attachment`), plus an optional `"_notes"` object (batch 13):
free-form `"{ "<field path>": "<why this reading is uncertain>" }"`
documentation the parser accepts and IGNORES — neither `plan` nor
`extract` ever reads it. Use it to mark every field whose meaning
could not be derived from names/types alone. Each entity names:

- `"db"`: one kind or an array — `"index"` (`Core\Index.db`) or the
  message-DB kinds `"one2one"`, `"group"`, `"stranger"`. A `message`
  mapping may use the message kinds only; the other entities are
  index-only. The same `message` mapping is applied to EVERY DB of
  the listed kinds.
- `"table"`: the source table (must exist in every listed kind's
  inventory sample).
- `"columns"`: the column map.

### Column map values

| value form | meaning |
|---|---|
| `"col"` | read source column `col` |
| `{ "const": <scalar> }` | a literal |
| `{ "const": "$db_id" }` | the digits of the one2one/group DB FILE name (`123.db` → `"123"`) — the conversation id the capture path derives; rejected for index/stranger kinds |
| `{ "expr": "ms_to_ms", "of": "col" }` | source is already epoch ms |
| `{ "expr": "s_to_ms",  "of": "col" }` | source is epoch SECONDS → ×1000 |
| `{ "expr": "string",   "of": "col" }` | coerce to a string (INTEGER ids become decimal strings) |
| `{ "expr": "int",      "of": "col" }` | coerce to an integer |
| `{ "expr": "json_object_of", "of": ["a","b"] }` | a nested object `{ "a": …, "b": … }` from the listed columns |

The expr whitelist is exactly: `ms_to_ms`, `s_to_ms`, `string`,
`int`, `json_object_of`. Anything else is a parse error.

### Target fields per entity

- **message** maps the CAPTURE ENVELOPE names — `msgId` (required),
  `ts` (required, and it MUST declare its unit via
  `ms_to_ms`/`s_to_ms`), at least one of `uidFrom`/`idTo`, plus the
  optional `msgType` and `content` and any extra target names
  (carried into the payload verbatim — e.g. `cliMsgId`).
  `conv_id`, `sender_id`, `text`, `kind`, `source`, `is_group` are
  DERIVED (mapping them is an error): the extractor applies the same
  rules `normalize.rs` applies to wire messages — group conv = `idTo`
  (or `{"const":"$db_id"}`), 1-1 conv = `uidFrom` (or `idTo` for
  self-sent `uidFrom=="0"`), sender = `uidFrom` unless `"0"`, text =
  string content (a media-kind `content` column holding JSON text is
  embedded as the parsed OBJECT, the wire shape), kind = the msgType
  table code. The payload it builds is the capture envelope, so
  `content_hash` and the writer's attachment extraction behave
  exactly as on the capture path; `source` is `"import"`, `is_group`
  comes from the DB kind.
- **conversation**: `id` (required), `is_group` (required — a const,
  or a column where 0/""/"false"/NULL mean false), `title`,
  `avatar_url`, `last_msg_id`, `last_ts`, `raw` (defaults to a JSON
  object of every column the mapping reads).
- **contact**: `user_id` (required), `display_name`, `avatar_url`,
  `raw`.
- **group**: `group_id` (required), `name`, `raw`.
- **attachment**: `msg_id` (required) + the `attachments` column
  names (`idx`, `kind`, `url`, `local_path`, `size`, `sha256`). It is
  validated and **counted only** — no `Write` exists for it in this
  batch: the writer derives attachment refs from message payloads at
  apply time, and the Desktop media/hardlink step is item 2.6.
  Vocabulary note: today the kinds cover `Core\Index.db` and
  `Core\Message\*.db`; `Media.db`/`Reaction.db` are separate Core DBs
  and need a vocabulary extension in a later batch if you want to
  map them directly.

Without `--mapping`, the dry run uses the **built-in skeleton that
maps nothing** (`{"msgType": {}, "entities": {}}`) — useful as a
smoke test of the snapshot + shadow-copy path.

## 3. Iterate: plan errors name exactly what is missing

`plan` validates every referenced table/column against the
inventory samples, plus the required fields, the field whitelists,
the ts unit rule and `$db_id` placement. ALL violations are listed
at once (never just the first):

```
import failed: mapping failed validation (2 error(s)):
  - mapping plan: entities.message: table "msgs" does not exist in Core/Message/123.db (one2one kind)
  - mapping plan: entities.message: missing required target field 'msgId'
```

Fix, re-run, repeat until `plan OK`. This loop is the point of
`--inventory`: you iterate against the real schema without ever
reading a row value.

## 4. Run the dry run and read it

```powershell
target\debug\zalors.exe import `
  --from-snapshot "D:\ZaloRust Data\import-snapshot\2026-MM-DD" `
  --account default --uin-hash dca62c394a68 `
  --key-file D:\.opencode\d7\zalo-desktop-uin-key-2026-11-19.bin `
  --dry-run --mapping mapping.json `
  --shadow-copy "$env:LOCALAPPDATA\com.o365serveronms.zalors\shadow"
```

(`--shadow-copy` accepts the shadow STORE dir; its FILES are copied
to a temp dir and the copy is opened `query_only` — the live store is
never opened by SQLite.)

Batch 15 (KQ2 applied to the import path): `--own-uid-from-settings`
seeds the extraction's self-sent sender substitution
(`uidFrom == "0"` rows) from `settings.shadow.own_uid`, read through
the settings loader — the value is never printed; the dry run only
reports `own_uid set: true/false`. Env `ZR_OWN_UID` (shape-validated,
5..=32 ASCII digits) wins over the settings file when set — the same
override the repair/replay probes use. Without either, self-sent
import rows keep a NULL sender (visible in the probe as the
missing-sender count).

Output, per entity mapped:

```
import dry-run: messages: extracted=4 new=2 fill_null=1 ignored=1 update_import=0 skipped=0 by_kind=one2one=4
import dry-run: message content decode: decoded=2 not_encrypted=2 failed=0
import dry-run: unmapped codes: 406 row(s) carry codes the mapping does not list — at apply time: refused without --unmapped-as-raw, else stored kind=100 with text=NULL (content only in payload_json, the raw code string included):
import dry-run:   code -4 x 278
import dry-run:   code -1909 x 128
```

- The second line (batch 24) counts the BasicEncryption decode of
  the mapped `content` column (§1f) — counts only, never a value.
- The last lines (batch 25) are the unmapped-code census — the SAME
  fixed all-DB aggregation the apply preflight runs (§7 precondition
  4), so the dry run lists exactly what an apply would refuse on (or
  hatch). With the batch-25 table on the real snapshot the only
  codes here are the Desktop-local rows `-4` (MSG_INFO) and `-1909`
  (MSG_INFO_CHAT, §1g); with every occurring code mapped it prints
  `import dry-run: unmapped codes: none (every code in the snapshot
  is mapped)`. A census that itself cannot run (unreadable DB,
  non-plain `msgType` mapping) prints `census failed: …` — the apply
  keeps its fail-closed refusal on the same condition.

- `extracted` — rows the mapping turned into `Write`s (`skipped` =
  rows it could not: NULL keys, an unparsable ts, a blob in a direct
  field).
- `new` — no row with that msg_id in the shadow copy: the apply step
  would INSERT.
- `fill_null` — a capture/e2ee row exists and import would only
  fill a NULL cell (`text`/`sender_id`). **Import never replaces
  capture/e2ee text, payload or type** — its rank is below both.
  For conversation/contact/group the upsert has no rank guard, so
  `fill_null` there means "the import would change at least one
  stored cell" (a differing title/name, a `raw_json` refresh, a type
  flip, or a forward move of `last_msg_id`).
- `update_import` — a row a PREVIOUS import wrote whose payload
  would change (rank 1 >= 1; a converging replay is `ignored`).
- `ignored` — nothing would change.

Without `--shadow-copy` the classification is skipped (you still
get the extraction counts). `--delta` adds, per DB:

```
import delta: Core/Message/111.db cursor=none total_rows=4 would_extract=4 next_cursor=1690000003:104
```

The cursor lives in the shadow DB's `sync_cursors` table under
`import:<db-relative-path>` as `"<max_ts>:<max_rowid>"` — **in the
source column's own units** (the delta comparison compares against
the raw ts column; changing the mapping's ts unit requires a fresh
cursor). `--delta` skips a row only when BOTH `rowid <= max_rowid`
AND `ts <= max_ts` — a fresh rowid or a newer ts is always included;
an in-place edit of an old row is not (the accepted 2.7 risk: web
capture already records recalls). The dry run only READS cursors;
it never writes them (`write_import_cursor` is for the approved
apply step).

## 5. The 2.3 acceptance: overlap probe

When the dry run looks sane, run the probe that the AC actually
measures — it compares the Desktop rows (through your mapping) with
the shadow rows for the 20 most recent conversations present in both
(10 one2one + 10 group when available), cut to the overlapping time
window:

```powershell
$env:ZR_SNAPSHOT_DIR = "D:\ZaloRust Data\import-snapshot\2026-MM-DD"
$env:ZR_D7_KEY_FILE  = "D:\.opencode\d7\zalo-desktop-uin-key-2026-11-19.bin"
$env:ZR_UIN_HASH     = "dca62c394a68"
$env:ZR_MAPPING      = "D:\...\mapping.json"
cargo test --lib probe_import_overlap -- --ignored --nocapture
```

(`ZR_PROBE_DIR` overrides which shadow store gets copied.)

Per conversation (h12 of the conversation id only — never the raw
id, never message content):

```
overlap: conv=1a2b3c4d5e6f kind=one2one desktop=210 shadow=205 matched=209 pct=99.5% type=209/209 type_str=209/209 (compared 209) ts=209/209 sender=205/205 (compared 205)
```

Two type axes (batch 15): `type` is the NUMERIC axis — degenerate
while the still-soaking pre-H1-fix build writes `type=100` for every
real message — and `type_str` is the meaningful one: the import's
MAPPED msgType string vs the shadow payload's `$.msgType` (the
original wire string). The first line reports both; a mapping whose
`msgType` table is wrong shows up as `type_str` disagreements long
before the numeric axis means anything.

Totals and the verdict lines at the end:

```
overlap: TOTAL ...
overlap: AC msgId overlap >= 99%: MET (99.1%)
overlap: AC type/ts 100% on matches: MET
overlap: AC sender 100% on matches: NOT MET (missing-sender matches are shown above)
```

- `pct` counts Desktop msgIds found in the shadow (the AC's
  direction: "msgId Desktop trùng msgId shadow ≥ 99%").
- Sender agreement is over the matches where BOTH sides have a
  sender; self-sent Desktop rows keep a NULL sender in the import
  unless an own uid is configured — `ZR_OWN_UID` for the probe
  (validated, printed only as `own_uid set: true/false`) or the
  CLI's `--own-uid-from-settings` — and those matches are reported
  in the `(compared N)` / missing-sender line — nothing is hidden,
  decide whether they are acceptable or fix them in the
  mapping/own-uid configuration.
- The probe is pure comparison plus reads: it opens the snapshot
  through the batch-6 guards and the shadow DB through a temp copy;
  it writes nothing and asserts nothing about your data (the verdict
  lines are the measurement).

If `pct` is low, the usual suspects are: msgId stored as
`cliMsgId`/int vs string, the ts unit (run the dry run and compare a
few `ts_agree` rows), or a conv derivation that misses (`{"const":
"$db_id"}` on `idTo` is the fix for one2one/group DBs whose rows name
the wrong party).

## 6. What is deliberately NOT here

- No media hardlinking (2.6 is the PLAN — §8; the hardlink itself is
  a later, separate step).
- No writes anywhere in §1–§5: snapshot DBs open immutable, the shadow
  store is file-copied and opened `query_only`, cursors are read-only
  in the dry run. The only write step is `--apply` (§7), and it writes
  only into the `--target` store the user passes — never the snapshot,
  never the live Desktop tree.

## 7. Running the import (2.5) — the guarded apply step

`--apply` is the only mode in this tool that writes. It writes ONLY
into the shadow store you pass with `--target`, and it refuses to
start unless every precondition holds — a refusal exits non-zero with
a message naming exactly what is missing.

```powershell
target\debug\zalors.exe import `
  --from-snapshot "<snapshot dir>" `
  --account default --uin-hash <sha256-12 of the D7 passphrase> `
  --key-file "<D7 key capture>" `
  --mapping "<mapping.json>" `
  --target "<shadow store dir>" `
  --apply --i-have-a-backup-plan
```

(The `--key-file` is the DPAPI-wrapped D7 capture — never the key as
text; only its sha256-12 ever appears in output, cross-checked against
`--uin-hash`.)

**The preconditions, in the order they run** (each enforced in code,
each with a unit test on synthetic fixtures):

1. `--apply` AND the explicit second flag `--i-have-a-backup-plan` AND
   `--target <shadow store dir>` AND `--mapping <file>`. There is NO
   default target: the live store is never silently chosen — you pass
   it, even when it *is* the live store. Parse errors exit 2; runtime
   refusals exit 1.
2. The app must not be running: the run refuses if any process named
   `zalors.exe` other than the importing process itself exists (exact
   name match, own PID excluded), and also refuses when the check
   itself cannot run (fail closed — one writer, A5).
3. Before the first write: `backup::backup_db` of the target into
   `<target>\pre-import-backups\` (the batch-8 SQLCipher export), then
   `verify_backup` (sha256 + `cipher_integrity_check` +
   `integrity_check` + per-table counts). A failed backup or verify
   aborts the run — nothing was written. The run prints the backup
   manifest path. One backup set is added per apply run.
4. The mapping must pass `plan`, and **every msgType code that occurs
   in the snapshot must be mapped** — the preflight runs batch 15's
   fixed distinct aggregation on the mapping's raw msgType column in
   EVERY DB of the mapped kinds and sums the counts. An unmapped code
   without the hatch aborts the run with the per-code counts:

   ```
   import failed: refusing --apply: 406 row(s) carry msgType codes the mapping does not list ...
     - code -4 x 278
     - code -1909 x 128
     ...
   ```

   (With the batch-25 table (§1g) the real snapshot's only unmapped
   codes are the Desktop-local pair `-4`/`-1909` — codes with NO wire
   msgType, so there is nothing to add to the table for them.)

   The ONE escape hatch is `--unmapped-as-raw`: with it, unmapped rows
   are written `kind=100` with `text` forced NULL — content kept only
   in `payload_json`, the raw code string included — never
   JSON-as-text (a media-kind `content` column often holds JSON text,
   and storing that in `text` is exactly what the hatch must never
   do). The preflight prints the per-code counts that will take this
   path. A row with a NULL msgType is unmapped by definition (no code,
   no mapping) and takes the same path. Codes with no wire msgType
   (Desktop-local rows, e.g. the negative sentinel codes the Zalo PC
   26.11.12 source declares without a string) have nothing to add —
   `--unmapped-as-raw` is their only path today, or a later, explicit
   skip decision; any OTHER code listed here is new evidence — re-run
   `probe_import_codes` before mapping it.
5. The run counts and prints how many rows whose `uidFrom` is **NULL
   (not "0")** received the own-uid substitution via
   `normalize::sender_for` — the shared rule treats NULL as self when
   an own uid is configured (`--own-uid-from-settings`, or env
   `ZR_OWN_UID`), and that rule is NOT changed by this batch; the
   number is the reviewer's input for deciding whether NULL should
   stay "self" on the import path.
6. (batch 24) The Desktop content column must **decode cleanly**: a
   pre-apply census decodes the raw `content` cell of every row in
   every mapped DB with the same passphrase that opened them, and
   the run REFUSES when more than 1% of the census rows fail
   (`Failed` — the wrong-key signature: with the right passphrase
   the XOR output is always valid JSON, so a widespread failure
   means the key or the mapping's content column is wrong), printing
   the counts:

   ```
   import apply: content decode census: rows=8418 decoded=8390 not_encrypted=27 failed=1 (0.01% failed)
   ```

   A mapping with no plain content column skips the census (printed,
   never silent). The refusal fires before the target is even opened
   — zero bytes move.

**The write path**: extract → `writer::apply` with `source='import'`,
inside batches of 500 rows per `BEGIN IMMEDIATE … COMMIT`, each row
isolated by the pipeline's SAVEPOINT so one bad row never aborts the
batch — errors are counted and kind-logged (`errors=1 kinds=message:sqlite_Abort/5`),
and only a statement that kills the whole transaction stops the batch.
Import precedence is the writer's own guard, reinforced by
classify-then-skip: import only ever fills NULL cells of capture/e2ee
rows — their text/payload/type are byte-identical before and after
(unit-tested), and writes classified `Ignored` are skipped outright.

**Resume**: per source DB, a `sync_cursors` row (`import:Core/Message/<db>`,
`"<max raw ts>:<max rowid>`) is written **in the same transaction as
its batch**. Kill the run anywhere: the committed batches + their
cursors survive, the next run resumes exactly there (unit-tested by
stopping after DB 1 and by seeding a mid-DB cursor — the re-run
imports only the tail). A single row that errors permanently (the
poison-row test) stays behind its batch's cursor and is simply not
retried until the cursor moves.

**Idempotence**: a second full apply changes 0 rows — the run prints
`store changes (total_changes delta since the backup): 0`. Two layers
make that true: cursors skip already-imported DBs outright, and (the
strict case, with cursors cleared) every re-extracted write is
classified `Ignored` and skipped — 0 data rows change, only the cursor
rows are rewritten.

**After the run**, verify with the probes:

```powershell
cargo test --lib probe_import_overlap -- --ignored --nocapture   # the 2.3 AC, again
cargo test --lib probe_audit_shapes -- --ignored --nocapture     # the integrity metrics stayed 0
cargo test --lib probe_import_codes -- --ignored --nocapture     # codes vs $.msgType purity
# and the golden oracle (the frozen V1 copy — never the live DB):
$env:ZR_GOLDEN_DIR="D:\.opencode\golden-oracle-2026-11-14"; cargo test --lib golden_replay -- --ignored --nocapture
```

**Mapping changes after an apply**: a re-apply only revisits rows whose
cursor does not cover them, so extending the mapping's `msgType`
table requires the documented cursor reset — delete the
`import:Core/Message/<db>` rows from `sync_cursors` (or apply into a
fresh store copy) — the same rule as changing the mapping's ts unit.
With the cursors reset, previously-hatched rows are re-applied as
`update_import` writes: import rank (1) >= the stored import rank (1)
replaces `payload_json`/`type`/`text`, so the hatch is not a dead end —
the unit test pins exactly that. Two caveats, stated honestly:
`fill_null` proper (import into a CAPTURE/e2ee row) can only fill
`text`/`sender_id` — it cannot change `type` on those rows (rank 1 <
2, the writer's guard), and a media code (e.g. `chat.photo`) fills
`type` but never `text` — media content objects do not become text.

## 8. Media (2.6) — plan only

`--media-plan` is the 2.6 dry run: it discovers where the snapshot
keeps Desktop media metadata — `Core\Index.db` tables named
`image`/`file`/`media`, plus every table of `Core\Media.db` when that
DB is present — and, within those, reads the first column whose name
contains `path` (case-insensitive; a table without such a column is
skipped). Row values are used ONLY internally: a value counts when
it is an absolute local path (drive letter or UNC); urls and relative
values are not rows. For each such row it computes, with
`std::fs::metadata` alone (no content is read):

- does the file exist (a directory or an unreadable path counts as
  missing),
- its size,
- whether the path is on the same volume as the media store
  (drive-letter comparison — the KQ9/D9 hardlink rule; the store root
  is resolved exactly the way the media worker resolves it:
  `settings.shadow.media_store`, else the documented default).

No sha256 happens anywhere in this plan — hashing is the later apply
step's job — and NO hardlink is ever created. Output is counts only
(never a path value):

```
media plan: dry-run — no hashing, no hardlinks, nothing written
media plan: Core/Index.db table image (path column "filePath")
media plan: rows=… present=… missing=… total_bytes=… same_volume=yes:… no:…
media plan: … bytes_hardlinking_saves_vs_copy=… media_dbs_failed=…
```

`bytes_hardlinking_saves_vs_copy` is the sum of the present,
same-volume bytes — exactly the files a hardlink could deduplicate
(the number to compare against "free space on D: dropped < 1 % of
49.4 GB" when the real hardlink step runs later). The table/column
names in the per-table lines are shape (the inventory vocabulary), and
they are also the knobs to adjust if the real Desktop schema turns
out to name its media tables or path columns differently: run
`--inventory` and check what the three Index tables and `Media.db`
actually carry.

## 9. Imported history in the media queue (batch 26)

The batch-25 apply writes every message through `writer::apply` with
`source='import'`, and the writer derives attachment refs from media
payloads at apply time — so the import filled `attachments` with
KNOWN urls from history (58,665 rows on the real store). The live
media thread picks any `status='ref'` row, which silently turned the
import into exactly the history backfill scan the media module doc
forbids. Batch 26 separates the two queues; the import tool itself
is unchanged.

**Statuses** (`attachments.status` — still NO CHECK constraint, no
migration, no schema VERSION bump; the writer stays the single status
authority):

- `ref` — a live capture's url; the ONLY thing the live thread picks.
- `ref-import` — a known url from imported history. Rows created for
  a `source='import'` write start here (the writer passes the
  write's source into the extraction), and the live thread never
  picks them by default. A later live capture of the same
  `(msg_id, idx)` improves the row's url through the shared rule but
  never upgrades the status.
- `expired` — the link is gone (HTTP 403/404/410). Expired CDN
  history is not a broken row: the url is kept and the row is never
  retried. Every other download failure still lands as `failed`.

**The repair step** moves the pre-batch-26 import rows into the
history queue. The report line appends `media_import_requeued=` as
its LAST field and the maintenance counts line appends
`media_import_requeue=` (every existing field keeps its name and
order); the step itself moves exactly the import-sourced rows still
carrying a live-queue status (`ref`/`failed`) to `ref-import`. It is
idempotent (a second run reports 0), never demotes
`downloaded`/`ref-encrypted`/`expired` rows, and never touches
capture-sourced rows:

```powershell
target\debug\zalors.exe repair --target "<shadow store dir>" --dry-run
```

**The opt-in backfill** — `shadow.media_backfill_import` (bool,
DEFAULT FALSE): with it true the app may also drain the history, but
only after the `ref` queue produced no rows in that cycle, at most 2
rows per cycle. A circuit breaker pauses the picks for the rest of
the session after 20 consecutive `gone`/`http_other` outcomes on
import rows and logs exactly one line:

```
shadow media: import backfill paused (consecutive_fail=20)
```

The cycle log itself gains the failure split, appended after every
existing field (kinds only — the ureq error text embeds the request
url and never reaches a log):

```
shadow media: cycle reported ok=… failed=… blocked_host=… blocked_redirect=… ref_encrypted=… failed_kinds=(gone … http_other … timeout … net … store …)
```

**The shape tool** answers "why does a pick fail" without ever
printing a url (`shadow/media_cli.rs`, dispatched from `main.rs` like
`repair`):

```powershell
target\debug\zalors.exe media --target "<shadow store dir>" --shape
target\debug\zalors.exe media --target "<shadow store dir>" --shape --probe-http 5
```

READ-ONLY with the normal key resolution (the raw DPAPI key file, or
the passphrase remember file; a Locked store refuses — this CLI
never accepts a password), no process check, no backup: safe to run
while the app keeps running. It prints:

- the census, grouped by `messages.source` (capture / e2ee / import /
  no-message) × `kind` × `status` × host verdict (the allowlist
  SUFFIX, `blocked` or `nourl`) × path shape (segment count and the
  first segment's charset CLASS, never a value) × sorted query KEY
  names, with a flag when any key looks like expiry/signature
  (`exp`, `expires`, `e`, `sig`, `signature`, `token`, `x-amz-*`,
  case-insensitive);
- for import rows: which payload FIELD the picker took each url from
  (`params.hd`, `href`, …) and whether the pick still matches the
  stored url, plus every url-bearing key NAME Desktop content
  carries at all (names + counts).

`--probe-http <n>` (1..=20, default OFF) is the batch's ONLY network
code path: for up to n import-sourced
`status IN ('ref','failed','expired')` rows PER KIND whose url
passes the allowlist, ONE GET with the download agent's own config
(no automatic redirects, the same timeouts), reading at most the
first 16 bytes, reporting the class — 2xx with the `magic_ok`
verdict, 3xx with an allowed or blocked Location, 403/404/410, other
4xx, 5xx, timeout, tls/dns/io. Nothing is stored, no url is ever
printed, and no test calls it. `--out <file>` also writes the report
to a file and REFUSES if the file already exists.

## 10. Zalo PC local media: probe + dry-run plan (batch 27)

The CDN cannot serve this history (`--probe-http` measured 15/15 dead
links), but Zalo PC keeps a local copy of much of it under
`<root>\media\<uid>\ZaloDownloads\<sub>\…`, where `<sub>` is one of
`picture, video, file, fileNoise, fileThumb, voice, richThumb,
zinstant, resource, Cache` (plus `<root>\media\<uid>\sticker\…`).
Batch 27 adds the READ-ONLY tools that measure how the Desktop's own
rows point into that tree, plus a DRY-RUN planner for copying the
files into the media store later. **Copying is NOT part of batch 27**
— it is a later, user-approved batch (27b) that comes after the real
numbers below are read.

Hard rules for both tools (H-rule): never a path value, file name,
directory name, uid, msgId or message text — only counts, the fixed
`<sub>` vocabulary (anything else prints as `other`), path-shape,
extension and magic classes, length/charset buckets and booleans. The
only file facts ever gathered are the FIRST 16 BYTES (the magic) and
`metadata().len()` (the size) — no whole file is ever read, hashed or
copied, and `fileNoise` contents are never decoded. The snapshot opens
through the usual guards (`mode=ro&immutable=1`); the store opens
READ-ONLY with the normal key resolution (a Locked passphrase store
refuses — the CLI never accepts a password). Nothing is written
anywhere: no DB, no files, no temp copies, `--out` aside.

### 10.1 The inventory covers the top-level snapshot DBs (M1)

`--inventory` now ALSO tries every `*.db` directly under the
snapshot's uid dir (`Media.db`, `MsgInfo.db`, `Res.db`, `Meta.db`,
`Reaction.db`, `Sync.db`, `E2ee.db`, `Preferences.db`) with the SAME
open path and key as `Core/*.db` — SQLCipher with the snapshot
passphrase and the detected profile first, then a plain SQLite open —
and reports:

```
inventory: top-level DBs: 8 (opened cipher=… plain=… no=…)
inventory: top-level <name>.db opened=yes (cipher|plain) (N table(s))
  <the same table/column/rowcount lines as Core/>
inventory: top-level <name>.db opened=no (<log-safe kind>)
```

`sqlite_NotADatabase/26` means "wrong key or another format" for a
file that is neither plain SQLite nor SQLCipher-with-this-key (the
expected verdict for the real Media.db & co). The `--out` JSON gains
the same section (`top_level`, `serde(default)` — old files still
load). Everything the mode printed for `Core/` above the new section
is unchanged.

### 10.2 The probe (M2)

```powershell
target\debug\zalors.exe import `
  --from-snapshot "<cold snapshot dir>" --account default `
  --uin-hash dca62c394a68 --key-file "<D7 capture>" `
  --local-media-probe --local-media-root "D:\Zalo Data" [--out <file>]
```

`--local-media-root` is REQUIRED and is a USER SETTING passed
explicitly (the Zalo PC media root — the dir whose `media` child holds
the per-uid trees). Its own mode: mutually exclusive with
`--apply`/`--inventory`/`--mapping`/`--shadow-copy`/`--delta`/
`--distinct`/`--content-shape`/`--media-plan`. `--out <file>` writes
the same report to a NEW file. It reports:

- **the census** — for every message row in every snapshot message DB,
  per Desktop msgType code (the fixed SELECT reads only the
  bookkeeping columns `msgId, msgType, localPath, folderPath,
  previewThumb, fileSize, cliMsgId, sendDttm` — never the `message`
  text): rows, localPath/folderPath/previewThumb presence, the path
  shape class (`abs_drive`/`abs_unc`/`relative`/`file_url`/`other`),
  under-root yes/no (case-insensitive prefix after normalising
  slashes, on the path RESOLVED via folderPath when relative), the
  `<sub>` it falls in, file exists, `size == fileSize` match/differ,
  the magic class of the first 16 bytes (`jpg, png, gif, webp, jxl,
  jxl_container, mp4, webm_mkv, pdf, zip, html, other`), and the
  name-contains-msgId/-cliMsgId/-sendDttm(13-digit) booleans;
- **the zcloud census** — `Core/Index.db`'s `zcloud` by `zType`, the
  same localPath census with `zSize` as the size column (skipped with
  a line if the table/columns are absent);
- **the reverse coverage** — a walk of
  `<root>\media\*\ZaloDownloads\*` that counts, per `<sub>` with a
  magic histogram, the files NO message row's `localPath` points at
  (`*.rescache` index files skipped, hard 200 000-file cap).

Batch 27c (reviewer findings on the real data): every column of every
scan is read as a SQLite Value and coerced — the real Desktop
`message` table declares `sendDttm:TEXT` (digits stay TEXT) and
`fileSize:INTEGER` (non-numeric text stays text), so the old
fixed-type read of `sendDttm` dropped EVERY row on the real snapshot
(`query_failed=467616`, `rows=0`). A type surprise is counted and
NEVER drops the row: the `message DBs:` line gains
`row_failed=` (a row whose `rows.next()` errored) and
`coerce_none=<col>:N,…` (the un-coercible values by column name,
`none` when everything coerced); `query_failed` is now strictly the
per-DB prepare/query failures; the zcloud line carries the same two
counters. The header also no longer echoes path values (H-rule):
`root=given (exists)` instead of the root, and `report written
(--out)` instead of the file name (the `--out` refusal keeps its
wording, without the path).

### 10.3 The plan (M3, DRY RUN ONLY)

```powershell
target\debug\zalors.exe import `
  --from-snapshot "<cold snapshot dir>" --account default `
  --uin-hash dca62c394a68 --key-file "<D7 capture>" `
  --local-media-plan --target "<shadow store dir>" `
  --local-media-root "D:\Zalo Data"
```

The store opens READ-ONLY with the `repair_cli` key resolution (the
app may keep running; a Locked passphrase store refuses). For each
attachment whose message has `source='import'` (ANY status), the plan
finds the Desktop row with the same message id (the import's own
`msgId` → `msg_id` mapping), resolves its `localPath` (joining
`folderPath` when the cell is relative) and classifies ONE outcome per
shadow kind, in this priority:

`already_downloaded` (the row already has the file) ·
`no_desktop_row` · `no_local_path` · `outside_root` (the resolved
path is not under `--local-media-root`) · `noise_obfuscated` (the path
is under `fileNoise` — counted, never decoded) · `missing_file` ·
`size_excluded` (exists but 0 bytes or over the 512 MB cap — the
would_copy definition's own size clause) · `magic_mismatch` (fails
`media::magic_ok` for the row's kind; batch 27 M4 makes JPEG XL an
image, so `.jxl` copies are fine) · `would_copy` (exists, size in
range, magic fits).

It also prints the TOTAL BYTES `would_copy` would add (the sum of
`metadata().len()`), and the `no_attachment_row` census: per Desktop
msgType, the rows whose local file exists while the shadow knows the
message but has no attachment row for it (`not_in_shadow` counts the
rows whose message was never imported at all — the imported video gap
the batch-26 census found, msgType 18, is `no_attachment_row`). NO
writes of any kind: no DB, no files, no temp copies.

Batch 27c: the plan's own snapshot scan uses the same tolerant
reads — its header line is `message DBs dbs=… opened=…
open_failed=… query_failed=… no_table=… rows=… row_failed=…
coerce_none=…`, counting what the old code silently skipped, and it
states `store=given` / `root=given (exists)` instead of echoing the
`--target` / `--local-media-root` path values.

### 10.4 JPEG XL is an image (M4)

`media::magic_ok(Some("image"), …)` now also accepts the JXL bare
codestream (`FF 0A`) and the container signature
(`00 00 00 0C 4A 58 4C 20 0D 0A 87 0A`). This also affects live
downloads — a CDN serving JXL is no longer flagged `ref-encrypted`
(intended), and the archive window serves JXL as `image/jxl` (the
viewer would otherwise 404 every stored JXL the store now accepts).

### 10.5 Media.db / Res.db — the import-attachment link (batch 27d)

The real-data run killed `message.localPath` as the link: it is EMPTY
for 57.6k of the 58.5k import attachments, 744 more rows point
outside the media root (`--local-media-plan` measured
`would_copy=0`), and `Index.db zcloud.localPath` is empty for all
1,023 rows — while the reverse coverage counted ~80k files under
`ZaloDownloads` that NO message row points at (`picture` 19.8k,
`resource` 58.7k, `video` 897, …). The link therefore has to live in
the TOP-LEVEL snapshot DBs, which all open with the snapshot cipher
key (§10.1): `Media.db` (`image` 115k rows: `mediaId pk, convId,
cliMsgId, …, content, type, sendDttm, localPath, previewThumb,
metadata`; `file` 8.3k: the same plus `folderPath`/`thumbMetadata`)
and `Res.db` (`res`: `uid pk, size, type, atime, params`; `ref`:
`msgId pk, convId, uid`).

`--local-media-probe` (same command as §10.2) gains three sections
plus one skipped milestone, all with the §10.2 tolerant reads and the
same H-rule (counts, fixed vocabularies, path-shape/magic classes,
rendered code tokens, and JSON key NAMES — schema, printed under the
`--content-shape` rule: identifier-shaped names as-is, anything else
as `k:<sha256-12>`; never a value):

- **Media.db, by `type` code** — per table (`image`, `file`):
  rows; the non-empty counts of the table's path columns
  (`localpath`/`previewthumb` or `localpath`/`folderpath`); the path
  shape class, under-root and `<sub>` over the rows with a
  `localPath` (relative cells resolve via `folderPath`, the file
  table's own column); `exists`, `size_zero`, `total_bytes` and the
  magic class of the resolved file (the first 16 bytes and
  `metadata().len()` only, as everywhere in §10); the name relations
  (`climsgid`/`mediaid`/`senddttm` contained in the cache file name,
  plus the exactly-13-digit `dttm13` run); and the row relations as
  booleans — `climsgid_in_message` (the row's `cliMsgId` equals some
  Desktop `message.cliMsgId`), `mediaid_in_message` (`mediaId`
  equals some `message.msgId`) and `pair_in_message` (the
  `(convId, cliMsgId)` pair matches — the message row's convId is
  its DB file-name digits, the mapping's own conversation-id
  domain). For `content` and the metadata column: the five shape
  classes (`json_object | json_array | text | empty | other`,
  `text` = a JSON string scalar, the double-encoded Desktop shape),
  the top-30 key names, and — for `content` only — the batch-24
  `BasicEncryption` decode with the snapshot key
  (`--content-shape --decrypt-basic`'s own helper), reported as
  `decrypt=ok|fail|na` counts plus the decoded shape and key names
  (`ok` = decoded, `na` = the cell was never encrypted, `fail` = a
  blob or the wrong-key signature).
- **Res.db** — `res` by `type`: the `params` shape and top-30 key
  names, plus `uid_file_hits` — how many `uid` values equal a cache
  file STEM, per `<sub>` (the stems come from the §10.2 reverse-
  coverage walk, which now gathers them for every file). `ref`:
  `msgid_in_message` (vs every `message.msgId`) and `uid_in_res`
  (vs the `res` uids), yes/no/na.
- **file-name keys** — for the cache's `picture`/`video`/`resource`
  files, how many carry an exactly-13-digit name part equal to some
  `message.sendDttm` / `message.cliMsgId` / `message.msgId`, or some
  `Media.db image.sendDttm` / `image.cliMsgId` (HashSets over the
  scans; counts only). The measured name shapes it targets: picture
  `<letter><13 digits>_<32 alnum>.jxl|.jpg`, video 13 digits.

Everything above a missing DB, table or column prints one skipped
line (the zcloud convention — a report, never fatal). The walk's
hard 200 000-file cap now also bounds these sets (`cap_hit=yes`
means partial).

**M2 is SKIPPED and reported as such.** The milestone asked whether
the 32-char part of a picture file name is the MD5 of a content url
(full and without query, per url field — `oriUrl`, `normalUrl`,
`thumbUrl`, `hdUrl`, `href`, `params.hd`, … the key names
`zalors media --shape` already reports). No MD5 implementation
exists anywhere in the dependency tree (`sha2`/`blake2` only — a SHA
hex is 64 chars and can never equal a 32-char part), and the brief
forbids adding a crate, so the probe prints exactly:

```
local-media-probe: picture-name hash: md5=unavailable (no MD5 implementation exists in the dependency tree and the brief forbids adding a crate — milestone skipped)
```

A later batch may revisit it only with an approved dependency (or a
reviewer-vetted hand-rolled MD5, which the current brief does not
allow).

### 10.6 The plan matches by cache name keys (batch 27e, DRY RUN ONLY)

The v1 plan (§10.3) followed `localPath` only. Measured on the real
cache with the 27d probe, the cache file NAMES carry the message key:
`picture` = `<letter><13 digits>_<32 alnum>.jxl|jpg` and `video` =
`<13 digits>`, both equal to the Desktop `message.msgId` (which is the
shadow `messages.msg_id` of an import row); `resource` files are named
by the 13-digit `message.cliMsgId`. The plan v2 therefore builds ONE
in-memory candidate index from a single read-only walk of
`<root>\media\*\ZaloDownloads\{picture,video,resource,file}` (the 27d
walk: `*.rescache` skipped, 200 000-file cap) and chooses per
attachment:

- **Keys.** picture/video: the one 13-digit run of the stem is the
  msgId; resource: it is the cliMsgId (the plan's Desktop scan now
  also reads `cliMsgId`, tolerantly as in 27c). A stem with zero or
  more than one 13-digit run is `unkeyed` (counted per sub).
  `file` files are real-named and stay unkeyed here; `fileNoise` is
  never indexed or decoded. The Desktop row's own `localPath`
  (batch 27) stays as one more candidate source when it resolves under
  the root.
- **`choose_candidate(kind, cands)`** (pure). Keep candidates whose
  magic fits the kind (`media::magic_ok`: image jpg/png/gif/webp/jxl,
  video mp4/webm, file and voice any), drop size 0 and size above
  512 MB. Preference: (1) a renderable copy beats JXL (the WebView2
  archive viewer cannot render JPEG XL), (2) picture/video before
  resource, (3) the larger size. Outcomes: `already_downloaded`
  (decided before the lookup), `would_copy_renderable`,
  `would_copy_jxl_only`, `magic_mismatch`, `size_excluded`,
  `no_candidate`.
- **What the files are.** Only the first 16 bytes and
  `metadata().len()` are read. The H-rule holds: counts, fixed
  vocabularies, buckets and booleans only. No writes.

Report lines (all counts; `<w>` = `picture|video|resource|file|localPath`):

```
local-media-plan: kind=<k> rows=<n> outcomes already_downloaded=<n>(bytes=<b>) would_copy_renderable=<n>(bytes=<b>) would_copy_jxl_only=<n>(bytes=<b>) magic_mismatch=<n>(bytes=<b>) size_excluded=<n>(bytes=<b>) no_candidate=<n>(bytes=<b>)
local-media-plan: kind=<k> won picture:<n> video:<n> resource:<n> file:<n> localPath:<n>
local-media-plan: total would_copy bytes=<b>
local-media-plan: image attachments (kind=image, not already downloaded): rows=<n> fitting histogram 0:<n> 1:<n> 2:<n> 3+:<n>
local-media-plan: image messages: messages=<n> atts_vs_fitting_differ=<n>
local-media-plan: picture vs resource (both fitting): pairs=<n> ratio <0.25:<n> 0.25–0.75:<n> 0.75–1.33:<n> >1.33:<n>
local-media-plan: picture vs resource magic pairs <picMagic>/<resMagic>=<n> ... | none
local-media-plan: videos (import messages with Desktop msgType 18): messages=<n> with_fitting_candidate=<n> bytes=<b> no_attachment_row=<n>
local-media-plan: candidate walk: ... cap_hit=yes|no
local-media-plan: index sub=<picture|video|resource|file> files=<n> keyed=<n> unkeyed=<n> keys=<n> keys_needed=<n>
```

The picture-vs-resource ratio is resource size over picture size; it
tells whether `resource` is a thumbnail (`<0.25`) or the original.
`no_attachment_row` counts msgType-18 videos that have no attachment
row, which batch 27b will have to create. Attachment-index to file
ordering is unknown, so multi-image messages are only counted
(`atts_vs_fitting_differ`), never matched one to one.

### 10.7 Copy the local media into the store, and show JPEG XL (batch 27b)

Batch 27b turns the §10.6 selection into real copies, and makes the
archive viewer show JPEG XL. Decisions taken by the user: files are
REAL copies (no hardlinks), and `jxl-oxide` (pure Rust) is the only new
crate.

#### M1 — `import --local-media-copy`

```powershell
# DRY RUN: the same selection, then what WOULD be copied. No writes; the
# app may keep running.
target\debug\zalors.exe import `
  --from-snapshot "<cold snapshot dir>" --account default `
  --uin-hash <sha256-12> --key-file "<D7 capture>" `
  --local-media-copy --target "<shadow store dir>" `
  --local-media-root "<Zalo PC media root>" [--include-video] [--limit N]

# APPLY: quit the app first.
target\debug\zalors.exe import `
  --from-snapshot "<cold snapshot dir>" --account default `
  --uin-hash <sha256-12> --key-file "<D7 capture>" `
  --local-media-copy --apply --i-have-a-backup-plan `
  --target "<shadow store dir>" --local-media-root "<Zalo PC media root>" `
  [--include-video] [--limit N]
```

No `ZR_*` environment variable is read by this mode. The MEDIA root (where the
files are copied) is resolved like the live media thread resolves it:
`settings.shadow.media_store`, else `D:\ZaloRust Data` when it exists,
else the app-data default. `--target` is the shadow STORE dir; it has
no default. It is its own mode (one mode per run: it refuses
`--inventory`, `--mapping`, `--shadow-copy`, `--delta`, `--distinct`,
`--content-shape`, `--media-plan`, `--local-media-probe`,
`--local-media-plan`, `--out`), and it does not take `--mapping`.

**Guards of `--apply`**, in this order; each refuses with zero writes:

1. no other `zalors.exe` runs (a probe that cannot run also refuses);
2. the store opens read-write with the normal key resolution (a Locked
   passphrase store gets the documented remember-file refusal; the CLI
   never accepts a password);
3. the stored schema version equals this binary's;
4. the disk check: `planned bytes x 1.05 + 1 GiB` must be STRICTLY
   below the free space of the volume holding the MEDIA root (the free
   space probe is injectable in tests; an unmeasurable volume refuses);
5. a verified store backup (the repair helper: sha + integrity + counts)
   into `<target>\pre-localmedia-backups\`, BEFORE the first write.

The selection runs read-only before guard 4 (it needs the planned bytes).
When it plans nothing, `--apply` makes no backup and writes nothing.

**Selection** (per import-sourced attachment, plan v2 plus these rules):

- eligible statuses: `ref-import`, `ref`, `failed`, `expired`.
  `downloaded` is `already_downloaded`; any other status (`ref-encrypted`)
  is `not_eligible`. Neither is ever touched;
- `multi_attachment`: the message has more than one attachment row of
  that kind (the idx to file order is unknown). Skipped;
- `ambiguous_key`: a candidate reached through the `resource` cliMsgId
  key counts only when that cliMsgId sits on exactly ONE Desktop message
  row across all message DBs (counted during the scan); otherwise it is
  dropped, and when nothing is left the outcome is `ambiguous_key`;
- `size_mismatch`: for kinds `file` and `video`, when the Desktop
  `fileSize` is known (> 0) the chosen candidate's size must equal it
  exactly; a mismatching candidate is dropped and the next best is
  tried; none left is `size_mismatch`;
- the rest are plan v2's outcomes: `no_candidate`, `magic_mismatch`,
  `size_excluded`, `would_copy_renderable`, `would_copy_jxl_only`.

**`--include-video`.** Considers import messages with Desktop msgType 18
that have NO attachment row. Only when a video candidate is selected, one
`attachments` row is inserted (`idx=0`, `kind='video'`, `status='ref-import'`;
`msg_id`, `idx` and `status` are the table's only NOT NULL columns, so
`url`, `local_path`, `size` and `sha256` start NULL and are set by the
copy at once; a NULL `url` is never picked by the media thread) and then
copied like any other row. The insert and the update run in one
savepoint after the file was stored, so a failed copy leaves no row.
Without the flag, such videos are only counted.

**Copy.** The chosen file opens and streams through
`media::store_stream` (content addressed, magic sniffed, 512 MB cap), and
the row is updated through the SAME statement `Job::MediaDone` uses for a
successful download (`writer::media_downloaded`: `status='downloaded'`,
`local_path`, `sha256`, `size`). A per-file error is counted by kind
(`open`, `io`, `magic`, `too_big`, `store`) and leaves the row unchanged;
the run continues. A transaction commits every 200 copies, `--limit N`
stops after N copies, and a counts-only progress line prints every 1000
files. A second `--apply` copies 0 and changes nothing.

**Report** (H-rule: counts, the fixed vocabulary and byte sums only; no
path, file name, id, URL, sha or message text):

```
local-media-copy <mode>: kind=<k> rows=<n> outcomes already_downloaded=<n> not_eligible=<n> multi_attachment=<n> ambiguous_key=<n> no_candidate=<n> magic_mismatch=<n> size_excluded=<n> size_mismatch=<n> would_copy_renderable=<n>(bytes=<b>) would_copy_jxl_only=<n>(bytes=<b>)
local-media-copy <mode>: videos (msgType 18, no attachment row): messages=<n> outcomes ... rows_to_insert=<n>
local-media-copy <mode>: planned: files=<n> bytes=<b> new_video_rows=<n>
local-media-copy <mode>: disk check: needed_bytes=<b> result=ok|NOT ENOUGH FREE SPACE|free space unmeasurable
local-media-copy apply: backup verified OK in <target>\pre-localmedia-backups (sha+integrity+counts)
local-media-copy apply: progress files=<n> copied=<n> errors=<n> bytes=<b>
local-media-copy apply: copied=<n> bytes_copied=<b> errors open=<n> io=<n> magic=<n> too_big=<n> store=<n>
local-media-copy apply: video rows inserted=<n>
local-media-copy apply: integrity_check=ok
```

(`<mode>` is `dry run` or `apply`.)

#### M2 — JPEG XL in the archive viewer

WebView2 cannot decode JPEG XL, and most of the local picture cache is
JXL. In the archive media protocol (`zrarchive`), when an `image` row's
stored bytes are JXL (bare codestream or ISO-BMFF container):

1. the first frame is decoded to 8-bit sRGB with `jxl-oxide` (RGB or
   RGBA; a gray image stays gray);
2. batch 28 replaced the full-size PNG that this step first produced
   with WebP derivatives, see §10.8 (`shadow::jxl_decode` keeps the
   decode, `shadow::img_derive` does the rest);
3. the result is served as `image/webp`.

More than 50 megapixels refuses before any frame is rendered (the
header is checked as soon as the image initialises; the decoder's
allocations are also capped), and a decode failure behaves like a refused
content type (404). Nothing logs a path. `archive::content_type_for`
still reports `image/jxl` for the raw sniff; the serving path decides on
the conversion.

Dependencies: `jxl-oxide 0.12.6` with `default-features = false` (no
rayon, no CMS: a single-threaded decode that handles well-known color
encodings; an image that needs an external CMS is a decode failure),
and (batch 27b only) `png`, pinned to `=0.18.1`; batch 28 dropped that
direct dependency (the PNG encoder is gone; `png` stays in the tree
through `image`). The deployed app is a debug build; the
`[profile.dev.package.*]` overrides that keep the decoding crates fast
there are described in §10.8 M4.

### 10.8 WebP derivatives, the pre-warm CLI and a fast debug decode (batch 28)

Batch 27b served a JPEG XL image as a full-size PNG (3.7 MB on average,
decoded on the first view). Batch 28 replaces that with lossy WebP
derivatives, cached on disk and pre-warmed.

#### M1 — `shadow::img_derive`

| variant | long edge | WebP quality | sources |
|---|---|---|---|
| `thumb` | <= 480 px | 75 | JPEG XL, JPEG, PNG |
| `view` | <= 2048 px | 80 | JPEG XL, JPEG, PNG |
| `orig` | <= 16383 px (the WebP maximum) | 85 | JPEG XL only |

- Never upscaled, aspect ratio kept, `image::imageops::resize` with
  `FilterType::Triangle`.
- JPEG XL decodes through `shadow::jxl_decode` (64 MB input, 50 MP and
  2 GiB allocation caps unchanged). JPEG and PNG decode with `image`;
  the 50 MP cap is checked from the header before any pixel is decoded.
  The EXIF orientation of a JPEG is applied.
- GIF, WebP and any other source have no derivative: the original is
  served as before.
- Alpha is kept (RGBA WebP); gray becomes RGB.
- A JPEG/PNG whose long edge is already within the variant's edge and
  that is smaller than 300 KB gets no derivative (`UseOriginal`): the
  original is served. `orig` of a JPEG/PNG is always the original.
- Cache: `<media root>\cache\img\<variant>\<aa>\<sha>.webp`, `<sha>` the
  store file's own name (64 lowercase hex), `<aa>` its first two
  characters; a file with another name is keyed by the sha256 of its
  bytes. A temp file is written in the same directory and renamed; on a
  lost race the existing file is kept. The old `cache\jxl-png` directory
  is no longer read or written (it can be deleted).
- Concurrency: the same sha is never decoded twice at once. A request
  WAITS (at most 30 s) while another thread builds that sha, then
  re-checks the cache and serves it; after the 30 s it builds anyway and
  renames over the other result (same bytes). The guard is an in-process
  `Mutex<HashSet<sha>>` with a `Condvar`.
- Every failure is a plain kind (`too_large`, `too_many_pixels`,
  `decode`, `format`, `encode`, `io`, `unsupported`, `bad_key`,
  `use_original`); nothing carries a path.

#### M2 — serving

The media URL is `/media/<msgId>/<idx>` plus an optional `?v=thumb`,
`?v=view` or `?v=orig`; no query means `view`. The query is parsed
strictly (`archive::parse_media_query`): an empty query, an unknown
value, a duplicate or any other parameter is refused (404). The URL still
carries ids only; the file is resolved inside the media root; the CSP
`img-src zrarchive:` is unchanged.

For an `image` row: `thumb`/`view` serve the cached WebP
(`image/webp`), or the original bytes when the rule above says so;
`orig` serves a full-size WebP q85 for a JPEG XL and the original bytes
for JPEG/PNG. A JPEG XL is never served raw. Any other derivative failure
is a 404 (`private, no-store`). Derivatives carry
`Cache-Control: private, max-age=31536000, immutable` (the key is the
content sha). Video, file and voice rows are unchanged, Range included.
The only log line is `archive: derivatives built=<n>` once per 100
builds.

In the viewer (`settings-ui/archive.js`) an `<img>` in a message bubble
asks for `?v=thumb` when the bubble box (`.att-media`, at most 320 CSS
px wide) needs no more than 480 device pixels, i.e. 320 x
`devicePixelRatio` <= 480 (a 100% to 150% display), else `?v=view`.
`mediaUrl(msgId, idx, variant)` adds the query; videos get none.

#### M3 — pre-warm

```
zalors import --media-derivatives --target <store> [--variants thumb,view] [--limit N] [--threads N]
```

Read-only on the store (it opens the way the archive window does, so it
works next to the running app; a password-protected store without its
remember file refuses). The only writes are cache files under
`<media root>\cache\img\`. For every `attachments` row with
`kind='image' AND status='downloaded'` the file is resolved inside the
media root and each distinct sha is processed once, all missing variants
from ONE decode, by `--threads` workers (default cores - 2, at least 1,
max 64) pulling from a shared queue. A disk check runs first: (220 KB
per missing view + 20 KB per missing thumb) x 1.2 + 1 GiB must be below
the free space of the media root's volume (a variant that would not be
written, such as a small JPEG whose original is served, is not counted).
Idempotent: a second run builds 0. `--limit N` processes only the first
N distinct files; `--variants` accepts `thumb` and `view` (`orig` is
built on demand).

Report lines (counts, fixed vocabulary and byte sums only):

```
media-derivatives: store=given (read-only)
media-derivatives: rows=<n> distinct_shas=<n> unresolved_paths=<n> variants=<list> limit=<n|none> threads=<n>
media-derivatives: missing before: view=<n> thumb=<n>
media-derivatives: disk check: needed_bytes=<b> (est x 1.2 + 1 GiB) result=<ok|NOT ENOUGH FREE SPACE|free space unmeasurable>
media-derivatives: progress shas=<n>/<total>            (every 500 shas)
media-derivatives: variant=<v> built=<n> cached=<n> use_original=<n> errors=<n> <kind>=<n>...
media-derivatives: shas=<n> bytes_written=<b> elapsed_s=<s>
media-derivatives: done
```

#### M4 — a fast decode in the debug build

The deployed app is a debug build. Two things made the image path slow
there although `jxl-*`/`png` already built at opt-level 3:

1. Generic code that the app instantiates itself is compiled at the
   app's own opt-level (0), whatever the dependency's profile says:
   `image::imageops::resize` (a 3000x2000 frame took 1.3 s to the view
   size) and jxl-oxide's `ImageStream::write_to_buffer::<u8>` (330-400
   ms of the decode). The app now calls only non-generic entry points:
   `DynamicImage::resize_exact`, and for RGB/RGBA frames up to 12 MP
   `Render::image_all_channels` + `DynamicImage::into_rgb8/into_rgba8`
   (the streaming path stays for gray, extra channels and bigger frames).
2. `libwebp-sys` is C built through `cc`, which reads the profile's
   opt-level: it was compiled `-O0` (WebP view encode 540 ms). The dev
   profile also keeps debug assertions and overflow checks on inside the
   pixel loops.

The fix is in `Cargo.toml`: `[profile.dev.package.*]` with
`opt-level = 3`, `debug-assertions = false`, `overflow-checks = false` for
the `jxl-*` crates, `png`, `miniz_oxide`, `fdeflate`, `crc32fast`,
`simd-adler32`, `brotli-decompressor@5.0.3`, `image`, `zune-jpeg`,
`zune-core`, `webp`, `libwebp-sys` and `bytemuck`, plus the two
non-generic call changes above. Measured in the unit-test (dev) profile
on a synthetic 3000x2000 JPEG XL (388 KB, made with ffmpeg/libjxl from a
generated image, not real data): thumb + view derivatives 3.6 s before,
about 0.7-0.9 s after; a synthetic 3000x2000 JPEG (675 KB) 4.3 s before,
about 0.35 s after. Real files must be re-measured in the deployed app.
