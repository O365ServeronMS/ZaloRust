# Desktop → shadow mapping (Phase 2.3/2.4 tooling)

This is the how-to for the three tools batch 12 added to
`zalors import`:

- `--inventory` — what tables/columns a cold snapshot actually holds
  (audit §4 item 2.2/2.3 groundwork);
- `--mapping <file>` + `--shadow-copy <dir>` (+ `--delta`) — the
  declarative mapping dry run with a read-only classification against
  a temp COPY of your shadow store (item 2.4);
- `probe_import_overlap` — the 2.3 acceptance probe (≥99% msgId
  overlap, 100% type/ts/sender on the matches) that a mapping must
  pass before any apply step is even proposed.

Everything here is **dry-run only**: `--apply` stays fail-closed until
P2 item 2.5 is explicitly approved (see "What still needs you"
below). Nothing in this pipeline writes to the snapshot, the shadow
store, or the live Desktop data — source DBs open
`mode=ro&immutable=1`, and the shadow store is only ever file-copied
to a temp dir and opened `query_only` there.

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
4. **Approve `--apply` later** — item 2.5 (backup, batch import,
   resume cursors) is a separate, user-approved step. This batch does
   not wire it.
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

Output, per entity mapped:

```
import dry-run: messages: extracted=4 new=2 fill_null=1 ignored=1 update_import=0 skipped=0 by_kind=one2one=4
```

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
overlap: conv=1a2b3c4d5e6f kind=one2one desktop=210 shadow=205 matched=209 pct=99.5% type=209/209 ts=209/209 sender=205/205 (compared 205)
```

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
  (the capture path substitutes the configured own uid), and those
  matches are reported in the `(compared N)` / missing-sender line —
  nothing is hidden, decide whether they are acceptable or fix them
  in the mapping/own-uid configuration.
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

- No `--apply` (2.5): fail-closed, needs your approval, a backup,
  and the batch/resume machinery.
- No media hardlinking (2.6) and no direct `Media.db`/`Reaction.db`
  vocabulary (see the attachment note above).
- No writes to anything: snapshot DBs open immutable, the shadow
  store is file-copied and opened `query_only`, cursors are
  read-only in the dry run.
