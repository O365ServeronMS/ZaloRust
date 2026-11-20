# Desktop → shadow mapping (Phase 2.3/2.4 tooling)

This is the how-to for the tools batch 12 added to `zalors import`,
the batch-14 addition, the batch-15 additions, and the batch-16
additions:

- `--inventory` — what tables/columns a cold snapshot actually holds
  (audit §4 item 2.2/2.3 groundwork);
- `--distinct` — whitelisted distinct values of one CODE column in a
  sample DB (batch 14 N1: the tool that settles code tables without
  ever printing content); with `--all-dbs` (batch 15) it sums the
  same aggregation across EVERY DB of a message kind;
- `--mapping <file>` + `--shadow-copy <dir>` (+ `--delta`, and batch
  15's `--own-uid-from-settings`) — the declarative mapping dry run
  with a read-only classification against a temp COPY of your shadow
  store (item 2.4);
- `probe_import_overlap` — the 2.3 acceptance probe (≥99% msgId
  overlap, 100% type/ts/sender on the matches) that a mapping must
  pass before any apply step is even proposed; batch 15 adds the
  `type_str` axis (the meaningful type comparison today);
- `probe_import_codes` (batch 15) — the code cross-tab that resolves
  the Desktop NUMERIC msgType codes against the shadow payload's
  original wire `$.msgType` strings, matched by msgId — the type
  arbiter that needs no deploy;
- `--apply` (batch 16, §7) — the guarded write step (item 2.5): all
  preconditions enforced in code, a verified pre-import backup,
  batched savepoint writes with per-DB resume cursors, and a
  zero-change second run;
- `--media-plan` (batch 16, §8) — the media hardlink PREP dry run
  (item 2.6): counts only, no hashing, no hardlinks.

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
   import failed: refusing --apply: 12600 row(s) carry msgType codes the mapping does not list ...
     - code 19 x 5123
     - code 20 x 3400
     ...
   ```

   The ONE escape hatch is `--unmapped-as-raw`: with it, unmapped rows
   are written `kind=100` with `text` forced NULL — content kept only
   in `payload_json`, the raw code string included — never
   JSON-as-text (a media-kind `content` column often holds JSON text,
   and storing that in `text` is exactly what the hatch must never
   do). The preflight prints the per-code counts that will take this
   path. A row with a NULL msgType is unmapped by definition (no code,
   no mapping) and takes the same path.
5. The run counts and prints how many rows whose `uidFrom` is **NULL
   (not "0")** received the own-uid substitution via
   `normalize::sender_for` — the shared rule treats NULL as self when
   an own uid is configured (`--own-uid-from-settings`, or env
   `ZR_OWN_UID`), and that rule is NOT changed by this batch; the
   number is the reviewer's input for deciding whether NULL should
   stay "self" on the import path.

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
