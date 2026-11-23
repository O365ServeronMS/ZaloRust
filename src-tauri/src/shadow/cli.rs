//! `zalors import` CLI (P2, audit §4 items 2.0–2.4; batch 6 F1;
//! batch 12 adds `--inventory`/`--out` and the
//! `--mapping`/`--shadow-copy`/`--delta` dry-run mode; batch 14
//! adds the whitelisted `--distinct` code-column probe; batch 23a
//! adds the `--content-shape … --by` content-shape probe; batch 27
//! adds the `--local-media-probe` census and the `--local-media-plan`
//! dry-run planner over the Zalo PC local media tree).
//!
//! Spec (KQ4: the import only ever reads a COLD SNAPSHOT):
//! ```text
//! zalors import --from-snapshot <dir> --account <id> --uin-hash <sha256-12>
//!              [--key-file <file>] [--cipher-compat <3|4>]
//!              [--dry-run | --apply]
//!              [--inventory [--out <file>]
//!               | [--distinct <dbkind>:<table>.<column>]… (max 10)
//!               | [--content-shape <dbkind>:<table>.<col> --by <code_col>
//!                  [--all-dbs] [--out <file>]]
//!               | [--mapping <file>] [--shadow-copy <dir>] [--delta]]
//!              [--help]
//! ```
//! - Value flags consume exactly one value; a missing value or one that
//!   starts with `--` is an error, never a silent skip (audit M2-5: the
//!   old parser advanced two args even for valueless flags, losing
//!   `--key-file` when it followed `--apply`).
//! - `--from-zalo-pc` is RENAMED to `--from-snapshot`: import never
//!   points at the live Desktop tree (KQ4), and `import::run` refuses
//!   any path without a `snapshot-manifest.json`.
//! - The Desktop key is never accepted on argv, never printed, never
//!   logged — only its length and sha256-12 ever appear (F2).
//! - `--dry-run` (the default) performs ZERO writes on the snapshot:
//!   every source DB opens `mode=ro&immutable=1`, so SQLite cannot even
//!   create `-wal`/`-shm` (audit M2-6, F3).
//! - Batch-12 modes are dry-run only: `--inventory`, `--mapping`,
//!   `--shadow-copy`, `--delta` and `--out` all conflict with
//!   `--apply` (item 2.5 wires the writer later, user-approved).
//! - `--inventory` is its own mode; `--mapping`/`--shadow-copy`
//!   select the mapping dry run (`--mapping` absent there = the
//!   built-in skeleton that maps nothing); `--delta` needs that mode.

use std::path::PathBuf;

use super::import::{self, CipherProfile};

/// The usage text (`--help`, and after any parse error).
const USAGE: &str = "\
usage: zalors import --from-snapshot <dir> --account <id> --uin-hash <sha256-12>
       [--key-file <file>] [--cipher-compat <3|4>] [--dry-run | --apply] [--help]

modes (one per run; everything except --apply is dry-run only):
  (default)                  F4 snapshot inventory counts (one line)
  --inventory                schema inventory of Core\\Index.db + ONE sample
                             per message-DB kind (names/types/counts only);
                             --out <file> writes the same as JSON
  --distinct <kind>:<t>.<c>  whitelisted code-column distinct values (batch 14):
                             the column NAME must match the code-column
                             whitelist (type/kind/status/state/cmd/.../is*/
                             has*), values render code-shape only — numbers,
                             NULL, <=32-char [A-Za-z0-9._:-] tokens, else
                             text(len,h12) / blob(len) fingerprints;
                             repeatable, max 10 per run; from the FIRST
                             sample DB of that kind, or with --all-dbs (batch
                             15) summed across EVERY DB of a message kind
  --content-shape <k>:<t>.<c> --by <code_col>
                              content-shape probe (batch 23a): per distinct
                              value of the whitelisted --by code column, the
                              row count, the JSON-shape census of ONE content
                              column (json_object / json_array /
                              json_string_scalar / not_json / null) and the
                              top 8 top-level key signatures — key NAMES only
                              (any other key prints k:<sha256-12>), type
                              letters s/n/b/o/a/z, one nesting level for
                              string values that parse as JSON objects, a
                              24-key cap per signature. NEVER a value: codes
                              render through the --distinct code-shape
                              renderer. The FIRST sample DB of the kind, or
                              with --all-dbs every DB of the message kind
                              summed; --out <file> writes the same as JSON
  --decrypt-basic            with --content-shape (batch 24): decode each raw
                              cell with the Desktop BasicEncryption transform
                              (the snapshot passphrase, in memory only, never
                              printed) BEFORE the shape folding — decoded
                              cells fold through the shadow-side classifier,
                              so the shapes compare directly with the wire
                              $.content. Valid only with --content-shape;
                              the output stays shape only (the header gains
                              ' decrypt=basic')
  --mapping <file>           mapping dry run (docs/import-mapping.md): extract
  [--shadow-copy <dir>]      per the mapping JSON and, with --shadow-copy,
  [--delta]                  classify each write READ-ONLY against a temp
                             COPY of that shadow store. Without --mapping the
                             built-in skeleton (maps nothing) is used.
  --media-plan               2.6 dry run: for each Desktop media row with a
                             local file path (Core\\Index.db tables
                             image/file/media + every Core\\Media.db table),
                             counts files present/missing, total bytes,
                             same-volume yes/no, and the bytes hardlinking
                             would save vs copying. Counts only — no hashing,
                             no hardlinks, nothing written.
  --local-media-probe       batch 27 M2, read-only census of the Zalo PC
                             local media tree as the Desktop's own rows see
                             it, per Desktop msgType code: localPath/
                             folderPath/previewThumb presence, path shape
                             class (abs_drive/abs_unc/relative/file_url/
                             other), under-root yes/no, the <sub> it falls
                             in (picture/video/file/fileNoise/fileThumb/
                             voice/richThumb/zinstant/resource/Cache/sticker,
                             else other), file exists, size==fileSize, magic
                             class of the first 16 bytes, and the
                             name-contains-msgId/-cliMsgId/-sendDttm
                             booleans; PLUS the Index.db zcloud localPath
                             census by zType and the reverse-coverage walk
                             (files under <root>\\media\\*\\ZaloDownloads\\*
                             that no message row points at, per <sub> +
                             magic histogram, *.rescache skipped, hard cap
                             200k files). --out <file> writes the same
                             report and refuses if the file exists. Never
                             prints a path value, file name, uid, msgId or
                             message text. Needs --local-media-root.
  --local-media-plan        batch 27 M3, DRY RUN ONLY: for each attachment
                             whose message has source='import' (any status),
                             find the Desktop row with the same message id
                             (msgId -> msg_id, the import's own mapping),
                             resolve its localPath (folderPath when
                             relative) and classify ONE outcome per shadow
                             kind: already_downloaded / would_copy /
                             magic_mismatch / missing_file / no_local_path /
                             noise_obfuscated / no_desktop_row /
                             outside_root / size_excluded, plus the total
                             bytes would_copy would add. The store opens
                             READ-ONLY with the repair_cli key resolution
                             (a Locked passphrase store refuses — the CLI
                             never accepts a password). NO writes of any
                             kind: no DB, no files, no temp copies. Needs
                             --local-media-root and --target.
  --local-media-copy        batch 27b: copy the Zalo PC local media files the
                             plan v2 selects into the shadow media store
                             (content-addressed, real copies, no hardlinks).
                             Without --apply it is a DRY RUN: the selection
                             report only, no writes. With --apply
                             --i-have-a-backup-plan it writes, after: no other
                             zalors.exe, the store opens read-write (a Locked
                             store refuses), the schema version matches, the
                             disk check (planned bytes x 1.05 + 1 GiB must be
                             below the free space of the MEDIA root's volume),
                             and a verified store backup into
                             <target>\\pre-localmedia-backups\\. Only rows
                             in status ref-import/ref/failed/expired are
                             eligible; downloaded and ref-encrypted rows are
                             never touched. Extra outcomes: ambiguous_key (a
                             cliMsgId on more than one Desktop message row),
                             multi_attachment, size_mismatch (file/video vs the
                             Desktop fileSize). Idempotent: a second --apply
                             copies 0. Rides --include-video and --limit N.
                             Needs --local-media-root and --target; no
                             --mapping.
  --include-video            with --local-media-copy: also create + copy an
                             attachment row (idx 0, kind video, status
                             ref-import) for Desktop msgType-18 messages that
                             have none, only when a video candidate is
                             selected. Without it videos are only counted
  --limit <N>                with --local-media-copy: stop after N copies (a
                             first small real run); with --media-derivatives:
                             process only the first N distinct files
  --media-derivatives        batch 28: pre-warm the WebP derivative cache
                             (thumb 480 px q75, view 2048 px q80) of every
                             downloaded image attachment (JPEG XL, JPEG,
                             PNG) into <media root>\\cache\\img\\. The store
                             opens READ-ONLY (the app may keep running); the
                             only writes are cache files (temp + rename).
                             Idempotent: a second run builds 0. Disk check
                             first. Counts only in the report. Needs
                             --target (no snapshot flags, no --apply).
  --variants <list>          with --media-derivatives: comma list of thumb,
                             view (default thumb,view)
  --threads <N>              with --media-derivatives: worker threads
                             (default: cores - 2, at least 1; max 64)
  --apply                    2.5, the guarded write step (see the
                             preconditions at the bottom) — needs
                             --mapping, --target and --i-have-a-backup-plan

flags:
--from-snapshot  cold snapshot dir (made by tools/snapshot.ps1; KQ4: the
                  live Zalo Desktop tree is never read)
--account        ZaloRust account id (e.g. default)
--uin-hash       expected sha256-12 of the Desktop key (12 lowercase hex)
--key-file       DPAPI-wrapped D7 key capture (the key is never on argv)
--cipher-compat  force cipher profile 3 or 4 instead of auto-detecting
--out <file>     JSON report (with --inventory or --content-shape); the same
                  report as text (with --local-media-probe)
--local-media-root <dir>  the Zalo PC LOCAL media root — a USER SETTING
                  passed explicitly (the dir whose `media` child holds the
                  per-uid ZaloDownloads trees), never read from the
                  snapshot; required by both local-media modes
--shadow-copy    shadow STORE dir whose temp COPY is classified against
                  (its files are read; the store itself is never opened)
--delta          skip rows at/before the per-DB import cursor (dry-run only)
--distinct       see the modes above: whitelisted code-column distinct
                  values, repeatable, max 10 per run, dry-run only
--content-shape  see the modes above: the content-shape probe over ONE
                  content column, grouped by --by; its own mode, dry-run
                  only, needs --by
--by <code_col>  with --content-shape: the code column to group by — it
                  must pass the --distinct code-column whitelist
--decrypt-basic  with --content-shape (batch 24): decode each raw cell
                  (Desktop BasicEncryption, the snapshot passphrase —
                  in memory only, never printed) before the shape
                  folding; valid only with --content-shape
--all-dbs        with --distinct/--content-shape: aggregate across EVERY
                  DB of the message kind (one2one/group/stranger),
                  summing per-DB counts (batch 15); an index spec is
                  refused — there is exactly one Core\\Index.db
--own-uid-from-settings   with --mapping/--shadow-copy or --apply: seed the
                  import extraction's self-sent sender from
                  settings.shadow.own_uid read through the settings loader
                  (never printed; env ZR_OWN_UID, shape-validated, wins as
                  the override)
--dry-run        inventory only, zero writes (the default)
--target <dir>   with --apply: the shadow STORE dir to write into (no
                  default — the live store is never silently chosen).
                  With --local-media-plan: the shadow STORE dir to
                  classify READ-ONLY (the app may keep running)
--i-have-a-backup-plan   with --apply: the explicit confirmation flag. The
                  run still makes its own verified backup first
                  (<target>\\pre-import-backups\\) before the first write;
                  this flag says you ALSO have your own way to restore
--unmapped-as-raw        with --apply: the ONE escape hatch for msgType
                  codes the mapping does not list (the run refuses
                  otherwise, listing them with counts). Unmapped rows are
                  written kind=100 with text NULL — content only in
                  payload_json, raw code string included — never
                  JSON-as-text
--help           this usage, exit 0

the --apply preconditions (each refuses with a clear message, exit 1):
  1. --apply + --i-have-a-backup-plan + --target + --mapping
  2. no other zalors.exe process may run (the store has one writer)
  3. a verified backup of the target before the first write
  4. every msgType code in the snapshot mapped (or --unmapped-as-raw)
  5. the target's schema version must match this binary (the run
     never migrates a store — open it once with the matching build)
  6. the Desktop content column must BasicEncryption-decode cleanly:
     more than 1% failed rows in the decode census refuses the apply
     with the counts (a wrong-key detector, batch 24)
  resume: per-DB cursors, written in the same transaction as each
  batch; a killed run resumes where it stopped, and after any per-DB
  error the cursor stays at the last good batch (a re-run retries the
  failed rows). DBs that open fine but have no mapped table are
  skipped and counted (dbs_no_table). Idempotent: a second full
  apply changes 0 rows (the total_changes delta).";

/// Parsed `zalors import` arguments (pure parse result — see `parse`).
#[derive(Debug, Clone, PartialEq)]
pub struct ImportArgs {
    /// `--from-snapshot <dir>` (required): a cold snapshot made by
    /// `tools/snapshot.ps1`, carrying `snapshot-manifest.json`.
    pub from_snapshot: PathBuf,
    /// `--account <id>` (required): the ZaloRust account id ("default").
    pub account: String,
    /// `--uin-hash <sha256-12>` (required): the expected sha256-12 of
    /// the D7 passphrase; the loaded key must hash to exactly this.
    pub uin_hash: String,
    /// `--key-file <file>`: the DPAPI-wrapped D7 capture. Optional at
    /// parse time; `run` fails closed when it is absent.
    pub key_file: Option<PathBuf>,
    /// `--cipher-compat <3|4>`: force a profile instead of detection.
    pub cipher_compat: Option<CipherProfile>,
    /// `--inventory` (batch 12 L1): shape-only schema inventory mode.
    pub inventory: bool,
    /// `--out <file>`: JSON inventory report (with `--inventory`).
    pub out: Option<PathBuf>,
    /// `--mapping <file>` (batch 12 L2): the declarative mapping JSON.
    pub mapping: Option<PathBuf>,
    /// `--shadow-copy <dir>`: the shadow STORE dir to file-copy and
    /// classify against read-only (never the live store is opened).
    pub shadow_copy: Option<PathBuf>,
    /// `--delta` (batch 12 L4): skip rows at/before the per-DB cursor
    /// (dry-run only now).
    pub delta: bool,
    /// `--distinct <dbkind>:<table>.<column>` (batch 14 N1), parsed
    /// specs in argv order: whitelisted code-column distinct values
    /// from the first sample DB of each kind. Repeatable, max
    /// `distinct::MAX_PER_RUN` per run; dry-run only.
    pub distinct: Vec<import::distinct::DistinctSpec>,
    /// `--all-dbs` (batch 15 O2): with `--distinct`, run the same
    /// fixed aggregation in EVERY DB of the requested message kind
    /// and sum the counts, instead of reading the first sample.
    /// Parse refuses it without `--distinct` and for `index` specs
    /// (there is exactly one `Core\Index.db`).
    pub all_dbs: bool,
    /// `--own-uid-from-settings` (batch 15 O4): read the own uid from
    /// `settings.shadow.own_uid` through the settings loader and seed
    /// the import extraction's self-sent sender substitution with it
    /// (the value is never printed). Env `ZR_OWN_UID` — validated
    /// with `account::valid_uid` — wins as the per-run override.
    /// Mapping dry-run mode only.
    pub own_uid_from_settings: bool,
    /// `--target <dir>` (batch 16 P1, 2.5): the shadow STORE dir the
    /// apply writes into. NO default — the live store is never
    /// silently chosen; the user passes it. Apply mode only.
    pub target: Option<PathBuf>,
    /// `--i-have-a-backup-plan` (batch 16 P1, 2.5): the explicit second
    /// flag `--apply` demands. The run still makes and verifies its
    /// own backup first; this flag confirms the user ALSO has their
    /// own way to restore. Apply mode only.
    pub i_have_a_backup_plan: bool,
    /// `--unmapped-as-raw` (batch 16 P1, 2.5): the ONE escape hatch for
    /// msgType codes the mapping does not list. With it, unmapped rows
    /// are written kind=100 with text forced NULL (content only in
    /// payload_json, raw code string included) — never JSON-as-text.
    /// Without it the apply refuses, listing the unmapped codes with
    /// counts. Apply mode only.
    pub unmapped_as_raw: bool,
    /// `--media-plan` (batch 16 P2, 2.6): the media hardlink PREP dry
    /// run — counts only, no hashing, no hardlinks. Its own mode.
    pub media_plan: bool,
    /// `--local-media-probe` (batch 27 M2): the read-only census of
    /// the Zalo PC local media tree — every snapshot message row's
    /// `localPath` by Desktop msgType code, the Index.db `zcloud`
    /// census by `zType`, and the reverse-coverage walk. Its own
    /// dry-run mode; requires `--local-media-root`.
    pub local_media_probe: bool,
    /// `--local-media-plan` (batch 27 M3): the DRY-RUN copy planner —
    /// for each import-sourced attachment, resolve the Desktop row's
    /// `localPath` and classify the outcome per shadow kind. NO
    /// writes of any kind. Its own dry-run mode; requires
    /// `--local-media-root` and `--target`.
    pub local_media_plan: bool,
    /// `--local-media-root <dir>` (batch 27): the Zalo PC local media
    /// root — a USER SETTING passed explicitly (the dir whose
    /// `media` child holds the per-uid `ZaloDownloads` trees). Never
    /// read from the snapshot. Required by both local-media modes.
    pub local_media_root: Option<PathBuf>,
    /// `--local-media-copy` (batch 27b M1): copy the chosen Zalo PC
    /// local media files into the shadow media store. Without
    /// `--apply` it is a DRY RUN; with `--apply
    /// --i-have-a-backup-plan` it writes after the guards. Its own
    /// mode; requires `--local-media-root` and `--target`.
    pub local_media_copy: bool,
    /// `--include-video` (batch 27b M1, `--local-media-copy` only):
    /// also create + copy attachment rows for Desktop msgType-18
    /// messages that have no attachment row.
    pub include_video: bool,
    /// `--limit N` (batch 27b M1, `--local-media-copy` only): stop
    /// after N copies (a first small real run).
    pub limit: Option<u64>,
    /// `--content-shape <kind>:<table>.<content_col>` (batch 23a C1):
    /// the content-SHAPE probe mode — per distinct value of the
    /// whitelisted `--by` code column, the row count, the JSON-shape
    /// census of ONE content column and its top key signatures,
    /// everything shape-only by construction (key names + type
    /// letters, never a value). Its own dry-run mode.
    pub content_shape: Option<import::distinct::DistinctSpec>,
    /// `--by <code_col>` (batch 23a C1): the code column the shapes
    /// are grouped by. Required with `--content-shape`, refused
    /// without it; must pass the batch-14 code-column whitelist
    /// (validated against the inventory at run time).
    pub by: Option<String>,
    /// `--decrypt-basic` (batch 24 D3): with `--content-shape`, run
    /// the Desktop BasicEncryption decode on each raw content cell
    /// (with the snapshot passphrase from `import::prepare` — in
    /// memory only, never printed) BEFORE the shape folding. Valid
    /// only with `--content-shape`; the output stays shape only.
    pub decrypt_basic: bool,
    /// `--media-derivatives` (batch 28 M3): pre-warm the WebP
    /// derivative cache. Its own mode; read-only on the store;
    /// requires `--target` (no snapshot flags).
    pub media_derivatives: bool,
    /// `--variants thumb,view` (batch 28): the variants to build;
    /// empty = both. `orig` is refused here (it is built on demand).
    pub variants: Vec<super::img_derive::Variant>,
    /// `--threads N` (batch 28): worker threads, 1..=64.
    pub threads: Option<u32>,
    /// `--apply`: write into the shadow DB (guarded by the
    /// preconditions in `import_apply`).
    pub apply: bool,
    /// `--help`: print usage, exit 0 (no other flag required).
    pub help: bool,
}

/// Store a first-wins-once value; duplicates are a parse error.
fn set_once<T>(slot: &mut Option<T>, flag: &str, value: T) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!("{flag} given twice"));
    }
    *slot = Some(value);
    Ok(())
}

/// Store a valueless flag; repeats are a parse error.
fn set_bool_once(slot: &mut bool, flag: &str) -> Result<(), String> {
    if *slot {
        return Err(format!("{flag} given twice"));
    }
    *slot = true;
    Ok(())
}

/// Validate the `--uin-hash` shape: exactly 12 lowercase hex chars
/// (the same shape `shadow::account::valid_uin_hash` pins).
fn validate_uin_hash(flag: &str, value: &str) -> Result<String, String> {
    if value.len() != 12
        || !value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(format!(
            "{flag} must be 12 lowercase hex chars (sha256-12), got {value:?}"
        ));
    }
    Ok(value.to_string())
}

/// Parse the `--variants` value: a comma list of `thumb` / `view`, no
/// duplicates, no empty items. `orig` is refused: the full-size JXL
/// conversion is built on demand, not pre-warmed.
fn parse_variants(raw: &str) -> Result<Vec<super::img_derive::Variant>, String> {
    use super::img_derive::Variant;
    let mut out: Vec<Variant> = Vec::new();
    for item in raw.split(',') {
        let v = match Variant::parse(item) {
            Some(Variant::Orig) => {
                return Err(
                    "--variants: orig is built on demand, pre-warm covers thumb and view only"
                        .into(),
                )
            }
            Some(v) => v,
            None => {
                return Err(format!(
                    "--variants must be a comma list of thumb,view, got {raw:?}"
                ))
            }
        };
        if out.contains(&v) {
            return Err(format!("--variants lists {} twice", v.name()));
        }
        out.push(v);
    }
    Ok(out)
}

/// Parse the `--cipher-compat` value: only 3 or 4.
fn parse_cipher_compat(value: &str) -> Result<CipherProfile, String> {
    match value {
        "4" => Ok(CipherProfile::Compat4),
        "3" => Ok(CipherProfile::Compat3),
        other => Err(format!("--cipher-compat must be 3 or 4, got {other:?}")),
    }
}

/// Parse the argv of a `zalors import ...` invocation (everything after
/// the `import` word). Pure: never prints, never touches the FS.
///
/// Rules (audit M2-5 + batch 12):
/// - value flags consume one value; missing or `--`-prefixed value is
///   an error;
/// - boolean flags consume nothing;
/// - unknown args are an error (`--from-zalo-pc` gets a rename hint);
/// - duplicates are an error;
/// - `--dry-run` + `--apply` together are an error;
/// - the batch-12 modes are dry-run only: `--inventory`, `--mapping`,
///   `--shadow-copy`, `--delta`, `--out` all conflict with `--apply`;
/// - `--out` needs `--inventory`; `--inventory` excludes the mapping
///   mode; `--delta` needs the mapping mode;
/// - `--help` short-circuits the required flags: usage, exit 0.
pub fn parse(args: &[String]) -> Result<ImportArgs, String> {
    let mut from_snapshot: Option<PathBuf> = None;
    let mut account: Option<String> = None;
    let mut uin_hash: Option<String> = None;
    let mut key_file: Option<PathBuf> = None;
    let mut cipher_compat: Option<CipherProfile> = None;
    let mut out: Option<PathBuf> = None;
    let mut mapping: Option<PathBuf> = None;
    let mut shadow_copy: Option<PathBuf> = None;
    let mut distinct: Vec<import::distinct::DistinctSpec> = Vec::new();
    let mut content_shape: Option<import::distinct::DistinctSpec> = None;
    let mut by: Option<String> = None;
    let (mut dry_run, mut apply, mut help, mut inventory, mut delta) =
        (false, false, false, false, false);
    let (mut all_dbs, mut own_uid_from_settings, mut decrypt_basic) = (false, false, false);
    let (mut i_have_a_backup_plan, mut unmapped_as_raw, mut media_plan) = (false, false, false);
    let (mut local_media_probe, mut local_media_plan) = (false, false);
    let (mut local_media_copy, mut include_video) = (false, false);
    let mut limit: Option<u64> = None;
    let mut media_derivatives = false;
    let mut variants_raw: Option<String> = None;
    let mut threads: Option<u32> = None;
    let mut local_media_root: Option<PathBuf> = None;
    let mut target: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        let value_flag = matches!(
            flag,
            "--from-snapshot"
                | "--account"
                | "--uin-hash"
                | "--key-file"
                | "--cipher-compat"
                | "--out"
                | "--mapping"
                | "--shadow-copy"
                | "--distinct"
                | "--target"
                | "--content-shape"
                | "--by"
                | "--local-media-root"
                | "--limit"
                | "--variants"
                | "--threads"
        );
        if value_flag {
            let value =
                args.get(i + 1).ok_or_else(|| format!("{flag} requires a value"))?;
            if value.starts_with("--") {
                return Err(format!("{flag} requires a value, got {value}"));
            }
            match flag {
                "--from-snapshot" => set_once(&mut from_snapshot, flag, PathBuf::from(value))?,
                "--account" => set_once(&mut account, flag, value.to_string())?,
                "--uin-hash" => set_once(&mut uin_hash, flag, validate_uin_hash(flag, value)?)?,
                "--key-file" => set_once(&mut key_file, flag, PathBuf::from(value))?,
                "--cipher-compat" => {
                    set_once(&mut cipher_compat, flag, parse_cipher_compat(value)?)?
                }
                "--out" => set_once(&mut out, flag, PathBuf::from(value))?,
                "--mapping" => set_once(&mut mapping, flag, PathBuf::from(value))?,
                "--shadow-copy" => set_once(&mut shadow_copy, flag, PathBuf::from(value))?,
                // Batch 16 P1 (2.5): the store the apply writes into —
                // no default, the user passes it.
                "--target" => set_once(&mut target, flag, PathBuf::from(value))?,
                // Batch 27 M2/M3: the Zalo PC local media root — a
                // user setting passed explicitly, never read from the
                // snapshot.
                "--local-media-root" => {
                    set_once(&mut local_media_root, flag, PathBuf::from(value))?
                }
                // Batch 27b: `--limit N` (local-media-copy), N >= 1.
                "--limit" => {
                    let n: u64 = value
                        .parse()
                        .ok()
                        .filter(|n| *n >= 1)
                        .ok_or_else(|| {
                            format!("--limit must be a whole number >= 1, got {value:?}")
                        })?;
                    set_once(&mut limit, flag, n)?
                }
                // Batch 28: the pre-warm's variant list and worker count.
                "--variants" => set_once(&mut variants_raw, flag, value.to_string())?,
                "--threads" => {
                    let n: u32 = value
                        .parse()
                        .ok()
                        .filter(|n| (1..=64).contains(n))
                        .ok_or_else(|| {
                            format!("--threads must be a whole number 1..=64, got {value:?}")
                        })?;
                    set_once(&mut threads, flag, n)?
                }
                // Batch 14 N1: repeatable, max 10 per run. The spec
                // shape (kind, table, column) is validated HERE, pure;
                // existence + the code-column whitelist run against
                // the inventory in `run_distinct`.
                "--distinct" => {
                    distinct.push(import::distinct::parse_spec(value)?);
                    if distinct.len() > import::distinct::MAX_PER_RUN {
                        return Err(format!(
                            "--distinct: at most {} per run (this is the {}th)",
                            import::distinct::MAX_PER_RUN,
                            distinct.len()
                        ));
                    }
                }
                // Batch 23a C1: the content-shape probe's spec parses
                // through the SAME shape rule (with this flag's name
                // in the errors); existence + the --by whitelist run
                // against the inventory in `run_content_shape`.
                "--content-shape" => {
                    set_once(
                        &mut content_shape,
                        flag,
                        import::distinct::parse_spec_for(flag, value)?,
                    )?;
                }
                // …and its required companion: the code column the
                // shapes are grouped by (non-empty; a name that fails
                // the batch-14 whitelist is refused at run time with
                // the rule quoted).
                "--by" => {
                    if value.is_empty() {
                        return Err(String::from("--by requires a non-empty column name"));
                    }
                    set_once(&mut by, flag, value.to_string())?;
                }
                _ => unreachable!("the value_flag match lists every value flag"),
            }
            i += 2;
            continue;
        }
        match flag {
            "--dry-run" => set_bool_once(&mut dry_run, flag)?,
            "--apply" => set_bool_once(&mut apply, flag)?,
            "--help" => set_bool_once(&mut help, flag)?,
            "--inventory" => set_bool_once(&mut inventory, flag)?,
            "--delta" => set_bool_once(&mut delta, flag)?,
            // Batch 15 O2/O4: valueless mode riders.
            "--all-dbs" => set_bool_once(&mut all_dbs, flag)?,
            "--own-uid-from-settings" => set_bool_once(&mut own_uid_from_settings, flag)?,
            // Batch 16 P1/P2: the apply preconditions + the media plan.
            "--i-have-a-backup-plan" => set_bool_once(&mut i_have_a_backup_plan, flag)?,
            "--unmapped-as-raw" => set_bool_once(&mut unmapped_as_raw, flag)?,
            "--media-plan" => set_bool_once(&mut media_plan, flag)?,
            // Batch 24 D3: the content-shape probe's decode rider.
            "--decrypt-basic" => set_bool_once(&mut decrypt_basic, flag)?,
            // Batch 27 M2/M3: the two local-media modes.
            "--local-media-probe" => set_bool_once(&mut local_media_probe, flag)?,
            "--local-media-plan" => set_bool_once(&mut local_media_plan, flag)?,
            // Batch 27b: the copy mode and its video rider.
            "--local-media-copy" => set_bool_once(&mut local_media_copy, flag)?,
            "--include-video" => set_bool_once(&mut include_video, flag)?,
            // Batch 28: the derivative pre-warm.
            "--media-derivatives" => set_bool_once(&mut media_derivatives, flag)?,
            "--from-zalo-pc" => {
                return Err(
                    "unknown flag --from-zalo-pc: renamed to --from-snapshot \
                     (imports read a cold snapshot, never the live tree — KQ4)"
                        .into(),
                );
            }
            other => return Err(format!("unknown argument {other}")),
        }
        i += 1;
    }

    if dry_run && apply {
        return Err("--dry-run and --apply are mutually exclusive".into());
    }
    // Batch 28 M3: --media-derivatives is its own mode — read-only on
    // the store, writes only cache files, so it takes no snapshot
    // flags and no --apply gate.
    let variants: Vec<super::img_derive::Variant> = match &variants_raw {
        None => Vec::new(),
        Some(raw) => parse_variants(raw)?,
    };
    if media_derivatives {
        let conflicting = [
            ("--apply", apply),
            ("--dry-run", dry_run),
            ("--i-have-a-backup-plan", i_have_a_backup_plan),
            ("--inventory", inventory),
            ("--mapping", mapping.is_some()),
            ("--shadow-copy", shadow_copy.is_some()),
            ("--delta", delta),
            ("--media-plan", media_plan),
            ("--distinct", !distinct.is_empty()),
            ("--content-shape", content_shape.is_some()),
            ("--local-media-probe", local_media_probe),
            ("--local-media-plan", local_media_plan),
            ("--local-media-copy", local_media_copy),
            ("--local-media-root", local_media_root.is_some()),
            ("--include-video", include_video),
            ("--out", out.is_some()),
            ("--unmapped-as-raw", unmapped_as_raw),
            ("--all-dbs", all_dbs),
            ("--own-uid-from-settings", own_uid_from_settings),
            ("--from-snapshot", from_snapshot.is_some()),
            ("--account", account.is_some()),
            ("--uin-hash", uin_hash.is_some()),
            ("--key-file", key_file.is_some()),
            ("--cipher-compat", cipher_compat.is_some()),
        ]
        .into_iter()
        .find(|(_, on)| *on);
        if let Some((flag, _)) = conflicting {
            return Err(format!(
                "--media-derivatives cannot be combined with {flag} (one mode per run; it \
                 reads the store read-only and needs only --target)"
            ));
        }
        if target.is_none() && !help {
            return Err(
                "--media-derivatives needs --target <shadow store dir>: there is no default — \
                 the live store is never silently chosen"
                    .into(),
            );
        }
    } else if variants_raw.is_some() || threads.is_some() {
        return Err(
            "--variants/--threads are --media-derivatives flags: add --media-derivatives or \
             drop them"
                .into(),
        );
    }
    // Batch 24 D3: --decrypt-basic rides the --content-shape mode (it
    // is that probe's decode step) — checked before the --apply
    // preconditions so a bare rider never masquerades as one. It
    // inherits the mode's dry-run only rule: --content-shape
    // conflicts with --apply below.
    if decrypt_basic && content_shape.is_none() {
        return Err(
            "--decrypt-basic needs --content-shape: it is the content-shape \
             probe's decode step (the Desktop BasicEncryption unwrap applied \
             to each raw cell before the shape folding)"
                .into(),
        );
    }
    // Batch-12/14 modes stay dry-run only (2.5 wires writes only
    // through its own preconditions): refuse any combination with
    // --apply, naming the flag.
    if apply {
        let conflicting = [
            ("--inventory", inventory),
            ("--delta", delta),
            ("--out", out.is_some()),
            ("--shadow-copy", shadow_copy.is_some()),
            ("--distinct", !distinct.is_empty()),
            ("--media-plan", media_plan),
            ("--content-shape", content_shape.is_some()),
            ("--local-media-probe", local_media_probe),
            ("--local-media-plan", local_media_plan),
        ]
        .into_iter()
        .find(|(_, on)| *on);
        if let Some((flag, _)) = conflicting {
            return Err(format!(
                "{flag} is dry-run only and conflicts with --apply \
                 (2.5 has its own preconditions — docs/import-mapping.md)"
            ));
        }
    }
    // Batch 16 P1 (2.5 precondition 1): the three explicit apply-only
    // flags REQUIRE --apply, and --apply requires them + --mapping.
    if apply {
        if !i_have_a_backup_plan {
            return Err(
                "--apply needs --i-have-a-backup-plan: the apply writes into the \
                 shadow store — confirm you have a way to restore it (the run \
                 also makes its own verified backup first)".into(),
            );
        }
        if target.is_none() {
            return Err(
                "--apply needs --target <shadow store dir>: there is no default — \
                 the live store is never silently chosen".into(),
            );
        }
        if mapping.is_none() && !local_media_copy {
            return Err(
                "--apply needs --mapping <file>: the built-in skeleton maps nothing".into(),
            );
        }
    }
    for (on, flag) in [
        // Batch 27 M3: --target also rides --local-media-plan (a
        // read-only mode), so the apply-mode refusal is conditional.
        (
            target.is_some() && !local_media_plan && !local_media_copy && !media_derivatives,
            "--target",
        ),
        (i_have_a_backup_plan, "--i-have-a-backup-plan"),
        (unmapped_as_raw, "--unmapped-as-raw"),
    ] {
        if on && !apply {
            if flag == "--target" {
                return Err(
                    "--target is an --apply/--local-media-plan/--local-media-copy-mode flag: \
                     add --apply (and its other preconditions), --local-media-plan or \
                     --local-media-copy, or drop it"
                        .into(),
                );
            }
            return Err(format!(
                "{flag} is an --apply-mode flag: add --apply (and its other \
                 preconditions) or drop it"
            ));
        }
    }
    if out.is_some() && !inventory && content_shape.is_none() && !local_media_probe {
        return Err(
            "--out needs --inventory, --content-shape or --local-media-probe (it is the report \
             file of one of them)"
                .into(),
        );
    }
    if inventory && (mapping.is_some() || shadow_copy.is_some() || delta || media_plan) {
        return Err(
            "--inventory cannot be combined with --mapping/--shadow-copy/--delta/--media-plan \
             (one mode per run)"
                .into(),
        );
    }
    // Batch 14 N1: --distinct is its own mode too.
    if !distinct.is_empty()
        && (inventory || mapping.is_some() || shadow_copy.is_some() || delta || media_plan)
    {
        return Err(
            "--distinct cannot be combined with --inventory/--mapping/--shadow-copy/--delta/--media-plan \
             (one mode per run)"
                .into(),
        );
    }
    // Batch 23a C1: --content-shape is its own mode, and --by rides
    // only with it.
    if content_shape.is_some()
        && (inventory
            || mapping.is_some()
            || shadow_copy.is_some()
            || delta
            || media_plan
            || !distinct.is_empty())
    {
        return Err(
            "--content-shape cannot be combined with \
             --inventory/--mapping/--shadow-copy/--delta/--distinct/--media-plan \
             (one mode per run)"
                .into(),
        );
    }
    // Batch 16 P2: --media-plan is its own dry-run mode.
    if media_plan && (mapping.is_some() || shadow_copy.is_some() || delta) {
        return Err(
            "--media-plan cannot be combined with --mapping/--shadow-copy/--delta \
             (it needs no mapping — it discovers the media tables itself)"
                .into(),
        );
    }
    // Batch 27 M2/M3: the two local-media modes are their own dry-run
    // modes — mutually exclusive with every other mode and each other.
    if (local_media_probe || local_media_plan)
        && (inventory
            || mapping.is_some()
            || shadow_copy.is_some()
            || delta
            || media_plan
            || !distinct.is_empty()
            || content_shape.is_some())
    {
        return Err(
            "--local-media-probe/--local-media-plan cannot be combined with \
             --inventory/--mapping/--shadow-copy/--delta/--distinct/--content-shape/--media-plan \
             (one mode per run)"
                .into(),
        );
    }
    if local_media_probe && local_media_plan {
        return Err(
            "--local-media-probe and --local-media-plan are mutually exclusive \
             (one mode per run)"
                .into(),
        );
    }
    // Batch 27b: --local-media-copy is its own mode too (dry run
    // without --apply, the guarded copy with it).
    if local_media_copy {
        let conflicting = [
            ("--inventory", inventory),
            ("--mapping", mapping.is_some()),
            ("--shadow-copy", shadow_copy.is_some()),
            ("--delta", delta),
            ("--media-plan", media_plan),
            ("--distinct", !distinct.is_empty()),
            ("--content-shape", content_shape.is_some()),
            ("--local-media-probe", local_media_probe),
            ("--local-media-plan", local_media_plan),
            ("--out", out.is_some()),
            ("--unmapped-as-raw", unmapped_as_raw),
        ]
        .into_iter()
        .find(|(_, on)| *on);
        if let Some((flag, _)) = conflicting {
            return Err(format!(
                "--local-media-copy cannot be combined with {flag} (one mode per run)"
            ));
        }
        if local_media_root.is_none() {
            return Err(
                "--local-media-copy needs --local-media-root <dir>: the Zalo PC local media \
                 root (a user setting)"
                    .into(),
            );
        }
        if target.is_none() {
            return Err(
                "--local-media-copy needs --target <shadow store dir>: there is no default — \
                 the live store is never silently chosen"
                    .into(),
            );
        }
    }
    if include_video && !local_media_copy {
        return Err(
            "--include-video/--limit are --local-media-copy flags: add --local-media-copy or \
             drop them"
                .into(),
        );
    }
    if limit.is_some() && !local_media_copy && !media_derivatives {
        return Err(
            "--include-video/--limit are --local-media-copy flags: add --local-media-copy or \
             drop them (--limit also rides --media-derivatives)"
                .into(),
        );
    }
    // Both modes need the root (a user setting, never a snapshot
    // value); the root without either mode is an error too.
    if (local_media_probe || local_media_plan) && local_media_root.is_none() {
        return Err(
            "--local-media-probe/--local-media-plan need --local-media-root <dir>: the Zalo PC \
             local media root (a user setting — the dir whose `media` child holds the \
             per-uid ZaloDownloads trees)"
                .into(),
        );
    }
    if local_media_root.is_some() && !local_media_probe && !local_media_plan && !local_media_copy
    {
        return Err(
            "--local-media-root needs --local-media-probe, --local-media-plan or \
             --local-media-copy (it is the local-media modes' root argument)"
                .into(),
        );
    }
    // M3 needs the store. (A `--local-media-probe --target …` misuse
    // is caught by the generic --target rule above, which names both
    // modes that may carry the flag.)
    if local_media_plan && target.is_none() {
        return Err(
            "--local-media-plan needs --target <shadow store dir>: the plan classifies the \
             store's import-sourced attachments (read-only — the app may keep running)"
                .into(),
        );
    }
    // Batch 15 O2 / batch 23a C1: --all-dbs rides the --distinct mode
    // and the --content-shape mode, and only a message kind has more
    // than one DB to aggregate.
    if all_dbs && distinct.is_empty() && content_shape.is_none() {
        return Err(
            "--all-dbs needs --distinct or --content-shape \
             (it aggregates every DB of the requested message kind)"
                .into(),
        );
    }
    if all_dbs {
        if let Some(bad) = distinct
            .iter()
            .find(|s| s.kind == super::import_map::MapDb::Index)
        {
            return Err(format!(
                "--all-dbs with {}: the snapshot has exactly ONE index DB — drop --all-dbs",
                import::distinct::spec_str(bad)
            ));
        }
        if let Some(bad) = content_shape
            .iter()
            .find(|s| s.kind == super::import_map::MapDb::Index)
        {
            return Err(format!(
                "--all-dbs with {}: the snapshot has exactly ONE index DB — drop --all-dbs",
                import::distinct::spec_str(bad)
            ));
        }
    }
    // Batch 23a C1: --content-shape and --by are a pair — one without
    // the other is a parse error naming both.
    if content_shape.is_some() && by.is_none() {
        return Err(
            "--content-shape needs --by <code column>: it names the whitelisted \
             code column the content shapes are grouped by"
                .into(),
        );
    }
    if by.is_some() && content_shape.is_none() {
        return Err(
            "--by needs --content-shape: it is the grouping column of the \
             content-shape probe"
                .into(),
        );
    }
    // Batch 15 O4 + batch 16: --own-uid-from-settings rides the
    // mapping mode AND the apply step (the batch-15 rule applies
    // there too — the brief's P1 item 5).
    if own_uid_from_settings
        && mapping.is_none()
        && shadow_copy.is_none()
        && !apply
    {
        return Err(
            "--own-uid-from-settings needs the mapping mode or --apply: add --mapping <file> \
             (it seeds the import extraction's self-sent sender)"
                .into(),
        );
    }
    if delta && mapping.is_none() && shadow_copy.is_none() {
        return Err(
            "--delta needs the mapping mode: add --mapping <file> and/or \
             --shadow-copy <dir>"
                .into(),
        );
    }
    if help {
        return Ok(ImportArgs {
            from_snapshot: PathBuf::new(),
            account: String::new(),
            uin_hash: String::new(),
            key_file: None,
            cipher_compat: None,
            inventory,
            out,
            mapping,
            shadow_copy,
            delta,
            distinct,
            all_dbs,
            own_uid_from_settings,
            target,
            i_have_a_backup_plan,
            unmapped_as_raw,
            media_plan,
            local_media_probe,
            local_media_plan,
            local_media_root,
            local_media_copy,
            include_video,
            limit,
            content_shape,
            by,
            decrypt_basic,
            media_derivatives,
            variants,
            threads,
            apply: false,
            help: true,
        });
    }
    // --media-derivatives needs no snapshot (it never reads one).
    let snapshot_flags_optional = media_derivatives;
    Ok(ImportArgs {
        from_snapshot: match from_snapshot {
            Some(p) => p,
            None if snapshot_flags_optional => PathBuf::new(),
            None => return Err("missing required --from-snapshot <dir>".into()),
        },
        account: match account {
            Some(v) => v,
            None if snapshot_flags_optional => String::new(),
            None => return Err("missing required --account <id>".into()),
        },
        uin_hash: match uin_hash {
            Some(v) => v,
            None if snapshot_flags_optional => String::new(),
            None => return Err("missing required --uin-hash <sha256-12>".into()),
        },
        key_file,
        cipher_compat,
        inventory,
        out,
        mapping,
        shadow_copy,
        delta,
        distinct,
        all_dbs,
        own_uid_from_settings,
        target,
        i_have_a_backup_plan,
        unmapped_as_raw,
        media_plan,
        local_media_probe,
        local_media_plan,
        local_media_root,
        local_media_copy,
        include_video,
        limit,
        content_shape,
        by,
        decrypt_basic,
        media_derivatives,
        variants,
        threads,
        apply,
        help: false,
    })
}

/// CLI entrypoint (the bin dispatches `zalors import …` here BEFORE
/// starting Tauri, audit M2-5). Returns the process exit code:
/// 0 usage/success · 1 runtime failure · 2 parse error.
pub fn main(args: &[String]) -> i32 {
    match parse(args) {
        Ok(a) if a.help => {
            println!("{USAGE}");
            0
        }
        // Batch 16 P1 (2.5): the guarded write step. It must dispatch
        // BEFORE the mapping mode — an apply carries --mapping too.
        // The process probe is wired HERE (the real tasklist); the
        // preconditions themselves are unit-tested with an injected
        // probe. Batch 16 fix F3: the apply streams every line through
        // a println sink as it is produced — the backup path and the
        // progress lines stay visible even when a later step fails
        // (errors still exit 1).
        // Batch 27b: the local-media COPY mode (dry run or guarded
        // apply) — it carries --apply but NOT --mapping, so it must
        // dispatch before the mapping apply below.
        // Batch 28 M3: the derivative pre-warm (read-only store, cache
        // writes only) — it needs no snapshot, no apply gate.
        Ok(a) if a.media_derivatives => {
            let mut out = |line: &str| println!("{line}");
            match super::derive_cli::run_wired(&a, &mut out) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("import failed: {e}");
                    1
                }
            }
        }
        Ok(a) if a.local_media_copy => {
            let mut out = |line: &str| println!("{line}");
            match import::run_local_media_copy(
                &a,
                &mut out,
                || super::import_apply::zalors_running_besides(std::process::id()),
            ) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("import failed: {e}");
                    1
                }
            }
        }
        Ok(a) if a.apply => {
            let mut out = |line: &str| println!("{line}");
            match super::import_apply::run_apply(
                &a,
                &mut out,
                || super::import_apply::zalors_running_besides(std::process::id()),
            ) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("import failed: {e}");
                    1
                }
            }
        }
        // Batch 12 L1: the schema inventory mode.
        Ok(a) if a.inventory => match import::run_inventory(&a) {
            Ok(lines) => {
                for line in &lines {
                    println!("{line}");
                }
                0
            }
            Err(e) => {
                eprintln!("import failed: {e}");
                1
            }
        },
        // Batch 12 L2/L4: the mapping dry-run mode.
        Ok(a) if a.mapping.is_some() || a.shadow_copy.is_some() => {
            match import::run_mapping_dry(&a) {
                Ok(lines) => {
                    for line in &lines {
                        println!("{line}");
                    }
                    0
                }
                Err(e) => {
                    eprintln!("import failed: {e}");
                    1
                }
            }
        }
        // Batch 14 N1: the whitelisted distinct-values mode.
        Ok(a) if !a.distinct.is_empty() => match import::run_distinct(&a) {
            Ok(lines) => {
                for line in &lines {
                    println!("{line}");
                }
                0
            }
            Err(e) => {
                eprintln!("import failed: {e}");
                1
            }
        },
        // Batch 23a C1: the content-shape probe mode (parse guarantees
        // --by is present with it).
        Ok(a) if a.content_shape.is_some() => match import::run_content_shape(&a) {
            Ok(lines) => {
                for line in &lines {
                    println!("{line}");
                }
                0
            }
            Err(e) => {
                eprintln!("import failed: {e}");
                1
            }
        },
        // Batch 16 P2 (2.6): the media hardlink PREP dry run.
        Ok(a) if a.media_plan => match import::run_media_plan(&a) {
            Ok(lines) => {
                for line in &lines {
                    println!("{line}");
                }
                0
            }
            Err(e) => {
                eprintln!("import failed: {e}");
                1
            }
        },
        // Batch 27 M2: the local-media read-only census.
        Ok(a) if a.local_media_probe => match import::run_local_media_probe(&a) {
            Ok(lines) => {
                for line in &lines {
                    println!("{line}");
                }
                0
            }
            Err(e) => {
                eprintln!("import failed: {e}");
                1
            }
        },
        // Batch 27 M3: the local-media DRY-RUN copy planner (no
        // writes of any kind).
        Ok(a) if a.local_media_plan => match import::run_local_media_plan(&a) {
            Ok(lines) => {
                for line in &lines {
                    println!("{line}");
                }
                0
            }
            Err(e) => {
                eprintln!("import failed: {e}");
                1
            }
        },
        Ok(a) => match import::run(&a) {
            Ok(summary) => {
                // F4: counts, profile name, key sha12 — nothing else.
                println!("{}", summary.line());
                0
            }
            Err(e) => {
                eprintln!("import failed: {e}");
                1
            }
        },
        Err(e) => {
            eprintln!("import: {e}\n{USAGE}");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shadow::import_map;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_full_dry_run_invocation() {
        let a = parse(&args(&[
            "--from-snapshot",
            r"D:\snap",
            "--account",
            "default",
            "--uin-hash",
            "dca62c394a68",
            "--key-file",
            r"D:\k.bin",
            "--cipher-compat",
            "4",
            "--dry-run",
        ]))
        .unwrap();
        assert_eq!(a.from_snapshot, PathBuf::from(r"D:\snap"));
        assert_eq!(a.account, "default");
        assert_eq!(a.uin_hash, "dca62c394a68");
        assert_eq!(a.key_file, Some(PathBuf::from(r"D:\k.bin")));
        assert_eq!(a.cipher_compat, Some(CipherProfile::Compat4));
        assert!(!a.apply);
        assert!(!a.help);
    }

    #[test]
    fn parse_the_old_bug_apply_key_file_keeps_the_value() {
        // M2-5: the old parser advanced i += 2 even for valueless
        // flags, so `--apply --key-file X` silently LOST --key-file.
        // The invocation now carries --apply's full precondition set
        // (the parse-level enforcement of precondition 1).
        let a = parse(&args(&[
            "--from-snapshot",
            r"D:\snap",
            "--account",
            "default",
            "--uin-hash",
            "dca62c394a68",
            "--apply",
            "--i-have-a-backup-plan",
            "--target",
            r"D:\shadow",
            "--mapping",
            "m.json",
            "--key-file",
            "k.bin",
        ]))
        .unwrap();
        assert!(a.apply);
        assert!(a.i_have_a_backup_plan);
        assert_eq!(a.target, Some(PathBuf::from(r"D:\shadow")));
        assert_eq!(a.key_file, Some(PathBuf::from("k.bin")));
        // The escape hatch rides along.
        let a2 = parse(&args(&[
            "--from-snapshot",
            r"D:\snap",
            "--account",
            "default",
            "--uin-hash",
            "dca62c394a68",
            "--apply",
            "--i-have-a-backup-plan",
            "--target",
            r"D:\shadow",
            "--mapping",
            "m.json",
            "--unmapped-as-raw",
            "--key-file",
            "k.bin",
        ]))
        .unwrap();
        assert!(a2.unmapped_as_raw);
    }

    // --- batch 16 P1: --apply preconditions (parse level) ---------------

    #[test]
    fn parse_apply_names_every_missing_precondition_flag() {
        // A consistent base, minus one flag at a time.
        let base = |skip: &str| {
            let mut v: Vec<String> = args(&[
                "--from-snapshot",
                "s",
                "--account",
                "default",
                "--uin-hash",
                "dca62c394a68",
                "--apply",
                "--i-have-a-backup-plan",
                "--target",
                r"D:\shadow",
                "--mapping",
                "m.json",
            ]);
            v.retain(|a| a != skip && {
                // drop the value of the skipped value-flag too
                !(skip == "--target" && a == r"D:\shadow")
                    && !(skip == "--mapping" && a == "m.json")
            });
            v
        };
        for (skip, needle) in [
            ("--i-have-a-backup-plan", "--apply needs --i-have-a-backup-plan"),
            ("--target", "--apply needs --target <shadow store dir>"),
            ("--mapping", "--apply needs --mapping <file>"),
        ] {
            let e = parse(&base(skip)).unwrap_err();
            assert!(e.contains(needle), "{skip} -> {e}");
        }
    }

    #[test]
    fn parse_apply_mode_flags_require_apply() {
        // Each apply-mode flag outside --apply names itself. Batch 27
        // M3: --target also rides --local-media-plan, so its refusal
        // names BOTH modes; the two pure apply flags keep theirs.
        let e = parse(&with_base(&["--target", r"D:\shadow"])).unwrap_err();
        assert!(
            e.contains("--target is an --apply/--local-media-plan/--local-media-copy-mode flag"),
            "{e}"
        );
        for flag in ["--i-have-a-backup-plan", "--unmapped-as-raw"] {
            let e = parse(&with_base(&[flag])).unwrap_err();
            assert!(
                e.contains(&format!("{flag} is an --apply-mode flag")),
                "{flag} -> {e}"
            );
        }
        // Duplicates are still errors inside the mode.
        let e = parse(&args(&[
            "--apply",
            "--i-have-a-backup-plan",
            "--target",
            r"D:\s",
            "--mapping",
            "m.json",
            "--target",
            r"D:\s2",
        ]))
        .unwrap_err();
        assert!(e.contains("--target given twice"), "{e}");
        let e = parse(&args(&[
            "--apply",
            "--i-have-a-backup-plan",
            "--target",
            r"D:\s",
            "--mapping",
            "m.json",
            "--i-have-a-backup-plan",
        ]))
        .unwrap_err();
        assert!(e.contains("--i-have-a-backup-plan given twice"), "{e}");
    }

    // --- batch 27b M1: --local-media-copy (parse) ---------------------------

    #[test]
    fn parse_local_media_copy_rules() {
        // A dry run needs only the root and the store (no --mapping).
        let a = parse(&with_base(&[
            "--local-media-copy",
            "--local-media-root",
            r"D:\Zalo Data",
            "--target",
            r"D:\shadow",
        ]))
        .unwrap();
        assert!(a.local_media_copy && !a.apply && !a.include_video);
        assert_eq!(a.limit, None);
        // The riders.
        let a = parse(&with_base(&[
            "--local-media-copy",
            "--local-media-root",
            r"D:\Zalo Data",
            "--target",
            r"D:\shadow",
            "--include-video",
            "--limit",
            "25",
        ]))
        .unwrap();
        assert!(a.include_video);
        assert_eq!(a.limit, Some(25));
        // The guarded apply needs --i-have-a-backup-plan but NOT --mapping.
        let a = parse(&with_base(&[
            "--local-media-copy",
            "--local-media-root",
            r"D:\Zalo Data",
            "--target",
            r"D:\shadow",
            "--apply",
            "--i-have-a-backup-plan",
        ]))
        .unwrap();
        assert!(a.apply && a.local_media_copy && a.i_have_a_backup_plan);
        assert!(a.mapping.is_none());

        let base = ["--local-media-copy", "--local-media-root", r"D:\Z", "--target", r"D:\s"];
        for (extra, needle) in [
            (vec!["--apply"], "--apply needs --i-have-a-backup-plan"),
            (
                vec!["--i-have-a-backup-plan"],
                "--i-have-a-backup-plan is an --apply-mode flag",
            ),
            (vec!["--limit", "0"], "--limit must be a whole number >= 1"),
            (vec!["--limit", "x"], "--limit must be a whole number >= 1"),
            (vec!["--limit", "5", "--limit", "6"], "--limit given twice"),
            (vec!["--include-video", "--include-video"], "--include-video given twice"),
            (vec!["--inventory"], "--local-media-copy cannot be combined with --inventory"),
            (
                vec!["--mapping", "m.json"],
                "--local-media-copy cannot be combined with --mapping",
            ),
            (
                vec!["--local-media-plan"],
                "--local-media-copy cannot be combined with --local-media-plan",
            ),
            (
                vec!["--local-media-probe"],
                "--local-media-copy cannot be combined with --local-media-probe",
            ),
            (vec!["--out", "x"], "--out needs --inventory"),
        ] {
            let mut v: Vec<&str> = base.to_vec();
            v.extend(extra.iter().copied());
            let e = parse(&with_base(&v)).unwrap_err();
            assert!(e.contains(needle), "{v:?} -> {e}");
        }
        // Missing root / store name themselves.
        let e = parse(&with_base(&["--local-media-copy", "--target", r"D:\s"])).unwrap_err();
        assert!(e.contains("--local-media-copy needs --local-media-root"), "{e}");
        let e = parse(&with_base(&["--local-media-copy", "--local-media-root", r"D:\Z"]))
            .unwrap_err();
        assert!(e.contains("--local-media-copy needs --target"), "{e}");
        // The riders need the mode.
        for flags in [vec!["--include-video"], vec!["--limit", "3"]] {
            let e = parse(&with_base(&flags)).unwrap_err();
            assert!(e.contains("are --local-media-copy flags"), "{flags:?} -> {e}");
        }
        // The apply of the mapping mode still needs its --mapping.
        let e = parse(&with_base(&[
            "--apply",
            "--i-have-a-backup-plan",
            "--target",
            r"D:\s",
        ]))
        .unwrap_err();
        assert!(e.contains("--apply needs --mapping"), "{e}");
    }

    // --- batch 27 M2/M3: --local-media-probe / --local-media-plan (parse) ---

    #[test]
    fn parse_local_media_modes_rules() {
        // The probe needs only the root; the plan needs the root AND
        // the store.
        let a = parse(&with_base(&[
            "--local-media-probe",
            "--local-media-root",
            r"D:\Zalo Data",
        ]))
        .unwrap();
        assert!(a.local_media_probe && !a.local_media_plan);
        assert_eq!(a.local_media_root, Some(PathBuf::from(r"D:\Zalo Data")));
        assert!(!a.apply);
        let a = parse(&with_base(&[
            "--local-media-plan",
            "--local-media-root",
            r"D:\Zalo Data",
            "--target",
            r"D:\shadow",
        ]))
        .unwrap();
        assert!(a.local_media_plan && !a.local_media_probe);
        assert_eq!(a.target, Some(PathBuf::from(r"D:\shadow")));
        // --out rides the probe (the report file) and refuses to
        // overwrite at run time.
        let a = parse(&with_base(&[
            "--local-media-probe",
            "--local-media-root",
            r"D:\Zalo Data",
            "--out",
            "report.txt",
        ]))
        .unwrap();
        assert_eq!(a.out, Some(PathBuf::from("report.txt")));

        // Every missing / misused flag names itself.
        for (flags, needle) in [
            (
                vec!["--local-media-probe"],
                "need --local-media-root",
            ),
            (
                vec!["--local-media-plan", "--target", r"D:\s"],
                "need --local-media-root",
            ),
            (
                vec!["--local-media-plan", "--local-media-root", r"D:\Z"],
                "--local-media-plan needs --target",
            ),
            (
                vec!["--local-media-root", r"D:\Z"],
                "--local-media-root needs --local-media-probe, --local-media-plan or",
            ),
            (
                vec!["--local-media-probe", "--local-media-plan"],
                "mutually exclusive",
            ),
            (
                vec!["--local-media-probe", "--local-media-root", r"D:\Z", "--target", r"D:\s"],
                "--target is an --apply/--local-media-plan/--local-media-copy-mode flag",
            ),
            (
                vec!["--local-media-plan", "--local-media-root", r"D:\Z", "--out", "x"],
                "--out needs --inventory, --content-shape or --local-media-probe",
            ),
            // One mode per run: each existing mode conflicts.
            (
                vec!["--local-media-probe", "--local-media-root", r"D:\Z", "--inventory"],
                "--local-media-probe/--local-media-plan cannot be combined",
            ),
            (
                vec!["--local-media-plan", "--local-media-root", r"D:\Z", "--target", r"D:\s",
                     "--mapping", "m.json"],
                "--local-media-probe/--local-media-plan cannot be combined",
            ),
            (
                vec!["--local-media-probe", "--local-media-root", r"D:\Z",
                     "--distinct", "one2one:message.msgType"],
                "--local-media-probe/--local-media-plan cannot be combined",
            ),
            (
                vec!["--local-media-probe", "--local-media-root", r"D:\Z",
                     "--content-shape", "one2one:message.message", "--by", "msgType"],
                "--local-media-probe/--local-media-plan cannot be combined",
            ),
            (
                vec!["--local-media-probe", "--local-media-root", r"D:\Z", "--media-plan"],
                "--local-media-probe/--local-media-plan cannot be combined",
            ),
            // Dry-run only: --apply conflicts, naming the flag.
            (
                vec!["--apply", "--i-have-a-backup-plan", "--target", r"D:\s",
                     "--mapping", "m.json", "--local-media-probe",
                     "--local-media-root", r"D:\Z"],
                "--local-media-probe is dry-run only and conflicts with --apply",
            ),
            (
                vec!["--apply", "--i-have-a-backup-plan", "--target", r"D:\s",
                     "--mapping", "m.json", "--local-media-plan",
                     "--local-media-root", r"D:\Z"],
                "--local-media-plan is dry-run only and conflicts with --apply",
            ),
            // Duplicates.
            (
                vec!["--local-media-probe", "--local-media-probe"],
                "--local-media-probe given twice",
            ),
            (
                vec!["--local-media-probe", "--local-media-root", "a",
                     "--local-media-root", "b"],
                "--local-media-root given twice",
            ),
        ] {
            let e = parse(&with_base(&flags)).unwrap_err();
            assert!(e.contains(needle), "{:?} -> {e}", flags);
        }
        // A CONSISTENT invocation yields to help; a conflicting pair
        // beats it (the batch-6 convention).
        let a = parse(&args(&["--help", "--local-media-probe", "--local-media-root", "r"]))
            .unwrap();
        assert!(a.help);
    }

    // --- batch 16 P2: --media-plan (parse level) ------------------------

    #[test]
    fn parse_media_plan_mode_rules() {
        // Alone it parses; every other mode conflicts with it.
        let a = parse(&with_base(&["--media-plan"])).unwrap();
        assert!(a.media_plan);
        assert!(!a.apply);
        for (flags, needle) in [
            (
                vec!["--apply", "--i-have-a-backup-plan", "--target", r"D:\s",
                     "--mapping", "m.json", "--media-plan"],
                "--media-plan is dry-run only and conflicts with --apply",
            ),
            (
                vec!["--inventory", "--media-plan"],
                "--inventory cannot be combined",
            ),
            (
                vec!["--mapping", "m.json", "--media-plan"],
                "--media-plan cannot be combined",
            ),
            (
                vec!["--shadow-copy", r"D:\s", "--media-plan"],
                "--media-plan cannot be combined",
            ),
            (
                vec!["--delta", "--mapping", "m.json", "--media-plan"],
                "--media-plan cannot be combined",
            ),
            (
                vec!["--distinct", "one2one:message.msgType", "--media-plan"],
                "--distinct cannot be combined",
            ),
            (
                vec!["--media-plan", "--media-plan"],
                "--media-plan given twice",
            ),
        ] {
            let e = parse(&with_base(&flags)).unwrap_err();
            assert!(e.contains(needle), "{:?} -> {e}", flags);
        }
        // A CONSISTENT invocation yields to help; a conflicting pair
        // beats it (the batch-6 convention).
        let a = parse(&args(&["--help", "--media-plan"])).unwrap();
        assert!(a.help);
    }

    #[test]
    fn parse_own_uid_from_settings_now_rides_apply_too() {
        // The batch-15 rule applies to the apply step as well (P1
        // item 5): the flag is valid with --apply, still refused
        // outside both modes.
        let e = parse(&with_base(&["--own-uid-from-settings"])).unwrap_err();
        assert!(e.contains("needs the mapping mode or --apply"), "{e}");
        let a = parse(&args(&[
            "--from-snapshot",
            "s",
            "--account",
            "default",
            "--uin-hash",
            "dca62c394a68",
            "--apply",
            "--i-have-a-backup-plan",
            "--target",
            r"D:\shadow",
            "--mapping",
            "m.json",
            "--own-uid-from-settings",
        ]))
        .unwrap();
        assert!(a.own_uid_from_settings && a.apply);
    }

    #[test]
    fn parse_defaults_to_dry_run() {
        let a = parse(&args(&[
            "--from-snapshot",
            "s",
            "--account",
            "default",
            "--uin-hash",
            "dca62c394a68",
        ]))
        .unwrap();
        assert!(!a.apply, "no --dry-run/--apply means dry-run");
    }

    #[test]
    fn parse_value_flag_at_end_is_an_error() {
        let e = parse(&args(&["--from-snapshot"])).unwrap_err();
        assert!(e.contains("--from-snapshot requires a value"), "{e}");
    }

    #[test]
    fn parse_flag_like_value_is_an_error() {
        let e = parse(&args(&["--from-snapshot", "--account"])).unwrap_err();
        assert!(e.contains("--from-snapshot requires a value"), "{e}");
        let e = parse(&args(&["--account", "--apply"])).unwrap_err();
        assert!(e.contains("--account requires a value"), "{e}");
    }

    /// A valid base invocation to hang extra flags off.
    fn with_base(extra: &[&str]) -> Vec<String> {
        let mut v = args(&[
            "--from-snapshot",
            "s",
            "--account",
            "default",
            "--uin-hash",
            "dca62c394a68",
        ]);
        v.extend(extra.iter().map(|s| s.to_string()));
        v
    }

    #[test]
    fn parse_single_dash_value_is_accepted() {
        // Only a `--` prefix counts as a missing value; a lone `-weird`
        // path is a value like any other.
        let a = parse(&args(&[
            "--from-snapshot",
            "-weird-dir",
            "--account",
            "default",
            "--uin-hash",
            "dca62c394a68",
        ]))
        .unwrap();
        assert_eq!(a.from_snapshot, PathBuf::from("-weird-dir"));
    }

    #[test]
    fn parse_unknown_argument() {
        let e = parse(&args(&["--bogus"])).unwrap_err();
        assert!(e.contains("unknown argument --bogus"), "{e}");
    }

    #[test]
    fn parse_old_flag_name_reports_the_rename() {
        let e = parse(&args(&["--from-zalo-pc", r"D:\x"])).unwrap_err();
        assert!(e.contains("renamed to --from-snapshot"), "{e}");
    }

    #[test]
    fn parse_duplicate_value_flag() {
        let e = parse(&args(&["--account", "a", "--account", "b"])).unwrap_err();
        assert!(e.contains("--account given twice"), "{e}");
    }

    #[test]
    fn parse_duplicate_boolean_flag() {
        let e = parse(&args(&["--dry-run", "--dry-run"])).unwrap_err();
        assert!(e.contains("--dry-run given twice"), "{e}");
        let e = parse(&args(&["--help", "--help"])).unwrap_err();
        assert!(e.contains("--help given twice"), "{e}");
    }

    #[test]
    fn parse_dry_run_and_apply_conflict_in_both_orders() {
        for order in [&["--dry-run", "--apply"] as &[&str], &["--apply", "--dry-run"]] {
            let e = parse(&args(order)).unwrap_err();
            assert!(e.contains("mutually exclusive"), "{e}");
        }
    }

    #[test]
    fn parse_help_flag_short_circuits() {
        let a = parse(&args(&["--help"])).unwrap();
        assert!(a.help);
    }

    #[test]
    fn parse_help_alongside_valid_flags() {
        let a = parse(&args(&["--help", "--account", "default"])).unwrap();
        assert!(a.help);
    }

    #[test]
    fn parse_uin_hash_rejects_bad_shapes() {
        // The codebase shape (account::valid_uin_hash): exactly 12
        // LOWERCASE hex chars.
        for bad in [
            "dca62c394a6",     // 11 chars
            "dca62c394a68d",   // 13 chars
            "dca62c394a6z",     // not hex
            "DCA62C394A68",     // uppercase
            "",
        ] {
            let e = parse(&args(&["--uin-hash", bad])).unwrap_err();
            assert!(e.contains("12 lowercase hex"), "{bad} -> {e}");
        }
    }

    #[test]
    fn parse_cipher_compat_accepts_only_3_or_4() {
        assert_eq!(
            parse(&with_base(&["--cipher-compat", "3"])).unwrap().cipher_compat,
            Some(CipherProfile::Compat3)
        );
        assert_eq!(
            parse(&with_base(&["--cipher-compat", "4"])).unwrap().cipher_compat,
            Some(CipherProfile::Compat4)
        );
        for bad in ["5", "four", ""] {
            let e = parse(&with_base(&["--cipher-compat", bad])).unwrap_err();
            assert!(e.contains("must be 3 or 4"), "{bad} -> {e}");
        }
        assert!(parse(&args(&["--cipher-compat"])).is_err(), "still needs a value");
    }

    #[test]
    fn parse_missing_required_flags_are_named() {
        let e = parse(&args(&[])).unwrap_err();
        assert!(e.contains("missing required --from-snapshot"), "{e}");
        let e = parse(&args(&["--from-snapshot", "s"])).unwrap_err();
        assert!(e.contains("missing required --account"), "{e}");
        let e = parse(&args(&["--from-snapshot", "s", "--account", "default"])).unwrap_err();
        assert!(e.contains("missing required --uin-hash"), "{e}");
    }

    #[test]
    fn parse_key_file_is_optional() {
        let a = parse(&args(&[
            "--from-snapshot",
            "s",
            "--account",
            "default",
            "--uin-hash",
            "dca62c394a68",
        ]))
        .unwrap();
        assert_eq!(a.key_file, None);
        assert!(parse(&args(&["--key-file"])).is_err(), "still needs a value");
    }

    // --- batch 12: --inventory / --out / --mapping / --shadow-copy / --delta

    #[test]
    fn parse_new_value_flags_consume_exactly_one_value() {
        let a = parse(&args(&[
            "--from-snapshot",
            "s",
            "--account",
            "default",
            "--uin-hash",
            "dca62c394a68",
            "--mapping",
            "m.json",
            "--shadow-copy",
            r"D:\shadow",
            "--delta",
        ]))
        .unwrap();
        assert_eq!(a.mapping, Some(PathBuf::from("m.json")));
        assert_eq!(a.shadow_copy, Some(PathBuf::from(r"D:\shadow")));
        assert!(a.delta);
        assert!(!a.inventory);
        // Missing value / ---prefixed value are errors, per flag.
        for flag in ["--mapping", "--shadow-copy", "--out"] {
            let e = parse(&args(&[flag])).unwrap_err();
            assert!(e.contains(&format!("{flag} requires a value")), "{e}");
            let e = parse(&args(&[flag, "--apply"])).unwrap_err();
            assert!(e.contains(&format!("{flag} requires a value")), "{e}");
        }
    }

    #[test]
    fn parse_new_flags_default_to_off() {
        let a = parse(&args(&[
            "--from-snapshot",
            "s",
            "--account",
            "default",
            "--uin-hash",
            "dca62c394a68",
        ]))
        .unwrap();
        assert!(!a.inventory);
        assert_eq!(a.out, None);
        assert_eq!(a.mapping, None);
        assert_eq!(a.shadow_copy, None);
        assert!(!a.delta);
    }

    #[test]
    fn parse_duplicate_new_flags_are_errors() {
        for flags in [
            vec!["--mapping", "a.json", "--mapping", "b.json"],
            vec!["--shadow-copy", "x", "--shadow-copy", "y"],
            vec!["--out", "a", "--out", "b"],
        ] {
            let e = parse(&args(&flags)).unwrap_err();
            assert!(e.contains("given twice"), "{}", e);
        }
        for flag in ["--inventory", "--delta"] {
            let e = parse(&args(&[flag, flag])).unwrap_err();
            assert!(e.contains(&format!("{flag} given twice")), "{e}");
        }
    }

    #[test]
    fn parse_batch12_modes_conflict_with_apply() {
        // Each dry-run-only flag names itself in the conflict error.
        // (--mapping is NO LONGER in this list: batch 16 made it an
        // --apply REQUIREMENT instead of a conflict.)
        for (flags, flag) in [
            (vec!["--inventory"], "--inventory"),
            (vec!["--shadow-copy", r"D:\s"], "--shadow-copy"),
            (vec!["--delta", "--mapping", "m.json"], "--delta"),
            (vec!["--inventory", "--out", "o.json"], "--inventory"),
        ] {
            let mut v = vec!["--apply"];
            v.extend(flags);
            let e = parse(&args(&v)).unwrap_err();
            assert!(
                e.contains(&format!("{flag} is dry-run only and conflicts with --apply")),
                "{e}"
            );
        }
        // --out with --apply (no --inventory) also names itself.
        let e = parse(&args(&["--apply", "--out", "o.json"])).unwrap_err();
        assert!(e.contains("--out is dry-run only"), "{e}");
    }

    #[test]
    fn parse_out_needs_inventory() {
        let e = parse(&args(&["--out", "o.json"])).unwrap_err();
        assert!(e.contains("--out needs --inventory"), "{e}");
        // With --inventory (and the required flags) it is fine.
        let a = parse(&with_base(&["--inventory", "--out", "o.json"])).unwrap();
        assert!(a.inventory);
        assert_eq!(a.out, Some(PathBuf::from("o.json")));
    }

    #[test]
    fn parse_inventory_excludes_the_mapping_mode() {
        for flags in [
            vec!["--inventory", "--mapping", "m.json"],
            vec!["--inventory", "--shadow-copy", r"D:\s"],
            vec!["--inventory", "--delta"],
        ] {
            let e = parse(&args(&flags)).unwrap_err();
            assert!(
                e.contains("--inventory cannot be combined with --mapping/--shadow-copy/--delta"),
                "{}",
                e
            );
        }
    }

    #[test]
    fn parse_delta_needs_the_mapping_mode() {
        let e = parse(&args(&["--delta"])).unwrap_err();
        assert!(e.contains("--delta needs the mapping mode"), "{e}");
        // Either selector is enough (required flags included).
        assert!(parse(&with_base(&["--delta", "--mapping", "m.json"])).is_ok());
        assert!(parse(&with_base(&["--delta", "--shadow-copy", r"D:\s"])).is_ok());
    }

    // --- batch 14 N1: --distinct ----------------------------------------

    #[test]
    fn parse_distinct_consumes_one_value_and_repeats_to_ten() {
        // Ten specs parse; the 11th is refused with the cap named.
        let mut v = args(&[
            "--from-snapshot",
            "s",
            "--account",
            "default",
            "--uin-hash",
            "dca62c394a68",
        ]);
        for i in 0..10 {
            v.push("--distinct".into());
            v.push(format!("one2one:message.msgType{i}"));
        }
        let a = parse(&v).unwrap();
        assert_eq!(a.distinct.len(), 10);
        assert_eq!(a.distinct[0].column, "msgType0");
        assert_eq!(a.distinct[9].column, "msgType9");
        assert_eq!(a.distinct[0].kind, import_map::MapDb::OneToOne);
        // Duplicate specs are allowed (the brief says repeatable).
        let a = parse(&args(&[
            "--from-snapshot",
            "s",
            "--account",
            "default",
            "--uin-hash",
            "dca62c394a68",
            "--distinct",
            "one2one:message.msgType",
            "--distinct",
            "one2one:message.msgType",
        ]))
        .unwrap();
        assert_eq!(a.distinct.len(), 2);
        v.push("--distinct".into());
        v.push("one2one:message.eleventh".into());
        let e = parse(&v).unwrap_err();
        assert!(e.contains("at most 10 per run"), "{e}");
        assert!(e.contains("11th"), "{e}");
        // A missing or flag-like value is an error, like every value flag.
        let e = parse(&args(&["--distinct"])).unwrap_err();
        assert!(e.contains("--distinct requires a value"), "{e}");
        let e = parse(&args(&["--distinct", "--apply"])).unwrap_err();
        assert!(e.contains("--distinct requires a value"), "{e}");
    }

    #[test]
    fn parse_distinct_validates_the_spec_shape() {
        let a = parse(&with_base(&["--distinct", "index:conversation.isGroup"])).unwrap();
        assert_eq!(
            a.distinct,
            vec![import::distinct::DistinctSpec {
                kind: import_map::MapDb::Index,
                table: "conversation".into(),
                column: "isGroup".into(),
            }]
        );
        for (bad, needle) in [
            (
                "bogus:message.msgType",
                "unknown dbkind \"bogus\" (allowed: index, one2one, group, stranger)",
            ),
            ("one2one", "must be <dbkind>:<table>.<column>"),
            ("one2one:message", "missing the .<column> part"),
            ("one2one:.msgType", "empty <table> part"),
            ("group:message.", "empty <column> part"),
        ] {
            let e = parse(&with_base(&["--distinct", bad])).unwrap_err();
            assert!(e.contains(&format!("--distinct {bad:?}:")), "{bad} -> {e}");
            assert!(e.contains(needle), "{bad} -> {e}");
        }
    }

    #[test]
    fn parse_distinct_conflicts_with_apply_and_the_other_modes() {
        // --apply names the flag (dry-run only).
        let e = parse(&args(&[
            "--apply",
            "--distinct",
            "index:conversation.isGroup",
        ]))
        .unwrap_err();
        assert!(
            e.contains("--distinct is dry-run only and conflicts with --apply"),
            "{e}"
        );
        // One mode per run.
        for flags in [
            vec!["--inventory", "--distinct", "index:conversation.isGroup"],
            vec!["--mapping", "m.json", "--distinct", "index:conversation.isGroup"],
            vec!["--delta", "--mapping", "m.json", "--distinct", "index:conversation.isGroup"],
            vec!["--shadow-copy", r"D:\s", "--distinct", "index:conversation.isGroup"],
        ] {
            let e = parse(&args(&flags)).unwrap_err();
            assert!(e.contains("--distinct cannot be combined"), "{e}");
        }
        // --out still needs --inventory.
        let e = parse(&args(&["--distinct", "index:conversation.isGroup", "--out", "o.json"]))
            .unwrap_err();
        assert!(e.contains("--out needs --inventory"), "{e}");
        // --help yields on a consistent invocation…
        let a = parse(&args(&["--help", "--distinct", "index:conversation.isGroup"])).unwrap();
        assert!(a.help);
        // …but a conflicting pair is still an error — conflicts beat
        // help, exactly like the batch-6 --dry-run/--apply rule.
        let e = parse(&args(&[
            "--help",
            "--inventory",
            "--distinct",
            "index:conversation.isGroup",
        ]))
        .unwrap_err();
        assert!(e.contains("--distinct cannot be combined"), "{e}");
    }

    // --- batch 15: --all-dbs / --own-uid-from-settings ---------------------

    #[test]
    fn parse_all_dbs_needs_distinct_and_refuses_index_specs() {
        // Needs --distinct (whatever other mode was picked).
        let e = parse(&with_base(&["--all-dbs"])).unwrap_err();
        assert!(e.contains("--all-dbs needs --distinct"), "{e}");
        let e = parse(&with_base(&["--all-dbs", "--inventory"])).unwrap_err();
        assert!(e.contains("--all-dbs needs --distinct"), "{e}");
        // An index spec is refused: exactly one Core\Index.db.
        let e = parse(&with_base(&[
            "--all-dbs",
            "--distinct",
            "index:conversation.isGroup",
        ]))
        .unwrap_err();
        assert!(
            e.contains(
                "--all-dbs with index:conversation.isGroup: the snapshot has exactly ONE index DB"
            ),
            "{e}"
        );
        // The message kinds aggregate across every DB of the kind.
        let a = parse(&with_base(&[
            "--all-dbs",
            "--distinct",
            "one2one:message.msgType",
            "--distinct",
            "group:message.msgType",
            "--distinct",
            "stranger:message.msgType",
        ]))
        .unwrap();
        assert!(a.all_dbs);
        assert_eq!(a.distinct.len(), 3);
        // Duplicates are a parse error like every valueless flag.
        let e = parse(&with_base(&[
            "--all-dbs",
            "--distinct",
            "one2one:message.msgType",
            "--all-dbs",
        ]))
        .unwrap_err();
        assert!(e.contains("--all-dbs given twice"), "{e}");
        // A CONSISTENT invocation yields to help…
        let a = parse(&args(&[
            "--help",
            "--all-dbs",
            "--distinct",
            "one2one:message.msgType",
        ]))
        .unwrap();
        assert!(a.help);
    }

    #[test]
    fn parse_own_uid_from_settings_needs_the_mapping_mode() {
        // Outside the mapping mode the flag has nothing to seed.
        let e = parse(&with_base(&["--own-uid-from-settings"])).unwrap_err();
        assert!(e.contains("--own-uid-from-settings needs the mapping mode"), "{e}");
        let e = parse(&with_base(&[
            "--own-uid-from-settings",
            "--distinct",
            "one2one:message.msgType",
        ]))
        .unwrap_err();
        assert!(e.contains("--own-uid-from-settings needs the mapping mode"), "{e}");
        // Either mapping-mode selector is enough.
        let a = parse(&with_base(&["--own-uid-from-settings", "--mapping", "m.json"])).unwrap();
        assert!(a.own_uid_from_settings);
        let a = parse(&with_base(&[
            "--own-uid-from-settings",
            "--shadow-copy",
            r"D:\s",
        ]))
        .unwrap();
        assert!(a.own_uid_from_settings);
        // It rides along with --delta (still the mapping mode).
        let a = parse(&with_base(&[
            "--own-uid-from-settings",
            "--delta",
            "--mapping",
            "m.json",
        ]))
        .unwrap();
        assert!(a.own_uid_from_settings);
        assert!(a.delta);
        // Duplicates are an error.
        let e = parse(&with_base(&[
            "--own-uid-from-settings",
            "--mapping",
            "m.json",
            "--own-uid-from-settings",
        ]))
        .unwrap_err();
        assert!(e.contains("--own-uid-from-settings given twice"), "{e}");
        // A CONSISTENT invocation yields to help…
        let a = parse(&args(&[
            "--help",
            "--own-uid-from-settings",
            "--mapping",
            "m.json",
        ]))
        .unwrap();
        assert!(a.help);
    }

    // --- batch 23a C1: --content-shape / --by ------------------------------

    #[test]
    fn parse_content_shape_needs_by_and_vice_versa() {
        // A consistent invocation parses; each half alone names both.
        let a = parse(&with_base(&[
            "--content-shape",
            "one2one:message.message",
            "--by",
            "msgType",
        ]))
        .unwrap();
        assert_eq!(
            a.content_shape,
            Some(import::distinct::DistinctSpec {
                kind: import_map::MapDb::OneToOne,
                table: "message".into(),
                column: "message".into(),
            })
        );
        assert_eq!(a.by.as_deref(), Some("msgType"));
        assert!(!a.apply);
        let e = parse(&with_base(&["--content-shape", "one2one:message.message"]))
            .unwrap_err();
        assert!(e.contains("--content-shape needs --by <code column>"), "{e}");
        let e = parse(&with_base(&["--by", "msgType"])).unwrap_err();
        assert!(e.contains("--by needs --content-shape"), "{e}");
        // --by never rides another mode (here: --distinct).
        let e = parse(&with_base(&[
            "--distinct",
            "one2one:message.msgType",
            "--by",
            "msgType",
        ]))
        .unwrap_err();
        assert!(e.contains("--by needs --content-shape"), "{e}");
        // An empty --by is refused; duplicates and missing/flag-like
        // values are errors like every value flag.
        let e = parse(&with_base(&[
            "--content-shape",
            "one2one:message.message",
            "--by",
            "",
        ]))
        .unwrap_err();
        assert!(e.contains("--by requires a non-empty column name"), "{e}");
        for flags in [
            vec![
                "--content-shape",
                "one2one:message.message",
                "--content-shape",
                "group:message.message",
                "--by",
                "msgType",
            ],
            vec![
                "--content-shape",
                "one2one:message.message",
                "--by",
                "msgType",
                "--by",
                "status",
            ],
        ] {
            let e = parse(&with_base(&flags)).unwrap_err();
            assert!(e.contains("given twice"), "{flags:?} -> {e}");
        }
        for flag in ["--content-shape", "--by"] {
            let e = parse(&args(&[flag])).unwrap_err();
            assert!(e.contains(&format!("{flag} requires a value")), "{e}");
            let e = parse(&args(&[flag, "--apply"])).unwrap_err();
            assert!(e.contains(&format!("{flag} requires a value")), "{e}");
        }
    }

    #[test]
    fn parse_content_shape_validates_the_spec_shape_under_its_own_name() {
        // The spec parses through the same <kind>:<table>.<column>
        // rule, but the errors name --content-shape, never --distinct.
        let a = parse(&with_base(&[
            "--content-shape",
            "stranger:zz.table.col",
            "--by",
            "msgType",
        ]))
        .unwrap();
        assert_eq!(a.content_shape.as_ref().unwrap().kind, import_map::MapDb::Stranger);
        for (bad, needle) in [
            (
                "bogus:message.message",
                "unknown dbkind \"bogus\" (allowed: index, one2one, group, stranger)",
            ),
            ("one2one:message", "missing the .<column> part"),
            ("one2one:.message", "empty <table> part"),
            ("group:message.", "empty <column> part"),
        ] {
            let e = parse(&with_base(&["--content-shape", bad, "--by", "msgType"]))
                .unwrap_err();
            assert!(e.contains(&format!("--content-shape {bad:?}:")), "{bad} -> {e}");
            assert!(e.contains(needle), "{bad} -> {e}");
            assert!(!e.contains("--distinct"), "{bad} -> {e}");
        }
    }

    #[test]
    fn parse_content_shape_conflicts_with_apply_and_the_other_modes() {
        // --apply names the flag (dry-run only).
        let e = parse(&args(&[
            "--apply",
            "--i-have-a-backup-plan",
            "--target",
            r"D:\s",
            "--mapping",
            "m.json",
            "--content-shape",
            "one2one:message.message",
            "--by",
            "msgType",
        ]))
        .unwrap_err();
        assert!(
            e.contains("--content-shape is dry-run only and conflicts with --apply"),
            "{e}"
        );
        // One mode per run — each names --content-shape.
        for flags in [
            vec!["--inventory", "--content-shape", "one2one:message.message", "--by", "msgType"],
            vec!["--mapping", "m.json", "--content-shape", "one2one:message.message", "--by", "msgType"],
            vec!["--shadow-copy", r"D:\s", "--content-shape", "one2one:message.message", "--by", "msgType"],
            vec!["--delta", "--mapping", "m.json", "--content-shape", "one2one:message.message", "--by", "msgType"],
            vec!["--distinct", "one2one:message.msgType", "--content-shape", "one2one:message.message", "--by", "msgType"],
            vec!["--media-plan", "--content-shape", "one2one:message.message", "--by", "msgType"],
        ] {
            let e = parse(&with_base(&flags)).unwrap_err();
            assert!(e.contains("--content-shape cannot be combined"), "{flags:?} -> {e}");
        }
        // --out rides the content-shape mode (and still needs one of
        // its two modes).
        let a = parse(&with_base(&[
            "--content-shape",
            "one2one:message.message",
            "--by",
            "msgType",
            "--out",
            "o.json",
        ]))
        .unwrap();
        assert_eq!(a.out, Some(PathBuf::from("o.json")));
        // A CONSISTENT invocation yields to help…
        let a = parse(&args(&[
            "--help",
            "--content-shape",
            "one2one:message.message",
            "--by",
            "msgType",
        ]))
        .unwrap();
        assert!(a.help);
        // …but a conflicting pair (or a missing --by) beats help.
        let e = parse(&args(&[
            "--help",
            "--inventory",
            "--content-shape",
            "one2one:message.message",
            "--by",
            "msgType",
        ]))
        .unwrap_err();
        assert!(e.contains("--content-shape cannot be combined"), "{e}");
        let e = parse(&args(&["--help", "--content-shape", "one2one:message.message"]))
            .unwrap_err();
        assert!(e.contains("--content-shape needs --by"), "{e}");
    }

    #[test]
    fn parse_content_shape_all_dbs_rides_and_refuses_index_specs() {
        // --all-dbs rides the content-shape mode too.
        let a = parse(&with_base(&[
            "--all-dbs",
            "--content-shape",
            "one2one:message.message",
            "--by",
            "msgType",
        ]))
        .unwrap();
        assert!(a.all_dbs);
        assert!(a.content_shape.is_some());
        // An index spec is refused: exactly one Core\Index.db.
        let e = parse(&with_base(&[
            "--all-dbs",
            "--content-shape",
            "index:conversation.raw",
            "--by",
            "msgType",
        ]))
        .unwrap_err();
        assert!(
            e.contains(
                "--all-dbs with index:conversation.raw: the snapshot has exactly ONE index DB"
            ),
            "{e}"
        );
        // Without --all-dbs the index kind is a normal (sample) spec.
        let a = parse(&with_base(&[
            "--content-shape",
            "index:conversation.raw",
            "--by",
            "localType",
        ]))
        .unwrap();
        assert_eq!(a.content_shape.as_ref().unwrap().kind, import_map::MapDb::Index);
        // The updated --all-dbs message still leads with the old text.
        let e = parse(&with_base(&["--all-dbs"])).unwrap_err();
        assert!(e.contains("--all-dbs needs --distinct"), "{e}");
        assert!(e.contains("or --content-shape"), "{e}");
    }

    // --- batch 24 D3: --decrypt-basic -------------------------------------

    #[test]
    fn parse_decrypt_basic_rides_the_content_shape_mode_only() {
        // With --content-shape (and its --by) it parses.
        let a = parse(&with_base(&[
            "--content-shape",
            "one2one:message.message",
            "--by",
            "msgType",
            "--decrypt-basic",
        ]))
        .unwrap();
        assert!(a.decrypt_basic);
        assert!(!a.apply);
        // It also rides --all-dbs + --out (still the same mode).
        let a = parse(&with_base(&[
            "--all-dbs",
            "--content-shape",
            "one2one:message.message",
            "--by",
            "msgType",
            "--decrypt-basic",
            "--out",
            "o.json",
        ]))
        .unwrap();
        assert!(a.decrypt_basic && a.all_dbs);
        // Alone, or on any other mode, it names its mode — checked
        // BEFORE the --apply preconditions, so the error is the
        // rider's, never a misleading precondition one.
        for flags in [
            vec!["--decrypt-basic"],
            vec!["--decrypt-basic", "--inventory"],
            vec!["--decrypt-basic", "--mapping", "m.json"],
            vec!["--decrypt-basic", "--shadow-copy", r"D:\s"],
            vec!["--decrypt-basic", "--distinct", "one2one:message.msgType"],
            vec!["--decrypt-basic", "--media-plan"],
            vec!["--decrypt-basic", "--apply"],
        ] {
            let e = parse(&with_base(&flags)).unwrap_err();
            assert!(
                e.contains("--decrypt-basic needs --content-shape"),
                "{flags:?} -> {e}"
            );
        }
        // With --apply AND --content-shape the mode's own dry-run
        // conflict fires (the rider inherits it).
        let e = parse(&args(&[
            "--apply",
            "--i-have-a-backup-plan",
            "--target",
            r"D:\s",
            "--mapping",
            "m.json",
            "--content-shape",
            "one2one:message.message",
            "--by",
            "msgType",
            "--decrypt-basic",
        ]))
        .unwrap_err();
        assert!(
            e.contains("--content-shape is dry-run only and conflicts with --apply"),
            "{e}"
        );
        // Duplicates are an error like every valueless flag.
        let e = parse(&with_base(&[
            "--content-shape",
            "one2one:message.message",
            "--by",
            "msgType",
            "--decrypt-basic",
            "--decrypt-basic",
        ]))
        .unwrap_err();
        assert!(e.contains("--decrypt-basic given twice"), "{e}");
        // A CONSISTENT invocation yields to help…
        let a = parse(&args(&[
            "--help",
            "--content-shape",
            "one2one:message.message",
            "--by",
            "msgType",
            "--decrypt-basic",
        ]))
        .unwrap();
        assert!(a.help);
        // …but the missing-mode rider beats help (the batch-6 rule).
        let e = parse(&args(&["--help", "--decrypt-basic"])).unwrap_err();
        assert!(e.contains("--decrypt-basic needs --content-shape"), "{e}");
    }

    #[test]
    fn parse_the_briefs_mapping_invocation() {
        // The documented dry run: --dry-run --mapping m.json
        // --shadow-copy <dir> --delta.
        let a = parse(&args(&[
            "--from-snapshot",
            r"D:\ZaloRust Data\import-snapshot\2026-11-21",
            "--account",
            "default",
            "--uin-hash",
            "dca62c394a68",
            "--key-file",
            r"D:\.opencode\d7\zalo-desktop-uin-key-2026-11-19.bin",
            "--dry-run",
            "--mapping",
            "m.json",
            "--shadow-copy",
            r"D:\ZaloRust Data\shadow-copy",
            "--delta",
        ]))
        .unwrap();
        assert!(!a.apply);
        assert_eq!(a.mapping, Some(PathBuf::from("m.json")));
        assert_eq!(a.shadow_copy, Some(PathBuf::from(r"D:\ZaloRust Data\shadow-copy")));
        assert!(a.delta);
    }

    #[test]
    fn parse_help_short_circuits_the_new_flags_too() {
        let a = parse(&args(&["--help", "--inventory", "--out", "o.json"])).unwrap();
        assert!(a.help);
        // A CONSISTENT batch-12 invocation with --help yields to help…
        let a = parse(&args(&["--help", "--mapping", "m.json", "--shadow-copy", r"D:\s"])).unwrap();
        assert!(a.help);
        // …but a conflicting pair is still an error — conflicts beat
        // help, exactly like the batch-6 --dry-run/--apply rule.
        let e = parse(&args(&["--help", "--inventory", "--mapping", "m.json"])).unwrap_err();
        assert!(e.contains("--inventory cannot be combined"), "{e}");
    }

    #[test]
    fn cli_main_help_exits_zero() {
        assert_eq!(main(&args(&["--help"])), 0);
    }

    #[test]
    fn cli_main_parse_error_exits_two() {
        assert_eq!(main(&args(&["--bogus"])), 2);
    }

    #[test]
    fn cli_main_run_error_exits_one() {
        // A temp dir with no snapshot-manifest.json: the F3 guard fires.
        let dir = std::env::temp_dir().join(format!(
            "zr-cli-main-{}-{}",
            std::process::id(),
            super::super::schema::now_ms()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let code = main(&args(&[
            "--from-snapshot",
            &dir.to_string_lossy(),
            "--account",
            "default",
            "--uin-hash",
            "dca62c394a68",
        ]));
        assert_eq!(code, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- batch 28 M3: --media-derivatives (parse) ---------------------------

    #[test]
    fn parse_media_derivatives_rules() {
        use crate::shadow::img_derive::Variant;
        // Only --target: no snapshot flags, no --apply.
        let a = parse(&args(&["--media-derivatives", "--target", r"D:\shadow"])).unwrap();
        assert!(a.media_derivatives && !a.apply);
        assert_eq!(a.target, Some(PathBuf::from(r"D:\shadow")));
        assert!(a.variants.is_empty() && a.threads.is_none() && a.limit.is_none());
        // The riders.
        let a = parse(&args(&[
            "--media-derivatives",
            "--target",
            r"D:\shadow",
            "--variants",
            "view,thumb",
            "--limit",
            "50",
            "--threads",
            "3",
        ]))
        .unwrap();
        assert_eq!(a.variants, vec![Variant::View, Variant::Thumb]);
        assert_eq!(a.limit, Some(50));
        assert_eq!(a.threads, Some(3));
        // --help still short-circuits.
        assert!(parse(&args(&["--media-derivatives", "--help"])).unwrap().help);
        // Needs --target.
        let e = parse(&args(&["--media-derivatives"])).unwrap_err();
        assert!(e.contains("--media-derivatives needs --target"), "{e}");
        // Bad rider values.
        for (extra, needle) in [
            (vec!["--variants", "orig"], "orig is built on demand"),
            (vec!["--variants", "thumb,thumb"], "lists thumb twice"),
            (vec!["--variants", "thumb,"], "comma list of thumb,view"),
            (vec!["--variants", ""], "comma list of thumb,view"),
            (vec!["--variants", "big"], "comma list of thumb,view"),
            (vec!["--threads", "0"], "--threads must be a whole number 1..=64"),
            (vec!["--threads", "65"], "--threads must be a whole number 1..=64"),
            (vec!["--threads", "x"], "--threads must be a whole number 1..=64"),
            (vec!["--limit", "0"], "--limit must be a whole number >= 1"),
        ] {
            let mut v = args(&["--media-derivatives", "--target", r"D:\s"]);
            v.extend(extra.iter().map(|s| s.to_string()));
            let e = parse(&v).unwrap_err();
            assert!(e.contains(needle), "{extra:?} -> {e}");
        }
        // One mode per run: everything else conflicts, naming the flag.
        for (extra, flag) in [
            (vec!["--apply"], "--apply"),
            (vec!["--i-have-a-backup-plan"], "--i-have-a-backup-plan"),
            (vec!["--inventory"], "--inventory"),
            (vec!["--mapping", "m.json"], "--mapping"),
            (vec!["--delta"], "--delta"),
            (vec!["--media-plan"], "--media-plan"),
            (vec!["--local-media-copy"], "--local-media-copy"),
            (vec!["--local-media-plan"], "--local-media-plan"),
            (vec!["--local-media-probe"], "--local-media-probe"),
            (vec!["--local-media-root", "r"], "--local-media-root"),
            (vec!["--include-video"], "--include-video"),
            (vec!["--out", "o.json"], "--out"),
            (vec!["--from-snapshot", "s"], "--from-snapshot"),
            (vec!["--account", "default"], "--account"),
            (vec!["--uin-hash", "dca62c394a68"], "--uin-hash"),
            (vec!["--key-file", "k"], "--key-file"),
        ] {
            let mut v = args(&["--media-derivatives", "--target", r"D:\s"]);
            v.extend(extra.iter().map(|s| s.to_string()));
            let e = parse(&v).unwrap_err();
            assert!(
                e.contains(&format!("--media-derivatives cannot be combined with {flag}")),
                "{extra:?} -> {e}"
            );
        }
        // The riders without the mode are refused, and --limit keeps
        // its old rule for the other modes.
        let e = parse(&with_base(&["--variants", "thumb"])).unwrap_err();
        assert!(e.contains("are --media-derivatives flags"), "{e}");
        let e = parse(&with_base(&["--threads", "2"])).unwrap_err();
        assert!(e.contains("are --media-derivatives flags"), "{e}");
        let e = parse(&with_base(&["--limit", "2"])).unwrap_err();
        assert!(e.contains("are --local-media-copy flags"), "{e}");
        // Without the mode --target is still an apply/plan/copy flag.
        let e = parse(&with_base(&["--target", r"D:\s"])).unwrap_err();
        assert!(e.contains("--target is an --apply/--local-media-plan"), "{e}");
        // Duplicates.
        let e = parse(&args(&[
            "--media-derivatives",
            "--media-derivatives",
            "--target",
            r"D:\s",
        ]))
        .unwrap_err();
        assert!(e.contains("given twice"), "{e}");
    }
}
