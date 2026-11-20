//! `zalors import` CLI (P2, audit §4 items 2.0–2.4; batch 6 F1;
//! batch 12 adds `--inventory`/`--out` and the
//! `--mapping`/`--shadow-copy`/`--delta` dry-run mode; batch 14
//! adds the whitelisted `--distinct` code-column probe).
//!
//! Spec (KQ4: the import only ever reads a COLD SNAPSHOT):
//! ```text
//! zalors import --from-snapshot <dir> --account <id> --uin-hash <sha256-12>
//!              [--key-file <file>] [--cipher-compat <3|4>]
//!              [--dry-run | --apply]
//!              [--inventory [--out <file>]
//!               | [--distinct <dbkind>:<table>.<column>]… (max 10)
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
--out <file>     JSON inventory report (only with --inventory)
--shadow-copy    shadow STORE dir whose temp COPY is classified against
                  (its files are read; the store itself is never opened)
--delta          skip rows at/before the per-DB import cursor (dry-run only)
--distinct       see the modes above: whitelisted code-column distinct
                  values, repeatable, max 10 per run, dry-run only
--all-dbs        with --distinct: aggregate the column across EVERY DB of
                  the message kind (one2one/group/stranger), summing
                  per-DB counts (batch 15); an index spec is refused —
                  there is exactly one Core\\Index.db
--own-uid-from-settings   with --mapping/--shadow-copy or --apply: seed the
                  import extraction's self-sent sender from
                  settings.shadow.own_uid read through the settings loader
                  (never printed; env ZR_OWN_UID, shape-validated, wins as
                  the override)
--dry-run        inventory only, zero writes (the default)
--target <dir>   with --apply: the shadow STORE dir to write into. No
                  default — the live store is never silently chosen
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
    let (mut dry_run, mut apply, mut help, mut inventory, mut delta) =
        (false, false, false, false, false);
    let (mut all_dbs, mut own_uid_from_settings) = (false, false);
    let (mut i_have_a_backup_plan, mut unmapped_as_raw, mut media_plan) = (false, false, false);
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
        if mapping.is_none() {
            return Err(
                "--apply needs --mapping <file>: the built-in skeleton maps nothing".into(),
            );
        }
    }
    for (on, flag) in [
        (target.is_some(), "--target"),
        (i_have_a_backup_plan, "--i-have-a-backup-plan"),
        (unmapped_as_raw, "--unmapped-as-raw"),
    ] {
        if on && !apply {
            return Err(format!(
                "{flag} is an --apply-mode flag: add --apply (and its other \
                 preconditions) or drop it"
            ));
        }
    }
    if out.is_some() && !inventory {
        return Err("--out needs --inventory (it is the JSON inventory report)".into());
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
    // Batch 16 P2: --media-plan is its own dry-run mode.
    if media_plan && (mapping.is_some() || shadow_copy.is_some() || delta) {
        return Err(
            "--media-plan cannot be combined with --mapping/--shadow-copy/--delta \
             (it needs no mapping — it discovers the media tables itself)"
                .into(),
        );
    }
    // Batch 15 O2: --all-dbs rides the --distinct mode, and only a
    // message kind has more than one DB to aggregate.
    if all_dbs && distinct.is_empty() {
        return Err(
            "--all-dbs needs --distinct (it aggregates every DB of the requested message kind)"
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
            apply: false,
            help: true,
        });
    }
    Ok(ImportArgs {
        from_snapshot: from_snapshot.ok_or("missing required --from-snapshot <dir>")?,
        account: account.ok_or("missing required --account <id>")?,
        uin_hash: uin_hash.ok_or("missing required --uin-hash <sha256-12>")?,
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
        // Each apply-mode flag outside --apply names itself.
        for (flags, flag) in [
            (vec!["--target", r"D:\shadow"], "--target"),
            (vec!["--i-have-a-backup-plan"], "--i-have-a-backup-plan"),
            (vec!["--unmapped-as-raw"], "--unmapped-as-raw"),
        ] {
            let e = parse(&with_base(&flags)).unwrap_err();
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
}
