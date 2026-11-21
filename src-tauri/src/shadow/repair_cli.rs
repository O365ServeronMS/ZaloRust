//! `zalors repair` CLI (batch 20, audit T8 / §1.2 migration): the
//! guarded user entry for the one-time v1 data repair
//! (`repair::repair_v1`), with the same safety level as the import
//! apply (batch 16) — preconditions with zero writes, a verified
//! backup before the first write, ONE transaction for the whole
//! repair, and integrity + idempotence checks after.
//!
//! ```text
//! zalors repair --target <shadow store dir> [--dry-run | --apply --i-have-a-backup-plan]
//!               [--own-uid-from-settings] [--help]
//! ```
//!
//! Hard rules obeyed:
//! - The CLI never accepts a password (not on argv, not in env): a
//!   passphrase-mode store opens only through its remember file, and
//!   a `Locked` store gets the documented refusal (the `import_apply`
//!   pattern, R4).
//! - `--dry-run` (the default) NEVER opens the target read-write.
//!   `backup_db`'s export needs a READ-WRITE source connection — this
//!   build's read-only opens set `PRAGMA query_only`, and SQLite's
//!   ATTACH inherits the main connection's open flags, so an export
//!   from a read-only source can never write its destination. The
//!   closest read-only-safe alternative is the one used here: a BYTE
//!   COPY of the store's file set inside a NEW temp dir is the
//!   export's source, and the repair runs on the exported copy. The
//!   target itself is only ever opened read-only; its bytes never
//!   change. The temp dir is left on disk, its path printed (the
//!   maint_repair convention).
//! - `--apply --i-have-a-backup-plan` makes its own verified backup
//!   into `<target>\pre-repair-backups\` BEFORE the first write, then
//!   runs the whole repair in ONE transaction — any step error rolls
//!   back, so the store is unchanged since the backup.
//! - Output is counts, kinds and paths only — never message text,
//!   ids, uids, keys or passwords; the own uid prints only as
//!   `own_uid set: true/false`. Every line is STREAMED through the
//!   sink as it is produced (batch 16 F3): a later failure never
//!   hides the backup path or the progress lines.

use std::path::{Path, PathBuf};

use rusqlite::Connection;

use super::backup;
use super::import;
use super::passphrase::{self, StoreKey};
use super::pipeline::sqlite_kind;
use super::repair;
use super::schema;
use super::db_file;
use crate::migrate::sqlcipher;

/// The usage text (`--help`, and after any parse error).
const USAGE: &str = "\
usage: zalors repair --target <shadow store dir>
                     [--dry-run | --apply --i-have-a-backup-plan]
                     [--own-uid-from-settings] [--help]

modes (one per run):
  (default) --dry-run   the guarded REPORT: the target opens READ-ONLY and
                        its bytes never change. A verified backup is made
                        into a NEW temp dir (never under the target) and
                        the repair runs on that COPY: counts before,
                        repair_v1_checked, integrity checks, counts
                        after, then a second dry run that must be all
                        zeros. The temp copy is left on disk and its
                        path is printed.
  --apply               the guarded WRITE step (needs the second flag
   --i-have-a-backup-plan   --i-have-a-backup-plan): a verified backup in
                        <target>\\pre-repair-backups\\ first, then the
                        whole repair in ONE transaction (BEGIN IMMEDIATE
                        .. COMMIT — any step error rolls back, so the
                        store is unchanged since the backup), then
                        integrity + idempotence checks.

flags:
--target <dir>          the shadow STORE dir to repair. REQUIRED in both
                        modes; no default — the live store is never
                        silently chosen
--dry-run                report only, zero writes on the target (default)
--apply                  write into the store (the guarded step above)
--i-have-a-backup-plan   with --apply: the explicit confirmation. The run
                        still makes and verifies its own backup first
                        (<target>\\pre-repair-backups\\); this flag says
                        you ALSO have your own way to restore
--own-uid-from-settings  seed the step-(e) sender backfill's own uid from
                        settings.shadow.own_uid (env ZR_OWN_UID,
                        shape-validated, wins as the override; never
                        printed — only 'own_uid set: true/false').
                        Without an own uid step (e) is SKIPPED (and
                        said so)
--help                   this usage, exit 0

the preconditions (BOTH modes, in this order; each refuses with a
clear message and zero writes, exit 1):
  1. no other zalors.exe process may run (the store has one writer)
  2. <target>\\default.db must exist
  3. the store must open (passphrase mode without a usable remember
     file refuses — the CLI never accepts a password, not on argv,
     not in env)
  4. the store's schema version must match this binary (the run never
     migrates a store — open it once with the matching build, quit it,
     then re-run)

notes:
  --dry-run never opens the target read-write: backup_db's export needs a
     read-write source (a read-only open is query_only and SQLite's
     ATTACH inherits the main connection's flags), so the export runs on
     a byte copy of the store inside the temp dir. The target itself is
     only ever opened read-only.
exit codes: 0 ok · 1 runtime refusal or failure · 2 parse error";

/// Parsed `zalors repair` arguments (pure parse result — see `parse`).
#[derive(Debug, Clone, PartialEq)]
pub struct RepairArgs {
    /// `--target <dir>` (required, both modes): the shadow STORE dir.
    /// No default — the live store is never silently chosen.
    pub target: PathBuf,
    /// `--dry-run`: report only (the default when neither mode flag
    /// is given).
    pub dry_run: bool,
    /// `--apply`: the guarded write step.
    pub apply: bool,
    /// `--own-uid-from-settings`: read the own uid from
    /// `settings.shadow.own_uid` through the settings loader (env
    /// `ZR_OWN_UID` wins; the value is never printed).
    pub own_uid_from_settings: bool,
    /// `--i-have-a-backup-plan`: the explicit confirmation `--apply`
    /// demands (apply mode only).
    pub i_have_a_backup_plan: bool,
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

/// Parse the argv of a `zalors repair ...` invocation (everything
/// after the `repair` word). Pure: never prints, never touches the
/// FS. Rules (the `cli.rs` style): value flags consume exactly one
/// value (missing or `--`-prefixed is an error); boolean flags
/// consume nothing; unknown args are errors; duplicates are errors;
/// `--dry-run` + `--apply` conflict; `--i-have-a-backup-plan`
/// requires `--apply`; `--help` short-circuits the required flags —
/// but a conflicting pair still beats it (the batch-6 convention).
pub fn parse(args: &[String]) -> Result<RepairArgs, String> {
    let mut target: Option<PathBuf> = None;
    let (mut dry_run, mut apply, mut help) = (false, false, false);
    let (mut own_uid_from_settings, mut i_have_a_backup_plan) = (false, false);

    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        if flag == "--target" {
            let value =
                args.get(i + 1).ok_or_else(|| format!("{flag} requires a value"))?;
            if value.starts_with("--") {
                return Err(format!("{flag} requires a value, got {value}"));
            }
            set_once(&mut target, flag, PathBuf::from(value))?;
            i += 2;
            continue;
        }
        match flag {
            "--dry-run" => set_bool_once(&mut dry_run, flag)?,
            "--apply" => set_bool_once(&mut apply, flag)?,
            "--i-have-a-backup-plan" => set_bool_once(&mut i_have_a_backup_plan, flag)?,
            "--own-uid-from-settings" => set_bool_once(&mut own_uid_from_settings, flag)?,
            "--help" => set_bool_once(&mut help, flag)?,
            other => return Err(format!("unknown argument {other}")),
        }
        i += 1;
    }

    if dry_run && apply {
        return Err("--dry-run and --apply are mutually exclusive".into());
    }
    if apply && !i_have_a_backup_plan {
        return Err(
            "--apply needs --i-have-a-backup-plan: the repair rewrites rows in the \
             shadow store — confirm you have a way to restore it (the run also makes \
             its own verified backup first)"
                .into(),
        );
    }
    if i_have_a_backup_plan && !apply {
        return Err(
            "--i-have-a-backup-plan is an --apply-mode flag: add --apply (and its \
             other preconditions) or drop it"
                .into(),
        );
    }
    if help {
        return Ok(RepairArgs {
            target: PathBuf::new(),
            dry_run,
            apply: false,
            own_uid_from_settings,
            i_have_a_backup_plan,
            help: true,
        });
    }
    Ok(RepairArgs {
        target: target.ok_or("missing required --target <shadow store dir>")?,
        dry_run,
        apply,
        own_uid_from_settings,
        i_have_a_backup_plan,
        help: false,
    })
}

/// CLI entrypoint (the bin dispatches `zalors repair …` here BEFORE
/// starting Tauri, exactly like `import`). Returns the process exit
/// code: 0 usage/success · 1 runtime refusal/failure · 2 parse
/// error. The process probe is wired HERE (the real tasklist);
/// `run`'s preconditions are unit-tested with an injected probe.
pub fn main(args: &[String]) -> i32 {
    match parse(args) {
        Ok(a) if a.help => {
            println!("{USAGE}");
            0
        }
        Ok(a) => {
            let mut out = |line: &str| println!("{line}");
            match run(
                &a,
                &mut out,
                || super::import_apply::zalors_running_besides(std::process::id()),
            ) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("repair: {e}");
                    1
                }
            }
        }
        Err(e) => {
            eprintln!("repair: {e}\n{USAGE}");
            2
        }
    }
}

/// The repair run: the preconditions with the process probe injected
/// (tests pass their own), the own uid resolved through
/// `import::resolve_own_uid` (`ZR_OWN_UID`, else settings when the
/// flag is given — never printed), then the mode's guarded flow with
/// every line streamed through `out`.
pub fn run(
    a: &RepairArgs,
    out: &mut dyn FnMut(&str),
    zalors_running: impl Fn() -> Option<bool>,
) -> Result<(), String> {
    let own_uid = import::resolve_own_uid(a.own_uid_from_settings);
    run_with_own_uid(a, own_uid.as_deref(), out, zalors_running)
}

/// The repair run with the own uid INJECTED (the deterministic twin
/// of [`run`] — tests drive this so no test ever reads the process
/// env or the real settings file).
fn run_with_own_uid(
    a: &RepairArgs,
    own_uid: Option<&str>,
    out: &mut dyn FnMut(&str),
    zalors_running: impl Fn() -> Option<bool>,
) -> Result<(), String> {
    // Runtime belts (parse enforces; direct callers get the same
    // refusals).
    if a.apply && !a.i_have_a_backup_plan {
        return Err(
            "--apply needs --i-have-a-backup-plan: the repair rewrites rows in the \
             shadow store — confirm you have a way to restore it (the run also makes \
             its own verified backup first)"
                .into(),
        );
    }
    if !a.apply && a.i_have_a_backup_plan {
        return Err(
            "--i-have-a-backup-plan is an --apply-mode flag: add --apply (and its \
             other preconditions) or drop it"
                .into(),
        );
    }
    let target = a.target.clone();
    let mode = if a.apply { "repair apply" } else { "repair dry run" };

    // Precondition 1: single writer — no other zalors.exe. A check
    // that cannot run also refuses (fail closed).
    match zalors_running() {
        Some(false) => {}
        Some(true) => {
            return Err(
                "refusing: another zalors.exe process is running — quit the app first \
                 (the shadow store has one writer)"
                    .into(),
            )
        }
        None => {
            return Err(
                "refusing: cannot verify that no other zalors.exe is running \
                 (tasklist failed) — quit the app and retry"
                    .into(),
            )
        }
    }
    out(&format!(
        "{mode}: target={} ({})",
        target.display(),
        if a.apply { "read-write" } else { "read-only" }
    ));
    out(&format!("{mode}: no other zalors.exe is running"));

    // Precondition 2: the store's DB file exists.
    let db_path = db_file(&target);
    if !db_path.is_file() {
        return Err(format!(
            "--target: no {} — not a shadow store dir?",
            db_path.display()
        ));
    }

    // Precondition 3: the store opens (the dry run READ-ONLY; the
    // apply read-write — it is the writer). A Locked passphrase store
    // gets the remember-file message: the CLI never accepts a
    // password, not on argv, not in env.
    let readonly = !a.apply;
    let (conn, store_key) = match passphrase::open_store(&target, readonly) {
        Ok((c, k)) => (c, k),
        Err(passphrase::StoreOpenError::Locked) => {
            return Err(
                "the target store is password-protected (passphrase mode): unlock it in \
                 the app with 'Nhớ trên máy này' (remember on this machine) enabled, then \
                 re-run — the repair CLI never accepts passwords"
                    .into(),
            )
        }
        Err(passphrase::StoreOpenError::Other(k)) => {
            return Err(format!(
                "--target: store open failed ({k}) — no key file / broken store?"
            ))
        }
    };

    // Precondition 4: the stored schema version equals this binary's
    // (the import wording; the refusal fires BEFORE any backup or
    // copy, so zero bytes move).
    let stored_v: i64 = conn
        .query_row("SELECT MAX(version) FROM schema_meta", [], |r| r.get(0))
        .unwrap_or(0);
    if stored_v != schema::VERSION {
        return Err(format!(
            "target schema v{stored_v}, this binary expects v{} — open the store once \
             with the matching zalors build (it migrates on start), quit it, then re-run",
            schema::VERSION
        ));
    }
    out(&format!(
        "{mode}: target schema v{stored_v} matches this binary (v{})",
        schema::VERSION
    ));

    // The own uid (KQ2): never printed, only `own_uid set: …`; a run
    // without it says step (e) is skipped.
    out(&format!("{mode}: own_uid set: {}", own_uid.is_some()));
    if own_uid.is_none() {
        out(&format!(
            "{mode}: step (e) sender backfill SKIPPED — no own uid (set ZR_OWN_UID or \
             pass --own-uid-from-settings)"
        ));
    }

    if a.apply {
        run_apply_mode(&target, &conn, &store_key, own_uid, out)
    } else {
        run_dry_mode(&target, conn, &store_key, own_uid, out)
    }
}

/// `--dry-run`: the guarded report. The target stays read-only; the
/// repair runs on a verified COPY under the OS temp dir.
fn run_dry_mode(
    target: &Path,
    ro_conn: Connection,
    store_key: &StoreKey,
    own_uid: Option<&str>,
    out: &mut dyn FnMut(&str),
) -> Result<(), String> {
    // A verified backup of the target, made WITHOUT ever opening the
    // target read-write (see the module docs: `backup_db`'s export
    // cannot run from a read-only source). The export's source is a
    // BYTE COPY of the store's file set in a NEW temp dir — never
    // under the target.
    let tmp = new_temp_dir()?;
    let copy_dir = tmp.join("copy");
    std::fs::create_dir_all(&copy_dir).map_err(|e| format!("temp dir: {}", io_kind(&e)))?;
    copy_store_files(target, &copy_dir)?;
    // The target's read-only connection is no longer needed — release
    // it before the copy is opened (the files are stable: no writer
    // may run, precondition 1).
    drop(ro_conn);
    let copy_conn = open_with_store_key(&db_file(&copy_dir), store_key, false)?;

    // The verified backup itself (the repair target), sourced from the
    // COPY — never the target.
    let backup_dir = tmp.join("backup");
    let mut now = schema::now_ms();
    // The stamp resolves to one second: a re-run inside the same
    // second would collide — bump until the stamp is free (the import
    // loop).
    while backup::backup_db_path(&backup_dir, now).exists() {
        now += 1_000;
    }
    let manifest = backup::backup_db(&copy_conn, &store_key.backup_key(), &backup_dir, now)
        .map_err(|k| format!("dry-run backup failed ({k}) — the target was never touched"))?;
    let backup_path = backup::backup_db_path(&backup_dir, now);
    backup::verify_backup(&backup_path, &store_key.backup_key(), &manifest)
        .map_err(|k| format!("dry-run backup verify failed ({k}) — the target was never touched"))?;
    let manifest_path = backup_path.with_extension("json");
    out(&format!(
        "repair dry run: verified backup OK: {} (verified: sha+integrity+counts)",
        manifest_path.display()
    ));
    drop(copy_conn);

    // The repair runs on the BACKUP copy, read-write. Identical bytes
    // to the target, so the report is exactly what an apply would do.
    let rep_conn = open_with_store_key(&backup_path, store_key, false)?;

    out("== counts before (the copy) ==");
    for l in repair::counts_lines(&rep_conn) {
        out(&l);
    }

    out("== repair_v1_checked (applied to the copy; the target stays read-only) ==");
    // One transaction keeps the copy's repaired state atomic: on any
    // step error the copy rolls back and the run refuses — the report
    // a reviewer compares against the apply mode is never half-done,
    // and it mirrors the apply's own single transaction exactly.
    if let Err(e) = rep_conn.execute_batch("BEGIN IMMEDIATE") {
        return Err(format!(
            "BEGIN IMMEDIATE on the copy failed: {} — the target was never touched",
            sqlite_kind(&e)
        ));
    }
    let report = match repair::repair_v1_checked(&rep_conn, own_uid) {
        Ok(r) => r,
        Err(e) => {
            if rep_conn.execute_batch("ROLLBACK").is_err() {
                let _ = rep_conn.execute_batch("ROLLBACK");
            }
            out(&format!(
                "repair failed at step {} ({}) — rolled back on the copy, the target \
                 was never touched",
                e.step, e.kind
            ));
            return Err(format!(
                "step {} ({}) failed on the copy — the target was never touched; \
                 inspect {}",
                e.step,
                e.kind,
                tmp.display()
            ));
        }
    };
    if let Err(e) = rep_conn.execute_batch("COMMIT") {
        let _ = rep_conn.execute_batch("ROLLBACK");
        return Err(format!(
            "COMMIT on the copy failed: {} — the target was never touched",
            sqlite_kind(&e)
        ));
    }
    out(&format!("report: {}", repair::report_fields(&report)));

    // Post-repair integrity (cipher check tolerated if unsupported).
    let integrity: String = rep_conn
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .map_err(|e| format!("integrity_check failed: {}", sqlite_kind(&e)))?;
    if integrity != "ok" {
        return Err(format!(
            "integrity_check is not ok after the repair on the copy (first row: \
             {integrity:?}) — the target was never touched; inspect {}",
            tmp.display()
        ));
    }
    let cipher: String = rep_conn
        .query_row("PRAGMA cipher_integrity_check", [], |r| r.get(0))
        .unwrap_or_else(|_| "not supported".into());
    out(&format!(
        "repair dry run: integrity_check={integrity} cipher_integrity_check={cipher}"
    ));

    out("== counts after (the repaired copy — what the target WOULD look like) ==");
    for l in repair::counts_lines(&rep_conn) {
        out(&l);
    }

    out("== second repair (dry run on the repaired copy — must be all zeros) ==");
    let second = repair::repair_v1_dry_run_checked(&rep_conn, own_uid).map_err(|e| {
        format!(
            "the idempotence dry run failed at step {} ({}) — the target was never touched",
            e.step, e.kind
        )
    })?;
    if second == repair::RepairReport::default() {
        out("report: all zeros (idempotent)");
    } else {
        out(&format!(
            "report: NOT idempotent — second pass: {}",
            repair::report_fields(&second)
        ));
        return Err(format!(
            "the repaired copy is NOT idempotent (a second dry run reported work) — \
             the target was never touched; inspect {}",
            tmp.display()
        ));
    }

    out(&format!(
        "repair dry run: temp dir (left on disk for inspection): {}",
        tmp.display()
    ));
    Ok(())
}

/// `--apply`: the guarded write step. Verified backup under
/// `<target>\pre-repair-backups\` FIRST, then the whole repair in ONE
/// transaction, then integrity + idempotence checks. Any failure
/// rolls back — the store is unchanged since the backup.
fn run_apply_mode(
    target: &Path,
    conn: &Connection,
    store_key: &StoreKey,
    own_uid: Option<&str>,
    out: &mut dyn FnMut(&str),
) -> Result<(), String> {
    // Precondition: the verified backup, into
    // <target>\pre-repair-backups\ — made BEFORE the first write; a
    // backup or verify failure stops the run here.
    let backup_dir = target.join("pre-repair-backups");
    let mut now = schema::now_ms();
    // The stamp resolves to one second: a re-run inside the same
    // second would collide with the previous backup's file names —
    // bump until the stamp is free (each run gets its own backup set,
    // the same loop as import).
    while backup::backup_db_path(&backup_dir, now).exists() {
        now += 1_000;
    }
    let manifest = backup::backup_db(conn, &store_key.backup_key(), &backup_dir, now)
        .map_err(|k| format!("pre-repair backup failed ({k}) — no writes were performed"))?;
    let backup_path = backup::backup_db_path(&backup_dir, now);
    backup::verify_backup(&backup_path, &store_key.backup_key(), &manifest)
        .map_err(|k| format!("pre-repair backup verify failed ({k}) — no writes were performed"))?;
    let manifest_path = backup_path.with_extension("json");
    out(&format!(
        "repair apply: backup OK: {} (verified: sha+integrity+counts)",
        manifest_path.display()
    ));

    out("== counts before ==");
    for l in repair::counts_lines(conn) {
        out(&l);
    }

    // The whole repair in ONE transaction — deliberate: the store is
    // small (hundreds of rows to tens of thousands), so BEGIN
    // IMMEDIATE holds the write lock only for a short, bounded
    // repair; no batching, and any step error rolls EVERYTHING back
    // to the state the backup just captured.
    if let Err(e) = conn.execute_batch("BEGIN IMMEDIATE") {
        return Err(format!("BEGIN IMMEDIATE failed: {}", sqlite_kind(&e)));
    }
    let report = match repair::repair_v1_checked(conn, own_uid) {
        Ok(r) => r,
        Err(e) => {
            // ROLLBACK either way: if the failed statement already
            // aborted the transaction the ROLLBACK is a no-op (one
            // best-effort retry for the odd state); either way the
            // store is exactly the state the backup captured.
            if conn.execute_batch("ROLLBACK").is_err() {
                let _ = conn.execute_batch("ROLLBACK");
            }
            out(&format!(
                "repair failed at step {} ({}) — rolled back, store unchanged since \
                 the backup",
                e.step, e.kind
            ));
            return Err(format!(
                "step {} failed ({}) — rolled back, store unchanged since the backup: {}",
                e.step,
                e.kind,
                manifest_path.display()
            ));
        }
    };
    if let Err(e) = conn.execute_batch("COMMIT") {
        let _ = conn.execute_batch("ROLLBACK");
        return Err(format!(
            "COMMIT failed: {} — rolled back, store unchanged since the backup: {}",
            sqlite_kind(&e),
            manifest_path.display()
        ));
    }

    // Post-commit integrity: a bad verdict points at the backup (the
    // repair IS committed — restoring is the user's call).
    let integrity: String = conn
        .query_row("PRAGMA integrity_check;", [], |r| r.get(0))
        .map_err(|e| format!("integrity_check failed: {}", sqlite_kind(&e)))?;
    if integrity != "ok" {
        return Err(format!(
            "integrity_check is not ok after the repair (first row: {integrity:?}) — the \
             repair IS committed; restore from the pre-repair backup: {}",
            manifest_path.display()
        ));
    }
    out("repair apply: integrity_check=ok");
    let cipher: String = conn
        .query_row("PRAGMA cipher_integrity_check", [], |r| r.get(0))
        .unwrap_or_else(|_| "not supported".into());
    out(&format!("repair apply: cipher_integrity_check={cipher}"));

    out("== counts after ==");
    for l in repair::counts_lines(conn) {
        out(&l);
    }

    // Idempotence: a second dry run must report all zeros.
    let second = repair::repair_v1_dry_run_checked(conn, own_uid).map_err(|e| {
        format!(
            "the idempotence dry run failed at step {} ({}) — the repair IS committed; \
             the pre-repair backup is at {}",
            e.step,
            e.kind,
            manifest_path.display()
        )
    })?;
    if second == repair::RepairReport::default() {
        out("report: all zeros (idempotent)");
    } else {
        out(&format!(
            "report: NOT idempotent — second pass: {}",
            repair::report_fields(&second)
        ));
        return Err(format!(
            "the repaired store is NOT idempotent (a second dry run reported work) — the \
             repair IS committed; restore from the pre-repair backup: {}",
            manifest_path.display()
        ));
    }

    out(&format!("report: {}", repair::report_fields(&report)));
    Ok(())
}

// --- helpers ---------------------------------------------------------------

/// Log-safe io error kind (H-rule — the backup.rs shape).
fn io_kind(e: &std::io::Error) -> String {
    format!("{:?}", e.kind())
}

/// A NEW temp dir for one dry run (`std::env::temp_dir()`, never
/// under the target). Left on disk; its path is printed.
fn new_temp_dir() -> Result<PathBuf, String> {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "zr-repair-dry-{}-{}-{}",
        std::process::id(),
        schema::now_ms(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).map_err(|e| format!("temp dir: {}", io_kind(&e)))?;
    Ok(dir)
}

/// Byte-copy the store's DB file set (`default.db` + `-wal`/`-shm`
/// when present — the probe_util copy set minus the key/mode files:
/// the key that opened the target opens the copy, no second DPAPI
/// read, and no key material ever lands in the temp dir).
fn copy_store_files(target: &Path, dest: &Path) -> Result<(), String> {
    let db = db_file(target);
    let mut from = vec![db.clone()];
    for suffix in ["-wal", "-shm"] {
        let name = format!("{}{suffix}", db.file_name().unwrap().to_string_lossy());
        from.push(target.join(name));
    }
    for f in from {
        if !f.exists() {
            continue; // -wal/-shm are absent on a checkpointed store
        }
        let to = dest.join(f.file_name().unwrap());
        std::fs::copy(&f, &to).map_err(|e| format!("copy: {}", io_kind(&e)))?;
        // A copy can inherit the source's read-only attribute; clear
        // it so SQLite can open the copy read-write.
        if let Ok(meta) = std::fs::metadata(&to) {
            let mut perm = meta.permissions();
            #[allow(clippy::permissions_set_readonly_false)]
            perm.set_readonly(false);
            let _ = std::fs::set_permissions(&to, perm);
        }
    }
    Ok(())
}

/// Open a byte copy / an exported backup of the target with the SAME
/// key that opened the target (identical bytes, identical key — never
/// a second DPAPI unwrap, never a password prompt). Kind-only errors.
fn open_with_store_key(
    path: &Path,
    key: &StoreKey,
    readonly: bool,
) -> Result<Connection, String> {
    let kind = |e: &sqlcipher::KeyError| -> String {
        match e {
            sqlcipher::KeyError::Io(_) => "io".into(),
            sqlcipher::KeyError::Db(_) => "db".into(),
            sqlcipher::KeyError::WrongPassword => "wrong-password".into(),
        }
    };
    match key {
        StoreKey::Raw(k) => {
            sqlcipher::open_with_key_opts(path, k, readonly).map_err(|e| kind(&e))
        }
        StoreKey::Passphrase(p) => {
            sqlcipher::open_with_passphrase_opts(path, p, readonly).map_err(|e| kind(&e))
        }
    }
}

#[cfg(test)]
mod tests {
    //! Synthetic stores ONLY — every fixture lives under the OS temp
    //! dir; the real store (`D:\ZaloRust Data\…`) and the snapshot are
    //! never touched (the hard rule). The process probe is INJECTED,
    //! so no test ever consults the real process table; the own uid is
    //! injected through `run_with_own_uid`, so no test ever reads the
    //! process env or the real settings file.

    use super::*;
    use super::super::key_file;
    use crate::migrate::sqlcipher;
    use std::path::Path;
    use zeroize::Zeroizing;

    /// A fake own uid of the documented shape (never a real one).
    const FAKE_UID: &str = "1234567890123456789";

    /// R3 (batch 21): remove a temp dir when the guard drops — even
    /// when an assert fails mid-test. The PRODUCTION dry run still
    /// leaves its `zr-repair-dry-*` dir on purpose (documented); the
    /// TESTS clean up every dir they cause.
    struct TempDirGuard(PathBuf);

    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The temp dir a dry run printed (its "left on disk for
    /// inspection" line), as a guard — `None` when the run refused
    /// before making one (nothing to clean).
    fn dry_tmp_of(lines: &[String]) -> Option<TempDirGuard> {
        lines
            .iter()
            .find_map(|l| {
                l.strip_prefix("repair dry run: temp dir (left on disk for inspection): ")
            })
            .map(|p| TempDirGuard(PathBuf::from(p)))
    }

    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    /// A fresh unique temp dir (synthetic fixtures only).
    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zr-repair-cli-{tag}-{}-{}-{}",
            std::process::id(),
            schema::now_ms(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn sha256_file(path: &Path) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(std::fs::read(path).unwrap());
        format!("{:x}", h.finalize())
    }

    // --- the fixture: a raw-key store with the legacy v1 defects ---

    /// Seed the legacy v1 defects the repair exists for: an orphan
    /// conv (cB), a stale last_msg pointer + NULL content_hash rows
    /// + an old type code + a self-sent NULL sender (cA), and a
    /// ping-pong revision pair (cR). All ids/values are FAKE.
    fn seed_legacy(conn: &Connection) {
        // cA: a conversation whose pointers name the OLDER message.
        conn.execute(
            "INSERT INTO conversations (id, type, unread, updated_at, last_msg_id, last_ts)
             VALUES ('cA', 0, 0, 1, 'a2', 100)",
            [],
        )
        .unwrap();
        // cR: a conversation with no pointers at all.
        conn.execute(
            "INSERT INTO conversations (id, type, unread, updated_at)
             VALUES ('cR', 0, 0, 1)",
            [],
        )
        .unwrap();
        // A v1-era row: stored type 7 (old code) although the payload
        // says msgType text (table code 1); content_hash NULL.
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, rev, deleted, source)
             VALUES ('a1','cA',NULL,300,7,NULL,?1,0,0,'capture')",
            rusqlite::params![
                r#"{"msgId":"a1","uidFrom":"u9","idTo":"cA","ts":300,"msgType":"text","content":"x"}"#
            ],
        )
        .unwrap();
        // a2: clean shape, still NULL content_hash (the v1 legacy).
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, rev, deleted, source)
             VALUES ('a2','cA',NULL,100,1,NULL,?1,0,0,'capture')",
            rusqlite::params![
                r#"{"msgId":"a2","uidFrom":"u9","idTo":"cA","ts":100,"msgType":"text","content":"y"}"#
            ],
        )
        .unwrap();
        // s1: self-sent (uidFrom '0'), sender stuck at NULL (H4-b).
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, rev, deleted, source)
             VALUES ('s1','cA',NULL,400,1,NULL,?1,0,0,'capture')",
            rusqlite::params![
                r#"{"msgId":"s1","uidFrom":"0","idTo":"cA","ts":400,"msgType":"text","content":"me"}"#
            ],
        )
        .unwrap();
        // a3: an ORPHAN — conv cB has no conversations row.
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, rev, deleted, source)
             VALUES ('a3','cB',NULL,50,1,NULL,?1,0,0,'capture')",
            rusqlite::params![
                r#"{"msgId":"a3","uidFrom":"u9","idTo":"cB","ts":50,"msgType":"text","content":"z"}"#
            ],
        )
        .unwrap();
        // p1 (cR): current payload content "v2", rev inflated to 5.
        let p1 =
            r#"{"msgId":"p1","uidFrom":"u1","idTo":"cR","ts":500,"msgType":"text","content":"v2"}"#;
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, content_hash, rev, deleted, source)
             VALUES ('p1','cR','u1',500,1,'v2',?1,?2,5,0,'capture')",
            rusqlite::params![p1, writer_hash(p1)],
        )
        .unwrap();
        // rev1: representation-only ping-pong (SAME content, other key
        // order — canonical hashing must see through it): pruned.
        conn.execute(
            "INSERT INTO message_revisions (msg_id, rev, ts, kind, payload_json)
             VALUES ('p1',1,1,'edit',?1)",
            rusqlite::params![
                r#"{"content":"v2","msgType":"text","idTo":"cR","uidFrom":"u1","ts":500,"msgId":"p1"}"#
            ],
        )
        .unwrap();
        // rev2: a REAL edit (different content) — kept.
        conn.execute(
            "INSERT INTO message_revisions (msg_id, rev, ts, kind, payload_json)
             VALUES ('p1',2,1,'edit',?1)",
            rusqlite::params![
                r#"{"msgId":"p1","uidFrom":"u1","idTo":"cR","ts":500,"msgType":"text","content":"v1"}"#
            ],
        )
        .unwrap();
    }

    /// The writer's digest for a payload (fixture helper).
    fn writer_hash(payload: &str) -> String {
        super::super::writer::content_hash(payload).unwrap()
    }

    /// A synthetic RAW-mode shadow store (default.db + the DPAPI key
    /// file `passphrase::open_store` expects) with the legacy defects
    /// seeded. Never a real store dir.
    fn fixture_store(tag: &str) -> PathBuf {
        let dir = temp_dir(tag);
        let key = Zeroizing::new(sqlcipher::generate_key().unwrap());
        sqlcipher::save_key(&key, &key_file(&dir)).unwrap();
        {
            let conn = sqlcipher::open_with_key(&db_file(&dir), &key).unwrap();
            schema::apply(&conn).unwrap();
            seed_legacy(&conn);
        }
        dir
    }

    /// Open a fixture store read-write (assertions after a run).
    fn open_rw(dir: &Path) -> Connection {
        let key = Zeroizing::new(sqlcipher::load_key(&key_file(dir)).unwrap());
        sqlcipher::open_with_key(&db_file(dir), &key).unwrap()
    }

    /// The expected report line for the seeded defects.
    const SEEDED_REPORT: &str = "report: conv_stubs_created=1 last_msg_fixed=3 \
content_hash_filled=4 types_remapped=1 senders_backfilled=1 revisions_pruned=1 revs_reset=1";

    fn dry_args(target: &Path) -> RepairArgs {
        RepairArgs {
            target: target.to_path_buf(),
            dry_run: true,
            apply: false,
            own_uid_from_settings: false,
            i_have_a_backup_plan: false,
            help: false,
        }
    }

    fn apply_args(target: &Path) -> RepairArgs {
        RepairArgs {
            target: target.to_path_buf(),
            dry_run: false,
            apply: true,
            own_uid_from_settings: false,
            i_have_a_backup_plan: true,
            help: false,
        }
    }

    /// Run with a Vec sink (what the CLI's println sink does) and the
    /// injected probe; the lines are KEPT even on Err (streamed
    /// output, the F3 property).
    fn run_collect(
        a: &RepairArgs,
        own_uid: Option<&str>,
        z: impl Fn() -> Option<bool>,
    ) -> (Result<(), String>, Vec<String>) {
        let mut lines: Vec<String> = Vec::new();
        let r = run_with_own_uid(a, own_uid, &mut |l: &str| lines.push(l.to_string()), z);
        (r, lines)
    }

    // --- parse ------------------------------------------------------------

    #[test]
    fn parse_full_invocations_both_modes() {
        let a = parse(&args(&["--target", r"D:\shadow", "--dry-run"])).unwrap();
        assert_eq!(a.target, PathBuf::from(r"D:\shadow"));
        assert!(a.dry_run && !a.apply && !a.help);
        // No mode flag at all: dry run (the default).
        let a = parse(&args(&["--target", r"D:\shadow"])).unwrap();
        assert!(!a.apply && !a.dry_run, "no --dry-run/--apply means dry-run");
        // The apply mode with its full precondition set + the uid flag.
        let a = parse(&args(&[
            "--target",
            r"D:\shadow",
            "--apply",
            "--i-have-a-backup-plan",
            "--own-uid-from-settings",
        ]))
        .unwrap();
        assert!(a.apply && a.i_have_a_backup_plan && a.own_uid_from_settings);
        // A single-dash value is a value like any other (the cli.rs
        // rule: only a `--` prefix counts as a missing value).
        let a = parse(&args(&["--target", "-weird-dir"])).unwrap();
        assert_eq!(a.target, PathBuf::from("-weird-dir"));
    }

    #[test]
    fn parse_target_is_required_in_both_modes() {
        let e = parse(&args(&[])).unwrap_err();
        assert!(e.contains("missing required --target"), "{e}");
        // Required with --apply too — and the apply gates run first,
        // so the missing --target surfaces once they are satisfied.
        let e = parse(&args(&["--apply", "--i-have-a-backup-plan"])).unwrap_err();
        assert!(e.contains("missing required --target"), "{e}");
        // Value-flag shape errors.
        let e = parse(&args(&["--target"])).unwrap_err();
        assert!(e.contains("--target requires a value"), "{e}");
        let e = parse(&args(&["--target", "--apply"])).unwrap_err();
        assert!(e.contains("--target requires a value"), "{e}");
    }

    #[test]
    fn parse_conflicts_and_mode_gating() {
        for order in [&["--dry-run", "--apply"] as &[&str], &["--apply", "--dry-run"]] {
            let e = parse(&args(order)).unwrap_err();
            assert!(e.contains("mutually exclusive"), "{e}");
        }
        // The conflict beats the precondition checks (and --help).
        let e = parse(&args(&["--apply", "--dry-run", "--i-have-a-backup-plan"])).unwrap_err();
        assert!(e.contains("mutually exclusive"), "{e}");
        let e = parse(&args(&["--apply"])).unwrap_err();
        assert!(e.contains("--apply needs --i-have-a-backup-plan"), "{e}");
        let e = parse(&args(&["--i-have-a-backup-plan"])).unwrap_err();
        assert!(e.contains("--i-have-a-backup-plan is an --apply-mode flag"), "{e}");
        let e = parse(&args(&["--target", r"D:\s", "--i-have-a-backup-plan"])).unwrap_err();
        assert!(e.contains("--apply-mode flag"), "{e}");
    }

    #[test]
    fn parse_duplicates_and_unknown_args() {
        for flags in [
            vec!["--target", "a", "--target", "b"],
            vec!["--dry-run", "--dry-run"],
            vec!["--apply", "--apply", "--i-have-a-backup-plan"],
            vec!["--apply", "--i-have-a-backup-plan", "--i-have-a-backup-plan"],
            vec!["--own-uid-from-settings", "--own-uid-from-settings"],
            vec!["--help", "--help"],
        ] {
            let e = parse(&args(&flags)).unwrap_err();
            assert!(e.contains("given twice"), "{flags:?} -> {e}");
        }
        let e = parse(&args(&["--bogus"])).unwrap_err();
        assert!(e.contains("unknown argument --bogus"), "{e}");
    }

    #[test]
    fn parse_help_short_circuits_but_conflicts_win() {
        let a = parse(&args(&["--help"])).unwrap();
        assert!(a.help);
        let a = parse(&args(&["--help", "--target", r"D:\s"])).unwrap();
        assert!(a.help);
        // A consistent apply invocation yields to help…
        let a = parse(&args(&[
            "--help", "--target", r"D:\s", "--apply", "--i-have-a-backup-plan",
        ]))
        .unwrap();
        assert!(a.help);
        // …but a conflicting pair is still an error.
        let e = parse(&args(&["--help", "--dry-run", "--apply"])).unwrap_err();
        assert!(e.contains("mutually exclusive"), "{e}");
    }

    // --- preconditions 1-2 (the probe + the store file) -------------------

    #[test]
    fn run_refuses_when_another_zalors_runs_or_the_probe_fails() {
        // The refusal fires BEFORE the target is even looked at, so a
        // bogus path keeps this first part tiny…
        let a = dry_args(Path::new(r"D:\no\such\store"));
        let (r, _) = run_collect(&a, None, || Some(true));
        let e = r.unwrap_err();
        assert!(e.contains("another zalors.exe process is running"), "{e}");
        assert!(e.contains("one writer"), "{e}");
        let (r, _) = run_collect(&a, None, || None);
        let e = r.unwrap_err();
        assert!(e.contains("cannot verify"), "{e}");
        assert!(e.contains("tasklist failed"), "{e}");
        // …but a REAL fixture store proves nothing was written, in
        // both modes.
        let store = fixture_store("procs");
        let before = sha256_file(&db_file(&store));
        let a = apply_args(&store);
        let (r, _) = run_collect(&a, Some(FAKE_UID), || Some(true));
        assert!(r.unwrap_err().contains("another zalors.exe"), "apply mode too");
        assert_eq!(sha256_file(&db_file(&store)), before, "nothing written");
        assert!(!store.join("pre-repair-backups").exists());
        let _ = std::fs::remove_dir_all(&store);
    }

    #[test]
    fn run_refuses_a_missing_store_file_and_a_locked_passphrase_store() {
        // A dir with no default.db at all.
        let dir = temp_dir("nodb");
        let a = dry_args(&dir);
        let (r, _) = run_collect(&a, None, || Some(false));
        let e = r.unwrap_err();
        assert!(e.contains("--target: no "), "{e}");
        assert!(e.contains("default.db"), "{e}");

        // A passphrase-mode store without a remember file: the Locked
        // refusal (a passphrase fixture helper exists — `write_marker`;
        // the refusal fires before any DB open, so the marker alone is
        // the fixture). The CLI never accepts a password.
        let store = fixture_store("locked");
        passphrase::write_marker(&store, schema::now_ms()).unwrap();
        let a = dry_args(&store);
        let (r, _) = run_collect(&a, None, || Some(false));
        let e = r.unwrap_err();
        assert!(e.contains("password-protected (passphrase mode)"), "{e}");
        assert!(e.contains("never accepts passwords"), "{e}");
        assert!(e.contains("Nhớ trên máy này"), "{e}");
        let a = apply_args(&store);
        let (r, _) = run_collect(&a, None, || Some(false));
        assert!(r.unwrap_err().contains("passphrase mode"), "apply mode too");
        let _ = std::fs::remove_dir_all(&store);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- precondition 4 (the schema-version gate) -------------------------

    #[test]
    fn schema_mismatch_refuses_before_any_backup() {
        let store = fixture_store("schemav");
        let older = schema::VERSION - 1;
        {
            let conn = open_rw(&store);
            conn.execute_batch(&format!(
                "DELETE FROM schema_meta;
                 INSERT INTO schema_meta (version, applied_at) VALUES ({older}, 1);"
            ))
            .unwrap();
        }
        let before = sha256_file(&db_file(&store));
        // Apply mode: refused BEFORE the backup — zero writes, no
        // pre-repair-backups dir is created.
        let a = apply_args(&store);
        let (r, _) = run_collect(&a, Some(FAKE_UID), || Some(false));
        let e = r.unwrap_err();
        assert!(
            e.contains(&format!(
                "target schema v{older}, this binary expects v{}",
                schema::VERSION
            )),
            "{e}"
        );
        assert!(e.contains("open the store once with the matching zalors build"), "{e}");
        assert!(
            !store.join("pre-repair-backups").exists(),
            "the refusal precedes the backup"
        );
        // Dry mode: the same refusal, and the target's bytes never move.
        let a = dry_args(&store);
        let (r, _) = run_collect(&a, None, || Some(false));
        assert!(r.unwrap_err().contains(&format!("target schema v{older}")));
        assert_eq!(sha256_file(&db_file(&store)), before, "no writes");
        let _ = std::fs::remove_dir_all(&store);
    }

    // --- the dry run -------------------------------------------------------

    #[test]
    fn dry_run_reports_the_defects_and_never_touches_the_target() {
        let store = fixture_store("dryrun");
        let _store_guard = TempDirGuard(store.clone());
        let before = sha256_file(&db_file(&store));

        let a = dry_args(&store);
        let (r, lines) = run_collect(&a, Some(FAKE_UID), || Some(false));
        // R3: guards bind BEFORE the asserts (a failed run still
        // cleans up its `zr-repair-dry-*` dir), and the dry run's dir
        // is the one dir the run leaves on purpose — the TEST removes it.
        let _tmp_guard = dry_tmp_of(&lines);
        r.unwrap();
        let joined = lines.join("\n");

        // The target's bytes are identical — read-only open only, and
        // no backup dir under the target.
        assert_eq!(sha256_file(&db_file(&store)), before, "the target's bytes must not change");
        assert!(!store.join("pre-repair-backups").exists());

        // The own uid is never printed — only `own_uid set: true`.
        assert!(joined.contains("own_uid set: true"), "{joined}");
        assert!(!joined.contains(FAKE_UID), "the uid itself never prints");

        // The report matches the seeded defects exactly (one counter
        // per field).
        assert!(joined.contains(SEEDED_REPORT), "{joined}");

        // Counts before/after bracket the repair on the copy.
        assert!(joined.contains("messages=5 conversations=2 revisions=2"), "{joined}");
        assert!(joined.contains("self_sent_sender_null=1 msgs_without_conv_row=1"), "{joined}");
        assert!(joined.contains("messages=5 conversations=3 revisions=1"), "{joined}");

        // The verified backup + integrity + idempotence lines.
        assert!(joined.contains("repair dry run: verified backup OK: "), "{joined}");
        assert!(joined.contains("integrity_check=ok"), "{joined}");
        assert!(joined.contains("report: all zeros (idempotent)"), "{joined}");

        // The temp copy exists (left on disk, its path printed) and
        // carries the repair; the target still does NOT.
        let tmp = lines
            .iter()
            .find_map(|l| {
                l.strip_prefix("repair dry run: temp dir (left on disk for inspection): ")
            })
            .unwrap();
        let tmp = PathBuf::from(tmp);
        assert!(tmp.is_dir(), "{tmp:?}");
        assert!(
            tmp.starts_with(std::env::temp_dir()),
            "never under the target: {tmp:?}"
        );
        let manifest_line = lines
            .iter()
            .find(|l| l.starts_with("repair dry run: verified backup OK: "))
            .unwrap();
        let manifest_path = PathBuf::from(
            manifest_line
                .trim_start_matches("repair dry run: verified backup OK: ")
                .trim_end_matches(" (verified: sha+integrity+counts)"),
        );
        assert!(manifest_path.is_file(), "{manifest_path:?}");
        {
            let repaired = manifest_path.with_extension("db");
            assert!(repaired.is_file(), "{repaired:?}");
            let key = Zeroizing::new(sqlcipher::load_key(&key_file(&store)).unwrap());
            let conn = sqlcipher::open_with_key_readonly(&repaired, &key).unwrap();
            let stubs: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM conversations WHERE id='cB'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(stubs, 1, "the copy was repaired");
            let sender: Option<String> = conn
                .query_row(
                    "SELECT sender_id FROM messages WHERE msg_id='s1'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(sender.as_deref(), Some(FAKE_UID), "the backfill landed on the copy");
        }
        {
            let conn = open_rw(&store);
            let (stubs, sender): (i64, Option<String>) = conn
                .query_row(
                    "SELECT (SELECT COUNT(*) FROM conversations WHERE id='cB'),
                            (SELECT sender_id FROM messages WHERE msg_id='s1')",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert_eq!(stubs, 0, "the target was NOT repaired");
            assert_eq!(sender, None, "the target's rows are untouched");
        }
    }

    #[test]
    fn dry_run_without_own_uid_skips_step_e() {
        let store = fixture_store("nouid");
        let _store_guard = TempDirGuard(store.clone());
        let a = dry_args(&store);
        let (r, lines) = run_collect(&a, None, || Some(false));
        let _tmp_guard = dry_tmp_of(&lines);
        r.unwrap();
        let joined = lines.join("\n");
        assert!(joined.contains("own_uid set: false"), "{joined}");
        assert!(joined.contains("SKIPPED — no own uid"), "{joined}");
        // Step (e) is the only step gated on the uid: everything else
        // still reports.
        assert!(joined.contains("senders_backfilled=0"), "{joined}");
        assert!(joined.contains("conv_stubs_created=1"), "{joined}");
        assert!(joined.contains("revisions_pruned=1"), "{joined}");
        assert!(joined.contains("report: all zeros (idempotent)"), "{joined}");
    }

    // --- the apply ---------------------------------------------------------

    #[test]
    fn apply_end_to_end_verified_backup_and_idempotent_rerun() {
        let store = fixture_store("apply");
        let a = apply_args(&store);
        let (r, lines) = run_collect(&a, Some(FAKE_UID), || Some(false));
        r.unwrap();
        let joined = lines.join("\n");

        // The verified backup exists under <target>\pre-repair-backups.
        let manifest_path = lines
            .iter()
            .find(|l| l.starts_with("repair apply: backup OK: "))
            .unwrap()
            .trim_start_matches("repair apply: backup OK: ")
            .trim_end_matches(" (verified: sha+integrity+counts)")
            .to_string();
        let manifest_path = PathBuf::from(manifest_path);
        assert!(manifest_path.is_file(), "{manifest_path:?}");
        assert!(
            manifest_path.to_string_lossy().contains("pre-repair-backups"),
            "{manifest_path:?}"
        );
        assert!(manifest_path.with_extension("db").is_file());

        // The report counters match the seeds; the second dry run (the
        // idempotence probe) is all zeros.
        assert!(joined.contains(SEEDED_REPORT), "{joined}");
        assert!(joined.contains("report: all zeros (idempotent)"), "{joined}");
        assert!(joined.contains("integrity_check=ok"), "{joined}");
        assert!(joined.contains("own_uid set: true"), "{joined}");
        assert!(!joined.contains(FAKE_UID), "the uid itself never prints");

        // The store itself: repaired rows.
        {
            let conn = open_rw(&store);
            let (sender, rev, stubs, ty): (Option<String>, i64, i64, i64) = conn
                .query_row(
                    "SELECT (SELECT sender_id FROM messages WHERE msg_id='s1'),
                            (SELECT rev FROM messages WHERE msg_id='p1'),
                            (SELECT COUNT(*) FROM conversations WHERE id='cB'),
                            (SELECT type FROM messages WHERE msg_id='a1')",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .unwrap();
            assert_eq!(sender.as_deref(), Some(FAKE_UID), "the self-sent backfill");
            assert_eq!(rev, 1, "rev = the remaining real edit");
            assert_eq!(stubs, 1, "the orphan conv got its stub");
            assert_eq!(ty, 1, "the old type code was remapped");
        }

        // A re-run reports ALL ZEROS and still makes its OWN backup
        // (a second manifest set exists).
        let (r2, lines2) = run_collect(&a, Some(FAKE_UID), || Some(false));
        r2.unwrap();
        let joined2 = lines2.join("\n");
        assert!(
            joined2.contains(
                "report: conv_stubs_created=0 last_msg_fixed=0 content_hash_filled=0 \
                 types_remapped=0 senders_backfilled=0 revisions_pruned=0 revs_reset=0"
            ),
            "{joined2}"
        );
        assert!(joined2.contains("report: all zeros (idempotent)"), "{joined2}");
        let manifests = std::fs::read_dir(store.join("pre-repair-backups"))
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
            .count();
        assert_eq!(manifests, 2, "each apply run makes its own backup set");
        let _ = std::fs::remove_dir_all(&store);
    }

    #[test]
    fn apply_step_failure_rolls_back_to_the_pre_run_state() {
        let store = fixture_store("errpath");
        // Force a LATER step to fail: drop the revisions table after
        // the seeds are in — steps (a)-(e) do work inside the
        // transaction, then step (f)'s prepare fails, and ALL of it
        // must roll back.
        {
            let conn = open_rw(&store);
            conn.execute_batch("DROP TABLE message_revisions;").unwrap();
        }
        // The pre-run state over every table the repair touches (the
        // dropped table cannot be counted; nothing else touches it).
        let state = |dir: &Path| -> (i64, i64, i64, i64, i64, i64) {
            let conn = open_rw(dir);
            conn.query_row(
                "SELECT (SELECT COUNT(*) FROM conversations),
                        (SELECT COUNT(*) FROM conversations WHERE last_msg_id IS NOT NULL),
                        (SELECT COUNT(*) FROM messages WHERE content_hash IS NULL),
                        (SELECT COALESCE(SUM(type), 0) FROM messages),
                        (SELECT COUNT(*) FROM messages WHERE sender_id IS NULL),
                        (SELECT COALESCE(SUM(rev), 0) FROM messages)",
                [],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                    ))
                },
            )
            .unwrap()
        };
        let before = state(&store);

        let a = apply_args(&store);
        let (r, lines) = run_collect(&a, Some(FAKE_UID), || Some(false));
        let e = r.unwrap_err();
        assert!(e.contains("rev_prune"), "the step is named: {e}");
        assert!(e.contains("rolled back, store unchanged since the backup"), "{e}");
        let joined = lines.join("\n");
        // The streamed failure line: the step name + kind, the exact
        // brief wording. A backup exists (made before the first write).
        assert!(joined.contains("repair failed at step rev_prune ("), "{joined}");
        assert!(
            joined.contains("— rolled back, store unchanged since the backup"),
            "{joined}"
        );
        assert!(joined.contains("repair apply: backup OK: "), "{joined}");
        // The data rows equal the pre-run state: the transaction (and
        // with it every earlier step's work) rolled back.
        assert_eq!(state(&store), before, "rolled back to the pre-run state");
        let _ = std::fs::remove_dir_all(&store);
    }

    // --- the real entry's own-uid plumbing ---------------------------------

    #[test]
    fn run_the_real_entry_resolves_the_uid_and_completes() {
        // `run` (the real entry) resolves the own uid itself through
        // `import::resolve_own_uid`; whatever uid this machine
        // provides, the dry run completes with the invariant lines —
        // and the uid value itself is never in the output.
        let store = fixture_store("realrun");
        let _store_guard = TempDirGuard(store.clone());
        let a = dry_args(&store);
        let mut lines: Vec<String> = Vec::new();
        let r = run(&a, &mut |l: &str| lines.push(l.to_string()), || Some(false));
        let _tmp_guard = dry_tmp_of(&lines);
        r.unwrap();
        let joined = lines.join("\n");
        assert!(
            joined.contains("own_uid set: true") || joined.contains("own_uid set: false"),
            "{joined}"
        );
        assert!(joined.contains("repair dry run: verified backup OK: "), "{joined}");
        assert!(joined.contains("report: all zeros (idempotent)"), "{joined}");
    }
}
