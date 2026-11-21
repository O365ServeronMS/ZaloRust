//! `--apply` — P2 item 2.5 (batch 16): the user-approved write step of
//! the Desktop import. Everything before this batch was dry-run only;
//! this module is the ONLY code path that writes into a shadow store,
//! and it refuses to run unless every precondition holds.
//!
//! Preconditions (audit §4 item 2.5, all enforced in code, each with
//! a test; a refusal exits non-zero with a clear message):
//! 1. `--apply` AND the explicit second flag `--i-have-a-backup-plan`
//!    AND `--target <shadow store dir>` — the target has NO default
//!    to the live path; the user passes it.
//! 2. The app must not be running: refuse if any process named
//!    `zalors.exe` other than the current process exists (exact name
//!    match, current PID excluded — the store has one writer, A5).
//!    A check that cannot run also refuses (fail closed).
//! 3. Before the first write: `backup::backup_db` of the target into
//!    `<target>\pre-import-backups\` + `verify_backup` must succeed;
//!    the manifest path is printed.
//! 4. The mapping `plan` must be clean, and every msgType code that
//!    occurs in the snapshot must be mapped (the batch-15 all-DB
//!    distinct aggregation over every mapped message DB). Unmapped
//!    media codes would store their JSON content as message text, so
//!    without the hatch the apply REFUSES and lists the codes with
//!    per-code counts. The ONE escape hatch is `--unmapped-as-raw`:
//!    unmapped rows are written kind=100 with `text` forced NULL
//!    (content kept only in payload_json, raw code string included) —
//!    never JSON-as-text.
//! 5. Rows whose `uidFrom` is NULL (not "0") that received the
//!    own-uid substitution via `normalize::sender_for` are counted
//!    and printed as a number — the shared rule treats NULL as self,
//!    and that rule is NOT changed here; the count is the reviewer's
//!    input for deciding whether it should be.
//!
//! Write path: extract → `writer::apply` with `source='import'`
//! inside batches of 500 rows per `BEGIN IMMEDIATE … COMMIT`, each
//! row isolated by the pipeline-style SAVEPOINT so one bad row never
//! aborts the batch (errors are counted + kind-logged), and the
//! per-DB `sync_cursors` row is written in the SAME transaction as
//! its batch — a killed run resumes exactly where it stopped.
//! Import precedence is the writer's own guard (import only fills
//! NULL cells of capture/e2ee rows, never replaces their
//! text/payload/type), reinforced here: writes classified `Ignored`
//! are skipped outright, so a second full apply changes 0 rows
//! (`total_changes()` delta == 0, measured after the backup so the
//! backup export itself never pollutes the idempotence number).
//!
//! Everything prints counts, kinds and user-passed paths only — never
//! a message id, a uid, a row's file path value, or key material.
//!
//! Batch 16 fix (review F1–F4):
//! - F1: a DB that opens fine but has NO mapped table (the real
//!   snapshot has 4 such group DBs) is skipped in the census AND the
//!   write loop and counted as `dbs_no_table` — refusing on them made
//!   a real apply impossible. Any other open/read failure keeps the
//!   fail-closed behaviour.
//! - F2: the resume cursor never passes a row that was not written:
//!   per DB, the first item error, abort, cursor-write error or
//!   failed COMMIT freezes that DB's cursor for the rest of the run.
//!   The committed rows are idempotently skipped on re-run; the
//!   failed ones are re-extracted and retried.
//! - F3: output is STREAMED through a sink as it is produced (the
//!   CLI prints live), so a later failure never hides the backup
//!   path or the progress lines that already printed.
//! - F4: the target's stored schema version must equal this
//!   binary's `schema::VERSION`, checked BEFORE the backup — the
//!   import CLI never migrates a store as a side effect, and never
//!   writes into a schema it does not match.

use std::collections::BTreeMap;
use std::path::PathBuf;

use rusqlite::types::Value as SV;
use rusqlite::Connection;

use super::cli::ImportArgs;
use super::import::{self, distinct};
use super::import_map::{self, CodedWrite, ImportCursor, MapDb, Verdict};
use super::pipeline::sqlite_kind;
use super::schema;
use super::{db_file, Write};

/// Rows per write transaction (the brief's batch size).
pub const APPLY_BATCH_ROWS: usize = 500;

/// One progress line every N message DBs (counts only).
pub const PROGRESS_EVERY: usize = 25;

/// The single-writer image name (precondition 2).
const ZALORS_EXE: &str = "zalors.exe";

// --- precondition 2: the process check ------------------------------------

/// Pure: the PIDs in `tasklist /FI "IMAGENAME eq zalors.exe" /FO CSV
/// /NH` output whose image name is EXACTLY `zalors.exe` (the filter
/// already matched; the parse re-checks case-insensitively), minus
/// `own`. A line that does not carry a parsable PID is ignored — the
/// live probe's "no tasks" info line is exactly that.
pub fn tasklist_zalors_pids(csv: &str, own: u32) -> Vec<u32> {
    let mut out = Vec::new();
    for line in csv.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut fields = line.split(',');
        let Some(img) = fields.next() else { continue };
        let Some(pid) = fields.next() else { continue };
        let img = img.trim_matches('"');
        if !img.eq_ignore_ascii_case(ZALORS_EXE) {
            continue;
        }
        let Some(pid) = pid.trim_matches('"').trim().parse::<u32>().ok() else {
            continue;
        };
        if pid == own {
            continue;
        }
        out.push(pid);
    }
    out
}

/// The live probe: `Some(true)` when a `zalors.exe` besides ours runs,
/// `Some(false)` when none does, `None` when the check itself failed
/// (fail closed — the caller refuses on `None`).
pub fn zalors_running_besides(own_pid: u32) -> Option<bool> {
    let out = std::process::Command::new("tasklist")
        .args(["/FI", "IMAGENAME eq zalors.exe", "/FO", "CSV", "/NH"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let csv = String::from_utf8_lossy(&out.stdout).into_owned();
    Some(!tasklist_zalors_pids(&csv, own_pid).is_empty())
}

// --- precondition 4: the unmapped-code preflight ---------------------------

/// A source msgType value as the mapping-key string (`None` for
/// NULL/BLOB — those cannot be proven mapped). Mirrors the extractor's
/// `sv_str` semantics; kept local because that helper is private.
fn code_key(v: &SV) -> Option<String> {
    match v {
        SV::Text(s) => Some(s.clone()),
        SV::Integer(i) => Some(i.to_string()),
        SV::Real(f) => Some(f.to_string()),
        _ => None,
    }
}

/// One preflight finding: an unmapped code (rendered code-shape only)
/// and how many snapshot rows carry it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnmappedCode {
    /// The rendered code token (numbers as-is, NULL for NULL, weird
    /// TEXT as the `text(len,h12)` fingerprint — never the value).
    pub rendered: String,
    pub rows: i64,
}

/// (F1) Does the mapped table exist as a real table in this OPENED DB
/// (`sqlite_master`, `type='table'` — the only row class the plan's
/// inventory validation accepts, so a same-named VIEW does not count)?
/// The real snapshot has group DBs that open fine but carry no
/// `message` table: those are SKIPPED (counted as `dbs_no_table`) in
/// the census and the write loop — refusing on them made a real apply
/// impossible. A sqlite_master read failure is NOT an "absent table":
/// it refuses fail-closed like every other read failure.
fn mapped_table_exists(conn: &Connection, table: &str) -> Result<bool, rusqlite::Error> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        rusqlite::params![table],
        |r| r.get::<_, i64>(0),
    )
    .map(|n| n != 0)
}

/// The preflight (precondition 4): run batch 15's fixed distinct
/// aggregation (`distinct::group_counts`) on the message table's RAW
/// msgType column in EVERY DB of the mapped kinds, sum with the same
/// fold (`distinct::aggregate_counts`), and keep the codes the
/// mapping does not list. Returns the unmapped codes plus the F1
/// count of DBs skipped for having no mapped table at all. A DB that
/// cannot be opened, whose sqlite_master cannot be read, or whose
/// msgType read fails makes the whole preflight fail — "every code
/// that occurs is mapped" cannot be verified behind an unreadable
/// DB. A DB whose msgType trips the 50-distinct cap is likewise
/// refused (that column is not behaving like a code column there —
/// the batch-15 rule). A DB that opens fine but has NO mapped table
/// carries no rows: it can neither break the preflight nor
/// contribute writes, so it is skipped and counted instead of
/// failing the run.
fn unmapped_census(
    p: &import::Prepared,
    plan: &import_map::Plan,
) -> Result<(Vec<UnmappedCode>, usize), String> {
    let Some(ep) = plan.message.as_ref() else {
        return Ok((Vec::new(), 0)); // no message entity: nothing to verify
    };
    let mt_col = import_map::msg_type_column(ep)?;
    let dbs = applicable_dbs(p, plan)?;
    let mut per_db: Vec<Vec<(SV, i64)>> = Vec::new();
    let mut capped: Vec<String> = Vec::new();
    let mut no_table = 0usize;
    for db in &dbs {
        let conn = import::open_desktop_db(&db.path, p.passphrase.as_str(), p.profile)
            .map_err(|e| format!("preflight: {} open failed: {e} — refusing", db.rel))?;
        // F1: the mapped table must EXIST before anything is read; an
        // ABSENT table is a counted skip, never a refusal. The check
        // itself failing is a read failure and still refuses.
        let table = mapped_table_exists(&conn, &ep.table).map_err(|e| {
            format!("preflight: {} sqlite_master read failed: {e} — refusing", db.rel)
        })?;
        if !table {
            no_table += 1;
            continue;
        }
        let rows = distinct::group_counts(&conn, &ep.table, &mt_col)
            .map_err(|e| format!("preflight: {} msgType read failed: {e} — refusing", db.rel))?;
        if rows.len() > 50 {
            capped.push(db.rel.clone());
        }
        per_db.push(rows);
    }
    if !capped.is_empty() {
        return Err(format!(
            "preflight: the msgType column has more than 50 distinct values in {} DB(s) \
             (e.g. {}) — not a code column there; refusing",
            capped.len(),
            capped[0]
        ));
    }
    let (summed, _) = distinct::aggregate_counts(&per_db);
    let mut unmapped: Vec<UnmappedCode> = Vec::new();
    for (v, n) in summed {
        let key = code_key(&v);
        let mapped = key
            .as_ref()
            .is_some_and(|k| plan.msg_type.contains_key(k));
        if mapped {
            continue;
        }
        let rendered = match key {
            Some(_) => distinct::render_value(&v),
            None => "NULL".to_string(),
        };
        if let Some(existing) = unmapped.iter_mut().find(|u| u.rendered == rendered) {
            existing.rows += n;
        } else {
            unmapped.push(UnmappedCode { rendered, rows: n });
        }
    }
    Ok((unmapped, no_table))
}

/// The refusal/preflight lines for a non-empty unmapped set (counts
/// only; the rendered tokens went through the batch-14 renderer).
fn unmapped_lines(unmapped: &[UnmappedCode], hatch: bool) -> Vec<String> {
    let total: i64 = unmapped.iter().map(|u| u.rows).sum();
    let mut lines = Vec::new();
    if hatch {
        lines.push(format!(
            "import apply: --unmapped-as-raw: {total} row(s) will be stored kind=100 text=NULL \
             (content only in payload_json), by raw code:"
        ));
    } else {
        lines.push(format!(
            "import apply: unmapped codes: {total} row(s) carry codes the mapping does not list:"
        ));
    }
    for u in unmapped {
        lines.push(format!("import apply:   code {} x {}", u.rendered, u.rows));
    }
    lines
}

// --- the write path ---------------------------------------------------------

/// One applicable message DB of the mapping (the census and the write
/// loop enumerate EXACTLY the same set).
struct DbJob {
    /// `Core/Message/<name>` — the cursor scope suffix and the report
    /// name (a snapshot-relative path, printable per the dry-run
    /// convention).
    rel: String,
    kind: MapDb,
    db_id: Option<u64>,
    path: PathBuf,
}

fn applicable_dbs(p: &import::Prepared, plan: &import_map::Plan) -> Result<Vec<DbJob>, String> {
    let msg_dir = p.uid_dir.join("Core").join("Message");
    let mut out = Vec::new();
    for (name, kind) in import::message_db_names(&p.uid_dir)? {
        let (map_kind, db_id) = match kind {
            import::DbKind::OneToOne(id) => (MapDb::OneToOne, Some(id)),
            import::DbKind::Group(id) => (MapDb::Group, Some(id)),
            import::DbKind::StrangerBox => (MapDb::Stranger, None),
            // `undefined.db` and unknown names stay counted, skipped.
            import::DbKind::Undefined | import::DbKind::Other => continue,
        };
        if !plan
            .message
            .as_ref()
            .is_some_and(|e| e.db.contains(&map_kind))
        {
            continue;
        }
        out.push(DbJob {
            rel: format!("Core/Message/{name}"),
            kind: map_kind,
            db_id,
            path: msg_dir.join(&name),
        });
    }
    Ok(out)
}

/// Run counters (counts only — no values ever).
#[derive(Debug, Default, Clone, PartialEq)]
pub struct ApplyStats {
    pub dbs_total: usize,
    pub dbs_opened: usize,
    /// F1: DBs that opened fine but have no mapped table — skipped in
    /// the census AND the write loop, printed as `dbs_no_table=N`.
    pub dbs_no_table: usize,
    /// F2: DBs whose resume cursor froze this run after a batch error
    /// (item error, abort, cursor-write error or failed COMMIT).
    pub dbs_cursor_frozen: usize,
    pub msgs_extracted: usize,
    pub msgs_skipped: usize,
    pub msgs_applied: usize,
    pub msgs_ignored: usize,
    pub msgs_new: usize,
    pub msgs_fill_null: usize,
    pub msgs_update_import: usize,
    pub msgs_unmapped_raw: usize,
    /// Rows whose uidFrom was NULL (not "0") that received the
    /// own-uid substitution via `normalize::sender_for`. Printed as a
    /// number; the rule itself is untouched.
    pub uid_from_null_substituted: usize,
    pub conv_applied: usize,
    pub conv_ignored: usize,
    pub contact_applied: usize,
    pub contact_ignored: usize,
    pub group_applied: usize,
    pub group_ignored: usize,
    pub errors: usize,
    pub error_kinds: BTreeMap<String, usize>,
    pub own_uid_set: bool,
}

impl ApplyStats {
    fn add_error_kind(&mut self, kind: String) {
        self.errors += 1;
        *self.error_kinds.entry(kind).or_insert(0) += 1;
    }

    fn error_kinds_line(&self) -> String {
        self.error_kinds
            .iter()
            .map(|(k, n)| format!("{k} x{n}"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// One batch's successes — folded into the run stats only after the
/// batch's COMMIT landed (an aborted/rolled-back batch contributes
/// only its error facts, exactly like `pipeline::process_batch`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct BatchTally {
    applied: usize,
    ignored: usize,
    new: usize,
    fill_null: usize,
    update_import: usize,
    unmapped_raw: usize,
}

impl BatchTally {
    fn bump_verdict(&mut self, v: Verdict) {
        match v {
            Verdict::New => self.new += 1,
            Verdict::FillNull => self.fill_null += 1,
            Verdict::Ignored => self.ignored += 1,
            Verdict::UpdateImport => self.update_import += 1,
        }
    }
}

/// `pipeline::apply_item`'s exact savepoint isolation (T2/H3): a
/// failing write rolls back only itself; the rest of the batch still
/// commits. The `is_autocommit()` check after an error is the caller's.
fn apply_item(conn: &Connection, w: &Write) -> Result<&'static str, rusqlite::Error> {
    conn.execute_batch("SAVEPOINT item")?;
    match super::writer::apply(conn, w) {
        Ok(tag) => {
            conn.execute_batch("RELEASE item")?;
            Ok(tag)
        }
        Err(e) => {
            // Best-effort: if the failing statement already aborted the
            // whole transaction the savepoint is gone — the caller's
            // `is_autocommit()` check catches that case and stops the
            // batch instead of writing through in autocommit.
            let _ = conn.execute_batch("ROLLBACK TO item; RELEASE item;");
            Err(e)
        }
    }
}

/// `SELECT total_changes()` — the idempotence AC's measure, taken
/// from SQLite itself.
fn sqlite_total_changes(conn: &Connection) -> i64 {
    conn.query_row("SELECT total_changes()", [], |r| r.get(0)).unwrap_or(0)
}

/// One message batch: BEGIN IMMEDIATE → classify each write against
/// the target (skipping `Ignored` — the idempotence rule) → apply the
/// rest with per-item savepoints → write the batch's cursor in the
/// SAME transaction → COMMIT. `run_cursor` is the per-DB running
/// watermark; it only advances when the batch actually committed AND
/// its cursor was written.
///
/// F2 — the resume cursor must never pass a row that was not written:
/// `frozen` is this DB's freeze flag. The first per-item error
/// (non-abort or abort), cursor-write error or failed COMMIT sets it
/// for the REST of the DB — no further cursor advance is written, so
/// the stored watermark stays at the last fully-good batch instead of
/// silently passing the failed rows. Rows committed after the freeze
/// are idempotently skipped on re-run (classify-then-skip); the
/// failed ones are re-extracted and retried.
fn apply_message_batch(
    conn: &Connection,
    plan: &import_map::Plan,
    rel: &str,
    batch: &[CodedWrite],
    run_cursor: &mut ImportCursor,
    frozen: &mut bool,
    stats: &mut ApplyStats,
) {
    // The batch's cursor: the running watermark folded with THIS
    // batch's rows — computed up front, written inside the
    // transaction, and only folded back into `run_cursor` on COMMIT.
    let mut batch_cursor = *run_cursor;
    for cw in batch {
        batch_cursor.max_ts = batch_cursor.max_ts.max(cw.src_ts_raw);
        batch_cursor.max_rowid = batch_cursor.max_rowid.max(cw.src_rowid);
    }
    if let Err(e) = conn.execute_batch("BEGIN IMMEDIATE") {
        stats.add_error_kind(format!("begin:{}", sqlite_kind(&e)));
        // F2: the batch never ran; a later batch's cursor must not
        // pass these unwritten rows either.
        *frozen = true;
        return;
    }
    let mut tally = BatchTally::default();
    let mut aborted = false;
    // A DB frozen by an earlier batch never writes another cursor
    // advance; a NEW error in THIS batch freezes it before the
    // cursor write below.
    let mut batch_frozen = *frozen;
    for (i, cw) in batch.iter().enumerate() {
        // Classify inside the transaction (it sees this batch's own
        // earlier writes). A lookup failure skips the row fail-closed:
        // a write we cannot classify is never applied blindly.
        let verdict = match import_map::classify_write(conn, &cw.write) {
            Ok(v) => v,
            Err(_) => {
                stats.add_error_kind("lookup".into());
                // F2: this row was not written — the cursor must not
                // pass it.
                batch_frozen = true;
                if conn.is_autocommit() {
                    // F2: the transaction died on the lookup. The
                    // unprocessed remainder is counted, the successes
                    // stay rolled back, and the next batch starts fresh.
                    aborted = true;
                    for _ in (i + 1)..batch.len() {
                        stats.add_error_kind("item:aborted".into());
                    }
                    break;
                }
                continue;
            }
        };
        if verdict == Verdict::Ignored {
            tally.ignored += 1;
            continue;
        }
        match apply_item(conn, &cw.write) {
            Ok(_) => {
                tally.applied += 1;
                tally.bump_verdict(verdict);
                if !import_map::code_is_mapped(plan, cw) {
                    tally.unmapped_raw += 1;
                }
            }
            Err(e) => {
                stats.add_error_kind(format!("{}:{}", cw.write.tag(), sqlite_kind(&e)));
                // F2: this row was not written — the cursor must not
                // pass it (whether the batch commits or not).
                batch_frozen = true;
                // F2: a statement that ABORTED the transaction leaves
                // `is_autocommit()` true — the savepoint is gone and
                // every later statement would land in autocommit mode.
                // Stop the batch instead; the unprocessed remainder is
                // counted, the successes stay rolled back.
                if conn.is_autocommit() {
                    aborted = true;
                    for _ in (i + 1)..batch.len() {
                        stats.add_error_kind("item:aborted".into());
                    }
                    break;
                }
            }
        }
    }
    if aborted {
        // The transaction is already gone (that is what aborted means);
        // best-effort rollback, then the next batch starts fresh.
        let _ = conn.execute_batch("ROLLBACK");
        // F2: the aborted batch's rows were not written; later batches
        // must not advance the cursor past them.
        *frozen = true;
        return;
    }
    if batch_frozen {
        // F2: a row in this batch was not written (or the DB is
        // already frozen) — the cursor write is skipped so the
        // watermark never passes the failed row; the batch still
        // commits its good rows.
        *frozen = true;
    } else if let Err(e) = import_map::write_import_cursor_if_advanced(conn, rel, batch_cursor) {
        stats.add_error_kind(format!("cursor:{}", sqlite_kind(&e)));
        // F2: the cursor state is unknown — never advance past this.
        *frozen = true;
    }
    match conn.execute_batch("COMMIT") {
        Ok(()) => {
            stats.msgs_applied += tally.applied;
            stats.msgs_ignored += tally.ignored;
            stats.msgs_new += tally.new;
            stats.msgs_fill_null += tally.fill_null;
            stats.msgs_update_import += tally.update_import;
            stats.msgs_unmapped_raw += tally.unmapped_raw;
            if !*frozen {
                *run_cursor = batch_cursor;
            }
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK");
            stats.add_error_kind(format!("commit:{}", sqlite_kind(&e)));
            // F2: the batch (and its cursor write) rolled back — the
            // cursor must never pass it.
            *frozen = true;
        }
    }
}

/// One message DB: read the stored cursor (resume), extract with the
/// delta filter, apply the hatch to unmapped rows, then write the
/// batches. F2: the first batch error of any kind freezes this DB's
/// cursor for the rest of the call. Exposed separately so tests can
/// drive one DB directly.
#[allow(clippy::too_many_arguments)]
fn apply_message_db(
    conn: &Connection,
    src: &Connection,
    plan: &import_map::Plan,
    rel: &str,
    kind: MapDb,
    db_id: Option<u64>,
    own_uid: Option<&str>,
    batch_size: usize,
    stats: &mut ApplyStats,
) -> Result<(), String> {
    let stored = import_map::read_import_cursor(conn, rel)?;
    let opts = import_map::ExtractOpts {
        kind,
        db_id,
        cursor: stored,
        own_uid,
    };
    let (mut coded, skipped) = import_map::extract_coded(src, plan, &opts)?;
    stats.msgs_extracted += coded.len();
    stats.msgs_skipped += skipped;
    // The hatch (precondition 4's escape): unmapped rows are written
    // kind=100 with text NULL — never JSON-as-text. A run that got
    // here passed the preflight, so the hatch being off means every
    // row is mapped and this loop is a no-op; belt: refuse here too.
    for cw in &mut coded {
        if !import_map::code_is_mapped(plan, cw) {
            import_map::force_unmapped_raw(cw);
        }
        // The NULL-uidFrom count (precondition 5): rows whose uidFrom
        // was NULL — not "0" — that the shared `sender_for` rule
        // substituted with the configured own uid. Counted as an
        // extraction fact; the rule itself is never changed here.
        if cw.uid_from_null
            && matches!(&cw.write, Write::Message { sender_id: Some(_), .. })
        {
            stats.uid_from_null_substituted += 1;
        }
    }
    let mut run_cursor = stored.unwrap_or(ImportCursor {
        max_ts: i64::MIN,
        max_rowid: i64::MIN,
    });
    let batch_size = batch_size.max(1);
    // F2: this DB's freeze flag — set by the first batch error of any
    // kind; while it is set, `apply_message_batch` never writes another
    // cursor advance for this DB. Counted once per frozen DB so the
    // summary can say a re-run retries them.
    let mut frozen = false;
    for batch in coded.chunks(batch_size) {
        apply_message_batch(conn, plan, rel, batch, &mut run_cursor, &mut frozen, stats);
    }
    if frozen {
        stats.dbs_cursor_frozen += 1;
    }
    Ok(())
}

/// The progress line (counts only, the brief's exact fields).
fn progress_line(done: usize, total: usize, stats: &ApplyStats, elapsed_s: u64) -> String {
    format!(
        "import apply: dbs={done}/{total} msgs_written={} errors={} elapsed={elapsed_s}s",
        stats.msgs_applied, stats.errors
    )
}

/// `run_apply` — the CLI entry (the process probe is injected so the
/// precondition is testable without touching the real process table).
pub fn run_apply(
    a: &ImportArgs,
    out: &mut dyn FnMut(&str),
    zalors_running: impl Fn() -> Option<bool>,
) -> Result<(), String> {
    run_apply_with_limit(a, out, zalors_running, None)
}

/// The apply step. F3: every line is EMITTED through `out` as it is
/// produced (preflight, backup path, progress, summary) — nothing is
/// buffered, so a later failure never hides what already printed; the
/// Err still carries the failure and exits 1. `stop_after_dbs` is
/// `None` in production; tests pass `Some(n)` to stop cleanly after n
/// committed DBs — exactly the state a killed run leaves behind
/// (committed batches + their cursors) — and then re-run to prove the
/// resume.
pub fn run_apply_with_limit(
    a: &ImportArgs,
    out: &mut dyn FnMut(&str),
    zalors_running: impl Fn() -> Option<bool>,
    stop_after_dbs: Option<usize>,
) -> Result<(), String> {
    let started = std::time::Instant::now();
    let mut stats = ApplyStats::default();

    // Precondition 1 (parse enforces; runtime belt for direct callers).
    if !a.apply {
        return Err("--apply is not set — run_apply is the apply step".into());
    }
    if !a.i_have_a_backup_plan {
        return Err(
            "--apply needs --i-have-a-backup-plan: the apply writes into the shadow store; \
             confirm you have a way to restore it (the run also makes its own backup first)"
                .into(),
        );
    }
    let Some(target) = a.target.clone() else {
        return Err(
            "--apply needs --target <shadow store dir>: there is no default — the live \
             store is never silently chosen".into(),
        );
    };
    let Some(map_path) = a.mapping.clone() else {
        return Err(
            "--apply needs --mapping <file>: the built-in skeleton maps nothing".into(),
        );
    };

    // Precondition 2: single writer — no other zalors.exe.
    match zalors_running() {
        Some(false) => {}
        Some(true) => {
            return Err(
                "refusing --apply: another zalors.exe process is running — quit the app \
                 first (the shadow store has one writer)"
                    .into(),
            )
        }
        None => {
            return Err(
                "refusing --apply: cannot verify that no other zalors.exe is running \
                 (tasklist failed) — quit the app and retry"
                    .into(),
            )
        }
    }
    out(&format!(
        "import apply: target={} (read-write)",
        target.display()
    ));
    out("import apply: no other zalors.exe is running");

    // Snapshot guards + key + profile (read-only, the batch-6 rules).
    let p = import::prepare(a)?;
    let mapping = import_map::load_mapping_file(&map_path)?;
    let g = import::gather_inventories(&p)?;
    let plan = import_map::plan(&mapping, &g.inv).map_err(|errs| {
        format!(
            "mapping failed validation ({} error(s)):\n  - {}",
            errs.len(),
            errs.join("\n  - ")
        )
    })?;
    out(&format!("import apply: plan OK ({})", plan.summary_line()));

    // The batch-15 own-uid rule, unchanged (KQ2): `ZR_OWN_UID`, else
    // `--own-uid-from-settings`. The value is never printed.
    let own_uid = import::resolve_own_uid(a.own_uid_from_settings);
    stats.own_uid_set = own_uid.is_some();
    out(&format!(
        "import apply: own_uid set: {}",
        stats.own_uid_set
    ));

    // Precondition 4: every msgType code that occurs is mapped.
    let (unmapped, census_no_table) = unmapped_census(&p, &plan)?;
    // F1: the DBs the census skipped for having no mapped table —
    // printed in the preflight and again in the final summary; the
    // write loop skips exactly the same set.
    out(&format!(
        "import apply: dbs_no_table={census_no_table} (DBs that open fine but have \
         no mapped table — skipped in the census and the write loop)"
    ));
    if unmapped.is_empty() {
        out("import apply: unmapped codes: none (every code in the snapshot is mapped)");
    } else if !a.unmapped_as_raw {
        let total: i64 = unmapped.iter().map(|u| u.rows).sum();
        let mut msg = format!(
            "refusing --apply: {total} row(s) carry msgType codes the mapping does not \
             list — unmapped media codes would store their JSON content as message text.\n\
             Unmapped codes (per-code row counts, the batch-15 all-DB aggregation):\n"
        );
        for u in &unmapped {
            msg.push_str(&format!("  - code {} x {}\n", u.rendered, u.rows));
        }
        msg.push_str(
            "Add the codes to the mapping's \"msgType\" table, or pass --unmapped-as-raw to \
             store those rows as kind=100 with NULL text (content only in payload_json, \
             the raw code string included) — never JSON-as-text.",
        );
        return Err(msg);
    } else {
        for l in unmapped_lines(&unmapped, true) {
            out(&l);
        }
    }

    // The target store (no default; the user passed it).
    let db_path = db_file(&target);
    if !db_path.is_file() {
        return Err(format!(
            "--target: no {} — not a shadow store dir?",
            db_path.display()
        ));
    }
    // Batch 18 (R4): the target opens in whichever mode its marker says
    // — raw through the DPAPI key file, passphrase through the remember
    // file ONLY. The import CLI never accepts a password (argv/env are
    // out by hard rule), so a passphrase-mode store without a usable
    // remember file refuses with the documented message.
    let (conn, store_key) = match super::passphrase::open_store(&target, false) {
        Ok((c, k)) => (c, k),
        Err(super::passphrase::StoreOpenError::Locked) => {
            return Err(
                "the target store is password-protected (passphrase mode): unlock it in the app \
                 with 'Nhớ trên máy này' (remember on this machine) enabled, then re-run — the \
                 import CLI never accepts passwords"
                    .into(),
            );
        }
        Err(super::passphrase::StoreOpenError::Other(k)) => {
            return Err(format!(
                "--target: store open failed ({k}) — no key file / broken store?"
            ));
        }
    };

    // Precondition 6 (batch 16 fix F4): the store's schema version
    // must equal this binary's. The live store of the soaking build is
    // an OLDER schema; the import CLI must not migrate the user's live
    // store as a side effect (this open never applies the schema) nor
    // write into a schema it does not match. Read the stored version
    // the same way `schema::apply` does; the refusal fires BEFORE the
    // backup, so zero bytes move.
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
        "import apply: target schema v{stored_v} matches this binary (v{})",
        schema::VERSION
    ));

    // Precondition 3: backup + verify BEFORE the first write.
    let backup_dir = target.join("pre-import-backups");
    let mut now = schema::now_ms();
    // The stamp resolves to one second: a re-run inside the same second
    // would collide with the previous backup's file names — bump until
    // the stamp is free (each run gets its own backup set).
    while super::backup::backup_db_path(&backup_dir, now).exists() {
        now += 1_000;
    }
    let manifest = super::backup::backup_db(&conn, &store_key.backup_key(), &backup_dir, now)
        .map_err(|kind| format!("pre-import backup failed ({kind}) — no writes were performed"))?;
    let backup_db_path = super::backup::backup_db_path(&backup_dir, now);
    super::backup::verify_backup(&backup_db_path, &store_key.backup_key(), &manifest)
        .map_err(|kind| format!("pre-import backup verify failed ({kind}) — no writes were performed"))?;
    let manifest_path = backup_db_path.with_extension("json");
    out(&format!(
        "import apply: backup OK: {} (verified: sha+integrity+counts)",
        manifest_path.display()
    ));
    // The idempotence measure starts AFTER the backup: the export
    // itself changes rows through this connection (ATTACHed dest) and
    // must never pollute the store's delta.
    let changes_before_write = sqlite_total_changes(&conn);

    // The index entities (conversation/contact/group): extract from
    // Core\Index.db, classify, apply the non-ignored in batched
    // transactions. (The attachment entity stays counted-only — 2.6
    // groundwork; no Write exists for it.)
    let index_entities = [
        plan.conversation.is_some(),
        plan.contact.is_some(),
        plan.group.is_some(),
    ]
    .into_iter()
    .any(|on| on);
    if index_entities {
        let index_path = p.uid_dir.join("Core").join("Index.db");
        let index_conn =
            import::open_desktop_db(&index_path, p.passphrase.as_str(), p.profile)?;
        let opts = import_map::ExtractOpts {
            kind: MapDb::Index,
            db_id: None,
            cursor: None,
            own_uid: own_uid.as_deref(),
        };
        let (writes, _skips) = import_map::extract(&index_conn, &plan, &opts)?;
        for batch in writes.chunks(APPLY_BATCH_ROWS) {
            if let Err(e) = conn.execute_batch("BEGIN IMMEDIATE") {
                stats.add_error_kind(format!("begin:{}", sqlite_kind(&e)));
                continue;
            }
            let mut tally = (0usize, 0usize, 0usize, 0usize, 0usize, 0usize); // conv/contact/group applied+ignored
            let mut aborted = false;
            for (i, w) in batch.iter().enumerate() {
                let verdict = match import_map::classify_write(&conn, w) {
                    Ok(v) => v,
                    Err(_) => {
                        stats.add_error_kind("lookup".into());
                        if conn.is_autocommit() {
                            aborted = true;
                            for _ in (i + 1)..batch.len() {
                                stats.add_error_kind("item:aborted".into());
                            }
                            break;
                        }
                        continue;
                    }
                };
                if verdict == Verdict::Ignored {
                    match w {
                        Write::Conversation { .. } => tally.1 += 1,
                        Write::Contact { .. } => tally.3 += 1,
                        Write::Group { .. } => tally.5 += 1,
                        _ => {}
                    }
                    continue;
                }
                match apply_item(&conn, w) {
                    Ok(_) => match w {
                        Write::Conversation { .. } => tally.0 += 1,
                        Write::Contact { .. } => tally.2 += 1,
                        Write::Group { .. } => tally.4 += 1,
                        _ => {}
                    },
                    Err(e) => {
                        stats.add_error_kind(format!("{}:{}", w.tag(), sqlite_kind(&e)));
                        if conn.is_autocommit() {
                            aborted = true;
                            for _ in (i + 1)..batch.len() {
                                stats.add_error_kind("item:aborted".into());
                            }
                            break;
                        }
                    }
                }
            }
            if aborted {
                let _ = conn.execute_batch("ROLLBACK");
                continue;
            }
            match conn.execute_batch("COMMIT") {
                Ok(()) => {
                    stats.conv_applied += tally.0;
                    stats.conv_ignored += tally.1;
                    stats.contact_applied += tally.2;
                    stats.contact_ignored += tally.3;
                    stats.group_applied += tally.4;
                    stats.group_ignored += tally.5;
                }
                Err(e) => {
                    let _ = conn.execute_batch("ROLLBACK");
                    stats.add_error_kind(format!("commit:{}", sqlite_kind(&e)));
                }
            }
        }
    }

    // The message DBs: census order == write order (the same set).
    let dbs = applicable_dbs(&p, &plan)?;
    stats.dbs_total = dbs.len();
    // F1: the mapped table's name — every DB whose sqlite_master lacks
    // it is skipped (counted), exactly like the census.
    let msg_table: Option<String> = plan.message.as_ref().map(|ep| ep.table.clone());
    let mut done = 0usize;
    for db in &dbs {
        if stop_after_dbs == Some(done) {
            break;
        }
        let src = import::open_desktop_db(&db.path, p.passphrase.as_str(), p.profile)
            .map_err(|e| format!("{}: open failed: {e} — stopping (a re-run resumes here)", db.rel))?;
        // F1: no mapped table → nothing to import from this DB; skip
        // it and count (the census skipped the same DB). The check
        // itself failing is a read failure and stops the run.
        if let Some(table) = &msg_table {
            let present = mapped_table_exists(&src, table).map_err(|e| {
                format!("{}: sqlite_master read failed: {e} — stopping (a re-run resumes here)", db.rel)
            })?;
            if !present {
                stats.dbs_no_table += 1;
                continue;
            }
        }
        stats.dbs_opened += 1;
        apply_message_db(
            &conn,
            &src,
            &plan,
            &db.rel,
            db.kind,
            db.db_id,
            own_uid.as_deref(),
            APPLY_BATCH_ROWS,
            &mut stats,
        )?;
        done += 1;
        if done % PROGRESS_EVERY == 0 {
            out(&progress_line(
                done,
                stats.dbs_total,
                &stats,
                started.elapsed().as_secs(),
            ));
        }
    }

    // Final summary (counts only) + integrity check.
    out(&format!(
        "import apply: dbs opened={}/{} dbs_no_table={}",
        stats.dbs_opened, stats.dbs_total, stats.dbs_no_table
    ));
    out(&format!(
        "import apply: messages: extracted={} skipped={} applied={} new={} fill_null={} \
         update_import={} ignored={} unmapped_raw={}",
        stats.msgs_extracted,
        stats.msgs_skipped,
        stats.msgs_applied,
        stats.msgs_new,
        stats.msgs_fill_null,
        stats.msgs_update_import,
        stats.msgs_ignored,
        stats.msgs_unmapped_raw
    ));
    out(&format!(
        "import apply: uidFrom-NULL rows substituted via sender_for: {} \
         (own_uid set: {}; the shared rule is unchanged)",
        stats.uid_from_null_substituted, stats.own_uid_set
    ));
    if plan.conversation.is_some() {
        out(&format!(
            "import apply: conversations: applied={} ignored={}",
            stats.conv_applied, stats.conv_ignored
        ));
    }
    if plan.contact.is_some() {
        out(&format!(
            "import apply: contacts: applied={} ignored={}",
            stats.contact_applied, stats.contact_ignored
        ));
    }
    if plan.group.is_some() {
        out(&format!(
            "import apply: groups: applied={} ignored={}",
            stats.group_applied, stats.group_ignored
        ));
    }
    if stats.errors == 0 {
        out("import apply: errors=0");
    } else {
        out(&format!(
            "import apply: errors={} kinds={}",
            stats.errors,
            stats.error_kinds_line()
        ));
    }
    // F2: the DBs whose cursor froze this run. Their stored watermark
    // is at the last fully-good batch, so a re-run re-extracts the
    // rows after it — the already-committed ones idempotently skipped,
    // the failed ones retried.
    if stats.dbs_cursor_frozen > 0 {
        out(&format!(
            "import apply: cursor frozen for {} DB(s) after errors — a re-run retries them",
            stats.dbs_cursor_frozen
        ));
    }
    let delta = sqlite_total_changes(&conn) - changes_before_write;
    out(&format!(
        "import apply: store changes (total_changes delta since the backup): {delta}"
    ));
    let integrity: String = conn
        .query_row("PRAGMA integrity_check;", [], |r| r.get(0))
        .map_err(|e| format!("integrity_check failed: {}", sqlite_kind(&e)))?;
    if integrity != "ok" {
        return Err(format!(
            "integrity_check is not ok after the apply (first row: {integrity:?})"
        ));
    }
    out("import apply: integrity_check=ok");
    out(&format!(
        "import apply: done elapsed={}s",
        started.elapsed().as_secs()
    ));
    Ok(())
}

#[cfg(test)]
mod tests {
    //! Synthetic fixtures ONLY — every snapshot, key and store lives
    //! under the OS temp dir; the real Desktop tree, the real D7 key
    //! and the real shadow store are never touched (the hard rule).
    //! The process probe is INJECTED (`|| Some(false)`), so no test
    //! ever consults the real process table either.

    use super::*;
    use super::super::key_file;
    use crate::migrate::sqlcipher;
    use serde_json::json;
    use std::path::Path;
    use zeroize::Zeroizing;

    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    /// A fresh unique temp dir (synthetic fixtures only).
    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zr-apply-{tag}-{}-{}-{}",
            std::process::id(),
            schema::now_ms(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The fake passphrase every fixture DB is keyed with (a synthetic
    /// 32-char string — never a real key).
    const PASS: &str = "fakefakefakefakefakefakefake1234";

    /// A synthetic Desktop-style cipher DB keyed by the PASSPHRASE form
    /// (M2-3) with arbitrary SQL. No DPAPI — cross-platform.
    fn make_cipher_db_sql(path: &Path, sql: &str) {
        let conn = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_CREATE,
        )
        .unwrap();
        import::apply_passphrase_key(&conn, PASS).unwrap();
        conn.execute_batch(sql).unwrap();
        conn.close().map_err(|(_, e)| e).unwrap();
    }

    /// The fake Desktop message schema: mapped code 1, unmapped codes
    /// 19/20, a NULL code, a NULL uidFrom and a "0" uidFrom.
    const MSG_DB_SQL: &str = "CREATE TABLE msg (
        id INTEGER PRIMARY KEY, cliId TEXT, fromUid TEXT, toUid TEXT,
        ts INTEGER, type INTEGER, content TEXT
      );
      INSERT INTO msg (id, cliId, fromUid, toUid, ts, type, content) VALUES
        (101, 'c101', 'u1', 'u2', 1690000000, 1,    'hello there'),
        (102, 'c102', 'u1', 'u2', 1690000001, 19,   '{\"href\":\"https://fake-photo-stal.zdn.vn/x.jpg\"}'),
        (103, 'c103', NULL, 'u9', 1690000002, 1,    'no from column value'),
        (104, 'c104', '0',  'u9', 1690000003, 1,    'self sent'),
        (105, 'c105', 'u1', 'u2', 1690000004, 20,   'plain late-mapped text'),
        (106, 'c106', 'u1', 'u2', 1690000005, NULL, 'never typed');";

    /// A second one2one DB (the resume test needs two).
    const MSG_DB2_SQL: &str = "CREATE TABLE msg (
        id INTEGER PRIMARY KEY, cliId TEXT, fromUid TEXT, toUid TEXT,
        ts INTEGER, type INTEGER, content TEXT
      );
      INSERT INTO msg (id, cliId, fromUid, toUid, ts, type, content) VALUES
        (201, 'c201', 'u1', 'u2', 1690000010, 1,  'second db row'),
        (202, 'c202', 'u1', 'u2', 1690000011, 19, '{\"href\":\"https://fake-photo-stal.zdn.vn/y.jpg\"}');";

    /// F1: a DB that opens fine but has NO `msg` table (the real
    /// snapshot's no-table DBs are group DBs; the kind is irrelevant
    /// to the skip, so the fixture uses a 1-1 name).
    const NO_MSG_TABLE_DB_SQL: &str = "CREATE TABLE something_else (x INTEGER);";

    /// F1: a DB whose `msg` table EXISTS but whose msgType column is
    /// missing. The census read does not fail on this (SQLite's
    /// double-quoted-string quirk compiles the quoted missing column
    /// as a literal), so the divergence surfaces as an unmapped code
    /// and the run still refuses — never a silent skip.
    const NO_MSG_TYPE_COLUMN_DB_SQL: &str = "CREATE TABLE msg (
        id INTEGER PRIMARY KEY, cliId TEXT, fromUid TEXT, toUid TEXT,
        ts INTEGER, content TEXT
      );
      INSERT INTO msg (id, cliId, fromUid, toUid, ts, content) VALUES
        (301, 'c301', 'u1', 'u2', 1690000020, 'no type column here'),
        (302, 'c302', 'u1', 'u2', 1690000021, 'nor here');";

    /// F3: a DB whose mapped table EXISTS (type='table', so F1 keeps
    /// it) and whose census read works (`group_counts` never touches
    /// rowid) but whose EXTRACT read fails — a WITHOUT ROWID table has
    /// no rowid, which the coded extraction selects. The failure lands
    /// in the write loop, AFTER the backup.
    const NO_ROWID_DB_SQL: &str = "CREATE TABLE msg (
        id TEXT PRIMARY KEY, cliId TEXT, fromUid TEXT, toUid TEXT,
        ts INTEGER, type INTEGER, content TEXT
      ) WITHOUT ROWID;";

    /// The fake Index.db schema (a conversation table the mapping's
    /// conversation entity reads).
    const INDEX_DB_APPLY_SQL: &str = "CREATE TABLE conv (
        id INTEGER PRIMARY KEY, isGroup INTEGER, name TEXT, avatar TEXT
      );
      INSERT INTO conv (id, isGroup, name) VALUES
        (11, 0, 'Alice A'), (12, 1, 'Group G');";

    /// The first mapping: code 1 mapped; 19/20/NULL deliberately NOT
    /// (the preconditions exercise exactly that).
    const APPLY_MAPPING_JSON: &str = r#"{
      "msgType": { "1": "webchat" },
      "entities": {
        "message": {
          "db": ["one2one"], "table": "msg",
          "columns": {
            "msgId": "id", "uidFrom": "fromUid", "idTo": "toUid",
            "ts": { "expr": "s_to_ms", "of": "ts" },
            "msgType": "type", "content": "content", "cliMsgId": "cliId"
          }
        },
        "conversation": {
          "db": "index", "table": "conv",
          "columns": {
            "id": "id", "is_group": "isGroup", "title": "name",
            "avatar_url": "avatar"
          }
        }
      }
    }"#;

    /// The later mapping: 19 -> chat.photo, 20 -> webchat (the
    /// hatch-is-not-a-dead-end test re-applies with it).
    const LATER_MAPPING_JSON: &str = r#"{
      "msgType": { "1": "webchat", "19": "chat.photo", "20": "webchat" },
      "entities": {
        "message": {
          "db": ["one2one"], "table": "msg",
          "columns": {
            "msgId": "id", "uidFrom": "fromUid", "idTo": "toUid",
            "ts": { "expr": "s_to_ms", "of": "ts" },
            "msgType": "type", "content": "content", "cliMsgId": "cliId"
          }
        }
      }
    }"#;

    /// The mapping's plan against the fixture's own inventories (no
    /// DPAPI: the DBs open with the fake passphrase directly).
    fn fixture_plan(
        mapping: &str,
        msg_conn: &Connection,
        index_conn: &Connection,
    ) -> import_map::Plan {
        use import::inventory::{inventory_db, KindInventory, SnapshotInventories};
        let mapping = import_map::parse_mapping(mapping.as_bytes()).unwrap();
        let inv = SnapshotInventories {
            index: Some(KindInventory {
                source_rel: "Core/Index.db".into(),
                inventory: inventory_db(index_conn).unwrap(),
            }),
            one_to_one: Some(KindInventory {
                source_rel: "Core/Message/111.db".into(),
                inventory: inventory_db(msg_conn).unwrap(),
            }),
            group: None,
            stranger_box: None,
        };
        import_map::plan(&mapping, &inv).unwrap()
    }

    /// A synthetic snapshot with Index.db + 111.db + 222.db (all real
    /// cipher DBs, all under the OS temp dir).
    fn fixture_snapshot(dir: &Path) {
        let core = dir.join("Core");
        std::fs::create_dir_all(core.join("Message")).unwrap();
        make_cipher_db_sql(&core.join("Index.db"), INDEX_DB_APPLY_SQL);
        make_cipher_db_sql(&core.join("Message").join("111.db"), MSG_DB_SQL);
        make_cipher_db_sql(&core.join("Message").join("222.db"), MSG_DB2_SQL);
    }

    /// A FAKE D7 key file (Windows): the same JSON shape as the real
    /// capture, DPAPI-wrapped with no entropy.
    #[cfg(windows)]
    fn fake_d7_key_file(path: &Path) {
        let payload = json!({
            "date": "2026-11-20T00:00:00Z",
            "target_sha12": import::sha12(PASS.as_bytes()),
            "value_len": PASS.len() as u64,
            "value": PASS,
        });
        sqlcipher::save_key(payload.to_string().as_bytes(), path).unwrap();
    }

    /// A FAKE shadow store dir (never the live one) + a full synthetic
    /// snapshot + manifest + D7 key. Returns (snapshot dir, store dir,
    /// mapping file path).
    #[cfg(windows)]
    fn fixture_apply_world(tag: &str) -> (PathBuf, PathBuf, PathBuf) {
        let dir = temp_dir(tag);
        let snap = dir.join("snap");
        fixture_snapshot(&snap);
        // The manifest the snapshot guard requires (shape only).
        std::fs::write(
            snap.join(import::SNAPSHOT_MANIFEST),
            json!({
                "created": 1763600000000i64,
                "source_root_sha12": "aaaaaaaaaaaa",
                "files": [
                    { "rel": "Core\\Index.db", "size": 4096u64, "mtime": 1700000000000i64 }
                ]
            })
            .to_string(),
        )
        .unwrap();
        fake_d7_key_file(&snap.join("d7.bin"));
        let store = dir.join("store");
        std::fs::create_dir_all(&store).unwrap();
        drop(fake_shadow_store(&store));
        let map = dir.join("mapping.json");
        std::fs::write(&map, APPLY_MAPPING_JSON).unwrap();
        (snap, store, map)
    }

    /// A fake shadow store: default.db (schema applied) + default.key.
    fn fake_shadow_store(dir: &Path) -> Connection {
        let key = sqlcipher::generate_key().unwrap();
        sqlcipher::save_key(&key, &key_file(dir)).unwrap();
        let conn = sqlcipher::open_with_key(&db_file(dir), &key).unwrap();
        schema::apply(&conn).unwrap();
        conn
    }

    /// Re-open a fake store read-write (assertions after a run).
    fn open_store(dir: &Path) -> Connection {
        let key = sqlcipher::load_key(&key_file(dir)).unwrap();
        sqlcipher::open_with_key(&db_file(dir), &key).unwrap()
    }

    /// ImportArgs for the apply mode against the fixture world.
    fn apply_args(snap: &Path, store: &Path, map: &Path) -> ImportArgs {
        ImportArgs {
            from_snapshot: snap.to_path_buf(),
            account: "default".into(),
            uin_hash: import::sha12(PASS.as_bytes()),
            key_file: Some(snap.join("d7.bin")),
            cipher_compat: None,
            inventory: false,
            out: None,
            mapping: Some(map.to_path_buf()),
            shadow_copy: None,
            delta: false,
            distinct: Vec::new(),
            all_dbs: false,
            own_uid_from_settings: false,
            apply: true,
            i_have_a_backup_plan: true,
            target: Some(store.to_path_buf()),
            unmapped_as_raw: false,
            media_plan: false,
            content_shape: None,
            by: None,
            help: false,
        }
    }

    /// (msg_id, type, text, source) of one message row.
    fn msg_row(conn: &Connection, id: &str) -> (String, i64, Option<String>, String) {
        conn.query_row(
            "SELECT msg_id, type, text, source FROM messages WHERE msg_id = ?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap()
    }

    /// One stored cursor for a DB scope.
    fn stored_cursor(conn: &Connection, rel: &str) -> Option<import_map::ImportCursor> {
        import_map::read_import_cursor(conn, rel).unwrap()
    }

    fn sha256_file(path: &Path) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(std::fs::read(path).unwrap());
        format!("{:x}", h.finalize())
    }

    // --- F3: the collecting sink (what the CLI's println sink does,
    // minus stdout) ---------------------------------------------------

    /// Run the real entry with a Vec sink; on Err the lines are lost
    /// (use [`apply_collect_keep`] when they matter).
    fn apply_collect(
        a: &ImportArgs,
        z: impl Fn() -> Option<bool>,
    ) -> Result<Vec<String>, String> {
        let (r, lines) = apply_collect_keep(a, z);
        r.map(|()| lines)
    }

    /// Run the real entry with a Vec sink and KEEP the emitted lines
    /// even when it fails — the property F3 exists for.
    fn apply_collect_keep(
        a: &ImportArgs,
        z: impl Fn() -> Option<bool>,
    ) -> (Result<(), String>, Vec<String>) {
        let mut lines: Vec<String> = Vec::new();
        let r = run_apply(a, &mut |l: &str| lines.push(l.to_string()), z);
        (r, lines)
    }

    /// The stop-limited variant with a Vec sink (the resume tests).
    fn apply_with_limit_collect(
        a: &ImportArgs,
        z: impl Fn() -> Option<bool>,
        stop: Option<usize>,
    ) -> Result<Vec<String>, String> {
        let mut lines: Vec<String> = Vec::new();
        let r = run_apply_with_limit(a, &mut |l: &str| lines.push(l.to_string()), z, stop);
        r.map(|()| lines)
    }

    // --- precondition 2 --------------------------------------------------

    #[test]
    fn tasklist_parsing_matches_exact_name_and_excludes_own_pid() {
        let own = 4242u32;
        // CSV rows (tasklist /FO CSV /NH): own process, a foreign
        // zalors, an upper-case one, a lookalike name, an unrelated
        // image, a junk line.
        let csv = "\"zalors.exe\",\"4242\",\"Console\",\"1\",\"12,345 K\"\n\
                    \"zalors.exe\",\"3664\",\"Console\",\"1\",\"98,765 K\"\n\
                    \"ZALORS.EXE\",\"777\",\"Console\",\"1\",\"1 K\"\n\
                    \"zalors2.exe\",\"888\",\"Console\",\"1\",\"1 K\"\n\
                    \"explorer.exe\",\"999\",\"Console\",\"1\",\"5 K\"\n\
                    \"no pid here\"\n";
        assert_eq!(tasklist_zalors_pids(csv, own), vec![3664, 777]);
        // The no-match info line yields nothing.
        assert_eq!(
            tasklist_zalors_pids(
                "INFO: No tasks are running which match the specified criteria.",
                own
            ),
            Vec::<u32>::new()
        );
        assert_eq!(tasklist_zalors_pids("", own), Vec::<u32>::new());
        // A different own pid keeps everything else.
        assert_eq!(tasklist_zalors_pids(csv, 1), vec![4242, 3664, 777]);
    }

    #[test]
    fn run_apply_refuses_when_another_zalors_is_running_or_unknown() {
        // The refusal fires BEFORE the snapshot is even looked at, so
        // a bogus snapshot path is fine (and the fixture stays tiny).
        let dir = temp_dir("procs");
        let map = dir.join("mapping.json");
        std::fs::write(&map, APPLY_MAPPING_JSON).unwrap();
        let a = apply_args(&dir.join("snap"), &dir.join("store"), &map);
        // Another zalors.exe (precondition 2, Some(true)).
        let e = apply_collect(&a, || Some(true)).unwrap_err();
        assert!(e.contains("another zalors.exe process is running"), "{e}");
        assert!(e.contains("one writer"), "{e}");
        // The check itself failed (None) — fail closed.
        let e = apply_collect(&a, || None).unwrap_err();
        assert!(e.contains("cannot verify"), "{e}");
        assert!(e.contains("tasklist failed"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- precondition 1 (runtime belt; parse tests live in cli.rs) ----

    #[test]
    fn run_apply_names_the_missing_explicit_flags() {
        let dir = temp_dir("flags");
        let map = dir.join("mapping.json");
        std::fs::write(&map, APPLY_MAPPING_JSON).unwrap();
        // No --i-have-a-backup-plan.
        let mut a = apply_args(&dir.join("snap"), &dir.join("store"), &map);
        a.i_have_a_backup_plan = false;
        let e = apply_collect(&a, || Some(false)).unwrap_err();
        assert!(e.contains("--apply needs --i-have-a-backup-plan"), "{e}");
        // No --target.
        let mut a = apply_args(&dir.join("snap"), &dir.join("store"), &map);
        a.target = None;
        let e = apply_collect(&a, || Some(false)).unwrap_err();
        assert!(e.contains("--apply needs --target"), "{e}");
        // No --mapping.
        let mut a = apply_args(&dir.join("snap"), &dir.join("store"), &map);
        a.mapping = None;
        let e = apply_collect(&a, || Some(false)).unwrap_err();
        assert!(e.contains("--apply needs --mapping"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- precondition 4: the unmapped-code preflight --------------------

    #[test]
    fn unmapped_census_sums_codes_across_every_mapped_db() {
        // Cross-platform (no DPAPI): the census reads the fixture DBs
        // through a hand-built Prepared. 19 appears in BOTH DBs (x2),
        // 20 and NULL once each; code 1 is mapped and absent.
        let dir = temp_dir("census");
        fixture_snapshot(&dir);
        let p = import::Prepared {
            uid_dir: dir.clone(),
            passphrase: Zeroizing::new(PASS.to_string()),
            profile: import::CipherProfile::Compat4,
            key_sha12: import::sha12(PASS.as_bytes()),
        };
        let msg = import::open_desktop_db(
            &dir.join("Core").join("Message").join("111.db"),
            PASS,
            import::CipherProfile::Compat4,
        )
        .unwrap();
        let idx = import::open_desktop_db(
            &dir.join("Core").join("Index.db"),
            PASS,
            import::CipherProfile::Compat4,
        )
        .unwrap();
        let plan = fixture_plan(APPLY_MAPPING_JSON, &msg, &idx);
        let (unmapped, no_table) = unmapped_census(&p, &plan).unwrap();
        assert_eq!(no_table, 0, "the fixture DBs all have the mapped table");
        // (counts only; tokens went through the batch-14 renderer)
        assert_eq!(unmapped.len(), 3, "{unmapped:?}");
        let by_token: BTreeMap<&str, i64> = unmapped
            .iter()
            .map(|u| (u.rendered.as_str(), u.rows))
            .collect();
        assert_eq!(by_token["19"], 2, "{by_token:?}");
        assert_eq!(by_token["20"], 1, "{by_token:?}");
        assert_eq!(by_token["NULL"], 1, "{by_token:?}");
        assert!(!by_token.contains_key("1"), "mapped codes never appear");
        // F1: a DB that opens fine but has NO mapped table is skipped
        // and counted — never a refusal, and it contributes no codes.
        // (The real snapshot's no-table DBs are group DBs; the kind is
        // irrelevant to the mechanism, so the fixture uses a 1-1 name.)
        make_cipher_db_sql(
            &dir.join("Core").join("Message").join("333.db"),
            NO_MSG_TABLE_DB_SQL,
        );
        let (unmapped2, no_table2) = unmapped_census(&p, &plan).unwrap();
        assert_eq!(no_table2, 1, "the no-table DB is counted, not fatal");
        assert_eq!(unmapped2, unmapped, "it contributed no codes");
        // The later mapping leaves only the NULL code unmapped.
        let plan2 = fixture_plan(LATER_MAPPING_JSON, &msg, &idx);
        let (unmapped3, no_table3) = unmapped_census(&p, &plan2).unwrap();
        assert_eq!(no_table3, 1, "the skip is stable across mappings");
        assert_eq!(unmapped3.len(), 1);
        assert_eq!(unmapped3[0].rendered, "NULL");
        assert_eq!(unmapped3[0].rows, 1);
        // R3 (batch 21): the two fixture DB connections must close
        // BEFORE the cleanup — an open SQLite handle keeps the file
        // locked on Windows and the removal fails silently.
        drop(msg);
        drop(idx);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    #[cfg(windows)]
    fn run_apply_refuses_unmapped_codes_and_writes_nothing() {
        let (snap, store, map) = fixture_apply_world("refuse");
        let before = (
            sha256_file(&db_file(&store)),
            sha256_file(&key_file(&store)),
        );
        let a = apply_args(&snap, &store, &map);
        let e = apply_collect(&a, || Some(false)).unwrap_err();
        // The refusal lists every unmapped code with its count and the
        // hatch hint — and nothing else ever happened.
        assert!(e.contains("4 row(s) carry msgType codes"), "{e}");
        assert!(e.contains("code 19 x 2"), "{e}");
        assert!(e.contains("code 20 x 1"), "{e}");
        assert!(e.contains("code NULL x 1"), "{e}");
        assert!(e.contains("never JSON-as-text"), "{e}");
        assert!(e.contains("--unmapped-as-raw"), "{e}");
        assert_eq!(
            (
                sha256_file(&db_file(&store)),
                sha256_file(&key_file(&store))
            ),
            before,
            "no writes performed"
        );
        // The backup precondition never fired (it comes after the
        // preflight): no pre-import-backups dir exists.
        assert!(!store.join("pre-import-backups").exists());
        let _ = std::fs::remove_dir_all(snap.parent().unwrap());
    }

    // --- F1: DBs without the mapped table --------------------------------

    #[test]
    #[cfg(windows)]
    fn a_db_without_the_mapped_table_is_skipped_and_counted() {
        // The real snapshot has group DBs that open fine but have NO
        // message table; the old code refused on them, so a real apply
        // could never succeed. Now they are skipped in the census AND
        // the write loop and counted as dbs_no_table.
        let (snap, store, map) = fixture_apply_world("notable");
        make_cipher_db_sql(
            &snap.join("Core").join("Message").join("333.db"),
            NO_MSG_TABLE_DB_SQL,
        );
        let mut a = apply_args(&snap, &store, &map);
        a.unmapped_as_raw = true;
        let lines = apply_collect(&a, || Some(false)).unwrap();
        let joined = lines.join("\n");
        // The census passed, the apply completed, the skip is counted
        // in BOTH the preflight and the final summary.
        assert!(
            joined.contains("dbs_no_table=1 (DBs that open fine but have no mapped table"),
            "{joined}"
        );
        assert!(joined.contains("import apply: dbs opened=2/3 dbs_no_table=1"), "{joined}");
        assert!(joined.contains("integrity_check=ok"), "{joined}");
        assert_eq!(
            joined.matches("dbs_no_table=1").count(),
            2,
            "preflight + summary both print it: {joined}"
        );
        {
            let conn = open_store(&store);
            // Only the two real DBs landed (8 rows), the no-table DB
            // was never read for rows and never got a cursor.
            let n: i64 = conn
                .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
                .unwrap();
            assert_eq!(n, 8);
            assert_eq!(
                stored_cursor(&conn, "Core/Message/111.db"),
                Some(import_map::ImportCursor { max_ts: 1690000005, max_rowid: 106 })
            );
            assert!(stored_cursor(&conn, "Core/Message/333.db").is_none());
        }
        let _ = std::fs::remove_dir_all(snap.parent().unwrap());
    }

    #[test]
    #[cfg(windows)]
    fn a_db_whose_table_exists_but_whose_msgtype_column_is_missing_still_refuses() {
        // F1's other edge: the mapped table EXISTS, so the DB is not
        // skipped — but the read diverges. The census's fixed
        // aggregation quotes the msgType column, and SQLite's
        // double-quoted-string quirk compiles a MISSING column as the
        // literal instead of failing, so the divergence surfaces as an
        // unmapped code ("type" x rows) and the run refuses — never a
        // silent skip, never a silent apply.
        let (snap, store, map) = fixture_apply_world("nocol");
        make_cipher_db_sql(
            &snap.join("Core").join("Message").join("444.db"),
            NO_MSG_TYPE_COLUMN_DB_SQL,
        );
        let before = (
            sha256_file(&db_file(&store)),
            sha256_file(&key_file(&store)),
        );
        let a = apply_args(&snap, &store, &map);
        let e = apply_collect(&a, || Some(false)).unwrap_err();
        assert!(e.contains("refusing --apply"), "{e}");
        // The divergent DB's own artifact: code "type" x 2 (the literal
        // the quirk produces, one per row of that DB's msg table).
        assert!(e.contains("code type x 2"), "{e}");
        // Fail-closed, zero writes: the refusal is a preflight one.
        assert_eq!(
            (
                sha256_file(&db_file(&store)),
                sha256_file(&key_file(&store))
            ),
            before,
            "no writes performed"
        );
        assert!(!store.join("pre-import-backups").exists());
        let _ = std::fs::remove_dir_all(snap.parent().unwrap());
    }

    // --- the hatch + backup + idempotence -------------------------------

    #[test]
    #[cfg(windows)]
    fn run_apply_hatch_backup_idempotence_end_to_end() {
        let (snap, store, map) = fixture_apply_world("hatch");
        let mut a = apply_args(&snap, &store, &map);
        a.unmapped_as_raw = true;

        let lines = apply_collect(&a, || Some(false)).unwrap();
        let joined = lines.join("\n");
        // Preflight prints the per-code counts that take the path.
        assert!(joined.contains("--unmapped-as-raw: 4 row(s)"), "{joined}");
        assert!(joined.contains("code 19 x 2"), "{joined}");
        // F4: the current-version store passes the schema check (the
        // fixture store is created by schema::apply).
        assert!(
            joined.contains(&format!(
                "import apply: target schema v{} matches this binary",
                schema::VERSION
            )),
            "{joined}"
        );
        // F1: the fixture DBs all have the mapped table.
        assert!(joined.contains("dbs_no_table=0"), "{joined}");
        // The backup precondition: made, verified, path printed.
        assert!(joined.contains("import apply: backup OK: "), "{joined}");
        let manifest_path = lines
            .iter()
            .find(|l| l.starts_with("import apply: backup OK: "))
            .unwrap()
            .trim_start_matches("import apply: backup OK: ")
            .trim_end_matches(" (verified: sha+integrity+counts)")
            .to_string();
        let manifest_path = PathBuf::from(manifest_path);
        assert!(manifest_path.is_file(), "{manifest_path:?}");
        assert!(
            manifest_path.to_string_lossy().contains("pre-import-backups"),
            "{manifest_path:?}"
        );
        assert!(manifest_path.with_extension("db").is_file());
        // Progress + summary lines, counts only.
        assert!(joined.contains("import apply: dbs opened=2/2"), "{joined}");
        assert!(joined.contains("integrity_check=ok"), "{joined}");
        assert!(
            joined.contains("uidFrom-NULL rows substituted via sender_for: 0"),
            "{joined}"
        );

        // The store: mapped rows are normal writes, unmapped rows are
        // kind=100 with NULL text and the raw code in the payload.
        {
            let conn = open_store(&store);
            assert_eq!(
                msg_row(&conn, "101"),
                ("101".into(), 1, Some("hello there".into()), "import".into())
            );
            let (t, text, src) = {
                let (id, t, text, src) = msg_row(&conn, "102");
                assert_eq!(id, "102");
                (t, text, src)
            };
            assert_eq!(t, 100, "hatch rows are kind 100");
            assert_eq!(text, None, "hatch rows never store JSON-as-text");
            assert_eq!(src, "import");
            assert_eq!(msg_row(&conn, "105").1, 100);
            assert_eq!(msg_row(&conn, "106").1, 100);
            assert_eq!(msg_row(&conn, "202").1, 100);
            // The payload keeps the raw code and the content.
            let payload: String = conn
                .query_row(
                    "SELECT payload_json FROM messages WHERE msg_id='102'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(payload.contains(r#""msgType":"19""#), "{payload}");
            assert!(payload.contains("fake-photo-stal.zdn.vn"), "{payload}");
            // The conversations from the mapping's index entity.
            let convs: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM conversations WHERE id IN ('11','12')",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(convs, 2);
            // Cursors: written, in the RAW ts domain, at each DB's max.
            assert_eq!(
                stored_cursor(&conn, "Core/Message/111.db"),
                Some(import_map::ImportCursor { max_ts: 1690000005, max_rowid: 106 })
            );
            assert_eq!(
                stored_cursor(&conn, "Core/Message/222.db"),
                Some(import_map::ImportCursor { max_ts: 1690000011, max_rowid: 202 })
            );
            // No revisions were produced.
            let revs: i64 = conn
                .query_row("SELECT COUNT(*) FROM message_revisions", [], |r| r.get(0))
                .unwrap();
            assert_eq!(revs, 0);
        }

        // SECOND full apply: cursors skip everything; the printed
        // total_changes delta is exactly 0.
        let lines2 = apply_collect(&a, || Some(false)).unwrap();
        let joined2 = lines2.join("\n");
        assert!(
            joined2.contains("messages: extracted=0 skipped=0 applied=0"),
            "{joined2}"
        );
        assert!(
            joined2.contains("store changes (total_changes delta since the backup): 0"),
            "{joined2}"
        );
        let _ = std::fs::remove_dir_all(snap.parent().unwrap());
    }

    #[test]
    #[cfg(windows)]
    fn run_apply_reapply_with_cleared_cursors_changes_no_data_rows() {
        // The strictest idempotence: cursors deleted, so the second
        // apply RE-EXTRACTS every row — and the classify-then-skip
        // rule still writes 0 of them.
        let (snap, store, map) = fixture_apply_world("idem");
        let mut a = apply_args(&snap, &store, &map);
        a.unmapped_as_raw = true;
        apply_collect(&a, || Some(false)).unwrap();
        {
            let conn = open_store(&store);
            conn.execute("DELETE FROM sync_cursors", []).unwrap();
        }
        let msgs_before: i64 = {
            let conn = open_store(&store);
            conn.query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
                .unwrap()
        };
        let lines2 = apply_collect(&a, || Some(false)).unwrap();
        let joined2 = lines2.join("\n");
        // 8 extracted rows, every one classified Ignored, none applied.
        assert!(
            joined2.contains(
                "messages: extracted=8 skipped=0 applied=0 new=0 fill_null=0 \
                 update_import=0 ignored=8"
            ),
            "{joined2}"
        );
        assert!(
            joined2.contains("conversations: applied=0 ignored=2"),
            "{joined2}"
        );
        let msgs_after: i64 = {
            let conn = open_store(&store);
            conn.query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
                .unwrap()
        };
        assert_eq!(msgs_before, msgs_after, "no data row changed");
        let _ = std::fs::remove_dir_all(snap.parent().unwrap());
    }

    #[test]
    #[cfg(windows)]
    fn a_later_mapping_reapply_fills_the_hatch_rows() {
        // The hatch is not a dead end: after the mapping learns 19 and
        // 20, a re-apply (with the documented cursor reset) fills the
        // rows' type and text via import-rank replacement.
        let (snap, store, map) = fixture_apply_world("later");
        let mut a = apply_args(&snap, &store, &map);
        a.unmapped_as_raw = true;
        apply_collect(&a, || Some(false)).unwrap();

        // The later mapping + the documented cursor reset (the same
        // rule as changing the mapping's ts unit).
        let later = snap.parent().unwrap().join("mapping-later.json");
        std::fs::write(&later, LATER_MAPPING_JSON).unwrap();
        {
            let conn = open_store(&store);
            conn.execute("DELETE FROM sync_cursors", []).unwrap();
        }
        let mut a2 = apply_args(&snap, &store, &later);
        a2.unmapped_as_raw = true; // the NULL-code row still needs it
        let lines2 = apply_collect(&a2, || Some(false)).unwrap();
        let joined2 = lines2.join("\n");
        // Only the NULL code is still unmapped.
        assert!(joined2.contains("--unmapped-as-raw: 1 row(s)"), "{joined2}");
        // All three previously-hatch rows (102, 105, 202) now carry a
        // mapped code and a different payload: import rank replaces
        // import rank, so they are UpdateImport writes.
        assert!(joined2.contains("update_import=3"), "{joined2}");

        {
            let conn = open_store(&store);
            // 102 (code 19 -> chat.photo): media row — type filled,
            // text stays NULL by design (objects never become text),
            // the payload now carries the mapped msgType.
            let (_, t, text, _) = msg_row(&conn, "102");
            assert_eq!(t, 2, "chat.photo code");
            assert_eq!(text, None, "media objects never become text");
            let payload: String = conn
                .query_row(
                    "SELECT payload_json FROM messages WHERE msg_id='102'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert!(payload.contains(r#""msgType":"chat.photo""#), "{payload}");
            // 105 (code 20 -> webchat): the plain text fills.
            let (_, t, text, _) = msg_row(&conn, "105");
            assert_eq!(t, 1, "webchat code");
            assert_eq!(text.as_deref(), Some("plain late-mapped text"));
            // 106 (NULL code): unchanged hatch row.
            let (_, t, text, _) = msg_row(&conn, "106");
            assert_eq!(t, 100);
            assert_eq!(text, None);
            // 202 in the second DB too.
            let (_, t, _, _) = msg_row(&conn, "202");
            assert_eq!(t, 2);
        }
        let _ = std::fs::remove_dir_all(snap.parent().unwrap());
    }

    // --- resume ------------------------------------------------------------

    #[test]
    #[cfg(windows)]
    fn a_partial_run_resumes_where_it_stopped() {
        // Simulate a killed run: stop_after_dbs(1) commits DB 1's
        // batches + cursor, then "dies". The full re-run imports only
        // DB 2.
        let (snap, store, map) = fixture_apply_world("resume");
        let mut a = apply_args(&snap, &store, &map);
        a.unmapped_as_raw = true;
        let lines = apply_with_limit_collect(&a, || Some(false), Some(1)).unwrap();
        let joined = lines.join("\n");
        assert!(joined.contains("import apply: dbs opened=1/2"), "{joined}");
        {
            let conn = open_store(&store);
            // 111.db landed fully…
            let n111: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM messages WHERE msg_id IN \
                     ('101','102','103','104','105','106')",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(n111, 6);
            // …with its cursor; 222.db was never touched.
            assert!(stored_cursor(&conn, "Core/Message/111.db").is_some());
            assert!(stored_cursor(&conn, "Core/Message/222.db").is_none());
            let n222: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM messages WHERE msg_id IN ('201','202')",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(n222, 0);
        }
        // The full run resumes: DB 1 is cursor-skipped (0 extracted),
        // DB 2 imports.
        let lines2 = apply_collect(&a, || Some(false)).unwrap();
        let joined2 = lines2.join("\n");
        assert!(
            joined2.contains("messages: extracted=2 skipped=0 applied=2"),
            "{joined2}"
        );
        {
            let conn = open_store(&store);
            let n: i64 = conn
                .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
                .unwrap();
            assert_eq!(n, 8, "6 + the resumed 2");
            assert_eq!(
                stored_cursor(&conn, "Core/Message/222.db"),
                Some(import_map::ImportCursor { max_ts: 1690000011, max_rowid: 202 })
            );
        }
        let _ = std::fs::remove_dir_all(snap.parent().unwrap());
    }

    #[test]
    #[cfg(windows)]
    fn a_seeded_batch_cursor_skips_the_committed_rows() {
        // The state a killed MID-DB run leaves: a cursor covering the
        // first committed batch. The re-run imports only the tail —
        // the per-batch cursor semantics, at value level.
        let (snap, store, map) = fixture_apply_world("seedcur");
        {
            let conn = open_store(&store);
            conn.execute(
                "INSERT INTO sync_cursors (scope, cursor, updated_at) VALUES (?1, ?2, ?3)",
                rusqlite::params![
                    import_map::import_scope("Core/Message/111.db"),
                    "1690000000:101",
                    42i64
                ],
            )
            .unwrap();
        }
        let mut a = apply_args(&snap, &store, &map);
        a.unmapped_as_raw = true;
        let lines = apply_collect(&a, || Some(false)).unwrap();
        let joined = lines.join("\n");
        // 111.db contributes its 5 tail rows; 222.db its 2.
        assert!(joined.contains("messages: extracted=7"), "{joined}");
        {
            let conn = open_store(&store);
            let n101: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM messages WHERE msg_id='101'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(n101, 0, "the cursor-covered row never re-imports");
            let n_rest: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM messages WHERE msg_id IN \
                     ('102','103','104','105','106')",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(n_rest, 5);
            // The cursor advanced to the DB's full max.
            assert_eq!(
                stored_cursor(&conn, "Core/Message/111.db"),
                Some(import_map::ImportCursor { max_ts: 1690000005, max_rowid: 106 })
            );
        }
        let _ = std::fs::remove_dir_all(snap.parent().unwrap());
    }

    // --- error isolation ---------------------------------------------------

    #[test]
    #[cfg(windows)]
    fn one_bad_row_is_counted_and_the_batch_still_commits() {
        // The pipeline-style poison: a trigger makes ONE insert fail.
        // The savepoint isolates it, the batch commits, the error is
        // counted with its kind, and the run finishes with integrity ok.
        // F2: the cursor must NOT advance past the poisoned row — the
        // whole DB (one batch here) freezes — and a re-run with the
        // trigger removed writes that row.
        let (snap, store, map) = fixture_apply_world("poison");
        {
            let conn = open_store(&store);
            conn.execute_batch(
                "CREATE TRIGGER zr_deny BEFORE INSERT ON messages
                 WHEN NEW.msg_id = '105'
                 BEGIN SELECT RAISE(ABORT, 'crafted'); END;",
            )
            .unwrap();
        }
        let mut a = apply_args(&snap, &store, &map);
        a.unmapped_as_raw = true;
        let lines = apply_collect(&a, || Some(false)).unwrap();
        let joined = lines.join("\n");
        assert!(joined.contains("errors=1 kinds=message:sqlite_"), "{joined}");
        assert!(joined.contains("integrity_check=ok"), "{joined}");
        // F2: the poisoned DB froze — the summary says so.
        assert!(
            joined.contains(
                "import apply: cursor frozen for 1 DB(s) after errors — a re-run retries them"
            ),
            "{joined}"
        );
        {
            let conn = open_store(&store);
            let (bad, ok): (i64, i64) = conn
                .query_row(
                    "SELECT (SELECT COUNT(*) FROM messages WHERE msg_id='105'),
                            (SELECT COUNT(*) FROM messages WHERE msg_id='101')",
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap();
            assert_eq!(bad, 0, "the poison row never landed");
            assert_eq!(ok, 1, "the rest of the batch committed");
            // F2: the cursor did NOT advance past the poisoned row —
            // 111.db's only batch froze, so no cursor exists for it at
            // all; 222.db (clean) still wrote its own.
            assert!(
                stored_cursor(&conn, "Core/Message/111.db").is_none(),
                "the poisoned DB's cursor never moved"
            );
            assert_eq!(
                stored_cursor(&conn, "Core/Message/222.db"),
                Some(import_map::ImportCursor { max_ts: 1690000011, max_rowid: 202 })
            );
        }
        // F2: the re-run (trigger removed) retries the poisoned row.
        {
            let conn = open_store(&store);
            conn.execute_batch("DROP TRIGGER zr_deny").unwrap();
        }
        let lines2 = apply_collect(&a, || Some(false)).unwrap();
        let joined2 = lines2.join("\n");
        assert!(
            !joined2.contains("cursor frozen"),
            "a clean re-run freezes nothing: {joined2}"
        );
        {
            let conn = open_store(&store);
            // 101-104,106 re-extracted and idempotently skipped; 105
            // retried and written.
            let n105: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM messages WHERE msg_id='105'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(n105, 1, "the re-run wrote the poisoned row");
            let n_all: i64 = conn
                .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
                .unwrap();
            assert_eq!(n_all, 8);
            // No errors this time → the cursor advances to the DB max.
            assert_eq!(
                stored_cursor(&conn, "Core/Message/111.db"),
                Some(import_map::ImportCursor { max_ts: 1690000005, max_rowid: 106 })
            );
        }
        let _ = std::fs::remove_dir_all(snap.parent().unwrap());
    }

    #[test]
    fn an_aborted_middle_batch_leaves_the_cursor_at_the_pre_abort_value() {
        // F2's abort arm, driven directly (cross-platform, no DPAPI):
        // three batches of two; the MIDDLE one aborts its transaction
        // (RAISE(ROLLBACK) — the statement class that leaves
        // `is_autocommit()` true, the pipeline test's crafted poison).
        // The old code computed the NEXT batch's cursor from its own
        // later rows, silently passing the aborted ones; now the
        // cursor freezes at the pre-abort value and a re-run retries
        // exactly the rolled-back rows.
        const FAKE_OWN: &str = "1234567890123456789";
        let dir = temp_dir("abortcur");
        fixture_snapshot(&dir);
        let src = import::open_desktop_db(
            &dir.join("Core").join("Message").join("111.db"),
            PASS,
            import::CipherProfile::Compat4,
        )
        .unwrap();
        let idx = import::open_desktop_db(
            &dir.join("Core").join("Index.db"),
            PASS,
            import::CipherProfile::Compat4,
        )
        .unwrap();
        let plan = fixture_plan(APPLY_MAPPING_JSON, &src, &idx);
        let store = dir.join("store");
        std::fs::create_dir_all(&store).unwrap();
        drop(fake_shadow_store(&store));
        let conn = open_store(&store);
        conn.execute_batch(
            "CREATE TRIGGER zr_tx_gone BEFORE INSERT ON messages
             WHEN NEW.msg_id = '103'
             BEGIN SELECT RAISE(ROLLBACK, 'crafted'); END;",
        )
        .unwrap();

        // Batches [101,102] [103,104] [105,106]: the first commits
        // with its cursor; the second ABORTS; the third still commits
        // its rows but, frozen, writes no cursor.
        let mut stats = ApplyStats::default();
        apply_message_db(
            &conn,
            &src,
            &plan,
            "Core/Message/111.db",
            MapDb::OneToOne,
            Some(111),
            Some(FAKE_OWN),
            2,
            &mut stats,
        )
        .unwrap();
        assert_eq!(stats.dbs_cursor_frozen, 1, "this DB froze");
        assert_eq!(
            stored_cursor(&conn, "Core/Message/111.db"),
            Some(import_map::ImportCursor { max_ts: 1690000001, max_rowid: 102 }),
            "the cursor stays at the pre-abort batch"
        );
        {
            let present = |ids: &[&str]| -> i64 {
                let q = format!(
                    "SELECT COUNT(*) FROM messages WHERE msg_id IN ('{}')",
                    ids.join("','")
                );
                conn.query_row(&q, [], |r| r.get(0)).unwrap()
            };
            assert_eq!(present(&["101", "102"]), 2, "the first batch committed");
            assert_eq!(present(&["103", "104"]), 0, "the aborted batch rolled back");
            // The batch AFTER the abort still committed its rows (the
            // freeze only stops cursor writes) — idempotently skipped
            // on the re-run below.
            assert_eq!(present(&["105", "106"]), 2, "the good batch after the abort");
        }

        // The re-run: the delta filter starts at the pre-abort cursor,
        // so the aborted rows are re-extracted. The committed ones are
        // idempotently skipped; the rolled-back ones land; the cursor
        // advances normally (no errors this time).
        conn.execute_batch("DROP TRIGGER zr_tx_gone").unwrap();
        let mut stats2 = ApplyStats::default();
        apply_message_db(
            &conn,
            &src,
            &plan,
            "Core/Message/111.db",
            MapDb::OneToOne,
            Some(111),
            Some(FAKE_OWN),
            2,
            &mut stats2,
        )
        .unwrap();
        assert_eq!(stats2.dbs_cursor_frozen, 0, "a clean re-run freezes nothing");
        assert_eq!(stats2.msgs_extracted, 4, "only the post-cursor rows re-read");
        assert_eq!(stats2.msgs_applied, 2, "103 + 104 retried; 105/106 skipped");
        assert_eq!(stats2.msgs_ignored, 2, "the already-committed rows skipped");
        {
            let n_all: i64 = conn
                .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
                .unwrap();
            assert_eq!(n_all, 6, "every row landed exactly once");
            assert_eq!(
                stored_cursor(&conn, "Core/Message/111.db"),
                Some(import_map::ImportCursor { max_ts: 1690000005, max_rowid: 106 })
            );
        }
        // R3 (batch 21): close the fixture connections before the
        // cleanup (open handles lock the files on Windows).
        drop(src);
        drop(idx);
        drop(conn);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- F3: streamed output ---------------------------------------------

    #[test]
    #[cfg(windows)]
    fn a_write_loop_failure_after_the_backup_keeps_the_backup_line() {
        // F3: everything already emitted stays visible when a later
        // step fails. The injection: a DB whose mapped table EXISTS
        // (so F1 keeps it) and whose census read works, but whose
        // table is WITHOUT ROWID — the coded extraction selects
        // rowid, so the WRITE LOOP fails after the backup was made
        // and verified. (An open failure cannot be injected here: the
        // census opens every mapped DB first and would refuse first —
        // fail-closed by design.)
        let (snap, store, map) = fixture_apply_world("stream");
        make_cipher_db_sql(
            &snap.join("Core").join("Message").join("555.db"),
            NO_ROWID_DB_SQL,
        );
        let mut a = apply_args(&snap, &store, &map);
        a.unmapped_as_raw = true;
        let (r, lines) = apply_collect_keep(&a, || Some(false));
        let e = r.unwrap_err();
        assert!(e.contains("no such column: rowid"), "{e}");
        // The sink kept everything emitted before the failure —
        // including the backup manifest path, printed AFTER the
        // backup was made and verified.
        let joined = lines.join("\n");
        assert!(
            joined.contains("import apply: backup OK: "),
            "the backup line must survive the failure: {joined}"
        );
        assert!(joined.contains("import apply: target schema v"), "{joined}");
        assert!(joined.contains("import apply: dbs_no_table=0"), "{joined}");
        // The two good DBs landed before the failing one; the failing
        // DB never contributed rows.
        {
            let conn = open_store(&store);
            let n: i64 = conn
                .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
                .unwrap();
            assert_eq!(n, 8, "111.db + 222.db landed before the failure");
        }
        let _ = std::fs::remove_dir_all(snap.parent().unwrap());
    }

    // --- precondition 6 (F4): the schema-version gate -------------------

    #[test]
    #[cfg(windows)]
    fn run_apply_refuses_a_target_whose_schema_version_differs() {
        // The live store of the soaking build is an older schema (v1);
        // the import CLI must not migrate it as a side effect nor
        // write into a schema it does not match. Set the stored
        // version low and check the refusal fires BEFORE the backup
        // with zero writes.
        let (snap, store, map) = fixture_apply_world("schemav");
        {
            let conn = open_store(&store);
            conn.execute_batch(
                "DELETE FROM schema_meta;
                 INSERT INTO schema_meta (version, applied_at) VALUES (1, 1);",
            )
            .unwrap();
        }
        let before = (
            sha256_file(&db_file(&store)),
            sha256_file(&key_file(&store)),
        );
        let mut a = apply_args(&snap, &store, &map);
        a.unmapped_as_raw = true;
        let e = apply_collect(&a, || Some(false)).unwrap_err();
        assert!(
            e.contains(&format!(
                "target schema v1, this binary expects v{} — open the store once with \
                 the matching zalors build (it migrates on start), quit it, then re-run",
                schema::VERSION
            )),
            "{e}"
        );
        // Zero writes: the store bytes are unchanged and no backup
        // was made (the refusal precedes precondition 3).
        assert_eq!(
            (
                sha256_file(&db_file(&store)),
                sha256_file(&key_file(&store))
            ),
            before,
            "no writes performed"
        );
        assert!(!store.join("pre-import-backups").exists());
        let _ = std::fs::remove_dir_all(snap.parent().unwrap());
    }

    // --- import precedence -------------------------------------------------

    #[test]
    #[cfg(windows)]
    fn import_never_overwrites_capture_rows() {
        // The AC: capture/e2ee text/payload are compared before and
        // after — they must be byte-identical. The one allowed cell
        // (a NULL text) is the only thing that fills.
        let (snap, store, map) = fixture_apply_world("prec");
        {
            let conn = open_store(&store);
            // A capture row with everything set, same msg_id as an
            // import row that says something entirely different.
            super::super::writer::apply(
                &conn,
                &Write::Message {
                    msg_id: "101".into(),
                    conv_id: "u1".into(),
                    sender_id: Some("u1".into()),
                    ts: 1_690_000_000_000,
                    kind: 1,
                    text: Some("cap-text-101".into()),
                    payload: r#"{"msgId":"101","uidFrom":"u1","idTo":"u2","ts":1690000000000,"msgType":"webchat","content":"cap-text-101"}"#.into(),
                    source: "capture",
                    is_group: Some(false),
                },
            )
            .unwrap();
            // A capture cipher-only row: NULL text AND NULL sender.
            super::super::writer::apply(
                &conn,
                &Write::Message {
                    msg_id: "103".into(),
                    conv_id: "u9".into(),
                    sender_id: None,
                    ts: 1_690_000_002_000,
                    kind: 1,
                    text: None,
                    payload: r#"{"msgId":"103","uidFrom":null,"idTo":"u9","ts":1690000002000,"msgType":"webchat","content":"QUJD"}"#.into(),
                    source: "capture",
                    is_group: Some(false),
                },
            )
            .unwrap();
        }
        let capture_rows = {
            let conn = open_store(&store);
            let mut st = conn
                .prepare(
                    "SELECT msg_id, conv_id, sender_id, ts, type, text, payload_json, rev, source \
                     FROM messages WHERE source IN ('capture','e2ee') ORDER BY msg_id",
                )
                .unwrap();
            let rows: Vec<(
                String,
                String,
                Option<String>,
                i64,
                i64,
                Option<String>,
                String,
                i64,
                String,
            )> = st
                .query_map([], |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                        r.get(8)?,
                    ))
                })
                .unwrap()
                .flatten()
                .collect();
            rows
        };

        let mut a = apply_args(&snap, &store, &map);
        a.unmapped_as_raw = true;
        apply_collect(&a, || Some(false)).unwrap();
        {
            let conn = open_store(&store);
            let mut st = conn
                .prepare(
                    "SELECT msg_id, conv_id, sender_id, ts, type, text, payload_json, rev, source \
                     FROM messages WHERE source IN ('capture','e2ee') ORDER BY msg_id",
                )
                .unwrap();
            let after: Vec<(
                String,
                String,
                Option<String>,
                i64,
                i64,
                Option<String>,
                String,
                i64,
                String,
            )> = st
                .query_map([], |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                        r.get(8)?,
                    ))
                })
                .unwrap()
                .flatten()
                .collect();
            // 101 (capture, everything set): byte-identical.
            assert_eq!(
                after[0], capture_rows[0],
                "import never touches a full capture row"
            );
            // 103 (capture cipher-only): payload/type/source stay; the
            // NULL text cell is the ONE thing import may fill.
            assert_eq!(after[1].0, capture_rows[1].0);
            assert_eq!(after[1].1, capture_rows[1].1, "conv frozen");
            assert_eq!(after[1].3, capture_rows[1].3, "ts frozen");
            assert_eq!(after[1].4, capture_rows[1].4, "type never replaced");
            assert_eq!(after[1].6, capture_rows[1].6, "payload never replaced");
            assert_eq!(after[1].7, capture_rows[1].7, "no rev bump");
            assert_eq!(after[1].8, capture_rows[1].8, "source stays capture");
            assert_eq!(
                after[1].5.as_deref(),
                Some("no from column value"),
                "the NULL text cell is the one import fills"
            );
        }
        let _ = std::fs::remove_dir_all(snap.parent().unwrap());
    }

    // --- precondition 5: the NULL-uidFrom count ---------------------------

    #[test]
    fn apply_message_db_counts_uid_from_null_substituted() {
        // Cross-platform (no DPAPI): drive one DB directly, with an
        // explicit own uid (a FAKE one — never a real uid).
        const FAKE_OWN: &str = "1234567890123456789";
        let dir = temp_dir("uidnull");
        fixture_snapshot(&dir);
        let src = import::open_desktop_db(
            &dir.join("Core").join("Message").join("111.db"),
            PASS,
            import::CipherProfile::Compat4,
        )
        .unwrap();
        let idx = import::open_desktop_db(
            &dir.join("Core").join("Index.db"),
            PASS,
            import::CipherProfile::Compat4,
        )
        .unwrap();
        let plan = fixture_plan(APPLY_MAPPING_JSON, &src, &idx);
        let store = dir.join("store");
        std::fs::create_dir_all(&store).unwrap();
        drop(fake_shadow_store(&store));
        let conn = open_store(&store);
        let mut stats = ApplyStats::default();
        apply_message_db(
            &conn,
            &src,
            &plan,
            "Core/Message/111.db",
            MapDb::OneToOne,
            Some(111),
            Some(FAKE_OWN),
            500,
            &mut stats,
        )
        .unwrap();
        // Row 103 (uidFrom NULL) received the substitution via the
        // SHARED sender_for rule — counted. Row 104 (uidFrom "0") is
        // also substituted, but it is NOT the NULL case the reviewer
        // asked about, so the count stays 1.
        assert_eq!(stats.uid_from_null_substituted, 1);
        let (s103, s104): (Option<String>, Option<String>) = conn
            .query_row(
                "SELECT (SELECT sender_id FROM messages WHERE msg_id='103'),
                        (SELECT sender_id FROM messages WHERE msg_id='104')",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(s103.as_deref(), Some(FAKE_OWN));
        assert_eq!(s104.as_deref(), Some(FAKE_OWN), "the '0' rule is unchanged");
        // Without an own uid both senders stay NULL and nothing counts.
        let store2 = dir.join("store2");
        std::fs::create_dir_all(&store2).unwrap();
        drop(fake_shadow_store(&store2));
        let conn2 = open_store(&store2);
        let mut stats2 = ApplyStats::default();
        apply_message_db(
            &conn2,
            &src,
            &plan,
            "Core/Message/111.db",
            MapDb::OneToOne,
            Some(111),
            None,
            500,
            &mut stats2,
        )
        .unwrap();
        assert_eq!(
            stats2.uid_from_null_substituted, 0,
            "no substitution without an own uid"
        );
        // R3 (batch 21): close every fixture connection before the
        // cleanup (open handles lock the files on Windows).
        drop(src);
        drop(idx);
        drop(conn);
        drop(conn2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- the progress line -------------------------------------------------

    #[test]
    fn progress_line_carries_counts_only() {
        let mut s = ApplyStats::default();
        s.msgs_applied = 42;
        s.errors = 1;
        assert_eq!(
            progress_line(25, 1473, &s, 7),
            "import apply: dbs=25/1473 msgs_written=42 errors=1 elapsed=7s"
        );
    }
}

