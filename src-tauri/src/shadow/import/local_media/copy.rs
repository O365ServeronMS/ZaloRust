//! Batch 27b M1: `import --local-media-copy` — copy the Zalo PC local
//! media files plan v2 selects into the content-addressed shadow media
//! store, and mark the attachment rows downloaded.
//!
//! A child module of `local_media` on purpose: it reuses the plan's
//! private machinery (`walk_candidate_index`, `gather_candidates`,
//! `choose_candidate`'s helpers, the tolerant Desktop scan) without
//! widening any visibility.
//!
//! Modes: without `--apply` a DRY RUN (the selection report, no
//! writes, the app may keep running); with `--apply
//! --i-have-a-backup-plan` the write path, after these guards in this
//! order — (1) no other zalors.exe, (2) the store opens read-write
//! with the normal key resolution (Locked refuses), (3) the schema
//! version matches, (4) the disk check on the MEDIA root's volume,
//! (5) a verified store backup into `<target>\pre-localmedia-backups\`
//! BEFORE the first write. Real copies only: every file streams
//! through `media::store_stream` (content addressed, magic sniffed,
//! 512 MB cap) and the row is updated through the SAME statement the
//! live download uses (`writer::media_downloaded`).
//!
//! H-rule: no output line carries a path, file name, id, URL, sha or
//! message text — counts, fixed vocabulary (kind, outcome, error
//! kind) and byte sums only.
//!
//! Selection (per import-sourced attachment, plan v2 + the 27b rules):
//! - `downloaded` → `already_downloaded`; any status outside
//!   `ref-import|ref|failed|expired` (i.e. `ref-encrypted`) →
//!   `not_eligible` — never touched;
//! - the message has more than one attachment row of that kind →
//!   `multi_attachment` (the idx↔file order is unknown);
//! - a candidate reached through the resource `cliMsgId` key counts
//!   only when that cliMsgId sits on exactly ONE Desktop message row
//!   across all message DBs, else it is dropped; nothing left because
//!   of that → `ambiguous_key`;
//! - for kinds `file` and `video`, a known (>0) Desktop `fileSize`
//!   must equal the chosen candidate's size exactly, else that
//!   candidate is dropped and the next best is tried; none left →
//!   `size_mismatch`;
//! - the rest are plan v2's outcomes (`no_candidate`,
//!   `magic_mismatch`, `size_excluded`, `would_copy_renderable`,
//!   `would_copy_jxl_only`).

use std::cell::Cell;
use std::collections::{BTreeMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use rusqlite::Connection;

use super::{
    better, choose_candidate, coerce_none_field, fits_filters, gather_candidates, norm_path,
    scan_desktop_rows, walk_candidate_index, CandFacts, CandVia, Candidate, Choice, DeskScan,
    MagicClass, MediaSub, PLAN_COERCE_COLS, WALK_CAP,
};
use crate::shadow::cli::ImportArgs;
use crate::shadow::{backup, media, passphrase, pipeline::sqlite_kind, schema, writer};

/// Statuses a copy may overwrite (the brief's list). `downloaded` and
/// `ref-encrypted` are never touched.
pub const ELIGIBLE_STATUSES: [&str; 4] = ["ref-import", "ref", "failed", "expired"];

/// Commit a transaction every this many successful copies.
pub const COMMIT_EVERY: u32 = 200;
/// Print a counts-only progress line every this many files.
pub const PROGRESS_EVERY: u64 = 1000;
/// The disk check's fixed headroom (1 GiB).
const DISK_HEADROOM: u128 = 1 << 30;

/// One row's selection outcome — plan v2's labels plus the 27b ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Outcome {
    AlreadyDownloaded,
    NotEligible,
    MultiAttachment,
    AmbiguousKey,
    NoCandidate,
    MagicMismatch,
    SizeExcluded,
    SizeMismatch,
    WouldCopyRenderable,
    WouldCopyJxlOnly,
}

impl Outcome {
    pub fn field(self) -> &'static str {
        match self {
            Outcome::AlreadyDownloaded => "already_downloaded",
            Outcome::NotEligible => "not_eligible",
            Outcome::MultiAttachment => "multi_attachment",
            Outcome::AmbiguousKey => "ambiguous_key",
            Outcome::NoCandidate => "no_candidate",
            Outcome::MagicMismatch => "magic_mismatch",
            Outcome::SizeExcluded => "size_excluded",
            Outcome::SizeMismatch => "size_mismatch",
            Outcome::WouldCopyRenderable => "would_copy_renderable",
            Outcome::WouldCopyJxlOnly => "would_copy_jxl_only",
        }
    }
}

/// The fixed print order of the outcome fields.
const OUTCOME_FIELDS: [Outcome; 10] = [
    Outcome::AlreadyDownloaded,
    Outcome::NotEligible,
    Outcome::MultiAttachment,
    Outcome::AmbiguousKey,
    Outcome::NoCandidate,
    Outcome::MagicMismatch,
    Outcome::SizeExcluded,
    Outcome::SizeMismatch,
    Outcome::WouldCopyRenderable,
    Outcome::WouldCopyJxlOnly,
];

/// What the pure selection decided for one row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sel {
    Skip(Outcome),
    /// Copy the candidate at this index of the candidate list.
    Copy { idx: usize, jxl: bool },
}

/// The pure inputs of one row's selection (besides its candidates).
#[derive(Debug, Clone, Copy)]
pub struct SelInput<'a> {
    pub kind: Option<&'a str>,
    pub status: &'a str,
    /// How many attachment rows of THIS kind the message has.
    pub kind_rows_in_msg: u32,
    /// The Desktop `fileSize` (coerced), when known.
    pub desk_file_size: Option<i64>,
    /// Does the row's cliMsgId occur on exactly ONE Desktop message
    /// row across all message DBs?
    pub cli_unique: bool,
}

/// The status / multi-attachment skips — decided BEFORE any candidate
/// is gathered (so a downloaded row never touches the file system).
pub fn pre_skip(status: &str, kind_rows_in_msg: u32) -> Option<Outcome> {
    if status == "downloaded" {
        return Some(Outcome::AlreadyDownloaded);
    }
    if !ELIGIBLE_STATUSES.contains(&status) {
        return Some(Outcome::NotEligible);
    }
    if kind_rows_in_msg > 1 {
        return Some(Outcome::MultiAttachment);
    }
    None
}

/// A candidate reached through the resource `cliMsgId` key: an index
/// entry in the `resource` sub (msgId keys only ever reach
/// picture/video/file; the localPath route is a different `via`).
fn via_cli_key(c: &CandFacts) -> bool {
    c.via == CandVia::Index && c.sub == MediaSub::Resource
}

fn is_jxl(m: MagicClass) -> bool {
    matches!(m, MagicClass::Jxl | MagicClass::JxlContainer)
}

/// The 27b selection, PURE over (row facts, candidate facts) —
/// unit-tested for every arm.
pub fn select(inp: &SelInput<'_>, cands: &[CandFacts]) -> Sel {
    if let Some(o) = pre_skip(inp.status, inp.kind_rows_in_msg) {
        return Sel::Skip(o);
    }
    // The ambiguous-key rule.
    let mut kept: Vec<usize> = Vec::new();
    let mut dropped = false;
    for (i, c) in cands.iter().enumerate() {
        if via_cli_key(c) && !inp.cli_unique {
            dropped = true;
        } else {
            kept.push(i);
        }
    }
    if kept.is_empty() {
        return Sel::Skip(if dropped {
            Outcome::AmbiguousKey
        } else {
            Outcome::NoCandidate
        });
    }
    // Plan v2's empty reasons over what is left.
    let kept_facts: Vec<CandFacts> = kept.iter().map(|&i| cands[i]).collect();
    match choose_candidate(inp.kind, &kept_facts) {
        Choice::NoCandidate => return Sel::Skip(Outcome::NoCandidate),
        Choice::MagicMismatch => return Sel::Skip(Outcome::MagicMismatch),
        Choice::SizeExcluded => return Sel::Skip(Outcome::SizeExcluded),
        _ => {}
    }
    // The size rule (file / video): the chosen candidate's size must
    // equal the Desktop fileSize exactly; a mismatching candidate is
    // dropped and the next best tried — i.e. the best of the fitting
    // candidates that DO match.
    let want: Option<u64> = match inp.kind {
        Some("file") | Some("video") => inp
            .desk_file_size
            .filter(|n| *n > 0)
            .map(|n| n as u64),
        _ => None,
    };
    let mut best: Option<usize> = None;
    for &i in &kept {
        let c = &cands[i];
        if !fits_filters(inp.kind, c) {
            continue;
        }
        if let Some(w) = want {
            if c.size != w {
                continue;
            }
        }
        best = match best {
            Some(b) if !better(c, &cands[b]) => Some(b),
            _ => Some(i),
        };
    }
    match best {
        Some(idx) => Sel::Copy {
            idx,
            jxl: is_jxl(cands[idx].magic),
        },
        None => Sel::Skip(Outcome::SizeMismatch),
    }
}

/// The disk rule: `planned × 1.05 + 1 GiB` must be STRICTLY below the
/// free space. Pure, integer math (the 5% rounds up).
pub fn disk_ok(planned_bytes: u64, free_bytes: u64) -> bool {
    needed_bytes(planned_bytes) < free_bytes as u128
}

/// `planned × 1.05 + 1 GiB`, rounded up.
pub fn needed_bytes(planned_bytes: u64) -> u128 {
    (planned_bytes as u128 * 105).div_ceil(100) + DISK_HEADROOM
}

/// The free-space probe, injectable for tests: free bytes on the
/// volume of the given path (`None` = could not be measured → the
/// check fails closed).
pub type FreeSpaceFn<'a> = &'a dyn Fn(&Path) -> Option<u64>;

/// Everything the copy run needs from its environment, injected so the
/// tests never read the real settings, the process list or the disk.
pub struct CopyEnv<'a> {
    /// The media store root the live media thread writes to.
    pub media_root: PathBuf,
    pub free_space: FreeSpaceFn<'a>,
    /// `Some(true)` another zalors.exe runs; `None` = check failed.
    pub zalors_running: &'a dyn Fn() -> Option<bool>,
}

/// Why one copy failed — the brief's five kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CopyErr {
    Open,
    Io,
    Magic,
    TooBig,
    Store,
}

impl CopyErr {
    fn name(self) -> &'static str {
        match self {
            CopyErr::Open => "open",
            CopyErr::Io => "io",
            CopyErr::Magic => "magic",
            CopyErr::TooBig => "too_big",
            CopyErr::Store => "store",
        }
    }
}

/// Marks a failed READ so an `Io` from `store_stream` can be told
/// apart from a failed temp-file write (`store`).
struct ReadProbe<R> {
    inner: R,
    failed: Rc<Cell<bool>>,
}

impl<R: Read> Read for ReadProbe<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let r = self.inner.read(buf);
        if r.is_err() {
            self.failed.set(true);
        }
        r
    }
}

/// Stream one candidate file into the store. Returns (rel, sha, size).
fn copy_one(
    path: &Path,
    media_root: &Path,
    kind: Option<&str>,
) -> Result<(String, String, u64), CopyErr> {
    let file = std::fs::File::open(path).map_err(|_| CopyErr::Open)?;
    let failed = Rc::new(Cell::new(false));
    let reader = ReadProbe {
        inner: file,
        failed: failed.clone(),
    };
    media::store_stream(reader, media_root, kind).map_err(|e| classify(&e, failed.get()))
}

/// Map a `store_stream` failure to the brief's five error kinds:
/// a sniff mismatch is `magic`, the 512 MB cap `too_big`, an I/O
/// error raised by READING the source `io`, everything else
/// (temp-file create/write, rename) `store`.
fn classify(e: &media::StoreError, read_failed: bool) -> CopyErr {
    match e {
        media::StoreError::Sniff => CopyErr::Magic,
        media::StoreError::TooBig => CopyErr::TooBig,
        media::StoreError::Io(_) if read_failed => CopyErr::Io,
        _ => CopyErr::Store,
    }
}

/// One planned copy.
struct Planned {
    /// `None` = a new video row to INSERT (`--include-video`).
    rowid: Option<i64>,
    msg_id: String,
    kind: Option<String>,
    path: PathBuf,
    size: u64,
}

/// (count, bytes) per outcome.
type Tally = BTreeMap<Outcome, (u64, u64)>;

fn tally_line(tally: &Tally) -> String {
    OUTCOME_FIELDS
        .iter()
        .map(|o| {
            let (n, b) = tally.get(o).copied().unwrap_or((0, 0));
            if matches!(o, Outcome::WouldCopyRenderable | Outcome::WouldCopyJxlOnly) {
                format!("{}={}(bytes={b})", o.field(), n)
            } else {
                format!("{}={}", o.field(), n)
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Mark an attachment downloaded (or INSERT the new video row first)
/// inside a per-item savepoint — the row is untouched on any error.
fn db_apply(
    conn: &Connection,
    pl: &Planned,
    rel: &str,
    sha: &str,
    size: i64,
) -> rusqlite::Result<()> {
    conn.execute_batch("SAVEPOINT item")?;
    let r = (|| -> rusqlite::Result<()> {
        let rowid = match pl.rowid {
            Some(r) => r,
            None => {
                // Minimal NOT NULL satisfaction: attachments requires
                // msg_id, idx and status; kind is set, url / local_path
                // / size / sha256 stay NULL until the update below
                // (a NULL url is never picked by the media thread).
                conn.execute(
                    "INSERT INTO attachments (msg_id, idx, kind, status) \
                     VALUES (?1, 0, 'video', 'ref-import')",
                    [&pl.msg_id],
                )?;
                conn.last_insert_rowid()
            }
        };
        let n = writer::media_downloaded(conn, rowid, rel, sha, size)?;
        if n != 1 {
            return Err(rusqlite::Error::StatementChangedRows(n));
        }
        Ok(())
    })();
    match r {
        Ok(()) => conn.execute_batch("RELEASE item"),
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK TO item; RELEASE item;");
            Err(e)
        }
    }
}

/// The nearest existing ancestor of `p` (the free-space query needs a
/// path that exists).
fn existing_ancestor(p: &Path) -> PathBuf {
    let mut cur = p.to_path_buf();
    while !cur.exists() {
        match cur.parent() {
            Some(par) if !par.as_os_str().is_empty() => cur = par.to_path_buf(),
            _ => break,
        }
    }
    cur
}

fn locked_refusal() -> String {
    "the target store is password-protected (passphrase mode): unlock it in the app with \
     'Nhớ trên máy này' (remember on this machine) enabled, then re-run — the local-media \
     copy CLI never accepts passwords"
        .into()
}

/// The run. `a.apply` picks the mode; every line streams through
/// `out`.
pub fn copy_run(
    a: &ImportArgs,
    root: &Path,
    target: &Path,
    env: &CopyEnv<'_>,
    out: &mut dyn FnMut(&str),
) -> Result<(), String> {
    let apply = a.apply;
    let mode = if apply {
        "local-media-copy apply"
    } else {
        "local-media-copy dry run"
    };
    // Runtime belt (parse enforces too).
    if apply && !a.i_have_a_backup_plan {
        return Err("--apply needs --i-have-a-backup-plan: the copy writes files into the \
                    media store and rows into the shadow store"
            .into());
    }

    // Guard 1: single writer — no other zalors.exe (apply only; the
    // dry run is read-only and the app may keep running). A check
    // that cannot run also refuses (fail closed).
    if apply {
        match (env.zalors_running)() {
            Some(false) => {}
            Some(true) => {
                return Err("refusing: another zalors.exe process is running — quit the app \
                            first (the shadow store has one writer)"
                    .into())
            }
            None => {
                return Err("refusing: cannot verify that no other zalors.exe is running \
                            (tasklist failed) — quit the app and retry"
                    .into())
            }
        }
        out(&format!("{mode}: no other zalors.exe is running"));
    }

    // Guard 2: the store opens (read-write for apply, read-only for
    // the dry run). A Locked passphrase store refuses.
    let db_path = crate::shadow::db_file(target);
    if !db_path.is_file() {
        return Err(format!(
            "--target: no {} — not a shadow store dir?",
            db_path.display()
        ));
    }
    let (conn, store_key) = match passphrase::open_store(target, !apply) {
        Ok(t) => t,
        Err(passphrase::StoreOpenError::Locked) => return Err(locked_refusal()),
        Err(passphrase::StoreOpenError::Other(k)) => {
            return Err(format!(
                "--target: store open failed ({k}) — no key file / broken store?"
            ))
        }
    };
    out(&format!(
        "{mode}: store=given ({})",
        if apply { "read-write" } else { "read-only" }
    ));

    // Guard 3: the schema version.
    let stored_v: i64 = conn
        .query_row("SELECT MAX(version) FROM schema_meta", [], |r| r.get(0))
        .unwrap_or(0);
    if stored_v != schema::VERSION {
        return Err(format!(
            "target schema v{stored_v}, this binary expects v{} — open the store once with the \
             matching zalors build (it migrates on start), quit it, then re-run",
            schema::VERSION
        ));
    }
    out(&format!("{mode}: target schema v{stored_v} matches this binary"));
    out(&format!(
        "{mode}: root=given include_video={} limit={}",
        if a.include_video { "yes" } else { "no" },
        a.limit.map(|n| n.to_string()).unwrap_or_else(|| "none".into())
    ));

    // The snapshot (the usual import guards), after the store so a
    // Locked store fails fast without touching it.
    let p = super::super::prepare(a)?;
    let root_norm = norm_path(&root.to_string_lossy());

    // The store reads (kinds / statuses are shadow vocabulary; ids
    // stay in memory).
    let sqlite_err = |e: rusqlite::Error| format!("store read failed ({})", sqlite_kind(&e));
    struct Att {
        rowid: i64,
        msg_id: String,
        kind: Option<String>,
        status: String,
    }
    let atts: Vec<Att> = {
        let mut st = conn
            .prepare(
                "SELECT a.rowid, a.msg_id, a.kind, a.status
                   FROM attachments a
                   JOIN messages m ON m.msg_id = a.msg_id
                  WHERE m.source = 'import'
                  ORDER BY a.msg_id, a.idx",
            )
            .map_err(sqlite_err)?;
        let rows = st
            .query_map([], |r| {
                Ok(Att {
                    rowid: r.get(0)?,
                    msg_id: r.get(1)?,
                    kind: r.get(2)?,
                    status: r.get(3)?,
                })
            })
            .map_err(sqlite_err)?;
        rows.filter_map(Result::ok).collect()
    };
    let import_msg_ids: Vec<String> = {
        let mut st = conn
            .prepare("SELECT msg_id FROM messages WHERE source = 'import' ORDER BY msg_id")
            .map_err(sqlite_err)?;
        let rows = st
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(sqlite_err)?;
        rows.filter_map(Result::ok).collect()
    };
    let att_msg_ids: HashSet<String> = {
        let mut st = conn
            .prepare("SELECT DISTINCT msg_id FROM attachments")
            .map_err(sqlite_err)?;
        let rows = st
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(sqlite_err)?;
        rows.filter_map(Result::ok).collect()
    };
    // Attachment rows per (message, kind) — ANY status — for the
    // multi_attachment rule.
    let mut per_kind: BTreeMap<(String, Option<String>), u32> = BTreeMap::new();
    for at in &atts {
        *per_kind
            .entry((at.msg_id.clone(), at.kind.clone()))
            .or_insert(0) += 1;
    }

    // The Desktop scan: every message DB once, with the cliMsgId
    // occurrence counts.
    let needed: HashSet<String> = import_msg_ids.iter().cloned().collect();
    let DeskScan {
        desk_rows,
        scan,
        cli_counts,
        ..
    } = scan_desktop_rows(&p, &needed, true)?;
    out(&format!(
        "{mode}: snapshot profile={} message DBs dbs={} opened={} open_failed={} \
         query_failed={} no_table={} rows={} row_failed={} coerce_none={}",
        p.profile.name(),
        scan.dbs,
        scan.opened,
        scan.open_failed,
        scan.query_failed,
        scan.no_table,
        scan.rows,
        scan.row_failed,
        coerce_none_field(&PLAN_COERCE_COLS, &scan.coerce_none)
    ));
    let cli_unique_n = cli_counts.values().filter(|n| **n == 1).count();
    let cli_multi_n = cli_counts.values().filter(|n| **n > 1).count();
    out(&format!(
        "{mode}: cliMsgId census: keys={} on_one_row={} on_several_rows={}",
        cli_counts.len(),
        cli_unique_n,
        cli_multi_n
    ));

    // The candidate index: ONE read-only walk.
    let ix = walk_candidate_index(root);
    out(&format!(
        "{mode}: candidate walk: uids={} uids_with_zalodownloads={} files_seen={} \
         rescache_skipped={} indexed={} cap={} cap_hit={}",
        ix.uids,
        ix.uids_with_zdl,
        ix.files_seen,
        ix.rescache_skipped,
        ix.indexed,
        WALK_CAP,
        if ix.cap_hit { "yes" } else { "no" }
    ));

    // --- the selection ---------------------------------------------------------
    let mut kinds: BTreeMap<String, (u64, Tally)> = BTreeMap::new();
    let mut planned: Vec<Planned> = Vec::new();
    for at in &atts {
        let kind_key = at.kind.clone().unwrap_or_else(|| "none".into());
        let e = kinds.entry(kind_key).or_default();
        e.0 += 1;
        let n_kind = per_kind
            .get(&(at.msg_id.clone(), at.kind.clone()))
            .copied()
            .unwrap_or(1);
        let desk = desk_rows.get(&at.msg_id);
        let sel = if let Some(o) = pre_skip(&at.status, n_kind) {
            Sel::Skip(o)
        } else {
            let cands = gather_candidates(&ix, &root_norm, &at.msg_id, desk);
            let facts: Vec<CandFacts> = cands.iter().map(Candidate::facts).collect();
            let sel = select(
                &SelInput {
                    kind: at.kind.as_deref(),
                    status: &at.status,
                    kind_rows_in_msg: n_kind,
                    desk_file_size: desk.and_then(|d| d.file_size),
                    cli_unique: cli_unique(desk, &cli_counts),
                },
                &facts,
            );
            if let Sel::Copy { idx, .. } = sel {
                planned.push(Planned {
                    rowid: Some(at.rowid),
                    msg_id: at.msg_id.clone(),
                    kind: at.kind.clone(),
                    path: cands[idx].path.clone(),
                    size: cands[idx].size,
                });
                let size = cands[idx].size;
                let o = outcome_of(sel);
                let t = e.1.entry(o).or_insert((0, 0));
                t.0 += 1;
                t.1 += size;
                continue;
            }
            sel
        };
        let Sel::Skip(o) = sel else { unreachable!() };
        e.1.entry(o).or_insert((0, 0)).0 += 1;
    }
    out(&format!(
        "{mode}: import-sourced attachments: rows={} kinds={}",
        atts.len(),
        kinds.len()
    ));
    for (kind, (rows, tally)) in &kinds {
        out(&format!(
            "{mode}: kind={kind} rows={rows} outcomes {}",
            tally_line(tally)
        ));
    }

    // Videos: import messages whose Desktop row is msgType 18 and that
    // have NO attachment row.
    let mut v_tally: Tally = BTreeMap::new();
    let mut v_msgs = 0u64;
    let mut v_new: Vec<Planned> = Vec::new();
    for mid in &import_msg_ids {
        let Some(d) = desk_rows.get(mid) else {
            continue;
        };
        if d.msg_type != Some(18) || att_msg_ids.contains(mid) {
            continue;
        }
        v_msgs += 1;
        let cands = gather_candidates(&ix, &root_norm, mid, Some(d));
        let facts: Vec<CandFacts> = cands.iter().map(Candidate::facts).collect();
        let sel = select(
            &SelInput {
                kind: Some("video"),
                status: "ref-import",
                kind_rows_in_msg: 0,
                desk_file_size: d.file_size,
                cli_unique: cli_unique(Some(d), &cli_counts),
            },
            &facts,
        );
        match sel {
            Sel::Copy { idx, .. } => {
                let t = v_tally.entry(outcome_of(sel)).or_insert((0, 0));
                t.0 += 1;
                t.1 += cands[idx].size;
                v_new.push(Planned {
                    rowid: None,
                    msg_id: mid.clone(),
                    kind: Some("video".into()),
                    path: cands[idx].path.clone(),
                    size: cands[idx].size,
                });
            }
            Sel::Skip(o) => v_tally.entry(o).or_insert((0, 0)).0 += 1,
        }
    }
    out(&format!(
        "{mode}: videos (msgType 18, no attachment row): messages={v_msgs} outcomes {} \
         rows_to_insert={} ({})",
        tally_line(&v_tally),
        v_new.len(),
        if a.include_video {
            "--include-video: they are inserted and copied"
        } else {
            "counted only; add --include-video to insert and copy them"
        }
    ));
    if a.include_video {
        planned.extend(v_new);
    }

    // --limit N: stop after N copies. The disk check and the planned
    // totals count the first N planned files; the loop itself stops
    // after N SUCCESSFUL copies (a failed file does not use one up).
    let take = a.limit.map(|n| n as usize).unwrap_or(usize::MAX);
    let planned_bytes: u64 = planned.iter().take(take).map(|p| p.size).sum();
    let planned_video_rows = planned.iter().take(take).filter(|p| p.rowid.is_none()).count();
    out(&format!(
        "{mode}: planned: files={} bytes={planned_bytes} new_video_rows={planned_video_rows}",
        planned.len().min(take)
    ));

    // The disk check numbers (the media root's volume).
    let probe = existing_ancestor(&env.media_root);
    let free = (env.free_space)(&probe);
    let disk_pass = match free {
        Some(f) => disk_ok(planned_bytes, f),
        None => false,
    };
    out(&format!(
        "{mode}: disk check: needed_bytes={} (planned x 1.05 + 1 GiB) result={}",
        needed_bytes(planned_bytes),
        match free {
            Some(_) if disk_pass => "ok",
            Some(_) => "NOT ENOUGH FREE SPACE",
            None => "free space unmeasurable",
        }
    ));

    if !apply {
        out(&format!(
            "{mode}: done (DRY RUN — nothing was written; add --apply --i-have-a-backup-plan \
             to copy)"
        ));
        return Ok(());
    }

    // --- apply -----------------------------------------------------------------
    if planned.is_empty() {
        out(&format!(
            "{mode}: nothing to copy — no backup made, no writes (idempotent)"
        ));
        out(&format!("{mode}: copied=0 bytes=0"));
        return Ok(());
    }
    // Guard 4: the disk check.
    if free.is_none() {
        return Err("disk check: cannot measure the free space of the media root's volume — \
                    no writes were performed"
            .into());
    }
    if !disk_pass {
        return Err(format!(
            "disk check: not enough free space on the media root's volume (needs planned bytes \
             x 1.05 + 1 GiB = {} bytes, planned bytes = {planned_bytes}) — no writes were \
             performed",
            needed_bytes(planned_bytes)
        ));
    }
    // Guard 5: the verified backup, BEFORE the first write.
    let backup_dir = target.join("pre-localmedia-backups");
    let mut now = schema::now_ms();
    while backup::backup_db_path(&backup_dir, now).exists() {
        now += 1_000;
    }
    let manifest = backup::backup_db(&conn, &store_key.backup_key(), &backup_dir, now)
        .map_err(|k| format!("pre-localmedia backup failed ({k}) — no writes were performed"))?;
    let backup_path = backup::backup_db_path(&backup_dir, now);
    backup::verify_backup(&backup_path, &store_key.backup_key(), &manifest).map_err(|k| {
        format!("pre-localmedia backup verify failed ({k}) — no writes were performed")
    })?;
    out(&format!(
        "{mode}: backup verified OK in <target>\\pre-localmedia-backups (sha+integrity+counts)"
    ));

    // The copy loop. The media root must exist (store_stream writes
    // its temp file directly under it).
    std::fs::create_dir_all(&env.media_root)
        .map_err(|_| "media root: cannot create the directory — no writes were performed".to_string())?;
    conn.execute_batch("BEGIN IMMEDIATE")
        .map_err(|e| format!("BEGIN IMMEDIATE failed: {}", sqlite_kind(&e)))?;
    let (mut copied, mut bytes, mut inserted, mut in_tx) = (0u64, 0u64, 0u64, 0u32);
    let mut errors: BTreeMap<CopyErr, u64> = BTreeMap::new();
    let mut processed = 0u64;
    for pl in &planned {
        processed += 1;
        match copy_one(&pl.path, &env.media_root, pl.kind.as_deref()) {
            Ok((rel, sha, size)) => match db_apply(&conn, pl, &rel, &sha, size as i64) {
                Ok(()) => {
                    copied += 1;
                    bytes += size;
                    if pl.rowid.is_none() {
                        inserted += 1;
                    }
                    in_tx += 1;
                    if in_tx >= COMMIT_EVERY {
                        conn.execute_batch("COMMIT; BEGIN IMMEDIATE").map_err(|e| {
                            let _ = conn.execute_batch("ROLLBACK");
                            format!("commit failed: {}", sqlite_kind(&e))
                        })?;
                        in_tx = 0;
                    }
                }
                Err(e) => {
                    // A statement that aborted the whole transaction
                    // leaves autocommit on: stop (nothing after it may
                    // land outside a transaction).
                    if conn.is_autocommit() {
                        return Err(format!(
                            "the transaction was aborted by a failing statement ({}) — rows \
                             since the last commit were not saved; the store is otherwise \
                             unchanged since the backup",
                            sqlite_kind(&e)
                        ));
                    }
                    *errors.entry(CopyErr::Store).or_insert(0) += 1;
                }
            },
            Err(k) => *errors.entry(k).or_insert(0) += 1,
        }
        if processed % PROGRESS_EVERY == 0 {
            out(&format!(
                "{mode}: progress files={processed} copied={copied} errors={} bytes={bytes}",
                errors.values().sum::<u64>()
            ));
        }
        if let Some(n) = a.limit {
            if copied >= n {
                break;
            }
        }
    }
    conn.execute_batch("COMMIT")
        .map_err(|e| format!("COMMIT failed: {}", sqlite_kind(&e)))?;

    let err_fields = [
        CopyErr::Open,
        CopyErr::Io,
        CopyErr::Magic,
        CopyErr::TooBig,
        CopyErr::Store,
    ]
    .iter()
    .map(|k| format!("{}={}", k.name(), errors.get(k).copied().unwrap_or(0)))
    .collect::<Vec<_>>()
    .join(" ");
    out(&format!(
        "{mode}: copied={copied} bytes_copied={bytes} errors {err_fields}"
    ));
    out(&format!("{mode}: video rows inserted={inserted}"));

    // Post-run integrity (the repair convention).
    let integrity: String = conn
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .map_err(|e| format!("integrity_check failed: {}", sqlite_kind(&e)))?;
    out(&format!("{mode}: integrity_check={integrity}"));
    if integrity != "ok" {
        return Err("integrity_check is not ok after the copy — restore from the \
                    pre-localmedia backup"
            .into());
    }
    out(&format!("{mode}: done"));
    Ok(())
}

/// Does the row's cliMsgId occur on exactly one Desktop message row?
/// (A row without a cliMsgId has no resource candidates at all, so the
/// answer is irrelevant — `true`.)
fn cli_unique(
    desk: Option<&super::DeskRow>,
    counts: &std::collections::HashMap<String, u32>,
) -> bool {
    match desk.and_then(|d| d.cli_msg_id.as_ref()) {
        Some(c) => counts.get(c).copied() == Some(1),
        None => true,
    }
}

fn outcome_of(sel: Sel) -> Outcome {
    match sel {
        Sel::Skip(o) => o,
        Sel::Copy { jxl: true, .. } => Outcome::WouldCopyJxlOnly,
        Sel::Copy { jxl: false, .. } => Outcome::WouldCopyRenderable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cf(sub: MediaSub, via: CandVia, size: u64, magic: MagicClass) -> CandFacts {
        CandFacts {
            sub,
            via,
            size,
            magic,
        }
    }

    fn inp<'a>(kind: &'a str, status: &'a str) -> SelInput<'a> {
        SelInput {
            kind: Some(kind),
            status,
            kind_rows_in_msg: 1,
            desk_file_size: None,
            cli_unique: true,
        }
    }

    const IDX: CandVia = CandVia::Index;

    #[test]
    fn only_the_four_statuses_are_eligible() {
        let c = [cf(MediaSub::Picture, IDX, 10, MagicClass::Jpg)];
        for s in ["ref-import", "ref", "failed", "expired"] {
            assert!(
                matches!(select(&inp("image", s), &c), Sel::Copy { idx: 0, jxl: false }),
                "{s}"
            );
        }
        assert_eq!(
            select(&inp("image", "downloaded"), &c),
            Sel::Skip(Outcome::AlreadyDownloaded)
        );
        assert_eq!(
            select(&inp("image", "ref-encrypted"), &c),
            Sel::Skip(Outcome::NotEligible)
        );
        assert_eq!(
            select(&inp("image", "something-new"), &c),
            Sel::Skip(Outcome::NotEligible)
        );
        // The pre-skip never needs candidates.
        assert_eq!(pre_skip("downloaded", 9), Some(Outcome::AlreadyDownloaded));
        assert_eq!(pre_skip("ref-encrypted", 1), Some(Outcome::NotEligible));
        assert_eq!(pre_skip("ref", 2), Some(Outcome::MultiAttachment));
        assert_eq!(pre_skip("ref", 1), None);
        assert_eq!(pre_skip("ref", 0), None);
    }

    #[test]
    fn multi_attachment_skips_before_any_candidate() {
        let c = [cf(MediaSub::Picture, IDX, 10, MagicClass::Jpg)];
        let mut i = inp("image", "ref-import");
        i.kind_rows_in_msg = 2;
        assert_eq!(select(&i, &c), Sel::Skip(Outcome::MultiAttachment));
        // …even with no candidates at all.
        assert_eq!(select(&i, &[]), Sel::Skip(Outcome::MultiAttachment));
    }

    #[test]
    fn a_cli_key_candidate_needs_a_unique_cli_msg_id() {
        let res = cf(MediaSub::Resource, IDX, 5, MagicClass::Jpg);
        let pic = cf(MediaSub::Picture, IDX, 3, MagicClass::Jpg);
        let mut i = inp("image", "ref-import");
        // Unique: the resource candidate counts (and the picture
        // still wins on the sub rule).
        assert_eq!(select(&i, &[res]), Sel::Copy { idx: 0, jxl: false });
        i.cli_unique = false;
        // Ambiguous and nothing else: ambiguous_key.
        assert_eq!(select(&i, &[res]), Sel::Skip(Outcome::AmbiguousKey));
        // Ambiguous but a msgId-keyed picture remains: it wins.
        assert_eq!(select(&i, &[res, pic]), Sel::Copy { idx: 1, jxl: false });
        // No candidates at all is no_candidate, not ambiguous_key.
        assert_eq!(select(&i, &[]), Sel::Skip(Outcome::NoCandidate));
        // The localPath route into the resource sub is NOT a cli-key
        // candidate (a different via): it survives an ambiguous key.
        let lp = cf(MediaSub::Resource, CandVia::LocalPath, 5, MagicClass::Jpg);
        assert_eq!(select(&i, &[lp]), Sel::Copy { idx: 0, jxl: false });
    }

    #[test]
    fn ambiguous_key_loses_to_the_empty_reasons_of_what_is_left() {
        let res = cf(MediaSub::Resource, IDX, 5, MagicClass::Jpg);
        // What is left is an mp4 in an image row: magic_mismatch.
        let bad = cf(MediaSub::Picture, IDX, 5, MagicClass::Mp4);
        let mut i = inp("image", "ref-import");
        i.cli_unique = false;
        assert_eq!(select(&i, &[res, bad]), Sel::Skip(Outcome::MagicMismatch));
    }

    #[test]
    fn size_mismatch_applies_to_file_and_video_only() {
        let c = [cf(MediaSub::File, IDX, 100, MagicClass::Other)];
        // file: known fileSize must match exactly.
        let mut i = inp("file", "ref-import");
        i.desk_file_size = Some(100);
        assert_eq!(select(&i, &c), Sel::Copy { idx: 0, jxl: false });
        i.desk_file_size = Some(99);
        assert_eq!(select(&i, &c), Sel::Skip(Outcome::SizeMismatch));
        // Unknown or non-positive fileSize: no size rule.
        i.desk_file_size = None;
        assert_eq!(select(&i, &c), Sel::Copy { idx: 0, jxl: false });
        i.desk_file_size = Some(0);
        assert_eq!(select(&i, &c), Sel::Copy { idx: 0, jxl: false });
        i.desk_file_size = Some(-5);
        assert_eq!(select(&i, &c), Sel::Copy { idx: 0, jxl: false });
        // image: the rule does not apply even with a differing size.
        let mut img = inp("image", "ref-import");
        img.desk_file_size = Some(1);
        let ic = [cf(MediaSub::Picture, IDX, 100, MagicClass::Jpg)];
        assert_eq!(select(&img, &ic), Sel::Copy { idx: 0, jxl: false });
        // video: it does.
        let mut v = inp("video", "ref-import");
        v.desk_file_size = Some(7);
        let vc = [cf(MediaSub::Video, IDX, 100, MagicClass::Mp4)];
        assert_eq!(select(&v, &vc), Sel::Skip(Outcome::SizeMismatch));
        v.desk_file_size = Some(100);
        assert_eq!(select(&v, &vc), Sel::Copy { idx: 0, jxl: false });
    }

    #[test]
    fn size_mismatch_falls_back_to_the_next_best_candidate() {
        // The best by preference (video sub, larger) has the wrong
        // size; the resource copy matches the Desktop fileSize.
        let big = cf(MediaSub::Video, IDX, 500, MagicClass::Mp4);
        let small = cf(MediaSub::Resource, IDX, 300, MagicClass::Mp4);
        let mut i = inp("video", "ref-import");
        i.desk_file_size = Some(300);
        assert_eq!(select(&i, &[big, small]), Sel::Copy { idx: 1, jxl: false });
        // Both match in size: the preference order decides (video sub).
        let big2 = cf(MediaSub::Video, IDX, 300, MagicClass::Mp4);
        assert_eq!(select(&i, &[small, big2]), Sel::Copy { idx: 1, jxl: false });
        // Neither matches.
        i.desk_file_size = Some(1);
        assert_eq!(select(&i, &[big, small]), Sel::Skip(Outcome::SizeMismatch));
    }

    #[test]
    fn plan_v2_outcomes_survive() {
        let i = inp("image", "failed");
        assert_eq!(select(&i, &[]), Sel::Skip(Outcome::NoCandidate));
        assert_eq!(
            select(&i, &[cf(MediaSub::Picture, IDX, 5, MagicClass::Mp4)]),
            Sel::Skip(Outcome::MagicMismatch)
        );
        assert_eq!(
            select(&i, &[cf(MediaSub::Picture, IDX, 0, MagicClass::Jpg)]),
            Sel::Skip(Outcome::SizeExcluded)
        );
        // JXL only → copy, flagged jxl; renderable beats JXL.
        let jxl = cf(MediaSub::Picture, IDX, 9, MagicClass::Jxl);
        let jpg = cf(MediaSub::Resource, IDX, 4, MagicClass::Jpg);
        assert_eq!(select(&i, &[jxl]), Sel::Copy { idx: 0, jxl: true });
        assert_eq!(select(&i, &[jxl, jpg]), Sel::Copy { idx: 1, jxl: false });
    }

    #[test]
    fn disk_rule_is_planned_times_1_05_plus_1_gib_strictly_below_free() {
        let gib: u128 = 1 << 30;
        assert_eq!(needed_bytes(0), gib);
        assert_eq!(needed_bytes(100), 105 + gib);
        assert_eq!(needed_bytes(1), 2 + gib); // 1.05 rounds UP to 2
        let need = needed_bytes(1_000_000) as u64;
        assert!(!disk_ok(1_000_000, need)); // equal is NOT enough
        assert!(disk_ok(1_000_000, need + 1));
        assert!(!disk_ok(1_000_000, 0));
        assert!(!disk_ok(0, 1 << 30)); // exactly the headroom: refuse
        assert!(disk_ok(0, (1 << 30) + 1));
    }

    #[test]
    fn outcome_fields_are_the_fixed_vocabulary() {
        let names: Vec<&str> = OUTCOME_FIELDS.iter().map(|o| o.field()).collect();
        assert_eq!(
            names,
            [
                "already_downloaded",
                "not_eligible",
                "multi_attachment",
                "ambiguous_key",
                "no_candidate",
                "magic_mismatch",
                "size_excluded",
                "size_mismatch",
                "would_copy_renderable",
                "would_copy_jxl_only"
            ]
        );
    }

    #[test]
    fn tally_line_prints_bytes_only_for_the_copy_outcomes() {
        let mut t: Tally = BTreeMap::new();
        t.insert(Outcome::WouldCopyRenderable, (2, 30));
        t.insert(Outcome::SizeMismatch, (1, 0));
        let l = tally_line(&t);
        assert!(l.contains("would_copy_renderable=2(bytes=30)"), "{l}");
        assert!(l.contains("size_mismatch=1 "), "{l}");
        assert!(l.contains("would_copy_jxl_only=0(bytes=0)"), "{l}");
    }

    #[test]
    fn existing_ancestor_walks_up_to_something_that_exists() {
        let tmp = std::env::temp_dir();
        let deep = tmp.join("zr-no-such-a").join("b").join("c");
        assert_eq!(existing_ancestor(&deep), tmp);
        assert_eq!(existing_ancestor(&tmp), tmp);
    }

    #[test]
    fn store_errors_map_to_the_five_kinds() {
        use media::StoreError as E;
        let io = || std::io::Error::other("x");
        assert_eq!(classify(&E::Sniff, false), CopyErr::Magic);
        assert_eq!(classify(&E::TooBig, false), CopyErr::TooBig);
        assert_eq!(classify(&E::Io(io()), true), CopyErr::Io);
        assert_eq!(classify(&E::Io(io()), false), CopyErr::Store);
        assert_eq!(classify(&E::Other("rename".into()), false), CopyErr::Store);
        assert_eq!(classify(&E::Other("rename".into()), true), CopyErr::Store);
        let names: Vec<&str> = [
            CopyErr::Open,
            CopyErr::Io,
            CopyErr::Magic,
            CopyErr::TooBig,
            CopyErr::Store,
        ]
        .iter()
        .map(|k| k.name())
        .collect();
        assert_eq!(names, ["open", "io", "magic", "too_big", "store"]);
    }

    #[test]
    fn copy_one_counts_open_and_magic_errors_and_leaves_no_temp() {
        let dir = std::env::temp_dir().join(format!(
            "zr-copy-one-{}-{}",
            std::process::id(),
            crate::shadow::schema::now_ms()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let media_root = dir.join("media");
        std::fs::create_dir_all(&media_root).unwrap();
        // open: a missing file.
        assert_eq!(
            copy_one(&dir.join("missing"), &media_root, Some("image")).unwrap_err(),
            CopyErr::Open
        );
        // magic: an image row whose bytes are not an image.
        let bad = dir.join("plain");
        std::fs::write(&bad, b"plain text, no magic").unwrap();
        assert_eq!(
            copy_one(&bad, &media_root, Some("image")).unwrap_err(),
            CopyErr::Magic
        );
        // …the same bytes copy fine for a `file` row (no sniff), into
        // the content-addressed layout.
        let (rel, sha, size) = copy_one(&bad, &media_root, Some("file")).unwrap();
        assert_eq!(size, 20);
        assert_eq!(rel, format!("{}/{}/{}", &sha[..2], &sha[2..4], sha));
        assert_eq!(std::fs::read(media_root.join(&rel)).unwrap(), b"plain text, no magic");
        // store: a media root that is not a directory.
        assert_eq!(
            copy_one(&bad, &dir.join("no-such-root"), Some("file")).unwrap_err(),
            CopyErr::Store
        );
        // No temp file survives any of it.
        let tmps = std::fs::read_dir(&media_root)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .count();
        assert_eq!(tmps, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_probe_flags_a_failed_read_only() {
        struct Bad;
        impl Read for Bad {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("x"))
            }
        }
        let flag = Rc::new(Cell::new(false));
        let mut p = ReadProbe {
            inner: Bad,
            failed: flag.clone(),
        };
        let mut b = [0u8; 4];
        assert!(p.read(&mut b).is_err());
        assert!(flag.get());
        let flag2 = Rc::new(Cell::new(false));
        let mut ok = ReadProbe {
            inner: &b"abc"[..],
            failed: flag2.clone(),
        };
        assert_eq!(ok.read(&mut b).unwrap(), 3);
        assert!(!flag2.get());
    }
}
