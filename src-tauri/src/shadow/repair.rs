//! One-time data repair for shadow DB v1 rows written BEFORE the H3/H4
//! writer fixes (audit 2026-11-19 §1.2 / T8).
//!
//! NOT wired into `runtime` or startup: repairs rewrite live data and
//! must only run from an explicit maintenance entry point or a test,
//! after a backup (audit §1.2's "Migration 1 lần" note). Run the
//! [`repair_v1_dry_run`] first and compare reports; the `maint_repair`
//! ignored test runs both against a temp COPY of the live store; the
//! guarded `zalors repair` CLI (batch 20, `repair_cli.rs`) is the user
//! entry point.
//!
//! Batch 20 (S1): every step now has ONE implementation
//! (`repair_v1_impl`) behind two error policies. The old
//! [`repair_v1`]/[`repair_v1_dry_run`] keep their swallow-and-count
//! behaviour (a step's failure contributes today's zero/partial
//! value); the new [`repair_v1_checked`]/[`repair_v1_dry_run_checked`]
//! abort at the FIRST SQL failure and report a [`RepairError`] — a
//! step NAME plus the sqlite error KIND, never row data.
//!
//! Scope (deliberately narrow):
//! - create conversation stubs for orphan messages (H4-e);
//! - recompute `conversations.last_msg_id`/`last_ts` from the newest
//!   message by ts (H4-d);
//! - fill `messages.content_hash` where NULL (H4-f), using the exact
//!   digest the writer now stores so later replays compare like with
//!   like;
//! - recompute `messages.type` from the payload msgType through the
//!   SAME table the writer uses (B6/H1) — so V1 rows (0/1/2/5/8/9/99
//!   codes) and 100-bucket rows land on the batch-2/25 codes; a
//!   repair re-run after batch 25 also moves rows whose payload
//!   msgType is one of the newly-coded strings (chat.list.action /
//!   chat.ecard / group.poll / chat.todo → 14-17, chat.undo /
//!   chat.delete.everyone → 8, chat.webcontent.v2 → 9) off the 100
//!   bucket;
//! - (e) KQ2 backfill: fill `sender_id` for self-sent rows stuck at
//!   NULL from the configured own uid (audit §1.2 migration bullet);
//! - (f) H4 ping-pong revisions: delete edit revisions whose payload
//!   hashes (with the SAME `writer::content_hash`) equal the message's
//!   CURRENT payload — representation-only noise — then set each
//!   touched message's `rev` to the number of remaining revisions.
//!   Recall/delete revisions are never touched.
//! - (g, batch 26 M3) import media requeue: attachment rows whose
//!   message is import-sourced but whose status is still a LIVE-queue
//!   one (`ref`/`failed` — the pre-batch-26 import wrote them) move to
//!   `ref-import`, the history queue the live media thread never
//!   picks. `downloaded`/`ref-encrypted`/`expired` rows are untouched
//!   (a real download is never demoted); idempotent — a second run
//!   reports 0.

use rusqlite::Connection;
use serde_json::Value;

use super::pipeline::sqlite_kind;
use super::{account, normalize, schema, writer};

/// What `repair_v1` changed. All counters: no row data ever leaves this
/// module (H-rule: counts only).
#[derive(Debug, Default, Clone, PartialEq)]
pub struct RepairReport {
    pub conv_stubs_created: usize,
    pub last_msg_fixed: usize,
    pub content_hash_filled: usize,
    /// B6/H1: rows whose `type` was recomputed from the payload msgType.
    pub types_remapped: usize,
    /// (e) KQ2: self-sent rows (payload uidFrom='0') whose NULL sender
    /// was filled from the configured own uid.
    pub senders_backfilled: usize,
    /// (f) H4: representation-only edit revisions deleted.
    pub revisions_pruned: usize,
    /// (f) H4: touched messages whose `rev` was set to the remaining
    /// revision count.
    pub revs_reset: usize,
    /// (g, batch 26 M3) import-sourced attachment rows moved from the
    /// live queue (`ref`/`failed`) to the history queue
    /// (`ref-import`). The LAST field — the report line appends only.
    pub media_import_requeued: usize,
}

/// Step names carried by [`RepairError::step`] — one per repair step
/// (a)-(g), plus the dry run's BEGIN. Stable strings: the CLI prints
/// them verbatim in its failure line.
pub const STEP_CONV_STUBS: &str = "conv_stubs";
pub const STEP_LAST_MSG: &str = "last_msg";
pub const STEP_CONTENT_HASH: &str = "content_hash";
pub const STEP_TYPE_REMAP: &str = "type_remap";
pub const STEP_SENDER_BACKFILL: &str = "sender_backfill";
pub const STEP_REV_PRUNE: &str = "rev_prune";
/// (g, batch 26 M3) the import media requeue.
pub const STEP_MEDIA_REQUEUE: &str = "media_requeue";
/// The dry run's `BEGIN IMMEDIATE`.
pub const STEP_BEGIN: &str = "begin";

/// Why a repair step failed (batch 20 S1): the step NAME plus the
/// sqlite error KIND (`pipeline::sqlite_kind`) — never row data, ids,
/// paths or sqlite error text (H-rule).
#[derive(Debug, Clone, PartialEq)]
pub struct RepairError {
    /// Which step failed (a [`STEP_*`](self) constant).
    pub step: &'static str,
    /// The sqlite error kind, e.g. `sqlite_SQLError/1`.
    pub kind: String,
}

fn rerr(step: &'static str, e: &rusqlite::Error) -> RepairError {
    RepairError {
        step,
        kind: sqlite_kind(e),
    }
}

/// Run the v1 repair. Idempotent: a second run over a repaired DB
/// reports zero everywhere. `own_uid` gates step (e): `Some(valid uid)`
/// backfills self-sent senders (KQ2), `None` (or a bad-shaped uid)
/// skips it. Per-step failures are counted as "nothing done for that
/// step" — this is a maintenance helper, not a pipeline path (the
/// pipeline's no-swallowed-errors rule lives in
/// `pipeline::process_batch`). Batch 20: the steps are ONE
/// implementation shared with [`repair_v1_checked`]; this is the count
/// policy, byte-for-byte the pre-batch-20 behaviour.
pub fn repair_v1(conn: &Connection, own_uid: Option<&str>) -> RepairReport {
    repair_v1_impl(conn, own_uid, false).0
}

/// (S1, batch 20) The error-propagating variant a LIVE apply drives:
/// the first SQL failure of any step aborts the pass and comes back
/// as a [`RepairError`] — the step NAME plus the sqlite error KIND,
/// never row data. Every step runs exactly as [`repair_v1`]; the
/// partial work before the failure is the caller's to undo (the CLI
/// wraps this in one `BEGIN IMMEDIATE … COMMIT/ROLLBACK`).
pub fn repair_v1_checked(
    conn: &Connection,
    own_uid: Option<&str>,
) -> Result<RepairReport, RepairError> {
    match repair_v1_impl(conn, own_uid, true) {
        (r, None) => Ok(r),
        (_, Some(e)) => Err(e),
    }
}

/// Collect `query_map` rows under the error policy: the count policy
/// keeps the pre-batch-20 per-row skip (`filter_map(Result::ok)`); the
/// checked policy turns the first row-read failure into the step's
/// error.
fn gather_rows<T>(
    it: impl Iterator<Item = rusqlite::Result<T>>,
    fail_fast: bool,
    step: &'static str,
) -> Result<Vec<T>, RepairError> {
    let mut out = Vec::new();
    for row in it {
        match row {
            Ok(v) => out.push(v),
            Err(e) => {
                if fail_fast {
                    return Err(RepairError {
                        step,
                        kind: sqlite_kind(&e),
                    });
                }
                // Count policy: today's silent row skip.
            }
        }
    }
    Ok(out)
}

/// The ONE implementation of every repair step. `fail_fast` selects
/// the error policy:
///
/// - `false` (the [`repair_v1`] policy): a step's own SQL failure
///   contributes exactly the pre-batch-20 value (zero rows / empty
///   vec / today's partial tuple), later steps still run, and the
///   first failure is recorded in the second tuple slot (nothing
///   consumed that slot before batch 20; the probe ignores it).
/// - `true` (the [`repair_v1_checked`] policy): the FIRST SQL failure
///   — statement or row read — aborts the pass and is returned; no
///   later step runs. A live apply rolls its whole transaction back
///   anyway, so stop-at-first-error is the safe shape.
///
/// Step (c) selects `payload_json` as `Option<String>` (NULL → skip):
/// identical to the rows the pre-batch-20 `filter_map(Result::ok)`
/// dropped, under BOTH policies.
fn repair_v1_impl(
    conn: &Connection,
    own_uid: Option<&str>,
    fail_fast: bool,
) -> (RepairReport, Option<RepairError>) {
    let mut r = RepairReport::default();
    let mut first_err: Option<RepairError> = None;

    /// One fallible statement site: abort (checked policy) or record
    /// the first error and yield the count policy's exact
    /// pre-batch-20 default.
    macro_rules! soft {
        ($step:expr, $expr:expr, $default:expr) => {
            match $expr {
                Ok(v) => v,
                Err(e) => {
                    let err = rerr($step, &e);
                    if fail_fast {
                        return (r, Some(err));
                    }
                    first_err.get_or_insert(err);
                    $default
                }
            }
        };
    }
    /// The same, for an error value already in hand.
    macro_rules! soft_err {
        ($step:expr, $e:expr, $default:expr) => {{
            let err = rerr($step, &$e);
            if fail_fast {
                return (r, Some(err));
            }
            first_err.get_or_insert(err);
            $default
        }};
    }

    // (a) H4-e: stub every conversation a message references but no
    // conversations row names. Same stub shape as the writer's Message
    // arm (type 0, unread 0).
    let orphans: Vec<String> = match conn.prepare(
        "SELECT DISTINCT m.conv_id FROM messages m
         LEFT JOIN conversations c ON c.id = m.conv_id
         WHERE c.id IS NULL",
    ) {
        Ok(mut st) => match st.query_map([], |row| row.get::<_, String>(0)) {
            Ok(it) => match gather_rows(it, fail_fast, STEP_CONV_STUBS) {
                Ok(v) => v,
                // gather_rows only errs under the checked policy.
                Err(e) => return (r, Some(e)),
            },
            Err(e) => soft_err!(STEP_CONV_STUBS, e, Vec::new()),
        },
        Err(e) => soft_err!(STEP_CONV_STUBS, e, Vec::new()),
    };
    for id in &orphans {
        let n = soft!(
            STEP_CONV_STUBS,
            conn.execute(
                "INSERT OR IGNORE INTO conversations (id, type, unread, updated_at)
                 VALUES (?1, 0, 0, ?2)",
                rusqlite::params![id, schema::now_ms()],
            ),
            0
        );
        r.conv_stubs_created += n;
    }

    // (b) H4-d: point last_msg_id/last_ts at the newest message by ts
    // (ties broken by msg_id, so the result is insertion-order
    // independent). Only rows whose pointers actually change are
    // counted, hence a second run reports 0.
    r.last_msg_fixed = soft!(
        STEP_LAST_MSG,
        conn.execute(
            "UPDATE conversations
                SET last_msg_id = (SELECT m.msg_id FROM messages m
                                    WHERE m.conv_id = conversations.id
                                    ORDER BY m.ts DESC, m.msg_id DESC LIMIT 1),
                    last_ts    = (SELECT MAX(m.ts) FROM messages m
                                   WHERE m.conv_id = conversations.id)
              WHERE EXISTS (SELECT 1 FROM messages m WHERE m.conv_id = conversations.id)
                AND (conversations.last_msg_id IS NULL
                     OR conversations.last_msg_id <>
                        (SELECT m.msg_id FROM messages m
                          WHERE m.conv_id = conversations.id
                          ORDER BY m.ts DESC, m.msg_id DESC LIMIT 1)
                     OR conversations.last_ts IS NULL
                     OR conversations.last_ts <>
                        (SELECT MAX(m.ts) FROM messages m
                          WHERE m.conv_id = conversations.id))",
            [],
        ),
        0
    );

    // (c) H4-f: fill content_hash for legacy rows (same digest the
    // writer now stores on insert). `payload_json` reads as
    // Option<String>: a NULL payload is skipped — exactly the rows the
    // pre-batch-20 row-level drop removed.
    {
        let rows: Vec<(i64, Option<String>)> = match conn
            .prepare("SELECT rowid, payload_json FROM messages WHERE content_hash IS NULL")
        {
            Ok(mut st) => match st.query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, Option<String>>(1)?))
            }) {
                Ok(it) => match gather_rows(it, fail_fast, STEP_CONTENT_HASH) {
                    Ok(v) => v,
                    Err(e) => return (r, Some(e)),
                },
                Err(e) => soft_err!(STEP_CONTENT_HASH, e, Vec::new()),
            },
            Err(e) => soft_err!(STEP_CONTENT_HASH, e, Vec::new()),
        };
        for (rowid, payload) in rows {
            // Invalid/absent JSON keeps a NULL hash (the writer's
            // first-fill rule then treats the row as legacy, never an
            // edit).
            let Some(p) = payload else { continue };
            let Some(h) = writer::content_hash(&p) else { continue };
            let n = soft!(
                STEP_CONTENT_HASH,
                conn.execute(
                    "UPDATE messages SET content_hash = ?2
                      WHERE rowid = ?1 AND content_hash IS NULL",
                    rusqlite::params![rowid, h],
                ),
                0
            );
            r.content_hash_filled += n;
        }
    }

    // (d) B6/H1: recompute `messages.type` from the payload msgType —
    // row by row in Rust through normalize::msg_type_code, the SAME
    // table the writer uses (single source of truth: a SQL CASE here
    // could drift from it). Rows with NULL/invalid JSON payloads keep
    // their stored type (nothing to recompute from); the UPDATE only
    // lands where the code really differs, so a second run reports 0.
    {
        let rows: Vec<(i64, Option<String>, i64)> = match conn
            .prepare("SELECT rowid, payload_json, type FROM messages")
        {
            Ok(mut st) => match st.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            }) {
                Ok(it) => match gather_rows(it, fail_fast, STEP_TYPE_REMAP) {
                    Ok(v) => v,
                    Err(e) => return (r, Some(e)),
                },
                Err(e) => soft_err!(STEP_TYPE_REMAP, e, Vec::new()),
            },
            Err(e) => soft_err!(STEP_TYPE_REMAP, e, Vec::new()),
        };
        for (rowid, payload, cur_type) in rows {
            let Some(payload) = payload else { continue };
            let Ok(v) = serde_json::from_str::<Value>(&payload) else {
                continue;
            };
            // Mirror the writer exactly: a missing msgType reads as ""
            // (table code 0).
            let msg_type = v.get("msgType").and_then(Value::as_str).unwrap_or("");
            let want = normalize::msg_type_code(msg_type);
            if want != cur_type {
                let n = soft!(
                    STEP_TYPE_REMAP,
                    conn.execute(
                        "UPDATE messages SET type = ?2 WHERE rowid = ?1",
                        rusqlite::params![rowid, want],
                    ),
                    0
                );
                r.types_remapped += n;
            }
        }
    }

    // (e) KQ2 sender backfill: self-sent rows written before the uid
    // was known are stuck at sender NULL forever (H4-b: the old ON
    // CONFLICT never filled it). One statement; None (or a bad-shaped
    // uid, the same rule `account::resolve_own_uid` applies) skips the
    // step.
    r.senders_backfilled = soft!(
        STEP_SENDER_BACKFILL,
        backfill_senders(conn, own_uid),
        0
    );

    // (f) H4 ping-pong revisions (see `prune_ping_pong_revisions`).
    let (pruned, reset) = match prune_ping_pong_revisions(conn, fail_fast) {
        Ok(v) => v,
        // The checked policy only: the count policy folds today's
        // partials into its Ok values.
        Err(e) => return (r, Some(e)),
    };
    r.revisions_pruned = pruned;
    r.revs_reset = reset;

    // (g, batch 26 M3) import media requeue — the LAST step. An
    // attachment row whose message has source='import' belongs to the
    // history queue: the live media thread picking it would be exactly
    // the history backfill the media module's doc forbids (the
    // pre-batch-26 import wrote every row as 'ref'). Only the two
    // live-queue statuses move; downloaded/ref-encrypted/expired rows
    // are untouched (a real download is never demoted, and a gone
    // link is already terminal). The UPDATE only lands on rows that
    // still carry a live-queue status, so a second run reports 0.
    r.media_import_requeued = soft!(
        STEP_MEDIA_REQUEUE,
        conn.execute(
            "UPDATE attachments SET status = 'ref-import'
              WHERE status IN ('ref', 'failed')
                AND msg_id IN (SELECT msg_id FROM messages WHERE source = 'import')",
            [],
        ),
        0
    );

    (r, first_err)
}

/// (e) KQ2: fill `sender_id` for every self-sent row still at NULL.
/// A row is self-sent when its payload says `uidFrom='0'` (the exact
/// audit §3-KQ2 statement). `Ok(0)` without touching SQL when the uid
/// is absent/bad-shaped (the same rule `account::resolve_own_uid`
/// applies to a configured uid).
fn backfill_senders(
    conn: &Connection,
    own_uid: Option<&str>,
) -> rusqlite::Result<usize> {
    let Some(uid) = own_uid.filter(|u| account::valid_uid(u)) else {
        return Ok(0);
    };
    conn.execute(
        "UPDATE messages SET sender_id = ?1
          WHERE sender_id IS NULL AND json_extract(payload_json, '$.uidFrom') = '0'",
        rusqlite::params![uid],
    )
}

/// (f) H4 ping-pong: the pre-fix writer bumped `rev` on every
/// same-rank rewrite, so a message that only changed REPRESENTATION
/// (capture ciphertext vs e2ee plaintext of the same content, field
/// order, …) collected `edit` revisions that say nothing. A revision is
/// representation-only when hashing its payload with the SAME
/// `writer::content_hash(msgType, content)` as `messages` yields the
/// message's CURRENT hash and its kind is 'edit'; those are deleted
/// and each touched message's `rev` is set to the number of remaining
/// revision rows (renumbering is not needed — the count is the
/// semantic). Recall/delete rows are never candidates; a revision whose
/// payload does not hash (invalid JSON) or whose message is gone stays
/// (conservative). Returns `(revisions_pruned, revs_reset)`.
///
/// Under the count policy every failure keeps today's partial tuple
/// (the step stops where it stopped); under the checked policy the
/// first failure is `Err(STEP_REV_PRUNE)`.
fn prune_ping_pong_revisions(
    conn: &Connection,
    fail_fast: bool,
) -> Result<(usize, usize), RepairError> {
    // (msg_id, rev) of every representation-only edit revision.
    let mut prune: Vec<(String, i64)> = Vec::new();
    {
        let mut st = match conn.prepare(
            "SELECT r.msg_id, r.rev, r.payload_json, m.payload_json
               FROM message_revisions r
               JOIN messages m ON m.msg_id = r.msg_id
              WHERE r.kind = 'edit'",
        ) {
            Ok(st) => st,
            Err(e) => {
                if fail_fast {
                    return Err(rerr(STEP_REV_PRUNE, &e));
                }
                return Ok((0, 0));
            }
        };
        let rows = match st.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
            ))
        }) {
            Ok(it) => it,
            Err(e) => {
                if fail_fast {
                    return Err(rerr(STEP_REV_PRUNE, &e));
                }
                return Ok((0, 0));
            }
        };
        match gather_rows(rows, fail_fast, STEP_REV_PRUNE) {
            Ok(rows) => {
                for (msg_id, rev, rev_payload, msg_payload) in rows {
                    let (Some(rp), Some(mp)) = (rev_payload, msg_payload) else {
                        continue;
                    };
                    // Canonical hashing: key order cannot hide a real change,
                    // and an unhashable payload is never "representation-only".
                    let same = match (writer::content_hash(&rp), writer::content_hash(&mp)) {
                        (Some(a), Some(b)) => a == b,
                        _ => false,
                    };
                    if same {
                        prune.push((msg_id, rev));
                    }
                }
            }
            Err(e) => return Err(e),
        }
    }
    if prune.is_empty() {
        return Ok((0, 0));
    }
    let mut pruned = 0usize;
    {
        let mut del = match conn
            .prepare("DELETE FROM message_revisions WHERE msg_id = ?1 AND rev = ?2")
        {
            Ok(st) => st,
            Err(e) => {
                if fail_fast {
                    return Err(rerr(STEP_REV_PRUNE, &e));
                }
                return Ok((0, 0));
            }
        };
        for (msg_id, rev) in &prune {
            let n = match del.execute(rusqlite::params![msg_id, rev]) {
                Ok(n) => n,
                Err(e) => {
                    if fail_fast {
                        return Err(rerr(STEP_REV_PRUNE, &e));
                    }
                    0
                }
            };
            pruned += n;
        }
    }
    // Each touched message: rev = the number of REMAINING revision rows
    // (recall/delete rows count — they are real history). Only rows
    // whose rev actually moves are counted, so a second run reports 0.
    let mut reset = 0usize;
    {
        let mut st = match conn.prepare(
            "UPDATE messages
                SET rev = (SELECT COUNT(*) FROM message_revisions r
                            WHERE r.msg_id = messages.msg_id)
              WHERE msg_id = ?1
                AND rev <> (SELECT COUNT(*) FROM message_revisions r
                             WHERE r.msg_id = messages.msg_id)",
        ) {
            Ok(st) => st,
            Err(e) => {
                if fail_fast {
                    return Err(rerr(STEP_REV_PRUNE, &e));
                }
                return Ok((pruned, 0));
            }
        };
        let touched: std::collections::BTreeSet<&String> = prune.iter().map(|(m, _)| m).collect();
        for msg_id in touched {
            let n = match st.execute(rusqlite::params![msg_id]) {
                Ok(n) => n,
                Err(e) => {
                    if fail_fast {
                        return Err(rerr(STEP_REV_PRUNE, &e));
                    }
                    0
                }
            };
            reset += n;
        }
    }
    Ok((pruned, reset))
}

/// The same work as [`repair_v1`], run inside `BEGIN IMMEDIATE …
/// ROLLBACK`: the returned report shows what WOULD change, and the DB
/// is provably untouched (audit §1.2 risk note: run the migration on a
/// copy first and compare). The caller supplies a COPY of the live DB
/// (`maint_repair` does); a failed BEGIN reports zero everywhere.
/// Batch 20: implemented on the shared core (count policy).
pub fn repair_v1_dry_run(conn: &Connection, own_uid: Option<&str>) -> RepairReport {
    dry_run_impl(conn, own_uid, false).0
}

/// (S1, batch 20) The checked variant the CLI's idempotence probe
/// drives: `BEGIN IMMEDIATE`, the checked core, then `ROLLBACK`
/// ALWAYS — on success and on error alike; a COMMIT never runs. The
/// report shows what a second pass WOULD still change (all zeros on a
/// repaired DB).
pub fn repair_v1_dry_run_checked(
    conn: &Connection,
    own_uid: Option<&str>,
) -> Result<RepairReport, RepairError> {
    let (r, err) = dry_run_impl(conn, own_uid, true);
    match err {
        None => Ok(r),
        Some(e) => Err(e),
    }
}

/// One `BEGIN IMMEDIATE … (core) … ROLLBACK` pass over the error
/// policies (the shared core's dry-run twin: `false` is the
/// pre-batch-20 behaviour, `true` aborts at the first SQL failure).
fn dry_run_impl(
    conn: &Connection,
    own_uid: Option<&str>,
    fail_fast: bool,
) -> (RepairReport, Option<RepairError>) {
    if let Err(e) = conn.execute_batch("BEGIN IMMEDIATE") {
        // A failed BEGIN reports zero everywhere (the pre-batch-20
        // behaviour); the checked variant surfaces the kind.
        return (
            RepairReport::default(),
            Some(RepairError {
                step: STEP_BEGIN,
                kind: sqlite_kind(&e),
            }),
        );
    }
    let (r, err) = repair_v1_impl(conn, own_uid, fail_fast);
    // ROLLBACK always — even on error, and never COMMIT. One
    // best-effort retry for an odd savepoint state, then whatever
    // happens, no COMMIT ever runs.
    if conn.execute_batch("ROLLBACK").is_err() {
        let _ = conn.execute_batch("ROLLBACK");
    }
    (r, err)
}

/// The two counts lines the maintenance probe (`maint_repair`) and the
/// repair CLI print — moved from the probe (batch 20) so both print
/// IDENTICAL shapes. Counts only (H-rule: no row data, ids or
/// content); a query that fails reads -1. Batch 26 M3 appends the
/// requeueable-import-media census to the END of the second line —
/// existing fields keep their names and order.
pub fn counts_lines(conn: &Connection) -> Vec<String> {
    let q = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get(0)).unwrap_or(-1) };
    vec![
        format!(
            "messages={} conversations={} revisions={} attachments={} raw_events={} contacts={} groups={}",
            q("SELECT COUNT(*) FROM messages"),
            q("SELECT COUNT(*) FROM conversations"),
            q("SELECT COUNT(*) FROM message_revisions"),
            q("SELECT COUNT(*) FROM attachments"),
            q("SELECT COUNT(*) FROM raw_events"),
            q("SELECT COUNT(*) FROM contacts"),
            q("SELECT COUNT(*) FROM groups"),
        ),
        format!(
            "sender_null={} self_sent_sender_null={} msgs_without_conv_row={} convs_lastmsg_not_newest={} rev_gt0={} media_import_requeue={}",
            q("SELECT COUNT(*) FROM messages WHERE sender_id IS NULL"),
            q("SELECT COUNT(*) FROM messages WHERE json_extract(payload_json,'$.uidFrom')='0' AND sender_id IS NULL"),
            q("SELECT COUNT(*) FROM messages m WHERE NOT EXISTS (SELECT 1 FROM conversations c WHERE c.id=m.conv_id)"),
            q("SELECT COUNT(*) FROM conversations c JOIN messages m ON m.msg_id=c.last_msg_id
                 WHERE m.ts < (SELECT MAX(ts) FROM messages x WHERE x.conv_id=c.id)"),
            q("SELECT COUNT(*) FROM messages WHERE rev>0"),
            // (g, batch 26): import-sourced attachment rows still in a
            // live-queue status — what the requeue step would move.
            q("SELECT COUNT(*) FROM attachments
                 WHERE status IN ('ref','failed')
                   AND msg_id IN (SELECT msg_id FROM messages WHERE source = 'import')"),
        ),
    ]
}

/// The report as ONE line, one counter per field — the CLI's printable
/// shape (counts only; the caller adds its own `report: ` prefix).
/// Batch 26 M3 appends its counter at the END — existing fields and
/// their order are untouched.
pub fn report_fields(r: &RepairReport) -> String {
    format!(
        "conv_stubs_created={} last_msg_fixed={} content_hash_filled={} \
         types_remapped={} senders_backfilled={} revisions_pruned={} revs_reset={} \
         media_import_requeued={}",
        r.conv_stubs_created,
        r.last_msg_fixed,
        r.content_hash_filled,
        r.types_remapped,
        r.senders_backfilled,
        r.revisions_pruned,
        r.revs_reset,
        r.media_import_requeued,
    )
}

#[cfg(test)]
mod tests {
    use super::super::schema;
    use super::*;
    use crate::migrate::sqlcipher;
    use rusqlite::Connection;

    fn db() -> Connection {
        let key = sqlcipher::generate_key().unwrap();
        let conn = sqlcipher::open_in_memory(&key).unwrap();
        schema::apply(&conn).unwrap();
        conn
    }

    fn legacy_msg(conn: &Connection, msg_id: &str, conv: &str, ts: i64) {
        // A v1-era row: content_hash NULL, written before the fix.
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, rev, deleted, source)
             VALUES (?1, ?2, NULL, ?3, 1, NULL, ?4, 0, 0, 'capture')",
            rusqlite::params![
                msg_id,
                conv,
                ts,
                format!(r#"{{"msgId":"{msg_id}","msgType":"text","content":"c"}}"#)
            ],
        )
        .unwrap();
    }

    #[test]
    fn repair_v1_orphan_stub_and_last_pointers() {
        let conn = db();
        // Orphan messages in "cA" (no conversations row), newest ts 300.
        legacy_msg(&conn, "a1", "cA", 300);
        legacy_msg(&conn, "a2", "cA", 100);
        // An existing conversation whose pointer is WRONG (older msg).
        conn.execute(
            "INSERT INTO conversations (id, type, unread, updated_at, last_msg_id, last_ts)
             VALUES ('cA', 0, 0, 1, 'a2', 100)",
            [],
        )
        .unwrap();
        // An orphan in "cB" with no conversation row at all.
        legacy_msg(&conn, "a3", "cB", 50);

        let r = repair_v1(&conn, None);
        // Only cB was a true orphan (cA already had its row).
        assert_eq!(r.conv_stubs_created, 1);
        let (ty, unread, last_b, ts_b): (i64, i64, Option<String>, Option<i64>) = conn
            .query_row(
                "SELECT type, unread, last_msg_id, last_ts FROM conversations WHERE id='cB'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .unwrap();
        assert_eq!((ty, unread), (0, 0));
        assert_eq!(last_b.as_deref(), Some("a3"));
        assert_eq!(ts_b, Some(50));
        // cA's pointer was recomputed to the ts-300 message.
        let (last_a, ts_a): (Option<String>, Option<i64>) = conn
            .query_row(
                "SELECT last_msg_id, last_ts FROM conversations WHERE id='cA'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(last_a.as_deref(), Some("a1"), "recomputed to the newest ts");
        assert_eq!(ts_a, Some(300));
        // Both fixed rows counted (cA pointer + cB fill).
        assert_eq!(r.last_msg_fixed, 2);
        // All three legacy rows got their content_hash.
        assert_eq!(r.content_hash_filled, 3);
        let null_hash: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE content_hash IS NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(null_hash, 0);
        // The stored hash is exactly the writer's digest for the payload.
        let stored: Option<String> = conn
            .query_row(
                "SELECT content_hash FROM messages WHERE msg_id='a1'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            stored.as_deref(),
            writer::content_hash(r#"{"msgId":"a1","msgType":"text","content":"c"}"#).as_deref()
        );
        // Out-of-scope by design: revisions untouched. These rows carry
        // msgType "text" (stored type 1 == the table code), so the B6
        // remap counts 0 for them.
        let revisions: i64 = conn
            .query_row("SELECT COUNT(*) FROM message_revisions", [], |row| row.get(0))
            .unwrap();
        assert_eq!(revisions, 0);
        assert_eq!(r.types_remapped, 0);
    }

    #[test]
    fn repair_v1_idempotent_second_run() {
        let conn = db();
        legacy_msg(&conn, "a1", "cA", 300);
        legacy_msg(&conn, "a2", "cA", 100);
        conn.execute(
            "INSERT INTO conversations (id, type, unread, updated_at, last_msg_id, last_ts)
             VALUES ('cA', 0, 0, 1, 'a2', 100)",
            [],
        )
        .unwrap();
        let r1 = repair_v1(&conn, None);
        assert!(r1.conv_stubs_created == 0 && r1.last_msg_fixed == 1 && r1.content_hash_filled == 2);
        // Snapshot the repaired state, run again, compare.
        let (last, ts, hash_a1): (Option<String>, Option<i64>, Option<String>) = conn
            .query_row(
                "SELECT (SELECT last_msg_id FROM conversations WHERE id='cA'),
                        (SELECT last_ts FROM conversations WHERE id='cA'),
                        (SELECT content_hash FROM messages WHERE msg_id='a1')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        let r2 = repair_v1(&conn, None);
        assert_eq!(r2, RepairReport::default(), "second run changes nothing");
        let (last2, ts2, hash_a1_2): (Option<String>, Option<i64>, Option<String>) = conn
            .query_row(
                "SELECT (SELECT last_msg_id FROM conversations WHERE id='cA'),
                        (SELECT last_ts FROM conversations WHERE id='cA'),
                        (SELECT content_hash FROM messages WHERE msg_id='a1')",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!((last.as_deref(), ts, hash_a1.as_deref()), (last2.as_deref(), ts2, hash_a1_2.as_deref()));
    }

    // --- B6/H1: type remap through the batch-2 table -----------------------

    #[test]
    fn repair_v1_remaps_types_from_payload_msgtype() {
        let conn = db();
        // A V1-era row: msgType chat.photo, but the pre-rebuild writer
        // stored its own code 1.
        let v1 = r#"{"msgId":"tp","msgType":"chat.photo","content":{"href":"https://fake-photo-stal.zdn.vn/x.jpg"}}"#;
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, rev, deleted, source)
             VALUES ('tp','cT',NULL,1,1,NULL,?1,0,0,'capture')",
            rusqlite::params![v1],
        )
        .unwrap();
        // A 100-bucket row (the rebuild's old table knew no wire string).
        let weird = r#"{"msgId":"tw","msgType":"chat.recommended","content":{"href":"https://fake-link.example/x"}}"#;
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, rev, deleted, source)
             VALUES ('tw','cT',NULL,2,100,NULL,?1,0,0,'e2ee')",
            rusqlite::params![weird],
        )
        .unwrap();
        // A row already on the table code (webchat -> 1): not counted.
        let ok = r#"{"msgId":"to","msgType":"webchat","content":"c"}"#;
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, rev, deleted, source)
             VALUES ('to','cT',NULL,3,1,NULL,?1,0,0,'capture')",
            rusqlite::params![ok],
        )
        .unwrap();
        // Rows with nothing to recompute from: NULL payload and invalid
        // JSON keep their stored type.
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, rev, deleted, source)
             VALUES ('tn','cT',NULL,4,7,NULL,NULL,0,0,'capture')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, rev, deleted, source)
             VALUES ('tx','cT',NULL,5,9,NULL,'not json',0,0,'capture')",
            [],
        )
        .unwrap();

        let r = repair_v1(&conn, None);
        assert_eq!(r.types_remapped, 2, "only the two rows whose type really changed");
        let types: Vec<(String, i64)> = {
            let mut st = conn
                .prepare("SELECT msg_id, type FROM messages ORDER BY ts")
                .unwrap();
            st.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get(1)?)))
                .unwrap()
                .filter_map(Result::ok)
                .collect()
        };
        // chat.photo -> 2, chat.recommended -> 7 (the link card), the
        // rest untouched (including the NULL/invalid-payload rows).
        assert_eq!(
            types,
            vec![
                ("tp".to_string(), 2),
                ("tw".to_string(), 7),
                ("to".to_string(), 1),
                ("tn".to_string(), 7),
                ("tx".to_string(), 9),
            ]
        );
        // Idempotent: a second run changes nothing (same table, same
        // payloads).
        let r2 = repair_v1(&conn, None);
        assert_eq!(r2.types_remapped, 0);
    }

    // --- (e) KQ2 sender backfill ------------------------------------------

    /// Fake message with an explicit sender (payload shape: self-sent
    /// rows carry uidFrom='0').
    fn sender_msg(conn: &Connection, msg_id: &str, payload: &str, sender: Option<&str>) {
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, rev, deleted, source)
             VALUES (?1, 'cS', ?2, 1, 1, NULL, ?3, 0, 0, 'capture')",
            rusqlite::params![msg_id, sender, payload],
        )
        .unwrap();
    }

    fn self_sent(msg_id: &str) -> String {
        format!(
            r#"{{"msgId":"{msg_id}","uidFrom":"0","idTo":"u9","msgType":"text","content":"x"}}"#
        )
    }

    #[test]
    fn repair_v1_backfills_self_sent_senders_only() {
        const UID: &str = "1234567890123456789"; // fake, valid shape
        let conn = db();
        // Self-sent rows: one stuck at NULL (the H4-b legacy), one
        // already set. Plus an incoming row with NULL sender — a
        // uidFrom of '0' is what marks self-sent, 'u2' must not match.
        sender_msg(&conn, "s1", &self_sent("s1"), None);
        sender_msg(&conn, "s2", &self_sent("s2"), Some("777"));
        sender_msg(
            &conn,
            "s3",
            r#"{"msgId":"s3","uidFrom":"u2","idTo":"u9","msgType":"text","content":"x"}"#,
            None,
        );

        let r = repair_v1(&conn, Some(UID));
        assert_eq!(r.senders_backfilled, 1, "only the NULL self-sent row");
        let sender = |id: &str| -> Option<String> {
            conn.query_row("SELECT sender_id FROM messages WHERE msg_id = ?1", [id], |x| x.get(0))
                .unwrap()
        };
        assert_eq!(sender("s1").as_deref(), Some(UID), "backfilled");
        assert_eq!(sender("s2").as_deref(), Some("777"), "already set — untouched");
        assert_eq!(sender("s3"), None, "not self-sent — untouched");
        // Idempotent: nothing left at NULL with uidFrom='0'.
        assert_eq!(repair_v1(&conn, Some(UID)).senders_backfilled, 0);

        // None (uid unknown) skips the step entirely.
        let conn2 = db();
        sender_msg(&conn2, "s1", &self_sent("s1"), None);
        assert_eq!(repair_v1(&conn2, None).senders_backfilled, 0);

        // A bad-shaped uid behaves as absent (same rule as
        // account::resolve_own_uid applies to a configured uid).
        let conn3 = db();
        sender_msg(&conn3, "s1", &self_sent("s1"), None);
        assert_eq!(repair_v1(&conn3, Some("12a")).senders_backfilled, 0);
    }

    // --- (f) H4 ping-pong revision prune -----------------------------------

    fn revision(conn: &Connection, msg_id: &str, rev: i64, kind: &str, payload: &str) {
        conn.execute(
            "INSERT INTO message_revisions (msg_id, rev, ts, kind, payload_json)
             VALUES (?1, ?2, 1, ?3, ?4)",
            rusqlite::params![msg_id, rev, kind, payload],
        )
        .unwrap();
    }

    #[test]
    fn repair_v1_prunes_ping_pong_edits_and_resets_rev() {
        let conn = db();
        // Current message payload: content "v2", rev inflated by the
        // pre-fix ping-pong writer.
        let cur =
            r#"{"msgId":"p1","uidFrom":"u1","idTo":"cP","ts":1,"msgType":"text","content":"v2"}"#;
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, content_hash, rev, deleted, source)
             VALUES ('p1','cP','u1',1,1,'v2',?1,?2,5,0,'capture')",
            rusqlite::params![cur, writer::content_hash(cur).unwrap()],
        )
        .unwrap();
        // rev1: representation-only ping-pong — SAME content, different
        // key order (canonical hashing must see through it).
        let reordered =
            r#"{"content":"v2","msgType":"text","idTo":"cP","uidFrom":"u1","ts":1,"msgId":"p1"}"#;
        revision(&conn, "p1", 1, "edit", reordered);
        // rev2: a REAL edit (different content) — kept.
        revision(
            &conn,
            "p1",
            2,
            "edit",
            r#"{"msgId":"p1","uidFrom":"u1","idTo":"cP","ts":1,"msgType":"text","content":"v1"}"#,
        );
        // rev3: hash-equal to the current payload BUT kind 'recall' —
        // the kind guard keeps it (a real undo is history).
        revision(&conn, "p1", 3, "recall", cur);
        // rev4: invalid JSON — cannot hash, kept (conservative).
        revision(&conn, "p1", 4, "edit", "not json");
        // A revision for a message that no longer exists — kept (no
        // current payload to compare against).
        revision(&conn, "pX", 1, "edit", reordered);

        let r = repair_v1(&conn, None);
        assert_eq!(r.revisions_pruned, 1, "only the representation-only edit");
        assert_eq!(r.revs_reset, 1, "p1: rev 5 -> remaining 3");
        let rev: i64 = conn
            .query_row("SELECT rev FROM messages WHERE msg_id='p1'", [], |x| x.get(0))
            .unwrap();
        assert_eq!(rev, 3, "rev = the number of remaining revisions");
        let remaining: Vec<(i64, String)> = {
            let mut st = conn
                .prepare("SELECT rev, kind FROM message_revisions WHERE msg_id='p1' ORDER BY rev")
                .unwrap();
            st.query_map([], |x| Ok((x.get::<_, i64>(0)?, x.get::<_, String>(1)?)))
                .unwrap()
                .filter_map(Result::ok)
                .collect()
        };
        assert_eq!(
            remaining,
            vec![
                (2, "edit".to_string()),
                (3, "recall".to_string()),
                (4, "edit".to_string()),
            ],
            "the real edit, the recall and the unhashable row survive"
        );
        let orphan: i64 = conn
            .query_row("SELECT COUNT(*) FROM message_revisions WHERE msg_id='pX'", [], |x| {
                x.get(0)
            })
            .unwrap();
        assert_eq!(orphan, 1, "no message row -> never compared, kept");

        // Idempotent: nothing left to prune; rev already equals the count.
        let r2 = repair_v1(&conn, None);
        assert_eq!(r2.revisions_pruned, 0);
        assert_eq!(r2.revs_reset, 0);
    }

    // --- dry run -------------------------------------------------------------

    /// Count/aggregate checksum over every column the repair steps
    /// touch (messages, conversations, message_revisions) — "byte for
    /// byte" in the counts/hashes sense of the brief.
    fn checksum(conn: &Connection) -> String {
        let q = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get(0)).unwrap() };
        format!(
            "msgs={mn} {mhash} {mtype} {mrev} {mnull} {msendernull} {mtlen} \
             convs={cn} {clastlen} {cts} {ctitlelen} \
             revrows={rn} {rrev} {rtlen}",
            mn = q("SELECT COUNT(*) FROM messages"),
            mhash = q("SELECT COALESCE(SUM(CASE WHEN content_hash IS NULL THEN 1 ELSE 0 END),0) FROM messages"),
            mtype = q("SELECT COALESCE(SUM(type),0) FROM messages"),
            mrev = q("SELECT COALESCE(SUM(rev),0) FROM messages"),
            mnull = q("SELECT COUNT(*) FROM messages WHERE sender_id IS NULL"),
            msendernull = q("SELECT COALESCE(SUM(CASE WHEN sender_id IS NULL THEN 1 ELSE 0 END),0) FROM messages"),
            mtlen = q("SELECT COALESCE(SUM(length(payload_json)),0) FROM messages"),
            cn = q("SELECT COUNT(*) FROM conversations"),
            clastlen = q("SELECT COALESCE(SUM(COALESCE(length(last_msg_id),0)),0) FROM conversations"),
            cts = q("SELECT COALESCE(SUM(COALESCE(last_ts,0)),0) FROM conversations"),
            ctitlelen = q("SELECT COALESCE(SUM(COALESCE(length(title),0)),0) FROM conversations"),
            rn = q("SELECT COUNT(*) FROM message_revisions"),
            rrev = q("SELECT COALESCE(SUM(rev),0) FROM message_revisions"),
            rtlen = q("SELECT COALESCE(SUM(COALESCE(length(payload_json),0)),0) FROM message_revisions"),
        )
    }

    #[test]
    fn repair_v1_dry_run_leaves_the_db_untouched() {
        const UID: &str = "1234567890123456789"; // fake, valid shape
        let conn = db();
        // The full legacy mess in one DB: orphan conv (cD has no row),
        // V1-era type 7 with payload msgType text, content_hash NULL,
        // sender NULL on a self-sent row, and one ping-pong revision.
        let p = r#"{"msgId":"d1","uidFrom":"0","idTo":"cD","ts":1,"msgType":"text","content":"x"}"#;
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, rev, deleted, source)
             VALUES ('d1','cD',NULL,1,7,NULL,?1,2,0,'capture')",
            rusqlite::params![p],
        )
        .unwrap();
        revision(&conn, "d1", 1, "edit", p);

        let before = checksum(&conn);
        let dry = repair_v1_dry_run(&conn, Some(UID));
        // The report says what WOULD change — every step reports work…
        assert_eq!(dry.conv_stubs_created, 1, "cD stub");
        assert_eq!(dry.last_msg_fixed, 1, "the fresh stub gets its pointer");
        assert_eq!(dry.content_hash_filled, 1);
        assert_eq!(dry.types_remapped, 1, "type 7 -> table code 1 (text)");
        assert_eq!(dry.senders_backfilled, 1);
        assert_eq!(dry.revisions_pruned, 1);
        assert_eq!(dry.revs_reset, 1, "rev 2 -> remaining 0");
        // …but the DB is unchanged (counts/hashes identical).
        assert_eq!(checksum(&conn), before, "dry run must not persist anything");

        // The real run changes the DB and is idempotent afterwards.
        let r1 = repair_v1(&conn, Some(UID));
        assert_eq!(r1.conv_stubs_created, 1);
        assert_eq!(r1.last_msg_fixed, 1);
        assert_eq!(r1.content_hash_filled, 1);
        assert_eq!(r1.types_remapped, 1);
        assert_eq!(r1.senders_backfilled, 1);
        assert_eq!(r1.revisions_pruned, 1);
        assert_eq!(r1.revs_reset, 1);
        assert_ne!(checksum(&conn), before, "the real run persisted the repair");
        // A second real run is all zeros, and a third moves nothing.
        let r2 = repair_v1(&conn, Some(UID));
        assert_eq!(r2, RepairReport::default(), "second run all zeros");
        let after = checksum(&conn);
        let _ = repair_v1(&conn, Some(UID));
        assert_eq!(checksum(&conn), after, "third run changes nothing");
    }

    // --- batch 20 S1: the checked core --------------------------------------

    /// Lighter than `checksum`: it must also work on a DB whose
    /// `message_revisions` table is gone (the checked-core fixture).
    fn light_state(conn: &Connection) -> (i64, i64, i64, i64) {
        conn.query_row(
            "SELECT (SELECT COUNT(*) FROM conversations),
                    (SELECT COUNT(*) FROM messages WHERE content_hash IS NULL),
                    (SELECT COUNT(*) FROM messages WHERE sender_id IS NULL),
                    (SELECT COALESCE(SUM(type),0) FROM messages)",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap()
    }

    #[test]
    fn repair_v1_checked_names_the_step_and_the_count_policy_keeps_counting() {
        // Drop a table step (f) needs. The count policy runs FIRST (a
        // bare connection autocommits, so the checked run's partial
        // work would otherwise land before the count run's asserts):
        // the good steps still report (cA stub + hash fill), (f)
        // contributes its zero — the pre-batch-20 behaviour.
        let conn = db();
        legacy_msg(&conn, "a1", "cA", 300);
        conn.execute("DROP TABLE message_revisions", []).unwrap();
        let r = repair_v1(&conn, None);
        assert_eq!(r.conv_stubs_created, 1);
        assert_eq!(r.content_hash_filled, 1);
        assert_eq!(r.revisions_pruned, 0);
        assert_eq!(r.revs_reset, 0);

        // The checked core over the same DB: nothing is left to do in
        // steps (a)-(e), so the FIRST SQL failure is step (f)'s
        // prepare — named, with a kind, never the error text.
        let e = repair_v1_checked(&conn, None).unwrap_err();
        assert_eq!(e.step, STEP_REV_PRUNE);
        assert!(!e.kind.is_empty(), "a sqlite kind, never the error text");
    }

    #[test]
    fn repair_v1_dry_run_checked_reports_the_same_and_never_commits() {
        // The happy path: the checked dry run reports EXACTLY what the
        // plain dry run reports, and persists nothing either.
        const UID: &str = "1234567890123456789"; // fake, valid shape
        let conn = db();
        legacy_msg(&conn, "a1", "cA", 300);
        revision(&conn, "a1", 1, "edit", &legacy_payload("a1"));
        let before = checksum(&conn);
        let plain = repair_v1_dry_run(&conn, Some(UID));
        let checked = repair_v1_dry_run_checked(&conn, Some(UID)).unwrap();
        assert_eq!(plain, checked);
        assert_eq!(checked.revisions_pruned, 1, "the ping-pong edit");
        assert_eq!(checksum(&conn), before, "no COMMIT ever ran");
    }

    #[test]
    fn repair_v1_dry_run_checked_rolls_back_even_on_error() {
        // The failure arm: a step error inside the BEGIN must still
        // end ROLLBACK-ed (never COMMIT) — the DB equals its pre-run
        // state even though steps (a)-(e) had already done work inside
        // the transaction.
        let conn = db();
        legacy_msg(&conn, "a1", "cA", 300);
        conn.execute("DROP TABLE message_revisions", []).unwrap();
        let before = light_state(&conn);
        let e = repair_v1_dry_run_checked(&conn, None).unwrap_err();
        assert_eq!(e.step, STEP_REV_PRUNE);
        assert_eq!(light_state(&conn), before, "the failed pass rolled back");
        // The plain dry run over the same DB keeps its swallow-and-count
        // behaviour (zeros for (f), work reported for the rest).
        let r = repair_v1_dry_run(&conn, None);
        assert_eq!(r.conv_stubs_created, 1);
        assert_eq!(r.revisions_pruned, 0);
        assert_eq!(light_state(&conn), before, "still untouched");
    }

    /// The payload `legacy_msg` stores for `msg_id` (the revision
    /// fixture hashes equal to it — the representation-only case).
    fn legacy_payload(msg_id: &str) -> String {
        format!(r#"{{"msgId":"{msg_id}","msgType":"text","content":"c"}}"#)
    }

    // --- (g, batch 26 M3): the import media requeue -----------------------

    /// One attachment row (FAKE url — never a real one) for a message.
    fn att_row(conn: &Connection, msg_id: &str, idx: i64, status: &str) {
        conn.execute(
            "INSERT INTO attachments (msg_id, idx, kind, url, status)
             VALUES (?1, ?2, 'image', 'https://fake-stal.zdn.vn/x.jpg', ?3)",
            rusqlite::params![msg_id, idx, status],
        )
        .unwrap();
    }

    /// A message row with an explicit source (minimal columns).
    fn src_msg(conn: &Connection, msg_id: &str, source: &str) {
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, ts, type, source)
             VALUES (?1, 'cM', 1, 1, ?2)",
            rusqlite::params![msg_id, source],
        )
        .unwrap();
    }

    fn status_of(conn: &Connection, msg_id: &str, idx: i64) -> String {
        conn.query_row(
            "SELECT status FROM attachments WHERE msg_id = ?1 AND idx = ?2",
            rusqlite::params![msg_id, idx],
            |r| r.get(0),
        )
        .unwrap()
    }

    #[test]
    fn repair_v1_requeues_import_media_and_is_idempotent() {
        // (g): import-sourced `ref`/`failed` rows move to the history
        // queue; downloaded/ref-encrypted/expired rows stay; a capture
        // row NEVER moves; a second run reports 0.
        let conn = db();
        src_msg(&conn, "im1", "import");
        src_msg(&conn, "im2", "import");
        src_msg(&conn, "im3", "import");
        src_msg(&conn, "im4", "import");
        src_msg(&conn, "im5", "import");
        src_msg(&conn, "cm1", "capture");
        att_row(&conn, "im1", 0, "ref");          // -> ref-import
        att_row(&conn, "im2", 0, "failed");      // -> ref-import
        att_row(&conn, "im3", 0, "downloaded");  // untouched
        att_row(&conn, "im4", 0, "ref-encrypted"); // untouched
        att_row(&conn, "im5", 0, "expired");     // untouched
        att_row(&conn, "cm1", 0, "failed");      // capture: untouched
        // An attachment with NO message row at all: untouched (nothing
        // proves it is import-sourced).
        att_row(&conn, "ghost", 0, "ref");

        let r1 = repair_v1(&conn, None);
        assert_eq!(r1.media_import_requeued, 2, "exactly the two live-queued import rows");
        assert_eq!(status_of(&conn, "im1", 0), "ref-import");
        assert_eq!(status_of(&conn, "im2", 0), "ref-import");
        assert_eq!(status_of(&conn, "im3", 0), "downloaded");
        assert_eq!(status_of(&conn, "im4", 0), "ref-encrypted");
        assert_eq!(status_of(&conn, "im5", 0), "expired");
        assert_eq!(status_of(&conn, "cm1", 0), "failed", "capture-sourced rows are untouched");
        assert_eq!(status_of(&conn, "ghost", 0), "ref", "no message row: untouched");

        // Idempotent: nothing left in a live-queue import status.
        let r2 = repair_v1(&conn, None);
        assert_eq!(r2.media_import_requeued, 0, "second run reports 0");
        // The counts-line census agrees before/after.
        let q = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get(0)).unwrap() };
        let still: i64 = q(
            "SELECT COUNT(*) FROM attachments
              WHERE status IN ('ref','failed')
                AND msg_id IN (SELECT msg_id FROM messages WHERE source = 'import')",
        );
        assert_eq!(still, 0);

        // The checked core reports the same step (fail-fast paths all
        // succeed on a healthy DB).
        let r3 = repair_v1_checked(&conn, None).unwrap();
        assert_eq!(r3.media_import_requeued, 0);
    }

    #[test]
    fn repair_v1_requeue_step_is_last_in_the_report_and_counts() {
        // Shape pins: the new counter is APPENDED — every existing
        // field keeps its name and position.
        let line = report_fields(&RepairReport::default());
        assert!(
            line.ends_with("media_import_requeued=0"),
            "the batch-26 counter is the last field: {line}"
        );
        let prefix = "conv_stubs_created=0 last_msg_fixed=0 content_hash_filled=0 \
                      types_remapped=0 senders_backfilled=0 revisions_pruned=0 revs_reset=0";
        assert!(
            line.starts_with(prefix),
            "the existing fields keep their names and order: {line}"
        );
        let conn = db();
        let lines = counts_lines(&conn);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "messages=0 conversations=0 revisions=0 attachments=0 raw_events=0 contacts=0 groups=0",
            "the first counts line is unchanged");
        assert!(
            lines[1].starts_with(
                "sender_null=0 self_sent_sender_null=0 msgs_without_conv_row=0 \
                 convs_lastmsg_not_newest=0 rev_gt0=0"
            ),
            "the second line's existing fields keep their order: {lines:?}"
        );
        assert!(lines[1].ends_with("media_import_requeue=0"), "appended at the END");
        // With import rows present the census counts them (the dry-run
        // visibility the CLI prints before/after).
        src_msg(&conn, "im1", "import");
        att_row(&conn, "im1", 0, "ref");
        let lines = counts_lines(&conn);
        assert!(lines[1].ends_with("media_import_requeue=1"));
        // The dry run reports the WOULD-BE count and persists nothing.
        let before = counts_lines(&conn);
        let dry = repair_v1_dry_run(&conn, None);
        assert_eq!(dry.media_import_requeued, 1);
        assert_eq!(counts_lines(&conn), before, "the dry run moved nothing");
    }
}
