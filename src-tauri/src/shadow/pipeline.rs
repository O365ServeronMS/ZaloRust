//! Pure batch transform: decoded events in, `raw_events` + domain writes out.
//! Kept separate from `runtime` so the whole flow is unit-testable against
//! fixture envelopes without any thread or IPC involvement.
//!
//! Batch discipline (audit H3/T2): one `BEGIN IMMEDIATE … COMMIT` wraps the
//! whole batch — everything lands together or nothing does. Each item runs
//! inside its own SAVEPOINT, so a failing write rolls back only itself and
//! is COUNTED in the [`Summary`] (never swallowed; the flusher logs counts
//! + error kinds only).

use std::collections::BTreeMap;

use rusqlite::Connection;
use serde_json::Value;

use super::{Write, normalize, writer};

/// One decoded item entering the pipeline.
#[derive(Debug, Clone)]
pub struct Incoming {
    /// 'ws' | 'rest' | 'e2ee' — mirrors `raw_events.kind`.
    pub kind: &'static str,
    /// 'in' | 'out'.
    pub direction: &'static str,
    /// Endpoint path for REST, `ws:<cmd>/<subCmd>` for WS frames.
    pub endpoint: String,
    /// The decoded envelope (or the flagged-undecoded stored shape).
    pub env: Value,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Summary {
    pub raw_events: usize,
    /// `raw_events` inserts that failed (H3: counted, never swallowed).
    pub raw_errors: usize,
    pub messages: usize,
    pub conversations: usize,
    pub groups: usize,
    pub contacts: usize,
    pub other_writes: usize,
    /// Domain writes that failed (H3: counted, never swallowed).
    pub write_errors: usize,
    /// Log-safe per-kind error counts (F3): `<write tag>:<error kind>`
    /// (or `begin:`/`commit:`/`trim:`/`media:` for batch-level failures,
    /// `<tag>:`/`item:`/`media:` + `aborted` for writes never attempted
    /// after the transaction aborted, F2) → occurrences. Bounded by the
    /// number of DISTINCT kinds, never by the failure count: a batch of
    /// 500 one-kind failures is one entry. Error text, SQL params and
    /// payloads never enter here.
    pub write_error_kinds: BTreeMap<String, usize>,
}

impl Summary {
    pub fn add_write(&mut self, tag: &str) {
        match tag {
            "message" => self.messages += 1,
            "conversation" => self.conversations += 1,
            "group" => self.groups += 1,
            "contact" => self.contacts += 1,
            _ => self.other_writes += 1,
        }
    }

    /// Count one failed write with its log-safe descriptor (F3).
    pub(crate) fn add_error_kind(&mut self, descriptor: impl Into<String>) {
        *self.write_error_kinds.entry(descriptor.into()).or_insert(0) += 1;
        self.write_errors += 1;
    }

    /// Render the per-kind counts for the flusher's log line (F3), e.g.
    /// `media:sqlite_ConstraintViolation/787 x1, message:sqlite_Full/5132 x3`
    /// (BTreeMap order = stable, sorted).
    pub(crate) fn format_error_kinds(&self) -> String {
        self.write_error_kinds
            .iter()
            .map(|(kind, n)| format!("{kind} x{n}"))
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// F2: the batch transaction is gone — everything already applied
    /// inside it rolled back, so none of the counted successes landed.
    /// (Failure counters stay: those events really happened.)
    fn zero_success(&mut self) {
        self.raw_events = 0;
        self.messages = 0;
        self.conversations = 0;
        self.groups = 0;
        self.contacts = 0;
        self.other_writes = 0;
    }
}

/// Log-safe rusqlite error classifier (H-rule: counts/kinds only): the
/// SQLite primary code name + numeric extended code, or a static
/// rusqlite variant label. Never the error text — sqlite messages can
/// quote SQL, and rusqlite wrappers can embed values.
pub(crate) fn sqlite_kind(e: &rusqlite::Error) -> String {
    match e {
        rusqlite::Error::SqliteFailure(err, _) => {
            format!("sqlite_{:?}/{}", err.code, err.extended_code)
        }
        rusqlite::Error::QueryReturnedNoRows => "no_rows".into(),
        rusqlite::Error::InvalidColumnType(..) => "invalid_column_type".into(),
        _ => "rusqlite_other".into(),
    }
}

/// Apply one write inside the batch transaction, isolated by a SAVEPOINT
/// (T2/H3): a failing item rolls back only itself; the rest of the batch
/// still commits.
fn apply_item(conn: &Connection, w: &Write) -> Result<&'static str, rusqlite::Error> {
    conn.execute_batch("SAVEPOINT item")?;
    match writer::apply(conn, w) {
        Ok(tag) => {
            conn.execute_batch("RELEASE item")?;
            Ok(tag)
        }
        Err(e) => {
            // Clear the savepoint so later items proceed. Best-effort:
            // if the failing statement already aborted the whole
            // transaction the savepoint is gone — `process_batch`'s
            // `is_autocommit()` check (F2) catches exactly that case and
            // stops the batch instead of writing through in autocommit.
            let _ = conn.execute_batch("ROLLBACK TO item; RELEASE item;");
            Err(e)
        }
    }
}

/// Apply one media outcome inside the batch transaction (T3/A5), with
/// the same per-item savepoint isolation.
fn apply_media_item(
    conn: &Connection,
    rowid: i64,
    outcome: &writer::MediaOutcome,
) -> Result<usize, rusqlite::Error> {
    conn.execute_batch("SAVEPOINT item")?;
    match writer::media_done(conn, rowid, outcome) {
        Ok(n) => {
            conn.execute_batch("RELEASE item")?;
            Ok(n)
        }
        Err(e) => {
            let _ = conn.execute_batch("ROLLBACK TO item; RELEASE item;");
            Err(e)
        }
    }
}

/// F2: the batch transaction is gone — a failing statement ABORTED it
/// (SQLite does this for e.g. SQLITE_FULL, SQLITE_IOERR, SQLITE_NOMEM,
/// some SQLITE_BUSY), so `is_autocommit()` is true, the per-item
/// savepoint is gone and every later statement would run — and land —
/// in AUTOCOMMIT mode, breaking "everything lands together or nothing
/// does". The batch stops instead: every unprocessed remainder is
/// counted as one error of kind `aborted`, the success counters are
/// zeroed (their writes rolled back with the transaction and did NOT
/// land), and the caller skips COMMIT — there is nothing left to
/// commit.
fn count_aborted(
    s: &mut Summary,
    // Writes of the current item that never ran (tags already known).
    remaining_writes: impl Iterator<Item = &'static str>,
    // Whole items after — or the unfinished current — item.
    remaining_items: usize,
    // Media outcomes after the current one.
    remaining_media: usize,
) {
    for tag in remaining_writes {
        s.add_error_kind(format!("{tag}:aborted"));
    }
    for _ in 0..remaining_items {
        s.add_error_kind("item:aborted");
    }
    for _ in 0..remaining_media {
        s.add_error_kind("media:aborted");
    }
    s.zero_success();
}

/// Run one batch: store the raw envelopes, normalize them to writes,
/// apply the writes and any media outcomes, trim the ring — all inside
/// a single `BEGIN IMMEDIATE … COMMIT`. `own_uid` substitutes self-sent
/// senders. Per-item errors never abort the batch; they are counted in
/// the [`Summary`] and the transaction still commits — EXCEPT when the
/// error itself aborted the transaction (F2): then processing stops at
/// once, the remainder is counted as `aborted`, and nothing after the
/// abort point is written (in or out of the transaction).
pub fn process_batch(
    conn: &Connection,
    batch: &[Incoming],
    // Media outcomes queued by the media thread (T3), applied inside
    // the same transaction: `[(attachments.rowid, outcome)]`.
    media: &[(i64, writer::MediaOutcome)],
    raw_days: u32,
    own_uid: Option<&str>,
) -> Summary {
    let mut s = Summary::default();
    // H3/T2: one transaction per batch. BEGIN IMMEDIATE takes the write
    // lock up front, so a busy DB waits (busy_timeout, T1) instead of
    // failing mid-batch.
    if let Err(e) = conn.execute_batch("BEGIN IMMEDIATE") {
        s.add_error_kind(format!("begin:{}", sqlite_kind(&e)));
        return s;
    }
    // F2: after ANY item/media error, check that the transaction is
    // still alive. If the error aborted it, `is_autocommit()` is true —
    // `ROLLBACK TO item` was a no-op and the next statement would run
    // in AUTOCOMMIT mode (and land!), only for COMMIT to then fail
    // with "no transaction". Stop the batch instead.
    for (i, item) in batch.iter().enumerate() {
        let payload = item.env.to_string();
        match writer::raw_event(conn, item.direction, item.kind, &item.endpoint, &payload) {
            Ok(()) => s.raw_events += 1,
            Err(_) => {
                s.raw_errors += 1;
                if conn.is_autocommit() {
                    // The transaction died on the raw insert: this
                    // item's writes never ran, plus everything behind.
                    count_aborted(&mut s, std::iter::empty(), batch.len() - i, media.len());
                    return s;
                }
            }
        }
        let writes = match item.kind {
            "ws" => normalize::normalize_ws(&item.env, own_uid),
            "rest" => normalize::normalize_rest(&item.endpoint, &item.env, own_uid),
            "e2ee" => normalize::normalize_e2ee_message(&item.env, own_uid)
                .into_iter()
                .collect(),
            _ => Vec::new(),
        };
        for (j, w) in writes.iter().enumerate() {
            match apply_item(conn, w) {
                Ok(tag) => s.add_write(tag),
                Err(e) => {
                    s.add_error_kind(format!("{}:{}", w.tag(), sqlite_kind(&e)));
                    if conn.is_autocommit() {
                        // The rest of THIS item's writes (tags known)…
                        let tail = writes[j + 1..].iter().map(|w| w.tag());
                        // …then every whole item and media outcome after.
                        count_aborted(&mut s, tail, batch.len() - i - 1, media.len());
                        return s;
                    }
                }
            }
        }
    }
    // T3/A5: media outcomes land on the flusher's own connection, inside
    // the same batch transaction.
    for (k, (rowid, outcome)) in media.iter().enumerate() {
        if let Err(e) = apply_media_item(conn, *rowid, outcome) {
            s.add_error_kind(format!("media:{}", sqlite_kind(&e)));
            if conn.is_autocommit() {
                count_aborted(&mut s, std::iter::empty(), 0, media.len() - k - 1);
                return s;
            }
        }
    }
    if let Err(e) = writer::trim_raw_events(conn, raw_days) {
        s.add_error_kind(format!("trim:{}", sqlite_kind(&e)));
    }
    if let Err(e) = conn.execute_batch("COMMIT") {
        // H3: a failed commit loses the whole batch — roll back, report,
        // and zero the success counters so the log never claims writes
        // that did not land.
        let _ = conn.execute_batch("ROLLBACK");
        s.add_error_kind(format!("commit:{}", sqlite_kind(&e)));
        s.zero_success();
    }
    s
}

#[cfg(test)]
mod tests {
    use super::super::writer::MediaOutcome;
    use super::super::{schema, Write};
    use super::*;
    use crate::migrate::sqlcipher;

    fn db() -> Connection {
        let key = sqlcipher::generate_key().unwrap();
        let conn = sqlcipher::open_in_memory(&key).unwrap();
        schema::apply(&conn).unwrap();
        conn
    }

    #[test]
    fn batch_end_to_end() {
        let conn = db();
        let batch = vec![
            Incoming {
                kind: "ws",
                direction: "in",
                endpoint: "ws:2/1".into(),
                env: serde_json::json!({
                    "cmd": 2, "subCmd": 1,
                    "data": {"msgs": [{"msgId": "m1", "uidFrom": "u9", "idTo": "0",
                                        "ts": 42, "msgType": "text", "content": "hi"}]}
                }),
            },
            Incoming {
                kind: "rest",
                direction: "in",
                endpoint: "/a/preloadconvers/get-last-msgs".into(),
                env: serde_json::json!({
                    "error_code": 0,
                    "data": {"clearUnreads": [{"idTo": "u9", "isGroup": false, "lastMsgId": "m1"}]}
                }),
            },
        ];
        let s = process_batch(&conn, &batch, &[], 7, None);
        assert_eq!(s.raw_events, 2);
        assert_eq!(s.messages, 1);
        assert_eq!(s.conversations, 1);
        assert_eq!(s.write_errors, 0);
        let msgs: i64 = conn
            .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
            .unwrap();
        assert_eq!(msgs, 1);
        // T7: the ws message also created the stub for conv 'u9', and the
        // clearUnreads upsert landed on the SAME row.
        let conv: i64 = conn
            .query_row("SELECT COUNT(*) FROM conversations", [], |r| r.get(0))
            .unwrap();
        assert_eq!(conv, 1);
        let _ = Write::Group { group_id: String::new(), name: None, raw: String::new() };
    }

    #[test]
    fn batch_item_failure_isolated() {
        let conn = db();
        // Craft one failing write: a trigger aborts the insert for one
        // specific msg_id (a constraint violation at statement level).
        conn.execute_batch(
            "CREATE TRIGGER zr_deny BEFORE INSERT ON messages
             WHEN NEW.msg_id = 'm_bad'
             BEGIN SELECT RAISE(ABORT, 'crafted'); END;",
        )
        .unwrap();
        let msg = |id: &str| Incoming {
            kind: "e2ee",
            direction: "in",
            endpoint: "e2ee:bridge".into(),
            env: serde_json::json!({
                "msgId": id, "uidFrom": "u1", "idTo": "u2", "ts": 5,
                "msgType": "text", "content": "x"
            }),
        };
        let batch = vec![msg("m_bad"), msg("m_ok")];
        let s = process_batch(&conn, &batch, &[], 7, None);
        // The failing item is counted, not swallowed…
        assert_eq!(s.write_errors, 1);
        assert!(
            s.write_error_kinds.keys().any(|k| k.starts_with("message:sqlite_")),
            "descriptor must carry the write tag + sqlite kind, got {:?}",
            s.write_error_kinds
        );
        // …the other item still committed…
        assert_eq!(s.messages, 1);
        let (ok, bad): (i64, i64) = conn
            .query_row(
                "SELECT (SELECT COUNT(*) FROM messages WHERE msg_id='m_ok'),
                        (SELECT COUNT(*) FROM messages WHERE msg_id='m_bad')",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((ok, bad), (1, 0), "one item rolled back, one committed");
        // …and the batch itself committed (raw rows landed).
        let raw: i64 = conn
            .query_row("SELECT COUNT(*) FROM raw_events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(raw, 2);
    }

    #[test]
    fn media_outcomes_apply_inside_the_batch() {
        let conn = db();
        conn.execute(
            "INSERT INTO attachments (msg_id, idx, kind, url, status)
             VALUES ('m1', 0, 'image', 'https://h/x', 'ref')",
            [],
        )
        .unwrap();
        let rowid: i64 = conn
            .query_row("SELECT rowid FROM attachments", [], |r| r.get(0))
            .unwrap();
        let s = process_batch(
            &conn,
            &[],
            &[(rowid, MediaOutcome::Downloaded { path: "ab/cd/e".into(), sha256: "e".into(), size: 7 })],
            7,
            None,
        );
        assert_eq!(s.write_errors, 0);
        let status: String = conn
            .query_row("SELECT status FROM attachments WHERE rowid = ?1", [rowid], |r| r.get(0))
            .unwrap();
        assert_eq!(status, "downloaded");
    }

    #[test]
    fn error_kinds_are_bounded_and_aggregated() {
        // F3: one entry per DISTINCT kind, whatever the failure count —
        // a 500-failure batch of one kind logs one token, not 500.
        let mut s = Summary::default();
        s.add_error_kind("message:sqlite_ConstraintViolation/787");
        s.add_error_kind("message:sqlite_ConstraintViolation/787");
        s.add_error_kind("media:sqlite_Full/5132");
        assert_eq!(s.write_errors, 3);
        assert_eq!(s.write_error_kinds.len(), 2);
        assert_eq!(s.write_error_kinds["message:sqlite_ConstraintViolation/787"], 2);
        // BTreeMap order keeps the log line stable (sorted by kind).
        assert_eq!(
            s.format_error_kinds(),
            "media:sqlite_Full/5132 x1, message:sqlite_ConstraintViolation/787 x2"
        );
    }

    #[test]
    fn count_aborted_counts_remainder_and_zeroes_successes() {
        // F2: the extracted "transaction gone" decision. Failures stay
        // counted; successes are zeroed (they rolled back); every
        // unprocessed remainder is one `aborted` error.
        let mut s = Summary {
            raw_events: 3,
            raw_errors: 1,
            messages: 2,
            conversations: 1,
            groups: 0,
            contacts: 0,
            other_writes: 1,
            write_errors: 0,
            write_error_kinds: BTreeMap::new(),
        };
        count_aborted(&mut s, ["message", "conversation"].into_iter(), 2, 1);
        assert_eq!(s.write_errors, 5);
        assert_eq!(s.write_error_kinds.get("message:aborted"), Some(&1));
        assert_eq!(s.write_error_kinds.get("conversation:aborted"), Some(&1));
        assert_eq!(s.write_error_kinds.get("item:aborted"), Some(&2));
        assert_eq!(s.write_error_kinds.get("media:aborted"), Some(&1));
        assert_eq!(s.raw_events, 0);
        assert_eq!(s.messages, 0);
        assert_eq!(s.raw_errors, 1, "failures still happened — keep them");
    }

    #[test]
    fn batch_abort_stops_processing_and_zeroes_counters() {
        // F2: RAISE(ROLLBACK) in a trigger reproduces the aborting
        // error class (SQLITE_FULL / SQLITE_IOERR / SQLITE_NOMEM, some
        // SQLITE_BUSY) with no test hook: after the failing statement
        // the transaction is GONE (`is_autocommit()` true), which is
        // exactly the state the old code kept writing through in
        // AUTOCOMMIT mode. This exercises the real production path.
        let conn = db();
        conn.execute_batch(
            "CREATE TRIGGER zr_tx_gone BEFORE INSERT ON messages
             WHEN NEW.msg_id = 'm_kill'
             BEGIN SELECT RAISE(ROLLBACK, 'crafted'); END;",
        )
        .unwrap();
        let msg = |id: &str| Incoming {
            kind: "e2ee",
            direction: "in",
            endpoint: "e2ee:bridge".into(),
            env: serde_json::json!({
                "msgId": id, "uidFrom": "u1", "idTo": "u2", "ts": 5,
                "msgType": "text", "content": "x"
            }),
        };
        let batch = vec![msg("m_kill"), msg("m_never")];
        let s = process_batch(&conn, &batch, &[], 7, None);
        // The failed write carries its sqlite kind…
        assert!(
            s.write_error_kinds.keys().any(|k| k.starts_with("message:sqlite_")),
            "got kinds {:?}",
            s.write_error_kinds
        );
        // …and every unprocessed item is counted as `aborted`.
        assert_eq!(s.write_error_kinds.get("item:aborted"), Some(&1));
        assert_eq!(s.write_errors, 2, "failed write + one aborted item");
        // Success counters zeroed: the raw insert that "succeeded"
        // before the abort rolled back with the transaction.
        assert_eq!(s.raw_events, 0);
        assert_eq!(s.messages, 0);
        assert_eq!(s.conversations, 0);
        // All-or-nothing held: nothing landed, in- or out-of-batch.
        let (msgs, raws): (i64, i64) = conn
            .query_row(
                "SELECT (SELECT COUNT(*) FROM messages),
                        (SELECT COUNT(*) FROM raw_events)",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((msgs, raws), (0, 0));
    }

    #[test]
    fn batch_abort_in_media_counts_remaining_media() {
        // F2, media arm: the first outcome kills the transaction; the
        // second must not autocommit — it is counted `media:aborted`
        // and never applied.
        let conn = db();
        conn.execute_batch(
            "CREATE TRIGGER zr_tx_gone_upd BEFORE UPDATE ON attachments
             WHEN NEW.status = 'downloaded' AND NEW.local_path = 'kill'
             BEGIN SELECT RAISE(ROLLBACK, 'crafted'); END;",
        )
        .unwrap();
        for i in 0..2 {
            conn.execute(
                "INSERT INTO attachments (msg_id, idx, kind, url, status)
                 VALUES (?1, 0, 'image', 'https://h/x', 'ref')",
                [format!("m{i}")],
            )
            .unwrap();
        }
        let ids: Vec<i64> = {
            let mut st = conn
                .prepare("SELECT rowid FROM attachments ORDER BY rowid")
                .unwrap();
            st.query_map([], |r| r.get::<_, i64>(0))
                .unwrap()
                .filter_map(Result::ok)
                .collect()
        };
        let media = vec![
            (ids[0], MediaOutcome::Downloaded { path: "kill".into(), sha256: "k".into(), size: 1 }),
            (ids[1], MediaOutcome::Downloaded { path: "ok".into(), sha256: "o".into(), size: 2 }),
        ];
        let s = process_batch(&conn, &[], &media, 7, None);
        assert!(
            s.write_error_kinds.keys().any(|k| k.starts_with("media:sqlite_")),
            "got kinds {:?}",
            s.write_error_kinds
        );
        assert_eq!(s.write_error_kinds.get("media:aborted"), Some(&1));
        assert_eq!(s.write_errors, 2, "failed outcome + one aborted outcome");
        // Neither outcome landed — the row that would have accepted the
        // second outcome in autocommit mode still reads 'ref'.
        let flipped: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM attachments WHERE status <> 'ref'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(flipped, 0);
    }
}
