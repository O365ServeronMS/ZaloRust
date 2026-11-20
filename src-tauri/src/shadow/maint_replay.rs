//! MAINTENANCE (audit KQ8, batch 7 G5): replay the misplaced Roaming
//! shadow DB into a COPY of the main store — offline, FILTERED, and
//! only ever on temp copies.
//!
//! KQ8: `%APPDATA%\com.o365serveronms.zalors\shadow\` holds a second
//! store (its own `default.key`, ~14 min of capture 15:08–15:22 on
//! 2026-11-19) that must be replayed into the main DB later, with the
//! app stopped. This tool is that replay's dry-run harness:
//!
//! - SOURCE = the Roaming dir (`ZR_ROAMING_DIR` override), copied to a
//!   temp dir and opened READ-ONLY (`probe_util::open_copy_from`);
//! - TARGET = a temp COPY of the main live set opened READ-WRITE
//!   (`probe_util::open_copy_rw`) — the live DB is never opened;
//! - every source `raw_events` row is offered in id order; kind='e2ee'
//!   rows pass the SAME gate the live path applies
//!   (`normalize::e2ee_admit` — no msgId / key-shaped noise is dropped,
//!   audit C1/KQ7); rows already in the target (same kind + endpoint +
//!   payload sha256) are skipped; the rest is fed through
//!   `pipeline::process_batch` in batches of 500;
//! - running the replay TWICE on the same target copy must add 0
//!   messages the second time (the first run's `raw_events` inserts
//!   make every row a duplicate) — asserted inside the test.
//!
//! H-rule: the printout is counts, kind names and temp-dir paths only
//! — never uids (the own uid prints as configured true/false), keys,
//! endpoints, payload text or file names from the media store.
//!
//! Run (reviewer, after the soak ends; a stopped app gives a cleaner
//! source copy — the copy itself is the only thing at risk):
//! ```text
//! $env:ZR_OWN_UID = "<this account's uid>"
//! cargo test --lib maint_replay_roaming -- --ignored --nocapture
//! ```
//! `ZR_ROAMING_DIR` overrides the source dir (synthetic runs point it
//! at a scratch store instead of the real Roaming one).

use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;

use rusqlite::Connection;
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::normalize::{e2ee_admit, E2eeRefusal};
use super::pipeline::{self, Incoming};
use super::probe_util;

/// The misplaced Roaming store (`ZR_ROAMING_DIR` override, else the
/// documented `%APPDATA%` path).
fn roaming_dir() -> PathBuf {
    if let Some(p) = std::env::var_os("ZR_ROAMING_DIR") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    default_roaming_dir(std::env::var_os("APPDATA").unwrap_or_default())
}

/// The pure part of [`roaming_dir`], unit-tested without env access.
fn default_roaming_dir(appdata: std::ffi::OsString) -> PathBuf {
    PathBuf::from(appdata)
        .join("com.o365serveronms.zalors")
        .join("shadow")
}

/// One source `raw_events` row selected for the replay (values stay
/// in memory only; nothing is printed from here).
#[derive(Debug, Clone, PartialEq)]
struct SourceRow {
    id: i64,
    direction: Option<String>,
    kind: Option<String>,
    endpoint: Option<String>,
    payload: Option<String>,
}

/// Read every source `raw_events` row in id order (reads only).
fn select_source_rows(conn: &Connection) -> Vec<SourceRow> {
    let mut st = conn
        .prepare(
            "SELECT id, direction, kind, endpoint, payload_json \
             FROM raw_events ORDER BY id",
        )
        .unwrap();
    let rows = st
        .query_map([], |r| {
            Ok(SourceRow {
                id: r.get(0)?,
                direction: r.get(1)?,
                kind: r.get(2)?,
                endpoint: r.get(3)?,
                payload: r.get(4)?,
            })
        })
        .unwrap();
    rows.filter_map(Result::ok).collect()
}

/// Rows per kind, as the report prints them (kind names + counts only).
fn rows_by_kind(conn: &Connection) -> BTreeMap<String, i64> {
    let mut st = conn
        .prepare(
            "SELECT COALESCE(kind, '<none>'), COUNT(*) \
             FROM raw_events GROUP BY 1 ORDER BY 1",
        )
        .unwrap();
    st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
        .unwrap()
        .filter_map(Result::ok)
        .collect()
}

/// Canonical form of a stored payload: the serde re-serialization when
/// it parses, the raw string otherwise. Stored payloads ARE
/// `Value::to_string` output on both sides, but two builds could
/// differ in textual details (key order) — hashing the canonical form
/// makes "the same capture" dedupe no matter which build wrote either
/// row. Pure.
fn canonical_payload(payload: &str) -> String {
    serde_json::from_str::<Value>(payload)
        .map(|v| v.to_string())
        .unwrap_or_else(|_| payload.to_string())
}

/// Dedupe key: `kind`, `endpoint` and the FULL sha256 of the payload's
/// canonical form, joined with a byte separator that cannot appear in a
/// kind or endpoint-safe form — two rows with equal keys are the same
/// capture.
fn dedupe_key(kind: &str, endpoint: &str, payload: &str) -> String {
    let mut h = Sha256::new();
    h.update(canonical_payload(payload).as_bytes());
    format!("{kind}\u{1}{endpoint}\u{1}{:x}", h.finalize())
}

/// The target's dedupe key set over all its `raw_events` rows (reads
/// only; payloads never leave this function).
fn target_keys(conn: &Connection) -> HashSet<String> {
    let mut st = conn
        .prepare("SELECT kind, endpoint, payload_json FROM raw_events")
        .unwrap();
    let rows = st
        .query_map([], |r| {
            Ok((
                r.get::<_, Option<String>>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, Option<String>>(2)?,
            ))
        })
        .unwrap();
    rows.filter_map(Result::ok)
        .map(|(k, e, p)| {
            dedupe_key(
                k.as_deref().unwrap_or(""),
                e.as_deref().unwrap_or(""),
                p.as_deref().unwrap_or(""),
            )
        })
        .collect()
}

/// Why one source row was not replayed (pure classification).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SkipReason {
    /// kind='e2ee' refused by the live gate — no msgId.
    E2eeNoMsgId,
    /// kind='e2ee' refused by the live gate — key-shaped payload.
    E2eeKeyish,
    /// kind='e2ee' refused by the live gate — not JSON.
    E2eeNotJson,
    /// Same kind+endpoint+payload sha256 already in the target.
    Duplicate,
    /// A kind the pipeline does not route (legacy kinds).
    UnknownKind,
    /// A non-e2ee payload that does not parse as JSON.
    NotJson,
}

/// Skip counters for one replay pass (shape-only by construction).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct ReplaySkips {
    e2ee_no_msgid: usize,
    e2ee_keyish: usize,
    e2ee_not_json: usize,
    duplicate: usize,
    unknown_kind: usize,
    not_json: usize,
}

impl ReplaySkips {
    fn bump(&mut self, r: SkipReason) {
        match r {
            SkipReason::E2eeNoMsgId => self.e2ee_no_msgid += 1,
            SkipReason::E2eeKeyish => self.e2ee_keyish += 1,
            SkipReason::E2eeNotJson => self.e2ee_not_json += 1,
            SkipReason::Duplicate => self.duplicate += 1,
            SkipReason::UnknownKind => self.unknown_kind += 1,
            SkipReason::NotJson => self.not_json += 1,
        }
    }

    fn total(&self) -> usize {
        self.e2ee_no_msgid
            + self.e2ee_keyish
            + self.e2ee_not_json
            + self.duplicate
            + self.unknown_kind
            + self.not_json
    }

    /// The report line (counters only).
    fn line(&self) -> String {
        format!(
            "e2ee_no_msgid={} e2ee_keyish={} e2ee_not_json={} duplicate={} unknown_kind={} not_json={}",
            self.e2ee_no_msgid, self.e2ee_keyish, self.e2ee_not_json,
            self.duplicate, self.unknown_kind, self.not_json
        )
    }
}

/// Route a stored kind string to the pipeline's static kind tags
/// (`pipeline::normalize_kind` dispatches exactly these three).
fn route_kind(kind: &str) -> Option<&'static str> {
    match kind {
        "ws" => Some("ws"),
        "rest" => Some("rest"),
        "e2ee" => Some("e2ee"),
        _ => None,
    }
}

/// The pure replay plan: filter + dedupe + batch the source rows.
/// Nothing here touches a DB or prints — that keeps the KQ8 selection
/// rules unit-testable on fake rows. Returns the admitted batches
/// (chunked to `batch_max`) and the skip counters.
fn plan_replay(
    rows: &[SourceRow],
    seen: &HashSet<String>,
    batch_max: usize,
) -> (Vec<Vec<Incoming>>, ReplaySkips) {
    let mut skips = ReplaySkips::default();
    let mut admitted: Vec<Incoming> = Vec::new();
    for row in rows {
        let kind = row.kind.as_deref().unwrap_or("");
        let payload = row.payload.as_deref().unwrap_or("");
        // The live e2ee gate first (KQ8: "replay có lọc").
        if kind == "e2ee" {
            match e2ee_admit(payload) {
                Ok(env) => {
                    if skip_common(row, kind, seen, &mut skips) {
                        continue;
                    }
                    admitted.push(Incoming {
                        kind: "e2ee",
                        direction: direction_tag(row.direction.as_deref()),
                        endpoint: row.endpoint.clone().unwrap_or_default(),
                        env,
                    });
                    continue;
                }
                Err(E2eeRefusal::NoMsgId) => skips.bump(SkipReason::E2eeNoMsgId),
                Err(E2eeRefusal::KeyShaped) => skips.bump(SkipReason::E2eeKeyish),
                Err(E2eeRefusal::NotJson) => skips.bump(SkipReason::E2eeNotJson),
            }
            continue;
        }
        // ws / rest / anything else: dedupe and route first, parse last
        // (an unparsable payload of an unknown kind counts once, as
        // unknown — routing decides what the row even is).
        if skip_common(row, kind, seen, &mut skips) {
            continue;
        }
        let Some(tag) = route_kind(kind) else {
            skips.bump(SkipReason::UnknownKind);
            continue;
        };
        match serde_json::from_str::<Value>(payload) {
            Ok(env) => admitted.push(Incoming {
                kind: tag,
                direction: direction_tag(row.direction.as_deref()),
                endpoint: row.endpoint.clone().unwrap_or_default(),
                env,
            }),
            Err(_) => skips.bump(SkipReason::NotJson),
        }
    }
    // Batches of `batch_max` (KQ8: 500 per batch, like the live path).
    let batches = admitted
        .chunks(batch_max.max(1))
        .map(<[Incoming]>::to_vec)
        .collect();
    (batches, skips)
}

/// The checks shared by every kind: duplicate against the target's
/// existing rows. Returns true when the row is skipped.
fn skip_common(
    row: &SourceRow,
    kind: &str,
    seen: &HashSet<String>,
    skips: &mut ReplaySkips,
) -> bool {
    let key = dedupe_key(
        kind,
        row.endpoint.as_deref().unwrap_or(""),
        row.payload.as_deref().unwrap_or(""),
    );
    if seen.contains(&key) {
        skips.bump(SkipReason::Duplicate);
        true
    } else {
        false
    }
}

/// Stored directions map onto the pipeline's two tags; anything else
/// keeps the live default ("in").
fn direction_tag(direction: Option<&str>) -> &'static str {
    match direction {
        Some("out") => "out",
        _ => "in",
    }
}

/// The table counts the report prints before/after (counts only).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct TableCounts {
    raw_events: i64,
    messages: i64,
    conversations: i64,
    contacts: i64,
    groups: i64,
    attachments: i64,
}

fn table_counts(conn: &Connection) -> TableCounts {
    let q = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get(0)).unwrap_or(-1) };
    TableCounts {
        raw_events: q("SELECT COUNT(*) FROM raw_events"),
        messages: q("SELECT COUNT(*) FROM messages"),
        conversations: q("SELECT COUNT(*) FROM conversations"),
        contacts: q("SELECT COUNT(*) FROM contacts"),
        groups: q("SELECT COUNT(*) FROM groups"),
        attachments: q("SELECT COUNT(*) FROM attachments"),
    }
}

/// Sum pipeline summaries across batches (counters only).
fn merge_summary(total: &mut pipeline::Summary, s: pipeline::Summary) {
    total.raw_events += s.raw_events;
    total.raw_errors += s.raw_errors;
    total.messages += s.messages;
    total.conversations += s.conversations;
    total.groups += s.groups;
    total.contacts += s.contacts;
    total.other_writes += s.other_writes;
    total.write_errors += s.write_errors;
    for (k, v) in s.write_error_kinds {
        *total.write_error_kinds.entry(k).or_insert(0) += v;
    }
}

/// One replay pass over the target copy: build the plan from the
/// target's CURRENT dedupe keys, then run the batches through the
/// pipeline. `raw_days = u32::MAX` so the replay never trims the
/// target's ring — the copy must keep everything it already holds.
fn replay_once(
    tgt: &Connection,
    rows: &[SourceRow],
    own_uid: Option<&str>,
    batch_max: usize,
) -> (usize, ReplaySkips, pipeline::Summary) {
    let seen = target_keys(tgt);
    let (batches, skips) = plan_replay(rows, &seen, batch_max);
    let mut total = pipeline::Summary::default();
    for batch in &batches {
        let s = pipeline::process_batch(tgt, batch, &[], u32::MAX, own_uid);
        merge_summary(&mut total, s);
    }
    (batches.len(), skips, total)
}

#[test]
#[ignore]
fn maint_replay_roaming() {
    // KQ8: source = the misplaced Roaming store (READ-ONLY copy);
    // target = a temp COPY of the main live set (READ-WRITE). Neither
    // the live DB nor the Roaming store is ever opened directly.
    let src_dir = roaming_dir();
    let (src, src_tmp) = probe_util::open_copy_from(&src_dir, true);
    let (tgt, tgt_tmp) = probe_util::open_copy_rw();

    // KQ2: the own uid is configuration — validated, and the report
    // only ever says whether one was configured.
    let own_uid = std::env::var("ZR_OWN_UID")
        .ok()
        .filter(|u| super::account::valid_uid(u));
    println!("maint replay: own uid configured: {}", own_uid.is_some());

    // Source census (counts + kind names only).
    let by_kind = rows_by_kind(&src);
    let kinds: Vec<String> = by_kind
        .iter()
        .map(|(k, n)| format!("{k}={n}"))
        .collect();
    let total_source: i64 = by_kind.values().sum();
    println!("maint replay: source rows by kind: {} (total {total_source})", kinds.join(" "));

    let rows = select_source_rows(&src);
    let before = table_counts(&tgt);

    // Pass 1.
    let (batches, skips, total) = replay_once(&tgt, &rows, own_uid.as_deref(), 500);
    println!("maint replay: skipped: {}", skips.line());
    println!(
        "maint replay: admitted={} in {batches} batch(es) of <= 500",
        rows.len() - skips.total()
    );
    println!(
        "maint replay: totals: raw={} raw_errors={} messages={} convs={} groups={} contacts={} other={} write_errors={}{}",
        total.raw_events, total.raw_errors, total.messages, total.conversations,
        total.groups, total.contacts, total.other_writes, total.write_errors,
        if total.write_error_kinds.is_empty() {
            String::new()
        } else {
            format!(" (kinds: {})", total.format_error_kinds())
        }
    );
    let after1 = table_counts(&tgt);
    println!(
        "maint replay: target counts: raw_events {}->{} messages {}->{} conversations {}->{} contacts {}->{} groups {}->{} attachments {}->{}",
        before.raw_events, after1.raw_events, before.messages, after1.messages,
        before.conversations, after1.conversations, before.contacts, after1.contacts,
        before.groups, after1.groups, before.attachments, after1.attachments
    );

    // Pass 2 on the SAME target copy: every admitted row of pass 1 is
    // now in the target's raw_events, so everything is either a
    // duplicate or an e2ee refusal again — 0 new messages.
    let (batches2, skips2, total2) = replay_once(&tgt, &rows, own_uid.as_deref(), 500);
    let after2 = table_counts(&tgt);
    let added = after2.messages - after1.messages;
    println!(
        "maint replay: pass 2: batches={batches2} admitted=0 expected (skipped: {}) messages added={added}",
        skips2.line()
    );
    assert_eq!(
        added, 0,
        "the second replay pass must add 0 messages to the same copy"
    );
    assert_eq!(total2.messages, 0, "the second pass's pipeline wrote no messages");
    assert_eq!(batches2, 0, "with everything skipped, no batch is built");

    // Both temp copies stay on disk for the reviewer; print the dirs.
    println!("maint replay: source copy dir: {}", src_tmp.display());
    println!("maint replay: target copy dir: {}", tgt_tmp.display());
}

#[cfg(test)]
mod tests {
    use super::super::account;
    use super::super::schema;
    use super::*;
    use crate::migrate::sqlcipher;

    fn db() -> Connection {
        let key = sqlcipher::generate_key().unwrap();
        let conn = sqlcipher::open_in_memory(&key).unwrap();
        schema::apply(&conn).unwrap();
        conn
    }

    fn raw(conn: &Connection, id_out: &mut i64, kind: &str, ep: &str, payload: &str) -> i64 {
        conn.execute(
            "INSERT INTO raw_events (ts, direction, kind, endpoint, payload_json)
             VALUES (1, 'in', ?1, ?2, ?3)",
            rusqlite::params![kind, ep, payload],
        )
        .unwrap();
        let id: i64 = conn
            .query_row("SELECT last_insert_rowid()", [], |r| r.get(0))
            .unwrap();
        *id_out = id;
        id
    }

    // FAKE payloads (never real traffic): a ws envelope carrying one
    // message, a rest clearUnreads body, valid/keyish/no-msgId e2ee
    // payloads, and noise.
    const WS_ENV: &str = r#"{"cmd":2,"subCmd":1,"data":{"data":{"msgs":[{"msgId":"fake1","uidFrom":"u1","idTo":"0","ts":1,"msgType":"text","content":"x"}]}}}"#;
    const REST_ENV: &str = r#"{"error_code":0,"data":{"clearUnreads":[{"idTo":"u9","isGroup":false,"lastMsgId":"m1"}]}}"#;
    const E2EE_OK: &str = r#"{"msgId":"fake2","uidFrom":"u1","idTo":"u2","ts":1,"msgType":"webchat","content":"c"}"#;
    const E2EE_NO_ID: &str = r#"{"sigBytes":16,"words":[1,2,3,4]}"#;
    const E2EE_KEYISH: &str = r#"{"msgId":"fake3","data":{"ciphertext":{},"salt":{}}}"#;

    fn seeded_source() -> Connection {
        let conn = db();
        let mut last = 0i64;
        raw(&conn, &mut last, "ws", "ws:2/1", WS_ENV);
        raw(&conn, &mut last, "rest", "https://x/a/preloadconvers/get-last-msgs", REST_ENV);
        raw(&conn, &mut last, "e2ee", "e2ee:bridge", E2EE_OK);
        raw(&conn, &mut last, "e2ee", "e2ee:bridge", E2EE_NO_ID);
        raw(&conn, &mut last, "e2ee", "e2ee:bridge", E2EE_KEYISH);
        raw(&conn, &mut last, "e2ee", "e2ee:bridge", "not json");
        raw(&conn, &mut last, "ws", "ws:551/0", "\u{1}not json either");
        raw(&conn, &mut last, "ws-open", "ws:1/0", "{}");
        conn
    }

    #[test]
    fn roaming_default_dir_is_the_documented_path() {
        assert_eq!(
            default_roaming_dir(std::ffi::OsString::from(r"C:\Users\u\AppData\Roaming")),
            PathBuf::from(r"C:\Users\u\AppData\Roaming\com.o365serveronms.zalors\shadow")
        );
    }

    #[test]
    fn select_returns_rows_in_id_order() {
        let conn = seeded_source();
        let rows = select_source_rows(&conn);
        assert_eq!(rows.len(), 8);
        assert!(rows.windows(2).all(|w| w[0].id < w[1].id), "id order");
        assert_eq!(rows[0].kind.as_deref(), Some("ws"));
        assert_eq!(rows[7].kind.as_deref(), Some("ws-open"));
        // Kind census matches the rows.
        let kinds = rows_by_kind(&conn);
        assert_eq!(kinds["ws"], 2);
        assert_eq!(kinds["rest"], 1);
        assert_eq!(kinds["e2ee"], 4);
        assert_eq!(kinds["ws-open"], 1);
    }

    #[test]
    fn dedupe_key_is_payload_sensitive() {
        let a = dedupe_key("ws", "ws:2/1", WS_ENV);
        assert_eq!(a, dedupe_key("ws", "ws:2/1", WS_ENV));
        // Cosmetic-only differences canonicalize away: key order and
        // trailing whitespace are NOT a new capture.
        assert_eq!(a, dedupe_key("ws", "ws:2/1", &reordered_ws_env()));
        assert_eq!(a, dedupe_key("ws", "ws:2/1", &format!("{WS_ENV} ")));
        // A real difference — kind, endpoint or content — changes it.
        assert_ne!(a, dedupe_key("ws", "ws:3/1", WS_ENV));
        assert_ne!(a, dedupe_key("rest", "ws:2/1", WS_ENV));
        assert_ne!(a, dedupe_key("ws", "ws:2/1", &WS_ENV.replace("fake1", "fake9")));
        // Unparsable payloads fall back to the raw bytes.
        assert_ne!(dedupe_key("ws", "e", "\u{1}a"), dedupe_key("ws", "e", "\u{1}b"));
    }

    /// The same WS capture with its top-level keys in a different
    /// order — one line, so the fixture stays readable.
    fn reordered_ws_env() -> String {
        r#"{"data":{"data":{"msgs":[{"msgId":"fake1","uidFrom":"u1","idTo":"0","ts":1,"msgType":"text","content":"x"}]}},"subCmd":1,"cmd":2}"#.into()
    }

    #[test]
    fn plan_filters_e2ee_noise_and_duplicates() {
        let src = seeded_source();
        let rows = select_source_rows(&src);
        // The target already holds the ws row verbatim (the same
        // capture reached the main store) and the e2ee-no-id row (noise
        // captured into both stores by the old tap).
        let tgt = db();
        let mut last = 0i64;
        raw(&tgt, &mut last, "ws", "ws:2/1", WS_ENV);
        raw(&tgt, &mut last, "e2ee", "e2ee:bridge", E2EE_NO_ID);
        let seen = target_keys(&tgt);

        let (batches, skips) = plan_replay(&rows, &seen, 500);
        // admitted: rest + e2ee_ok -> 2 rows, one batch.
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].len(), 2);
        // The e2ee gate runs BEFORE the duplicate check (KQ8: filter
        // first), so the no-id row counts as refused — even though the
        // same noise also reached the target's raw_events.
        assert_eq!(skips.e2ee_no_msgid, 1);
        assert_eq!(skips.e2ee_keyish, 1);
        assert_eq!(skips.e2ee_not_json, 1);
        assert_eq!(skips.duplicate, 1, "only the ws row is a plain duplicate");
        assert_eq!(skips.unknown_kind, 1, "the legacy ws-open kind");
        assert_eq!(skips.not_json, 1, "the unparsable ws payload");
        assert_eq!(rows.len() - skips.total(), 2);
        // The two admitted Incomings keep their stored kinds and
        // endpoints (never printed, just carried).
        let kinds: Vec<&str> = batches[0].iter().map(|i| i.kind).collect();
        assert_eq!(kinds, vec!["rest", "e2ee"]);
        assert_eq!(batches[0][0].direction, "in");
    }

    #[test]
    fn plan_chunks_batches_at_the_limit() {
        let mut rows = Vec::new();
        for i in 0..501 {
            rows.push(SourceRow {
                id: i as i64,
                direction: Some("in".into()),
                kind: Some("rest".into()),
                endpoint: Some("https://x/a/b".into()),
                payload: Some(REST_ENV.replace("u9", &format!("u{i}"))),
            });
        }
        let (batches, skips) = plan_replay(&rows, &HashSet::new(), 500);
        assert_eq!(batches.len(), 2);
        assert_eq!(batches[0].len(), 500);
        assert_eq!(batches[1].len(), 1);
        assert_eq!(skips.total(), 0);
        // batch_max 0 still yields progress (chunks of 1).
        let (tiny, _) = plan_replay(&rows, &HashSet::new(), 0);
        assert_eq!(tiny.len(), 501);
    }

    #[test]
    fn direction_tag_only_recognizes_out() {
        assert_eq!(direction_tag(Some("out")), "out");
        assert_eq!(direction_tag(Some("in")), "in");
        assert_eq!(direction_tag(None), "in");
        assert_eq!(direction_tag(Some("sideways")), "in");
    }

    #[test]
    fn replay_lands_messages_then_pass_two_adds_zero() {
        // The miniature KQ8 acceptance: pass 1 writes the fake
        // messages, pass 2 on the same target writes none.
        let src = seeded_source();
        let rows = select_source_rows(&src);
        let tgt = db();
        let before = table_counts(&tgt);
        assert_eq!(before.messages, 0);

        // FAKE uid of the documented shape.
        let own_uid = Some("1234567890123456789");
        assert!(account::valid_uid(own_uid.unwrap()));

        let (batches, skips, total) = replay_once(&tgt, &rows, own_uid, 500);
        assert_eq!(batches, 1);
        // The target starts EMPTY here, so nothing is a duplicate yet:
        // 3 refusals (the e2ee gate) + unknown kind + not json.
        assert_eq!(skips.total(), 5);
        // ws fake1 + e2ee fake2 land as messages; the rest row makes
        // one conversation.
        assert_eq!(total.messages, 2);
        assert_eq!(total.conversations, 1);
        assert_eq!(total.write_errors, 0);
        let after1 = table_counts(&tgt);
        assert_eq!(after1.messages, 2);

        // Pass 2: everything is refused or a duplicate now — the three
        // pass-1 inserts joined the target's raw_events.
        let (batches2, skips2, total2) = replay_once(&tgt, &rows, own_uid, 500);
        assert_eq!(batches2, 0);
        assert_eq!(total2.messages, 0);
        assert_eq!(total2.raw_events, 0);
        assert_eq!(skips2.duplicate, 3, "ws + rest + e2ee_ok from pass 1");
        assert_eq!(skips2.e2ee_no_msgid, 1, "the gate still fires first");
        let after2 = table_counts(&tgt);
        assert_eq!(after2.messages, after1.messages, "no new messages");
        assert_eq!(after2.raw_events, after1.raw_events, "no new raw rows");
    }

    #[test]
    fn merge_summary_sums_counters_and_kinds() {
        let mut a = pipeline::Summary::default();
        a.messages = 1;
        a.write_error_kinds.insert("message:sqlite_Full/5132".into(), 2);
        let mut b = pipeline::Summary::default();
        b.messages = 3;
        b.write_errors = 1;
        b.write_error_kinds.insert("media:sqlite_Full/5132".into(), 1);
        merge_summary(&mut a, b);
        assert_eq!(a.messages, 4);
        assert_eq!(a.write_errors, 1);
        assert_eq!(a.write_error_kinds["message:sqlite_Full/5132"], 2);
        assert_eq!(a.write_error_kinds["media:sqlite_Full/5132"], 1);
    }

    #[test]
    fn target_keys_cover_every_target_row() {
        let tgt = db();
        let mut last = 0i64;
        raw(&tgt, &mut last, "ws", "ws:2/1", WS_ENV);
        raw(&tgt, &mut last, "rest", "https://x/a/b", REST_ENV);
        let keys = target_keys(&tgt);
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&dedupe_key("ws", "ws:2/1", WS_ENV)));
        assert!(keys.contains(&dedupe_key("rest", "https://x/a/b", REST_ENV)));
    }

    #[test]
    fn source_row_never_prints_helpers_stay_shape_only() {
        // The report lines carry counters and kind names only; this is
        // the regression net for future edits of the print helpers.
        let s = ReplaySkips {
            e2ee_no_msgid: 4133,
            e2ee_keyish: 2,
            duplicate: 7,
            ..ReplaySkips::default()
        };
        let line = s.line();
        assert_eq!(s.total(), 4142);
        assert!(line.starts_with("e2ee_no_msgid=4133"));
        assert!(!line.contains(':') || !line.contains("https://"), "no endpoints in the line");
        assert!(!line.contains("u1"), "no uids in the line");
    }
}
