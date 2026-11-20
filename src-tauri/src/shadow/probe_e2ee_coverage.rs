//! E2EE COVERAGE PROBE (audit §4 item 1.5 AC iv, batch 10 J3).
//! SHAPE ONLY — counts, h12 id fingerprints and UTC hour buckets;
//! never a msgId in clear, never message content, urls or keys.
//!
//! AC iv: "mọi cmd 551 có msgId → hoặc plaintext `source='e2ee'` hoặc
//! được liệt kê" — every cmd-551 frame's msgId must either have a
//! messages row that the bridge tap delivered as plaintext
//! (`source='e2ee'` with text), or be LISTED by the probe (the
//! audit's warm-up allowance makes a small list acceptable; a large
//! one is a capture gap).
//!
//! How "cmd 551" and "where the msgId lives" are decided — by
//! REUSING the pipeline's own functions, not by re-deriving them:
//! - the stored envelope carries `cmd` at the top level (wire.rs
//!   `decode_ws_frame`); probe_recent.rs pins the same test
//!   (`v.get("cmd") == Some(&Value::from(551))`);
//! - the msgIds are exactly what [`normalize::normalize_ws`] yields
//!   for the envelope — the same `unwrap_payload` descent and the
//!   same `msgs`/`groupMsgs`/`pageMsgs`/`eeMsgs` arrays the flusher
//!   reads, so the census can never drift from what the pipeline
//!   would have written;
//! - `source='e2ee'` with non-empty `text` is "plaintext", the same
//!   definition `probe_e2ee` prints.
//!
//! Undecoded rows (the stored `undecoded` flag — no per-connection
//! key yet) and unparsable payloads cannot yield msgIds: they are
//! counted separately and never inflate `no_row`.
//!
//! Warm-up: the audit allows excluding rows within the first 10
//! minutes after each app `session start`. That marker is NOT
//! derivable from this data: it lives in the app's dlog file
//! (`=== session start ===`), never in the DB, and a raw_events ts
//! gap is not a reliable start signal (sleep/reconnect gaps look the
//! same). The probe therefore prints a note instead of excluding.
//!
//! Run (reviewer, after the app is stopped — reads a temp COPY):
//!   cargo test --lib probe_e2ee_coverage -- --ignored --nocapture

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::Connection;
use serde_json::Value;

use super::probe_util;
use super::{normalize, Write};

/// How one cmd-551 msgId stands in `messages` (pure classification).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Cover {
    /// A messages row the bridge delivered as plaintext:
    /// `source='e2ee'` AND non-empty text.
    Plaintext,
    /// A messages row exists but the plaintext never landed (still
    /// cipher-only) — the LISTED bucket of AC iv.
    CipherOnly,
    /// No messages row at all — the LISTED bucket of AC iv.
    NoRow,
}

/// `row` is the `(source, text)` of the messages row, `None` when the
/// row is missing (pure).
pub(super) fn classify(row: Option<(&str, Option<&str>)>) -> Cover {
    match row {
        None => Cover::NoRow,
        Some((source, text)) => {
            if source == "e2ee" && text.is_some_and(|t| !t.is_empty()) {
                Cover::Plaintext
            } else {
                Cover::CipherOnly
            }
        }
    }
}

/// One UTC hour bucket `yyyyMMddTHH` for a raw_events ts (shape-only
/// label; same civil-date math as the backup stamps).
pub(super) fn ts_bucket(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (y, m, d) = super::backup::civil_from_days(days);
    format!("{y:04}{m:02}{d:02}T{:02}", sod / 3600)
}

/// Up to this many uncovered ids listed (AC iv's "được liệt kê").
pub(super) const SAMPLE_MAX: usize = 10;

/// The AC iv census (pure; unit-tested on fake rows).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Census {
    /// (msg_id, frame ts) pairs seen in cmd-551 frames — duplicates
    /// included, so a frame count and an id count both exist.
    pub occurrences: usize,
    /// Distinct msgIds.
    pub ids: usize,
    pub plaintext: usize,
    pub cipher_only: usize,
    pub no_row: usize,
    /// Up to [`SAMPLE_MAX`] uncovered ids (first-seen order) as
    /// (h12, UTC hour bucket) — the id itself is never kept here.
    pub sample: Vec<(String, String)>,
}

/// Aggregate the census: `occurrences` is one entry per (msg_id, ts)
/// as the frames produced it; `cover` maps every id involved to its
/// [`Cover`] (missing key == [`Cover::NoRow`]). Pure.
pub(super) fn census(occurrences: &[(String, i64)], cover: &BTreeMap<String, Cover>) -> Census {
    // First-seen order (a BTreeSet only dedupes; the Vec keeps order).
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut first: Vec<(&str, i64)> = Vec::new();
    for (id, ts) in occurrences {
        if seen.insert(id.as_str()) {
            first.push((id.as_str(), *ts));
        }
    }
    let mut out = Census {
        occurrences: occurrences.len(),
        ids: first.len(),
        plaintext: 0,
        cipher_only: 0,
        no_row: 0,
        sample: Vec::new(),
    };
    for (id, ts) in first {
        // The sample entry carries h12 + bucket only — the id itself
        // never survives into the output (H-rule).
        let list = |out: &mut Census| {
            if out.sample.len() < SAMPLE_MAX {
                out.sample.push((probe_util::h12(id), ts_bucket(ts)));
            }
        };
        match cover.get(id).copied().unwrap_or(Cover::NoRow) {
            Cover::Plaintext => out.plaintext += 1,
            Cover::CipherOnly => {
                out.cipher_only += 1;
                list(&mut out);
            }
            Cover::NoRow => {
                out.no_row += 1;
                list(&mut out);
            }
        }
    }
    out
}

/// Scan `raw_events` (kind='ws', id > since) for cmd-551 frames and
/// return one (msg_id, frame ts) occurrence per message the
/// pipeline's own normalizer extracts, plus the row counters. Pure
/// w.r.t. the census: reads the COPY, writes nothing, prints
/// nothing.
fn scan_551(conn: &Connection, since: i64) -> (Vec<(String, i64)>, usize, usize, usize, usize) {
    let mut occurrences: Vec<(String, i64)> = Vec::new();
    let (mut frames, mut frames_without_id, mut undecoded, mut unparsable) = (0usize, 0usize, 0usize, 0usize);
    let mut st = conn
        .prepare("SELECT ts, payload_json FROM raw_events WHERE kind = 'ws' AND id > ?1 ORDER BY id")
        .unwrap();
    let rows = st
        .query_map([since], |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, Option<String>>(1)?))
        })
        .unwrap();
    for row in rows {
        let (ts, p) = row.unwrap();
        let Some(p) = p else {
            unparsable += 1;
            continue;
        };
        let Ok(env) = serde_json::from_str::<Value>(&p) else {
            unparsable += 1;
            continue;
        };
        // The stored undecoded flag (wire.rs): no key yet, no payload
        // — such a frame can never yield a msgId.
        if env.get("undecoded").is_some() {
            undecoded += 1;
            continue;
        }
        if env.get("cmd") != Some(&Value::from(551)) {
            continue;
        }
        frames += 1;
        // The pipeline's own extraction (probe_coverage's dispatch
        // runs the same fn for kind='ws'): whatever the flusher would
        // have written, this probe counts.
        let n_before = occurrences.len();
        for w in normalize::normalize_ws(&env, None) {
            if let Write::Message { msg_id, .. } = w {
                occurrences.push((msg_id, ts));
            }
        }
        if occurrences.len() == n_before {
            frames_without_id += 1;
        }
    }
    (occurrences, frames, frames_without_id, undecoded, unparsable)
}

/// Classify every id in `occurrences` against the messages table
/// (reads the COPY only).
fn cover_of(conn: &Connection, occurrences: &[(String, i64)]) -> BTreeMap<String, Cover> {
    let mut cover: BTreeMap<String, Cover> = BTreeMap::new();
    for (id, _) in occurrences {
        if cover.contains_key(id) {
            continue;
        }
        let row: Option<(String, Option<String>)> = conn
            .query_row("SELECT source, text FROM messages WHERE msg_id = ?1", [id], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .ok();
        let c = match row {
            Some((source, text)) => classify(Some((source.as_str(), text.as_deref()))),
            None => Cover::NoRow,
        };
        cover.insert(id.clone(), c);
    }
    cover
}

#[test]
#[ignore = "copies the live store to a temp dir and reads it — reviewer-run"]
fn probe_e2ee_coverage() {
    let (conn, _tmp) = probe_util::open_copy();
    let since = probe_util::since_id();
    let (occurrences, frames, frames_without_id, undecoded, unparsable) = scan_551(&conn, since);
    let cover = cover_of(&conn, &occurrences);
    let c = census(&occurrences, &cover);

    println!(
        "e2ee_coverage: since_id={since} cmd551_frames={frames} frames_without_msgid={frames_without_id} undecoded={undecoded} unparsable={unparsable}"
    );
    println!(
        "  msg_ids={} frame_occurrences={} plaintext_e2ee={} row_cipher_only={} no_row={} uncovered={}",
        c.ids,
        c.occurrences,
        c.plaintext,
        c.cipher_only,
        c.no_row,
        c.cipher_only + c.no_row
    );
    println!(
        "  warm-up: NOT excluded — the session-start marker lives in the app log (dlog), not in the DB, so it is not derivable from this copy"
    );
    for (h, bucket) in &c.sample {
        println!("  uncovered: h12={h} ts_bucket={bucket} (UTC hour)");
    }
    if c.cipher_only + c.no_row > c.sample.len() {
        println!(
            "  (…{} more uncovered, not listed)",
            c.cipher_only + c.no_row - c.sample.len()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In-memory DB with the schema + fake cmd-551 shaped rows.
    fn db() -> Connection {
        let key = crate::migrate::sqlcipher::generate_key().unwrap();
        let conn = crate::migrate::sqlcipher::open_in_memory(&key).unwrap();
        super::super::schema::apply(&conn).unwrap();
        conn
    }

    /// A decoded cmd-551 envelope carrying one E2EE message (the
    /// shape the flusher stores: ciphertext content + the `e2ee`
    /// marker, msgId at the message level).
    fn frame_551(msg_id: &str, e2ee: bool) -> String {
        let e2ee_field = if e2ee { r#","e2ee":"abc""# } else { "" };
        format!(
            r#"{{"cmd":551,"subCmd":0,"error_code":0,"data":{{"data":{{"msgs":[{{"msgId":"{msg_id}","uidFrom":"u1","idTo":"0","ts":1,"msgType":"text","content":"QUJD"{e2ee_field}}}]}}}}}}"#
        )
    }

    fn raw(conn: &Connection, ts: i64, payload: &str) {
        conn.execute(
            "INSERT INTO raw_events (ts, direction, kind, endpoint, payload_json)
             VALUES (?1, 'in', 'ws', 'ws:551/0', ?2)",
            rusqlite::params![ts, payload],
        )
        .unwrap();
    }

    fn msg_row(conn: &Connection, id: &str, source: &str, text: Option<&str>) {
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, source)
             VALUES (?1, 'c1', 'u1', 1, 1, ?2, '{}', ?3)",
            rusqlite::params![id, text, source],
        )
        .unwrap();
    }

    #[test]
    fn classify_covers_the_four_buckets() {
        // Plaintext: exactly source='e2ee' AND non-empty text.
        assert_eq!(classify(Some(("e2ee", Some("bản rõ")))), Cover::Plaintext);
        // Row-but-not-plaintext shapes…
        assert_eq!(classify(Some(("e2ee", Some("")))), Cover::CipherOnly);
        assert_eq!(classify(Some(("e2ee", None))), Cover::CipherOnly);
        assert_eq!(classify(Some(("capture", Some("x")))), Cover::CipherOnly);
        // …and no row at all.
        assert_eq!(classify(None), Cover::NoRow);
    }

    #[test]
    fn ts_bucket_renders_utc_hours() {
        // 0 = 1970-01-01T00 UTC; 1795161374000 = 2026-11-20T07:56:14Z
        // (the backup.rs stamp test vector).
        assert_eq!(ts_bucket(0), "19700101T00");
        assert_eq!(ts_bucket(1_795_161_374_000), "20261120T07");
        // Negative never happens (ms since epoch); must not panic.
        assert_eq!(ts_bucket(-1000), "19691231T23");
    }

    #[test]
    fn census_counts_dedupes_and_bounds_the_sample() {
        // 3 distinct ids over 4 frame occurrences; id1 covered,
        // id2/id3 uncovered in that first-seen order.
        let occ = vec![
            ("id1".into(), 100i64),
            ("id2".into(), 200),
            ("id1".into(), 300), // replay of the same frame: no new id
            ("id3".into(), 400),
        ];
        let cover = BTreeMap::from([("id1".to_string(), Cover::Plaintext)]);
        let c = census(&occ, &cover);
        assert_eq!(c.occurrences, 4);
        assert_eq!(c.ids, 3);
        assert_eq!(c.plaintext, 1);
        assert_eq!(c.cipher_only, 0);
        assert_eq!(c.no_row, 2);
        assert_eq!(c.sample.len(), 2);
        // Sample entries are h12 + bucket, never the id; first-seen
        // order (200 before 400).
        assert_eq!(c.sample[0], (probe_util::h12("id2"), ts_bucket(200)));
        assert_eq!(c.sample[1], (probe_util::h12("id3"), ts_bucket(400)));
        assert_ne!(c.sample[0].0, "id2");
    }

    #[test]
    fn census_sample_caps_at_ten_and_skips_covered() {
        // 12 uncovered + 1 plaintext: the sample is exactly
        // SAMPLE_MAX, all uncovered, none of the covered id.
        let mut occ = Vec::new();
        for i in 0..12 {
            occ.push((format!("u{i}"), 1000 + i as i64));
        }
        occ.push(("ok".into(), 2000));
        let cover = BTreeMap::from([("ok".to_string(), Cover::Plaintext)]);
        let c = census(&occ, &cover);
        assert_eq!(c.no_row, 12);
        assert_eq!(c.sample.len(), SAMPLE_MAX);
        assert!(c.sample.iter().all(|(h, _)| *h != probe_util::h12("ok")));
    }

    #[test]
    fn scan_551_reuses_the_normalizer_and_skips_noise() {
        let conn = db();
        // Two decoded cmd-551 frames (one msgId each)…
        raw(&conn, 100, &frame_551("fake1", true));
        raw(&conn, 200, &frame_551("fake2", true));
        // …a non-551 frame (ignored)…
        raw(&conn, 300, r#"{"cmd":2,"subCmd":1,"error_code":0,"data":{"data":{"msgs":[{"msgId":"other","uidFrom":"u1","idTo":"0","ts":1,"msgType":"text","content":"x"}]}}}"#);
        // …an undecoded 551 (no key — cannot yield ids)…
        raw(&conn, 400, r#"{"cmd":551,"subCmd":0,"encrypt":2,"undecoded":"no-key","body":"abc"}"#);
        // …and an unparsable row.
        raw(&conn, 500, "\u{1}not json");

        let (occ, frames, frames_without_id, undecoded, unparsable) = scan_551(&conn, 0);
        assert_eq!(frames, 2, "only the decoded cmd-551 frames");
        assert_eq!(frames_without_id, 0);
        assert_eq!(undecoded, 1);
        assert_eq!(unparsable, 1);
        assert_eq!(
            occ,
            vec![("fake1".to_string(), 100), ("fake2".to_string(), 200)],
            "msgIds are exactly what normalize_ws extracts"
        );

        // since scopes the scan: nothing after a baseline of 0 rows
        // beyond the max id.
        let max_id: i64 = conn
            .query_row("SELECT MAX(id) FROM raw_events", [], |r| r.get(0))
            .unwrap();
        let (occ2, ..) = scan_551(&conn, max_id);
        assert!(occ2.is_empty());
    }

    #[test]
    fn scan_551_counts_frames_that_yield_no_msgid() {
        let conn = db();
        // A decoded 551 with no message arrays (e.g. an ack shape).
        raw(&conn, 100, r#"{"cmd":551,"subCmd":0,"error_code":0,"data":{"data":{"other":1}}}"#);
        let (occ, frames, frames_without_id, undecoded, unparsable) = scan_551(&conn, 0);
        assert_eq!(frames, 1);
        assert_eq!(frames_without_id, 1);
        assert!(occ.is_empty());
        assert_eq!((undecoded, unparsable), (0, 0));
    }

    #[test]
    fn cover_of_reads_the_messages_table() {
        let conn = db();
        msg_row(&conn, "p1", "e2ee", Some("plaintext"));
        msg_row(&conn, "c1", "capture", None);
        let occ = vec![
            ("p1".to_string(), 1),
            ("c1".to_string(), 2),
            ("gone".to_string(), 3),
        ];
        let cover = cover_of(&conn, &occ);
        assert_eq!(cover["p1"], Cover::Plaintext);
        assert_eq!(cover["c1"], Cover::CipherOnly);
        assert_eq!(cover["gone"], Cover::NoRow);
        // The end-to-end census over the same fake rows.
        let c = census(&occ, &cover);
        assert_eq!(
            (c.ids, c.plaintext, c.cipher_only, c.no_row),
            (3, 1, 1, 1)
        );
    }
}
