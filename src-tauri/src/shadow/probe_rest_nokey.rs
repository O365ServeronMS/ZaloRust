//! NO-KEY REST PROBE (batch 21, R2). SHAPE ONLY — counts and safe
//! endpoint paths; never ciphertext, plaintext, ids, keys or urls
//! with query strings.
//!
//! For REST `raw_events` rows flagged `undecoded:"no-key"` (batch 19's
//! audit trail — one truncated row per body that arrived BEFORE the
//! handshake armed the key), prints a count per safe endpoint, and
//! next to it how many of those no-key rows have a DECODED REST row
//! with the same safe endpoint within 10 minutes AFTER them — the
//! visible signature of a successful pending-queue drain
//! (`rest_pending` holds a body at most 10 minutes, so a drain lands
//! its decoded row inside exactly that window).
//!
//! Definitions (pinned by the unit test):
//! - `no_key` — REST rows whose stored envelope carries
//!   `undecoded:"no-key"`;
//! - `drained` — no-key rows with >= 1 decoded row of the SAME safe
//!   endpoint whose ts falls in `[t, t + 10 min]`; a decoded row is a
//!   REST row with NO `undecoded` flag and a stored `data` value (the
//!   inner envelope a successful decode stores);
//! - `undrained` = `no_key - drained` (the bodies the queue evicted,
//!   dropped at shutdown, or that still failed to decode).
//!
//! NOTE on legacy rows: the pre-H2 rows (ids < 800) store string-`data`
//! envelopes WITHOUT the flag and would count as "decoded" here —
//! harmlessly, because their ts (13–14 Nov) can never fall inside a
//! window behind a batch-19+ no-key row.
//!
//! `ZR_PROBE_SINCE_MS` scopes the no-key rows to `ts >= cut`
//! (unset/<= 0 = the whole ring); the decoded-row window may reach
//! past the cut because the drain relation is anchored on the no-key
//! row's ts.
//!
//! Run (reviewer — the probe works on a temp COPY, never the live DB):
//!   cargo test --lib probe_rest_nokey -- --ignored --nocapture

use std::collections::BTreeMap;

use rusqlite::Connection;

use super::capture::safe_endpoint;
use super::probe_util;

/// The drain window (R1, batch 19): a queued body is at most 10
/// minutes old when the handshake drains it.
const WINDOW_MS: i64 = 10 * 60 * 1000;

/// One safe endpoint's census (shape only).
#[derive(Debug, Default, PartialEq, Eq)]
struct NoKeyEndpoint {
    endpoint: String,
    no_key: i64,
    drained: i64,
}

/// Pure: the per-endpoint census. `nokey` is `(safe endpoint, ts)` per
/// flagged row, `decoded` the decoded rows; a no-key row counts
/// `drained` when a decoded row with the SAME endpoint exists with
/// `ts in [t, t + WINDOW_MS]`. Endpoints are grouped and printed in
/// sorted order (deterministic output).
fn census(nokey: &[(String, i64)], decoded: &[(String, i64)]) -> Vec<NoKeyEndpoint> {
    // Decoded rows grouped per endpoint, each group sorted by ts.
    let mut by_ep: BTreeMap<&str, Vec<i64>> = BTreeMap::new();
    for (ep, ts) in decoded {
        by_ep.entry(ep.as_str()).or_default().push(*ts);
    }
    for v in by_ep.values_mut() {
        v.sort();
    }
    let mut out: BTreeMap<String, NoKeyEndpoint> = BTreeMap::new();
    for (ep, t) in nokey {
        let entry = out.entry(ep.clone()).or_default();
        entry.endpoint = ep.clone();
        entry.no_key += 1;
        if let Some(times) = by_ep.get(ep.as_str()) {
            // First decoded row at/after the no-key row: inside the
            // window it proves the body drained.
            if let Some(&t2) = times.iter().find(|&&x| x >= *t) {
                if t2 <= t + WINDOW_MS {
                    entry.drained += 1;
                }
            }
        }
    }
    out.into_values().collect()
}

/// `(endpoint, ts)` pairs for one SQL shape (kind/flag selected by the
/// caller's SQL); unreadable rows are skipped, never fatal.
fn query_pairs<P: rusqlite::Params>(conn: &Connection, sql: &str, params: P) -> Vec<(String, i64)> {
    let Ok(mut st) = conn.prepare(sql) else {
        return Vec::new();
    };
    st.query_map(params, |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
        .map(|it| it.filter_map(Result::ok).collect())
        .unwrap_or_default()
}

/// The flagged rows (REST only), scoped to `since_ms` (0 = all).
fn nokey_rows(conn: &Connection, since_ms: i64) -> Vec<(String, i64)> {
    query_pairs(
        conn,
        "SELECT endpoint, ts FROM raw_events \
         WHERE kind = 'rest' \
           AND json_extract(payload_json, '$.undecoded') = 'no-key' \
           AND ts >= ?1",
        [since_ms],
    )
}

/// The decoded rows (REST only): no flag, a stored `data` value.
fn decoded_rows(conn: &Connection) -> Vec<(String, i64)> {
    query_pairs(
        conn,
        "SELECT endpoint, ts FROM raw_events \
         WHERE kind = 'rest' \
           AND json_extract(payload_json, '$.undecoded') IS NULL \
           AND json_extract(payload_json, '$.data') IS NOT NULL",
        [],
    )
}

/// The whole census over a connection (the unit test's synthetic store
/// and the ignored probe's copy both land here).
fn rest_nokey_census(conn: &Connection, since_ms: i64) -> Vec<NoKeyEndpoint> {
    // The stored endpoint is already safe for post-rebuild rows, but
    // the legacy V1 rows carry FULL urls with query strings — render
    // everything through `safe_endpoint` before it can group or print.
    let nokey = nokey_rows(conn, since_ms)
        .into_iter()
        .map(|(ep, ts)| (safe_endpoint(&ep), ts))
        .collect::<Vec<_>>();
    let decoded = decoded_rows(conn)
        .into_iter()
        .map(|(ep, ts)| (safe_endpoint(&ep), ts))
        .collect::<Vec<_>>();
    census(&nokey, &decoded)
}

#[test]
#[ignore = "copies the live store to a temp dir (read-only) and prints the no-key census — reviewer-run"]
fn probe_rest_nokey() {
    let since = probe_util::since_ms();
    let (conn, _tmp) = probe_util::open_copy();
    let rows = rest_nokey_census(&conn, since);
    let (no_key, drained): (i64, i64) =
        rows.iter().fold((0, 0), |(a, b), r| (a + r.no_key, b + r.drained));
    println!(
        "probe_rest_nokey: no_key={} drained={} undrained={} endpoints={} window_ms={} since_ms={}",
        no_key,
        drained,
        no_key - drained,
        rows.len(),
        WINDOW_MS,
        if since > 0 { since.to_string() } else { "all".to_string() }
    );
    for r in &rows {
        println!(
            "  {} no_key={} drained={} undrained={}",
            r.endpoint,
            r.no_key,
            r.drained,
            r.no_key - r.drained
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrate::sqlcipher;
    use crate::shadow::schema;

    /// The census on a SYNTHETIC in-memory store (fake endpoints, fake
    /// ts — never the real store; the hard rule).
    #[test]
    fn census_counts_drains_within_the_window_on_a_synthetic_store() {
        let key = sqlcipher::generate_key().unwrap();
        let conn = sqlcipher::open_in_memory(&key).unwrap();
        schema::apply(&conn).unwrap();
        let ins = |kind: &str, ep: &str, ts: i64, payload: &str| {
            conn.execute(
                "INSERT INTO raw_events (ts, direction, kind, endpoint, payload_json) \
                 VALUES (?1, 'in', ?2, ?3, ?4)",
                rusqlite::params![ts, kind, ep, payload],
            )
            .unwrap();
        };
        let nokey = r#"{"error_code":0,"data":"trunc","undecoded":"no-key"}"#;
        let decoded = r#"{"error_code":0,"data":{"msgs":[]}}"#;

        // A: no-key at t=1000, decoded 500 ms later -> drained.
        ins("rest", "/a/get-last-msgs", 1000, nokey);
        ins("rest", "/a/get-last-msgs", 1500, decoded);
        // A: no-key at t=2000, decoded PAST the window -> undrained.
        ins("rest", "/a/get-last-msgs", 2000, nokey);
        ins("rest", "/a/get-last-msgs", 2000 + WINDOW_MS + 1, decoded);
        // B: a no-key row with no decoded row at all.
        ins("rest", "/a/getprofiles/v2", 3000, nokey);
        // C: a decoded row BEFORE the no-key row does not drain it.
        ins("rest", "/a/getmg-v2", 500, decoded);
        ins("rest", "/a/getmg-v2", 600, nokey);
        // D (ws): the same flag on another kind never counts.
        ins("ws", "/a/ws", 700, nokey);
        // A: a flagged `undecoded:true` row counts in NEITHER set.
        ins("rest", "/a/get-last-msgs", 800, r#"{"error_code":0,"data":"x","undecoded":true}"#);
        // E: a no-cipher row (no `data`) is not a decoded row.
        ins("rest", "/a/getmg-v2", 900, r#"{"error_code":0}"#);

        let rows = rest_nokey_census(&conn, 0);
        assert_eq!(
            rows,
            vec![
                NoKeyEndpoint { endpoint: "/a/get-last-msgs".into(), no_key: 2, drained: 1 },
                NoKeyEndpoint { endpoint: "/a/getmg-v2".into(), no_key: 1, drained: 0 },
                NoKeyEndpoint { endpoint: "/a/getprofiles/v2".into(), no_key: 1, drained: 0 },
            ],
            "sorted by endpoint; ws and unflagged kinds never count"
        );

        // `ZR_PROBE_SINCE_MS` scopes the no-key rows: with the cut at
        // 2500 only the t=3000 row remains.
        let scoped = rest_nokey_census(&conn, 2500);
        assert_eq!(
            scoped,
            vec![NoKeyEndpoint { endpoint: "/a/getprofiles/v2".into(), no_key: 1, drained: 0 }]
        );
        // A cut above everything counts nothing.
        assert!(rest_nokey_census(&conn, 100_000).is_empty());
    }

    /// Legacy V1 rows carry FULL urls (query strings included) — the
    /// census must group them under the SAFE rendering before any
    /// printing can happen.
    #[test]
    fn census_renders_legacy_full_urls_through_safe_endpoint() {
        let key = sqlcipher::generate_key().unwrap();
        let conn = sqlcipher::open_in_memory(&key).unwrap();
        schema::apply(&conn).unwrap();
        let nokey = r#"{"error_code":0,"data":"trunc","undecoded":"no-key"}"#;
        let decoded = r#"{"error_code":0,"data":{"msgs":[]}}"#;
        for (ep, ts) in [
            ("https://tt-convers-wpa.chat.zalo.me/api/preloadconvers/get-last-msgs?zcid=fake-a", 1000i64),
            ("https://tt-convers-wpa.chat.zalo.me/api/preloadconvers/get-last-msgs?zcid=fake-b", 1100),
        ] {
            conn.execute(
                "INSERT INTO raw_events (ts, direction, kind, endpoint, payload_json) \
                 VALUES (?1, 'in', 'rest', ?2, ?3)",
                rusqlite::params![ts, ep, nokey],
            )
            .unwrap();
        }
        conn.execute(
            "INSERT INTO raw_events (ts, direction, kind, endpoint, payload_json) \
             VALUES (?1, 'in', 'rest', ?2, ?3)",
            rusqlite::params![
                1200i64,
                "https://tt-convers-wpa.chat.zalo.me/api/preloadconvers/get-last-msgs?zcid=fake-c",
                decoded
            ],
        )
        .unwrap();
        let rows = rest_nokey_census(&conn, 0);
        assert_eq!(rows.len(), 1, "the two query-string urls group together");
        assert_eq!(rows[0].endpoint, "/api/preloadconvers/get-last-msgs");
        assert_eq!(rows[0].no_key, 2);
        assert_eq!(rows[0].drained, 2, "both windows contain the decoded row");
    }
}
