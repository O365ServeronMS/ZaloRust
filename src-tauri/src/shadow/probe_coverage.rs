//! COVERAGE PROBE (audit §4 item 1.5 AC iii, batch 5 E1). SHAPE ONLY —
//! counts, msgType strings, safe endpoint names and sha256-12 of ids;
//! never payload values, urls, uids, msgIds in clear, or keys.
//!
//! Re-runs the pipeline's own normalizer dispatch
//! (`pipeline::normalize_kind`) over every stored `raw_events` payload
//! with `id > ZR_PROBE_SINCE_ID` (default 0), collects the message ids
//! each row WOULD produce, and anti-joins them against `messages` —
//! AC iii: every msgId seen on the wire must have a messages row.
//!
//! Undecoded rows (the stored `undecoded` envelope flag) and unparsable
//! payloads are counted per kind separately: they cannot yield
//! messages, so they must not inflate `missing`.
//!
//! Also prints the audit 1.2 integrity counters (the migration AC) in
//! one block: self_sent_sender_null, msgs_without_conv_row,
//! convs_lastmsg_not_newest, type_100_by_msgType (msgType strings are
//! allowed), rev_gt0_by_source, rest_endpoints_with_query.
//!
//! Run (reviewer, after the app is stopped — reads a temp COPY):
//!   cargo test --lib probe_coverage -- --ignored --nocapture

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::Connection;
use serde_json::Value;

use super::capture::safe_endpoint;
use super::pipeline::normalize_kind;
use super::probe_util;
use super::Write;

/// Per-kind census of one scan over `raw_events` (shape-only fields).
#[derive(Default)]
struct KindCov {
    raw_rows: usize,
    rows_with_msg: usize,
    undecoded: usize,
    unparsable: usize,
    ids: BTreeSet<String>,
    /// id -> "kind <safe endpoint>" of the first row that produced it
    /// (only used for the missing-sample line; the id itself is never
    /// printed — only its h12).
    origin: BTreeMap<String, String>,
}

/// Re-run the normalizer dispatch over every raw_events row with
/// `id > since` and census what it would write (pure: reads only,
/// writes nothing, prints nothing).
fn scan_raw(conn: &Connection, since: i64) -> BTreeMap<String, KindCov> {
    let mut out: BTreeMap<String, KindCov> = BTreeMap::new();
    let mut st = conn
        .prepare("SELECT kind, endpoint, payload_json FROM raw_events WHERE id > ?1 ORDER BY id")
        .unwrap();
    let rows = st
        .query_map([since], |r| {
            Ok((
                r.get::<_, Option<String>>(0)?.unwrap_or_default(),
                r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                r.get::<_, Option<String>>(2)?.unwrap_or_default(),
            ))
        })
        .unwrap();
    for row in rows {
        let (kind, ep, payload) = row.unwrap();
        let cov = out.entry(kind.clone()).or_default();
        cov.raw_rows += 1;
        let Ok(env) = serde_json::from_str::<Value>(&payload) else {
            cov.unparsable += 1;
            continue;
        };
        // The stored undecoded flag (wire.rs: `"undecoded": "no-key"` or
        // `true`) — those rows can never yield messages.
        if env.get("undecoded").is_some() {
            cov.undecoded += 1;
            continue;
        }
        // own_uid = None: the probe must not depend on account config;
        // a None uid only leaves self-sent senders NULL, which never
        // changes WHICH msg ids a row produces.
        let writes = normalize_kind(&kind, &ep, &env, None);
        let msg_ids: Vec<String> = writes
            .iter()
            .filter_map(|w| match w {
                Write::Message { msg_id, .. } => Some(msg_id.clone()),
                _ => None,
            })
            .collect();
        if !msg_ids.is_empty() {
            cov.rows_with_msg += 1;
        }
        for id in msg_ids {
            if cov.ids.insert(id.clone()) {
                cov.origin
                    .entry(id)
                    .or_insert_with(|| format!("{kind} {}", safe_endpoint(&ep)));
            }
        }
    }
    out
}

/// Anti-join: which of `ids` have no `messages` row (pure).
fn missing_in_messages(conn: &Connection, ids: &BTreeSet<String>) -> BTreeSet<String> {
    let known: BTreeSet<String> = {
        let mut st = conn.prepare("SELECT msg_id FROM messages").unwrap();
        st.query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .filter_map(Result::ok)
            .collect()
    };
    ids.difference(&known).cloned().collect()
}

/// The audit 1.2 integrity counters (shape-only; msgType strings and
/// source labels are allowed). `since` scopes the raw_events counter.
struct Integrity {
    self_sent_sender_null: i64,
    msgs_without_conv_row: i64,
    convs_lastmsg_not_newest: i64,
    /// msgType string + count.
    type_100_by_msg_type: Vec<(String, i64)>,
    /// source + count.
    rev_gt0_by_source: Vec<(String, i64)>,
    rest_endpoints_with_query: i64,
}

/// Aggregate the integrity counters (pure; the exact audit AC names).
fn integrity_counters(conn: &Connection, since: i64) -> Integrity {
    let q = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get(0)).unwrap_or(-1) };
    let pairs = |sql: &str| -> Vec<(String, i64)> {
        let mut st = match conn.prepare(sql) {
            Ok(st) => st,
            Err(_) => return Vec::new(),
        };
        st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
            .map(|it| it.filter_map(Result::ok).collect())
            .unwrap_or_default()
    };
    Integrity {
        self_sent_sender_null: q(
            "SELECT COUNT(*) FROM messages \
             WHERE json_extract(payload_json,'$.uidFrom')='0' AND sender_id IS NULL",
        ),
        msgs_without_conv_row: q(
            "SELECT COUNT(*) FROM messages m \
             WHERE NOT EXISTS (SELECT 1 FROM conversations c WHERE c.id = m.conv_id)",
        ),
        convs_lastmsg_not_newest: q(
            "SELECT COUNT(*) FROM conversations c JOIN messages m ON m.msg_id = c.last_msg_id \
             WHERE m.ts < (SELECT MAX(ts) FROM messages x WHERE x.conv_id = c.id)",
        ),
        type_100_by_msg_type: pairs(
            "SELECT COALESCE(json_extract(payload_json,'$.msgType'),'<none>'), COUNT(*) \
             FROM messages WHERE type = 100 GROUP BY 1 ORDER BY 2 DESC, 1",
        ),
        rev_gt0_by_source: pairs(
            "SELECT source, COUNT(*) FROM messages WHERE rev > 0 GROUP BY 1 ORDER BY 1",
        ),
        rest_endpoints_with_query: conn
            .query_row(
                "SELECT COUNT(*) FROM raw_events \
                  WHERE kind='rest' AND endpoint LIKE '%?%' AND id > ?1",
                [since],
                |r| r.get(0),
            )
            .unwrap_or(-1),
    }
}

#[test]
#[ignore]
fn probe_coverage() {
    let (conn, _tmp) = probe_util::open_copy();
    let since = probe_util::since_id();
    println!("== raw_events -> messages coverage (since_id={since}) ==");
    let cov = scan_raw(&conn, since);
    let all_ids: BTreeSet<String> = cov.values().flat_map(|c| c.ids.iter().cloned()).collect();
    let missing = missing_in_messages(&conn, &all_ids);

    let mut total_missing = 0usize;
    for (kind, c) in &cov {
        let kmissing = c.ids.intersection(&missing).count();
        total_missing += kmissing;
        println!(
            "kind {kind}: raw_rows={} rows_with_msg={} distinct_msg_ids={} missing={} undecoded={} unparsable={}",
            c.raw_rows, c.rows_with_msg, c.ids.len(), kmissing, c.undecoded, c.unparsable
        );
    }
    println!("total_missing={total_missing}");
    // Up to 10 missing ids: h12 + kind + safe endpoint, never the id.
    let mut sample = 0usize;
    'outer: for (kind, c) in &cov {
        for id in c.ids.intersection(&missing) {
            if sample >= 10 {
                break 'outer;
            }
            let h = probe_util::h12(id);
            let origin = c.origin.get(id).cloned().unwrap_or_else(|| kind.clone());
            println!("missing: h12={h} {origin}");
            sample += 1;
        }
    }
    if total_missing > sample {
        println!("(…{more} more, not listed)", more = total_missing - sample);
    }

    println!("== integrity (audit 1.2 AC) ==");
    let i = integrity_counters(&conn, since);
    println!(
        "self_sent_sender_null={} msgs_without_conv_row={} convs_lastmsg_not_newest={} rest_endpoints_with_query={}",
        i.self_sent_sender_null,
        i.msgs_without_conv_row,
        i.convs_lastmsg_not_newest,
        i.rest_endpoints_with_query
    );
    let t100: Vec<String> = i
        .type_100_by_msg_type
        .iter()
        .map(|(mt, n)| format!("{mt}={n}"))
        .collect();
    println!("type_100_by_msgType: {}", t100.join(" "));
    let revs: Vec<String> = i
        .rev_gt0_by_source
        .iter()
        .map(|(s, n)| format!("{s}={n}"))
        .collect();
    println!("rev_gt0_by_source: {}", revs.join(" "));
}

#[cfg(test)]
mod tests {
    use super::super::schema;
    use super::*;
    use crate::migrate::sqlcipher;

    fn db() -> Connection {
        let key = sqlcipher::generate_key().unwrap();
        let conn = sqlcipher::open_in_memory(&key).unwrap();
        schema::apply(&conn).unwrap();
        conn
    }

    fn raw(conn: &Connection, kind: &str, ep: &str, payload: &str) {
        conn.execute(
            "INSERT INTO raw_events (ts, direction, kind, endpoint, payload_json)
             VALUES (1, 'in', ?1, ?2, ?3)",
            rusqlite::params![kind, ep, payload],
        )
        .unwrap();
    }

    fn msg(conn: &Connection, id: &str, conv: &str, payload: &str, rev: i64, typ: i64) {
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, rev, deleted, source)
             VALUES (?1, ?2, 'u1', 1, ?3, NULL, ?4, ?5, 0, 'capture')",
            rusqlite::params![id, conv, typ, payload, rev],
        )
        .unwrap();
    }

    const WS_ENV: &str = r#"{"cmd":2,"subCmd":1,"data":{"data":{"msgs":[{"msgId":"MSGID","uidFrom":"u1","idTo":"0","ts":1,"msgType":"text","content":"x"}]}}}"#;

    fn ws_payload(id: &str) -> String {
        WS_ENV.replace("MSGID", id)
    }

    #[test]
    fn scan_counts_per_kind_and_flags_the_missing_row() {
        let conn = db();
        // ws row whose message exists, and one whose message is MISSING.
        raw(&conn, "ws", "ws:2/1", &ws_payload("fake1"));
        raw(&conn, "ws", "ws:2/1", &ws_payload("fake2"));
        msg(&conn, "fake1", "cA", &r#"{"msgId":"fake1","uidFrom":"u1","ts":1,"msgType":"text","content":"x"}"#, 0, 1);
        // rest row: clearUnreads only -> conversations, no message ids.
        raw(&conn, "rest", "https://x/a/preloadconvers/get-last-msgs?sig=zzz",
            r#"{"error_code":0,"data":{"clearUnreads":[{"idTo":"u9","isGroup":false,"lastMsgId":"m1"}]}}"#);
        // e2ee row whose message is missing.
        raw(&conn, "e2ee", "e2ee:bridge",
            r#"{"msgId":"fake3","uidFrom":"u1","idTo":"u2","ts":1,"msgType":"webchat","content":"c"}"#);
        // The stored undecoded flag, and one unparsable row: neither can
        // yield messages, so they must not enter `missing`.
        raw(&conn, "ws", "ws:551/0", r#"{"cmd":551,"subCmd":0,"encrypt":2,"undecoded":"no-key"}"#);
        raw(&conn, "ws", "ws:1/0", "\u{1}not json");

        let cov = scan_raw(&conn, 0);
        let ws = &cov["ws"];
        assert_eq!(ws.raw_rows, 4);
        assert_eq!(ws.rows_with_msg, 2);
        assert_eq!(ws.undecoded, 1);
        assert_eq!(ws.unparsable, 1);
        assert_eq!(ws.ids.len(), 2);
        let rest = &cov["rest"];
        assert_eq!(rest.raw_rows, 1);
        assert_eq!(rest.rows_with_msg, 0, "clearUnreads yields conversations, not messages");
        assert_eq!(cov["e2ee"].ids.len(), 1);

        let all: BTreeSet<String> = cov.values().flat_map(|c| c.ids.iter().cloned()).collect();
        let missing = missing_in_messages(&conn, &all);
        assert_eq!(
            missing,
            BTreeSet::from(["fake2".to_string(), "fake3".to_string()]),
            "only the un-written ids are missing"
        );
        // The sample-line origins carry kind + safe endpoint (query stripped).
        assert_eq!(cov["e2ee"].origin["fake3"], "e2ee e2ee:bridge");
        assert_eq!(cov["ws"].origin["fake2"], "ws ws:2/1");
    }

    #[test]
    fn scan_respects_the_since_baseline() {
        let conn = db();
        raw(&conn, "ws", "ws:2/1", &ws_payload("fake1"));
        let max_id: i64 = conn
            .query_row("SELECT MAX(id) FROM raw_events", [], |r| r.get(0))
            .unwrap();
        raw(&conn, "ws", "ws:2/1", &ws_payload("fake2"));
        let cov = scan_raw(&conn, max_id);
        assert_eq!(cov["ws"].raw_rows, 1, "only rows with id > since");
        assert_eq!(cov["ws"].ids, BTreeSet::from(["fake2".to_string()]));
        assert_eq!(scan_raw(&conn, 0)["ws"].raw_rows, 2);
    }

    #[test]
    fn integrity_counters_match_fake_rows() {
        let conn = db();
        // Self-sent row stuck at sender NULL (KQ2) + a normal row.
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, rev, deleted, source)
             VALUES ('s1','cS',NULL,1,1,NULL,'{\"msgId\":\"s1\",\"uidFrom\":\"0\",\"ts\":1,\"msgType\":\"text\",\"content\":\"x\"}',0,0,'capture')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, rev, deleted, source)
             VALUES ('m1','cN','u2',1,1,NULL,'{\"msgId\":\"m1\",\"uidFrom\":\"u2\",\"ts\":1,\"msgType\":\"text\",\"content\":\"x\"}',0,0,'capture')",
            [],
        )
        .unwrap();
        // cS has NO conversations row (orphan message); cN points at the
        // OLDER message while a newer one exists (stale pointer).
        conn.execute(
            "INSERT INTO conversations (id, type, unread, updated_at, last_msg_id, last_ts)
             VALUES ('cN', 0, 0, 1, 'm1', 1)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, rev, deleted, source)
             VALUES ('m2','cN','u2',2,100,NULL,'{\"msgId\":\"m2\",\"uidFrom\":\"u2\",\"ts\":2,\"msgType\":\"chat.brandnew\",\"content\":\"y\"}',3,0,'e2ee')",
            [],
        )
        .unwrap();
        // rest rows: one with a query (after since), one without.
        raw(&conn, "rest", "https://x/a/b?sig=1", "{}");
        raw(&conn, "rest", "https://x/a/c", "{}");

        let i = integrity_counters(&conn, 0);
        assert_eq!(i.self_sent_sender_null, 1);
        assert_eq!(i.msgs_without_conv_row, 1, "the cS orphan");
        assert_eq!(i.convs_lastmsg_not_newest, 1, "cN points at m1, m2 is newer");
        assert_eq!(i.type_100_by_msg_type, vec![("chat.brandnew".to_string(), 1)]);
        assert_eq!(i.rev_gt0_by_source, vec![("e2ee".to_string(), 1)]);
        assert_eq!(i.rest_endpoints_with_query, 1);
        // since scopes the rest counter.
        let max_id: i64 = conn
            .query_row("SELECT MAX(id) FROM raw_events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(integrity_counters(&conn, max_id).rest_endpoints_with_query, 0);
    }
}
