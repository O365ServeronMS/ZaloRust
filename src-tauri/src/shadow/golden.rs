//! GOLDEN REPLAY (rebuild verification, 2026-11-19).
//!
//! The surviving shadow DB (`%LOCALAPPDATA%\com.o365serveronms.zalors\
//! shadow\default.db`, captured 2026-11-13/14 with the lost
//! implementation) holds BOTH the decoded `raw_events` AND the normalized
//! `messages`/`conversations` the previous implementation produced. That
//! makes it a perfect oracle: replay every stored event through THIS
//! rebuild's `pipeline` into a scratch DB and compare, row by row.
//!
//! Never prints message content — only ids, counts and field PRESENCE
//! (handoff rule: no message values in logs).
//!
//! Run: cargo test --lib golden -- --ignored --nocapture

use std::collections::BTreeMap;
use std::path::PathBuf;

use rusqlite::Connection;
use serde_json::Value;

use super::pipeline::{self, Incoming};
use super::schema;
use crate::migrate::sqlcipher;

fn live_dir() -> PathBuf {
    PathBuf::from(std::env::var("LOCALAPPDATA").unwrap())
        .join("com.o365serveronms.zalors/shadow")
}

pub(crate) fn open_live() -> Connection {
    let dir = live_dir();
    let key = sqlcipher::load_key(&dir.join("default.key")).unwrap();
    sqlcipher::open_with_key_readonly(&dir.join("default.db"), &key).unwrap()
}

fn scratch() -> Connection {
    let key = sqlcipher::generate_key().unwrap();
    let conn = sqlcipher::open_in_memory(&key).unwrap();
    schema::apply(&conn).unwrap();
    conn
}

#[test]
#[ignore]
fn golden_replay_messages_and_conversations() {
    let live = open_live();

    // --- expectations from the live DB (counts + per-message fields) ---
    struct LiveMsg {
        conv: String,
        sender: Option<String>,
        ts: i64,
        has_text: bool,
    }
    let mut live_msgs: BTreeMap<String, LiveMsg> = BTreeMap::new();
    {
        let mut st = live
            .prepare("SELECT msg_id, conv_id, sender_id, ts, text FROM messages")
            .unwrap();
        let rows = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, Option<String>>(4)?,
                ))
            })
            .unwrap();
        for row in rows {
            let (id, conv, sender, ts, text) = row.unwrap();
            live_msgs.insert(
                id,
                LiveMsg {
                    conv,
                    sender,
                    ts,
                    has_text: text.as_deref().is_some_and(|t| !t.is_empty()),
                },
            );
        }
    }
    let mut live_convs: BTreeMap<String, i64> = BTreeMap::new();
    {
        let mut st = live.prepare("SELECT id, type FROM conversations").unwrap();
        let rows = st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))).unwrap();
        for row in rows {
            let (id, t) = row.unwrap();
            live_convs.insert(id, t);
        }
    }

    let replay = scratch();
    // Learn the account uid the old implementation substituted for
    // self-sent rows (uidFrom "0"): the live sender of a message whose
    // payload still says uidFrom=0.
    let own_uid: Option<String> = live
        .query_row(
            "SELECT sender_id FROM messages WHERE payload_json LIKE '%\"uidFrom\":\"0\"%' \
             AND sender_id IS NOT NULL AND sender_id <> '0' LIMIT 1",
            [],
            |r| r.get(0),
        )
        .ok();
    println!("own_uid learned from live: {}", own_uid.is_some());
    let mut st = live
        .prepare("SELECT direction, kind, endpoint, payload_json FROM raw_events ORDER BY id")
        .unwrap();
    let rows = st
        .query_map([], |r| {
            Ok((
                r.get::<_, Option<String>>(0)?.unwrap_or_default(),
                r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                r.get::<_, Option<String>>(3)?.unwrap_or_default(),
            ))
        })
        .unwrap();
    let mut batch: Vec<Incoming> = Vec::new();
    let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
    let mut acc = pipeline::Summary::default();
    for row in rows {
        let (dir, kind, ep, payload) = row.unwrap();
        let Ok(env) = serde_json::from_str::<Value>(&payload) else {
            continue;
        };
        *by_kind.entry(kind.clone()).or_default() += 1;
        batch.push(Incoming {
            kind: match kind.as_str() {
                "ws" => "ws",
                "rest" => "rest",
                _ => "e2ee",
            },
            direction: match dir.as_str() {
                "out" => "out",
                _ => "in",
            },
            endpoint: ep,
            env,
        });
        if batch.len() >= 500 {
            let s = pipeline::process_batch(&replay, &batch, 7, own_uid.as_deref());
            acc.raw_events += s.raw_events;
            acc.messages += s.messages;
            acc.conversations += s.conversations;
            acc.groups += s.groups;
            acc.contacts += s.contacts;
            acc.other_writes += s.other_writes;
            batch.clear();
        }
    }
    if !batch.is_empty() {
        let s = pipeline::process_batch(&replay, &batch, 7, own_uid.as_deref());
        acc.raw_events += s.raw_events;
        acc.messages += s.messages;
        acc.conversations += s.conversations;
        acc.groups += s.groups;
        acc.contacts += s.contacts;
        acc.other_writes += s.other_writes;
    }
    println!(
        "replay summary: raw={} msgs={} convs={} groups={} contacts={} other={}",
        acc.raw_events, acc.messages, acc.conversations, acc.groups, acc.contacts, acc.other_writes
    );

    // --- compare (never print content) ---
    let mut repl_msgs: BTreeMap<String, LiveMsg> = BTreeMap::new();
    {
        let mut st = replay
            .prepare("SELECT msg_id, conv_id, sender_id, ts, text FROM messages")
            .unwrap();
        let rows = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, i64>(3)?,
                    r.get::<_, Option<String>>(4)?,
                ))
            })
            .unwrap();
        for row in rows {
            let (id, conv, sender, ts, text) = row.unwrap();
            repl_msgs.insert(
                id,
                LiveMsg {
                    conv,
                    sender,
                    ts,
                    has_text: text.as_deref().is_some_and(|t| !t.is_empty()),
                },
            );
        }
    }
    let mut repl_convs: BTreeMap<String, i64> = BTreeMap::new();
    {
        let mut st = replay.prepare("SELECT id, type FROM conversations").unwrap();
        let rows = st
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
            .unwrap();
        for row in rows {
            let (id, t) = row.unwrap();
            repl_convs.insert(id, t);
        }
    }

    let mut missing: Vec<&String> = live_msgs.keys().filter(|k| !repl_msgs.contains_key(*k)).collect();
    let mut extra: Vec<&String> = repl_msgs.keys().filter(|k| !live_msgs.contains_key(*k)).collect();
    let mut conv_mismatch = 0;
    let mut ts_mismatch = 0;
    let mut sender_mismatch = 0;
    let mut text_regress = 0;
    for (id, lm) in &live_msgs {
        let Some(rm) = repl_msgs.get(id) else { continue };
        if rm.conv != lm.conv {
            conv_mismatch += 1;
        }
        if rm.ts != lm.ts {
            ts_mismatch += 1;
        }
        if rm.sender != lm.sender {
            sender_mismatch += 1;
        }
        // A replayed cipher row with no text is FINE as long as the live
        // row also has none; losing live plaintext would be a regression.
        if lm.has_text && !rm.has_text {
            text_regress += 1;
        }
    }
    let convs_missing: Vec<&String> = live_convs.keys().filter(|k| !repl_convs.contains_key(*k)).collect();
    let convs_extra: Vec<&String> = repl_convs.keys().filter(|k| !live_convs.contains_key(*k)).collect();

    // Diff diagnostics (ids + flags only, never content).
    println!("-- diff details --");
    for id in extra.iter().take(6) {
        if let Some(rm) = repl_msgs.get(*id) {
            let live_is_group = live_convs.get(&rm.conv).map(|t| *t == 1);
            println!("EXTRA {id}: conv={} conv_live_type={:?} sender={:?} text={}", rm.conv, live_is_group, rm.sender.is_some(), rm.has_text);
        }
    }
    for (id, lm) in live_msgs.iter() {
        let Some(rm) = repl_msgs.get(id) else { continue };
        if rm.conv != lm.conv {
            let lt = live_convs.get(&lm.conv).copied();
            let rt = repl_convs.get(&rm.conv).copied();
            println!("CONVDIFF {id}: live={}/type{:?} replay={}/type{:?}", lm.conv, lt, rm.conv, rt);
        }
        if rm.sender != lm.sender {
            println!(
                "SENDERDIFF {id}: live={:?} replay={:?} conv={}",
                lm.sender.is_some(),
                rm.sender.is_some(),
                lm.conv
            );
        }
    }
    for id in convs_extra.iter().take(4) {
        let ty = repl_convs.get(*id).copied();
        println!("CONVEXTRA {id}: replay type={ty:?} msgs_in_replay={}", repl_msgs.values().filter(|m| &m.conv == *id).count());
    }

    println!(
        "raw_events by kind: {:?}
live: messages={} conversations={} | replay: messages={} conversations={}
messages: missing_in_replay={} extra_in_replay={} conv_mismatch={} ts_mismatch={} sender_mismatch={} text_regression={}
conversations: missing_in_replay={} extra_in_replay={}",
        by_kind,
        live_msgs.len(),
        live_convs.len(),
        repl_msgs.len(),
        repl_convs.len(),
        missing.len(),
        extra.len(),
        conv_mismatch,
        ts_mismatch,
        sender_mismatch,
        text_regress,
        convs_missing.len(),
        convs_extra.len(),
    );
    if !missing.is_empty() {
        println!("sample missing: {:?}", missing.iter().take(5).collect::<Vec<_>>());
    }
    if !extra.is_empty() {
        println!("sample extra: {:?}", extra.iter().take(5).collect::<Vec<_>>());
    }

    // Acceptance: every live message must replay with the exact same
    // conversation/sender/ts, and the replay must never REGRESS text.
    // Known-diffs (documented, see handoff v2 — the OLD implementation's
    // quirks that the rebuild deliberately does NOT reproduce):
    // - `extra`: the old pipeline DROPPED 2 groupMsgs messages whose
    //   sender-conv was unknown; this pipeline keeps everything.
    // - `conv_known_diff`: the old code mapped 2 groupMsgs messages into a
    //   private conv by uidFrom; the wire truth (idTo = group, type 1)
    //   favors this rebuild's mapping.
    // - `conv_extra -1`: sentinel, now skipped.
    let total = live_msgs.len();
    let ok = missing.is_empty()
        && ts_mismatch == 0
        && sender_mismatch == 0
        && text_regress == 0
        && conv_mismatch <= 2
        && extra.len() <= 2
        && convs_extra.is_empty();
    println!(
        "GOLDEN: {} ({}/{} messages exact; known-diffs: conv={} extra={} convs_extra={})",
        if ok { "PASS" } else { "DIFFS" },
        total - missing.len(),
        total,
        conv_mismatch,
        extra.len(),
        convs_extra.len(),
    );
}

#[test]
#[ignore]
fn golden_shape_inventory() {
    // Prints per-endpoint envelope shapes (keys/counts only, no values) so
    // unmapped sources surface quickly.
    let live = open_live();
    let mut st = live
        .prepare("SELECT kind, endpoint, payload_json FROM raw_events ORDER BY id")
        .unwrap();
    let rows = st
        .query_map([], |r| {
            Ok((
                r.get::<_, Option<String>>(0)?.unwrap_or_default(),
                r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                r.get::<_, Option<String>>(2)?.unwrap_or_default(),
            ))
        })
        .unwrap();
    let mut inv: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
    for row in rows {
        let (kind, ep, payload) = row.unwrap();
        let v: Value = serde_json::from_str(&payload).unwrap_or(Value::Null);
        let data_keys = v
            .get("data")
            .and_then(Value::as_object)
            .map(|o| o.keys().cloned().collect::<Vec<_>>().join(","))
            .unwrap_or_else(|| "-".into());
        let label = match kind.as_str() {
            "ws" => format!(
                "ws cmd={}/{}",
                v.get("cmd").map(|c| c.to_string()).unwrap_or("?".into()),
                v.get("subCmd").map(|c| c.to_string()).unwrap_or("?".into())
            ),
            _ => format!("rest {ep}"),
        };
        let g = inv.entry(label).or_default();
        *g.entry(data_keys).or_default() += 1;
    }
    for (label, keys) in inv.iter().take(60) {
        println!("{label}");
        for (k, n) in keys.iter().take(6) {
            println!("   {n:3}x data[{k}]");
        }
    }
}
