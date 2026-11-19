//! Pure batch transform: decoded events in, `raw_events` + domain writes out.
//! Kept separate from `runtime` so the whole flow is unit-testable against
//! fixture envelopes without any thread or IPC involvement.

use rusqlite::Connection;
use serde_json::Value;

use super::{normalize, writer};

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
    pub messages: usize,
    pub conversations: usize,
    pub groups: usize,
    pub contacts: usize,
    pub other_writes: usize,
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
}

/// Run one batch: store the raw envelopes, normalize them to writes, apply
/// the writes, trim the ring. `own_uid` substitutes self-sent senders.
/// Errors are per-item and only skip that item (a malformed envelope must
/// never stall the pipeline).
pub fn process_batch(
    conn: &Connection,
    batch: &[Incoming],
    raw_days: u32,
    own_uid: Option<&str>,
) -> Summary {
    let mut s = Summary::default();
    for item in batch {
        let payload = item.env.to_string();
        if writer::raw_event(conn, item.direction, item.kind, &item.endpoint, &payload).is_ok() {
            s.raw_events += 1;
        }
        let writes = match item.kind {
            "ws" => normalize::normalize_ws(&item.env, own_uid),
            "rest" => normalize::normalize_rest(&item.endpoint, &item.env, own_uid),
            "e2ee" => normalize::normalize_e2ee_message(&item.env, own_uid)
                .into_iter()
                .collect(),
            _ => Vec::new(),
        };
        for w in writes {
            if let Ok(tag) = writer::apply(conn, &w) {
                s.add_write(tag);
            }
        }
    }
    let _ = writer::trim_raw_events(conn, raw_days);
    s
}

#[cfg(test)]
mod tests {
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
        let s = process_batch(&conn, &batch, 7, None);
        assert_eq!(s.raw_events, 2);
        assert_eq!(s.messages, 1);
        assert_eq!(s.conversations, 1);
        let msgs: i64 = conn
            .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
            .unwrap();
        assert_eq!(msgs, 1);
        let conv: i64 = conn
            .query_row("SELECT COUNT(*) FROM conversations", [], |r| r.get(0))
            .unwrap();
        assert_eq!(conv, 1);
        let _ = Write::Group { group_id: String::new(), name: None, raw: String::new() };
    }
}
