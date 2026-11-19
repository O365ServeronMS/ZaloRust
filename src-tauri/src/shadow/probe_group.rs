//! Targeted group-message field probe (ids/keys only).
use serde_json::Value;

use super::probe_util::open_copy;

#[test]
#[ignore]
fn probe_group_fields() {
    let (live, _tmp) = open_copy();
    // 1. The message the old code mapped to a different conv.
    for msg_id in ["8486229703394", "8484506616301", "8482383933793"] {
        let mut st = live
            .prepare("SELECT kind, payload_json FROM raw_events WHERE payload_json LIKE ?1 LIMIT 3")
            .unwrap();
        let like = format!("%\"{msg_id}\"%");
        for row in st.query_map([like], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        }).unwrap() {
            let (kind, p) = row.unwrap();
            let v: Value = serde_json::from_str(&p).unwrap_or(Value::Null);
            // find the message object anywhere in the payload
            fn find_msg<'a>(v: &'a Value, msg_id: &str) -> Option<&'a Value> {
                match v {
                    Value::Object(m) => {
                        if m.get("msgId").and_then(Value::as_str) == Some(msg_id) {
                            return Some(v);
                        }
                        for x in m.values() {
                            if let Some(f) = find_msg(x, msg_id) {
                                return Some(f);
                            }
                        }
                        None
                    }
                    Value::Array(a) => {
                        for x in a {
                            if let Some(f) = find_msg(x, msg_id) {
                                return Some(f);
                            }
                        }
                        None
                    }
                    _ => None,
                }
            }
            let Some(m) = find_msg(&v, msg_id) else { continue };
            let obj = m.as_object().unwrap();
            let idish: Vec<String> = obj
                .iter()
                .filter(|(k, x)| {
                    (k.contains("id") || k.contains("Id") || k.contains("group") || k.contains("uid"))
                        && x.as_str().map(|s| s.len() >= 2).unwrap_or(false)
                })
                .map(|(k, x)| format!("{k}={}", x.as_str().unwrap_or("?")))
                .collect();
            println!("{msg_id} [{kind}]: {}", idish.join(" "));
        }
        // live row for comparison
        let live_row: Option<(String, Option<String>)> = live
            .query_row(
                "SELECT conv_id, sender_id FROM messages WHERE msg_id = ?1",
                [msg_id],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?)),
            )
            .ok();
        println!("{msg_id} LIVE: conv/sender = {live_row:?}");
    }
    // 2. All clearUnreads idTo sentinel values.
    let mut st = live
        .prepare("SELECT payload_json FROM raw_events WHERE kind='ws' AND payload_json LIKE '%clearUnreads%' LIMIT 40")
        .unwrap();
    let mut sentinels: std::collections::BTreeSet<String> = Default::default();
    let mut sentinel_list: Vec<String> = Vec::new();
    for row in st.query_map([], |r| Ok(r.get::<_, String>(0)?)).unwrap() {
        let p = row.unwrap();
        let v: Value = serde_json::from_str(&p).unwrap_or(Value::Null);
        fn find_arr(v: &Value, out: &mut Vec<String>) {
            if let Value::Object(m) = v {
                for (k, x) in m {
                    if k == "clearUnreads" {
                        if let Some(arr) = x.as_array() {
                            for c in arr {
                                if let Some(id) = c.get("idTo").and_then(Value::as_str) {
                                    let is_group = c.get("isGroup").and_then(Value::as_bool);
                                    let bad = id.len() < 5 || id.starts_with('-');
                                    if bad {
                                        out.push(format!("{id} isGroup={:?}", is_group));
                                    }
                                }
                            }
                        }
                    }
                    find_arr(x, out);
                }
            } else if let Value::Array(a) = v {
                for x in a {
                    find_arr(x, out);
                }
            }
        }
        find_arr(&v, &mut sentinel_list);
    }
    for s in sentinel_list.iter().take(10) {
        println!("SENTINEL idTo: {s}");
    }
}
