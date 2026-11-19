//! Envelope -> `Write` mapping (rebuild 2026-11-19).
//!
//! Sources of truth for the field names below (all verified live by the
//! previous session; shapes re-checked against the surviving shadow DB
//! during the golden replay):
//! - WS envelopes carry messages under `data.msgs | groupMsgs | pageMsgs`;
//!   group ids are plain 19-digit numbers with NO `g` prefix (handoff:
//!   commit 66ec655 note).
//! - `preloadconvers/get-last-msgs` responses carry
//!   `clearUnreads[] {idTo, isGroup, lastMsgId}` for the conversation
//!   list plus recent `msgs/groupMsgs/pageMsgs/eeMsgs`.
//! - `getmg-v2.gridInfoMap` carries group names (id -> info).
//! - E2EE plaintext arrives via the bridge IPC (`shadow_e2ee_message`),
//!   never through the WS stream (cmd 551 ciphertext stays in
//!   payload_json; the writer never lets ciphertext overwrite plaintext).
//!
//! Field semantics:
//! - `uidFrom == "0"` marks the user's own messages (send-to-me echo).
//! - `content` is a JSON string for text/cipher and an object for media
//!   shapes; E2EE ciphertext must never land in `text`.

use serde_json::Value;

use super::Write;

/// Unwrap the envelope nesting to the actual payload object.
///
/// Verified against the surviving shadow DB (golden, 2026-11-19):
/// - WS rows: `{cmd, subCmd, data: {data: PAYLOAD, error_code, error_message}}`
///   — the decoded `data` is itself an inner envelope; the payload sits one
///   level deeper at `data.data`.
/// - REST rows (decoded): `{error_code, data: PAYLOAD}` — the payload is
///   directly under `data`.
/// - REST rows (stored undecoded): `data` is a ciphertext STRING; if it
///   parses as JSON, descend; otherwise there is no payload (skipped).
pub fn unwrap_payload(env: &Value) -> Value {
    let mut cur = env.clone();
    for _ in 0..3 {
        let Some(d) = cur.get("data").cloned() else {
            break;
        };
        match d {
            Value::Object(_) => {
                // An object that still carries a "data" key is another
                // envelope layer (error_code may or may not be present);
                // otherwise this IS the payload.
                let has_data = d.get("data").is_some();
                cur = d;
                if !has_data {
                    break;
                }
            }
            Value::String(s) => match serde_json::from_str::<Value>(&s) {
                Ok(v) => cur = v,
                Err(_) => break, // ciphertext: no payload
            },
            _ => break,
        }
    }
    cur
}

/// Map a WS envelope (`{cmd, subCmd, data, ...}`) to writes.
/// `own_uid`: the logged-in account uid (bridge handshake); self-sent
/// messages carry `uidFrom == "0"` and get `sender_id = own_uid`.
pub fn normalize_ws(env: &Value, own_uid: Option<&str>) -> Vec<Write> {
    let mut out = Vec::new();
    let payload = unwrap_payload(env);
    let Some(data) = payload.as_object() else {
        return out;
    };
    for (key, is_group) in [
        ("msgs", false),
        ("groupMsgs", true),
        ("pageMsgs", false),
        ("eeMsgs", false),
    ] {
        let Some(arr) = data.get(key).and_then(Value::as_array) else {
            continue;
        };
        for m in arr {
            if let Some(w) = message_to_write(m, is_group, "capture", own_uid) {
                out.push(w);
            }
        }
    }
    // WS frames also carry conversation stubs (clearUnreads) on message
    // pushes: {idTo, isGroup, lastMsgId} (verified: same shape as REST).
    if let Some(clear) = data.get("clearUnreads").and_then(Value::as_array) {
        for c in clear {
            if let Some(w) = clear_to_conversation(c) {
                out.push(w);
            }
        }
    }
    out
}

fn clear_to_conversation(c: &Value) -> Option<Write> {
    let id = c.get("idTo").and_then(Value::as_str)?;
    // Sentinel ids (verified live): "-1" (unknown) and "0" never name a
    // real conversation.
    if id == "-1" || id == "0" {
        return None;
    }
    let is_group = c.get("isGroup").and_then(Value::as_bool).unwrap_or(false);
    Some(Write::Conversation {
        id: id.to_string(),
        is_group,
        title: None,
        avatar_url: None,
        last_msg_id: c.get("lastMsgId").and_then(Value::as_str).map(str::to_string),
        last_ts: None,
        raw: serde_json::to_string(c).unwrap_or_default(),
    })
}

/// Map a decoded REST envelope for `endpoint` to writes.
pub fn normalize_rest(endpoint: &str, env: &Value, own_uid: Option<&str>) -> Vec<Write> {
    let mut out = Vec::new();
    let payload = unwrap_payload(env);
    let Some(data) = payload.as_object() else {
        return out;
    };
    if endpoint.contains("get-last-msgs") || endpoint.contains("preloadconvers") {
        if let Some(clear) = data.get("clearUnreads").and_then(Value::as_array) {
            for c in clear {
                if let Some(w) = clear_to_conversation(c) {
                    out.push(w);
                }
            }
        }
        for (key, is_group) in
            [("msgs", false), ("groupMsgs", true), ("pageMsgs", false), ("eeMsgs", false)]
        {
            let Some(arr) = data.get(key).and_then(Value::as_array) else {
                continue;
            };
            for m in arr {
                if let Some(w) = message_to_write(m, is_group, "capture", own_uid) {
                    out.push(w);
                }
            }
        }
    }
    // Group metadata: gridInfoMap {gid: {name, ...}}.
    if endpoint.contains("getmg-v2") {
        if let Some(grid) = data.get("gridInfoMap").and_then(Value::as_object) {
            for (gid, info) in grid {
                if !looks_like_group_id(gid) && !info.get("name").is_some() {
                    continue;
                }
                out.push(Write::Group {
                    group_id: gid.clone(),
                    name: info.get("name").and_then(Value::as_str).map(str::to_string),
                    raw: compact(info),
                });
            }
        }
    }
    // Contacts (friend/getprofiles/v2 and friendsheep shapes): a payload
    // array of profiles with userId/displayName/avatar.
    if endpoint.contains("getprofiles") || endpoint.contains("friendsheep") {
        let arr = payload.as_array().cloned().unwrap_or_default();
        for prof in &arr {
            let Some(uid) = prof.get("userId").and_then(Value::as_str) else {
                continue;
            };
            out.push(Write::Contact {
                user_id: uid.to_string(),
                display_name: prof
                    .get("displayName")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                avatar_url: prof
                    .get("avatar")
                    .or_else(|| prof.get("avatarUrl"))
                    .and_then(Value::as_str)
                    .map(str::to_string),
                raw: compact(prof),
            });
        }
    }
    out
}

/// Map one E2EE plaintext message forwarded by the bridge tap.
/// `m` is the decrypted message object; `source` is always `e2ee`.
pub fn normalize_e2ee_message(m: &Value, own_uid: Option<&str>) -> Option<Write> {
    message_to_write(m, false, "e2ee", own_uid)
}

fn message_to_write(
    m: &Value,
    is_group: bool,
    source: &'static str,
    own_uid: Option<&str>,
) -> Option<Write> {
    let obj = m.as_object()?;
    let msg_id = str_field(obj, &["msgId", "messageId"])?;
    // Conversation id: groups use idTo (19 digits, no 'g' prefix); 1-1 uses
    // the other party (uidFrom for incoming, idTo for send-to-me echoes).
    let uid_from = obj.get("uidFrom").and_then(Value::as_str);
    let id_to = obj.get("idTo").and_then(Value::as_str);
    let conv_id = if is_group {
        id_to?.to_string()
    } else {
        match (uid_from, id_to) {
            (Some(f), Some(_)) if f != "0" => f.to_string(),
            (Some("0"), Some(t)) => t.to_string(),
            (Some(f), None) => f.to_string(),
            (None, Some(t)) => t.to_string(),
            _ => return None,
        }
    };
    let ts = int_field(obj, &["ts", "dTime", "clientTs", "timestamp"]).unwrap_or(0);
    let kind_str = obj.get("msgType").and_then(Value::as_str).unwrap_or("");
    let kind = msg_type_code(kind_str);
    // Self-sent messages carry uidFrom == "0"; the account's real uid is
    // learned from the page (handshake getUserId). Without it the sender
    // stays NULL rather than pretending "0" is a person.
    let sender_id = match uid_from {
        Some("0") | None => own_uid.map(str::to_string),
        Some(f) => Some(f.to_string()),
    };
    // Text: non-E2EE string content, OR a bridge-delivered e2ee plaintext
    // (source 'e2ee' is what the page itself decrypted — it IS text). An
    // E2EE cipher row (base64 content on the capture path) must never land
    // in `text`.
    let e2ee = obj
        .get("e2ee")
        .and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty());
    let text = match obj.get("content") {
        Some(Value::String(s)) if source == "e2ee" || !e2ee => {
            Some(s.chars().take(8000).collect::<String>())
        }
        _ => None,
    };
    Some(Write::Message {
        msg_id,
        conv_id,
        sender_id,
        ts,
        kind,
        text,
        payload: compact(m),
        source,
    })
}

/// Stable numeric codes for `messages.type` (app-local convention, kept
/// identical across runs; the original string stays in payload_json).
pub fn msg_type_code(t: &str) -> i64 {
    match t {
        "text" => 1,
        "photo" | "image" => 2,
        "sticker" => 3,
        "file" => 4,
        "voice" => 5,
        "video" => 6,
        "link" | "links" => 7,
        "recall" => 8,
        "chatContent" => 9,
        "notification" => 10,
        _ if t.is_empty() => 0,
        _ => 100,
    }
}

/// Group ids are 19-digit numerics (verified); anything non-numeric in the
/// grid map is not a conversation.
fn looks_like_group_id(s: &str) -> bool {
    !s.is_empty() && s.len() >= 15 && s.bytes().all(|b| b.is_ascii_digit())
}

fn str_field(obj: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<String> {
    for k in keys {
        match obj.get(*k) {
            Some(Value::String(s)) => return Some(s.clone()),
            Some(Value::Number(n)) => return Some(n.to_string()),
            _ => {}
        }
    }
    None
}

fn int_field(obj: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<i64> {
    for k in keys {
        match obj.get(*k) {
            Some(Value::Number(n)) => return n.as_i64(),
            Some(Value::String(s)) => {
                if let Ok(v) = s.parse::<i64>() {
                    return Some(v);
                }
            }
            _ => {}
        }
    }
    None
}

fn compact(v: &Value) -> String {
    serde_json::to_string(v).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ws_msgs_group_and_1_1() {
        let env = json!({
            "cmd": 2, "subCmd": 1,
            "data": {
                "data": {
                    "msgs": [{"msgId": "m1", "uidFrom": "8441", "idTo": "0", "ts": 1731987200000i64,
                              "msgType": "text", "content": "chào bạn"}],
                    "groupMsgs": [{"msgId": "m2", "uidFrom": "8441", "idTo": "4945066207717951086",
                                    "ts": 1731987201000i64, "msgType": "text", "content": "nhóm ơi"}]
                }
            }
        });
        let out = normalize_ws(&env, None);
        assert_eq!(out.len(), 2);
        match &out[0] {
            Write::Message { msg_id, conv_id, sender_id, ts, text, source, .. } => {
                assert_eq!(msg_id, "m1");
                assert_eq!(conv_id, "8441");
                assert_eq!(sender_id.as_deref(), Some("8441"));
                assert_eq!(*ts, 1731987200000);
                assert_eq!(text.as_deref(), Some("chào bạn"));
                assert_eq!(*source, "capture");
            }
            _ => panic!(),
        }
        match &out[1] {
            Write::Message { conv_id, .. } => assert_eq!(conv_id, "4945066207717951086"),
            _ => panic!(),
        }
    }

    #[test]
    fn self_sent_substitutes_own_uid() {
        let env = json!({
            "cmd": 2, "subCmd": 1,
            "data": { "data": {
                "msgs": [{"msgId": "ms", "uidFrom": "0", "idTo": "5162", "ts": 7, "msgType": "text", "content": "tôi gửi"}]
            }}
        });
        let out = normalize_ws(&env, Some("2294947733392101048"));
        match &out[0] {
            Write::Message { conv_id, sender_id, .. } => {
                assert_eq!(conv_id, "5162");
                assert_eq!(sender_id.as_deref(), Some("2294947733392101048"));
            }
            _ => panic!(),
        }
        // Without a learned uid the sender stays NULL, never "0".
        let out = normalize_ws(&env, None);
        match &out[0] {
            Write::Message { sender_id, .. } => assert_eq!(sender_id, &None),
            _ => panic!(),
        }
    }

    #[test]
    fn e2ee_cipher_never_becomes_text() {
        let m = json!({"msgId": "m3", "uidFrom": "8441", "idTo": "0", "ts": 1,
                        "msgType": "text", "content": "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaA==",
                        "e2ee": "abc"});
        let Some(Write::Message { text, payload, .. }) = message_to_write(&m, false, "capture", None)
        else {
            panic!()
        };
        assert!(text.is_none(), "ciphertext must not land in text");
        assert!(payload.contains("e2ee"));
        // The bridge-delivered plaintext DOES produce text with source e2ee.
        let plain = json!({"msgId": "m3", "uidFrom": "8441", "idTo": "0", "ts": 1,
                            "msgType": "text", "content": "bản rõ thật", "e2ee": "abc"});
        let Some(Write::Message { text, source, .. }) = normalize_e2ee_message(&plain, None) else {
            panic!()
        };
        assert_eq!(text.as_deref(), Some("bản rõ thật"));
        assert_eq!(source, "e2ee");
    }

    #[test]
    fn rest_preload_and_groups() {
        let env = json!({
            "error_code": 0,
            "data": {
                "clearUnreads": [
                    {"idTo": "8441", "isGroup": false, "lastMsgId": "m9"},
                    {"idTo": "4945066207717951086", "isGroup": true, "lastMsgId": "m2"},
                    {"idTo": "-1", "isGroup": false, "lastMsgId": "x"}
                ],
                "msgs": [{"msgId": "m9", "uidFrom": "0", "idTo": "8441", "ts": 5, "msgType": "text", "content": "tôi gửi"}]
            }
        });
        let out = normalize_rest("https://wpa.chat.zalo.me/a/preloadconvers/get-last-msgs", &env, None);
        assert_eq!(out.len(), 3, "the -1 sentinel row must be skipped");
        assert!(matches!(&out[0], Write::Conversation { is_group: false, .. }));
        assert!(matches!(&out[1], Write::Conversation { is_group: true, .. }));
        match &out[2] {
            Write::Message { conv_id, text, .. } => {
                // Send-to-me echo: uidFrom "0" -> conv is idTo.
                assert_eq!(conv_id, "8441");
                assert_eq!(text.as_deref(), Some("tôi gửi"));
            }
            _ => panic!(),
        }
        let grid = json!({"error_code": 0, "data": {"gridInfoMap": {
            "4945066207717951086": {"name": "Nhóm dự án"}
        }}});
        let out = normalize_rest("https://wpa.chat.zalo.me/a/group/getmg-v2", &grid, None);
        match &out[0] {
            Write::Group { group_id, name, .. } => {
                assert_eq!(group_id, "4945066207717951086");
                assert_eq!(name.as_deref(), Some("Nhóm dự án"));
            }
            _ => panic!(),
        }
    }
}
