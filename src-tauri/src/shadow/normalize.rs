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

use super::event_stats::EventTally;
use super::{rest_ext, ws_events, Write};

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
    normalize_ws_ex(env, own_uid).0
}

/// [`normalize_ws`] plus the counts-only [`EventTally`] of the passive
/// event decoding (batch 30 M2-M4: reactions, controls, receipts,
/// typing, duplicate login; see `ws_events`). The message / conversation
/// writes are EXACTLY the pre-batch-30 ones and come first; the event
/// writes (new kinds only) are appended after them.
pub fn normalize_ws_ex(env: &Value, own_uid: Option<&str>) -> (Vec<Write>, EventTally) {
    let mut out = Vec::new();
    let mut tally = EventTally::default();
    let payload = unwrap_payload(env);
    if let Some(data) = payload.as_object() {
        for (key, is_group) in [
            ("msgs", Some(false)),
            ("groupMsgs", Some(true)),
            ("pageMsgs", Some(false)),
            ("eeMsgs", Some(false)),
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
    }
    // Batch 30: the passive event decoding, keyed by the envelope's cmd.
    if let Some(cmd) = env
        .get("cmd")
        .and_then(Value::as_u64)
        .and_then(|c| u16::try_from(c).ok())
    {
        out.extend(ws_events::decode(cmd, &payload, own_uid, &mut tally));
    }
    (out, tally)
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
    normalize_rest_ex(endpoint, env, own_uid).0
}

/// [`normalize_rest`] plus the counts-only tally of the batch-30 M6
/// endpoints (`rest_ext`). The pre-batch-30 branches are unchanged.
pub fn normalize_rest_ex(
    endpoint: &str,
    env: &Value,
    own_uid: Option<&str>,
) -> (Vec<Write>, EventTally) {
    let mut out = Vec::new();
    let mut tally = EventTally::default();
    let payload = unwrap_payload(env);
    // Batch 30 M6: friends / group id list / member + mini profiles /
    // avatar urls (an array body for getfriends, objects for the rest).
    out.extend(rest_ext::normalize_rest_ext(endpoint, &payload, &mut tally));
    let Some(data) = payload.as_object() else {
        return (out, tally);
    };
    if endpoint.contains("get-last-msgs") || endpoint.contains("preloadconvers") {
        if let Some(clear) = data.get("clearUnreads").and_then(Value::as_array) {
            for c in clear {
                if let Some(w) = clear_to_conversation(c) {
                    out.push(w);
                }
            }
        }
        for (key, is_group) in [
            ("msgs", Some(false)),
            ("groupMsgs", Some(true)),
            ("pageMsgs", Some(false)),
            ("eeMsgs", Some(false)),
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
    (out, tally)
}

/// Why an E2EE bridge payload was refused (audit 1.0-a, A6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum E2eeRefusal {
    NotJson,
    NoMsgId,
    KeyShaped,
}

/// Gate for bridge-forwarded E2EE payloads, applied BEFORE anything is
/// stored (raw_events included). Mirrors the bridge's forward policy so a
/// stale or tampered bridge still cannot land key material in the DB:
/// - must be a JSON object carrying `msgId`/`messageId` (string or number);
/// - must not contain key-shaped data anywhere within depth 3 (CryptoJS
///   WordArray `sigBytes/words`, CipherParams `ciphertext/salt`, Signal
///   store `record`, `*Key` private material, huge byte-index objects).
pub fn e2ee_admit(payload: &str) -> Result<Value, E2eeRefusal> {
    let v: Value = serde_json::from_str(payload).map_err(|_| E2eeRefusal::NotJson)?;
    let obj = v.as_object().ok_or(E2eeRefusal::NoMsgId)?;
    let has_id = ["msgId", "messageId"].iter().any(|k| match obj.get(*k) {
        Some(Value::String(s)) => !s.is_empty() && s.len() < 40,
        Some(Value::Number(_)) => true,
        _ => false,
    });
    if !has_id {
        return Err(E2eeRefusal::NoMsgId);
    }
    if key_shaped(&v, 0) {
        return Err(E2eeRefusal::KeyShaped);
    }
    Ok(v)
}

fn key_shaped(v: &Value, depth: u32) -> bool {
    const KEYISH: &[&str] = &[
        "priv", "private", "secret", "chainkey", "rootkey", "sessionkey", "privkey",
        "identitykey", "signedprekey", "prekey", "mackey", "enckey", "keypair", "sigbytes",
        "words", "record", "ciphertext", "salt",
    ];
    if depth > 3 {
        return false;
    }
    match v {
        Value::Object(m) => {
            if m.len() > 400 {
                return true;
            }
            m.iter().any(|(k, x)| {
                KEYISH.contains(&k.to_ascii_lowercase().as_str()) || key_shaped(x, depth + 1)
            })
        }
        Value::Array(a) => a.len() > 4096 || a.iter().any(|x| key_shaped(x, depth + 1)),
        _ => false,
    }
}

/// Self-sent sender substitution (KQ2) — the ONE shared rule for the
/// capture path AND the Desktop import extract (batch 15 O4):
/// `uidFrom == "0"` (or an absent uidFrom) marks the user's own
/// message, so the configured own uid becomes the sender; without one
/// the sender stays NULL rather than pretending "0" is a person. The
/// import extract must not fork this rule — it calls this helper.
pub fn sender_for(uid_from: Option<&str>, own_uid: Option<&str>) -> Option<String> {
    match uid_from {
        Some("0") | None => own_uid.map(str::to_string),
        Some(f) => Some(f.to_string()),
    }
}

/// Map one E2EE plaintext message forwarded by the bridge tap.
/// `m` is the decrypted message object; `source` is always `e2ee`.
///
/// B5, re-verified for batch 10 (J5): the stub marker stays `None`
/// because the bridge payload carries NO reliable group marker:
/// - the group-ness of a capture-side message lives in the ENVELOPE
///   ARRAY KEY (`groupMsgs` vs `msgs`/`pageMsgs`/`eeMsgs` — verified
///   live, audit §1 item 5: the same message sits in
///   `.data.data.groupMsgs[0]`), and bridge.js forwards only the
///   message object, never the array it came from;
/// - `isGroup` exists only on `clearUnreads` conversation stubs, and
///   `toGroupId` appears nowhere in the observed wire shapes;
/// - guessing from `idTo`'s shape is exactly the unreliable kind:
///   group ids and peer uids are BOTH 19-digit numbers with no `g`
///   prefix (probe_group/probe_ctx measured both), so a length or
///   numeric check would silently mistype half the stubs.
/// An honest unknown beats a wrong guess: the stub stays type 0 and
/// the Conversation/Group writes still refine the type later.
pub fn normalize_e2ee_message(m: &Value, own_uid: Option<&str>) -> Option<Write> {
    message_to_write(m, None, "e2ee", own_uid)
}

fn message_to_write(
    m: &Value,
    // `Some(true)` for the `groupMsgs` array, `Some(false)` for the
    // 1-1 arrays (`msgs`/`pageMsgs`/`eeMsgs`); `None` when the source
    // does not say (bridge E2EE). Drives BOTH the conversation-id
    // logic and the stub conversation type (B5: `Some(true)` -> the
    // writer's stub is `type 1`; Conversation/Group writes still
    // refine it later).
    is_group: Option<bool>,
    source: &'static str,
    own_uid: Option<&str>,
) -> Option<Write> {
    let obj = m.as_object()?;
    let msg_id = str_field(obj, &["msgId", "messageId"])?;
    // Conversation id: groups use idTo (19 digits, no 'g' prefix); 1-1 uses
    // the other party (uidFrom for incoming, idTo for send-to-me echoes).
    let uid_from = obj.get("uidFrom").and_then(Value::as_str);
    let id_to = obj.get("idTo").and_then(Value::as_str);
    let conv_id = if is_group == Some(true) {
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
    // a configuration decision (KQ2 — see sender_for, the shared rule
    // the import extract reuses). Without it the sender stays NULL
    // rather than pretending "0" is a person.
    let sender_id = sender_for(uid_from, own_uid);
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
        is_group,
    })
}

/// Stable numeric codes for `messages.type` (app-local convention, kept
/// identical across runs; the original string stays in payload_json).
///
/// H1 (batch 2): the REAL wire strings — `webchat`, `chat.photo`,
/// `chat.video.msg`, `share.file`, `chat.sticker`, `chat.recommended`,
/// `chat.delete`, `chat.webcontent` (measured on the live DB, audit
/// §2-H1) — map first; the V1-era strings (`text`, `photo`, …) keep
/// the SAME codes so pre-rebuild rows stay comparable. Plausible
/// not-yet-seen shapes (`chat.voice`, `chat.gif`, `chat.doodle`,
/// `chat.location.new`, `chat.link`) get their own codes up front so
/// they never pool in the 100 bucket. `chat.recommended` is a
/// link/call card, NOT media (7). Unknown strings still land in 100 —
/// the audit's "type=100 chỉ còn msgType thật sự lạ" gate depends on
/// that signal staying honest.
///
/// Batch 25 completes the table from the Zalo PC 26.11.12 source read
/// (Claude, static: the `MSG_*` export module + the wire-string switch
/// in `pc-dist/sync-v2-sub-worker.*.js`, mapped through
/// `tools/import-mapping/zalo-desktop-26.11.json`): `chat.undo`
/// (MSG_UNDO) and `chat.delete.everyone` (MSG_DEL_EVERYONE) join the
/// recall family 8, `chat.webcontent.v2` joins `chat.webcontent` at 9,
/// and `chat.list.action` (MSG_OA) = 14, `chat.ecard` (MSG_ECARD) =
/// 15, `group.poll` (MSG_POLL) = 16, `chat.todo` (MSG_TODO) = 17.
/// Every consumer of these codes is kept in sync: `writer::
/// is_recall_msg` recognises the whole recall family,
/// `import_map::MEDIA_CODES` re-parses the object/array content of the
/// new kinds, and `archive::preview_label` labels them.
pub fn msg_type_code(t: &str) -> i64 {
    match t {
        // Real wire shapes (H1).
        "webchat" => 1,
        "chat.photo" => 2,
        "chat.sticker" => 3,
        "share.file" => 4,
        "chat.voice" => 5,
        "chat.video.msg" => 6,
        "chat.recommended" | "chat.link" => 7,
        // Recall family (batch 25): the marker strings the Zalo PC
        // 26.11.12 source names — MSG_UNDO and MSG_DEL_EVERYONE join
        // chat.delete / V1 recall; writer::is_recall_msg mirrors
        // exactly this family.
        "chat.delete" | "chat.undo" | "chat.delete.everyone" => 8,
        // Web-content family (batch 25: chat.webcontent.v2 joins).
        "chat.webcontent" | "chat.webcontent.v2" => 9,
        "notification" => 10,
        "chat.gif" => 11,
        "chat.doodle" => 12,
        "chat.location.new" => 13,
        // Batch 25 new kinds (Zalo PC 26.11.12 MSG_OA / MSG_ECARD /
        // MSG_POLL / MSG_TODO).
        "chat.list.action" => 14,
        "chat.ecard" => 15,
        "group.poll" => 16,
        "chat.todo" => 17,
        // V1-era strings keep their codes (back-compat with rows the
        // pre-rebuild writer stored).
        "text" => 1,
        "photo" | "image" => 2,
        "sticker" => 3,
        "file" => 4,
        "voice" => 5,
        "video" => 6,
        "link" | "links" => 7,
        "recall" => 8,
        "chatContent" => 9,
        _ if t.is_empty() => 0,
        _ => 100,
    }
}

/// Map zca-js's numeric client message type (`cliMsgType`, e.g.
/// `quote.cliMsgType`, sync ingest) to ZaloRust's `msg_type_code`
/// (batch 30 M7). The numbers are the ones zca-js `getClientMessageType`
/// assigns to the wire strings:
///
/// | zca-js | wire string | ZaloRust code |
/// |---|---|---|
/// | 1 | webchat | 1 |
/// | 31 | chat.voice | 5 |
/// | 32 | chat.photo | 2 |
/// | 36 | chat.sticker | 3 |
/// | 37 | chat.doodle | 12 |
/// | 38 | chat.recommended / chat.link | 7 |
/// | 43 | chat.location.new | 13 |
/// | 44 | chat.video.msg | 6 |
/// | 46 | share.file | 4 |
/// | 49 | chat.gif | 11 |
///
/// Anything else is 100 (genuinely unknown), the same honest bucket
/// `msg_type_code` uses. 29a's quote extraction (`archive::
/// parse_payload`) reads only a quote's text/attach/sender, never its
/// cliMsgType, so it has no consumer of this yet.
///
/// Ported from zca-js src/utils.ts getClientMessageType (MIT, (c) RFS-ADRENO and contributors)
pub fn cli_msg_type_code(n: i64) -> i64 {
    match n {
        1 => 1,
        31 => 5,
        32 => 2,
        36 => 3,
        37 => 12,
        38 => 7,
        43 => 13,
        44 => 6,
        46 => 4,
        49 => 11,
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
        let Some(Write::Message { text, payload, .. }) = message_to_write(&m, Some(false), "capture", None)
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

    #[test]
    fn e2ee_gate_admits_messages_only() {
        // A real-shaped message passes (content and nested fields allowed).
        let ok = r#"{"msgId":"8506747288934","uidFrom":"1","idTo":"2","ts":"1","msgType":"webchat",
                    "content":"x","e2ee":"abc","quote":{"msg":"y"},"propertyExt":{"color":0}}"#;
        assert!(e2ee_admit(ok).is_ok());
        assert!(e2ee_admit(r#"{"msgId":12345,"content":{"href":"h","params":"{}"}}"#).is_ok());
        // No msgId -> refused (CryptoJS WordArray, configs, empty objects).
        assert_eq!(
            e2ee_admit(r#"{"sigBytes":16,"words":[1,2,3,4]}"#).unwrap_err(),
            E2eeRefusal::NoMsgId
        );
        assert_eq!(e2ee_admit("{}").unwrap_err(), E2eeRefusal::NoMsgId);
        assert_eq!(e2ee_admit("[1,2,3]").unwrap_err(), E2eeRefusal::NoMsgId);
        assert_eq!(e2ee_admit("not json").unwrap_err(), E2eeRefusal::NotJson);
        // msgId present but key-shaped data inside -> refused.
        for bad in [
            r#"{"msgId":"m","key":{"sigBytes":16,"words":[1]}}"#,
            r#"{"msgId":"m","data":{"ciphertext":{},"salt":{}}}"#,
            r#"{"msgId":"m","identifier":"a","record":"b"}"#,
            r#"{"msgId":"m","session":{"rootKey":"r"}}"#,
        ] {
            assert_eq!(e2ee_admit(bad).unwrap_err(), E2eeRefusal::KeyShaped, "{bad}");
        }
        // Byte buffers serialized as {0:..,1:..,...} are refused.
        let mut big = String::from(r#"{"msgId":"m","buf":{"#);
        big.push_str(&(0..500).map(|i| format!(r#""{i}":1"#)).collect::<Vec<_>>().join(","));
        big.push_str("}}");
        assert_eq!(e2ee_admit(&big).unwrap_err(), E2eeRefusal::KeyShaped);
    }

    // --- Batch 2 (H1 / B5) -------------------------------------------------

    #[test]
    fn msg_type_table_maps_wire_and_v1_strings() {
        // Real wire shapes (H1, measured on the live DB) + plausible
        // not-yet-seen ones, with the V1-era strings mapped to the SAME
        // codes for back-compat. Batch 25: the Zalo PC 26.11.12 source
        // strings (the recall/webcontent families plus the four new
        // kinds). Unknown strings stay in the 100 bucket (the "type=100
        // only for genuinely unknown msgType" gate).
        let table = [
            ("webchat", 1i64),
            ("text", 1),
            ("chat.photo", 2),
            ("photo", 2),
            ("image", 2),
            ("chat.sticker", 3),
            ("sticker", 3),
            ("share.file", 4),
            ("file", 4),
            ("chat.voice", 5),
            ("voice", 5),
            ("chat.video.msg", 6),
            ("video", 6),
            ("chat.recommended", 7),
            ("chat.link", 7),
            ("link", 7),
            ("links", 7),
            ("chat.delete", 8),
            ("recall", 8),
            // Batch 25: chat.undo / chat.delete.everyone join the
            // recall family; chat.webcontent.v2 joins chat.webcontent.
            ("chat.undo", 8),
            ("chat.delete.everyone", 8),
            ("chat.webcontent", 9),
            ("chat.webcontent.v2", 9),
            ("chatContent", 9),
            ("notification", 10),
            ("chat.gif", 11),
            ("chat.doodle", 12),
            ("chat.location.new", 13),
            // Batch 25 new kinds (Zalo PC 26.11.12: MSG_OA, MSG_ECARD,
            // MSG_POLL, MSG_TODO).
            ("chat.list.action", 14),
            ("chat.ecard", 15),
            ("group.poll", 16),
            ("chat.todo", 17),
            ("", 0),
            ("something.brandnew", 100),
        ];
        for (s, code) in table {
            assert_eq!(msg_type_code(s), code, "msgType {s:?}");
        }
    }

    #[test]
    fn original_msg_type_stays_in_payload_and_kind_follows_table() {
        // message_to_write stores the WHOLE message object, so the
        // wire string must survive in payload_json (B1 "already the
        // case" — verified here, no extra column needed).
        let m = json!({"msgId": "mw", "uidFrom": "u1", "idTo": "u2", "ts": 1,
                        "msgType": "chat.photo", "content": {"href": "https://fake-photo-stal.zdn.vn/x.jpg"}});
        let Some(Write::Message { kind, payload, .. }) = message_to_write(&m, Some(true), "capture", None)
        else {
            panic!()
        };
        assert_eq!(kind, 2, "chat.photo -> table code 2");
        assert!(payload.contains("\"msgType\":\"chat.photo\""), "wire string stays in payload_json");
        // The recall family (batch 25: chat.delete, chat.undo,
        // chat.delete.everyone, V1 recall) keeps its type-8 alignment
        // with writer::is_recall_msg — the marker strings below are
        // exactly the family the table codes as 8.
        let d = json!({"msgId": "md", "uidFrom": "u1", "idTo": "u2", "ts": 1,
                        "msgType": "chat.delete", "content": ""});
        let Some(Write::Message { kind, .. }) = message_to_write(&d, None, "e2ee", None) else {
            panic!()
        };
        assert_eq!(kind, 8);
        for recall in ["chat.undo", "chat.delete.everyone"] {
            let u = json!({"msgId": "mu", "uidFrom": "u1", "idTo": "u2", "ts": 1,
                            "msgType": recall, "content": ""});
            let Some(Write::Message { kind, .. }) = message_to_write(&u, None, "e2ee", None)
            else {
                panic!()
            };
            assert_eq!(kind, 8, "{recall} joins the recall family");
        }
        // Unknown strings land in 100, empty in 0.
        assert_eq!(msg_type_code("chat.brand.new"), 100);
        assert_eq!(msg_type_code(""), 0);
    }

    #[test]
    fn cli_msg_type_code_maps_the_zca_js_numbers() {
        // Batch 30 M7: every zca-js getClientMessageType number lands on
        // the same code msg_type_code gives its wire string.
        for (n, wire, code) in [
            (1i64, "webchat", 1i64),
            (31, "chat.voice", 5),
            (32, "chat.photo", 2),
            (36, "chat.sticker", 3),
            (37, "chat.doodle", 12),
            (38, "chat.recommended", 7),
            (43, "chat.location.new", 13),
            (44, "chat.video.msg", 6),
            (46, "share.file", 4),
            (49, "chat.gif", 11),
        ] {
            assert_eq!(cli_msg_type_code(n), code, "number {n}");
            assert_eq!(msg_type_code(wire), code, "wire {wire} agrees");
        }
        assert_eq!(msg_type_code("chat.link"), cli_msg_type_code(38));
        for unknown in [0i64, 2, 30, 39, 99, -1, i64::MAX] {
            assert_eq!(cli_msg_type_code(unknown), 100, "{unknown}");
        }
    }

    #[test]
    fn ws_events_leave_the_message_writes_untouched() {
        // Batch 30: a message frame still yields exactly its message
        // writes; a 601 control frame yields event writes only.
        let msg = json!({
            "cmd": 501, "subCmd": 0,
            "data": {"data": {"msgs": [{"msgId": "m1", "uidFrom": "8441", "idTo": "0", "ts": 1, "msgType": "webchat", "content": "x"}]}}
        });
        let (w, t) = normalize_ws_ex(&msg, None);
        assert_eq!(w.len(), 1);
        assert!(matches!(&w[0], Write::Message { kind: 1, .. }));
        assert_eq!(t.get("frames.501"), 1);
        let ctl = json!({
            "cmd": 601, "subCmd": 0,
            "data": {"data": {"controls": [{"content": {"act_type": "fr", "act": "remove", "data": "8441"}}]}}
        });
        let (w, t) = normalize_ws_ex(&ctl, None);
        assert!(w.is_empty());
        assert_eq!((t.get("frames.601"), t.get("fr.remove")), (1, 1));
        // normalize_ws is the same writes without the tally.
        assert_eq!(normalize_ws(&msg, None), normalize_ws_ex(&msg, None).0);
        // An undecoded (ciphertext-string) envelope is still just a frame count.
        let opaque = json!({"cmd": 612, "subCmd": 0, "encrypt": 3, "undecoded": "no-key", "body": "x"});
        let (w, t) = normalize_ws_ex(&opaque, None);
        assert!(w.is_empty());
        assert_eq!(t.get("frames.612"), 1);
    }

    #[test]
    fn group_marker_flows_from_the_envelope_arrays() {
        // B5: groupMsgs -> Some(true) (conv = idTo, stub type 1), the
        // 1-1 arrays -> Some(false).
        let env = json!({
            "cmd": 2, "subCmd": 1,
            "data": { "data": {
                "msgs": [{"msgId": "k1", "uidFrom": "u1", "idTo": "0", "ts": 1,
                          "msgType": "text", "content": "a"}],
                "groupMsgs": [{"msgId": "k2", "uidFrom": "u1", "idTo": "4945066207717951086", "ts": 1,
                                "msgType": "text", "content": "b"}]
            }}
        });
        let out = normalize_ws(&env, None);
        match (&out[0], &out[1]) {
            (
                Write::Message { is_group: one, conv_id: c1, .. },
                Write::Message { is_group: grp, conv_id: c2, .. },
            ) => {
                assert_eq!(*one, Some(false));
                assert_eq!(*grp, Some(true));
                assert_eq!(c1, "u1");
                assert_eq!(c2, "4945066207717951086", "group conv is idTo");
            }
            _ => panic!(),
        }
        // The bridge E2EE payload carries no group context -> None
        // (B5: honest unknown; conv id keeps the 1-1 logic). Pinned
        // for batch 10 (J5): even a payload whose `idTo` IS a
        // 19-digit group-shaped id stays `None` — group ids and peer
        // uids are indistinguishable by shape, so NO heuristic may
        // fire here (see normalize_e2ee_message's doc).
        let plain = json!({"msgId": "k3", "uidFrom": "u1", "idTo": "0", "ts": 1,
                            "msgType": "webchat", "content": "c"});
        let Some(Write::Message { is_group, .. }) = normalize_e2ee_message(&plain, None) else {
            panic!()
        };
        assert_eq!(is_group, None);
        let group_shaped = json!({"msgId": "k4", "uidFrom": "u1", "idTo": "4945066207717951086",
                                   "ts": 1, "msgType": "webchat", "content": "c"});
        let Some(Write::Message { is_group, conv_id, .. }) =
            normalize_e2ee_message(&group_shaped, None)
        else {
            panic!()
        };
        assert_eq!(is_group, None, "a group-SHAPED idTo is not a group MARKER");
        assert_eq!(conv_id, "u1", "the 1-1 conv logic still applies");
    }
}
