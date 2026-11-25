//! Passive WS event decoding (batch 30 M2-M4): reactions, controls
//! (group / friend / sync events), receipts and noise frames.
//!
//! PASSIVE ONLY: everything here decodes what Zalo Web already
//! received on its own socket. Nothing is sent, nothing is written
//! into the page (A2 stays read-only; see `docs/shadow-architecture.md`).
//!
//! The decoded frame arrives as `normalize::normalize_ws_ex`'s
//! payload (`unwrap_payload` of the stored envelope); this module maps
//! it to [`Write`]s plus a counts-only [`EventTally`]:
//!
//! | cmd | meaning | class | result |
//! |---|---|---|---|
//! | 501 510 511 521 551 | messages (existing path) | decoded | `normalize_ws` message arrays |
//! | 601 | controls: group / fr / transfer_sync2 / file_done | decoded | group events -> writes, rest counted |
//! | 610 611 612 | reactions (history / live) | decoded | `Write::Reaction` |
//! | 502 522 | delivered / seen receipts | counted | frames + items per array, nothing stored |
//! | 602 | typing | counted | frames + items |
//! | 3000 | duplicate login | counted | counter (+ one hourly log line) |
//! | 1 2 | key / ping | ignored | frames counter only |
//! | other | not classified yet | unclassified | `frames.unclassified` |
//!
//! Every table / shape below is ported from zca-js (MIT, (c)
//! RFS-ADRENO and contributors):
//! - Ported from zca-js src/apis/listen.ts (cmd 601/602/502/522/610/611/612/3000 handling)
//! - Ported from zca-js src/models/Reaction.ts (TReaction, rIcon/rMsg)
//! - Ported from zca-js src/models/GroupEvent.ts (TGroupEvent shapes, GroupEventType)
//! - Ported from zca-js src/utils.ts getGroupEventType / getFriendEventType
//! - Ported from zca-js src/models/DeliveredMessage.ts, SeenMessage.ts
//!
//! H-rule: counts and fixed labels only in stats; system-line text
//! carries display names from the event, never ids or URLs; keys,
//! cookies and the uid never appear anywhere here.

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::event_stats::{EventTally, DUP_LOGIN_LABEL};
use super::Write;

// --- frame classification ------------------------------------------------------

/// How a WS command is treated (batch 30 M4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmdClass {
    /// Produces domain writes.
    Decoded,
    /// Counted by frames/items, nothing stored.
    Counted,
    /// Deliberately ignored (key / ping): frames counter only.
    Ignored,
    /// Not known to this table — the only "unknown" bucket left.
    Unclassified,
}

/// The classification table (see the module docs).
pub fn classify_cmd(cmd: u16) -> CmdClass {
    match cmd {
        501 | 510 | 511 | 521 | 551 | 601 | 610 | 611 | 612 => CmdClass::Decoded,
        502 | 522 | 602 | 3000 => CmdClass::Counted,
        1 | 2 => CmdClass::Ignored,
        _ => CmdClass::Unclassified,
    }
}

fn frame_label(cmd: u16) -> &'static str {
    match cmd {
        1 => "frames.1",
        2 => "frames.2",
        501 => "frames.501",
        502 => "frames.502",
        510 => "frames.510",
        511 => "frames.511",
        521 => "frames.521",
        522 => "frames.522",
        551 => "frames.551",
        601 => "frames.601",
        602 => "frames.602",
        610 => "frames.610",
        611 => "frames.611",
        612 => "frames.612",
        3000 => DUP_LOGIN_LABEL,
        _ => "frames.unclassified",
    }
}

// --- small JSON helpers --------------------------------------------------------

/// A non-empty string, or a number rendered as a string (ids arrive
/// as either; big ids stay exact because serde_json keeps u64).
fn sv(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn num(v: Option<&Value>) -> Option<i64> {
    match v? {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.trim().parse::<i64>().ok(),
        _ => None,
    }
}

/// A server time as epoch milliseconds (values below 1e11 are
/// seconds). `None` for missing / non-positive values.
fn time_ms(v: Option<&Value>) -> Option<i64> {
    let n = num(v)?;
    if n <= 0 {
        return None;
    }
    Some(if n < 100_000_000_000 { n.saturating_mul(1000) } else { n })
}

/// A non-empty `https://` URL (the repo's rule for every stored link).
fn https(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::String(s) if s.starts_with("https://") => Some(s.clone()),
        _ => None,
    }
}

/// A value that is a JSON object, or a string holding one.
fn json_of(v: &Value) -> Option<Value> {
    match v {
        Value::String(s) => serde_json::from_str::<Value>(s).ok(),
        other => Some(other.clone()),
    }
}

fn cap_name(s: &str) -> String {
    s.chars().take(80).collect()
}

// --- entry point ---------------------------------------------------------------

/// Decode one WS frame's payload for `cmd`. Always bumps the frame
/// label; the writes (if any) are returned, the counts go to `t`.
pub fn decode(cmd: u16, payload: &Value, own_uid: Option<&str>, t: &mut EventTally) -> Vec<Write> {
    t.bump(frame_label(cmd));
    let mut out = Vec::new();
    match cmd {
        610 | 611 | 612 => reactions(payload, own_uid, t, &mut out),
        601 => controls(payload, own_uid, t, &mut out),
        502 => receipts(
            payload,
            t,
            "rcpt.502.frames",
            &[("delivereds", "rcpt.502.delivereds"), ("seens", "rcpt.502.seens")],
        ),
        522 => receipts(
            payload,
            t,
            "rcpt.522.frames",
            &[("delivereds", "rcpt.522.delivereds"), ("groupSeens", "rcpt.522.groupSeens")],
        ),
        602 => {
            let n = payload
                .get("actions")
                .and_then(Value::as_array)
                .map_or(0, Vec::len) as u64;
            t.add("typing.602.items", n);
        }
        _ => {}
    }
    out
}

// --- M4: receipts ----------------------------------------------------------------

fn receipts(payload: &Value, t: &mut EventTally, frames: &'static str, arrays: &[(&str, &'static str)]) {
    t.bump(frames);
    for (key, label) in arrays {
        let n = payload.get(*key).and_then(Value::as_array).map_or(0, Vec::len) as u64;
        t.add(label, n);
    }
}

// --- M2: reactions -----------------------------------------------------------------

fn reactions(payload: &Value, own_uid: Option<&str>, t: &mut EventTally, out: &mut Vec<Write>) {
    // 610 carries `reacts`, 611 `reactGroups`, 612 can carry both.
    for key in ["reacts", "reactGroups"] {
        let Some(arr) = payload.get(key).and_then(Value::as_array) else {
            continue;
        };
        for item in arr {
            t.bump("react.seen");
            let Some(o) = item.as_object() else {
                t.bump("react.skipped");
                continue;
            };
            // `content` is a JSON STRING on the live frame, an object
            // on the history frames.
            let Some(content) = o.get("content").and_then(json_of) else {
                t.bump("react.skipped");
                continue;
            };
            // The reactor: "0" is the user itself; an unknown own uid
            // cannot be substituted -> skip and count.
            let reactor = match sv(o.get("uidFrom")) {
                Some(u) if u == "0" => own_uid.map(str::to_string),
                other => other,
            };
            let Some(reactor) = reactor else {
                t.bump("react.skipped");
                continue;
            };
            // `rIcon: ""` removes; a missing rIcon is not a reaction.
            let Some(icon) = content.get("rIcon").and_then(Value::as_str) else {
                t.bump("react.skipped");
                continue;
            };
            let ts = num(o.get("ts")).unwrap_or(0);
            let targets: Vec<String> = content
                .get("rMsg")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(|m| sv(m.get("gMsgID"))).collect())
                .unwrap_or_default();
            if targets.is_empty() {
                t.bump("react.skipped");
                continue;
            }
            for msg_id in targets {
                if icon.is_empty() {
                    t.bump("react.removed");
                } else {
                    t.bump("react.applied");
                }
                out.push(Write::Reaction {
                    msg_id,
                    user_id: reactor.clone(),
                    emoji: icon.to_string(),
                    ts,
                    remove: icon.is_empty(),
                });
            }
        }
    }
}

// --- M3: controls ------------------------------------------------------------------

fn controls(payload: &Value, own_uid: Option<&str>, t: &mut EventTally, out: &mut Vec<Write>) {
    let Some(arr) = payload.get("controls").and_then(Value::as_array) else {
        return;
    };
    for c in arr {
        let Some(content) = c.get("content").and_then(json_of) else {
            t.bump("ctl.other");
            continue;
        };
        let act_type = content.get("act_type").and_then(Value::as_str).unwrap_or("");
        let act = content.get("act").and_then(Value::as_str).unwrap_or("");
        let data = content.get("data");
        match act_type {
            "group" => {
                // Zalo sends both `join` and `join_reject` when an admin
                // approves; zca-js ignores the reject, so do we.
                if act == "join_reject" {
                    t.bump("grp.join_reject_ignored");
                    continue;
                }
                match data.and_then(json_of) {
                    Some(d) => group_event(act, &d, own_uid, t, out),
                    None => {
                        t.bump(group_label(act));
                        t.bump("grp.bad_data");
                    }
                }
            }
            "fr" => {
                // zca-js: `req` duplicates `req_v2`; ignored.
                if act == "req" {
                    t.bump("fr.req_ignored");
                    continue;
                }
                t.bump(friend_label(act));
                if act == "add" {
                    if let Some(d) = data.and_then(json_of) {
                        friend_add(&d, t, out);
                    }
                }
            }
            "transfer_sync2" => {
                // Batch 31 probes this; nothing is stored here.
                t.bump(match act {
                    "transfer_status" => "sync.transfer_status",
                    "upload_batch" => "sync.upload_batch",
                    "transfer_error" => "sync.transfer_error",
                    _ => "sync.other",
                });
            }
            "file_done" => t.bump("ctl.file_done"),
            "typing" => t.bump("ctl.typing"),
            _ => t.bump("ctl.other"),
        }
    }
}

/// `GroupEventType` vocabulary (zca-js getGroupEventType) -> label.
fn group_label(act: &str) -> &'static str {
    match act {
        "join_request" => "grp.join_request",
        "join" => "grp.join",
        "leave" => "grp.leave",
        "remove_member" => "grp.remove_member",
        "block_member" => "grp.block_member",
        "update_setting" => "grp.update_setting",
        "update_avatar" => "grp.update_avatar",
        "update" => "grp.update",
        "new_link" => "grp.new_link",
        "add_admin" => "grp.add_admin",
        "remove_admin" => "grp.remove_admin",
        "new_pin_topic" => "grp.new_pin_topic",
        "update_pin_topic" => "grp.update_pin_topic",
        "update_topic" => "grp.update_topic",
        "update_board" => "grp.update_board",
        "remove_board" => "grp.remove_board",
        "reorder_pin_topic" => "grp.reorder_pin_topic",
        "unpin_topic" => "grp.unpin_topic",
        "remove_topic" => "grp.remove_topic",
        "accept_remind" => "grp.accept_remind",
        "reject_remind" => "grp.reject_remind",
        "remind_topic" => "grp.remind_topic",
        _ => "grp.other",
    }
}

/// `FriendEventType` vocabulary (zca-js getFriendEventType) -> label.
fn friend_label(act: &str) -> &'static str {
    match act {
        "add" => "fr.add",
        "remove" => "fr.remove",
        "block" => "fr.block",
        "unblock" => "fr.unblock",
        "block_call" => "fr.block_call",
        "unblock_call" => "fr.unblock_call",
        "req_v2" => "fr.req_v2",
        "reject" => "fr.reject",
        "undo_req" => "fr.undo_req",
        "seen_fr_req" => "fr.seen_fr_req",
        "pin_unpin" => "fr.pin_unpin",
        "pin_create" => "fr.pin_create",
        _ => "fr.other",
    }
}

/// `fr` / `add`: the payload is normally just the uid string; when it
/// is an object carrying a name, fill the contact (fill-only: a
/// better stored name is never replaced).
fn friend_add(d: &Value, t: &mut EventTally, out: &mut Vec<Write>) {
    let Some(o) = d.as_object() else {
        return;
    };
    let Some(uid) = sv(o.get("userId").or_else(|| o.get("uid")).or_else(|| o.get("id"))) else {
        return;
    };
    let name = ["displayName", "dName", "zaloName", "name"]
        .iter()
        .find_map(|k| o.get(*k).and_then(Value::as_str).filter(|s| !s.is_empty()))
        .map(cap_name);
    let avatar = https(o.get("avatar"));
    if name.is_some() || avatar.is_some() {
        t.bump("fr.add_named");
        out.push(Write::ContactFill {
            user_id: uid,
            display_name: name,
            avatar_url: avatar,
            event_ts: None,
            raw: None,
        });
    }
}

struct Member {
    id: String,
    name: Option<String>,
    avatar: Option<String>,
}

fn members_of(o: &Map<String, Value>) -> Vec<Member> {
    o.get("updateMembers")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|m| {
                    let id = sv(m.get("id"))?;
                    Some(Member {
                        id,
                        name: m
                            .get("dName")
                            .and_then(Value::as_str)
                            .filter(|s| !s.is_empty())
                            .map(cap_name),
                        avatar: https(m.get("avatar")),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// The acts whose payload is the `TGroupEventBase` shape.
fn is_base_act(act: &str) -> bool {
    matches!(
        act,
        "join" | "leave" | "remove_member" | "block_member" | "update_setting" | "update_avatar"
            | "update" | "new_link" | "add_admin" | "remove_admin"
    )
}

/// Short deterministic hash of the member ids (the `sys:` msg id part).
fn short_hash(ids: &[String]) -> String {
    let mut sorted: Vec<&str> = ids.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    let mut h = Sha256::new();
    h.update(sorted.join(",").as_bytes());
    let d = h.finalize();
    d.iter().take(4).map(|b| format!("{b:02x}")).collect()
}

/// "A", "A và B", "A, B và C", "A, B, C và N người khác".
fn join_names(names: &[String]) -> String {
    match names.len() {
        0 => String::new(),
        1 => names[0].clone(),
        2 => format!("{} và {}", names[0], names[1]),
        3 => format!("{}, {} và {}", names[0], names[1], names[2]),
        n => format!("{}, {}, {} và {} người khác", names[0], names[1], names[2], n - 3),
    }
}

/// One group event -> writes. The system line goes FIRST: it creates the
/// conversation stub, so the name/avatar mirror that follows has a row
/// to land on even for a group the store has not seen a message of.
fn group_event(act: &str, d: &Value, own_uid: Option<&str>, t: &mut EventTally, out: &mut Vec<Write>) {
    let (rest, line) = group_event_parts(act, d, own_uid, t);
    out.extend(line);
    out.extend(rest);
}

/// `(name/avatar/contact/participant writes, the system line)`.
fn group_event_parts(
    act: &str,
    d: &Value,
    own_uid: Option<&str>,
    t: &mut EventTally,
) -> (Vec<Write>, Option<Write>) {
    let mut out: Vec<Write> = Vec::new();
    t.bump(group_label(act));
    let Some(o) = d.as_object() else {
        t.bump("grp.bad_data");
        return (out, None);
    };
    let pin = matches!(act, "new_pin_topic" | "unpin_topic");
    if !is_base_act(act) && !pin {
        // Known or unknown act without a stored effect: counted above.
        return (out, None);
    }
    let Some(gid) = sv(o.get("groupId").or_else(|| o.get("group_id"))) else {
        t.bump("grp.no_group_id");
        return (out, None);
    };
    let is_own = |id: &str| own_uid.is_some_and(|u| u == id);
    let members = if pin { Vec::new() } else { members_of(o) };
    let member_ids: Vec<String> = members.iter().map(|m| m.id.clone()).collect();
    // The actor: sourceId (pin topics: actorId). creatorId is the
    // GROUP's creator, so it is a fallback only for acts where the
    // sender of the change is plausibly the creator-side field
    // (never for membership acts).
    let membership = matches!(act, "join" | "leave" | "remove_member");
    let actor_raw = if pin {
        sv(o.get("actorId"))
    } else {
        sv(o.get("sourceId")).or_else(|| if membership { None } else { sv(o.get("creatorId")) })
    };
    // "0" is the user itself; without a known own uid the actor stays
    // unknown (never "0" as a person, same rule as `sender_for`).
    let actor_id = actor_raw.and_then(|a| {
        if a == "0" {
            own_uid.map(str::to_string)
        } else {
            Some(a)
        }
    });
    // Event time: `time`; pin topics carry it on the topic itself.
    let ts = if pin {
        o.get("topic").and_then(Value::as_object).and_then(|tp| {
            time_ms(tp.get("editTime")).or_else(|| time_ms(tp.get("createTime")))
        })
    } else {
        time_ms(o.get("time"))
    };

    if !pin {
        // Name / avatar from the event itself.
        let name = o
            .get("groupName")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(cap_name);
        let avatar = https(o.get("avt")).or_else(|| https(o.get("info").and_then(|i| i.get("avt"))));
        if let Some(ts) = ts {
            if name.is_some() || avatar.is_some() {
                out.push(Write::GroupEvent {
                    group_id: gid.clone(),
                    name,
                    avatar_url: avatar,
                    ts,
                });
            }
        } else if name.is_some() || avatar.is_some() {
            t.bump("grp.no_time");
        }
        // Member display data (name / avatar), never an empty over a
        // better value (the writer fills or only replaces with newer).
        for m in &members {
            if m.name.is_some() || m.avatar.is_some() {
                out.push(Write::ContactFill {
                    user_id: m.id.clone(),
                    display_name: m.name.clone(),
                    avatar_url: m.avatar.clone(),
                    event_ts: ts,
                    raw: None,
                });
            }
        }
    }

    let Some(ts) = ts else {
        // Without a server time the participants change and the system
        // line cannot be made idempotent: counted, not stored.
        t.bump("grp.no_time");
        return (out, None);
    };

    // Participants.
    match act {
        "join" if !member_ids.is_empty() => out.push(Write::ParticipantsDelta {
            conv_id: gid.clone(),
            add: member_ids.clone(),
            remove: Vec::new(),
            roles: Vec::new(),
            ts,
        }),
        "leave" | "remove_member" if !member_ids.is_empty() => out.push(Write::ParticipantsDelta {
            conv_id: gid.clone(),
            add: Vec::new(),
            remove: member_ids.clone(),
            roles: Vec::new(),
            ts,
        }),
        "add_admin" | "remove_admin" if !member_ids.is_empty() => {
            let role = if act == "add_admin" { 1 } else { 0 };
            out.push(Write::ParticipantsDelta {
                conv_id: gid.clone(),
                add: Vec::new(),
                remove: Vec::new(),
                roles: member_ids.iter().map(|id| (id.clone(), role)).collect(),
                ts,
            });
        }
        _ => {}
    }

    // System line (types: join, leave, remove_member, update,
    // update_avatar, add_admin, remove_admin, new_pin_topic,
    // unpin_topic).
    let wants_line = matches!(
        act,
        "join" | "leave" | "remove_member" | "update" | "update_avatar" | "add_admin"
            | "remove_admin" | "new_pin_topic" | "unpin_topic"
    );
    if !wants_line {
        return (out, None);
    }
    let needs_members = matches!(act, "join" | "leave" | "remove_member" | "add_admin" | "remove_admin");
    if needs_members && members.is_empty() {
        t.bump("grp.no_members");
        return (out, None);
    }
    let display = |m: &Member| {
        if is_own(&m.id) {
            "Bạn".to_string()
        } else {
            m.name.clone().unwrap_or_else(|| "một thành viên".to_string())
        }
    };
    let names: Vec<String> = members.iter().map(display).collect();
    let list = join_names(&names);
    let actor_name: Option<String> = actor_id.as_deref().and_then(|a| {
        if is_own(a) {
            Some("Bạn".to_string())
        } else {
            members.iter().find(|m| m.id == a).and_then(|m| m.name.clone())
        }
    });
    let actor_in_members = actor_id
        .as_deref()
        .is_some_and(|a| members.iter().any(|m| m.id == a));
    // "Một thành viên" stands in for an actor the event does not name.
    let some_actor = actor_name.clone().unwrap_or_else(|| "Một thành viên".to_string());
    let group_name = o
        .get("groupName")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(cap_name);
    let text = match act {
        "join" if actor_id.is_some() && !actor_in_members => {
            format!("{some_actor} đã thêm {list} vào nhóm")
        }
        "join" => format!("{list} đã tham gia nhóm"),
        "leave" => format!("{list} đã rời nhóm"),
        "remove_member" if actor_id.is_some() && !actor_in_members => {
            format!("{some_actor} đã xóa {list} khỏi nhóm")
        }
        "remove_member" => format!("{list} đã bị xóa khỏi nhóm"),
        "update" => match (&group_name, &actor_name) {
            (Some(n), Some(a)) => format!("{a} đã đổi tên nhóm thành {n}"),
            (Some(n), None) => format!("Tên nhóm đã được đổi thành {n}"),
            (None, _) => "Thông tin nhóm đã được cập nhật".to_string(),
        },
        "update_avatar" => match &actor_name {
            Some(a) => format!("{a} đã đổi ảnh đại diện nhóm"),
            None => "Ảnh đại diện nhóm đã được thay đổi".to_string(),
        },
        "add_admin" => match &actor_name {
            Some(a) => format!("{a} đã bổ nhiệm {list} làm phó nhóm"),
            None => format!("{list} đã được bổ nhiệm làm phó nhóm"),
        },
        "remove_admin" => match &actor_name {
            Some(a) => format!("{a} đã gỡ quyền phó nhóm của {list}"),
            None => format!("{list} đã bị gỡ quyền phó nhóm"),
        },
        "new_pin_topic" => match &actor_name {
            Some(a) => format!("{a} đã ghim một mục lên đầu nhóm"),
            None => "Một mục đã được ghim lên đầu nhóm".to_string(),
        },
        // unpin_topic
        _ => match &actor_name {
            Some(a) => format!("{a} đã bỏ ghim một mục"),
            None => "Một mục đã được bỏ ghim".to_string(),
        },
    };
    let payload = json!({
        "sys": "group",
        "act": act,
        "actor": actor_id,
        "members": member_ids,
    });
    t.bump("grp.sys_line");
    let line = Write::Message {
        msg_id: format!("sys:{gid}:{ts}:{act}:{}", short_hash(&member_ids)),
        conv_id: gid,
        sender_id: actor_id,
        ts,
        // 10 = notification (normalize::msg_type_code("notification")).
        kind: 10,
        text: Some(text),
        payload: payload.to_string(),
        source: "capture",
        is_group: Some(true),
    };
    (out, Some(line))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrate::sqlcipher;
    use crate::shadow::{schema, writer};
    use rusqlite::Connection;

    const OWN: &str = "1000000000000000009";
    const GID: &str = "4945066207717951086";
    const T0: i64 = 1_731_987_200_000;

    fn db() -> Connection {
        let key = sqlcipher::generate_key().unwrap();
        let conn = sqlcipher::open_in_memory(&key).unwrap();
        schema::apply(&conn).unwrap();
        conn
    }

    fn run(cmd: u16, payload: Value) -> (Vec<Write>, EventTally) {
        let mut t = EventTally::default();
        let w = decode(cmd, &payload, Some(OWN), &mut t);
        (w, t)
    }

    fn apply_all(conn: &Connection, ws: &[Write]) {
        for w in ws {
            writer::apply(conn, w).unwrap();
        }
    }

    fn ctl(act_type: &str, act: &str, data: Value) -> Value {
        json!({"controls": [{"content": {"act_type": act_type, "act": act, "data": data}}]})
    }

    fn react_item(uid_from: &str, content: Value, as_string: bool) -> Value {
        let content = if as_string { Value::String(content.to_string()) } else { content };
        json!({"msgId": "r1", "cliMsgId": "c1", "uidFrom": uid_from, "idTo": GID,
               "ts": T0.to_string(), "content": content})
    }

    fn reaction_content(icon: &str, targets: &[&str]) -> Value {
        json!({"rMsg": targets.iter().map(|g| json!({"gMsgID": g, "cMsgID": "1", "msgType": 1})).collect::<Vec<_>>(),
               "rIcon": icon, "rType": 0, "source": 6})
    }

    // --- M4: classification ----------------------------------------------------------

    #[test]
    fn scoped_cmds_are_classified_after_and_unknown_before() {
        // BEFORE (batch 29a): normalize_ws knew only frames whose payload
        // had msgs / groupMsgs / pageMsgs / eeMsgs / clearUnreads, so the
        // control, reaction, receipt, typing and duplicate-login frames
        // were all "unknown" (nothing decoded, nothing counted).
        fn before(cmd: u16) -> &'static str {
            match cmd {
                501 | 510 | 511 | 521 | 551 => "decoded",
                _ => "unknown",
            }
        }
        let after = |c: u16| match classify_cmd(c) {
            CmdClass::Decoded => "decoded",
            CmdClass::Counted => "counted",
            CmdClass::Ignored => "ignored",
            CmdClass::Unclassified => "unknown",
        };
        for (cmd, was, now) in [
            (501u16, "decoded", "decoded"),
            (521, "decoded", "decoded"),
            (601, "unknown", "decoded"),
            (610, "unknown", "decoded"),
            (611, "unknown", "decoded"),
            (612, "unknown", "decoded"),
            (502, "unknown", "counted"),
            (522, "unknown", "counted"),
            (602, "unknown", "counted"),
            (3000, "unknown", "counted"),
            (1, "unknown", "ignored"),
            (2, "unknown", "ignored"),
        ] {
            assert_eq!(before(cmd), was, "before {cmd}");
            assert_eq!(after(cmd), now, "after {cmd}");
        }
        assert_eq!(after(9999), "unknown", "a really unknown cmd stays unknown");
    }

    #[test]
    fn receipts_typing_and_duplicate_login_are_counted_only() {
        let (w, t) = run(
            502,
            json!({"delivereds": [{"msgId": "1"}, {"msgId": "2"}], "seens": [{"msgId": "3"}]}),
        );
        assert!(w.is_empty());
        assert_eq!(t.get("frames.502"), 1);
        assert_eq!(t.get("rcpt.502.frames"), 1);
        assert_eq!(t.get("rcpt.502.delivereds"), 2);
        assert_eq!(t.get("rcpt.502.seens"), 1);
        let (w, t) = run(522, json!({"delivereds": [{}], "groupSeens": [{}, {}, {}]}));
        assert!(w.is_empty());
        assert_eq!(t.get("rcpt.522.delivereds"), 1);
        assert_eq!(t.get("rcpt.522.groupSeens"), 3);
        let (w, t) = run(602, json!({"actions": [{"act_type": "typing"}, {"act_type": "typing"}]}));
        assert!(w.is_empty());
        assert_eq!(t.get("typing.602.items"), 2);
        let (w, t) = run(3000, json!({}));
        assert!(w.is_empty());
        assert_eq!(t.get(DUP_LOGIN_LABEL), 1);
        assert_eq!(t.get("frames.unclassified"), 0, "none of these is unclassified any more");
        let (_, t) = run(9999, json!({}));
        assert_eq!(t.get("frames.unclassified"), 1);
    }

    // --- M2: reactions -----------------------------------------------------------------

    #[test]
    fn reaction_add_remove_self_and_string_content() {
        // Live 612: content is a JSON STRING; one item per array.
        let payload = json!({
            "reacts": [react_item("8441", reaction_content("/-heart", &["g1", "g2"]), true)],
            "reactGroups": [react_item("0", reaction_content("", &["g3"]), true)]
        });
        let (w, t) = run(612, payload);
        assert_eq!(t.get("react.seen"), 2);
        assert_eq!(t.get("react.applied"), 2, "two rMsg targets");
        assert_eq!(t.get("react.removed"), 1);
        assert_eq!(t.get("react.skipped"), 0);
        assert_eq!(
            w[0],
            Write::Reaction {
                msg_id: "g1".into(),
                user_id: "8441".into(),
                emoji: "/-heart".into(),
                ts: T0,
                remove: false
            }
        );
        // "0" -> the own uid; "" icon -> a removal.
        assert_eq!(
            w[2],
            Write::Reaction { msg_id: "g3".into(), user_id: OWN.into(), emoji: "".into(), ts: T0, remove: true }
        );
        // History 610: content as an OBJECT.
        let (w, t) = run(
            610,
            json!({"reacts": [react_item("8441", reaction_content(":>", &["g9"]), false)]}),
        );
        assert_eq!(t.get("react.applied"), 1);
        assert!(matches!(&w[0], Write::Reaction { msg_id, emoji, .. } if msg_id == "g9" && emoji == ":>"));
        // Unknown own uid: a self reaction is skipped and counted.
        let mut t = EventTally::default();
        let w = decode(
            611,
            &json!({"reactGroups": [react_item("0", reaction_content("/-strong", &["g1"]), true)]}),
            None,
            &mut t,
        );
        assert!(w.is_empty());
        assert_eq!((t.get("react.seen"), t.get("react.skipped")), (1, 1));
        // Malformed items are skipped, never a panic.
        let (w, t) = run(
            612,
            json!({"reacts": [1, {"uidFrom": "8441", "content": "{not json"},
                              {"uidFrom": "8441", "content": {"rIcon": "/-heart"}}]}),
        );
        assert!(w.is_empty());
        assert_eq!((t.get("react.seen"), t.get("react.skipped")), (3, 3));
    }

    #[test]
    fn reaction_writes_converge_remove_and_may_precede_the_message() {
        let conn = db();
        let add = |icon: &str, ts: i64, remove: bool| Write::Reaction {
            msg_id: "m-not-yet-captured".into(),
            user_id: "8441".into(),
            emoji: icon.into(),
            ts,
            remove,
        };
        let count = || -> (i64, String) {
            conn.query_row(
                "SELECT COUNT(*), COALESCE(MAX(emoji), '') FROM reactions WHERE msg_id = 'm-not-yet-captured'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap()
        };
        // Stored with NO message row (no FK).
        writer::apply(&conn, &add("/-heart", 100, false)).unwrap();
        assert_eq!(count(), (1, "/-heart".into()));
        // A replay and an older reaction change nothing; a newer one replaces.
        writer::apply(&conn, &add("/-heart", 100, false)).unwrap();
        writer::apply(&conn, &add(":>", 50, false)).unwrap();
        assert_eq!(count(), (1, "/-heart".into()));
        writer::apply(&conn, &add(":>", 200, false)).unwrap();
        assert_eq!(count(), (1, ":>".into()));
        // A removal older than the stored reaction is ignored; a newer one deletes.
        writer::apply(&conn, &add("", 150, true)).unwrap();
        assert_eq!(count().0, 1);
        writer::apply(&conn, &add("", 300, true)).unwrap();
        assert_eq!(count().0, 0);
    }

    // --- M3: group events ----------------------------------------------------------------

    fn group_data(extra: Value) -> Value {
        let mut base = json!({
            "groupId": GID, "groupName": "Nhóm dự án", "sourceId": "7001", "creatorId": "7000",
            "time": T0.to_string(), "avt": "https://ava.example.invalid/g.jpg", "info": {},
            "updateMembers": []
        });
        for (k, v) in extra.as_object().unwrap() {
            base[k] = v.clone();
        }
        base
    }

    fn members(list: &[(&str, &str)]) -> Value {
        json!(list
            .iter()
            .map(|(id, n)| json!({"id": id, "dName": n, "avatar": format!("https://ava.example.invalid/{id}.jpg"), "type": 0}))
            .collect::<Vec<_>>())
    }

    fn sys_msgs(ws: &[Write]) -> Vec<(&String, &Option<String>, &Option<String>, &String)> {
        ws.iter()
            .filter_map(|w| match w {
                Write::Message { msg_id, sender_id, text, payload, kind: 10, .. } => {
                    Some((msg_id, sender_id, text, payload))
                }
                _ => None,
            })
            .collect()
    }

    #[test]
    fn join_writes_name_avatar_contacts_participants_and_a_system_line() {
        let data = group_data(json!({"updateMembers": members(&[("8441", "Lan"), ("8442", "Mai")])}));
        let (w, t) = run(601, ctl("group", "join", data));
        assert_eq!(t.get("grp.join"), 1);
        assert_eq!(t.get("grp.sys_line"), 1);
        assert!(w.contains(&Write::GroupEvent {
            group_id: GID.into(),
            name: Some("Nhóm dự án".into()),
            avatar_url: Some("https://ava.example.invalid/g.jpg".into()),
            ts: T0
        }));
        assert!(w.iter().any(|x| matches!(x, Write::ContactFill { user_id, display_name, .. }
            if user_id == "8441" && display_name.as_deref() == Some("Lan"))));
        assert!(w.contains(&Write::ParticipantsDelta {
            conv_id: GID.into(),
            add: vec!["8441".into(), "8442".into()],
            remove: vec![],
            roles: vec![],
            ts: T0
        }));
        let sys = sys_msgs(&w);
        assert_eq!(sys.len(), 1);
        let (id, sender, text, payload) = sys[0];
        assert!(id.starts_with(&format!("sys:{GID}:{T0}:join:")), "{id}");
        assert_eq!(sender.as_deref(), Some("7001"), "the actor is sourceId");
        // Actor 7001 is not in updateMembers, so its name is unknown.
        assert_eq!(text.as_deref(), Some("Một thành viên đã thêm Lan và Mai vào nhóm"));
        // ids only in the payload; no names, no urls.
        let p: Value = serde_json::from_str(payload).unwrap();
        assert_eq!(p, json!({"sys": "group", "act": "join", "actor": "7001", "members": ["8441", "8442"]}));
        assert!(!payload.contains("Lan") && !payload.contains("http"));
        // A self-join (actor is the member) reads as "đã tham gia nhóm".
        let data = group_data(json!({"sourceId": "8441", "updateMembers": members(&[("8441", "Lan")])}));
        let (w, _) = run(601, ctl("group", "join", data));
        assert_eq!(sys_msgs(&w)[0].2.as_deref(), Some("Lan đã tham gia nhóm"));
    }

    #[test]
    fn each_system_line_act_has_its_template_and_type_10() {
        let ms = members(&[("8441", "Lan")]);
        let own_ms = members(&[(OWN, "Tôi")]);
        let cases: Vec<(&str, Value, &str)> = vec![
            ("leave", group_data(json!({"updateMembers": ms})), "Lan đã rời nhóm"),
            (
                "remove_member",
                group_data(json!({"updateMembers": ms})),
                "Một thành viên đã xóa Lan khỏi nhóm",
            ),
            (
                "remove_member",
                group_data(json!({"sourceId": "7001", "updateMembers": own_ms})),
                "Một thành viên đã xóa Bạn khỏi nhóm",
            ),
            (
                "update",
                group_data(json!({"sourceId": OWN})),
                "Bạn đã đổi tên nhóm thành Nhóm dự án",
            ),
            ("update", group_data(json!({})), "Tên nhóm đã được đổi thành Nhóm dự án"),
            ("update_avatar", group_data(json!({})), "Ảnh đại diện nhóm đã được thay đổi"),
            (
                "add_admin",
                group_data(json!({"updateMembers": ms})),
                "Lan đã được bổ nhiệm làm phó nhóm",
            ),
            (
                "remove_admin",
                group_data(json!({"updateMembers": ms})),
                "Lan đã bị gỡ quyền phó nhóm",
            ),
        ];
        for (act, data, want) in cases {
            let (w, _) = run(601, ctl("group", act, data));
            let sys = sys_msgs(&w);
            assert_eq!(sys.len(), 1, "{act}");
            assert_eq!(sys[0].2.as_deref(), Some(want), "{act}");
        }
        // Pin topics: actorId + the topic's own time.
        let pin = json!({"groupId": GID, "actorId": "7001",
                         "topic": {"id": "t1", "createTime": T0, "editTime": 0, "type": 2}});
        for (act, want) in [
            ("new_pin_topic", "Một mục đã được ghim lên đầu nhóm"),
            ("unpin_topic", "Một mục đã được bỏ ghim"),
        ] {
            let (w, t) = run(601, ctl("group", act, pin.clone()));
            assert_eq!(sys_msgs(&w)[0].2.as_deref(), Some(want), "{act}");
            assert_eq!(sys_msgs(&w)[0].1.as_deref(), Some("7001"));
            assert_eq!(t.get("grp.sys_line"), 1);
        }
        // The kind really is the notification code of the normalizer table.
        assert_eq!(crate::shadow::normalize::msg_type_code("notification"), 10);
    }

    #[test]
    fn unknown_and_non_line_acts_count_by_name_and_store_nothing() {
        let (w, t) = run(601, ctl("group", "some_future_act", group_data(json!({}))));
        assert!(w.is_empty());
        assert_eq!(t.get("grp.other"), 1);
        // Known but without a stored effect: counted by its own name.
        for act in ["join_request", "block_member_x", "update_board", "remind_topic", "new_link"] {
            let (w, t) = run(601, ctl("group", act, group_data(json!({}))));
            if act == "new_link" {
                // base-shaped: name/avatar still apply, no system line.
                assert!(sys_msgs(&w).is_empty());
                assert_eq!(t.get("grp.new_link"), 1);
            } else if act == "block_member_x" {
                assert_eq!(t.get("grp.other"), 1);
                assert!(w.is_empty());
            } else {
                assert!(w.is_empty(), "{act}");
                assert_eq!(t.get(group_label(act)), 1, "{act}");
            }
        }
        // join_reject is ignored entirely (zca-js).
        let (w, t) = run(601, ctl("group", "join_reject", group_data(json!({}))));
        assert!(w.is_empty());
        assert_eq!(t.get("grp.join_reject_ignored"), 1);
        assert_eq!(t.get("grp.join"), 0);
        // data as a JSON STRING works; garbage is counted, not stored.
        let s = group_data(json!({"updateMembers": members(&[("8441", "Lan")])})).to_string();
        let (w, _) = run(601, ctl("group", "leave", Value::String(s)));
        assert_eq!(sys_msgs(&w).len(), 1);
        let (w, t) = run(601, ctl("group", "leave", Value::String("{oops".into())));
        assert!(w.is_empty());
        assert_eq!(t.get("grp.bad_data"), 1);
    }

    #[test]
    fn friend_and_sync_and_other_controls_are_counted_only() {
        let mut p = json!({"controls": []});
        let items = [
            ("fr", "add", json!("8441")),
            ("fr", "remove", json!("8441")),
            ("fr", "req", json!({})),
            ("fr", "req_v2", json!({"toUid": "1", "fromUid": "2"})),
            ("fr", "brand_new", json!({})),
            ("transfer_sync2", "transfer_status", json!({"status": 3})),
            ("transfer_sync2", "upload_batch", json!({})),
            ("transfer_sync2", "transfer_error", json!({})),
            ("transfer_sync2", "something_else", json!({})),
            ("file_done", "x", json!({})),
            ("typing", "typing", json!({})),
            ("whatever", "x", json!({})),
        ];
        for (at, a, d) in items {
            p["controls"]
                .as_array_mut()
                .unwrap()
                .push(json!({"content": {"act_type": at, "act": a, "data": d}}));
        }
        let (w, t) = run(601, p);
        assert!(w.is_empty(), "nothing is written for these");
        for (label, n) in [
            ("fr.add", 1),
            ("fr.remove", 1),
            ("fr.req_ignored", 1),
            ("fr.req_v2", 1),
            ("fr.other", 1),
            ("sync.transfer_status", 1),
            ("sync.upload_batch", 1),
            ("sync.transfer_error", 1),
            ("sync.other", 1),
            ("ctl.file_done", 1),
            ("ctl.typing", 1),
            ("ctl.other", 1),
        ] {
            assert_eq!(t.get(label), n, "{label}");
        }
        // fr/add with a named object fills the contact (fill-only).
        let (w, t) = run(
            601,
            ctl("fr", "add", json!({"userId": "8441", "displayName": "Lan", "avatar": "https://ava.example.invalid/1.jpg"})),
        );
        assert_eq!(t.get("fr.add_named"), 1);
        assert!(matches!(&w[0], Write::ContactFill { user_id, event_ts: None, .. } if user_id == "8441"));
    }

    #[test]
    fn group_event_writes_apply_participants_roles_and_replay_idempotently() {
        let conn = db();
        // The group has a conversation + a known (older) name and a contact.
        conn.execute(
            "INSERT INTO conversations (id, type, title, avatar_url, unread, updated_at) VALUES (?1, 1, 'Tên cũ', NULL, 0, 1)",
            [GID],
        )
        .unwrap();
        conn.execute("INSERT INTO groups (group_id, name, updated_at) VALUES (?1, 'Tên cũ', 1)", [GID]).unwrap();
        conn.execute(
            "INSERT INTO contacts (user_id, display_name, updated_at) VALUES ('8441', 'Lan (bạn)', ?1)",
            [schema::now_ms()],
        )
        .unwrap();
        let join = group_data(json!({"updateMembers": members(&[("8441", "Lan"), ("8442", "Mai")])}));
        let (w, _) = run(601, ctl("group", "join", join.clone()));
        apply_all(&conn, &w);
        let q = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get(0)).unwrap() };
        let s = |sql: &str| -> String { conn.query_row(sql, [], |r| r.get(0)).unwrap() };
        // Group name (event is newer than the stored row) + avatar url.
        assert_eq!(s(&format!("SELECT name FROM groups WHERE group_id='{GID}'")), "Nhóm dự án");
        assert_eq!(s(&format!("SELECT title FROM conversations WHERE id='{GID}'")), "Nhóm dự án");
        assert_eq!(
            s(&format!("SELECT avatar_url FROM conversations WHERE id='{GID}'")),
            "https://ava.example.invalid/g.jpg"
        );
        // Contacts: a stored name is NOT replaced by an OLDER event (the
        // stored row is newer than T0); a missing one is filled.
        assert_eq!(s("SELECT display_name FROM contacts WHERE user_id='8441'"), "Lan (bạn)");
        assert_eq!(s("SELECT display_name FROM contacts WHERE user_id='8442'"), "Mai");
        assert_eq!(q("SELECT COUNT(*) FROM participants"), 2);
        assert_eq!(q("SELECT COUNT(*) FROM messages WHERE type = 10"), 1);
        let sys_id = s("SELECT msg_id FROM messages WHERE type = 10");
        assert!(sys_id.starts_with("sys:"));
        // The system line landed with source capture and ids-only payload.
        assert_eq!(s("SELECT source FROM messages WHERE type = 10"), "capture");
        // Idempotent replay: same rows, no new revision.
        let rows = |sql: &str| q(sql);
        let before = (
            rows("SELECT COUNT(*) FROM messages"),
            rows("SELECT COUNT(*) FROM participants"),
            rows("SELECT COALESCE(SUM(rev),0) FROM messages"),
        );
        apply_all(&conn, &w);
        apply_all(&conn, &w);
        let after = (
            rows("SELECT COUNT(*) FROM messages"),
            rows("SELECT COUNT(*) FROM participants"),
            rows("SELECT COALESCE(SUM(rev),0) FROM messages"),
        );
        assert_eq!(before, after);
        assert_eq!(q("SELECT COUNT(*) FROM message_revisions"), 0);
        // Leave removes; admin sets the role.
        let (w, _) = run(
            601,
            ctl("group", "add_admin", group_data(json!({"time": (T0 + 10).to_string(), "updateMembers": members(&[("8442", "Mai")])}))),
        );
        apply_all(&conn, &w);
        assert_eq!(q("SELECT role FROM participants WHERE user_id='8442'"), 1);
        let (w, _) = run(
            601,
            ctl("group", "remove_admin", group_data(json!({"time": (T0 + 20).to_string(), "updateMembers": members(&[("8442", "Mai")])}))),
        );
        apply_all(&conn, &w);
        assert_eq!(q("SELECT role FROM participants WHERE user_id='8442'"), 0);
        let (w, _) = run(
            601,
            ctl("group", "leave", group_data(json!({"time": (T0 + 30).to_string(), "updateMembers": members(&[("8441", "Lan")])}))),
        );
        apply_all(&conn, &w);
        assert_eq!(q("SELECT COUNT(*) FROM participants"), 1);
        // Documented limit (no tombstones, no schema change): an
        // OUT-OF-ORDER replay of an older `join` re-adds a member who left
        // later. In-order replays (raw_events order) converge.
        let (w_join_old, _) = run(601, ctl("group", "join", join));
        apply_all(&conn, &w_join_old);
        assert_eq!(q("SELECT COUNT(*) FROM participants WHERE user_id='8441'"), 1);
    }

    #[test]
    fn name_precedence_never_overwrites_better_with_empty_or_old() {
        let conn = db();
        // Stored group name written LONG after the event time.
        conn.execute(
            "INSERT INTO groups (group_id, name, updated_at) VALUES (?1, 'Tên hiện tại', ?2)",
            rusqlite::params![GID, schema::now_ms()],
        )
        .unwrap();
        // An OLD event (T0 is far in the past) with a different name loses.
        let (w, _) = run(601, ctl("group", "update", group_data(json!({"groupName": "Tên cổ"}))));
        apply_all(&conn, &w);
        let name: String = conn
            .query_row("SELECT name FROM groups WHERE group_id=?1", [GID], |r| r.get(0))
            .unwrap();
        assert_eq!(name, "Tên hiện tại");
        // An empty groupName / avatar produces no GroupEvent write at all.
        let (w, _) = run(
            601,
            ctl("group", "leave", group_data(json!({"groupName": "", "avt": "", "updateMembers": members(&[("8441", "")])}))),
        );
        assert!(!w.iter().any(|x| matches!(x, Write::GroupEvent { .. })));
        // An event with a NOW-ish time (live) wins over the stored row.
        let live_ts = schema::now_ms();
        let (w, _) = run(
            601,
            ctl("group", "update", group_data(json!({"groupName": "Tên mới", "time": live_ts.to_string()}))),
        );
        apply_all(&conn, &w);
        let name: String = conn
            .query_row("SELECT name FROM groups WHERE group_id=?1", [GID], |r| r.get(0))
            .unwrap();
        assert_eq!(name, "Tên mới");
        // ContactFill: fill-only never replaces; empty never fills.
        let fill = |name: Option<&str>, ts: Option<i64>| Write::ContactFill {
            user_id: "u1".into(),
            display_name: name.map(str::to_string),
            avatar_url: None,
            event_ts: ts,
            raw: None,
        };
        writer::apply(&conn, &fill(Some("Tên 1"), None)).unwrap();
        writer::apply(&conn, &fill(Some("Tên 2"), None)).unwrap();
        writer::apply(&conn, &fill(None, Some(live_ts))).unwrap();
        writer::apply(&conn, &fill(Some(""), Some(live_ts))).unwrap();
        let n: String = conn
            .query_row("SELECT display_name FROM contacts WHERE user_id='u1'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, "Tên 1");
        writer::apply(&conn, &fill(Some("Tên 3"), Some(live_ts + 1))).unwrap();
        let n: String = conn
            .query_row("SELECT display_name FROM contacts WHERE user_id='u1'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, "Tên 3", "a newer event may replace");
    }

    #[test]
    fn event_wins_rule_has_a_skew_margin() {
        use crate::shadow::writer::event_wins;
        assert!(event_wins(true, Some(i64::MAX), 0), "an empty cell always takes it");
        assert!(event_wins(false, None, 0), "no stored timestamp");
        assert!(event_wins(false, Some(1_000_000), 1_000_000 - 60_000), "inside the skew margin");
        assert!(!event_wins(false, Some(1_000_000), 1_000_000 - 200_000), "older than the margin");
    }

    #[test]
    fn system_lines_do_not_break_previews_and_stay_searchable() {
        // Decision (batch 30 M3): a type-10 row keeps its Vietnamese text
        // (FTS indexes it: "ai đã rời nhóm" is findable and the preview
        // shows the sentence); archive::preview_of falls back to the
        // "[thông báo]" label only when a type-10 row has no text.
        let conn = db();
        let data = group_data(json!({"updateMembers": members(&[("8441", "Lan")])}));
        let (w, _) = run(601, ctl("group", "leave", data));
        apply_all(&conn, &w);
        let (kind, text): (i64, String) = conn
            .query_row("SELECT type, text FROM messages WHERE type = 10", [], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap();
        assert_eq!(
            crate::shadow::archive::preview_of(Some(&text), kind).as_deref(),
            Some("Lan đã rời nhóm")
        );
        assert_eq!(crate::shadow::archive::preview_of(None, kind).as_deref(), Some("[thông báo]"));
        // The conversation stub exists as a group (type 1) and points at the line.
        let (ty, last): (i64, String) = conn
            .query_row(
                "SELECT type, last_msg_id FROM conversations WHERE id = ?1",
                [GID],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(ty, 1);
        assert!(last.starts_with("sys:"));
        // No attachment rows from a system line.
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM attachments", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 0);
        let hits = crate::shadow::search::search(&conn, "roi nhom", 10).unwrap();
        assert_eq!(hits.len(), 1, "type-10 text is searchable");
    }

    #[test]
    fn short_hash_is_order_independent_and_names_join_sensibly() {
        assert_eq!(
            short_hash(&["b".into(), "a".into()]),
            short_hash(&["a".into(), "b".into()])
        );
        assert_ne!(short_hash(&["a".into()]), short_hash(&["b".into()]));
        assert_eq!(short_hash(&[]).len(), 8);
        let n = |k: usize| (0..k).map(|i| format!("N{i}")).collect::<Vec<_>>();
        assert_eq!(join_names(&n(1)), "N0");
        assert_eq!(join_names(&n(2)), "N0 và N1");
        assert_eq!(join_names(&n(3)), "N0, N1 và N2");
        assert_eq!(join_names(&n(5)), "N0, N1, N2 và 2 người khác");
    }
}
