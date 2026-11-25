//! The extra REST normalizers (batch 30 M6): contact / group endpoints
//! Zalo Web calls ITSELF; this only decodes the responses it already
//! received (passive: no request is ever made from here).
//!
//! | path suffix | zca-js response type | result |
//! |---|---|---|
//! | `/api/social/friend/getfriends` | `User[]` | contacts: display name + avatar (same precedence as `getprofiles`) |
//! | `/api/group/getlg/v4` | `{version, gridVerMap}` | `groups` stubs for the id list; never deletes |
//! | `/api/social/group/members` | `{profiles: {id: GroupMemberProfile}}` | contacts, fill-only (see below) |
//! | `/api/social/friend/getminiprofiles` | `{id: {userId, avatar, zaloName}}` | contacts, fill-only |
//! | `/api/social/profile/avatar-url` | `{id: {avatar}}` | `contacts.avatar_url` (current server value) |
//!
//! Rules (mirroring the existing `getprofiles` branch):
//! - an empty / missing value is `None` and never overwrites a better
//!   stored one;
//! - phone numbers and every other profile field are IGNORED (the
//!   stored `raw` is a tiny id-only object, D5 privacy);
//! - `group/members` answers a list of MEMBER ids and carries NO group
//!   id (the request's encrypted `params` hold only the member ids), so
//!   it cannot produce `participants` rows: contacts only (reported in
//!   batch 30's deliverable);
//! - `getminiprofiles` / `group/members` give the account's own
//!   `zaloName`, which is not the friend alias a contact may already
//!   carry: they use fill-only `ContactFill` (never replace a name).
//!
//! Counts only: each endpoint bumps `rest.<name>.bodies` and
//! `rest.<name>.items`.
//!
//! Ported from zca-js src/apis/{getAllFriends,getAllGroups,getGroupMembersInfo,getMiniProfiles,getAvatarUrlProfile}.ts (MIT, (c) RFS-ADRENO and contributors)

use serde_json::{json, Value};

use super::event_stats::EventTally;
use super::Write;

/// `event_ts` for a response that IS the current server state: newer
/// than any stored row (the writer's comparison saturates).
const ALWAYS_NEWER: i64 = i64::MAX / 4;

/// At most this many group ids from one `getlg/v4` body.
const MAX_GROUP_IDS: usize = 20_000;

/// The endpoint's path without scheme/host/query, lowercased.
fn path_of(endpoint: &str) -> String {
    let no_q = endpoint.split(['?', '#']).next().unwrap_or("");
    let path = match no_q.find("://") {
        Some(i) => no_q[i + 3..].find('/').map_or("/", |j| &no_q[i + 3 + j..]),
        None => no_q,
    };
    path.to_ascii_lowercase()
}

fn s(v: Option<&Value>) -> Option<String> {
    match v? {
        Value::String(x) if !x.is_empty() => Some(x.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn text(v: Option<&Value>) -> Option<String> {
    v.and_then(Value::as_str)
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(|x| x.chars().take(80).collect())
}

fn url(v: Option<&Value>) -> Option<String> {
    v.and_then(Value::as_str)
        .filter(|x| x.starts_with("https://") || x.starts_with("http://"))
        .map(str::to_string)
}

/// A group id is a long digit string (same rule as `getmg-v2`).
fn looks_like_group_id(x: &str) -> bool {
    x.len() >= 15 && x.bytes().all(|b| b.is_ascii_digit())
}

fn id_raw(src: &str, uid: &str) -> String {
    json!({ "src": src, "userId": uid }).to_string()
}

/// Map the five endpoints. `payload` is the unwrapped body
/// (`normalize::unwrap_payload`): an array for `getfriends`, an object
/// for the rest. Returns no writes for any other endpoint.
pub fn normalize_rest_ext(endpoint: &str, payload: &Value, t: &mut EventTally) -> Vec<Write> {
    let path = path_of(endpoint);
    let mut out = Vec::new();
    if path.ends_with("/api/social/friend/getfriends") {
        t.bump("rest.getfriends.bodies");
        // `unwrap_payload` does not descend an ARRAY `data`, so the body
        // may arrive as the whole `{error_code, data: [..]}` envelope.
        let Some(arr) = payload
            .as_array()
            .or_else(|| payload.get("data").and_then(Value::as_array))
        else {
            return out;
        };
        for u in arr {
            let Some(uid) = s(u.get("userId")) else {
                continue;
            };
            t.bump("rest.getfriends.items");
            out.push(Write::Contact {
                display_name: text(u.get("displayName")),
                avatar_url: url(u.get("avatar")),
                raw: id_raw("getfriends", &uid),
                user_id: uid,
            });
        }
    } else if path.ends_with("/api/group/getlg/v4") {
        t.bump("rest.getlg.bodies");
        let Some(map) = payload.get("gridVerMap").and_then(Value::as_object) else {
            return out;
        };
        for gid in map.keys().take(MAX_GROUP_IDS) {
            if looks_like_group_id(gid) {
                t.bump("rest.getlg.items");
                out.push(Write::GroupStub { group_id: gid.clone() });
            }
        }
    } else if path.ends_with("/api/social/group/members") {
        t.bump("rest.members.bodies");
        let Some(map) = payload.get("profiles").and_then(Value::as_object) else {
            return out;
        };
        for (key, p) in map {
            let uid = s(p.get("id")).unwrap_or_else(|| key.trim_end_matches("_0").to_string());
            if uid.is_empty() {
                continue;
            }
            t.bump("rest.members.items");
            out.push(Write::ContactFill {
                display_name: text(p.get("displayName")).or_else(|| text(p.get("zaloName"))),
                avatar_url: url(p.get("avatar")),
                event_ts: None,
                raw: Some(id_raw("members", &uid)),
                user_id: uid,
            });
        }
    } else if path.ends_with("/api/social/friend/getminiprofiles") {
        t.bump("rest.miniprofiles.bodies");
        let Some(map) = payload.as_object() else {
            return out;
        };
        for (key, p) in map {
            let uid = s(p.get("userId")).unwrap_or_else(|| key.clone());
            if !p.is_object() || uid.is_empty() {
                continue;
            }
            t.bump("rest.miniprofiles.items");
            out.push(Write::ContactFill {
                display_name: text(p.get("zaloName")),
                avatar_url: url(p.get("avatar")),
                event_ts: None,
                raw: Some(id_raw("miniprofiles", &uid)),
                user_id: uid,
            });
        }
    } else if path.ends_with("/api/social/profile/avatar-url") {
        t.bump("rest.avatar_url.bodies");
        let Some(map) = payload.as_object() else {
            return out;
        };
        for (uid, p) in map {
            let Some(avatar) = url(p.get("avatar")) else {
                continue;
            };
            t.bump("rest.avatar_url.items");
            out.push(Write::ContactFill {
                user_id: uid.clone(),
                display_name: None,
                avatar_url: Some(avatar),
                // The response is the current server value.
                event_ts: Some(ALWAYS_NEWER),
                raw: None,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrate::sqlcipher;
    use crate::shadow::{normalize, schema, writer};

    fn db() -> rusqlite::Connection {
        let key = sqlcipher::generate_key().unwrap();
        let conn = sqlcipher::open_in_memory(&key).unwrap();
        schema::apply(&conn).unwrap();
        conn
    }

    fn rest(ep: &str, data: Value) -> (Vec<Write>, EventTally) {
        let env = json!({"error_code": 0, "data": data});
        normalize::normalize_rest_ex(ep, &env, None)
    }

    const GID: &str = "4945066207717951086";

    #[test]
    fn getfriends_maps_name_and_avatar_and_ignores_the_phone() {
        let (w, t) = rest(
            "/api/social/friend/getfriends",
            json!([
                {"userId": "8441", "displayName": "Lan", "avatar": "https://ava.example.invalid/8441.jpg",
                 "phoneNumber": "0900000000", "zaloName": "lan.z"},
                {"userId": "8442", "displayName": "", "avatar": ""},
                {"displayName": "no id"}
            ]),
        );
        assert_eq!((t.get("rest.getfriends.bodies"), t.get("rest.getfriends.items")), (1, 2));
        assert_eq!(w.len(), 2);
        match &w[0] {
            Write::Contact { user_id, display_name, avatar_url, raw } => {
                assert_eq!(user_id, "8441");
                assert_eq!(display_name.as_deref(), Some("Lan"));
                assert_eq!(avatar_url.as_deref(), Some("https://ava.example.invalid/8441.jpg"));
                assert!(!raw.contains("0900000000"), "no phone in raw");
            }
            _ => panic!(),
        }
        // Empty values are None, so a stored better value survives.
        match &w[1] {
            Write::Contact { display_name, avatar_url, .. } => {
                assert!(display_name.is_none() && avatar_url.is_none());
            }
            _ => panic!(),
        }
        let conn = db();
        for x in &w {
            writer::apply(&conn, x).unwrap();
        }
        let (name, ava): (Option<String>, Option<String>) = conn
            .query_row("SELECT display_name, avatar_url FROM contacts WHERE user_id='8441'", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!((name.as_deref(), ava.is_some()), (Some("Lan"), true));
        // The empty second profile keeps whatever was there.
        writer::apply(
            &conn,
            &Write::Contact {
                user_id: "8442".into(),
                display_name: Some("Mai".into()),
                avatar_url: None,
                raw: "{}".into(),
            },
        )
        .unwrap();
        writer::apply(&conn, &w[1]).unwrap();
        let n: String = conn
            .query_row("SELECT display_name FROM contacts WHERE user_id='8442'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, "Mai");
    }

    #[test]
    fn getlg_v4_ensures_group_stubs_and_never_changes_existing_rows() {
        let (w, t) = rest(
            "https://group.example.invalid/api/group/getlg/v4?zpw_ver=1",
            json!({"version": "5", "gridVerMap": {GID: "9", "123": "1", "5": "x"}}),
        );
        assert_eq!((t.get("rest.getlg.bodies"), t.get("rest.getlg.items")), (1, 1));
        assert_eq!(w, vec![Write::GroupStub { group_id: GID.into() }]);
        let conn = db();
        conn.execute(
            "INSERT INTO groups (group_id, name, raw_json, updated_at) VALUES (?1, 'Giữ nguyên', '{\"totalMember\":7}', 1)",
            [GID],
        )
        .unwrap();
        writer::apply(&conn, &w[0]).unwrap();
        let (n, raw): (String, String) = conn
            .query_row("SELECT name, raw_json FROM groups WHERE group_id=?1", [GID], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!((n.as_str(), raw.as_str()), ("Giữ nguyên", "{\"totalMember\":7}"));
        // A new id gets a stub; the count of groups only goes up.
        let other = "4945066207717951099";
        writer::apply(&conn, &Write::GroupStub { group_id: other.into() }).unwrap();
        let c: i64 = conn.query_row("SELECT COUNT(*) FROM groups", [], |r| r.get(0)).unwrap();
        assert_eq!(c, 2);
    }

    #[test]
    fn group_members_and_miniprofiles_are_fill_only() {
        let (w, t) = rest(
            "/api/social/group/members",
            json!({"profiles": {
                "8441_0": {"id": "8441", "displayName": "Lan", "zaloName": "lan.z", "avatar": "https://ava.example.invalid/1.jpg"},
                "8442_0": {"displayName": "", "zaloName": "mai.z", "avatar": ""}
            }, "unchangeds_profile": []}),
        );
        assert_eq!((t.get("rest.members.bodies"), t.get("rest.members.items")), (1, 2));
        assert!(w.iter().all(|x| matches!(x, Write::ContactFill { event_ts: None, .. })));
        assert!(
            !w.iter().any(|x| matches!(x, Write::ParticipantsDelta { .. })),
            "the response carries no group id: no participants"
        );
        // 8442: the key's `_0` suffix is stripped; the zaloName stands in.
        assert!(w.iter().any(|x| matches!(x, Write::ContactFill { user_id, display_name, .. }
            if user_id == "8442" && display_name.as_deref() == Some("mai.z"))));
        let (w2, t2) = rest(
            "/api/social/friend/getminiprofiles",
            json!({"8441": {"userId": "8441", "avatar": "https://ava.example.invalid/m.jpg", "zaloName": "lan.mini"}}),
        );
        assert_eq!((t2.get("rest.miniprofiles.bodies"), t2.get("rest.miniprofiles.items")), (1, 1));
        let conn = db();
        for x in w.iter().chain(w2.iter()) {
            writer::apply(&conn, x).unwrap();
        }
        let n: String = conn
            .query_row("SELECT display_name FROM contacts WHERE user_id='8441'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, "Lan", "the later zaloName did not replace the first name");
    }

    #[test]
    fn avatar_url_updates_only_the_avatar() {
        let (w, t) = rest(
            "/api/social/profile/avatar-url",
            json!({"8441": {"avatar": "https://ava.example.invalid/new.jpg"}, "8442": {"avatar": ""}}),
        );
        assert_eq!((t.get("rest.avatar_url.bodies"), t.get("rest.avatar_url.items")), (1, 1));
        let conn = db();
        conn.execute(
            "INSERT INTO contacts (user_id, display_name, avatar_url, updated_at) VALUES ('8441', 'Lan', 'https://ava.example.invalid/old.jpg', ?1)",
            [schema::now_ms()],
        )
        .unwrap();
        for x in &w {
            writer::apply(&conn, x).unwrap();
        }
        let (n, a): (String, String) = conn
            .query_row("SELECT display_name, avatar_url FROM contacts WHERE user_id='8441'", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!((n.as_str(), a.as_str()), ("Lan", "https://ava.example.invalid/new.jpg"));
    }

    #[test]
    fn other_endpoints_and_bad_shapes_yield_nothing() {
        let (w, t) = rest("/api/preloadconvers/other", json!({"x": 1}));
        assert!(w.is_empty() && t.is_empty());
        let (w, t) = rest("/api/social/friend/getfriends", json!({"not": "an array"}));
        assert!(w.is_empty());
        assert_eq!(t.get("rest.getfriends.bodies"), 1);
        let (w, _) = rest("/api/group/getlg/v4", json!("string"));
        assert!(w.is_empty());
    }
}
