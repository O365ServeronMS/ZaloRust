//! Shadow-side content-shape probe (batch 23a C2): the shadow half of
//! the second arbiter for the unmapped Desktop msgType codes.
//!
//! The Desktop half is `zalors import --content-shape … --by …`
//! (batch 23a C1) over a cold snapshot; this probe groups the SHADOW
//! store's messages by the payload's ORIGINAL wire `$.msgType`
//! string (the meaningful type axis while the numeric `type` column
//! is degenerate — audit H1) and folds the SHAPE of `$.content` per
//! group through the SAME shared pure functions
//! (`import::content_shape`): the five-bucket census, the top-8 key
//! signatures, the one-level nesting rule and every cap. With both
//! halves in hand, batch 23b can fill the mapping's `msgType` table:
//! a code maps when its content shape matches exactly one shadow
//! msgType family AND any batch-15 cross-tab hits agree.
//!
//! PRIVACY (the batch-23a hard rule, same as C1): never a value. The
//! msgType token prints only when code-like
//! (`^[A-Za-z0-9._:-]{1,40}$` — the brief's rule), else its h12;
//! missing/absent msgType prints `NULL`. Key names print only when
//! identifier-shaped, else `k:<sha256-12>`; content values never
//! print at all.
//!
//! The live store is NEVER opened: everything runs on a temp COPY
//! (`probe_util::open_copy`, E0/M2-6). No required env — the copy
//! helper reads `ZR_PROBE_DIR` when set; `ZR_PROBE_SINCE_MS`
//! (optional, via `probe_util::since_ms`) cuts the census to rows
//! with `ts >= <epoch ms>` (unset/<=0 = the whole store).
//!
//! Run (reviewer step, real data):
//! ```text
//! cargo test --lib probe_shadow_content_shape -- --ignored --nocapture
//! ```
//!
//! The grouping is PURE (`shadow_groups` + `msg_type_token` +
//! `render`) and unit-tested below on a synthetic in-memory shadow
//! DB; only the copy-open lives in the ignored test.

use std::collections::BTreeMap;

use rusqlite::Connection;
use serde_json::Value as J;

use super::import::content_shape as cs;
use super::probe_util;

/// The brief's token rule for the wire msgType string: print verbatim
/// only when it matches `^[A-Za-z0-9._:-]{1,40}$`, else its h12.
pub fn msg_type_token(mt: &str) -> String {
    let ok = (1..=40).contains(&mt.len())
        && mt.bytes().all(|b| {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-')
        });
    if ok {
        mt.to_string()
    } else {
        probe_util::h12(mt)
    }
}

/// Group the shadow store's messages by the payload's wire `$.msgType`
/// and fold each group's `$.content` shapes (pure: a connection in, a
/// report out). `since_ms > 0` cuts to `ts >= since_ms`
/// (`ZR_PROBE_SINCE_MS`); 0 reads the whole store. A payload that is
/// not a JSON object has neither msgType nor content: it lands in the
/// `NULL` group with a `null` content bucket — visible, never hidden.
/// Returns the groups plus the total row count.
pub fn shadow_groups(
    conn: &Connection,
    since_ms: i64,
) -> Result<(BTreeMap<String, cs::ShapeGroup>, usize), String> {
    let mut sql = String::from("SELECT payload_json FROM messages");
    if since_ms > 0 {
        sql.push_str(" WHERE ts >= ?1");
    }
    let mut st = conn
        .prepare(&sql)
        .map_err(|e| format!("reading the shadow copy's messages failed: {e}"))?;
    let read = |r: &rusqlite::Row| -> rusqlite::Result<Option<String>> {
        r.get::<_, Option<String>>(0)
    };
    let rows: Vec<Option<String>> = if since_ms > 0 {
        st.query_map([since_ms], read)
            .map_err(|e| format!("reading the shadow copy's messages failed: {e}"))?
            .flatten()
            .collect()
    } else {
        st.query_map([], read)
            .map_err(|e| format!("reading the shadow copy's messages failed: {e}"))?
            .flatten()
            .collect()
    };
    let mut groups: BTreeMap<String, cs::ShapeGroup> = BTreeMap::new();
    let mut total = 0usize;
    for payload in rows {
        total += 1;
        // A malformed/absent payload is honestly reported: no msgType
        // → the NULL group, no content → the null bucket.
        let obj = payload
            .as_deref()
            .and_then(|s| serde_json::from_str::<J>(s).ok())
            .and_then(|v| v.as_object().cloned());
        let token = match obj.as_ref().and_then(|o| o.get("msgType")).and_then(J::as_str) {
            Some(mt) => msg_type_token(mt),
            None => "NULL".to_string(),
        };
        let content = obj.as_ref().and_then(|o| o.get("content")).cloned();
        groups
            .entry(token)
            .or_default()
            .fold_content_json(content.as_ref());
    }
    Ok((groups, total))
}

/// The whole report (pure): the header (row count, the cut, the group
/// count), then the shared per-group blocks under this probe's
/// prefix, with `msgType` as the group key. Same 64-code cap, top-8
/// signatures and 24-key signature cap as the C1 report — the shared
/// `cs::cap_groups`/`cs::group_block` guarantee it.
pub fn render(groups: BTreeMap<String, cs::ShapeGroup>, rows: usize, since_ms: i64) -> Vec<String> {
    let capped = cs::cap_groups(groups);
    let mut lines = vec![format!(
        "shadow-content-shape: rows={rows} since_ms={since_ms} groups={}",
        capped.len()
    )];
    for g in &capped {
        lines.extend(cs::group_block("shadow-content-shape:", "msgType", g));
    }
    lines.push(format!("shadow-content-shape: grand rows={rows}"));
    lines
}

/// The reviewer's probe: everything runs on a temp COPY of the live
/// store — never the live path (E0). No required env; `ZR_PROBE_DIR`
/// overrides the copy source and `ZR_PROBE_SINCE_MS` cuts the census.
#[test]
#[ignore]
fn probe_shadow_content_shape() {
    let (conn, tmp) = probe_util::open_copy();
    println!("shadow-content-shape: store copy: {}", tmp.display());
    let since = probe_util::since_ms();
    let (groups, rows) = shadow_groups(&conn, since).expect("reading the shadow copy's messages");
    for line in render(groups, rows, since) {
        println!("{line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A synthetic in-memory shadow-shaped messages table (fixture
    /// data only — every value carries a SENTINEL so the tests prove
    /// no value ever prints).
    fn mem() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE messages (ts INTEGER, payload_json TEXT)")
            .unwrap();
        conn
    }

    fn insert(conn: &Connection, ts: i64, payload: &str) {
        conn.execute(
            "INSERT INTO messages (ts, payload_json) VALUES (?1, ?2)",
            rusqlite::params![ts, payload],
        )
        .unwrap();
    }

    #[test]
    fn msg_type_token_follows_the_briefs_rule() {
        // Code-like tokens print verbatim…
        for ok in [
            "webchat",
            "chat.photo",
            "share.file",
            "chat.video.msg",
            "chat.list.action",
            "a",
            "a".repeat(40).as_str(),
        ] {
            assert_eq!(msg_type_token(ok), ok.to_string(), "{ok:?}");
        }
        // …anything else is its h12: too long, empty, spaces, quotes,
        // non-ASCII. (A hyphenated token like SENTINEL-MSGTYPE IS
        // code-shaped — `-` is in the rule's alphabet.)
        for hashed in [
            "a".repeat(41).as_str(),
            "",
            "a sentence with spaces",
            "ünïcödé",
        ] {
            let out = msg_type_token(hashed);
            assert_eq!(out, probe_util::h12(hashed), "{hashed:?}");
            assert_ne!(out, hashed, "never the raw string: {hashed:?}");
        }
    }

    #[test]
    fn shadow_groups_group_by_msgtype_and_fold_content_shapes() {
        let conn = mem();
        // webchat: two prose contents (strings that are NOT JSON) …
        insert(
            &conn,
            1000,
            r#"{"msgId":"s1","msgType":"webchat","content":"hello SENTINEL-PROSE-1"}"#,
        );
        insert(
            &conn,
            1001,
            r#"{"msgId":"s2","msgType":"webchat","content":"more SENTINEL-PROSE-2 words"}"#,
        );
        // …share.file: a content OBJECT whose params is an object
        // carrying sentinel values …
        insert(
            &conn,
            1002,
            r#"{"msgId":"s3","msgType":"share.file","content":{
                 "href":"https://sentinel-cdn.example/f",
                 "params":{"fileSize":"987654321","fileExt":"SENTINEL-EXT"},
                 "title":"SENTINEL-TITLE-1","type":"file"}}"#
                .replace('\n', "")
                .as_str(),
        );
        // …chat.photo: a content STRING that itself parses as a JSON
        // object (classifies exactly like the Desktop column) …
        insert(
            &conn,
            1003,
            r#"{"msgId":"s4","msgType":"chat.photo","content":"{\"thumb\":\"SENTINEL-THUMB\",\"type\":\"photo\"}"}"#,
        );
        // …a msgType that is NOT code-shaped: the group label is its
        // h12, never the sentence …
        insert(
            &conn,
            1004,
            r#"{"msgId":"s5","msgType":"a long sentence msgType SENTINEL-MT","content":"x"}"#,
        );
        // …a payload with NO msgType, and a malformed payload: both
        // land in the NULL group (the malformed one with a null
        // content bucket).
        insert(&conn, 1005, r#"{"msgId":"s6","content":{"a":1}}"#);
        insert(&conn, 1006, "definitely not json");

        let (groups, rows) = shadow_groups(&conn, 0).unwrap();
        assert_eq!(rows, 7, "every payload row is counted");
        assert_eq!(groups.len(), 5, "webchat, share.file, chat.photo, h12, NULL");
        let webchat = &groups["webchat"];
        assert_eq!(webchat.rows, 2);
        assert_eq!(webchat.not_json, 2, "prose strings do not parse as JSON");
        assert!(webchat.sigs.is_empty(), "no key signatures outside json_object");
        let file = &groups["share.file"];
        assert_eq!(file.rows, 1);
        assert_eq!(file.json_object, 1);
        // The wire `params` is a real object here → letter `o` (the
        // brief's nesting rule expands STRING values only).
        assert_eq!(
            file.sigs.keys().next().unwrap().as_str(),
            "{href:s,params:o,title:s,type:s}"
        );
        let photo = &groups["chat.photo"];
        assert_eq!(photo.json_object, 1, "a content string holding JSON text");
        assert_eq!(photo.sigs.keys().next().unwrap().as_str(), "{thumb:s,type:s}");
        let null_g = &groups["NULL"];
        assert_eq!(null_g.rows, 2);
        assert_eq!(null_g.json_object, 1, "the no-msgType payload still has content");
        assert_eq!(null_g.null, 1, "the malformed payload has no content at all");
        // The non-code-shaped msgType group exists under its h12.
        let h12 = probe_util::h12("a long sentence msgType SENTINEL-MT");
        assert!(groups.contains_key(&h12), "{groups:?}");

        // The report renders the shared blocks with msgType as the key
        // — and NO sentinel from any content value ever appears.
        let lines = render(groups, rows, 0);
        let joined = lines.join("\n");
        assert!(
            joined.contains("shadow-content-shape: rows=7 since_ms=0 groups=5"),
            "{joined}"
        );
        assert!(
            joined.contains(
                "shadow-content-shape: msgType=webchat rows=2 json_object=0 json_array=0 \
                 json_string_scalar=0 not_json=2 null=0"
            ),
            "{joined}"
        );
        assert!(
            joined.contains(
                "shadow-content-shape: msgType=share.file rows=1 json_object=1 json_array=0 \
                 json_string_scalar=0 not_json=0 null=0"
            ),
            "{joined}"
        );
        assert!(
            joined.contains("shadow-content-shape:  {href:s,params:o,title:s,type:s} x 1"),
            "{joined}"
        );
        assert!(
            joined.contains(&format!("shadow-content-shape: msgType={h12} rows=1")),
            "{joined}"
        );
        assert!(
            joined.contains(
                "shadow-content-shape: msgType=NULL rows=2 json_object=1 json_array=0 \
                 json_string_scalar=0 not_json=0 null=1"
            ),
            "{joined}"
        );
        assert!(joined.contains("shadow-content-shape: grand rows=7"), "{joined}");
        for sentinel in [
            "SENTINEL-PROSE",
            "sentinel-cdn.example",
            "SENTINEL-TITLE",
            "SENTINEL-EXT",
            "SENTINEL-THUMB",
            "SENTINEL-MT",
            "987654321",
        ] {
            assert!(!joined.contains(sentinel), "{sentinel} leaked:\n{joined}");
        }
    }

    #[test]
    fn shadow_groups_honours_the_since_ms_cut() {
        // Rows on both sides of the cut: only the at/after side counts.
        let conn = mem();
        insert(
            &conn,
            999,
            r#"{"msgId":"old","msgType":"webchat","content":"old SENTINEL-OLD"}"#,
        );
        insert(
            &conn,
            1000,
            r#"{"msgId":"new","msgType":"webchat","content":"new SENTINEL-NEW"}"#,
        );
        let (groups, rows) = shadow_groups(&conn, 1000).unwrap();
        assert_eq!(rows, 1, "the cut is inclusive and skips the old row");
        assert_eq!(groups["webchat"].rows, 1);
        // A cut above everything counts nothing.
        let (groups, rows) = shadow_groups(&conn, 1001).unwrap();
        assert_eq!(rows, 0);
        assert!(groups.is_empty());
        let lines = render(groups, rows, 1001);
        assert!(
            lines[0].contains("shadow-content-shape: rows=0 since_ms=1001 groups=0"),
            "{lines:?}"
        );
    }

    #[test]
    fn shadow_groups_cap_the_codes_like_c1() {
        // 70 msgType families: the shared cap keeps 64 + other —
        // the SAME caps as the C1 report, by construction.
        let conn = mem();
        for i in 0..70 {
            insert(
                &conn,
                1000 + i,
                &format!(
                    r#"{{"msgId":"m{i}","msgType":"chat.kind.{i:02}","content":"prose"}}"#
                ),
            );
        }
        let (groups, rows) = shadow_groups(&conn, 0).unwrap();
        assert_eq!(rows, 70);
        let lines = render(groups, rows, 0);
        let joined = lines.join("\n");
        assert!(joined.contains("groups=65"), "{joined}");
        assert!(
            joined.contains("shadow-content-shape: msgType=other rows=6"),
            "{joined}"
        );
        // The other group is LAST (after the 64 ranked families), and
        // every kept family prints exactly its counter line (prose
        // content has no key signatures).
        let kept_lines = joined
            .lines()
            .filter(|l| l.contains("msgType=chat.kind."))
            .count();
        assert_eq!(kept_lines, 64);
        let other_line = joined
            .lines()
            .position(|l| l.contains("msgType=other"))
            .unwrap();
        let last_kept = joined
            .lines()
            .position(|l| l.contains("msgType=chat.kind.63"))
            .unwrap();
        assert!(other_line > last_kept, "{joined}");
    }
}
