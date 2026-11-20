//! Code cross-tab probe (batch 15 O1): resolve the Desktop NUMERIC
//! `msgType` codes by joining matched msgIds — no deploy needed.
//!
//! The reviewer's key insight: the soaking build stores the wrong
//! NUMERIC `messages.type` (100 for everything real), but the shadow's
//! `payload_json` still carries the ORIGINAL wire msgType STRING
//! (`$.msgType`, e.g. `webchat`, `chat.photo`, `share.file`, …). So
//! the Desktop code table can be settled NOW by cross-tabbing.
//!
//! For EVERY message DB of the mapped kinds in the snapshot (not just
//! the 20 newest conversations), extract (msgId, desktop msgType
//! code) through the mapping's raw column access
//! (`import_map::extract_msg_codes` — it reads ONLY the msgId and
//! msgType source columns), join to the shadow copy's `messages` by
//! msg_id, and count pairs `(desktop_code, shadow $.msgType)`.
//!
//! Printout is shape-only per the batch privacy rule: counts plus
//! code-shaped tokens through the batch-14 renderer (≤32 chars of
//! `[A-Za-z0-9._:-]`, else `text(len,h12)`), never a msgId, a
//! conversation id, a DB file name or content. msgType wire strings
//! and Desktop numeric codes are type vocabulary, allowed by the
//! brief.
//!
//! Inputs (all required; `#[ignore]`d, same contract as
//! `probe_import_overlap`):
//! - `ZR_SNAPSHOT_DIR`  — a cold snapshot made by tools/snapshot.ps1;
//! - `ZR_D7_KEY_FILE`   — the DPAPI-wrapped D7 key capture;
//! - `ZR_UIN_HASH`      — the expected sha256-12 of that key;
//! - `ZR_MAPPING`       — the mapping JSON to read the msgId/msgType
//!   columns from.
//! The shadow DB is a temp COPY of the live store
//! (`probe_util::open_copy`, `ZR_PROBE_DIR` overrides the source).
//!
//! Run:
//! ```text
//! cargo test --lib probe_import_codes -- --ignored --nocapture
//! ```
//!
//! The aggregation (`CodeTab::add_pairs`, `CodeTab::dominant`,
//! `CodeTab::render`) is PURE and unit-tested below, including an
//! end-to-end pass on synthetic DBs; only the snapshot/shadow I/O
//! lives in the ignored test.

use std::collections::BTreeMap;

use rusqlite::types::Value as SV;
use rusqlite::Connection;

use super::cli::ImportArgs;
use super::import::{self, DbKind};
use super::import_map::{self, MapDb};
use super::probe_util;

/// Per-desktop-code totals.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct CodeTotals {
    /// msgIds of this code found in the shadow's `messages`.
    pub matched: usize,
    /// msgIds of this code with NO shadow row ("no shadow match").
    pub unmatched: usize,
}

/// The cross-tab: `(desktop code, shadow $.msgType)` → matched count,
/// plus per-code totals. `None` in the pair key means "the shadow row
/// exists but its payload carries no `$.msgType`" (rendered `NULL`).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CodeTab {
    pub pairs: BTreeMap<(String, Option<String>), usize>,
    pub per_code: BTreeMap<String, CodeTotals>,
}

impl CodeTab {
    /// Fold ONE DB's (msgId, code) batch against the shadow's
    /// msg_id → payload `$.msgType` map (pure; called per DB so the
    /// whole snapshot never sits in memory at once).
    pub fn add_pairs(
        &mut self,
        desktop: &[(String, String)],
        shadow: &BTreeMap<String, Option<String>>,
    ) {
        for (msg_id, code) in desktop {
            let tot = self.per_code.entry(code.clone()).or_default();
            match shadow.get(msg_id) {
                None => tot.unmatched += 1,
                Some(mt) => {
                    tot.matched += 1;
                    *self.pairs.entry((code.clone(), mt.clone())).or_insert(0) += 1;
                }
            }
        }
    }

    /// The dominant shadow msgType for `code` and its purity — the
    /// share of the code's MATCHED rows it covers. `None` when the
    /// code has no matched row. Ties break deterministically by the
    /// BTreeMap's key order.
    pub fn dominant(&self, code: &str) -> Option<(Option<String>, f64)> {
        let mut total = 0usize;
        let mut best: Option<(Option<String>, usize)> = None;
        for ((c, mt), n) in &self.pairs {
            if c != code {
                continue;
            }
            total += n;
            let better = match &best {
                Some((_, bn)) => n > bn,
                None => true,
            };
            if better {
                best = Some((mt.clone(), *n));
            }
        }
        best.map(|(mt, n)| (mt, 100.0 * n as f64 / total as f64))
    }

    /// The whole report (pure): the pair table, then per-code totals
    /// with the no-shadow-match counts, the dominant msgType and its
    /// purity. Every value is rendered through the batch-14
    /// code-shaped renderer — never raw content.
    pub fn render(&self) -> Vec<String> {
        let render_tok = |s: &str| super::import::distinct::render_value(&SV::Text(s.to_string()));
        let mut lines = vec!["code-cross-tab: desktop_code | shadow_msgType | count".to_string()];
        for ((code, mt), n) in &self.pairs {
            let mts = match mt {
                Some(s) => render_tok(s),
                None => "NULL".to_string(),
            };
            lines.push(format!(
                "code-cross-tab: {} | {} | {}",
                render_tok(code),
                mts,
                n
            ));
        }
        let mut grand_matched = 0usize;
        let mut grand_unmatched = 0usize;
        for (code, tot) in &self.per_code {
            grand_matched += tot.matched;
            grand_unmatched += tot.unmatched;
            let (dom_s, purity) = match self.dominant(code) {
                Some((Some(s), p)) => (render_tok(s.as_str()), p),
                Some((None, p)) => ("NULL".to_string(), p),
                None => ("-".to_string(), 0.0),
            };
            lines.push(format!(
                "code-cross-tab: totals: code={} matched={} no_shadow_match={} dominant={} purity={purity:.1}%",
                render_tok(code),
                tot.matched,
                tot.unmatched,
                dom_s
            ));
        }
        lines.push(format!(
            "code-cross-tab: grand: desktop_rows={} matched={} no_shadow_match={}",
            grand_matched + grand_unmatched,
            grand_matched,
            grand_unmatched
        ));
        lines
    }
}

/// msg_id → payload `$.msgType` for every shadow message (`None` when
/// the payload carries no msgType). Reads the temp COPY only; a
/// malformed payload would fail the query, which is a probe error,
/// not silent data.
fn shadow_msg_type_map(conn: &Connection) -> rusqlite::Result<BTreeMap<String, Option<String>>> {
    let mut st =
        conn.prepare("SELECT msg_id, json_extract(payload_json, '$.msgType') FROM messages")?;
    let rows = st.query_map([], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
    })?;
    Ok(rows.flatten().collect())
}

#[test]
#[ignore]
fn probe_import_codes() {
    let snap = std::env::var("ZR_SNAPSHOT_DIR")
        .expect("ZR_SNAPSHOT_DIR: point at a cold snapshot (tools/snapshot.ps1 output)");
    let key = std::env::var("ZR_D7_KEY_FILE")
        .expect("ZR_D7_KEY_FILE: the DPAPI-wrapped D7 key capture");
    let uin = std::env::var("ZR_UIN_HASH").expect("ZR_UIN_HASH: the expected sha256-12 of the key");
    let map = std::env::var("ZR_MAPPING").expect("ZR_MAPPING: the mapping JSON to cross-tab");

    // The batch-6 guards run through the normal import prepare:
    // manifest, live-tree refusal, key/uin cross-check, profile.
    let a = ImportArgs {
        from_snapshot: std::path::PathBuf::from(&snap),
        account: "default".into(),
        uin_hash: uin,
        key_file: Some(std::path::PathBuf::from(&key)),
        cipher_compat: None,
        inventory: false,
        out: None,
        mapping: Some(std::path::PathBuf::from(&map)),
        shadow_copy: None,
        delta: false,
        distinct: Vec::new(),
        all_dbs: false,
        own_uid_from_settings: false,
        apply: false,
        help: false,
    };
    let p = import::prepare(&a).expect("snapshot guards + key + cipher profile");
    let mapping = import_map::load_mapping_file(std::path::Path::new(&map))
        .expect("loading the mapping JSON");
    let g = import::gather_inventories(&p).expect("gathering the snapshot inventories");
    let plan = import_map::plan(&mapping, &g.inv)
        .unwrap_or_else(|errs| panic!("mapping failed validation:\n  - {}", errs.join("\n  - ")));
    println!(
        "code-cross-tab: plan OK ({}) snapshot one_to_one={} group={} stranger_box={}",
        plan.summary_line(),
        g.one_to_one,
        g.group,
        g.stranger_box
    );
    let Some(ep) = plan.message.as_ref() else {
        println!("code-cross-tab: the mapping maps no message entity — nothing to cross-tab");
        return;
    };
    let kinds = ep.db.clone();

    // The shadow side: a temp COPY of the live store, read-only.
    let (shadow, tmp) = probe_util::open_copy();
    println!("code-cross-tab: shadow copy: {}", tmp.display());
    let shadow_map = shadow_msg_type_map(&shadow).expect("reading the shadow copy's msgType map");
    println!("code-cross-tab: shadow messages={}", shadow_map.len());

    // EVERY message DB of the mapped kinds — not just 20 convs.
    let msg_dir = p.uid_dir.join("Core").join("Message");
    let mut tab = CodeTab::default();
    let mut dbs = 0usize;
    let mut opened = 0usize;
    let mut failed = 0usize;
    let mut skipped_rows = 0usize;
    for (name, kind) in import::message_db_names(&p.uid_dir).expect("enumerating Core/Message") {
        let map_kind = match kind {
            DbKind::OneToOne(_) => MapDb::OneToOne,
            DbKind::Group(_) => MapDb::Group,
            DbKind::StrangerBox => MapDb::Stranger,
            // `undefined.db` and unknown names stay counted, skipped.
            DbKind::Undefined | DbKind::Other => continue,
        };
        if !kinds.contains(&map_kind) {
            continue;
        }
        dbs += 1;
        match import::open_desktop_db(&msg_dir.join(&name), p.passphrase.as_str(), p.profile) {
            Ok(conn) => match import_map::extract_msg_codes(&conn, ep) {
                Ok((pairs, skipped)) => {
                    opened += 1;
                    skipped_rows += skipped;
                    tab.add_pairs(&pairs, &shadow_map);
                }
                // The error names the mapping's table/column names —
                // never row data.
                Err(e) => {
                    failed += 1;
                    println!("code-cross-tab: one DB extract failed (skipped): {e}");
                }
            },
            Err(_) => failed += 1,
        }
    }
    println!(
        "code-cross-tab: message DBs considered={dbs} opened={opened} failed={failed} rows_skipped={skipped_rows}"
    );
    for line in tab.render() {
        println!("{line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(id: &str, code: &str) -> (String, String) {
        (id.to_string(), code.to_string())
    }

    fn smap(entries: &[(&str, Option<&str>)]) -> BTreeMap<String, Option<String>> {
        entries
            .iter()
            .map(|(id, mt)| (id.to_string(), mt.map(|s| s.to_string())))
            .collect()
    }

    #[test]
    fn cross_tab_counts_pairs_totals_and_no_shadow_match() {
        // Three states of the join: matched-with-string, matched
        // without a payload msgType (NULL bucket), and no shadow row.
        let shadow = smap(&[
            ("a", Some("webchat")),
            ("b", Some("chat.photo")),
            ("c", None),
        ]);
        let mut tab = CodeTab::default();
        tab.add_pairs(
            &[pair("a", "1"), pair("b", "2"), pair("c", "1"), pair("x", "1")],
            &shadow,
        );
        // A second DB batch folds into the same tab.
        tab.add_pairs(&[pair("a", "1"), pair("y", "9")], &shadow);
        assert_eq!(
            tab.pairs,
            BTreeMap::from([
                (("1".to_string(), Some("webchat".to_string())), 2),
                (("2".to_string(), Some("chat.photo".to_string())), 1),
                (("1".to_string(), None), 1),
            ])
        );
        assert_eq!(
            tab.per_code,
            BTreeMap::from([
                ("1".to_string(), CodeTotals { matched: 3, unmatched: 1 }),
                ("2".to_string(), CodeTotals { matched: 1, unmatched: 0 }),
                ("9".to_string(), CodeTotals { matched: 0, unmatched: 1 }),
            ])
        );
        // Empty folds are no-ops.
        let mut t2 = CodeTab::default();
        t2.add_pairs(&[], &shadow);
        assert_eq!(t2, CodeTab::default());
    }

    #[test]
    fn dominant_purity_is_the_share_of_matched_rows() {
        // 9 desktop code-"1" rows join to webchat, 1 to chat.photo →
        // dominant webchat at 90% purity. Built through the public
        // fold, no internals.
        let shadow: BTreeMap<String, Option<String>> = (0..10)
            .map(|i| {
                (
                    format!("m{i}"),
                    Some(if i == 9 { "chat.photo" } else { "webchat" }.to_string()),
                )
            })
            .collect();
        let mut tab = CodeTab::default();
        let batch: Vec<(String, String)> = (0..10).map(|i| (format!("m{i}"), "1".into())).collect();
        tab.add_pairs(&batch, &shadow);
        let (dom, purity) = tab.dominant("1").unwrap();
        assert_eq!(dom.as_deref(), Some("webchat"));
        assert!((purity - 90.0).abs() < 1e-9, "{purity}");
        // A code with no matched row has no dominant.
        assert_eq!(tab.dominant("404"), None);
        // A code whose only match is the NULL bucket.
        let mut tab = CodeTab::default();
        let shadow = smap(&[("z", None)]);
        tab.add_pairs(&[pair("z", "7")], &shadow);
        let (dom, purity) = tab.dominant("7").unwrap();
        assert_eq!(dom, None, "the NULL bucket is the dominant 'value'");
        assert!((purity - 100.0).abs() < 1e-9);
    }

    #[test]
    fn render_is_code_shaped_only() {
        // Code-shaped msgTypes print as tokens; anything else is the
        // len+h12 fingerprint; the NULL bucket prints NULL; the
        // totals lines carry no-shadow-match counts + purity.
        let mut tab = CodeTab::default();
        let shadow = smap(&[
            ("a", Some("chat.photo")),
            ("a2", Some("chat.photo")),
            ("b", Some("a very long sentence that is not a code")),
            ("c", None),
        ]);
        tab.add_pairs(
            &[
                pair("a", "2"),
                pair("a2", "2"),
                pair("b", "2"),
                pair("c", "8"),
                pair("gone", "9"),
            ],
            &shadow,
        );
        let lines = tab.render();
        let joined = lines.join("\n");
        assert!(joined.contains("code-cross-tab: desktop_code | shadow_msgType | count"));
        assert!(joined.contains("code-cross-tab: 2 | chat.photo | 2"), "{joined}");
        assert!(joined.contains("code-cross-tab: 8 | NULL | 1"), "{joined}");
        // The sentence is fingerprinted, never printed.
        assert!(joined.contains("| text(len=39,h12="), "{joined}");
        assert!(!joined.contains("sentence"), "{joined}");
        // Totals + purity + the grand line.
        assert!(
            joined.contains(
                "code-cross-tab: totals: code=2 matched=3 no_shadow_match=0 dominant=chat.photo purity=66.7%"
            ),
            "{joined}"
        );
        assert!(
            joined.contains("code-cross-tab: totals: code=9 matched=0 no_shadow_match=1 dominant=- purity=0.0%"),
            "{joined}"
        );
        assert!(
            joined.contains("code-cross-tab: grand: desktop_rows=5 matched=4 no_shadow_match=1"),
            "{joined}"
        );
    }

    #[test]
    fn end_to_end_on_synthetic_dbs() {
        // The whole chain on FAKE DBs: a Desktop message DB through
        // the mapping plan, a shadow-shaped messages table, the
        // cross-tab fold and its report.
        use super::super::import::inventory::{
            inventory_db, KindInventory, SnapshotInventories,
        };

        let desktop = Connection::open_in_memory().unwrap();
        desktop
            .execute_batch(
                "CREATE TABLE message (
                   msgId TEXT PRIMARY KEY, cliMsgId TEXT, fromUid TEXT, toUid TEXT,
                   serverTime TEXT, msgType INTEGER, message TEXT
                 );
                 INSERT INTO message (msgId, serverTime, msgType) VALUES
                   ('d1', '1690000000000', 1),
                   ('d2', '1690000001000', 1),
                   ('d3', '1690000002000', 2),
                   ('d4', '1690000003000', 4),
                   ('d5', '1690000004000', NULL),
                   (NULL, '1690000006000', 1),
                   ('d7', '1690000005000', 5);",
            )
            .unwrap();
        // Plan the real-shape mapping against the synthetic schema.
        let doc = r#"{
          "msgType": {},
          "entities": { "message": {
            "db": ["one2one"], "table": "message",
            "columns": {
              "msgId": "msgId",
              "ts": { "expr": "ms_to_ms", "of": "serverTime" },
              "uidFrom": "fromUid", "idTo": "toUid",
              "msgType": "msgType", "content": "message"
            }
          } }
        }"#;
        let mapping = super::super::import_map::parse_mapping(doc.as_bytes()).unwrap();
        let kinds = SnapshotInventories {
            index: None,
            one_to_one: Some(KindInventory {
                source_rel: "Core/Message/111.db".into(),
                inventory: inventory_db(&desktop).unwrap(),
            }),
            group: None,
            stranger_box: None,
        };
        let plan = super::super::import_map::plan(&mapping, &kinds).unwrap();
        let ep = plan.message.as_ref().unwrap();

        // (msgId, raw code): the NULL msgType row and the NULL msgId
        // row are skipped, counted.
        let (pairs, skipped) = super::super::import_map::extract_msg_codes(&desktop, ep).unwrap();
        assert_eq!(skipped, 2, "NULL msgType (d5) + NULL msgId (d6)");
        assert_eq!(pairs.len(), 5);

        // A shadow-shaped messages table: d1/d2/d3 match with their
        // wire strings, d4 matches but its payload has NO msgType
        // (NULL bucket), d7 has no shadow row at all.
        let shadow = Connection::open_in_memory().unwrap();
        shadow
            .execute_batch(
                "CREATE TABLE messages (
                   msg_id TEXT PRIMARY KEY, payload_json TEXT
                 );
                 INSERT INTO messages (msg_id, payload_json) VALUES
                   ('d1', '{\"msgId\":\"d1\",\"msgType\":\"webchat\"}'),
                   ('d2', '{\"msgId\":\"d2\",\"msgType\":\"webchat\"}'),
                   ('d3', '{\"msgId\":\"d3\",\"msgType\":\"chat.photo\"}'),
                   ('d4', '{\"msgId\":\"d4\"}');",
            )
            .unwrap();
        let smap = shadow_msg_type_map(&shadow).unwrap();
        assert_eq!(smap.len(), 4);
        assert_eq!(smap["d1"].as_deref(), Some("webchat"));
        assert_eq!(smap["d4"], None, "payload without msgType → NULL bucket");

        let mut tab = CodeTab::default();
        tab.add_pairs(&pairs, &smap);
        assert_eq!(tab.per_code["1"], CodeTotals { matched: 2, unmatched: 0 });
        assert_eq!(tab.per_code["2"], CodeTotals { matched: 1, unmatched: 0 });
        // d4 IS in the shadow (NULL bucket) — a match, not unmatched.
        assert_eq!(tab.per_code["4"], CodeTotals { matched: 1, unmatched: 0 });
        // d7 has no shadow row: the no-shadow-match count.
        assert_eq!(tab.per_code["5"], CodeTotals { matched: 0, unmatched: 1 });
        let (dom, purity) = tab.dominant("1").unwrap();
        assert_eq!(dom.as_deref(), Some("webchat"));
        assert!((purity - 100.0).abs() < 1e-9);
        // The report is code-shaped only, with the NULL bucket visible.
        let joined = tab.render().join("\n");
        assert!(joined.contains("code-cross-tab: 4 | NULL | 1"), "{joined}");
        assert!(
            joined.contains("code-cross-tab: totals: code=4 matched=1 no_shadow_match=0 dominant=NULL purity=100.0%"),
            "{joined}"
        );
        assert!(
            joined.contains("code-cross-tab: grand: desktop_rows=5 matched=4 no_shadow_match=1"),
            "{joined}"
        );
    }
}
