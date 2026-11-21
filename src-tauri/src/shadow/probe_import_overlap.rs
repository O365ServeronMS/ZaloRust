//! Overlap probe (batch 12 L3, audit §4 item 2.3 AC): the gate the
//! mapping must pass before any `--apply` is even proposed.
//!
//! For the 20 most recent conversations present in BOTH a cold
//! snapshot and the shadow DB (10 one2one + 10 group, when
//! available), extract the Desktop messages through the user's
//! mapping, cut both sides to the overlapping time window, match by
//! msgId, and report type/ts/sender agreement on the matches.
//!
//! Batch 15 O3: a SECOND type axis — `type_str agreement` — compares
//! the import's MAPPED msgType string with the shadow payload's
//! ORIGINAL wire `$.msgType` string. That is the meaningful type
//! comparison today: the still-soaking pre-H1-fix build writes the
//! degenerate numeric `type=100` for every real message, so the
//! numeric axis is near-vacuous, while `payload_json` still carries
//! the true wire string verbatim.
//!
//! Batch 15 O4 (KQ2 on the import path): `ZR_OWN_UID` (validated
//! with `account::valid_uid`) seeds the self-sent sender
//! substitution, exactly like the CLI's own-uid rule; the value is
//! never printed — only `own_uid set: true/false`.
//!
//! Printout is shape-only per the batch-12 hard rule: conversations
//! appear as `h12(conv id)`, never as the raw id; counts and
//! percentages only — no message text, no payload, no senders.
//!
//! Inputs (all required; the probe is `#[ignore]`d):
//! - `ZR_SNAPSHOT_DIR`  — a cold snapshot made by tools/snapshot.ps1
//!   (the batch-6 guards run: manifest + never the live tree);
//! - `ZR_D7_KEY_FILE`    — the DPAPI-wrapped D7 key capture;
//! - `ZR_UIN_HASH`       — the expected sha256-12 of that key;
//! - `ZR_MAPPING`        — the mapping JSON (`docs/import-mapping.md`).
//! The shadow DB is a temp COPY of the live store
//! (`probe_util::open_copy`, `ZR_PROBE_DIR` overrides the source).
//!
//! Run:
//! ```text
//! cargo test --lib probe_import_overlap -- --ignored --nocapture
//! ```
//!
//! The comparison core (`overlap_window`, `in_window`,
//! `compare_overlap`) is PURE and unit-tested below; only the I/O
//! lives in the ignored test.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde_json::Value;

use super::cli::ImportArgs;
use super::import;
use super::import_map::{self, MapDb};
use super::probe_util;
use super::Write;

/// One message reduced to the comparison facts. The msg_id is a
/// matching key, never printed raw (h12 only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsgLite {
    pub msg_id: String,
    pub ts: i64,
    pub kind: i64,
    pub sender: Option<String>,
    /// The payload's msgType STRING (batch 15 O3): on the Desktop side
    /// the import's MAPPED msgType, on the shadow side the stored
    /// payload's ORIGINAL `$.msgType` wire string. The meaningful
    /// type comparison while the numeric `kind` axis is degenerate.
    pub type_str: Option<String>,
}

fn ts_range(m: &[MsgLite]) -> Option<(i64, i64)> {
    if m.is_empty() {
        return None;
    }
    let min = m.iter().map(|x| x.ts).min().unwrap();
    let max = m.iter().map(|x| x.ts).max().unwrap();
    Some((min, max))
}

/// The overlapping time window: the intersection of the two sides'
/// [min ts, max ts] ranges. `None` when either side is empty or the
/// ranges do not intersect. Pure.
pub fn overlap_window(desktop: &[MsgLite], shadow: &[MsgLite]) -> Option<(i64, i64)> {
    let (dmin, dmax) = ts_range(desktop)?;
    let (smin, smax) = ts_range(shadow)?;
    let lo = dmin.max(smin);
    let hi = dmax.min(smax);
    (lo <= hi).then_some((lo, hi))
}

/// The messages inside `w` (inclusive bounds). Pure.
pub fn in_window<'a>(m: &'a [MsgLite], w: &(i64, i64)) -> Vec<&'a MsgLite> {
    m.iter().filter(|x| x.ts >= w.0 && x.ts <= w.1).collect()
}

/// The pure comparison: two sides already cut to the window, matched
/// by msgId. Type agreement is counted over matches on BOTH axes —
/// the numeric `kind` (degenerate while the soak build writes
/// type=100) and `type_str` (the import's mapped msgType vs the
/// shadow payload's `$.msgType`, the meaningful axis today; compared
/// only when both sides have a string, like the sender axis). ts
/// agreement over matches; sender agreement over the matches where
/// BOTH sides have a sender (the capture path substitutes the own uid
/// where import leaves NULL — the report shows the not-compared
/// count so nothing is hidden).
pub fn compare_overlap(desktop: &[MsgLite], shadow: &[MsgLite]) -> OverlapCounters {
    let mut c = OverlapCounters::default();
    c.desktop = desktop.len();
    c.shadow = shadow.len();
    let mut by_id: BTreeMap<&str, &MsgLite> = BTreeMap::new();
    for m in shadow {
        by_id
            .entry(m.msg_id.as_str())
            .or_insert(m); // a duplicate shadow row never double-counts
    }
    for d in desktop {
        let Some(s) = by_id.get(d.msg_id.as_str()) else { continue };
        c.matched += 1;
        if d.kind == s.kind {
            c.type_agree += 1;
        }
        if let (Some(a), Some(b)) = (&d.type_str, &s.type_str) {
            c.type_str_compared += 1;
            if a == b {
                c.type_str_agree += 1;
            }
        }
        if d.ts == s.ts {
            c.ts_agree += 1;
        }
        if let (Some(a), Some(b)) = (&d.sender, &s.sender) {
            c.sender_compared += 1;
            if a == b {
                c.sender_agree += 1;
            }
        }
    }
    c
}

/// Per-conversation and total counters (shape only).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct OverlapCounters {
    pub desktop: usize,
    pub shadow: usize,
    pub matched: usize,
    pub type_agree: usize,
    pub type_str_agree: usize,
    pub type_str_compared: usize,
    pub ts_agree: usize,
    pub sender_agree: usize,
    pub sender_compared: usize,
}

impl OverlapCounters {
    /// Add `o` into `self` (the totals fold).
    pub fn add(&mut self, o: OverlapCounters) {
        self.desktop += o.desktop;
        self.shadow += o.shadow;
        self.matched += o.matched;
        self.type_agree += o.type_agree;
        self.type_str_agree += o.type_str_agree;
        self.type_str_compared += o.type_str_compared;
        self.ts_agree += o.ts_agree;
        self.sender_agree += o.sender_agree;
        self.sender_compared += o.sender_compared;
    }
}

#[test]
#[ignore]
fn probe_import_overlap() {
    let snap = std::env::var("ZR_SNAPSHOT_DIR")
        .expect("ZR_SNAPSHOT_DIR: point at a cold snapshot (tools/snapshot.ps1 output)");
    let key = std::env::var("ZR_D7_KEY_FILE")
        .expect("ZR_D7_KEY_FILE: the DPAPI-wrapped D7 key capture");
    let uin = std::env::var("ZR_UIN_HASH").expect("ZR_UIN_HASH: the expected sha256-12 of the key");
    let map = std::env::var("ZR_MAPPING").expect("ZR_MAPPING: the mapping JSON to verify");

    // The batch-6 guards run through the normal import prepare:
    // manifest, live-tree refusal, key/uin cross-check, profile.
    let a = ImportArgs {
        from_snapshot: PathBuf::from(&snap),
        account: "default".into(),
        uin_hash: uin,
        key_file: Some(PathBuf::from(&key)),
        cipher_compat: None,
        inventory: false,
        out: None,
        mapping: Some(PathBuf::from(&map)),
        shadow_copy: None,
        delta: false,
        distinct: Vec::new(),
        all_dbs: false,
        own_uid_from_settings: false,
        target: None,
        i_have_a_backup_plan: false,
        unmapped_as_raw: false,
        media_plan: false,
        content_shape: None,
        by: None,
        apply: false,
        help: false,
    };
    let p = import::prepare(&a).expect("snapshot guards + key + cipher profile");
    let mapping = import_map::load_mapping_file(PathBuf::from(&map).as_path())
        .expect("loading the mapping JSON");
    let g = import::gather_inventories(&p).expect("gathering the snapshot inventories");
    let plan = import_map::plan(&mapping, &g.inv)
        .unwrap_or_else(|errs| panic!("mapping failed validation:\n  - {}", errs.join("\n  - ")));
    println!(
        "overlap: plan OK ({}) snapshot one_to_one={} group={} stranger_box={}",
        plan.summary_line(),
        g.one_to_one,
        g.group,
        g.stranger_box
    );
    if plan.message.is_none() {
        println!("overlap: the mapping maps no message entity — nothing to compare");
        return;
    }

    // Batch 15 O4 (KQ2 on the import path): `ZR_OWN_UID`, validated,
    // never printed — only whether one was found (the maint_repair
    // convention). Without it the self-sent import rows keep a NULL
    // sender and the missing-sender line below shows them.
    let own_uid = std::env::var("ZR_OWN_UID")
        .ok()
        .filter(|u| super::account::valid_uid(u));
    println!("overlap: own_uid set: {}", own_uid.is_some());

    // The shadow side: a temp COPY of the live store, read-only.
    let (shadow, tmp) = probe_util::open_copy();
    println!("overlap: shadow copy: {}", tmp.display());

    // The 20 most recent conversations present in both: walk the
    // shadow's conversations by last_ts DESC, keep a conv when the
    // snapshot has its Desktop DB file, up to 10 per bucket.
    struct Pick {
        id: String,
        is_group: bool,
    }
    let msg_dir = p.uid_dir.join("Core").join("Message");
    let mut picks: Vec<Pick> = Vec::new();
    {
        let mut st = shadow
            .prepare(
                "SELECT id, type FROM conversations \
                 WHERE last_ts IS NOT NULL ORDER BY last_ts DESC",
            )
            .unwrap();
        let rows = st
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)? == 1)))
            .unwrap();
        for row in rows.flatten() {
            let (id, is_group) = row;
            if picks.iter().filter(|x| x.is_group == is_group).count() >= 10 {
                continue;
            }
            let name = if is_group {
                format!("g{id}.db")
            } else {
                format!("{id}.db")
            };
            if !msg_dir.join(&name).is_file() {
                continue; // not present in the snapshot
            }
            picks.push(Pick { id, is_group });
            if picks.iter().filter(|x| x.is_group).count() >= 10
                && picks.iter().filter(|x| !x.is_group).count() >= 10
            {
                break;
            }
        }
    }
    let n_o2o = picks.iter().filter(|x| !x.is_group).count();
    let n_grp = picks.iter().filter(|x| x.is_group).count();
    println!("overlap: conversations selected: one2one={n_o2o} group={n_grp}");
    let covers = |grp: bool| {
        plan.message
            .as_ref()
            .is_some_and(|e| e.db.contains(&(if grp { MapDb::Group } else { MapDb::OneToOne })))
    };

    let mut total = OverlapCounters::default();
    let mut convs_compared = 0usize;
    for pick in &picks {
        let h = probe_util::h12(&pick.id);
        let kind = if pick.is_group { MapDb::Group } else { MapDb::OneToOne };
        let kind_s = if pick.is_group { "group" } else { "one2one" };
        if !covers(pick.is_group) {
            println!("overlap: conv={h} kind={kind_s}: the mapping does not cover this DB kind");
            continue;
        }
        let name = if pick.is_group {
            format!("g{}.db", pick.id)
        } else {
            format!("{}.db", pick.id)
        };
        let conn = match import::open_desktop_db(&msg_dir.join(&name), p.passphrase.as_str(), p.profile) {
            Ok(c) => c,
            Err(_) => {
                // No ids or values in the skip line — shape only.
                println!("overlap: conv={h} kind={kind_s}: Desktop DB open failed: skipped");
                continue;
            }
        };
        let db_id = pick.id.parse::<u64>().ok();
        let (writes, _skips) = import_map::extract(
            &conn,
            &plan,
            &import_map::ExtractOpts {
                kind,
                db_id,
                cursor: None,
                own_uid: own_uid.as_deref(),
            },
        )
        .expect("extraction must not fail on an opened DB");
        // Keep only this conversation's messages (a 1-1 DB is one
        // conversation, but the mapping derives conv ids per row).
        let desktop: Vec<MsgLite> = writes
            .into_iter()
            .filter_map(|w| match w {
                Write::Message {
                    msg_id,
                    conv_id,
                    sender_id,
                    ts,
                    kind,
                    payload,
                    ..
                } if conv_id == pick.id => {
                    // The import's MAPPED msgType string, read back
                    // from the payload it built (batch 15 O3).
                    let type_str = serde_json::from_str::<Value>(&payload)
                        .ok()
                        .and_then(|p| p.get("msgType").and_then(Value::as_str).map(str::to_string));
                    Some(MsgLite {
                        msg_id,
                        ts,
                        kind,
                        sender: sender_id,
                        type_str,
                    })
                }
                _ => None,
            })
            .collect();
        let shadow_msgs: Vec<MsgLite> = {
            // The shadow payload's ORIGINAL wire $.msgType (batch 15
            // O3) rides along as the second type axis.
            let mut st = shadow
                .prepare(
                    "SELECT msg_id, ts, type, sender_id, \
                     json_extract(payload_json, '$.msgType') \
                     FROM messages WHERE conv_id = ?1",
                )
                .unwrap();
            let rows = st
                .query_map(rusqlite::params![pick.id], |r| {
                    Ok(MsgLite {
                        msg_id: r.get(0)?,
                        ts: r.get(1)?,
                        kind: r.get(2)?,
                        sender: r.get(3)?,
                        type_str: r.get::<_, Option<String>>(4)?,
                    })
                })
                .unwrap();
            rows.flatten().collect()
        };
        let Some(w) = overlap_window(&desktop, &shadow_msgs) else {
            println!(
                "overlap: conv={h} kind={kind_s}: no time overlap (desktop={} shadow={})",
                desktop.len(),
                shadow_msgs.len()
            );
            continue;
        };
        let d: Vec<MsgLite> = in_window(&desktop, &w).into_iter().cloned().collect();
        let s: Vec<MsgLite> = in_window(&shadow_msgs, &w).into_iter().cloned().collect();
        let c = compare_overlap(&d, &s);
        let pct = if c.desktop > 0 {
            100.0 * c.matched as f64 / c.desktop as f64
        } else {
            100.0
        };
        // Shape-only line: h12 conv id, counts and percentages — no
        // ids, no ts bounds, no content (batch-12 hard rule).
        println!(
            "overlap: conv={h} kind={kind_s} desktop={} shadow={} matched={} pct={pct:.1} type={}/{} type_str={}/{} (compared {}) ts={}/{} sender={}/{} (compared {})",
            c.desktop, c.shadow, c.matched,
            c.type_agree, c.matched, c.type_str_agree, c.type_str_compared, c.type_str_compared,
            c.ts_agree, c.matched,
            c.sender_agree, c.sender_compared, c.sender_compared
        );
        total.add(c);
        convs_compared += 1;
    }

    // Totals vs the 2.3 AC: >=99% msgId overlap on the time
    // intersection, 100% type/ts/sender on the matches.
    let pct = if total.desktop > 0 {
        100.0 * total.matched as f64 / total.desktop as f64
    } else {
        0.0
    };
    println!(
        "overlap: TOTAL convs={convs_compared} desktop={} shadow={} matched={} pct={pct:.1}%",
        total.desktop, total.shadow, total.matched
    );
    println!(
        "overlap: agreement on matches: type={}/{} (numeric axis) type_str={}/{} of {} compared (payload $.msgType axis) ts={}/{} sender={}/{} of {} compared ({} matches have no sender on one side)",
        total.type_agree, total.matched,
        total.type_str_agree, total.type_str_compared, total.type_str_compared,
        total.ts_agree, total.matched,
        total.sender_agree, total.sender_compared, total.sender_compared,
        total.matched - total.sender_compared
    );
    println!(
        "overlap: type_str is the meaningful type axis today — the shadow's numeric type stays \
         degenerate (type=100) until the post-H1-fix build deploys; re-read both after deploy"
    );
    let overlap_ok = pct >= 99.0 && total.desktop > 0;
    let type_ts_ok =
        total.matched > 0 && total.type_agree == total.matched && total.ts_agree == total.matched;
    let sender_ok = total.sender_compared == total.matched && total.sender_agree == total.sender_compared;
    println!(
        "overlap: AC msgId overlap >= 99%: {} ({pct:.1}%)",
        if overlap_ok { "MET" } else { "NOT MET" }
    );
    println!(
        "overlap: AC type/ts 100% on matches: {}",
        if type_ts_ok { "MET" } else { "NOT MET" }
    );
    println!(
        "overlap: AC sender 100% on matches: {} (missing-sender matches are shown above)",
        if sender_ok { "MET" } else { "NOT MET" }
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(id: &str, ts: i64, kind: i64, sender: Option<&str>) -> MsgLite {
        MsgLite {
            msg_id: id.into(),
            ts,
            kind,
            sender: sender.map(str::to_string),
            type_str: None,
        }
    }

    /// `m` plus the payload msgType STRING (batch 15 O3).
    fn ms(id: &str, ts: i64, kind: i64, sender: Option<&str>, type_str: Option<&str>) -> MsgLite {
        MsgLite {
            msg_id: id.into(),
            ts,
            kind,
            sender: sender.map(str::to_string),
            type_str: type_str.map(str::to_string),
        }
    }

    #[test]
    fn overlap_window_intersects_ranges() {
        let d = vec![m("a", 100, 1, None), m("b", 300, 1, None)];
        let s = vec![m("c", 200, 1, None), m("e", 500, 1, None)];
        assert_eq!(overlap_window(&d, &s), Some((200, 300)));
        // Inclusive bounds touch.
        let s2 = vec![m("f", 300, 1, None), m("g", 900, 1, None)];
        assert_eq!(overlap_window(&d, &s2), Some((300, 300)));
        // Disjoint, empty, single-sided.
        let s3 = vec![m("h", 301, 1, None)];
        assert_eq!(overlap_window(&d, &s3), None);
        assert_eq!(overlap_window(&d, &[]), None);
        assert_eq!(overlap_window(&[], &s), None);
        assert_eq!(overlap_window(&[], &[]), None);
        // A single message on both sides: the point window.
        let d1 = vec![m("x", 42, 1, None)];
        let s1 = vec![m("y", 42, 1, None)];
        assert_eq!(overlap_window(&d1, &s1), Some((42, 42)));
    }

    #[test]
    fn in_window_is_inclusive() {
        let msgs = vec![m("a", 1, 1, None), m("b", 5, 1, None), m("c", 10, 1, None)];
        let got = in_window(&msgs, &(1, 10));
        assert_eq!(got.len(), 3);
        let got = in_window(&msgs, &(5, 5));
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].msg_id, "b");
        let got = in_window(&msgs, &(6, 9));
        assert!(got.is_empty());
    }

    #[test]
    fn compare_counts_matches_and_agreement() {
        // desktop in window: 3; shadow in window: 3; 2 match.
        let d = vec![
            m("m1", 100, 1, Some("u1")),
            m("m2", 110, 2, Some("u2")),
            m("m3", 120, 6, None),
        ];
        let s = vec![
            m("m1", 100, 1, Some("u1")),   // full agree
            m("m2", 111, 2, Some("u2")),   // ts differs
            m("m9", 130, 1, Some("u3")),   // no desktop twin
        ];
        let c = compare_overlap(&d, &s);
        assert_eq!(c.desktop, 3);
        assert_eq!(c.shadow, 3);
        assert_eq!(c.matched, 2);
        assert_eq!(c.type_agree, 2);
        assert_eq!(c.ts_agree, 1);
        assert_eq!(c.sender_agree, 2);
        assert_eq!(c.sender_compared, 2);
        // A duplicate shadow row never double-counts a match.
        let s_dup = [s.clone(), vec![m("m1", 100, 1, Some("u1"))]].concat();
        let c2 = compare_overlap(&d, &s_dup);
        assert_eq!(c2.matched, 2);
        assert_eq!(c2.shadow, 4, "the shadow count still counts its rows");
        // Sender missing on one side is not compared (import leaves
        // self-sent NULL; capture substitutes the own uid).
        let d2 = vec![m("m4", 200, 1, None)];
        let s2 = vec![m("m4", 200, 1, Some("own"))];
        let c3 = compare_overlap(&d2, &s2);
        assert_eq!(c3.matched, 1);
        assert_eq!(c3.sender_compared, 0);
        assert_eq!(c3.sender_agree, 0);
        // Type disagreement is visible.
        let s3 = vec![m("m4", 200, 9, Some("own"))];
        let c4 = compare_overlap(&d2, &s3);
        assert_eq!(c4.type_agree, 0);
    }

    #[test]
    fn compare_counts_type_str_agreement_on_the_string_axis() {
        // Batch 15 O3: the second type axis — the import's MAPPED
        // msgType string vs the shadow payload's $.msgType.
        // Full agree.
        let d = vec![ms("m1", 100, 100, None, Some("webchat"))];
        let s = vec![ms("m1", 100, 100, None, Some("webchat"))];
        let c = compare_overlap(&d, &s);
        assert_eq!(c.type_str_compared, 1);
        assert_eq!(c.type_str_agree, 1);
        // Disagree: an UNMAPPED Desktop code stays the raw code string
        // while the shadow carries the original wire string.
        let s = vec![ms("m1", 100, 100, None, Some("chat.photo"))];
        let c = compare_overlap(&d, &s);
        assert_eq!(c.type_str_agree, 0, "\"webchat\" != \"chat.photo\"");
        // A missing string on one side is not compared (reported,
        // never hidden — same rule as the sender axis).
        let s = vec![ms("m1", 100, 100, None, None)];
        let c = compare_overlap(&d, &s);
        assert_eq!(c.type_str_compared, 0);
        assert_eq!(c.type_str_agree, 0);
        // The numeric axis and the string axis are independent: this
        // pair agrees numerically (both 100) but not on the string.
        assert_eq!(c.type_agree, 1);
    }

    #[test]
    fn counters_add_up() {
        let a = OverlapCounters {
            desktop: 3,
            shadow: 2,
            matched: 1,
            type_agree: 1,
            type_str_agree: 1,
            type_str_compared: 1,
            ts_agree: 0,
            sender_agree: 1,
            sender_compared: 1,
        };
        let mut t = OverlapCounters::default();
        t.add(a);
        t.add(a);
        assert_eq!(t.desktop, 6);
        assert_eq!(t.matched, 2);
        assert_eq!(t.ts_agree, 0);
        assert_eq!(t.type_str_agree, 2);
        assert_eq!(t.type_str_compared, 2);
        assert_eq!(t.sender_compared, 2);
    }
}
