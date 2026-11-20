//! Where do E2EE messages live on the wire? Census of e2ee markers.
use serde_json::Value;

use super::probe_util::open_copy;

#[test]
#[ignore]
fn probe_e2ee_where() {
    let (live, _tmp) = open_copy();
    // 1. cmds that carried the 5 known E2EE messages (old data).
    let mut st = live
        .prepare("SELECT kind, endpoint, payload_json FROM raw_events WHERE payload_json LIKE '%\"e2ee\":\"%' LIMIT 40")
        .unwrap();
    let mut carriers: std::collections::BTreeMap<String, usize> = Default::default();
    for row in st.query_map([], |r| {
        Ok((
            r.get::<_, Option<String>>(0)?.unwrap_or_default(),
            r.get::<_, Option<String>>(1)?.unwrap_or_default(),
            r.get::<_, Option<String>>(2)?.unwrap_or_default(),
        ))
    }).unwrap() {
        let (kind, ep, p) = row.unwrap();
        let v: Value = serde_json::from_str(&p).unwrap_or(Value::Null);
        let label = if kind == "ws" {
            format!("ws cmd={}/{}", v.get("cmd").map(|c| c.to_string()).unwrap_or("?".into()),
                v.get("subCmd").map(|c| c.to_string()).unwrap_or("?".into()))
        } else {
            format!("rest {}", crate::shadow::capture::safe_endpoint(&ep))
        };
        *carriers.entry(label).or_default() += 1;
    }
    println!("e2ee-carrying events (old data):");
    for (k, n) in carriers.iter() {
        println!("  {n:3}x {k}");
    }
    // 2. recent window: any e2ee/ee markers at all?
    // Q4 (batch 17): rolling last-hour window from the real clock.
    let since = super::schema::now_ms() - 3_600_000;
    let n: i64 = live
        .query_row(
            "SELECT COUNT(*) FROM raw_events WHERE ts > ?1 AND payload_json LIKE '%e2ee%'",
            [since],
            |r| r.get(0),
        )
        .unwrap();
    println!("recent rows mentioning e2ee (last 1h): {n}");
    // 3. cmds present in the old 551-class events.
    let mut st = live
        .prepare("SELECT DISTINCT payload_json FROM raw_events WHERE kind='ws' AND payload_json LIKE '%\"cmd\":551%' LIMIT 3")
        .unwrap();
    let mut found = 0;
    for row in st.query_map([], |r| Ok(r.get::<_, String>(0)?)).unwrap() {
        let p = row.unwrap();
        let v: Value = serde_json::from_str(&p).unwrap_or(Value::Null);
        let ks = v.get("data").and_then(Value::as_object)
            .map(|o| o.keys().cloned().collect::<Vec<_>>().join(","))
            .unwrap_or_default();
        println!("old cmd551 data keys: {}", &ks[..ks.len().min(100)]);
        found += 1;
    }
    if found == 0 {
        println!("old cmd551: none found (551 may be nested deeper or absent)");
    }
}
