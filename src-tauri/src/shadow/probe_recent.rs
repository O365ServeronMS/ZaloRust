//! Recent-events census: which cmds landed, and what cmd 551 carries.
use serde_json::Value;

use super::probe_util::open_copy;

#[test]
#[ignore]
fn probe_recent_cmds() {
    let (live, _tmp) = open_copy();
    // Anything from the last 2 hours — Q4 (batch 17): a rolling
    // window from the REAL clock (the old hardcoded cutoff froze the
    // window at audit time and went stale as the soak ran on).
    let cutoff: i64 = super::schema::now_ms() - 2 * 3_600_000;
    let mut st = live
        .prepare("SELECT kind, endpoint, payload_json FROM raw_events WHERE ts > ?1 ORDER BY id")
        .unwrap();
    let rows = st
        .query_map([cutoff], |r| {
            Ok((
                r.get::<_, Option<String>>(0)?.unwrap_or_default(),
                r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                r.get::<_, Option<String>>(2)?.unwrap_or_default(),
            ))
        })
        .unwrap();
    let mut by_cmd: std::collections::BTreeMap<String, usize> = Default::default();
    let mut shapes_551: std::collections::BTreeSet<String> = Default::default();
    let mut msgs_shapes: std::collections::BTreeSet<String> = Default::default();
    for row in rows {
        let (kind, ep, p) = row.unwrap();
        let Ok(v) = serde_json::from_str::<Value>(&p) else {
            *by_cmd.entry(format!("{kind}:unparsed")).or_default() += 1;
            continue;
        };
        let label = if kind == "ws" {
            format!(
                "ws cmd={}/{}",
                v.get("cmd").map(|c| c.to_string()).unwrap_or("?".into()),
                v.get("subCmd").map(|c| c.to_string()).unwrap_or("?".into())
            )
        } else {
            format!("rest {}", crate::shadow::capture::safe_endpoint(&ep))
        };
        *by_cmd.entry(label).or_default() += 1;
        if kind == "ws" && v.get("cmd") == Some(&Value::from(551)) {
            let ks = v
                .get("data")
                .and_then(Value::as_object)
                .map(|o| o.keys().cloned().collect::<Vec<_>>().join(","))
                .unwrap_or_default();
            shapes_551.insert(format!("{}", &ks[..ks.len().min(120)]));
        }
        // any msgs arrays?
        let inner = v
            .get("data")
            .and_then(|d| d.get("data"))
            .cloned()
            .unwrap_or(Value::Null);
        if let Some(o) = inner.as_object() {
            if o.keys().any(|k| k.contains("sgs")) {
                let ks = o.keys().cloned().collect::<Vec<_>>().join(",");
                msgs_shapes.insert(format!("{}", &ks[..ks.len().min(120)]));
            }
        }
    }
    for (k, n) in by_cmd.iter() {
        println!("{n:4}x {k}");
    }
    for s in shapes_551.iter() {
        println!("CMD551 data keys: {s}");
    }
    for s in msgs_shapes.iter() {
        println!("MSGS-LEVEL keys: {s}");
    }
}
