//! Probe: full key set + array name for the diff messages.
use serde_json::Value;

use super::golden::open_live;

#[test]
#[ignore]
fn probe_array_context() {
    let live = open_live();
    for msg_id in ["8486229703394", "8484506616301", "8482383933793"] {
        let mut st = live
            .prepare("SELECT kind, payload_json FROM raw_events WHERE payload_json LIKE ?1 LIMIT 5")
            .unwrap();
        let like = format!("%\"{msg_id}\"%");
        for row in st.query_map([like], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        }).unwrap() {
            let (kind, p) = row.unwrap();
            let v: Value = serde_json::from_str(&p).unwrap_or(Value::Null);
            fn find_ctx<'a>(v: &'a Value, msg_id: &str, path: &str, out: &mut Vec<(String, &'a Value)>) {
                match v {
                    Value::Object(m) => {
                        if m.get("msgId").and_then(Value::as_str) == Some(msg_id) {
                            out.push((path.to_string(), v));
                        }
                        for (k, x) in m {
                            find_ctx(x, msg_id, &format!("{path}.{k}"), out);
                        }
                    }
                    Value::Array(a) => {
                        for (i, x) in a.iter().enumerate() {
                            find_ctx(x, msg_id, &format!("{path}[{i}]"), out);
                        }
                    }
                    _ => {}
                }
            }
            let mut hits = Vec::new();
            find_ctx(&v, msg_id, "", &mut hits);
            for (path, m) in hits.iter().take(2) {
                let keys: Vec<String> = m.as_object().map(|o| o.keys().cloned().collect()).unwrap_or_default();
                let is_group_field = m.get("isGroup").map(|x| x.to_string());
                println!("{msg_id} [{kind}] path={path}");
                println!("   isGroup field={:?} uidFrom={} idTo={} keys={}",
                    is_group_field,
                    m.get("uidFrom").and_then(Value::as_str).unwrap_or("-"),
                    m.get("idTo").and_then(Value::as_str).unwrap_or("-"),
                    keys.join(","));
            }
        }
        println!("----");
    }
    // 3. Which uid is "self"? Count field contexts of both candidates.
    for uid in ["3488546127013384456", "2294947733392101048", "1701032015085618426", "4006768326137472507"] {
        let mut st = live
            .prepare("SELECT kind, payload_json FROM raw_events WHERE payload_json LIKE ?1 LIMIT 400")
            .unwrap();
        let like = format!("%{uid}%");
        let mut hits = 0;
        let mut ctx: std::collections::BTreeMap<String, usize> = Default::default();
        for row in st.query_map([like], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        }).unwrap() {
            let (kind, p) = row.unwrap();
            if p.contains(uid) {
                hits += 1;
                let field = if p.contains(&format!("\"uidFrom\":\"{uid}\"")) { "uidFrom" }
                    else if p.contains(&format!("\"idTo\":\"{uid}\"")) { "idTo" }
                    else if p.contains(&format!("\"senderId\":\"{uid}\"")) { "senderId" }
                    else if p.contains(&format!("\"userId\":\"{uid}\"")) { "userId" }
                    else if p.contains(&format!("\"creatorId\":\"{uid}\"")) { "creatorId" }
                    else if p.contains(&format!("\"ownerId\":\"{uid}\"")) { "ownerId" }
                    else if p.contains(&format!("\"{uid}\":")) { "as-json-key" }
                    else { "other" };
                *ctx.entry(format!("{kind}:{field}")).or_default() += 1;
            }
        }
        let ctxs: Vec<String> = ctx.into_iter().take(8).map(|(k, v)| format!("{k}={v}")).collect();
        println!("UID {uid}: {hits} rows; contexts: {}", ctxs.join(", "));
    }
}
