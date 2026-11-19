//! Focused shape probe for normalize debugging (values never printed).
use serde_json::Value;

use super::golden::open_live;
use crate::migrate::sqlcipher;

fn shape(v: &Value, depth: usize) -> String {
    let ind = "  ".repeat(depth.max(1) - 1);
    match v {
        Value::Object(m) => {
            let parts: Vec<String> = m
                .iter()
                .map(|(k, x)| match x {
                    Value::Array(a) => format!("{k}:arr{}", a.len()),
                    Value::Object(o) => format!("{k}:obj{}", o.len()),
                    Value::String(s) => format!("{k}:str{}", s.len()),
                    Value::Number(_) => format!("{k}:num"),
                    Value::Bool(_) => format!("{k}:bool"),
                    Value::Null => format!("{k}:null"),
                })
                .collect();
            format!("{ind}{{{}}}", parts.join(", "))
        }
        Value::Array(a) => format!("{ind}arr{}", a.len()),
        Value::String(s) => format!("{ind}str{}", s.len()),
        _ => format!("{ind}scalar"),
    }
}

#[test]
#[ignore]
fn probe_shapes() {
    let live = open_live();
    // 1. One message payload_json: field names/types.
    {
        let mut st = live
            .prepare("SELECT msg_id, payload_json FROM messages ORDER BY ts DESC LIMIT 1")
            .unwrap();
        for row in st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))).unwrap().take(1) {
            let (id, p) = row.unwrap();
            let v: Value = serde_json::from_str(&p).unwrap();
            println!("MSG {id}:");
            println!("{}", shape(&v, 1));
        }
    }
    // 2. WS events carrying msgs/groupMsgs — print data KEYS.
    {
        let mut st = live
            .prepare("SELECT endpoint, payload_json FROM raw_events WHERE kind='ws' AND payload_json LIKE '%msgs%' LIMIT 3")
            .unwrap();
        for row in st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))).unwrap() {
            let (ep, p) = row.unwrap();
            let v: Value = serde_json::from_str(&p).unwrap_or(Value::Null);
            println!("WS-MSGS endpoint={ep}");
            println!("{}", shape(&v, 1));
            if let Some(d) = v.get("data").and_then(Value::as_object) {
                println!("  data keys: {:?}", d.keys().collect::<Vec<_>>());
                for (k, x) in d.iter() {
                    if let Some(arr) = x.as_array() {
                        if let Some(m) = arr.first() {
                            println!("  {k}[0]:");
                            println!("{}", shape(m, 3));
                        }
                    }
                }
            }
        }
    }
    // 2c. Deep-unroll: WS data.data and REST data-string parses.
    {
        let mut st = live
            .prepare("SELECT kind, endpoint, payload_json FROM raw_events WHERE kind='ws' AND payload_json LIKE '%msgs%' LIMIT 2")
            .unwrap();
        for row in st.query_map([], |r| Ok((r.get::<_, String>(1)?, r.get::<_, String>(2)?))).unwrap() {
            let (_ep, p) = row.unwrap();
            let v: Value = serde_json::from_str(&p).unwrap();
            let inner = v.get("data").and_then(|d| d.get("data")).cloned().unwrap_or(Value::Null);
            println!("WS-INNER (data.data):");
            println!("{}", shape(&inner, 2));
            if let Some(arr) = inner.get("msgs").and_then(Value::as_array) {
                if let Some(m) = arr.first() {
                    println!("  inner msgs[0]:");
                    println!("{}", shape(m, 4));
                }
            }
            if let Some(arr) = inner.get("groupMsgs").and_then(Value::as_array) {
                if let Some(m) = arr.first() {
                    println!("  inner groupMsgs[0]:");
                    println!("{}", shape(m, 4));
                }
            }
        }
        let mut st = live
            .prepare("SELECT payload_json FROM raw_events WHERE kind='rest' AND endpoint LIKE '%get-last-msgs%' LIMIT 1")
            .unwrap();
        for row in st.query_map([], |r| Ok(r.get::<_, String>(0)?)).unwrap() {
            let p = row.unwrap();
            let v: Value = serde_json::from_str(&p).unwrap();
            if let Some(s) = v.get("data").and_then(Value::as_str) {
                let e: Value = serde_json::from_str(s).unwrap_or(Value::Null);
                println!("REST-DATA-STRING parsed:");
                println!("{}", shape(&e, 1));
                if let Some(inner) = e.get("data") {
                    println!("  inner data:");
                    println!("{}", shape(inner, 2));
                    if let Some(cu) = inner.get("clearUnreads").and_then(Value::as_array) {
                        if let Some(c) = cu.first() {
                            println!("    clearUnreads[0]:");
                            println!("{}", shape(c, 4));
                        }
                    }
                    if let Some(arr) = inner.get("msgs").and_then(Value::as_array) {
                        if let Some(m) = arr.first() {
                            println!("    inner msgs[0]:");
                            println!("{}", shape(m, 4));
                        }
                    }
                }
            }
        }
    }
    // 2b. Parse-failure census (the replay skipped unparseable rows).
    {
        let mut st = live.prepare("SELECT kind, payload_json FROM raw_events").unwrap();
        let rows = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, Option<String>>(0)?.unwrap_or_default(),
                    r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                ))
            })
            .unwrap();
        let mut bad: std::collections::BTreeMap<String, (usize, String)> = Default::default();
        for row in rows {
            let (kind, p) = row.unwrap();
            if serde_json::from_str::<Value>(&p).is_err() {
                let e = bad.entry(kind).or_insert((0, String::new()));
                e.0 += 1;
                if e.1.is_empty() {
                    // shape only: length + prefix class
                    let printable = p.chars().take(60).collect::<String>();
                    let cls = if printable.chars().all(|c| c.is_ascii_graphic() || c == ' ') {
                        "ascii"
                    } else {
                        "binary"
                    };
                    e.1 = format!("len={} class={} head={:?}", p.len(), cls, &printable[..printable.len().min(40)]);
                }
            }
        }
        for (k, (n, desc)) in bad {
            println!("PARSE-FAIL kind={k}: {n} rows; first: {desc}");
        }
    }
    // 3. REST get-last-msgs.
    {
        let mut st = live
            .prepare("SELECT endpoint, payload_json FROM raw_events WHERE kind='rest' AND endpoint LIKE '%get-last-msgs%' LIMIT 1")
            .unwrap();
        for row in st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))).unwrap() {
            let (ep, p) = row.unwrap();
            let v: Value = serde_json::from_str(&p).unwrap();
            println!("REST-LAST-MSGS (len {}):", p.len());
            println!("{}", shape(&v, 1));
            let d = v.get("data").cloned().unwrap_or(v.clone());
            if let Some(cu) = d.get("clearUnreads").and_then(Value::as_array) {
                if let Some(c) = cu.first() {
                    println!("  clearUnreads[0]:");
                    println!("{}", shape(c, 3));
                }
            }
            if let Some(arr) = d.get("msgs").and_then(Value::as_array) {
                if let Some(m) = arr.first() {
                    println!("  msgs[0]:");
                    println!("{}", shape(m, 3));
                }
            }
        }
    }
    // 4. ws-open kind.
    {
        let mut st = live
            .prepare("SELECT endpoint, payload_json FROM raw_events WHERE kind='ws-open' LIMIT 2")
            .unwrap();
        for row in st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))).unwrap() {
            let (ep, p) = row.unwrap();
            let v: Value = serde_json::from_str(&p).unwrap_or(Value::Null);
            println!("WS-OPEN endpoint={ep} len={}", p.len());
            println!("{}", shape(&v, 1));
        }
    }
    // 5. Which ws cmds exist.
    {
        let mut st = live
            .prepare("SELECT endpoint, COUNT(*) FROM raw_events WHERE kind='ws' GROUP BY 1 ORDER BY 2 DESC")
            .unwrap();
        for row in st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))).unwrap() {
            let (ep, n) = row.unwrap();
            println!("WS {n:3}x {ep}");
        }
    }
    // 6. Normalize dry-run counts over ALL events.
    {
        let mut st = live
            .prepare("SELECT kind, endpoint, payload_json FROM raw_events")
            .unwrap();
        let rows = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, Option<String>>(0)?.unwrap_or_default(),
                    r.get::<_, Option<String>>(1)?.unwrap_or_default(),
                    r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                ))
            })
            .unwrap();
        let mut norm_ws = 0usize;
        let mut norm_rest = 0usize;
        let mut total_ws = 0usize;
        let mut total_rest = 0usize;
        let mut cmds_with_writes: std::collections::BTreeMap<String, usize> = Default::default();
        for row in rows {
            let (kind, ep, p) = row.unwrap();
            let Ok(v) = serde_json::from_str::<Value>(&p) else { continue };
            match kind.as_str() {
                "ws" => {
                    total_ws += 1;
                    let w = crate::shadow::normalize::normalize_ws(&v, None);
                    if !w.is_empty() {
                        norm_ws += w.len();
                        let cmd = format!(
                            "{}/{}",
                            v.get("cmd").map(|c| c.to_string()).unwrap_or("?".into()),
                            v.get("subCmd").map(|c| c.to_string()).unwrap_or("?".into())
                        );
                        *cmds_with_writes.entry(format!("ws {cmd}")).or_default() += w.len();
                    }
                }
                "rest" => {
                    total_rest += 1;
                    let w = crate::shadow::normalize::normalize_rest(&ep, &v, None);
                    if !w.is_empty() {
                        norm_rest += w.len();
                        *cmds_with_writes.entry(format!("rest {}", crate::shadow::capture::safe_endpoint(&ep))).or_default() += w.len();
                    }
                }
                _ => {}
            }
        }
        println!(
            "normalize dry-run: ws events={total_ws} ws writes={norm_ws} | rest events={total_rest} rest writes={norm_rest}"
        );
        for (k, n) in cmds_with_writes.iter().take(20) {
            println!("  {n:3}x {k}");
        }
    }
    let _ = sqlcipher::generate_key;
}
