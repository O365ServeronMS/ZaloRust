//! TEMP probe: newest message content shape (keys only).
#[test]
#[ignore]
fn probe_latest_content() {
    let (conn, _tmp) = super::probe_util::open_copy();
    let mut st = conn.prepare("SELECT msg_id, source, ts, payload_json FROM messages ORDER BY rowid DESC LIMIT 3").unwrap();
    for row in st.query_map([], |r| Ok((r.get::<_,String>(0)?, r.get::<_,String>(1)?, r.get::<_,i64>(2)?, r.get::<_,String>(3)?))).unwrap() {
        let (id, source, ts, p) = row.unwrap();
        let v: serde_json::Value = serde_json::from_str(&p).unwrap_or(serde_json::Value::Null);
        let msgtype = v.get("msgType").and_then(|x| x.as_str()).unwrap_or("-");
        let ctype = match v.get("content") {
            Some(serde_json::Value::String(s)) => format!("str{}", s.chars().take(24).collect::<String>().len()),
            Some(serde_json::Value::Object(o)) => format!("obj[{}]", o.keys().cloned().collect::<Vec<_>>().join(",")),
            _ => "-".into(),
        };
        let ckeys = v.get("content").and_then(|c| c.as_object()).map(|o| o.keys().cloned().collect::<Vec<_>>().join(",")).unwrap_or_default();
        println!("MSG {id} source={source} ts={ts} type={msgtype} content={ctype}");
        if ckeys.len() > 0 { println!("   ckeys: {}", &ckeys[..ckeys.len().min(200)]); }
    }
}
