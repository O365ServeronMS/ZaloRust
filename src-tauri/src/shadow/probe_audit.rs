//! AUDIT PROBE (2026-11-19, auditor). SHAPE ONLY — prints counts, msgType
//! labels, JSON key NAMES and json types. Never prints message content,
//! urls, ids of people, keys or tokens.
//!
//! Run: cargo test --lib probe_audit -- --ignored --nocapture

#[test]
#[ignore]
fn probe_audit_shapes() {
    let conn = super::golden::open_live();
    let q = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get(0)).unwrap_or(-1) };

    println!("== messages.type x payload.msgType x typeof(content) ==");
    let mut st = conn
        .prepare(
            "SELECT type, COALESCE(json_extract(payload_json,'$.msgType'),'<none>'),
                    json_type(payload_json,'$.content'), source, COUNT(*)
               FROM messages GROUP BY 1,2,3,4 ORDER BY 5 DESC",
        )
        .unwrap();
    let rows = st
        .query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, i64>(4)?,
            ))
        })
        .unwrap();
    for row in rows {
        let (t, mt, ct, src, n) = row.unwrap();
        println!("  type={t:<4} msgType={mt:<22} content={:<8} source={src:<8} n={n}", ct.unwrap_or_default());
    }

    println!("== content object KEY NAMES for non-string content (by msgType) ==");
    let mut st = conn
        .prepare(
            "SELECT json_extract(m.payload_json,'$.msgType'), j.key, j.type, COUNT(*)
               FROM messages m, json_each(m.payload_json,'$.content') j
              WHERE json_type(m.payload_json,'$.content') = 'object'
              GROUP BY 1,2,3 ORDER BY 1,2",
        )
        .unwrap();
    let rows = st
        .query_map([], |r| {
            Ok((
                r.get::<_, Option<String>>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })
        .unwrap();
    for row in rows {
        let (mt, k, ty, n) = row.unwrap();
        println!("  msgType={:<22} key={k:<14} json={ty:<8} n={n}", mt.unwrap_or_default());
    }

    println!("== top-level payload keys (all messages) ==");
    let mut st = conn
        .prepare(
            "SELECT j.key, COUNT(*) FROM messages m, json_each(m.payload_json) j
              GROUP BY 1 ORDER BY 2 DESC",
        )
        .unwrap();
    let rows = st
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
        .unwrap();
    let keys: Vec<String> = rows.map(|r| { let (k, n) = r.unwrap(); format!("{k}:{n}") }).collect();
    println!("  {}", keys.join(" "));

    println!("== integrity / invariants ==");
    println!(
        "  attachments={} att_ref={} att_downloaded={} att_failed={}",
        q("SELECT COUNT(*) FROM attachments"),
        q("SELECT COUNT(*) FROM attachments WHERE status='ref'"),
        q("SELECT COUNT(*) FROM attachments WHERE status='downloaded'"),
        q("SELECT COUNT(*) FROM attachments WHERE status='failed'"),
    );
    println!(
        "  self_sent(uidFrom=0)={} self_sent_sender_null={} sender_null_total={}",
        q("SELECT COUNT(*) FROM messages WHERE json_extract(payload_json,'$.uidFrom')='0'"),
        q("SELECT COUNT(*) FROM messages WHERE json_extract(payload_json,'$.uidFrom')='0' AND sender_id IS NULL"),
        q("SELECT COUNT(*) FROM messages WHERE sender_id IS NULL"),
    );
    println!(
        "  rev>0={} max_rev={} revisions={} e2ee_rows_payload_has_e2ee_key={}",
        q("SELECT COUNT(*) FROM messages WHERE rev>0"),
        q("SELECT COALESCE(MAX(rev),0) FROM messages"),
        q("SELECT COUNT(*) FROM message_revisions"),
        q("SELECT COUNT(*) FROM messages WHERE source='e2ee' AND json_extract(payload_json,'$.e2ee') IS NOT NULL"),
    );
    println!(
        "  msgs_without_conv_row={} convs_lastmsg_not_newest={} ts_zero={}",
        q("SELECT COUNT(*) FROM messages m WHERE NOT EXISTS (SELECT 1 FROM conversations c WHERE c.id=m.conv_id)"),
        q("SELECT COUNT(*) FROM conversations c JOIN messages m ON m.msg_id=c.last_msg_id
             WHERE m.ts < (SELECT MAX(ts) FROM messages x WHERE x.conv_id=c.id)"),
        q("SELECT COUNT(*) FROM messages WHERE ts=0"),
    );
    println!(
        "  contacts={} groups={} reactions={} raw_events={} raw_undecoded={}",
        q("SELECT COUNT(*) FROM contacts"),
        q("SELECT COUNT(*) FROM groups"),
        q("SELECT COUNT(*) FROM reactions"),
        q("SELECT COUNT(*) FROM raw_events"),
        q("SELECT COUNT(*) FROM raw_events WHERE payload_json LIKE '{\"cmd\":%\"undecoded\"%'"),
    );
    println!(
        "  raw_with_key_field={} (must be 0 for new rows; legacy V1 b64 frames excluded)",
        q("SELECT COUNT(*) FROM raw_events WHERE json_valid(payload_json)
             AND json_extract(payload_json,'$.data.key') IS NOT NULL
             AND json_extract(payload_json,'$.data.key') NOT LIKE '<redacted%'"),
    );

    println!("== REST endpoints seen (safe names) ==");
    let mut st = conn
        .prepare("SELECT kind, endpoint, COUNT(*) FROM raw_events WHERE kind='rest' GROUP BY 1,2 ORDER BY 3 DESC LIMIT 40")
        .unwrap();
    let rows = st
        .query_map([], |r| Ok((r.get::<_, Option<String>>(0)?, r.get::<_, Option<String>>(1)?, r.get::<_, i64>(2)?)))
        .unwrap();
    for row in rows {
        let (_k, e, n) = row.unwrap();
        println!("  {:<60} n={n}", e.unwrap_or_default());
    }
}

#[test]
#[ignore]
fn probe_audit_deep() {
    let conn = super::golden::open_live();
    let q = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get(0)).unwrap_or(-1) };
    let rows = |sql: &str| -> Vec<String> {
        let mut st = conn.prepare(sql).unwrap();
        let n = st.column_count();
        st.query_map([], |r| {
            let mut v = Vec::new();
            for i in 0..n {
                let x: rusqlite::types::Value = r.get(i)?;
                v.push(match x {
                    rusqlite::types::Value::Null => "NULL".into(),
                    rusqlite::types::Value::Integer(i) => i.to_string(),
                    rusqlite::types::Value::Real(f) => f.to_string(),
                    rusqlite::types::Value::Text(t) => t,
                    rusqlite::types::Value::Blob(b) => format!("blob{}", b.len()),
                });
            }
            Ok(v.join(" | "))
        })
        .unwrap()
        .filter_map(Result::ok)
        .collect()
    };
    println!("== rev>0 by source / revisions ==");
    for r in rows("SELECT source, COUNT(*), SUM(rev) FROM messages WHERE rev>0 GROUP BY 1") { println!("  {r}"); }
    println!("== source=e2ee rows WITHOUT e2ee key (msgId | msgType | ctype | clen | ws_hits | rest_hits) ==");
    for r in rows("SELECT m.msg_id, json_extract(m.payload_json,'$.msgType'), json_type(m.payload_json,'$.content'),
                          length(json_extract(m.payload_json,'$.content')),
                          (SELECT COUNT(*) FROM raw_events r WHERE r.kind='ws' AND instr(r.payload_json, m.msg_id)>0),
                          (SELECT COUNT(*) FROM raw_events r WHERE r.kind='rest' AND instr(r.payload_json, m.msg_id)>0)
                     FROM messages m WHERE m.source='e2ee' AND json_extract(m.payload_json,'$.e2ee') IS NULL") { println!("  {r}"); }
    println!("== cipher-only E2EE rows vs tap start ==");
    for r in rows("SELECT MIN(CAST(json_extract(payload_json,'$.ts') AS INTEGER)), MAX(CAST(json_extract(payload_json,'$.ts') AS INTEGER)), COUNT(*)
                     FROM messages WHERE json_extract(payload_json,'$.e2ee') <> '' AND source <> 'e2ee'") { println!("  cipher_only ts min|max|n: {r}"); }
    for r in rows("SELECT MIN(ts), MAX(ts), COUNT(*) FROM raw_events WHERE kind='e2ee'") { println!("  e2ee raw ts min|max|n: {r}"); }
    println!("== raw_events retention (oracle) ==");
    for r in rows("SELECT date(ts/1000,'unixepoch','localtime'), kind, COUNT(*) FROM raw_events GROUP BY 1,2 ORDER BY 1,2") { println!("  {r}"); }
    println!("  oldest_raw_ts={} rest_endpoints_with_query_after_rebuild={}",
        q("SELECT MIN(ts) FROM raw_events"),
        q("SELECT COUNT(*) FROM raw_events WHERE kind='rest' AND instr(endpoint,'?')>0 AND id > (SELECT MIN(id) FROM raw_events WHERE kind='e2ee')"));
    println!("== e2ee raw payload top-level shapes (key sets) ==");
    for r in rows("SELECT CASE WHEN json_valid(payload_json) THEN json_type(payload_json) ELSE 'invalid' END,
                          (SELECT group_concat(key, ',') FROM (SELECT key FROM json_each(r.payload_json) ORDER BY key LIMIT 8)) ks,
                          COUNT(*) FROM raw_events r WHERE kind='e2ee' GROUP BY 1,2 ORDER BY 3 DESC LIMIT 15") { println!("  {r}"); }
    println!("  e2ee raw with msgId={} without msgId={}",
        q("SELECT COUNT(*) FROM raw_events WHERE kind='e2ee' AND json_extract(payload_json,'$.msgId') IS NOT NULL"),
        q("SELECT COUNT(*) FROM raw_events WHERE kind='e2ee' AND json_extract(payload_json,'$.msgId') IS NULL"));
    println!("== photo/video/file params KEY NAMES + href host, by source ==");
    for r in rows("SELECT m.source, json_extract(m.payload_json,'$.msgType'), j.key, COUNT(*)
                     FROM messages m, json_each(json_extract(m.payload_json,'$.content.params')) j
                    WHERE json_type(m.payload_json,'$.content')='object'
                      AND json_valid(json_extract(m.payload_json,'$.content.params'))
                    GROUP BY 1,2,3 ORDER BY 1,2,3") { println!("  {r}"); }
    for r in rows("SELECT source, json_extract(payload_json,'$.msgType'),
                          substr(json_extract(payload_json,'$.content.href'), 1, instr(substr(json_extract(payload_json,'$.content.href'),9),'/')+7) AS host,
                          COUNT(*) FROM messages WHERE json_type(payload_json,'$.content')='object' AND json_extract(payload_json,'$.msgType') IN ('chat.photo','chat.video.msg','share.file','chat.voice') GROUP BY 1,2,3 ORDER BY 4 DESC") { println!("  host: {r}"); }
}
