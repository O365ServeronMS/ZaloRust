//! E2EE plaintext coverage probe (from the original probes; kept as a
//! permanent ignored diagnostic). Prints counts only, never content.
//!
//! Run: cargo test --lib probe_e2ee -- --ignored --nocapture

#[test]
#[ignore]
fn probe_e2ee_plain() {
    let dir = std::path::PathBuf::from(std::env::var("LOCALAPPDATA").unwrap())
        .join("com.o365serveronms.zalors/shadow");
    let key = crate::migrate::sqlcipher::load_key(&dir.join("default.key")).unwrap();
    let conn = crate::migrate::sqlcipher::open_with_key_readonly(&dir.join("default.db"), &key)
        .unwrap();
    let q = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get(0)).unwrap() };
    println!(
        "e2ee_total={} plaintext(source=e2ee)={} with_text={} cipher_only={} messages_total={} convs_total={} raw_events={}",
        q("SELECT COUNT(*) FROM messages WHERE payload_json LIKE '%\"e2ee\":\"_%'"),
        q("SELECT COUNT(*) FROM messages WHERE source='e2ee'"),
        q("SELECT COUNT(*) FROM messages WHERE source='e2ee' AND text IS NOT NULL AND text <> ''"),
        q("SELECT COUNT(*) FROM messages WHERE payload_json LIKE '%\"e2ee\":\"_%' AND source <> 'e2ee'"),
        q("SELECT COUNT(*) FROM messages"),
        q("SELECT COUNT(*) FROM conversations"),
        q("SELECT COUNT(*) FROM raw_events"),
    );
    let (max_ts, recent): (i64, i64) = conn
        .query_row(
            "SELECT (SELECT MAX(ts) FROM raw_events), (SELECT COUNT(*) FROM raw_events WHERE ts > 1795075000000)",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    println!("raw_events max_ts={max_ts} recent_1h={recent} now~=1795076200000");
}
