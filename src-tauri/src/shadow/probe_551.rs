//! TEMP probe: cmd 551 census in the recent window.
#[test]
#[ignore]
fn probe_551_now() {
    let dir = std::path::PathBuf::from(std::env::var("LOCALAPPDATA").unwrap())
        .join("com.o365serveronms.zalors/shadow");
    let key = crate::migrate::sqlcipher::load_key(&crate::shadow::key_file(&dir)).unwrap();
    let conn = crate::migrate::sqlcipher::open_with_key_readonly(&crate::shadow::db_file(&dir), &key).unwrap();
    let q = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get(0)).unwrap() };
    println!("recent551={} total551={} recent_e2ee_rows={}",
        q("SELECT COUNT(*) FROM raw_events WHERE ts > 1795077000000 AND payload_json LIKE '%\"cmd\":551%'"),
        q("SELECT COUNT(*) FROM raw_events WHERE payload_json LIKE '%\"cmd\":551%'"),
        q("SELECT COUNT(*) FROM raw_events WHERE ts > 1795077000000 AND payload_json LIKE '%e2ee%'"),
    );
}
