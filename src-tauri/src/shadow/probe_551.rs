//! TEMP probe: cmd 551 census in the recent window.
#[test]
#[ignore]
fn probe_551_now() {
    let (conn, _tmp) = super::probe_util::open_copy();
    let q = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get(0)).unwrap() };
    println!("recent551={} total551={} recent_e2ee_rows={}",
        q("SELECT COUNT(*) FROM raw_events WHERE ts > 1795077000000 AND payload_json LIKE '%\"cmd\":551%'"),
        q("SELECT COUNT(*) FROM raw_events WHERE payload_json LIKE '%\"cmd\":551%'"),
        q("SELECT COUNT(*) FROM raw_events WHERE ts > 1795077000000 AND payload_json LIKE '%e2ee%'"),
    );
}
