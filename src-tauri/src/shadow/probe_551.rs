//! TEMP probe: cmd 551 census in the recent window.
#[test]
#[ignore]
fn probe_551_now() {
    let (conn, _tmp) = super::probe_util::open_copy();
    // Q4 (batch 17): a rolling last-hour window from the REAL clock —
    // the old hardcoded epoch cut froze the "recent" window at audit
    // time and silently grew stale.
    let since = super::schema::now_ms() - 3_600_000;
    let q = |sql: &str| -> i64 {
        conn.query_row(sql, [since], |r| r.get(0)).unwrap()
    };
    println!(
        "recent551={} total551={} recent_e2ee_rows={} (window: ts > now-1h, since={since})",
        q("SELECT COUNT(*) FROM raw_events WHERE ts > ?1 AND payload_json LIKE '%\"cmd\":551%'"),
        q("SELECT COUNT(*) FROM raw_events WHERE payload_json LIKE '%\"cmd\":551%'"),
        q("SELECT COUNT(*) FROM raw_events WHERE ts > ?1 AND payload_json LIKE '%e2ee%'"),
    );
}
