//! TEMPORARY probe run inline via cargo test - do not commit.
#[test]
#[ignore]
fn probe_attach() {
    let dir = std::path::PathBuf::from(std::env::var("LOCALAPPDATA").unwrap())
        .join("com.o365serveronms.zalors/shadow");
    let key = crate::migrate::sqlcipher::load_key(&dir.join("default.key")).unwrap();
    let conn = crate::migrate::sqlcipher::open_with_key_readonly(&dir.join("default.db"), &key).unwrap();
    let q = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get(0)).unwrap() };
    println!("attachments total={} ref={} downloaded={} failed={} https_ref={}",
        q("SELECT COUNT(*) FROM attachments"),
        q("SELECT COUNT(*) FROM attachments WHERE status='ref'"),
        q("SELECT COUNT(*) FROM attachments WHERE status='downloaded'"),
        q("SELECT COUNT(*) FROM attachments WHERE status='failed'"),
        q("SELECT COUNT(*) FROM attachments WHERE status='ref' AND url LIKE 'https://%'"),
    );
}
