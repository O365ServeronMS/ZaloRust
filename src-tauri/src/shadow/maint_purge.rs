//! MAINTENANCE (audit step 1.0-b, 2026-11-19): purge the key material the
//! old inventory tap stored in `raw_events` (kind = 'e2ee').
//!
//! A row is purged when its payload fails the SAME gate the live path now
//! applies (`normalize::e2ee_admit`): no msgId, key-shaped data, or not
//! JSON. `messages` and every other table are never touched.
//!
//! Default = DRY RUN (read-only open, prints counts only).
//! Apply only with the app STOPPED (single-writer rule A5):
//!   $env:ZR_PURGE_APPLY = "1"
//!   cargo test --lib maint_purge_e2ee_keyish -- --ignored --nocapture
//! Apply sets `secure_delete`, deletes, checkpoints the WAL and VACUUMs so
//! freed pages do not keep the old bytes. No backup is taken on purpose:
//! a backup would preserve exactly the data being removed.

use super::normalize::{e2ee_admit, E2eeRefusal};

fn app_running() -> bool {
    std::process::Command::new("tasklist")
        .args(["/FI", "IMAGENAME eq zalors.exe", "/NH"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("zalors.exe"))
        .unwrap_or(true) // cannot tell -> assume running (fail closed)
}

#[test]
#[ignore]
fn maint_purge_e2ee_keyish() {
    let dir = std::path::PathBuf::from(std::env::var("LOCALAPPDATA").unwrap())
        .join("com.o365serveronms.zalors/shadow");
    let apply = std::env::var("ZR_PURGE_APPLY").as_deref() == Ok("1");
    // KQ10: the account helpers name the store files.
    // Batch 18 (R4): this maintenance probe goes through the same rule
    // as every non-app opener — a passphrase-mode store opens only via
    // its remember file; without one it REFUSES (this probe never
    // accepts a password). Fail-closed with the documented message
    // instead of a panic on a missing key file.
    let conn = match super::passphrase::open_store(&dir, !apply) {
        Ok((c, _)) => c,
        Err(super::passphrase::StoreOpenError::Locked) => {
            eprintln!(
                "the store is password-protected (passphrase mode) — unlock it in the app with \
                 'Nhớ trên máy này' (remember on this machine) enabled, then re-run; this probe \
                 never accepts passwords"
            );
            return;
        }
        Err(super::passphrase::StoreOpenError::Other(k)) => {
            panic!("store open failed ({k}) — broken store dir?")
        }
    };
    if apply && app_running() {
        panic!("refusing to apply: zalors.exe is running (stop the app first — single writer)");
    }
    let count = |sql: &str| -> i64 { conn.query_row(sql, [], |r| r.get(0)).unwrap() };
    let msgs_before = count("SELECT COUNT(*) FROM messages");

    let mut purge: Vec<i64> = Vec::new();
    let (mut keep, mut no_id, mut keyish, mut not_json) = (0usize, 0usize, 0usize, 0usize);
    {
        let mut st = conn
            .prepare("SELECT id, payload_json FROM raw_events WHERE kind = 'e2ee'")
            .unwrap();
        let rows = st
            .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, Option<String>>(1)?)))
            .unwrap();
        for row in rows {
            let (id, p) = row.unwrap();
            match e2ee_admit(p.as_deref().unwrap_or("")) {
                Ok(_) => keep += 1,
                Err(e) => {
                    match e {
                        E2eeRefusal::NoMsgId => no_id += 1,
                        E2eeRefusal::KeyShaped => keyish += 1,
                        E2eeRefusal::NotJson => not_json += 1,
                    }
                    purge.push(id);
                }
            }
        }
    }
    println!(
        "e2ee raw rows: keep={keep} purge={} (no_msgid={no_id} keyish={keyish} not_json={not_json}) messages={msgs_before} mode={}",
        purge.len(),
        if apply { "APPLY" } else { "dry-run" }
    );
    if !apply || purge.is_empty() {
        return;
    }
    conn.busy_timeout(std::time::Duration::from_secs(10)).unwrap();
    conn.execute_batch("PRAGMA secure_delete = ON;").unwrap();
    conn.execute_batch("BEGIN IMMEDIATE;").unwrap();
    {
        let mut del = conn.prepare("DELETE FROM raw_events WHERE id = ?1").unwrap();
        for id in &purge {
            del.execute([id]).unwrap();
        }
    }
    conn.execute_batch("COMMIT;").unwrap();
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); VACUUM; PRAGMA wal_checkpoint(TRUNCATE);")
        .unwrap();
    let msgs_after = count("SELECT COUNT(*) FROM messages");
    let integrity: String = conn.query_row("PRAGMA integrity_check", [], |r| r.get(0)).unwrap();
    println!(
        "purged={} messages {msgs_before}->{msgs_after} integrity={integrity}",
        purge.len()
    );
    assert_eq!(msgs_before, msgs_after, "messages must not change");
    assert_eq!(integrity, "ok");
}
