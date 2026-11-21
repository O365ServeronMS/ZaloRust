//! MAINTENANCE PROBE (audit §1.2 migration, batch 5 E4). Runs the v1
//! repair against a temp COPY of the live store — first as a dry run
//! (report only), then for real — and proves idempotency with a second
//! run. The DB opened here is structurally guaranteed to be a COPY:
//! `probe_util::open_copy_rw` can only hand out a fresh temp-dir copy
//! (asserted again below), so it is IMPOSSIBLE for this test to open
//! the live path for writing.
//!
//! `ZR_OWN_UID` (optional): the account uid for the KQ2 sender
//! backfill, validated with `account::valid_uid` — NEVER printed, only
//! `own_uid set: true/false`.
//!
//! The temp copy is LEFT ON DISK (path printed) so the reviewer can
//! inspect or delete it.
//!
//! Run LATER, with the app stopped (single writer), never while other
//! probes hold the same data:
//!   cargo test --lib maint_repair -- --ignored --nocapture

use rusqlite::Connection;

/// Counts only (H-rule): no row data, ids or content ever printed.
/// (Batch 20: the queries moved into `repair::counts_lines` so the
/// probe and the repair CLI print identical shapes.)
fn print_counts(conn: &Connection) {
    for l in super::repair::counts_lines(conn) {
        println!("{l}");
    }
}

#[test]
#[ignore]
fn maint_repair() {
    // A fresh temp COPY, opened READ-WRITE — never the live store.
    let (conn, tmp) = super::probe_util::open_copy_rw();
    let opened = super::db_file(&tmp);
    assert!(
        opened.starts_with(std::env::temp_dir()),
        "the repaired DB must be a temp copy, never the live path"
    );
    assert_ne!(opened, super::db_file(&super::probe_util::probe_dir()));
    println!("copy dir (left on disk for inspection): {}", tmp.display());

    // ZR_OWN_UID: validated, never printed.
    let own_uid = std::env::var("ZR_OWN_UID")
        .ok()
        .filter(|u| super::account::valid_uid(u));
    println!("own_uid set: {}", own_uid.is_some());

    println!("== counts before ==");
    print_counts(&conn);

    println!("== repair_v1_dry_run (BEGIN IMMEDIATE .. ROLLBACK) ==");
    let dry = super::repair::repair_v1_dry_run(&conn, own_uid.as_deref());
    println!("dry report: {dry:?}");

    println!("== repair_v1 (applied to the COPY) ==");
    let r1 = super::repair::repair_v1(&conn, own_uid.as_deref());
    println!("repair report: {r1:?}");

    // Post-repair integrity (cipher check: tolerated if unsupported).
    let ic: String = conn
        .query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .unwrap_or_else(|_| "query-error".into());
    let cic: String = conn
        .query_row("PRAGMA cipher_integrity_check", [], |r| r.get(0))
        .unwrap_or_else(|_| "not supported".into());
    println!("integrity_check={ic} cipher_integrity_check={cic}");

    println!("== counts after ==");
    print_counts(&conn);

    println!("== second repair (must be all zeros) ==");
    let r2 = super::repair::repair_v1(&conn, own_uid.as_deref());
    println!("second report: {r2:?}");
    assert_eq!(
        r2,
        super::repair::RepairReport::default(),
        "repair_v1 must be idempotent on the repaired copy"
    );
    println!("maint_repair: done (copy left at {})", tmp.display());
}
