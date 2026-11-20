//! Probe access to the live shadow DB ALWAYS goes through a COPY
//! (audit M2-6, batch 5 E0).
//!
//! A READ_ONLY SQLite connection in WAL mode still creates/touches the
//! live `-shm` (and a fresh reader can force a checkpoint): "read
//! only" is NOT "0 ghi" while the app is soaking. Every probe therefore
//! copies `default.db` + `-wal` + `-shm` + `default.key` into a unique
//! temp dir and opens THAT — the live store is never opened at all.
//! Copies are left on disk (cheap; `maint_repair` deliberately leaves
//! its copy for the reviewer to inspect).
//!
//! H-rule: nothing here prints; callers print shapes only.
//!
//! Env overrides (both optional):
//! - `ZR_PROBE_DIR` — the live store dir to copy from (default
//!   `%LOCALAPPDATA%\com.o365serveronms.zalors\shadow`);
//! - `ZR_PROBE_SINCE_ID` — `raw_events` id baseline for coverage
//!   probes (default 0 = scan the whole ring);
//! - `ZR_PROBE_SINCE_MS` — epoch-ms cut for the time-scoped integrity
//!   block (Q6, batch 17; unset/<=0 = no second block).

use std::path::{Path, PathBuf};

use rusqlite::Connection;
use sha2::{Digest, Sha256};

/// The live store dir the probes copy from (`ZR_PROBE_DIR` override,
/// else the documented Roaming path).
pub fn probe_dir() -> PathBuf {
    if let Some(p) = std::env::var_os("ZR_PROBE_DIR") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    default_probe_dir(std::env::var_os("LOCALAPPDATA").unwrap_or_default())
}

/// `%LOCALAPPDATA%\com.o365serveronms.zalors\shadow` — the pure part of
/// [`probe_dir`], unit-tested without touching process env.
fn default_probe_dir(local: std::ffi::OsString) -> PathBuf {
    PathBuf::from(local)
        .join("com.o365serveronms.zalors")
        .join("shadow")
}

/// The file set copied for one probe: `<account>.db` + `-wal`/`-shm`
/// (when present) + `<account>.key` + the batch-18 mode files
/// (`default.keymode.json`, `default.pass.dpapi`) when present. The
/// KQ10 account helpers own the names — nothing here hardcodes
/// "default". A passphrase-mode store opens through its remember file
/// or refuses clearly (see [`open_at`]).
fn live_set(dir: &Path) -> Vec<PathBuf> {
    let db = super::db_file(dir);
    let mut out = vec![db.clone()];
    for suffix in ["-wal", "-shm"] {
        let name = format!("{}{suffix}", db.file_name().unwrap().to_string_lossy());
        out.push(dir.join(name));
    }
    out.push(super::key_file(dir));
    out.push(super::keymode_file(dir));
    out.push(super::pass_dpapi_file(dir));
    out
}

/// The structural guarantee behind E4: everything this module opens is
/// a fresh child of the OS temp dir, never the live store.
fn assert_is_temp_copy(tmp: &Path) {
    assert!(
        tmp.starts_with(std::env::temp_dir()),
        "probe copy must live under the OS temp dir"
    );
    assert_ne!(tmp, probe_dir(), "probe copy must never be the live dir");
}

/// Copy the live set into a fresh `zr-probe-<pid>-<ms>-<seq>` dir under
/// the OS temp dir (same uniqueness pattern as `golden::open_oracle`:
/// pid+ms alone collided with parallel tests) and return the dir. The
/// copy is left on disk.
///
/// Batch 7 G5 (KQ8): the copy step is split from the dir choice so the
/// Roaming misplaced store can be copied the same way — see
/// [`copy_live_set_from`].
pub fn copy_live_set() -> PathBuf {
    copy_live_set_from(&probe_dir())
}

/// [`copy_live_set`] for an EXPLICIT store dir — used by the KQ8 replay
/// (`maint_replay.rs`) to copy the misplaced Roaming store. The temp
/// assertion still runs: a caller passing the live dir by accident gets
/// a fresh COPY under the OS temp dir, never a handle on the source.
pub fn copy_live_set_from(dir: &Path) -> PathBuf {
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let tmp = std::env::temp_dir().join(format!(
        "zr-probe-{}-{}-{}",
        std::process::id(),
        super::schema::now_ms(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&tmp).unwrap();
    assert_is_temp_copy(&tmp);
    assert_ne!(tmp, dir, "probe copy must never be the source dir");
    for from in live_set(dir) {
        if !from.exists() {
            continue; // -wal/-shm are absent on a checkpointed store
        }
        let to = tmp.join(from.file_name().unwrap());
        std::fs::copy(&from, &to).unwrap();
        // Copies can inherit a read-only attribute (the frozen oracle
        // dir has one); clear it so SQLite can use the temp -shm.
        let mut perm = std::fs::metadata(&to).unwrap().permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perm.set_readonly(false);
        std::fs::set_permissions(&to, perm).unwrap();
    }
    tmp
}

fn open_at(tmp: &Path, readonly: bool) -> Connection {
    // Batch 18: whichever mode the copied store is in — raw through the
    // copied key file, passphrase through the copied remember file. A
    // passphrase-mode store WITHOUT a usable remember file refuses with
    // the documented message (R4); the CLI/probe side never asks for a
    // password.
    match super::passphrase::open_store(tmp, readonly) {
        Ok((conn, _)) => conn,
        Err(super::passphrase::StoreOpenError::Locked) => {
            panic!(
                "the store is password-protected (passphrase mode) — unlock it in the app with \
                 'Nhớ trên máy này' (remember on this machine) enabled, then re-run this probe; \
                 the CLI never accepts passwords"
            );
        }
        Err(super::passphrase::StoreOpenError::Other(k)) => {
            panic!("store open failed ({k}) — not a shadow store dir, or a broken one?")
        }
    }
}

/// Open a COPY of the live DB read-only. Returns the connection plus
/// the temp dir holding the copy (left on disk).
pub fn open_copy() -> (Connection, PathBuf) {
    let tmp = copy_live_set();
    (open_at(&tmp, true), tmp)
}

/// Open a COPY of the live DB read-WRITE — maintenance probes only
/// (E4: `repair_v1` on a copy). The temp-copy assertion makes it
/// impossible for this helper to hand out a live-path connection.
pub fn open_copy_rw() -> (Connection, PathBuf) {
    let tmp = copy_live_set();
    assert_is_temp_copy(&tmp);
    (open_at(&tmp, false), tmp)
}

/// Open a COPY of an EXPLICIT store dir (batch 7 G5/KQ8): the misplaced
/// Roaming store read-only as the replay SOURCE, or any store copy
/// read-write. Same guarantee as [`open_copy`]/[`open_copy_rw`] — the
/// connection is on a temp copy, never on `dir`.
pub fn open_copy_from(dir: &Path, readonly: bool) -> (Connection, PathBuf) {
    let tmp = copy_live_set_from(dir);
    assert_is_temp_copy(&tmp);
    (open_at(&tmp, readonly), tmp)
}

/// The `raw_events` id baseline for coverage probes (`ZR_PROBE_SINCE_ID`;
/// default 0 = the whole ring; an unparsable value falls back to 0 —
/// coverage must never silently skip rows).
pub fn since_id() -> i64 {
    parse_since(std::env::var("ZR_PROBE_SINCE_ID").ok().as_deref())
}

/// The pure part of [`since_id`], unit-tested without touching process env.
fn parse_since(raw: Option<&str>) -> i64 {
    raw.and_then(|s| s.trim().parse::<i64>().ok()).unwrap_or(0)
}

/// The epoch-ms cut for the time-scoped integrity block (Q6, batch 17;
/// `ZR_PROBE_SINCE_MS`). 0 (unset, unparsable or non-positive) means
/// "no second block" — an epoch-ms cut at or before 1970 is never a
/// meaningful acceptance boundary.
pub fn since_ms() -> i64 {
    parse_since_ms(std::env::var("ZR_PROBE_SINCE_MS").ok().as_deref())
}

/// The pure part of [`since_ms`], unit-tested without touching process env.
fn parse_since_ms(raw: Option<&str>) -> i64 {
    let v = raw
        .and_then(|s| s.trim().parse::<i64>().ok())
        .unwrap_or(0);
    if v <= 0 {
        0
    } else {
        v
    }
}

/// Time-scoped integrity counters (Q6, batch 17): the audit 1.2
/// acceptance fields restricted to messages FIRST WRITTEN at/after the
/// cut, so old rows from the soak build cannot dominate the verdict.
///
/// **There is no first-write column.** `messages` (schema.rs DDL) has no
/// created_at/inserted_at, and `writer::apply` stamps no write time on a
/// message row — the only `now_ms()` stamps go to `raw_events.ts`,
/// `message_revisions.ts` and `conversations.updated_at`, none of which
/// link back to a message's first write. The best available proxy is
/// **`messages.ts`**: the event time from the wire payload, set on the
/// first insert and frozen afterwards by the upsert
/// (`ts = COALESCE(messages.ts, excluded.ts)`), so for capture/e2ee
/// rows it equals the arrival time within seconds. Documented caveat:
/// `source='import'` rows carry their ORIGINAL historical ts (written
/// now, ts in the past), so a since-cut excludes them even when they
/// were just written — import-cleanliness must be judged from the
/// import's own dry-run census, not from this block.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct TimeScopedIntegrity {
    pub messages: i64,
    pub self_sent: i64,
    pub self_sent_sender_null: i64,
    pub msgs_without_conv_row: i64,
    pub sender_null_total: i64,
    /// msgType string + count (msgType labels are shape-safe).
    pub type_100_by_msg_type: Vec<(String, i64)>,
}

/// `type=100` census by payload msgType string, scoped to the cut
/// (pure; msgType labels are shape-safe). Empty when the query fails.
fn type_100_by_msg_type(conn: &Connection, since_ms: i64) -> Vec<(String, i64)> {
    let Ok(mut st) = conn.prepare(
        "SELECT COALESCE(json_extract(payload_json,'$.msgType'),'<none>'), COUNT(*) \
         FROM messages WHERE type = 100 AND ts >= ?1 \
         GROUP BY 1 ORDER BY 2 DESC, 1",
    ) else {
        return Vec::new();
    };
    st.query_map([since_ms], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?))
    })
    .map(|it| it.filter_map(Result::ok).collect())
    .unwrap_or_default()
}

/// Aggregate the time-scoped integrity counters (pure; the cut is
/// inclusive: `ts >= since_ms`).
pub fn integrity_since(conn: &Connection, since_ms: i64) -> TimeScopedIntegrity {
    let q = |sql: &str| -> i64 {
        conn.query_row(sql, [since_ms], |r| r.get(0))
            .unwrap_or(-1)
    };
    TimeScopedIntegrity {
        messages: q("SELECT COUNT(*) FROM messages WHERE ts >= ?1"),
        self_sent: q(
            "SELECT COUNT(*) FROM messages \
             WHERE ts >= ?1 AND json_extract(payload_json,'$.uidFrom')='0'",
        ),
        self_sent_sender_null: q(
            "SELECT COUNT(*) FROM messages \
             WHERE ts >= ?1 AND json_extract(payload_json,'$.uidFrom')='0' \
               AND sender_id IS NULL",
        ),
        msgs_without_conv_row: q(
            "SELECT COUNT(*) FROM messages m \
             WHERE m.ts >= ?1 \
               AND NOT EXISTS (SELECT 1 FROM conversations c WHERE c.id = m.conv_id)",
        ),
        sender_null_total: q(
            "SELECT COUNT(*) FROM messages WHERE ts >= ?1 AND sender_id IS NULL",
        ),
        type_100_by_msg_type: type_100_by_msg_type(conn, since_ms),
    }
}

/// The `== integrity since <ms> ==` block both probes print (shape
/// only; msgType strings are allowed). The proxy line documents WHY
/// the cut is `messages.ts` — there is no first-write column.
pub fn print_integrity_since(conn: &Connection, since_ms: i64) {
    let i = integrity_since(conn, since_ms);
    println!(
        "  proxy: messages has no first-write column; the cut is messages.ts \
(frozen at first write; import rows carry historical ts)"
    );
    println!(
        "  messages={} self_sent={} self_sent_sender_null={} sender_null_total={} msgs_without_conv_row={}",
        i.messages, i.self_sent, i.self_sent_sender_null, i.sender_null_total,
        i.msgs_without_conv_row
    );
    let t100: Vec<String> = i
        .type_100_by_msg_type
        .iter()
        .map(|(mt, n)| format!("{mt}={n}"))
        .collect();
    println!("  type_100_by_msgType: {}", t100.join(" "));
}

/// sha256 hex of `s`, first 12 chars — the probe-safe id fingerprint.
pub fn h12(s: &str) -> String {
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    let hex = format!("{:x}", h.finalize());
    hex.chars().take(12).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Pure parts only (E0): h12 + env parsing + name derivation. The
    // copy itself is exercised by the ignored probes on real data.

    #[test]
    fn h12_known_vectors_and_shape() {
        // sha256("abc")  = ba7816bf8f01cfea4141…
        // sha256("")     = e3b0c44298fc1c14…
        assert_eq!(h12("abc"), "ba7816bf8f01");
        assert_eq!(h12(""), "e3b0c44298fc");
        // Always exactly 12 lowercase hex chars; never equal for
        // different inputs.
        for s in ["x", "fake-msg-id", "1234567890123456789"] {
            let h = h12(s);
            assert_eq!(h.len(), 12, "{s:?}");
            assert!(h.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
        }
        assert_ne!(h12("a"), h12("b"));
    }

    #[test]
    fn parse_since_shapes() {
        assert_eq!(parse_since(None), 0);
        assert_eq!(parse_since(Some("0")), 0);
        assert_eq!(parse_since(Some("42")), 42);
        assert_eq!(parse_since(Some(" -7 ")), -7, "trimmed");
        // Unparsable/empty fall back to 0 (scan the whole ring).
        assert_eq!(parse_since(Some("")), 0);
        assert_eq!(parse_since(Some("abc")), 0);
        assert_eq!(parse_since(Some("12x3")), 0);
    }

    #[test]
    fn parse_since_ms_shapes() {
        // Q6: unset / unparsable / non-positive all disable the block.
        assert_eq!(parse_since_ms(None), 0);
        assert_eq!(parse_since_ms(Some("")), 0);
        assert_eq!(parse_since_ms(Some("abc")), 0);
        assert_eq!(parse_since_ms(Some("0")), 0);
        assert_eq!(parse_since_ms(Some("-5")), 0);
        // A real epoch-ms cut survives, trimmed or not.
        assert_eq!(parse_since_ms(Some("1795123456000")), 1_795_123_456_000);
        assert_eq!(parse_since_ms(Some(" 1795123456000 ")), 1_795_123_456_000);
    }

    #[test]
    fn integrity_since_counts_only_rows_at_or_after_the_cut() {
        // Q6: a synthetic store with rows on BOTH sides of the cut.
        use crate::migrate::sqlcipher as sc;
        let key = sc::generate_key().unwrap();
        let conn = sc::open_in_memory(&key).unwrap();
        super::super::schema::apply(&conn).unwrap();

        let msg = |id: &str, conv: &str, sender: Option<&str>, ts: i64, typ: i64, uid_from: &str| {
            conn.execute(
                "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, rev, deleted, source)
                 VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, 0, 0, 'capture')",
                rusqlite::params![
                    id,
                    conv,
                    sender,
                    ts,
                    typ,
                    format!(r#"{{"msgId":"{id}","uidFrom":"{uid_from}","ts":{ts},"msgType":"text","content":"x"}}"#)
                ],
            )
            .unwrap();
        };
        let cut = 1_000_000i64;
        // OLD side (before the cut): a self-sent row stuck at sender
        // NULL, an unknown-msgType type=100 row, and an orphan conv.
        msg("old_self", "cOld", None, cut - 1000, 1, "0");
        msg("old_100", "cOld", Some("u1"), cut - 500, 100, "u1");
        msg("old_orphan", "cMissing", Some("u1"), cut - 100, 1, "u1");
        // NEW side (at/after the cut): a clean row, a self-sent row
        // with the sender RESOLVED, and one new unknown-msgType row.
        msg("new_ok", "cNew", Some("u2"), cut, 1, "u2");
        msg("new_self", "cNew", Some("me"), cut + 1000, 1, "0");
        msg("new_100", "cNew", Some("u2"), cut + 2000, 100, "u2");
        for c in ["cOld", "cNew"] {
            conn.execute(
                "INSERT INTO conversations (id, type, unread, updated_at) VALUES (?1, 0, 0, 1)",
                [c],
            )
            .unwrap();
        }

        let i = super::integrity_since(&conn, cut);
        // Only the new side counts, and the cut is inclusive.
        assert_eq!(i.messages, 3);
        assert_eq!(i.self_sent, 1, "new_self only; old_self is behind the cut");
        assert_eq!(i.self_sent_sender_null, 0, "new_self has its sender resolved");
        assert_eq!(i.sender_null_total, 0);
        assert_eq!(i.msgs_without_conv_row, 0, "cNew exists; the cMissing orphan is old");
        assert_eq!(
            i.type_100_by_msg_type,
            vec![("text".to_string(), 1)],
            "only new_100 lands in the scoped type=100 census"
        );

        // Sanity both ways: the old side alone, via a cut above every
        // new row, counts nothing…
        let above = super::integrity_since(&conn, cut + 10_000);
        assert_eq!(above.messages, 0);
        assert_eq!(above.type_100_by_msg_type, Vec::new());
        // …and a cut below everything equals a whole-store count.
        let all = super::integrity_since(&conn, 1);
        assert_eq!(all.messages, 6);
        assert_eq!(all.self_sent, 2);
        assert_eq!(all.self_sent_sender_null, 1, "old_self");
        assert_eq!(all.msgs_without_conv_row, 1, "old_orphan");
        assert_eq!(all.sender_null_total, 1);
        assert_eq!(
            all.type_100_by_msg_type,
            vec![("text".to_string(), 2)],
            "old_100 + new_100"
        );
    }

    #[test]
    fn default_probe_dir_is_the_documented_path() {
        assert_eq!(
            default_probe_dir(std::ffi::OsString::from(r"C:\Users\u\AppData\Local")),
            PathBuf::from(r"C:\Users\u\AppData\Local\com.o365serveronms.zalors\shadow")
        );
    }

    #[test]
    fn live_set_names_follow_the_account_helpers() {
        // Pure: the copy set is exactly db + -wal + -shm + key + the two
        // batch-18 mode files as the KQ10 account helpers name them (the
        // marker/remember entries are skipped at copy time when absent).
        let dir = Path::new(r"D:\shadow");
        assert_eq!(
            live_set(dir),
            vec![
                super::super::db_file(dir),
                dir.join("default.db-wal"),
                dir.join("default.db-shm"),
                super::super::key_file(dir),
                super::super::keymode_file(dir),
                super::super::pass_dpapi_file(dir),
            ]
        );
    }

    #[test]
    fn copy_live_set_from_copies_an_explicit_dir_under_temp() {
        // A FAKE store (opaque bytes), never a real one: the KQ8 replay
        // copies the Roaming dir the same way the probes copy the live
        // dir, and this checks the mechanics without touching it.
        let fake = std::env::temp_dir().join(format!(
            "zr-fake-store-{}-{}",
            std::process::id(),
            super::super::schema::now_ms()
        ));
        let _ = std::fs::remove_dir_all(&fake);
        std::fs::create_dir_all(&fake).unwrap();
        std::fs::write(super::super::db_file(&fake), b"opaque-bytes-db").unwrap();
        std::fs::write(fake.join("default.db-wal"), b"opaque-bytes-wal").unwrap();
        std::fs::write(super::super::key_file(&fake), b"opaque-bytes-key").unwrap();

        let tmp = copy_live_set_from(&fake);
        assert!(tmp.starts_with(std::env::temp_dir()));
        assert_ne!(tmp, fake);
        assert_eq!(
            std::fs::read(tmp.join("default.db")).unwrap(),
            b"opaque-bytes-db"
        );
        assert_eq!(
            std::fs::read(tmp.join("default.db-wal")).unwrap(),
            b"opaque-bytes-wal"
        );
        // -wal/-shm present in the source are copied; -shm absent here.
        assert!(!tmp.join("default.db-shm").exists());
        assert_eq!(
            std::fs::read(tmp.join("default.key")).unwrap(),
            b"opaque-bytes-key"
        );
        std::fs::remove_dir_all(&tmp).unwrap();
        std::fs::remove_dir_all(&fake).unwrap();
    }
}
