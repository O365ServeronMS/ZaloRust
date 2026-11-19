//! Own-account identity for the shadow DB (audit §4 item 1.4 / KQ2).
//!
//! The own uid is a CONFIGURATION decision (D18): the bridge's
//! DI-token probing (`MC.resolveToken(...)`) never hit in practice and
//! was an A2 page-behaviour risk, so the flusher seeds the uid from
//! `settings.shadow.own_uid` and treats the handshake's learned uid
//! only as a cross-check (a mismatch is logged once, never applied).
//!
//! H-rule: nothing here logs or stores a uid value — shapes and
//! lengths only. The `accounts` row stores the uid (row id) plus the
//! uin_hash fingerprint (sha256 of the UIN, first 12 hex chars) — the
//! UIN itself is never stored, and a hash is never invented (KQ2).

use rusqlite::Connection;

use super::schema;

/// A Zalo userId shape: ASCII digits, length 5..=32 (D18's real uid is
/// 19 digits; the window tolerates the observed shape range).
pub fn valid_uid(uid: &str) -> bool {
    (5..=32).contains(&uid.len()) && uid.bytes().all(|b| b.is_ascii_digit())
}

/// A uin_hash shape: exactly 12 lowercase hex chars
/// (`sha256(UIN)[:12]` as the audit measured it).
pub fn valid_uin_hash(hash: &str) -> bool {
    hash.len() == 12
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// What the flusher should do after one handshake uid resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UidEvent {
    /// The effective uid did not change.
    Same,
    /// Nothing valid was configured: a valid learned uid was adopted
    /// (today's behaviour, kept for unconfigured installs).
    Learned,
    /// A configured uid stays authoritative while the handshake
    /// offered a valid, different one — logged once per process, the
    /// configured value is never replaced.
    Mismatch,
}

/// Decide the flusher's own-uid after one handshake (pure; KQ2):
/// - a VALID configured uid ALWAYS wins — the learned uid only
///   cross-checks (`Mismatch` when it validly differs);
/// - a configured uid that fails the shape check behaves as absent
///   (the flusher already logged the rejection at start);
/// - with nothing configured, a valid learned uid is adopted
///   (today's behaviour); an invalid or equal one changes nothing.
pub fn resolve_own_uid(
    configured: Option<&str>,
    current: Option<&str>,
    learned: Option<&str>,
) -> (Option<String>, UidEvent) {
    if let Some(c) = configured.filter(|c| valid_uid(c)) {
        let mismatch = learned
            .filter(|l| valid_uid(l))
            .is_some_and(|l| l != c);
        let ev = if mismatch { UidEvent::Mismatch } else { UidEvent::Same };
        return (Some(c.to_string()), ev);
    }
    match learned.filter(|l| valid_uid(l)) {
        Some(l) if current != Some(l) => (Some(l.to_string()), UidEvent::Learned),
        _ => (current.map(str::to_string), UidEvent::Same),
    }
}

/// Fill the `accounts` row for the configured account (KQ2/KQ10):
/// the uid is the row id, `uin_hash` the only fingerprint stored. One
/// small upsert — the caller runs it inside its own transaction, once
/// per process at flusher start. `uin_hash` is validated by the caller;
/// the schema's NOT NULL is the last line of defence.
pub fn upsert_account(conn: &Connection, uid: &str, uin_hash: &str) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT INTO accounts (id, uin_hash, display_name, created_at)
         VALUES (?1, ?2, NULL, ?3)
         ON CONFLICT(id) DO UPDATE SET uin_hash = excluded.uin_hash",
        rusqlite::params![uid, uin_hash, schema::now_ms()],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FAKE uid of the documented shape (never a real one).
    const FAKE_UID: &str = "1234567890123456789";
    /// FAKE 12-hex fingerprint (never a real uin_hash).
    const FAKE_HASH: &str = "abc123def456";

    #[test]
    fn uid_shape() {
        assert!(valid_uid(FAKE_UID));
        assert!(valid_uid("12345")); // shortest
        assert!(valid_uid("9".repeat(32).as_str())); // longest
        assert!(!valid_uid("1234")); // too short
        assert!(!valid_uid("9".repeat(33).as_str())); // too long
        assert!(!valid_uid(""));
        assert!(!valid_uid("12345a")); // non-digit
        assert!(!valid_uid(" 12345")); // whitespace is not a digit
        assert!(!valid_uid("１２３４５")); // unicode digits are not ASCII
    }

    #[test]
    fn uin_hash_shape() {
        assert!(valid_uin_hash(FAKE_HASH));
        assert!(valid_uin_hash("000000000000"));
        assert!(valid_uin_hash("ffffffffffff"));
        assert!(!valid_uin_hash("ABC123DEF456")); // uppercase
        assert!(!valid_uin_hash("abc123def45")); // 11 chars
        assert!(!valid_uin_hash("abc123def4567")); // 13 chars
        assert!(!valid_uin_hash("abc123def45g")); // 'g' is not hex
        assert!(!valid_uin_hash(""));
    }

    // --- resolve_own_uid: every case ---------------------------------------

    #[test]
    fn resolve_with_nothing_configured_keeps_learning() {
        // Today's behaviour, kept: a valid learned uid is adopted.
        let (uid, ev) = resolve_own_uid(None, None, Some(FAKE_UID));
        assert_eq!((uid.as_deref(), ev), (Some(FAKE_UID), UidEvent::Learned));
        // Same uid again: no change, no event.
        let (uid, ev) = resolve_own_uid(None, Some(FAKE_UID), Some(FAKE_UID));
        assert_eq!((uid.as_deref(), ev), (Some(FAKE_UID), UidEvent::Same));
        // A different valid learned uid replaces it (page re-login).
        let (uid, ev) = resolve_own_uid(None, Some(FAKE_UID), Some("9876543210987654321"));
        assert_eq!(uid.as_deref(), Some("9876543210987654321"));
        assert_eq!(ev, UidEvent::Learned);
        // Invalid or absent learned uids change nothing.
        let (uid, ev) = resolve_own_uid(None, Some(FAKE_UID), Some("12a"));
        assert_eq!((uid.as_deref(), ev), (Some(FAKE_UID), UidEvent::Same));
        let (uid, ev) = resolve_own_uid(None, Some(FAKE_UID), None);
        assert_eq!((uid.as_deref(), ev), (Some(FAKE_UID), UidEvent::Same));
        // Everything absent stays absent.
        assert_eq!(resolve_own_uid(None, None, None), (None, UidEvent::Same));
    }

    #[test]
    fn resolve_with_configured_uid_always_keeps_it() {
        // The configured one wins, whatever the handshake says.
        let (uid, ev) = resolve_own_uid(Some(FAKE_UID), Some(FAKE_UID), None);
        assert_eq!((uid.as_deref(), ev), (Some(FAKE_UID), UidEvent::Same));
        let (uid, ev) = resolve_own_uid(Some(FAKE_UID), Some(FAKE_UID), Some(FAKE_UID));
        assert_eq!((uid.as_deref(), ev), (Some(FAKE_UID), UidEvent::Same));
        // A valid, DIFFERENT learned uid: kept + Mismatch (the flusher
        // logs that once per process).
        let (uid, ev) = resolve_own_uid(Some(FAKE_UID), Some(FAKE_UID), Some("9876543210987654321"));
        assert_eq!((uid.as_deref(), ev), (Some(FAKE_UID), UidEvent::Mismatch));
        // An invalid learned uid is not a mismatch signal.
        let (uid, ev) = resolve_own_uid(Some(FAKE_UID), Some(FAKE_UID), Some("nope"));
        assert_eq!((uid.as_deref(), ev), (Some(FAKE_UID), UidEvent::Same));
        // Mismatch is flagged even before the configured value was
        // seeded (current = None at the very first handshake).
        let (uid, ev) = resolve_own_uid(Some(FAKE_UID), None, Some("9876543210987654321"));
        assert_eq!((uid.as_deref(), ev), (Some(FAKE_UID), UidEvent::Mismatch));
    }

    #[test]
    fn resolve_treats_badly_shaped_config_as_absent() {
        // The flusher logged the rejection at start; resolution then
        // behaves as unconfigured (a valid learned uid is adopted).
        let (uid, ev) = resolve_own_uid(Some("bad-shape"), None, Some(FAKE_UID));
        assert_eq!((uid.as_deref(), ev), (Some(FAKE_UID), UidEvent::Learned));
        let (uid, ev) = resolve_own_uid(Some(""), None, None);
        assert_eq!((uid.as_deref(), ev), (None, UidEvent::Same));
    }

    // --- accounts upsert ---------------------------------------------------

    #[test]
    fn upsert_account_inserts_then_updates_only_the_hash() {
        use crate::migrate::sqlcipher;
        let key = sqlcipher::generate_key().unwrap();
        let conn = sqlcipher::open_in_memory(&key).unwrap();
        super::super::schema::apply(&conn).unwrap();

        upsert_account(&conn, FAKE_UID, FAKE_HASH).unwrap();
        let (hash, name, created): (String, Option<String>, i64) = conn
            .query_row(
                "SELECT uin_hash, display_name, created_at FROM accounts WHERE id = ?1",
                [FAKE_UID],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(hash, FAKE_HASH);
        assert_eq!(name, None);
        let first_created = created;

        // Re-run (idempotent shape): only the hash moves; created_at is
        // the insert's, display_name untouched.
        upsert_account(&conn, FAKE_UID, "000000000000").unwrap();
        let (hash, name, created): (String, Option<String>, i64) = conn
            .query_row(
                "SELECT uin_hash, display_name, created_at FROM accounts WHERE id = ?1",
                [FAKE_UID],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(hash, "000000000000");
        assert_eq!(name, None);
        assert_eq!(created, first_created, "created_at must not be rewritten");
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM accounts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1, "one row per account id");
    }
}
