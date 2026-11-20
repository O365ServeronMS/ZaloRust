//! Shadow DB schema v2 — mirrored from `D:\.opencode\zalo-shadow-schema-v1.sql`
//! (the SQL file is the spec of record for v1; the v2 additions below
//! live only here — the worktree must not touch files outside it).
//!
//! Principles (unchanged from the lost implementation):
//! - Idempotent upserts keyed by server ids; keep `raw_json` of every row.
//! - `raw_events` is a ring buffer (7-day retention by default, D4).
//! - The DB file itself is SQLCipher-encrypted; encryption is an
//!   application-layer decision (D2), invisible to this module.
//!
//! v1 → v2 (batch 9, audit KQ5 / §4 Phase 3 item 3.1): a contentless
//! FTS5 mirror `messages_fts(body)` of `messages.text`, kept in sync
//! by three triggers, so the index is written inside the writer's own
//! transaction and can never drift from the table. The tokenizer is
//! `unicode61 remove_diacritics 2`: Vietnamese tone marks (and the
//! ơ/ư horns) fold away at tokenize time, but **đ/Đ is a distinct
//! letter, not a diacritic** — the indexed text is therefore
//! `fold(text) = replace(replace(lower(text),'đ','d'),'Đ','d')`
//! (SQLite `lower()` is ASCII-only; `unicode61` itself case-folds).
//! Recall/deleted messages keep the indexed text as stored by the
//! writer (no special case): the FTS row always mirrors
//! `messages.text`, whatever the writer decided that is.
//!
//! Upgrade: an existing v1 DB (schema_meta MAX(version) == 1) is
//! backfilled ONCE inside one migration transaction
//! ([`FTS_BACKFILL`]); a fresh DB gets the table + triggers from the
//! DDL and stamps v2 directly (nothing to backfill). `schema_meta`
//! keeps one row per applied version — `MAX(version)` is current.

use rusqlite::Connection;

/// Schema version stamped into `schema_meta` (one row per version;
/// the current one is `MAX(version)`).
///
/// v2 (batch 9): `messages_fts` + sync triggers (KQ5).
pub const VERSION: i64 = 2;

/// Complete DDL for a fresh shadow DB. `IF NOT EXISTS` everywhere so the
/// same script applies idempotently on every open.
pub const DDL: &str = r#"
CREATE TABLE IF NOT EXISTS schema_meta (
  version    INTEGER NOT NULL,
  applied_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS accounts (
  id           TEXT PRIMARY KEY,          -- userId
  uin_hash     TEXT NOT NULL,             -- sha256(UIN)[:12], không lưu plaintext
  display_name TEXT,
  created_at   INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS conversations (
  id         TEXT PRIMARY KEY,            -- convId (private: userId, group: groupId)
  type       INTEGER NOT NULL,            -- 0 private, 1 group
  title      TEXT,
  avatar_url TEXT,
  last_msg_id TEXT,
  last_ts    INTEGER,
  unread     INTEGER NOT NULL DEFAULT 0,
  raw_json   TEXT,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS participants (
  conv_id   TEXT NOT NULL,
  user_id   TEXT NOT NULL,
  role      INTEGER,
  joined_ts INTEGER,
  raw_json  TEXT,
  PRIMARY KEY (conv_id, user_id)
);
CREATE TABLE IF NOT EXISTS messages (
  msg_id       TEXT PRIMARY KEY,          -- server message id (idempotency key)
  conv_id      TEXT NOT NULL,
  sender_id    TEXT,
  ts           INTEGER NOT NULL,
  type         INTEGER NOT NULL,
  text         TEXT,
  payload_json TEXT,                      -- toàn bộ field gốc
  rev          INTEGER NOT NULL DEFAULT 0,
  deleted      INTEGER NOT NULL DEFAULT 0,
  content_hash TEXT,
  source       TEXT NOT NULL              -- 'capture' | 'e2ee' | 'import'
);
CREATE INDEX IF NOT EXISTS idx_messages_conv_ts ON messages(conv_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_messages_ts      ON messages(ts);
CREATE TABLE IF NOT EXISTS message_revisions (
  msg_id       TEXT NOT NULL,
  rev          INTEGER NOT NULL,
  ts           INTEGER NOT NULL,
  kind         TEXT NOT NULL,             -- 'edit' | 'recall' | 'delete'
  payload_json TEXT,
  PRIMARY KEY (msg_id, rev)
);
CREATE TABLE IF NOT EXISTS attachments (
  msg_id     TEXT NOT NULL,
  idx        INTEGER NOT NULL,
  kind       TEXT,                        -- image | video | file | voice
  url        TEXT,                        -- lazy download
  local_path TEXT,                        -- RELATIVE to the media root: ab/cd/<sha> (KQ9)
  size       INTEGER,
  sha256     TEXT,
  status     TEXT NOT NULL DEFAULT 'ref', -- ref | downloaded | failed | ref-encrypted (B4/KQ1)
  PRIMARY KEY (msg_id, idx)
);
CREATE TABLE IF NOT EXISTS contacts (
  user_id      TEXT PRIMARY KEY,
  display_name TEXT,
  phone_hash   TEXT,                      -- không lưu số thô
  avatar_url   TEXT,
  raw_json     TEXT,
  updated_at   INTEGER
);
CREATE TABLE IF NOT EXISTS groups (
  group_id   TEXT PRIMARY KEY,
  name       TEXT,
  members_json TEXT,
  raw_json   TEXT,
  updated_at INTEGER
);
CREATE TABLE IF NOT EXISTS reactions (
  msg_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  emoji  TEXT NOT NULL,
  ts     INTEGER,
  PRIMARY KEY (msg_id, user_id)
);
CREATE TABLE IF NOT EXISTS sync_cursors (
  scope      TEXT PRIMARY KEY,            -- 'conv:<id>' | 'global'
  cursor     TEXT,                       -- msgId/timestamp cuối
  updated_at INTEGER
);
CREATE TABLE IF NOT EXISTS raw_events (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  ts           INTEGER NOT NULL,
  direction    TEXT,                      -- 'in' | 'out'
  kind         TEXT,                      -- 'rest' | 'ws'
  endpoint     TEXT,
  payload_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_raw_ts ON raw_events(ts);
-- v2 (KQ5): contentless FTS5 mirror of messages.text. contentless =>
-- no duplicate content copy; contentless_delete=1 (SQLite >= 3.43,
-- build verified by tests::fts5_is_compiled_in in search.rs) lets the
-- triggers delete by rowid. Folding: remove_diacritics 2 strips the
-- tone marks but NOT đ/Đ (a distinct letter), hence the explicit
-- đ/Đ -> d replace around the ASCII-only lower().
CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
  body,
  content='',
  contentless_delete=1,
  tokenize='unicode61 remove_diacritics 2'
);
CREATE TRIGGER IF NOT EXISTS messages_fts_ai AFTER INSERT ON messages
WHEN new.text IS NOT NULL AND new.text <> ''
BEGIN
  INSERT INTO messages_fts(rowid, body)
  VALUES (new.rowid, replace(replace(lower(new.text),'đ','d'),'Đ','d'));
END;
CREATE TRIGGER IF NOT EXISTS messages_fts_au AFTER UPDATE OF text ON messages
BEGIN
  DELETE FROM messages_fts WHERE rowid = old.rowid;
  INSERT INTO messages_fts(rowid, body)
    SELECT new.rowid, replace(replace(lower(new.text),'đ','d'),'Đ','d')
    WHERE new.text IS NOT NULL AND new.text <> '';
END;
CREATE TRIGGER IF NOT EXISTS messages_fts_ad AFTER DELETE ON messages
BEGIN
  DELETE FROM messages_fts WHERE rowid = old.rowid;
END;
"#;

/// v1 → v2 upgrade (batch 9 I2): backfill the FTS mirror ONCE from the
/// messages a v1 DB already holds. Runs inside the migration
/// transaction, directly into `messages_fts` (no triggers involved);
/// the triggers created by the DDL keep everything in sync afterwards.
/// Fresh DBs never run this (no rows to index).
pub const FTS_BACKFILL: &str = "
INSERT INTO messages_fts(rowid, body)
SELECT rowid, replace(replace(lower(text),'đ','d'),'Đ','d')
FROM messages
WHERE text IS NOT NULL AND text <> '';
";

/// Apply the DDL on `conn`, then bring an older schema up to
/// [`VERSION`] through the `schema_meta` mechanism (one row per
/// applied version; `MAX(version)` is current):
/// - fresh DB → the DDL creates everything, `MAX(version)` == 0 stamps
///   [`VERSION`] directly (nothing to backfill);
/// - v1 DB → one `BEGIN IMMEDIATE` transaction creates the FTS
///   objects via the DDL, backfills [`FTS_BACKFILL`] and stamps v2 —
///   everything lands together or nothing does;
/// - a DB already at (or above) [`VERSION`] is untouched.
///
/// Safe to call on every open (idempotent).
pub fn apply(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA foreign_keys = ON;",
    )?;
    conn.execute_batch(DDL)?;
    let cur: i64 = conn
        .query_row("SELECT MAX(version) FROM schema_meta", [], |r| r.get(0))
        .unwrap_or(0);
    if cur < VERSION {
        // One transaction: backfill + version stamp land together.
        // (A v1 DB is upgraded in place; a fresh DB — cur == 0 — only
        // stamps, the backfill of an empty messages table is a no-op
        // it does not need.)
        conn.execute_batch("BEGIN IMMEDIATE")?;
        let migrated = (|| -> rusqlite::Result<()> {
            if cur >= 1 {
                conn.execute_batch(FTS_BACKFILL)?;
            }
            conn.execute(
                "INSERT INTO schema_meta (version, applied_at) VALUES (?1, ?2)",
                rusqlite::params![VERSION, now_ms()],
            )?;
            Ok(())
        })();
        match migrated {
            Ok(()) => conn.execute_batch("COMMIT")?,
            Err(e) => {
                // The migration is gone: roll back and surface the
                // error (fail-closed — the caller must not run with a
                // half-upgraded schema).
                let _ = conn.execute_batch("ROLLBACK");
                return Err(e);
            }
        }
    }
    Ok(())
}

pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrate::sqlcipher;

    #[test]
    fn apply_twice_is_idempotent() {
        let key = sqlcipher::generate_key().unwrap();
        let conn = sqlcipher::open_in_memory(&key).unwrap();
        apply(&conn).unwrap();
        apply(&conn).unwrap();
        let v: i64 = conn
            .query_row("SELECT MAX(version) FROM schema_meta", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, VERSION);
        // A fresh DB stamps exactly one row (the current version).
        let rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema_meta", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 1);
        // 12 v1 objects + the v2 FTS mirror: the virtual table plus
        // its 4 shadow tables (_data, _idx, _docsize, _config).
        let tables: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(tables, 17, "schema_meta + 11 domain tables + messages_fts + 4 fts shadow tables");
        // The v2 objects exist and the triggers are the schema's own.
        let triggers: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name LIKE 'messages_fts_%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(triggers, 3, "ai + au + ad");
    }

    #[test]
    fn fresh_db_stamps_v2_with_no_backfill() {
        let key = sqlcipher::generate_key().unwrap();
        let conn = sqlcipher::open_in_memory(&key).unwrap();
        apply(&conn).unwrap();
        // Nothing indexed yet…
        let fts: i64 = conn
            .query_row("SELECT COUNT(*) FROM messages_fts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(fts, 0);
        // …but a message written after the fact is indexed by the
        // trigger with the documented folding (proven through MATCH —
        // a contentless table's body column cannot be read back).
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, source)
             VALUES ('m1', 'c1', 'u1', 1, 1, 'Đường về Hà Nội', '{}', 'capture')",
            [],
        )
        .unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM messages_fts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
        let hits = super::super::search::search(&conn, "duong ve ha noi", 10).unwrap();
        assert_eq!(hits.len(), 1, "đ→d + ASCII lower(); tone marks strip at tokenize time");
        assert_eq!(hits[0].msg_id, "m1");
    }

    /// Hand-built v1 DB (pre-FTS): messages + a v1 `schema_meta` row.
    /// The messages DDL is copied verbatim from the const above — the
    /// point is that `apply` upgrades it in place.
    fn v1_db_with_rows() -> Connection {
        let key = sqlcipher::generate_key().unwrap();
        let conn = sqlcipher::open_in_memory(&key).unwrap();
        conn.execute_batch(
            "CREATE TABLE schema_meta (version INTEGER NOT NULL, applied_at INTEGER NOT NULL);
             CREATE TABLE messages (
               msg_id       TEXT PRIMARY KEY,
               conv_id      TEXT NOT NULL,
               sender_id    TEXT,
               ts           INTEGER NOT NULL,
               type         INTEGER NOT NULL,
               text         TEXT,
               payload_json TEXT,
               rev          INTEGER NOT NULL DEFAULT 0,
               deleted      INTEGER NOT NULL DEFAULT 0,
               content_hash TEXT,
               source       TEXT NOT NULL
             );
             INSERT INTO schema_meta (version, applied_at) VALUES (1, 1);
             INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, source) VALUES
               ('m1', 'c1', 'u1', 1, 1, 'Hà Nội có phố cổ', '{}', 'capture'),
               ('m2', 'c1', 'u1', 2, 1, NULL, '{}', 'capture'),
               ('m3', 'c1', 'u1', 3, 1, '', '{}', 'capture'),
               ('m4', 'c1', 'u1', 4, 1, 'đường lên bản nhỏ', '{}', 'capture');",
        )
        .unwrap();
        conn
    }

    #[test]
    fn upgrade_from_v1_backfills_fts_once() {
        let conn = v1_db_with_rows();
        apply(&conn).unwrap();
        // Both version rows exist; MAX is current.
        let (max_v, v1_rows, v2_rows): (i64, i64, i64) = conn
            .query_row(
                "SELECT MAX(version),
                        (SELECT COUNT(*) FROM schema_meta WHERE version = 1),
                        (SELECT COUNT(*) FROM schema_meta WHERE version = 2)
                 FROM schema_meta",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!((max_v, v1_rows, v2_rows), (VERSION, 1, 1));
        // The backfill indexed exactly the non-empty texts (NULL and
        // '' are skipped, per the trigger WHEN clauses too).
        let fts: i64 = conn
            .query_row("SELECT COUNT(*) FROM messages_fts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(fts, 2, "m1, m4 — never the NULL or '' rows");
        // Search (the v2 feature) works over the backfilled rows —
        // diacritics-insensitive, đ→d.
        let hits = super::super::search::search(&conn, "ha noi", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].msg_id, "m1");
        let hits = super::super::search::search(&conn, "duong", 10).unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].msg_id, "m4");
        // Re-apply: nothing new (no second stamp, no duplicate rows).
        apply(&conn).unwrap();
        let (fts2, v2_rows2): (i64, i64) = conn
            .query_row(
                "SELECT (SELECT COUNT(*) FROM messages_fts),
                        (SELECT COUNT(*) FROM schema_meta WHERE version = 2)",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((fts2, v2_rows2), (2, 1));
        // And the triggers keep the upgraded DB in sync afterwards.
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, source)
             VALUES ('m5', 'c1', 'u1', 5, 1, 'tin mới', '{}', 'capture')",
            [],
        )
        .unwrap();
        let fts3: i64 = conn
            .query_row("SELECT COUNT(*) FROM messages_fts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(fts3, 3);
    }

    #[test]
    fn a_future_version_is_never_downgraded() {
        // A DB stamped with a HIGHER version (opened by older code)
        // must not be touched: no stamp, no backfill.
        let key = sqlcipher::generate_key().unwrap();
        let conn = sqlcipher::open_in_memory(&key).unwrap();
        conn.execute_batch(
            "CREATE TABLE schema_meta (version INTEGER NOT NULL, applied_at INTEGER NOT NULL);
             INSERT INTO schema_meta (version, applied_at) VALUES (99, 1);",
        )
        .unwrap();
        apply(&conn).unwrap();
        let (max_v, rows): (i64, i64) = conn
            .query_row(
                "SELECT MAX(version), COUNT(*) FROM schema_meta",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((max_v, rows), (99, 1), "no v2 stamp beside the future one");
    }
}
