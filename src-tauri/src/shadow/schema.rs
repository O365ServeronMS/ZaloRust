//! Shadow DB schema v1 — mirrored from `D:\.opencode\zalo-shadow-schema-v1.sql`
//! (the SQL file is the spec of record; keep both in sync).
//!
//! Principles (unchanged from the lost implementation):
//! - Idempotent upserts keyed by server ids; keep `raw_json` of every row.
//! - `raw_events` is a ring buffer (7-day retention by default, D4).
//! - The DB file itself is SQLCipher-encrypted; encryption is an
//!   application-layer decision (D2), invisible to this module.

use rusqlite::Connection;

/// Schema version stamped into `schema_meta` on creation.
pub const VERSION: i64 = 1;

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
"#;

/// Apply the DDL on `conn` and stamp `schema_meta` for a fresh DB.
/// Safe to call on every open (idempotent).
pub fn apply(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA foreign_keys = ON;",
    )?;
    conn.execute_batch(DDL)?;
    let n: i64 = conn.query_row(
        "SELECT COUNT(*) FROM schema_meta WHERE version = ?1",
        [VERSION],
        |r| r.get(0),
    )?;
    if n == 0 {
        conn.execute(
            "INSERT INTO schema_meta (version, applied_at) VALUES (?1, ?2)",
            rusqlite::params![VERSION, now_ms()],
        )?;
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
            .query_row("SELECT version FROM schema_meta", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, VERSION);
        let tables: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(tables, 12, "schema_meta + 11 domain tables in schema v1");
    }
}
