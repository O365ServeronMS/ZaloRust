//! Shadow DB schema v3 — v1 mirrored from `D:\.opencode\zalo-shadow-schema-v1.sql`
//! (the SQL file is the spec of record for v1; the v2/v3 additions
//! below live only here — the worktree must not touch files outside it).
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
//! DDL and stamps the current version directly (nothing to
//! backfill). `schema_meta` keeps one row per applied version —
//! `MAX(version)` is current.
//!
//! v2 → v3 (batch 10, audit follow-up to KQ5): the update trigger
//! gained a `WHEN old.text IS NOT new.text` guard. The writer's
//! upsert rewrites `text` on EVERY replay, so the unguarded `au`
//! trigger deleted + reinserted the FTS row even when the text did
//! not change — the single most common write in a capture pipeline.
//! `CREATE TRIGGER IF NOT EXISTS` cannot replace a live v2 trigger,
//! so the migration DROPs and recreates it ([`FTS_AU_V3`]); no
//! backfill is needed (the v2 mirror is already exact).

use rusqlite::Connection;

/// Schema version stamped into `schema_meta` (one row per version;
/// the current one is `MAX(version)`).
///
/// v2 (batch 9): `messages_fts` + sync triggers (KQ5).
///
/// v3 (batch 10): the `au` trigger only fires when the text really
/// changed (`WHEN old.text IS NOT new.text` — SQLite's null-safe
/// inequality, so NULL↔text transitions still re-index).
pub const VERSION: i64 = 3;

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
  status     TEXT NOT NULL DEFAULT 'ref', -- ref | downloaded | failed | ref-encrypted (B4/KQ1) | expired (M2: link gone) | ref-import (M3: import history, live thread never picks). Deliberately NO CHECK constraint — batch 26 added the two statuses without a migration or VERSION bump; SQLite has no ALTER ADD CONSTRAINT anyway, and the writer is the single status authority.
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
-- v3 (batch 10): only a REAL text change re-indexes. The writer's
-- upsert rewrites `text` on every replay; without this guard each
-- replay cost a contentless-FTS delete + insert for nothing.
-- `IS NOT` is SQLite's NULL-safe inequality: NULL -> text, text ->
-- NULL and any real edit all fire; equal text (incl. NULL = NULL)
-- does not.
WHEN old.text IS NOT new.text
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

/// v2 → v3 upgrade (batch 10): the `au` trigger gained its
/// `WHEN old.text IS NOT new.text` guard. The DDL runs before the
/// migration with `IF NOT EXISTS`, which is a no-op on a live v2
/// trigger, so the migration replaces it explicitly. No backfill:
/// the v2 mirror is already exact — re-running [`FTS_BACKFILL`]
/// would collide on existing rowids.
pub const FTS_AU_V3: &str = "
DROP TRIGGER IF EXISTS messages_fts_au;
CREATE TRIGGER messages_fts_au AFTER UPDATE OF text ON messages
WHEN old.text IS NOT new.text
BEGIN
  DELETE FROM messages_fts WHERE rowid = old.rowid;
  INSERT INTO messages_fts(rowid, body)
    SELECT new.rowid, replace(replace(lower(new.text),'đ','d'),'Đ','d')
    WHERE new.text IS NOT NULL AND new.text <> '';
END;
";

/// Apply the DDL on `conn`, then bring an older schema up to
/// [`VERSION`] through the `schema_meta` mechanism (one row per
/// applied version; `MAX(version)` is current):
/// - fresh DB → the DDL creates everything, `MAX(version)` == 0 stamps
///   [`VERSION`] directly (nothing to backfill);
/// - v1 DB → one `BEGIN IMMEDIATE` transaction creates the FTS
///   objects via the DDL, backfills [`FTS_BACKFILL`] and stamps the
///   current version — everything lands together or nothing does;
/// - v2 DB → the same transaction replaces the `au` trigger with its
///   v3 `WHEN` form ([`FTS_AU_V3`], no backfill) and stamps;
/// - a DB already at (or above) [`VERSION`] is untouched.
///
/// A pre-v2 DB jumps straight to the current version (one stamp row):
/// it was never opened at the intermediate one. Safe to call on every
/// open (idempotent).
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
        // One transaction: the version's own step + the stamp land
        // together. (A v1 DB is upgraded in place — the DDL already
        // created its FTS objects in the v3 form; a fresh DB —
        // cur == 0 — only stamps: the backfill of an empty messages
        // table is a no-op it does not need.)
        conn.execute_batch("BEGIN IMMEDIATE")?;
        let migrated = (|| -> rusqlite::Result<()> {
            match cur {
                1 => conn.execute_batch(FTS_BACKFILL)?,
                2 => conn.execute_batch(FTS_AU_V3)?,
                _ => {}
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
        // The FTS objects exist and the triggers are the schema's own.
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
    fn fresh_db_stamps_v3_with_the_guarded_au_trigger() {
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
        // v3 (batch 10): the fresh DB's au trigger is the guarded
        // form — equal text must never reach the trigger body.
        let au_sql: String = conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='trigger' AND name='messages_fts_au'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            au_sql.contains("WHEN old.text IS NOT new.text"),
            "fresh DBs get the v3 guarded trigger"
        );
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
    fn upgrade_from_v1_backfills_fts_once_and_jumps_to_v3() {
        let conn = v1_db_with_rows();
        apply(&conn).unwrap();
        // The v1 row is kept; the stamp is the CURRENT version (a v1
        // DB never paused at 2 — it was never opened there).
        let (max_v, v1_rows, v3_rows): (i64, i64, i64) = conn
            .query_row(
                "SELECT MAX(version),
                        (SELECT COUNT(*) FROM schema_meta WHERE version = 1),
                        (SELECT COUNT(*) FROM schema_meta WHERE version = 3)
                 FROM schema_meta",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!((max_v, v1_rows, v3_rows), (VERSION, 1, 1));
        // The DDL already created the v3-form trigger (nothing existed
        // to keep), so the migration only backfilled.
        let au_sql: String = conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='trigger' AND name='messages_fts_au'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(au_sql.contains("WHEN old.text IS NOT new.text"));
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
        // Re-apply: nothing new (no second stamp, no duplicate rows —
        // a v3 re-run of the v1 backfill would collide on rowids).
        apply(&conn).unwrap();
        let (fts2, v3_rows2): (i64, i64) = conn
            .query_row(
                "SELECT (SELECT COUNT(*) FROM messages_fts),
                        (SELECT COUNT(*) FROM schema_meta WHERE version = 3)",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((fts2, v3_rows2), (2, 1));
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

    /// The batch-9 v2 au trigger body, VERBATIM (the unguarded form the
    /// migration must replace). Kept here — and not in the DDL — so a
    /// future edit of the live trigger text cannot silently change
    /// what this upgrade path claims to migrate from.
    const FTS_AU_V2_BODY: &str = "
CREATE TRIGGER messages_fts_au AFTER UPDATE OF text ON messages
BEGIN
  DELETE FROM messages_fts WHERE rowid = old.rowid;
  INSERT INTO messages_fts(rowid, body)
    SELECT new.rowid, replace(replace(lower(new.text),'đ','d'),'Đ','d')
    WHERE new.text IS NOT NULL AND new.text <> '';
END;";

    /// A DB in the exact state batch 9 left it: FTS objects with the
    /// UNGUARDED au trigger, `schema_meta` rows {1, 2}, one indexed
    /// message.
    fn v2_db_with_rows() -> Connection {
        let key = sqlcipher::generate_key().unwrap();
        let conn = sqlcipher::open_in_memory(&key).unwrap();
        apply(&conn).unwrap(); // creates the FTS table + triggers…
        // …then rewind the au trigger to the batch-9 body and stamp
        // the version rows a batch-9 open would have left.
        conn.execute_batch("DROP TRIGGER messages_fts_au;").unwrap();
        conn.execute_batch(FTS_AU_V2_BODY).unwrap();
        conn.execute_batch("DELETE FROM schema_meta;").unwrap();
        conn.execute_batch(
            "INSERT INTO schema_meta (version, applied_at) VALUES (1, 1);
             INSERT INTO schema_meta (version, applied_at) VALUES (2, 2);",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, source)
             VALUES ('g1', 'c1', 'u1', 1, 1, 'đường cũ', '{}', 'capture')",
            [],
        )
        .unwrap();
        conn
    }

    #[test]
    fn upgrade_from_v2_replaces_the_au_trigger_without_backfill() {
        let conn = v2_db_with_rows();
        // The v2 shape really is the old one (guarded only by the
        // fixture, but that is exactly what a batch-9 DB holds).
        let au_sql_before: String = conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='trigger' AND name='messages_fts_au'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!au_sql_before.contains("WHEN"));
        let fts_before: i64 = conn
            .query_row("SELECT COUNT(*) FROM messages_fts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(fts_before, 1, "the ai trigger indexed the fixture row");

        apply(&conn).unwrap();
        // All three version rows exist (1 and 2 are history); MAX is 3.
        let (max_v, rows): (i64, i64) = conn
            .query_row("SELECT MAX(version), COUNT(*) FROM schema_meta", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!((max_v, rows), (VERSION, 3), "rows 1,2 kept + the v3 stamp");
        // The trigger is the guarded form now.
        let au_sql: String = conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type='trigger' AND name='messages_fts_au'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            au_sql.contains("WHEN old.text IS NOT new.text"),
            "the migration must replace, not keep, the v2 trigger"
        );
        // No backfill ran: the mirror kept its exact row (a v1-style
        // re-backfill would collide on the existing rowid).
        let fts_after: i64 = conn
            .query_row("SELECT COUNT(*) FROM messages_fts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(fts_after, fts_before);
        // …and the upgraded trigger behaves: a REAL edit re-indexes.
        conn.execute("UPDATE messages SET text = 'đường mới' WHERE msg_id = 'g1'", [])
            .unwrap();
        assert_eq!(super::super::search::search(&conn, "duong moi", 10).unwrap().len(), 1);
        assert!(super::super::search::search(&conn, "duong cu", 10).unwrap().is_empty());
        // Re-apply is a no-op (no second stamp, trigger unchanged).
        apply(&conn).unwrap();
        let rows: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM schema_meta WHERE version = 3",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(rows, 1);
    }

    // --- v3 (batch 10): the au trigger's WHEN guard ----------------------

    /// `SELECT total_changes()` — everything this connection has
    /// written so far (trigger bodies included).
    fn total_changes(conn: &Connection) -> i64 {
        conn.query_row("SELECT total_changes()", [], |r| r.get(0)).unwrap()
    }

    /// One writer-path message with full control over the text.
    fn wmsg(msg_id: &str, text: Option<&str>) -> crate::shadow::Write {
        let content = match text {
            Some(t) => serde_json::to_string(t).unwrap(),
            None => "\"\"".to_string(),
        };
        crate::shadow::Write::Message {
            msg_id: msg_id.into(),
            conv_id: "c1".into(),
            sender_id: Some("u1".into()),
            ts: 1000,
            kind: 1,
            text: text.map(str::to_string),
            payload: format!(
                r#"{{"msgId":"{msg_id}","uidFrom":"u1","idTo":"c1","ts":1000,"msgType":"text","content":{content}}}"#
            ),
            source: "capture",
            is_group: None,
        }
    }

    #[test]
    fn identical_replay_writes_no_fts_rows() {
        // J2: the writer's upsert rewrites `text` on every replay, so
        // the ONLY thing the v3 WHEN guard can save is the au
        // trigger's delete+insert. Prove it by measuring
        // total_changes() around one identical replay against a
        // baseline connection with the au trigger dropped: identical
        // text must cost EXACTLY the same (zero FTS work), while a
        // REAL edit must cost more on the trigger side — the
        // measurement is only honest because it can see the
        // difference.
        let mk = |au: bool| {
            let key = sqlcipher::generate_key().unwrap();
            let conn = sqlcipher::open_in_memory(&key).unwrap();
            apply(&conn).unwrap();
            if !au {
                conn.execute_batch("DROP TRIGGER messages_fts_au;").unwrap();
            }
            conn
        };
        let with_au = mk(true);
        let no_au = mk(false);
        // Same fresh insert on both.
        super::super::writer::apply(&with_au, &wmsg("r1", Some("Hà Nội hôm nay"))).unwrap();
        super::super::writer::apply(&no_au, &wmsg("r1", Some("Hà Nội hôm nay"))).unwrap();

        // Identical replay: with the guard it must cost exactly what
        // a connection with NO au trigger costs (0 FTS writes).
        let (base_au, base_no) = (total_changes(&with_au), total_changes(&no_au));
        super::super::writer::apply(&with_au, &wmsg("r1", Some("Hà Nội hôm nay"))).unwrap();
        super::super::writer::apply(&no_au, &wmsg("r1", Some("Hà Nội hôm nay"))).unwrap();
        let (replay_au, replay_no) = (total_changes(&with_au) - base_au, total_changes(&no_au) - base_no);
        assert_eq!(
            replay_au, replay_no,
            "identical replay did {replay_au} changes with the trigger vs {replay_no} without — the WHEN guard must cut FTS writes to zero"
        );

        // Sensitivity: a REAL edit fires au on the trigger side only,
        // so the deltas differ — this is what proves the measurement
        // above can actually see FTS writes.
        let (e_au, e_no) = (total_changes(&with_au), total_changes(&no_au));
        super::super::writer::apply(&with_au, &wmsg("r1", Some("Sài Gòn nắng"))).unwrap();
        super::super::writer::apply(&no_au, &wmsg("r1", Some("Sài Gòn nắng"))).unwrap();
        let (edit_au, edit_no) = (total_changes(&with_au) - e_au, total_changes(&no_au) - e_no);
        assert!(
            edit_au > edit_no,
            "a real edit must still re-index: {edit_au} with the trigger vs {edit_no} without"
        );
        // …and the re-index is correct, not just charged.
        assert_eq!(super::super::search::search(&with_au, "sai gon nang", 10).unwrap().len(), 1);
        assert!(super::super::search::search(&with_au, "ha noi", 10).unwrap().is_empty());

        // Timings for the report (printed, never asserted — the
        // change-count equality above is the proof): the replay
        // workload J2 exists for, on the three trigger states.
        let v2_au = {
            let conn = mk(true);
            conn_v2_trigger(&conn);
            conn
        };
        let n = 2_000;
        let time_replays = |conn: &Connection| -> std::time::Duration {
            let w = wmsg("r1", Some("Hà Nội hôm nay"));
            let t0 = std::time::Instant::now();
            for _ in 0..n {
                super::super::writer::apply(conn, &w).unwrap();
            }
            t0.elapsed()
        };
        println!(
            "identical replay x{n}: v3_au={}ms v2_au={}ms no_au={}ms",
            time_replays(&with_au).as_millis(),
            time_replays(&v2_au).as_millis(),
            time_replays(&no_au).as_millis(),
        );
    }

    /// Swap a fresh v3 DB's au trigger back to the UNGUARDED batch-9
    /// body (the timing comparison above needs the old cost too).
    fn conn_v2_trigger(conn: &Connection) {
        conn.execute_batch("DROP TRIGGER messages_fts_au;").unwrap();
        conn.execute_batch(FTS_AU_V2_BODY).unwrap();
    }

    #[test]
    fn au_trigger_handles_null_and_empty_text_transitions() {
        // The WHEN clause must keep the full trigger semantics for
        // every REAL transition (`IS NOT` is null-safe), only skipping
        // equal text — including NULL = NULL.
        let key = sqlcipher::generate_key().unwrap();
        let conn = sqlcipher::open_in_memory(&key).unwrap();
        apply(&conn).unwrap();
        let fts_n = |id: &str| -> i64 {
            conn.query_row(
                "SELECT COUNT(*) FROM messages_fts
                 WHERE rowid = (SELECT rowid FROM messages WHERE msg_id = ?1)",
                [id],
                |r| r.get(0),
            )
            .unwrap()
        };

        // NULL -> text (the e2ee decode shape): old.text IS NOT
        // new.text fires; the row is indexed.
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, source)
             VALUES ('n1', 'c1', 'u1', 1, 1, NULL, '{}', 'capture')",
            [],
        )
        .unwrap();
        assert_eq!(fts_n("n1"), 0);
        conn.execute("UPDATE messages SET text = 'bản rõ' WHERE msg_id = 'n1'", [])
            .unwrap();
        assert_eq!(fts_n("n1"), 1);
        assert_eq!(super::super::search::search(&conn, "ban ro", 10).unwrap().len(), 1);

        // text -> NULL: fires; the delete half removes the row and the
        // insert half's WHERE skips the NULL.
        conn.execute("UPDATE messages SET text = NULL WHERE msg_id = 'n1'", []).unwrap();
        assert_eq!(fts_n("n1"), 0);
        assert!(super::super::search::search(&conn, "ban ro", 10).unwrap().is_empty());

        // NULL -> NULL: `IS NOT` is false, nothing runs.
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, source)
             VALUES ('n2', 'c1', 'u1', 2, 1, NULL, '{}', 'capture')",
            [],
        )
        .unwrap();
        let before = total_changes(&conn);
        conn.execute("UPDATE messages SET text = NULL WHERE msg_id = 'n2'", []).unwrap();
        let delta = total_changes(&conn) - before;
        assert_eq!(delta, 1, "only the messages row itself — no FTS write");

        // '' <-> text: both are real changes; '' is never indexed.
        conn.execute(
            "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, text, payload_json, source)
             VALUES ('n3', 'c1', 'u1', 3, 1, '', '{}', 'capture')",
            [],
        )
        .unwrap();
        assert_eq!(fts_n("n3"), 0, "the ai trigger's own WHEN skips ''");
        conn.execute("UPDATE messages SET text = 'tin mới' WHERE msg_id = 'n3'", []).unwrap();
        assert_eq!(fts_n("n3"), 1);
        conn.execute("UPDATE messages SET text = '' WHERE msg_id = 'n3'", []).unwrap();
        assert_eq!(fts_n("n3"), 0, "text -> '' drops the row from the index");
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
        assert_eq!((max_v, rows), (99, 1), "no v3 stamp beside the future one");
    }
}
