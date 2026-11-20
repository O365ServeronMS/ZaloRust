//! Schema inventory of one Desktop snapshot DB (batch 12 L1, audit
//! §4 items 2.2/2.3 groundwork).
//!
//! Shape-only by construction (batch-12 hard rule): table names,
//! column names with their DECLARED types and PRIMARY KEY flags, row
//! counts and index names. No row value ever crosses this module and
//! nothing here writes — callers pass the immutable read-only
//! connection `import::open_desktop_db` produces.
//!
//! `--inventory` prints the inventory of `Core\Index.db` plus ONE
//! sample per message-DB kind (the first 1-1, the first group,
//! stranger_box) and writes the same as JSON via `--out`. The samples
//! exist so a mapping (`import_map::plan`) can be validated against a
//! real schema without opening all 1 471 message DBs.
//!
//! Table set policy: EVERY `sqlite_master` row with `type='table'` is
//! inventoried (including `sqlite_sequence`-style internals if the
//! DB has them), so `tables.len()` equals the same count the 2.2
//! acceptance measures (`SELECT count(*) FROM sqlite_master WHERE
//! type='table'`).

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

/// One column of one table: name, declared type (`""` when SQLite
/// stores no type), PRIMARY KEY flag.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ColumnInfo {
    pub name: String,
    pub decl_type: String,
    pub pk: bool,
}

/// One inventoried table.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TableInfo {
    pub name: String,
    pub columns: Vec<ColumnInfo>,
    pub row_count: i64,
    /// Index names as `PRAGMA index_list` reports them (including
    /// `sqlite_autoindex_*` for PK/UNIQUE constraints).
    pub indexes: Vec<String>,
}

/// The inventory of one DB: every table, sorted by name.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct DbInventory {
    pub tables: Vec<TableInfo>,
}

/// Which snapshot file an inventory came from, plus the inventory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KindInventory {
    /// Forward-slash relative path inside the snapshot, e.g.
    /// `Core/Index.db`, `Core/Message/123.db`.
    pub source_rel: String,
    pub inventory: DbInventory,
}

/// The inventory set of a snapshot: `Core\Index.db` plus one sample
/// per message-DB kind. This is exactly the set `import_map::plan`
/// validates a mapping against.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotInventories {
    pub index: Option<KindInventory>,
    pub one_to_one: Option<KindInventory>,
    pub group: Option<KindInventory>,
    pub stranger_box: Option<KindInventory>,
}

/// Quote a SQLite identifier for interpolation into a statement
/// (`"name"`, internal quotes doubled). The names come from
/// `sqlite_master` itself, but the guard still refuses anything that
/// could break out of the quoted form: empty names, control
/// characters, NUL. Identifiers with doubled quotes inside are SAFE —
/// that is the documented SQLite quoting rule.
pub fn quote_ident(name: &str) -> Result<String, String> {
    if name.is_empty() {
        return Err("refusing to quote an empty identifier".into());
    }
    if name.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err(format!(
            "refusing to quote identifier {name:?}: control characters in the name"
        ));
    }
    Ok(format!("\"{}\"", name.replace('"', "\"\"")))
}

/// Inventory one DB: every table (`sqlite_master`), each with
/// `PRAGMA table_info`, `count(*)` and `PRAGMA index_list`. Read-only;
/// never returns a row value.
pub fn inventory_db(conn: &Connection) -> Result<DbInventory, String> {
    let names: Vec<String> = {
        let mut st = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .map_err(|e| format!("sqlite_master read failed: {e}"))?;
        let rows = st
            .query_map([], |r| r.get::<_, String>(0))
            .map_err(|e| format!("sqlite_master read failed: {e}"))?;
        rows.filter_map(Result::ok).collect()
    };
    let mut tables = Vec::with_capacity(names.len());
    for name in names {
        let q = quote_ident(&name)?;
        let columns: Vec<ColumnInfo> = {
            let mut st = conn
                .prepare(&format!("PRAGMA table_info({q})"))
                .map_err(|e| format!("table_info({name:?}) failed: {e}"))?;
            let rows = st
                .query_map([], |r| {
                    Ok(ColumnInfo {
                        name: r.get(1)?,
                        decl_type: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                        pk: r.get::<_, i64>(5)? > 0,
                    })
                })
                .map_err(|e| format!("table_info({name:?}) failed: {e}"))?;
            rows.filter_map(Result::ok).collect()
        };
        let row_count: i64 = conn
            .query_row(&format!("SELECT count(*) FROM {q}"), [], |r| r.get(0))
            .map_err(|e| format!("count(*) on {name:?} failed: {e}"))?;
        let indexes: Vec<String> = {
            let mut st = conn
                .prepare(&format!("PRAGMA index_list({q})"))
                .map_err(|e| format!("index_list({name:?}) failed: {e}"))?;
            let rows = st
                .query_map([], |r| r.get::<_, String>(1))
                .map_err(|e| format!("index_list({name:?}) failed: {e}"))?;
            rows.filter_map(Result::ok).collect()
        };
        tables.push(TableInfo {
            name,
            columns,
            row_count,
            indexes,
        });
    }
    Ok(DbInventory { tables })
}

impl DbInventory {
    /// The table with `name`, if inventoried.
    pub fn table(&self, name: &str) -> Option<&TableInfo> {
        self.tables.iter().find(|t| t.name == name)
    }

    /// Does the table have a column named `col`?
    pub fn has_column(&self, table: &str, col: &str) -> bool {
        self.table(table)
            .is_some_and(|t| t.columns.iter().any(|c| c.name == col))
    }
}

impl TableInfo {
    /// One shape-only report line (names, types, counts — never
    /// values): `msgs: rows=12 cols=(id:INTEGER pk,ts:INTEGER) idx=(a,b)`.
    pub fn line(&self) -> String {
        let cols: Vec<String> = self
            .columns
            .iter()
            .map(|c| {
                let pk = if c.pk { " pk" } else { "" };
                format!("{}:{}{pk}", c.name, c.decl_type)
            })
            .collect();
        let idx = if self.indexes.is_empty() {
            String::from("-")
        } else {
            self.indexes.join(",")
        };
        format!(
            "  {}: rows={} cols=({}) idx=({})",
            self.name,
            self.row_count,
            cols.join(","),
            idx
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrate::sqlcipher;

    /// A fresh encrypted in-memory DB (synthetic fixtures only).
    fn mem() -> Connection {
        let key = sqlcipher::generate_key().unwrap();
        let conn = sqlcipher::open_in_memory(&key).unwrap();
        conn
    }

    #[test]
    fn quote_ident_doubles_quotes_and_refuses_control_chars() {
        assert_eq!(quote_ident("msg").unwrap(), "\"msg\"");
        assert_eq!(quote_ident("we\"ird name").unwrap(), "\"we\"\"ird name\"");
        assert_eq!(quote_ident("Upper.Case").unwrap(), "\"Upper.Case\"");
        assert!(quote_ident("").is_err());
        assert!(quote_ident("a\u{7}b").is_err());
        assert!(quote_ident("a\nb").is_err());
        // An injection attempt stays one quoted identifier.
        assert_eq!(quote_ident("x\"; DROP TABLE t; --").unwrap().as_str(),
            "\"x\"\"; DROP TABLE t; --\"");
    }

    #[test]
    fn inventory_reports_tables_columns_counts_indexes() {
        let conn = mem();
        conn.execute_batch(
            "CREATE TABLE msg (
               id INTEGER PRIMARY KEY,
               cliId TEXT,
               fromUid TEXT NOT NULL,
               ts INTEGER,
               content TEXT
             );
             CREATE INDEX idx_msg_ts ON msg(ts);
             INSERT INTO msg (cliId, fromUid, ts, content)
               VALUES ('c1','u1',1690000000,'a'), ('c2','u2',1690000001,'b');
             CREATE TABLE conv (id TEXT PRIMARY KEY, name TEXT);
             INSERT INTO conv (id, name) VALUES ('c1','n');",
        )
        .unwrap();
        let inv = inventory_db(&conn).unwrap();
        assert_eq!(inv.tables.len(), 2, "sorted by name: conv, msg");
        assert_eq!(inv.tables[0].name, "conv");
        assert_eq!(inv.tables[0].row_count, 1);
        assert_eq!(inv.tables[0].columns.len(), 2);
        assert!(inv.tables[0].columns[0].pk, "TEXT PRIMARY KEY");
        // msg: 5 columns, one pk, one explicit index (+ no autoindex:
        // INTEGER PRIMARY KEY is the rowid alias).
        let msg = &inv.tables[1];
        assert_eq!(msg.name, "msg");
        assert_eq!(msg.row_count, 2);
        assert_eq!(msg.columns.len(), 5);
        assert_eq!(msg.columns[0].name, "id");
        assert_eq!(msg.columns[0].decl_type, "INTEGER");
        assert!(msg.columns[0].pk);
        assert_eq!(msg.columns[2].decl_type, "TEXT");
        assert!(!msg.columns[2].pk);
        assert_eq!(msg.indexes, vec!["idx_msg_ts".to_string()]);
        // The lookup helpers.
        assert!(inv.has_column("msg", "fromUid"));
        assert!(!inv.has_column("msg", "nope"));
        assert!(!inv.has_column("nope", "id"));
        // An untyped column reports an empty decl_type.
        conn.execute_batch("CREATE TABLE bare (x);").unwrap();
        let inv2 = inventory_db(&conn).unwrap();
        let bare = inv2.table("bare").unwrap();
        assert_eq!(bare.columns[0].decl_type, "");
        // The report line is names/types/counts only.
        let line = msg.line();
        assert!(line.contains("msg: rows=2"), "{line}");
        assert!(line.contains("id:INTEGER pk"), "{line}");
        assert!(line.contains("idx=(idx_msg_ts)"), "{line}");
    }

    #[test]
    fn inventory_covers_autoindexes_and_internal_tables() {
        let conn = mem();
        conn.execute_batch(
            "CREATE TABLE t (id TEXT PRIMARY KEY, v TEXT UNIQUE);
             INSERT INTO t (id, v) VALUES ('a','b');",
        )
        .unwrap();
        let inv = inventory_db(&conn).unwrap();
        let t = inv.table("t").unwrap();
        // type='table' rows are ALL inventoried; autoindexes show by name.
        assert_eq!(inv.tables.len(), 1);
        assert!(t.indexes.iter().any(|n| n.starts_with("sqlite_autoindex")),
            "autoindexes are reported: {:?}", t.indexes);
    }

    #[test]
    fn inventory_of_an_empty_db_is_empty() {
        let conn = mem();
        let inv = inventory_db(&conn).unwrap();
        assert!(inv.tables.is_empty());
        assert_eq!(inv, DbInventory::default());
    }

    #[test]
    fn inventory_json_round_trips() {
        let conn = mem();
        conn.execute_batch(
            "CREATE TABLE msg (id INTEGER PRIMARY KEY, ts INTEGER);
             INSERT INTO msg (ts) VALUES (7);",
        )
        .unwrap();
        let inv = inventory_db(&conn).unwrap();
        let json = serde_json::to_string_pretty(&inv).unwrap();
        let back: DbInventory = serde_json::from_str(&json).unwrap();
        assert_eq!(back, inv);
        // The JSON shape is pinned: exactly these keys.
        assert!(json.contains("\"tables\""));
        assert!(json.contains("\"decl_type\": \"INTEGER\""));
        assert!(json.contains("\"row_count\": 1"));
        assert!(json.contains("\"pk\": true"));
        // And the snapshot-level set serializes with per-kind sources.
        let set = SnapshotInventories {
            index: Some(KindInventory {
                source_rel: "Core/Index.db".into(),
                inventory: inv,
            }),
            one_to_one: None,
            group: None,
            stranger_box: None,
        };
        let j = serde_json::to_string(&set).unwrap();
        assert!(j.contains("\"source_rel\":\"Core/Index.db\""), "{j}");
        assert!(j.contains("\"one_to_one\":null"), "{j}");
        let back: SnapshotInventories = serde_json::from_str(&j).unwrap();
        assert_eq!(back, set);
    }
}
