//! Whitelisted distinct-values probe over a snapshot sample DB
//! (batch 14 N1, brief `glm-brief-batch14.md`).
//!
//! PRIVACY (the batch-14 hard rule): this tool must be UNABLE to
//! print row content. Three layered guards, all enforced in code and
//! all unit-tested:
//! 1. the column NAME must pass the code-column whitelist
//!    `^(.*_)?(type|kind|status|state|cmd|subcmd|sub_cmd|msgtype|msg_type|flag|flags|ver|version|src|source|unit|is[a-z_]*|has[a-z_]*)$`
//!    (case-insensitive) — content-bearing names (`message`,
//!    `displayName`, `serverTime`, …) are refused BEFORE any row is
//!    read, with an error naming the rule;
//! 2. the read is exactly one fixed aggregation
//!    `SELECT col, COUNT(*) FROM t GROUP BY col ORDER BY COUNT(*) DESC LIMIT 51`;
//! 3. a value is only ever rendered as: the INTEGER/REAL number,
//!    `NULL`, a code-shaped TEXT token (non-empty, ≤ 32 chars, every
//!    char in [A-Za-z0-9._:-] — e.g. `chat.photo`), the fingerprint
//!    `text(len=N,h12=…)` for any other TEXT, or `blob(len=N)`.
//! More than 50 distinct values print the first 50 plus
//! `… (more than 50 distinct — not a code column?)`.
//!
//! The DB probed is the FIRST sample of the requested kind (the very
//! sample `--inventory` reports): `index` = `Core\Index.db`,
//! `one2one`/`group`/`stranger` = the first sample by sorted file
//! name. Dry-run only (parse refuses `--apply`); every DB opens
//! `mode=ro&immutable=1` — nothing is written anywhere.
//!
//! H-rule: the aggregation and rendering halves are PURE and tested
//! below; only the CLI wires them to a connection.

use rusqlite::types::Value as SV;
use rusqlite::Connection;

use super::inventory::quote_ident;
use super::super::import_map::MapDb;

/// How many `--distinct` specs one run accepts (brief N1).
pub const MAX_PER_RUN: usize = 10;

/// The exact marker line when a column has more than 50 distinct
/// values (brief N1 wording).
pub const MORE_THAN_50: &str = "… (more than 50 distinct — not a code column?)";

/// The code-column whitelist as the refusal errors quote it (brief
/// N1, verbatim). Case-insensitive; content-bearing names can never
/// pass it.
pub const CODE_COLUMN_RULE: &str = "^(.*_)?(type|kind|status|state|cmd|subcmd|sub_cmd|msgtype|msg_type|flag|flags|ver|version|src|source|unit|is[a-z_]*|has[a-z_]*)$";

/// One parsed `--distinct <dbkind>:<table>.<column>` spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DistinctSpec {
    pub kind: MapDb,
    pub table: String,
    pub column: String,
}

/// Parse `<dbkind>:<table>.<column>` (pure; never touches the FS).
/// The dbkind must be a known kind name; the remainder splits at the
/// LAST '.' — a dotted table name still parses, a dotted column fails
/// the inventory existence check fail-closed.
pub fn parse_spec(s: &str) -> Result<DistinctSpec, String> {
    let err = |why: String| format!("--distinct {s:?}: {why}");
    let (kind_s, rest) = s.split_once(':').ok_or_else(|| {
        err(String::from(
            "must be <dbkind>:<table>.<column> (dbkind: index, one2one, group, stranger)",
        ))
    })?;
    let kind = MapDb::parse(kind_s).ok_or_else(|| {
        err(format!(
            "unknown dbkind {kind_s:?} (allowed: index, one2one, group, stranger)"
        ))
    })?;
    let (table, column) = rest.rsplit_once('.').ok_or_else(|| {
        err(String::from(
            "missing the .<column> part: must be <dbkind>:<table>.<column>",
        ))
    })?;
    if table.is_empty() {
        return Err(err(String::from("empty <table> part")));
    }
    if column.is_empty() {
        return Err(err(String::from("empty <column> part")));
    }
    Ok(DistinctSpec {
        kind,
        table: table.to_string(),
        column: column.to_string(),
    })
}

/// The spec echoed back as `<kind>:<table>.<column>` (report lines
/// and error prefixes).
pub fn spec_str(spec: &DistinctSpec) -> String {
    format!("{}:{}.{}", spec.kind.name(), spec.table, spec.column)
}

/// One tail alternative of the whitelist: the fixed words, or the
/// `is[a-z_]*` / `has[a-z_]*` flag shapes (the star may be empty —
/// `is` and `has` alone match).
fn is_tail_word(x: &str) -> bool {
    const ALTS: [&str; 16] = [
        "type", "kind", "status", "state", "cmd", "subcmd", "sub_cmd", "msgtype", "msg_type",
        "flag", "flags", "ver", "version", "src", "source", "unit",
    ];
    if ALTS.contains(&x) {
        return true;
    }
    for p in ["is", "has"] {
        if let Some(t) = x.strip_prefix(p) {
            if t.bytes().all(|b| b.is_ascii_lowercase() || b == b'_') {
                return true;
            }
        }
    }
    false
}

/// Does the column NAME pass the code-column whitelist (brief N1)?
/// Hand-rolled to the exact regex semantics, ASCII-case-insensitive
/// (the codebase adds no crates); control-character names are
/// refused outright — `quote_ident` refuses them for the SQL anyway,
/// and `.` in the rule never matches a newline.
pub fn is_code_column(name: &str) -> bool {
    if name.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return false;
    }
    let s = name.to_ascii_lowercase();
    // The bare tail (the optional `(.*)_` prefix skipped)…
    if is_tail_word(&s) {
        return true;
    }
    // …or any prefix ending in `_` followed by one of the tails.
    s.match_indices('_').any(|(i, _)| is_tail_word(&s[i + 1..]))
}

/// The only value forms the tool can ever print (N1 privacy rule):
/// INTEGER/REAL → the number; NULL → `NULL`; TEXT → the token only
/// when it is code-shaped (non-empty, ≤ 32 bytes, every char in
/// [A-Za-z0-9._:-] — `^[A-Za-z0-9._:-]+$`), otherwise the
/// fingerprint `text(len=N,h12=…)` (length + sha256-12, never the
/// content); BLOB → `blob(len=N)`.
pub fn render_value(v: &SV) -> String {
    match v {
        SV::Null => "NULL".to_string(),
        SV::Integer(i) => i.to_string(),
        SV::Real(f) => f.to_string(),
        SV::Text(s) => {
            let code_shaped = !s.is_empty()
                && s.len() <= 32
                && s
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'));
            if code_shaped {
                s.clone()
            } else {
                // Never the content: length + sha256-12 only.
                format!("text(len={},h12={})", s.len(), super::sha12(s.as_bytes()))
            }
        }
        SV::Blob(b) => format!("blob(len={})", b.len()),
    }
}

/// The exact N1 aggregation over one sample DB: counts by value,
/// most frequent first, capped at 51 (so "51 rows fetched" means
/// "more than 50 distinct"). Table/column are identifier-quoted
/// (the safety layer every module applies; the names come from the
/// inventory, never raw user SQL).
pub fn distinct_report(
    conn: &Connection,
    spec: &DistinctSpec,
    source_rel: &str,
) -> Result<Vec<String>, String> {
    let who = format!("--distinct {}:", spec_str(spec));
    let qt = quote_ident(&spec.table)?;
    let qc = quote_ident(&spec.column)?;
    let sql = format!(
        "SELECT {qc}, COUNT(*) FROM {qt} GROUP BY {qc} ORDER BY COUNT(*) DESC LIMIT 51"
    );
    let mut st = conn
        .prepare(&sql)
        .map_err(|e| format!("{who} {e}"))?;
    let rows: Vec<(SV, i64)> = st
        .query_map([], |r| Ok((r.get::<_, SV>(0)?, r.get::<_, i64>(1)?)))
        .map_err(|e| format!("{who} {e}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{who} {e}"))?;
    let mut lines = vec![format!("distinct: {} source={}", spec_str(spec), source_rel)];
    let capped = rows.len() > 50; // LIMIT 51 ⇒ 51 rows means more than 50 distinct
    for (v, n) in rows.iter().take(50) {
        lines.push(format!("  {} x {}", render_value(v), n));
    }
    if capped {
        lines.push(format!("  {MORE_THAN_50}"));
    }
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A plain in-memory DB (synthetic fixtures only).
    fn mem() -> Connection {
        Connection::open_in_memory().unwrap()
    }

    #[test]
    fn parse_spec_accepts_the_four_kinds_and_splits_at_the_last_dot() {
        for (s, kind, table, column) in [
            ("index:conversation.isGroup", MapDb::Index, "conversation", "isGroup"),
            ("one2one:message.msgType", MapDb::OneToOne, "message", "msgType"),
            ("group:message.msgType", MapDb::Group, "message", "msgType"),
            ("stranger:message.status", MapDb::Stranger, "message", "status"),
        ] {
            let spec = parse_spec(s).unwrap();
            assert_eq!(spec.kind, kind, "{s}");
            assert_eq!(spec.table, table, "{s}");
            assert_eq!(spec.column, column, "{s}");
            // The echo form is exactly the input shape.
            assert_eq!(spec_str(&spec), s);
        }
        // A dotted TABLE still parses (the split is at the last dot);
        // a dotted column would fail the inventory check fail-closed.
        let spec = parse_spec("one2one:za.lo.msgType").unwrap();
        assert_eq!(spec.table, "za.lo");
        assert_eq!(spec.column, "msgType");
    }

    #[test]
    fn parse_spec_rejects_every_malformed_form_with_exact_errors() {
        for (s, needle) in [
            (
                "message.msgType",
                "must be <dbkind>:<table>.<column>",
            ),
            ("bogus:message.msgType", "unknown dbkind \"bogus\" (allowed: index, one2one, group, stranger)"),
            ("index", "must be <dbkind>:<table>.<column>"),
            ("one2one:message", "missing the .<column> part"),
            ("one2one:.msgType", "empty <table> part"),
            ("one2one:message.", "empty <column> part"),
            (":message.msgType", "unknown dbkind \"\""),
        ] {
            let e = parse_spec(s).unwrap_err();
            assert!(e.contains(&format!("--distinct {s:?}:")), "{s} -> {e}");
            assert!(e.contains(needle), "{s} -> {e}");
        }
    }

    #[test]
    fn code_column_whitelist_accepts_the_rule_shapes() {
        for ok in [
            // The fixed alternatives, bare and with a `(.*)_` prefix.
            "type", "Type", "TYPE", "kind", "status", "state", "cmd", "subcmd", "sub_cmd",
            "msgType", "msg_type", "flag", "flags", "ver", "version", "src", "source", "unit",
            "x_type", "_type", "chat_delete_status", "a.b?_src",
            // The is/has flag shapes, bare and prefixed; the star may
            // be empty.
            "is", "has", "isActive", "is_active", "hasReact", "has_react", "__isUpdateMessage",
            "a_is_b", "my_has", "isLocalMsgId", "isErrorInfo", "isLastMsg",
        ] {
            assert!(is_code_column(ok), "{ok:?} must be accepted");
        }
    }

    #[test]
    fn code_column_whitelist_refuses_content_bearing_names() {
        for no in [
            // Message content and identifiers.
            "message", "content", "msgText", "textArguments", "displayName", "avatar",
            "userId", "fromUid", "toUid", "phone", "quote", "notify", "extra", "raw",
            // Type-like names that do NOT fit the rule: the prefix
            // must end in `_`.
            "localType", "platformType", "subType", "originMsgType", "e2eeStatus", "subState",
            "mytype", "typeof", "upSrc",
            // Flag-like names with a non-[a-z_] tail.
            "is2ee", "has1", "isE2ee",
            // Anything else.
            "serverTime", "sendDttm", "originTs", "localDttm", "st", "at", "ev", "ttl",
            // Control characters can never be a code column (and can
            // never reach the SQL — quote_ident refuses them too).
            "a\n_type", "a\u{7}b",
        ] {
            assert!(!is_code_column(no), "{no:?} must be refused");
        }
    }

    #[test]
    fn render_value_prints_numbers_null_and_code_shaped_text_only() {
        assert_eq!(render_value(&SV::Integer(1)), "1");
        assert_eq!(render_value(&SV::Integer(-5)), "-5");
        assert_eq!(render_value(&SV::Real(2.5)), "2.5");
        assert_eq!(render_value(&SV::Null), "NULL");
        // A code-shaped token prints as-is.
        assert_eq!(render_value(&SV::Text("chat.photo".into())), "chat.photo");
        assert_eq!(render_value(&SV::Text("webchat".into())), "webchat");
        assert_eq!(
            render_value(&SV::Text("a2345678901234567890123456789012".into())),
            "a2345678901234567890123456789012", // exactly 32 chars
        );
        // A blob is its length only.
        assert_eq!(render_value(&SV::Blob(vec![0xde, 0xad])), "blob(len=2)");
        assert_eq!(render_value(&SV::Blob(Vec::new())), "blob(len=0)");
    }

    #[test]
    fn render_value_fingerprints_anything_that_is_not_code_shaped() {
        let f = |s: &str| {
            let out = render_value(&SV::Text(s.into()));
            // Never the content, never a word of it.
            assert!(!out.contains(s), "{s:?} leaked: {out}");
            out
        };
        // A sentence (spaces), a name (spaces + non-ASCII), a phone
        // with country code (+ is not code-shaped): all len+h12.
        let sent = f("hello there from the other side!");
        assert!(sent.starts_with("text(len=32,h12="), "{sent}");
        let name = f("Nguyen Van A");
        assert!(name.starts_with("text(len=12,h12="), "{name}");
        let phone = f("+849481234567");
        assert!(phone.starts_with("text(len=13,h12="), "{phone}");
        // Too long to be a code (33 chars): fingerprinted.
        let long = f("a23456789012345678901234567890123");
        assert!(long.starts_with("text(len=33,h12="), "{long}");
        // Empty TEXT is not code-shaped (`+` needs one char): the
        // empty-string fingerprint (a pinned sha256 vector).
        assert_eq!(render_value(&SV::Text(String::new())), "text(len=0,h12=e3b0c44298fc)");
        // The h12 is exactly the import helper's sha256-12.
        assert_eq!(
            render_value(&SV::Text("hello there".into())),
            format!("text(len=11,h12={})", super::super::sha12(b"hello there"))
        );
        // The fingerprint form is always length + 12 hex chars.
        for s in ["x y", "ünïcödé", "tab\there"] {
            let out = render_value(&SV::Text(s.into()));
            let h12 = out
                .strip_prefix(&format!("text(len={},h12=", s.len()))
                .unwrap()
                .strip_suffix(')')
                .unwrap();
            assert_eq!(h12.len(), 12, "{s:?} -> {out}");
            assert!(h12.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
        }
    }

    #[test]
    fn distinct_report_orders_by_count_and_renders_privately() {
        let conn = mem();
        conn.execute_batch(
            "CREATE TABLE message (
               msgType, status, content TEXT
             );
             INSERT INTO message (msgType, status, content) VALUES
               (1, 0, 'sentences have spaces'),
               (1, 0, 'more sentences here'),
               (2, 1, 'chat.photo'),
               (NULL, NULL, 'x'),
               ('chat.photo', 0, 'y'),
               (1.5, 0, 'z'),
               (x'0102', 0, 'w');",
        )
        .unwrap();
        let spec = parse_spec("one2one:message.msgType").unwrap();
        let lines = distinct_report(&conn, &spec, "Core/Message/111.db").unwrap();
        assert_eq!(
            lines[0],
            "distinct: one2one:message.msgType source=Core/Message/111.db"
        );
        // Most frequent first; ties keep SQLite's order, so assert
        // membership rather than position for the singles.
        assert_eq!(lines[1], "  1 x 2");
        let joined = lines.join("\n");
        for needle in [
            "  2 x 1", "  NULL x 1", "  chat.photo x 1", "  1.5 x 1", "  blob(len=2) x 1",
        ] {
            assert!(joined.contains(needle), "{needle} missing: {joined}");
        }
        assert_eq!(lines.len(), 1 + 6, "{joined}");
        // Privacy: no content column was ever read, no sentence leaked.
        assert!(!joined.contains("sentences"), "{joined}");
        assert!(!joined.contains("hello"), "{joined}");
        // A refused column never gets this far (validated by the
        // caller), but the report itself only touches the one column.
        let spec2 = parse_spec("one2one:message.status").unwrap();
        let lines2 = distinct_report(&conn, &spec2, "Core/Message/111.db").unwrap();
        assert!(lines2.iter().any(|l| l == "  0 x 5"), "{lines2:?}");
        assert!(lines2.iter().any(|l| l == "  1 x 1"), "{lines2:?}");
    }

    #[test]
    fn distinct_report_caps_at_more_than_fifty_distinct() {
        // Deterministic order: value i appears (N - i) times.
        let seed = |n: i64| {
            let conn = mem();
            conn.execute_batch("CREATE TABLE t (msgType INTEGER);").unwrap();
            for i in 1..=n {
                for _ in 0..(n + 1 - i) {
                    conn.execute("INSERT INTO t (msgType) VALUES (?1)", [i]).unwrap();
                }
            }
            conn
        };
        let spec = parse_spec("one2one:t.msgType").unwrap();
        // 60 distinct: the first 50 (values 1..=50) plus the marker.
        let lines = distinct_report(&seed(60), &spec, "Core/Message/111.db").unwrap();
        assert_eq!(lines.len(), 1 + 50 + 1);
        assert_eq!(lines[1], "  1 x 60");
        assert_eq!(lines[50], "  50 x 11");
        assert_eq!(lines[51], format!("  {MORE_THAN_50}"));
        assert!(!lines.iter().any(|l| l.contains("51 x")), "{lines:?}");
        // 51 distinct: still the first 50 plus the marker.
        let lines = distinct_report(&seed(51), &spec, "Core/Message/111.db").unwrap();
        assert_eq!(lines.len(), 1 + 50 + 1);
        assert_eq!(lines[51], format!("  {MORE_THAN_50}"));
        // 50 distinct: all of them, no marker.
        let lines = distinct_report(&seed(50), &spec, "Core/Message/111.db").unwrap();
        assert_eq!(lines.len(), 1 + 50);
        assert_eq!(lines[50], "  50 x 1");
        assert!(!lines.iter().any(|l| l.contains(MORE_THAN_50)), "{lines:?}");
        // An empty table: just the header.
        let conn = mem();
        conn.execute_batch("CREATE TABLE t (msgType INTEGER);").unwrap();
        let lines = distinct_report(&conn, &spec, "Core/Message/111.db").unwrap();
        assert_eq!(lines.len(), 1);
    }

    #[test]
    fn distinct_report_quotes_identifiers_and_refuses_none() {
        // The quote layer: a table/column name with a quote in it
        // stays one quoted identifier (the inventory guard's rule).
        let conn = mem();
        conn.execute_batch(
            "CREATE TABLE \"we\"\"ird\" (\"ty\"\"pe\" INTEGER);
             INSERT INTO \"we\"\"ird\" (\"ty\"\"pe\") VALUES (1), (1), (2);",
        )
        .unwrap();
        let spec = DistinctSpec {
            kind: MapDb::OneToOne,
            table: "we\"ird".into(),
            column: "ty\"pe".into(),
        };
        let lines = distinct_report(&conn, &spec, "Core/Message/111.db").unwrap();
        assert_eq!(lines[1], "  1 x 2");
        assert!(lines.iter().any(|l| l == "  2 x 1"), "{lines:?}");
    }
}
