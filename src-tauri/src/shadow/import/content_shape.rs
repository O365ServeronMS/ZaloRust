//! Content-shape aggregation (batch 23a C1/C2): the second, shape-only
//! arbiter for the Desktop `msgType` codes the mapping does not list.
//!
//! The batch-15 cross-tab (`probe_import_codes`) joined Desktop
//! msgIds against shadow rows, but ~12.6k rows carry codes whose
//! matched-row count never reaches the promotion bar. The shape of the
//! CONTENT is an independent signal: a code whose content column reads
//! like `{href,params,title}` with `params` holding
//! `fileSize/fileExt`, and whose few cross-tab hits say `share.file`,
//! can be mapped with confidence.
//!
//! PRIVACY (the batch-23a hard rule): this module is UNABLE to print
//! a content value. Everything it emits is:
//! - the rendered CODE token (the caller renders it through the
//!   batch-14 `--distinct` code-shape renderer — numbers, NULL,
//!   ≤32-char code tokens, else len+h12 fingerprints);
//! - KEY NAMES that match `^[A-Za-z_][A-Za-z0-9_]{0,31}$` — any other
//!   key prints `k:<sha256-12>`;
//! - type letters (s/n/b/o/a/z), counts, and the `…+N` cap markers.
//! No text, id, url, number or file name taken from the content ever
//! crosses this module's output.
//!
//! Classification of one content cell (both sides agree by
//! construction — they share these functions):
//! - `null` — the cell is SQL NULL / the JSON content is absent/Null;
//! - `json_object` — the cell's text parses as a JSON object (Desktop
//!   content columns store objects as JSON text; the shadow payload's
//! `$.content` may be an object directly or a string holding the same
//! JSON text);
//! - `json_array` — the text parses as a JSON array;
//! - `json_string_scalar` — the text parses as a JSON string;
//! - `not_json` — everything else: prose, blobs, INTEGER/REAL cells,
//!   and number/bool/null JSON scalars (a cell that parses but is none
//!   of the three tracked shapes).
//!
//! Signature (`object_signature`): the sorted top-level keys of a
//! json_object row, each as `key:<letter>` with s/n/b/o/a/z; ONE level
//! of nesting — a string value that itself parses as a JSON object
//! adds `key{inner}` with the inner keys' letters (no deeper nesting,
//! arrays stay just `a`); capped at `MAX_SIG_KEYS` entries with
//! `…+N` appended (the inner list gets the same cap inside the
//! braces).
//!
//! H-rule: everything here is pure and unit-tested below; only
//! `import::run_content_shape` (C1) and the ignored
//! `probe_shadow_content_shape` (C2) wire it to a connection.

use std::collections::BTreeMap;

use rusqlite::types::Value as SV;
use serde::Serialize;
use serde_json::Value as J;

/// How many distinct code groups one report keeps (brief C1); the
/// rest merge into the `other` group.
pub const MAX_CODES: usize = 64;

/// How many key signatures print per group (brief C1).
pub const TOP_SIGS: usize = 8;

/// Cap of each signature's key list, overflow marked `…+N` (brief C1).
pub const MAX_SIG_KEYS: usize = 24;

/// The overflow group's label (brief C1: "the rest go into `other`").
pub const OTHER_LABEL: &str = "other";

/// The key-name rule the report quotes (brief C1): a key prints only
/// when it matches `^[A-Za-z_][A-Za-z0-9_]{0,31}$`; anything else
/// prints `k:<sha256-12>`.
pub const KEY_RULE: &str = "^[A-Za-z_][A-Za-z0-9_]{0,31}$";

/// One group's counters: rows, the five shape buckets, and the
/// signature → count map (json_object rows only).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ShapeGroup {
    pub rows: usize,
    pub json_object: usize,
    pub json_array: usize,
    pub json_string_scalar: usize,
    pub not_json: usize,
    pub null: usize,
    /// key signature → how many json_object rows produced it.
    pub sigs: BTreeMap<String, usize>,
}

impl ShapeGroup {
    /// Fold ONE cell of a Desktop content column (C1): SQL NULL →
    /// `null`; TEXT → the shared text classification; INTEGER/REAL/
    /// BLOB cells are never JSON text here → `not_json`.
    pub fn fold_cell(&mut self, v: &SV) {
        self.rows += 1;
        match v {
            SV::Null => self.null += 1,
            SV::Text(s) => self.fold_text_cell(s),
            SV::Integer(_) | SV::Real(_) | SV::Blob(_) => self.not_json += 1,
        }
    }

    /// Fold ONE shadow payload's `$.content` JSON value (C2):
    /// absent/Null → `null`; an object → `json_object` (signature
    /// from it directly); an array → `json_array`; a string → the
    /// shared text classification (the string may itself be JSON
    /// text — exactly the Desktop shape); a number/bool → `not_json`.
    pub fn fold_content_json(&mut self, v: Option<&J>) {
        self.rows += 1;
        match v {
            None | Some(J::Null) => self.null += 1,
            Some(J::Object(m)) => {
                self.json_object += 1;
                *self.sigs.entry(object_signature(m)).or_insert(0) += 1;
            }
            Some(J::Array(_)) => self.json_array += 1,
            Some(J::String(s)) => self.fold_text_cell(s),
            Some(J::Bool(_)) | Some(J::Number(_)) => self.not_json += 1,
        }
    }

    /// The shared text classification: parse `s` as JSON and bucket.
    fn fold_text_cell(&mut self, s: &str) {
        match serde_json::from_str::<J>(s) {
            Ok(J::Object(m)) => {
                self.json_object += 1;
                *self.sigs.entry(object_signature(&m)).or_insert(0) += 1;
            }
            Ok(J::Array(_)) => self.json_array += 1,
            // A JSON string scalar is still counted as such, but Zalo Desktop
            // double-encodes its `message` column (a JSON string whose text
            // is itself a JSON object). Claude found this on the real
            // snapshot: every row of every code was a string scalar. So
            // when the inner text parses as an object, its key signature is
            // recorded with a `str:` prefix. Key names only, as for objects.
            Ok(J::String(inner)) => {
                self.json_string_scalar += 1;
                let sig = match serde_json::from_str::<J>(&inner) {
                    Ok(J::Object(m)) => format!("str:{}", object_signature(&m)),
                    // Shape-only class of what the string holds instead:
                    // its JSON kind (or `text`), a length bucket, and a
                    // charset class. Never any of its characters.
                    Ok(J::Array(_)) => format!("str:array {}", len_bucket(&inner)),
                    Ok(J::String(_)) => format!("str:string {}", len_bucket(&inner)),
                    Ok(_) => format!("str:scalar {}", len_bucket(&inner)),
                    Err(_) => format!("str:text {} {}", len_bucket(&inner), charset_class(&inner)),
                };
                *self.sigs.entry(sig).or_insert(0) += 1;
            }
            // Number/bool/null scalars parse but are none of the three
            // tracked shapes — documented `not_json`.
            Ok(_) => self.not_json += 1,
            Err(_) => self.not_json += 1,
        }
    }
}

/// Length bucket of a string, in chars (shape only).
fn len_bucket(s: &str) -> &'static str {
    match s.chars().count() {
        0 => "len=0",
        1..=16 => "len<=16",
        17..=64 => "len<=64",
        65..=256 => "len<=256",
        257..=1024 => "len<=1k",
        _ => "len>1k",
    }
}

/// Charset class of a string (shape only): `b64` when every char is
/// base64/base64url, else `ascii` / `unicode`, with `+sp` when it
/// contains whitespace.
fn charset_class(s: &str) -> String {
    // Short words are base64-charset too; only call 16+ chars `b64`.
    let b64 = s.len() >= 16
        && s.chars().all(|c| c.is_ascii_alphanumeric() || "+/=-_".contains(c));
    if b64 {
        return "b64".into();
    }
    let base = if s.is_ascii() { "ascii" } else { "unicode" };
    let sp = if s.chars().any(char::is_whitespace) { "+sp" } else { "" };
    // Structural hints only: the CLASS of the first char, and whether
    // a `":` key/value joint appears. Never the chars themselves.
    let start = match s.chars().next() {
        Some('{') => "brace",
        Some('[') => "bracket",
        Some('"') => "quote",
        Some(c) if c.is_alphabetic() => "alpha",
        Some(c) if c.is_numeric() => "digit",
        Some(_) => "other",
        None => "none",
    };
    let joint = if s.contains("\":") { " jsonish" } else { "" };
    format!("{base}{sp} start={start}{joint}")
}

/// Does `k` match the brief's key rule `^[A-Za-z_][A-Za-z0-9_]{0,31}$`?
/// Hand-rolled to the exact regex semantics (ASCII only; the
/// codebase adds no crates). Everything else must be fingerprinted.
pub fn is_identifier_key(k: &str) -> bool {
    let b = k.as_bytes();
    match b.first() {
        Some(c) if c.is_ascii_alphabetic() || *c == b'_' => {}
        _ => return false,
    }
    b.len() <= 32 && b[1..].iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_')
}

/// The type letter of one JSON value (brief C1): s string, n number,
/// b bool, o object, a array, z null.
fn type_letter(v: &J) -> char {
    match v {
        J::String(_) => 's',
        J::Number(_) => 'n',
        J::Bool(_) => 'b',
        J::Object(_) => 'o',
        J::Array(_) => 'a',
        J::Null => 'z',
    }
}

/// A key's printed form: itself when identifier-shaped, else
/// `k:<sha256-12>` — never the raw name. `pub(crate)` so the batch-27d
/// Media.db/Res.db sections render key names under the SAME privacy
/// rule as `--content-shape` (schema-shaped names print, anything else
/// fingerprints).
pub(crate) fn render_key(k: &str) -> String {
    if is_identifier_key(k) {
        k.to_string()
    } else {
        format!("k:{}", super::sha12(k.as_bytes()))
    }
}

/// The signature of one top-level JSON object (the ONE shared builder,
/// used by both the C1 report and the C2 probe): sorted keys, each
/// `key:<letter>`, one level of nesting for string values that parse
/// as JSON objects, capped at [`MAX_SIG_KEYS`] entries with `…+N`.
///
/// Sorting is by the RENDERED key form, so the printed list is
/// alphabetical exactly as it reads — two DBs describe the same shape
/// with the same string. Inner lists get the same cap inside the
/// braces; inner values are letters only (one level, no deeper).
pub fn object_signature(m: &serde_json::Map<String, J>) -> String {
    let mut entries: Vec<(String, String)> = Vec::with_capacity(m.len());
    for (k, v) in m {
        let rk = render_key(k);
        let mut e = format!("{}:{}", rk, type_letter(v));
        if let J::String(s) = v {
            if let Ok(J::Object(inner)) = serde_json::from_str::<J>(s) {
                e.push_str(&inner_signature(&inner));
            }
        }
        entries.push((rk, e));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let shown: Vec<&str> = entries.iter().take(MAX_SIG_KEYS).map(|(_, e)| e.as_str()).collect();
    let mut out = format!("{{{}}}", shown.join(","));
    if entries.len() > MAX_SIG_KEYS {
        out = format!("{{{},…+{}}}", shown.join(","), entries.len() - MAX_SIG_KEYS);
    }
    out
}

/// The one-level nesting suffix `key{…}`: inner keys as `name:letter`,
/// sorted by rendered form, capped at [`MAX_SIG_KEYS`] with `…+N`.
fn inner_signature(inner: &serde_json::Map<String, J>) -> String {
    let mut entries: Vec<(String, String)> = Vec::with_capacity(inner.len());
    for (k, v) in inner {
        let rk = render_key(k);
        entries.push((rk.clone(), format!("{}:{}", rk, type_letter(v))));
    }
    entries.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let shown: Vec<&str> = entries.iter().take(MAX_SIG_KEYS).map(|(_, e)| e.as_str()).collect();
    let mut out = format!("{{{}}}", shown.join(","));
    if entries.len() > MAX_SIG_KEYS {
        out = format!("{{{},…+{}}}", shown.join(","), entries.len() - MAX_SIG_KEYS);
    }
    out
}

/// One group of the final report: the RENDERED code token plus its
/// counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShapeReportGroup {
    /// The rendered code token (`19`, `chat.photo`, `NULL`,
    /// `text(len=…,h12=…)`, …) — never a raw value.
    pub code: String,
    pub group: ShapeGroup,
}

/// Cap the groups (brief C1): the [`MAX_CODES`] codes with the most
/// rows (ties broken by rendered code token, ascending — BTreeMap
/// order makes this deterministic) keep their own block, in ranked
/// order; every remaining code merges into the `other` group, which
/// always prints LAST. Nothing is dropped — `other.rows` plus the
/// kept rows equal the total.
pub fn cap_groups(groups: BTreeMap<String, ShapeGroup>) -> Vec<ShapeReportGroup> {
    let mut all: Vec<(String, ShapeGroup)> = groups.into_iter().collect();
    all.sort_by(|a, b| {
        b.1.rows
            .cmp(&a.1.rows)
            .then_with(|| a.0.cmp(&b.0))
    });
    let mut out: Vec<ShapeReportGroup> = Vec::new();
    let mut other = ShapeGroup::default();
    let mut has_other = false;
    for (i, (code, g)) in all.into_iter().enumerate() {
        if i < MAX_CODES {
            out.push(ShapeReportGroup { code, group: g });
        } else {
            has_other = true;
            other.rows += g.rows;
            other.json_object += g.json_object;
            other.json_array += g.json_array;
            other.json_string_scalar += g.json_string_scalar;
            other.not_json += g.not_json;
            other.null += g.null;
            for (sig, n) in g.sigs {
                *other.sigs.entry(sig).or_insert(0) += n;
            }
        }
    }
    if has_other {
        out.push(ShapeReportGroup {
            code: OTHER_LABEL.to_string(),
            group: other,
        });
    }
    out
}

/// The top `n` signatures of one group: count descending, ties by
/// signature ascending (deterministic — SQLite's arbitrary order
/// never reaches the report).
pub fn top_sigs(g: &ShapeGroup, n: usize) -> Vec<(String, usize)> {
    let mut v: Vec<(String, usize)> = g.sigs.iter().map(|(s, c)| (s.clone(), *c)).collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v.truncate(n);
    v
}

/// One group's report block (shared by C1 and C2): the counters line
/// plus the top-[`TOP_SIGS`] signature lines. `key_name` is the
/// grouping column's semantic — `code` on the Desktop side, `msgType`
/// on the shadow side.
pub fn group_block(prefix: &str, key_name: &str, g: &ShapeReportGroup) -> Vec<String> {
    let s = &g.group;
    let mut lines = vec![format!(
        "{prefix} {key_name}={} rows={} json_object={} json_array={} \
         json_string_scalar={} not_json={} null={}",
        g.code, s.rows, s.json_object, s.json_array, s.json_string_scalar, s.not_json, s.null
    )];
    for (sig, n) in top_sigs(s, TOP_SIGS) {
        lines.push(format!("{prefix}  {sig} x {n}"));
    }
    lines
}

// --- the --out JSON document ---------------------------------------------

/// One signature with its count.
#[derive(Debug, Clone, Serialize)]
pub struct SigJson {
    pub sig: String,
    pub count: usize,
}

/// One group as JSON: exactly what the text block prints.
#[derive(Debug, Clone, Serialize)]
pub struct GroupJson {
    /// The RENDERED code token — never a raw value.
    pub code: String,
    pub rows: usize,
    pub json_object: usize,
    pub json_array: usize,
    pub json_string_scalar: usize,
    pub not_json: usize,
    pub null: usize,
    /// The top [`TOP_SIGS`] signatures, same order as the text.
    pub signatures: Vec<SigJson>,
}

impl From<&ShapeReportGroup> for GroupJson {
    fn from(g: &ShapeReportGroup) -> Self {
        GroupJson {
            code: g.code.clone(),
            rows: g.group.rows,
            json_object: g.group.json_object,
            json_array: g.group.json_array,
            json_string_scalar: g.group.json_string_scalar,
            not_json: g.group.not_json,
            null: g.group.null,
            signatures: top_sigs(&g.group, TOP_SIGS)
                .into_iter()
                .map(|(sig, count)| SigJson { sig, count })
                .collect(),
        }
    }
}

/// The `--out` JSON document (brief C1: "the same data as JSON") —
/// the capped groups with the same top-8 signatures the text prints.
#[derive(Debug, Clone, Serialize)]
pub struct ContentShapeJson {
    pub spec: String,
    pub by: String,
    /// The sample's `Core/...` source, or `ALL` with `--all-dbs`.
    pub source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dbs: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opened: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed: Option<usize>,
    pub total_rows: usize,
    pub groups: Vec<GroupJson>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj_of(v: J) -> serde_json::Map<String, J> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn double_encoded_object_text_gets_a_str_prefixed_signature() {
        let mut g = ShapeGroup::default();
        // Desktop shape: a JSON string whose text is a JSON object.
        let inner = r#"{"title":"SENTINEL_VALUE_1","href":"x","params":"{\"fileSize\":\"9\"}"}"#;
        let cell = serde_json::to_string(&J::String(inner.into())).unwrap();
        g.fold_cell(&SV::Text(cell));
        // A plain JSON string scalar gets only a shape class.
        g.fold_cell(&SV::Text(r#""SENTINEL text""#.into()));
        assert_eq!(g.rows, 2);
        assert_eq!(g.json_string_scalar, 2);
        assert_eq!(g.json_object, 0);
        let top = top_sigs(&g, 8);
        assert_eq!(top.len(), 2);
        let obj = top.iter().find(|(s, _)| s.starts_with("str:{")).unwrap();
        assert!(obj.0.contains("params:s{fileSize:s}"), "{:?}", top);
        assert!(top.iter().any(|(s, _)| s == "str:text len<=16 ascii+sp start=alpha"), "{:?}", top);
        for (s, _) in &top {
            assert!(!s.contains("SENTINEL"), "values must never appear: {s}");
        }
    }

    #[test]
    fn signature_letters_sorting_and_nesting() {
        // Every type letter, alphabetical order, and the one-level
        // nesting for a string that parses as a JSON object.
        let m = obj_of(json!({
            "title": "SENTINEL-T",
            "params": "{\"fileExt\":\"pdf\",\"fileSize\":\"12345\"}",
            "count": 7,
            "flag": true,
            "meta": {"inner": 1},
            "list": [1, 2],
            "none": null,
            "href": "https://sentinel.example/x"
        }));
        assert_eq!(
            object_signature(&m),
            "{count:n,flag:b,href:s,list:a,meta:o,none:z,\
             params:s{fileExt:s,fileSize:s},title:s}"
        );
        // A string that parses as an ARRAY/scalar/number stays a
        // plain `s` — only objects get the brace detail.
        let m = obj_of(json!({
            "arr": "[1,2]", "str": "\"quoted\"", "num": "123", "txt": "prose"
        }));
        assert_eq!(object_signature(&m), "{arr:s,num:s,str:s,txt:s}");
        // Inner values are LETTERS ONLY — no second nesting level.
        let m = obj_of(json!({
            "params": "{\"deep\":\"{\\\"x\\\":1}\"}"
        }));
        assert_eq!(object_signature(&m), "{params:s{deep:s}}");
        // Empty objects stay `{}`; an empty inner list stays `{}`.
        let m = obj_of(json!({"a": {}, "b": "{}"}));
        assert_eq!(object_signature(&m), "{a:o,b:s{}}");
    }

    #[test]
    fn non_identifier_keys_print_their_fingerprint_only() {
        // The brief's rule: only ^[A-Za-z_][A-Za-z0-9_]{0,31}$ prints
        // as-is; anything else is k:<sha256-12>.
        let f = |k: &str| render_key(k);
        assert_eq!(f("a"), "a");
        assert_eq!(f("_x"), "_x");
        assert_eq!(f("z".repeat(32).as_str()), "z".repeat(32));
        for hashed in [
            "1abc",               // leading digit
            "a-b",                // hyphen is not in the rule
            "a b",                // space
            "a.b",                // dot
            "ünïcödé",            // non-ASCII
            "",                   // empty
            "z".repeat(33).as_str(), // 33 chars
            "a\nb",               // control char
        ] {
            let out = f(hashed);
            assert_ne!(out, hashed, "{hashed:?} must be fingerprinted");
            assert_eq!(out, format!("k:{}", super::super::sha12(hashed.as_bytes())), "{hashed:?}");
            assert!(out.starts_with("k:") && out.len() == 2 + 12, "{hashed:?} -> {out}");
        }
        // The hashed form sits in the sorted signature like any key.
        let m = obj_of(json!({"we ird!": 1, "aa": 2}));
        let sig = object_signature(&m);
        assert!(sig.starts_with("{aa:n,k:"), "{sig}");
        assert!(!sig.contains("we ird"), "never the raw name: {sig}");
    }

    #[test]
    fn signature_caps_at_twenty_four_keys_inside_and_out() {
        // 30 top-level keys: 24 sorted entries + …+6.
        let mut m = serde_json::Map::new();
        for i in 0..30 {
            m.insert(format!("k{i:02}"), json!(1));
        }
        let sig = object_signature(&m);
        assert!(sig.starts_with("{k00:n,k01:n"), "{sig}");
        assert!(sig.ends_with("k23:n,…+6}"), "{sig}");
        assert!(!sig.contains("k24"), "{sig}");
        // 24 keys exactly: no marker.
        let mut m24 = serde_json::Map::new();
        for i in 0..24 {
            m24.insert(format!("k{i:02}"), json!(1));
        }
        let sig = object_signature(&m24);
        assert!(sig.ends_with("k23:n}"), "{sig}");
        assert!(!sig.contains("…"), "{sig}");
        // The inner list gets the same cap inside the braces (30 inner
        // keys: i00..i29).
        let inner = format!(
            "{{{}}}",
            (0..30)
                .map(|i| format!("\"i{i:02}\":1"))
                .collect::<Vec<_>>()
                .join(",")
        );
        let m = obj_of(json!({ "params": inner }));
        let sig = object_signature(&m);
        assert!(
            sig.starts_with("{params:s{i00:n,i01:n") && sig.ends_with("i23:n,…+6}}"),
            "{sig}"
        );
        assert!(!sig.contains("i24"), "{sig}");
    }

    #[test]
    fn fold_cell_classifies_the_five_buckets() {
        let mut g = ShapeGroup::default();
        // json_object (with its signature), array, string scalar…
        g.fold_cell(&SV::Text(r#"{"a":1}"#.into()));
        g.fold_cell(&SV::Text("[1,2]".into()));
        g.fold_cell(&SV::Text("\"quoted\"".into()));
        // …prose, a JSON number/bool/null scalar text, a blob and an
        // INTEGER cell are all not_json…
        g.fold_cell(&SV::Text("prose SENTINEL".into()));
        g.fold_cell(&SV::Text("123".into()));
        g.fold_cell(&SV::Text("null".into()));
        g.fold_cell(&SV::Blob(vec![1, 2]));
        g.fold_cell(&SV::Integer(9));
        // …and SQL NULL is null.
        g.fold_cell(&SV::Null);
        assert_eq!(
            g,
            ShapeGroup {
                rows: 9,
                json_object: 1,
                json_array: 1,
                json_string_scalar: 1,
                not_json: 5,
                null: 1,
                sigs: BTreeMap::from([
                    ("{a:n}".to_string(), 1),
                    ("str:text len<=16 ascii start=alpha".to_string(), 1),
                ]),
            }
        );
    }

    #[test]
    fn fold_content_json_matches_the_desktop_classification() {
        // The shadow side folds the payload's $.content JSON value:
        // an object → json_object with the signature straight from
        // it; a string → the SHARED text path (so a content string
        // holding JSON-object text classifies exactly like the
        // Desktop column); array/number/absent/Null fill the rest.
        let mut g = ShapeGroup::default();
        g.fold_content_json(Some(&json!({"href": "https://sentinel.example/x"})));
        g.fold_content_json(Some(&json!("{\"a\":1}")));
        g.fold_content_json(Some(&json!([1, 2])));
        // …a string content that IS a quoted JSON string…
        g.fold_content_json(Some(&json!("\"quoted SENTINEL\"")));
        g.fold_content_json(Some(&json!(7)));
        g.fold_content_json(Some(&J::Null));
        g.fold_content_json(None);
        assert_eq!(g.rows, 7);
        assert_eq!(g.json_object, 2, "the object value and the object-as-string");
        assert_eq!(g.json_array, 1);
        assert_eq!(g.json_string_scalar, 1, "a content string that is a quoted JSON string");
        assert_eq!(g.not_json, 1, "a JSON number content");
        assert_eq!(g.null, 2, "J::Null and an absent $.content");
        assert_eq!(
            g.sigs,
            BTreeMap::from([
                ("{a:n}".to_string(), 1),
                ("{href:s}".to_string(), 1),
                ("str:text len<=16 ascii+sp start=alpha".to_string(), 1),
            ])
        );
    }

    #[test]
    fn cap_groups_keeps_sixtyfour_and_merges_the_rest_into_other() {
        // 70 codes; code i carries i+1 rows, so the ranking is fixed.
        let mut groups = BTreeMap::new();
        for i in 0..70 {
            let mut g = ShapeGroup::default();
            g.rows = i + 1;
            groups.insert(format!("c{i:02}"), g);
        }
        let capped = cap_groups(groups);
        assert_eq!(capped.len(), MAX_CODES + 1, "64 kept + other");
        // Ranked by rows descending: the biggest code first.
        assert_eq!(capped[0].code, "c69");
        assert_eq!(capped[0].group.rows, 70);
        // The kept set is the 64 largest (c06..c69); other is LAST.
        assert_eq!(capped[63].code, "c06");
        assert_eq!(capped[64].code, OTHER_LABEL);
        assert_eq!(capped[64].group.rows, 1 + 2 + 3 + 4 + 5 + 6, "c00..c05");
        // Nothing is dropped: kept + other = the grand total.
        let total: usize = capped.iter().map(|g| g.group.rows).sum();
        assert_eq!(total, (1..=70).sum::<usize>());
        // 64 codes or fewer: no other group at all.
        let small: BTreeMap<String, ShapeGroup> =
            (0..3).map(|i| (format!("c{i}"), ShapeGroup { rows: i + 1, ..Default::default() }))
                .collect();
        let capped = cap_groups(small);
        assert_eq!(capped.len(), 3);
        assert!(!capped.iter().any(|g| g.code == OTHER_LABEL));
        // Rows ties break by code token ascending (deterministic).
        let tie: BTreeMap<String, ShapeGroup> = ["b", "a"].iter().map(|c| {
            (c.to_string(), ShapeGroup { rows: 2, ..Default::default() })
        }).collect();
        let capped = cap_groups(tie);
        assert_eq!(capped[0].code, "a");
        assert_eq!(capped[1].code, "b");
    }

    #[test]
    fn group_block_and_json_never_carry_a_content_value() {
        // The batch-23a privacy rule, end to end over the shared
        // report forms: feed contents carrying unique SENTINEL values
        // and assert none appears in ANY output line — nor in the
        // serialized --out JSON.
        let sentinels = [
            "SENTINEL-PROSE-WORDS",
            "https://sentinel-host.example/a/b?c=1",
            "SENTINEL-TITLE-TEXT",
            "SENTINEL-FILE-EXT",
            "9876543210987654321098",
        ];
        let mut g = ShapeGroup::default();
        // Prose with a sentinel url and words inside.
        g.fold_cell(&SV::Text(
            "see https://sentinel-host.example/a/b?c=1 — SENTINEL-PROSE-WORDS here".into(),
        ));
        // An object whose VALUES carry sentinels (title, href, ext,
        // a long numeric string)…
        g.fold_cell(&SV::Text(
            r#"{"href":"https://sentinel-host.example/a/b?c=1",
                "params":"{\"fileExt\":\"SENTINEL-FILE-EXT\",\"fileSize\":\"9876543210987654321098\"}",
                "title":"SENTINEL-TITLE-TEXT","type":"file"}"#
                .replace('\n', "")
                .as_str()
                .into(),
        ));
        // …a non-identifier key carrying a sentinel INSIDE the name…
        g.fold_cell(&SV::Text(
            r#"{"SENTINEL-KEY-NAME!": 1, "ok": "x"}"#.into(),
        ));
        // …and a not-JSON cell whose code token is a long sentence.
        let mut groups = BTreeMap::new();
        groups.insert("code-token-1".to_string(), g);
        groups.insert(
            "text(len=35,h12=000000000000)".to_string(),
            ShapeGroup { rows: 1, ..Default::default() },
        );
        let capped = cap_groups(groups);
        let mut lines: Vec<String> = Vec::new();
        for grp in &capped {
            lines.extend(group_block("content-shape:", "code", grp));
        }
        let json = serde_json::to_string_pretty(&ContentShapeJson {
            spec: "one2one:message.message".into(),
            by: "msgType".into(),
            source: "ALL".into(),
            dbs: Some(2),
            opened: Some(2),
            failed: Some(0),
            total_rows: capped.iter().map(|g| g.group.rows).sum(),
            groups: capped.iter().map(Into::into).collect(),
        })
        .unwrap();
        let all = lines.join("\n") + "\n" + &json;
        for s in sentinels {
            assert!(!all.contains(s), "{s} leaked:\n{all}");
        }
        // The expected shape lines DID print — key names, letters and
        // the hashed key form only.
        let joined = lines.join("\n");
        assert!(
            joined.contains(
                "content-shape: code=code-token-1 rows=3 json_object=2 json_array=0 \
                 json_string_scalar=0 not_json=1 null=0"
            ),
            "{joined}"
        );
        assert!(
            joined.contains("content-shape:  {href:s,params:s{fileExt:s,fileSize:s},title:s,type:s} x 1"),
            "{joined}"
        );
        assert!(
            joined.contains(&format!("content-shape:  {{k:{}:n,ok:s}} x 1", super::super::sha12(b"SENTINEL-KEY-NAME!"))),
            "{joined}"
        );
        // The JSON mirrors the text (same groups, same top-8 sigs).
        assert!(json.contains("\"json_object\": 2"), "{json}");
        assert!(json.contains("\"spec\": \"one2one:message.message\""), "{json}");
        assert!(json.contains("\"dbs\": 2"), "{json}");
    }

    #[test]
    fn top_sigs_order_by_count_then_name_and_cap() {
        let mut g = ShapeGroup::default();
        for (sig, n) in [("{b:s}", 2usize), ("{a:s}", 5), ("{c:s}", 5), ("{d:s}", 1)] {
            g.sigs.insert(sig.to_string(), n);
        }
        let top = top_sigs(&g, 3);
        assert_eq!(
            top,
            vec![("{a:s}".to_string(), 5), ("{c:s}".to_string(), 5), ("{b:s}".to_string(), 2)]
        );
        // The cap is a plain truncation of the ranked list.
        assert_eq!(top_sigs(&g, 2).len(), 2);
        assert!(top_sigs(&g, 0).is_empty());
    }
}
