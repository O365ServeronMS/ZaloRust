//! Content-agreement probe (batch 23b T1): what encoding does the
//! Desktop `message` column use?
//!
//! Batch 23a's shape census established that EVERY Desktop
//! `message.message` cell, for every msgType code, is a JSON string
//! scalar — but after ONE unwrap the inner text is neither JSON nor
//! plain text (webchat starts with a NON-alphanumeric char; media
//! codes start with a letter, contain spaces and have no `":`
//! key/value joint). So the import's `content` column may hold an
//! encoded or obfuscated form, and `import --apply` (2.5) must not
//! run until it is understood. Batches 14/15 only ever compared
//! msgId, ts and sender — never content. This probe is that missing
//! comparison: it joins the Desktop message rows to the shadow copy
//! by msgId (the batch-15 way, over EVERY mapped message DB) and
//! asks, per wire msgType family, WHICH transform — if any — turns
//! the Desktop text into the shadow's `$.content`.
//!
//! Batch 24 D3 adds the `decrypted` section per family: batch 23b's
//! candidate transforms are now ANSWERED (Claude read the Desktop
//! app code — the column is `BasicEncryption`-XORed with the same
//! passphrase that opens the DB), so every matched pair's RAW cell
//! additionally runs through `desktop_cipher::decode_field` with the
//! snapshot passphrase (in memory only, never printed). Per family:
//! the decode outcome counts (`decoded` / `not_encrypted` /
//! `failed`, over the pairs with a cell to decode); for a string `S`
//! whether the decoded value equals it (`eq`, `eq_trim`); for an
//! object `S` whether the decoded object has the SAME key set, and
//! per identifier-shaped key whether the decoded object's string
//! value is equal (`obj_eq[key]=n/m`). Counts only — never a decoded
//! value.
//!
//! Per matched pair:
//! - `D` = the Desktop content cell after ONE JSON-string unwrap
//!   (the raw text when it does not unwrap; NULL/BLOB → the pair is
//!   counted `d_missing`, never tested);
//! - `S` = the shadow payload's `$.content`.
//!
//! String `S` (webchat and the like): `eq`, `eq_trim`,
//! `d_contains_s`, `s_contains_d`, `eq_after_drop_k` (k = 1..=4,
//! recording WHICH k), `eq_b64`, `eq_reversed`, `eq_char_shift`
//! (delta -64..=64, recording WHICH delta), `eq_xor_byte` (recording
//! WHICH byte), and the `len(D)-len(S)` relation in the buckets
//! `<-8, -8..-1, 0, 1..8, >8`. `eq_nfc` is SKIPPED and said so in
//! the report: NFC normalization needs the Unicode data tables and
//! the no-new-crate rule forbids adding them.
//!
//! Object `S` (media): per identifier-shaped key of `S` whose value
//! is a non-empty string, whether D contains that value verbatim
//! (`d_contains[key]`); the length relation of D to the SERIALIZED
//! `S`; and whether D, after the same candidate transforms (drop-k,
//! b64, char-shift with the delta found above on the string side —
//! scanning -64..=64 when the string side found none), parses as a
//! JSON object with the SAME key set (`transform_parses`).
//!
//! PRIVACY (the batch hard rule): the output is COUNTS ONLY —
//! booleans tallied per test per msgType family plus small integer
//! parameters (the matching k / delta / byte). Never a content
//! value, id, prefix/suffix or hash of content. The wire msgType
//! tokens print code-like verbatim, else their h12 (the batch-23a
//! rule), and the shadow content's identifier-shaped KEY NAMES print
//! (as in `content_shape`); type vocabulary is allowed. The unit
//! tests feed SENTINEL-laden data and assert no output line carries
//! it.
//!
//! Inputs (all required; `#[ignore]`d — the REVIEWER runs this on the
//! real pair, same contract as `probe_import_codes`):
//! - `ZR_SNAPSHOT_DIR` — a cold snapshot made by tools/snapshot.ps1;
//! - `ZR_D7_KEY_FILE`  — the DPAPI-wrapped D7 key capture;
//! - `ZR_UIN_HASH`     — the expected sha256-12 of that key;
//! - `ZR_MAPPING`      — the mapping JSON (its message entity names
//!   the msgId and content source columns).
//! The shadow DB is a temp COPY of the live store
//! (`probe_util::open_copy`; `ZR_PROBE_DIR` overrides the source).
//!
//! Run (reviewer step, real data):
//! ```text
//! cargo test --lib probe_import_content_agree -- --ignored --nocapture
//! ```
//!
//! The classifiers (`desktop_text`, `classify_string`,
//! `classify_object`, `decrypted_string`, `decrypted_object`), the
//! folds and the whole report are PURE and unit-tested below,
//! including an end-to-end pass on synthetic DBs; only the
//! snapshot/shadow I/O lives in the ignored test.

use std::collections::BTreeMap;

use base64::Engine as _;
use rusqlite::types::Value as SV;
use rusqlite::Connection;
use serde_json::Value as J;

use super::cli::ImportArgs;
use super::import::desktop_cipher::{decode_field, FieldDecode};
use super::import::{self, DbKind};
use super::import::content_shape as cs;
use super::import::inventory::quote_ident;
use super::import_map::{self, FieldRes, MapDb};
use super::probe_shadow_content_shape::msg_type_token;
use super::probe_util;

// --- the pure classifiers ---------------------------------------------------

/// The `len(D)-len(S)` buckets, in the brief's exact vocabulary.
const LEN_BUCKETS: [&str; 5] = ["<-8", "-8..-1", "0", "1..8", ">8"];

/// The object-side candidate transforms, in print order. `char_shift`
/// uses the delta found on the string side; with no delta found it
/// scans -64..=64 (recording any delta that works).
const TRANSFORMS: [&str; 6] = ["drop1", "drop2", "drop3", "drop4", "b64", "char_shift"];

/// The bucket index of `d_len - s_len` (chars): `<-8, -8..-1, 0,
/// 1..8, >8`. Pure.
pub fn len_rel(d_len: usize, s_len: usize) -> usize {
    match d_len as i64 - s_len as i64 {
        i64::MIN..=-9 => 0,
        -8..=-1 => 1,
        0 => 2,
        1..=8 => 3,
        _ => 4,
    }
}

/// ONE JSON-string unwrap of `text`: the inner string when `text`
/// parses as a JSON string scalar, else `text` unchanged (exactly
/// one level — a doubly-encoded string is not unwrapped twice).
pub fn unwrap_once(text: &str) -> String {
    match serde_json::from_str::<J>(text) {
        Ok(J::String(inner)) => inner,
        _ => text.to_string(),
    }
}

/// `D` — the Desktop content cell after ONE JSON-string unwrap (the
/// raw text when it does not unwrap). NULL/BLOB → `None` (no text to
/// test; the pair counts as `d_missing`). INTEGER/REAL coerce to
/// their decimal text (which never unwraps as a JSON string).
pub fn desktop_text(cell: &SV) -> Option<String> {
    let text = match cell {
        SV::Null | SV::Blob(_) => return None,
        SV::Text(s) => s.clone(),
        SV::Integer(i) => i.to_string(),
        SV::Real(f) => f.to_string(),
    };
    Some(unwrap_once(&text))
}

/// Base64-decode `s` to UTF-8 text: the standard and URL-safe
/// alphabets, padded or not (the crate's four general-purpose
/// engines tried in order; `base64` is already a dependency — no new
/// crate). `None` on any invalid char, length or non-UTF-8 result.
pub fn b64_decode_to_utf8(s: &str) -> Option<String> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        if let Ok(bytes) = engine.decode(s) {
            if let Ok(text) = String::from_utf8(bytes) {
                return Some(text);
            }
        }
    }
    None
}

/// `D` minus its first `k` chars equals `S`.
fn drop_k_eq(d: &str, s: &str, k: u8) -> bool {
    let mut it = d.chars();
    for _ in 0..k {
        if it.next().is_none() {
            return false;
        }
    }
    it.as_str() == s
}

/// Every char of `d` shifted by the constant code-point `delta`
/// equals `s`. Empty strings never match (a vacuous shift is not a
/// transform); an out-of-range or surrogate target fails the delta.
fn char_shift_eq(d: &str, s: &str, delta: i64) -> bool {
    let dn = d.chars().count();
    if dn == 0 || dn != s.chars().count() {
        return false;
    }
    d.chars().zip(s.chars()).all(|(dc, sc)| {
        let v = dc as i64 + delta;
        v >= 0 && char::from_u32(v as u32) == Some(sc)
    })
}

/// `d`'s UTF-8 bytes XOR the one constant byte `b` equal `s`'s bytes.
/// Empty strings never match.
fn xor_byte_eq(d: &str, s: &str, b: u8) -> bool {
    let (db, sb) = (d.as_bytes(), s.as_bytes());
    if db.is_empty() || db.len() != sb.len() {
        return false;
    }
    db.iter().zip(sb.iter()).all(|(x, y)| x ^ b == *y)
}

/// One string pair's test results (pure). The parameterized tests
/// record WHICH parameter matched; at most one k, delta or byte can
/// match a non-empty pair.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StringMatch {
    pub eq: bool,
    pub eq_trim: bool,
    pub d_contains_s: bool,
    pub s_contains_d: bool,
    /// The k in 1..=4 whose prefix-drop matched.
    pub drop_k: Option<u8>,
    pub b64: bool,
    pub reversed: bool,
    /// The code-point delta in -64..=64 that matched.
    pub char_shift: Option<i64>,
    /// The byte value in 0..=255 that matched.
    pub xor_byte: Option<u8>,
    /// The `len(D)-len(S)` bucket index.
    pub len_rel: usize,
}

/// Run every string-side test on one pair (pure). `eq_nfc` is
/// deliberately absent: NFC needs the Unicode tables and the
/// no-new-crate rule forbids adding them — the report says so.
pub fn classify_string(d: &str, s: &str) -> StringMatch {
    let mut m = StringMatch {
        eq: d == s,
        eq_trim: d.trim() == s.trim(),
        d_contains_s: !s.is_empty() && d.contains(s),
        s_contains_d: !d.is_empty() && s.contains(d),
        drop_k: None,
        // Empty S never counts as a b64 relation (eq explains it).
        b64: !s.is_empty() && b64_decode_to_utf8(d).as_deref() == Some(s),
        reversed: !d.is_empty() && !s.is_empty() && d.chars().rev().eq(s.chars()),
        char_shift: None,
        xor_byte: None,
        len_rel: len_rel(d.chars().count(), s.chars().count()),
    };
    for k in 1u8..=4 {
        if drop_k_eq(d, s, k) {
            m.drop_k = Some(k);
            break;
        }
    }
    if !d.is_empty() && !s.is_empty() {
        for delta in -64i64..=64 {
            if char_shift_eq(d, s, delta) {
                m.char_shift = Some(delta);
                break;
            }
        }
        for b in 0u8..=255 {
            if xor_byte_eq(d, s, b) {
                m.xor_byte = Some(b);
                break;
            }
        }
    }
    m
}

/// `text` shifted by `delta` — `None` when any target char is out of
/// range or a surrogate (the transform cannot produce text then).
fn shift_chars(text: &str, delta: i64) -> Option<String> {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        let v = c as i64 + delta;
        out.push(u32::try_from(v).ok().and_then(char::from_u32)?);
    }
    Some(out)
}

/// Does `text` parse as a JSON object with the SAME key set as `s`?
fn parses_with_same_keys(text: &str, s: &serde_json::Map<String, J>) -> bool {
    let Ok(J::Object(o)) = serde_json::from_str::<J>(text) else {
        return false;
    };
    let want: std::collections::BTreeSet<&str> = s.keys().map(String::as_str).collect();
    let got: std::collections::BTreeSet<&str> = o.keys().map(String::as_str).collect();
    got == want
}

/// One object pair's test results (pure). `d_contains` carries only
/// the identifier-shaped keys of `S` whose values are non-empty
/// strings (non-identifier keys are not examined and never print);
/// `transform_parses` carries the six candidate transforms.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ObjectMatch {
    /// key → does D contain that value verbatim?
    pub d_contains: BTreeMap<String, bool>,
    /// `len(D) - len(serialized S)` bucket index.
    pub len_rel: usize,
    /// transform → does transformed D parse as a JSON object with
    /// the same key set as S?
    pub transform_parses: BTreeMap<String, bool>,
    /// The char-shift delta that matched, when `char_shift` did.
    pub char_shift_delta: Option<i64>,
}

/// Run every object-side test on one pair (pure). `deltas` are the
/// deltas found on the string side of the SAME run ("the delta found
/// above"); empty → the full -64..=64 scan.
pub fn classify_object(
    d: &str,
    s: &serde_json::Map<String, J>,
    deltas: &[i64],
) -> ObjectMatch {
    let mut out = ObjectMatch::default();
    for (k, v) in s {
        if !cs::is_identifier_key(k) {
            continue; // not identifier-shaped: never examined, never printed
        }
        if let J::String(val) = v {
            if !val.is_empty() {
                out.d_contains.insert(k.clone(), d.contains(val.as_str()));
            }
        }
    }
    let serialized = serde_json::to_string(s).unwrap_or_default();
    out.len_rel = len_rel(d.chars().count(), serialized.chars().count());
    for k in 1u8..=4 {
        let dropped: String = d.chars().skip(k as usize).collect();
        out.transform_parses
            .insert(format!("drop{k}"), parses_with_same_keys(&dropped, s));
    }
    let b64_hit = b64_decode_to_utf8(d)
        .map(|t| parses_with_same_keys(&t, s))
        .unwrap_or(false);
    out.transform_parses.insert("b64".into(), b64_hit);
    let tried: Vec<i64> = if deltas.is_empty() {
        (-64..=64).collect()
    } else {
        deltas.to_vec()
    };
    let mut cs_found = false;
    for delta in tried {
        match shift_chars(d, delta) {
            Some(shifted) if parses_with_same_keys(&shifted, s) => {
                cs_found = true;
                out.char_shift_delta = Some(delta);
                break;
            }
            _ => {}
        }
    }
    out.transform_parses.insert("char_shift".into(), cs_found);
    out
}

// --- batch 24 D3: the decrypted section (pure) ------------------------------

/// The decrypted section's STRING-side test (pure): `(eq, eq_trim)`
/// of a decode outcome's value against the shadow string `S`. A
/// `Failed` outcome (no value) is never equal.
pub fn decrypted_string(v: Option<&J>, s: &str) -> (bool, bool) {
    match v.and_then(J::as_str) {
        Some(x) => (x == s, x.trim() == s.trim()),
        None => (false, false),
    }
}

/// The decrypted section's OBJECT-side test (pure): whether the decode
/// outcome's value is an object with `S`'s EXACT key set, plus — per
/// identifier-shaped key of `S` holding a non-empty string — whether
/// the decoded object's value at that key is the SAME string. Other
/// keys are never examined and never print (the `d_contains` privacy
/// rule).
pub fn decrypted_object(
    v: Option<&J>,
    s: &serde_json::Map<String, J>,
) -> (bool, BTreeMap<String, bool>) {
    let vo = v.and_then(J::as_object);
    let same = vo.is_some_and(|o| {
        let want: std::collections::BTreeSet<&str> = s.keys().map(String::as_str).collect();
        let got: std::collections::BTreeSet<&str> = o.keys().map(String::as_str).collect();
        want == got
    });
    let mut eq = BTreeMap::new();
    for (k, sv) in s {
        if !cs::is_identifier_key(k) {
            continue;
        }
        if let J::String(val) = sv {
            if !val.is_empty() {
                eq.insert(k.clone(), vo.is_some_and(|o| o.get(k) == Some(sv)));
            }
        }
    }
    (same, eq)
}

/// The decrypted section's tallies for one family (counts only —
/// never a decoded value).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DecryptedCounters {
    /// Decode outcomes over the family's pairs WITH a cell to decode
    /// (the `d_missing` pairs have nothing to decode and are already
    /// counted in the family header).
    pub decoded: usize,
    pub not_encrypted: usize,
    pub failed: usize,
    /// Pairs whose `S` is a string (the string side's denominator).
    pub string_pairs: usize,
    pub string_eq: usize,
    pub string_eq_trim: usize,
    /// Pairs whose `S` is an object (the object side's denominator).
    pub object_pairs: usize,
    pub object_same_keys: usize,
    /// identifier key of S (non-empty string value) → (equal, examined).
    pub obj_eq: BTreeMap<String, (usize, usize)>,
}

// --- the fold ---------------------------------------------------------------

/// String-side tallies for one family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringCounters {
    pub pairs: usize,
    pub eq: usize,
    pub eq_trim: usize,
    pub d_contains_s: usize,
    pub s_contains_d: usize,
    /// k → how many pairs matched with that k.
    pub drop_k: BTreeMap<u8, usize>,
    pub b64: usize,
    pub reversed: usize,
    /// delta → how many pairs matched with that delta.
    pub char_shift: BTreeMap<i64, usize>,
    /// byte → how many pairs matched with that byte.
    pub xor_byte: BTreeMap<u8, usize>,
    pub len_rel: [usize; 5],
}

impl Default for StringCounters {
    fn default() -> Self {
        StringCounters {
            pairs: 0,
            eq: 0,
            eq_trim: 0,
            d_contains_s: 0,
            s_contains_d: 0,
            drop_k: BTreeMap::new(),
            b64: 0,
            reversed: 0,
            char_shift: BTreeMap::new(),
            xor_byte: BTreeMap::new(),
            len_rel: [0; 5],
        }
    }
}

impl StringCounters {
    pub fn fold(&mut self, m: &StringMatch) {
        self.pairs += 1;
        self.eq += m.eq as usize;
        self.eq_trim += m.eq_trim as usize;
        self.d_contains_s += m.d_contains_s as usize;
        self.s_contains_d += m.s_contains_d as usize;
        if let Some(k) = m.drop_k {
            *self.drop_k.entry(k).or_insert(0) += 1;
        }
        self.b64 += m.b64 as usize;
        self.reversed += m.reversed as usize;
        if let Some(delta) = m.char_shift {
            *self.char_shift.entry(delta).or_insert(0) += 1;
        }
        if let Some(b) = m.xor_byte {
            *self.xor_byte.entry(b).or_insert(0) += 1;
        }
        self.len_rel[m.len_rel] += 1;
    }

    fn drop_total(&self) -> usize {
        self.drop_k.values().sum()
    }
}

/// Object-side tallies for one family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectCounters {
    pub pairs: usize,
    /// key → (how many pairs' D contained the value, keys examined).
    pub d_contains: BTreeMap<String, (usize, usize)>,
    /// transform → how many pairs passed the parse test.
    pub transform_parses: BTreeMap<String, usize>,
    /// delta → how many char-shift parses matched with that delta.
    pub char_shift_deltas: BTreeMap<i64, usize>,
    pub len_rel: [usize; 5],
}

impl Default for ObjectCounters {
    fn default() -> Self {
        ObjectCounters {
            pairs: 0,
            d_contains: BTreeMap::new(),
            transform_parses: BTreeMap::new(),
            char_shift_deltas: BTreeMap::new(),
            len_rel: [0; 5],
        }
    }
}

impl ObjectCounters {
    pub fn fold(&mut self, m: &ObjectMatch) {
        self.pairs += 1;
        for (k, hit) in &m.d_contains {
            let e = self.d_contains.entry(k.clone()).or_insert((0, 0));
            e.1 += 1;
            if *hit {
                e.0 += 1;
            }
        }
        for (t, hit) in &m.transform_parses {
            if *hit {
                *self.transform_parses.entry(t.clone()).or_insert(0) += 1;
            }
        }
        if let Some(delta) = m.char_shift_delta {
            *self.char_shift_deltas.entry(delta).or_insert(0) += 1;
        }
        self.len_rel[m.len_rel] += 1;
    }
}

/// One wire-msgType family's whole tally.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FamilyCounters {
    /// Matched pairs (the msgId join), tested or not.
    pub matched: usize,
    /// Desktop content cell NULL/BLOB — no D to test.
    pub d_missing: usize,
    /// S neither a string nor an object (number, array, bool, null,
    /// absent) — neither side's tests apply.
    pub s_other: usize,
    pub string: StringCounters,
    pub object: ObjectCounters,
    /// (batch 24 D3) The decrypted section.
    pub decrypted: DecryptedCounters,
}

impl FamilyCounters {
    pub fn fold_string(&mut self, m: &StringMatch) {
        self.string.fold(m);
    }
    pub fn fold_object(&mut self, m: &ObjectMatch) {
        self.object.fold(m);
    }
    /// (batch 24 D3) Fold one D-present matched pair's decrypted
    /// section: the RAW cell's decode outcome plus, per side of `S`,
    /// the agreement tests. Counts only — never a decoded value.
    /// Callers skip `d_missing` pairs entirely (nothing to decode).
    pub fn fold_decrypted(&mut self, outcome: &FieldDecode, s: Option<&J>) {
        match outcome {
            FieldDecode::Decoded(_) => self.decrypted.decoded += 1,
            FieldDecode::NotEncrypted(_) => self.decrypted.not_encrypted += 1,
            FieldDecode::Failed(_) => self.decrypted.failed += 1,
        }
        let v = match outcome {
            FieldDecode::Decoded(v) | FieldDecode::NotEncrypted(v) => Some(v),
            FieldDecode::Failed(_) => None,
        };
        match s {
            Some(J::String(s)) => {
                self.decrypted.string_pairs += 1;
                let (eq, eq_trim) = decrypted_string(v, s);
                self.decrypted.string_eq += eq as usize;
                self.decrypted.string_eq_trim += eq_trim as usize;
            }
            Some(J::Object(o)) => {
                self.decrypted.object_pairs += 1;
                let (same, eqm) = decrypted_object(v, o);
                self.decrypted.object_same_keys += same as usize;
                for (k, hit) in eqm {
                    let e = self.decrypted.obj_eq.entry(k).or_insert((0, 0));
                    e.1 += 1;
                    if hit {
                        e.0 += 1;
                    }
                }
            }
            _ => {}
        }
    }
}

/// The grand counters the report header prints.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Grand {
    pub shadow_messages: usize,
    pub desktop_rows: usize,
    pub matched: usize,
    pub no_shadow_match: usize,
    pub dbs: usize,
    pub opened: usize,
    pub failed: usize,
    pub rows_skipped: usize,
}

// --- the report (pure) ------------------------------------------------------

/// One parameter histogram line (`char_shift: delta=3 x 9 total=9`).
fn hist_line<N: std::fmt::Display>(name: &str, param: &str, hist: &BTreeMap<N, usize>) -> String {
    let total: usize = hist.values().sum();
    let body = if hist.is_empty() {
        "none".to_string()
    } else {
        hist.iter()
            .map(|(v, n)| format!("{param}={v} x {n}"))
            .collect::<Vec<_>>()
            .join(" ")
    };
    format!("content-agree:   {name}: {body} total={total}")
}

fn len_line(name: &str, b: &[usize; 5]) -> String {
    format!(
        "content-agree:   {name}: {}={} {}={} 0={} {}={} {}={}",
        LEN_BUCKETS[0], b[0], LEN_BUCKETS[1], b[1], b[2], LEN_BUCKETS[3], b[3], LEN_BUCKETS[4],
        b[4]
    )
}

fn d_contains_line(m: &BTreeMap<String, (usize, usize)>) -> String {
    if m.is_empty() {
        return "content-agree:   d_contains: (none)".into();
    }
    let body = m
        .iter()
        .map(|(k, (hit, tot))| format!("{k}={hit}/{tot}"))
        .collect::<Vec<_>>()
        .join(" ");
    format!("content-agree:   d_contains: {body}")
}

/// (batch 24 D3) The decrypted section's per-key equality line
/// (`eq[key]=n/m`) — key NAMES only, counts only.
fn decrypted_obj_eq_line(m: &BTreeMap<String, (usize, usize)>) -> String {
    if m.is_empty() {
        return "content-agree:   decrypted obj_eq: (none)".into();
    }
    let body = m
        .iter()
        .map(|(k, (eq, tot))| format!("{k}={eq}/{tot}"))
        .collect::<Vec<_>>()
        .join(" ");
    format!("content-agree:   decrypted obj_eq: {body}")
}

/// The whole report: the grand header, the per-family blocks (EVERY
/// test prints, zeros included, so absences are visible) and the
/// short `verdict:` line per family. Pure.
pub fn render(families: &BTreeMap<String, FamilyCounters>, grand: &Grand) -> Vec<String> {
    let mut lines = vec![
        format!(
            "content-agree: shadow messages={} desktop_rows={} matched={} no_shadow_match={}",
            grand.shadow_messages, grand.desktop_rows, grand.matched, grand.no_shadow_match
        ),
        format!(
            "content-agree: message DBs considered={} opened={} failed={} rows_skipped={}",
            grand.dbs, grand.opened, grand.failed, grand.rows_skipped
        ),
        String::from(
            "content-agree: eq_nfc: skipped (no NFC normalization without a new crate; \
             the brief allows skipping it)",
        ),
    ];
    if families.is_empty() {
        lines.push(String::from("content-agree: no matched pairs - nothing to classify"));
        return lines;
    }
    for (token, f) in families {
        lines.push(format!(
            "content-agree: msgType={token} matched={} string_pairs={} object_pairs={} \
             d_missing={} s_other={}",
            f.matched, f.string.pairs, f.object.pairs, f.d_missing, f.s_other
        ));
        // String side.
        lines.push(format!(
            "content-agree:   eq={} eq_trim={} d_contains_s={} s_contains_d={}",
            f.string.eq, f.string.eq_trim, f.string.d_contains_s, f.string.s_contains_d
        ));
        lines.push(format!(
            "content-agree:   drop_k: k=1:{} k=2:{} k=3:{} k=4:{} total={}",
            f.string.drop_k.get(&1).copied().unwrap_or(0),
            f.string.drop_k.get(&2).copied().unwrap_or(0),
            f.string.drop_k.get(&3).copied().unwrap_or(0),
            f.string.drop_k.get(&4).copied().unwrap_or(0),
            f.string.drop_total()
        ));
        lines.push(format!(
            "content-agree:   b64={} reversed={}",
            f.string.b64, f.string.reversed
        ));
        lines.push(hist_line("char_shift", "delta", &f.string.char_shift));
        lines.push(hist_line("xor_byte", "byte", &f.string.xor_byte));
        lines.push(len_line("len_rel", &f.string.len_rel));
        // Object side.
        lines.push(d_contains_line(&f.object.d_contains));
        lines.push(format!(
            "content-agree:   transform_parses: drop1={} drop2={} drop3={} drop4={} b64={} \
             char_shift={}",
            f.object.transform_parses.get("drop1").copied().unwrap_or(0),
            f.object.transform_parses.get("drop2").copied().unwrap_or(0),
            f.object.transform_parses.get("drop3").copied().unwrap_or(0),
            f.object.transform_parses.get("drop4").copied().unwrap_or(0),
            f.object.transform_parses.get("b64").copied().unwrap_or(0),
            f.object.transform_parses.get("char_shift").copied().unwrap_or(0)
        ));
        lines.push(len_line("len_rel_vs_serialized", &f.object.len_rel));
        // Batch 24 D3: the decrypted section — the decode outcome
        // counts over the D-present pairs, then the per-side
        // agreement tests. Every line prints, zeros included.
        lines.push(format!(
            "content-agree:   decrypted: decoded={} not_encrypted={} failed={}",
            f.decrypted.decoded, f.decrypted.not_encrypted, f.decrypted.failed
        ));
        lines.push(format!(
            "content-agree:   decrypted string: pairs={} eq={} eq_trim={}",
            f.decrypted.string_pairs, f.decrypted.string_eq, f.decrypted.string_eq_trim
        ));
        lines.push(format!(
            "content-agree:   decrypted object: pairs={} same_keys={}",
            f.decrypted.object_pairs, f.decrypted.object_same_keys
        ));
        lines.push(decrypted_obj_eq_line(&f.decrypted.obj_eq));
    }
    for (token, f) in families {
        lines.push(family_verdict(token, f));
    }
    lines
}

/// The highest-count entry of a histogram (ties → the smallest key).
fn dominant<N: Ord + Copy>(hist: &BTreeMap<N, usize>) -> Option<(N, usize)> {
    let mut best: Option<(N, usize)> = None;
    for (v, n) in hist {
        let better = match best {
            None => *n > 0,
            Some((_, bn)) => *n > bn,
        };
        if better {
            best = Some((*v, *n));
        }
    }
    best
}

/// The short per-family verdict: the transform explaining >= 90% of
/// the family's TESTED pairs (priority: eq, drop_k, b64, reversed,
/// char_shift, xor_byte, eq_trim — eq names identity, which also
/// shows up as char_shift delta 0 / xor byte 0 and out-ranks them),
/// else `none` with the best coverage, so the report never hides
/// what the closest candidate was.
pub fn family_verdict(token: &str, f: &FamilyCounters) -> String {
    let tested = f.string.pairs + f.object.pairs;
    if tested == 0 {
        return format!("verdict: {token} none (no testable pairs)");
    }
    let pct = |n: usize| 100.0 * n as f64 / tested as f64;
    let mut drop_hist = f.string.drop_k.clone();
    for k in 1u8..=4 {
        let n = f
            .object
            .transform_parses
            .get(&format!("drop{k}"))
            .copied()
            .unwrap_or(0);
        if n > 0 {
            *drop_hist.entry(k).or_insert(0) += n;
        }
    }
    let mut cs_hist = f.string.char_shift.clone();
    for (delta, n) in &f.object.char_shift_deltas {
        *cs_hist.entry(*delta).or_insert(0) += n;
    }
    let (drop_total, drop_label) = match dominant(&drop_hist) {
        Some((k, n)) => (n, format!("drop_k(k={k})")),
        None => (0, "drop_k".to_string()),
    };
    let (cs_total, cs_label) = match dominant(&cs_hist) {
        Some((d, n)) => (n, format!("char_shift(delta={d})")),
        None => (0, "char_shift".to_string()),
    };
    let (xor_total, xor_label) = match dominant(&f.string.xor_byte) {
        Some((b, n)) => (n, format!("xor_byte(byte={b})")),
        None => (0, "xor_byte".to_string()),
    };
    let cands: Vec<(String, usize)> = vec![
        ("eq".into(), f.string.eq),
        (drop_label, drop_total),
        (
            "b64".into(),
            f.string.b64
                + f.object.transform_parses.get("b64").copied().unwrap_or(0),
        ),
        ("reversed".into(), f.string.reversed),
        (cs_label, cs_total),
        (xor_label, xor_total),
        ("eq_trim".into(), f.string.eq_trim),
    ];
    for (label, count) in &cands {
        if *count > 0 && pct(*count) >= 90.0 {
            return format!("verdict: {token} {label} {:.1}%", pct(*count));
        }
    }
    let mut best: Option<(usize, String)> = None;
    for (label, count) in &cands {
        let better = match &best {
            None => *count > 0,
            Some((bn, _)) => count > bn,
        };
        if better {
            best = Some((*count, label.clone()));
        }
    }
    match best {
        None => format!("verdict: {token} none (no transform matched any pair)"),
        Some((count, label)) => {
            format!("verdict: {token} none (best {label} {:.1}%)", pct(count))
        }
    }
}

// --- the desktop/shadow reads -----------------------------------------------

/// The shadow side of one matched pair: the payload's wire
/// `$.msgType` (the family key's source) and its `$.content`.
#[derive(Debug, Clone, PartialEq)]
pub struct ShadowSide {
    pub msg_type: Option<String>,
    pub content: Option<J>,
}

/// msg_id → payload `$.msgType` + `$.content` for every shadow
/// message, parsed once (a malformed/non-object payload yields
/// None/None — the NULL family, honestly visible). Reads the temp
/// COPY only; a malformed payload would fail the parse, not the
/// query.
pub fn shadow_content_map(conn: &Connection) -> rusqlite::Result<BTreeMap<String, ShadowSide>> {
    let mut st = conn.prepare("SELECT msg_id, payload_json FROM messages")?;
    let rows = st.query_map([], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
    })?;
    let mut out = BTreeMap::new();
    for (id, payload) in rows.flatten() {
        let obj = payload
            .as_deref()
            .and_then(|p| serde_json::from_str::<J>(p).ok())
            .and_then(|v| v.as_object().cloned());
        let (msg_type, content) = match &obj {
            Some(o) => (
                o.get("msgType").and_then(J::as_str).map(str::to_string),
                o.get("content").cloned(),
            ),
            None => (None, None),
        };
        out.insert(id, ShadowSide { msg_type, content });
    }
    Ok(out)
}

/// (batch 23b) One Desktop message row for the join: the msgId, `D`
/// (the cell after ONE JSON-string unwrap) and the RAW cell — the
/// batch-24 decrypted section decodes the raw cell. No row value
/// other than (msgId, D, the raw cell) ever leaves this function.
#[derive(Debug, Clone, PartialEq)]
pub struct DesktopCell {
    pub id: String,
    /// `D` — `None` when the raw cell is NULL/BLOB (a matched pair,
    /// tallied `d_missing`).
    pub d: Option<String>,
    /// The raw SQLite cell, exactly as stored (batch 24 D3 input).
    pub raw: SV,
}

/// (batch 23b) One Desktop message row reduced to the join key plus
/// `D` and the raw cell: the msgId source column and the CONTENT
/// source column the mapping names — nothing else is ever read. Both
/// must be PLAIN column mappings (a const/expr is a mapping product,
/// refused fail-closed exactly like `extract_msg_codes`). Rows whose
/// msgId is NULL/BLOB are skipped and counted; a NULL/BLOB content
/// cell keeps `D = None` (a matched pair, tallied `d_missing`).
pub fn extract_msg_texts(
    conn: &Connection,
    ep: &import_map::EntityPlan,
) -> Result<(Vec<DesktopCell>, usize), String> {
    let col_of = |target: &str| -> Result<String, String> {
        let Some(spec) = ep.fields.iter().find(|f| f.target == target) else {
            return Err(format!(
                "extract_msg_texts: entities.message has no '{target}' target \
                 - the content-agreement probe needs msgId + content"
            ));
        };
        match &spec.res {
            FieldRes::Col(i) => Ok(ep.select[*i].clone()),
            _ => Err(format!(
                "extract_msg_texts: entities.message.columns.{target} must map a PLAIN \
                 source column (a const/expr value is a mapping product, not the raw \
                 Desktop cell)"
            )),
        }
    };
    let id_col = col_of("msgId")?;
    let content_col = col_of("content")?;
    let qt = quote_ident(&ep.table)?;
    let qid = quote_ident(&id_col)?;
    let qc = quote_ident(&content_col)?;
    let sql = format!("SELECT {qid}, {qc} FROM {qt} ORDER BY rowid");
    let mut st = conn
        .prepare(&sql)
        .map_err(|e| format!("{}: {e}", ep.table))?;
    let rows = st
        .query_map([], |r| Ok((r.get::<_, SV>(0)?, r.get::<_, SV>(1)?)))
        .map_err(|e| format!("{}: {e}", ep.table))?;
    let mut out = Vec::new();
    let mut skipped = 0usize;
    for row in rows {
        let (idv, contentv) = row.map_err(|e| format!("{}: {e}", ep.table))?;
        match import_map::sv_str(&idv) {
            Some(id) => out.push(DesktopCell {
                id,
                d: desktop_text(&contentv),
                raw: contentv,
            }),
            None => skipped += 1,
        }
    }
    Ok((out, skipped))
}

/// One buffered matched pair with an OBJECT `S` — folded after all
/// string pairs, so the char-shift test can use the delta(s) found
/// above. Memory stays bounded by the matched-object-pair count.
struct ObjPair {
    token: String,
    d: String,
    obj: serde_json::Map<String, J>,
}

/// The reviewer's probe (batch 23b T1). Everything runs on the cold
/// snapshot through the batch-6 guards and on a temp COPY of the
/// live store — never the live path. Never run by the implementer.
#[test]
#[ignore]
fn probe_import_content_agree() {
    let snap = std::env::var("ZR_SNAPSHOT_DIR")
        .expect("ZR_SNAPSHOT_DIR: point at a cold snapshot (tools/snapshot.ps1 output)");
    let key = std::env::var("ZR_D7_KEY_FILE")
        .expect("ZR_D7_KEY_FILE: the DPAPI-wrapped D7 key capture");
    let uin = std::env::var("ZR_UIN_HASH").expect("ZR_UIN_HASH: the expected sha256-12 of the key");
    let map = std::env::var("ZR_MAPPING")
        .expect("ZR_MAPPING: the mapping JSON (its message entity names the msgId/content columns)");

    // The batch-6 guards run through the normal import prepare:
    // manifest, live-tree refusal, key/uin cross-check, profile.
    let a = ImportArgs {
        from_snapshot: std::path::PathBuf::from(&snap),
        account: "default".into(),
        uin_hash: uin,
        key_file: Some(std::path::PathBuf::from(&key)),
        cipher_compat: None,
        inventory: false,
        out: None,
        mapping: Some(std::path::PathBuf::from(&map)),
        shadow_copy: None,
        delta: false,
        distinct: Vec::new(),
        all_dbs: false,
        own_uid_from_settings: false,
        target: None,
        i_have_a_backup_plan: false,
        unmapped_as_raw: false,
        media_plan: false,
        local_media_probe: false,
        local_media_plan: false,
        local_media_root: None,
        content_shape: None,
        by: None,
        decrypt_basic: false,
        apply: false,
        help: false,
    };
    let p = import::prepare(&a).expect("snapshot guards + key + cipher profile");
    let mapping = import_map::load_mapping_file(std::path::Path::new(&map))
        .expect("loading the mapping JSON");
    let g = import::gather_inventories(&p).expect("gathering the snapshot inventories");
    let plan = import_map::plan(&mapping, &g.inv)
        .unwrap_or_else(|errs| panic!("mapping failed validation:\n  - {}", errs.join("\n  - ")));
    println!(
        "content-agree: plan OK ({}) snapshot one_to_one={} group={} stranger_box={}",
        plan.summary_line(),
        g.one_to_one,
        g.group,
        g.stranger_box
    );
    let Some(ep) = plan.message.as_ref() else {
        println!("content-agree: the mapping maps no message entity - nothing to compare");
        return;
    };
    let kinds = ep.db.clone();

    // The shadow side: a temp COPY of the live store, read-only.
    let (shadow, tmp) = probe_util::open_copy();
    println!("content-agree: shadow copy: {}", tmp.display());
    let smap = shadow_content_map(&shadow).expect("reading the shadow copy's message map");
    println!("content-agree: shadow messages={}", smap.len());

    // EVERY mapped message DB — the batch-15 join, plus the content.
    let msg_dir = p.uid_dir.join("Core").join("Message");
    let mut families: BTreeMap<String, FamilyCounters> = BTreeMap::new();
    let mut obj_pairs: Vec<ObjPair> = Vec::new();
    let mut grand = Grand {
        shadow_messages: smap.len(),
        ..Grand::default()
    };
    for (name, kind) in import::message_db_names(&p.uid_dir).expect("enumerating Core/Message") {
        let map_kind = match kind {
            DbKind::OneToOne(_) => MapDb::OneToOne,
            DbKind::Group(_) => MapDb::Group,
            DbKind::StrangerBox => MapDb::Stranger,
            // `undefined.db` and unknown names stay counted, skipped.
            DbKind::Undefined | DbKind::Other => continue,
        };
        if !kinds.contains(&map_kind) {
            continue;
        }
        grand.dbs += 1;
        match import::open_desktop_db(&msg_dir.join(&name), p.passphrase.as_str(), p.profile) {
            Ok(conn) => match extract_msg_texts(&conn, ep) {
                Ok((pairs, skipped)) => {
                    grand.opened += 1;
                    grand.rows_skipped += skipped;
                    for cell in pairs {
                        grand.desktop_rows += 1;
                        let Some(side) = smap.get(&cell.id) else {
                            grand.no_shadow_match += 1;
                            continue;
                        };
                        grand.matched += 1;
                        let token = match &side.msg_type {
                            Some(mt) => msg_type_token(mt),
                            None => "NULL".to_string(),
                        };
                        let f = families.entry(token.clone()).or_default();
                        f.matched += 1;
                        // Batch 24 D3: the decrypted section — decode
                        // the RAW cell with the snapshot passphrase
                        // (in memory only, never printed) and fold
                        // the outcome + the per-side agreement counts.
                        // d_missing pairs have no cell to decode.
                        if cell.d.is_some() {
                            f.fold_decrypted(
                                &decode_field(&cell.raw, p.passphrase.as_str()),
                                side.content.as_ref(),
                            );
                        }
                        match (&cell.d, &side.content) {
                            (None, _) => f.d_missing += 1,
                            (Some(d), Some(J::String(s))) => {
                                f.fold_string(&classify_string(d, s));
                            }
                            (Some(d), Some(J::Object(o))) => {
                                // Folded after the string side: the
                                // char-shift transform uses the delta
                                // found above.
                                obj_pairs.push(ObjPair {
                                    token,
                                    d: d.clone(),
                                    obj: o.clone(),
                                });
                            }
                            (Some(_), _) => f.s_other += 1,
                        }
                    }
                }
                // The error names the mapping's table/column names —
                // never row data.
                Err(e) => {
                    grand.failed += 1;
                    println!("content-agree: one DB extract failed (skipped): {e}");
                }
            },
            Err(_) => grand.failed += 1,
        }
    }

    // The object side runs with the delta(s) the string side found.
    let mut deltas: Vec<i64> = families
        .values()
        .flat_map(|f| f.string.char_shift.keys().copied())
        .collect();
    deltas.sort();
    deltas.dedup();
    let deltas_s = if deltas.is_empty() {
        "none".to_string()
    } else {
        deltas
            .iter()
            .map(|d| format!("delta={d}"))
            .collect::<Vec<_>>()
            .join(",")
    };
    println!(
        "content-agree: char_shift deltas found on the string side: {deltas_s} \
         (the object side scans -64..=64 when none)"
    );
    for op in &obj_pairs {
        let m = classify_object(&op.d, &op.obj, &deltas);
        families
            .entry(op.token.clone())
            .or_default()
            .fold_object(&m);
    }
    for line in render(&families, &grand) {
        println!("{line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The FAKE passphrase standing in for the snapshot D7 key in the
    /// synthetic decrypted-section tests (batch 24 D3) — never a real
    /// key, never real content.
    const FAKE_KEY: &str = "fakefakefakefakefakefakefake24";

    fn b64_encode(s: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(s.as_bytes())
    }

    fn xor_bytes(s: &str, b: u8) -> String {
        let out: Vec<u8> = s.bytes().map(|x| x ^ b).collect();
        String::from_utf8(out).unwrap()
    }

    fn shift(s: &str, delta: i64) -> String {
        s.chars()
            .map(|c| char::from_u32((c as i64 + delta) as u32).unwrap())
            .collect()
    }

    // --- D and the length buckets ---------------------------------------

    #[test]
    fn desktop_text_unwraps_exactly_one_json_string_level() {
        // A JSON string cell unwraps once…
        let cell = SV::Text(serde_json::to_string(&J::String("inner SENTINEL".into())).unwrap());
        assert_eq!(desktop_text(&cell).as_deref(), Some("inner SENTINEL"));
        // …and only once: a doubly-encoded string keeps its second
        // encoding (the brief's exact rule).
        let twice = serde_json::to_string(&J::String(
            serde_json::to_string(&J::String("deep SENTINEL".into())).unwrap(),
        ))
        .unwrap();
        let cell = SV::Text(twice.clone());
        assert_eq!(
            desktop_text(&cell).as_deref(),
            Some(serde_json::to_string(&J::String("deep SENTINEL".into())).unwrap().as_str())
        );
        // Non-string JSON and prose stay raw.
        for raw in ["prose SENTINEL", "123", "null", "{\"a\":1}", "[1,2]"] {
            assert_eq!(desktop_text(&SV::Text(raw.into())).as_deref(), Some(raw));
        }
        // NULL/BLOB have no D; INTEGER/REAL coerce to decimal text.
        assert_eq!(desktop_text(&SV::Null), None);
        assert_eq!(desktop_text(&SV::Blob(vec![1])), None);
        assert_eq!(desktop_text(&SV::Integer(7)).as_deref(), Some("7"));
    }

    #[test]
    fn len_rel_bucket_boundaries() {
        // d_len - s_len: <-8 | -8..-1 | 0 | 1..8 | >8.
        assert_eq!(len_rel(0, 9), 0, "-9");
        assert_eq!(len_rel(0, 8), 1, "-8");
        assert_eq!(len_rel(9, 10), 1, "-1");
        assert_eq!(len_rel(5, 5), 2, "0");
        assert_eq!(len_rel(6, 5), 3, "1");
        assert_eq!(len_rel(13, 5), 3, "8");
        assert_eq!(len_rel(14, 5), 4, "9");
    }

    // --- every transform, found exactly ---------------------------------

    #[test]
    fn classify_string_finds_each_transform_exactly() {
        // eq — identity (also delta 0 / byte 0, which eq out-ranks).
        let s = "Zalo 23b identity SENTINEL-A mix";
        let m = classify_string(s, s);
        assert!(m.eq && m.eq_trim);
        assert!(m.d_contains_s && m.s_contains_d);
        assert_eq!(m.drop_k, None);
        assert!(!m.b64 && !m.reversed);
        assert_eq!(m.char_shift, Some(0), "identity is delta 0");
        assert_eq!(m.xor_byte, Some(0), "identity is byte 0");
        assert_eq!(m.len_rel, 2);

        // eq_trim — a whitespace-only difference.
        let d = format!(" \t{s} \n ");
        let m = classify_string(&d, s);
        assert!(!m.eq && m.eq_trim);
        assert_eq!(m.drop_k, None);
        assert_eq!(m.char_shift, None, "length differs - no shift can match");
        assert_eq!(m.xor_byte, None);
        assert_eq!(m.len_rel, 3, "+5 chars");

        // eq_after_drop_k — k junk chars in front, k recorded.
        for k in 1u8..=4 {
            let d = format!("{}{s}", "JUNK".chars().take(k as usize).collect::<String>());
            let m = classify_string(&d, s);
            assert!(!m.eq, "k={k}");
            assert_eq!(m.drop_k, Some(k), "the matching k is recorded");
            assert!(m.d_contains_s && !m.s_contains_d);
            assert_eq!(m.char_shift, None);
            assert_eq!(m.xor_byte, None);
            assert_eq!(m.len_rel, 3, "diff = k in 1..8");
        }
        // 5 junk chars: no k in 1..=4 matches.
        let d = format!("JUNKX{s}");
        assert_eq!(classify_string(&d, s).drop_k, None);

        // eq_b64 — D is the standard-alphabet encoding of S.
        let d = b64_encode(s);
        let m = classify_string(&d, s);
        assert!(m.b64, "the b64 round-trip must be found");
        assert!(!m.eq && m.drop_k.is_none() && !m.reversed && !m.eq_trim);
        assert_eq!(m.char_shift, None);
        assert_eq!(m.xor_byte, None);
        assert!(!m.d_contains_s, "the encoded form does not contain the raw value");

        // eq_reversed.
        let d: String = s.chars().rev().collect();
        let m = classify_string(&d, s);
        assert!(m.reversed);
        assert!(!m.eq && !m.eq_trim && m.drop_k.is_none() && !m.b64);
        assert_eq!(m.char_shift, None, "reversal is not a constant shift for mixed text");
        assert_eq!(m.xor_byte, None);

        // eq_char_shift — recorded delta, both signs. The test shifts
        // D BY delta to get S, so a classifier-reported +7 needs
        // D = shift(S, -7).
        let d = shift(s, -7);
        let m = classify_string(&d, s);
        assert_eq!(m.char_shift, Some(7));
        assert!(!m.eq && !m.eq_trim && m.drop_k.is_none() && !m.b64 && !m.reversed);
        assert_eq!(m.xor_byte, None, "a char shift is not a byte xor for mixed text");
        let d = shift(s, 13);
        assert_eq!(classify_string(&d, s).char_shift, Some(-13));

        // eq_xor_byte — a constant byte on the UTF-8 bytes, recorded.
        let s2 = "Zalo 23b xor SENTINEL-B 019";
        let d = xor_bytes(s2, 0x5A);
        let m = classify_string(&d, s2);
        assert_eq!(m.xor_byte, Some(0x5A));
        assert!(!m.eq && !m.eq_trim && m.drop_k.is_none() && !m.b64 && !m.reversed);
        assert_eq!(m.char_shift, None);

        // Nothing matches an unrelated pair.
        let m = classify_string("completely unrelated SENTINEL-C text", "some other SENTINEL-D words");
        assert!(!m.eq && !m.eq_trim && !m.d_contains_s && !m.s_contains_d);
        assert!(m.drop_k.is_none() && !m.b64 && !m.reversed);
        assert_eq!(m.char_shift, None);
        assert_eq!(m.xor_byte, None);
    }

    #[test]
    fn classify_string_never_counts_vacuous_matches() {
        // Empty == empty is identity only: the b64/shift/xor tests
        // never fire on a vacuous pair.
        let m = classify_string("", "");
        assert!(m.eq && m.eq_trim);
        assert!(!m.b64);
        assert_eq!(m.char_shift, None);
        assert_eq!(m.xor_byte, None);
        assert!(!m.d_contains_s && !m.s_contains_d, "empty containment is vacuous");
        // drop_k is a length-determined prefix drop, so it DOES count
        // for an empty S with a <=4-char prefix — length picks the k.
        let m = classify_string("ab", "");
        assert!(!m.eq && !m.eq_trim && !m.b64);
        assert_eq!(m.drop_k, Some(2));
        assert_eq!(m.char_shift, None);
        assert_eq!(m.xor_byte, None);
        // A non-empty pair never matches more than one k/delta/byte.
        let s = "SENTINEL-EDGE text 123";
        let m = classify_string(&format!("qq{s}"), s);
        assert_eq!(m.drop_k, Some(2));
        let m = classify_string(&shift(s, -31), s);
        assert_eq!(m.char_shift, Some(31));
        let m = classify_string(&xor_bytes(s, 0x0F), s);
        assert_eq!(m.xor_byte, Some(0x0F));
    }

    #[test]
    fn b64_decoder_covers_the_four_alphabets_and_rejects_garbage() {
        // Padded and unpadded, standard and URL-safe.
        assert_eq!(b64_decode_to_utf8(&b64_encode("hi SENTINEL")).as_deref(), Some("hi SENTINEL"));
        assert_eq!(b64_decode_to_utf8("aGk").as_deref(), Some("hi"), "unpadded standard");
        assert_eq!(b64_decode_to_utf8("aGk=").as_deref(), Some("hi"));
        // A 4-char group without padding is canonical: the url-safe
        // alphabet also decodes it (to a DIFFERENT third byte).
        assert_eq!(b64_decode_to_utf8("aGk_").as_deref(), Some("hi?"));
        assert_eq!(
            b64_decode_to_utf8(&base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode("url SENTINEL".as_bytes()))
                .as_deref(),
            Some("url SENTINEL")
        );
        // Multi-byte UTF-8 survives; invalid UTF-8 and garbage fail.
        assert_eq!(b64_decode_to_utf8("w6k=").as_deref(), Some("\u{e9}"));
        assert_eq!(b64_decode_to_utf8("/w=="), None, "0xFF is not UTF-8");
        assert_eq!(b64_decode_to_utf8("a Gk="), None, "space is invalid");
        assert_eq!(b64_decode_to_utf8("aGk!"), None);
        assert_eq!(b64_decode_to_utf8("abcde"), None, "length % 4 == 1");
    }

    // --- the object side --------------------------------------------------

    fn media_obj() -> serde_json::Map<String, J> {
        json!({
            "href": "https://sentinel-cdn.example/x.jpg",
            "title": "SENTINEL-TITLE",
            "count": 7,
            "empty": "",
            "we ird!": "SENTINEL-NONID-KEY"
        })
        .as_object()
        .unwrap()
        .clone()
    }

    #[test]
    fn classify_object_drop_b64_and_char_shift() {
        let s = media_obj();
        let ser = serde_json::to_string(&s).unwrap();

        // drop2: two junk chars in front of the serialized object.
        let d = format!("xy{ser}");
        let m = classify_object(&d, &s, &[]);
        assert!(m.transform_parses["drop2"]);
        for t in ["drop1", "drop3", "drop4", "b64", "char_shift"] {
            assert!(!m.transform_parses[t], "{t} must not fire");
        }
        assert_eq!(m.char_shift_delta, None);
        assert!(m.d_contains["href"] && m.d_contains["title"]);
        assert_eq!(m.d_contains.len(), 2, "number/empty/non-identifier values are not keys");
        assert_eq!(m.len_rel, 3, "+2 chars vs the serialized S");

        // b64: D encodes the serialized object — the values are NOT
        // verbatim inside D.
        let d = b64_encode(&ser);
        let m = classify_object(&d, &s, &[]);
        assert!(m.transform_parses["b64"]);
        assert!(!m.d_contains["href"], "the encoded form does not contain the value");
        for t in ["drop1", "drop2", "drop3", "drop4", "char_shift"] {
            assert!(!m.transform_parses[t], "{t} must not fire");
        }

        // char_shift with the delta found above: the test shifts D BY
        // delta to get the parse, so a reported +9 needs
        // D = shift(serialized, -9).
        let d = shift(&ser, -9);
        let m = classify_object(&d, &s, &[9]);
        assert!(m.transform_parses["char_shift"]);
        assert_eq!(m.char_shift_delta, Some(9));
        // With no delta found above, the scan finds the same 9.
        let m = classify_object(&d, &s, &[]);
        assert!(m.transform_parses["char_shift"]);
        assert_eq!(m.char_shift_delta, Some(9));
        // A DIFFERENT delta found above does not match.
        let m = classify_object(&d, &s, &[5]);
        assert!(!m.transform_parses["char_shift"]);

        // A parse with the WRONG key set is not a match.
        let other = json!({"href": "x", "extra": 1}).as_object().unwrap().clone();
        let d = serde_json::to_string(&other).unwrap();
        let m = classify_object(&d, &s, &[]);
        for t in TRANSFORMS {
            assert!(!m.transform_parses[t], "{t} must not fire on a key-set mismatch");
        }
    }

    // --- batch 24 D3: the decrypted section (pure) ----------------------

    #[test]
    fn decrypted_string_classifies_each_outcome() {
        // A decoded value equal to S: eq and eq_trim.
        let v = json!("match me");
        assert_eq!(decrypted_string(Some(&v), "match me"), (true, true));
        // A whitespace-only difference.
        assert_eq!(decrypted_string(Some(&v), "  match me "), (false, true));
        // A non-string decoded value against a string S.
        assert_eq!(decrypted_string(Some(&json!({"a": 1})), "x"), (false, false));
        assert_eq!(decrypted_string(Some(&json!(7)), "x"), (false, false));
        assert_eq!(decrypted_string(Some(&json!("")), "x"), (false, false));
        // A Failed outcome carries no value: never equal.
        assert_eq!(decrypted_string(None, "x"), (false, false));
        // Empty S equals only an empty decoded string.
        assert_eq!(decrypted_string(Some(&json!("")), ""), (true, true));
    }

    #[test]
    fn decrypted_object_classifies_each_outcome() {
        let s = json!({
            "href": "https://sentinel-dec.example/x",
            "title": "SENTINEL-DEC-T",
            "count": 7,
            "empty": "",
            "we ird!": "SENTINEL-DEC-NONID"
        })
        .as_object()
        .unwrap()
        .clone();
        // Same key set: same_keys true even where a string value
        // differs — the per-key eq carries the difference.
        let same_keys = json!({
            "href": "https://sentinel-dec.example/x",
            "title": "different text, same keys",
            "count": 7,
            "empty": "",
            "we ird!": "SENTINEL-DEC-NONID"
        });
        let (ok, eqm) = decrypted_object(Some(&same_keys), &s);
        assert!(ok, "the exact key set matches");
        assert_eq!(
            eqm.len(),
            2,
            "href + title only — number/empty/non-identifier keys are never examined"
        );
        assert!(eqm["href"], "the equal string value");
        assert!(!eqm["title"], "the differing string value");
        // A different key set.
        let (ok2, _) = decrypted_object(Some(&json!({"href": "x", "extra": 1})), &s);
        assert!(!ok2, "an extra key breaks same_keys");
        // Non-object decoded values.
        assert!(!decrypted_object(Some(&json!("x")), &s).0);
        assert!(!decrypted_object(Some(&json!(null)), &s).0);
        // A Failed outcome: no value, but the per-key denominators
        // still count the pair as examined-and-not-equal.
        let (ok3, eq3) = decrypted_object(None, &s);
        assert!(!ok3);
        assert_eq!(eq3.len(), 2);
        assert!(!eq3["href"] && !eq3["title"]);
    }

    #[test]
    fn fold_decrypted_partitions_and_agrees_per_side() {
        let mut f = FamilyCounters::default();
        // A Decoded string pair that agrees, a Failed string pair, an
        // s_other pair (outcome counted, no agreement), a d_missing
        // pair (skipped by the caller, nothing here).
        f.fold_decrypted(
            &FieldDecode::Decoded(json!("SENTINEL-FOLD ok")),
            Some(&json!("SENTINEL-FOLD ok")),
        );
        f.fold_decrypted(
            &FieldDecode::Failed(super::super::import::desktop_cipher::DecodeFail::XorParse),
            Some(&json!("SENTINEL-FOLD other")),
        );
        f.fold_decrypted(&FieldDecode::NotEncrypted(json!(7)), Some(&json!(9)));
        let d = &f.decrypted;
        assert_eq!((d.decoded, d.not_encrypted, d.failed), (1, 1, 1));
        assert_eq!((d.string_pairs, d.string_eq, d.string_eq_trim), (2, 1, 1));
        assert_eq!((d.object_pairs, d.object_same_keys), (0, 0));
        assert!(d.obj_eq.is_empty());
        // An object pair through the fold: same keys + per-key eq.
        f.fold_decrypted(
            &FieldDecode::Decoded(json!({"href": "https://sentinel-fold/x", "title": "T"})),
            Some(&json!({"href": "https://sentinel-fold/x", "title": "other"})),
        );
        let d = &f.decrypted;
        assert_eq!(d.decoded, 2);
        assert_eq!((d.object_pairs, d.object_same_keys), (1, 1));
        assert_eq!(d.obj_eq.get("href"), Some(&(1, 1)));
        assert_eq!(d.obj_eq.get("title"), Some(&(0, 1)));
    }

    // --- the fold, the report and the verdict ----------------------------

    #[test]
    fn render_prints_every_test_and_the_verdict_names_the_explaining_transform() {
        // A webchat family: 9 of 10 string pairs explained by
        // char_shift(+3) -> the verdict names it at 90.0%.
        let mut fam = FamilyCounters::default();
        for i in 0..9 {
            let s = format!("webchat body {i} SENTINEL-PLAIN-{i}");
            let d = shift(&s, -3);
            fam.fold_string(&classify_string(&d, &s));
        }
        fam.fold_string(&classify_string("unrelated SENTINEL-U one", "target SENTINEL-V one"));
        fam.matched = 10;
        // Batch 24 D3: fold the decrypted section over the same 10
        // pairs — 9 decode to exactly S, 1 fails.
        for i in 0..9 {
            let s = format!("webchat body {i} SENTINEL-PLAIN-{i}");
            let sv = json!(s);
            fam.fold_decrypted(&FieldDecode::Decoded(sv.clone()), Some(&sv));
        }
        fam.fold_decrypted(
            &FieldDecode::Failed(super::super::import::desktop_cipher::DecodeFail::XorParse),
            Some(&json!("target SENTINEL-V one")),
        );
        // And a family with no testable pairs at all.
        let mut fam2 = FamilyCounters::default();
        fam2.matched = 2;
        fam2.d_missing = 2;
        let mut families = BTreeMap::new();
        families.insert("webchat".to_string(), fam);
        families.insert("chat.photo".to_string(), fam2);

        let grand = Grand {
            shadow_messages: 12,
            desktop_rows: 11,
            matched: 12,
            no_shadow_match: 0,
            dbs: 3,
            opened: 3,
            failed: 0,
            rows_skipped: 1,
        };
        let lines = render(&families, &grand);
        let joined = lines.join("\n");
        // The grand header lines.
        assert!(
            joined.contains("content-agree: shadow messages=12 desktop_rows=11 matched=12 no_shadow_match=0"),
            "{joined}"
        );
        assert!(
            joined.contains("content-agree: message DBs considered=3 opened=3 failed=0 rows_skipped=1"),
            "{joined}"
        );
        // The skipped-test note says so.
        assert!(
            joined.contains("eq_nfc: skipped (no NFC normalization without a new crate"),
            "{joined}"
        );
        // Every string test prints, zeros included.
        assert!(
            joined.contains("content-agree: msgType=webchat matched=10 string_pairs=10 object_pairs=0 d_missing=0 s_other=0"),
            "{joined}"
        );
        assert!(joined.contains("eq=0 eq_trim=0 d_contains_s=0 s_contains_d=0"), "{joined}");
        assert!(joined.contains("drop_k: k=1:0 k=2:0 k=3:0 k=4:0 total=0"), "{joined}");
        assert!(joined.contains("b64=0 reversed=0"), "{joined}");
        assert!(joined.contains("char_shift: delta=3 x 9 total=9"), "{joined}");
        assert!(joined.contains("xor_byte: none total=0"), "{joined}");
        assert!(
            joined.contains("len_rel: <-8=0 -8..-1=0 0=9 1..8=1 >8=0"),
            "{joined}"
        );
        // The object block prints its zeros for a string-only family.
        assert!(joined.contains("d_contains: (none)"), "{joined}");
        assert!(
            joined.contains("transform_parses: drop1=0 drop2=0 drop3=0 drop4=0 b64=0 char_shift=0"),
            "{joined}"
        );
        // The verdicts.
        assert!(joined.contains("verdict: webchat char_shift(delta=3) 90.0%"), "{joined}");
        assert!(joined.contains("verdict: chat.photo none (no testable pairs)"), "{joined}");
        // Batch 24 D3: the decrypted section lines — the tallies, and
        // the all-zero lines for the d_missing-only family.
        assert!(
            joined.contains("content-agree:   decrypted: decoded=9 not_encrypted=0 failed=1"),
            "{joined}"
        );
        assert!(
            joined.contains("content-agree:   decrypted string: pairs=10 eq=9 eq_trim=9"),
            "{joined}"
        );
        assert!(
            joined.contains("content-agree:   decrypted: decoded=0 not_encrypted=0 failed=0"),
            "{joined}"
        );
        assert!(
            joined.contains("content-agree:   decrypted string: pairs=0 eq=0 eq_trim=0"),
            "{joined}"
        );
        assert!(
            joined.contains("content-agree:   decrypted object: pairs=0 same_keys=0"),
            "{joined}"
        );
        assert!(joined.contains("content-agree:   decrypted obj_eq: (none)"), "{joined}");
        // No content leaked anywhere.
        for sentinel in ["SENTINEL-PLAIN", "SENTINEL-U", "SENTINEL-V"] {
            assert!(!joined.contains(sentinel), "{sentinel} leaked:\n{joined}");
        }
    }

    #[test]
    fn verdict_prefers_eq_over_eq_trim_and_names_none_below_the_bar() {
        // eq beats eq_trim when both explain the family.
        let mut fam = FamilyCounters::default();
        for i in 0..10 {
            let s = format!("same {i} SENTINEL-W");
            fam.fold_string(&classify_string(&s, &s));
        }
        assert_eq!(
            family_verdict("webchat", &fam),
            "verdict: webchat eq 100.0%"
        );
        // Below 90%: none, with the best coverage named.
        let mut fam = FamilyCounters::default();
        for i in 0..10 {
            let s = format!("body {i} SENTINEL-X");
            if i < 3 {
                fam.fold_string(&classify_string(&s, &s));
            } else {
                fam.fold_string(&classify_string(&format!("zzz-{i}"), &s));
            }
        }
        assert_eq!(
            family_verdict("webchat", &fam),
            "verdict: webchat none (best eq 30.0%)"
        );
        // Tested pairs but not a single match.
        let mut fam = FamilyCounters::default();
        for i in 0..4 {
            let s = format!("body {i} SENTINEL-Y");
            fam.fold_string(&classify_string(&format!("zzz-{i}"), &s));
        }
        assert_eq!(
            family_verdict("webchat", &fam),
            "verdict: webchat none (no transform matched any pair)"
        );
    }

    // --- end to end on synthetic DBs --------------------------------------

    #[test]
    fn end_to_end_on_synthetic_dbs() {
        // The whole chain on FAKE DBs: a Desktop message DB through
        // the mapping plan, a shadow-shaped messages table, the
        // batch-15 join, the classifiers, the report. Every value
        // carries a SENTINEL so the final assert proves nothing
        // crossed the output boundary.
        use super::super::import::inventory::{
            inventory_db, KindInventory, SnapshotInventories,
        };
        use rusqlite::params;

        let desktop = Connection::open_in_memory().unwrap();
        desktop
            .execute_batch(
                "CREATE TABLE message (
                   msgId TEXT, cliMsgId TEXT, fromUid TEXT, toUid TEXT,
                   serverTime TEXT, msgType INTEGER, message TEXT
                 );",
            )
            .unwrap();
        let cell = |inner: &str| serde_json::to_string(&J::String(inner.into())).unwrap();
        desktop
            .execute(
                "INSERT INTO message (msgId, serverTime, msgType, message) VALUES (?1, ?2, ?3, ?4)",
                params!["sid-0001", "1690000000000", 1, cell("SENTINEL-E2E-PLAIN")],
            )
            .unwrap();
        desktop
            .execute(
                "INSERT INTO message (msgId, serverTime, msgType, message) VALUES (?1, ?2, ?3, ?4)",
                params!["sid-0002", "1690000001000", 1, cell("  SENTINEL-E2E-TRIM  ")],
            )
            .unwrap();
        let media_inner = r#"ab{"href":"https://sentinel-e2e-cdn/x","title":"T3"}"#;
        desktop
            .execute(
                "INSERT INTO message (msgId, serverTime, msgType, message) VALUES (?1, ?2, ?3, ?4)",
                params!["sid-0003", "1690000002000", 2, cell(media_inner)],
            )
            .unwrap();
        desktop
            .execute(
                "INSERT INTO message (msgId, serverTime, msgType, message) VALUES (?1, ?2, ?3, ?4)",
                params!["sid-0004", "1690000003000", 1, cell("SENTINEL-E2E-GHOST")],
            )
            .unwrap();
        desktop
            .execute(
                "INSERT INTO message (msgId, serverTime, msgType, message) VALUES (?1, ?2, ?3, ?4)",
                params!["sid-0005", "1690000004000", 5, SV::Null],
            )
            .unwrap();
        desktop
            .execute(
                "INSERT INTO message (msgId, serverTime, msgType, message) VALUES (?1, ?2, ?3, ?4)",
                params!["sid-0006", "1690000005000", 1, cell("SENTINEL-E2E-OTHER")],
            )
            .unwrap();
        desktop
            .execute(
                "INSERT INTO message (msgId, serverTime, msgType, message) VALUES (?1, ?2, ?3, ?4)",
                params![SV::Null, "1690000006000", 1, cell("x")],
            )
            .unwrap();

        let doc = r#"{
          "msgType": {},
          "entities": { "message": {
            "db": ["one2one"], "table": "message",
            "columns": {
              "msgId": "msgId",
              "ts": { "expr": "ms_to_ms", "of": "serverTime" },
              "uidFrom": "fromUid", "idTo": "toUid",
              "msgType": "msgType", "content": "message"
            }
          } }
        }"#;
        let mapping = import_map::parse_mapping(doc.as_bytes()).unwrap();
        let kinds = SnapshotInventories {
            index: None,
            one_to_one: Some(KindInventory {
                source_rel: "Core/Message/111.db".into(),
                inventory: inventory_db(&desktop).unwrap(),
            }),
            group: None,
            stranger_box: None,
            top_level: Vec::new(),
        };
        let plan = import_map::plan(&mapping, &kinds).unwrap();
        let ep = plan.message.as_ref().unwrap();
        let (pairs, skipped) = extract_msg_texts(&desktop, ep).unwrap();
        assert_eq!(skipped, 1, "the NULL-msgId row");
        assert_eq!(pairs.len(), 6);
        assert_eq!(pairs[0].d.as_deref(), Some("SENTINEL-E2E-PLAIN"));
        assert_eq!(pairs[1].d.as_deref(), Some("  SENTINEL-E2E-TRIM  "));
        assert_eq!(pairs[4].d, None, "the NULL content cell has no D");

        // The shadow-shaped side.
        let shadow = Connection::open_in_memory().unwrap();
        shadow
            .execute_batch("CREATE TABLE messages (msg_id TEXT PRIMARY KEY, payload_json TEXT)")
            .unwrap();
        let ins = |conn: &Connection, id: &str, payload: &str| {
            conn.execute(
                "INSERT INTO messages (msg_id, payload_json) VALUES (?1, ?2)",
                params![id, payload],
            )
            .unwrap();
        };
        ins(
            &shadow,
            "sid-0001",
            r#"{"msgId":"sid-0001","msgType":"webchat","content":"SENTINEL-E2E-PLAIN"}"#,
        );
        ins(
            &shadow,
            "sid-0002",
            r#"{"msgId":"sid-0002","msgType":"webchat","content":"SENTINEL-E2E-TRIM"}"#,
        );
        ins(
            &shadow,
            "sid-0003",
            r#"{"msgId":"sid-0003","msgType":"chat.photo","content":{"href":"https://sentinel-e2e-cdn/x","title":"T3"}}"#,
        );
        ins(&shadow, "sid-0005", r#"{"msgId":"sid-0005","content":7}"#);
        ins(&shadow, "sid-0006", r#"{"msgId":"sid-0006","msgType":"webchat","content":[1,2]}"#);
        let smap = shadow_content_map(&shadow).unwrap();
        assert_eq!(smap.len(), 5);

        // The ignored probe's join + fold, verbatim — with a FAKE key
        // standing in for the snapshot passphrase (the plain string
        // scalar cells take the Failed path here; the dedicated
        // decrypted-section test below covers the Decoded path).
        let mut families: BTreeMap<String, FamilyCounters> = BTreeMap::new();
        let mut obj_pairs: Vec<ObjPair> = Vec::new();
        let mut grand = Grand {
            shadow_messages: smap.len(),
            ..Grand::default()
        };
        for cell in pairs {
            grand.desktop_rows += 1;
            let Some(side) = smap.get(&cell.id) else {
                grand.no_shadow_match += 1;
                continue;
            };
            grand.matched += 1;
            let token = match &side.msg_type {
                Some(mt) => msg_type_token(mt),
                None => "NULL".to_string(),
            };
            let f = families.entry(token.clone()).or_default();
            f.matched += 1;
            if cell.d.is_some() {
                f.fold_decrypted(&decode_field(&cell.raw, FAKE_KEY), side.content.as_ref());
            }
            match (&cell.d, &side.content) {
                (None, _) => f.d_missing += 1,
                (Some(d), Some(J::String(s))) => f.fold_string(&classify_string(d, s)),
                (Some(d), Some(J::Object(o))) => {
                    obj_pairs.push(ObjPair { token, d: d.clone(), obj: o.clone() });
                }
                (Some(_), _) => f.s_other += 1,
            }
        }
        let mut deltas: Vec<i64> = families
            .values()
            .flat_map(|f| f.string.char_shift.keys().copied())
            .collect();
        deltas.sort();
        deltas.dedup();
        for op in &obj_pairs {
            let m = classify_object(&op.d, &op.obj, &deltas);
            families.entry(op.token.clone()).or_default().fold_object(&m);
        }
        let lines = render(&families, &grand);
        let joined = lines.join("\n");

        // The grand line and the per-family blocks.
        assert!(
            joined.contains(
                "content-agree: shadow messages=5 desktop_rows=6 matched=5 no_shadow_match=1"
            ),
            "{joined}"
        );
        // webchat: sid-0001 eq (also eq_trim), sid-0002 eq_trim-only,
        // sid-0006 s_other -> eq_trim covers both string pairs.
        assert!(
            joined.contains(
                "content-agree: msgType=webchat matched=3 string_pairs=2 object_pairs=0 \
                 d_missing=0 s_other=1"
            ),
            "{joined}"
        );
        assert!(joined.contains("eq=1 eq_trim=2 d_contains_s=2 s_contains_d=1"), "{joined}");
        assert!(
            joined.contains("len_rel: <-8=0 -8..-1=0 0=1 1..8=1 >8=0"),
            "{joined}"
        );
        assert!(joined.contains("char_shift: delta=0 x 1 total=1"), "{joined}");
        assert!(joined.contains("verdict: webchat eq_trim 100.0%"), "{joined}");
        // chat.photo: the drop2 object parse + the verbatim values.
        assert!(
            joined.contains(
                "content-agree: msgType=chat.photo matched=1 string_pairs=0 object_pairs=1 \
                 d_missing=0 s_other=0"
            ),
            "{joined}"
        );
        assert!(joined.contains("d_contains: href=1/1 title=1/1"), "{joined}");
        assert!(
            joined.contains("transform_parses: drop1=0 drop2=1 drop3=0 drop4=0 b64=0 char_shift=0"),
            "{joined}"
        );
        assert!(joined.contains("verdict: chat.photo drop_k(k=2) 100.0%"), "{joined}");
        // The NULL family (no msgType) with a d_missing pair.
        assert!(
            joined.contains("content-agree: msgType=NULL matched=1 string_pairs=0 object_pairs=0 \
                             d_missing=1 s_other=0"),
            "{joined}"
        );
        assert!(joined.contains("verdict: NULL none (no testable pairs)"), "{joined}");

        // Batch 24 D3: the decrypted section over the SAME fixture
        // (folded with the FAKE key): every plain string-scalar cell
        // takes the Failed path (the unencrypted standard shape), the
        // NULL-cell pair is skipped (d_missing), and the counts stay
        // zeros for it.
        assert!(
            joined.contains("content-agree:   decrypted: decoded=0 not_encrypted=0 failed=3"),
            "{joined}"
        );
        assert!(
            joined.contains("content-agree:   decrypted string: pairs=2 eq=0 eq_trim=0"),
            "{joined}"
        );
        assert!(
            joined.contains("content-agree:   decrypted object: pairs=1 same_keys=0"),
            "{joined}"
        );
        assert!(
            joined.contains("content-agree:   decrypted obj_eq: href=0/1 title=0/1"),
            "{joined}"
        );

        // PRIVACY: no content value, no id, no url from either side.
        for sentinel in ["SENTINEL-E2E", "sentinel-e2e-cdn", "sid-000"] {
            assert!(!joined.contains(sentinel), "{sentinel} leaked:\n{joined}");
        }
    }

    #[test]
    fn end_to_end_decrypted_section_decodes_synthetic_cells() {
        // Batch 24 D3, the Decoded path end to end on FAKE DBs: the
        // Desktop cells are encrypted with the exact Zalo pipeline
        // (cell = JSON.stringify(xor(JSON.stringify(value), key)),
        // key = the FAKE passphrase), the shadow contents equal the
        // decoded values — the decrypted section must report Decoded
        // plus eq / same_keys / obj_eq. A plain string-literal cell
        // (the unencrypted standard shape) and a NULL cell ride along
        // for the Failed and d_missing paths.
        use super::super::import::inventory::{
            inventory_db, KindInventory, SnapshotInventories,
        };
        use rusqlite::params;

        let enc = |v: &J, key: &str| -> String {
            let plain = serde_json::to_string(v).unwrap();
            let xored = super::super::import::desktop_cipher::basic_xor_utf16(&plain, key);
            serde_json::to_string(&J::String(xored)).unwrap()
        };

        let desktop = Connection::open_in_memory().unwrap();
        desktop
            .execute_batch(
                "CREATE TABLE message (
                   msgId TEXT, cliMsgId TEXT, fromUid TEXT, toUid TEXT,
                   serverTime TEXT, msgType INTEGER, message TEXT
                 );",
            )
            .unwrap();
        let ins = |id: &str, code: i64, cell: SV| {
            desktop
                .execute(
                    "INSERT INTO message (msgId, serverTime, msgType, message) \
                     VALUES (?1, ?2, ?3, ?4)",
                    params![id, "1690000000000", code, cell],
                )
                .unwrap();
        };
        // e1: an encrypted webchat string; e2: an encrypted media
        // object; e3: the unencrypted standard shape (Failed); e4: a
        // NULL cell (d_missing).
        ins("e1", 1, SV::Text(enc(&json!("SENTINEL-DEC-PLAIN body"), FAKE_KEY)));
        ins(
            "e2",
            2,
            SV::Text(enc(
                &json!({"href": "https://sentinel-dec-cdn/x", "title": "SENTINEL-DEC-T"}),
                FAKE_KEY,
            )),
        );
        ins(
            "e3",
            1,
            SV::Text(serde_json::to_string(&json!("never encrypted SENTINEL-DEC-RAW")).unwrap()),
        );
        ins("e4", 1, SV::Null);

        let doc = r#"{
          "msgType": {},
          "entities": { "message": {
            "db": ["one2one"], "table": "message",
            "columns": {
              "msgId": "msgId",
              "ts": { "expr": "ms_to_ms", "of": "serverTime" },
              "uidFrom": "fromUid", "idTo": "toUid",
              "msgType": "msgType", "content": "message"
            }
          } }
        }"#;
        let mapping = import_map::parse_mapping(doc.as_bytes()).unwrap();
        let kinds = SnapshotInventories {
            index: None,
            one_to_one: Some(KindInventory {
                source_rel: "Core/Message/111.db".into(),
                inventory: inventory_db(&desktop).unwrap(),
            }),
            group: None,
            stranger_box: None,
            top_level: Vec::new(),
        };
        let plan = import_map::plan(&mapping, &kinds).unwrap();
        let ep = plan.message.as_ref().unwrap();
        let (pairs, skipped) = extract_msg_texts(&desktop, ep).unwrap();
        assert_eq!(skipped, 0);
        assert_eq!(pairs.len(), 4);

        // The shadow-shaped side.
        let shadow = Connection::open_in_memory().unwrap();
        shadow
            .execute_batch("CREATE TABLE messages (msg_id TEXT PRIMARY KEY, payload_json TEXT)")
            .unwrap();
        let ins_s = |conn: &Connection, id: &str, payload: &str| {
            conn.execute(
                "INSERT INTO messages (msg_id, payload_json) VALUES (?1, ?2)",
                params![id, payload],
            )
            .unwrap();
        };
        ins_s(
            &shadow,
            "e1",
            r#"{"msgId":"e1","msgType":"webchat","content":"SENTINEL-DEC-PLAIN body"}"#,
        );
        ins_s(
            &shadow,
            "e2",
            r#"{"msgId":"e2","msgType":"chat.photo","content":{"href":"https://sentinel-dec-cdn/x","title":"SENTINEL-DEC-T"}}"#,
        );
        ins_s(
            &shadow,
            "e3",
            r#"{"msgId":"e3","msgType":"webchat","content":"never encrypted SENTINEL-DEC-RAW"}"#,
        );
        ins_s(&shadow, "e4", r#"{"msgId":"e4","msgType":"webchat","content":7}"#);
        let smap = shadow_content_map(&shadow).unwrap();

        // The ignored probe's join + fold, verbatim (the FAKE key stands
        // in for the snapshot passphrase): BOTH the batch-23b sections
        // and the batch-24 decrypted section.
        let mut families: BTreeMap<String, FamilyCounters> = BTreeMap::new();
        let mut obj_pairs: Vec<ObjPair> = Vec::new();
        for cell in pairs {
            let Some(side) = smap.get(&cell.id) else { panic!("no shadow row") };
            let token = match &side.msg_type {
                Some(mt) => msg_type_token(mt),
                None => "NULL".to_string(),
            };
            let f = families.entry(token.clone()).or_default();
            f.matched += 1;
            if cell.d.is_some() {
                f.fold_decrypted(&decode_field(&cell.raw, FAKE_KEY), side.content.as_ref());
            }
            match (&cell.d, &side.content) {
                (None, _) => f.d_missing += 1,
                (Some(d), Some(J::String(s))) => f.fold_string(&classify_string(d, s)),
                (Some(d), Some(J::Object(o))) => {
                    obj_pairs.push(ObjPair { token, d: d.clone(), obj: o.clone() });
                }
                (Some(_), _) => f.s_other += 1,
            }
        }
        for op in &obj_pairs {
            let m = classify_object(&op.d, &op.obj, &[]);
            families.entry(op.token.clone()).or_default().fold_object(&m);
        }
        let lines = render(&families, &Grand::default());
        let joined = lines.join("\n");

        // webchat (e1 Decoded+eq, e3 Failed, e4 d_missing):
        assert!(
            joined.contains("content-agree: msgType=webchat matched=3 string_pairs=2 object_pairs=0 \
                             d_missing=1 s_other=0"),
            "{joined}"
        );
        assert!(
            joined.contains("content-agree:   decrypted: decoded=1 not_encrypted=0 failed=1"),
            "{joined}"
        );
        assert!(
            joined.contains("content-agree:   decrypted string: pairs=2 eq=1 eq_trim=1"),
            "{joined}"
        );
        // chat.photo (e2 Decoded, same keys, per-key equality):
        assert!(
            joined.contains("content-agree: msgType=chat.photo matched=1 string_pairs=0 object_pairs=1 \
                             d_missing=0 s_other=0"),
            "{joined}"
        );
        assert!(
            joined.contains("content-agree:   decrypted: decoded=1 not_encrypted=0 failed=0"),
            "{joined}"
        );
        assert!(
            joined.contains("content-agree:   decrypted object: pairs=1 same_keys=1"),
            "{joined}"
        );
        assert!(
            joined.contains("content-agree:   decrypted obj_eq: href=1/1 title=1/1"),
            "{joined}"
        );

        // PRIVACY: no decoded value, no key, no id ever prints — the
        // decrypted section carries counts and key NAMES only.
        for sentinel in ["SENTINEL-DEC", "sentinel-dec-cdn"] {
            assert!(!joined.contains(sentinel), "{sentinel} leaked:\n{joined}");
        }
    }

    // --- the privacy rule, standalone -------------------------------------

    #[test]
    fn no_output_line_ever_contains_content_or_ids() {
        // SENTINEL-laden data on both sides and every shape: string
        // pairs for each transform family, object pairs whose values
        // carry sentinels, a non-code-shaped msgType that must print
        // only as its h12. No output line may carry any of it.
        const SENT: [&str; 6] = [
            "SENTINEL-PLAIN-TEXT-7f3a",
            "https://sentinel-cdn.example/x.jpg",
            "SENTINEL-OBJ-TITLE",
            "SENTINEL-OBJ-DESC",
            "SENTINEL-MSGTYPE-SENTENCE",
            "SENTINEL-MSGID-987654",
        ];
        let s = "SENTINEL-PLAIN-TEXT-7f3a";
        let mut f1 = FamilyCounters::default();
        f1.matched = 2;
        f1.fold_string(&classify_string(s, s));
        f1.fold_string(&classify_string(&shift(s, -4), s));
        // Batch 24 D3: the decrypted section over the same
        // sentinel-laden pair — counts and key NAMES only, so no new
        // leak surface exists.
        f1.fold_decrypted(&FieldDecode::Decoded(json!(s)), Some(&json!(s)));

        let obj = json!({
            "href": "https://sentinel-cdn.example/x.jpg",
            "title": "SENTINEL-OBJ-TITLE",
            "description": "SENTINEL-OBJ-DESC"
        })
        .as_object()
        .unwrap()
        .clone();
        let d = serde_json::to_string(&obj).unwrap();
        let mut f2 = FamilyCounters::default();
        f2.matched = 1;
        f2.fold_object(&classify_object(&d, &obj, &[]));

        let mut families = BTreeMap::new();
        families.insert("webchat".to_string(), f1);
        let hashed = msg_type_token("SENTINEL-MSGTYPE-SENTENCE with words");
        families.insert(hashed, f2);

        let grand = Grand {
            shadow_messages: 3,
            desktop_rows: 3,
            matched: 3,
            no_shadow_match: 0,
            dbs: 1,
            opened: 1,
            failed: 0,
            rows_skipped: 0,
        };
        let lines = render(&families, &grand);
        for line in &lines {
            for sentinel in SENT {
                assert!(!line.contains(sentinel), "{sentinel} leaked:\n{line}");
            }
        }
        // The shape that DID print: family tokens (verbatim or h12),
        // key names, counts and the verdicts.
        let joined = lines.join("\n");
        // 1 eq + 1 char_shift of 2 pairs: no transform reaches the
        // 90% bar, and eq (the priority-order tie winner) is named
        // as the best.
        assert!(joined.contains("verdict: webchat none (best eq 50.0%)"), "{joined}");
        assert!(joined.contains("d_contains: description=1/1 href=1/1 title=1/1"), "{joined}");
        assert!(joined.contains(&format!("verdict: {}", msg_type_token("SENTINEL-MSGTYPE-SENTENCE with words"))), "{joined}");
        assert!(!joined.contains("SENTINEL"), "nothing sentinel-shaped ever prints");
    }
}
