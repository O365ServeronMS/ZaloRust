//! The Zalo PC `BasicEncryption` field transform (batch 24 D1).
//!
//! What Claude established by reading the Zalo Desktop 26.11.12 app
//! code (static, read-only): the data-transform layer
//! (`main-dist/utility-process-sqlite.js` + the pc-dist workers) gives
//! the SQLite adapter's `message` table exactly ONE config —
//! `version 0, sentiveFields ["message"], methodology
//! BasicEncryption` — and initialises the transformer with the
//! partition's `cipherKey`: the SAME string the DB is opened with
//! (`PRAGMA key '<cipherKey>'`), i.e. the D7 passphrase the import
//! already uses. `fromDB` decodes each sensitive field holding a
//! non-empty string with
//!
//! ```js
//! // BasicEncryption revealSync (the non-IE branch, Electron) —
//! // UTF-16 code units, key cycling from the start:
//! let n = 0, r = [];
//! for (let i = 0; i < t.length; i++) {
//!   r.push(String.fromCharCode(t.charCodeAt(i) ^ key.charCodeAt(n)));
//!   n++; if (n > key.length - 1) n = 0;
//! }
//! return r.join("");
//! ```
//!
//! and then `JSON.parse`s the result. The SQLite column holds a JSON
//! string literal whose value is the XOR output (batch 23a saw a JSON
//! string scalar for every row), so decoding is: JSON-unwrap the cell
//! to a string `t` → XOR `t`'s UTF-16 units with the key's units,
//! cycling → `JSON.parse` the output, which yields the content value
//! (a string for webchat, an object for media). XOR is self-inverse,
//! so encryption is the same operation (batch 23b's length evidence
//! agrees: the length is preserved and webchat D is longer than S by
//! the JSON quotes and escapes).
//!
//! PRIVACY (the batch hard rule): the key is the D7 passphrase — it
//! arrives in memory only, exactly the way `import::prepare` already
//! passes it, and nothing in this module ever logs, prints, stores or
//! hashes it. Decrypted content never crosses this module's boundary
//! into any print — callers get a `serde_json::Value` or a failure
//! KIND, and the only other thing this module can produce is a
//! `DecodeCounts` (three integers).
//!
//! `decode_field`'s decision tree (the JS fallback mirrored in
//! spirit — "keep the value as it was"):
//! - a JSON **string scalar** cell: unwrap → XOR → parse.
//!   `Decoded(v)` when the parse succeeds (the expected path for
//!   every real row, given the batch-23a census);
//! - the same shape when XOR+parse FAILS: if the unwrapped text
//!   parses as JSON **on its own**, the row was stored double-encoded
//!   but never encrypted → `NotEncrypted(parse(t))` (the brief's
//!   "XOR+parse fails while the raw cell parses as JSON on its own"
//!   clause — the raw content text in hand at that point);
//! - the same shape when NEITHER parses: `Failed(XorParse)` — the
//!   wrong-key signature, and the reason D2's apply gate exists: with
//!   the right key the XOR output always parses, so a widespread
//!   `XorParse` means the passphrase (or the column reading) is wrong;
//! - a cell that is NOT a JSON string scalar: kept as it was — its
//!   own JSON meaning when it has one (an object/array/number text),
//!   else the raw text (prose), and NULL/INTEGER/REAL as their JSON
//!   values → `NotEncrypted(v)`;
//! - a BLOB: no text and no JSON value — `Failed(Blob)`, the one cell
//!   class that can never become a value.
//!
//! Everything here is pure and unit-tested below (synthetic keys
//! only); the module never touches a connection.

use rusqlite::types::Value as SV;
use serde_json::Value;

/// The BasicEncryption `revealSync`/`hideSync` transform, exactly the
/// JS loop above, on UTF-16 code units: each unit of `t` is XORed with
/// the key unit at the cycling index (`n++; if (n > key.length - 1)
/// n = 0`, which is `i % key.len()` in closed form), and the units
/// are reassembled with `String::from_utf16_lossy` — the Rust
/// equivalent of `String.fromCharCode` + `join`, differing only on
/// unpaired surrogates, which the lossy assembly replaces with
/// U+FFFD. An EMPTY key returns the input unchanged (in JS,
/// `charCodeAt` on `""` is `NaN` and `x ^ NaN === x`).
pub fn basic_xor_utf16(t: &str, key: &str) -> String {
    if key.is_empty() {
        return t.to_string();
    }
    let key_units: Vec<u16> = key.encode_utf16().collect();
    let last = key_units.len() - 1;
    let mut n = 0usize;
    let mut out: Vec<u16> = Vec::with_capacity(t.len());
    for u in t.encode_utf16() {
        out.push(u ^ key_units[n]);
        n += 1;
        if n > last {
            n = 0;
        }
    }
    String::from_utf16_lossy(&out)
}

/// Why a decode failed — a kind enum ONLY (no value ever rides a
/// failure out of this module).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeFail {
    /// The cell is a BLOB: no text to unwrap and no JSON value to
    /// keep — the one cell class that can never decode.
    Blob,
    /// The cell is a JSON string literal, but neither the XOR output
    /// nor the unwrapped text parses as JSON — the wrong-key
    /// signature (with the right key the XOR output is always the
    /// `JSON.stringify` of the content, which parses).
    XorParse,
}

/// One field-decode outcome. `Decoded`/`NotEncrypted` carry the
/// content VALUE (in memory only); `Failed` carries a kind, never a
/// value.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldDecode {
    /// Cell → JSON-unwrap → XOR → `JSON.parse` succeeded: the content
    /// value the Desktop transform would have produced.
    Decoded(Value),
    /// The cell was kept as it was (see the module docs for the exact
    /// cell classes): its own JSON meaning, else the raw text.
    NotEncrypted(Value),
    Failed(DecodeFail),
}

/// `decode_field` — one Desktop cell through the BasicEncryption
/// pipeline with `key` (the D7 passphrase, in memory only). The exact
/// decision tree is in the module docs; the one rule worth repeating:
/// the wrong-key signature is `Failed(XorParse)`, so D2's apply gate
/// (refuse above 1% failed) is a wrong-key detector.
pub fn decode_field(cell: &SV, key: &str) -> FieldDecode {
    let text = match cell {
        // Not a JSON string scalar: keep the value as it was. (A NULL
        // content cell is normal — many rows have none.)
        SV::Null => return FieldDecode::NotEncrypted(Value::Null),
        SV::Integer(i) => return FieldDecode::NotEncrypted(Value::Number((*i).into())),
        SV::Real(f) => {
            return FieldDecode::NotEncrypted(
                serde_json::Number::from_f64(*f).map(Value::Number).unwrap_or(Value::Null),
            )
        }
        // No text, no JSON value: the one undecodable cell class.
        SV::Blob(_) => return FieldDecode::Failed(DecodeFail::Blob),
        SV::Text(s) => s,
    };
    // The standard BasicEncryption shape: a JSON string literal.
    if let Ok(Value::String(t)) = serde_json::from_str::<Value>(text) {
        let plain = basic_xor_utf16(&t, key);
        if let Ok(v) = serde_json::from_str::<Value>(&plain) {
            return FieldDecode::Decoded(v);
        }
        // The JS fallback in spirit: maybe never encrypted — the
        // unwrapped text parses as JSON on its own, so keep that
        // value as it was.
        if let Ok(v) = serde_json::from_str::<Value>(&t) {
            return FieldDecode::NotEncrypted(v);
        }
        return FieldDecode::Failed(DecodeFail::XorParse);
    }
    // Not a JSON string scalar: its own JSON meaning when it has one…
    if let Ok(v) = serde_json::from_str::<Value>(text) {
        return FieldDecode::NotEncrypted(v);
    }
    // …else the raw text, kept as it was.
    FieldDecode::NotEncrypted(Value::String(text.to_string()))
}

/// Per-extract tallies of the decode outcomes — D2's
/// `content_decoded` / `content_not_encrypted` / `content_failed`
/// (counts only; the values themselves never leave the extractor).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DecodeCounts {
    pub decoded: usize,
    pub not_encrypted: usize,
    pub failed: usize,
}

impl DecodeCounts {
    /// Fold one outcome into the counters.
    pub fn fold(&mut self, r: &FieldDecode) {
        match r {
            FieldDecode::Decoded(_) => self.decoded += 1,
            FieldDecode::NotEncrypted(_) => self.not_encrypted += 1,
            FieldDecode::Failed(_) => self.failed += 1,
        }
    }

    /// Rows tallied (the three buckets partition the decoded cells).
    pub fn total(&self) -> usize {
        self.decoded + self.not_encrypted + self.failed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The synthetic key every positive test uses — a FAKE 2-unit
    /// string (U+20AC/U+20AB, both with bit 13 set). Units with bit 13
    /// set XOR any unit whose bit 13 is clear (ASCII, Vietnamese,
    /// surrogate pairs — every unit the round-trip texts use) to a
    /// unit with bit 13 SET, which can never be a surrogate
    /// (0xD800..=0xDFFF all have bit 13 clear), so the cipher is
    /// always a valid UTF-16 string and `from_utf16_lossy` never has
    /// to replace anything. Never a real key.
    const KEY: &str = "\u{20ac}\u{20ab}";

    /// The exact Zalo pipeline on synthetic data: the SQLite cell
    /// stores `JSON.stringify(xor(JSON.stringify(value), key))`.
    fn enc_cell(value: &Value, key: &str) -> String {
        let plain = serde_json::to_string(value).unwrap();
        let xored = basic_xor_utf16(&plain, key);
        serde_json::to_string(&Value::String(xored)).unwrap()
    }

    // --- D1: the XOR helper ------------------------------------------------

    #[test]
    fn round_trips_ascii_vietnamese_surrogate_pairs_and_json() {
        // ASCII.
        let ascii = "hello there, batch 24!";
        // Vietnamese (non-ASCII BMP: diacritics below U+2000).
        let viet = "Ch\u{e0}o b\u{1ea1}n, r\u{1ea5}t h\u{e2}n h\u{1ea1}nh \u{111}\u{1b0}\u{1ee3}c l\u{e0}m quen!";
        // Chars above U+FFFF — UTF-16 surrogate pairs in the units.
        let emoji = "sticker \u{1f600} and \u{1f389} party";
        // The JSON text of a media-shaped object (what the pipeline
        // actually XORs for media rows).
        let obj = json!({
            "href": "https://fake-stal.example/x.jpg",
            "params": "{\"fileSize\":\"9\",\"fileExt\":\"pdf\"}",
            "thumb": "https://fake/t.jpg",
            "title": "SENTINEL-TITLE"
        });
        let obj_text = serde_json::to_string(&obj).unwrap();
        for plain in [ascii, viet, emoji, obj_text.as_str()] {
            let cipher = basic_xor_utf16(plain, KEY);
            // Self-inverse (the JS observation), exactly — the
            // intermediate must be a valid String for the inverse to
            // reproduce the input byte-for-byte.
            assert_eq!(basic_xor_utf16(&cipher, KEY), plain);
            // The JS loop is length-preserving in UTF-16 units.
            assert_eq!(cipher.encode_utf16().count(), plain.encode_utf16().count());
        }
        // And the full pipeline round trip: the cell decodes back to
        // the exact content value (a string, then an object).
        for value in [
            json!("plain webchat text with Ch\u{e0}o and \u{1f600}"),
            json!({"href": "https://fake-stal.example/x.jpg", "title": "SENTINEL-T"}),
        ] {
            let cell = SV::Text(enc_cell(&value, KEY));
            assert_eq!(decode_field(&cell, KEY), FieldDecode::Decoded(value));
        }
    }

    #[test]
    fn key_cycles_for_lengths_1_7_and_64() {
        // A text longer than every key, so the index wraps. The
        // reference uses the closed form (i % key.len()); the helper
        // uses the JS's imperative n++/reset — they must agree.
        let t = "The quick brown fox jumps over the lazy dog. \
                 0123456789 ABCDEFGHIJKLMNOPQRSTUVWXYZ a different tail!";
        assert!(t.encode_utf16().count() > 64, "the text must outlast the 64-key");
        for key in ["k", "k1yA9sz", "abcd".repeat(16).as_str()] {
            assert_eq!(key.encode_utf16().count(), [1, 7, 64][[1, 7, 64]
                .iter()
                .position(|&n| n == key.encode_utf16().count())
                .unwrap()]);
            let key_units: Vec<u16> = key.encode_utf16().collect();
            let expect: Vec<u16> = t
                .encode_utf16()
                .enumerate()
                .map(|(i, u)| u ^ key_units[i % key_units.len()])
                .collect();
            assert_eq!(
                basic_xor_utf16(t, key),
                String::from_utf16_lossy(&expect),
                "key len {}",
                key.len()
            );
        }
    }

    #[test]
    fn an_empty_key_returns_the_input_unchanged() {
        for t in ["", "plain", "Ch\u{e0}o b\u{1ea1}n \u{1f600}", "{\"k\":1}"] {
            assert_eq!(basic_xor_utf16(t, ""), t);
        }
    }

    #[test]
    fn hand_computed_vector_matches_the_js_algorithm() {
        // Walked by hand from the JS loop, UTF-16 units:
        //   'A'(0x41)^'x'(0x78) = 0x39 '9'   (n: 0 -> 1)
        //   'B'(0x42)^'y'(0x79) = 0x3B ';'   (n: 1 -> 2 > 1 -> 0)
        //   'C'(0x43)^'x'(0x78) = 0x3B ';'   (cycled back to 'x')
        //   'D'(0x44)^'y'(0x79) = 0x3D '='
        assert_eq!(basic_xor_utf16("ABCD", "xy"), "9;;=");
        // 'A'^'x'='9', 'B'^'y'=';' — the 3-unit key never reaches 'z'.
        assert_eq!(basic_xor_utf16("AB", "xyz"), "9;");
        // 'é'(0xE9)^'k'(0x6B) = 0x82 — a unit above ASCII.
        assert_eq!(basic_xor_utf16("\u{e9}", "k"), "\u{82}");
        // Self-inverse on the same vectors.
        assert_eq!(basic_xor_utf16("9;;=", "xy"), "ABCD");
        assert_eq!(basic_xor_utf16("\u{82}", "k"), "\u{e9}");
    }

    // --- D1: decode_field --------------------------------------------------

    #[test]
    fn decode_field_decodes_the_exact_zalo_pipeline() {
        for value in [
            json!("a webchat string: Ch\u{e0}o b\u{1ea1}n!"),
            json!({"href": "https://fake-stal.example/x.jpg",
                   "params": "{\"fileSize\":\"9\"}",
                   "title": "SENTINEL-TITLE"}),
        ] {
            let cell = SV::Text(enc_cell(&value, KEY));
            assert_eq!(decode_field(&cell, KEY), FieldDecode::Decoded(value));
        }
        // Re-encrypting the decoded value reproduces the same cell
        // (the transform is its own inverse).
        let value = json!("round trip me");
        let cell = enc_cell(&value, KEY);
        match decode_field(&SV::Text(cell.clone()), KEY) {
            FieldDecode::Decoded(v) => assert_eq!(enc_cell(&v, KEY), cell),
            other => panic!("expected Decoded, got {other:?}"),
        }
    }

    #[test]
    fn decode_field_keeps_a_non_string_scalar_cell_as_it_was() {
        // NULL / INTEGER / REAL are not JSON string scalars.
        assert_eq!(decode_field(&SV::Null, KEY), FieldDecode::NotEncrypted(json!(null)));
        assert_eq!(decode_field(&SV::Integer(7), KEY), FieldDecode::NotEncrypted(json!(7)));
        assert_eq!(decode_field(&SV::Real(1.5), KEY), FieldDecode::NotEncrypted(json!(1.5)));
        // A JSON TEXT cell that is not a string scalar: its own JSON
        // meaning, kept (an object, an array, a number).
        for (text, want) in [
            (r#"{"href":"x","params":"{\"a\":\"b\"}"}"#,
             json!({"href":"x","params":"{\"a\":\"b\"}"})),
            ("[1,2]", json!([1, 2])),
            ("123", json!(123)),
        ] {
            assert_eq!(
                decode_field(&SV::Text(text.into()), KEY),
                FieldDecode::NotEncrypted(want),
                "{text}"
            );
        }
        // Prose: not JSON at all — the raw text kept as it was.
        assert_eq!(
            decode_field(&SV::Text("plain prose Ch\u{e0}o".into()), KEY),
            FieldDecode::NotEncrypted(json!("plain prose Ch\u{e0}o"))
        );
        // The empty string the JS fromDB skips is prose here.
        assert_eq!(
            decode_field(&SV::Text(String::new()), KEY),
            FieldDecode::NotEncrypted(json!(""))
        );
    }

    #[test]
    fn decode_field_falls_back_when_the_inner_text_parses_as_json() {
        // XOR+parse fails (wrong key for this cell), but the unwrapped
        // text parses as JSON on its own: the row was stored
        // double-encoded, never encrypted — the JS fallback in
        // spirit, keep the value as it was.
        let inner = serde_json::to_string(&json!("never encrypted SENTINEL")).unwrap();
        let cell = serde_json::to_string(&Value::String(inner)).unwrap();
        assert_eq!(
            decode_field(&SV::Text(cell), KEY),
            FieldDecode::NotEncrypted(json!("never encrypted SENTINEL"))
        );
        // The same shape for an object content.
        let inner = serde_json::to_string(&json!({"href": "SENTINEL-H"})).unwrap();
        let cell = serde_json::to_string(&Value::String(inner)).unwrap();
        assert_eq!(
            decode_field(&SV::Text(cell), KEY),
            FieldDecode::NotEncrypted(json!({"href": "SENTINEL-H"}))
        );
    }

    #[test]
    fn decode_field_fails_on_blobs_and_wrong_key_cells() {
        // A blob: no text, no JSON value.
        assert_eq!(
            decode_field(&SV::Blob(vec![1, 2]), KEY),
            FieldDecode::Failed(DecodeFail::Blob)
        );
        // A cell encrypted with a DIFFERENT key: the XOR output is
        // garbage (not JSON) and the unwrapped text is garbage too —
        // the wrong-key signature the apply gate exists to catch.
        let cell = enc_cell(&json!("needs the right key"), "another-fake-key-24");
        assert_eq!(
            decode_field(&SV::Text(cell), KEY),
            FieldDecode::Failed(DecodeFail::XorParse)
        );
        // The plain unencrypted standard shape (a JSON string literal
        // of prose): the Desktop transform itself could not read this
        // without its JSON.parse throwing, so it is a failure here
        // too — counted, never silently imported as content.
        let cell = serde_json::to_string(&json!("plain prose inside a JSON string")).unwrap();
        assert_eq!(
            decode_field(&SV::Text(cell), KEY),
            FieldDecode::Failed(DecodeFail::XorParse)
        );
    }

    #[test]
    fn decode_counts_fold_the_three_outcomes() {
        let mut c = DecodeCounts::default();
        assert_eq!(c.total(), 0);
        c.fold(&decode_field(&SV::Text(enc_cell(&json!("x"), KEY)), KEY));
        c.fold(&decode_field(&SV::Null, KEY));
        c.fold(&decode_field(&SV::Blob(vec![1]), KEY));
        assert_eq!(c, DecodeCounts { decoded: 1, not_encrypted: 1, failed: 1 });
        assert_eq!(c.total(), 3);
    }
}
