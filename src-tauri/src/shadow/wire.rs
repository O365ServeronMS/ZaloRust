//! WS frame / REST body wire decode (rebuild 2026-11-19).
//!
//! Every format here was verified against the live `chat.zalo.me` web
//! client on 2026-11-13/14 (see handoff); the fixtures in the tests
//! round-trip through the same primitives.
//!
//! # WS frames (binary)
//!
//! ```text
//! [version:u8][cmd:u16 LE][subCmd:i8] + JSON {data, encrypt, error_code, error_message}
//! ```
//! - `encrypt = 0`: `data` is a plain JSON value.
//! - `encrypt = 1`: `data` is a base64 string; the bytes are gzip; the
//!   decompressed text is the JSON value.
//! - `encrypt = 2`: `data` is a percent-encoded base64 string; the decoded
//!   bytes are `[IV 16][AAD 16][ct+tag]` of AES-128-GCM with the
//!   per-connection key (frame `cmd=1 subCmd=1`, field `key`, RAM only),
//!   and the plaintext is gzip.
//!
//! # REST bodies
//!
//! Response JSON `{error_code, data: "<cipher>"}` where `data` is
//! percent-encoded base64 of AES-128-CBC (zero IV, PKCS7) using the
//! runtime REST key the page holds (web bundle: `decodeAES` with
//! `getSecretKey()`; the key is fetched from the server, it is NOT a
//! static bundle constant — hence the bridge hands it over once via the
//! `shadow_e2ee_handshake` IPC). The plaintext is the inner envelope
//! `{data, error_code, error_message}`.
//!
//! NOTE (handoff): `zcld.chat.zalo.me/cloudmedia/*` responses use a
//! different key and stay undecoded — stored, never claimed decrypted.

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use aes_gcm::aead::Aead as _;
use base64::Engine as _;
use serde_json::{json, Map, Value};

/// AES-128-GCM with a 16-byte nonce (Zalo's nonstandard GCM IV length).
type Aes128GcmN16 = aes_gcm::AesGcm<aes_gcm::aes::Aes128, aes_gcm::aead::consts::U16>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;
/// The ENCODE side of the CBC format — used only by the test fixture
/// builders below (the app only decodes).
#[cfg(test)]
type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// A parsed WS frame: header fields plus the raw JSON body.
#[derive(Debug, Clone)]
pub struct WsFrame {
    pub cmd: u16,
    pub sub_cmd: i8,
    pub body: Value,
}

/// Why a body stayed undecoded (never an error: capture is lossy-tolerant).
#[derive(Debug, Clone, PartialEq)]
pub enum Undecoded {
    /// encrypt=1/2 body was not shaped as expected.
    BadEncoding,
    /// encrypt=2 but no per-connection key yet (key frame not seen).
    NoKey,
    /// Crypto/decompress failed (key rotation mid-connection etc.).
    Crypto,
}

/// Result of decoding one WS frame body.
#[derive(Debug, Clone)]
pub enum WsDecoded {
    /// Decoded envelope: `{cmd, subCmd, data, error_code, error_message}`.
    Envelope(Value),
    /// Kept for forensics with the reason; `stored` is the JSON the
    /// previous implementation wrote to `raw_events`:
    /// `{cmd, subCmd, encrypt, body, undecoded}`.
    Undecoded { why: Undecoded, stored: Value },
}

impl WsDecoded {
    /// The value to persist in `raw_events.payload_json`.
    pub fn stored_value(&self) -> Value {
        match self {
            WsDecoded::Envelope(v) => v.clone(),
            WsDecoded::Undecoded { stored, .. } => stored.clone(),
        }
    }
}

/// Parse the 4-byte header + JSON tail of a binary WS frame.
pub fn parse_ws_frame(bytes: &[u8]) -> Option<WsFrame> {
    if bytes.len() < 5 {
        return None;
    }
    let cmd = u16::from_le_bytes([bytes[1], bytes[2]]);
    let sub_cmd = bytes[3] as i8;
    let body: Value = serde_json::from_slice(&bytes[4..]).ok()?;
    Some(WsFrame { cmd, sub_cmd, body })
}

/// Decode one frame's `data` into the stored envelope.
///
/// `key` is the current per-connection AES key (16 bytes, RAM only). For
/// `cmd=1 subCmd=1` frames the caller is expected to harvest `data.key`
/// first (see `ws_frame_key`) — this function then redacts it before the
/// envelope is stored anywhere.
pub fn decode_ws_frame(frame: &WsFrame, key: Option<&[u8; 16]>) -> WsDecoded {
    let mut env = Map::new();
    env.insert("cmd".into(), json!(frame.cmd));
    env.insert("subCmd".into(), json!(frame.sub_cmd));
    if let Some(ec) = frame.body.get("error_code") {
        env.insert("error_code".into(), ec.clone());
    }
    if let Some(em) = frame.body.get("error_message") {
        if !em.is_null() {
            env.insert("error_message".into(), em.clone());
        }
    }
    let encrypt = frame
        .body
        .get("encrypt")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let data = frame.body.get("data").cloned().unwrap_or(Value::Null);
    let decoded = match (encrypt, data) {
        (0, d) => d,
        (1, Value::String(s)) => match decode_gzip_b64(&s) {
            Some(v) => v,
            None => return undecoded(&frame, encrypt, Undecoded::BadEncoding),
        },
        (2, Value::String(s)) => match key {
            None => return undecoded(&frame, 2, Undecoded::NoKey),
            Some(k) => match decode_gcm_gzip(&s, k) {
                Some(v) => v,
                None => return undecoded(&frame, 2, Undecoded::Crypto),
            },
        },
        // Unknown encode or unexpected `data` type: keep as-is.
        (_, d) => d,
    };
    env.insert("data".into(), decoded);
    WsDecoded::Envelope(Value::Object(env))
}

/// Extract (and base64-decode) the per-connection key carried by a
/// `cmd=1 subCmd=1` frame (`data.key`; some builds carry it top-level).
/// The key never leaves RAM (never stored, never logged — handoff rule).
pub fn ws_frame_key(frame: &WsFrame) -> Option<[u8; 16]> {
    if frame.cmd != 1 || frame.sub_cmd != 1 {
        return None;
    }
    let k = frame
        .body
        .get("data")
        .and_then(|d| d.get("key"))
        .and_then(Value::as_str)
        .or_else(|| frame.body.get("key").and_then(Value::as_str))?;
    decode_key_field(k)
}

/// The key field is base64 of 16 bytes. Be tolerant of a raw 16-char form
/// (both produce a usable AES-128 key; wrong guesses simply fail to
/// decrypt and surface as `Undecoded::Crypto`).
pub fn decode_key_field(k: &str) -> Option<[u8; 16]> {
    if let Ok(raw) = B64.decode(k) {
        if raw.len() == 16 {
            let mut out = [0u8; 16];
            out.copy_from_slice(&raw);
            return Some(out);
        }
    }
    let b = k.as_bytes();
    if b.len() == 16 {
        let mut out = [0u8; 16];
        out.copy_from_slice(b);
        return Some(out);
    }
    None
}

/// Replace the key field's value with a shape marker before storage.
pub fn redact_key_in_envelope(env: &mut Value) {
    if let Some(data) = env.get_mut("data") {
        if let Some(o) = data.as_object_mut() {
            if let Some(k) = o.get("key").and_then(Value::as_str) {
                let shape = format!("<redacted:len{}>", k.len());
                o.insert("key".into(), Value::String(shape));
            }
        }
    }
}

fn undecoded(frame: &WsFrame, encrypt: i64, why: Undecoded) -> WsDecoded {
    let body = frame
        .body
        .get("data")
        .map(|d| match d {
            Value::String(s) => Value::String(s.chars().take(2048).collect()),
            other => other.clone(),
        })
        .unwrap_or(Value::Null);
    let stored = json!({
        "cmd": frame.cmd,
        "subCmd": frame.sub_cmd,
        "encrypt": encrypt,
        "undecoded": why.tag(),
        "body": body,
    });
    WsDecoded::Undecoded { why, stored }
}

impl Undecoded {
    pub fn tag(&self) -> &'static str {
        match self {
            Undecoded::BadEncoding => "bad-encoding",
            Undecoded::NoKey => "no-key",
            Undecoded::Crypto => "crypto",
        }
    }
}

/// gzip + base64: `b64(gzip(json))`.
fn decode_gzip_b64(s: &str) -> Option<Value> {
    let raw = B64.decode(s.trim()).ok()?;
    gunzip(&raw).and_then(|t| serde_json::from_slice(&t).ok())
}

/// percent-decode -> base64 -> [IV16|AAD16|ct+tag] AES-128-GCM -> gunzip.
fn decode_gcm_gzip(s: &str, key: &[u8; 16]) -> Option<Value> {
    let pct = percent_decode(s);
    let raw = B64.decode(pct.trim()).ok()?;
    if raw.len() < 32 + 16 {
        return None;
    }
    let (iv, rest) = raw.split_at(16);
    let (aad, ct) = rest.split_at(16);
    let cipher = <Aes128GcmN16 as aes_gcm::KeyInit>::new(key.into());
    let nonce = aes_gcm::aead::generic_array::GenericArray::from_slice(iv);
    let plain = cipher
        .decrypt(nonce, aes_gcm::aead::Payload { msg: ct, aad })
        .ok()?;
    let json = gunzip(&plain)?;
    serde_json::from_slice(&json).ok()
}

/// REST: percent-decode -> base64 -> AES-128-CBC (zero IV) -> inner JSON.
/// Returns `None` when the ciphertext cannot be decrypted (no key yet,
/// rotation, or a non-zpw endpoint such as cloudmedia).
pub fn decode_rest_body(data: &str, key: &[u8; 16]) -> Option<Value> {
    let pct = percent_decode(data);
    let ct = B64.decode(pct.trim()).ok()?;
    if ct.is_empty() || ct.len() % 16 != 0 {
        return None;
    }
    let iv = [0u8; 16];
    let dec = Aes128CbcDec::new_from_slices(key, &iv).ok()?;
    let plain = dec.decrypt_padded_vec_mut::<Pkcs7>(&ct).ok()?;
    serde_json::from_slice(&plain).ok()
}

/// Stored shape for a REST event: the decoded inner envelope
/// `{error_code, data}` when decoded, else `{error_code, data, undecoded}`.
///
/// R1 (batch 19): a decrypt whose INNER envelope still has a STRING
/// `data` is flagged `undecoded: true` like a failed decrypt — the
/// pre-H2 legacy rows (ids < 800) show exactly that shape stored
/// unflagged, which made `rest_stats` and the coverage probes call a
/// ciphertext row "decoded". With the flag, no NEW stored envelope
/// with a string `data` can ever look decoded (the payload under it
/// is unreachable: `normalize::unwrap_payload` only descends strings
/// that parse as JSON, and a cipher string never does).
pub fn rest_envelope(endpoint: &str, outer: &Value, key: Option<&[u8; 16]>) -> Value {
    let ec = outer.get("error_code").cloned().unwrap_or(Value::Null);
    let data_s = outer.get("data").and_then(Value::as_str);
    let mut env = match (data_s, key) {
        (Some(s), Some(k)) => match decode_rest_body(s, k) {
            Some(inner) => flag_string_data(inner),
            None => json!({
                "error_code": ec,
                "data": truncate_str(s),
                "undecoded": true,
            }),
        },
        (Some(s), None) => json!({
            "error_code": ec,
            "data": truncate_str(s),
            "undecoded": "no-key",
        }),
        (None, _) => json!({ "error_code": ec }),
    };
    if let Some(o) = env.as_object_mut() {
        o.entry("error_code")
            .or_insert_with(|| outer.get("error_code").cloned().unwrap_or(Value::Null));
    }
    let _ = endpoint;
    env
}

fn truncate_str(s: &str) -> String {
    s.chars().take(2048).collect()
}

/// R1 (batch 19): a decrypted inner whose `data` is STILL a string
/// carries an unreachable payload — flag it `undecoded: true` (see
/// `rest_envelope`'s doc). A bare non-object decrypt (e.g. a scalar
/// JSON string) cannot carry the flag — it has no object to insert
/// into — and stays unflagged; `classify_rest_envelope` still counts
/// it by the outer's shape.
fn flag_string_data(mut inner: Value) -> Value {
    if data_is_opaque_string(&inner) {
        if let Some(o) = inner.as_object_mut() {
            o.insert("undecoded".into(), Value::Bool(true));
        }
    }
    inner
}

/// Review fix (batch 19): `data` is a string that is NOT a JSON object
/// or array. A JSON-encoded string payload is reachable —
/// `normalize::unwrap_payload` parses and descends it — so it is a
/// decoded payload and must not be flagged or counted undecoded.
pub(crate) fn data_is_opaque_string(env: &Value) -> bool {
    match env.get("data") {
        Some(Value::String(s)) => !matches!(
            serde_json::from_str::<Value>(s),
            Ok(Value::Object(_)) | Ok(Value::Array(_))
        ),
        _ => false,
    }
}

/// Minimal percent-decoder (no allocation for unreserved input).
///
/// C5 (batch 3): a literal `+` is NOT mapped to space. Every caller
/// feeds the result straight into base64 (`decode_gcm_gzip`,
/// `decode_rest_body`) and the base64 alphabet has no space — so a
/// literal `+` in these payloads is always a real base64 char. A
/// percent-encoder escapes `+` to `%2B` anyway, so no legitimate
/// percent-encoded input loses meaning; meanwhile RAW base64 bodies
/// (no percent-encoding, `+` and `/` literal) keep decrypting instead
/// of failing on a corrupted string (audit §2-H2 risk note). The
/// `+`→space convention belongs to form-urlencoded query strings;
/// neither REST response bodies nor WS `encrypt=2` frames are one.
pub fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            let hi = (b[i + 1] as char).to_digit(16);
            let lo = (b[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push((h * 16 + l) as u8);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn gunzip(raw: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut d = flate2::read::GzDecoder::new(raw);
    let mut out = Vec::new();
    d.read_to_end(&mut out).ok()?;
    Some(out)
}

// ----------------------------------------------------------------------------
// Test helpers (also used by capture integration tests): the ENCODE side of
// each format, used only to build fixtures. Not used by the app runtime.
// ----------------------------------------------------------------------------

#[doc(hidden)]
pub fn test_gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

#[cfg(test)]
pub fn test_encode_gcm_gzip(payload: &Value, key: &[u8; 16], iv: &[u8; 16], aad: &[u8]) -> String {
    let json = serde_json::to_vec(payload).unwrap();
    let gz = test_gzip(&json);
    let cipher = <Aes128GcmN16 as aes_gcm::KeyInit>::new(key.into());
    let nonce = aes_gcm::aead::generic_array::GenericArray::from_slice(iv);
    let ct = cipher
        .encrypt(nonce, aes_gcm::aead::Payload { msg: &gz, aad })
        .unwrap();
    let mut raw = Vec::with_capacity(32 + ct.len());
    raw.extend_from_slice(iv);
    raw.extend_from_slice(aad);
    raw.extend_from_slice(&ct);
    percent_encode_b64(&B64.encode(&raw))
}

#[cfg(test)]
pub fn test_encode_rest(payload: &Value, key: &[u8; 16]) -> String {
    use aes::cipher::BlockEncryptMut as _;
    let json = serde_json::to_vec(payload).unwrap();
    let iv = [0u8; 16];
    let enc = Aes128CbcEnc::new_from_slices(key, &iv).unwrap();
    let ct = enc.encrypt_padded_vec_mut::<Pkcs7>(&json);
    percent_encode_b64(&B64.encode(&ct))
}

#[cfg(test)]
fn percent_encode_b64(s: &str) -> String {
    let mut out = String::new();
    for c in s.chars() {
        match c {
            '+' => out.push_str("%2B"),
            '/' => out.push_str("%2F"),
            '=' => out.push_str("%3D"),
            ch => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(cmd: u16, sub: i8, body: Value) -> WsFrame {
        WsFrame { cmd, sub_cmd: sub, body }
    }

    #[test]
    fn header_parse() {
        let mut b = vec![1u8, 0xE4, 0x01, 1]; // cmd=484? whatever: LE bytes
        let json = br#"{"data":{"x":1},"encrypt":0,"error_code":0}"#;
        b.extend_from_slice(json);
        let f = parse_ws_frame(&b).unwrap();
        assert_eq!(f.cmd, u16::from_le_bytes([0xE4, 0x01]));
        assert_eq!(f.sub_cmd, 1);
        let WsDecoded::Envelope(env) = decode_ws_frame(&f, None) else {
            panic!("must decode");
        };
        assert_eq!(env["cmd"], 484);
        assert_eq!(env["data"]["x"], 1);
        assert_eq!(env["error_code"], 0);
    }

    #[test]
    fn encrypt1_roundtrip() {
        let payload = json!({"msgs": [{"msgId": "m1", "content": "xin chào"}]});
        let gz = test_gzip(&serde_json::to_vec(&payload).unwrap());
        let body = json!({"data": B64.encode(&gz), "encrypt": 1, "error_code": 0});
        let f = frame(2, 1, body);
        let WsDecoded::Envelope(env) = decode_ws_frame(&f, None) else {
            panic!("must decode");
        };
        assert_eq!(env["data"]["msgs"][0]["msgId"], "m1");
    }

    #[test]
    fn encrypt2_roundtrip_and_nokey() {
        let key: [u8; 16] = [7; 16];
        let iv: [u8; 16] = [9; 16];
        let aad: &[u8] = &[0xAA; 16];
        let payload = json!({"data0": {"hello": "world"}});
        let enc = test_encode_gcm_gzip(&payload, &key, &iv, aad);
        let body = json!({"data": enc, "encrypt": 2, "error_code": 0});
        let f = frame(3, 2, body.clone());
        // Without a key: undecoded with the previous impl's stored shape.
        let WsDecoded::Undecoded { why, stored } = decode_ws_frame(&f, None) else {
            panic!("no key must not decode");
        };
        assert_eq!(why, Undecoded::NoKey);
        assert_eq!(stored["undecoded"], "no-key");
        // With the key: full envelope.
        let WsDecoded::Envelope(env) = decode_ws_frame(&f, Some(&key)) else {
            panic!("with key must decode");
        };
        assert_eq!(env["data"]["data0"]["hello"], "world");
    }

    #[test]
    fn key_frame_harvest_and_redaction() {
        let key = [0x11; 16];
        let kf = frame(
            1,
            1,
            json!({"data": {"key": B64.encode(key), "other": 1}, "encrypt": 0, "error_code": 0}),
        );
        assert_eq!(ws_frame_key(&kf), Some(key));
        let WsDecoded::Envelope(mut env) = decode_ws_frame(&kf, None) else {
            panic!()
        };
        redact_key_in_envelope(&mut env);
        assert_eq!(env["data"]["key"], json!("<redacted:len24>"));
        assert_eq!(env["data"]["other"], 1);
    }

    #[test]
    fn rest_roundtrip() {
        let key = [0x33; 16];
        let inner = json!({"error_code": 0, "data": {"convs": [1, 2, 3]}});
        let enc = test_encode_rest(&inner, &key);
        let outer = json!({"error_code": 0, "data": enc});
        let env = rest_envelope("https://wpa.chat.zalo.me/a/get-last-msgs", &outer, Some(&key));
        assert_eq!(env["error_code"], 0);
        assert_eq!(env["data"]["convs"][2], 3);
        // Undecodable -> flagged, never claimed decrypted.
        let nokey = rest_envelope("https://wpa.chat.zalo.me/a/get-last-msgs", &outer, None);
        assert_eq!(nokey["undecoded"], "no-key");
        let bad = rest_envelope("https://wpa.chat.zalo.me/a/x", &outer, Some(&[9u8; 16]));
        assert_eq!(bad["undecoded"], true);
    }

    #[test]
    fn decoded_inner_with_string_data_is_flagged_undecoded() {
        // R1 (batch 19): the legacy pre-H2 rows stored string-`data`
        // envelopes WITHOUT the flag and got called "decoded". The one
        // live path that can still produce that SHAPE is a decrypt
        // whose inner envelope carries a string `data` (a plain-string
        // payload, or a doubly-wrapped cipher): it must be flagged so
        // no NEW row can look decoded while its payload is unreachable.
        let key = [0x44u8; 16];
        let inner = json!({"error_code": 0, "data": "still-a-string"});
        let enc = test_encode_rest(&inner, &key);
        let outer = json!({"error_code": 0, "data": enc});
        let env = rest_envelope("https://wpa.chat.zalo.me/a/x", &outer, Some(&key));
        assert_eq!(env["undecoded"], true, "string data is never a decoded payload");
        assert_eq!(env["data"], "still-a-string");
        assert_eq!(env["error_code"], 0, "the error_code backfill still ran");
        // The normal decoded shape (object data) stays unflagged.
        let inner = json!({"error_code": 0, "data": {"ok": 1}});
        let enc = test_encode_rest(&inner, &key);
        let outer = json!({"error_code": 0, "data": enc});
        let env = rest_envelope("https://wpa.chat.zalo.me/a/x", &outer, Some(&key));
        assert!(env.get("undecoded").is_none(), "an object payload is decoded");
        assert_eq!(env["data"]["ok"], 1);
        // A JSON-encoded string payload is reachable (unwrap_payload
        // parses it): decoded, never flagged.
        let inner = json!({"error_code": 0, "data": "{\"msgs\":[]}"});
        let enc = test_encode_rest(&inner, &key);
        let outer = json!({"error_code": 0, "data": enc});
        let env = rest_envelope("https://wpa.chat.zalo.me/a/x", &outer, Some(&key));
        assert!(env.get("undecoded").is_none(), "a JSON-string payload is decoded");
        assert!(!data_is_opaque_string(&json!({"data": "[1]"})));
        assert!(data_is_opaque_string(&json!({"data": "\"plain\""})));
    }

    #[test]
    fn percent_decode_basics() {
        assert_eq!(percent_decode("a%2Bb%3Dc"), "a+b=c");
        assert_eq!(percent_decode("no-escapes"), "no-escapes");
        assert_eq!(percent_decode("bad%zz"), "bad%zz");
        // C5: a literal `+` survives — both callers feed base64, whose
        // alphabet has no space, so the old `+`->space mapping could
        // only corrupt.
        assert_eq!(percent_decode("a+b/c=="), "a+b/c==");
        assert_eq!(percent_decode("+"), "+");
    }

    #[test]
    fn rest_raw_base64_with_plus_and_slash_roundtrips() {
        // C5: pin that a cipher whose base64 carries literal `+` and
        // `/` decodes BOTH as raw base64 (no percent-encoding — the
        // shape the live web client most plausibly sends) and in the
        // percent-encoded form. The old `+`->space mapping made the
        // raw form fail decryption; base64 has no spaces, so it can
        // never be right for these payloads.
        let key = [0x33u8; 16];
        let iv = [0u8; 16];
        // Find a small payload whose ciphertext base64 visibly carries
        // both a `+` and a `/` (a handful of tries at most — each
        // ciphertext is fresh AES output).
        let (raw_b64, n): (String, u64) = {
            // The trait brings encrypt_padded_vec_mut into this scope
            // (test_encode_rest imports it locally for itself).
            use aes::cipher::BlockEncryptMut as _;
            let mut i = 0u64;
            loop {
                let enc = Aes128CbcEnc::new_from_slices(&key, &iv).unwrap();
                let inner = serde_json::to_vec(&json!({"error_code": 0, "data": {"n": i}})).unwrap();
                let ct = enc.encrypt_padded_vec_mut::<Pkcs7>(&inner);
                let b64 = B64.encode(&ct);
                if b64.contains('+') && b64.contains('/') {
                    break (b64, i);
                }
                i += 1;
            }
        };
        assert!(raw_b64.contains('+') && raw_b64.contains('/'), "{raw_b64}");
        // Raw form: base64 with literal + and / must survive untouched.
        let outer = json!({"error_code": 0, "data": raw_b64});
        let env = rest_envelope("https://wpa.chat.zalo.me/a/get-last-msgs", &outer, Some(&key));
        assert_eq!(env["data"]["n"], n, "raw base64 with + and / must decode");
        // The percent-encoded form of the SAME ciphertext also decodes.
        let pct = percent_encode_b64(&raw_b64);
        let outer2 = json!({"error_code": 0, "data": pct});
        let env2 = rest_envelope("https://wpa.chat.zalo.me/a/get-last-msgs", &outer2, Some(&key));
        assert_eq!(env2["data"]["n"], n);
    }
}
