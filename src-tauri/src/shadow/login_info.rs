//! Passive decode of the `getLoginInfo` response (batch 30 M5).
//!
//! Zalo Web calls `/api/login/getLoginInfo` itself. The response is NOT
//! encrypted with the page's REST key: it uses a key derived from the
//! request's own query params `zcid` and `zcid_ext`, which is why the
//! REST-key decode (and the pending drain) used to report
//! `bad_padding` for this endpoint. The request URL reaches the flusher
//! untouched (`Job::RestBody.endpoint` is the full CDP URL; only the
//! STORED endpoint goes through `capture::safe_endpoint`), so the key
//! can be derived in RAM and the body decoded without sending anything.
//!
//! Derivation (zca-js `ParamsEncryptor.createEncryptKey`):
//! ```text
//! n   = MD5_hex(zcid_ext).to_uppercase()
//! key = even(n)[0..8] + even(zcid)[0..12] + reverse(odd(zcid))[0..12]
//! ```
//! `even`/`odd` are the characters at even/odd indexes. A 32-character
//! (32-byte UTF-8) key makes CryptoJS pick AES-256; the ciphertext is
//! base64 (after percent-decoding), CBC, zero IV, PKCS7.
//!
//! What is kept (A6, H-rule): ONLY the own uid (armed through the usual
//! `account::resolve_own_uid` path), the REST key `zpw_enk` (compared
//! with the armed one, or armed when none exists) and the service map
//! `zpw_service_map_v3` (a process-wide RAM struct for the future
//! light-read batch). The decoded body is NEVER persisted: `raw_events`
//! gets a redacted shape with a key COUNT. No key, `zcid`/`zcid_ext`,
//! cookie, uid or URL is ever logged or stored.
//!
//! Ported from zca-js src/utils.ts ParamsEncryptor.createEncryptKey and
//! decryptResp, src/apis/login.ts (MIT, (c) RFS-ADRENO and contributors)

use std::collections::BTreeMap;
use std::sync::Mutex;

use md5::{Digest, Md5};
use serde_json::{json, Value};
use zeroize::Zeroize;

use super::wire::{self, RestFail, RestOutcome};

/// The endpoint path suffix (hosts vary).
pub const LOGIN_INFO_SUFFIX: &str = "/api/login/getlogininfo";

/// Does this URL (or stored path) name the getLoginInfo endpoint?
/// Query and fragment are ignored; the compare is ASCII
/// case-insensitive.
pub fn is_login_info_endpoint(url: &str) -> bool {
    let no_frag = url.split('#').next().unwrap_or("");
    let path = no_frag.split('?').next().unwrap_or("");
    path.to_ascii_lowercase().ends_with(LOGIN_INFO_SUFFIX)
}

/// One query parameter of `url`, percent-decoded. `None` when absent
/// or empty. The value is key material for zcid/zcid_ext: callers keep
/// it in RAM only.
pub fn query_param(url: &str, name: &str) -> Option<String> {
    let no_frag = url.split('#').next().unwrap_or("");
    let q = no_frag.split_once('?')?.1;
    for pair in q.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k == name {
            let d = wire::percent_decode(v);
            return if d.is_empty() { None } else { Some(d) };
        }
    }
    None
}

fn hex_upper(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 15) as usize] as char);
    }
    s
}

/// `[...e]` split into the characters at even and odd indexes.
fn process_str(e: &str) -> (Vec<char>, Vec<char>) {
    let (mut even, mut odd) = (Vec::new(), Vec::new());
    for (i, c) in e.chars().enumerate() {
        if i % 2 == 0 {
            even.push(c);
        } else {
            odd.push(c);
        }
    }
    (even, odd)
}

/// Derive the 32-byte response key from the request's `zcid` and
/// `zcid_ext`. `None` when either is empty or the result is not
/// exactly 32 bytes (zca-js would hand CryptoJS a key of another
/// length; there is no AES variant for it that a real response uses).
///
/// Ported from zca-js src/utils.ts ParamsEncryptor.createEncryptKey (MIT, (c) RFS-ADRENO and contributors)
pub fn derive_key(zcid: &str, zcid_ext: &str) -> Option<[u8; 32]> {
    if zcid.is_empty() || zcid_ext.is_empty() {
        return None;
    }
    let mut h = Md5::new();
    h.update(zcid_ext.as_bytes());
    let n = hex_upper(&h.finalize());
    let (n_even, _) = process_str(&n);
    let (a_even, a_odd) = process_str(zcid);
    let mut key = String::with_capacity(32);
    key.extend(n_even.iter().take(8));
    key.extend(a_even.iter().take(12));
    key.extend(a_odd.iter().rev().take(12));
    let out = if key.len() == 32 {
        let mut k = [0u8; 32];
        k.copy_from_slice(key.as_bytes());
        Some(k)
    } else {
        None
    };
    key.zeroize();
    out
}

// --- the service map (RAM only, for batch 33) ------------------------------

/// `zpw_service_map_v3`: service name -> API host URLs. RAM only; no
/// `Debug`, wiped on drop, never logged (URLs are values).
pub struct ServiceMap {
    entries: BTreeMap<String, Vec<String>>,
}

impl ServiceMap {
    /// Parse the wire shape `{ "chat": ["https://…"], … }` (a bare
    /// string is accepted as a one-element list). Bounded: 64 services,
    /// 16 URLs each; only `https://` URLs survive.
    pub fn from_value(v: &Value) -> Option<ServiceMap> {
        let o = v.as_object()?;
        let mut entries = BTreeMap::new();
        for (name, urls) in o.iter().take(64) {
            let list: Vec<String> = match urls {
                Value::Array(a) => a
                    .iter()
                    .filter_map(Value::as_str)
                    .filter(|u| u.starts_with("https://"))
                    .take(16)
                    .map(str::to_string)
                    .collect(),
                Value::String(s) if s.starts_with("https://") => vec![s.clone()],
                _ => Vec::new(),
            };
            if !list.is_empty() {
                entries.insert(name.clone(), list);
            }
        }
        if entries.is_empty() {
            None
        } else {
            Some(ServiceMap { entries })
        }
    }

    /// How many services are known (a count, safe to log).
    pub fn services(&self) -> usize {
        self.entries.len()
    }
}

impl Drop for ServiceMap {
    fn drop(&mut self) {
        for list in self.entries.values_mut() {
            for u in list.iter_mut() {
                u.zeroize();
            }
        }
        self.entries.clear();
    }
}

static SERVICE_MAP: Mutex<Option<ServiceMap>> = Mutex::new(None);

/// Replace the process-wide service map (flusher thread only).
pub fn publish_service_map(m: ServiceMap) {
    *SERVICE_MAP.lock().unwrap_or_else(|e| e.into_inner()) = Some(m);
}

/// How many services the published map holds (`0` when none) — a count.
pub fn service_map_len() -> usize {
    SERVICE_MAP
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map_or(0, ServiceMap::services)
}

/// The host URLs of one service, copied out for the light-read batch.
/// RAM only: the caller must not log or persist the URLs.
pub fn service_urls(name: &str) -> Option<Vec<String>> {
    SERVICE_MAP
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .and_then(|m| m.entries.get(name).cloned())
}

// --- the decode --------------------------------------------------------------

/// What a decoded login response yields. Secrets inside: no `Debug`,
/// wiped on drop.
pub struct LoginFacts {
    /// The account uid (digits), if the body carried one.
    pub uid: Option<String>,
    /// `zpw_enk` base64-decoded to the 16-byte REST key.
    pub rest_key: Option<[u8; 16]>,
    pub service_map: Option<ServiceMap>,
    /// How many top-level keys the inner `data` object had (a count).
    pub top_keys: usize,
}

impl Drop for LoginFacts {
    fn drop(&mut self) {
        if let Some(u) = self.uid.as_mut() {
            u.zeroize();
        }
        if let Some(k) = self.rest_key.as_mut() {
            k.zeroize();
        }
    }
}

/// The result of one getLoginInfo body: the REDACTED shape to store in
/// `raw_events`, the decode outcome (for the REST stage counters) and
/// the facts when it decoded.
pub struct LoginDecoded {
    pub env: Value,
    pub outcome: RestOutcome,
    pub facts: Option<LoginFacts>,
}

/// Decode one getLoginInfo response. `url` is the FULL request URL (RAM
/// only — its `zcid`/`zcid_ext` derive the key), `outer` the parsed
/// response `{error_code, data: "<cipher>"}`. The stored `env` never
/// carries the body: `{error_code, data: {redacted, keys}}` on
/// success, the usual `undecoded` flag otherwise.
pub fn decode_login_info(url: &str, outer: &Value) -> LoginDecoded {
    let ec = outer.get("error_code").cloned().unwrap_or(Value::Null);
    let fail = |kind: RestFail, flag: Value| LoginDecoded {
        env: json!({ "error_code": ec, "undecoded": flag }),
        outcome: RestOutcome::Failed(kind),
        facts: None,
    };
    let Some(cipher) = outer.get("data").and_then(Value::as_str) else {
        return LoginDecoded {
            env: json!({ "error_code": ec }),
            outcome: RestOutcome::NoCipher,
            facts: None,
        };
    };
    let (Some(mut zcid), Some(mut ext)) = (query_param(url, "zcid"), query_param(url, "zcid_ext"))
    else {
        // The request carried no key params: nothing to derive.
        return fail(RestFail::NoKey, json!("no-key"));
    };
    let key = derive_key(&zcid, &ext);
    zcid.zeroize();
    ext.zeroize();
    let Some(mut key) = key else {
        return fail(RestFail::NoKey, json!("no-key"));
    };
    let decoded = wire::decode_rest_body_why_256(cipher, &key);
    key.zeroize();
    let inner = match decoded {
        Ok(v) => v,
        Err(kind) => return fail(kind, json!(true)),
    };
    // The payload sits under `data` (zca-js: `loginData.data`).
    let Some(data) = inner.get("data").and_then(Value::as_object) else {
        return fail(RestFail::OpaqueData, json!(true));
    };
    let uid = match data.get("uid") {
        Some(Value::String(s)) => Some(s.clone()),
        Some(Value::Number(n)) => Some(n.to_string()),
        _ => None,
    };
    let rest_key = data
        .get("zpw_enk")
        .and_then(Value::as_str)
        .and_then(wire::decode_key_field);
    let service_map = data.get("zpw_service_map_v3").and_then(ServiceMap::from_value);
    let top_keys = data.len();
    LoginDecoded {
        env: json!({
            "error_code": ec,
            "data": { "redacted": "login-info", "keys": top_keys },
        }),
        outcome: RestOutcome::Decoded,
        facts: Some(LoginFacts { uid, rest_key, service_map, top_keys }),
    }
}

/// Should a no-key REST body be held in the pending queue? Everything
/// with a cipher string and no armed key, EXCEPT getLoginInfo: its key
/// is not the REST key, so the drain could only ever fail it with
/// `bad_padding` (batch 30 M5).
pub fn should_hold_pending(endpoint: &str, outer: &Value, rest_key_armed: bool) -> bool {
    !rest_key_armed
        && outer.get("data").and_then(Value::as_str).is_some()
        && !is_login_info_endpoint(endpoint)
}

/// What the "rest key agrees" log line says (kind only).
pub fn agree_line(agrees: bool) -> &'static str {
    if agrees {
        "rest key: login-info agrees=true"
    } else {
        "rest key: login-info agrees=false"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
    use base64::Engine as _;

    // Synthetic vector, computed OUTSIDE this crate with Python's
    // hashlib (MD5) and `cryptography` (AES-256-CBC, zero IV, PKCS7):
    // an independent implementation of the zca-js derivation + cipher.
    const ZCID: &str = "7F3A9C21B84E5D06A1C2E3F4958677A8B9C0D1E2F3A4B5C6D7E8F90123456789";
    const ZCID_EXT: &str = "a1b2c3d4e5f6";
    const MD5_UPPER: &str = "025D43B1978D96E4D40D2316C90E3CAA";
    const KEY: &str = "054B989E7392B450ACEF975319876543";
    const FAKE_UID: &str = "1000000000000000007";
    const ENK_B64: &str = "AAECAwQFBgcICQoLDA0ODw==";
    const CIPHER_B64: &str = "haVq2WoNBuOc6BmaEtJOBoFCQH1yZBEyDg55ACtmWxtT4S1yv0MBb6mhSdmLjHIzWNxu+z3UO648t+dFZ4MGj8p33aUkpw2kJnPVV2NS2jq1+ueskZnrzemSyYoDTdiqy5r+c0YxgTmzi2KQw2jCHGnPGEU7ylTAT0dpoqTn6Dv9j2JZFe4uE58qDKH52Eu+Z7odZNMfa9DuiaB886ribbRmdgVWuTS+LnUH6WR+phsqrBUdGdrkCAqgljIIzs4zVO3TPBghoZoLMYco3RlMjj9B93sjPuVKpfOVBmxz6M8/GOalfa0LLCZz82gZA8vEE69PVen0o9XhQuf7+rXuaFbu7Bsj8z8bpczOdMWHAJ0=";

    fn url() -> String {
        format!(
            "https://wpa.fake.invalid/api/login/getLoginInfo?zcid={ZCID}&zcid_ext={ZCID_EXT}&enc_ver=v2&nretry=0"
        )
    }

    #[test]
    fn md5_and_key_match_the_independent_vector() {
        let mut h = Md5::new();
        h.update(ZCID_EXT.as_bytes());
        assert_eq!(hex_upper(&h.finalize()), MD5_UPPER);
        // MD5 sanity: the RFC 1321 "abc" vector.
        let mut h = Md5::new();
        h.update(b"abc");
        assert_eq!(hex_upper(&h.finalize()), "900150983CD24FB0D6963F7D28E17F72");
        let k = derive_key(ZCID, ZCID_EXT).unwrap();
        assert_eq!(std::str::from_utf8(&k).unwrap(), KEY);
        // Degenerate inputs never produce a key.
        assert!(derive_key("", ZCID_EXT).is_none());
        assert!(derive_key(ZCID, "").is_none());
        assert!(derive_key("ABC", ZCID_EXT).is_none(), "too short for 32 chars");
    }

    #[test]
    fn decode_matches_the_independent_ciphertext_and_redacts_the_body() {
        let outer = json!({ "error_code": 0, "data": CIPHER_B64 });
        let d = decode_login_info(&url(), &outer);
        assert_eq!(d.outcome, RestOutcome::Decoded);
        // Stored shape: redacted, a key COUNT only.
        assert_eq!(d.env["data"]["redacted"], "login-info");
        assert_eq!(d.env["data"]["keys"], 5);
        let stored = d.env.to_string();
        for secret in [FAKE_UID, ENK_B64, "fake.invalid", ZCID, ZCID_EXT] {
            assert!(!stored.contains(secret), "stored env must not carry {secret}");
        }
        let f = d.facts.as_ref().unwrap();
        assert_eq!(f.uid.as_deref(), Some(FAKE_UID));
        assert_eq!(f.rest_key.unwrap(), (0u8..16).collect::<Vec<_>>().as_slice());
        assert_eq!(f.top_keys, 5);
        assert_eq!(f.service_map.as_ref().unwrap().services(), 2);
        // The REST-stage classifier calls it decoded (no undecoded flag).
        assert_eq!(
            crate::shadow::rest_stats::classify_rest_envelope(&outer, &d.env),
            crate::shadow::rest_stats::RestDecode::Decoded
        );
    }

    #[test]
    fn round_trip_with_the_in_crate_encryptor_and_failure_kinds() {
        type Enc = cbc::Encryptor<aes::Aes256>;
        let key = derive_key(ZCID, ZCID_EXT).unwrap();
        let body = json!({"data": {"uid": FAKE_UID, "other": 1}, "error_code": 0});
        let ct = Enc::new_from_slices(&key, &[0u8; 16])
            .unwrap()
            .encrypt_padded_vec_mut::<Pkcs7>(&serde_json::to_vec(&body).unwrap());
        let b64 = base64::engine::general_purpose::STANDARD.encode(ct);
        let outer = json!({"error_code": 0, "data": b64});
        let d = decode_login_info(&url(), &outer);
        assert_eq!(d.outcome, RestOutcome::Decoded);
        assert_eq!(d.facts.as_ref().unwrap().top_keys, 2);
        assert!(d.facts.as_ref().unwrap().rest_key.is_none());
        // Wrong params -> bad_padding (the key differs), flagged undecoded.
        let wrong = url().replace("a1b2c3d4e5f6", "ffffffffffff");
        let d = decode_login_info(&wrong, &outer);
        assert_eq!(d.outcome, RestOutcome::Failed(RestFail::BadPadding));
        assert_eq!(d.env["undecoded"], true);
        // No params in the URL -> no-key.
        let d = decode_login_info("https://wpa.fake.invalid/api/login/getLoginInfo", &outer);
        assert_eq!(d.outcome, RestOutcome::Failed(RestFail::NoKey));
        assert_eq!(d.env["undecoded"], "no-key");
        // No cipher string -> nothing to decode.
        let d = decode_login_info(&url(), &json!({"error_code": 0}));
        assert_eq!(d.outcome, RestOutcome::NoCipher);
    }

    #[test]
    fn endpoint_match_and_query_params() {
        assert!(is_login_info_endpoint(&url()));
        assert!(is_login_info_endpoint("/api/login/getLoginInfo"));
        assert!(!is_login_info_endpoint("https://x.invalid/api/login/getServerInfo?zcid=1"));
        assert_eq!(query_param(&url(), "zcid").as_deref(), Some(ZCID));
        assert_eq!(query_param(&url(), "zcid_ext").as_deref(), Some(ZCID_EXT));
        assert_eq!(query_param(&url(), "missing"), None);
        assert_eq!(query_param("https://x.invalid/p?a=%41%42&b=", "a").as_deref(), Some("AB"));
        assert_eq!(query_param("https://x.invalid/p?b=", "b"), None);
    }

    #[test]
    fn bad_padding_no_longer_reaches_the_drain_for_login_info() {
        // BEFORE (batch 21 behaviour): the body queues while no key is
        // armed and the drain decodes it with the 16-byte REST key ->
        // bad_padding. AFTER: it is never held, and decoding it with
        // the derived key succeeds.
        let outer = json!({"error_code": 0, "data": CIPHER_B64});
        let rest_key = [9u8; 16];
        let (_, old) = wire::rest_envelope_outcome("/api/login/getLoginInfo", &outer, Some(&rest_key));
        assert!(matches!(old, RestOutcome::Failed(RestFail::BadPadding) | RestOutcome::Failed(RestFail::BadLen)));
        assert!(!should_hold_pending(&url(), &outer, false));
        assert!(should_hold_pending("https://x.invalid/api/other", &outer, false));
        assert!(!should_hold_pending("https://x.invalid/api/other", &outer, true));
        assert_eq!(decode_login_info(&url(), &outer).outcome, RestOutcome::Decoded);
        // Through the real pending queue: the held body would fail,
        // so the flusher must never push it (should_hold_pending).
        let mut pend = super::super::rest_pending::PendingRest::new();
        if should_hold_pending(&url(), &outer, false) {
            pend.push(url(), outer.clone(), "in", 0);
        }
        let drained = pend.drain_with_key(&rest_key);
        assert_eq!(drained.failed, 0);
        assert!(drained.fail_tally.render().is_empty());
    }

    #[test]
    fn service_map_is_bounded_https_only_and_publishable() {
        let v = json!({
            "chat": ["https://a.invalid", "http://plain.invalid"],
            "bad": ["http://nope.invalid"],
            "one": "https://b.invalid",
            "num": 3
        });
        let m = ServiceMap::from_value(&v).unwrap();
        assert_eq!(m.services(), 2, "http-only and non-list entries are dropped");
        publish_service_map(m);
        assert_eq!(service_map_len(), 2);
        assert_eq!(service_urls("chat").unwrap(), vec!["https://a.invalid".to_string()]);
        assert!(service_urls("bad").is_none());
        assert!(ServiceMap::from_value(&json!([1])).is_none());
    }

    #[test]
    fn rest_key_agreement_check_is_a_plain_compare() {
        let a = wire::decode_key_field(ENK_B64).unwrap();
        let armed_same = a;
        let mut armed_other = a;
        armed_other[0] ^= 1;
        assert!(a == armed_same);
        assert!(a != armed_other);
        assert_eq!(agree_line(true), "rest key: login-info agrees=true");
        assert_eq!(agree_line(false), "rest key: login-info agrees=false");
    }
}
