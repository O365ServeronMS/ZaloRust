//! REST capture stage counters (audit H2, batch 3 C2).
//!
//! `raw_events kind='rest'` stayed at 0 for the whole rebuild while the
//! WS path worked, and no counter existed to say WHICH stage dropped
//! the bodies (audit §2-H2). This module counts every stage of the
//! REST path, cumulative for the process lifetime:
//!
//! ```text
//! responseReceived ─▶ api_matched ─▶ loadingFinished / loadingFailed
//!   ─▶ Network.getResponseBody (call_err | ok | err variants)
//!   ─▶ deliver_rest ─▶ flusher (outer_json_err | decoded | undecoded | no_key)
//!                        no-key bodies (R1, batch 19): pending queue in RAM
//!                          ─▶ handshake drain (pending_queued | pending_decoded
//!                             | pending_failed | pending_evicted)
//! ```
//!
//! One summary line logs at most once per 60 s and only when a counter
//! moved — the same throttle shape as the e2ee counter in
//! `commands.rs::shadow_e2ee_message`. Counts only: never urls, hosts,
//! requestIds or bodies (H-rule).
//!
//! `api_host_unmatched` counts urls whose host ends with `zalo.me` but
//! `capture::is_api_url` said no — the host bucket that tells us the
//! predicate is too narrow. The host value itself is NEVER logged.
//!
//! The bumping threads are the WebView2 UI thread (capture events) and
//! the flusher thread; statics are fine. Everything pure (formatting,
//! the throttle decision, the envelope classification) lives in free
//! functions so it is unit-testable without a live WebView2.

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Mutex;
use std::time::Duration;

use serde_json::Value;

/// Minimum spacing between two summary log lines (C2).
const LOG_EVERY: Duration = Duration::from_secs(60);

/// One stage whose counter bumps by one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestStage {
    /// Any `Network.responseReceived` (static assets included).
    ResponseSeen,
    /// `capture::is_api_url` accepted the url.
    ApiMatched,
    /// `Network.loadingFinished` for a rid still in `pending`.
    FinishedSeen,
    /// `Network.loadingFailed` for a rid still in `pending` (C4).
    FailedSeen,
    /// `CallDevToolsProtocolMethod` returned Err, or the completion
    /// handler got an error (the error text is never logged).
    BodyCallErr,
    /// `capture::parse_get_response_body` produced bytes.
    BodyOk,
    /// Completion JSON was not valid JSON.
    BodyErrNotJson,
    /// Completion JSON had no `body` string.
    BodyErrNoBody,
    /// `base64Encoded: true` but the body did not decode.
    BodyErrBadB64,
    /// The body decoded to zero bytes.
    BodyErrEmpty,
    /// `runtime::deliver_rest` was called.
    Delivered,
    /// Flusher: `serde_json::from_slice(&body)` failed on a
    /// `Job::RestBody` (used to `continue` silently).
    OuterJsonErr,
    /// Flusher: `wire::rest_envelope` decrypted the inner envelope.
    Decoded,
    /// Flusher: key armed but decryption failed (`undecoded: true`).
    Undecoded,
    /// Flusher: no REST key armed (`undecoded: "no-key"`).
    NoKey,
    /// Flusher (R1, batch 19): a no-key REST body entered the pending
    /// queue — its full ciphertext is held in RAM (bounded) until a
    /// handshake arms the key.
    PendingQueued,
    /// Flusher (R1, batch 19): a pending body decoded at a handshake
    /// drain. NOT also counted `Decoded`: that stage counts
    /// arrival-time decodes only, so `decoded + pending_decoded` is
    /// the total of bodies that ever decoded.
    PendingDecoded,
    /// Flusher (R1, batch 19): a pending body still failed to decode
    /// at a handshake drain — dropped, never retried.
    PendingFailed,
    /// Flusher (R1, batch 19): a pending body left the queue WITHOUT a
    /// decode attempt — the count, bytes or age bound fired, or a
    /// body whose ciphertext alone exceeds the bytes bound was refused
    /// at the door.
    PendingEvicted,
    /// Host ends with `zalo.me` but `is_api_url` said no.
    ApiHostUnmatched,
}

/// Cumulative per-process counters (Relaxed ordering: counts only).
#[derive(Debug, Default)]
pub struct RestStageCounters {
    pub response_seen: AtomicU64,
    pub api_matched: AtomicU64,
    pub finished_seen: AtomicU64,
    pub failed_seen: AtomicU64,
    pub body_call_err: AtomicU64,
    pub body_ok: AtomicU64,
    pub body_err_notjson: AtomicU64,
    pub body_err_nobody: AtomicU64,
    pub body_err_badb64: AtomicU64,
    pub body_err_empty: AtomicU64,
    pub delivered: AtomicU64,
    pub outer_json_err: AtomicU64,
    pub decoded: AtomicU64,
    pub undecoded: AtomicU64,
    pub no_key: AtomicU64,
    pub pending_queued: AtomicU64,
    pub pending_decoded: AtomicU64,
    pub pending_failed: AtomicU64,
    pub pending_evicted: AtomicU64,
    pub api_host_unmatched: AtomicU64,
    /// R1 (batch 21): the per-kind breakdown of the `undecoded` bucket
    /// (arrival-time decodes with an armed key). Their sum always
    /// equals `undecoded` through the live path.
    pub undecoded_bad_b64: AtomicU64,
    pub undecoded_bad_len: AtomicU64,
    pub undecoded_bad_padding: AtomicU64,
    pub undecoded_not_utf8: AtomicU64,
    pub undecoded_not_json: AtomicU64,
    pub undecoded_opaque_data: AtomicU64,
}

pub static REST_STAGES: RestStageCounters = RestStageCounters {
    response_seen: AtomicU64::new(0),
    api_matched: AtomicU64::new(0),
    finished_seen: AtomicU64::new(0),
    failed_seen: AtomicU64::new(0),
    body_call_err: AtomicU64::new(0),
    body_ok: AtomicU64::new(0),
    body_err_notjson: AtomicU64::new(0),
    body_err_nobody: AtomicU64::new(0),
    body_err_badb64: AtomicU64::new(0),
    body_err_empty: AtomicU64::new(0),
    delivered: AtomicU64::new(0),
    outer_json_err: AtomicU64::new(0),
    decoded: AtomicU64::new(0),
    undecoded: AtomicU64::new(0),
    no_key: AtomicU64::new(0),
    pending_queued: AtomicU64::new(0),
    pending_decoded: AtomicU64::new(0),
    pending_failed: AtomicU64::new(0),
    pending_evicted: AtomicU64::new(0),
    api_host_unmatched: AtomicU64::new(0),
    undecoded_bad_b64: AtomicU64::new(0),
    undecoded_bad_len: AtomicU64::new(0),
    undecoded_bad_padding: AtomicU64::new(0),
    undecoded_not_utf8: AtomicU64::new(0),
    undecoded_not_json: AtomicU64::new(0),
    undecoded_opaque_data: AtomicU64::new(0),
};

/// A point-in-time copy of all stage counters (for formatting and the
/// throttle's "did anything change" check).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RestStageSnapshot {
    pub response_seen: u64,
    pub api_matched: u64,
    pub finished_seen: u64,
    pub failed_seen: u64,
    pub body_call_err: u64,
    pub body_ok: u64,
    pub body_err_notjson: u64,
    pub body_err_nobody: u64,
    pub body_err_badb64: u64,
    pub body_err_empty: u64,
    pub delivered: u64,
    pub outer_json_err: u64,
    pub decoded: u64,
    pub undecoded: u64,
    pub no_key: u64,
    pub pending_queued: u64,
    pub pending_decoded: u64,
    pub pending_failed: u64,
    pub pending_evicted: u64,
    pub api_host_unmatched: u64,
    /// R1 (batch 21): per-kind breakdown of `undecoded`.
    pub undecoded_bad_b64: u64,
    pub undecoded_bad_len: u64,
    pub undecoded_bad_padding: u64,
    pub undecoded_not_utf8: u64,
    pub undecoded_not_json: u64,
    pub undecoded_opaque_data: u64,
}

impl RestStageSnapshot {
    /// Const zeroed snapshot (for static initialization).
    pub const fn zeroed() -> Self {
        Self {
            response_seen: 0,
            api_matched: 0,
            finished_seen: 0,
            failed_seen: 0,
            body_call_err: 0,
            body_ok: 0,
            body_err_notjson: 0,
            body_err_nobody: 0,
            body_err_badb64: 0,
            body_err_empty: 0,
            delivered: 0,
            outer_json_err: 0,
            decoded: 0,
            undecoded: 0,
            no_key: 0,
            pending_queued: 0,
            pending_decoded: 0,
            pending_failed: 0,
            pending_evicted: 0,
            api_host_unmatched: 0,
            undecoded_bad_b64: 0,
            undecoded_bad_len: 0,
            undecoded_bad_padding: 0,
            undecoded_not_utf8: 0,
            undecoded_not_json: 0,
            undecoded_opaque_data: 0,
        }
    }
}

impl RestStageCounters {
    fn field(&self, s: RestStage) -> &AtomicU64 {
        match s {
            RestStage::ResponseSeen => &self.response_seen,
            RestStage::ApiMatched => &self.api_matched,
            RestStage::FinishedSeen => &self.finished_seen,
            RestStage::FailedSeen => &self.failed_seen,
            RestStage::BodyCallErr => &self.body_call_err,
            RestStage::BodyOk => &self.body_ok,
            RestStage::BodyErrNotJson => &self.body_err_notjson,
            RestStage::BodyErrNoBody => &self.body_err_nobody,
            RestStage::BodyErrBadB64 => &self.body_err_badb64,
            RestStage::BodyErrEmpty => &self.body_err_empty,
            RestStage::Delivered => &self.delivered,
            RestStage::OuterJsonErr => &self.outer_json_err,
            RestStage::Decoded => &self.decoded,
            RestStage::Undecoded => &self.undecoded,
            RestStage::NoKey => &self.no_key,
            RestStage::PendingQueued => &self.pending_queued,
            RestStage::PendingDecoded => &self.pending_decoded,
            RestStage::PendingFailed => &self.pending_failed,
            RestStage::PendingEvicted => &self.pending_evicted,
            RestStage::ApiHostUnmatched => &self.api_host_unmatched,
        }
    }

    /// Increment one stage on THIS instance (no logging).
    pub fn bump_on(&self, s: RestStage) {
        self.field(s).fetch_add(1, Relaxed);
    }

    /// Copy of all counters (used by the pure helpers below).
    pub fn snapshot(&self) -> RestStageSnapshot {
        RestStageSnapshot {
            response_seen: self.response_seen.load(Relaxed),
            api_matched: self.api_matched.load(Relaxed),
            finished_seen: self.finished_seen.load(Relaxed),
            failed_seen: self.failed_seen.load(Relaxed),
            body_call_err: self.body_call_err.load(Relaxed),
            body_ok: self.body_ok.load(Relaxed),
            body_err_notjson: self.body_err_notjson.load(Relaxed),
            body_err_nobody: self.body_err_nobody.load(Relaxed),
            body_err_badb64: self.body_err_badb64.load(Relaxed),
            body_err_empty: self.body_err_empty.load(Relaxed),
            delivered: self.delivered.load(Relaxed),
            outer_json_err: self.outer_json_err.load(Relaxed),
            decoded: self.decoded.load(Relaxed),
            undecoded: self.undecoded.load(Relaxed),
            no_key: self.no_key.load(Relaxed),
            pending_queued: self.pending_queued.load(Relaxed),
            pending_decoded: self.pending_decoded.load(Relaxed),
            pending_failed: self.pending_failed.load(Relaxed),
            pending_evicted: self.pending_evicted.load(Relaxed),
            api_host_unmatched: self.api_host_unmatched.load(Relaxed),
            undecoded_bad_b64: self.undecoded_bad_b64.load(Relaxed),
            undecoded_bad_len: self.undecoded_bad_len.load(Relaxed),
            undecoded_bad_padding: self.undecoded_bad_padding.load(Relaxed),
            undecoded_not_utf8: self.undecoded_not_utf8.load(Relaxed),
            undecoded_not_json: self.undecoded_not_json.load(Relaxed),
            undecoded_opaque_data: self.undecoded_opaque_data.load(Relaxed),
        }
    }

    /// The per-kind counter for one undecoded kind (R1, batch 21);
    /// `None` for `NoKey` — that bucket has its own named counter.
    fn fail_kind_field(&self, k: crate::shadow::wire::RestFail) -> Option<&AtomicU64> {
        use crate::shadow::wire::RestFail as F;
        Some(match k {
            F::BadB64 => &self.undecoded_bad_b64,
            F::BadLen => &self.undecoded_bad_len,
            F::BadPadding => &self.undecoded_bad_padding,
            F::NotUtf8 => &self.undecoded_not_utf8,
            F::NotJson => &self.undecoded_not_json,
            F::OpaqueData => &self.undecoded_opaque_data,
            F::NoKey => return None,
        })
    }

    /// C2 + R1 (batch 21): one REST envelope's full counter effect on
    /// THIS instance (no logging) — the bucket still comes from the
    /// stored envelope's flag (`classify_rest_envelope`, defense in
    /// depth), and the kind breakdown rides the outcome from the same
    /// decode call. Kindless outcomes (a hand-built legacy pair that
    /// still classifies undecoded) degrade honestly to the bucket with
    /// no kind — never asserted.
    pub fn bump_rest_decode_on(
        &self,
        outer: &Value,
        env: &Value,
        outcome: crate::shadow::wire::RestOutcome,
    ) {
        match classify_rest_envelope(outer, env) {
            RestDecode::Decoded => self.bump_on(RestStage::Decoded),
            RestDecode::Undecoded => {
                if let crate::shadow::wire::RestOutcome::Failed(k) = outcome {
                    if let Some(c) = self.fail_kind_field(k) {
                        // The kind bumps FIRST so a summary line emitted
                        // by the bucket bump below already shows it.
                        c.fetch_add(1, Relaxed);
                    }
                }
                self.bump_on(RestStage::Undecoded);
            }
            RestDecode::NoKey => self.bump_on(RestStage::NoKey),
            RestDecode::NoCipher => {}
        }
    }
}

/// Bump the process-wide counters, then maybe log the summary line.
pub fn bump(s: RestStage) {
    REST_STAGES.bump_on(s);
    maybe_log();
}

/// Pure: the one summary line (cumulative counts only). The pending
/// group (R1, batch 19) carries the no-key hold queue's lifecycle; the
/// `undecoded_kinds` group (R1, batch 21) breaks the `undecoded` bucket
/// down by decode stage. Every pre-existing field keeps its name and
/// position.
pub fn format_stage_line(s: &RestStageSnapshot) -> String {
    format!(
        "shadow rest stages: seen={} api={} finished={} failed={} \
         body_ok={} body_err=(notjson {} nobody {} badb64 {} empty {}) \
         call_err={} delivered={} outer_json_err={} decoded={} undecoded={} \
         no_key={} pending=(queued {} decoded {} failed {} evicted {}) \
         host_unmatched={} \
         undecoded_kinds=(bad_b64 {} bad_len {} bad_padding {} not_utf8 {} \
         not_json {} opaque {}) (cumulative)",
        s.response_seen,
        s.api_matched,
        s.finished_seen,
        s.failed_seen,
        s.body_ok,
        s.body_err_notjson,
        s.body_err_nobody,
        s.body_err_badb64,
        s.body_err_empty,
        s.body_call_err,
        s.delivered,
        s.outer_json_err,
        s.decoded,
        s.undecoded,
        s.no_key,
        s.pending_queued,
        s.pending_decoded,
        s.pending_failed,
        s.pending_evicted,
        s.api_host_unmatched,
        s.undecoded_bad_b64,
        s.undecoded_bad_len,
        s.undecoded_bad_padding,
        s.undecoded_not_utf8,
        s.undecoded_not_json,
        s.undecoded_opaque_data
    )
}

/// Pure throttle decision (the shape `commands.rs::shadow_e2ee_message`
/// uses): emit when `LOG_EVERY` has passed since the last line AND at
/// least one counter moved since it. `last_log_ms = 0` means "never
/// logged", so the first change logs immediately.
pub fn log_due(
    now_ms: i64,
    last_log_ms: i64,
    last: &RestStageSnapshot,
    cur: &RestStageSnapshot,
) -> bool {
    now_ms.saturating_sub(last_log_ms) >= LOG_EVERY.as_millis() as i64 && last != cur
}

/// How one `wire::rest_envelope` result counts (pure).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestDecode {
    /// `data` was a cipher string and it decrypted.
    Decoded,
    /// Key armed, decryption failed — `"undecoded": true` in the
    /// stored envelope.
    Undecoded,
    /// No key armed — `"undecoded": "no-key"`.
    NoKey,
    /// No `data` string on the response: nothing to decode (plain
    /// JSON bodies), counted nowhere.
    NoCipher,
}

/// Classify one REST envelope for the stage counters: `outer` is the
/// response JSON the flusher parsed, `env` what `wire::rest_envelope`
/// returned. The `undecoded` flag is the primary signal; a decoded
/// inner whose `data` is STILL a string is counted UNDECODED even
/// without the flag (R1, batch 19: `wire::rest_envelope` already
/// flags that shape, so this arm is defense in depth — a legacy-shaped
/// pair can never be called "decoded" again).
pub fn classify_rest_envelope(outer: &Value, env: &Value) -> RestDecode {
    let had_cipher = outer.get("data").and_then(Value::as_str).is_some();
    match env.get("undecoded") {
        Some(Value::String(s)) if s == "no-key" => RestDecode::NoKey,
        Some(_) => RestDecode::Undecoded,
        None if had_cipher => {
            if crate::shadow::wire::data_is_opaque_string(env) {
                RestDecode::Undecoded
            } else {
                RestDecode::Decoded
            }
        }
        None => RestDecode::NoCipher,
    }
}

/// Flusher-side bump for one `Job::RestBody` (C2). No-op for
/// `NoCipher` bodies — the three named buckets stay honest. R1
/// (batch 21): the outcome from `wire::rest_envelope_outcome` adds
/// the per-kind breakdown of the `undecoded` bucket.
pub fn bump_rest_decode(outer: &Value, env: &Value, outcome: crate::shadow::wire::RestOutcome) {
    REST_STAGES.bump_rest_decode_on(outer, env, outcome);
    maybe_log();
}

/// Last logged line: when it was emitted and the counts it showed.
struct LastLog {
    ms: i64,
    snap: RestStageSnapshot,
}

static LAST_LOG: Mutex<LastLog> =
    Mutex::new(LastLog { ms: 0, snap: RestStageSnapshot::zeroed() });

fn maybe_log() {
    let now = crate::shadow::schema::now_ms();
    let snap = REST_STAGES.snapshot();
    let due = {
        let mut last = LAST_LOG.lock().unwrap_or_else(|e| e.into_inner());
        if log_due(now, last.ms, &last.snap, &snap) {
            last.ms = now;
            last.snap = snap;
            true
        } else {
            false
        }
    };
    // Logged outside the lock: `dlog` is a plain file append.
    if due {
        crate::dlog::log(&format_stage_line(&snap));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn stage_line_format() {
        let zero = RestStageSnapshot::zeroed();
        assert_eq!(
            format_stage_line(&zero),
            "shadow rest stages: seen=0 api=0 finished=0 failed=0 body_ok=0 \
             body_err=(notjson 0 nobody 0 badb64 0 empty 0) call_err=0 \
             delivered=0 outer_json_err=0 decoded=0 undecoded=0 no_key=0 \
             pending=(queued 0 decoded 0 failed 0 evicted 0) \
             host_unmatched=0 \
             undecoded_kinds=(bad_b64 0 bad_len 0 bad_padding 0 not_utf8 0 \
             not_json 0 opaque 0) (cumulative)"
        );
        let mut s = zero;
        s.response_seen = 100;
        s.api_matched = 7;
        s.finished_seen = 5;
        s.failed_seen = 1;
        s.body_ok = 4;
        s.body_err_badb64 = 1;
        s.delivered = 4;
        s.decoded = 3;
        s.undecoded = 1;
        s.pending_queued = 1;
        s.pending_decoded = 1;
        s.pending_failed = 2;
        s.pending_evicted = 3;
        s.undecoded_bad_padding = 1;
        let line = format_stage_line(&s);
        assert!(line.contains("seen=100 api=7 finished=5 failed=1"), "{line}");
        assert!(line.contains("body_ok=4"), "{line}");
        assert!(line.contains("body_err=(notjson 0 nobody 0 badb64 1 empty 0)"), "{line}");
        assert!(line.contains("delivered=4 outer_json_err=0"), "{line}");
        assert!(line.contains("decoded=3 undecoded=1 no_key=0"), "{line}");
        assert!(line.contains("pending=(queued 1 decoded 1 failed 2 evicted 3)"), "{line}");
        assert!(line.contains("host_unmatched=0"), "{line}");
        // R1 (batch 21): the kind group rides the SAME line, appended
        // after every pre-existing field.
        assert!(
            line.contains("undecoded_kinds=(bad_b64 0 bad_len 0 bad_padding 1 \
             not_utf8 0 not_json 0 opaque 0)"),
            "{line}"
        );
        assert!(line.ends_with("(cumulative)"), "{line}");
        // The line is built from a fixed template and integers only —
        // no url, host, requestId or body fragment can ever appear.
        for forbidden in ["https", "zalo.me", "zadn.vn", "requestId", "{", "}"] {
            assert!(!line.contains(forbidden), "{line}");
        }
    }

    #[test]
    fn throttle_shape() {
        let a = RestStageSnapshot::zeroed();
        let mut b = a;
        b.api_matched = 1;
        // Nothing changed -> never, even after an hour.
        assert!(!log_due(3_600_000, 0, &a, &a));
        // Changed but inside the 60 s window -> no.
        assert!(!log_due(1_000_000, 950_000, &a, &b));
        // Changed and 60 s passed -> yes.
        assert!(log_due(1_000_000, 940_000, &a, &b));
        // First ever change (last_log_ms = 0) -> immediate.
        assert!(log_due(60_000, 0, &a, &b));
        assert!(!log_due(60_000, 0, &a, &a));
    }

    #[test]
    fn local_counters_snapshot_tracks_bumps() {
        // A LOCAL instance so parallel tests never fight over the
        // process-wide static.
        let c = RestStageCounters::default();
        c.bump_on(RestStage::ResponseSeen);
        c.bump_on(RestStage::ResponseSeen);
        c.bump_on(RestStage::ApiMatched);
        c.bump_on(RestStage::FinishedSeen);
        c.bump_on(RestStage::FailedSeen);
        c.bump_on(RestStage::BodyOk);
        c.bump_on(RestStage::BodyErrNotJson);
        c.bump_on(RestStage::BodyErrNoBody);
        c.bump_on(RestStage::BodyErrBadB64);
        c.bump_on(RestStage::BodyErrEmpty);
        c.bump_on(RestStage::BodyCallErr);
        c.bump_on(RestStage::Delivered);
        c.bump_on(RestStage::OuterJsonErr);
        c.bump_on(RestStage::Decoded);
        c.bump_on(RestStage::Undecoded);
        c.bump_on(RestStage::NoKey);
        c.bump_on(RestStage::PendingQueued);
        c.bump_on(RestStage::PendingDecoded);
        c.bump_on(RestStage::PendingFailed);
        c.bump_on(RestStage::PendingEvicted);
        c.bump_on(RestStage::ApiHostUnmatched);
        let s = c.snapshot();
        assert_eq!(s.response_seen, 2);
        assert_eq!(s.api_matched, 1);
        assert_eq!(s.finished_seen, 1);
        assert_eq!(s.failed_seen, 1);
        assert_eq!(s.body_ok, 1);
        assert_eq!(s.body_err_notjson, 1);
        assert_eq!(s.body_err_nobody, 1);
        assert_eq!(s.body_err_badb64, 1);
        assert_eq!(s.body_err_empty, 1);
        assert_eq!(s.body_call_err, 1);
        assert_eq!(s.delivered, 1);
        assert_eq!(s.outer_json_err, 1);
        assert_eq!(s.decoded, 1);
        assert_eq!(s.undecoded, 1);
        assert_eq!(s.no_key, 1);
        assert_eq!(s.pending_queued, 1);
        assert_eq!(s.pending_decoded, 1);
        assert_eq!(s.pending_failed, 1);
        assert_eq!(s.pending_evicted, 1);
        assert_eq!(s.api_host_unmatched, 1);
        // The pure helpers compose with a snapshot diff.
        let zero = RestStageSnapshot::zeroed();
        assert!(log_due(120_000, 0, &zero, &s));
    }

    #[test]
    fn undecoded_kinds_break_down_the_undecoded_bucket_only() {
        // R1 (batch 21): a LOCAL instance (no statics), driven through
        // the real decode path — every undecoded body bumps exactly one
        // kind, and no other bucket ever moves a kind counter.
        use crate::shadow::wire::{self, RestFail, RestOutcome};
        let c = RestStageCounters::default();
        let key = [0x33u8; 16];
        let ep = "https://wpa.chat.zalo.me/a/x";
        // (a) A wrong-key decrypt -> undecoded + bad_padding.
        let inner = json!({"error_code": 0, "data": {"convs": [1, 2, 3]}});
        let outer = json!({"error_code": 0, "data": wire::test_encode_rest(&inner, &key)});
        let (env, out) = wire::rest_envelope_outcome(ep, &outer, Some(&[9u8; 16]));
        assert_eq!(out, RestOutcome::Failed(RestFail::BadPadding));
        c.bump_rest_decode_on(&outer, &env, out);
        // (b) The opaque-string decrypt -> undecoded + opaque_data.
        let sinner = json!({"error_code": 0, "data": "still-a-string"});
        let souter = json!({"error_code": 0, "data": wire::test_encode_rest(&sinner, &key)});
        let (env, out) = wire::rest_envelope_outcome(ep, &souter, Some(&key));
        assert_eq!(out, RestOutcome::Failed(RestFail::OpaqueData));
        c.bump_rest_decode_on(&souter, &env, out);
        // (c) Decoded, no-key and no-cipher bodies never touch the kinds.
        let (env, out) = wire::rest_envelope_outcome(ep, &outer, Some(&key));
        assert_eq!(out, RestOutcome::Decoded);
        c.bump_rest_decode_on(&outer, &env, out);
        let (env, out) = wire::rest_envelope_outcome(ep, &outer, None);
        assert_eq!(out, RestOutcome::Failed(RestFail::NoKey));
        c.bump_rest_decode_on(&outer, &env, out);
        let plain = json!({"error_code": 0, "data": {"plain": true}});
        let (env, out) = wire::rest_envelope_outcome(ep, &plain, Some(&key));
        assert_eq!(out, RestOutcome::NoCipher);
        c.bump_rest_decode_on(&plain, &env, out);
        // The kinds sum to the undecoded bucket, and each body landed
        // in its own kind.
        let s = c.snapshot();
        assert_eq!(s.undecoded, 2);
        assert_eq!(
            s.undecoded_bad_b64
                + s.undecoded_bad_len
                + s.undecoded_bad_padding
                + s.undecoded_not_utf8
                + s.undecoded_not_json
                + s.undecoded_opaque_data,
            s.undecoded,
            "the kinds are exactly the undecoded bucket"
        );
        assert_eq!(s.undecoded_bad_padding, 1);
        assert_eq!(s.undecoded_opaque_data, 1);
        assert_eq!(s.undecoded_bad_b64, 0);
        assert_eq!(s.decoded, 1);
        assert_eq!(s.no_key, 1);
    }

    #[test]
    fn classify_rest_envelope_buckets() {
        use crate::shadow::wire;
        let key = [0x33u8; 16];
        let inner = json!({"error_code": 0, "data": {"convs": [1, 2, 3]}});
        let enc = wire::test_encode_rest(&inner, &key);
        let outer = json!({"error_code": 0, "data": enc});
        // Decoded with the key armed.
        let env = wire::rest_envelope("https://wpa.chat.zalo.me/a/get-last-msgs", &outer, Some(&key));
        assert_eq!(classify_rest_envelope(&outer, &env), RestDecode::Decoded);
        // No key armed -> distinguishable no-key bucket.
        let env = wire::rest_envelope("https://wpa.chat.zalo.me/a/get-last-msgs", &outer, None);
        assert_eq!(classify_rest_envelope(&outer, &env), RestDecode::NoKey);
        // Key armed but wrong -> undecoded.
        let env = wire::rest_envelope("https://wpa.chat.zalo.me/a/x", &outer, Some(&[9u8; 16]));
        assert_eq!(classify_rest_envelope(&outer, &env), RestDecode::Undecoded);
        // No data string at all -> nothing to decode, counted nowhere.
        let plain = json!({"error_code": 0, "data": {"plain": true}});
        let env = wire::rest_envelope("https://wpa.chat.zalo.me/a/x", &plain, Some(&key));
        assert_eq!(classify_rest_envelope(&plain, &env), RestDecode::NoCipher);
    }

    #[test]
    fn classify_counts_the_legacy_string_data_shape_undecoded() {
        // R1 (batch 19): a stored envelope with a STRING `data` and no
        // `undecoded` flag is the legacy pre-H2 shape (4 rows, ids <
        // 800) — it must never be called "decoded" again, neither via
        // the flag `wire::rest_envelope` now emits nor via the
        // belt-and-braces string check.
        use crate::shadow::wire;
        let key = [0x44u8; 16];
        // (a) The live path: a decrypt whose inner carries a string
        // `data` — rest_envelope flags it, so the pair classifies
        // undecoded through the normal flag arm.
        let inner = json!({"error_code": 0, "data": "still-a-string"});
        let outer = json!({"error_code": 0, "data": wire::test_encode_rest(&inner, &key)});
        let env = wire::rest_envelope("https://wpa.chat.zalo.me/a/x", &outer, Some(&key));
        assert_eq!(env["undecoded"], true, "wire must flag it first");
        assert_eq!(classify_rest_envelope(&outer, &env), RestDecode::Undecoded);
        // (b) Defense in depth: the same shape hand-built WITHOUT the
        // flag (exactly what the legacy rows look like) still counts
        // undecoded, never decoded.
        let legacy_env = json!({"error_code": 0, "data": "ciphertext-looking-string"});
        assert_eq!(
            classify_rest_envelope(&outer, &legacy_env),
            RestDecode::Undecoded
        );
        // Sanity: the same env with an OBJECT data stays decoded.
        let obj_env = json!({"error_code": 0, "data": {"msgs": []}});
        assert_eq!(classify_rest_envelope(&outer, &obj_env), RestDecode::Decoded);
    }
}
