//! In-RAM hold for REST bodies that arrive BEFORE the REST key arms
//! (batch 19, R1).
//!
//! Why it exists (measured on the DB copy, 2026-11-19): the app boots
//! and `/api/preloadconvers/get-last-msgs` fires at start — BEFORE the
//! web bundle hands the REST key over via `Job::Handshake`. With no
//! key the flusher could only store the TRUNCATED ciphertext
//! (`wire::rest_envelope`, `undecoded: "no-key"`), so the real 45–65 KB
//! body could never be decoded later; REST added no messages after the
//! 16:38 deploy.
//!
//! The fix keeps the ciphertext in RAM until the key arms:
//! - the no-key `raw_events` row is STILL written first (truncated,
//!   `undecoded: "no-key"`) — the audit trail, unchanged;
//! - the FULL outer envelope rides a bounded queue: at most 32
//!   bodies, at most 8 MiB of ciphertext in total, at most 10 minutes
//!   old; the OLDEST entry is evicted first;
//! - a `Job::Handshake` that arms or REPLACES the key drains the
//!   queue in arrival order with the new key: a body that decodes
//!   becomes a normal `pipeline::Incoming` (kind "rest", safe
//!   endpoint) — a NEW decoded `raw_events` row plus its normalized
//!   writes, the old no-key row never rewritten; a body that still
//!   fails is dropped and counted;
//! - bodies evicted by any bound, or still queued at shutdown, are
//!   dropped and wiped: the ciphertext is the user's data in
//!   encrypted form — never logged, never persisted beyond each
//!   body's truncated no-key row (H-rule).
//!
//! Pure container + decode logic: NO statics (the flusher owns every
//! `rest_stats` bump), clock and key injected, so each bound and the
//! drain are unit-testable without threads or sleeps.
//!
//! PRIVACY: [`PendingBody`] and [`PendingRest`] deliberately do NOT
//! derive `Debug` — a `{:?}` of a held body would dump the user's
//! ciphertext and the raw endpoint (URLs can carry query-string ids).

use std::collections::VecDeque;

use serde_json::Value;
use zeroize::Zeroize;

use super::pipeline;
use super::rest_stats::{self, RestDecode};
use super::{capture, wire};

/// At most this many bodies ride the queue (R1).
pub const MAX_BODIES: usize = 32;
/// At most this many bytes of ciphertext in total (R1): 8 MiB.
pub const MAX_CIPHER_BYTES: usize = 8 * 1024 * 1024;
/// A queued body is at most this old before eviction (R1): 10 min.
/// The bound is inclusive-alive: an entry leaves only strictly PAST
/// the 10-minute mark.
pub const MAX_AGE_MS: i64 = 10 * 60 * 1000;

/// One held body: the raw endpoint (RAM only — `drain_with_key`
/// renders it through `capture::safe_endpoint` before anything can be
/// stored), the FULL outer envelope (`data` = the ciphertext string),
/// the direction, and the arrival time for the age bound.
pub struct PendingBody {
    pub endpoint: String,
    pub outer: Value,
    pub direction: &'static str,
    pub arrival_ms: i64,
}

/// What one [`PendingRest::push`] displaced (R1). `evicted` counts
/// every body dropped WITHOUT a decode attempt: aged out past the
/// bound, evicted by the count or bytes bound, or refused at the door
/// because its ciphertext alone exceeds the bytes bound. The caller
/// bumps `rest_stats::PendingEvicted` per count and treats
/// `accepted == false` as "never queued".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PushOutcome {
    pub accepted: bool,
    pub evicted: usize,
}

/// The result of draining the queue with a newly armed key (R1).
/// No `Debug` derive: the items carry decoded user payloads.
#[derive(Default)]
pub struct DrainOutcome {
    /// Decoded bodies, in arrival order, ready for the pipeline.
    pub items: Vec<pipeline::Incoming>,
    /// Bodies that still failed to decode with the new key (the
    /// caller counts them `rest_stats::PendingFailed`; already wiped).
    pub failed: usize,
}

impl DrainOutcome {
    /// How many bodies decoded (== `items.len()`).
    pub fn decoded(&self) -> usize {
        self.items.len()
    }
}

/// The bounded hold itself (R1). Insertion order == arrival order;
/// every bound evicts the OLDEST entry only.
#[derive(Default)]
pub struct PendingRest {
    queue: VecDeque<PendingBody>,
    cipher_bytes: usize,
}

impl PendingRest {
    pub fn new() -> Self {
        Self { queue: VecDeque::new(), cipher_bytes: 0 }
    }

    /// Bodies currently held.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Ciphertext bytes currently held (the `data` strings only — the
    /// brief's bound is on ciphertext, not JSON framing).
    pub fn cipher_bytes(&self) -> usize {
        self.cipher_bytes
    }

    /// The ciphertext byte length of one outer envelope.
    fn cipher_len(outer: &Value) -> usize {
        outer.get("data").and_then(Value::as_str).map_or(0, str::len)
    }

    /// Queue one body (R1). Age-bound entries leave first, then the
    /// OLDEST entries until the new body fits both bounds. A body
    /// whose ciphertext alone exceeds `MAX_CIPHER_BYTES` is refused at
    /// the door (counted with the evicted; its no-key raw row —
    /// already written by the caller — is the only trace).
    pub fn push(
        &mut self,
        endpoint: String,
        outer: Value,
        direction: &'static str,
        now_ms: i64,
    ) -> PushOutcome {
        let mut evicted = self.purge_aged(now_ms);
        let len = Self::cipher_len(&outer);
        if len > MAX_CIPHER_BYTES {
            // Refused: can never fit under the bytes bound.
            let mut outer = outer;
            wipe_outer(&mut outer);
            return PushOutcome { accepted: false, evicted: evicted + 1 };
        }
        while self.queue.len() >= MAX_BODIES || self.cipher_bytes + len > MAX_CIPHER_BYTES {
            match self.queue.pop_front() {
                Some(mut b) => {
                    self.cipher_bytes -= Self::cipher_len(&b.outer);
                    wipe_body(&mut b);
                    evicted += 1;
                }
                // Unreachable (`len <= MAX_CIPHER_BYTES` was checked),
                // but never loop forever.
                None => break,
            }
        }
        self.cipher_bytes += len;
        self.queue.push_back(PendingBody { endpoint, outer, direction, arrival_ms: now_ms });
        PushOutcome { accepted: true, evicted }
    }

    /// Drop and wipe every body older than `MAX_AGE_MS` (R1). Returns
    /// how many left; the caller counts them evicted. The clock is
    /// injected, so tests never sleep.
    pub fn purge_aged(&mut self, now_ms: i64) -> usize {
        let mut n = 0;
        loop {
            let aged = self
                .queue
                .front()
                .is_some_and(|b| now_ms.saturating_sub(b.arrival_ms) > MAX_AGE_MS);
            if !aged {
                break;
            }
            let Some(mut b) = self.queue.pop_front() else {
                break;
            };
            self.cipher_bytes -= Self::cipher_len(&b.outer);
            wipe_body(&mut b);
            n += 1;
        }
        n
    }

    /// Drain the whole queue with a freshly armed key (R1), in
    /// arrival order. Each held body is decoded with
    /// `wire::rest_envelope`; a decoded body becomes a normal
    /// `pipeline::Incoming` (kind "rest", safe endpoint) — the
    /// caller's `process_batch` writes the NEW decoded raw row plus
    /// the normalized writes. A body that still fails (or the
    /// flagged string-`data` shape, R1) counts `failed`. Every entry
    /// is wiped either way.
    pub fn drain_with_key(&mut self, key: &[u8; 16]) -> DrainOutcome {
        let mut out = DrainOutcome::default();
        while let Some(mut b) = self.queue.pop_front() {
            self.cipher_bytes -= Self::cipher_len(&b.outer);
            let env = wire::rest_envelope(&b.endpoint, &b.outer, Some(key));
            match rest_stats::classify_rest_envelope(&b.outer, &env) {
                RestDecode::Decoded => out.items.push(pipeline::Incoming {
                    kind: "rest",
                    direction: b.direction,
                    endpoint: capture::safe_endpoint(&b.endpoint),
                    env,
                }),
                // `Undecoded` is the expected failure; `NoKey`/`NoCipher`
                // are unreachable through the flusher (the key is armed
                // and only string-`data` bodies queue) — counted, never
                // asserted, so a future path change degrades honestly.
                _ => out.failed += 1,
            }
            wipe_body(&mut b);
        }
        out
    }
}

impl Drop for PendingRest {
    /// Shutdown (R1): every still-queued body is dropped and wiped —
    /// the ciphertext never leaves RAM, and nothing is persisted
    /// beyond each body's truncated no-key row.
    fn drop(&mut self) {
        while let Some(mut b) = self.queue.pop_front() {
            wipe_body(&mut b);
        }
        self.cipher_bytes = 0;
    }
}

/// Best-effort heap wipe of one held body: zero the ciphertext string
/// and the raw endpoint (a URL can carry query-string ids, R2) before
/// the values drop.
fn wipe_body(b: &mut PendingBody) {
    wipe_outer(&mut b.outer);
    b.endpoint.zeroize();
}

/// Zero the ciphertext `data` string in place (best effort — the user
/// must not linger in freed heap); the rest of the outer envelope is
/// response framing, not secrets.
fn wipe_outer(outer: &mut Value) {
    if let Some(Value::String(s)) = outer.get_mut("data") {
        s.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shadow::wire;
    use serde_json::json;

    /// Fake ciphertext-shaped outer (NOT real crypto — the queue only
    /// looks at the string's LENGTH for the bounds; the drain tests
    /// use real `test_encode_rest` bodies).
    fn fake_outer(len: usize) -> Value {
        json!({"error_code": 0, "data": "x".repeat(len)})
    }

    /// A real decryptable outer whose inner names one message `id`.
    fn real_outer(msg_id: &str, key: &[u8; 16]) -> Value {
        let inner = json!({"error_code": 0, "data": {"msgs": [{"msgId": msg_id}]}});
        json!({"error_code": 0, "data": wire::test_encode_rest(&inner, key)})
    }

    #[test]
    fn push_then_drain_decodes_in_arrival_order_with_safe_endpoints() {
        let key: [u8; 16] = [0x19; 16];
        let mut q = PendingRest::new();
        assert_eq!(
            q.push("/a/get-last-msgs?zcid=fake".into(), real_outer("p1", &key), "in", 1_000),
            PushOutcome { accepted: true, evicted: 0 }
        );
        assert_eq!(
            q.push("/a/get-last-msgs?zcid=other".into(), real_outer("p2", &key), "in", 2_000),
            PushOutcome { accepted: true, evicted: 0 }
        );
        assert_eq!(q.len(), 2);
        assert!(q.cipher_bytes() > 0);
        let out = q.drain_with_key(&key);
        assert_eq!(out.decoded(), 2);
        assert_eq!(out.failed, 0);
        assert!(q.is_empty(), "the drain consumes the queue");
        assert_eq!(q.cipher_bytes(), 0);
        // Arrival order, kind "rest", and the endpoint stored SAFE —
        // the raw query-string URL only ever rode RAM.
        for (i, item) in out.items.iter().enumerate() {
            assert_eq!(item.kind, "rest");
            assert_eq!(item.direction, "in");
            assert_eq!(item.endpoint, "/a/get-last-msgs", "no query string survives");
            assert_eq!(item.env["data"]["msgs"][0]["msgId"], format!("p{}", i + 1));
        }
    }

    #[test]
    fn count_bound_evicts_the_oldest_identity_proof() {
        // Fill the queue with REAL bodies, each naming its own id, so
        // the drain proves WHICH body the 33rd push evicted.
        let key: [u8; 16] = [0x19; 16];
        let mut q = PendingRest::new();
        for i in 0..MAX_BODIES {
            let out = q.push(format!("e{i}"), real_outer(&format!("b{i}"), &key), "in", i as i64);
            assert_eq!(out, PushOutcome { accepted: true, evicted: 0 }, "below cap");
        }
        // Push #33 evicts the OLDEST (b0), never the incoming one.
        let out = q.push("e32".into(), real_outer("b32", &key), "in", 32);
        assert_eq!(out, PushOutcome { accepted: true, evicted: 1 });
        assert_eq!(q.len(), MAX_BODIES);
        let drained = q.drain_with_key(&key);
        assert_eq!(drained.decoded(), MAX_BODIES);
        assert_eq!(drained.failed, 0);
        let ids: Vec<String> = drained
            .items
            .iter()
            .map(|it| it.env["data"]["msgs"][0]["msgId"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(ids[0], "b1", "b0 was the evicted one; b1 is now the oldest");
        assert_eq!(ids[31], "b32", "the incoming body survived");
    }

    #[test]
    fn bytes_bound_evicts_oldest_first_and_keeps_the_accounting() {
        // Same eviction path as the count bound (pop_front), so this
        // test pins the BYTE accounting; oldest-first ordering itself
        // is pinned by the count test above.
        let big = 3 * 1024 * 1024; // 3 MiB each; two fit, three do not.
        let mut q = PendingRest::new();
        assert_eq!(q.push("e0".into(), fake_outer(big), "in", 1).evicted, 0);
        assert_eq!(q.push("e1".into(), fake_outer(big), "in", 2).evicted, 0);
        assert_eq!(q.cipher_bytes(), 2 * big);
        // Third 3 MiB body: 9 MiB > 8 MiB -> the OLDEST leaves first.
        let out = q.push("e2".into(), fake_outer(big), "in", 3);
        assert_eq!(out, PushOutcome { accepted: true, evicted: 1 });
        assert_eq!(q.len(), 2);
        assert_eq!(q.cipher_bytes(), 2 * big, "evicted bytes left the budget");
        // Fourth: still 6 MiB + 3 MiB > cap -> evicts again.
        let out = q.push("e3".into(), fake_outer(big), "in", 4);
        assert_eq!(out, PushOutcome { accepted: true, evicted: 1 });
        assert_eq!(q.len(), 2);
        assert_eq!(q.cipher_bytes(), 2 * big);
    }

    #[test]
    fn age_bound_evicts_with_the_injected_clock_no_sleeps() {
        let mut q = PendingRest::new();
        assert_eq!(q.push("e0".into(), fake_outer(10), "in", 0).evicted, 0);
        assert_eq!(q.push("e1".into(), fake_outer(10), "in", 100).evicted, 0);
        // At exactly 10 minutes old an entry is STILL alive (the
        // bound is inclusive-alive).
        assert_eq!(q.purge_aged(MAX_AGE_MS), 0);
        assert_eq!(q.len(), 2);
        // One ms past the bound: e0 leaves, e1 stays.
        assert_eq!(q.purge_aged(MAX_AGE_MS + 100), 1);
        assert_eq!(q.len(), 1);
        assert_eq!(q.cipher_bytes(), 10);
        // push() purges aged entries first (same injected clock).
        let out = q.push("e2".into(), fake_outer(10), "in", MAX_AGE_MS + 200);
        assert_eq!(out, PushOutcome { accepted: true, evicted: 1 }, "e1 aged out");
        assert_eq!(q.len(), 1, "only e2 remains");
        assert_eq!(q.cipher_bytes(), 10);
    }

    #[test]
    fn oversized_single_body_is_refused_at_the_door() {
        let mut q = PendingRest::new();
        // Bigger than the whole bytes budget alone: never queued, and
        // counted with the evicted (dropped without a decode attempt).
        let out = q.push("e0".into(), fake_outer(MAX_CIPHER_BYTES + 1), "in", 1);
        assert_eq!(out, PushOutcome { accepted: false, evicted: 1 });
        assert!(q.is_empty());
        assert_eq!(q.cipher_bytes(), 0);
        // An at-cap body alone still fits ("at most").
        let out = q.push("e1".into(), fake_outer(MAX_CIPHER_BYTES), "in", 2);
        assert_eq!(out, PushOutcome { accepted: true, evicted: 0 });
        assert_eq!(q.cipher_bytes(), MAX_CIPHER_BYTES);
        // One more byte would exceed the budget: the at-cap body goes.
        let out = q.push("e2".into(), fake_outer(1), "in", 3);
        assert_eq!(out, PushOutcome { accepted: true, evicted: 1 });
        assert_eq!(q.cipher_bytes(), 1);
    }

    #[test]
    fn drain_failure_is_counted_and_the_entry_is_consumed() {
        let wrong = [0x11u8; 16]; // the body was sealed with this
        let armed = [0x22u8; 16]; // but the handshake armed this
        let mut q = PendingRest::new();
        assert_eq!(
            q.push("e".into(), real_outer("never", &wrong), "in", 1).evicted,
            0
        );
        let out = q.drain_with_key(&armed);
        assert_eq!(out.failed, 1);
        assert_eq!(out.decoded(), 0);
        assert!(q.is_empty(), "a failed body is dropped, not re-queued");
        assert_eq!(q.cipher_bytes(), 0);
    }

    #[test]
    fn drain_counts_the_flagged_string_data_shape_as_failed() {
        // R1's legacy-shape rule AT THE DRAIN: an inner that decrypts
        // but whose `data` is STILL a string is flagged undecoded by
        // `wire::rest_envelope` -> the drain must count it failed,
        // never emit it as a decoded item.
        let key = [0x33u8; 16];
        let inner = json!({"error_code": 0, "data": "still-a-string"});
        let outer = json!({"error_code": 0, "data": wire::test_encode_rest(&inner, &key)});
        let mut q = PendingRest::new();
        assert_eq!(q.push("e".into(), outer, "in", 1).evicted, 0);
        let out = q.drain_with_key(&key);
        assert_eq!(out.failed, 1);
        assert_eq!(out.decoded(), 0);
        assert!(q.is_empty());
    }
}
