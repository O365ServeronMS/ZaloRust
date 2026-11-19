//! WS frame stage counters (audit M4 / D2, batch 4).
//!
//! Text-opcode frames used to fail base64 and vanish silently (audit
//! §2-M4), and closes were invisible. This module counts, cumulatively
//! per process:
//!
//! ```text
//! ok      frames whose payload base64-decoded and were delivered
//! text    text-opcode frames (counted, NEVER decoded — that is policy)
//! bad_b64 binary-shaped payloads that failed base64
//! closed  tracked connections that closed
//! keys    live gauge: per-connection keys currently armed in the flusher
//! ```
//!
//! R1 (batch 4 review) added two eviction counters so bounded-store
//! behaviour is visible instead of silent:
//! ```text
//! ids_evicted  ws_ids entries evicted at WS_IDS_CAP (capture layer,
//!              oldest-only — the clear-all it replaced took the live
//!              socket's id with it)
//! keys_evicted per-connection keys evicted at WS_KEYS_CAP (flusher,
//!              oldest-only — a WS key is sent ONCE per connection,
//!              so an evicted one stays undecoded until reconnect)
//! ```
//!
//! One summary line logs at most once per 60 s and only when a counter
//! moved — the same throttle shape as `rest_stats`. Counts only: never
//! urls, requestIds, payloads or key bytes (H-rule).
//!
//! The bumping thread is the WebView2 UI thread (capture events); the
//! `keys` gauge is set by the flusher whenever its key map changes.
//! Everything pure (formatting, the throttle decision) lives in free
//! functions so it is unit-testable without a live WebView2.

use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::sync::Mutex;
use std::time::Duration;

/// Minimum spacing between two summary log lines (same as `rest_stats`).
const LOG_EVERY: Duration = Duration::from_secs(60);

/// One stage whose counter bumps by one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsStage {
    /// A frame classified binary and delivered to the flusher.
    FramesOk,
    /// A text-opcode frame (opcode 1): counted, never decoded.
    TextFrames,
    /// A binary-shaped payload that failed base64 (used to vanish).
    BadB64,
    /// A tracked connection closed (its flusher key was dropped).
    Closed,
    /// R1: a `ws_ids` entry was evicted at `WS_IDS_CAP` (oldest-only
    /// — counted so capture loss is visible, never silent).
    IdsEvicted,
    /// R1: a per-connection WS key was evicted at `WS_KEYS_CAP`
    /// (oldest-only — that connection stays undecoded until it
    /// reconnects, so the count must be visible).
    KeysEvicted,
}

/// Cumulative per-process counters (Relaxed ordering: counts only).
#[derive(Debug, Default)]
pub struct WsStageCounters {
    pub frames_ok: AtomicU64,
    pub text_frames: AtomicU64,
    pub bad_b64: AtomicU64,
    pub closed: AtomicU64,
    pub ids_evicted: AtomicU64,
    pub keys_evicted: AtomicU64,
}

pub static WS_STAGES: WsStageCounters = WsStageCounters {
    frames_ok: AtomicU64::new(0),
    text_frames: AtomicU64::new(0),
    bad_b64: AtomicU64::new(0),
    closed: AtomicU64::new(0),
    ids_evicted: AtomicU64::new(0),
    keys_evicted: AtomicU64::new(0),
};

/// Live gauge: how many per-connection keys the flusher holds right
/// now. A count, not a value — the gauge never names a connection.
pub static WS_KEYS_LIVE: AtomicU64 = AtomicU64::new(0);

/// A point-in-time copy of the stage counters.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct WsStageSnapshot {
    pub frames_ok: u64,
    pub text_frames: u64,
    pub bad_b64: u64,
    pub closed: u64,
    pub ids_evicted: u64,
    pub keys_evicted: u64,
}

impl WsStageSnapshot {
    /// Const zeroed snapshot (for static initialization).
    pub const fn zeroed() -> Self {
        Self {
            frames_ok: 0,
            text_frames: 0,
            bad_b64: 0,
            closed: 0,
            ids_evicted: 0,
            keys_evicted: 0,
        }
    }
}

impl WsStageCounters {
    fn field(&self, s: WsStage) -> &AtomicU64 {
        match s {
            WsStage::FramesOk => &self.frames_ok,
            WsStage::TextFrames => &self.text_frames,
            WsStage::BadB64 => &self.bad_b64,
            WsStage::Closed => &self.closed,
            WsStage::IdsEvicted => &self.ids_evicted,
            WsStage::KeysEvicted => &self.keys_evicted,
        }
    }

    /// Increment one stage on THIS instance (no logging).
    pub fn bump_on(&self, s: WsStage) {
        self.field(s).fetch_add(1, Relaxed);
    }

    /// Copy of all counters (used by the pure helpers below).
    pub fn snapshot(&self) -> WsStageSnapshot {
        WsStageSnapshot {
            frames_ok: self.frames_ok.load(Relaxed),
            text_frames: self.text_frames.load(Relaxed),
            bad_b64: self.bad_b64.load(Relaxed),
            closed: self.closed.load(Relaxed),
            ids_evicted: self.ids_evicted.load(Relaxed),
            keys_evicted: self.keys_evicted.load(Relaxed),
        }
    }
}

/// Bump the process-wide counters, then maybe log the summary line.
pub fn bump(s: WsStage) {
    WS_STAGES.bump_on(s);
    maybe_log();
}

/// Publish the flusher's live key count (a gauge, not a counter: no
/// summary is triggered by it alone).
pub fn set_keys(n: u64) {
    WS_KEYS_LIVE.store(n, Relaxed);
}

/// Pure: the one summary line (cumulative counts + the live key
/// gauge). R1: the two eviction counts ride the same fixed template —
/// bounded-store capture loss must be visible, never silent.
pub fn format_stage_line(s: &WsStageSnapshot, keys: u64) -> String {
    format!(
        "shadow ws stages: ok={} text={} bad_b64={} closed={} ids_evicted={} keys_evicted={} keys={} (cumulative)",
        s.frames_ok, s.text_frames, s.bad_b64, s.closed, s.ids_evicted, s.keys_evicted, keys
    )
}

/// Pure throttle decision (the same shape `rest_stats` uses): emit when
/// `LOG_EVERY` has passed since the last line AND at least one counter
/// moved since it. `last_log_ms = 0` means "never logged", so the first
/// change logs immediately.
pub fn log_due(now_ms: i64, last_log_ms: i64, last: &WsStageSnapshot, cur: &WsStageSnapshot) -> bool {
    now_ms.saturating_sub(last_log_ms) >= LOG_EVERY.as_millis() as i64 && last != cur
}

/// Last logged line: when it was emitted and the counts it showed.
struct LastLog {
    ms: i64,
    snap: WsStageSnapshot,
}

static LAST_LOG: Mutex<LastLog> =
    Mutex::new(LastLog { ms: 0, snap: WsStageSnapshot::zeroed() });

fn maybe_log() {
    let now = crate::shadow::schema::now_ms();
    let snap = WS_STAGES.snapshot();
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
        let keys = WS_KEYS_LIVE.load(Relaxed);
        crate::dlog::log(&format_stage_line(&snap, keys));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_line_format() {
        let zero = WsStageSnapshot::zeroed();
        assert_eq!(
            format_stage_line(&zero, 0),
            "shadow ws stages: ok=0 text=0 bad_b64=0 closed=0 ids_evicted=0 keys_evicted=0 keys=0 (cumulative)"
        );
        let mut s = zero;
        s.frames_ok = 100;
        s.text_frames = 7;
        s.bad_b64 = 2;
        s.closed = 1;
        s.ids_evicted = 3;
        s.keys_evicted = 1;
        let line = format_stage_line(&s, 4);
        assert!(line.contains("ok=100 text=7"), "{line}");
        assert!(line.contains("bad_b64=2 closed=1"), "{line}");
        assert!(
            line.contains("ids_evicted=3 keys_evicted=1 keys=4"),
            "{line}"
        );
        assert!(line.ends_with("(cumulative)"), "{line}");
        // Fixed template + integers only: no requestId, url or payload
        // fragment can ever appear.
        for forbidden in ["https", "zalo", "requestId", "{", "}"] {
            assert!(!line.contains(forbidden), "{line}");
        }
    }

    #[test]
    fn throttle_shape() {
        let a = WsStageSnapshot::zeroed();
        let mut b = a;
        b.frames_ok = 1;
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
        let c = WsStageCounters::default();
        for _ in 0..2 {
            c.bump_on(WsStage::FramesOk);
        }
        c.bump_on(WsStage::TextFrames);
        c.bump_on(WsStage::BadB64);
        c.bump_on(WsStage::Closed);
        // R1: both eviction stages count too.
        c.bump_on(WsStage::IdsEvicted);
        c.bump_on(WsStage::IdsEvicted);
        c.bump_on(WsStage::KeysEvicted);
        let s = c.snapshot();
        assert_eq!(s.frames_ok, 2);
        assert_eq!(s.text_frames, 1);
        assert_eq!(s.bad_b64, 1);
        assert_eq!(s.closed, 1);
        assert_eq!(s.ids_evicted, 2);
        assert_eq!(s.keys_evicted, 1);
        let zero = WsStageSnapshot::zeroed();
        assert!(log_due(120_000, 0, &zero, &s));
    }
}
