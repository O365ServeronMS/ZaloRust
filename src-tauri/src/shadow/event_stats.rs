//! Counts-only tally of the passively decoded WS events and the extra
//! REST normalizers (batch 30 M2-M6).
//!
//! [`EventTally`] is a pure bag of counters keyed by a FIXED vocabulary
//! of `&'static str` labels (`react.seen`, `grp.join`, `fr.add`,
//! `rcpt.502.delivereds`, `frames.612`, ...): the normalizers can only
//! bump labels this crate names, so the key set is bounded no matter
//! what the wire carries (an unknown group act lands in `grp.other`,
//! an unknown frame in `frames.unclassified`). `normalize` builds one
//! per envelope, `pipeline::process_batch` sums them into
//! `Summary.events`, and the flusher hands the batch's tally to
//! [`record`], which keeps the process-wide cumulative counts and logs
//! at most ONE summary line per 60 s, only when something moved (same
//! throttle shape as `ws_stats` / `rest_stats`).
//!
//! H-rule: labels and counts only — never ids, names, urls or payloads.
//!
//! cmd 3000 (Zalo says another session took over) gets ONE extra
//! counts-only line, "ws: session replaced elsewhere (cmd 3000)",
//! rate-limited to one per hour.

use std::collections::BTreeMap;
use std::sync::Mutex;

/// Minimum spacing between two summary lines.
const LOG_EVERY_MS: i64 = 60_000;
/// Minimum spacing between two cmd-3000 lines.
const DUP_LOGIN_EVERY_MS: i64 = 60 * 60_000;

/// The cmd-3000 label (also the line's trigger).
pub const DUP_LOGIN_LABEL: &str = "dup_login.3000";

/// Counters keyed by a fixed label vocabulary.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct EventTally(pub BTreeMap<&'static str, u64>);

impl EventTally {
    pub fn bump(&mut self, label: &'static str) {
        self.add(label, 1);
    }

    pub fn add(&mut self, label: &'static str, n: u64) {
        if n > 0 {
            *self.0.entry(label).or_insert(0) += n;
        }
    }

    pub fn get(&self, label: &str) -> u64 {
        self.0.get(label).copied().unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn merge(&mut self, other: &EventTally) {
        for (k, n) in &other.0 {
            self.add(k, *n);
        }
    }

    /// `k=v k=v ...` in label order (stable, sorted).
    pub fn render(&self) -> String {
        self.0
            .iter()
            .map(|(k, n)| format!("{k}={n}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Pure throttle: log when the spacing passed and the counts moved.
pub fn log_due(now_ms: i64, last_ms: i64, last: &EventTally, cur: &EventTally) -> bool {
    now_ms.saturating_sub(last_ms) >= LOG_EVERY_MS && last != cur
}

/// Pure hourly gate for the cmd-3000 line (`last_ms = 0` = never).
pub fn dup_login_due(now_ms: i64, last_ms: i64) -> bool {
    last_ms == 0 || now_ms.saturating_sub(last_ms) >= DUP_LOGIN_EVERY_MS
}

struct State {
    cumulative: EventTally,
    last_log_ms: i64,
    last_logged: EventTally,
    last_dup_ms: i64,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);

/// Fold one batch's tally into the process-wide counts and log when
/// due. Called by the flusher after `process_batch`.
pub fn record(batch: &EventTally) {
    if batch.is_empty() {
        return;
    }
    let now = crate::shadow::schema::now_ms();
    let (line, dup) = {
        let mut g = STATE.lock().unwrap_or_else(|e| e.into_inner());
        let st = g.get_or_insert_with(|| State {
            cumulative: EventTally::default(),
            last_log_ms: 0,
            last_logged: EventTally::default(),
            last_dup_ms: 0,
        });
        st.cumulative.merge(batch);
        let line = if log_due(now, st.last_log_ms, &st.last_logged, &st.cumulative) {
            st.last_log_ms = now;
            st.last_logged = st.cumulative.clone();
            Some(format!("shadow events: {} (cumulative)", st.cumulative.render()))
        } else {
            None
        };
        let dup = batch.get(DUP_LOGIN_LABEL) > 0 && dup_login_due(now, st.last_dup_ms);
        if dup {
            st.last_dup_ms = now;
        }
        (line, dup)
    };
    // Logged outside the lock: `dlog` is a plain file append.
    if let Some(l) = line {
        crate::dlog::log(&l);
    }
    if dup {
        crate::dlog::log("ws: session replaced elsewhere (cmd 3000)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tally_adds_merges_and_renders_sorted() {
        let mut a = EventTally::default();
        a.bump("react.seen");
        a.add("react.applied", 2);
        a.add("react.removed", 0); // zero adds nothing
        let mut b = EventTally::default();
        b.bump("react.seen");
        a.merge(&b);
        assert_eq!(a.get("react.seen"), 2);
        assert_eq!(a.get("react.removed"), 0);
        assert_eq!(a.render(), "react.applied=2 react.seen=2");
        assert!(EventTally::default().is_empty());
    }

    #[test]
    fn summary_line_is_throttled_and_only_when_something_moved() {
        let mut cur = EventTally::default();
        cur.bump("grp.join");
        let last = EventTally::default();
        assert!(log_due(60_000, 0, &last, &cur), "first change logs");
        assert!(!log_due(30_000, 0, &last, &cur), "inside the 60 s spacing");
        assert!(!log_due(120_000, 1, &cur, &cur), "nothing moved");
    }

    #[test]
    fn cmd_3000_line_is_hourly() {
        assert!(dup_login_due(5, 0), "never logged -> due");
        assert!(!dup_login_due(1_000 + 59 * 60_000, 1_000));
        assert!(dup_login_due(1_000 + 60 * 60_000, 1_000));
    }

    #[test]
    fn record_accumulates_without_panicking() {
        let mut t = EventTally::default();
        t.bump(DUP_LOGIN_LABEL);
        record(&t);
        record(&EventTally::default());
    }
}
