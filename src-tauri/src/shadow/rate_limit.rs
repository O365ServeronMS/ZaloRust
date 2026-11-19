//! Pure token bucket (audit M3 / D3, batch 4).
//!
//! `shadow_e2ee_message` and `shadow_handshake` are callable by ANY
//! script on chat.zalo.me (the ACL already limits callers to that
//! origin). Page scripts are trusted at page level — the same level
//! the page itself runs at — and the bucket does not change that
//! trust; it only bounds abuse, so a runaway loop or a hostile script
//! on the page cannot flood the shadow pipeline or spam handshakes.
//!
//! No wall clock inside: the caller passes `now_ms`, so the arithmetic
//! (including the awkward edges) is unit-testable.

/// One token bucket. `tokens` starts full (`capacity`); `last_ms = 0`
/// means "never used", and the first refill is capped by `capacity`
/// like any other, so a fresh bucket neither starves nor overflows.
#[derive(Debug, Clone)]
pub struct RateLimiter {
    capacity: f64,
    refill_per_sec: f64,
    tokens: f64,
    last_ms: i64,
}

impl RateLimiter {
    /// `refill_per_sec` may be fractional (e.g. 1 token per 60 s is
    /// `1.0 / 60.0`). `const` so it can sit behind a static `Mutex`.
    pub const fn new(capacity: f64, refill_per_sec: f64) -> Self {
        Self { capacity, refill_per_sec, tokens: capacity, last_ms: 0 }
    }

    /// Take one token, refilling for the elapsed time first.
    ///
    /// Time going backwards never refills and never panics: the clock
    /// anomaly is ignored (the bucket keeps its previous fill state),
    /// not rewarded. A long idle refills up to `capacity` and no
    /// further.
    pub fn allow(&mut self, now_ms: i64) -> bool {
        if now_ms > self.last_ms {
            let elapsed_ms = (now_ms - self.last_ms) as f64;
            self.tokens =
                (self.tokens + elapsed_ms * self.refill_per_sec / 1000.0).min(self.capacity);
            self.last_ms = now_ms;
        }
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RateLimiter;

    #[test]
    fn burst_spends_capacity_then_denies() {
        let mut b = RateLimiter::new(5.0, 0.0); // no refill: pure burst
        let now = 1_000_000i64;
        for _ in 0..5 {
            assert!(b.allow(now), "capacity of 5 must absorb a burst of 5");
        }
        assert!(!b.allow(now), "the 6th call in a burst is over the limit");
        assert!(!b.allow(now));
    }

    #[test]
    fn refill_recovers_one_token_per_interval() {
        // 10 tokens/sec: after 100 ms exactly one token is back.
        let mut b = RateLimiter::new(2.0, 10.0);
        let t0 = 100_000i64;
        assert!(b.allow(t0));
        assert!(b.allow(t0));
        assert!(!b.allow(t0), "burst spent");
        assert!(!b.allow(t0 + 50), "half an interval is half a token");
        assert!(b.allow(t0 + 100), "one full interval refills one token");
        assert!(!b.allow(t0 + 100), "…and only one");
        // A long stretch refills back to capacity, not beyond.
        assert!(b.allow(t0 + 1_000_000));
        assert!(b.allow(t0 + 1_000_000));
        assert!(!b.allow(t0 + 1_000_000));
    }

    #[test]
    fn long_idle_does_not_overflow_capacity() {
        let mut b = RateLimiter::new(3.0, 50.0);
        // Spend everything, then idle "forever".
        let t0 = 1_000i64;
        for _ in 0..3 {
            assert!(b.allow(t0));
        }
        assert!(!b.allow(t0));
        let much_later = t0 + 10_000_000_000;
        for _ in 0..3 {
            assert!(b.allow(much_later), "idle refill is capped at capacity");
        }
        assert!(!b.allow(much_later), "no more than capacity");
        // Same from a fresh bucket whose last_ms is 0 (never used):
        let mut fresh = RateLimiter::new(3.0, 50.0);
        for _ in 0..3 {
            assert!(fresh.allow(much_later));
        }
        assert!(!fresh.allow(much_later));
    }

    #[test]
    fn time_going_backwards_neither_panics_nor_grants_extra() {
        let mut b = RateLimiter::new(2.0, 1000.0); // very fast refill
        let t0 = 5_000i64;
        assert!(b.allow(t0));
        assert!(b.allow(t0));
        assert!(!b.allow(t0), "spent");
        // Clock jumps backwards: no refill, no panic, still spent.
        assert!(!b.allow(t0 - 4_000), "backwards time must not grant");
        assert!(!b.allow(0));
        // The bucket kept its own clock: forward time refills from
        // t0, not from the bogus earlier stamps.
        assert!(b.allow(t0 + 1));
    }

    #[test]
    fn fractional_refill_of_one_token_per_minute() {
        // The handshake shape (D3): capacity 5, 1 token per 60 s.
        let mut b = RateLimiter::new(5.0, 1.0 / 60.0);
        let t0 = 1_000_000i64;
        for _ in 0..5 {
            assert!(b.allow(t0));
        }
        assert!(!b.allow(t0));
        // 59 s is not yet a whole token back…
        assert!(!b.allow(t0 + 59_000), "just under one minute");
        // …60 s is.
        assert!(b.allow(t0 + 60_000), "one full minute refills one token");
        assert!(!b.allow(t0 + 60_000));
        // A new process starts full again (fresh bucket).
        let mut fresh = RateLimiter::new(5.0, 1.0 / 60.0);
        for _ in 0..5 {
            assert!(fresh.allow(t0 + 120_000));
        }
    }

    #[test]
    fn e2ee_shape_absorbs_a_history_sync_and_still_bounds_abuse() {
        // The e2ee shape (R2, batch 4 review): capacity 5000, refill
        // 500/s. Opening a large conversation or the post-login sync
        // decrypts history in bursts — hundreds to thousands of
        // messages in seconds — and dropping legitimate plaintext is
        // unrecoverable data loss. The bucket absorbs the whole burst
        // and still bounds abuse: past the burst a runaway loop
        // stalls at 500/s.
        let mut b = RateLimiter::new(5000.0, 500.0);
        let t0 = 1_000_000i64;
        // The whole burst lands at one instant and fits.
        for _ in 0..5_000 {
            assert!(b.allow(t0), "a history-sync burst of 5000 must fit");
        }
        assert!(!b.allow(t0), "past the burst the bucket does bound abuse");
        // 500/s refill: 1 ms is half a token, 2 ms one full token.
        assert!(!b.allow(t0 + 1), "1 ms is only half a token back");
        assert!(b.allow(t0 + 2), "2 ms refills one full token at 500/s");
        // Sustained past-burst traffic runs at exactly the refill
        // rate, never faster: 2.5 s of 1-ms calls grant 1_250.
        let mut allowed = 0u32;
        for ms in 3..2_503 {
            if b.allow(t0 + ms) {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 1_250, "2.5 s of traffic at 500/s");
    }
}
