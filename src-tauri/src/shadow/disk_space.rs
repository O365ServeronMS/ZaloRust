//! Disk-space guard for the shadow media store (audit §4 item 4.3,
//! D13, batch 8 H3).
//!
//! Pure verdict ([`space_verdict`]) + one Win32 call
//! ([`disk_free_space`]). The media worker checks the store volume
//! BEFORE every download cycle; on [`SpaceVerdict::Stop`] it skips the
//! cycle entirely (rows stay `ref`, nothing is marked failed) and text
//! capture is never affected — it lives on the flusher, not here.
//!
//! H-rules: the transition messages are static; free/total bytes never
//! enter a log line.
//!
//! Free-space API: batch 7 skipped the KQ9 free-space check because
//! the `windows` crate's `Win32_Storage_FileSystem` feature is not
//! enabled and no batch may add crates/features — so this module
//! declares `GetDiskFreeSpaceExW` by hand, exactly the way `main.rs`
//! declares `AttachConsole` for the import CLI (batch 7 G4).

use std::path::Path;

/// Media-download decision for one volume check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpaceVerdict {
    /// Enough free space (or unknown — never pause on missing data).
    Ok,
    /// Free space at or below the warn threshold: downloads continue,
    /// one log line per transition.
    Warn,
    /// Free space at or below the stop threshold: downloads pause
    /// until space returns above it.
    Stop,
}

/// Pure threshold decision (unit-tested; no IO).
///
/// `free_pct = free/total` compared INCLUSIVELY against the thresholds
/// (`free_pct == stop_pct` is already `Stop` — stopping one threshold
/// early is safer than one late). `warn_pct < stop_pct` is a benign
/// misconfiguration: the Stop arm is checked first, so a warn line
/// below the stop threshold is simply unreachable. A zero total (the
/// API failed or returned nothing) is `Ok`: an unmeasurable volume
/// must not pause downloads, and the next cycle re-checks.
pub fn space_verdict(free_bytes: u64, total_bytes: u64, warn_pct: u8, stop_pct: u8) -> SpaceVerdict {
    if total_bytes == 0 {
        return SpaceVerdict::Ok;
    }
    // u128 keeps the percentage math exact for any u64 volume.
    let free = free_bytes as u128;
    let total = total_bytes as u128;
    if free * 100 <= u128::from(stop_pct) * total {
        SpaceVerdict::Stop
    } else if free * 100 <= u128::from(warn_pct) * total {
        SpaceVerdict::Warn
    } else {
        SpaceVerdict::Ok
    }
}

/// The one log line a verdict transition produces, or `None` when the
/// state did not change (H-rule: log ONCE per transition, so a volume
/// sitting below a threshold never spams the log). Pure.
pub fn transition_log(prev: SpaceVerdict, now: SpaceVerdict) -> Option<&'static str> {
    use SpaceVerdict::{Ok, Stop, Warn};
    if prev == now {
        return None;
    }
    Some(match now {
        Stop => "shadow media: paused (disk space)",
        Warn => {
            if prev == Stop {
                "shadow media: resumed (disk space)"
            } else {
                "shadow media: disk space warn"
            }
        }
        Ok => {
            if prev == Stop {
                "shadow media: resumed (disk space)"
            } else {
                "shadow media: disk space ok"
            }
        }
    })
}

/// Free/total bytes of the volume holding `dir`, as Windows reports
/// them for THIS caller (`lpFreeBytesAvailableToCaller` — the
/// quota-limited number the process can actually write).
///
/// Windows-only by design (the shipped app is a Windows build; the
/// SQLCipher store path is Windows-pinned too). Other platforms get
/// `None`, which the callers map to [`SpaceVerdict::Ok`] — an
/// unmeasurable volume never pauses anything.
#[cfg(windows)]
pub fn disk_free_space(dir: &Path) -> Option<(u64, u64)> {
    use std::os::windows::ffi::OsStrExt;
    // kernel32 import declared by hand — same pattern as main.rs's
    // AttachConsole (no new crates or windows-rs features).
    #[link(name = "kernel32")]
    extern "system" {
        fn GetDiskFreeSpaceExW(
            lpDirectoryName: *const u16,
            lpFreeBytesAvailableToCaller: *mut u64,
            lpTotalNumberOfBytes: *mut u64,
            lpTotalNumberOfFreeBytes: *mut u64,
        ) -> i32;
    }
    let mut wide: Vec<u16> = dir.as_os_str().encode_wide().collect();
    wide.push(0);
    let (mut free, mut total, mut total_free) = (0u64, 0u64, 0u64);
    // BOOL: nonzero on success. The directory does not need to exist
    // for the VOLUME holding it to be resolved, but a missing volume
    // returns 0 → None (fail-open at the caller, never a fake number).
    let ok = unsafe {
        GetDiskFreeSpaceExW(wide.as_ptr(), &mut free, &mut total, &mut total_free)
    };
    (ok != 0).then_some((free, total))
}

#[cfg(not(windows))]
pub fn disk_free_space(_dir: &Path) -> Option<(u64, u64)> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // 1 GiB / 100 GiB for percentage math.
    const GIB: u64 = 1024 * 1024 * 1024;
    const PCT: u64 = GIB / 100; // exactly 1% of a 100 GiB volume

    #[test]
    fn verdicts_follow_the_thresholds_inclusively() {
        // Defaults from the settings: warn 10 %, stop 3 %.
        assert_eq!(space_verdict(50 * GIB, 100 * GIB, 10, 3), SpaceVerdict::Ok);
        assert_eq!(space_verdict(10 * GIB, 100 * GIB, 10, 3), SpaceVerdict::Warn);
        assert_eq!(space_verdict(3 * GIB, 100 * GIB, 10, 3), SpaceVerdict::Stop);
        // The thresholds are INCLUSIVE (free_pct == threshold counts
        // as that tier); one byte above a line is the tier above it.
        assert_eq!(space_verdict(10 * GIB + 1, 100 * GIB, 10, 3), SpaceVerdict::Ok);
        assert_eq!(space_verdict(3 * GIB + 1, 100 * GIB, 10, 3), SpaceVerdict::Warn);
        assert_eq!(space_verdict(3 * GIB - 1, 100 * GIB, 10, 3), SpaceVerdict::Stop);
        // Between the two lines is Warn on BOTH sides (10 % is the
        // warn line itself; below it, still above stop, stays Warn).
        assert_eq!(space_verdict(10 * GIB - 1, 100 * GIB, 10, 3), SpaceVerdict::Warn);
        assert_eq!(space_verdict(4 * GIB, 100 * GIB, 10, 3), SpaceVerdict::Warn);
    }

    #[test]
    fn verdict_edges_zero_total_zero_pct_full_disk() {
        // Unmeasurable volume: never a pause on missing data.
        assert_eq!(space_verdict(0, 0, 10, 3), SpaceVerdict::Ok);
        // stop_pct = 0: only a literally full/over-full disk stops —
        // but the warn tier still applies above it.
        assert_eq!(space_verdict(1, 100 * GIB, 10, 0), SpaceVerdict::Warn);
        assert_eq!(space_verdict(0, 100 * GIB, 10, 0), SpaceVerdict::Stop);
        // warn_pct = 100 (hand-edited maximum): everything warns —
        // even a 100 % free volume sits ON the warn line — and a
        // full disk still stops.
        assert_eq!(space_verdict(99 * GIB, 100 * GIB, 100, 3), SpaceVerdict::Warn);
        assert_eq!(space_verdict(100 * GIB, 100 * GIB, 100, 3), SpaceVerdict::Warn);
        assert_eq!(space_verdict(0, 100 * GIB, 100, 3), SpaceVerdict::Stop);
        // warn below stop is a benign no-op (Stop is checked first).
        assert_eq!(space_verdict(2 * GIB, 100 * GIB, 1, 3), SpaceVerdict::Stop);
        assert_eq!(space_verdict(50 * GIB, 100 * GIB, 1, 3), SpaceVerdict::Ok);
        // Fractional percentages stay exact (u128 math, no rounding):
        // 2.5 % free with stop 3 % must Stop even though integer
        // division of small numbers could floor it to 2.
        assert_eq!(space_verdict(5 * PCT / 2, 100 * GIB, 10, 3), SpaceVerdict::Stop);
    }

    #[test]
    fn transition_log_lines_are_exact_and_once_per_change() {
        use SpaceVerdict::{Ok, Stop, Warn};
        // No change → no line, ever.
        assert_eq!(transition_log(Ok, Ok), None);
        assert_eq!(transition_log(Warn, Warn), None);
        assert_eq!(transition_log(Stop, Stop), None);
        // Entering Stop from either side pauses.
        assert_eq!(transition_log(Ok, Stop), Some("shadow media: paused (disk space)"));
        assert_eq!(transition_log(Warn, Stop), Some("shadow media: paused (disk space)"));
        // Leaving Stop resumes (also Stop→Warn: downloads resume there).
        assert_eq!(transition_log(Stop, Ok), Some("shadow media: resumed (disk space)"));
        assert_eq!(transition_log(Stop, Warn), Some("shadow media: resumed (disk space)"));
        // Ok↔Warn warns/heals.
        assert_eq!(transition_log(Ok, Warn), Some("shadow media: disk space warn"));
        assert_eq!(transition_log(Warn, Ok), Some("shadow media: disk space ok"));
    }

    #[cfg(windows)]
    #[test]
    fn disk_free_space_measures_the_temp_volume_sensibly() {
        // Shape-only: a real volume reports a positive total and a
        // free number within it. No bytes are logged anywhere.
        let (free, total) = disk_free_space(&std::env::temp_dir())
            .expect("GetDiskFreeSpaceExW must work on the temp dir");
        assert!(total > 0);
        assert!(free <= total);
    }

    #[cfg(not(windows))]
    #[test]
    fn disk_free_space_is_none_off_windows() {
        assert_eq!(disk_free_space(Path::new("/tmp")), None);
    }

    #[test]
    fn a_missing_volume_reports_none_not_zeroes() {
        // A path on a volume the OS cannot resolve must yield None
        // (fail-open at the caller) — never (0, N), which would read
        // as a full disk and stop downloads forever. The reserved
        // device namespace with a made-up name resolves to nothing on
        // Windows; non-Windows is None by definition.
        assert_eq!(disk_free_space(Path::new(r"\\.\nonexistent-zr-volume\x")), None);
    }
}
