//! Minimal diagnostic log to a file under the app-data dir, so failures are
//! visible even on a Windows GUI-subsystem build (which has no attached
//! console — `eprintln!` goes nowhere there). Added for issue #3 (Windows
//! toast notifications not appearing).
//!
//! - Windows: `%LOCALAPPDATA%\zalo-web\logs\zalors.log`
//! - Linux:   `$XDG_DATA_HOME/zalo-web/logs/zalors.log` (or `~/.local/share/...`)
//!
//! Truncated once per launch via [`init`] and appended thereafter; once an
//! append would exceed [`MAX_LOG_BYTES`] the file is ROTATED at runtime
//! (current → `zalors.previous.log`, fresh file started, one marker line),
//! so a long soak no longer stops writing at the cap. Best-effort: never
//! panics. It records control flow and error codes only — never message
//! titles or bodies (no PII).

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// The page can reach `log`, so a session's log is capped instead of growing
/// until the disk is full.
const MAX_LOG_BYTES: u64 = 1024 * 1024;
const MAX_LINE_CHARS: usize = 500;

/// Serializes writes across the per-account notification threads.
static LOCK: Mutex<()> = Mutex::new(());

fn log_path() -> Option<PathBuf> {
    if cfg!(test) {
        return None;
    } // Unit fixtures must never pollute the installed app's log.
    if cfg!(debug_assertions) && std::env::var("ZALORS_SMOKE").as_deref() == Ok("1") {
        return std::env::var_os("ZALORS_SMOKE_REPORT")
            .map(PathBuf::from)
            .map(|p| p.with_extension("log"));
    }
    #[cfg(windows)]
    let base: Option<PathBuf> = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    #[cfg(not(windows))]
    let base: Option<PathBuf> = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/share")));

    let dir = base?.join("zalo-web").join("logs");
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir.join("zalors.log"))
}

/// Start a fresh log for this launch (truncate). Best-effort.
pub fn init() {
    if let Some(p) = log_path() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        // Keep the preceding run: a forced termination must not erase the
        // last control-flow evidence as soon as the user opens the app again.
        if p.exists() {
            let previous = p.with_file_name(format!(
                "{}.previous.log",
                p.file_stem().unwrap_or_default().to_string_lossy()
            ));
            let _ = std::fs::copy(&p, previous);
        }
        let _ = std::fs::File::create(&p);
    }
    log("=== session start ===");
}

/// Append one line. Best-effort: silently does nothing if the path or write
/// fails, and never panics (mutex poison is recovered).
pub fn log(msg: &str) {
    let Some(p) = log_path() else { return };
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    append_capped(&p, MAX_LOG_BYTES, ts, msg);
}

/// One capped append, split from [`log`] so the rotation behaviour is
/// unit-testable against an explicit temp path with an injected (small)
/// cap — unit fixtures must never touch the installed app's log
/// (`log_path()` is `None` under `cfg(test)`).
///
/// When the append would exceed `cap`, the current file is rotated away
/// first (see [`rotate`]) and the line lands in the fresh file — the line
/// being written is never lost. If the rotation itself fails, this falls
/// back to the pre-rotation behaviour: the capped file keeps whatever it
/// has and the line is dropped (still never a panic).
fn append_capped(p: &Path, cap: u64, ts: u64, msg: &str) {
    let msg: String = msg.chars().take(MAX_LINE_CHARS).collect();
    let line_len = format!("[{ts}] {msg}\n").len() as u64;
    let cur = std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
    if cur.saturating_add(line_len) > cap && !rotate(p, cap, ts) {
        return; // rotation failed: keep the old capped behaviour
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(p)
    {
        let _ = writeln!(f, "[{ts}] {msg}");
    }
}

/// Move the current log onto `<stem>.previous.log` (replacing it) and start
/// a fresh file with one marker line. Returns false when the rename fails
/// (the caller then keeps the old drop-the-line behaviour; a marker without
/// its file is worthless, so nothing is written in that case). Best-effort:
/// if the fresh file cannot be created, the caller's append still creates
/// it, so a successful rotation never loses the line being written.
fn rotate(p: &Path, cap: u64, ts: u64) -> bool {
    let previous = p.with_file_name(format!(
        "{}.previous.log",
        p.file_stem().unwrap_or_default().to_string_lossy()
    ));
    if std::fs::rename(p, &previous).is_err() {
        return false;
    }
    if let Ok(mut f) = std::fs::File::create(p) {
        let _ = writeln!(f, "[{ts}] dlog: rotated (cap {cap})");
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn unit_fixtures_never_use_the_installed_log() {
        assert!(super::log_path().is_none());
    }

    /// A unique temp dir per test (parallel-safe); removed on drop.
    struct TempDir(PathBuf);
    impl TempDir {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "zr-dlog-test-{tag}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis())
                    .unwrap_or(0)
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            TempDir(dir)
        }
        fn log(&self) -> PathBuf {
            self.0.join("zalors.log")
        }
        fn previous(&self) -> PathBuf {
            self.0.join("zalors.previous.log")
        }
        fn read(&self, p: &Path) -> String {
            std::fs::read_to_string(p).unwrap_or_default()
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn rotation_at_cap_keeps_the_line_and_the_old_content() {
        let t = TempDir::new("rotate");
        // A small injected cap: three ~len-16 lines blow past 40 bytes.
        let cap = 40u64;
        append_capped(&t.log(), cap, 1000, "line one");
        append_capped(&t.log(), cap, 1001, "line two");
        // This append would exceed the cap: rotate first, then land.
        append_capped(&t.log(), cap, 1002, "line three past the cap");

        let cur = t.read(&t.log());
        let prev = t.read(&t.previous());
        // The line being written is never lost.
        assert!(cur.contains("line three past the cap"), "current: {cur:?}");
        // The fresh file carries exactly one rotation marker line,
        // reporting the cap it rotated at.
        assert!(cur.contains("dlog: rotated (cap 40)"), "current: {cur:?}");
        assert_eq!(
            cur.lines().count(),
            2,
            "marker + the line that triggered the rotation"
        );
        // Everything written before the rotation moved to .previous.log.
        assert!(prev.contains("line one"));
        assert!(prev.contains("line two"));
        assert!(!prev.contains("rotated"));
        // The capped file stays small — the cap still holds.
        assert!(cur.len() as u64 <= cap + 64);
    }

    #[test]
    fn rotation_failure_falls_back_to_the_old_capped_behaviour() {
        let t = TempDir::new("renamefail");
        append_capped(&t.log(), 100, 2000, "early line");
        // Make the rename fail: the rotation target is a DIRECTORY,
        // so `rename(file -> existing dir)` cannot succeed.
        std::fs::create_dir_all(t.previous()).unwrap();
        let before = t.read(&t.log());
        // No panic (the test itself proves that), and the old
        // behaviour holds: the capped file is left untouched and the
        // would-have-rotated line is dropped.
        append_capped(&t.log(), 10, 2001, "this line exceeds the cap");
        assert_eq!(t.read(&t.log()), before, "no write, no panic");
        assert_eq!(
            std::fs::read_dir(t.previous()).unwrap().count(),
            0,
            "the blocker directory is untouched"
        );
    }

    #[test]
    fn under_the_cap_never_rotates() {
        let t = TempDir::new("nocap");
        append_capped(&t.log(), 1024, 3000, "fits");
        append_capped(&t.log(), 1024, 3001, "fits too");
        let cur = t.read(&t.log());
        assert!(cur.contains("fits"));
        assert!(cur.contains("fits too"));
        assert!(!cur.contains("rotated"));
        assert!(!t.previous().exists(), "no .previous.log is created");
    }

    #[test]
    fn line_length_limit_still_applies() {
        let t = TempDir::new("linelen");
        let long: String = "x".repeat(MAX_LINE_CHARS + 500);
        append_capped(&t.log(), 1 << 20, 4000, &long);
        let cur = t.read(&t.log());
        let msg = cur
            .strip_prefix("[4000] ")
            .unwrap_or(&cur)
            .trim_end_matches('\n')
            .to_string();
        assert_eq!(msg.chars().count(), MAX_LINE_CHARS);
    }
}
