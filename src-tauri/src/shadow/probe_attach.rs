//! Attachments probe for the batch-2 media layout (audit §1.3 AC,
//! batch 5 E2). SHAPE ONLY: counts, statuses and kinds — never urls,
//! file names, sizes or content.
//!
//! Reads through a temp COPY of the DB (M2-6: a READ_ONLY connection
//! still touches the live `-shm`); files in the media store are opened
//! READ-ONLY and never modified.
//!
//! For `downloaded` rows the probe re-verifies the store contract
//! (audit §1.3 verify step): `media::resolve_local_path` maps the
//! stored `local_path` under the media root (`ZR_MEDIA_ROOT` overrides
//! the root so a moved/copied store can be probed); sha256(file) is
//! compared with the `sha256` column AND with the file name (by
//! convention the name IS the sha); image/video bytes are sniffed with
//! the SAME `media::magic_ok` the downloader uses.
//!
//! Run: cargo test --lib probe_attach -- --ignored --nocapture

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::{media, probe_util};
use crate::settings::ShadowSettings;

/// One downloaded row's verdict (disjoint categories — checks run in a
/// fixed priority: file_missing > size_mismatch > sha_mismatch >
/// magic_bad — so every row lands in exactly one bucket).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Ok,
    FileMissing,
    SizeMismatch,
    ShaMismatch,
    MagicBad,
}

/// A plausible sha file name (the store's convention: name == sha).
fn looks_like_sha_name(name: &str) -> bool {
    name.len() == 64 && name.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Verdict for one `downloaded` row (pure: reads the file, writes
/// nothing). KQ9: new rows store a RELATIVE path resolved against the
/// media root; legacy rows stored absolute paths — checked where they
/// point, read-only either way. A NULL/legacy cell never fabricates a
/// mismatch: missing comparisons are skipped, not failed.
fn verdict(
    kind: Option<&str>,
    local_path: Option<&str>,
    sha_col: Option<&str>,
    size_col: Option<i64>,
    cfg: &ShadowSettings,
) -> Verdict {
    let Some(p) = local_path else { return Verdict::FileMissing };
    let path = if Path::new(p).is_absolute() {
        PathBuf::from(p)
    } else {
        media::resolve_local_path(cfg, p)
    };
    let Ok(bytes) = std::fs::read(&path) else {
        return Verdict::FileMissing;
    };
    if let Some(want) = size_col {
        if want != bytes.len() as i64 {
            return Verdict::SizeMismatch;
        }
    }
    let mut h = Sha256::new();
    h.update(&bytes);
    let sha = format!("{:x}", h.finalize());
    // sha256(file) vs the sha256 column…
    if let Some(col) = sha_col {
        if !sha.eq_ignore_ascii_case(col) {
            return Verdict::ShaMismatch;
        }
    }
    // …and vs the file name (only when the name is a plausible sha, so
    // legacy file names cannot produce noise).
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if looks_like_sha_name(name) && !name.eq_ignore_ascii_case(&sha) {
        return Verdict::ShaMismatch;
    }
    // B4/KQ1 magic sniff (image/video only; other kinds pass).
    if !media::magic_ok(kind, &bytes) {
        return Verdict::MagicBad;
    }
    Verdict::Ok
}

/// The media cfg probes use: `ShadowSettings::default()` with an
/// optional `ZR_MEDIA_ROOT` override of the store root.
fn probe_cfg() -> ShadowSettings {
    let mut cfg = ShadowSettings::default();
    if let Some(root) = std::env::var_os("ZR_MEDIA_ROOT") {
        if !root.is_empty() {
            cfg.media_store = Some(root.to_string_lossy().into_owned());
        }
    }
    cfg
}

#[test]
#[ignore]
fn probe_attach() {
    let (conn, _tmp) = probe_util::open_copy();
    let cfg = probe_cfg();

    println!("== attachments by status x kind ==");
    {
        let mut st = conn
            .prepare(
                "SELECT status, COALESCE(kind,'-'), COUNT(*)
                 FROM attachments GROUP BY 1,2 ORDER BY 1,2",
            )
            .unwrap();
        let rows = st
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)?))
            })
            .unwrap();
        for row in rows {
            let (status, kind, n) = row.unwrap();
            println!("  {status} x {kind} = {n}");
        }
    }

    // KQ9: downloaded rows' local_path — absolute (legacy) vs relative.
    let (abs, rel, none): (i64, i64, i64) = {
        let mut st = conn
            .prepare("SELECT local_path FROM attachments WHERE status='downloaded'")
            .unwrap();
        let rows = st
            .query_map([], |r| r.get::<_, Option<String>>(0))
            .unwrap();
        let (mut a, mut r, mut n) = (0i64, 0i64, 0i64);
        for row in rows {
            match row.unwrap() {
                Some(p) if Path::new(&p).is_absolute() => a += 1,
                Some(_) => r += 1,
                None => n += 1,
            }
        }
        (a, r, n)
    };
    println!("downloaded: local_path_abs={abs} local_path_rel={rel} local_path_null={none}");

    // Per-row file verification (read-only; counts only).
    let mut counts: std::collections::BTreeMap<&str, usize> = Default::default();
    {
        let mut st = conn
            .prepare("SELECT kind, local_path, sha256, size FROM attachments WHERE status='downloaded'")
            .unwrap();
        let rows = st
            .query_map([], |r| {
                Ok((
                    r.get::<_, Option<String>>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, Option<i64>>(3)?,
                ))
            })
            .unwrap();
        for row in rows {
            let (kind, path, sha, size) = row.unwrap();
            let v = verdict(kind.as_deref(), path.as_deref(), sha.as_deref(), size, &cfg);
            let label = match v {
                Verdict::Ok => "ok",
                Verdict::FileMissing => "file_missing",
                Verdict::SizeMismatch => "size_mismatch",
                Verdict::ShaMismatch => "sha_mismatch",
                Verdict::MagicBad => "magic_bad",
            };
            *counts.entry(label).or_default() += 1;
        }
    }
    let line: Vec<String> = counts.iter().map(|(k, n)| format!("{k}={n}")).collect();
    println!("downloaded file check: {}", line.join(" "));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unique scratch dir under the OS temp dir — never the live
    /// media root (same pattern as the media.rs tests).
    fn scratch() -> PathBuf {
        let uniq = format!(
            "zr-attach-probe-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let d = std::env::temp_dir().join(uniq);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn sha_hex(bytes: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(bytes);
        format!("{:x}", h.finalize())
    }

    fn cfg_for(root: &Path) -> ShadowSettings {
        let mut cfg = ShadowSettings::default();
        cfg.media_store = Some(root.to_string_lossy().into_owned());
        cfg
    }

    #[test]
    fn verdict_buckets_end_to_end() {
        let root = scratch();
        let cfg = cfg_for(&root);

        // A good jpeg stored the KQ9 way: <root>/ab/cd/<sha>.
        let jpeg = [0xFFu8, 0xD8, 0xFF, 0xE0, 1, 2, 3, 4, 5, 6];
        let sha = sha_hex(&jpeg);
        let rel = format!("ab/cd/{sha}");
        std::fs::create_dir_all(root.join("ab/cd")).unwrap();
        std::fs::write(root.join(&rel), jpeg).unwrap();
        assert_eq!(
            verdict(Some("image"), Some(rel.as_str()), Some(sha.as_str()), Some(jpeg.len() as i64), &cfg),
            Verdict::Ok
        );
        // NULL sha column and a NULL size column never fabricate a
        // mismatch (legacy-friendly).
        assert_eq!(verdict(Some("image"), Some(rel.as_str()), None, None, &cfg), Verdict::Ok);

        // file_missing: gone file and NULL local_path.
        assert_eq!(verdict(Some("image"), Some("ab/cd/ffffffff"), None, None, &cfg), Verdict::FileMissing);
        assert_eq!(verdict(Some("image"), None, None, None, &cfg), Verdict::FileMissing);

        // size_mismatch: the size column is off by one.
        assert_eq!(
            verdict(Some("image"), Some(rel.as_str()), Some(sha.as_str()), Some(jpeg.len() as i64 + 1), &cfg),
            Verdict::SizeMismatch
        );

        // sha_mismatch: the sha column is wrong…
        assert_eq!(
            verdict(Some("image"), Some(rel.as_str()), Some("deadbeef"), Some(jpeg.len() as i64), &cfg),
            Verdict::ShaMismatch
        );
        // …or the file NAME is a different (plausible) sha.
        let other_sha = format!("{:0>64}", "aa");
        let wrong_name = format!("ab/ef/{other_sha}");
        std::fs::create_dir_all(root.join("ab/ef")).unwrap();
        std::fs::write(root.join(&wrong_name), jpeg).unwrap();
        assert_eq!(
            verdict(Some("image"), Some(wrong_name.as_str()), Some(sha.as_str()), Some(jpeg.len() as i64), &cfg),
            Verdict::ShaMismatch
        );

        // magic_bad: image kind, non-image bytes, sha/size honest
        // (KQ1: E2EE CDN bytes may be ciphertext).
        let cipher = [0x37u8, 0x9E, 0x2C, 0xF1, 8, 9, 10, 11];
        let csha = sha_hex(&cipher);
        let crel = format!("cd/ef/{csha}");
        std::fs::create_dir_all(root.join("cd/ef")).unwrap();
        std::fs::write(root.join(&crel), cipher).unwrap();
        assert_eq!(
            verdict(Some("image"), Some(crel.as_str()), Some(csha.as_str()), Some(cipher.len() as i64), &cfg),
            Verdict::MagicBad
        );
        // Same bytes, kind file (never sniffed) -> ok.
        assert_eq!(
            verdict(Some("file"), Some(crel.as_str()), Some(csha.as_str()), Some(cipher.len() as i64), &cfg),
            Verdict::Ok
        );

        // Legacy shapes: an ABSOLUTE local_path is checked where it
        // points; a legacy non-sha file name is skipped, not failed.
        let abs = root.join(&rel);
        assert_eq!(
            verdict(Some("image"), Some(&abs.to_string_lossy()), Some(sha.as_str()), Some(jpeg.len() as i64), &cfg),
            Verdict::Ok
        );
        std::fs::create_dir_all(root.join("legacy")).unwrap();
        std::fs::write(root.join("legacy/photo.jpg"), jpeg).unwrap();
        assert_eq!(verdict(Some("image"), Some("legacy/photo.jpg"), None, None, &cfg), Verdict::Ok);

        let _ = std::fs::remove_dir_all(&root);
    }
}
