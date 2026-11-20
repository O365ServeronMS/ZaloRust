//! Shadow settings field validation (audit §4 items 1.3/KQ9 and
//! 1.4/KQ2, batch 7 G1; free-space check added in batch 9 I0).
//!
//! `commands::set_settings` validates every user-entered shadow field
//! BEFORE the settings file is written; the pure checks live here so
//! they are unit-testable without an app handle (same split as
//! `downloads::validate_dir` for the download folder).
//!
//! H-rules:
//! - error strings are user-facing and VALUE-FREE — a bad uid or hash
//!   is reported by its shape, never by echoing what was typed;
//! - the media-store probe file is created and removed again, so
//!   validation leaves nothing behind in the user's folder.

use std::path::{Component, Path};

use super::account;

/// The Desktop data root whose volume the media store must share
/// (audit KQ9 / §4 item 2.6: the import's `CreateHardLink` step needs
/// store and Desktop data on ONE volume). The production call site
/// passes it ONLY when it exists; a missing root skips the
/// same-volume check (the brief's rule), so a machine without
/// `D:\Zalo Data` can still configure a store.
pub const DESKTOP_DATA_ROOT: &str = "D:\\Zalo Data";

/// Why a media-store path was refused (KQ9). Classified before the
/// user-facing string so tests assert the REASON, not a localized
/// message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaStoreError {
    /// Not an absolute path.
    NotAbsolute,
    /// The folder does not exist. Creating it is deliberately NOT part
    /// of validation — a path under an existing parent still errors
    /// "does not exist" (the brief's rule).
    Missing,
    /// The path exists but is not a directory.
    NotADir,
    /// The probe file could not be created (and removed) in it.
    NotWritable,
    /// A different volume than the reference root (D9 hardlink).
    DifferentVolume,
    // KQ9 free space is NOT a variant here: the check runs only in
    // [`validate_media_store`] (the media-store entry point), not in
    // [`check_media_store`], because `check_backup_dir` reuses that
    // function and batch 8's backup-folder semantics must stay
    // unchanged. The decision is the pure helper
    // [`free_space_ok`] (unit-tested with fake numbers); the
    // unmeasurable-volume case (`GetDiskFreeSpaceExW` → None) skips
    // the check — see the module docs in `disk_space`.
}

/// Minimum free space the media-store volume must report (KQ9): the
/// GiB number that may appear in the user-facing refusal — nothing
/// else about the volume is ever echoed.
pub const MIN_FREE_GIB: u64 = 5;

/// [`MIN_FREE_GIB`] in bytes.
pub const MIN_FREE_BYTES: u64 = MIN_FREE_GIB * 1024 * 1024 * 1024;

/// Pure free-space decision (I0, batch 9 — tested with fake
/// `(free, threshold)` pairs, never a real volume): refuse when the
/// measured free space is strictly below the threshold; exactly at
/// the threshold passes. The `None` (API failure / non-Windows) case
/// never reaches this function — [`validate_media_store`] skips the
/// whole check instead.
fn free_space_ok(free: u64, threshold: u64) -> bool {
    free >= threshold
}

/// Why an own-identity field was refused (KQ2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnIdError {
    /// The uid is not 5..=32 ASCII digits.
    BadUidShape,
    /// The hash (after lowercasing) is not 12 lowercase hex chars.
    BadUinHashShape,
}

/// Windows drive letter of an absolute path, lowercased (`Some('d')`).
/// `None` for paths without a drive prefix (relative paths, UNC shares,
/// Unix roots). Pure — no IO, so tests can pass fake paths.
fn drive_letter(path: &Path) -> Option<char> {
    let comp = path.components().next()?;
    let Component::Prefix(prefix) = comp else {
        return None;
    };
    match prefix.kind() {
        std::path::Prefix::Disk(c) | std::path::Prefix::VerbatimDisk(c) => {
            Some((c as char).to_ascii_lowercase())
        }
        _ => None,
    }
}

/// Same-volume decision for the KQ9/D9 hardlink rule: two paths are on
/// the same volume when both carry a Windows drive letter and the
/// letters match (case-insensitive). Anything without a comparable
/// drive letter (UNC share, Unix root, relative path) counts as same —
/// the hardlink step re-checks at import time anyway, and refusing a
/// store we cannot classify would block valid setups. Pure.
pub fn same_volume(a: &Path, b: &Path) -> bool {
    match (drive_letter(a), drive_letter(b)) {
        (Some(x), Some(y)) => x == y,
        _ => true,
    }
}

/// The KQ9 media-store checks, in the brief's order: absolute; exists
/// (never created here); is a dir; writable via a create+delete probe
/// file `.zr-write-test-<pid>`; same volume as `reference_root` when a
/// reference is given.
///
/// `reference_root` is a parameter so unit tests can use temp dirs;
/// the production caller passes `DESKTOP_DATA_ROOT` only when it
/// exists.
pub fn check_media_store(
    path: &Path,
    reference_root: Option<&Path>,
) -> Result<(), MediaStoreError> {
    if !path.is_absolute() {
        return Err(MediaStoreError::NotAbsolute);
    }
    if !path.exists() {
        return Err(MediaStoreError::Missing);
    }
    if !path.is_dir() {
        return Err(MediaStoreError::NotADir);
    }
    let probe = path.join(format!(".zr-write-test-{}", std::process::id()));
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
        }
        Err(_) => return Err(MediaStoreError::NotWritable),
    }
    if let Some(root) = reference_root {
        if !same_volume(path, root) {
            return Err(MediaStoreError::DifferentVolume);
        }
    }
    Ok(())
}

/// [`check_media_store`] with the classified error mapped to a
/// translated, value-free message (the path itself is never echoed),
/// PLUS the KQ9 free-space check (batch 9 I0): the store's volume must
/// report at least [`MIN_FREE_GIB`] GiB free, measured with batch 8's
/// `disk_space::disk_free_space`; when the API returns `None` the
/// check is skipped entirely (an unmeasurable volume must not block a
/// valid folder). The only value the refusal may echo is the GiB
/// number itself. This is the signature `set_settings` calls.
pub fn validate_media_store(
    path: &Path,
    reference_root: Option<&Path>,
) -> Result<(), String> {
    use crate::i18n::{tr, trf};
    check_media_store(path, reference_root).map_err(|e| {
        tr(match e {
            MediaStoreError::NotAbsolute => {
                "O caminho da pasta de armazenamento precisa ser absoluto."
            }
            MediaStoreError::Missing => "A pasta de armazenamento não existe.",
            MediaStoreError::NotADir => "O caminho de armazenamento não é uma pasta.",
            MediaStoreError::NotWritable => {
                "Não é possível gravar na pasta de armazenamento."
            }
            MediaStoreError::DifferentVolume => {
                "A pasta de armazenamento precisa estar na mesma unidade dos dados do Zalo."
            }
        })
        .into_owned()
    })?;
    // KQ9 free space (batch 9 I0): refuse below the threshold; `None`
    // (API failure, non-Windows) skips the check. Only the GiB number
    // is ever echoed back — never the measured bytes, never the path.
    if let Some((free, _total)) = super::disk_space::disk_free_space(path) {
        if !free_space_ok(free, MIN_FREE_BYTES) {
            return Err(trf(
                "A pasta de armazenamento precisa de pelo menos {0} GB de espaço livre.",
                &[&MIN_FREE_GIB],
            ));
        }
    }
    Ok(())
}

/// `settings.shadow.backup_dir` checks (batch 8 H4): exactly the
/// media-store checks EXCEPT the same-volume rule — a backup folder
/// may live on any drive (the D9 hardlink constraint is an
/// import-media concern, not a backup concern). Same classified error
/// type so tests assert the REASON.
pub fn check_backup_dir(path: &Path) -> Result<(), MediaStoreError> {
    check_media_store(path, None)
}

/// [`check_backup_dir`] with the classified error mapped to a
/// translated, value-free message (backup-specific strings — the path
/// itself is never echoed).
pub fn validate_backup_dir(path: &Path) -> Result<(), String> {
    use crate::i18n::tr;
    check_backup_dir(path).map_err(|e| {
        tr(match e {
            MediaStoreError::NotAbsolute => {
                "O caminho da pasta de backup precisa ser absoluto."
            }
            MediaStoreError::Missing => "A pasta de backup não existe.",
            MediaStoreError::NotADir => "O caminho de backup não é uma pasta.",
            MediaStoreError::NotWritable => {
                "Não é possível gravar na pasta de backup."
            }
            // Unreachable (no reference root is passed — backups may
            // live on any drive); kept for match exhaustiveness, and
            // reuses the translated storage string so the arm can
            // never render raw source text.
            MediaStoreError::DifferentVolume => {
                "A pasta de armazenamento precisa estar na mesma unidade dos dados do Zalo."
            }
        })
        .into_owned()
    })
}

/// `settings.shadow.backup_dir`: trimmed; empty becomes `None` (the
/// documented "not configured" — no backup thread starts).
pub fn normalize_backup_dir(raw: Option<&str>) -> Option<String> {
    normalize_media_store(raw)
}

/// `settings.shadow.media_store`: trimmed; empty becomes `None` (the
/// documented default root then applies, see `media::media_store_root`).
pub fn normalize_media_store(raw: Option<&str>) -> Option<String> {
    let t = raw.map(str::trim).unwrap_or("");
    if t.is_empty() {
        None
    } else {
        Some(t.to_string())
    }
}

/// `settings.shadow.own_uid` (KQ2): empty becomes `None`; anything else
/// must pass `account::valid_uid`. The VALUE never enters the error.
pub fn normalize_own_uid(raw: Option<&str>) -> Result<Option<String>, OwnIdError> {
    let t = raw.map(str::trim).unwrap_or("");
    if t.is_empty() {
        return Ok(None);
    }
    if account::valid_uid(t) {
        Ok(Some(t.to_string()))
    } else {
        Err(OwnIdError::BadUidShape)
    }
}

/// `settings.shadow.own_uin_hash` (KQ2): empty becomes `None`; anything
/// else is LOWERCASED first, then must pass `account::valid_uin_hash`.
pub fn normalize_own_uin_hash(raw: Option<&str>) -> Result<Option<String>, OwnIdError> {
    let t = raw.map(str::trim).unwrap_or("").to_ascii_lowercase();
    if t.is_empty() {
        return Ok(None);
    }
    if account::valid_uin_hash(&t) {
        Ok(Some(t))
    } else {
        Err(OwnIdError::BadUinHashShape)
    }
}

/// Both identity fields at once, with the same value-free error
/// strings `set_settings` shows. Returns the normalized pair to store.
pub fn validate_own_identity(
    uid: Option<&str>,
    uin_hash: Option<&str>,
) -> Result<(Option<String>, Option<String>), String> {
    use crate::i18n::tr;
    let uid = normalize_own_uid(uid).map_err(|e| {
        tr(match e {
            OwnIdError::BadUidShape => {
                "O uid configurado não é válido: use de 5 a 32 dígitos."
            }
            OwnIdError::BadUinHashShape => {
                "O hash UIN configurado não é válido: use 12 caracteres hexadecimais minúsculos."
            }
        })
        .into_owned()
    })?;
    let uin_hash = normalize_own_uin_hash(uin_hash).map_err(|e| {
        tr(match e {
            OwnIdError::BadUidShape => {
                "O uid configurado não é válido: use de 5 a 32 dígitos."
            }
            OwnIdError::BadUinHashShape => {
                "O hash UIN configurado não é válido: use 12 caracteres hexadecimais minúsculos."
            }
        })
        .into_owned()
    })?;
    Ok((uid, uin_hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// FAKE uid of the documented shape (never a real one).
    const FAKE_UID: &str = "1234567890123456789";
    /// FAKE 12-hex fingerprint (never a real uin_hash).
    const FAKE_HASH: &str = "abc123def456";

    fn scratch(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("zalors-store-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    // --- same_volume (pure, fake paths — no IO) ---------------------------

    #[test]
    fn same_volume_compares_drive_letters_case_insensitively() {
        assert!(same_volume(Path::new(r"D:\ZaloRust Data"), Path::new(r"d:\Zalo Data")));
        assert!(!same_volume(Path::new(r"D:\store"), Path::new(r"C:\Zalo Data")));
        assert!(same_volume(
            Path::new(r"\\?\D:\store"),
            Path::new(r"D:\Zalo Data")
        ), "verbatim drive letters compare too");
    }

    #[test]
    fn paths_without_a_drive_letter_are_never_flagged_different() {
        // UNC shares and Unix-style roots cannot be classified — the
        // hardlink step re-checks, so validation must not block them.
        assert!(same_volume(Path::new(r"\\server\share\store"), Path::new(r"D:\Zalo Data")));
        assert!(same_volume(Path::new("/tmp/store"), Path::new(r"D:\Zalo Data")));
        assert!(same_volume(Path::new("relative"), Path::new(r"D:\Zalo Data")));
    }

    // --- check_media_store (temp dirs) ------------------------------------

    #[test]
    fn media_store_requires_an_absolute_path() {
        assert_eq!(
            check_media_store(Path::new("relative/store"), Some(Path::new(DESKTOP_DATA_ROOT))),
            Err(MediaStoreError::NotAbsolute)
        );
    }

    #[test]
    fn media_store_missing_is_an_error_even_when_the_parent_exists() {
        // The brief's rule: creation is NOT part of validation — a
        // path under an existing parent still errors "does not exist".
        let parent = scratch("parent");
        assert!(parent.is_dir());
        assert_eq!(
            check_media_store(&parent.join("never-created"), None),
            Err(MediaStoreError::Missing)
        );
        std::fs::remove_dir_all(&parent).unwrap();
    }

    #[test]
    fn media_store_rejects_a_file_path() {
        let d = scratch("file");
        let f = d.join("not-a-dir.txt");
        std::fs::write(&f, b"x").unwrap();
        assert_eq!(check_media_store(&f, None), Err(MediaStoreError::NotADir));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn media_store_accepts_a_writable_folder_and_leaves_nothing_behind() {
        let d = scratch("ok");
        // Two temp dirs = same volume on any test machine, and a
        // missing reference root skips the volume check entirely.
        let other = scratch("ref");
        assert_eq!(check_media_store(&d, Some(&other)), Ok(()));
        assert_eq!(check_media_store(&d, None), Ok(()));
        assert_eq!(
            std::fs::read_dir(&d).unwrap().count(),
            0,
            "the probe file must be removed again"
        );
        std::fs::remove_dir_all(&d).unwrap();
        std::fs::remove_dir_all(&other).unwrap();
    }

    #[test]
    fn media_store_flags_a_reference_root_on_another_drive() {
        // Pure part: build a reference root whose drive letter differs
        // from the scratch dir's, whatever machine the test runs on.
        let d = scratch("vol");
        let own = drive_letter(&d).unwrap_or('c');
        let other = if own == 'd' { 'q' } else { 'd' };
        let reference = PathBuf::from(format!("{other}:\\Zalo Data"));
        assert_eq!(
            check_media_store(&d, Some(&reference)),
            Err(MediaStoreError::DifferentVolume)
        );
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn media_store_rejects_a_read_only_folder() {
        use std::os::unix::fs::PermissionsExt;
        let d = scratch("ro");
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o555)).unwrap();
        // root ignores permission bits; only assert when they are enforced.
        if std::fs::write(d.join("t"), b"").is_err() {
            assert_eq!(check_media_store(&d, None), Err(MediaStoreError::NotWritable));
        }
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::remove_dir_all(&d).unwrap();
    }

    // --- KQ9 free space (batch 9 I0) --------------------------------------

    #[test]
    fn free_space_ok_decides_on_the_threshold_edge() {
        // The pure (free, threshold) decision — fake numbers, no IO.
        // The API-failure case never reaches this helper:
        // validate_media_store skips the whole check when
        // disk_free_space returns None.
        let t = MIN_FREE_BYTES;
        assert!(free_space_ok(t, t), "exactly at the threshold passes");
        assert!(free_space_ok(t + 1, t));
        assert!(!free_space_ok(t - 1, t), "one byte under the threshold refuses");
        assert!(!free_space_ok(0, t));
        assert!(free_space_ok(u64::MAX, t));
        assert!(free_space_ok(0, 0), "a zero threshold accepts anything");
        assert_eq!(MIN_FREE_GIB, 5, "the documented KQ9 minimum");
        assert_eq!(MIN_FREE_BYTES, 5 * 1024 * 1024 * 1024);
    }

    #[test]
    fn media_store_free_space_message_echoes_only_the_gib_number() {
        // The refusal's translated strings carry the GiB threshold and
        // nothing else — no measured bytes, no path, no volume label.
        // Asserted through the i18n tables in both languages; the dev
        // machine's real volume is never under test control.
        for lang in [crate::i18n::Lang::Vi, crate::i18n::Lang::En] {
            let msg = crate::i18n::trf_in(
                lang,
                "A pasta de armazenamento precisa de pelo menos {0} GB de espaço livre.",
                &[&MIN_FREE_GIB],
            );
            assert!(msg.contains('5'), "{lang:?}: {msg}");
            assert!(
                !msg.contains("5368709120") && !msg.contains("1073741824"),
                "no raw byte counts in the user-facing string: {msg}"
            );
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn media_store_free_space_skipped_when_the_api_returns_none() {
        // Off Windows `disk_free_space` is None by definition: a valid
        // folder must pass validate_media_store with the check
        // skipped (the skip is the `if let Some` in validate_media_store).
        let d = scratch("space-none");
        assert_eq!(validate_media_store(&d, None), Ok(()));
        assert_eq!(validate_media_store(&d, Some(&scratch("space-ref"))), Ok(()));
        std::fs::remove_dir_all(&d).unwrap();
        std::fs::remove_dir_all(scratch("space-ref")).unwrap();
    }

    // --- validate_media_store (user-facing strings) -----------------------

    #[test]
    fn validate_media_store_errors_are_translated_and_value_free() {
        let missing = scratch("msg").join("does-not-exist");
        let err = validate_media_store(&missing, None).unwrap_err();
        assert!(!err.is_empty());
        // The path itself is never echoed back at the user.
        let echoed = missing.to_string_lossy();
        assert!(
            !err.contains("does-not-exist") && !err.contains(echoed.as_ref()),
            "error echoed the path: {err}"
        );
        std::fs::remove_dir_all(scratch("msg")).unwrap();
    }

    // --- backup_dir (batch 8 H4) -------------------------------------------

    #[test]
    fn backup_dir_accepts_a_writable_folder_with_no_volume_rule() {
        // No same-volume rule (H4): there is no reference-root
        // parameter to pass, so `DifferentVolume` can never be
        // produced — a backup folder on ANY drive passes the same
        // existence/writability checks as the media store.
        let d = scratch("backup-ok");
        assert_eq!(check_backup_dir(&d), Ok(()));
        assert_eq!(validate_backup_dir(&d), Ok(()));
        assert_eq!(
            std::fs::read_dir(&d).unwrap().count(),
            0,
            "the probe file must be removed again"
        );
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn backup_dir_errors_are_classified_and_value_free() {
        assert_eq!(check_backup_dir(Path::new("relative/backups")), Err(MediaStoreError::NotAbsolute));
        assert_eq!(
            check_backup_dir(&scratch("bk").join("never-created")),
            Err(MediaStoreError::Missing)
        );
        let d = scratch("bk-file");
        let f = d.join("not-a-dir.txt");
        std::fs::write(&f, b"x").unwrap();
        assert_eq!(check_backup_dir(&f), Err(MediaStoreError::NotADir));
        // The user-facing strings never echo the path.
        let err = validate_backup_dir(&f).unwrap_err();
        let echoed = f.to_string_lossy();
        assert!(
            !err.is_empty()
                && !err.contains("not-a-dir") && !err.contains(echoed.as_ref()),
            "error echoed the path: {err}"
        );
        std::fs::remove_dir_all(&d).unwrap();
        std::fs::remove_dir_all(scratch("bk")).unwrap();
    }

    #[test]
    fn backup_dir_normalization_matches_the_media_store_shape() {
        assert_eq!(normalize_backup_dir(None), None);
        assert_eq!(normalize_backup_dir(Some("")), None);
        assert_eq!(normalize_backup_dir(Some("   ")), None);
        assert_eq!(
            normalize_backup_dir(Some(" D:\\ZaloRust Backups ")),
            Some("D:\\ZaloRust Backups".into())
        );
    }

    // --- own identity (KQ2) ------------------------------------------------

    #[test]
    fn own_uid_empty_is_none_and_valid_shape_passes() {
        assert_eq!(normalize_own_uid(None), Ok(None));
        assert_eq!(normalize_own_uid(Some("")), Ok(None));
        assert_eq!(normalize_own_uid(Some("   ")), Ok(None));
        assert_eq!(normalize_own_uid(Some(FAKE_UID)), Ok(Some(FAKE_UID.into())));
        // Whitespace around a valid uid is trimmed, not rejected.
        assert_eq!(
            normalize_own_uid(Some(&format!(" {FAKE_UID} "))),
            Ok(Some(FAKE_UID.into()))
        );
    }

    #[test]
    fn own_uid_bad_shape_is_rejected_by_shape_only() {
        for bad in ["1234", "12345a", "１２３４５", "9".repeat(33).as_str()] {
            assert_eq!(normalize_own_uid(Some(bad)), Err(OwnIdError::BadUidShape), "{bad:?}");
        }
        // Whitespace is trimmed BEFORE the shape check (a pasted uid
        // with a stray space still saves).
        assert_eq!(normalize_own_uid(Some(" 12345 ")), Ok(Some("12345".into())));
    }

    #[test]
    fn own_uin_hash_is_lowercased_before_the_shape_check() {
        assert_eq!(normalize_own_uin_hash(None), Ok(None));
        assert_eq!(normalize_own_uin_hash(Some("  ")), Ok(None));
        assert_eq!(
            normalize_own_uin_hash(Some("ABC123DEF456")),
            Ok(Some("abc123def456".into()))
        );
        assert_eq!(normalize_own_uin_hash(Some(FAKE_HASH)), Ok(Some(FAKE_HASH.into())));
        for bad in ["abc123def45", "abc123def4567", "abc123def45g", "ABC123DEF45G"] {
            assert_eq!(
                normalize_own_uin_hash(Some(bad)),
                Err(OwnIdError::BadUinHashShape),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn own_identity_errors_never_echo_the_value() {
        let bad_uid = "not-a-uid-<redacted>";
        let err = validate_own_identity(Some(bad_uid), None).unwrap_err();
        assert!(!err.contains(bad_uid), "error echoed the uid value: {err}");
        let bad_hash = "ZZZZZZZZZZZZ";
        let err = validate_own_identity(None, Some(bad_hash)).unwrap_err();
        assert!(
            !err.contains(bad_hash),
            "error echoed the hash value: {err}"
        );
        // The good path returns the normalized pair unchanged.
        let (uid, hash) = validate_own_identity(Some(FAKE_UID), Some("ABC123DEF456")).unwrap();
        assert_eq!(uid.as_deref(), Some(FAKE_UID));
        assert_eq!(hash.as_deref(), Some("abc123def456"));
    }

    // --- media_store normalization ----------------------------------------

    #[test]
    fn media_store_empty_is_none_and_whitespace_is_trimmed() {
        assert_eq!(normalize_media_store(None), None);
        assert_eq!(normalize_media_store(Some("")), None);
        assert_eq!(normalize_media_store(Some("   ")), None);
        assert_eq!(
            normalize_media_store(Some(" D:\\ZaloRust Data ")),
            Some("D:\\ZaloRust Data".into())
        );
    }

    #[test]
    fn desktop_data_root_is_the_audit_path() {
        assert_eq!(DESKTOP_DATA_ROOT, "D:\\Zalo Data");
    }
}
