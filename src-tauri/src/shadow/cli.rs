//! `zalors import` CLI (P2, audit §4 items 2.0–2.4; batch 6 F1).
//!
//! Spec (KQ4: the import only ever reads a COLD SNAPSHOT):
//! ```text
//! zalors import --from-snapshot <dir> --account <id> --uin-hash <sha256-12>
//!              [--key-file <file>] [--cipher-compat <3|4>] [--dry-run | --apply] [--help]
//! ```
//! - Value flags consume exactly one value; a missing value or one that
//!   starts with `--` is an error, never a silent skip (audit M2-5: the
//!   old parser advanced two args even for valueless flags, losing
//!   `--key-file` when it followed `--apply`).
//! - `--from-zalo-pc` is RENAMED to `--from-snapshot`: import never
//!   points at the live Desktop tree (KQ4), and `import::run` refuses
//!   any path without a `snapshot-manifest.json`.
//! - The Desktop key is never accepted on argv, never printed, never
//!   logged — only its length and sha256-12 ever appear (F2).
//! - `--dry-run` (the default) performs ZERO writes on the snapshot:
//!   every source DB opens `mode=ro&immutable=1`, so SQLite cannot even
//!   create `-wal`/`-shm` (audit M2-6, F3).
//! - `--apply` stays fail-closed until P2 item 2.5 wires the writer.

use std::path::PathBuf;

use super::import::{self, CipherProfile};

/// The usage text (`--help`, and after any parse error).
const USAGE: &str = "\
usage: zalors import --from-snapshot <dir> --account <id> --uin-hash <sha256-12>
       [--key-file <file>] [--cipher-compat <3|4>] [--dry-run | --apply] [--help]

--from-snapshot  cold snapshot dir (made by tools/snapshot.ps1; KQ4: the
                  live Zalo Desktop tree is never read)
--account        ZaloRust account id (e.g. default)
--uin-hash       expected sha256-12 of the Desktop key (12 lowercase hex)
--key-file       DPAPI-wrapped D7 key capture (the key is never on argv)
--cipher-compat  force cipher profile 3 or 4 instead of auto-detecting
--dry-run        inventory only, zero writes (the default)
--apply          write into the shadow DB (not wired yet: fail-closed)
--help           this usage, exit 0";

/// Parsed `zalors import` arguments (pure parse result — see `parse`).
#[derive(Debug, Clone, PartialEq)]
pub struct ImportArgs {
    /// `--from-snapshot <dir>` (required): a cold snapshot made by
    /// `tools/snapshot.ps1`, carrying `snapshot-manifest.json`.
    pub from_snapshot: PathBuf,
    /// `--account <id>` (required): the ZaloRust account id ("default").
    pub account: String,
    /// `--uin-hash <sha256-12>` (required): the expected sha256-12 of
    /// the D7 passphrase; the loaded key must hash to exactly this.
    pub uin_hash: String,
    /// `--key-file <file>`: the DPAPI-wrapped D7 capture. Optional at
    /// parse time; `run` fails closed when it is absent.
    pub key_file: Option<PathBuf>,
    /// `--cipher-compat <3|4>`: force a profile instead of detection.
    pub cipher_compat: Option<CipherProfile>,
    /// `--apply`: write into the shadow DB (still fail-closed).
    pub apply: bool,
    /// `--help`: print usage, exit 0 (no other flag required).
    pub help: bool,
}

/// Store a first-wins-once value; duplicates are a parse error.
fn set_once<T>(slot: &mut Option<T>, flag: &str, value: T) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!("{flag} given twice"));
    }
    *slot = Some(value);
    Ok(())
}

/// Store a valueless flag; repeats are a parse error.
fn set_bool_once(slot: &mut bool, flag: &str) -> Result<(), String> {
    if *slot {
        return Err(format!("{flag} given twice"));
    }
    *slot = true;
    Ok(())
}

/// Validate the `--uin-hash` shape: exactly 12 lowercase hex chars
/// (the same shape `shadow::account::valid_uin_hash` pins).
fn validate_uin_hash(flag: &str, value: &str) -> Result<String, String> {
    if value.len() != 12
        || !value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(format!(
            "{flag} must be 12 lowercase hex chars (sha256-12), got {value:?}"
        ));
    }
    Ok(value.to_string())
}

/// Parse the `--cipher-compat` value: only 3 or 4.
fn parse_cipher_compat(value: &str) -> Result<CipherProfile, String> {
    match value {
        "4" => Ok(CipherProfile::Compat4),
        "3" => Ok(CipherProfile::Compat3),
        other => Err(format!("--cipher-compat must be 3 or 4, got {other:?}")),
    }
}

/// Parse the argv of a `zalors import ...` invocation (everything after
/// the `import` word). Pure: never prints, never touches the FS.
///
/// Rules (audit M2-5):
/// - value flags consume one value; missing or `--`-prefixed value is
///   an error;
/// - boolean flags consume nothing;
/// - unknown args are an error (`--from-zalo-pc` gets a rename hint);
/// - duplicates are an error;
/// - `--dry-run` + `--apply` together are an error;
/// - `--help` short-circuits the required flags: usage, exit 0.
pub fn parse(args: &[String]) -> Result<ImportArgs, String> {
    let mut from_snapshot: Option<PathBuf> = None;
    let mut account: Option<String> = None;
    let mut uin_hash: Option<String> = None;
    let mut key_file: Option<PathBuf> = None;
    let mut cipher_compat: Option<CipherProfile> = None;
    let (mut dry_run, mut apply, mut help) = (false, false, false);

    let mut i = 0;
    while i < args.len() {
        let flag = args[i].as_str();
        let value_flag = matches!(
            flag,
            "--from-snapshot" | "--account" | "--uin-hash" | "--key-file" | "--cipher-compat"
        );
        if value_flag {
            let value =
                args.get(i + 1).ok_or_else(|| format!("{flag} requires a value"))?;
            if value.starts_with("--") {
                return Err(format!("{flag} requires a value, got {value}"));
            }
            match flag {
                "--from-snapshot" => set_once(&mut from_snapshot, flag, PathBuf::from(value))?,
                "--account" => set_once(&mut account, flag, value.to_string())?,
                "--uin-hash" => set_once(&mut uin_hash, flag, validate_uin_hash(flag, value)?)?,
                "--key-file" => set_once(&mut key_file, flag, PathBuf::from(value))?,
                "--cipher-compat" => {
                    set_once(&mut cipher_compat, flag, parse_cipher_compat(value)?)?
                }
                _ => unreachable!("the value_flag match lists every value flag"),
            }
            i += 2;
            continue;
        }
        match flag {
            "--dry-run" => set_bool_once(&mut dry_run, flag)?,
            "--apply" => set_bool_once(&mut apply, flag)?,
            "--help" => set_bool_once(&mut help, flag)?,
            "--from-zalo-pc" => {
                return Err(
                    "unknown flag --from-zalo-pc: renamed to --from-snapshot \
                     (imports read a cold snapshot, never the live tree — KQ4)"
                        .into(),
                );
            }
            other => return Err(format!("unknown argument {other}")),
        }
        i += 1;
    }

    if dry_run && apply {
        return Err("--dry-run and --apply are mutually exclusive".into());
    }
    if help {
        return Ok(ImportArgs {
            from_snapshot: PathBuf::new(),
            account: String::new(),
            uin_hash: String::new(),
            key_file: None,
            cipher_compat: None,
            apply: false,
            help: true,
        });
    }
    Ok(ImportArgs {
        from_snapshot: from_snapshot.ok_or("missing required --from-snapshot <dir>")?,
        account: account.ok_or("missing required --account <id>")?,
        uin_hash: uin_hash.ok_or("missing required --uin-hash <sha256-12>")?,
        key_file,
        cipher_compat,
        apply,
        help: false,
    })
}

/// CLI entrypoint (the bin dispatches `zalors import …` here BEFORE
/// starting Tauri, audit M2-5). Returns the process exit code:
/// 0 usage/success · 1 runtime failure · 2 parse error.
pub fn main(args: &[String]) -> i32 {
    match parse(args) {
        Ok(a) if a.help => {
            println!("{USAGE}");
            0
        }
        Ok(a) => match import::run(&a) {
            Ok(summary) => {
                // F4: counts, profile name, key sha12 — nothing else.
                println!("{}", summary.line());
                0
            }
            Err(e) => {
                eprintln!("import failed: {e}");
                1
            }
        },
        Err(e) => {
            eprintln!("import: {e}\n{USAGE}");
            2
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn parse_full_dry_run_invocation() {
        let a = parse(&args(&[
            "--from-snapshot",
            r"D:\snap",
            "--account",
            "default",
            "--uin-hash",
            "dca62c394a68",
            "--key-file",
            r"D:\k.bin",
            "--cipher-compat",
            "4",
            "--dry-run",
        ]))
        .unwrap();
        assert_eq!(a.from_snapshot, PathBuf::from(r"D:\snap"));
        assert_eq!(a.account, "default");
        assert_eq!(a.uin_hash, "dca62c394a68");
        assert_eq!(a.key_file, Some(PathBuf::from(r"D:\k.bin")));
        assert_eq!(a.cipher_compat, Some(CipherProfile::Compat4));
        assert!(!a.apply);
        assert!(!a.help);
    }

    #[test]
    fn parse_the_old_bug_apply_key_file_keeps_the_value() {
        // M2-5: the old parser advanced i += 2 even for valueless
        // flags, so `--apply --key-file X` silently LOST --key-file.
        let a = parse(&args(&[
            "--from-snapshot",
            r"D:\snap",
            "--account",
            "default",
            "--uin-hash",
            "dca62c394a68",
            "--apply",
            "--key-file",
            "k.bin",
        ]))
        .unwrap();
        assert!(a.apply);
        assert_eq!(a.key_file, Some(PathBuf::from("k.bin")));
    }

    #[test]
    fn parse_defaults_to_dry_run() {
        let a = parse(&args(&[
            "--from-snapshot",
            "s",
            "--account",
            "default",
            "--uin-hash",
            "dca62c394a68",
        ]))
        .unwrap();
        assert!(!a.apply, "no --dry-run/--apply means dry-run");
    }

    #[test]
    fn parse_value_flag_at_end_is_an_error() {
        let e = parse(&args(&["--from-snapshot"])).unwrap_err();
        assert!(e.contains("--from-snapshot requires a value"), "{e}");
    }

    #[test]
    fn parse_flag_like_value_is_an_error() {
        let e = parse(&args(&["--from-snapshot", "--account"])).unwrap_err();
        assert!(e.contains("--from-snapshot requires a value"), "{e}");
        let e = parse(&args(&["--account", "--apply"])).unwrap_err();
        assert!(e.contains("--account requires a value"), "{e}");
    }

    /// A valid base invocation to hang extra flags off.
    fn with_base(extra: &[&str]) -> Vec<String> {
        let mut v = args(&[
            "--from-snapshot",
            "s",
            "--account",
            "default",
            "--uin-hash",
            "dca62c394a68",
        ]);
        v.extend(extra.iter().map(|s| s.to_string()));
        v
    }

    #[test]
    fn parse_single_dash_value_is_accepted() {
        // Only a `--` prefix counts as a missing value; a lone `-weird`
        // path is a value like any other.
        let a = parse(&args(&[
            "--from-snapshot",
            "-weird-dir",
            "--account",
            "default",
            "--uin-hash",
            "dca62c394a68",
        ]))
        .unwrap();
        assert_eq!(a.from_snapshot, PathBuf::from("-weird-dir"));
    }

    #[test]
    fn parse_unknown_argument() {
        let e = parse(&args(&["--bogus"])).unwrap_err();
        assert!(e.contains("unknown argument --bogus"), "{e}");
    }

    #[test]
    fn parse_old_flag_name_reports_the_rename() {
        let e = parse(&args(&["--from-zalo-pc", r"D:\x"])).unwrap_err();
        assert!(e.contains("renamed to --from-snapshot"), "{e}");
    }

    #[test]
    fn parse_duplicate_value_flag() {
        let e = parse(&args(&["--account", "a", "--account", "b"])).unwrap_err();
        assert!(e.contains("--account given twice"), "{e}");
    }

    #[test]
    fn parse_duplicate_boolean_flag() {
        let e = parse(&args(&["--dry-run", "--dry-run"])).unwrap_err();
        assert!(e.contains("--dry-run given twice"), "{e}");
        let e = parse(&args(&["--help", "--help"])).unwrap_err();
        assert!(e.contains("--help given twice"), "{e}");
    }

    #[test]
    fn parse_dry_run_and_apply_conflict_in_both_orders() {
        for order in [&["--dry-run", "--apply"] as &[&str], &["--apply", "--dry-run"]] {
            let e = parse(&args(order)).unwrap_err();
            assert!(e.contains("mutually exclusive"), "{e}");
        }
    }

    #[test]
    fn parse_help_flag_short_circuits() {
        let a = parse(&args(&["--help"])).unwrap();
        assert!(a.help);
    }

    #[test]
    fn parse_help_alongside_valid_flags() {
        let a = parse(&args(&["--help", "--account", "default"])).unwrap();
        assert!(a.help);
    }

    #[test]
    fn parse_uin_hash_rejects_bad_shapes() {
        // The codebase shape (account::valid_uin_hash): exactly 12
        // LOWERCASE hex chars.
        for bad in [
            "dca62c394a6",     // 11 chars
            "dca62c394a68d",   // 13 chars
            "dca62c394a6z",     // not hex
            "DCA62C394A68",     // uppercase
            "",
        ] {
            let e = parse(&args(&["--uin-hash", bad])).unwrap_err();
            assert!(e.contains("12 lowercase hex"), "{bad} -> {e}");
        }
    }

    #[test]
    fn parse_cipher_compat_accepts_only_3_or_4() {
        assert_eq!(
            parse(&with_base(&["--cipher-compat", "3"])).unwrap().cipher_compat,
            Some(CipherProfile::Compat3)
        );
        assert_eq!(
            parse(&with_base(&["--cipher-compat", "4"])).unwrap().cipher_compat,
            Some(CipherProfile::Compat4)
        );
        for bad in ["5", "four", ""] {
            let e = parse(&with_base(&["--cipher-compat", bad])).unwrap_err();
            assert!(e.contains("must be 3 or 4"), "{bad} -> {e}");
        }
        assert!(parse(&args(&["--cipher-compat"])).is_err(), "still needs a value");
    }

    #[test]
    fn parse_missing_required_flags_are_named() {
        let e = parse(&args(&[])).unwrap_err();
        assert!(e.contains("missing required --from-snapshot"), "{e}");
        let e = parse(&args(&["--from-snapshot", "s"])).unwrap_err();
        assert!(e.contains("missing required --account"), "{e}");
        let e = parse(&args(&["--from-snapshot", "s", "--account", "default"])).unwrap_err();
        assert!(e.contains("missing required --uin-hash"), "{e}");
    }

    #[test]
    fn parse_key_file_is_optional() {
        let a = parse(&args(&[
            "--from-snapshot",
            "s",
            "--account",
            "default",
            "--uin-hash",
            "dca62c394a68",
        ]))
        .unwrap();
        assert_eq!(a.key_file, None);
        assert!(parse(&args(&["--key-file"])).is_err(), "still needs a value");
    }

    #[test]
    fn cli_main_help_exits_zero() {
        assert_eq!(main(&args(&["--help"])), 0);
    }

    #[test]
    fn cli_main_parse_error_exits_two() {
        assert_eq!(main(&args(&["--bogus"])), 2);
    }

    #[test]
    fn cli_main_run_error_exits_one() {
        // A temp dir with no snapshot-manifest.json: the F3 guard fires.
        let dir = std::env::temp_dir().join(format!(
            "zr-cli-main-{}-{}",
            std::process::id(),
            super::super::schema::now_ms()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let code = main(&args(&[
            "--from-snapshot",
            &dir.to_string_lossy(),
            "--account",
            "default",
            "--uin-hash",
            "dca62c394a68",
        ]));
        assert_eq!(code, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
