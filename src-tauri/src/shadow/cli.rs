//! `zalors import` CLI (P2 skeleton, fail-closed).
//!
//! Spec (handoff acceptance P2):
//! ```text
//! zalors import --from-zalo-pc <dir> --account <id> --uin-hash <sha256-12>
//!              [--key-file <dpapi-wrapped-key.bin>] [--dry-run] [--apply]
//! ```
//! - `--dry-run` (the default) must perform ZERO writes on the source
//!   (verify via mtime, see handoff: the old dry-run once failed this by
//!   touching `Core\Index.db-shm` — the rebuild opens every source DB with
//!   SQLITE_OPEN_READ_ONLY and never lets SQLCipher create -wal/-shm).
//! - `--apply` writes into the shadow DB with `source='import'` (D5:
//!   import never overwrites capture data without a newer timestamp).
//! - The UIN key never appears on the command line: `--key-file` points
//!   at the DPAPI-wrapped capture (see D7, `zalo-desktop-uin-key-*.bin`).

use std::path::PathBuf;

use super::import;

pub struct ImportArgs {
    pub from: PathBuf,
    pub account: String,
    pub uin_hash: String,
    pub key_file: Option<PathBuf>,
    pub apply: bool,
}

/// Parse the argv of a `zalors import ...` invocation. Returns `None` (and
/// prints usage) when the invocation does not match the spec.
pub fn parse(args: &[String]) -> Option<ImportArgs> {
    let mut from: Option<PathBuf> = None;
    let mut account: Option<String> = None;
    let mut uin_hash: Option<String> = None;
    let mut key_file: Option<PathBuf> = None;
    let mut apply = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--from-zalo-pc" => from = args.get(i + 1).map(PathBuf::from),
            "--account" => account = args.get(i + 1).cloned(),
            "--uin-hash" => uin_hash = args.get(i + 1).cloned(),
            "--key-file" => key_file = args.get(i + 1).map(PathBuf::from),
            "--dry-run" => apply = false,
            "--apply" => apply = true,
            _ => {}
        }
        i += 2;
    }
    Some(ImportArgs {
        from: from?,
        account: account?,
        uin_hash: uin_hash?,
        key_file,
        apply,
    })
}

/// CLI entrypoint (called from a `zalors import` process launch).
pub fn main(args: &[String]) -> i32 {
    let Some(a) = parse(args) else {
        eprintln!(
            "usage: zalors import --from-zalo-pc <dir> --account <id> --uin-hash <sha256-12> \
             [--key-file <file>] [--dry-run | --apply]"
        );
        return 2;
    };
    match import::run(&a.from, &a.account, &a.uin_hash, a.key_file.as_deref(), a.apply) {
        Ok(s) => {
            println!(
                "import {} {}: conversations={} messages={} groups={} contacts={} (dry_run={})",
                a.account, a.uin_hash, s.conversations, s.messages, s.groups, s.contacts, !a.apply
            );
            0
        }
        Err(e) => {
            eprintln!("import failed: {e}");
            1
        }
    }
}
