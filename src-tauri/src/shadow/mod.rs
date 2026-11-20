//! Shadow DB pipeline (rebuilt 2026-11-19; see `zalo-handoff-v2` docs).
//!
//! The shadow DB is a long-lived, SQLCipher-encrypted mirror of the user's
//! own Zalo Web traffic, fed by the running app on this machine only:
//!
//! ```text
//!  WebView2 (chat.zalo.me)
//!   │  CDP Network domain events (capture.rs, Windows)
//!   ▼
//!  raw frames (WS binary + REST response bodies)
//!   │  wire.rs: AES-128-GCM (per-connection key), zpw_enk CBC, gzip
//!   ▼
//!  decoded envelopes  ──(runtime.rs batches, D4/D5 defaults)──▶ raw_events
//!   │  normalize.rs: envelope -> domain rows (never trust blindly)
//!   ▼
//!  writer.rs: idempotent upserts into the schema below
//! ```
//!
//! Guarantees (handoff "Requirements"):
//! - No cookie/token/key values ever enter logs, the DB `raw_events`
//!   payloads are the app's own message traffic, and the E2EE bridge hook
//!   only forwards what the web client itself decrypted in-page.
//! - Upserts are keyed by server ids (msg_id, conv_id); a replay of the
//!   same event converges instead of duplicating (`rev` bumps only when
//!   the payload actually changed).
//! - Modules:
//!   - `schema`  — DDL + migration (v1)
//!   - `wire`    — WS frame / REST body decode (pure, unit-tested)
//!   - `capture` — CDP plumbing + `safe_endpoint` for logs
//!   - `normalize` — envelope -> row mapping (source of truth for shapes)
//!   - `writer`  — SQLCipher upserts (single owner of DB writes)
//!   - `pipeline` — batching rules (batch_ms / batch_max)
//!   - `runtime` — process-wide state, delivery from IPC + capture
//!   - `cli`     — `zalors import` entry (P2)
//!   - `import`  — Zalo Desktop DB import (P2)
//!   - `repair`  — one-time v1 data repair (maintenance only, never
//!     called from runtime)

pub mod account;
/// Insertion-ordered bounded set/map — eviction of the OLDEST entry
/// only (R1, batch 4 review: clear-all eviction killed live capture
/// state in `capture.rs` and `runtime.rs`).
pub mod bounded;
pub mod capture;
pub mod cli;
pub mod import;
pub mod media;
pub mod normalize;
pub mod pipeline;
/// Pure token bucket bounding the bridge IPC commands (audit M3/D3).
pub mod rate_limit;
/// One-time v1 data repair (audit T8). Maintenance/tests ONLY — never
/// called from `runtime` or startup.
pub mod repair;
/// REST capture stage counters (audit H2 / batch 3 C2).
pub mod rest_stats;
pub mod runtime;
pub mod schema;
/// Shadow settings field validation (audit 1.3/KQ9 + 1.4/KQ2, batch 7
/// G1): the pure checks `commands::set_settings` runs before the
/// settings file is written.
pub mod settings_check;
/// WS frame stage counters (audit M4/D2, batch 4).
pub mod ws_stats;
pub mod wire;
pub mod writer;

// --- KQ10: the one shadow account ------------------------------------------

/// The shadow DB's account id (KQ10/D18): this build is single-account
/// and every on-disk shadow artifact is named after it. Renaming the
/// store later is a file rename plus this constant — nothing else
/// hardcodes it.
///
/// NOT the same concept as the app's window account id that
/// `accounts.rs`/`window.rs`/`lib.rs` also call `"default"` (which
/// profile/window an account opens in); those stay untouched.
pub const SHADOW_ACCOUNT: &str = "default";

/// The shadow DB file for `dir` (`<dir>/default.db`).
pub fn db_file(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join(format!("{SHADOW_ACCOUNT}.db"))
}

/// The DPAPI-wrapped key file for `dir` (`<dir>/default.key`).
pub fn key_file(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join(format!("{SHADOW_ACCOUNT}.key"))
}

#[cfg(test)]
mod account_path_tests {
    use super::{db_file, key_file, SHADOW_ACCOUNT};
    use std::path::Path;

    #[test]
    fn shadow_account_paths_are_the_default_files() {
        let dir = Path::new(r"D:\shadow");
        assert_eq!(SHADOW_ACCOUNT, "default");
        assert_eq!(db_file(dir), dir.join("default.db"));
        assert_eq!(key_file(dir), dir.join("default.key"));
    }
}

#[cfg(test)]
mod golden;

/// Probe access to the live DB always goes through a temp COPY (audit
/// M2-6: a READ_ONLY WAL connection still touches the live `-shm`).
#[cfg(test)]
mod probe_util;

#[cfg(test)]
mod probe_shapes;

#[cfg(test)]
mod probe_group;

#[cfg(test)]
mod probe_ctx;

#[cfg(test)]
mod probe_conv;

#[cfg(test)]
mod probe_e2ee;

#[cfg(test)]
mod probe_recent;

#[cfg(test)]
mod probe_where;

/// One normalized write instruction produced by `normalize`.
/// The writer maps each variant onto one upsert (see writer.rs).
#[derive(Debug, Clone, PartialEq)]
pub enum Write {
    /// A chat conversation (private or group).
    Conversation {
        id: String,
        is_group: bool,
        title: Option<String>,
        avatar_url: Option<String>,
        last_msg_id: Option<String>,
        last_ts: Option<i64>,
        raw: String,
    },
    /// One message, keyed by the server `msg_id` (idempotency key).
    Message {
        msg_id: String,
        conv_id: String,
        sender_id: Option<String>,
        ts: i64,
        kind: i64,
        text: Option<String>,
        payload: String,
        /// 'capture' | 'e2ee' | 'import'
        source: &'static str,
        /// Stub conversation type hint (B5): `Some(true)` when the
        /// envelope says the message is a group one (`groupMsgs`),
        /// `Some(false)` for the 1-1 arrays, `None` when the source
        /// does not say (bridge E2EE payload). The writer creates the
        /// stub as `type 1` only for `Some(true)`; Conversation/Group
        /// writes still refine the type later.
        is_group: Option<bool>,
    },
    /// An edit/recall/delete revision observed for an existing message.
    Revision {
        msg_id: String,
        rev: i64,
        ts: i64,
        kind: String,
        payload: String,
    },
    /// A reaction (cmd 603/610/611/612 in the WS stream).
    Reaction {
        msg_id: String,
        user_id: String,
        emoji: String,
        ts: i64,
    },
    /// A group member list snapshot.
    Participants { conv_id: String, raw: String },
    /// Contact row (display data only; phone is hashed, D5 privacy).
    Contact {
        user_id: String,
        display_name: Option<String>,
        avatar_url: Option<String>,
        raw: String,
    },
    /// Group metadata row.
    Group {
        group_id: String,
        name: Option<String>,
        raw: String,
    },
}

impl Write {
    /// Stable tag for logs/tests.
    pub fn tag(&self) -> &'static str {
        match self {
            Write::Conversation { .. } => "conversation",
            Write::Message { .. } => "message",
            Write::Revision { .. } => "revision",
            Write::Reaction { .. } => "reaction",
            Write::Participants { .. } => "participants",
            Write::Contact { .. } => "contact",
            Write::Group { .. } => "group",
        }
    }
}

#[cfg(test)]
mod probe_attach;

#[cfg(test)]
mod probe_latest;

#[cfg(test)]
mod probe_551;

#[cfg(test)]
mod probe_audit;

/// Coverage probe (audit §4 item 1.5 AC iii): re-run the pipeline's
/// normalizer over stored raw_events and anti-join against messages.
#[cfg(test)]
mod probe_coverage;

/// Maintenance probe (audit §1.2 migration, E4): repair_v1 dry-run +
/// real run against a temp COPY of the live store — never the live DB.
#[cfg(test)]
mod maint_repair;

#[cfg(test)]
mod maint_purge;

/// MAINTENANCE (audit KQ8, batch 7 G5): replay the misplaced Roaming
/// store into a temp COPY of the main one — filtered, idempotent,
/// never the live DB. Selection/dedupe are pure + unit-tested; the
/// replay itself is the ignored `maint_replay_roaming` test.
#[cfg(test)]
mod maint_replay;
