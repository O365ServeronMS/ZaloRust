//! Configurable Desktop→shadow mapping (batch 12 L2, audit §4 Phase 2
//! items 2.3 + 2.4/2.7 groundwork).
//!
//! The mapping is a DECLARATIVE JSON file — there is NO free SQL in
//! it, ever. Every value is one of:
//! ```json
//! "target_field": "source_column"
//! "target_field": { "const": <scalar or "$db_id"> }
//! "target_field": { "expr": "<whitelisted>", "of": "<column>" }
//! "target_field": { "expr": "json_object_of", "of": ["col", …] }
//! ```
//!
//! with the expr whitelist exactly: `ms_to_ms` (pass the source ms
//! through), `s_to_ms` (seconds → ms), `string`, `int`,
//! `json_object_of` (build a nested object from the listed columns).
//! `{"const": "$db_id"}` resolves to the digits of the one2one/group
//! DB FILE NAME (`123.db` → "123"), which is the conversation id the
//! capture path would derive; plan rejects it for index/stranger
//! kinds.
//!
//! Batch 13: the top level also accepts an optional `"_notes"`
//! object — free-form `{ "<field path>": "<why uncertain>" }`
//! documentation for readings that names/types alone cannot settle.
//! The parser accepts it and DROPS it: `plan`/`extract` never see it.
//!
//! Target fields per entity:
//! - `message` maps the CAPTURE ENVELOPE names (`msgId`, `uidFrom`,
//!   `idTo`, `ts`, `msgType`, `content`) plus any extra target names
//!   (carried into the payload verbatim). `extract` then derives
//!   `conv_id`/`sender_id`/`text`/`kind`/`payload` EXACTLY the way
//!   `normalize::message_to_write` does for wire messages, so the
//!   `Write::Message` values are the same the capture path produces —
//!   only `source = "import"` and `is_group` (from the DB kind)
//!   differ. `ts` MUST declare its unit via `ms_to_ms`/`s_to_ms`.
//!   A media-kind `content` column that holds a JSON text becomes the
//!   parsed OBJECT in the payload (the wire shape; that is what keeps
//!   `writer::content_hash` and attachment extraction comparable).
//!   Batch 15 O4 (KQ2 applied to the import path): the self-sent
//!   sender substitution is `normalize::sender_for` — the SAME rule
//!   the capture path applies — seeded from `ExtractOpts::own_uid`
//!   (env `ZR_OWN_UID` or `--own-uid-from-settings`, never printed).
//! - `conversation` (fields `id`*, `is_group`*, `title`,
//!   `avatar_url`, `last_msg_id`, `last_ts`, `raw`),
//!   `contact` (`user_id`*, `display_name`, `avatar_url`, `raw`),
//!   `group` (`group_id`*, `name`, `raw`) map the `Write` struct
//!   fields; `raw` defaults to a JSON object of every column the
//!   mapping reads (* = required).
//! - `attachment` (`msg_id`* + the `attachments` column names) is
//!   validated and COUNTED only: the writer derives attachment rows
//!   from message payloads, and the Desktop-side media table is 2.6
//!   (hardlink) groundwork — no `Write` exists for it in this batch.
//!
//! `plan(mapping, inventories)` validates every referenced
//! table/column against the snapshot inventory and lists EXACTLY what
//! is missing — the user iterates the mapping against the real
//! `--inventory` output. `extract` builds its SELECT from the
//! validated, identifier-quoted names and bound parameters only.
//!
//! Dry-run classification (2.4): for each extracted `Write`, the
//! writer's precedence rules are applied READ-ONLY against a temp COPY
//! of the shadow store (`open_shadow_copy`: file-copy, then
//! `open_with_key_readonly`, which sets `query_only` + busy_timeout —
//! the live store is never opened). Verdicts per message:
//! - `New` — no row with that msg_id;
//! - `FillNull` — a capture/e2ee row exists and import would only
//!   fill a NULL cell (`text`/`sender_id`; import NEVER replaces
//!   capture/e2ee text, payload or type — writer rank 1 < 2/3);
//! - `UpdateImport` — an import row exists and the payload changed
//!   (rank 1 >= 1; a converging replay is `Ignored`);
//! - `Ignored` — nothing would change.
//! For conversation/contact/group the writer has no rank guard
//! (COALESCE fills, `type`/`updated_at`/`raw_json` always rewrite), so
//! `FillNull` there means "the import would change at least one stored
//! cell".
//!
//! Delta cursors (2.7 groundwork, L4): `sync_cursors` rows with scope
//! `import:<db-relative-path>` holding `"<max_ts>:<max_rowid>"`, where
//! `max_ts` is the max of the RAW source ts column (the domain the
//! delta comparison runs in — changing the mapping's ts unit needs a
//! fresh cursor, documented). With `--delta`, `extract` skips a row
//! only when BOTH `rowid <= max_rowid` AND `ts <= max_ts` (a fresh
//! rowid or a newer ts is included; an in-place edit of an old row is
//! not — the accepted 2.7 risk). The dry run READS the cursor from
//! the shadow copy and never writes it; `write_import_cursor` exists
//! for the later, user-approved apply step and is exercised by tests
//! only.
//!
//! Hard rules honored here: nothing in this module prints; no row
//! value ever leaves a function boundary except into a `Write`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use rusqlite::types::Value as SV;
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;

use super::Write;
use super::import::inventory::{
    quote_ident, KindInventory, SnapshotInventories, TableInfo,
};
use super::normalize::msg_type_code;
use super::schema;

/// The entities a mapping may describe.
pub const ENTITIES: [&str; 5] = ["conversation", "contact", "group", "message", "attachment"];

/// Which snapshot DB kind an entity maps. The message DBs are the
/// `Core\Message\*.db` classes; `index` is `Core\Index.db`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MapDb {
    Index,
    OneToOne,
    Group,
    Stranger,
}

impl MapDb {
    pub fn parse(s: &str) -> Option<MapDb> {
        match s {
            "index" => Some(MapDb::Index),
            "one2one" => Some(MapDb::OneToOne),
            "group" => Some(MapDb::Group),
            "stranger" => Some(MapDb::Stranger),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            MapDb::Index => "index",
            MapDb::OneToOne => "one2one",
            MapDb::Group => "group",
            MapDb::Stranger => "stranger",
        }
    }
}

/// The fixed expr whitelist (brief L2). Anything else is a plan/parse
/// error — there is no way to express free SQL through the config.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expr {
    /// Source is already epoch ms: coerce to i64, pass through.
    MsToMs,
    /// Source is epoch SECONDS: multiply by 1000.
    SToMs,
    /// Coerce to a string.
    Str,
    /// Coerce to an integer.
    Int,
    /// Build a JSON object from the listed columns.
    JsonObjectOf,
}

impl Expr {
    pub fn parse(s: &str) -> Option<Expr> {
        match s {
            "ms_to_ms" => Some(Expr::MsToMs),
            "s_to_ms" => Some(Expr::SToMs),
            "string" => Some(Expr::Str),
            "int" => Some(Expr::Int),
            "json_object_of" => Some(Expr::JsonObjectOf),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Expr::MsToMs => "ms_to_ms",
            Expr::SToMs => "s_to_ms",
            Expr::Str => "string",
            Expr::Int => "int",
            Expr::JsonObjectOf => "json_object_of",
        }
    }

    pub const WHITELIST: &'static str = "ms_to_ms, s_to_ms, string, int, json_object_of";
}

/// The operand of an expr: one column or (for `json_object_of`) the
/// column list.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldOf {
    Col(String),
    Cols(Vec<String>),
}

/// One target-field value in the config.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldCfg {
    Col(String),
    /// `{const: …}` — a literal scalar, or the string `"$db_id"`.
    Const(Value),
    Expr { expr: Expr, of: FieldOf },
}

/// One entity's config section.
#[derive(Debug, Clone, PartialEq)]
pub struct EntityCfg {
    pub db: Vec<MapDb>,
    pub table: String,
    pub columns: BTreeMap<String, FieldCfg>,
}

/// A whole mapping file.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Mapping {
    /// Desktop msgType string → web msgType string. Pass-through by
    /// default (an empty map).
    pub msg_type: BTreeMap<String, String>,
    pub entities: BTreeMap<String, EntityCfg>,
}

impl Mapping {
    /// The built-in skeleton: maps NOTHING (no entity, no msgType
    /// entry) — the default when the mapping mode runs without
    /// `--mapping`, and the documented starting point for a real one.
    pub fn skeleton() -> Mapping {
        Mapping::default()
    }
}

/// A pretty skeleton JSON document (for `docs/import-mapping.md` and
/// tests): same shape a user starts from, mapping nothing.
pub fn skeleton_json() -> String {
    serde_json::to_string_pretty(&serde_json::json!({
        "msgType": {},
        "entities": {}
    }))
    .unwrap()
}

// --- parsing (hand-rolled: every error names exactly what is wrong) ----

/// Parse a mapping file's bytes. Never touches the FS.
pub fn parse_mapping(bytes: &[u8]) -> Result<Mapping, String> {
    let v: Value = serde_json::from_slice(bytes)
        .map_err(|e| format!("mapping is not valid JSON: {e}"))?;
    parse_mapping_value(&v)
}

/// Read and parse `--mapping <file>`.
pub fn load_mapping_file(path: &Path) -> Result<Mapping, String> {
    let bytes =
        std::fs::read(path).map_err(|e| format!("--mapping {path:?}: cannot read: {e}"))?;
    parse_mapping(&bytes)
}

fn parse_mapping_value(v: &Value) -> Result<Mapping, String> {
    let obj = v
        .as_object()
        .ok_or_else(|| String::from("mapping: top level must be a JSON object"))?;
    for k in obj.keys() {
        if k != "msgType" && k != "entities" && k != "_notes" {
            return Err(format!(
                "mapping: unknown key {k:?} (allowed: \"msgType\", \"entities\", \"_notes\")"
            ));
        }
    }
    // Batch 13: an optional top-level "_notes" object — the mapping
    // author's uncertainty notes (batch brief: which reading is a
    // guess pending the batch-14 distinct-values tool). It is
    // documentation ONLY: free-form, never validated against the
    // inventory, and neither `plan` nor `extract` ever reads it.
    if let Some(notes) = obj.get("_notes") {
        if !notes.is_object() {
            return Err(String::from(
                "mapping: \"_notes\" must be an object (field path -> note)",
            ));
        }
    }
    let mut msg_type = BTreeMap::new();
    if let Some(mt) = obj.get("msgType") {
        let m = mt.as_object().ok_or_else(|| {
            String::from("mapping: \"msgType\" must be an object of {desktop msgType: web msgType}")
        })?;
        for (from, to) in m {
            let to = to.as_str().ok_or_else(|| {
                format!("mapping: msgType.{from:?} must be a string (the web msgType)")
            })?;
            if from.is_empty() {
                return Err(String::from("mapping: msgType keys must be non-empty"));
            }
            msg_type.insert(from.clone(), to.to_string());
        }
    }
    let mut entities = BTreeMap::new();
    if let Some(en) = obj.get("entities") {
        let m = en.as_object().ok_or_else(|| {
            String::from(
                "mapping: \"entities\" must be an object keyed by conversation/contact/group/message/attachment",
            )
        })?;
        for (name, cfg) in m {
            if !ENTITIES.contains(&name.as_str()) {
                return Err(format!(
                    "mapping: entities: unknown entity {name:?} (allowed: {})",
                    ENTITIES.join(", ")
                ));
            }
            let e = parse_entity(name, cfg)?;
            entities.insert(name.clone(), e);
        }
    }
    Ok(Mapping { msg_type, entities })
}

fn parse_entity(name: &str, cfg: &Value) -> Result<EntityCfg, String> {
    let p = |msg: String| format!("mapping: entities.{name}: {msg}");
    let obj = cfg
        .as_object()
        .ok_or_else(|| p(String::from("must be a JSON object")))?;
    for k in obj.keys() {
        if !["db", "table", "columns"].contains(&k.as_str()) {
            return Err(p(format!(
                "unknown key {k:?} (allowed: \"db\", \"table\", \"columns\")"
            )));
        }
    }
    let table = obj
        .get("table")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| p(String::from("missing required key \"table\" (the source table)")))?
        .to_string();
    let db_v = obj
        .get("db")
        .ok_or_else(|| p(String::from("missing required key \"db\" (index/one2one/group/stranger)")))?;
    let db = {
        let one_or_many = match db_v {
            Value::String(_) | Value::Array(_) => db_v,
            _ => return Err(p(String::from("\"db\" must be a kind name or an array of kind names"))),
        };
        let mut kinds = Vec::new();
        match one_or_many {
            Value::String(s) => {
                let k = MapDb::parse(s).ok_or_else(|| {
                    p(format!(
                        "unknown db kind {s:?} (allowed: index, one2one, group, stranger)"
                    ))
                })?;
                kinds.push(k);
            }
            Value::Array(a) => {
                if a.is_empty() {
                    return Err(p(String::from("\"db\" must name at least one kind")));
                }
                for item in a {
                    let s = item.as_str().ok_or_else(|| {
                        p(String::from("\"db\" entries must be kind name strings"))
                    })?;
                    let k = MapDb::parse(s).ok_or_else(|| {
                        p(format!(
                            "unknown db kind {s:?} (allowed: index, one2one, group, stranger)"
                        ))
                    })?;
                    if !kinds.contains(&k) {
                        kinds.push(k);
                    }
                }
            }
            _ => unreachable!("shape checked above"),
        }
        kinds
    };
    let mut columns = BTreeMap::new();
    if let Some(cols) = obj.get("columns") {
        let m = cols.as_object().ok_or_else(|| {
            p(String::from(
                "\"columns\" must be an object of target field -> source column",
            ))
        })?;
        for (target, cv) in m {
            if target.is_empty() {
                return Err(p(String::from("columns: target field names must be non-empty")));
            }
            let fc = parse_field(name, target, cv)?;
            columns.insert(target.clone(), fc);
        }
    }
    Ok(EntityCfg { db, table, columns })
}

fn parse_field(entity: &str, target: &str, cv: &Value) -> Result<FieldCfg, String> {
    let p = |msg: String| format!("mapping: entities.{entity}.columns.{target}: {msg}");
    match cv {
        Value::String(s) => {
            if s.is_empty() {
                return Err(p(String::from(
                    "a plain string must be a non-empty source column name",
                )));
            }
            Ok(FieldCfg::Col(s.clone()))
        }
        Value::Object(o) => {
            if let Some(c) = o.get("const") {
                if o.len() != 1 {
                    return Err(p(String::from("\"const\" takes exactly one key")));
                }
                match c {
                    Value::String(_)
                    | Value::Number(_)
                    | Value::Bool(_) => Ok(FieldCfg::Const(c.clone())),
                    _ => Err(p(String::from(
                        "\"const\" must be a scalar (string, number, bool) — or the string \"$db_id\"",
                    ))),
                }
            } else if let Some(e) = o.get("expr") {
                if o.len() != 2 || !o.contains_key("of") {
                    return Err(p(String::from(
                        "an expr needs exactly the two keys \"expr\" and \"of\"",
                    )));
                }
                let es = e
                    .as_str()
                    .ok_or_else(|| p(String::from("\"expr\" must be a string")))?;
                let expr = Expr::parse(es)
                    .ok_or_else(|| p(format!("unknown expr {es:?} (whitelist: {})", Expr::WHITELIST)))?;
                let of = o.get("of").expect("checked above");
                let of_res = match expr {
                    Expr::JsonObjectOf => {
                        let arr = of.as_array().filter(|a| !a.is_empty()).ok_or_else(|| {
                            p(String::from("json_object_of takes {\"of\": [\"col\", …]} (a non-empty array)"))
                        })?;
                        let mut cols = Vec::with_capacity(arr.len());
                        for c in arr {
                            let s = c.as_str().filter(|s| !s.is_empty()).ok_or_else(|| {
                                p(String::from(
                                    "json_object_of: every \"of\" entry must be a non-empty column name",
                                ))
                            })?;
                            cols.push(s.to_string());
                        }
                        FieldOf::Cols(cols)
                    }
                    _ => {
                        let s = of
                            .as_str()
                            .filter(|s| !s.is_empty())
                            .ok_or_else(|| p(format!("expr {es:?} takes {{\"of\": \"<column>\"}}")))?;
                        FieldOf::Col(s.to_string())
                    }
                };
                Ok(FieldCfg::Expr { expr, of: of_res })
            } else {
                Err(p(String::from(
                    "an object value must be {\"const\": …} or {\"expr\": …, \"of\": …}",
                )))
            }
        }
        _ => Err(p(String::from(
            "must be a source column string, {\"const\": …} or {\"expr\": …, \"of\": …}",
        ))),
    }
}

// --- planning -------------------------------------------------------------

/// Which entity a plan slot is (drives whitelists + required fields).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntityKind {
    Conversation,
    Contact,
    Group,
    Message,
    Attachment,
}

impl EntityKind {
    fn name(self) -> &'static str {
        match self {
            EntityKind::Conversation => "conversation",
            EntityKind::Contact => "contact",
            EntityKind::Group => "group",
            EntityKind::Message => "message",
            EntityKind::Attachment => "attachment",
        }
    }

    /// `None` for message (core envelope names + free extras); the
    /// fixed field list otherwise.
    fn allowed_targets(self) -> Option<&'static [&'static str]> {
        match self {
            EntityKind::Conversation => Some(&[
                "id", "is_group", "title", "avatar_url", "last_msg_id", "last_ts", "raw",
            ]),
            EntityKind::Contact => Some(&["user_id", "display_name", "avatar_url", "raw"]),
            EntityKind::Group => Some(&["group_id", "name", "raw"]),
            EntityKind::Attachment => Some(&[
                "msg_id", "idx", "kind", "url", "local_path", "size", "sha256",
            ]),
            EntityKind::Message => None,
        }
    }

    fn required(self) -> &'static [&'static str] {
        match self {
            EntityKind::Conversation => &["id", "is_group"],
            EntityKind::Contact => &["user_id"],
            EntityKind::Group => &["group_id"],
            EntityKind::Message => &["msgId", "ts"],
            EntityKind::Attachment => &["msg_id"],
        }
    }
}

/// Target fields the extractor DERIVES for messages — mapping them by
/// hand is an error, not a silent override.
const DERIVED_MESSAGE_FIELDS: [&str; 6] =
    ["conv_id", "sender_id", "text", "kind", "source", "is_group"];

/// One resolved target field.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldSpec {
    pub target: String,
    pub res: FieldRes,
}

#[derive(Debug, Clone, PartialEq)]
pub enum FieldRes {
    /// Index into `EntityPlan::select`.
    Col(usize),
    Const(Value),
    Expr { expr: Expr, of: FieldOfRes },
}

#[derive(Debug, Clone, PartialEq)]
pub enum FieldOfRes {
    Col(usize),
    Cols(Vec<usize>),
}

/// One entity, validated and resolved: the table, the exact SELECT
/// column list (every referenced source column, deduped, in first-use
/// order) and the per-target resolutions.
#[derive(Debug, Clone, PartialEq)]
pub struct EntityPlan {
    pub db: Vec<MapDb>,
    pub table: String,
    pub select: Vec<String>,
    pub fields: Vec<FieldSpec>,
}

impl EntityPlan {
    /// The ts column name (delta filtering), when this is a message
    /// entity with its unit-declared ts.
    fn ts_col(&self) -> Option<&str> {
        let spec = self.fields.iter().find(|f| f.target == "ts")?;
        match &spec.res {
            FieldRes::Expr {
                of: FieldOfRes::Col(i),
                ..
            } => self.select.get(*i).map(String::as_str),
            _ => None,
        }
    }
}

/// The validated mapping: everything `extract` needs.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Plan {
    pub msg_type: BTreeMap<String, String>,
    pub conversation: Option<EntityPlan>,
    pub contact: Option<EntityPlan>,
    pub group: Option<EntityPlan>,
    pub message: Option<EntityPlan>,
    pub attachment: Option<EntityPlan>,
}

impl Plan {
    /// Shape-only summary of what is mapped (report lines).
    pub fn summary_line(&self) -> String {
        let mut parts = Vec::new();
        for (name, slot) in [
            ("conversation", &self.conversation),
            ("contact", &self.contact),
            ("group", &self.group),
            ("message", &self.message),
            ("attachment", &self.attachment),
        ] {
            if let Some(ep) = slot {
                let kinds: Vec<&str> = ep.db.iter().map(|d| d.name()).collect();
                parts.push(format!(
                    "{name}[{}]table={}",
                    kinds.join("+"),
                    ep.table
                ));
            }
        }
        if parts.is_empty() {
            String::from("nothing mapped (skeleton)")
        } else {
            format!("msgType entries={}, {}", self.msg_type.len(), parts.join(" "))
        }
    }
}

fn kind_inventory<'a>(
    inv: &'a SnapshotInventories,
    d: MapDb,
) -> Option<&'a KindInventory> {
    match d {
        MapDb::Index => inv.index.as_ref(),
        MapDb::OneToOne => inv.one_to_one.as_ref(),
        MapDb::Group => inv.group.as_ref(),
        MapDb::Stranger => inv.stranger_box.as_ref(),
    }
}

/// Columns one field config references (for existence checks).
fn referenced_cols(f: &FieldCfg) -> Vec<&str> {
    match f {
        FieldCfg::Col(c) => vec![c.as_str()],
        FieldCfg::Const(_) => Vec::new(),
        FieldCfg::Expr { of, .. } => match of {
            FieldOf::Col(c) => vec![c.as_str()],
            FieldOf::Cols(cs) => cs.iter().map(String::as_str).collect(),
        },
    }
}

/// Validate one entity against the snapshot inventories. Pushes
/// precise errors into `errs`; returns the plan when the config
/// section is absent (not mapped).
fn plan_entity(
    cfg: Option<&EntityCfg>,
    k: EntityKind,
    inv: &SnapshotInventories,
    errs: &mut Vec<String>,
) -> Option<EntityPlan> {
    let Some(cfg) = cfg else { return None };
    let who = format!("entities.{}", k.name());

    // Entity vs DB kind.
    for &d in &cfg.db {
        let bad = match k {
            EntityKind::Message => d == MapDb::Index,
            _ => d != MapDb::Index,
        };
        if bad {
            let allowed = if k == EntityKind::Message {
                "one2one, group, stranger"
            } else {
                "index"
            };
            errs.push(format!(
                "mapping plan: {who}.db: kind {:?} is not valid for a {who} mapping (allowed: {allowed})",
                d.name(),
            ));
        }
    }

    // Target field names.
    for t in cfg.columns.keys() {
        if let Some(allowed) = k.allowed_targets() {
            if !allowed.contains(&t.as_str()) {
                errs.push(format!(
                    "mapping plan: {who}.columns.{t}: unknown target field (allowed: {})",
                    allowed.join(", ")
                ));
            }
        } else if DERIVED_MESSAGE_FIELDS.contains(&t.as_str()) {
            errs.push(format!(
                "mapping plan: {who}.columns.{t}: '{t}' is DERIVED by the extractor — map uidFrom/idTo/ts/msgType/content instead"
            ));
        } else if t.is_empty() {
            errs.push(format!("mapping plan: {who}.columns: empty target field name"));
        }
    }

    // Required fields.
    for req in k.required() {
        if !cfg.columns.contains_key(*req) {
            errs.push(format!(
                "mapping plan: {who}: missing required target field '{req}'"
            ));
        }
    }

    // Message-specific rules.
    if k == EntityKind::Message {
        match cfg.columns.get("ts") {
            Some(FieldCfg::Expr { expr: Expr::MsToMs, .. })
            | Some(FieldCfg::Expr { expr: Expr::SToMs, .. }) => {}
            Some(_) => errs.push(format!(
                "mapping plan: {who}.columns.ts: must declare the source unit — {{\"expr\":\"ms_to_ms\"|\"s_to_ms\",\"of\":\"<col>\"}}"
            )),
            None => {} // already reported by the required check
        }
        if !cfg.columns.contains_key("uidFrom") && !cfg.columns.contains_key("idTo") {
            errs.push(format!(
                "mapping plan: {who}: needs 'uidFrom' or 'idTo' mapped — the conversation derivation has no source otherwise"
            ));
        }
        // $db_id placement: one2one/group message DBs only.
        for (t, f) in &cfg.columns {
            if let FieldCfg::Const(v) = f {
                if v.as_str() == Some("$db_id") {
                    if cfg.db.iter().any(|d| !matches!(d, MapDb::OneToOne | MapDb::Group)) {
                        errs.push(format!(
                            "mapping plan: {who}.columns.{t}: {{\"const\":\"$db_id\"}} needs a one2one/group message DB (the digits come from the DB file name)"
                        ));
                    }
                }
            }
        }
    } else {
        // $db_id makes no sense outside message mappings at all.
        for (t, f) in &cfg.columns {
            if let FieldCfg::Const(v) = f {
                if v.as_str() == Some("$db_id") {
                    errs.push(format!(
                        "mapping plan: {who}.columns.{t}: {{\"const\":\"$db_id\"}} is only valid in a message mapping over one2one/group DBs"
                    ));
                }
            }
        }
    }

    // Per-kind existence checks against the samples.
    for &d in &cfg.db {
        let Some(kinv) = kind_inventory(inv, d) else {
            errs.push(format!(
                "mapping plan: {who}.db: the snapshot has no {} sample to validate against",
                d.name()
            ));
            continue;
        };
        let table: Option<&TableInfo> = kinv.inventory.table(&cfg.table);
        let Some(tinfo) = table else {
            errs.push(format!(
                "mapping plan: {who}: table {:?} does not exist in {} ({} kind)",
                cfg.table, kinv.source_rel, d.name()
            ));
            continue;
        };
        for (target, f) in &cfg.columns {
            for col in referenced_cols(f) {
                if !tinfo.columns.iter().any(|c| c.name == col) {
                    errs.push(format!(
                        "mapping plan: {}: columns.{}: column {:?} does not exist in table {:?} ({} kind, inventory {})",
                        who, target, col, cfg.table, d.name(), kinv.source_rel
                    ));
                }
            }
        }
    }

    // Resolve the SELECT list and the field specs. (If anything above
    // failed, the caller drops the whole plan anyway; resolution here
    // never invents columns — only names already referenced.)
    let mut select: Vec<String> = Vec::new();
    let push_col = |name: &str, select: &mut Vec<String>| -> usize {
        if let Some(i) = select.iter().position(|c| c == name) {
            i
        } else {
            select.push(name.to_string());
            select.len() - 1
        }
    };
    let mut fields = Vec::with_capacity(cfg.columns.len());
    for (target, f) in &cfg.columns {
        let res = match f {
            FieldCfg::Col(c) => FieldRes::Col(push_col(c, &mut select)),
            FieldCfg::Const(v) => FieldRes::Const(v.clone()),
            FieldCfg::Expr { expr, of } => FieldRes::Expr {
                expr: *expr,
                of: match of {
                    FieldOf::Col(c) => FieldOfRes::Col(push_col(c, &mut select)),
                    FieldOf::Cols(cs) => FieldOfRes::Cols(
                        cs.iter().map(|c| push_col(c, &mut select)).collect(),
                    ),
                },
            },
        };
        fields.push(FieldSpec {
            target: target.clone(),
            res,
        });
    }
    Some(EntityPlan {
        db: cfg.db.clone(),
        table: cfg.table.clone(),
        select,
        fields,
    })
}

/// Validate `mapping` against the snapshot inventories. Every missing
/// table/column, every unknown field/expr and every rule violation is
/// one error line listing exactly what is wrong; ALL of them are
/// returned (never just the first) so the user can iterate.
pub fn plan(m: &Mapping, inv: &SnapshotInventories) -> Result<Plan, Vec<String>> {
    let mut errs = Vec::new();
    let conversation = plan_entity(m.entities.get("conversation"), EntityKind::Conversation, inv, &mut errs);
    let contact = plan_entity(m.entities.get("contact"), EntityKind::Contact, inv, &mut errs);
    let group = plan_entity(m.entities.get("group"), EntityKind::Group, inv, &mut errs);
    let message = plan_entity(m.entities.get("message"), EntityKind::Message, inv, &mut errs);
    let attachment = plan_entity(m.entities.get("attachment"), EntityKind::Attachment, inv, &mut errs);
    if errs.is_empty() {
        Ok(Plan {
            msg_type: m.msg_type.clone(),
            conversation,
            contact,
            group,
            message,
            attachment,
        })
    } else {
        Err(errs)
    }
}

// --- L4: import cursors (2.7 groundwork) ---------------------------------

/// A per-DB import watermark: the max RAW source ts (in the source
/// column's own units — that is what the delta comparison uses) and
/// the max rowid. Encoded into `sync_cursors.cursor` as
/// `"<ts>:<rowid>"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImportCursor {
    pub max_ts: i64,
    pub max_rowid: i64,
}

/// `sync_cursors.scope` for one imported DB: `import:<db-relative-path>`.
pub fn import_scope(db_rel: &str) -> String {
    format!("import:{db_rel}")
}

pub fn encode_cursor(c: ImportCursor) -> String {
    format!("{}:{}", c.max_ts, c.max_rowid)
}

pub fn decode_cursor(s: &str) -> Option<ImportCursor> {
    let (ts, rowid) = s.split_once(':')?;
    let ts: i64 = ts.trim().parse().ok()?;
    let rowid: i64 = rowid.trim().parse().ok()?;
    Some(ImportCursor { max_ts: ts, max_rowid: rowid })
}

/// Read one DB's cursor. `Ok(None)` when no row exists; a present but
/// undecodable cursor is an ERROR (fail closed — the caller decides),
/// never a silent full re-import.
pub fn read_import_cursor(conn: &Connection, db_rel: &str) -> Result<Option<ImportCursor>, String> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT cursor FROM sync_cursors WHERE scope = ?1",
            params![import_scope(db_rel)],
            |r| r.get(0),
        )
        .optional()
        .map_err(|e| format!("sync_cursors read failed: {e}"))?;
    match raw {
        None => Ok(None),
        Some(s) => match decode_cursor(&s) {
            Some(c) => Ok(Some(c)),
            None => Err(format!(
                "sync_cursors: cursor for scope {:?} is corrupt: {s:?}",
                import_scope(db_rel)
            )),
        },
    }
}

/// Write one DB's cursor (upsert). Only the later, user-approved apply
/// step will call this; the dry run is read-only.
pub fn write_import_cursor(
    conn: &Connection,
    db_rel: &str,
    c: ImportCursor,
) -> rusqlite::Result<usize> {
    conn.execute(
        "INSERT INTO sync_cursors (scope, cursor, updated_at) VALUES (?1, ?2, ?3)
         ON CONFLICT(scope) DO UPDATE SET
           cursor = excluded.cursor,
           updated_at = excluded.updated_at",
        params![import_scope(db_rel), encode_cursor(c), schema::now_ms()],
    )
}

/// (batch 16 P1, 2.5 resume + idempotence) Write one DB's cursor ONLY
/// when it actually advanced past the stored one. The apply step calls
/// this inside each batch's transaction; a re-apply of a fully
/// imported DB must be a zero-change run (the idempotence AC measures
/// `total_changes()`), so rewriting an identical cursor row — or,
/// worse, moving the watermark BACKWARDS when a later batch's max is
/// lower — is skipped. Returns whether a write happened.
pub fn write_import_cursor_if_advanced(
    conn: &Connection,
    db_rel: &str,
    c: ImportCursor,
) -> rusqlite::Result<bool> {
    let stored: Option<String> = conn
        .query_row(
            "SELECT cursor FROM sync_cursors WHERE scope = ?1",
            params![import_scope(db_rel)],
            |r| r.get(0),
        )
        .optional()?;
    match stored.as_deref() {
        Some(s) => {
            let old = decode_cursor(s);
            let advanced = match old {
                Some(o) => c.max_ts > o.max_ts || c.max_rowid > o.max_rowid,
                // A corrupt stored cursor was already refused at read
                // time (read_import_cursor fails closed); belt only.
                None => true,
            };
            if !advanced {
                return Ok(false);
            }
        }
        None => {}
    }
    write_import_cursor(conn, db_rel, c)?;
    Ok(true)
}

/// The cursor an apply pass would WRITE for this DB: max raw ts +
/// max rowid of the entity's table. `None` for entities without a
/// unit-declared ts (the cursor is a message-table watermark).
pub fn next_cursor(conn: &Connection, ep: &EntityPlan) -> Result<Option<ImportCursor>, String> {
    let Some(ts_col) = ep.ts_col() else { return Ok(None) };
    let q = quote_ident(&ep.table)?;
    let qts = quote_ident(ts_col)?;
    conn.query_row(
        &format!("SELECT max({qts}), max(rowid) FROM {q}"),
        [],
        |r| {
            Ok(Some(ImportCursor {
                max_ts: r.get::<_, Option<i64>>(0)?.unwrap_or(0),
                max_rowid: r.get::<_, Option<i64>>(1)?.unwrap_or(0),
            }))
        },
    )
    .map_err(|e| format!("cursor probe on {:?} failed: {e}", ep.table))
}

// --- extraction -----------------------------------------------------------

/// Per-row extraction options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtractOpts<'a> {
    pub kind: MapDb,
    /// Digits from the DB file name (`123.db` → Some(123)); None for
    /// index/stranger.
    pub db_id: Option<u64>,
    /// L4 `--delta`: skip rows with `rowid <= max_rowid AND ts <= max_ts`.
    pub cursor: Option<ImportCursor>,
    /// Own-uid for the self-sent sender substitution (batch 15 O4,
    /// KQ2): rows with `uidFrom == "0"` (or no uidFrom) get this as
    /// `sender_id` through `normalize::sender_for` — the SAME rule
    /// the capture path applies. `None` keeps the sender NULL. The
    /// value is never printed or logged anywhere.
    pub own_uid: Option<&'a str>,
}

/// Per-entity skip counts (rows the mapping read but could not turn
/// into a Write: NULL keys, unparsable ts, blob in a direct field…).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ExtractSkips {
    pub conversation: usize,
    pub contact: usize,
    pub group: usize,
    pub message: usize,
    pub attachment: usize,
}

/// The entity plan in `slot`, when its db kinds include `kind`.
fn applicable<'a>(slot: &'a Option<EntityPlan>, kind: &MapDb) -> Option<&'a EntityPlan> {
    slot.as_ref().filter(|e| e.db.contains(kind))
}

/// Extract every Write the mapping produces from ONE DB of kind
/// `opts.kind` (the connection is that DB; the plan tells which
/// entities apply to the kind). One source row becomes at most one
/// Write — the same values the capture path produces. Callers stream
/// DB-by-DB so memory stays bounded by one conversation's history.
pub fn extract(
    conn: &Connection,
    plan: &Plan,
    opts: &ExtractOpts,
) -> Result<(Vec<Write>, ExtractSkips), String> {
    let mut out = Vec::new();
    let mut skips = ExtractSkips::default();
    match opts.kind {
        MapDb::Index => {
            if let Some(ep) = applicable(&plan.conversation, &opts.kind) {
                let rows = read_source_rows(conn, ep, None)?;
                for vals in &rows {
                    match conversation_row(ep, vals) {
                        Some(w) => out.push(w),
                        None => skips.conversation += 1,
                    }
                }
            }
            if let Some(ep) = applicable(&plan.contact, &opts.kind) {
                let rows = read_source_rows(conn, ep, None)?;
                for vals in &rows {
                    match contact_row(ep, vals) {
                        Some(w) => out.push(w),
                        None => skips.contact += 1,
                    }
                }
            }
            if let Some(ep) = applicable(&plan.group, &opts.kind) {
                let rows = read_source_rows(conn, ep, None)?;
                for vals in &rows {
                    match group_row(ep, vals) {
                        Some(w) => out.push(w),
                        None => skips.group += 1,
                    }
                }
            }
        }
        MapDb::OneToOne | MapDb::Group | MapDb::Stranger => {
            if let Some(ep) = applicable(&plan.message, &opts.kind) {
                let delta = opts
                    .cursor
                    .map(|c| (ep.ts_col().expect("plan guarantees a unit ts"), c));
                let rows = read_source_rows(conn, ep, delta)?;
                for vals in &rows {
                    match message_row(
                        ep,
                        vals,
                        &plan.msg_type,
                        opts.kind,
                        opts.db_id,
                        opts.own_uid,
                    ) {
                        Some(w) => out.push(w),
                        None => skips.message += 1,
                    }
                }
            }
        }
    }
    Ok((out, skips))
}

/// Row count of an entity's table (attachment refs, delta totals).
pub fn count_rows(conn: &Connection, ep: &EntityPlan) -> Result<i64, String> {
    let q = quote_ident(&ep.table)?;
    conn.query_row(&format!("SELECT count(*) FROM {q}"), [], |r| r.get(0))
        .map_err(|e| format!("count(*) on {:?} failed: {e}", ep.table))
}

/// (batch 16 P1, item 2.5) The RAW msgType source column of the message
/// plan — the apply preflight aggregates exactly THIS column with
/// batch 15's fixed distinct read. A const/expr msgType is refused
/// fail-closed (the same rule `extract_msg_codes` applies): the
/// preflight must see the raw stored code, never a mapping product —
/// otherwise "every code that occurs is mapped" could not be verified.
pub fn msg_type_column(ep: &EntityPlan) -> Result<String, String> {
    let Some(spec) = ep.fields.iter().find(|f| f.target == "msgType") else {
        return Err(String::from(
            "entities.message has no 'msgType' target — the apply preflight \
             cannot verify mapped codes without it",
        ));
    };
    match &spec.res {
        FieldRes::Col(i) => Ok(ep.select[*i].clone()),
        _ => Err(String::from(
            "entities.message.columns.msgType must map a PLAIN source column \
             (a const/expr value is a mapping product, not the raw Desktop \
             code the preflight must verify)",
        )),
    }
}

// --- batch 16 P1: coded extraction (the apply step's read path) -----------

/// One extracted message plus the facts the apply step (2.5) needs
/// and the plain `Write` does not carry:
/// - the RAW Desktop msgType code the source row held (post-mapping
///   it only survives in the payload when UNMAPPED — the mapped
///   string replaced it — so the unmapped decision needs it carried
///   explicitly);
/// - whether the row's `uidFrom` was NULL (not "0"): the shared
///   `normalize::sender_for` rule treats NULL as self when an own uid
///   is configured, and the reviewer wants that COUNT reported before
///   deciding whether NULL should stay "self" on the import path (the
///   rule itself never changes here);
/// - the source row's rowid and RAW ts (the cursor's own units) so
///   each committed batch can advance the per-DB resume cursor
///   exactly as far as it actually wrote.
#[derive(Debug, Clone)]
pub struct CodedWrite {
    pub write: Write,
    /// The raw msgType code as a string ("19"); `None` when the row's
    /// msgType was NULL/BLOB.
    pub raw_code: Option<String>,
    /// uidFrom was NULL (not "0", not an unmapped column).
    pub uid_from_null: bool,
    /// The source row's rowid (the `next_cursor` domain).
    pub src_rowid: i64,
    /// The source row's RAW ts value (the `next_cursor` domain — the
    /// delta comparison runs in the source column's own units).
    pub src_ts_raw: i64,
}

/// (batch 16 P1) Is this coded write's msgType code MAPPED by the
/// plan's msgType table? A NULL raw code cannot be proven mapped —
/// unmapped, fail closed (the hatch and the refusal both treat it so).
pub fn code_is_mapped(plan: &Plan, cw: &CodedWrite) -> bool {
    match &cw.raw_code {
        Some(code) => plan.msg_type.contains_key(code),
        None => false,
    }
}

/// (batch 16 P1, `--unmapped-as-raw`) The ONE escape hatch for an
/// unmapped row, in place: `kind` forced to 100 (`msg_type_code`'s
/// unknown bucket — the mapping has no opinion about this code) and
/// `text` forced NULL. A media-kind `content` column often holds JSON
/// text, and without a mapped code the extractor leaves that JSON as a
/// string — storing it in `text` would put JSON-as-text into the
/// store. With the hatch the content survives ONLY inside
/// `payload_json`, which also keeps the RAW code string (the
/// extractor's pass-through left it there). A later mapping that adds
/// the code makes a re-apply fill `type`/`text` (import rank 1 >= the
/// row's import rank) — the hatch is not a dead end.
pub fn force_unmapped_raw(cw: &mut CodedWrite) {
    if let Write::Message { kind, text, .. } = &mut cw.write {
        *kind = 100;
        *text = None;
    }
}

/// `read_source_rows`, plus each row's rowid as the first tuple field
/// (the coded-extraction read; the cursor domain needs it). Same
/// identifier quoting, same optional delta filter, same rowid order.
fn read_source_rows_with_rowid(
    conn: &Connection,
    ep: &EntityPlan,
    delta: Option<(&str, ImportCursor)>,
) -> Result<Vec<(i64, Vec<SV>)>, String> {
    let qtable = quote_ident(&ep.table)?;
    let cols: Vec<String> = ep
        .select
        .iter()
        .map(|c| quote_ident(c))
        .collect::<Result<Vec<String>, String>>()?;
    let mut sql = format!("SELECT rowid, {} FROM {qtable}", cols.join(", "));
    if let Some((ts_col, _)) = delta {
        let qts = quote_ident(ts_col)?;
        sql.push_str(&format!(" WHERE (rowid > ?1 OR {qts} > ?2)"));
    }
    sql.push_str(" ORDER BY rowid");
    let mut st = conn
        .prepare(&sql)
        .map_err(|e| format!("{}: {e}", ep.table))?;
    let n = ep.select.len();
    let map_row = |r: &rusqlite::Row| -> rusqlite::Result<(i64, Vec<SV>)> {
        let rowid = r.get::<_, SV>(0)?;
        let id = match rowid {
            SV::Integer(i) => i,
            // The delta filter already assumes an integer rowid
            // (`next_cursor` does `max(rowid)`); anything else means
            // the table shadows the name — surface it, never guess.
            _ => return Err(rusqlite::Error::InvalidColumnType(0, "rowid".into(), rusqlite::types::Type::Integer)),
        };
        let mut vals = Vec::with_capacity(n);
        for i in 0..n {
            vals.push(r.get::<_, SV>(i + 1)?);
        }
        Ok((id, vals))
    };
    let rows = match delta {
        Some((_, c)) => st
            .query_map(params![c.max_rowid, c.max_ts], map_row)
            .map_err(|e| format!("{}: {e}", ep.table))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("{}: {e}", ep.table))?,
        None => st
            .query_map([], map_row)
            .map_err(|e| format!("{}: {e}", ep.table))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format!("{}: {e}", ep.table))?,
    };
    Ok(rows)
}

/// (batch 16 P1, item 2.5) The message-entity extraction WITH the raw
/// codes — the apply step's read path. Same rows, same skips, same
/// `Write` values as [`extract`] (it is the same `message_row`); the
/// extra fields are the facts [`CodedWrite`] documents. One source row
/// still becomes at most one write, so memory stays bounded by one
/// conversation's history.
pub fn extract_coded(
    conn: &Connection,
    plan: &Plan,
    opts: &ExtractOpts,
) -> Result<(Vec<CodedWrite>, usize), String> {
    let mut out = Vec::new();
    let mut skipped = 0usize;
    let Some(ep) = applicable(&plan.message, &opts.kind) else {
        return Ok((out, skipped));
    };
    let ts_name = ep.ts_col().expect("plan guarantees a unit-declared ts");
    let delta = opts.cursor.map(|c| (ts_name, c));
    let rows = read_source_rows_with_rowid(conn, ep, delta)?;
    let ts_idx = ep.select.iter().position(|c| c == ts_name);
    for (rowid, vals) in &rows {
        let uid_from_null = match field_res(ep, "uidFrom") {
            Some(FieldRes::Col(i)) => matches!(vals[*i], SV::Null | SV::Blob(_)),
            _ => false,
        };
        let raw_ts = ts_idx.map(|i| sv_i64(&vals[i]).unwrap_or(0)).unwrap_or(0);
        let raw_code = string_field_opt(ep, vals, "msgType", opts.db_id);
        match message_row(ep, vals, &plan.msg_type, opts.kind, opts.db_id, opts.own_uid) {
            Some(write) => out.push(CodedWrite {
                write,
                raw_code,
                uid_from_null,
                src_rowid: *rowid,
                src_ts_raw: raw_ts,
            }),
            None => skipped += 1,
        }
    }
    Ok((out, skipped))
}

/// (batch 15 O1) The minimal code-cross-tab extractor: one
/// (msgId, raw Desktop msgType) pair per row of the mapped message
/// table, reading ONLY the two source columns the mapping names for
/// the `msgId`/`msgType` targets — nothing else. Both must be PLAIN
/// column mappings: a const/expr `msgType` is refused (fail closed —
/// the cross-tab must see the raw stored code, never a mapping
/// product). Rows whose msgId or msgType is NULL/BLOB are skipped and
/// counted (they can never join). No other column is ever read; no
/// row value other than the pair itself ever leaves this function.
pub fn extract_msg_codes(
    conn: &Connection,
    ep: &EntityPlan,
) -> Result<(Vec<(String, String)>, usize), String> {
    let col_of = |target: &str| -> Result<String, String> {
        let Some(spec) = ep.fields.iter().find(|f| f.target == target) else {
            return Err(format!(
                "extract_msg_codes: entities.message has no '{target}' target \
                 — the code cross-tab needs msgId + msgType"
            ));
        };
        match &spec.res {
            FieldRes::Col(i) => Ok(ep.select[*i].clone()),
            _ => Err(format!(
                "extract_msg_codes: entities.message.columns.{target} must map a PLAIN \
                 source column (a const/expr value is a mapping product, not the raw \
                 Desktop code)"
            )),
        }
    };
    let id_col = col_of("msgId")?;
    let mt_col = col_of("msgType")?;
    let qt = quote_ident(&ep.table)?;
    let qid = quote_ident(&id_col)?;
    let qmt = quote_ident(&mt_col)?;
    let sql = format!("SELECT {qid}, {qmt} FROM {qt} ORDER BY rowid");
    let mut st = conn
        .prepare(&sql)
        .map_err(|e| format!("{}: {e}", ep.table))?;
    let rows = st
        .query_map([], |r| Ok((r.get::<_, SV>(0)?, r.get::<_, SV>(1)?)))
        .map_err(|e| format!("{}: {e}", ep.table))?;
    let mut out = Vec::new();
    let mut skipped = 0usize;
    for row in rows {
        let (idv, mtv) = row.map_err(|e| format!("{}: {e}", ep.table))?;
        match (sv_str(&idv), sv_str(&mtv)) {
            (Some(id), Some(mt)) => out.push((id, mt)),
            _ => skipped += 1,
        }
    }
    Ok((out, skipped))
}

/// SELECT every referenced column (identifier-quoted), optionally
/// delta-filtered, in rowid order. No row value is returned to a
/// caller that does not know the mapping.
fn read_source_rows(
    conn: &Connection,
    ep: &EntityPlan,
    delta: Option<(&str, ImportCursor)>,
) -> Result<Vec<Vec<SV>>, String> {
    let qtable = quote_ident(&ep.table)?;
    let cols: Vec<String> = ep
        .select
        .iter()
        .map(|c| quote_ident(c))
        .collect::<Result<Vec<String>, String>>()?;
    let mut sql = format!("SELECT {} FROM {qtable}", cols.join(", "));
    if let Some((ts_col, _)) = delta {
        let qts = quote_ident(ts_col)?;
        sql.push_str(&format!(" WHERE (rowid > ?1 OR {qts} > ?2)"));
    }
    sql.push_str(" ORDER BY rowid");
    let mut st = conn
        .prepare(&sql)
        .map_err(|e| format!("{}: {e}", ep.table))?;
    let n = ep.select.len();
    let map_row = |r: &rusqlite::Row| -> rusqlite::Result<Vec<SV>> {
        (0..n).map(|i| r.get::<_, SV>(i)).collect()
    };
    let rows = match delta {
        Some((_, c)) => {
            let it = st
                .query_map(params![c.max_rowid, c.max_ts], map_row)
                .map_err(|e| format!("{}: {e}", ep.table))?;
            it.filter_map(Result::ok).collect::<Vec<_>>()
        }
        None => {
            let it = st
                .query_map([], map_row)
                .map_err(|e| format!("{}: {e}", ep.table))?;
            it.filter_map(Result::ok).collect::<Vec<_>>()
        }
    };
    Ok(rows)
}

// --- value coercion -------------------------------------------------------

/// A source value as a string (ids stored as INTEGER become decimal
/// strings — the capture envelope's ids are strings). NULL/blob → None.
fn sv_str(v: &SV) -> Option<String> {
    match v {
        SV::Text(s) => Some(s.clone()),
        SV::Integer(i) => Some(i.to_string()),
        SV::Real(f) => Some(f.to_string()),
        _ => None,
    }
}

fn sv_i64(v: &SV) -> Option<i64> {
    match v {
        SV::Integer(i) => Some(*i),
        SV::Real(f) => Some(*f as i64),
        SV::Text(s) => s.trim().parse::<i64>().ok(),
        _ => None,
    }
}

/// Truthiness of a source value for `is_group`: NULL/0/""/"0"/"false"
/// → false, anything else → true. Blob → None (skip row).
fn sv_bool(v: &SV) -> Option<bool> {
    match v {
        SV::Null => Some(false),
        SV::Integer(i) => Some(*i != 0),
        SV::Real(f) => Some(*f != 0.0),
        SV::Text(s) => {
            Some(!(s.is_empty() || s == "0" || s.eq_ignore_ascii_case("false")))
        }
        _ => None,
    }
}

/// A source value as JSON (NULL→null, int/real→number, text→string).
/// Blob → None: a direct field holding a blob skips the row.
fn sv_json(v: &SV) -> Option<Value> {
    match v {
        SV::Null => Some(Value::Null),
        SV::Integer(i) => Some(Value::Number((*i).into())),
        SV::Real(f) => serde_json::Number::from_f64(*f).map(Value::Number),
        SV::Text(s) => Some(Value::String(s.clone())),
        SV::Blob(_) => None,
    }
}

/// Lenient JSON (raw/json_object_of contexts): a blob becomes null
/// instead of failing the row.
fn sv_json_lenient(v: &SV) -> Value {
    sv_json(v).unwrap_or(Value::Null)
}

/// ts per its declared unit. Real/text-with-fraction seconds are
/// accepted (×1000, truncated to i64).
fn sv_to_ms(v: &SV, expr: Expr) -> Option<i64> {
    match expr {
        Expr::MsToMs => sv_i64(v),
        Expr::SToMs => match v {
            SV::Integer(i) => i.checked_mul(1000),
            SV::Real(f) => Some((*f * 1000.0) as i64),
            SV::Text(s) => {
                let t = s.trim();
                if let Ok(i) = t.parse::<i64>() {
                    i.checked_mul(1000)
                } else {
                    t.parse::<f64>().ok().map(|f| (f * 1000.0) as i64)
                }
            }
            _ => None,
        },
        _ => None,
    }
}

/// Resolve a `{"const": …}`: `$db_id` becomes the DB file's digits
/// (None db_id → the row is skipped — plan keeps this unreachable
/// for index/stranger).
fn const_json(v: &Value, db_id: Option<u64>) -> Option<Value> {
    if v.as_str() == Some("$db_id") {
        return Some(Value::String(db_id?.to_string()));
    }
    Some(v.clone())
}

/// One field's JSON value for the payload.
fn field_json(ep: &EntityPlan, vals: &[SV], spec: &FieldSpec, db_id: Option<u64>) -> Option<Value> {
    match &spec.res {
        FieldRes::Col(i) => sv_json(&vals[*i]),
        FieldRes::Const(v) => const_json(v, db_id),
        FieldRes::Expr { expr, of } => match of {
            FieldOfRes::Col(i) => {
                let v = &vals[*i];
                match expr {
                    Expr::Str => sv_json(&SV::Text(sv_str(v)?)),
                    Expr::Int => sv_json(&SV::Integer(sv_i64(v)?)),
                    _ => sv_json(v),
                }
            }
            FieldOfRes::Cols(ix) => {
                let mut m = serde_json::Map::new();
                for &i in ix {
                    m.insert(ep.select[i].clone(), sv_json_lenient(&vals[i]));
                }
                Some(Value::Object(m))
            }
        },
    }
}

/// msgType codes whose `content` may arrive as a JSON *text* holding
/// an object (the wire stores media content as an object; Desktop
/// serializes it back to a text column). Parsed into the object so
/// the payload matches the capture shape (H1/KQ1).
const MEDIA_CODES: &[i64] = &[2, 3, 4, 5, 6, 11, 12];

fn content_json(kind_code: i64, j: Value) -> Value {
    if MEDIA_CODES.contains(&kind_code) {
        if let Value::String(s) = &j {
            if let Ok(parsed) = serde_json::from_str::<Value>(s) {
                if parsed.is_object() || parsed.is_array() {
                    return parsed;
                }
            }
        }
    }
    j
}

fn field_res<'a>(ep: &'a EntityPlan, target: &str) -> Option<&'a FieldRes> {
    ep.fields.iter().find(|f| f.target == target).map(|f| &f.res)
}

fn string_field_opt(ep: &EntityPlan, vals: &[SV], target: &str, db_id: Option<u64>) -> Option<String> {
    match field_res(ep, target)? {
        FieldRes::Col(i) => sv_str(&vals[*i]),
        FieldRes::Const(v) => const_json(v, db_id).and_then(|j| match j {
            Value::String(s) => Some(s),
            Value::Number(n) => Some(n.to_string()),
            _ => None,
        }),
        FieldRes::Expr { expr: Expr::Str, of: FieldOfRes::Col(i) } => sv_str(&vals[*i]),
        FieldRes::Expr { expr: Expr::Int, of: FieldOfRes::Col(i) } => sv_i64(&vals[*i]).map(|n| n.to_string()),
        _ => None,
    }
}

fn string_field(ep: &EntityPlan, vals: &[SV], target: &str, db_id: Option<u64>) -> Option<String> {
    string_field_opt(ep, vals, target, db_id).filter(|s| !s.is_empty())
}

fn int_field_opt(ep: &EntityPlan, vals: &[SV], target: &str, db_id: Option<u64>) -> Option<i64> {
    match field_res(ep, target)? {
        FieldRes::Col(i) => sv_i64(&vals[*i]),
        FieldRes::Const(v) => const_json(v, db_id).and_then(|j| j.as_i64()),
        FieldRes::Expr { expr, of: FieldOfRes::Col(i) } => {
            let v = &vals[*i];
            match expr {
                Expr::Int => sv_i64(v),
                Expr::MsToMs | Expr::SToMs => sv_to_ms(v, *expr),
                _ => None,
            }
        }
        _ => None,
    }
}

fn bool_field(ep: &EntityPlan, vals: &[SV], target: &str, db_id: Option<u64>) -> Option<bool> {
    match field_res(ep, target)? {
        FieldRes::Col(i) => sv_bool(&vals[*i]),
        FieldRes::Const(v) => const_json(v, db_id).and_then(|j| j.as_bool()),
        _ => None,
    }
}

/// The `raw` JSON text: the mapped `raw` field when present, else the
/// default object of every column the mapping reads (blobs → null).
fn raw_field(ep: &EntityPlan, vals: &[SV], db_id: Option<u64>) -> String {
    if let Some(spec) = ep.fields.iter().find(|f| f.target == "raw") {
        if let Some(j) = field_json(ep, vals, spec, db_id) {
            return j.to_string();
        }
    }
    let mut m = serde_json::Map::new();
    for (i, name) in ep.select.iter().enumerate() {
        m.insert(name.clone(), sv_json_lenient(&vals[i]));
    }
    Value::Object(m).to_string()
}

// --- per-entity row transforms --------------------------------------------

/// One `msg`-table row → the same `Write::Message` the capture path
/// would produce for that message (source "import", is_group from the
/// DB kind). None = skip (counted by the caller).
fn message_row(
    ep: &EntityPlan,
    vals: &[SV],
    mtm: &BTreeMap<String, String>,
    kind: MapDb,
    db_id: Option<u64>,
    own_uid: Option<&str>,
) -> Option<Write> {
    // msgId (required, non-empty).
    let msg_id = string_field(ep, vals, "msgId", db_id)?;

    // ts (unit expr — plan guarantees it).
    let ts = match field_res(ep, "ts")? {
        FieldRes::Expr { expr, of: FieldOfRes::Col(i) } => sv_to_ms(&vals[*i], *expr)?,
        _ => return None,
    };

    let uid_from = string_field_opt(ep, vals, "uidFrom", db_id);
    let id_to = string_field_opt(ep, vals, "idTo", db_id);

    // Conversation derivation — normalize.rs's rules, kind-aware for
    // groups (conv = idTo; group ids are the plain digits).
    let conv_id = match kind {
        MapDb::Group => id_to.clone()?,
        _ => match (uid_from.as_deref(), id_to.as_deref()) {
            (Some(f), Some(_)) if f != "0" => f.to_string(),
            (Some("0"), Some(t)) => t.to_string(),
            (Some(f), None) => f.to_string(),
            (None, Some(t)) => t.to_string(),
            _ => return None,
        },
    };
    // Junk guard the capture side applies to conversation stubs
    // ("-1"/"0" are sentinels, never a conversation).
    if conv_id.is_empty() || conv_id == "0" || conv_id == "-1" {
        return None;
    }

    // Self-sent sender substitution — the ONE shared rule, reused
    // (batch 15 O4): `uidFrom == "0"` (or absent) + a configured own
    // uid becomes the sender, else NULL. The payload below keeps the
    // raw uidFrom ("0") exactly like the capture envelope.
    let sender_id = super::normalize::sender_for(uid_from.as_deref(), own_uid);

    // msgType: the configurable Desktop→web table, pass-through by
    // default; the mapped string is what lands in the payload.
    let desktop_mt = string_field_opt(ep, vals, "msgType", db_id);
    let mapped_mt = desktop_mt.map(|s| mtm.get(&s).cloned().unwrap_or(s));
    let kind_code = msg_type_code(mapped_mt.as_deref().unwrap_or(""));

    // Payload: every mapped target under its target name, with the
    // core fields normalized to the capture envelope semantics.
    let mut pay = serde_json::Map::new();
    for spec in &ep.fields {
        let j = field_json(ep, vals, spec, db_id)?;
        let j = match spec.target.as_str() {
            "msgId" => Value::String(msg_id.clone()),
            "ts" => Value::Number(ts.into()),
            "uidFrom" => match &uid_from {
                Some(f) => Value::String(f.clone()),
                None => Value::Null,
            },
            "idTo" => match &id_to {
                Some(t) => Value::String(t.clone()),
                None => Value::Null,
            },
            "msgType" => match &mapped_mt {
                Some(s) => Value::String(s.clone()),
                None => Value::Null,
            },
            "content" => content_json(kind_code, j),
            _ => j,
        };
        pay.insert(spec.target.clone(), j);
    }
    // Text: string content only (capture semantics — media objects
    // never become text), truncated like normalize.rs does. Read
    // BEFORE the payload string takes ownership of the map.
    let text = match pay.get("content") {
        Some(Value::String(s)) => Some(s.chars().take(8000).collect::<String>()),
        _ => None,
    };
    let payload = Value::Object(pay).to_string();

    Some(Write::Message {
        msg_id,
        conv_id,
        sender_id,
        ts,
        kind: kind_code,
        text,
        payload,
        source: "import",
        is_group: Some(kind == MapDb::Group),
    })
}

fn conversation_row(ep: &EntityPlan, vals: &[SV]) -> Option<Write> {
    let db_id = None; // $db_id cannot appear here (plan rejects it)
    let id = string_field(ep, vals, "id", db_id)?;
    let is_group = bool_field(ep, vals, "is_group", db_id)?;
    let title = string_field_opt(ep, vals, "title", db_id);
    let avatar_url = string_field_opt(ep, vals, "avatar_url", db_id);
    let last_msg_id = string_field_opt(ep, vals, "last_msg_id", db_id);
    let last_ts = int_field_opt(ep, vals, "last_ts", db_id);
    let raw = raw_field(ep, vals, db_id);
    Some(Write::Conversation {
        id,
        is_group,
        title,
        avatar_url,
        last_msg_id,
        last_ts,
        raw,
    })
}

fn contact_row(ep: &EntityPlan, vals: &[SV]) -> Option<Write> {
    let db_id = None;
    let user_id = string_field(ep, vals, "user_id", db_id)?;
    let display_name = string_field_opt(ep, vals, "display_name", db_id);
    let avatar_url = string_field_opt(ep, vals, "avatar_url", db_id);
    let raw = raw_field(ep, vals, db_id);
    Some(Write::Contact {
        user_id,
        display_name,
        avatar_url,
        raw,
    })
}

fn group_row(ep: &EntityPlan, vals: &[SV]) -> Option<Write> {
    let db_id = None;
    let group_id = string_field(ep, vals, "group_id", db_id)?;
    let name = string_field_opt(ep, vals, "name", db_id);
    let raw = raw_field(ep, vals, db_id);
    Some(Write::Group {
        group_id,
        name,
        raw,
    })
}

// --- dry-run classification (the writer's rules, read-only) --------------

/// What the writer would do with one extracted Write. See the module
/// docs for the exact semantics per entity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// No row with that key: the write would INSERT.
    New,
    /// A row exists and the write would touch at least one cell
    /// (messages: only NULL `text`/`sender_id` cells — import NEVER
    /// replaces capture/e2ee text, payload or type).
    FillNull,
    /// A row exists and nothing would change.
    Ignored,
    /// An import-sourced row exists whose payload would be replaced
    /// (rank 1 >= 1; a converging replay is `Ignored`).
    UpdateImport,
}

/// Per-entity dry-run counters (one line per entity in the report).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct EntityCounters {
    pub extracted: usize,
    pub new: usize,
    pub fill_null: usize,
    pub ignored: usize,
    pub update_import: usize,
    pub skipped: usize,
}

impl EntityCounters {
    pub fn bump(&mut self, v: Verdict) {
        match v {
            Verdict::New => self.new += 1,
            Verdict::FillNull => self.fill_null += 1,
            Verdict::Ignored => self.ignored += 1,
            Verdict::UpdateImport => self.update_import += 1,
        }
    }

    /// One shape-only report line.
    pub fn line(&self) -> String {
        format!(
            "extracted={} new={} fill_null={} ignored={} update_import={} skipped={}",
            self.extracted, self.new, self.fill_null, self.ignored, self.update_import, self.skipped
        )
    }
}

/// The stored message facts the classification needs.
#[derive(Debug, Clone)]
pub struct StoredMsg {
    pub source: String,
    pub text: Option<String>,
    pub sender_id: Option<String>,
    pub payload: String,
}

/// The stored conversation facts.
#[derive(Debug, Clone)]
pub struct StoredConv {
    pub is_group: bool,
    pub title: Option<String>,
    pub avatar_url: Option<String>,
    pub last_msg_id: Option<String>,
    pub last_ts: Option<i64>,
}

/// The stored contact facts.
#[derive(Debug, Clone)]
pub struct StoredContact {
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub raw_json: Option<String>,
}

/// The stored group facts.
#[derive(Debug, Clone)]
pub struct StoredGroup {
    pub name: Option<String>,
    pub raw_json: Option<String>,
}

/// Message verdict per the writer's ON CONFLICT (H4/T6): import ranks
/// below capture/e2ee, so for those rows only NULL `text`/`sender_id`
/// cells can change; an import row is fully replaceable.
pub fn classify_message(
    stored: Option<&StoredMsg>,
    inc_text: Option<&str>,
    inc_sender: Option<&str>,
    inc_payload: &str,
) -> Verdict {
    let Some(st) = stored else { return Verdict::New };
    let fill_text = st.text.is_none() && inc_text.is_some();
    let fill_sender = st.sender_id.is_none() && inc_sender.is_some();
    match st.source.as_str() {
        "capture" | "e2ee" => {
            if fill_text || fill_sender {
                Verdict::FillNull
            } else {
                Verdict::Ignored
            }
        }
        _ => {
            if st.payload == inc_payload {
                Verdict::Ignored
            } else {
                Verdict::UpdateImport
            }
        }
    }
}

/// Conversation verdict: the conversation upsert has NO rank guard —
/// `type`/`updated_at` always rewrite, and a non-NULL incoming
/// title/avatar REPLACES a differing stored one (COALESCE only
/// protects NULL cells). Any of those changes, or a forward move of
/// the last pointer, counts as a touch.
pub fn classify_conversation(
    stored: Option<&StoredConv>,
    is_group: bool,
    title: Option<&str>,
    avatar_url: Option<&str>,
    last_msg_id: Option<&str>,
    last_ts: Option<i64>,
) -> Verdict {
    let Some(st) = stored else { return Verdict::New };
    let fill = st.is_group != is_group
        || title.is_some_and(|t| st.title.as_deref() != Some(t))
        || avatar_url.is_some_and(|a| st.avatar_url.as_deref() != Some(a));
    let pointer = last_ts.is_some_and(|t| t >= st.last_ts.unwrap_or(0))
        && last_msg_id.is_some()
        && st.last_msg_id.as_deref() != last_msg_id;
    if fill || pointer {
        Verdict::FillNull
    } else {
        Verdict::Ignored
    }
}

/// Contact verdict: same writer shape — a non-NULL incoming
/// display_name/avatar replaces a differing stored one;
/// `raw_json`/`updated_at` always rewrite.
pub fn classify_contact(
    stored: Option<&StoredContact>,
    display_name: Option<&str>,
    avatar_url: Option<&str>,
    raw: &str,
) -> Verdict {
    let Some(st) = stored else { return Verdict::New };
    let fill = display_name.is_some_and(|d| st.display_name.as_deref() != Some(d))
        || avatar_url.is_some_and(|a| st.avatar_url.as_deref() != Some(a))
        || st.raw_json.as_deref() != Some(raw);
    if fill {
        Verdict::FillNull
    } else {
        Verdict::Ignored
    }
}

/// Group verdict: a non-NULL incoming name replaces a differing
/// stored one; `raw_json`/`updated_at` always rewrite.
pub fn classify_group(
    stored: Option<&StoredGroup>,
    name: Option<&str>,
    raw: &str,
) -> Verdict {
    let Some(st) = stored else { return Verdict::New };
    let fill = name.is_some_and(|n| st.name.as_deref() != Some(n))
        || st.raw_json.as_deref() != Some(raw);
    if fill {
        Verdict::FillNull
    } else {
        Verdict::Ignored
    }
}

/// Classify one extracted Write against the shadow DB `conn` (a
/// READ-ONLY copy — never the live store). Lookups only; no write.
pub fn classify_write(conn: &Connection, w: &Write) -> Result<Verdict, String> {
    match w {
        Write::Message {
            msg_id,
            text,
            sender_id,
            payload,
            ..
        } => {
            let stored: Option<StoredMsg> = conn
                .query_row(
                    "SELECT source, text, sender_id, payload_json FROM messages WHERE msg_id = ?1",
                    params![msg_id],
                    |r| {
                        Ok(StoredMsg {
                            source: r.get(0)?,
                            text: r.get(1)?,
                            sender_id: r.get(2)?,
                            payload: r.get(3)?,
                        })
                    },
                )
                .optional()
                .map_err(|e| format!("shadow lookup failed (messages): {e}"))?;
            Ok(classify_message(
                stored.as_ref(),
                text.as_deref(),
                sender_id.as_deref(),
                payload,
            ))
        }
        Write::Conversation {
            id,
            is_group,
            title,
            avatar_url,
            last_msg_id,
            last_ts,
            ..
        } => {
            let stored: Option<StoredConv> = conn
                .query_row(
                    "SELECT type, title, avatar_url, last_msg_id, last_ts \
                     FROM conversations WHERE id = ?1",
                    params![id],
                    |r| {
                        Ok(StoredConv {
                            is_group: r.get::<_, i64>(0)? == 1,
                            title: r.get(1)?,
                            avatar_url: r.get(2)?,
                            last_msg_id: r.get(3)?,
                            last_ts: r.get(4)?,
                        })
                    },
                )
                .optional()
                .map_err(|e| format!("shadow lookup failed (conversations): {e}"))?;
            Ok(classify_conversation(
                stored.as_ref(),
                *is_group,
                title.as_deref(),
                avatar_url.as_deref(),
                last_msg_id.as_deref(),
                *last_ts,
            ))
        }
        Write::Contact {
            user_id,
            display_name,
            avatar_url,
            raw,
        } => {
            let stored: Option<StoredContact> = conn
                .query_row(
                    "SELECT display_name, avatar_url, raw_json FROM contacts WHERE user_id = ?1",
                    params![user_id],
                    |r| {
                        Ok(StoredContact {
                            display_name: r.get(0)?,
                            avatar_url: r.get(1)?,
                            raw_json: r.get(2)?,
                        })
                    },
                )
                .optional()
                .map_err(|e| format!("shadow lookup failed (contacts): {e}"))?;
            Ok(classify_contact(
                stored.as_ref(),
                display_name.as_deref(),
                avatar_url.as_deref(),
                raw,
            ))
        }
        Write::Group { group_id, name, raw } => {
            let stored: Option<StoredGroup> = conn
                .query_row(
                    "SELECT name, raw_json FROM groups WHERE group_id = ?1",
                    params![group_id],
                    |r| {
                        Ok(StoredGroup {
                            name: r.get(0)?,
                            raw_json: r.get(1)?,
                        })
                    },
                )
                .optional()
                .map_err(|e| format!("shadow lookup failed (groups): {e}"))?;
            Ok(classify_group(stored.as_ref(), name.as_deref(), raw))
        }
        _ => Err("classify: import never produces this write kind".into()),
    }
}

// --- the shadow copy (2.4: classify against a COPY, never the live) ------

/// Copy a shadow STORE dir (`<dir>/default.db` + `-wal`/`-shm` +
/// `default.key`) into a fresh temp dir and open the COPY read-only
/// (`open_with_key_readonly`: `query_only` + busy_timeout). The
/// source dir is only ever READ as files — SQLite never opens it, so
/// the live store is never touched. The temp dir is left on disk for
/// inspection (the probe convention).
pub fn open_shadow_copy(store_dir: &Path) -> Result<(Connection, PathBuf), String> {
    let db = super::db_file(store_dir);
    let key = super::key_file(store_dir);
    if !db.is_file() {
        return Err(format!(
            "--shadow-copy: no {} — not a shadow store dir?",
            db.display()
        ));
    }
    // Batch 18 (R4): a passphrase-mode store refuses without its
    // remember file — the CLI never accepts passwords — so the copy
    // carries the mode files and opens in whichever mode the marker
    // says. A missing key file is only fatal in raw mode.
    if super::passphrase::read_mode(store_dir) == super::passphrase::StoreKeyMode::Raw
        && !key.is_file()
    {
        return Err(format!("--shadow-copy: no {} — broken store?", key.display()));
    }
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let tmp = std::env::temp_dir().join(format!(
        "zr-import-shadow-{}-{}-{}",
        std::process::id(),
        schema::now_ms(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).map_err(|e| format!("temp dir {}: {e}", tmp.display()))?;
    assert!(tmp.starts_with(std::env::temp_dir()), "the copy must live under the OS temp dir");
    assert_ne!(tmp, store_dir, "the copy must never be the store dir itself");
    for from in [
        db.clone(),
        db.with_file_name(format!(
            "{}-wal",
            db.file_name().unwrap().to_string_lossy()
        )),
        db.with_file_name(format!(
            "{}-shm",
            db.file_name().unwrap().to_string_lossy()
        )),
        key.clone(),
        super::keymode_file(store_dir),
        super::pass_dpapi_file(store_dir),
    ] {
        if !from.exists() {
            continue; // a checkpointed store has no sidecars
        }
        let to = tmp.join(from.file_name().unwrap());
        std::fs::copy(&from, &to).map_err(|e| format!("copying {}: {e}", from.display()))?;
        // A read-only attribute would block the temp -shm; clear it.
        let mut perm = std::fs::metadata(&to)
            .map_err(|e| format!("copying {}: {e}", from.display()))?
            .permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perm.set_readonly(false);
        std::fs::set_permissions(&to, perm)
            .map_err(|e| format!("copying {}: {e}", from.display()))?;
    }
    match super::passphrase::open_store(&tmp, true) {
        Ok((conn, _)) => Ok((conn, tmp)),
        Err(super::passphrase::StoreOpenError::Locked) => Err(
            "the shadow store is password-protected (passphrase mode): unlock it in the app with \
             'Nhớ trên máy này' (remember on this machine) enabled, then re-run — the CLI never \
             accepts passwords"
                .into(),
        ),
        Err(super::passphrase::StoreOpenError::Other(k)) => {
            Err(format!("--shadow-copy: open failed ({k})"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrate::sqlcipher;
    use serde_json::json;

    /// A synthetic, encrypted in-memory DB — never a real one.
    fn mem() -> Connection {
        let key = sqlcipher::generate_key().unwrap();
        let conn = sqlcipher::open_in_memory(&key).unwrap();
        conn
    }

    /// The fake Desktop-like schema the brief suggests, plus the
    /// account-wide tables, seeded with a few FAKE rows.
    fn desktop_like() -> Connection {
        let conn = mem();
        conn.execute_batch(
            "CREATE TABLE msg (
               id INTEGER PRIMARY KEY, cliId TEXT, fromUid TEXT, toUid TEXT,
               ts INTEGER, type TEXT, content TEXT
             );
             INSERT INTO msg (id, cliId, fromUid, toUid, ts, type, content) VALUES
               (101, 'c101', 'u1', 'u2', 1690000000, 'chat.text.v2', 'hello there'),
               (102, 'c102', 'u2', 'u1', 1690000001, 'chat.photo',
                 '{\"href\":\"https://fake-photo-stal.zdn.vn/x.jpg\",\"thumb\":\"https://fake/t.jpg\"}'),
               (103, 'c103', '0',   'u9', 1690000002, 'webchat', 'self sent'),
               (104, 'c104', 'u1', 'g77', 1690000003, 'chat.text.v2', 'group hello');
             CREATE TABLE conv (id INTEGER PRIMARY KEY, name TEXT, avatar TEXT);
             INSERT INTO conv (id, name, avatar) VALUES (11, 'Alice', 'https://fake/av1');
             CREATE TABLE contact (uid TEXT PRIMARY KEY, dname TEXT, avatar TEXT);
             INSERT INTO contact (uid, dname, avatar) VALUES ('u1', 'Bob', 'https://fake/av2');
             CREATE TABLE grp (gid TEXT PRIMARY KEY, gname TEXT);
             INSERT INTO grp (gid, gname) VALUES ('g77', 'Team');
             CREATE TABLE media (msgId TEXT, path TEXT);",
        )
        .unwrap();
        conn
    }

    /// The message-DB and index-DB inventories wrapped for `plan`.
    fn inventories(msg_conn: &Connection, index_conn: &Connection) -> SnapshotInventories {
        SnapshotInventories {
            index: Some(KindInventory {
                source_rel: "Core/Index.db".into(),
                inventory: super::super::import::inventory::inventory_db(index_conn).unwrap(),
            }),
            one_to_one: Some(KindInventory {
                source_rel: "Core/Message/123.db".into(),
                inventory: super::super::import::inventory::inventory_db(msg_conn).unwrap(),
            }),
            group: Some(KindInventory {
                source_rel: "Core/Message/g456.db".into(),
                inventory: super::super::import::inventory::inventory_db(msg_conn).unwrap(),
            }),
            stranger_box: Some(KindInventory {
                source_rel: "Core/Message/stranger_box.db".into(),
                inventory: super::super::import::inventory::inventory_db(msg_conn).unwrap(),
            }),
        }
    }

    /// The full mapping for the fake schema (message db as an ARRAY of
    /// kinds, the index entities as single strings — both parse
    /// paths covered).
    const MAPPING_JSON: &str = r#"{
      "msgType": { "chat.text.v2": "webchat" },
      "entities": {
        "message": {
          "db": ["one2one", "group"],
          "table": "msg",
          "columns": {
            "msgId": "id",
            "uidFrom": "fromUid",
            "idTo": "toUid",
            "ts": { "expr": "s_to_ms", "of": "ts" },
            "msgType": "type",
            "content": "content",
            "cliMsgId": "cliId"
          }
        },
        "conversation": {
          "db": "index",
          "table": "conv",
          "columns": {
            "id": "id",
            "is_group": { "const": false },
            "title": "name",
            "avatar_url": "avatar",
            "raw": { "expr": "json_object_of", "of": ["id", "name"] }
          }
        },
        "contact": {
          "db": "index",
          "table": "contact",
          "columns": {
            "user_id": "uid",
            "display_name": "dname",
            "avatar_url": "avatar",
            "raw": { "expr": "json_object_of", "of": ["uid", "dname"] }
          }
        },
        "group": {
          "db": "index",
          "table": "grp",
          "columns": {
            "group_id": "gid",
            "name": "gname"
          }
        }
      }
    }"#;

    #[test]
    fn skeleton_maps_nothing_and_serializes() {
        let m = Mapping::skeleton();
        assert!(m.entities.is_empty());
        assert!(m.msg_type.is_empty());
        let j = skeleton_json();
        let back: Value = serde_json::from_str(&j).unwrap();
        assert_eq!(back, json!({"msgType": {}, "entities": {}}));
        let parsed = parse_mapping(j.as_bytes()).unwrap();
        assert_eq!(parsed, m);
    }

    #[test]
    fn parse_mapping_accepts_a_notes_object_and_ignores_it() {
        // Batch 13: the brief's uncertainty notes ride along in a
        // top-level "_notes" object. Parsing accepts it and drops it —
        // a mapping without the notes parses to the exact same Mapping.
        let doc = r#"{
          "_notes": { "entities.message.columns.ts": "unit guessed, pending batch 14" },
          "msgType": {},
          "entities": {
            "group": { "db": "index", "table": "grp", "columns": { "group_id": "gid" } }
          }
        }"#;
        let m = parse_mapping(doc.as_bytes()).unwrap();
        assert_eq!(m.entities.len(), 1);
        let same = parse_mapping(
            br#"{"msgType": {},"entities": {"group": {"db": "index", "table": "grp", "columns": {"group_id": "gid"}}}}"#,
        )
        .unwrap();
        assert_eq!(m, same, "_notes must not change the parsed mapping");
    }

    #[test]
    fn parse_mapping_rejects_a_malformed_notes_object() {
        for bad in [r#"{"_notes": []}"#, r#"{"_notes": "text"}"#, r#"{"_notes": 1}"#] {
            let e = parse_mapping(bad.as_bytes()).unwrap_err();
            assert!(e.contains("\"_notes\" must be an object"), "{bad} -> {e}");
        }
        // Unknown keys are still refused, with _notes listed as allowed.
        let e = parse_mapping(br#"{"sql":"SELECT 1"}"#).unwrap_err();
        assert!(
            e.contains("unknown key \"sql\" (allowed: \"msgType\", \"entities\", \"_notes\")"),
            "{e}"
        );
    }

    #[test]
    fn parse_full_mapping_both_db_forms() {
        let m = parse_mapping(MAPPING_JSON.as_bytes()).unwrap();
        assert_eq!(m.msg_type["chat.text.v2"], "webchat");
        assert_eq!(m.entities.len(), 4);
        let msg = &m.entities["message"];
        assert_eq!(msg.db, vec![MapDb::OneToOne, MapDb::Group]);
        assert_eq!(msg.table, "msg");
        assert_eq!(msg.columns["msgId"], FieldCfg::Col("id".into()));
        assert_eq!(
            msg.columns["ts"],
            FieldCfg::Expr {
                expr: Expr::SToMs,
                of: FieldOf::Col("ts".into())
            }
        );
        let conv = &m.entities["conversation"];
        assert_eq!(conv.db, vec![MapDb::Index]);
        assert_eq!(conv.columns["is_group"], FieldCfg::Const(json!(false)));
    }

    #[test]
    fn parse_rejects_every_wrong_shape_with_exact_errors() {
        for (doc, needle, why) in [
            ("[]", "top level must be a JSON object", "not an object"),
            (
                r#"{"sql":"SELECT 1"}"#,
                "unknown key \"sql\" (allowed: \"msgType\", \"entities\", \"_notes\")",
                "free SQL has no place in a mapping",
            ),
            (
                r#"{"msgType": []}"#,
                "\"msgType\" must be an object",
                "msgType not an object",
            ),
            (
                r#"{"msgType": {"a": 1}}"#,
                "msgType.\"a\" must be a string",
                "msgType value not a string",
            ),
            (
                r#"{"entities": {"conv": {}}}"#,
                "unknown entity \"conv\" (allowed: conversation, contact, group, message, attachment)",
                "unknown entity",
            ),
            (
                r#"{"entities": {"message": {"db":"idx","table":"t","columns":{}}}}"#,
                "unknown db kind \"idx\" (allowed: index, one2one, group, stranger)",
                "bad db kind",
            ),
            (
                r#"{"entities": {"message": {"db":["one2one"],"table":"","columns":{}}}}"#,
                "missing required key \"table\"",
                "empty table",
            ),
            (
                r#"{"entities": {"message": {"db":"one2one","table":"t","cols":{}}}}"#,
                "unknown key \"cols\" (allowed: \"db\", \"table\", \"columns\")",
                "unknown entity key",
            ),
            (
                r#"{"entities": {"message": {"table":"t","columns":{}}}}"#,
                "missing required key \"db\" (index/one2one/group/stranger)",
                "missing db",
            ),
            (
                r#"{"entities": {"message": {"db":"one2one","table":"t","columns":{"x":1}}}}"#,
                "must be a source column string, {\"const\": …} or {\"expr\": …, \"of\": …}",
                "bad column value type",
            ),
            (
                r#"{"entities": {"message": {"db":"one2one","table":"t","columns":{"x":{"const":null}}}}}"#,
                "\"const\" must be a scalar",
                "null const",
            ),
            (
                r#"{"entities": {"message": {"db":"one2one","table":"t","columns":{"ts":{"expr":"seconds","of":"ts"}}}}}"#,
                "unknown expr \"seconds\" (whitelist: ms_to_ms, s_to_ms, string, int, json_object_of)",
                "unknown expr",
            ),
            (
                r#"{"entities": {"message": {"db":"one2one","table":"t","columns":{"ts":{"expr":"s_to_ms"}}}}}"#,
                "an expr needs exactly the two keys \"expr\" and \"of\"",
                "expr without of",
            ),
            (
                r#"{"entities": {"message": {"db":"one2one","table":"t","columns":{"x":{"expr":"json_object_of","of":"ts"}}}}}"#,
                "json_object_of takes {\"of\": [\"col\", …]} (a non-empty array)",
                "json_object_of with a string of",
            ),
            (
                r#"{"entities": {"message": {"db":"one2one","table":"t","columns":{"x":{"expr":"string","of":[]}}}}}"#,
                "expr \"string\" takes {\"of\": \"<column>\"}",
                "string expr with an array of",
            ),
            (
                r#"{"entities": {"message": {"db":"one2one","table":"t","columns":{"x":""}}}}"#,
                "a plain string must be a non-empty source column name",
                "empty column string",
            ),
            (
                "not json",
                "mapping is not valid JSON",
                "garbage bytes",
            ),
        ] {
            let e = parse_mapping(doc.as_bytes()).unwrap_err();
            assert!(e.contains(needle), "{why}: got {e}");
        }
    }

    #[test]
    fn plan_accepts_the_full_mapping() {
        let msg_conn = desktop_like();
        let idx_conn = desktop_like();
        let inv = inventories(&msg_conn, &idx_conn);
        let m = parse_mapping(MAPPING_JSON.as_bytes()).unwrap();
        let p = plan(&m, &inv).unwrap();
        assert!(p.conversation.is_some());
        assert!(p.contact.is_some());
        assert!(p.group.is_some());
        assert!(p.message.is_some());
        assert!(p.attachment.is_none());
        let msg = p.message.as_ref().unwrap();
        assert_eq!(msg.table, "msg");
        // The SELECT list is every referenced column, deduped, in the
        // sorted target-field order (the config is stored as a map).
        assert_eq!(
            msg.select,
            vec!["cliId", "content", "toUid", "id", "type", "ts", "fromUid"]
        );
        // The summary line is shape-only.
        let line = p.summary_line();
        assert!(line.contains("msgType entries=1"), "{line}");
        assert!(line.contains("message[one2one+group]table=msg"), "{line}");
    }

    #[test]
    fn plan_lists_exactly_what_is_missing() {
        let msg_conn = desktop_like();
        let idx_conn = desktop_like();
        let inv = inventories(&msg_conn, &idx_conn);

        // 1. Missing table in the one2one sample (and the group sample
        //    reports it too — every mapped kind is checked).
        let m: Mapping = parse_mapping(
            br#"{"entities": {"message": {
                  "db": ["one2one", "group"], "table": "nope",
                  "columns": {"msgId": "id", "ts": {"expr": "s_to_ms", "of": "ts"},
                              "uidFrom": "fromUid"}}}}"#,
        )
        .unwrap();
        let errs = plan(&m, &inv).unwrap_err();
        assert_eq!(errs.len(), 2, "{errs:?}");
        assert!(
            errs.iter().all(|e| e.contains("table \"nope\" does not exist in Core/Message/")),
            "{errs:?}"
        );

        // 2. Missing column, named exactly.
        let m: Mapping = parse_mapping(
            br#"{"entities": {"message": {
                  "db": "one2one", "table": "msg",
                  "columns": {"msgId": "nope", "uidFrom": "fromUid",
                              "ts": {"expr": "s_to_ms", "of": "ts"}}}}}"#,
        )
        .unwrap();
        let errs = plan(&m, &inv).unwrap_err();
        assert_eq!(errs.len(), 1, "{errs:?}");
        assert!(
            errs[0].contains("columns.msgId: column \"nope\" does not exist in table \"msg\""),
            "{}",
            errs[0]
        );

        // 3. Required fields + ts unit + uidFrom/idTo, all reported at once.
        let m: Mapping = parse_mapping(
            br#"{"entities": {"message": {
                  "db": "one2one", "table": "msg",
                  "columns": {"ts": "ts", "content": "content"}}}}"#,
        )
        .unwrap();
        let errs = plan(&m, &inv).unwrap_err();
        let joined = errs.join("\n");
        assert!(joined.contains("missing required target field 'msgId'"), "{joined}");
        assert!(joined.contains("must declare the source unit"), "{joined}");
        assert!(joined.contains("needs 'uidFrom' or 'idTo'"), "{joined}");

        // 4. Unknown target fields / derived fields / bad kinds / $db_id.
        let m: Mapping = parse_mapping(
            br#"{"entities": {
                  "conversation": {"db": "index", "table": "conv", "columns": {
                      "id": "id", "nope": "name"}},
                  "message": {"db": ["index", "stranger"], "table": "msg", "columns": {
                      "msgId": "id", "conv_id": "toUid",
                      "ts": {"expr": "ms_to_ms", "of": "ts"},
                      "idTo": {"const": "$db_id"}}}}}"#,
        )
        .unwrap();
        let errs = plan(&m, &inv).unwrap_err();
        let joined = errs.join("\n");
        assert!(joined.contains("columns.nope: unknown target field (allowed: id, is_group, title"), "{joined}");
        assert!(joined.contains("missing required target field 'is_group'"), "{joined}");
        // message with db [index, stranger]: index is not a message kind…
        assert!(joined.contains("kind \"index\" is not valid for a entities.message mapping"), "{joined}");
        // …$db_id with stranger in the mix is refused…
        assert!(joined.contains("{\"const\":\"$db_id\"} needs a one2one/group message DB"), "{joined}");
        // …and conv_id is derived.
        assert!(joined.contains("'conv_id' is DERIVED by the extractor"), "{joined}");

        // 5. A kind with no sample in the snapshot.
        let mut inv2 = inv.clone();
        inv2.group = None;
        let m: Mapping = parse_mapping(
            br#"{"entities": {"message": {
                  "db": "group", "table": "msg",
                  "columns": {"msgId": "id", "idTo": "toUid",
                              "ts": {"expr": "s_to_ms", "of": "ts"}}}}}"#,
        )
        .unwrap();
        let errs = plan(&m, &inv2).unwrap_err();
        assert!(
            errs.iter().any(|e| e.contains("no group sample to validate against")),
            "{errs:?}"
        );
    }

    #[test]
    fn extract_message_rows_match_the_capture_write_shape() {
        let conn = desktop_like();
        let inv = inventories(&conn, &conn);
        let m = parse_mapping(MAPPING_JSON.as_bytes()).unwrap();
        let p = plan(&m, &inv).unwrap();
        let opts = ExtractOpts {
            kind: MapDb::OneToOne,
            db_id: Some(123),
            cursor: None,
            own_uid: None,
        };
        let (writes, skips) = extract(&conn, &p, &opts).unwrap();
        assert_eq!(skips.message, 0);
        assert_eq!(writes.len(), 4, "the whole table is the conversation");

        // Row 101: plain text, s_to_ms, msgType table chat.text.v2 -> webchat.
        let Write::Message {
            msg_id,
            conv_id,
            sender_id,
            ts,
            kind,
            text,
            payload,
            source,
            is_group,
        } = &writes[0]
        else {
            panic!();
        };
        assert_eq!(msg_id, "101");
        assert_eq!(conv_id, "u1", "incoming 1-1: conv = uidFrom (capture rule)");
        assert_eq!(sender_id.as_deref(), Some("u1"));
        assert_eq!(*ts, 1_690_000_000_000, "s_to_ms");
        assert_eq!(*kind, 1, "webchat -> code 1");
        assert_eq!(text.as_deref(), Some("hello there"));
        assert_eq!(*source, "import");
        assert_eq!(*is_group, Some(false));
        // The payload is the capture envelope shape, sorted keys, with
        // the MAPPED msgType and normalized ms ts.
        let pay: Value = serde_json::from_str(payload).unwrap();
        assert_eq!(
            pay,
            json!({
                "cliMsgId": "c101",
                "content": "hello there",
                "idTo": "u2",
                "msgId": "101",
                "msgType": "webchat",
                "ts": 1690000000000i64,
                "uidFrom": "u1"
            })
        );

        // Row 102: chat.photo content arrives as JSON TEXT and becomes
        // the parsed OBJECT (the wire shape), so no text.
        let Write::Message {
            msg_id, kind, text, payload, ..
        } = &writes[1]
        else {
            panic!();
        };
        assert_eq!(msg_id, "102");
        assert_eq!(*kind, 2, "chat.photo -> code 2 (pass-through msgType)");
        assert!(text.is_none(), "media content is not text");
        let pay: Value = serde_json::from_str(payload).unwrap();
        assert_eq!(
            pay["content"],
            json!({"href": "https://fake-photo-stal.zdn.vn/x.jpg",
                    "thumb": "https://fake/t.jpg"}),
            "the JSON-text content is embedded as the object"
        );

        // Row 103: uidFrom "0" (self-sent) -> conv = idTo, sender None.
        let Write::Message { conv_id, sender_id, .. } = &writes[2] else { panic!() };
        assert_eq!(conv_id, "u9");
        assert_eq!(sender_id, &None, "no own-uid substitution for import");

        // Row 104 stays a normal row in a one2one-shaped DB: conv = uidFrom.
        let Write::Message { conv_id, .. } = &writes[3] else { panic!() };
        assert_eq!(conv_id, "u1");
    }

    #[test]
    fn extract_substitutes_own_uid_on_self_sent_rows() {
        // Batch 15 O4 (KQ2 applied to the import path): with an own
        // uid configured, self-sent rows get a sender through the SAME
        // `normalize::sender_for` rule the capture path applies; the
        // payload keeps the raw uidFrom ("0"), exactly like the
        // capture envelope. Without one the sender stays NULL.
        const FAKE_UID: &str = "1234567890123456789";
        let conn = desktop_like();
        // Row 106: uidFrom NULL — the shared rule treats an absent
        // uidFrom as self-sent too (no fork of the rule).
        conn.execute_batch(
            "INSERT INTO msg (id, cliId, fromUid, toUid, ts, type, content) VALUES
               (106, 'c106', NULL, 'u9', 1690000004, 'webchat', 'x');",
        )
        .unwrap();
        let inv = inventories(&conn, &conn);
        let m = parse_mapping(MAPPING_JSON.as_bytes()).unwrap();
        let p = plan(&m, &inv).unwrap();

        let sender_of = |writes: &[Write], id: &str| {
            writes
                .iter()
                .find_map(|w| match w {
                    Write::Message { msg_id, sender_id, .. } if msg_id == id => {
                        Some(sender_id.clone())
                    }
                    _ => None,
                })
                .unwrap()
        };

        let (writes, _) = extract(
            &conn,
            &p,
            &ExtractOpts {
                kind: MapDb::OneToOne,
                db_id: Some(123),
                cursor: None,
                own_uid: Some(FAKE_UID),
            },
        )
        .unwrap();
        // Row 103 (uidFrom "0"): the own uid, never "0"/NULL.
        assert_eq!(sender_of(&writes, "103").as_deref(), Some(FAKE_UID));
        // Row 106 (uidFrom absent): the shared rule substitutes too.
        assert_eq!(sender_of(&writes, "106").as_deref(), Some(FAKE_UID));
        // A peer row is untouched by the substitution.
        assert_eq!(sender_of(&writes, "101").as_deref(), Some("u1"));
        // The payload keeps the RAW uidFrom ("0") — capture shape.
        let payload103 = writes
            .iter()
            .find_map(|w| match w {
                Write::Message { msg_id, payload, .. } if msg_id == "103" => Some(payload.clone()),
                _ => None,
            })
            .unwrap();
        let pay: Value = serde_json::from_str(&payload103).unwrap();
        assert_eq!(pay["uidFrom"], json!("0"), "the payload keeps the raw uidFrom");
        // Sender NULL still — the sender_id field, not the payload.
        let (writes, _) = extract(
            &conn,
            &p,
            &ExtractOpts {
                kind: MapDb::OneToOne,
                db_id: Some(123),
                cursor: None,
                own_uid: None,
            },
        )
        .unwrap();
        assert_eq!(sender_of(&writes, "103"), None, "no own uid: stays NULL");
    }

    #[test]
    fn extract_msg_codes_reads_only_msgid_and_msgtype() {
        // Batch 15 O1: the minimal extractor pairs (msgId, raw
        // Desktop msgType) per row and skips NULL/BLOB values,
        // counted. The four FAKE rows of desktop_like pair cleanly.
        let conn = desktop_like();
        let inv = inventories(&conn, &conn);
        let m = parse_mapping(MAPPING_JSON.as_bytes()).unwrap();
        let p = plan(&m, &inv).unwrap();
        let ep = p.message.as_ref().unwrap();
        let (pairs, skipped) = extract_msg_codes(&conn, ep).unwrap();
        assert_eq!(skipped, 0);
        assert_eq!(
            pairs,
            vec![
                ("101".to_string(), "chat.text.v2".to_string()),
                ("102".to_string(), "chat.photo".to_string()),
                ("103".to_string(), "webchat".to_string()),
                ("104".to_string(), "chat.text.v2".to_string()),
            ]
        );
        // Rows with a NULL/BLOB msgType never join: they are skipped
        // and counted, never guessed into the tab. (A NULL msgId is
        // impossible in this fixture — `id INTEGER PRIMARY KEY`
        // auto-assigns — so that case is covered by the probe's
        // synthetic end-to-end test, whose msgId is a TEXT pk.)
        conn.execute_batch(
            "INSERT INTO msg (id, fromUid, toUid, ts, type, content) VALUES
               (107, 'u1', 'u2', 1, NULL, 'x'),
               (108, 'u1', 'u2', 1, x'00', 'x');",
        )
        .unwrap();
        let (pairs, skipped) = extract_msg_codes(&conn, ep).unwrap();
        assert_eq!(skipped, 2, "NULL msgType + BLOB msgType");
        assert_eq!(pairs.len(), 4, "only the complete rows pair");
    }

    #[test]
    fn extract_msg_codes_refuses_non_plain_or_missing_targets() {
        let conn = desktop_like();
        let inv = inventories(&conn, &conn);
        // A const msgType is a mapping product, not the raw code.
        let doc = MAPPING_JSON.replace("\"msgType\": \"type\",", "\"msgType\": {\"const\": \"webchat\"},");
        let m = parse_mapping(doc.as_bytes()).unwrap();
        let p = plan(&m, &inv).unwrap();
        let e = extract_msg_codes(&conn, p.message.as_ref().unwrap()).unwrap_err();
        assert!(
            e.contains("entities.message.columns.msgType must map a PLAIN source column"),
            "{e}"
        );
        // No msgType target at all.
        let doc = MAPPING_JSON.replace("            \"msgType\": \"type\",\n", "");
        let m = parse_mapping(doc.as_bytes()).unwrap();
        let p = plan(&m, &inv).unwrap();
        let e = extract_msg_codes(&conn, p.message.as_ref().unwrap()).unwrap_err();
        assert!(e.contains("has no 'msgType' target"), "{e}");
    }

    #[test]
    fn extract_group_kind_uses_idto_and_db_id_const() {
        let conn = desktop_like();
        let inv = inventories(&conn, &conn);
        // Same mapping, but idTo is the DB file's id ($db_id) — the
        // g<id>.db case where the group id IS the file digits.
        let doc = MAPPING_JSON.replace(
            "\"idTo\": \"toUid\",",
            "\"idTo\": {\"const\": \"$db_id\"},",
        );
        let m = parse_mapping(doc.as_bytes()).unwrap();
        let p = plan(&m, &inv).unwrap();
        let opts = ExtractOpts {
            kind: MapDb::Group,
            db_id: Some(77),
            cursor: None,
            own_uid: None,
        };
        let (writes, skips) = extract(&conn, &p, &opts).unwrap();
        assert_eq!(skips.message, 0);
        // Group kind: conv = idTo = the db_id const; is_group true.
        let Write::Message { conv_id, is_group, payload, .. } = &writes[0] else { panic!() };
        assert_eq!(conv_id, "77");
        assert_eq!(*is_group, Some(true));
        let pay: Value = serde_json::from_str(payload).unwrap();
        assert_eq!(pay["idTo"], json!("77"));
        // Every row of the DB maps with the same conv (a g<id>.db IS
        // one conversation).
        assert!(writes.iter().all(|w| matches!(w,
            Write::Message { conv_id, is_group: Some(true), .. }
                if conv_id == "77")));
    }

    #[test]
    fn extract_index_entities_and_raw_defaults() {
        let conn = desktop_like();
        let inv = inventories(&conn, &conn);
        let m = parse_mapping(MAPPING_JSON.as_bytes()).unwrap();
        let p = plan(&m, &inv).unwrap();
        let opts = ExtractOpts {
            kind: MapDb::Index,
            db_id: None,
            cursor: None,
            own_uid: None,
        };
        let (writes, skips) = extract(&conn, &p, &opts).unwrap();
        assert_eq!((skips.conversation, skips.contact, skips.group), (0, 0, 0));
        assert_eq!(writes.len(), 3, "1 conversation + 1 contact + 1 group");
        let conv = writes.iter().find_map(|w| match w {
            Write::Conversation { id, raw, .. } => Some((id.clone(), raw.clone())),
            _ => None,
        });
        let Some((id, raw)) = conv else { panic!("no conversation write") };
        assert_eq!(id, "11");
        assert_eq!(
            serde_json::from_str::<Value>(&raw).unwrap(),
            json!({"id": 11, "name": "Alice"}),
            "the mapped json_object_of raw"
        );
        // group entity has NO raw mapping -> default raw = every
        // column the mapping reads.
        let grp = writes.iter().find_map(|w| match w {
            Write::Group { group_id, name, raw } => Some((group_id.clone(), name.clone(), raw.clone())),
            _ => None,
        });
        let Some((gid, name, raw)) = grp else { panic!("no group write") };
        assert_eq!(gid, "g77");
        assert_eq!(name.as_deref(), Some("Team"));
        assert_eq!(
            serde_json::from_str::<Value>(&raw).unwrap(),
            json!({"gid": "g77", "gname": "Team"}),
            "raw defaults to the object of every read column"
        );
    }

    #[test]
    fn extract_skips_bad_rows_and_counts_them() {
        let conn = desktop_like();
        conn.execute_batch(
            "INSERT INTO msg (id, fromUid, toUid, ts, type, content) VALUES
               (105, 'u1', 'u2', 'not-a-number', 'webchat', 'x'),
               (106, NULL, NULL, 1690000000, 'webchat', 'x'),
               (107, 'u1', 'u2', NULL, 'webchat', 'x');",
        )
        .unwrap();
        let inv = inventories(&conn, &conn);
        let m = parse_mapping(MAPPING_JSON.as_bytes()).unwrap();
        let p = plan(&m, &inv).unwrap();
        let opts = ExtractOpts {
            kind: MapDb::OneToOne,
            db_id: Some(1),
            cursor: None,
            own_uid: None,
        };
        let (writes, skips) = extract(&conn, &p, &opts).unwrap();
        assert_eq!(skips.message, 3, "unparsable ts, no conv source, NULL ts");
        assert_eq!(writes.len(), 4, "the four good rows still extract");
    }

    #[test]
    fn extract_delta_skips_rows_at_or_before_the_cursor() {
        let conn = desktop_like();
        // rowids 1..4 carry ts 100..400; cursor (300, 2) keeps only
        // rows with rowid > 2 OR ts > 300.
        conn.execute_batch(
            "DELETE FROM msg;
             INSERT INTO msg (id, fromUid, toUid, ts, type, content) VALUES
               (1, 'a', 'b', 100, 'webchat', 'x'),
               (2, 'a', 'b', 200, 'webchat', 'x'),
               (3, 'a', 'b', 300, 'webchat', 'x'),
               (4, 'a', 'b', 400, 'webchat', 'x'),
               (5, 'a', 'b', 350, 'webchat', 'x');",
        )
        .unwrap();
        let inv = inventories(&conn, &conn);
        let m = parse_mapping(MAPPING_JSON.as_bytes()).unwrap();
        let p = plan(&m, &inv).unwrap();
        let opts = ExtractOpts {
            kind: MapDb::OneToOne,
            db_id: Some(1),
            cursor: Some(ImportCursor { max_ts: 300, max_rowid: 2 }),
            own_uid: None,
        };
        let (writes, _) = extract(&conn, &p, &opts).unwrap();
        // Include iff rowid > 2 OR raw ts > 300: row 3 (rowid 3) is
        // included by rowid even though its ts equals the watermark;
        // rows 4 (400) and 5 (rowid 5) by both. Only rows 1 and 2
        // are skipped. (The cursor's max_ts is in the RAW column
        // domain — the s_to_ms normalization happens afterwards.)
        let ids: Vec<String> = writes
            .iter()
            .filter_map(|w| match w {
                Write::Message { msg_id, .. } => Some(msg_id.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(ids, vec!["3", "4", "5"], "rowid>2 OR raw ts>300");
        // The cursor an apply pass would write is the raw max pair.
        let nc = next_cursor(&conn, p.message.as_ref().unwrap()).unwrap();
        assert_eq!(nc, Some(ImportCursor { max_ts: 400, max_rowid: 5 }));
    }

    #[test]
    fn cursors_round_trip_in_sync_cursors() {
        // Pure encode/decode.
        let c = ImportCursor { max_ts: 1_690_000_000_000, max_rowid: 4242 };
        assert_eq!(decode_cursor(&encode_cursor(c)).unwrap(), c);
        assert_eq!(import_scope("Core/Message/123.db"), "import:Core/Message/123.db");
        assert!(decode_cursor("nope").is_none());
        assert!(decode_cursor("1:2:3").is_none());
        assert!(decode_cursor("x:2").is_none());
        assert!(decode_cursor(":2").is_none());

        // On a real sync_cursors table (in-memory shadow DB).
        let key = sqlcipher::generate_key().unwrap();
        let conn = sqlcipher::open_in_memory(&key).unwrap();
        super::super::schema::apply(&conn).unwrap();
        assert_eq!(read_import_cursor(&conn, "Core/Message/123.db").unwrap(), None);
        write_import_cursor(&conn, "Core/Message/123.db", c).unwrap();
        assert_eq!(read_import_cursor(&conn, "Core/Message/123.db").unwrap(), Some(c));
        // The scope string is exactly the documented form.
        let scope: String = conn
            .query_row(
                "SELECT scope FROM sync_cursors WHERE cursor = ?1",
                params![encode_cursor(c)],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(scope, "import:Core/Message/123.db");
        // A second DB keeps its own row; an update replaces.
        write_import_cursor(&conn, "Core/Message/g456.db", c).unwrap();
        let n: i64 = conn
            .query_row("SELECT count(*) FROM sync_cursors", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 2);
        let c2 = ImportCursor { max_ts: 5, max_rowid: 6 };
        write_import_cursor(&conn, "Core/Message/123.db", c2).unwrap();
        assert_eq!(read_import_cursor(&conn, "Core/Message/123.db").unwrap(), Some(c2));

        // A corrupt cursor fails closed instead of silently resetting.
        conn.execute(
            "UPDATE sync_cursors SET cursor = 'garbage' WHERE scope = ?1",
            params![import_scope("Core/Message/123.db")],
        )
        .unwrap();
        let e = read_import_cursor(&conn, "Core/Message/123.db").unwrap_err();
        assert!(e.contains("corrupt"), "{e}");
    }

    // --- classification --------------------------------------------------

    /// A capture/e2ee row the import must never touch.
    fn stored(source: &str, text: Option<&str>, sender: Option<&str>, payload: &str) -> StoredMsg {
        StoredMsg {
            source: source.into(),
            text: text.map(str::to_string),
            sender_id: sender.map(str::to_string),
            payload: payload.into(),
        }
    }

    #[test]
    fn classify_message_import_never_overwrites_capture_text() {
        let cap = stored("capture", Some("cap-text"), Some("u1"), r#"{"msgId":"m1"}"#);
        // Import arrives with DIFFERENT text/payload: ignored.
        assert_eq!(
            classify_message(Some(&cap), Some("imp-text"), Some("u2"), r#"{"msgId":"m1","imp":1}"#),
            Verdict::Ignored,
            "capture/e2ee rows are never replaced by import"
        );
        // Same values: still ignored (nothing to do).
        assert_eq!(
            classify_message(Some(&cap), Some("cap-text"), Some("u1"), r#"{"msgId":"m1"}"#),
            Verdict::Ignored
        );
        // NULL text cell + import has text: fill.
        let cap_null = stored("capture", None, Some("u1"), r#"{"msgId":"m1","e2ee":"k"}"#);
        assert_eq!(
            classify_message(Some(&cap_null), Some("imp-text"), None, r#"{"msgId":"m1"}"#),
            Verdict::FillNull
        );
        // NULL sender + import has one: fill.
        let cap_nosender = stored("e2ee", Some("plain"), None, r#"{"msgId":"m1"}"#);
        assert_eq!(
            classify_message(Some(&cap_nosender), None, Some("u9"), r#"{"msgId":"m1"}"#),
            Verdict::FillNull
        );
        // Nothing fillable and nothing equal: ignored even for e2ee.
        assert_eq!(
            classify_message(Some(&cap_nosender), None, None, r#"{"msgId":"m1"}"#),
            Verdict::Ignored
        );
        // Import-sourced rows: converging replay ignored, changed
        // payload would update (rank 1 >= 1).
        let imp = stored("import", Some("t"), Some("u1"), r#"{"msgId":"m1"}"#);
        assert_eq!(
            classify_message(Some(&imp), Some("t"), Some("u1"), r#"{"msgId":"m1"}"#),
            Verdict::Ignored
        );
        assert_eq!(
            classify_message(Some(&imp), Some("t"), Some("u1"), r#"{"msgId":"m1","v":2}"#),
            Verdict::UpdateImport
        );
        // No row at all: new.
        assert_eq!(
            classify_message(None, Some("t"), Some("u1"), r#"{"msgId":"m9"}"#),
            Verdict::New
        );
    }

    #[test]
    fn classify_conversation_contact_group_shapes() {
        // Conversation: new.
        assert_eq!(
            classify_conversation(None, false, None, None, None, None),
            Verdict::New
        );
        // Identical row: ignored.
        let conv = StoredConv {
            is_group: false,
            title: Some("T".into()),
            avatar_url: Some("https://fake/a".into()),
            last_msg_id: Some("m1".into()),
            last_ts: Some(100),
        };
        assert_eq!(
            classify_conversation(Some(&conv), false, Some("T"), Some("https://fake/a"), Some("m1"), Some(100)),
            Verdict::Ignored
        );
        // NULL title filled, pointer at the same ts with a different
        // last_msg_id, type flip: all touch.
        let mut bare = conv.clone();
        bare.title = None;
        assert_eq!(
            classify_conversation(Some(&bare), false, Some("T"), None, None, None),
            Verdict::FillNull
        );
        assert_eq!(
            classify_conversation(Some(&conv), true, Some("T"), Some("https://fake/a"), Some("m1"), Some(100)),
            Verdict::FillNull,
            "the type always rewrites — a flip is a change"
        );
        // The pointer moves only forward in ts.
        assert_eq!(
            classify_conversation(Some(&conv), false, Some("T"), Some("https://fake/a"), Some("m0"), Some(99)),
            Verdict::Ignored,
            "an older ts never moves last_msg_id"
        );
        assert_eq!(
            classify_conversation(Some(&conv), false, Some("T"), Some("https://fake/a"), Some("m2"), Some(101)),
            Verdict::FillNull
        );
    }

    #[test]
    fn classify_contact_shapes() {
        let c = StoredContact {
            display_name: Some("N".into()),
            avatar_url: None,
            raw_json: Some(r#"{"u":"1"}"#.into()),
        };
        assert_eq!(classify_contact(None, None, None, "{}"), Verdict::New);
        assert_eq!(classify_contact(Some(&c), Some("N"), None, r#"{"u":"1"}"#), Verdict::Ignored);
        // NULL avatar filled.
        assert_eq!(classify_contact(Some(&c), Some("N"), Some("https://fake/a"), r#"{"u":"1"}"#), Verdict::FillNull);
        // raw_json always rewrites: a different raw is a change.
        assert_eq!(classify_contact(Some(&c), Some("N"), None, r#"{"u":"2"}"#), Verdict::FillNull);
    }

    #[test]
    fn classify_group_shapes() {
        let g = StoredGroup {
            name: Some("G".into()),
            raw_json: Some(r#"{"g":"1"}"#.into()),
        };
        assert_eq!(classify_group(None, None, "{}"), Verdict::New);
        assert_eq!(classify_group(Some(&g), Some("G"), r#"{"g":"1"}"#), Verdict::Ignored);
        assert_eq!(classify_group(Some(&g), Some("G2"), r#"{"g":"1"}"#), Verdict::FillNull);
    }

    #[test]
    fn classify_write_and_extract_against_a_real_shadow_copy_schema() {
        // The whole chain: fake Desktop DB -> extract -> classify
        // against an in-memory shadow DB the writer populated.
        let shadow = mem();
        super::super::schema::apply(&shadow).unwrap();
        // Seed: m101 exists as capture WITH text; m102 exists as
        // capture cipher-only (NULL text AND NULL sender); m999 does
        // not exist; m103 exists from a previous import (a payload
        // the new extraction will supersede).
        let cap = Write::Message {
            msg_id: "101".into(),
            conv_id: "u1".into(),
            sender_id: Some("u1".into()),
            ts: 1_690_000_000_000,
            kind: 1,
            text: Some("cap-text".into()),
            payload: r#"{"msgId":"101","uidFrom":"u1","idTo":"u2","ts":1690000000000,"msgType":"webchat","content":"cap-text"}"#.into(),
            source: "capture",
            is_group: Some(false),
        };
        let cap_null = Write::Message {
            msg_id: "102".into(),
            conv_id: "u1".into(),
            sender_id: None,
            ts: 1_690_000_001_000,
            kind: 2,
            text: None,
            payload: r#"{"msgId":"102","uidFrom":"u1","idTo":"u2","ts":1690000001000,"msgType":"chat.photo"}"#.into(),
            source: "capture",
            is_group: Some(false),
        };
        let mut imp_prior = cap.clone();
        if let Write::Message { msg_id, source, .. } = &mut imp_prior {
            *msg_id = "103".into();
            *source = "import";
        }
        for w in [&cap, &cap_null, &imp_prior] {
            super::super::writer::apply(&shadow, w).unwrap();
        }

        let conn = desktop_like();
        let inv = inventories(&conn, &conn);
        let m = parse_mapping(MAPPING_JSON.as_bytes()).unwrap();
        let p = plan(&m, &inv).unwrap();
        let (writes, _) = extract(
            &conn,
            &p,
            &ExtractOpts { kind: MapDb::OneToOne, db_id: Some(1), cursor: None, own_uid: None },
        )
        .unwrap();
        let verdicts: Vec<(&str, Verdict)> = writes
            .iter()
            .filter_map(|w| match w {
                Write::Message { msg_id, .. } => {
                    Some((msg_id.as_str(), classify_write(&shadow, w).unwrap()))
                }
                _ => None,
            })
            .collect();
        let v = |id: &str| verdicts.iter().find(|(m, _)| *m == id).unwrap().1;
        assert_eq!(v("101"), Verdict::Ignored, "capture row with text: never touched");
        assert_eq!(v("102"), Verdict::FillNull, "capture row with a NULL sender: import fills it");
        assert_eq!(v("103"), Verdict::UpdateImport, "prior import row, changed payload");
        assert_eq!(v("104"), Verdict::New, "no shadow row yet");

        // And the writer itself agrees: applying the extracted import
        // Writes to the shadow DB leaves capture text/payload intact.
        for w in &writes {
            if matches!(w, Write::Message { .. }) {
                super::super::writer::apply(&shadow, w).unwrap();
            }
        }
        let (text101, source101): (Option<String>, String) = shadow
            .query_row("SELECT text, source FROM messages WHERE msg_id='101'", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(text101.as_deref(), Some("cap-text"), "import never overwrites capture text");
        assert_eq!(source101, "capture");
        let (sender102, payload102): (Option<String>, String) = shadow
            .query_row(
                "SELECT sender_id, payload_json FROM messages WHERE msg_id='102'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(sender102.as_deref(), Some("u2"), "import filled the NULL sender");
        assert!(
            payload102.starts_with(r#"{"msgId":"102""#),
            "…but the capture payload stayed"
        );
        let payload103: String = shadow
            .query_row("SELECT payload_json FROM messages WHERE msg_id='103'", [], |r| r.get(0))
            .unwrap();
        assert!(
            payload103.contains("\"cliMsgId\":\"c103\""),
            "the prior import row was updated (rank 1 >= 1)"
        );
    }

    #[test]
    fn open_shadow_copy_copies_and_never_touches_the_source() {
        // A FAKE store (never the live one): build it, copy it, prove
        // the source bytes never changed and the copy is query_only.
        let base = std::env::temp_dir().join(format!(
            "zr-map-shadow-{}-{}",
            std::process::id(),
            schema::now_ms()
        ));
        let _ = std::fs::remove_dir_all(&base);
        let store = base.join("store");
        std::fs::create_dir_all(&store).unwrap();
        let key = sqlcipher::generate_key().unwrap();
        sqlcipher::save_key(&key, &super::super::key_file(&store)).unwrap();
        {
            let conn = sqlcipher::open_with_key(&super::super::db_file(&store), &key).unwrap();
            super::super::schema::apply(&conn).unwrap();
            conn.execute(
                "INSERT INTO messages (msg_id, conv_id, sender_id, ts, type, payload_json, source)
                 VALUES ('m1', 'c1', 'u1', 1, 1, '{}', 'capture')",
                [],
            )
            .unwrap();
        }
        let hash = |p: &Path| {
            use sha2::Digest;
            let mut h = sha2::Sha256::new();
            h.update(std::fs::read(p).unwrap());
            format!("{:x}", h.finalize())
        };
        let db_path = super::super::db_file(&store);
        let key_path = super::super::key_file(&store);
        let before = (hash(&db_path), hash(&key_path));

        let (conn, tmp) = open_shadow_copy(&store).unwrap();
        assert!(tmp.starts_with(std::env::temp_dir()));
        assert_ne!(tmp, store);
        assert!(tmp.to_string_lossy().contains("zr-import-shadow-"));
        let n: i64 = conn
            .query_row("SELECT count(*) FROM messages", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1);
        // query_only is on: a write must fail.
        let qo: i64 = conn.query_row("PRAGMA query_only", [], |r| r.get(0)).unwrap();
        assert_eq!(qo, 1);
        assert!(conn.execute("DELETE FROM messages", []).is_err());

        assert_eq!((hash(&db_path), hash(&key_path)), before, "the store files never changed");
        // A missing store dir fails with a clear error.
        let e = open_shadow_copy(&base.join("nope")).unwrap_err();
        assert!(e.contains("--shadow-copy"), "{e}");
        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
