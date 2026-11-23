//! Batch 28 M3: `import --media-derivatives` — pre-warm the WebP
//! derivative cache of the archive images.
//!
//! READ-ONLY on the store: the shadow DB opens read-only (the same
//! `passphrase::open_store(.., true)` path the archive window uses; a
//! Locked passphrase store refuses — the CLI never accepts a password;
//! a read-only open works next to the running app, which holds the
//! store with WAL readers + one writer). It writes ONLY into
//! `<media root>\cache\img\` (temp file + rename, content addressed by
//! the stored file's sha), so no `--apply` gate and no backup are
//! needed; the run is idempotent (a second run builds 0).
//!
//! Every `attachments` row with `kind='image' AND status='downloaded'`
//! is resolved INSIDE the media root (`media::resolve_local_path` +
//! `archive::under_root_file`, the archive's own guards); each distinct
//! sha is processed once, all missing variants of one sha from ONE
//! decode ([`img_derive::cached_many`]), by N scoped worker threads
//! pulling from a shared queue (no new crate).
//!
//! The disk check runs first: (220 KB per missing view + 20 KB per
//! missing thumb) x 1.2 + 1 GiB must be below the free space of the
//! media root's volume (injectable, like the 27b copy's probe). A
//! variant counts as missing only when the run would really write it
//! (a small JPEG/PNG whose original is served never does).
//!
//! H-rule: every output line is counts, fixed vocabulary (variant and
//! error kinds) and byte sums — never a path, file name, id, URL, sha
//! or message text.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Mutex};
use std::time::Instant;

use super::cli::ImportArgs;
use super::img_derive::{self, DeriveError, Variant};
use super::{archive, media, passphrase};

/// Estimated bytes per derivative (the 30-image measurement: 198 KB
/// view / 17 KB thumb on average, rounded up).
pub const EST_VIEW_BYTES: u64 = 220 * 1024;
pub const EST_THUMB_BYTES: u64 = 20 * 1024;
/// Headroom added to the disk check.
const DISK_HEADROOM: u128 = 1024 * 1024 * 1024;
/// A counts-only progress line every this many distinct shas.
pub const PROGRESS_EVERY: usize = 500;

/// Free bytes on the volume of the given path (`None` = unmeasurable
/// → the check fails closed). Injectable for tests.
pub type FreeSpaceFn<'a> = &'a dyn Fn(&Path) -> Option<u64>;

/// Everything the run takes from its environment, injected so the
/// tests never read the real settings or the disk.
pub struct DeriveEnv<'a> {
    /// The media store root the archive reads (the cache lives in it).
    pub media_root: PathBuf,
    pub free_space: FreeSpaceFn<'a>,
}

/// The estimate, rounded up: `(missing_view x 220 KB + missing_thumb
/// x 20 KB) x 1.2 + 1 GiB`.
pub fn needed_bytes(missing_view: u64, missing_thumb: u64) -> u128 {
    let base = missing_view as u128 * EST_VIEW_BYTES as u128
        + missing_thumb as u128 * EST_THUMB_BYTES as u128;
    (base * 12).div_ceil(10) + DISK_HEADROOM
}

/// The disk rule: the estimate must be STRICTLY below the free space.
pub fn disk_ok(missing_view: u64, missing_thumb: u64, free_bytes: u64) -> bool {
    needed_bytes(missing_view, missing_thumb) < free_bytes as u128
}

/// Default worker count: `available_parallelism() - 2`, at least 1.
pub fn default_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get().saturating_sub(2))
        .unwrap_or(1)
        .max(1)
}

/// The nearest existing ancestor (the volume probe for a media root
/// that may not exist yet).
fn existing_ancestor(p: &Path) -> PathBuf {
    let mut cur = p.to_path_buf();
    loop {
        if cur.exists() {
            return cur;
        }
        match cur.parent() {
            Some(par) if !par.as_os_str().is_empty() => cur = par.to_path_buf(),
            _ => return cur,
        }
    }
}

/// Per-variant tallies.
#[derive(Debug, Default, Clone)]
struct Tally {
    built: u64,
    cached: u64,
    use_original: u64,
    errors: BTreeMap<&'static str, u64>,
}

impl Tally {
    fn merge(&mut self, o: &Tally) {
        self.built += o.built;
        self.cached += o.cached;
        self.use_original += o.use_original;
        for (k, n) in &o.errors {
            *self.errors.entry(k).or_insert(0) += n;
        }
    }
    fn line(&self) -> String {
        let errs: u64 = self.errors.values().sum();
        let mut s = format!(
            "built={} cached={} use_original={} errors={errs}",
            self.built, self.cached, self.use_original
        );
        for (k, n) in &self.errors {
            s.push_str(&format!(" {k}={n}"));
        }
        s
    }
}

#[derive(Debug, Default, Clone)]
struct Totals {
    per_variant: Vec<Tally>,
    bytes_written: u64,
}

fn locked_refusal() -> String {
    "the target store is password-protected (passphrase mode): unlock it in the app with \
     'Nhớ trên máy này' (remember on this machine) enabled, then re-run — the derivative \
     pre-warm CLI never accepts passwords"
        .into()
}

/// The run. Lines stream through `out`.
pub fn run(
    a: &ImportArgs,
    env: &DeriveEnv<'_>,
    out: &mut dyn FnMut(&str),
) -> Result<(), String> {
    let mode = "media-derivatives";
    let target = a
        .target
        .as_deref()
        .expect("cli::main routes --media-derivatives here; parse guarantees --target");
    let variants: Vec<Variant> = if a.variants.is_empty() {
        vec![Variant::Thumb, Variant::View]
    } else {
        a.variants.clone()
    };
    let threads = a.threads.map(|n| n as usize).unwrap_or_else(default_threads).max(1);
    let started = Instant::now();

    // The store, READ-ONLY.
    let db_path = super::db_file(target);
    if !db_path.is_file() {
        return Err("--target: no shadow DB file in it — not a shadow store dir?".into());
    }
    let (conn, _key) = match passphrase::open_store(target, true) {
        Ok(t) => t,
        Err(passphrase::StoreOpenError::Locked) => return Err(locked_refusal()),
        Err(passphrase::StoreOpenError::Other(k)) => {
            return Err(format!(
                "--target: store open failed ({k}) — no key file / broken store?"
            ))
        }
    };
    out(&format!("{mode}: store=given (read-only)"));

    // The rows -> distinct stored files, resolved inside the media root.
    let cfg = crate::settings::ShadowSettings {
        media_store: Some(env.media_root.to_string_lossy().into_owned()),
        ..Default::default()
    };
    let sqlite_err = |e: rusqlite::Error| format!("store read failed ({})", sqlite_kind(&e));
    let rels: Vec<String> = {
        let mut st = conn
            .prepare(
                "SELECT local_path FROM attachments
                  WHERE kind = 'image' AND status = 'downloaded'
                    AND local_path IS NOT NULL AND local_path <> ''
                  ORDER BY msg_id, idx",
            )
            .map_err(sqlite_err)?;
        let rows = st.query_map([], |r| r.get::<_, String>(0)).map_err(sqlite_err)?;
        rows.filter_map(Result::ok).collect()
    };
    let rows = rels.len() as u64;
    // One entry per distinct stored path, in a stable order.
    let mut files: BTreeMap<String, PathBuf> = BTreeMap::new();
    let mut unresolved = 0u64;
    for rel in rels.iter().collect::<BTreeSet<_>>() {
        let abs = media::resolve_local_path(&cfg, rel);
        if archive::under_root_file(&abs, &env.media_root) {
            // Key: the stored file's sha when it is one (the cache key);
            // else the path string (processed through the hashing
            // helper below).
            let key = img_derive::sha_from_file_name(&abs)
                .unwrap_or_else(|| format!("path:{rel}"));
            files.entry(key).or_insert(abs);
        } else {
            unresolved += 1;
        }
    }
    let mut queue: Vec<(String, PathBuf)> = files.into_iter().collect();
    if let Some(n) = a.limit {
        queue.truncate(n as usize);
    }
    let total = queue.len();
    out(&format!(
        "{mode}: rows={rows} distinct_shas={total} unresolved_paths={unresolved} variants={} \
         limit={} threads={threads}",
        variants.iter().map(|v| v.name()).collect::<Vec<_>>().join(","),
        a.limit.map(|n| n.to_string()).unwrap_or_else(|| "none".into())
    ));

    // The disk check: how many variants are still missing.
    // "Missing" counts only what the run will really write: a variant
    // whose original is served (small JPEG/PNG) or that has no format
    // never produces a file (`img_derive::needs_build`).
    let (mut miss_view, mut miss_thumb) = (0u64, 0u64);
    for (key, src) in &queue {
        for v in &variants {
            let cached = img_derive::is_store_sha(key)
                && img_derive::cache_path(&env.media_root, *v, key).is_file();
            if !cached && img_derive::needs_build(src, *v) {
                match v {
                    Variant::Thumb => miss_thumb += 1,
                    _ => miss_view += 1,
                }
            }
        }
    }
    out(&format!(
        "{mode}: missing before: view={miss_view} thumb={miss_thumb}"
    ));
    let need = needed_bytes(miss_view, miss_thumb);
    if miss_view + miss_thumb > 0 {
        let probe = existing_ancestor(&env.media_root);
        let free = (env.free_space)(&probe);
        let verdict = match free {
            Some(f) if need < f as u128 => "ok",
            Some(_) => "NOT ENOUGH FREE SPACE",
            None => "free space unmeasurable",
        };
        out(&format!(
            "{mode}: disk check: needed_bytes={need} (est x 1.2 + 1 GiB) result={verdict}"
        ));
        if verdict != "ok" {
            return Err(format!(
                "disk check: {verdict} on the media root's volume (needs {need} bytes) — \
                 nothing was written"
            ));
        }
    } else {
        out(&format!("{mode}: nothing missing — no disk check needed"));
    }

    // The workers.
    let next = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let totals = Mutex::new(Totals {
        per_variant: vec![Tally::default(); variants.len()],
        ..Default::default()
    });
    let (tx, rx) = mpsc::channel::<usize>();
    std::thread::scope(|s| {
        for _ in 0..threads {
            let tx = tx.clone();
            let (queue, variants, next, done, totals) = (&queue, &variants, &next, &done, &totals);
            let root = env.media_root.as_path();
            s.spawn(move || {
                let mut local = Totals {
                    per_variant: vec![Tally::default(); variants.len()],
                    ..Default::default()
                };
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some((key, src)) = queue.get(i) else { break };
                    let results = if img_derive::is_store_sha(key) {
                        img_derive::cached_many(src, key, root, variants)
                    } else {
                        // A non-store file name: one hash, then the same path.
                        match std::fs::read(src) {
                            Ok(bytes) => {
                                let sha = {
                                    use sha2::{Digest, Sha256};
                                    format!("{:x}", Sha256::digest(&bytes))
                                };
                                img_derive::cached_many(src, &sha, root, variants)
                            }
                            Err(_) => vec![Err(DeriveError::Io); variants.len()],
                        }
                    };
                    for (t, r) in local.per_variant.iter_mut().zip(results) {
                        match r {
                            Ok(d) if d.built => {
                                t.built += 1;
                                local.bytes_written += d.bytes;
                            }
                            Ok(_) => t.cached += 1,
                            Err(DeriveError::UseOriginal) => t.use_original += 1,
                            Err(e) => *t.errors.entry(e.name()).or_insert(0) += 1,
                        }
                    }
                    let n = done.fetch_add(1, Ordering::Relaxed) + 1;
                    if n % PROGRESS_EVERY == 0 {
                        let _ = tx.send(n);
                    }
                }
                let mut g = crate::lock::guard(totals);
                for (a, b) in g.per_variant.iter_mut().zip(&local.per_variant) {
                    a.merge(b);
                }
                g.bytes_written += local.bytes_written;
            });
        }
        drop(tx);
        // The main thread prints the progress lines (the sink is not
        // Send, so the workers only post counts).
        for n in rx {
            out(&format!("{mode}: progress shas={n}/{total}"));
        }
    });

    let t = crate::lock::guard(&totals).clone();
    for (v, tally) in variants.iter().zip(&t.per_variant) {
        out(&format!("{mode}: variant={} {}", v.name(), tally.line()));
    }
    out(&format!(
        "{mode}: shas={total} bytes_written={} elapsed_s={}",
        t.bytes_written,
        started.elapsed().as_secs()
    ));
    out(&format!("{mode}: done"));
    Ok(())
}

/// The wired entry (the real settings and the real free-space probe).
/// The media root is resolved exactly the way the archive resolves it
/// (`settings.shadow.media_store`, else the documented default).
pub fn run_wired(a: &ImportArgs, out: &mut dyn FnMut(&str)) -> Result<(), String> {
    let settings = crate::settings::path_without_app()
        .map(|path| crate::settings::load_at(&path))
        .unwrap_or_default();
    let media_root = media::media_store_root(&settings.shadow);
    let free = |p: &Path| super::disk_space::disk_free_space(p).map(|(free, _total)| free);
    let env = DeriveEnv { media_root, free_space: &free };
    run(a, &env, out)
}

/// The SQLite error kind only (never the message — it could quote a
/// path). Same idea as the other CLIs.
fn sqlite_kind(e: &rusqlite::Error) -> String {
    match e {
        rusqlite::Error::SqliteFailure(f, _) => format!("{:?}", f.code),
        _ => "other".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrate::sqlcipher;
    use sha2::{Digest, Sha256};

    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zr-dcli-{tag}-{}-{}-{}",
            std::process::id(),
            super::super::schema::now_ms(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn png(w: u32, h: u32) -> Vec<u8> {
        let img = image::DynamicImage::ImageRgb8(image::RgbImage::from_pixel(
            w,
            h,
            image::Rgb([9, 99, 199]),
        ));
        let mut v = Vec::new();
        img.write_to(&mut std::io::Cursor::new(&mut v), image::ImageFormat::Png)
            .unwrap();
        v
    }

    const TINY_JXL: [u8; 42] = [
        0xff, 0x0a, 0x30, 0x54, 0x10, 0x09, 0x08, 0x06, 0x01, 0x00, 0x78, 0x00, 0x4b, 0x38, 0x41,
        0x3c, 0xb6, 0x3a, 0x51, 0xfe, 0x00, 0x47, 0x1e, 0xa0, 0x85, 0xb8, 0x27, 0x1a, 0x48, 0x45,
        0x84, 0x1b, 0x71, 0x4f, 0xa8, 0x3e, 0x8e, 0x30, 0x03, 0x92, 0x84, 0x01,
    ];

    struct Fx {
        store: PathBuf,
        media: PathBuf,
    }

    /// A synthetic raw-key store with the attachments below and a
    /// media root with their files (content-addressed names):
    /// - m1: a JXL image (downloaded), m2: a 1000x800 PNG (downloaded),
    ///   m3: a 50x50 PNG (downloaded, small -> use_original), plus a
    ///   second row (m4) pointing at the SAME file as m2 (one sha);
    /// - ignored: a `ref` image, a downloaded video, a downloaded image
    ///   whose file is missing (counted as unresolved).
    fn fixture() -> Fx {
        let base = scratch("fx");
        let store = base.join("store");
        let media = base.join("media");
        std::fs::create_dir_all(&store).unwrap();
        std::fs::create_dir_all(&media).unwrap();
        let key = sqlcipher::generate_key().unwrap();
        sqlcipher::save_key(&key, &super::super::key_file(&store)).unwrap();
        let conn = sqlcipher::open_with_key(&super::super::db_file(&store), &key).unwrap();
        super::super::schema::apply(&conn).unwrap();
        let put = |bytes: &[u8]| -> String {
            let sha = format!("{:x}", Sha256::digest(bytes));
            let dir = media.join(&sha[..2]).join(&sha[2..4]);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join(&sha), bytes).unwrap();
            format!("{}/{}/{sha}", &sha[..2], &sha[2..4])
        };
        let row = |msg: &str, kind: &str, status: &str, rel: Option<&str>| {
            conn.execute(
                "INSERT INTO attachments (msg_id, idx, kind, local_path, status)
                 VALUES (?1, 0, ?2, ?3, ?4)",
                rusqlite::params![msg, kind, rel, status],
            )
            .unwrap();
        };
        let jxl = put(&TINY_JXL);
        let mid = put(&png(1000, 800));
        let small = put(&png(50, 50));
        row("m1", "image", "downloaded", Some(&jxl));
        row("m2", "image", "downloaded", Some(&mid));
        row("m3", "image", "downloaded", Some(&small));
        row("m4", "image", "downloaded", Some(&mid));
        row("m5", "image", "ref", None);
        row("m6", "video", "downloaded", Some(&small));
        row("m7", "image", "downloaded", Some(&format!("aa/bb/{}", "d".repeat(64))));
        drop(conn);
        Fx { store, media }
    }

    fn run_with(
        fx: &Fx,
        extra: &[&str],
        free: Option<u64>,
    ) -> (Result<(), String>, Vec<String>) {
        let mut argv = vec!["--media-derivatives".to_string(), "--target".to_string()];
        argv.push(fx.store.to_string_lossy().into_owned());
        argv.extend(extra.iter().map(|s| s.to_string()));
        let a = super::super::cli::parse(&argv).expect("parses");
        let free_fn = move |_: &Path| free;
        let env = DeriveEnv { media_root: fx.media.clone(), free_space: &free_fn };
        let mut lines = Vec::new();
        let r = run(&a, &env, &mut |l: &str| lines.push(l.to_string()));
        (r, lines)
    }

    fn find<'a>(lines: &'a [String], needle: &str) -> &'a str {
        lines
            .iter()
            .find(|l| l.contains(needle))
            .unwrap_or_else(|| panic!("no line with {needle:?} in {lines:#?}"))
    }

    const GIB: u64 = 1024 * 1024 * 1024;

    #[test]
    fn the_prewarm_builds_the_missing_variants_and_a_second_run_builds_none() {
        let fx = fixture();
        let (r, lines) = run_with(&fx, &["--threads", "2"], Some(100 * GIB));
        r.expect("first run");
        // 5 downloaded-image rows (m1..m4, m7), 4 distinct files of
        // which 3 resolve; the m7 file is missing.
        let head = find(&lines, "rows=");
        assert!(head.contains("rows=5 distinct_shas=3 unresolved_paths=1"), "{head}");
        assert!(head.contains("variants=thumb,view") && head.contains("threads=2"), "{head}");
        // thumb: jxl + mid built, small = use_original.
        // view: jxl built; mid (1000 px, small file) and small = use_original.
        let thumb = find(&lines, "variant=thumb");
        assert!(thumb.contains("built=2 cached=0 use_original=1 errors=0"), "{thumb}");
        let view = find(&lines, "variant=view");
        assert!(view.contains("built=1 cached=0 use_original=2 errors=0"), "{view}");
        let tot = find(&lines, "bytes_written=");
        assert!(!tot.contains("bytes_written=0 "), "{tot}");
        assert!(lines.last().unwrap().ends_with("done"));
        // The files are where the archive looks for them.
        let n = |v: &str| -> usize {
            fn count(d: &Path) -> usize {
                std::fs::read_dir(d).map(|rd| rd.flatten().map(|e| {
                    let p = e.path();
                    if p.is_dir() { count(&p) } else { 1 }
                }).sum()).unwrap_or(0)
            }
            count(&fx.media.join("cache").join("img").join(v))
        };
        assert_eq!((n("thumb"), n("view")), (2, 1));
        // Idempotent: the second run builds 0 (everything cached; the
        // use_original ones are decided again, never written).
        let (r2, lines2) = run_with(&fx, &[], Some(100 * GIB));
        r2.expect("second run");
        let thumb = find(&lines2, "variant=thumb");
        assert!(thumb.contains("built=0 cached=2 use_original=1 errors=0"), "{thumb}");
        let view = find(&lines2, "variant=view");
        assert!(view.contains("built=0 cached=1 use_original=2 errors=0"), "{view}");
        assert!(find(&lines2, "bytes_written=").contains("bytes_written=0 "));
        assert_eq!((n("thumb"), n("view")), (2, 1));
        let _ = std::fs::remove_dir_all(fx.store.parent().unwrap());
    }

    #[test]
    fn variants_and_limit_narrow_the_run() {
        let fx = fixture();
        let (r, lines) = run_with(&fx, &["--variants", "view", "--limit", "1"], Some(100 * GIB));
        r.unwrap();
        assert!(find(&lines, "rows=").contains("variants=view limit=1"));
        assert!(!lines.iter().any(|l| l.contains("variant=thumb")));
        // One distinct file only (sorted by path), thumb never built.
        let thumb_dir = fx.media.join("cache").join("img").join("thumb");
        assert!(!thumb_dir.exists());
        let _ = std::fs::remove_dir_all(fx.store.parent().unwrap());
    }

    #[test]
    fn the_disk_check_refuses_before_any_write() {
        let fx = fixture();
        // Only 1 GiB free: the estimate (>= 1 GiB headroom + the files)
        // is not strictly below it.
        let (r, lines) = run_with(&fx, &[], Some(GIB));
        let e = r.unwrap_err();
        assert!(e.contains("NOT ENOUGH FREE SPACE") && e.contains("nothing was written"), "{e}");
        assert!(find(&lines, "disk check").contains("NOT ENOUGH FREE SPACE"));
        assert!(!fx.media.join("cache").exists(), "nothing written");
        // An unmeasurable volume fails closed too.
        let (r, lines) = run_with(&fx, &[], None);
        assert!(r.unwrap_err().contains("free space unmeasurable"));
        assert!(find(&lines, "disk check").contains("free space unmeasurable"));
        assert!(!fx.media.join("cache").exists());
        let _ = std::fs::remove_dir_all(fx.store.parent().unwrap());
    }

    #[test]
    fn the_disk_estimate_is_the_documented_formula() {
        // (220 KB per view + 20 KB per thumb) x 1.2 + 1 GiB, strict.
        assert_eq!(needed_bytes(0, 0), GIB as u128);
        let base = 10u128 * 220 * 1024 + 5 * 20 * 1024;
        assert_eq!(needed_bytes(10, 5), (base * 12).div_ceil(10) + GIB as u128);
        assert!(!disk_ok(0, 0, GIB)); // strictly below
        assert!(disk_ok(0, 0, GIB + 1));
        assert!(disk_ok(10, 5, 2 * GIB));
        assert!(!disk_ok(10_000_000, 0, 2 * GIB));
    }

    #[test]
    fn nothing_missing_needs_no_disk_check() {
        let fx = fixture();
        run_with(&fx, &[], Some(100 * GIB)).0.unwrap();
        // Even with no measurable free space a fully warm cache passes.
        let (r, lines) = run_with(&fx, &[], None);
        r.unwrap();
        assert!(find(&lines, "nothing missing").contains("no disk check needed"));
        let _ = std::fs::remove_dir_all(fx.store.parent().unwrap());
    }

    #[test]
    fn the_report_never_carries_a_path_name_id_or_sha() {
        let fx = fixture();
        let (r, lines) = run_with(&fx, &[], Some(100 * GIB));
        r.unwrap();
        let all = lines.join("\n");
        let base = fx.store.parent().unwrap().to_string_lossy().into_owned();
        assert!(!all.contains(&base), "no path");
        for needle in ["m1", "m2", "m3", "m7", ".webp", "\\", "/", "ab/", "cd/"] {
            assert!(!all.contains(needle), "{needle:?} in the report");
        }
        // No 64-hex run anywhere.
        let mut run = 0;
        for c in all.chars() {
            if c.is_ascii_hexdigit() && !c.is_ascii_uppercase() { run += 1 } else { run = 0 }
            assert!(run < 40, "a sha-like run in the report");
        }
        let _ = std::fs::remove_dir_all(fx.store.parent().unwrap());
    }

    #[test]
    fn a_missing_store_or_a_bad_target_refuses_clearly() {
        let fx = fixture();
        let empty = scratch("empty");
        let a = super::super::cli::parse(&[
            "--media-derivatives".into(),
            "--target".into(),
            empty.to_string_lossy().into_owned(),
        ])
        .unwrap();
        let free_fn = |_: &Path| Some(100 * GIB);
        let env = DeriveEnv { media_root: fx.media.clone(), free_space: &free_fn };
        let e = run(&a, &env, &mut |_| {}).unwrap_err();
        assert!(e.contains("not a shadow store dir"), "{e}");
        let _ = std::fs::remove_dir_all(&empty);
        let _ = std::fs::remove_dir_all(fx.store.parent().unwrap());
    }

    #[test]
    fn the_default_thread_count_is_at_least_one() {
        assert!(default_threads() >= 1);
    }
}
