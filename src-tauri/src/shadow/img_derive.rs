//! Batch 28 M1: WebP derivatives (thumb + view) of the archive images.
//!
//! Batch 27b served a JPEG XL image as a full-size PNG (3.7 MB on
//! average, decoded on the first view). This module replaces that with
//! lossy WebP derivatives cached on disk and pre-warmed by the
//! `import --media-derivatives` CLI:
//!
//! | variant | long edge | WebP quality | source |
//! |---|---|---|---|
//! | `thumb` | <= 480 | 75 | JXL, JPEG, PNG |
//! | `view`  | <= 2048 | 80 | JXL, JPEG, PNG |
//! | `orig`  | <= 16383 (the WebP maximum) | 85 | JXL only |
//!
//! `orig` is the "full size" of a JPEG XL image (WebView2 cannot show
//! the JXL itself); for JPEG and PNG the original bytes are served as
//! they are, so `orig` on those is [`DeriveError::UseOriginal`].
//!
//! Rules:
//! - never upscale; the aspect ratio is kept; resizing is
//!   `image::imageops::resize` with `FilterType::Triangle` (reached
//!   through the non-generic `DynamicImage::resize_exact`, so it runs
//!   optimised in the debug build too);
//! - JXL decodes through [`super::jxl_decode`] (its caps hold: 64 MB
//!   input, 50 MP, the 2 GiB allocation tracker); JPEG and PNG decode
//!   through `image` with the SAME 50 MP cap, checked from the header
//!   BEFORE any pixel is decoded, plus an allocation limit. EXIF
//!   orientation of a JPEG is applied (`ImageDecoder::orientation` +
//!   `DynamicImage::apply_orientation`);
//! - GIF, WebP and every other source have no derivative
//!   ([`DeriveError::Unsupported`]): the caller serves the original;
//! - alpha is kept (`Encoder::from_rgba`); gray becomes RGB;
//! - a JPEG/PNG that is already no longer than the variant's edge AND
//!   smaller than [`SMALL_SOURCE_BYTES`] gets no derivative
//!   ([`DeriveError::UseOriginal`]): the original is already as small;
//! - the cache is content addressed:
//!   `<media root>\cache\img\<variant>\<aa>\<sha>.webp`, `<sha>` the
//!   store file's own name (64 lowercase hex) and `<aa>` its first two
//!   characters. The key never depends on the path;
//! - a derivative is written to a temp file in the same directory and
//!   renamed; on a lost race the existing file is kept;
//! - the same sha is never decoded twice at once: a request waits
//!   (bounded, [`FLIGHT_WAIT`]) while another thread builds it, then
//!   re-checks the cache; after the wait it builds anyway (and renames
//!   over the other result, identical bytes by construction).
//!
//! H-rule: every failure is a plain [`DeriveError`] kind (never a
//! path, never an error text); nothing here logs.

use std::collections::HashSet;
use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex, OnceLock};
use std::time::{Duration, Instant};

use image::imageops::FilterType;
use image::{DynamicImage, ImageBuffer, ImageDecoder, ImageFormat, Rgb, Rgba};
use sha2::{Digest, Sha256};

use super::jxl_decode::{self, JxlError};

/// Long-edge cap of the `thumb` variant.
pub const THUMB_EDGE: u32 = 480;
/// Long-edge cap of the `view` variant.
pub const VIEW_EDGE: u32 = 2048;
/// Long-edge cap of the `orig` variant: the largest dimension WebP can
/// hold (a 50 MP JXL that is very wide is scaled down to fit).
pub const ORIG_EDGE: u32 = 16383;
/// WebP quality of each variant.
pub const THUMB_QUALITY: f32 = 75.0;
pub const VIEW_QUALITY: f32 = 80.0;
pub const ORIG_QUALITY: f32 = 85.0;
/// A JPEG/PNG smaller than this AND within the variant's edge is
/// served as the original (see [`DeriveError::UseOriginal`]).
pub const SMALL_SOURCE_BYTES: u64 = 300 * 1024;
/// Cap on the allocations of the `image` decoders (the 50 MP cap on
/// RGBA is 200 MB; this leaves headroom for one working copy).
const IMAGE_ALLOC_LIMIT: u64 = 1024 * 1024 * 1024;
/// How long one request waits for another thread decoding the same sha.
pub const FLIGHT_WAIT: Duration = Duration::from_secs(30);

/// One derivative variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Variant {
    Thumb,
    View,
    Orig,
}

impl Variant {
    /// The URL value (`?v=…`) and the cache directory name.
    pub fn name(self) -> &'static str {
        match self {
            Variant::Thumb => "thumb",
            Variant::View => "view",
            Variant::Orig => "orig",
        }
    }
    /// Strict parse of the URL value: exactly `thumb`, `view` or `orig`.
    pub fn parse(s: &str) -> Option<Variant> {
        match s {
            "thumb" => Some(Variant::Thumb),
            "view" => Some(Variant::View),
            "orig" => Some(Variant::Orig),
            _ => None,
        }
    }
    /// The long-edge cap.
    pub fn edge(self) -> u32 {
        match self {
            Variant::Thumb => THUMB_EDGE,
            Variant::View => VIEW_EDGE,
            Variant::Orig => ORIG_EDGE,
        }
    }
    /// The WebP quality.
    pub fn quality(self) -> f32 {
        match self {
            Variant::Thumb => THUMB_QUALITY,
            Variant::View => VIEW_QUALITY,
            Variant::Orig => ORIG_QUALITY,
        }
    }
}

/// Why a derivative was not produced (kinds only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeriveError {
    /// The source is bigger than the 64 MB input cap.
    TooLarge,
    /// width x height is above 50 MP (or zero).
    TooManyPixels,
    /// The bytes did not decode (corrupt / truncated / unsupported).
    Decode,
    /// The decoded frame has a shape this build cannot handle.
    Format,
    /// The WebP encoder failed.
    Encode,
    /// A source or cache file could not be read, written or renamed.
    Io,
    /// The format has no derivative (GIF, WebP, anything else).
    Unsupported,
    /// The cache key (sha) is not 64 lowercase hex.
    BadKey,
    /// The original is already as small as the derivative would be:
    /// the caller serves the original bytes.
    UseOriginal,
}

impl DeriveError {
    /// Fixed vocabulary for counts-only reports.
    pub fn name(self) -> &'static str {
        match self {
            DeriveError::TooLarge => "too_large",
            DeriveError::TooManyPixels => "too_many_pixels",
            DeriveError::Decode => "decode",
            DeriveError::Format => "format",
            DeriveError::Encode => "encode",
            DeriveError::Io => "io",
            DeriveError::Unsupported => "unsupported",
            DeriveError::BadKey => "bad_key",
            DeriveError::UseOriginal => "use_original",
        }
    }
}

impl From<JxlError> for DeriveError {
    fn from(e: JxlError) -> Self {
        match e {
            JxlError::TooLarge => DeriveError::TooLarge,
            JxlError::TooManyPixels => DeriveError::TooManyPixels,
            JxlError::Decode => DeriveError::Decode,
            JxlError::Format => DeriveError::Format,
        }
    }
}

// --- pure helpers ---------------------------------------------------------------

/// The size of a derivative: the image fitted into `edge` on its long
/// side, aspect ratio kept (short side rounded to nearest, at least 1),
/// never enlarged. `(w, h)` unchanged when it already fits.
pub fn fit_dims(w: u32, h: u32, edge: u32) -> (u32, u32) {
    if w == 0 || h == 0 || edge == 0 {
        return (w, h);
    }
    let long = w.max(h);
    if long <= edge {
        return (w, h);
    }
    let scale = |side: u32| -> u32 {
        let v = (side as u64 * edge as u64 + long as u64 / 2) / long as u64;
        (v.max(1)) as u32
    };
    if w >= h {
        (edge, scale(h))
    } else {
        (scale(w), edge)
    }
}

/// Is this a store file name (64 lowercase hex)?
pub fn is_store_sha(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The store file's sha when its own name is one.
pub fn sha_from_file_name(src: &Path) -> Option<String> {
    let n = src.file_name()?.to_str()?;
    is_store_sha(n).then(|| n.to_string())
}

/// `<media root>\cache\img\<variant>\<aa>\<sha>.webp`. Content
/// addressed: the key is the sha only. `sha` must be a store sha (the
/// callers check [`is_store_sha`]).
pub fn cache_path(media_root: &Path, v: Variant, sha: &str) -> PathBuf {
    media_root
        .join("cache")
        .join("img")
        .join(v.name())
        .join(&sha[..2])
        .join(format!("{sha}.webp"))
}

/// The "already small" rule for a JPEG/PNG source: shorter than
/// [`SMALL_SOURCE_BYTES`] AND its long edge within the variant's edge.
pub fn small_enough_to_serve_as_is(src_len: u64, w: u32, h: u32, v: Variant) -> bool {
    src_len < SMALL_SOURCE_BYTES && w.max(h) <= v.edge()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Src {
    Jpeg,
    Png,
    Jxl,
}

fn sniff(head: &[u8]) -> Option<Src> {
    if head.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some(Src::Jpeg)
    } else if head.starts_with(&[0x89, 0x50, 0x4E, 0x47]) {
        Some(Src::Png)
    } else if jxl_decode::is_jxl(head) {
        Some(Src::Jxl)
    } else {
        None
    }
}

/// A decoded image, 8-bit RGB or RGBA.
struct Decoded {
    w: u32,
    h: u32,
    alpha: bool,
    data: Vec<u8>,
}

fn from_dynamic(img: DynamicImage) -> Decoded {
    if img.color().has_alpha() {
        let b = img.into_rgba8();
        Decoded { w: b.width(), h: b.height(), alpha: true, data: b.into_raw() }
    } else {
        let b = img.into_rgb8();
        Decoded { w: b.width(), h: b.height(), alpha: false, data: b.into_raw() }
    }
}

/// JXL pixels (1..4 channels) to RGB/RGBA: gray is replicated.
fn from_jxl(px: jxl_decode::JxlPixels) -> Result<Decoded, DeriveError> {
    let n = px.width as usize * px.height as usize;
    match px.channels {
        3 | 4 if px.data.len() == n * px.channels => Ok(Decoded {
            w: px.width,
            h: px.height,
            alpha: px.channels == 4,
            data: px.data,
        }),
        1 if px.data.len() == n => {
            let mut out = Vec::with_capacity(n * 3);
            for &g in &px.data {
                out.extend_from_slice(&[g, g, g]);
            }
            Ok(Decoded { w: px.width, h: px.height, alpha: false, data: out })
        }
        2 if px.data.len() == n * 2 => {
            let mut out = Vec::with_capacity(n * 4);
            for c in px.data.chunks_exact(2) {
                out.extend_from_slice(&[c[0], c[0], c[0], c[1]]);
            }
            Ok(Decoded { w: px.width, h: px.height, alpha: true, data: out })
        }
        _ => Err(DeriveError::Format),
    }
}

/// Decode a JPEG/PNG: header dimensions are checked against the 50 MP
/// cap before any pixel is decoded; `want` gets the header size so the
/// caller can apply the "already small" rule before the full decode.
fn decode_raster(
    bytes: &[u8],
    fmt: ImageFormat,
    gate: impl FnOnce(u32, u32) -> bool,
) -> Result<Option<Decoded>, DeriveError> {
    let mut reader = image::ImageReader::with_format(Cursor::new(bytes), fmt);
    let mut limits = image::Limits::no_limits();
    limits.max_alloc = Some(IMAGE_ALLOC_LIMIT);
    reader.limits(limits);
    let mut decoder = reader.into_decoder().map_err(|_| DeriveError::Decode)?;
    let (w, h) = decoder.dimensions();
    if !jxl_decode::pixels_ok(w, h) {
        return Err(DeriveError::TooManyPixels);
    }
    if !gate(w, h) {
        return Ok(None);
    }
    let orientation = decoder.orientation().unwrap_or(image::metadata::Orientation::NoTransforms);
    let mut img = DynamicImage::from_decoder(decoder).map_err(|_| DeriveError::Decode)?;
    img.apply_orientation(orientation);
    Ok(Some(from_dynamic(img)))
}

/// Resize (never upscale) and encode as a lossy WebP.
fn encode_variant(d: &Decoded, v: Variant) -> Result<Vec<u8>, DeriveError> {
    let (nw, nh) = fit_dims(d.w, d.h, v.edge());
    if nw == 0 || nh == 0 || nw > ORIG_EDGE || nh > ORIG_EDGE {
        return Err(DeriveError::Format);
    }
    // `DynamicImage::resize_exact` is a NON-generic entry point: it runs
    // `imageops::resize` (Triangle) inside the `image` crate, which the
    // dev profile builds at opt-level 3. Calling the generic
    // `imageops::resize` from here would instantiate it in THIS crate at
    // the app's opt-level (measured: 5x slower in the debug build).
    let resized: Option<Vec<u8>> = if (nw, nh) == (d.w, d.h) {
        None
    } else if d.alpha {
        let buf = ImageBuffer::<Rgba<u8>, Vec<u8>>::from_raw(d.w, d.h, d.data.clone())
            .ok_or(DeriveError::Format)?;
        let small = DynamicImage::ImageRgba8(buf).resize_exact(nw, nh, FilterType::Triangle);
        Some(small.into_rgba8().into_raw())
    } else {
        let buf = ImageBuffer::<Rgb<u8>, Vec<u8>>::from_raw(d.w, d.h, d.data.clone())
            .ok_or(DeriveError::Format)?;
        let small = DynamicImage::ImageRgb8(buf).resize_exact(nw, nh, FilterType::Triangle);
        Some(small.into_rgb8().into_raw())
    };
    let pixels: &[u8] = resized.as_deref().unwrap_or(&d.data);
    let enc = if d.alpha {
        webp::Encoder::from_rgba(pixels, nw, nh)
    } else {
        webp::Encoder::from_rgb(pixels, nw, nh)
    };
    let mem = enc
        .encode_simple(false, v.quality())
        .map_err(|_| DeriveError::Encode)?;
    Ok(mem.to_vec())
}

/// Build the WebP bytes of several variants of one source with ONE
/// decode. Pure (no IO). Per variant: `Ok(webp bytes)`, or the reason
/// there is none (`UseOriginal`, `Unsupported`, a decode kind).
pub fn derive_many(bytes: &[u8], vs: &[Variant]) -> Vec<Result<Vec<u8>, DeriveError>> {
    let n = vs.len();
    let fail_all = |e: DeriveError| vec![Err(e); n];
    if bytes.len() as u64 > jxl_decode::MAX_INPUT_BYTES {
        return fail_all(DeriveError::TooLarge);
    }
    let Some(src) = sniff(bytes) else {
        return fail_all(DeriveError::Unsupported);
    };
    let mut out: Vec<Option<Result<Vec<u8>, DeriveError>>> = vec![None; n];
    // JPEG/PNG: `orig` is the original bytes, always.
    if src != Src::Jxl {
        for (i, v) in vs.iter().enumerate() {
            if *v == Variant::Orig {
                out[i] = Some(Err(DeriveError::UseOriginal));
            }
        }
    }
    let wanted = |out: &[Option<_>]| vs.iter().enumerate().any(|(i, _)| out[i].is_none());
    if !wanted(&out) {
        return out.into_iter().map(|o| o.expect("all decided")).collect();
    }
    let decoded: Result<Option<Decoded>, DeriveError> = match src {
        Src::Jxl => jxl_decode::decode_pixels(bytes)
            .map_err(DeriveError::from)
            .and_then(from_jxl)
            .map(Some),
        Src::Jpeg | Src::Png => {
            let fmt = if src == Src::Jpeg { ImageFormat::Jpeg } else { ImageFormat::Png };
            let len = bytes.len() as u64;
            // The "already small" rule needs only the header: decide
            // per variant first, decode only when one variant is left.
            let mut small = vec![false; n];
            let r = decode_raster(bytes, fmt, |w, h| {
                for (i, v) in vs.iter().enumerate() {
                    if out[i].is_none() && small_enough_to_serve_as_is(len, w, h, *v) {
                        small[i] = true;
                    }
                }
                vs.iter()
                    .enumerate()
                    .any(|(i, _)| out[i].is_none() && !small[i])
            });
            for (i, s) in small.iter().enumerate() {
                if *s && out[i].is_none() {
                    out[i] = Some(Err(DeriveError::UseOriginal));
                }
            }
            r
        }
    };
    match decoded {
        Ok(Some(d)) => {
            for (i, v) in vs.iter().enumerate() {
                if out[i].is_none() {
                    out[i] = Some(encode_variant(&d, *v));
                }
            }
        }
        Ok(None) => {} // every remaining variant was decided "use original"
        Err(e) => {
            for slot in out.iter_mut().filter(|s| s.is_none()) {
                *slot = Some(Err(e));
            }
        }
    }
    out.into_iter().map(|o| o.expect("all decided")).collect()
}

/// One variant: the WebP bytes of a source (see [`derive_many`]).
pub fn derive_bytes(bytes: &[u8], v: Variant) -> Result<Vec<u8>, DeriveError> {
    derive_many(bytes, &[v]).pop().expect("one result")
}

/// Would variant `v` of this stored file need a derivative file at all
/// (`false`: the original is served, or the format has none)? A cheap
/// prediction for the pre-warm's disk estimate: it reads only the head
/// of a file, or the whole file when that is smaller than
/// [`SMALL_SOURCE_BYTES`] (then only its header dimensions are used).
pub fn needs_build(src: &Path, v: Variant) -> bool {
    use std::io::Read;
    let Ok(meta) = std::fs::metadata(src) else {
        return false;
    };
    let len = meta.len();
    let Ok(mut f) = std::fs::File::open(src) else {
        return false;
    };
    let take = len.min(SMALL_SOURCE_BYTES) as usize;
    let mut buf = vec![0u8; take];
    let mut filled = 0usize;
    while filled < take {
        match f.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(_) => return false,
        }
    }
    buf.truncate(filled);
    match sniff(&buf) {
        None => false,
        Some(Src::Jxl) => true,
        Some(src_kind) => {
            if v == Variant::Orig {
                return false;
            }
            if len >= SMALL_SOURCE_BYTES {
                return true;
            }
            let fmt = if src_kind == Src::Jpeg { ImageFormat::Jpeg } else { ImageFormat::Png };
            match image::ImageReader::with_format(Cursor::new(&buf[..]), fmt).into_dimensions() {
                Ok((w, h)) => !small_enough_to_serve_as_is(len, w, h, v),
                Err(_) => true, // undecodable: the run counts it as an error
            }
        }
    }
}

// --- the in-flight guard --------------------------------------------------------

fn flights() -> &'static (Mutex<HashSet<String>>, Condvar) {
    static F: OnceLock<(Mutex<HashSet<String>>, Condvar)> = OnceLock::new();
    F.get_or_init(|| (Mutex::new(HashSet::new()), Condvar::new()))
}

/// RAII claim on one sha: held while its derivatives are built.
struct Flight {
    key: Option<String>,
}

impl Flight {
    /// Wait (up to `wait`) until nobody else holds `sha`, then claim
    /// it. After the wait the claim is skipped and the caller builds
    /// anyway (the rename that follows keeps whichever file landed).
    fn enter(sha: &str, wait: Duration) -> Flight {
        let (m, cv) = flights();
        let deadline = Instant::now() + wait;
        let mut set = crate::lock::guard(m);
        while set.contains(sha) {
            let now = Instant::now();
            if now >= deadline {
                return Flight { key: None };
            }
            let (g, _) = cv
                .wait_timeout(set, deadline - now)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            set = g;
        }
        set.insert(sha.to_string());
        Flight { key: Some(sha.to_string()) }
    }
}

impl Drop for Flight {
    fn drop(&mut self) {
        if let Some(k) = self.key.take() {
            let (m, cv) = flights();
            crate::lock::guard(m).remove(&k);
            cv.notify_all();
        }
    }
}

// --- the cache ------------------------------------------------------------------

/// A derivative on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Derived {
    pub path: PathBuf,
    /// `true` when this call wrote the file, `false` for a cache hit.
    pub built: bool,
    /// The cache file's size.
    pub bytes: u64,
}

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

fn hit(path: &Path) -> Option<u64> {
    std::fs::metadata(path)
        .ok()
        .filter(|m| m.is_file() && m.len() > 0)
        .map(|m| m.len())
}

/// Write `webp` to `final_path` through a temp file in the same
/// directory and a rename; on a lost race the existing file is kept.
fn write_atomic(final_path: &Path, webp: &[u8]) -> Result<u64, DeriveError> {
    let dir = final_path.parent().ok_or(DeriveError::Io)?;
    std::fs::create_dir_all(dir).map_err(|_| DeriveError::Io)?;
    let stem = final_path.file_stem().and_then(|s| s.to_str()).ok_or(DeriveError::Io)?;
    let tmp = dir.join(format!(
        "{stem}.{}.{}.tmp",
        std::process::id(),
        TMP_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let write = (|| -> std::io::Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(webp)?;
        f.sync_all()
    })();
    if write.is_err() {
        let _ = std::fs::remove_file(&tmp);
        return Err(DeriveError::Io);
    }
    match std::fs::rename(&tmp, final_path) {
        Ok(()) => Ok(webp.len() as u64),
        Err(_) => {
            let _ = std::fs::remove_file(&tmp);
            // A concurrent builder may have won the rename.
            hit(final_path).ok_or(DeriveError::Io)
        }
    }
}

/// Cached derivatives of one stored file, several variants with at most
/// ONE decode. `src` is the already-containment-checked store file and
/// `sha` its content sha (its file name). One result per variant, in
/// order. Variants that are cached are returned without reading `src`.
pub fn cached_many(
    src: &Path,
    sha: &str,
    media_root: &Path,
    vs: &[Variant],
) -> Vec<Result<Derived, DeriveError>> {
    cached_many_waiting(src, sha, media_root, vs, FLIGHT_WAIT)
}

fn cached_many_waiting(
    src: &Path,
    sha: &str,
    media_root: &Path,
    vs: &[Variant],
    wait: Duration,
) -> Vec<Result<Derived, DeriveError>> {
    let n = vs.len();
    if !is_store_sha(sha) {
        return vec![Err(DeriveError::BadKey); n];
    }
    let mut res: Vec<Option<Result<Derived, DeriveError>>> = vec![None; n];
    let fill_hits = |res: &mut Vec<Option<Result<Derived, DeriveError>>>| {
        for (i, v) in vs.iter().enumerate() {
            if res[i].is_none() {
                let p = cache_path(media_root, *v, sha);
                if let Some(len) = hit(&p) {
                    res[i] = Some(Ok(Derived { path: p, built: false, bytes: len }));
                }
            }
        }
    };
    fill_hits(&mut res);
    if res.iter().all(Option::is_some) {
        return res.into_iter().map(|r| r.expect("all set")).collect();
    }
    let Ok(meta) = std::fs::metadata(src) else {
        return vec![Err(DeriveError::Io); n];
    };
    if meta.len() > jxl_decode::MAX_INPUT_BYTES {
        return vec![Err(DeriveError::TooLarge); n];
    }
    // One builder per sha; a waiter re-checks the cache afterwards.
    let _flight = Flight::enter(sha, wait);
    fill_hits(&mut res);
    let todo: Vec<usize> = (0..n).filter(|i| res[*i].is_none()).collect();
    if !todo.is_empty() {
        match std::fs::read(src) {
            Err(_) => {
                for i in &todo {
                    res[*i] = Some(Err(DeriveError::Io));
                }
            }
            Ok(bytes) => {
                let want: Vec<Variant> = todo.iter().map(|i| vs[*i]).collect();
                let built = derive_many(&bytes, &want);
                for (i, r) in todo.iter().zip(built) {
                    res[*i] = Some(r.and_then(|webp| {
                        let p = cache_path(media_root, vs[*i], sha);
                        write_atomic(&p, &webp).map(|bytes| Derived { path: p, built: true, bytes })
                    }));
                }
            }
        }
    }
    res.into_iter().map(|r| r.expect("all set")).collect()
}

/// The cached derivative for one stored file (the brief's entry point):
/// the cache file when present, else decode, resize, encode and write
/// it. `DeriveError::UseOriginal` means "serve the original bytes".
pub fn cached_derivative(
    src: &Path,
    sha: &str,
    media_root: &Path,
    v: Variant,
) -> Result<PathBuf, DeriveError> {
    cached_many(src, sha, media_root, &[v])
        .pop()
        .expect("one result")
        .map(|d| d.path)
}

/// [`cached_derivative`] for a store file whose sha is its own name;
/// a file with another name is keyed by the sha256 of its bytes. Also
/// tells whether this call built the file (for the counts-only log).
pub fn cached_derivative_file(
    src: &Path,
    media_root: &Path,
    v: Variant,
) -> Result<Derived, DeriveError> {
    let sha = match sha_from_file_name(src) {
        Some(s) => s,
        None => {
            let meta = std::fs::metadata(src).map_err(|_| DeriveError::Io)?;
            if meta.len() > jxl_decode::MAX_INPUT_BYTES {
                return Err(DeriveError::TooLarge);
            }
            let bytes = std::fs::read(src).map_err(|_| DeriveError::Io)?;
            format!("{:x}", Sha256::digest(&bytes))
        }
    };
    cached_many(src, &sha, media_root, &[v]).pop().expect("one result")
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;

    static SEQ: AtomicU64 = AtomicU64::new(0);

    fn scratch() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zr-derive-{}-{}-{}",
            std::process::id(),
            crate::shadow::schema::now_ms(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The 42-byte example codestream from the jxl-oxide crate docs
    /// (MIT OR Apache-2.0, public documentation).
    pub(crate) const TINY_JXL: [u8; 42] = [
        0xff, 0x0a, 0x30, 0x54, 0x10, 0x09, 0x08, 0x06, 0x01, 0x00, 0x78, 0x00, 0x4b, 0x38, 0x41,
        0x3c, 0xb6, 0x3a, 0x51, 0xfe, 0x00, 0x47, 0x1e, 0xa0, 0x85, 0xb8, 0x27, 0x1a, 0x48, 0x45,
        0x84, 0x1b, 0x71, 0x4f, 0xa8, 0x3e, 0x8e, 0x30, 0x03, 0x92, 0x84, 0x01,
    ];

    /// 64x32 RGB gradient JPEG with EXIF orientation 6 (rotate 90 CW:
    /// shown as 32x64). Made once with an external encoder (`image`
    /// here only decodes JPEG); 834 bytes.
    const JPEG_ORIENT6_B64: &str = concat!(
        "/9j/4AAQSkZJRgABAQAAAQABAAD/4QAiRXhpZgAATU0AKgAAAAgAAQESAAMAAAABAAYAAAAAAAD/2wBDAA0JCgsKCA0LCgsO",
        "Dg0PEyAVExISEyccHhcgLikxMC4pLSwzOko+MzZGNywtQFdBRkxOUlNSMj5aYVpQYEpRUk//2wBDAQ4ODhMREyYVFSZPNS01",
        "T09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT09PT0//wAARCAAgAEADASIAAhEBAxEB/8QA",
        "HwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKB",
        "kaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWG",
        "h4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QA",
        "HwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEI",
        "FEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOE",
        "hYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oA",
        "DAMBAAIRAxEAPwDhVt/aplt/atFbb2qZbb2r15VzjpYkzlt/apltvatFbb2qZbb2rCVc9KliTOW39qmW39q0VtvapltvasZV",
        "z06WJM5bf2qZbb2rRW29qmW29qxlXPSpYkzVtvapVtvatJbb2qZbb2rGVc/KqWJM1bb2qZbb2rSW29qlW29qxlXPSpYkzltv",
        "apltvatFbb2qZbb2rGVc9KliTOW29qmW29q0VtvapltvasZVz0qWJP/Z",
    );

    /// 1000x600 smooth-gradient JPEG (5.5 KB), no EXIF.
    const JPEG_1000X600_B64: &str = concat!(
        "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDABQODxIPDRQSEBIXFRQYHjIhHhwcHj0sLiQySUBMS0dARkVQWnNiUFVtVkVGZIhl",
        "bXd7gYKBTmCNl4x9lnN+gXz/2wBDARUXFx4aHjshITt8U0ZTfHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8fHx8",
        "fHx8fHx8fHx8fHx8fHz/wAARCAJYA+gDASIAAhEBAxEB/8QAFwABAQEBAAAAAAAAAAAAAAAAAAEFBv/EABQQAQAAAAAAAAAA",
        "AAAAAAAAAAD/xAAZAQEBAQEBAQAAAAAAAAAAAAABAAYEBQP/xAAUEQEAAAAAAAAAAAAAAAAAAAAA/9oADAMBAAIRAxEAPwDk",
        "hR7D5ooIgoEigiCiKKCIKAooJAoiigiCgKKCQKIooIgoCigiCiSCiICgoKIgKkgoCAqKCiICpIKAgKigoiAqKCgQCooKIgKi",
        "goCiipIKIgCIKAooJAoiigCCiKKCIKJIoAgoiigiCiSKAIKIooIgoiigECiKCiIKIooBAoigoiAoKCiQCooKIsIFd7HIKIoo",
        "qSCgKKKigoiiipIKAooIgoiigCCiSKCIKIooAgokigiCiKKAIKIoKJAoigoCCiKCiQKIoKAgKigoiCgSCiICooKIgKEgoiAq",
        "KCiICgoKJAKigoiAoKCiSKKigoiiigoKIooJAoCigiCiKKCQKAooIgoiigiCgSKCIKIooIgoEgoiCiLBFHexwCpIKIgKCgoi",
        "AqKCiQCgoKIooqKCiSKKCgoiigiCiKKKEgoiigiCiKKAQKIooIgoCigiCiSKCIKAooIgoiigkCgKCiIKIoKJAKCgoiCiKCiQ",
        "CgoKIgKigoiAoSCiICooKAgKkgoiAqKCgICooKJIoqKCgKKCIKJIoqKCgKKCIKIooJAoCgoiwhR3scgokAqKCiICgoKIgKkg",
        "oiAoKCiICpIKAgKigoiAqKCgQCooKIooqKCgSKCIKIooIgoEigiCiKKCIKAooJAoiigiCgKKCIKJIoAgoigoiCiSCgIKIoKI",
        "gKigoEAqKCiICooKBAKigoiAqKCgICpIKIgKCgoiAqSCiICgoKIooqSCiKKAIKIsFQegxwKBIKIgoiigCCiSKCIKIoKAgKig",
        "okAqKCgICooKJAKigoCAqKCiICpIKAgKigoiAqSCgICooKIoooKCiSKKigoiigCCiSKCIKIooAgokigiCiKKAIKIooJAoiig",
        "CCiKKCIKBIKIgoigoiAoSCiICooKIgKCgokAqKCiICgoKJAKigoiAAsIUegxqKAIKIooIgoiigECiKKCIKIooBAoiigiCgKC",
        "iIKJIoIgoCgoiAqSCiICgoKIgKigokAoKCiICooKJAKCgoiAqKCgICpIKIooqKCgIAkCiKKCIKAooIgokigiCgKKCIKJIoIg",
        "oCigiCiKKCQKAooIgoigoECiKCiIKIoKAgKkgoiAqKCgTCBXoMcgoiigCCiKKKkgoiigCCiKKCIKBIoIgoiigiCgSKCIKIoo",
        "IgoCigkCiKCiIKAoKJAoigoiCgKCiICpIKAgKigoiAqSCgICooKIgKigoEAqKCiKKKigoEiiooKIooqKCgKKKkgoiigCCiKK",
        "CQKIooAgoiigiCiSKAIKIooIgokigCCiKCiIKJMEUd7HAKigoCAqKCiQCooKAgKigokigiCgKKKigoiigkCgKKKigoiigECi",
        "KKCIKIooAgokigiCiKKAIKJIoIgoiigCAqKCiQKIoKAgKigokAoKCiICooKIgKEgoiAqKCiIChIKIgKigoiAoKCiSKKigoii",
        "igoKJIoIgoiigCCiKKCQKAooIgoigokwhR3scgoiAqKCgICpIKIgKigoCAqSCiICgoKIgKigokAoKCiKKKigokiigoKIooIg",
        "okigCCiKKCIKIooBAoiigiCiKKAIKJIoIgoCigiCiSCiICgoKIgKkgoiAoKCiICooKJAKCgoiAqKCiQCgoKIgKigoCAqSCiI",
        "CooKAgCQKIooqKCgKKCIKJMFQd7HAoigoiCgSKCIKIoKIgoCgokAqKCiICgoKJAKigoiAoKCiICpIKAgKigoiAqSCgICooKI",
        "ooqKCgSKKigoiiiooKBIoIgoiigiCgKKCQKIooAgoiigkCiKKAIKIooIgokgoCCiKCiIKJIKAgKigoiAqKCgQCooKIgKigoE",
        "AqKCiICgoKIgCTCFHexyKCIKIooJAoCigiCiKKCQKAoKIgoiigiCgSCiICoooAgKkgoiAqKCgICooKJAKigoCAqKCiQCooKA",
        "gKigoiiipIKAgKigoiiihIKIooIgoiigCCiSKCIKIooAgokigiCiKKAIKIooJAoiigCCiKCiQKAoKIgoigoiCgSCiICooKIg",
        "KEgoiwgV3scgoiigkCiKKKCgoiigiCiSKAIKIooIgokigCCiKKCIKIooBAoiigiCiKCgQKIoKIgKCgoiAqSCiICgoKIgKigo",
        "kAoKCiICooKJAKCgoiiiooKIoooSCiKKKigoCigkCiKKCIKAooIgokigiCgKKCIKJIoIgoCigiCiSKCIKAooIgoigoECiLBF",
        "HoMcAoKCiQCooKIgKCgoiAqSCiKKAIKIooqSCiKKAIKIooIgoEigiCiKKCIKBIoIgoiigiCgKKCQKIooIgoCgokAqKCiIKAo",
        "KIgKkgoCAqKCiICpIKAgKigoiAqKCgQCooKIgKigoEAqKCiKKKigoCigkCiKKCIKAooJAoiigCCiKKCIKJIKAsIFegxyCiIC",
        "hIKIgKigoCAqSCiICooKAgKigokiiooKAooqKCiSKKigoCigiCiKKCQKAooIgoiigECiKKCIKIooAgokigiCiKKAIKJIoIgo",
        "igoCAqKCiQCooKAgKigokAqKCgICooKIgKEgoiAqKCiIChIKIgKigoiAoKCiQCooKIoooKCiSKCIKIsFQd7HAokgoCCiKKCI",
        "KIoKBAKigoiAqKCgQCooKIgKigoCAqSCiICgoKIgKkgoiAoKCiKKKigokiigoKIooIgokigCCiKKCIKIooBAoiigiCgKKCQK",
        "IooIgoCigiCiSCiIKAoKIgokgoiAoKCiIKIoKJAKCgoiAqKCiQCgoKIgKigoCAqSCiIAiwhR3scigkCiKKAIKIooJAoCigiC",
        "iKCiIKBIoIgKigoiAoSCiICooKIgKCgokAqKCiICgoKJAKigoiAoKCiICpIKAooqKCiICpIKAooqKCiKKCIKBIoIgoiigiCg",
        "KKCQKIooIgoCigkCiKKAIKIooJAoigoCCiKCiIKJIKAgKigoiAqSCgICooKIsFRXexyCiSKCIKAooIgokigiCgKKCIKIooJA",
        "oCigiCiKKCQKAoKIgoigoiCgSCiIKIoKAgKkgoiAqKCgICpIKIgKigoCAqKCiQCooKAgKigokiiooKAooqKCiKKKEgoiigiC",
        "iKKKEgoiigiCiKKAIKJIoIgoiigCCiKKCQKIooAgoiigkCgKCiIKIsEUd7GgKigoiAqKCgIAkCiKKKigoCigkCiKKAIKIooI",
        "gokigCCiKKCIKJIoAgoiigiCiKKAQKIoKIgoigoECiKCiICgoKIgKkgoiAoKCiICpIKIgKCgoiAqKCiQCgoKIgKigokiigoK",
        "IooqKCgQCooKIooIgoCigkCiKKCIKAooIgokigiCgKCiTCBXoMcgoCAqKCiIChIKIgKigoiAoKCiQCooKIoooKCiSKCIKIoo",
        "AgoiigkCiKKAIKIooJAoCigiCiKKCIKBIoIgoiigiCgSKCIKIooIgoCgokAqKCiIKAoKJAKigoiAoKCiICpIKAgKigoiAqSC",
        "gICooKIgKigoEiiooKIooqKCgSKKigoiigiCgTBUHoMcCgKCiIKIoKJAoCgoiAqKCiQCgoKIgKigoCAqSCiICooKAgKkgoiA",
        "qKCgICooKJIoqKCgKKCIKJIoIgoCigiCiKKCQKAooIgoiigECiKKCIKIooAgokigiCiKCgIKJIoIgKigoCAqKCiQKIoKAgKi",
        "gokAoKCiICooKIgKEgoiAqKCiIAEwhR6DHIoIgoCigiCiSCgIKIooIgokgoCCiKCiICooKBAKigoiAqKCgQCooKIgKigoEAq",
        "KCiICgoKIgKkgoiAoKCiKKKkgoiiigoKIooqKCiSKAIKIooIgokigCCiKKCIKIooBAoiigiCgKKCQKIoKIgoCgoiCiSCiICg",
        "oKIgKkgoiAoKCiICooKJMFQd7HAoiigCCiSKCIKIooAgoiigkCiKKAIKIooJAoigoCCiKCiIKBIKIgoigoiAoSCiICooKIgK",
        "CgokAqKCiICgoKJAKigoiAoKCiICpIKAooqKCiKKKkgoCiiooKIooIgoEigiCiKKCIKBIoIgoiigiCgKKCQKIooIgoCgokCi",
        "KCgIKIoKIgokwRR3scAqKCiIChIKIgCIKAooqSCiKKCIKAooIgokigiCgKKCIKJIoIgoCigiCiKKCQKAooIgoiigECiKCiIK",
        "IoKAgKkgoiAqKCgICpIKIgKigoCAqKCiQCooKAgKigokAqKCgKKKigoiiihIKIgCIKIooBAoiigiCiKKAIKJIoIgoiigCCiS",
        "CiLCBXexyCiICpIKAgKigoiAqKCgQCooKIgKigoEiiooKIooIgoCigkCiKKCIKAooJAoiigCCiKKCIKJIoAgoiigiCiSKAIK",
        "IooIgoigoECiKCiICooKBAKigoiAoKCiICpIKIgKCgoiAqSCiICgoKIgKigokAoKCiKKKigokigCCiKKCIKAooJAoiwRR3sc",
        "CiKCiQKIoKAgKigoiAqSCgICooKIgKEgoiAqKCiICgoKJAKigoiAoKCiQCooKIooAgokiiooKIooAgoiigkCgKKCIKIooJAo",
        "CigiCiKKCIKBIoIgoiigiCgKCiQKIoKIgKCgokAqKCgIKIoKJAKigoCAqKCiICpIKAgKigoiAqSCgIAiwhR6DHIoAgokigiC",
        "gKCiIKJIoIgoCgoiCiSCiICgoKIgKigokAoKCiICooKIgKEgoiAqKCgICpIKIgKigoCAqKCiSKKigoCigiCiSKCIKAooIgok",
        "igiCgKKCIKIooBAoiigiCiKCgQKIooIgoigoCCiSCiICooKAgKigokAqKCgICooKJAKigoCwVB6DHAoEigiCiKKCIKAooJAo",
        "iigiCgKKCQKIooAgoiigiCiSCgIKIoKIgokgoCCiKCiICooKBAKigoiAqKCgQCooKIgKCgoiAqSCiICgoKIooqSCiKKKCgoi",
        "iiooKJIoAgoiigiCiSKAIKIooIgoiigECiKKCIKAooJAoigoiCgKCiIKJIKIgALCFHoMcAqSCgKKKigoiigkCgKKKigoiigC",
        "CiSKCIKIooAgokigiCiKKAIKIooJAoigoCCiKCiQKIooAgoigoiCgSCiICooKIgKEgoiAqKCiICgoKJAKigoiAoKCiQCooKI",
        "gKCgoiigkCgKKKigoiigkCgKKCIKIooIgoEigiCiKKCIKBIoIgoigoiwgV3scgokAoKCiICooKJAKCgoiAqKCiIChIKIooqK",
        "CgKKKkgoiigiCgKKCIKJIoIgoCigiCiSKCIKAooIgokigiCgKCiIKIoKJAoCgoiCiKCgQCooKIgKigoCAqSCiICooKAgKkgo",
        "iAqKCgICooKJIoqKCgKKKigoiiihIKIooIgoiigECiKKCIKIsEUd7GgoigoiAoKCiICpIKAgKigoiAqSCgICooKIgKigoEAq",
        "KCiICooKBAKigoiAIgoCigkCiKKKigoCigkCiKKAIKIooIgokigCCiKKCIKJIoAgoiigiCiKKAQKIoKIgoigoEAqKCiICgoK",
        "JAKigoiAoKCiICpIKIgKCgoiAqSCiKKKCgoigokwhR3scigiCiKKAIKJIKIgoigoCCiKCiQKIoKAgKigokAqKCgICooKIgKE",
        "goiAqKCiIChIKIgKigoiAoKCiQCooKIooAgokigiCiKKAIKIooJAoCigiCiKKCQKAooIgoiigiCgSCiIKIooIgKEgoiAqKCi",
        "ICgoKJAKigoiAoKCiQCooKAgKigokwVB3scCiKKCIKIooBAoiigiCiKKAQKIooIgoCigiCiSKCIKAoKIgokgoiCgKCiIKIoK",
        "JAKCgoiAqKCiQCgoKIgKigoiAoSCiICooKAgKkgoiiiooKAooqKCiSKKigoCigiCiSKCIKAooIgoiigkCgKKCIKIooBAoigo",
        "iCiKCgIKJIKIgKigoCAJMIUd7HAKigoiiiooKBIoIgoiigiCgSKCIKIooIgoEigiCiKKCIKAooJAoiigCCiKCiQKIoKAgoii",
        "giAqSCgIKIoKIgKkgoCAqKCiICooKBAKigoiAoKCiQCooKIgKCgoiAqSCiKKAIKIooqSCiKKAIKIooIgokigCCiKKCIKJIoA",
        "goiigiCgKCiTCBXoMcgoCAqKCiQCooKAgKigoiAqSCgICooKIooqSCgKKCIKIooAgokigiCiKKAIKJIoIgoiigCCiKKCQKIo",
        "oAgoigokCiKCgICooKJAKCgoiAqKCiIChIKIgKigoiAoKCiQCooKIgKCgokiiooKIoooKCiSKCIKIooAgoiigkCgKKCIKIoo",
        "JAoCwRR6DHAoCgoiAqSCiICgoKIgKkgoiAoKCiICpIKIgKCgoiAqKCiQCgoKIgKigoCigkCiKKCIKAooqSCiKKCIKAooIgok",
        "igiCgKKCIKJIoIgoCigiCiKKCQKAoKIgoigoECiKCiICooKBAKigoiAqKCgICpIKIgKigoCAqKCiQCooKAooqKCiSCiLCFHe",
        "xyKCIKBIoIgoigoiCgKCiQKIoKIgKCgokAqKCiICgoKIgKkgoCAqKCiICpIKAgKigoiAqKCgSKKigoiAqKCgSKCIKIooIgoC",
        "igkCiKKAIKIooJAoiigCCiKCiIKJIoAgoigoiCiSKAICooKIgKigoEAqKCiICooKBAKigoiAoKCiICpIKIsFQd7HAoiigkCg",
        "KKCIKIooAgokigiCiKKAIKJIoIgoigoCCiKCiQKIoKAgKigokAqKCgICooKJAKCgoiAqKCiIChIKIgKigoiiihIKIooqKCiK",
        "KKCgokigiCiKKAIKJIoIgoCigiCiKKCQKAooIgoiigkCgKCiIKIoKIgoEgoiCiKCiIChIKIgCLCAd7HKAiAJCgiAAigiAIig",
        "EAIigiAIigEAIigiAIigCAJCgiAIigCAJACKgIgAKgIgCSgAgCKgIgCSgAgCKgIgCKgBACKgIgCKgBACKgIgCKgAgCSgIgCI",
        "oAgCQoIgAIoIgCIoJAAIoIgCIoJAAIoIgCIoIgAQAi//2Q==",
    );

    fn b64(s: &str) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD.decode(s).unwrap()
    }

    fn png_of(img: DynamicImage) -> Vec<u8> {
        let mut v = Vec::new();
        img.write_to(&mut Cursor::new(&mut v), ImageFormat::Png).unwrap();
        v
    }

    fn solid_rgb(w: u32, h: u32) -> Vec<u8> {
        png_of(DynamicImage::ImageRgb8(image::RgbImage::from_pixel(w, h, Rgb([200, 30, 90]))))
    }

    /// Incompressible RGB noise (an LCG, no rand crate).
    fn noise_rgb(w: u32, h: u32) -> Vec<u8> {
        let mut x: u32 = 0x1234_5678;
        let img = image::RgbImage::from_fn(w, h, |_, _| {
            let mut next = || {
                x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (x >> 24) as u8
            };
            Rgb([next(), next(), next()])
        });
        png_of(DynamicImage::ImageRgb8(img))
    }

    /// (width, height, has_alpha) of a WebP, asserting the RIFF/WEBP magic.
    fn webp_info(bytes: &[u8]) -> (u32, u32, bool) {
        assert_eq!(&bytes[..4], b"RIFF");
        assert_eq!(&bytes[8..12], b"WEBP");
        let img = webp::Decoder::new(bytes).decode().expect("a valid WebP");
        (img.width(), img.height(), img.is_alpha())
    }

    fn sha_of(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    // --- sizing -----------------------------------------------------------------

    #[test]
    fn variant_sizing_math_never_upscales_and_keeps_the_aspect() {
        assert_eq!(fit_dims(3000, 2000, VIEW_EDGE), (2048, 1365));
        assert_eq!(fit_dims(2000, 3000, VIEW_EDGE), (1365, 2048));
        assert_eq!(fit_dims(3000, 2000, THUMB_EDGE), (480, 320));
        // Already within the edge: unchanged (no upscale), also exactly at it.
        assert_eq!(fit_dims(100, 50, THUMB_EDGE), (100, 50));
        assert_eq!(fit_dims(480, 300, THUMB_EDGE), (480, 300));
        assert_eq!(fit_dims(2048, 2048, VIEW_EDGE), (2048, 2048));
        assert_eq!(fit_dims(1, 1, THUMB_EDGE), (1, 1));
        // One pixel over: both sides scale.
        assert_eq!(fit_dims(481, 481, THUMB_EDGE), (480, 480));
        // Odd sizes round to nearest and the short side is never 0.
        assert_eq!(fit_dims(1001, 3, THUMB_EDGE), (480, 1));
        assert_eq!(fit_dims(3, 1001, THUMB_EDGE), (1, 480));
        assert_eq!(fit_dims(100_000, 7, THUMB_EDGE), (480, 1));
        assert_eq!(fit_dims(1000, 999, THUMB_EDGE), (480, 480)); // 479.52 rounds up
        assert_eq!(fit_dims(1000, 997, THUMB_EDGE), (480, 479)); // 478.56
        // u64 math: no overflow at the extremes.
        assert_eq!(fit_dims(u32::MAX, u32::MAX, ORIG_EDGE), (ORIG_EDGE, ORIG_EDGE));
        // Degenerate input is returned as is.
        assert_eq!(fit_dims(0, 10, 480), (0, 10));
        // The `orig` edge is the WebP maximum.
        assert_eq!(fit_dims(50_000, 1_000, ORIG_EDGE), (16383, 328));
        assert_eq!(Variant::Thumb.edge(), 480);
        assert_eq!(Variant::View.edge(), 2048);
        assert_eq!(Variant::Orig.edge(), 16383);
        assert_eq!(Variant::Thumb.quality(), 75.0);
        assert_eq!(Variant::View.quality(), 80.0);
        assert_eq!(Variant::Orig.quality(), 85.0);
    }

    #[test]
    fn the_variant_names_parse_strictly() {
        for v in [Variant::Thumb, Variant::View, Variant::Orig] {
            assert_eq!(Variant::parse(v.name()), Some(v));
        }
        for bad in ["", "Thumb", "VIEW", "full", "thumb ", "thumb,view", "ORIG", "0"] {
            assert_eq!(Variant::parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn the_use_original_rule_is_small_file_and_short_edge() {
        let k = 1024u64;
        // Smaller than 300 KB and within the edge: original.
        assert!(small_enough_to_serve_as_is(299 * k, 480, 300, Variant::Thumb));
        assert!(small_enough_to_serve_as_is(10, 2048, 100, Variant::View));
        // 300 KB or more, or one edge over: build.
        assert!(!small_enough_to_serve_as_is(300 * k, 480, 300, Variant::Thumb));
        assert!(!small_enough_to_serve_as_is(100, 481, 300, Variant::Thumb));
        assert!(!small_enough_to_serve_as_is(100, 100, 481, Variant::Thumb));
        // The same file can be original for view but built for thumb.
        assert!(small_enough_to_serve_as_is(100 * k, 1000, 800, Variant::View));
        assert!(!small_enough_to_serve_as_is(100 * k, 1000, 800, Variant::Thumb));
    }

    #[test]
    fn the_cache_path_has_the_documented_shape() {
        let root = Path::new("R");
        let sha = format!("ab{}", "c".repeat(62));
        let p = cache_path(root, Variant::Thumb, &sha);
        let comps: Vec<String> = p
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect();
        assert_eq!(comps, ["R", "cache", "img", "thumb", "ab", &format!("{sha}.webp")]);
        let dir_of = |v: Variant| {
            cache_path(root, v, &sha)
                .parent()
                .unwrap()
                .parent()
                .unwrap()
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        };
        assert_eq!(dir_of(Variant::View), "view");
        assert_eq!(dir_of(Variant::Orig), "orig");
        // The key is the sha only: two roots differ only by the root.
        assert_eq!(
            cache_path(Path::new("X"), Variant::View, &sha).strip_prefix("X").unwrap(),
            cache_path(Path::new("Y"), Variant::View, &sha).strip_prefix("Y").unwrap()
        );
        assert!(is_store_sha(&sha));
        for bad in ["", "abc", &"A".repeat(64), &"g".repeat(64), &"a".repeat(63), &"a".repeat(65)] {
            assert!(!is_store_sha(bad), "{bad:?}");
        }
    }

    // --- decode -> WebP ------------------------------------------------------------

    #[test]
    fn a_png_becomes_a_resized_webp_per_variant() {
        let png = solid_rgb(2100, 1000);
        let view = derive_bytes(&png, Variant::View).unwrap();
        assert_eq!(webp_info(&view), (2048, 975, false));
        let thumb = derive_bytes(&png, Variant::Thumb).unwrap();
        assert_eq!(webp_info(&thumb), (480, 229, false));
        // `orig` of a PNG is the original bytes, always.
        assert_eq!(derive_bytes(&png, Variant::Orig), Err(DeriveError::UseOriginal));
    }

    #[test]
    fn a_small_png_is_served_as_the_original() {
        let png = solid_rgb(100, 50);
        assert!((png.len() as u64) < SMALL_SOURCE_BYTES);
        for v in [Variant::Thumb, Variant::View, Variant::Orig] {
            assert_eq!(derive_bytes(&png, v), Err(DeriveError::UseOriginal), "{v:?}");
        }
        // Within the view edge but over the thumb edge: view serves the
        // original, thumb is built.
        let mid = solid_rgb(1000, 800);
        assert_eq!(derive_bytes(&mid, Variant::View), Err(DeriveError::UseOriginal));
        assert_eq!(webp_info(&derive_bytes(&mid, Variant::Thumb).unwrap()), (480, 384, false));
    }

    #[test]
    fn a_big_file_with_small_dimensions_is_reencoded_never_upscaled() {
        let png = noise_rgb(400, 400);
        assert!((png.len() as u64) >= SMALL_SOURCE_BYTES, "fixture must be over 300 KB");
        // Both variants rebuild at the source size (no upscale) and the
        // result is far smaller than the noise PNG.
        for v in [Variant::Thumb, Variant::View] {
            let w = derive_bytes(&png, v).unwrap();
            assert_eq!(webp_info(&w), (400, 400, false));
            assert!(w.len() < png.len());
        }
    }

    #[test]
    fn many_variants_come_from_one_decode_with_the_same_bytes() {
        let png = solid_rgb(2100, 1000);
        let both = derive_many(&png, &[Variant::Thumb, Variant::View]);
        assert_eq!(both[0].as_ref().unwrap(), &derive_bytes(&png, Variant::Thumb).unwrap());
        assert_eq!(both[1].as_ref().unwrap(), &derive_bytes(&png, Variant::View).unwrap());
        assert!(derive_many(&png, &[]).is_empty());
    }

    #[test]
    fn alpha_is_kept_and_gray_becomes_rgb() {
        let rgba = png_of(DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(
            900,
            300,
            Rgba([10, 20, 30, 128]),
        )));
        let w = derive_bytes(&rgba, Variant::Thumb).unwrap();
        assert_eq!(webp_info(&w), (480, 160, true));
        let gray = png_of(DynamicImage::ImageLuma8(image::GrayImage::from_pixel(
            700,
            100,
            image::Luma([77]),
        )));
        let w = derive_bytes(&gray, Variant::Thumb).unwrap();
        assert_eq!(webp_info(&w), (480, 69, false));
        // Gray + alpha keeps its alpha.
        let ga = png_of(DynamicImage::ImageLumaA8(image::GrayAlphaImage::from_pixel(
            700,
            100,
            image::LumaA([77, 100]),
        )));
        assert!(webp_info(&derive_bytes(&ga, Variant::Thumb).unwrap()).2);
    }

    #[test]
    fn a_jpeg_decodes_resizes_and_applies_exif_orientation() {
        // Resize path: 1000x600 -> thumb 480x288; view serves the original.
        let jpg = b64(JPEG_1000X600_B64);
        assert_eq!(&jpg[..3], &[0xFF, 0xD8, 0xFF]);
        assert!((jpg.len() as u64) < SMALL_SOURCE_BYTES);
        assert_eq!(webp_info(&derive_bytes(&jpg, Variant::Thumb).unwrap()), (480, 288, false));
        assert_eq!(derive_bytes(&jpg, Variant::View), Err(DeriveError::UseOriginal));
        assert_eq!(derive_bytes(&jpg, Variant::Orig), Err(DeriveError::UseOriginal));
        // Orientation 6: the 64x32 stored image is shown as 32x64.
        let rot = b64(JPEG_ORIENT6_B64);
        let d = decode_raster(&rot, ImageFormat::Jpeg, |_, _| true).unwrap().unwrap();
        assert_eq!((d.w, d.h), (32, 64), "EXIF orientation 6 swaps the sides");
        // The small original is simply served as is.
        assert_eq!(derive_bytes(&rot, Variant::Thumb), Err(DeriveError::UseOriginal));
    }

    #[test]
    fn the_50_megapixel_cap_refuses_from_the_header() {
        // A PNG whose IHDR says 10001 x 5001 (50.01 MP) followed by an
        // IDAT chunk header: the header is read, the cap refuses, no
        // pixel is ever decoded (there are none).
        fn crc(data: &[u8]) -> u32 {
            let mut c = 0xFFFF_FFFFu32;
            for &b in data {
                c ^= b as u32;
                for _ in 0..8 {
                    c = if c & 1 != 0 { 0xEDB8_8320 ^ (c >> 1) } else { c >> 1 };
                }
            }
            !c
        }
        fn chunk(kind: &[u8; 4], body: &[u8]) -> Vec<u8> {
            let mut v = (body.len() as u32).to_be_bytes().to_vec();
            let mut td = kind.to_vec();
            td.extend_from_slice(body);
            v.extend_from_slice(&td);
            v.extend_from_slice(&crc(&td).to_be_bytes());
            v
        }
        let big = |w: u32, h: u32| {
            let mut ihdr = w.to_be_bytes().to_vec();
            ihdr.extend_from_slice(&h.to_be_bytes());
            ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
            let mut png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
            png.extend(chunk(b"IHDR", &ihdr));
            png.extend(chunk(b"IDAT", &[0x78, 0x9C]));
            png
        };
        assert_eq!(
            derive_bytes(&big(10_001, 5_001), Variant::Thumb),
            Err(DeriveError::TooManyPixels)
        );
        assert_eq!(
            derive_bytes(&big(10_001, 5_001), Variant::View),
            Err(DeriveError::TooManyPixels)
        );
        // Exactly 50 MP passes the cap (it then fails on the missing
        // pixel data, as a plain decode error, not a cap error).
        assert_eq!(derive_bytes(&big(10_000, 5_000), Variant::Thumb), Err(DeriveError::Decode));
    }

    #[test]
    fn jpeg_xl_decodes_to_webp_for_every_variant() {
        let px = jxl_decode::decode_pixels(&TINY_JXL).unwrap();
        for v in [Variant::Thumb, Variant::View, Variant::Orig] {
            let w = derive_bytes(&TINY_JXL, v).unwrap_or_else(|e| panic!("{v:?}: {e:?}"));
            let (fw, fh) = fit_dims(px.width, px.height, v.edge());
            let (iw, ih, _) = webp_info(&w);
            assert_eq!((iw, ih), (fw, fh), "{v:?}");
        }
        // A JXL is never "use original": no WebView can show it.
        assert!(derive_many(&TINY_JXL, &[Variant::Thumb, Variant::Orig])
            .iter()
            .all(|r| r.is_ok()));
    }

    #[test]
    fn other_sources_have_no_derivative() {
        let webp_head = [b'R', b'I', b'F', b'F', 0, 0, 0, 0, b'W', b'E', b'B', b'P', 0, 0];
        for (name, bytes) in [
            ("gif", b"GIF89a\x01\x00\x01\x00".to_vec()),
            ("webp", webp_head.to_vec()),
            ("mp4", vec![0, 0, 0, 0, b'f', b't', b'y', b'p', 1, 2, 3, 4]),
            ("garbage", vec![1, 2, 3, 4, 5, 6, 7, 8]),
            ("empty", Vec::new()),
        ] {
            assert_eq!(
                derive_bytes(&bytes, Variant::View),
                Err(DeriveError::Unsupported),
                "{name}"
            );
        }
        // Right magic, broken body: a decode error.
        assert_eq!(
            derive_bytes(&[0xFF, 0xD8, 0xFF, 0xE0, 1, 2], Variant::View),
            Err(DeriveError::Decode)
        );
        assert_eq!(
            derive_bytes(&[0x89, b'P', b'N', b'G', 1, 2], Variant::View),
            Err(DeriveError::Decode)
        );
        assert_eq!(derive_bytes(&[0xFF, 0x0A, 1, 2, 3], Variant::View), Err(DeriveError::Decode));
    }

    // --- the cache -----------------------------------------------------------------

    fn store_file(root: &Path, bytes: &[u8]) -> (PathBuf, String) {
        let sha = sha_of(bytes);
        let dir = root.join(&sha[..2]).join(&sha[2..4]);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(&sha);
        std::fs::write(&p, bytes).unwrap();
        (p, sha)
    }

    fn no_temp_left(dir: &Path) -> bool {
        std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .all(|e| !e.file_name().to_string_lossy().ends_with(".tmp"))
    }

    #[test]
    fn the_cache_builds_once_reuses_and_leaves_no_temp() {
        let root = scratch();
        let png = solid_rgb(2100, 1000);
        let (src, sha) = store_file(&root, &png);
        let first = cached_many(&src, &sha, &root, &[Variant::Thumb, Variant::View]);
        let (t, v) = (first[0].clone().unwrap(), first[1].clone().unwrap());
        assert!(t.built && v.built);
        assert_eq!(t.path, cache_path(&root, Variant::Thumb, &sha));
        assert_eq!(v.path, cache_path(&root, Variant::View, &sha));
        assert!(t.bytes > 0 && t.bytes == std::fs::metadata(&t.path).unwrap().len());
        assert!(no_temp_left(t.path.parent().unwrap()) && no_temp_left(v.path.parent().unwrap()));
        // Replace the cache file's bytes: a second call REUSES it (no
        // decode, no rewrite) and does not even read the source.
        std::fs::write(&t.path, b"sentinel").unwrap();
        std::fs::remove_file(&src).unwrap();
        let again = cached_derivative(&src, &sha, &root, Variant::Thumb).unwrap();
        assert_eq!(again, t.path);
        assert_eq!(std::fs::read(&again).unwrap(), b"sentinel");
        let again = cached_many(&src, &sha, &root, &[Variant::Thumb, Variant::View]);
        assert!(again.iter().all(|r| !r.as_ref().unwrap().built));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_cache_failures_are_kinds_and_write_no_file() {
        let root = scratch();
        // Bad key.
        let (src, _) = store_file(&root, &solid_rgb(600, 600));
        for bad in ["", "xyz", &"A".repeat(64), &"a".repeat(63)] {
            assert_eq!(
                cached_derivative(&src, bad, &root, Variant::Thumb),
                Err(DeriveError::BadKey)
            );
        }
        // Missing source.
        let sha = "b".repeat(64);
        assert_eq!(
            cached_derivative(&root.join("nope"), &sha, &root, Variant::Thumb),
            Err(DeriveError::Io)
        );
        // Undecodable and unsupported sources.
        let (bad, bsha) = store_file(&root, &[0xFF, 0xD8, 0xFF, 0xE0, 1, 2, 3]);
        assert_eq!(
            cached_derivative(&bad, &bsha, &root, Variant::Thumb),
            Err(DeriveError::Decode)
        );
        let (gif, gsha) = store_file(&root, b"GIF89a\x01\x00\x01\x00");
        assert_eq!(
            cached_derivative(&gif, &gsha, &root, Variant::View),
            Err(DeriveError::Unsupported)
        );
        // UseOriginal.
        let (small, ssha) = store_file(&root, &solid_rgb(20, 20));
        assert_eq!(
            cached_derivative(&small, &ssha, &root, Variant::View),
            Err(DeriveError::UseOriginal)
        );
        // None of those wrote a cache file.
        fn count_files(d: &Path) -> usize {
            let mut n = 0;
            if let Ok(rd) = std::fs::read_dir(d) {
                for e in rd.flatten() {
                    let p = e.path();
                    n += if p.is_dir() { count_files(&p) } else { 1 };
                }
            }
            n
        }
        assert_eq!(count_files(&root.join("cache").join("img")), 0);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_non_store_file_name_is_keyed_by_the_content_sha() {
        let root = scratch();
        let png = solid_rgb(900, 900);
        let src = root.join("plainname.png");
        std::fs::write(&src, &png).unwrap();
        let d = cached_derivative_file(&src, &root, Variant::Thumb).unwrap();
        assert!(d.built);
        assert_eq!(d.path, cache_path(&root, Variant::Thumb, &sha_of(&png)));
        // A store-named file uses its own name.
        let (s2, sha2) = store_file(&root, &png);
        assert_eq!(sha_from_file_name(&s2).as_deref(), Some(sha2.as_str()));
        assert_eq!(sha_from_file_name(&src), None);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn write_atomic_keeps_a_whole_file_and_no_temp() {
        let root = scratch();
        let p = cache_path(&root, Variant::View, &"c".repeat(64));
        assert_eq!(write_atomic(&p, b"first").unwrap(), 5);
        assert!(no_temp_left(p.parent().unwrap()));
        // A second writer for the same key: the file stays whole and no
        // temp remains (whichever rename won).
        write_atomic(&p, b"second!").unwrap();
        let now = std::fs::read(&p).unwrap();
        assert!(now == b"first" || now == b"second!");
        assert!(no_temp_left(p.parent().unwrap()));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn needs_build_predicts_what_the_run_writes() {
        let root = scratch();
        let put = |name: &str, bytes: &[u8]| {
            let p = root.join(name);
            std::fs::write(&p, bytes).unwrap();
            p
        };
        let small = put("small.png", &solid_rgb(20, 20));
        let mid = put("mid.png", &solid_rgb(1000, 800));
        let noisy = put("noisy.png", &noise_rgb(400, 400));
        let jxl = put("a.jxl", &TINY_JXL);
        let gif = put("a.gif", b"GIF89a\x01\x00\x01\x00");
        let all = [Variant::Thumb, Variant::View, Variant::Orig];
        let row = |p: &Path| all.map(|v| needs_build(p, v));
        assert_eq!(row(&small), [false, false, false]);
        assert_eq!(row(&mid), [true, false, false]);
        assert_eq!(row(&noisy), [true, true, false]);
        assert_eq!(row(&jxl), [true, true, true]);
        assert_eq!(row(&gif), [false, false, false]);
        assert_eq!(row(&root.join("missing")), [false, false, false]);
        // It agrees with the real thing for every fixture and variant.
        for p in [&small, &mid, &noisy, &jxl, &gif] {
            let bytes = std::fs::read(p).unwrap();
            for v in all {
                let wrote = derive_bytes(&bytes, v).is_ok();
                assert_eq!(needs_build(p, v), wrote, "{v:?}");
            }
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    // --- the in-flight guard ---------------------------------------------------------

    #[test]
    fn the_flight_guard_waits_then_builds_anyway_and_releases() {
        let sha = format!("flight-{}", SEQ.fetch_add(1, Ordering::Relaxed));
        let first = Flight::enter(&sha, Duration::from_millis(10));
        assert!(first.key.is_some());
        // A second request times out after its wait, without a claim.
        let t0 = Instant::now();
        let second = Flight::enter(&sha, Duration::from_millis(60));
        assert!(second.key.is_none());
        assert!(t0.elapsed() >= Duration::from_millis(50));
        // Dropping the claimless one does not release the real claim.
        drop(second);
        assert!(Flight::enter(&sha, Duration::from_millis(1)).key.is_none());
        // Dropping the owner releases it at once.
        drop(first);
        let again = Flight::enter(&sha, Duration::from_millis(1));
        assert!(again.key.is_some());
        // Another sha never blocks.
        assert!(Flight::enter("other-sha", Duration::from_millis(1)).key.is_some());
    }

    #[test]
    fn concurrent_requests_for_one_sha_build_it_once() {
        let root = scratch();
        let png = noise_rgb(600, 600);
        let (src, sha) = store_file(&root, &png);
        let built = AtomicU64::new(0);
        let ok = AtomicU64::new(0);
        std::thread::scope(|s| {
            for _ in 0..6 {
                s.spawn(|| {
                    let r = cached_many(&src, &sha, &root, &[Variant::Thumb]).pop().unwrap();
                    let d = r.expect("every request gets the derivative");
                    ok.fetch_add(1, Ordering::SeqCst);
                    if d.built {
                        built.fetch_add(1, Ordering::SeqCst);
                    }
                });
            }
        });
        assert_eq!(ok.load(Ordering::SeqCst), 6);
        assert_eq!(built.load(Ordering::SeqCst), 1, "the waiters re-check the cache");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// M4 measurement harness (prints stage timings to stderr; a
    /// no-op unless `ZR_BENCH_JXL` / `ZR_BENCH_JPG` name a SYNTHETIC
    /// file). Run: `ZR_BENCH_JXL=<file> cargo test --lib bench_stages
    /// -- --nocapture`. It asserts only that the stages succeed.
    #[test]
    fn bench_stages_print_timings_when_a_bench_file_is_given() {
        let ms = |t: Instant| t.elapsed().as_secs_f64() * 1000.0;
        if let Ok(p) = std::env::var("ZR_BENCH_JXL") {
            let bytes = std::fs::read(&p).unwrap();
            let t = Instant::now();
            let slow_px = jxl_decode::decode_pixels_with(&bytes, false).unwrap();
            let t_decode_stream = ms(t);
            let t = Instant::now();
            let px = jxl_decode::decode_pixels(&bytes).unwrap();
            let t_decode = ms(t);
            let worst = px
                .data
                .iter()
                .zip(&slow_px.data)
                .map(|(a, b)| (*a as i32 - *b as i32).abs())
                .max()
                .unwrap_or(0);
            drop(slow_px);
            let t = Instant::now();
            let d = from_jxl(px).unwrap();
            let t_conv = ms(t);
            let t = Instant::now();
            let src = ImageBuffer::<Rgb<u8>, &[u8]>::from_raw(d.w, d.h, &d.data[..]).unwrap();
            let (vw, vh) = fit_dims(d.w, d.h, VIEW_EDGE);
            let rv = image::imageops::resize(&src, vw, vh, FilterType::Triangle);
            let t_resize_view = ms(t);
            let t = Instant::now();
            let (tw, th) = fit_dims(d.w, d.h, THUMB_EDGE);
            let rt = image::imageops::resize(&src, tw, th, FilterType::Triangle);
            let t_resize_thumb = ms(t);
            let dynimg = DynamicImage::ImageRgb8(
                ImageBuffer::<Rgb<u8>, Vec<u8>>::from_raw(d.w, d.h, d.data.clone()).unwrap(),
            );
            let t = Instant::now();
            let _ = dynimg.resize_exact(vw, vh, FilterType::Triangle);
            let t_exact_view = ms(t);
            let t = Instant::now();
            let _ = dynimg.resize_exact(tw, th, FilterType::Triangle);
            let t_exact_thumb = ms(t);
            let t = Instant::now();
            let wv = webp::Encoder::from_rgb(rv.as_raw(), vw, vh).encode_simple(false, 80.0).unwrap().to_vec();
            let t_enc_view = ms(t);
            let t = Instant::now();
            let wt = webp::Encoder::from_rgb(rt.as_raw(), tw, th).encode_simple(false, 75.0).unwrap().to_vec();
            let t_enc_thumb = ms(t);
            let t = Instant::now();
            let both = derive_many(&bytes, &[Variant::Thumb, Variant::View]);
            let t_both = ms(t);
            assert!(both.iter().all(|r| r.is_ok()));
            eprintln!(
                "BENCH jxl {}x{} src={}B: decode={t_decode:.0}ms (streaming reference {t_decode_stream:.0}ms, max diff {worst}) conv={t_conv:.0}ms \
                 generic_resize_view={t_resize_view:.0}ms generic_resize_thumb={t_resize_thumb:.0}ms \n                 resize_exact_view={t_exact_view:.0}ms resize_exact_thumb={t_exact_thumb:.0}ms \
                 webp_view={t_enc_view:.0}ms ({}B) webp_thumb={t_enc_thumb:.0}ms ({}B) \
                 derive_many(thumb+view)={t_both:.0}ms",
                d.w, d.h, bytes.len(), wv.len(), wt.len()
            );
        }
        if let Ok(p) = std::env::var("ZR_BENCH_JPG") {
            let bytes = std::fs::read(&p).unwrap();
            let t = Instant::now();
            let r = derive_many(&bytes, &[Variant::Thumb, Variant::View]);
            let t_both = ms(t);
            assert!(r.iter().all(|r| r.is_ok()));
            eprintln!(
                "BENCH jpeg src={}B: derive_many(thumb+view)={t_both:.0}ms (view {}B thumb {}B)",
                bytes.len(),
                r[1].as_ref().unwrap().len(),
                r[0].as_ref().unwrap().len()
            );
        }
    }
}
