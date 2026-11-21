//! Batch 27b M2: show JPEG XL in the archive viewer.
//!
//! The archive viewer runs in WebView2, which cannot render JPEG XL,
//! and most of the Zalo PC local picture cache is JXL. When the media
//! protocol is asked for an `image` row whose stored bytes are JXL
//! (bare codestream or ISO-BMFF container), the bytes are decoded to
//! 8-bit sRGB (first frame only) with the pure-Rust `jxl-oxide`,
//! encoded as a PNG with the `png` crate, cached at
//! `<media root>\cache\jxl-png\<sha>.png` (temp file + rename, reused
//! when present) and served as `image/png`.
//!
//! Rules:
//! - more than [`MAX_PIXELS`] (width x height) refuses BEFORE any
//!   frame is rendered (the header check runs as soon as the image
//!   initialises), and the decoder's allocations are capped;
//! - every failure is a plain [`JxlError`] kind (never a path, never
//!   an error text that could quote one); the caller treats it like a
//!   refused content type (404). Nothing here logs.
//! - the cache name is the store file's own sha (its file name, 64
//!   hex), else the sha256 of the bytes — the cache is content
//!   addressed, so a re-stored file never serves a stale PNG.

use std::io::Write;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// The decode refuses images above this many pixels (50 megapixels).
pub const MAX_PIXELS: u64 = 50_000_000;
/// The largest JXL file read into memory for a decode (the whole
/// serving path is for viewing; anything bigger is refused).
pub const MAX_INPUT_BYTES: u64 = 64 * 1024 * 1024;
/// Cap on the decoder's own allocations.
const ALLOC_LIMIT_BYTES: usize = 2 * 1024 * 1024 * 1024;

/// Why a JXL view could not be produced (kinds only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JxlError {
    /// The input is bigger than [`MAX_INPUT_BYTES`].
    TooLarge,
    /// width x height is above [`MAX_PIXELS`] (or zero).
    TooManyPixels,
    /// The bytes did not decode (corrupt / truncated / unsupported).
    Decode,
    /// The decoded frame is not an RGB/RGBA/gray image.
    Format,
    /// The PNG encoder failed.
    Encode,
    /// A cache file could not be read, written or renamed.
    Io,
}

/// Are these head bytes JPEG XL (either on-disk form)?
pub fn is_jxl(head: &[u8]) -> bool {
    head.starts_with(&[0xFF, 0x0A])
        || head.starts_with(&[0x00, 0x00, 0x00, 0x0C, 0x4A, 0x58, 0x4C, 0x20, 0x0D, 0x0A, 0x87, 0x0A])
}

/// The pixel-count rule: 0 < width x height <= [`MAX_PIXELS`].
pub fn pixels_ok(width: u32, height: u32) -> bool {
    let px = (width as u64) * (height as u64);
    px > 0 && px <= MAX_PIXELS
}

/// Encode interleaved 8-bit samples as a PNG. `channels` is 1 (gray),
/// 2 (gray+alpha), 3 (RGB) or 4 (RGBA); `pixels.len()` must be exactly
/// `width * height * channels`.
pub fn encode_png(
    width: u32,
    height: u32,
    channels: usize,
    pixels: &[u8],
) -> Result<Vec<u8>, JxlError> {
    let color = match channels {
        1 => png::ColorType::Grayscale,
        2 => png::ColorType::GrayscaleAlpha,
        3 => png::ColorType::Rgb,
        4 => png::ColorType::Rgba,
        _ => return Err(JxlError::Format),
    };
    if width == 0 || height == 0 {
        return Err(JxlError::Format);
    }
    let want = (width as u64)
        .checked_mul(height as u64)
        .and_then(|p| p.checked_mul(channels as u64))
        .ok_or(JxlError::Format)?;
    if want != pixels.len() as u64 {
        return Err(JxlError::Format);
    }
    let mut out = Vec::new();
    {
        let mut enc = png::Encoder::new(&mut out, width, height);
        enc.set_color(color);
        enc.set_depth(png::BitDepth::Eight);
        // Fast compression: the cache is local and the decode already
        // dominates.
        enc.set_compression(png::Compression::Fast);
        let mut w = enc.write_header().map_err(|_| JxlError::Encode)?;
        w.write_image_data(pixels).map_err(|_| JxlError::Encode)?;
        w.finish().map_err(|_| JxlError::Encode)?;
    }
    Ok(out)
}

/// Decode the first frame of a JXL byte string to a PNG (8-bit sRGB,
/// RGB or RGBA; a gray image stays gray, which every viewer treats as
/// sRGB gray).
pub fn jxl_to_png(bytes: &[u8]) -> Result<Vec<u8>, JxlError> {
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(JxlError::TooLarge);
    }
    let tracker = jxl_oxide::AllocTracker::with_limit(ALLOC_LIMIT_BYTES);
    let mut uninit = jxl_oxide::JxlImage::builder()
        .alloc_tracker(tracker)
        .build_uninit();
    // Feed in chunks until the header initialises, so the pixel cap
    // is checked before any frame data is decoded.
    let mut pos = 0usize;
    let mut image = loop {
        if pos >= bytes.len() {
            return Err(JxlError::Decode);
        }
        let end = (pos + 4096).min(bytes.len());
        uninit
            .feed_bytes(&bytes[pos..end])
            .map_err(|_| JxlError::Decode)?;
        pos = end;
        match uninit.try_init().map_err(|_| JxlError::Decode)? {
            jxl_oxide::InitializeResult::NeedMoreData(u) => uninit = u,
            jxl_oxide::InitializeResult::Initialized(img) => break img,
        }
    };
    let (w, h) = (image.width(), image.height());
    if !pixels_ok(w, h) {
        return Err(JxlError::TooManyPixels);
    }
    let px = (w as u64) * (h as u64);
    while pos < bytes.len() {
        let end = (pos + 64 * 1024).min(bytes.len());
        image
            .feed_bytes(&bytes[pos..end])
            .map_err(|_| JxlError::Decode)?;
        pos = end;
    }
    image.finalize().map_err(|_| JxlError::Decode)?;
    // 8-bit sRGB output for a colour image (a gray image keeps its
    // gray transfer curve request so no channel is invented).
    let gray = image.pixel_format().is_grayscale();
    let intent = jxl_oxide::RenderingIntent::Relative;
    image.request_color_encoding(if gray {
        jxl_oxide::EnumColourEncoding::gray_srgb(intent)
    } else {
        jxl_oxide::EnumColourEncoding::srgb(intent)
    });
    let channels = match image.pixel_format() {
        jxl_oxide::PixelFormat::Gray => 1,
        jxl_oxide::PixelFormat::Graya => 2,
        jxl_oxide::PixelFormat::Rgb => 3,
        jxl_oxide::PixelFormat::Rgba => 4,
        _ => return Err(JxlError::Format), // CMYK: no CMS in this build
    };
    let render = image.render_frame(0).map_err(|_| JxlError::Decode)?;
    let mut stream = render.stream();
    if stream.width() != w || stream.height() != h || stream.channels() as usize != channels {
        return Err(JxlError::Format);
    }
    let mut buf = vec![0u8; px as usize * channels];
    let n = stream.write_to_buffer::<u8>(&mut buf);
    if n != buf.len() {
        return Err(JxlError::Decode);
    }
    encode_png(w, h, channels, &buf)
}

/// The store file's sha: its own file name when that is 64 lowercase
/// hex (the content-addressed store name), else the sha256 of `bytes`.
fn cache_name_sha(src: &Path, bytes: &[u8]) -> String {
    if let Some(n) = src.file_name().and_then(|n| n.to_str()) {
        if n.len() == 64 && n.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            return n.to_string();
        }
    }
    format!("{:x}", Sha256::digest(bytes))
}

/// `<media root>\cache\jxl-png\<sha>.png`.
pub fn cache_path(media_root: &Path, sha: &str) -> PathBuf {
    media_root.join("cache").join("jxl-png").join(format!("{sha}.png"))
}

/// The cached PNG for one stored JXL file: reuse the cache file when
/// it exists, else decode, write `<sha>.<pid>.tmp` and rename it into
/// place. `src` is the already-containment-checked store file.
pub fn cached_png(src: &Path, media_root: &Path) -> Result<PathBuf, JxlError> {
    let meta = std::fs::metadata(src).map_err(|_| JxlError::Io)?;
    if meta.len() > MAX_INPUT_BYTES {
        return Err(JxlError::TooLarge);
    }
    // Cheap path: a store file named by its sha has a predictable
    // cache name — no read needed when it is already cached.
    if let Some(n) = src.file_name().and_then(|n| n.to_str()) {
        if n.len() == 64 && n.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
            let hit = cache_path(media_root, n);
            if hit.is_file() {
                return Ok(hit);
            }
        }
    }
    let bytes = std::fs::read(src).map_err(|_| JxlError::Io)?;
    let sha = cache_name_sha(src, &bytes);
    let final_path = cache_path(media_root, &sha);
    if final_path.is_file() {
        return Ok(final_path);
    }
    let png = jxl_to_png(&bytes)?;
    let dir = final_path.parent().ok_or(JxlError::Io)?;
    std::fs::create_dir_all(dir).map_err(|_| JxlError::Io)?;
    let tmp = dir.join(format!("{sha}.{}.tmp", std::process::id()));
    let write = (|| -> std::io::Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&png)?;
        f.sync_all()
    })();
    if write.is_err() {
        let _ = std::fs::remove_file(&tmp);
        return Err(JxlError::Io);
    }
    match std::fs::rename(&tmp, &final_path) {
        Ok(()) => Ok(final_path),
        Err(_) => {
            let _ = std::fs::remove_file(&tmp);
            // A concurrent request may have won the rename.
            if final_path.is_file() {
                Ok(final_path)
            } else {
                Err(JxlError::Io)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    fn scratch() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zr-jxl-{}-{}-{}",
            std::process::id(),
            crate::shadow::schema::now_ms(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The 42-byte example codestream from the jxl-oxide crate docs
    /// (MIT OR Apache-2.0, public documentation — nothing is fetched
    /// at test time). Whether it is gray or colour, the decode must
    /// yield a valid PNG of the header's own dimensions.
    const TINY_JXL: [u8; 42] = [
        0xff, 0x0a, 0x30, 0x54, 0x10, 0x09, 0x08, 0x06, 0x01, 0x00, 0x78, 0x00, 0x4b, 0x38, 0x41,
        0x3c, 0xb6, 0x3a, 0x51, 0xfe, 0x00, 0x47, 0x1e, 0xa0, 0x85, 0xb8, 0x27, 0x1a, 0x48, 0x45,
        0x84, 0x1b, 0x71, 0x4f, 0xa8, 0x3e, 0x8e, 0x30, 0x03, 0x92, 0x84, 0x01,
    ];

    fn png_dims(png: &[u8]) -> (u32, u32, u8) {
        assert_eq!(&png[..8], &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
        let w = u32::from_be_bytes(png[16..20].try_into().unwrap());
        let h = u32::from_be_bytes(png[20..24].try_into().unwrap());
        (w, h, png[25]) // colour type byte
    }

    #[test]
    fn is_jxl_sniffs_both_forms() {
        assert!(is_jxl(&[0xFF, 0x0A, 1]));
        assert!(is_jxl(&[
            0x00, 0x00, 0x00, 0x0C, 0x4A, 0x58, 0x4C, 0x20, 0x0D, 0x0A, 0x87, 0x0A, 9
        ]));
        assert!(!is_jxl(&[0xFF, 0xD8, 0xFF]));
        assert!(!is_jxl(&[]));
    }

    #[test]
    fn encode_png_roundtrips_dims_and_validates_lengths() {
        // 2x1 RGBA.
        let png = encode_png(2, 1, 4, &[1, 2, 3, 255, 4, 5, 6, 128]).unwrap();
        assert_eq!(png_dims(&png), (2, 1, 6));
        // RGB and gray color types.
        assert_eq!(png_dims(&encode_png(1, 1, 3, &[1, 2, 3]).unwrap()).2, 2);
        assert_eq!(png_dims(&encode_png(1, 1, 1, &[7]).unwrap()).2, 0);
        // Wrong pixel count, zero dims, bad channel count.
        assert_eq!(encode_png(2, 2, 3, &[0; 5]), Err(JxlError::Format));
        assert_eq!(encode_png(0, 2, 3, &[]), Err(JxlError::Format));
        assert_eq!(encode_png(1, 1, 5, &[0; 5]), Err(JxlError::Format));
        // The PNG decodes back to the same pixels with the png crate.
        let src: Vec<u8> = (0..3 * 4 * 3).map(|i| i as u8).collect();
        let enc = encode_png(4, 3, 3, &src).unwrap();
        let dec = png::Decoder::new(std::io::Cursor::new(enc));
        let mut r = dec.read_info().unwrap();
        let mut buf = vec![0u8; r.output_buffer_size().unwrap()];
        let info = r.next_frame(&mut buf).unwrap();
        assert_eq!((info.width, info.height), (4, 3));
        assert_eq!(&buf[..info.buffer_size()], &src[..]);
    }

    #[test]
    fn a_real_jxl_decodes_to_a_valid_png() {
        let png = jxl_to_png(&TINY_JXL).expect("the crate-docs vector must decode");
        let (w, h, ct) = png_dims(&png);
        assert!(w > 0 && h > 0 && (w as u64) * (h as u64) <= MAX_PIXELS);
        assert!(matches!(ct, 0 | 2 | 4 | 6), "color type {ct}");
        // And it decodes back through the png crate to the same size.
        let dec = png::Decoder::new(std::io::Cursor::new(&png));
        let mut r = dec.read_info().unwrap();
        let mut buf = vec![0u8; r.output_buffer_size().unwrap()];
        let info = r.next_frame(&mut buf).unwrap();
        assert_eq!((info.width, info.height), (w, h));
    }

    #[test]
    fn invalid_jxl_bytes_fail_as_decode_errors() {
        // Right magic, garbage body.
        assert_eq!(jxl_to_png(&[0xFF, 0x0A, 1, 2, 3, 4, 5, 6]), Err(JxlError::Decode));
        assert_eq!(jxl_to_png(&[]), Err(JxlError::Decode));
        // A truncated real stream.
        assert!(jxl_to_png(&TINY_JXL[..20]).is_err());
    }

    #[test]
    fn cache_reuses_the_file_and_never_leaves_a_temp() {
        let root = scratch();
        let store = root.join("ab").join("cd");
        std::fs::create_dir_all(&store).unwrap();
        // A store-style name: 64 lowercase hex.
        let sha = "a".repeat(64);
        let src = store.join(&sha);
        std::fs::write(&src, TINY_JXL).unwrap();
        let first = cached_png(&src, &root).unwrap();
        assert_eq!(first, cache_path(&root, &sha));
        assert!(first.is_file());
        let a = std::fs::read(&first).unwrap();
        // Replace the cache file's bytes: a second call must REUSE it
        // (no re-decode, no rewrite).
        std::fs::write(&first, b"sentinel").unwrap();
        let second = cached_png(&src, &root).unwrap();
        assert_eq!(second, first);
        assert_eq!(std::fs::read(&second).unwrap(), b"sentinel");
        assert!(a.starts_with(&[0x89, b'P']));
        // No temp file left behind.
        let left: Vec<_> = std::fs::read_dir(first.parent().unwrap())
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(left.is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn cache_name_falls_back_to_the_content_sha() {
        let root = scratch();
        let src = root.join("plainname.jxl");
        std::fs::write(&src, TINY_JXL).unwrap();
        let p = cached_png(&src, &root).unwrap();
        let want = format!("{:x}", Sha256::digest(TINY_JXL));
        assert_eq!(p, cache_path(&root, &want));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_decode_failure_writes_no_cache_file() {
        let root = scratch();
        let src = root.join("bad.jxl");
        std::fs::write(&src, [0xFFu8, 0x0A, 1, 2, 3, 4, 5, 6]).unwrap();
        assert_eq!(cached_png(&src, &root), Err(JxlError::Decode));
        assert!(!root.join("cache").join("jxl-png").exists()
            || std::fs::read_dir(root.join("cache").join("jxl-png")).unwrap().count() == 0);
        // A missing source is an Io error, not a panic.
        assert_eq!(cached_png(&root.join("nope"), &root), Err(JxlError::Io));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_pixel_cap_is_50_megapixels() {
        assert_eq!(MAX_PIXELS, 50_000_000);
        assert!(pixels_ok(7000, 7142)); // 49 994 000
        assert!(pixels_ok(10_000, 5_000)); // exactly 50 MP
        assert!(!pixels_ok(10_000, 5_001));
        assert!(!pixels_ok(u32::MAX, u32::MAX)); // no overflow
        assert!(!pixels_ok(0, 100));
    }
}
