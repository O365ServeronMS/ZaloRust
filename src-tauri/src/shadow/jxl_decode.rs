//! Batch 27b M2 / batch 28 M1: decode JPEG XL for the archive viewer.
//!
//! The archive viewer runs in WebView2, which cannot render JPEG XL,
//! and most of the Zalo PC local picture cache is JXL. This module
//! decodes the first frame of a JXL byte string (bare codestream or
//! ISO-BMFF container) to 8-bit sRGB pixels with the pure-Rust
//! `jxl-oxide`. Batch 28 moved the encoding half to
//! [`super::img_derive`], which turns the pixels into cached WebP
//! derivatives (a full-size PNG per image was ~3.7 MB; the WebP
//! thumb/view derivatives are 17 KB / 198 KB on average).
//!
//! Rules:
//! - more than [`MAX_PIXELS`] (width x height) refuses BEFORE any
//!   frame is rendered (the header check runs as soon as the image
//!   initialises), and the decoder's allocations are capped;
//! - every failure is a plain [`JxlError`] kind (never a path, never
//!   an error text that could quote one); the caller treats it like a
//!   refused content type (404). Nothing here logs.

/// The decode refuses images above this many pixels (50 megapixels).
pub const MAX_PIXELS: u64 = 50_000_000;
/// The largest JXL file read into memory for a decode (the whole
/// serving path is for viewing; anything bigger is refused).
pub const MAX_INPUT_BYTES: u64 = 64 * 1024 * 1024;
/// Cap on the decoder's own allocations.
const ALLOC_LIMIT_BYTES: usize = 2 * 1024 * 1024 * 1024;

/// Why a JXL decode failed (kinds only).
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

/// One decoded frame: interleaved 8-bit samples, `channels` 1 (gray),
/// 2 (gray+alpha), 3 (RGB) or 4 (RGBA); `data.len()` is exactly
/// `width * height * channels`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JxlPixels {
    pub width: u32,
    pub height: u32,
    pub channels: usize,
    pub data: Vec<u8>,
}

/// Up to this many pixels the f32 -> u8 conversion goes through the
/// optimised non-generic entry points (see [`decode_pixels`]); above it
/// the streaming path is used, because the interleaved f32 copy would
/// cost 12-16 bytes per pixel more (a 12 MP RGBA frame is ~190 MB).
pub const FAST_CONVERT_MAX_PIXELS: u64 = 12_000_000;

/// Decode the first frame of a JXL byte string to 8-bit sRGB pixels
/// (a gray image stays gray, which every viewer treats as sRGB gray).
///
/// Debug-build speed (batch 28 M4): `ImageStream::write_to_buffer::<u8>`
/// is generic, so it is instantiated in the APP crate at the app's
/// opt-level (0 in a debug build) however the `jxl-*` crates are built;
/// that loop alone took 330-400 ms of a 3000x2000 decode. For an RGB or
/// RGBA frame of up to [`FAST_CONVERT_MAX_PIXELS`] the decode therefore
/// takes the non-generic `Render::image_all_channels` (inside jxl-oxide)
/// and converts with `DynamicImage::into_rgb8/into_rgba8` (inside
/// `image`), both built at opt-level 3 by the profile overrides. Gray,
/// gray+alpha, frames with extra channels and bigger frames keep the
/// streaming path, which is the reference behaviour.
pub fn decode_pixels(bytes: &[u8]) -> Result<JxlPixels, JxlError> {
    decode_pixels_with(bytes, true)
}

pub(crate) fn decode_pixels_with(bytes: &[u8], fast: bool) -> Result<JxlPixels, JxlError> {
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
    if fast && (3..=4).contains(&channels) && px <= FAST_CONVERT_MAX_PIXELS {
        let fb = render.image_all_channels();
        // Only the plain colour(+alpha) layout; anything else (extra
        // channels, an oriented frame whose size differs) takes the
        // streaming path below.
        if fb.channels() == channels
            && fb.width() as u64 == w as u64
            && fb.height() as u64 == h as u64
            && fb.buf().len() as u64 == px * channels as u64
        {
            let data = if channels == 3 {
                image::Rgb32FImage::from_raw(w, h, fb.buf().to_vec())
                    .map(|b| image::DynamicImage::ImageRgb32F(b).into_rgb8().into_raw())
            } else {
                image::Rgba32FImage::from_raw(w, h, fb.buf().to_vec())
                    .map(|b| image::DynamicImage::ImageRgba32F(b).into_rgba8().into_raw())
            };
            if let Some(data) = data {
                if data.len() as u64 == px * channels as u64 {
                    return Ok(JxlPixels { width: w, height: h, channels, data });
                }
            }
        }
    }
    let mut stream = render.stream();
    if stream.width() != w || stream.height() != h || stream.channels() as usize != channels {
        return Err(JxlError::Format);
    }
    let mut buf = vec![0u8; px as usize * channels];
    let n = stream.write_to_buffer::<u8>(&mut buf);
    if n != buf.len() {
        return Err(JxlError::Decode);
    }
    Ok(JxlPixels {
        width: w,
        height: h,
        channels,
        data: buf,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The 42-byte example codestream from the jxl-oxide crate docs
    /// (MIT OR Apache-2.0, public documentation — nothing is fetched
    /// at test time).
    pub(crate) const TINY_JXL: [u8; 42] = [
        0xff, 0x0a, 0x30, 0x54, 0x10, 0x09, 0x08, 0x06, 0x01, 0x00, 0x78, 0x00, 0x4b, 0x38, 0x41,
        0x3c, 0xb6, 0x3a, 0x51, 0xfe, 0x00, 0x47, 0x1e, 0xa0, 0x85, 0xb8, 0x27, 0x1a, 0x48, 0x45,
        0x84, 0x1b, 0x71, 0x4f, 0xa8, 0x3e, 0x8e, 0x30, 0x03, 0x92, 0x84, 0x01,
    ];

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
    fn a_real_jxl_decodes_to_pixels_of_its_header_size() {
        let px = decode_pixels(&TINY_JXL).expect("the crate-docs vector must decode");
        assert!(px.width > 0 && px.height > 0);
        assert!((px.width as u64) * (px.height as u64) <= MAX_PIXELS);
        assert!((1..=4).contains(&px.channels), "channels {}", px.channels);
        assert_eq!(
            px.data.len(),
            px.width as usize * px.height as usize * px.channels
        );
    }

    /// The fast conversion (f32 frame -> `image`) and the streaming
    /// reference path must agree (within one level of rounding).
    #[test]
    fn the_fast_and_streaming_conversions_agree() {
        let fast = decode_pixels_with(&TINY_JXL, true).unwrap();
        let slow = decode_pixels_with(&TINY_JXL, false).unwrap();
        assert_eq!(
            (fast.width, fast.height, fast.channels),
            (slow.width, slow.height, slow.channels)
        );
        assert_eq!(fast.data.len(), slow.data.len());
        let worst = fast
            .data
            .iter()
            .zip(&slow.data)
            .map(|(a, b)| (*a as i32 - *b as i32).abs())
            .max()
            .unwrap_or(0);
        assert!(worst <= 1, "fast vs streaming differ by {worst}");
    }

    #[test]
    fn invalid_jxl_bytes_fail_as_decode_errors() {
        // Right magic, garbage body.
        assert_eq!(decode_pixels(&[0xFF, 0x0A, 1, 2, 3, 4, 5, 6]), Err(JxlError::Decode));
        assert_eq!(decode_pixels(&[]), Err(JxlError::Decode));
        // A truncated real stream.
        assert!(decode_pixels(&TINY_JXL[..20]).is_err());
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
