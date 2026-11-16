//! Decoding, hashing and thumbnailing for image clips.

use anyhow::{anyhow, Result};
use image::{imageops::FilterType, ImageFormat};
use sha2::{Digest, Sha256};
use std::io::Cursor;

/// Longest edge of the thumbnail shown in the history list.
const THUMB_MAX: u32 = 160;

pub struct ImageClip {
    pub png: Vec<u8>,
    pub thumb_png: Vec<u8>,
    pub width: u32,
    pub height: u32,
    pub hash: String,
}

/// Identity is the decoded pixels, not the encoded file.
///
/// Copying an image back out of the history re-encodes it through a different
/// PNG writer, so the bytes change while the picture does not. Hashing pixels
/// keeps dedupe and echo-suppression working across that round trip.
fn pixel_hash(width: u32, height: u32, rgba: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(width.to_le_bytes());
    h.update(height.to_le_bytes());
    h.update(rgba);
    format!("{:x}", h.finalize())
}

pub fn prepare(bytes: &[u8]) -> Result<ImageClip> {
    let img = image::load_from_memory(bytes)
        .map_err(|e| anyhow!("unrecognised image data: {e}"))?;
    let rgba = img.to_rgba8();
    let (width, height) = rgba.dimensions();
    if width == 0 || height == 0 {
        return Err(anyhow!("image has no pixels"));
    }
    let hash = pixel_hash(width, height, rgba.as_raw());

    // Normalise to PNG so the store holds one format whatever was offered.
    let mut png = Vec::new();
    img.write_to(&mut Cursor::new(&mut png), ImageFormat::Png)?;

    let mut thumb_png = Vec::new();
    img.resize(THUMB_MAX, THUMB_MAX, FilterType::Triangle)
        .write_to(&mut Cursor::new(&mut thumb_png), ImageFormat::Png)?;

    Ok(ImageClip { png, thumb_png, width, height, hash })
}

/// Decodes a stored PNG back to the raw RGBA that the clipboard wants.
pub fn to_rgba(png: &[u8]) -> Result<(u32, u32, Vec<u8>)> {
    let rgba = image::load_from_memory(png)
        .map_err(|e| anyhow!("stored image is unreadable: {e}"))?
        .to_rgba8();
    let (w, h) = rgba.dimensions();
    Ok((w, h, rgba.into_raw()))
}

pub fn human_size(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.0} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png_fixture(w: u32, h: u32, shade: u8) -> Vec<u8> {
        let img = image::RgbaImage::from_fn(w, h, |x, _| {
            image::Rgba([shade, (x % 256) as u8, 128, 255])
        });
        let mut out = Vec::new();
        image::DynamicImage::ImageRgba8(img)
            .write_to(&mut Cursor::new(&mut out), ImageFormat::Png)
            .unwrap();
        out
    }

    #[test]
    fn prepares_dimensions_and_thumbnail() {
        let c = prepare(&png_fixture(400, 200, 10)).unwrap();
        assert_eq!((c.width, c.height), (400, 200));
        assert!(!c.png.is_empty() && !c.thumb_png.is_empty());
        assert!(c.thumb_png.len() < c.png.len(), "thumbnail should be smaller");
    }

    #[test]
    fn hash_follows_pixels_not_encoding() {
        let original = png_fixture(60, 40, 7);
        let once = prepare(&original).unwrap();
        // Re-encoding the image the way a clipboard round trip would.
        let twice = prepare(&once.png).unwrap();
        assert_eq!(once.hash, twice.hash);
    }

    #[test]
    fn different_images_hash_differently() {
        assert_ne!(
            prepare(&png_fixture(60, 40, 7)).unwrap().hash,
            prepare(&png_fixture(60, 40, 9)).unwrap().hash
        );
    }

    #[test]
    fn rgba_round_trip_preserves_size() {
        let c = prepare(&png_fixture(32, 24, 3)).unwrap();
        let (w, h, rgba) = to_rgba(&c.png).unwrap();
        assert_eq!((w, h), (32, 24));
        assert_eq!(rgba.len(), 32 * 24 * 4);
    }

    #[test]
    fn rejects_junk() {
        assert!(prepare(b"not an image at all").is_err());
    }
}
