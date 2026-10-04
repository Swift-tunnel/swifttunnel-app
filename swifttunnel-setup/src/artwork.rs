//! The website's petal artwork, embedded and graded into a deep, soft-focus
//! night version: the window's background. White copy reads on all of it.
use std::{cell::RefCell, io::Cursor, sync::OnceLock};
use windows::Win32::{Foundation::RECT, Graphics::Gdi::*};

struct Pixels {
    bytes: Vec<u8>,
    width: i32,
    height: i32,
}

/// Colour by how bright the artwork was: deep navy where it was cobalt, a
/// luminous cobalt where the petal was white. Stops are (luminance, RGB).
const NIGHT: [(f32, [f32; 3]); 4] = [
    (0.22, [4.0, 7.0, 30.0]),
    (0.56, [14.0, 25.0, 118.0]),
    (0.74, [27.0, 46.0, 178.0]),
    (0.97, [70.0, 96.0, 238.0]),
];

fn night(luminance: f32) -> [f32; 3] {
    let (first, last) = (NIGHT[0], NIGHT[NIGHT.len() - 1]);
    if luminance <= first.0 {
        return first.1;
    }
    for pair in NIGHT.windows(2) {
        let ((from, a), (to, b)) = (pair[0], pair[1]);
        if luminance <= to {
            let t = (luminance - from) / (to - from);
            return [0, 1, 2].map(|c| a[c] + (b[c] - a[c]) * t);
        }
    }
    last.1
}

fn smooth(from: f32, to: f32, value: f32) -> f32 {
    let t = ((value - from) / (to - from)).clamp(0.0, 1.0);
    t * t * (3.0 - 2.0 * t)
}

/// One box blur pass along rows (`step` 4) or columns (`step` a row), in place.
fn blur_lines(
    bytes: &mut [u8],
    lines: usize,
    length: usize,
    start: impl Fn(usize) -> usize,
    step: usize,
    radius: usize,
) {
    let mut line = vec![0u8; length * 4];
    let window = (radius * 2 + 1) as u32;
    for index in 0..lines {
        let base = start(index);
        for i in 0..length {
            line[i * 4..i * 4 + 4].copy_from_slice(&bytes[base + i * step..base + i * step + 4]);
        }
        for channel in 0..3 {
            let at = |i: isize| line[i.clamp(0, length as isize - 1) as usize * 4 + channel] as u32;
            let mut sum: u32 = (-(radius as isize)..=radius as isize).map(at).sum();
            for i in 0..length {
                bytes[base + i * step + channel] = (sum / window) as u8;
                sum += at(i as isize + radius as isize + 1);
                sum -= at(i as isize - radius as isize);
            }
        }
    }
}

/// Three box passes each way: close to a Gaussian, and cheap enough to run once.
fn blur(bytes: &mut [u8], width: usize, height: usize, radius: usize) {
    for _ in 0..3 {
        blur_lines(bytes, height, width, |row| row * width * 4, 4, radius);
        blur_lines(bytes, width, height, |column| column * 4, width * 4, radius);
    }
}

fn decode() -> Option<Pixels> {
    let mut reader = png::Decoder::new(Cursor::new(include_bytes!("../resources/petals.png")))
        .read_info()
        .ok()?;
    let mut bytes = vec![0; reader.output_buffer_size()];
    let info = reader.next_frame(&mut bytes).ok()?;
    if info.color_type != png::ColorType::Rgba || info.bit_depth != png::BitDepth::Eight {
        return None;
    }
    bytes.truncate(info.buffer_size());
    // The window is wider than the artwork, so it covers the window by width
    // and keeps the top.
    let width = info.width as usize;
    let rows = ((info.width as f32 * super::ASPECT).round() as usize).min(info.height as usize);
    bytes.truncate(width * rows * 4);
    for row in bytes.chunks_exact_mut(width * 4) {
        // Mirrored: the petal's body, the light, sits on the right behind the
        // card, and the copy on the left gets the dark.
        for x in 0..width / 2 {
            let (left, right) = (x * 4, (width - 1 - x) * 4);
            for c in 0..4 {
                row.swap(left + c, right + c);
            }
        }
        for pixel in row.chunks_exact_mut(4) {
            let luminance =
                (0.299 * pixel[0] as f32 + 0.587 * pixel[1] as f32 + 0.114 * pixel[2] as f32)
                    / 255.0;
            let [r, g, b] = night(luminance);
            // BGRA, as GDI wants it.
            pixel.copy_from_slice(&[b as u8, g as u8, r as u8, 255]);
        }
    }
    // Soft focus is where the depth comes from.
    blur(&mut bytes, width, rows, width / 150);
    Some(Pixels {
        bytes,
        width: info.width.try_into().ok()?,
        height: rows.try_into().ok()?,
    })
}

fn grain(x: usize, y: usize) -> f32 {
    let mut n = (x as u32)
        .wrapping_mul(374_761_393)
        .wrapping_add((y as u32).wrapping_mul(668_265_263));
    n = (n ^ (n >> 13)).wrapping_mul(1_274_126_177);
    ((n ^ (n >> 16)) & 0xffff) as f32 / 65_535.0 - 0.5
}

/// Where the light does not reach: navy, never black. BGR, like the pixels.
const SHADOW: [f32; 3] = [58.0, 14.0, 8.0];

/// Finishes the artwork at the size it is shown: the light falls away from the
/// upper right towards the edges, the status row at the bottom gets the
/// darkest part, and a fine grain keeps the gradients from banding.
fn finish(pixels: &mut [u8], width: usize, height: usize) {
    let (w, h) = (width as f32, height as f32);
    for (y, row) in pixels.chunks_exact_mut(width * 4).enumerate() {
        let v = y as f32 / h;
        let floor = 1.0 - 0.52 * smooth(0.58, 0.97, v);
        for (x, pixel) in row.chunks_exact_mut(4).enumerate() {
            let (dx, dy) = ((x as f32 / w - 0.68) * (w / h), v - 0.34);
            let light = floor * (1.0 - 0.64 * smooth(0.22, 1.18, (dx * dx + dy * dy).sqrt()));
            let noise = grain(x, y) * 9.0;
            for (channel, shadow) in pixel[..3].iter_mut().zip(SHADOW) {
                let lit = *channel as f32 * light + shadow * (1.0 - light) * 0.6;
                *channel = (lit + noise).clamp(0.0, 255.0) as u8;
            }
        }
    }
}

/// The artwork scaled to one window size, kept so a repaint is a plain copy.
struct Scaled {
    width: i32,
    height: i32,
    bitmap: HBITMAP,
}

thread_local! {
    static SCALED: RefCell<Option<Scaled>> = const { RefCell::new(None) };
}

unsafe fn scale(image: &Pixels, width: i32, height: i32) -> Option<HBITMAP> {
    let source = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: image.width,
            biHeight: -image.height,
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB.0,
            ..Default::default()
        },
        ..Default::default()
    };
    let target = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biWidth: width,
            biHeight: -height,
            ..source.bmiHeader
        },
        ..Default::default()
    };
    let dc = CreateCompatibleDC(None);
    let mut bits = std::ptr::null_mut();
    let bitmap = CreateDIBSection(Some(dc), &target, DIB_RGB_COLORS, &mut bits, None, 0).ok();
    if let Some(bitmap) = bitmap {
        let previous = SelectObject(dc, bitmap.into());
        SetStretchBltMode(dc, HALFTONE);
        let _ = SetBrushOrgEx(dc, 0, 0, None);
        StretchDIBits(
            dc,
            0,
            0,
            width,
            height,
            0,
            0,
            image.width,
            image.height,
            Some(image.bytes.as_ptr().cast()),
            &source,
            DIB_RGB_COLORS,
            SRCCOPY,
        );
        SelectObject(dc, previous);
        let _ = GdiFlush();
        if !bits.is_null() && width > 0 && height > 0 {
            let (width, height) = (width as usize, height as usize);
            // The section's own pixels: top-down BGRA, width * height * 4 bytes.
            finish(
                std::slice::from_raw_parts_mut(bits.cast::<u8>(), width * height * 4),
                width,
                height,
            );
        }
    }
    let _ = DeleteDC(dc);
    bitmap
}

pub unsafe fn paint(dc: HDC, bounds: RECT) {
    static IMAGE: OnceLock<Option<Pixels>> = OnceLock::new();
    let Some(image) = IMAGE.get_or_init(decode) else {
        return;
    };
    let (width, height) = (bounds.right - bounds.left, bounds.bottom - bounds.top);
    SCALED.with_borrow_mut(|scaled| {
        if !scaled
            .as_ref()
            .is_some_and(|s| s.width == width && s.height == height)
        {
            if let Some(old) = scaled.take() {
                let _ = DeleteObject(old.bitmap.into());
            }
            *scaled = scale(image, width, height).map(|bitmap| Scaled {
                width,
                height,
                bitmap,
            });
        }
        if let Some(scaled) = scaled {
            let source = CreateCompatibleDC(Some(dc));
            let previous = SelectObject(source, scaled.bitmap.into());
            let _ = BitBlt(
                dc,
                bounds.left,
                bounds.top,
                width,
                height,
                Some(source),
                0,
                0,
                SRCCOPY,
            );
            SelectObject(source, previous);
            let _ = DeleteDC(source);
        }
    });
}
