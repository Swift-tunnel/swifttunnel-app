//! A cached, embedded copy of the website's petal artwork, in its own colours.
use std::{io::Cursor, sync::OnceLock};
use windows::Win32::{Foundation::RECT, Graphics::Gdi::*};

struct Pixels {
    bytes: Vec<u8>,
    width: i32,
    height: i32,
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
    // and keeps the top, the way the website's hero shows it: the pale petal
    // band behind the ink copy, the cobalt below it.
    let width = info.width as usize;
    let rows = ((info.width as f32 * super::ASPECT).round() as usize).min(info.height as usize);
    bytes.truncate(width * rows * 4);
    for (index, pixel) in bytes.chunks_exact_mut(4).enumerate() {
        let y = (index / width) as f32 / rows as f32;
        // The bottom deepens to cobalt so white status text and buttons read
        // on it wherever the petal's edge happens to fall.
        let t = ((y - 0.70) / 0.17).clamp(0.0, 1.0);
        let fade = t * t * (3.0 - 2.0 * t) * 0.9;
        for (channel, deep) in [24.0, 36.0, 150.0].iter().enumerate() {
            pixel[channel] = (pixel[channel] as f32 * (1.0 - fade) + deep * fade) as u8;
        }
        pixel.swap(0, 2);
    }
    Some(Pixels {
        bytes,
        width: info.width.try_into().ok()?,
        height: rows.try_into().ok()?,
    })
}

pub unsafe fn paint(dc: HDC, bounds: RECT) {
    static IMAGE: OnceLock<Option<Pixels>> = OnceLock::new();
    if let Some(image) = IMAGE.get_or_init(decode) {
        let info = BITMAPINFO {
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
        let old_mode = SetStretchBltMode(dc, HALFTONE);
        let mut origin = windows::Win32::Foundation::POINT::default();
        let _ = SetBrushOrgEx(dc, 0, 0, Some(&mut origin));
        StretchDIBits(
            dc,
            bounds.left,
            bounds.top,
            bounds.right - bounds.left,
            bounds.bottom - bounds.top,
            0,
            0,
            image.width,
            image.height,
            Some(image.bytes.as_ptr().cast()),
            &info,
            DIB_RGB_COLORS,
            SRCCOPY,
        );
        SetStretchBltMode(dc, STRETCH_BLT_MODE(old_mode));
        let _ = SetBrushOrgEx(dc, origin.x, origin.y, None);
    }
}
