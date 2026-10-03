//! A cached, embedded copy of the website's petal artwork.
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
    for (index, pixel) in bytes.chunks_exact_mut(4).enumerate() {
        let y = (index / info.width as usize) as f32 / info.height as f32;
        // Blue-violet tint with a quiet dark lower edge behind the controls.
        let fade = ((y - 0.42) / 0.58).clamp(0.0, 1.0).powi(2) * 0.88;
        for (channel, tint) in [0.22, 0.18, 0.36].iter().enumerate() {
            let shaded = pixel[channel] as f32 * tint;
            pixel[channel] = (shaded * (1.0 - fade) + [15.0, 13.0, 23.0][channel] * fade) as u8;
        }
        pixel.swap(0, 2);
    }
    Some(Pixels {
        bytes,
        width: info.width.try_into().ok()?,
        height: info.height.try_into().ok()?,
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
