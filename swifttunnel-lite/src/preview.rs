//! Render the window to an image file without showing a window.
//!
//! Lite runs elevated, and Windows refuses a non-elevated process any control
//! over an elevated process's window: `SetWindowPos` returns ERROR_ACCESS_DENIED
//! and the window cannot be raised, moved or reliably captured from outside.
//! Which means the only way to see what a change looks like was to ask a human
//! to look at their screen, and visual work with no feedback loop is how three
//! attempts at this UI shipped looking wrong.
//!
//! So the same paint path runs against an offscreen bitmap and is written out
//! as a BMP. Same code, same fonts, same layout, no window and no elevation.
//! BMP rather than PNG purely to avoid an encoder dependency for a dev tool:
//! the header is a dozen fields and every image viewer reads it.
//!
//! Reached with `swifttunnel-lite --preview <path> [--connected]`.

use std::ffi::c_void;
use std::io::Write;

use windows::Win32::Foundation::RECT;
use windows::Win32::Graphics::Gdi::{
    BI_RGB, BITMAPINFO, BITMAPINFOHEADER, CreateCompatibleDC, CreateDIBSection, DIB_RGB_COLORS,
    DeleteDC, DeleteObject, HDC, HGDIOBJ, SelectObject,
};

/// Paint into an offscreen surface and write it out.
///
/// The closure is handed exactly what `WM_PAINT` would hand the real window, so
/// there is no second rendering path to keep in step with the first.
pub fn render<F>(path: &str, width: i32, height: i32, paint: F) -> std::io::Result<()>
where
    F: FnOnce(HDC, RECT),
{
    if width <= 0 || height <= 0 {
        return Err(std::io::Error::other("preview size must be positive"));
    }

    let header = BITMAPINFOHEADER {
        biSize: size_of::<BITMAPINFOHEADER>() as u32,
        biWidth: width,
        // Top-down, matching the canvas, so the rows need no flipping until the
        // BMP itself demands it below.
        biHeight: -height,
        biPlanes: 1,
        biBitCount: 32,
        biCompression: BI_RGB.0,
        ..Default::default()
    };
    let info = BITMAPINFO {
        bmiHeader: header,
        ..Default::default()
    };

    let mut bits: *mut c_void = std::ptr::null_mut();

    // SAFETY: standard offscreen DC setup. Every handle created here is
    // released before returning, on both the success and failure paths.
    unsafe {
        let dc = CreateCompatibleDC(None);
        if dc.is_invalid() {
            return Err(std::io::Error::other("could not create a memory DC"));
        }

        let bitmap = match CreateDIBSection(Some(dc), &info, DIB_RGB_COLORS, &mut bits, None, 0) {
            Ok(bitmap) if !bits.is_null() => bitmap,
            _ => {
                let _ = DeleteDC(dc);
                return Err(std::io::Error::other("could not create the preview bitmap"));
            }
        };

        let previous = SelectObject(dc, HGDIOBJ(bitmap.0));

        paint(
            dc,
            RECT {
                left: 0,
                top: 0,
                right: width,
                bottom: height,
            },
        );

        let pixels =
            std::slice::from_raw_parts(bits as *const u32, (width * height) as usize).to_vec();

        SelectObject(dc, previous);
        let _ = DeleteObject(HGDIOBJ(bitmap.0));
        let _ = DeleteDC(dc);

        write_bmp(path, width, height, &pixels)
    }
}

/// A 32bpp bottom-up BMP, which is the layout the format assumes by default.
fn write_bmp(path: &str, width: i32, height: i32, pixels: &[u32]) -> std::io::Result<()> {
    let pixel_bytes = (width * height * 4) as u32;
    let offset = 14u32 + 40u32;
    let mut out = Vec::with_capacity((offset + pixel_bytes) as usize);

    // BITMAPFILEHEADER
    out.extend_from_slice(b"BM");
    out.extend_from_slice(&(offset + pixel_bytes).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&offset.to_le_bytes());

    // BITMAPINFOHEADER
    out.extend_from_slice(&40u32.to_le_bytes());
    out.extend_from_slice(&width.to_le_bytes());
    out.extend_from_slice(&height.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&32u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&pixel_bytes.to_le_bytes());
    out.extend_from_slice(&2835i32.to_le_bytes());
    out.extend_from_slice(&2835i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());

    // Rows bottom-up, and the alpha byte forced opaque: GDI text leaves it at
    // zero, which some viewers honour and render as a fully transparent image.
    for y in (0..height).rev() {
        for x in 0..width {
            let p = pixels[(y * width + x) as usize] | 0xFF00_0000;
            out.extend_from_slice(&p.to_le_bytes());
        }
    }

    let mut file = std::fs::File::create(path)?;
    file.write_all(&out)?;
    Ok(())
}
