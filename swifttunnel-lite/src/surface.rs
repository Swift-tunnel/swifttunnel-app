//! Gets the software-rendered surface onto the screen.
//!
//! The window is drawn in two passes. Shapes are composited in [`crate::canvas`]
//! because GDI cannot antialias them, then blitted here in one copy, and text is
//! drawn by GDI straight onto the result. Splitting it that way keeps the good
//! half of GDI (its text rasteriser, which already has the embedded faces) and
//! replaces the half that was making every card look like a Windows 95 dialog.
//!
//! Nothing is cached. Repainting only happens when something actually changed,
//! since nothing in Lite animates, so a few hundred thousand pixels of work on
//! a state change is cheaper than the bookkeeping to avoid it.

use std::ffi::c_void;

use windows::Win32::Graphics::Gdi::{
    BI_RGB, BITMAPINFO, BITMAPINFOHEADER, BitBlt, CreateCompatibleDC, CreateDIBSection,
    DIB_RGB_COLORS, DeleteDC, DeleteObject, HDC, HGDIOBJ, SRCCOPY, SelectObject,
};

use crate::canvas::Canvas;


/// Copy a finished canvas to the window.
pub fn blit(dc: HDC, canvas: &Canvas) {
    if canvas.width <= 0 || canvas.height <= 0 {
        return;
    }

    let header = BITMAPINFOHEADER {
        biSize: size_of::<BITMAPINFOHEADER>() as u32,
        biWidth: canvas.width,
        // Negative height gives a top-down DIB, so row 0 is the top and the
        // buffer reads the way the canvas was written.
        biHeight: -canvas.height,
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
    let bitmap = unsafe { CreateDIBSection(None, &info, DIB_RGB_COLORS, &mut bits, None, 0) };
    let Ok(bitmap) = bitmap else {
        return;
    };
    if bits.is_null() {
        unsafe {
            let _ = DeleteObject(HGDIOBJ(bitmap.0));
        }
        return;
    }

    // SAFETY: CreateDIBSection returned a buffer of exactly width * height
    // 32-bit pixels and nothing else refers to it.
    let out = unsafe {
        std::slice::from_raw_parts_mut(bits as *mut u32, (canvas.width * canvas.height) as usize)
    };
    canvas.write_bgrx(out);

    unsafe {
        let mem = CreateCompatibleDC(Some(dc));
        if !mem.is_invalid() {
            let previous = SelectObject(mem, HGDIOBJ(bitmap.0));
            let _ = BitBlt(
                dc,
                0,
                0,
                canvas.width,
                canvas.height,
                Some(mem),
                0,
                0,
                SRCCOPY,
            );
            SelectObject(mem, previous);
            let _ = DeleteDC(mem);
        }
        let _ = DeleteObject(HGDIOBJ(bitmap.0));
    }
}
