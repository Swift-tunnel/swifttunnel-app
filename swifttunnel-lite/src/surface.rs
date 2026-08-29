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
    DIB_RGB_COLORS, DeleteDC, DeleteObject, HBITMAP, HDC, HGDIOBJ, SRCCOPY, SelectObject,
};

use crate::canvas::Canvas;


/// An offscreen surface that everything is drawn into before it reaches the
/// window.
///
/// Shapes used to be blitted straight to the window and the text drawn on top
/// of it afterwards, which put two separate operations on screen for every
/// repaint: the background first, then the words. A repaint or two is invisible
/// but typing produces a stream of them, and the gap between the two shows up
/// as the whole interface flickering.
///
/// Kept between paints rather than rebuilt, which also drops a DIB allocation
/// per frame.
pub struct Buffer {
    dc: HDC,
    bitmap: HBITMAP,
    bits: *mut u32,
    width: i32,
    height: i32,
}

impl Buffer {
    pub fn new() -> Self {
        Self {
            dc: HDC::default(),
            bitmap: HBITMAP::default(),
            bits: std::ptr::null_mut(),
            width: 0,
            height: 0,
        }
    }

    /// Point the buffer at a surface of this size, rebuilding only on a change.
    fn ensure(&mut self, reference: HDC, width: i32, height: i32) -> bool {
        if width <= 0 || height <= 0 {
            return false;
        }
        if !self.dc.is_invalid() && self.width == width && self.height == height {
            return true;
        }
        self.release();

        let header = BITMAPINFOHEADER {
            biSize: size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: width,
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

        // SAFETY: the bitmap is owned here and released in release()/Drop.
        unsafe {
            let mut bits: *mut c_void = std::ptr::null_mut();
            let Ok(bitmap) = CreateDIBSection(None, &info, DIB_RGB_COLORS, &mut bits, None, 0)
            else {
                return false;
            };
            if bits.is_null() {
                let _ = DeleteObject(HGDIOBJ(bitmap.0));
                return false;
            }
            let dc = CreateCompatibleDC(Some(reference));
            if dc.is_invalid() {
                let _ = DeleteObject(HGDIOBJ(bitmap.0));
                return false;
            }
            SelectObject(dc, HGDIOBJ(bitmap.0));

            self.dc = dc;
            self.bitmap = bitmap;
            self.bits = bits as *mut u32;
            self.width = width;
            self.height = height;
        }
        true
    }

    /// Prepare a surface of this size and hand back the context for it.
    pub fn begin(&mut self, reference: HDC, width: i32, height: i32) -> Option<HDC> {
        self.ensure(reference, width, height).then_some(self.dc)
    }

    /// Copy the composited shapes in, under whatever text is drawn after.
    pub fn fill_from(&mut self, canvas: &Canvas) {
        if self.bits.is_null() || canvas.width != self.width || canvas.height != self.height {
            return;
        }
        // SAFETY: the section was created with exactly this many pixels.
        let out = unsafe {
            std::slice::from_raw_parts_mut(self.bits, (self.width * self.height) as usize)
        };
        canvas.write_bgrx(out);
    }

    /// One operation, so the window never shows a half-drawn frame.
    pub fn present(&self, dst: HDC) {
        if self.dc.is_invalid() {
            return;
        }
        // SAFETY: both contexts are live for the duration of the call.
        unsafe {
            let _ = BitBlt(
                dst,
                0,
                0,
                self.width,
                self.height,
                Some(self.dc),
                0,
                0,
                SRCCOPY,
            );
        }
    }

    fn release(&mut self) {
        // SAFETY: each handle is deleted once and then cleared.
        unsafe {
            if !self.dc.is_invalid() {
                let _ = DeleteDC(self.dc);
                self.dc = HDC::default();
            }
            if !self.bitmap.is_invalid() {
                let _ = DeleteObject(HGDIOBJ(self.bitmap.0));
                self.bitmap = HBITMAP::default();
            }
        }
        self.bits = std::ptr::null_mut();
        self.width = 0;
        self.height = 0;
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        self.release();
    }
}
