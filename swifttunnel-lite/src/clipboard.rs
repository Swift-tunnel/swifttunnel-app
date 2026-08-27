//! Reading text out of the clipboard.
//!
//! Custom FFlags arrive as a JSON object somebody was given in a Discord
//! message or a forum post. Typing that into a 340px window is not a thing
//! anyone would do, so Lite takes it from the clipboard instead.

#![cfg(windows)]

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::DataExchange::{
    CloseClipboard, GetClipboardData, IsClipboardFormatAvailable, OpenClipboard,
};
use windows::Win32::System::Memory::{GlobalLock, GlobalUnlock};
use windows::Win32::System::Ole::CF_UNICODETEXT;

/// Whatever text is on the clipboard, or `None` if there is none.
///
/// Capped, because this feeds a JSON parser and core refuses anything over
/// 8KB anyway. Reading a hundred megabytes off the clipboard to then reject it
/// would be a poor use of a machine that is short of memory.
pub fn text(limit: usize) -> Option<String> {
    // SAFETY: the clipboard is opened, read and closed within this block, and
    // the handle is locked for exactly as long as it is being copied from.
    unsafe {
        if !IsClipboardFormatAvailable(CF_UNICODETEXT.0 as u32).is_ok() {
            return None;
        }
        if OpenClipboard(None).is_err() {
            return None;
        }

        let result = read_locked(limit);

        let _ = CloseClipboard();
        result
    }
}

/// The body of the read, so every early exit still closes the clipboard.
unsafe fn read_locked(limit: usize) -> Option<String> {
    unsafe {
        let handle: HANDLE = GetClipboardData(CF_UNICODETEXT.0 as u32).ok()?;
        let ptr = GlobalLock(std::mem::transmute::<HANDLE, _>(handle)) as *const u16;
        if ptr.is_null() {
            return None;
        }

        // The buffer is NUL-terminated; walk it rather than trusting a length
        // the clipboard never gave us.
        let mut len = 0usize;
        while len < limit && *ptr.add(len) != 0 {
            len += 1;
        }
        let text = String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len));

        let _ = GlobalUnlock(std::mem::transmute::<HANDLE, _>(handle));
        Some(text)
    }
}
