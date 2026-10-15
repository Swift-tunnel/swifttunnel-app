//! Reading text out of the clipboard.
//!
//! Paste into sign-in fields without trusting another app's text allocation.

#![cfg(windows)]

use windows::Win32::Foundation::{HANDLE, HGLOBAL};
use windows::Win32::System::DataExchange::{
    CloseClipboard, GetClipboardData, IsClipboardFormatAvailable, OpenClipboard,
};
use windows::Win32::System::Memory::{GlobalLock, GlobalSize, GlobalUnlock};
use windows::Win32::System::Ole::CF_UNICODETEXT;

/// Whatever text is on the clipboard, or `None` if there is none.
///
/// The limit counts UTF-16 units. Overlong, unterminated or malformed input
/// is refused rather than silently pasting a truncated password.
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
        read_allocation(HGLOBAL(handle.0), limit)
    }
}

unsafe fn read_allocation(memory: HGLOBAL, limit: usize) -> Option<String> {
    unsafe {
        // CF_UNICODETEXT should be terminated, but another application can
        // supply malformed data. Never search beyond the actual allocation.
        let bytes = GlobalSize(memory);
        if bytes < size_of::<u16>() {
            return None;
        }
        let ptr = GlobalLock(memory) as *const u16;
        if ptr.is_null() {
            return None;
        }
        struct Locked(HGLOBAL);
        impl Drop for Locked {
            fn drop(&mut self) {
                unsafe {
                    let _ = GlobalUnlock(self.0);
                }
            }
        }
        let _locked = Locked(memory);
        let units = (bytes / size_of::<u16>()).min(limit.saturating_add(1));
        decode_text(std::slice::from_raw_parts(ptr, units), limit)
    }
}

fn decode_text(units: &[u16], limit: usize) -> Option<String> {
    let end = units
        .iter()
        .take(limit.saturating_add(1))
        .position(|unit| *unit == 0)?;
    String::from_utf16(&units[..end]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_unterminated_and_overlong_text_is_not_read_or_truncated() {
        assert_eq!(decode_text(&[65], 256), None);
        assert_eq!(decode_text(&[65, 66, 67, 0], 2), None);
        assert_eq!(decode_text(&[65, 66, 0], 2), Some("AB".into()));
        assert_eq!(decode_text(&[], 256), None);
    }

    #[test]
    fn unicode_is_preserved_without_replacing_broken_surrogates() {
        let text = "hello \u{1f642}";
        let units: Vec<u16> = text.encode_utf16().chain(Some(0)).collect();
        assert_eq!(decode_text(&units, units.len()), Some(text.into()));
        assert_eq!(decode_text(&[0xd800, 0], 256), None);
    }

    #[test]
    fn reads_only_an_owned_global_allocation_and_releases_the_lock() {
        use windows::Win32::Foundation::GlobalFree;
        use windows::Win32::System::Memory::{
            GMEM_MOVEABLE, GMEM_ZEROINIT, GlobalAlloc, GlobalFlags,
        };
        unsafe {
            let memory = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, 16).unwrap();
            let ptr = GlobalLock(memory) as *mut u16;
            assert!(!ptr.is_null());
            ptr.write(65);
            let _ = GlobalUnlock(memory);
            assert_eq!(read_allocation(memory, 256), Some("A".into()));
            assert_eq!(read_allocation(memory, 0), None);
            let locks = GlobalFlags(memory) & 0xff;
            // This bindings version incorrectly treats GlobalFree's NULL-on-
            // success return as an error. Check the lock count before freeing.
            let _ = GlobalFree(Some(memory));
            assert_eq!(locks, 0, "clipboard reader left the allocation locked");
        }
    }
}
