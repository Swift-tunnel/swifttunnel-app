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

/// One clipboard read owned by the window. Windows may wait on a delayed
/// renderer, so never perform it in the window's input-message handler.
pub struct Reader {
    pending: Option<std::sync::mpsc::Receiver<Option<String>>>,
    alive: std::sync::Arc<std::sync::Mutex<bool>>,
}

impl Default for Reader {
    fn default() -> Self {
        Self {
            pending: None,
            alive: std::sync::Arc::new(std::sync::Mutex::new(true)),
        }
    }
}

impl Drop for Reader {
    fn drop(&mut self) {
        // Synchronize with posting, never with the slow clipboard read. Once
        // the window is gone its HWND may belong to an unrelated new window.
        *self.alive.lock().unwrap_or_else(|error| error.into_inner()) = false;
    }
}

impl Reader {
    pub fn start(
        &mut self,
        read: impl FnOnce() -> Option<String> + Send + 'static,
        notify: impl FnOnce() + Send + 'static,
    ) -> std::io::Result<bool> {
        use std::sync::mpsc::TryRecvError;
        if let Some(pending) = &self.pending
            && matches!(pending.try_recv(), Err(TryRecvError::Empty))
        {
            return Ok(false);
        }
        self.pending = None;
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let alive = self.alive.clone();
        std::thread::Builder::new()
            .name("clipboard-read".into())
            .spawn(move || {
                struct Notify<F: FnOnce()>(Option<F>);
                impl<F: FnOnce()> Drop for Notify<F> {
                    fn drop(&mut self) {
                        if let Some(notify) = self.0.take() {
                            notify();
                        }
                    }
                }
                // Even a worker unwind must let the window retire its pending read.
                let _notify = Notify(Some(move || {
                    let alive = alive.lock().unwrap_or_else(|error| error.into_inner());
                    if *alive {
                        notify();
                    }
                }));
                let _ = sender.try_send(read());
            })?;
        self.pending = Some(receiver);
        Ok(true)
    }

    /// None means still pending; Some(None) means no usable text was returned.
    pub fn take(&mut self) -> Option<Option<String>> {
        use std::sync::mpsc::TryRecvError;
        let result = self.pending.as_ref()?.try_recv();
        match result {
            Err(TryRecvError::Empty) => None,
            Ok(text) => {
                self.pending = None;
                Some(text)
            }
            Err(TryRecvError::Disconnected) => {
                self.pending = None;
                Some(None)
            }
        }
    }
}

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
    fn a_pending_read_does_not_block_input_or_admit_another_worker() {
        use std::sync::mpsc;
        use std::time::Duration;
        let mut reader = Reader::default();
        let (started, ready) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        let (posted, notified) = mpsc::channel();
        assert!(
            reader
                .start(
                    move || {
                        let _ = started.send(());
                        let _ = wait.recv_timeout(Duration::from_secs(2));
                        Some("fixture text".into())
                    },
                    move || {
                        let _ = posted.send(());
                    }
                )
                .unwrap()
        );
        ready.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(reader.take(), None);
        assert!(!reader.start(|| panic!("duplicate worker"), || {}).unwrap());
        let _ = release.send(());
        notified.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(reader.take(), Some(Some("fixture text".into())));
        let (posted, notified) = mpsc::channel();
        assert!(
            reader
                .start(
                    || None,
                    move || {
                        let _ = posted.send(());
                    }
                )
                .unwrap()
        );
        notified.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(reader.take(), Some(None));
    }

    #[test]
    fn dropping_the_window_does_not_wait_for_the_read_or_notify_a_reused_handle() {
        use std::sync::mpsc;
        use std::time::Duration;
        let mut reader = Reader::default();
        let (started, ready) = mpsc::channel();
        let (release, wait) = mpsc::channel();
        let (posted, notified) = mpsc::channel();
        reader
            .start(
                move || {
                    let _ = started.send(());
                    let _ = wait.recv_timeout(Duration::from_secs(2));
                    None
                },
                move || {
                    let _ = posted.send(());
                },
            )
            .unwrap();
        ready.recv_timeout(Duration::from_secs(1)).unwrap();
        drop(reader);
        let _ = release.send(());
        assert!(matches!(
            notified.recv_timeout(Duration::from_secs(1)),
            Err(mpsc::RecvTimeoutError::Disconnected)
        ));
    }

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
