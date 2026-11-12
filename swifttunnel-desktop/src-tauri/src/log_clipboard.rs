use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::time::{Duration, Instant};
use windows::Win32::Foundation::{GlobalFree, HANDLE, HGLOBAL, HWND};
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData,
};
use windows::Win32::System::Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock};
use windows::Win32::System::Ole::CF_HDROP;
use windows::Win32::UI::Shell::DROPFILES;

struct FileDrop(HGLOBAL);

impl FileDrop {
    fn new(path: &Path) -> io::Result<Self> {
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0, 0]).collect();
        let offset = size_of::<DROPFILES>();
        let header = DROPFILES {
            pFiles: offset as u32,
            fWide: true.into(),
            ..Default::default()
        };

        // SAFETY: the movable allocation covers both the header and the
        // double-NUL-terminated UTF-16 file list. The offset is u16-aligned.
        unsafe {
            let memory = Self(GlobalAlloc(
                GMEM_MOVEABLE,
                offset + size_of_val(wide.as_slice()),
            )?);
            let data = GlobalLock(memory.0).cast::<u8>();
            if data.is_null() {
                return Err(io::Error::last_os_error());
            }
            data.cast::<DROPFILES>().write_unaligned(header);
            std::ptr::copy_nonoverlapping(
                wide.as_ptr(),
                data.add(offset).cast::<u16>(),
                wide.len(),
            );
            // Zero indicates the last lock was released.
            let _ = GlobalUnlock(memory.0);
            Ok(memory)
        }
    }
}

impl Drop for FileDrop {
    fn drop(&mut self) {
        // SAFETY: this guard owns an unlocked allocation until it is published.
        let _ = unsafe { GlobalFree(Some(self.0)) };
    }
}

pub fn copy_file(owner: HWND, path: &Path, deadline: Instant) -> io::Result<()> {
    let file = FileDrop::new(path)?;
    // SAFETY: owner is the SwiftTunnel window. Clipboard operations run on
    // this worker thread, and every successful open is paired with a close.
    unsafe {
        for _ in 0..4 {
            if Instant::now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            if OpenClipboard(Some(owner)).is_ok() {
                return publish(file, deadline);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        OpenClipboard(Some(owner))?;
        publish(file, deadline)
    }
}

/// The clipboard must already be open on this thread.
unsafe fn publish(file: FileDrop, deadline: Instant) -> io::Result<()> {
    let result = (|| {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        unsafe { EmptyClipboard()? };
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        unsafe { SetClipboardData(CF_HDROP.0 as u32, Some(HANDLE(file.0.0)))? };
        // Windows now owns the memory.
        std::mem::forget(file);
        Ok(())
    })();
    let _ = unsafe { CloseClipboard() };
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::UI::Shell::{DragQueryFileW, HDROP};

    #[test]
    fn windows_reads_one_unicode_file_from_the_drop_payload() {
        let path = Path::new(r"C:\Users\測試 user\logs\swifttunnel.log");
        let file = FileDrop::new(path).unwrap();
        let drop = HDROP(file.0.0);
        // SAFETY: the allocation contains an unlocked CF_HDROP payload.
        unsafe {
            assert_eq!(DragQueryFileW(drop, u32::MAX, None), 1);
            let mut buf = [0; 260];
            let len = DragQueryFileW(drop, 0, Some(&mut buf)) as usize;
            assert_eq!(
                String::from_utf16(&buf[..len]).unwrap(),
                path.to_str().unwrap()
            );
        }
    }
}
