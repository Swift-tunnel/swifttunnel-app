//! The notification-area icon, so closing the window does not drop the tunnel.
//!
//! Without this, closing Lite destroyed the window, which dropped the engine,
//! which dropped `VpnConnection`, which tore the tunnel down. Mid-game. And
//! Settings carried a "Close to tray" switch the whole time, which flipped a
//! saved boolean and changed nothing.
//!
//! The icon is the app's own, carried in the binary rather than loaded from
//! disk, so Lite stays one self-contained exe.

#![cfg(windows)]

use windows::Win32::Foundation::{HWND, LPARAM, POINT};
use windows::Win32::UI::Shell::{
    NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NOTIFYICONDATAW, Shell_NotifyIconW,
};
use windows::Win32::UI::WindowsAndMessaging::{
    AppendMenuW, CreateIconFromResourceEx, CreatePopupMenu, DestroyMenu, GetCursorPos, HICON,
    LR_DEFAULTCOLOR, LookupIconIdFromDirectoryEx, MF_SEPARATOR, MF_STRING, SetForegroundWindow,
    TPM_BOTTOMALIGN, TPM_RETURNCMD, TPM_RIGHTALIGN, TrackPopupMenu, WM_APP,
};
use windows::core::w;

/// Posted by the shell when the icon is clicked.
pub const WM_TRAY: u32 = WM_APP + 2;

/// Menu command ids, returned by `TrackPopupMenu`.
pub const CMD_SHOW: usize = 1;
pub const CMD_QUIT: usize = 2;

/// The app icon, so the tray entry is not a blank rectangle.
const ICON: &[u8] = include_bytes!("../resources/icon.ico");

pub struct Tray {
    hwnd: HWND,
    added: bool,
}

impl Tray {
    /// Put the icon in the notification area.
    ///
    /// Failure is not fatal: the window still works, it just cannot be closed
    /// to the tray, and `close_to_tray` checks [`Tray::present`] before
    /// promising otherwise.
    pub fn new(hwnd: HWND) -> Self {
        let mut data = NOTIFYICONDATAW {
            cbSize: size_of::<NOTIFYICONDATAW>() as u32,
            hWnd: hwnd,
            uID: 1,
            uFlags: NIF_ICON | NIF_MESSAGE | NIF_TIP,
            uCallbackMessage: WM_TRAY,
            hIcon: load_icon(),
            ..Default::default()
        };

        // szTip is a fixed 128-wide array, so the text is copied in rather
        // than pointed at.
        for (slot, ch) in data
            .szTip
            .iter_mut()
            .zip("SwiftTunnel Lite".encode_utf16().chain(std::iter::once(0)))
        {
            *slot = ch;
        }

        // SAFETY: `data` is fully initialised above and outlives the call.
        let added = unsafe { Shell_NotifyIconW(NIM_ADD, &data).as_bool() };
        if !added {
            log::warn!("could not add the tray icon; closing will quit instead");
        }

        Self { hwnd, added }
    }

    /// Whether the icon is actually there.
    pub fn present(&self) -> bool {
        self.added
    }

    /// Show the right-click menu and return the command chosen, if any.
    ///
    /// The foreground dance is required: a popup menu owned by a window that
    /// is not in the foreground never receives the click that dismisses it,
    /// and is left on screen until the next one opens.
    pub fn menu(&self) -> Option<usize> {
        // SAFETY: every handle created here is destroyed before returning.
        unsafe {
            let menu = CreatePopupMenu().ok()?;
            let _ = AppendMenuW(menu, MF_STRING, CMD_SHOW, w!("Open SwiftTunnel Lite"));
            let _ = AppendMenuW(menu, MF_SEPARATOR, 0, None);
            let _ = AppendMenuW(menu, MF_STRING, CMD_QUIT, w!("Quit"));

            let mut point = POINT::default();
            let _ = GetCursorPos(&mut point);
            let _ = SetForegroundWindow(self.hwnd);

            let chosen = TrackPopupMenu(
                menu,
                TPM_RIGHTALIGN | TPM_BOTTOMALIGN | TPM_RETURNCMD,
                point.x,
                point.y,
                None,
                self.hwnd,
                None,
            );
            let _ = DestroyMenu(menu);

            (chosen.0 != 0).then_some(chosen.0 as usize)
        }
    }
}

impl Drop for Tray {
    fn drop(&mut self) {
        if !self.added {
            return;
        }
        let data = NOTIFYICONDATAW {
            cbSize: size_of::<NOTIFYICONDATAW>() as u32,
            hWnd: self.hwnd,
            uID: 1,
            ..Default::default()
        };
        // SAFETY: removing an icon this process added.
        unsafe {
            let _ = Shell_NotifyIconW(NIM_DELETE, &data);
        }
    }
}

/// Build an HICON from the embedded .ico.
///
/// An .ico is a directory of images; the shell wants one of them at the size
/// it asked for. `LookupIconIdFromDirectoryEx` picks the best match and
/// returns its offset into the file, and `CreateIconFromResourceEx` turns the
/// image at that offset into an icon.
///
/// Doing it this way rather than through a resource script keeps Lite a single
/// self-contained exe and adds no build dependency.
fn load_icon() -> HICON {
    // SAFETY: ICON is a 'static byte slice from include_bytes!, and both calls
    // are given its length so neither can read past it.
    unsafe {
        let offset = LookupIconIdFromDirectoryEx(ICON.as_ptr(), true, 0, 0, LR_DEFAULTCOLOR);
        if offset <= 0 || offset as usize >= ICON.len() {
            log::warn!("the embedded icon has no usable image");
            return HICON(std::ptr::null_mut());
        }
        let image = &ICON[offset as usize..];
        CreateIconFromResourceEx(image, true, 0x0003_0000, 0, 0, LR_DEFAULTCOLOR)
        .unwrap_or_else(|error| {
            log::warn!("could not build the tray icon: {error}");
            HICON(std::ptr::null_mut())
        })
    }
}

/// Which mouse message the shell packed into a `WM_TRAY` notification.
pub fn tray_event(lparam: LPARAM) -> u32 {
    lparam.0 as u32
}
