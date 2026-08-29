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
    app_icon(0, 0)
}

/// Build the app icon at a given size, 0 for the file's own default.
///
/// Public because the window needs it too: the taskbar button, Alt+Tab and the
/// title bar all read the window's icon, and the window class left it null, so
/// the tray was the only place the logo appeared.
pub fn app_icon(cx: i32, cy: i32) -> HICON {
    // Prefer the exe's own icon group. LoadImageW picks the right image out of
    // it for the size asked and scales from that, which the raw-bytes path
    // below does not: it kept handing back a 32px master to be blown up to 96
    // on the sign-in screen, which is why the logo looked like a mosaic.
    if cx > 0 && cy > 0 {
        // SAFETY: resource id 1 is the icon embedded by build.rs, and a null
        // module handle means this executable.
        unsafe {
            if let Ok(module) = windows::Win32::System::LibraryLoader::GetModuleHandleW(None)
                && let Ok(handle) = windows::Win32::UI::WindowsAndMessaging::LoadImageW(
                    Some(module.into()),
                    windows::core::PCWSTR(1 as *const u16),
                    windows::Win32::UI::WindowsAndMessaging::IMAGE_ICON,
                    cx,
                    cy,
                    LR_DEFAULTCOLOR,
                )
            {
                return HICON(handle.0);
            }
        }
    }

    // SAFETY: ICON is a 'static byte slice from include_bytes!, and both calls
    // are given its length so neither can read past it.
    unsafe {
        // Ask the directory for an image at least as big as the one wanted, so
        // a 96px logo is a 256px master scaled down rather than a 32px one
        // scaled up. Windows picks the nearest, and nearest-below on an upscale
        // is what made the sign-in logo look pixelated.
        let (want_x, want_y) = if cx > 32 { (256, 256) } else { (cx, cy) };
        let offset =
            LookupIconIdFromDirectoryEx(ICON.as_ptr(), true, want_x, want_y, LR_DEFAULTCOLOR);
        if offset <= 0 || offset as usize >= ICON.len() {
            log::warn!("the embedded icon has no usable image");
            return HICON(std::ptr::null_mut());
        }
        let image = &ICON[offset as usize..];
        CreateIconFromResourceEx(image, true, 0x0003_0000, cx, cy, LR_DEFAULTCOLOR)
        .unwrap_or_else(|error| {
            log::warn!("could not build the app icon: {error}");
            HICON(std::ptr::null_mut())
        })
    }
}

/// Which mouse message the shell packed into a `WM_TRAY` notification.
pub fn tray_event(lparam: LPARAM) -> u32 {
    lparam.0 as u32
}
