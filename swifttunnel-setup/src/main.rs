//! Offline Desktop and Lite setup. A native window owns the controls while a
//! worker stages the protected MSI and runs product-scoped Windows Installer
//! transactions. Direct MSI installations retain their existing interface.

#![windows_subsystem = "windows"]

mod backend;
mod model;
mod ui;

/// The installer payload, staged into OUT_DIR by build.rs.
///
/// Empty on a debug or `cargo check` build, where there is no MSI to embed. A
/// release build without one is refused by build.rs, so an empty payload here
/// can only mean somebody ran the debug binary.
const MSI_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/payload.msi"));

/// Name used for the unpacked copy. Windows records the path it installed from
/// as the source, so this deliberately looks like a real installer name rather
/// than a random temporary file.
const MSI_NAME: &str = env!("SWIFTTUNNEL_SETUP_NAME");

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    let (commands, receive_commands) = std::sync::mpsc::channel();
    let (events, receive_events) = std::sync::mpsc::channel();
    if let Err(error) = std::thread::Builder::new()
        .name("installer-worker".into())
        .spawn(move || backend::worker(receive_commands, events))
    {
        return fail(&format!("Could not start the installer worker: {error}"), 1);
    }
    match ui::run(Box::new(ui::State::new(commands, receive_events))) {
        Ok(code) => code,
        Err(error) => fail(&error, 1),
    }
}

/// Tell the user, then return the exit code.
///
/// Every way this launcher can fail used to fail in silence. It asks for
/// administrator, so Windows shows a prompt, and then nothing happens at all:
/// no window, no console, no error. Somebody who accepted that prompt and saw
/// nothing has no way to tell a blocked download from a broken one, and the
/// ticket that follows says only "it just didn't open".
///
/// A message box is the whole fix. There is no console to print to, because a
/// flashing console window is exactly the impression an unsigned installer does
/// not need.
fn fail(message: &str, code: i32) -> i32 {
    // Recorded before the box, not after. MessageBoxW blocks until somebody
    // dismisses it, and a user who force-closes the dialog would otherwise
    // leave nothing behind for the ticket that follows.
    log_failure(message);

    message_box(message, true);
    code
}

fn message_box(message: &str, error: bool) {
    #[cfg(windows)]
    {
        // Declared here rather than pulling in a Windows crate: one function,
        // and this binary is deliberately tiny.
        #[link(name = "user32")]
        unsafe extern "system" {
            fn MessageBoxW(
                hwnd: *mut core::ffi::c_void,
                text: *const u16,
                caption: *const u16,
                utype: u32,
            ) -> i32;
        }
        const MB_OK: u32 = 0x0000_0000;
        let icon = if error { 0x0000_0010 } else { 0x0000_0040 };
        const MB_SETFOREGROUND: u32 = 0x0001_0000;

        let wide = |s: &str| {
            s.encode_utf16()
                .chain(std::iter::once(0))
                .collect::<Vec<u16>>()
        };
        let text = wide(message);
        let caption = wide("SwiftTunnel Setup");
        // SAFETY: both strings are NUL terminated and outlive the call.
        unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                text.as_ptr(),
                caption.as_ptr(),
                MB_OK | icon | MB_SETFOREGROUND,
            );
        }
    }
}

/// Leave a note beside the installer too, for a ticket that arrives after the
/// box has been dismissed.
fn log_failure(message: &str) {
    if let Ok(cache) = swifttunnel_installer_cache::InstallerCache::open() {
        let _ = cache.write_note(
            swifttunnel_installer_cache::CacheNote::SetupError,
            message.as_bytes(),
        );
    }
}
