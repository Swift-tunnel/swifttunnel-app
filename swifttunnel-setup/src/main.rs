//! The installer the website hands out.
//!
//! It does two things the MSI cannot do for itself, and they are opposite ends
//! of the same failure.
//!
//! It runs the orphaned-registration repair *before* `msiexec` starts, which no
//! custom action inside an MSI can be sequenced to do. Without that, an upgrade
//! on a machine whose cached package is missing dies on "The feature you are
//! trying to use is on a network resource that is unavailable" with no way
//! forward. That is the cure.
//!
//! And it leaves the package it installed from somewhere permanent, so the next
//! upgrade has a source to fall back on when Windows' own cached copy is
//! deleted. That is the prevention, and it is the more important half: it used
//! to install out of `%TEMP%` and delete the file immediately afterwards, so
//! every install made here started out needing the repair.
//!
//! The rest is deliberately boring. It hands the MSI to `msiexec` with the
//! normal installer UI, waits, and returns whatever msiexec returned. The user
//! sees the same install they always did, one UAC prompt earlier.
//!
//! No console window: the manifest asks for administrator, so Windows prompts
//! at launch, and msiexec draws the only UI. A flashing console would look
//! like a script running against the machine, which is exactly the impression
//! an unsigned installer does not need.

#![windows_subsystem = "windows"]

use std::process::Command;

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
    if MSI_BYTES.is_empty() {
        // A debug build carries no installer. Refuse rather than write a
        // zero byte file and hand msiexec something meaningless.
        return fail(
            concat!(
                "This copy of the installer is incomplete, so there is nothing to install.",
                "\n\n",
                "Download SwiftTunnel again from swifttunnel.net."
            ),
            2,
        );
    }

    // Best effort, and never fatal. A machine that is not broken finds nothing
    // to do here, and a repair that fails should still let the install be
    // attempted: the worst case is the old error the user would have had
    // anyway, rather than an installer that refuses to start.
    let _ = swifttunnel_msi_repair::repair();

    let installer = match stage_payload() {
        Ok(installer) => installer,
        Err(error) => return fail(&format!("SwiftTunnel could not prepare its protected installer cache.\n\n{error}\n\nCheck free disk space, run setup as administrator, and contact support if this persists."), 1),
    };

    let status = swifttunnel_installer_cache::windows_installer_path().and_then(|msiexec| {
        use std::os::windows::process::CommandExt;
        Command::new(msiexec)
            .arg("/i")
            .arg(installer.path())
            .creation_flags(0x0800_0000)
            .status()
    });
    // Keep the verified handle until msiexec exits. Never prune registered
    // sources by filename count, including after failed/cancelled installation.
    drop(installer);

    match status {
        Ok(s) => s.code().unwrap_or(1),
        Err(error) => fail(
            &format!(
                "SwiftTunnel could not start Windows Installer.\n\n{error}\n\nRestart the PC and try again."
            ),
            1,
        ),
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
        const MB_ICONERROR: u32 = 0x0000_0010;
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
                MB_OK | MB_ICONERROR | MB_SETFOREGROUND,
            );
        }
    }
    code
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

/// Authenticated embedded bytes enter the same immutable cache as both updaters
/// and MSI repair. Name/content and handle-sharing tests live in that library,
/// where they can run without setup's elevation manifest or embedded MSI.
fn stage_payload() -> Result<swifttunnel_installer_cache::ProtectedInstaller, String> {
    swifttunnel_installer_cache::InstallerCache::open()
        .and_then(|cache| cache.stage(MSI_NAME, MSI_BYTES))
        .map_err(|error| error.to_string())
}
