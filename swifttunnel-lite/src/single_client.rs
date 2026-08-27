//! One SwiftTunnel client at a time, whichever build it is.
//!
//! Lite and the full app are separate executables that both install and bind
//! the packet filter driver and rewrite the routing table. Running them
//! together is not a race anyone wants to find out the shape of on a user's
//! machine, so the second one to start does not.
//!
//! It also closes an abuse route. The two share an account, a settings file
//! and the server-side quota, but a second client is still a second set of
//! timers and a second connection attempt.
//!
//! The lock is the same named mutex the desktop build takes, which is what
//! makes the exclusion mutual: neither knows about the other beyond this name.
//! Session-local rather than `Global\`, because what is being protected is one
//! user's network stack rather than the machine's, so two people signed in at
//! once get one client each, which is correct.

#[cfg(windows)]
mod imp {
    use windows::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError};
    use windows::Win32::System::Threading::CreateMutexW;
    use windows::Win32::UI::WindowsAndMessaging::{
        FindWindowW, IsIconic, IsWindowVisible, SW_RESTORE, SW_SHOW, SetForegroundWindow,
        ShowWindow,
    };
    use windows::core::{PCWSTR, w};

    /// Titles the running client might have. Both are checked because either
    /// build could be the one already up.
    const TITLES: [PCWSTR; 2] = [w!("SwiftTunnel"), w!("SwiftTunnel Lite")];

    /// Whether this process may continue.
    ///
    /// Returns false when another client already holds the lock, having first
    /// tried to bring that one to the front so the click that launched this
    /// one still does something useful.
    pub fn acquire() -> bool {
        // SAFETY: a named mutex with no security attributes. The handle is
        // deliberately leaked on success (see below) and closed on failure.
        unsafe {
            let Ok(handle) = CreateMutexW(None, true, w!("SwiftTunnelSingleClient")) else {
                // If the lock cannot be created at all, let the app run. A
                // guard that fails closed would make an unexplained OS error
                // look like the app refusing to start.
                log::warn!("could not create the single-client lock; continuing");
                return true;
            };

            if GetLastError() != ERROR_ALREADY_EXISTS {
                // The handle is deliberately never closed. Ownership of a
                // named mutex lasts as long as the handle does, so closing it
                // at any point would let a second client in while this one is
                // still tunnelling. The OS releases it when the process exits,
                // which is exactly the lifetime wanted.
                return true;
            }

            let _ = CloseHandle(handle);
            log::info!("another SwiftTunnel client is already running; focusing it");
            focus_running_client();
            false
        }
    }

    /// Bring whichever client is already up to the front.
    ///
    /// Best effort. Windows refuses `SetForegroundWindow` from a process that
    /// is not itself in the foreground, and there is nothing useful to do
    /// about that beyond having tried: the important half is that this process
    /// exits.
    fn focus_running_client() {
        for title in TITLES {
            // SAFETY: both arguments are static, NUL-terminated wide strings.
            unsafe {
                let Ok(window) = FindWindowW(None, title) else {
                    continue;
                };
                if window.0.is_null() {
                    continue;
                }
                // Three states, not two. Minimised needs restoring, but a
                // window closed to the tray is *hidden*, which is not the same
                // thing: it is not iconic, so restoring alone leaves it
                // invisible and the click that launched the second copy
                // appears to do nothing at all.
                if IsIconic(window).as_bool() {
                    let _ = ShowWindow(window, SW_RESTORE);
                } else if !IsWindowVisible(window).as_bool() {
                    let _ = ShowWindow(window, SW_SHOW);
                }
                let _ = SetForegroundWindow(window);
                return;
            }
        }
    }
}

#[cfg(not(windows))]
mod imp {
    pub fn acquire() -> bool {
        true
    }
}

pub use imp::acquire;
