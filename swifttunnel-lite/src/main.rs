#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! SwiftTunnel Lite.
//!
//! Three things and nothing else: bring the tunnel up, unlock Roblox's frame
//! cap, and show the frame rate. A plain Win32 window, no WebView2.
//!
//! Everything that has to be identical to the full app is reused rather than
//! reimplemented. `swifttunnel-core` owns the account, the relay ticket
//! signing and the tunnel itself, and the free-tier limit is enforced by the
//! server on `/api/vpn/relay-ticket`. Sharing that code path is what makes the
//! two clients behave the same; a second implementation of any of it would
//! drift.
//!
//! Sharing the auth store also means somebody already signed in to the full
//! app is signed in here: both read the same machine-bound `auth_session.dat`.

use swifttunnel_core::auth::AuthManager;

mod engine;
mod gdi;
mod theme;
mod ui;

fn main() {
    init_logging();

    // Loads the stored session, so a user signed in to the full app is already
    // signed in here.
    let auth = match AuthManager::new() {
        Ok(auth) => auth,
        Err(error) => {
            log::error!("failed to initialise auth: {error}");
            return;
        }
    };

    log::info!(
        "SwiftTunnel Lite starting, signed in: {}",
        auth.is_logged_in()
    );

    if let Err(error) = ui::run(auth) {
        log::error!("window failed: {error}");
    }
}

/// Log beside the full app's own log, under the shared SwiftTunnel data
/// directory, so support requests can be answered from one place.
fn init_logging() {
    let Some(dir) = dirs::data_dir().map(|d| d.join("SwiftTunnel").join("logs")) else {
        return;
    };
    if std::fs::create_dir_all(&dir).is_err() {
        return;
    }
    let Ok(file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join("swifttunnel-lite.log"))
    else {
        return;
    };

    let _ = simplelog::WriteLogger::init(
        simplelog::LevelFilter::Info,
        simplelog::Config::default(),
        file,
    );
}
