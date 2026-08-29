#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! SwiftTunnel Lite.
//!
//! The tunnel and Roblox's frame cap, in a 340x480 window with no WebView2.
//!
//! # Why not the app with the pages removed
//!
//! That was tried, and shipped as a build of the React client behind a flag.
//! It works and it looks right, because it is the real design system, but a
//! webview costs about 390MB of process group before a line of UI is drawn
//! while the whole Rust side is 10MB. A client whose reason to exist is not
//! taxing your machine cannot be 97% browser, so the interface here is painted
//! directly: shapes composited in software by `canvas`, text by GDI in the
//! product's own Geist, no compositor, no GPU process, and nothing repainted
//! unless something changed.
//!
//! # What is not reimplemented
//!
//! Everything that has to behave identically. `swifttunnel-core` owns the
//! account, the relay ticket signing, the tunnel and Roblox's settings file,
//! and the free-tier limit is enforced server-side on `/api/vpn/relay-ticket`.
//! Sharing that code path is what keeps the two clients honest with each
//! other. The settings file is the same file too, so a region picked in one is
//! picked in both.

mod canvas;
mod clipboard;
mod engine;
mod fonts;
mod gdi;
mod picker;
mod preview;
mod screens;
mod single_client;
mod state;
mod surface;
mod theme;
mod tray;
mod ui;
mod view;

use state::Push;
use view::Screen;

fn main() {
    init_logging();

    // Before any window or font is created: the whole UI is set in these, and
    // GDI substitutes silently rather than failing if they are missing.
    fonts::install();

    // --cleanup: undo every system change and exit.
    //
    // Run by the standalone installer before it takes the files away. It is
    // core own uninstall routine, the same one the full app runs, so the
    // routes, the firewall rules, the hosts entries and both clients Run
    // entries go with it rather than being left on the machine.
    if std::env::args().any(|a| a == "--cleanup") {
        match swifttunnel_core::network_booster::cleanup_all_system_state() {
            Ok(()) => log::info!("cleanup finished"),
            Err(error) => log::error!("cleanup failed: {error}"),
        }
        return;
    }

    // --install-driver: put the split tunnel driver in place and exit.
    //
    // Run by the standalone installer as a deferred custom action, the same
    // way the full app does it. Lite ships the driver package beside its own
    // exe, and core already looks in `exe_dir/drivers` for it, so this needs
    // no new driver logic. It comes before the single-client lock because it
    // is not a client: it installs and exits, and refusing to do that because
    // somebody has the app open would leave the machine without a driver.
    if std::env::args().any(|a| a == "--install-driver") {
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()));
        let program_files = std::path::PathBuf::from(
            std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".to_string()),
        );

        let health = swifttunnel_core::vpn::SplitTunnelDriver::health_check();
        log::info!(
            "driver helper: ready={} status={} message={}",
            health.ready,
            health.status.as_str(),
            health.message
        );
        if health.ready {
            log::info!("driver already ready; installer helper exiting");
            return;
        }

        // Force the reinstall when the health check asks for one, the same
        // decision the full app installer makes. A package that is staged but
        // whose filter is not bound to anything installs cleanly and stays
        // broken, and only the uninstall-first path clears it.
        let force = health.recommended_action
            == swifttunnel_core::vpn::DriverRecommendedAction::Reinstall
            || std::env::args().any(|a| a == "--force");
        log::info!("driver helper: force={force}");

        match swifttunnel_core::vpn::SplitTunnelDriver::install_driver_from_bundled_package(
            None,
            exe_dir.as_deref(),
            &program_files,
            force,
        ) {
            Ok(()) => log::info!("driver installed by the Lite installer"),
            Err(error) => log::error!("Lite installer driver install failed: {error}"),
        }
        return;
    }

    // Before the engine, which starts threads and opens the settings file:
    // if the full app is already up, this process should do nothing but
    // bring it to the front and leave.
    //
    // The preview switch is exempt. It paints one frame offscreen and
    // exits, touching no driver and no network, and refusing to render a
    // screenshot because the app happens to be open would make the only
    // feedback loop this UI has depend on it being closed.
    let previewing = std::env::args().any(|a| a == "--preview");
    if !previewing && !single_client::acquire() {
        return;
    }

    let engine = match engine::Engine::new() {
        Ok(engine) => engine,
        Err(error) => {
            log::error!("could not start: {error}");
            return;
        }
    };

    // Developer switch: paint one frame to a file and exit.
    //
    // Lite runs elevated, and Windows will not let an unelevated tool capture
    // an elevated window, which left visual work with no feedback loop and is
    // a large part of why several attempts at this interface shipped wrong.
    let args: Vec<String> = std::env::args().collect();
    if let Some(i) = args.iter().position(|a| a == "--preview") {
        let path = args
            .get(i + 1)
            .cloned()
            .unwrap_or_else(|| "preview.bmp".to_string());
        let connected = args.iter().any(|a| a == "--connected");
        let named = |flag: &str| {
            args.iter()
                .position(|a| a == flag)
                .and_then(|i| args.get(i + 1))
                .map(String::as_str)
        };
        let screen = match named("--screen") {
            Some("roblox") => Screen::Roblox,
            Some("settings") => Screen::Settings,
            _ => Screen::Connect,
        };
        let push = match named("--push") {
            Some("regions") => Push::Regions,
            Some("adapters") => Push::Adapters,
            _ => Push::None,
        };
        let bench = args.iter().any(|a| a == "--bench");
        let lockout = match named("--lockout") {
            Some("signed-out") => Some(state::Lockout::SignedOut),
            Some("banned") => Some(state::Lockout::Banned(String::new())),
            Some("update") => Some(state::Lockout::UpdateRequired(String::new())),
            _ => None,
        };
        let login_text = named("--login-text").map(str::to_string);
        match ui::render_preview(
            engine,
            &path,
            screen,
            push,
            connected,
            lockout,
            login_text,
            bench,
        ) {
            Ok(()) => println!("wrote {path}"),
            Err(error) => eprintln!("preview failed: {error}"),
        }
        return;
    }

    if let Err(error) = ui::run(engine) {
        log::error!("window failed: {error}");
    }
}

/// Where Lite's log lives.
///
/// Beside the full app's own, under the shared SwiftTunnel data directory, so
/// a support request can be answered from one place. Public because Settings
/// offers to open it and there should be one definition of the path.
pub fn log_path() -> Option<std::path::PathBuf> {
    dirs::data_dir().map(|d| {
        d.join("SwiftTunnel")
            .join("logs")
            .join("swifttunnel-lite.log")
    })
}

fn init_logging() {
    let Some(path) = log_path() else {
        return;
    };
    let Some(dir) = path.parent() else {
        return;
    };
    if std::fs::create_dir_all(dir).is_err() {
        return;
    }

    // Roll a log that has grown too large rather than appending to it for
    // ever. A connect that retries the driver eight times a second writes a
    // surprising amount, and nobody can attach a 50MB file to a message. The
    // threshold is core own, shared with the full app.
    let _ = swifttunnel_core::rotate_log_if_needed(&path);

    let Ok(file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    else {
        return;
    };

    let _ = simplelog::WriteLogger::init(
        simplelog::LevelFilter::Info,
        simplelog::Config::default(),
        file,
    );
}
