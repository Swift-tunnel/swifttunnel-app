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
mod engine;
mod fonts;
mod gdi;
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
        match ui::render_preview(engine, &path, screen, push, connected, bench) {
            Ok(()) => println!("wrote {path}"),
            Err(error) => eprintln!("preview failed: {error}"),
        }
        return;
    }

    if let Err(error) = ui::run(engine) {
        log::error!("window failed: {error}");
    }
}

/// Log beside the full app's own log, under the shared SwiftTunnel data
/// directory, so a support request can be answered from one place.
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
