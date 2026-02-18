mod autostart;
mod commands;
mod events;
mod state;
mod tray;
mod window_restore;

use std::sync::Arc;

use log::info;
use state::AppState;
use tauri::{Emitter, Manager};
use window_restore::restore_main_window;

const APP_ICON: tauri::image::Image<'static> = tauri::include_image!("./icons/icon.png");

#[cfg(windows)]
fn sync_runtime_assets(app: &tauri::App) {
    use std::fs;
    use std::path::PathBuf;

    fn first_existing(candidates: Vec<PathBuf>) -> Option<PathBuf> {
        candidates.into_iter().find(|p| p.exists())
    }

    let resource_dir = match app.path().resource_dir() {
        Ok(path) => path,
        Err(e) => {
            log::warn!("Could not resolve resource directory: {}", e);
            return;
        }
    };

    let exe_dir = match std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|p| p.to_path_buf()))
    {
        Some(path) => path,
        None => {
            log::warn!("Could not resolve executable directory");
            return;
        }
    };

    let targets: Vec<(&str, Option<PathBuf>, PathBuf)> = vec![
        (
            "wintun.dll",
            first_existing(vec![
                resource_dir.join("drivers").join("wintun.dll"),
                resource_dir.join("wintun.dll"),
            ]),
            exe_dir.join("wintun.dll"),
        ),
        (
            "WinpkFilter-x64.msi",
            first_existing(vec![
                resource_dir.join("drivers").join("WinpkFilter-x64.msi"),
                resource_dir.join("WinpkFilter-x64.msi"),
            ]),
            exe_dir.join("drivers").join("WinpkFilter-x64.msi"),
        ),
        (
            "winfw.dll",
            first_existing(vec![resource_dir.join("drivers").join("winfw.dll")]),
            exe_dir.join("drivers").join("winfw.dll"),
        ),
        (
            "mullvad-split-tunnel.sys",
            first_existing(vec![
                resource_dir
                    .join("drivers")
                    .join("mullvad-split-tunnel.sys"),
            ]),
            exe_dir.join("drivers").join("mullvad-split-tunnel.sys"),
        ),
    ];

    for (name, source, destination) in targets {
        let Some(source) = source else {
            log::debug!("Bundled runtime asset not found: {}", name);
            continue;
        };

        if let Some(parent) = destination.parent() {
            if let Err(e) = fs::create_dir_all(parent) {
                log::warn!(
                    "Failed to create asset directory {}: {}",
                    parent.display(),
                    e
                );
                continue;
            }
        }

        let should_copy = match (fs::metadata(&source), fs::metadata(&destination)) {
            (Ok(src), Ok(dst)) => src.len() != dst.len(),
            (Ok(_), Err(_)) => true,
            (Err(e), _) => {
                log::warn!("Failed to inspect {}: {}", source.display(), e);
                false
            }
        };

        if should_copy {
            match fs::copy(&source, &destination) {
                Ok(_) => info!(
                    "Staged runtime asset {} -> {}",
                    source.display(),
                    destination.display()
                ),
                Err(e) => log::warn!(
                    "Failed to stage runtime asset {} -> {}: {}",
                    source.display(),
                    destination.display(),
                    e
                ),
            }
        }
    }
}

#[cfg(not(windows))]
fn sync_runtime_assets(_app: &tauri::App) {}

pub fn run() {
    env_logger::init();
    let launched_from_startup = autostart::launched_from_startup_flag();

    let mut ctx = tauri::generate_context!();
    ctx.set_default_window_icon(Some(APP_ICON.clone()));
    ctx.set_tray_icon(Some(APP_ICON.clone()));

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            // Focus existing window when second instance launches
            if let Some(window) = app.get_webview_window("main") {
                restore_main_window(&window);
            }
        }))
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .invoke_handler(tauri::generate_handler![
            // Auth
            commands::auth::auth_get_state,
            commands::auth::auth_start_oauth,
            commands::auth::auth_poll_oauth,
            commands::auth::auth_cancel_oauth,
            commands::auth::auth_complete_oauth,
            commands::auth::auth_logout,
            commands::auth::auth_refresh_profile,
            // VPN
            commands::vpn::vpn_get_state,
            commands::vpn::vpn_connect,
            commands::vpn::vpn_disconnect,
            commands::vpn::vpn_get_throughput,
            commands::vpn::vpn_get_ping,
            commands::vpn::vpn_get_diagnostics,
            // Servers
            commands::vpn::server_get_list,
            commands::vpn::server_get_latencies,
            commands::vpn::server_refresh,
            commands::vpn::server_smart_select,
            // Optimizer
            commands::optimizer::boost_get_metrics,
            commands::optimizer::boost_toggle,
            commands::optimizer::boost_update_config,
            commands::optimizer::boost_get_system_info,
            commands::optimizer::boost_restart_roblox,
            // Network
            commands::network::network_start_stability_test,
            commands::network::network_start_speed_test,
            commands::network::network_start_bufferbloat_test,
            // Settings
            commands::settings::settings_load,
            commands::settings::settings_save,
            // Updater
            commands::updater::updater_check_channel,
            commands::updater::updater_install_channel,
            // System
            commands::system::system_is_admin,
            commands::system::system_check_driver,
            commands::system::system_install_driver,
            commands::system::system_open_url,
            commands::system::system_restart_as_admin,
        ])
        .setup(move |app| {
            info!("SwiftTunnel desktop app starting up");
            sync_runtime_assets(app);

            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_icon(APP_ICON.clone());
            }

            let runtime =
                Arc::new(tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime"));

            let app_state = AppState::new(runtime.clone()).expect("Failed to initialize app state");
            let run_on_startup_enabled = app_state.settings.lock().run_on_startup;
            app.manage(app_state);

            if let Err(e) = autostart::sync_run_on_startup(app.handle(), run_on_startup_enabled) {
                log::warn!("Failed to sync startup registration: {}", e);
            }

            if launched_from_startup {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.hide();
                }
            }

            // Set up system tray
            if let Err(e) = tray::setup_tray(app.handle()) {
                log::error!("Failed to set up system tray: {}", e);
            }

            // Spawn background task to load server list
            let app_handle = app.handle().clone();
            runtime.spawn(async move {
                info!("Loading server list in background...");
                match swifttunnel_core::vpn::servers::load_server_list().await {
                    Ok((servers, regions, source)) => {
                        info!(
                            "Server list loaded: {} servers, {} regions (source: {})",
                            servers.len(),
                            regions.len(),
                            source
                        );
                        if let Some(state) = app_handle.try_state::<AppState>() {
                            let mut sl = state.server_list.lock();
                            sl.update(servers, regions, source.clone());
                        }
                        let _ = app_handle.emit(events::SERVER_LIST_UPDATED, source.to_string());
                    }
                    Err(e) => {
                        log::error!("Failed to load server list: {}", e);
                    }
                }
            });

            // Spawn background task to refresh auth profile
            let app_handle = app.handle().clone();
            runtime.spawn(async move {
                if let Some(state) = app_handle.try_state::<AppState>() {
                    let auth = state.auth_manager.lock().await;
                    if auth.is_logged_in() {
                        info!("Refreshing user profile on startup...");
                        if let Err(e) = auth.refresh_profile().await {
                            log::warn!("Failed to refresh profile on startup: {}", e);
                        }
                    }
                }
            });

            Ok(())
        })
        .run(ctx)
        .expect("error while running tauri application");
}
