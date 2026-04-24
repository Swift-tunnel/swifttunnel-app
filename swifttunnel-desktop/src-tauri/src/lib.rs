mod autostart;
mod commands;
mod events;
mod harness;
mod logging;
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
    use std::path::{Path, PathBuf};

    fn first_existing(candidates: Vec<PathBuf>) -> Option<PathBuf> {
        candidates.into_iter().find(|p| p.exists())
    }

    fn sync_file(source: &Path, destination: &Path) -> Result<bool, String> {
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                format!(
                    "Failed to create asset directory {}: {}",
                    parent.display(),
                    e
                )
            })?;
        }

        let should_copy = match (fs::metadata(source), fs::metadata(destination)) {
            (Ok(src), Ok(dst)) => src.len() != dst.len(),
            (Ok(_), Err(_)) => true,
            (Err(e), _) => {
                return Err(format!("Failed to inspect {}: {}", source.display(), e));
            }
        };

        if !should_copy {
            return Ok(false);
        }

        fs::copy(source, destination).map_err(|e| {
            format!(
                "Failed to stage runtime asset {} -> {}: {}",
                source.display(),
                destination.display(),
                e
            )
        })?;
        Ok(true)
    }

    fn sync_entry(source: &Path, destination: &Path) -> Result<usize, String> {
        if source.is_dir() {
            fs::create_dir_all(destination).map_err(|e| {
                format!(
                    "Failed to create asset directory {}: {}",
                    destination.display(),
                    e
                )
            })?;

            let mut copied_files = 0;
            for entry in fs::read_dir(source).map_err(|e| {
                format!("Failed to read asset directory {}: {}", source.display(), e)
            })? {
                let entry = entry
                    .map_err(|e| format!("Failed to read entry in {}: {}", source.display(), e))?;
                copied_files += sync_entry(&entry.path(), &destination.join(entry.file_name()))?;
            }
            Ok(copied_files)
        } else if sync_file(source, destination)? {
            Ok(1)
        } else {
            Ok(0)
        }
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
        {
            let msi_name = swifttunnel_core::vpn::winpkfilter::native_msi_package().msi_name;
            (
                msi_name,
                first_existing(vec![
                    resource_dir.join("drivers").join(msi_name),
                    resource_dir.join(msi_name),
                ]),
                exe_dir.join("drivers").join(msi_name),
            )
        },
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
            if name.starts_with("WinpkFilter-") {
                log::warn!(
                    "Bundled runtime asset not found: {} (runtime fallback download will be used)",
                    name
                );
            } else {
                log::debug!("Bundled runtime asset not found: {}", name);
            }
            continue;
        };

        match sync_entry(&source, &destination) {
            Ok(copied) if copied > 0 => info!(
                "Staged runtime asset {} -> {}",
                source.display(),
                destination.display()
            ),
            Ok(_) => {}
            Err(e) => {
                log::warn!("{}", e);
            }
        }
    }
}

#[cfg(not(windows))]
fn sync_runtime_assets(_app: &tauri::App) {}

pub fn run() {
    logging::init();
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
            commands::vpn::vpn_preflight_binding,
            commands::vpn::vpn_connect,
            commands::vpn::vpn_disconnect,
            commands::vpn::vpn_get_throughput,
            commands::vpn::vpn_get_ping,
            commands::vpn::vpn_get_diagnostics,
            commands::vpn::vpn_list_network_adapters,
            // Servers
            commands::vpn::server_get_list,
            commands::vpn::server_get_latencies,
            commands::vpn::server_refresh,
            commands::vpn::server_smart_select,
            // Optimizer
            commands::optimizer::boost_get_metrics,
            commands::optimizer::boost_get_system_memory,
            commands::optimizer::boost_update_config,
            commands::optimizer::boost_clean_ram,
            commands::optimizer::boost_get_system_info,
            commands::optimizer::boost_restart_roblox,
            // Network
            commands::network::network_start_stability_test,
            commands::network::network_start_speed_test,
            commands::network::network_start_bufferbloat_test,
            // Settings
            commands::settings::settings_load,
            commands::settings::settings_save,
            commands::settings::settings_generate_network_diagnostics_bundle,
            // Updater
            commands::updater::updater_check_channel,
            commands::updater::updater_install_channel,
            // System
            commands::system::system_is_admin,
            commands::system::system_check_driver,
            commands::system::system_install_driver,
            commands::system::system_repair_driver,
            commands::system::system_reset_driver,
            commands::system::system_open_url,
            commands::system::system_restart_as_admin,
            commands::system::system_show_notification,
            commands::system::system_launched_from_startup,
            commands::system::system_cleanup,
            commands::system::system_uninstall,
            commands::system::system_copy_log_to_clipboard,
        ])
        .setup(move |app| {
            info!("SwiftTunnel desktop app starting up");
            sync_runtime_assets(app);

            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_icon(APP_ICON.clone());
            }

            let runtime =
                Arc::new(tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime"));

            // Clean up any stale hosts-file entries from old proxy versions
            swifttunnel_core::roblox_proxy::hosts::recover_stale();

            let app_state = AppState::new(runtime.clone(), launched_from_startup)
                .expect("Failed to initialize app state");

            // Recover network booster state from persisted snapshot (crash recovery)
            app_state.network_booster.lock().recover_from_snapshot();

            // Recover TSO/IPv6 adapter settings if the app crashed while connected
            swifttunnel_core::vpn::recover_tso_on_startup();
            swifttunnel_core::vpn::recover_ipv6_on_startup();

            let run_on_startup_enabled = app_state.settings.lock().run_on_startup;
            let vpn_state_rx = app_state.vpn_state_handle.clone();
            app.manage(app_state);

            // Bridge every `VpnConnection` state transition — explicit
            // transitions AND the silent in-place mutations from the relay
            // health / auto-routing / process monitor tasks — to the UI's
            // `VPN_STATE_CHANGED` event. Without this, the UI can render a
            // state the backend has already moved past (e.g. showing a live
            // session timer after the relay reported "dead").
            commands::vpn::spawn_vpn_state_bridge(app.handle().clone(), vpn_state_rx);

            if let Err(e) = autostart::sync_run_on_startup(app.handle(), run_on_startup_enabled) {
                log::warn!("Failed to sync startup registration: {}", e);
            }

            // Window starts hidden via tauri.conf.json ("visible": false).
            // The frontend will call getCurrentWindow().show() after React loads,
            // unless launched_from_startup is true (user clicks tray to reveal).

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
        .build(ctx)
        .expect("error while building tauri application")
        .run(|_app, event| {
            match event {
                tauri::RunEvent::WindowEvent {
                    label,
                    event: tauri::WindowEvent::Destroyed,
                    ..
                } => {
                    if label == "main" {
                        // The main window was destroyed (not hidden). Exit the app
                        // so the tray icon doesn't leave a zombie process. The
                        // minimize-to-tray path uses hide(), not close(), so
                        // Destroyed only fires when the user actually wants to quit
                        // or an unexpected close occurred.
                        _app.exit(0);
                    }
                }
                tauri::RunEvent::Exit => {
                    // Clean up any stale hosts-file entries from old proxy versions
                    swifttunnel_core::roblox_proxy::hosts::recover_stale();
                    // Restore network booster modifications (registry, MTU, firewall, QoS)
                    if let Some(state) = _app.try_state::<crate::state::AppState>() {
                        let roblox_pid = {
                            let mut monitor = state.performance_monitor.lock();
                            monitor.get_roblox_pid().unwrap_or(0)
                        };
                        if let Err(e) = state.system_optimizer.lock().restore(roblox_pid) {
                            log::warn!("Failed to restore system settings on exit: {e}");
                        }
                        if let Err(e) = state.network_booster.lock().restore() {
                            log::warn!("Failed to restore network settings on exit: {e}");
                        }
                    }
                }
                _ => {}
            }
        });
}

pub fn run_testbench_harness(args: &[String]) -> i32 {
    harness::run_testbench_harness(args)
}
