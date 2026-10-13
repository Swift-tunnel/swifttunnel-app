use crate::state::AppState;
use swifttunnel_core::roblox_launcher::{LauncherConfig, SessionReport};
use tauri::State;
#[tauri::command]
pub fn games_displays() -> Vec<swifttunnel_core::roblox_window::Display> {
    swifttunnel_core::roblox_window::displays()
}
#[tauri::command]
pub fn games_startup_target() -> Option<String> {
    crate::game_shortcut::take_request()
}
#[tauri::command]
pub async fn games_create_shortcut(place_id: String, name: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || crate::game_shortcut::create(&place_id, &name))
        .await
        .map_err(|e| e.to_string())?
}
#[tauri::command]
pub fn games_launcher_config() -> Result<LauncherConfig, String> {
    LauncherConfig::load()
}
#[tauri::command]
pub fn games_save_launcher_config(config: LauncherConfig) -> Result<(), String> {
    config.save()
}
#[tauri::command]
pub fn games_session_reports() -> Result<Vec<SessionReport>, String> {
    let mut reports: Vec<SessionReport> =
        swifttunnel_core::roblox_launcher::load("game-sessions.json")?.unwrap_or_default();
    reports.truncate(20);
    Ok(reports)
}
#[tauri::command]
pub fn games_clear_session_reports() -> Result<(), String> {
    swifttunnel_core::roblox_launcher::save("game-sessions.json", &Vec::<SessionReport>::new())
}
#[tauri::command]
pub async fn games_launch_diagnostics(state: State<'_, AppState>) -> Result<Vec<String>, String> {
    let config = state.settings.lock().config.roblox_settings.clone();
    let optimizer = state.roblox_optimizer.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let mut notes = vec![];
        match swifttunnel_core::roblox_native_launch::official_player() {
            Ok(_) => notes.push(
                "Official Roblox player found. SwiftTunnel Play bypasses registered strap handlers."
                    .into(),
            ),
            Err(e) => notes.push(e),
        };
        if swifttunnel_core::roblox_launch_flags::pending() {
            notes.push("A temporary launch profile is active. It restores after Roblox closes.".into());
            if let Some(note) = swifttunnel_core::roblox_launch_flags::diagnostic()? {
                notes.push(note);
            }
        }
        if let Ok(preview) = optimizer.lock().inspect_launcher_imports() {
            if preview.sources.len() > 1 {
                notes.push("Multiple launcher flag files exist. Native Play uses only SwiftTunnel's selected profile; other launcher files are kept.".into());
            }
        }
        if config.custom_fflags_enabled {
            notes.push(
                "Custom SwiftTunnel flags are enabled. Try Safe launch to test without these flags."
                    .into(),
            );
        }
        match swifttunnel_core::vpn::list_network_adapters() {
            Ok(adapters) => {
                for adapter in adapters
                    .into_iter()
                    .filter(|a| a.is_up && a.is_default_route)
                {
                    notes.push(format!(
                        "Windows default route: {} ({}, interface {}).",
                        adapter.friendly_name, adapter.kind, adapter.if_index
                    ));
                    if matches!(adapter.kind.as_str(), "tunnel" | "virtual")
                        && !adapter.friendly_name.contains("SwiftTunnel")
                    {
                        notes.push("Another virtual adapter owns a default route. Check other VPNs if game packets or joins are failing; this alone does not prove a conflict.".into());
                    }
                }
            }
            Err(error) => notes.push(format!("Network adapter diagnostics unavailable: {error}")),
        }
        Ok(notes)
    })
    .await
    .map_err(|error| error.to_string())?
}
