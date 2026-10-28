use swifttunnel_core::roblox_launcher::LauncherConfig;
#[tauri::command]
pub async fn games_displays() -> Result<Vec<swifttunnel_core::roblox_window::Display>, String> {
    tauri::async_runtime::spawn_blocking(swifttunnel_core::roblox_window::displays)
        .await
        .map_err(|error| {
            log::warn!("Display discovery task failed: {error}");
            "Couldn't read your displays. Reopen game settings to retry.".into()
        })
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
pub async fn games_launcher_config() -> Result<LauncherConfig, String> {
    tauri::async_runtime::spawn_blocking(LauncherConfig::load)
        .await
        .map_err(|e| e.to_string())?
}
#[tauri::command]
pub async fn games_save_launcher_config(config: LauncherConfig) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || config.save())
        .await
        .map_err(|e| e.to_string())?
}
