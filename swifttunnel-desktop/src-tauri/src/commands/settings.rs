use serde::Serialize;
use tauri::State;

use crate::state::AppState;

#[derive(Serialize)]
pub struct SettingsResponse {
    pub json: String,
}

#[tauri::command]
pub fn settings_load(state: State<'_, AppState>) -> Result<SettingsResponse, String> {
    let settings = state.settings.lock();
    let json = serde_json::to_string(&*settings).map_err(|e| format!("Serialize error: {}", e))?;
    Ok(SettingsResponse { json })
}

#[tauri::command]
pub fn settings_save(state: State<'_, AppState>, settings_json: String) -> Result<(), String> {
    let new_settings: swifttunnel_core::settings::AppSettings =
        serde_json::from_str(&settings_json)
            .map_err(|e| format!("Invalid settings JSON: {}", e))?;

    swifttunnel_core::settings::save_settings(&new_settings)?;

    {
        let mut discord = state.discord_manager.lock();
        discord.set_enabled(new_settings.enable_discord_rpc);
    }

    let mut settings = state.settings.lock();
    *settings = new_settings;

    Ok(())
}
