use serde::Serialize;
use tauri::State;

use crate::state::AppState;

#[derive(Serialize)]
pub struct ProxyStateResponse {
    pub state: String,
    pub error: Option<String>,
    pub active_connections: u64,
    pub total_connections: u64,
    pub bytes_relayed: u64,
}

#[tauri::command]
pub async fn proxy_get_state(state: State<'_, AppState>) -> Result<ProxyStateResponse, String> {
    let proxy = state.roblox_proxy.lock().await;
    let stats = proxy.stats();

    let (state_str, error) = match proxy.state() {
        swifttunnel_core::roblox_proxy::ProxyState::Stopped => ("stopped", None),
        swifttunnel_core::roblox_proxy::ProxyState::Starting => ("starting", None),
        swifttunnel_core::roblox_proxy::ProxyState::Running => ("running", None),
        swifttunnel_core::roblox_proxy::ProxyState::Error(e) => ("error", Some(e.clone())),
    };

    Ok(ProxyStateResponse {
        state: state_str.to_string(),
        error,
        active_connections: stats.active_connections,
        total_connections: stats.total_connections,
        bytes_relayed: stats.bytes_relayed,
    })
}

#[tauri::command]
pub async fn proxy_toggle(state: State<'_, AppState>, enabled: bool) -> Result<(), String> {
    let sni_fragment = state.settings.lock().roblox_network_bypass_sni_fragment;

    let mut proxy = state.roblox_proxy.lock().await;

    if enabled {
        proxy.start(sni_fragment).await.map_err(|e| e.to_string())?;
    } else {
        proxy.stop().await.map_err(|e| e.to_string())?;
    }

    // Persist the setting
    {
        let mut settings = state.settings.lock();
        settings.roblox_network_bypass = enabled;
        let _ = swifttunnel_core::settings::save_settings(&settings);
    }

    Ok(())
}
