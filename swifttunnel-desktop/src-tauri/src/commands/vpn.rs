use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use tauri::{AppHandle, Emitter, State};

use crate::events::{SERVER_LIST_UPDATED, VPN_STATE_CHANGED, VpnStateEvent};
use crate::state::AppState;
use swifttunnel_core::settings::AdapterBindingMode;

#[derive(Serialize)]
pub struct VpnStateResponse {
    pub state: String,
    pub region: Option<String>,
    pub server_endpoint: Option<String>,
    pub assigned_ip: Option<String>,
    pub relay_auth_mode: Option<String>,
    pub split_tunnel_active: bool,
    pub tunneled_processes: Vec<String>,
    pub error: Option<String>,
}

fn map_vpn_state(conn_state: swifttunnel_core::vpn::ConnectionState) -> VpnStateResponse {
    match conn_state {
        swifttunnel_core::vpn::ConnectionState::Disconnected => VpnStateResponse {
            state: "disconnected".to_string(),
            region: None,
            server_endpoint: None,
            assigned_ip: None,
            relay_auth_mode: None,
            split_tunnel_active: false,
            tunneled_processes: vec![],
            error: None,
        },
        swifttunnel_core::vpn::ConnectionState::FetchingConfig => VpnStateResponse {
            state: "fetching_config".to_string(),
            region: None,
            server_endpoint: None,
            assigned_ip: None,
            relay_auth_mode: None,
            split_tunnel_active: false,
            tunneled_processes: vec![],
            error: None,
        },
        swifttunnel_core::vpn::ConnectionState::ConfiguringSplitTunnel => VpnStateResponse {
            state: "configuring_split_tunnel".to_string(),
            region: None,
            server_endpoint: None,
            assigned_ip: None,
            relay_auth_mode: None,
            split_tunnel_active: false,
            tunneled_processes: vec![],
            error: None,
        },
        swifttunnel_core::vpn::ConnectionState::Connected {
            server_region,
            server_endpoint,
            assigned_ip,
            relay_auth_mode,
            split_tunnel_active,
            tunneled_processes,
            ..
        } => VpnStateResponse {
            state: "connected".to_string(),
            region: Some(server_region),
            server_endpoint: Some(server_endpoint),
            assigned_ip: Some(assigned_ip),
            relay_auth_mode: Some(relay_auth_mode),
            split_tunnel_active,
            tunneled_processes,
            error: None,
        },
        swifttunnel_core::vpn::ConnectionState::Disconnecting => VpnStateResponse {
            state: "disconnecting".to_string(),
            region: None,
            server_endpoint: None,
            assigned_ip: None,
            relay_auth_mode: None,
            split_tunnel_active: false,
            tunneled_processes: vec![],
            error: None,
        },
        swifttunnel_core::vpn::ConnectionState::Error(msg) => VpnStateResponse {
            state: "error".to_string(),
            region: None,
            server_endpoint: None,
            assigned_ip: None,
            relay_auth_mode: None,
            split_tunnel_active: false,
            tunneled_processes: vec![],
            error: Some(msg),
        },
    }
}

fn parse_game_presets(game_presets: &[String]) -> HashSet<swifttunnel_core::vpn::GamePreset> {
    game_presets
        .iter()
        .filter_map(|preset| {
            let normalized = preset.trim().to_ascii_lowercase();
            match normalized.as_str() {
                "roblox" => Some(swifttunnel_core::vpn::GamePreset::Roblox),
                "valorant" => Some(swifttunnel_core::vpn::GamePreset::Valorant),
                "fortnite" => Some(swifttunnel_core::vpn::GamePreset::Fortnite),
                _ => None,
            }
        })
        .collect()
}

fn apply_connected_session_settings(
    settings: &mut swifttunnel_core::settings::AppSettings,
    region: &str,
) {
    settings.last_connected_region = Some(region.to_string());
    settings.resume_vpn_on_startup = true;
}

fn apply_disconnected_session_settings(settings: &mut swifttunnel_core::settings::AppSettings) {
    settings.resume_vpn_on_startup = false;
}

fn persist_session_settings(
    state: &AppState,
    connected_region: Option<&str>,
) -> Result<(), String> {
    let mut settings = state.settings.lock();
    if let Some(region) = connected_region {
        apply_connected_session_settings(&mut settings, region);
    } else {
        apply_disconnected_session_settings(&mut settings);
    }
    let snapshot = settings.clone();
    drop(settings);
    swifttunnel_core::settings::save_settings(&snapshot)
}

async fn emit_vpn_state(app: &AppHandle, state: &AppState) {
    let vpn = state.vpn_connection.lock().await;
    let conn_state = vpn.state().await;
    drop(vpn);

    let response = map_vpn_state(conn_state);
    let payload = VpnStateEvent {
        state: response.state,
        region: response.region,
        server_endpoint: response.server_endpoint,
        assigned_ip: response.assigned_ip,
        error: response.error,
    };
    let _ = app.emit(VPN_STATE_CHANGED, payload);
}

#[tauri::command]
pub async fn vpn_get_state(state: State<'_, AppState>) -> Result<VpnStateResponse, String> {
    let vpn = state.vpn_connection.lock().await;
    let conn_state = vpn.state().await;
    Ok(map_vpn_state(conn_state))
}

#[tauri::command]
pub async fn vpn_connect(
    state: State<'_, AppState>,
    app: AppHandle,
    region: String,
    game_presets: Vec<String>,
) -> Result<(), String> {
    {
        let mut discord = state.discord_manager.lock();
        discord.set_connecting(&region);
    }

    // Gather needed data from settings and server list before locking vpn
    let (
        custom_relay,
        auto_routing,
        relay_qos_enabled,
        whitelisted_regions,
        forced_servers,
        preferred_physical_adapter_guid,
    ) = {
        let settings = state.settings.lock();
        let preferred_physical_adapter_guid = match settings.adapter_binding_mode {
            AdapterBindingMode::Manual => settings.preferred_physical_adapter_guid.clone(),
            AdapterBindingMode::SmartAuto => None,
        };
        (
            if settings.custom_relay_server.is_empty() {
                None
            } else {
                Some(settings.custom_relay_server.clone())
            },
            settings.auto_routing_enabled,
            settings.config.network_settings.gaming_qos,
            settings.whitelisted_regions.clone(),
            settings.forced_servers.clone(),
            preferred_physical_adapter_guid,
        )
    };

    let preset_set = parse_game_presets(&game_presets);
    let tunnel_apps = swifttunnel_core::vpn::get_apps_for_preset_set(&preset_set);

    // Build available_servers list from the dynamic server list
    let available_servers: Vec<(String, SocketAddr, Option<u32>)> = {
        let sl = state.server_list.lock();
        sl.servers()
            .iter()
            .filter_map(|s| {
                let addr: SocketAddr = format!("{}:{}", s.ip, 51821).parse().ok()?;
                let latency = sl.get_latency(&s.region);
                Some((s.region.clone(), addr, latency))
            })
            .collect()
    };

    // Get access token
    let access_token = {
        let auth = state.auth_manager.lock().await;
        auth.get_access_token().await.map_err(|e| e.to_string())?
    };

    let mut vpn = state.vpn_connection.lock().await;
    let result = vpn
        .connect(
            &access_token,
            &region,
            tunnel_apps,
            custom_relay,
            auto_routing,
            relay_qos_enabled,
            available_servers,
            whitelisted_regions,
            forced_servers,
            preferred_physical_adapter_guid,
        )
        .await
        .map_err(|e| swifttunnel_core::vpn::user_friendly_error(&e));
    drop(vpn);

    {
        let mut discord = state.discord_manager.lock();
        if result.is_ok() {
            discord.set_connected(&region);
        } else {
            discord.set_idle();
        }
    }

    if result.is_ok() {
        if let Err(e) = persist_session_settings(&state, Some(&region)) {
            log::warn!("Failed to persist connected session settings: {}", e);
        }
    }

    emit_vpn_state(&app, &state).await;
    result
}

#[tauri::command]
pub async fn vpn_disconnect(state: State<'_, AppState>, app: AppHandle) -> Result<(), String> {
    let mut vpn = state.vpn_connection.lock().await;
    let result = vpn
        .disconnect()
        .await
        .map_err(|e| swifttunnel_core::vpn::user_friendly_error(&e));
    drop(vpn);

    {
        let mut discord = state.discord_manager.lock();
        discord.set_idle();
    }

    if result.is_ok() {
        if let Err(e) = persist_session_settings(&state, None) {
            log::warn!("Failed to persist disconnected session settings: {}", e);
        }
    }

    emit_vpn_state(&app, &state).await;
    result
}

#[tauri::command]
pub async fn vpn_get_ping(state: State<'_, AppState>) -> Result<Option<u32>, String> {
    let vpn = state.vpn_connection.lock().await;
    let relay_addr = vpn.current_relay_addr();
    drop(vpn);

    let addr = match relay_addr {
        Some(a) => a,
        None => return Ok(None),
    };

    let ip = addr.ip().to_string();
    let result = tokio::task::spawn_blocking(move || {
        swifttunnel_core::vpn::servers::measure_latency_icmp(&ip)
    })
    .await
    .map_err(|e| format!("Ping task failed: {}", e))?;

    Ok(result)
}

#[derive(Serialize)]
pub struct ThroughputResponse {
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub packets_tunneled: u64,
    pub packets_bypassed: u64,
}

#[tauri::command]
pub async fn vpn_get_throughput(
    state: State<'_, AppState>,
) -> Result<Option<ThroughputResponse>, String> {
    let vpn = state.vpn_connection.lock().await;
    Ok(vpn.get_throughput_stats().map(|stats| ThroughputResponse {
        bytes_up: stats.get_bytes_tx(),
        bytes_down: stats.get_bytes_rx(),
        packets_tunneled: 0,
        packets_bypassed: 0,
    }))
}

#[derive(Serialize)]
pub struct DiagnosticsResponse {
    pub adapter_name: Option<String>,
    pub adapter_guid: Option<String>,
    pub selected_if_index: Option<u32>,
    pub resolved_if_index: Option<u32>,
    pub has_default_route: bool,
    pub route_resolution_source: Option<String>,
    pub route_resolution_target_ip: Option<String>,
    pub manual_binding_active: bool,
    pub packets_tunneled: u64,
    pub packets_bypassed: u64,
}

#[tauri::command]
pub async fn vpn_get_diagnostics(
    state: State<'_, AppState>,
) -> Result<Option<DiagnosticsResponse>, String> {
    let vpn = state.vpn_connection.lock().await;
    Ok(vpn
        .get_split_tunnel_diagnostics()
        .map(|diag| DiagnosticsResponse {
            adapter_name: diag.adapter_name,
            adapter_guid: diag.adapter_guid,
            selected_if_index: diag.selected_if_index,
            resolved_if_index: diag.resolved_if_index,
            has_default_route: diag.has_default_route,
            route_resolution_source: Some(diag.route_resolution_source),
            route_resolution_target_ip: diag.route_resolution_target_ip,
            manual_binding_active: diag.manual_binding_active,
            packets_tunneled: diag.packets_tunneled,
            packets_bypassed: diag.packets_bypassed,
        }))
}

#[tauri::command]
pub fn vpn_list_network_adapters() -> Result<Vec<swifttunnel_core::vpn::NetworkAdapterInfo>, String>
{
    swifttunnel_core::vpn::list_network_adapters().map_err(|e| e.to_string())
}

// --- Server commands ---

#[derive(Serialize)]
pub struct ServerRegionResponse {
    pub id: String,
    pub name: String,
    pub description: String,
    pub country_code: String,
    pub servers: Vec<String>,
}

#[derive(Serialize)]
pub struct ServerInfoResponse {
    pub region: String,
    pub name: String,
    pub country_code: String,
    pub ip: String,
    pub port: u16,
}

#[derive(Serialize)]
pub struct ServerListResponse {
    pub regions: Vec<ServerRegionResponse>,
    pub servers: Vec<ServerInfoResponse>,
    pub source: String,
}

#[tauri::command]
pub fn server_get_list(state: State<'_, AppState>) -> ServerListResponse {
    let sl = state.server_list.lock();
    ServerListResponse {
        regions: sl
            .regions()
            .iter()
            .map(|r| ServerRegionResponse {
                id: r.id.clone(),
                name: r.name.clone(),
                description: r.description.clone(),
                country_code: r.country_code.clone(),
                servers: r.servers.clone(),
            })
            .collect(),
        servers: sl
            .servers()
            .iter()
            .map(|s| ServerInfoResponse {
                region: s.region.clone(),
                name: s.name.clone(),
                country_code: s.country_code.clone(),
                ip: s.ip.clone(),
                port: s.port,
            })
            .collect(),
        source: sl.source.to_string(),
    }
}

#[derive(Serialize)]
pub struct LatencyEntry {
    pub region: String,
    pub latency_ms: Option<u32>,
}

#[tauri::command]
pub async fn server_get_latencies(state: State<'_, AppState>) -> Result<Vec<LatencyEntry>, String> {
    let probes: Vec<(String, String, u16, String)> = {
        let sl = state.server_list.lock();
        sl.regions()
            .iter()
            .filter_map(|region| {
                let server_id = region.servers.first()?.clone();
                let server = sl.get_server(&server_id)?;
                Some((region.id.clone(), server.ip.clone(), server.port, server_id))
            })
            .collect()
    };

    let mut tasks = tokio::task::JoinSet::new();
    for (region_id, ip, port, server_id) in probes {
        tasks.spawn(async move {
            let endpoint = format!("{ip}:{port}");
            let latency = swifttunnel_core::vpn::servers::measure_latency(&endpoint)
                .await
                .or_else(|| swifttunnel_core::vpn::servers::measure_latency_icmp(&ip));
            (region_id, server_id, latency)
        });
    }

    let mut measured: HashMap<String, (String, Option<u32>)> = HashMap::new();
    while let Some(result) = tasks.join_next().await {
        if let Ok((region_id, server_id, latency)) = result {
            measured.insert(region_id, (server_id, latency));
        }
    }

    let mut sl = state.server_list.lock();
    for (_region_id, (server_id, latency)) in measured {
        sl.set_latency(&server_id, latency);
    }

    Ok(sl
        .regions()
        .iter()
        .map(|r| LatencyEntry {
            region: r.id.clone(),
            latency_ms: sl.get_region_best_latency(&r.id),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_connected_session_settings_marks_resume_and_region() {
        let mut settings = swifttunnel_core::settings::AppSettings::default();
        apply_connected_session_settings(&mut settings, "singapore");
        assert_eq!(settings.last_connected_region.as_deref(), Some("singapore"));
        assert!(settings.resume_vpn_on_startup);
    }

    #[test]
    fn apply_disconnected_session_settings_clears_resume_flag() {
        let mut settings = swifttunnel_core::settings::AppSettings::default();
        settings.resume_vpn_on_startup = true;
        apply_disconnected_session_settings(&mut settings);
        assert!(!settings.resume_vpn_on_startup);
    }
}

#[tauri::command]
pub async fn server_refresh(state: State<'_, AppState>, app: AppHandle) -> Result<String, String> {
    let (servers, regions, source) = swifttunnel_core::vpn::servers::load_server_list().await?;

    let mut sl = state.server_list.lock();
    sl.update(servers, regions, source.clone());
    drop(sl);

    let _ = app.emit(SERVER_LIST_UPDATED, source.to_string());

    Ok(source.to_string())
}

#[tauri::command]
pub fn server_smart_select(state: State<'_, AppState>, region_id: String) -> Option<String> {
    let sl = state.server_list.lock();
    // Find the server with lowest latency in the region
    let region = sl.get_region(&region_id)?;
    let mut best: Option<(String, u32)> = None;
    for server_id in &region.servers {
        if let Some(latency) = sl.get_latency(server_id) {
            if best
                .as_ref()
                .map_or(true, |(_, best_ms)| latency < *best_ms)
            {
                best = Some((server_id.clone(), latency));
            }
        }
    }
    best.map(|(id, _)| id)
        .or_else(|| region.servers.first().cloned())
}
