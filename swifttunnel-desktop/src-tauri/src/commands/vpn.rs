use serde::Serialize;
use std::collections::HashSet;
use std::net::SocketAddr;
use tauri::{AppHandle, Emitter, State};

use crate::events::{SERVER_LIST_UPDATED, VPN_STATE_CHANGED, VpnStateEvent};
use crate::state::AppState;
use swifttunnel_core::settings::AdapterBindingMode;
use swifttunnel_core::vpn::{
    AdapterBindingPreference, BindingPreferenceSource, BindingPreflightInfo, preflight_binding,
};

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

fn resolve_discord_region(
    conn_state: &swifttunnel_core::vpn::ConnectionState,
    requested_region: &str,
) -> String {
    match conn_state {
        swifttunnel_core::vpn::ConnectionState::Connected { server_region, .. }
            if !server_region.trim().is_empty() =>
        {
            server_region.clone()
        }
        _ => requested_region.to_string(),
    }
}

pub(crate) fn parse_game_presets(
    game_presets: &[String],
) -> HashSet<swifttunnel_core::vpn::GamePreset> {
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

pub(crate) fn current_binding_preference(
    settings: &mut swifttunnel_core::settings::AppSettings,
) -> Result<Option<AdapterBindingPreference>, String> {
    match settings.adapter_binding_mode {
        AdapterBindingMode::Manual => {
            Ok(settings
                .preferred_physical_adapter_guid
                .clone()
                .map(|guid| AdapterBindingPreference {
                    guid,
                    source: BindingPreferenceSource::Manual,
                    network_signature: None,
                }))
        }
        AdapterBindingMode::SmartAuto => {
            let base = preflight_binding(None).map_err(|e| e.to_string())?;
            let Some(guid) = settings
                .network_binding_overrides
                .get(&base.network_signature)
                .cloned()
            else {
                return Ok(None);
            };

            Ok(Some(AdapterBindingPreference {
                guid,
                source: BindingPreferenceSource::RememberedAuto,
                network_signature: Some(base.network_signature),
            }))
        }
    }
}

pub(crate) fn build_binding_preflight(
    settings: &mut swifttunnel_core::settings::AppSettings,
) -> Result<BindingPreflightInfo, String> {
    let binding_preference = current_binding_preference(settings)?;
    let preflight = preflight_binding(binding_preference.clone()).map_err(|e| e.to_string())?;

    if let Some(preference) = binding_preference {
        if preference.source == BindingPreferenceSource::RememberedAuto
            && !preflight.cached_override_used
            && preflight.recommended_guid.as_deref() != Some(preference.guid.as_str())
        {
            settings
                .network_binding_overrides
                .remove(&preference.network_signature.unwrap_or_default());
        }
    }

    Ok(preflight)
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
pub async fn vpn_preflight_binding(
    state: State<'_, AppState>,
    _region: String,
    _game_presets: Vec<String>,
) -> Result<BindingPreflightInfo, String> {
    let settings_arc = state.settings.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let mut settings = settings_arc.lock();
        let previous_overrides = settings.network_binding_overrides.clone();
        let preflight = build_binding_preflight(&mut settings)?;
        let settings_snapshot = settings.clone();
        let overrides_changed = previous_overrides != settings.network_binding_overrides;
        drop(settings);

        if overrides_changed {
            swifttunnel_core::settings::save_settings(&settings_snapshot)?;
        }

        Ok(preflight)
    })
    .await
    .map_err(|e| format!("Preflight binding task failed: {}", e))?
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
        binding_preference,
        game_process_performance,
        enable_api_tunneling,
    ) = {
        let mut settings = state.settings.lock();
        let previous_overrides = settings.network_binding_overrides.clone();
        let preflight = build_binding_preflight(&mut settings)?;
        if preflight.status != "ok" {
            return Err(preflight.reason);
        }
        let binding_preference = current_binding_preference(&mut settings)?;
        let settings_snapshot = settings.clone();
        let overrides_changed = previous_overrides != settings.network_binding_overrides;
        drop(settings);

        if overrides_changed {
            swifttunnel_core::settings::save_settings(&settings_snapshot)?;
        }

        (
            if settings_snapshot.custom_relay_server.is_empty() {
                None
            } else {
                Some(settings_snapshot.custom_relay_server.clone())
            },
            settings_snapshot.auto_routing_enabled,
            settings_snapshot.config.network_settings.gaming_qos,
            settings_snapshot.whitelisted_regions.clone(),
            settings_snapshot.forced_servers.clone(),
            binding_preference,
            settings_snapshot.game_process_performance,
            settings_snapshot.enable_api_tunneling,
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
            binding_preference,
            game_process_performance,
            enable_api_tunneling,
        )
        .await
        .map_err(|e| swifttunnel_core::vpn::user_friendly_error(&e));
    drop(vpn);

    let discord_region = if result.is_ok() {
        let vpn = state.vpn_connection.lock().await;
        let conn_state = vpn.state().await;
        Some(resolve_discord_region(&conn_state, &region))
    } else {
        None
    };

    {
        let mut discord = state.discord_manager.lock();
        if let Some(ref connected_region) = discord_region {
            discord.set_connected(connected_region);
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
    let (relay_ping, relay_addr) = {
        let vpn = state.vpn_connection.lock().await;
        let relay_ping = vpn.get_relay_ping_snapshot().and_then(|snapshot| {
            if !snapshot.enabled {
                return None;
            }
            snapshot
                .last_rtt_ms
                .or(snapshot.p50_rtt_ms)
                .or(snapshot.p99_rtt_ms)
        });
        let relay_addr = vpn.current_relay_addr();
        (relay_ping, relay_addr)
    };

    // Preferred source: in-tunnel relay RTT telemetry from control-plane ping/pong.
    // This keeps ping populated even when ICMP is blocked or rate-limited.
    if relay_ping.is_some() {
        return Ok(relay_ping);
    }

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
    pub binding_reason: String,
    pub binding_stage: String,
    pub cached_override_used: bool,
    pub network_signature: Option<String>,
    pub last_validation_result: String,
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
            binding_reason: diag.binding_reason,
            binding_stage: diag.binding_stage,
            cached_override_used: diag.cached_override_used,
            network_signature: diag.network_signature,
            last_validation_result: diag.last_validation_result,
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
pub async fn server_get_list(
    state: State<'_, AppState>,
) -> Result<ServerListResponse, String> {
    let server_list = state.server_list.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let sl = server_list.lock();
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
    })
    .await
    .map_err(|e| format!("Server list task failed: {}", e))
}

#[derive(Serialize)]
pub struct LatencyEntry {
    pub region: String,
    pub latency_ms: Option<u32>,
}

const LATENCY_PROBE_CONCURRENCY: usize = 8;

fn build_latency_probe_targets(
    sl: &swifttunnel_core::vpn::servers::DynamicServerList,
) -> Vec<(String, String, u16)> {
    sl.servers()
        .iter()
        .map(|server| (server.region.clone(), server.ip.clone(), server.port))
        .collect()
}

fn apply_latency_measurements(
    sl: &mut swifttunnel_core::vpn::servers::DynamicServerList,
    measurements: &[(String, Option<u32>)],
) -> Vec<LatencyEntry> {
    for (server_id, latency) in measurements {
        sl.set_latency(server_id, *latency);
    }

    sl.regions()
        .iter()
        .map(|region| LatencyEntry {
            region: region.id.clone(),
            latency_ms: sl.get_region_best_latency(&region.id),
        })
        .collect()
}

fn select_best_server_in_region(
    sl: &swifttunnel_core::vpn::servers::DynamicServerList,
    region_id: &str,
) -> Option<String> {
    let region = sl.get_region(region_id)?;
    let mut best: Option<(String, u32)> = None;
    for server_id in &region.servers {
        if let Some(latency) = sl.get_latency(server_id) {
            if best.as_ref().is_none_or(|(_, best_ms)| latency < *best_ms) {
                best = Some((server_id.clone(), latency));
            }
        }
    }
    best.map(|(id, _)| id)
        .or_else(|| region.servers.first().cloned())
}

#[tauri::command]
pub async fn server_get_latencies(state: State<'_, AppState>) -> Result<Vec<LatencyEntry>, String> {
    let probes = {
        let sl = state.server_list.lock();
        build_latency_probe_targets(&sl)
    };

    let mut tasks = tokio::task::JoinSet::new();
    let mut measured: Vec<(String, Option<u32>)> = Vec::with_capacity(probes.len());
    for (server_id, ip, port) in probes {
        if tasks.len() >= LATENCY_PROBE_CONCURRENCY {
            if let Some(result) = tasks.join_next().await {
                if let Ok((server_id, latency)) = result {
                    measured.push((server_id, latency));
                }
            }
        }
        tasks.spawn(async move {
            let endpoint = format!("{ip}:{port}");
            let latency = swifttunnel_core::vpn::servers::measure_latency(&endpoint)
                .await
                .or_else(|| swifttunnel_core::vpn::servers::measure_latency_icmp(&ip));
            (server_id, latency)
        });
    }

    while let Some(result) = tasks.join_next().await {
        if let Ok((server_id, latency)) = result {
            measured.push((server_id, latency));
        }
    }

    let mut sl = state.server_list.lock();
    Ok(apply_latency_measurements(&mut sl, &measured))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    use swifttunnel_core::vpn::servers::{
        DynamicGamingRegion, DynamicServerInfo, DynamicServerList, ServerListSource,
    };

    fn make_server(region: &str, ip: &str) -> DynamicServerInfo {
        DynamicServerInfo {
            region: region.to_string(),
            name: region.to_string(),
            country_code: "XX".to_string(),
            ip: ip.to_string(),
            port: 51821,
            phantun_available: false,
            phantun_port: None,
        }
    }

    fn make_region(id: &str, servers: &[&str]) -> DynamicGamingRegion {
        DynamicGamingRegion {
            id: id.to_string(),
            name: id.to_string(),
            description: id.to_string(),
            country_code: "XX".to_string(),
            servers: servers.iter().map(|server| (*server).to_string()).collect(),
        }
    }

    fn make_dynamic_server_list() -> DynamicServerList {
        let mut list = DynamicServerList::new_empty();
        list.update(
            vec![
                make_server("singapore", "1.1.1.1"),
                make_server("singapore-02", "1.1.1.2"),
                make_server("tokyo-01", "2.2.2.1"),
            ],
            vec![
                make_region("singapore", &["singapore", "singapore-02"]),
                make_region("tokyo", &["tokyo-01"]),
            ],
            ServerListSource::Api,
        );
        list
    }

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

    #[test]
    fn resolve_discord_region_prefers_connected_server_region() {
        let conn_state = swifttunnel_core::vpn::ConnectionState::Connected {
            since: Instant::now(),
            server_region: "us-east-nj".to_string(),
            server_endpoint: "1.2.3.4:51821".to_string(),
            assigned_ip: "V3-Relay".to_string(),
            relay_auth_mode: "authenticated".to_string(),
            split_tunnel_active: true,
            tunneled_processes: vec!["RobloxPlayerBeta.exe".to_string()],
        };

        assert_eq!(
            resolve_discord_region(&conn_state, "na-east"),
            "us-east-nj".to_string()
        );
    }

    #[test]
    fn resolve_discord_region_falls_back_when_not_connected() {
        assert_eq!(
            resolve_discord_region(
                &swifttunnel_core::vpn::ConnectionState::FetchingConfig,
                "singapore"
            ),
            "singapore".to_string()
        );
    }

    #[test]
    fn resolve_discord_region_falls_back_when_connected_region_empty() {
        let conn_state = swifttunnel_core::vpn::ConnectionState::Connected {
            since: Instant::now(),
            server_region: "   ".to_string(),
            server_endpoint: "1.2.3.4:51821".to_string(),
            assigned_ip: "V3-Relay".to_string(),
            relay_auth_mode: "authenticated".to_string(),
            split_tunnel_active: true,
            tunneled_processes: vec![],
        };

        assert_eq!(
            resolve_discord_region(&conn_state, "germany"),
            "germany".to_string()
        );
    }

    #[test]
    fn build_latency_probe_targets_includes_every_server() {
        let list = make_dynamic_server_list();
        let probes = build_latency_probe_targets(&list);

        assert_eq!(probes.len(), 3);
        assert!(probes.contains(&("singapore".to_string(), "1.1.1.1".to_string(), 51821)));
        assert!(probes.contains(&("singapore-02".to_string(), "1.1.1.2".to_string(), 51821)));
        assert!(probes.contains(&("tokyo-01".to_string(), "2.2.2.1".to_string(), 51821)));
    }

    #[test]
    fn apply_latency_measurements_updates_all_servers_and_region_best_latency() {
        let mut list = make_dynamic_server_list();
        let measurements = vec![
            ("singapore".to_string(), Some(18)),
            ("singapore-02".to_string(), Some(7)),
            ("tokyo-01".to_string(), Some(40)),
        ];

        let latencies = apply_latency_measurements(&mut list, &measurements);

        assert_eq!(list.get_latency("singapore"), Some(18));
        assert_eq!(list.get_latency("singapore-02"), Some(7));
        assert_eq!(list.get_region_best_latency("singapore"), Some(7));
        assert_eq!(list.get_region_best_latency("tokyo"), Some(40));

        assert!(
            latencies
                .iter()
                .any(|entry| entry.region == "singapore" && entry.latency_ms == Some(7))
        );
        assert!(
            latencies
                .iter()
                .any(|entry| entry.region == "tokyo" && entry.latency_ms == Some(40))
        );
    }

    #[test]
    fn select_best_server_in_region_prefers_lowest_latency() {
        let mut list = make_dynamic_server_list();
        list.set_latency("singapore", Some(22));
        list.set_latency("singapore-02", Some(9));

        let selected = select_best_server_in_region(&list, "singapore");
        assert_eq!(selected.as_deref(), Some("singapore-02"));
    }

    #[test]
    fn select_best_server_in_region_falls_back_to_first_server_without_latency() {
        let list = make_dynamic_server_list();

        let selected = select_best_server_in_region(&list, "singapore");
        assert_eq!(selected.as_deref(), Some("singapore"));
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
    select_best_server_in_region(&sl, &region_id)
}
