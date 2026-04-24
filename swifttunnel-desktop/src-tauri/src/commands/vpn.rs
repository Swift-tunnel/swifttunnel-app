use serde::Serialize;
use std::collections::{HashMap, HashSet};
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
    /// Relay health status: None/absent = healthy, "stale" = no traffic 30s+, "dead" = no response 60s+
    pub relay_status: Option<String>,
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
            relay_status: None,
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
            relay_status: None,
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
            relay_status: None,
        },
        swifttunnel_core::vpn::ConnectionState::Connected {
            server_region,
            server_endpoint,
            assigned_ip,
            relay_auth_mode,
            split_tunnel_active,
            tunneled_processes,
            relay_status,
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
            relay_status,
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
            relay_status: None,
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
            relay_status: None,
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

/// Tear down the live VPN session and drop all in-memory state that points at
/// it. Always clears the published split-tunnel handle, sets Discord idle, and
/// persists the disconnected session — even when the driver-level disconnect
/// returns an error, because at that point the driver state is undefined and
/// we'd rather report `None` to the UI (and refuse to auto-resume on next
/// launch) than leave a stale handle or a stale `resume_vpn_on_startup` flag.
///
/// Shared between `vpn_disconnect` (explicit user action) and the in-app
/// uninstall path in `commands::system`, which needs the same teardown
/// ordering before it queues the NSIS uninstaller.
pub(crate) async fn disconnect_and_persist(state: &AppState) -> Result<(), String> {
    let mut vpn = state.vpn_connection.lock().await;
    let result = vpn
        .disconnect()
        .await
        .map_err(|e| swifttunnel_core::vpn::user_friendly_error(&e));
    // Clear the published handle whether disconnect succeeded or not — on
    // failure the driver state is undefined and we'd rather report None to
    // the UI than hand it a stale pointer.
    *state.split_tunnel_handle.write() = None;
    drop(vpn);

    {
        let mut discord = state.discord_manager.lock();
        discord.set_idle();
    }

    // Always persist the disconnected session. If disconnect failed the
    // driver is in an unknown state, so clearing `resume_vpn_on_startup` is
    // safer than letting the app auto-resume into it on next launch.
    if let Err(e) = persist_session_settings(state, None) {
        log::warn!("Failed to persist disconnected session settings: {}", e);
    }

    result
}

fn vpn_state_event(conn_state: swifttunnel_core::vpn::ConnectionState) -> VpnStateEvent {
    let response = map_vpn_state(conn_state);
    VpnStateEvent {
        state: response.state,
        region: response.region,
        server_endpoint: response.server_endpoint,
        assigned_ip: response.assigned_ip,
        error: response.error,
    }
}

/// Subscribe to VPN state transitions and bridge each one to the
/// `VPN_STATE_CHANGED` Tauri event.
///
/// `VpnConnection` publishes every state change (explicit `set_state`, the
/// relay-health / auto-routing / process-monitor in-place updates, and
/// `switch_server`) through a single `tokio::sync::watch` channel. This
/// bridge is the ONLY place that forwards those updates to the UI, which
/// is why individual command handlers no longer need to emit manually —
/// any code path that reaches `self.state` is already covered.
pub(crate) fn spawn_vpn_state_bridge(
    app: AppHandle,
    mut rx: tokio::sync::watch::Receiver<swifttunnel_core::vpn::ConnectionState>,
) {
    tauri::async_runtime::spawn(async move {
        // The initial value is marked unseen on `subscribe()`, so the first
        // `changed()` returns immediately and the UI gets a definitive
        // snapshot right after startup. Subsequent iterations wake only on
        // actual transitions.
        loop {
            let conn_state = rx.borrow_and_update().clone();
            let _ = app.emit(VPN_STATE_CHANGED, vpn_state_event(conn_state));
            if rx.changed().await.is_err() {
                // Sender dropped — the VpnConnection is gone, which only
                // happens during app teardown. Stop the bridge cleanly.
                break;
            }
        }
    });
}

#[tauri::command]
pub async fn vpn_get_state(state: State<'_, AppState>) -> Result<VpnStateResponse, String> {
    // Read the inner state Arc directly so we don't have to wait on the
    // outer vpn_connection mutex while a connect or disconnect is mid-flight.
    let conn_state = state.vpn_state_handle.borrow().clone();
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
    region: String,
    game_presets: Vec<String>,
) -> Result<(), String> {
    // Gather needed data from settings and server list before locking vpn
    let (settings_snapshot, binding_preference, overrides_changed) = {
        let mut settings = state.settings.lock();
        let previous_overrides = settings.network_binding_overrides.clone();
        let preflight = build_binding_preflight(&mut settings)?;
        if preflight.status != "ok" {
            return Err(preflight.reason);
        }
        let binding_preference = current_binding_preference(&mut settings)?;
        let snapshot = settings.clone();
        let overrides_changed = previous_overrides != settings.network_binding_overrides;
        (snapshot, binding_preference, overrides_changed)
    };

    if overrides_changed {
        let snapshot_for_save = settings_snapshot.clone();
        tauri::async_runtime::spawn_blocking(move || {
            swifttunnel_core::settings::save_settings(&snapshot_for_save)
        })
        .await
        .map_err(|e| format!("save_settings task failed: {}", e))??;
    }

    let (
        custom_relay,
        mut auto_routing,
        relay_qos_enabled,
        whitelisted_regions,
        forced_servers,
        game_process_performance,
        enable_api_tunneling,
    ) = (
        if settings_snapshot.custom_relay_server.is_empty() {
            None
        } else {
            Some(settings_snapshot.custom_relay_server.clone())
        },
        settings_snapshot.auto_routing_enabled,
        settings_snapshot.config.network_settings.gaming_qos,
        settings_snapshot.whitelisted_regions.clone(),
        settings_snapshot.forced_servers.clone(),
        settings_snapshot.game_process_performance,
        settings_snapshot.enable_api_tunneling,
    );
    if custom_relay.is_some() && auto_routing {
        log::info!("Auto-routing disabled for this session because custom_relay_server is set");
        auto_routing = false;
    }

    let preset_set = parse_game_presets(&game_presets);
    let tunnel_apps = swifttunnel_core::vpn::get_apps_for_preset_set(&preset_set);

    // Build available_servers list from the dynamic server list
    let (connect_region, available_servers): (String, Vec<(String, SocketAddr, Option<u32>)>) = {
        let sl = state.server_list.lock();
        (
            resolve_initial_connect_region(&sl, &region, auto_routing, &forced_servers),
            build_available_servers(&sl),
        )
    };
    if connect_region != region {
        log::info!(
            "Auto-routing: initial connect region resolved from '{}' to '{}' using ping-test latency cache",
            region,
            connect_region
        );
    }

    {
        let mut discord = state.discord_manager.lock();
        discord.set_connecting(&connect_region);
    }

    // Get access token
    let access_token = {
        let auth = state.auth_manager.lock().await;
        auth.get_access_token().await.map_err(|e| e.to_string())?
    };

    let mut vpn = state.vpn_connection.lock().await;
    let result = vpn
        .connect(
            &access_token,
            &connect_region,
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
    if result.is_ok() {
        // Publish the inner split-tunnel driver handle so polling commands
        // can read throughput/diagnostics/ping without queuing behind the
        // outer vpn_connection mutex.
        *state.split_tunnel_handle.write() = vpn.split_tunnel_handle();
    }
    drop(vpn);

    let discord_region = if result.is_ok() {
        let conn_state = state.vpn_state_handle.borrow().clone();
        Some(resolve_discord_region(&conn_state, &connect_region))
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
        if let Err(e) = persist_session_settings(&state, Some(&connect_region)) {
            log::warn!("Failed to persist connected session settings: {}", e);
        }
    }

    // No manual emit here — `spawn_vpn_state_bridge` forwards every
    // state transition published by `VpnConnection` to the UI.
    result
}

#[tauri::command]
pub async fn vpn_disconnect(state: State<'_, AppState>) -> Result<(), String> {
    disconnect_and_persist(&state).await
}

#[tauri::command]
pub async fn vpn_get_ping(state: State<'_, AppState>) -> Result<Option<u32>, String> {
    // Read both the relay ping snapshot and the current relay address from
    // the split-tunnel driver handle directly so we don't have to wait on
    // the outer vpn_connection mutex while connect/disconnect is in flight.
    let driver = state.split_tunnel_handle.read().clone();
    let (relay_ping, relay_addr) = match driver {
        Some(handle) => match handle.try_lock() {
            Ok(driver) => {
                let snapshot = driver
                    .get_relay_context()
                    .map(|relay| relay.ping_snapshot());
                let relay_ping = snapshot.and_then(|snapshot| {
                    if !snapshot.enabled {
                        return None;
                    }
                    // p99 here would mislead the UI: it's the worst-case tail,
                    // not the current ping. Stick to last_rtt and fall back to
                    // median only.
                    snapshot.last_rtt_ms.or(snapshot.p50_rtt_ms)
                });
                let relay_addr = driver.current_relay_addr();
                (relay_ping, relay_addr)
            }
            Err(_) => (None, None),
        },
        None => (None, None),
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
    // Bypass the outer vpn_connection mutex by hitting the split-tunnel
    // driver handle directly. Returns None until connect() finishes wiring it.
    let driver = state.split_tunnel_handle.read().clone();
    let stats = match driver {
        Some(handle) => handle
            .try_lock()
            .ok()
            .and_then(|driver| driver.get_throughput_stats()),
        None => None,
    };
    Ok(stats.map(|stats| ThroughputResponse {
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
    let driver = state.split_tunnel_handle.read().clone();
    let diag = match driver {
        Some(handle) => handle
            .try_lock()
            .ok()
            .and_then(|driver| driver.get_diagnostics()),
        None => None,
    };
    Ok(diag.map(|diag| DiagnosticsResponse {
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
    pub relay_available: bool,
    pub relay_port: Option<u16>,
}

#[derive(Serialize)]
pub struct ServerListResponse {
    pub regions: Vec<ServerRegionResponse>,
    pub servers: Vec<ServerInfoResponse>,
    pub source: String,
}

#[tauri::command]
pub async fn server_get_list(state: State<'_, AppState>) -> Result<ServerListResponse, String> {
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
                    relay_available: s.relay_available,
                    relay_port: s.relay_port,
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
        .filter(|server| server.relay_available)
        .map(|server| {
            (
                server.region.clone(),
                server.ip.clone(),
                server.effective_relay_port(),
            )
        })
        .collect()
}

/// Build the (region, socket_addr, latency) tuples passed into `VpnConnection::connect`
/// from the dynamic server list. Honors each server's per-relay UDP port instead of
/// hardcoding 51821 — relays migrating to alternate ports must remain reachable.
pub(crate) fn build_available_servers(
    sl: &swifttunnel_core::vpn::servers::DynamicServerList,
) -> Vec<(String, SocketAddr, Option<u32>)> {
    sl.servers()
        .iter()
        .filter(|s| s.relay_available)
        .filter_map(|s| {
            let addr: SocketAddr = format!("{}:{}", s.ip, s.effective_relay_port())
                .parse()
                .ok()?;
            let latency = sl.get_latency(&s.region);
            Some((s.region.clone(), addr, latency))
        })
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
        if !sl
            .get_server(server_id)
            .is_some_and(|server| server.relay_available)
        {
            continue;
        }
        if let Some(latency) = sl.get_latency(server_id) {
            if best.as_ref().is_none_or(|(_, best_ms)| latency < *best_ms) {
                best = Some((server_id.clone(), latency));
            }
        }
    }
    best.map(|(id, _)| id).or_else(|| {
        region
            .servers
            .iter()
            .find(|server_id| {
                sl.get_server(server_id)
                    .is_some_and(|server| server.relay_available)
            })
            .cloned()
    })
}

fn select_best_region_by_latency(
    sl: &swifttunnel_core::vpn::servers::DynamicServerList,
    forced_servers: &HashMap<String, String>,
) -> Option<String> {
    sl.regions()
        .iter()
        .filter_map(|region| {
            let latency = forced_servers
                .get(&region.id)
                .and_then(|server_id| sl.get_latency(server_id))
                .or_else(|| {
                    if forced_servers.contains_key(&region.id) {
                        None
                    } else {
                        sl.get_region_best_latency(&region.id)
                    }
                });
            latency.map(|latency| (region.id.clone(), latency))
        })
        .min_by(|(region_a, latency_a), (region_b, latency_b)| {
            latency_a
                .cmp(latency_b)
                .then_with(|| region_a.cmp(region_b))
        })
        .map(|(region_id, _)| region_id)
}

fn resolve_initial_connect_region(
    sl: &swifttunnel_core::vpn::servers::DynamicServerList,
    requested_region: &str,
    auto_routing: bool,
    forced_servers: &HashMap<String, String>,
) -> String {
    if !auto_routing {
        return requested_region.to_string();
    }

    if forced_servers.contains_key(requested_region) {
        return requested_region.to_string();
    }

    select_best_region_by_latency(sl, forced_servers)
        .unwrap_or_else(|| requested_region.to_string())
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
            let _ = port; // V3 relays don't echo unauthenticated probes — ICMP is the only signal we have.
            let latency = swifttunnel_core::vpn::servers::measure_latency_icmp(&ip);
            (server_id, latency)
        });
    }

    while let Some(result) = tasks.join_next().await {
        if let Ok((server_id, latency)) = result {
            measured.push((server_id, latency));
        }
    }

    let (entries, available_servers) = {
        let mut sl = state.server_list.lock();
        let entries = apply_latency_measurements(&mut sl, &measured);
        let available_servers = build_available_servers(&sl);
        (entries, available_servers)
    };

    sync_auto_router_available_servers(&state, available_servers).await;

    Ok(entries)
}

async fn sync_auto_router_available_servers(
    state: &AppState,
    available_servers: Vec<(String, SocketAddr, Option<u32>)>,
) {
    let auto_router = {
        let vpn = state.vpn_connection.lock().await;
        vpn.auto_router().cloned()
    };

    if let Some(router) = auto_router {
        router.set_available_servers(available_servers);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    use swifttunnel_core::vpn::servers::{
        DynamicGamingRegion, DynamicServerInfo, DynamicServerList, ServerListSource,
    };

    fn make_server(region: &str, ip: &str) -> DynamicServerInfo {
        make_server_with_port(region, ip, 51821)
    }

    fn make_server_with_port(region: &str, ip: &str, port: u16) -> DynamicServerInfo {
        DynamicServerInfo {
            region: region.to_string(),
            name: region.to_string(),
            country_code: "XX".to_string(),
            ip: ip.to_string(),
            port,
            phantun_available: false,
            phantun_port: None,
            relay_available: true,
            relay_port: Some(port),
        }
    }

    fn make_unavailable_server(region: &str, ip: &str) -> DynamicServerInfo {
        DynamicServerInfo {
            relay_available: false,
            relay_port: None,
            ..make_server_with_port(region, ip, 51821)
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
            relay_status: None,
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
            relay_status: None,
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
    fn build_latency_probe_targets_excludes_unavailable_relays() {
        let mut list = DynamicServerList::new_empty();
        list.update(
            vec![
                make_server("singapore", "1.1.1.1"),
                make_unavailable_server("tokyo-01", "2.2.2.1"),
            ],
            vec![
                make_region("singapore", &["singapore"]),
                make_region("tokyo", &["tokyo-01"]),
            ],
            ServerListSource::Api,
        );

        let probes = build_latency_probe_targets(&list);
        assert_eq!(
            probes,
            vec![("singapore".to_string(), "1.1.1.1".to_string(), 51821)]
        );
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

    #[test]
    fn select_best_region_by_latency_uses_ping_test_region_best() {
        let mut list = make_dynamic_server_list();
        list.set_latency("singapore", Some(28));
        list.set_latency("singapore-02", Some(12));
        list.set_latency("tokyo-01", Some(19));

        let selected = select_best_region_by_latency(&list, &HashMap::new());
        assert_eq!(selected.as_deref(), Some("singapore"));
    }

    #[test]
    fn resolve_initial_connect_region_keeps_manual_region() {
        let mut list = make_dynamic_server_list();
        list.set_latency("singapore", Some(12));
        list.set_latency("tokyo-01", Some(5));

        let selected = resolve_initial_connect_region(&list, "singapore", false, &HashMap::new());
        assert_eq!(selected, "singapore");
    }

    #[test]
    fn resolve_initial_connect_region_uses_ping_test_best_for_auto_routing() {
        let mut list = make_dynamic_server_list();
        list.set_latency("singapore", Some(22));
        list.set_latency("singapore-02", Some(16));
        list.set_latency("tokyo-01", Some(9));

        let selected = resolve_initial_connect_region(&list, "singapore", true, &HashMap::new());
        assert_eq!(selected, "tokyo");
    }

    #[test]
    fn resolve_initial_connect_region_falls_back_without_ping_results() {
        let list = make_dynamic_server_list();

        let selected = resolve_initial_connect_region(&list, "singapore", true, &HashMap::new());
        assert_eq!(selected, "singapore");
    }

    #[test]
    fn resolve_initial_connect_region_keeps_requested_region_with_forced_server() {
        let mut list = make_dynamic_server_list();
        list.set_latency("singapore", Some(22));
        list.set_latency("singapore-02", Some(16));
        list.set_latency("tokyo-01", Some(9));
        let forced_servers = HashMap::from([("singapore".to_string(), "singapore-02".to_string())]);

        let selected = resolve_initial_connect_region(&list, "singapore", true, &forced_servers);
        assert_eq!(selected, "singapore");
    }

    #[test]
    fn select_best_region_by_latency_scores_forced_region_by_forced_server() {
        let mut list = make_dynamic_server_list();
        list.set_latency("singapore", Some(5));
        list.set_latency("singapore-02", Some(50));
        list.set_latency("tokyo-01", Some(20));
        let forced_servers = HashMap::from([("singapore".to_string(), "singapore-02".to_string())]);

        let selected = select_best_region_by_latency(&list, &forced_servers);
        assert_eq!(selected.as_deref(), Some("tokyo"));
    }

    #[test]
    fn build_available_servers_uses_dynamic_port() {
        let mut list = DynamicServerList::new_empty();
        list.update(
            vec![
                make_server_with_port("singapore", "1.1.1.1", 51821),
                make_server_with_port("alt", "2.2.2.2", 51822),
                make_server_with_port("phantun", "3.3.3.3", 60001),
            ],
            vec![
                make_region("singapore", &["singapore"]),
                make_region("alt", &["alt"]),
                make_region("phantun", &["phantun"]),
            ],
            ServerListSource::Api,
        );

        let built = build_available_servers(&list);
        let by_region: std::collections::HashMap<_, _> = built
            .iter()
            .map(|(region, addr, _)| (region.clone(), *addr))
            .collect();

        assert_eq!(
            by_region.get("singapore"),
            Some(&"1.1.1.1:51821".parse().unwrap())
        );
        assert_eq!(
            by_region.get("alt"),
            Some(&"2.2.2.2:51822".parse().unwrap())
        );
        assert_eq!(
            by_region.get("phantun"),
            Some(&"3.3.3.3:60001".parse().unwrap())
        );
    }

    #[test]
    fn build_available_servers_excludes_unavailable_relays() {
        let mut list = DynamicServerList::new_empty();
        list.update(
            vec![
                make_server("singapore", "1.1.1.1"),
                make_unavailable_server("tokyo-01", "2.2.2.1"),
            ],
            vec![
                make_region("singapore", &["singapore"]),
                make_region("tokyo", &["tokyo-01"]),
            ],
            ServerListSource::Api,
        );

        let built = build_available_servers(&list);
        assert_eq!(built.len(), 1);
        assert_eq!(built[0].0, "singapore");
    }
}

#[tauri::command]
pub async fn server_refresh(state: State<'_, AppState>, app: AppHandle) -> Result<String, String> {
    let (servers, regions, source) = swifttunnel_core::vpn::servers::load_server_list().await?;

    let available_servers = {
        let mut sl = state.server_list.lock();
        sl.update(servers, regions, source.clone());
        build_available_servers(&sl)
    };
    sync_auto_router_available_servers(&state, available_servers).await;

    let _ = app.emit(SERVER_LIST_UPDATED, source.to_string());

    Ok(source.to_string())
}

#[tauri::command]
pub fn server_smart_select(state: State<'_, AppState>, region_id: String) -> Option<String> {
    let sl = state.server_list.lock();
    select_best_server_in_region(&sl, &region_id)
}
