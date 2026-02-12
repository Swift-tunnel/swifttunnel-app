use serde::Serialize;
use tauri::State;

use crate::state::AppState;

#[derive(Serialize)]
pub struct PerformanceMetricsResponse {
    pub fps: f32,
    pub cpu_usage: f32,
    pub ram_usage: f64,
    pub ram_total: f64,
    pub ping: u32,
    pub roblox_running: bool,
    pub process_id: Option<u32>,
}

#[tauri::command]
pub fn boost_get_metrics(state: State<'_, AppState>) -> PerformanceMetricsResponse {
    let mut monitor = state.performance_monitor.lock();
    let mut metrics = swifttunnel_core::structs::PerformanceMetrics::default();
    monitor.update_metrics(&mut metrics);

    PerformanceMetricsResponse {
        fps: metrics.fps,
        cpu_usage: metrics.cpu_usage,
        ram_usage: metrics.ram_usage,
        ram_total: metrics.ram_total,
        ping: metrics.ping,
        roblox_running: metrics.roblox_running,
        process_id: metrics.process_id,
    }
}

#[tauri::command]
pub fn boost_toggle(state: State<'_, AppState>, enable: bool) -> Result<(), String> {
    let settings = state.settings.lock().clone();

    if enable {
        // Apply system optimizations
        let mut sys_opt = state.system_optimizer.lock();
        sys_opt
            .apply_optimizations(&settings.config.system_optimization, 0)
            .map_err(|e| e.to_string())?;

        // Apply network optimizations
        let mut net_boost = state.network_booster.lock();
        net_boost
            .apply_optimizations(&settings.config.network_settings)
            .map_err(|e| e.to_string())?;

        // Apply roblox optimizations
        let roblox_opt = state.roblox_optimizer.lock();
        roblox_opt
            .apply_optimizations(&settings.config.roblox_settings)
            .map_err(|e| e.to_string())?;
    } else {
        // Revert system optimizations
        let mut sys_opt = state.system_optimizer.lock();
        sys_opt.restore(0).map_err(|e| e.to_string())?;

        // Revert network optimizations
        let mut net_boost = state.network_booster.lock();
        net_boost.restore().map_err(|e| e.to_string())?;

        // Revert roblox optimizations
        let roblox_opt = state.roblox_optimizer.lock();
        roblox_opt.restore_settings().map_err(|e| e.to_string())?;
    }

    // Update settings
    {
        let mut s = state.settings.lock();
        s.optimizations_active = enable;
        swifttunnel_core::settings::save_settings(&s).map_err(|e| e.to_string())?;
    }

    Ok(())
}

#[tauri::command]
pub fn boost_update_config(state: State<'_, AppState>, config_json: String) -> Result<(), String> {
    let config: swifttunnel_core::structs::Config =
        serde_json::from_str(&config_json).map_err(|e| format!("Invalid config: {}", e))?;

    let mut settings = state.settings.lock();
    settings.config = config;
    swifttunnel_core::settings::save_settings(&settings).map_err(|e| e.to_string())?;

    Ok(())
}

#[derive(Serialize)]
pub struct SystemInfoResponse {
    pub is_admin: bool,
    pub os_version: String,
    pub cpu_count: usize,
}

#[tauri::command]
pub fn boost_get_system_info() -> SystemInfoResponse {
    SystemInfoResponse {
        is_admin: swifttunnel_core::is_administrator(),
        os_version: std::env::consts::OS.to_string(),
        cpu_count: std::thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(1),
    }
}
