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

fn reconcile_boosts(state: &AppState, config: &swifttunnel_core::structs::Config) -> Vec<String> {
    let mut warnings = Vec::new();
    // Resolve Roblox PID from performance monitor (needed for process-specific boosts)
    let roblox_pid = {
        let mut monitor = state.performance_monitor.lock();
        monitor.get_roblox_pid().unwrap_or(0)
    };

    // Restore first, then apply the current per-boost config so disabled toggles are respected.
    {
        let mut system_optimizer = state.system_optimizer.lock();
        if let Err(e) = system_optimizer.restore(roblox_pid) {
            warnings.push(format!("System optimizer restore: {}", e));
        }
        if let Err(e) =
            system_optimizer.apply_optimizations(&config.system_optimization, roblox_pid)
        {
            warnings.push(format!("System optimizer: {}", e));
        }
    }

    {
        let mut network_booster = state.network_booster.lock();
        if let Err(e) = network_booster.reconcile_optimizations(&config.network_settings) {
            warnings.push(format!("Network booster: {}", e));
        }
    }

    {
        let roblox_optimizer = state.roblox_optimizer.lock();
        if let Err(e) = roblox_optimizer.restore_settings() {
            warnings.push(format!("Roblox optimizer restore: {}", e));
        }
        if let Err(e) = roblox_optimizer.apply_optimizations(&config.roblox_settings) {
            warnings.push(format!("Roblox optimizer: {}", e));
        }
    }

    warnings
}

#[tauri::command]
pub fn boost_update_config(state: State<'_, AppState>, config_json: String) -> Result<(), String> {
    let config: swifttunnel_core::structs::Config =
        serde_json::from_str(&config_json).map_err(|e| format!("Invalid config: {}", e))?;

    {
        let mut settings = state.settings.lock();
        settings.config = config.clone();
        swifttunnel_core::settings::save_settings(&settings).map_err(|e| e.to_string())?;
    }

    let warnings = reconcile_boosts(&state, &config);
    if !warnings.is_empty() {
        log::warn!(
            "Boost config applied with warnings: {}",
            warnings.join("; ")
        );
    }

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

#[tauri::command]
pub async fn boost_restart_roblox(state: State<'_, AppState>) -> Result<(), String> {
    #[cfg(windows)]
    {
        let roblox_optimizer = state.roblox_optimizer.clone();
        tauri::async_runtime::spawn_blocking(move || {
            let roblox = roblox_optimizer.lock();

            roblox
                .close_running_instances()
                .map_err(|e| format!("Failed to close Roblox: {}", e))?;

            // Give Roblox a moment to fully exit before relaunching.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while std::time::Instant::now() < deadline {
                if !roblox.is_roblox_running() {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(250));
            }

            if roblox.is_roblox_running() {
                return Err("Roblox did not exit in time. Please try again.".to_string());
            }

            roblox
                .reopen_client()
                .map_err(|e| format!("Failed to relaunch Roblox: {}", e))?;

            Ok(())
        })
        .await
        .map_err(|e| format!("Roblox restart task failed: {}", e))?
    }

    #[cfg(not(windows))]
    {
        let _ = state;
        Err("Roblox restart is only supported on Windows".to_string())
    }
}
