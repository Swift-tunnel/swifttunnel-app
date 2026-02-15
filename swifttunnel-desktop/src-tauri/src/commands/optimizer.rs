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

    // Resolve Roblox PID from performance monitor (needed for process-specific boosts)
    let roblox_pid = {
        let mut monitor = state.performance_monitor.lock();
        monitor.get_roblox_pid().unwrap_or(0)
    };

    if enable {
        // Apply system optimizations (with real PID for priority/affinity)
        state
            .system_optimizer
            .lock()
            .apply_optimizations(&settings.config.system_optimization, roblox_pid)
            .map_err(|e| e.to_string())?;

        // Apply network optimizations
        state
            .network_booster
            .lock()
            .apply_optimizations(&settings.config.network_settings)
            .map_err(|e| e.to_string())?;

        // Apply roblox optimizations
        state
            .roblox_optimizer
            .lock()
            .apply_optimizations(&settings.config.roblox_settings)
            .map_err(|e| e.to_string())?;
    } else {
        // Revert system optimizations
        state
            .system_optimizer
            .lock()
            .restore(roblox_pid)
            .map_err(|e| e.to_string())?;

        // Revert network optimizations
        state
            .network_booster
            .lock()
            .restore()
            .map_err(|e| e.to_string())?;

        // Revert roblox optimizations
        state
            .roblox_optimizer
            .lock()
            .restore_settings()
            .map_err(|e| e.to_string())?;
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

    let optimizations_active;
    {
        let mut settings = state.settings.lock();
        settings.config = config;
        optimizations_active = settings.optimizations_active;
        swifttunnel_core::settings::save_settings(&settings).map_err(|e| e.to_string())?;
    }

    // If boosts are currently active, re-apply with the updated config
    if optimizations_active {
        let settings = state.settings.lock().clone();
        let roblox_pid = {
            let mut monitor = state.performance_monitor.lock();
            monitor.get_roblox_pid().unwrap_or(0)
        };

        state
            .system_optimizer
            .lock()
            .apply_optimizations(&settings.config.system_optimization, roblox_pid)
            .map_err(|e| e.to_string())?;

        state
            .network_booster
            .lock()
            .apply_optimizations(&settings.config.network_settings)
            .map_err(|e| e.to_string())?;

        state
            .roblox_optimizer
            .lock()
            .apply_optimizations(&settings.config.roblox_settings)
            .map_err(|e| e.to_string())?;
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
