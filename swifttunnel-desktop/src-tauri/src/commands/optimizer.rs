use serde::Serialize;
use tauri::{Emitter, State};

use crate::events;
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
pub async fn boost_get_metrics(
    state: State<'_, AppState>,
) -> Result<PerformanceMetricsResponse, String> {
    let performance_monitor = state.performance_monitor.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let mut monitor = performance_monitor.lock();
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
    })
    .await
    .map_err(|e| format!("Metrics task failed: {}", e))
}

#[derive(Clone, Serialize)]
pub struct SystemMemorySnapshotResponse {
    pub total_mb: u64,
    pub used_mb: u64,
    pub available_mb: u64,
    pub load_pct: u8,
    pub standby_mb: Option<u64>,
    pub modified_mb: Option<u64>,
}

impl From<swifttunnel_core::ram_cleaner::SystemMemorySnapshot> for SystemMemorySnapshotResponse {
    fn from(value: swifttunnel_core::ram_cleaner::SystemMemorySnapshot) -> Self {
        Self {
            total_mb: value.total_mb,
            used_mb: value.used_mb,
            available_mb: value.available_mb,
            load_pct: value.load_pct,
            standby_mb: value.standby_mb,
            modified_mb: value.modified_mb,
        }
    }
}

#[derive(Clone, Serialize)]
pub struct StandbyPurgeResultResponse {
    pub attempted: bool,
    pub success: bool,
    pub skipped_reason: Option<String>,
}

impl From<swifttunnel_core::ram_cleaner::StandbyPurgeResult> for StandbyPurgeResultResponse {
    fn from(value: swifttunnel_core::ram_cleaner::StandbyPurgeResult) -> Self {
        Self {
            attempted: value.attempted,
            success: value.success,
            skipped_reason: value.skipped_reason,
        }
    }
}

#[derive(Clone, Serialize)]
pub struct ModifiedFlushResultResponse {
    pub attempted: bool,
    pub success: bool,
    pub skipped_reason: Option<String>,
}

impl From<swifttunnel_core::ram_cleaner::ModifiedFlushResult> for ModifiedFlushResultResponse {
    fn from(value: swifttunnel_core::ram_cleaner::ModifiedFlushResult) -> Self {
        Self {
            attempted: value.attempted,
            success: value.success,
            skipped_reason: value.skipped_reason,
        }
    }
}

#[derive(Clone, Serialize)]
pub struct RamCleanResultResponse {
    pub before: SystemMemorySnapshotResponse,
    pub after: SystemMemorySnapshotResponse,
    pub trimmed_count: u32,
    pub standby_purge: StandbyPurgeResultResponse,
    pub modified_flush: ModifiedFlushResultResponse,
    pub freed_mb: i64,
    pub standby_freed_mb: Option<i64>,
    pub modified_freed_mb: Option<i64>,
    pub duration_ms: u64,
    pub warnings: Vec<String>,
}

impl From<swifttunnel_core::ram_cleaner::RamCleanResult> for RamCleanResultResponse {
    fn from(value: swifttunnel_core::ram_cleaner::RamCleanResult) -> Self {
        Self {
            before: value.before.into(),
            after: value.after.into(),
            trimmed_count: value.trimmed_count,
            standby_purge: value.standby_purge.into(),
            modified_flush: value.modified_flush.into(),
            freed_mb: value.freed_mb,
            standby_freed_mb: value.standby_freed_mb,
            modified_freed_mb: value.modified_freed_mb,
            duration_ms: value.duration_ms,
            warnings: value.warnings,
        }
    }
}

#[tauri::command]
pub async fn boost_get_system_memory() -> Result<SystemMemorySnapshotResponse, String> {
    #[cfg(windows)]
    {
        tauri::async_runtime::spawn_blocking(|| {
            swifttunnel_core::ram_cleaner::get_system_memory_snapshot()
                .map(SystemMemorySnapshotResponse::from)
                .map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| format!("System memory task failed: {}", e))?
    }

    #[cfg(not(windows))]
    {
        Err("System memory stats are only supported on Windows".to_string())
    }
}

#[tauri::command]
pub async fn boost_update_config(
    state: State<'_, AppState>,
    config_json: String,
) -> Result<(), String> {
    let config: swifttunnel_core::structs::Config =
        serde_json::from_str(&config_json).map_err(|e| format!("Invalid config: {}", e))?;

    let settings = state.settings.clone();
    let performance_monitor = state.performance_monitor.clone();
    let system_optimizer = state.system_optimizer.clone();
    let network_booster = state.network_booster.clone();
    let roblox_optimizer = state.roblox_optimizer.clone();

    tauri::async_runtime::spawn_blocking(move || {
        {
            let mut s = settings.lock();
            s.config = config.clone();
            swifttunnel_core::settings::save_settings(&s).map_err(|e| e.to_string())?;
        }

        let warnings = {
            let mut warn_list = Vec::new();
            let roblox_pid = {
                let mut monitor = performance_monitor.lock();
                monitor.get_roblox_pid().unwrap_or(0)
            };

            {
                let mut so = system_optimizer.lock();
                if let Err(e) = so.restore(roblox_pid) {
                    warn_list.push(format!("System optimizer restore: {}", e));
                }
                if let Err(e) = so.apply_optimizations(&config.system_optimization, roblox_pid) {
                    warn_list.push(format!("System optimizer: {}", e));
                }
            }

            {
                let mut nb = network_booster.lock();
                if let Err(e) = nb.reconcile_optimizations(&config.network_settings) {
                    warn_list.push(format!("Network booster: {}", e));
                }
            }

            {
                let ro = roblox_optimizer.lock();
                if let Err(e) = ro.restore_settings() {
                    warn_list.push(format!("Roblox optimizer restore: {}", e));
                }
                if let Err(e) = ro.apply_optimizations(&config.roblox_settings) {
                    warn_list.push(format!("Roblox optimizer: {}", e));
                }
            }

            warn_list
        };

        if !warnings.is_empty() {
            log::warn!(
                "Boost config applied with warnings: {}",
                warnings.join("; ")
            );
        }

        Ok(())
    })
    .await
    .map_err(|e| format!("Boost config task failed: {}", e))?
}

#[tauri::command]
pub async fn boost_clean_ram(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<RamCleanResultResponse, String> {
    #[cfg(windows)]
    {
        // Exclude Roblox PID to avoid stutters; foreground PID is excluded inside core.
        let roblox_pid = {
            let mut monitor = state.performance_monitor.lock();
            monitor.get_roblox_pid().unwrap_or(0)
        };

        let mut exclude_pids: Vec<u32> = Vec::new();
        if roblox_pid != 0 {
            exclude_pids.push(roblox_pid);
        }

        let app_handle = app.clone();
        let result = tauri::async_runtime::spawn_blocking(move || {
            swifttunnel_core::ram_cleaner::clean_ram(
                &exclude_pids,
                |stage, snapshot, trimmed, current, warning| {
                    let payload = events::RamCleanProgressEvent {
                        stage: stage.to_string(),
                        total_mb: snapshot.total_mb,
                        used_mb: snapshot.used_mb,
                        available_mb: snapshot.available_mb,
                        load_pct: snapshot.load_pct,
                        standby_mb: snapshot.standby_mb,
                        modified_mb: snapshot.modified_mb,
                        trimmed_count: trimmed,
                        current_process: current,
                        warning,
                    };
                    let _ = app_handle.emit(events::RAM_CLEAN_PROGRESS, payload);
                },
            )
        })
        .await
        .map_err(|e| format!("RAM clean task failed: {}", e))?
        .map_err(|e| e.to_string())?;

        Ok(RamCleanResultResponse::from(result))
    }

    #[cfg(not(windows))]
    {
        let _ = state;
        let _ = app;
        Err("RAM cleaner is only supported on Windows".to_string())
    }
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
