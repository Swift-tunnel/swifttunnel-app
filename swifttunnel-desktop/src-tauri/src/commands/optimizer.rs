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

fn ram_clean_boost_verified(result: &swifttunnel_core::ram_cleaner::RamCleanResult) -> bool {
    result.modified_flush.success && result.standby_purge.success
}

fn ram_clean_boost_failure_reasons(
    result: &swifttunnel_core::ram_cleaner::RamCleanResult,
) -> Vec<String> {
    let mut reasons = Vec::new();

    if !result.modified_flush.success {
        reasons.push(format!(
            "modified flush {}",
            result
                .modified_flush
                .skipped_reason
                .as_deref()
                .unwrap_or("failed without a reported reason")
        ));
    }

    if !result.standby_purge.success {
        reasons.push(format!(
            "standby purge {}",
            result
                .standby_purge
                .skipped_reason
                .as_deref()
                .unwrap_or("failed without a reported reason")
        ));
    }

    reasons
}

fn ram_clean_boost_warnings(
    result: &swifttunnel_core::ram_cleaner::RamCleanResult,
    mut progress_warnings: Vec<String>,
) -> Vec<String> {
    for warning in &result.warnings {
        if !progress_warnings.contains(warning) {
            progress_warnings.push(warning.clone());
        }
    }

    progress_warnings
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

#[derive(Clone, Serialize)]
pub struct BoostUpdateResult {
    pub warnings: Vec<String>,
    pub applied_config: swifttunnel_core::structs::Config,
    pub saved_config: swifttunnel_core::structs::Config,
}

#[tauri::command]
pub async fn boost_update_config(
    state: State<'_, AppState>,
    config_json: String,
) -> Result<BoostUpdateResult, String> {
    let mut config: swifttunnel_core::structs::Config =
        serde_json::from_str(&config_json).map_err(|e| format!("Invalid config: {}", e))?;
    config.network_settings.normalize_legacy_master_boost();

    let settings = state.settings.clone();
    let performance_monitor = state.performance_monitor.clone();
    let system_optimizer = state.system_optimizer.clone();
    let network_booster = state.network_booster.clone();
    let roblox_optimizer = state.roblox_optimizer.clone();

    tauri::async_runtime::spawn_blocking(move || {
        let mut applied_config = config.clone();
        let mut saved_config = config.clone();

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
                let outcome =
                    so.apply_optimizations_checked(&config.system_optimization, roblox_pid);
                applied_config.system_optimization = outcome.applied_config;
                saved_config.system_optimization = outcome.saved_config;
                warn_list.extend(
                    outcome
                        .warnings
                        .into_iter()
                        .map(|warning| format!("System optimizer: {}", warning)),
                );
            }

            #[cfg(windows)]
            if config.system_optimization.clear_standby_memory {
                let exclude_pids = if roblox_pid == 0 {
                    Vec::new()
                } else {
                    vec![roblox_pid]
                };
                let mut progress_warnings = Vec::new();
                match swifttunnel_core::ram_cleaner::clean_ram(
                    &exclude_pids,
                    |_, _, _, _, warning| {
                        if let Some(warning) = warning {
                            progress_warnings.push(warning);
                        }
                    },
                ) {
                    Ok(result) => {
                        for warning in ram_clean_boost_warnings(&result, progress_warnings) {
                            warn_list
                                .push(format!("System optimizer: RAM clean boost: {}", warning));
                        }

                        if !ram_clean_boost_verified(&result) {
                            applied_config.system_optimization.clear_standby_memory = false;
                            saved_config.system_optimization.clear_standby_memory = false;
                            let reasons = ram_clean_boost_failure_reasons(&result);
                            warn_list.push(format!(
                                "System optimizer: RAM clean boost did not verify: {}",
                                reasons.join("; ")
                            ));
                        }
                    }
                    Err(e) => {
                        for warning in progress_warnings {
                            warn_list
                                .push(format!("System optimizer: RAM clean boost: {}", warning));
                        }
                        applied_config.system_optimization.clear_standby_memory = false;
                        saved_config.system_optimization.clear_standby_memory = false;
                        warn_list.push(format!("System optimizer: RAM clean boost: {}", e));
                    }
                }
            }

            #[cfg(not(windows))]
            if config.system_optimization.clear_standby_memory {
                applied_config.system_optimization.clear_standby_memory = false;
                saved_config.system_optimization.clear_standby_memory = false;
                warn_list.push(
                    "System optimizer: RAM clean boost is only supported on Windows".to_string(),
                );
            }

            {
                let mut nb = network_booster.lock();
                let outcome = nb.reconcile_optimizations_checked(&config.network_settings);
                applied_config.network_settings = outcome.applied_config;
                saved_config.network_settings = applied_config.network_settings.clone();
                warn_list.extend(
                    outcome
                        .warnings
                        .into_iter()
                        .map(|warning| format!("Network booster: {}", warning)),
                );
            }

            {
                let ro = roblox_optimizer.lock();
                if let Err(e) = ro.restore_settings() {
                    warn_list.push(format!("Roblox optimizer restore: {}", e));
                }
                match ro.apply_optimizations(&config.roblox_settings) {
                    Ok(opt_warnings) => warn_list.extend(opt_warnings),
                    Err(e) => warn_list.push(format!("Roblox optimizer: {}", e)),
                }
            }

            warn_list
        };

        {
            let mut s = settings.lock();
            s.config = saved_config.clone();
            swifttunnel_core::settings::save_settings(&s).map_err(|e| e.to_string())?;
        }

        if !warnings.is_empty() {
            log::warn!(
                "Boost config applied with warnings: {}",
                warnings.join("; ")
            );
        }

        Ok(BoostUpdateResult {
            warnings,
            applied_config,
            saved_config,
        })
    })
    .await
    .map_err(|e| format!("Boost config task failed: {}", e))?
}

#[tauri::command]
pub async fn boost_sync_effective_config(
    state: State<'_, AppState>,
) -> Result<BoostUpdateResult, String> {
    let settings = state.settings.clone();
    let network_booster = state.network_booster.clone();

    tauri::async_runtime::spawn_blocking(move || {
        let mut current_config = {
            let s = settings.lock();
            s.config.clone()
        };
        current_config
            .network_settings
            .normalize_legacy_master_boost();

        let effective_network_config = {
            let nb = network_booster.lock();
            nb.effective_network_config(&current_config.network_settings)
        };

        let mut applied_config = current_config.clone();
        applied_config.network_settings = effective_network_config;

        let mut warnings = Vec::new();
        if current_config.network_settings.disable_nagle
            && !applied_config.network_settings.disable_nagle
        {
            warnings.push(
                "Network booster: Disable Nagle's algorithm was not active on Windows".to_string(),
            );
        }
        if current_config.network_settings.disable_network_throttling
            && !applied_config.network_settings.disable_network_throttling
        {
            warnings.push(
                "Network booster: Disable network throttling was not active on Windows".to_string(),
            );
        }
        if current_config.network_settings.gaming_qos && !applied_config.network_settings.gaming_qos
        {
            warnings.push("Network booster: Gaming QoS was not active on Windows".to_string());
        }

        if applied_config.network_settings.disable_nagle
            != current_config.network_settings.disable_nagle
            || applied_config.network_settings.disable_network_throttling
                != current_config.network_settings.disable_network_throttling
            || applied_config.network_settings.gaming_qos
                != current_config.network_settings.gaming_qos
            || applied_config.network_settings.prioritize_roblox_traffic
                != current_config.network_settings.prioritize_roblox_traffic
        {
            let mut s = settings.lock();
            s.config = applied_config.clone();
            swifttunnel_core::settings::save_settings(&s).map_err(|e| e.to_string())?;
        }

        Ok(BoostUpdateResult {
            warnings,
            saved_config: applied_config.clone(),
            applied_config,
        })
    })
    .await
    .map_err(|e| format!("Boost config sync task failed: {}", e))?
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

#[cfg(test)]
mod tests {
    use super::*;
    use swifttunnel_core::ram_cleaner::{
        ModifiedFlushResult, RamCleanResult, StandbyPurgeResult, SystemMemorySnapshot,
    };

    fn memory_snapshot() -> SystemMemorySnapshot {
        SystemMemorySnapshot {
            total_mb: 16_384,
            available_mb: 4_096,
            used_mb: 12_288,
            load_pct: 75,
            standby_mb: Some(512),
            modified_mb: Some(128),
        }
    }

    fn ram_clean_result(modified_success: bool, standby_success: bool) -> RamCleanResult {
        RamCleanResult {
            before: memory_snapshot(),
            after: memory_snapshot(),
            trimmed_count: 0,
            standby_purge: StandbyPurgeResult {
                attempted: standby_success,
                success: standby_success,
                skipped_reason: (!standby_success).then(|| "Requires Administrator".to_string()),
            },
            modified_flush: ModifiedFlushResult {
                attempted: modified_success,
                success: modified_success,
                skipped_reason: (!modified_success)
                    .then(|| "SeIncreaseQuotaPrivilege unavailable".to_string()),
            },
            freed_mb: 0,
            standby_freed_mb: Some(0),
            modified_freed_mb: Some(0),
            duration_ms: 1,
            warnings: Vec::new(),
        }
    }

    #[test]
    fn ram_clean_boost_requires_both_memory_list_phases_to_succeed() {
        assert!(ram_clean_boost_verified(&ram_clean_result(true, true)));
        assert!(!ram_clean_boost_verified(&ram_clean_result(false, true)));
        assert!(!ram_clean_boost_verified(&ram_clean_result(true, false)));
    }

    #[test]
    fn ram_clean_failure_reasons_report_failed_memory_list_phases() {
        let result = ram_clean_result(false, false);

        let reasons = ram_clean_boost_failure_reasons(&result);

        assert_eq!(reasons.len(), 2);
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("modified flush"))
        );
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("standby purge"))
        );
    }

    #[test]
    fn ram_clean_warnings_include_callback_only_messages_and_dedupe_result_messages() {
        let mut result = ram_clean_result(true, true);
        result.warnings = vec![
            "trim failed for browser.exe".to_string(),
            "aggregate warning".to_string(),
        ];

        let warnings = ram_clean_boost_warnings(
            &result,
            vec![
                "trim failed for browser.exe".to_string(),
                "callback-only warning".to_string(),
            ],
        );

        assert_eq!(
            warnings,
            vec![
                "trim failed for browser.exe".to_string(),
                "callback-only warning".to_string(),
                "aggregate warning".to_string(),
            ]
        );
    }
}
