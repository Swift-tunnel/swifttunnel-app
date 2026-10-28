use serde::Serialize;
use tauri::{Emitter, State};

use crate::events;
use crate::state::AppState;

static CONFIG_CHANGE: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

pub(crate) fn begin_config_change() -> Result<tokio::sync::SemaphorePermit<'static>, String> {
    CONFIG_CHANGE.try_acquire().map_err(|_| {
        "Another settings change is running. Wait for it to finish, then retry.".to_string()
    })
}

/// Mandatory account cleanup waits for an admitted apply/reset rather than
/// restoring Windows halfway through that operation or silently skipping it.
pub(crate) async fn wait_for_config_change() -> Result<tokio::sync::SemaphorePermit<'static>, String>
{
    CONFIG_CHANGE.acquire().await.map_err(|_| {
        "Could not finish restoring settings. Restart SwiftTunnel and try again.".into()
    })
}

#[derive(Serialize)]
pub struct PerformanceMetricsResponse {
    pub fps: f32,
    pub cpu_usage: f32,
    pub ram_usage: f64,
    pub ram_total: f64,
    pub ping: u32,
    pub roblox_running: bool,
    /// True when Roblox is the foreground (active) window. The in-game overlay
    /// keys off this so it only draws over Roblox, not the desktop/other apps.
    pub roblox_foreground: bool,
    pub process_id: Option<u32>,
}

#[tauri::command]
pub async fn boost_get_metrics(
    state: State<'_, AppState>,
    overlay_wants_fps: Option<bool>,
    _overlay_wants_ping: Option<bool>,
) -> Result<PerformanceMetricsResponse, String> {
    let performance_monitor = state.performance_monitor.clone();
    let fps_monitor = state.fps_monitor.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let metrics = {
            let mut monitor = performance_monitor.lock();
            let mut metrics = swifttunnel_core::structs::PerformanceMetrics::default();
            monitor.update_metrics(&mut metrics);
            metrics
        };

        // Settings own permission to trace; polls supply game presence. A
        // slow poll after disable cannot grant permission to restart tracing.
        // ETW startup/shutdown must not hold the process-discovery lock.
        let fps = fps_monitor.sample_for_process(
            metrics.process_id.filter(|_| metrics.roblox_running),
            overlay_wants_fps.unwrap_or(true),
        ) as f32;

        PerformanceMetricsResponse {
            fps,
            cpu_usage: metrics.cpu_usage,
            ram_usage: metrics.ram_usage,
            ram_total: metrics.ram_total,
            ping: metrics.ping,
            roblox_running: metrics.roblox_running,
            roblox_foreground: swifttunnel_core::performance_monitor::foreground_window_is_roblox(
                metrics.process_id.filter(|_| metrics.roblox_running),
            ),
            process_id: metrics.process_id,
        }
    })
    .await
    .map_err(|e| format!("Metrics task failed: {}", e))
}

#[derive(Serialize)]
pub struct CursorPosResponse {
    pub x: i32,
    pub y: i32,
    /// Primary (left) mouse button currently held — drives the overlay drag.
    pub left_down: bool,
}

/// Global cursor position (physical screen px) + left-button state for the
/// in-game overlay's grab-to-move. Cheap `GetCursorPos` + `GetAsyncKeyState`;
/// safe to poll a few dozen times a second while dragging.
#[tauri::command]
pub fn boost_cursor_pos() -> CursorPosResponse {
    let (x, y) = swifttunnel_core::performance_monitor::cursor_position();
    CursorPosResponse {
        x,
        y,
        left_down: swifttunnel_core::performance_monitor::left_mouse_down(),
    }
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

#[derive(Clone, Serialize)]
pub struct BoostUpdateResult {
    pub warnings: Vec<String>,
    pub applied_config: swifttunnel_core::structs::Config,
}

#[tauri::command]
pub async fn boost_update_config(
    state: State<'_, AppState>,
    config_json: String,
) -> Result<BoostUpdateResult, String> {
    if config_json.len() > 256 * 1024 {
        return Err(
            "These settings are too large to apply. Reload your saved settings and retry.".into(),
        );
    }
    let operation = begin_config_change()?;
    let mut config: swifttunnel_core::structs::Config =
        serde_json::from_str(&config_json).map_err(|e| format!("Invalid config: {}", e))?;
    config.network_settings.normalize_legacy_master_boost();
    // Refuse an invalid active XML cap before any system/network changes.
    let _ = config.roblox_settings.checked_frame_cap()?;

    let settings = state.settings.clone();
    let performance_monitor = state.performance_monitor.clone();
    let system_optimizer = state.system_optimizer.clone();
    let network_booster = state.network_booster.clone();
    let roblox_optimizer = state.roblox_optimizer.clone();

    tauri::async_runtime::spawn_blocking(move || {
        let _operation = operation;
        let mut applied_config = config.clone();

        let mut warnings = {
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
                warn_list.extend(
                    outcome
                        .warnings
                        .into_iter()
                        .map(|warning| format!("System optimizer: {}", warning)),
                );
            }

            {
                let mut nb = network_booster.lock();
                let outcome = nb.reconcile_optimizations_checked(&config.network_settings);
                applied_config.network_settings = outcome.applied_config;
                warn_list.extend(
                    outcome
                        .warnings
                        .into_iter()
                        .map(|warning| format!("Network booster: {}", warning)),
                );
            }

            warn_list
        };

        // A launch or watcher must not slip between applying the files and
        // publishing their matching config. Keep optimizer -> settings order.
        let ro = roblox_optimizer.lock();
        let saved_roblox = settings.lock().config.roblox_settings.clone();
        let (roblox_settings, roblox_warnings) = apply_global_roblox_config(
            &config.roblox_settings,
            &saved_roblox,
            swifttunnel_core::roblox_game_profile::pending()
                || swifttunnel_core::roblox_launch_flags::pending(),
            || {
                let mut warnings = Vec::new();
                if let Err(e) = ro.restore_settings() {
                    warnings.push(format!("Roblox optimizer restore: {}", e));
                }
                match ro.apply_optimizations(&config.roblox_settings) {
                    Ok(opt_warnings) => warnings.extend(opt_warnings),
                    Err(e) => warnings.push(format!("Roblox optimizer: {}", e)),
                }
                warnings
            },
        );
        applied_config.roblox_settings = roblox_settings;
        warnings.extend(roblox_warnings);

        {
            let mut s = settings.lock();
            persist_applied_config(
                &mut s,
                &applied_config,
                swifttunnel_core::settings::save_settings,
            )?;
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
        })
    })
    .await
    .map_err(|e| format!("Boost config task failed: {}", e))?
}

#[tauri::command]
pub async fn boost_sync_effective_config(
    state: State<'_, AppState>,
) -> Result<BoostUpdateResult, String> {
    // Files/registry values midway through recovery or apply do not describe
    // the effective saved configuration. Wait before probing and publishing.
    let operation = wait_for_config_change().await?;
    let settings = state.settings.clone();
    let network_booster = state.network_booster.clone();
    let roblox_optimizer = state.roblox_optimizer.clone();

    tauri::async_runtime::spawn_blocking(move || {
        let _operation = operation;
        let observed = {
            let s = settings.lock();
            s.config.clone()
        };
        let mut current_config = observed.clone();
        current_config
            .network_settings
            .normalize_legacy_master_boost();

        let effective_network_config = {
            let nb = network_booster.lock();
            nb.effective_network_config(&current_config.network_settings)
        };
        // Reflect the Roblox client's real state — FFlags/FPS wiped by a Roblox
        // update or the user should show as off on the Optimize page.
        // Launch preparation, recovery and the flag editor use this same
        // lock. Keep it until the reconciled settings have been committed.
        let ro = roblox_optimizer.lock();
        let effective_roblox_config = ro.effective_roblox_config(&current_config.roblox_settings);

        let mut applied_config = current_config.clone();
        applied_config.network_settings = effective_network_config;
        applied_config.roblox_settings = effective_roblox_config;

        persist_effective_config(
            &mut settings.lock(),
            &observed,
            &applied_config,
            swifttunnel_core::settings::save_settings,
        )
    })
    .await
    .map_err(|e| format!("Boost config sync task failed: {}", e))?
}

fn persist_effective_config(
    settings: &mut swifttunnel_core::settings::AppSettings,
    observed: &swifttunnel_core::structs::Config,
    effective: &swifttunnel_core::structs::Config,
    persist: impl FnOnce(&swifttunnel_core::settings::AppSettings) -> Result<(), String>,
) -> Result<BoostUpdateResult, String> {
    let mut next = settings.clone();
    // Windows probes can be slow. Never replace a newer editor save with
    // the config captured before those probes started, or touch other sections.
    if next.config.network_settings == observed.network_settings {
        next.config.network_settings = effective.network_settings.clone();
    }
    if next.config.roblox_settings == observed.roblox_settings {
        next.config.roblox_settings = effective.roblox_settings.clone();
    }
    let mut warnings = Vec::new();
    if settings.config.network_settings.disable_nagle && !next.config.network_settings.disable_nagle
    {
        warnings
            .push("Network booster: Disable Nagle's algorithm was not active on Windows".into());
    }
    if settings.config.network_settings.disable_network_throttling
        && !next.config.network_settings.disable_network_throttling
    {
        warnings
            .push("Network booster: Disable network throttling was not active on Windows".into());
    }
    if next.config.network_settings != settings.config.network_settings
        || next.config.roblox_settings != settings.config.roblox_settings
    {
        persist(&next)?;
        *settings = next;
    }
    Ok(BoostUpdateResult {
        warnings,
        applied_config: settings.config.clone(),
    })
}

fn apply_global_roblox_config(
    requested: &swifttunnel_core::structs::RobloxSettingsConfig,
    saved: &swifttunnel_core::structs::RobloxSettingsConfig,
    temporary_pending: bool,
    apply: impl FnOnce() -> Vec<String>,
) -> (swifttunnel_core::structs::RobloxSettingsConfig, Vec<String>) {
    if temporary_pending {
        let warnings = if requested != saved {
            vec!["Roblox's per-game settings are still active. Close Roblox, then apply your global Roblox changes again after recovery finishes.".into()]
        } else {
            Vec::new()
        };
        return (saved.clone(), warnings);
    }
    (requested.clone(), apply())
}

fn persist_applied_config(
    settings: &mut swifttunnel_core::settings::AppSettings,
    config: &swifttunnel_core::structs::Config,
    persist: impl FnOnce(&swifttunnel_core::settings::AppSettings) -> Result<(), String>,
) -> Result<(), String> {
    let mut updated = settings.clone();
    updated.config = config.clone();
    persist(&updated)?;
    *settings = updated;
    Ok(())
}

fn persist_roblox_reset(
    settings: &mut swifttunnel_core::settings::AppSettings,
    persist: impl FnOnce(&swifttunnel_core::settings::AppSettings) -> Result<(), String>,
) -> Result<swifttunnel_core::structs::RobloxSettingsConfig, String> {
    let mut updated = settings.clone();
    updated.config.roblox_settings = swifttunnel_core::structs::RobloxSettingsConfig::default();
    persist(&updated)?;
    *settings = updated;
    Ok(settings.config.roblox_settings.clone())
}

fn persist_completed_client_reset(
    settings: &mut swifttunnel_core::settings::AppSettings,
    report: &swifttunnel_core::roblox_optimizer::RobloxResetReport,
    persist: impl FnOnce(&swifttunnel_core::settings::AppSettings) -> Result<(), String>,
) -> Result<(), String> {
    // A failed close or partial file reset is not confirmation that all
    // saved overrides are off. Keep the old intent available for a retry.
    if !report.failures.is_empty() {
        return Ok(());
    }
    persist_roblox_reset(settings, persist).map(|_| ())
}

/// Reset all SwiftTunnel changes to the Roblox client — clears our FFlags
/// (Ultraboost / custom), restores the GlobalBasicSettings backup (FPS, window,
/// graphics) when present, and resets the saved Roblox config to defaults. Used
/// by the Repair tab's "reset Roblox settings" fix.
#[tauri::command]
pub async fn boost_reset_roblox_settings(
    state: State<'_, AppState>,
) -> Result<swifttunnel_core::structs::RobloxSettingsConfig, String> {
    let operation = begin_config_change()?;
    let settings = state.settings.clone();
    let roblox_optimizer = state.roblox_optimizer.clone();

    tauri::async_runtime::spawn_blocking(move || {
        let _operation = operation;
        // Flag/launch preparation shares this lock. Keep it through the saved
        // defaults too, or a new apply can land between reset and persistence.
        let ro = roblox_optimizer.lock();
        ro.reset_swifttunnel_changes().map_err(|e| e.to_string())?;
        let mut s = settings.lock();
        persist_roblox_reset(&mut s, swifttunnel_core::settings::save_settings)
    })
    .await
    .map_err(|e| format!("Reset Roblox task failed: {}", e))?
}

/// Put the Roblox client back to stock, whoever changed it.
///
/// Wider than `boost_reset_roblox_settings`, which only takes our own keys
/// out. This deletes every `ClientAppSettings.json` on the machine, including
/// the one a bootstrapper keeps in its modifications folder and copies into the
/// game at every launch. That copy is why resetting Roblox's own files never
/// fixes a stuck flag, and why this exists as a separate, clearly destructive
/// action rather than something folded into the ordinary reset.
#[tauri::command]
pub async fn boost_reset_roblox_client(
    state: State<'_, AppState>,
) -> Result<swifttunnel_core::roblox_optimizer::RobloxResetReport, String> {
    let operation = begin_config_change()?;
    let settings = state.settings.clone();
    let roblox_optimizer = state.roblox_optimizer.clone();

    tauri::async_runtime::spawn_blocking(move || {
        let _operation = operation;
        let ro = roblox_optimizer.lock();
        let report = ro.reset_client_to_default();

        // The saved config has to follow the client, or the app goes on showing
        // Ultraboost as on over a Roblox that no longer has a single flag in it.
        {
            let mut s = settings.lock();
            persist_completed_client_reset(
                &mut s,
                &report,
                swifttunnel_core::settings::save_settings,
            )?;
        }

        Ok(report)
    })
    .await
    .map_err(|e| format!("Reset Roblox client task failed: {}", e))?
}

#[tauri::command]
pub async fn boost_clean_ram(
    state: State<'_, AppState>,
    app: tauri::AppHandle,
) -> Result<RamCleanResultResponse, String> {
    #[cfg(windows)]
    {
        let performance_monitor = state.performance_monitor.clone();
        let app_handle = app.clone();
        let result = tauri::async_runtime::spawn_blocking(move || {
            // The fresh exclusion scan can block too. Keep it with the cleanup
            // worker rather than blocking the async command executor first.
            let roblox_pid = performance_monitor.lock().get_roblox_pid();
            let exclude_pids: Vec<u32> = roblox_pid.into_iter().collect();
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
        let preferred_client = state.games.lock().current.as_ref().map(|game| game.client);
        tauri::async_runtime::spawn_blocking(move || {
            let roblox = roblox_optimizer.lock();
            let client = match preferred_client {
                Some(client) => client,
                None => {
                    swifttunnel_core::roblox_native_launch::running_client()?.unwrap_or_default()
                }
            };
            // Resolve before closing anything; a missing installation must not
            // strand the user after terminating a working game.
            let player = swifttunnel_core::roblox_native_launch::official_player_for(client)?;

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
                .reopen_client(&player)
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

#[tauri::command]
pub async fn boost_close_roblox(state: State<'_, AppState>) -> Result<(), String> {
    state.games.lock().left_confirmed = true;
    #[cfg(windows)]
    {
        let roblox_optimizer = state.roblox_optimizer.clone();
        tauri::async_runtime::spawn_blocking(move || {
            let roblox = roblox_optimizer.lock();

            roblox
                .close_running_instances()
                .map_err(|e| format!("Failed to close Roblox: {}", e))?;

            Ok(())
        })
        .await
        .map_err(|e| format!("Roblox close task failed: {}", e))?
    }

    #[cfg(not(windows))]
    {
        let _ = state;
        Err("Roblox close is only supported on Windows".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use swifttunnel_core::settings::AppSettings;

    #[test]
    fn a_temporary_game_profile_is_not_overwritten_by_a_global_boost_apply() {
        let saved = swifttunnel_core::structs::RobloxSettingsConfig::default();
        let mut requested = saved.clone();
        requested.target_fps = 400;
        let mut touched = false;
        let (applied, warnings) = apply_global_roblox_config(&requested, &saved, true, || {
            touched = true;
            Vec::new()
        });
        assert!(
            !touched,
            "Neither restore nor apply may touch the temporary game files"
        );
        assert_eq!(applied, saved);
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn a_network_only_apply_during_a_game_does_not_rewrite_roblox_or_warn() {
        let saved = swifttunnel_core::structs::RobloxSettingsConfig::default();
        let mut touched = false;
        let (applied, warnings) = apply_global_roblox_config(&saved, &saved, true, || {
            touched = true;
            Vec::new()
        });
        assert!(!touched);
        assert_eq!(applied, saved);
        assert!(warnings.is_empty());
    }

    #[test]
    fn global_roblox_apply_resumes_after_temporary_settings_are_restored() {
        let saved = swifttunnel_core::structs::RobloxSettingsConfig::default();
        let mut requested = saved.clone();
        requested.target_fps = 400;
        let mut touched = false;
        let (applied, warnings) = apply_global_roblox_config(&requested, &saved, false, || {
            touched = true;
            vec!["existing apply warning".into()]
        });
        assert!(touched);
        assert_eq!(applied, requested);
        assert_eq!(warnings, ["existing apply warning"]);
    }

    #[test]
    fn failed_boost_save_keeps_the_last_confirmed_config_in_memory() {
        let mut settings = AppSettings::default();
        settings.minimize_to_tray = false;
        let original = settings.config.clone();
        let mut requested = original.clone();
        requested.roblox_settings.target_fps = 400;
        let result = persist_applied_config(&mut settings, &requested, |_| Err("disk full".into()));
        assert_eq!(result.unwrap_err(), "disk full");
        assert_eq!(
            serde_json::to_value(&settings.config).unwrap(),
            serde_json::to_value(&original).unwrap()
        );
        assert!(!settings.minimize_to_tray);
    }

    #[test]
    fn successful_boost_save_publishes_the_saved_config_and_preserves_other_preferences() {
        let mut settings = AppSettings::default();
        settings.minimize_to_tray = false;
        let mut requested = settings.config.clone();
        requested.roblox_settings.target_fps = 400;
        let mut written = None;
        persist_applied_config(&mut settings, &requested, |snapshot| {
            written = Some(snapshot.clone());
            Ok(())
        })
        .unwrap();
        assert_eq!(
            serde_json::to_value(&written.unwrap().config).unwrap(),
            serde_json::to_value(&requested).unwrap()
        );
        assert_eq!(
            serde_json::to_value(&settings.config).unwrap(),
            serde_json::to_value(&requested).unwrap()
        );
        assert!(!settings.minimize_to_tray);
    }

    #[tokio::test]
    async fn config_change_reservation_stays_with_the_worker_and_recovers_after_failure() {
        use std::{sync::mpsc, time::Duration};
        let operation = begin_config_change().unwrap();
        assert!(begin_config_change().is_err());
        let (started, ready) = mpsc::channel();
        let (release, resume) = mpsc::channel();
        let worker = std::thread::spawn(move || {
            let _operation = operation;
            started.send(()).unwrap();
            let _ = resume.recv_timeout(Duration::from_secs(3));
            Err::<(), _>("simulated settings apply failure")
        });
        ready.recv_timeout(Duration::from_secs(2)).unwrap();
        let refused_overlap = begin_config_change().is_err();
        let mut cleanup = Box::pin(wait_for_config_change());
        assert!(
            tokio::time::timeout(Duration::from_millis(5), &mut cleanup)
                .await
                .is_err()
        );
        release.send(()).unwrap();
        assert!(worker.join().unwrap().is_err());
        assert!(refused_overlap);
        let cleanup = cleanup.await.unwrap();
        assert!(begin_config_change().is_err());
        drop(cleanup);
        assert!(begin_config_change().is_ok());
        let failed = std::panic::catch_unwind(|| {
            let _operation = begin_config_change().unwrap();
            panic!("owned simulated settings worker panic");
        });
        assert!(failed.is_err());
        assert!(begin_config_change().is_ok());
    }

    #[test]
    fn slow_reconciliation_keeps_newer_flags_network_and_unrelated_settings() {
        let mut settings = AppSettings::default();
        let observed = settings.config.clone();
        let mut measured = observed.clone();
        measured.roblox_settings.unlock_fps = false;
        measured.network_settings.disable_nagle = false;
        settings.config.roblox_settings.custom_fflags_enabled = true;
        settings.config.roblox_settings.custom_fflags_json = r#"{"FFlagDebugSkyGray":true}"#.into();
        settings.config.network_settings.disable_nagle = true;
        settings.config.overlay.enabled = !observed.overlay.enabled;
        settings.config.profile = swifttunnel_core::structs::OptimizationProfile::HighEnd;
        let expected = serde_json::to_value(&settings).unwrap();
        let result = persist_effective_config(&mut settings, &observed, &measured, |_| {
            panic!("a stale read must not write any part of newer settings")
        })
        .unwrap();
        assert!(result.warnings.is_empty());
        assert_eq!(serde_json::to_value(&settings).unwrap(), expected);
        assert_eq!(
            serde_json::to_value(result.applied_config).unwrap(),
            expected["config"]
        );
    }

    #[test]
    fn reconciliation_persists_only_unchanged_observations_and_keeps_memory_on_failure() {
        let mut settings = AppSettings::default();
        settings.config.network_settings.disable_nagle = true;
        let observed = settings.config.clone();
        let mut measured = observed.clone();
        measured.network_settings.disable_nagle = false;
        measured.roblox_settings.unlock_fps = false;
        settings.config.overlay.enabled = !observed.overlay.enabled;
        let before = serde_json::to_value(&settings).unwrap();
        assert!(
            persist_effective_config(&mut settings, &observed, &measured, |_| Err(
                "disk full".into()
            ))
            .is_err()
        );
        assert_eq!(serde_json::to_value(&settings).unwrap(), before);
        let result = persist_effective_config(&mut settings, &observed, &measured, |candidate| {
            assert!(!candidate.config.roblox_settings.unlock_fps);
            assert!(!candidate.config.network_settings.disable_nagle);
            assert_eq!(
                candidate.config.overlay.enabled,
                before["config"]["overlay"]["enabled"].as_bool().unwrap()
            );
            Ok(())
        })
        .unwrap();
        assert_eq!(result.warnings.len(), 1);
        assert!(!settings.config.roblox_settings.unlock_fps);
    }

    #[test]
    fn failed_reset_save_keeps_the_previous_preferences_for_retry() {
        let mut settings = AppSettings::default();
        settings.config.roblox_settings.ultraboost = true;
        settings.config.roblox_settings.target_fps = 650;
        let before = serde_json::to_value(&settings).unwrap();
        let result = persist_roblox_reset(&mut settings, |_| Err("disk full".into()));
        assert_eq!(result.unwrap_err(), "disk full");
        assert_eq!(serde_json::to_value(&settings).unwrap(), before);

        let restored = persist_roblox_reset(&mut settings, |_| Ok(())).unwrap();
        assert!(!restored.ultraboost);
        assert_eq!(settings.config.roblox_settings, restored);
    }

    #[test]
    fn failed_or_partial_client_reset_cannot_publish_saved_defaults() {
        for removed in [0, 2] {
            let mut settings = AppSettings::default();
            settings.config.roblox_settings.ultraboost = true;
            settings.config.roblox_settings.target_fps = 650;
            let before = serde_json::to_value(&settings).unwrap();
            let report = swifttunnel_core::roblox_optimizer::RobloxResetReport {
                flag_files_removed: removed,
                failures: vec!["fixture close or file error".into()],
                ..Default::default()
            };
            persist_completed_client_reset(&mut settings, &report, |_| {
                panic!("a failed reset cannot confirm the entire section is off")
            })
            .unwrap();
            assert_eq!(serde_json::to_value(settings).unwrap(), before);
        }
        let mut settings = AppSettings::default();
        settings.config.roblox_settings.ultraboost = true;
        persist_completed_client_reset(&mut settings, &Default::default(), |_| Ok(())).unwrap();
        assert!(!settings.config.roblox_settings.ultraboost);
    }

    #[test]
    fn reset_persists_only_the_roblox_section_and_returns_the_saved_values() {
        let mut settings = AppSettings::default();
        settings.selected_region = "tokyo".into();
        settings.run_on_startup = true;
        settings.config.roblox_settings.ultraboost = true;
        let mut expected = settings.clone();
        expected.config.roblox_settings = Default::default();
        let expected = serde_json::to_value(expected).unwrap();
        let result = persist_roblox_reset(&mut settings, |candidate| {
            assert_eq!(serde_json::to_value(candidate).unwrap(), expected);
            Ok(())
        })
        .unwrap();
        assert_eq!(serde_json::to_value(&settings).unwrap(), expected);
        assert_eq!(result, settings.config.roblox_settings);
    }
}
