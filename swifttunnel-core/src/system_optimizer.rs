use crate::hidden_command;
use crate::structs::*;
use log::{info, warn};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Media::{timeBeginPeriod, timeEndPeriod};
use windows::Win32::System::Threading::*;

const ALL_CORES_AFFINITY_MASK: usize = usize::MAX;

// ntdll.dll functions for low-level system control
unsafe extern "system" {
    // Sub-millisecond timer resolution (0.5ms)
    fn NtSetTimerResolution(
        DesiredResolution: u32,
        SetResolution: u8,
        CurrentResolution: *mut u32,
    ) -> i32;
}

const GAME_BAR_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR";
const GAME_BAR_VALUE: &str = "AppCaptureEnabled";
const FULLSCREEN_KEY: &str = r"HKCU\System\GameConfigStore";
const FULLSCREEN_VALUE: &str = "GameDVR_FSEBehaviorMode";
const GAME_MODE_KEY: &str = r"HKCU\Software\Microsoft\GameBar";
const GAME_MODE_ALLOW_AUTO_VALUE: &str = "AllowAutoGameMode";
const GAME_MODE_ENABLED_VALUE: &str = "AutoGameModeEnabled";
const MMCSS_GAMES_KEY: &str =
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games";
const MMCSS_SYSTEM_PROFILE_KEY: &str =
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile";
// Windows 11 22H2+ scopes `NtSetTimerResolution` / `timeBeginPeriod` to the
// calling process only. Without this registry override, a 0.5ms resolution
// request from SwiftTunnel does not propagate to Roblox — the boost becomes
// effectively a no-op for the game. Setting this key to 1 restores the
// Windows 10 global-timer behavior. The kernel reads it at boot, so a reboot
// is required for changes to take effect.
const GLOBAL_TIMER_RESOLUTION_KEY: &str =
    r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel";
const GLOBAL_TIMER_RESOLUTION_VALUE: &str = "GlobalTimerResolutionRequests";
const BALANCED_POWER_PLAN_GUID: &str = "381b4222-f694-41f0-9685-ff5bb260df2e";
const HIGH_PERFORMANCE_POWER_PLAN_GUID: &str = "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c";
const ULTIMATE_POWER_PLAN_GUID: &str = "e9a42b02-d5df-448d-aa00-03f14749eb61";
const SWIFTTUNNEL_POWER_PLAN_GUID: &str = "44444444-4444-4444-4444-444444444452";
const SWIFTTUNNEL_POWER_PLAN_NAME: &str = "SwiftTunnel";
const SWIFTTUNNEL_POWER_PLAN_DESCRIPTION: &str = "SwiftTunnel optimized gaming power plan";
const SWIFTTUNNEL_POWER_PLAN_BYTES: &[u8] =
    include_bytes!("../resources/swifttunnel_power_plan.pow");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SwiftTunnelPowerPlanCleanup {
    Noop,
    DeleteInactive,
    ActivateBalancedThenDelete,
    UnknownActivePlan,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct MmcssSnapshot {
    scheduling_category: Option<String>,
    sfio_priority: Option<String>,
    background_only: Option<String>,
    priority: Option<u32>,
    clock_rate: Option<u32>,
    system_responsiveness: Option<u32>,
}

pub struct SystemOptimizer {
    original_priority: Option<u32>,
    original_affinity: Option<usize>,
    timer_resolution_active: bool,
    global_timer_snapshot: Option<Option<u32>>,
    original_power_plan_guid: Option<Option<String>>,
    game_bar_snapshot: Option<Option<u32>>,
    fullscreen_optimization_snapshot: Option<Option<u32>>,
    game_mode_allow_auto_snapshot: Option<Option<u32>>,
    game_mode_enabled_snapshot: Option<Option<u32>>,
    mmcss_snapshot: Option<MmcssSnapshot>,
    swifttunnel_power_plan_imported: bool,
}

impl SystemOptimizer {
    pub fn new() -> Self {
        Self {
            original_priority: None,
            original_affinity: None,
            timer_resolution_active: false,
            global_timer_snapshot: None,
            original_power_plan_guid: None,
            game_bar_snapshot: None,
            fullscreen_optimization_snapshot: None,
            game_mode_allow_auto_snapshot: None,
            game_mode_enabled_snapshot: None,
            mmcss_snapshot: None,
            swifttunnel_power_plan_imported: false,
        }
    }

    /// Validate that every requested core index is reachable on this CPU.
    ///
    /// Returns the affinity mask on success. Rejects an empty list (no cores
    /// would mean "no CPU allowed to run the process" — Windows rejects this
    /// but `SetProcessAffinityMask` returns success on some kernels, leaving
    /// the process unrunnable).
    pub(crate) fn validate_cpu_cores(cores: &[usize]) -> Result<usize> {
        if cores.is_empty() {
            return Err(anyhow::anyhow!(
                "CPU affinity requires at least one core; got empty list"
            ));
        }

        let max_cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(64);

        let max_bit = (std::mem::size_of::<usize>() * 8) - 1;
        let mut mask: usize = 0;
        for &core in cores {
            if core >= max_cores {
                return Err(anyhow::anyhow!(
                    "CPU affinity core {} is out of range; system has {} logical core(s)",
                    core,
                    max_cores
                ));
            }
            if core > max_bit {
                return Err(anyhow::anyhow!(
                    "CPU affinity core {} exceeds usize width ({} bits) on this platform",
                    core,
                    max_bit + 1
                ));
            }
            mask |= 1usize << core;
        }
        Ok(mask)
    }

    fn parse_registry_dword(token: &str) -> Option<u32> {
        let raw = token.trim();
        if raw.is_empty() {
            return None;
        }

        if let Some(hex) = raw.strip_prefix("0x") {
            return u32::from_str_radix(hex, 16).ok();
        }

        raw.parse::<u32>().ok()
    }

    fn query_registry_dword(key_path: &str, value_name: &str) -> Option<u32> {
        let output = hidden_command("reg")
            .args(["query", key_path, "/v", value_name])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        for line in output_str.lines() {
            if !line.contains(value_name) || !line.contains("REG_DWORD") {
                continue;
            }

            let value = line
                .split_once("REG_DWORD")
                .map(|(_, tail)| tail.trim())
                .unwrap_or_default();
            if let Some(parsed) = Self::parse_registry_dword(value) {
                return Some(parsed);
            }
        }

        None
    }

    fn query_registry_string(key_path: &str, value_name: &str) -> Option<String> {
        let output = hidden_command("reg")
            .args(["query", key_path, "/v", value_name])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        for line in output_str.lines() {
            if !line.contains(value_name) || !line.contains("REG_SZ") {
                continue;
            }

            let value = line
                .split_once("REG_SZ")
                .map(|(_, tail)| tail.trim())
                .unwrap_or_default();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }

        None
    }

    fn set_registry_dword(key_path: &str, value_name: &str, value: u32) {
        let value_str = value.to_string();
        let output = hidden_command("reg")
            .args([
                "add",
                key_path,
                "/v",
                value_name,
                "/t",
                "REG_DWORD",
                "/d",
                &value_str,
                "/f",
            ])
            .output();

        match output {
            Ok(result) if result.status.success() => {}
            Ok(_) => warn!("Failed to set {}\\{} to {}", key_path, value_name, value),
            Err(e) => warn!(
                "Failed to set {}\\{} to {}: {}",
                key_path, value_name, value, e
            ),
        }
    }

    fn set_registry_string(key_path: &str, value_name: &str, value: &str) {
        let output = hidden_command("reg")
            .args([
                "add", key_path, "/v", value_name, "/t", "REG_SZ", "/d", value, "/f",
            ])
            .output();

        match output {
            Ok(result) if result.status.success() => {}
            Ok(_) => warn!("Failed to set {}\\{} to {}", key_path, value_name, value),
            Err(e) => warn!(
                "Failed to set {}\\{} to {}: {}",
                key_path, value_name, value, e
            ),
        }
    }

    fn restore_registry_dword(key_path: &str, value_name: &str, snapshot: Option<u32>) {
        match snapshot {
            Some(value) => Self::set_registry_dword(key_path, value_name, value),
            None => {
                let _ = hidden_command("reg")
                    .args(["delete", key_path, "/v", value_name, "/f"])
                    .output();
            }
        }
    }

    fn restore_registry_string(key_path: &str, value_name: &str, snapshot: Option<String>) {
        match snapshot {
            Some(value) => Self::set_registry_string(key_path, value_name, &value),
            None => {
                let _ = hidden_command("reg")
                    .args(["delete", key_path, "/v", value_name, "/f"])
                    .output();
            }
        }
    }

    fn capture_dword_snapshot(slot: &mut Option<Option<u32>>, key_path: &str, value_name: &str) {
        if slot.is_none() {
            *slot = Some(Self::query_registry_dword(key_path, value_name));
        }
    }

    fn parse_guid_from_output(output: &str) -> Option<String> {
        output
            .split(|c: char| !c.is_ascii_hexdigit() && c != '-')
            .find(|token| token.len() == 36 && token.matches('-').count() == 4)
            .map(|token| token.to_ascii_lowercase())
    }

    fn output_contains_guid(output: &str, guid: &str) -> bool {
        output
            .split(|c: char| !c.is_ascii_hexdigit() && c != '-')
            .any(|token| token.len() == 36 && token.eq_ignore_ascii_case(guid))
    }

    fn power_plan_guid(plan: &PowerPlan) -> &'static str {
        match plan {
            PowerPlan::Balanced => BALANCED_POWER_PLAN_GUID,
            PowerPlan::HighPerformance => HIGH_PERFORMANCE_POWER_PLAN_GUID,
            PowerPlan::Ultimate => ULTIMATE_POWER_PLAN_GUID,
            PowerPlan::SwiftTunnel => SWIFTTUNNEL_POWER_PLAN_GUID,
        }
    }

    fn active_power_plan_guid() -> Option<String> {
        let output = hidden_command("powercfg")
            .args(["/GETACTIVESCHEME"])
            .output()
            .ok()?;

        if !output.status.success() {
            return None;
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        Self::parse_guid_from_output(&output_str)
    }

    fn is_power_plan_installed(guid: &str) -> Option<bool> {
        let output = hidden_command("powercfg").args(["/list"]).output().ok()?;

        if !output.status.success() {
            return None;
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        Some(Self::output_contains_guid(&output_str, guid))
    }

    fn set_active_power_plan_guid(guid: &str) -> bool {
        let output = hidden_command("powercfg")
            .args(["/setactive", guid])
            .output();

        match output {
            Ok(result) if result.status.success() => true,
            Ok(_) => {
                warn!("Failed to restore power plan {}", guid);
                false
            }
            Err(e) => {
                warn!("Failed to restore power plan {}: {}", guid, e);
                false
            }
        }
    }

    fn can_delete_imported_swifttunnel_power_plan(
        original_restore_succeeded: bool,
        balanced_fallback_succeeded: bool,
    ) -> bool {
        original_restore_succeeded || balanced_fallback_succeeded
    }

    fn delete_power_plan_guid(guid: &str) -> bool {
        let output = hidden_command("powercfg").args(["/delete", guid]).output();

        match output {
            Ok(result) if result.status.success() => true,
            Ok(_) => {
                warn!("Failed to delete SwiftTunnel power plan {}", guid);
                false
            }
            Err(e) => {
                warn!("Failed to delete SwiftTunnel power plan {}: {}", guid, e);
                false
            }
        }
    }

    fn swifttunnel_power_plan_cleanup_decision(
        active_guid: Option<&str>,
        installed: Option<bool>,
    ) -> SwiftTunnelPowerPlanCleanup {
        if active_guid.is_some_and(|guid| guid.eq_ignore_ascii_case(SWIFTTUNNEL_POWER_PLAN_GUID)) {
            return SwiftTunnelPowerPlanCleanup::ActivateBalancedThenDelete;
        }

        match (active_guid, installed) {
            (Some(_), Some(true)) => SwiftTunnelPowerPlanCleanup::DeleteInactive,
            (None, Some(true)) => SwiftTunnelPowerPlanCleanup::UnknownActivePlan,
            _ => SwiftTunnelPowerPlanCleanup::Noop,
        }
    }

    /// Remove SwiftTunnel's custom power plan during ban cleanup even when
    /// the in-memory import snapshot was lost across an app restart.
    pub fn cleanup_swifttunnel_power_plan_after_ban(&mut self) -> Result<()> {
        let active_guid = Self::active_power_plan_guid();
        let installed = Self::is_power_plan_installed(SWIFTTUNNEL_POWER_PLAN_GUID);

        match Self::swifttunnel_power_plan_cleanup_decision(active_guid.as_deref(), installed) {
            SwiftTunnelPowerPlanCleanup::Noop => Ok(()),
            SwiftTunnelPowerPlanCleanup::DeleteInactive => {
                if Self::delete_power_plan_guid(SWIFTTUNNEL_POWER_PLAN_GUID) {
                    self.swifttunnel_power_plan_imported = false;
                    Ok(())
                } else {
                    Err(anyhow::anyhow!(
                        "SwiftTunnel power plan is inactive but could not be deleted"
                    ))
                }
            }
            SwiftTunnelPowerPlanCleanup::ActivateBalancedThenDelete => {
                if !Self::set_active_power_plan_guid(BALANCED_POWER_PLAN_GUID) {
                    return Err(anyhow::anyhow!(
                        "SwiftTunnel power plan is active and Balanced fallback could not be activated"
                    ));
                }

                if Self::delete_power_plan_guid(SWIFTTUNNEL_POWER_PLAN_GUID) {
                    self.swifttunnel_power_plan_imported = false;
                    Ok(())
                } else {
                    Err(anyhow::anyhow!(
                        "Balanced fallback is active, but SwiftTunnel power plan could not be deleted"
                    ))
                }
            }
            SwiftTunnelPowerPlanCleanup::UnknownActivePlan => Err(anyhow::anyhow!(
                "SwiftTunnel power plan is installed, but the active power plan could not be determined"
            )),
        }
    }

    fn write_swifttunnel_power_plan_resource(path: &Path) -> Result<()> {
        fs::write(path, SWIFTTUNNEL_POWER_PLAN_BYTES)
            .map_err(|e| anyhow::anyhow!("Failed to stage SwiftTunnel power plan: {}", e))
    }

    fn staged_swifttunnel_power_plan_path() -> PathBuf {
        std::env::temp_dir().join("swifttunnel_power_plan.pow")
    }

    fn import_swifttunnel_power_plan(&mut self) -> Result<()> {
        let staged_path = Self::staged_swifttunnel_power_plan_path();
        Self::write_swifttunnel_power_plan_resource(&staged_path)?;

        let path_arg = staged_path.to_string_lossy().to_string();
        let output = hidden_command("powercfg")
            .args(["/import", &path_arg, SWIFTTUNNEL_POWER_PLAN_GUID])
            .output();

        let import_result = match output {
            Ok(result) if result.status.success() => {
                let _ = hidden_command("powercfg")
                    .args([
                        "/changename",
                        SWIFTTUNNEL_POWER_PLAN_GUID,
                        SWIFTTUNNEL_POWER_PLAN_NAME,
                        SWIFTTUNNEL_POWER_PLAN_DESCRIPTION,
                    ])
                    .output();
                self.swifttunnel_power_plan_imported = true;
                info!("SwiftTunnel power plan imported successfully");
                Ok(())
            }
            Ok(result) => {
                let stderr = String::from_utf8_lossy(&result.stderr);
                Err(anyhow::anyhow!(
                    "powercfg /import failed for SwiftTunnel power plan: {}",
                    stderr.trim()
                ))
            }
            Err(e) => Err(anyhow::anyhow!(
                "Failed to run powercfg /import for SwiftTunnel power plan: {}",
                e
            )),
        };

        if let Err(e) = fs::remove_file(&staged_path) {
            warn!(
                "Failed to remove staged SwiftTunnel power plan file {}: {}",
                staged_path.display(),
                e
            );
        }

        import_result
    }

    fn ensure_swifttunnel_power_plan(&mut self) -> Result<()> {
        let installed = Self::is_power_plan_installed(SWIFTTUNNEL_POWER_PLAN_GUID);
        if Self::should_import_swifttunnel_power_plan(installed) {
            return self.import_swifttunnel_power_plan();
        }

        if installed.is_none() {
            warn!("Could not list power plans before activating SwiftTunnel power plan");
        }

        Ok(())
    }

    fn should_import_swifttunnel_power_plan(installed: Option<bool>) -> bool {
        matches!(installed, Some(false))
    }

    fn capture_system_state_snapshots(&mut self, config: &SystemOptimizationConfig) {
        if config.disable_game_bar {
            Self::capture_dword_snapshot(&mut self.game_bar_snapshot, GAME_BAR_KEY, GAME_BAR_VALUE);
        }

        if config.disable_fullscreen_optimization {
            Self::capture_dword_snapshot(
                &mut self.fullscreen_optimization_snapshot,
                FULLSCREEN_KEY,
                FULLSCREEN_VALUE,
            );
        }

        if config.game_mode_enabled {
            Self::capture_dword_snapshot(
                &mut self.game_mode_allow_auto_snapshot,
                GAME_MODE_KEY,
                GAME_MODE_ALLOW_AUTO_VALUE,
            );
            Self::capture_dword_snapshot(
                &mut self.game_mode_enabled_snapshot,
                GAME_MODE_KEY,
                GAME_MODE_ENABLED_VALUE,
            );
        }

        if config.mmcss_gaming_profile && self.mmcss_snapshot.is_none() {
            self.mmcss_snapshot = Some(MmcssSnapshot {
                scheduling_category: Self::query_registry_string(
                    MMCSS_GAMES_KEY,
                    "Scheduling Category",
                ),
                sfio_priority: Self::query_registry_string(MMCSS_GAMES_KEY, "SFIO Priority"),
                background_only: Self::query_registry_string(MMCSS_GAMES_KEY, "Background Only"),
                priority: Self::query_registry_dword(MMCSS_GAMES_KEY, "Priority"),
                clock_rate: Self::query_registry_dword(MMCSS_GAMES_KEY, "Clock Rate"),
                system_responsiveness: Self::query_registry_dword(
                    MMCSS_SYSTEM_PROFILE_KEY,
                    "SystemResponsiveness",
                ),
            });
        }

        if !matches!(config.power_plan, PowerPlan::Balanced)
            && self.original_power_plan_guid.is_none()
        {
            self.original_power_plan_guid = Some(Self::active_power_plan_guid());
        }
    }

    fn restore_mmcss_snapshot(snapshot: MmcssSnapshot) {
        Self::restore_registry_string(
            MMCSS_GAMES_KEY,
            "Scheduling Category",
            snapshot.scheduling_category,
        );
        Self::restore_registry_string(MMCSS_GAMES_KEY, "SFIO Priority", snapshot.sfio_priority);
        Self::restore_registry_string(MMCSS_GAMES_KEY, "Background Only", snapshot.background_only);
        Self::restore_registry_dword(MMCSS_GAMES_KEY, "Priority", snapshot.priority);
        Self::restore_registry_dword(MMCSS_GAMES_KEY, "Clock Rate", snapshot.clock_rate);
        Self::restore_registry_dword(
            MMCSS_SYSTEM_PROFILE_KEY,
            "SystemResponsiveness",
            snapshot.system_responsiveness,
        );
    }

    /// Apply all system optimizations
    pub fn apply_optimizations(
        &mut self,
        config: &SystemOptimizationConfig,
        process_id: u32,
    ) -> Result<()> {
        info!(
            "Applying system optimizations for process ID: {}",
            process_id
        );

        self.capture_system_state_snapshots(config);

        if config.set_high_priority {
            if process_id == 0 {
                info!("Skipping process priority boost: no active game process detected yet");
            } else if let Err(e) = self.set_process_priority(process_id) {
                // Process-specific boosts can legitimately fail during restart flows.
                // Keep applying all other boosts; priority will be retried by runtime monitors.
                warn!(
                    "Could not set process priority for PID {} (will retry later): {}",
                    process_id, e
                );
            }
        }

        if config.set_cpu_affinity && !config.cpu_cores.is_empty() {
            if process_id == 0 {
                info!("Skipping CPU affinity boost: no active game process detected yet");
            } else if let Err(e) = self.set_cpu_affinity(process_id, &config.cpu_cores) {
                warn!(
                    "Could not set CPU affinity for PID {} (will retry later): {}",
                    process_id, e
                );
            }
        }

        if config.disable_game_bar {
            self.disable_game_bar()?;
        }

        if config.disable_fullscreen_optimization {
            self.disable_fullscreen_optimizations()?;
        }

        self.set_power_plan(&config.power_plan)?;

        // Tier 1 (Safe) Boosts
        if config.timer_resolution_1ms {
            self.set_timer_resolution(true)?;
        }

        if config.mmcss_gaming_profile {
            self.apply_mmcss_profile()?;
        }

        if config.game_mode_enabled {
            self.enable_game_mode()?;
        }

        Ok(())
    }

    /// Set Roblox process to high priority
    fn set_process_priority(&mut self, process_id: u32) -> Result<()> {
        info!("Setting process priority to high for PID: {}", process_id);

        unsafe {
            let handle = OpenProcess(
                PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION,
                false,
                process_id,
            )?;

            if handle.is_invalid() {
                return Err(anyhow::anyhow!("Failed to open process"));
            }

            // Store original priority for restoration
            let current_priority = GetPriorityClass(handle);
            if current_priority != 0 {
                self.original_priority = Some(current_priority);
            }

            // Set to high priority (but not realtime to avoid system issues)
            let result = SetPriorityClass(handle, HIGH_PRIORITY_CLASS);

            let _ = CloseHandle(handle);

            if result.is_ok() {
                info!("Successfully set process priority to HIGH");
                Ok(())
            } else {
                Err(anyhow::anyhow!("Failed to set process priority"))
            }
        }
    }

    /// Set CPU affinity for Roblox process. Captures the existing affinity
    /// mask on first apply so `restore` can undo it cleanly.
    fn set_cpu_affinity(&mut self, process_id: u32, cores: &[usize]) -> Result<()> {
        let affinity_mask = Self::validate_cpu_cores(cores)?;
        info!(
            "Setting CPU affinity for PID: {} to cores: {:?} (mask 0x{:X})",
            process_id, cores, affinity_mask
        );

        unsafe {
            let handle = OpenProcess(
                PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION,
                false,
                process_id,
            )?;

            if handle.is_invalid() {
                return Err(anyhow::anyhow!("Failed to open process"));
            }

            // Capture pre-apply mask once per boost cycle so restore returns
            // the process to its original state, not to "all cores".
            if self.original_affinity.is_none() {
                let mut process_mask: usize = 0;
                let mut system_mask: usize = 0;
                if GetProcessAffinityMask(handle, &mut process_mask, &mut system_mask).is_ok()
                    && process_mask != 0
                {
                    self.original_affinity = Some(process_mask);
                } else {
                    // Fall back to "all cores in the system" if we can't read
                    // the current mask — better than leaving the process
                    // pinned forever after disable.
                    self.original_affinity = Some(if system_mask != 0 {
                        system_mask
                    } else {
                        ALL_CORES_AFFINITY_MASK
                    });
                    warn!(
                        "Could not read original affinity for PID {}; restore will use system mask",
                        process_id
                    );
                }
            }

            let result = SetProcessAffinityMask(handle, affinity_mask);
            let _ = CloseHandle(handle);

            if result.is_ok() {
                info!("Successfully set CPU affinity");
                Ok(())
            } else {
                Err(anyhow::anyhow!("Failed to set CPU affinity"))
            }
        }
    }

    /// Restore CPU affinity to the snapshot taken on first apply.
    /// Best-effort: a vanished PID is logged, not an error.
    fn restore_cpu_affinity(&mut self, process_id: u32) {
        let Some(mask) = self.original_affinity.take() else {
            return;
        };

        if process_id == 0 {
            info!("Skipping CPU affinity restore: no active game process");
            return;
        }

        unsafe {
            let handle = match OpenProcess(
                PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION,
                false,
                process_id,
            ) {
                Ok(h) if !h.is_invalid() => h,
                Ok(_) => {
                    info!("CPU affinity restore: PID {} has no handle", process_id);
                    return;
                }
                Err(e) => {
                    info!(
                        "CPU affinity restore: PID {} unreachable (likely exited): {}",
                        process_id, e
                    );
                    return;
                }
            };

            if let Err(e) = SetProcessAffinityMask(handle, mask) {
                warn!(
                    "Failed to restore CPU affinity for PID {} to mask 0x{:X}: {}",
                    process_id, mask, e
                );
            } else {
                info!(
                    "Restored CPU affinity for PID {} to mask 0x{:X}",
                    process_id, mask
                );
            }
            let _ = CloseHandle(handle);
        }
    }

    /// Disable Windows Game Bar
    fn disable_game_bar(&self) -> Result<()> {
        info!("Disabling Windows Game Bar");

        let output = hidden_command("reg")
            .args([
                "add",
                GAME_BAR_KEY,
                "/v",
                GAME_BAR_VALUE,
                "/t",
                "REG_DWORD",
                "/d",
                "0",
                "/f",
            ])
            .output();

        match output {
            Ok(result) if result.status.success() => {
                info!("Game Bar disabled successfully");
                Ok(())
            }
            Ok(result) => {
                let stderr = String::from_utf8_lossy(&result.stderr);
                Err(anyhow::anyhow!(
                    "Game Bar disable failed: {}",
                    stderr.trim()
                ))
            }
            Err(e) => Err(anyhow::anyhow!("Game Bar disable: reg invoke failed: {}", e)),
        }
    }

    /// Disable fullscreen optimizations for Roblox
    fn disable_fullscreen_optimizations(&self) -> Result<()> {
        info!("Disabling fullscreen optimizations");

        let output = hidden_command("reg")
            .args([
                "add",
                FULLSCREEN_KEY,
                "/v",
                FULLSCREEN_VALUE,
                "/t",
                "REG_DWORD",
                "/d",
                "2",
                "/f",
            ])
            .output();

        match output {
            Ok(result) if result.status.success() => {
                info!("Fullscreen optimizations disabled");
                Ok(())
            }
            Ok(result) => {
                let stderr = String::from_utf8_lossy(&result.stderr);
                Err(anyhow::anyhow!(
                    "Fullscreen optimization disable failed: {}",
                    stderr.trim()
                ))
            }
            Err(e) => Err(anyhow::anyhow!(
                "Fullscreen optimization disable: reg invoke failed: {}",
                e
            )),
        }
    }

    /// Set Windows power plan. Returns Err on import or activation failure
    /// so the caller can surface the failure to the user instead of falsely
    /// reporting "boost applied".
    fn set_power_plan(&mut self, plan: &PowerPlan) -> Result<()> {
        let guid = Self::power_plan_guid(plan);

        info!("Setting power plan to: {:?}", plan);

        if matches!(plan, PowerPlan::SwiftTunnel) {
            if let Err(e) = self.ensure_swifttunnel_power_plan() {
                return Err(anyhow::anyhow!(
                    "SwiftTunnel power plan import failed: {}",
                    e
                ));
            }
        }

        let output = hidden_command("powercfg")
            .args(["/setactive", guid])
            .output();

        match output {
            Ok(result) if result.status.success() => {
                info!("Power plan set successfully");
                Ok(())
            }
            Ok(result) => {
                let stderr = String::from_utf8_lossy(&result.stderr);
                Err(anyhow::anyhow!(
                    "powercfg /setactive {} failed (admin may be required): {}",
                    guid,
                    stderr.trim()
                ))
            }
            Err(e) => Err(anyhow::anyhow!(
                "powercfg /setactive {} invocation failed: {}",
                guid,
                e
            )),
        }
    }

    // ===== TIER 1 (SAFE) BOOSTS =====

    /// Set system timer resolution to 0.5ms for smoother frame pacing.
    /// Uses NtSetTimerResolution for sub-millisecond precision (5000 = 0.5ms
    /// in 100ns units), with timeBeginPeriod(1) as a fallback.
    ///
    /// On Windows 11 22H2+ the timer resolution call is per-process scoped,
    /// so we also write `GlobalTimerResolutionRequests=1` to restore the
    /// system-wide behavior that lets Roblox benefit from our request.
    /// The kernel reads that key only at boot, so the global half of this
    /// boost takes effect after the next reboot.
    pub fn set_timer_resolution(&mut self, enable: bool) -> Result<()> {
        if enable && !self.timer_resolution_active {
            info!("Setting timer resolution to 0.5ms");
            unsafe {
                // Try NtSetTimerResolution for 0.5ms (5000 * 100ns = 0.5ms)
                let mut current: u32 = 0;
                let status = NtSetTimerResolution(5000, 1, &mut current);
                if status == 0 {
                    // STATUS_SUCCESS
                    self.timer_resolution_active = true;
                    info!(
                        "Timer resolution set to 0.5ms via NtSetTimerResolution (actual: {:.3}ms)",
                        current as f64 / 10000.0
                    );
                } else {
                    // Fallback to timeBeginPeriod(1) for 1ms
                    warn!(
                        "NtSetTimerResolution failed (0x{:08X}), falling back to 1ms",
                        status
                    );
                    let result = timeBeginPeriod(1);
                    if result == 0 {
                        self.timer_resolution_active = true;
                        info!("Timer resolution set to 1ms via timeBeginPeriod (fallback)");
                    } else {
                        warn!("Failed to set timer resolution: error code {}", result);
                    }
                }
            }

            // Make sure the system-wide override is on so the per-process
            // resolution we just set is honored for other processes too on
            // Win11 22H2+. Snapshot the prior value so restore() can revert.
            self.enable_global_timer_resolution_override();
        } else if !enable && self.timer_resolution_active {
            info!("Restoring default timer resolution");
            unsafe {
                // Undo NtSetTimerResolution
                let mut current: u32 = 0;
                let _ = NtSetTimerResolution(5000, 0, &mut current);
                // Also undo timeBeginPeriod in case fallback was used
                let _ = timeEndPeriod(1);
                self.timer_resolution_active = false;
            }
            self.restore_global_timer_resolution_override();
        }
        Ok(())
    }

    fn enable_global_timer_resolution_override(&mut self) {
        Self::capture_dword_snapshot(
            &mut self.global_timer_snapshot,
            GLOBAL_TIMER_RESOLUTION_KEY,
            GLOBAL_TIMER_RESOLUTION_VALUE,
        );

        // Skip the write if it's already 1 — avoids an unnecessary reg call
        // and prevents spurious "needs reboot" telemetry on repeat applies.
        if Self::query_registry_dword(
            GLOBAL_TIMER_RESOLUTION_KEY,
            GLOBAL_TIMER_RESOLUTION_VALUE,
        ) == Some(1)
        {
            return;
        }

        Self::set_registry_dword(
            GLOBAL_TIMER_RESOLUTION_KEY,
            GLOBAL_TIMER_RESOLUTION_VALUE,
            1,
        );

        // The kernel reads this key only at boot — log so users grepping for
        // "why isn't my timer boost working" get a useful breadcrumb.
        info!(
            "Wrote {}\\{}=1; reboot required for the global override to take effect on Windows 11 22H2+",
            GLOBAL_TIMER_RESOLUTION_KEY, GLOBAL_TIMER_RESOLUTION_VALUE
        );
    }

    fn restore_global_timer_resolution_override(&mut self) {
        if let Some(snapshot) = self.global_timer_snapshot.take() {
            Self::restore_registry_dword(
                GLOBAL_TIMER_RESOLUTION_KEY,
                GLOBAL_TIMER_RESOLUTION_VALUE,
                snapshot,
            );
        }
    }

    /// Apply MMCSS (Multimedia Class Scheduler Service) gaming profile
    /// This boosts priority for game processes via the Windows scheduler
    pub fn apply_mmcss_profile(&self) -> Result<()> {
        info!("Applying MMCSS gaming profile");

        // Set MMCSS gaming profile registry keys
        let mmcss_keys = [
            (
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games",
                "Scheduling Category",
                "High",
            ),
            (
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games",
                "SFIO Priority",
                "High",
            ),
            (
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games",
                "Background Only",
                "False",
            ),
        ];

        for (key_path, value_name, value_data) in mmcss_keys.iter() {
            Self::set_registry_string(key_path, value_name, value_data);
        }

        // Set DWORD values separately
        let dword_keys = [
            (
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games",
                "Priority",
                "6",
            ),
            (
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games",
                "Clock Rate",
                "10000",
            ),
            (
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile",
                "SystemResponsiveness",
                "0",
            ),
        ];

        for (key_path, value_name, value_data) in dword_keys.iter() {
            if let Ok(value) = value_data.parse::<u32>() {
                Self::set_registry_dword(key_path, value_name, value);
            }
        }

        info!("MMCSS gaming profile applied");
        Ok(())
    }

    /// Restore MMCSS profile to Windows defaults
    pub fn restore_mmcss_profile(&mut self) -> Result<()> {
        if let Some(snapshot) = self.mmcss_snapshot.take() {
            info!("Restoring MMCSS profile from snapshot");
            Self::restore_mmcss_snapshot(snapshot);
            return Ok(());
        }

        info!("Restoring MMCSS profile to defaults");
        Self::set_registry_string(MMCSS_GAMES_KEY, "Scheduling Category", "Medium");
        Self::set_registry_string(MMCSS_GAMES_KEY, "SFIO Priority", "Normal");
        Self::set_registry_string(MMCSS_GAMES_KEY, "Background Only", "True");
        Self::set_registry_dword(MMCSS_GAMES_KEY, "Priority", 2);
        Self::set_registry_dword(MMCSS_GAMES_KEY, "Clock Rate", 10000);
        Self::set_registry_dword(MMCSS_SYSTEM_PROFILE_KEY, "SystemResponsiveness", 20);
        Ok(())
    }

    /// Enable Windows Game Mode for resource prioritization
    pub fn enable_game_mode(&self) -> Result<()> {
        info!("Enabling Windows Game Mode");

        let game_mode_keys = [
            (GAME_MODE_KEY, GAME_MODE_ALLOW_AUTO_VALUE, "1"),
            (GAME_MODE_KEY, GAME_MODE_ENABLED_VALUE, "1"),
        ];

        for (key_path, value_name, value_data) in game_mode_keys.iter() {
            if let Ok(value) = value_data.parse::<u32>() {
                Self::set_registry_dword(key_path, value_name, value);
            }
        }

        info!("Windows Game Mode enabled");
        Ok(())
    }

    /// Disable Windows Game Mode
    pub fn disable_game_mode(&self) -> Result<()> {
        info!("Disabling Windows Game Mode");

        let game_mode_keys = [
            (GAME_MODE_KEY, GAME_MODE_ALLOW_AUTO_VALUE, "0"),
            (GAME_MODE_KEY, GAME_MODE_ENABLED_VALUE, "0"),
        ];

        for (key_path, value_name, value_data) in game_mode_keys.iter() {
            if let Ok(value) = value_data.parse::<u32>() {
                Self::set_registry_dword(key_path, value_name, value);
            }
        }

        info!("Windows Game Mode disabled");
        Ok(())
    }

    // ===== SYSTEM RESTORE POINT =====

    /// Create a Windows System Restore Point before applying optimizations
    /// Returns the description of the restore point if successful
    pub fn create_restore_point(description: &str) -> Result<String> {
        info!("Creating System Restore Point: {}", description);

        // Enable System Restore on C: drive first (in case it's disabled)
        let enable_output = hidden_command("powershell")
            .args([
                "-Command",
                "Enable-ComputerRestore -Drive 'C:\\' -ErrorAction SilentlyContinue",
            ])
            .output();

        if let Err(e) = enable_output {
            warn!("Failed to enable System Restore: {}", e);
            // Continue anyway, it might already be enabled
        }

        // Create the restore point
        let ps_command = format!(
            "Checkpoint-Computer -Description '{}' -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop",
            description.replace('\'', "''") // Escape single quotes
        );

        let output = hidden_command("powershell")
            .args(["-Command", &ps_command])
            .output();

        match output {
            Ok(result) => {
                if result.status.success() {
                    info!("System Restore Point created successfully");
                    Ok(description.to_string())
                } else {
                    let stderr = String::from_utf8_lossy(&result.stderr);
                    // Check for common issues
                    if stderr.contains("frequency") || stderr.contains("24 hours") {
                        warn!("Restore point not created: Windows limits to one per 24 hours");
                        // This is not a failure - Windows just throttles restore points
                        Ok(format!("{} (throttled by Windows)", description))
                    } else {
                        warn!("Failed to create restore point: {}", stderr);
                        Err(anyhow::anyhow!(
                            "Failed to create restore point: {}",
                            stderr
                        ))
                    }
                }
            }
            Err(e) => {
                warn!("Failed to run restore point command: {}", e);
                Err(anyhow::anyhow!("Failed to create restore point: {}", e))
            }
        }
    }

    /// Restore the system using System Restore (opens the Windows UI)
    pub fn open_system_restore() -> Result<()> {
        info!("Opening Windows System Restore");

        let output = Command::new("rstrui.exe").spawn();

        match output {
            Ok(_) => {
                info!("System Restore UI opened");
                Ok(())
            }
            Err(e) => {
                warn!("Failed to open System Restore: {}", e);
                Err(anyhow::anyhow!("Failed to open System Restore: {}", e))
            }
        }
    }

    /// Restore original system settings
    pub fn restore(&mut self, process_id: u32) -> Result<()> {
        info!("Restoring original system settings");

        // Restore timer resolution if active
        if self.timer_resolution_active {
            self.set_timer_resolution(false)?;
        }
        // Safety net: clean up the global timer override snapshot even if
        // `timer_resolution_active` was already false (e.g., crash recovery).
        self.restore_global_timer_resolution_override();

        if let Some(priority) = self.original_priority.take() {
            unsafe {
                if let Ok(handle) = OpenProcess(PROCESS_SET_INFORMATION, false, process_id) {
                    if !handle.is_invalid() {
                        let _ = SetPriorityClass(handle, PROCESS_CREATION_FLAGS(priority));
                        let _ = CloseHandle(handle);
                    }
                }
            }
        }

        // Affinity is restored independently of priority because the boost can
        // be enabled with affinity-only or priority-only configs.
        self.restore_cpu_affinity(process_id);

        if let Some(snapshot) = self.mmcss_snapshot.take() {
            Self::restore_mmcss_snapshot(snapshot);
        }

        if let Some(snapshot) = self.game_mode_enabled_snapshot.take() {
            Self::restore_registry_dword(GAME_MODE_KEY, GAME_MODE_ENABLED_VALUE, snapshot);
        }

        if let Some(snapshot) = self.game_mode_allow_auto_snapshot.take() {
            Self::restore_registry_dword(GAME_MODE_KEY, GAME_MODE_ALLOW_AUTO_VALUE, snapshot);
        }

        if let Some(snapshot) = self.fullscreen_optimization_snapshot.take() {
            Self::restore_registry_dword(FULLSCREEN_KEY, FULLSCREEN_VALUE, snapshot);
        }

        if let Some(snapshot) = self.game_bar_snapshot.take() {
            Self::restore_registry_dword(GAME_BAR_KEY, GAME_BAR_VALUE, snapshot);
        }

        let mut original_power_plan_restored = false;
        if let Some(snapshot) = self.original_power_plan_guid.take() {
            if let Some(guid) = snapshot {
                original_power_plan_restored = Self::set_active_power_plan_guid(&guid);
            }
        }

        if self.swifttunnel_power_plan_imported {
            let balanced_fallback_restored = if original_power_plan_restored {
                false
            } else {
                warn!(
                    "Original power plan was not restored before deleting SwiftTunnel power plan; falling back to Balanced"
                );
                Self::set_active_power_plan_guid(BALANCED_POWER_PLAN_GUID)
            };

            if Self::can_delete_imported_swifttunnel_power_plan(
                original_power_plan_restored,
                balanced_fallback_restored,
            ) {
                if Self::delete_power_plan_guid(SWIFTTUNNEL_POWER_PLAN_GUID) {
                    self.swifttunnel_power_plan_imported = false;
                }
            } else {
                warn!(
                    "Skipping SwiftTunnel power plan deletion because no safe replacement plan could be activated"
                );
            }
        }

        Ok(())
    }

    /// Check if timer resolution is currently active
    pub fn is_timer_resolution_active(&self) -> bool {
        self.timer_resolution_active
    }
}

impl Default for SystemOptimizer {
    fn default() -> Self {
        Self::new()
    }
}

/// Restore all system optimizer changes for uninstall.
///
/// Reverses MMCSS profile, Game Bar, fullscreen optimizations, Game Mode,
/// and power plan to Windows defaults. Uses `let _ =` for each operation
/// so individual failures never short-circuit the rest.
pub fn cleanup_for_uninstall() {
    info!("System optimizer: cleaning up for uninstall");

    // 1. Restore MMCSS profile to Windows defaults
    let mut optimizer = SystemOptimizer::new();
    let _ = optimizer.restore_mmcss_profile();

    // 2. Delete Game Bar override (let Windows use its default)
    let _ = hidden_command("reg")
        .args([
            "delete",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\GameDVR",
            "/v",
            "AppCaptureEnabled",
            "/f",
        ])
        .output();

    // 3. Delete fullscreen optimization override
    let _ = hidden_command("reg")
        .args([
            "delete",
            r"HKCU\System\GameConfigStore",
            "/v",
            "GameDVR_FSEBehaviorMode",
            "/f",
        ])
        .output();

    // 4. Delete Game Mode overrides
    let _ = hidden_command("reg")
        .args([
            "delete",
            r"HKCU\Software\Microsoft\GameBar",
            "/v",
            "AllowAutoGameMode",
            "/f",
        ])
        .output();
    let _ = hidden_command("reg")
        .args([
            "delete",
            r"HKCU\Software\Microsoft\GameBar",
            "/v",
            "AutoGameModeEnabled",
            "/f",
        ])
        .output();

    // 5. Restore Balanced power plan
    let _ = hidden_command("powercfg")
        .args(["/setactive", BALANCED_POWER_PLAN_GUID])
        .output();

    let _ = hidden_command("powercfg")
        .args(["/delete", SWIFTTUNNEL_POWER_PLAN_GUID])
        .output();

    info!("System optimizer: uninstall cleanup completed");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn power_plan_guid_maps_swifttunnel_to_embedded_plan_guid() {
        assert_eq!(
            SystemOptimizer::power_plan_guid(&PowerPlan::SwiftTunnel),
            SWIFTTUNNEL_POWER_PLAN_GUID
        );
    }

    #[test]
    fn power_plan_guid_parser_matches_exact_guid_tokens() {
        let output = format!(
            "Power Scheme GUID: {}  (SwiftTunnel) *",
            SWIFTTUNNEL_POWER_PLAN_GUID.to_ascii_uppercase()
        );

        assert!(SystemOptimizer::output_contains_guid(
            &output,
            SWIFTTUNNEL_POWER_PLAN_GUID
        ));
    }

    #[test]
    fn power_plan_guid_parser_rejects_superficially_similar_text() {
        let output = "Power Scheme GUID: 44444444-4444-4444-4444-444444444453 (Other)";

        assert!(!SystemOptimizer::output_contains_guid(
            output,
            SWIFTTUNNEL_POWER_PLAN_GUID
        ));
    }

    #[test]
    fn swifttunnel_power_plan_import_is_only_for_confirmed_missing_plan() {
        assert!(SystemOptimizer::should_import_swifttunnel_power_plan(Some(
            false
        )));
        assert!(!SystemOptimizer::should_import_swifttunnel_power_plan(
            Some(true)
        ));
        assert!(!SystemOptimizer::should_import_swifttunnel_power_plan(None));
    }

    #[test]
    fn imported_power_plan_delete_requires_a_safe_active_replacement() {
        assert!(SystemOptimizer::can_delete_imported_swifttunnel_power_plan(
            true, false
        ));
        assert!(SystemOptimizer::can_delete_imported_swifttunnel_power_plan(
            false, true
        ));
        assert!(!SystemOptimizer::can_delete_imported_swifttunnel_power_plan(false, false));
    }

    #[test]
    fn stale_active_swifttunnel_power_plan_switches_to_balanced_before_delete() {
        assert_eq!(
            SystemOptimizer::swifttunnel_power_plan_cleanup_decision(
                Some(SWIFTTUNNEL_POWER_PLAN_GUID),
                Some(true),
            ),
            SwiftTunnelPowerPlanCleanup::ActivateBalancedThenDelete
        );
    }

    #[test]
    fn inactive_swifttunnel_power_plan_can_be_deleted_without_switching() {
        assert_eq!(
            SystemOptimizer::swifttunnel_power_plan_cleanup_decision(
                Some(BALANCED_POWER_PLAN_GUID),
                Some(true),
            ),
            SwiftTunnelPowerPlanCleanup::DeleteInactive
        );
    }

    #[test]
    fn similar_active_power_plan_does_not_trigger_balanced_fallback() {
        assert_eq!(
            SystemOptimizer::swifttunnel_power_plan_cleanup_decision(
                Some("44444444-4444-4444-4444-444444444453"),
                Some(false),
            ),
            SwiftTunnelPowerPlanCleanup::Noop
        );
    }

    #[test]
    fn installed_swifttunnel_power_plan_is_not_deleted_when_active_plan_is_unknown() {
        assert_eq!(
            SystemOptimizer::swifttunnel_power_plan_cleanup_decision(None, Some(true)),
            SwiftTunnelPowerPlanCleanup::UnknownActivePlan
        );
    }

    #[test]
    fn embedded_swifttunnel_power_plan_resource_is_present() {
        assert!(SWIFTTUNNEL_POWER_PLAN_BYTES.starts_with(b"regf"));
        assert!(SWIFTTUNNEL_POWER_PLAN_BYTES.len() > 1024);
    }

    #[test]
    fn validate_cpu_cores_rejects_empty_list() {
        let err = SystemOptimizer::validate_cpu_cores(&[]).unwrap_err();
        assert!(
            err.to_string().contains("at least one core"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn validate_cpu_cores_rejects_core_beyond_available_parallelism() {
        // Pick a core id well past any realistic machine. This is the negative
        // test for the prior bug where impossible cores were silently OR'd into
        // an unrunnable mask.
        let err = SystemOptimizer::validate_cpu_cores(&[10_000]).unwrap_err();
        assert!(
            err.to_string().contains("out of range")
                || err.to_string().contains("exceeds usize width"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn validate_cpu_cores_builds_correct_mask_for_known_core_zero() {
        // Every machine has at least core 0.
        let mask = SystemOptimizer::validate_cpu_cores(&[0]).unwrap();
        assert_eq!(mask, 0b1);
    }

    #[test]
    fn validate_cpu_cores_combines_bits_for_multiple_cores() {
        if std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
            < 2
        {
            return; // skip on single-core CI
        }
        let mask = SystemOptimizer::validate_cpu_cores(&[0, 1]).unwrap();
        assert_eq!(mask, 0b11);
    }

    #[test]
    fn restore_cpu_affinity_with_no_snapshot_is_noop() {
        let mut optimizer = SystemOptimizer::new();
        // No state captured — must not panic and must not contact a process.
        optimizer.restore_cpu_affinity(0);
        optimizer.restore_cpu_affinity(u32::MAX);
        assert!(optimizer.original_affinity.is_none());
    }

    #[test]
    fn restore_cpu_affinity_with_dead_pid_clears_snapshot_without_panic() {
        let mut optimizer = SystemOptimizer::new();
        optimizer.original_affinity = Some(0b1);
        // u32::MAX is an unreachable PID; OpenProcess should fail and the
        // restore path must classify it as "process gone" without panic.
        optimizer.restore_cpu_affinity(u32::MAX);
        assert!(
            optimizer.original_affinity.is_none(),
            "snapshot should be consumed even when restore can't reach the process"
        );
    }
}
