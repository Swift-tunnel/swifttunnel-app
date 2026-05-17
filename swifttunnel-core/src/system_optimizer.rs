use crate::hidden_command;
use crate::structs::*;
use log::{info, warn};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Media::{timeBeginPeriod, timeEndPeriod};
use windows::Win32::System::Threading::*;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegistryWrite<'a> {
    Dword {
        key_path: &'a str,
        value_name: &'a str,
        value: u32,
    },
    String {
        key_path: &'a str,
        value_name: &'a str,
        value: &'a str,
    },
}

pub struct SystemOptimizer {
    original_priority: Option<u32>,
    timer_resolution_active: bool,
    original_power_plan_guid: Option<Option<String>>,
    game_bar_snapshot: Option<Option<u32>>,
    fullscreen_optimization_snapshot: Option<Option<u32>>,
    game_mode_allow_auto_snapshot: Option<Option<u32>>,
    game_mode_enabled_snapshot: Option<Option<u32>>,
    mmcss_snapshot: Option<MmcssSnapshot>,
    swifttunnel_power_plan_imported: bool,
}

pub struct SystemApplyOutcome {
    pub applied_config: SystemOptimizationConfig,
    pub warnings: Vec<String>,
}

impl SystemOptimizer {
    pub fn new() -> Self {
        Self {
            original_priority: None,
            timer_resolution_active: false,
            original_power_plan_guid: None,
            game_bar_snapshot: None,
            fullscreen_optimization_snapshot: None,
            game_mode_allow_auto_snapshot: None,
            game_mode_enabled_snapshot: None,
            mmcss_snapshot: None,
            swifttunnel_power_plan_imported: false,
        }
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

    fn command_failure_message(command_label: &str, stderr: &[u8], stdout: &[u8]) -> String {
        let stderr = String::from_utf8_lossy(stderr).trim().to_string();
        if !stderr.is_empty() {
            return format!("{} failed: {}", command_label, stderr);
        }

        let stdout = String::from_utf8_lossy(stdout).trim().to_string();
        if !stdout.is_empty() {
            return format!("{} failed: {}", command_label, stdout);
        }

        format!("{} failed without an error message", command_label)
    }

    fn try_set_registry_dword(key_path: &str, value_name: &str, value: u32) -> Result<()> {
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
            Ok(result) => {
                return Err(anyhow::anyhow!(
                    "{}",
                    Self::command_failure_message(
                        &format!("reg add {}\\{}", key_path, value_name),
                        &result.stderr,
                        &result.stdout,
                    )
                ));
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "failed to run reg add {}\\{}: {}",
                    key_path,
                    value_name,
                    e
                ));
            }
        }

        match Self::query_registry_dword(key_path, value_name) {
            Some(actual) if actual == value => Ok(()),
            Some(actual) => Err(anyhow::anyhow!(
                "{}\\{} verified as {}, expected {}",
                key_path,
                value_name,
                actual,
                value
            )),
            None => Err(anyhow::anyhow!(
                "{}\\{} was not readable after write",
                key_path,
                value_name
            )),
        }
    }

    fn set_registry_dword(key_path: &str, value_name: &str, value: u32) {
        if let Err(e) = Self::try_set_registry_dword(key_path, value_name, value) {
            warn!("{}", e);
        }
    }

    fn try_set_registry_string(key_path: &str, value_name: &str, value: &str) -> Result<()> {
        let output = hidden_command("reg")
            .args([
                "add", key_path, "/v", value_name, "/t", "REG_SZ", "/d", value, "/f",
            ])
            .output();

        match output {
            Ok(result) if result.status.success() => {}
            Ok(result) => {
                return Err(anyhow::anyhow!(
                    "{}",
                    Self::command_failure_message(
                        &format!("reg add {}\\{}", key_path, value_name),
                        &result.stderr,
                        &result.stdout,
                    )
                ));
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "failed to run reg add {}\\{}: {}",
                    key_path,
                    value_name,
                    e
                ));
            }
        }

        match Self::query_registry_string(key_path, value_name) {
            Some(actual) if actual == value => Ok(()),
            Some(actual) => Err(anyhow::anyhow!(
                "{}\\{} verified as {:?}, expected {:?}",
                key_path,
                value_name,
                actual,
                value
            )),
            None => Err(anyhow::anyhow!(
                "{}\\{} was not readable after write",
                key_path,
                value_name
            )),
        }
    }

    fn set_registry_string(key_path: &str, value_name: &str, value: &str) {
        if let Err(e) = Self::try_set_registry_string(key_path, value_name, value) {
            warn!("{}", e);
        }
    }

    fn apply_registry_write(write: RegistryWrite<'_>) -> Result<()> {
        match write {
            RegistryWrite::Dword {
                key_path,
                value_name,
                value,
            } => Self::try_set_registry_dword(key_path, value_name, value),
            RegistryWrite::String {
                key_path,
                value_name,
                value,
            } => Self::try_set_registry_string(key_path, value_name, value),
        }
    }

    fn apply_registry_writes_with_rollback<'a, F, R>(
        writes: &[RegistryWrite<'a>],
        mut apply: F,
        rollback: R,
    ) -> Result<()>
    where
        F: FnMut(RegistryWrite<'a>) -> Result<()>,
        R: FnOnce(),
    {
        for write in writes.iter().copied() {
            if let Err(e) = apply(write) {
                rollback();
                return Err(e);
            }
        }

        Ok(())
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

    fn power_plan_from_guid(guid: &str) -> Option<PowerPlan> {
        if guid.eq_ignore_ascii_case(BALANCED_POWER_PLAN_GUID) {
            Some(PowerPlan::Balanced)
        } else if guid.eq_ignore_ascii_case(HIGH_PERFORMANCE_POWER_PLAN_GUID) {
            Some(PowerPlan::HighPerformance)
        } else if guid.eq_ignore_ascii_case(ULTIMATE_POWER_PLAN_GUID) {
            Some(PowerPlan::Ultimate)
        } else if guid.eq_ignore_ascii_case(SWIFTTUNNEL_POWER_PLAN_GUID) {
            Some(PowerPlan::SwiftTunnel)
        } else {
            None
        }
    }

    fn active_power_plan() -> Option<PowerPlan> {
        Self::active_power_plan_guid().and_then(|guid| Self::power_plan_from_guid(&guid))
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

    fn try_set_active_power_plan_guid(guid: &str) -> Result<()> {
        let output = hidden_command("powercfg")
            .args(["/setactive", guid])
            .output();

        match output {
            Ok(result) if result.status.success() => {}
            Ok(result) => {
                return Err(anyhow::anyhow!(
                    "{}",
                    Self::command_failure_message(
                        &format!("powercfg /setactive {}", guid),
                        &result.stderr,
                        &result.stdout,
                    )
                ));
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "failed to run powercfg /setactive {}: {}",
                    guid,
                    e
                ));
            }
        }

        match Self::active_power_plan_guid() {
            Some(active) if active.eq_ignore_ascii_case(guid) => Ok(()),
            Some(active) => Err(anyhow::anyhow!(
                "active power plan verified as {}, expected {}",
                active,
                guid
            )),
            None => Err(anyhow::anyhow!(
                "active power plan could not be read after setting {}",
                guid
            )),
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

    fn capture_mmcss_snapshot() -> MmcssSnapshot {
        MmcssSnapshot {
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
        }
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
            self.mmcss_snapshot = Some(Self::capture_mmcss_snapshot());
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
    #[deprecated(note = "Use apply_optimizations_checked so persisted config is reconciled")]
    pub fn apply_optimizations(
        &mut self,
        config: &SystemOptimizationConfig,
        process_id: u32,
    ) -> Result<()> {
        let outcome = self.apply_optimizations_checked(config, process_id);
        if !outcome.warnings.is_empty() {
            warn!(
                "System optimizations applied with warnings: {}",
                outcome.warnings.join("; ")
            );
        }

        Ok(())
    }

    /// Apply system optimizations and return the config safe to persist.
    ///
    /// Process-only boosts with no target process keep the requested setting so
    /// the next apply while Roblox is running can honor the user's intent.
    /// Registry, timer, and power-plan boosts must verify via the corresponding
    /// Windows readback before the UI persists them as active.
    pub fn apply_optimizations_checked(
        &mut self,
        config: &SystemOptimizationConfig,
        process_id: u32,
    ) -> SystemApplyOutcome {
        info!(
            "Applying system optimizations for process ID: {}",
            process_id
        );

        let mut applied_config = config.clone();
        let mut warnings = Vec::new();

        self.capture_system_state_snapshots(config);

        if config.set_high_priority {
            if process_id == 0 {
                warnings
                    .push("High Priority Mode is waiting for an active Roblox process".to_string());
            } else if let Err(e) = self.set_process_priority(process_id) {
                applied_config.set_high_priority = false;
                warnings.push(format!(
                    "High Priority Mode could not be applied to PID {}: {}",
                    process_id, e
                ));
            }
        }

        if config.set_cpu_affinity {
            if config.cpu_cores.is_empty() {
                applied_config.set_cpu_affinity = false;
                warnings
                    .push("CPU affinity skipped because no CPU cores were selected".to_string());
            } else if process_id == 0 {
                warnings.push("CPU affinity is waiting for an active Roblox process".to_string());
            } else if let Err(e) = self.set_cpu_affinity(process_id, &config.cpu_cores) {
                applied_config.set_cpu_affinity = false;
                warnings.push(format!(
                    "CPU affinity could not be applied to PID {}: {}",
                    process_id, e
                ));
            }
        }

        if config.disable_game_bar {
            if let Err(e) = self.disable_game_bar() {
                applied_config.disable_game_bar = false;
                warnings.push(format!("Disable Game Bar did not verify: {}", e));
            }
        }

        if config.disable_fullscreen_optimization {
            if let Err(e) = self.disable_fullscreen_optimizations() {
                applied_config.disable_fullscreen_optimization = false;
                warnings.push(format!(
                    "Disable fullscreen optimization did not verify: {}",
                    e
                ));
            }
        }

        if let Err(e) = self.set_power_plan(&config.power_plan) {
            if let Some(active_power_plan) = Self::active_power_plan() {
                applied_config.power_plan = active_power_plan;
                warnings.push(format!(
                    "Power plan did not verify: {}; active plan read back as {:?}",
                    e, active_power_plan
                ));
            } else {
                applied_config.power_plan =
                    config.previous_power_plan.unwrap_or(PowerPlan::Balanced);
                warnings.push(format!(
                    "Power plan did not verify and the active plan could not be mapped to a SwiftTunnel option: {}",
                    e
                ));
            }
        }

        // Tier 1 (Safe) Boosts
        if config.timer_resolution_1ms {
            if let Err(e) = self.set_timer_resolution(true) {
                applied_config.timer_resolution_1ms = false;
                warnings.push(format!("Timer resolution did not verify: {}", e));
            }
        }

        if config.mmcss_gaming_profile {
            if let Err(e) = self.apply_mmcss_profile() {
                applied_config.mmcss_gaming_profile = false;
                warnings.push(format!("MMCSS Gaming Profile did not verify: {}", e));
            }
        }

        if config.game_mode_enabled {
            if let Err(e) = self.enable_game_mode() {
                applied_config.game_mode_enabled = false;
                warnings.push(format!("Windows Game Mode did not verify: {}", e));
            }
        }

        SystemApplyOutcome {
            applied_config,
            warnings,
        }
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

            let current_priority = GetPriorityClass(handle);
            if current_priority != 0 && self.original_priority.is_none() {
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

    /// Set CPU affinity for Roblox process
    fn set_cpu_affinity(&mut self, process_id: u32, cores: &[usize]) -> Result<()> {
        info!(
            "Setting CPU affinity for PID: {} to cores: {:?}",
            process_id, cores
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

            // Calculate affinity mask
            let mut affinity_mask: usize = 0;
            for &core in cores {
                affinity_mask |= 1 << core;
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

    /// Disable Windows Game Bar
    fn disable_game_bar(&self) -> Result<()> {
        info!("Disabling Windows Game Bar");

        Self::try_set_registry_dword(GAME_BAR_KEY, GAME_BAR_VALUE, 0)?;
        info!("Game Bar disabled successfully");
        Ok(())
    }

    /// Disable fullscreen optimizations for Roblox
    fn disable_fullscreen_optimizations(&self) -> Result<()> {
        info!("Disabling fullscreen optimizations");

        Self::try_set_registry_dword(FULLSCREEN_KEY, FULLSCREEN_VALUE, 2)?;
        info!("Fullscreen optimizations disabled");
        Ok(())
    }

    /// Set Windows power plan
    fn set_power_plan(&mut self, plan: &PowerPlan) -> Result<()> {
        let guid = Self::power_plan_guid(plan);

        info!("Setting power plan to: {:?}", plan);

        if matches!(plan, PowerPlan::SwiftTunnel) {
            if let Err(e) = self.ensure_swifttunnel_power_plan() {
                return Err(anyhow::anyhow!(
                    "could not prepare SwiftTunnel power plan: {}",
                    e
                ));
            }
        }

        Self::try_set_active_power_plan_guid(guid)?;
        info!("Power plan set successfully");
        Ok(())
    }

    // ===== TIER 1 (SAFE) BOOSTS =====

    /// Set system timer resolution to 0.5ms for smoother frame pacing
    /// Uses NtSetTimerResolution for sub-millisecond precision (5000 = 0.5ms in 100ns units)
    /// Falls back to timeBeginPeriod(1) if NtSetTimerResolution fails
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
                        return Err(anyhow::anyhow!(
                            "NtSetTimerResolution failed with 0x{:08X} and timeBeginPeriod failed with {}",
                            status,
                            result
                        ));
                    }
                }
            }
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
        }
        Ok(())
    }

    /// Apply MMCSS (Multimedia Class Scheduler Service) gaming profile
    /// This boosts priority for game processes via the Windows scheduler
    pub fn apply_mmcss_profile(&mut self) -> Result<()> {
        info!("Applying MMCSS gaming profile");
        let rollback_snapshot = self
            .mmcss_snapshot
            .clone()
            .unwrap_or_else(Self::capture_mmcss_snapshot);

        let mmcss_writes = [
            RegistryWrite::String {
                key_path: MMCSS_GAMES_KEY,
                value_name: "Scheduling Category",
                value: "High",
            },
            RegistryWrite::String {
                key_path: MMCSS_GAMES_KEY,
                value_name: "SFIO Priority",
                value: "High",
            },
            RegistryWrite::String {
                key_path: MMCSS_GAMES_KEY,
                value_name: "Background Only",
                value: "False",
            },
            RegistryWrite::Dword {
                key_path: MMCSS_GAMES_KEY,
                value_name: "Priority",
                value: 6,
            },
            RegistryWrite::Dword {
                key_path: MMCSS_GAMES_KEY,
                value_name: "Clock Rate",
                value: 10000,
            },
            RegistryWrite::Dword {
                key_path: MMCSS_SYSTEM_PROFILE_KEY,
                value_name: "SystemResponsiveness",
                value: 0,
            },
        ];

        Self::apply_registry_writes_with_rollback(
            &mmcss_writes,
            Self::apply_registry_write,
            || Self::restore_mmcss_snapshot(rollback_snapshot.clone()),
        )?;

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
    pub fn enable_game_mode(&mut self) -> Result<()> {
        info!("Enabling Windows Game Mode");
        let rollback_allow_auto = self.game_mode_allow_auto_snapshot.unwrap_or_else(|| {
            Self::query_registry_dword(GAME_MODE_KEY, GAME_MODE_ALLOW_AUTO_VALUE)
        });
        let rollback_enabled = self
            .game_mode_enabled_snapshot
            .unwrap_or_else(|| Self::query_registry_dword(GAME_MODE_KEY, GAME_MODE_ENABLED_VALUE));

        let game_mode_writes = [
            RegistryWrite::Dword {
                key_path: GAME_MODE_KEY,
                value_name: GAME_MODE_ALLOW_AUTO_VALUE,
                value: 1,
            },
            RegistryWrite::Dword {
                key_path: GAME_MODE_KEY,
                value_name: GAME_MODE_ENABLED_VALUE,
                value: 1,
            },
        ];

        Self::apply_registry_writes_with_rollback(
            &game_mode_writes,
            Self::apply_registry_write,
            || {
                Self::restore_registry_dword(
                    GAME_MODE_KEY,
                    GAME_MODE_ENABLED_VALUE,
                    rollback_enabled,
                );
                Self::restore_registry_dword(
                    GAME_MODE_KEY,
                    GAME_MODE_ALLOW_AUTO_VALUE,
                    rollback_allow_auto,
                );
            },
        )?;

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
    fn power_plan_from_guid_maps_known_plan_guids() {
        assert_eq!(
            SystemOptimizer::power_plan_from_guid(BALANCED_POWER_PLAN_GUID),
            Some(PowerPlan::Balanced)
        );
        assert_eq!(
            SystemOptimizer::power_plan_from_guid(HIGH_PERFORMANCE_POWER_PLAN_GUID),
            Some(PowerPlan::HighPerformance)
        );
        assert_eq!(
            SystemOptimizer::power_plan_from_guid(ULTIMATE_POWER_PLAN_GUID),
            Some(PowerPlan::Ultimate)
        );
        assert_eq!(
            SystemOptimizer::power_plan_from_guid(SWIFTTUNNEL_POWER_PLAN_GUID),
            Some(PowerPlan::SwiftTunnel)
        );
    }

    #[test]
    fn power_plan_from_guid_rejects_unknown_or_similar_guid() {
        assert_eq!(
            SystemOptimizer::power_plan_from_guid("44444444-4444-4444-4444-444444444453"),
            None
        );
        assert_eq!(
            SystemOptimizer::power_plan_from_guid("not-a-real-guid"),
            None
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
    fn checked_apply_preserves_process_priority_request_without_pid() {
        let mut optimizer = SystemOptimizer::new();
        let config = SystemOptimizationConfig {
            set_high_priority: true,
            ..Default::default()
        };

        let outcome = optimizer.apply_optimizations_checked(&config, 0);

        assert!(outcome.applied_config.set_high_priority);
        assert!(outcome.warnings.iter().any(|warning| {
            warning.contains("High Priority Mode")
                && warning.contains("waiting for an active Roblox process")
        }));
    }

    #[test]
    fn checked_apply_preserves_cpu_affinity_request_without_pid() {
        let mut optimizer = SystemOptimizer::new();
        let config = SystemOptimizationConfig {
            set_cpu_affinity: true,
            cpu_cores: vec![0, 1],
            ..Default::default()
        };

        let outcome = optimizer.apply_optimizations_checked(&config, 0);

        assert!(outcome.applied_config.set_cpu_affinity);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|warning| warning.contains("CPU affinity")
                    && warning.contains("waiting for an active Roblox process"))
        );
    }

    #[test]
    fn checked_apply_rejects_cpu_affinity_without_selected_cores() {
        let mut optimizer = SystemOptimizer::new();
        let config = SystemOptimizationConfig {
            set_cpu_affinity: true,
            cpu_cores: Vec::new(),
            ..Default::default()
        };

        let outcome = optimizer.apply_optimizations_checked(&config, 1234);

        assert!(!outcome.applied_config.set_cpu_affinity);
        assert!(
            outcome
                .warnings
                .iter()
                .any(|warning| warning.contains("no CPU cores were selected"))
        );
    }

    #[test]
    fn registry_write_plan_rolls_back_after_a_partial_failure() {
        let writes = [
            RegistryWrite::Dword {
                key_path: "HKCU\\Software\\SwiftTunnel",
                value_name: "First",
                value: 1,
            },
            RegistryWrite::Dword {
                key_path: "HKCU\\Software\\SwiftTunnel",
                value_name: "Second",
                value: 1,
            },
            RegistryWrite::Dword {
                key_path: "HKCU\\Software\\SwiftTunnel",
                value_name: "Third",
                value: 1,
            },
        ];
        let mut attempted = Vec::new();
        let mut rolled_back = false;

        let result = SystemOptimizer::apply_registry_writes_with_rollback(
            &writes,
            |write| {
                attempted.push(write);
                if attempted.len() == 2 {
                    Err(anyhow::anyhow!("second write failed"))
                } else {
                    Ok(())
                }
            },
            || {
                rolled_back = true;
            },
        );

        assert!(result.is_err());
        assert_eq!(attempted.as_slice(), &writes[..2]);
        assert!(rolled_back);
    }

    #[test]
    fn registry_write_plan_rolls_back_even_when_first_write_fails() {
        let writes = [RegistryWrite::Dword {
            key_path: "HKCU\\Software\\SwiftTunnel",
            value_name: "First",
            value: 1,
        }];
        let mut rolled_back = false;

        let result = SystemOptimizer::apply_registry_writes_with_rollback(
            &writes,
            |_| Err(anyhow::anyhow!("first write failed")),
            || {
                rolled_back = true;
            },
        );

        assert!(result.is_err());
        assert!(rolled_back);
    }

    #[test]
    fn registry_write_plan_does_not_roll_back_when_all_writes_succeed() {
        let writes = [RegistryWrite::String {
            key_path: "HKCU\\Software\\SwiftTunnel",
            value_name: "Mode",
            value: "Enabled",
        }];
        let mut rolled_back = false;

        let result = SystemOptimizer::apply_registry_writes_with_rollback(
            &writes,
            |_| Ok(()),
            || {
                rolled_back = true;
            },
        );

        assert!(result.is_ok());
        assert!(!rolled_back);
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
}
