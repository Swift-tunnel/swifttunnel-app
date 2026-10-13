use crate::structs::*;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use windows::Win32::Foundation::{CloseHandle, FILETIME, HANDLE};
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

struct StagedPowerPlan(PathBuf);
impl Drop for StagedPowerPlan {
    fn drop(&mut self) {
        if let Err(error) = fs::remove_file(&self.0) {
            warn!("Could not remove this operation's temporary power plan: {error}");
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProcessIdentity {
    pid: u32,
    created: u64,
}

struct BoostProcess(HANDLE);
impl Drop for BoostProcess {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}
impl BoostProcess {
    fn open(pid: u32) -> windows::core::Result<Self> {
        unsafe {
            OpenProcess(
                PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION,
                false,
                pid,
            )
            .map(Self)
        }
    }
    fn identity(&self, pid: u32) -> windows::core::Result<ProcessIdentity> {
        let (mut created, mut exited, mut kernel, mut user) = (
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
        );
        unsafe {
            GetProcessTimes(self.0, &mut created, &mut exited, &mut kernel, &mut user)?;
        }
        Ok(ProcessIdentity {
            pid,
            created: ((created.dwHighDateTime as u64) << 32) | created.dwLowDateTime as u64,
        })
    }
    fn same_live_process(identity: ProcessIdentity) -> Result<Option<Self>> {
        let process = match Self::open(identity.pid) {
            Ok(process) => process,
            // ERROR_INVALID_PARAMETER is the normal OpenProcess result for an exited PID.
            Err(error) if error.code().0 as u32 == 0x80070057 => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if process.identity(identity.pid)? != identity {
            return Ok(None);
        }
        Ok(Some(process))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SwiftTunnelPowerPlanCleanup {
    Noop,
    DeleteInactive,
    ActivateBalancedThenDelete,
    UnknownActivePlan,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct MmcssSnapshot {
    scheduling_category: Option<String>,
    sfio_priority: Option<String>,
    background_only: Option<String>,
    priority: Option<u32>,
    clock_rate: Option<u32>,
    system_responsiveness: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", content = "value", rename_all = "snake_case")]
enum RegistryDwordSnapshot {
    Present(u32),
    Absent,
}

impl RegistryDwordSnapshot {
    fn from_snapshot(snapshot: Option<u32>) -> Self {
        match snapshot {
            Some(value) => Self::Present(value),
            None => Self::Absent,
        }
    }

    fn into_snapshot(self) -> Option<u32> {
        match self {
            Self::Present(value) => Some(value),
            Self::Absent => None,
        }
    }
}

/// On-disk snapshot of persistent system settings SwiftTunnel has changed.
///
/// Priority and affinity belong to the target process's lifetime. Registry
/// settings and the active power plan need durable rollback records.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
struct PersistentSystemSnapshot {
    global_timer_snapshot: Option<RegistryDwordSnapshot>,
    game_bar_snapshot: Option<RegistryDwordSnapshot>,
    fullscreen_optimization_snapshot: Option<RegistryDwordSnapshot>,
    game_mode_allow_auto_snapshot: Option<RegistryDwordSnapshot>,
    game_mode_enabled_snapshot: Option<RegistryDwordSnapshot>,
    mmcss_snapshot: Option<MmcssSnapshot>,
    original_power_plan_guid: Option<String>,
    swifttunnel_power_plan_imported: bool,
}

const SYSTEM_SNAPSHOT_FILE: &str = "system_optimizer_recovery_v2.json";
const LEGACY_SYSTEM_SNAPSHOT_FILE: &str = "system_optimizer_snapshots.json";

fn system_snapshot_path() -> Option<PathBuf> {
    dirs::config_dir().map(|p| p.join("SwiftTunnel").join(SYSTEM_SNAPSHOT_FILE))
}

pub struct SystemOptimizer {
    original_priority: Option<u32>,
    original_affinity: Option<usize>,
    priority_identity: Option<ProcessIdentity>,
    affinity_identity: Option<ProcessIdentity>,
    timer_resolution_active: bool,
    global_timer_snapshot: Option<Option<u32>>,
    original_power_plan_guid: Option<Option<String>>,
    game_bar_snapshot: Option<Option<u32>>,
    fullscreen_optimization_snapshot: Option<Option<u32>>,
    game_mode_allow_auto_snapshot: Option<Option<u32>>,
    game_mode_enabled_snapshot: Option<Option<u32>>,
    mmcss_snapshot: Option<MmcssSnapshot>,
    swifttunnel_power_plan_imported: bool,
    snapshot_path: Option<PathBuf>,
    snapshot_loaded: bool,
    last_persisted_snapshot: Option<PersistentSystemSnapshot>,
}

pub struct SystemApplyOutcome {
    pub applied_config: SystemOptimizationConfig,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SystemBoostToggle {
    HighPriority,
    CpuAffinity,
    GameBar,
    FullscreenOptimization,
    PowerPlan,
    TimerResolution,
    MmcssGamingProfile,
    GameMode,
}

impl SystemOptimizer {
    pub fn new() -> Self {
        Self {
            original_priority: None,
            original_affinity: None,
            priority_identity: None,
            affinity_identity: None,
            timer_resolution_active: false,
            global_timer_snapshot: None,
            original_power_plan_guid: None,
            game_bar_snapshot: None,
            fullscreen_optimization_snapshot: None,
            game_mode_allow_auto_snapshot: None,
            game_mode_enabled_snapshot: None,
            mmcss_snapshot: None,
            swifttunnel_power_plan_imported: false,
            snapshot_path: system_snapshot_path(),
            snapshot_loaded: false,
            last_persisted_snapshot: None,
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

    fn registry_root(path: &str) -> Result<(winreg::RegKey, &str)> {
        use winreg::{
            RegKey,
            enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE},
        };
        if let Some(subkey) = path.strip_prefix("HKCU\\") {
            Ok((RegKey::predef(HKEY_CURRENT_USER), subkey))
        } else if let Some(subkey) = path.strip_prefix("HKLM\\") {
            Ok((RegKey::predef(HKEY_LOCAL_MACHINE), subkey))
        } else {
            Err(anyhow::anyhow!("Unsupported system registry root: {path}"))
        }
    }

    fn optional_registry_read<T>(result: std::io::Result<T>) -> Result<Option<T>> {
        match result {
            Ok(value) => Ok(Some(value)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    pub(crate) fn query_registry_checked<T: winreg::types::FromRegValue>(
        path: &str,
        name: &str,
    ) -> Result<Option<T>> {
        use winreg::enums::{KEY_QUERY_VALUE, KEY_WOW64_64KEY};
        let (root, subkey) = Self::registry_root(path)?;
        match Self::optional_registry_read(
            root.open_subkey_with_flags(subkey, KEY_QUERY_VALUE | KEY_WOW64_64KEY),
        )? {
            Some(key) => crate::registry_value::read(&key, name).map_err(Into::into),
            None => Ok(None),
        }
    }

    fn query_registry_dword(key_path: &str, value_name: &str) -> Option<u32> {
        Self::query_registry_checked(key_path, value_name)
            .ok()
            .flatten()
    }

    fn set_registry_dword_checked(key_path: &str, value_name: &str, value: u32) -> Result<()> {
        use winreg::enums::{KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_WOW64_64KEY};
        let (root, subkey) = Self::registry_root(key_path)?;
        let (key, _) = root
            .create_subkey_with_flags(subkey, KEY_SET_VALUE | KEY_QUERY_VALUE | KEY_WOW64_64KEY)?;
        key.set_value(value_name, &value)?;
        if crate::registry_value::read::<u32>(&key, value_name)? != Some(value) {
            return Err(anyhow::anyhow!(
                "Registry value did not match after writing {key_path}\\{value_name}"
            ));
        }
        Ok(())
    }

    pub(crate) fn set_registry_string_checked(
        key_path: &str,
        value_name: &str,
        value: &str,
    ) -> Result<()> {
        if (value.encode_utf16().count() + 1) * 2 > crate::registry_value::MAX_VALUE_BYTES {
            return Err(anyhow::anyhow!(
                "Registry string exceeds the 64 KiB write limit"
            ));
        }
        use winreg::enums::{KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_WOW64_64KEY};
        let (root, subkey) = Self::registry_root(key_path)?;
        let (key, _) = root
            .create_subkey_with_flags(subkey, KEY_SET_VALUE | KEY_QUERY_VALUE | KEY_WOW64_64KEY)?;
        key.set_value(value_name, &value)?;
        if crate::registry_value::read::<String>(&key, value_name)?.as_deref() != Some(value) {
            return Err(anyhow::anyhow!(
                "Registry value did not match after writing {key_path}\\{value_name}"
            ));
        }
        Ok(())
    }

    fn restore_registry_dword_checked(
        key_path: &str,
        value_name: &str,
        snapshot: Option<u32>,
    ) -> Result<()> {
        match snapshot {
            Some(value) => Self::set_registry_dword_checked(key_path, value_name, value),
            None => Self::delete_registry_value_checked(key_path, value_name),
        }
    }

    fn restore_registry_string_checked(
        key_path: &str,
        value_name: &str,
        snapshot: Option<&str>,
    ) -> Result<()> {
        match snapshot {
            Some(value) => Self::set_registry_string_checked(key_path, value_name, value),
            None => Self::delete_registry_value_checked(key_path, value_name),
        }
    }

    pub(crate) fn delete_registry_value_checked(key_path: &str, value_name: &str) -> Result<()> {
        use winreg::enums::{KEY_QUERY_VALUE, KEY_SET_VALUE, KEY_WOW64_64KEY};
        let (root, subkey) = Self::registry_root(key_path)?;
        let Some(key) = Self::optional_registry_read(
            root.open_subkey_with_flags(subkey, KEY_SET_VALUE | KEY_QUERY_VALUE | KEY_WOW64_64KEY),
        )?
        else {
            return Ok(());
        };
        match key.delete_value(value_name) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
        }
        if crate::registry_value::exists(&key, value_name)? {
            return Err(anyhow::anyhow!(
                "Registry value still exists after removing {key_path}\\{value_name}"
            ));
        }
        Ok(())
    }

    fn capture_dword_snapshot(
        slot: &mut Option<Option<u32>>,
        key_path: &str,
        value_name: &str,
    ) -> Result<()> {
        if slot.is_none() {
            *slot = Some(Self::query_registry_checked(key_path, value_name)?);
        }
        Ok(())
    }

    fn read_persistent_snapshot(path: &Path) -> Result<Option<PersistentSystemSnapshot>> {
        let content = match crate::utils::read_text_file_bounded(
            path,
            256 * 1024,
            "System optimizer recovery",
        ) {
            Ok(content) => content,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        serde_json::from_str(&content).map(Some).map_err(Into::into)
    }

    fn ensure_snapshot_loaded(&mut self) -> Result<()> {
        if self.snapshot_loaded {
            return Ok(());
        }
        let path = self
            .snapshot_path
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No system recovery folder is available"))?;
        let legacy = path.with_file_name(LEGACY_SYSTEM_SNAPSHOT_FILE);
        let current = Self::read_persistent_snapshot(path)?;
        let migrating = current.is_none();
        let saved = if migrating {
            Self::read_persistent_snapshot(&legacy)?
        } else {
            current
        };
        if let Some(saved) = saved {
            self.global_timer_snapshot = saved
                .global_timer_snapshot
                .map(RegistryDwordSnapshot::into_snapshot);
            self.game_bar_snapshot = saved
                .game_bar_snapshot
                .map(RegistryDwordSnapshot::into_snapshot);
            self.fullscreen_optimization_snapshot = saved
                .fullscreen_optimization_snapshot
                .map(RegistryDwordSnapshot::into_snapshot);
            self.game_mode_allow_auto_snapshot = saved
                .game_mode_allow_auto_snapshot
                .map(RegistryDwordSnapshot::into_snapshot);
            self.game_mode_enabled_snapshot = saved
                .game_mode_enabled_snapshot
                .map(RegistryDwordSnapshot::into_snapshot);
            self.mmcss_snapshot = saved.mmcss_snapshot.clone();
            self.original_power_plan_guid = saved.original_power_plan_guid.clone().map(Some);
            self.swifttunnel_power_plan_imported = saved.swifttunnel_power_plan_imported;
            self.last_persisted_snapshot = if migrating { None } else { Some(saved) };
            if migrating {
                // Write the expanded record before removing the old timer-only
                // file, which an older app would otherwise clear unconditionally.
                self.persist_snapshot()?;
                if let Err(error) = fs::remove_file(&legacy) {
                    warn!(
                        "New system recovery record is saved, but the legacy record could not be removed: {error}"
                    );
                }
            }
        }
        self.snapshot_loaded = true;
        Ok(())
    }

    fn persistent_snapshot(&self) -> PersistentSystemSnapshot {
        PersistentSystemSnapshot {
            global_timer_snapshot: self
                .global_timer_snapshot
                .map(RegistryDwordSnapshot::from_snapshot),
            game_bar_snapshot: self
                .game_bar_snapshot
                .map(RegistryDwordSnapshot::from_snapshot),
            fullscreen_optimization_snapshot: self
                .fullscreen_optimization_snapshot
                .map(RegistryDwordSnapshot::from_snapshot),
            game_mode_allow_auto_snapshot: self
                .game_mode_allow_auto_snapshot
                .map(RegistryDwordSnapshot::from_snapshot),
            game_mode_enabled_snapshot: self
                .game_mode_enabled_snapshot
                .map(RegistryDwordSnapshot::from_snapshot),
            mmcss_snapshot: self.mmcss_snapshot.clone(),
            original_power_plan_guid: self.original_power_plan_guid.clone().flatten(),
            swifttunnel_power_plan_imported: self.swifttunnel_power_plan_imported,
        }
    }

    fn write_persistent_snapshot(path: &Path, snapshot: &PersistentSystemSnapshot) -> Result<()> {
        use std::io::Write;
        fs::create_dir_all(
            path.parent()
                .ok_or_else(|| anyhow::anyhow!("Invalid system recovery path"))?,
        )?;
        let bytes = serde_json::to_vec_pretty(snapshot)?;
        let temp = path.with_extension(format!(
            "{}.{:032x}.tmp",
            std::process::id(),
            rand::random::<u128>()
        ));
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp)?;
        let result = (|| {
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temp, path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result.map_err(Into::into)
    }

    fn persist_snapshot(&mut self) -> Result<()> {
        let snapshot = self.persistent_snapshot();
        if self.last_persisted_snapshot.as_ref() == Some(&snapshot) {
            return Ok(());
        }
        let path = self
            .snapshot_path
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No system recovery folder is available"))?;
        if snapshot == PersistentSystemSnapshot::default() {
            match fs::remove_file(path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        } else {
            Self::write_persistent_snapshot(path, &snapshot)?;
        }
        self.last_persisted_snapshot = Some(snapshot);
        Ok(())
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
        let output = crate::utils::run_hidden_command_output_with_timeout(
            "powercfg",
            &["/GETACTIVESCHEME"],
            std::time::Duration::from_secs(15),
        )
        .ok()?;

        if !output.status.success() {
            return None;
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        Self::parse_guid_from_output(&output_str)
    }

    fn is_power_plan_installed(guid: &str) -> Option<bool> {
        let output = crate::utils::run_hidden_command_output_with_timeout(
            "powercfg",
            &["/list"],
            std::time::Duration::from_secs(15),
        )
        .ok()?;

        if !output.status.success() {
            return None;
        }

        let output_str = String::from_utf8_lossy(&output.stdout);
        Some(Self::output_contains_guid(&output_str, guid))
    }

    fn set_active_power_plan_guid(guid: &str) -> bool {
        let output = crate::utils::run_hidden_command_output_with_timeout(
            "powercfg",
            &["/setactive", guid],
            std::time::Duration::from_secs(15),
        );

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
        let output = crate::utils::run_hidden_command_output_with_timeout(
            "powercfg",
            &["/delete", guid],
            std::time::Duration::from_secs(15),
        );

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
                    if self.snapshot_loaded {
                        self.persist_snapshot()?;
                    }
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
                    if self.snapshot_loaded {
                        self.persist_snapshot()?;
                    }
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

    fn stage_swifttunnel_power_plan(dir: &Path) -> Result<StagedPowerPlan> {
        use std::io::Write;
        let path = dir.join(format!(
            "swifttunnel_power_plan-{}-{:032x}.pow",
            std::process::id(),
            rand::random::<u128>()
        ));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        let staged = StagedPowerPlan(path);
        file.write_all(SWIFTTUNNEL_POWER_PLAN_BYTES)?;
        file.sync_all()?;
        Ok(staged)
    }

    fn import_swifttunnel_power_plan(&mut self) -> Result<()> {
        let staged = Self::stage_swifttunnel_power_plan(&std::env::temp_dir())?;
        let staged_path = &staged.0;

        let path_arg = staged_path.to_string_lossy().to_string();
        let output = crate::utils::run_hidden_command_output_with_timeout(
            "powercfg",
            &["/import", &path_arg, SWIFTTUNNEL_POWER_PLAN_GUID],
            std::time::Duration::from_secs(15),
        );

        let import_result = match output {
            Ok(result) if result.status.success() => {
                let _ = crate::utils::run_hidden_command_output_with_timeout(
                    "powercfg",
                    &[
                        "/changename",
                        SWIFTTUNNEL_POWER_PLAN_GUID,
                        SWIFTTUNNEL_POWER_PLAN_NAME,
                        SWIFTTUNNEL_POWER_PLAN_DESCRIPTION,
                    ],
                    std::time::Duration::from_secs(15),
                );
                self.swifttunnel_power_plan_imported = true;
                self.persist_snapshot()?;
                info!("SwiftTunnel power plan imported successfully");
                Ok(())
            }
            Ok(result) => {
                let stderr = String::from_utf8_lossy(&result.stderr);
                let stdout = String::from_utf8_lossy(&result.stdout);
                // The SwiftTunnel plan has a fixed GUID, so "a power scheme with
                // the specified GUID already exists" just means a previous apply
                // (or an earlier app session — the in-memory `imported` flag
                // resets on restart while the Windows plan persists) already
                // installed it. That's success, not a failure.
                if format!("{stderr}\n{stdout}")
                    .to_lowercase()
                    .contains("already exists")
                {
                    self.swifttunnel_power_plan_imported = true;
                    self.persist_snapshot()?;
                    info!("SwiftTunnel power plan already present; using existing scheme");
                    Ok(())
                } else {
                    Err(anyhow::anyhow!(
                        "powercfg /import failed for SwiftTunnel power plan: {}",
                        stderr.trim()
                    ))
                }
            }
            Err(e) => Err(anyhow::anyhow!(
                "Failed to run powercfg /import for SwiftTunnel power plan: {}",
                e
            )),
        };

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

    fn fallback_power_plan_config(config: &SystemOptimizationConfig) -> PowerPlan {
        Self::active_power_plan_guid()
            .as_deref()
            .and_then(Self::power_plan_from_guid)
            .or(config.previous_power_plan)
            .unwrap_or(PowerPlan::Balanced)
    }

    fn mark_failed_boost(
        applied_config: &mut SystemOptimizationConfig,
        toggle: SystemBoostToggle,
        fallback_power_plan: PowerPlan,
    ) {
        match toggle {
            SystemBoostToggle::HighPriority => applied_config.set_high_priority = false,
            SystemBoostToggle::CpuAffinity => applied_config.set_cpu_affinity = false,
            SystemBoostToggle::GameBar => applied_config.disable_game_bar = false,
            SystemBoostToggle::FullscreenOptimization => {
                applied_config.disable_fullscreen_optimization = false;
            }
            SystemBoostToggle::PowerPlan => applied_config.power_plan = fallback_power_plan,
            SystemBoostToggle::TimerResolution => applied_config.timer_resolution_1ms = false,
            SystemBoostToggle::MmcssGamingProfile => applied_config.mmcss_gaming_profile = false,
            SystemBoostToggle::GameMode => applied_config.game_mode_enabled = false,
        }
    }

    fn record_failure(
        applied_config: &mut SystemOptimizationConfig,
        warnings: &mut Vec<String>,
        toggle: SystemBoostToggle,
        label: &str,
        error: impl std::fmt::Display,
        fallback_power_plan: PowerPlan,
    ) {
        Self::mark_failed_boost(applied_config, toggle, fallback_power_plan);
        warnings.push(format!("{}: {}", label, error));
    }

    fn capture_system_state_snapshots(&mut self, config: &SystemOptimizationConfig) -> Result<()> {
        self.ensure_snapshot_loaded()?;
        if config.disable_game_bar {
            Self::capture_dword_snapshot(
                &mut self.game_bar_snapshot,
                GAME_BAR_KEY,
                GAME_BAR_VALUE,
            )?;
        }
        if config.disable_fullscreen_optimization {
            Self::capture_dword_snapshot(
                &mut self.fullscreen_optimization_snapshot,
                FULLSCREEN_KEY,
                FULLSCREEN_VALUE,
            )?;
        }
        if config.game_mode_enabled {
            Self::capture_dword_snapshot(
                &mut self.game_mode_allow_auto_snapshot,
                GAME_MODE_KEY,
                GAME_MODE_ALLOW_AUTO_VALUE,
            )?;
            Self::capture_dword_snapshot(
                &mut self.game_mode_enabled_snapshot,
                GAME_MODE_KEY,
                GAME_MODE_ENABLED_VALUE,
            )?;
        }
        if config.mmcss_gaming_profile && self.mmcss_snapshot.is_none() {
            self.mmcss_snapshot = Some(MmcssSnapshot {
                scheduling_category: Self::query_registry_checked(
                    MMCSS_GAMES_KEY,
                    "Scheduling Category",
                )?,
                sfio_priority: Self::query_registry_checked(MMCSS_GAMES_KEY, "SFIO Priority")?,
                background_only: Self::query_registry_checked(MMCSS_GAMES_KEY, "Background Only")?,
                priority: Self::query_registry_checked(MMCSS_GAMES_KEY, "Priority")?,
                clock_rate: Self::query_registry_checked(MMCSS_GAMES_KEY, "Clock Rate")?,
                system_responsiveness: Self::query_registry_checked(
                    MMCSS_SYSTEM_PROFILE_KEY,
                    "SystemResponsiveness",
                )?,
            });
        }
        // Even Balanced changes the active plan. Capture it before any switch.
        if self.original_power_plan_guid.is_none() {
            self.original_power_plan_guid =
                Some(Some(Self::active_power_plan_guid().ok_or_else(|| {
                    anyhow::anyhow!(
                        "Could not read the current power plan; system changes were skipped"
                    )
                })?));
        }
        self.persist_snapshot()
    }

    fn restore_mmcss_snapshot(snapshot: &MmcssSnapshot) -> Result<()> {
        let mut failures = Vec::new();
        for (name, value) in [
            (
                "Scheduling Category",
                snapshot.scheduling_category.as_deref(),
            ),
            ("SFIO Priority", snapshot.sfio_priority.as_deref()),
            ("Background Only", snapshot.background_only.as_deref()),
        ] {
            if let Err(error) = Self::restore_registry_string_checked(MMCSS_GAMES_KEY, name, value)
            {
                failures.push(error.to_string());
            }
        }
        for (path, name, value) in [
            (MMCSS_GAMES_KEY, "Priority", snapshot.priority),
            (MMCSS_GAMES_KEY, "Clock Rate", snapshot.clock_rate),
            (
                MMCSS_SYSTEM_PROFILE_KEY,
                "SystemResponsiveness",
                snapshot.system_responsiveness,
            ),
        ] {
            if let Err(error) = Self::restore_registry_dword_checked(path, name, value) {
                failures.push(error.to_string());
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "MMCSS restore failed: {}",
                failures.join("; ")
            ))
        }
    }

    fn restore_dword_slot(slot: &mut Option<Option<u32>>, path: &str, name: &str) -> Result<()> {
        if let Some(value) = *slot {
            Self::restore_registry_dword_checked(path, name, value)?;
            *slot = None;
        }
        Ok(())
    }

    /// Apply system optimizations and return the config that actually applied.
    ///
    /// Retryable process-local states such as "Roblox is not running yet" keep
    /// the requested toggle enabled so a later runtime monitor can apply it.
    /// Hard backing failures clear the affected toggle before the config is
    /// persisted.
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
        let fallback_power_plan = Self::fallback_power_plan_config(config);

        if let Err(error) = self.capture_system_state_snapshots(config) {
            applied_config.set_high_priority = false;
            applied_config.set_cpu_affinity = false;
            applied_config.disable_game_bar = false;
            applied_config.disable_fullscreen_optimization = false;
            applied_config.timer_resolution_1ms = false;
            applied_config.mmcss_gaming_profile = false;
            applied_config.game_mode_enabled = false;
            applied_config.power_plan = fallback_power_plan;
            return SystemApplyOutcome {
                applied_config,
                warnings: vec![format!(
                    "System changes skipped because recovery data could not be prepared: {error}"
                )],
            };
        }

        if config.set_high_priority {
            if process_id == 0 {
                info!("Skipping process priority boost: no active game process detected yet");
            } else if let Err(e) = self.set_process_priority(process_id) {
                Self::record_failure(
                    &mut applied_config,
                    &mut warnings,
                    SystemBoostToggle::HighPriority,
                    "Set process priority",
                    e,
                    fallback_power_plan,
                );
            }
        }

        if config.set_cpu_affinity {
            if config.cpu_cores.is_empty() {
                Self::record_failure(
                    &mut applied_config,
                    &mut warnings,
                    SystemBoostToggle::CpuAffinity,
                    "Set CPU affinity",
                    "no CPU cores selected",
                    fallback_power_plan,
                );
            } else if let Err(e) = Self::validate_cpu_cores(&config.cpu_cores) {
                Self::record_failure(
                    &mut applied_config,
                    &mut warnings,
                    SystemBoostToggle::CpuAffinity,
                    "Set CPU affinity",
                    e,
                    fallback_power_plan,
                );
            } else if process_id == 0 {
                info!("Skipping CPU affinity boost: no active game process detected yet");
            } else if let Err(e) = self.set_cpu_affinity(process_id, &config.cpu_cores) {
                Self::record_failure(
                    &mut applied_config,
                    &mut warnings,
                    SystemBoostToggle::CpuAffinity,
                    "Set CPU affinity",
                    e,
                    fallback_power_plan,
                );
            }
        }

        if config.disable_game_bar
            && let Err(e) = self.disable_game_bar()
        {
            Self::record_failure(
                &mut applied_config,
                &mut warnings,
                SystemBoostToggle::GameBar,
                "Disable Game Bar",
                e,
                fallback_power_plan,
            );
        }

        if config.disable_fullscreen_optimization
            && let Err(e) = self.disable_fullscreen_optimizations()
        {
            Self::record_failure(
                &mut applied_config,
                &mut warnings,
                SystemBoostToggle::FullscreenOptimization,
                "Disable fullscreen optimizations",
                e,
                fallback_power_plan,
            );
        }

        if let Err(e) = self.set_power_plan(&config.power_plan) {
            Self::record_failure(
                &mut applied_config,
                &mut warnings,
                SystemBoostToggle::PowerPlan,
                "Set power plan",
                e,
                fallback_power_plan,
            );
        }

        // Tier 1 (Safe) Boosts
        if config.timer_resolution_1ms
            && let Err(e) = self.set_timer_resolution(true)
        {
            Self::record_failure(
                &mut applied_config,
                &mut warnings,
                SystemBoostToggle::TimerResolution,
                "Set timer resolution",
                e,
                fallback_power_plan,
            );
        }

        if config.mmcss_gaming_profile
            && let Err(e) = self.apply_mmcss_profile()
        {
            Self::record_failure(
                &mut applied_config,
                &mut warnings,
                SystemBoostToggle::MmcssGamingProfile,
                "Apply MMCSS gaming profile",
                e,
                fallback_power_plan,
            );
        }

        if config.game_mode_enabled
            && let Err(e) = self.enable_game_mode()
        {
            Self::record_failure(
                &mut applied_config,
                &mut warnings,
                SystemBoostToggle::GameMode,
                "Enable Game Mode",
                e,
                fallback_power_plan,
            );
        }

        SystemApplyOutcome {
            applied_config,
            warnings,
        }
    }

    /// Preserve one original per process lifetime, including PID reuse.
    fn set_process_priority(&mut self, pid: u32) -> Result<()> {
        let process = BoostProcess::open(pid)?;
        let identity = process.identity(pid)?;
        if self.priority_identity != Some(identity) {
            self.original_priority = None;
            self.priority_identity = Some(identity);
        }
        let current = unsafe { GetPriorityClass(process.0) };
        if current == 0 {
            return Err(anyhow::anyhow!(
                "Could not read the process's original priority; priority was left unchanged"
            ));
        }
        if self.original_priority.is_none() {
            self.original_priority = Some(current);
        }
        unsafe {
            SetPriorityClass(process.0, HIGH_PRIORITY_CLASS)?;
        }
        Ok(())
    }

    fn restore_process_priority(&mut self) -> Result<()> {
        if let Some((identity, value)) = self.priority_identity.zip(self.original_priority)
            && let Some(process) = BoostProcess::same_live_process(identity)?
        {
            unsafe {
                SetPriorityClass(process.0, PROCESS_CREATION_FLAGS(value))?;
            }
        }
        self.original_priority = None;
        self.priority_identity = None;
        Ok(())
    }

    fn set_cpu_affinity(&mut self, pid: u32, cores: &[usize]) -> Result<()> {
        let mask = Self::validate_cpu_cores(cores)?;
        let process = BoostProcess::open(pid)?;
        let identity = process.identity(pid)?;
        if self.affinity_identity != Some(identity) {
            self.original_affinity = None;
            self.affinity_identity = Some(identity);
        }
        if self.original_affinity.is_none() {
            let (mut original, mut system) = (0, 0);
            unsafe {
                GetProcessAffinityMask(process.0, &mut original, &mut system)?;
            }
            if original == 0 {
                return Err(anyhow::anyhow!(
                    "Could not read the original CPU affinity; affinity was left unchanged"
                ));
            }
            self.original_affinity = Some(original);
        }
        unsafe {
            SetProcessAffinityMask(process.0, mask)?;
        }
        Ok(())
    }

    fn restore_cpu_affinity(&mut self, _current_pid: u32) -> Result<()> {
        if let Some((identity, value)) = self.affinity_identity.zip(self.original_affinity)
            && let Some(process) = BoostProcess::same_live_process(identity)?
        {
            unsafe {
                SetProcessAffinityMask(process.0, value)?;
            }
        }
        self.original_affinity = None;
        self.affinity_identity = None;
        Ok(())
    }

    /// Disable Windows Game Bar
    fn disable_game_bar(&self) -> Result<()> {
        Self::set_registry_dword_checked(GAME_BAR_KEY, GAME_BAR_VALUE, 0)
    }

    /// Disable fullscreen optimizations for Roblox
    fn disable_fullscreen_optimizations(&self) -> Result<()> {
        Self::set_registry_dword_checked(FULLSCREEN_KEY, FULLSCREEN_VALUE, 2)
    }

    /// Set Windows power plan. Returns Err on import or activation failure
    /// so the caller can surface the failure to the user instead of falsely
    /// reporting "boost applied".
    fn set_power_plan(&mut self, plan: &PowerPlan) -> Result<()> {
        let guid = Self::power_plan_guid(plan);

        info!("Setting power plan to: {:?}", plan);

        if matches!(plan, PowerPlan::SwiftTunnel)
            && let Err(e) = self.ensure_swifttunnel_power_plan()
        {
            return Err(anyhow::anyhow!(
                "SwiftTunnel power plan import failed: {}",
                e
            ));
        }

        let output = crate::utils::run_hidden_command_output_with_timeout(
            "powercfg",
            &["/setactive", guid],
            std::time::Duration::from_secs(15),
        );

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
            let mut timer_applied = false;
            unsafe {
                // Try NtSetTimerResolution for 0.5ms (5000 * 100ns = 0.5ms)
                let mut current: u32 = 0;
                let status = NtSetTimerResolution(5000, 1, &mut current);
                if status == 0 {
                    // STATUS_SUCCESS
                    self.timer_resolution_active = true;
                    timer_applied = true;
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
                        timer_applied = true;
                        info!("Timer resolution set to 1ms via timeBeginPeriod (fallback)");
                    } else {
                        warn!("Failed to set timer resolution: error code {}", result);
                    }
                }
            }

            if !timer_applied {
                return Err(anyhow::anyhow!(
                    "NtSetTimerResolution and timeBeginPeriod both failed"
                ));
            }

            // Make sure the system-wide override is on so the per-process
            // resolution we just set is honored for other processes too on
            // Win11 22H2+. Snapshot the prior value so restore() can revert.
            if let Err(e) = self.enable_global_timer_resolution_override() {
                self.clear_timer_resolution_request();
                let _ = self.restore_global_timer_resolution_override();
                return Err(e);
            }
        } else if !enable && self.timer_resolution_active {
            info!("Restoring default timer resolution");
            self.clear_timer_resolution_request();
            self.restore_global_timer_resolution_override()?;
        }
        Ok(())
    }

    fn clear_timer_resolution_request(&mut self) {
        if !self.timer_resolution_active {
            return;
        }

        unsafe {
            // Undo NtSetTimerResolution
            let mut current: u32 = 0;
            let _ = NtSetTimerResolution(5000, 0, &mut current);
            // Also undo timeBeginPeriod in case fallback was used
            let _ = timeEndPeriod(1);
            self.timer_resolution_active = false;
        }
    }

    fn enable_global_timer_resolution_override(&mut self) -> Result<()> {
        self.ensure_snapshot_loaded()?;
        Self::capture_dword_snapshot(
            &mut self.global_timer_snapshot,
            GLOBAL_TIMER_RESOLUTION_KEY,
            GLOBAL_TIMER_RESOLUTION_VALUE,
        )?;
        self.persist_snapshot()?;

        // Skip the write if it's already 1 — avoids an unnecessary reg call
        // and prevents spurious "needs reboot" telemetry on repeat applies.
        if Self::query_registry_dword(GLOBAL_TIMER_RESOLUTION_KEY, GLOBAL_TIMER_RESOLUTION_VALUE)
            == Some(1)
        {
            return Ok(());
        }

        Self::set_registry_dword_checked(
            GLOBAL_TIMER_RESOLUTION_KEY,
            GLOBAL_TIMER_RESOLUTION_VALUE,
            1,
        )?;

        // Verify via readback before claiming success. A non-admin session can
        // reject the HKLM write; persisting the toggle anyway would leave users
        // chasing a phantom reboot prompt.
        match Self::query_registry_dword(GLOBAL_TIMER_RESOLUTION_KEY, GLOBAL_TIMER_RESOLUTION_VALUE)
        {
            Some(1) => {
                info!(
                    "Wrote {}\\{}=1; reboot required for the global override to take effect on Windows 11 22H2+",
                    GLOBAL_TIMER_RESOLUTION_KEY, GLOBAL_TIMER_RESOLUTION_VALUE
                );
                Ok(())
            }
            other => Err(anyhow::anyhow!(
                "GlobalTimerResolutionRequests write was not visible after apply (read back {:?}); admin rights may be required for HKLM\\…\\kernel",
                other
            )),
        }
    }

    fn restore_global_timer_resolution_override(&mut self) -> Result<()> {
        if let Some(snapshot) = self.global_timer_snapshot.take() {
            if let Err(e) = Self::restore_registry_dword_checked(
                GLOBAL_TIMER_RESOLUTION_KEY,
                GLOBAL_TIMER_RESOLUTION_VALUE,
                snapshot,
            ) {
                self.global_timer_snapshot = Some(snapshot);
                let _ = self.persist_snapshot();
                return Err(e);
            }
            self.persist_snapshot()?;
        }
        Ok(())
    }

    /// Recover persistent system optimizer changes after a forced app exit.
    pub fn recover_from_snapshot(&mut self) {
        if let Err(error) = self.ensure_snapshot_loaded() {
            warn!("System recovery data could not be read; original file kept: {error}");
            return;
        }
        if self.persistent_snapshot() == PersistentSystemSnapshot::default() {
            return;
        }
        if let Err(error) = self.restore(0) {
            warn!("System recovery has pending changes: {error}");
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
            Self::set_registry_string_checked(key_path, value_name, value_data)?;
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
                Self::set_registry_dword_checked(key_path, value_name, value)?;
            }
        }

        info!("MMCSS gaming profile applied");
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
                Self::set_registry_dword_checked(key_path, value_name, value)?;
            }
        }

        info!("Windows Game Mode enabled");
        Ok(())
    }

    // ===== SYSTEM RESTORE POINT =====

    /// Create a Windows System Restore Point before applying optimizations
    /// Returns the description of the restore point if successful
    pub fn create_restore_point(description: &str) -> Result<String> {
        info!("Creating System Restore Point: {}", description);

        // Enable System Restore on C: drive first (in case it's disabled)
        let enable_output = crate::utils::run_hidden_command_output_with_timeout(
            "powershell",
            &[
                "-Command",
                "Enable-ComputerRestore -Drive 'C:\\' -ErrorAction SilentlyContinue",
            ],
            std::time::Duration::from_secs(30),
        );

        if let Err(e) = enable_output {
            warn!("Failed to enable System Restore: {}", e);
            // Continue anyway, it might already be enabled
        }

        // Create the restore point
        let ps_command = format!(
            "Checkpoint-Computer -Description '{}' -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop",
            description.replace('\'', "''") // Escape single quotes
        );

        // Restore points go through VSS, which is one of the more reliable
        // ways to hang a Windows box. Two minutes is generous for a snapshot
        // and still returns control if the writer is stuck.
        let output = crate::run_hidden_command_with_timeout(
            "powershell",
            &["-Command", &ps_command],
            std::time::Duration::from_secs(120),
        );

        if output.timed_out {
            warn!("Restore point creation exceeded its deadline and was stopped");
            return Err(anyhow::anyhow!(
                "Windows did not finish creating a restore point in time"
            ));
        }

        {
            {
                if output.success {
                    info!("System Restore Point created successfully");
                    Ok(description.to_string())
                } else {
                    let stderr = output.stderr.trim();
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
        self.ensure_snapshot_loaded()?;
        let mut restore_errors = Vec::new();

        // Restore timer resolution if active
        if self.timer_resolution_active
            && let Err(e) = self.set_timer_resolution(false)
        {
            restore_errors.push(format!("timer resolution: {}", e));
        }
        // Safety net: clean up the global timer override snapshot even if
        // `timer_resolution_active` was already false (e.g., crash recovery).
        if let Err(e) = self.restore_global_timer_resolution_override() {
            restore_errors.push(format!("global timer override: {}", e));
        }

        if let Err(error) = self.restore_process_priority() {
            restore_errors.push(format!("Process priority: {error}"));
        }
        if let Err(error) = self.restore_cpu_affinity(process_id) {
            restore_errors.push(format!("CPU affinity: {error}"));
        }

        if let Some(snapshot) = self.mmcss_snapshot.clone() {
            match Self::restore_mmcss_snapshot(&snapshot) {
                Ok(()) => self.mmcss_snapshot = None,
                Err(error) => restore_errors.push(error.to_string()),
            }
        }
        for result in [
            Self::restore_dword_slot(
                &mut self.game_mode_enabled_snapshot,
                GAME_MODE_KEY,
                GAME_MODE_ENABLED_VALUE,
            ),
            Self::restore_dword_slot(
                &mut self.game_mode_allow_auto_snapshot,
                GAME_MODE_KEY,
                GAME_MODE_ALLOW_AUTO_VALUE,
            ),
            Self::restore_dword_slot(
                &mut self.fullscreen_optimization_snapshot,
                FULLSCREEN_KEY,
                FULLSCREEN_VALUE,
            ),
            Self::restore_dword_slot(&mut self.game_bar_snapshot, GAME_BAR_KEY, GAME_BAR_VALUE),
        ] {
            if let Err(error) = result {
                restore_errors.push(error.to_string());
            }
        }

        let mut original_power_plan_restored = false;
        if let Some(Some(guid)) = self.original_power_plan_guid.clone() {
            original_power_plan_restored = Self::set_active_power_plan_guid(&guid);
            if original_power_plan_restored {
                self.original_power_plan_guid = None;
            } else {
                restore_errors.push(format!("Could not restore the original power plan {guid}"));
            }
        }

        if self.swifttunnel_power_plan_imported
            && Self::is_power_plan_installed(SWIFTTUNNEL_POWER_PLAN_GUID) == Some(false)
        {
            self.swifttunnel_power_plan_imported = false;
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
                if Self::is_power_plan_installed(SWIFTTUNNEL_POWER_PLAN_GUID) == Some(false)
                    || Self::delete_power_plan_guid(SWIFTTUNNEL_POWER_PLAN_GUID)
                {
                    self.swifttunnel_power_plan_imported = false;
                } else {
                    restore_errors
                        .push("Could not remove the imported SwiftTunnel power plan".into());
                }
            } else {
                restore_errors.push("No safe replacement power plan could be activated".into());
                warn!(
                    "Skipping SwiftTunnel power plan deletion because no safe replacement plan could be activated"
                );
            }
        }

        if let Err(error) = self.persist_snapshot() {
            restore_errors.push(format!("Recovery records could not be updated: {error}"));
        }
        if restore_errors.is_empty() {
            Ok(())
        } else {
            Err(anyhow::anyhow!(
                "some system optimizer restore operations failed: {}",
                restore_errors.join("; ")
            ))
        }
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
    let mut optimizer = SystemOptimizer::new();
    if let Err(error) = optimizer.ensure_snapshot_loaded() {
        warn!(
            "System rollback records could not be read during uninstall; originals were kept: {error}"
        );
        return;
    }
    if optimizer.persistent_snapshot() != PersistentSystemSnapshot::default() {
        if let Err(error) = optimizer.restore(0) {
            warn!("Some system settings could not be restored during uninstall: {error}");
        }
    }
    // Older builds did not save these originals. Do not guess at Windows
    // defaults and overwrite settings another tool or the player chose.
    if let Err(error) = optimizer.cleanup_swifttunnel_power_plan_after_ban() {
        warn!("Could not remove the SwiftTunnel power plan during uninstall: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn repeated_priority_apply_keeps_the_first_original_priority() {
        use std::os::windows::process::CommandExt;
        struct TestChild(std::process::Child);
        impl Drop for TestChild {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let child = TestChild(
            crate::hidden_command("powershell")
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Start-Sleep -Seconds 20",
                ])
                .creation_flags(crate::utils::CREATE_NO_WINDOW | NORMAL_PRIORITY_CLASS.0)
                .spawn()
                .unwrap(),
        );
        let mut optimizer = SystemOptimizer::new();
        optimizer.set_process_priority(child.0.id()).unwrap();
        optimizer.set_process_priority(child.0.id()).unwrap();
        assert_eq!(optimizer.original_priority, Some(NORMAL_PRIORITY_CLASS.0));
        optimizer.restore_process_priority().unwrap();
        let process = BoostProcess::open(child.0.id()).unwrap();
        assert_eq!(
            unsafe { GetPriorityClass(process.0) },
            NORMAL_PRIORITY_CLASS.0
        );
        optimizer.set_process_priority(child.0.id()).unwrap();
        // Simulate a reused PID: an original from a different creation time
        // must never be applied to the current process.
        optimizer.priority_identity.as_mut().unwrap().created ^= 1;
        optimizer.restore_process_priority().unwrap();
        assert_eq!(
            unsafe { GetPriorityClass(process.0) },
            HIGH_PRIORITY_CLASS.0
        );
        assert!(optimizer.original_priority.is_none());
        let (mut mask, mut system_mask) = (0, 0);
        unsafe { GetProcessAffinityMask(process.0, &mut mask, &mut system_mask).unwrap() };
        optimizer.affinity_identity = Some(process.identity(child.0.id()).unwrap());
        optimizer.original_affinity = Some(mask);
        // Restoration uses the recorded process, not this unrelated PID.
        optimizer.restore_cpu_affinity(u32::MAX).unwrap();
        assert!(optimizer.affinity_identity.is_none());
        optimizer.affinity_identity = Some(ProcessIdentity {
            created: process.identity(child.0.id()).unwrap().created ^ 1,
            pid: child.0.id(),
        });
        optimizer.original_affinity = Some(0); // Would fail if the wrong process were touched.
        optimizer.restore_cpu_affinity(child.0.id()).unwrap();
        assert!(optimizer.original_affinity.is_none());
        // Only this short-lived child was modified; no Roblox/user process is opened.
    }

    #[test]
    fn system_records_cover_every_persistent_setting_and_accept_old_timer_only_files() {
        let old: PersistentSystemSnapshot =
            serde_json::from_str(r#"{"global_timer_snapshot":{"state":"absent"}}"#).unwrap();
        assert_eq!(
            old.global_timer_snapshot,
            Some(RegistryDwordSnapshot::Absent)
        );
        assert!(old.game_bar_snapshot.is_none());
        let full = PersistentSystemSnapshot {
            global_timer_snapshot: Some(RegistryDwordSnapshot::Absent),
            game_bar_snapshot: Some(RegistryDwordSnapshot::Present(9)),
            fullscreen_optimization_snapshot: Some(RegistryDwordSnapshot::Absent),
            game_mode_allow_auto_snapshot: Some(RegistryDwordSnapshot::Present(0)),
            game_mode_enabled_snapshot: Some(RegistryDwordSnapshot::Present(1)),
            mmcss_snapshot: Some(MmcssSnapshot {
                scheduling_category: Some(String::new()),
                priority: Some(2),
                ..Default::default()
            }),
            original_power_plan_guid: Some(BALANCED_POWER_PLAN_GUID.into()),
            swifttunnel_power_plan_imported: true,
        };
        assert_eq!(
            serde_json::from_slice::<PersistentSystemSnapshot>(&serde_json::to_vec(&full).unwrap())
                .unwrap(),
            full
        );
    }

    #[cfg(windows)]
    #[test]
    fn system_records_preserve_old_files_on_failure_and_skip_unchanged_writes() {
        use std::os::windows::fs::OpenOptionsExt;
        let dir = std::env::temp_dir().join(format!(
            "swift-system-audit-{:032x}",
            rand::random::<u128>()
        ));
        fs::create_dir(&dir).unwrap();
        let path = dir.join(SYSTEM_SNAPSHOT_FILE);
        fs::write(&path, "bad record").unwrap();
        assert!(SystemOptimizer::read_persistent_snapshot(&path).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "bad record");
        let before = PersistentSystemSnapshot {
            game_bar_snapshot: Some(RegistryDwordSnapshot::Present(9)),
            ..Default::default()
        };
        SystemOptimizer::write_persistent_snapshot(&path, &before).unwrap();
        let original = fs::read(&path).unwrap();
        let mut optimizer = SystemOptimizer::new();
        optimizer.snapshot_path = Some(path.clone());
        optimizer.ensure_snapshot_loaded().unwrap();
        assert_eq!(optimizer.game_bar_snapshot, Some(Some(9)));
        let lock = fs::OpenOptions::new()
            .read(true)
            .share_mode(1)
            .open(&path)
            .unwrap();
        // An unchanged record must succeed even while replacement is blocked.
        optimizer.persist_snapshot().unwrap();
        optimizer.game_bar_snapshot = Some(Some(10));
        assert!(optimizer.persist_snapshot().is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        drop(lock);
        optimizer.persist_snapshot().unwrap();
        assert_eq!(
            SystemOptimizer::read_persistent_snapshot(&path)
                .unwrap()
                .unwrap()
                .game_bar_snapshot,
            Some(RegistryDwordSnapshot::Present(10))
        );
        fs::remove_file(&path).unwrap();
        fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn corruption_blocks_preparation_and_does_not_overwrite_recovery_records() {
        let dir = std::env::temp_dir().join(format!(
            "swift-system-corrupt-{:032x}",
            rand::random::<u128>()
        ));
        fs::create_dir(&dir).unwrap();
        let path = dir.join(SYSTEM_SNAPSHOT_FILE);
        fs::write(&path, "unfinished recovery data").unwrap();
        let mut optimizer = SystemOptimizer::new();
        optimizer.snapshot_path = Some(path.clone());
        assert!(
            optimizer
                .capture_system_state_snapshots(&SystemOptimizationConfig::default())
                .is_err()
        );
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "unfinished recovery data"
        );
        fs::remove_file(path).unwrap();
        fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn legacy_recovery_is_migrated_before_the_old_file_is_removed() {
        let dir = std::env::temp_dir().join(format!(
            "swift-system-migrate-{:032x}",
            rand::random::<u128>()
        ));
        fs::create_dir(&dir).unwrap();
        let legacy = dir.join(LEGACY_SYSTEM_SNAPSHOT_FILE);
        fs::write(
            &legacy,
            r#"{"global_timer_snapshot":{"state":"present","value":0}}"#,
        )
        .unwrap();
        let path = dir.join(SYSTEM_SNAPSHOT_FILE);
        let mut optimizer = SystemOptimizer::new();
        optimizer.snapshot_path = Some(path.clone());
        optimizer.ensure_snapshot_loaded().unwrap();
        assert_eq!(optimizer.global_timer_snapshot, Some(Some(0)));
        assert_eq!(
            SystemOptimizer::read_persistent_snapshot(&path)
                .unwrap()
                .unwrap()
                .global_timer_snapshot,
            Some(RegistryDwordSnapshot::Present(0))
        );
        assert!(!legacy.exists());
        fs::remove_file(path).unwrap();
        fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn power_plan_staging_is_exclusive_and_cleans_only_its_own_files() {
        let dir =
            std::env::temp_dir().join(format!("swift-power-audit-{:032x}", rand::random::<u128>()));
        fs::create_dir(&dir).unwrap();
        let unrelated = dir.join("swifttunnel_power_plan.pow");
        fs::write(&unrelated, "leave this file alone").unwrap();
        let one = SystemOptimizer::stage_swifttunnel_power_plan(&dir).unwrap();
        let two = SystemOptimizer::stage_swifttunnel_power_plan(&dir).unwrap();
        assert_ne!(one.0, two.0);
        assert_eq!(fs::read(&one.0).unwrap(), SWIFTTUNNEL_POWER_PLAN_BYTES);
        let first = one.0.clone();
        drop(one);
        assert!(!first.exists());
        assert!(two.0.exists());
        drop(two);
        assert_eq!(
            fs::read_to_string(&unrelated).unwrap(),
            "leave this file alone"
        );
        fs::remove_file(unrelated).unwrap();
        fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn registry_failures_are_not_absence_and_failed_restores_retain_the_original() {
        assert_eq!(
            SystemOptimizer::optional_registry_read::<u32>(
                Err(std::io::ErrorKind::NotFound.into())
            )
            .unwrap(),
            None
        );
        assert!(
            SystemOptimizer::optional_registry_read::<u32>(Err(
                std::io::ErrorKind::PermissionDenied.into()
            ))
            .is_err()
        );
        let mut pending = Some(Some(9));
        assert!(
            SystemOptimizer::restore_dword_slot(&mut pending, "INVALID\\Audit", "Original")
                .is_err()
        );
        assert_eq!(pending, Some(Some(9)));
    }

    #[cfg(windows)]
    #[test]
    fn native_registry_round_trip_preserves_absence_empty_strings_and_rejects_wrong_types() {
        use winreg::{RegKey, enums::HKEY_CURRENT_USER};
        let relative = format!(
            r"Software\SwiftTunnel\OptimizerTests\{:032x}",
            rand::random::<u128>()
        );
        let path = format!("HKCU\\{relative}");
        let root = RegKey::predef(HKEY_CURRENT_USER);
        let (key, _) = root.create_subkey(&relative).unwrap();
        let mut absent = Some(None);
        SystemOptimizer::set_registry_dword_checked(&path, "Value", 42).unwrap();
        SystemOptimizer::restore_dword_slot(&mut absent, &path, "Value").unwrap();
        assert!(key.get_raw_value("Value").is_err());
        SystemOptimizer::set_registry_string_checked(&path, "Value", "").unwrap();
        assert_eq!(
            SystemOptimizer::query_registry_checked::<String>(&path, "Value").unwrap(),
            Some(String::new())
        );
        assert!(SystemOptimizer::query_registry_checked::<u32>(&path, "Value").is_err());
        let mut present = Some(Some(9));
        SystemOptimizer::restore_dword_slot(&mut present, &path, "Value").unwrap();
        assert_eq!(key.get_value::<u32, _>("Value").unwrap(), 9);
        key.set_raw_value(
            "Large",
            &winreg::RegValue {
                bytes: vec![0; crate::registry_value::MAX_VALUE_BYTES + 1],
                vtype: winreg::enums::RegType::REG_BINARY,
            },
        )
        .unwrap();
        assert!(SystemOptimizer::query_registry_checked::<String>(&path, "Large").is_err());
        assert!(crate::registry_value::exists(&key, "Large").unwrap());
        assert!(
            SystemOptimizer::set_registry_string_checked(
                &path,
                "Value",
                &"x".repeat(crate::registry_value::MAX_VALUE_BYTES)
            )
            .is_err()
        );
        assert_eq!(key.get_value::<u32, _>("Value").unwrap(), 9);
        drop(key);
        assert!(relative.starts_with(r"Software\SwiftTunnel\OptimizerTests\"));
        root.delete_subkey_all(relative).unwrap();
    }

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
    fn failed_system_boosts_clear_only_the_failed_toggle() {
        let mut config = SystemOptimizationConfig {
            set_high_priority: true,
            set_cpu_affinity: true,
            disable_game_bar: true,
            disable_fullscreen_optimization: true,
            power_plan: PowerPlan::SwiftTunnel,
            timer_resolution_1ms: true,
            mmcss_gaming_profile: true,
            game_mode_enabled: true,
            ..Default::default()
        };

        SystemOptimizer::mark_failed_boost(
            &mut config,
            SystemBoostToggle::TimerResolution,
            PowerPlan::HighPerformance,
        );
        assert!(!config.timer_resolution_1ms);
        assert!(config.set_high_priority);
        assert!(config.set_cpu_affinity);
        assert_eq!(config.power_plan, PowerPlan::SwiftTunnel);

        SystemOptimizer::mark_failed_boost(
            &mut config,
            SystemBoostToggle::PowerPlan,
            PowerPlan::HighPerformance,
        );
        assert_eq!(config.power_plan, PowerPlan::HighPerformance);
    }

    #[test]
    fn persistent_system_snapshot_preserves_absent_and_present_timer_values() {
        let absent = PersistentSystemSnapshot {
            global_timer_snapshot: Some(RegistryDwordSnapshot::Absent),
            ..Default::default()
        };
        let absent_json = serde_json::to_string(&absent).unwrap();
        let absent_roundtrip: PersistentSystemSnapshot =
            serde_json::from_str(&absent_json).unwrap();
        assert_eq!(
            absent_roundtrip.global_timer_snapshot,
            Some(RegistryDwordSnapshot::Absent)
        );

        let present = PersistentSystemSnapshot {
            global_timer_snapshot: Some(RegistryDwordSnapshot::Present(1)),
            ..Default::default()
        };
        let present_json = serde_json::to_string(&present).unwrap();
        let present_roundtrip: PersistentSystemSnapshot =
            serde_json::from_str(&present_json).unwrap();
        assert_eq!(
            present_roundtrip.global_timer_snapshot,
            Some(RegistryDwordSnapshot::Present(1))
        );
    }

    #[test]
    fn restore_cpu_affinity_with_no_snapshot_is_noop() {
        let mut optimizer = SystemOptimizer::new();
        // No state captured — must not panic and must not contact a process.
        optimizer.restore_cpu_affinity(0).unwrap();
        optimizer.restore_cpu_affinity(u32::MAX).unwrap();
        assert!(optimizer.original_affinity.is_none());
    }

    #[test]
    fn restore_cpu_affinity_with_dead_pid_clears_snapshot_without_panic() {
        let mut optimizer = SystemOptimizer::new();
        optimizer.original_affinity = Some(0b1);
        optimizer.affinity_identity = Some(ProcessIdentity {
            pid: u32::MAX,
            created: 0,
        });
        // u32::MAX is an unreachable PID; OpenProcess should fail and the
        // restore path must classify it as "process gone" without panic.
        optimizer.restore_cpu_affinity(u32::MAX).unwrap();
        assert!(
            optimizer.original_affinity.is_none(),
            "snapshot should be consumed even when restore can't reach the process"
        );
    }
}
