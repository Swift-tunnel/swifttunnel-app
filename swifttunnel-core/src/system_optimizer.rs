use crate::hidden_command;
use crate::structs::*;
use log::{info, warn};
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
    timer_resolution_active: bool,
    original_power_plan_guid: Option<Option<String>>,
    game_bar_snapshot: Option<Option<u32>>,
    fullscreen_optimization_snapshot: Option<Option<u32>>,
    game_mode_allow_auto_snapshot: Option<Option<u32>>,
    game_mode_enabled_snapshot: Option<Option<u32>>,
    mmcss_snapshot: Option<MmcssSnapshot>,
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

    fn set_active_power_plan_guid(guid: &str) {
        let output = hidden_command("powercfg")
            .args(["/setactive", guid])
            .output();

        match output {
            Ok(result) if result.status.success() => {}
            Ok(_) => warn!("Failed to restore power plan {}", guid),
            Err(e) => warn!("Failed to restore power plan {}: {}", guid, e),
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
            Ok(_) => {
                info!("Game Bar disabled successfully");
                Ok(())
            }
            Err(e) => {
                warn!("Failed to disable Game Bar: {}", e);
                Ok(()) // Non-critical
            }
        }
    }

    /// Disable fullscreen optimizations for Roblox
    fn disable_fullscreen_optimizations(&self) -> Result<()> {
        info!("Disabling fullscreen optimizations");

        // This would typically be done by modifying the Roblox executable properties
        // For now, we'll use registry approach
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
            Ok(_) => {
                info!("Fullscreen optimizations disabled");
                Ok(())
            }
            Err(e) => {
                warn!("Failed to disable fullscreen optimizations: {}", e);
                Ok(())
            }
        }
    }

    /// Set Windows power plan
    fn set_power_plan(&mut self, plan: &PowerPlan) -> Result<()> {
        let guid = match plan {
            PowerPlan::Balanced => "381b4222-f694-41f0-9685-ff5bb260df2e",
            PowerPlan::HighPerformance => "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c",
            PowerPlan::Ultimate => "e9a42b02-d5df-448d-aa00-03f14749eb61",
        };

        info!("Setting power plan to: {:?}", plan);

        let output = hidden_command("powercfg")
            .args(["/setactive", guid])
            .output();

        match output {
            Ok(result) => {
                if result.status.success() {
                    info!("Power plan set successfully");
                    Ok(())
                } else {
                    warn!("Failed to set power plan (may require admin)");
                    Ok(())
                }
            }
            Err(e) => {
                warn!("Failed to set power plan: {}", e);
                Ok(())
            }
        }
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
                        warn!("Failed to set timer resolution: error code {}", result);
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

        if let Some(snapshot) = self.original_power_plan_guid.take() {
            if let Some(guid) = snapshot {
                Self::set_active_power_plan_guid(&guid);
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
        .args(["/setactive", "381b4222-f694-41f0-9685-ff5bb260df2e"])
        .output();

    info!("System optimizer: uninstall cleanup completed");
}
