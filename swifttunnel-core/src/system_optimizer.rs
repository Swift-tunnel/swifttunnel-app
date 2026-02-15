use crate::hidden_command;
use crate::structs::*;
use log::{info, warn};
use std::process::Command;
use windows::Win32::Foundation::CloseHandle;
use windows::Win32::Media::{timeBeginPeriod, timeEndPeriod};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::Threading::*;

// ntdll.dll functions for low-level system control
unsafe extern "system" {
    // Sub-millisecond timer resolution (0.5ms)
    fn NtSetTimerResolution(
        DesiredResolution: u32,
        SetResolution: u8,
        CurrentResolution: *mut u32,
    ) -> i32;

    // Standby memory purge (actual RAM clearing)
    fn NtSetSystemInformation(
        SystemInformationClass: u32,
        SystemInformation: *const std::ffi::c_void,
        SystemInformationLength: u32,
    ) -> i32;
}

/// SystemMemoryListInformation class for NtSetSystemInformation
const SYSTEM_MEMORY_LIST_INFORMATION: u32 = 80;
/// Command to purge the standby list (free cached RAM)
const MEMORY_PURGE_STANDBY_LIST: u32 = 4;

pub struct SystemOptimizer {
    original_priority: Option<u32>,
    timer_resolution_active: bool,
}

impl SystemOptimizer {
    pub fn new() -> Self {
        Self {
            original_priority: None,
            timer_resolution_active: false,
        }
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

        if config.clear_standby_memory {
            self.clear_standby_memory()?;
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

    /// Clear standby memory to free up RAM
    ///
    /// Uses NtSetSystemInformation with MemoryPurgeStandbyList to actually
    /// release cached pages back to the free list. Requires admin privileges
    /// (SeProfileSingleProcessPrivilege).
    fn clear_standby_memory(&self) -> Result<()> {
        info!("Clearing standby memory via NtSetSystemInformation");

        unsafe {
            // Enable SeProfileSingleProcessPrivilege (required for standby purge)
            if let Err(e) = Self::enable_privilege("SeProfileSingleProcessPrivilege") {
                warn!("Could not enable memory privilege (not admin?): {}", e);
                return Ok(()); // Non-critical, continue with other boosts
            }

            let command: u32 = MEMORY_PURGE_STANDBY_LIST;
            let status = NtSetSystemInformation(
                SYSTEM_MEMORY_LIST_INFORMATION,
                &command as *const u32 as *const std::ffi::c_void,
                std::mem::size_of::<u32>() as u32,
            );

            if status == 0 {
                info!("Standby memory purged successfully");
            } else {
                warn!(
                    "NtSetSystemInformation failed (0x{:08X}) — requires admin privileges",
                    status as u32
                );
            }
        }

        Ok(())
    }

    /// Enable a Windows privilege by name (e.g. "SeProfileSingleProcessPrivilege")
    unsafe fn enable_privilege(privilege_name: &str) -> Result<()> {
        use windows::core::PCWSTR;

        let mut token = windows::Win32::Foundation::HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )?;

        // Convert privilege name to wide string
        let wide_name: Vec<u16> = privilege_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let mut luid = windows::Win32::Foundation::LUID::default();
        LookupPrivilegeValueW(PCWSTR::null(), PCWSTR(wide_name.as_ptr()), &mut luid)?;

        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None)?;
        let _ = CloseHandle(token);

        Ok(())
    }

    /// Disable Windows Game Bar
    fn disable_game_bar(&self) -> Result<()> {
        info!("Disabling Windows Game Bar");

        let output = hidden_command("reg")
            .args([
                "add",
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\GameDVR",
                "/v",
                "AppCaptureEnabled",
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
                "HKCU\\System\\GameConfigStore",
                "/v",
                "GameDVR_FSEBehaviorMode",
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
    fn set_power_plan(&self, plan: &PowerPlan) -> Result<()> {
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
            let output = hidden_command("reg")
                .args([
                    "add", key_path, "/v", value_name, "/t", "REG_SZ", "/d", value_data, "/f",
                ])
                .output();

            if let Err(e) = output {
                warn!("Failed to set MMCSS key {}: {}", value_name, e);
            }
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
            let output = hidden_command("reg")
                .args([
                    "add",
                    key_path,
                    "/v",
                    value_name,
                    "/t",
                    "REG_DWORD",
                    "/d",
                    value_data,
                    "/f",
                ])
                .output();

            if let Err(e) = output {
                warn!("Failed to set MMCSS DWORD {}: {}", value_name, e);
            }
        }

        info!("MMCSS gaming profile applied");
        Ok(())
    }

    /// Restore MMCSS profile to Windows defaults
    pub fn restore_mmcss_profile(&self) -> Result<()> {
        info!("Restoring MMCSS profile to defaults");

        // Restore default MMCSS string values
        let mmcss_keys = [
            (
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games",
                "Scheduling Category",
                "Medium",
            ),
            (
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games",
                "SFIO Priority",
                "Normal",
            ),
            (
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games",
                "Background Only",
                "True",
            ),
        ];

        for (key_path, value_name, value_data) in mmcss_keys.iter() {
            let output = hidden_command("reg")
                .args([
                    "add", key_path, "/v", value_name, "/t", "REG_SZ", "/d", value_data, "/f",
                ])
                .output();

            if let Err(e) = output {
                warn!("Failed to restore MMCSS key {}: {}", value_name, e);
            }
        }

        // Restore default DWORD values
        let dword_keys = [
            (
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games",
                "Priority",
                "2",
            ),
            (
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games",
                "Clock Rate",
                "10000",
            ),
            (
                r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile",
                "SystemResponsiveness",
                "20",
            ),
        ];

        for (key_path, value_name, value_data) in dword_keys.iter() {
            let output = hidden_command("reg")
                .args([
                    "add",
                    key_path,
                    "/v",
                    value_name,
                    "/t",
                    "REG_DWORD",
                    "/d",
                    value_data,
                    "/f",
                ])
                .output();

            if let Err(e) = output {
                warn!("Failed to restore MMCSS DWORD {}: {}", value_name, e);
            }
        }

        info!("MMCSS profile restored to defaults");
        Ok(())
    }

    /// Enable Windows Game Mode for resource prioritization
    pub fn enable_game_mode(&self) -> Result<()> {
        info!("Enabling Windows Game Mode");

        let game_mode_keys = [
            (r"HKCU\Software\Microsoft\GameBar", "AllowAutoGameMode", "1"),
            (
                r"HKCU\Software\Microsoft\GameBar",
                "AutoGameModeEnabled",
                "1",
            ),
        ];

        for (key_path, value_name, value_data) in game_mode_keys.iter() {
            let output = hidden_command("reg")
                .args([
                    "add",
                    key_path,
                    "/v",
                    value_name,
                    "/t",
                    "REG_DWORD",
                    "/d",
                    value_data,
                    "/f",
                ])
                .output();

            match output {
                Ok(_) => {}
                Err(e) => {
                    warn!("Failed to set Game Mode key {}: {}", value_name, e);
                }
            }
        }

        info!("Windows Game Mode enabled");
        Ok(())
    }

    /// Disable Windows Game Mode
    pub fn disable_game_mode(&self) -> Result<()> {
        info!("Disabling Windows Game Mode");

        let game_mode_keys = [
            (r"HKCU\Software\Microsoft\GameBar", "AllowAutoGameMode", "0"),
            (
                r"HKCU\Software\Microsoft\GameBar",
                "AutoGameModeEnabled",
                "0",
            ),
        ];

        for (key_path, value_name, value_data) in game_mode_keys.iter() {
            let output = hidden_command("reg")
                .args([
                    "add",
                    key_path,
                    "/v",
                    value_name,
                    "/t",
                    "REG_DWORD",
                    "/d",
                    value_data,
                    "/f",
                ])
                .output();

            match output {
                Ok(_) => {}
                Err(e) => {
                    warn!("Failed to disable Game Mode key {}: {}", value_name, e);
                }
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

        if let Some(priority) = self.original_priority {
            unsafe {
                if let Ok(handle) = OpenProcess(PROCESS_SET_INFORMATION, false, process_id) {
                    if !handle.is_invalid() {
                        let _ = SetPriorityClass(handle, PROCESS_CREATION_FLAGS(priority));
                        let _ = CloseHandle(handle);
                    }
                }
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
