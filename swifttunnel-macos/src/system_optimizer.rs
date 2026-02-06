use crate::structs::*;
use log::{info, warn};
use std::process::Command;

pub struct SystemOptimizer {
    original_priority: Option<i32>,
    app_nap_disabled: bool,
    power_assertion_id: Option<u32>,
}

impl SystemOptimizer {
    pub fn new() -> Self {
        Self {
            original_priority: None,
            app_nap_disabled: false,
            power_assertion_id: None,
        }
    }

    /// Apply all system optimizations
    pub fn apply_optimizations(&mut self, config: &SystemOptimizationConfig, process_id: u32) -> Result<()> {
        info!("Applying system optimizations for process ID: {}", process_id);

        if config.set_high_priority {
            self.set_process_priority(process_id)?;
        }

        // Disable App Nap for Roblox (macOS-specific, replaces Windows Game Bar disable)
        if config.disable_game_bar {
            self.disable_app_nap()?;
        }

        // Set QoS class for our process to UserInteractive (highest non-realtime)
        // Replaces Windows MMCSS gaming profile
        if config.mmcss_gaming_profile {
            self.set_qos_user_interactive()?;
        }

        // Prevent system sleep while gaming (replaces Windows power plan)
        self.prevent_sleep()?;

        // Note: timer_resolution_1ms and game_mode have no direct macOS equivalent
        // macOS handles timer resolution automatically and has no "Game Mode" toggle
        if config.timer_resolution_1ms {
            info!("Timer resolution: macOS manages timer resolution automatically, no action needed");
        }
        if config.game_mode_enabled {
            info!("Game Mode: macOS has no equivalent, skipping");
        }

        Ok(())
    }

    /// Set Roblox process to higher priority using setpriority
    ///
    /// On macOS, nice values range from -20 (highest) to 20 (lowest).
    /// We set to -10 which is elevated but not maximum priority.
    fn set_process_priority(&mut self, process_id: u32) -> Result<()> {
        info!("Setting process priority for PID: {}", process_id);

        unsafe {
            // Get current priority for restoration
            // getpriority returns the nice value; on error returns -1 and sets errno
            let errno_ptr = libc::__error();
            *errno_ptr = 0;
            let current = libc::getpriority(libc::PRIO_PROCESS, process_id as libc::id_t);
            if *errno_ptr == 0 {
                self.original_priority = Some(current);
            }

            // Set to higher priority (-10 is elevated, -20 would be max)
            let result = libc::setpriority(libc::PRIO_PROCESS, process_id as libc::id_t, -10);

            if result == 0 {
                info!("Successfully set process priority to -10 (elevated)");
                Ok(())
            } else {
                let err = std::io::Error::last_os_error();
                // Not fatal if we lack permission (requires root for negative nice)
                warn!("Failed to set process priority: {} (may require root)", err);
                Ok(())
            }
        }
    }

    /// Disable App Nap for Roblox
    ///
    /// App Nap is macOS's power-saving feature that throttles background apps.
    /// We disable it for Roblox to prevent frame drops when the game isn't focused.
    fn disable_app_nap(&mut self) -> Result<()> {
        info!("Disabling App Nap for Roblox");

        let output = Command::new("defaults")
            .args(["write", "com.roblox.RobloxPlayer", "NSAppSleepDisabled", "-bool", "YES"])
            .output();

        match output {
            Ok(result) => {
                if result.status.success() {
                    self.app_nap_disabled = true;
                    info!("App Nap disabled for Roblox");
                } else {
                    warn!("Failed to disable App Nap (defaults write failed)");
                }
            }
            Err(e) => {
                warn!("Failed to run defaults command: {}", e);
            }
        }

        Ok(())
    }

    /// Re-enable App Nap for Roblox
    fn restore_app_nap(&mut self) -> Result<()> {
        if !self.app_nap_disabled {
            return Ok(());
        }

        info!("Re-enabling App Nap for Roblox");

        let output = Command::new("defaults")
            .args(["delete", "com.roblox.RobloxPlayer", "NSAppSleepDisabled"])
            .output();

        match output {
            Ok(_) => {
                self.app_nap_disabled = false;
                info!("App Nap re-enabled for Roblox");
            }
            Err(e) => {
                warn!("Failed to re-enable App Nap: {}", e);
            }
        }

        Ok(())
    }

    /// Set QoS class to UserInteractive for the current thread
    ///
    /// This is the macOS equivalent of Windows MMCSS - it tells the scheduler
    /// to prioritize this thread for interactive/real-time work.
    fn set_qos_user_interactive(&self) -> Result<()> {
        info!("Setting QoS class to UserInteractive");

        // QOS_CLASS_USER_INTERACTIVE = 0x21
        // pthread_set_qos_class_self_np sets the QoS for the calling thread
        // This function may not be in the libc crate, so we declare it directly
        extern "C" {
            fn pthread_set_qos_class_self_np(
                qos_class: libc::c_uint,
                relative_priority: libc::c_int,
            ) -> libc::c_int;
        }

        const QOS_CLASS_USER_INTERACTIVE: libc::c_uint = 0x21;

        unsafe {
            let result = pthread_set_qos_class_self_np(
                QOS_CLASS_USER_INTERACTIVE,
                0, // relative priority within the class
            );

            if result == 0 {
                info!("QoS class set to UserInteractive");
            } else {
                warn!("Failed to set QoS class: error code {}", result);
            }
        }

        Ok(())
    }

    /// Prevent system sleep using caffeinate
    ///
    /// Starts a caffeinate process that prevents the display and system from sleeping.
    /// This replaces the Windows power plan switching.
    fn prevent_sleep(&mut self) -> Result<()> {
        info!("Preventing system sleep with caffeinate");

        // -d prevents display sleep, -i prevents idle sleep
        // We spawn it as a background process; it will be killed on restore
        match Command::new("caffeinate")
            .args(["-di"])
            .spawn()
        {
            Ok(child) => {
                self.power_assertion_id = Some(child.id());
                info!("caffeinate started (PID: {})", child.id());
            }
            Err(e) => {
                warn!("Failed to start caffeinate: {}", e);
            }
        }

        Ok(())
    }

    /// Stop the caffeinate process
    fn restore_sleep(&mut self) {
        if let Some(pid) = self.power_assertion_id.take() {
            info!("Stopping caffeinate (PID: {})", pid);
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }
        }
    }

    /// Restore original system settings
    pub fn restore(&mut self, process_id: u32) -> Result<()> {
        info!("Restoring original system settings");

        // Restore process priority
        if let Some(priority) = self.original_priority.take() {
            unsafe {
                let result = libc::setpriority(
                    libc::PRIO_PROCESS,
                    process_id as libc::id_t,
                    priority,
                );
                if result != 0 {
                    warn!("Failed to restore process priority");
                }
            }
        }

        // Re-enable App Nap
        let _ = self.restore_app_nap();

        // Stop caffeinate
        self.restore_sleep();

        Ok(())
    }

    // Stub methods for GUI compatibility (Windows features with no macOS equivalent)

    pub fn set_timer_resolution(&mut self, _enabled: bool) -> Result<()> {
        info!("Timer resolution: macOS manages this automatically");
        Ok(())
    }

    pub fn apply_mmcss_profile(&mut self) -> Result<()> {
        info!("MMCSS: No equivalent on macOS, using QoS classes instead");
        self.set_qos_user_interactive()
    }

    pub fn restore_mmcss_profile(&mut self) -> Result<()> {
        info!("MMCSS restore: No action needed on macOS");
        Ok(())
    }

    pub fn enable_game_mode(&mut self) -> Result<()> {
        info!("Game Mode: macOS has no equivalent, skipping");
        Ok(())
    }

    pub fn disable_game_mode(&mut self) -> Result<()> {
        info!("Game Mode disable: No action needed on macOS");
        Ok(())
    }

    pub fn create_restore_point(name: &str) -> Result<String> {
        info!("System Restore: macOS uses Time Machine instead, skipping");
        Ok(format!("{} (Time Machine)", name))
    }

    pub fn open_system_restore() -> Result<()> {
        info!("Opening Time Machine preferences");
        let _ = std::process::Command::new("open")
            .arg("-b")
            .arg("com.apple.systempreferences")
            .arg("/System/Library/PreferencePanes/TimeMachine.prefPane")
            .spawn();
        Ok(())
    }
}

impl Default for SystemOptimizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SystemOptimizer {
    fn drop(&mut self) {
        // Ensure caffeinate is stopped even if restore() wasn't called
        self.restore_sleep();
    }
}
