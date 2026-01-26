use crate::structs::*;
use sysinfo::{System, Process, ProcessesToUpdate};
use std::time::Duration;

pub struct PerformanceMonitor {
    system: System,
    roblox_process_name: String,
}

impl PerformanceMonitor {
    pub fn new() -> Self {
        let mut system = System::new_all();
        system.refresh_all();

        Self {
            system,
            roblox_process_name: "RobloxPlayerBeta.exe".to_string(),
        }
    }

    /// Update performance metrics
    pub fn update_metrics(&mut self, metrics: &mut PerformanceMetrics) {
        // Refresh only what we need (processes + memory) instead of refresh_all()
        // which queries CPU, disks, networks, components - all unnecessary here
        self.system.refresh_processes(ProcessesToUpdate::All, true);
        self.system.refresh_memory();

        // Find Roblox process
        let roblox_process = self.find_roblox_process();

        if let Some((pid, process)) = roblox_process {
            metrics.roblox_running = true;
            metrics.process_id = Some(pid);

            // Get CPU usage (per core, so we average it)
            metrics.cpu_usage = process.cpu_usage();

            // Get RAM usage
            metrics.ram_usage = process.memory() as f64 / 1024.0 / 1024.0; // Convert to MB

        } else {
            metrics.roblox_running = false;
            metrics.process_id = None;
            metrics.cpu_usage = 0.0;
            metrics.ram_usage = 0.0;
        }

        // Get total system CPU usage
        let _total_cpu = self.system.global_cpu_usage();

        // Get total system RAM
        metrics.ram_total = self.system.total_memory() as f64 / 1024.0 / 1024.0;

        // FPS would need to be read from game or estimated
        // For now, we'll leave it as is (would require more advanced techniques)

        // Ping would come from network monitor
        // metrics.ping is updated elsewhere
    }

    /// Find Roblox process
    fn find_roblox_process(&self) -> Option<(u32, &Process)> {
        for (pid, process) in self.system.processes() {
            let process_name = process.name().to_string_lossy();

            if process_name.contains("RobloxPlayerBeta") ||
               process_name.contains("RobloxPlayer") ||
               process_name.contains("Roblox") {
                return Some((pid.as_u32(), process));
            }
        }
        None
    }

    /// Get Roblox process ID if running
    pub fn get_roblox_pid(&mut self) -> Option<u32> {
        self.system.refresh_processes(ProcessesToUpdate::All, true);
        self.find_roblox_process().map(|(pid, _)| pid)
    }

    /// Check if Roblox is currently running
    pub fn is_roblox_running(&mut self) -> bool {
        self.system.refresh_processes(ProcessesToUpdate::All, true);
        self.find_roblox_process().is_some()
    }

    /// Get system information
    pub fn get_system_info(&self) -> SystemInfo {
        SystemInfo {
            total_memory: self.system.total_memory() / 1024 / 1024, // MB
            used_memory: self.system.used_memory() / 1024 / 1024,   // MB
            cpu_count: self.system.cpus().len(),
            os_version: System::long_os_version().unwrap_or_else(|| "Unknown".to_string()),
            system_name: System::name().unwrap_or_else(|| "Unknown".to_string()),
        }
    }

    /// Monitor process continuously (for background monitoring)
    pub async fn monitor_continuously(
        mut self,
        mut metrics: PerformanceMetrics,
        interval: Duration,
    ) -> PerformanceMetrics {
        loop {
            self.update_metrics(&mut metrics);
            tokio::time::sleep(interval).await;
        }
    }
}

impl Default for PerformanceMonitor {
    fn default() -> Self {
        Self::new()
    }
}

/// System information struct
#[derive(Debug, Clone)]
pub struct SystemInfo {
    pub total_memory: u64,
    pub used_memory: u64,
    pub cpu_count: usize,
    pub os_version: String,
    pub system_name: String,
}
