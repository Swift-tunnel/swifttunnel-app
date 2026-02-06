use crate::structs::*;
use sysinfo::{System, Process, ProcessesToUpdate};
use std::time::Duration;

pub struct PerformanceMonitor {
    system: System,
    roblox_process_name: String,
}

impl PerformanceMonitor {
    pub fn new() -> Self {
        let mut system = System::new();
        system.refresh_processes(ProcessesToUpdate::All, true);
        system.refresh_memory();
        system.refresh_cpu_all();

        Self {
            system,
            roblox_process_name: "RobloxPlayerBeta.exe".to_string(),
        }
    }

    /// Update performance metrics
    pub fn update_metrics(&mut self, metrics: &mut PerformanceMetrics) {
        // If we know the PID from last scan, only refresh that one process
        if let Some(pid) = metrics.process_id {
            let pid = sysinfo::Pid::from_u32(pid);
            self.system.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);

            // Check if process is still alive
            if let Some(process) = self.system.process(pid) {
                metrics.cpu_usage = process.cpu_usage();
                metrics.ram_usage = process.memory() as f64 / 1024.0 / 1024.0;
            } else {
                // Process exited, clear state and do full scan next time
                metrics.roblox_running = false;
                metrics.process_id = None;
                metrics.cpu_usage = 0.0;
                metrics.ram_usage = 0.0;
            }
        } else {
            // No known PID — do full process scan to find Roblox
            self.system.refresh_processes(ProcessesToUpdate::All, true);
            if let Some((pid, process)) = self.find_roblox_process() {
                metrics.roblox_running = true;
                metrics.process_id = Some(pid);
                metrics.cpu_usage = process.cpu_usage();
                metrics.ram_usage = process.memory() as f64 / 1024.0 / 1024.0;
            } else {
                metrics.roblox_running = false;
                metrics.process_id = None;
                metrics.cpu_usage = 0.0;
                metrics.ram_usage = 0.0;
            }
        }

        // Get total system RAM
        self.system.refresh_memory();
        metrics.ram_total = self.system.total_memory() as f64 / 1024.0 / 1024.0;
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

/// Get system info without requiring a full PerformanceMonitor instance.
/// Only refreshes memory and CPU — avoids expensive full process scan.
pub fn get_system_info_lightweight() -> SystemInfo {
    let mut system = System::new();
    system.refresh_memory();
    system.refresh_cpu_all();
    SystemInfo {
        total_memory: system.total_memory() / 1024 / 1024,
        used_memory: system.used_memory() / 1024 / 1024,
        cpu_count: system.cpus().len(),
        os_version: System::long_os_version().unwrap_or_else(|| "Unknown".to_string()),
        system_name: System::name().unwrap_or_else(|| "Unknown".to_string()),
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
