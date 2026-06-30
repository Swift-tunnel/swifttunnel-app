use crate::process_names::is_roblox_process_name;
use crate::structs::*;
use std::time::Duration;
use sysinfo::{Process, ProcessesToUpdate, System};

/// True when the foreground (focused) window belongs to a Roblox process. Used
/// to show the in-game overlay only while Roblox is the active window, so it
/// never draws over the desktop or other apps the user has alt-tabbed to.
#[cfg(windows)]
pub fn foreground_window_is_roblox() -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::ProcessStatus::K32GetProcessImageFileNameW;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowThreadProcessId};

    unsafe {
        let hwnd = GetForegroundWindow();
        let mut pid: u32 = 0;
        GetWindowThreadProcessId(hwnd, Some(&mut pid));
        if pid == 0 {
            return false;
        }
        let Ok(handle) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) else {
            return false;
        };
        if handle.is_invalid() {
            return false;
        }
        let mut buffer = [0u16; 512];
        let len = K32GetProcessImageFileNameW(handle, &mut buffer);
        let _ = CloseHandle(handle);
        if len == 0 {
            return false;
        }
        let path = String::from_utf16_lossy(&buffer[..len as usize]);
        is_roblox_process_name(&path)
    }
}

#[cfg(not(windows))]
pub fn foreground_window_is_roblox() -> bool {
    false
}

/// Global cursor position in physical screen pixels. The in-game overlay polls
/// this so the stats bar can become grabbable only while the cursor is over it
/// (dropping click-through briefly) without the overlay ever needing focus.
#[cfg(windows)]
pub fn cursor_position() -> (i32, i32) {
    use windows::Win32::Foundation::POINT;
    use windows::Win32::UI::WindowsAndMessaging::GetCursorPos;

    unsafe {
        let mut point = POINT { x: 0, y: 0 };
        if GetCursorPos(&mut point).is_ok() {
            (point.x, point.y)
        } else {
            (0, 0)
        }
    }
}

#[cfg(not(windows))]
pub fn cursor_position() -> (i32, i32) {
    (0, 0)
}

/// True while the primary (left) mouse button is physically down. The in-game
/// overlay drives its drag from this global state (plus the cursor position)
/// instead of webview mouse events, which are unreliable on a click-through
/// window whose interactivity toggles underneath the drag.
#[cfg(windows)]
pub fn left_mouse_down() -> bool {
    use windows::Win32::UI::Input::KeyboardAndMouse::{GetAsyncKeyState, VK_LBUTTON};
    // High bit set => key/button is currently down.
    unsafe { (GetAsyncKeyState(VK_LBUTTON.0 as i32) as u16 & 0x8000) != 0 }
}

#[cfg(not(windows))]
pub fn left_mouse_down() -> bool {
    false
}

/// Add `WS_EX_NOACTIVATE` to a window so clicking it never pulls foreground
/// focus from the app underneath. The in-game overlay needs this: a normal
/// topmost window activates when clicked (to grab/drag the bar), which knocks
/// Roblox out of the foreground — and since the overlay only shows while Roblox
/// IS the foreground window, it would hide itself mid-drag. With NOACTIVATE the
/// overlay still receives the drag clicks while the game stays focused.
#[cfg(windows)]
pub fn set_window_no_activate(hwnd_raw: isize) {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::{
        GWL_EXSTYLE, GetWindowLongPtrW, SetWindowLongPtrW, WS_EX_NOACTIVATE,
    };

    if hwnd_raw == 0 {
        return;
    }
    unsafe {
        let hwnd = HWND(hwnd_raw as *mut core::ffi::c_void);
        let current = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
        SetWindowLongPtrW(hwnd, GWL_EXSTYLE, current | (WS_EX_NOACTIVATE.0 as isize));
    }
}

#[cfg(not(windows))]
pub fn set_window_no_activate(_hwnd_raw: isize) {}

/// Minimum gap between whole-system process scans while Roblox isn't running.
/// Metrics are polled every 1-2s by the UI; rescanning every process each tick
/// is real CPU on weak machines for a "did Roblox start yet?" answer that can
/// be a few seconds stale.
const FULL_SCAN_MIN_INTERVAL: Duration = Duration::from_secs(4);

pub struct PerformanceMonitor {
    system: System,
    last_full_scan: Option<std::time::Instant>,
    last_metrics: PerformanceMetrics,
}

impl PerformanceMonitor {
    pub fn new() -> Self {
        // No eager refresh: construction happens during app startup, where a
        // whole-system process scan adds launch latency. The first
        // `update_metrics` call performs the initial scan instead.
        Self {
            system: System::new(),
            last_full_scan: None,
            last_metrics: PerformanceMetrics::default(),
        }
    }

    /// Update performance metrics
    pub fn update_metrics(&mut self, metrics: &mut PerformanceMetrics) {
        // Keep the last known Roblox PID across calls. Overlay polling creates a
        // fresh `PerformanceMetrics` each tick, while full process scans are
        // intentionally throttled; without this cache most ticks briefly looked
        // like "Roblox not running" and cleared the FPS target.
        *metrics = self.last_metrics.clone();

        // If we know the PID from last scan, only refresh that one process
        if let Some(pid) = metrics.process_id {
            let pid = sysinfo::Pid::from_u32(pid);
            self.system
                .refresh_processes(ProcessesToUpdate::Some(&[pid]), true);

            // Check if process is still alive
            if let Some(process) = self.system.process(pid) {
                metrics.cpu_usage = normalize_process_cpu(process.cpu_usage());
                metrics.ram_usage = process.memory() as f64 / 1024.0 / 1024.0;
            } else {
                // Process exited, clear state and do full scan next time
                metrics.roblox_running = false;
                metrics.process_id = None;
                metrics.cpu_usage = 0.0;
                metrics.ram_usage = 0.0;
            }
        } else {
            // No known PID — full process scan to find Roblox, throttled so
            // 1s metric polling doesn't whole-system-scan every tick.
            let scan_due = self
                .last_full_scan
                .is_none_or(|at| at.elapsed() >= FULL_SCAN_MIN_INTERVAL);
            if scan_due {
                self.last_full_scan = Some(std::time::Instant::now());
                self.system.refresh_processes(ProcessesToUpdate::All, true);
            }
            if scan_due && let Some((pid, process)) = self.find_roblox_process() {
                metrics.roblox_running = true;
                metrics.process_id = Some(pid);
                metrics.cpu_usage = normalize_process_cpu(process.cpu_usage());
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
        self.last_metrics = metrics.clone();
    }

    /// Find Roblox process
    fn find_roblox_process(&self) -> Option<(u32, &Process)> {
        for (pid, process) in self.system.processes() {
            let process_name = process.name().to_string_lossy();
            if is_roblox_process_name(&process_name) {
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

fn normalize_process_cpu(raw_cpu: f32) -> f32 {
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .max(1) as f32;
    (raw_cpu / cores).clamp(0.0, 100.0)
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
