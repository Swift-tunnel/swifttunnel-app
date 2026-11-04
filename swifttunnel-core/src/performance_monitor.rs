use crate::process_names::is_roblox_player_process_name;
use crate::structs::*;
use std::time::Duration;
use sysinfo::{Process, ProcessRefreshKind, ProcessesToUpdate, System};

/// Match the foreground window to the player whose stats are being reported.
/// Studio, installers and another player instance must not expose that
/// player's overlay. Discovery already validated the supplied process ID.
#[cfg(windows)]
pub fn foreground_window_is_roblox(player_pid: Option<u32>) -> bool {
    use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowThreadProcessId};

    let Some(player_pid) = player_pid.filter(|pid| *pid != 0) else {
        return false;
    };
    unsafe {
        let hwnd = GetForegroundWindow();
        let mut pid: u32 = 0;
        GetWindowThreadProcessId(hwnd, Some(&mut pid));
        pid == player_pid
    }
}

#[cfg(not(windows))]
pub fn foreground_window_is_roblox(_player_pid: Option<u32>) -> bool {
    false
}

/// Global cursor position in physical screen pixels. The in-game overlay polls
/// this so the stats bar can become grabbable only while the cursor is over it
/// (dropping click-through briefly) without the overlay ever needing focus.
#[cfg(windows)]
pub fn cursor_position() -> Option<(i32, i32)> {
    use windows::Win32::Foundation::POINT;
    use windows::Win32::UI::WindowsAndMessaging::GetCursorPos;

    unsafe {
        let mut point = POINT { x: 0, y: 0 };
        if GetCursorPos(&mut point).is_ok() {
            Some((point.x, point.y))
        } else {
            // An unavailable input desktop is not a cursor at the origin.
            None
        }
    }
}

#[cfg(not(windows))]
pub fn cursor_position() -> Option<(i32, i32)> {
    None
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

// sysinfo's convenience refresh also reads disk I/O and executable paths for
// every process. The performance monitor only consumes names, CPU and RAM.
fn metrics_refresh_kind() -> ProcessRefreshKind {
    ProcessRefreshKind::new().with_cpu().with_memory()
}

/// An open handle to the confirmed player process. While the handle is open
/// Windows cannot reuse its PID, so "still running" is one non-blocking wait
/// instead of a sysinfo refresh. sysinfo's `ProcessesToUpdate::Some` still
/// snapshots every process and thread on the machine (512KiB+ buffer), and
/// presence polls come from the overlay, the join watcher and the window-size
/// watcher several times a second while Roblox runs.
struct PlayerHandle {
    pid: u32,
    #[cfg(windows)]
    handle: windows::Win32::Foundation::HANDLE,
}

impl PlayerHandle {
    #[cfg(windows)]
    fn open(pid: u32) -> Option<Self> {
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
        };
        // Query rights let CPU/RAM samples come from this handle too. If the
        // player refuses them, presence checks still work on SYNCHRONIZE and
        // samples fall back to sysinfo.
        let handle = unsafe {
            OpenProcess(
                PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                pid,
            )
        }
        .or_else(|_| unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, pid) })
        .ok()?;
        Some(Self { pid, handle })
    }

    #[cfg(not(windows))]
    fn open(_pid: u32) -> Option<Self> {
        None
    }

    /// Total CPU time (kernel + user, 100ns units) and working set in bytes,
    /// the same working-set figure sysinfo reports as `memory()`.
    #[cfg(windows)]
    fn usage(&self) -> Option<(u64, u64)> {
        use windows::Win32::Foundation::FILETIME;
        use windows::Win32::System::ProcessStatus::{
            K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
        };
        use windows::Win32::System::Threading::GetProcessTimes;
        let mut created = FILETIME::default();
        let mut exited = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        unsafe {
            GetProcessTimes(
                self.handle,
                &mut created,
                &mut exited,
                &mut kernel,
                &mut user,
            )
        }
        .ok()?;
        let mut counters = PROCESS_MEMORY_COUNTERS {
            cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
            ..Default::default()
        };
        if !unsafe { K32GetProcessMemoryInfo(self.handle, &mut counters, counters.cb) }.as_bool() {
            return None;
        }
        let ticks =
            |time: FILETIME| (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime);
        Some((
            ticks(kernel).saturating_add(ticks(user)),
            counters.WorkingSetSize as u64,
        ))
    }

    #[cfg(not(windows))]
    fn usage(&self) -> Option<(u64, u64)> {
        None
    }

    #[cfg(windows)]
    fn is_running(&self) -> bool {
        use windows::Win32::Foundation::WAIT_TIMEOUT;
        use windows::Win32::System::Threading::WaitForSingleObject;
        unsafe { WaitForSingleObject(self.handle, 0) == WAIT_TIMEOUT }
    }

    #[cfg(not(windows))]
    fn is_running(&self) -> bool {
        false
    }
}

#[cfg(windows)]
impl Drop for PlayerHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(self.handle);
        }
    }
}

// The handle is only waited on, queried and closed; all are thread-safe.
#[cfg(windows)]
unsafe impl Send for PlayerHandle {}

pub struct PerformanceMonitor {
    system: System,
    player_handle: Option<PlayerHandle>,
    last_full_scan: Option<std::time::Instant>,
    last_metrics: PerformanceMetrics,
    last_metrics_sample: Option<(std::time::Instant, Option<u32>)>,
    /// CPU baseline for samples read from `player_handle`: (pid, when, total
    /// CPU time in 100ns units).
    handle_cpu_baseline: Option<(u32, std::time::Instant, u64)>,
    #[cfg(test)]
    full_scans: usize,
    #[cfg(test)]
    metric_samples: usize,
}

impl PerformanceMonitor {
    pub fn new() -> Self {
        // No eager refresh: construction happens during app startup, where a
        // whole-system process scan adds launch latency. The first
        // `update_metrics` call performs the initial scan instead.
        Self {
            system: System::new(),
            player_handle: None,
            last_full_scan: None,
            last_metrics: PerformanceMetrics::default(),
            last_metrics_sample: None,
            handle_cpu_baseline: None,
            #[cfg(test)]
            full_scans: 0,
            #[cfg(test)]
            metric_samples: 0,
        }
    }

    /// Update performance metrics
    pub fn update_metrics(&mut self, metrics: &mut PerformanceMetrics) {
        self.update_metrics_at(metrics, std::time::Instant::now());
    }

    fn update_metrics_at(&mut self, metrics: &mut PerformanceMetrics, now: std::time::Instant) {
        // Keep the last known Roblox PID across calls. Overlay polling creates a
        // fresh `PerformanceMetrics` each tick, while full process scans are
        // intentionally throttled; without this cache most ticks briefly looked
        // like "Roblox not running" and cleared the FPS target.
        *metrics = self.last_metrics.clone();

        let sample_due = self.last_metrics_sample.is_none_or(|(at, _)| {
            now.saturating_duration_since(at) >= sysinfo::MINIMUM_CPU_UPDATE_INTERVAL
        });
        if sample_due && let Some((pid, cpu_usage, ram_usage)) = self.sample_held_player(now) {
            metrics.process_id = Some(pid);
            metrics.roblox_running = true;
            metrics.cpu_usage = cpu_usage;
            metrics.ram_usage = ram_usage;
            self.system.refresh_memory();
            metrics.ram_total = self.system.total_memory() as f64 / 1024.0 / 1024.0;
            self.last_metrics_sample = Some((now, metrics.process_id));
            #[cfg(test)]
            {
                self.metric_samples += 1;
            }
            self.last_metrics = metrics.clone();
            return;
        }
        // Presence remains fresh even when another consumer just sampled the
        // CPU counters. Do not overwrite their baseline with a near-zero gap.
        metrics.process_id = self.refresh_player(false, sample_due);
        let player_changed = self
            .last_metrics_sample
            .is_some_and(|(_, pid)| pid != metrics.process_id);
        if player_changed && !sample_due && metrics.process_id.is_some() {
            // Presence-only discovery may have found a different player. Its
            // first sample must not inherit the previous player's CPU/RAM.
            metrics.process_id = self.refresh_player(false, true);
        }
        metrics.roblox_running = metrics.process_id.is_some();
        if sample_due || player_changed {
            if let Some(process) = metrics
                .process_id
                .and_then(|pid| self.system.process(sysinfo::Pid::from_u32(pid)))
            {
                metrics.cpu_usage = normalize_process_cpu(process.cpu_usage());
                metrics.ram_usage = process.memory() as f64 / 1024.0 / 1024.0;
            } else {
                metrics.cpu_usage = 0.0;
                metrics.ram_usage = 0.0;
            }
            self.system.refresh_memory();
            metrics.ram_total = self.system.total_memory() as f64 / 1024.0 / 1024.0;
            self.last_metrics_sample = Some((now, metrics.process_id));
            #[cfg(test)]
            {
                self.metric_samples += 1;
            }
        } else if !metrics.roblox_running {
            metrics.cpu_usage = 0.0;
            metrics.ram_usage = 0.0;
        }
        self.last_metrics = metrics.clone();
    }

    /// Sample CPU and RAM of the confirmed player from its held handle.
    ///
    /// The overlay asks for a sample every second for the whole match. Going
    /// through sysinfo for that meant `ProcessesToUpdate::Some`, which on
    /// Windows still snapshots every process and thread on the machine and
    /// then filters. The held handle answers the same two questions with two
    /// cheap queries, and it was opened only after the name check, so the
    /// PID cannot have been reused. `None` falls back to the sysinfo path.
    fn sample_held_player(&mut self, now: std::time::Instant) -> Option<(u32, f32, f64)> {
        let handle = self.player_handle.as_ref()?;
        let pid = handle.pid;
        if self.last_metrics.process_id != Some(pid) || !handle.is_running() {
            return None;
        }
        let Some((cpu_time, working_set)) = handle.usage() else {
            self.handle_cpu_baseline = None;
            return None;
        };
        let cpu_usage = match self.handle_cpu_baseline {
            Some((baseline_pid, at, baseline)) if baseline_pid == pid => {
                held_process_cpu_percent(baseline, cpu_time, now.saturating_duration_since(at))
            }
            // First sample for this player: no interval yet, as with sysinfo.
            _ => 0.0,
        };
        self.handle_cpu_baseline = Some((pid, now, cpu_time));
        Some((pid, cpu_usage, working_set as f64 / 1024.0 / 1024.0))
    }

    /// Find the in-game Roblox player process (the thing whose FPS/CPU/RAM we
    /// report, and what "Roblox running" on the dashboard means). Only the
    /// player counts — the launcher/app host lingering in the background does
    /// not mean the user is in a game.
    fn find_roblox_process(&self) -> Option<(u32, &Process)> {
        for (pid, process) in self.system.processes() {
            let process_name = process.name().to_string_lossy();
            if is_roblox_player_process_name(&process_name) {
                return Some((pid.as_u32(), process));
            }
        }
        None
    }

    /// Refresh a known player only. Idle polling shares one discovery scan
    /// across metrics, the overlay and launch tracking, rather than each caller
    /// scanning every process. Destructive operations request fresh discovery.
    fn refresh_player(&mut self, force_discovery: bool, sample_metrics: bool) -> Option<u32> {
        let known = self.last_metrics.process_id;
        if !force_discovery
            && !sample_metrics
            && let Some(handle) = &self.player_handle
            && Some(handle.pid) == known
            && handle.is_running()
        {
            return known;
        }
        let pid = self.refresh_player_with_sysinfo(force_discovery, sample_metrics);
        if pid != self.player_handle.as_ref().map(|handle| handle.pid) {
            self.player_handle = pid.and_then(PlayerHandle::open);
            self.handle_cpu_baseline = self.player_handle.as_ref().and_then(|handle| {
                handle
                    .usage()
                    .map(|(cpu_time, _)| (handle.pid, std::time::Instant::now(), cpu_time))
            });
        }
        pid
    }

    fn refresh_player_with_sysinfo(
        &mut self,
        force_discovery: bool,
        sample_metrics: bool,
    ) -> Option<u32> {
        let refresh = if sample_metrics {
            metrics_refresh_kind()
        } else {
            // Presence checks must not consume CPU sampling baselines or
            // query memory just to learn whether a process still exists.
            ProcessRefreshKind::new()
        };
        if let Some(pid) = self.last_metrics.process_id {
            let process_pid = sysinfo::Pid::from_u32(pid);
            self.system.refresh_processes_specifics(
                ProcessesToUpdate::Some(&[process_pid]),
                true,
                refresh,
            );
            if self.system.process(process_pid).is_some_and(|process| {
                is_roblox_player_process_name(&process.name().to_string_lossy())
            }) {
                return Some(pid);
            }
        }
        let scan_due = force_discovery
            || self
                .last_full_scan
                .is_none_or(|at| at.elapsed() >= FULL_SCAN_MIN_INTERVAL);
        let pid = if scan_due {
            self.last_full_scan = Some(std::time::Instant::now());
            self.system.refresh_processes_specifics(
                ProcessesToUpdate::All,
                true,
                ProcessRefreshKind::new(),
            );
            #[cfg(test)]
            {
                self.full_scans += 1;
            }
            let pid = self.find_roblox_process().map(|(pid, _)| pid);
            if sample_metrics && let Some(pid) = pid {
                // Discovery needs only names. Read CPU/RAM for the selected
                // player rather than every process on the computer.
                self.system.refresh_processes_specifics(
                    ProcessesToUpdate::Some(&[sysinfo::Pid::from_u32(pid)]),
                    true,
                    refresh,
                );
                if !self
                    .system
                    .process(sysinfo::Pid::from_u32(pid))
                    .is_some_and(|process| {
                        is_roblox_player_process_name(&process.name().to_string_lossy())
                    })
                {
                    self.last_metrics.process_id = None;
                    self.last_metrics.roblox_running = false;
                    return None;
                }
            }
            pid
        } else {
            None
        };
        self.last_metrics.process_id = pid;
        self.last_metrics.roblox_running = pid.is_some();
        pid
    }

    /// Polling may take up to four seconds to discover a newly started player;
    /// an already discovered player's exit is checked on every call.
    pub fn poll_roblox_pid(&mut self) -> Option<u32> {
        self.refresh_player(false, false)
    }

    /// Fresh discovery for applying/restoring optimizations and launch safety.
    pub fn get_roblox_pid(&mut self) -> Option<u32> {
        self.refresh_player(true, false)
    }

    /// Fresh check for cleanup/launch safety. Do not use this for routine polls.
    pub fn is_roblox_running(&mut self) -> bool {
        self.refresh_player(true, false).is_some()
    }
}

/// Share of the whole machine's CPU used between two process CPU-time
/// readings, on the same 0-100 scale as `normalize_process_cpu`.
fn held_process_cpu_percent(before_100ns: u64, after_100ns: u64, elapsed: Duration) -> f32 {
    let cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .max(1) as f64;
    let wall_100ns = elapsed.as_nanos() as f64 / 100.0;
    if wall_100ns <= 0.0 {
        return 0.0;
    }
    let used = after_100ns.saturating_sub(before_100ns) as f64;
    ((used / (wall_100ns * cores)) * 100.0).clamp(0.0, 100.0) as f32
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

#[cfg(test)]
mod polling_tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn presence_polls_of_a_live_player_use_the_held_handle_not_a_snapshot() {
        let mut monitor = PerformanceMonitor::new();
        let pid = std::process::id();
        monitor.last_metrics.process_id = Some(pid);
        monitor.player_handle = PlayerHandle::open(pid);
        assert!(monitor.player_handle.is_some());
        for _ in 0..10 {
            assert_eq!(monitor.poll_roblox_pid(), Some(pid));
        }
        assert_eq!(monitor.full_scans, 0);
        // Fresh discovery still verifies by name; this test process is not a
        // Roblox player, so it is dropped along with its handle.
        assert_eq!(monitor.get_roblox_pid(), None);
        assert!(monitor.player_handle.is_none());
    }

    #[cfg(windows)]
    #[test]
    fn metric_samples_of_a_held_player_do_not_snapshot_the_system() {
        let mut monitor = PerformanceMonitor::new();
        let pid = std::process::id();
        monitor.last_metrics.process_id = Some(pid);
        monitor.player_handle = PlayerHandle::open(pid);
        assert!(monitor.player_handle.as_ref().unwrap().usage().is_some());
        let start = std::time::Instant::now();
        let mut metrics = PerformanceMetrics::default();
        for step in 0..3 {
            monitor.update_metrics_at(&mut metrics, start + Duration::from_secs(step));
            assert_eq!(metrics.process_id, Some(pid));
            assert!(metrics.roblox_running);
            assert!(metrics.ram_usage > 0.0);
            assert!((0.0..=100.0).contains(&metrics.cpu_usage));
        }
        assert_eq!(monitor.metric_samples, 3);
        assert_eq!(monitor.full_scans, 0);
    }

    #[test]
    fn held_player_cpu_is_a_share_of_the_whole_machine() {
        let cores = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1) as f32;
        // One core fully busy for one second.
        let one_core = held_process_cpu_percent(0, 10_000_000, Duration::from_secs(1));
        assert!((one_core - 100.0 / cores).abs() < 0.01);
        assert_eq!(held_process_cpu_percent(5, 5, Duration::from_secs(1)), 0.0);
        assert_eq!(held_process_cpu_percent(0, 10, Duration::ZERO), 0.0);
        // A counter that went backwards (cannot happen for one process) clamps.
        assert_eq!(held_process_cpu_percent(10, 5, Duration::from_secs(1)), 0.0);
        assert!(held_process_cpu_percent(0, u64::MAX, Duration::from_secs(1)) <= 100.0);
    }

    #[test]
    fn overlapping_metrics_consumers_share_a_sample_without_deferring_the_next_due_sample() {
        let mut monitor = PerformanceMonitor::new();
        let now = std::time::Instant::now();
        monitor.last_full_scan = Some(now);
        let mut metrics = PerformanceMetrics::default();
        monitor.update_metrics_at(&mut metrics, now);
        for _ in 0..20 {
            monitor.update_metrics_at(&mut metrics, now);
        }
        assert_eq!(monitor.metric_samples, 1);
        monitor.update_metrics_at(&mut metrics, now + sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
        assert_eq!(monitor.metric_samples, 2);
    }

    #[test]
    fn a_cached_metrics_sample_does_not_keep_a_gone_or_reused_player_alive() {
        let mut monitor = PerformanceMonitor::new();
        let now = std::time::Instant::now();
        monitor.last_full_scan = Some(now);
        monitor.last_metrics_sample = Some((now, Some(std::process::id())));
        monitor.last_metrics.process_id = Some(std::process::id());
        monitor.last_metrics.roblox_running = true;
        monitor.last_metrics.cpu_usage = 70.0;
        monitor.last_metrics.ram_usage = 512.0;
        let mut metrics = PerformanceMetrics::default();
        monitor.update_metrics_at(&mut metrics, now);
        assert!(metrics.process_id.is_none());
        assert!(!metrics.roblox_running);
        assert_eq!(metrics.cpu_usage, 0.0);
        assert_eq!(metrics.ram_usage, 0.0);
    }

    #[test]
    #[ignore = "manual host-dependent process polling benchmark"]
    fn compare_repeated_full_scans_with_shared_polling() {
        let mut old = System::new();
        let started = std::time::Instant::now();
        for _ in 0..20 {
            old.refresh_processes(ProcessesToUpdate::All, true);
        }
        let repeated = started.elapsed();
        let mut lean = System::new();
        let started = std::time::Instant::now();
        for _ in 0..20 {
            lean.refresh_processes_specifics(ProcessesToUpdate::All, true, metrics_refresh_kind());
        }
        let lean_scans = started.elapsed();
        // Read-only host check: the reduced refresh must still populate the
        // process identity and memory used by the dashboard.
        let process = lean
            .process(sysinfo::Pid::from_u32(std::process::id()))
            .unwrap();
        assert!(!process.name().is_empty());
        assert!(process.memory() > 0);
        let mut monitor = PerformanceMonitor::new();
        let started = std::time::Instant::now();
        for _ in 0..20 {
            monitor.poll_roblox_pid();
        }
        println!(
            "20 default scans: {repeated:?}; 20 CPU/RAM-only scans: {lean_scans:?}; 20 shared polls: {:?}; full scans performed: {}",
            started.elapsed(),
            monitor.full_scans
        );
    }

    #[test]
    fn idle_consumers_share_discovery_and_safety_checks_still_force_a_scan() {
        let mut monitor = PerformanceMonitor::new();
        monitor.last_full_scan = Some(std::time::Instant::now());
        for _ in 0..20 {
            assert!(monitor.poll_roblox_pid().is_none());
            monitor.update_metrics(&mut PerformanceMetrics::default());
        }
        assert_eq!(monitor.full_scans, 0);
        monitor.is_roblox_running();
        assert_eq!(monitor.full_scans, 1);
        monitor.last_metrics.process_id = None;
        monitor.last_full_scan = Some(std::time::Instant::now() - FULL_SCAN_MIN_INTERVAL);
        monitor.poll_roblox_pid();
        assert_eq!(monitor.full_scans, 2);
    }

    #[test]
    fn reused_pid_is_not_mistaken_for_a_player() {
        let mut monitor = PerformanceMonitor::new();
        monitor.last_full_scan = Some(std::time::Instant::now());
        monitor.last_metrics.process_id = Some(std::process::id());
        monitor.last_metrics.roblox_running = true;
        let mut metrics = PerformanceMetrics::default();
        monitor.update_metrics(&mut metrics);
        assert!(!metrics.roblox_running);
        assert_eq!(metrics.process_id, None);
        assert_eq!(metrics.cpu_usage, 0.0);
        assert_eq!(metrics.ram_usage, 0.0);
        assert_eq!(monitor.full_scans, 0);
    }
}
