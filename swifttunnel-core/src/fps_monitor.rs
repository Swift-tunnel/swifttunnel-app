//! ETW FPS Monitor — anti-cheat-safe in-game FPS.
//!
//! Reports a game's real framerate by counting `Microsoft-Windows-DXGI`
//! Present events emitted by the target process, entirely from OUTSIDE that
//! process. We never read its memory, inject, or hook anything — this is the
//! same OS-level present-event source PresentMon uses — so Roblox's Byfron /
//! Hyperion anti-cheat has nothing to flag.
//!
//! Each call to `IDXGISwapChain::Present` logs a DXGI "Present Start" event
//! (id 42) in the *calling* process's context. Counting those whose
//! `EventHeader.ProcessId` is the game and dividing by elapsed time gives
//! presents-per-second = FPS. Mirrors the real-time ETW session pattern in
//! [`crate::vpn::process_watcher`].
//!
//! ## Requirements
//! - Administrator privileges (real-time ETW session). SwiftTunnel runs
//!   elevated; if not, `StartTraceW` fails and we simply report 0 FPS (the
//!   overlay shows "--") while the supervisor keeps retrying.
//! - Windows 10 or later.

use std::ffi::c_void;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use windows::Win32::Foundation::ERROR_SUCCESS;
use windows::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, CloseTrace, ControlTraceW, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
    EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW, EVENT_TRACE_PROPERTIES,
    EVENT_TRACE_REAL_TIME_MODE, EnableTraceEx2, OpenTraceW, PROCESS_TRACE_MODE_EVENT_RECORD,
    PROCESS_TRACE_MODE_REAL_TIME, ProcessTrace, StartTraceW, TRACE_LEVEL_VERBOSE,
    WNODE_FLAG_TRACED_GUID,
};
use windows::core::{GUID, PCWSTR, PWSTR};

/// Microsoft-Windows-DXGI provider. Present events are logged in the context of
/// the process that called `Present`, so `EventHeader.ProcessId` is the game.
const DXGI_PROVIDER_GUID: GUID = GUID::from_values(
    0xca11c036,
    0x0102,
    0x4a2d,
    [0xa6, 0xad, 0xf0, 0x3c, 0xfe, 0xd5, 0xd3, 0xc9],
);

/// DXGI present tasks. Roblox can report frames through the older `Present`
/// task or the newer swap-chain partner tasks depending on the renderer /
/// driver path, so count present-start tasks instead of one hard-coded event id.
const DXGI_PRESENT_TASKS: &[u16] = &[9, 80, 468, 482];
const ETW_OPCODE_START: u8 = 1;

const SESSION_NAME: &str = "SwiftTunnelFpsMonitor";
const TRACE_MATCH_ANY_KEYWORD_ALL: u64 = u64::MAX;

/// Sanity ceiling so a delayed buffer flush can't briefly report absurd FPS.
const MAX_REPORTABLE_FPS: u32 = 2000;

/// State shared between the ETW callback, the sampler, and the public API.
struct FpsShared {
    /// PID whose presents we count (0 = none / no game in focus).
    target_pid: AtomicU32,
    /// Monotonic count of presents seen for `target_pid`.
    present_count: AtomicU64,
    /// Most recent presents-per-second sample.
    current_fps: AtomicU32,
    stop_flag: AtomicBool,
}

/// The live ETW session + sampler threads for one enabled stretch.
struct FpsRuntime {
    shared: Arc<FpsShared>,
    etw_thread: Option<JoinHandle<()>>,
    sampler_thread: Option<JoinHandle<()>>,
}

impl FpsRuntime {
    fn stop(&mut self) {
        self.shared.stop_flag.store(true, Ordering::SeqCst);
        // Stopping the session unblocks the blocking `ProcessTrace` call. Skip
        // when there's no ETW thread (e.g. inert test runtimes) so we don't
        // fire a stray `ControlTraceW` at an unrelated session.
        if self.etw_thread.is_some() {
            stop_existing_session();
        }
        if let Some(h) = self.etw_thread.take() {
            let _ = h.join();
        }
        if let Some(h) = self.sampler_thread.take() {
            let _ = h.join();
        }
    }
}

/// Anti-cheat-safe FPS source. While enabled it owns a real-time ETW session
/// (counts DXGI presents) plus a 1-second sampler that turns the running count
/// into FPS.
///
/// DEMAND-DRIVEN: the ETW callback fires for every present from every process
/// system-wide, which is real overhead on weak machines — so nothing runs
/// until `set_enabled(true)` (the in-game overlay being on), and disabling the
/// overlay tears the session down again.
pub struct FpsMonitor {
    runtime: std::sync::Mutex<Option<FpsRuntime>>,
    target_pid: AtomicU32,
}

impl FpsMonitor {
    /// An idle monitor: no ETW session, no threads, FPS reads 0.
    pub fn new() -> Self {
        Self {
            runtime: std::sync::Mutex::new(None),
            target_pid: AtomicU32::new(0),
        }
    }

    /// Start or stop the ETW session + sampler. Idempotent and cheap when the
    /// state already matches, so callers may invoke it on every settings save.
    /// Starting never fails: if ETW can't start (e.g. not elevated) the
    /// supervisor retries and FPS stays 0.
    pub fn set_enabled(&self, enabled: bool) {
        let Ok(mut runtime) = self.runtime.lock() else {
            return;
        };
        if enabled == runtime.is_some() {
            return;
        }

        if !enabled {
            if let Some(mut active) = runtime.take() {
                active.stop();
                log::info!("FPS monitor stopped (overlay disabled)");
            }
            return;
        }

        let shared = Arc::new(FpsShared {
            target_pid: AtomicU32::new(self.target_pid.load(Ordering::Acquire)),
            present_count: AtomicU64::new(0),
            current_fps: AtomicU32::new(0),
            stop_flag: AtomicBool::new(false),
        });

        let etw_thread = {
            let shared = shared.clone();
            std::thread::Builder::new()
                .name("etw-fps-monitor".to_string())
                .spawn(move || supervise_etw_session(shared))
                .ok()
        };

        let sampler_thread = {
            let shared = shared.clone();
            std::thread::Builder::new()
                .name("fps-sampler".to_string())
                .spawn(move || run_sampler(shared))
                .ok()
        };

        log::info!("FPS monitor started (overlay enabled)");
        *runtime = Some(FpsRuntime {
            shared,
            etw_thread,
            sampler_thread,
        });
    }

    /// Point the monitor at a game process (0 to clear). Switching targets
    /// resets the window so a new game never inherits the old one's count.
    pub fn set_target_pid(&self, pid: u32) {
        self.target_pid.store(pid, Ordering::Release);
        let Ok(runtime) = self.runtime.lock() else {
            return;
        };
        let Some(active) = runtime.as_ref() else {
            return;
        };
        let prev = active.shared.target_pid.swap(pid, Ordering::Release);
        if prev != pid {
            active.shared.present_count.store(0, Ordering::Release);
            active.shared.current_fps.store(0, Ordering::Release);
        }
    }

    /// Latest presents-per-second for the target process (0 if disabled or
    /// none/unknown).
    pub fn current_fps(&self) -> u32 {
        let Ok(runtime) = self.runtime.lock() else {
            return 0;
        };
        runtime
            .as_ref()
            .map(|active| active.shared.current_fps.load(Ordering::Acquire))
            .unwrap_or(0)
    }
}

impl Default for FpsMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for FpsMonitor {
    fn drop(&mut self) {
        self.set_enabled(false);
    }
}

/// 1-second sampler: FPS = presents counted in the elapsed window. A light
/// 2-sample average smooths the jitter from ETW's ~1s buffer flushing at low
/// present rates (at real gaming framerates buffers fill sub-second anyway).
fn run_sampler(shared: Arc<FpsShared>) {
    let mut last_count = shared.present_count.load(Ordering::Acquire);
    let mut last_at = Instant::now();

    loop {
        // Interruptible ~1s sleep so shutdown is prompt.
        for _ in 0..10 {
            if shared.stop_flag.load(Ordering::Acquire) {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        let count = shared.present_count.load(Ordering::Acquire);
        let now = Instant::now();
        let elapsed = now.duration_since(last_at).as_secs_f64();
        last_at = now;

        if shared.target_pid.load(Ordering::Acquire) == 0 {
            shared.current_fps.store(0, Ordering::Release);
            last_count = count;
            continue;
        }

        let delta = count.saturating_sub(last_count);
        last_count = count;

        let raw = if elapsed > 0.0 {
            (delta as f64 / elapsed).round() as u32
        } else {
            0
        }
        .min(MAX_REPORTABLE_FPS);

        let prev = shared.current_fps.load(Ordering::Acquire);
        let smoothed = if prev == 0 { raw } else { (raw + prev) / 2 };
        shared.current_fps.store(smoothed, Ordering::Release);
    }
}

/// Supervisor: (re)start the ETW session with capped exponential backoff so a
/// transient failure (or starting before elevation) doesn't permanently kill
/// FPS. Mirrors the process watcher's supervisor.
fn supervise_etw_session(shared: Arc<FpsShared>) {
    const INITIAL_BACKOFF_MS: u64 = 1_000;
    const MAX_BACKOFF_MS: u64 = 30_000;
    const LONG_RUN_RESET_SECS: u64 = 60;
    let mut backoff_ms = INITIAL_BACKOFF_MS;

    while !shared.stop_flag.load(Ordering::Acquire) {
        let started = Instant::now();
        match run_etw_session(&shared) {
            Ok(()) => {
                log::info!("ETW FPS monitor exited normally");
                break;
            }
            Err(e) => {
                if started.elapsed() >= Duration::from_secs(LONG_RUN_RESET_SECS) {
                    backoff_ms = INITIAL_BACKOFF_MS;
                }
                // Only `warn`: failing here means "no FPS" (commonly just not
                // elevated), not a broken app.
                log::warn!(
                    "ETW FPS monitor unavailable: {}; retrying in {}ms",
                    e,
                    backoff_ms
                );
                let until = Instant::now() + Duration::from_millis(backoff_ms);
                while Instant::now() < until {
                    if shared.stop_flag.load(Ordering::Acquire) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
            }
        }
    }
}

/// Run one real-time ETW session, blocking in `ProcessTrace` until stopped.
fn run_etw_session(shared: &Arc<FpsShared>) -> Result<(), String> {
    stop_existing_session();

    unsafe {
        let session_name_wide: Vec<u16> = SESSION_NAME
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let properties_size =
            std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + (session_name_wide.len() * 2) + 2;
        let mut properties_buffer = vec![0u8; properties_size];
        let properties = properties_buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

        (*properties).Wnode.BufferSize = properties_size as u32;
        (*properties).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        (*properties).Wnode.ClientContext = 1; // QPC timestamps
        (*properties).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        (*properties).FlushTimer = 1; // flush every second for a live HUD
        (*properties).LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;

        let name_dest =
            (properties as *mut u8).add((*properties).LoggerNameOffset as usize) as *mut u16;
        std::ptr::copy_nonoverlapping(
            session_name_wide.as_ptr(),
            name_dest,
            session_name_wide.len(),
        );

        let mut session_handle = CONTROLTRACE_HANDLE::default();
        let result = StartTraceW(
            &mut session_handle,
            PCWSTR(session_name_wide.as_ptr()),
            properties,
        );
        if result != ERROR_SUCCESS {
            return Err(format!("StartTraceW failed: 0x{:08X}", result.0));
        }

        // Enable all DXGI keywords and filter to Present-start in the callback. A
        // zero keyword mask can miss non-default provider events on some
        // systems, which leaves the overlay showing "--" even though the trace
        // started correctly.
        let result = EnableTraceEx2(
            session_handle,
            &DXGI_PROVIDER_GUID,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
            TRACE_LEVEL_VERBOSE as u8,
            TRACE_MATCH_ANY_KEYWORD_ALL,
            0,
            0,
            None,
        );
        if result != ERROR_SUCCESS {
            ControlTraceW(
                session_handle,
                PCWSTR::null(),
                properties,
                EVENT_TRACE_CONTROL_STOP,
            );
            return Err(format!("EnableTraceEx2 failed: 0x{:08X}", result.0));
        }

        // The callback needs the shared state; hand it a heap Arc clone and free
        // it after ProcessTrace returns.
        let context_ptr = Box::into_raw(Box::new(shared.clone()));

        let mut logfile = EVENT_TRACE_LOGFILEW::default();
        logfile.LoggerName = PWSTR(session_name_wide.as_ptr() as *mut u16);
        logfile.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(present_event_callback);
        logfile.Context = context_ptr as *mut c_void;

        let trace_handle = OpenTraceW(&mut logfile);
        if trace_handle.Value == u64::MAX {
            drop(Box::from_raw(context_ptr));
            ControlTraceW(
                session_handle,
                PCWSTR::null(),
                properties,
                EVENT_TRACE_CONTROL_STOP,
            );
            return Err("OpenTraceW failed".to_string());
        }

        log::info!("ETW FPS monitor running (DXGI present trace)");

        let handles = [trace_handle];
        let result = ProcessTrace(&handles, None, None);

        CloseTrace(trace_handle);
        drop(Box::from_raw(context_ptr));
        ControlTraceW(
            session_handle,
            PCWSTR::null(),
            properties,
            EVENT_TRACE_CONTROL_STOP,
        );

        if result != ERROR_SUCCESS && !shared.stop_flag.load(Ordering::SeqCst) {
            return Err(format!("ProcessTrace failed: 0x{:08X}", result.0));
        }
    }

    Ok(())
}

/// Stop any existing session with our name (left over from a crash / restart).
fn stop_existing_session() {
    unsafe {
        let session_name_wide: Vec<u16> = SESSION_NAME
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let properties_size =
            std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + (session_name_wide.len() * 2) + 2;
        let mut properties_buffer = vec![0u8; properties_size];
        let properties = properties_buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;
        (*properties).Wnode.BufferSize = properties_size as u32;
        (*properties).LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;
        let name_dest =
            (properties as *mut u8).add((*properties).LoggerNameOffset as usize) as *mut u16;
        std::ptr::copy_nonoverlapping(
            session_name_wide.as_ptr(),
            name_dest,
            session_name_wide.len(),
        );
        ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            PCWSTR(session_name_wide.as_ptr()),
            properties,
            EVENT_TRACE_CONTROL_STOP,
        );
    }
}

/// ETW callback — counts a present-start for the target process. Kept to a
/// handful of atomic ops since it fires for every present from every process
/// system-wide.
unsafe extern "system" fn present_event_callback(event_record: *mut EVENT_RECORD) {
    if event_record.is_null() {
        return;
    }
    let record = &*event_record;
    let ctx = record.UserContext as *const Arc<FpsShared>;
    if ctx.is_null() {
        return;
    }
    let shared = &*ctx;

    if shared.stop_flag.load(Ordering::Relaxed) {
        return;
    }
    if record.EventHeader.ProviderId != DXGI_PROVIDER_GUID {
        return;
    }
    let descriptor = record.EventHeader.EventDescriptor;
    if !DXGI_PRESENT_TASKS.contains(&descriptor.Task) || descriptor.Opcode != ETW_OPCODE_START {
        return;
    }
    let target = shared.target_pid.load(Ordering::Acquire);
    if target == 0 || record.EventHeader.ProcessId != target {
        return;
    }
    shared.present_count.fetch_add(1, Ordering::Release);
}

#[cfg(test)]
impl FpsMonitor {
    /// A monitor that is "enabled" but has no ETW session or threads — for
    /// unit-testing the target / FPS bookkeeping without touching real tracing.
    fn inert_active() -> Self {
        Self {
            runtime: std::sync::Mutex::new(Some(FpsRuntime {
                shared: Arc::new(FpsShared {
                    target_pid: AtomicU32::new(0),
                    present_count: AtomicU64::new(0),
                    current_fps: AtomicU32::new(0),
                    stop_flag: AtomicBool::new(true),
                }),
                etw_thread: None,
                sampler_thread: None,
            })),
            target_pid: AtomicU32::new(0),
        }
    }

    fn test_shared(&self) -> Arc<FpsShared> {
        self.runtime
            .lock()
            .unwrap()
            .as_ref()
            .expect("test monitor must be active")
            .shared
            .clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn switching_target_resets_the_window() {
        let monitor = FpsMonitor::inert_active();
        let shared = monitor.test_shared();
        // Simulate counted presents, then a target switch.
        shared.present_count.store(500, Ordering::Release);
        shared.current_fps.store(240, Ordering::Release);
        monitor.set_target_pid(4321);
        assert_eq!(shared.present_count.load(Ordering::Acquire), 0);
        assert_eq!(monitor.current_fps(), 0);
    }

    #[test]
    fn same_target_keeps_the_window() {
        let monitor = FpsMonitor::inert_active();
        let shared = monitor.test_shared();
        monitor.set_target_pid(1000);
        shared.present_count.store(120, Ordering::Release);
        shared.current_fps.store(120, Ordering::Release);
        // Re-pointing at the same PID must not wipe the running count.
        monitor.set_target_pid(1000);
        assert_eq!(shared.present_count.load(Ordering::Acquire), 120);
        assert_eq!(monitor.current_fps(), 120);
    }

    #[test]
    fn no_target_reports_zero_fps() {
        let monitor = FpsMonitor::inert_active();
        // Default target is 0 (no game) -> never reports FPS.
        assert_eq!(monitor.current_fps(), 0);
    }

    #[test]
    fn disabled_monitor_is_a_safe_no_op() {
        let monitor = FpsMonitor::new();
        // No session, no threads: reads are 0 and writes don't panic. The
        // target is still remembered so enabling later can start hot.
        monitor.set_target_pid(1234);
        assert_eq!(monitor.current_fps(), 0);
        // Disabling an already-disabled monitor is fine.
        monitor.set_enabled(false);
        assert_eq!(monitor.current_fps(), 0);
    }
}
