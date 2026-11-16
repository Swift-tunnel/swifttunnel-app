//! ETW FPS monitor using events emitted outside the game process.
//!
//! Estimates a game's frame submission rate by counting Microsoft-Windows-DXGI
//! Present events emitted by the target process. This does not read the game's
//! memory or inject hooks. PresentMon uses the same provider, but its full
//! presentation analysis is more detailed than this lightweight counter.
//!
//! Each call to `IDXGISwapChain::Present` logs a DXGI "Present Start" event
//! (id 42) in the *calling* process's context. Counting those whose
//! `EventHeader.ProcessId` is the game and dividing by elapsed time gives
//! presents-per-second. This is not a measurement of displayed frames. Mirrors
//! the real-time ETW session pattern in
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

use windows::Win32::Foundation::{
    ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED, ERROR_SUCCESS, WIN32_ERROR,
};
use windows::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, CloseTrace, ControlTraceW, ENABLE_TRACE_PARAMETERS,
    ENABLE_TRACE_PARAMETERS_VERSION_2, EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_FILTER_DESCRIPTOR,
    EVENT_FILTER_TYPE_EVENT_ID, EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_LOGFILEW,
    EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, EnableTraceEx2, OpenTraceW,
    PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, ProcessTrace, StartTraceW,
    TRACE_LEVEL_VERBOSE, WNODE_FLAG_TRACED_GUID,
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

// Present-start IDs for the four tasks above in the DXGI manifest. Filter these
// in ETW as well as checking task, opcode and PID in the callback, avoiding the
// delivery of unrelated swap-chain operations and matching stop events.
const DXGI_PRESENT_EVENT_IDS: [u16; 4] = [42, 178, 854, 882];

// EVENT_FILTER_EVENT_ID has a variable-length trailing USHORT array. Keep the
// complete native layout in one aligned allocation for EnableTraceEx2.
#[repr(C)]
struct PresentEventFilter {
    filter_in: bool,
    reserved: u8,
    count: u16,
    events: [u16; 4],
}

fn enable_present_events(
    mut enable: impl FnMut(Option<&ENABLE_TRACE_PARAMETERS>) -> WIN32_ERROR,
) -> WIN32_ERROR {
    let filter = PresentEventFilter {
        filter_in: true,
        reserved: 0,
        count: DXGI_PRESENT_EVENT_IDS.len() as u16,
        events: DXGI_PRESENT_EVENT_IDS,
    };
    let mut descriptor = EVENT_FILTER_DESCRIPTOR {
        Ptr: std::ptr::from_ref(&filter) as u64,
        Size: std::mem::size_of_val(&filter) as u32,
        Type: EVENT_FILTER_TYPE_EVENT_ID,
    };
    let parameters = ENABLE_TRACE_PARAMETERS {
        Version: ENABLE_TRACE_PARAMETERS_VERSION_2,
        EnableFilterDesc: &mut descriptor,
        FilterDescCount: 1,
        ..Default::default()
    };
    let result = enable(Some(&parameters));
    // Keep FPS available if a provider/platform rejects event-ID filtering.
    // Permission and session errors still follow the ordinary retry policy.
    if result == ERROR_INVALID_PARAMETER || result == ERROR_NOT_SUPPORTED {
        enable(None)
    } else {
        result
    }
}

/// Session behind the in-game overlay's FPS readout.
const OVERLAY_SESSION_NAME: &str = "SwiftTunnelFpsMonitor";

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
    window: parking_lot::Mutex<FpsWindow>,
    stop_flag: AtomicBool,
    /// ETW session this monitor owns.
    session_name: &'static str,
}

struct FpsWindow {
    count: u64,
    at: Instant,
}
impl FpsWindow {
    fn new(at: Instant) -> Self {
        Self { count: 0, at }
    }
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
            stop_existing_session(self.shared.session_name);
        }
        if let Some(h) = self.etw_thread.take() {
            let _ = h.join();
        }
        if let Some(h) = self.sampler_thread.take() {
            let _ = h.join();
        }
    }
}

/// External FPS source. While enabled it owns a real-time ETW session
/// (counts DXGI presents) plus a 1-second sampler that turns the running count
/// into FPS.
///
/// DEMAND-DRIVEN: the ETW callback receives present events from every process
/// system-wide, so nothing runs
/// until `set_enabled(true)` and `set_enabled(false)` tears the session down
/// again. The overlay enables its monitor while it shows FPS. Connecting a
/// tunnel does not start an additional trace for diagnostic logging.
pub struct FpsMonitor {
    runtime: std::sync::Mutex<Option<FpsRuntime>>,
    requested_enabled: AtomicBool,
    target_pid: AtomicU32,
    latest_observation: AtomicU64,
    session_name: &'static str,
}

#[derive(Clone, Copy)]
pub struct FpsObservation {
    generation: u64,
    pid: Option<u32>,
}

impl FpsMonitor {
    /// The overlay's monitor, idle: no ETW session, no threads, FPS reads 0.
    pub fn new() -> Self {
        Self::named(OVERLAY_SESSION_NAME)
    }

    /// An idle monitor that traces under its own ETW session name. Any other
    /// monitor running at the same time must use a different name.
    pub fn named(session_name: &'static str) -> Self {
        Self {
            runtime: std::sync::Mutex::new(None),
            requested_enabled: AtomicBool::new(false),
            target_pid: AtomicU32::new(0),
            latest_observation: AtomicU64::new(0),
            session_name,
        }
    }

    /// Start or stop the ETW session + sampler. Idempotent and cheap when the
    /// state already matches, so callers may invoke it on every settings save.
    /// No session starts without a target. If ETW is unavailable its supervisor
    /// retries; worker creation failures leave no partial runtime behind.
    pub fn set_enabled(&self, enabled: bool) {
        let Ok(mut runtime) = self.runtime.lock() else {
            return;
        };
        self.requested_enabled.store(enabled, Ordering::Release);
        self.reconcile_runtime(&mut runtime);
    }

    fn reconcile_runtime(&self, runtime: &mut Option<FpsRuntime>) {
        let enabled = self.requested_enabled.load(Ordering::Acquire)
            && self.target_pid.load(Ordering::Acquire) != 0;
        if enabled == runtime.is_some() {
            return;
        }

        if !enabled {
            if let Some(mut active) = runtime.take() {
                active.stop();
                log::info!("FPS monitor stopped ({})", self.session_name);
            }
            return;
        }

        let shared = Arc::new(FpsShared {
            target_pid: AtomicU32::new(self.target_pid.load(Ordering::Acquire)),
            present_count: AtomicU64::new(0),
            current_fps: AtomicU32::new(0),
            window: parking_lot::Mutex::new(FpsWindow::new(Instant::now())),
            stop_flag: AtomicBool::new(false),
            session_name: self.session_name,
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

        let mut active = FpsRuntime {
            shared,
            etw_thread,
            sampler_thread,
        };
        if active.etw_thread.is_none() || active.sampler_thread.is_none() {
            active.stop();
            log::warn!("FPS monitor worker could not start ({})", self.session_name);
            return;
        }
        log::info!("FPS monitor started ({})", self.session_name);
        *runtime = Some(active);
    }

    /// Point the monitor at a game process (0 to clear). Switching targets
    /// resets the window so a new game never inherits the old one's count.
    #[cfg(test)]
    fn set_target_pid(&self, pid: u32) {
        let Ok(mut runtime) = self.runtime.lock() else {
            return;
        };
        self.set_target_pid_locked(&mut runtime, pid);
    }

    fn set_target_pid_locked(&self, runtime: &mut Option<FpsRuntime>, pid: u32) {
        self.target_pid.store(pid, Ordering::Release);
        // The saved preference owns permission to trace; a poll supplies only
        // presence. No trace runs while Roblox is closed, and a late poll
        // cannot override a disabled preference.
        self.reconcile_runtime(runtime);
        let Some(active) = runtime.as_ref() else {
            return;
        };
        // Serialize the once-per-second sample with target changes, without
        // adding a lock to the high-frequency ETW event callback.
        let mut window = active.shared.window.lock();
        let prev = active.shared.target_pid.swap(pid, Ordering::Release);
        if prev != pid {
            active.shared.present_count.store(0, Ordering::Release);
            active.shared.current_fps.store(0, Ordering::Release);
            *window = FpsWindow::new(Instant::now());
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

    /// Record order while the caller still owns its process-discovery lock.
    /// This never starts/stops a trace or acquires the trace lifecycle lock.
    pub fn observe_process(&self, pid: Option<u32>) -> FpsObservation {
        FpsObservation {
            generation: self
                .latest_observation
                .fetch_add(1, Ordering::AcqRel)
                .wrapping_add(1),
            pid,
        }
    }

    /// A poll supplies target presence, never permission to enable tracing.
    pub fn sample_for_process(&self, observation: FpsObservation, requested: bool) -> u32 {
        let Ok(mut runtime) = self.runtime.lock() else {
            return 0;
        };
        // Check after acquiring the lifecycle lock. Another metrics query can
        // observe a new player while this call waits for trace shutdown.
        if observation.generation != self.latest_observation.load(Ordering::Acquire) {
            return 0;
        }
        self.set_target_pid_locked(&mut runtime, observation.pid.unwrap_or(0));
        if requested && observation.pid.is_some() {
            runtime
                .as_ref()
                .map(|active| active.shared.current_fps.load(Ordering::Acquire))
                .unwrap_or(0)
        } else {
            0
        }
    }

    #[cfg(test)]
    fn test_sample_for_process(&self, pid: Option<u32>, requested: bool) -> u32 {
        self.sample_for_process(self.observe_process(pid), requested)
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
    loop {
        // Interruptible ~1s sleep so shutdown is prompt.
        for _ in 0..10 {
            if shared.stop_flag.load(Ordering::Acquire) {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }

        sample_window(&shared, Instant::now());
    }
}

fn sample_window(shared: &FpsShared, now: Instant) {
    let mut window = shared.window.lock();
    // A target reset can win the lock after the sampler captured its clock.
    // Do not consume new frames using a timestamp from before that reset.
    if now <= window.at {
        return;
    }
    let count = shared.present_count.load(Ordering::Acquire);
    let elapsed = now.saturating_duration_since(window.at).as_secs_f64();
    window.at = now;

    if shared.target_pid.load(Ordering::Acquire) == 0 {
        shared.current_fps.store(0, Ordering::Release);
        window.count = count;
        return;
    }

    let delta = count.saturating_sub(window.count);
    window.count = count;

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

fn reset_failed_session_sample(shared: &FpsShared, now: impl FnOnce() -> Instant) {
    let mut window = shared.window.lock();
    // Retire old samples before clearing the failed trace's frames and history.
    // Clock the reset under this lock so a waiting old sample remains stale.
    let now = now();
    shared.present_count.store(0, Ordering::Release);
    shared.current_fps.store(0, Ordering::Release);
    *window = FpsWindow::new(now);
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
                reset_failed_session_sample(&shared, Instant::now);
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
#[allow(clippy::field_reassign_with_default)]
fn run_etw_session(shared: &Arc<FpsShared>) -> Result<(), String> {
    stop_existing_session(shared.session_name);

    unsafe {
        let session_name_wide: Vec<u16> = shared
            .session_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let properties_size =
            std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + (session_name_wide.len() * 2) + 2;
        let mut properties_buffer = crate::etw_lifecycle::trace_properties_storage(properties_size);
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

        // Keep all DXGI keywords, but deliver only the present-start IDs. A
        // zero keyword mask can miss non-default provider events on some
        // systems, which leaves the overlay showing "--" even though the trace
        // started correctly.
        let result = enable_present_events(|parameters| {
            EnableTraceEx2(
                session_handle,
                &DXGI_PROVIDER_GUID,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
                TRACE_LEVEL_VERBOSE as u8,
                TRACE_MATCH_ANY_KEYWORD_ALL,
                0,
                0,
                parameters.map(std::ptr::from_ref),
            )
        });
        if result != ERROR_SUCCESS {
            let _ = ControlTraceW(
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

        // EVENT_TRACE_LOGFILEW carries anonymous unions, which a struct
        // literal cannot initialise field by field. The stepwise form is the
        // only one that compiles here.
        let mut logfile = EVENT_TRACE_LOGFILEW::default();
        logfile.LoggerName = PWSTR(session_name_wide.as_ptr() as *mut u16);
        logfile.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(present_event_callback);
        logfile.Context = context_ptr as *mut c_void;

        let trace_handle = OpenTraceW(&mut logfile);
        if trace_handle.Value == u64::MAX {
            drop(Box::from_raw(context_ptr));
            let _ = ControlTraceW(
                session_handle,
                PCWSTR::null(),
                properties,
                EVENT_TRACE_CONTROL_STOP,
            );
            return Err("OpenTraceW failed".to_string());
        }

        log::info!("ETW FPS monitor running (DXGI present trace)");

        let handles = [trace_handle];
        let result = crate::etw_lifecycle::process_trace_unless_stopped(&shared.stop_flag, || {
            ProcessTrace(&handles, None, None)
        });

        let _ = CloseTrace(trace_handle);
        drop(Box::from_raw(context_ptr));
        let _ = ControlTraceW(
            session_handle,
            PCWSTR::null(),
            properties,
            EVENT_TRACE_CONTROL_STOP,
        );

        crate::etw_lifecycle::trace_session_result(&shared.stop_flag, result)?;
    }

    Ok(())
}

/// Stop any existing session with this name (left over from a crash / restart).
fn stop_existing_session(session_name: &str) {
    unsafe {
        let session_name_wide: Vec<u16> = session_name
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let properties_size =
            std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + (session_name_wide.len() * 2) + 2;
        let mut properties_buffer = crate::etw_lifecycle::trace_properties_storage(properties_size);
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
        let result = ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            PCWSTR(session_name_wide.as_ptr()),
            properties,
            EVENT_TRACE_CONTROL_STOP,
        );
        crate::etw_lifecycle::report_trace_stop_result(session_name, result);
    }
}

/// ETW callback — counts a present-start for the target process. Kept to a
/// handful of atomic ops since it fires for every present from every process
/// system-wide.
unsafe extern "system" fn present_event_callback(event_record: *mut EVENT_RECORD) {
    unsafe {
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
                    window: parking_lot::Mutex::new(FpsWindow::new(Instant::now())),
                    stop_flag: AtomicBool::new(true),
                    session_name: OVERLAY_SESSION_NAME,
                }),
                etw_thread: None,
                sampler_thread: None,
            })),
            requested_enabled: AtomicBool::new(true),
            target_pid: AtomicU32::new(0),
            latest_observation: AtomicU64::new(0),
            session_name: OVERLAY_SESSION_NAME,
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
    fn late_observations_cannot_clear_or_retarget_a_newer_players_trace() {
        for old_pid in [None, Some(1000)] {
            let monitor = FpsMonitor::inert_active();
            let old = monitor.observe_process(old_pid);
            let fresh = monitor.observe_process(Some(2000));
            assert_eq!(monitor.sample_for_process(fresh, true), 0);
            let shared = monitor.test_shared();
            shared.current_fps.store(240, Ordering::Release);
            assert_eq!(monitor.sample_for_process(old, false), 0);
            assert_eq!(monitor.target_pid.load(Ordering::Acquire), 2000);
            assert!(monitor.runtime.lock().unwrap().is_some());
            assert_eq!(monitor.current_fps(), 240);
        }
    }

    #[test]
    fn late_observations_are_checked_after_waiting_for_the_trace_lock() {
        let monitor = Arc::new(FpsMonitor::inert_active());
        monitor.set_target_pid(1000);
        let old = monitor.observe_process(None);
        let held = monitor.runtime.lock().unwrap();
        let waiting = monitor.clone();
        let worker = std::thread::spawn(move || waiting.sample_for_process(old, false));
        // Recording presence must not wait behind trace setup/shutdown.
        let observing = monitor.clone();
        let (observed, observed_rx) = std::sync::mpsc::channel();
        let observer = std::thread::spawn(move || {
            let _ = observed.send(observing.observe_process(Some(2000)));
        });
        let fresh = observed_rx.recv_timeout(Duration::from_secs(2));
        drop(held);
        observer.join().unwrap();
        assert_eq!(worker.join().unwrap(), 0);
        let fresh = fresh.expect("recording presence must not take the lifecycle lock");
        assert_eq!(monitor.target_pid.load(Ordering::Acquire), 1000);
        assert!(monitor.runtime.lock().unwrap().is_some());
        assert_eq!(monitor.sample_for_process(fresh, true), 0);
        assert_eq!(monitor.target_pid.load(Ordering::Acquire), 2000);
    }

    #[test]
    fn a_sample_clocked_before_a_reset_cannot_consume_the_new_frames() {
        let monitor = FpsMonitor::inert_active();
        monitor.set_target_pid(1000);
        let shared = monitor.test_shared();
        let at = shared.window.lock().at;
        shared.present_count.store(120, Ordering::Release);
        sample_window(&shared, at - Duration::from_nanos(1));
        assert_eq!(monitor.current_fps(), 0);
        sample_window(&shared, at + Duration::from_secs(1));
        assert_eq!(monitor.current_fps(), 120);
    }

    #[test]
    fn private_trace_outage_clears_the_previous_sample_and_pending_frames() {
        let monitor = FpsMonitor::inert_active();
        let observation = monitor.observe_process(Some(1000));
        monitor.sample_for_process(observation, true);
        let shared = monitor.test_shared();
        let at = shared.window.lock().at;
        shared.present_count.store(240, Ordering::Release);
        sample_window(&shared, at + Duration::from_secs(1));
        assert_eq!(monitor.current_fps(), 240);
        // These previous-session frames were not sampled before the failure.
        shared.present_count.store(300, Ordering::Release);
        let failed_at = at + Duration::from_secs(2);
        reset_failed_session_sample(&shared, || failed_at);
        assert_eq!(monitor.current_fps(), 0);
        assert_eq!(shared.present_count.load(Ordering::Acquire), 0);
        assert_eq!(shared.window.lock().count, 0);
        assert_eq!(shared.window.lock().at, failed_at);
        assert_eq!(shared.target_pid.load(Ordering::Acquire), 1000);
        assert_eq!(monitor.target_pid.load(Ordering::Acquire), 1000);
        assert_eq!(
            monitor.latest_observation.load(Ordering::Acquire),
            observation.generation
        );
        assert_eq!(monitor.sample_for_process(observation, true), 0);
        sample_window(&shared, failed_at + Duration::from_secs(1));
        assert_eq!(monitor.current_fps(), 0);
        // A recovered trace starts a fresh sample, without the old smoothing.
        shared.present_count.store(120, Ordering::Release);
        sample_window(&shared, failed_at + Duration::from_secs(2));
        assert_eq!(monitor.current_fps(), 120);
    }

    #[test]
    fn private_trace_outage_rejects_a_sample_clocked_before_the_reset() {
        let monitor = FpsMonitor::inert_active();
        monitor.set_target_pid(1000);
        let shared = monitor.test_shared();
        let at = shared.window.lock().at;
        shared.present_count.store(240, Ordering::Release);
        sample_window(&shared, at + Duration::from_secs(1));
        let failed_at = at + Duration::from_secs(2);
        reset_failed_session_sample(&shared, || failed_at);
        shared.present_count.store(180, Ordering::Release);
        sample_window(&shared, failed_at - Duration::from_nanos(1));
        assert_eq!(monitor.current_fps(), 0);
        assert_eq!(shared.present_count.load(Ordering::Acquire), 180);
        sample_window(&shared, failed_at + Duration::from_secs(1));
        assert_eq!(monitor.current_fps(), 180);
    }

    #[test]
    fn a_new_player_does_not_inherit_the_previous_counter_baseline() {
        let monitor = FpsMonitor::inert_active();
        let shared = monitor.test_shared();
        monitor.set_target_pid(1000);
        let at = shared.window.lock().at;
        shared.present_count.store(120, Ordering::Release);
        sample_window(&shared, at + Duration::from_secs(1));
        assert_eq!(monitor.current_fps(), 120);
        monitor.set_target_pid(2000);
        let at = shared.window.lock().at;
        shared.present_count.store(240, Ordering::Release);
        sample_window(&shared, at + Duration::from_secs(1));
        assert_eq!(monitor.current_fps(), 240);
    }

    #[test]
    fn an_older_sample_must_publish_before_the_new_target_is_reset() {
        let monitor = Arc::new(FpsMonitor::inert_active());
        monitor.set_target_pid(1000);
        let shared = monitor.test_shared();
        let held_sample = shared.window.lock();
        let changing = monitor.clone();
        let worker = std::thread::spawn(move || changing.set_target_pid(2000));
        let deadline = Instant::now() + Duration::from_secs(2);
        while monitor.target_pid.load(Ordering::Acquire) != 2000 && Instant::now() < deadline {
            std::thread::yield_now();
        }
        let entered = monitor.target_pid.load(Ordering::Acquire);
        let sample_target = shared.target_pid.load(Ordering::Acquire);
        // The old sampler finishes while it owns the shared sampling window.
        shared.current_fps.store(180, Ordering::Release);
        drop(held_sample);
        worker.join().unwrap();
        assert_eq!(entered, 2000);
        assert_eq!(
            sample_target, 1000,
            "the target must wait for an active sample"
        );
        assert_eq!(
            monitor.current_fps(),
            0,
            "a previous player's sample survived the reset"
        );
    }

    #[test]
    fn native_filter_preserves_the_counted_present_events_and_excludes_noise() {
        use windows::Win32::System::Diagnostics::Etw::EVENT_FILTER_EVENT_ID;

        assert_eq!(
            std::mem::offset_of!(PresentEventFilter, events),
            std::mem::offset_of!(EVENT_FILTER_EVENT_ID, Events)
        );
        let result = enable_present_events(|parameters| {
            let parameters = parameters.expect("event filtering should be requested");
            assert_eq!(parameters.Version, ENABLE_TRACE_PARAMETERS_VERSION_2);
            assert_eq!(parameters.FilterDescCount, 1);
            let descriptor = unsafe { &*parameters.EnableFilterDesc };
            assert_eq!(descriptor.Type, EVENT_FILTER_TYPE_EVENT_ID);
            assert_eq!(descriptor.Size as usize, 4 + 4 * 2);
            let filter = unsafe { &*(descriptor.Ptr as *const PresentEventFilter) };
            assert!(filter.filter_in);
            assert_eq!(filter.reserved, 0);
            assert_eq!(filter.count, 4);

            // IDs/tasks from the Windows DXGI provider manifest, including the
            // newer partner paths already supported by the callback.
            for (id, task) in [(42, 9), (178, 80), (854, 468), (882, 482)] {
                assert!(DXGI_PRESENT_TASKS.contains(&task));
                assert!(filter.events.contains(&id));
            }
            // Present-stop, swap-chain creation and GetLastPresentCount.
            for id in [43, 179, 855, 883, 10, 196] {
                assert!(!filter.events.contains(&id));
            }
            ERROR_SUCCESS
        });
        assert_eq!(result, ERROR_SUCCESS);
    }

    #[test]
    fn unsupported_filter_falls_back_but_real_enable_failures_are_preserved() {
        use windows::Win32::Foundation::ERROR_ACCESS_DENIED;

        for first_result in [ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED] {
            let mut calls = Vec::new();
            let result = enable_present_events(|parameters| {
                calls.push(parameters.is_some());
                if parameters.is_some() {
                    first_result
                } else {
                    ERROR_SUCCESS
                }
            });
            assert_eq!(result, ERROR_SUCCESS);
            assert_eq!(calls, [true, false]);
        }
        let mut calls = 0;
        let result = enable_present_events(|_| {
            calls += 1;
            ERROR_ACCESS_DENIED
        });
        assert_eq!(result, ERROR_ACCESS_DENIED);
        assert_eq!(calls, 1);
    }

    #[test]
    fn late_metrics_poll_cannot_restart_a_disabled_trace() {
        let monitor = FpsMonitor::inert_active();
        monitor.set_enabled(false);
        assert_eq!(monitor.test_sample_for_process(Some(1234), true), 0);
        assert!(monitor.runtime.lock().unwrap().is_none());
    }

    #[test]
    fn an_enabled_fps_preference_does_not_start_threads_without_a_game() {
        let monitor = FpsMonitor::new();
        monitor.set_enabled(true);
        for _ in 0..10 {
            assert_eq!(monitor.test_sample_for_process(None, true), 0);
        }
        assert!(monitor.requested_enabled.load(Ordering::Acquire));
        assert!(monitor.runtime.lock().unwrap().is_none());
    }

    #[test]
    fn closing_the_game_stops_the_runtime_and_stale_polls_cannot_override_disable() {
        let monitor = FpsMonitor::inert_active();
        monitor.set_target_pid(1234);
        assert!(monitor.runtime.lock().unwrap().is_some());
        monitor.test_sample_for_process(None, true);
        assert!(monitor.runtime.lock().unwrap().is_none());
        assert!(monitor.requested_enabled.load(Ordering::Acquire));
        monitor.set_enabled(false);
        assert_eq!(monitor.test_sample_for_process(Some(1234), true), 0);
        assert!(monitor.runtime.lock().unwrap().is_none());
    }

    #[test]
    fn non_fps_poll_does_not_stop_another_consumers_trace() {
        let monitor = FpsMonitor::inert_active();
        monitor.set_target_pid(1234);
        monitor
            .test_shared()
            .current_fps
            .store(120, Ordering::Release);
        assert_eq!(monitor.test_sample_for_process(Some(1234), false), 0);
        assert!(monitor.runtime.lock().unwrap().is_some());
        assert_eq!(monitor.test_sample_for_process(Some(1234), true), 120);
    }

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
    fn separately_named_monitors_do_not_share_session_identity() {
        // Each session start stops whatever runs under its name, so a shared
        // name makes the two monitors stop each other.
        let other = FpsMonitor::named("SwiftTunnelFpsTest");
        assert_ne!(FpsMonitor::new().session_name, other.session_name);
        assert_eq!(other.session_name, "SwiftTunnelFpsTest");
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
