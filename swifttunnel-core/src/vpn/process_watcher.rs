//! ETW Process Watcher - Instant Process Detection
//!
//! Uses Windows Event Tracing (ETW) to detect process creation INSTANTLY,
//! before the process makes any network connections.
//!
//! This solves the race condition where:
//! 1. Browser launches RobloxPlayerBeta.exe via roblox-player:// protocol
//! 2. Roblox immediately tries to connect to game server
//! 3. Our 50ms polling hasn't detected the process yet
//! 4. First packets bypass VPN → Error 279
//!
//! With ETW, we get notified within microseconds of process creation,
//! allowing us to add the process to the tunnel list BEFORE it makes
//! any network connections.
//!
//! ## Provider
//! Microsoft-Windows-Kernel-Process (GUID: 22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716)
//! Event ID 1 = Process Start
//!
//! ## Requirements
//! - Administrator privileges (for kernel-level ETW provider)
//! - Windows 10 or later

use crate::process_names::process_name_matches_any_tunnel_app;
use crossbeam_channel::{Receiver, Sender, bounded};
use parking_lot::RwLock;
use std::collections::HashSet;
use std::ffi::c_void;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
use windows::Win32::System::Diagnostics::Etw::{
    CONTROLTRACE_HANDLE, CloseTrace, ControlTraceW, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
    EVENT_RECORD, EVENT_TRACE_CONTROL_STOP, EVENT_TRACE_FLAG_PROCESS, EVENT_TRACE_LOGFILEW,
    EVENT_TRACE_PROPERTIES, EVENT_TRACE_REAL_TIME_MODE, EnableTraceEx2, OpenTraceW,
    PROCESS_TRACE_MODE_EVENT_RECORD, PROCESS_TRACE_MODE_REAL_TIME, PROCESSTRACE_HANDLE,
    ProcessTrace, StartTraceW, TRACE_LEVEL_INFORMATION, WNODE_FLAG_TRACED_GUID,
};
use windows::core::{GUID, PCWSTR, PWSTR};

/// Microsoft-Windows-Kernel-Process provider GUID
/// This is the kernel provider that emits process start/stop events
const KERNEL_PROCESS_GUID: GUID = GUID::from_values(
    0x22fb2cd6,
    0x0e7b,
    0x422b,
    [0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16],
);

/// Event ID for process start
const EVENT_ID_PROCESS_START: u16 = 1;

/// Keyword for process events
const WINEVENT_KEYWORD_PROCESS: u64 = 0x10;

/// Session name for our ETW trace
const SESSION_NAME: &str = "SwiftTunnelProcessWatcher";

/// Event sent when a new process is detected
#[derive(Debug, Clone)]
pub struct ProcessStartEvent {
    /// Process ID of the new process
    pub pid: u32,
    /// Process name (just the exe name, not full path)
    pub name: String,
    /// Full image path (NT path format, e.g., \Device\HarddiskVolume3\...\RobloxPlayerBeta.exe)
    /// Used for WFP filtering. May be empty if we couldn't get it.
    pub image_path: String,
    /// Parent process ID
    pub parent_pid: u32,
}

/// ETW Process Watcher
///
/// Monitors for process creation events in real-time using ETW.
/// When a process matching the watch list starts, sends notification
/// via channel for immediate action.
pub struct ProcessWatcher {
    /// Channel to receive process start events
    receiver: Receiver<ProcessStartEvent>,
    /// Handle to stop the watcher
    stop_flag: Arc<AtomicBool>,
    /// Thread handle
    thread_handle: Option<std::thread::JoinHandle<()>>,
}

impl ProcessWatcher {
    /// Create and start a new process watcher
    ///
    /// # Arguments
    /// * `watch_list` - Process names to watch for (lowercase, e.g., "robloxplayerbeta.exe")
    ///
    /// # Returns
    /// The watcher instance and a receiver for process events
    pub fn start(watch_list: HashSet<String>) -> Result<Self, String> {
        let (sender, receiver) = bounded(100);
        let stop_flag = Arc::new(AtomicBool::new(false));

        // Seed the watcher with any matching processes that are ALREADY running before
        // SwiftTunnel connected. ETW only fires on process *start* events, so a game
        // launched before the tunnel — the most common "connected but no game traffic
        // flows" cause — would otherwise never get registered. Run synchronously so the
        // synthetic events are queued before we return to the caller.
        enumerate_running_matching_processes(&sender, &watch_list);

        let stop_flag_clone = stop_flag.clone();
        let watch_list = Arc::new(RwLock::new(watch_list));
        let watch_list_clone = watch_list.clone();

        let thread_handle = std::thread::Builder::new()
            .name("etw-process-watcher".to_string())
            .spawn(move || {
                // Supervisor loop: restart the ETW session on error with
                // capped exponential backoff. Without this, a one-time ETW
                // failure leaves the process cache permanently stale — new
                // game launches never get tunneled and the user has no
                // indication why.
                const INITIAL_BACKOFF_MS: u64 = 1_000;
                const MAX_BACKOFF_MS: u64 = 30_000;
                const LONG_RUN_RESET_SECS: u64 = 60;
                let mut backoff_ms = INITIAL_BACKOFF_MS;

                while !stop_flag_clone.load(Ordering::Acquire) {
                    let started_at = std::time::Instant::now();
                    match run_etw_session(
                        sender.clone(),
                        stop_flag_clone.clone(),
                        watch_list_clone.clone(),
                    ) {
                        Ok(()) => {
                            // Normal exit (stop was requested inside the session).
                            log::info!("ETW process watcher exited normally");
                            break;
                        }
                        Err(e) => {
                            // If it ran long enough before failing, treat as a
                            // fresh failure and reset backoff; otherwise escalate.
                            if started_at.elapsed()
                                >= std::time::Duration::from_secs(LONG_RUN_RESET_SECS)
                            {
                                backoff_ms = INITIAL_BACKOFF_MS;
                            }
                            log::error!(
                                "ETW process watcher failed: {}; restarting in {}ms",
                                e,
                                backoff_ms
                            );

                            // Interruptible sleep so shutdown isn't delayed.
                            let sleep_until = std::time::Instant::now()
                                + std::time::Duration::from_millis(backoff_ms);
                            while std::time::Instant::now() < sleep_until {
                                if stop_flag_clone.load(Ordering::Acquire) {
                                    return;
                                }
                                std::thread::sleep(std::time::Duration::from_millis(100));
                            }

                            backoff_ms = (backoff_ms * 2).min(MAX_BACKOFF_MS);
                        }
                    }
                }
            })
            .map_err(|e| format!("Failed to spawn ETW thread: {}", e))?;

        Ok(Self {
            receiver,
            stop_flag,
            thread_handle: Some(thread_handle),
        })
    }

    /// Get the receiver for process events
    pub fn receiver(&self) -> &Receiver<ProcessStartEvent> {
        &self.receiver
    }

    /// Try to receive a process event without blocking
    pub fn try_recv(&self) -> Option<ProcessStartEvent> {
        self.receiver.try_recv().ok()
    }

    /// Stop the watcher
    pub fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        // Stop the ETW session to unblock ProcessTrace (it's a blocking call)
        stop_existing_session();
        if let Some(handle) = self.thread_handle.take() {
            // join() blocks until the worker exits — no need to sleep first.
            let _ = handle.join();
        }
    }
}

impl Drop for ProcessWatcher {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Run the ETW session (called from background thread)
fn run_etw_session(
    sender: Sender<ProcessStartEvent>,
    stop_flag: Arc<AtomicBool>,
    watch_list: Arc<RwLock<HashSet<String>>>,
) -> Result<(), String> {
    log::info!("Starting ETW process watcher...");

    // First, try to stop any existing session with our name
    stop_existing_session();

    unsafe {
        // Allocate properties structure with space for session name
        let session_name_wide: Vec<u16> = SESSION_NAME
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let properties_size =
            std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + (session_name_wide.len() * 2) + 2;
        let mut properties_buffer = vec![0u8; properties_size];
        let properties = properties_buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

        // Initialize properties
        (*properties).Wnode.BufferSize = properties_size as u32;
        (*properties).Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        (*properties).Wnode.ClientContext = 1; // Query performance counter
        (*properties).LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        (*properties).EnableFlags = EVENT_TRACE_FLAG_PROCESS;
        (*properties).LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;

        // Copy session name
        let name_dest =
            (properties as *mut u8).add((*properties).LoggerNameOffset as usize) as *mut u16;
        std::ptr::copy_nonoverlapping(
            session_name_wide.as_ptr(),
            name_dest,
            session_name_wide.len(),
        );

        // Start the trace session
        let mut session_handle = CONTROLTRACE_HANDLE::default();
        let result = StartTraceW(
            &mut session_handle,
            PCWSTR(session_name_wide.as_ptr()),
            properties,
        );

        if result != ERROR_SUCCESS {
            return Err(format!("StartTraceW failed: 0x{:08X}", result.0));
        }

        log::info!("ETW session started, handle: {:?}", session_handle);

        // Enable the kernel process provider
        let result = EnableTraceEx2(
            session_handle,
            &KERNEL_PROCESS_GUID,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
            TRACE_LEVEL_INFORMATION as u8,
            WINEVENT_KEYWORD_PROCESS, // Keywords
            0,                        // MatchAnyKeyword
            0,                        // Timeout
            None,                     // EnableParameters
        );

        if result != ERROR_SUCCESS {
            // Clean up session
            ControlTraceW(
                session_handle,
                PCWSTR::null(),
                properties,
                EVENT_TRACE_CONTROL_STOP,
            );
            return Err(format!("EnableTraceEx2 failed: 0x{:08X}", result.0));
        }

        log::info!("ETW provider enabled");

        // Create context for callback
        let context = Box::new(CallbackContext {
            sender: sender.clone(),
            stop_flag: stop_flag.clone(),
            watch_list: watch_list.clone(),
        });
        let context_ptr = Box::into_raw(context);

        // Open trace for processing
        let mut logfile = EVENT_TRACE_LOGFILEW::default();
        logfile.LoggerName = PWSTR(session_name_wide.as_ptr() as *mut u16);
        logfile.Anonymous1.ProcessTraceMode =
            PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(event_record_callback);
        logfile.Context = context_ptr as *mut c_void;

        let trace_handle = OpenTraceW(&mut logfile);
        if trace_handle.Value == u64::MAX {
            // Clean up
            let _ = Box::from_raw(context_ptr);
            ControlTraceW(
                session_handle,
                PCWSTR::null(),
                properties,
                EVENT_TRACE_CONTROL_STOP,
            );
            return Err("OpenTraceW failed".to_string());
        }

        log::info!("ETW trace opened, processing events...");

        // Process events (this blocks until trace is closed or error)
        let handles = [trace_handle];
        let result = ProcessTrace(&handles, None, None);

        // Clean up
        CloseTrace(trace_handle);
        let _ = Box::from_raw(context_ptr);

        // Stop the session
        ControlTraceW(
            session_handle,
            PCWSTR::null(),
            properties,
            EVENT_TRACE_CONTROL_STOP,
        );

        if result != ERROR_SUCCESS && !stop_flag.load(Ordering::SeqCst) {
            return Err(format!("ProcessTrace failed: 0x{:08X}", result.0));
        }
    }

    log::info!("ETW process watcher stopped");
    Ok(())
}

/// Stop any existing ETW session with our name
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

        let result = ControlTraceW(
            CONTROLTRACE_HANDLE::default(),
            PCWSTR(session_name_wide.as_ptr()),
            properties,
            EVENT_TRACE_CONTROL_STOP,
        );

        if result == ERROR_SUCCESS {
            log::info!("Stopped existing ETW session");
        }
    }
}

/// Context passed to ETW callback
struct CallbackContext {
    sender: Sender<ProcessStartEvent>,
    stop_flag: Arc<AtomicBool>,
    watch_list: Arc<RwLock<HashSet<String>>>,
}

/// ETW event callback - called for each event
unsafe extern "system" fn event_record_callback(event_record: *mut EVENT_RECORD) {
    if event_record.is_null() {
        return;
    }

    let record = &*event_record;
    let context = record.UserContext as *mut CallbackContext;
    if context.is_null() {
        return;
    }
    let ctx = &*context;

    // Check stop flag
    if ctx.stop_flag.load(Ordering::Relaxed) {
        return;
    }

    // Only process start events from our provider
    if record.EventHeader.ProviderId != KERNEL_PROCESS_GUID {
        return;
    }
    if record.EventHeader.EventDescriptor.Id != EVENT_ID_PROCESS_START {
        return;
    }

    // Parse the event data
    if let Some(event) = parse_process_start_event(record) {
        // Check if this process is in our watch list
        let name_lower = event.name.to_lowercase();
        let watch_list = ctx.watch_list.read();
        let should_notify = should_watch_process(&name_lower, &watch_list);

        if should_notify {
            log::info!(
                "ETW detected watched process: {} (PID: {}, Parent: {})",
                event.name,
                event.pid,
                event.parent_pid
            );
            let _ = ctx.sender.try_send(event);
        }
    }
}

fn should_watch_process(process_name_lower: &str, watch_list: &HashSet<String>) -> bool {
    process_name_matches_any_tunnel_app(process_name_lower, watch_list)
}

/// Parse process start event from EVENT_RECORD
unsafe fn parse_process_start_event(record: &EVENT_RECORD) -> Option<ProcessStartEvent> {
    let pid = record.EventHeader.ProcessId;

    // The UserData contains the event-specific data
    // For process start events, the structure varies by Windows version
    // We need to carefully parse it

    let user_data = record.UserData;
    let user_data_len = record.UserDataLength as usize;

    if user_data.is_null() || user_data_len < 16 {
        return None;
    }

    let data = std::slice::from_raw_parts(user_data as *const u8, user_data_len);

    // Try to extract process information
    // The layout for ProcessStart event (Version 4, Windows 10+):
    // Offset 0: UniqueProcessKey (8 bytes, pointer)
    // Offset 8: ProcessId (4 bytes)
    // Offset 12: ParentId (4 bytes)
    // Offset 16: SessionId (4 bytes)
    // Offset 20: ExitStatus (4 bytes)
    // Offset 24: DirectoryTableBase (8 bytes)
    // Offset 32: Flags (4 bytes)
    // Offset 36: UserSID (variable, starts with SID length)
    // After SID: ImageFileName (null-terminated ANSI string)

    if data.len() < 36 {
        return None;
    }

    // Read ProcessId and ParentId from the event data
    let event_pid = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let parent_pid = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);

    // Find the image filename - it's an ANSI string after the variable-length SID
    // Skip to offset 36 and then skip the SID
    let mut offset = 36usize;

    // SID structure: first byte is revision, second is sub-authority count
    // Total SID size = 8 + (4 * sub_authority_count)
    // Bounds check: ensure we can read at least offset + 1 for sub_auth_count
    if offset + 1 < data.len() {
        let sub_auth_count = data[offset + 1] as usize;
        let sid_size = 8 + (4 * sub_auth_count);
        offset += sid_size;
    }

    // Now we should be at the ImageFileName (ANSI null-terminated)
    let mut name = String::new();
    if offset < data.len() {
        // Read ANSI string until null terminator
        for &byte in &data[offset..] {
            if byte == 0 {
                break;
            }
            name.push(byte as char);
        }
    }

    // Try to get the full image path from the OS (more reliable than event data).
    // This must remain a full NT path because the WFP blocker converts it to a DOS path.
    let image_path = get_process_image_path_by_pid(event_pid).unwrap_or_default();

    // If we couldn't get the name from event data, extract from full path
    if name.is_empty() {
        name = image_path
            .rsplit('\\')
            .next()
            .unwrap_or("unknown")
            .to_string();
    }

    // Extract just the filename from path if the event data gave us a full path
    let short_name = name.rsplit('\\').next().unwrap_or(&name).to_string();

    Some(ProcessStartEvent {
        pid: event_pid,
        name: short_name,
        image_path,
        parent_pid,
    })
}

/// One-shot scan of currently running processes at watcher startup. Emits synthetic
/// `ProcessStartEvent`s for any matching the watch list so games already running before
/// SwiftTunnel connected get registered for tunneling. Without this, a player who alt-tabs
/// into Roblox first and then opens the app sees "connected" but their packets bypass
/// the tunnel silently — ETW alone only catches future process starts.
///
/// Returns the number of synthetic events emitted (informational, not load-bearing).
fn enumerate_running_matching_processes(
    sender: &Sender<ProcessStartEvent>,
    watch_list: &HashSet<String>,
) -> usize {
    use windows::Win32::System::ProcessStatus::EnumProcesses;

    if watch_list.is_empty() {
        return 0;
    }

    // Sized for typical Windows sessions; over-provision rather than retry.
    let mut pids = vec![0u32; 4096];
    let mut bytes_returned = 0u32;
    let enum_ok = unsafe {
        EnumProcesses(
            pids.as_mut_ptr(),
            (pids.len() * std::mem::size_of::<u32>()) as u32,
            &mut bytes_returned,
        )
        .is_ok()
    };
    if !enum_ok {
        log::warn!("ETW initial scan: EnumProcesses failed; relying on ETW start events only");
        return 0;
    }

    let pid_count = bytes_returned as usize / std::mem::size_of::<u32>();
    let mut emitted = 0usize;

    for &pid in &pids[..pid_count] {
        if pid == 0 {
            continue;
        }
        let Some(image_path) = get_process_image_path_by_pid(pid) else {
            continue;
        };
        let short_name = image_path.rsplit('\\').next().unwrap_or("").to_string();
        if short_name.is_empty() {
            continue;
        }
        let name_lower = short_name.to_ascii_lowercase();
        if !should_watch_process(&name_lower, watch_list) {
            continue;
        }

        let event = ProcessStartEvent {
            pid,
            name: short_name.clone(),
            image_path,
            // Parent PID is unavailable from EnumProcesses without a Toolhelp32 snapshot,
            // and downstream tunneling decisions key off the PID itself, not the parent.
            parent_pid: 0,
        };
        log::info!(
            "ETW initial scan: registered already-running {} (PID {}) for tunneling",
            short_name,
            pid
        );
        if sender.try_send(event).is_err() {
            // The bounded(100) channel is the same one ETW uses; if it's already full at
            // startup something is very wrong upstream. Stop scanning rather than spin.
            log::warn!(
                "ETW initial scan: event channel full at {} entries; halting scan",
                emitted
            );
            return emitted;
        }
        emitted += 1;
    }

    if emitted > 0 {
        log::info!(
            "ETW initial scan: seeded {} already-running matching process(es)",
            emitted
        );
    }
    emitted
}

/// Get the full NT image path for a PID using Windows API.
fn get_process_image_path_by_pid(pid: u32) -> Option<String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::ProcessStatus::GetProcessImageFileNameW;
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        if handle.is_invalid() {
            return None;
        }

        let mut capacity = 260usize;
        let path = loop {
            let mut buffer = vec![0u16; capacity];
            let len = GetProcessImageFileNameW(handle, &mut buffer) as usize;
            if len == 0 {
                let _ = CloseHandle(handle);
                return None;
            }
            if len < buffer.len() || capacity >= 32 * 1024 {
                break String::from_utf16_lossy(&buffer[..len]);
            }
            capacity = (capacity * 2).min(32 * 1024);
        };

        if CloseHandle(handle).is_err() {
            log::debug!("Failed to close process handle for PID {}", pid);
        }

        Some(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_process_start_event() {
        let event = ProcessStartEvent {
            pid: 1234,
            name: "RobloxPlayerBeta.exe".to_string(),
            image_path: r"\Device\HarddiskVolume3\Users\test\AppData\Local\Roblox\Versions\version-xxx\RobloxPlayerBeta.exe".to_string(),
            parent_pid: 5678,
        };
        assert_eq!(event.pid, 1234);
        assert_eq!(event.name, "RobloxPlayerBeta.exe");
        assert!(event.image_path.contains("RobloxPlayerBeta.exe"));
    }

    #[test]
    fn test_should_watch_process_matches_aliases() {
        let watch_list: HashSet<String> =
            ["robloxplayerbeta.exe".to_string(), "roblox".to_string()]
                .into_iter()
                .collect();

        assert!(should_watch_process("robloxapp.exe", &watch_list));
        assert!(should_watch_process(
            "robloxplayerlauncher.exe",
            &watch_list
        ));
        assert!(!should_watch_process("chrome.exe", &watch_list));
        assert!(!should_watch_process("player.exe", &watch_list));
    }

    #[test]
    fn test_should_watch_process_rejects_store_roblox_package_path() {
        let watch_list: HashSet<String> =
            ["robloxplayerbeta.exe".to_string()].into_iter().collect();

        assert!(!should_watch_process(
            r"c:\program files\windowsapps\robloxcorporation.roblox_2.617.655.0_x64__55nm5eh3cm0pr\windows10universal.exe",
            &watch_list
        ));
        assert!(!should_watch_process("windows10universal.exe", &watch_list));
        assert!(!should_watch_process(
            r"c:\program files\windowsapps\microsoft.microsoftsolitairecollection_4.20.0.0_x64__8wekyb3d8bbwe\windows10universal.exe",
            &watch_list
        ));

        let legacy_watch_list: HashSet<String> =
            ["windows10universal.exe".to_string()].into_iter().collect();
        assert!(!should_watch_process(
            "windows10universal.exe",
            &legacy_watch_list
        ));
    }
}
