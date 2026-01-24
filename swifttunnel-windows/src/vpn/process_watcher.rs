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

use std::collections::HashSet;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use crossbeam_channel::{Sender, Receiver, bounded};
use parking_lot::RwLock;

use windows::core::{GUID, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    ERROR_SUCCESS, HANDLE, WIN32_ERROR, ERROR_WMI_INSTANCE_NOT_FOUND,
};
use windows::Win32::System::Diagnostics::Etw::{
    StartTraceW, ControlTraceW, EnableTraceEx2, OpenTraceW, ProcessTrace, CloseTrace,
    EVENT_TRACE_PROPERTIES, EVENT_TRACE_LOGFILEW, EVENT_RECORD, EVENT_TRACE_CONTROL_STOP,
    EVENT_TRACE_REAL_TIME_MODE, TRACE_LEVEL_INFORMATION, EVENT_CONTROL_CODE_ENABLE_PROVIDER,
    PROCESS_TRACE_MODE_REAL_TIME, PROCESS_TRACE_MODE_EVENT_RECORD, WNODE_FLAG_TRACED_GUID,
    EVENT_TRACE_FLAG_PROCESS,
};

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
        let stop_flag_clone = stop_flag.clone();
        let watch_list = Arc::new(RwLock::new(watch_list));
        let watch_list_clone = watch_list.clone();

        let thread_handle = std::thread::Builder::new()
            .name("etw-process-watcher".to_string())
            .spawn(move || {
                if let Err(e) = run_etw_session(sender, stop_flag_clone, watch_list_clone) {
                    log::error!("ETW process watcher failed: {}", e);
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
        if let Some(handle) = self.thread_handle.take() {
            // Give the thread a moment to notice the stop flag
            std::thread::sleep(std::time::Duration::from_millis(100));
            // We can't really force-stop ProcessTrace, but setting the flag
            // will cause it to exit on the next event or timeout
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
        let session_name_wide: Vec<u16> = SESSION_NAME.encode_utf16().chain(std::iter::once(0)).collect();
        let properties_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + (session_name_wide.len() * 2) + 2;
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
        let name_dest = (properties as *mut u8).add((*properties).LoggerNameOffset as usize) as *mut u16;
        std::ptr::copy_nonoverlapping(session_name_wide.as_ptr(), name_dest, session_name_wide.len());

        // Start the trace session
        let mut session_handle: u64 = 0;
        let result = StartTraceW(
            &mut session_handle,
            PCWSTR(session_name_wide.as_ptr()),
            properties,
        );

        if result != ERROR_SUCCESS.0 {
            return Err(format!("StartTraceW failed: 0x{:08X}", result));
        }

        log::info!("ETW session started, handle: {}", session_handle);

        // Enable the kernel process provider
        let result = EnableTraceEx2(
            HANDLE(session_handle as isize),
            &KERNEL_PROCESS_GUID,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
            TRACE_LEVEL_INFORMATION as u8,
            WINEVENT_KEYWORD_PROCESS, // Keywords
            0, // MatchAnyKeyword
            0, // Timeout
            None, // EnableParameters
        );

        if result != ERROR_SUCCESS.0 {
            // Clean up session
            ControlTraceW(
                HANDLE(session_handle as isize),
                PCWSTR::null(),
                properties,
                EVENT_TRACE_CONTROL_STOP,
            );
            return Err(format!("EnableTraceEx2 failed: 0x{:08X}", result));
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
        logfile.Anonymous1.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        logfile.Anonymous2.EventRecordCallback = Some(event_record_callback);
        logfile.Context = context_ptr as *mut c_void;

        let trace_handle = OpenTraceW(&mut logfile);
        if trace_handle.0 == u64::MAX as isize {
            // Clean up
            let _ = Box::from_raw(context_ptr);
            ControlTraceW(
                HANDLE(session_handle as isize),
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
            HANDLE(session_handle as isize),
            PCWSTR::null(),
            properties,
            EVENT_TRACE_CONTROL_STOP,
        );

        if result != ERROR_SUCCESS.0 && !stop_flag.load(Ordering::SeqCst) {
            return Err(format!("ProcessTrace failed: 0x{:08X}", result));
        }
    }

    log::info!("ETW process watcher stopped");
    Ok(())
}

/// Stop any existing ETW session with our name
fn stop_existing_session() {
    unsafe {
        let session_name_wide: Vec<u16> = SESSION_NAME.encode_utf16().chain(std::iter::once(0)).collect();
        let properties_size = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() + (session_name_wide.len() * 2) + 2;
        let mut properties_buffer = vec![0u8; properties_size];
        let properties = properties_buffer.as_mut_ptr() as *mut EVENT_TRACE_PROPERTIES;

        (*properties).Wnode.BufferSize = properties_size as u32;
        (*properties).LoggerNameOffset = std::mem::size_of::<EVENT_TRACE_PROPERTIES>() as u32;

        let name_dest = (properties as *mut u8).add((*properties).LoggerNameOffset as usize) as *mut u16;
        std::ptr::copy_nonoverlapping(session_name_wide.as_ptr(), name_dest, session_name_wide.len());

        let result = ControlTraceW(
            HANDLE(0),
            PCWSTR(session_name_wide.as_ptr()),
            properties,
            EVENT_TRACE_CONTROL_STOP,
        );

        if result == ERROR_SUCCESS.0 {
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

        let should_notify = watch_list.iter().any(|app| {
            let app_stem = app.trim_end_matches(".exe");
            let name_stem = name_lower.trim_end_matches(".exe");
            name_stem.contains(app_stem) || app_stem.contains(name_stem)
        });

        if should_notify {
            log::info!(
                "ETW detected watched process: {} (PID: {}, Parent: {})",
                event.name, event.pid, event.parent_pid
            );
            let _ = ctx.sender.try_send(event);
        }
    }
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
    if offset < data.len() {
        let sub_auth_count = data.get(offset + 1).copied().unwrap_or(0) as usize;
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

    // If we couldn't get the name from event data, try to get it from PID
    if name.is_empty() {
        name = get_process_name_by_pid(event_pid).unwrap_or_else(|| format!("pid_{}", event_pid));
    }

    // Extract just the filename from path if it's a full path
    let name = name.rsplit('\\').next().unwrap_or(&name).to_string();

    Some(ProcessStartEvent {
        pid: event_pid,
        name,
        parent_pid,
    })
}

/// Get process name by PID using Windows API
fn get_process_name_by_pid(pid: u32) -> Option<String> {
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    use windows::Win32::System::ProcessStatus::GetProcessImageFileNameW;
    use windows::Win32::Foundation::CloseHandle;

    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        if handle.is_invalid() {
            return None;
        }

        let mut buffer = [0u16; 260];
        let len = GetProcessImageFileNameW(handle, &mut buffer);
        CloseHandle(handle).ok();

        if len == 0 {
            return None;
        }

        let path = String::from_utf16_lossy(&buffer[..len as usize]);
        let name = path.rsplit('\\').next().unwrap_or(&path);
        Some(name.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_start_event() {
        let event = ProcessStartEvent {
            pid: 1234,
            name: "RobloxPlayerBeta.exe".to_string(),
            parent_pid: 5678,
        };
        assert_eq!(event.pid, 1234);
        assert_eq!(event.name, "RobloxPlayerBeta.exe");
    }
}
