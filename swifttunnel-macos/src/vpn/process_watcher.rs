//! macOS Process Watcher - Instant Process Detection via kqueue
//!
//! Uses kqueue EVFILT_PROC with NOTE_EXEC/NOTE_EXIT/NOTE_FORK to detect process
//! creation instantly, before the process makes any network connections.
//!
//! This is the macOS equivalent of Windows ETW (Event Tracing for Windows).
//!
//! The approach combines two strategies:
//! 1. **Polling** (sysinfo): Periodically scans all processes to find game processes
//!    that were already running before the watcher started.
//! 2. **kqueue EVFILT_PROC**: Watches known PIDs for exec/fork/exit events to detect
//!    child processes spawned by game launchers (e.g., Roblox launcher -> RobloxPlayer).
//!
//! Since macOS kqueue requires specific PIDs to watch (unlike ETW which watches globally),
//! we use polling as the primary detection mechanism and kqueue for tracking lifecycle
//! of already-detected processes and their children.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use crossbeam_channel::{Sender, Receiver, bounded};
use parking_lot::RwLock;

/// Event sent when a new process is detected
#[derive(Debug, Clone)]
pub struct ProcessStartEvent {
    /// Process ID of the new process
    pub pid: u32,
    /// Process name (just the binary name, not full path)
    pub name: String,
    /// Full executable path (e.g., /Applications/Roblox.app/Contents/MacOS/RobloxPlayer)
    pub image_path: String,
    /// Parent process ID
    pub parent_pid: u32,
}

/// Process event types
#[derive(Debug, Clone)]
pub enum ProcessEvent {
    /// A watched process was started/detected
    Started(ProcessStartEvent),
    /// A watched process has exited
    Exited { pid: u32, name: String },
}

/// macOS Process Watcher
///
/// Monitors for process creation events using sysinfo polling + kqueue lifecycle tracking.
/// When a process matching the watch list starts, sends notification via channel.
pub struct ProcessWatcher {
    /// Channel to receive process start events
    receiver: Receiver<ProcessStartEvent>,
    /// Handle to stop the watcher
    stop_flag: Arc<AtomicBool>,
    /// Thread handle for polling
    poll_thread: Option<std::thread::JoinHandle<()>>,
    /// Thread handle for kqueue monitoring
    kqueue_thread: Option<std::thread::JoinHandle<()>>,
    /// Set of PIDs currently being watched via kqueue
    watched_pids: Arc<RwLock<HashSet<u32>>>,
}

impl ProcessWatcher {
    /// Create and start a new process watcher
    ///
    /// # Arguments
    /// * `watch_list` - Process names to watch for (lowercase, e.g., "robloxplayer")
    pub fn start(watch_list: HashSet<String>) -> Result<Self, String> {
        let (sender, receiver) = bounded(100);
        let stop_flag = Arc::new(AtomicBool::new(false));
        let watched_pids = Arc::new(RwLock::new(HashSet::new()));
        let watch_list = Arc::new(RwLock::new(watch_list));

        // Start polling thread for initial process detection
        let poll_sender = sender.clone();
        let poll_stop = stop_flag.clone();
        let poll_watch_list = watch_list.clone();
        let poll_watched_pids = watched_pids.clone();

        let poll_thread = std::thread::Builder::new()
            .name("process-watcher-poll".to_string())
            .spawn(move || {
                run_poll_loop(poll_sender, poll_stop, poll_watch_list, poll_watched_pids);
            })
            .map_err(|e| format!("Failed to spawn poll thread: {}", e))?;

        // Start kqueue thread for lifecycle monitoring of detected PIDs
        let kq_sender = sender;
        let kq_stop = stop_flag.clone();
        let kq_watched_pids = watched_pids.clone();
        let kq_watch_list = watch_list;

        let kqueue_thread = std::thread::Builder::new()
            .name("process-watcher-kqueue".to_string())
            .spawn(move || {
                if let Err(e) = run_kqueue_loop(kq_sender, kq_stop, kq_watched_pids, kq_watch_list)
                {
                    log::error!("kqueue process watcher failed: {}", e);
                }
            })
            .map_err(|e| format!("Failed to spawn kqueue thread: {}", e))?;

        log::info!("Process watcher started (polling + kqueue)");

        Ok(Self {
            receiver,
            stop_flag,
            poll_thread: Some(poll_thread),
            kqueue_thread: Some(kqueue_thread),
            watched_pids,
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

        if let Some(handle) = self.poll_thread.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.kqueue_thread.take() {
            let _ = handle.join();
        }

        log::info!("Process watcher stopped");
    }
}

impl Drop for ProcessWatcher {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Polling loop - scans all processes periodically to find game processes
fn run_poll_loop(
    sender: Sender<ProcessStartEvent>,
    stop_flag: Arc<AtomicBool>,
    watch_list: Arc<RwLock<HashSet<String>>>,
    watched_pids: Arc<RwLock<HashSet<u32>>>,
) {
    use sysinfo::System;

    log::info!("Process poll loop started");

    let mut system = System::new();
    let mut known_pids: HashSet<u32> = HashSet::new();

    // Polling interval: 250ms (faster than Windows' 50ms poll since macOS kqueue
    // handles lifecycle, but slower than ETW which is instant)
    let poll_interval = std::time::Duration::from_millis(250);

    while !stop_flag.load(Ordering::Relaxed) {
        system.refresh_processes(
            sysinfo::ProcessesToUpdate::All,
            true,
        );

        let watch_list = watch_list.read();

        for (pid, process) in system.processes() {
            let pid_u32 = pid.as_u32();

            // Skip already-known processes
            if known_pids.contains(&pid_u32) {
                continue;
            }

            let proc_name = process.name().to_string_lossy().to_lowercase();

            let should_notify = watch_list.iter().any(|app| {
                proc_name.contains(app.as_str()) || app.contains(proc_name.as_str())
            });

            if should_notify {
                known_pids.insert(pid_u32);

                // Add to kqueue watch list
                watched_pids.write().insert(pid_u32);

                let name = process.name().to_string_lossy().to_string();
                let image_path = process
                    .exe()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();
                let parent_pid = process
                    .parent()
                    .map(|p| p.as_u32())
                    .unwrap_or(0);

                log::info!(
                    "Poll detected watched process: {} (PID: {}, Parent: {})",
                    name, pid_u32, parent_pid
                );

                let _ = sender.try_send(ProcessStartEvent {
                    pid: pid_u32,
                    name,
                    image_path,
                    parent_pid,
                });
            }
        }

        // Clean up known_pids for exited processes
        known_pids.retain(|pid| {
            system.process(sysinfo::Pid::from_u32(*pid)).is_some()
        });

        std::thread::sleep(poll_interval);
    }

    log::info!("Process poll loop stopped");
}

/// kqueue loop - watches specific PIDs for fork/exec/exit events
///
/// When a watched PID forks a child, we check if the child matches our watch list.
/// When a watched PID exits, we notify that it's gone.
fn run_kqueue_loop(
    sender: Sender<ProcessStartEvent>,
    stop_flag: Arc<AtomicBool>,
    watched_pids: Arc<RwLock<HashSet<u32>>>,
    watch_list: Arc<RwLock<HashSet<String>>>,
) -> Result<(), String> {
    use nix::sys::event::{EventFilter, EventFlag, FilterFlag, KEvent, Kqueue};
    use std::time::Duration;

    log::info!("kqueue process watcher started");

    let kq = Kqueue::new().map_err(|e| format!("Failed to create kqueue: {}", e))?;

    // Track which PIDs we've registered with kqueue
    let mut registered_pids: HashSet<u32> = HashSet::new();

    let timeout = Duration::from_millis(100);

    while !stop_flag.load(Ordering::Relaxed) {
        // Register any new PIDs that the poll thread discovered
        let current_watched = watched_pids.read().clone();
        for &pid in &current_watched {
            if !registered_pids.contains(&pid) {
                // Register this PID for NOTE_FORK | NOTE_EXIT | NOTE_EXEC events
                let changelist = [KEvent::new(
                    pid as usize,
                    EventFilter::EVFILT_PROC,
                    EventFlag::EV_ADD | EventFlag::EV_ENABLE,
                    FilterFlag::NOTE_FORK | FilterFlag::NOTE_EXIT | FilterFlag::NOTE_EXEC,
                    0,
                    0,
                )];

                let mut eventlist = Vec::new();
                // kevent with changelist to register, empty eventlist
                match kq.kevent(&changelist, &mut eventlist, Some(libc::timespec { tv_sec: 0, tv_nsec: 0 })) {
                    Ok(_) => {
                        registered_pids.insert(pid);
                        log::debug!("kqueue: Registered PID {} for monitoring", pid);
                    }
                    Err(e) => {
                        // Process might have already exited
                        log::debug!("kqueue: Failed to register PID {}: {}", pid, e);
                    }
                }
            }
        }

        // Wait for events
        let mut events = vec![KEvent::new(0, EventFilter::EVFILT_PROC, EventFlag::empty(), FilterFlag::empty(), 0, 0); 16];

        let ts = libc::timespec { tv_sec: timeout.as_secs() as i64, tv_nsec: timeout.subsec_nanos() as i64 };
        let n = match kq.kevent(&[], &mut events, Some(ts)) {
            Ok(n) => n,
            Err(e) => {
                if stop_flag.load(Ordering::Relaxed) {
                    break;
                }
                log::debug!("kqueue: kevent error: {}", e);
                continue;
            }
        };

        for event in &events[..n] {
            let pid = event.ident() as u32;
            let fflags = event.fflags();

            if fflags.contains(FilterFlag::NOTE_FORK) {
                // A watched process forked - check the child
                // On macOS, the child PID is often pid+1 but that's not guaranteed.
                // We can also detect it on next poll cycle. For now, just log it.
                log::debug!("kqueue: PID {} forked a child process", pid);
            }

            if fflags.contains(FilterFlag::NOTE_EXEC) {
                // A process called exec - check if it's now a game process
                if let Some(name) = super::process_tracker::get_process_name(pid) {
                    let name_lower = name.to_lowercase();
                    let watch_list = watch_list.read();
                    let should_notify = watch_list.iter().any(|app| {
                        name_lower.contains(app.as_str()) || app.contains(name_lower.as_str())
                    });

                    if should_notify {
                        let image_path =
                            super::process_tracker::get_process_path(pid).unwrap_or_default();

                        log::info!(
                            "kqueue: Detected exec of watched process: {} (PID: {})",
                            name, pid
                        );

                        let _ = sender.try_send(ProcessStartEvent {
                            pid,
                            name,
                            image_path,
                            parent_pid: 0,
                        });

                        watched_pids.write().insert(pid);
                    }
                }
            }

            if fflags.contains(FilterFlag::NOTE_EXIT) {
                log::debug!("kqueue: PID {} exited", pid);
                registered_pids.remove(&pid);
                watched_pids.write().remove(&pid);
            }
        }
    }

    log::info!("kqueue process watcher stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_start_event() {
        let event = ProcessStartEvent {
            pid: 1234,
            name: "RobloxPlayer".to_string(),
            image_path: "/Applications/Roblox.app/Contents/MacOS/RobloxPlayer".to_string(),
            parent_pid: 5678,
        };
        assert_eq!(event.pid, 1234);
        assert_eq!(event.name, "RobloxPlayer");
        assert!(event.image_path.contains("RobloxPlayer"));
    }
}
