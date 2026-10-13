//! Roblox Log Watcher
//!
//! Monitors Roblox log files to detect game server IPs.
//! Similar to Bloxstrap's server location notification feature.

use crate::roblox_library::{RobloxClient, valid_job_id, valid_place_id};
use regex_lite::Regex;
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread;
use std::time::Duration;

/// Events emitted by the Roblox watcher
#[derive(Debug, Clone)]
pub enum RobloxEvent {
    PlayerOpened,
    GameLeft {
        job_id: Option<String>,
    },
    /// Detected a game server connection
    GameServerDetected {
        ip: Ipv4Addr,
    },
    GameJoined {
        ip: Ipv4Addr,
        place_id: String,
        job_id: String,
        client: RobloxClient,
        fresh_join: bool,
    },
}

/// Watches Roblox log files for game server connections
pub struct RobloxWatcher {
    receiver: Receiver<RobloxEvent>,
    stop_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl RobloxWatcher {
    /// Create a new Roblox watcher
    /// Returns None if the Roblox logs directory doesn't exist
    pub fn new() -> Option<Self> {
        let base = PathBuf::from(std::env::var("LOCALAPPDATA").ok()?);
        let directories = vec![
            base.join("Roblox").join("logs"),
            base.join("RobloxPCVNG").join("logs"),
        ];
        let (sender, receiver) = mpsc::sync_channel(64);
        let stop_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_flag_clone = stop_flag.clone();

        // Spawn watcher thread
        thread::Builder::new()
            .name("roblox-log-tail".into())
            .spawn(move || {
                watch_logs(directories, sender, stop_flag_clone);
            })
            .ok()?;

        log::info!("Roblox log watcher started");
        Some(Self {
            receiver,
            stop_flag,
        })
    }

    /// Poll for new events (non-blocking)
    pub fn poll(&self) -> Vec<RobloxEvent> {
        let mut events = Vec::new();
        while let Ok(event) = self.receiver.try_recv() {
            events.push(event);
        }
        events
    }

    /// Stop the watcher
    pub fn stop(&self) {
        self.stop_flag
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Drop for RobloxWatcher {
    fn drop(&mut self) {
        self.stop();
    }
}

fn parse_join(line: &str) -> Option<(String, String, Ipv4Addr)> {
    static JOIN: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
    let pattern = JOIN.get_or_init(|| {
        Regex::new(r"! Joining game '([0-9a-fA-F\-]+)' place (\d+) at (\d+\.\d+\.\d+\.\d+)")
            .unwrap()
    });
    let captures = pattern.captures(line)?;
    let job = captures.get(1)?.as_str();
    let place = captures.get(2)?.as_str();
    let ip = captures.get(3)?.as_str().parse().ok()?;
    // Roblox now logs its private RCC address here. Keep the identifiers,
    // but only publish a session after the public transport is confirmed.
    if !valid_job_id(job) || !valid_place_id(place) {
        return None;
    }
    Some((place.into(), job.to_ascii_lowercase(), ip))
}

#[derive(Default)]
struct JoinTracker {
    pending: Option<(String, String, Ipv4Addr, bool)>,
    last: Option<String>,
}
impl JoinTracker {
    fn feed(&mut self, lines: &[String], fresh: bool, client: RobloxClient) -> Vec<RobloxEvent> {
        let mut events = Vec::new();
        for line in lines {
            if fresh && line.contains("[FLog::DataModelStarterModule] Launching Lua App") {
                events.push(RobloxEvent::PlayerOpened);
            } else if line.contains("[FLog::SingleSurfaceApp] leaveUGCGameInternal")
                || line.contains("[FLog::Network] Time to disconnect replication data:")
            {
                if fresh {
                    events.push(RobloxEvent::GameLeft {
                        job_id: self.last.clone(),
                    });
                }
                self.last = None;
                self.pending = None;
                if !fresh {
                    events.clear();
                }
            } else if let Some((place, job, ip)) = parse_join(line) {
                self.pending = Some((place, job, ip, fresh));
            } else if line.contains("[FLog::Network] serverId:") {
                static SERVER: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
                let pattern =
                    SERVER.get_or_init(|| Regex::new(r"serverId:\s*(\d+\.\d+\.\d+\.\d+)").unwrap());
                let Some(ip) = pattern
                    .captures(line)
                    .and_then(|c| c.get(1))
                    .and_then(|value| value.as_str().parse::<Ipv4Addr>().ok())
                    .filter(|ip| !is_private_ip(*ip))
                else {
                    continue;
                };
                let Some((place_id, job_id, _, join_fresh)) = self.pending.take() else {
                    continue;
                };
                if !is_private_ip(ip) && self.last.as_ref() != Some(&job_id) {
                    self.last = Some(job_id.clone());
                    events.push(RobloxEvent::GameJoined {
                        ip,
                        place_id,
                        job_id,
                        client,
                        fresh_join: join_fresh || fresh,
                    });
                }
            }
        }
        // Existing logs may contain several old sessions; attach only the
        // latest state, with no notification/cleaning replay.
        if !fresh
            && self
                .pending
                .as_ref()
                .is_some_and(|(_, job, _, _)| self.last.as_ref() != Some(job))
        {
            events.clear();
        }
        if !fresh && events.len() > 1 {
            events = events.into_iter().rev().take(1).collect();
        }
        events
    }
}

/// Compile regex patterns once at startup (panics if patterns are invalid - programmer error)
fn get_patterns() -> (&'static Regex, &'static Regex) {
    use std::sync::OnceLock;

    static JOINING_PATTERN: OnceLock<Regex> = OnceLock::new();
    static UDMUX_PATTERN: OnceLock<Regex> = OnceLock::new();

    let joining = JOINING_PATTERN.get_or_init(|| {
        Regex::new(r"! Joining game '[0-9a-f\-]+' place \d+ at (\d+\.\d+\.\d+\.\d+)")
            .expect("Invalid joining regex pattern")
    });

    let udmux = UDMUX_PATTERN.get_or_init(|| {
        Regex::new(r"UDMUX Address = (\d+\.\d+\.\d+\.\d+), Port = \d+")
            .expect("Invalid UDMUX regex pattern")
    });

    (joining, udmux)
}

/// Main log watching loop
fn watch_logs(
    directories: Vec<PathBuf>,
    sender: SyncSender<RobloxEvent>,
    stop_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    // Get compiled regex patterns (compiled once, reused)
    let (joining_pattern, udmux_pattern) = get_patterns();

    let mut seen_ips: HashSet<Ipv4Addr> = HashSet::new();
    let mut current_file: Option<TailedFile> = None;
    let mut last_file_check = std::time::Instant::now();
    let mut tracker = JoinTracker::default();
    let started = std::time::SystemTime::now();
    let mut directories: Vec<_> = directories.into_iter().map(LogDirectory::new).collect();

    loop {
        if stop_flag.load(std::sync::atomic::Ordering::SeqCst) {
            log::info!("Roblox watcher stopping");
            break;
        }

        // Check for new/updated log file every 2 seconds
        if last_file_check.elapsed() > Duration::from_secs(2) {
            if let Some(newest) = directories
                .iter_mut()
                .filter_map(|dir| dir.newest(std::time::Instant::now()))
                .max_by_key(|path| fs::metadata(path).ok().and_then(|m| m.modified().ok()))
            {
                let should_switch = current_file
                    .as_ref()
                    .map(|f| f.path != newest || !f.matches_current_file(&newest))
                    .unwrap_or(true);

                if should_switch {
                    log::info!("Switching to log file: {:?}", newest);
                    match TailedFile::new(&newest) {
                        Ok(file) => {
                            current_file = Some(file);
                            seen_ips.clear(); // Reset seen IPs for new session
                            tracker = JoinTracker::default();
                        }
                        Err(e) => {
                            log::warn!("Failed to open log file {:?}: {}", newest, e);
                            current_file = None;
                        }
                    }
                }
            }
            last_file_check = std::time::Instant::now();
        }

        // Read new lines from current file
        if let Some(ref mut file) = current_file {
            // Catch an existing session for the library, but do not replay its
            // notifications or RAM-clean side effects when SwiftTunnel opens.
            let fresh_join = file
                .reader
                .stream_position()
                .is_ok_and(|pos| pos >= file.initial_end)
                || fs::metadata(&file.path)
                    .and_then(|meta| meta.created())
                    .is_ok_and(|created| created >= started);
            match file.read_new_lines() {
                Ok(lines) => {
                    let was_reset = std::mem::take(&mut file.reset_observed);
                    if was_reset {
                        tracker = JoinTracker::default();
                        seen_ips.clear();
                    }
                    let client = if file
                        .path
                        .components()
                        .any(|c| c.as_os_str() == "RobloxPCVNG")
                    {
                        RobloxClient::Vng
                    } else {
                        RobloxClient::Standard
                    };
                    for event in tracker.feed(&lines, fresh_join || was_reset, client) {
                        let _ = sender.try_send(event);
                    }
                    for line in lines {
                        // Try each pattern
                        for pattern in [joining_pattern, udmux_pattern] {
                            if let Some(caps) = pattern.captures(&line)
                                && let Some(ip_match) = caps.get(1)
                                && let Ok(ip) = ip_match.as_str().parse::<Ipv4Addr>()
                            {
                                // Skip private IPs (10.x.x.x, 192.168.x.x, etc.)
                                if !is_private_ip(ip) && !seen_ips.contains(&ip) {
                                    seen_ips.insert(ip);
                                    log::info!("Detected game server: {}", ip);
                                    if seen_ips.len() > 1024 {
                                        seen_ips.clear();
                                    }
                                    let _ = sender.try_send(RobloxEvent::GameServerDetected { ip });
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    // Log file read error and reset to find a new file
                    log::warn!("Error reading log file: {}", e);
                    current_file = None;
                }
            }
        }

        thread::sleep(Duration::from_millis(1000)); // 1 second is sufficient for log file changes
    }
}

/// Watch directory entry changes instead of restatting every old log every
/// two seconds. New files still appear at the usual two-second check. A periodic
/// rescan also covers a reused file or a filesystem with unreliable timestamps.
struct LogDirectory {
    path: PathBuf,
    changed: Option<std::time::SystemTime>,
    scanned: Option<std::time::Instant>,
    newest: Option<PathBuf>,
    #[cfg(test)]
    scans: usize,
}
impl LogDirectory {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            changed: None,
            scanned: None,
            newest: None,
            #[cfg(test)]
            scans: 0,
        }
    }
    fn newest(&mut self, now: std::time::Instant) -> Option<PathBuf> {
        let changed = fs::metadata(&self.path)
            .ok()
            .and_then(|meta| meta.modified().ok());
        if self
            .scanned
            .is_none_or(|at| now.duration_since(at) >= Duration::from_secs(30))
            || changed != self.changed
            || self.newest.as_ref().is_some_and(|path| !path.is_file())
        {
            self.newest = find_newest_log_file(&self.path);
            self.changed = changed;
            self.scanned = Some(now);
            #[cfg(test)]
            {
                self.scans += 1;
            }
        }
        self.newest.clone()
    }
}

/// Find the newest log file in the directory
fn find_newest_log_file(dir: &Path) -> Option<PathBuf> {
    fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name().to_string_lossy().to_ascii_lowercase();
            name.ends_with(".log") && name.contains("player") && !name.contains("crashhandler")
        })
        .max_by_key(|e| e.metadata().ok().and_then(|m| m.modified().ok()))
        .map(|e| e.path())
}

/// Check if IP is private (RFC 1918)
fn is_private_ip(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    if ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_link_local()
        || octets[0] == 0
        || octets[0] >= 240
        || (octets[0] == 100 && (64..=127).contains(&octets[1]))
    {
        return true;
    }
    // 10.0.0.0/8
    if octets[0] == 10 {
        return true;
    }
    // 172.16.0.0/12
    if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        return true;
    }
    // 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }
    // 127.0.0.0/8 (loopback)
    if octets[0] == 127 {
        return true;
    }
    false
}

/// A file being tailed for new content
struct TailedFile {
    reader: BufReader<File>,
    path: PathBuf,
    pending_line: Vec<u8>,
    discarding_line: bool,
    initial_end: u64,
    identity: Option<(u64, [u8; 16])>,
    reset_observed: bool,
    observed_len: u64,
}

impl TailedFile {
    fn new(path: &Path) -> std::io::Result<Self> {
        let file = File::open(path)?;
        let identity = file_identity(&file);
        let mut reader = BufReader::new(file);

        // Read last 64KB to catch current session
        const TAIL_BYTES: i64 = 65536;
        let file_size = reader.seek(SeekFrom::End(0))? as i64;
        let start_pos = (file_size - TAIL_BYTES).max(0);
        reader.seek(SeekFrom::Start(start_pos as u64))?;

        // Skip first potentially incomplete line if not at file start
        if start_pos > 0 {
            reader.skip_until(b'\n')?;
        }

        Ok(Self {
            reader,
            path: path.to_path_buf(),
            pending_line: Vec::new(),
            discarding_line: false,
            initial_end: file_size as u64,
            identity,
            reset_observed: false,
            observed_len: file_size as u64,
        })
    }

    fn matches_current_file(&self, path: &Path) -> bool {
        self.identity.is_none_or(|identity| {
            File::open(path)
                .ok()
                .is_some_and(|file| file_identity(&file).is_none_or(|current| current == identity))
        })
    }

    fn read_new_lines(&mut self) -> std::io::Result<Vec<String>> {
        // Limit both work per poll and retained partial-line memory. A damaged
        // or actively growing log must not monopolize the watcher thread.
        const MAX_LINE_BYTES: usize = 64 * 1024;
        const MAX_POLL_BYTES: usize = 256 * 1024;
        const MAX_POLL_LINES: usize = 2048;
        // A log reused/truncated in place must not leave the old reader stuck
        // past EOF forever, or combine an old partial line with a new session.
        let length = self.reader.get_ref().metadata()?.len();
        if length < self.observed_len || length < self.reader.stream_position()? {
            self.reader.seek(SeekFrom::Start(0))?;
            self.pending_line.clear();
            self.discarding_line = false;
            self.initial_end = 0;
            self.reset_observed = true;
        }
        self.observed_len = length;
        let mut lines = Vec::new();
        let mut remaining = MAX_POLL_BYTES;
        while remaining > 0 && lines.len() < MAX_POLL_LINES {
            let available = self.reader.fill_buf()?;
            let available = &available[..available.len().min(remaining)];
            if available.is_empty() {
                break;
            }
            let count = available
                .iter()
                .position(|b| *b == b'\n')
                .map_or(available.len(), |position| position + 1);
            let complete = available[count - 1] == b'\n';
            if !self.discarding_line {
                if self.pending_line.len() + count > MAX_LINE_BYTES {
                    self.pending_line.clear();
                    self.discarding_line = true;
                } else {
                    self.pending_line.extend_from_slice(&available[..count]);
                }
            }
            self.reader.consume(count);
            remaining -= count;
            if complete {
                if !self.discarding_line {
                    let line = String::from_utf8_lossy(&self.pending_line);
                    let trimmed = line.trim_end();
                    if !trimmed.is_empty() {
                        lines.push(trimmed.to_string());
                    }
                }
                self.pending_line.clear();
                self.discarding_line = false;
            }
        }

        Ok(lines)
    }
}

fn file_identity(file: &File) -> Option<(u64, [u8; 16])> {
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::Storage::FileSystem::{
            FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx,
        };
        let mut info = FILE_ID_INFO::default();
        unsafe {
            GetFileInformationByHandleEx(
                HANDLE(file.as_raw_handle()),
                FileIdInfo,
                (&mut info as *mut FILE_ID_INFO).cast(),
                std::mem::size_of::<FILE_ID_INFO>() as u32,
            )
        }
        .ok()?;
        Some((info.VolumeSerialNumber, info.FileId.Identifier))
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata().ok()?;
        let mut id = [0; 16];
        id[..8].copy_from_slice(&metadata.ino().to_le_bytes());
        Some((metadata.dev(), id))
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = file;
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn vng_joins_keep_the_client_identity_for_library_and_rejoin() {
        let events = JoinTracker::default().feed(
            &[
                "! Joining game '550e8400-e29b-41d4-a716-446655440000' place 1818 at 128.116.47.33"
                    .into(),
                "[FLog::Network] serverId: 128.116.47.33".into(),
            ],
            true,
            RobloxClient::Vng,
        );
        assert!(
            matches!(&events[..], [RobloxEvent::GameJoined { client: RobloxClient::Vng, place_id, fresh_join: true, .. }] if place_id == "1818")
        );
    }
    #[test]
    fn player_open_and_close_are_detected_without_a_game_connection() {
        let mut tracker = JoinTracker::default();
        let lines = vec![
            "2026-10-13T07:35:01.660Z [FLog::DataModelStarterModule] Launching Lua App".into(),
            "2026-10-13T07:35:14.289Z [FLog::SingleSurfaceApp] leaveUGCGameInternal".into(),
        ];
        let events = tracker.feed(&lines, true, RobloxClient::Standard);
        assert_eq!(events.len(), 2);
        assert!(matches!(events[0], RobloxEvent::PlayerOpened));
        assert!(matches!(events[1], RobloxEvent::GameLeft { job_id: None }));
        assert!(
            JoinTracker::default()
                .feed(&lines, false, RobloxClient::Standard)
                .is_empty()
        );
    }
    #[test]
    fn private_rcc_address_is_confirmed_only_by_public_transport() {
        let mut tracker = JoinTracker::default();
        let join =
            "! Joining game '43967833-027f-4d08-8220-92f7d326b130' place 10449761463 at 10.35.4.27";
        assert!(
            tracker
                .feed(&[join.into()], true, RobloxClient::Standard)
                .is_empty()
        );
        let events = tracker.feed(
            &["[FLog::Network] serverId: 128.116.47.33|59611".into()],
            true,
            RobloxClient::Standard,
        );
        assert!(
            matches!(&events[0], RobloxEvent::GameJoined { ip, place_id, .. } if *ip == Ipv4Addr::new(128,116,47,33) && place_id == "10449761463")
        );
        let mut tracker = JoinTracker::default();
        assert!(
            tracker
                .feed(
                    &[
                        join.into(),
                        "[FLog::Network] serverId: 10.35.4.27|59611".into()
                    ],
                    true,
                    RobloxClient::Standard
                )
                .is_empty()
        );
        // Private/invalid intermediate lines cannot consume the pending join.
        let events = tracker.feed(
            &[
                "[FLog::Network] serverId: invalid".into(),
                "[FLog::Network] serverId: 128.116.47.33|59611".into(),
            ],
            true,
            RobloxClient::Standard,
        );
        assert!(
            matches!(&events[..], [RobloxEvent::GameJoined { place_id, .. }] if place_id == "10449761463")
        );
    }
    #[test]
    fn notifications_require_a_confirmed_connection_not_a_failed_join_attempt() {
        let mut tracker = JoinTracker::default();
        let join = "[FLog::Output] ! Joining game '550e8400-e29b-41d4-a716-446655440000' place 1818 at 34.1.2.3".to_string();
        assert!(
            tracker
                .feed(&[join], true, RobloxClient::Standard)
                .is_empty()
        );
        let events = tracker.feed(
            &["[FLog::Network] serverId: 34.1.2.3|49152".into()],
            true,
            RobloxClient::Standard,
        );
        assert!(
            matches!(&events[0], RobloxEvent::GameJoined { place_id, fresh_join: true, .. } if place_id == "1818")
        );
        let events = tracker.feed(
            &["[FLog::Network] Time to disconnect replication data: 0".into()],
            true,
            RobloxClient::Standard,
        );
        assert!(matches!(&events[0], RobloxEvent::GameLeft { .. }));
    }
    #[test]
    fn opening_after_a_closed_session_does_not_attach_old_game_metadata() {
        let mut tracker = JoinTracker::default();
        let lines = vec![
            "[FLog::Output] ! Joining game '550e8400-e29b-41d4-a716-446655440000' place 1818 at 34.1.2.3".into(),
            "[FLog::Network] serverId: 34.1.2.3|49152".into(),
            "[FLog::SingleSurfaceApp] leaveUGCGameInternal".into(),
        ];
        assert!(
            tracker
                .feed(&lines, false, RobloxClient::Standard)
                .is_empty()
        );
    }
    #[test]
    fn join_metadata_accepts_cloud_destinations_but_not_tokens_or_invalid_ids() {
        let join = "! Joining game '550e8400-e29b-41d4-a716-446655440000' place 1818 at 34.1.2.3";
        let (place, job, ip) = parse_join(join).unwrap();
        assert_eq!(place, "1818");
        assert!(valid_job_id(&job));
        assert_eq!(ip.to_string(), "34.1.2.3");
        assert!(parse_join(&join.replace("34.1.2.3", "10.35.4.27")).is_some());
        assert!(parse_join(&join.replace("1818", "0")).is_none());
        assert!(
            parse_join(&join.replace("550e8400-e29b-41d4-a716-446655440000", "abc-def")).is_none()
        );
    }
    #[test]
    fn player_log_selection_never_uses_studio_or_installer_logs() {
        let dir = std::env::temp_dir().join(format!("swift-log-selection-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("roblox_Player.log"), "player").unwrap();
        fs::write(dir.join("roblox_Studio.log"), "studio").unwrap();
        fs::write(dir.join("roblox_Installer.log"), "installer").unwrap();
        fs::write(dir.join("roblox_Player_CrashHandler_last.log"), "crash").unwrap();
        assert_eq!(
            find_newest_log_file(&dir).unwrap(),
            dir.join("roblox_Player.log")
        );
        fs::remove_dir_all(dir).unwrap();
    }
    use std::fs;
    use std::net::Ipv4Addr;

    fn tail_fixture(contents: &[u8]) -> (PathBuf, TailedFile) {
        let path = std::env::temp_dir().join(format!(
            "swifttunnel-tail-{}-{}.log",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(&path, contents).unwrap();
        let tail = TailedFile::new(&path).unwrap();
        (path, tail)
    }

    #[test]
    fn tail_consumes_invalid_utf8_once_and_keeps_following_events() {
        let (path, mut tail) =
            tail_fixture(b"bad\xfftext\nUDMUX Address = 198.51.100.10, Port = 54321\n");
        let lines = tail
            .read_new_lines()
            .expect("a malformed byte must not restart the watcher");
        assert_eq!(lines.len(), 2);
        assert!(get_patterns().1.is_match(&lines[1]));
        assert!(tail.read_new_lines().unwrap().is_empty());
        drop(tail);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn tail_waits_for_a_complete_line_before_detecting_an_address() {
        use std::io::Write;
        let (path, mut tail) = tail_fixture(b"UDMUX Address = 198.51.100.");
        assert!(tail.read_new_lines().unwrap().is_empty());
        let mut writer = fs::OpenOptions::new().append(true).open(&path).unwrap();
        writer.write_all(b"10, Port = 54321\n").unwrap();
        let lines = tail.read_new_lines().unwrap();
        assert_eq!(lines, ["UDMUX Address = 198.51.100.10, Port = 54321"]);
        drop(writer);
        drop(tail);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn a_truncated_log_cannot_leave_the_reader_at_old_eof_or_mix_partial_lines() {
        let (path, mut tail) = tail_fixture(b"old partial line without its delimiter");
        assert!(tail.read_new_lines().unwrap().is_empty());
        fs::write(&path, b"new\n").unwrap();
        assert_eq!(tail.read_new_lines().unwrap(), ["new"]);
        assert!(tail.reset_observed);
        assert_eq!(tail.initial_end, 0);
        assert!(tail.read_new_lines().unwrap().is_empty());
        drop(tail);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn same_path_replacement_is_not_the_same_open_log() {
        let (path, tail) = tail_fixture(b"old log\n");
        assert!(tail.matches_current_file(&path));
        assert!(tail.identity.is_some());
        let replacement = path.with_extension("replacement.log");
        fs::write(&replacement, b"new log\n").unwrap();
        fs::rename(&replacement, &path).unwrap();
        assert!(!tail.matches_current_file(&path));
        drop(tail);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn many_tiny_log_rows_are_read_in_bounded_batches_without_losing_the_join() {
        let mut contents = "noise\n".repeat(3000);
        contents.push_str("! Joining game '550e8400-e29b-41d4-a716-446655440000' place 1818 at 10.0.0.1\n[FLog::Network] serverId: 128.116.47.33\n");
        let (path, mut tail) = tail_fixture(contents.as_bytes());
        let first = tail.read_new_lines().unwrap();
        assert_eq!(first.len(), 2048);
        let second = tail.read_new_lines().unwrap();
        let events = JoinTracker::default().feed(&second, true, RobloxClient::Standard);
        assert!(
            matches!(&events[..], [RobloxEvent::GameJoined { place_id, .. }] if place_id == "1818")
        );
        drop(tail);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn tail_bounds_oversized_lines_and_recovers_after_the_delimiter() {
        use std::io::Write;
        let (path, mut tail) = tail_fixture(b"");
        let mut writer = fs::OpenOptions::new().append(true).open(&path).unwrap();
        writer.write_all(&vec![b'x'; 1024 * 1024]).unwrap();
        writer
            .write_all(b"\nUDMUX Address = 198.51.100.10, Port = 54321\n")
            .unwrap();
        assert!(tail.read_new_lines().unwrap().is_empty());
        assert!(tail.reader.stream_position().unwrap() <= 256 * 1024);
        assert!(tail.pending_line.len() <= 64 * 1024);
        let mut lines = Vec::new();
        for _ in 0..4 {
            lines.extend(tail.read_new_lines().unwrap());
        }
        assert_eq!(lines, ["UDMUX Address = 198.51.100.10, Port = 54321"]);
        drop(writer);
        drop(tail);
        fs::remove_file(path).unwrap();
    }

    // ── is_private_ip ───────────────────────────────────────────────

    #[test]
    fn is_private_ip_10_range() {
        assert!(is_private_ip(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_private_ip(Ipv4Addr::new(10, 255, 255, 255)));
    }

    #[test]
    fn is_private_ip_172_range() {
        assert!(is_private_ip(Ipv4Addr::new(172, 16, 0, 0)));
        assert!(is_private_ip(Ipv4Addr::new(172, 31, 255, 255)));
    }

    #[test]
    fn is_private_ip_192_168_range() {
        assert!(is_private_ip(Ipv4Addr::new(192, 168, 0, 1)));
        assert!(is_private_ip(Ipv4Addr::new(192, 168, 255, 255)));
    }

    #[test]
    fn is_private_ip_loopback() {
        assert!(is_private_ip(Ipv4Addr::new(127, 0, 0, 1)));
        assert!(is_private_ip(Ipv4Addr::new(127, 255, 255, 255)));
    }

    #[test]
    fn is_private_ip_public_ips_return_false() {
        assert!(!is_private_ip(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(!is_private_ip(Ipv4Addr::new(1, 1, 1, 1)));
        assert!(!is_private_ip(Ipv4Addr::new(203, 0, 113, 5)));
    }

    #[test]
    fn is_private_ip_boundary_172_15_is_public() {
        assert!(!is_private_ip(Ipv4Addr::new(172, 15, 255, 255)));
    }

    #[test]
    fn is_private_ip_boundary_172_32_is_public() {
        assert!(!is_private_ip(Ipv4Addr::new(172, 32, 0, 0)));
    }

    // ── get_patterns (regex matching) ───────────────────────────────

    #[test]
    fn joining_pattern_matches_log_line() {
        let (joining, _) = get_patterns();
        let line = "! Joining game 'abc-def-123' place 12345 at 203.0.113.5";
        let caps = joining
            .captures(line)
            .expect("should match joining pattern");
        assert_eq!(caps.get(1).unwrap().as_str(), "203.0.113.5");
    }

    #[test]
    fn udmux_pattern_matches_log_line() {
        let (_, udmux) = get_patterns();
        let line = "UDMUX Address = 198.51.100.10, Port = 54321";
        let caps = udmux.captures(line).expect("should match udmux pattern");
        assert_eq!(caps.get(1).unwrap().as_str(), "198.51.100.10");
    }

    #[test]
    fn patterns_do_not_match_random_strings() {
        let (joining, udmux) = get_patterns();
        let line = "Loading assets from CDN...";
        assert!(joining.captures(line).is_none());
        assert!(udmux.captures(line).is_none());
    }

    #[test]
    fn joining_pattern_captures_ip_only() {
        let (joining, _) = get_patterns();
        let line = "! Joining game '550e8400-e29b-41d4-a716-446655440000' place 99999 at 1.2.3.4";
        let caps = joining.captures(line).unwrap();
        assert_eq!(caps.get(1).unwrap().as_str(), "1.2.3.4");
    }

    // ── find_newest_log_file ────────────────────────────────────────

    #[test]
    fn find_newest_log_file_returns_most_recent() {
        let dir = std::env::temp_dir().join("roblox_watcher_test_logs");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        // Create older file
        let old_path = dir.join("old_Player.log");
        fs::write(&old_path, "old").unwrap();

        // Small delay to ensure different modification times
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Create newer file
        let new_path = dir.join("new_Player.log");
        fs::write(&new_path, "new").unwrap();

        let result = find_newest_log_file(&dir).unwrap();
        assert_eq!(result, new_path);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn find_newest_log_file_ignores_non_log_files() {
        let dir = std::env::temp_dir().join("roblox_watcher_test_nonlog");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        fs::write(dir.join("data.txt"), "not a log").unwrap();
        fs::write(dir.join("actual_Player.log"), "a log").unwrap();

        let result = find_newest_log_file(&dir).unwrap();
        assert_eq!(result, dir.join("actual_Player.log"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn find_newest_log_file_returns_none_for_empty_dir() {
        let dir = std::env::temp_dir().join("roblox_watcher_test_empty");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        assert!(find_newest_log_file(&dir).is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn log_directory_cache_keeps_polling_cheap_and_discovers_new_files() {
        let dir =
            std::env::temp_dir().join(format!("roblox_directory_cache_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let at = std::time::Instant::now();
        let mut cache = LogDirectory::new(dir.clone());
        assert_eq!(cache.newest(at), None);
        fs::create_dir_all(&dir).unwrap();
        let first = dir.join("first_Player.log");
        fs::write(&first, "first").unwrap();
        assert_eq!(
            cache.newest(at + Duration::from_secs(2)),
            Some(first.clone())
        );
        let scans = cache.scans;
        for seconds in 3..20 {
            assert_eq!(
                cache.newest(at + Duration::from_secs(seconds)),
                Some(first.clone())
            );
        }
        assert_eq!(cache.scans, scans);
        std::thread::sleep(Duration::from_millis(50));
        let second = dir.join("second_Player.log");
        fs::write(&second, "second").unwrap();
        assert_eq!(
            cache.newest(at + Duration::from_secs(21)),
            Some(second.clone())
        );
        fs::remove_file(&second).unwrap();
        assert_eq!(
            cache.newest(at + Duration::from_secs(22)),
            Some(first.clone())
        );
        assert_eq!(cache.newest(at + Duration::from_secs(53)), Some(first));
        assert!(cache.scans >= scans + 3);
        let _ = fs::remove_dir_all(dir);
    }
}
