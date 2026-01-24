//! Roblox Log Watcher
//!
//! Monitors Roblox log files to detect game server IPs.
//! Similar to Bloxstrap's server location notification feature.

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;
use regex::Regex;

/// Events emitted by the Roblox watcher
#[derive(Debug, Clone)]
pub enum RobloxEvent {
    /// Detected a game server connection
    GameServerDetected { ip: Ipv4Addr },
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
        let logs_dir = get_roblox_logs_dir()?;

        if !logs_dir.exists() {
            log::warn!("Roblox logs directory not found: {:?}", logs_dir);
            return None;
        }

        let (sender, receiver) = mpsc::channel();
        let stop_flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_flag_clone = stop_flag.clone();

        // Spawn watcher thread
        thread::spawn(move || {
            watch_logs(logs_dir, sender, stop_flag_clone);
        });

        log::info!("Roblox log watcher started");
        Some(Self { receiver, stop_flag })
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
        self.stop_flag.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Drop for RobloxWatcher {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Get Roblox logs directory path
fn get_roblox_logs_dir() -> Option<PathBuf> {
    let local_app_data = std::env::var("LOCALAPPDATA").ok()?;
    Some(PathBuf::from(local_app_data).join("Roblox").join("logs"))
}

/// Main log watching loop
fn watch_logs(
    logs_dir: PathBuf,
    sender: Sender<RobloxEvent>,
    stop_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    // Regex patterns for detecting game server IPs
    // Pattern 1: "! Joining game 'JOBID' place PLACEID at IPADDRESS"
    let joining_pattern = Regex::new(r"! Joining game '[0-9a-f\-]+' place \d+ at (\d+\.\d+\.\d+\.\d+)").ok();

    // Pattern 2: "UDMUX Address = IPADDRESS, Port = PORT"
    let udmux_pattern = Regex::new(r"UDMUX Address = (\d+\.\d+\.\d+\.\d+), Port = \d+").ok();

    let mut seen_ips: HashSet<Ipv4Addr> = HashSet::new();
    let mut current_file: Option<TailedFile> = None;
    let mut last_file_check = std::time::Instant::now();

    loop {
        if stop_flag.load(std::sync::atomic::Ordering::SeqCst) {
            log::info!("Roblox watcher stopping");
            break;
        }

        // Check for new/updated log file every 2 seconds
        if last_file_check.elapsed() > Duration::from_secs(2) {
            if let Some(newest) = find_newest_log_file(&logs_dir) {
                let should_switch = current_file.as_ref()
                    .map(|f| f.path != newest)
                    .unwrap_or(true);

                if should_switch {
                    log::info!("Watching log file: {:?}", newest);
                    current_file = TailedFile::new(&newest).ok();
                    seen_ips.clear(); // Reset seen IPs for new session
                }
            }
            last_file_check = std::time::Instant::now();
        }

        // Read new lines from current file
        if let Some(ref mut file) = current_file {
            if let Ok(lines) = file.read_new_lines() {
                for line in lines {
                    // Try each pattern
                    for pattern in [&joining_pattern, &udmux_pattern].iter().flatten() {
                        if let Some(caps) = pattern.captures(&line) {
                            if let Some(ip_match) = caps.get(1) {
                                if let Ok(ip) = ip_match.as_str().parse::<Ipv4Addr>() {
                                    // Skip private IPs (10.x.x.x, 192.168.x.x, etc.)
                                    if !is_private_ip(ip) && !seen_ips.contains(&ip) {
                                        seen_ips.insert(ip);
                                        log::info!("Detected game server: {}", ip);
                                        let _ = sender.send(RobloxEvent::GameServerDetected { ip });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        thread::sleep(Duration::from_millis(500));
    }
}

/// Find the newest log file in the directory
fn find_newest_log_file(dir: &Path) -> Option<PathBuf> {
    fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path().extension().map(|ext| ext == "log").unwrap_or(false)
        })
        .max_by_key(|e| e.metadata().ok().and_then(|m| m.modified().ok()))
        .map(|e| e.path())
}

/// Check if IP is private (RFC 1918)
fn is_private_ip(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
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
}

impl TailedFile {
    fn new(path: &Path) -> std::io::Result<Self> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);

        // Read last 64KB to catch current session
        const TAIL_BYTES: i64 = 65536;
        let file_size = reader.seek(SeekFrom::End(0))? as i64;
        let start_pos = (file_size - TAIL_BYTES).max(0);
        reader.seek(SeekFrom::Start(start_pos as u64))?;

        Ok(Self {
            reader,
            path: path.to_path_buf(),
        })
    }

    fn read_new_lines(&mut self) -> std::io::Result<Vec<String>> {
        let mut lines = Vec::new();
        let mut line = String::new();

        loop {
            match self.reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    let trimmed = line.trim_end().to_string();
                    if !trimmed.is_empty() {
                        lines.push(trimmed);
                    }
                    line.clear();
                }
                Err(e) => return Err(e),
            }
        }

        Ok(lines)
    }
}
