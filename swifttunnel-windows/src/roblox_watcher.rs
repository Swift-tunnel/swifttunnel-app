//! Roblox Log File Watcher
//!
//! Monitors Roblox log files to detect game server IPs BEFORE the connection starts.
//! This enables ExitLag-style automatic region switching based on detected server location.
//!
//! ## How it works:
//! 1. Watches %LOCALAPPDATA%\Roblox\logs\ for new log files
//! 2. Tails the latest log file in real-time
//! 3. Parses for UDMUX Address patterns (DDoS proxy IP)
//! 4. Emits events with server IP for region switching
//!
//! ## Log patterns (from Bloxstrap):
//! - UDMUX Address = 1.2.3.4, Port = 12345 (primary - DDoS proxy)
//! - ! Joining game 'uuid' place 123 at 1.2.3.4 (fallback)

use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime};

use log::{debug, error, info, warn};
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use regex::Regex;

/// Events emitted by the Roblox watcher
#[derive(Debug, Clone)]
pub enum RobloxEvent {
    /// Detected a game server IP that we're about to connect to
    GameServerDetected {
        ip: Ipv4Addr,
        /// Timestamp when the IP was detected
        timestamp: SystemTime,
    },
    /// Roblox started (new log file created)
    RobloxStarted,
    /// Roblox stopped (process ended)
    RobloxStopped,
    /// Error watching files
    WatchError(String),
}

/// Configuration for the Roblox watcher
#[derive(Debug, Clone)]
pub struct WatcherConfig {
    /// How often to poll the log file for new content (ms)
    pub poll_interval_ms: u64,
    /// Maximum age of a log file to consider it "current" (seconds)
    pub max_log_age_secs: u64,
    /// Whether to emit duplicate IPs (same IP seen again)
    pub emit_duplicates: bool,
}

impl Default for WatcherConfig {
    fn default() -> Self {
        Self {
            poll_interval_ms: 100, // 100ms poll for real-time detection
            max_log_age_secs: 300, // 5 minutes - log files older are ignored
            emit_duplicates: false, // Don't spam duplicate IP events
        }
    }
}

/// Roblox log file watcher
pub struct RobloxWatcher {
    /// Receiver for events
    event_rx: mpsc::Receiver<RobloxEvent>,
    /// Stop signal for the watcher thread
    stop_signal: Arc<AtomicBool>,
    /// Watcher thread handle
    thread_handle: Option<thread::JoinHandle<()>>,
}

impl RobloxWatcher {
    /// Create a new Roblox watcher
    ///
    /// Returns None if the Roblox logs directory doesn't exist
    pub fn new(config: WatcherConfig) -> Option<Self> {
        let logs_dir = get_roblox_logs_dir()?;

        if !logs_dir.exists() {
            warn!("Roblox logs directory does not exist: {}", logs_dir.display());
            return None;
        }

        info!("Starting Roblox watcher on: {}", logs_dir.display());

        let (event_tx, event_rx) = mpsc::channel();
        let stop_signal = Arc::new(AtomicBool::new(false));
        let stop_signal_clone = Arc::clone(&stop_signal);

        let thread_handle = thread::spawn(move || {
            run_watcher_loop(logs_dir, event_tx, stop_signal_clone, config);
        });

        Some(Self {
            event_rx,
            stop_signal,
            thread_handle: Some(thread_handle),
        })
    }

    /// Try to receive an event without blocking
    pub fn try_recv(&self) -> Option<RobloxEvent> {
        self.event_rx.try_recv().ok()
    }

    /// Receive an event, blocking until one is available
    pub fn recv(&self) -> Option<RobloxEvent> {
        self.event_rx.recv().ok()
    }

    /// Receive an event with timeout
    pub fn recv_timeout(&self, timeout: Duration) -> Option<RobloxEvent> {
        self.event_rx.recv_timeout(timeout).ok()
    }

    /// Check if the watcher is still running
    pub fn is_running(&self) -> bool {
        !self.stop_signal.load(Ordering::Relaxed)
    }

    /// Stop the watcher
    pub fn stop(&self) {
        self.stop_signal.store(true, Ordering::Relaxed);
    }
}

impl Drop for RobloxWatcher {
    fn drop(&mut self) {
        self.stop_signal.store(true, Ordering::Relaxed);
        if let Some(handle) = self.thread_handle.take() {
            let _ = handle.join();
        }
    }
}

/// Get the Roblox logs directory path
fn get_roblox_logs_dir() -> Option<PathBuf> {
    dirs::data_local_dir().map(|d| d.join("Roblox").join("logs"))
}

/// Main watcher loop - runs in a background thread
fn run_watcher_loop(
    logs_dir: PathBuf,
    event_tx: mpsc::Sender<RobloxEvent>,
    stop_signal: Arc<AtomicBool>,
    config: WatcherConfig,
) {
    // Compile regex patterns once
    // UDMUX Address = 1.2.3.4, Port = 12345
    let udmux_pattern = Regex::new(r"UDMUX Address = ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)").unwrap();
    // ! Joining game 'uuid' place 123 at 1.2.3.4
    let join_pattern = Regex::new(r"! Joining game '[0-9a-f\-]+' place \d+ at ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)").unwrap();

    // Track seen IPs to avoid duplicates
    let seen_ips: Arc<Mutex<HashSet<Ipv4Addr>>> = Arc::new(Mutex::new(HashSet::new()));

    // Current file being tailed
    let current_file: Arc<Mutex<Option<TailedFile>>> = Arc::new(Mutex::new(None));

    // Set up file system watcher for new log files
    let (fs_tx, fs_rx) = mpsc::channel();

    let watcher_result = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
        if let Ok(event) = res {
            let _ = fs_tx.send(event);
        }
    });

    let mut watcher = match watcher_result {
        Ok(w) => w,
        Err(e) => {
            let _ = event_tx.send(RobloxEvent::WatchError(format!("Failed to create watcher: {}", e)));
            return;
        }
    };

    if let Err(e) = watcher.watch(&logs_dir, RecursiveMode::NonRecursive) {
        let _ = event_tx.send(RobloxEvent::WatchError(format!("Failed to watch directory: {}", e)));
        return;
    }

    // Find the most recent log file to start tailing
    if let Some(latest) = find_latest_log_file(&logs_dir, config.max_log_age_secs) {
        info!("Found existing log file: {}", latest.display());
        if let Ok(tf) = TailedFile::new(&latest) {
            *current_file.lock().unwrap() = Some(tf);
        }
    }

    let poll_interval = Duration::from_millis(config.poll_interval_ms);

    // Main loop
    while !stop_signal.load(Ordering::Relaxed) {
        // Check for new files from watcher
        while let Ok(event) = fs_rx.try_recv() {
            if let EventKind::Create(_) = event.kind {
                for path in event.paths {
                    if is_roblox_log_file(&path) {
                        info!("New Roblox log file: {}", path.display());
                        let _ = event_tx.send(RobloxEvent::RobloxStarted);

                        // Start tailing the new file
                        if let Ok(tf) = TailedFile::new(&path) {
                            *current_file.lock().unwrap() = Some(tf);
                            // Clear seen IPs for new session
                            seen_ips.lock().unwrap().clear();
                        }
                    }
                }
            }
        }

        // Poll current file for new lines
        let mut current_lock = current_file.lock().unwrap();
        if let Some(ref mut tailed) = *current_lock {
            match tailed.read_new_lines() {
                Ok(lines) => {
                    for line in lines {
                        // Check for UDMUX pattern (primary)
                        if let Some(caps) = udmux_pattern.captures(&line) {
                            if let Some(ip_match) = caps.get(1) {
                                if let Ok(ip) = Ipv4Addr::from_str(ip_match.as_str()) {
                                    let should_emit = config.emit_duplicates || {
                                        let mut seen = seen_ips.lock().unwrap();
                                        seen.insert(ip)
                                    };

                                    if should_emit {
                                        info!("Detected game server IP (UDMUX): {}", ip);
                                        let _ = event_tx.send(RobloxEvent::GameServerDetected {
                                            ip,
                                            timestamp: SystemTime::now(),
                                        });
                                    }
                                }
                            }
                        }
                        // Check for join pattern (fallback)
                        else if let Some(caps) = join_pattern.captures(&line) {
                            if let Some(ip_match) = caps.get(1) {
                                if let Ok(ip) = Ipv4Addr::from_str(ip_match.as_str()) {
                                    let should_emit = config.emit_duplicates || {
                                        let mut seen = seen_ips.lock().unwrap();
                                        seen.insert(ip)
                                    };

                                    if should_emit {
                                        info!("Detected game server IP (Join): {}", ip);
                                        let _ = event_tx.send(RobloxEvent::GameServerDetected {
                                            ip,
                                            timestamp: SystemTime::now(),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    debug!("Error reading log file: {}", e);
                    // File might have been deleted/rotated
                    *current_lock = None;
                }
            }
        }
        drop(current_lock);

        thread::sleep(poll_interval);
    }

    info!("Roblox watcher stopped");
}

/// Find the most recent Roblox log file
fn find_latest_log_file(logs_dir: &Path, max_age_secs: u64) -> Option<PathBuf> {
    let entries = fs::read_dir(logs_dir).ok()?;
    let now = SystemTime::now();

    entries
        .filter_map(|e| e.ok())
        .filter(|e| is_roblox_log_file(&e.path()))
        .filter_map(|e| {
            let metadata = e.metadata().ok()?;
            let modified = metadata.modified().ok()?;
            let age = now.duration_since(modified).ok()?;

            // Skip old files
            if age.as_secs() > max_age_secs {
                return None;
            }

            Some((e.path(), modified))
        })
        .max_by_key(|(_, modified)| *modified)
        .map(|(path, _)| path)
}

/// Check if a path is a Roblox log file
fn is_roblox_log_file(path: &Path) -> bool {
    let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    // Roblox log files are named like: 0.xxx.log
    filename.ends_with(".log") &&
    filename.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false)
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

        // Seek to end - we only care about new content
        reader.seek(SeekFrom::End(0))?;

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
                Ok(0) => break, // No more data
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

/// Map a game server IP to a VPN region
/// Returns the region ID (e.g., "singapore", "germany") for routing
pub fn map_ip_to_region(ip: Ipv4Addr, location: &str) -> Option<String> {
    // Parse location string to determine best VPN region
    // Location format: "City, Region, Country" or "City, Country"
    let location_lower = location.to_lowercase();

    // Asia-Pacific
    if location_lower.contains("singapore") || location_lower.contains(", sg") {
        return Some("singapore".to_string());
    }
    if location_lower.contains("tokyo") || location_lower.contains("japan") || location_lower.contains(", jp") {
        return Some("tokyo".to_string());
    }
    if location_lower.contains("sydney") || location_lower.contains("australia") || location_lower.contains(", au") {
        return Some("sydney".to_string());
    }
    if location_lower.contains("mumbai") || location_lower.contains("india") || location_lower.contains(", in") {
        return Some("mumbai".to_string());
    }
    if location_lower.contains("hong kong") || location_lower.contains(", hk") {
        return Some("singapore".to_string()); // Route to Singapore
    }

    // Europe
    if location_lower.contains("germany") || location_lower.contains(", de") ||
       location_lower.contains("frankfurt") || location_lower.contains("berlin") {
        return Some("germany".to_string());
    }
    if location_lower.contains("france") || location_lower.contains(", fr") ||
       location_lower.contains("paris") {
        return Some("paris".to_string());
    }
    if location_lower.contains("london") || location_lower.contains("uk") ||
       location_lower.contains("united kingdom") || location_lower.contains(", gb") {
        return Some("germany".to_string()); // Route to Germany (closest)
    }
    if location_lower.contains("amsterdam") || location_lower.contains("netherlands") ||
       location_lower.contains(", nl") {
        return Some("germany".to_string()); // Route to Germany
    }

    // Americas
    if location_lower.contains("united states") || location_lower.contains(", us") ||
       location_lower.contains("virginia") || location_lower.contains("california") ||
       location_lower.contains("ohio") || location_lower.contains("oregon") ||
       location_lower.contains("new york") || location_lower.contains("texas") {
        return Some("america".to_string());
    }
    if location_lower.contains("brazil") || location_lower.contains(", br") ||
       location_lower.contains("sao paulo") {
        return Some("brazil".to_string());
    }
    if location_lower.contains("canada") || location_lower.contains(", ca") {
        return Some("america".to_string()); // Route to US
    }

    // Fallback based on IP ranges (Roblox servers)
    // These are approximate guesses based on common hosting locations
    let first_octet = ip.octets()[0];
    match first_octet {
        // AWS ranges often start with certain prefixes
        3 | 18 | 54 | 52 => Some("america".to_string()),  // Likely US/AWS
        35 => Some("america".to_string()), // Google Cloud US
        _ => None,
    }
}

/// Determine standby regions based on user's primary region
/// Returns 1-2 regions to keep as warm standby tunnels
pub fn get_standby_regions(primary_region: &str) -> Vec<String> {
    match primary_region {
        // Asia-Pacific users
        "singapore" | "tokyo" | "mumbai" | "sydney" => {
            vec!["america".to_string(), "germany".to_string()]
        }
        // Europe users
        "germany" | "paris" => {
            vec!["america".to_string(), "singapore".to_string()]
        }
        // Americas users
        "america" | "brazil" => {
            vec!["germany".to_string(), "singapore".to_string()]
        }
        // Default
        _ => vec!["america".to_string(), "singapore".to_string()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udmux_pattern() {
        let pattern = Regex::new(r"UDMUX Address = ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)").unwrap();

        let line = "2024.01.15 12:34:56.789 UDMUX Address = 128.116.50.100, Port = 12345";
        let caps = pattern.captures(line).unwrap();
        assert_eq!(caps.get(1).unwrap().as_str(), "128.116.50.100");
    }

    #[test]
    fn test_join_pattern() {
        let pattern = Regex::new(r"! Joining game '[0-9a-f\-]+' place \d+ at ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)").unwrap();

        let line = "! Joining game 'a1b2c3d4-e5f6-7890-abcd-ef1234567890' place 12345678 at 209.206.42.10";
        let caps = pattern.captures(line).unwrap();
        assert_eq!(caps.get(1).unwrap().as_str(), "209.206.42.10");
    }

    #[test]
    fn test_map_ip_to_region() {
        assert_eq!(map_ip_to_region(Ipv4Addr::new(1, 2, 3, 4), "Singapore, SG"), Some("singapore".to_string()));
        assert_eq!(map_ip_to_region(Ipv4Addr::new(1, 2, 3, 4), "Ashburn, Virginia, US"), Some("america".to_string()));
        assert_eq!(map_ip_to_region(Ipv4Addr::new(1, 2, 3, 4), "Frankfurt, Germany"), Some("germany".to_string()));
        assert_eq!(map_ip_to_region(Ipv4Addr::new(1, 2, 3, 4), "Tokyo, Japan"), Some("tokyo".to_string()));
        assert_eq!(map_ip_to_region(Ipv4Addr::new(1, 2, 3, 4), "Sydney, AU"), Some("sydney".to_string()));
    }

    #[test]
    fn test_is_roblox_log_file() {
        assert!(is_roblox_log_file(Path::new("0.604.1.6040677.log")));
        assert!(is_roblox_log_file(Path::new("0.123.456.log")));
        assert!(!is_roblox_log_file(Path::new("player.log")));
        assert!(!is_roblox_log_file(Path::new("readme.txt")));
    }

    #[test]
    fn test_get_standby_regions() {
        let standby = get_standby_regions("singapore");
        assert!(standby.contains(&"america".to_string()));
        assert!(standby.contains(&"germany".to_string()));

        let standby = get_standby_regions("america");
        assert!(standby.contains(&"germany".to_string()));
        assert!(standby.contains(&"singapore".to_string()));
    }
}
