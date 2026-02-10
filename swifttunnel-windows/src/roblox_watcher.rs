//! Roblox Log Watcher
//!
//! Monitors Roblox log files to detect game server IPs.
//! Similar to Bloxstrap's server location notification feature.

use regex_lite::Regex;
use std::collections::HashSet;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;

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

/// Get Roblox logs directory path
fn get_roblox_logs_dir() -> Option<PathBuf> {
    let local_app_data = std::env::var("LOCALAPPDATA").ok()?;
    Some(PathBuf::from(local_app_data).join("Roblox").join("logs"))
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
    logs_dir: PathBuf,
    sender: Sender<RobloxEvent>,
    stop_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    // Get compiled regex patterns (compiled once, reused)
    let (joining_pattern, udmux_pattern) = get_patterns();

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
                let should_switch = current_file
                    .as_ref()
                    .map(|f| f.path != newest)
                    .unwrap_or(true);

                if should_switch {
                    log::info!("Switching to log file: {:?}", newest);
                    match TailedFile::new(&newest) {
                        Ok(file) => {
                            current_file = Some(file);
                            seen_ips.clear(); // Reset seen IPs for new session
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
            match file.read_new_lines() {
                Ok(lines) => {
                    for line in lines {
                        // Try each pattern
                        for pattern in [joining_pattern, udmux_pattern] {
                            if let Some(caps) = pattern.captures(&line) {
                                if let Some(ip_match) = caps.get(1) {
                                    if let Ok(ip) = ip_match.as_str().parse::<Ipv4Addr>() {
                                        // Skip private IPs (10.x.x.x, 192.168.x.x, etc.)
                                        if !is_private_ip(ip) && !seen_ips.contains(&ip) {
                                            seen_ips.insert(ip);
                                            log::info!("Detected game server: {}", ip);
                                            let _ =
                                                sender.send(RobloxEvent::GameServerDetected { ip });
                                        }
                                    }
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

/// Find the newest log file in the directory
fn find_newest_log_file(dir: &Path) -> Option<PathBuf> {
    fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "log")
                .unwrap_or(false)
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

        // Skip first potentially incomplete line if not at file start
        if start_pos > 0 {
            let mut discard = String::new();
            let _ = reader.read_line(&mut discard);
        }

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::net::Ipv4Addr;

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
        let old_path = dir.join("old.log");
        fs::write(&old_path, "old").unwrap();

        // Small delay to ensure different modification times
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Create newer file
        let new_path = dir.join("new.log");
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
        fs::write(dir.join("actual.log"), "a log").unwrap();

        let result = find_newest_log_file(&dir).unwrap();
        assert_eq!(result, dir.join("actual.log"));

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
}
