//! Utility functions for SwiftTunnel (macOS)

use std::future::Future;
use std::process::Command;
use std::time::Duration;
use std::path::PathBuf;

/// Create a Command (no special flags needed on macOS unlike Windows CREATE_NO_WINDOW)
pub fn hidden_command(program: &str) -> Command {
    Command::new(program)
}

/// Check if the current process has root privileges
pub fn is_administrator() -> bool {
    unsafe { libc::geteuid() == 0 }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  URL OPENING
// ═══════════════════════════════════════════════════════════════════════════════

/// Open a URL in the user's default browser using macOS `open` command
pub fn open_url(url: &str) {
    if let Err(e) = Command::new("open").arg(url).spawn() {
        log::warn!("Failed to open URL '{}': {}", url, e);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  ELEVATION UTILITIES
// ═══════════════════════════════════════════════════════════════════════════════

/// Pending connection state to pass between non-elevated and elevated process
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct PendingConnection {
    pub region: String,
    pub server: String,
    pub apps: Vec<String>,
    pub routing_mode: u8, // 0 = V1, 1 = V2
    pub timestamp: u64,
}

/// Get the macOS Application Support directory for SwiftTunnel
fn swifttunnel_data_dir() -> PathBuf {
    dirs::data_dir()
        .map(|d| d.join("SwiftTunnel"))
        .unwrap_or_else(|| {
            // Fallback: ~/Library/Application Support/SwiftTunnel
            dirs::home_dir()
                .map(|h| h.join("Library").join("Application Support").join("SwiftTunnel"))
                .unwrap_or_else(|| PathBuf::from("/tmp/SwiftTunnel"))
        })
}

/// Get the path for the pending connection temp file
pub fn pending_connection_path() -> PathBuf {
    swifttunnel_data_dir().join("pending_connect.json")
}

/// Save pending connection state for elevated process to pick up
pub fn save_pending_connection(pending: &PendingConnection) -> std::io::Result<()> {
    let path = pending_connection_path();

    // Ensure directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let json = serde_json::to_string(pending)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

    std::fs::write(&path, json)?;
    log::info!("Saved pending connection to: {}", path.display());
    Ok(())
}

/// Load and delete pending connection state
///
/// Returns Some(PendingConnection) if a valid pending connection exists,
/// None if no file or file is too old (>30 seconds).
pub fn load_pending_connection() -> Option<PendingConnection> {
    let path = pending_connection_path();

    if !path.exists() {
        return None;
    }

    // Read and delete the file
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(e) => {
            log::warn!("Failed to read pending connection file: {}", e);
            let _ = std::fs::remove_file(&path);
            return None;
        }
    };

    // Delete the file immediately to prevent reuse
    let _ = std::fs::remove_file(&path);

    // Parse JSON
    let pending: PendingConnection = match serde_json::from_str(&content) {
        Ok(p) => p,
        Err(e) => {
            log::warn!("Failed to parse pending connection: {}", e);
            return None;
        }
    };

    // Check timestamp - reject if older than 30 seconds
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if now - pending.timestamp > 30 {
        log::warn!("Pending connection expired ({}s old)", now - pending.timestamp);
        return None;
    }

    log::info!("Loaded pending connection: region={}, server={}", pending.region, pending.server);
    Some(pending)
}

/// Relaunch the current process with administrator privileges using osascript
///
/// Uses AppleScript `do shell script ... with administrator privileges` to trigger
/// the macOS authorization dialog. The current process should exit after calling this.
pub fn relaunch_elevated() -> std::io::Result<()> {
    let exe_path = std::env::current_exe()?;
    let exe_path_str = exe_path.to_string_lossy();

    log::info!("Relaunching elevated: {}", exe_path_str);

    // Use osascript to request admin privileges via macOS authorization dialog
    let script = format!(
        "do shell script \"'{}' --resume-connect\" with administrator privileges",
        exe_path_str.replace('\'', "'\\''")
    );

    let result = Command::new("osascript")
        .args(["-e", &script])
        .spawn();

    match result {
        Ok(_) => {
            log::info!("Elevated process launched successfully");
            Ok(())
        }
        Err(e) => {
            log::error!("Failed to launch elevated process: {}", e);
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("Failed to elevate: {}", e),
            ))
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  RETRY UTILITIES
// ═══════════════════════════════════════════════════════════════════════════════

/// Default retry delays in milliseconds (exponential backoff)
const DEFAULT_RETRY_DELAYS: [u64; 3] = [1000, 2000, 4000];

/// Retry an async operation with exponential backoff
pub async fn with_retry<T, E, F, Fut>(
    max_attempts: u32,
    operation: F,
) -> Result<T, E>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: std::fmt::Display,
{
    let max_attempts = max_attempts.clamp(1, 10);
    let mut last_error: Option<E> = None;

    for attempt in 1..=max_attempts {
        match operation().await {
            Ok(value) => return Ok(value),
            Err(e) => {
                if attempt < max_attempts {
                    let delay_idx = (attempt as usize - 1).min(DEFAULT_RETRY_DELAYS.len() - 1);
                    let delay_ms = DEFAULT_RETRY_DELAYS[delay_idx];
                    log::warn!(
                        "Attempt {}/{} failed: {}, retrying in {}ms...",
                        attempt, max_attempts, e, delay_ms
                    );
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                } else {
                    log::error!("All {} attempts failed. Last error: {}", max_attempts, e);
                }
                last_error = Some(e);
            }
        }
    }

    Err(last_error.expect("at least one attempt should have been made"))
}

/// Retry a synchronous operation with exponential backoff
pub fn with_retry_sync<T, E, F>(
    max_attempts: u32,
    operation: F,
) -> Result<T, E>
where
    F: Fn() -> Result<T, E>,
    E: std::fmt::Display,
{
    let max_attempts = max_attempts.clamp(1, 10);
    let mut last_error: Option<E> = None;

    for attempt in 1..=max_attempts {
        match operation() {
            Ok(value) => return Ok(value),
            Err(e) => {
                if attempt < max_attempts {
                    let delay_idx = (attempt as usize - 1).min(DEFAULT_RETRY_DELAYS.len() - 1);
                    let delay_ms = DEFAULT_RETRY_DELAYS[delay_idx];
                    log::warn!(
                        "Attempt {}/{} failed: {}, retrying in {}ms...",
                        attempt, max_attempts, e, delay_ms
                    );
                    std::thread::sleep(Duration::from_millis(delay_ms));
                } else {
                    log::error!("All {} attempts failed. Last error: {}", max_attempts, e);
                }
                last_error = Some(e);
            }
        }
    }

    Err(last_error.expect("at least one attempt should have been made"))
}

// ═══════════════════════════════════════════════════════════════════════════════
//  LOG ROTATION
// ═══════════════════════════════════════════════════════════════════════════════

/// Maximum log file size before rotation (1MB)
const MAX_LOG_SIZE: u64 = 1024 * 1024;

/// Rotate log file if it exceeds the maximum size
///
/// Renames the current log to .old (deleting previous .old) if it's too large.
/// Returns Ok(true) if rotation occurred, Ok(false) if not needed.
pub fn rotate_log_if_needed(log_path: &std::path::Path) -> std::io::Result<bool> {
    if !log_path.exists() {
        return Ok(false);
    }

    let metadata = std::fs::metadata(log_path)?;
    if metadata.len() <= MAX_LOG_SIZE {
        return Ok(false);
    }

    // Create .old path
    let old_path = log_path.with_extension("log.old");

    // Delete previous .old file if it exists
    if old_path.exists() {
        let _ = std::fs::remove_file(&old_path);
    }

    // Rename current log to .old
    std::fs::rename(log_path, &old_path)?;

    log::info!("Rotated log file: {} -> {}", log_path.display(), old_path.display());
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hidden_command() {
        let cmd = hidden_command("echo");
        assert!(format!("{:?}", cmd).contains("echo"));
    }

    #[test]
    fn test_is_administrator() {
        // In normal test execution, we shouldn't be root
        // Just verify it doesn't panic
        let _ = is_administrator();
    }

    #[tokio::test]
    async fn test_with_retry_success_first_attempt() {
        let result: Result<i32, &str> = with_retry(3, || async { Ok(42) }).await;
        assert_eq!(result, Ok(42));
    }

    #[tokio::test]
    async fn test_with_retry_all_fail() {
        let result: Result<i32, &str> = with_retry(2, || async { Err("error") }).await;
        assert_eq!(result, Err("error"));
    }

    #[test]
    fn test_with_retry_sync_success() {
        let result: Result<i32, &str> = with_retry_sync(3, || Ok(42));
        assert_eq!(result, Ok(42));
    }

    #[test]
    fn test_swifttunnel_data_dir() {
        let dir = swifttunnel_data_dir();
        assert!(dir.to_string_lossy().contains("SwiftTunnel"));
    }
}
