//! Utility functions for SwiftTunnel

use std::future::Future;
use std::process::Command;
use std::time::Duration;
use std::path::PathBuf;

#[cfg(windows)]
use std::os::windows::process::CommandExt;

/// Windows CREATE_NO_WINDOW flag to prevent console windows from appearing
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Create a Command that won't show a console window on Windows
///
/// This is essential for GUI apps to prevent scary command prompts
/// from flashing when running shell commands in the background.
pub fn hidden_command(program: &str) -> Command {
    let mut cmd = Command::new(program);

    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);

    cmd
}

/// Check if the current process has administrator privileges
///
/// Returns true if running with elevated privileges, false otherwise.
#[cfg(windows)]
pub fn is_administrator() -> bool {
    unsafe {
        use windows::Win32::Security::{
            GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
        };
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        use windows::Win32::Foundation::CloseHandle;

        let mut token_handle = windows::Win32::Foundation::HANDLE::default();

        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle).is_err() {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION::default();
        let mut return_length: u32 = 0;

        let result = GetTokenInformation(
            token_handle,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut std::ffi::c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        );

        let _ = CloseHandle(token_handle);

        if result.is_ok() {
            elevation.TokenIsElevated != 0
        } else {
            false
        }
    }
}

#[cfg(not(windows))]
pub fn is_administrator() -> bool {
    // On non-Windows, check if running as root
    unsafe { libc::geteuid() == 0 }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  ELEVATION UTILITIES
// ═══════════════════════════════════════════════════════════════════════════════

/// Pending connection state to pass between non-elevated and elevated process
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct PendingConnection {
    pub region: String,
    pub server: String,
    pub apps: Vec<String>,
    pub routing_mode: u8, // 0 = V1, 1 = V2
    pub timestamp: u64,
}

/// Get the path for the pending connection temp file
fn pending_connection_path() -> PathBuf {
    dirs::data_local_dir()
        .map(|d| d.join("SwiftTunnel").join("pending_connect.json"))
        .unwrap_or_else(|| PathBuf::from("pending_connect.json"))
}

/// Save pending connection state for elevated process to pick up
///
/// Saves region, server, and app list to a temp file that the elevated
/// process will read and auto-connect with.
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

/// Relaunch the current process with administrator privileges
///
/// Uses ShellExecuteW with "runas" verb to trigger UAC prompt.
/// Returns Ok(()) if the elevated process was successfully started.
/// The current process should exit after calling this.
#[cfg(windows)]
pub fn relaunch_elevated() -> std::io::Result<()> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    use windows::core::PCWSTR;

    // Get current executable path
    let exe_path = std::env::current_exe()?;
    let exe_path_str = exe_path.to_string_lossy();

    // Convert to wide string (UTF-16)
    let verb: Vec<u16> = OsStr::new("runas").encode_wide().chain(Some(0)).collect();
    let file: Vec<u16> = OsStr::new(&*exe_path_str).encode_wide().chain(Some(0)).collect();
    let params: Vec<u16> = OsStr::new("--resume-connect").encode_wide().chain(Some(0)).collect();

    log::info!("Relaunching elevated: {}", exe_path_str);

    unsafe {
        let result = ShellExecuteW(
            None,
            PCWSTR(verb.as_ptr()),
            PCWSTR(file.as_ptr()),
            PCWSTR(params.as_ptr()),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        );

        // ShellExecuteW returns > 32 on success
        let result_int = result.0 as isize;
        if result_int > 32 {
            log::info!("Elevated process launched successfully");
            Ok(())
        } else {
            let error = match result_int {
                0 => "Out of memory",
                2 => "File not found",
                3 => "Path not found",
                5 => "Access denied (UAC cancelled?)",
                _ => "Unknown error",
            };
            log::error!("ShellExecuteW failed: {} (code {})", error, result_int);
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("Failed to elevate: {} (code {})", error, result_int),
            ))
        }
    }
}

#[cfg(not(windows))]
pub fn relaunch_elevated() -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Elevation not supported on this platform",
    ))
}

// ═══════════════════════════════════════════════════════════════════════════════
//  RETRY UTILITIES
// ═══════════════════════════════════════════════════════════════════════════════

/// Default retry delays in milliseconds (exponential backoff)
const DEFAULT_RETRY_DELAYS: [u64; 3] = [1000, 2000, 4000];

/// Retry an async operation with exponential backoff
///
/// # Arguments
/// * `max_attempts` - Maximum number of attempts (1-10)
/// * `operation` - Async closure that returns Result<T, E>
///
/// # Returns
/// The result of the first successful attempt, or the last error
///
/// # Example
/// ```ignore
/// let result = with_retry(3, || async {
///     http_client.get(url).send().await
/// }).await;
/// ```
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
///
/// # Arguments
/// * `max_attempts` - Maximum number of attempts (1-10)
/// * `operation` - Closure that returns Result<T, E>
///
/// # Returns
/// The result of the first successful attempt, or the last error
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
        // Just verify it creates a command without panicking
        assert!(format!("{:?}", cmd).contains("echo"));
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
}
