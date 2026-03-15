//! Utility functions for SwiftTunnel

use std::future::Future;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

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
    #[cfg(windows)]
    let mut cmd = Command::new(resolve_windows_command_path(program));

    #[cfg(not(windows))]
    let mut cmd = Command::new(program);

    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);

    cmd
}

#[cfg(windows)]
fn is_powershell_program(program: &str) -> bool {
    program.eq_ignore_ascii_case("powershell") || program.eq_ignore_ascii_case("powershell.exe")
}

#[cfg(windows)]
fn resolve_windows_command_path(program: &str) -> PathBuf {
    let system_root = std::env::var_os("SystemRoot")
        .or_else(|| std::env::var_os("WINDIR"))
        .map(PathBuf::from);

    resolve_windows_command_path_with_root(program, system_root.as_deref())
}

#[cfg(windows)]
fn is_system32_program(program: &str) -> bool {
    matches!(
        program.to_ascii_lowercase().as_str(),
        "pnputil" | "pnputil.exe" | "msiexec" | "msiexec.exe"
    )
}

#[cfg(windows)]
fn resolve_windows_command_path_with_root(
    program: &str,
    system_root: Option<&std::path::Path>,
) -> PathBuf {
    if is_powershell_program(program) {
        let mut candidates = Vec::new();
        if let Some(root) = system_root {
            candidates.push(
                root.join("System32")
                    .join("WindowsPowerShell")
                    .join("v1.0")
                    .join("powershell.exe"),
            );
            candidates.push(
                root.join("Sysnative")
                    .join("WindowsPowerShell")
                    .join("v1.0")
                    .join("powershell.exe"),
            );
            candidates.push(
                root.join("SysWOW64")
                    .join("WindowsPowerShell")
                    .join("v1.0")
                    .join("powershell.exe"),
            );
        }

        return candidates
            .into_iter()
            .find(|candidate| candidate.is_file())
            .unwrap_or_else(|| PathBuf::from(program));
    }

    if is_system32_program(program) {
        if let Some(root) = system_root {
            let exe_name = if program.ends_with(".exe") {
                program.to_string()
            } else {
                format!("{program}.exe")
            };
            let candidate = root.join("System32").join(&exe_name);
            if candidate.is_file() {
                return candidate;
            }
        }
    }

    PathBuf::from(program)
}

/// Normalize a GUID string to lowercase canonical form.
///
/// Accepts either raw GUID (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`) or
/// wrapped GUID (`{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`), and can extract
/// either form when embedded within larger strings.
pub fn normalize_guid_ascii_lowercase(value: &str) -> Option<String> {
    fn is_guid_ascii(bytes: &[u8]) -> bool {
        if bytes.len() != 36 {
            return false;
        }
        const DASH_POS: [usize; 4] = [8, 13, 18, 23];
        for (i, &b) in bytes.iter().enumerate() {
            if DASH_POS.contains(&i) {
                if b != b'-' {
                    return false;
                }
                continue;
            }
            if !b.is_ascii_hexdigit() {
                return false;
            }
        }
        true
    }

    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }

    let bytes = trimmed.as_bytes();

    // Fast path: `{GUID}` anywhere inside the string.
    for (open_idx, &b) in bytes.iter().enumerate() {
        if b != b'{' {
            continue;
        }
        let Some(close_rel) = bytes[open_idx + 1..].iter().position(|&b| b == b'}') else {
            continue;
        };
        let close_idx = open_idx + 1 + close_rel;
        let inner = &bytes[open_idx + 1..close_idx];
        if is_guid_ascii(inner) {
            return trimmed
                .get(open_idx + 1..close_idx)
                .map(|guid| guid.to_ascii_lowercase());
        }
    }

    // Fallback: raw GUID without braces somewhere in the string.
    for start in 0..=bytes.len().saturating_sub(36) {
        let candidate = &bytes[start..start + 36];
        if is_guid_ascii(candidate) {
            return trimmed
                .get(start..start + 36)
                .map(|guid| guid.to_ascii_lowercase());
        }
    }

    None
}

/// Check if the current process has administrator privileges
///
/// Returns true if running with elevated privileges, false otherwise.
#[cfg(windows)]
pub fn is_administrator() -> bool {
    unsafe {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::Security::{
            GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
        };
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

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
//  URL OPENING
// ═══════════════════════════════════════════════════════════════════════════════

/// Open a URL in the user's default browser using Windows ShellExecuteW
#[cfg(windows)]
pub fn open_url(url: &str) {
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOW;
    use windows::core::HSTRING;
    unsafe {
        ShellExecuteW(
            None,
            &HSTRING::from("open"),
            &HSTRING::from(url),
            None,
            None,
            SW_SHOW,
        );
    }
}

#[cfg(not(windows))]
pub fn open_url(_url: &str) {
    // No-op on non-Windows platforms
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
    pub routing_mode: u8, // Legacy field, kept for IPC compatibility
    pub timestamp: u64,
}

/// Get the path for the pending connection temp file
pub fn pending_connection_path() -> PathBuf {
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
        log::warn!(
            "Pending connection expired ({}s old)",
            now - pending.timestamp
        );
        return None;
    }

    log::info!(
        "Loaded pending connection: region={}, server={}",
        pending.region,
        pending.server
    );
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
    let file: Vec<u16> = OsStr::new(&*exe_path_str)
        .encode_wide()
        .chain(Some(0))
        .collect();
    let params: Vec<u16> = OsStr::new("--resume-connect")
        .encode_wide()
        .chain(Some(0))
        .collect();

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

/// Quote a single argument for Windows command-line parsing.
///
/// Produces a string that round-trips through `CommandLineToArgvW`:
/// - Args without special characters are returned as-is.
/// - Args with spaces, tabs, or quotes are wrapped in `"..."` with
///   backslashes and quotes escaped per the 2n/2n+1 rule.
pub fn quote_windows_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
        return arg.to_owned();
    }

    let mut out = String::from('"');
    let mut backslashes: usize = 0;

    for ch in arg.chars() {
        match ch {
            '\\' => backslashes += 1,
            '"' => {
                // 2n+1 backslashes before a quote → n literal backslashes + literal quote
                out.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                // Backslashes not before a quote are literal
                out.extend(std::iter::repeat_n('\\', backslashes));
                backslashes = 0;
                out.push(ch);
            }
        }
    }

    // Trailing backslashes must be doubled before the closing quote
    out.extend(std::iter::repeat_n('\\', backslashes * 2));
    out.push('"');
    out
}

/// Relaunch the current process elevated, preserving command-line arguments
///
/// Unlike `relaunch_elevated()` which hardcodes `--resume-connect`, this
/// passes through whatever arguments the current process was started with
/// (e.g. `--startup`). Used by the admin gate in `main()`.
#[cfg(windows)]
pub fn relaunch_elevated_with_args() -> std::io::Result<()> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
    use windows::core::PCWSTR;

    let exe_path = std::env::current_exe()?;
    let exe_path_str = exe_path.to_string_lossy();

    // Collect and properly quote each argument for CommandLineToArgvW
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args_joined = args
        .iter()
        .map(|a| quote_windows_arg(a))
        .collect::<Vec<_>>()
        .join(" ");

    let verb: Vec<u16> = OsStr::new("runas").encode_wide().chain(Some(0)).collect();
    let file: Vec<u16> = OsStr::new(&*exe_path_str)
        .encode_wide()
        .chain(Some(0))
        .collect();
    let params: Vec<u16> = OsStr::new(&args_joined)
        .encode_wide()
        .chain(Some(0))
        .collect();

    log::info!(
        "Relaunching elevated with args: {} {}",
        exe_path_str,
        args_joined
    );

    unsafe {
        let result = ShellExecuteW(
            None,
            PCWSTR(verb.as_ptr()),
            PCWSTR(file.as_ptr()),
            PCWSTR(params.as_ptr()),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        );

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
pub fn relaunch_elevated_with_args() -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Elevation not supported on this platform",
    ))
}

#[cfg(windows)]
fn escape_powershell_single_quoted(value: &str) -> String {
    value.replace('\'', "''")
}

#[cfg(windows)]
fn build_elevated_wait_script(exe_path: &str, args: &[String]) -> String {
    let escaped_exe = escape_powershell_single_quoted(exe_path);
    let arg_list = if args.is_empty() {
        "$argList=@(); ".to_string()
    } else {
        let rendered_args = args
            .iter()
            .map(|arg| format!("'{}'", escape_powershell_single_quoted(arg)))
            .collect::<Vec<_>>()
            .join(",");
        format!("$argList=@({rendered_args}); ")
    };

    format!(
        "$ErrorActionPreference='Stop'; \
         {arg_list}\
         $p=Start-Process -FilePath '{escaped_exe}' -Verb RunAs -ArgumentList $argList -Wait -PassThru; \
         exit $p.ExitCode"
    )
}

/// Relaunch the current process elevated and wait for the elevated child to exit.
///
/// Returns the elevated process exit code. This is used for flows such as
/// uninstall cleanup where the caller must not continue until the privileged
/// work has definitely completed.
#[cfg(windows)]
pub fn relaunch_elevated_with_args_and_wait() -> std::io::Result<i32> {
    let exe_path = std::env::current_exe()?;
    let exe_path_str = exe_path.to_string_lossy().to_string();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let script = build_elevated_wait_script(&exe_path_str, &args);

    let output = hidden_command("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()?;

    let exit_code = output.status.code().unwrap_or(1);
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if !stderr.is_empty() { stderr } else { stdout };

    if !output.status.success() && !detail.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("Failed to elevate and wait: {detail}"),
        ));
    }

    Ok(exit_code)
}

#[cfg(not(windows))]
pub fn relaunch_elevated_with_args_and_wait() -> std::io::Result<i32> {
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
pub async fn with_retry<T, E, F, Fut>(max_attempts: u32, operation: F) -> Result<T, E>
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
                        attempt,
                        max_attempts,
                        e,
                        delay_ms
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
pub fn with_retry_sync<T, E, F>(max_attempts: u32, operation: F) -> Result<T, E>
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
                        attempt,
                        max_attempts,
                        e,
                        delay_ms
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

    log::info!(
        "Rotated log file: {} -> {}",
        log_path.display(),
        old_path.display()
    );
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    use std::fs;

    #[test]
    fn test_hidden_command() {
        let cmd = hidden_command("echo");
        // Just verify it creates a command without panicking
        assert!(format!("{:?}", cmd).contains("echo"));
    }

    #[cfg(windows)]
    #[test]
    fn test_resolve_windows_command_path_prefers_absolute_powershell() {
        let root = std::env::temp_dir().join(format!(
            "swifttunnel_test_windows_root_{}",
            std::process::id()
        ));
        let powershell = root
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");

        if let Some(parent) = powershell.parent() {
            fs::create_dir_all(parent).expect("create fake powershell parent");
        }
        fs::write(&powershell, b"").expect("create fake powershell");

        let resolved = resolve_windows_command_path_with_root("powershell", Some(root.as_path()));
        assert_eq!(resolved, powershell);

        fs::remove_file(&powershell).ok();
        fs::remove_dir_all(&root).ok();
    }

    #[cfg(windows)]
    #[test]
    fn test_resolve_windows_command_path_leaves_other_programs_unchanged() {
        let resolved = resolve_windows_command_path_with_root("cmd", None);
        assert_eq!(resolved, PathBuf::from("cmd"));
    }

    #[cfg(windows)]
    #[test]
    fn test_resolve_windows_command_path_resolves_system32_programs() {
        let root = std::env::temp_dir().join(format!(
            "swifttunnel_test_sys32_{}",
            std::process::id()
        ));
        let pnputil = root.join("System32").join("pnputil.exe");
        let msiexec = root.join("System32").join("msiexec.exe");

        fs::create_dir_all(pnputil.parent().unwrap()).expect("create System32 dir");
        fs::write(&pnputil, b"").expect("create fake pnputil");
        fs::write(&msiexec, b"").expect("create fake msiexec");

        assert_eq!(
            resolve_windows_command_path_with_root("pnputil", Some(root.as_path())),
            pnputil
        );
        assert_eq!(
            resolve_windows_command_path_with_root("msiexec", Some(root.as_path())),
            msiexec
        );
        // Without .exe suffix should also work
        assert_eq!(
            resolve_windows_command_path_with_root("pnputil", Some(root.as_path())),
            pnputil
        );

        fs::remove_dir_all(&root).ok();
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
    fn test_normalize_guid_ascii_lowercase_accepts_wrapped_guid() {
        let guid = normalize_guid_ascii_lowercase("  {AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}  ");
        assert_eq!(
            guid.as_deref(),
            Some("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        );
    }

    #[test]
    fn test_normalize_guid_ascii_lowercase_extracts_embedded_guid() {
        let guid =
            normalize_guid_ascii_lowercase("\\\\DEVICE\\\\{12345678-1234-1234-1234-1234567890AB}");
        assert_eq!(
            guid.as_deref(),
            Some("12345678-1234-1234-1234-1234567890ab")
        );
    }

    #[test]
    fn test_is_administrator_returns_bool() {
        // Just verify it returns without panicking on any platform
        let _result: bool = is_administrator();
    }

    // Avoid calling relaunch_elevated_with_args() directly in tests —
    // on Windows it invokes ShellExecuteW("runas") which can trigger UAC.
    // Instead we verify the function is linked and test the quoting helper.

    #[cfg(not(windows))]
    #[test]
    fn test_relaunch_elevated_with_args_returns_unsupported() {
        let result = relaunch_elevated_with_args();
        assert!(result.is_err());
    }

    #[cfg(windows)]
    #[test]
    fn test_relaunch_elevated_with_args_is_linked() {
        // Verify the symbol exists without invoking it
        let _f: fn() -> std::io::Result<()> = relaunch_elevated_with_args;
    }

    #[cfg(windows)]
    #[test]
    fn test_relaunch_elevated_with_args_and_wait_is_linked() {
        let _f: fn() -> std::io::Result<i32> = relaunch_elevated_with_args_and_wait;
    }

    #[cfg(windows)]
    #[test]
    fn test_build_elevated_wait_script_escapes_single_quotes() {
        let script = build_elevated_wait_script(
            "C:\\Program Files\\Swift'Tunnel\\swifttunnel-desktop.exe",
            &["--cleanup".to_string(), "O'Hara".to_string()],
        );
        assert!(script.contains("Swift''Tunnel"));
        assert!(script.contains("'--cleanup'"));
        assert!(script.contains("'O''Hara'"));
        assert!(script.contains("Start-Process -FilePath"));
        assert!(script.contains("-Wait -PassThru"));
    }

    #[test]
    fn test_quote_windows_arg_simple_flag() {
        assert_eq!(quote_windows_arg("--startup"), "--startup");
    }

    #[test]
    fn test_quote_windows_arg_with_spaces() {
        assert_eq!(
            quote_windows_arg("C:\\Users\\A B\\config.json"),
            "\"C:\\Users\\A B\\config.json\""
        );
    }

    #[test]
    fn test_quote_windows_arg_with_quotes() {
        // Inner quote must be escaped as \"
        assert_eq!(quote_windows_arg("say \"hi\""), "\"say \\\"hi\\\"\"");
    }

    #[test]
    fn test_quote_windows_arg_trailing_backslashes() {
        // Trailing backslashes before closing quote must be doubled
        assert_eq!(
            quote_windows_arg("path with trailing\\\\"),
            "\"path with trailing\\\\\\\\\""
        );
    }

    #[test]
    fn test_quote_windows_arg_empty() {
        assert_eq!(quote_windows_arg(""), "\"\"");
    }

    #[test]
    fn test_quote_windows_arg_no_special_chars() {
        assert_eq!(quote_windows_arg("--resume-connect"), "--resume-connect");
    }
}
