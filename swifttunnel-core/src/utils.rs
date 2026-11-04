//! Utility functions for SwiftTunnel

use std::future::Future;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

/// Compare lexical path components without resolving links or parent traversal.
/// Windows uses ordinal UTF-16 case comparison; other platforms stay exact.
pub(crate) fn paths_match(left: &Path, right: &Path) -> bool {
    let mut right = right.components();
    left.components().all(|left| {
        right
            .next()
            .is_some_and(|right| same_path_part(left.as_os_str(), right.as_os_str()))
    }) && right.next().is_none()
}

pub(crate) fn same_path_part(left: &std::ffi::OsStr, right: &std::ffi::OsStr) -> bool {
    if left == right {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        use windows::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};
        let left = left.encode_wide().collect::<Vec<_>>();
        let right = right.encode_wide().collect::<Vec<_>>();
        unsafe { CompareStringOrdinal(&left, &right, true) == CSTR_EQUAL }
    }
    #[cfg(not(windows))]
    {
        left == right
    }
}

/// Keep synchronous OS/file work owned by its caller while allowing other
/// tasks on a multithreaded runtime to continue. This does not cancel or put
/// a time limit on the work. Non-threaded callers retain synchronous behavior.
pub(crate) fn blocking_step<T>(work: impl FnOnce() -> T) -> T {
    if tokio::runtime::Handle::try_current()
        .is_ok_and(|runtime| runtime.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread)
    {
        tokio::task::block_in_place(work)
    } else {
        work()
    }
}

/// Bound old local-text readers as well as HTTP responses. Metadata catches
/// already oversized files; Take also protects against growth during reading.
pub fn read_text_file_bounded(
    path: &std::path::Path,
    max_bytes: usize,
    context: &str,
) -> std::io::Result<String> {
    String::from_utf8(read_file_bounded(path, max_bytes, context)?)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

pub(crate) fn read_file_bounded(
    path: &std::path::Path,
    max_bytes: usize,
    context: &str,
) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let file = std::fs::File::open(path)?;
    let too_large = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{context} exceeds its {max_bytes}-byte limit"),
        )
    };
    if file.metadata()?.len() > max_bytes as u64 {
        return Err(too_large());
    }
    let mut bytes = Vec::new();
    file.take(max_bytes.saturating_add(1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes {
        return Err(too_large());
    }
    Ok(bytes)
}

#[cfg(windows)]
use std::os::windows::process::CommandExt;

/// Windows CREATE_NO_WINDOW flag to prevent console windows from appearing
/// (public so other modules can hide raw `std::process::Command` spawns too)
#[cfg(windows)]
pub const CREATE_NO_WINDOW: u32 = 0x08000000;

/// Create a Command that won't show a console window on Windows
///
/// This is essential for GUI apps to prevent scary command prompts
/// from flashing when running shell commands in the background.
///
/// For PowerShell commands, `-NoProfile -NonInteractive` is injected
/// automatically so that every callsite benefits from reduced AV
/// heuristic scoring (profile-loading and interactive-mode are traits
/// that malware scanners weight heavily).
pub fn hidden_command(program: &str) -> Command {
    #[cfg(windows)]
    let mut cmd = Command::new(resolve_windows_command_path(program));

    #[cfg(not(windows))]
    let mut cmd = Command::new(program);

    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);

    #[cfg(windows)]
    if is_powershell_program(program) {
        cmd.args(["-NoProfile", "-NonInteractive"]);
    }

    cmd
}

#[cfg(windows)]
fn is_powershell_program(program: &str) -> bool {
    program.eq_ignore_ascii_case("powershell") || program.eq_ignore_ascii_case("powershell.exe")
}

#[cfg(windows)]
fn resolve_windows_command_path(program: &str) -> PathBuf {
    // Do not trust SystemRoot/WINDIR from the process environment here. The
    // desktop app runs elevated, so environment-controlled system-tool
    // resolution would turn `hidden_command("powershell")` into an elevated
    // PATH/root hijack. Ask kernel32 for the real System32 directory instead
    // and derive the Windows root from that trusted path.
    let system_root = trusted_windows_root();
    resolve_windows_command_path_with_root(program, system_root.as_deref())
}

#[cfg(windows)]
pub(crate) fn trusted_windows_root() -> Option<PathBuf> {
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use windows::Win32::System::SystemInformation::GetSystemDirectoryW;

    let mut buffer = [0u16; 260];
    let len = unsafe { GetSystemDirectoryW(Some(&mut buffer)) } as usize;
    if len == 0 || len >= buffer.len() {
        return None;
    }

    PathBuf::from(OsString::from_wide(&buffer[..len]))
        .parent()
        .map(|path| path.to_path_buf())
}

#[cfg(windows)]
fn is_system32_program(program: &str) -> bool {
    matches!(
        program.to_ascii_lowercase().as_str(),
        "pnputil"
            | "pnputil.exe"
            | "ipconfig"
            | "ipconfig.exe"
            | "msiexec"
            | "msiexec.exe"
            | "netsh"
            | "netsh.exe"
            | "powercfg"
            | "powercfg.exe"
            | "sc"
            | "sc.exe"
            | "cmd"
            | "cmd.exe"
            | "ping"
            | "ping.exe"
            | "route"
            | "route.exe"
            | "w32tm"
            | "w32tm.exe"
            | "rstrui"
            | "rstrui.exe"
            | "reg"
            | "reg.exe"
            | "schtasks"
            | "schtasks.exe"
    )
}

#[cfg(windows)]
fn resolve_windows_command_path_with_root(
    program: &str,
    system_root: Option<&std::path::Path>,
) -> PathBuf {
    if program.eq_ignore_ascii_case("explorer") || program.eq_ignore_ascii_case("explorer.exe") {
        return system_root
            .map(|root| root.join("explorer.exe"))
            .unwrap_or_default();
    }

    if is_powershell_program(program) {
        let Some(root) = system_root else {
            return PathBuf::new();
        };
        let canonical = root.join("System32/WindowsPowerShell/v1.0/powershell.exe");
        let candidates = [
            canonical.clone(),
            root.join("Sysnative/WindowsPowerShell/v1.0/powershell.exe"),
            root.join("SysWOW64/WindowsPowerShell/v1.0/powershell.exe"),
        ];
        return candidates
            .into_iter()
            .find(|candidate| candidate.is_file())
            // A missing OS copy must fail there rather than run a same-named
            // executable from the working directory or an inherited PATH.
            .unwrap_or(canonical);
    }

    if is_system32_program(program) {
        let Some(root) = system_root else {
            return PathBuf::new();
        };
        let name = program.to_ascii_lowercase();
        let stem = name.strip_suffix(".exe").unwrap_or(&name);
        return root.join("System32").join(format!("{stem}.exe"));
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
    for (start, candidate) in bytes.windows(36).enumerate() {
        if is_guid_ascii(candidate) {
            return trimmed
                .get(start..start + 36)
                .map(|guid| guid.to_ascii_lowercase());
        }
    }

    None
}

/// `dwCurrentState` of a Windows service, read from the service control
/// manager.
///
/// Use this rather than parsing `sc query`: sc translates its field labels
/// (`STATE` is `STATUS` on German Windows, `ÉTAT` on French), so text
/// parsing silently failed outside English installs.
#[cfg(windows)]
pub fn query_service_state(name: &str) -> Result<u32, String> {
    use windows::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatus, SC_MANAGER_CONNECT,
        SERVICE_QUERY_STATUS, SERVICE_STATUS,
    };
    use windows::core::PCWSTR;

    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let scm = OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT)
            .map_err(|e| format!("could not open the service control manager: {e}"))?;
        let result = match OpenServiceW(scm, PCWSTR(wide.as_ptr()), SERVICE_QUERY_STATUS) {
            Ok(service) => {
                let mut status = SERVICE_STATUS::default();
                let queried = QueryServiceStatus(service, &mut status)
                    .map(|()| status.dwCurrentState.0)
                    .map_err(|e| format!("could not query service {name}: {e}"));
                let _ = CloseServiceHandle(service);
                queried
            }
            Err(e) => Err(format!("could not open service {name}: {e}")),
        };
        let _ = CloseServiceHandle(scm);
        result
    }
}

#[cfg(not(windows))]
pub fn query_service_state(_name: &str) -> Result<u32, String> {
    Err("Windows services are only available on Windows".to_string())
}

/// The `sc query` name for a `dwCurrentState` value.
pub fn service_state_name(state: u32) -> &'static str {
    match state {
        1 => "STOPPED",
        2 => "START_PENDING",
        3 => "STOP_PENDING",
        4 => "RUNNING",
        5 => "CONTINUE_PENDING",
        6 => "PAUSE_PENDING",
        7 => "PAUSED",
        _ => "unknown",
    }
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

#[cfg(windows)]
fn checked_shell_target(target: &str) -> Result<(&'static str, String), String> {
    let invalid = || "Only web links and existing folders can be opened.".to_string();
    if target.is_empty() || target.len() > 8192 || target.chars().any(char::is_control) {
        return Err(invalid());
    }
    if let Ok(url) = url::Url::parse(target)
        && matches!(url.scheme(), "http" | "https")
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
    {
        // Pass the parsed URL, which encodes shell-sensitive raw characters.
        return Ok(("open", url.into()));
    }
    let path = std::path::Path::new(target);
    if path.is_absolute() && path.is_dir() {
        // Do not use the executable-capable "open" verb for a folder, including
        // if the filesystem object changes after this inspection.
        return Ok(("explore", target.to_string()));
    }
    Err(invalid())
}

/// Open a web URL or existing absolute folder, without logging credential URLs.
#[cfg(windows)]
pub fn try_open_url(url: &str) -> Result<(), String> {
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::SW_SHOW;
    use windows::core::HSTRING;
    // ShellExecute's "open" verb also executes programs and registered custom
    // protocols. This helper serves browser links and exported-file folders.
    let (verb, target) = checked_shell_target(url)?;
    let result = unsafe {
        ShellExecuteW(
            None,
            &HSTRING::from(verb),
            &HSTRING::from(target),
            None,
            None,
            SW_SHOW,
        )
    };
    let code = result.0 as isize;
    if code > 32 {
        Ok(())
    } else {
        Err(format!(
            "Windows could not open this link (shell error {code}). Check your default browser."
        ))
    }
}

#[cfg(not(windows))]
pub fn try_open_url(_url: &str) -> Result<(), String> {
    Err("Opening links is only supported on Windows.".into())
}

// ═══════════════════════════════════════════════════════════════════════════════
//  ELEVATION UTILITIES
// ═══════════════════════════════════════════════════════════════════════════════

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

/// Run `exe` elevated (UAC prompt) via pure Win32 `ShellExecuteExW`, wait for
/// it to exit, and return its exit code.
///
/// This replaces the old PowerShell `Start-Process -Verb RunAs -Wait` wrapper —
/// no PowerShell process is spawned, so nothing can ever flash a console
/// window. `hide_window` controls the elevated child's own window (use `true`
/// for console tools like msiexec; `false` when relaunching the GUI app).
#[cfg(windows)]
pub fn run_elevated_and_wait(exe: &str, params: &str, hide_window: bool) -> std::io::Result<i32> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject};
    use windows::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
    use windows::Win32::UI::WindowsAndMessaging::{SW_HIDE, SW_SHOWNORMAL};
    use windows::core::PCWSTR;

    let verb: Vec<u16> = OsStr::new("runas").encode_wide().chain(Some(0)).collect();
    let file: Vec<u16> = OsStr::new(exe).encode_wide().chain(Some(0)).collect();
    let params_w: Vec<u16> = OsStr::new(params).encode_wide().chain(Some(0)).collect();

    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(params_w.as_ptr()),
        nShow: if hide_window {
            SW_HIDE.0
        } else {
            SW_SHOWNORMAL.0
        },
        ..Default::default()
    };

    unsafe { ShellExecuteExW(&mut info) }.map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("Elevation was declined or failed: {e}"),
        )
    })?;

    let process = info.hProcess;
    if process.is_invalid() {
        return Err(std::io::Error::other(
            "Elevated process started but no handle was returned",
        ));
    }

    let mut code: u32 = 1;
    unsafe {
        WaitForSingleObject(process, INFINITE);
        let _ = GetExitCodeProcess(process, &mut code);
        let _ = CloseHandle(process);
    }
    Ok(code as i32)
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

/// Outcome of a bounded external command run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedCommandOutput {
    pub success: bool,
    /// True when the child or its output streams did not finish by the deadline.
    pub timed_out: bool,
    /// Process exit code. Callers that branch on specific codes need this;
    /// 3010 from a driver install means "reboot required", not failure.
    /// None if execution or output capture failed or exceeded its deadline.
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

/// Preserve process-output callers while using the shared bounded collector.
pub fn run_hidden_command_output_with_timeout<S: AsRef<std::ffi::OsStr>>(
    program: &str,
    args: &[S],
    timeout: Duration,
) -> std::io::Result<std::process::Output> {
    let result = run_hidden_command_with_timeout(program, args, timeout);
    let Some(code) = result.exit_code else {
        let kind = if result.timed_out {
            std::io::ErrorKind::TimedOut
        } else {
            std::io::ErrorKind::Other
        };
        return Err(std::io::Error::new(
            kind,
            format!("{program}: {}", result.stderr.trim()),
        ));
    };
    #[cfg(windows)]
    let status = {
        use std::os::windows::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(code as u32)
    };
    #[cfg(unix)]
    let status = {
        use std::os::unix::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(code << 8)
    };
    Ok(std::process::Output {
        status,
        stdout: result.stdout.into_bytes(),
        stderr: result.stderr.into_bytes(),
    })
}

/// Run a hidden command and give up after `timeout`.
///
/// `Command::output()` blocks until the child exits, with no upper bound. That
/// is fine when the child always exits, but PowerShell on a damaged Windows
/// install does not always start, and support tickets showed the result: the
/// Repair tab spinning for twenty minutes and Copy log doing nothing at all,
/// with no error to report, because the call never returned to produce one.
/// Reinstalling the app cannot fix that, since the broken part is Windows.
///
/// Anything that shells out on a user's machine needs a deadline. A button that
/// reports a failure is recoverable; a button that hangs forever is not.
pub fn run_hidden_command_with_timeout<S: AsRef<std::ffi::OsStr>>(
    program: &str,
    args: &[S],
    timeout: Duration,
) -> BoundedCommandOutput {
    let child = match hidden_command(program)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(e) => {
            return BoundedCommandOutput {
                success: false,
                timed_out: false,
                exit_code: None,
                stdout: String::new(),
                stderr: format!("Failed to start {program}: {e}"),
            };
        }
    };

    collect_command_output(child, program, timeout)
}

// Windows pipes are drained by their sole reader using only the number of
// bytes already available. A descendant can keep a write handle open after
// its parent exits, so waiting for EOF on reader threads is not bounded.
#[cfg(windows)]
fn drain_available_pipe<P: std::io::Read + std::os::windows::io::AsRawHandle>(
    pipe: &mut Option<P>,
    output: &mut Vec<u8>,
) -> std::io::Result<bool> {
    use windows::Win32::Foundation::{ERROR_BROKEN_PIPE, HANDLE};
    use windows::Win32::System::Pipes::PeekNamedPipe;

    let Some(reader) = pipe.as_mut() else {
        return Ok(false);
    };
    // Bound each pass so a continuously chatty stdout cannot starve stderr or
    // the deadline check. Cap capture as well, without stopping pipe draining.
    const PASS_BYTES: usize = 64 * 1024;
    const CAPTURE_BYTES: usize = 4 * 1024 * 1024;
    let mut total = 0;
    let mut truncated = false;
    while total < PASS_BYTES {
        let mut available = 0;
        let peek = unsafe {
            PeekNamedPipe(
                HANDLE(reader.as_raw_handle()),
                None,
                0,
                None,
                Some(&mut available),
                None,
            )
        };
        if let Err(error) = peek {
            if error.code() == windows::core::HRESULT::from_win32(ERROR_BROKEN_PIPE.0) {
                *pipe = None;
                return Ok(truncated);
            }
            return Err(std::io::Error::other(error));
        }
        if available == 0 {
            break;
        }
        let mut buffer = [0u8; 8192];
        let requested = (available as usize)
            .min(buffer.len())
            .min(PASS_BYTES - total);
        let count = reader.read(&mut buffer[..requested])?;
        if count == 0 {
            *pipe = None;
            break;
        }
        let captured = count.min(CAPTURE_BYTES.saturating_sub(output.len()));
        output.extend_from_slice(&buffer[..captured]);
        truncated |= captured < count;
        total += count;
    }
    Ok(truncated)
}

#[cfg(windows)]
fn collect_command_output(
    mut child: std::process::Child,
    program: &str,
    timeout: Duration,
) -> BoundedCommandOutput {
    use std::time::Instant;

    let started = Instant::now();
    let mut stdout_pipe = child.stdout.take();
    let mut stderr_pipe = child.stderr.take();
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut status = None;
    let mut truncated = false;
    let mut timed_out = false;
    let mut failure = None;
    loop {
        match (
            drain_available_pipe(&mut stdout_pipe, &mut stdout),
            drain_available_pipe(&mut stderr_pipe, &mut stderr),
        ) {
            (Ok(out), Ok(err)) => truncated |= out || err,
            (Err(error), _) | (_, Err(error)) => {
                failure = Some(format!("Failed to read {program} output: {error}"));
                break;
            }
        }
        if status.is_none() {
            match child.try_wait() {
                Ok(value) => status = value,
                Err(error) => {
                    failure = Some(format!("Failed while waiting for {program}: {error}"));
                    break;
                }
            }
        }
        if status.is_some() && stdout_pipe.is_none() && stderr_pipe.is_none() {
            break;
        }
        if started.elapsed() >= timeout {
            timed_out = true;
            failure = Some(format!(
                "{program} did not finish within {:.3}s (process or output streams)",
                timeout.as_secs_f64()
            ));
            break;
        }
        std::thread::sleep(Duration::from_millis(5).min(timeout - started.elapsed().min(timeout)));
    }
    if status.is_none() {
        // Stop only the process we started. Do not wait on descendants or leave
        // blocked reader threads behind. Closing our pipes releases capture.
        if let Err(error) = child.kill() {
            failure = Some(format!(
                "{}; could not stop {program}: {error}",
                failure.unwrap_or_default()
            ));
        }
        let _ = child.try_wait();
    }
    if truncated {
        failure = Some(format!(
            "{}; command output exceeded the 4 MiB per-stream capture limit",
            failure.unwrap_or_default()
        ));
    }
    let mut stderr = String::from_utf8_lossy(&stderr).into_owned();
    if let Some(message) = &failure {
        stderr.push_str(&format!("\n{message}"));
    }
    BoundedCommandOutput {
        success: failure.is_none() && status.is_some_and(|value| value.success()),
        timed_out,
        exit_code: if failure.is_none() {
            status.and_then(|value| value.code())
        } else {
            None
        },
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr,
    }
}

#[cfg(not(windows))]
fn collect_command_output(
    mut child: std::process::Child,
    program: &str,
    timeout: Duration,
) -> BoundedCommandOutput {
    use std::io::Read;
    use std::time::Instant;

    // Read both pipes on their own threads, starting now.
    //
    // A pipe holds only a few kilobytes. Waiting for the child first and
    // reading afterwards works until the child writes more than that: it then
    // blocks on write, cannot reach its own exit, and the wait here can only
    // end at the timeout. `pnputil /enum-drivers` prints about 1800 lines and
    // deadlocked exactly this way, taking the full 180 seconds and returning
    // nothing, on a machine where the same command finishes in 0.2s by hand.
    // Every caller with more than a bufferful of output had the same flaw.
    let stdout_reader = child.stdout.take().map(|pipe| {
        std::thread::spawn(move || {
            let mut out = String::new();
            let mut pipe = pipe;
            let _ = pipe.read_to_string(&mut out);
            out
        })
    });
    let stderr_reader = child.stderr.take().map(|pipe| {
        std::thread::spawn(move || {
            let mut out = String::new();
            let mut pipe = pipe;
            let _ = pipe.read_to_string(&mut out);
            out
        })
    });

    // Legacy non-Windows collector. Unlike the Windows implementation above,
    // its EOF waits are not bounded if descendants retain the pipe handles.
    let collect = |handle: Option<std::thread::JoinHandle<String>>| -> String {
        handle.and_then(|h| h.join().ok()).unwrap_or_default()
    };

    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return BoundedCommandOutput {
                    success: status.success(),
                    timed_out: false,
                    exit_code: status.code(),
                    stdout: collect(stdout_reader),
                    stderr: collect(stderr_reader),
                };
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    // Whatever it managed to say before being stopped is worth
                    // keeping: on a timeout it is the only clue available.
                    let partial_stdout = collect(stdout_reader);
                    let partial_stderr = collect(stderr_reader);
                    return BoundedCommandOutput {
                        success: false,
                        timed_out: true,
                        exit_code: None,
                        stdout: partial_stdout,
                        stderr: format!(
                            "{program} did not finish within {}s and was stopped{}",
                            timeout.as_secs(),
                            if partial_stderr.is_empty() {
                                String::new()
                            } else {
                                format!(": {partial_stderr}")
                            }
                        ),
                    };
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                return BoundedCommandOutput {
                    success: false,
                    timed_out: false,
                    exit_code: None,
                    stdout: collect(stdout_reader),
                    stderr: format!("Failed while waiting for {program}: {e}"),
                };
            }
        }
    }
}

/// An error and everything underneath it, on one line.
///
/// `reqwest::Error` displays as `error sending request for url (...)` and stops
/// there. The reason lives in its source chain, and logging with `{}` threw it
/// away, so every network ticket arrived saying only that a request failed.
///
/// The difference is not academic. A player on T-Mobile spent five days and
/// four tickets on a failure that turned out to be
/// `SEC_E_INVALID_TOKEN (0x80090308)`, a middlebox answering his TLS handshake
/// with something that was not TLS. That string names the problem outright, and
/// we had it in hand every one of those five days and dropped it on the floor.
///
/// The chain separates the cases support has to tell apart and previously could
/// not: `dns error` means a resolver problem and a different DNS fixes it,
/// `tcp connect error` means refused or reset, and a schannel or certificate
/// code means something is sitting in the middle of the handshake.
pub fn describe_error_chain(error: &dyn std::error::Error) -> String {
    let mut parts = vec![error.to_string()];
    let mut source = error.source();
    // Bounded: a cycle in a source chain would otherwise hang the logger, and
    // nothing useful lives past a handful of levels anyway.
    while let Some(current) = source {
        let text = current.to_string();
        // Chains repeat themselves often, and a line that says the same thing
        // three times is harder to read than one that says it once.
        if !parts.iter().any(|seen| seen == &text) {
            parts.push(text);
        }
        if parts.len() >= 6 {
            break;
        }
        source = current.source();
    }
    parts.join(": ")
}

#[cfg(test)]
mod error_chain_tests {
    use super::describe_error_chain;
    use std::error::Error;
    use std::fmt;

    #[derive(Debug)]
    struct Layer {
        text: String,
        source: Option<Box<Layer>>,
    }

    impl fmt::Display for Layer {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(&self.text)
        }
    }

    impl Error for Layer {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            self.source
                .as_deref()
                .map(|inner| inner as &(dyn Error + 'static))
        }
    }

    fn chain(texts: &[&str]) -> Layer {
        let mut current: Option<Box<Layer>> = None;
        for text in texts.iter().rev() {
            current = Some(Box::new(Layer {
                text: (*text).to_string(),
                source: current,
            }));
        }
        *current.expect("at least one layer")
    }

    /// The cause is the point. Without it the line says only what the user
    /// already knew: a request failed.
    #[test]
    fn the_cause_survives_into_the_log_line() {
        let error = chain(&[
            "error sending request for url (https://www.swifttunnel.net/api/vpn/servers)",
            "schannel: next InitializeSecurityContext failed: SEC_E_INVALID_TOKEN (0x80090308)",
        ]);
        let described = describe_error_chain(&error);
        assert!(
            described.contains("SEC_E_INVALID_TOKEN"),
            "the reason must reach the log, got {described}"
        );
        assert!(
            described.contains("api/vpn/servers"),
            "and so must the request it belongs to, got {described}"
        );
    }

    /// A single error still reads as one sentence.
    #[test]
    fn one_layer_is_left_alone() {
        assert_eq!(describe_error_chain(&chain(&["dns error"])), "dns error");
    }

    /// Chains repeat themselves, and a line saying the same thing three times
    /// is harder to read than one saying it once.
    #[test]
    fn a_repeated_layer_is_only_said_once() {
        let described = describe_error_chain(&chain(&["connection reset", "connection reset"]));
        assert_eq!(described, "connection reset");
    }

    /// A cycle must not hang the logger.
    #[test]
    fn a_long_chain_is_bounded() {
        let deep: Vec<String> = (0..40).map(|i| format!("layer {i}")).collect();
        let refs: Vec<&str> = deep.iter().map(String::as_str).collect();
        let described = describe_error_chain(&chain(&refs));
        assert_eq!(described.matches(": ").count(), 5, "at most six layers");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_state_names_match_sc_query() {
        assert_eq!(service_state_name(1), "STOPPED");
        assert_eq!(service_state_name(2), "START_PENDING");
        assert_eq!(service_state_name(4), "RUNNING");
        assert_eq!(service_state_name(7), "PAUSED");
        assert_eq!(service_state_name(0), "unknown");
        assert_eq!(service_state_name(8), "unknown");
    }

    #[cfg(windows)]
    #[test]
    fn query_service_state_reads_a_core_service_and_rejects_a_missing_one() {
        // The RPC endpoint mapper runs on every supported Windows install.
        assert_eq!(query_service_state("RpcSs"), Ok(4));
        assert!(query_service_state("SwiftTunnelNoSuchService").is_err());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn cancelling_a_blocking_step_keeps_its_operation_owned_until_it_returns() {
        let gate = std::sync::Arc::new(tokio::sync::Mutex::new(()));
        let worker_gate = gate.clone();
        let started = std::sync::Arc::new(tokio::sync::Notify::new());
        let worker_started = started.clone();
        let (release, waiting) = std::sync::mpsc::channel();
        let task = tokio::spawn(async move {
            let _operation = worker_gate.lock().await;
            blocking_step(|| {
                // Native cleanup boundaries can nest, such as driver teardown
                // removing a WFP filter. Both retain the outer operation owner.
                blocking_step(|| {
                    worker_started.notify_one();
                    waiting.recv_timeout(Duration::from_secs(2)).unwrap();
                });
            });
        });
        started.notified().await;
        task.abort();
        assert!(
            gate.try_lock().is_err(),
            "the physical operation still owns admission"
        );
        release.send(()).unwrap();
        let _ = task.await;
        assert!(gate.try_lock().is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn shell_links_allow_web_pages_and_folders_without_accepting_programs_or_protocols() {
        for target in [
            "https://www.swifttunnel.net/login?state=fixture&redirect_port=17435",
            "http://127.0.0.1:17435/callback",
        ] {
            assert_eq!(
                checked_shell_target(target).unwrap(),
                ("open", target.to_string())
            );
        }
        for target in [
            "javascript:alert(1)",
            "file:///C:/Windows/notepad.exe",
            "ms-settings:network-proxy",
            "roblox://placeId=1",
            "cmd.exe",
            "https://user:password@example.invalid/",
            "https://example.invalid/\nforged",
            "https://example.invalid/\0ignored",
        ] {
            assert!(
                checked_shell_target(target).is_err(),
                "rejected shell target: {target:?}"
            );
        }
        let directory =
            std::env::temp_dir().join(format!("SwiftTunnel-shell-{:032x}", rand::random::<u128>()));
        std::fs::create_dir(&directory).unwrap();
        struct OwnedDirectory(PathBuf);
        impl Drop for OwnedDirectory {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _owned = OwnedDirectory(directory.clone());
        assert_eq!(
            checked_shell_target(&directory.to_string_lossy())
                .unwrap()
                .0,
            "explore"
        );
        for name in ["fixture.exe", "fixture.lnk", "fixture.url", "fixture.bat"] {
            let path = directory.join(name);
            std::fs::write(&path, b"test fixture, never executed").unwrap();
            assert!(checked_shell_target(&path.to_string_lossy()).is_err());
        }
    }
    #[cfg(windows)]
    use std::fs;

    #[cfg(windows)]
    #[test]
    fn bounded_process_output_preserves_exit_codes_and_captured_output() {
        let output = run_hidden_command_output_with_timeout(
            "cmd",
            &["/C", "echo bounded-output & exit /b 7"],
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(output.status.code(), Some(7));
        assert!(String::from_utf8_lossy(&output.stdout).contains("bounded-output"));
    }

    #[cfg(windows)]
    #[test]
    fn bounded_process_output_reports_timeout_as_an_error() {
        let error = run_hidden_command_output_with_timeout(
            "powershell",
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Start-Sleep -Seconds 2",
            ],
            Duration::from_millis(20),
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    }

    #[test]
    fn bounded_local_text_accepts_the_limit_and_refuses_an_oversized_file() {
        let path = std::env::temp_dir().join(format!(
            "swifttunnel_bounded_text_{}",
            rand::random::<u64>()
        ));
        std::fs::write(&path, "12345678").unwrap();
        assert_eq!(
            read_text_file_bounded(&path, 8, "Test").unwrap(),
            "12345678"
        );
        assert_eq!(
            read_text_file_bounded(&path, 7, "Test").unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn test_hidden_command() {
        let cmd = hidden_command("echo");
        // Just verify it creates a command without panicking
        assert!(format!("{:?}", cmd).contains("echo"));
    }

    /// A command that says more than a pipe holds must still finish.
    ///
    /// This is the exact shape that hung: the runner waited for the child and
    /// only read the pipes afterwards, so a child writing past the buffer
    /// blocked on write, could never reach its own exit, and the wait ended
    /// only at the timeout. `pnputil /enum-drivers` prints ~1800 lines and
    /// took the whole 180 second budget during uninstall while finishing in
    /// 0.2s by hand.
    ///
    /// The timeout here is generous on purpose. The assertion is not about
    /// speed, it is that a large output does not by itself cause a timeout.
    #[cfg(windows)]
    #[test]
    fn a_chatty_command_does_not_deadlock_on_its_own_output() {
        let script = std::env::temp_dir().join("swifttunnel-chatty-test.bat");
        // ~4000 lines of 64 characters is roughly 256KB, many times any pipe
        // buffer, and small enough to stay quick.
        fs::write(
            &script,
            "@echo off\r\nfor /L %%i in (1,1,4000) do @echo \
             0123456789012345678901234567890123456789012345678901234567890123\r\n",
        )
        .expect("write the test script");

        let started = std::time::Instant::now();
        let output = run_hidden_command_with_timeout(
            "cmd",
            &["/c", script.to_str().expect("utf-8 temp path")],
            Duration::from_secs(60),
        );
        let elapsed = started.elapsed();
        let _ = fs::remove_file(&script);

        assert!(
            !output.timed_out,
            "a chatty command timed out after {elapsed:?}, so its output deadlocked it"
        );
        assert!(
            output.stdout.len() > 200_000,
            "expected the full output, got {} bytes",
            output.stdout.len()
        );
        assert!(output.success, "stderr was: {}", output.stderr);
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
        let resolved = resolve_windows_command_path_with_root("custom-helper", None);
        assert_eq!(resolved, PathBuf::from("custom-helper"));
    }

    #[cfg(windows)]
    #[test]
    fn explorer_uses_the_windows_root_and_never_searches_path() {
        let root = std::path::Path::new("E:/Windows");
        for name in ["explorer", "Explorer.EXE"] {
            assert_eq!(
                resolve_windows_command_path_with_root(name, Some(root)),
                root.join("explorer.exe")
            );
            assert!(
                resolve_windows_command_path_with_root(name, None)
                    .as_os_str()
                    .is_empty()
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn known_windows_tools_never_fall_back_to_executable_search() {
        let root = PathBuf::from(r"E:\Windows");
        for (name, executable) in [
            ("ipconfig", "ipconfig.exe"),
            ("NETSH.EXE", "netsh.exe"),
            ("PNPUTIL.EXE", "pnputil.exe"),
            ("route", "route.exe"),
            ("w32tm", "w32tm.exe"),
            ("cmd", "cmd.exe"),
            ("ping", "ping.exe"),
            ("rstrui.exe", "rstrui.exe"),
            ("reg", "reg.exe"),
            ("REG.EXE", "reg.exe"),
            ("schtasks", "schtasks.exe"),
            ("SCHTASKS.EXE", "schtasks.exe"),
        ] {
            // No actual E: directory or executable needs to exist. Missing
            // OS files must fail at that path, not select an adjacent helper.
            assert_eq!(
                resolve_windows_command_path_with_root(name, Some(&root)),
                root.join("System32").join(executable),
                "{name}"
            );
        }
        assert_eq!(
            resolve_windows_command_path_with_root("powershell", Some(&root)),
            root.join("System32/WindowsPowerShell/v1.0/powershell.exe")
        );
    }

    #[cfg(windows)]
    #[test]
    fn unavailable_windows_directory_refuses_system_tools_instead_of_searching_path() {
        for name in [
            "powershell",
            "netsh",
            "ipconfig",
            "pnputil",
            "route",
            "w32tm",
            "cmd",
            "ping",
            "rstrui.exe",
            "reg",
            "REG.EXE",
            "schtasks",
            "SCHTASKS.EXE",
        ] {
            assert!(
                resolve_windows_command_path_with_root(name, None)
                    .as_os_str()
                    .is_empty(),
                "{name}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn test_resolve_windows_command_path_resolves_system32_programs() {
        let root =
            std::env::temp_dir().join(format!("swifttunnel_test_sys32_{}", std::process::id()));
        let pnputil = root.join("System32").join("pnputil.exe");
        let msiexec = root.join("System32").join("msiexec.exe");
        let powercfg = root.join("System32").join("powercfg.exe");
        let sc = root.join("System32").join("sc.exe");

        fs::create_dir_all(pnputil.parent().unwrap()).expect("create System32 dir");
        fs::write(&pnputil, b"").expect("create fake pnputil");
        fs::write(&msiexec, b"").expect("create fake msiexec");
        fs::write(&powercfg, b"").expect("create fake powercfg");
        fs::write(&sc, b"").expect("create fake sc");

        assert_eq!(
            resolve_windows_command_path_with_root("pnputil", Some(root.as_path())),
            pnputil
        );
        assert_eq!(
            resolve_windows_command_path_with_root("msiexec", Some(root.as_path())),
            msiexec
        );
        assert_eq!(
            resolve_windows_command_path_with_root("powercfg", Some(root.as_path())),
            powercfg
        );
        assert_eq!(
            resolve_windows_command_path_with_root("sc", Some(root.as_path())),
            sc
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
    fn test_normalize_guid_rejects_short_or_malformed_adapter_preferences() {
        for input in ["", " ", "auto", "Wi-Fi", "{}", "{bad}", "é", "无线网络"] {
            assert_eq!(normalize_guid_ascii_lowercase(input), None, "{input:?}");
        }
        let valid = "12345678-1234-1234-1234-1234567890AB";
        for end in 1..valid.len() {
            assert_eq!(normalize_guid_ascii_lowercase(&valid[..end]), None);
        }
        assert_eq!(
            normalize_guid_ascii_lowercase(&format!("无线 {valid} end")),
            Some(valid.to_ascii_lowercase())
        );
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

    #[cfg(windows)]
    #[test]
    fn test_run_elevated_and_wait_is_linked() {
        // Verify the pure-Win32 elevation path exists without invoking it
        // (invoking would show a real UAC prompt).
        let _f: fn(&str, &str, bool) -> std::io::Result<i32> = run_elevated_and_wait;
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
        assert_eq!(quote_windows_arg("--cleanup"), "--cleanup");
    }

    /// Reproduces the support tickets: a helper that never exits.
    ///
    /// Before the timeout existed this call could not return at all, which is
    /// what made Repair spin for twenty minutes and Copy log look dead. The
    /// point of the test is the deadline, so it asserts we come back promptly
    /// and say why, rather than asserting anything about the child.
    #[cfg(windows)]
    #[test]
    fn hanging_helper_is_killed_at_the_deadline() {
        use std::time::Instant;

        let started = Instant::now();
        // `ping -t` runs until killed, standing in for a PowerShell that never
        // starts properly on a damaged install.
        let out =
            run_hidden_command_with_timeout("ping", &["-t", "127.0.0.1"], Duration::from_secs(2));
        let elapsed = started.elapsed();

        assert!(out.timed_out, "expected the deadline to fire");
        assert!(!out.success);
        assert!(
            out.stderr.contains("did not finish"),
            "caller needs something to show the user, got: {}",
            out.stderr
        );
        assert!(
            elapsed < Duration::from_secs(15),
            "returned after {elapsed:?}; the deadline is what stops the UI hanging"
        );
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "subprocess fixture, invoked by the inherited-pipe regression"]
    fn inherited_pipe_holder_fixture() {
        println!("descendant has stdout");
        eprintln!("descendant has stderr");
        std::thread::sleep(Duration::from_secs(5));
    }

    #[cfg(windows)]
    fn spawn_inherited_pipe_holder() {
        let exe = std::env::current_exe().unwrap();
        let _child = hidden_command(exe.to_str().unwrap())
            .args([
                "--ignored",
                "--exact",
                "utils::tests::inherited_pipe_holder_fixture",
                "--nocapture",
            ])
            .stdout(std::process::Stdio::inherit())
            .stderr(std::process::Stdio::inherit())
            .spawn()
            .unwrap();
        // Dropping Child does not terminate it. This models a helper that
        // starts a descendant retaining both inherited output handles.
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "subprocess fixture, invoked by the inherited-pipe regression"]
    fn exited_parent_fixture() {
        spawn_inherited_pipe_holder();
        println!("parent ready");
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "subprocess fixture, invoked by the inherited-pipe regression"]
    fn hanging_parent_fixture() {
        spawn_inherited_pipe_holder();
        println!("parent ready");
        std::thread::sleep(Duration::from_secs(5));
    }

    #[cfg(windows)]
    fn assert_inherited_pipes_respect_deadline(fixture: &str) {
        let started = std::time::Instant::now();
        let exe = std::env::current_exe().unwrap();
        let result = run_hidden_command_with_timeout(
            exe.to_str().unwrap(),
            &["--ignored", "--exact", fixture, "--nocapture"],
            Duration::from_millis(500),
        );
        assert!(result.stdout.contains("parent ready"), "{result:?}");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "inherited pipe defeated the deadline: {:?}",
            started.elapsed()
        );
        assert!(result.timed_out, "{result:?}");
        assert!(!result.success);
    }

    #[cfg(windows)]
    #[test]
    fn inherited_pipes_after_parent_exit_respect_deadline() {
        assert_inherited_pipes_respect_deadline("utils::tests::exited_parent_fixture");
    }

    #[cfg(windows)]
    #[test]
    fn inherited_pipes_after_parent_timeout_respect_deadline() {
        assert_inherited_pipes_respect_deadline("utils::tests::hanging_parent_fixture");
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "subprocess fixture, invoked by the output-limit regression"]
    fn excessive_output_fixture() {
        use std::io::Write;
        let block = [b'x'; 8192];
        for _ in 0..640 {
            std::io::stdout().write_all(&block).unwrap();
            std::io::stderr().write_all(&block).unwrap();
        }
    }

    #[cfg(windows)]
    #[test]
    fn excessive_output_is_drained_but_reported_as_incomplete() {
        let exe = std::env::current_exe().unwrap();
        let result = run_hidden_command_with_timeout(
            exe.to_str().unwrap(),
            &[
                "--ignored",
                "--exact",
                "utils::tests::excessive_output_fixture",
                "--nocapture",
            ],
            Duration::from_secs(30),
        );
        assert!(!result.timed_out, "must keep draining: {result:?}");
        assert_eq!(result.exit_code, None);
        assert!(
            !result.success,
            "truncated output cannot be treated as complete"
        );
        assert_eq!(result.stdout.len(), 4 * 1024 * 1024);
        assert!(result.stderr.len() < 4 * 1024 * 1024 + 256);
        assert!(result.stderr.contains("capture limit"));
    }

    #[cfg(windows)]
    #[test]
    fn completed_helper_preserves_reboot_required_exit_code() {
        let result =
            run_hidden_command_with_timeout("cmd", &["/C", "exit /b 3010"], Duration::from_secs(5));
        assert_eq!(result.exit_code, Some(3010));
        assert!(!result.success);
        assert!(!result.timed_out);
    }

    #[cfg(windows)]
    #[test]
    fn quick_helper_still_succeeds_and_captures_output() {
        let out = run_hidden_command_with_timeout(
            "cmd",
            &["/C", "echo swifttunnel-ok"],
            Duration::from_secs(30),
        );
        assert!(out.success, "stderr: {}", out.stderr);
        assert!(!out.timed_out);
        assert!(
            out.stdout.contains("swifttunnel-ok"),
            "stdout: {}",
            out.stdout
        );
    }

    #[test]
    fn missing_program_reports_instead_of_hanging() {
        let out = run_hidden_command_with_timeout(
            "swifttunnel-no-such-program",
            &[] as &[&str],
            Duration::from_secs(5),
        );
        assert!(!out.success);
        assert!(!out.timed_out, "a missing program is not a timeout");
        assert!(!out.stderr.is_empty(), "the caller needs a reason to show");
    }
}
