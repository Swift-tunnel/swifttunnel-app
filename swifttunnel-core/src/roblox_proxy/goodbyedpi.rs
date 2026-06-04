//! Scoped GoodbyeDPI launcher for Roblox country-ban traffic.
//!
//! SwiftTunnel no longer routes browser-owned Roblox HTTP(S) through the relay.
//! When Bypass country bans is enabled, this helper starts a bundled GoodbyeDPI
//! process with a narrow hostlist so both browser and Roblox app traffic get DPI
//! circumvention without becoming relay-owned traffic.

use log::{debug, info, warn};
use std::collections::HashSet;
use std::fs;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};
use std::time::Duration;

const GOODBYEDPI_ENV_PATH: &str = "SWIFTTUNNEL_GOODBYEDPI_PATH";
const GOODBYEDPI_EXE_NAME: &str = "goodbyedpi.exe";
const HOSTLIST_NAME: &str = "roblox-hostlist.txt";
const ROBLOX_REACHABILITY_TARGET: (&str, u16) = ("www.roblox.com", 443);
const GOODBYEDPI_MODE_STARTUP_WAIT: Duration = Duration::from_secs(3);
const ROBLOX_REACHABILITY_TIMEOUT: Duration = Duration::from_millis(1500);

#[derive(Debug)]
#[must_use = "dropping GoodbyeDpiGuard stops the GoodbyeDPI subprocess immediately"]
pub struct GoodbyeDpiGuard {
    child: Child,
    exe_path: PathBuf,
    hostlist_path: PathBuf,
    stopped: bool,
}

impl GoodbyeDpiGuard {
    pub fn stop(&mut self) {
        if self.stopped {
            return;
        }
        self.stopped = true;

        match self.child.try_wait() {
            Ok(Some(status)) => {
                info!(
                    "GoodbyeDPI already exited before cleanup (status: {}, exe: {})",
                    status,
                    self.exe_path.display()
                );
            }
            Ok(None) => match self.child.kill() {
                Ok(()) => {
                    if let Err(e) = self.child.wait() {
                        warn!(
                            "Failed to wait for GoodbyeDPI process {} cleanup: {}",
                            self.child.id(),
                            e
                        );
                    } else {
                        info!("Stopped GoodbyeDPI helper ({})", self.exe_path.display());
                    }
                }
                Err(e) => {
                    warn!(
                        "Failed to stop GoodbyeDPI process {} ({}): {}",
                        self.child.id(),
                        self.exe_path.display(),
                        e
                    );
                    match self.child.try_wait() {
                        Ok(Some(status)) => {
                            info!(
                                "GoodbyeDPI exited during cleanup race (status: {}, exe: {})",
                                status,
                                self.exe_path.display()
                            );
                        }
                        Ok(None) => {
                            warn!(
                                "Skipping blocking wait for GoodbyeDPI process {} after kill failure",
                                self.child.id()
                            );
                        }
                        Err(wait_err) => {
                            warn!(
                                "Failed to re-check GoodbyeDPI process {} after kill failure: {}",
                                self.child.id(),
                                wait_err
                            );
                        }
                    }
                }
            },
            Err(e) => {
                warn!(
                    "Failed to inspect GoodbyeDPI process {} during cleanup: {}",
                    self.child.id(),
                    e
                );
            }
        }

        if let Err(e) = remove_hostlist_file(&self.hostlist_path) {
            warn!(
                "Failed to remove GoodbyeDPI Roblox hostlist {}: {}",
                self.hostlist_path.display(),
                e
            );
        }
    }
}

impl Drop for GoodbyeDpiGuard {
    fn drop(&mut self) {
        self.stop();
    }
}

pub fn start_for_roblox() -> Result<Option<GoodbyeDpiGuard>, String> {
    if !cfg!(windows) {
        debug!("GoodbyeDPI helper skipped: supported only on Windows");
        return Ok(None);
    }

    let Some(exe_path) = locate_goodbyedpi_executable() else {
        warn!("GoodbyeDPI helper not found; Bypass country bans will not apply to Roblox traffic");
        return Ok(None);
    };

    let hostlist_path = write_roblox_hostlist()?;
    let mut failures = Vec::new();

    for mode in 1..=9 {
        let args = build_goodbyedpi_args(mode, &hostlist_path);
        let mut child = match spawn_goodbyedpi(&exe_path, &args) {
            Ok(child) => child,
            Err(e) => {
                failures.push(format!("-{mode}: {e}"));
                continue;
            }
        };

        info!(
            "Started GoodbyeDPI helper pid={} mode=-{} exe={} hostlist={}",
            child.id(),
            mode,
            exe_path.display(),
            hostlist_path.display()
        );

        std::thread::sleep(GOODBYEDPI_MODE_STARTUP_WAIT);

        match child.try_wait() {
            Ok(Some(status)) => {
                failures.push(format!("-{mode}: exited early with {status}"));
                continue;
            }
            Ok(None) => {}
            Err(e) => {
                failures.push(format!("-{mode}: failed to inspect process: {e}"));
                stop_child_process(&mut child, &exe_path);
                continue;
            }
        }

        if roblox_https_reachable() {
            info!("GoodbyeDPI mode -{} made Roblox HTTPS reachable", mode);
            return Ok(Some(GoodbyeDpiGuard {
                child,
                exe_path,
                hostlist_path,
                stopped: false,
            }));
        }

        failures.push(format!(
            "-{mode}: {}:{} was not reachable",
            ROBLOX_REACHABILITY_TARGET.0, ROBLOX_REACHABILITY_TARGET.1
        ));
        stop_child_process(&mut child, &exe_path);
    }

    if let Err(cleanup_err) = remove_hostlist_file(&hostlist_path) {
        warn!(
            "Failed to remove GoodbyeDPI hostlist after mode escalation failure {}: {}",
            hostlist_path.display(),
            cleanup_err
        );
    }

    Err(format!(
        "GoodbyeDPI could not make Roblox reachable after trying modes -1 through -9 ({})",
        failures.join("; ")
    ))
}

pub fn cleanup_for_uninstall() -> Result<(), String> {
    let mut errors = Vec::new();

    if cfg!(windows) {
        if let Err(e) = stop_managed_goodbyedpi_processes() {
            errors.push(e);
        }
    }

    if let Err(e) = remove_goodbyedpi_data_dir() {
        errors.push(e);
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

fn locate_goodbyedpi_executable() -> Option<PathBuf> {
    let current_exe = std::env::current_exe().ok();
    let env_path = std::env::var_os(GOODBYEDPI_ENV_PATH)
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty());

    candidate_executable_paths(current_exe.as_deref(), env_path)
        .into_iter()
        .find(|path| path.is_file())
}

fn write_roblox_hostlist() -> Result<PathBuf, String> {
    let dir = goodbyedpi_data_dir();
    fs::create_dir_all(&dir).map_err(|e| {
        format!(
            "Failed to create GoodbyeDPI data directory {}: {e}",
            dir.display()
        )
    })?;

    let path = dir.join(HOSTLIST_NAME);
    fs::write(&path, roblox_hostlist_contents()).map_err(|e| {
        format!(
            "Failed to write GoodbyeDPI Roblox hostlist {}: {e}",
            path.display()
        )
    })?;
    Ok(path)
}

fn goodbyedpi_data_dir() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("SwiftTunnel")
        .join("goodbyedpi")
}

fn remove_goodbyedpi_data_dir() -> Result<(), String> {
    remove_goodbyedpi_data_dir_at(&goodbyedpi_data_dir())
}

fn remove_goodbyedpi_data_dir_at(path: &Path) -> Result<(), String> {
    match fs::remove_dir_all(path) {
        Ok(()) => {
            info!("Removed GoodbyeDPI runtime directory {}", path.display());
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!(
            "Failed to remove GoodbyeDPI runtime directory {}: {e}",
            path.display()
        )),
    }
}

fn remove_hostlist_file(path: &Path) -> Result<(), std::io::Error> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

fn spawn_goodbyedpi(exe_path: &Path, args: &[String]) -> Result<Child, String> {
    let program = exe_path.to_string_lossy();
    let mut command = crate::hidden_command(&program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(dir) = exe_path.parent() {
        command.current_dir(dir);
    }

    command.spawn().map_err(|e| {
        format!(
            "failed to start {} with args {:?}: {e}",
            exe_path.display(),
            args
        )
    })
}

fn stop_child_process(child: &mut Child, exe_path: &Path) {
    match child.try_wait() {
        Ok(Some(status)) => {
            debug!(
                "GoodbyeDPI helper already stopped during escalation (status: {}, exe: {})",
                status,
                exe_path.display()
            );
        }
        Ok(None) => {
            if let Err(e) = child.kill() {
                warn!(
                    "Failed to stop GoodbyeDPI helper during escalation pid={} exe={}: {}",
                    child.id(),
                    exe_path.display(),
                    e
                );
            }
            if let Err(e) = child.wait() {
                warn!(
                    "Failed to wait for GoodbyeDPI helper during escalation pid={} exe={}: {}",
                    child.id(),
                    exe_path.display(),
                    e
                );
            }
        }
        Err(e) => {
            warn!(
                "Failed to inspect GoodbyeDPI helper during escalation pid={} exe={}: {}",
                child.id(),
                exe_path.display(),
                e
            );
        }
    }
}

fn roblox_https_reachable() -> bool {
    let Ok(addrs) = ROBLOX_REACHABILITY_TARGET.to_socket_addrs() else {
        return false;
    };

    addrs
        .take(8)
        .any(|addr| TcpStream::connect_timeout(&addr, ROBLOX_REACHABILITY_TIMEOUT).is_ok())
}

pub(crate) fn build_goodbyedpi_args(mode: u8, hostlist_path: &Path) -> Vec<String> {
    vec![
        format!("-{mode}"),
        "--blacklist".to_string(),
        hostlist_path.to_string_lossy().to_string(),
    ]
}

pub(crate) fn roblox_hostlist_contents() -> String {
    let mut out = String::new();
    for domain in super::hosts::ROBLOX_BOOTSTRAP_DOMAINS {
        out.push_str(domain);
        out.push('\n');
    }
    out
}

fn stop_managed_goodbyedpi_processes() -> Result<(), String> {
    let current_exe = std::env::current_exe().ok();
    let program_files = std::env::var_os("ProgramFiles").map(PathBuf::from);
    let roots = managed_goodbyedpi_roots(current_exe.as_deref(), program_files.as_deref());
    if roots.is_empty() {
        return Ok(());
    }

    let script = build_stop_managed_processes_script(&roots);
    let status = crate::hidden_command("powershell")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &script,
        ])
        .status()
        .map_err(|e| format!("Failed to run GoodbyeDPI process cleanup: {e}"))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "GoodbyeDPI process cleanup exited with {}",
            status
                .code()
                .map_or_else(|| "unknown status".to_string(), |code| code.to_string())
        ))
    }
}

fn managed_goodbyedpi_roots(
    current_exe: Option<&Path>,
    program_files: Option<&Path>,
) -> Vec<PathBuf> {
    let mut roots = Vec::new();

    if let Some(base) = current_exe.and_then(Path::parent) {
        roots.push(base.join("tools").join("goodbyedpi"));
        roots.push(base.join("resources").join("tools").join("goodbyedpi"));
        roots.push(base.join("goodbyedpi"));
    }

    if let Some(program_files) = program_files {
        let install_root = program_files.join("SwiftTunnel");
        roots.push(install_root.join("tools").join("goodbyedpi"));
        roots.push(
            install_root
                .join("resources")
                .join("tools")
                .join("goodbyedpi"),
        );
        roots.push(install_root.join("goodbyedpi"));
    }

    dedupe_paths(roots)
}

fn build_stop_managed_processes_script(roots: &[PathBuf]) -> String {
    let roots = roots
        .iter()
        .map(|path| format!("'{}'", powershell_single_quote(&path.to_string_lossy())))
        .collect::<Vec<_>>()
        .join(", ");

    format!(
        r#"$ErrorActionPreference = 'Stop'
$roots = @({roots}) | ForEach-Object {{
  [System.IO.Path]::GetFullPath($_).TrimEnd('\') + '\'
}}
Get-CimInstance Win32_Process -Filter "Name = 'goodbyedpi.exe'" | ForEach-Object {{
  $path = $_.ExecutablePath
  if (-not [string]::IsNullOrWhiteSpace($path)) {{
    $fullPath = [System.IO.Path]::GetFullPath($path)
    foreach ($root in $roots) {{
      if ($fullPath.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase)) {{
        Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop
        break
      }}
    }}
  }}
}}"#
    )
}

fn powershell_single_quote(value: &str) -> String {
    value.replace('\'', "''")
}

pub(crate) fn candidate_executable_paths(
    current_exe: Option<&Path>,
    env_path: Option<PathBuf>,
) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Some(path) = env_path {
        paths.push(path);
    }

    if let Some(base) = current_exe.and_then(Path::parent) {
        add_goodbyedpi_candidates(&mut paths, &base.join("tools").join("goodbyedpi"));
        add_goodbyedpi_candidates(
            &mut paths,
            &base.join("resources").join("tools").join("goodbyedpi"),
        );
        add_goodbyedpi_candidates(&mut paths, &base.join("goodbyedpi"));
    }

    if let Some(program_files) = std::env::var_os("ProgramFiles").map(PathBuf::from) {
        add_goodbyedpi_candidates(
            &mut paths,
            &program_files
                .join("SwiftTunnel")
                .join("tools")
                .join("goodbyedpi"),
        );
        add_goodbyedpi_candidates(
            &mut paths,
            &program_files
                .join("SwiftTunnel")
                .join("resources")
                .join("tools")
                .join("goodbyedpi"),
        );
    }

    dedupe_paths(paths)
}

fn add_goodbyedpi_candidates(paths: &mut Vec<PathBuf>, root: &Path) {
    paths.push(root.join(GOODBYEDPI_EXE_NAME));
    paths.push(root.join("x86_64").join(GOODBYEDPI_EXE_NAME));
    paths.push(root.join("x86").join(GOODBYEDPI_EXE_NAME));
}

fn dedupe_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for path in paths {
        if seen.insert(path.clone()) {
            out.push(path);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn goodbyedpi_args_use_requested_mode_and_blacklist() {
        let path = PathBuf::from(r"C:\ProgramData\SwiftTunnel\goodbyedpi\roblox-hostlist.txt");

        let args = build_goodbyedpi_args(1, &path);

        assert_eq!(args[0], "-1");
        assert_eq!(args[1], "--blacklist");
        assert_eq!(args[2], path.to_string_lossy());
    }

    #[test]
    fn roblox_hostlist_is_exact_bootstrap_allowlist() {
        let contents = roblox_hostlist_contents();
        let domains: Vec<&str> = contents.lines().collect();

        assert_eq!(
            domains.as_slice(),
            super::super::hosts::ROBLOX_BOOTSTRAP_DOMAINS
        );
        assert!(domains.contains(&"www.roblox.com"));
        assert!(domains.contains(&"auth.roblox.com"));
        assert!(!domains.contains(&"roblox.com"));
        assert!(contents.ends_with('\n'));
    }

    #[test]
    fn candidate_paths_prioritize_env_then_staged_tools() {
        let exe = PathBuf::from("C:/Program Files/SwiftTunnel/SwiftTunnel.exe");
        let env = PathBuf::from("D:/tools/goodbyedpi.exe");

        let paths = candidate_executable_paths(Some(&exe), Some(env.clone()));

        assert_eq!(paths.first(), Some(&env));
        assert!(paths.contains(&PathBuf::from(
            "C:/Program Files/SwiftTunnel/tools/goodbyedpi/goodbyedpi.exe"
        )));
        assert!(paths.contains(&PathBuf::from(
            "C:/Program Files/SwiftTunnel/tools/goodbyedpi/x86_64/goodbyedpi.exe"
        )));
    }

    #[test]
    fn remove_hostlist_file_ignores_missing_file() {
        let path = std::env::temp_dir().join("swifttunnel-missing-goodbyedpi-hostlist.txt");
        let _ = fs::remove_file(&path);

        assert!(remove_hostlist_file(&path).is_ok());
    }

    #[test]
    fn managed_goodbyedpi_roots_scope_to_install_dirs() {
        let roots = managed_goodbyedpi_roots(
            Some(Path::new(r"C:\Program Files\SwiftTunnel\SwiftTunnel.exe")),
            Some(Path::new(r"C:\Program Files")),
        );

        assert!(roots.contains(&PathBuf::from(
            r"C:\Program Files\SwiftTunnel\tools\goodbyedpi"
        )));
        assert!(roots.contains(&PathBuf::from(
            r"C:\Program Files\SwiftTunnel\resources\tools\goodbyedpi"
        )));
        assert!(!roots.contains(&PathBuf::from(r"D:\tools\goodbyedpi")));
    }

    #[test]
    fn stop_script_uses_path_scoped_process_cleanup() {
        let script = build_stop_managed_processes_script(&[PathBuf::from(
            r"C:\Program Files\Swift'Tunnel\tools\goodbyedpi",
        )]);

        assert!(script.contains("Get-CimInstance Win32_Process"));
        assert!(script.contains("Name = 'goodbyedpi.exe'"));
        assert!(script.contains("ExecutablePath"));
        assert!(script.contains("StartsWith"));
        assert!(script.contains("Stop-Process"));
        assert!(script.contains("Swift''Tunnel"));
        assert!(!script.contains("taskkill"));
    }

    #[test]
    fn remove_goodbyedpi_data_dir_ignores_missing_dir() {
        let path = std::env::temp_dir().join("swifttunnel-missing-goodbyedpi-dir");
        let _ = fs::remove_dir_all(&path);

        assert!(remove_goodbyedpi_data_dir_at(&path).is_ok());
    }
}
