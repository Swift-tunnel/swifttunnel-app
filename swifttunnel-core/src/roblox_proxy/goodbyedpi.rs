//! Scoped GoodbyeDPI launcher for Roblox country-ban traffic.
//!
//! SwiftTunnel no longer routes browser-owned Roblox HTTP(S) through the relay.
//! When Bypass country bans is enabled, this helper starts a bundled GoodbyeDPI
//! process with a narrow hostlist so both browser and Roblox app traffic get DPI
//! circumvention without becoming relay-owned traffic.

use log::{debug, info, warn};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Stdio};

const GOODBYEDPI_ENV_PATH: &str = "SWIFTTUNNEL_GOODBYEDPI_PATH";
const GOODBYEDPI_EXE_NAME: &str = "goodbyedpi.exe";
const HOSTLIST_NAME: &str = "roblox-hostlist.txt";

#[derive(Debug)]
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
    let args = build_goodbyedpi_args(&hostlist_path);
    let program = exe_path.to_string_lossy();
    let mut command = crate::hidden_command(&program);
    command
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(dir) = exe_path.parent() {
        command.current_dir(dir);
    }

    let child = match command.spawn() {
        Ok(child) => child,
        Err(e) => {
            if let Err(cleanup_err) = remove_hostlist_file(&hostlist_path) {
                warn!(
                    "Failed to remove GoodbyeDPI hostlist after spawn failure {}: {}",
                    hostlist_path.display(),
                    cleanup_err
                );
            }
            return Err(format!(
                "Failed to start GoodbyeDPI helper {} with hostlist {}: {e}",
                exe_path.display(),
                hostlist_path.display()
            ));
        }
    };

    info!(
        "Started GoodbyeDPI helper pid={} exe={} hostlist={}",
        child.id(),
        exe_path.display(),
        hostlist_path.display()
    );

    Ok(Some(GoodbyeDpiGuard {
        child,
        exe_path,
        hostlist_path,
        stopped: false,
    }))
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

fn remove_hostlist_file(path: &Path) -> Result<(), std::io::Error> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

pub(crate) fn build_goodbyedpi_args(hostlist_path: &Path) -> Vec<String> {
    vec![
        "-9".to_string(),
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
    fn goodbyedpi_args_use_modern_mode_and_blacklist() {
        let path = PathBuf::from(r"C:\ProgramData\SwiftTunnel\goodbyedpi\roblox-hostlist.txt");

        let args = build_goodbyedpi_args(&path);

        assert_eq!(args[0], "-9");
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
}
