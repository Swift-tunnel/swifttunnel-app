use crate::structs::Result;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct SystemMemorySnapshot {
    pub total_mb: u64,
    pub available_mb: u64,
    pub used_mb: u64,
    pub load_pct: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StandbyPurgeResult {
    pub attempted: bool,
    pub success: bool,
    pub skipped_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RamCleanResult {
    pub before: SystemMemorySnapshot,
    pub after: SystemMemorySnapshot,
    pub trimmed_count: u32,
    pub standby_purge: StandbyPurgeResult,
    pub duration_ms: u64,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
struct ProcessSample {
    pid: u32,
    name: String,
    memory_bytes: u64,
    cpu_usage: f32,
}

const MIN_PROCESS_BYTES: u64 = 200 * 1024 * 1024;
const MAX_TRIM_PROCESSES: usize = 20;
const MAX_CPU_PERCENT: f32 = 2.0;

const DENYLIST_NAMES_LOWER: &[&str] = &[
    "system",
    "registry",
    "idle",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "dwm.exe",
    "audiodg.exe",
    "fontdrvhost.exe",
    "sihost.exe",
    "taskhostw.exe",
    "conhost.exe",
    "msmpeng.exe",
];

fn select_trim_candidates(
    processes: Vec<ProcessSample>,
    exclude_pids: &HashSet<u32>,
) -> Vec<ProcessSample> {
    let mut candidates: Vec<ProcessSample> = processes
        .into_iter()
        .filter(|p| !exclude_pids.contains(&p.pid))
        .filter(|p| {
            let name = p.name.to_ascii_lowercase();
            !DENYLIST_NAMES_LOWER.contains(&name.as_str())
        })
        .filter(|p| p.memory_bytes >= MIN_PROCESS_BYTES)
        .filter(|p| {
            let cpu = if p.cpu_usage.is_finite() {
                p.cpu_usage
            } else {
                0.0
            };
            cpu <= MAX_CPU_PERCENT
        })
        .collect();

    candidates.sort_by(|a, b| b.memory_bytes.cmp(&a.memory_bytes));
    candidates.truncate(MAX_TRIM_PROCESSES);
    candidates
}

pub fn get_system_memory_snapshot() -> Result<SystemMemorySnapshot> {
    #[cfg(windows)]
    {
        windows_impl::get_system_memory_snapshot()
    }

    #[cfg(not(windows))]
    {
        Err(anyhow::anyhow!("RAM cleaner is only supported on Windows"))
    }
}

pub fn clean_ram<F>(exclude_pids: &[u32], mut on_progress: F) -> Result<RamCleanResult>
where
    F: FnMut(&str, SystemMemorySnapshot, u32, Option<String>, Option<String>),
{
    #[cfg(windows)]
    {
        windows_impl::clean_ram(exclude_pids, &mut on_progress)
    }

    #[cfg(not(windows))]
    {
        let _ = exclude_pids;
        let _ = on_progress;
        Err(anyhow::anyhow!("RAM cleaner is only supported on Windows"))
    }
}

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use std::ffi::c_void;

    use sysinfo::{ProcessesToUpdate, System};
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Security::{
        AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    };
    use windows::Win32::System::ProcessStatus::EmptyWorkingSet;
    use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    use windows::Win32::System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_SET_QUOTA,
    };
    use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, GetWindowThreadProcessId};
    use windows::core::PCWSTR;

    unsafe extern "system" {
        fn NtSetSystemInformation(
            SystemInformationClass: u32,
            SystemInformation: *const c_void,
            SystemInformationLength: u32,
        ) -> i32;
    }

    const SYSTEM_MEMORY_LIST_INFORMATION: u32 = 80;
    const MEMORY_PURGE_STANDBY_LIST: u32 = 4;

    pub(super) fn get_system_memory_snapshot() -> Result<SystemMemorySnapshot> {
        unsafe {
            let mut status = MEMORYSTATUSEX::default();
            status.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;

            GlobalMemoryStatusEx(&mut status)?;

            let total_mb = status.ullTotalPhys / 1024 / 1024;
            let available_mb = status.ullAvailPhys / 1024 / 1024;
            let used_mb = total_mb.saturating_sub(available_mb);

            Ok(SystemMemorySnapshot {
                total_mb,
                available_mb,
                used_mb,
                load_pct: status.dwMemoryLoad as u8,
            })
        }
    }

    fn foreground_pid() -> Option<u32> {
        unsafe {
            let hwnd = GetForegroundWindow();
            if hwnd.0.is_null() {
                return None;
            }
            let mut pid: u32 = 0;
            GetWindowThreadProcessId(hwnd, Some(&mut pid));
            if pid == 0 { None } else { Some(pid) }
        }
    }

    fn snapshot_or_warn(warnings: &mut Vec<String>) -> SystemMemorySnapshot {
        match get_system_memory_snapshot() {
            Ok(snap) => snap,
            Err(e) => {
                warnings.push(format!("Failed to read system memory stats: {}", e));
                SystemMemorySnapshot {
                    total_mb: 0,
                    available_mb: 0,
                    used_mb: 0,
                    load_pct: 0,
                }
            }
        }
    }

    fn sample_processes() -> Vec<ProcessSample> {
        let mut system = System::new();
        system.refresh_processes(ProcessesToUpdate::All, true);
        std::thread::sleep(Duration::from_millis(200));
        system.refresh_processes(ProcessesToUpdate::All, true);

        system
            .processes()
            .iter()
            .map(|(pid, p)| ProcessSample {
                pid: pid.as_u32(),
                name: p.name().to_string_lossy().to_string(),
                memory_bytes: p.memory(),
                cpu_usage: p.cpu_usage(),
            })
            .collect()
    }

    fn trim_working_set(pid: u32) -> Result<()> {
        unsafe {
            let handle = OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_QUOTA,
                false,
                pid,
            )?;

            if handle.is_invalid() {
                return Err(anyhow::anyhow!("Failed to open process"));
            }

            let result = EmptyWorkingSet(handle);
            let _ = CloseHandle(handle);

            result.map_err(|e| anyhow::anyhow!("EmptyWorkingSet failed: {}", e))
        }
    }

    fn enable_privilege(privilege_name: &str) -> Result<()> {
        unsafe {
            let mut token = windows::Win32::Foundation::HANDLE::default();
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                &mut token,
            )?;

            let wide_name: Vec<u16> = privilege_name
                .encode_utf16()
                .chain(std::iter::once(0))
                .collect();

            let mut luid = windows::Win32::Foundation::LUID::default();
            LookupPrivilegeValueW(PCWSTR::null(), PCWSTR(wide_name.as_ptr()), &mut luid)?;

            let tp = TOKEN_PRIVILEGES {
                PrivilegeCount: 1,
                Privileges: [LUID_AND_ATTRIBUTES {
                    Luid: luid,
                    Attributes: SE_PRIVILEGE_ENABLED,
                }],
            };

            AdjustTokenPrivileges(token, false, Some(&tp), 0, None, None)?;
            let _ = CloseHandle(token);
            Ok(())
        }
    }

    fn purge_standby_list() -> StandbyPurgeResult {
        if !crate::is_administrator() {
            return StandbyPurgeResult {
                attempted: false,
                success: false,
                skipped_reason: Some("Requires Administrator".to_string()),
            };
        }

        unsafe {
            if let Err(e) = enable_privilege("SeProfileSingleProcessPrivilege") {
                return StandbyPurgeResult {
                    attempted: false,
                    success: false,
                    skipped_reason: Some(format!(
                        "Could not enable SeProfileSingleProcessPrivilege: {}",
                        e
                    )),
                };
            }

            let command: u32 = MEMORY_PURGE_STANDBY_LIST;
            let status = NtSetSystemInformation(
                SYSTEM_MEMORY_LIST_INFORMATION,
                &command as *const u32 as *const c_void,
                std::mem::size_of::<u32>() as u32,
            );

            if status == 0 {
                StandbyPurgeResult {
                    attempted: true,
                    success: true,
                    skipped_reason: None,
                }
            } else {
                StandbyPurgeResult {
                    attempted: true,
                    success: false,
                    skipped_reason: Some(format!("NtSetSystemInformation failed (0x{status:08X})")),
                }
            }
        }
    }

    pub(super) fn clean_ram<F>(exclude_pids: &[u32], on_progress: &mut F) -> Result<RamCleanResult>
    where
        F: FnMut(&str, SystemMemorySnapshot, u32, Option<String>, Option<String>),
    {
        let started = Instant::now();
        let mut warnings: Vec<String> = Vec::new();

        let mut exclude_set: HashSet<u32> = exclude_pids.iter().copied().collect();
        exclude_set.insert(std::process::id());
        if let Some(pid) = foreground_pid() {
            exclude_set.insert(pid);
        }

        let before = snapshot_or_warn(&mut warnings);
        on_progress("start", before, 0, None, None);

        info!("Sampling processes for RAM clean...");
        let processes = sample_processes();
        let candidates = select_trim_candidates(processes, &exclude_set);
        info!("RAM clean: {} trim candidates selected", candidates.len());

        let mut trimmed_count: u32 = 0;
        for candidate in candidates {
            let current_name = candidate.name.clone();
            match trim_working_set(candidate.pid) {
                Ok(()) => {
                    trimmed_count = trimmed_count.saturating_add(1);
                    let snap = snapshot_or_warn(&mut warnings);
                    on_progress("trimming", snap, trimmed_count, Some(current_name), None);
                }
                Err(e) => {
                    let msg = format!("{} (pid {}): {}", candidate.name, candidate.pid, e);
                    warn!("RAM clean warning: {}", msg);
                    warnings.push(msg.clone());
                    let snap = snapshot_or_warn(&mut warnings);
                    on_progress(
                        "trimming",
                        snap,
                        trimmed_count,
                        Some(current_name),
                        Some(msg),
                    );
                }
            }
        }

        let snap = snapshot_or_warn(&mut warnings);
        on_progress("standby_purge", snap, trimmed_count, None, None);

        let standby_purge = purge_standby_list();
        if !standby_purge.success {
            if let Some(reason) = standby_purge.skipped_reason.clone() {
                warnings.push(format!("Standby purge: {}", reason));
            }
        }

        let after = snapshot_or_warn(&mut warnings);
        on_progress("done", after, trimmed_count, None, None);

        Ok(RamCleanResult {
            before,
            after,
            trimmed_count,
            standby_purge,
            duration_ms: started.elapsed().as_millis() as u64,
            warnings,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc(pid: u32, name: &str, memory_mb: u64, cpu: f32) -> ProcessSample {
        ProcessSample {
            pid,
            name: name.to_string(),
            memory_bytes: memory_mb * 1024 * 1024,
            cpu_usage: cpu,
        }
    }

    #[test]
    fn select_candidates_excludes_denylist_names_case_insensitive() {
        let processes = vec![
            proc(10, "svchost.exe", 800, 0.0),
            proc(11, "Chrome.exe", 900, 0.0),
        ];
        let exclude = HashSet::new();
        let selected = select_trim_candidates(processes, &exclude);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].pid, 11);
    }

    #[test]
    fn select_candidates_excludes_explicit_pids() {
        let processes = vec![
            proc(10, "chrome.exe", 900, 0.0),
            proc(11, "discord.exe", 700, 0.0),
        ];
        let exclude: HashSet<u32> = [11].into_iter().collect();
        let selected = select_trim_candidates(processes, &exclude);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].pid, 10);
    }

    #[test]
    fn select_candidates_skips_busy_processes() {
        let processes = vec![
            proc(10, "chrome.exe", 900, 10.0),
            proc(11, "discord.exe", 700, 1.0),
        ];
        let exclude = HashSet::new();
        let selected = select_trim_candidates(processes, &exclude);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].pid, 11);
    }

    #[test]
    fn select_candidates_applies_memory_threshold_and_caps_max() {
        let mut processes = Vec::new();
        processes.push(proc(1, "small.exe", 199, 0.0));
        for i in 0..25 {
            processes.push(proc(100 + i, &format!("p{i}.exe"), 200 + i as u64, 0.0));
        }
        let exclude = HashSet::new();
        let selected = select_trim_candidates(processes, &exclude);
        assert_eq!(selected.len(), MAX_TRIM_PROCESSES);
        assert!(selected.iter().all(|p| p.memory_bytes >= MIN_PROCESS_BYTES));
        // Highest memory first (200+24)
        assert_eq!(selected[0].pid, 124);
    }
}
