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
    pub standby_mb: Option<u64>,
    pub modified_mb: Option<u64>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MemoryListStats {
    pub standby_mb: u64,
    pub modified_mb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModifiedFlushResult {
    pub attempted: bool,
    pub success: bool,
    pub skipped_reason: Option<String>,
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
    pub modified_flush: ModifiedFlushResult,
    pub freed_mb: i64,
    pub standby_freed_mb: Option<i64>,
    pub modified_freed_mb: Option<i64>,
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

const MIN_PROCESS_BYTES: u64 = 50 * 1024 * 1024;
const MAX_TRIM_PROCESSES: usize = 40;
const MAX_CPU_PERCENT: f32 = 5.0;

const DENYLIST_NAMES_LOWER: &[&str] = &[
    // System critical
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
    // SwiftTunnel itself
    "swifttunnel.exe",
    "swifttunnel-desktop.exe",
    // Roblox
    "robloxplayerbeta.exe",
    "robloxplayer.exe",
    "windows10universal.exe",
    "robloxplayerlauncher.exe",
    "robloxstudiobeta.exe",
    "robloxstudio.exe",
    "robloxstudiolauncherbeta.exe",
    "robloxstudiolauncher.exe",
    // Valorant
    "valorant-win64-shipping.exe",
    "valorant.exe",
    "riotclientservices.exe",
    "riotclientux.exe",
    "riotclientuxrender.exe",
    // Fortnite
    "fortniteclient-win64-shipping.exe",
    "fortnitelauncher.exe",
    "epicgameslauncher.exe",
    "epicwebhelper.exe",
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

pub fn get_memory_list_stats() -> Option<MemoryListStats> {
    #[cfg(windows)]
    {
        windows_impl::query_memory_lists()
    }

    #[cfg(not(windows))]
    {
        None
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

        fn NtQuerySystemInformation(
            SystemInformationClass: u32,
            SystemInformation: *mut c_void,
            SystemInformationLength: u32,
            ReturnLength: *mut u32,
        ) -> i32;
    }

    const SYSTEM_MEMORY_LIST_INFORMATION: u32 = 80;
    const MEMORY_PURGE_STANDBY_LIST: u32 = 4;
    const MEMORY_FLUSH_MODIFIED_LIST: u32 = 3;

    /// Matches Windows `SYSTEM_MEMORY_LIST_INFORMATION` (class 80).
    /// 27 usize fields on x64.
    #[repr(C)]
    struct SystemMemoryListInfo {
        _zeroed_page_count: usize,
        _free_page_count: usize,
        modified_page_count: usize,
        _modified_no_write_page_count: usize,
        _bad_page_count: usize,
        page_count_by_priority: [usize; 8],
        _repurposed_page_by_priority: [usize; 8],
        _modified_page_count_page_file: usize,
    }

    pub(super) fn query_memory_lists() -> Option<MemoryListStats> {
        unsafe {
            let mut info: SystemMemoryListInfo = std::mem::zeroed();
            let mut return_length: u32 = 0;
            let status = NtQuerySystemInformation(
                SYSTEM_MEMORY_LIST_INFORMATION,
                &mut info as *mut _ as *mut c_void,
                std::mem::size_of::<SystemMemoryListInfo>() as u32,
                &mut return_length,
            );
            if status != 0 {
                return None;
            }

            let page_size: u64 = 4096;
            let standby_pages: u64 = info.page_count_by_priority.iter().sum::<usize>() as u64;
            let modified_pages: u64 = info.modified_page_count as u64;

            Some(MemoryListStats {
                standby_mb: standby_pages * page_size / 1_048_576,
                modified_mb: modified_pages * page_size / 1_048_576,
            })
        }
    }

    pub(super) fn get_system_memory_snapshot() -> Result<SystemMemorySnapshot> {
        unsafe {
            let mut status = MEMORYSTATUSEX::default();
            status.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;

            GlobalMemoryStatusEx(&mut status)?;

            let total_mb = status.ullTotalPhys / 1024 / 1024;
            let available_mb = status.ullAvailPhys / 1024 / 1024;
            let used_mb = total_mb.saturating_sub(available_mb);

            let mem_lists = query_memory_lists();

            Ok(SystemMemorySnapshot {
                total_mb,
                available_mb,
                used_mb,
                load_pct: status.dwMemoryLoad as u8,
                standby_mb: mem_lists.map(|s| s.standby_mb),
                modified_mb: mem_lists.map(|s| s.modified_mb),
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
                    standby_mb: None,
                    modified_mb: None,
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

    fn flush_modified_list() -> ModifiedFlushResult {
        if !crate::is_administrator() {
            return ModifiedFlushResult {
                attempted: false,
                success: false,
                skipped_reason: Some("Requires Administrator".to_string()),
            };
        }

        unsafe {
            if let Err(e) = enable_privilege("SeIncreaseQuotaPrivilege") {
                return ModifiedFlushResult {
                    attempted: false,
                    success: false,
                    skipped_reason: Some(format!(
                        "Could not enable SeIncreaseQuotaPrivilege: {}",
                        e
                    )),
                };
            }

            let command: u32 = MEMORY_FLUSH_MODIFIED_LIST;
            let status = NtSetSystemInformation(
                SYSTEM_MEMORY_LIST_INFORMATION,
                &command as *const u32 as *const c_void,
                std::mem::size_of::<u32>() as u32,
            );

            if status == 0 {
                ModifiedFlushResult {
                    attempted: true,
                    success: true,
                    skipped_reason: None,
                }
            } else {
                ModifiedFlushResult {
                    attempted: true,
                    success: false,
                    skipped_reason: Some(format!(
                        "NtSetSystemInformation failed (0x{status:08X})"
                    )),
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

        // Phase 2: Flush modified page list (converts dirty pages to standby)
        let snap = snapshot_or_warn(&mut warnings);
        on_progress("flushing_modified", snap, trimmed_count, None, None);

        let modified_flush = flush_modified_list();
        if !modified_flush.success {
            if let Some(reason) = modified_flush.skipped_reason.clone() {
                warnings.push(format!("Modified flush: {}", reason));
            }
        }

        // Phase 3: Purge standby list (reclaims all standby pages including newly flushed)
        let pre_standby = snapshot_or_warn(&mut warnings);
        on_progress("standby_purge", pre_standby, trimmed_count, None, None);

        let standby_purge = purge_standby_list();
        if !standby_purge.success {
            if let Some(reason) = standby_purge.skipped_reason.clone() {
                warnings.push(format!("Standby purge: {}", reason));
            }
        }

        let after = snapshot_or_warn(&mut warnings);
        on_progress("done", after, trimmed_count, None, None);

        // Compute freed deltas
        let freed_mb = after.available_mb as i64 - before.available_mb as i64;
        let standby_freed_mb = match (before.standby_mb, after.standby_mb) {
            (Some(b), Some(a)) => Some(b as i64 - a as i64),
            _ => None,
        };
        let modified_freed_mb = match (before.modified_mb, after.modified_mb) {
            (Some(b), Some(a)) => Some(b as i64 - a as i64),
            _ => None,
        };

        Ok(RamCleanResult {
            before,
            after,
            trimmed_count,
            standby_purge,
            modified_flush,
            freed_mb,
            standby_freed_mb,
            modified_freed_mb,
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
            proc(11, "discord.exe", 700, 4.0),
        ];
        let exclude = HashSet::new();
        let selected = select_trim_candidates(processes, &exclude);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].pid, 11);
    }

    #[test]
    fn select_candidates_applies_memory_threshold_and_caps_max() {
        let mut processes = Vec::new();
        // Below 50MB threshold - should be excluded
        processes.push(proc(1, "small.exe", 49, 0.0));
        for i in 0..45 {
            processes.push(proc(100 + i, &format!("p{i}.exe"), 50 + i as u64, 0.0));
        }
        let exclude = HashSet::new();
        let selected = select_trim_candidates(processes, &exclude);
        assert_eq!(selected.len(), MAX_TRIM_PROCESSES);
        assert!(selected.iter().all(|p| p.memory_bytes >= MIN_PROCESS_BYTES));
        // Highest memory first (50+44)
        assert_eq!(selected[0].pid, 144);
    }

    #[test]
    fn select_candidates_excludes_game_processes() {
        let processes = vec![
            proc(10, "RobloxPlayerBeta.exe", 800, 0.0),
            proc(11, "valorant-win64-shipping.exe", 900, 0.0),
            proc(12, "FortniteClient-Win64-Shipping.exe", 700, 0.0),
            proc(13, "Chrome.exe", 600, 0.0),
        ];
        let exclude = HashSet::new();
        let selected = select_trim_candidates(processes, &exclude);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].pid, 13);
    }

    #[test]
    fn select_candidates_excludes_swifttunnel_processes() {
        let processes = vec![
            proc(10, "swifttunnel.exe", 500, 0.0),
            proc(11, "SwiftTunnel-Desktop.exe", 300, 0.0),
            proc(12, "Chrome.exe", 600, 0.0),
        ];
        let exclude = HashSet::new();
        let selected = select_trim_candidates(processes, &exclude);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].pid, 12);
    }

    #[test]
    fn memory_list_stats_default() {
        let stats = MemoryListStats::default();
        assert_eq!(stats.standby_mb, 0);
        assert_eq!(stats.modified_mb, 0);
    }

    #[test]
    fn system_memory_snapshot_optional_fields() {
        let snap = SystemMemorySnapshot {
            total_mb: 16000,
            available_mb: 8000,
            used_mb: 8000,
            load_pct: 50,
            standby_mb: Some(2048),
            modified_mb: Some(512),
        };
        assert_eq!(snap.standby_mb, Some(2048));
        assert_eq!(snap.modified_mb, Some(512));

        let snap_none = SystemMemorySnapshot {
            total_mb: 16000,
            available_mb: 8000,
            used_mb: 8000,
            load_pct: 50,
            standby_mb: None,
            modified_mb: None,
        };
        assert_eq!(snap_none.standby_mb, None);
        assert_eq!(snap_none.modified_mb, None);
    }
}
