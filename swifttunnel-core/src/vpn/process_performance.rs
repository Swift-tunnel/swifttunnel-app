use crate::settings::GameProcessPerformanceSettings;
use std::collections::HashMap;

const GPU_PREFERENCES_KEY_PATH: &str = r"Software\Microsoft\DirectX\UserGpuPreferences";
const GPU_PREFERENCE_HIGH_PERFORMANCE: &str = "GpuPreference=2;";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GameProcessPerformancePolicy {
    pub high_performance_gpu_binding: bool,
    pub prefer_performance_cores: bool,
    pub unbind_cpu0: bool,
}

impl GameProcessPerformancePolicy {
    pub fn is_enabled(self) -> bool {
        self.high_performance_gpu_binding || self.prefer_performance_cores || self.unbind_cpu0
    }
}

impl From<GameProcessPerformanceSettings> for GameProcessPerformancePolicy {
    fn from(value: GameProcessPerformanceSettings) -> Self {
        Self {
            high_performance_gpu_binding: value.high_performance_gpu_binding,
            prefer_performance_cores: value.prefer_performance_cores,
            unbind_cpu0: value.unbind_cpu0,
        }
    }
}

#[derive(Debug, Clone)]
struct AppliedProcessState {
    process_name: String,
    affinity_original: Option<usize>,
    affinity_applied: bool,
    cpu_sets_original: Option<Vec<u32>>,
    cpu_sets_applied: bool,
    gpu_registry_key: Option<String>,
}

impl AppliedProcessState {
    fn new(process_name: String) -> Self {
        Self {
            process_name,
            affinity_original: None,
            affinity_applied: false,
            cpu_sets_original: None,
            cpu_sets_applied: false,
            gpu_registry_key: None,
        }
    }

    fn has_any_applied_control(&self) -> bool {
        self.affinity_applied || self.cpu_sets_applied || self.gpu_registry_key.is_some()
    }
}

#[derive(Debug, Clone)]
struct GpuPreferenceSnapshot {
    value_name: String,
    previous_value: Option<String>,
    ref_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CpuSetDescriptor {
    pub id: u32,
    pub logical_processor_index: u8,
    pub efficiency_class: u8,
    pub parked: bool,
}

pub struct GameProcessPerformanceManager {
    policy: GameProcessPerformancePolicy,
    active_processes: HashMap<u32, AppliedProcessState>,
    gpu_preferences: HashMap<String, GpuPreferenceSnapshot>,
}

impl GameProcessPerformanceManager {
    pub fn new(policy: GameProcessPerformancePolicy) -> Self {
        Self {
            policy,
            active_processes: HashMap::new(),
            gpu_preferences: HashMap::new(),
        }
    }

    pub fn policy(&self) -> GameProcessPerformancePolicy {
        self.policy
    }

    pub fn sync_targets(&mut self, running_targets: &[(u32, String)]) {
        if !self.policy.is_enabled() {
            return;
        }

        let mut desired: HashMap<u32, String> = HashMap::with_capacity(running_targets.len());
        for (pid, name) in running_targets {
            desired.entry(*pid).or_insert_with(|| name.clone());
        }

        for (&pid, name) in &desired {
            if !self.active_processes.contains_key(&pid) {
                self.apply_for_process(pid, name.clone());
            }
        }

        let stale_pids: Vec<u32> = self
            .active_processes
            .keys()
            .filter(|pid| !desired.contains_key(pid))
            .copied()
            .collect();

        for pid in stale_pids {
            self.revert_for_process(pid, "process_exit");
        }
    }

    pub fn cleanup_all(&mut self, reason: &str) {
        let tracked: Vec<u32> = self.active_processes.keys().copied().collect();
        for pid in tracked {
            self.revert_for_process(pid, reason);
        }

        #[cfg(windows)]
        {
            // Defensive cleanup in case refs got out of sync.
            if !self.gpu_preferences.is_empty() {
                let remaining: Vec<String> = self.gpu_preferences.keys().cloned().collect();
                for key in remaining {
                    if let Some(snapshot) = self.gpu_preferences.remove(&key) {
                        if let Err(e) =
                            restore_gpu_preference(&snapshot.value_name, &snapshot.previous_value)
                        {
                            log::warn!(
                                "Process tuning: failed to force-restore GPU preference '{}' during cleanup: {}",
                                snapshot.value_name,
                                e
                            );
                        } else {
                            log::info!(
                                "Process tuning: force-restored GPU preference for '{}' during cleanup",
                                snapshot.value_name
                            );
                        }
                    }
                }
            }
        }

        #[cfg(not(windows))]
        {
            self.gpu_preferences.clear();
        }
    }

    fn apply_for_process(&mut self, pid: u32, process_name: String) {
        let mut state = AppliedProcessState::new(process_name.clone());

        #[cfg(windows)]
        {
            self.apply_windows_process_controls(pid, &mut state);
        }

        #[cfg(not(windows))]
        {
            let _ = pid;
            let _ = &mut state;
            log::debug!("Process tuning is only supported on Windows");
        }

        if state.has_any_applied_control() {
            self.active_processes.insert(pid, state);
        } else {
            log::info!(
                "Process tuning: no controls applied for '{}' (PID {})",
                process_name,
                pid
            );
        }
    }

    fn revert_for_process(&mut self, pid: u32, reason: &str) {
        let Some(state) = self.active_processes.remove(&pid) else {
            return;
        };

        #[cfg(windows)]
        {
            self.revert_windows_process_controls(pid, &state, reason);
        }

        #[cfg(not(windows))]
        {
            let _ = reason;
            log::debug!(
                "Process tuning revert skipped for '{}' (PID {}) on non-Windows",
                state.process_name,
                pid
            );
        }
    }

    #[cfg(windows)]
    fn apply_windows_process_controls(&mut self, pid: u32, state: &mut AppliedProcessState) {
        use windows::Win32::Foundation::CloseHandle;

        let process = open_process_for_tuning(pid);
        let mut process_open_failed = false;

        match process {
            Some(handle) => {
                if self.policy.prefer_performance_cores || self.policy.unbind_cpu0 {
                    self.apply_cpu_policy_for_process(pid, handle, state);
                }

                if self.policy.high_performance_gpu_binding {
                    self.apply_gpu_binding(pid, handle, state);
                }

                unsafe {
                    let _ = CloseHandle(handle);
                }
            }
            None => {
                process_open_failed = true;
                log::warn!(
                    "Process tuning: failed to open '{}' (PID {}) for tuning",
                    state.process_name,
                    pid
                );
            }
        }

        if process_open_failed && self.policy.high_performance_gpu_binding {
            log::warn!(
                "Process tuning: GPU binding skipped for '{}' (PID {}) because process handle was unavailable",
                state.process_name,
                pid
            );
        }
    }

    #[cfg(windows)]
    fn revert_windows_process_controls(
        &mut self,
        pid: u32,
        state: &AppliedProcessState,
        reason: &str,
    ) {
        use windows::Win32::Foundation::CloseHandle;

        let process = open_process_for_tuning(pid);

        if let Some(handle) = process {
            if state.cpu_sets_applied {
                match cpu_set_api() {
                    Some(api) => {
                        let restore_ids = state.cpu_sets_original.clone().unwrap_or_default();
                        if let Err(e) = set_process_default_cpu_sets(api, handle, &restore_ids) {
                            log::warn!(
                                "Process tuning: failed to restore CPU sets for '{}' (PID {}): {}",
                                state.process_name,
                                pid,
                                e
                            );
                        } else {
                            log::info!(
                                "Process tuning: restored CPU sets for '{}' (PID {}) on {}",
                                state.process_name,
                                pid,
                                reason
                            );
                        }
                    }
                    None => {
                        log::warn!(
                            "Process tuning: CPU Sets API unavailable while restoring '{}' (PID {})",
                            state.process_name,
                            pid
                        );
                    }
                }
            }

            if state.affinity_applied {
                if let Some(original_mask) = state.affinity_original {
                    unsafe {
                        if let Err(e) = windows::Win32::System::Threading::SetProcessAffinityMask(
                            handle,
                            original_mask,
                        ) {
                            log::warn!(
                                "Process tuning: failed to restore affinity for '{}' (PID {}): {}",
                                state.process_name,
                                pid,
                                e
                            );
                        } else {
                            log::info!(
                                "Process tuning: restored affinity for '{}' (PID {}) on {}",
                                state.process_name,
                                pid,
                                reason
                            );
                        }
                    }
                }
            }

            unsafe {
                let _ = CloseHandle(handle);
            }
        } else if state.cpu_sets_applied || state.affinity_applied {
            log::info!(
                "Process tuning: process '{}' (PID {}) already exited before runtime restore ({})",
                state.process_name,
                pid,
                reason
            );
        }

        if let Some(gpu_key) = &state.gpu_registry_key {
            self.decrement_gpu_binding_reference(gpu_key, &state.process_name, pid, reason);
        }
    }

    #[cfg(windows)]
    fn apply_cpu_policy_for_process(
        &self,
        pid: u32,
        process: windows::Win32::Foundation::HANDLE,
        state: &mut AppliedProcessState,
    ) {
        let mut cpu_sets_applied = false;

        if self.policy.prefer_performance_cores || self.policy.unbind_cpu0 {
            match self.try_apply_cpu_sets_policy(pid, process, state) {
                Ok(()) => {
                    cpu_sets_applied = true;
                }
                Err(e) => {
                    log::warn!(
                        "Process tuning: CPU Sets policy unavailable for '{}' (PID {}): {}",
                        state.process_name,
                        pid,
                        e
                    );
                }
            }
        }

        if !cpu_sets_applied {
            if self.policy.unbind_cpu0 {
                self.apply_affinity_cpu0_unbind_fallback(pid, process, state);
            }
            if self.policy.prefer_performance_cores {
                log::warn!(
                    "Process tuning: P-core preference for '{}' (PID {}) requires CPU Sets API; fallback cannot guarantee hybrid-core steering",
                    state.process_name,
                    pid
                );
            }
        }
    }

    #[cfg(windows)]
    fn try_apply_cpu_sets_policy(
        &self,
        pid: u32,
        process: windows::Win32::Foundation::HANDLE,
        state: &mut AppliedProcessState,
    ) -> Result<(), String> {
        let api =
            cpu_set_api().ok_or_else(|| "CPU Sets API not exported by kernel32".to_string())?;

        let cpu_sets = query_system_cpu_sets(api)?;
        if cpu_sets.is_empty() {
            return Err("No system CPU sets were reported".to_string());
        }

        let selected = select_cpu_set_ids(
            &cpu_sets,
            self.policy.prefer_performance_cores,
            self.policy.unbind_cpu0,
        );

        if selected.is_empty() {
            return Err("No eligible CPU set IDs after policy filters".to_string());
        }

        let original = match get_process_default_cpu_sets(api, process) {
            Ok(ids) => Some(ids),
            Err(e) => {
                log::warn!(
                    "Process tuning: unable to snapshot original CPU sets for '{}' (PID {}): {}",
                    state.process_name,
                    pid,
                    e
                );
                None
            }
        };

        set_process_default_cpu_sets(api, process, &selected)?;

        state.cpu_sets_original = original;
        state.cpu_sets_applied = true;

        log::info!(
            "Process tuning: applied CPU sets {:?} to '{}' (PID {}) (prefer_p_cores={}, unbind_cpu0={})",
            selected,
            state.process_name,
            pid,
            self.policy.prefer_performance_cores,
            self.policy.unbind_cpu0
        );

        Ok(())
    }

    #[cfg(windows)]
    fn apply_affinity_cpu0_unbind_fallback(
        &self,
        pid: u32,
        process: windows::Win32::Foundation::HANDLE,
        state: &mut AppliedProcessState,
    ) {
        let mut process_mask: usize = 0;
        let mut system_mask: usize = 0;

        unsafe {
            if let Err(e) = windows::Win32::System::Threading::GetProcessAffinityMask(
                process,
                &mut process_mask,
                &mut system_mask,
            ) {
                log::warn!(
                    "Process tuning: failed to query affinity for '{}' (PID {}): {}",
                    state.process_name,
                    pid,
                    e
                );
                return;
            }
        }

        if process_mask == 0 {
            log::warn!(
                "Process tuning: affinity mask is empty for '{}' (PID {}), skipping CPU0 unbind",
                state.process_name,
                pid
            );
            return;
        }

        let updated_mask = compute_affinity_mask_without_cpu0(process_mask);
        if updated_mask == process_mask {
            log::info!(
                "Process tuning: CPU0 unbind not applicable for '{}' (PID {}) on current affinity mask 0x{:X}",
                state.process_name,
                pid,
                process_mask
            );
            return;
        }

        unsafe {
            if let Err(e) =
                windows::Win32::System::Threading::SetProcessAffinityMask(process, updated_mask)
            {
                log::warn!(
                    "Process tuning: failed to apply CPU0 affinity unbind for '{}' (PID {}): {}",
                    state.process_name,
                    pid,
                    e
                );
                return;
            }
        }

        state.affinity_original = Some(process_mask);
        state.affinity_applied = true;

        log::info!(
            "Process tuning: applied CPU0 affinity unbind for '{}' (PID {}) (0x{:X} -> 0x{:X})",
            state.process_name,
            pid,
            process_mask,
            updated_mask
        );
    }

    #[cfg(windows)]
    fn apply_gpu_binding(
        &mut self,
        pid: u32,
        process: windows::Win32::Foundation::HANDLE,
        state: &mut AppliedProcessState,
    ) {
        let Some(process_path) = resolve_process_image_path(process) else {
            log::warn!(
                "Process tuning: failed to resolve executable path for '{}' (PID {}), GPU binding skipped",
                state.process_name,
                pid
            );
            return;
        };

        let value_name = normalize_gpu_value_name(&process_path);
        let map_key = value_name.to_ascii_lowercase();

        if let Some(existing) = self.gpu_preferences.get_mut(&map_key) {
            existing.ref_count += 1;
            state.gpu_registry_key = Some(map_key);
            log::info!(
                "Process tuning: reused GPU preference ref for '{}' (PID {})",
                state.process_name,
                pid
            );
            return;
        }

        let previous_value = match read_gpu_preference_value(&value_name) {
            Ok(value) => value,
            Err(e) => {
                log::warn!(
                    "Process tuning: failed to read previous GPU preference for '{}': {}",
                    value_name,
                    e
                );
                None
            }
        };

        match write_gpu_preference_value(&value_name, GPU_PREFERENCE_HIGH_PERFORMANCE) {
            Ok(()) => {
                self.gpu_preferences.insert(
                    map_key.clone(),
                    GpuPreferenceSnapshot {
                        value_name: value_name.clone(),
                        previous_value,
                        ref_count: 1,
                    },
                );
                state.gpu_registry_key = Some(map_key);
                log::info!(
                    "Process tuning: applied high-performance GPU preference for '{}' (PID {}) => {}",
                    state.process_name,
                    pid,
                    value_name
                );
            }
            Err(e) => {
                log::warn!(
                    "Process tuning: failed to apply GPU preference for '{}' (PID {}): {}",
                    state.process_name,
                    pid,
                    e
                );
            }
        }
    }

    #[cfg(windows)]
    fn decrement_gpu_binding_reference(
        &mut self,
        gpu_key: &str,
        process_name: &str,
        pid: u32,
        reason: &str,
    ) {
        let mut should_restore = false;
        if let Some(entry) = self.gpu_preferences.get_mut(gpu_key) {
            if entry.ref_count > 1 {
                entry.ref_count -= 1;
                log::info!(
                    "Process tuning: decreased GPU preference ref for '{}' (PID {}), remaining refs={}",
                    process_name,
                    pid,
                    entry.ref_count
                );
                return;
            }
            should_restore = true;
        }

        if !should_restore {
            return;
        }

        if let Some(snapshot) = self.gpu_preferences.remove(gpu_key) {
            match restore_gpu_preference(&snapshot.value_name, &snapshot.previous_value) {
                Ok(()) => {
                    log::info!(
                        "Process tuning: restored GPU preference for '{}' after '{}' (PID {}, reason={})",
                        snapshot.value_name,
                        process_name,
                        pid,
                        reason
                    );
                }
                Err(e) => {
                    log::warn!(
                        "Process tuning: failed to restore GPU preference for '{}' after '{}' (PID {}, reason={}): {}",
                        snapshot.value_name,
                        process_name,
                        pid,
                        reason,
                        e
                    );
                }
            }
        }
    }
}

pub(crate) fn select_cpu_set_ids(
    cpu_sets: &[CpuSetDescriptor],
    prefer_performance_cores: bool,
    unbind_cpu0: bool,
) -> Vec<u32> {
    let mut candidates: Vec<&CpuSetDescriptor> =
        cpu_sets.iter().filter(|set| !set.parked).collect();
    if candidates.is_empty() {
        candidates = cpu_sets.iter().collect();
    }

    if prefer_performance_cores {
        if let Some(best_efficiency) = candidates.iter().map(|set| set.efficiency_class).min() {
            candidates.retain(|set| set.efficiency_class == best_efficiency);
        }
    }

    if unbind_cpu0 {
        candidates.retain(|set| set.logical_processor_index != 0);
    }

    // If strict filters emptied the list, relax performance-core preference but still honor CPU0 exclusion.
    if candidates.is_empty() && unbind_cpu0 {
        let mut fallback: Vec<&CpuSetDescriptor> =
            cpu_sets.iter().filter(|set| !set.parked).collect();
        if fallback.is_empty() {
            fallback = cpu_sets.iter().collect();
        }
        fallback.retain(|set| set.logical_processor_index != 0);
        candidates = fallback;
    }

    let mut ids: Vec<u32> = candidates.into_iter().map(|set| set.id).collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

pub(crate) fn compute_affinity_mask_without_cpu0(mask: usize) -> usize {
    if (mask & 1) == 0 {
        return mask;
    }
    if mask.count_ones() <= 1 {
        return mask;
    }
    mask & !1usize
}

fn normalize_gpu_value_name(path: &str) -> String {
    path.trim().replace('/', "\\")
}

#[cfg(windows)]
fn open_process_for_tuning(pid: u32) -> Option<windows::Win32::Foundation::HANDLE> {
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_SET_INFORMATION,
    };

    unsafe {
        OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_INFORMATION,
            false,
            pid,
        )
        .ok()
        .filter(|handle| !handle.is_invalid())
    }
}

#[cfg(windows)]
unsafe extern "system" {
    fn QueryFullProcessImageNameW(
        hprocess: windows::Win32::Foundation::HANDLE,
        dwflags: u32,
        lpexename: *mut u16,
        lpdwsize: *mut u32,
    ) -> i32;
}

#[cfg(windows)]
fn resolve_process_image_path(process: windows::Win32::Foundation::HANDLE) -> Option<String> {
    let mut buffer = vec![0u16; 32_768];
    let mut length: u32 = buffer.len() as u32;

    let ok = unsafe { QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &mut length) };

    if ok == 0 || length == 0 {
        return None;
    }

    Some(String::from_utf16_lossy(&buffer[..length as usize]))
}

#[cfg(windows)]
fn read_gpu_preference_value(value_name: &str) -> Result<Option<String>, String> {
    use winreg::RegKey;
    use winreg::enums::HKEY_CURRENT_USER;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (key, _) = hkcu
        .create_subkey(GPU_PREFERENCES_KEY_PATH)
        .map_err(|e| format!("create_subkey {}: {}", GPU_PREFERENCES_KEY_PATH, e))?;

    match key.get_value::<String, _>(value_name) {
        Ok(value) => Ok(Some(value)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("get_value {}: {}", value_name, e)),
    }
}

#[cfg(windows)]
fn write_gpu_preference_value(value_name: &str, value: &str) -> Result<(), String> {
    use winreg::RegKey;
    use winreg::enums::HKEY_CURRENT_USER;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (key, _) = hkcu
        .create_subkey(GPU_PREFERENCES_KEY_PATH)
        .map_err(|e| format!("create_subkey {}: {}", GPU_PREFERENCES_KEY_PATH, e))?;

    key.set_value(value_name, &value)
        .map_err(|e| format!("set_value {}: {}", value_name, e))
}

#[cfg(windows)]
fn restore_gpu_preference(value_name: &str, previous_value: &Option<String>) -> Result<(), String> {
    use winreg::RegKey;
    use winreg::enums::HKEY_CURRENT_USER;

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (key, _) = hkcu
        .create_subkey(GPU_PREFERENCES_KEY_PATH)
        .map_err(|e| format!("create_subkey {}: {}", GPU_PREFERENCES_KEY_PATH, e))?;

    match previous_value {
        Some(value) => key
            .set_value(value_name, value)
            .map_err(|e| format!("restore set_value {}: {}", value_name, e)),
        None => match key.delete_value(value_name) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("delete_value {}: {}", value_name, e)),
        },
    }
}

#[cfg(windows)]
#[derive(Clone, Copy)]
struct CpuSetApi {
    get_system_cpu_set_information: unsafe extern "system" fn(
        *mut std::ffi::c_void,
        u32,
        *mut u32,
        windows::Win32::Foundation::HANDLE,
        u32,
    ) -> i32,
    get_process_default_cpu_sets: unsafe extern "system" fn(
        windows::Win32::Foundation::HANDLE,
        *mut u32,
        u32,
        *mut u32,
    ) -> i32,
    set_process_default_cpu_sets:
        unsafe extern "system" fn(windows::Win32::Foundation::HANDLE, *const u32, u32) -> i32,
}

#[cfg(windows)]
unsafe extern "system" {
    fn GetModuleHandleW(lpmodulename: *const u16) -> isize;
    fn GetProcAddress(hmodule: isize, lpprocname: *const u8) -> *const std::ffi::c_void;
}

#[cfg(windows)]
fn cpu_set_api() -> Option<CpuSetApi> {
    static CPU_SET_API: std::sync::OnceLock<Option<CpuSetApi>> = std::sync::OnceLock::new();
    *CPU_SET_API.get_or_init(load_cpu_set_api)
}

#[cfg(windows)]
fn load_cpu_set_api() -> Option<CpuSetApi> {
    let get_system = kernel32_proc_address(b"GetSystemCpuSetInformation\0")?;
    let get_process = kernel32_proc_address(b"GetProcessDefaultCpuSets\0")?;
    let set_process = kernel32_proc_address(b"SetProcessDefaultCpuSets\0")?;

    let api = unsafe {
        CpuSetApi {
            get_system_cpu_set_information: std::mem::transmute(get_system),
            get_process_default_cpu_sets: std::mem::transmute(get_process),
            set_process_default_cpu_sets: std::mem::transmute(set_process),
        }
    };

    Some(api)
}

#[cfg(windows)]
fn kernel32_proc_address(symbol: &'static [u8]) -> Option<*const std::ffi::c_void> {
    let module_name: Vec<u16> = "kernel32.dll"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let module = unsafe { GetModuleHandleW(module_name.as_ptr()) };
    if module == 0 {
        return None;
    }

    let address = unsafe { GetProcAddress(module, symbol.as_ptr()) };
    if address.is_null() {
        None
    } else {
        Some(address)
    }
}

#[cfg(windows)]
fn query_system_cpu_sets(api: CpuSetApi) -> Result<Vec<CpuSetDescriptor>, String> {
    use windows::Win32::Foundation::HANDLE;

    let mut needed_len: u32 = 0;
    unsafe {
        (api.get_system_cpu_set_information)(
            std::ptr::null_mut(),
            0,
            &mut needed_len,
            HANDLE::default(),
            0,
        );
    }

    if needed_len == 0 {
        return Err("CPU Sets API returned an empty buffer length".to_string());
    }

    let mut buffer = vec![0u8; needed_len as usize];
    let ok = unsafe {
        (api.get_system_cpu_set_information)(
            buffer.as_mut_ptr() as *mut std::ffi::c_void,
            needed_len,
            &mut needed_len,
            HANDLE::default(),
            0,
        )
    };

    if ok == 0 {
        return Err(format!(
            "GetSystemCpuSetInformation failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    buffer.truncate(needed_len as usize);
    Ok(parse_cpu_set_buffer(&buffer))
}

#[cfg(windows)]
fn parse_cpu_set_buffer(buffer: &[u8]) -> Vec<CpuSetDescriptor> {
    const CPU_SET_INFO_TYPE: u32 = 0;

    let mut output = Vec::new();
    let mut offset = 0usize;

    while offset + 8 <= buffer.len() {
        let size = match read_u32_le(buffer, offset) {
            Some(v) if v >= 8 => v as usize,
            _ => break,
        };

        if offset + size > buffer.len() {
            break;
        }

        let info_type = read_u32_le(buffer, offset + 4).unwrap_or(u32::MAX);

        // For CpuSet records, parse only the fields we need from documented offsets.
        if info_type == CPU_SET_INFO_TYPE && size >= 24 {
            if let Some(id) = read_u32_le(buffer, offset + 8) {
                let logical_processor_index = buffer[offset + 14];
                let efficiency_class = buffer[offset + 18];
                let all_flags = buffer[offset + 19];
                let parked = (all_flags & 0x01) != 0;

                output.push(CpuSetDescriptor {
                    id,
                    logical_processor_index,
                    efficiency_class,
                    parked,
                });
            }
        }

        offset += size;
    }

    output
}

#[cfg(windows)]
fn read_u32_le(buffer: &[u8], offset: usize) -> Option<u32> {
    let slice = buffer.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

#[cfg(windows)]
fn get_process_default_cpu_sets(
    api: CpuSetApi,
    process: windows::Win32::Foundation::HANDLE,
) -> Result<Vec<u32>, String> {
    let mut required_count: u32 = 0;
    let first_ok = unsafe {
        (api.get_process_default_cpu_sets)(process, std::ptr::null_mut(), 0, &mut required_count)
    };

    if first_ok != 0 && required_count == 0 {
        return Ok(Vec::new());
    }

    if required_count == 0 {
        return Err(format!(
            "GetProcessDefaultCpuSets sizing call failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let mut ids = vec![0u32; required_count as usize];
    let second_ok = unsafe {
        (api.get_process_default_cpu_sets)(
            process,
            ids.as_mut_ptr(),
            ids.len() as u32,
            &mut required_count,
        )
    };

    if second_ok == 0 {
        return Err(format!(
            "GetProcessDefaultCpuSets query call failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    ids.truncate(required_count as usize);
    Ok(ids)
}

#[cfg(windows)]
fn set_process_default_cpu_sets(
    api: CpuSetApi,
    process: windows::Win32::Foundation::HANDLE,
    ids: &[u32],
) -> Result<(), String> {
    let ptr = if ids.is_empty() {
        std::ptr::null()
    } else {
        ids.as_ptr()
    };

    let ok = unsafe { (api.set_process_default_cpu_sets)(process, ptr, ids.len() as u32) };
    if ok == 0 {
        return Err(format!(
            "SetProcessDefaultCpuSets failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cpu_set(id: u32, logical_index: u8, efficiency_class: u8) -> CpuSetDescriptor {
        CpuSetDescriptor {
            id,
            logical_processor_index: logical_index,
            efficiency_class,
            parked: false,
        }
    }

    #[test]
    fn select_cpu_set_ids_prefers_performance_cores() {
        let sets = vec![
            cpu_set(10, 0, 0),
            cpu_set(11, 1, 0),
            cpu_set(20, 2, 8),
            cpu_set(21, 3, 8),
        ];

        let selected = select_cpu_set_ids(&sets, true, false);
        assert_eq!(selected, vec![10, 11]);
    }

    #[test]
    fn select_cpu_set_ids_excludes_cpu0() {
        let sets = vec![cpu_set(100, 0, 0), cpu_set(101, 1, 0), cpu_set(102, 2, 0)];
        let selected = select_cpu_set_ids(&sets, false, true);
        assert_eq!(selected, vec![101, 102]);
    }

    #[test]
    fn select_cpu_set_ids_handles_single_cpu_when_cpu0_unbind_enabled() {
        let sets = vec![cpu_set(100, 0, 0)];
        let selected = select_cpu_set_ids(&sets, false, true);
        assert!(selected.is_empty());
    }

    #[test]
    fn compute_affinity_mask_without_cpu0_removes_cpu0_when_possible() {
        // CPUs 0,1,2 enabled
        let mask = 0b0111usize;
        assert_eq!(compute_affinity_mask_without_cpu0(mask), 0b0110usize);
    }

    #[test]
    fn compute_affinity_mask_without_cpu0_keeps_single_cpu_system() {
        let mask = 0b0001usize;
        assert_eq!(compute_affinity_mask_without_cpu0(mask), mask);
    }

    #[test]
    fn policy_from_settings_maps_all_flags() {
        let settings = GameProcessPerformanceSettings {
            high_performance_gpu_binding: true,
            prefer_performance_cores: true,
            unbind_cpu0: false,
        };

        let policy = GameProcessPerformancePolicy::from(settings);
        assert!(policy.high_performance_gpu_binding);
        assert!(policy.prefer_performance_cores);
        assert!(!policy.unbind_cpu0);
        assert!(policy.is_enabled());
    }
}
