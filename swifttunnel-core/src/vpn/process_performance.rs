use crate::settings::GameProcessPerformanceSettings;
use std::collections::HashMap;

const GPU_PREFERENCES_KEY_PATH: &str = r"HKCU\Software\Microsoft\DirectX\UserGpuPreferences";

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
struct TemporarySetting<T> {
    original: T,
    applied: T,
}

fn restore_setting<T: PartialEq>(
    slot: &mut Option<TemporarySetting<T>>,
    read: impl FnOnce() -> Result<T, String>,
    restore: impl FnOnce(&T) -> Result<(), String>,
) -> Result<(), String> {
    if let Some(setting) = slot {
        if read()? == setting.applied {
            restore(&setting.original)?;
        }
        *slot = None;
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct AppliedProcessState {
    process_name: String,
    #[cfg(windows)]
    created: Option<u64>,
    affinity: Option<TemporarySetting<usize>>,
    cpu_sets: Option<TemporarySetting<Vec<u32>>>,
    gpu_registry_key: Option<String>,
}

impl AppliedProcessState {
    fn new(process_name: String) -> Self {
        Self {
            process_name,
            #[cfg(windows)]
            created: None,
            affinity: None,
            cpu_sets: None,
            gpu_registry_key: None,
        }
    }

    fn has_any_applied_control(&self) -> bool {
        self.affinity.is_some() || self.cpu_sets.is_some() || self.gpu_registry_key.is_some()
    }
}

#[derive(Debug, Clone)]
struct GpuPreferenceSnapshot {
    value_name: String,
    previous_value: Option<String>,
    applied_value: String,
    ref_count: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CpuSetDescriptor {
    pub id: u32,
    pub group: u16,
    pub logical_processor_index: u8,
    pub efficiency_class: u8,
    pub parked: bool,
    pub allocated_to_other_process: bool,
}

pub struct GameProcessPerformanceManager {
    policy: GameProcessPerformancePolicy,
    active_processes: HashMap<u32, AppliedProcessState>,
    gpu_preferences: HashMap<String, GpuPreferenceSnapshot>,
    failed_attempts: HashMap<u32, (String, std::time::Instant)>,
}

impl GameProcessPerformanceManager {
    pub fn new(policy: GameProcessPerformancePolicy) -> Self {
        Self {
            policy,
            active_processes: HashMap::new(),
            gpu_preferences: HashMap::new(),
            failed_attempts: HashMap::new(),
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
            #[cfg(windows)]
            if let Some(original) = self
                .active_processes
                .get(&pid)
                .and_then(|state| state.created)
                && process_creation_for_pid(pid).is_some_and(|current| original != current)
            {
                self.revert_for_process(pid, "process_replaced");
            }
            if !self.active_processes.contains_key(&pid) {
                if self
                    .failed_attempts
                    .get(&pid)
                    .is_some_and(|(previous_name, at)| {
                        previous_name == name && at.elapsed() < std::time::Duration::from_secs(10)
                    })
                {
                    continue;
                }
                self.apply_for_process(pid, name.clone());
            }
        }
        self.failed_attempts
            .retain(|pid, _| desired.contains_key(pid));

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
        self.failed_attempts.clear();
        let tracked: Vec<u32> = self.active_processes.keys().copied().collect();
        for pid in tracked {
            self.revert_for_process(pid, reason);
        }

        #[cfg(windows)]
        if !self.active_processes.is_empty() {
            log::warn!(
                "Process tuning restore has pending originals; they remain available for retry"
            );
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
            self.failed_attempts.remove(&pid);
            self.active_processes.insert(pid, state);
        } else {
            self.failed_attempts
                .insert(pid, (process_name.clone(), std::time::Instant::now()));
            log::info!(
                "Process tuning: no controls applied for '{}' (PID {})",
                process_name,
                pid
            );
        }
    }

    fn revert_for_process(&mut self, pid: u32, reason: &str) {
        let Some(mut state) = self.active_processes.remove(&pid) else {
            return;
        };

        #[cfg(windows)]
        {
            self.revert_windows_process_controls(pid, &mut state, reason);
            if state.has_any_applied_control() {
                self.active_processes.insert(pid, state);
            }
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
        let Some(handle) = open_process_for_tuning(pid) else {
            log::warn!(
                "Process tuning could not open {} (PID {pid})",
                state.process_name
            );
            return;
        };
        let identity = crate::process_snapshot::creation_time(handle);
        let image = crate::process_snapshot::image_for_handle(handle);
        if let (Ok(created), Ok(image)) = (identity, image) {
            if crate::process_names::process_name_matches_alias(&image, &state.process_name) {
                state.created = Some(created);
                if self.policy.prefer_performance_cores || self.policy.unbind_cpu0 {
                    self.apply_cpu_policy_for_process(pid, handle, state);
                }
                if self.policy.high_performance_gpu_binding {
                    self.apply_gpu_binding(pid, &image, state);
                }
            }
        } else {
            log::warn!(
                "Process tuning could not verify {} (PID {pid}); controls were skipped",
                state.process_name
            );
        }
        unsafe {
            let _ = CloseHandle(handle);
        }
    }

    #[cfg(windows)]
    fn revert_windows_process_controls(
        &mut self,
        pid: u32,
        state: &mut AppliedProcessState,
        reason: &str,
    ) {
        use windows::Win32::Foundation::CloseHandle;
        if state.cpu_sets.is_some() || state.affinity.is_some() {
            if let Some(handle) = open_process_for_tuning(pid) {
                match crate::process_snapshot::creation_time(handle) {
                    Ok(created) if state.created == Some(created) => {
                        if state.cpu_sets.is_some() {
                            let result = cpu_set_api()
                                .ok_or_else(|| "CPU Sets API is unavailable".to_string())
                                .and_then(|api| {
                                    restore_setting(
                                        &mut state.cpu_sets,
                                        || {
                                            get_process_default_cpu_sets(api, handle).map(
                                                |mut ids| {
                                                    ids.sort_unstable();
                                                    ids.dedup();
                                                    ids
                                                },
                                            )
                                        },
                                        |original| {
                                            set_process_default_cpu_sets(api, handle, original)
                                        },
                                    )
                                });
                            if let Err(error) = result {
                                log::warn!(
                                    "CPU set restore for {} (PID {pid}) failed: {error}",
                                    state.process_name
                                );
                            }
                        }
                        let result = restore_setting(
                            &mut state.affinity,
                            || {
                                let (mut current, mut system) = (0, 0);
                                unsafe {
                                    windows::Win32::System::Threading::GetProcessAffinityMask(
                                        handle,
                                        &mut current,
                                        &mut system,
                                    )
                                }
                                .map_err(|error| error.to_string())?;
                                Ok(current)
                            },
                            |original| {
                                unsafe {
                                    windows::Win32::System::Threading::SetProcessAffinityMask(
                                        handle, *original,
                                    )
                                }
                                .map_err(|error| error.to_string())
                            },
                        );
                        if let Err(error) = result {
                            log::warn!(
                                "Affinity restore for {} (PID {pid}) failed: {error}",
                                state.process_name
                            );
                        }
                    }
                    Ok(_) => {
                        state.cpu_sets = None;
                        state.affinity = None;
                    }
                    Err(error) => log::warn!("Could not verify process for restore: {error}"),
                }
                unsafe {
                    let _ = CloseHandle(handle);
                }
            } else if crate::process_snapshot::list()
                .is_ok_and(|processes| !processes.iter().any(|process| process.pid == pid))
            {
                state.cpu_sets = None;
                state.affinity = None;
            }
        }
        if let Some(key) = state.gpu_registry_key.clone()
            && self.decrement_gpu_binding_reference(&key, &state.process_name, pid, reason)
        {
            state.gpu_registry_key = None;
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
        self.try_apply_cpu_sets_policy_with_api(api, pid, process, state)
    }

    #[cfg(windows)]
    fn try_apply_cpu_sets_policy_with_api(
        &self,
        api: CpuSetApi,
        pid: u32,
        process: windows::Win32::Foundation::HANDLE,
        state: &mut AppliedProcessState,
    ) -> Result<(), String> {
        let cpu_sets = query_system_cpu_sets(api, process)?;
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

        let original = get_process_default_cpu_sets(api, process).map_err(|error| {
            format!("Original CPU sets could not be read; selection was left unchanged: {error}")
        })?;

        set_process_default_cpu_sets(api, process, &selected)?;

        state.cpu_sets = Some(TemporarySetting {
            original,
            applied: selected.clone(),
        });

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

        state.affinity = Some(TemporarySetting {
            original: process_mask,
            applied: updated_mask,
        });

        log::info!(
            "Process tuning: applied CPU0 affinity unbind for '{}' (PID {}) (0x{:X} -> 0x{:X})",
            state.process_name,
            pid,
            process_mask,
            updated_mask
        );
    }

    #[cfg(windows)]
    fn apply_gpu_binding(&mut self, pid: u32, process_path: &str, state: &mut AppliedProcessState) {
        let value_name = normalize_gpu_value_name(process_path);
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
                return;
            }
        };

        let applied_value = crate::roblox_optimizer::RobloxOptimizer::high_performance_gpu_value(
            previous_value.as_deref(),
        );
        if previous_value.as_deref() == Some(applied_value.as_str()) {
            return;
        }
        match write_gpu_preference_value(&value_name, &applied_value) {
            Ok(()) => {
                self.gpu_preferences.insert(
                    map_key.clone(),
                    GpuPreferenceSnapshot {
                        value_name: value_name.clone(),
                        previous_value,
                        applied_value,
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
        _process_name: &str,
        _pid: u32,
        _reason: &str,
    ) -> bool {
        self.release_gpu_reference_with(gpu_key, |snapshot| {
            restore_gpu_preference(
                &snapshot.value_name,
                &snapshot.previous_value,
                &snapshot.applied_value,
            )
        })
    }

    #[cfg(windows)]
    fn release_gpu_reference_with(
        &mut self,
        key: &str,
        restore: impl FnOnce(&GpuPreferenceSnapshot) -> Result<(), String>,
    ) -> bool {
        let Some(snapshot) = self.gpu_preferences.get_mut(key) else {
            return true;
        };
        if snapshot.ref_count > 1 {
            snapshot.ref_count -= 1;
            return true;
        }
        match restore(snapshot) {
            Ok(()) => {
                self.gpu_preferences.remove(key);
                true
            }
            Err(error) => {
                log::warn!("GPU preference restore failed; original retained: {error}");
                false
            }
        }
    }
}

pub(crate) fn select_cpu_set_ids(
    cpu_sets: &[CpuSetDescriptor],
    prefer_performance_cores: bool,
    unbind_cpu0: bool,
) -> Vec<u32> {
    let eligible: Vec<_> = cpu_sets
        .iter()
        .filter(|set| {
            !set.allocated_to_other_process
                && !(unbind_cpu0 && set.group == 0 && set.logical_processor_index == 0)
        })
        .collect();
    let mut candidates: Vec<&CpuSetDescriptor> =
        eligible.iter().copied().filter(|set| !set.parked).collect();
    if candidates.is_empty() {
        candidates = eligible;
    }

    if prefer_performance_cores
        // Windows documents higher EfficiencyClass values as faster cores.
        && let Some(best_efficiency) = candidates.iter().map(|set| set.efficiency_class).max()
    {
        candidates.retain(|set| set.efficiency_class == best_efficiency);
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
fn process_creation_for_pid(pid: u32) -> Option<u64> {
    let handle = open_process_for_tuning(pid)?;
    let created = crate::process_snapshot::creation_time(handle).ok();
    unsafe {
        let _ = windows::Win32::Foundation::CloseHandle(handle);
    }
    created
}

#[cfg(windows)]
fn read_gpu_preference_value(value_name: &str) -> Result<Option<String>, String> {
    crate::system_optimizer::SystemOptimizer::query_registry_checked(
        GPU_PREFERENCES_KEY_PATH,
        value_name,
    )
    .map_err(|error| error.to_string())
}
#[cfg(windows)]
fn write_gpu_preference_value(value_name: &str, value: &str) -> Result<(), String> {
    crate::system_optimizer::SystemOptimizer::set_registry_string_checked(
        GPU_PREFERENCES_KEY_PATH,
        value_name,
        value,
    )
    .map_err(|error| error.to_string())
}
#[cfg(windows)]
fn restore_gpu_preference(
    value_name: &str,
    previous: &Option<String>,
    applied: &str,
) -> Result<(), String> {
    if read_gpu_preference_value(value_name)?.as_deref() != Some(applied) {
        return Ok(());
    }
    match previous {
        Some(value) => write_gpu_preference_value(value_name, value),
        None => crate::system_optimizer::SystemOptimizer::delete_registry_value_checked(
            GPU_PREFERENCES_KEY_PATH,
            value_name,
        )
        .map_err(|error| error.to_string()),
    }
}

#[cfg(windows)]
type GetSystemCpuSetInformationFn = unsafe extern "system" fn(
    *mut std::ffi::c_void,
    u32,
    *mut u32,
    windows::Win32::Foundation::HANDLE,
    u32,
) -> i32;

#[cfg(windows)]
type GetProcessDefaultCpuSetsFn =
    unsafe extern "system" fn(windows::Win32::Foundation::HANDLE, *mut u32, u32, *mut u32) -> i32;

#[cfg(windows)]
type SetProcessDefaultCpuSetsFn =
    unsafe extern "system" fn(windows::Win32::Foundation::HANDLE, *const u32, u32) -> i32;

#[cfg(windows)]
#[derive(Clone, Copy)]
struct CpuSetApi {
    get_system_cpu_set_information: GetSystemCpuSetInformationFn,
    get_process_default_cpu_sets: GetProcessDefaultCpuSetsFn,
    set_process_default_cpu_sets: SetProcessDefaultCpuSetsFn,
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
            get_system_cpu_set_information: std::mem::transmute::<
                *const std::ffi::c_void,
                GetSystemCpuSetInformationFn,
            >(get_system),
            get_process_default_cpu_sets: std::mem::transmute::<
                *const std::ffi::c_void,
                GetProcessDefaultCpuSetsFn,
            >(get_process),
            set_process_default_cpu_sets: std::mem::transmute::<
                *const std::ffi::c_void,
                SetProcessDefaultCpuSetsFn,
            >(set_process),
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
fn query_system_cpu_sets(
    api: CpuSetApi,
    process: windows::Win32::Foundation::HANDLE,
) -> Result<Vec<CpuSetDescriptor>, String> {
    let mut needed_len: u32 = 0;
    unsafe {
        (api.get_system_cpu_set_information)(std::ptr::null_mut(), 0, &mut needed_len, process, 0);
    }

    if needed_len == 0 || needed_len > 1024 * 1024 {
        return Err("CPU Sets API returned an invalid buffer length".to_string());
    }

    let mut buffer = vec![0u8; needed_len as usize];
    let ok = unsafe {
        (api.get_system_cpu_set_information)(
            buffer.as_mut_ptr() as *mut std::ffi::c_void,
            needed_len,
            &mut needed_len,
            process,
            0,
        )
    };

    if ok == 0 {
        return Err(format!(
            "GetSystemCpuSetInformation failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    if needed_len as usize > buffer.len() {
        return Err("CPU Sets API returned more data than its buffer".into());
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
        if info_type == CPU_SET_INFO_TYPE
            && size >= 24
            && let Some(id) = read_u32_le(buffer, offset + 8)
        {
            let logical_processor_index = buffer[offset + 14];
            let efficiency_class = buffer[offset + 18];
            let all_flags = buffer[offset + 19];
            let parked = (all_flags & 0x01) != 0;

            output.push(CpuSetDescriptor {
                id,
                group: u16::from_le_bytes([buffer[offset + 12], buffer[offset + 13]]),
                logical_processor_index,
                efficiency_class,
                parked,
                allocated_to_other_process: all_flags & 0x02 != 0 && all_flags & 0x04 == 0,
            });
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

    if required_count == 0 || required_count > 65536 {
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

    if required_count as usize > ids.len() {
        return Err("CPU Sets API returned more IDs than its buffer".into());
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

    #[test]
    fn undo_keeps_failed_originals_but_does_not_overwrite_a_later_manual_setting() {
        let mut setting = Some(TemporarySetting {
            original: 7u32,
            applied: 14u32,
        });
        assert!(restore_setting(&mut setting, || Err("Read denied".into()), |_| Ok(())).is_err());
        assert_eq!(setting.as_ref().unwrap().original, 7);
        assert!(restore_setting(&mut setting, || Ok(14), |_| Err("Write denied".into())).is_err());
        assert_eq!(setting.as_ref().unwrap().original, 7);
        restore_setting(
            &mut setting,
            || Ok(14),
            |value| {
                assert_eq!(*value, 7);
                Ok(())
            },
        )
        .unwrap();
        assert!(setting.is_none());
        setting = Some(TemporarySetting {
            original: 7,
            applied: 14,
        });
        restore_setting(
            &mut setting,
            || Ok(3),
            |_| panic!("A manual value must not be overwritten"),
        )
        .unwrap();
        assert!(setting.is_none());
    }

    #[cfg(windows)]
    #[test]
    fn failed_gpu_restore_keeps_the_original_and_shared_references_release_once() {
        let mut manager =
            GameProcessPerformanceManager::new(GameProcessPerformancePolicy::default());
        manager.gpu_preferences.insert(
            "fixture".into(),
            GpuPreferenceSnapshot {
                value_name: "fixture.exe".into(),
                previous_value: Some("GpuPreference=1;".into()),
                applied_value: "GpuPreference=2;".into(),
                ref_count: 2,
            },
        );
        assert!(manager.release_gpu_reference_with("fixture", |_| panic!(
            "A shared preference cannot be restored yet"
        )));
        assert_eq!(manager.gpu_preferences["fixture"].ref_count, 1);
        assert!(
            !manager.release_gpu_reference_with("fixture", |_| Err("Permission denied".into()))
        );
        assert_eq!(
            manager.gpu_preferences["fixture"].previous_value.as_deref(),
            Some("GpuPreference=1;")
        );
        assert_eq!(manager.gpu_preferences["fixture"].ref_count, 1);
        assert!(manager.release_gpu_reference_with("fixture", |_| Ok(())));
        assert!(manager.gpu_preferences.is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn runtime_restore_cannot_touch_a_replacement_process_or_retry_failed_apply_on_every_poll() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let child = Child(
            crate::hidden_command("powershell")
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Start-Sleep -Seconds 20",
                ])
                .spawn()
                .unwrap(),
        );
        let pid = child.0.id();
        let mut state = AppliedProcessState::new("powershell.exe".into());
        state.created = Some(process_creation_for_pid(pid).unwrap() ^ 1);
        state.affinity = Some(TemporarySetting {
            original: 0,
            applied: usize::MAX,
        }); // Invalid original exposes a wrong restore.
        let mut manager =
            GameProcessPerformanceManager::new(GameProcessPerformancePolicy::default());
        manager.active_processes.insert(pid, state);
        manager.revert_for_process(pid, "fixture_replaced");
        assert!(manager.active_processes.is_empty());
        // A nonexistent PID cannot be tuned; repeated polls retain one retry
        // deadline instead of spawning repeated topology/registry operations.
        manager.policy.unbind_cpu0 = true;
        let missing = [(u32::MAX, "fixture.exe".to_string())];
        manager.sync_targets(&missing);
        let first = manager.failed_attempts[&u32::MAX].1;
        for _ in 0..20 {
            manager.sync_targets(&missing);
        }
        assert_eq!(manager.failed_attempts[&u32::MAX].1, first);
        manager.sync_targets(&[]);
        assert!(manager.failed_attempts.is_empty());
    }

    fn cpu_set(id: u32, logical_index: u8, efficiency_class: u8) -> CpuSetDescriptor {
        CpuSetDescriptor {
            id,
            group: 0,
            logical_processor_index: logical_index,
            efficiency_class,
            parked: false,
            allocated_to_other_process: false,
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
        assert_eq!(selected, vec![20, 21]);
    }

    #[test]
    fn cpu_selection_respects_allocations_groups_and_available_cores() {
        let mut reserved = cpu_set(1, 1, 10);
        reserved.allocated_to_other_process = true;
        let mut other_group_zero = cpu_set(2, 0, 8);
        other_group_zero.group = 1;
        let mut parked = cpu_set(3, 2, 12);
        parked.parked = true;
        let sets = [
            cpu_set(4, 0, 8),
            other_group_zero,
            reserved,
            parked,
            cpu_set(5, 1, 0),
        ];
        assert_eq!(select_cpu_set_ids(&sets, true, true), vec![2]);
        assert_eq!(
            select_cpu_set_ids(&[reserved, parked], false, false),
            vec![3]
        );
        assert!(select_cpu_set_ids(&[reserved], false, false).is_empty());
        // If CPU0 is the only fast core, use eligible slower cores rather than
        // silently including CPU0 or a core reserved for another application.
        assert_eq!(
            select_cpu_set_ids(&[cpu_set(4, 0, 8), cpu_set(5, 1, 0)], true, true),
            vec![5]
        );
    }

    #[cfg(windows)]
    fn cpu_record(id: u32, group: u16, index: u8, class: u8, flags: u8) -> [u8; 32] {
        let mut record = [0; 32];
        record[0..4].copy_from_slice(&32u32.to_le_bytes());
        record[8..12].copy_from_slice(&id.to_le_bytes());
        record[12..14].copy_from_slice(&group.to_le_bytes());
        record[14] = index;
        record[18] = class;
        record[19] = flags;
        record
    }

    #[cfg(windows)]
    #[test]
    fn cpu_records_keep_allocation_and_group_metadata_and_reject_partial_records() {
        let buffer = [
            cpu_record(10, 0, 1, 8, 0x02),
            cpu_record(20, 1, 0, 10, 0x06),
        ]
        .concat();
        let records = parse_cpu_set_buffer(&buffer);
        assert!(records[0].allocated_to_other_process);
        assert!(!records[1].allocated_to_other_process);
        assert_eq!(records[1].group, 1);
        assert_eq!(select_cpu_set_ids(&records, true, true), vec![20]);
        for length in 0..32 {
            assert!(parse_cpu_set_buffer(&buffer[..length]).is_empty());
        }
        let mut corrupt = cpu_record(30, 0, 0, 0, 0);
        corrupt[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_cpu_set_buffer(&corrupt).is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn unreadable_original_cpu_sets_cannot_apply_and_api_lengths_are_bounded() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use windows::Win32::Foundation::HANDLE;
        static SET_CALLS: AtomicUsize = AtomicUsize::new(0);
        unsafe extern "system" fn topology(
            out: *mut std::ffi::c_void,
            length: u32,
            needed: *mut u32,
            _process: HANDLE,
            _flags: u32,
        ) -> i32 {
            let record = cpu_record(20, 0, 1, 8, 0);
            unsafe {
                *needed = record.len() as u32;
                if out.is_null() || length < record.len() as u32 {
                    return 0;
                }
                std::ptr::copy_nonoverlapping(record.as_ptr(), out.cast::<u8>(), record.len());
            }
            1
        }
        unsafe extern "system" fn failed_original(
            _process: HANDLE,
            _ids: *mut u32,
            _count: u32,
            needed: *mut u32,
        ) -> i32 {
            unsafe {
                *needed = 0;
            }
            0
        }
        unsafe extern "system" fn set(_process: HANDLE, _ids: *const u32, _count: u32) -> i32 {
            SET_CALLS.fetch_add(1, Ordering::SeqCst);
            1
        }
        unsafe extern "system" fn huge_topology(
            _out: *mut std::ffi::c_void,
            _length: u32,
            needed: *mut u32,
            _process: HANDLE,
            _flags: u32,
        ) -> i32 {
            unsafe {
                *needed = u32::MAX;
            }
            0
        }
        unsafe extern "system" fn huge_original(
            _process: HANDLE,
            _ids: *mut u32,
            _count: u32,
            needed: *mut u32,
        ) -> i32 {
            unsafe {
                *needed = u32::MAX;
            }
            0
        }
        let api = CpuSetApi {
            get_system_cpu_set_information: topology,
            get_process_default_cpu_sets: failed_original,
            set_process_default_cpu_sets: set,
        };
        let manager = GameProcessPerformanceManager::new(GameProcessPerformancePolicy {
            prefer_performance_cores: true,
            ..Default::default()
        });
        let mut state = AppliedProcessState::new("fixture.exe".into());
        assert!(
            manager
                .try_apply_cpu_sets_policy_with_api(api, 1, HANDLE::default(), &mut state)
                .is_err()
        );
        assert_eq!(SET_CALLS.load(Ordering::SeqCst), 0);
        assert!(state.cpu_sets.is_none());
        assert!(
            query_system_cpu_sets(
                CpuSetApi {
                    get_system_cpu_set_information: huge_topology,
                    ..api
                },
                HANDLE::default()
            )
            .is_err()
        );
        assert!(
            get_process_default_cpu_sets(
                CpuSetApi {
                    get_process_default_cpu_sets: huge_original,
                    ..api
                },
                HANDLE::default()
            )
            .is_err()
        );
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
