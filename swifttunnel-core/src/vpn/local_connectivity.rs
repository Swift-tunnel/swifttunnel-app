//! Local internet reachability hint.
//!
//! Used to disambiguate "the relay went away" from "the user's machine lost
//! internet" when the relay-health monitor is about to declare a session dead.
//! On Windows we ask `GetNetworkConnectivityHint` — the same NLM signal that
//! drives the "No internet access" badge in the system tray.
//!
//! Minimum supported Windows: 10 build 17763 (1809). `GetNetworkConnectivityHint`
//! only exists in `iphlpapi.dll` on Windows 10 build 19041 (2004) and newer.
//! Calling it through the `windows` crate creates a STATIC import, which makes
//! the whole EXE fail to load on older builds with "entry point
//! GetNetworkConnectivityHint could not be located". We therefore resolve it
//! dynamically at runtime (`LoadLibraryEx` + `GetProcAddress`); when the symbol is
//! absent we degrade gracefully to `Unknown` instead of refusing to launch.

/// Authoritative-enough verdict on whether this device can currently reach
/// the public internet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalConnectivity {
    /// OS reports internet (or constrained internet) is available.
    Reachable,
    /// OS reports no public internet — local-network-only or fully offline.
    Offline,
    /// We could not get a verdict (API failed, hint=Unknown, non-Windows
    /// build). Treat as "do not override the existing relay-failure path."
    Unknown,
}

#[cfg(windows)]
type GetNetworkConnectivityHintFn = unsafe extern "system" fn(
    *mut windows::Win32::Networking::WinSock::NL_NETWORK_CONNECTIVITY_HINT,
) -> u32;

#[cfg(windows)]
unsafe extern "system" {
    fn LoadLibraryExW(
        lplibfilename: *const u16,
        file: *mut std::ffi::c_void,
        flags: u32,
    ) -> *mut std::ffi::c_void;
    fn GetProcAddress(hmodule: isize, lpprocname: *const u8) -> *const std::ffi::c_void;
    fn FreeLibrary(hmodule: *mut std::ffi::c_void) -> i32;
}

#[cfg(windows)]
fn load_connectivity_library() -> Option<isize> {
    use std::os::windows::ffi::OsStrExt;
    let path = crate::utils::trusted_windows_root()?
        .join("System32")
        .join("iphlpapi.dll");
    let name: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // LOAD_LIBRARY_SEARCH_SYSTEM32 also restricts dependency resolution. Do
    // not search the application directory, current directory or PATH from
    // this elevated process. The optional API still resolves dynamically.
    let module = unsafe { LoadLibraryExW(name.as_ptr(), std::ptr::null_mut(), 0x800) };
    (!module.is_null()).then_some(module as isize)
}

/// Resolve `GetNetworkConnectivityHint` from `iphlpapi.dll` at runtime, once.
///
/// Returns `None` on Windows builds older than 10 2004 (19041) where the symbol
/// does not exist. Resolving dynamically (instead of importing it statically via
/// the `windows` crate) is what keeps the EXE loadable on those older builds.
#[cfg(windows)]
fn network_connectivity_hint_fn() -> Option<GetNetworkConnectivityHintFn> {
    static RESOLVED: std::sync::OnceLock<Option<GetNetworkConnectivityHintFn>> =
        std::sync::OnceLock::new();

    *RESOLVED.get_or_init(|| {
        let module = load_connectivity_library()?;

        let address =
            unsafe { GetProcAddress(module, c"GetNetworkConnectivityHint".as_ptr().cast::<u8>()) };
        if address.is_null() {
            // No function pointer will retain this reference on older Windows.
            unsafe {
                let _ = FreeLibrary(module as *mut std::ffi::c_void);
            }
            return None;
        }

        // SAFETY: `GetNetworkConnectivityHint` has the signature
        // `NETIO_STATUS GetNetworkConnectivityHint(NL_NETWORK_CONNECTIVITY_HINT*)`,
        // which matches `GetNetworkConnectivityHintFn` (NETIO_STATUS is a u32).
        Some(unsafe {
            std::mem::transmute::<*const std::ffi::c_void, GetNetworkConnectivityHintFn>(address)
        })
    })
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use std::os::windows::ffi::OsStringExt;

    unsafe extern "system" {
        fn GetModuleFileNameW(module: isize, name: *mut u16, size: u32) -> u32;
    }

    #[test]
    fn connectivity_library_resolves_to_the_real_windows_system_directory() {
        let module = load_connectivity_library().expect("Windows IP helper library");
        let mut name = [0u16; 32768];
        let length =
            unsafe { GetModuleFileNameW(module, name.as_mut_ptr(), name.len() as u32) } as usize;
        // Balance this test's reference, not the process-wide resolver's handle.
        unsafe {
            let _ = FreeLibrary(module as *mut std::ffi::c_void);
        }
        assert!(length > 0 && length < name.len());
        let actual = std::path::PathBuf::from(std::ffi::OsString::from_wide(&name[..length]));
        let expected = crate::utils::trusted_windows_root()
            .unwrap()
            .join("System32")
            .join("iphlpapi.dll");
        assert!(
            actual
                .to_string_lossy()
                .eq_ignore_ascii_case(&expected.to_string_lossy()),
            "loaded {actual:?}, expected {expected:?}"
        );
    }
}

// The NLM connectivity-hint values come from windows-rs, which generates them
// in Windows own PascalCase. They resolve as constants rather than bindings, so
// the match below does what it looks like; the naming is simply not ours.
#[cfg(windows)]
#[allow(non_upper_case_globals)]
pub fn probe() -> LocalConnectivity {
    use windows::Win32::Networking::WinSock::{
        NL_NETWORK_CONNECTIVITY_HINT, NetworkConnectivityLevelHintConstrainedInternetAccess,
        NetworkConnectivityLevelHintHidden, NetworkConnectivityLevelHintInternetAccess,
        NetworkConnectivityLevelHintLocalAccess, NetworkConnectivityLevelHintNone,
        NetworkConnectivityLevelHintUnknown,
    };

    // Missing on Windows < 10 2004: degrade to Unknown instead of crashing.
    let Some(get_hint) = network_connectivity_hint_fn() else {
        return LocalConnectivity::Unknown;
    };

    let mut hint = NL_NETWORK_CONNECTIVITY_HINT::default();
    // SAFETY: out-pointer write into a stack-allocated, properly-sized struct.
    let status = unsafe { get_hint(&mut hint) };
    if status != 0 {
        return LocalConnectivity::Unknown;
    }

    match hint.ConnectivityLevel {
        NetworkConnectivityLevelHintInternetAccess
        | NetworkConnectivityLevelHintConstrainedInternetAccess => LocalConnectivity::Reachable,
        NetworkConnectivityLevelHintLocalAccess | NetworkConnectivityLevelHintNone => {
            LocalConnectivity::Offline
        }
        // `Hidden` means NLM couldn't determine the interface's connectivity
        // properties — typical on VPN-managed virtual adapters, hidden-SSID
        // corporate networks, and some Wi-Fi drivers. It is *not* a reliable
        // "offline" signal and treating it as one would cause the post-connect
        // watchdog to fire spurious adapter-reset rollbacks on those configs.
        // Mapped to `Unknown` so the existing "do not override the relay
        // failure path" semantic carries through.
        NetworkConnectivityLevelHintHidden | NetworkConnectivityLevelHintUnknown => {
            LocalConnectivity::Unknown
        }
        _ => LocalConnectivity::Unknown,
    }
}

#[cfg(not(windows))]
pub fn probe() -> LocalConnectivity {
    LocalConnectivity::Unknown
}
