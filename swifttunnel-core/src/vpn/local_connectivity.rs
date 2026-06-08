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
//! dynamically at runtime (`LoadLibrary` + `GetProcAddress`); when the symbol is
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
    fn LoadLibraryW(lplibfilename: *const u16) -> isize;
    fn GetProcAddress(hmodule: isize, lpprocname: *const u8) -> *const std::ffi::c_void;
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
        let lib_name: Vec<u16> = "iphlpapi.dll"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let module = unsafe { LoadLibraryW(lib_name.as_ptr()) };
        if module == 0 {
            return None;
        }

        let address = unsafe { GetProcAddress(module, b"GetNetworkConnectivityHint\0".as_ptr()) };
        if address.is_null() {
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

#[cfg(windows)]
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
