//! Local internet reachability hint.
//!
//! Used to disambiguate "the relay went away" from "the user's machine lost
//! internet" when the relay-health monitor is about to declare a session dead.
//! On Windows we ask `GetNetworkConnectivityHint` — the same NLM signal that
//! drives the "No internet access" badge in the system tray.

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
pub fn probe() -> LocalConnectivity {
    use windows::Win32::NetworkManagement::IpHelper::GetNetworkConnectivityHint;
    use windows::Win32::Networking::WinSock::{
        NL_NETWORK_CONNECTIVITY_HINT, NetworkConnectivityLevelHintConstrainedInternetAccess,
        NetworkConnectivityLevelHintHidden, NetworkConnectivityLevelHintInternetAccess,
        NetworkConnectivityLevelHintLocalAccess, NetworkConnectivityLevelHintNone,
        NetworkConnectivityLevelHintUnknown,
    };

    let mut hint = NL_NETWORK_CONNECTIVITY_HINT::default();
    // SAFETY: out-pointer write into a stack-allocated, properly-sized struct.
    let status = unsafe { GetNetworkConnectivityHint(&mut hint) };
    if status.is_err() {
        return LocalConnectivity::Unknown;
    }

    match hint.ConnectivityLevel {
        NetworkConnectivityLevelHintInternetAccess
        | NetworkConnectivityLevelHintConstrainedInternetAccess => LocalConnectivity::Reachable,
        NetworkConnectivityLevelHintLocalAccess
        | NetworkConnectivityLevelHintNone
        | NetworkConnectivityLevelHintHidden => LocalConnectivity::Offline,
        NetworkConnectivityLevelHintUnknown => LocalConnectivity::Unknown,
        _ => LocalConnectivity::Unknown,
    }
}

#[cfg(not(windows))]
pub fn probe() -> LocalConnectivity {
    LocalConnectivity::Unknown
}
