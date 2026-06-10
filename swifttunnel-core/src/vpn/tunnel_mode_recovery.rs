//! Stuck tunnel-mode crash recovery
//!
//! While connected, the packet reader puts the physical adapter into
//! WinpkFilter's `MSTCP_FLAG_SENT_RECEIVE_TUNNEL` mode, in which the NDISRD
//! kernel filter diverts every sent/received packet to the reader. If the
//! process dies without resetting the mode (force-kill, crash, Windows
//! shutdown killing the app mid-session), the filter keeps diverting packets
//! to a process that no longer exists and the machine loses all connectivity
//! on that adapter — the 2026-06 "no wifi after SwiftTunnel" incident class.
//!
//! A marker file is written before the reader can enter tunnel mode and
//! deleted only after a verified reset of all adapter modes. A persisting
//! marker therefore means a prior session may have left tunnel mode active,
//! and startup recovery escalates accordingly: reset with bounded retries
//! instead of the single silent best-effort pass used when no marker exists.
//!
//! The marker is the structured recovery trigger; driver error strings are
//! never substring-matched. Whether a repair is attempted at all is decided
//! from the driver install evidence (`SplitTunnelDriver::driver_install_evidence`):
//! if the NDISRD driver is not installed, the kernel filter cannot be holding
//! tunnel mode, so a leftover marker is stale and is cleared without any
//! repair attempt.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Marker file name stored in %LOCALAPPDATA%/SwiftTunnel/
const TUNNEL_MODE_MARKER_FILE: &str = "tunnel_mode.marker";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TunnelModeMarker {
    /// Device name of the adapter the session intended to tunnel
    /// (diagnostic only — recovery always sweeps every adapter because a
    /// wedged reader can lose its handle before we learn the final binding).
    pub adapter_name: String,
}

fn get_marker_path() -> Option<PathBuf> {
    dirs::data_local_dir().map(|d| d.join("SwiftTunnel").join(TUNNEL_MODE_MARKER_FILE))
}

/// Write the tunnel-mode marker. Called before the packet reader can put the
/// adapter into tunnel mode, so a crash at any later point leaves the marker
/// behind for startup recovery.
pub fn write_tunnel_mode_marker(adapter_name: &str) {
    let Some(marker_path) = get_marker_path() else {
        return;
    };
    if let Some(parent) = marker_path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let marker = TunnelModeMarker {
        adapter_name: adapter_name.trim().to_string(),
    };
    let payload = serde_json::to_vec(&marker).unwrap_or_else(|_| adapter_name.as_bytes().to_vec());
    if let Err(e) = fs::write(&marker_path, payload) {
        log::warn!("Failed to write tunnel-mode marker: {}", e);
    } else {
        log::debug!(
            "Tunnel-mode marker written for adapter: {}",
            marker.adapter_name
        );
    }
}

/// Delete the tunnel-mode marker. Only call after a verified adapter-mode
/// reset (or when the marker is known stale) — deleting it early would mask
/// a primary failure with a secondary success.
pub fn delete_tunnel_mode_marker() {
    let Some(marker_path) = get_marker_path() else {
        return;
    };
    if marker_path.exists() {
        if let Err(e) = fs::remove_file(&marker_path) {
            log::warn!("Failed to delete tunnel-mode marker: {}", e);
        } else {
            log::debug!("Tunnel-mode marker deleted");
        }
    }
}

/// Read the tunnel-mode marker if present.
pub fn read_tunnel_mode_marker() -> Option<TunnelModeMarker> {
    let marker_path = get_marker_path()?;
    let raw = fs::read(&marker_path).ok()?;
    if let Ok(marker) = serde_json::from_slice::<TunnelModeMarker>(&raw) {
        return Some(marker);
    }
    // Unreadable contents still mean "a session was active and never cleaned
    // up" — recover with a generic marker instead of skipping silently.
    Some(TunnelModeMarker {
        adapter_name: String::from_utf8_lossy(&raw).trim().to_string(),
    })
}

/// What startup recovery should do, decided from structured state only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelModeRecoveryPlan {
    /// Marker present and the driver is installed: adapters may be stuck in
    /// tunnel mode. Reset with bounded retries; keep the marker on failure so
    /// the next launch retries.
    RepairWithRetries,
    /// Marker present but no NDISRD install evidence: the kernel filter is
    /// not loaded, so tunnel mode cannot be active. The marker is stale —
    /// clear it without attempting any repair.
    ClearStaleMarker,
    /// No marker: single best-effort sweep, matching the historical behavior
    /// and covering sessions from builds that predate the marker.
    BestEffortSweep,
}

pub fn plan_tunnel_mode_recovery(
    marker_present: bool,
    driver_installed: bool,
) -> TunnelModeRecoveryPlan {
    match (marker_present, driver_installed) {
        (true, true) => TunnelModeRecoveryPlan::RepairWithRetries,
        (true, false) => TunnelModeRecoveryPlan::ClearStaleMarker,
        (false, _) => TunnelModeRecoveryPlan::BestEffortSweep,
    }
}

/// Per-launch retry bound for [`TunnelModeRecoveryPlan::RepairWithRetries`].
/// Cross-launch retries happen via the persisting marker, so this stays small.
pub const RECOVERY_MAX_ATTEMPTS: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryOutcome {
    /// How many reset attempts ran (0 for [`TunnelModeRecoveryPlan::ClearStaleMarker`]).
    pub attempts: u32,
    /// Whether all adapter modes are confirmed back to default (or trivially
    /// so because the driver is not loaded).
    pub cleaned: bool,
    /// Whether the marker (if any) should be deleted. Stays `false` when the
    /// reset could not be verified so the next launch retries.
    pub delete_marker: bool,
}

/// Execute a recovery plan. `reset_all_adapters` must return `true` only when
/// every adapter mode is verified back to default; `on_retry` runs between
/// failed attempts (the production caller sleeps there, tests count calls).
///
/// Attempts are bounded by [`RECOVERY_MAX_ATTEMPTS`]; this function cannot
/// loop forever regardless of what the closures do.
pub fn execute_recovery_plan<F, R>(
    plan: TunnelModeRecoveryPlan,
    mut reset_all_adapters: F,
    mut on_retry: R,
) -> RecoveryOutcome
where
    F: FnMut() -> bool,
    R: FnMut(u32),
{
    match plan {
        TunnelModeRecoveryPlan::ClearStaleMarker => RecoveryOutcome {
            attempts: 0,
            cleaned: true,
            delete_marker: true,
        },
        TunnelModeRecoveryPlan::BestEffortSweep => {
            let cleaned = reset_all_adapters();
            RecoveryOutcome {
                attempts: 1,
                cleaned,
                // No marker exists in this plan; nothing to delete either way.
                delete_marker: false,
            }
        }
        TunnelModeRecoveryPlan::RepairWithRetries => {
            for attempt in 1..=RECOVERY_MAX_ATTEMPTS {
                if reset_all_adapters() {
                    return RecoveryOutcome {
                        attempts: attempt,
                        cleaned: true,
                        delete_marker: true,
                    };
                }
                if attempt < RECOVERY_MAX_ATTEMPTS {
                    on_retry(attempt);
                }
            }
            RecoveryOutcome {
                attempts: RECOVERY_MAX_ATTEMPTS,
                cleaned: false,
                delete_marker: false,
            }
        }
    }
}

/// Recover from a prior session that may have left adapters in WinpkFilter
/// tunnel mode. Runs at every app launch (and from the network repair
/// command) before any new session starts.
pub fn recover_tunnel_mode_on_startup() {
    use super::split_tunnel::SplitTunnelDriver;

    let marker = read_tunnel_mode_marker();
    let driver_installed = SplitTunnelDriver::driver_install_evidence();
    let plan = plan_tunnel_mode_recovery(marker.is_some(), driver_installed);

    if let Some(marker) = &marker {
        log::warn!(
            "Tunnel-mode marker found - a prior session may have left adapter(s) in tunnel mode (adapter: '{}', plan: {:?})",
            marker.adapter_name,
            plan
        );
    }

    let outcome = execute_recovery_plan(
        plan,
        || SplitTunnelDriver::cleanup_stale_state_checked().fully_clean(),
        |attempt| {
            log::warn!(
                "Tunnel-mode recovery attempt {}/{} did not verify clean; retrying",
                attempt,
                RECOVERY_MAX_ATTEMPTS
            );
            std::thread::sleep(std::time::Duration::from_millis(500));
        },
    );

    match plan {
        TunnelModeRecoveryPlan::ClearStaleMarker => {
            log::info!(
                "Tunnel-mode marker is stale (NDISRD driver not installed, so tunnel mode cannot persist); clearing without repair"
            );
        }
        TunnelModeRecoveryPlan::RepairWithRetries if outcome.cleaned => {
            log::info!(
                "Tunnel-mode recovery complete after {} attempt(s); all adapter modes verified default",
                outcome.attempts
            );
        }
        TunnelModeRecoveryPlan::RepairWithRetries => {
            log::error!(
                "Tunnel-mode recovery FAILED after {} attempt(s); marker kept so the next launch retries. \
                 Use Repair Center → Internet recovery, or reboot to clear the kernel filter state.",
                outcome.attempts
            );
        }
        TunnelModeRecoveryPlan::BestEffortSweep => {
            // No marker: keep the historical quiet behavior (fresh installs
            // legitimately have no driver yet). Details were already logged by
            // cleanup_stale_state_checked.
        }
    }

    if outcome.delete_marker && marker.is_some() {
        delete_tunnel_mode_marker();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_marker_roundtrip() {
        write_tunnel_mode_marker(r"\DEVICE\{TEST-GUID}");
        let read_back = read_tunnel_mode_marker();
        assert_eq!(
            read_back.map(|m| m.adapter_name),
            Some(r"\DEVICE\{TEST-GUID}".to_string())
        );
        delete_tunnel_mode_marker();
        assert_eq!(read_tunnel_mode_marker(), None);
    }

    #[test]
    fn test_plan_marker_with_driver_repairs() {
        assert_eq!(
            plan_tunnel_mode_recovery(true, true),
            TunnelModeRecoveryPlan::RepairWithRetries
        );
    }

    /// Negative case: a leftover marker with NO driver installed looks like
    /// the repairable case (marker present, cleanup would "fail" because the
    /// driver can't open) but is non-repairable by mode reset — tunnel mode
    /// cannot be active without the kernel filter. It must be classified as
    /// stale, attempt zero resets, and clear the marker so it cannot retry
    /// forever across launches.
    #[test]
    fn test_negative_marker_without_driver_is_stale_not_repaired() {
        assert_eq!(
            plan_tunnel_mode_recovery(true, false),
            TunnelModeRecoveryPlan::ClearStaleMarker
        );

        let mut reset_calls = 0u32;
        let outcome = execute_recovery_plan(
            TunnelModeRecoveryPlan::ClearStaleMarker,
            || {
                reset_calls += 1;
                false
            },
            |_| {},
        );
        assert_eq!(
            reset_calls, 0,
            "stale marker must not trigger repair attempts"
        );
        assert!(outcome.cleaned);
        assert!(outcome.delete_marker);
    }

    #[test]
    fn test_no_marker_is_single_best_effort() {
        assert_eq!(
            plan_tunnel_mode_recovery(false, true),
            TunnelModeRecoveryPlan::BestEffortSweep
        );
        assert_eq!(
            plan_tunnel_mode_recovery(false, false),
            TunnelModeRecoveryPlan::BestEffortSweep
        );

        let mut reset_calls = 0u32;
        let outcome = execute_recovery_plan(
            TunnelModeRecoveryPlan::BestEffortSweep,
            || {
                reset_calls += 1;
                false
            },
            |_| {},
        );
        assert_eq!(reset_calls, 1, "best-effort sweep must not retry");
        assert!(!outcome.cleaned);
        assert!(!outcome.delete_marker);
    }

    #[test]
    fn test_repair_retries_are_bounded_and_keep_marker_on_failure() {
        let mut reset_calls = 0u32;
        let mut retry_calls = 0u32;
        let outcome = execute_recovery_plan(
            TunnelModeRecoveryPlan::RepairWithRetries,
            || {
                reset_calls += 1;
                false
            },
            |_| retry_calls += 1,
        );
        assert_eq!(reset_calls, RECOVERY_MAX_ATTEMPTS);
        assert_eq!(retry_calls, RECOVERY_MAX_ATTEMPTS - 1);
        assert!(!outcome.cleaned);
        assert!(
            !outcome.delete_marker,
            "marker must persist so the next launch retries"
        );
    }

    #[test]
    fn test_repair_stops_at_first_verified_clean() {
        let mut reset_calls = 0u32;
        let outcome = execute_recovery_plan(
            TunnelModeRecoveryPlan::RepairWithRetries,
            || {
                reset_calls += 1;
                reset_calls == 2
            },
            |_| {},
        );
        assert_eq!(reset_calls, 2);
        assert!(outcome.cleaned);
        assert!(outcome.delete_marker);
        assert_eq!(outcome.attempts, 2);
    }
}
